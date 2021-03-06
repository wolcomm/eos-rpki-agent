#!/usr/bin/env python
# Copyright (c) 2019 Ben Maddison. All rights reserved.
#
# The contents of this file are licensed under the MIT License
# (the "License"); you may not use this file except in compliance with the
# License.
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations under
# the License.
"""rpki_agent agent implementation."""

from __future__ import print_function

import collections
import datetime
import filecmp
import os
import shutil
import signal
import tempfile

import eossdk

from rpki_agent.base import RpkiBase
from rpki_agent.listener import RpkiListener
from rpki_agent.worker import RpkiWorker


class RpkiAgent(RpkiBase, eossdk.AgentHandler, eossdk.TimeoutHandler,
                eossdk.FdHandler):
    """An EOS SDK based agent that creates routing policy objects."""

    sysdb_mounts = ("agent",)
    agent_options = ("cache_url", "refresh_interval")

    @classmethod
    def set_sysdb_mp(cls, name):
        """Create the SysdbMountProfiles file for the agent."""
        # set the path
        profile_path = os.path.join("/usr/lib/SysdbMountProfiles", name)
        # get a tempfile for writing the profile to
        with tempfile.NamedTemporaryFile() as tmp:
            # write the profile file
            tmp.write("agentName:{}-%sliceId\n\n".format(name))
            for profile in cls.sysdb_mounts:
                tmp.write("Include: EosSdk_{}.include\n".format(profile))
            tmp.flush()
            # check whether an existing file matches and bail out
            if os.path.isfile(profile_path):
                if filecmp.cmp(profile_path, tmp.name, shallow=False):
                    return False
            # copy the tempfile into place
            shutil.copy(tmp.name, profile_path)
        return True

    def __init__(self, sdk):
        """Initialise the agent instance."""
        # Set up tracing
        RpkiBase.__init__(self)
        # get sdk managers
        self.agent_mgr = sdk.get_agent_mgr()
        self.timeout_mgr = sdk.get_timeout_mgr()
        # init sdk handlers
        eossdk.AgentHandler.__init__(self, self.agent_mgr)
        eossdk.TimeoutHandler.__init__(self, self.timeout_mgr)
        eossdk.FdHandler.__init__(self)
        # set worker process to None
        self.worker = None
        self.watching = set()
        # set default confg options
        self._cache_url = None
        self._refresh_interval = 10
        # create state containers
        self._status = None
        self._last_start = None
        self._last_end = None
        self._result = None
        self.state = dict()

    @property
    def cache_url(self):
        """Get 'cache_url' property."""
        return self._cache_url

    @cache_url.setter
    def cache_url(self, url):
        """Set 'cache_url' property."""
        self._cache_url = url

    @property
    def refresh_interval(self):
        """Get 'refresh_interval' property."""
        return self._refresh_interval

    @refresh_interval.setter
    def refresh_interval(self, i):
        """Set 'refresh_interval' property."""
        if i:
            i = int(i)
        else:
            i = 10
        if i in range(10, 86400):
            self._refresh_interval = i
        else:
            raise ValueError("refresh_interval must be in range 1 - 86399")

    @property
    def status(self):
        """Get 'status' property."""
        return self._status

    @status.setter
    def status(self, s):
        """Set 'status' property."""
        self._status = s
        self.agent_mgr.status_set("status", self.status)
        self.info("Status: {}".format(self.status))

    @property
    def result(self):
        """Get 'result' property."""
        return self._result

    @result.setter
    def result(self, r):
        """Set 'result' property."""
        self._result = r
        self.agent_mgr.status_set("result", self.result)
        self.notice("Result: {}".format(self.result))

    @property
    def last_start(self):
        """Set the 'last_start' timestamp."""
        return self._last_start

    @last_start.setter
    def last_start(self, ts):
        """Set the 'last_start' timestamp."""
        if not isinstance(ts, datetime.datetime):
            raise TypeError("Expected datetime.datetime, got {}".format(ts))
        self._last_start = ts
        self.agent_mgr.status_set("last_start", str(self.last_start))
        self.info("Last start: {}".format(ts))

    @property
    def last_end(self):
        """Set the 'last_end' timestamp."""
        return self._last_end

    @last_end.setter
    def last_end(self, ts):
        """Set the 'last_end' timestamp."""
        if not isinstance(ts, datetime.datetime):
            raise TypeError("Expected datetime.datetime, got {}".format(ts))
        self._last_end = ts
        self.agent_mgr.status_set("last_end", str(self.last_end))
        self.info("Last end: {}".format(ts))

    def configure(self):
        """Read and set all configuration options."""
        self.info("Reading configuration options")
        for key in self.agent_mgr.agent_option_iter():
            value = self.agent_mgr.agent_option(key)
            self.set(key, value)

    def set(self, key, value):
        """Set a configuration option."""
        if not value:
            value = None
        self.info("Setting configuration '{}'='{}'".format(key, value))
        if key in self.agent_options:
            setattr(self, key, value)
        else:
            self.warning("Ignoring unknown option '{}'".format(key))

    def start(self):
        """Start up the agent."""
        self.status = "init"
        self.configure()
        self.init()
        self.run()

    def init(self):
        """Start up the Listener."""
        try:
            self.info("Initialising listener")
            self.listener = RpkiListener()
            self.watch(self.listener.p_err, "error")
            self.info("Starting listener")
            self.listener.start()
            self.info("Listener started: pid {}".format(self.listener.pid))
        except Exception as e:
            self.err("Starting listener failed: {}".format(e))
            raise e

    def run(self):
        """Spawn worker process to retrieve VRP data."""
        self.status = "running"
        if self.cache_url is not None:
            self.last_start = datetime.datetime.now()
            try:
                self.info("Initialising worker")
                self.worker = RpkiWorker(cache_url=self.cache_url)
                self.watch(self.worker.p_data, "result")
                self.watch(self.worker.p_err, "error")
                self.info("Starting worker")
                self.worker.start()
                self.info("Worker started: pid {}".format(self.worker.pid))
            except Exception as e:
                self.err("Starting worker failed: {}".format(e))
                self.failure(err=e)
        else:
            self.warning("'cache_url' is not set".format(self.cache_url))
            self.sleep()

    def watch(self, conn, type):
        """Watch a Connection for new data."""
        self.info("Trying to watch for {} data on {}".format(type, conn))
        fileno = conn.fileno()
        self.watch_readable(fileno, True)
        self.watching.add(conn)
        self.info("Watching {} for {} data".format(conn, type))

    def unwatch(self, conn, close=False):
        """Stop watching a Connection for new data."""
        self.info("Trying to remove watch on {}".format(conn))
        fileno = conn.fileno()
        self.watch_readable(fileno, False)
        if conn in self.watching:
            self.watching.remove(conn)
        self.info("Stopped watching {}".format(conn))
        if close:
            self.info("Closing connection {}".format(conn))
            conn.close()

    def success(self):
        """Process VRP data."""
        self.status = "finalising"
        self.info("Receiving results from worker")
        (stats, vrps) = self.worker.data
        self.info("Sending listener HUP signal")
        os.kill(self.listener.pid, signal.SIGHUP)
        self.info("Sending new VRP set to listener")
        self.listener.p_data.send(vrps)
        self.report(**stats)
        self.result = "ok"
        self.last_end = datetime.datetime.now()
        self.cleanup(process=self.worker)
        self.sleep()

    def failure(self, err=None, process=None, restart=False):
        """Handle worker exception."""
        self.status = "error"
        if err is None:
            try:
                err = process.error
            except Exception as e:
                self.err("Retreiving exception from {} failed"
                         .format(process.__class__.__name__))
                err = e
        self.err(err)
        self.result = "failed"
        self.last_end = datetime.datetime.now()
        if restart:
            self.restart()
        else:
            self.cleanup(process=process)
            self.sleep()

    def report(self, **stats):
        """Report statistics to the agent manager."""
        for name, value in stats.items():
            self.info("{}: {}".format(name, value))
            self.agent_mgr.status_set(name, str(value))

    def cleanup(self, process):
        """Kill the process if it is still running."""
        self.status = "cleanup"
        process_name = process.__class__.__name__
        self.info("Cleaning up {} process".format(process_name))
        if process is not None:
            self.info("Closing connections from {}".format(process_name))
            try:
                for conn in [c for c in
                             [getattr(process, k) for k in dir(process)]
                             if isinstance(c, collections.Hashable)
                             and c in self.watching]:
                    self.unwatch(conn, close=True)
            except Exception as e:
                self.err(e)
            if process.is_alive():
                self.info("Killing {}: pid {}".format(process_name,
                                                      process.pid))
                process.terminate()
                process.join()
        self.info("Cleanup complete")

    def sleep(self):
        """Go to sleep for 'refresh_interval' seconds."""
        self.status = "sleeping"
        self.timeout_time_is(eossdk.now() + self.refresh_interval)

    def shutdown(self):
        """Shutdown the agent gracefully."""
        self.notice("Shutting down")
        try:
            self.cleanup(process=self.worker)
            self.cleanup(process=self.listener)
        except Exception as e:
            self.err(e)
        self.status = "shutdown"
        self.agent_mgr.agent_shutdown_complete_is(True)

    def restart(self):
        """Restart the agent."""
        self.notice("Restarting")
        self.status = "restarting"
        try:
            self.cleanup(process=self.worker)
            self.cleanup(process=self.listener)
        except Exception as e:
            self.err(e)
        self.start()

    def on_initialized(self):
        """Start the agent after initialisation."""
        self.start()

    def on_agent_option(self, key, value):
        """Handle a change to a configuration option."""
        self.set(key, value)

    def on_agent_enabled(self, enabled):
        """Handle a change in the admin state of the agent."""
        if enabled:
            self.notice("Agent enabled")
        else:
            self.notice("Agent disabled")
            self.shutdown()

    def on_timeout(self):
        """Handle a 'refresh_interval' timeout."""
        self.run()

    def on_readable(self, fd):
        """Handle a watched file descriptor becoming readable."""
        self.info("Watched file descriptor {} is readable".format(fd))
        if fd == self.worker.p_data.fileno():
            self.info("Data channel is ready")
            return self.success()
        elif fd == self.worker.p_err.fileno():
            self.info("Exception received from worker")
            return self.failure(process=self.worker)
        elif fd == self.listener.p_err.fileno():
            self.info("Exception received from listener")
            return self.failure(process=self.listener, restart=True)
        else:
            self.warning("Unknown file descriptor: ignoring")
