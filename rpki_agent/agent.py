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

import filecmp
import os
import shutil
import tempfile

import eossdk


class RpkiAgent(eossdk.AgentHandler, eossdk.TimeoutHandler):
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
        self.name = sdk.name()
        self.tracer = eossdk.Tracer(self.name)
        # get sdk managers
        self.agent_mgr = sdk.get_agent_mgr()
        self.timeout_mgr = sdk.get_timeout_mgr()
        # init sdk handlers
        eossdk.AgentHandler.__init__(self, self.agent_mgr)
        eossdk.TimeoutHandler.__init__(self, self.timeout_mgr)
        # set default confg options
        self._cache_url = None
        self._refresh_interval = 10
        # create state containers
        self._status = None
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
        self.agent_mgr.status_set("status", self._status)
        self.trace("Status: {}".format(self.status))

    def trace(self, msg, level=0):
        """Write tracing output."""
        self.tracer.trace(level, msg)

    def configure(self):
        """Read and set all configuration options."""
        self.trace("Reading configuration options")
        for key in self.agent_mgr.agent_option_iter():
            value = self.agent_mgr.agent_option(key)
            self.set(key, value)

    def set(self, key, value):
        """Set a configuration option."""
        if not value:
            value = None
        self.trace("Setting configuration '{}'='{}'".format(key, value))
        if key in self.agent_options:
            setattr(self, key, value)
        else:
            self.trace("Ignoring unknown option '{}'".format(key))

    def run(self):
        """Refresh VRP data and update state."""
        self.status = "running"
        if self.cache_url is not None:
            self.trace("Getting VRP set from {}".format(self.cache_url))
        else:
            self.trace("'cache_url' is not set".format(self.cache_url))
        self.sleep()

    def sleep(self):
        """Go to sleep for 'refresh_interval' seconds."""
        self.status = "sleeping"
        self.timeout_time_is(eossdk.now() + self.refresh_interval)

    def on_initialized(self):
        """Start the agent after initialisation."""
        self.status = "init"
        self.configure()
        self.run()

    def on_agent_option(self, key, value):
        """Handle a change to a configuration option."""
        self.set(key, value)

    def on_timeout(self):
        """Handle a 'refresh_interval' timeout."""
        self.run()
