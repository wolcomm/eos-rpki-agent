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
"""rpki_agent listener module."""

from __future__ import print_function

import multiprocessing
import signal
import time

import flask
import gunicorn.app.base

from rpki_agent.base import RpkiBase
# from rpki_agent.vrp import VRP, VRPSet
from rpki_agent.exceptions import handle_sigterm, TermException


class RpkiListener(multiprocessing.Process, RpkiBase):
    """Listener to respond to requests for RPKI VRP config data."""

    def __init__(self, *args, **kwargs):
        """Initialise an RpkiListener instance."""
        super(RpkiListener, self).__init__(*args, **kwargs)
        RpkiBase.__init__(self)
        self.p_err, self.c_err = multiprocessing.Pipe(duplex=False)
        self.c_data, self.p_data = multiprocessing.Pipe(duplex=False)

    def run(self):
        """Run the listener process."""
        self.info("Listener started")
        signal.signal(signal.SIGTERM, handle_sigterm)
        try:
            http_server = RpkiHttpServer(conn=self.c_data)
            http_server.run()
        except TermException:
            self.notice("Got SIGTERM signal: exiting.")
        except Exception as e:
            self.err(e)
            self.c_err.send(e)
        finally:
            self.c_err.close()
            self.c_data.close()

    @property
    def error(self):
        """Get exception raised by listener."""
        if self.p_err.poll():
            return self.p_err.recv()


class RpkiHttpServer(gunicorn.app.base.BaseApplication, RpkiBase):
    """An integrated webserver."""

    app = flask.Flask(__name__)

    def __init__(self, conn, *args, **kwargs):
        """Initialise an RpkiHttpServer instance."""
        RpkiBase.__init__(self)
        self.conn = conn
        self.vrps = None
        self.origins = set()
        self.covered = {"ipv4": [], "ipv6": []}
        self.for_origin = {"ipv4": {}, "ipv6": {}}
        super(RpkiHttpServer, self).__init__(*args, **kwargs)
        self.cfg.set("workers", multiprocessing.cpu_count() * 2)

    def load(self):
        """Load WSGI application."""
        return self.app

    def load_config(self):
        """Reload VRP data and process config objects."""
        if self.get_vrps():
            self.process_vrps()

    def get_vrps(self):
        """Receive VRP set from agent process."""
        self.info("Trying to get new VRP data from agent")
        for i in range(3):
            time.sleep(1)
            if self.conn.poll():
                self.vrps = self.conn.recv()
                self.info("Got data on try {}".format(i))
                return True
            self.info("Nothing to receive on try {}".format(i))
        self.warning("No data received from agent")
        return False

    def process_vrps(self):
        """Pre-process VRP set into EOS config syntax."""
        self.origins = set()
        for afi in ("ipv4", "ipv6"):
            self.info("Creating prefix-lists for {} address-family"
                      .format(afi))
            self.covered[afi] = ["seq {seq} permit {prefix} le {maxLength}"
                                 .format(seq=seq, **entry)
                                 for seq, entry
                                 in enumerate(self.vrps.covered(afi))]
            origins = self.vrps.origins(afi)
            self.for_origin[afi] = {}
            for asn in origins:
                self.for_origin[afi][asn] = ["seq {seq} permit {prefix} le {maxLength}"  # noqa: E501
                                             .format(seq=seq, **entry)
                                             for seq, entry
                                             in enumerate(self.vrps.for_origin(asn, afi))]  # noqa: E501
            self.origins.update(origins)

    def run(self, *args, **kwargs):
        """Run the webserver."""
        @self.app.route("/prefix-lists/<afi>/covered")
        def covered(afi):
            try:
                return "\n".join(self.covered[afi])
            except KeyError:
                flask.abort(404)

        @self.app.route("/prefix-lists/<afi>/origin/<origin>")
        def for_origin(afi, origin):
            try:
                return "\n".join(self.for_origin[afi][origin])
            except KeyError:
                flask.abort(404)

        @self.app.route("/as-paths/<origin>")
        def as_path(origin):
            if origin in self.origins:
                return "permit _{}$ any\n".format(origin)
            else:
                flask.abort(404)

        super(RpkiHttpServer, self).run(*args, **kwargs)
