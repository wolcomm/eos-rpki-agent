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
"""rpki_agent worker functions."""

from __future__ import print_function

import multiprocessing
import signal

import eossdk
import requests

from rpki_agent.vrp import VRP, VRPSet
from rpki_agent.exceptions import handle_sigterm, TermException


class RpkiWorker(multiprocessing.Process):
    """Worker to fetch and process RPKI VRP data."""

    def __init__(self, cache_url, *args, **kwargs):
        """Initialise an RpkiWorker instance."""
        super(RpkiWorker, self).__init__(*args, **kwargs)
        self.tracer = eossdk.Tracer(self.__class__.__name__)
        self.cache_url = cache_url
        self.p_err, self.c_err = multiprocessing.Pipe(duplex=False)
        self.p_data, self.c_data = multiprocessing.Pipe(duplex=False)

    def trace(self, msg, level=0):
        """Write tracing output."""
        self.tracer.trace(level, str(msg))

    def run(self):
        """Run the worker process."""
        signal.signal(signal.SIGTERM, handle_sigterm)
        try:
            vrps = self.fetch()
            self.trace("Got {} ipv4 and {} ipv6 covered prefixes"
                       .format(len(vrps.covered("ipv4")),
                               len(vrps.covered("ipv6"))))
            self.trace("Got {} ipv4 and {} ipv6 origin ASNs"
                       .format(len(vrps.origins("ipv4")),
                               len(vrps.origins("ipv6"))))
            self.c_data.send(vrps)
        except TermException:
            self.trace("Got SIGTERM signal: exiting.")
        except Exception as e:
            self.trace(e)
            self.c_err.send(e)
        finally:
            self.c_err.close()
            self.c_data.close()

    def fetch(self):
        """Fetch VRP set from the RPKI validation cache."""
        self.trace("Getting VRP set from {}".format(self.cache_url))
        with requests.Session() as s:
            resp = s.get(self.cache_url,
                         headers={"Accept": "application/json"})
            data = resp.json()
        vrps = VRPSet([VRP(**r) for r in data["roas"]])
        self.trace("Fetched {} VRPs".format(len(vrps)))
        return vrps

    @property
    def data(self):
        """Get data from the worker."""
        if self.p_data.poll():
            return self.p_data.recv()

    @property
    def error(self):
        """Get exception raised by worker."""
        if self.p_err.poll():
            return self.p_err.recv()
