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

import eossdk
import requests

from rpki_agent.vrp import VRP


class RpkiWorker(multiprocessing.Process):
    """Worker to fetch and process RPKI VRP data."""

    def __init__(self, cache_url, *args, **kwargs):
        """Initialise a RpkiWorker instance."""
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
        try:
            self.trace("Getting VRP set from {}".format(self.cache_url))
            with requests.Session() as s:
                resp = s.get(self.cache_url,
                             headers={"Accept": "application/json"})
                data = resp.json()
            vrps = [VRP(**r) for r in data["roas"]]
            self.trace("Fetched {} VRPs".format(len(vrps)))
            self.c_data.send(vrps)
        except Exception as e:
            self.trace(e)
            self.c_err.send(e)
        finally:
            self.c_err.close()
            self.c_data.close()

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
