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

import pyeapi
import requests

from rpki_agent.base import RpkiBase
from rpki_agent.vrp import VRP, VRPSet
from rpki_agent.exceptions import handle_sigterm, TermException


class RpkiWorker(multiprocessing.Process, RpkiBase):
    """Worker to fetch and process RPKI VRP data."""

    def __init__(self, cache_url, *args, **kwargs):
        """Initialise an RpkiWorker instance."""
        super(RpkiWorker, self).__init__(*args, **kwargs)
        RpkiBase.__init__(self)
        self.cache_url = cache_url
        self.p_err, self.c_err = multiprocessing.Pipe(duplex=False)
        self.p_data, self.c_data = multiprocessing.Pipe(duplex=False)

    def run(self):
        """Run the worker process."""
        self.info("Worker started")
        signal.signal(signal.SIGTERM, handle_sigterm)
        try:
            stats = dict()
            self.node = self.connect_eapi()
            vrps = self.fetch()
            all_origins = set()
            self.info("Calculating statistics")
            for afi in ("ipv4", "ipv6"):
                covered = vrps.covered(afi)
                origins = vrps.origins(afi)
                stats["covered_prefixes_{}".format(afi)] = len(covered)
                stats["origin_asns_{}".format(afi)] = len(origins)
                all_origins.update(origins)
            stats["origin_asns_total"] = len(all_origins)
            self.c_data.send((stats, vrps))
        except TermException:
            self.notice("Got SIGTERM signal: exiting.")
        except Exception as e:
            self.err(e)
            self.c_err.send(e)
        finally:
            self.c_err.close()
            self.c_data.close()

    def connect_eapi(self):
        """Connect to the local eapi unix domain socket."""
        self.info("Trying to connect to local eapi endpoint")
        connection = pyeapi.client.connect(transport="socket")
        node = pyeapi.client.Node(connection=connection)
        self.info("Connected to eapi endpoint with version {}"
                  .format(node.version))
        return node

    def fetch(self):
        """Fetch VRP set from the RPKI validation cache."""
        self.info("Getting VRP set from {}".format(self.cache_url))
        with requests.Session() as s:
            resp = s.get(self.cache_url,
                         headers={"Accept": "application/json"})
            data = resp.json()
        vrps = VRPSet([VRP(**r) for r in data["roas"]])
        self.info("Fetched {} VRPs".format(len(vrps)))
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
