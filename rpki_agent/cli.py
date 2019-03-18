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
"""rpki_agent cli entry point."""

from __future__ import print_function
from __future__ import unicode_literals

import argparse
import sys

import eossdk


class RpkiAgent(eossdk.AgentHandler):
    """An EOS SDK based agent that creates routing policy objects."""

    def __init__(self, sdk, args):
        """Initialise the agent instance."""
        self.name = self.__class__.__name__
        self.tracer = sdk.Tracer(self.name)
        self.tracer.trace0("Setting up {}".format(self.name))
        self.args = args
        self.agent_mgr = sdk.get_agent_mgr()
        eossdk.AgentHandler.__init__(self, self.agent_mgr)
        self.tracer.trace0("Set up done")

    def on_initialized(self):
        """Handle the initialised event from the AgentHandler."""
        self.tracer.trace0("Connecting to {}".format(self.args.cache_url))


def main():
    """Run the RpkiAgent."""
    try:
        # get an instance of the EOS SDK
        sdk = eossdk.Sdk()
    except Exception as e:
        return 3
    try:
        # parse any cli arguments
        args = _get_args()
        # create an instance of the RpkiAgent
        agent = RpkiAgent(sdk, args)  # noqa: W0612
        # enter the sdk event-loop
        sdk.main_loop()
    except KeyboardInterrupt:
        return 1
    except Exception as e:
        print(e)
        return 2
    return


def _get_args():
    """Parse cli args and return."""
    # set up the cli args parser
    parser = argparse.ArgumentParser()
    parser.add_argument("--cache-url", "-c", type=str, required=True)
    # get cli args
    args = parser.parse_args()
    return args


if __name__ == "__main__":
    sys.exit(main())
