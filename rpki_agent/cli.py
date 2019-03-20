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

import sys

import eossdk

from rpki_agent import RpkiAgent


def main():
    """Run the RpkiAgent."""
    try:
        # get an instance of the EOS SDK
        sdk = eossdk.Sdk()
        # create a Sysdb mount profile, restarting if necessary
        if RpkiAgent.set_sysdb_mp(eossdk.name()):
            # return a user defined status to indicate
            # that a restart is desired
            return 64
        # create an instance of the RpkiAgent
        agent = RpkiAgent(sdk, args)  # noqa: W0612
        # enter the sdk event-loop
        sdk.main_loop()
    except KeyboardInterrupt:
        return 130
    except Exception:
        return 1
    return


if __name__ == "__main__":
    sys.exit(main())
