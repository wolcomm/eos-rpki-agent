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


def main():
    """Run the RpkiAgent."""
    try:
        args = _get_args()
    except KeyboardInterrupt:
        return 1
    except Exception as e:
        print(e)
        return 2
    print("Connecting to {}".format(args.cache_url))
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
