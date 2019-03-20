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
"""rpki_agent vrp module."""

from __future__ import print_function

import ipaddress


class VRP(object):
    """A validated ROA payload object."""

    def __init__(self, **kwargs):
        """Initialize a VRP."""
        self.as_dict = kwargs
        for k, v in kwargs.items():
            setattr(self, k, v)

    @property
    def afi(self):
        """Get the address-family of the VRP."""
        return "ipv{}".format(ipaddress.ip_network(self.prefix).version)

    @property
    def key(self):
        """Get a hashable tuple of attributes."""
        return (self.asn, self.prefix, self.maxLength, self.ta)

    @property
    def as_number(self):
        """Get the bare AS number of the VRP."""
        return self.asn.lstrip("AS")

    @property
    def prefix_len(self):
        """Get the prefix length of self.prefix."""
        return ipaddress.ip_network(self.prefix).prefixlen

    @property
    def len_range(self):
        """Check whether the VRP matches a range of prefix lengths."""
        return (self.maxLength > self.prefix_len)

    def __hash__(self):
        """Make VRP objects hashable."""
        return hash(self.key)

    def __repr__(self):
        """Representation as a dict."""
        return self.as_dict.__repr__()
