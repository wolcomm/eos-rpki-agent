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

import collections
import ipaddress

from aggregate_prefixes.aggregate_prefixes import aggregate_prefixes


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


class VRPSet(collections.Set):
    """A set of VRPs."""

    def __init__(self, iterable):
        """Initialise a VRPSet."""
        self.elements = set(iterable)

    def __iter__(self):
        """Implement iteration."""
        return self.elements.__iter__()

    def __contains__(self, value):
        """Implement membership."""
        return self.elements.__contains__(value)

    def __len__(self):
        """Implement sizing."""
        return self.elements.__len__()

    def covered(self, afi):
        """Return a set of prefixes covered by the VRP set."""
        return set(aggregate_prefixes([vrp.prefix for vrp in self
                                       if vrp.afi == afi]))

    def origins(self, afi):
        """Return a set of origins in the VRP set."""
        return set([vrp.as_number for vrp in self
                    if vrp.afi == afi and vrp.asn != "AS0"])

    def prefixes_by_origin(self, origin, afi):
        """Return the VRPSet of VRPs with the given origin AS."""
        return VRPSet([vrp for vrp in self
                       if vrp.as_number == origin and vrp.afi == afi])
