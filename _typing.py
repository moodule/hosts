# -*- coding: utf-8 -*-

"""
=============
Custom Typing
=============

Pipe the domain blocked by your privacy-badger.
"""

from __future__ import division, print_function, absolute_import

import json
from typing import Literal, TypedDict

#####################################################################
# DNS POLICIES
#####################################################################

DnsPolicy = Literal[u"", u"block", u"allow"]

#####################################################################
# ACTION MAPS
#####################################################################

class PrivacyBadgerActionMap(TypedDict):
	action_map: dict
	settings_map: dict
	snitch_map: dict
