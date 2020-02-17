# -*- coding: utf-8 -*-

"""
=============
Custom Typing
=============

Pipe the domain blocked by your privacy-badger.
"""

from __future__ import division, print_function, absolute_import

import json
from typing import Literal

#####################################################################
# DNS POLICIES
#####################################################################

DnsPolicy = Literal[u"", u"block", u"allow"]
