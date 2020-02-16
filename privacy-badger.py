# -*- coding: utf-8 -*-

"""
==============
Privacy-Badger
==============

Pipe the domain blocked by your privacy-badger.
"""

from __future__ import division, print_function, absolute_import

import json
from typing import List

#####################################################################
#
#####################################################################

def extract_blocked_hosts(
        data: str) -> List[str]:
    """
    Extract the blocked hosts from a privacy-badger export

    Parameters
    ----------
    data: str.
        The exported data, as a json string.

    Returns
    -------
    out: list.
        The list of blocked domains.
    """
    __structured_data = json.loads(data)
    return [
        __domain
        for __domain, __action
        in __structured_data.get("action_map", {}).items()
        if __action["heuristicAction"] == u"block"]
