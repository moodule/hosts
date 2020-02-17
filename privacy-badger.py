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
# POLICY
#####################################################################

def get_final_policy(
        action_map: dict,
        user_precedence: bool = False) -> str:
    """
    Gives the final policy for a domain.

    Parameters
    ----------
    action_map: dict.
        The policies of both the user and the badger, for the domain.
    user_precedence: bool.
        Does the user have the final word for the policy?

    Returns
    -------
    out: str.
        The final policy for the domain.
    """
    if user_precedence:
        if action_map["userAction"]:
            return action_map["userAction"]
        else:
            return action_map["heuristicAction"]
    else:
        if action_map["heuristicAction"]:
            return action_map["heuristicAction"]
        else:
            return action_map["userAction"]

#####################################################################
# EXTRACT
#####################################################################

def extract_blocked_hosts(
        data: str,
        user_precedence: bool = False) -> List[str]:
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
        for __domain, __action_map
        in __structured_data.get("action_map", {}).items()
        if is_policy_block(__action_map, user_precedence)]

#####################################################################
# EXPORT
#####################################################################

def format_domain_list_in_dns_hosts_style(
        domains: List[str]) -> List[str]:
    """
    Format a list of domains as a DNS hosts file.

    Parameters
    ----------
    domains: list.
        The list of domains to format.

    Returns
    -------
    out: lsit.
        A list of str lines ready to be written in a hosts file.
    """
    return [
        "0.0.0.0 {}\n".format(__domain)
        for __domain in domains]
