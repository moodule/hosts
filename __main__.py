# -*- coding: utf-8 -*-

"""
=======
DNS RPZ
=======

Generate DNS RPZ from surfing data.
"""

from __future__ import division, print_function, absolute_import

import json

from privacy_badger import format_as_hosts_blacklist, extract_blacklisted_domains

#####################################################################
# END TO END
#####################################################################

if __name__ == "__main__":
    with open("privacy-badger.dump.json", "r") as __data_file:
        # read the badger's export
        __raw_data = __data_file.readline()

        # retrieve only the blocked domains
        __hosts_blacklist = extract_blacklisted_domains(
            data=__raw_data,
            user_precedence=False)  # trust the badger's heuristic
            
        # write as a DNS hosts file
        with open("hosts", "w") as __hosts_file:
            __hosts_file.writelines(
                format_as_hosts_blacklist(__hosts_blacklist))
