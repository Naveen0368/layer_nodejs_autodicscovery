# -*- coding: utf-8 -*-

"""sysdescrparser.a10_acos."""


import re
from f5 import F5


# pylint: disable=no-member
class F5BIGIP(F5):

    """Class A10ACOS.

    SNMP sysDescr for A10ACOS.

    """

    def __init__(self, raw):
        """Constructor."""
        super(F5BIGIP, self).__init__(raw)
        self.os = 'F5 BIG-IP'
        self.model = self.UNKNOWN
        self.version = self.UNKNOWN

    # def parseFIXME(self):
    #     """Parse."""
    #     regex = (r'^(?:AX\s+Series\s+Advanced\s+Traffic'
    #              r'\s+Manager|Thunder\s+Series\s+Unified'
    #              r'\s+Application\s+Service\s+Gateway)\s+(.*),(?:\s+|)'
    #              r'.*\s+(?:version|ACOS)\s+(.*),')
    #     pat = re.compile(regex)
    #     res = pat.search(self.raw)
    #     if res:
    #         self.model = res.group(1)
    #         self.version = res.group(2)
    #         self.device_type = ""
    #         return self
    #     return False


    def parse(self):
        """Parse."""
        # BIG-IP 2200 : Linux 3.10.0-514.26.2.el7.x86_64 : BIG-IP software release 13.1.1.2, build 0.0.4
        if self.raw.lower().startswith("big-ip"):
            self.device_type = self.LOADBALANCER
            return self

        return False
