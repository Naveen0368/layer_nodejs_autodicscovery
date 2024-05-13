# -*- coding: utf-8 -*-

"""sysdescrparser.a10_acos."""


import re
from apc import APC

# pylint: disable=no-member
class APCAP(APC):

    """Class A10ACOS.

    SNMP sysDescr for A10ACOS.

    """

    def __init__(self, raw):
        """Constructor."""
        super(APCAP, self).__init__(raw)
        self.os = 'APC OS'
        self.model = self.UNKNOWN
        self.version = self.UNKNOWN
        self.device_type = self.UNKNOWN


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
        if self.raw.lower().startswith("apc") and "os" in self.raw.lower():
            self.device_type = self.POWER
            return self

        return False
