# -*- coding: utf-8 -*-

"""sysdescrparser.a10_acos."""


import re
from vmware import Vmware


# pylint: disable=no-member
class VmwareEsxi(Vmware):

    """Class A10ACOS.

    SNMP sysDescr for A10ACOS.

    """

    def __init__(self, raw):
        """Constructor."""
        super(VmwareEsxi, self).__init__(raw)
        self.os = 'ESXi'
        self.model = self.UNKNOWN
        self.version = self.UNKNOWN
        self.devicetype = self.UNKNOWN


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
        if "esxi" in self.raw.lower():
            self.devicetype = self.HYPERVISOR
            return self

        return False
