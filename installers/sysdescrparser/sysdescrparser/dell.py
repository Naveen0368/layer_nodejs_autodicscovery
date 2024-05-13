# -*- coding: utf-8 -*-

"""sysdescrparser.sun."""

from sysdescr import SysDescr


# pylint: disable=no-name-in-module
class Dell(SysDescr):

    """Class Sun.

    This class is only for vendor definition.

    """

    def __init__(self, raw):
        """Constructor."""
        super(Dell, self).__init__(raw)
        self.vendor = 'Dell'
        self.model = self.UNKNOWN
        self.os = self.UNKNOWN
        self.version = self.UNKNOWN

    def parse(self):
        """Parsing for sysDescr value."""
        dell_str = "dell"
        if self.raw.lower().startswith(dell_str):
            self.devicetype = self.SERVER
        return self
