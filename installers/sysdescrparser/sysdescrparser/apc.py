# -*- coding: utf-8 -*-

"""sysdescrparser.a10."""

from sysdescr import SysDescr


# pylint: disable=no-name-in-module
class APC(SysDescr):

    """Class A10.

    This class is only for vendor definition.

    """

    def __init__(self, raw):
        """Constructor."""
        super(APC, self).__init__(raw)
        self.vendor = 'APC'
        self.model = self.UNKNOWN
        self.os = self.UNKNOWN
        self.version = self.UNKNOWN
        self.devicetype = self.UNKNOWN

    def parse(self):
        """Parsing for sysDescr value."""
        return self
