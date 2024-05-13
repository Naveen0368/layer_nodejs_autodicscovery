# -*- coding: utf-8 -*-

"""sysdescrparser.a10."""

from sysdescr import SysDescr


# pylint: disable=no-name-in-module
class F5(SysDescr):

    """Class A10.

    This class is only for vendor definition.

    """

    def __init__(self, raw):
        """Constructor."""
        super(F5, self).__init__(raw)
        self.vendor = 'F5'
        self.model = self.UNKNOWN
        self.os = self.UNKNOWN
        self.version = self.UNKNOWN
        self.devicetype = self.UNKNOWN

    def parse(self):
        """Parsing for sysDescr value."""
        return self
