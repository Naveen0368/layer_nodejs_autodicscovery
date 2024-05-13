# -*- coding: utf-8 -*-

"""sysdescrparser.brocade."""

from sysdescr import SysDescr


# pylint: disable=no-name-in-module
class Vmware(SysDescr):

    """Class Brocade.

    This class is only for vendor definition.

    """

    def __init__(self, raw):
        """Constructor."""
        super(Vmware, self).__init__(raw)
        self.vendor = 'Vmware'
        self.model = self.UNKNOWN
        self.os = self.UNKNOWN
        self.version = self.UNKNOWN

    def parse(self):
        """Parsing for sysDescr value."""
        return self
