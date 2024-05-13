# -*- coding: utf-8 -*-

"""sysdescrparser.sun."""

from sysdescr import SysDescr


# pylint: disable=no-name-in-module
class Ubiquiti(SysDescr):

    """Class Sun.

    This class is only for vendor definition.

    """

    def __init__(self, raw):
        """Constructor."""
        super(Ubiquiti, self).__init__(raw)
        self.vendor = 'Ubiquiti'
        self.model = self.UNKNOWN
        self.os = self.UNKNOWN
        self.version = self.UNKNOWN

    def parse(self):
        """Parsing for sysDescr value."""
        uap_str = 'uap-hd'
        if self.raw.lower().startswith(uap_str):
            self.devicetype = self.SWITCH
            return self

        return False