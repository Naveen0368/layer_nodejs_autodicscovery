# -*- coding: utf-8 -*-

"""sysdescrparser.sun."""

from sysdescr import SysDescr


# pylint: disable=no-name-in-module
class Nimble(SysDescr):

    """Class Sun.

    This class is only for vendor definition.

    """

    def __init__(self, raw):
        """Constructor."""
        super(Nimble, self).__init__(raw)
        self.vendor = 'Nimble'
        self.model = self.UNKNOWN
        self.os = self.UNKNOWN
        self.version = self.UNKNOWN

    def parse(self):
        """Parsing for sysDescr value."""
        uap_str = 'nimble'
        if self.raw.lower().startswith(uap_str):
            self.devicetype = self.STORAGE
            return self

        return False