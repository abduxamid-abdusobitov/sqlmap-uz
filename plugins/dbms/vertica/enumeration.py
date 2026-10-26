#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission
"""

from lib.core.data import logger
from plugins.generic.enumeration import Enumeration as GenericEnumeration

class Enumeration(GenericEnumeration):
    def getRoles(self, *args, **kwargs):
        warnMsg = 'Vertica da foydalanuvchi rollarini olish mumkin emas'
        logger.warning(warnMsg)

        return {}
