#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission
"""

from lib.core.data import logger
from plugins.generic.enumeration import Enumeration as GenericEnumeration

class Enumeration(GenericEnumeration):
    def getBanner(self):
        warnMsg = 'FrontBase da bannerni olish mumkin emas'
        logger.warning(warnMsg)

        return None

    def getPrivileges(self, *args, **kwargs):
        warnMsg = 'FrontBase da foydalanuvchi huquqlarini olish mumkin emas'
        logger.warning(warnMsg)

        return {}

    def getHostname(self):
        warnMsg = 'FrontBase da xost nomini olish mumkin emas'
        logger.warning(warnMsg)

    def getStatements(self):
        warnMsg = 'FrontBase da SQL buyruqlarini olish mumkin emas'
        logger.warning(warnMsg)

        return []
