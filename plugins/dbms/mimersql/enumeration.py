#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission
"""

from lib.core.data import logger
from plugins.generic.enumeration import Enumeration as GenericEnumeration

class Enumeration(GenericEnumeration):
    def getPasswordHashes(self):
        warnMsg = 'MimerSQL da parol xeshlarini olish mumkin emas'
        logger.warning(warnMsg)

        return {}

    def getStatements(self):
        warnMsg = 'MimerSQL da SQL buyruqlarini olish mumkin emas'
        logger.warning(warnMsg)

        return []

    def getRoles(self, *args, **kwargs):
        warnMsg = 'MimerSQL da foydalanuvchi rollarini olish mumkin emas'
        logger.warning(warnMsg)

        return {}

    def getHostname(self):
        warnMsg = 'MimerSQL da xost nomini olish mumkin emas'
        logger.warning(warnMsg)
