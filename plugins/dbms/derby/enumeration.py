#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission
"""

from lib.core.common import singleTimeWarnMessage
from lib.core.data import logger
from plugins.generic.enumeration import Enumeration as GenericEnumeration

class Enumeration(GenericEnumeration):
    def getPasswordHashes(self):
        warnMsg = 'Apache Derby da parol xeshlarini olish mumkin emas'
        logger.warning(warnMsg)

        return {}

    def getStatements(self):
        warnMsg = 'Apache Derby da SQL buyruqlarini olish mumkin emas'
        logger.warning(warnMsg)

        return []

    def getPrivileges(self, *args, **kwargs):
        warnMsg = 'Apache Derby da foydalanuvchi huquqlarini olish mumkin emas'
        logger.warning(warnMsg)

        return {}

    def getRoles(self, *args, **kwargs):
        warnMsg = 'Apache Derby da foydalanuvchi rollarini olish mumkin emas'
        logger.warning(warnMsg)

        return {}

    def getHostname(self):
        warnMsg = 'Apache Derby da xost nomini olish mumkin emas'
        logger.warning(warnMsg)

    def getBanner(self):
        warnMsg = 'Apache Derby da bannerni olish mumkin emas'
        singleTimeWarnMessage(warnMsg)
