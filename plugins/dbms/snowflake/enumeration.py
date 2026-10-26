#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission
"""

from lib.core.data import logger
from lib.core.exception import SqlmapUnsupportedFeatureException
from plugins.generic.enumeration import Enumeration as GenericEnumeration

class Enumeration(GenericEnumeration):
    def getPasswordHashes(self):
        warnMsg = 'Snowflake da foydalanuvchi parol xeshlarini olish mumkin emas'
        logger.warning(warnMsg)
        return {}

    def getRoles(self, *args, **kwargs):
        warnMsg = 'Snowflake da foydalanuvchi rollarini olish mumkin emas'
        logger.warning(warnMsg)

        return {}

    def searchDb(self):
        warnMsg = 'Snowflake da bazalarni qidirish mumkin emas'
        logger.warning(warnMsg)
        return []

    def searchColumn(self):
        errMsg = 'Snowflake da ustunlarni qidirish mumkin emas'
        raise SqlmapUnsupportedFeatureException(errMsg)
