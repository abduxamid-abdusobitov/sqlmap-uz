#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission
"""

from lib.core.data import logger
from lib.core.settings import CACHE_DEFAULT_SCHEMA
from plugins.generic.enumeration import Enumeration as GenericEnumeration

class Enumeration(GenericEnumeration):
    def getCurrentDb(self):
        return CACHE_DEFAULT_SCHEMA

    def getUsers(self):
        warnMsg = 'Cache da foydalanuvchilarni olish mumkin emas'
        logger.warning(warnMsg)

        return []

    def getPasswordHashes(self):
        warnMsg = 'Cache da parol xeshlarini olish mumkin emas'
        logger.warning(warnMsg)

        return {}

    def getPrivileges(self, *args, **kwargs):
        warnMsg = 'Cache da foydalanuvchi huquqlarini olish mumkin emas'
        logger.warning(warnMsg)

        return {}

    def getStatements(self):
        warnMsg = 'Cache da SQL buyruqlarini olish mumkin emas'
        logger.warning(warnMsg)

        return []

    def getRoles(self, *args, **kwargs):
        warnMsg = 'Cache da foydalanuvchi rollarini olish mumkin emas'
        logger.warning(warnMsg)

        return {}

    def getHostname(self):
        warnMsg = 'Cache da xost nomini olish mumkin emas'
        logger.warning(warnMsg)
