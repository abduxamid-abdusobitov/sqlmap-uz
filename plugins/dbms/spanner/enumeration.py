#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission
"""

from lib.core.data import logger
from lib.core.settings import SPANNER_DEFAULT_SCHEMA
from plugins.generic.enumeration import Enumeration as GenericEnumeration

class Enumeration(GenericEnumeration):
    def getCurrentDb(self):
        return SPANNER_DEFAULT_SCHEMA

    def getCurrentUser(self):
        warnMsg = 'Spanner da joriy foydalanuvchini olish mumkin emas'
        logger.warning(warnMsg)

    def isDba(self, user=None):
        warnMsg = 'Spanner da joriy foydalanuvchi DBA ekanini tekshirish mumkin emas'
        logger.warning(warnMsg)

    def getUsers(self):
        warnMsg = 'Spanner da foydalanuvchilarni olish mumkin emas'
        logger.warning(warnMsg)

        return []

    def getPasswordHashes(self):
        warnMsg = 'Spanner da foydalanuvchi parol xeshlarini olish mumkin emas'
        logger.warning(warnMsg)

        return {}

    def getRoles(self, *args, **kwargs):
        warnMsg = 'Spanner da foydalanuvchi rollarini olish mumkin emas'
        logger.warning(warnMsg)

        return {}

    def getPrivileges(self, *args, **kwargs):
        warnMsg = 'Spanner da foydalanuvchi huquqlarini olish mumkin emas'
        logger.warning(warnMsg)

        return {}

    def getHostname(self):
        warnMsg = 'Spanner da xost nomini olish mumkin emas'
        logger.warning(warnMsg)
