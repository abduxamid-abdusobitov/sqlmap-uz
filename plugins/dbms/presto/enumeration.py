#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission
"""

from lib.core.data import logger
from plugins.generic.enumeration import Enumeration as GenericEnumeration

class Enumeration(GenericEnumeration):
    # NOTE: getBanner()/getCurrentDb() are intentionally NOT overridden - modern Presto/Trino expose
    # version() and current_schema (wired in queries.xml), so the generic implementations work.

    def isDba(self, user=None):
        warnMsg = 'Presto da joriy foydalanuvchi DBA ekanini tekshirish mumkin emas'
        logger.warning(warnMsg)

    def getUsers(self):
        warnMsg = 'Presto da foydalanuvchilarni olish mumkin emas'
        logger.warning(warnMsg)

        return []

    def getPasswordHashes(self):
        warnMsg = 'Presto da foydalanuvchi parol xeshlarini olish mumkin emas'
        logger.warning(warnMsg)

        return {}

    def getPrivileges(self, *args, **kwargs):
        warnMsg = 'Presto da foydalanuvchi huquqlarini olish mumkin emas'
        logger.warning(warnMsg)

        return {}

    def getRoles(self, *args, **kwargs):
        warnMsg = 'Presto da foydalanuvchi rollarini olish mumkin emas'
        logger.warning(warnMsg)

        return {}

    def getHostname(self):
        warnMsg = 'Presto da xost nomini olish mumkin emas'
        logger.warning(warnMsg)

    def getStatements(self):
        warnMsg = 'Presto da SQL buyruqlarini olish mumkin emas'
        logger.warning(warnMsg)

        return []
