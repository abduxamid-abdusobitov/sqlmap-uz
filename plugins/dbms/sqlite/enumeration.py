#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission
"""

from lib.core.data import logger
from lib.core.exception import SqlmapUnsupportedFeatureException
from plugins.generic.enumeration import Enumeration as GenericEnumeration

class Enumeration(GenericEnumeration):
    def getCurrentUser(self):
        warnMsg = 'SQLite da joriy foydalanuvchini olish mumkin emas'
        logger.warning(warnMsg)

    def getCurrentDb(self):
        warnMsg = 'SQLite da joriy baza nomini olish mumkin emas'
        logger.warning(warnMsg)

    def isDba(self, user=None):
        warnMsg = 'SQLite da joriy foydalanuvchi barcha huquqlarga ega'
        logger.warning(warnMsg)

        return True

    def getUsers(self):
        warnMsg = 'SQLite da foydalanuvchilarni olish mumkin emas'
        logger.warning(warnMsg)

        return []

    def getPasswordHashes(self):
        warnMsg = 'SQLite da foydalanuvchi parol xeshlarini olish mumkin emas'
        logger.warning(warnMsg)

        return {}

    def getPrivileges(self, *args, **kwargs):
        warnMsg = 'SQLite da foydalanuvchi huquqlarini olish mumkin emas'
        logger.warning(warnMsg)

        return {}

    def getDbs(self):
        warnMsg = "SQLite da bazalarni olish (faqat '--tables' ishlating) mumkin emas"
        logger.warning(warnMsg)

        return []

    def searchDb(self):
        warnMsg = 'SQLite da bazalarni qidirish mumkin emas'
        logger.warning(warnMsg)

        return []

    def searchColumn(self):
        errMsg = 'SQLite da ustunlarni qidirish mumkin emas'
        raise SqlmapUnsupportedFeatureException(errMsg)

    def getHostname(self):
        warnMsg = 'SQLite da xost nomini olish mumkin emas'
        logger.warning(warnMsg)

    def getStatements(self):
        warnMsg = 'SQLite da SQL buyruqlarini olish mumkin emas'
        logger.warning(warnMsg)

        return []
