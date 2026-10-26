#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission
"""

from lib.core.data import logger
from plugins.generic.enumeration import Enumeration as GenericEnumeration

class Enumeration(GenericEnumeration):
    def getPasswordHashes(self):
        warnMsg = 'Virtuoso da foydalanuvchi parol xeshlarini olish mumkin emas'
        logger.warning(warnMsg)

        return {}

    def getPrivileges(self, *args, **kwargs):
        warnMsg = 'Virtuoso da foydalanuvchi huquqlarini olish mumkin emas'
        logger.warning(warnMsg)

        return {}

    def getRoles(self, *args, **kwargs):
        warnMsg = 'Virtuoso da foydalanuvchi rollarini olish mumkin emas'
        logger.warning(warnMsg)

        return {}

    def searchDb(self):
        warnMsg = 'Virtuoso da bazalarni qidirish mumkin emas'
        logger.warning(warnMsg)

        return []

    def searchTable(self):
        warnMsg = 'Virtuoso da jadvallarni qidirish mumkin emas'
        logger.warning(warnMsg)

        return []

    def searchColumn(self):
        warnMsg = 'Virtuoso da ustunlarni qidirish mumkin emas'
        logger.warning(warnMsg)

        return []

    def search(self):
        warnMsg = 'Virtuoso da qidirish parametri mavjud emas'
        logger.warning(warnMsg)

    def getStatements(self):
        warnMsg = 'Virtuoso da SQL buyruqlarini olish mumkin emas'
        logger.warning(warnMsg)

        return []
