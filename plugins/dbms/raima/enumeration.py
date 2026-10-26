#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission
"""

from lib.core.data import logger
from plugins.generic.enumeration import Enumeration as GenericEnumeration

class Enumeration(GenericEnumeration):
    def getBanner(self):
        warnMsg = 'Raima Database Manager da bannerni olish mumkin emas'
        logger.warning(warnMsg)

        return None

    def getCurrentUser(self):
        warnMsg = 'Raima Database Manager da joriy foydalanuvchini olish mumkin emas'
        logger.warning(warnMsg)

    def getCurrentDb(self):
        warnMsg = 'Raima Database Manager da joriy baza nomini olish mumkin emas'
        logger.warning(warnMsg)

    def isDba(self, user=None):
        warnMsg = 'Raima Database Manager da joriy foydalanuvchi DBA ekanini tekshirish mumkin emas'
        logger.warning(warnMsg)

    def getUsers(self):
        warnMsg = 'Raima Database Manager da foydalanuvchilarni olish mumkin emas'
        logger.warning(warnMsg)

        return []

    def getPasswordHashes(self):
        warnMsg = 'Raima Database Manager da foydalanuvchi parol xeshlarini olish mumkin emas'
        logger.warning(warnMsg)

        return {}

    def getPrivileges(self, *args, **kwargs):
        warnMsg = 'Raima Database Manager da foydalanuvchi huquqlarini olish mumkin emas'
        logger.warning(warnMsg)

        return {}

    def getDbs(self):
        warnMsg = "Raima Database Manager da bazalarni olish (faqat '--tables' ishlating) mumkin emas"
        logger.warning(warnMsg)

        return []

    def searchDb(self):
        warnMsg = 'Raima Database Manager da bazalarni qidirish mumkin emas'
        logger.warning(warnMsg)

        return []

    def searchTable(self):
        warnMsg = 'Raima Database Manager da jadvallarni qidirish mumkin emas'
        logger.warning(warnMsg)

        return []

    def searchColumn(self):
        warnMsg = 'Raima Database Manager da ustunlarni qidirish mumkin emas'
        logger.warning(warnMsg)

        return []

    def search(self):
        warnMsg = 'Raima Database Manager da qidirish parametri mavjud emas'
        logger.warning(warnMsg)

    def getHostname(self):
        warnMsg = 'Raima Database Manager da xost nomini olish mumkin emas'
        logger.warning(warnMsg)

    def getStatements(self):
        warnMsg = 'Raima Database Manager da SQL buyruqlarini olish mumkin emas'
        logger.warning(warnMsg)

        return []
