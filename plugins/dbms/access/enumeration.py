#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission
"""

from lib.core.data import logger
from plugins.generic.enumeration import Enumeration as GenericEnumeration

class Enumeration(GenericEnumeration):
    def getBanner(self):
        warnMsg = 'Microsoft Access da bannerni olish mumkin emas'
        logger.warning(warnMsg)

        return None

    def getCurrentUser(self):
        warnMsg = 'Microsoft Access da joriy foydalanuvchini olish mumkin emas'
        logger.warning(warnMsg)

    def getCurrentDb(self):
        warnMsg = 'Microsoft Access da joriy baza nomini olish mumkin emas'
        logger.warning(warnMsg)

    def isDba(self, user=None):
        warnMsg = 'Microsoft Access da joriy foydalanuvchi DBA ekanini tekshirish mumkin emas'
        logger.warning(warnMsg)

    def getUsers(self):
        warnMsg = 'Microsoft Access da foydalanuvchilarni olish mumkin emas'
        logger.warning(warnMsg)

        return []

    def getPasswordHashes(self):
        warnMsg = 'Microsoft Access da foydalanuvchi parol xeshlarini olish mumkin emas'
        logger.warning(warnMsg)

        return {}

    def getPrivileges(self, *args, **kwargs):
        warnMsg = 'Microsoft Access da foydalanuvchi huquqlarini olish mumkin emas'
        logger.warning(warnMsg)

        return {}

    def getDbs(self):
        warnMsg = "Microsoft Access da bazalarni olish (faqat '--tables' ishlating) mumkin emas"
        logger.warning(warnMsg)

        return []

    def searchDb(self):
        warnMsg = 'Microsoft Access da bazalarni qidirish mumkin emas'
        logger.warning(warnMsg)

        return []

    def searchTable(self):
        warnMsg = 'Microsoft Access da jadvallarni qidirish mumkin emas'
        logger.warning(warnMsg)

        return []

    def searchColumn(self):
        warnMsg = 'Microsoft Access da ustunlarni qidirish mumkin emas'
        logger.warning(warnMsg)

        return []

    def search(self):
        warnMsg = 'Microsoft Access da qidirish parametri mavjud emas'
        logger.warning(warnMsg)

    def getHostname(self):
        warnMsg = 'Microsoft Access da xost nomini olish mumkin emas'
        logger.warning(warnMsg)

    def getStatements(self):
        warnMsg = 'Microsoft Access da SQL buyruqlarini olish mumkin emas'
        logger.warning(warnMsg)

        return []
