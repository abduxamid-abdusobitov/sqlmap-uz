#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission
"""

from lib.core.data import logger
from plugins.generic.enumeration import Enumeration as GenericEnumeration

class Enumeration(GenericEnumeration):
    def getDbs(self):
        warnMsg = "Firebird da bazalarni olish (faqat '--tables' ishlating) mumkin emas"
        logger.warning(warnMsg)

        return []

    def getPasswordHashes(self):
        warnMsg = 'Firebird da foydalanuvchi parol xeshlarini olish mumkin emas'
        logger.warning(warnMsg)

        return {}

    def searchDb(self):
        warnMsg = 'Firebird da bazalarni qidirish mumkin emas'
        logger.warning(warnMsg)

        return []

    def getHostname(self):
        warnMsg = 'Firebird da xost nomini olish mumkin emas'
        logger.warning(warnMsg)

    def getStatements(self):
        warnMsg = 'Firebird da SQL buyruqlarini olish mumkin emas'
        logger.warning(warnMsg)

        return []
