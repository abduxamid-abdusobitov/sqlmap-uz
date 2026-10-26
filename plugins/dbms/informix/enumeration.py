#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission
"""

from lib.core.data import logger
from plugins.generic.enumeration import Enumeration as GenericEnumeration

class Enumeration(GenericEnumeration):
    def searchDb(self):
        warnMsg = 'Informix da bazalarni qidirish yaratilmagan'
        logger.warning(warnMsg)

        return []

    def searchTable(self):
        warnMsg = 'Informix da jadvallarni qidirish yaratilmagan'
        logger.warning(warnMsg)

        return []

    def searchColumn(self):
        warnMsg = 'Informix da ustunlarni qidirish yaratilmagan'
        logger.warning(warnMsg)

        return []

    def search(self):
        warnMsg = 'Informix da qidirish parametri mavjud emas'
        logger.warning(warnMsg)

    def getStatements(self):
        warnMsg = 'Informix da SQL buyruqlarini olish mumkin emas'
        logger.warning(warnMsg)

        return []
