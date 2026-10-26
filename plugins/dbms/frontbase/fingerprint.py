#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission
"""

from lib.core.common import Backend
from lib.core.common import Format
from lib.core.data import conf
from lib.core.data import kb
from lib.core.data import logger
from lib.core.enums import DBMS
from lib.core.session import setDbms
from lib.core.settings import FRONTBASE_ALIASES
from lib.request import inject
from plugins.generic.fingerprint import Fingerprint as GenericFingerprint

class Fingerprint(GenericFingerprint):
    def __init__(self):
        GenericFingerprint.__init__(self, DBMS.FRONTBASE)

    def getFingerprint(self):
        value = ""
        wsOsFp = Format.getOs("web server", kb.headersFp)

        if wsOsFp:
            value += "%s\n" % wsOsFp

        if kb.data.banner:
            dbmsOsFp = Format.getOs("back-end DBMS", kb.bannerFp)

            if dbmsOsFp:
                value += "%s\n" % dbmsOsFp

        value += 'serverdagi DBMS: '

        if not conf.extensiveFp:
            value += DBMS.FRONTBASE
            return value

        actVer = Format.getDbms()
        blank = " " * 15
        value += 'faol aniqlash: %s' % actVer

        if kb.bannerFp:
            banVer = kb.bannerFp.get("dbmsVersion")

            if banVer:
                banVer = Format.getDbms([banVer])
                value += '\n%sbanner orqali aniqlash: %s' % (blank, banVer)

        htmlErrorFp = Format.getErrorParsedDBMSes()

        if htmlErrorFp:
            value += '\n%sHTML xatosi orqali aniqlash: %s' % (blank, htmlErrorFp)

        return value

    def checkDbms(self):
        if not conf.extensiveFp and Backend.isDbmsWithin(FRONTBASE_ALIASES):
            setDbms(DBMS.FRONTBASE)
            return True

        infoMsg = '%s tekshirilmoqda' % DBMS.FRONTBASE
        logger.info(infoMsg)

        result = inject.checkBooleanExpression("(SELECT degradedTransactions FROM INFORMATION_SCHEMA.IO_STATISTICS)>=0")

        if result:
            infoMsg = '%s tasdiqlanmoqda' % DBMS.FRONTBASE
            logger.info(infoMsg)

            result = inject.checkBooleanExpression("(SELECT TOP (0,1) file_version FROM INFORMATION_SCHEMA.FRAGMENTATION)>=0")

            if not result:
                warnMsg = 'serverdagi DBMS %s emas' % DBMS.FRONTBASE
                logger.warning(warnMsg)

                return False

            setDbms(DBMS.FRONTBASE)

            return True
        else:
            warnMsg = 'serverdagi DBMS %s emas' % DBMS.FRONTBASE
            logger.warning(warnMsg)

            return False
