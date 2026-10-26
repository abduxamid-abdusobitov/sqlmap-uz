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
from lib.core.settings import ALTIBASE_ALIASES
from lib.request import inject
from plugins.generic.fingerprint import Fingerprint as GenericFingerprint

class Fingerprint(GenericFingerprint):
    def __init__(self):
        GenericFingerprint.__init__(self, DBMS.ALTIBASE)

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
            value += DBMS.ALTIBASE
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
        if not conf.extensiveFp and Backend.isDbmsWithin(ALTIBASE_ALIASES):
            setDbms(DBMS.ALTIBASE)

            self.getBanner()

            return True

        infoMsg = '%s tekshirilmoqda' % DBMS.ALTIBASE
        logger.info(infoMsg)

        # Reference: http://support.altibase.com/fileDownload.do?gubun=admin&no=228
        result = inject.checkBooleanExpression("CHOSUNG(NULL) IS NULL")

        if result:
            infoMsg = '%s tasdiqlanmoqda' % DBMS.ALTIBASE
            logger.info(infoMsg)

            result = inject.checkBooleanExpression("TDESENCRYPT(NULL,NULL) IS NULL")

            if not result:
                warnMsg = 'serverdagi DBMS %s emas' % DBMS.ALTIBASE
                logger.warning(warnMsg)

                return False

            setDbms(DBMS.ALTIBASE)

            self.getBanner()

            return True
        else:
            warnMsg = 'serverdagi DBMS %s emas' % DBMS.ALTIBASE
            logger.warning(warnMsg)

            return False
