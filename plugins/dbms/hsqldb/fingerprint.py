#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission
"""

import re

from lib.core.common import Backend
from lib.core.common import Format
from lib.core.common import unArrayizeValue
from lib.core.data import conf
from lib.core.data import kb
from lib.core.data import logger
from lib.core.enums import DBMS
from lib.core.session import setDbms
from lib.core.settings import HSQLDB_ALIASES
from lib.request import inject
from plugins.generic.fingerprint import Fingerprint as GenericFingerprint

class Fingerprint(GenericFingerprint):
    def __init__(self):
        GenericFingerprint.__init__(self, DBMS.HSQLDB)

    def getFingerprint(self):
        value = ""
        wsOsFp = Format.getOs("web server", kb.headersFp)

        if wsOsFp and not conf.api:
            value += "%s\n" % wsOsFp

        if kb.data.banner:
            dbmsOsFp = Format.getOs("back-end DBMS", kb.bannerFp)

            if dbmsOsFp and not conf.api:
                value += "%s\n" % dbmsOsFp

        value += 'serverdagi DBMS: '
        actVer = Format.getDbms()

        if not conf.extensiveFp:
            value += actVer
            return value

        blank = " " * 15
        value += 'faol aniqlash: %s' % actVer

        if kb.bannerFp:
            banVer = kb.bannerFp.get("dbmsVersion")

            if banVer:
                if re.search(r"-log$", kb.data.banner or ""):
                    banVer += ", logging enabled"

                banVer = Format.getDbms([banVer])
                value += '\n%sbanner orqali aniqlash: %s' % (blank, banVer)

        htmlErrorFp = Format.getErrorParsedDBMSes()

        if htmlErrorFp:
            value += '\n%sHTML xatosi orqali aniqlash: %s' % (blank, htmlErrorFp)

        return value

    def checkDbms(self):
        """
        References for fingerprint:
        DATABASE_VERSION()
        version 2.2.6 added two-arg REPLACE functio REPLACE('a','a') compared to REPLACE('a','a','d')
        version 2.2.5 added SYSTIMESTAMP function
        version 2.2.3 added REGEXPR_SUBSTRING and REGEXPR_SUBSTRING_ARRAY functions
        version 2.2.0 added support for ROWNUM() function
        version 2.1.0 added MEDIAN aggregate function
        version < 2.0.1 added support for datetime ROUND and TRUNC functions
        version 2.0.0 added VALUES support
        version 1.8.0.4 Added org.hsqldbdb.Library function, getDatabaseFullProductVersion to return the
                        full version string, including the 4th digit (e.g 1.8.0.4).
        version 1.7.2 CASE statements added and INFORMATION_SCHEMA

        """

        if not conf.extensiveFp and Backend.isDbmsWithin(HSQLDB_ALIASES):
            setDbms("%s %s" % (DBMS.HSQLDB, Backend.getVersion()))

            if Backend.isVersionGreaterOrEqualThan("1.7.2"):
                kb.data.has_information_schema = True

            self.getBanner()

            return True

        infoMsg = '%s tekshirilmoqda' % DBMS.HSQLDB
        logger.info(infoMsg)

        result = inject.checkBooleanExpression("CASEWHEN(1=1,1,0)=1")

        if result:
            infoMsg = '%s tasdiqlanmoqda' % DBMS.HSQLDB
            logger.info(infoMsg)

            result = inject.checkBooleanExpression("ROUNDMAGIC(PI())>=3")    # Note: same check without the blacklisted LEAST()

            if not result:
                warnMsg = 'serverdagi DBMS %s emas' % DBMS.HSQLDB
                logger.warning(warnMsg)

                return False
            else:
                result = inject.checkBooleanExpression("ZERO() IS 0")   # Note: check for H2 DBMS (sharing majority of same functions)
                if result:
                    warnMsg = 'serverdagi DBMS %s emas' % DBMS.HSQLDB
                    logger.warning(warnMsg)

                    return False

                kb.data.has_information_schema = True
                Backend.setVersion(">= 1.7.2")
                setDbms("%s 1.7.2" % DBMS.HSQLDB)

                banner = self.getBanner()
                if banner:
                    Backend.setVersion("= %s" % banner)
                else:
                    if inject.checkBooleanExpression("(SELECT [RANDNUM] FROM (VALUES(0)))=[RANDNUM]"):
                        Backend.setVersionList([">= 2.0.0", "< 2.3.0"])
                    else:
                        banner = unArrayizeValue(inject.getValue("\"org.hsqldbdb.Library.getDatabaseFullProductVersion\"()", safeCharEncode=True))
                        if banner:
                            Backend.setVersion("= %s" % banner)
                        else:
                            Backend.setVersionList([">= 1.7.2", "< 1.8.0"])

            return True
        else:
            warnMsg = 'serverdagi DBMS %s emas' % DBMS.HSQLDB
            logger.warning(warnMsg)

            dbgMsg = '...yoki versiyasi < 1.7.2'
            logger.debug(dbgMsg)

            return False

    def getHostname(self):
        warnMsg = 'HSQLDB da xost nomini olish mumkin emas'
        logger.warning(warnMsg)

    def checkDbmsOs(self, detailed=False):
        if Backend.getOs():
            infoMsg = 'serverdagi DBMS operatsion tizimi: %s' % Backend.getOs()
            logger.info(infoMsg)
        else:
            self.userChooseDbmsOs()
