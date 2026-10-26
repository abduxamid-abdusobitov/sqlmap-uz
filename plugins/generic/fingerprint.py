#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission
"""

from lib.core.uzbek import ut
from lib.core.common import Backend
from lib.core.common import readInput
from lib.core.data import logger
from lib.core.enums import OS
from lib.core.exception import SqlmapUndefinedMethod

class Fingerprint(object):
    """
    This class defines generic fingerprint functionalities for plugins.
    """

    def __init__(self, dbms):
        Backend.forceDbms(dbms)

    def getFingerprint(self):
        errMsg = "'getFingerprint' metodi aniqlanishi kerak "
        errMsg += 'tegishli DBMS plagini ichida'
        raise SqlmapUndefinedMethod(errMsg)

    def checkDbms(self):
        errMsg = "'checkDbms' metodi aniqlanishi kerak "
        errMsg += 'tegishli DBMS plagini ichida'
        raise SqlmapUndefinedMethod(errMsg)

    def checkDbmsOs(self, detailed=False):
        errMsg = "'checkDbmsOs' metodi aniqlanishi kerak "
        errMsg += 'tegishli DBMS plagini ichida'
        raise SqlmapUndefinedMethod(errMsg)

    def forceDbmsEnum(self):
        pass

    def userChooseDbmsOs(self):
        warnMsg = "sqlmap ayrim sabablarga ko'ra aniqlay olmadi: "
        warnMsg += 'serverdagi DBMS operatsion tizimini'
        logger.warning(warnMsg)

        msg = ut('do you want to provide the OS? [(W)indows/(l)inux]', 'OT ni belgilaysizmi? [(W)indows/(l)inux]')

        while True:
            os = readInput(msg, default='W').upper()

            if os == 'W':
                Backend.setOs(OS.WINDOWS)
                break
            elif os == 'L':
                Backend.setOs(OS.LINUX)
                break
            else:
                warnMsg = "noto'g'ri qiymat"
                logger.warning(warnMsg)
