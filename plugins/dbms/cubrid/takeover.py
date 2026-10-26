#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission
"""

from lib.core.exception import SqlmapUnsupportedFeatureException
from plugins.generic.takeover import Takeover as GenericTakeover

class Takeover(GenericTakeover):
    def osCmd(self):
        errMsg = 'Cubrid da buyruqlarni bajarish mumkin emas'
        raise SqlmapUnsupportedFeatureException(errMsg)

    def osShell(self):
        errMsg = 'Cubrid da buyruqlarni bajarish mumkin emas'
        raise SqlmapUnsupportedFeatureException(errMsg)

    def osPwn(self):
        errMsg = "Cubrid da ulanish o'rnatib bo'lmaydi: "
        errMsg += 'alohida kanal ulanishi'
        raise SqlmapUnsupportedFeatureException(errMsg)

    def osSmb(self):
        errMsg = "Cubrid da ulanish o'rnatib bo'lmaydi: "
        errMsg += 'alohida kanal ulanishi'
        raise SqlmapUnsupportedFeatureException(errMsg)
