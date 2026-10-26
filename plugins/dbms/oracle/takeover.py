#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission
"""

from lib.core.exception import SqlmapUnsupportedFeatureException
from plugins.generic.takeover import Takeover as GenericTakeover

class Takeover(GenericTakeover):
    def osCmd(self):
        errMsg = "Operatsion tizim buyrug'ini bajarish hali "
        errMsg += 'Oracle uchun yaratilmagan'
        raise SqlmapUnsupportedFeatureException(errMsg)

    def osShell(self):
        errMsg = "Operatsion tizim qobig'i hali "
        errMsg += 'Oracle uchun yaratilmagan'
        raise SqlmapUnsupportedFeatureException(errMsg)

    def osPwn(self):
        errMsg = 'Operatsion tizimni alohida kanal orqali boshqarish '
        errMsg += 'Oracle uchun hali yaratilmagan'
        raise SqlmapUnsupportedFeatureException(errMsg)

    def osSmb(self):
        errMsg = 'Bir amalda alohida kanal orqali OT boshqaruvi '
        errMsg += 'Oracle uchun hali yaratilmagan'
        raise SqlmapUnsupportedFeatureException(errMsg)
