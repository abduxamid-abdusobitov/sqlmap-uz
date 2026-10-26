#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission
"""

import os
import string

from lib.core.common import singleTimeWarnMessage
from lib.core.enums import PRIORITY

__priority__ = PRIORITY.LOWEST

def dependencies():
    singleTimeWarnMessage("'%s' tamper skripti faqat ASP veb-ilovalari uchun mo'ljallangan" % os.path.basename(__file__).split(".")[0])

def tamper(payload, **kwargs):
    """
    Har bir belgi oldiga % qo'shadi.

    Requirement:
        * ASP

    Tested against:
        * Microsoft SQL Server 2000, 2005
        * MySQL 5.1.56, 5.5.11
        * PostgreSQL 9.0

    Notes:
        * Useful to bypass weak and bespoke web application firewalls

    >>> tamper('SELECT FIELD FROM TABLE')
    '%S%E%L%E%C%T %F%I%E%L%D %F%R%O%M %T%A%B%L%E'
    """

    retVal = payload

    if payload:
        retVal = ""
        i = 0

        while i < len(payload):
            if payload[i] == '%' and (i < len(payload) - 2) and payload[i + 1:i + 2] in string.hexdigits and payload[i + 2:i + 3] in string.hexdigits:
                retVal += payload[i:i + 3]
                i += 3
            elif payload[i] != ' ':
                retVal += '%%%s' % payload[i]
                i += 1
            else:
                retVal += payload[i]
                i += 1

    return retVal
