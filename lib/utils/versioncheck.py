#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission
"""

import sys
import time

PYVERSION = sys.version.split()[0]

if PYVERSION < "2.7":
    sys.exit("[%s] [CRITICAL] mos kelmaydigan Python versiyasi ('%s'). Sqlmap uchun 2.7 yoki 3.x kerak ('https://www.python.org/downloads/')" % (time.strftime("%X"), PYVERSION))

errors = []
extensions = ("bz2", "gzip", "pyexpat", "ssl", "sqlite3", "zlib")
for _ in extensions:
    try:
        __import__(_)
    except ImportError:
        errors.append(_)

if errors:
    errMsg = "[%s] [CRITICAL] bir yoki bir nechta asosiy kengaytma yo'q (%s) " % (time.strftime("%X"), ", ".join("'%s'" % _ for _ in errors))
    errMsg += 'ehtimol, joriy Python versiyasi '
    errMsg += "tegishli ishlab chiqish paketlarisiz yig'ilgan"
    sys.exit(errMsg)
