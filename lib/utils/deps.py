#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission
"""

from lib.core.data import logger
from lib.core.dicts import DBMS_DICT
from lib.core.enums import DBMS
from lib.core.settings import IS_WIN

def checkDependencies():
    missing_libraries = set()

    for dbmsName, data in DBMS_DICT.items():
        if data[1] is None:
            continue

        try:
            if dbmsName in (DBMS.MSSQL, DBMS.SYBASE):
                __import__("_mssql")

                pymssql = __import__("pymssql")
                if not hasattr(pymssql, "__version__") or pymssql.__version__ < "1.0.2":
                    warnMsg = "'%s' tashqi kutubxonasi " % data[1]
                    warnMsg += "to'g'ri ishlashi uchun versiya >= 1.0.2 bo'lishi kerak. "
                    warnMsg += "Yuklab olish: '%s'" % data[2]
                    logger.warning(warnMsg)
            elif dbmsName == DBMS.MYSQL:
                __import__("pymysql")
            elif dbmsName in (DBMS.PGSQL, DBMS.CRATEDB):
                __import__("psycopg2")
            elif dbmsName == DBMS.ORACLE:
                __import__("oracledb")
            elif dbmsName == DBMS.SQLITE:
                __import__("sqlite3")
            elif dbmsName == DBMS.ACCESS:
                __import__("pyodbc")
            elif dbmsName == DBMS.FIREBIRD:
                __import__("firebirdsql")
            elif dbmsName == DBMS.DB2:
                __import__("ibm_db_dbi")
            elif dbmsName in (DBMS.HSQLDB, DBMS.CACHE):
                __import__("jaydebeapi")
                __import__("jpype")
            elif dbmsName == DBMS.INFORMIX:
                __import__("ibm_db_dbi")
            elif dbmsName == DBMS.MONETDB:
                __import__("pymonetdb")
            elif dbmsName == DBMS.DERBY:
                __import__("drda")
            elif dbmsName == DBMS.VERTICA:
                __import__("vertica_python")
            elif dbmsName == DBMS.PRESTO:
                __import__("prestodb")
            elif dbmsName == DBMS.MIMERSQL:
                __import__("mimerpy")
            elif dbmsName == DBMS.CUBRID:
                __import__("CUBRIDdb")
            elif dbmsName == DBMS.CLICKHOUSE:
                __import__("clickhouse_connect")
        except:
            warnMsg = "sqlmapga '%s' tashqi kutubxonasi kerak " % data[1]
            warnMsg += 'DBMS ga bevosita ulanish uchun '
            warnMsg += "'%s'. Yuklab olish: '%s'" % (dbmsName, data[2])
            logger.warning(warnMsg)
            missing_libraries.add(data[1])

            continue

        debugMsg = "'%s' tashqi kutubxonasi topildi" % data[1]
        logger.debug(debugMsg)

    try:
        __import__("impacket")
        debugMsg = "'python-impacket' tashqi kutubxonasi topildi"
        logger.debug(debugMsg)
    except ImportError:
        warnMsg = "sqlmapga 'python-impacket' tashqi kutubxonasi kerak: "
        warnMsg += 'alohida kanal orqali boshqarish uchun. Yuklab olish: '
        warnMsg += "'https://github.com/coresecurity/impacket'"
        logger.warning(warnMsg)
        missing_libraries.add('python-impacket')

    try:
        __import__("tkinter")
        debugMsg = "'tkinter' kutubxonasi topildi"
        logger.debug(debugMsg)
    except ImportError:
        warnMsg = "sqlmapga 'tkinter' kutubxonasi kerak, "
        warnMsg += "agar grafik interfeysdan foydalanmoqchi bo'lsangiz"
        logger.warning(warnMsg)
        missing_libraries.add('tkinter')

    try:
        __import__("tkinter.ttk")
        debugMsg = "'tkinter.ttk' kutubxonasi topildi"
        logger.debug(debugMsg)
    except ImportError:
        warnMsg = "sqlmapga 'tkinter.ttk' kutubxonasi kerak, "
        warnMsg += "agar grafik interfeysdan foydalanmoqchi bo'lsangiz"
        logger.warning(warnMsg)
        missing_libraries.add('tkinter.ttk')

    if IS_WIN:
        try:
            __import__("pyreadline")
            debugMsg = "'python-pyreadline' tashqi kutubxonasi topildi"
            logger.debug(debugMsg)
        except ImportError:
            warnMsg = "sqlmapga 'pyreadline' tashqi kutubxonasi kerak: "
            warnMsg += "TAB orqali avtomatik to'ldirish "
            warnMsg += 'va tarix imkoniyatlari uchun SQL '
            warnMsg += "hamda OT qobig'ida. Yuklab olish: "
            warnMsg += "'https://pypi.org/project/pyreadline/'"
            logger.warning(warnMsg)
            missing_libraries.add('python-pyreadline')

    if len(missing_libraries) == 0:
        infoMsg = "barcha bog'liqliklar o'rnatilgan"
        logger.info(infoMsg)
