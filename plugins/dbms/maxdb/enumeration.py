#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission
"""

from lib.core.uzbek import ut
import re

from lib.core.common import isListLike
from lib.core.common import isTechniqueAvailable
from lib.core.common import readInput
from lib.core.common import safeSQLIdentificatorNaming
from lib.core.common import unsafeSQLIdentificatorNaming
from lib.core.data import conf
from lib.core.data import kb
from lib.core.data import logger
from lib.core.data import paths
from lib.core.data import queries
from lib.core.enums import DBMS
from lib.core.enums import PAYLOAD
from lib.core.exception import SqlmapMissingMandatoryOptionException
from lib.core.exception import SqlmapNoneDataException
from lib.core.exception import SqlmapUserQuitException
from lib.core.settings import CURRENT_DB
from lib.utils.brute import columnExists
from lib.utils.pivotdumptable import pivotDumpTable
from plugins.generic.enumeration import Enumeration as GenericEnumeration
from thirdparty import six
from thirdparty.six.moves import zip as _zip

class Enumeration(GenericEnumeration):
    def __init__(self):
        GenericEnumeration.__init__(self)

        kb.data.processChar = lambda x: x.replace('_', ' ') if x else x

    def getPasswordHashes(self):
        warnMsg = 'SAP MaxDB da foydalanuvchi parol xeshlarini olish mumkin emas'
        logger.warning(warnMsg)

        return {}

    def getDbs(self):
        if len(kb.data.cachedDbs) > 0:
            return kb.data.cachedDbs

        infoMsg = 'baza nomlari olinmoqda'
        logger.info(infoMsg)

        rootQuery = queries[DBMS.MAXDB].dbs
        query = rootQuery.inband.query
        retVal = pivotDumpTable("(%s) AS %s" % (query, kb.aliasName), ['%s.schemaname' % kb.aliasName], blind=True)

        if retVal:
            kb.data.cachedDbs = next(six.itervalues(retVal[0]))

        if kb.data.cachedDbs:
            kb.data.cachedDbs.sort()

        return kb.data.cachedDbs

    def getTables(self, bruteForce=None):
        if len(kb.data.cachedTables) > 0:
            return kb.data.cachedTables

        self.forceDbmsEnum()

        if conf.db == CURRENT_DB:
            conf.db = self.getCurrentDb()

        if conf.db:
            dbs = conf.db.split(',')
        else:
            dbs = self.getDbs()

        for db in (_ for _ in dbs if _):
            dbs[dbs.index(db)] = safeSQLIdentificatorNaming(db)

        infoMsg = 'baza jadvallari olinmoqda:'
        infoMsg += "%s: %s" % ("s" if len(dbs) > 1 else "", ", ".join(db if isinstance(db, six.string_types) else db[0] for db in sorted(dbs)))
        logger.info(infoMsg)

        rootQuery = queries[DBMS.MAXDB].tables

        for db in dbs:
            query = rootQuery.inband.query % (("'%s'" % db) if db != "USER" else 'USER')
            blind = not isTechniqueAvailable(PAYLOAD.TECHNIQUE.UNION)
            retVal = pivotDumpTable("(%s) AS %s" % (query, kb.aliasName), ['%s.tablename' % kb.aliasName], blind=blind)

            if retVal:
                for table in list(retVal[0].values())[0]:
                    if db not in kb.data.cachedTables:
                        kb.data.cachedTables[db] = [table]
                    else:
                        kb.data.cachedTables[db].append(table)

        for db, tables in kb.data.cachedTables.items():
            kb.data.cachedTables[db] = sorted(tables) if tables else tables

        return kb.data.cachedTables

    def getColumns(self, onlyColNames=False, colTuple=None, bruteForce=None, dumpMode=False):
        self.forceDbmsEnum()

        if conf.db is None or conf.db == CURRENT_DB:
            if conf.db is None:
                warnMsg = "baza parametri yo'q. Sqlmap "
                warnMsg += 'joriy bazadan foydalanadi, '
                warnMsg += 'jadval ustunlari'
                logger.warning(warnMsg)

            conf.db = self.getCurrentDb()

        elif conf.db is not None:
            if ',' in conf.db:
                errMsg = 'jadvallarning ustunlarini olishda '
                errMsg += 'faqat bitta baza nomi berilishi mumkin'
                raise SqlmapMissingMandatoryOptionException(errMsg)

        conf.db = safeSQLIdentificatorNaming(conf.db)

        if conf.col:
            colList = conf.col.split(',')
        else:
            colList = []

        if conf.exclude:
            colList = [_ for _ in colList if re.search(conf.exclude, _, re.I) is None]

        for col in colList:
            colList[colList.index(col)] = safeSQLIdentificatorNaming(col)

        if conf.tbl:
            tblList = conf.tbl.split(',')
        else:
            self.getTables()

            if len(kb.data.cachedTables) > 0:
                tblList = list(kb.data.cachedTables.values())

                if tblList and isListLike(tblList[0]):
                    tblList = tblList[0]
            else:
                errMsg = "jadvallarni olib bo'lmadi "
                errMsg += "'%s' bazasida" % unsafeSQLIdentificatorNaming(conf.db)
                raise SqlmapNoneDataException(errMsg)

        for tbl in tblList:
            tblList[tblList.index(tbl)] = safeSQLIdentificatorNaming(tbl, True)

        if bruteForce:
            resumeAvailable = False

            for tbl in tblList:
                for db, table, colName, colType in kb.brute.columns:
                    if db == conf.db and table == tbl:
                        resumeAvailable = True
                        break

            if resumeAvailable and not conf.freshQueries or colList:
                columns = {}

                for column in colList:
                    columns[column] = None

                for tbl in tblList:
                    for db, table, colName, colType in kb.brute.columns:
                        if db == conf.db and table == tbl:
                            columns[colName] = colType

                    if conf.db in kb.data.cachedColumns:
                        kb.data.cachedColumns[safeSQLIdentificatorNaming(conf.db)][safeSQLIdentificatorNaming(tbl, True)] = columns
                    else:
                        kb.data.cachedColumns[safeSQLIdentificatorNaming(conf.db)] = {safeSQLIdentificatorNaming(tbl, True): columns}

                return kb.data.cachedColumns

            message = ut('do you want to use common column existence check? [y/N/q] ', 'keng tarqalgan ustunlar mavjudligi tekshirilsinmi? [y/N/q] ')
            choice = readInput(message, default='Y' if 'Y' in message else 'N').upper()

            if choice == 'N':
                return
            elif choice == 'Q':
                raise SqlmapUserQuitException
            else:
                return columnExists(paths.COMMON_COLUMNS)

        rootQuery = queries[DBMS.MAXDB].columns

        for tbl in tblList:
            if conf.db is not None and len(kb.data.cachedColumns) > 0 and conf.db in kb.data.cachedColumns and tbl in kb.data.cachedColumns[conf.db]:
                infoMsg = 'jadvallar ustunlari olindi: '
                infoMsg += "'%s' bazasi" % unsafeSQLIdentificatorNaming(conf.db)
                logger.info(infoMsg)

                return {conf.db: kb.data.cachedColumns[conf.db]}

            if dumpMode and colList:
                if safeSQLIdentificatorNaming(conf.db) not in kb.data.cachedColumns:
                    kb.data.cachedColumns[safeSQLIdentificatorNaming(conf.db)] = {}
                kb.data.cachedColumns[safeSQLIdentificatorNaming(conf.db)][safeSQLIdentificatorNaming(tbl, True)] = dict((_, None) for _ in colList)
                continue

            infoMsg = 'ustunlar olinmoqda '
            infoMsg += "'%s' jadvali uchun " % unsafeSQLIdentificatorNaming(tbl)
            infoMsg += "'%s' bazasida" % unsafeSQLIdentificatorNaming(conf.db)
            logger.info(infoMsg)

            blind = not isTechniqueAvailable(PAYLOAD.TECHNIQUE.UNION)

            query = rootQuery.inband.query % (unsafeSQLIdentificatorNaming(tbl), ("'%s'" % unsafeSQLIdentificatorNaming(conf.db)) if unsafeSQLIdentificatorNaming(conf.db) != "USER" else 'USER')
            retVal = pivotDumpTable("(%s) AS %s" % (query, kb.aliasName), ['%s.columnname' % kb.aliasName, '%s.datatype' % kb.aliasName, '%s.len' % kb.aliasName], blind=blind)

            if retVal:
                table = {}
                columns = {}

                for columnname, datatype, length in _zip(retVal[0]["%s.columnname" % kb.aliasName], retVal[0]["%s.datatype" % kb.aliasName], retVal[0]["%s.len" % kb.aliasName]):
                    columns[safeSQLIdentificatorNaming(columnname)] = "%s(%s)" % (datatype, length)

                if conf.db not in kb.data.cachedColumns:
                    kb.data.cachedColumns[conf.db] = {}
                kb.data.cachedColumns[conf.db][tbl] = columns

        return kb.data.cachedColumns

    def getPrivileges(self, *args, **kwargs):
        warnMsg = 'SAP MaxDB da foydalanuvchi huquqlarini olish mumkin emas'
        logger.warning(warnMsg)

        return {}

    def search(self):
        warnMsg = 'SAP MaxDB da qidirish parametri mavjud emas'
        logger.warning(warnMsg)

    def getHostname(self):
        warnMsg = 'SAP MaxDB da xost nomini olish mumkin emas'
        logger.warning(warnMsg)

    def getStatements(self):
        warnMsg = 'SAP MaxDB da SQL buyruqlarini olish mumkin emas'
        logger.warning(warnMsg)

        return []
