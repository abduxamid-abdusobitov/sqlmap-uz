#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission
"""

from __future__ import division

from lib.core.uzbek import ut
import codecs
import collections
import functools
import glob
import importlib
import inspect
import json
import logging
import os
import random
import re
import socket
import sys
import tempfile
import threading
import time
import traceback

from lib.controller.checks import checkConnection
from lib.core.common import Backend
from lib.core.common import boldifyMessage
from lib.core.common import checkFile
from lib.core.common import dataToStdout
from lib.core.common import decodeStringEscape
from lib.core.common import fetchRandomAgent
from lib.core.common import filterNone
from lib.core.common import findLocalPort
from lib.core.common import findPageForms
from lib.core.common import getConsoleWidth
from lib.core.common import getFileItems
from lib.core.common import getFileType
from lib.core.common import getPublicTypeMembers
from lib.core.common import getSafeExString
from lib.core.common import intersect
from lib.core.common import normalizePath
from lib.core.common import ntToPosixSlashes
from lib.core.common import openFile
from lib.core.common import parseRequestFile
from lib.core.common import parseTargetDirect
from lib.core.common import paths
from lib.core.common import randomStr
from lib.core.common import readCachedFileContent
from lib.core.common import readInput
from lib.core.common import resetCookieJar
from lib.core.common import runningAsAdmin
from lib.core.common import safeExpandUser
from lib.core.common import safeFilepathEncode
from lib.core.common import saveConfig
from lib.core.common import setColor
from lib.core.common import setOptimize
from lib.core.common import setPaths
from lib.core.common import singleTimeWarnMessage
from lib.core.common import urldecode
from lib.core.compat import cmp
from lib.core.compat import round
from lib.core.compat import xrange
from lib.core.convert import getUnicode
from lib.core.data import conf
from lib.core.data import kb
from lib.core.data import logger
from lib.core.data import mergedOptions
from lib.core.data import queries
from lib.core.datatype import AttribDict
from lib.core.datatype import InjectionDict
from lib.core.datatype import LRUDict
from lib.core.datatype import OrderedSet
from lib.core.defaults import defaults
from lib.core.dicts import DBMS_DICT
from lib.core.dicts import DUMP_REPLACEMENTS
from lib.core.enums import ADJUST_TIME_DELAY
from lib.core.enums import AUTH_TYPE
from lib.core.enums import CUSTOM_LOGGING
from lib.core.enums import DUMP_FORMAT
from lib.core.enums import FORK
from lib.core.enums import HTTP_HEADER
from lib.core.enums import HTTPMETHOD
from lib.core.enums import MKSTEMP_PREFIX
from lib.core.enums import MOBILES
from lib.core.enums import OPTION_TYPE
from lib.core.enums import PAYLOAD
from lib.core.enums import PRIORITY
from lib.core.enums import PROXY_TYPE
from lib.core.enums import REFLECTIVE_COUNTER
from lib.core.enums import WIZARD
from lib.core.exception import SqlmapConnectionException
from lib.core.exception import SqlmapDataException
from lib.core.exception import SqlmapFilePathException
from lib.core.exception import SqlmapGenericException
from lib.core.exception import SqlmapInstallationException
from lib.core.exception import SqlmapMissingDependence
from lib.core.exception import SqlmapMissingMandatoryOptionException
from lib.core.exception import SqlmapMissingPrivileges
from lib.core.exception import SqlmapSilentQuitException
from lib.core.exception import SqlmapSyntaxException
from lib.core.exception import SqlmapSystemException
from lib.core.exception import SqlmapUnsupportedDBMSException
from lib.core.exception import SqlmapUserQuitException
from lib.core.exception import SqlmapValueException
from lib.core.log import FORMATTER
from lib.core.optiondict import optDict
from lib.core.settings import CODECS_LIST_PAGE
from lib.core.settings import CUSTOM_INJECTION_MARK_CHAR
from lib.core.settings import DBMS_ALIASES
from lib.core.settings import DEFAULT_GET_POST_DELIMITER
from lib.core.settings import DEFAULT_PAGE_ENCODING
from lib.core.settings import DEFAULT_TOR_HTTP_PORTS
from lib.core.settings import DEFAULT_TOR_SOCKS_PORTS
from lib.core.settings import DEFAULT_USER_AGENT
from lib.core.settings import DUMMY_URL
from lib.core.settings import IGNORE_CODE_WILDCARD
from lib.core.settings import IS_WIN
from lib.core.settings import KB_CHARS_BOUNDARY_CHAR
from lib.core.settings import KB_CHARS_LOW_FREQUENCY_ALPHABET
from lib.core.settings import LOCALHOST
from lib.core.settings import MAX_CONNECT_RETRIES
from lib.core.settings import MAX_NUMBER_OF_THREADS
from lib.core.settings import NULL
from lib.core.settings import PARAMETER_SPLITTING_REGEX
from lib.core.settings import PRECONNECT_CANDIDATE_TIMEOUT
from lib.core.settings import PROXY_ENVIRONMENT_VARIABLES
from lib.core.settings import SOCKET_PRE_CONNECT_QUEUE_SIZE
from lib.core.settings import NONSQL_TECHNIQUES
from lib.core.settings import SQLMAP_ENVIRONMENT_PREFIX
from lib.core.settings import SUPPORTED_DBMS
from lib.core.settings import SUPPORTED_OS
from lib.core.settings import TIME_DELAY_CANDIDATES
from lib.core.settings import UNKNOWN_DBMS_VERSION
from lib.core.settings import URI_INJECTABLE_REGEX
from lib.core.threads import getCurrentThreadData
from lib.core.threads import setDaemon
from lib.core.update import update
from lib.parse.configfile import configFileParser
from lib.parse.payloads import loadBoundaries
from lib.parse.payloads import loadPayloads
from lib.request.basic import checkCharEncoding
from lib.request import authrefresh
from lib.request.basicauthhandler import SmartHTTPBasicAuthHandler
from lib.request.chunkedhandler import ChunkedHandler
from lib.request.connect import Connect as Request
from lib.request.dns import DNSServer
from lib.request.dns import InteractshDNSServer
from lib.request.httpshandler import HTTPSHandler
from lib.request.keepalive import HTTPKeepAliveHandler
from lib.request.keepalive import HTTPSKeepAliveHandler
from lib.request.pkihandler import HTTPSPKIAuthHandler
from lib.request.rangehandler import HTTPRangeHandler
from lib.request.redirecthandler import SmartRedirectHandler
from lib.utils.crawler import crawl
from lib.utils.deps import checkDependencies
from lib.utils.har import HTTPCollectorFactory
from lib.utils.purge import purge
from lib.utils.search import search
from thirdparty import six
from lib.request.multiparthandler import MultipartPostHandler
from thirdparty.six.moves import collections_abc as _collections
from thirdparty.six.moves import http_client as _http_client
from thirdparty.six.moves import http_cookiejar as _http_cookiejar
from thirdparty.six.moves import urllib as _urllib
from thirdparty.socks import socks
from xml.etree.ElementTree import ElementTree

authHandler = _urllib.request.BaseHandler()
chunkedHandler = ChunkedHandler()
httpsHandler = HTTPSHandler()
keepAliveHandler = HTTPKeepAliveHandler()
keepAliveHandlerHTTPS = HTTPSKeepAliveHandler()
proxyHandler = _urllib.request.ProxyHandler()
redirectHandler = SmartRedirectHandler()
rangeHandler = HTTPRangeHandler()
multipartPostHandler = MultipartPostHandler()

# Reference: https://mail.python.org/pipermail/python-list/2009-November/558615.html
try:
    WindowsError
except NameError:
    WindowsError = None

def _loadQueries():
    """
    Loads queries from 'xml/queries.xml' file.
    """

    def iterate(node, retVal=None):
        class DictObject(object):
            def __init__(self):
                self.__dict__ = {}

            def __contains__(self, name):
                return name in self.__dict__

        if retVal is None:
            retVal = DictObject()

        for child in node.findall("*"):
            instance = DictObject()
            retVal.__dict__[child.tag] = instance
            if child.attrib:
                instance.__dict__.update(child.attrib)
            else:
                iterate(child, instance)

        return retVal

    tree = ElementTree()
    try:
        tree.parse(paths.QUERIES_XML)
    except Exception as ex:
        errMsg = "quyidagi bilan muammo bor ko'rinadi: "
        errMsg += "'%s' fayli ('%s'). Iltimos, " % (paths.QUERIES_XML, getSafeExString(ex))
        errMsg += "unga o'zgartirish kiritmaganingizni tekshiring"
        raise SqlmapInstallationException(errMsg)

    for node in tree.findall("*"):
        queries[node.attrib['value']] = iterate(node)

def _setMultipleTargets():
    """
    Define a configuration parameter if we are running in multiple target
    mode.
    """

    initialTargetsCount = len(kb.targets)
    seen = set()

    if not conf.logFile:
        return

    debugMsg = "nishonlar ro'yxati '%s' dan olinmoqda" % conf.logFile
    logger.debug(debugMsg)

    if not os.path.exists(conf.logFile):
        errMsg = "ko'rsatilgan nishonlar ro'yxati mavjud emas"
        raise SqlmapFilePathException(errMsg)

    if checkFile(conf.logFile, False):
        for target in parseRequestFile(conf.logFile):
            url, _, data, _, _ = target
            key = re.sub(r"(\w+=)[^%s ]*" % (conf.paramDel or DEFAULT_GET_POST_DELIMITER), r"\g<1>", "%s %s" % (url, data))
            if key not in seen:
                kb.targets.add(target)
                seen.add(key)

    elif os.path.isdir(conf.logFile):
        files = os.listdir(conf.logFile)
        files.sort()

        for reqFile in files:
            if not re.search(r"([\d]+)\-request", reqFile):
                continue

            for target in parseRequestFile(os.path.join(conf.logFile, reqFile)):
                url, _, data, _, _ = target
                key = re.sub(r"(\w+=)[^%s ]*" % (conf.paramDel or DEFAULT_GET_POST_DELIMITER), r"\g<1>", "%s %s" % (url, data))
                if key not in seen:
                    kb.targets.add(target)
                    seen.add(key)

    else:
        errMsg = "ko'rsatilgan nishonlar ro'yxati fayl ham, "
        errMsg += 'papka ham emas'
        raise SqlmapFilePathException(errMsg)

    updatedTargetsCount = len(kb.targets)

    if updatedTargetsCount > initialTargetsCount:
        infoMsg = 'sqlmap %d ta elementni tahlil qildi: ' % (updatedTargetsCount - initialTargetsCount)
        infoMsg += "takrorlanmaydigan parametrli so'rovlar "
        infoMsg += "nishonlar ro'yxatidan tekshirishga tayyor"
        logger.info(infoMsg)

def _adjustLoggingFormatter():
    """
    Solves problem of line deletition caused by overlapping logging messages
    and retrieved data info in inference mode
    """

    if hasattr(FORMATTER, '_format'):
        return

    def format(record):
        message = FORMATTER._format(record)
        message = boldifyMessage(message)
        if kb.get("prependFlag"):
            message = "\n%s" % message
            kb.prependFlag = False
        return message

    FORMATTER._format = FORMATTER.format
    FORMATTER.format = format

def _setRequestFromFile():
    """
    This function checks if the way to make a HTTP request is through supplied
    textual file, parses it and saves the information into the knowledge base.
    """

    if conf.requestFile:
        for requestFile in re.split(PARAMETER_SPLITTING_REGEX, conf.requestFile):
            requestFile = safeExpandUser(requestFile)
            url = None
            seen = set()

            if not checkFile(requestFile, False):
                errMsg = "berilgan HTTP so'rov fayli '%s' " % requestFile
                errMsg += 'mavjud emas'
                raise SqlmapFilePathException(errMsg)

            infoMsg = "HTTP so'rovi '%s' dan o'qilmoqda" % requestFile
            logger.info(infoMsg)

            for target in parseRequestFile(requestFile):
                url = target[0]
                if url not in seen:
                    kb.targets.add(target)
                    if len(kb.targets) > 1:
                        conf.multipleTargets = True
                    seen.add(url)

            if url is None:
                errMsg = "berilgan '%s' fayli " % requestFile
                errMsg += "ichida parametrli yaroqli HTTP so'rovi yo'q"
                raise SqlmapDataException(errMsg)

    if conf.secondReq:
        conf.secondReq = safeExpandUser(conf.secondReq)

        if not checkFile(conf.secondReq, False):
            errMsg = "berilgan ikkinchi tartibli HTTP so'rovi fayli '%s' " % conf.secondReq
            errMsg += 'mavjud emas'
            raise SqlmapFilePathException(errMsg)

        infoMsg = "ikkinchi tartibli HTTP so'rovi '%s' dan olinmoqda" % conf.secondReq
        logger.info(infoMsg)

        try:
            target = next(parseRequestFile(conf.secondReq, False))
            kb.secondReq = target
        except StopIteration:
            errMsg = "berilgan ikkinchi tartibli HTTP so'rovi fayli '%s' " % conf.secondReq
            errMsg += "ichida yaroqli HTTP so'rovi yo'q"
            raise SqlmapDataException(errMsg)

def _setCrawler():
    if not conf.crawlDepth:
        return

    if not conf.bulkFile:
        if conf.url:
            crawl(conf.url)
        elif conf.requestFile and kb.targets:
            target = next(iter(kb.targets))
            crawl(target[0], target[2], target[3])

def _doSearch():
    """
    This function performs search dorking, parses results
    and saves the testable hosts into the knowledge base.
    """

    if not conf.googleDork:
        return

    kb.data.onlyGETs = None

    def retrieve():
        links = search(conf.googleDork)

        if not links:
            errMsg = 'quyidagi uchun natija topilmadi: '
            errMsg += 'qidiruv dork ifodasi'
            raise SqlmapGenericException(errMsg)

        for link in links:
            link = urldecode(link)
            if re.search(r"(.*?)\?(.+)", link) or conf.forms:
                kb.targets.add((link, conf.method, conf.data, conf.cookie, None))
            elif re.search(URI_INJECTABLE_REGEX, link, re.I):
                if kb.data.onlyGETs is None and conf.data is None and not conf.googleDork:
                    message = ut('do you want to scan only results containing GET parameters? [Y/n] ', 'faqat GET parametrli natijalar tekshirilsinmi? [Y/n] ')
                    kb.data.onlyGETs = readInput(message, default='Y', boolean=True)
                if not kb.data.onlyGETs or conf.googleDork:
                    kb.targets.add((link, conf.method, conf.data, conf.cookie, None))

        return links

    while True:
        links = retrieve()

        if kb.targets:
            infoMsg = "%d ta natija topildi, so'rov: " % len(links)
            infoMsg += 'qidiruv dork ifodasi'

            if not conf.forms:
                infoMsg += ", "

                if len(links) == len(kb.targets):
                    infoMsg += 'barchasi '
                else:
                    infoMsg += "%d " % len(kb.targets)

                infoMsg += 'tasi tekshiriladigan nishon'

            logger.info(infoMsg)
            break

        else:
            message = ut('found %d results ', '%d ta natija topildi ') % len(links)
            message += ut('for your search dork expression, but none of them ', 'qidiruv dorki uchun, ammo ularning hech birida ')
            message += ut('have GET parameters to test for SQL injection. ', "SQL-inyeksiyaga tekshiriladigan GET parametri yo'q. ")
            message += ut('Do you want to skip to the next result page? [Y/n]', "Keyingi natijalar sahifasiga o'tasizmi? [Y/n]")

            if not readInput(message, default='Y', boolean=True):
                raise SqlmapSilentQuitException
            else:
                conf.googlePage += 1

def _setStdinPipeTargets():
    # Note: an explicit target source takes precedence. Without this, any non-interactive run (CI,
    # cron, subprocess) would reroute '-m/-l/-r/-g' targets through the STDIN container, losing both
    # their count and their order
    if any((conf.url, conf.direct, conf.logFile, conf.bulkFile, conf.requestFile, conf.googleDork, conf.openApiFile)):
        return

    if isinstance(conf.stdinPipe, _collections.Iterable):
        infoMsg = "nishonlar ro'yxati 'STDIN' dan olinmoqda"
        logger.info(infoMsg)

        class _(object):
            def __init__(self):
                self.__rest = OrderedSet()

            def __iter__(self):
                return self

            def __next__(self):
                return self.next()

            def next(self):
                while True:
                    try:
                        line = next(conf.stdinPipe)
                    except (IOError, OSError, TypeError, UnicodeDecodeError):
                        line = None
                    except StopIteration:
                        line = None

                    if line:
                        match = re.search(r"\b(https?://[^\s'\"]+|[\w.]+\.\w{2,3}[/\w+]*\?[^\s'\"]+)", line, re.I)
                        if match:
                            return (match.group(0), conf.method, conf.data, conf.cookie, None)
                        # Note: a non-empty line that is not a target (blank line, comment,
                        # non-parameterized URL) must be skipped, not treated as end-of-input
                        continue

                    # end-of-input (or read error): drain any queued targets, then stop
                    if self.__rest:
                        return self.__rest.pop()

                    raise StopIteration()

            def add(self, elem):
                self.__rest.add(elem)

        kb.targets = _()

def _setBulkMultipleTargets():
    if not conf.bulkFile:
        return

    conf.bulkFile = safeExpandUser(conf.bulkFile)

    infoMsg = "ko'p nishonli ro'yxat '%s' dan olinmoqda" % conf.bulkFile
    logger.info(infoMsg)

    if not checkFile(conf.bulkFile, False):
        errMsg = "ko'rsatilgan ro'yxat fayli "
        errMsg += 'mavjud emas'
        raise SqlmapFilePathException(errMsg)

    found = False
    for line in getFileItems(conf.bulkFile):
        if conf.scope and not re.search(conf.scope, line, re.I):
            continue

        if re.match(r"[^ ]+\?(.+)", line, re.I) or kb.customInjectionMark in line or conf.data:
            found = True
            kb.targets.add((line.strip(), conf.method, conf.data, conf.cookie, None))

    if not found and not conf.forms and not conf.crawlDepth:
        warnMsg = 'yaroqli GET parametrli havolalar topilmadi'
        logger.warning(warnMsg)

def _setOpenApiTargets():
    if not conf.openApiFile:
        return

    from lib.parse.openapi import openApiTargets

    if conf.method:
        warnMsg = "'--method' OpenAPI/Swagger tavsifidan olingan HTTP usullarini almashtiradi"
        logger.warning(warnMsg)

    # origin resolves a spec's relative 'servers' to absolute target URLs: an explicit '--openapi-base'
    # (needed for a host-less local spec) or, when fetched by URL, the fetch URL itself.
    origin = conf.openApiBase.rstrip('/') if conf.openApiBase else None
    if re.match(r"(?i)\Ahttps?://", conf.openApiFile):
        infoMsg = "OpenAPI/Swagger tavsifi '%s' dan olinmoqda" % conf.openApiFile
        logger.info(infoMsg)
        from lib.request.connect import Connect as Request
        content = Request.getPage(url=conf.openApiFile, raise404=True)[0]
        if not origin:
            match = re.match(r"(?i)(https?://[^/]+)", conf.openApiFile)
            origin = match.group(1) if match else None
    else:
        conf.openApiFile = safeExpandUser(conf.openApiFile)
        checkFile(conf.openApiFile)
        infoMsg = "OpenAPI/Swagger tavsifi '%s' dan tahlil qilinmoqda" % conf.openApiFile
        logger.info(infoMsg)
        with openFile(conf.openApiFile) as f:
            content = f.read()

    tags = [_.strip() for _ in re.split(PARAMETER_SPLITTING_REGEX, conf.openApiTags) if _.strip()] if conf.openApiTags else None
    if tags:
        infoMsg = 'faqat shu tegli OpenAPI/Swagger amallari olinadi: %s' % ", ".join(tags)
        logger.info(infoMsg)

    try:
        targets = openApiTargets(content, origin, tags)
    except ValueError as ex:
        errMsg = "OpenAPI/Swagger tavsifini tahlil qilib bo'lmadi ('%s')" % getSafeExString(ex)
        raise SqlmapSyntaxException(errMsg)

    if re.search(r"(?i)securitySchemes|securityDefinitions", content) and not any((conf.authType, conf.authCred, conf.authFile)) and not any((_[0] or "").lower() == HTTP_HEADER.AUTHORIZATION.lower() for _ in (conf.httpHeaders or [])):
        warnMsg = "OpenAPI/Swagger autentifikatsiya talabini ko'rsatgan, ammo kirish ma'lumotlari berilmagan. "
        warnMsg += "API autentifikatsiya talab qilsa, so'rovlar rad etilishi mumkin. Kirish ma'lumotlarini bering: "
        warnMsg += '\'--auth-type\'/\'--auth-cred\' yoki sarlavha (masalan, --headers="Authorization: Bearer ...")'
        logger.warning(warnMsg)

    before = len(kb.targets)                               # openapi carries per-target bodies -> no conf.data fallback
    mutating = 0
    for url, method, data, headers in targets:
        if conf.scope and not re.search(conf.scope, url, re.I):
            continue
        if method not in ("GET", "HEAD", "OPTIONS"):
            mutating += 1
        kb.targets.add((url, method, data, conf.cookie, tuple(headers) if headers else None))

    added = len(kb.targets) - before
    if added:
        conf.multipleTargets = True
        infoMsg = 'OpenAPI/Swagger tavsifidan %d ta nishon olindi' % added
        logger.info(infoMsg)
        if mutating:
            warnMsg = "olingan nishonlardan %d tasi holatni o'zgartiruvchi HTTP usulidan foydalanadi (masalan, POST/PUT/PATCH/DELETE). " % mutating
            warnMsg += "Ularni tekshirish server ma'lumotlarini yaratishi, o'zgartirishi yoki o'chirishi mumkin"
            logger.warning(warnMsg)
    else:
        warnMsg = 'OpenAPI/Swagger tavsifidan yaroqli nishon olinmadi'
        if not conf.openApiBase:
            warnMsg += " (nisbiy 'servers' bo'lsa, '--openapi-base' bering yoki tavsifni URL orqali oling)"
        logger.warning(warnMsg)

def _findPageForms():
    if not conf.forms or conf.crawlDepth:
        return

    if conf.url and not checkConnection():
        return

    found = False
    infoMsg = 'formalar qidirilmoqda'
    logger.info(infoMsg)

    if not any((conf.bulkFile, conf.googleDork)):
        page, _, _ = Request.queryPage(content=True, ignoreSecondOrder=True)
        if findPageForms(page, conf.url, True, True):
            found = True
    else:
        if conf.bulkFile:
            targets = getFileItems(conf.bulkFile)
        elif conf.googleDork:
            targets = [_[0] for _ in kb.targets]
            kb.targets.clear()
        else:
            targets = []

        for i in xrange(len(targets)):
            try:
                target = targets[i].strip()

                if not re.search(r"(?i)\Ahttp[s]*://", target):
                    target = "http://%s" % target

                page, _, _ = Request.getPage(url=target.strip(), cookie=conf.cookie, crawling=True, raise404=False)
                if findPageForms(page, target, False, True):
                    found = True

                if conf.verbose in (1, 2):
                    status = '%d/%d links visited (%d%%)' % (i + 1, len(targets), round(100.0 * (i + 1) / len(targets)))
                    dataToStdout("\r[%s] [INFO] %s" % (time.strftime("%X"), status), True)
            except KeyboardInterrupt:
                break
            except Exception as ex:
                errMsg = "'%s' da formalarni qidirishda muammo ('%s')" % (target, getSafeExString(ex))
                logger.error(errMsg)

    if not found:
        warnMsg = 'formalar topilmadi'
        logger.warning(warnMsg)

def _setDBMSAuthentication():
    """
    Check and set the DBMS authentication credentials to run statements as
    another user, not the session user
    """

    if not conf.dbmsCred:
        return

    debugMsg = "DBMS kirish ma'lumotlari sozlanmoqda"
    logger.debug(debugMsg)

    match = re.search(r"^(.+?):(.*?)$", conf.dbmsCred)

    if not match:
        errMsg = "DBMS kirish ma'lumotlari quyidagi formatda bo'lishi kerak: "
        errMsg += "username:password"
        raise SqlmapSyntaxException(errMsg)

    conf.dbmsUsername = match.group(1)
    conf.dbmsPassword = match.group(2)

def _setMetasploit():
    if not conf.osPwn and not conf.osSmb and not conf.osBof:
        return

    debugMsg = 'alohida kanal orqali boshqarish sozlanmoqda'
    logger.debug(debugMsg)

    msfEnvPathExists = False

    if IS_WIN:
        try:
            __import__("win32file")
        except ImportError:
            errMsg = "sqlmapga 'pywin32' tashqi moduli kerak, "
            errMsg += 'Metasploit imkoniyatlaridan foydalanish uchun '
            errMsg += 'Windowsda. Yuklab olish manzili: '
            errMsg += "'https://github.com/mhammond/pywin32'"
            raise SqlmapMissingDependence(errMsg)

        if not conf.msfPath:
            for candidate in os.environ.get("PATH", "").split(';'):
                if all(_ in candidate for _ in ("metasploit", "bin")):
                    conf.msfPath = os.path.dirname(candidate.rstrip('\\'))
                    break

    if conf.osSmb:
        isAdmin = runningAsAdmin()

        if not isAdmin:
            errMsg = 'sqlmapni administrator sifatida ishga tushiring, '
            errMsg += "agar SMB relay amalini bajarmoqchi bo'lsangiz, chunki "
            errMsg += 'foydalanuvchi belgilagan SMB TCP portini '
            errMsg += 'kiruvchi ulanishlar uchun tinglash kerak'
            raise SqlmapMissingPrivileges(errMsg)

    if conf.msfPath:
        for path in (conf.msfPath, os.path.join(conf.msfPath, "bin")):
            if any(os.path.exists(normalizePath(os.path.join(path, "%s%s" % (_, ".bat" if IS_WIN else "")))) for _ in ("msfcli", "msfconsole")):
                msfEnvPathExists = True
                if all(os.path.exists(normalizePath(os.path.join(path, "%s%s" % (_, ".bat" if IS_WIN else "")))) for _ in ("msfvenom",)):
                    kb.oldMsf = False
                elif all(os.path.exists(normalizePath(os.path.join(path, "%s%s" % (_, ".bat" if IS_WIN else "")))) for _ in ("msfencode", "msfpayload")):
                    kb.oldMsf = True
                else:
                    msfEnvPathExists = False

                conf.msfPath = path
                break

        if msfEnvPathExists:
            debugMsg = "berilgan Metasploit Framework yo'li "
            debugMsg += "'%s' yaroqli" % conf.msfPath
            logger.debug(debugMsg)
        else:
            warnMsg = "berilgan Metasploit Framework yo'li "
            warnMsg += "'%s' yaroqsiz. Sababi " % conf.msfPath
            warnMsg += "yo'l mavjud emas yoki "
            warnMsg += "kerakli Metasploit dasturlaridan biri yo'q: "
            warnMsg += 'msfcli, msfconsole, msfencode va '
            warnMsg += 'msfpayload orasida'
            logger.warning(warnMsg)
    else:
        warnMsg = "Metasploit o'rnatilgan mahalliy yo'l "
        warnMsg += "ko'rsatilmagan"
        logger.warning(warnMsg)

    if not msfEnvPathExists:
        warnMsg = "sqlmap Metasploit Framework o'rnatilishini "
        warnMsg += "muhit yo'llaridan qidiradi"
        logger.warning(warnMsg)

        envPaths = os.environ.get("PATH", "").split(";" if IS_WIN else ":")

        for envPath in envPaths:
            envPath = envPath.replace(";", "")

            if any(os.path.exists(normalizePath(os.path.join(envPath, "%s%s" % (_, ".bat" if IS_WIN else "")))) for _ in ("msfcli", "msfconsole")):
                msfEnvPathExists = True
                if all(os.path.exists(normalizePath(os.path.join(envPath, "%s%s" % (_, ".bat" if IS_WIN else "")))) for _ in ("msfvenom",)):
                    kb.oldMsf = False
                elif all(os.path.exists(normalizePath(os.path.join(envPath, "%s%s" % (_, ".bat" if IS_WIN else "")))) for _ in ("msfencode", "msfpayload")):
                    kb.oldMsf = True
                else:
                    msfEnvPathExists = False

                if msfEnvPathExists:
                    infoMsg = 'Metasploit Framework topildi '
                    infoMsg += "'%s' yo'liga o'rnatilgan" % envPath
                    logger.info(infoMsg)

                    conf.msfPath = envPath

                    break

    if not msfEnvPathExists:
        errMsg = "Metasploit Framework o'rnatilishi topilmadi. "
        errMsg += "Uni 'https://www.metasploit.com/download/' dan olishingiz mumkin"
        raise SqlmapFilePathException(errMsg)

def _setWriteFile():
    if not conf.fileWrite:
        return

    debugMsg = 'fayl yozish funksiyasi sozlanmoqda'
    logger.debug(debugMsg)

    if not os.path.exists(conf.fileWrite):
        errMsg = "berilgan mahalliy '%s' fayli mavjud emas" % conf.fileWrite
        raise SqlmapFilePathException(errMsg)

    if not conf.fileDest:
        errMsg = "serverdagi DBMS to'liq yo'lini ko'rsatmadingiz: "
        errMsg += "mahalliy '%s' fayli yoziladigan joy" % conf.fileWrite
        raise SqlmapMissingMandatoryOptionException(errMsg)

    conf.fileWriteType = getFileType(conf.fileWrite)

def _setOS():
    """
    Force the back-end DBMS operating system option.
    """

    if not conf.os:
        return

    if conf.os.lower() not in SUPPORTED_OS:
        errMsg = "serverdagi DBMS uchun qo'llanmaydigan operatsion "
        errMsg += "tizim berilgan. OT uchun qo'llanadigan tizimlar "
        errMsg += 'va fayl tizimiga kirish uchun: %s. ' % ', '.join([o.capitalize() for o in SUPPORTED_OS])
        errMsg += 'Serverdagi operatsion tizimni bilmasangiz, '
        errMsg += "uni belgilamang; sqlmap o'zi aniqlab "
        errMsg += 'beradi.'
        raise SqlmapUnsupportedDBMSException(errMsg)

    debugMsg = 'serverdagi DBMS operatsion tizimi foydalanuvchi bergan '
    debugMsg += "'%s' qiymatiga" % conf.os
    logger.debug(debugMsg)

    Backend.setOs(conf.os)

def _setTechnique():
    validTechniques = sorted(getPublicTypeMembers(PAYLOAD.TECHNIQUE), key=lambda x: x[1])
    validLetters = [_[0][0].upper() for _ in validTechniques]

    if conf.technique and isinstance(conf.technique, six.string_types):
        _ = []

        for letter in conf.technique.upper():
            if letter not in validLetters:
                errMsg = '--technique qiymati quyidagi harflardan tuzilishi kerak: '
                errMsg += "%s. Qo'llanmaga qarang: " % ", ".join(validLetters)
                errMsg += "batafsil ma'lumot uchun qo'llanmaga qarang"
                raise SqlmapSyntaxException(errMsg)

            for validTech, validInt in validTechniques:
                if letter == validTech[0]:
                    _.append(validInt)
                    break

        conf.technique = _

def _setDBMS():
    """
    Force the back-end DBMS option.
    """

    if not conf.dbms:
        return

    debugMsg = "DBMS turi foydalanuvchi bergan qiymatga o'rnatilmoqda"
    logger.debug(debugMsg)

    conf.dbms = conf.dbms.lower()
    regex = re.search(r"%s ([\d\.]+)" % ("(%s)" % "|".join(SUPPORTED_DBMS)), conf.dbms, re.I)

    if regex:
        conf.dbms = regex.group(1)
        Backend.setVersion(regex.group(2))

    if conf.dbms not in SUPPORTED_DBMS:
        errMsg = "qo'llanmaydigan ma'lumotlar bazasi boshqaruv "
        errMsg += "tizimi berilgan. Qo'llanadigan DBMSlar: %s. " % ', '.join(sorted((_ for _ in (list(DBMS_DICT) + getPublicTypeMembers(FORK, True))), key=str.lower))
        errMsg += 'Serverdagi DBMS ni bilmasangiz, uni belgilamang; '
        errMsg += "sqlmap o'zi aniqlab beradi."
        raise SqlmapUnsupportedDBMSException(errMsg)

    for dbms, aliases in DBMS_ALIASES:
        if conf.dbms in aliases:
            conf.dbms = dbms

            break

def _listTamperingFunctions():
    """
    Lists available tamper functions
    """

    if conf.listTampers:
        infoMsg = "mavjud tamper skriptlari ro'yxati\n"
        logger.info(infoMsg)

        for script in sorted(glob.glob(os.path.join(paths.SQLMAP_TAMPER_PATH, "*.py"))):
            with openFile(script, 'r') as f:
                content = f.read()
            match = re.search(r'(?s)__priority__.+"""(.+)"""', content)
            if match:
                comment = match.group(1).strip()
                dataToStdout("* %s - %s\n" % (setColor(os.path.basename(script), "yellow"), re.sub(r" *\n *", " ", comment.split("\n\n")[0].strip())))

def _argSpec(function):
    """
    Cross Py2/Py3 argument-name introspection - inspect.getargspec() is deprecated since
    Python 3.0 and removed entirely since 3.11, while inspect.getfullargspec() (used here
    whenever available) covers the same 'args'/'keywords' need without the warning/removal
    """

    return inspect.getfullargspec(function) if hasattr(inspect, "getfullargspec") else inspect.getargspec(function)

def _kwargsName(function):
    """
    Name of 'function's **kwargs-style catch-all parameter, or None - the field holding it is
    called 'varkw' on a getfullargspec() result and 'keywords' on a (Python 2) getargspec() one
    """

    spec = _argSpec(function)
    return getattr(spec, "varkw", None) or getattr(spec, "keywords", None)

def _setTamperingFunctions():
    """
    Loads tampering functions from given script(s)
    """

    if conf.tamper:
        last_priority = PRIORITY.HIGHEST
        check_priority = True
        resolve_priorities = False
        priorities = []

        for script in re.split(PARAMETER_SPLITTING_REGEX, conf.tamper):
            found = False

            path = safeFilepathEncode(paths.SQLMAP_TAMPER_PATH)
            script = safeFilepathEncode(script.strip())

            try:
                if not script:
                    continue

                elif os.path.exists(os.path.join(path, script if script.endswith(".py") else "%s.py" % script)):
                    script = os.path.join(path, script if script.endswith(".py") else "%s.py" % script)

                elif not os.path.exists(script):
                    errMsg = "'%s' tamper skripti mavjud emas" % script
                    raise SqlmapFilePathException(errMsg)

                elif not script.endswith(".py"):
                    errMsg = "'%s' tamper skripti '.py' kengaytmali bo'lsin" % script
                    raise SqlmapSyntaxException(errMsg)
            except UnicodeDecodeError:
                errMsg = "'--tamper' da noto'g'ri belgi berilgan"
                raise SqlmapSyntaxException(errMsg)

            dirname, filename = os.path.split(script)
            dirname = os.path.abspath(dirname)

            infoMsg = "'%s' tamper moduli yuklanmoqda" % filename[:-3]
            logger.info(infoMsg)

            if not os.path.exists(os.path.join(dirname, "__init__.py")):
                errMsg = "bo'sh '__init__.py' fayli borligini tekshiring "
                errMsg += "tamper skriptlari papkasi ichida: '%s'" % dirname
                raise SqlmapGenericException(errMsg)

            if dirname not in sys.path:
                sys.path.insert(0, dirname)

            try:
                getattr(importlib, "invalidate_caches", lambda: None)()  # Note: py3.3+ only; a script just written into an already-scanned dir is invisible to a cached FileFinder (Windows coarse mtime)
                module = __import__(safeFilepathEncode(filename[:-3]))
            except Exception as ex:
                raise SqlmapSyntaxException("'%s' tamper modulini import qilib bo'lmadi (%s)" % (getUnicode(filename[:-3]), getSafeExString(ex)))

            priority = PRIORITY.NORMAL if not hasattr(module, "__priority__") else module.__priority__
            priority = priority if priority is not None else PRIORITY.LOWEST

            if not isinstance(priority, int):
                warnMsg = "'%s' tamper modulida '__priority__' qiymati noto'g'ri " % filename[:-3]
                warnMsg += "('%d' deb olinadi)" % PRIORITY.NORMAL
                logger.warning(warnMsg)

                priority = PRIORITY.NORMAL

            for name, function in inspect.getmembers(module, inspect.isfunction):
                if name == "tamper" and (hasattr(inspect, "signature") and all(_ in inspect.signature(function).parameters for _ in ("payload", "kwargs")) or _argSpec(function).args and _kwargsName(function) == "kwargs"):
                    found = True
                    kb.tamperFunctions.append(function)
                    function.__name__ = module.__name__

                    if check_priority and priority > last_priority:
                        message = ut('it appears that you might have mixed ', 'ehtimol, tamper skriptlari ')
                        message += ut('the order of tamper scripts. ', 'tartibi aralashib ketgan. ')
                        message += ut('Do you want to auto resolve this? [Y/n/q] ', 'Avtomatik tuzatilsinmi? [Y/n/q] ')
                        choice = readInput(message, default='Y').upper()

                        if choice == 'N':
                            resolve_priorities = False
                        elif choice == 'Q':
                            raise SqlmapUserQuitException
                        else:
                            resolve_priorities = True

                        check_priority = False

                    priorities.append((priority, function))
                    last_priority = priority

                    break
                elif name == "dependencies":
                    try:
                        function()
                    except Exception as ex:
                        errMsg = "bog'liqliklarni tekshirishda xato "
                        errMsg += "'%s' tamper moduli uchun ('%s')" % (getUnicode(filename[:-3]), getSafeExString(ex))
                        raise SqlmapGenericException(errMsg)

            if not found:
                errMsg = "'tamper(payload, **kwargs)' funksiyasi yo'q "
                errMsg += "'%s' tamper skriptida" % script
                raise SqlmapGenericException(errMsg)

        if kb.tamperFunctions and len(kb.tamperFunctions) > 3:
            warnMsg = "juda ko'p tamper skriptidan foydalanish odatda "
            warnMsg += 'tavsiya etilmaydi'
            logger.warning(warnMsg)

        # tamper scripts rewrite SQL injection payloads; the self-contained non-SQL engines do not run
        # payloads through the tampering hook, so warn instead of silently ignoring the user's
        # '--tamper'. One tuple drives both the test and the name lookup - keeping two lists in step is
        # exactly how this raised StopIteration, and leaving an engine OUT (as '--hql' was) is how the
        # warning silently stops covering one.
        _nonSqlEngines = ("graphql", "nosql", "ldap", "xpath", "ssti", "xslt", "xxe", "hql", "sparql", "odata")
        if kb.tamperFunctions and any(conf.get(_) for _ in _nonSqlEngines):
            engine = next(_ for _ in _nonSqlEngines if conf.get(_))
            warnMsg = "tamper skriptlari faqat SQL-inyeksiya payloadlariga qo'llanadi va "
            warnMsg += "'--%s' mexanizmi tomonidan hisobga olinmaydi" % engine
            logger.warning(warnMsg)

        if resolve_priorities and priorities:
            priorities.sort(key=functools.cmp_to_key(lambda a, b: cmp(a[0], b[0])), reverse=True)
            kb.tamperFunctions = []

            for _, function in priorities:
                kb.tamperFunctions.append(function)

def _setPreprocessFunctions():
    """
    Loads preprocess function(s) from given script(s)
    """

    if conf.preprocess:
        for script in re.split(PARAMETER_SPLITTING_REGEX, conf.preprocess):
            found = False
            function = None

            script = safeFilepathEncode(script.strip())

            try:
                if not script:
                    continue

                if not os.path.exists(script):
                    errMsg = "'%s' oldindan qayta ishlash skripti mavjud emas" % script
                    raise SqlmapFilePathException(errMsg)

                elif not script.endswith(".py"):
                    errMsg = "'%s' oldindan qayta ishlash skripti '.py' kengaytmali bo'lsin" % script
                    raise SqlmapSyntaxException(errMsg)
            except UnicodeDecodeError:
                errMsg = "'--preprocess' da noto'g'ri belgi berilgan"
                raise SqlmapSyntaxException(errMsg)

            dirname, filename = os.path.split(script)
            dirname = os.path.abspath(dirname)

            infoMsg = "'%s' oldindan qayta ishlash moduli yuklanmoqda" % filename[:-3]
            logger.info(infoMsg)

            if not os.path.exists(os.path.join(dirname, "__init__.py")):
                errMsg = "bo'sh '__init__.py' fayli borligini tekshiring "
                errMsg += "oldindan qayta ishlash skriptlari papkasida: '%s'" % dirname
                raise SqlmapGenericException(errMsg)

            if dirname not in sys.path:
                sys.path.insert(0, dirname)

            try:
                getattr(importlib, "invalidate_caches", lambda: None)()  # Note: py3.3+ only; a script just written into an already-scanned dir is invisible to a cached FileFinder (Windows coarse mtime)
                module = __import__(safeFilepathEncode(filename[:-3]))
            except Exception as ex:
                raise SqlmapSyntaxException("'%s' oldindan qayta ishlash modulini import qilib bo'lmadi (%s)" % (getUnicode(filename[:-3]), getSafeExString(ex)))

            for name, function in inspect.getmembers(module, inspect.isfunction):
                try:
                    if name == "preprocess" and _argSpec(function).args and all(_ in _argSpec(function).args for _ in ("req",)):
                        found = True

                        kb.preprocessFunctions.append(function)
                        function.__name__ = module.__name__

                        break
                except ValueError:  # Note: https://github.com/sqlmapproject/sqlmap/issues/4357
                    pass

            if not found:
                errMsg = "'preprocess(req)' funksiyasi yo'q "
                errMsg += "'%s' oldindan qayta ishlash skriptida" % script
                raise SqlmapGenericException(errMsg)
            else:
                try:
                    function(_urllib.request.Request("http://localhost"))
                except Exception as ex:
                    tbMsg = traceback.format_exc()

                    if conf.debug:
                        dataToStdout(tbMsg)

                    handle, filename = tempfile.mkstemp(prefix=MKSTEMP_PREFIX.PREPROCESS, suffix=".py")
                    os.close(handle)

                    openFile(filename, "w+").write("#!/usr/bin/env\n\ndef preprocess(req):\n    pass\n")
                    openFile(os.path.join(os.path.dirname(filename), "__init__.py"), "w+").write("pass")

                    errMsg = "'preprocess(req)' funksiyasi "
                    errMsg += "'%s' oldindan qayta ishlash skriptida " % script
                    errMsg += "sinovda muammo yuz berdi ('%s'). " % getSafeExString(ex)
                    errMsg += "Namuna skript: '%s'" % filename
                    raise SqlmapGenericException(errMsg)

def _setPostprocessFunctions():
    """
    Loads postprocess function(s) from given script(s)
    """

    if conf.postprocess:
        for script in re.split(PARAMETER_SPLITTING_REGEX, conf.postprocess):
            found = False
            function = None

            script = safeFilepathEncode(script.strip())

            try:
                if not script:
                    continue

                if not os.path.exists(script):
                    errMsg = "'%s' yakuniy qayta ishlash skripti mavjud emas" % script
                    raise SqlmapFilePathException(errMsg)

                elif not script.endswith(".py"):
                    errMsg = "'%s' yakuniy qayta ishlash skripti '.py' kengaytmali bo'lsin" % script
                    raise SqlmapSyntaxException(errMsg)
            except UnicodeDecodeError:
                errMsg = "'--postprocess' da noto'g'ri belgi berilgan"
                raise SqlmapSyntaxException(errMsg)

            dirname, filename = os.path.split(script)
            dirname = os.path.abspath(dirname)

            infoMsg = "'%s' yakuniy qayta ishlash moduli yuklanmoqda" % filename[:-3]
            logger.info(infoMsg)

            if not os.path.exists(os.path.join(dirname, "__init__.py")):
                errMsg = "bo'sh '__init__.py' fayli borligini tekshiring "
                errMsg += "yakuniy qayta ishlash skriptlari papkasida: '%s'" % dirname
                raise SqlmapGenericException(errMsg)

            if dirname not in sys.path:
                sys.path.insert(0, dirname)

            try:
                getattr(importlib, "invalidate_caches", lambda: None)()  # Note: py3.3+ only; a script just written into an already-scanned dir is invisible to a cached FileFinder (Windows coarse mtime)
                module = __import__(safeFilepathEncode(filename[:-3]))
            except Exception as ex:
                raise SqlmapSyntaxException("'%s' yakuniy qayta ishlash modulini import qilib bo'lmadi (%s)" % (getUnicode(filename[:-3]), getSafeExString(ex)))

            for name, function in inspect.getmembers(module, inspect.isfunction):
                if name == "postprocess" and _argSpec(function).args and all(_ in _argSpec(function).args for _ in ("page", "headers", "code")):
                    found = True

                    kb.postprocessFunctions.append(function)
                    function.__name__ = module.__name__

                    break

            if not found:
                errMsg = "'postprocess(page, headers=None, code=None)' funksiyasi yo'q "
                errMsg += "'%s' yakuniy qayta ishlash skriptida" % script
                raise SqlmapGenericException(errMsg)
            else:
                try:
                    _, _, _ = function("", {}, None)
                except:
                    handle, filename = tempfile.mkstemp(prefix=MKSTEMP_PREFIX.PREPROCESS, suffix=".py")
                    os.close(handle)

                    openFile(filename, "w+").write("#!/usr/bin/env\n\ndef postprocess(page, headers=None, code=None):\n    return page, headers, code\n")
                    openFile(os.path.join(os.path.dirname(filename), "__init__.py"), "w+").write("pass")

                    errMsg = "'postprocess(page, headers=None, code=None)' funksiyasi "
                    errMsg += "'%s' yakuniy qayta ishlash skriptida " % script
                    errMsg += "'(page, headers, code)' kortejini qaytarishi kerak "
                    errMsg += "(Eslatma: namuna skript '%s' da)" % filename
                    raise SqlmapGenericException(errMsg)

def _setAuthRefreshFunction():
    """
    Load the authentication refresh hook without performing a login during initialization.
    """

    if conf.authRefresh:
        try:
            script = safeFilepathEncode(conf.authRefresh.strip())

            if not os.path.isfile(script):
                raise SqlmapFilePathException("'%s' autentifikatsiya yangilash skripti mavjud emas" % script)
            if not script.endswith(".py"):
                raise SqlmapSyntaxException("autentifikatsiyani yangilash skripti '.py' kengaytmali bo'lishi kerak")

            dirname, filename = os.path.split(os.path.abspath(script))
            if dirname not in sys.path:
                sys.path.insert(0, dirname)

            logger.info("'%s' autentifikatsiyani yangilash moduli yuklanmoqda" % filename[:-3])
            try:
                getattr(importlib, "invalidate_caches", lambda: None)()
                module = __import__(safeFilepathEncode(filename[:-3]))
                function = getattr(module, "refresh", None)
                if not inspect.isfunction(function):
                    raise ValueError("missing function 'refresh()'")
                spec = _argSpec(function)
                if len(spec.args) > len(spec.defaults or ()) or any(_ not in (getattr(spec, "kwonlydefaults", None) or {}) for _ in getattr(spec, "kwonlyargs", ())):
                    raise ValueError("function 'refresh()' must be callable without arguments")
            except Exception:
                raise SqlmapSyntaxException("'%s' autentifikatsiya skriptidan 'refresh()' ni yuklab bo'lmadi" % script)
        except (SqlmapFilePathException, SqlmapSyntaxException) as ex:
            errMsg = "%s. Namuna skript: '%s'" % (getSafeExString(ex), authrefresh.createTemplate())
            raise type(ex)(errMsg)

        kb.authRefreshFunction = function

def _setThreads():
    if not isinstance(conf.threads, int) or conf.threads <= 0:
        conf.threads = 1

def _setDNSCache():
    """
    Makes a cached version of socket._getaddrinfo to avoid subsequent DNS requests.
    """

    def _getaddrinfo(*args, **kwargs):
        key = (args, frozenset(kwargs.items()))

        if key in kb.cache.addrinfo:
            return kb.cache.addrinfo[key]

        kb.cache.addrinfo[key] = socket._getaddrinfo(*args, **kwargs)
        return kb.cache.addrinfo[key]

    if not hasattr(socket, "_getaddrinfo"):
        socket._getaddrinfo = socket.getaddrinfo
        socket.getaddrinfo = _getaddrinfo

def _setSocketPreConnect():
    """
    Makes a pre-connect version of socket.create_connection
    """

    if conf.disablePrecon:
        return

    def _thread():
        while kb.get("threadContinue") and not conf.get("disablePrecon"):
            done = False
            try:
                with kb.locks.socket:
                    keys = list(socket._ready.keys())

                for key in keys:
                    with kb.locks.socket:
                        q = socket._ready.get(key)
                        if q is None or len(q) >= SOCKET_PRE_CONNECT_QUEUE_SIZE:
                            continue
                        args = key[0]
                        kwargs = dict(key[1])

                    s = socket._create_connection(*args, **kwargs)

                    with kb.locks.socket:
                        q = socket._ready.get(key)
                        if q is not None and len(q) < SOCKET_PRE_CONNECT_QUEUE_SIZE:
                            q.append((s, time.time()))
                            s = None
                            done = True

                    if s is not None:
                        try:
                            s.close()
                        except:
                            pass

            except KeyboardInterrupt:
                break
            except:
                pass
            finally:
                time.sleep(0.01 if not done else 0.001)

    def create_connection(*args, **kwargs):
        retVal = None
        stale = []

        key = (tuple(args), frozenset(kwargs.items()))
        with kb.locks.socket:
            if key not in socket._ready:
                socket._ready[key] = collections.deque()

            q = socket._ready[key]
            while len(q) > 0:
                candidate, created = q.popleft()
                if (time.time() - created) < PRECONNECT_CANDIDATE_TIMEOUT:
                    retVal = candidate
                    break
                else:
                    stale.append(candidate)

        for candidate in stale:
            try:
                candidate.shutdown(socket.SHUT_RDWR)
                candidate.close()
            except:
                pass

        if not retVal:
            retVal = socket._create_connection(*args, **kwargs)
        else:
            try:
                retVal.settimeout(kwargs.get("timeout", socket.getdefaulttimeout()))
            except:
                pass

        return retVal

    if not hasattr(socket, "_create_connection"):
        socket._ready = {}
        socket._create_connection = socket.create_connection
        socket.create_connection = create_connection

        thread = threading.Thread(target=_thread)
        setDaemon(thread)
        thread.start()

def _setHTTPHandlers():
    """
    Check and set the HTTP/SOCKS proxy for all HTTP requests.
    """

    with kb.locks.handlers:
        if conf.proxyList:
            conf.proxy = conf.proxyList[0]
            conf.proxyList = conf.proxyList[1:] + conf.proxyList[:1]

            if len(conf.proxyList) > 1:
                infoMsg = "berilgan proksilar ro'yxatidan '%s' yuklanmoqda" % conf.proxy
                logger.info(infoMsg)

        elif not conf.proxy:
            if conf.hostname in ("localhost", "127.0.0.1") or conf.ignoreProxy:
                proxyHandler.proxies = {}

        if conf.proxy:
            debugMsg = "barcha HTTP so'rovlari uchun HTTP/SOCKS proksisi sozlanmoqda"
            logger.debug(debugMsg)

            try:
                _ = _urllib.parse.urlsplit(conf.proxy)
            except Exception as ex:
                errMsg = "noto'g'ri proksi manzili: '%s' ('%s')" % (conf.proxy, getSafeExString(ex))
                raise SqlmapSyntaxException(errMsg)

            match = re.search(r"\A([^:]*):([^:]*)@([^@]+)\Z", _.netloc)
            if match:
                username, password = _urllib.parse.unquote(match.group(1)), _urllib.parse.unquote(match.group(2))
            else:
                username, password = None, None

            hostnamePort = _.netloc.rsplit('@', 1)[-1].rsplit(":", 1)

            scheme = _.scheme.upper()
            hostname = hostnamePort[0]
            port = None

            if len(hostnamePort) == 2:
                try:
                    port = int(hostnamePort[1])
                except:
                    pass  # drops into the next check block

            if not all((scheme, hasattr(PROXY_TYPE, scheme), hostname, port)):
                errMsg = "proksi formati '(%s)://address:port' bo'lishi kerak" % "|".join(_[0].lower() for _ in getPublicTypeMembers(PROXY_TYPE))
                raise SqlmapSyntaxException(errMsg)

            if conf.proxyCred:
                _ = re.search(r"\A(.*?):(.*?)\Z", conf.proxyCred)
                if not _:
                    errMsg = "proksi kirish ma'lumotlari "
                    errMsg += "username:password formatida bo'lishi kerak"
                    raise SqlmapSyntaxException(errMsg)
                else:
                    username = _.group(1)
                    password = _.group(2)

            if scheme in (PROXY_TYPE.SOCKS4, PROXY_TYPE.SOCKS5):
                proxyHandler.proxies = {}

                if scheme == PROXY_TYPE.SOCKS4:
                    warnMsg = "SOCKS4 DNS nomlarini aniqlashni qo'llamaydi (DNS sizib chiqishiga sabab bo'ladi)"
                    singleTimeWarnMessage(warnMsg)

                socks.setdefaultproxy(socks.PROXY_TYPE_SOCKS5 if scheme == PROXY_TYPE.SOCKS5 else socks.PROXY_TYPE_SOCKS4, hostname, port, username=username, password=password)
                socks.wrapmodule(_http_client)
            else:
                socks.unwrapmodule(_http_client)

                if conf.proxyCred:
                    # Reference: http://stackoverflow.com/questions/34079/how-to-specify-an-authenticated-proxy-for-a-python-http-connection
                    proxyString = "%s@" % conf.proxyCred
                elif match:
                    # Note: credentials from the proxy URL itself (kept URL-encoded, as urllib decodes them on its own)
                    proxyString = "%s:%s@" % (match.group(1), match.group(2))
                else:
                    proxyString = ""

                proxyString += "%s:%d" % (hostname, port)
                proxyHandler.proxies = kb.proxies = {"http": proxyString, "https": proxyString}

            proxyHandler.__init__(proxyHandler.proxies)

        if not proxyHandler.proxies:
            for _ in ("http", "https"):
                if hasattr(proxyHandler, "%s_open" % _):
                    delattr(proxyHandler, "%s_open" % _)

        debugMsg = "HTTP so'rovlarini ochish obyekti yaratilmoqda"
        logger.debug(debugMsg)

        handlers = filterNone([multipartPostHandler, proxyHandler if proxyHandler.proxies else None, authHandler, redirectHandler, rangeHandler, chunkedHandler if conf.chunked else None, httpsHandler])

        if not conf.dropSetCookie:
            if not conf.loadCookies:
                conf.cj = _http_cookiejar.CookieJar()
            else:
                conf.cj = _http_cookiejar.MozillaCookieJar()
                resetCookieJar(conf.cj)

            handlers.append(_urllib.request.HTTPCookieProcessor(conf.cj))

        # Reference: http://www.w3.org/Protocols/rfc2616/rfc2616-sec8.html
        # Note: persistent (Keep-Alive) connections are used by default (including through an HTTP(s)
        # proxy - the keep-alive handler pools the proxy socket for plain HTTP and the CONNECT-tunnelled
        # socket per origin for HTTPS); '--no-keep-alive' opts out, and they are automatically disabled
        # when incompatible (authentication methods, or chunked transfer-encoding of the request body -
        # handled by a dedicated, non-pooling handler). Negotiate is the one auth exception: its token is
        # a per-request, end-to-end header (minted fresh each request, no connection-bound handshake), so
        # persistent connections remain safe and worthwhile.
        negotiateAuth = (conf.authType or "").lower() == AUTH_TYPE.NEGOTIATE
        conf.keepAlive = not conf.noKeepAlive and not conf.chunked and (not conf.authType or negotiateAuth)

        if conf.keepAlive:
            # persistent connections for both HTTP and HTTPS; the keep-alive HTTPS
            # handler supersedes the regular one (reusing its SSL connection)
            if httpsHandler in handlers:
                handlers.remove(httpsHandler)
            handlers.append(keepAliveHandler)
            handlers.append(keepAliveHandlerHTTPS)
        elif not conf.noKeepAlive and (conf.authType or conf.chunked):
            reason = "authentication methods" if conf.authType else "chunked transfer-encoding"
            debugMsg = "doimiy Keep-Alive ulanishlari o'chirildi (%s bilan mos emas)" % reason
            logger.debug(debugMsg)

        opener = _urllib.request.build_opener(*handlers)
        opener.addheaders = []  # Note: clearing default "User-Agent: Python-urllib/X.Y"
        _urllib.request.install_opener(opener)

def _setSafeVisit():
    """
    Check and set the safe visit options.
    """
    if not any((conf.safeUrl, conf.safeReqFile)):
        return

    if conf.safeReqFile:
        checkFile(conf.safeReqFile)

        raw = readCachedFileContent(conf.safeReqFile)
        match = re.search(r"\A([A-Z]+) ([^ ]+) HTTP/[0-9.]+\Z", raw.split('\n')[0].strip())

        if match:
            kb.safeReq.method = match.group(1)
            kb.safeReq.url = match.group(2)
            kb.safeReq.headers = {}

            for line in raw.split('\n')[1:]:
                line = line.strip()
                if line and ':' in line:
                    key, value = line.split(':', 1)
                    value = value.strip()
                    kb.safeReq.headers[key] = value
                    if key.upper() == HTTP_HEADER.HOST.upper():
                        if not value.startswith("http"):
                            scheme = "http"
                            if value.endswith(":443"):
                                scheme = "https"
                            value = "%s://%s" % (scheme, value)
                        kb.safeReq.url = _urllib.parse.urljoin(value, kb.safeReq.url)
                else:
                    break

            post = None

            if '\r\n\r\n' in raw:
                post = raw[raw.find('\r\n\r\n') + 4:]
            elif '\n\n' in raw:
                post = raw[raw.find('\n\n') + 2:]

            if post and post.strip():
                kb.safeReq.post = post
            else:
                kb.safeReq.post = None
        else:
            errMsg = "xavfsiz so'rov faylining formati noto'g'ri"
            raise SqlmapSyntaxException(errMsg)
    else:
        if not re.search(r"(?i)\Ahttp[s]*://", conf.safeUrl):
            if ":443/" in conf.safeUrl:
                conf.safeUrl = "https://%s" % conf.safeUrl
            else:
                conf.safeUrl = "http://%s" % conf.safeUrl

    if (conf.safeFreq or 0) <= 0:
        errMsg = "xavfsiz tashrif uchun '--safe-freq' qiymatini to'g'ri (>0) kiriting"
        raise SqlmapSyntaxException(errMsg)

def _setPrefixSuffix():
    if conf.prefix is not None and conf.suffix is not None:
        # Create a custom boundary object for user's supplied prefix
        # and suffix
        boundary = AttribDict()

        boundary.level = 1
        boundary.clause = [0]
        boundary.where = [1, 2, 3]
        boundary.prefix = conf.prefix
        boundary.suffix = conf.suffix

        if " like" in boundary.suffix.lower():
            if "'" in boundary.suffix.lower():
                boundary.ptype = 3
            elif '"' in boundary.suffix.lower():
                boundary.ptype = 5
        elif "'" in boundary.suffix:
            boundary.ptype = 2
        elif '"' in boundary.suffix:
            boundary.ptype = 4
        else:
            boundary.ptype = 1

        # user who provides --prefix/--suffix does not want other boundaries
        # to be tested for
        conf.boundaries = [boundary]

def _setAuthCred():
    """
    Adds authentication credentials (if any) for current target to the password manager
    (used by connection handler)
    """

    if kb.passwordMgr and all(_ is not None for _ in (conf.scheme, conf.hostname, conf.port, conf.authUsername, conf.authPassword)):
        kb.passwordMgr.add_password(None, "%s://%s:%d" % (conf.scheme, conf.hostname, conf.port), conf.authUsername, conf.authPassword)

def _setHTTPAuthentication():
    """
    Check and set the HTTP(s) authentication method (Basic, Digest, Bearer, NTLM, Negotiate or PKI),
    username and password for first three methods, or PEM private key file for
    PKI authentication
    """

    global authHandler

    if not conf.authType and not conf.authCred and not conf.authFile:
        return

    if conf.authFile and not conf.authType:
        conf.authType = AUTH_TYPE.PKI

    elif conf.authType and not conf.authCred and not conf.authFile:
        errMsg = 'HTTP autentifikatsiya turi berilgan, ammo '
        errMsg += "kirish ma'lumotlari kiritilmagan"
        raise SqlmapSyntaxException(errMsg)

    elif not conf.authType and conf.authCred:
        errMsg = "HTTP kirish ma'lumotlari berilgan, "
        errMsg += 'ammo turi ko\'rsatilmagan (masalan, --auth-type="basic")'
        raise SqlmapSyntaxException(errMsg)

    elif (conf.authType or "").lower() not in (AUTH_TYPE.BASIC, AUTH_TYPE.DIGEST, AUTH_TYPE.BEARER, AUTH_TYPE.NTLM, AUTH_TYPE.NEGOTIATE, AUTH_TYPE.PKI):
        errMsg = "HTTP autentifikatsiya turi quyidagilardan bo'lsin: "
        errMsg += 'Basic, Digest, Bearer, NTLM, Negotiate yoki PKI'
        raise SqlmapSyntaxException(errMsg)

    if not conf.authFile:
        debugMsg = "HTTP autentifikatsiya turi va kirish ma'lumotlari sozlanmoqda"
        logger.debug(debugMsg)

        authType = conf.authType.lower()

        if authType in (AUTH_TYPE.BASIC, AUTH_TYPE.DIGEST):
            regExp = "^(.*?):(.*?)$"
            errMsg = "HTTP %s kirish ma'lumotlari " % authType
            errMsg += "qiymat 'username:password' formatida bo'lishi kerak"
        elif authType == AUTH_TYPE.BEARER:
            conf.httpHeaders.append((HTTP_HEADER.AUTHORIZATION, "Bearer %s" % conf.authCred.strip()))
            return
        elif authType in (AUTH_TYPE.NTLM, AUTH_TYPE.NEGOTIATE):
            # Note: the DOMAIN\username part is colon-free, so the password group takes the full
            # remainder (a greedy first group would otherwise swallow colons inside the password).
            # For Negotiate, DOMAIN is the Kerberos realm.
            regExp = "^([^:]*\\\\[^:]*):(.*)$"
            errMsg = "HTTP %s kirish ma'lumotlari " % authType
            errMsg += "'DOMAIN\\username:password' formatida bo'lishi kerak"
        elif authType == AUTH_TYPE.PKI:
            errMsg = 'HTTP PKI autentifikatsiyasi uchun '
            errMsg += '`--auth-file` kerak'
            raise SqlmapSyntaxException(errMsg)

        aCredRegExp = re.search(regExp, conf.authCred)

        if not aCredRegExp:
            raise SqlmapSyntaxException(errMsg)

        conf.authUsername = aCredRegExp.group(1)
        conf.authPassword = aCredRegExp.group(2)

        kb.passwordMgr = _urllib.request.HTTPPasswordMgrWithDefaultRealm()

        _setAuthCred()

        if authType == AUTH_TYPE.BASIC:
            authHandler = SmartHTTPBasicAuthHandler(kb.passwordMgr)

        elif authType == AUTH_TYPE.DIGEST:
            authHandler = _urllib.request.HTTPDigestAuthHandler(kb.passwordMgr)

        elif authType == AUTH_TYPE.NTLM:
            from lib.request.ntlm import HTTPNtlmAuthHandler
            authHandler = HTTPNtlmAuthHandler(kb.passwordMgr)

        elif authType == AUTH_TYPE.NEGOTIATE:
            from lib.request.kerberos import HTTPNegotiateAuthHandler
            # DOMAIN is the Kerberos realm; the KDC is auto-discovered (env / krb5.conf / DNS SRV / realm)
            realm, _, user = conf.authUsername.partition('\\')
            authHandler = HTTPNegotiateAuthHandler(realm, user, conf.authPassword)
    else:
        debugMsg = 'HTTP(s) autentifikatsiyasining PEM maxfiy kaliti sozlanmoqda'
        logger.debug(debugMsg)

        _ = safeExpandUser(conf.authFile)
        checkFile(_)
        authHandler = HTTPSPKIAuthHandler(_)

def _setHTTPExtraHeaders():
    if conf.headers:
        debugMsg = "qo'shimcha HTTP sarlavhalari sozlanmoqda"
        logger.debug(debugMsg)

        if "\\n" in conf.headers:
            conf.headers = conf.headers.replace("\\r\\n", "\\n").split("\\n")
        else:
            conf.headers = conf.headers.replace("\r\n", "\n").split("\n")

        for headerValue in conf.headers:
            if not headerValue.strip():
                continue

            if headerValue.startswith('@'):
                checkFile(headerValue[1:])
                kb.headersFile = headerValue[1:]
            elif headerValue.count(':') >= 1:
                header, value = (_.lstrip() for _ in headerValue.split(":", 1))

                if header and value:
                    conf.httpHeaders.append((header, value))
            else:
                errMsg = "noto'g'ri sarlavha: %s. To'g'ri format: 'name:value'" % repr(headerValue).lstrip('u')
                raise SqlmapSyntaxException(errMsg)

    elif not conf.requestFile and len(conf.httpHeaders or []) < 2:
        if conf.encoding:
            conf.httpHeaders.append((HTTP_HEADER.ACCEPT_CHARSET, "%s;q=0.7,*;q=0.1" % conf.encoding))

        # Invalidating any caching mechanism in between
        # Reference: http://stackoverflow.com/a/1383359
        conf.httpHeaders.append((HTTP_HEADER.CACHE_CONTROL, "no-cache"))

def _setHTTPUserAgent():
    """
    Set the HTTP User-Agent header.
    Depending on the user options it can be:

        * The default sqlmap string
        * A default value read as user option
        * A random value read from a list of User-Agent headers from a
          file choosed as user option
    """

    debugMsg = 'HTTP User-Agent sarlavhasi sozlanmoqda'
    logger.debug(debugMsg)

    if conf.mobile:
        if conf.randomAgent:
            _ = random.sample([_[1] for _ in getPublicTypeMembers(MOBILES, True)], 1)[0]
            conf.httpHeaders.append((HTTP_HEADER.USER_AGENT, _))
        else:
            message = ut('which smartphone do you want sqlmap to imitate ', 'sqlmap qaysi smartfonga taqlid qilsin, ')
            message += ut('through HTTP User-Agent header?\n', 'HTTP User-Agent sarlavhasi orqali?\n')
            items = sorted(getPublicTypeMembers(MOBILES, True))

            for count in xrange(len(items)):
                item = items[count]
                message += "[%d] %s%s\n" % (count + 1, item[0], " (default)" if item == MOBILES.IPHONE else "")

            test = readInput(message.rstrip('\n'), default=items.index(MOBILES.IPHONE) + 1)

            try:
                item = items[int(test) - 1]
            except:
                item = MOBILES.IPHONE

            conf.httpHeaders.append((HTTP_HEADER.USER_AGENT, item[1]))

    elif conf.agent:
        conf.httpHeaders.append((HTTP_HEADER.USER_AGENT, conf.agent))

    elif not conf.randomAgent:
        _ = True

        for header, _ in conf.httpHeaders:
            if header.upper() == HTTP_HEADER.USER_AGENT.upper():
                _ = False
                break

        if _:
            conf.httpHeaders.append((HTTP_HEADER.USER_AGENT, DEFAULT_USER_AGENT))

    else:
        userAgent = fetchRandomAgent()

        infoMsg = "tasodifiy HTTP User-Agent '%s' olindi: " % userAgent
        infoMsg += "'%s' faylidan" % paths.USER_AGENTS
        logger.info(infoMsg)

        conf.httpHeaders.append((HTTP_HEADER.USER_AGENT, userAgent))

def _setHTTPReferer():
    """
    Set the HTTP Referer
    """

    if conf.referer:
        debugMsg = 'HTTP Referer sarlavhasi sozlanmoqda'
        logger.debug(debugMsg)

        conf.httpHeaders.append((HTTP_HEADER.REFERER, conf.referer))

def _setHTTPHost():
    """
    Set the HTTP Host
    """

    if conf.host:
        debugMsg = 'HTTP Host sarlavhasi sozlanmoqda'
        logger.debug(debugMsg)

        conf.httpHeaders.append((HTTP_HEADER.HOST, conf.host))

def _setHTTPCookies():
    """
    Set the HTTP Cookie header
    """

    if conf.cookie:
        debugMsg = 'HTTP Cookie sarlavhasi sozlanmoqda'
        logger.debug(debugMsg)

        conf.httpHeaders.append((HTTP_HEADER.COOKIE, conf.cookie))

def _setHostname():
    """
    Set value conf.hostname
    """

    if conf.url:
        try:
            conf.hostname = _urllib.parse.urlsplit(conf.url).netloc.split(':')[0]
        except ValueError as ex:
            errMsg = 'quyidagi jarayonda muammo: '
            errMsg += "'%s' URL ni tahlil qilishda ('%s')" % (conf.url, getSafeExString(ex))
            raise SqlmapDataException(errMsg)

def _setHTTPTimeout():
    """
    Set the HTTP timeout
    """

    if conf.timeout:
        debugMsg = 'HTTP kutish muddati sozlanmoqda'
        logger.debug(debugMsg)

        conf.timeout = float(conf.timeout)

        if conf.timeout < 3.0:
            warnMsg = 'eng kam HTTP kutish vaqti 3 soniya; sqlmap '
            warnMsg += "uni qayta o'rnatadi"
            logger.warning(warnMsg)

            conf.timeout = 3.0
    else:
        conf.timeout = 30.0

    try:
        socket.setdefaulttimeout(conf.timeout)
    except OverflowError as ex:
        raise SqlmapValueException("'--timeout' uchun noto'g'ri qiymat ('%s')" % getSafeExString(ex))

def _checkDependencies():
    """
    Checks for missing dependencies.
    """

    if conf.dependencies:
        checkDependencies()

def _createHomeDirectories():
    """
    Creates directories inside sqlmap's home directory
    """

    if conf.get("purge"):
        return

    for context in ("output", "history"):
        directory = paths["SQLMAP_%s_PATH" % getUnicode(context).upper()]   # NOTE: https://github.com/sqlmapproject/sqlmap/issues/4363
        try:
            if not os.path.isdir(directory):
                os.makedirs(directory)

            _ = os.path.join(directory, randomStr())
            open(_, "w+").close()
            os.remove(_)

            if conf.get("outputDir") and context == "output":
                warnMsg = "'%s' quyidagi papka sifatida ishlatilmoqda: %s" % (directory, context)
                logger.warning(warnMsg)
        except (OSError, IOError) as ex:
            tempDir = tempfile.mkdtemp(prefix="sqlmap%s" % context)
            warnMsg = "amalni bajarib bo'lmadi: %s %s papkasi " % ("create" if not os.path.isdir(directory) else "write to the", context)
            warnMsg += "'%s' (%s). " % (directory, getUnicode(ex))
            warnMsg += "O'rniga '%s' vaqtinchalik papkasi ishlatilmoqda" % getUnicode(tempDir)
            logger.warning(warnMsg)

            paths["SQLMAP_%s_PATH" % context.upper()] = tempDir

def _pympTempLeakPatch(tempDir):  # Cross-referenced function
    raise NotImplementedError

def _createTemporaryDirectory():
    """
    Creates temporary directory for this run.
    """

    if conf.tmpDir:
        try:
            if not os.path.isdir(conf.tmpDir):
                os.makedirs(conf.tmpDir)

            _ = os.path.join(conf.tmpDir, randomStr())

            open(_, "w+").close()
            os.remove(_)

            tempfile.tempdir = conf.tmpDir

            warnMsg = "vaqtinchalik papka sifatida '%s' ishlatilmoqda" % conf.tmpDir
            logger.warning(warnMsg)
        except (OSError, IOError) as ex:
            errMsg = 'murojaat qilishda muammo: '
            errMsg += "vaqtinchalik papkalar manzili ('%s')" % getSafeExString(ex)
            raise SqlmapSystemException(errMsg)
    else:
        try:
            if not os.path.isdir(tempfile.gettempdir()):
                os.makedirs(tempfile.gettempdir())
        except Exception as ex:
            warnMsg = 'murojaat qilishda muammo: '
            warnMsg += "tizim vaqtinchalik papkalari manzili ('%s'). Iltimos, " % getSafeExString(ex)
            warnMsg += 'diskda yetarli joy borligini tekshiring. Muammo qolsa, '
            warnMsg += "'TEMP' muhit o'zgaruvchisini boshqa joyga belgilang, "
            warnMsg += 'joriy foydalanuvchi yoza oladigan joyga'
            logger.warning(warnMsg)

    if "sqlmap" not in (tempfile.tempdir or "") or conf.tmpDir and tempfile.tempdir == conf.tmpDir:
        try:
            tempfile.tempdir = tempfile.mkdtemp(prefix="sqlmap", suffix=str(os.getpid()))
        except:
            tempfile.tempdir = os.path.join(paths.SQLMAP_HOME_PATH, "tmp", "sqlmap%s%d" % (randomStr(6), os.getpid()))

    kb.tempDir = tempfile.tempdir

    if not os.path.isdir(tempfile.tempdir):
        try:
            os.makedirs(tempfile.tempdir)
        except Exception as ex:
            errMsg = 'sozlashda muammo yuz berdi: '
            errMsg += "vaqtinchalik papka manzili ('%s')" % getSafeExString(ex)
            raise SqlmapSystemException(errMsg)

    conf.tempDirs.append(tempfile.tempdir)

    if six.PY3:
        _pympTempLeakPatch(kb.tempDir)

def _cleanupOptions():
    """
    Cleanup configuration attributes.
    """

    if conf.encoding:
        try:
            codecs.lookup(conf.encoding)
        except LookupError:
            errMsg = "noma'lum kodlash: '%s'" % conf.encoding
            raise SqlmapValueException(errMsg)

    debugMsg = 'sozlash parametrlari tartibga keltirilmoqda'
    logger.debug(debugMsg)

    width = getConsoleWidth()

    if conf.eta:
        conf.progressWidth = width - 26
    else:
        conf.progressWidth = width - 46

    for key, value in conf.items():
        if value and any(key.endswith(_) for _ in ("Path", "File", "Dir")):
            if isinstance(value, str):
                conf[key] = safeExpandUser(value)

    if conf.testParameter:
        conf.testParameter = urldecode(conf.testParameter)
        conf.testParameter = [_.strip() for _ in re.split(PARAMETER_SPLITTING_REGEX, conf.testParameter)]
    else:
        conf.testParameter = []

    if conf.ignoreCode:
        if conf.ignoreCode == IGNORE_CODE_WILDCARD:
            conf.ignoreCode = xrange(0, 1000)
        else:
            try:
                conf.ignoreCode = [int(_) for _ in re.split(PARAMETER_SPLITTING_REGEX, conf.ignoreCode)]
            except ValueError:
                errMsg = "'--ignore-code' butun sonlar ro'yxati yoki '%s' umumiy belgisi bo'lishi kerak" % IGNORE_CODE_WILDCARD
                raise SqlmapSyntaxException(errMsg)
    else:
        conf.ignoreCode = []

    if conf.abortCode:
        try:
            conf.abortCode = [int(_) for _ in re.split(PARAMETER_SPLITTING_REGEX, conf.abortCode)]
        except ValueError:
            errMsg = "'--abort-code' butun sonlar ro'yxati bo'lishi kerak"
            raise SqlmapSyntaxException(errMsg)
    else:
        conf.abortCode = []

    if conf.paramFilter:
        conf.paramFilter = [_.strip() for _ in re.split(PARAMETER_SPLITTING_REGEX, conf.paramFilter.upper())]
    else:
        conf.paramFilter = []

    if conf.base64Parameter:
        conf.base64Parameter = urldecode(conf.base64Parameter)
        conf.base64Parameter = conf.base64Parameter.strip()
        conf.base64Parameter = re.split(PARAMETER_SPLITTING_REGEX, conf.base64Parameter)
    else:
        conf.base64Parameter = []

    if conf.agent:
        conf.agent = re.sub(r"[\r\n]", "", conf.agent)

    if conf.user:
        conf.user = conf.user.replace(" ", "")

    if conf.rParam:
        if all(_ in conf.rParam for _ in ('=', ',')):
            original = conf.rParam
            conf.rParam = []
            for part in original.split(';'):
                if '=' in part:
                    left, right = part.split('=', 1)
                    conf.rParam.append(left)
                    kb.randomPool[left] = filterNone(_.strip() for _ in right.split(','))
                else:
                    conf.rParam.append(part)
        else:
            conf.rParam = conf.rParam.replace(" ", "")
            conf.rParam = re.split(PARAMETER_SPLITTING_REGEX, conf.rParam)
    else:
        conf.rParam = []

    if conf.paramDel:
        conf.paramDel = decodeStringEscape(conf.paramDel)

    if conf.skip:
        conf.skip = conf.skip.replace(" ", "")
        conf.skip = re.split(PARAMETER_SPLITTING_REGEX, conf.skip)
    else:
        conf.skip = []

    if conf.cookie:
        conf.cookie = re.sub(r"[\r\n]", "", conf.cookie)

    if conf.delay:
        conf.delay = float(conf.delay)

    if conf.url:
        conf.url = conf.url.strip().lstrip('/')
        if not re.search(r"\A\w+://", conf.url):
            conf.url = "http://%s" % conf.url

    if conf.fileRead:
        conf.fileRead = ntToPosixSlashes(normalizePath(conf.fileRead))

    if conf.fileWrite:
        conf.fileWrite = ntToPosixSlashes(normalizePath(conf.fileWrite))

    if conf.fileDest:
        conf.fileDest = ntToPosixSlashes(normalizePath(conf.fileDest))

    if conf.msfPath:
        conf.msfPath = ntToPosixSlashes(normalizePath(conf.msfPath))

    if conf.tmpPath:
        conf.tmpPath = ntToPosixSlashes(normalizePath(conf.tmpPath))

    if any((conf.googleDork, conf.logFile, conf.bulkFile, conf.forms, conf.crawlDepth, conf.stdinPipe, conf.openApiFile)):
        conf.multipleTargets = True

    if conf.optimize:
        setOptimize()

    if conf.os:
        conf.os = conf.os.capitalize()

    if conf.forceDbms:
        conf.dbms = conf.forceDbms

    if conf.dbms:
        kb.dbmsFilter = []
        for _ in conf.dbms.split(','):
            for dbms, aliases in DBMS_ALIASES:
                if _.strip().lower() in aliases:
                    kb.dbmsFilter.append(dbms)
                    conf.dbms = dbms if conf.dbms and ',' not in conf.dbms else None
                    break

    if conf.uValues:
        conf.uCols = "%d-%d" % (1 + conf.uValues.count(','), 1 + conf.uValues.count(','))

    if conf.testFilter:
        conf.testFilter = conf.testFilter.strip('*+')
        conf.testFilter = re.sub(r"([^.])([*+])", r"\g<1>.\g<2>", conf.testFilter)

        try:
            re.compile(conf.testFilter)
        except re.error:
            conf.testFilter = re.escape(conf.testFilter)

    if conf.csrfToken:
        original = conf.csrfToken
        try:
            re.compile(conf.csrfToken)

            if re.escape(conf.csrfToken) != conf.csrfToken:
                message = ut("provided value for option '--csrf-token' is a regular expression? [y/N] ", "'--csrf-token' uchun berilgan qiymat muntazam ifodami? [y/N] ")
                if not readInput(message, default='N', boolean=True):
                    conf.csrfToken = re.escape(conf.csrfToken)
        except re.error:
            conf.csrfToken = re.escape(conf.csrfToken)
        finally:
            class _(six.text_type):
                pass
            conf.csrfToken = _(conf.csrfToken)
            conf.csrfToken._original = original

    if conf.testSkip:
        conf.testSkip = conf.testSkip.strip('*+')
        conf.testSkip = re.sub(r"([^.])([*+])", r"\g<1>.\g<2>", conf.testSkip)

        try:
            re.compile(conf.testSkip)
        except re.error:
            conf.testSkip = re.escape(conf.testSkip)

    if "timeSec" not in kb.explicitSettings:
        if conf.tor:
            conf.timeSec = 2 * conf.timeSec
            kb.adjustTimeDelay = ADJUST_TIME_DELAY.DISABLE

            warnMsg = 'standart qiymat oshirilmoqda: '
            warnMsg += "'--time-sec' %d ga, chunki " % conf.timeSec
            warnMsg += "'--tor' berilgani sabab"
            logger.warning(warnMsg)
    else:
        kb.adjustTimeDelay = ADJUST_TIME_DELAY.DISABLE

    if conf.retries:
        conf.retries = min(conf.retries, MAX_CONNECT_RETRIES)

    if conf.url:
        match = re.search(r"\A(\w+://)?([^/@?]+)@", conf.url)
        if match:
            credentials = match.group(2)
            conf.url = conf.url.replace("%s@" % credentials, "", 1)

            conf.authType = AUTH_TYPE.BASIC
            conf.authCred = credentials if ':' in credentials else "%s:" % credentials

    if conf.code:
        conf.code = int(conf.code)

    if conf.csvDel:
        conf.csvDel = decodeStringEscape(conf.csvDel)

    if conf.torPort and hasattr(conf.torPort, "isdigit") and conf.torPort.isdigit():
        conf.torPort = int(conf.torPort)

    if conf.torType:
        conf.torType = conf.torType.upper()

    if conf.outputDir:
        paths.SQLMAP_OUTPUT_PATH = os.path.realpath(os.path.expanduser(conf.outputDir))
        setPaths(paths.SQLMAP_ROOT_PATH)

    if conf.string:
        conf.string = decodeStringEscape(conf.string)

    if conf.getAll:
        for _ in WIZARD.ALL:
            conf.__setitem__(_, True)

    if conf.noCast:
        DUMP_REPLACEMENTS.clear()

    if conf.dumpFormat:
        conf.dumpFormat = conf.dumpFormat.upper()

    if conf.torType:
        conf.torType = conf.torType.upper()

    if conf.col:
        conf.col = re.sub(r"\s*,\s*", ',', conf.col)

    if conf.exclude:
        regex = False
        original = conf.exclude

        if any(_ in conf.exclude for _ in ('+', '*')):
            try:
                re.compile(conf.exclude)
            except re.error:
                pass
            else:
                regex = True

        if not regex:
            conf.exclude = re.sub(r"\s*,\s*", ',', conf.exclude)
            conf.exclude = r"\A%s\Z" % '|'.join(re.escape(_) for _ in conf.exclude.split(','))
        else:
            conf.exclude = re.sub(r"(\w+)\$", r"\g<1>\$", conf.exclude)

        class _(six.text_type):
            pass

        conf.exclude = _(conf.exclude)
        conf.exclude._original = original

    if conf.binaryFields:
        conf.binaryFields = conf.binaryFields.replace(" ", "")
        conf.binaryFields = re.split(PARAMETER_SPLITTING_REGEX, conf.binaryFields)

    envProxy = max(os.environ.get(_, "") for _ in PROXY_ENVIRONMENT_VARIABLES)
    if re.search(r"\A(https?|socks[45])://.+:\d+\Z", envProxy) and conf.proxy is None:
        debugMsg = "muhitdagi '%s' proksisi ishlatilmoqda" % envProxy
        logger.debug(debugMsg)

        conf.proxy = envProxy

    if any((conf.proxy, conf.proxyFile, conf.tor)):
        conf.disablePrecon = True

    if conf.dummy:
        conf.batch = True

    threadData = getCurrentThreadData()
    threadData.reset()

def _cleanupEnvironment():
    """
    Cleanup environment (e.g. from leftovers after --shell).
    """

    if getattr(_http_client.socket, "socket", None) is not getattr(socks, "_orgsocket", None):
        socks.unwrapmodule(_http_client)

    if hasattr(socket, "_ready"):
        socket._ready.clear()

def _purge():
    """
    Safely removes (purges) sqlmap data directory.
    """

    if conf.purge:
        purge(paths.SQLMAP_HOME_PATH)

def _setConfAttributes():
    """
    This function set some needed attributes into the configuration
    singleton.
    """

    debugMsg = 'sozlamalar ishga tayyorlanmoqda'
    logger.debug(debugMsg)

    conf.authUsername = None
    conf.authPassword = None
    conf.boundaries = []
    conf.cj = None
    conf.dbmsConnector = None
    conf.dbmsHandler = None
    conf.dnsServer = None
    conf.dumpPath = None
    conf.fileWriteType = None
    conf.HARCollectorFactory = None
    conf.hashDB = None
    conf.hashDBFile = None
    conf.httpCollector = None
    conf.httpHeaders = []
    conf.hostname = None
    conf.ipv6 = False
    conf.multipleTargets = False
    conf.outputPath = None
    conf.paramDict = {}
    conf.parameters = {}
    conf.path = None
    conf.port = None
    conf.proxyList = None
    conf.resultsFP = None
    conf.scheme = None
    conf.tests = []
    conf.tempDirs = []
    conf.trafficFP = None

def _setKnowledgeBaseAttributes(flushAll=True):
    """
    This function set some needed attributes into the knowledge base
    singleton.
    """

    debugMsg = 'bilimlar bazasi ishga tayyorlanmoqda'
    logger.debug(debugMsg)

    kb.absFilePaths = set()
    kb.adjustTimeDelay = None
    kb.alerted = False
    kb.aliasName = randomStr()
    kb.alwaysRefresh = None
    kb.arch = None
    kb.authHeader = None
    kb.bannerFp = AttribDict()
    kb.base64Originals = {}
    kb.binaryField = False
    kb.browserVerification = None

    kb.brute = AttribDict({"tables": [], "columns": []})
    kb.bruteMode = False

    kb.cache = AttribDict()
    kb.cache.addrinfo = {}
    kb.cache.content = LRUDict(capacity=16)
    kb.cache.comparison = LRUDict(capacity=256)
    kb.cache.encoding = LRUDict(capacity=256)
    kb.cache.alphaBoundaries = None
    kb.cache.charsetAsciiTbl = None
    kb.cache.hashRegex = None
    kb.cache.intBoundaries = None
    kb.cache.parsedDbms = {}
    kb.cache.regex = {}
    kb.cache.stdev = {}

    kb.captchaDetected = None

    kb.chars = AttribDict()
    kb.chars.delimiter = randomStr(length=6, lowercase=True)
    # NOTE: markers have to be mutually distinct (e.g. equal start/stop makes the delimited output ambiguous, while equal replacement markers make _errorReplaceChars() restore the wrong character). Also, none of the inner letters may be the boundary character itself, as that makes a marker contain a shorter one (e.g. 'qzqxq' carrying 'qzq')
    _ = set()
    while len(_) < 2:
        _.add(randomStr(length=3, alphabet=KB_CHARS_LOW_FREQUENCY_ALPHABET))
    kb.chars.start, kb.chars.stop = ("%s%s%s" % (KB_CHARS_BOUNDARY_CHAR, __, KB_CHARS_BOUNDARY_CHAR) for __ in _)

    _ = set()
    while len(_) < 4:
        _.add(randomStr(length=1, lowercase=True))
        _.discard(KB_CHARS_BOUNDARY_CHAR)
    kb.chars.at, kb.chars.space, kb.chars.dollar, kb.chars.hash_ = ("%s%s%s" % (KB_CHARS_BOUNDARY_CHAR, __, KB_CHARS_BOUNDARY_CHAR) for __ in _)

    kb.checkWafMode = False
    kb.choices = AttribDict(keycheck=False)
    kb.codePage = None
    kb.commonOutputs = None
    kb.connErrorCounter = 0
    kb.copyExecTest = None
    kb.counters = {}
    kb.customInjectionMark = CUSTOM_INJECTION_MARK_CHAR
    kb.data = AttribDict()
    kb.dataOutputFlag = False

    # Active back-end DBMS fingerprint
    kb.dbms = None
    kb.dbmsFilter = []
    kb.dbmsVersion = [UNKNOWN_DBMS_VERSION]

    kb.delayCandidates = TIME_DELAY_CANDIDATES * [0]
    kb.dep = None
    kb.disableHtmlDecoding = False
    kb.disableShiftTable = False
    kb.dnsMode = False
    kb.dnsTest = None
    kb.docRoot = None
    kb.droppingRequests = False
    kb.dumpColumns = None
    kb.dumpTable = None
    kb.dumpKeyboardInterrupt = False
    kb.dynamicMarkings = []
    kb.dynamicParameter = False
    kb.endDetection = False
    kb.explicitSettings = set()
    kb.extendTests = None
    kb.errorChunkLength = None
    kb.errorIsNone = True
    kb.falsePositives = []
    kb.fileReadMode = False
    kb.fingerprinted = False
    kb.followSitemapRecursion = None
    kb.forcedDbms = None
    kb.forcePartialUnion = False
    kb.forceThreads = None
    kb.forceWhere = None
    kb.forkNote = None
    kb.futileUnion = None
    kb.fuzzUnionTest = None
    kb.gadget = None
    kb.heavilyDynamic = False
    kb.headersFile = None
    kb.headersFp = {}
    kb.heuristicDbms = None
    kb.heuristicExtendedDbms = None
    kb.heuristicCode = None
    kb.heuristicMode = False
    kb.heuristicPage = False
    kb.heuristicTest = None
    kb.hintValue = ""
    kb.jwtChecked = False
    kb.htmlFp = []
    kb.huffmanModel = {}
    kb.respTruncated = False
    kb.huffmanValidated = False
    kb.disableHuffman = False
    kb.huffmanProbes = 0
    kb.huffmanEscapes = 0
    kb.lowCardCache = {}
    kb.dumpCharset = {}
    kb.dumpCharsetStable = {}
    kb.litmusCounter = 0
    kb.reliabilityAlarm = False
    kb.httpErrorCodes = {}
    kb.inferenceMode = False
    kb.ignoreCasted = None
    kb.ignoreNotFound = False
    kb.ignoreTimeout = False
    kb.identifiedWafs = set()
    kb.injection = InjectionDict()
    kb.injections = []
    kb.jsonAggMode = False
    kb.laggingChecked = False
    kb.lastParserStatus = None

    kb.locks = AttribDict()
    for _ in ("authRefresh", "cache", "connError", "count", "handlers", "hint", "identYwaf", "index", "io", "limit", "liveCookies", "log", "multibit", "prediction", "socket", "redirect", "request", "value"):
        kb.locks[_] = threading.Lock()

    kb.authRefreshHeaders = {}
    kb.authRefreshVersion = 0
    kb.authRefreshFailed = False

    kb.matchRatio = None
    kb.maxConnectionsFlag = False
    kb.trueLength = None
    kb.mergeCookies = None
    kb.mysqlUtf8mb4 = None
    kb.multiThreadMode = False
    kb.multibit = {}                    # per injection point: absent=untried, False=unusable, else the row channel profile
    kb.multibitHinted = False
    kb.multipleCtrlC = False
    kb.negativeLogic = False
    kb.nchar = True
    kb.nullConnection = None
    kb.oldMsf = None
    kb.orderByColumns = None
    kb.originalCode = None
    kb.originalPage = None
    kb.originalPageTime = None
    kb.originalTimeDelay = None
    kb.originalUrls = dict()

    # Back-end DBMS underlying operating system fingerprint via banner (-b)
    # parsing
    kb.os = None
    kb.osVersion = None
    kb.osSP = None

    kb.pageCompress = True
    kb.pageTemplate = None
    kb.pageTemplates = dict()
    kb.pageEncoding = DEFAULT_PAGE_ENCODING

    # calibrated TRUE/FALSE reference bodies for the boolean same-HTTP-code anomaly guard (inference.py)
    kb.trueTemplate = None
    kb.falseTemplate = None

    # latched once network jitter is observed, so character validation escalates to a majority vote
    kb.jitterSeen = False
    kb.pageStable = None
    kb.pageStructurallyStable = None
    kb.partRun = None
    kb.permissionFlag = False
    kb.place = None
    kb.postHint = None
    kb.grpcWeb = None
    kb.postSpaceToPlus = False
    kb.postUrlEncode = True
    kb.prependFlag = False
    kb.processResponseCounter = 0
    kb.previousMethod = None
    kb.processNonCustom = None
    kb.processUserMarks = None
    kb.proxies = None
    kb.proxyAuthHeader = None
    kb.queryCounter = 0
    kb.randomPool = {}
    kb.reflectiveMechanism = True
    kb.reflectiveCounters = {REFLECTIVE_COUNTER.MISS: 0, REFLECTIVE_COUNTER.HIT: 0}
    kb.requestCounter = 0
    kb.resendPostOnRedirect = None
    kb.resolutionDbms = None
    kb.responseTimes = {}
    kb.responseTimeMode = None
    kb.responseTimePayload = None
    kb.resumeValues = True
    kb.safeCharEncode = False
    kb.safeReq = AttribDict()
    kb.secondReq = None
    kb.serverHeader = None
    kb.singleLogFlags = set()
    kb.skipSeqMatcher = False
    kb.smokeMode = False
    kb.reduceTests = None
    kb.sslSuccess = False
    kb.startTime = time.time()
    kb.stickyDBMS = False
    kb.suppressResumeInfo = False
    kb.tableFrom = None
    kb.technique = None
    kb.timeless = None          # active HTTP/2 timeless-timing oracle (lib/request/timeless.py) or None
    kb.timelessHinted = False   # whether the "target speaks HTTP/2 -> try --timeless" nudge was shown (once/run)
    kb.timelessRestore = None   # classic time-based vector to re-forge stragglers onto after disengaging
    kb.tempDir = None
    kb.testMode = False
    kb.testOnlyCustom = False
    kb.testQueryCount = 0
    kb.testType = None
    kb.threadContinue = True
    kb.threadException = False
    kb.uChar = NULL
    kb.udfFail = False
    kb.unionDuplicates = False
    kb.unionTemplate = None
    kb.wafBypass = None
    kb.webSocketRecvCount = None
    kb.wizardMode = False
    kb.xpCmdshellAvailable = False

    if flushAll:
        kb.checkSitemap = None
        kb.crawledHosts = set()                            # hosts whose robots.txt / well-known paths were already probed
        kb.headerPaths = {}
        kb.keywords = set(getFileItems(paths.SQL_KEYWORDS))
        kb.lastCtrlCTime = None
        kb.normalizeCrawlingChoice = None
        kb.passwordMgr = None
        kb.postprocessFunctions = []
        kb.preprocessFunctions = []
        kb.authRefreshFunction = None
        kb.skipVulnHost = None
        kb.storeCrawlingChoice = None
        kb.tamperFunctions = []
        kb.targets = OrderedSet()
        kb.testedParams = set()
        kb.userAgents = None
        kb.vainRun = True
        kb.vulnHosts = set()
        kb.wafFunctions = []
        kb.wordlists = None

def _useWizardInterface():
    """
    Presents simple wizard interface for beginner users
    """

    if not conf.wizard:
        return

    logger.info('sozlash yordamchisi ishga tushirilmoqda')

    while not conf.url:
        message = ut('Please enter full target URL (-u): ', "Nishonning to'liq URL manzilini kiriting (-u): ")
        conf.url = readInput(message, default=None, checkBatch=False)

    message = ut('%s data (--data) [Enter for None]: ', "%s ma'lumotlari (--data) [yo'q bo'lsa Enter]: ") % ((conf.method if conf.method != HTTPMETHOD.GET else None) or HTTPMETHOD.POST)
    conf.data = readInput(message, default=None)

    if not (any('=' in _ for _ in (conf.url, conf.data)) or '*' in conf.url):
        warnMsg = 'tekshirish uchun GET va/yoki %s parametrlari topilmadi ' % ((conf.method if conf.method != HTTPMETHOD.GET else None) or HTTPMETHOD.POST)
        warnMsg += "(masalan, 'http://www.site.com/vuln.php?id=1' dagi GET 'id' parametri). "
        if not conf.crawlDepth and not conf.forms:
            warnMsg += 'Formalar qidiriladi'
            conf.forms = True
        logger.warning(warnMsg)

    choice = None

    while choice is None or choice not in ("", "1", "2", "3"):
        message = ut('Injection difficulty (--level/--risk). Please choose:\n', 'Inyeksiya murakkabligi (--level/--risk). Tanlang:\n')
        message += ut('[1] Normal (default)\n[2] Medium\n[3] Hard', "[1] Oddiy (standart)\n[2] O'rtacha\n[3] Murakkab")
        choice = readInput(message, default='1')

        if choice == '2':
            conf.risk = 2
            conf.level = 3
        elif choice == '3':
            conf.risk = 3
            conf.level = 5
        else:
            conf.risk = 1
            conf.level = 1

    if not conf.getAll:
        choice = None

        while choice is None or choice not in ("", "1", "2", "3"):
            message = ut('Enumeration (--banner/--current-user/etc). Please choose:\n', "Ma'lumot olish (--banner/--current-user/va boshqalar). Tanlang:\n")
            message += ut('[1] Basic (default)\n[2] Intermediate\n[3] All', "[1] Asosiy (standart)\n[2] O'rtacha\n[3] Barchasi")
            choice = readInput(message, default='1')

            if choice == '2':
                options = WIZARD.INTERMEDIATE
            elif choice == '3':
                options = WIZARD.ALL
            else:
                options = WIZARD.BASIC

            for _ in options:
                conf.__setitem__(_, True)

    logger.debug('sqlmap chiqishi kamaytirilmoqda.. ish avtomatik bajariladi')
    conf.verbose = 0

    conf.batch = True
    conf.threads = 4

    dataToStdout('\nsqlmap ishlamoqda, kuting..\n\n')

    kb.wizardMode = True

def _saveConfig():
    """
    Saves the command line options to a sqlmap configuration INI file
    Format.
    """

    if not conf.saveConfig:
        return

    debugMsg = 'buyruq qatori parametrlari INI fayliga saqlanmoqda'
    logger.debug(debugMsg)

    saveConfig(conf, conf.saveConfig)

    infoMsg = "buyruq qatori parametrlari '%s' ga saqlandi" % conf.saveConfig
    logger.info(infoMsg)

def setVerbosity():
    """
    This function set the verbosity of sqlmap output messages.
    """

    if conf.verbose is None:
        conf.verbose = 1

    conf.verbose = int(conf.verbose)

    if conf.verbose == 0:
        logger.setLevel(logging.ERROR)
    elif conf.verbose == 1:
        logger.setLevel(logging.INFO)
    elif conf.verbose > 2 and conf.eta:
        conf.verbose = 2
        logger.setLevel(logging.DEBUG)
    elif conf.verbose == 2:
        logger.setLevel(logging.DEBUG)
    elif conf.verbose == 3:
        logger.setLevel(CUSTOM_LOGGING.PAYLOAD)
    elif conf.verbose == 4:
        logger.setLevel(CUSTOM_LOGGING.TRAFFIC_OUT)
    elif conf.verbose >= 5:
        logger.setLevel(CUSTOM_LOGGING.TRAFFIC_IN)

def _normalizeOptions(inputOptions):
    """
    Sets proper option types
    """

    types_ = {}
    for group in optDict.keys():
        types_.update(optDict[group])

    for key in inputOptions:
        if key in types_:
            value = inputOptions[key]
            if value is None:
                continue

            type_ = types_[key]
            if type_ and isinstance(type_, tuple):
                type_ = type_[0]

            if type_ == OPTION_TYPE.BOOLEAN:
                try:
                    value = bool(value)
                except (TypeError, ValueError):
                    value = False
            elif type_ == OPTION_TYPE.INTEGER:
                try:
                    value = int(value)
                except (TypeError, ValueError):
                    value = 0
            elif type_ == OPTION_TYPE.FLOAT:
                try:
                    value = float(value)
                except (TypeError, ValueError):
                    value = 0.0

            inputOptions[key] = value

def _mergeOptions(inputOptions, overrideOptions):
    """
    Merge command line options with configuration file and default options.

    @param inputOptions: optparse object with command line options.
    @type inputOptions: C{instance}
    """

    if inputOptions.configFile:
        configFileParser(inputOptions.configFile)

    if hasattr(inputOptions, "items"):
        inputOptionsItems = inputOptions.items()
    else:
        inputOptionsItems = inputOptions.__dict__.items()

    for key, value in inputOptionsItems:
        if key not in conf or value not in (None, False) or overrideOptions:
            conf[key] = value

    if not conf.api:
        for key, value in conf.items():
            if value is not None:
                kb.explicitSettings.add(key)

    for key, value in defaults.items():
        if hasattr(conf, key) and conf[key] is None:
            conf[key] = value

            if conf.unstable:
                if key in ("timeSec", "retries", "timeout"):
                    conf[key] *= 2

    if conf.unstable:
        conf.forcePartial = True

    lut = {}
    for group in optDict.keys():
        lut.update((_.upper(), _) for _ in optDict[group])

    envOptions = {}
    for key, value in os.environ.items():
        if key.upper().startswith(SQLMAP_ENVIRONMENT_PREFIX):
            _ = key[len(SQLMAP_ENVIRONMENT_PREFIX):].upper()
            if _ in lut:
                envOptions[lut[_]] = value

    if envOptions:
        _normalizeOptions(envOptions)
        for key, value in envOptions.items():
            conf[key] = value

    mergedOptions.update(conf)

def _setTrafficOutputFP():
    if conf.trafficFile:
        infoMsg = 'HTTP trafik jurnali fayli sozlanmoqda'
        logger.info(infoMsg)

        conf.trafficFP = openFile(conf.trafficFile, "w+")

def _setupHTTPCollector():
    if not conf.harFile:
        return

    conf.httpCollector = HTTPCollectorFactory(conf.harFile).create()

def _setDNSServer():
    if not conf.dnsDomain:
        return

    from lib.core.settings import OOB_INTERACTSH_SERVERS

    _requested = conf.dnsDomain.strip().lower()
    if _requested in ("interactsh", "oast", "oob") or _requested in OOB_INTERACTSH_SERVERS:
        infoMsg = "interactsh orqali DNS ma'lumot yig'ish sozlanmoqda"
        logger.info(infoMsg)

        try:
            conf.dnsServer = InteractshDNSServer(server=_requested if _requested in OOB_INTERACTSH_SERVERS else None)
            conf.dnsServer.run()
            conf.dnsDomain = conf.dnsServer.domain
        except socket.error as ex:
            errMsg = 'ishga tayyorlashda xato yuz berdi: '
            errMsg += "interactsh DNS yig'uvchisi ('%s')" % getSafeExString(ex)
            raise SqlmapGenericException(errMsg)

        infoMsg = "interactsh DNS yig'uvchisi ishlatilmoqda (ma'lumot chiqarish domeni: '%s')" % conf.dnsDomain
        logger.info(infoMsg)
        return

    infoMsg = 'DNS serveri ishga tayyorlanmoqda'
    logger.info(infoMsg)

    isAdmin = runningAsAdmin()

    if isAdmin:
        try:
            conf.dnsServer = DNSServer()
            conf.dnsServer.run()
        except socket.error as ex:
            errMsg = 'ishga tayyorlashda xato yuz berdi: '
            errMsg += "DNS serveri ('%s')" % getSafeExString(ex)
            raise SqlmapGenericException(errMsg)
    else:
        errMsg = 'sqlmapni administrator sifatida ishga tushiring, '
        errMsg += "agar DNS orqali ma'lumot chiqarishni bajarmoqchi bo'lsangiz, "
        errMsg += 'chunki maxsus UDP 53 portini tinglash kerak: '
        errMsg += "kiruvchi manzil aniqlash so'rovlari uchun"
        raise SqlmapMissingPrivileges(errMsg)

def _setProxyList():
    if not conf.proxyFile:
        return

    conf.proxyList = []
    # Note: preserve an explicit scheme and any 'user:pass@' credentials (entries use the same format
    # as --proxy); otherwise a SOCKS proxy is silently downgraded to HTTP and proxy auth is dropped
    for match in re.finditer(r"(?i)((http[^:\s]*|socks[^:\s]*)://)?(?:([^:@\s/]+:[^@\s/]*)@)?([\w\-.]+):(\d+)", readCachedFileContent(conf.proxyFile)):
        _, type_, cred, address, port = match.groups()
        conf.proxyList.append("%s://%s%s:%s" % (type_ or "http", ("%s@" % cred) if cred else "", address, port))

def _setTorProxySettings():
    if not conf.tor:
        return

    if conf.torType == PROXY_TYPE.HTTP:
        _setTorHttpProxySettings()
    else:
        _setTorSocksProxySettings()

def _setTorHttpProxySettings():
    infoMsg = 'Tor HTTP proksisi sozlanmoqda'
    logger.info(infoMsg)

    port = findLocalPort(DEFAULT_TOR_HTTP_PORTS if not conf.torPort else (conf.torPort,))

    if port:
        conf.proxy = "http://%s:%d" % (LOCALHOST, port)
    else:
        errMsg = "Tor HTTP proksisiga ulanib bo'lmadi. "
        errMsg += "Tor to'plami o'rnatilgan va sozlanganini tekshiring, "
        errMsg += "'--tor' dan muvaffaqiyatli foydalanish uchun "
        raise SqlmapConnectionException(errMsg)

    if not conf.checkTor:
        warnMsg = "'--check-tor' dan foydalaning, "
        warnMsg += "Tor anonim tarmog'iga "
        warnMsg += 'ulanishda, chunki '
        warnMsg += "ayrim to'plamlarning standart sozlamalarida muammolar bor "
        warnMsg += '(masalan, Vidalia)'
        logger.warning(warnMsg)

def _setTorSocksProxySettings():
    infoMsg = 'Tor SOCKS proksisi sozlanmoqda'
    logger.info(infoMsg)

    port = findLocalPort(DEFAULT_TOR_SOCKS_PORTS if not conf.torPort else (conf.torPort,))

    if not port:
        errMsg = "Tor SOCKS proksisiga ulanib bo'lmadi. "
        errMsg += "Tor xizmati o'rnatilgan va sozlanganini tekshiring, "
        errMsg += "'--tor' dan muvaffaqiyatli foydalanish uchun "
        raise SqlmapConnectionException(errMsg)

    # SOCKS5 to prevent DNS leaks (http://en.wikipedia.org/wiki/Tor_%28anonymity_network%29)
    socks.setdefaultproxy(socks.PROXY_TYPE_SOCKS5 if conf.torType == PROXY_TYPE.SOCKS5 else socks.PROXY_TYPE_SOCKS4, LOCALHOST, port)
    socks.wrapmodule(_http_client)

def _setHttpOptions():
    if conf.chunked and conf.data:
        if hasattr(_http_client.HTTPConnection, "_set_content_length"):
            _http_client.HTTPConnection._set_content_length = lambda self, *args, **kwargs: None
        else:
            def putheader(self, header, *values):
                if header != HTTP_HEADER.CONTENT_LENGTH:
                    self._putheader(header, *values)

            if not hasattr(_http_client.HTTPConnection, "_putheader"):
                _http_client.HTTPConnection._putheader = _http_client.HTTPConnection.putheader

            _http_client.HTTPConnection.putheader = putheader

    if conf.http10:
        _http_client.HTTPConnection._http_vsn = 10
        _http_client.HTTPConnection._http_vsn_str = 'HTTP/1.0'

def _checkTor():
    if not conf.checkTor:
        return

    infoMsg = 'Tor ulanishi tekshirilmoqda'
    logger.info(infoMsg)

    try:
        page, _, _ = Request.getPage(url="https://check.torproject.org/api/ip", raise404=False)
        tor_status = json.loads(page)
    except (SqlmapConnectionException, TypeError, ValueError):
        tor_status = None

    if not tor_status or not tor_status.get("IsTor"):
        errMsg = "Tor noto'g'ri sozlanganga o'xshaydi. '--tor-type' va/yoki '--tor-port' ni sinab ko'ring"
        raise SqlmapConnectionException(errMsg)
    else:
        infoMsg = "Tor to'g'ri ishlatilmoqda"
        logger.info(infoMsg)

def _basicOptionValidation():
    _nonSqlTechniques = ["--%s" % _ for _ in NONSQL_TECHNIQUES if conf.get(_)]
    if len(_nonSqlTechniques) > 1:
        errMsg = "bir vaqtda faqat bitta SQL bo'lmagan usul ishlatiladi (topildi: %s). " % ", ".join(_nonSqlTechniques)
        errMsg += 'har biri alohida server turini tekshiradi; bittasini tanlang'
        raise SqlmapSyntaxException(errMsg)

    if conf.limitStart is not None and not (isinstance(conf.limitStart, int) and conf.limitStart > 0):
        errMsg = "'--start' (limitStart) noldan katta butun son bo'lishi kerak (>0)"
        raise SqlmapSyntaxException(errMsg)

    if conf.limitStop is not None and not (isinstance(conf.limitStop, int) and conf.limitStop > 0):
        errMsg = "'--stop' (limitStop) noldan katta butun son bo'lishi kerak (>0)"
        raise SqlmapSyntaxException(errMsg)

    if conf.level is not None and not (isinstance(conf.level, int) and conf.level >= 1 and conf.level <= 5):
        errMsg = "'--level' [1, 5] oralig'idagi butun son bo'lishi kerak"
        raise SqlmapSyntaxException(errMsg)

    if conf.risk is not None and not (isinstance(conf.risk, int) and conf.risk >= 1 and conf.risk <= 3):
        errMsg = "'--risk' [1, 3] oralig'idagi butun son bo'lishi kerak"
        raise SqlmapSyntaxException(errMsg)

    if isinstance(conf.limitStart, int) and conf.limitStart > 0 and \
       isinstance(conf.limitStop, int) and conf.limitStop < conf.limitStart:
        warnMsg = "'--start' (limitStart) qiymati --stop (limitStop) dan katta bo'lsa, ishlash beqaror bo'lishi mumkin"
        logger.warning(warnMsg)

    if isinstance(conf.firstChar, int) and conf.firstChar > 0 and \
       isinstance(conf.lastChar, int) and conf.lastChar < conf.firstChar:
        errMsg = "'--first' (firstChar) qiymati --last (lastChar) dan kichik yoki teng bo'lishi kerak"
        raise SqlmapSyntaxException(errMsg)

    if conf.proxyFile and not any((conf.randomAgent, conf.mobile, conf.agent, conf.requestFile)):
        warnMsg = "'--random-agent' dan foydalanish tavsiya etiladi, "
        warnMsg += "'--proxy-file' ishlatilganda"
        logger.warning(warnMsg)

    if conf.textOnly and conf.nullConnection:
        errMsg = "'--text-only' '--null-connection' bilan mos emas"
        raise SqlmapSyntaxException(errMsg)

    if conf.http2 and any((conf.tor, conf.proxy and conf.proxy.lower().startswith("socks"))):
        errMsg = 'HTTP/2 hozircha SOCKS/Tor proksilari bilan mos emas'
        raise SqlmapSyntaxException(errMsg)

    if conf.uValues and conf.uChar:
        errMsg = "'--union-values' '--union-char' bilan mos emas"
        raise SqlmapSyntaxException(errMsg)

    if conf.base64Parameter and conf.tamper:
        errMsg = "'--base64' '--tamper' bilan mos emas"
        raise SqlmapSyntaxException(errMsg)

    if conf.eta and conf.verbose > defaults.verbose:
        errMsg = "'--eta' '-v' bilan mos emas"
        raise SqlmapSyntaxException(errMsg)

    if conf.secondUrl and conf.secondReq:
        errMsg = "'--second-url' '--second-req') bilan mos emas"
        raise SqlmapSyntaxException(errMsg)

    if conf.direct and conf.url:
        errMsg = "'-d' '-u' ('--url') bilan mos emas"
        raise SqlmapSyntaxException(errMsg)

    if conf.direct and conf.dbms:
        errMsg = "'-d' '--dbms' bilan mos emas"
        raise SqlmapSyntaxException(errMsg)

    if conf.titles and conf.nullConnection:
        errMsg = "'--titles' '--null-connection' bilan mos emas"
        raise SqlmapSyntaxException(errMsg)

    if conf.dumpTable and conf.search:
        errMsg = "'--dump' '--search' bilan mos emas"
        raise SqlmapSyntaxException(errMsg)

    if conf.alert and os.environ.get("SQLMAP_UNSAFE_ALERT") != '1':
        errMsg = 'xavfsizlik uchun, ehtimoliy zararli kod bajarilishining oldini olish maqsadida, '
        errMsg += "sozlash fayli yoki ko'chirib qo'yish orqali OT buyruqlarini bajarishda "
        errMsg += "'--alert' uchun muhit o'zgaruvchisi "
        errMsg += "'SQLMAP_UNSAFE_ALERT=1' aniq belgilanishi kerak"
        raise SqlmapSystemException(errMsg)

    if conf.evalCode and os.environ.get("SQLMAP_UNSAFE_EVAL") != '1':
        errMsg = 'xavfsizlik uchun, ehtimoliy zararli kod bajarilishining oldini olish maqsadida, '
        errMsg += "sozlash fayli yoki ko'chirib qo'yish orqali Python kodini bajarishda "
        errMsg += "'--eval' uchun muhit o'zgaruvchisi "
        errMsg += "'SQLMAP_UNSAFE_EVAL=1' aniq belgilanishi kerak"
        raise SqlmapSystemException(errMsg)

    if conf.chunked and not any((conf.data, conf.requestFile, conf.forms, conf.openApiFile)):
        errMsg = "'--chunked' uchun POST parametrlari kerak: '--data', '-r', '--forms' yoki '--openapi'"
        raise SqlmapSyntaxException(errMsg)

    if conf.api and not conf.configFile:
        errMsg = "'--api' uchun '-c' kerak"
        raise SqlmapSyntaxException(errMsg)

    if conf.data and conf.nullConnection:
        errMsg = "'--data' '--null-connection' bilan mos emas"
        raise SqlmapSyntaxException(errMsg)

    if conf.string and conf.nullConnection:
        errMsg = "'--string' '--null-connection' bilan mos emas"
        raise SqlmapSyntaxException(errMsg)

    if conf.notString and conf.nullConnection:
        errMsg = "'--not-string' '--null-connection' bilan mos emas"
        raise SqlmapSyntaxException(errMsg)

    if conf.tor and conf.osPwn:
        errMsg = "'--tor' '--os-pwn' bilan mos emas"
        raise SqlmapSyntaxException(errMsg)

    if conf.noCast and conf.hexConvert:
        errMsg = "'--no-cast' '--hex' bilan mos emas"
        raise SqlmapSyntaxException(errMsg)

    if conf.crawlDepth:
        try:
            xrange(conf.crawlDepth)
        except OverflowError as ex:
            errMsg = "'--crawl' uchun noto'g'ri qiymat ('%s')" % getSafeExString(ex)
            raise SqlmapSyntaxException(errMsg)

    if conf.dumpAll and conf.search:
        errMsg = "'--dump-all' '--search' bilan mos emas"
        raise SqlmapSyntaxException(errMsg)

    if conf.string and conf.notString:
        errMsg = "'--string' '--not-string' bilan mos emas"
        raise SqlmapSyntaxException(errMsg)

    if conf.regexp and conf.nullConnection:
        errMsg = "'--regexp' '--null-connection' bilan mos emas"
        raise SqlmapSyntaxException(errMsg)

    if conf.regexp:
        try:
            re.compile(conf.regexp)
        except Exception as ex:
            errMsg = "noto'g'ri muntazam ifoda: '%s' ('%s')" % (conf.regexp, getSafeExString(ex))
            raise SqlmapSyntaxException(errMsg)

    if conf.paramExclude:
        if re.search(r"\A\w+,", conf.paramExclude):
            conf.paramExclude = r"\A(%s)\Z" % ('|'.join(re.escape(_).strip() for _ in conf.paramExclude.split(',')))

        try:
            re.compile(conf.paramExclude)
        except Exception as ex:
            errMsg = "noto'g'ri muntazam ifoda: '%s' ('%s')" % (conf.paramExclude, getSafeExString(ex))
            raise SqlmapSyntaxException(errMsg)

    if conf.retryOn:
        try:
            re.compile(conf.retryOn)
        except Exception as ex:
            errMsg = "noto'g'ri muntazam ifoda: '%s' ('%s')" % (conf.retryOn, getSafeExString(ex))
            raise SqlmapSyntaxException(errMsg)

        if conf.retries == defaults.retries:
            conf.retries = 5 * conf.retries

            warnMsg = 'standart qiymat oshirilmoqda: '
            warnMsg += "'--retries' %d ga, chunki " % conf.retries
            warnMsg += "'--retry-on' berilgan"
            logger.warning(warnMsg)

    if conf.cookieDel and len(conf.cookieDel) != 1:
        errMsg = "'--cookie-del' bitta belgi bo'lishi kerak (masalan, ';')"
        raise SqlmapSyntaxException(errMsg)

    if conf.crawlExclude:
        try:
            re.compile(conf.crawlExclude)
        except Exception as ex:
            errMsg = "noto'g'ri muntazam ifoda: '%s' ('%s')" % (conf.crawlExclude, getSafeExString(ex))
            raise SqlmapSyntaxException(errMsg)

    if conf.scope:
        try:
            re.compile(conf.scope)
        except Exception as ex:
            errMsg = "noto'g'ri muntazam ifoda: '%s' ('%s')" % (conf.scope, getSafeExString(ex))
            raise SqlmapSyntaxException(errMsg)

    if conf.dumpTable and conf.dumpAll:
        errMsg = "'--dump' '--dump-all' bilan mos emas"
        raise SqlmapSyntaxException(errMsg)

    if conf.threads > MAX_NUMBER_OF_THREADS and not conf.get("skipThreadCheck"):
        errMsg = "ulanish muammolaridan qochish uchun eng ko'p oqimlar soni %d" % MAX_NUMBER_OF_THREADS
        raise SqlmapSyntaxException(errMsg)

    if conf.forms and not any((conf.url, conf.googleDork, conf.bulkFile)):
        errMsg = "'--forms' uchun '-u' ('--url'), '-g' yoki '-m' kerak"
        raise SqlmapSyntaxException(errMsg)

    if conf.crawlExclude and not conf.crawlDepth:
        errMsg = "'--crawl-exclude' uchun '--crawl' kerak"
        raise SqlmapSyntaxException(errMsg)

    if conf.safePost and not conf.safeUrl:
        errMsg = "'--safe-post' uchun '--safe-url' kerak"
        raise SqlmapSyntaxException(errMsg)

    if conf.safeFreq and not any((conf.safeUrl, conf.safeReqFile)):
        errMsg = "'--safe-freq' uchun '--safe-url' yoki '--safe-req' kerak"
        raise SqlmapSyntaxException(errMsg)

    if conf.safeReqFile and any((conf.safeUrl, conf.safePost)):
        errMsg = "'--safe-req' '--safe-url' va '--safe-post' bilan mos emas"
        raise SqlmapSyntaxException(errMsg)

    if conf.csrfUrl and not conf.csrfToken:
        errMsg = "'--csrf-url' uchun '--csrf-token' kerak"
        raise SqlmapSyntaxException(errMsg)

    if conf.csrfMethod and not conf.csrfToken:
        errMsg = "'--csrf-method' uchun '--csrf-token' kerak"
        raise SqlmapSyntaxException(errMsg)

    if conf.csrfData and not conf.csrfToken:
        errMsg = "'--csrf-data' uchun '--csrf-token' kerak"
        raise SqlmapSyntaxException(errMsg)

    if conf.csrfToken and conf.threads > 1:
        errMsg = "'--csrf-token' '--threads' bilan mos emas"
        raise SqlmapSyntaxException(errMsg)

    if conf.requestFile and conf.url and conf.url != DUMMY_URL:
        errMsg = "'-r' '-u' ('--url') bilan mos emas"
        raise SqlmapSyntaxException(errMsg)

    if conf.direct and conf.proxy:
        errMsg = "'-d' '--proxy' bilan mos emas"
        raise SqlmapSyntaxException(errMsg)

    if conf.direct and conf.tor:
        errMsg = "'-d' '--tor' bilan mos emas"
        raise SqlmapSyntaxException(errMsg)

    if not conf.technique:
        errMsg = "'--technique' bo'sh bo'lishi mumkin emas"
        raise SqlmapSyntaxException(errMsg)

    if conf.tor and conf.ignoreProxy:
        errMsg = "'--tor' '--ignore-proxy' bilan mos emas"
        raise SqlmapSyntaxException(errMsg)

    if conf.tor and conf.proxy:
        errMsg = "'--tor' '--proxy' bilan mos emas"
        raise SqlmapSyntaxException(errMsg)

    if conf.proxy and conf.proxyFile:
        errMsg = "'--proxy' '--proxy-file' bilan mos emas"
        raise SqlmapSyntaxException(errMsg)

    if conf.proxyFreq and not conf.proxyFile:
        errMsg = "'--proxy-freq' uchun '--proxy-file' kerak"
        raise SqlmapSyntaxException(errMsg)

    if conf.checkTor and not any((conf.tor, conf.proxy)):
        errMsg = "'--check-tor' uchun '--tor' (yoki Tor HTTP proksi manzili bilan '--proxy') kerak"
        raise SqlmapSyntaxException(errMsg)

    if conf.torPort is not None and not (isinstance(conf.torPort, int) and conf.torPort >= 0 and conf.torPort <= 65535):
        errMsg = "'--tor-port' [0, 65535] oralig'ida bo'lishi kerak"
        raise SqlmapSyntaxException(errMsg)

    if conf.torType not in getPublicTypeMembers(PROXY_TYPE, True):
        errMsg = "'--tor-type' quyidagi qiymatlardan birini qabul qiladi: %s" % ", ".join(getPublicTypeMembers(PROXY_TYPE, True))
        raise SqlmapSyntaxException(errMsg)

    if conf.dumpFormat not in getPublicTypeMembers(DUMP_FORMAT, True):
        errMsg = "'--dump-format' quyidagi qiymatlardan birini qabul qiladi: %s" % ", ".join(getPublicTypeMembers(DUMP_FORMAT, True))
        raise SqlmapSyntaxException(errMsg)

    if conf.uValues and (not re.search(r"\A['\w\s.,()%s-]+\Z" % CUSTOM_INJECTION_MARK_CHAR, conf.uValues) or conf.uValues.count(CUSTOM_INJECTION_MARK_CHAR) != 1):
        errMsg = "'--union-values' yaroqli UNION ustun qiymatlari va inyeksiya joyini o'z ichiga olishi kerak "
        errMsg += "(masalan, 'NULL,1,%s,NULL')" % CUSTOM_INJECTION_MARK_CHAR
        raise SqlmapSyntaxException(errMsg)

    if conf.skip and conf.testParameter:
        if intersect(conf.skip, conf.testParameter):
            errMsg = "'--skip' '-p' bilan mos emas"
            raise SqlmapSyntaxException(errMsg)

    if conf.rParam and conf.testParameter:
        if intersect(conf.rParam, conf.testParameter):
            errMsg = "'--randomize' '-p' bilan mos emas"
            raise SqlmapSyntaxException(errMsg)

    if conf.mobile and conf.agent:
        errMsg = "'--mobile' '--user-agent' bilan mos emas"
        raise SqlmapSyntaxException(errMsg)

    if conf.proxy and conf.ignoreProxy:
        errMsg = "'--proxy' '--ignore-proxy' bilan mos emas"
        raise SqlmapSyntaxException(errMsg)

    if conf.alert and conf.alert.startswith('-'):
        errMsg = "'--alert' yaroqli operatsion tizim buyrug'i bo'lishi kerak"
        raise SqlmapSyntaxException(errMsg)

    if conf.timeSec < 1:
        errMsg = "'--time-sec' musbat butun son bo'lishi kerak"
        raise SqlmapSyntaxException(errMsg)

    if conf.hashFile and any((conf.direct, conf.url, conf.logFile, conf.bulkFile, conf.googleDork, conf.configFile, conf.requestFile, conf.updateAll, conf.smokeTest, conf.wizard, conf.dependencies, conf.purge, conf.listTampers)):
        errMsg = "'--crack' alohida ishlatilishi kerak"
        raise SqlmapSyntaxException(errMsg)

    if isinstance(conf.uCols, six.string_types):
        if not conf.uCols.isdigit() and ("-" not in conf.uCols or len(conf.uCols.split("-")) != 2):
            errMsg = "'--union-cols' chiziqchali oraliq bo'lishi kerak "
            errMsg += '(masalan, 1-10) yoki butun son (masalan, 5)'
            raise SqlmapSyntaxException(errMsg)

    if conf.dbmsCred and ':' not in conf.dbmsCred:
        errMsg = "'--dbms-cred' qiymati quyidagi "
        errMsg += 'formatda bo\'lsin: <username>:<password> (masalan, "root:pass")'
        raise SqlmapSyntaxException(errMsg)

    if conf.encoding:
        _ = checkCharEncoding(conf.encoding, False)
        if _ is None:
            errMsg = "noma'lum kodlash: '%s'. Murojaat qiling: " % conf.encoding
            errMsg += "'%s', to'liq ro'yxatni olish uchun: " % CODECS_LIST_PAGE
            errMsg += "qo'llanadigan kodlashlar"
            raise SqlmapSyntaxException(errMsg)
        else:
            conf.encoding = _

    if conf.fileWrite and not os.path.isfile(conf.fileWrite):
        errMsg = "'%s' fayli mavjud emas" % os.path.abspath(conf.fileWrite)
        raise SqlmapFilePathException(errMsg)

    if conf.loadCookies and not os.path.exists(conf.loadCookies):
        errMsg = "'%s' cookie fayli mavjud emas" % os.path.abspath(conf.loadCookies)
        raise SqlmapFilePathException(errMsg)

def initOptions(inputOptions=AttribDict(), overrideOptions=False):
    _setConfAttributes()
    _setKnowledgeBaseAttributes()
    _mergeOptions(inputOptions, overrideOptions)

def init():
    """
    Set attributes into both configuration and knowledge base singletons
    based upon command line and configuration file options.
    """

    _useWizardInterface()
    setVerbosity()
    _saveConfig()
    _setRequestFromFile()
    _cleanupOptions()
    _cleanupEnvironment()
    _purge()
    _checkDependencies()
    _createHomeDirectories()
    _createTemporaryDirectory()
    _basicOptionValidation()
    _setProxyList()
    _setTorProxySettings()
    _setDNSServer()
    _adjustLoggingFormatter()
    _setMultipleTargets()
    _listTamperingFunctions()
    _setTamperingFunctions()
    _setPreprocessFunctions()
    _setPostprocessFunctions()
    _setAuthRefreshFunction()
    _setTrafficOutputFP()
    _setupHTTPCollector()
    _setHttpOptions()

    parseTargetDirect()

    if any((conf.url, conf.logFile, conf.bulkFile, conf.requestFile, conf.googleDork, conf.stdinPipe, conf.openApiFile)):
        _setHostname()
        _setHTTPTimeout()
        _setHTTPExtraHeaders()
        _setHTTPCookies()
        _setHTTPReferer()
        _setHTTPHost()
        _setHTTPUserAgent()
        _setHTTPAuthentication()
        _setHTTPHandlers()
        _setDNSCache()
        _setSocketPreConnect()
        _setSafeVisit()
        _doSearch()
        _setStdinPipeTargets()
        _setBulkMultipleTargets()
        _setOpenApiTargets()
        _checkTor()
        _setCrawler()
        _findPageForms()
        _setDBMS()
        _setTechnique()

    _setThreads()
    _setOS()
    _setWriteFile()
    _setMetasploit()
    _setDBMSAuthentication()
    loadBoundaries()
    loadPayloads()
    _setPrefixSuffix()
    update()
    _loadQueries()
