#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission
"""

from __future__ import division

from lib.core.uzbek import ut
import os
import re
import subprocess
import time

from lib.controller.action import action
from lib.controller.checks import checkConnection
from lib.controller.checks import checkDynParam
from lib.controller.checks import checkInternet
from lib.controller.checks import checkJWT
from lib.controller.checks import checkNullConnection
from lib.controller.checks import checkSqlInjection
from lib.controller.checks import checkStability
from lib.controller.checks import checkWaf
from lib.controller.checks import heuristicCheckSqlInjection
from lib.core.agent import agent
from lib.core.common import dataToStdout
from lib.core.common import extractRegexResult
from lib.core.common import getFilteredPageContent
from lib.core.common import getPublicTypeMembers
from lib.core.common import getSafeExString
from lib.core.common import hashDBRetrieve
from lib.core.common import hashDBWrite
from lib.core.common import intersect
from lib.core.common import isDigit
from lib.core.common import isListLike
from lib.core.common import parseTargetUrl
from lib.core.common import popValue
from lib.core.common import pushValue
from lib.core.common import randomInt
from lib.core.common import randomStr
from lib.core.common import readInput
from lib.core.common import removePostHintPrefix
from lib.core.common import safeCSValue
from lib.core.common import showHttpErrorCodes
from lib.core.common import singleTimeWarnMessage
from lib.core.common import urldecode
from lib.core.common import urlencode
from lib.core.compat import xrange
from lib.core.data import conf
from lib.core.data import kb
from lib.core.data import logger
from lib.core.decorators import stackedmethod
from lib.core.enums import CONTENT_TYPE
from lib.core.enums import HASHDB_KEYS
from lib.core.enums import HEURISTIC_TEST
from lib.core.enums import HTTP_HEADER
from lib.core.enums import HTTPMETHOD
from lib.core.enums import NOTE
from lib.core.enums import PAYLOAD
from lib.core.enums import PLACE
from lib.core.exception import SqlmapBaseException
from lib.core.exception import SqlmapConnectionException
from lib.core.exception import SqlmapNoneDataException
from lib.core.exception import SqlmapNotVulnerableException
from lib.core.exception import SqlmapSilentQuitException
from lib.core.exception import SqlmapSkipTargetException
from lib.core.exception import SqlmapSystemException
from lib.core.exception import SqlmapUserQuitException
from lib.core.exception import SqlmapValueException
from lib.core.settings import ASP_NET_CONTROL_REGEX
from lib.core.settings import CSRF_TOKEN_PARAMETER_INFIXES
from lib.core.settings import DEFAULT_GET_POST_DELIMITER
from lib.core.settings import NONSQL_TECHNIQUES
from lib.core.settings import EMPTY_FORM_FIELDS_REGEX
from lib.core.settings import GOOGLE_ANALYTICS_COOKIE_REGEX
from lib.core.settings import HASHDB_STALE_DAYS
from lib.core.settings import HOST_ALIASES
from lib.core.settings import IGNORE_PARAMETERS
from lib.core.settings import LOW_TEXT_PERCENT
from lib.core.settings import REFERER_ALIASES
from lib.core.settings import USER_AGENT_ALIASES
from lib.core.settings import WAF_BYPASS_MAX_TRIALS
from lib.core.target import initTargetEnv
from lib.core.target import setupTargetEnv
from lib.utils.hash import crackHashFile

def _selectInjection():
    """
    Selection function for injection place, parameters and type.
    """

    points = {}

    for injection in kb.injections:
        place = injection.place
        parameter = injection.parameter
        ptype = injection.ptype

        point = (place, parameter, ptype)

        if point not in points:
            points[point] = injection
        else:
            for key in points[point]:
                if key != 'data':
                    points[point][key] = points[point][key] or injection[key]
            points[point]['data'].update(injection['data'])

    if len(points) == 1:
        kb.injection = kb.injections[0]

    elif len(points) > 1:
        message = ut('there were multiple injection points, please select ', 'bir nechta inyeksiya nuqtasi topildi; ')
        message += ut('the one to use for following injections:\n', 'keyingi inyeksiyalar uchun birini tanlang:\n')

        points = []

        for i in xrange(0, len(kb.injections)):
            place = kb.injections[i].place
            parameter = kb.injections[i].parameter
            ptype = kb.injections[i].ptype
            point = (place, parameter, ptype)

            if point not in points:
                points.append(point)
                ptype = PAYLOAD.PARAMETER[ptype] if isinstance(ptype, int) else ptype

                message += ut('[%d] place: %s, parameter: ', '[%d] joy: %s, parametr: ') % (i, place)
                message += ut('%s, type: %s', '%s, tur: %s') % (parameter, ptype)

                if i == 0:
                    message += ut(' (default)', ' (standart)')

                message += "\n"

        message += ut('[q] Quit', '[q] Chiqish')
        choice = readInput(message, default='0').upper()

        if isDigit(choice) and int(choice) < len(kb.injections) and int(choice) >= 0:
            index = int(choice)
        elif choice == 'Q':
            raise SqlmapUserQuitException
        else:
            errMsg = "noto'g'ri tanlov"
            raise SqlmapValueException(errMsg)

        kb.injection = kb.injections[index]

def _formatInjection(inj):
    paramType = conf.method if conf.method not in (None, HTTPMETHOD.GET, HTTPMETHOD.POST) else inj.place
    data = 'Parametr: %s (%s)\n' % (inj.parameter, paramType)

    for stype, sdata in inj.data.items():
        title = sdata.title
        vector = sdata.vector
        comment = sdata.comment
        payload = agent.adjustLateValues(sdata.payload)
        if inj.place == PLACE.CUSTOM_HEADER:
            payload = payload.split(',', 1)[1]
        if stype == PAYLOAD.TECHNIQUE.UNION:
            count = re.sub(r"(?i)(\(.+\))|(\blimit[^a-z]+)", "", sdata.payload).count(',') + 1
            title = re.sub(r"\d+ to \d+", str(count), title)
            vector = agent.forgeUnionQuery("[QUERY]", vector[0], vector[1], vector[2], None, None, vector[5], vector[6])
            if count == 1:
                title = title.replace("columns", "column")
        elif comment:
            vector = "%s%s" % (vector, comment)
        data += '    Tur: %s\n' % PAYLOAD.SQLINJECTION[stype]
        data += '    Nomi: %s\n' % title
        data += "    Payload: %s\n" % urldecode(payload, unsafe="&", spaceplus=(inj.place != PLACE.GET and kb.postSpaceToPlus))
        data += '    Vektor: %s\n\n' % vector if conf.verbose > 1 else "\n"

    return data

def _autoWafBypass(place, parameter, value):
    """
    Automatic WAF/IPS bypass (offered interactively once a WAF/IPS is detected, cached in
    kb.wafBypass). The request fingerprint has already been neutralized up-front (non-scanner
    User-Agent, see checkWaf), so here the empirically-ranked candidate tamper scripts are trialled
    and the first that RESTORES a confirmed injection is adopted. Re-running checkSqlInjection()
    through a candidate is itself the validation - it succeeds only if the resulting payload both
    passes the WAF and stays valid SQL, so junk/incompatible candidates are rejected automatically.
    """

    from lib.utils.wafbypass import candidateTampers, loadTamper

    retVal = None

    savedTamper = kb.tamperFunctions
    savedTechnique = conf.technique
    conf.technique = [PAYLOAD.TECHNIQUE.BOOLEAN]    # bound each trial to a quick boolean re-check

    candidates = candidateTampers(identifiedWafs=kb.identifiedWafs)

    try:
        for count, name in enumerate(candidates):
            if count >= WAF_BYPASS_MAX_TRIALS:
                break

            function = loadTamper(name)
            if function is None:
                continue

            kb.tamperFunctions = [function]
            logger.info("'%s' tamper skripti bilan WAF/IPS ni chetlab o'tishga urinish" % name)

            injection = checkSqlInjection(place, parameter, value)
            if getattr(injection, "place", None) is not None and NOTE.FALSE_POSITIVE_OR_UNEXPLOITABLE not in injection.notes:
                logger.info("WAF/IPS '%s' tamper skripti orqali chetlab o'tildi (skanerga xos bo'lmagan User-Agent bilan)" % name)
                logger.info("xuddi shu natijani '--random-agent' va '%s' tamper skripti bilan qo'lda takrorlash mumkin" % name)
                retVal = injection
                return retVal

            if kb.droppingRequests and count >= 2:
                logger.warning("nishon so'rovlarni uzishda davom etmoqda; WAF/IPS ni chetlab o'tish to'xtatildi")
                break
    finally:
        conf.technique = savedTechnique
        if retVal is None:      # nothing worked - leave tampering untouched
            kb.tamperFunctions = savedTamper
            # honest bail: say it could not be bypassed and what to try manually
            logger.warning("WAF/IPS ni avtomatik chetlab o'tib bo'lmadi; u xatti-harakat yoki tezlikni tekshirishi mumkin ('--tamper', '--delay' yoki '--proxy' almashtirishni ko'rib chiqing)")

    return retVal

def _targetInfo():
    return {"url": conf.url, "query": conf.parameters.get(PLACE.GET), "data": conf.parameters.get(PLACE.POST)}

def _showInjections():
    if conf.wizard and kb.wizardMode:
        kb.wizardMode = False

    if kb.testQueryCount > 0:
        header = 'sqlmap quyidagi inyeksiya nuqtalarini aniqladi, '
        header += "jami %d ta HTTP(s) so'rovi bilan" % kb.testQueryCount
    else:
        header = 'sqlmap saqlangan sessiyadan quyidagi inyeksiya nuqtalarini tikladi'

    if conf.api:
        conf.dumper.string("", _targetInfo(), content_type=CONTENT_TYPE.TARGET)
        conf.dumper.string("", kb.injections, content_type=CONTENT_TYPE.TECHNIQUES)
    else:
        # --report-json: capture the same TECHNIQUES structure the API emits, without printing it (the
        # human-readable injection points are rendered just below); TARGET is reported per target in start()
        if conf.reportJson:
            conf.dumper._reportData(kb.injections, CONTENT_TYPE.TECHNIQUES)

        data = "".join(set(_formatInjection(_) for _ in kb.injections)).rstrip("\n")
        conf.dumper.string(header, data)

    # when results were resumed (no test requests this run), nudge if the session file is stale -
    # this is the common "why is it showing old/unexpected results?" confusion
    if kb.testQueryCount == 0 and not conf.freshQueries:
        try:
            days = int((time.time() - os.path.getmtime(conf.hashDBFile)) / (24 * 3600))
        except (OSError, IOError, TypeError):
            days = 0

        if days >= HASHDB_STALE_DAYS:
            warnMsg = 'yuqoridagi natijalar %d kun oldin yangilangan sessiyadan tiklandi, ' % days
            warnMsg += "shuning uchun ular eskirgan bo'lishi mumkin. Qayta tekshirish uchun '--flush-session', "
            warnMsg += "keshlangan so'rov natijalarini chetlab o'tish uchun '--fresh-queries' ishlating"
            logger.warning(warnMsg)

    if conf.tamper:
        warnMsg = "tamper skriptlari kiritgan o'zgarishlar "
        warnMsg += "ko'rsatilgan payload mazmuniga kiritilmagan"
        logger.warning(warnMsg)

    if conf.hpp:
        warnMsg = "HTTP parametrlarini takrorlashdagi o'zgarishlar "
        warnMsg += "ko'rsatilgan payload mazmuniga kiritilmagan"
        logger.warning(warnMsg)

def _randomFillBlankFields(value):
    retVal = value

    if extractRegexResult(EMPTY_FORM_FIELDS_REGEX, value):
        message = ut('do you want to fill blank fields with random values? [Y/n] ', "bo'sh maydonlar tasodifiy qiymatlar bilan to'ldirilsinmi? [Y/n] ")

        if readInput(message, default='Y', boolean=True):
            for match in re.finditer(EMPTY_FORM_FIELDS_REGEX, retVal):
                item = match.group("result")
                if not any(_ in item for _ in IGNORE_PARAMETERS) and not re.search(ASP_NET_CONTROL_REGEX, item):
                    newValue = randomStr() if not re.search(r"^id|id$", item, re.I) else randomInt()
                    if item[-1] == DEFAULT_GET_POST_DELIMITER:
                        retVal = retVal.replace(item, "%s%s%s" % (item[:-1], newValue, DEFAULT_GET_POST_DELIMITER))
                    else:
                        retVal = retVal.replace(item, "%s%s" % (item, newValue))

    return retVal

def _saveToHashDB():
    injections = hashDBRetrieve(HASHDB_KEYS.KB_INJECTIONS, True)
    if not isListLike(injections):
        injections = []
    injections.extend(_ for _ in kb.injections if _ and _.place is not None and _.parameter is not None)

    _ = dict()
    for injection in injections:
        key = (injection.place, injection.parameter, injection.ptype)
        if key not in _:
            _[key] = injection
        else:
            _[key].data.update(injection.data)
    hashDBWrite(HASHDB_KEYS.KB_INJECTIONS, list(_.values()), True)

    _ = hashDBRetrieve(HASHDB_KEYS.KB_ABS_FILE_PATHS, True)
    hashDBWrite(HASHDB_KEYS.KB_ABS_FILE_PATHS, kb.absFilePaths | (_ if isinstance(_, set) else set()), True)

    if not hashDBRetrieve(HASHDB_KEYS.KB_CHARS):
        hashDBWrite(HASHDB_KEYS.KB_CHARS, kb.chars, True)

    if not hashDBRetrieve(HASHDB_KEYS.KB_DYNAMIC_MARKINGS):
        hashDBWrite(HASHDB_KEYS.KB_DYNAMIC_MARKINGS, kb.dynamicMarkings, True)

def _saveToResultsFile():
    if not conf.resultsFP:
        return

    results = {}
    techniques = dict((_[1], _[0]) for _ in getPublicTypeMembers(PAYLOAD.TECHNIQUE))

    for injection in kb.injections + kb.falsePositives:
        if injection.place is None or injection.parameter is None:
            continue

        key = (injection.place, injection.parameter, ';'.join(injection.notes))
        if key not in results:
            results[key] = []

        results[key].extend(list(injection.data.keys()))

    try:
        for key, value in results.items():
            place, parameter, notes = key
            line = "%s,%s,%s,%s,%s%s" % (safeCSValue(kb.originalUrls.get(conf.url) or conf.url), place, parameter, "".join(techniques[_][0].upper() for _ in sorted(value)), notes, os.linesep)
            conf.resultsFP.write(line)

        conf.resultsFP.flush()
    except IOError as ex:
        errMsg = "'%s' natijalar fayliga yozib bo'lmadi ('%s'). " % (conf.resultsFile, getSafeExString(ex))
        raise SqlmapSystemException(errMsg)

@stackedmethod
def start():
    """
    This function calls a function that performs checks on both URL
    stability and all GET, POST, Cookie and User-Agent parameters to
    check if they are dynamic and SQL injection affected
    """

    if conf.hashFile:
        crackHashFile(conf.hashFile)

    if conf.direct:
        initTargetEnv()
        setupTargetEnv()
        action()
        return True

    if conf.url and not any((conf.forms, conf.crawlDepth)):
        kb.targets.add((conf.url, conf.method, conf.data, conf.cookie, None))

    if conf.configFile and not kb.targets:
        errMsg = "sozlash fayli noto'g'ri tahrirlangan; "
        errMsg += "nishon URL, nishonlar ro'yxati yoki Google dorkni belgilang"
        logger.error(errMsg)
        return False

    if kb.targets and isListLike(kb.targets) and len(kb.targets) > 1:
        infoMsg = 'jami %d ta nishon topildi' % len(kb.targets)
        logger.info(infoMsg)

    targetCount = 0
    initialHeaders = list(conf.httpHeaders)

    for targetUrl, targetMethod, targetData, targetCookie, targetHeaders in kb.targets:
        targetCount += 1

        # --report-json / REST API: give each target its own taskid in the shared collector, so a multi-target
        # run (e.g. '-m' bulk file) doesn't have later targets overwrite earlier ones (see _reportData/StdDbOut.write)
        if conf.reportJson or conf.api:
            kb.reportTaskId = targetCount

        try:
            if conf.checkInternet:
                infoMsg = 'internet ulanishi tekshirilmoqda'
                logger.info(infoMsg)

                if not checkInternet():
                    warnMsg = '[%s] [WARNING] ulanish aniqlanmadi' % time.strftime("%X")
                    dataToStdout(warnMsg)

                    valid = False
                    for _ in xrange(conf.retries):
                        if checkInternet():
                            valid = True
                            break
                        else:
                            dataToStdout('.')
                            time.sleep(5)

                    if not valid:
                        errMsg = 'internet ulanishini tekshirib, qayta ishga tushiring'
                        raise SqlmapConnectionException(errMsg)
                    else:
                        dataToStdout("\n")

            conf.url = targetUrl
            conf.method = targetMethod.upper().strip() if targetMethod else targetMethod
            conf.data = targetData
            conf.cookie = targetCookie
            conf.httpHeaders = list(initialHeaders)
            conf.httpHeaders.extend(targetHeaders or [])

            if conf.randomAgent or conf.mobile:
                for header, value in initialHeaders:
                    if header.upper() == HTTP_HEADER.USER_AGENT.upper():
                        conf.httpHeaders.append((header, value))
                        break

            if conf.data:
                # Note: explicitly URL encode __ ASP(.NET) parameters (e.g. to avoid problems with Base64 encoded '+' character) - standard procedure in web browsers
                conf.data = re.sub(r"\b(__\w+)=([^&]+)", lambda match: "%s=%s" % (match.group(1), urlencode(match.group(2), safe='%')), conf.data)

            conf.httpHeaders = [conf.httpHeaders[i] for i in xrange(len(conf.httpHeaders)) if conf.httpHeaders[i][0].upper() not in (__[0].upper() for __ in conf.httpHeaders[i + 1:])]

            initTargetEnv()
            parseTargetUrl()

            testSqlInj = False

            if PLACE.GET in conf.parameters and not any((conf.data, conf.testParameter)):
                for parameter in re.findall(r"([^=]+)=([^%s]+%s?|\Z)" % (re.escape(conf.paramDel or "") or DEFAULT_GET_POST_DELIMITER, re.escape(conf.paramDel or "") or DEFAULT_GET_POST_DELIMITER), conf.parameters[PLACE.GET]):
                    paramKey = (conf.hostname, conf.path, PLACE.GET, parameter[0])

                    if paramKey not in kb.testedParams:
                        testSqlInj = True
                        break
            else:
                paramKey = (conf.hostname, conf.path, None, None)
                if paramKey not in kb.testedParams:
                    testSqlInj = True

            if testSqlInj and conf.hostname in kb.vulnHosts:
                if kb.skipVulnHost is None:
                    message = ut('SQL injection vulnerability has already been detected ', 'SQL-inyeksiya zaifligi allaqachon aniqlangan ')
                    message += ut("against '%s'. Do you want to skip ", "'%s' uchun. O'tkazib yuborasizmi: ") % conf.hostname
                    message += ut('further tests involving it? [Y/n]', 'unga oid keyingi testlarni? [Y/n]')

                    kb.skipVulnHost = readInput(message, default='Y', boolean=True)

                testSqlInj = not kb.skipVulnHost

            if not testSqlInj:
                infoMsg = "'%s' o'tkazib yuborildi" % targetUrl
                logger.info(infoMsg)
                continue

            if conf.multipleTargets:
                if conf.forms and conf.method:
                    message = ut('[%d/%s] Form:\n%s %s', '[%d/%s] Forma:\n%s %s') % (targetCount, len(kb.targets) if isListLike(kb.targets) else '?', conf.method, targetUrl)
                else:
                    message = "[%d/%s] URL:\n%s %s" % (targetCount, len(kb.targets) if isListLike(kb.targets) else '?', HTTPMETHOD.GET, targetUrl)

                if conf.cookie:
                    message += "\nCookie: %s" % conf.cookie

                if conf.data is not None:
                    message += ut('\n%s data: %s', "\n%s ma'lumotlari: %s") % ((conf.method if conf.method != HTTPMETHOD.GET else None) or HTTPMETHOD.POST, urlencode(conf.data or "") if re.search(r"\A\s*[<{]", conf.data or "") is None else conf.data)

                if conf.forms and conf.method:
                    if conf.method == HTTPMETHOD.GET and targetUrl.find("?") == -1:
                        continue

                    message += ut('\ndo you want to test this form? [Y/n/q] ', '\nbu formani tekshirasizmi? [Y/n/q] ')
                    choice = readInput(message, default='Y').upper()

                    if choice == 'N':
                        continue
                    elif choice == 'Q':
                        break
                    else:
                        if conf.method != HTTPMETHOD.GET:
                            message = ut('Edit %s data [default: %s]%s: ', "%s ma'lumotlarini tahrirlang [standart: %s]%s: ") % (conf.method, urlencode(conf.data or "") if re.search(r"\A\s*[<{]", conf.data or "None") is None else conf.data, " (Warning: blank fields detected)" if conf.data and extractRegexResult(EMPTY_FORM_FIELDS_REGEX, conf.data) else "")
                            conf.data = readInput(message, default=conf.data)
                            conf.data = _randomFillBlankFields(conf.data)
                            conf.data = urldecode(conf.data) if conf.data and urlencode(DEFAULT_GET_POST_DELIMITER, None) not in conf.data else conf.data

                        else:
                            if '?' in targetUrl:
                                firstPart, secondPart = targetUrl.split('?', 1)
                                message = ut('Edit GET data [default: %s]: ', "GET ma'lumotlarini tahrirlang [standart: %s]: ") % secondPart
                                test = readInput(message, default=secondPart)
                                test = _randomFillBlankFields(test)
                                conf.url = "%s?%s" % (firstPart, test)

                        parseTargetUrl()

                else:
                    if not conf.scope:
                        message += ut('\ndo you want to test this URL? [Y/n/q]', '\nbu URL ni tekshirasizmi? [Y/n/q]')
                        choice = readInput(message, default='Y').upper()

                        if choice == 'N':
                            dataToStdout(os.linesep)
                            continue
                        elif choice == 'Q':
                            break
                    else:
                        pass

                    infoMsg = "'%s' URL tekshirilmoqda" % targetUrl
                    logger.info(infoMsg)

            if conf.graphql and PLACE.GET not in conf.parameters:
                # graphqlScan() is self-contained and operates on the GraphQL
                # document, not on HTTP parameters. A dummy GET parameter keeps
                # _setRequestParams() from appending the URI injection marker ('*')
                # to a bare endpoint URL (which would break detection under
                # '--batch'); it is discarded by graphqlScan() on entry.
                conf.parameters[PLACE.GET] = "x"

            setupTargetEnv()

            # --report-json: every tested target gets its own group with its identity, also when nothing is found
            # (otherwise its errors, e.g. connection failures, would have no group to land in)
            if conf.reportJson:
                conf.dumper._reportData(_targetInfo(), CONTENT_TYPE.TARGET)

            if not any((conf.graphql,)) and not checkConnection(suppressOutput=conf.forms):
                continue

            if conf.rParam and kb.originalPage:
                kb.randomPool = dict(_ for _ in kb.randomPool.items() if isinstance(_[1], list))

                for match in re.finditer(r"(?si)<select[^>]+\bname\s*=\s*[\"']([^\"']+)(.+?)</select>", kb.originalPage):
                    name, _ = match.groups()
                    options = tuple(re.findall(r"<option[^>]+\bvalue\s*=\s*[\"']([^\"']+)", _))
                    if options:
                        kb.randomPool[name] = options

            checkWaf()

            checkJWT()

            if conf.mineParams and not any(conf.get(_) for _ in NONSQL_TECHNIQUES):
                from lib.utils.paraminer import mineParameters
                mineParameters()

            if any(conf.get(_) for _ in NONSQL_TECHNIQUES) and (conf.reportJson or conf.resultsFile):
                singleTimeWarnMessage("'--report-json'/'--results-file' hozircha SQL bo'lmagan %s usuli natijalarini saqlamaydi; ular faqat konsolda ko'rsatiladi" % '/'.join("--%s" % _ for _ in NONSQL_TECHNIQUES))

            if conf.graphql:
                from lib.techniques.graphql.inject import graphqlScan
                graphqlScan()
                continue

            if conf.nosql:
                from lib.techniques.nosql.inject import nosqlScan
                nosqlScan()
                continue

            if conf.ldap:
                from lib.techniques.ldap.inject import ldapScan
                ldapScan()
                continue

            if conf.xpath:
                from lib.techniques.xpath.inject import xpathScan
                xpathScan()
                continue

            if conf.ssti:
                from lib.techniques.ssti.inject import sstiScan
                sstiScan()
                continue

            if conf.xslt:
                from lib.techniques.xslt.inject import xsltScan
                xsltScan()
                continue

            if conf.xxe:
                from lib.techniques.xxe.inject import xxeScan
                xxeScan()
                continue

            if conf.hql:
                from lib.techniques.hql.inject import hqlScan
                hqlScan()
                continue

            if conf.sparql:
                from lib.techniques.sparql.inject import sparqlScan
                sparqlScan()
                continue

            if conf.odata:
                from lib.techniques.odata.inject import odataScan
                odataScan()
                continue

            if conf.jwt:
                from lib.techniques.jwt.inject import jwtScan
                jwtScan()
                continue

            if conf.nullConnection:
                checkNullConnection()

            if (len(kb.injections) == 0 or (len(kb.injections) == 1 and kb.injections[0].place is None)) and (kb.injection.place is None or kb.injection.parameter is None):
                if not any((conf.string, conf.notString, conf.regexp)) and any(_ in conf.technique for _ in (PAYLOAD.TECHNIQUE.BOOLEAN, PAYLOAD.TECHNIQUE.UNION)):
                    # NOTE: besides the not-stable warning, this marks dynamic content for removal, which
                    # UNION column-count detection relies on too (it compares pages) - so it must run when
                    # UNION is tested even if BOOLEAN is excluded (e.g. '--technique=U' on a dynamic page)
                    checkStability()

                # Do a little prioritization reorder of a testable parameter list
                parameters = list(conf.parameters.keys())

                # Order of testing list (first to last)
                orderList = (PLACE.CUSTOM_POST, PLACE.CUSTOM_HEADER, PLACE.URI, PLACE.POST, PLACE.GET)

                for place in orderList[::-1]:
                    if place in parameters:
                        parameters.remove(place)
                        parameters.insert(0, place)

                proceed = True
                for place in parameters:
                    # Test User-Agent and Referer headers only if
                    # --level >= 3
                    skip = (place == PLACE.USER_AGENT and (kb.testOnlyCustom or conf.level < 3))
                    skip |= (place == PLACE.REFERER and (kb.testOnlyCustom or conf.level < 3))

                    # --param-filter
                    skip |= (len(conf.paramFilter) > 0 and place.upper() not in conf.paramFilter)

                    # Test Host header only if
                    # --level >= 5
                    skip |= (place == PLACE.HOST and (kb.testOnlyCustom or conf.level < 5))

                    # Test Cookie header only if --level >= 2
                    skip |= (place == PLACE.COOKIE and (kb.testOnlyCustom or conf.level < 2))

                    skip |= (place == PLACE.USER_AGENT and intersect(USER_AGENT_ALIASES, conf.skip, True) not in ([], None))
                    skip |= (place == PLACE.REFERER and intersect(REFERER_ALIASES, conf.skip, True) not in ([], None))
                    skip |= (place == PLACE.COOKIE and intersect(PLACE.COOKIE, conf.skip, True) not in ([], None))
                    skip |= (place == PLACE.HOST and intersect(PLACE.HOST, conf.skip, True) not in ([], None))

                    skip &= not (place == PLACE.USER_AGENT and intersect(USER_AGENT_ALIASES, conf.testParameter, True))
                    skip &= not (place == PLACE.REFERER and intersect(REFERER_ALIASES, conf.testParameter, True))
                    skip &= not (place == PLACE.HOST and intersect(HOST_ALIASES, conf.testParameter, True))
                    skip &= not (place == PLACE.COOKIE and intersect((PLACE.COOKIE,), conf.testParameter, True))

                    if skip:
                        continue

                    if place not in conf.paramDict or place not in conf.parameters:
                        continue

                    paramDict = conf.paramDict[place]

                    paramType = conf.method if conf.method not in (None, HTTPMETHOD.GET, HTTPMETHOD.POST) else place

                    for parameter, value in paramDict.items():
                        if not proceed:
                            break

                        kb.vainRun = False
                        testSqlInj = True
                        paramKey = (conf.hostname, conf.path, place, parameter)

                        if kb.processUserMarks:
                            if testSqlInj and place not in (PLACE.CUSTOM_POST, PLACE.CUSTOM_HEADER, PLACE.URI):
                                if kb.processNonCustom is None:
                                    message = ut('other non-custom parameters found. ', 'boshqa oddiy parametrlar ham topildi. ')
                                    message += ut('Do you want to process them too? [Y/n/q] ', 'Ularni ham qayta ishlaysizmi? [Y/n/q] ')
                                    choice = readInput(message, default='Y').upper()

                                    if choice == 'Q':
                                        raise SqlmapUserQuitException
                                    else:
                                        kb.processNonCustom = choice == 'Y'

                                if not kb.processNonCustom:
                                    infoMsg = "%sparametr '%s' o'tkazib yuborildi" % ("%s " % paramType if paramType != parameter else "", parameter)
                                    logger.info(infoMsg)
                                    continue

                        if paramKey in kb.testedParams:
                            testSqlInj = False

                            infoMsg = "avval tekshirilgan %sparametr '%s' o'tkazib yuborildi" % ("%s " % paramType if paramType != parameter else "", parameter)
                            logger.info(infoMsg)

                        elif any(_ in conf.testParameter for _ in (parameter, removePostHintPrefix(parameter))):
                            pass

                        elif parameter in conf.rParam:
                            testSqlInj = False

                            infoMsg = "%sparametr '%s' ni tasodifiylashtirish o'tkazib yuborildi" % ("%s " % paramType if paramType != parameter else "", parameter)
                            logger.info(infoMsg)

                        elif parameter in conf.skip or kb.postHint and parameter.split(' ')[-1] in conf.skip:
                            testSqlInj = False

                            infoMsg = "%sparametr '%s' o'tkazib yuborildi" % ("%s " % paramType if paramType != parameter else "", parameter)
                            logger.info(infoMsg)

                        elif conf.paramExclude and (re.search(conf.paramExclude, parameter, re.I) or kb.postHint and re.search(conf.paramExclude, parameter.split(' ')[-1], re.I) or re.search(conf.paramExclude, place, re.I)):
                            testSqlInj = False

                            infoMsg = "%sparametr '%s' o'tkazib yuborildi" % ("%s " % paramType if paramType != parameter else "", parameter)
                            logger.info(infoMsg)

                        elif conf.csrfToken and re.search(conf.csrfToken, parameter, re.I):
                            testSqlInj = False

                            infoMsg = "anti-CSRF token parametri '%s' o'tkazib yuborildi" % parameter
                            logger.info(infoMsg)

                        # Ignore session-like parameters for --level < 4
                        elif conf.level < 4 and (parameter.upper() in IGNORE_PARAMETERS or any(_ in parameter.lower() for _ in CSRF_TOKEN_PARAMETER_INFIXES) or re.search(GOOGLE_ANALYTICS_COOKIE_REGEX, parameter)):
                            testSqlInj = False

                            infoMsg = "%sparametr '%s' hisobga olinmaydi" % ("%s " % paramType if paramType != parameter else "", parameter)
                            logger.info(infoMsg)

                        elif PAYLOAD.TECHNIQUE.BOOLEAN in conf.technique or conf.skipStatic:
                            check = checkDynParam(place, parameter, value)

                            if not check:
                                warnMsg = "%sparametr '%s' dinamik emasga o'xshaydi" % ("%s " % paramType if paramType != parameter else "", parameter)
                                logger.warning(warnMsg)

                                if conf.skipStatic:
                                    infoMsg = "o'zgarmas %sparametr '%s' o'tkazib yuborildi" % ("%s " % paramType if paramType != parameter else "", parameter)
                                    logger.info(infoMsg)

                                    testSqlInj = False
                            else:
                                infoMsg = "%sparametr '%s' dinamik ko'rinadi" % ("%s " % paramType if paramType != parameter else "", parameter)
                                logger.info(infoMsg)

                        kb.testedParams.add(paramKey)

                        if testSqlInj:
                            try:
                                if place == PLACE.COOKIE:
                                    pushValue(kb.mergeCookies)
                                    kb.mergeCookies = False

                                check = heuristicCheckSqlInjection(place, parameter)

                                if check != HEURISTIC_TEST.POSITIVE:
                                    if conf.smart or (kb.ignoreCasted and check == HEURISTIC_TEST.CASTED):
                                        infoMsg = "%sparametr '%s' o'tkazib yuborildi" % ("%s " % paramType if paramType != parameter else "", parameter)
                                        logger.info(infoMsg)
                                        continue

                                infoMsg = "%sparametr '%s' SQL-inyeksiyaga tekshirilmoqda" % ("%s " % paramType if paramType != parameter else "", parameter)
                                logger.info(infoMsg)

                                injection = checkSqlInjection(place, parameter, value)

                                # WAF/IPS bypass accepted: the parameter looks injectable (heuristics) but
                                # the standard payloads were blocked -> try to auto-bypass it (request
                                # fingerprint neutralization and/or a tamper script)
                                if getattr(injection, "place", None) is None and kb.wafBypass and check == HEURISTIC_TEST.POSITIVE \
                                   and not conf.tamper and not kb.tamperFunctions:
                                    injection = _autoWafBypass(place, parameter, value) or injection

                                proceed = not kb.endDetection
                                injectable = False

                                if getattr(injection, "place", None) is not None:
                                    if NOTE.FALSE_POSITIVE_OR_UNEXPLOITABLE in injection.notes:
                                        kb.falsePositives.append(injection)
                                    else:
                                        injectable = True

                                        kb.injections.append(injection)

                                        if not kb.alerted:
                                            if conf.alert:
                                                infoMsg = "ogohlantiruvchi qobiq buyruqlari bajarilmoqda ('%s')" % conf.alert
                                                logger.info(infoMsg)
                                                try:
                                                    process = subprocess.Popen(conf.alert, shell=True)
                                                    process.wait()
                                                except Exception as ex:
                                                    errMsg = "'%s' bajarilishida xato ('%s')" % (conf.alert, getSafeExString(ex))
                                                    logger.error(errMsg)

                                            kb.alerted = True

                                        # In case when user wants to end detection phase (Ctrl+C)
                                        if not proceed:
                                            break

                                        msg = ut("%sparameter '%s' ", "%sparametr '%s' ") % ("%s " % injection.place if injection.place != injection.parameter else "", injection.parameter)
                                        msg += ut('is vulnerable. Do you want to keep testing the others (if any)? [y/N] ', 'zaif. Boshqa parametrlarni tekshirishni davom ettirasizmi? [y/N] ')

                                        if not readInput(msg, default='N', boolean=True):
                                            proceed = False
                                            paramKey = (conf.hostname, conf.path, None, None)
                                            kb.testedParams.add(paramKey)

                                if not injectable:
                                    warnMsg = "%sparametr '%s' inyeksiyaga zaif emasga o'xshaydi" % ("%s " % paramType if paramType != parameter else "", parameter)
                                    logger.warning(warnMsg)

                            finally:
                                if place == PLACE.COOKIE:
                                    kb.mergeCookies = popValue()

            if len(kb.injections) == 0 or (len(kb.injections) == 1 and kb.injections[0].place is None):
                if kb.vainRun and not conf.multipleTargets:
                    errMsg = "berilgan ma'lumotlarda tekshirish uchun parametr topilmadi "
                    errMsg += "(masalan, 'www.site.com/index.php?id=1' dagi GET 'id' parametri)"
                    if kb.originalPage:
                        advice = []
                        if not conf.forms and re.search(r"<form", kb.originalPage) is not None:
                            advice.append("--forms")
                        if not conf.crawlDepth and re.search(r"href=[\"']/?\w", kb.originalPage) is not None:
                            advice.append("--crawl=2")
                        if advice:
                            errMsg += ". '%s' bilan qayta ishga tushirish tavsiya etiladi" % ' '.join(advice)
                    raise SqlmapNoneDataException(errMsg)
                else:
                    errMsg = "tekshirilgan parametrlarning hech biri inyeksiyaga zaif ko'rinmaydi."

                    if conf.level < 5 or conf.risk < 3:
                        errMsg += " Ko'proq test o'tkazish uchun '--level'/'--risk' "
                        errMsg += "qiymatlarini oshirib ko'ring."

                    if isinstance(conf.technique, list) and len(conf.technique) < 5:
                        errMsg += " '--technique' parametrini bermasdan qayta ishga tushiring."

                    if not conf.textOnly and kb.originalPage:
                        percent = (100.0 * len(getFilteredPageContent(kb.originalPage)) / len(kb.originalPage))

                        if kb.dynamicMarkings:
                            errMsg += " '--text-only' parametrini sinab ko'ring, "
                            errMsg += "agar nishon sahifasida matn ulushi kam bo'lsa "
                            errMsg += 'matnli mazmun (taxminan %.2f%% ' % percent
                            errMsg += 'sahifa mazmuni matn).'
                        elif percent < LOW_TEXT_PERCENT and not kb.errorIsNone:
                            errMsg += " '--text-only' bilan qayta urinib ko'ring "
                            errMsg += '(--technique=BU bilan birga), chunki bu holat '
                            errMsg += "shu usulga mos ko'rinadi "
                            errMsg += '(matn kam va '
                            errMsg += "taqqoslash mexanizmi hech bo'lmasa "
                            errMsg += 'bitta dinamik parametrni ham aniqlay olmadi).'

                    if kb.heuristicTest == HEURISTIC_TEST.POSITIVE:
                        errMsg += ' Evristik test ijobiy chiqqani sabab '
                        errMsg += "testlarni davom ettirish qat'iy tavsiya etiladi."

                    if conf.string:
                        errMsg += ' Shuningdek, qayta ishga tushirishda '
                        errMsg += "'--string' uchun to'g'ri qiymat bering: tanlangan matn "
                        errMsg += 'faqat True javoblariga '
                        errMsg += "mos kelmayotgan bo'lishi mumkin."
                    elif conf.regexp:
                        errMsg += ' Shuningdek, qayta ishga tushirishda '
                        errMsg += "'--regexp' uchun to'g'ri qiymat: tanlangan muntazam "
                        errMsg += 'ifoda '
                        errMsg += "faqat True javoblariga mos kelmayotgan bo'lishi mumkin."

                    if not conf.tamper:
                        if kb.identifiedWafs:
                            errMsg += " Ish davomida WAF/IPS ('%s') aniqlangani uchun, " % ", ".join(kb.identifiedWafs)
                            errMsg += "'--tamper' bilan qayta urinish tavsiya etiladi (masalan, '--tamper=space2comment')"
                        else:
                            errMsg += " Himoya mexanizmi bor deb o'ylasangiz "
                            errMsg += "(masalan, WAF), quyidagini sinab ko'ring: "
                            errMsg += "'--tamper' (masalan, '--tamper=space2comment')"

                        if not conf.randomAgent:
                            errMsg += " va/yoki '--random-agent'"

                    raise SqlmapNotVulnerableException(errMsg.rstrip('.'))
            else:
                # Flush the flag
                kb.testMode = False

                _saveToResultsFile()
                _saveToHashDB()
                _showInjections()
                _selectInjection()

            if kb.injection.place is not None and kb.injection.parameter is not None:
                if conf.multipleTargets:
                    message = ut('do you want to exploit this SQL injection? [Y/n] ', 'bu SQL-inyeksiyadan foydalanasizmi? [Y/n] ')
                    condition = readInput(message, default='Y', boolean=True)
                else:
                    condition = True

                if condition:
                    try:
                        action()
                    finally:
                        if conf.proof:
                            from lib.utils.prove import proveExploitation
                            proveExploitation()

        except KeyboardInterrupt:
            if kb.lastCtrlCTime and (time.time() - kb.lastCtrlCTime < 1):
                kb.multipleCtrlC = True
                raise SqlmapUserQuitException("foydalanuvchi to'xtatdi (Ctrl+C bir necha marta bosildi)")

            kb.lastCtrlCTime = time.time()

            if conf.multipleTargets:
                warnMsg = "foydalanuvchi ko'p nishonli rejimda to'xtatdi"
                logger.warning(warnMsg)

                message = ut('do you want to skip to the next target in list? [Y/n/q]', "ro'yxatdagi keyingi nishonga o'tasizmi? [Y/n/q]")
                choice = readInput(message, default='Y').upper()

                if choice == 'N':
                    return False
                elif choice == 'Q':
                    raise SqlmapUserQuitException
            else:
                raise

        except SqlmapSkipTargetException:
            pass

        except SqlmapUserQuitException:
            raise

        except SqlmapSilentQuitException:
            raise

        except SqlmapBaseException as ex:
            errMsg = getSafeExString(ex)

            if conf.multipleTargets:
                _saveToResultsFile()

                errMsg += ", keyingi nishonga o'tilmoqda"
                logger.error(errMsg.lstrip(", "))
            else:
                logger.critical(errMsg)
                return False

        finally:
            showHttpErrorCodes()

            if kb.maxConnectionsFlag:
                warnMsg = 'nishonda '
                warnMsg += "eng ko'p ulanishlar soni "
                warnMsg += "cheklanganga o'xshaydi"
                logger.warning(warnMsg)

    if kb.dataOutputFlag and not conf.multipleTargets:
        logger.info("olingan ma'lumotlar '%s' ichidagi matn fayllariga yozildi" % conf.outputPath)

    if conf.multipleTargets:
        if conf.resultsFile:
            infoMsg = 'bir nechta nishonni tekshirish natijalari '
            infoMsg += "'%s' CSV faylida saqlangan" % conf.resultsFile
            logger.info(infoMsg)

    return True
