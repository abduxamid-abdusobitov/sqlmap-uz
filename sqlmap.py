#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission
"""

from __future__ import print_function

try:
    import os
    import sys

    sys.dont_write_bytecode = True

    # Reference: https://github.com/python/cpython/issues/156319 - CPython's tier-2 optimizer can
    # corrupt frame locals (raising exceptions the executed code cannot produce), but only when the
    # experimental JIT is on AND a sys.monitoring tool (debugger/profiler/coverage run) is active at
    # the same time - neither alone triggers it. So only silence monitoring when the JIT is also on;
    # otherwise leave it alone (e.g. a legitimate `coverage run sqlmap.py ...` must keep working).
    if hasattr(sys, "monitoring") and (sys._jit.is_enabled() if hasattr(sys, "_jit") else (sys.version_info >= (3, 13) and os.environ.get("PYTHON_JIT") == '1')):
        for _ in range(6):  # valid tool id range (Reference: https://docs.python.org/3/library/sys.monitoring.html)
            try:
                if sys.monitoring.get_tool(_) is not None:
                    sys.monitoring.set_events(_, sys.monitoring.events.NO_EVENTS)
            except Exception:
                pass

    try:
        __import__("lib.utils.versioncheck")  # this has to be the first non-standard import
    except ImportError:
        sys.exit("[!] o'rnatish noto'g'ri (modullar yo'q). Batafsil: 'https://github.com/sqlmapproject/sqlmap/#installation'")

    import bdb
    import glob
    import inspect
    import json
    import logging
    import os
    import re
    import shutil
    import sys
    import tempfile
    import threading
    import time
    import traceback
    import warnings

    try:
        ResourceWarning
    except NameError:
        ResourceWarning = Warning

    if "--deprecations" not in sys.argv:
        warnings.filterwarnings(action="ignore", category=DeprecationWarning)
    else:
        warnings.resetwarnings()
        warnings.filterwarnings(action="ignore", message="'crypt'", category=DeprecationWarning)
        warnings.simplefilter("ignore", category=ImportWarning)
        warnings.simplefilter("ignore", category=ResourceWarning)

    warnings.filterwarnings(action="ignore", message="Python 2 is no longer supported")
    warnings.filterwarnings(action="ignore", message=".*was already imported", category=UserWarning)
    warnings.filterwarnings(action="ignore", message=".*using a very old release", category=UserWarning)
    warnings.filterwarnings(action="ignore", message=".*default buffer size will be used", category=RuntimeWarning)
    warnings.filterwarnings(action="ignore", category=UserWarning, module="psycopg2")

    from lib.core.data import logger

    from lib.core.common import banner
    from lib.core.common import checkPipedInput
    from lib.core.common import codeIsModified
    from lib.core.common import createGithubIssue
    from lib.core.common import dataToStdout
    from lib.core.common import extractRegexResult
    from lib.core.common import filterNone
    from lib.core.common import getDaysFromLastUpdate
    from lib.core.common import getFileItems
    from lib.core.common import getSafeExString
    from lib.core.common import maskSensitiveData
    from lib.core.common import openFile
    from lib.core.common import setPaths
    from lib.core.common import weAreFrozen
    from lib.core.convert import getUnicode
    from lib.core.common import setColor
    from lib.core.common import unhandledExceptionMessage
    from lib.core.compat import LooseVersion
    from lib.core.compat import xrange
    from lib.core.data import cmdLineOptions
    from lib.core.data import conf
    from lib.core.data import kb
    from lib.core.datatype import OrderedSet
    from lib.core.enums import MKSTEMP_PREFIX
    from lib.core.exception import SqlmapBaseException
    from lib.core.exception import SqlmapShellQuitException
    from lib.core.exception import SqlmapSilentQuitException
    from lib.core.exception import SqlmapUserQuitException
    from lib.core.option import init
    from lib.core.option import initOptions
    from lib.core.patch import dirtyPatches
    from lib.core.patch import resolveCrossReferences
    from lib.core.settings import GIT_PAGE
    from lib.core.settings import IS_WIN
    from lib.core.settings import LAST_UPDATE_NAGGING_DAYS
    from lib.core.settings import LEGAL_DISCLAIMER
    from lib.core.settings import THREAD_FINALIZATION_TIMEOUT
    from lib.core.settings import UNICODE_ENCODING
    from lib.core.settings import VERSION
    from lib.parse.cmdline import cmdLineParser
    from lib.utils.crawler import crawl
except KeyboardInterrupt:
    errMsg = "foydalanuvchi to'xtatdi"

    if "logger" in globals():
        logger.critical(errMsg)
        raise SystemExit
    else:
        import time
        sys.exit("\r[%s] [CRITICAL] %s" % (time.strftime("%X"), errMsg))

def modulePath():
    """
    This will get us the program's directory, even if we are frozen
    using py2exe
    """

    try:
        _ = sys.executable if weAreFrozen() else __file__
    except NameError:
        _ = inspect.getsourcefile(modulePath)

    return getUnicode(os.path.dirname(os.path.realpath(_)), encoding=sys.getfilesystemencoding() or UNICODE_ENCODING)

def checkEnvironment():
    try:
        os.path.isdir(modulePath())
    except UnicodeEncodeError:
        errMsg = "tizimingiz ASCII bo'lmagan belgili yo'llarni to'g'ri qayta ishlamayapti. "
        errMsg += "Sqlmap papkasini boshqa joyga ko'chiring"
        logger.critical(errMsg)
        raise SystemExit

    if LooseVersion(VERSION) < LooseVersion("1.0"):
        errMsg = 'ish muhitingiz (masalan, PYTHONPATH) '
        errMsg += 'buzilgan. Sqlmapning yangi versiyasini '
        errMsg += 'eski versiyalar uchun yozilgan ishga tushirish skriptlari bilan '
        errMsg += 'ishlatmayotganingizni tekshiring'
        logger.critical(errMsg)
        raise SystemExit

    # Check for being run from inside a third-party repackage bundling sqlmap for resale
    _ = modulePath()
    repackaged = "sqlbox" in _.lower()
    while not repackaged and os.path.dirname(_) != _:
        if os.path.basename(_) == "XDATA" and all(os.path.isdir(os.path.join(_, __)) for __ in ("_tools", "_DB")):
            repackaged = True
        _ = os.path.dirname(_)

    if repackaged:
        errMsg = 'bu sqlmap nusxasi uchinchi tomon qayta qadoqlagan '
        errMsg += "to'plamdan ishlayotganga o'xshaydi. Sqlmap GPL litsenziyasidagi bepul va ochiq kodli dastur (https://sqlmap.org). "
        errMsg += "Uni yopiq kodli yoki pulli dasturga qo'shish uchun alohida tijoriy "
        errMsg += 'litsenziya kerak (sales@sqlmap.org)'
        logger.critical(errMsg)
        raise SystemExit

    # Patch for pip (import) environment
    if "sqlmap.sqlmap" in sys.modules:
        for _ in ("cmdLineOptions", "conf", "kb"):
            globals()[_] = getattr(sys.modules["lib.core.data"], _)

        for _ in ("SqlmapBaseException", "SqlmapShellQuitException", "SqlmapSilentQuitException", "SqlmapUserQuitException"):
            globals()[_] = getattr(sys.modules["lib.core.exception"], _)

def main():
    """
    Main function of sqlmap when running from command line.
    """

    try:
        dirtyPatches()
        resolveCrossReferences()
        checkEnvironment()
        setPaths(modulePath())
        banner()

        # Store original command line options for possible later restoration
        args = cmdLineParser()
        cmdLineOptions.update(args.__dict__ if hasattr(args, "__dict__") else args)
        initOptions(cmdLineOptions)

        if checkPipedInput():
            conf.batch = True

        if conf.get("api"):
            # heavy imports
            from lib.utils.api import StdDbOut
            from lib.utils.api import setRestAPILog

            # Overwrite system standard output and standard error to write
            # to an IPC database
            sys.stdout = StdDbOut(conf.taskid, messagetype="stdout")
            sys.stderr = StdDbOut(conf.taskid, messagetype="stderr")

            setRestAPILog()

        conf.showTime = True
        dataToStdout('[!] huquqiy eslatma: %s\n\n' % LEGAL_DISCLAIMER, forceOutput=True)
        dataToStdout('[*] boshlandi: %s\n\n' % time.strftime("%X /%Y-%m-%d/"), forceOutput=True)

        init()

        if conf.get("reportJson"):
            from lib.utils.api import setupReportCollector
            conf.reportCollector = setupReportCollector()

        if not conf.updateAll:
            # Postponed imports (faster start)
            if conf.smokeTest:
                from lib.core.testing import smokeTest
                os._exitcode = 1 - (smokeTest() or 0)
            elif conf.vulnTest:
                from lib.core.testing import vulnTest
                os._exitcode = 1 - (vulnTest() or 0)
            elif conf.fpTest:
                from lib.core.testing import fpTest
                os._exitcode = 1 - (fpTest() or 0)
            elif conf.payloadLint:
                from lib.core.testing import payloadLintTest
                os._exitcode = 1 - (payloadLintTest() or 0)
            elif conf.apiTest:
                from lib.core.testing import apiTest
                os._exitcode = 1 - (apiTest() or 0)
            else:
                from lib.controller.controller import start
                if conf.profile:
                    from lib.core.profiling import profile
                    profile()
                else:
                    try:
                        if conf.crawlDepth and conf.bulkFile:
                            targets = getFileItems(conf.bulkFile)

                            for i in xrange(len(targets)):
                                target = None

                                try:
                                    kb.targets = OrderedSet()
                                    target = targets[i]

                                    if not re.search(r"(?i)\Ahttp[s]*://", target):
                                        target = "https://%s" % target

                                    infoMsg = "'%s' manzilidagi sahifalarni ko'rib chiqish boshlandi (%d/%d)" % (target, i + 1, len(targets))
                                    logger.info(infoMsg)

                                    crawl(target)
                                except Exception as ex:
                                    if target and not isinstance(ex, SqlmapUserQuitException):
                                        errMsg = "'%s' sahifalarini ko'rib chiqishda muammo ('%s')" % (target, getSafeExString(ex))
                                        logger.error(errMsg)
                                    else:
                                        raise
                                else:
                                    if kb.targets:
                                        start()
                        else:
                            start()
                    except Exception as ex:
                        os._exitcode = 1

                        if "can't start new thread" in getSafeExString(ex):
                            errMsg = "yangi oqimlarni ishga tushirib bo'lmadi. OT (u)limit cheklovlarini tekshiring"
                            logger.critical(errMsg)
                            raise SystemExit
                        else:
                            raise

    except SqlmapUserQuitException:
        if not conf.batch:
            errMsg = 'foydalanuvchi chiqdi'
            logger.error(errMsg)

    except (SqlmapSilentQuitException, bdb.BdbQuit):
        pass

    except SqlmapShellQuitException:
        cmdLineOptions.sqlmapShell = False

    except SqlmapBaseException as ex:
        errMsg = getSafeExString(ex)
        logger.critical(errMsg)

        os._exitcode = 1

        raise SystemExit

    except KeyboardInterrupt:
        try:
            print()
        except IOError:
            pass

    except EOFError:
        print()

        errMsg = "exit"
        logger.error(errMsg)

    except SystemExit as ex:
        os._exitcode = ex.code or 0

    except:
        print()
        errMsg = unhandledExceptionMessage()
        excMsg = traceback.format_exc()
        valid = not codeIsModified()

        os._exitcode = 255

        if any(_ in excMsg for _ in ("MemoryError", "Cannot allocate memory")):
            errMsg = 'xotira tugagani aniqlandi'
            logger.critical(errMsg)
            raise SystemExit

        elif any(_ in excMsg for _ in ("No space left", "Disk quota exceeded", "Disk full while accessing")):
            errMsg = "chiqarish qurilmasida bo'sh joy qolmadi"
            logger.critical(errMsg)
            raise SystemExit

        elif any(_ in excMsg for _ in ("The paging file is too small",)):
            errMsg = 'almashtirish fayli uchun joy qolmadi'
            logger.critical(errMsg)
            raise SystemExit

        elif all(_ in excMsg for _ in ("Access is denied", "subprocess", "metasploit")):
            errMsg = 'Metasploitni ishga tushirishda ruxsat xatosi'
            logger.critical(errMsg)
            raise SystemExit

        elif all(_ in excMsg for _ in ("Permission denied", "metasploit")):
            errMsg = 'Metasploitdan foydalanishda ruxsat xatosi'
            logger.critical(errMsg)
            raise SystemExit

        elif "Read-only file system" in excMsg:
            errMsg = "chiqarish qurilmasi faqat o'qish rejimida ulangan"
            logger.critical(errMsg)
            raise SystemExit

        elif "Insufficient system resources" in excMsg:
            errMsg = 'tizim resurslari tugagani aniqlandi'
            logger.critical(errMsg)
            raise SystemExit

        elif "OperationalError: disk I/O error" in excMsg:
            errMsg = 'chiqarish qurilmasida kiritish/chiqarish xatosi'
            logger.critical(errMsg)
            raise SystemExit

        elif "Violation of BIDI" in excMsg:
            errMsg = "URL noto'g'ri (Bidi IDNA qoidasi buzilgan - RFC 5893)"
            logger.critical(errMsg)
            raise SystemExit

        elif "Invalid IPv6 URL" in excMsg:
            errMsg = "noto'g'ri URL ('%s')" % excMsg.strip().split('\n')[-1]
            logger.critical(errMsg)
            raise SystemExit

        elif "_mkstemp_inner" in excMsg:
            errMsg = 'vaqtinchalik fayllarga murojaat qilishda muammo'
            logger.critical(errMsg)
            raise SystemExit

        elif any(_ in excMsg for _ in ("tempfile.mkdtemp", "tempfile.mkstemp", "tempfile.py")):
            errMsg = "'%s' vaqtinchalik papkasiga yozib bo'lmadi. " % tempfile.gettempdir()
            errMsg += "Disk to'lmaganini va "
            errMsg += 'vaqtinchalik fayl yoki papka yaratish uchun '
            errMsg += 'yozish huquqingiz borligini tekshiring'
            logger.critical(errMsg)
            raise SystemExit

        elif "Permission denied: '" in excMsg:
            match = re.search(r"Permission denied: '([^']*)", excMsg)
            errMsg = "'%s' fayliga murojaat qilishda ruxsat xatosi" % match.group(1)
            logger.critical(errMsg)
            raise SystemExit

        elif all(_ in excMsg for _ in ("twophase", "sqlalchemy")):
            errMsg = "'sqlalchemy' paketini yangilang (>= 1.1.11) "
            errMsg += "(Manba: 'https://qiita.com/tkprof/items/7d7b2d00df9c5f16fffe')"
            logger.critical(errMsg)
            raise SystemExit

        elif all(_ in excMsg for _ in ("httpcore", "typing.", "AttributeError")):
            errMsg = "'httpcore' paketini yangilang (>= 1.0.8) "
            errMsg += "(Manba: 'https://github.com/encode/httpcore/discussions/995')"
            logger.critical(errMsg)
            raise SystemExit

        elif "invalid maximum character passed to PyUnicode_New" in excMsg and re.search(r"\A3\.[34]", sys.version) is not None:
            errMsg = 'Python versiyasini yangilang (>= 3.5) '
            errMsg += "(Manba: 'https://bugs.python.org/issue18183')"
            logger.critical(errMsg)
            raise SystemExit

        elif all(_ in excMsg for _ in ("scramble_caching_sha2", "TypeError")):
            errMsg = "'PyMySQL' paketining eskiroq versiyasini o'rnating (=< 0.8.1) "
            errMsg += "(Manba: 'https://github.com/PyMySQL/PyMySQL/issues/700')"
            logger.critical(errMsg)
            raise SystemExit

        elif "must be pinned buffer, not bytearray" in excMsg:
            errMsg = 'Python interpretatorida xato yuz berdi; bu xato '
            errMsg += '2.7 da tuzatilgan. Tegishli versiyaga yangilang '
            errMsg += "(Manba: 'https://bugs.python.org/issue8104')"
            logger.critical(errMsg)
            raise SystemExit

        elif all(_ in excMsg for _ in ("OSError: [Errno 22] Invalid argument: '", "importlib")):
            errMsg = "'%s' faylini o'qib bo'lmadi" % extractRegexResult(r"OSError: \[Errno 22\] Invalid argument: '(?P<result>[^']+)", excMsg)
            logger.critical(errMsg)
            raise SystemExit

        elif "hash_randomization" in excMsg:
            errMsg = 'Python interpretatorida xato yuz berdi; bu xato '
            errMsg += '2.7.3 da tuzatilgan. Tegishli versiyaga yangilang '
            errMsg += "(Manba: 'https://docs.python.org/2/library/sys.html')"
            logger.critical(errMsg)
            raise SystemExit

        elif any(_ in excMsg for _ in ("AttributeError:", "TypeError:")) and re.search(r"3\.11\.\d+a", sys.version):
            errMsg = "Sqlmapni Python 3.11 ning ALPHA versiyalarida ishlatishda ma'lum muammo bor. "
            errMsg += 'Pythonning barqaror versiyasini yuklab oling'
            logger.critical(errMsg)
            raise SystemExit

        elif all(_ in excMsg for _ in ("Resource temporarily unavailable", "os.fork()", "dictionaryAttack")):
            errMsg = 'xeshlarni bir necha jarayonda tekshirishda muammo yuz berdi. '
            errMsg += "'--threads=1' bilan qayta ishga tushiring"
            logger.critical(errMsg)
            raise SystemExit

        elif "can't start new thread" in excMsg:
            errMsg = 'yangi oqim yaratishda muammo yuz berdi. '
            errMsg += "Juda ko'p jarayon ishlamayotganini tekshiring"
            if not IS_WIN:
                errMsg += " (yoki 'ulimit -u' qiymatini oshiring)"
            logger.critical(errMsg)
            raise SystemExit

        elif "can't allocate read lock" in excMsg:
            errMsg = 'soketning odatiy ishlashida muammo yuz berdi '
            errMsg += "('%s')" % excMsg.strip().split('\n')[-1]
            logger.critical(errMsg)
            raise SystemExit

        elif all(_ in excMsg for _ in ("pymysql", "configparser")):
            errMsg = "'pymsql' noto'g'ri ishga tushirilgani aniqlandi (Python3 bog'liqliklari ishlatilgan)"
            logger.critical(errMsg)
            raise SystemExit

        elif all(_ in excMsg for _ in ("drda", "to_bytes")):
            errMsg = "'drda' noto'g'ri ishga tushirilgani aniqlandi (Python3 sintaksisi ishlatilgan)"
            logger.critical(errMsg)
            raise SystemExit

        elif "'WebSocket' object has no attribute 'status'" in excMsg:
            errMsg = "noto'g'ri websocket kutubxonasi aniqlandi"
            errMsg += " (Manba: 'https://github.com/sqlmapproject/sqlmap/issues/4572#issuecomment-775041086')"
            logger.critical(errMsg)
            raise SystemExit

        elif all(_ in excMsg for _ in ("window = tkinter.Tk()",)):
            errMsg = 'grafik interfeysni ishga tushirishda muammo yuz berdi '
            errMsg += "('%s')" % excMsg.strip().split('\n')[-1]
            logger.critical(errMsg)
            raise SystemExit

        elif any(_ in excMsg for _ in ("unable to access item 'liveTest'",)):
            errMsg = 'sqlmapning turli versiyalariga tegishli fayllar ishlatilgani aniqlandi'
            logger.critical(errMsg)
            raise SystemExit

        elif any(_ in errMsg for _ in (": 9.9.9#",)):
            errMsg = "LOL xD"
            logger.critical(errMsg)
            raise SystemExit

        elif kb.get("dumpKeyboardInterrupt"):
            raise SystemExit

        elif any(_ in excMsg for _ in ("Broken pipe", "KeyboardInterrupt")):
            raise SystemExit

        elif valid is False:
            errMsg = "kod nazorat summasi mos kelmadi (avtomatik xato hisoboti o'chirildi). "
            errMsg += 'Eng yangi ishlab chiqish versiyasini rasmiy GitHub '
            errMsg += "repozitoriysidan oling: '%s'" % GIT_PAGE
            logger.critical(errMsg)
            print()
            dataToStdout(excMsg)
            raise SystemExit

        elif any(_ in "%s\n%s" % (errMsg, excMsg) for _ in ("tamper/", "waf/", "--engagement-dojo")):
            logger.critical(errMsg)
            print()
            dataToStdout(excMsg)
            raise SystemExit

        elif any(_ in excMsg for _ in ("ImportError", "ModuleNotFoundError", "<frozen", "Can't find file for module", "SAXReaderNotAvailable", "<built-in function compile> returned NULL without setting an exception", "source code string cannot contain null bytes", "No module named", "tp_name field", "module 'sqlite3' has no attribute 'OperationalError'")):
            errMsg = "noto'g'ri ish muhiti ('%s')" % excMsg.split("Error: ")[-1].strip()
            logger.critical(errMsg)
            raise SystemExit

        elif all(_ in excMsg for _ in ("SyntaxError: Non-ASCII character", ".py on line", "but no encoding declared")):
            errMsg = "noto'g'ri ish muhiti ('%s')" % excMsg.split("Error: ")[-1].strip()
            logger.critical(errMsg)
            raise SystemExit

        elif all(_ in excMsg for _ in ("FileNotFoundError: [Errno 2] No such file or directory", "os.getcwd()")):
            errMsg = "noto'g'ri ish muhiti ('%s')" % excMsg.split("Error: ")[-1].strip()
            logger.critical(errMsg)
            raise SystemExit

        elif all(_ in excMsg for _ in ("PermissionError: [WinError 5]", "multiprocessing")):
            errMsg = "bu tizimda ko'p jarayonli ishlash uchun ruxsat muammosi bor. "
            errMsg += "'--disable-multi' bilan qayta ishga tushiring"
            logger.critical(errMsg)
            raise SystemExit

        elif all(_ in excMsg for _ in ("No such file", "_'")):
            errMsg = "o'rnatish fayllari buzilgan ('%s'). " % excMsg.strip().split('\n')[-1]
            errMsg += 'Eng yangi ishlab chiqish versiyasini rasmiy GitHub '
            errMsg += "repozitoriysidan oling: '%s'" % GIT_PAGE
            logger.critical(errMsg)
            raise SystemExit

        elif all(_ in excMsg for _ in ("No such file", "sqlmap.conf", "Test")):
            errMsg = 'ishlab chiqish uchun yashirin testlarni ishchi muhitda ishga tushirmoqchisiz'
            logger.critical(errMsg)
            raise SystemExit

        elif "'DictObject' object has no attribute '" in excMsg and all(_ in errMsg for _ in ("(fingerprinted)", "(identified)")):
            errMsg = "ma'lumotlarni sanab olishda muammo yuz berdi. "
            errMsg += "Natija yolg'on ijobiy bo'lishi ehtimoli katta; "
            errMsg += "'--flush-session' bilan qayta ishga tushirish tavsiya etiladi"
            logger.critical(errMsg)
            raise SystemExit

        elif "database disk image is malformed" in excMsg:
            errMsg = "mahalliy sessiya fayli buzilganga o'xshaydi. '--flush-session' bilan qayta ishga tushiring"
            logger.critical(errMsg)
            raise SystemExit

        elif "'cryptography' package is required" in excMsg:
            errMsg = "'cryptography' tashqi kutubxonasi kerak"
            logger.critical(errMsg)
            raise SystemExit

        elif "AttributeError: 'module' object has no attribute 'F_GETFD'" in excMsg:
            errMsg = 'noto\'g\'ri ish muhiti ("%s") ' % excMsg.split("Error: ")[-1].strip()
            errMsg += "(Manba: 'https://stackoverflow.com/a/38841364' va 'https://bugs.python.org/issue24944#msg249231')"
            logger.critical(errMsg)
            raise SystemExit

        elif "bad marshal data (unknown type code)" in excMsg:
            match = re.search(r"\s*(.+)\s+ValueError", excMsg)
            errMsg = '.pyc fayllaringizdan biri buzilgan%s' % (" ('%s')" % match.group(1) if match else "")
            errMsg += ". Muammoni tuzatish uchun tizimdagi .pyc fayllarini o'chiring"
            logger.critical(errMsg)
            raise SystemExit

        elif (sys._jit.is_enabled() if hasattr(sys, "_jit") else (sys.version_info >= (3, 13) and os.environ.get("PYTHON_JIT") == '1')):
            errMsg = "Pythonning tajribaviy JIT kompilyatori yoqilgan. CPythondagi ma'lum xato sabab "
            errMsg += "ikkinchi bosqich optimizatori to'g'ri kadrda noto'g'ri buyruqlarni bajarib, "
            errMsg += 'asl koddan kelib chiqmaydigan istisnolarni keltirib chiqaradi '
            errMsg += "(Manba: 'https://github.com/python/cpython/issues/156319'). Uni "
            errMsg += "o'chirib qayta ishga tushiring (masalan, 'PYTHON_JIT=0'); muammo qolsa, xabar bering"
            logger.critical(errMsg)
            print()
            dataToStdout(excMsg)
            raise SystemExit

        for match in re.finditer(r'File "(.+?)", line', excMsg):
            file_ = match.group(1)
            try:
                file_ = os.path.relpath(file_, os.path.dirname(__file__))
            except ValueError:
                pass
            file_ = file_.replace("\\", '/')
            if "../" in file_:
                file_ = re.sub(r"(\.\./)+", '/', file_)
            else:
                file_ = file_.lstrip('/')
            file_ = re.sub(r"/{2,}", '/', file_)
            excMsg = excMsg.replace(match.group(1), file_)

        errMsg = maskSensitiveData(errMsg)
        excMsg = maskSensitiveData(excMsg)

        if conf.get("api") or not valid or kb.get("lastCtrlCTime"):
            logger.critical("%s\n%s" % (errMsg, excMsg))
        else:
            logger.critical(errMsg)
            dataToStdout("%s\n" % setColor(excMsg.strip(), level=logging.CRITICAL))
            createGithubIssue(errMsg, excMsg)

    finally:
        kb.threadContinue = False

        if (getDaysFromLastUpdate() or 0) > LAST_UPDATE_NAGGING_DAYS:
            warnMsg = 'sqlmap versiyangiz eskirgan'
            logger.warning(warnMsg)

        # emit the JSON report BEFORE the closing banner, so it does not appear awkwardly after
        # "[*] ending @ ..."
        if conf.get("reportCollector") is not None:
            try:
                from lib.utils.api import writeReportJson
                writeReportJson(conf.reportCollector, conf.reportJson)
                logger.info("JSON hisoboti '%s' fayliga yozildi" % conf.reportJson)
            except Exception as ex:
                logger.error("JSON hisobotini '%s' fayliga yozib bo'lmadi ('%s')" % (conf.reportJson, getSafeExString(ex)))
            finally:
                try:
                    conf.reportCollector.disconnect()
                except Exception as ex:
                    logger.debug("hisobot yig'uvchisini yopishda muammo ('%s')" % getSafeExString(ex))

        if conf.get("showTime"):
            dataToStdout('\n[*] tugadi: %s\n\n' % time.strftime("%X /%Y-%m-%d/"), forceOutput=True)

        kb.threadException = True

        for tempDir in conf.get("tempDirs", []):
            for prefix in (MKSTEMP_PREFIX.IPC, MKSTEMP_PREFIX.TESTING, MKSTEMP_PREFIX.COOKIE_JAR, MKSTEMP_PREFIX.BIG_ARRAY):
                for filepath in glob.glob(os.path.join(tempDir, "%s*" % prefix)):
                    try:
                        os.remove(filepath)
                    except OSError:
                        pass

            if any((conf.vulnTest, conf.fpTest, conf.smokeTest, conf.payloadLint, conf.apiTest)) or not filterNone(filepath for filepath in glob.glob(os.path.join(tempDir, '*')) if not any(filepath.endswith(_) for _ in (".lock", ".exe", ".so", '_'))):  # ignore junk files
                try:
                    shutil.rmtree(tempDir, ignore_errors=True)
                except OSError:
                    pass

        if conf.get("hashDB"):
            conf.hashDB.flush()
            conf.hashDB.close()         # NOTE: because of PyPy

        if conf.get("harFile"):
            try:
                with openFile(conf.harFile, "w+") as f:
                    json.dump(conf.httpCollector.obtain(), fp=f, indent=4, separators=(',', ': '))
            except SqlmapBaseException as ex:
                errMsg = getSafeExString(ex)
                logger.critical(errMsg)

        if conf.get("api"):
            conf.databaseCursor.disconnect()

        if conf.get("dumper"):
            conf.dumper.flush()

        # short delay for thread finalization
        _ = time.time()
        while threading.active_count() > 1 and (time.time() - _) < THREAD_FINALIZATION_TIMEOUT:
            time.sleep(0.01)

        if cmdLineOptions.get("sqlmapShell"):
            cmdLineOptions.clear()
            conf.clear()
            kb.clear()
            conf.disableBanner = True
            main()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass
    except SystemExit:
        raise
    except:
        traceback.print_exc()
    finally:
        # Reference: http://stackoverflow.com/questions/1635080/terminate-a-multi-thread-python-program
        if threading.active_count() > 1:
            os._exit(getattr(os, "_exitcode", 0))
        else:
            sys.exit(getattr(os, "_exitcode", 0))
else:
    # cancelling postponed imports (because of CI/CD checks)
    __import__("lib.controller.controller")

    # exposing the programmatic library facade as 'sqlmap.scan()' / 'sqlmap.scanFromRequest()'
    from lib.utils.library import scan, scanFromRequest, SqlmapError

# public library API (also marks the re-exported names above as intentional for pyflakes)
__all__ = ["scan", "scanFromRequest", "SqlmapError"]
