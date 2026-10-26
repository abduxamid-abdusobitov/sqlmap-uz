#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission
"""

from lib.core.uzbek import ut
import glob
import os
import re
import shutil
import subprocess
import time
import zipfile

from lib.core.common import dataToStdout
from lib.core.common import extractRegexResult
from lib.core.common import getLatestRevision
from lib.core.common import getSafeExString
from lib.core.common import openFile
from lib.core.common import readInput
from lib.core.convert import getText
from lib.core.data import conf
from lib.core.data import logger
from lib.core.data import paths
from lib.core.revision import getRevisionNumber
from lib.core.settings import GIT_REPOSITORY
from lib.core.settings import IS_WIN
from lib.core.settings import VERSION
from lib.core.settings import TYPE
from lib.core.settings import ZIPBALL_PAGE
from thirdparty.six.moves import urllib as _urllib

def update():
    if not conf.updateAll:
        return

    success = False

    if TYPE == "pip":
        infoMsg = 'sqlmap eng yangi barqaror versiyaga yangilanmoqda: '
        infoMsg += 'PyPI repozitoriysidan'
        logger.info(infoMsg)

        debugMsg = "sqlmap o'zini 'pip' buyrug'i orqali yangilashga urinadi"
        logger.debug(debugMsg)

        dataToStdout('\r[%s] [INFO] yangilanmoqda' % time.strftime("%X"))

        output = ""
        try:
            process = subprocess.Popen("pip install -U sqlmap", shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, cwd=paths.SQLMAP_ROOT_PATH)
            output, _ = process.communicate()
            success = not process.returncode
        except Exception as ex:
            success = False
            output = getSafeExString(ex)
        finally:
            output = getText(output)

        if success:
            logger.info("%s eng yangi tahrir '%s'" % ("already at" if "already up-to-date" in output else "updated to", extractRegexResult(r"\binstalled sqlmap-(?P<result>\d+\.\d+\.\d+)", output) or extractRegexResult(r"\((?P<result>\d+\.\d+\.\d+)\)", output)))
        else:
            logger.error("yangilash tugallanmadi ('%s')" % re.sub(r"[^a-z0-9:/\\]+", " ", output).strip())

    elif not os.path.exists(os.path.join(paths.SQLMAP_ROOT_PATH, ".git")):
        warnMsg = "bu git repozitoriysi emas. 'sqlmapproject/sqlmap' ni klonlash tavsiya etiladi "
        warnMsg += "GitHub dan (masalan, 'git clone --depth 1 %s sqlmap')" % GIT_REPOSITORY
        logger.warning(warnMsg)

        if VERSION == getLatestRevision():
            logger.info("allaqachon eng yangi '%s' tahriri ishlatilmoqda" % (getRevisionNumber() or VERSION))
            return

        message = ut("do you want to try to fetch the latest 'zipball' from repository and extract it (experimental) ? [y/N]", 'repozitoriydan eng yangi ZIP arxivini olib ochishga urinilsinmi (tajribaviy)? [y/N]')
        if readInput(message, default='N', boolean=True):
            directory = os.path.abspath(paths.SQLMAP_ROOT_PATH)

            try:
                open(os.path.join(directory, "sqlmap.py"), "w+b")
            except Exception as ex:
                errMsg = "'%s' papkasi mazmunini yangilab bo'lmadi ('%s')" % (directory, getSafeExString(ex))
                logger.error(errMsg)
            else:
                attrs = os.stat(os.path.join(directory, "sqlmap.py")).st_mode
                for wildcard in ('*', ".*"):
                    for _ in glob.glob(os.path.join(directory, wildcard)):
                        try:
                            if os.path.isdir(_):
                                shutil.rmtree(_)
                            else:
                                os.remove(_)
                        except:
                            pass

                if glob.glob(os.path.join(directory, '*')):
                    errMsg = "'%s' papkasi mazmunini tozalab bo'lmadi" % directory
                    logger.error(errMsg)
                else:
                    try:
                        archive = _urllib.request.urlretrieve(ZIPBALL_PAGE)[0]

                        with zipfile.ZipFile(archive) as f:
                            for info in f.infolist():
                                info.filename = re.sub(r"\Asqlmap[^/]+", "", info.filename)
                                if info.filename:
                                    f.extract(info, directory)

                        filepath = os.path.join(paths.SQLMAP_ROOT_PATH, "lib", "core", "settings.py")
                        if os.path.isfile(filepath):
                            with openFile(filepath, "r") as f:
                                version = re.search(r"(?m)^VERSION\s*=\s*['\"]([^'\"]+)", f.read()).group(1)
                                logger.info("eng yangi '%s#dev' versiyasiga yangilandi" % version)
                                success = True
                    except Exception as ex:
                        logger.error("yangilash tugallanmadi ('%s')" % getSafeExString(ex))
                    else:
                        if not success:
                            logger.error('yangilash tugallanmadi')
                        else:
                            try:
                                os.chmod(os.path.join(directory, "sqlmap.py"), attrs)
                            except OSError:
                                logger.warning("'%s' fayl atributlarini o'rnatib bo'lmadi" % os.path.join(directory, "sqlmap.py"))

    else:
        infoMsg = 'sqlmap eng yangi ishlab chiqish versiyasiga yangilanmoqda: '
        infoMsg += 'GitHub repozitoriysidan'
        logger.info(infoMsg)

        debugMsg = "sqlmap o'zini 'git' buyrug'i orqali yangilashga urinadi"
        logger.debug(debugMsg)

        dataToStdout('\r[%s] [INFO] yangilanmoqda' % time.strftime("%X"))

        output = ""
        try:
            process = subprocess.Popen("git checkout . && git pull %s HEAD" % GIT_REPOSITORY, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, cwd=paths.SQLMAP_ROOT_PATH)
            output, _ = process.communicate()
            success = not process.returncode
        except Exception as ex:
            success = False
            output = getSafeExString(ex)
        finally:
            output = getText(output)

        if success:
            logger.info("%s eng yangi tahrir '%s'" % ("already at" if "Already" in output else "updated to", getRevisionNumber()))
        else:
            if "Not a git repository" in output:
                errMsg = "yaroqli git repozitoriysi emas. 'sqlmapproject/sqlmap' ni oling "
                errMsg += "GitHub dan (masalan, 'git clone --depth 1 %s sqlmap')" % GIT_REPOSITORY
                logger.error(errMsg)
            else:
                logger.error("yangilash tugallanmadi ('%s')" % re.sub(r"\W+", " ", output).strip())

    if not success:
        if IS_WIN:
            infoMsg = 'Windows uchun '
            infoMsg += 'GitHub for Windows mijozi orqali yangilash '
            infoMsg += 'tavsiya etiladi (https://desktop.github.com/) yoki '
            infoMsg += 'eng yangi nusxani yuklab oling: '
            infoMsg += "https://github.com/sqlmapproject/sqlmap/releases"
        else:
            infoMsg = 'Linux uchun '
            infoMsg += "standart 'git' paketini o'rnatish tavsiya etiladi (masalan, 'apt install git')"

        logger.info(infoMsg)
