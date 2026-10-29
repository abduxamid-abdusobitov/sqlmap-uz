#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission

Update the Uzbek distribution without overwriting translations or local edits.
"""

import os
import subprocess

from lib.core.common import getSafeExString
from lib.core.convert import getText
from lib.core.data import conf
from lib.core.data import logger
from lib.core.data import paths
from lib.core.revision import getRevisionNumber

UZBEK_REPOSITORY = "https://github.com/abduxamid-abdusobitov/sqlmap-uz.git"
UZBEK_BRANCH = "main"


def _git(*args):
    process = subprocess.Popen(
        ["git"] + list(args), stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        cwd=paths.SQLMAP_ROOT_PATH,
    )
    output, _ = process.communicate()
    return process.returncode, getText(output)


def update():
    if not conf.updateAll:
        return

    # A .git file is valid too (linked worktrees). Never replace a ZIP/PyPI
    # installation with the upstream English distribution or delete its files.
    if not os.path.exists(os.path.join(paths.SQLMAP_ROOT_PATH, ".git")):
        logger.warning("Bu nusxa Git orqali o'rnatilmagan. O'zbekcha versiyani yangi papkaga oling: git clone %s sqlmap-uz" % UZBEK_REPOSITORY)
        return

    try:
        status, output = _git("status", "--porcelain", "--untracked-files=no")
        if status:
            logger.error("Git holatini tekshirib bo'lmadi: %s" % output.strip())
            return
        if output.strip():
            logger.warning("Mahalliy o'zgarishlar bor. Yangilashdan oldin ularni commit yoki stash qiling; fayllar o'zgartirilmadi.")
            return

        logger.info("SQLMAP-UZ o'zbekcha repozitoriydan yangilanmoqda")
        status, output = _git("pull", "--ff-only", UZBEK_REPOSITORY, UZBEK_BRANCH)
        if status:
            logger.error("Yangilash tugallanmadi. Git xabari: %s" % output.strip())
        else:
            logger.info("SQLMAP-UZ yangilandi. Tahrir: %s" % getRevisionNumber())
    except OSError as ex:
        logger.error("Yangilashni ishga tushirib bo'lmadi: %s" % getSafeExString(ex))
