#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission
"""

from lib.core.common import checkFile
from lib.core.common import getSafeExString
from lib.core.common import openFile
from lib.core.common import unArrayizeValue
from lib.core.common import UnicodeRawConfigParser
from lib.core.convert import getUnicode
from lib.core.data import cmdLineOptions
from lib.core.data import conf
from lib.core.data import logger
from lib.core.enums import OPTION_TYPE
from lib.core.exception import SqlmapMissingMandatoryOptionException
from lib.core.exception import SqlmapSyntaxException
from lib.core.optiondict import optDict

config = None

def configFileProxy(section, option, datatype):
    """
    Parse configuration file and save settings into the configuration
    advanced dictionary.
    """

    if config.has_option(section, option):
        try:
            if datatype == OPTION_TYPE.BOOLEAN:
                value = config.getboolean(section, option) if config.get(section, option) else False
            elif datatype == OPTION_TYPE.INTEGER:
                value = config.getint(section, option) if config.get(section, option) else 0
            elif datatype == OPTION_TYPE.FLOAT:
                value = config.getfloat(section, option) if config.get(section, option) else 0.0
            else:
                value = config.get(section, option)
        except ValueError as ex:
            errMsg = 'parametrni qayta ishlashda xato: '
            errMsg += "'%s', berilgan sozlash faylida ('%s')" % (option, getUnicode(ex))
            raise SqlmapSyntaxException(errMsg)

        if value:
            conf[option] = value
        else:
            conf[option] = None
    else:
        debugMsg = "kerakli '%s' parametri yo'q (bo'lim: " % option
        debugMsg += "'%s'), sozlash faylida; " % section
        debugMsg += "hisobga olinmadi. Keyingisiga o'tilmoqda."
        logger.debug(debugMsg)

def configFileParser(configFile):
    """
    Parse configuration file and save settings into the configuration
    advanced dictionary.
    """

    global config

    debugMsg = 'sozlash fayli tahlil qilinmoqda'
    logger.debug(debugMsg)

    checkFile(configFile)
    configFP = openFile(configFile, 'r')

    try:
        config = UnicodeRawConfigParser()
        if hasattr(config, "read_file"):
            config.read_file(configFP)
        else:
            config.readfp(configFP)
    except Exception as ex:
        errMsg = "sozlash fayli noto'g'ri yoki o'qib bo'lmaydi ('%s')" % getSafeExString(ex)
        raise SqlmapSyntaxException(errMsg)
    finally:
        configFP.close()

    if not config.has_section("Target"):
        errMsg = "sozlash faylida majburiy 'Target' bo'limi yo'q"
        raise SqlmapMissingMandatoryOptionException(errMsg)

    mandatory = False

    for option in ("direct", "url", "logFile", "bulkFile", "googleDork", "requestFile", "openApiFile", "wizard"):
        if config.has_option("Target", option) and config.get("Target", option) or cmdLineOptions.get(option):
            mandatory = True
            break

    if not mandatory:
        errMsg = "sozlash faylida majburiy parametr yo'q "
        errMsg += '(direct, url, logFile, bulkFile, googleDork, requestFile, openApiFile yoki wizard)'
        raise SqlmapMissingMandatoryOptionException(errMsg)

    for family, optionData in optDict.items():
        for option, datatype in optionData.items():
            datatype = unArrayizeValue(datatype)
            configFileProxy(family, option, datatype)
