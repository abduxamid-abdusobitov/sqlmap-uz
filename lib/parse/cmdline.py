#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission
"""

from __future__ import print_function

from lib.core.uzbek import install_parser_translation
install_parser_translation()
import os
import re
import shlex
import sys

try:
    from optparse import OptionError as ArgumentError
    from optparse import OptionGroup
    from optparse import OptionParser as ArgumentParser
    from optparse import SUPPRESS_HELP as SUPPRESS

    ArgumentParser.add_argument = ArgumentParser.add_option

    def _add_argument_group(self, *args, **kwargs):
        return self.add_option_group(OptionGroup(self, *args, **kwargs))

    ArgumentParser.add_argument_group = _add_argument_group

    def _add_argument(self, *args, **kwargs):
        return self.add_option(*args, **kwargs)

    OptionGroup.add_argument = _add_argument

except ImportError:
    from argparse import ArgumentParser
    from argparse import ArgumentError
    from argparse import SUPPRESS

finally:
    def get_actions(instance):
        for attr in ("option_list", "_group_actions", "_actions"):
            if hasattr(instance, attr):
                return getattr(instance, attr)

    def get_groups(parser):
        return getattr(parser, "option_groups", None) or getattr(parser, "_action_groups")

    def get_all_options(parser):
        retVal = set()

        for option in get_actions(parser):
            if hasattr(option, "option_strings"):
                retVal.update(option.option_strings)
            else:
                retVal.update(option._long_opts)
                retVal.update(option._short_opts)

        for group in get_groups(parser):
            for option in get_actions(group):
                if hasattr(option, "option_strings"):
                    retVal.update(option.option_strings)
                else:
                    retVal.update(option._long_opts)
                    retVal.update(option._short_opts)

        return retVal

from lib.core.common import checkOldOptions
from lib.core.common import checkSystemEncoding
from lib.core.common import dataToStdout
from lib.core.common import expandMnemonics
from lib.core.common import getSafeExString
from lib.core.compat import xrange
from lib.core.convert import getUnicode
from lib.core.data import cmdLineOptions
from lib.core.data import conf
from lib.core.data import logger
from lib.core.defaults import defaults
from lib.core.dicts import DEPRECATED_OPTIONS
from lib.core.enums import AUTOCOMPLETE_TYPE
from lib.core.exception import SqlmapShellQuitException
from lib.core.exception import SqlmapSilentQuitException
from lib.core.exception import SqlmapSyntaxException
from lib.core.option import _createHomeDirectories
from lib.core.settings import BASIC_HELP_ITEMS
from lib.core.settings import DUMMY_URL
from lib.core.settings import IGNORED_OPTIONS
from lib.core.settings import INFERENCE_UNKNOWN_CHAR
from lib.core.settings import IS_WIN
from lib.core.settings import MAX_HELP_OPTION_LENGTH
from lib.core.settings import VERSION_STRING
from lib.core.shell import autoCompletion
from lib.core.shell import clearHistory
from lib.core.shell import loadHistory
from lib.core.shell import saveHistory
from thirdparty.six.moves import input as _input

def cmdLineParser(argv=None):
    """
    This function parses the command line parameters and arguments
    """

    if not argv:
        argv = sys.argv

    checkSystemEncoding()

    # Reference: https://stackoverflow.com/a/4012683 (Note: previously used "...sys.getfilesystemencoding() or UNICODE_ENCODING")
    _ = getUnicode(os.path.basename(argv[0]), encoding=sys.stdin.encoding)

    usage = "%s%s [parametrlar]" % ("%s " % os.path.basename(sys.executable) if not IS_WIN else "", "\"%s\"" % _ if " " in _ else _)
    parser = ArgumentParser(usage=usage)

    try:
        parser.add_argument("--hh", dest="advancedHelp", action="store_true",
            help="Batafsil yordamni ko'rsatish va chiqish")

        parser.add_argument("--version", dest="showVersion", action="store_true",
            help="Dastur versiyasini ko'rsatish va chiqish")

        parser.add_argument("-v", dest="verbose", type=int,
            help='Batafsillik darajasi: 0-6 (standart: %d)' % defaults.verbose)

        # Target options
        target = parser.add_argument_group('Nishon', 'Nishonni belgilash uchun shu parametrlardan kamida bittasi kerak')

        target.add_argument("-u", "--url", dest="url",
            help='Nishon URL (masalan, "http://www.site.com/vuln.php?id=1")')

        target.add_argument("-d", dest="direct",
            help='Bazaga bevosita ulanish satri')

        target.add_argument("-l", dest="logFile",
            help='Nishonlarni Burp yoki WebScarab proksi jurnalidan olish')

        target.add_argument("-m", dest="bulkFile",
            help='Matn faylida berilgan bir nechta nishonni tekshirish')

        target.add_argument("-r", dest="requestFile",
            help="HTTP so'rovini fayldan yuklash")

        target.add_argument("-g", "--dork", dest="googleDork", metavar="DORK",
            help='Qidiruv dorki natijalarini nishon URL sifatida olish')

        target.add_argument("-c", dest="configFile",
            help='Sozlamalarni INI faylidan yuklash')

        target.add_argument("--openapi", dest="openApiFile",
            help='Nishonlarni OpenAPI/Swagger fayli yoki URL dan olish')

        target.add_argument("--openapi-base", dest="openApiBase",
            help="Xosti ko'rsatilmagan OpenAPI/Swagger uchun asosiy URL")

        target.add_argument("--openapi-tags", dest="openApiTags",
            help='Faqat berilgan tegli amallardan nishon olish')

        # Request options
        request = parser.add_argument_group("So'rov", 'Nishon URL bilan ulanish usulini belgilash parametrlari')

        request.add_argument("-A", "--user-agent", dest="agent",
            help='HTTP User-Agent sarlavhasi qiymati')

        request.add_argument("-H", "--header", dest="header",
            help='Qo\'shimcha sarlavha (masalan, "X-Forwarded-For: 127.0.0.1")')

        request.add_argument("-X", "--method", dest="method",
            help='Berilgan HTTP usulini majburan ishlatish (masalan, PUT)')

        request.add_argument("--data", dest="data",
            help='POST orqali yuboriladigan ma\'lumot (masalan, "id=1")')

        request.add_argument("--param-del", dest="paramDel",
            help='Parametr qiymatlarini ajratuvchi belgi (masalan, &)')

        request.add_argument("--cookie", dest="cookie",
            help='HTTP Cookie qiymati (masalan, "PHPSESSID=a8d127e..")')

        request.add_argument("--cookie-del", dest="cookieDel",
            help='Cookie qiymatlarini ajratuvchi belgi (masalan, ;)')

        request.add_argument("--live-cookies", dest="liveCookies",
            help='Joriy qiymatlar olinadigan yangilanib turuvchi cookie fayli')

        request.add_argument("--load-cookies", dest="loadCookies",
            help='Netscape/wget formatidagi cookie fayli')

        request.add_argument("--drop-set-cookie", dest="dropSetCookie", action="store_true",
            help='Javobdagi Set-Cookie sarlavhasini hisobga olmaslik')

        request.add_argument("--http1.0", dest="http10", action="store_true",
            help='HTTP 1.0 versiyasini ishlatish (eski)')

        request.add_argument("--http2", dest="http2", action="store_true",
            help='HTTP 2 versiyasini ishlatish (tajribaviy)')

        request.add_argument("--mobile", dest="mobile", action="store_true",
            help='HTTP User-Agent orqali smartfonga taqlid qilish')

        request.add_argument("--random-agent", dest="randomAgent", action="store_true",
            help='Tasodifiy HTTP User-Agent qiymatini ishlatish')

        request.add_argument("--host", dest="host",
            help='HTTP Host sarlavhasi qiymati')

        request.add_argument("--referer", dest="referer",
            help='HTTP Referer sarlavhasi qiymati')

        request.add_argument("--headers", dest="headers",
            help='Qo\'shimcha sarlavhalar (masalan, "Accept-Language: fr\nETag: 123")')

        request.add_argument("--auth-type", dest="authType",
            help='HTTP autentifikatsiya turi (Basic, Digest, Bearer, ...)')

        request.add_argument("--auth-cred", dest="authCred",
            help="HTTP kirish ma'lumotlari (name:password)")

        request.add_argument("--auth-file", dest="authFile",
            help='HTTP autentifikatsiyasi uchun PEM sertifikat/maxfiy kalit')

        request.add_argument("--abort-code", dest="abortCode",
            help="Berilgan HTTP xato kodida to'xtash (masalan, 401)")

        request.add_argument("--ignore-code", dest="ignoreCode",
            help='Berilgan HTTP xato kodini hisobga olmaslik (masalan, 401)')

        request.add_argument("--ignore-proxy", dest="ignoreProxy", action="store_true",
            help='Tizimning standart proksi sozlamalarini hisobga olmaslik')

        request.add_argument("--ignore-redirects", dest="ignoreRedirects", action="store_true",
            help="Qayta yo'naltirishlarni hisobga olmaslik")

        request.add_argument("--ignore-timeouts", dest="ignoreTimeouts", action="store_true",
            help='Ulanish kutish vaqti tugashini hisobga olmaslik')

        request.add_argument("--proxy", dest="proxy",
            help='Nishon URL ga proksi orqali ulanish')

        request.add_argument("--proxy-cred", dest="proxyCred",
            help="Proksi kirish ma'lumotlari (name:password)")

        request.add_argument("--proxy-file", dest="proxyFile",
            help="Proksilar ro'yxatini fayldan yuklash")

        request.add_argument("--proxy-freq", dest="proxyFreq", type=int,
            help="Ro'yxatdagi proksini almashtirishdan oldingi so'rovlar soni")

        request.add_argument("--tor", dest="tor", action="store_true",
            help="Tor anonim tarmog'idan foydalanish")

        request.add_argument("--tor-port", dest="torPort",
            help='Tor proksisi uchun boshqa port belgilash')

        request.add_argument("--tor-type", dest="torType",
            help='Tor turi: HTTP, SOCKS4 yoki SOCKS5 (standart)')

        request.add_argument("--check-tor", dest="checkTor", action="store_true",
            help="Tor to'g'ri ishlatilayotganini tekshirish")

        request.add_argument("--delay", dest="delay", type=float,
            help="HTTP so'rovlari orasidagi tanaffus, soniyada")

        request.add_argument("--timeout", dest="timeout", type=float,
            help='Ulanishni kutish muddati, soniyada (standart: %d)' % defaults.timeout)

        request.add_argument("--retries", dest="retries", type=int,
            help='Kutish vaqti tugaganda qayta urinishlar (standart: %d)' % defaults.retries)

        request.add_argument("--retry-on", dest="retryOn",
            help='Mazmun regexga mos kelsa, so\'rovni takrorlash (masalan, "drop")')

        request.add_argument("--randomize", dest="rParam",
            help="Berilgan parametrlar qiymatini tasodifiy o'zgartirish")

        request.add_argument("--safe-url", dest="safeUrl",
            help='Tekshiruv davomida muntazam ochiladigan URL')

        request.add_argument("--safe-post", dest="safePost",
            help="Xavfsiz URL ga yuboriladigan POST ma'lumotlari")

        request.add_argument("--safe-req", dest="safeReqFile",
            help="Xavfsiz HTTP so'rovini fayldan yuklash")

        request.add_argument("--safe-freq", dest="safeFreq", type=int,
            help="Xavfsiz URL tashriflari orasidagi oddiy so'rovlar soni")

        request.add_argument("--skip-urlencode", dest="skipUrlEncode", action="store_true",
            help="Payload ma'lumotlarini URL kodlamaslik")

        request.add_argument("--skip-xmlencode", dest="skipXmlEncode", action="store_true",
            help='Payloadni SOAP/XML uchun xavfsiz kodlamaslik')

        request.add_argument("--csrf-token", dest="csrfToken",
            help='Anti-CSRF tokeni saqlanadigan parametr')

        request.add_argument("--csrf-url", dest="csrfUrl",
            help='Anti-CSRF tokeni olinadigan URL')

        request.add_argument("--csrf-method", dest="csrfMethod",
            help='Anti-CSRF tokeni sahifasiga HTTP murojaat usuli')

        request.add_argument("--csrf-data", dest="csrfData",
            help="Anti-CSRF sahifasiga yuboriladigan POST ma'lumotlari")

        request.add_argument("--csrf-retries", dest="csrfRetries", type=int,
            help='Anti-CSRF tokeni uchun qayta urinishlar (standart: %d)' % defaults.csrfRetries)

        request.add_argument("--force-ssl", dest="forceSSL", action="store_true",
            help='SSL/HTTPS dan majburan foydalanish')

        request.add_argument("--chunked", dest="chunked", action="store_true",
            help="HTTP bo'laklab uzatish kodlashidagi POST so'rovlari")

        request.add_argument("--hpp", dest="hpp", action="store_true",
            help='HTTP parametrlarini takrorlash usulini ishlatish')

        request.add_argument("--eval", dest="evalCode",
            help='So\'rovdan oldin Python kodini bajarish (masalan, "import hashlib;id2=hashlib.md5(id).hexdigest()")')

        # Optimization options
        optimization = parser.add_argument_group('Optimallashtirish', 'Sqlmap ishlash tezligini yaxshilash parametrlari')

        optimization.add_argument("-o", dest="optimize", action="store_true",
            help='Barcha optimallashtirish parametrlarini yoqish')

        # Note: persistent (Keep-Alive) connections are used by default; this opts out
        optimization.add_argument("--no-keep-alive", dest="noKeepAlive", action="store_true",
            help="Doimiy HTTP(s) ulanishlarni (Keep-Alive) o'chirish")

        optimization.add_argument("--null-connection", dest="nullConnection", action="store_true",
            help='HTTP javob tanasisiz sahifa uzunligini olish')

        optimization.add_argument("--threads", dest="threads", type=int,
            help="Bir paytdagi HTTP(s) so'rovlari soni (standart: %d)" % defaults.threads)

        # Injection options
        injection = parser.add_argument_group('Inyeksiya', 'Tekshiriladigan parametrlar, maxsus payload va tamper skriptlarini belgilash')

        injection.add_argument("-p", dest="testParameter",
            help='Tekshiriladigan parametrlar')

        injection.add_argument("--skip", dest="skip",
            help='Berilgan parametrlarni tekshirmaslik')

        injection.add_argument("--skip-static", dest="skipStatic", action="store_true",
            help="Dinamik bo'lmagan parametrlarni tekshirmaslik")

        injection.add_argument("--param-exclude", dest="paramExclude",
            help='Parametrlarni tekshiruvdan chiqarish regexi (masalan, "ses")')

        injection.add_argument("--param-filter", dest="paramFilter",
            help='Parametrlarni joyiga qarab tanlash (masalan, "POST")')

        injection.add_argument("--dbms", dest="dbms",
            help="Serverdagi DBMS turini qo'lda belgilash")

        injection.add_argument("--dbms-cred", dest="dbmsCred",
            help="DBMS kirish ma'lumotlari (user:password)")

        injection.add_argument("--esperanto", dest="esperanto", action="store_true",
            help="DBMSga bog'liq bo'lmagan olish mexanizmini ishlatish")

        injection.add_argument("--os", dest="os",
            help="Serverdagi DBMS operatsion tizimini qo'lda belgilash")

        injection.add_argument("--invalid-bignum", dest="invalidBignum", action="store_true",
            help="Qiymatlarni noto'g'ri qilish uchun katta sonlar ishlatish")

        injection.add_argument("--invalid-logical", dest="invalidLogical", action="store_true",
            help="Qiymatlarni noto'g'ri qilish uchun mantiqiy amallar")

        injection.add_argument("--invalid-string", dest="invalidString", action="store_true",
            help="Qiymatlarni noto'g'ri qilish uchun tasodifiy matnlar")

        injection.add_argument("--no-cast", dest="noCast", action="store_true",
            help="Payload turini o'zgartirish mexanizmini o'chirish")

        injection.add_argument("--no-escape", dest="noEscape", action="store_true",
            help="Matnni ekranlash mexanizmini o'chirish")

        injection.add_argument("--prefix", dest="prefix",
            help='Inyeksiya payloadidan oldingi matn')

        injection.add_argument("--suffix", dest="suffix",
            help='Inyeksiya payloadidan keyingi matn')

        injection.add_argument("--tamper", dest="tamper",
            help="Inyeksiya ma'lumotiga berilgan tamper skriptlarini qo'llash")

        injection.add_argument("--proof", dest="proof", action="store_true",
            help='Topilgan inyeksiyadan foydalanish mumkinligini isbotlash')

        # Detection options
        detection = parser.add_argument_group('Aniqlash', 'Zaiflikni aniqlash bosqichini sozlash parametrlari')

        detection.add_argument("--level", dest="level", type=int,
            help='Tekshirish darajasi (1-5, standart: %d)' % defaults.level)

        detection.add_argument("--risk", dest="risk", type=int,
            help='Test xavf darajasi (1-3, standart: %d)' % defaults.risk)

        detection.add_argument("--string", dest="string",
            help="So'rov True bo'lganda mos keladigan matn")

        detection.add_argument("--not-string", dest="notString",
            help="So'rov False bo'lganda mos keladigan matn")

        detection.add_argument("--regexp", dest="regexp",
            help="So'rov True bo'lganda mos keladigan regex")

        detection.add_argument("--code", dest="code", type=int,
            help="So'rov True bo'lganda mos keladigan HTTP kodi")

        detection.add_argument("--lengths", dest="lengths", action="store_true",
            help='Sahifalarni faqat mazmun uzunligi bilan taqqoslash')

        detection.add_argument("--smart", dest="smart", action="store_true",
            help="Faqat ijobiy evristik natijada chuqur test o'tkazish")

        detection.add_argument("--text-only", dest="textOnly", action="store_true",
            help='Sahifalarni faqat matn mazmuni bilan taqqoslash')

        detection.add_argument("--titles", dest="titles", action="store_true",
            help='Sahifalarni faqat sarlavhasi bilan taqqoslash')

        # Techniques options
        techniques = parser.add_argument_group('Usullar', 'Muayyan SQL-inyeksiya usullari tekshiruvini sozlash')

        techniques.add_argument("--technique", dest="technique",
            help='SQL-inyeksiya usullari (standart: "%s")' % defaults.technique)

        techniques.add_argument("--time-sec", dest="timeSec", type=int,
            help='DBMS javobini kechiktirish soniyasi (standart: %d)' % defaults.timeSec)

        techniques.add_argument("--disable-stats", dest="disableStats", action="store_true",
            help="Kechikishni aniqlovchi statistik modelni o'chirish")

        techniques.add_argument("--timeless", dest="timeless", action="store_true",
            help='HTTP/2 timeless vaqt usuli (tezroq, kechikishsiz)')

        techniques.add_argument("--multi-bit", dest="multiBit", action="store_true",
            help="Har so'rovda bir necha bitni aks etgan qatorlardan o'qish")

        techniques.add_argument("--union-cols", dest="uCols",
            help="UNION SQL-inyeksiya testidagi ustunlar oralig'i")

        techniques.add_argument("--union-char", dest="uChar",
            help='Ustunlar sonini sinashda ishlatiladigan belgi')

        techniques.add_argument("--union-from", dest="uFrom",
            help='UNION SQL-inyeksiyasining FROM qismidagi jadval')

        techniques.add_argument("--union-values", dest="uValues",
            help='UNION SQL-inyeksiyasida ishlatiladigan ustun qiymatlari')

        techniques.add_argument("--dns-domain", dest="dnsDomain",
            help="DNS orqali chiqarish domeni (yoki sozlashsiz OOB uchun 'interactsh')")

        techniques.add_argument("--second-url", dest="secondUrl",
            help='Ikkinchi tartibli javob qidiriladigan sahifa URL manzili')

        techniques.add_argument("--second-req", dest="secondReq",
            help="Ikkinchi tartibli HTTP so'rovini fayldan yuklash")

        # Fingerprint options
        fingerprint = parser.add_argument_group('Tizimni aniqlash', "Serverdagi ma'lumotlar bazasi boshqaruv tizimi versiyasini aniqlash")

        fingerprint.add_argument("-f", "--fingerprint", dest="extensiveFp", action="store_true",
            help='DBMS versiyasini batafsil aniqlash')

        # Enumeration options
        enumeration = parser.add_argument_group("Ma'lumotlarni olish", "Serverdagi DBMS haqida ma'lumot, baza tuzilishi va jadval mazmunini olish")

        enumeration.add_argument("-a", "--all", dest="getAll", action="store_true",
            help="Barcha ma'lumotlarni olish")

        enumeration.add_argument("-b", "--banner", dest="getBanner", action="store_true",
            help='DBMS bannerini olish')

        enumeration.add_argument("--current-user", dest="getCurrentUser", action="store_true",
            help='DBMS joriy foydalanuvchisini olish')

        enumeration.add_argument("--current-db", dest="getCurrentDb", action="store_true",
            help='DBMS joriy bazasini olish')

        enumeration.add_argument("--hostname", dest="getHostname", action="store_true",
            help='DBMS serveri xost nomini olish')

        enumeration.add_argument("--audit", dest="getAudit", action="store_true",
            help='DBMS xavfsizlik sozlamalari va imkoniyatlarini tekshirish')

        enumeration.add_argument("--is-dba", dest="isDba", action="store_true",
            help='Joriy DBMS foydalanuvchisi DBA ekanini aniqlash')

        enumeration.add_argument("--users", dest="getUsers", action="store_true",
            help='DBMS foydalanuvchilarini sanab olish')

        enumeration.add_argument("--passwords", dest="getPasswordHashes", action="store_true",
            help='DBMS foydalanuvchilari parol xeshlarini olish')

        enumeration.add_argument("--privileges", dest="getPrivileges", action="store_true",
            help='DBMS foydalanuvchilari huquqlarini olish')

        enumeration.add_argument("--roles", dest="getRoles", action="store_true",
            help='DBMS foydalanuvchilari rollarini olish')

        enumeration.add_argument("--links", dest="getLinks", action="store_true",
            help="DBMS bog'lanishlarini olish")

        enumeration.add_argument("--dbs", dest="getDbs", action="store_true",
            help='DBMS bazalarini sanab olish')

        enumeration.add_argument("--tables", dest="getTables", action="store_true",
            help='Bazadagi jadvallarni sanab olish')

        enumeration.add_argument("--columns", dest="getColumns", action="store_true",
            help='Jadval ustunlarini sanab olish')

        enumeration.add_argument("--schema", dest="getSchema", action="store_true",
            help='DBMS sxemasini olish')

        enumeration.add_argument("--count", dest="getCount", action="store_true",
            help='Jadvallardagi yozuvlar sonini olish')

        enumeration.add_argument("--dump", dest="dumpTable", action="store_true",
            help="Jadval yozuvlarini ko'chirib olish")

        enumeration.add_argument("--dump-all", dest="dumpAll", action="store_true",
            help="Barcha jadvallar yozuvlarini ko'chirib olish")

        enumeration.add_argument("--search", dest="search", action="store_true",
            help='Ustun, jadval va/yoki baza nomlarini qidirish')

        enumeration.add_argument("--comments", dest="getComments", action="store_true",
            help="Ma'lumot olishda DBMS izohlarini tekshirish")

        enumeration.add_argument("--statements", dest="getStatements", action="store_true",
            help='DBMS da bajarilayotgan SQL buyruqlarini olish')

        enumeration.add_argument("--procs", dest="getProcs", action="store_true",
            help='Saqlangan protsedura/funksiyalar va manba kodini olish')

        enumeration.add_argument("-D", dest="db",
            help="Ma'lumot olinadigan DBMS bazasi")

        enumeration.add_argument("-T", dest="tbl",
            help="Ma'lumot olinadigan DBMS jadvallari")

        enumeration.add_argument("-C", dest="col",
            help="Ma'lumot olinadigan jadval ustunlari")

        enumeration.add_argument("--exclude", dest="exclude",
            help="Ma'lumot olinmaydigan DBMS identifikatorlari")

        enumeration.add_argument("-U", dest="user",
            help="Ma'lumoti olinadigan DBMS foydalanuvchisi")

        enumeration.add_argument("--exclude-sysdbs", dest="excludeSysDbs", action="store_true",
            help='Jadvallarni sanashda tizim bazalarini chiqarib tashlash')

        enumeration.add_argument("--pivot-column", dest="pivotColumn",
            help='Tayanch ustun nomi')

        enumeration.add_argument("--where", dest="dumpWhere",
            help='Jadvalni olishda WHERE shartidan foydalanish')

        enumeration.add_argument("--start", dest="limitStart", type=int,
            help='Olinadigan birinchi jadval yozuvi')

        enumeration.add_argument("--stop", dest="limitStop", type=int,
            help='Olinadigan oxirgi jadval yozuvi')

        enumeration.add_argument("--first", dest="firstChar", type=int,
            help="So'rov natijasidan olinadigan birinchi belgi")

        enumeration.add_argument("--last", dest="lastChar", type=int,
            help="So'rov natijasidan olinadigan oxirgi belgi")

        enumeration.add_argument("--sql-query", dest="sqlQuery",
            help="Bajariladigan SQL buyrug'i")

        enumeration.add_argument("--sql-shell", dest="sqlShell", action="store_true",
            help="Interaktiv SQL qobig'ini ochish")

        enumeration.add_argument("--sql-file", dest="sqlFile",
            help='Berilgan fayllardagi SQL buyruqlarini bajarish')

        # Brute force options
        brute = parser.add_argument_group('Variantlarni sinash', 'Variantlarni ketma-ket sinab tekshirish parametrlari')

        brute.add_argument("--common-tables", dest="commonTables", action="store_true",
            help='Keng tarqalgan jadvallar mavjudligini tekshirish')

        brute.add_argument("--common-columns", dest="commonColumns", action="store_true",
            help='Keng tarqalgan ustunlar mavjudligini tekshirish')

        brute.add_argument("--common-files", dest="commonFiles", action="store_true",
            help='Keng tarqalgan fayllar mavjudligini tekshirish')

        # User-defined function options
        udf = parser.add_argument_group('Foydalanuvchi funksiyasini kiritish', 'Maxsus foydalanuvchi funksiyalarini yaratish parametrlari')

        udf.add_argument("--udf-inject", dest="udfInject", action="store_true",
            help='Maxsus foydalanuvchi funksiyalarini kiritish')

        udf.add_argument("--shared-lib", dest="shLib",
            help="Umumiy kutubxonaning mahalliy yo'li")

        # File system options
        filesystem = parser.add_argument_group('Fayl tizimiga kirish', 'Serverdagi DBMS joylashgan fayl tizimiga kirish parametrlari')

        filesystem.add_argument("--file-read", dest="fileRead",
            help="Serverdagi DBMS fayl tizimidan fayl o'qish")

        filesystem.add_argument("--file-write", dest="fileWrite",
            help='Mahalliy faylni DBMS fayl tizimiga yozish')

        filesystem.add_argument("--file-dest", dest="fileDest",
            help="Serverdagi fayl yoziladigan to'liq yo'l")

        # Takeover options
        takeover = parser.add_argument_group('Operatsion tizimga kirish', 'Serverdagi DBMS joylashgan operatsion tizimga kirish parametrlari')

        takeover.add_argument("--os-cmd", dest="osCmd",
            help="Operatsion tizim buyrug'ini bajarish")

        takeover.add_argument("--os-shell", dest="osShell", action="store_true",
            help="Interaktiv operatsion tizim qobig'ini ochish")

        takeover.add_argument("--os-pwn", dest="osPwn", action="store_true",
            help="OOB qobig'i, Meterpreter yoki VNC ni ochish")

        takeover.add_argument("--os-smbrelay", dest="osSmb", action="store_true",
            help="OOB qobig'i, Meterpreter yoki VNC ni bir amalda ochish")

        takeover.add_argument("--os-bof", dest="osBof", action="store_true",
            help='Saqlangan protsedura bufer toshishidan foydalanish')

        takeover.add_argument("--priv-esc", dest="privEsc", action="store_true",
            help='Baza jarayoni foydalanuvchisi huquqlarini oshirish')

        takeover.add_argument("--msf-path", dest="msfPath",
            help="Metasploit Framework o'rnatilgan mahalliy yo'l")

        takeover.add_argument("--tmp-path", dest="tmpPath",
            help="Serverdagi vaqtinchalik papkaning to'liq yo'li")

        # Windows registry options
        windows = parser.add_argument_group('Windows reyestriga kirish', 'Serverdagi DBMS joylashgan Windows reyestriga kirish parametrlari')

        windows.add_argument("--reg-read", dest="regRead", action="store_true",
            help="Windows reyestri kalit qiymatini o'qish")

        windows.add_argument("--reg-add", dest="regAdd", action="store_true",
            help="Windows reyestri kalit qiymatiga ma'lumot yozish")

        windows.add_argument("--reg-del", dest="regDel", action="store_true",
            help="Windows reyestri kalit qiymatini o'chirish")

        windows.add_argument("--reg-key", dest="regKey",
            help='Windows reyestri kaliti')

        windows.add_argument("--reg-value", dest="regVal",
            help='Windows reyestri kaliti qiymati')

        windows.add_argument("--reg-data", dest="regData",
            help="Windows reyestri qiymati ma'lumoti")

        windows.add_argument("--reg-type", dest="regType",
            help='Windows reyestri qiymatining turi')

        # General options
        general = parser.add_argument_group('Umumiy', 'Dastur ishlashining umumiy parametrlarini sozlash')

        general.add_argument("-s", dest="sessionFile",
            help='Saqlangan .sqlite faylidan sessiyani yuklash')

        general.add_argument("-t", dest="trafficFile",
            help='Barcha HTTP trafikni matn fayliga yozish')

        general.add_argument("--abort-on-empty", dest="abortOnEmpty", action="store_true",
            help="Bo'sh natijada ma'lumot olishni to'xtatish")

        general.add_argument("--answers", dest="answers",
            help='Oldindan javob belgilash (masalan, "quit=N,follow=N")')

        general.add_argument("--base64", dest="base64Parameter",
            help="Base64 ma'lumot saqlovchi parametrlar")

        general.add_argument("--base64-safe", dest="base64Safe", action="store_true",
            help='URL va fayl nomiga xavfsiz Base64 alifbosi (RFC 4648)')

        general.add_argument("--batch", dest="batch", action="store_true",
            help='Savol bermasdan standart javoblar bilan ishlash')

        general.add_argument("--binary-fields", dest="binaryFields",
            help='Binar qiymatli natija maydonlari (masalan, "digest")')

        general.add_argument("--check-internet", dest="checkInternet", action="store_true",
            help='Nishonni tekshirishdan oldin internetni tekshirish')

        general.add_argument("--cleanup", dest="cleanup", action="store_true",
            help='DBMS dan sqlmap yaratgan UDF va jadvallarni tozalash')

        general.add_argument("--crawl", dest="crawlDepth", type=int,
            help="Nishon URL dan boshlab sayt sahifalarini ko'rib chiqish")

        general.add_argument("--crawl-exclude", dest="crawlExclude",
            help='Ko\'rib chiqilmaydigan sahifalar regexi (masalan, "logout")')

        general.add_argument("--csv-del", dest="csvDel",
            help='CSV natijasidagi ajratuvchi belgi (standart: "%s")' % defaults.csvDel)

        general.add_argument("--charset", dest="charset",
            help='Ko\'r SQL-inyeksiya belgilar to\'plami (masalan, "0123456789abcdef")')

        general.add_argument("--dump-file", dest="dumpFile",
            help="Olingan ma'lumotni boshqa faylga saqlash")

        general.add_argument("--dump-format", dest="dumpFormat",
            help='Saqlash formati: CSV (standart), HTML, SQLITE, JSONL')

        general.add_argument("--encoding", dest="encoding",
            help="Ma'lumot olishdagi belgilar kodlashi (masalan, GBK)")

        general.add_argument("--eta", dest="eta", action="store_true",
            help="Har bir natija uchun taxminiy qolgan vaqtni ko'rsatish")

        general.add_argument("--flush-session", dest="flushSession", action="store_true",
            help='Joriy nishon sessiya fayllarini tozalash')

        general.add_argument("--forms", dest="forms", action="store_true",
            help='Nishon URL dagi formalarni aniqlash va tekshirish')

        general.add_argument("--mine-params", dest="mineParams", action="store_true",
            help='Yashirin GET parametrlarini qidirib tekshirish')

        general.add_argument("--fresh-queries", dest="freshQueries", action="store_true",
            help="Sessiya faylidagi so'rov natijalarini hisobga olmaslik")

        general.add_argument("--gpage", dest="googlePage", type=int, metavar="PAGE",
            help='Dork natijalarini berilgan sahifa raqamidan olish')

        general.add_argument("--har", dest="harFile",
            help='Barcha HTTP trafikni HAR fayliga yozish')

        general.add_argument("--hex", dest="hexConvert", action="store_true",
            help="Ma'lumot olishda o'n oltilik formatga o'tkazish")

        general.add_argument("--output-dir", dest="outputDir", action="store",
            help="Natijalar uchun boshqa papka yo'li")

        general.add_argument("--parse-errors", dest="parseErrors", action="store_true",
            help="Javoblardagi DBMS xatolarini ajratish va ko'rsatish")

        general.add_argument("--auth-refresh", dest="authRefresh",
            help='HTTP 401 da autentifikatsiyani yangilash skripti')

        general.add_argument("--preprocess", dest="preprocess",
            help="So'rovni oldindan qayta ishlash skriptlari")

        general.add_argument("--postprocess", dest="postprocess",
            help='Javobni keyin qayta ishlash skriptlari')

        general.add_argument("--repair", dest="repair", action="store_true",
            help="Noma'lum belgi (%s) bor yozuvlarni qayta olish" % INFERENCE_UNKNOWN_CHAR)

        general.add_argument("--report-json", dest="reportJson",
            help='Ish natijalarini JSON fayliga saqlash')

        general.add_argument("--save", dest="saveConfig",
            help='Parametrlarni INI sozlash fayliga saqlash')

        general.add_argument("--scope", dest="scope",
            help='Nishonlarni filtrlash uchun regex')

        general.add_argument("--skip-heuristics", dest="skipHeuristics", action="store_true",
            help="Zaifliklarni evristik aniqlashni o'tkazib yuborish")

        general.add_argument("--skip-waf", dest="skipWaf", action="store_true",
            help="WAF/IPS himoyasini evristik aniqlashni o'tkazib yuborish")

        general.add_argument("--table-prefix", dest="tablePrefix",
            help='Vaqtinchalik jadval prefiksi (standart: "%s")' % defaults.tablePrefix)

        general.add_argument("--test-filter", dest="testFilter",
            help="Payload yoki nom bo'yicha test tanlash (masalan, ROW)")

        general.add_argument("--test-skip", dest="testSkip",
            help="Payload yoki nom bo'yicha testni o'tkazmaslik (masalan, BENCHMARK)")

        general.add_argument("--time-limit", dest="timeLimit", type=float,
            help='Ishlash vaqtini soniyada cheklash (masalan, 3600)')

        general.add_argument("--unsafe-naming", dest="unsafeNaming", action="store_true",
            help='DBMS identifikatorlarini ekranlamaslik (masalan, "user")')

        general.add_argument("--web-root", dest="webRoot",
            help='Veb-server hujjatlar papkasi (masalan, "/var/www")')

        # Non-SQL injection options
        nonsql = parser.add_argument_group("SQL bo'lmagan inyeksiyalar", 'SQLdan boshqa inyeksiya turlarini tekshirish parametrlari')

        nonsql.add_argument("--graphql", dest="graphql", action="store_true",
            help='GraphQL inyeksiyasini tekshirish')

        nonsql.add_argument("--ldap", dest="ldap", action="store_true",
            help='LDAP inyeksiyasini tekshirish')

        nonsql.add_argument("--nosql", dest="nosql", action="store_true",
            help='NoSQL inyeksiyasini tekshirish')

        nonsql.add_argument("--xpath", dest="xpath", action="store_true",
            help='XPath inyeksiyasini tekshirish')

        nonsql.add_argument("--ssti", dest="ssti", action="store_true",
            help='Server shabloniga inyeksiyani tekshirish')

        nonsql.add_argument("--xslt", dest="xslt", action="store_true",
            help='XSLT inyeksiyasini tekshirish')

        nonsql.add_argument("--xxe", dest="xxe", action="store_true",
            help='Tashqi XML obyekti (XXE) inyeksiyasini tekshirish')

        nonsql.add_argument("--hql", dest="hql", action="store_true",
            help='HQL/JPQL (Hibernate ORM) inyeksiyasini tekshirish')

        nonsql.add_argument("--sparql", dest="sparql", action="store_true",
            help='SPARQL inyeksiyasini tekshirish')

        nonsql.add_argument("--odata", dest="odata", action="store_true",
            help='OData $filter inyeksiyasini tekshirish')

        nonsql.add_argument("--jwt", dest="jwt", action="store_true",
            help='JSON Web Token (JWT) zaifliklarini tekshirish')

        nonsql.add_argument("--oob-server", dest="oobServer",
            help="Ko'r '--xxe' uchun tashqi aloqa serveri")

        nonsql.add_argument("--oob-token", dest="oobToken",
            help="O'zingiz joylashtirgan '--oob-server' autentifikatsiya tokeni")

        # Miscellaneous options
        miscellaneous = parser.add_argument_group('Boshqa', "Boshqa bo'limlarga kirmaydigan parametrlar")

        miscellaneous.add_argument("-z", dest="mnemonics",
            help='Qisqartmalarni ishlatish (masalan, "flu,bat,ban,tec=EU")')

        miscellaneous.add_argument("--alert", dest="alert",
            help="SQL-inyeksiya topilganda mahalliy OT buyrug'ini bajarish")

        miscellaneous.add_argument("--beep", dest="beep", action="store_true",
            help='Savol yoki zaiflik topilganda ovoz chiqarish')

        miscellaneous.add_argument("--dependencies", dest="dependencies", action="store_true",
            help="Yetishmayotgan ixtiyoriy sqlmap bog'liqliklarini tekshirish")

        miscellaneous.add_argument("--disable-coloring", dest="disableColoring", action="store_true",
            help="Konsoldagi ranglarni o'chirish")

        miscellaneous.add_argument("--disable-hashing", dest="disableHashing", action="store_true",
            help="Jadval natijalarida xesh tahlilini o'chirish")

        miscellaneous.add_argument("--gui", dest="gui", action="store_true",
            help='Grafik interfeys (Tkinter)')

        miscellaneous.add_argument("--list-tampers", dest="listTampers", action="store_true",
            help="Mavjud tamper skriptlari ro'yxatini ko'rsatish")

        miscellaneous.add_argument("--no-logging", dest="noLogging", action="store_true",
            help="Faylga jurnal yozishni o'chirish")

        miscellaneous.add_argument("--no-truncate", dest="noTruncate", action="store_true",
            help='Konsol matnini qisqartirmaslik (masalan, uzun yo...)')

        miscellaneous.add_argument("--offline", dest="offline", action="store_true",
            help="Internetsiz ishlash (faqat sessiya ma'lumotlari)")

        miscellaneous.add_argument("--purge", dest="purge", action="store_true",
            help="Sqlmap ma'lumot papkasi mazmunini xavfsiz o'chirish")

        miscellaneous.add_argument("--results-file", dest="resultsFile",
            help="Ko'p nishonli rejimdagi CSV natijalar fayli")

        miscellaneous.add_argument("--shell", dest="shell", action="store_true",
            help="Interaktiv sqlmap qobig'ini ochish")

        miscellaneous.add_argument("--tmp-dir", dest="tmpDir",
            help='Vaqtinchalik fayllar uchun mahalliy papka')

        miscellaneous.add_argument("--tui", dest="tui", action="store_true",
            help='Matnli interfeys (ncurses)')

        miscellaneous.add_argument("--unstable", dest="unstable", action="store_true",
            help='Beqaror ulanish uchun sozlamalarni moslash')

        miscellaneous.add_argument("--update", dest="updateAll", action="store_true",
            help='Sqlmapni yangilash')

        miscellaneous.add_argument("--wizard", dest="wizard", action="store_true",
            help='Yangi foydalanuvchilar uchun oddiy sozlash yordamchisi')

        # Hidden and/or experimental options
        parser.add_argument("--crack", dest="hashFile",
            help=SUPPRESS)  # "Load and crack hashes from a file (standalone)"

        parser.add_argument("--dummy", dest="dummy", action="store_true",
            help=SUPPRESS)

        parser.add_argument("--yuge", dest="yuge", action="store_true",
            help=SUPPRESS)

        parser.add_argument("--jitter", dest="jitter", type=int,
            help=SUPPRESS)

        parser.add_argument("--debug", dest="debug", action="store_true",
            help=SUPPRESS)

        parser.add_argument("--deprecations", dest="deprecations", action="store_true",
            help=SUPPRESS)

        parser.add_argument("--disable-multi", dest="disableMulti", action="store_true",
            help=SUPPRESS)

        parser.add_argument("--disable-precon", dest="disablePrecon", action="store_true",
            help=SUPPRESS)

        parser.add_argument("--no-huffman", dest="noHuffman", action="store_true",
            help=SUPPRESS)  # "Disable adaptive (Huffman) set-membership retrieval used by default to speed up blind table dumps"

        parser.add_argument("--profile", dest="profile", action="store_true",
            help=SUPPRESS)

        parser.add_argument("--localhost", dest="localhost", action="store_true",
            help=SUPPRESS)

        parser.add_argument("--force-dbms", dest="forceDbms",
            help=SUPPRESS)

        parser.add_argument("--force-dns", dest="forceDns", action="store_true",
            help=SUPPRESS)

        parser.add_argument("--force-partial", dest="forcePartial", action="store_true",
            help=SUPPRESS)

        parser.add_argument("--force-pivoting", dest="forcePivoting", action="store_true",
            help=SUPPRESS)

        # Experimental: dump table rows via keyset (seek) pagination on a detected indexed
        # primary key instead of ORDER BY ... LIMIT/OFFSET (much cheaper on huge tables).
        # --keyset forces it for any table size; --no-keyset disables it (incl. the automatic
        # use on large tables), falling back to the plain LIMIT/OFFSET dump.
        parser.add_argument("--keyset", dest="keyset", action="store_true",
            help=SUPPRESS)

        parser.add_argument("--no-keyset", dest="noKeyset", action="store_true",
            help=SUPPRESS)

        parser.add_argument("--ignore-stdin", dest="ignoreStdin", action="store_true",
            help=SUPPRESS)

        parser.add_argument("--non-interactive", dest="nonInteractive", action="store_true",
            help=SUPPRESS)

        parser.add_argument("--smoke-test", "--doc-test", dest="smokeTest", action="store_true",
            help=SUPPRESS)

        parser.add_argument("--vuln-test", dest="vulnTest", action="store_true",
            help=SUPPRESS)

        parser.add_argument("--fp-test", dest="fpTest", action="store_true",
            help=SUPPRESS)

        parser.add_argument("--payload-lint", dest="payloadLint", action="store_true",
            help=SUPPRESS)

        parser.add_argument("--api-test", dest="apiTest", action="store_true",
            help=SUPPRESS)

        parser.add_argument("--disable-json", dest="disableJson", action="store_true",
            help=SUPPRESS)

        # API options
        parser.add_argument("--api", dest="api", action="store_true",
            help=SUPPRESS)

        parser.add_argument("--taskid", dest="taskid",
            help=SUPPRESS)

        parser.add_argument("--database", dest="database",
            help=SUPPRESS)

        # Dirty hack to display longer options without breaking into two lines
        if hasattr(parser, "formatter"):
            def _(self, *args):
                retVal = parser.formatter._format_option_strings(*args)
                if len(retVal) > MAX_HELP_OPTION_LENGTH:
                    retVal = ("%%.%ds.." % (MAX_HELP_OPTION_LENGTH - parser.formatter.indent_increment)) % retVal
                return retVal

            parser.formatter._format_option_strings = parser.formatter.format_option_strings
            parser.formatter.format_option_strings = type(parser.formatter.format_option_strings)(_, parser)
        else:
            def _format_action_invocation(self, action):
                retVal = self.__format_action_invocation(action)
                if len(retVal) > MAX_HELP_OPTION_LENGTH:
                    retVal = ("%%.%ds.." % (MAX_HELP_OPTION_LENGTH - self._indent_increment)) % retVal
                return retVal

            parser.formatter_class.__format_action_invocation = parser.formatter_class._format_action_invocation
            parser.formatter_class._format_action_invocation = _format_action_invocation

        # Dirty hack for making a short option '-hh'
        if hasattr(parser, "get_option"):
            option = parser.get_option("--hh")
            option._short_opts = ["-hh"]
            option._long_opts = []
        else:
            for action in get_actions(parser):
                if action.option_strings == ["--hh"]:
                    action.option_strings = ["-hh"]
                    break

        # Dirty hack for inherent help message of switch '-h'
        if hasattr(parser, "get_option"):
            option = parser.get_option("-h")
            option.help = option.help.capitalize().replace("this help", "basic help")
            if "--help" in (getattr(option, "_long_opts", []) or []):
                option.help = "Qisqa yordamni ko'rsatish va chiqish"
        else:
            for action in get_actions(parser):
                if action.option_strings == ["-h", "--help"]:
                    action.help = action.help.capitalize().replace("this help", "basic help")
                    break

        _ = []
        advancedHelp = True
        extraHeaders = []
        auxIndexes = {}

        # Reference: https://stackoverflow.com/a/4012683 (Note: previously used "...sys.getfilesystemencoding() or UNICODE_ENCODING")
        for arg in argv:
            _.append(getUnicode(arg, encoding=sys.stdin.encoding))

        argv = _
        checkOldOptions(argv)

        if "--gui" in argv:
            from lib.utils.gui import runGui

            runGui(parser)

            raise SqlmapSilentQuitException

        elif "--tui" in argv:
            from lib.utils.tui import runTui

            runTui(parser)

            raise SqlmapSilentQuitException

        elif "--shell" in argv:
            _createHomeDirectories()

            parser.usage = ""
            cmdLineOptions.sqlmapShell = True

            commands = set(("x", "q", "exit", "quit", "clear"))
            commands.update(get_all_options(parser))

            autoCompletion(AUTOCOMPLETE_TYPE.SQLMAP, commands=commands)

            while True:
                command = None
                prompt = "sqlmap > "

                try:
                    # Note: in Python2 command should not be converted to Unicode before passing to shlex (Reference: https://bugs.python.org/issue1170)
                    command = _input(prompt).strip()
                except (KeyboardInterrupt, EOFError):
                    print()
                    raise SqlmapShellQuitException

                command = re.sub(r"(?i)\Anew\s+", "", command or "")

                if not command:
                    continue
                elif command.lower() == "clear":
                    clearHistory()
                    dataToStdout('[i] tarix tozalandi\n')
                    saveHistory(AUTOCOMPLETE_TYPE.SQLMAP)
                elif command.lower() in ("x", "q", "exit", "quit"):
                    raise SqlmapShellQuitException
                elif command[0] != '-':
                    if not re.search(r"(?i)\A(\?|help)\Z", command):
                        dataToStdout("[!] noto'g'ri parametrlar berilgan\n")
                    dataToStdout("[i] to'g'ri namuna: '-u http://www.site.com/vuln.php?id=1 --banner'\n")
                else:
                    saveHistory(AUTOCOMPLETE_TYPE.SQLMAP)
                    loadHistory(AUTOCOMPLETE_TYPE.SQLMAP)
                    break

            try:
                for arg in shlex.split(command):
                    argv.append(getUnicode(arg, encoding=sys.stdin.encoding))
            except ValueError as ex:
                raise SqlmapSyntaxException("buyruq qatorini tahlil qilishda muammo ('%s')" % getSafeExString(ex))

        longOptions = set(re.findall(r"\-\-([^= ]+?)=", parser.format_help()))
        longSwitches = set(re.findall(r"\-\-([^= ]+?)\s", parser.format_help()))

        for i in xrange(len(argv)):
            # Reference: https://en.wiktionary.org/wiki/-
            argv[i] = re.sub(u"\\A(\u2010|\u2013|\u2212|\u2014|\u4e00|\u1680|\uFE63|\uFF0D)+", lambda match: '-' * len(match.group(0)), argv[i])

            # Reference: https://unicode-table.com/en/sets/quotation-marks/
            argv[i] = argv[i].strip(u"\u00AB\u2039\u00BB\u203A\u201E\u201C\u201F\u201D\u2019\u275D\u275E\u276E\u276F\u2E42\u301D\u301E\u301F\uFF02\u201A\u2018\u201B\u275B\u275C")

            if argv[i] == "-hh":
                argv[i] = "-h"
            elif i == 1 and re.search(r"\A(http|www\.|\w[\w.-]+\.\w{2,})", argv[i]) is not None:
                argv[i] = "--url=%s" % argv[i]
            elif len(argv[i]) > 1 and all(ord(_) in xrange(0x2018, 0x2020) for _ in ((argv[i].split('=', 1)[-1].strip() or ' ')[0], argv[i][-1])):
                dataToStdout("[!] internetdan konsolga mos bo'lmagan qo'shtirnoqlar ko'chirilgan (%s)\n" % argv[i])
                raise SystemExit
            elif len(argv[i]) > 1 and u"\uff0c" in argv[i].split('=', 1)[-1]:
                dataToStdout("[!] internetdan konsolga mos bo'lmagan vergullar ko'chirilgan (%s)\n" % argv[i])
                raise SystemExit
            elif re.search(r"\A-\w=.+", argv[i]):
                dataToStdout("[!] qisqa parametrda noto'g'ri '=' belgisi aniqlandi ('%s')\n" % argv[i])
                raise SystemExit
            elif re.search(r"\A-\w{3,}", argv[i]):
                if argv[i].strip('-').split('=')[0] in (longOptions | longSwitches):
                    argv[i] = "-%s" % argv[i]
            elif argv[i] in IGNORED_OPTIONS:
                argv[i] = ""
            elif argv[i] in DEPRECATED_OPTIONS:
                argv[i] = ""
            elif argv[i] in ("-s", "--silent"):
                if i + 1 < len(argv) and argv[i + 1].startswith('-') or i + 1 == len(argv):
                    argv[i] = ""
                    conf.verbose = 0
            elif argv[i].startswith("--data-raw"):
                argv[i] = argv[i].replace("--data-raw", "--data", 1)
            elif argv[i].startswith("--auth-creds"):
                argv[i] = argv[i].replace("--auth-creds", "--auth-cred", 1)
            elif argv[i].startswith("--drop-cookie"):
                argv[i] = argv[i].replace("--drop-cookie", "--drop-set-cookie", 1)
            elif re.search(r"\A--tamper[^=\s]", argv[i]):
                argv[i] = ""
            elif re.search(r"\A(--(tamper|ignore-code|skip))(?!-)", argv[i]):
                key = re.search(r"\-?\-(\w+)\b", argv[i]).group(1)
                index = auxIndexes.get(key, None)
                if index is None:
                    index = i if '=' in argv[i] else (i + 1 if i + 1 < len(argv) and not argv[i + 1].startswith('-') else None)
                    auxIndexes[key] = index
                else:
                    delimiter = ','
                    argv[index] = "%s%s%s" % (argv[index], delimiter, argv[i].split('=')[1] if '=' in argv[i] else (argv[i + 1] if i + 1 < len(argv) and not argv[i + 1].startswith('-') else ""))
                    argv[i] = ""
            elif argv[i] in ("-H", "--header") or any(argv[i].startswith("%s=" % _) for _ in ("-H", "--header")):
                if '=' in argv[i]:
                    extraHeaders.append(argv[i].split('=', 1)[1])
                elif i + 1 < len(argv):
                    extraHeaders.append(argv[i + 1])
            elif argv[i] == "--deps":
                argv[i] = "--dependencies"
            elif argv[i] == "--disable-colouring":
                argv[i] = "--disable-coloring"
            elif argv[i] == "-r":
                for j in xrange(i + 2, len(argv)):
                    value = argv[j]
                    if os.path.isfile(value):
                        argv[i + 1] += ",%s" % value
                        argv[j] = ''
                    else:
                        break
            elif re.match(r"\A\d+!\Z", argv[i]) and argv[max(0, i - 1)] == "--threads" or re.match(r"\A--threads.+\d+!\Z", argv[i]):
                argv[i] = argv[i][:-1]
                conf.skipThreadCheck = True
            elif argv[i] == "--version":
                print(VERSION_STRING.split('/')[-1])
                raise SystemExit
            elif argv[i] in ("-h", "--help"):
                advancedHelp = False
                for group in get_groups(parser)[:]:
                    found = False
                    for option in get_actions(group):
                        if option.dest not in BASIC_HELP_ITEMS:
                            option.help = SUPPRESS
                        else:
                            found = True
                    if not found:
                        get_groups(parser).remove(group)
            elif '=' in argv[i] and not argv[i].startswith('-') and argv[i].split('=')[0] in longOptions and re.search(r"\A-{1,2}\w", argv[i - 1]) is None:
                dataToStdout("[!] boshida chiziqchasi yo'q uzun parametr aniqlandi ('%s')\n" % argv[i])
                raise SystemExit

        for verbosity in [_ for _ in argv if re.search(r"\A\-v+\Z", _)]:  # Note: list (not a generator) - the loop mutates argv (del), which would desync a live generator and leave a stray '-v' for argparse to choke on
            try:
                if argv.index(verbosity) == len(argv) - 1 or not argv[argv.index(verbosity) + 1].isdigit():
                    conf.verbose = verbosity.count('v')
                    del argv[argv.index(verbosity)]
            except (IndexError, ValueError):
                pass

        try:
            (args, _) = parser.parse_known_args(argv) if hasattr(parser, "parse_known_args") else parser.parse_args(argv)
        except UnicodeEncodeError as ex:
            dataToStdout("\n[!] %s\n" % getUnicode(ex.object.encode("unicode-escape")))
            raise SystemExit
        except SystemExit:
            if "-h" in argv and not advancedHelp:
                dataToStdout("\n[!] barcha parametrlarni ko'rish uchun '-hh' bilan ishga tushiring\n")
            raise

        if extraHeaders:
            if not args.headers:
                args.headers = ""
            delimiter = "\\n" if "\\n" in args.headers else "\n"
            args.headers += delimiter + delimiter.join(extraHeaders)

        # Expand given mnemonic options (e.g. -z "ign,flu,bat")
        for i in xrange(len(argv) - 1):
            if argv[i] == "-z":
                expandMnemonics(argv[i + 1], parser, args)

        if args.dummy:
            args.url = args.url or DUMMY_URL

        # Note: an explicit target source rules out reading targets from the standard input. Without
        # this, any non-interactive run (CI, cron, subprocess) would turn '-d/-u/-m/-l/-r/-g' into a
        # 'multiple targets' run reading from a pipe, which also resets per-target options in between
        if hasattr(sys.stdin, "fileno") and not any((os.isatty(sys.stdin.fileno()), args.api, args.ignoreStdin, "GITHUB_ACTIONS" in os.environ, args.direct, args.url, args.logFile, args.bulkFile, args.requestFile, args.googleDork, args.configFile, args.openApiFile)):
            args.stdinPipe = iter(sys.stdin.readline, None)
        else:
            args.stdinPipe = None

        if not any((args.direct, args.url, args.logFile, args.bulkFile, args.googleDork, args.configFile, args.requestFile, args.openApiFile, args.updateAll, args.smokeTest, args.vulnTest, args.fpTest, args.payloadLint, args.apiTest, args.wizard, args.dependencies, args.purge, args.listTampers, args.hashFile, args.stdinPipe)):
            errMsg = "majburiy parametr yo'q (-d, -u, -l, -m, -r, -g, -c, --wizard, --shell, --update, --purge, --list-tampers yoki --dependencies). "
            errMsg += 'Qisqa yordam uchun -h, batafsil yordam uchun -hh ishlating\n'
            parser.error(errMsg)

        return args

    except (ArgumentError, TypeError) as ex:
        parser.error(ex)

    except SystemExit:
        # Protection against Windows dummy double clicking
        if IS_WIN and "--non-interactive" not in sys.argv:
            dataToStdout('\nDavom etish uchun Enter bosing...')
            _input()
        raise

    debugMsg = 'buyruq qatori tahlil qilinmoqda'
    logger.debug(debugMsg)
