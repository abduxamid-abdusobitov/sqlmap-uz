#!/usr/bin/env python
"""Uzbek presentation helpers; flags, response data and prompt choices stay intact."""
try:
    _text = unicode
except NameError:
    _text = str

def _original(value):
    if isinstance(value, tuple):
        return tuple(_original(item) for item in value)
    if isinstance(value, dict):
        return dict((key, _original(item)) for key, item in value.items())
    return getattr(value, 'english', value)

class UzbekText(_text):
    def __new__(cls, english, translated):
        obj = _text.__new__(cls, translated)
        obj.english = english
        return obj

    def __add__(self, other):
        return UzbekText(self.english + _original(other), _text.__add__(self, other))

    def __radd__(self, other):
        # Python 2 unicode.__add__ requires a unicode receiver even for ASCII str prefixes.
        return UzbekText(_original(other) + self.english, _text.__add__(_text(other), self))

    def __mod__(self, values):
        return UzbekText(self.english % _original(values), _text.__mod__(self, values))

    def rstrip(self, chars=None):
        return UzbekText(self.english.rstrip(chars), _text.rstrip(self, chars))

    def strip(self, chars=None):
        return UzbekText(self.english.strip(chars), _text.strip(self, chars))

    def replace(self, old, new, count=-1):
        return UzbekText(self.english.replace(_original(old), _original(new), count), _text.replace(self, old, new, count))

ut = UzbekText

_PARSER_TEXT = {'Usage: %s\n': 'Ishlatish: %s\n', 'Usage': 'Ishlatish', 'usage: ': 'ishlatish: ', 'options': 'parametrlar', 'Options': 'Parametrlar', 'show this help message and exit': "yordamni ko'rsatish va chiqish", 'Show basic help message and exit': "Qisqa yordamni ko'rsatish va chiqish", 'no such option: %s': "bunday parametr yo'q: %s", 'ambiguous option: %s (%s?)': 'noaniq parametr: %s (%s?)', 'option %s: invalid %s value: %r': "%s parametri: %s qiymati noto'g'ri: %r", 'option %s requires an argument': '%s parametri uchun argument kerak', 'option %s requires %d arguments': '%s parametri uchun %d ta argument kerak', 'option %s: invalid choice: %r (choose from %s)': "%s parametri: noto'g'ri tanlov %r (tanlang: %s)", 'error: %s': 'xato: %s', '%s: error: %s\n': '%s: xato: %s\n', 'option %s must not have an argument': '%s parametriga argument berilmaydi', 'option %s: invalid integer value: %r': "%s parametri: noto'g'ri butun son: %r"}

def parser_text(message):
    return _PARSER_TEXT.get(message, message).replace("[options]", "[parametrlar]")

def install_parser_translation():
    import optparse
    optparse._ = parser_text
    try:
        import argparse
        argparse._ = parser_text
    except ImportError:
        pass
