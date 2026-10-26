#!/usr/bin/env python
"""Uzbek prompt compatibility and CLI rendering regressions (offline)."""
import os
import sys
import subprocess
import unittest
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _testutils import bootstrap
bootstrap()
from lib.core.uzbek import ut
from lib.core.common import readInput
from lib.core.data import conf, kb

class UzbekPromptTests(unittest.TestCase):
    def setUp(self):
        self.saved = dict((k, conf.get(k)) for k in ('answers','batch'))
        conf.batch = True
        conf.answers = None

    def tearDown(self):
        for key, val in self.saved.items():
            conf[key] = val

    def test_english_answer_matches_translated_prompt(self):
        conf.answers = 'follow=N'
        prompt = ut("got a %d redirect to ", "%d yo'naltirish olindi: ") % 302
        prompt += ut("'%s'. Do you want to follow? [Y/n] ", "'%s'. O'tasizmi? [Y/n] ") % 'http://localhost/next'
        self.assertFalse(readInput(prompt, default='Y', boolean=True))

    def test_english_answer_after_stripping(self):
        conf.answers = 'quit=Y'
        prompt = ut('do you want to quit? [y/N]\n', 'chiqasizmi? [y/N]\n').rstrip('\n')
        self.assertTrue(readInput(prompt, default='N', boolean=True))

    def test_uzbek_answer_key_is_also_accepted(self):
        conf.answers = 'chiqasizmi=Y'
        self.assertTrue(readInput(ut('quit? [y/N]', 'chiqasizmi? [y/N]'), default='N', boolean=True))

    def test_default_letters_still_work(self):
        self.assertTrue(readInput(ut('continue? [Y/n]', 'davom etasizmi? [Y/n]'), default='Y', boolean=True))
        self.assertFalse(readInput(ut('continue? [y/N]', 'davom etasizmi? [y/N]'), default='N', boolean=True))

    def test_dynamic_values_stay_verbatim(self):
        value = "SELECT 'user aborted', '%s', '--dbs'"
        prompt = ut('query: %s', "so'rov: %s") % value
        self.assertEqual(str(prompt), "so'rov: " + value)
        self.assertEqual(prompt.english, 'query: ' + value)

    def test_string_prefix_keeps_answer_metadata(self):
        prompt = '\n' + ut('continue? ', 'davom etasizmi? ')
        conf.answers = 'continue=N'
        self.assertFalse(readInput(prompt, default='Y', boolean=True))

    def test_cli_help_is_uzbek(self):
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        out = subprocess.check_output([sys.executable, os.path.join(root, 'sqlmap.py'), '-hh']).decode('utf-8')
        self.assertIn('Batafsil yordam', out)
        self.assertIn('--current-user', out)
        self.assertIn('--dbs', out)
        self.assertNotIn('Retrieve DBMS', out)

if __name__ == '__main__':
    unittest.main()
