#!/usr/bin/env python
"""Offline regression checks for the fork updater (no network or file deletion)."""
import os
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _testutils import bootstrap
bootstrap()

from lib.core.data import conf, paths
import lib.core.update as updater


class UzbekUpdateTests(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp(prefix='sqlmap-uz-update-')
        self.saved = (paths.SQLMAP_ROOT_PATH, conf.get('updateAll'), updater._git)
        paths.SQLMAP_ROOT_PATH = self.root
        conf.updateAll = True
        self.calls = []
        self.results = [(0, ''), (0, 'Already up to date.')]
        updater._git = self.fake_git

    def tearDown(self):
        paths.SQLMAP_ROOT_PATH, conf.updateAll, updater._git = self.saved
        shutil.rmtree(self.root)

    def fake_git(self, *args):
        self.calls.append(args)
        return self.results.pop(0)

    def git_checkout(self):
        os.mkdir(os.path.join(self.root, '.git'))

    def test_disabled_update_does_nothing(self):
        conf.updateAll = False
        updater.update()
        self.assertEqual(self.calls, [])

    def test_zip_installation_keeps_existing_files(self):
        filename = os.path.join(self.root, 'sqlmap.py')
        with open(filename, 'w') as handle:
            handle.write('local translation')
        updater.update()
        self.assertEqual(self.calls, [])
        with open(filename) as handle:
            self.assertEqual(handle.read(), 'local translation')

    def test_dirty_checkout_does_not_pull_or_reset(self):
        self.git_checkout()
        self.results = [(0, ' M lib/core/common.py\n')]
        updater.update()
        self.assertEqual(self.calls, [('status', '--porcelain', '--untracked-files=no')])

    def test_clean_checkout_uses_uzbek_main_and_fast_forward_only(self):
        self.git_checkout()
        updater.update()
        self.assertEqual(self.calls[-1], ('pull', '--ff-only',
            'https://github.com/abduxamid-abdusobitov/sqlmap-uz.git', 'main'))
        self.assertEqual(len(self.calls), 2)

    def test_worktree_git_file_is_accepted(self):
        with open(os.path.join(self.root, '.git'), 'w') as handle:
            handle.write('gitdir: /unused/worktree')
        updater.update()
        self.assertEqual(self.calls[-1][0], 'pull')

    def test_git_status_failure_stops_update(self):
        self.git_checkout()
        self.results = [(128, 'not a git repository')]
        updater.update()
        self.assertEqual(len(self.calls), 1)

    def test_diverged_history_is_not_retried_with_reset_or_merge(self):
        self.git_checkout()
        self.results = [(0, ''), (128, 'Not possible to fast-forward, aborting.')]
        updater.update()
        self.assertEqual(len(self.calls), 2)
        self.assertEqual(self.calls[-1][1], '--ff-only')

    def test_missing_git_does_not_crash(self):
        self.git_checkout()
        def missing_git(*args):
            raise OSError('git not found')
        updater._git = missing_git
        updater.update()


if __name__ == '__main__':
    unittest.main()
