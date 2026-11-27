"""Absicherung des Umbaus G/H: gemeinsame Quellen (common, winguard) und unveraenderte Fehlerwege von fw.py."""
import contextlib
import io
import subprocess
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import common
import fw
import grab as g
import winguard

CONFIG = g.load_config(Path(g.__file__).with_name('config.default.toml'))


class TestSharedSources(unittest.TestCase):
    def test_grab_reexports_common(self):
        for name in ('Failure', 'fail', 'safe_text', 'EVENT_PREFIX', 'CHECK_KEYS', 'ERROR_CHECK', 'check_key',
                     'HOST_RE', 'REDIRECT_HOSTS_ENV', 'UI_BROWSERS'):
            self.assertIs(getattr(g, name), getattr(common, name), name)
        self.assertEqual((common.EXIT_USER, common.EXIT_SAFETY, common.EXIT_RESOLVE, common.EXIT_MEDIA), (1, 2, 4, 5))

    def test_paths_from_winguard(self):
        self.assertEqual((g.POWERSHELL, g.CURL, g.NSLOOKUP, g.SYSTEM32),
                         (winguard.POWERSHELL, winguard.CURL, winguard.NSLOOKUP, winguard.SYSTEM32))
        self.assertEqual(g.guard_programs()[-2:], [winguard.CURL, winguard.NSLOOKUP])

    def test_selftest_codes_match_code_text(self):
        self.assertIn('SAFE = ' + repr(winguard.SELFTEST_CODES) + '\n', winguard.SELFTEST_CODE)
        self.assertEqual(set(winguard.SELFTEST_SAFE), set(winguard.SELFTEST_CODES.values()))

    def test_quick_script_is_adapter_block_of_full_script(self):
        prefix = winguard.STATE_SCRIPT.split('$rules = @()')[0]
        self.assertTrue(winguard.QUICK_STATE_SCRIPT.startswith(prefix))
        self.assertIn(f"-Name '{winguard.RULE_PREFIX}*'", winguard.STATE_SCRIPT)


class TestSession(unittest.TestCase):
    def test_session_is_the_only_state_and_patch_restores(self):
        """Der Prozesszustand liegt nur in g.SESSION (keine alten Modulnamen); eine eingesetzte Session gilt
        fuer emit/phase und wird von patch.object wiederhergestellt."""
        for name in ('EVENTS', '_phase', '_guard_warned', '_selftest_done', '_rules_ok', '_redirect_hosts'):
            self.assertFalse(hasattr(g, name), name)
        before = g.SESSION
        fresh = g.Session()
        self.assertEqual((fresh.events, fresh.phase, fresh.warned, fresh.selftest_done, fresh.rules_ok, fresh.redirect_hosts),
                         (False, 'start', set(), set(), set(), set()))
        fresh.events = True
        out = io.StringIO()
        with patch.object(g, 'SESSION', fresh), contextlib.redirect_stdout(out):
            g.phase('download')
            g.emit('title', name='x')
        self.assertEqual(fresh.phase, 'download')
        self.assertTrue(out.getvalue().startswith(common.EVENT_PREFIX))
        self.assertIs(g.SESSION, before)


class TestItem(unittest.TestCase):
    def test_media_host_check_survives_released_info(self):
        """Die Hostpruefung haengt nicht mehr davon ab, dass sie vor dem Freigeben der Infodaten laeuft."""
        def public(host):
            if host == '127.0.0.1':
                raise ValueError('privat')
        item = g.Item(name='x', referer='https://site.example/',
                      info={'url': 'https://cdn.example/a.mp4', 'formats': [{'url': 'https://127.0.0.1/b.mp4'}]})
        item.info = None   # wie transfer vor dem langen Transfer
        with patch.object(g, 'public_host', public), self.assertRaises(g.Failure) as caught:
            g.check_media_hosts(item)
        self.assertEqual(caught.exception.ident, 'MEDIA_HOST_PRIVATE')
        self.assertNotIn('cdn.example', repr(item))   # signierte Adressen nicht in repr

    def test_broken_format_list_fails_at_host_check_not_at_resolve(self):
        """Wie vor dem Umbau: unbrauchbare Formatliste stoert Vorschau/Groessen nicht, stoppt aber vor dem Transfer."""
        item = g.Item(name='x', referer='https://site.example/', info={'url': 'https://cdn.example/a.mp4', 'requested_formats': {'a': 1}})
        with self.assertRaises(TypeError):
            g.check_media_hosts(item)

    def test_only_hosts_kept_after_info_release(self):
        item = g.Item(name='x', referer='https://site.example/', info={'url': 'https://cdn.example/a.mp4?token=geheim'})
        item.info = None
        self.assertEqual(item.media_hosts, {'cdn.example'})
        self.assertNotIn('geheim', repr(vars(item)))


class TestFwQuery(unittest.TestCase):
    def test_subprocess_flags_and_timeout(self):
        seen = {}

        def fake_run(argv, **kw):
            seen.update(argv=argv, **kw)
            return subprocess.CompletedProcess(argv, 0, b'{"Adapters": [], "Rules": [], "Profiles": [], "RulesError": ""}', b'')

        with patch.object(fw.subprocess, 'run', fake_run):
            fw.query(CONFIG)
        self.assertEqual(seen['argv'][0], winguard.POWERSHELL)
        self.assertEqual(seen['creationflags'], 0x08000000)
        self.assertEqual(seen['timeout'], 60)
        self.assertIs(seen['stdin'], subprocess.DEVNULL)

    def test_error_paths_unchanged(self):
        with patch.object(fw, 'run', return_value=(1, '', 'Zugriff https://x.example/a verweigert\n')):
            with self.assertRaises(SystemExit) as caught:
                fw.query(CONFIG)
        self.assertEqual(str(caught.exception), 'Abfrage fehlgeschlagen: Zugriff [URL entfernt] verweigert')
        with patch.object(fw, 'run', return_value=(0, 'kein json', '')):
            with self.assertRaises(SystemExit) as caught:
                fw.query(CONFIG)
        self.assertEqual(str(caught.exception), 'Keine auswertbare Firewall-/Adapterabfrage')


if __name__ == '__main__':
    unittest.main()
