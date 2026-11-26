"""Oberflaeche: lokaler Server (Token, Host/Origin, CSP), Browserwahl, Ereignisse aus grab.py."""
import contextlib
import http.client
import http.server
import io
import json
from pathlib import Path
import sys
import tempfile
import threading
import unittest
import unittest.mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import grab as g
import ui

CONFIG_PATH = Path(g.__file__).with_name('config.default.toml')


class ServerCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        config = g.load_config(CONFIG_PATH)
        config['storage'] = self.tmp.name
        self.state = ui.State(config, CONFIG_PATH)
        # Keine echten grab.py-Prozesse (Netz) in Servertests: Vorgaenge nur vormerken.
        self.started = []
        self.state.start_worker = lambda mode: self.started.append(mode) or True
        self.token = 'testtoken-1234567890'
        port = [0]
        self.server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), ui.make_handler(self.state, self.token, port))
        port[0] = self.port = self.server.server_address[1]
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)

    def request(self, method, path, body=None, headers=None, token=True, host=None):
        conn = http.client.HTTPConnection('127.0.0.1', self.port, timeout=5)
        h = {'Host': host or f'127.0.0.1:{self.port}'}
        if token:
            h['X-QSGrab-Token'] = self.token
        data = None
        if body is not None:
            data = json.dumps(body).encode()
            h['Content-Type'] = 'application/json'
        h.update(headers or {})
        conn.request(method, path, body=data, headers=h)
        r = conn.getresponse()
        raw = r.read()
        conn.close()
        try:
            payload = json.loads(raw)
        except ValueError:
            payload = raw
        return r.status, dict(r.getheaders()), payload


class TestServerSecurity(ServerCase):
    def test_page_served_with_strict_headers(self):
        status, headers, body = self.request('GET', '/', token=False)
        self.assertEqual(status, 200)
        self.assertIn(b'Quite Safe Grab', body)
        csp = headers['Content-Security-Policy']
        for part in ("default-src 'none'", "script-src 'self'", "connect-src 'self'", "frame-ancestors 'none'"):
            self.assertIn(part, csp)
        self.assertEqual(headers['X-Content-Type-Options'], 'nosniff')
        # no-referrer wuerde Firefox/Mullvad bei POST "Origin: null" schicken lassen -> Knoepfe tot
        self.assertEqual(headers['Referrer-Policy'], 'same-origin')
        self.assertIn(b'<meta name="referrer" content="same-origin">', body)
        self.assertEqual(headers['Cache-Control'], 'no-store')

    def test_origin_null_is_refused(self):
        status = self.request('POST', '/api/queue/add', {'urls': ['https://a.example/x.mp4']}, headers={'Origin': 'null'})[0]
        self.assertEqual(status, 403)

    def test_page_has_no_external_resources(self):
        root = Path(ui.__file__).with_name('ui')
        for name in ('index.html', 'app.css', 'app.js'):
            text = (root / name).read_text(encoding='utf-8')
            self.assertNotRegex(text, r'(src|href)\s*=\s*["\']https?://', name)
            self.assertNotIn('@import', text, name)
            self.assertNotIn('innerHTML', text, name)

    def test_api_requires_token(self):
        self.assertEqual(self.request('GET', '/api/state', token=False)[0], 401)
        self.assertEqual(self.request('GET', '/api/state', headers={'X-QSGrab-Token': 'falsch'}, token=False)[0], 401)
        self.assertEqual(self.request('POST', '/api/queue/add', {'urls': ['https://a.example/x.mp4']}, token=False)[0], 403)
        self.assertEqual(self.request('GET', '/api/state')[0], 200)

    def test_foreign_host_and_origin_refused(self):
        # DNS-Rebinding: fremder Host-Kopf
        self.assertEqual(self.request('GET', '/api/state', host='evil.example')[0], 403)
        self.assertEqual(self.request('GET', '/', token=False, host=f'localhost:{self.port}')[0], 403)
        # Fremde Webseite: Origin passt nicht
        status = self.request('POST', '/api/queue/add', {'urls': ['https://a.example/x.mp4']},
                              headers={'Origin': 'https://evil.example'})[0]
        self.assertEqual(status, 403)
        self.assertEqual(self.state.queue, [])

    def test_post_requires_json_and_limits_size(self):
        conn = http.client.HTTPConnection('127.0.0.1', self.port, timeout=5)
        conn.request('POST', '/api/queue/add', body=b'urls=x', headers={
            'Host': f'127.0.0.1:{self.port}', 'X-QSGrab-Token': self.token, 'Content-Type': 'application/x-www-form-urlencoded'})
        self.assertEqual(conn.getresponse().status, 415)
        conn.close()
        status = self.request('POST', '/api/queue/add', {'urls': ['https://a.example/' + 'x' * 70000]})[0]
        self.assertEqual(status, 413)

    def test_unknown_paths(self):
        self.assertEqual(self.request('GET', '/../config.toml', token=False)[0], 404)
        self.assertEqual(self.request('GET', '/ui.py', token=False)[0], 404)
        self.assertEqual(self.request('POST', '/api/does-not-exist', {})[0], 404)


class TestQueueApi(ServerCase):
    def test_add_valid_and_invalid_links(self):
        status, _, body = self.request('POST', '/api/queue/add', {'urls': ['https://a.example/x.mp4', 'ftp://nope', 'kein link', '']})
        self.assertEqual(status, 200)
        self.assertEqual(body['added'], 1)
        self.assertEqual(len(body['invalid']), 2)
        st = self.request('GET', '/api/state')[2]
        self.assertEqual([q['status'] for q in st['queue']], ['waiting'])

    def test_name_rules(self):
        self.assertEqual(self.request('POST', '/api/queue/add', {'urls': ['https://a.example/1', 'https://a.example/2'], 'name': 'x'})[0], 400)
        self.assertEqual(self.request('POST', '/api/queue/add', {'urls': ['https://a.example/1'], 'name': '..\\boese'})[0], 400)
        self.assertEqual(self.request('POST', '/api/queue/add', {'urls': ['https://a.example/1'], 'name': 'Mein Film'})[0], 200)
        self.assertEqual(self.state.queue[0]['name'], 'Mein Film')

    def test_remove_and_clear(self):
        self.request('POST', '/api/queue/add', {'urls': ['https://a.example/1', 'https://a.example/2']})
        first = self.state.queue[0]['id']
        self.state.queue[1]['status'] = 'done'
        self.request('POST', '/api/queue/remove', {'id': first})
        self.assertEqual(len(self.state.queue), 1)
        self.request('POST', '/api/queue/clear', {})
        self.assertEqual(self.state.queue, [])

    def test_start_needs_waiting_items(self):
        status, _, body = self.request('POST', '/api/start', {})
        self.assertEqual(status, 400)
        self.assertIn('Keine wartenden', body['error'])

    def test_adding_links_starts_title_search(self):
        self.request('POST', '/api/queue/add', {'urls': ['https://a.example/1', 'https://a.example/2']})
        self.assertEqual(self.started, ['preview'])
        self.assertEqual([q['title_state'] for q in self.state.queue], ['pending', 'pending'])

    def test_start_during_title_search_is_deferred(self):
        self.request('POST', '/api/queue/add', {'urls': ['https://a.example/1']})
        self.state.worker, self.state.mode = object(), 'preview'   # Titelsuche laeuft
        status, _, body = self.request('POST', '/api/start', {})
        self.assertEqual((status, body.get('deferred')), (200, True))
        self.assertTrue(self.state.start_after_preview)
        self.state.mode = 'download'
        self.assertEqual(self.request('POST', '/api/start', {})[0], 400)

    def test_retry_searches_title_again(self):
        self.request('POST', '/api/queue/add', {'urls': ['https://a.example/1']})
        item = self.state.queue[0]
        item.update(status='failed', title_state='failed', error={'ident': 'X', 'message': 'x'})
        self.started.clear()
        self.request('POST', '/api/queue/retry', {'id': item['id']})
        self.assertEqual((item['status'], item['title_state']), ('waiting', 'pending'))
        self.assertEqual(self.started, ['preview'])

    def test_links_are_not_written_to_disk(self):
        self.request('POST', '/api/queue/add', {'urls': ['https://geheim.example/video.mp4']})
        self.state.set_check('vpn', True, 'ProTUN')
        self.state.save_checks()
        for p in Path(self.tmp.name).rglob('*'):
            if p.is_file():
                self.assertNotIn('geheim.example', p.read_text(encoding='utf-8', errors='replace'))


class TestEvents(unittest.TestCase):
    def test_emit_only_with_flag_and_strips_urls(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            g.emit('title', name='x')
        self.assertEqual(out.getvalue(), '')
        old = g.EVENTS
        g.EVENTS = True
        self.addCleanup(setattr, g, 'EVENTS', old)
        with contextlib.redirect_stdout(out):
            g.emit('error', ident='X', message='kaputt bei https://signed.example/abc?token=1')
        line = out.getvalue().strip()
        self.assertTrue(line.startswith(g.EVENT_PREFIX))
        ev = json.loads(line[len(g.EVENT_PREFIX):])
        self.assertEqual(ev['type'], 'error')
        self.assertNotIn('signed.example', ev['message'])

    def test_error_event_names_affected_check(self):
        old = g.EVENTS
        g.EVENTS = True
        self.addCleanup(setattr, g, 'EVENTS', old)
        out = io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
            g.error(g.Failure(2, 'DNS_GEO_FAILED', 'x'))
            g.error(g.Failure(4, 'LINK_RESOLUTION_FAILED', 'y'))
        evs = [json.loads(l[len(g.EVENT_PREFIX):]) for l in out.getvalue().splitlines()]
        self.assertEqual([e['check'] for e in evs], ['dns', None])
        self.assertTrue(set(g.ERROR_CHECK.values()) <= set(g.CHECK_KEYS))

    def test_progress_lines(self):
        old = g.EVENTS
        g.EVENTS = True
        self.addCleanup(setattr, g, 'EVENTS', old)
        cases = {
            '[download]  37.0% of    2.72MiB at    5.33MiB/s ETA 00:01': (37.0, '2.72MiB', '5.33MiB/s', '00:01'),
            '[download] 100% of    2.72MiB in 00:00:01 at 1.74MiB/s': (100.0, '2.72MiB', '1.74MiB/s', None),
            '[download]   0.0% of ~  101.10MiB at  Unknown B/s ETA Unknown': (0.0, '101.10MiB', None, None),
        }
        for line, (pct, total, speed, eta) in cases.items():
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                g.progress_event(line + '\n')
            ev = json.loads(out.getvalue().strip()[len(g.EVENT_PREFIX):])
            self.assertEqual((ev['percent'], ev['total'], ev['speed'], ev['eta']), (pct, total, speed, eta), line)
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            g.progress_event('[download] Destination: C:\\x\\raw.mp4')
            g.progress_event('[info] irgendwas')
        self.assertEqual(out.getvalue(), '')

    def test_state_handles_events(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        config = g.load_config(CONFIG_PATH)
        config['storage'] = tmp.name
        s = ui.State(config, CONFIG_PATH)
        s.current = {'id': 'a'}
        s.handle_event({'type': 'check', 'key': 'ipv4', 'ok': True, 'detail': '1.2.3.4 · CH · M247'})
        s.handle_event({'type': 'phase', 'phase': 'download'})
        s.handle_event({'type': 'progress', 'phase': 'download', 'percent': 12.5, 'speed': '2MiB/s', 'eta': '00:10', 'total': '100MiB'})
        s.handle_event({'type': 'title', 'name': 'Big_Buck_Bunny'})
        s.handle_event({'type': 'error', 'ident': 'DNS_GEO_FAILED', 'code': 2, 'message': 'Keine Geodaten', 'check': 'dns'})
        self.assertTrue(s.checks['ipv4']['ok'])
        self.assertFalse(s.checks['dns']['ok'])
        self.assertEqual((s.current['percent'], s.current['title']), (12.5, 'Big_Buck_Bunny'))
        self.assertEqual(s.current['error']['ident'], 'DNS_GEO_FAILED')
        snap = s.snapshot()
        self.assertEqual(snap['overall'], 'bad')
        # Ergebnisse ueberleben einen Neustart, gelten dann aber als "alt"
        s.save_checks()
        again = ui.State(config, CONFIG_PATH)
        self.assertTrue(again.checks['ipv4']['ok'])
        self.assertTrue(again.checks['ipv4']['stale'])
        self.assertEqual(again.snapshot()['overall'], 'bad')


class TestTitleSearch(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        config = g.load_config(CONFIG_PATH)
        config['storage'] = self.tmp.name
        self.config = config

    def test_state_maps_preview_events_to_items(self):
        s = ui.State(self.config, CONFIG_PATH)
        a = {'id': 'a', 'url': 'https://a.example/1', 'status': 'waiting', 'title': None, 'title_state': 'queued'}
        b = {'id': 'b', 'url': 'https://a.example/2', 'status': 'waiting', 'title': None, 'title_state': 'queued'}
        s.queue, s.preview_batch, s.current = [a, b], [a, b], {'id': 'preview'}
        s.handle_event({'type': 'preview_start', 'index': 0})
        self.assertEqual(a['title_state'], 'running')
        self.assertIn('1 von 2', s.current['title'])
        s.handle_event({'type': 'preview', 'index': 0, 'ok': True, 'name': 'Big_Buck_Bunny'})
        s.handle_event({'type': 'preview', 'index': 1, 'ok': False, 'ident': 'VOE_RESOLUTION_FAILED', 'code': 4,
                        'message': 'weg bei https://x.example/geheim'})
        s.handle_event({'type': 'preview', 'index': 7, 'ok': True, 'name': 'ignoriert'})
        self.assertEqual((a['title'], a['title_state'], a['status']), ('Big_Buck_Bunny', 'ok', 'waiting'))
        self.assertEqual((b['title_state'], b['status']), ('failed', 'failed'))
        self.assertNotIn('x.example', b['error']['message'])

    def test_grab_preview_reports_each_link(self):
        urls = ['https://ok.example/v.mp4', 'https://kaputt.example/x']
        def resolve(url, manual, *a):
            if 'kaputt' in url:
                g.fail(4, 'LINK_RESOLUTION_FAILED', 'Link nicht aufloesbar')
            return {'name': 'Mein_Video', 'voe': False, 'info': {}, 'media': None, 'referer': url}
        net = g.Network(self.config, None)
        checks = []
        net.check = lambda label, expected=None: checks.append(label) or '1.1.1.1'
        store = g.Store(self.tmp.name)
        old = g.EVENTS
        g.EVENTS = True
        self.addCleanup(setattr, g, 'EVENTS', old)
        out = io.StringIO()
        with unittest.mock.patch.object(g, 'resolve_item', resolve), contextlib.redirect_stdout(out):
            self.assertEqual(g.preview(self.config, None, net, store, urls), 0)
        events = [json.loads(l[len(g.EVENT_PREFIX):]) for l in out.getvalue().splitlines() if l.startswith(g.EVENT_PREFIX)]
        results = [e for e in events if e['type'] == 'preview']
        self.assertEqual([(e['index'], e['ok']) for e in results], [(0, True), (1, False)])
        self.assertEqual(results[0]['name'], 'Mein_Video')
        # Pruefpunkt vorher, vor jedem Eintrag und danach - wie die interaktive Vorschau
        self.assertEqual(checks, ['IPv4 vor Vorschau', 'IPv4 vor Vorschau-Eintrag', 'IPv4 vor Vorschau-Eintrag', 'IPv4 nach Vorschau'])

    def test_grab_preview_stops_on_security_abort(self):
        net = g.Network(self.config, None)
        calls = []
        def check(label, expected=None):
            calls.append(label)
            if label == 'IPv4 vor Vorschau-Eintrag':
                g.fail(2, 'EXIT_IP_CHANGED', 'Exit-IP geaendert')
            return '1.1.1.1'
        net.check = check
        with self.assertRaises(g.Failure) as caught, contextlib.redirect_stdout(io.StringIO()):
            g.preview(self.config, None, net, g.Store(self.tmp.name), ['https://a.example/1', 'https://a.example/2'])
        self.assertEqual(caught.exception.code, 2)
        self.assertEqual(calls, ['IPv4 vor Vorschau', 'IPv4 vor Vorschau-Eintrag'])

    def test_read_preview_urls(self):
        self.assertEqual(g.read_preview_urls(io.StringIO('https://a.example/1\n\n https://a.example/2 \n')),
                         ['https://a.example/1', 'https://a.example/2'])
        for bad in ('', 'ftp://x\n', '\n'.join(['https://a.example/x'] * 51)):
            with self.assertRaises(g.Failure):
                g.read_preview_urls(io.StringIO(bad))


class TestOverallAndProfile(unittest.TestCase):
    def test_old_good_results_are_stale_not_good(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        config = g.load_config(CONFIG_PATH)
        config['storage'] = tmp.name
        s = ui.State(config, CONFIG_PATH)
        for k in ui.CHECK_KEYS:
            s.set_check(k, True, 'ok')
        self.assertEqual(s.snapshot()['overall'], 'good')
        s.save_checks()
        again = ui.State(config, CONFIG_PATH)
        snap = again.snapshot()
        self.assertEqual(snap['overall'], 'stale')
        self.assertIsInstance(snap['tz_offset'], int)

    def test_profile_detection(self):
        self.assertEqual(ui.profile_of(['mb.exe', '-no-remote', '-profile', 'C:/p/mullvad', 'u'])[0], 'mullvad')
        kind, path = ui.profile_of(['edge.exe', '--user-data-dir=C:/p/edge', '--app=u'])
        self.assertEqual((kind, path), ('edge', Path('C:/p/edge')))
        with tempfile.TemporaryDirectory() as d:
            p = Path(d)
            self.assertFalse(ui.profile_in_use('mullvad', p))          # keine Sperrdatei
            (p / 'parent.lock').write_bytes(b'')
            self.assertFalse(ui.profile_in_use('mullvad', p))          # Datei da, aber frei
            if sys.platform == 'win32':
                import ctypes   # exklusiv offen halten wie der Browser
                k32 = ctypes.WinDLL('kernel32', use_last_error=True)
                k32.CreateFileW.restype = ctypes.c_void_p
                handle = k32.CreateFileW(str(p / 'parent.lock'), 0xC0000000, 0, None, 3, 0x80, None)
                try:
                    self.assertTrue(ui.profile_in_use('mullvad', p))
                finally:
                    k32.CloseHandle(ctypes.c_void_p(handle))
                self.assertFalse(ui.profile_in_use('mullvad', p))


class TestBrowserChoice(unittest.TestCase):
    URL = 'http://127.0.0.1:1/#t=x'
    ROOT = Path('C:/Quite Safe Grab/.ui-profile')

    def test_auto_prefers_mullvad(self):
        name, cmd = ui.browser_command('auto', self.URL, self.ROOT, (lambda: 'mb.exe', lambda: 'edge.exe'))
        self.assertEqual(name, 'Mullvad Browser')
        self.assertEqual(cmd[:2], ['mb.exe', '-no-remote'])
        self.assertIn(str(self.ROOT / 'mullvad'), cmd)
        self.assertEqual(cmd[-1], self.URL)

    def test_auto_falls_back_to_edge_with_own_profile(self):
        name, cmd = ui.browser_command('auto', self.URL, self.ROOT, (lambda: None, lambda: 'edge.exe'))
        self.assertTrue(name.startswith('Microsoft Edge'))
        self.assertIn(f'--user-data-dir={self.ROOT / "edge"}', cmd)
        self.assertIn(f'--app={self.URL}', cmd)
        self.assertIn('--disable-sync', cmd)

    def test_strict_mullvad_refuses_without_it(self):
        name, hint = ui.browser_command('mullvad', self.URL, self.ROOT, (lambda: None, lambda: 'edge.exe'))
        self.assertIsNone(name)
        self.assertIn('mullvad.net/browser', hint)

    def test_edge_choice_ignores_mullvad(self):
        name, cmd = ui.browser_command('edge', self.URL, self.ROOT, (lambda: 'mb.exe', lambda: 'edge.exe'))
        self.assertEqual(cmd[0], 'edge.exe')

    def test_config_option(self):
        text = CONFIG_PATH.read_text(encoding='utf-8')
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / 'c.toml'
            p.write_text(text.replace('ui_browser = "auto"', 'ui_browser = "firefox"'), encoding='utf-8')
            with self.assertRaises(g.Failure):
                g.load_config(p)
            # Aeltere config.toml ohne den Eintrag bleibt gueltig
            p.write_text(text.replace('ui_browser = "auto"', ''), encoding='utf-8')
            self.assertEqual(g.load_config(p)['ui_browser'], 'auto')


if __name__ == '__main__':
    unittest.main()
