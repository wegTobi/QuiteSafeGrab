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
sys.path.insert(0, str(Path(__file__).resolve().parent))
import grab as g
import ui
from helpers import RecordingNet, capture_events, make_state, write_config

CONFIG_PATH = Path(g.__file__).with_name('config.default.toml')


class ServerCase(unittest.TestCase):
    def setUp(self):
        self.state = make_state(self)
        # Keine echten grab.py-Prozesse (Netz) in Servertests: Vorgaenge nur vormerken.
        self.started = []
        self.state.start_worker = lambda mode: self.started.append(mode) or True
        self.state.start_sizes = lambda: self.started.append('sizes') or True
        self.token = 'testtoken-1234567890'
        self.server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), ui.make_handler(self.state, self.token))
        self.port = self.server.server_address[1]
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

    def test_remove_single_items(self):
        self.request('POST', '/api/queue/add', {'urls': ['https://a.example/1', 'https://a.example/2', 'https://a.example/3']})
        first, second, third = [x['id'] for x in self.state.queue]
        self.state.queue[1]['status'] = 'done'
        self.state.queue[2]['status'] = 'running'
        self.request('POST', '/api/queue/remove', {'id': first})
        self.assertEqual([x['id'] for x in self.state.queue], [second, third])
        self.request('POST', '/api/queue/remove', {'id': second})
        # laufende Eintraege lassen sich nicht entfernen
        self.request('POST', '/api/queue/remove', {'id': third})
        self.assertEqual([x['id'] for x in self.state.queue], [third])
        # die fruehere Sammelroute gibt es nicht mehr
        self.assertEqual(self.request('POST', '/api/queue/clear', {})[0], 404)
        self.assertEqual([x['id'] for x in self.state.queue], [third])

    def test_move_changes_order(self):
        self.request('POST', '/api/queue/add', {'urls': ['https://a.example/1', 'https://a.example/2', 'https://a.example/3']})
        a, b, c = [x['id'] for x in self.state.queue]
        ids = lambda: [x['id'] for x in self.state.queue]
        self.assertEqual(self.request('POST', '/api/queue/move', {'id': c, 'before': a})[0], 200)
        self.assertEqual(ids(), [c, a, b])
        self.assertEqual(self.request('POST', '/api/queue/move', {'id': c, 'before': None})[0], 200)
        self.assertEqual(ids(), [a, b, c])
        # ungueltig: unbekannte Ziele, sich selbst, laufender Eintrag
        self.assertEqual(self.request('POST', '/api/queue/move', {'id': a, 'before': 'gibtsnicht'})[0], 400)
        self.assertEqual(self.request('POST', '/api/queue/move', {'id': a, 'before': a})[0], 400)
        self.assertEqual(self.request('POST', '/api/queue/move', {'id': 'gibtsnicht', 'before': None})[0], 400)
        self.state.queue[0]['status'] = 'running'
        self.assertEqual(self.request('POST', '/api/queue/move', {'id': a, 'before': None})[0], 400)
        self.assertEqual(ids(), [a, b, c])

    def test_sizes_button_enables_and_starts_when_idle(self):
        self.request('POST', '/api/queue/add', {'urls': ['https://a.example/1']})
        self.started.clear()
        self.assertEqual(self.request('POST', '/api/sizes', {})[0], 200)
        self.assertTrue(self.state.sizes_enabled)
        self.assertEqual(self.started, ['preview', 'sizes'])   # Titel fehlt noch: Titelsuche, Groessen parallel

    def test_stop_ends_size_scan_too(self):
        tree = unittest.mock.Mock()
        self.state.size_worker, self.state.size_tree = object(), tree
        self.request('POST', '/api/stop', {})
        self.assertTrue(self.state.size_stop)
        tree.kill.assert_called_once()

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
        for p in self.state.storage.rglob('*'):
            if p.is_file():
                self.assertNotIn('geheim.example', p.read_text(encoding='utf-8', errors='replace'))


class TestEvents(unittest.TestCase):
    def test_emit_only_with_flag_and_strips_urls(self):
        out = io.StringIO()
        with unittest.mock.patch.object(g, 'SESSION', g.Session()), contextlib.redirect_stdout(out):
            g.emit('title', name='x')   # ohne --events: keine Ausgabe
        self.assertEqual(out.getvalue(), '')
        with capture_events() as cap:
            g.emit('error', ident='X', message='kaputt bei https://signed.example/abc?token=1')
        self.assertTrue(cap.output.startswith(g.EVENT_PREFIX))
        [ev] = cap.events
        self.assertEqual(ev['type'], 'error')
        self.assertNotIn('signed.example', ev['message'])

    def test_error_event_names_affected_check(self):
        with capture_events() as cap, contextlib.redirect_stderr(io.StringIO()):
            g.error(g.Failure(2, 'DNS_GEO_FAILED', 'x'))
            g.error(g.Failure(4, 'LINK_RESOLUTION_FAILED', 'y'))
        self.assertEqual([e['check'] for e in cap.events], ['dns', None])
        self.assertTrue(set(g.ERROR_CHECK.values()) <= set(g.CHECK_KEYS))

    def test_progress_lines(self):
        cases = {
            '[download]  37.0% of    2.72MiB at    5.33MiB/s ETA 00:01': (37.0, '2.72MiB', '5.33MiB/s', '00:01'),
            '[download] 100% of    2.72MiB in 00:00:01 at 1.74MiB/s': (100.0, '2.72MiB', '1.74MiB/s', None),
            '[download]   0.0% of ~  101.10MiB at  Unknown B/s ETA Unknown': (0.0, '101.10MiB', None, None),
        }
        for line, (pct, total, speed, eta) in cases.items():
            with capture_events() as cap:
                g.progress_event(line + '\n')
            [ev] = cap.events
            self.assertEqual((ev['percent'], ev['total'], ev['speed'], ev['eta']), (pct, total, speed, eta), line)
        with capture_events() as cap:
            g.progress_event('[download] Destination: C:\\x\\raw.mp4')
            g.progress_event('[info] irgendwas')
        self.assertEqual(cap.output, '')

    def test_state_handles_events(self):
        s = make_state(self)
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
        again = ui.State(s.config, CONFIG_PATH)
        self.assertTrue(again.checks['ipv4']['ok'])
        self.assertTrue(again.checks['ipv4']['stale'])
        self.assertEqual(again.snapshot()['overall'], 'bad')

    def test_preview_eta_starts_after_second_link(self):
        cur, clock = {}, iter([100.0, 104.0, 110.0, 116.0])   # Link 1 langsam, danach je 6 s
        with unittest.mock.patch.object(ui, 'now', lambda: next(clock)):
            ui.State.preview_eta(cur, 5)
            self.assertIsNone(cur['eta_seconds'])                       # nach Link 1: noch keine Schaetzung
            ui.State.preview_eta(cur, 5)
            self.assertEqual((cur['eta_seconds'], cur['eta_at']), (12, 104.0))   # 3 offen x 4 s
            ui.State.preview_eta(cur, 5)
            self.assertEqual(cur['eta_seconds'], 10)                    # 2 offen x 5 s (Mittel aus 4 und 6)
            ui.State.preview_eta(cur, 4)
            self.assertEqual(cur['eta_seconds'], 0)                     # alle fertig

    def test_sizes_on_request_only_and_events(self):
        s = make_state(self)
        a = {'id': 'a', 'url': 'https://a.example/1', 'status': 'waiting', 'title_state': 'ok'}
        b = {'id': 'b', 'url': 'https://a.example/2', 'status': 'waiting', 'title_state': 'ok'}
        c = {'id': 'c', 'url': 'https://a.example/3', 'status': 'waiting', 'title_state': 'pending'}
        s.queue = [a, b, c]
        self.assertEqual(s.pending_sizes(), [])                 # ohne Knopfdruck nie
        s.sizes_enabled = True
        self.assertEqual(s.pending_sizes(), [a, b])             # erst nach gefundenem Titel
        download = {'id': 'x', 'phase': 'download', 'percent': 40}
        s.size_batch, s.size_job, s.current = ui.BatchJob([a, b], 'size_state'), {'done': 0, 'total': 2}, download
        s.handle_size_event({'type': 'size_start', 'index': 0})
        s.handle_size_event({'type': 'phase', 'phase': 'sizes'})          # darf die Download-Anzeige nicht aendern
        s.handle_size_event({'type': 'size', 'index': 0, 'bytes': 700})
        s.handle_size_event({'type': 'size', 'index': 1, 'bytes': 'viel'})
        s.handle_size_event({'type': 'error', 'ident': 'X', 'message': 'kaputt'})
        self.assertEqual((a['size_state'], a['expected_size']), ('ok', 700))
        self.assertEqual((b['size_state'], b['expected_size']), ('unknown', None))
        self.assertEqual(download, {'id': 'x', 'phase': 'download', 'percent': 40})
        self.assertEqual(s.size_batch.error['message'], 'kaputt')
        snap = s.snapshot()
        self.assertTrue(snap['sizes_enabled'])
        self.assertEqual(snap['size_job'], {'done': 2, 'total': 2})

    def test_failed_size_scan_does_not_loop(self):
        s = make_state(self)
        s.sizes_enabled = True
        s.queue = [{'id': 'a', 'url': 'https://a.example/1', 'status': 'waiting', 'title_state': 'ok'}]
        with unittest.mock.patch.object(ui, 'run_grab', return_value=1):
            ui.SizeWorker(s).run()
        self.assertEqual(s.queue[0]['size_state'], 'unknown')
        self.assertEqual(s.pending_sizes(), [])
        self.assertEqual((s.size_worker, s.size_job, s.size_batch), (None, None, None))
        self.assertIsNone(s.banner)

    def test_security_abort_in_size_scan_stops_download(self):
        s = make_state(self)
        s.sizes_enabled = True
        s.queue = [{'id': 'a', 'url': 'https://a.example/1', 'status': 'waiting', 'title_state': 'ok'}]
        s.worker, s.tree = object(), unittest.mock.Mock()   # laufender Download

        def grab(*a, **kw):
            s.handle_size_event({'type': 'error', 'ident': 'HOME_COUNTRY_DETECTED', 'message': 'Heimatland erkannt.'})
            return 2

        with unittest.mock.patch.object(ui, 'run_grab', grab):
            ui.SizeWorker(s).run()
        self.assertTrue(s.stop_requested)
        s.tree.kill.assert_called_once()
        self.assertEqual(s.banner['level'], 'bad')
        self.assertIn('Heimatland erkannt.', s.banner['text'])

    def test_redirect_hosts_only_in_memory(self):
        s = make_state(self)
        s.handle_event({'type': 'redirect_host', 'host': 'mediathek.example'})
        for bad in ('Boese,host', 'a b.example', '../x', 123, None, 'x' * 300 + '.example'):
            s.handle_event({'type': 'redirect_host', 'host': bad})
        self.assertEqual(s.redirect_hosts, {'mediathek.example'})
        # nie auf der Festplatte, nie im Browser
        s.save_checks()
        stored = ''.join(p.read_text(encoding='utf-8', errors='replace') for p in s.storage.rglob('*') if p.is_file())
        self.assertNotIn('mediathek', stored)
        self.assertNotIn('mediathek', json.dumps(s.snapshot()))
        self.assertEqual(ui.State(s.config, CONFIG_PATH).redirect_hosts, set())
        # Weitergabe an grab.py nur per Umgebungsvariable (nicht in der Kommandozeile)
        seen = {}

        def popen(argv, **kw):
            seen.update(argv=argv, env=kw['env'])
            raise RuntimeError('stop')

        with unittest.mock.patch.object(ui.subprocess, 'Popen', popen), self.assertRaises(RuntimeError):
            ui.run_grab(s, ['--preview'], s.handle_event, lambda tree: None, stdin_text='')
        self.assertEqual(seen['env'][g.REDIRECT_HOSTS_ENV], 'mediathek.example')
        self.assertNotIn('mediathek', ' '.join(map(str, seen['argv'])))

    def test_page_constants_come_from_server(self):
        self.assertEqual([c['key'] for c in ui.UI_META['checks']], list(g.CHECK_KEYS))
        self.assertEqual([p['key'] for p in ui.UI_META['phases']], list(ui.common.DOWNLOAD_PHASES))
        self.assertEqual(ui.UI_META['limits']['name'], ui.MAX_NAME)
        s = make_state(self)
        s.queue = [{'id': 'a', 'url': 'https://a.example/1', 'name': 'Eigen', 'title': 'Gefunden', 'status': 'waiting'},
                   {'id': 'b', 'url': 'https://a.example/2', 'name': None, 'title': 'Gefunden', 'status': 'waiting'}]
        s.current = {'id': 'preview'}
        ui.State.preview_eta(s.current, 3)
        snap = s.snapshot()
        self.assertEqual([x['display'] for x in snap['queue']], ['Eigen', 'Gefunden'])
        self.assertNotIn('display', s.queue[0])                 # nur in der Antwort, nicht im Eintrag
        self.assertNotIn('preview_marks', snap['current'])      # bleibt im Server
        self.assertIn('preview_marks', s.current)

    def test_halt_ends_both_process_trees(self):
        s = make_state(self)
        s.worker, s.tree, s.size_worker, s.size_tree = object(), unittest.mock.Mock(), object(), unittest.mock.Mock()
        s.halt_locked()
        self.assertTrue(s.stop_requested and s.size_stop)
        s.tree.kill.assert_called_once()
        s.size_tree.kill.assert_called_once()

    def test_after_title_search_download_starts_only_if_not_halted(self):
        for stopped, expected in ((False, ['download']), (True, [])):
            s = make_state(self)
            started = []
            s.start_worker = lambda mode: started.append(mode) or True
            s.queue = [{'id': 'a', 'url': 'https://a.example/1', 'status': 'waiting', 'title_state': 'pending'}]
            s.start_after_preview = True
            worker = ui.Worker(s, 'preview')
            s.worker = worker

            def grab(state, extra, on_event, set_tree, stdin_text=None):
                on_event({'type': 'preview', 'index': 0, 'ok': True, 'name': 'T'})
                state.stop_requested = stopped
                return 1 if stopped else 0

            with unittest.mock.patch.object(ui, 'run_grab', grab), \
                 unittest.mock.patch.object(s, 'save_checks', lambda: None):
                worker.run()
            self.assertEqual(started, expected)
            self.assertEqual((s.worker, s.mode, s.start_after_preview), (None, 'idle', False))

    def test_grab_reads_only_valid_redirect_hosts(self):
        with unittest.mock.patch.object(g, 'SESSION', g.Session()):
            g.load_redirect_hosts({g.REDIRECT_HOSTS_ENV: 'Mediathek.Example, boese host,../x,,b.example'})
            self.assertEqual(g.SESSION.redirect_hosts, {'mediathek.example', 'b.example'})


class TestTitleSearch(unittest.TestCase):
    def setUp(self):
        self.state = make_state(self)
        self.config = self.state.config

    def test_state_maps_preview_events_to_items(self):
        s = self.state
        a = {'id': 'a', 'url': 'https://a.example/1', 'status': 'waiting', 'title': None, 'title_state': 'queued'}
        b = {'id': 'b', 'url': 'https://a.example/2', 'status': 'waiting', 'title': None, 'title_state': 'queued'}
        s.queue, s.preview_batch, s.current = [a, b], ui.BatchJob([a, b], 'title_state'), {'id': 'preview'}
        self.assertNotIn('preview_started', s.current)
        s.handle_event({'type': 'check', 'key': 'firewall', 'ok': True, 'detail': 'x'})
        self.assertEqual(s.current['check_step'], 'firewall')
        s.handle_event({'type': 'preview_start', 'index': 0})
        self.assertEqual(a['title_state'], 'running')
        self.assertIsInstance(s.current['preview_started'], float)
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
        net = RecordingNet()
        store = g.Store(self.state.storage)
        with unittest.mock.patch.object(g, 'resolve_item', resolve), capture_events() as cap:
            self.assertEqual(g.preview(self.config, None, net, store, urls), 0)
        results = [e for e in cap.events if e['type'] == 'preview']
        self.assertEqual([(e['index'], e['ok']) for e in results], [(0, True), (1, False)])
        self.assertEqual(results[0]['name'], 'Mein_Video')
        # Pruefpunkt vorher, vor jedem Eintrag und danach - wie die interaktive Vorschau
        self.assertEqual(net.calls, ['IPv4 vor Vorschau', 'IPv4 vor Vorschau-Eintrag', 'IPv4 vor Vorschau-Eintrag', 'IPv4 nach Vorschau'])

    def test_grab_preview_stops_on_security_abort(self):
        net = RecordingNet(fail_on=2)   # Sicherheitsabbruch am Pruefpunkt vor dem ersten Eintrag
        with self.assertRaises(g.Failure) as caught, contextlib.redirect_stdout(io.StringIO()):
            g.preview(self.config, None, net, g.Store(self.state.storage), ['https://a.example/1', 'https://a.example/2'])
        self.assertEqual(caught.exception.code, 2)
        self.assertEqual(net.calls, ['IPv4 vor Vorschau', 'IPv4 vor Vorschau-Eintrag'])   # sofort Ende, kein weiterer Pruefpunkt

    def test_read_preview_urls(self):
        self.assertEqual(g.read_preview_urls(io.StringIO('https://a.example/1\n\n https://a.example/2 \n')),
                         ['https://a.example/1', 'https://a.example/2'])
        for bad in ('', 'ftp://x\n', '\n'.join(['https://a.example/x'] * 51)):
            with self.assertRaises(g.Failure):
                g.read_preview_urls(io.StringIO(bad))


class TestOverallAndProfile(unittest.TestCase):
    def test_old_good_results_are_stale_not_good(self):
        s = make_state(self)
        for k in ui.CHECK_KEYS:
            s.set_check(k, True, 'ok')
        self.assertEqual(s.snapshot()['overall'], 'good')
        s.save_checks()
        again = ui.State(s.config, CONFIG_PATH)
        snap = again.snapshot()
        self.assertEqual(snap['overall'], 'stale')
        self.assertIsInstance(snap['tz_offset'], int)

    def test_profile_detection(self):
        root = Path('C:/p')
        mb = ui.browser_command('auto', 'u', root, (lambda: 'mb.exe', lambda: 'edge.exe'))
        self.assertEqual((mb.kind, mb.profile), ('mullvad', root / 'mullvad'))
        self.assertEqual(mb.argv[mb.argv.index('-profile') + 1], str(mb.profile))   # Startzeile nutzt dasselbe Profil
        edge = ui.browser_command('edge', 'u', root, (lambda: 'mb.exe', lambda: 'edge.exe'))
        self.assertEqual((edge.kind, edge.profile), ('edge', Path('C:/p/edge')))
        self.assertIn(f'--user-data-dir={edge.profile}', edge.argv)
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
        launch = ui.browser_command('auto', self.URL, self.ROOT, (lambda: 'mb.exe', lambda: 'edge.exe'))
        name, cmd = launch.name, launch.argv
        self.assertEqual(name, 'Mullvad Browser')
        self.assertEqual(cmd[:2], ['mb.exe', '-no-remote'])
        self.assertIn(str(self.ROOT / 'mullvad'), cmd)
        self.assertEqual(cmd[-1], self.URL)

    def test_auto_falls_back_to_edge_with_own_profile(self):
        launch = ui.browser_command('auto', self.URL, self.ROOT, (lambda: None, lambda: 'edge.exe'))
        name, cmd = launch.name, launch.argv
        self.assertTrue(name.startswith('Microsoft Edge'))
        self.assertIn(f'--user-data-dir={self.ROOT / "edge"}', cmd)
        self.assertIn(f'--app={self.URL}', cmd)
        self.assertIn('--disable-sync', cmd)

    def test_strict_mullvad_refuses_without_it(self):
        with self.assertRaises(ui.NoBrowser) as caught:
            ui.browser_command('mullvad', self.URL, self.ROOT, (lambda: None, lambda: 'edge.exe'))
        self.assertIn('mullvad.net/browser', str(caught.exception))

    def test_edge_choice_ignores_mullvad(self):
        launch = ui.browser_command('edge', self.URL, self.ROOT, (lambda: 'mb.exe', lambda: 'edge.exe'))
        self.assertEqual((launch.argv[0], launch.kind), ('edge.exe', 'edge'))

    def test_config_option(self):
        with self.assertRaises(g.Failure):
            g.load_config(write_config(self, lambda t: t.replace('ui_browser = "auto"', 'ui_browser = "firefox"')))
        # Aeltere config.toml ohne den Eintrag bleibt gueltig
        self.assertEqual(g.load_config(write_config(self, lambda t: t.replace('ui_browser = "auto"', '')))['ui_browser'], 'auto')


if __name__ == '__main__':
    unittest.main()
