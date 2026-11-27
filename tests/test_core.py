import contextlib
import copy
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import time
import unittest
import weakref
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import grab as g
import voe_resolver as voe
from helpers import RecordingNet, ScriptedRunner, nslookup_runner

CONFIG = g.load_config(Path(g.__file__).with_name('config.default.toml'))
TXT_1111 = 'o-o.myaddr.l.google.com\ttext =\n\n\t"1.1.1.1"\n'   # nslookup-Antwort: Resolver-Ausgang 1.1.1.1


class TestCore(unittest.TestCase):
    def test_redirect_host_is_remembered_and_checks_stay(self):
        """Mediathek-Weiterleitung: ab dem 2. Link derselben Seite zuerst der Weiterleitungsweg, ohne yt-dlp."""
        calls, net = [], RecordingNet()
        checks = net.calls

        class Runner:
            def run(self, args, **kw):
                calls.append('generic' if '--force-generic-extractor' in args else 'ytdlp')
                return g.Result(1, '', 'ERROR: Unsupported URL: https://mediathek.example/redirect/1')

        def resolver(url, *a):
            calls.append('redirect')
            return None if 'kaputt' in url else {'url': 'https://media.example/v.mp4', 'title': 'Film ' + url[-1]}

        def resolve(url):
            calls.clear(); checks.clear()
            return g.resolve_item(url, None, CONFIG, Runner(), net, Path('.'), '1.1.1.1')

        with patch.object(g, 'SESSION', g.Session()), patch.object(g, 'run_voe_resolver', side_effect=resolver):
            self.assertEqual(resolve('https://mediathek.example/redirect/1')['name'], 'Film_1')
            self.assertEqual(calls, ['ytdlp', 'generic', 'redirect'])
            self.assertEqual(checks, ['IPv4 vor Generic-Aufloesung', 'IPv4 vor Weiterleitungs-Aufloesung'])
            # 2. Link derselben Seite: direkt die Weiterleitung, keine weitere Netzanfrage
            self.assertEqual(resolve('https://mediathek.example/redirect/2')['name'], 'Film_2')
            self.assertEqual((calls, checks), (['redirect'], []))
            # andere Seite: normaler Ablauf
            resolve('https://andere.example/redirect/3')
            self.assertEqual(calls, ['ytdlp', 'generic', 'redirect'])
            # gemerkter Weg klappt nicht: Pruefung, dann alle Versuche, Weiterleitung nicht doppelt
            with self.assertRaises(g.Failure):
                resolve('https://mediathek.example/kaputt')
            self.assertEqual(calls, ['redirect', 'ytdlp', 'generic'])
            self.assertEqual(checks, ['IPv4 vor yt-dlp-Aufloesung', 'IPv4 vor Generic-Aufloesung'])
            # nur HTTPS wird gemerkt/benutzt
            with self.assertRaises(g.Failure):
                resolve('http://mediathek.example/redirect/4')
            self.assertNotIn('redirect', calls)

    def test_header_size(self):
        self.assertEqual(g._header_size('HTTP/1.1 200 OK\r\nContent-Length: 1234\r\n'), 1234)
        # Weiterleitung: nur der letzte Block zaehlt
        self.assertEqual(g._header_size('HTTP/1.1 302 Found\nContent-Length: 0\n\nHTTP/2 200\ncontent-length: 99\n'), 99)
        self.assertEqual(g._header_size('HTTP/1.1 206 Partial\nContent-Length: 1\nContent-Range: bytes 0-0/5000\n'), 5000)
        self.assertIsNone(g._header_size('HTTP/1.1 302 Found\nContent-Length: 50\n\nHTTP/1.1 200 OK\n'))
        self.assertIsNone(g._header_size('Content-Length: abc'))

    def test_media_size(self):
        checked = []

        def public(host):
            checked.append(host)
            if host in ('127.0.0.1', 'router.local'):
                raise ValueError('privat')

        self.enterContext(patch.object(g, 'public_host', public))
        voe = {'voe': True, 'media': 'https://cdn.example/v.mp4?sig=geheim', 'referer': 'https://voe.sx/', 'info': None}
        r = ScriptedRunner([g.Result(0, 'HTTP/1.1 200 OK\nContent-Length: 700\n')])
        self.assertEqual(g.media_size(voe, r, Path('.')), 700)
        self.assertEqual(checked, ['cdn.example'])
        argv, stdin = r.calls[-1]
        self.assertNotIn('--location', argv)                          # Weiterleitungen nie blind folgen
        self.assertIn('--head', argv)
        self.assertNotIn('geheim', ' '.join(map(str, argv)))          # signierte Adresse nicht in der Kommandozeile
        self.assertIn('sig=geheim', stdin)
        # HEAD verweigert -> ein einzelnes Byte anfragen
        r = ScriptedRunner([g.Result(22, '', 'HTTP 405'), g.Result(0, 'HTTP/1.1 206\nContent-Range: bytes 0-0/9000\n')])
        self.assertEqual(g.media_size(voe, r, Path('.')), 9000)
        self.assertIn('--range', r.calls[-1][0])
        # Weiterleitung: Ziel wird vor dem Abruf erneut geprueft
        checked.clear()
        r = ScriptedRunner([g.Result(0, 'HTTP/1.1 302 Found\nLocation: https://cdn2.example/v.mp4\n'),
                    g.Result(0, 'HTTP/1.1 200 OK\nContent-Length: 800\n')])
        self.assertEqual(g.media_size(voe, r, Path('.')), 800)
        self.assertEqual(checked, ['cdn.example', 'cdn2.example'])
        # Weiterleitung ins eigene Netz / auf den eigenen PC oder auf http: kein Abruf
        for target in ('https://127.0.0.1/x', 'https://router.local/x', 'http://cdn3.example/x'):
            r = ScriptedRunner([g.Result(0, f'HTTP/1.1 302 Found\nLocation: {target}\n')])
            self.assertIsNone(g.media_size(voe, r, Path('.')))
            self.assertEqual(len(r.calls), 1)
        r = ScriptedRunner([])
        self.assertIsNone(g.media_size(dict(voe, media='https://127.0.0.1/v.mp4'), r, Path('.')))
        self.assertEqual(r.calls, [])
        # Stream ohne Gesamtgroesse, yt-dlp-Angaben
        self.assertIsNone(g.media_size(dict(voe, media='https://cdn.example/master.m3u8'), ScriptedRunner([]), Path('.')))
        self.assertEqual(g.media_size({'info': {'filesize_approx': 5e8}}, ScriptedRunner([]), Path('.')), 500000000)
        self.assertEqual(g.media_size({'info': {'requested_formats': [{'filesize': 3}, {'filesize': 4}]}}, ScriptedRunner([]), Path('.')), 7)
        self.assertIsNone(g.media_size({'info': {'requested_formats': [{'filesize': 3}, {}]}}, ScriptedRunner([]), Path('.')))

    def test_media_hosts_must_be_public(self):
        def public(host):
            if host in ('127.0.0.1', 'fritz.box'):
                raise ValueError('privat')

        with patch.object(g, 'public_host', public):
            g.check_media_hosts({'media': 'https://cdn.example/v.mp4', 'info': None})
            g.check_media_hosts({'info': {'url': 'https://a.example/x', 'formats': [{'url': 'https://b.example/y'}]}})
            for bad in ({'media': 'https://127.0.0.1/v.mp4', 'info': None},
                        {'info': {'formats': [{'url': 'https://ok.example/1'}, {'manifest_url': 'http://fritz.box/m.m3u8'}]}},
                        {'media': '', 'info': None}):
                with self.assertRaises(g.Failure):
                    g.check_media_hosts(bad)

    def test_sizes_mode_checks_and_events(self):
        net, events = RecordingNet(), []

        class Store:
            @contextlib.contextmanager
            def workspace(self):
                yield Path('.')

        def resolve(url, *a):
            if 'kaputt' in url:
                raise g.Failure(4, 'LINK_RESOLUTION_FAILED', 'x')
            return {'voe': True, 'media': url, 'referer': 'https://voe.sx/', 'info': None}

        with patch.object(g, 'resolve_item', resolve), patch.object(g, 'media_size', lambda item, *a: 1000), \
                patch.object(g, 'emit', lambda kind, **d: events.append((kind, d))), contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(g.sizes(CONFIG, None, net, Store(), ['https://a.example/1', 'https://kaputt.example/2']), 0)
        self.assertEqual(net.calls, ['IPv4 vor Groessenabfrage', 'IPv4 vor Groessen-Eintrag', 'IPv4 vor Groessen-Eintrag', 'IPv4 nach Groessenabfrage'])
        self.assertIn(('size', {'index': 0, 'bytes': 1000}), events)
        self.assertIn(('size', {'index': 1, 'bytes': None}), events)

    def test_unicode_and_shell_characters(self):
        name = g.video_name('Watch Grüße & $(touch pwned); `whoami`.mp4 | VOE')
        self.assertIn('Grüße_&_', name)
        self.assertIn('$(touch_pwned)', name)
        self.assertNotIn('/', g.video_name('../../etc/passwd'))
        self.assertLessEqual(len(g.video_name('😀'*120).encode('utf-8')), 220)

    def test_url_input(self):
        for url in ('file:///etc/passwd', 'https://u:p@example.com/x', 'https://x/\r\nHeader:x', '--exec=whoami'):
            with self.assertRaises(ValueError):
                voe.valid_url(url)
        self.assertTrue(g.is_voe('https://any-host.example/e/abc123'))

    def test_policy_and_missing_country(self):
        data = {'ip': '1.1.1.1', 'country': 'Germany', 'organization': 'Proton'}
        net = g.Network(CONFIG, None, force=True)
        with self.assertRaises(g.Failure) as caught:
            net.policy(g.parse_status(data, 'am.i.mullvad.net'), 'Test')
        self.assertEqual(caught.exception.code, 2)
        data['country'] = 'France'
        data['organization'] = 'Vodafone Proton'
        with self.assertRaises(g.Failure):
            net.policy(g.parse_status(data, 'am.i.mullvad.net'), 'Test')
        del data['country']
        with self.assertRaises(ValueError):
            g.parse_status(data, 'am.i.mullvad.net')

    def test_current_mullvad_shape(self):
        info = g.parse_status({'ip': '1.1.1.1', 'country': 'The Netherlands', 'organization': 'WorldStream B.V.',
                               'blacklisted': {'blacklisted': False, 'results': []}}, 'am.i.mullvad.net')
        self.assertEqual(info['country_code'], '')
        self.assertEqual(info['org'], 'WorldStream B.V.')
        for value in ('127.0.0.1', 'not-an-ip', '192.168.1.2'):
            with self.assertRaises(ValueError):
                g.parse_status({'ip': value, 'country': 'NL', 'organization': 'Proton'}, 'am.i.mullvad.net')
        for country in ({'country_code':'ZZ'}, {'country':'Unknown'}, {'country':'--'}):
            with self.assertRaises(ValueError):
                g.parse_status({'ip':'1.1.1.1','organization':'Proton',**country},'am.i.mullvad.net')

    def test_fallback_exactly_three_plus_one(self):
        net = g.Network(CONFIG, None)
        calls = []
        def request(url, version=4):
            calls.append(url)
            if 'mullvad' in url:
                raise ValueError('simulated outage')
            return {'ip': '1.1.1.1', 'country_code': 'NL', 'country_name': 'Netherlands', 'org': 'Proton'}
        net.json_request = request
        with patch.object(g.time, 'sleep'):
            self.assertEqual(net.status()['source'], 'ipapi.co')
        self.assertEqual(len(calls), 4)
        net.json_request = lambda *a: {}
        with patch.object(g.time, 'sleep'), self.assertRaises(g.Failure) as caught:
            net.status()
        self.assertEqual(caught.exception.code, 2)

    def test_dns_single_txt_and_single_geo(self):
        net = g.Network(CONFIG, nslookup_runner('Server:  dns.example\nAddress:  10.2.0.1\n\nNicht autorisierende Antwort:\n'
                                                'o-o.myaddr.l.google.com\ttext =\n\n\t"1.1.1.1"\n'))
        count = []
        def geo(url, version=4):
            count.append(url)
            return {'ip': '1.1.1.1', 'country_code': 'NL', 'org': 'Proton'}
        net.json_request = geo
        self.assertEqual(net.dns(), '1.1.1.1')
        self.assertEqual(len(count), 1)
        # Gleicher Resolver im selben Lauf: keine zweite Abfrage, Policy greift trotzdem.
        with contextlib.redirect_stdout(io.StringIO()) as out:
            self.assertEqual(net.dns(), '1.1.1.1')
        self.assertEqual(len(count), 1)
        self.assertIn('DNS: IP 1.1.1.1', out.getvalue())

    def test_dns_reuses_exit_status_only_for_same_ip(self):
        count = []
        def geo(url, version=4):
            count.append(url)
            return {'ip': '1.1.1.1', 'country_code': 'NL', 'org': 'Proton'}
        net = g.Network(CONFIG, nslookup_runner(TXT_1111))
        net.json_request = geo
        same = {'ip': '1.1.1.1', 'country_code': 'NL', 'country': 'Netherlands', 'org': 'Proton AG', 'source': 'am.i.mullvad.net'}
        self.assertEqual(net.dns(same), '1.1.1.1')
        self.assertEqual(count, [])
        net = g.Network(CONFIG, nslookup_runner(TXT_1111))
        net.json_request = geo
        self.assertEqual(net.dns(dict(same, ip='2.2.2.2')), '1.1.1.1')
        self.assertEqual(len(count), 1)
        # Wiederverwendete Daten laufen weiter durch die Policy.
        net = g.Network(CONFIG, nslookup_runner(TXT_1111))
        with self.assertRaises(g.Failure) as caught:
            net.dns(dict(same, org='Telekom'))
        self.assertEqual(caught.exception.code, 2)

    def test_dns_geo_failure_for_new_resolver_still_stops(self):
        net = g.Network(CONFIG, nslookup_runner(TXT_1111))
        net.json_request = lambda *a, **kw: {'error': True, 'reason': 'RateLimited'}
        with self.assertRaises(g.Failure) as caught:
            net.dns({'ip': '9.9.9.9', 'country_code': 'NL', 'org': 'Proton'})
        self.assertEqual(caught.exception.ident, 'DNS_GEO_FAILED')

    def test_dns_geo_falls_back_to_ipinfo_once(self):
        calls = []
        def geo(url, version=4):
            calls.append(url)
            if 'ipapi.co' in url:
                raise ValueError('Status-Endpunkt antwortet nicht')   # z. B. HTTP 429
            return {'ip': '1.1.1.1', 'country': 'CH', 'org': 'AS9009 M247 Europe SRL', 'city': 'Zurich'}
        net = g.Network(CONFIG, nslookup_runner(TXT_1111))
        net.json_request = geo
        with contextlib.redirect_stdout(io.StringIO()) as out:
            self.assertEqual(net.dns({'ip': '9.9.9.9'}), '1.1.1.1')
            self.assertEqual(net.dns({'ip': '9.9.9.9'}), '1.1.1.1')
        self.assertEqual([u.split('/')[2] for u in calls], ['ipapi.co', 'ipinfo.io'])
        self.assertIn('M247 Europe SRL | Quelle ipinfo.io', out.getvalue())

    def test_ipinfo_data_goes_through_policy(self):
        info = g.parse_status({'ip': '1.1.1.1', 'country': 'DE', 'org': 'AS3320 Deutsche Telekom AG'}, 'ipinfo.io')
        self.assertEqual((info['country_code'], info['org']), ('DE', 'AS3320 Deutsche Telekom AG'))
        with self.assertRaises(g.Failure) as caught, contextlib.redirect_stdout(io.StringIO()):
            g.Network(CONFIG, None).policy(info, 'DNS')
        self.assertEqual(caught.exception.ident, 'HOME_COUNTRY_DETECTED')
        for bad in ({'ip': '1.1.1.1', 'country': 'CH'}, {'ip': '1.1.1.1', 'country': 'XX', 'org': 'M247'},
                    {'ip': '10.0.0.1', 'country': 'CH', 'org': 'M247'}, {'ip': '1.1.1.1', 'bogon': True},
                    {'error': {'title': 'Rate limit exceeded'}}):
            with self.assertRaises(ValueError):
                g.parse_status(bad, 'ipinfo.io')

    def test_dns_rejects_missing_private_and_ambiguous(self):
        self.assertEqual(g.parse_txt_ips('text =\n"192.168.0.1"\n"nope"'), set())
        self.assertEqual(g.parse_txt_ips('"1.1.1.1" "8.8.8.8"'), {'1.1.1.1', '8.8.8.8'})
        for text, ident in (('Server: x\n', 'DNS_RESOLVER_INVALID'), ('"1.1.1.1" "8.8.8.8"', 'DNS_RESOLVER_AMBIGUOUS')):
            with self.assertRaises(g.Failure) as caught:
                g.Network(CONFIG, nslookup_runner(text)).dns()
            self.assertEqual(caught.exception.ident, ident)

    def test_ipv6_unreachable_is_noted_reachable_is_checked(self):
        net = g.Network(CONFIG, None)
        net.json_request = lambda *a: (_ for _ in ()).throw(ValueError('kein IPv6'))
        with contextlib.redirect_stdout(io.StringIO()) as out:
            self.assertIsNone(net.ipv6())
        self.assertIn('nachgewiesen', out.getvalue())
        net.json_request = lambda *a: {'ip': '2606:4700:4700::1111', 'country': 'Germany', 'organization': 'Proton'}
        with contextlib.redirect_stdout(io.StringIO()), self.assertRaises(g.Failure) as caught:
            net.ipv6()
        self.assertEqual((caught.exception.code, caught.exception.ident), (2, 'IPV6_PATH_OPEN'))

    def test_any_reachable_ipv6_stops_even_allowlisted_or_forced(self):
        """IPv6 komplett gesperrt: jeder erreichbare IPv6-Weg stoppt mit Exit 2 - auch ueber Proton,
        auch mit --force, auch bei unlesbarer Antwort. Die IPv4-Ausnahme von --force bleibt."""
        proton = {'ip': '2a07:b944::1', 'country': 'Switzerland', 'organization': 'Proton AG'}
        outside = {'ip': '2606:4700:4700::1111', 'country': 'Netherlands', 'organization': 'Unbekannter Hoster B.V.'}
        for force in (False, True):
            for answer in (proton, outside, {'kaputt': True}):
                net = g.Network(CONFIG, None, force=force)
                net.json_request = lambda *a, answer=answer: answer
                events = []
                with patch.object(g, 'emit', lambda kind, **d: events.append((kind, d))), \
                        contextlib.redirect_stdout(io.StringIO()), self.assertRaises(g.Failure) as caught:
                    net.ipv6()
                self.assertEqual((caught.exception.code, caught.exception.ident), (2, 'IPV6_PATH_OPEN'))
                self.assertEqual([(k, d['key'], d['ok']) for k, d in events], [('check', 'ipv6', False)])
        # Gegenprobe: dieselbe Organisation ueber IPv4 laesst --force (mit Warnung) durch.
        net = g.Network(CONFIG, None, force=True)
        with contextlib.redirect_stdout(io.StringIO()) as out:
            net.policy(g.parse_status(dict(outside, ip='1.1.1.1'), 'am.i.mullvad.net'), 'IPv4')
        self.assertIn('--force', out.getvalue())
        self.assertEqual(g.ERROR_CHECK['IPV6_PATH_OPEN'], 'ipv6')

    def test_ip_change_blocks(self):
        net = g.Network(CONFIG, None)
        net.status = lambda: {'ip': '1.1.1.1', 'country_code': 'NL', 'country': 'NL', 'org': 'Proton', 'source': 'test'}
        net.dns = lambda known=None: '1.1.1.2'
        net.ipv6 = lambda: None
        with patch.object(g, 'ensure_guard'), self.assertRaises(g.Failure) as caught:
            net.check('Test', '8.8.8.8')
        self.assertEqual(caught.exception.ident, 'EXIT_IP_CHANGED')

    def test_network_process_failure_is_fatal(self):
        net = g.Network(CONFIG, None)
        net.status = lambda: g.fail(1, 'PROCESS_START_FAILED', 'test')
        with patch.object(g, 'ensure_guard'), self.assertRaises(g.Failure) as caught:
            net.check('test')
        self.assertEqual(caught.exception.code, 2)

    def test_metadata_values_not_only_names(self):
        for container in ('mov,mp4,m4a,3gp,3g2,mj2', 'matroska,webm'):
            data = {'format': {'format_name': container, 'duration': '2'}, 'streams': [{'codec_type': 'video', 'codec_name': 'h264', 'tags': {}}]}
            g.check_metadata(data)
            for tag in ('encoder', 'handler_name', 'language', 'duration', 'filename'):
                test = copy.deepcopy(data)
                test['streams'][0]['tags'] = {tag: 'tracking-123'}
                with self.assertRaises(g.Failure) as caught:
                    g.check_metadata(test)
                self.assertEqual(caught.exception.code, 5)
        for duration in ('00:00:20.000000000', '99:99:99.000000000'):
            data = {'format': {'format_name': 'matroska,webm', 'duration': '2'}, 'streams': [{'codec_type': 'video', 'tags': {'DURATION': duration}}]}
            with self.assertRaises(g.Failure):
                g.check_metadata(data)

    def test_vendor_id_only_neutral_default_in_mp4(self):
        def data(value, container='mov,mp4,m4a,3gp,3g2,mj2', kind='video'):
            return {'format': {'format_name': container, 'duration': '2'},
                    'streams': [{'codec_type': kind, 'codec_name': 'h264', 'tags': {'vendor_id': value}}]}
        g.check_metadata(data('[0][0][0][0]'))
        g.check_metadata(data('[0][0][0][0]', kind='audio'))
        for bad in (data('appl'), data('tracking-123'), data('[0][0][0][0]', 'matroska,webm'), data('[0][0][0][0]', kind='subtitle')):
            with self.assertRaises(g.Failure) as caught:
                g.check_metadata(bad)
            self.assertEqual(caught.exception.code, 5)

    def test_stream_loss_rejected(self):
        data = {'streams': [{'codec_type': 'video', 'codec_name': 'h264'}, {'codec_type': 'audio', 'codec_name': 'aac'}, {'codec_type': 'subtitle', 'codec_name': 'subrip'}, {'codec_type': 'attachment', 'codec_name': 'ttf'}]}
        with self.assertRaises(g.Failure):
            g.verify_streams(g.selected_streams(data), {'streams': data['streams'][:-1]})

    def test_queue_semantics(self):
        entries = [{'valid': True} for _ in range(3)]
        out = io.StringIO()
        def mixed(item, index, total):
            if index < 3:
                g.fail(4 if index == 1 else 5, 'SIMULATED', 'Fehler')
        with contextlib.redirect_stdout(out):
            self.assertEqual(g.run_queue(entries, mixed), 1)
        self.assertIn('1 erfolgreich, 2 übersprungen, 0 abgebrochen', out.getvalue())
        seen = []
        def fatal(item, index, total):
            seen.append(index)
            g.fail(2, 'SIMULATED', 'Netzfehler')
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(g.run_queue(entries, fatal), 2)
        self.assertEqual(seen, [1])

    def test_failed_probe_never_resolves(self):
        with tempfile.TemporaryDirectory() as d:
            store = g.Store(d)
            with patch.object(g, 'probe', side_effect=g.Failure(2, 'PROBE_FAILED', 'test')), patch.object(g, 'resolve_item') as resolve:
                with self.assertRaises(g.Failure):
                    g.download('https://example.com/x', None, CONFIG, None, None, store)
                resolve.assert_not_called()
            self.assertEqual(list(store.work.iterdir()), [])

    def test_probe_hard_deadline_exit_and_empty_file(self):
        for result,create in [(g.Result(7,''),True),(g.Result(0,''),False),(g.Result(-9,'',timed_out=True),True)]:
            class Fake:
                def run(self,args,**kwargs):
                    self.timeout=kwargs['timeout']
                    if create: (kwargs['cwd']/'probe.mp4').write_bytes(b'x')
                    return result
            with tempfile.TemporaryDirectory() as d:
                fake=Fake()
                with self.assertRaises(g.Failure) as caught:
                    g.probe(CONFIG,fake,RecordingNet(),Path(d))
                self.assertEqual(caught.exception.code,2)
                self.assertEqual(fake.timeout,60)
                self.assertFalse((Path(d)/'probe.mp4').exists())

    def test_postcheck_blocks_publication(self):
        net = RecordingNet(fail_on=1)   # erster Pruefpunkt hier = Nachpruefung (probe/transfer sind ersetzt)
        with tempfile.TemporaryDirectory() as d:
            store = g.Store(d)
            def fake_remux(raw, runner):
                raw.write_bytes(b'video')
                return raw, '.mp4'
            with patch.object(g, 'probe', return_value='1.1.1.1'), patch.object(g, 'resolve_item', return_value={'name': 'Test'}), \
                 patch.object(g, 'transfer', side_effect=lambda i,c,r,n,w,b: w/'clean.mp4'), patch.object(g, 'remux', side_effect=fake_remux), \
                 patch.object(g, 'check_media_hosts'), contextlib.redirect_stdout(io.StringIO()):
                with self.assertRaises(g.Failure) as caught:
                    g.download('https://example.com/x', None, CONFIG, None, net, store)
            # Abbruch kommt wirklich aus der Nachpruefung (nicht schon aus der Hostpruefung davor)
            self.assertEqual((caught.exception.code, caught.exception.ident), (2, 'EXIT_IP_CHANGED'))
            self.assertEqual(net.calls, ['IPv4 nach Transfer/Remux'])
            self.assertEqual(list(store.output.iterdir()), [])   # nichts veroeffentlicht
            self.assertEqual(list(store.state.iterdir()), [])    # und keine Spur (keine Exit-IP) im Zustand

    def test_exit_ip_never_stored_and_leftover_removed(self):
        """V6: Die Exit-IP landet nie auf der Platte; eine alte .last_exit_ip wird beim Bereinigen entfernt."""
        with tempfile.TemporaryDirectory() as d:
            store = g.Store(d)
            leftover = store.state / '.last_exit_ip'
            leftover.write_text('185.159.157.1\n', encoding='ascii')
            (store.state / 'ui-checks.json').write_text('{}', encoding='utf-8')
            with contextlib.redirect_stdout(io.StringIO()):
                store.cleanup()
            self.assertFalse(leftover.exists())
            self.assertTrue((store.state / 'ui-checks.json').is_file())   # nur genau diese Datei
            def fake_remux(raw, runner):
                raw.write_bytes(b'video')
                return raw, '.mp4'
            with patch.object(g, 'probe', return_value='185.159.157.1'), patch.object(g, 'resolve_item', return_value={'name': 'Test'}), \
                 patch.object(g, 'transfer', side_effect=lambda i,c,r,n,w,b: w/'clean.mp4'), patch.object(g, 'remux', side_effect=fake_remux), \
                 patch.object(g, 'check_media_hosts'), contextlib.redirect_stdout(io.StringIO()):
                target = g.download('https://example.com/x', None, CONFIG, None, RecordingNet(ip='185.159.157.1'), store)
            self.assertTrue(target.is_file())
            self.assertEqual(sorted(p.name for p in store.state.iterdir()), ['ui-checks.json'])
            for path in Path(d).rglob('*'):
                if path.is_file():
                    self.assertNotIn(b'185.159.157.1', path.read_bytes(), path.name)

    def test_leftover_exit_ip_only_removed_as_regular_file(self):
        with tempfile.TemporaryDirectory() as d:
            store = g.Store(d)
            odd = store.state / '.last_exit_ip'
            odd.mkdir()
            (odd / 'inhalt').write_text('x', encoding='ascii')
            with contextlib.redirect_stdout(io.StringIO()) as out:
                store.cleanup()
            self.assertTrue((odd / 'inhalt').is_file())   # kein Ordner/Link wird angefasst
            self.assertIn('keine normale Datei', out.getvalue())

    def test_atomic_collision_and_cleanup(self):
        with tempfile.TemporaryDirectory() as d:
            store = g.Store(d)
            with store.workspace() as work:
                raw = work / 'clean.mp4'
                raw.write_bytes(b'one')
                self.assertEqual(store.publish(raw, 'Grüße', '.mp4').name, 'Grüße.mp4')
                raw.write_bytes(b'two')
                self.assertEqual(store.publish(raw, 'Grüße', '.mp4').name, 'Grüße_2.mp4')
            self.assertEqual((store.output / 'Grüße.mp4').read_bytes(), b'one')
            self.assertEqual(list(store.work.iterdir()), [])
            old = store.work / ('a'*32)
            old.mkdir()
            (old / 'raw').write_bytes(b'x')
            past = time.time() - 90000
            os.utime(old, (past, past))
            self.assertEqual(store.cleanup(), 1)

    def test_active_and_symlink_work_not_deleted(self):
        with tempfile.TemporaryDirectory() as d:
            store = g.Store(d)
            with store.workspace() as work:
                past = time.time() - 90000
                os.utime(work, (past, past))
                store.cleanup()
                self.assertTrue(work.exists())
            old = store.work / ('b'*32)
            old.mkdir()
            try:
                (old / 'escape').symlink_to(store.output, target_is_directory=True)
            except OSError:
                self.skipTest('Symlinks nicht erlaubt (unter Windows Entwicklermodus/Adminrecht noetig)')
            os.utime(old, (past, past))
            self.assertEqual(store.cleanup(), 0)

    def test_native_exit_timeout_and_no_shell(self):
        runner = g.Runner()
        result = runner.run([sys.executable, '-c', 'import sys; print(sys.argv[1]); sys.exit(7)', 'Grüße & $(touch pwned); `whoami`'])
        self.assertEqual(result.code, 7)
        self.assertIn('$(touch pwned)', result.out)
        start = time.monotonic()
        result = runner.run([sys.executable, '-c', 'import time; time.sleep(20)'], timeout=0.2)
        self.assertTrue(result.timed_out)
        self.assertNotEqual(result.code, 0)
        self.assertLess(time.monotonic()-start, 5)

    def test_live_output_is_visible_without_retained_copy(self):
        class Sink:
            count=0
            def write(self,text): self.count += len(text); return len(text)
            def flush(self): pass
        sink=Sink()
        with contextlib.redirect_stdout(sink):
            result=g.Runner().run([sys.executable,'-c','import sys; sys.stdout.write("progress line\\n"*40000); sys.stderr.write("warning\\n")'],live=True)
        self.assertEqual(result.code,0)
        self.assertGreater(sink.count,500000)
        self.assertEqual((result.out,result.err),('',''))

    def test_info_memory_released_but_retry_file_preserved(self):
        class Info(dict): pass
        info=Info(url='https://cdn.example/video.mp4?token=private',title='Grüße')
        reference=weakref.ref(info)
        item=g.Item(voe=False,referer='https://example.com/',info=info,media=None)
        del info
        calls=[]
        class Net:
            def check(inner,*args):
                self.assertIsNone(reference())
        class Fake:
            def run(inner,args,**kw):
                self.assertIsNone(reference())
                path=Path(args[args.index('--load-info-json')+1])
                calls.append(json.loads(path.read_text()))
                if len(calls)==1:
                    return g.Result(1,'','Range error')
                raw=kw['cwd']/'raw.mp4'
                raw.write_bytes(b'valid')
                (kw['cwd']/'result-path.txt').write_text(str(raw)+'\n')
                return g.Result(0,'')
        with tempfile.TemporaryDirectory() as d:
            g.transfer(item,CONFIG,Fake(),Net(),Path(d),'1.1.1.1')
        self.assertEqual(len(calls),2)
        self.assertEqual(calls[0],calls[1])
        self.assertEqual(calls[1]['title'],'Grüße')

    def test_retry_is_fresh_and_headers(self):
        net = RecordingNet()
        class Fake:
            def __init__(self): self.calls = []
            def run(self, args, **kw):
                self.calls.append(args)
                work = kw['cwd']
                if len(self.calls) == 1:
                    (work / 'raw.mp4.part').write_bytes(b'broken')
                    return g.Result(1, '', 'HTTP 416 Range')
                assert not (work / 'raw.mp4.part').exists()
                raw = work / 'raw.mp4'
                raw.write_bytes(b'valid')
                (work / 'result-path.txt').write_text(str(raw)+'\n')
                return g.Result(0, '')
        item = {'voe': True, 'referer': 'https://voe.sx/', 'info': None, 'media': 'https://cdn.example/x.mp4?token=secret'}
        with tempfile.TemporaryDirectory() as d:
            fake = Fake()
            g.transfer(item, CONFIG, fake, net, Path(d), '1.1.1.1')
        self.assertEqual(len(net.calls), 2)
        self.assertIn('--http-chunk-size', fake.calls[0])
        self.assertNotIn('--http-chunk-size', fake.calls[1])
        self.assertNotIn('--concurrent-fragments', fake.calls[1])
        for args in fake.calls:
            self.assertEqual(args[args.index('--referer')+1], 'https://voe.sx/')
            self.assertEqual(args[args.index('--user-agent')+1], g.UA)

    def test_voe_fixture_and_redirect_restriction(self):
        page = '<html><meta property="og:title" content="Watch Grüße.mp4 | VOE"><script>sources = {"mp4":"https://cdn.example/film.mp4?token=abc"}</script></html>'
        result = voe.parse_page(page, 'https://voe.sx/e/abc')
        self.assertEqual(result['title'], 'Watch Grüße.mp4 | VOE')
        self.assertIn('token=abc', result['url'])
        with self.assertRaises(ValueError):
            voe.allowed_page('https://evil.example/e/a', ['voe.sx'])

    def test_voe_embed_url(self):
        self.assertEqual(voe.embed_url('https://caseyseemavoid.com/123test123'), 'https://caseyseemavoid.com/e/123test123')
        self.assertEqual(voe.embed_url('https://caseyseemavoid.com/abc/'), 'https://caseyseemavoid.com/e/abc')
        self.assertIsNone(voe.embed_url('https://caseyseemavoid.com/e/abc'))
        self.assertIsNone(voe.embed_url('https://voe.sx/abc'))

    def test_voe_retries_embed_page_once(self):
        hosts = ['voe.sx', 'caseyseemavoid.com']
        good = '<html><script>sources = {"mp4":"https://cdn.example/film.mp4"}</script></html>'
        pages = {'https://voe.sx/abc': ('https://caseyseemavoid.com/abc', '<html>kein Video</html>'),
                 'https://caseyseemavoid.com/e/abc': ('https://caseyseemavoid.com/e/abc', good)}
        opened = []

        class Response(io.BytesIO):
            def __enter__(self): return self
            def __exit__(self, *a): return False

        class Opener:
            def open(self, req, timeout):
                opened.append(req.full_url)
                final, body = pages[req.full_url]
                r = Response(body.encode()); r.url = final
                return r

        with patch.object(voe.urllib.request, 'build_opener', return_value=Opener()):
            result = voe.resolve('https://voe.sx/abc', hosts)
        self.assertEqual(result['url'], 'https://cdn.example/film.mp4')
        self.assertEqual(opened, ['https://voe.sx/abc', 'https://caseyseemavoid.com/e/abc'])

    def test_complete_url_adds_https_only_to_bare_hosts(self):
        self.assertEqual(g.complete_url(' freiefilme.de/redirect/3573819 '), 'https://freiefilme.de/redirect/3573819')
        self.assertEqual(g.complete_url('caseyseemavoid.com/abc'), 'https://caseyseemavoid.com/abc')
        self.assertEqual(g.complete_url('http://x.example/a'), 'http://x.example/a')
        for text in ('fertig', 'javascript:alert(1)', 'file:///C:/x', '/pfad/allein', 'ftp://x.example/a'):
            self.assertFalse(g.complete_url(text).startswith('https://'), text)

    def test_voe_without_e_on_configured_host(self):
        self.assertTrue(g.is_voe('https://voe.sx/abc123', ['voe.sx']))
        self.assertFalse(g.is_voe('https://mediathek.example/abc123', ['voe.sx']))
        self.assertEqual(g.voe_canonical('https://voe.sx/abc123'), 'https://voe.sx/e/abc123')
        self.assertEqual(g.voe_canonical('https://x.example/e/abc123'), 'https://voe.sx/e/abc123')

    def _redirect_opener(self, chain, seen):
        class Opener:
            def open(self, req, timeout):
                seen.append((req.full_url, req.get_header('Referer'), req.get_header('Cookie')))
                code, location = chain[req.full_url]
                if location:
                    raise voe.urllib.error.HTTPError(req.full_url, code, 'redirect', {'Location': location}, io.BytesIO())
                r = io.BytesIO(b'<html></html>'); r.status = code
                return contextlib.nullcontext(r)
        return Opener()

    def test_follow_redirect_chain_to_voe(self):
        hosts = ['voe.sx', 'caseyseemavoid.com']
        chain = {'https://mediathek.example/go/17': (302, '/out?id=17'),
                 'https://mediathek.example/out?id=17': (301, 'https://voe.sx/abc')}
        seen, checked = [], []
        with patch.object(voe.urllib.request, 'build_opener', return_value=self._redirect_opener(chain, seen)):
            self.assertEqual(voe.follow('https://mediathek.example/go/17', hosts, checked.append), 'https://voe.sx/abc')
        self.assertEqual(checked, ['mediathek.example', 'mediathek.example'])
        self.assertTrue(all(ref is None and cookie is None for _, ref, cookie in seen))

    def test_follow_refuses_unsafe_targets(self):
        hosts = ['voe.sx']
        cases = [{'https://m.example/a': (200, None)},                              # keine HTTP-Weiterleitung (z. B. JavaScript)
                 {'https://m.example/a': (302, 'http://voe.sx/abc')},               # nur HTTPS
                 {'https://m.example/a': (302, 'https://other.example/x'),          # Ziel kein VOE-Host
                  'https://other.example/x': (200, None)}]
        loop = {'https://m.example/a': (302, 'https://m.example/a')}                # Schleife -> zu viele Schritte
        for chain in cases + [loop]:
            with patch.object(voe.urllib.request, 'build_opener', return_value=self._redirect_opener(chain, [])):
                with self.assertRaises(ValueError):
                    voe.follow('https://m.example/a', hosts, lambda h: None)
        with self.assertRaises(ValueError):
            voe.public_host('127.0.0.1')
        with self.assertRaises(ValueError):
            voe.public_host('192.168.1.10')

    def test_preview_protects_order_and_passes_only_names(self):
        events=[]
        class Net:
            def check(self,*a): events.append('check'); return '1.1.1.1'
        def first_probe(*a): events.append('probe'); return '1.1.1.1'
        def resolve(url,manual,*args):
            events.append('resolve')
            if 'bad' in url: g.fail(4,'BAD_LINK','Simulierter Linkfehler')
            return {'name':'Grüße','media':'https://cdn.example/?token=must-not-reuse'}
        calls=[]
        def download(url,name,*args): calls.append((url,name))
        with tempfile.TemporaryDirectory() as d:
            store=g.Store(d)
            with patch.object(g,'probe',side_effect=first_probe), patch.object(g,'resolve_item',side_effect=resolve), \
                 patch.object(g,'download',side_effect=download), patch('builtins.input',side_effect=['https://example.com/good','https://example.com/bad','fertig','']), \
                 contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(g.interactive(CONFIG,g.Runner(),Net(),store),1)
            self.assertEqual(events[0],'probe')
            self.assertEqual(calls,[('https://example.com/good','Grüße')])
            self.assertEqual(list(store.work.iterdir()),[])


if __name__ == '__main__':
    unittest.main(verbosity=2)
