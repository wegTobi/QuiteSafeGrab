"""Goldwert-Tests: frieren das nach aussen sichtbare Verhalten VOR dem grossen Umbau ein.

Verglichen werden Kommandozeilen, PowerShell-Texte, Pruefpunkt-Reihenfolgen, Ereignisse, Exit-/Fehlercodes
und Sicherheits-Kopfzeilen der Oberflaeche mit den gespeicherten Werten in golden_behavior.json.
Alles laeuft offline mit Attrappen (keine echten Prozesse, kein Netz).

Maschinenabhaengige Teile (Programmordner, Python, Werkzeugpfade, Arbeitsordner) werden durch
Platzhalter wie <APP>, <PY>, <FFMPEG>, <WORK> ersetzt - die Datei enthaelt keine persoenlichen Pfade.

Neu erzeugen (nur bei freigegebenen V-Punkten, siehe UNTANGLE-PROTOKOLL.md, Arbeitsregel 3):
    set QSGRAB_WRITE_GOLDEN=1  und dann  python\\python.exe -m unittest tests.test_golden
"""
import base64
import contextlib
import http.client
import http.server
import io
import json
import os
from pathlib import Path
import re
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import grab as g
import syscompat as sc
import winguard
import fw
import ui

GOLDEN = Path(__file__).with_name('golden_behavior.json')
CONFIG_PATH = Path(g.__file__).with_name('config.default.toml')
CONFIG = g.load_config(CONFIG_PATH)

# Neutrale Beispielpfade (ohne Benutzernamen) fuer Firewallregeln und Wächter.
PROGRAMS = [r'C:\QSG\python\python.exe', r'C:\QSG\tools\ffmpeg.exe', r'C:\QSG\tools\ffprobe.exe',
            r'C:\Windows\System32\curl.exe', r'C:\Windows\System32\nslookup.exe']
VPN_IP = '10.2.0.2'
LAN_IP = '192.168.178.20'
V4_FOR = {'10.2.0.2': ['0.0.0.0-10.2.0.1', '10.2.0.3-126.255.255.255', '128.0.0.0-255.255.255.255'],
          '10.2.0.9': ['0.0.0.0-10.2.0.8', '10.2.0.10-126.255.255.255', '128.0.0.0-255.255.255.255']}


# --------------------------------------------------------------------------- Normalisierung
_WORK = []   # aktuelle Arbeitsordner (werden zu <WORK>)


def _replacements():
    pairs = [(g.FFMPEG, '<FFMPEG>'), (g.FFPROBE, '<FFPROBE>'), (g.CURL, '<CURL>'), (g.NSLOOKUP, '<NSLOOKUP>'),
             (g.POWERSHELL, '<POWERSHELL>'), (sys.executable, '<PY>'), (sc.real_exe(), '<PY>'),
             (str(g.SYSTEM32), '<SYSTEM32>'), (str(g.APP), '<APP>')]
    pairs += [(w, '<WORK>') for w in _WORK]
    seen, out = set(), []
    for value, name in pairs:
        if value and value not in seen:
            seen.add(value)
            out.append((value, name))
    return sorted(out, key=lambda p: -len(p[0]))


ENCODED = {winguard.powershell_args(winguard.STATE_SCRIPT)[-1]: '<ENC:STATE_SCRIPT>',
           winguard.powershell_args(winguard.QUICK_STATE_SCRIPT)[-1]: '<ENC:QUICK_STATE_SCRIPT>'}


def norm(value):
    if isinstance(value, Path):
        value = str(value)
    if isinstance(value, str):
        if value in ENCODED:
            return ENCODED[value]
        if value == winguard.SELFTEST_CODE:
            return '<SELFTEST_CODE>'
        for old, new in _replacements():
            value = value.replace(old, new)
        return value
    if isinstance(value, dict):
        return {str(k): norm(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [norm(v) for v in value]
    return value


@contextlib.contextmanager
def workdir():
    with tempfile.TemporaryDirectory() as d:
        _WORK.append(d)
        try:
            yield Path(d)
        finally:
            _WORK.remove(d)


class Recorder:
    """Gemeinsames Protokoll: Prozessaufrufe, Pruefpunkte, Ereignisse, Pausen, Ausgaben."""
    def __init__(self):
        self.log = []

    def call(self, argv, kw):
        entry = {'run': list(map(str, argv))}
        for key in ('timeout', 'live', 'cwd', 'input_text'):
            if key in kw:
                entry[key] = kw[key] if not isinstance(kw[key], Path) else str(kw[key])
        self.log.append(norm(entry))   # sofort: der Arbeitsordner ist spaeter schon geloescht

    def emit(self, kind, **data):
        self.log.append(norm({'emit': kind, **data}))

    def check(self, label, expected=None):
        self.log.append(norm({'check': label, 'expected': expected}))

    def result(self):
        return norm(self.log)


class ScriptedRunner:
    """Antworten der Reihe nach (Result oder Funktion argv, kw -> Result)."""
    def __init__(self, rec, answers):
        self.rec, self.answers = rec, list(answers)
        self.position = (1, 1)

    def run(self, argv, **kw):
        self.rec.call(argv, kw)
        answer = self.answers.pop(0)
        return answer(argv, kw) if callable(answer) else answer


class RecNet:
    def __init__(self, rec, ip='185.159.157.10', fail_label=None, skip=False):
        self.rec, self.ip, self.fail_label, self.skip = rec, ip, fail_label, skip

    def check(self, label, expected=None):
        self.rec.check(label, expected)
        if label == self.fail_label:
            g.fail(2, 'EXIT_IP_CHANGED', 'simuliert')
        return self.ip


class FakeStore:
    def __init__(self, work):
        self.work = work

    @contextlib.contextmanager
    def workspace(self):
        yield self.work


def failure(exc):
    return {'failure': exc.ident, 'code': exc.code}


def state_json(vpn=VPN_IP, lan=LAN_IP):
    adapters = [{'Name': 'WLAN', 'InterfaceDescription': 'Intel(R) Wi-Fi 6', 'IPv4': [lan]}]
    rules = []
    if vpn:
        adapters.append({'Name': 'ProtonVPN', 'InterfaceDescription': 'WireGuard Tunnel', 'IPv4': [vpn]})
        for i, program in enumerate(PROGRAMS, 1):
            rules.append({'Name': f'QuiteSafeGrab-v4-{i}', 'Enabled': 'True', 'Direction': 'Outbound', 'Action': 'Block',
                          'Program': program, 'LocalAddress': V4_FOR[vpn]})
            rules.append({'Name': f'QuiteSafeGrab-v6-{i}', 'Enabled': 'True', 'Direction': 'Outbound', 'Action': 'Block',
                          'Program': program, 'LocalAddress': ['::/1', '8000::/1']})
    return json.dumps({'Adapters': adapters, 'Rules': rules, 'RulesError': '',
                       'Profiles': [{'Name': n, 'Enabled': 'True'} for n in ('Domain', 'Private', 'Public')]})


@contextlib.contextmanager
def guard_env(rec):
    """Frischer Waechter-Zwischenspeicher, feste Programmliste, Ereignisse ins Protokoll."""
    with patch.object(g.sys, 'platform', 'win32'), patch.object(g, 'guard_programs', return_value=list(PROGRAMS)), \
         patch.object(g, 'SESSION', g.Session()), patch.object(g, 'emit', rec.emit):
        yield


class NetRunner:
    """Antwortet je nach Programm: PowerShell (Zustand), Selbsttest, curl (je URL), nslookup."""
    def __init__(self, rec, curl, nslookup, state=None, selftest='BLOCKED'):
        self.rec, self.curl, self.nslookup = rec, curl, nslookup
        self.state, self.selftest = state or state_json(), selftest
        self.position = (1, 1)

    def run(self, argv, **kw):
        self.rec.call(argv, kw)
        if argv[0] == g.POWERSHELL:
            return g.Result(0, self.state)
        if winguard.SELFTEST_CODE in argv:
            ips = argv[argv.index(winguard.SELFTEST_CODE) + 1:]
            return g.Result(0, '\n'.join(f'SELFTEST {ip} {self.selftest}' for ip in ips))
        if argv[0] == g.CURL:
            answers = self.curl[argv[-1]]
            answer = answers.pop(0) if isinstance(answers, list) else answers
            return answer if isinstance(answer, g.Result) else g.Result(0, json.dumps(answer))
        if argv[0] == g.NSLOOKUP:
            return g.Result(0, f'o-o.myaddr.l.google.com\ttext =\n\n\t"{self.nslookup}"\n')
        raise AssertionError('unerwarteter Aufruf')


def _ffprobe_json(container, after):
    if container == 'mp4':
        fmt = {'format_name': 'mov,mp4,m4a,3gp,3g2,mj2', 'duration': '5'}
        if after:
            fmt['tags'] = {'major_brand': 'isom', 'minor_version': '512', 'compatible_brands': 'isomiso2avc1mp41'}
        v = {'language': 'und', 'handler_name': 'VideoHandler', 'vendor_id': '[0][0][0][0]'}
        a = {'language': 'und', 'handler_name': 'SoundHandler', 'vendor_id': '[0][0][0][0]'}
    else:
        fmt = {'format_name': 'matroska,webm' if after else 'mpegts', 'duration': '5'}
        if after:
            fmt['tags'] = {'encoder': 'Lavf'}
        v = {'language': 'und', 'DURATION': '00:00:05.000000000'}
        a = {'language': 'und', 'DURATION': '00:00:05.000000000'}
    streams = [{'codec_type': 'video', 'codec_name': 'h264', 'tags': v if after else {'title': 'x'}},
               {'codec_type': 'audio', 'codec_name': 'aac', 'tags': a if after else {}}]
    if not after:
        streams.append({'codec_type': 'video', 'codec_name': 'mjpeg', 'tags': {}})   # zweites Bild: wird nicht uebernommen
    return {'format': fmt, 'streams': streams}


# --------------------------------------------------------------------------- Gruppen
def golden_winguard():
    sample = winguard.build_apply_script(PROGRAMS, [VPN_IP])
    return {
        'STATE_SCRIPT': winguard.STATE_SCRIPT,
        'QUICK_STATE_SCRIPT': winguard.QUICK_STATE_SCRIPT,
        'SELFTEST_CODE': winguard.SELFTEST_CODE,
        'SELFTEST_SAFE': list(winguard.SELFTEST_SAFE),
        'RULE_PREFIX': winguard.RULE_PREFIX,
        'LEGACY_RULE_PREFIXES': list(winguard.LEGACY_RULE_PREFIXES),
        'GROUP': winguard.GROUP,
        'DISPLAY_NAME': winguard.DISPLAY_NAME,
        'V6_ENTRIES': list(winguard.V6_ENTRIES),
        'powershell_args_STATE_SCRIPT': winguard.powershell_args(winguard.STATE_SCRIPT),
        'powershell_args_QUICK_STATE_SCRIPT': winguard.powershell_args(winguard.QUICK_STATE_SCRIPT),
        'apply_script': sample,
        'apply_script_two_vpn_ips': winguard.build_apply_script(PROGRAMS[:1], [VPN_IP, '10.2.0.9']),
        'remove_script': winguard.build_remove_script(),
        'fw_relaunch_script': norm(fw.relaunch_script('apply', r'D:\Konfig\config.toml')),
        'fw_status_codes': [fw.STATUS_OK, fw.STATUS_PROBLEM, fw.STATUS_NO_VPN],
    }


def golden_remux():
    out = {}
    for container in ('mp4', 'mpegts'):
        rec = Recorder()
        with workdir() as work:
            raw = work / ('raw.mp4' if container == 'mp4' else 'raw.ts')
            raw.write_bytes(b'raw')

            def ffprobe(argv, kw, after=False):
                return g.Result(0, json.dumps(_ffprobe_json(container, after)))

            def ffmpeg(argv, kw):
                Path(argv[-1]).write_bytes(b'clean')
                return g.Result(0, '')

            runner = ScriptedRunner(rec, [ffprobe, ffmpeg, lambda a, k: ffprobe(a, k, True)])
            with contextlib.redirect_stdout(io.StringIO()):
                clean, extension = g.remux(raw, runner)
            out[container] = {'calls': rec.result(), 'clean': norm(clean), 'extension': extension}
    return out


def golden_resolve():
    out = {}
    hosts = CONFIG['voe_hosts']
    voe_answer = lambda title: g.Result(0, json.dumps({'url': 'https://cdn.example/v.mp4?sig=geheim', 'title': title}))
    with patch.object(g, 'SESSION', g.Session()), contextlib.redirect_stdout(io.StringIO()):
        cases = [
            ('voe_e_link', 'https://voe.sx/e/abc123', [voe_answer('Big Buck Bunny')]),
            ('voe_host_without_e', 'https://susanexpectcare.com/abc123', [voe_answer('Film')]),
            ('redirect_first_time', 'https://mediathek.example/redirect/1',
             [g.Result(1, '', 'ERROR: Unsupported URL: https://mediathek.example/redirect/1'),
              g.Result(1, '', 'ERROR: generic failed'), voe_answer('Film 1')]),
            ('redirect_second_same_host', 'https://mediathek.example/redirect/2', [voe_answer('Film 2')]),
            ('redirect_first_fails', 'https://mediathek.example/kaputt',
             [g.Result(1, '', 'kein Ziel'), g.Result(1, '', 'ERROR: Unsupported URL'), g.Result(1, '', 'ERROR: generic failed')]),
            ('http_fails', 'http://plain.example/video',
             [g.Result(1, '', 'ERROR: Unsupported URL: http://plain.example/video'), g.Result(1, '', 'ERROR: generic failed')]),
            ('ytdlp_info', 'https://site.example/watch/42',
             [g.Result(0, json.dumps({'title': 'Ein Titel', 'url': 'https://cdn.site.example/42.mp4'}))]),
        ]
        for name, url, answers in cases:
            rec = Recorder()
            with workdir() as work, patch.object(g, 'emit', rec.emit):
                runner = ScriptedRunner(rec, answers)
                try:
                    item = g.resolve_item(url, None, CONFIG, runner, RecNet(rec), work, '185.159.157.10')
                    result = {k: item[k] for k in ('name', 'media', 'referer', 'voe')}
                    result['info'] = item['info']
                except g.Failure as exc:
                    result = failure(exc)
                out[name] = {'url': url, 'log': rec.result(), 'result': norm(result), 'left_answers': len(runner.answers)}
        out['redirect_hosts'] = sorted(g.SESSION.redirect_hosts)
    out['voe_hosts'] = hosts
    return out


def golden_network():
    out = {}
    exit_ip = '185.159.157.10'
    mullvad_ok = {'ip': exit_ip, 'country': 'Switzerland', 'organization': 'Proton AG'}

    # A: alles ueber Mullvad, IPv6 unerreichbar, Resolver = Exit-IP (keine Geo-Abfrage); zweite Pruefung schnell.
    rec = Recorder()
    runner = NetRunner(rec, {'https://am.i.mullvad.net/json': mullvad_ok,
                             'https://ipv6.am.i.mullvad.net/json': g.Result(7, '', 'no route')}, exit_ip)
    with guard_env(rec), patch.object(g.time, 'sleep', lambda s: rec.log.append({'sleep': s})), \
         contextlib.redirect_stdout(io.StringIO()) as stdout:
        net = g.Network(CONFIG, runner)
        r1 = net.check('IPv4 Statuspruefung')
        r2 = net.check('IPv4 vor Transfer', exit_ip)
    out['A_mullvad'] = {'log': rec.result(), 'returns': [r1, r2], 'stdout': norm(stdout.getvalue())}

    # B: Mullvad 3x unbrauchbar -> ipapi.co; IPv6 erreichbar; anderer Resolver: ipapi.co scheitert -> ipinfo.io;
    #    zweite Pruefung nutzt die gespeicherten Resolver-Geodaten (nur im Speicher).
    rec = Recorder()
    resolver = '185.159.157.53'
    runner = NetRunner(rec, {
        'https://am.i.mullvad.net/json': {},
        'https://ipapi.co/json/': {'ip': exit_ip, 'country_code': 'CH', 'country_name': 'Switzerland', 'org': 'Proton AG'},
        'https://ipv6.am.i.mullvad.net/json': {'ip': '2a07:b944::1', 'country': 'Switzerland', 'organization': 'Proton AG'},
        f'https://ipapi.co/{resolver}/json/': g.Result(22, '', 'HTTP 429'),
        f'https://ipinfo.io/{resolver}/json': {'ip': resolver, 'country': 'CH', 'org': 'AS62371 Proton AG'},
    }, resolver)
    with guard_env(rec), patch.object(g.time, 'sleep', lambda s: rec.log.append({'sleep': s})), \
         contextlib.redirect_stdout(io.StringIO()) as stdout:
        net = g.Network(CONFIG, runner)
        r1 = net.check('IPv4 vor Probe')
        r2 = net.check('IPv4 nach Probe', exit_ip)
        try:
            net.check('IPv4 nach Transfer/Remux', '9.9.9.9')
            r3 = None
        except g.Failure as exc:
            r3 = failure(exc)
    out['B_fallbacks'] = {'log': rec.result(), 'returns': [r1, r2, r3], 'stdout': norm(stdout.getvalue())}

    # C: Heimatland am Ausgang -> Abbruch mit check-Ereignis
    rec = Recorder()
    runner = NetRunner(rec, {'https://am.i.mullvad.net/json': {'ip': exit_ip, 'country': 'Germany', 'organization': 'Proton AG'}}, exit_ip)
    with guard_env(rec), contextlib.redirect_stdout(io.StringIO()) as stdout:
        try:
            g.Network(CONFIG, runner, force=True).check('IPv4 Statuspruefung')
            r = None
        except g.Failure as exc:
            r = failure(exc)
    out['C_home_country'] = {'log': rec.result(), 'returns': r, 'stdout': norm(stdout.getvalue())}

    # D: --skip-check: nur Waechter, keine Netzabfragen
    rec = Recorder()
    runner = NetRunner(rec, {}, exit_ip)
    with guard_env(rec), contextlib.redirect_stdout(io.StringIO()):
        r = g.Network(CONFIG, runner, skip=True).check('IPv4 vor Probe')
    out['D_skip'] = {'log': rec.result(), 'returns': r}

    # json_request-Kommandozeilen direkt
    rec = Recorder()
    runner = ScriptedRunner(rec, [g.Result(0, '{}')] * 4)
    net = g.Network(CONFIG, runner)
    for url, version in (('https://am.i.mullvad.net/json', 4), ('https://ipapi.co/json/', 4),
                         ('https://ipv6.am.i.mullvad.net/json', 6), ('https://ipinfo.io/1.1.1.1/json', 4)):
        net.json_request(url, version)
    out['json_request'] = rec.result()
    return out


def golden_probe_transfer():
    out = {'ydl_common_voe': norm(g.ydl_common('https://voe.sx/')),
           'ydl_common_origin': norm(g.ydl_common(g.origin('https://site.example/watch/42?x=1'))),
           'YDL': norm(g.YDL)}

    rec = Recorder()
    with workdir() as work:
        def probe_ok(argv, kw):
            (kw['cwd'] / 'probe.mp4').write_bytes(b'x')
            return g.Result(0, '')
        with contextlib.redirect_stdout(io.StringIO()):
            r = g.probe(CONFIG, ScriptedRunner(rec, [probe_ok]), RecNet(rec), work)
    out['probe'] = {'log': rec.result(), 'returns': r}

    rec = Recorder()
    with workdir() as work, contextlib.redirect_stdout(io.StringIO()):
        try:
            g.probe(CONFIG, ScriptedRunner(rec, [g.Result(1, '')]), RecNet(rec), work)
            r = None
        except g.Failure as exc:
            r = failure(exc)
    out['probe_fails'] = {'log': rec.result(), 'returns': r}

    def second_ok(argv, kw):
        raw = kw['cwd'] / 'raw.mp4'
        raw.write_bytes(b'valid')
        (kw['cwd'] / 'result-path.txt').write_text(str(raw) + '\n', encoding='utf-8')
        return g.Result(0, '')

    items = {'voe': {'voe': True, 'referer': 'https://voe.sx/', 'info': None, 'media': 'https://cdn.example/x.mp4?sig=geheim'},
             'info_json': {'voe': False, 'referer': 'https://site.example/', 'media': None,
                           'info': {'title': 'T', 'url': 'https://cdn.site.example/42.mp4'}}}
    for name, item in items.items():
        rec = Recorder()
        with workdir() as work, contextlib.redirect_stdout(io.StringIO()):
            raw = g.transfer(dict(item), CONFIG, ScriptedRunner(rec, [g.Result(1, '', 'HTTP 416'), second_ok]),
                             RecNet(rec), work, '185.159.157.10')
            out['transfer_' + name] = {'log': rec.result(), 'raw': norm(raw)}
    rec = Recorder()
    with workdir() as work, contextlib.redirect_stdout(io.StringIO()):
        try:
            g.transfer(dict(items['voe']), CONFIG, ScriptedRunner(rec, [g.Result(1, ''), g.Result(1, '')]),
                       RecNet(rec), work, '185.159.157.10')
            r = None
        except g.Failure as exc:
            r = failure(exc)
    out['transfer_fails'] = {'log': rec.result(), 'returns': r}
    return out


def golden_media_size():
    out = {}
    item = {'voe': True, 'media': 'https://cdn.example/v.mp4?sig=geheim', 'referer': 'https://voe.sx/', 'info': None}
    cases = {
        'head': [g.Result(0, 'HTTP/1.1 200 OK\nContent-Length: 700\n')],
        'range_fallback': [g.Result(22, '', 'HTTP 405'), g.Result(0, 'HTTP/1.1 206\nContent-Range: bytes 0-0/9000\n')],
        'redirect_hop': [g.Result(0, 'HTTP/1.1 302 Found\nLocation: https://cdn2.example/v.mp4?sig=zwei\n'),
                         g.Result(0, 'HTTP/1.1 200 OK\nContent-Length: 800\n')],
        'redirect_private': [g.Result(0, 'HTTP/1.1 302 Found\nLocation: https://127.0.0.1/x\n')],
        'nothing': [g.Result(22, ''), g.Result(22, '')],
    }
    for name, answers in cases.items():
        rec = Recorder()

        def public(host):
            rec.log.append({'public_host': host})
            if host in ('127.0.0.1',):
                raise ValueError('privat')

        with workdir() as work, patch.object(g, 'public_host', public):
            size = g.media_size(dict(item), ScriptedRunner(rec, answers), work)
        out[name] = {'log': rec.result(), 'size': size}
    return out


def golden_preview_sizes():
    out = {}

    def runner_for(rec):
        def answer(argv, kw):
            argv = list(map(str, argv))
            if len(argv) > 2 and argv[2].endswith('voe_resolver.py'):
                if '/e/' in argv[3]:
                    return g.Result(0, json.dumps({'url': 'https://cdn.example/v.mp4?sig=geheim', 'title': 'Big Buck Bunny'}))
                return g.Result(1, '', 'kein VOE')
            if argv[0] == g.CURL:
                return g.Result(0, 'HTTP/1.1 200 OK\nContent-Length: 5000000\n')
            return g.Result(1, '', 'ERROR: [generic] 404 Not Found')
        return ScriptedRunner(rec, [answer] * 20)

    urls = ['https://voe.sx/e/abc123', 'https://kaputt.example/video/2']
    for mode in ('preview', 'sizes'):
        rec = Recorder()
        with workdir() as work, patch.object(g, 'SESSION', g.Session()), patch.object(g, 'emit', rec.emit), \
             patch.object(g, 'public_host', lambda h: None), contextlib.redirect_stdout(io.StringIO()) as stdout:
            code = getattr(g, mode)(CONFIG, runner_for(rec), RecNet(rec), FakeStore(work), list(urls))
        out[mode] = {'log': rec.result(), 'code': code, 'stdout': norm(stdout.getvalue())}

    # Sicherheitsabbruch (Exit 2) beim Pruefpunkt vor dem zweiten Eintrag: sofort Ende
    for mode, label in (('preview', 'IPv4 vor Vorschau-Eintrag'), ('sizes', 'IPv4 vor Groessen-Eintrag')):
        rec = Recorder()

        class Net(RecNet):
            count = 0

            def check(self, lab, expected=None):
                self.rec.check(lab, expected)
                if lab == label:
                    Net.count += 1
                    if Net.count == 2:
                        g.fail(2, 'EXIT_IP_CHANGED', 'simuliert')
                return self.ip

        with workdir() as work, patch.object(g, 'SESSION', g.Session()), patch.object(g, 'emit', rec.emit), \
             patch.object(g, 'public_host', lambda h: None), contextlib.redirect_stdout(io.StringIO()):
            try:
                getattr(g, mode)(CONFIG, runner_for(rec), Net(rec), FakeStore(work), list(urls))
                r = None
            except g.Failure as exc:
                r = failure(exc)
        out[mode + '_fatal'] = {'log': rec.result(), 'returns': r}
    return out


def golden_guard():
    rec = Recorder()
    runner = NetRunner(rec, {}, '')
    steps = []
    with guard_env(rec), contextlib.redirect_stdout(io.StringIO()) as stdout:
        def step(name):
            rec.log.append({'step': name})
            try:
                g.ensure_guard(runner, CONFIG)
            except g.Failure as exc:
                rec.log.append(failure(exc))
        step('first')
        step('second_same_state')
        runner.state = state_json(vpn='10.2.0.9')
        step('changed_vpn_ip')
        step('changed_vpn_ip_again')
        runner.state = state_json(lan='192.168.1.77')
        step('changed_lan_ip')
        runner.state = state_json(vpn=None)
        step('vpn_gone')
    out = {'log': rec.result(), 'stdout': norm(stdout.getvalue())}

    # Fehlerfaelle der vollen Pruefung
    cases = {
        'selftest_open': (state_json(), 'OPEN:10060'),
        'rules_stale': (state_json().replace('10.2.0.3-126', '10.2.0.4-126'), 'BLOCKED'),
        'no_other_address': (json.dumps(dict(json.loads(state_json()), Adapters=json.loads(state_json())['Adapters'][1:])), 'BLOCKED'),
    }
    for name, (st, selftest) in cases.items():
        rec = Recorder()
        runner = NetRunner(rec, {}, '', state=st, selftest=selftest)
        with guard_env(rec), contextlib.redirect_stdout(io.StringIO()) as stdout:
            try:
                g.ensure_guard(runner, CONFIG)
            except g.Failure as exc:
                rec.log.append(failure(exc))
        out[name] = {'log': rec.result(), 'stdout': norm(stdout.getvalue())}
    for name, config in (('enforce_off', dict(CONFIG, firewall_enforce=False)),
                         ('no_patterns', dict(CONFIG, vpn_adapter_patterns=[], firewall_enforce=False))):
        rec = Recorder()
        runner = NetRunner(rec, {}, '')
        with guard_env(rec), contextlib.redirect_stdout(io.StringIO()) as stdout:
            g.ensure_guard(runner, config)
            g.ensure_guard(runner, config)
        out[name] = {'log': rec.result(), 'stdout': norm(stdout.getvalue())}
    return out


def golden_ui_headers():
    out = {}
    with tempfile.TemporaryDirectory() as d:
        config = g.load_config(CONFIG_PATH)
        config['storage'] = d
        state = ui.State(config, CONFIG_PATH)
        state.start_worker = lambda mode: True
        state.start_sizes = lambda: True
        token = 'testtoken-1234567890'
        port = [0]
        server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), ui.make_handler(state, token))
        port[0] = server.server_address[1]
        threading.Thread(target=server.serve_forever, daemon=True).start()
        try:
            def request(method, path, body=None, headers=None, with_token=True, host=None, raw=None):
                conn = http.client.HTTPConnection('127.0.0.1', port[0], timeout=5)
                h = {'Host': host or f'127.0.0.1:{port[0]}'}
                if with_token:
                    h['X-QSGrab-Token'] = token
                data = raw
                if body is not None:
                    data = json.dumps(body).encode()
                    h['Content-Type'] = 'application/json'
                h.update(headers or {})
                conn.request(method, path, body=data, headers=h)
                r = conn.getresponse()
                r.read()
                conn.close()
                hdrs = {k: v for k, v in r.getheaders() if k.lower() not in ('date', 'server', 'content-length')}
                return {'status': r.status, 'headers': dict(sorted(hdrs.items()))}

            add = {'urls': ['https://a.example/x.mp4']}
            out['GET /'] = request('GET', '/', with_token=False)
            out['GET /app.js'] = request('GET', '/app.js', with_token=False)
            out['GET /api/state'] = request('GET', '/api/state')
            out['GET /api/state no token'] = request('GET', '/api/state', with_token=False)
            out['GET /api/state wrong token'] = request('GET', '/api/state', with_token=False, headers={'X-QSGrab-Token': 'falsch'})
            out['GET /api/state wrong host'] = request('GET', '/api/state', host='evil.example')
            out['GET / localhost host'] = request('GET', '/', with_token=False, host=f'localhost:{port[0]}')
            out['GET unknown'] = request('GET', '/ui.py', with_token=False)
            out['POST no token'] = request('POST', '/api/queue/add', add, with_token=False)
            out['POST origin null'] = request('POST', '/api/queue/add', add, headers={'Origin': 'null'})
            out['POST foreign origin'] = request('POST', '/api/queue/add', add, headers={'Origin': 'https://evil.example'})
            out['POST non-JSON'] = request('POST', '/api/queue/add', raw=b'urls=x',
                                           headers={'Content-Type': 'application/x-www-form-urlencoded'})
            out['POST oversized'] = request('POST', '/api/queue/add', {'urls': ['https://a.example/' + 'x' * 70000]})
            out['POST unknown path'] = request('POST', '/api/does-not-exist', {})
            out['queue_after'] = len(state.queue)
        finally:
            server.shutdown()
            server.server_close()
    out['CSP'] = ui.CSP
    out['MAX_BODY'] = ui.MAX_BODY
    return out


def golden_emit():
    out = {}
    buf = io.StringIO()
    session = g.Session()   # phase 'start'
    session.events = True
    with patch.object(g, 'SESSION', session), \
         patch.object(g.time, 'time', lambda: 1700000000.12345), contextlib.redirect_stdout(buf):
        g.emit('check', key='vpn', ok=True, detail='ProtonVPN · 10.2.0.2 https://geheim.example/x?sig=1', n=3, none=None)
        g.phase('download')
        g.progress_event('[download]  42.5% of ~  12.34MiB at    1.50MiB/s ETA 00:07')
        g.progress_event('[download] 100% of 5.00MiB in 00:00:02 at Unknown B/s')
        g.progress_event('keine Fortschrittszeile')
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            g.error(g.Failure(2, 'EXIT_IP_CHANGED', 'Exit-IP geaendert https://x.example/a'))
            g.error(g.Failure(4, 'LINK_RESOLUTION_FAILED', 'nicht aufloesbar'))
    out['stdout_lines'] = buf.getvalue().splitlines()
    out['stderr_lines'] = err.getvalue().splitlines()
    buf = io.StringIO()
    with patch.object(g, 'SESSION', g.Session()), contextlib.redirect_stdout(buf):
        g.emit('check', key='vpn')
    out['events_off'] = buf.getvalue()
    out['EVENT_PREFIX'] = g.EVENT_PREFIX
    return out


def golden_codes():
    """Alle fail(<Code>, '<KENNUNG>')- und Failure(...)-Stellen in den Programmdateien -> Codes je Kennung.
    Code darf eine Zahl oder ein benannter Wert aus grab (z. B. spaetere Exitcode-Konstante) sein."""
    pattern = re.compile(r"(?:\bfail|\bFailure)\(\s*([A-Za-z_][\w.]*|\d+)\s*,\s*'([A-Z][A-Z0-9_]+)'")
    idents = {}
    unresolved = []
    for path in sorted(Path(g.APP).glob('*.py')):
        text = path.read_text(encoding='utf-8')
        for code, ident in pattern.findall(text):
            if not code.isdigit():
                value = g
                try:
                    for part in code.split('.'):
                        value = getattr(value, part)
                    code = str(int(value))
                except (AttributeError, TypeError, ValueError):
                    unresolved.append(f'{code}:{ident}')
                    continue
            idents.setdefault(ident, set()).add(int(code))
    # check_rules liefert (Kennung, Meldung); ensure_guard bricht damit per fail(2, *problem) ab.
    for ident in re.findall(r"return \('([A-Z][A-Z0-9_]+)',", Path(winguard.__file__).read_text(encoding='utf-8')):
        idents.setdefault(ident, set()).add(2)
    return {'idents': {k: sorted(v) for k, v in sorted(idents.items())}, 'unresolved': sorted(unresolved),
            'ERROR_CHECK': dict(sorted(g.ERROR_CHECK.items())), 'CHECK_KEYS': list(g.CHECK_KEYS),
            'REDIRECT_HOSTS_ENV': g.REDIRECT_HOSTS_ENV, 'HOST_RE': g.HOST_RE.pattern,
            'UI_BROWSERS': list(g.UI_BROWSERS), 'MAX_PREVIEW': g.MAX_PREVIEW,
            'check_key': {label: g.check_key(label) for label in ('IPv4 vor Probe', 'IPv6', 'DNS', 'IPv4 Statuspruefung')}}


GROUPS = {
    'winguard': golden_winguard,
    'remux': golden_remux,
    'resolve_item': golden_resolve,
    'network': golden_network,
    'probe_transfer': golden_probe_transfer,
    'media_size': golden_media_size,
    'preview_sizes': golden_preview_sizes,
    'ensure_guard': golden_guard,
    'ui_headers': golden_ui_headers,
    'emit': golden_emit,
    'codes': golden_codes,
}


def build(name):
    return json.loads(json.dumps(GROUPS[name](), ensure_ascii=False))


def personal_markers():
    """Begriffe, die nie in einer versionierten Datei stehen duerfen (wie make-release.ps1)."""
    markers = {'Users\\', str(Path.home())}
    user = os.environ.get('USERNAME') or ''
    markers |= {user} | {part for part in re.split(r'\s+', user) if len(part) >= 3}
    for key in ('COMPUTERNAME', 'USERPROFILE', 'TEMP'):
        if os.environ.get(key):
            markers.add(os.environ[key])
    return sorted(m for m in markers if m)


class TestGolden(unittest.TestCase):
    maxDiff = None

    @classmethod
    def setUpClass(cls):
        if os.environ.get('QSGRAB_WRITE_GOLDEN') == '1':
            data = {name: build(name) for name in GROUPS}
            text = json.dumps(data, ensure_ascii=False, indent=1, sort_keys=True) + '\n'
            for marker in personal_markers():
                if marker.casefold() in text.casefold():
                    raise RuntimeError('Persoenliche Daten in den Goldwerten - nicht geschrieben.')
            GOLDEN.write_text(text, encoding='utf-8', newline='\n')
        cls.golden = json.loads(GOLDEN.read_text(encoding='utf-8'))

    def compare(self, name):
        self.assertEqual(build(name), self.golden[name])

    def test_fixture_has_no_personal_data(self):
        """Die Goldwert-Datei enthaelt weder Benutzername noch Profilpfad, Rechnername oder Users\\-Pfade."""
        text = GOLDEN.read_text(encoding='utf-8').casefold()
        for marker in personal_markers():
            self.assertNotIn(marker.casefold(), text)
        self.assertEqual(sorted(self.golden), sorted(GROUPS))

    def test_winguard_scripts(self):
        """PowerShell-Abfragen, Selbsttest-Code, Regelnamen und das Anlege-/Entfernskript bleiben zeichengleich."""
        self.compare('winguard')

    def test_remux_command_lines(self):
        """ffmpeg- und ffprobe-Kommandozeilen des Remux (mp4 und mpegts -> mkv) samt Zeitlimits bleiben gleich."""
        self.compare('remux')

    def test_resolve_item_paths(self):
        """Aufloesung: VOE, Weiterleitung (erstes Mal, gemerkte Seite), http-Fehler - Aufrufe und Pruefpunkte in Reihenfolge."""
        self.compare('resolve_item')

    def test_network_checks(self):
        """Netzpruefung: curl/nslookup-Aufrufe, Ausweichwege, Pausen, Pruefpunkt-Ereignisse und Ausgaben bleiben gleich."""
        self.compare('network')

    def test_probe_and_transfer(self):
        """Probe und Transfer (mit Wiederholung ohne schnelle Schalter): yt-dlp-Kommandozeilen und Pruefpunkte."""
        self.compare('probe_transfer')

    def test_media_size_requests(self):
        """Groessenabfrage: curl-Aufrufe, Standardeingabe, Weiterleitungsschritt und Hostpruefung bleiben gleich."""
        self.compare('media_size')

    def test_preview_and_sizes_sequence(self):
        """Vorschau und Groessen: Pruefpunkte und Ereignisse fuer zwei Links (zweiter scheitert), Exit 2 bricht sofort ab."""
        self.compare('preview_sizes')

    def test_ensure_guard_sequence(self):
        """Waechter: volle/schnelle Abfrage, Selbsttest und check-Ereignisse bei gleichem und geaendertem Zustand."""
        self.compare('ensure_guard')

    def test_ui_security_headers(self):
        """Oberflaeche: Sicherheits-Kopfzeilen und Statuscodes fuer Token-, Host-, Origin-, JSON- und Groessenpruefung."""
        self.compare('ui_headers')

    def test_emit_format(self):
        """Ereigniszeilen @@QSGRAB {json} und FEHLER-Zeile auf stderr behalten ihr genaues Format."""
        self.compare('emit')

    def test_error_codes(self):
        """Fehlerkennungen und ihre Exitcodes, ERROR_CHECK und CHECK_KEYS bleiben gleich."""
        self.compare('codes')


if __name__ == '__main__':
    unittest.main()
