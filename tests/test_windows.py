"""Tests der Windows-Portierung: Plattformbausteine, Adapterpruefung, Konfiguration.

Laufen auf Windows und (soweit sinnvoll) auch auf Linux. Sie ersetzen keinen
echten VPN-/Kill-Switch-Test.
"""
import contextlib
import io
import ipaddress
import json
import os
from pathlib import Path
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import grab as g
import syscompat as sc
import winguard
from helpers import temp_dir, write_config

CONFIG = g.load_config(Path(g.__file__).with_name('config.default.toml'))

PROGRAMS = [r'C:\Users\Beispiel\Quite Safe Grab\python\python.exe', r'C:\Tools\qsgrab\tools\ffmpeg.exe',
            r'C:\Tools\qsgrab\tools\ffprobe.exe', r'C:\Windows\System32\curl.exe', r'C:\Windows\System32\nslookup.exe']
VPN_IP = '10.2.0.2'
LAN_IP = '192.168.178.20'
# Erwartete Sperrbereiche fest eingetragen (nicht mit der Umsetzung berechnet): alles ausser Loopback und VPN-Adresse.
V4_FOR = {'10.2.0.2': ['0.0.0.0-10.2.0.1', '10.2.0.3-126.255.255.255', '128.0.0.0-255.255.255.255'],
          '10.2.0.9': ['0.0.0.0-10.2.0.8', '10.2.0.10-126.255.255.255', '128.0.0.0-255.255.255.255']}


def adapters(vpn=VPN_IP, lan=LAN_IP):
    out = [{'Name': 'WLAN', 'InterfaceDescription': 'Intel(R) Wi-Fi 6', 'IPv4': [lan]}]
    if vpn:
        out.append({'Name': 'ProtonVPN', 'InterfaceDescription': 'WireGuard Tunnel', 'IPv4': [vpn]})
    return out


def good_rules(vpn=VPN_IP, programs=PROGRAMS):
    v4 = list(V4_FOR[vpn])
    rules = []
    for i, program in enumerate(programs, 1):
        rules.append({'Name': f'QuiteSafeGrab-v4-{i}', 'Enabled': 'True', 'Direction': 'Outbound', 'Action': 'Block',
                      'Program': program, 'LocalAddress': v4})
        rules.append({'Name': f'QuiteSafeGrab-v6-{i}', 'Enabled': 'True', 'Direction': 'Outbound', 'Action': 'Block',
                      'Program': program, 'LocalAddress': ['::/1', '8000::/1']})
    return rules


def state_json(ad=None, rules=None, profiles=None, rules_error=''):
    return json.dumps({'Adapters': adapters() if ad is None else ad, 'Rules': good_rules() if rules is None else rules,
                       'Profiles': [{'Name': n, 'Enabled': 'True'} for n in ('Domain', 'Private', 'Public')] if profiles is None else profiles,
                       'RulesError': rules_error})


def state(**kw):
    return winguard.parse_state(state_json(**kw))


class TestWinguardLogic(unittest.TestCase):
    def test_blocked_ranges_exclude_only_loopback_and_vpn(self):
        self.assertEqual(winguard.format_v4_ranges(winguard.blocked_v4_ranges([VPN_IP])), V4_FOR[VPN_IP])
        self.assertEqual(winguard.format_v4_ranges(winguard.blocked_v4_ranges(['10.2.0.9'])), V4_FOR['10.2.0.9'])
        ranges = winguard.blocked_v4_ranges([VPN_IP, '10.2.0.3'])
        self.assertEqual(winguard.format_v4_ranges(ranges)[1], '10.2.0.4-126.255.255.255')
        for ip, blocked in ((VPN_IP, False), ('127.0.0.1', False), ('192.168.178.20', True), ('10.2.0.1', True),
                            ('10.2.0.3', True), ('8.8.8.8', True), ('169.254.9.9', True), ('0.0.0.0', True), ('255.255.255.255', True)):
            self.assertEqual(winguard.touches(winguard.blocked_v4_ranges([VPN_IP]), int(ipaddress.IPv4Address(ip))), blocked, ip)

    def test_unusable_vpn_addresses_refused(self):
        for bad in ('127.0.0.1', '0.0.0.0', '169.254.1.1', '224.0.0.1', 'nope', ''):
            self.assertIsNone(winguard.usable_ipv4(bad))
            with self.assertRaises(ValueError):
                winguard.blocked_v4_ranges([bad])

    def test_parse_entry_forms(self):
        self.assertEqual(winguard.parse_entry('10.0.0.1-10.0.0.9'), (4, 167772161, 167772169))
        self.assertEqual(winguard.parse_entry('10.0.0.0/8'), (4, 167772160, 184549375))
        self.assertEqual(winguard.parse_entry('10.0.0.0/255.0.0.0'), (4, 167772160, 184549375))
        self.assertEqual(winguard.parse_entry('10.0.0.1'), (4, 167772161, 167772161))
        self.assertEqual(winguard.parse_entry('::/1'), (6, 0, 2 ** 127 - 1))
        self.assertIsNone(winguard.parse_entry('Any'))
        with self.assertRaises(ValueError):
            winguard.parse_entry('LocalSubnet')

    def test_state_parsing_is_tolerant_and_strict(self):
        single = {'Adapters': {'Name': 'ProTUN', 'InterfaceDescription': 'x', 'IPv4': '10.2.0.2'}, 'Rules': [], 'Profiles': [], 'RulesError': ''}
        parsed = winguard.parse_state('\ufeff' + json.dumps(single))
        self.assertEqual(parsed['adapters'][0]['ipv4'], ['10.2.0.2'])
        for bad in ('', 'kein json', '[1]', json.dumps({'RulesError': 'Zugriff verweigert'})):
            with self.assertRaises(ValueError):
                winguard.parse_state(bad)

    def test_vpn_and_other_addresses(self):
        st = state(ad=adapters() + [{'Name': 'Loopback', 'InterfaceDescription': 'lo', 'IPv4': ['127.0.0.1']},
                                    {'Name': 'Ethernet', 'InterfaceDescription': 'Realtek', 'IPv4': ['169.254.3.4', '192.168.1.5']}])
        vpn = winguard.vpn_adapters(st, ['proton'])
        self.assertEqual(winguard.vpn_ipv4(vpn), [VPN_IP])
        self.assertEqual(winguard.other_ipv4(st, ['proton']), ['169.254.3.4', '192.168.1.5', LAN_IP])

    def test_rules_ok(self):
        self.assertIsNone(winguard.check_rules(state(), PROGRAMS, [VPN_IP]))
        # Windows darf Gross-/Kleinschreibung und Rueckwaertsstriche anders liefern; einzelne Bereiche duerfen aufgeteilt sein.
        rules = good_rules()
        rules[0]['Program'] = rules[0]['Program'].upper()
        rules[0]['LocalAddress'] = ['0.0.0.0-9.255.255.255', '10.0.0.0-10.2.0.1', '10.2.0.3-126.255.255.255', '128.0.0.0/1']
        self.assertIsNone(winguard.check_rules(state(rules=rules), PROGRAMS, [VPN_IP]))

    def test_rules_fail_closed(self):
        def broken(change):
            rules = good_rules()
            change(rules)
            return winguard.check_rules(state(rules=rules), PROGRAMS, [VPN_IP])
        cases = {
            'stale vpn address': lambda r: r[0].update(LocalAddress=list(V4_FOR['10.2.0.9'])),
            'disabled': lambda r: r[0].update(Enabled='False'),
            'allow instead of block': lambda r: r[2].update(Action='Allow'),
            'inbound': lambda r: r[0].update(Direction='Inbound'),
            'program missing': lambda r: [r.pop(0), r.pop(0)],
            'v6 missing': lambda r: r.pop(1),
            'gap in v4': lambda r: r[0].update(LocalAddress=['0.0.0.0-10.2.0.1', '10.2.0.3-100.0.0.0']),
            'keyword address': lambda r: r[0].update(LocalAddress=['LocalSubnet']),
        }
        for name, change in cases.items():
            result = broken(change)
            self.assertIsNotNone(result, name)
            self.assertEqual(result[0], 'FIREWALL_RULES_MISSING', name)
        blocks_vpn = broken(lambda r: r[0].update(LocalAddress=['Any']))
        self.assertEqual(blocks_vpn[0], 'FIREWALL_BLOCKS_VPN')
        off = winguard.check_rules(state(profiles=[{'Name': 'Public', 'Enabled': 'False'}]), PROGRAMS, [VPN_IP])
        self.assertEqual(off[0], 'FIREWALL_DISABLED')
        self.assertEqual(winguard.check_rules(state(profiles=[]), PROGRAMS, [VPN_IP])[0], 'FIREWALL_DISABLED')

    def test_selftest_parsing(self):
        self.assertEqual(winguard.parse_selftest('SELFTEST 1.1.1.1 BLOCKED\nSELFTEST 2.2.2.2 OPEN:10060\n', ['1.1.1.1', '2.2.2.2', '3.3.3.3']),
                         ['2.2.2.2', '3.3.3.3'])
        self.assertEqual(winguard.parse_selftest('', ['1.1.1.1']), ['1.1.1.1'])
        out = 'SELFTEST 1.1.1.1 NOADDR\nSELFTEST 2.2.2.2 NOROUTE\nSELFTEST 3.3.3.3 OPEN:connected\nSELFTEST 4.4.4.4 OPEN:10060\n'
        self.assertEqual(winguard.parse_selftest(out, ['1.1.1.1', '2.2.2.2', '3.3.3.3', '4.4.4.4']), ['3.3.3.3', '4.4.4.4'])

    def test_selftest_code_maps_only_known_safe_errors(self):
        import socket
        cases = {10013: 'BLOCKED', 10049: 'NOADDR', 10051: 'NOROUTE', 10065: 'NOROUTE', 10060: 'OPEN:10060', 10061: 'OPEN:10061'}
        for code, expected in cases.items():
            class FakeSocket:
                def __init__(self, *a): pass
                def settimeout(self, t): pass
                def bind(self, addr): pass
                def connect(self, addr):
                    e = OSError('x'); e.winerror = code; raise e
                def close(self): pass
            buf = io.StringIO()
            with patch.object(socket, 'socket', FakeSocket), patch.object(sys, 'argv', ['x', '5.5.5.5']), contextlib.redirect_stdout(buf):
                exec(winguard.SELFTEST_CODE, {})
            self.assertEqual(buf.getvalue().split(), ['SELFTEST', '5.5.5.5', expected], code)

    def test_unbound_addresses_skipped(self):
        ad = adapters() + [{'Name': 'Ethernet 2', 'InterfaceDescription': 'x', 'IPv4': ['169.254.10.59', '192.168.1.5'],
                            'IPv4Unbound': '169.254.10.59'}]
        self.assertEqual(winguard.other_ipv4(state(ad=ad), ['proton']), ['192.168.1.5', LAN_IP])

    def test_apply_script_quoting_and_content(self):
        script = winguard.build_apply_script([r"C:\Users\O'Brien\tools\ffmpeg.exe"], [VPN_IP])
        self.assertIn("'C:\\Users\\O''Brien\\tools\\ffmpeg.exe'", script)
        self.assertIn('-Direction Outbound -Action Block', script)
        self.assertIn("'0.0.0.0-10.2.0.1','10.2.0.3-126.255.255.255','128.0.0.0-255.255.255.255'", script)
        self.assertIn("'::/1','8000::/1'", script)
        self.assertEqual(script.count('New-NetFirewallRule'), 2)
        self.assertIn("Remove-NetFirewallRule", script)
        # Alte Regeln aus der Zeit vor der Umbenennung werden mit entfernt, neue heissen QuiteSafeGrab-*
        for script_ in (script, winguard.build_remove_script()):
            self.assertIn("-Name 'PiGrab-*'", script_)
            self.assertIn("-Name 'QuiteSafeGrab-*'", script_)
        self.assertIn("New-NetFirewallRule -Name 'QuiteSafeGrab-v4-1'", script)
        self.assertNotIn("New-NetFirewallRule -Name 'PiGrab", script)
        for bad in ('ffmpeg.exe', 'C:\\a\nb.exe'):
            with self.assertRaises(ValueError):
                winguard.build_apply_script([bad], [VPN_IP])

    def test_fw_status_codes_and_relaunch_keep_config(self):
        import fw
        st = state()
        with patch.object(fw, 'query', return_value=(st, [], [])), patch.object(g, 'guard_programs', return_value=PROGRAMS), \
             contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(fw.status(CONFIG), fw.STATUS_NO_VPN)   # kein VPN: eigener Code, kein Textvergleich
        vpn = winguard.vpn_adapters(st, ['proton'])
        with patch.object(fw, 'query', return_value=(st, vpn, [VPN_IP])), patch.object(g, 'guard_programs', return_value=PROGRAMS), \
             contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(fw.status(CONFIG), fw.STATUS_OK)
        script = fw.relaunch_script('apply', r'D:\Eigene Konfig\config.toml')
        self.assertIn('--config', script)
        self.assertIn('Eigene Konfig', script)
        self.assertIn('-Verb RunAs', script)

    def fw_vpn(self, answer, config_path=None):
        """fw.py vpn mit nachgestellter Adapterabfrage; liefert (Exitcode, Ausgabe, Aufrufe)."""
        import fw
        calls = []

        def run(argv, timeout):
            calls.append(argv)
            if isinstance(answer, BaseException):
                raise answer
            return answer
        path = config_path or str(Path(g.__file__).with_name('config.default.toml'))
        with patch.object(fw, 'run', run), contextlib.redirect_stdout(io.StringIO()) as out:
            code = fw.main(['vpn', '--config', path])
        return code, out.getvalue(), calls

    def test_fw_vpn_only_zero_with_vpn_ipv4(self):
        """V2: nur eine gelungene Abfrage mit VPN-Adapter + IPv4 ergibt 0 (Update-Suche darf GitHub fragen)."""
        import fw
        import subprocess
        quick = winguard.powershell_args(winguard.QUICK_STATE_SCRIPT)
        code, out, calls = self.fw_vpn((0, json.dumps({'Adapters': adapters()}), ''))
        self.assertEqual(code, fw.VPN_UP)
        self.assertEqual(code, 0)
        self.assertIn('VPN verbunden', out)
        self.assertEqual(calls, [[winguard.POWERSHELL] + quick])   # nur lesen: eine Adapterabfrage, keine Regel
        cases = [
            ((0, json.dumps({'Adapters': adapters(vpn=None)}), ''), fw.VPN_DOWN),
            ((0, json.dumps({'Adapters': [{'Name': 'ProtonVPN', 'InterfaceDescription': 'x', 'IPv4': []}]}), ''), fw.VPN_DOWN),
            ((1, '', 'Zugriff verweigert'), fw.VPN_QUERY_FAILED),
            ((0, 'kein json', ''), fw.VPN_QUERY_FAILED),
            (subprocess.TimeoutExpired('powershell', 60), fw.VPN_QUERY_FAILED),
            (OSError('kaputt'), fw.VPN_QUERY_FAILED),
        ]
        for answer, expected in cases:
            code, out, calls = self.fw_vpn(answer)
            self.assertEqual(code, expected, answer)
            self.assertNotEqual(code, 0)
            self.assertTrue(out.strip())
        self.assertEqual((fw.VPN_CONFIG_ERROR, fw.VPN_QUERY_FAILED, fw.VPN_DOWN), (1, 2, 3))

    def test_fw_vpn_invalid_config_is_not_vpn_up(self):
        import fw
        vpn_up = (0, json.dumps({'Adapters': adapters()}), '')
        bad = write_config(self, lambda t: 'kein = [toml')
        code, out, calls = self.fw_vpn(vpn_up, str(bad))
        self.assertEqual((code, calls), (fw.VPN_CONFIG_ERROR, []))
        code, out, calls = self.fw_vpn(vpn_up, str(temp_dir(self) / 'fehlt.toml'))
        self.assertEqual((code, calls), (fw.VPN_CONFIG_ERROR, []))
        empty = write_config(self, lambda t: t.replace('["Proton", "ProTUN"]', '[]').replace('firewall_enforce = true', 'firewall_enforce = false'))
        code, out, calls = self.fw_vpn(vpn_up, str(empty))
        self.assertNotEqual(code, 0)   # ohne Adaptermuster ist kein VPN nachweisbar
        self.assertEqual(calls, [])

    def test_powershell_args_roundtrip(self):
        import base64
        args = winguard.powershell_args('Write-Output "x"')
        self.assertEqual(base64.b64decode(args[-1]).decode('utf-16-le'), 'Write-Output "x"')
        # Sicherheitsteil: Skript nur kodiert (kein -Command mit Klartext), nie interaktiv
        self.assertEqual(args[-2], '-EncodedCommand')
        self.assertIn('-NonInteractive', args)
        self.assertNotIn('-Command', args)


QUICK_ENCODED = winguard.powershell_args(winguard.QUICK_STATE_SCRIPT)[-1]


class FakeRunner:
    """Antwortet auf PowerShell-Abfrage und Selbsttest; merkt sich die Aufrufe.
    kinds: 'quick' (nur Adapter), 'full' (Adapter + Regeln) oder 'selftest:<ip,...>' je Aufruf."""
    def __init__(self, query, selftest='SELFTEST {ip} BLOCKED'):
        self.query, self.selftest, self.calls, self.kinds = query, selftest, [], []

    def run(self, argv, **kw):
        self.calls.append(argv)
        if argv[0] == g.POWERSHELL:
            self.kinds.append('quick' if argv[-1] == QUICK_ENCODED else 'full')
            return self.query if isinstance(self.query, g.Result) else g.Result(0, self.query)
        ips = argv[argv.index(g.winguard.SELFTEST_CODE) + 1:]
        self.kinds.append('selftest:' + ','.join(ips))
        return g.Result(0, '\n'.join(self.selftest.format(ip=ip) for ip in ips))


class TestGuard(unittest.TestCase):
    @contextlib.contextmanager
    def run_session(self, platform='win32'):
        """Ein grab.py-Lauf: frische Session (Waechter-Zwischenspeicher leer), feste Programmliste."""
        with patch.object(g.sys, 'platform', platform), patch.object(g, 'guard_programs', return_value=PROGRAMS), \
             patch.object(g, 'SESSION', g.Session()), contextlib.redirect_stdout(io.StringIO()) as out:
            yield out

    def guard(self, runner, config=CONFIG, platform='win32'):
        with self.run_session(platform) as out:
            g.ensure_guard(runner, config)
        return out.getvalue()

    def fails(self, runner, ident, config=CONFIG):
        with self.assertRaises(g.Failure) as caught:
            self.guard(runner, config)
        self.assertEqual((caught.exception.code, caught.exception.ident), (2, ident))

    def test_full_pass_runs_selftest_for_non_vpn_address(self):
        runner = FakeRunner(state_json())
        out = self.guard(runner)
        self.assertEqual(runner.calls[0][0], g.POWERSHELL)
        self.assertIn('-EncodedCommand', runner.calls[0])
        self.assertEqual(runner.kinds, ['full', 'selftest:' + LAN_IP])
        self.assertIn('Selbsttest bestanden', out)

    def test_selftest_runs_once_per_vpn_address(self):
        runner = FakeRunner(state_json())
        with self.run_session():
            g.ensure_guard(runner, CONFIG)
            g.ensure_guard(runner, CONFIG)
        self.assertEqual(runner.kinds, ['full', 'selftest:' + LAN_IP, 'quick'])  # 2 Abfragen + 1 Selbsttest

    def test_quick_check_after_full_pass_and_full_again_on_change(self):
        self.assertNotIn('Get-NetFirewallRule', winguard.QUICK_STATE_SCRIPT)
        runner = FakeRunner(state_json())
        with self.run_session():
            g.ensure_guard(runner, CONFIG)
            g.ensure_guard(runner, CONFIG)
            self.assertEqual(runner.kinds, ['full', 'selftest:' + LAN_IP, 'quick'])
            runner.kinds.clear()
            runner.query = state_json(ad=adapters(vpn='10.2.0.9'), rules=good_rules(vpn='10.2.0.9'))   # neue VPN-Adresse
            g.ensure_guard(runner, CONFIG)
            self.assertEqual(runner.kinds, ['quick', 'full', 'selftest:' + LAN_IP])
            runner.query = state_json(ad=adapters(vpn=None))   # VPN weg -> volle Pruefung meldet den Fehler
            with self.assertRaises(g.Failure) as caught:
                g.ensure_guard(runner, CONFIG)
            self.assertEqual(caught.exception.ident, 'VPN_ADAPTER_MISSING')

    def test_new_vpn_address_with_old_rules_stops_in_same_run(self):
        """Nach bestandener Pruefung wechselt die VPN-Adresse, die Regeln gelten noch fuer die alte:
        die schnelle Pruefung reicht nicht, die volle stoppt mit FIREWALL_RULES_MISSING."""
        runner = FakeRunner(state_json())
        with self.run_session():
            g.ensure_guard(runner, CONFIG)
            runner.kinds.clear()
            runner.query = state_json(ad=adapters(vpn='10.2.0.9'))   # Regeln weiter fuer 10.2.0.2
            with self.assertRaises(g.Failure) as caught:
                g.ensure_guard(runner, CONFIG)
            self.assertEqual((caught.exception.code, caught.exception.ident), (2, 'FIREWALL_RULES_MISSING'))
            self.assertEqual(runner.kinds, ['quick', 'full'])   # kein Selbsttest, kein Weiterlaufen
            with self.assertRaises(g.Failure) as caught:       # bleibt gesperrt, auch beim naechsten Pruefpunkt
                g.ensure_guard(runner, CONFIG)
            self.assertEqual(caught.exception.ident, 'FIREWALL_RULES_MISSING')

    def test_new_lan_address_gets_full_check_and_selftest(self):
        """V1: Selbsttest-Schluessel = guard_key (inkl. Nicht-VPN-Adressen). Neue LAN-Adresse B im selben Lauf:
        volle Pruefung UND Selbsttest fuer B."""
        lan_b = '192.168.1.77'
        runner = FakeRunner(state_json())
        with self.run_session():
            g.ensure_guard(runner, CONFIG)
            self.assertEqual(runner.kinds, ['full', 'selftest:' + LAN_IP])
            runner.kinds.clear()
            runner.query = state_json(ad=adapters(lan=lan_b))
            g.ensure_guard(runner, CONFIG)
            self.assertEqual(runner.kinds, ['quick', 'full', 'selftest:' + lan_b])
            runner.kinds.clear()
            g.ensure_guard(runner, CONFIG)   # unveraendert: nur schnelle Pruefung, kein weiterer Selbsttest
            self.assertEqual(runner.kinds, ['quick'])

    def test_new_lan_address_with_open_firewall_stops(self):
        """V1: Ist die neue Adresse nicht gesperrt, stoppt der Lauf (vorher wurde der Selbsttest uebersprungen)."""
        runner = FakeRunner(state_json())
        with self.run_session():
            g.ensure_guard(runner, CONFIG)
            runner.query = state_json(ad=adapters(lan='192.168.1.77'))
            runner.selftest = 'SELFTEST {ip} OPEN:10060'
            with self.assertRaises(g.Failure) as caught:
                g.ensure_guard(runner, CONFIG)
        self.assertEqual((caught.exception.code, caught.exception.ident), (2, 'FIREWALL_SELFTEST_FAILED'))

    def test_open_firewall_in_selftest_stops(self):
        for line in ('SELFTEST {ip} OPEN:10060', 'SELFTEST {ip} OPEN:connected', ''):
            self.fails(FakeRunner(state_json(), selftest=line), 'FIREWALL_SELFTEST_FAILED')

    def test_no_route_or_unusable_address_passes_selftest(self):
        for line in ('SELFTEST {ip} NOROUTE', 'SELFTEST {ip} NOADDR'):
            self.assertIn('Selbsttest bestanden', self.guard(FakeRunner(state_json(), selftest=line)))

    def test_missing_or_stale_rules_stop(self):
        self.fails(FakeRunner(state_json(rules=[])), 'FIREWALL_RULES_MISSING')
        self.fails(FakeRunner(state_json(ad=adapters(vpn='10.2.0.9'))), 'FIREWALL_RULES_MISSING')

    def test_no_vpn_adapter_or_address_stops(self):
        self.fails(FakeRunner(state_json(ad=adapters(vpn=None))), 'VPN_ADAPTER_MISSING')
        self.fails(FakeRunner(state_json(ad=[{'Name': 'ProtonVPN', 'InterfaceDescription': 'x', 'IPv4': []}])), 'VPN_IP_MISSING')

    def test_query_problems_stop(self):
        self.fails(FakeRunner(g.Result(1, '')), 'GUARD_QUERY_FAILED')
        self.fails(FakeRunner(g.Result(0, state_json(), timed_out=True)), 'GUARD_QUERY_FAILED')
        self.fails(FakeRunner('kein json'), 'GUARD_QUERY_INVALID')
        self.fails(FakeRunner(state_json(rules_error='Zugriff verweigert')), 'GUARD_QUERY_INVALID')

    def test_selftest_skipped_without_other_addresses(self):
        runner = FakeRunner(state_json(ad=[adapters()[1]]))
        out = self.guard(runner)
        self.assertEqual(runner.kinds, ['full'])
        self.assertIn('uebersprungen', out)

    def test_enforce_off_and_empty_patterns_only_warn(self):
        out = self.guard(FakeRunner(state_json(rules=[])), dict(CONFIG, firewall_enforce=False))
        self.assertIn('firewall_enforce = false', out)
        with self.assertRaises(g.Failure):  # Adapter muss trotzdem da sein
            self.guard(FakeRunner(state_json(ad=adapters(vpn=None))), dict(CONFIG, firewall_enforce=False))
        runner = FakeRunner(g.Result(1, ''))
        out = self.guard(runner, dict(CONFIG, vpn_adapter_patterns=[], firewall_enforce=False))
        self.assertEqual(runner.calls, [])
        self.assertIn('keine Adapter- und keine Firewallpruefung', out)

    def test_other_platforms_refused(self):
        with self.assertRaises(g.Failure) as caught:
            self.guard(FakeRunner(state_json()), platform='linux')
        self.assertEqual(caught.exception.ident, 'PLATFORM_UNSUPPORTED')

    def test_skip_check_still_requires_guard(self):
        net = g.Network(CONFIG, None, skip=True)
        with patch.object(g, 'ensure_guard', side_effect=g.Failure(2, 'VPN_ADAPTER_MISSING', 'x')) as guard, \
             self.assertRaises(g.Failure):
            net.check('Test')
        guard.assert_called_once()

    def test_guard_programs_cover_every_network_program(self):
        names = {Path(p).name.lower() for p in g.guard_programs()}
        self.assertTrue({'curl.exe', 'nslookup.exe'} <= names)
        self.assertTrue(any(n.startswith('ffmpeg') for n in names) and any(n.startswith('ffprobe') for n in names))
        self.assertIn(sc.real_exe(), g.guard_programs())


class TestConfig(unittest.TestCase):
    def write(self, extra):
        return write_config(self, extra)

    def test_adapter_patterns_validated(self):
        self.assertEqual(CONFIG['vpn_adapter_patterns'], ['Proton', 'ProTUN'])
        g.load_config(self.write(lambda t: t.replace('["Proton", "ProTUN"]', '[]').replace('firewall_enforce = true', 'firewall_enforce = false')))
        for bad in ('"Proton"', '[1]', '["("]', '[""]'):
            with self.assertRaises(g.Failure) as caught:
                g.load_config(self.write(lambda t, b=bad: t.replace('["Proton", "ProTUN"]', b)))
            self.assertEqual(caught.exception.ident, 'CONFIG_INVALID')

    def test_firewall_enforce_validated(self):
        self.assertIs(CONFIG['firewall_enforce'], True)
        for bad in ('"ja"', '1'):
            with self.assertRaises(g.Failure):
                g.load_config(self.write(lambda t, b=bad: t.replace('firewall_enforce = true', f'firewall_enforce = {b}')))
        with self.assertRaises(g.Failure):  # erzwingen ohne Adaptermuster ist widerspruechlich
            g.load_config(self.write(lambda t: t.replace('["Proton", "ProTUN"]', '[]')))
        g.load_config(self.write(lambda t: t.replace('["Proton", "ProTUN"]', '[]').replace('firewall_enforce = true', 'firewall_enforce = false')))

    def test_linux_leftovers_rejected(self):
        with self.assertRaises(g.Failure):
            g.load_config(self.write(lambda t: t + '\nmac_interface = "wlan0"\n'))


class TestPlatformPieces(unittest.TestCase):
    def test_lock_conflict_and_release(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / '.lock'
            first = sc.locked_file(path)
            with self.assertRaises((BlockingIOError, PermissionError)):
                second = sc.locked_file(path)
                second.close()
            first.close()
            sc.locked_file(path).close()

    def test_move_noreplace_never_overwrites(self):
        with tempfile.TemporaryDirectory() as d:
            a, b = Path(d) / 'a', Path(d) / 'b'
            a.write_bytes(b'neu')
            b.write_bytes(b'alt')
            with self.assertRaises(FileExistsError):
                sc.move_noreplace(a, b)
            self.assertEqual(b.read_bytes(), b'alt')
            self.assertTrue(a.exists())
            b.unlink()
            sc.move_noreplace(a, b)
            self.assertEqual(b.read_bytes(), b'neu')
            self.assertFalse(a.exists())

    def test_child_env_is_narrow(self):
        with patch.dict(os.environ, {'HTTPS_PROXY': 'http://x', 'PYTHONPATH': '/evil', 'PYTHONSTARTUP': 'x', 'SECRET_TOKEN': 'a'}):
            env = sc.child_env(Path('work'))
        for name in ('HTTPS_PROXY', 'PYTHONPATH', 'PYTHONSTARTUP', 'SECRET_TOKEN'):
            self.assertNotIn(name, env)
        self.assertEqual(env['YTDLP_NO_PLUGINS'], '1')
        self.assertEqual(env['PYTHONUTF8'], '1')
        self.assertEqual(env['TEMP'], str(Path('work')))

    def test_timeout_kills_whole_tree(self):
        """Elternprozess startet ein Kind; beide muessen nach dem Timeout weg sein."""
        with tempfile.TemporaryDirectory() as d:
            marker = Path(d) / 'child.pid'
            code = ('import subprocess,sys,time;'
                    f'p=subprocess.Popen([sys.executable,"-c","import time;time.sleep(60)"]);'
                    f'open({str(marker)!r},"w").write(str(p.pid));time.sleep(60)')
            started = time.monotonic()
            result = g.Runner().run([sys.executable, '-c', code], timeout=3)
            self.assertTrue(result.timed_out)
            self.assertLess(time.monotonic() - started, 20)
            pid = int(marker.read_text())
            time.sleep(1)
            self.assertFalse(self.alive(pid), 'Kindprozess lebt noch')

    @staticmethod
    def alive(pid):
        if os.name == 'nt':
            import subprocess
            out = subprocess.run(['tasklist', '/FI', f'PID eq {pid}', '/NH'], capture_output=True, text=True).stdout
            return str(pid) in out
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return False
        except PermissionError:
            return True
        # Zombie (nicht abgeholt) zaehlt als beendet
        try:
            return Path(f'/proc/{pid}/stat').read_text().split(')')[1].split()[0] != 'Z'
        except OSError:
            return False


class TestPaths(unittest.TestCase):
    def test_storage_in_short_name_temp_dir_is_accepted(self):
        with tempfile.TemporaryDirectory() as d:
            g.Store(d)

    def test_reparse_check_on_regular_dir_is_false(self):
        with tempfile.TemporaryDirectory() as d:
            self.assertFalse(sc.is_reparse_or_link(Path(d)))

    def test_symlinked_storage_refused(self):
        with tempfile.TemporaryDirectory() as d:
            real = Path(d) / 'real'
            real.mkdir()
            try:
                (Path(d) / 'link').symlink_to(real, target_is_directory=True)
            except OSError:
                self.skipTest('Symlinks nicht erlaubt (unter Windows Entwicklermodus/Adminrecht noetig)')
            with self.assertRaises(g.Failure) as caught:
                g.Store(Path(d) / 'link' / 'x')
            self.assertEqual(caught.exception.ident, 'STORAGE_SYMLINK')

    @unittest.skipUnless(sys.platform == 'win32', 'Junctions gibt es nur unter Windows')
    def test_junction_storage_refused(self):
        """Junction (mklink /J, ohne Sonderrechte) im Speicherpfad wird wie ein Symlink abgelehnt."""
        import subprocess
        with tempfile.TemporaryDirectory() as d:
            real = Path(d) / 'real'
            real.mkdir()
            link = Path(d) / 'junction'
            r = subprocess.run([os.path.join(sc.SYSTEM32, 'cmd.exe'), '/d', '/c', 'mklink', '/J', str(link), str(real)],
                               capture_output=True, stdin=subprocess.DEVNULL)
            if r.returncode != 0 or not link.exists():
                self.skipTest('mklink /J nicht moeglich')
            try:
                self.assertTrue(sc.is_reparse_or_link(link))
                for target in (link, link / 'x'):
                    with self.assertRaises(g.Failure) as caught:
                        g.Store(target)
                    self.assertEqual(caught.exception.ident, 'STORAGE_SYMLINK')
                self.assertEqual(list(real.iterdir()), [])   # nichts durch die Junction angelegt
            finally:
                os.rmdir(link)   # entfernt nur die Junction, nicht das Ziel


if __name__ == '__main__':
    unittest.main()
