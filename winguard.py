# SPDX-License-Identifier: GPL-3.0-only
"""Windows-Netzsperre fuer Quite Safe Grab: Firewallregeln nach Quelladresse (reine Logik, ohne Systemzugriff).

Idee (Gegenstueck zum Linux-Namespace): Fuer jedes Programm des Downloaders (guard_programs)
blockiert eine ausgehende Regel jeden Verkehr, dessen *Quelladresse* nicht die VPN-Adresse
(oder Loopback) ist. Faellt der Tunnel aus oder tauchen neue Adapter auf, waehlt Windows eine andere Quelladresse - und die Verbindung wird blockiert (WSAEACCES), statt
ungeschuetzt hinauszugehen. IPv6 wird fuer diese Programme vollstaendig blockiert.

Dieses Modul erzeugt und prueft nur Daten. Wirksam wird die Sperre erst durch die Regeln,
die fw.py mit Administratorrechten anlegt; grab.py prueft sie vor jedem Pruefpunkt.
"""
import base64
import ipaddress
import json
import ntpath
import re

import syscompat as sc

GROUP = 'QuiteSafeGrab'
DISPLAY_NAME = 'Quite Safe Grab'
RULE_PREFIX = 'QuiteSafeGrab-'
LEGACY_RULE_PREFIXES = ('PiGrab-',)   # Name vor der Umbenennung - wird bei apply/remove mit entfernt
MAX4 = 2 ** 32 - 1
MAX6 = 2 ** 128 - 1
LOOPBACK4 = (int(ipaddress.IPv4Address('127.0.0.0')), int(ipaddress.IPv4Address('127.255.255.255')))
V6_ENTRIES = ['::/1', '8000::/1']

# Systemprogramme mit festem Pfad (nie ueber PATH): curl/nslookup sind selbst durch die Netzsperre geschuetzt.
SYSTEM32 = sc.SYSTEM32
POWERSHELL = str(SYSTEM32 / 'WindowsPowerShell' / 'v1.0' / 'powershell.exe')
CURL = str(SYSTEM32 / 'curl.exe')
NSLOOKUP = str(SYSTEM32 / 'nslookup.exe')


def guard_programs(python_exe, ffmpeg, ffprobe):
    """Alle Programme, die der Downloader mit Netzwerkzugriff startet - fuer jedes gilt die Sperrregel."""
    return [python_exe, ffmpeg, ffprobe, CURL, NSLOOKUP]


# Adapter-Block und Regel-Block sind getrennt, damit die schnelle Abfrage genau den Adapter-Block nutzt.
_ADAPTER_BLOCK = r"""
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [Text.Encoding]::UTF8
$adapters = @(Get-NetAdapter | Where-Object { $_.Status -eq 'Up' } | ForEach-Object {
  [pscustomobject]@{ Name = [string]$_.Name; InterfaceDescription = [string]$_.InterfaceDescription;
    IPv4 = @(Get-NetIPAddress -InterfaceIndex $_.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue | ForEach-Object { [string]$_.IPAddress });
    IPv4Unbound = @(Get-NetIPAddress -InterfaceIndex $_.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue |
      Where-Object { @('Tentative', 'Duplicate', 'Invalid') -contains [string]$_.AddressState } | ForEach-Object { [string]$_.IPAddress }) } })
"""
_RULES_BLOCK = r"""$rules = @(); $rulesError = ''
try {
  $rules = @(Get-NetFirewallRule -Name '""" + RULE_PREFIX + r"""*' -ErrorAction Stop | ForEach-Object {
    $a = $_ | Get-NetFirewallAddressFilter; $p = $_ | Get-NetFirewallApplicationFilter
    [pscustomobject]@{ Name = [string]$_.Name; Enabled = [string]$_.Enabled; Direction = [string]$_.Direction;
      Action = [string]$_.Action; Program = [string]$p.Program;
      LocalAddress = @($a.LocalAddress | ForEach-Object { [string]$_ }) } })
} catch {
  if ($_.FullyQualifiedErrorId -notlike '*NotFound*') { $rulesError = [string]$_.Exception.Message }
}
$profiles = @(Get-NetFirewallProfile | ForEach-Object { [pscustomobject]@{ Name = [string]$_.Name; Enabled = [string]$_.Enabled } })
"""
STATE_SCRIPT = (_ADAPTER_BLOCK + _RULES_BLOCK
                + "[pscustomobject]@{ Adapters = $adapters; Rules = $rules; Profiles = $profiles; RulesError = $rulesError } | ConvertTo-Json -Compress -Depth 6\n")

# Schnelle Abfrage (~2 s statt ~13 s): nur Adapter und ihre IPv4-Adressen, ohne Firewallregeln.
# Wird nur benutzt, nachdem in DIESEM Lauf die volle Pruefung (Regeln + Selbsttest) bestanden ist.
QUICK_STATE_SCRIPT = _ADAPTER_BLOCK + "[pscustomobject]@{ Adapters = $adapters } | ConvertTo-Json -Compress -Depth 6\n"

QUERY_TIMEOUT = 60


class QueryFailed(Exception):
    """PowerShell-Abfrage ohne Exitcode 0 oder mit Zeitueberschreitung; err = Fehlerausgabe."""
    def __init__(self, err=''):
        super().__init__(err)
        self.err = err


class QueryInvalid(Exception):
    """Abfrage lief, ihre Ausgabe ist aber nicht auswertbar (Text aus parse_state)."""


def query_state(run, script=STATE_SCRIPT):
    """Adapter-/Firewallzustand abfragen. run(argv, timeout) -> (code, out, err, timed_out).
    Fehler: QueryFailed oder QueryInvalid - der Aufrufer bricht ab, nie ein ungeschuetzter Fallback."""
    code, out, err, timed_out = run([POWERSHELL] + powershell_args(script), QUERY_TIMEOUT)
    if code != 0 or timed_out:
        raise QueryFailed(err)
    try:
        return parse_state(out)
    except ValueError as exc:
        raise QueryInvalid(str(exc)) from exc


# Laeuft im geschuetzten Python: von jeder NICHT-VPN-Adresse aus muss connect() sofort an der Firewall scheitern.
# 192.0.2.1 (TEST-NET-1, RFC 5737) ist nirgends routbar; es wird kein Dritter kontaktiert.
# Als sicher gelten nur: BLOCKED (10013, Firewall), NOADDR (10049, Adresse nicht als Absender nutzbar)
# und NOROUTE (10051/10065, von dieser Adresse kein Weg ins Netz - Windows sendet kein Paket).
# Alles andere (Timeout, Verbindungsaufbau, unbekannte Fehler) bleibt OPEN und stoppt das Tool.
SELFTEST_CODES = {10013: 'BLOCKED', 10049: 'NOADDR', 10051: 'NOROUTE', 10065: 'NOROUTE'}
SELFTEST_CODE = r"""
import socket, sys
SAFE = """ + repr(SELFTEST_CODES) + r"""
for ip in sys.argv[1:]:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(3)
    try:
        s.bind((ip, 0))
        s.connect(('192.0.2.1', 9))
    except OSError as e:
        code = getattr(e, 'winerror', None) or e.errno
        print('SELFTEST', ip, SAFE.get(code, 'OPEN:%s' % code))
    else:
        print('SELFTEST', ip, 'OPEN:connected')
    finally:
        s.close()
"""
SELFTEST_SAFE = tuple(dict.fromkeys(SELFTEST_CODES.values()))


def as_list(value):
    if value is None or value == '':
        return []
    return value if isinstance(value, list) else [value]


def parse_state(text):
    """JSON der STATE_SCRIPT-Abfrage -> bereinigtes Dict; ValueError bei unbrauchbarer Ausgabe."""
    try:
        data = json.loads(text.lstrip('﻿'))
    except ValueError as exc:
        raise ValueError('Keine auswertbare Firewall-/Adapterabfrage') from exc
    if not isinstance(data, dict):
        raise ValueError('Unerwartetes Abfrageformat')
    if data.get('RulesError'):
        raise ValueError('Firewallregeln nicht lesbar')

    def objects(key):
        return [o for o in as_list(data.get(key)) if isinstance(o, dict)]

    adapters = []
    for a in objects('Adapters'):
        adapters.append({'name': str(a.get('Name', '')), 'description': str(a.get('InterfaceDescription', '')),
                         'ipv4': [str(x) for x in as_list(a.get('IPv4'))],
                         'ipv4_unbound': [str(x) for x in as_list(a.get('IPv4Unbound'))]})
    rules = []
    for r in objects('Rules'):
        rules.append({'name': str(r.get('Name', '')), 'enabled': str(r.get('Enabled', '')), 'direction': str(r.get('Direction', '')),
                      'action': str(r.get('Action', '')), 'program': str(r.get('Program', '')),
                      'local': [str(x) for x in as_list(r.get('LocalAddress'))]})
    profiles = [{'name': str(p.get('Name', '')), 'enabled': str(p.get('Enabled', ''))} for p in objects('Profiles')]
    return {'adapters': adapters, 'rules': rules, 'profiles': profiles}


def matches(adapter, patterns):
    label = f"{adapter['name']} {adapter['description']}"
    return any(re.search(p, label, re.I) for p in patterns)


def vpn_adapters(state, patterns):
    return [a for a in state['adapters'] if matches(a, patterns)]


def usable_ipv4(text):
    try:
        ip = ipaddress.IPv4Address(text)
    except ValueError:
        return None
    if ip.is_loopback or ip.is_unspecified or ip.is_multicast or ip.is_link_local or ip.is_reserved:
        return None
    return str(ip)


def vpn_ipv4(adapters):
    return sorted({ip for a in adapters for ip in map(usable_ipv4, a['ipv4']) if ip})


def other_ipv4(state, patterns):
    """Lokale IPv4-Adressen aller aktiven Nicht-VPN-Adapter (ohne Loopback) fuer den Selbsttest.

    Uebersprungen werden Adressen, die Windows noch nicht oder nicht mehr als Absender zulaesst
    (Tentative/Duplicate/Invalid). 'Deprecated' bleibt im Test, weil sie noch gebunden werden kann.
    """
    found = set()
    for a in state['adapters']:
        if matches(a, patterns):
            continue
        unbound = set(a.get('ipv4_unbound', []))
        for text in a['ipv4']:
            if text in unbound:
                continue
            try:
                ip = ipaddress.IPv4Address(text)
            except ValueError:
                continue
            if not ip.is_loopback and not ip.is_unspecified:
                found.add(str(ip))
    return sorted(found)


def blocked_v4_ranges(vpn_ips):
    """Alles ausser Loopback und den VPN-Adressen: Liste (lo, hi)."""
    holes = [LOOPBACK4]
    for text in vpn_ips:
        ip = ipaddress.IPv4Address(text)
        if usable_ipv4(text) is None:
            raise ValueError('Ungueltige VPN-Adresse: ' + text)
        holes.append((int(ip), int(ip)))
    holes.sort()
    ranges, cursor = [], 0
    for lo, hi in holes:
        if lo > cursor:
            ranges.append((cursor, lo - 1))
        cursor = max(cursor, hi + 1)
    if cursor <= MAX4:
        ranges.append((cursor, MAX4))
    return ranges


def format_v4_ranges(ranges):
    return [f'{ipaddress.IPv4Address(lo)}-{ipaddress.IPv4Address(hi)}' for lo, hi in ranges]


def parse_entry(text):
    """Firewall-Adresseintrag -> (version, lo, hi). Unbekannte Schluesselwoerter -> ValueError."""
    text = text.strip()
    if text.lower() == 'any':
        return None
    if '-' in text:
        a, b = (ipaddress.ip_address(x.strip()) for x in text.split('-', 1))
        if a.version != b.version:
            raise ValueError('Gemischter Bereich')
        return a.version, int(a), int(b)
    if '/' in text:
        base, mask = text.split('/', 1)
        if re.fullmatch(r'\d+\.\d+\.\d+\.\d+', mask):
            mask = str(ipaddress.IPv4Network('0.0.0.0/' + mask).prefixlen)
        net = ipaddress.ip_network(f'{base}/{mask}', strict=False)
        return net.version, int(net.network_address), int(net.broadcast_address)
    ip = ipaddress.ip_address(text)
    return ip.version, int(ip), int(ip)


def merge(ranges):
    out = []
    for lo, hi in sorted(ranges):
        if out and lo <= out[-1][1] + 1:
            out[-1] = (out[-1][0], max(out[-1][1], hi))
        else:
            out.append((lo, hi))
    return out


def covers(have, need):
    have = merge(have)
    return all(any(h_lo <= lo and hi <= h_hi for h_lo, h_hi in have) for lo, hi in merge(need))


def touches(have, value):
    return any(lo <= value <= hi for lo, hi in have)


def same_program(a, b):
    return ntpath.normcase(ntpath.normpath(a)) == ntpath.normcase(ntpath.normpath(b))


def check_rules(state, programs, vpn_ips):
    """None, wenn die Sperre vollstaendig und passend ist; sonst (Kennung, Meldung)."""
    if not state['profiles'] or any(p['enabled'].lower() != 'true' for p in state['profiles']):
        return ('FIREWALL_DISABLED', 'Die Windows-Firewall ist fuer mindestens ein Profil aus; die Regeln wuerden dort nicht wirken.')
    need4 = blocked_v4_ranges(vpn_ips)
    need6 = [(0, MAX6)]
    for program in programs:
        v4, v6 = [], []
        for rule in state['rules']:
            if not same_program(rule['program'], program):
                continue
            if rule['enabled'].lower() != 'true' or rule['direction'].lower() != 'outbound' or rule['action'].lower() != 'block':
                continue
            for entry in rule['local']:
                try:
                    parsed = parse_entry(entry)
                except ValueError:
                    continue
                if parsed is None:
                    v4.append((0, MAX4))
                    v6.append((0, MAX6))
                elif parsed[0] == 4:
                    v4.append(parsed[1:])
                else:
                    v6.append(parsed[1:])
        name = ntpath.basename(program)
        if not covers(v4, need4) or not covers(v6, need6):
            return ('FIREWALL_RULES_MISSING', f'Netzsperre fehlt oder passt nicht zur VPN-Adresse ({name}). Als Administrator einrichten: qsgrab.cmd firewall apply')
        if any(touches(merge(v4), int(ipaddress.IPv4Address(ip))) for ip in vpn_ips):
            return ('FIREWALL_BLOCKS_VPN', f'Die Sperrregel fuer {name} blockiert auch die VPN-Adresse. Neu einrichten: qsgrab.cmd firewall apply')
    return None


def parse_selftest(output, ips):
    """Liste der Adressen, die NICHT zuverlaessig gesperrt oder unbenutzbar waren."""
    result = {}
    for line in output.splitlines():
        parts = line.split()
        if len(parts) == 3 and parts[0] == 'SELFTEST':
            result[parts[1]] = parts[2]
    return [ip for ip in ips if result.get(ip) not in SELFTEST_SAFE]


def ps_quote(text):
    if re.search(r'[\x00-\x1f]', text):
        raise ValueError('Steuerzeichen in Pfad')
    return "'" + text.replace("'", "''") + "'"


def _remove_lines():
    return [f"Get-NetFirewallRule -Name '{p}*' -ErrorAction SilentlyContinue | Remove-NetFirewallRule"
            for p in (RULE_PREFIX,) + LEGACY_RULE_PREFIXES]


def build_apply_script(programs, vpn_ips):
    v4 = format_v4_ranges(blocked_v4_ranges(vpn_ips))
    lines = ["$ErrorActionPreference = 'Stop'"] + _remove_lines()
    for index, program in enumerate(programs, 1):
        if not ntpath.isabs(program):
            raise ValueError('Programmpfad nicht absolut: ' + program)
        quoted = ps_quote(program)
        for family, addresses in (('v4', v4), ('v6', V6_ENTRIES)):
            address_list = ','.join(ps_quote(a) for a in addresses)
            lines.append(f"New-NetFirewallRule -Name '{RULE_PREFIX}{family}-{index}' -DisplayName '{DISPLAY_NAME} Netzsperre {family} {index}' "
                         f"-Group '{GROUP}' -Direction Outbound -Action Block -Program {quoted} "
                         f"-LocalAddress @({address_list}) -Profile Any -Enabled True | Out-Null")
    return '\n'.join(lines)


def build_remove_script():
    return '\n'.join(["$ErrorActionPreference = 'Stop'"] + _remove_lines())


def powershell_args(script):
    """Argumente fuer powershell.exe: Skript als -EncodedCommand (kein Quoting-/Shell-Problem)."""
    encoded = base64.b64encode(script.encode('utf-16-le')).decode('ascii')
    return ['-NoLogo', '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Restricted', '-EncodedCommand', encoded]
