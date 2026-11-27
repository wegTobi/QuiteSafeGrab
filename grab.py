#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Quite Safe Grab: bounded processes, guarded networking and verified publication."""
from __future__ import annotations

import argparse
import contextlib
import dataclasses
import html
import ipaddress
import json
import math
import os
from pathlib import Path
import queue
import re
import shutil
import signal
import stat
import subprocess
import sys
import threading
import time
import tomllib
import unicodedata
import urllib.parse
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parent))
from voe_resolver import MAX_SIZE_HOPS, UA, VOE_ID_RE, VOE_REFERER, public_host, valid_url
import syscompat as sc
import winguard
import common
from common import (BROWSER_AUTO, BROWSER_EDGE, BROWSER_MULLVAD, CHECK_KEYS, ERROR_CHECK, EVENT_PREFIX, EXIT_MEDIA, EXIT_OK, EXIT_RESOLVE, EXIT_SAFETY, EXIT_USER,
                    HOST_RE, PHASE_CHECKS, PHASE_DONE, PHASE_DOWNLOAD, PHASE_PREVIEW, PHASE_PROBE, PHASE_REMUX, PHASE_RESOLVE, PHASE_SIZES,
                    PHASE_VERIFY, REDIRECT_HOSTS_ENV, UI_BROWSERS, Failure, check_key, fail, safe_text)

APP = Path(__file__).resolve().parent
SYSTEM32 = winguard.SYSTEM32


def _tool(name):
    candidate = APP / 'tools' / (name + '.exe')
    if candidate.is_file():
        return str(candidate)
    return shutil.which(name) or str(candidate)


# yt-dlp laeuft als Python-Modul in der eigenen Laufzeit (python\ + lib\, kein yt-dlp.exe noetig).
YDL = [sys.executable, '-I', '-m', 'yt_dlp']
FFMPEG = _tool('ffmpeg')
FFPROBE = _tool('ffprobe')
CURL = winguard.CURL
NSLOOKUP = winguard.NSLOOKUP
POWERSHELL = winguard.POWERSHELL
ISO_COUNTRIES = set(('AD AE AF AG AI AL AM AO AQ AR AS AT AU AW AX AZ BA BB BD BE BF BG BH BI BJ BL BM BN BO BQ BR BS BT BV BW BY BZ '
                     'CA CC CD CF CG CH CI CK CL CM CN CO CR CU CV CW CX CY CZ DE DJ DK DM DO DZ EC EE EG EH ER ES ET FI FJ FK FM FO FR '
                     'GA GB GD GE GF GG GH GI GL GM GN GP GQ GR GS GT GU GW GY HK HM HN HR HT HU ID IE IL IM IN IO IQ IR IS IT JE JM JO JP '
                     'KE KG KH KI KM KN KP KR KW KY KZ LA LB LC LI LK LR LS LT LU LV LY MA MC MD ME MF MG MH MK ML MM MN MO MP MQ MR MS MT MU MV MW MX MY MZ '
                     'NA NC NE NF NG NI NL NO NP NR NU NZ OM PA PE PF PG PH PK PL PM PN PR PS PT PW PY QA RE RO RS RU RW '
                     'SA SB SC SD SE SG SH SI SJ SK SL SM SN SO SR SS ST SV SX SY SZ TC TD TF TG TH TJ TK TL TM TN TO TR TT TV TW TZ '
                     'UA UG UM US UY UZ VA VC VE VG VI VN VU WF WS YE YT ZA ZM ZW').split())


class Session:
    """Prozesszustand eines grab.py-Laufs an einem Ort (nur im Speicher, nie auf der Festplatte)."""

    def __init__(self):
        self.events = False            # --events: Ereigniszeilen fuer ui.py
        self.phase = 'start'           # aktuelle Phase fuer progress-Ereignisse
        self.warned = set()            # Waechter-Warnungen, die schon einmal ausgegeben wurden
        self.selftest_done = set()     # Selbsttest bestanden, je guard_key (wie rules_ok)
        self.rules_ok = set()          # volle Pruefung (Regeln + Selbsttest) in diesem Lauf bestanden, je guard_key
        self.redirect_hosts = set()    # Seiten, deren Links in diesem Lauf nur per Weiterleitung aufloesbar waren
        self.position = (1, 1)         # Anzeige "läuft noch, x von y" der Warteschlange


SESSION = Session()   # Tests setzen den Zustand mit patch.object(g, 'SESSION', g.Session()) neu auf


# --- Maschinenlesbare Ereignisse fuer die Oberflaeche (ui.py), nur mit --events.
# Eine Zeile je Ereignis: "@@QSGRAB {json}". Nur Anzeige - keine Entscheidung haengt davon ab.
# Texte laufen durch safe_text (keine signierten URLs).
_PROGRESS = re.compile(r'^\[download\]\s+(?P<pct>\d{1,3}(?:\.\d+)?)%\s+of\s+~?\s*(?P<total>[\d.]+\s*[KMGT]?i?B)'
                       r'(?:\s+in\s+\S+)?(?:\s+at\s+(?P<speed>[\d.]+\s*[KMGT]?i?B/s|Unknown B/s))?(?:\s+ETA\s+(?P<eta>[\d:]+|Unknown))?')


def emit(kind, **data):
    if not SESSION.events:
        return
    clean = {k: (safe_text(v) if isinstance(v, str) else v) for k, v in data.items()}
    print(EVENT_PREFIX + json.dumps({'type': kind, 'time': round(time.time(), 3), **clean}, ensure_ascii=False), flush=True)


def phase(name):
    SESSION.phase = name
    emit('phase', phase=name)


def progress_event(line):
    """yt-dlp-Fortschrittszeile (--newline) als Ereignis; andere Zeilen ignorieren."""
    m = _PROGRESS.match(line.strip())
    if not m:
        return
    speed = m.group('speed')
    eta = m.group('eta')
    emit('progress', phase=SESSION.phase, percent=min(float(m.group('pct')), 100.0), total=m.group('total').replace(' ', ''),
         speed=None if not speed or speed.startswith('Unknown') else speed.replace(' ', ''),
         eta=None if not eta or eta == 'Unknown' else eta)


def error(exc):
    common.error(exc, emit)


def video_name(title):
    value = html.unescape(str(title)).strip()
    value = re.sub(r'^Watch\s+', '', value, flags=re.I)
    value = re.sub(r'\s*[-|]\s*VOE\s*$', '', value, flags=re.I)
    value = re.sub(r'(\.(mkv|mp4|avi|webm|mov))+$', '', value, flags=re.I)
    value = ''.join('-' if c in '<>:"/\\|?*' or unicodedata.category(c)[0] == 'C' else c for c in value)
    value = re.sub(r'\.{2,}', '.', value)
    value = re.sub(r'\s+', '_', value.strip().rstrip('. ')).strip('._')
    value = unicodedata.normalize('NFC', value)[:120]
    # Platz fuer Endung und Kollisionssuffix lassen.
    while len(value.encode('utf-8')) > 220:
        value = value[:-1]
    value = sc.safe_basename(value)
    if not value:
        fail(1, 'OUTPUT_NAME_INVALID', 'Kein verwendbarer Dateiname.')
    return value


def load_config(path):
    try:
        data = tomllib.loads(Path(path).read_text(encoding='utf-8-sig'))
        required = {'storage', 'home_country', 'home_country_names', 'blocked_orgs',
                    'allowed_patterns', 'probe_url', 'download_timeout_sec', 'voe_hosts', 'vpn_adapter_patterns', 'firewall_enforce'}
        optional = {'ui_browser': 'auto'}   # fehlt in aelteren config.toml - dann Vorgabe
        if set(data) - set(optional) != required:
            raise ValueError('Fehlende oder unbekannte Konfigurationseintraege')
        for key, default in optional.items():
            data.setdefault(key, default)
        if data['ui_browser'] not in UI_BROWSERS:
            raise ValueError('ui_browser muss "auto", "mullvad" oder "edge" sein')
        for key in ('home_country_names', 'blocked_orgs', 'allowed_patterns', 'voe_hosts'):
            # blocked_orgs darf leer sein (Zusatzsicherung; den Schutz traegt die Heimatland-Pruefung).
            empty_ok = key == 'blocked_orgs'
            if not isinstance(data[key], list) or (not data[key] and not empty_ok) or any(not isinstance(x, str) or not x.strip() for x in data[key]):
                raise ValueError(f'Ungueltige Liste: {key}')
        for pattern in data['blocked_orgs'] + data['allowed_patterns']:
            re.compile(pattern, re.I)
        timeout = data['download_timeout_sec']
        if type(timeout) is not int or not 1 <= timeout <= 2147483:
            raise ValueError('download_timeout_sec muss eine ganze Zahl von 1 bis 2147483 sein')
        if not re.fullmatch('[A-Z]{2}', data['home_country']):
            raise ValueError('home_country muss aus zwei Grossbuchstaben bestehen')
        if not isinstance(data['storage'], str) or not data['storage'].strip():
            raise ValueError('storage fehlt')
        patterns = data['vpn_adapter_patterns']
        if not isinstance(patterns, list) or any(not isinstance(x, str) or not x.strip() for x in patterns):
            raise ValueError('vpn_adapter_patterns muss eine Liste von Texten sein (leer = Adapterpruefung aus)')
        for pattern in patterns:
            re.compile(pattern, re.I)
        if not isinstance(data['firewall_enforce'], bool):
            raise ValueError('firewall_enforce muss true oder false sein')
        if data['firewall_enforce'] and not patterns:
            raise ValueError('firewall_enforce = true braucht vpn_adapter_patterns (die VPN-Adresse wird daraus ermittelt)')
        valid_url(data['probe_url'])
        return data
    except (OSError, ValueError, TypeError, KeyError, re.error) as exc:
        fail(1, 'CONFIG_INVALID', str(exc))


@dataclasses.dataclass
class Result:
    code: int
    out: str
    err: str = ''
    timed_out: bool = False


class Runner:
    def run(self, argv, *, timeout=120, live=False, cwd=None, input_text=None):
        # Enge Umgebung: keine Proxys, Python-Injektion, netrc oder yt-dlp-Konfiguration.
        env = sc.child_env(cwd)
        try:
            proc = subprocess.Popen(list(map(str, argv)), shell=False, cwd=cwd, env=env,
                                    stdin=subprocess.PIPE if input_text is not None else subprocess.DEVNULL,
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, **sc.popen_kwargs())
        except OSError:
            fail(1, 'PROCESS_START_FAILED', f'Programm nicht startbar: {Path(argv[0]).name}')
        tree = sc.ProcessTree(proc)
        messages = queue.Queue(maxsize=256)
        def reader(stream, channel):
            try:
                for line in iter(lambda: stream.readline(65536), b''):
                    messages.put((channel, line.decode('utf-8', errors='replace')))
            finally:
                stream.close()
                messages.put((channel, None))
        for ch, stream in enumerate((proc.stdout, proc.stderr)):
            threading.Thread(target=reader, args=(stream, ch), daemon=True).start()
        if input_text is not None:
            proc.stdin.write(input_text.encode('utf-8'))
            proc.stdin.close()
        buffers = [[], []]
        sizes = [0, 0]
        started, heartbeat, ended, expired = time.monotonic(), 30, 0, False
        try:
            while ended < 2 or proc.poll() is None:
                elapsed = time.monotonic() - started
                if elapsed >= timeout and not expired:
                    expired = True
                    tree.kill()
                if live and elapsed >= heartbeat:
                    print(f'läuft noch, {SESSION.position[0]} von {SESSION.position[1]}', flush=True)
                    heartbeat += 30
                try:
                    channel, line = messages.get(timeout=0.05)
                except queue.Empty:
                    continue
                if line is None:
                    ended += 1
                    continue
                if live:
                    print(safe_text(line), end='', flush=True)
                    progress_event(line)
                else:
                    buffers[channel].append(line)
                    sizes[channel] += len(line)
                    if sizes[channel] > 16 * 1024 * 1024:
                        tree.kill()
                        fail(1, 'PROCESS_OUTPUT_TOO_LARGE', 'Prozessausgabe zu gross.')
            code = proc.wait()
            if code is None:
                fail(1, 'PROCESS_EXIT_MISSING', 'Prozess ohne Exit-Code.')
            return Result(code, ''.join(buffers[0]), ''.join(buffers[1]), expired)
        finally:
            tree.close()
            proc.wait()


@contextlib.contextmanager
def gate(path):
    deadline = time.monotonic() + 15
    while True:
        try:
            lock = sc.locked_file(path)
            break
        except (BlockingIOError, PermissionError):
            if time.monotonic() >= deadline:
                fail(1, 'STORAGE_BUSY', 'Arbeitsablage ist gesperrt.')
            time.sleep(0.05)
    try:
        yield
    finally:
        lock.close()


def secure_directory(path):
    path = Path(os.path.abspath(Path(path).expanduser()))
    # Jede vorhandene Pfadkomponente pruefen (Symlink/Junction/Reparse-Point, z. B. OneDrive-Platzhalter).
    # Gleiche Pruefung getrennt in setup.ps1 (OneDrive-Warnung) und haertung.ps1 (Has-Reparse, Under-OneDrive).
    # Kein realpath-Vergleich: 8.3-Kurznamen wie BENUTZ~1 wuerden sonst faelschlich auffallen.
    if any(sc.is_reparse_or_link(p) for p in (path, *path.parents) if p.exists()):
        fail(1, 'STORAGE_SYMLINK', 'Ablage oder ein Elternpfad ist eine Verknuepfung/Junction/Cloud-Platzhalter. Anderen Speicherort waehlen.')
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    s = path.lstat()
    if not stat.S_ISDIR(s.st_mode) or sc.is_reparse_or_link(path):
        fail(1, 'STORAGE_UNSAFE', 'Ablage ist kein gewoehnliches Verzeichnis.')
    return path


def safe_tree(path):
    if sc.is_reparse_or_link(path) or not path.is_dir():
        return False
    for root, dirs, files in os.walk(path, followlinks=False):
        for name in dirs + files:
            entry = Path(root) / name
            mode = entry.lstat().st_mode
            if sc.is_reparse_or_link(entry) or not (stat.S_ISREG(mode) or stat.S_ISDIR(mode)):
                return False
    return True


class Store:
    OUTPUT_DIR = 'finished'
    WORK_DIR = '.work'
    STATE_DIR = '.state'
    GATE_FILE = '.work.lock'
    LEGACY_EXIT_IP_FILE = '.last_exit_ip'

    def __init__(self, base):
        self.base = secure_directory(base)
        self.output = secure_directory(self.base / self.OUTPUT_DIR)
        self.work = secure_directory(self.base / self.WORK_DIR)
        self.state = secure_directory(self.base / self.STATE_DIR)
        if self.output.stat().st_dev != self.work.stat().st_dev:
            fail(1, 'STORAGE_FILESYSTEM', 'Arbeits- und Ausgabeordner muessen auf demselben Dateisystem liegen.')
        self.gatepath = self.base / self.GATE_FILE

    def cleanup(self):
        removed = 0
        with gate(self.gatepath):
            self._remove_legacy_exit_ip()
            for path in self.work.iterdir():
                if not re.fullmatch('[a-f0-9]{32}', path.name) or path.is_symlink():
                    continue
                try:
                    if time.time() - path.stat().st_mtime <= 86400 or not safe_tree(path):
                        continue
                    # Sperre pruefen (aktiv = BlockingIOError) und vor dem Loeschen freigeben:
                    # unter Windows laesst sich eine geoeffnete Datei nicht entfernen.
                    # Die globale Sperre (gate) verhindert Wettlaeufe waehrenddessen.
                    sc.locked_file(path / '.active.lock').close()
                    shutil.rmtree(path)
                    removed += 1
                except OSError:
                    print(f'WARNUNG: Alter Arbeitsordner bleibt (aktiv/gesperrt/unsicher): {path.name}')
        print(f'Arbeitsordner bereinigt: {removed} (älter als 24 Stunden).')
        return removed

    @contextlib.contextmanager
    def workspace(self):
        with gate(self.gatepath):
            path = self.work / uuid.uuid4().hex
            path.mkdir(mode=0o700)
            lock = sc.locked_file(path / '.active.lock')
        try:
            yield path
        finally:
            with gate(self.gatepath):
                # Sperrdatei zuerst schliessen (Windows kann geoeffnete Dateien nicht loeschen).
                lock.close()
                try:
                    if path.parent != self.work or not safe_tree(path):
                        raise OSError('Unsicherer Arbeitsordner')
                    shutil.rmtree(path)
                except OSError:
                    print(f'WARNUNG: Arbeitsdaten nicht entfernt: {path.name}', file=sys.stderr)

    def publish(self, source, name, extension):
        if source.is_symlink() or not source.is_file() or source.stat().st_nlink != 1:
            fail(1, 'PUBLISH_SOURCE_INVALID', 'Ungueltige Veroeffentlichungsquelle.')
        with source.open('r+b') as f:
            os.fsync(f.fileno())
        with gate(self.gatepath):
            for index in range(1, 10000):
                suffix = '' if index == 1 else f'_{index}'
                candidate = name[:120-len(suffix)] + suffix
                if any((self.output / (candidate + ext)).exists() for ext in EXTENSIONS):
                    continue
                target = self.output / (candidate + extension)
                try:
                    sc.move_noreplace(source, target)
                except FileExistsError:
                    continue
                except OSError:
                    fail(1, 'PUBLISH_FAILED', 'Atomare Veroeffentlichung fehlgeschlagen (NTFS-Laufwerk noetig; Datei evtl. von Virenscanner/Programm gesperrt).')
                return target
        fail(1, 'OUTPUT_COLLISION_LIMIT', 'Zu viele gleichnamige Dateien.')

    def _remove_legacy_exit_ip(self):
        """Altlast frueherer Versionen: .state\\.last_exit_ip enthielt die VPN-Exit-IP. Wird nicht mehr
        geschrieben; eine liegengebliebene Datei wird entfernt - nur genau diese, nur als normale Datei
        (keine Verknuepfung/Junction/Reparse-Point)."""
        path = self.state / self.LEGACY_EXIT_IP_FILE
        try:
            st = os.lstat(path)
        except FileNotFoundError:
            return
        except OSError:
            print('WARNUNG: Alte Exit-IP-Datei nicht pruefbar: ' + self.LEGACY_EXIT_IP_FILE)
            return
        if not stat.S_ISREG(st.st_mode) or sc.is_reparse_or_link(path):
            print('WARNUNG: Alte Exit-IP-Datei ist keine normale Datei - bleibt unberuehrt: ' + self.LEGACY_EXIT_IP_FILE)
            return
        try:
            path.unlink()
            print('Alte Exit-IP-Datei entfernt: ' + self.LEGACY_EXIT_IP_FILE)
        except OSError:
            print('WARNUNG: Alte Exit-IP-Datei konnte nicht entfernt werden: ' + self.LEGACY_EXIT_IP_FILE)


def guard_key(state, patterns, vpn_ips, programs):
    return (tuple(vpn_ips), tuple(winguard.other_ipv4(state, patterns)), tuple(programs))


def query_state(runner, script):
    def run(argv, timeout):
        r = runner.run(argv, timeout=timeout)
        return r.code, r.out, r.err, r.timed_out
    try:
        return winguard.query_state(run, script)
    except winguard.QueryFailed:
        fail(2, 'GUARD_QUERY_FAILED', 'Adapter-/Firewallabfrage fehlgeschlagen; kein ungeschuetzter Fallback.')
    except winguard.QueryInvalid as exc:
        fail(2, 'GUARD_QUERY_INVALID', f'{exc}; kein ungeschuetzter Fallback.')


def guard_programs():
    """Alle Programme, die der Downloader mit Netzwerkzugriff startet (Pfade der laufenden Images)."""
    return winguard.guard_programs(sc.real_exe(), FFMPEG, FFPROBE)


def warn_once(key, text):
    if key not in SESSION.warned:
        SESSION.warned.add(key)
        print(text)


def _emit_vpn_ok(vpn, vpn_ips, ips_optional):
    """check-Ereignis 'vpn'. ips_optional: ohne Adresse entfaellt ' · ' (volle Pruefung); die schnelle Pruefung
    setzt es immer (sie kommt ohnehin nur mit bekannter VPN-Adresse hierher)."""
    ips = ' · ' + ', '.join(vpn_ips) if vpn_ips or not ips_optional else ''
    emit('check', key='vpn', ok=True, detail=', '.join(a['name'] for a in vpn) + ips)


def _emit_firewall_ok(programs):
    emit('check', key='firewall', ok=True, detail=f'{len(programs)} Programme gesperrt ausser ueber das VPN')


def ensure_guard(runner, config):
    """Windows-Netzsperre (Gegenstueck zum Linux-Namespace).

    1. Ein aktiver VPN-Adapter (Proton) mit IPv4-Adresse muss existieren.
    2. firewall_enforce: Fuer alle Downloader-Programme muss eine ausgehende Blockregel jeden Verkehr
       sperren, der NICHT von der VPN-Adresse (oder Loopback) ausgeht; IPv6 komplett gesperrt;
       Firewall-Profile an. Die Regeln legt fw.py als Administrator an (qsgrab.cmd firewall apply).
    3. Einmaliger Selbsttest je VPN-Adresse: Eine Verbindung aus einer Nicht-VPN-Adresse muss sofort
       an der Firewall scheitern (WSAEACCES).
    Alles fail-closed: Unklarheit stoppt mit Exit 2, nie ein ungeschuetzter Fallback.
    """
    if sys.platform != 'win32':
        fail(1, 'PLATFORM_UNSUPPORTED', 'Start nur unter Windows moeglich.')
    patterns = config['vpn_adapter_patterns']   # load_config verlangt beide Schluessel
    enforce = config['firewall_enforce']
    if not patterns:
        warn_once('patterns', 'WARNUNG: vpn_adapter_patterns ist leer - keine Adapter- und keine Firewallpruefung. Kill-Switch des VPN-Clients muss allein schuetzen.')
        return
    programs = guard_programs()
    if enforce and SESSION.rules_ok:
        state = query_state(runner, winguard.QUICK_STATE_SCRIPT)
        vpn = winguard.vpn_adapters(state, patterns)
        vpn_ips = winguard.vpn_ipv4(vpn)
        if vpn and guard_key(state, patterns, vpn_ips, programs) in SESSION.rules_ok:
            _emit_vpn_ok(vpn, vpn_ips, ips_optional=False)
            _emit_firewall_ok(programs)
            return
    state = query_state(runner, winguard.STATE_SCRIPT)
    vpn = winguard.vpn_adapters(state, patterns)
    if not vpn:
        emit('check', key='vpn', ok=False, detail='Kein aktiver VPN-Adapter')
        fail(2, 'VPN_ADAPTER_MISSING', 'Kein aktiver VPN-Adapter gefunden (Proton verbinden, Kill-Switch aktivieren). Kein ungeschuetzter Fallback.')
    vpn_ips = winguard.vpn_ipv4(vpn)
    _emit_vpn_ok(vpn, vpn_ips, ips_optional=True)
    if not enforce:
        warn_once('enforce', 'WARNUNG: firewall_enforce = false - nur Adapterpruefung, keine erzwungene Netzsperre.')
        emit('check', key='firewall', ok=None, detail='Abgeschaltet (firewall_enforce = false)')
        return
    if not vpn_ips:
        emit('check', key='firewall', ok=False, detail='VPN-Adapter ohne IPv4-Adresse')
        fail(2, 'VPN_IP_MISSING', 'Der VPN-Adapter hat keine nutzbare IPv4-Adresse.')
    problem = winguard.check_rules(state, programs, vpn_ips)
    if problem:
        emit('check', key='firewall', ok=False, detail=problem[1])
        fail(2, *problem)
    _emit_firewall_ok(programs)
    # Gleicher Schluessel wie rules_ok (inkl. Nicht-VPN-Adressen): eine neue lokale Adresse (z. B. WLAN-Wechsel)
    # wird im selben Lauf erneut im Selbsttest geprueft.
    key = guard_key(state, patterns, vpn_ips, programs)
    if key not in SESSION.selftest_done:
        others = winguard.other_ipv4(state, patterns)
        if others:
            test = runner.run([sys.executable, '-I', '-c', winguard.SELFTEST_CODE] + others, timeout=15 + 4 * len(others))
            open_ips = winguard.parse_selftest(test.out, others)
            if test.timed_out or open_ips:
                emit('check', key='selftest', ok=False, detail='Verbindung an der Firewall vorbei moeglich')
                fail(2, 'FIREWALL_SELFTEST_FAILED', 'Selbsttest: Verbindung aus einer Nicht-VPN-Adresse wurde NICHT von der Firewall blockiert. Regeln mit qsgrab.cmd firewall apply neu setzen.')
            print(f'Netzsperre: Selbsttest bestanden ({len(others)} Nicht-VPN-Adresse(n) blockiert oder ohne Weg ins Netz).')
            emit('check', key='selftest', ok=True, detail=f'{len(others)} andere Adresse(n) blockiert oder ohne Weg ins Netz')
        else:
            print('Netzsperre: Selbsttest uebersprungen (keine weitere lokale IPv4-Adresse neben dem VPN).')
            emit('check', key='selftest', ok=True, detail='Keine weitere lokale Adresse zu pruefen')
        SESSION.selftest_done.add(key)
    SESSION.rules_ok.add(key)


def parse_status(data, source, version=4):
    if not isinstance(data, dict) or data.get('error'):
        raise ValueError('Ungueltiger Status')
    ip = ipaddress.ip_address(data.get('ip', ''))
    if ip.version != version or not ip.is_global:
        raise ValueError('Keine passende oeffentliche IP')
    if source == 'ipinfo.io':
        # ipinfo.io: "country" ist das ISO-Kuerzel, "org" z. B. "AS9009 M247 Europe SRL"; kein Laendername.
        country_code = data.get('country') or ''
        country = country_code
        org = data.get('org')
    else:
        country_code = data.get('country_code') or ''
        country = (data.get('country_name') if source == 'ipapi.co' else data.get('country')) or data.get('country') or ''
        org = data.get('org') if source == 'ipapi.co' else data.get('organization')
    if not isinstance(country_code, str) or (country_code and not re.fullmatch('[A-Za-z]{2}', country_code)):
        raise ValueError('Ungueltiger Laendercode')
    if country_code and country_code.upper() not in ISO_COUNTRIES:
        raise ValueError('Unbekannter Laendercode')
    if not isinstance(country, str) or not (country_code or country.strip()) or not isinstance(org, str) or not org.strip():
        raise ValueError('Land/Organisation fehlt')
    if not country_code and (country.strip().casefold() in {'unknown', 'unbekannt', 'n/a', 'none', 'null', 'undefined', '-', '?'} or not any(c.isalpha() for c in country)):
        raise ValueError('Unbrauchbare Laenderangabe')
    blacklist = data.get('blacklisted')
    if isinstance(blacklist, dict) and blacklist.get('blacklisted') is True:
        print('WARNUNG: Mullvad-Blacklist: ' + safe_text(json.dumps(blacklist.get('results', []), ensure_ascii=False)))
    return {'ip': str(ip), 'country_code': country_code.upper(), 'country': country, 'org': org, 'source': source}


def parse_txt_ips(text):
    """Oeffentliche IPs aus den in Anfuehrungszeichen stehenden TXT-Werten der nslookup-Ausgabe."""
    ips = set()
    for txt in re.findall(r'"([^"\\]*)"', text):
        try:
            ip = ipaddress.ip_address(txt.strip())
        except ValueError:
            continue
        if ip.is_global:
            ips.add(str(ip))
    return ips


def curl_args(max_time, *, first=(), show_error=False, version=None):
    """Gemeinsame curl-Grundregeln: keine Proxys, nur HTTPS, feste Zeitlimits. first steht vor --disable
    (so ruft media_size curl bisher auf - Reihenfolge bewusst unveraendert)."""
    return ([CURL, *first, '--disable', '--silent'] + (['--show-error'] if show_error else []) +
            ['--fail', '--max-time', str(max_time), '--connect-timeout', '5', '--noproxy', '*'] +
            ([f'-{version}'] if version else []) + ['--proto', '=https'])


class Network:
    def __init__(self, config, runner, force=False, skip=False):
        self.c, self.r, self.force, self.skip = config, runner, force, skip
        # Resolver-Geodaten nur fuer diesen Programmlauf (nie gespeichert): ipapi.co drosselt geteilte VPN-Adressen.
        self._dns_geo = {}

    def json_request(self, url, version=4):
        r = self.r.run(curl_args(10, show_error=True, version=version) + ['--max-filesize', '1048576', url], timeout=12)
        if r.code != 0 or r.timed_out:
            raise ValueError('Status-Endpunkt antwortet nicht')
        return json.loads(r.out)

    def status(self):
        for attempt in range(3):
            try:
                return parse_status(self.json_request('https://am.i.mullvad.net/json'), 'am.i.mullvad.net')
            except (ValueError, TypeError):
                if attempt < 2:
                    time.sleep(2)
        print('Status-Fallback: Quelle ipapi.co (Mullvad nach drei Versuchen unbrauchbar).')
        try:
            return parse_status(self.json_request('https://ipapi.co/json/'), 'ipapi.co')
        except (ValueError, TypeError):
            fail(2, 'TUNNEL_STATUS_UNAVAILABLE', 'Mullvad und einmaliger ipapi.co-Fallback ohne brauchbaren Status.')

    def policy(self, info, label, allow_force=True):
        print(f'{label}: IP {info["ip"]} | {safe_text(info["country"])} | {safe_text(info["org"])} | Quelle {info["source"]}')
        detail = f'{info["ip"]} · {info["country_code"] or info["country"]} · {info["org"]} (Quelle {info["source"]})'
        try:
            self._policy(info, label, allow_force)
        except Failure:
            emit('check', key=check_key(label), ok=False, detail=detail, label=label)
            raise
        emit('check', key=check_key(label), ok=True, detail=detail, label=label)

    def _policy(self, info, label, allow_force):
        code, country = info['country_code'], info['country']
        if not code and not country:
            fail(2, 'IP_COUNTRY_UNKNOWN', f'{label}: Land fehlt.')
        if (code == self.c['home_country']) if code else (country.casefold() in {s.casefold() for s in self.c['home_country_names']}):
            fail(2, 'HOME_COUNTRY_DETECTED', f'{label}: Heimatland erkannt.')
        if any(re.search(p, info['org'], re.I) for p in self.c['blocked_orgs']):
            fail(2, 'BLOCKED_ORG', f'{label}: Organisation blockiert.')
        if not any(re.search(p, info['org'], re.I) for p in self.c['allowed_patterns']):
            if self.force and allow_force:
                print('WARNUNG: --force umgeht nur die Organisations-Positivliste fuer IPv4/DNS.')
            else:
                fail(2, 'ORG_NOT_ALLOWLISTED', f'{label}: Organisation nicht auf Positivliste.')

    def ipv6(self):
        """IPv6 ist komplett gesperrt (Nutzerentscheidung): Jeder erreichbare IPv6-Weg stoppt das Tool,
        egal ueber welchen Betreiber - auch mit --force. Die Firewall-Regeln sperren IPv6 ohnehin;
        ist es trotzdem erreichbar, stimmt etwas mit der Netzsperre nicht."""
        try:
            data = self.json_request('https://ipv6.am.i.mullvad.net/json', 6)
        except (ValueError, TypeError):
            print('IPv6: kein Internetpfad nachgewiesen (kein Beleg fuer einen sicheren Pfad).')
            emit('check', key='ipv6', ok=True, detail='Kein IPv6-Weg ins Internet')
            return None
        try:
            info = parse_status(data, 'am.i.mullvad.net', 6)
            detail = f'{info["ip"]} · {info["country_code"] or info["country"]} · {info["org"]} (Quelle {info["source"]})'
        except (ValueError, TypeError, KeyError):
            detail = 'Antwort nicht auswertbar'
        print('IPv6: Internetpfad gefunden - IPv6 ist gesperrt, Abbruch.')
        emit('check', key='ipv6', ok=False, detail='IPv6-Weg offen: ' + detail)
        fail(2, 'IPV6_PATH_OPEN', 'IPv6-Weg ins Internet gefunden, IPv6 ist gesperrt. Netzsperre pruefen (qsgrab.cmd firewall status).')

    def dns(self, known=None):
        """known: im selben Pruefpunkt soeben ermittelter IPv4-Status (fuer identischen Resolver wiederverwendet)."""
        r = self.r.run([NSLOOKUP, '-type=TXT', '-timeout=3', '-retry=1', 'o-o.myaddr.l.google.com'], timeout=20)
        if r.code != 0 or r.timed_out:
            fail(2, 'DNS_RESOLVER_FAILED', 'Systemresolver-TXT-Abfrage fehlgeschlagen.')
        ips = parse_txt_ips(r.out)
        if len(ips) > 1:
            fail(2, 'DNS_RESOLVER_AMBIGUOUS', 'Mehrere rekursive Ausgaenge; keine eindeutige Pruefung.')
        if not ips:
            fail(2, 'DNS_RESOLVER_INVALID', 'Kein eindeutiger oeffentlicher TXT-IP-Wert.')
        resolver = next(iter(ips))
        print('DNS: sichtbar rekursiver Ausgang: ' + resolver)
        if known and known.get('ip') == resolver:
            info = dict(known)
        elif resolver in self._dns_geo:
            info = dict(self._dns_geo[resolver])
        else:
            # Hoechstens eine erfolgreiche Geolokalisierung je neuer Resolveradresse und Lauf.
            # ipapi.co drosselt geteilte VPN-Adressen oft (HTTP 429); dann einmal ipinfo.io.
            version = ipaddress.ip_address(resolver).version
            info = None
            for url, source in ((f'https://ipapi.co/{resolver}/json/', 'ipapi.co'),
                                (f'https://ipinfo.io/{resolver}/json', 'ipinfo.io')):
                try:
                    candidate = parse_status(self.json_request(url), source, version)
                    if candidate['ip'] != resolver:
                        raise ValueError('Falsche Resolver-IP in Geodaten')
                    info = candidate
                    break
                except (ValueError, TypeError):
                    continue
            if info is None:
                fail(2, 'DNS_GEO_FAILED', 'Keine brauchbaren Resolver-Geodaten (ipapi.co und ipinfo.io).')
            self._dns_geo[resolver] = dict(info)
        self.policy(info, 'DNS')
        return resolver

    def check(self, label, expected=None):
        try:
            ensure_guard(self.r, self.c)
            if self.skip:
                return None
            status = self.status()
            self.policy(status, label)
            self.ipv6()
            self.dns(status)
            if expected and status['ip'] != expected:
                fail(2, 'EXIT_IP_CHANGED', 'Exit-IP geaendert; Ergebnis verwerfen und Original-Seitenlink frisch starten.')
            return status['ip']
        except Failure as exc:
            reraise_if_fatal(exc)
            fail(2, 'NETWORK_CHECK_ERROR', 'Netzwerk-Hilfsprozess fehlgeschlagen.')
        except (ValueError, OSError, TypeError, KeyError):
            fail(2, 'NETWORK_CHECK_ERROR', 'Netzwerkstatus konnte nicht vollstaendig geprueft werden.')


def ydl_options(referer):
    return ['--ignore-config', '--no-plugin-dirs', '--no-cache-dir', '--no-playlist',
            '--no-js-runtimes', '--no-remote-components', '--proxy', '', '--socket-timeout', '20',
            '--retries', '0', '--fragment-retries', '0', '--extractor-retries', '0', '--file-access-retries', '0',
            '--no-write-info-json', '--no-write-thumbnail', '--no-write-subs', '--no-write-auto-subs',
            '--referer', referer, '--user-agent', UA, '--ffmpeg-location', str(Path(FFMPEG).parent)]


def ydl_common(referer):
    return YDL + ydl_options(referer)


NO_URL = object()   # ydl_cmd ohne '--' und Adresse (--load-info-json bringt sie mit)


def ydl_cmd(referer, extra, url, first=()):
    """yt-dlp-Aufruf: Modul, first (schnelle Schalter des ersten Transferversuchs), Grundregeln, extra,
    zuletzt '--' und url (url=NO_URL bei --load-info-json)."""
    return YDL + list(first) + ydl_options(referer) + list(extra) + ([] if url is NO_URL else ['--', url])


def origin(url):
    p = urllib.parse.urlsplit(valid_url(url))
    return f'{p.scheme}://{p.netloc}/'


def complete_url(text):
    """Links ohne Schema (z. B. aus Scraping-Tools: "seite.de/redirect/123") bekommen https:// davor."""
    text = text.strip()
    if not re.match(r'[A-Za-z][A-Za-z0-9+.-]*://', text) and re.match(r'(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,}(?::\d+)?(?:[/?#]|$)', text):
        return 'https://' + text
    return text


def is_voe(url, hosts=()):
    p = urllib.parse.urlsplit(url)
    if re.fullmatch(f'/e/{VOE_ID_RE}', p.path):
        return True
    return p.hostname in hosts and bool(re.fullmatch(f'/{VOE_ID_RE}/?', p.path))


def voe_canonical(url):
    return VOE_REFERER + 'e/' + urllib.parse.urlsplit(url).path.strip('/').rsplit('/', 1)[-1]


def run_voe_resolver(url, config, runner, work):
    """Eigener Prozess: VOE-Seite auslesen (folgt bei fremden Hosts vorher nur echten HTTP-Weiterleitungen)."""
    r = runner.run([sys.executable, '-I', str(APP / 'voe_resolver.py'), url, json.dumps(config['voe_hosts'])], timeout=120, cwd=work)
    if r.code != 0 or r.timed_out:
        return None
    try:
        info = json.loads(r.out)
        return {'url': valid_url(info['url']), 'title': info.get('title')}
    except (ValueError, KeyError, TypeError):
        fail(4, 'VOE_RESOLUTION_INVALID', 'VOE lieferte keine eindeutige Medienadresse.')


def link_title(url, manual, found, host_fallback=False):
    """Eigener Name, sonst gefundener Titel, sonst letzter Pfadteil (yt-dlp-Links zuletzt der Hostname)."""
    p = urllib.parse.urlsplit(url)
    title = manual or found or p.path.rsplit('/', 1)[-1]
    return (title or p.hostname) if host_fallback else title


def media_urls(info, media):
    """Alle Medienadressen, die yt-dlp fuer diesen Eintrag abrufen koennte."""
    if info is None:
        return [media or '']
    urls = [info.get('url'), info.get('manifest_url'), info.get('fragment_base_url')]
    for f in (info.get('requested_formats') or []) + (info.get('formats') or []):
        if isinstance(f, dict):
            urls += [f.get('url'), f.get('manifest_url'), f.get('fragment_base_url')]
    return [u for u in urls if isinstance(u, str) and u]


@dataclasses.dataclass
class Item:
    """Aufgeloester Link. Die Hosts der Medienadressen entstehen beim Anlegen: transfer gibt info vor dem
    langen Transfer frei, die Hostpruefung (check_media_hosts) haengt davon nicht ab. Gespeichert werden nur
    die Hostnamen, nicht die signierten Adressen (die sollen mit info aus dem Speicher verschwinden)."""
    name: str = ''
    referer: str = ''
    voe: bool = False
    media: str | None = dataclasses.field(default=None, repr=False)   # signierte Adressen nie in Ausgaben
    info: dict | None = dataclasses.field(default=None, repr=False)   # yt-dlp-Infodaten (--load-info-json)

    def __post_init__(self):
        # Ein Fehler beim Sammeln (z. B. unbrauchbare Formatliste) tritt wie bisher erst in check_media_hosts auf,
        # nicht schon beim Aufloesen (Vorschau/Groessen bleiben davon unberuehrt).
        try:
            self._media_hosts, self._media_error = {urllib.parse.urlsplit(u).hostname for u in media_urls(self.info, self.media)}, None
        except Exception as exc:
            self._media_hosts, self._media_error = None, exc

    @property
    def media_hosts(self):
        """Hosts aller Medienadressen, die yt-dlp fuer diesen Eintrag abrufen koennte (None = ungueltige Adresse)."""
        if self._media_error is not None:
            raise self._media_error
        return set(self._media_hosts)

    def __getitem__(self, key):
        """Lesen wie beim frueheren dict (tests/test_golden.py liest item['name'] usw.)."""
        return getattr(self, key)


def as_item(value):
    """Item; ein dict mit denselben Feldern (Testattrappen) wird umgewandelt."""
    return value if isinstance(value, Item) else Item(**value)


def voe_item(info, url, manual):
    title = link_title(url, manual, info.get('title'))
    return Item(name=video_name(title), media=info['url'], referer=VOE_REFERER, voe=True)


def probe(config, runner, net, work):
    baseline = net.check('IPv4 vor Probe')
    if not net.skip:
        output = work / 'probe.mp4'
        try:
            r = runner.run(ydl_cmd(origin(config['probe_url']), ['--force-generic-extractor', '--newline', '--no-continue',
                                   '-o', str(output)], config['probe_url']), timeout=60, live=True, cwd=work)
            if r.code != 0 or r.timed_out:
                fail(2, 'PROBE_FAILED', f'Probe fehlgeschlagen: Exit={r.code}, Timeout={r.timed_out}.')
            if not output.is_file() or output.is_symlink() or output.stat().st_size == 0:
                fail(2, 'PROBE_OUTPUT_INVALID', 'Probe fehlt oder ist leer.')
        except Failure as exc:
            reraise_if_fatal(exc)
            fail(2, 'PROBE_FAILED', 'Probeprozess fehlgeschlagen.')
        finally:
            output.unlink(missing_ok=True)
    return net.check('IPv4 nach Probe', baseline)


def load_redirect_hosts(environ):
    """Von ui.py mitgegebene Seiten (nur im Speicher der Oberflaeche, nie auf der Festplatte).
    Aendert nur die Reihenfolge der Versuche, nie die Pruefungen; Ungueltiges wird ignoriert."""
    for host in environ.get(REDIRECT_HOSTS_ENV, '').split(',')[:100]:
        host = host.strip().lower()
        if HOST_RE.fullmatch(host):
            SESSION.redirect_hosts.add(host)


def resolve_item(url, manual, config, runner, net, work, baseline):
    valid_url(url)
    if is_voe(url, config['voe_hosts']):
        info = run_voe_resolver(voe_canonical(url), config, runner, work)
        if not info:
            fail(4, 'VOE_RESOLUTION_FAILED', 'VOE-Aufloesung fehlgeschlagen; Hostliste/Erreichbarkeit pruefen.')
        return voe_item(info, url, manual)
    parts = urllib.parse.urlsplit(url)
    redirect_first = parts.scheme == 'https' and parts.hostname in SESSION.redirect_hosts
    if redirect_first:
        # Diese Seite hat in diesem Lauf schon nur per Weiterleitung geklappt: den Weg zuerst versuchen
        # (spart zwei sichere Fehlversuche mit yt-dlp). Gleiche Regeln wie unten; die Pruefung davor
        # hat der Aufrufer gemacht, genau wie sonst vor dem ersten yt-dlp-Versuch.
        info = run_voe_resolver(url, config, runner, work)
        if info:
            return voe_item(info, url, manual)
        net.check('IPv4 vor yt-dlp-Aufloesung', baseline)
    referer, dump = origin(url), ['--skip-download', '--dump-single-json']
    r = runner.run(ydl_cmd(referer, dump, url), timeout=120, cwd=work)
    if r.code and 'Unsupported URL' in r.err + r.out:
        net.check('IPv4 vor Generic-Aufloesung', baseline)
        r = runner.run(ydl_cmd(referer, dump + ['--force-generic-extractor'], url), timeout=120, cwd=work)
    if (r.code != 0 or r.timed_out) and parts.scheme == 'https' and not redirect_first:
        # Weiterleitungslink (z. B. einer Mediathek) auf VOE? Nur echte HTTP-Weiterleitungen, Ziel muss in voe_hosts liegen.
        net.check('IPv4 vor Weiterleitungs-Aufloesung', baseline)
        info = run_voe_resolver(url, config, runner, work)
        if info:
            SESSION.redirect_hosts.add(parts.hostname)
            emit('redirect_host', host=parts.hostname)   # ui.py merkt es sich im Speicher fuer spaetere Laeufe
            return voe_item(info, url, manual)
    if r.code != 0 or r.timed_out:
        detail = safe_text((r.err + '\n' + r.out)[-2000:]).strip()
        fail(4, 'LINK_RESOLUTION_FAILED', f'Link nicht aufloesbar (yt-dlp Exit={r.code}, Timeout={r.timed_out}): {detail}')
    try:
        info = json.loads(r.out)
        if not info.get('url') and not any(x.get('url') for x in info.get('formats', [])):
            raise ValueError('Keine Medieninformationen')
        if info.get('_type') in ('playlist', 'multi_video'):
            raise ValueError('Keine einzelnen Medieninformationen')
        title = link_title(url, manual, info.get('title'), host_fallback=True)
        name = video_name(title)
    except (ValueError, TypeError):
        fail(4, 'LINK_INFO_INVALID', 'Keine brauchbaren einzelnen Medieninformationen.')
    # Ausserhalb des try: ein Fehler beim Sammeln der Medienadressen endet wie bisher nicht als LINK_INFO_INVALID.
    return Item(name=name, referer=referer, info=info)


def ffprobe(path, runner):
    r = runner.run([FFPROBE, '-v', 'error', '-show_format', '-show_streams', '-show_chapters', '-show_data_hash', 'sha256', '-of', 'json', str(path)], timeout=60, cwd=path.parent)
    if r.code != 0 or r.timed_out:
        fail(5, 'FFPROBE_FAILED', 'ffprobe fehlgeschlagen.')
    try:
        data = json.loads(r.out)
        if not data.get('format') or not data.get('streams'):
            raise ValueError('Format/Streams fehlen')
        return data
    except (ValueError, TypeError):
        fail(5, 'FFPROBE_EMPTY', 'Keine brauchbaren Format-/Streamdaten.')


# Veroeffentlichte Endungen (container_extension) - publish prueft Namenskollisionen ueber alle.
EXTENSIONS = (EXT_MP4, EXT_MKV, EXT_AVI) = ('.mp4', '.mkv', '.avi')

# Neutrale Pflichtwerte, die der Remux in jede Spur schreibt: (ffmpeg-Spurauswahl, Tag, Wert).
# Dieselbe Tabelle erzeugt die ffmpeg-Argumente und die Allowlist in check_metadata.
REMUX_TAGS = (('s', 'language', 'und'),
              ('s:v', 'handler_name', 'VideoHandler'),
              ('s:a', 'handler_name', 'SoundHandler'),
              ('s:s', 'handler_name', 'SubtitleHandler'),
              ('s:t', 'filename', 'attachment.bin'),
              ('s:t', 'mimetype', 'application/octet-stream'))
_STREAM_KINDS = {'v': 'video', 'a': 'audio', 's': 'subtitle', 't': 'attachment'}
_LANGUAGE = next(value for spec, tag, value in REMUX_TAGS if tag == 'language')
_HANDLERS = {_STREAM_KINDS[spec[2:]]: value for spec, tag, value in REMUX_TAGS if tag == 'handler_name'}
_ATTACHMENT_TAGS = {tag: value for spec, tag, value in REMUX_TAGS if spec == 's:t'}


def remux_metadata_args():
    args = ['-metadata', 'encoder=', '-metadata:s', 'encoder=']
    for spec, tag, value in REMUX_TAGS:
        args += ['-metadata:' + spec, f'{tag}={value}']
    return args


def container_extension(data):
    names = set(data['format'].get('format_name', '').split(','))
    if names & {'mov', 'mp4'}:
        return EXT_MP4
    if 'matroska' in names or names == {'mpegts'}:
        # Native HLS often delivers MPEG-TS. TS itself is never published:
        # remux every selected stream into MKV without transcoding codecs.
        return EXT_MKV
    if 'avi' in names:
        return EXT_AVI
    fail(1, 'CONTAINER_UNSUPPORTED', 'Nicht unterstuetzter Container: ' + ','.join(sorted(names)))


def check_metadata(data):
    extension = container_extension(data)
    if data.get('chapters'):
        fail(5, 'METADATA_CHAPTERS', 'Kapitel sind nicht entfernt.')
    try:
        duration = float(data['format'].get('duration', 0))
    except (ValueError, TypeError):
        duration = 0
    for index, block in enumerate([data['format']] + data['streams']):
        kind = block.get('codec_type') if index else 'format'
        for key, value in block.get('tags', {}).items():
            tag = key.lower()
            ok = False
            if tag == 'language':
                ok = kind in _STREAM_KINDS.values() and value == _LANGUAGE
            elif tag == 'handler_name':
                ok = extension in (EXT_MP4, EXT_MKV) and value == _HANDLERS.get(kind)
            elif tag == 'vendor_id':
                # FFmpeg >= 6.1 meldet den neutralen MP4-Standardwert; jeder andere Wert wird abgelehnt.
                ok = extension == EXT_MP4 and kind in ('video', 'audio') and value == '[0][0][0][0]'
            elif extension == EXT_MP4 and kind == 'format':
                allowed = {'major_brand': {'isom', 'mp42', 'mp41'}, 'minor_version': {'0', '512'},
                           'compatible_brands': {'isomiso2avc1mp41', 'isomiso2mp41', 'isomiso2avc1mp41av01', 'mp42mp41isom'}}
                ok = value in allowed.get(tag, set())
            if extension == EXT_MKV:
                if tag == 'encoder':
                    ok = kind == 'format' and value == 'Lavf'
                elif tag == 'duration' and kind in ('video', 'audio', 'subtitle'):
                    match = re.fullmatch(r'(\d{2}):([0-5]\d):([0-5]\d)\.(\d{9})', str(value))
                    if match and math.isfinite(duration):
                        h, m, s, ns = map(int, match.groups())
                        seconds = h*3600 + m*60 + s + ns/1e9
                        ok = 0 <= seconds <= duration + 0.1
                elif kind == 'attachment' and tag in _ATTACHMENT_TAGS:
                    ok = value == _ATTACHMENT_TAGS[tag]
            if not ok:
                fail(5, 'METADATA_TAGS_NOT_ALLOWED', f'Nicht erlaubter Metadatenwert: {safe_text(key)} (Wert wird nicht protokolliert).')


def selected_streams(data):
    videos = [s for s in data['streams'] if s['codec_type'] == 'video']
    if not videos:
        fail(1, 'VIDEO_STREAM_MISSING', 'Keine Videospur.')
    return [videos[0]] + [s for kind in ('audio', 'subtitle', 'attachment') for s in data['streams'] if s['codec_type'] == kind]


def verify_streams(expected, after):
    """expected: selected_streams() der Eingabe."""
    actual = after['streams']
    if len(expected) != len(actual):
        fail(5, 'STREAMS_LOST', 'Anzahl der Video-/Audio-/Untertitel-/Anhangsspuren abweichend.')
    for a, b in zip(expected, actual):
        if a.get('codec_type') == b.get('codec_type') == 'attachment':
            # Neutral filename/MIME can change ffprobe's inferred attachment codec.
            # Preserve and compare the actual attachment bytes instead.
            if not a.get('extradata_hash') or a.get('extradata_hash') != b.get('extradata_hash') or a.get('extradata_size') != b.get('extradata_size'):
                fail(5, 'ATTACHMENT_CHANGED', 'Anhangsinhalt konnte nicht unveraendert nachgewiesen werden.')
            continue
        if any(a.get(k) != b.get(k) for k in ('codec_type', 'codec_name')):
            fail(5, 'STREAMS_CHANGED', 'Streamtyp oder Codec abweichend; kein stilles Weglassen erlaubt.')


def remux(raw, runner):
    before = ffprobe(raw, runner)
    expected = selected_streams(before)
    extension = container_extension(before)
    clean = raw.parent / ('clean' + extension)
    args = [FFMPEG, '-nostdin', '-v', 'warning', '-n', '-i', str(raw),
            '-map', '0:v:0', '-map', '0:a?', '-map', '0:s?', '-map', '0:t?',
            '-fflags', '+bitexact', '-flags', '+bitexact', '-map_metadata', '-1', '-map_metadata:s', '-1',
            '-map_chapters', '-1', *remux_metadata_args(), '-c', 'copy', str(clean)]
    r = runner.run(args, timeout=1200, live=True, cwd=raw.parent)
    if r.code != 0 or r.timed_out or not clean.is_file() or clean.stat().st_size == 0:
        fail(5, 'FFMPEG_FAILED', 'Remux fehlgeschlagen (Stream/Container unvertraeglich oder Timeout).')
    after = ffprobe(clean, runner)
    check_metadata(after)
    verify_streams(expected, after)
    return clean, extension


def transfer(item, config, runner, net, work, baseline):
    item = as_item(item)
    # voe_item setzt den Referer immer; die Sperre bleibt als Schutz, falls ein VOE-Item anders entsteht.
    if item.voe and (item.referer != VOE_REFERER or not UA):
        fail(1, 'VOE_HEADERS_MISSING', 'VOE-Transfer ohne Pflichtheader verweigert.')
    extra = ['--newline', '--no-continue', '--abort-on-unavailable-fragments',
            '--hls-prefer-native', '--fixup', 'never', '--merge-output-format', 'mkv', '-o', str(work / 'raw.%(ext)s'),
            '--print-to-file', 'after_move:filepath', str(work / 'result-path.txt')]
    if item.info is not None:
        info_file = work / 'media.json'
        with info_file.open('w', encoding='utf-8') as stream:
            json.dump(item.info, stream)
        # The private info file is already required for --load-info-json/retry.
        # Release Python's format/URL graph before the long transfer starts.
        item.info = None
        extra += ['--load-info-json', str(info_file)]
        url = NO_URL
    else:
        extra += ['--force-generic-extractor']
        url = item.media
    fast = ['--http-chunk-size', '10M', '--concurrent-fragments', '4']
    for attempt in range(2):
        for old in work.iterdir():
            if old.name.startswith('raw.') or old.name == 'result-path.txt':
                if not old.is_file() or old.is_symlink():
                    fail(4, 'PARTIAL_UNSAFE', 'Unsicherer Teilstand.')
                old.unlink()
        net.check('IPv4 unmittelbar vor Transfer' if not attempt else 'IPv4 vor kompatiblem Retry', baseline)
        # No external preparatory operations between this checkpoint and transfer.
        current = ydl_cmd(item.referer, extra, url, first=fast if not attempt else ())
        result = runner.run(current, timeout=config['download_timeout_sec'], live=True, cwd=work)
        if result.code == 0 and not result.timed_out:
            try:
                lines = (work / 'result-path.txt').read_text(encoding='utf-8').splitlines()
                if len(lines) != 1:
                    raise ValueError('Kein eindeutiger Dateipfad')
                raw = Path(lines[0])
                if not raw.is_absolute():
                    raw = work / raw
                if raw.parent != work or raw.is_symlink() or not raw.name.startswith('raw.') or not raw.is_file() or raw.stat().st_size == 0:
                    raise ValueError('Unbrauchbare Rohdatei')
                return raw
            except (OSError, ValueError):
                fail(4, 'DOWNLOAD_OUTPUT_INVALID', 'Erfolgreicher Exit ohne eindeutige nichtleere Rohdatei.')
        if attempt == 0:
            print('WARNUNG: Transfer fehlgeschlagen; einmal frisch ohne HTTP-Chunks/parallele Fragmente.')
    fail(4, 'DOWNLOAD_FAILED', f'yt-dlp fehlgeschlagen: Exit={result.code}, Timeout={result.timed_out}.')


def check_media_hosts(item):
    """Vor dem Transfer: Videoquellen nur im oeffentlichen Internet - nie Heimnetz oder der eigene PC
    (eine praeparierte Seite koennte sonst Anfragen an lokale Geraete/Dienste ausloesen)."""
    hosts = as_item(item).media_hosts
    if not hosts or None in hosts:
        fail(4, 'MEDIA_HOST_INVALID', 'Videoquelle ohne gueltigen Host.')
    if len(hosts) > 20:
        fail(4, 'MEDIA_HOST_INVALID', 'Zu viele verschiedene Videoquellen.')
    for host in sorted(hosts):
        try:
            public_host(host)
        except ValueError:
            fail(4, 'MEDIA_HOST_PRIVATE', 'Videoquelle zeigt ins lokale Netz oder auf diesen PC - verweigert.')


def download(url, manual, config, runner, net, store):
    with store.workspace() as work:
        phase(PHASE_PROBE)
        baseline = probe(config, runner, net, work)
        phase(PHASE_RESOLVE)
        item = as_item(resolve_item(url, manual, config, runner, net, work, baseline))
        print('Name: ' + safe_text(item.name))
        emit('title', name=item.name)
        phase(PHASE_DOWNLOAD)
        check_media_hosts(item)
        raw = transfer(item, config, runner, net, work, baseline)
        phase(PHASE_REMUX)
        clean, extension = remux(raw, runner)
        phase(PHASE_VERIFY)
        net.check('IPv4 nach Transfer/Remux', baseline)
        target = store.publish(clean, item.name, extension)
        print('Fertig: ' + str(target))
        try:
            size = target.stat().st_size
        except OSError:
            size = None
        emit('done', file=target.name, size=size)
        phase(PHASE_DONE)
        return target


MAX_PREVIEW = 50


def read_preview_urls(stream):
    """Links fuer --preview: einer pro Zeile (Standardeingabe statt Kommandozeile - nicht in der Prozessliste)."""
    urls = [line.strip() for line in stream.read(1024 * 1024).splitlines() if line.strip()]
    if not urls or len(urls) > MAX_PREVIEW:
        fail(1, 'INPUT_URL_INVALID', f'1 bis {MAX_PREVIEW} Links erwartet.')
    for url in urls:
        try:
            valid_url(url)
        except ValueError:
            fail(1, 'INPUT_URL_INVALID', 'Ungueltige HTTP/HTTPS-URL in der Vorschau.')
    return urls


def reraise_if_fatal(exc):
    """Ein Sicherheitsabbruch (Exit 2) geht immer unveraendert weiter; andere Fehler behandelt der Aufrufer."""
    if exc.code == 2:
        raise exc


def for_each_link(urls, net, baseline, labels, announce, step):
    """Schleife fuer Vorschau, Groessen und den interaktiven Modus: announce(i), dann Pruefpunkt labels[0]
    vor jedem Link (die Aufloesung braucht ihn, siehe resolve_item), dann step(i, url); nach dem letzten Link
    Pruefpunkt labels[1]. Exit 2 bricht sofort ab, andere Fehler werden je Link geliefert.
    Liefert (Index, Ergebnis oder None, Failure oder None)."""
    before, after = labels
    for i, url in enumerate(urls):
        announce(i)
        try:
            # Auch je Eintrag pruefen: Eingabe und Aufloesung koennen dauern.
            net.check(before, baseline)
            result = step(i, url)
        except Failure as exc:
            reraise_if_fatal(exc)
            yield i, None, exc
            continue
        yield i, result, None
    net.check(after, baseline)


def queue_summary(ok, skipped, aborted):
    print(f'Warteschlange: {ok} erfolgreich, {skipped} übersprungen, {aborted} abgebrochen')


def resolve_titles(urls, config, runner, net, work, baseline, manual=None):
    """Titel aller Links ermitteln (Kommandozeile und Oberflaeche): Pruefpunkt vor jedem Eintrag und
    danach. Ein Sicherheitsabbruch (Exit 2) beendet sofort; ein nicht aufloesbarer Link wird gemeldet
    und der naechste geprueft. Liefert (Index, Name oder None, Failure oder None) - nur den Namen,
    nie signierte Medienadressen."""
    def announce(i):
        emit('preview_start', index=i)
        print(f'Pruefe Link {i+1}/{len(urls)}...')

    def title(i, url):
        item = resolve_item(url, f'{manual}_{i+1}' if manual else None, config, runner, net, work, baseline)
        return as_item(item).name
    return for_each_link(urls, net, baseline, ('IPv4 vor Vorschau-Eintrag', 'IPv4 nach Vorschau'), announce, title)


def preview(config, runner, net, store, urls):
    """--preview fuer die Oberflaeche: Titel ermitteln, ohne herunterzuladen."""
    phase(PHASE_PREVIEW)
    failed = 0
    with store.workspace() as work:
        baseline = net.check('IPv4 vor Vorschau')
        for i, name, exc in resolve_titles(urls, config, runner, net, work, baseline):
            if exc is None:
                print(f'{i+1}. OK: ' + safe_text(name))
                emit('preview', index=i, ok=True, name=name)
            else:
                failed += 1
                print(f'{i+1}. FEHLER: ' + safe_text(exc))
                emit('preview', index=i, ok=False, ident=exc.ident, code=exc.code, message=str(exc))
    emit('previewed', total=len(urls), failed=failed)
    return 0


def _header_size(text):
    """Groesse aus Antwortkoepfen (bei Weiterleitungen zaehlt der letzte Block)."""
    size = None
    for line in text.splitlines():
        name, _, value = line.partition(':')
        name, value = name.strip().lower(), value.strip()
        if name == 'content-range' and '/' in value and value.rsplit('/', 1)[1].isdigit():
            size = int(value.rsplit('/', 1)[1])
        elif name == 'content-length' and value.isdigit():
            size = int(value)
        elif line.upper().startswith('HTTP/'):
            size = None
    return size if size and size > 1 else None


def _header_location(text):
    """Ziel einer Weiterleitung (3xx + Location), sonst None."""
    lines = text.splitlines()
    status = lines[0].split() if lines else []
    if len(status) < 2 or not status[1].isdigit() or not 300 <= int(status[1]) < 400:
        return None
    for line in lines[1:]:
        name, _, value = line.partition(':')
        if name.strip().lower() == 'location' and value.strip():
            return value.strip()
    return None


def media_size(item, runner, work):
    """Dateigroesse ohne Download: yt-dlp-Angaben, sonst Kopfzeilen der Videodatei (HEAD, notfalls 1 Byte).
    HLS-Streams haben keine Gesamtgroesse -> None. Die Medienadresse geht per Standardeingabe an curl."""
    item = as_item(item)
    info = item.info
    if info is not None:
        size = info.get('filesize') or info.get('filesize_approx')
        if not size and info.get('requested_formats'):
            parts = [f.get('filesize') or f.get('filesize_approx') for f in info['requested_formats']]
            size = sum(parts) if all(parts) else None
        return int(size) if isinstance(size, (int, float)) and size > 0 else None
    url = item.media or ''
    if '.m3u8' in urllib.parse.urlsplit(url).path:
        return None
    # Weiterleitungen nicht blind folgen: jedes Ziel nur HTTPS und nur oeffentliche Adressen
    # (kein Heimnetz, kein 127.0.0.1) - gleiche Regel wie voe_resolver.follow().
    for _ in range(MAX_SIZE_HOPS):
        p = urllib.parse.urlsplit(url)
        # Nur das Schema, kein Port wie bei voe_resolver.https_443 (bewusst unveraendert).
        if p.scheme != 'https' or not p.hostname:
            return None
        try:
            public_host(p.hostname)
        except ValueError:
            return None
        config_text = 'url = "' + url.replace('\\', '\\\\').replace('"', '\\"') + '"\n'
        target = None
        for extra in (['--head'], ['--range', '0-0', '--dump-header', '-', '--output', os.devnull]):
            argv = curl_args(15, first=extra) + ['--user-agent', UA, '--referer', item.referer, '--config', '-']
            r = runner.run(argv, timeout=20, cwd=work, input_text=config_text)
            if r.code != 0 or r.timed_out:
                continue
            location = _header_location(r.out)
            if location:
                target = urllib.parse.urljoin(url, location)
                break
            size = _header_size(r.out)
            if size:
                return size
        if not target:
            return None
        url = target
    return None


def sizes(config, runner, net, store, urls):
    """--sizes fuer die Oberflaeche: Dateigroessen der wartenden Links ermitteln, ohne herunterzuladen."""
    phase(PHASE_SIZES)
    with store.workspace() as work:
        baseline = net.check('IPv4 vor Groessenabfrage')

        def announce(i):
            emit('size_start', index=i)
            print(f'Groesse {i+1}/{len(urls)}...')

        def size_of(i, url):
            return media_size(resolve_item(url, None, config, runner, net, work, baseline), runner, work)
        for i, size, exc in for_each_link(urls, net, baseline, ('IPv4 vor Groessen-Eintrag', 'IPv4 nach Groessenabfrage'),
                                          announce, size_of):
            if exc is not None:
                print(f'{i+1}. Groesse unbekannt: ' + safe_text(exc))
                emit('size', index=i, bytes=None)
                continue
            print(f'{i+1}. Groesse: ' + (f'{size / 1024**2:.0f} MB' if size else 'unbekannt'))
            emit('size', index=i, bytes=size)
    emit('sized', total=len(urls))
    return 0


def run_queue(entries, execute):
    ok = skipped = aborted = 0
    code = 0
    for i, entry in enumerate(entries):
        if not entry['valid']:
            skipped += 1
            code = 1
            continue
        try:
            execute(entry, i+1, len(entries))
            ok += 1
        except Failure as exc:
            error(exc)
            if exc.code == 2:
                aborted = len(entries)-i
                code = 2
                break
            skipped += 1
            code = 1
        except KeyboardInterrupt:
            aborted = len(entries)-i
            code = 1
            break
    queue_summary(ok, skipped, aborted)
    return code


def interactive(config, runner, net, store, manual=None):
    urls = []
    print('Ein HTTP/HTTPS-Link pro Zeile; leere Zeile, fertig oder ende beendet die Eingabe.')
    while True:
        line = input(f'Link {len(urls)+1}: ').strip()
        if not line or line.casefold() in ('fertig', 'ende'):
            break
        try:
            line = complete_url(line)
            valid_url(line)
            urls.append(line)
        except ValueError:
            print('Ungueltiger Link; vollstaendige HTTP/HTTPS-Adresse erforderlich.')
    if not urls:
        queue_summary(0, 0, 0)
        return 0
    entries = []
    try:
        with store.workspace() as work:
            baseline = probe(config, runner, net, work)
            for i, name, exc in resolve_titles(urls, config, runner, net, work, baseline, manual):
                entries.append({'url': urls[i], 'name': name, 'valid': True} if exc is None else
                               {'url': urls[i], 'name': '', 'valid': False, 'error': safe_text(exc)})
    except Failure as exc:
        error(exc)
        queue_summary(0, 0, len(urls))
        return exc.code
    for i, item in enumerate(entries):
        print(f'{i+1}. ' + ('OK: ' + safe_text(item['name']) if item['valid'] else 'FEHLER: ' + item['error']))
    if not any(x['valid'] for x in entries):
        queue_summary(0, len(entries), 0)   # alle Links unbrauchbar: nichts zu starten
        return 1
    while True:
        answer = input('Enter startet; abbrechen verwirft die Liste: ').strip().casefold()
        if answer == 'abbrechen':
            queue_summary(0, 0, len(entries))
            return 0
        if not answer:
            break
        print('Bitte Enter oder abbrechen eingeben.')
    def execute(item, index, total):
        SESSION.position = (index, total)
        download(item['url'], item['name'], config, runner, net, store)
    return run_queue(entries, execute)


def main(argv=None):
    parser = argparse.ArgumentParser(description='Quite Safe Grab fuer Windows — nur mit aktivem VPN (Proton-Kill-Switch).')
    parser.add_argument('url', nargs='?')
    parser.add_argument('name', nargs='?')
    parser.add_argument('--config', default=str(APP / 'config.toml'))
    parser.add_argument('--force', action='store_true', help='SICHTBARE AUSNAHME: IPv4-/DNS-Organisationspositivliste umgehen; keine Heimatland-/Blocklist-/Adapter-Ausnahme.')
    parser.add_argument('--skip-check', action='store_true', help='SICHTBARE AUSNAHME: IP/DNS/Probe/Stabilitaetskontrollen auslassen; VPN-Adapter-/Firewallpruefung bleibt Pflicht.')
    parser.add_argument('--check-only', action='store_true', help='Nur alle Sicherheitspruefungen ausfuehren (kein Download).')
    parser.add_argument('--events', action='store_true', help=argparse.SUPPRESS)  # Ereigniszeilen fuer ui.py
    parser.add_argument('--preview', action='store_true',
                        help='Nur Titel ermitteln (ein Link pro Zeile auf der Standardeingabe), kein Download.')
    parser.add_argument('--sizes', action='store_true', help=argparse.SUPPRESS)  # Dateigroessen fuer ui.py (Links auf stdin)
    args = parser.parse_args(argv)
    SESSION.events = args.events
    if SESSION.events:
        # Ausgabe geht in eine Pipe zu ui.py: immer UTF-8 statt der Windows-Codepage.
        for stream in (sys.stdout, sys.stderr, sys.stdin):
            with contextlib.suppress(AttributeError, ValueError):
                stream.reconfigure(encoding='utf-8', errors='replace')
        load_redirect_hosts(os.environ)   # nur im Oberflaechen-Betrieb
    try:
        if sys.platform != 'win32':
            fail(1, 'PLATFORM_UNSUPPORTED', 'Start nur unter Windows moeglich.')
        runner = Runner()
        config = load_config(args.config)
        phase(PHASE_CHECKS)
        ensure_guard(runner, config)
        if args.check_only:
            if args.url:
                fail(1, 'INPUT_CONFLICT', '--check-only nimmt keine Adresse an.')
            Network(config, runner).check('IPv4 Statuspruefung')
            print('Pruefung bestanden: alle Sicherheitspruefungen ohne Befund.')
            emit('checked', ok=True)
            return 0
        if args.force:
            print('WARNUNG: --force aktiv: nur IPv4-/DNS-Organisationspositivliste wird umgangen.')
        if args.skip_check:
            print('WARNUNG: --skip-check aktiv: KEINE IP/DNS/Probe/IP-Stabilitaetspruefung; VPN-Adapter-/Firewallpruefung weiterhin zwingend.')
        net = Network(config, runner, args.force, args.skip_check)
        store = Store(config['storage'])
        store.cleanup()
        if args.preview:
            if args.url:
                fail(1, 'INPUT_CONFLICT', '--preview liest die Links von der Standardeingabe.')
            return preview(config, runner, net, store, read_preview_urls(sys.stdin))
        if args.sizes:
            if args.url:
                fail(1, 'INPUT_CONFLICT', '--sizes liest die Links von der Standardeingabe.')
            return sizes(config, runner, net, store, read_preview_urls(sys.stdin))
        if args.url:
            args.url = complete_url(args.url)
            try:
                valid_url(args.url)
            except ValueError:
                fail(1, 'INPUT_URL_INVALID', 'Ungueltige HTTP/HTTPS-URL.')
            download(args.url, args.name, config, runner, net, store)
            return 0
        return interactive(config, runner, net, store, args.name)
    except Failure as exc:
        error(exc)
        return exc.code
    except (KeyboardInterrupt, EOFError):
        error(Failure(1, 'USER_ABORT', 'Durch Benutzer/Eingabeende abgebrochen.'))
        return 1
    except Exception as exc:
        error(Failure(1, 'UNEXPECTED_ERROR', f'Unerwarteter Fehler ({type(exc).__name__}); kein Erfolg gemeldet.'))
        return 1


def _interrupt(signum, frame):
    raise KeyboardInterrupt()


if __name__ == '__main__':
    for _sig in (signal.SIGTERM, getattr(signal, 'SIGBREAK', None)):
        if _sig is not None:
            signal.signal(_sig, _interrupt)
    sys.exit(main())
