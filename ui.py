# SPDX-License-Identifier: GPL-3.0-only
"""QuiteSafeGrab-Oberflaeche: kleiner lokaler Webserver plus Browserfenster.

Sicherheitsmodell
- Lauscht nur auf 127.0.0.1 (zufaelliger Port), nie im Netz erreichbar.
- Jede API-Anfrage braucht das zufaellige Zugriffstoken dieses Starts (Kopfzeile X-QSGrab-Token);
  Host- und Origin-Kopf muessen genau dieser Server sein (gegen fremde Webseiten / DNS-Rebinding).
- Strenge Content-Security-Policy: die Seite laedt nichts von aussen.
- Die API nimmt nur Links und Dateinamen an, nie Pfade oder Befehle.
- Downloads und alle Sicherheitspruefungen laufen unveraendert in grab.py (eigener Prozess);
  die Oberflaeche startet ihn nur und zeigt seine Ereignisse an.
- Warteschlange und Links liegen nur im Speicher. Gespeichert werden nur die letzten
  Pruefergebnisse (ohne Links) in <storage>\\.state\\ui-checks.json.
"""
from __future__ import annotations

import argparse
import collections
import dataclasses
import hmac
import http.server
import json
import os
from pathlib import Path
import secrets
import shutil
import subprocess
import sys
import threading
import time
import urllib.parse
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parent))
import common
import grab as g
import syscompat as sc

APP = Path(__file__).resolve().parent
STATIC = {'/': ('index.html', 'text/html; charset=utf-8'),
          '/app.css': ('app.css', 'text/css; charset=utf-8'),
          '/app.js': ('app.js', 'text/javascript; charset=utf-8'),
          '/logo.png': ('logo.png', 'image/png'),
          '/favicon.png': ('favicon.png', 'image/png'),
          '/favicon.ico': ('favicon.png', 'image/png')}
CSP = ("default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; "
       "base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
CHECK_KEYS = g.CHECK_KEYS
MAX_BODY = 64 * 1024
MAX_QUEUE = 200
MAX_NAME = 120
# Beenden: sobald das von Quite Safe Grab gestartete Browserfenster zu ist (und nichts laeuft).
# Ohne erkennbares Browserfenster erst nach langer Funkstille - Browser drosseln Timer in
# minimierten Fenstern stark, eine kurze Frist wuerde Quite Safe Grab faelschlich beenden.
IDLE_EXIT_SEC = 30 * 60
BROWSER_GONE_GRACE_SEC = 10
WATCHDOG_INTERVAL_SEC = 2
# Wird das Browserfenster bis dahin nie als offen erkannt, gilt es als geschlossen.
BROWSER_START_GRACE_SEC = 120

# Anzeige-Konstanten fuer app.js (kommen mit /api/state, damit sie nur hier stehen).
# Pruefpunkte: Beschriftung und Hinweis, solange dieser Punkt gerade geprueft wird (Reihenfolge = CHECK_KEYS).
CHECK_INFO = {
    'vpn': ('VPN-Adapter', 'Sicherheitsprüfung: VPN-Adapter wird geprüft …'),
    'firewall': ('Netzsperre', 'Sicherheitsprüfung: Netzsperre (Firewall) wird geprüft …'),
    'selftest': ('Selbsttest', 'Sicherheitsprüfung: Selbsttest der Netzsperre …'),
    'ipv4': ('IPv4-Ausgang', 'Sicherheitsprüfung: IPv4-Ausgang wird geprüft …'),
    'ipv6': ('IPv6', 'Sicherheitsprüfung: IPv6 wird geprüft …'),
    'dns': ('DNS-Ausgang', 'Sicherheitsprüfung: DNS-Ausgang wird geprüft …'),
}
# Phasen eines Downloads: Beschriftung und Hinweis, solange noch nichts heruntergeladen wird.
PHASE_INFO = {
    common.PHASE_CHECKS: ('Prüfen', 'Sicherheitsprüfung läuft (VPN, Firewall, IP, DNS) – der Download beginnt gleich.'),
    common.PHASE_PROBE: ('Probe', 'Kurzer Probe-Download zur Kontrolle der Verbindung – der Download beginnt gleich.'),
    common.PHASE_RESOLVE: ('Auflösen', 'Video wird gesucht – der Download beginnt gleich.'),
    common.PHASE_DOWNLOAD: ('Download', 'Verbindung zum Video wird aufgebaut …'),
    common.PHASE_REMUX: ('Remux', 'Video wird fertiggestellt (ohne Qualitätsverlust) …'),
    common.PHASE_VERIFY: ('Abschluss', 'Abschlussprüfung der Verbindung …'),
}
UI_META = {
    'checks': [{'key': k, 'label': CHECK_INFO[k][0], 'hint': CHECK_INFO[k][1]} for k in CHECK_KEYS],
    'checks_done_hint': 'Sicherheitsprüfung bestanden – es geht gleich los …',
    'phases': [{'key': p, 'label': PHASE_INFO[p][0], 'hint': PHASE_INFO[p][1]} for p in common.DOWNLOAD_PHASES],
    'status': {'waiting': 'wartet', 'running': 'läuft', 'done': 'fertig', 'failed': 'Fehler', 'stopped': 'angehalten'},
    'limits': {'name': MAX_NAME},
}
# Phasen, ab denen die Fortschrittswerte des vorigen Abschnitts nicht mehr gelten.
RESET_PROGRESS_PHASES = (common.PHASE_RESOLVE, common.PHASE_DOWNLOAD, common.PHASE_REMUX, common.PHASE_VERIFY)
# Abschlussmeldungen von grab.py, die die Oberflaeche bewusst nicht auswertet: Ergebnis ist der Exitcode des Prozesses.
IGNORED_EVENTS = frozenset({'checked', 'previewed', 'sized'})


def now():
    return round(time.time(), 3)


def clean_name(text):
    text = (text or '').strip()
    if not text:
        return ''
    if len(text) > MAX_NAME or any(c in text for c in '<>:"/\\|?*') or any(ord(c) < 32 for c in text):
        raise ValueError(f'Dateiname darf hoechstens {MAX_NAME} Zeichen und keine der Zeichen < > : " / \\ | ? * enthalten.')
    return text


def display_name(item):
    """Anzeige- und Dateiname eines Eintrags: eigener Name, sonst der gefundene Titel (wie die Kommandozeile)."""
    return item.get('name') or item.get('title')


def make_error(ev):
    """Fehler-Dict aus einem grab.py-Ereignis (ohne Adressen, gekuerzt)."""
    return {'ident': str(ev.get('ident', '')), 'code': ev.get('code'), 'message': g.safe_text(ev.get('message', ''))[:500]}


def banner(level, text):
    return {'level': level, 'text': text}


def security_banner(message, where=''):
    """Sicherheitsabbruch: haelt wie in der Kommandozeile die ganze Warteschlange an."""
    return banner('bad', f'Sicherheitsabbruch{where}: {message} Die Warteschlange wurde angehalten.')


def internal_error_banner(part, exc):
    return banner('bad', f'Interner Fehler der {part} ({type(exc).__name__}).')


class BatchJob:
    """Ein Stapel fuer grab.py --preview oder --sizes: Zeile i auf stdin gehoert zu Ereignis-Index i.

    field ist das Statusfeld der Eintraege ('title_state' bzw. 'size_state'). Alle Zugriffe unter State.lock.
    """

    def __init__(self, items, field):
        self.items, self.field = list(items), field
        self.error = None   # letztes error-Ereignis dieses Stapels (nur im Speicher)
        for item in self.items:
            item[field] = 'queued'

    def __len__(self):
        return len(self.items)

    def stdin_text(self):
        return '\n'.join(x['url'] for x in self.items) + '\n'

    def at(self, ev):
        """(Index, Eintrag) zum Ereignis-Index, (None, None) bei ungueltigem Index."""
        idx = ev.get('index')
        if not isinstance(idx, int) or not 0 <= idx < len(self.items):
            return None, None
        return idx, self.items[idx]

    def count(self, value):
        return sum(1 for x in self.items if x.get(self.field) == value)

    def release(self, value):
        """Aufraeumen nach dem Prozessende: nicht fertig gewordene Eintraege bekommen value."""
        for item in self.items:
            if item.get(self.field) in ('queued', 'running'):
                item[self.field] = value


class State:
    """Gesamter Zustand der Oberflaeche; alle Zugriffe unter self.lock.

    Methoden mit _locked im Namen sowie start_worker, start_sizes, handle_event und handle_size_event
    setzen voraus, dass der Aufrufer self.lock haelt.
    """

    def __init__(self, config, config_path):
        self.lock = threading.RLock()
        self.config, self.config_path = config, config_path
        # Frisches Mullvad-Profil: Die erste geladene Seite bekommt manchmal kein JavaScript (Erweiterungen
        # werden gerade eingerichtet). Bis die Seite sich einmal gemeldet hat, laedt sie sich deshalb neu.
        self.reload_until_alive = False
        self.page_alive = False
        self.storage = Path(os.path.abspath(Path(config['storage']).expanduser()))
        self.checks_file = self.storage / g.Store.STATE_DIR / 'ui-checks.json'
        self.checks = {k: None for k in CHECK_KEYS}
        self.last_check = None
        self.load_checks()
        self.queue = []
        self.current = None
        self.mode = 'idle'         # idle | check | preview | download
        self.stop_requested = False
        self.banner = None         # {'level', 'text'}
        self.log = collections.deque(maxlen=300)
        self.tree = None
        self.last_seen = time.monotonic()
        self.worker = None
        self.preview_batch = None  # BatchJob der laufenden Titelsuche
        self.start_after_preview = False
        # Seiten, die nur per Weiterleitung aufloesbar waren: NUR im Arbeitsspeicher, nie gespeichert,
        # weg beim Beenden der Oberflaeche. Beschleunigt nur die Reihenfolge der Versuche.
        self.redirect_hosts = set()
        # "Gesamtlaufzeit berechnen": ab dann bekommen wartende Links ihre Dateigroesse (nur im Speicher).
        self.sizes_enabled = False
        self.size_batch = None     # BatchJob der laufenden Groessenabfrage
        self.size_worker = None    # laeuft parallel zum Hauptvorgang (eigener Prozess)
        self.size_tree = None
        self.size_stop = False
        self.size_job = None       # {'done', 'total'} fuer die Anzeige

    def pending_titles(self):
        return [x for x in self.queue if x['status'] == 'waiting' and x.get('title_state') == 'pending']

    def pending_sizes(self):
        if not self.sizes_enabled:
            return []
        return [x for x in self.queue if x['status'] == 'waiting' and x.get('title_state') == 'ok'
                and x.get('size_state') in (None, 'queued')]

    # ---- Planer: einziger Ort, der Titelsuche, Download und Groessen anstoesst
    def schedule_locked(self, *, download=False, titles=False, sizes=False):
        """download: Download starten; sonst titles: Titelsuche, falls Eintraege ohne Titel warten;
        sizes: Groessenabfrage, falls angefordert und noetig (laeuft parallel). Jeder Start ist ein No-op,
        wenn der jeweilige Vorgang schon laeuft."""
        if download:
            self.start_worker('download')
        elif titles and self.pending_titles():
            self.start_worker('preview')
        if sizes:
            self.start_sizes()

    def start_sizes(self):
        """Groessenabfrage starten, falls angefordert, noetig und nicht schon laufend."""
        if self.size_worker is not None or not self.pending_sizes():
            return False
        self.size_stop = False
        self.size_worker = SizeWorker(self)
        self.size_worker.start()
        return True

    def start_worker(self, mode):
        """Startet einen Vorgang, falls keiner laeuft."""
        if self.worker is not None:
            return False
        self.mode, self.stop_requested = mode, False
        if mode != 'preview':
            self.banner = None
        self.worker = Worker(self, mode)
        self.worker.start()
        return True

    def halt_locked(self, *, sizes=True):
        """Stopp: Hauptvorgang (und mit sizes auch die Groessenabfrage) anhalten und ihre Prozessbaeume beenden."""
        if self.worker is not None:
            self.stop_requested = True
        if self.tree is not None:
            self.tree.kill()
        if sizes:
            if self.size_worker is not None:
                self.size_stop = True
            if self.size_tree is not None:
                self.size_tree.kill()

    def record_run_locked(self, code):
        """Nach einem grab.py-Lauf: Exitcode 0 = vollstaendige Pruefung bestanden; Ampeln speichern."""
        if code == 0:
            self.last_check = now()
        self.save_checks()

    def current_error_locked(self):
        return (self.current or {}).get('error') or {}

    def banner_level_locked(self):
        return (self.banner or {}).get('level')

    # ---- Pruefergebnisse
    def load_checks(self):
        try:
            data = json.loads(self.checks_file.read_text(encoding='utf-8'))
            for k in CHECK_KEYS:
                v = data.get('checks', {}).get(k)
                if isinstance(v, dict):
                    self.checks[k] = {'ok': v.get('ok'), 'detail': str(v.get('detail', ''))[:300],
                                      'time': float(v.get('time', 0)), 'stale': True}
            self.last_check = data.get('last_check')
        except (OSError, ValueError, TypeError, AttributeError):
            pass

    def save_checks(self):
        try:
            g.secure_directory(self.checks_file.parent)   # gleiche Pruefung wie grab.py (keine Verknuepfungen)
            if sc.is_reparse_or_link(self.checks_file):
                return
            tmp = self.checks_file.with_suffix('.tmp')
            tmp.write_text(json.dumps({'checks': self.checks, 'last_check': self.last_check}, ensure_ascii=False), encoding='utf-8')
            os.replace(tmp, self.checks_file)
        except (OSError, g.Failure):
            pass

    def set_check(self, key, ok, detail):
        if key in self.checks:
            self.checks[key] = {'ok': ok, 'detail': g.safe_text(detail or '')[:300], 'time': now(), 'stale': False}

    @staticmethod
    def preview_eta(cur, total):
        """Restzeit der Titelsuche. Der erste Link einer Seite ist oft deutlich langsamer (Weg wird erst
        gefunden), deshalb erst ab dem zweiten fertigen Link und nur aus den Links nach dem ersten."""
        marks = cur.setdefault('preview_marks', [])
        marks.append(now())
        remaining = total - len(marks)
        if remaining <= 0:
            cur.update(eta_seconds=0, eta_at=marks[-1])   # nur noch die Abschlusspruefung
        elif len(marks) >= 2:
            per = (marks[-1] - marks[0]) / (len(marks) - 1)
            cur.update(eta_seconds=round(per * remaining), eta_at=marks[-1])
        else:
            cur.update(eta_seconds=None, eta_at=None)

    # ---- Ereignisse aus grab.py (Hauptvorgang)
    def _ev_check(self, ev):
        self.set_check(ev.get('key'), ev.get('ok'), ev.get('detail'))
        if self.current is not None and ev.get('key') in CHECK_KEYS:
            self.current['check_step'] = ev.get('key')

    def _ev_phase(self, ev):
        cur = self.current
        if cur is None:
            return
        cur['phase'] = ev.get('phase')
        if ev.get('phase') in RESET_PROGRESS_PHASES:
            cur.update(percent=None, speed=None, eta=None, total=None)
        if ev.get('phase') == common.PHASE_DOWNLOAD:
            cur['download_started'] = now()

    def _ev_progress(self, ev):
        if self.current is not None and ev.get('phase') == common.PHASE_DOWNLOAD:
            self.current.update(percent=ev.get('percent'), speed=ev.get('speed'), eta=ev.get('eta'), total=ev.get('total'))

    def _ev_title(self, ev):
        if self.current is not None:
            self.current['title'] = ev.get('name')

    def _ev_done(self, ev):
        if self.current is not None:
            self.current['file'] = ev.get('file')
            self.current['size'] = ev.get('size')

    def _ev_redirect_host(self, ev):
        host = ev.get('host')
        if isinstance(host, str) and g.HOST_RE.fullmatch(host) and len(self.redirect_hosts) < 100:
            self.redirect_hosts.add(host)

    def _ev_preview_start(self, ev):
        job = self.preview_batch
        idx, item = job.at(ev) if job is not None else (None, None)
        if item is None:
            return
        item['title_state'] = 'running'
        cur = self.current
        if cur is not None:
            cur.setdefault('preview_started', now())
            cur['title'] = f'Titel {idx + 1} von {len(job)} wird gesucht'
            cur['percent'] = idx / len(job) * 100

    def _ev_preview(self, ev):
        job = self.preview_batch
        idx, item = job.at(ev) if job is not None else (None, None)
        if item is None:
            return
        if ev.get('ok'):
            item.update(title=ev.get('name'), title_state='ok')
        else:
            item.update(title_state='failed', status='failed', finished=now(), error=make_error(ev))
        cur = self.current
        if cur is not None:
            cur['percent'] = (idx + 1) / len(job) * 100
            self.preview_eta(cur, len(job))

    def _ev_error(self, ev):
        ident = str(ev.get('ident', ''))
        key = ev.get('check')   # betroffene Ampel, von grab.py mitgeschickt
        # Eine frische rote Ampel behaelt ihren ersten Befund.
        if key in self.checks and (self.checks.get(key) is None or self.checks[key].get('ok') is not False or self.checks[key].get('stale')):
            self.set_check(key, False, ev.get('message', ident))
        if self.current is not None:
            self.current['error'] = make_error(ev)

    _MAIN_EVENTS = {'check': _ev_check, 'phase': _ev_phase, 'progress': _ev_progress, 'title': _ev_title,
                    'done': _ev_done, 'redirect_host': _ev_redirect_host, 'preview_start': _ev_preview_start,
                    'preview': _ev_preview, 'error': _ev_error}

    def handle_event(self, ev):
        """Ereignis des Hauptvorgangs; IGNORED_EVENTS und unbekannte Arten bleiben ohne Wirkung."""
        fn = self._MAIN_EVENTS.get(ev.get('type'))
        if fn is not None:
            fn(self, ev)

    # ---- Ereignisse der Groessenabfrage: nur Pruefampeln, Groessen und Fehlertext - nie die Download-Anzeige
    def _size_ev_error(self, ev):
        if self.size_batch is not None:
            self.size_batch.error = make_error(ev)
        key = ev.get('check')
        if key in self.checks:
            self.set_check(key, False, ev.get('message', ''))

    def _size_ev_size_start(self, ev):
        item = self.size_batch.at(ev)[1] if self.size_batch is not None else None
        if item is not None:
            item['size_state'] = 'running'

    def _size_ev_size(self, ev):
        idx, item = self.size_batch.at(ev) if self.size_batch is not None else (None, None)
        if item is None:
            return
        size = ev.get('bytes')
        ok = isinstance(size, int) and not isinstance(size, bool) and 0 < size < 2 ** 50
        item.update(expected_size=size if ok else None, size_state='ok' if ok else 'unknown')
        if self.size_job is not None:
            self.size_job['done'] = idx + 1

    _SIZE_EVENTS = {'check': lambda self, ev: self.set_check(ev.get('key'), ev.get('ok'), ev.get('detail')),
                    'redirect_host': _ev_redirect_host, 'error': _size_ev_error,
                    'size_start': _size_ev_size_start, 'size': _size_ev_size}

    def handle_size_event(self, ev):
        """Ereignis der Groessenabfrage; alles andere (auch phase/progress) bleibt ohne Wirkung."""
        fn = self._SIZE_EVENTS.get(ev.get('type'))
        if fn is not None:
            fn(self, ev)

    def snapshot(self):
        history = []
        try:
            files = [p for p in (self.storage / g.Store.OUTPUT_DIR).iterdir() if p.is_file() and not p.is_symlink()]
            files.sort(key=lambda p: p.stat().st_mtime, reverse=True)
            for p in files[:30]:
                st = p.stat()
                history.append({'name': p.name, 'size': st.st_size, 'time': st.st_mtime})
        except OSError:
            pass
        ok_values = [c['ok'] for c in self.checks.values() if c]
        fresh = all(c and not c.get('stale') for c in self.checks.values())
        all_ok = len(ok_values) == len(CHECK_KEYS) and all(v is True for v in ok_values)
        overall = ('bad' if any(v is False for v in ok_values) else
                   'good' if all_ok and fresh else
                   'stale' if all_ok else
                   'unknown')
        current = None
        if self.current:   # preview_marks braucht nur der Server (Restzeit)
            current = {k: v for k, v in self.current.items() if k != 'preview_marks'}
        return {'checks': self.checks, 'overall': overall, 'last_check': self.last_check,
                'queue': [dict(item, display=display_name(item)) for item in self.queue], 'current': current,
                'mode': self.mode, 'banner': self.banner, 'start_pending': self.start_after_preview,
                'sizes_enabled': self.sizes_enabled, 'size_job': dict(self.size_job) if self.size_job else None, 'log': list(self.log)[-120:], 'history': history,
                'storage_finished': str(self.storage / g.Store.OUTPUT_DIR), 'browser': self.config.get('ui_browser', g.BROWSER_AUTO),
                'meta': UI_META,
                # Mullvad meldet Seiten absichtlich UTC (Fingerprint-Schutz): Ortszeit-Versatz kommt vom Server.
                'tz_offset': time.localtime().tm_gmtoff, 'server_time': now()}


def run_grab(s, extra, on_event, set_tree, stdin_text=None):
    """Startet grab.py --events und wartet auf das Ende. Rueckgabe: Exitcode.

    Ereignisse gehen (unter s.lock) an on_event, der Prozessbaum (fuer Stopp) an set_tree, am Ende set_tree(None).
    """
    argv = [sys.executable, '-I', str(APP / 'grab.py'), '--events', '--config', str(s.config_path)] + extra
    env = {k: v for k, v in os.environ.items()
           if not k.upper().startswith(('PYTHON', 'YTDLP')) and k.upper() not in
           ('HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY', 'NO_PROXY', 'SSLKEYLOGFILE', g.REDIRECT_HOSTS_ENV)}
    with s.lock:
        if s.redirect_hosts:
            # Umgebungsvariable statt Kommandozeile: taucht nicht in Prozesslisten/Protokollen auf.
            env[g.REDIRECT_HOSTS_ENV] = ','.join(sorted(s.redirect_hosts))
    proc = subprocess.Popen(argv, stdin=subprocess.PIPE if stdin_text is not None else subprocess.DEVNULL,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            cwd=str(APP), env=env, **sc.popen_kwargs())
    tree = sc.ProcessTree(proc)
    with s.lock:
        set_tree(tree)
    if stdin_text is not None:
        # Links ueber die Standardeingabe: tauchen nicht in der Prozessliste auf.
        try:
            proc.stdin.write(stdin_text.encode('utf-8'))
        except OSError:
            pass
        finally:
            proc.stdin.close()
    try:
        for raw in iter(proc.stdout.readline, b''):
            line = raw.decode('utf-8', errors='replace').rstrip('\r\n')
            with s.lock:
                if line.startswith(g.EVENT_PREFIX):
                    try:
                        ev = json.loads(line[len(g.EVENT_PREFIX):])
                        if isinstance(ev, dict):
                            on_event(ev)
                    except ValueError:
                        pass
                elif line.strip() and not line.startswith('[download] ') or line.startswith('[download] Destination'):
                    s.log.append({'time': now(), 'text': g.safe_text(line)[:400]})
        return proc.wait()
    finally:
        with s.lock:
            set_tree(None)
        tree.close()
        proc.stdout.close()


class Worker(threading.Thread):
    """Fuehrt grab.py fuer einen Auftrag oder die Warteschlange aus (immer nur einer zugleich)."""

    def __init__(self, state, mode):
        super().__init__(daemon=True)
        self.s, self.mode = state, mode

    def _set_tree(self, tree):
        self.s.tree = tree

    def grab(self, extra, stdin_text=None):
        return run_grab(self.s, extra, self.s.handle_event, self._set_tree, stdin_text)

    def find_titles(self):
        """Titelsuche fuer alle wartenden Eintraege ohne Titel. Rueckgabe: Exitcode (0 = nichts zu tun/ok)."""
        s = self.s
        with s.lock:
            pending = s.pending_titles()
            if not pending:
                return 0
            job = s.preview_batch = BatchJob(pending, 'title_state')
            s.current = {'id': 'preview', 'phase': common.PHASE_PREVIEW, 'title': f'Titel werden gesucht (0 von {len(job)})',
                         'percent': 0, 'started': now()}
            urls = job.stdin_text()
        code = self.grab(['--preview'], stdin_text=urls)
        with s.lock:
            job.release('pending')
            s.preview_batch = None
            found, bad = job.count('ok'), job.count('failed')
            if code == 0:
                text = f'Titel gefunden: {found} von {len(job)}.' + (f' {bad} Link(s) nicht aufloesbar.' if bad else '')
                s.banner = banner('warn' if bad else 'good', text)
            elif s.stop_requested:
                s.banner = banner('warn', 'Titelsuche angehalten.')
            else:
                prefix = 'Sicherheitsabbruch: ' if code == 2 else 'Titelsuche fehlgeschlagen: '
                s.banner = banner('bad', prefix + (s.current_error_locked().get('message') or f'Exitcode {code}'))
            s.record_run_locked(code)
            if code == 0:
                s.schedule_locked(sizes=True)   # Titel da: angeforderte Groessen sofort, parallel zu allem Weiteren
        return code

    def check(self):
        s = self.s
        with s.lock:
            s.current = {'id': 'check', 'phase': common.PHASE_CHECKS, 'title': 'Sicherheitspruefung', 'started': now()}
        code = self.grab(['--check-only'])
        with s.lock:
            if code == 0:
                s.banner = banner('good', 'Alle Sicherheitspruefungen bestanden.')
            elif not s.stop_requested:
                s.banner = banner('bad', s.current_error_locked().get('message') or f'Pruefung fehlgeschlagen (Exitcode {code}).')
            s.record_run_locked(code)

    def download_queue(self):
        s = self.s
        while True:
            with s.lock:
                if s.stop_requested:
                    break
                item = next((x for x in s.queue if x['status'] == 'waiting'), None)
                if item is None:
                    break
                item.update(status='running', started=now(), error=None)
                name = display_name(item)   # Dateiname = eigener Name oder gefundener Titel
                s.current = {'id': item['id'], 'phase': common.PHASE_CHECKS, 'title': name,
                             'percent': None, 'speed': None, 'eta': None, 'total': None, 'started': now()}
                url = item['url']
            code = self.grab([url] + ([name] if name else []))
            with s.lock:
                cur = s.current or {}
                item['finished'] = now()
                item['title'] = cur.get('title') or item.get('title')
                if code == 0:
                    item.update(status='done', file=cur.get('file'), size=cur.get('size'))
                elif s.stop_requested:
                    item['status'] = 'stopped'
                else:
                    item['status'] = 'failed'
                    item['error'] = cur.get('error') or {'ident': 'EXIT', 'code': code, 'message': f'Exitcode {code}'}
                s.record_run_locked(code)
                if code == 2:
                    s.banner = security_banner(item['error']['message'])
                    break
        with s.lock:
            if s.stop_requested and s.banner_level_locked() != 'bad':   # Sicherheitsabbruch bleibt sichtbar
                s.banner = banner('warn', 'Angehalten.')
            elif s.banner_level_locked() != 'bad':
                done = sum(1 for x in s.queue if x['status'] == 'done')
                s.banner = banner('good', f'Warteschlange abgearbeitet ({done} fertig).')

    def run(self):
        s = self.s
        try:
            if self.mode == 'preview':
                self.find_titles()
            elif self.mode == 'check':
                self.check()
            elif self.mode == 'download':
                # Erst alle Titel, dann laden - wie die Vorschau der Kommandozeile.
                if self.find_titles() == 0:
                    with s.lock:
                        s.banner = None   # Titel-Meldung der Vorstufe gilt nicht fuer den Download
                        s.schedule_locked(sizes=True)   # angeforderte Groessen laufen parallel zum Download
                    self.download_queue()
        except Exception as exc:  # nie still scheitern
            with s.lock:
                s.banner = internal_error_banner('Oberflaeche', exc)
        finally:
            with s.lock:
                halted = s.stop_requested or s.banner_level_locked() == 'bad'
                s.current = None
                s.mode = 'idle'
                s.stop_requested = False
                s.worker = None
                s.preview_batch = None
                start_next = s.start_after_preview and self.mode == 'preview'
                s.start_after_preview = False
                if not halted:
                    # "Start" waehrend der Titelsuche: jetzt laden. Sonst bekommen waehrend eines Downloads
                    # hinzugefuegte Links danach ihre Titel.
                    s.schedule_locked(download=start_next and any(x['status'] == 'waiting' for x in s.queue),
                                      titles=True, sizes=True)


class SizeWorker(threading.Thread):
    """Dateigroessen der wartenden Eintraege - eigener grab.py-Prozess, laeuft parallel zum Hauptvorgang.
    Eigene Ereignisverarbeitung (beruehrt die Download-Anzeige nicht), eigener Prozessbaum (Stopp)."""

    def __init__(self, state):
        super().__init__(daemon=True)
        self.s = state

    def _set_tree(self, tree):
        self.s.size_tree = tree

    def run(self):
        s = self.s
        try:
            while True:
                with s.lock:
                    pending = s.pending_sizes()
                    if not pending or s.size_stop:
                        break
                    job = s.size_batch = BatchJob(pending, 'size_state')
                    s.size_job = {'done': 0, 'total': len(job)}
                    urls = job.stdin_text()
                code = run_grab(s, ['--sizes'], s.handle_size_event, self._set_tree, stdin_text=urls)
                with s.lock:
                    job.release(None if s.size_stop else 'unknown')   # angehalten: spaeter erneut; Fehler: nicht endlos wiederholen
                    s.size_batch = None
                    if code == 2 and not s.size_stop:
                        # Sicherheitsabbruch in der Groessenabfrage gilt fuer alles: auch den Download anhalten.
                        s.banner = security_banner((job.error or {}).get('message') or f'Exitcode {code}', ' (Groessenabfrage)')
                        s.halt_locked(sizes=False)
                    s.save_checks()
                    if code != 0:
                        break
        except Exception as exc:  # nie still scheitern
            with s.lock:
                s.banner = internal_error_banner('Groessenabfrage', exc)
        finally:
            with s.lock:
                s.size_worker = None
                s.size_batch = None
                s.size_job = None
                s.size_stop = False


def make_handler(state, token, debug=False):
    class Handler(http.server.BaseHTTPRequestHandler):
        server_version = 'Quite Safe Grab'
        sys_version = ''

        def log_message(self, *args):   # keine Zugriffsprotokolle (Links stehen in Anfragen)
            pass

        def log_request(self, code='-', size='-'):
            if debug:   # nur Methode, Pfad ohne Query/Fragment und Status - nie Inhalte oder Schluessel
                path = urllib.parse.urlsplit(self.path).path
                print(f'[debug] {time.strftime("%H:%M:%S")} {self.command} {path} -> {code} '
                      f'(Token {"ja" if self.headers.get("X-QSGrab-Token") else "nein"}, '
                      f'Origin {self.headers.get("Origin") or "-"}, Host {self.headers.get("Host")})', flush=True)

        def origin_ok(self):
            expected = f'127.0.0.1:{self.server.server_address[1]}'
            if self.headers.get('Host') != expected:
                return False
            origin = self.headers.get('Origin')
            return origin in (None, f'http://{expected}')

        def send(self, code, body, ctype='application/json; charset=utf-8', refresh=False):
            data = body if isinstance(body, bytes) else json.dumps(body, ensure_ascii=False).encode('utf-8')
            self.send_response(code)
            if refresh:
                self.send_header('Refresh', '4')
            self.send_header('Content-Type', ctype)
            self.send_header('Content-Length', str(len(data)))
            self.send_header('Cache-Control', 'no-store')
            self.send_header('Content-Security-Policy', CSP)
            self.send_header('X-Content-Type-Options', 'nosniff')
            # same-origin statt no-referrer: Firefox/Mullvad schicken bei no-referrer fuer POST nur "Origin: null",
            # und die Origin-Pruefung wuerde jeden Knopfdruck ablehnen. Nach aussen geht weiterhin nichts.
            self.send_header('Referrer-Policy', 'same-origin')
            self.send_header('X-Frame-Options', 'DENY')
            self.send_header('Cross-Origin-Resource-Policy', 'same-origin')
            self.end_headers()
            self.wfile.write(data)

        def authorized(self):
            got = self.headers.get('X-QSGrab-Token', '')
            ok = hmac.compare_digest(got.encode('utf-8', 'replace'), token.encode('ascii'))
            if ok:
                with state.lock:
                    state.page_alive = True
            return ok

        def do_GET(self):
            if not self.origin_ok():
                return self.send(403, {'error': 'forbidden'})
            path = urllib.parse.urlsplit(self.path).path
            if path in STATIC:
                name, ctype = STATIC[path]
                with state.lock:
                    refresh = path == '/' and state.reload_until_alive and not state.page_alive
                try:
                    return self.send(200, (APP / 'ui' / name).read_bytes(), ctype, refresh=refresh)
                except OSError:
                    return self.send(404, {'error': 'missing'})
            if path == '/api/state':
                if not self.authorized():
                    return self.send(401, {'error': 'token'})
                with state.lock:
                    state.last_seen = time.monotonic()
                    return self.send(200, state.snapshot())
            return self.send(404, {'error': 'not found'})

        def do_POST(self):
            if not self.origin_ok() or not self.authorized():
                return self.send(403, {'error': 'forbidden'})
            if self.headers.get('Content-Type', '').split(';')[0].strip() != 'application/json':
                return self.send(415, {'error': 'json only'})
            try:
                length = int(self.headers.get('Content-Length', '0'))
            except ValueError:
                return self.send(400, {'error': 'length'})
            if not 0 <= length <= MAX_BODY:
                return self.send(413, {'error': 'too large'})
            try:
                body = json.loads(self.rfile.read(length) or b'{}')
                if not isinstance(body, dict):
                    raise ValueError
            except ValueError:
                return self.send(400, {'error': 'invalid json'})
            path = urllib.parse.urlsplit(self.path).path
            with state.lock:
                state.last_seen = time.monotonic()
                try:
                    result = self.route(path, body)
                except ValueError as exc:
                    return self.send(400, {'error': str(exc)})
            if result is None:
                return self.send(404, {'error': 'not found'})
            return self.send(200, result)

        def route(self, path, body):
            """Eine API-Route (unter state.lock). Vorgaenge startet nur state.schedule_locked bzw. start_worker('check')."""
            s = state
            if path == '/api/queue/add':
                urls = body.get('urls')
                if not isinstance(urls, list) or not urls or len(urls) > 50:
                    raise ValueError('Bitte 1 bis 50 Links angeben.')
                name = clean_name(body.get('name') if isinstance(body.get('name'), str) else '')
                if name and len(urls) > 1:
                    raise ValueError('Ein eigener Dateiname geht nur bei einem einzelnen Link.')
                if len(s.queue) + len(urls) > MAX_QUEUE:
                    raise ValueError('Warteschlange ist voll.')
                bad, added = [], 0
                for u in urls:
                    u = g.complete_url(u) if isinstance(u, str) else ''
                    if not u:
                        continue
                    try:
                        g.valid_url(u)
                        if len(u) > 4000:
                            raise ValueError
                    except ValueError:
                        bad.append(u[:80])
                        continue
                    s.queue.append({'id': uuid.uuid4().hex[:12], 'url': u, 'name': name or None, 'status': 'waiting',
                                    'added': now(), 'error': None, 'title': None, 'title_state': 'pending'})
                    added += 1
                if added:
                    s.schedule_locked(titles=True)   # Titel sofort suchen (laeuft gerade etwas, danach)
                return {'added': added, 'invalid': bad}
            if path == '/api/queue/remove':
                ident = body.get('id')
                s.queue[:] = [x for x in s.queue if not (x['id'] == ident and x['status'] != 'running')]
                return {'ok': True}
            if path == '/api/queue/move':
                ident, before = body.get('id'), body.get('before')
                item = next((x for x in s.queue if x['id'] == ident), None)
                if item is None or item['status'] == 'running':
                    raise ValueError('Dieser Eintrag kann nicht verschoben werden.')
                if before is not None and (before == ident or not any(x['id'] == before for x in s.queue)):
                    raise ValueError('Ungueltige Zielposition.')
                s.queue.remove(item)
                pos = len(s.queue) if before is None else next(i for i, x in enumerate(s.queue) if x['id'] == before)
                s.queue.insert(pos, item)
                return {'ok': True}
            if path == '/api/queue/retry':
                for x in s.queue:
                    if x['id'] == body.get('id') and x['status'] in ('failed', 'stopped'):
                        x.update(status='waiting', error=None)
                        if x.get('title_state') != 'ok':
                            x['title_state'] = 'pending'
                s.schedule_locked(titles=True)
                return {'ok': True}
            if path == '/api/start':
                if not any(x['status'] == 'waiting' for x in s.queue):
                    raise ValueError('Keine wartenden Links in der Warteschlange.')
                if s.worker is not None:
                    if s.mode == 'preview':
                        s.start_after_preview = True   # direkt nach der Titelsuche loslegen
                        return {'ok': True, 'deferred': True}
                    raise ValueError('Es laeuft bereits ein Vorgang.')
                s.schedule_locked(download=True)
                return {'ok': True}
            if path == '/api/sizes':
                # Ab jetzt Groessen fuer alle wartenden Links mit Titel - sofort und parallel zum Download.
                # Links ohne Titel folgen direkt nach ihrer Titelsuche.
                s.sizes_enabled = True
                s.schedule_locked(titles=True, sizes=True)
                return {'ok': True}
            if path == '/api/check':
                if not s.start_worker('check'):
                    raise ValueError('Es laeuft bereits ein Vorgang.')
                return {'ok': True}
            if path == '/api/stop':
                s.halt_locked()
                return {'ok': True}
            if path == '/api/open-folder':
                folder = s.storage / g.Store.OUTPUT_DIR
                if folder.is_dir() and not sc.is_reparse_or_link(folder):
                    os.startfile(str(folder))   # fester Pfad aus der Konfiguration, keine Eingabe
                return {'ok': True}
            if path == '/api/dismiss':
                s.banner = None
                return {'ok': True}
            return None

    return Handler


# ---- Browser
def _app_path(exe):
    try:
        import winreg
    except ImportError:
        return None
    for hive in (winreg.HKEY_CURRENT_USER, winreg.HKEY_LOCAL_MACHINE):
        try:
            with winreg.OpenKey(hive, rf'Software\Microsoft\Windows\CurrentVersion\App Paths\{exe}') as key:
                value = winreg.QueryValue(key, None)
                if value and Path(value.strip('"')).is_file():
                    return value.strip('"')
        except OSError:
            continue
    return None


def find_mullvad():
    # Gleiche Orte (die ersten beiden) prueft setup.ps1 nur fuer seinen Hinweistext; massgeblich ist diese Suche.
    env = os.environ
    for p in (Path(env.get('LOCALAPPDATA', '')) / 'Mullvad' / 'MullvadBrowser' / 'Release' / 'mullvadbrowser.exe',
              Path(env.get('ProgramFiles', r'C:\Program Files')) / 'Mullvad Browser' / 'Browser' / 'mullvadbrowser.exe',
              Path(env.get('LOCALAPPDATA', '')) / 'Mullvad Browser' / 'Browser' / 'mullvadbrowser.exe'):
        if p.is_file():
            return str(p)
    return _app_path('mullvadbrowser.exe')


def find_edge():
    env = os.environ
    for p in (Path(env.get('ProgramFiles(x86)', r'C:\Program Files (x86)')) / 'Microsoft' / 'Edge' / 'Application' / 'msedge.exe',
              Path(env.get('ProgramFiles', r'C:\Program Files')) / 'Microsoft' / 'Edge' / 'Application' / 'msedge.exe'):
        if p.is_file():
            return str(p)
    return _app_path('msedge.exe')


@dataclasses.dataclass(frozen=True)
class Launch:
    """Browserstart: Art (g.BROWSER_MULLVAD / g.BROWSER_EDGE), Anzeigename, Kommandozeile, Profilordner."""
    kind: str
    name: str
    argv: list
    profile: Path


class NoBrowser(Exception):
    """Kein passender Browser; die Meldung ist der Hinweis fuer den Nutzer."""


def browser_command(choice, url, profile_root, finders=(find_mullvad, find_edge)):
    """Launch fuer den Browserstart; NoBrowser mit Hinweis, wenn nicht moeglich."""
    find_mb, find_ed = finders
    if choice in (g.BROWSER_AUTO, g.BROWSER_MULLVAD):
        exe = find_mb()
        if exe:
            profile = profile_root / 'mullvad'
            return Launch(g.BROWSER_MULLVAD, 'Mullvad Browser',
                          [exe, '-no-remote', '-profile', str(profile), '-new-window', url], profile)
        if choice == g.BROWSER_MULLVAD:
            raise NoBrowser('Mullvad Browser nicht gefunden (ui_browser = "mullvad"). Installieren von '
                            'https://mullvad.net/browser oder in config.toml ui_browser = "auto" setzen.')
    exe = find_ed()
    if exe:
        profile = profile_root / 'edge'
        return Launch(g.BROWSER_EDGE, 'Microsoft Edge (eigenes Profil)',
                      [exe, f'--user-data-dir={profile}', f'--app={url}', '--no-first-run',
                       '--no-default-browser-check', '--disable-sync', '--disable-extensions',
                       '--disable-background-networking', '--disable-features=Translate,AutofillServerCommunication'],
                      profile)
    raise NoBrowser('Weder Mullvad Browser noch Microsoft Edge gefunden.')


def reset_profile(path):
    if path.exists() and not sc.is_reparse_or_link(path):
        shutil.rmtree(path, ignore_errors=True)


# Sperrdatei, die der Browser exklusiv offen haelt, solange er mit diesem Profil laeuft.
PROFILE_LOCK = {g.BROWSER_MULLVAD: 'parent.lock', g.BROWSER_EDGE: 'lockfile'}


def profile_in_use(kind, profile):
    """True, solange ein Browser dieses Profil offen hat (Sperrdatei nicht oeffenbar)."""
    lock = profile / PROFILE_LOCK.get(kind, '')
    if not lock.is_file():
        return False
    try:
        fd = os.open(lock, os.O_RDWR)
    except OSError:
        return True
    os.close(fd)
    return False


def mullvad_profile_ready(profile):
    """Profil ist eingerichtet: prefs.js vorhanden und keine Erweiterung mehr in Warteposition."""
    return (profile / 'prefs.js').is_file() and not any((profile / 'extensions' / 'staged').glob('*'))


def prepare_mullvad_profile(exe, profile):
    """Einmalige, unsichtbare Einrichtung eines neuen Mullvad-Profils.

    Beim allerersten Start installiert der Mullvad Browser seine Erweiterungen (NoScript, uBlock)
    und startet sich neu; in diesem Moment geladene Seiten bekommen kein JavaScript. Deshalb
    wird ein neues Profil vorher ohne Fenster (headless) initialisiert.
    """
    if mullvad_profile_ready(profile):
        return True
    profile.mkdir(parents=True, exist_ok=True)
    shot = profile / 'qsgrab-init.png'
    for _ in range(2):   # zweiter Lauf, falls Erweiterungen erst beim Neustart fertig werden
        try:
            subprocess.run([exe, '-headless', '-no-remote', '-profile', str(profile), '-screenshot', str(shot), 'about:blank'],
                           stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=120)
        except (OSError, subprocess.SubprocessError):
            return False
        finally:
            shot.unlink(missing_ok=True)
        if mullvad_profile_ready(profile):
            return True
    return (profile / 'prefs.js').is_file()


def main(argv=None):
    parser = argparse.ArgumentParser(description='QuiteSafeGrab-Oberflaeche (lokal, nur 127.0.0.1).')
    parser.add_argument('--config', default=str(APP / 'config.toml'))
    parser.add_argument('--no-browser', action='store_true', help='Keinen Browser starten, nur Adresse anzeigen (Entwicklung).')
    parser.add_argument('--debug', action='store_true', help='Anfragen (nur Methode/Pfad/Status) und Browserprozess anzeigen.')
    parser.add_argument('--no-check', action='store_true', help='Beim Start keine automatische Sicherheitspruefung.')
    args = parser.parse_args(argv)
    debug = args.debug
    try:
        config = g.load_config(args.config)
    except g.Failure as exc:
        g.error(exc)
        return exc.code
    state = State(config, Path(args.config))
    token = secrets.token_urlsafe(32)
    server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), make_handler(state, token, debug))
    server.daemon_threads = True
    url = f'http://127.0.0.1:{server.server_address[1]}/#t={token}'
    profile_root = APP / '.ui-profile'
    kind = profile = None
    print('QuiteSafeGrab-Oberflaeche laeuft lokal (nur dieser PC). Dieses Fenster offen lassen; schliessen beendet Quite Safe Grab.')
    if args.no_browser:
        print('Adresse: ' + url)
    else:
        try:
            launch = browser_command(config.get('ui_browser', g.BROWSER_AUTO), url, profile_root)
        except NoBrowser as exc:
            print(f'FEHLER: {exc}', file=sys.stderr)
            server.server_close()
            return 1
        kind, profile = launch.kind, launch.profile
        if profile_in_use(kind, profile):
            print('FEHLER: Ein QuiteSafeGrab-Browserfenster ist noch offen. Bitte schliessen und erneut starten.', file=sys.stderr)
            server.server_close()
            return 1
        profile_root.mkdir(exist_ok=True)
        if kind == g.BROWSER_EDGE:
            reset_profile(profile)   # Edge speichert Verlauf: immer frisch
        elif kind == g.BROWSER_MULLVAD:
            # Mullvad surft immer privat (kein Verlauf); das Profil bleibt, damit Erweiterungen eingerichtet sind.
            # Leerzeile, falls nichts vorzubereiten ist (Ausgabe wie bisher).
            print('Bereite Mullvad Browser vor ...' if not (profile / 'prefs.js').is_file() else '', flush=True)
            with state.lock:
                state.reload_until_alive = not mullvad_profile_ready(profile)
            if not prepare_mullvad_profile(launch.argv[0], profile):
                print('FEHLER: Mullvad-Browserprofil liess sich nicht einrichten.', file=sys.stderr)
                server.server_close()
                return 1
        try:
            subprocess.Popen(launch.argv, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, close_fds=True)
        except OSError:
            print('FEHLER: Browser liess sich nicht starten.', file=sys.stderr)
            server.server_close()
            return 1
        print(f'Geoeffnet in: {launch.name}')
        if kind == g.BROWSER_EDGE and config.get('ui_browser') == g.BROWSER_AUTO:
            print('Tipp: Mit installiertem Mullvad Browser (https://mullvad.net/browser) oeffnet Quite Safe Grab diesen - ohne Telemetrie, immer privat.')
    launched = time.monotonic()
    if not args.no_check:
        with state.lock:
            state.start_worker('check')

    def watchdog():
        gone_since = None
        seen_open = False
        while True:
            time.sleep(WATCHDOG_INTERVAL_SEC)
            if profile is not None:
                if profile_in_use(kind, profile):
                    seen_open, gone_since = True, None
                elif seen_open or time.monotonic() - launched > BROWSER_START_GRACE_SEC:
                    if gone_since is None and debug:
                        print('[debug] Browserprofil nicht mehr in Benutzung.', flush=True)
                    gone_since = gone_since or time.monotonic()
            with state.lock:
                busy = state.worker is not None or state.size_worker is not None   # auch waehrend der Groessenabfrage
                silent = time.monotonic() - state.last_seen
            if busy:
                continue
            if gone_since is not None and time.monotonic() - gone_since >= BROWSER_GONE_GRACE_SEC and silent >= BROWSER_GONE_GRACE_SEC:
                print('Browserfenster geschlossen - Quite Safe Grab beendet.')
            elif silent > IDLE_EXIT_SEC:
                print('Lange keine Verbindung zur Oberflaeche - Quite Safe Grab beendet.')
            else:
                continue
            server.shutdown()
            return
    threading.Thread(target=watchdog, daemon=True).start()
    try:
        server.serve_forever(poll_interval=0.5)
    except KeyboardInterrupt:
        pass
    finally:
        with state.lock:
            state.halt_locked()
        server.server_close()
        if kind == g.BROWSER_EDGE and not profile_in_use(kind, profile):
            reset_profile(profile)
    return 0


if __name__ == '__main__':
    sys.exit(main())
