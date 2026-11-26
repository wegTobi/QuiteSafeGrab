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
CHECK_KEYS = ('vpn', 'firewall', 'selftest', 'ipv4', 'ipv6', 'dns')
# Fehler-ID -> betroffene Pruefung (fuer Fehler, die ohne eigenes check-Ereignis enden)
ERROR_CHECK = {'GUARD_QUERY_FAILED': 'firewall', 'GUARD_QUERY_INVALID': 'firewall', 'FIREWALL_DISABLED': 'firewall',
               'FIREWALL_RULES_MISSING': 'firewall', 'FIREWALL_BLOCKS_VPN': 'firewall',
               'TUNNEL_STATUS_UNAVAILABLE': 'ipv4', 'EXIT_IP_CHANGED': 'ipv4', 'NETWORK_CHECK_ERROR': 'ipv4',
               'DNS_RESOLVER_FAILED': 'dns', 'DNS_RESOLVER_AMBIGUOUS': 'dns', 'DNS_RESOLVER_INVALID': 'dns',
               'DNS_GEO_FAILED': 'dns'}
DEBUG = False
MAX_BODY = 64 * 1024
MAX_QUEUE = 200
# Beenden: sobald das von Quite Safe Grab gestartete Browserfenster zu ist (und nichts laeuft).
# Ohne erkennbares Browserfenster erst nach langer Funkstille - Browser drosseln Timer in
# minimierten Fenstern stark, eine kurze Frist wuerde Quite Safe Grab faelschlich beenden.
IDLE_EXIT_SEC = 30 * 60
BROWSER_GONE_GRACE_SEC = 10


def now():
    return round(time.time(), 3)


def clean_name(text):
    text = (text or '').strip()
    if not text:
        return ''
    if len(text) > 120 or any(c in text for c in '<>:"/\\|?*') or any(ord(c) < 32 for c in text):
        raise ValueError('Dateiname darf hoechstens 120 Zeichen und keine der Zeichen < > : " / \\ | ? * enthalten.')
    return text


class State:
    """Gesamter Zustand der Oberflaeche; alle Zugriffe unter self.lock."""

    def __init__(self, config, config_path):
        self.lock = threading.RLock()
        self.config, self.config_path = config, config_path
        self.storage = Path(os.path.abspath(Path(config['storage']).expanduser()))
        self.checks_file = self.storage / '.state' / 'ui-checks.json'
        self.checks = {k: None for k in CHECK_KEYS}
        self.last_check = None
        self.load_checks()
        self.queue = []
        self.current = None        # laufender Auftrag (dict) oder None
        self.mode = 'idle'         # idle | download | check
        self.stop_requested = False
        self.banner = None         # {'level', 'text'}
        self.log = collections.deque(maxlen=300)
        self.tree = None
        self.last_seen = time.monotonic()
        self.worker = None
        self.preview_batch = None  # Eintraege der laufenden Titelsuche (Index = Zeile auf stdin)
        self.start_after_preview = False

    def pending_titles(self):
        return [x for x in self.queue if x['status'] == 'waiting' and x.get('title_state') == 'pending']

    def start_worker(self, mode):
        """Startet einen Vorgang, falls keiner laeuft (Aufrufer haelt self.lock)."""
        if self.worker is not None:
            return False
        self.mode, self.stop_requested = mode, False
        if mode != 'preview':
            self.banner = None
        self.worker = Worker(self, mode)
        self.worker.start()
        return True

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

    # ---- Ereignisse aus grab.py
    def handle_event(self, ev):
        kind = ev.get('type')
        cur = self.current
        if kind == 'check':
            self.set_check(ev.get('key'), ev.get('ok'), ev.get('detail'))
        elif kind == 'phase' and cur is not None:
            cur['phase'] = ev.get('phase')
            if ev.get('phase') in ('resolve', 'download', 'remux', 'verify'):
                cur.update(percent=None, speed=None, eta=None, total=None)
            if ev.get('phase') == 'download':
                cur['download_started'] = now()   # fuer die Durchschnittsgeschwindigkeit dieses Videos
        elif kind == 'progress' and cur is not None:
            if ev.get('phase') == 'download':
                cur.update(percent=ev.get('percent'), speed=ev.get('speed'), eta=ev.get('eta'), total=ev.get('total'))
        elif kind == 'title' and cur is not None:
            cur['title'] = ev.get('name')
        elif kind == 'done' and cur is not None:
            cur['file'] = ev.get('file')
            cur['size'] = ev.get('size')
        elif kind == 'checked':
            pass
        elif kind in ('preview_start', 'preview'):
            batch = self.preview_batch or []
            idx = ev.get('index')
            if not isinstance(idx, int) or not 0 <= idx < len(batch):
                return
            item = batch[idx]
            if kind == 'preview_start':
                item['title_state'] = 'running'
                if cur is not None:
                    cur['title'] = f'Titel {idx + 1} von {len(batch)} wird gesucht'
                    cur['percent'] = idx / len(batch) * 100
            elif ev.get('ok'):
                item.update(title=ev.get('name'), title_state='ok')
                if cur is not None:
                    cur['percent'] = (idx + 1) / len(batch) * 100
            else:
                item.update(title_state='failed', status='failed', finished=now(),
                            error={'ident': str(ev.get('ident', '')), 'code': ev.get('code'),
                                   'message': g.safe_text(ev.get('message', ''))[:500]})
        elif kind == 'error':
            ident = str(ev.get('ident', ''))
            key = ERROR_CHECK.get(ident)
            if key and (self.checks.get(key) is None or self.checks[key].get('ok') is not False or self.checks[key].get('stale')):
                self.set_check(key, False, ev.get('message', ident))
            if cur is not None:
                cur['error'] = {'ident': ident, 'code': ev.get('code'), 'message': g.safe_text(ev.get('message', ''))[:500]}

    def snapshot(self):
        history = []
        try:
            files = [p for p in (self.storage / 'finished').iterdir() if p.is_file() and not p.is_symlink()]
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
        return {'checks': self.checks, 'overall': overall, 'last_check': self.last_check,
                'queue': [dict(item) for item in self.queue], 'current': dict(self.current) if self.current else None,
                'mode': self.mode, 'banner': self.banner, 'start_pending': self.start_after_preview, 'log': list(self.log)[-120:], 'history': history,
                'storage_finished': str(self.storage / 'finished'), 'browser': self.config.get('ui_browser', 'auto'),
                # Mullvad meldet Seiten absichtlich UTC (Fingerprint-Schutz): Ortszeit-Versatz kommt vom Server.
                'tz_offset': time.localtime().tm_gmtoff, 'server_time': now()}


class Worker(threading.Thread):
    """Fuehrt grab.py fuer einen Auftrag oder die Warteschlange aus (immer nur einer zugleich)."""

    def __init__(self, state, mode):
        super().__init__(daemon=True)
        self.s, self.mode = state, mode

    def run_grab(self, extra, stdin_text=None):
        s = self.s
        argv = [sys.executable, '-I', str(APP / 'grab.py'), '--events', '--config', str(s.config_path)] + extra
        env = {k: v for k, v in os.environ.items()
               if not k.upper().startswith(('PYTHON', 'YTDLP')) and k.upper() not in
               ('HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY', 'NO_PROXY', 'SSLKEYLOGFILE')}
        proc = subprocess.Popen(argv, stdin=subprocess.PIPE if stdin_text is not None else subprocess.DEVNULL,
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                cwd=str(APP), env=env, **sc.popen_kwargs())
        tree = sc.ProcessTree(proc)
        with s.lock:
            s.tree = tree
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
                                s.handle_event(ev)
                        except ValueError:
                            pass
                    elif line.strip() and not line.startswith('[download] ') or line.startswith('[download] Destination'):
                        s.log.append({'time': now(), 'text': g.safe_text(line)[:400]})
            return proc.wait()
        finally:
            with s.lock:
                s.tree = None
            tree.close()
            proc.stdout.close()

    def find_titles(self):
        """Titelsuche fuer alle wartenden Eintraege ohne Titel. Rueckgabe: Exitcode (0 = nichts zu tun/ok)."""
        s = self.s
        with s.lock:
            batch = s.pending_titles()
            if not batch:
                return 0
            for item in batch:
                item['title_state'] = 'queued'
            s.preview_batch = batch
            s.current = {'id': 'preview', 'phase': 'preview', 'title': f'Titel werden gesucht (0 von {len(batch)})',
                         'percent': 0, 'started': now()}
            urls = '\n'.join(x['url'] for x in batch) + '\n'
        code = self.run_grab(['--preview'], stdin_text=urls)
        with s.lock:
            for item in batch:
                if item.get('title_state') in ('queued', 'running'):
                    item['title_state'] = 'pending'   # nicht fertig geworden: spaeter erneut
            s.preview_batch = None
            found = sum(1 for x in batch if x.get('title_state') == 'ok')
            bad = sum(1 for x in batch if x.get('title_state') == 'failed')
            if code == 0:
                s.last_check = now()
                text = f'Titel gefunden: {found} von {len(batch)}.' + (f' {bad} Link(s) nicht aufloesbar.' if bad else '')
                s.banner = {'level': 'warn' if bad else 'good', 'text': text}
            elif s.stop_requested:
                s.banner = {'level': 'warn', 'text': 'Titelsuche angehalten.'}
            else:
                err = (s.current or {}).get('error') or {}
                prefix = 'Sicherheitsabbruch: ' if code == 2 else 'Titelsuche fehlgeschlagen: '
                s.banner = {'level': 'bad', 'text': prefix + (err.get('message') or f'Exitcode {code}')}
            s.save_checks()
        return code

    def run(self):
        s = self.s
        try:
            if self.mode == 'preview':
                self.find_titles()
                return
            if self.mode == 'download':
                # Erst alle Titel, dann laden - wie die Vorschau der Kommandozeile.
                if self.find_titles() != 0:
                    return
                with s.lock:
                    s.banner = None
            if self.mode == 'check':
                with s.lock:
                    s.current = {'id': 'check', 'phase': 'checks', 'title': 'Sicherheitspruefung', 'started': now()}
                code = self.run_grab(['--check-only'])
                with s.lock:
                    if code == 0:
                        s.last_check = now()
                        s.banner = {'level': 'good', 'text': 'Alle Sicherheitspruefungen bestanden.'}
                    elif not s.stop_requested:
                        err = (s.current or {}).get('error') or {}
                        s.banner = {'level': 'bad', 'text': err.get('message') or f'Pruefung fehlgeschlagen (Exitcode {code}).'}
                    s.save_checks()
                return
            while True:
                with s.lock:
                    if s.stop_requested:
                        break
                    item = next((x for x in s.queue if x['status'] == 'waiting'), None)
                    if item is None:
                        break
                    item.update(status='running', started=now(), error=None)
                    s.current = {'id': item['id'], 'phase': 'checks', 'title': item.get('name') or item.get('title'),
                                 'percent': None, 'speed': None, 'eta': None, 'total': None, 'started': now()}
                    # Dateiname = eigener Name oder der in der Vorschau gefundene Titel (wie die Kommandozeile).
                    url, name = item['url'], item.get('name') or item.get('title')
                code = self.run_grab([url] + ([name] if name else []))
                with s.lock:
                    cur = s.current or {}
                    item['finished'] = now()
                    item['title'] = cur.get('title') or item.get('title')
                    if code == 0:
                        item.update(status='done', file=cur.get('file'), size=cur.get('size'))
                        s.last_check = now()
                    elif s.stop_requested:
                        item['status'] = 'stopped'
                    else:
                        item['status'] = 'failed'
                        item['error'] = cur.get('error') or {'ident': 'EXIT', 'code': code, 'message': f'Exitcode {code}'}
                    s.save_checks()
                    if code == 2:
                        # Wie in der Kommandozeile: Sicherheitsabbruch stoppt die ganze Warteschlange.
                        s.banner = {'level': 'bad', 'text': 'Sicherheitsabbruch: ' + item['error']['message'] +
                                    ' Die Warteschlange wurde angehalten.'}
                        break
            with s.lock:
                if s.stop_requested:
                    s.banner = {'level': 'warn', 'text': 'Angehalten.'}
                elif not s.banner or s.banner.get('level') != 'bad':
                    done = sum(1 for x in s.queue if x['status'] == 'done')
                    s.banner = {'level': 'good', 'text': f'Warteschlange abgearbeitet ({done} fertig).'}
        except Exception as exc:  # nie still scheitern
            with s.lock:
                s.banner = {'level': 'bad', 'text': f'Interner Fehler der Oberflaeche ({type(exc).__name__}).'}
        finally:
            with s.lock:
                halted = s.stop_requested or (s.banner or {}).get('level') == 'bad'
                s.current = None
                s.mode = 'idle'
                s.stop_requested = False
                s.worker = None
                s.preview_batch = None
                start_next = s.start_after_preview and self.mode == 'preview'
                s.start_after_preview = False
                if not halted and start_next and any(x['status'] == 'waiting' for x in s.queue):
                    s.start_worker('download')   # "Start" wurde waehrend der Titelsuche gedrueckt
                elif not halted and s.pending_titles():
                    # Waehrend eines Downloads hinzugefuegte Links bekommen danach ihre Titel.
                    s.start_worker('preview')


def make_handler(state, token, port_holder):
    class Handler(http.server.BaseHTTPRequestHandler):
        server_version = 'Quite Safe Grab'
        sys_version = ''

        def log_message(self, *args):   # keine Zugriffsprotokolle (Links stehen in Anfragen)
            pass

        def log_request(self, code='-', size='-'):
            if DEBUG:   # nur Methode, Pfad ohne Query/Fragment und Status - nie Inhalte oder Schluessel
                path = urllib.parse.urlsplit(self.path).path
                print(f'[debug] {time.strftime("%H:%M:%S")} {self.command} {path} -> {code} '
                      f'(Token {"ja" if self.headers.get("X-QSGrab-Token") else "nein"}, '
                      f'Origin {self.headers.get("Origin") or "-"}, Host {self.headers.get("Host")})', flush=True)

        def origin_ok(self):
            expected = f'127.0.0.1:{port_holder[0]}'
            if self.headers.get('Host') != expected:
                return False
            origin = self.headers.get('Origin')
            return origin in (None, f'http://{expected}')

        def send(self, code, body, ctype='application/json; charset=utf-8'):
            data = body if isinstance(body, bytes) else json.dumps(body, ensure_ascii=False).encode('utf-8')
            self.send_response(code)
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
            return hmac.compare_digest(got.encode('utf-8', 'replace'), token.encode('ascii'))

        def do_GET(self):
            if not self.origin_ok():
                return self.send(403, {'error': 'forbidden'})
            path = urllib.parse.urlsplit(self.path).path
            if path in STATIC:
                name, ctype = STATIC[path]
                try:
                    return self.send(200, (APP / 'ui' / name).read_bytes(), ctype)
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
                    u = u.strip() if isinstance(u, str) else ''
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
                    s.start_worker('preview')   # Titel sofort suchen (laeuft gerade etwas, danach)
                return {'added': added, 'invalid': bad}
            if path == '/api/queue/remove':
                ident = body.get('id')
                s.queue[:] = [x for x in s.queue if not (x['id'] == ident and x['status'] != 'running')]
                return {'ok': True}
            if path == '/api/queue/clear':
                s.queue[:] = [x for x in s.queue if x['status'] in ('waiting', 'running')]
                return {'ok': True}
            if path == '/api/queue/retry':
                for x in s.queue:
                    if x['id'] == body.get('id') and x['status'] in ('failed', 'stopped'):
                        x.update(status='waiting', error=None)
                        if x.get('title_state') != 'ok':
                            x['title_state'] = 'pending'
                if s.pending_titles():
                    s.start_worker('preview')
                return {'ok': True}
            if path == '/api/start':
                if not any(x['status'] == 'waiting' for x in s.queue):
                    raise ValueError('Keine wartenden Links in der Warteschlange.')
                if s.worker is not None:
                    if s.mode == 'preview':
                        s.start_after_preview = True   # direkt nach der Titelsuche loslegen
                        return {'ok': True, 'deferred': True}
                    raise ValueError('Es laeuft bereits ein Vorgang.')
                s.start_worker('download')
                return {'ok': True}
            if path == '/api/check':
                if not s.start_worker('check'):
                    raise ValueError('Es laeuft bereits ein Vorgang.')
                return {'ok': True}
            if path == '/api/stop':
                if s.worker is not None:
                    s.stop_requested = True
                    if s.tree is not None:
                        s.tree.kill()
                return {'ok': True}
            if path == '/api/open-folder':
                folder = s.storage / 'finished'
                if folder.is_dir() and not sc.is_reparse_or_link(folder):
                    os.startfile(str(folder))   # fester Pfad aus der Konfiguration, keine Eingabe
                return {'ok': True}
            if path == '/api/dismiss':
                s.banner = None
                return {'ok': True}
            if path == '/api/ping':
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


def browser_command(choice, url, profile_root, finders=(find_mullvad, find_edge)):
    """(Name, argv) fuer den Browserstart oder (None, Hinweis) wenn nicht moeglich."""
    find_mb, find_ed = finders
    if choice in ('auto', 'mullvad'):
        exe = find_mb()
        if exe:
            profile = profile_root / 'mullvad'
            return 'Mullvad Browser', [exe, '-no-remote', '-profile', str(profile), '-new-window', url]
        if choice == 'mullvad':
            return None, ('Mullvad Browser nicht gefunden (ui_browser = "mullvad"). Installieren von '
                          'https://mullvad.net/browser oder in config.toml ui_browser = "auto" setzen.')
    exe = find_ed()
    if exe:
        profile = profile_root / 'edge'
        return 'Microsoft Edge (eigenes Profil)', [exe, f'--user-data-dir={profile}', f'--app={url}', '--no-first-run',
                                                   '--no-default-browser-check', '--disable-sync', '--disable-extensions',
                                                   '--disable-background-networking', '--disable-features=Translate,AutofillServerCommunication']
    return None, 'Weder Mullvad Browser noch Microsoft Edge gefunden.'


def reset_profile(path):
    if path.exists() and not sc.is_reparse_or_link(path):
        shutil.rmtree(path, ignore_errors=True)


# Sperrdatei, die der Browser exklusiv offen haelt, solange er mit diesem Profil laeuft.
PROFILE_LOCK = {'mullvad': 'parent.lock', 'edge': 'lockfile'}


def profile_of(cmd):
    """(Art, Profilordner) aus einer Startzeile von browser_command."""
    if '-profile' in cmd:
        return 'mullvad', Path(cmd[cmd.index('-profile') + 1])
    for arg in cmd:
        if arg.startswith('--user-data-dir='):
            return 'edge', Path(arg.split('=', 1)[1])
    return None, None


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


def prepare_mullvad_profile(exe, profile):
    """Einmalige, unsichtbare Einrichtung eines neuen Mullvad-Profils.

    Beim allerersten Start installiert der Mullvad Browser seine Erweiterungen (NoScript, uBlock)
    und startet sich neu; in diesem Moment geladene Seiten bekommen kein JavaScript. Deshalb
    wird ein neues Profil vorher ohne Fenster (headless) initialisiert.
    """
    if (profile / 'prefs.js').is_file() and not any((profile / 'extensions' / 'staged').glob('*')):
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
        if (profile / 'prefs.js').is_file() and not any((profile / 'extensions' / 'staged').glob('*')):
            return True
    return (profile / 'prefs.js').is_file()


def main(argv=None):
    parser = argparse.ArgumentParser(description='QuiteSafeGrab-Oberflaeche (lokal, nur 127.0.0.1).')
    parser.add_argument('--config', default=str(APP / 'config.toml'))
    parser.add_argument('--no-browser', action='store_true', help='Keinen Browser starten, nur Adresse anzeigen (Entwicklung).')
    parser.add_argument('--debug', action='store_true', help='Anfragen (nur Methode/Pfad/Status) und Browserprozess anzeigen.')
    parser.add_argument('--no-check', action='store_true', help='Beim Start keine automatische Sicherheitspruefung.')
    args = parser.parse_args(argv)
    global DEBUG
    DEBUG = args.debug
    try:
        config = g.load_config(args.config)
    except g.Failure as exc:
        g.error(exc)
        return exc.code
    state = State(config, Path(args.config))
    token = secrets.token_urlsafe(32)
    port_holder = [0]
    server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), make_handler(state, token, port_holder))
    server.daemon_threads = True
    port_holder[0] = server.server_address[1]
    url = f'http://127.0.0.1:{port_holder[0]}/#t={token}'
    profile_root = APP / '.ui-profile'
    kind = profile = None
    print('QuiteSafeGrab-Oberflaeche laeuft lokal (nur dieser PC). Dieses Fenster offen lassen; schliessen beendet Quite Safe Grab.')
    if args.no_browser:
        print('Adresse: ' + url)
    else:
        name, cmd = browser_command(config.get('ui_browser', 'auto'), url, profile_root)
        if name is None:
            print('FEHLER: ' + cmd, file=sys.stderr)
            server.server_close()
            return 1
        kind, profile = profile_of(cmd)
        if profile_in_use(kind, profile):
            print('FEHLER: Ein QuiteSafeGrab-Browserfenster ist noch offen. Bitte schliessen und erneut starten.', file=sys.stderr)
            server.server_close()
            return 1
        profile_root.mkdir(exist_ok=True)
        if kind == 'edge':
            reset_profile(profile)   # Edge speichert Verlauf: immer frisch
        elif kind == 'mullvad':
            # Mullvad surft immer privat (kein Verlauf); das Profil bleibt, damit Erweiterungen eingerichtet sind.
            print('Bereite Mullvad Browser vor ...' if not (profile / 'prefs.js').is_file() else '', end='', flush=True)
            if not prepare_mullvad_profile(cmd[0], profile):
                print('\nFEHLER: Mullvad-Browserprofil liess sich nicht einrichten.', file=sys.stderr)
                server.server_close()
                return 1
        try:
            subprocess.Popen(cmd, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, close_fds=True)
        except OSError:
            print('FEHLER: Browser liess sich nicht starten.', file=sys.stderr)
            server.server_close()
            return 1
        print(f'\nGeoeffnet in: {name}' if kind == 'mullvad' else f'Geoeffnet in: {name}')
        if name.startswith('Microsoft Edge') and config.get('ui_browser') == 'auto':
            print('Tipp: Mit installiertem Mullvad Browser (https://mullvad.net/browser) oeffnet Quite Safe Grab diesen - ohne Telemetrie, immer privat.')
    launched = time.monotonic()
    if not args.no_check:
        # Beim Start einmal alle Sicherheitspruefungen, damit die Ampel sofort aktuell ist.
        with state.lock:
            state.start_worker('check')

    def watchdog():
        gone_since = None
        seen_open = False
        while True:
            time.sleep(2)
            if profile is not None:
                if profile_in_use(kind, profile):
                    seen_open, gone_since = True, None
                elif seen_open or time.monotonic() - launched > 120:
                    if gone_since is None and DEBUG:
                        print('[debug] Browserprofil nicht mehr in Benutzung.', flush=True)
                    gone_since = gone_since or time.monotonic()
            with state.lock:
                busy = state.worker is not None
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
            if state.tree is not None:
                state.tree.kill()
        server.server_close()
        if kind == 'edge' and not profile_in_use(kind, profile):
            reset_profile(profile)
    return 0


if __name__ == '__main__':
    sys.exit(main())
