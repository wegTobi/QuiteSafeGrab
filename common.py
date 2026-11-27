# SPDX-License-Identifier: GPL-3.0-only
"""Stabile Grundbausteine fuer Quite Safe Grab: Fehlertyp, Exitcodes, Textbereinigung, Ereignisprotokoll.

Haengt von keinem anderen Programmmodul ab; grab.py, ui.py und fw.py importieren von hier.
"""
import re
import sys
import unicodedata

# Exitcodes (Werte sind Teil der Schnittstelle zu ui.py, setup.ps1 und Nutzerskripten).
EXIT_OK = 0
EXIT_USER = 1      # Eingabe, Konfiguration, Ablage, Prozessfehler
EXIT_SAFETY = 2    # Sicherheitspruefung nicht bestanden: fail closed, Warteschlange haelt an
EXIT_RESOLVE = 4   # Link nicht aufloesbar
EXIT_MEDIA = 5     # Medienpruefung/Remux gescheitert


class Failure(Exception):
    def __init__(self, code, ident, message):
        super().__init__(message)
        self.code, self.ident = code, ident


def fail(code, ident, message):
    raise Failure(code, ident, message)


def safe_text(text):
    """Do not persist signed URLs; strip terminal control characters too."""
    text = re.sub(r'https?://[^\s<>"\']+', '[URL entfernt]', str(text))
    return ''.join(c for c in text if c in '\n\r\t' or unicodedata.category(c)[0] != 'C')


# --- Maschinenlesbares Ereignisprotokoll fuer die Oberflaeche (ui.py): eine Zeile "@@QSGRAB {json}".
EVENT_PREFIX = '@@QSGRAB '
CHECK_KEYS = ('vpn', 'firewall', 'selftest', 'ipv4', 'ipv6', 'dns')
# Fehler, die ohne eigenes check-Ereignis enden -> welche Pruefung (Ampel) sie betreffen.
ERROR_CHECK = {'GUARD_QUERY_FAILED': 'firewall', 'GUARD_QUERY_INVALID': 'firewall', 'FIREWALL_DISABLED': 'firewall',
               'FIREWALL_RULES_MISSING': 'firewall', 'FIREWALL_BLOCKS_VPN': 'firewall',
               'TUNNEL_STATUS_UNAVAILABLE': 'ipv4', 'EXIT_IP_CHANGED': 'ipv4', 'NETWORK_CHECK_ERROR': 'ipv4',
               'DNS_RESOLVER_FAILED': 'dns', 'DNS_RESOLVER_AMBIGUOUS': 'dns', 'DNS_RESOLVER_INVALID': 'dns',
               'DNS_GEO_FAILED': 'dns'}


# Phasen (Ereignis "phase"). DOWNLOAD_PHASES ist die Reihenfolge eines Downloads, so zeigt sie die Oberflaeche.
PHASE_CHECKS, PHASE_PROBE, PHASE_RESOLVE = 'checks', 'probe', 'resolve'
PHASE_DOWNLOAD, PHASE_REMUX, PHASE_VERIFY, PHASE_DONE = 'download', 'remux', 'verify', 'done'
PHASE_PREVIEW, PHASE_SIZES = 'preview', 'sizes'
DOWNLOAD_PHASES = (PHASE_CHECKS, PHASE_PROBE, PHASE_RESOLVE, PHASE_DOWNLOAD, PHASE_REMUX, PHASE_VERIFY)


def check_key(label):
    return 'ipv6' if label.startswith('IPv6') else 'dns' if label.startswith('DNS') else 'ipv4'


def error(exc, emit=None):
    """FEHLER-Zeile auf stderr; mit emit zusaetzlich das error-Ereignis (grab.py im --events-Betrieb)."""
    print(f'FEHLER: ID={exc.ident}; EXIT_CODE={exc.code}; MESSAGE={safe_text(exc)}', file=sys.stderr)
    if emit is not None:
        emit('error', ident=exc.ident, code=exc.code, message=str(exc), check=ERROR_CHECK.get(exc.ident))


# --- Seiten, deren Links nur per Weiterleitung aufloesbar waren: ui.py gibt sie per Umgebungsvariable weiter.
REDIRECT_HOSTS_ENV = 'QSGRAB_REDIRECT_HOSTS'
HOST_RE = re.compile(r'(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}')

# --- Browser fuer die Oberflaeche (config.toml: ui_browser)
BROWSER_AUTO, BROWSER_MULLVAD, BROWSER_EDGE = 'auto', 'mullvad', 'edge'
UI_BROWSERS = (BROWSER_AUTO, BROWSER_MULLVAD, BROWSER_EDGE)
