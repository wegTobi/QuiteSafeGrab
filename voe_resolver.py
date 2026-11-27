#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Restricted resolver; no eval, JS execution, downloads or debug-page files."""
import base64
import contextlib
import html
import io
import ipaddress
import json
from pathlib import Path
import re
import socket
import sys
import urllib.error
import urllib.parse
import urllib.request

UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:140.0) Gecko/20100101 Firefox/140.0'
VOE_REFERER = 'https://voe.sx/'   # Pflicht-Referer fuer VOE-Seiten und -Transfers (auch grab.py)

# VOE-IDs: grab.is_voe erkennt nur Kleinbuchstaben und Ziffern (VOE_ID_RE), embed_url auch Grossbuchstaben
# (EMBED_ID_RE). Bewusst nicht angeglichen - das wuerde aendern, welche Links als VOE gelten.
VOE_ID_RE = '[a-z0-9]+'
EMBED_ID_RE = '[A-Za-z0-9]+'

# Schrittgrenzen, bewusst verschieden (Angleichen waere eine Verhaltensaenderung):
MAX_PAGE_STEPS = 4   # resolve(): VOE-Seiten inkl. JavaScript-/Einbettungs-Sprung
MAX_HOPS = 5         # follow(): HTTP-Weiterleitungen bis zum VOE-Host
MAX_SIZE_HOPS = 4    # grab.media_size(): Weiterleitungen der Videodatei


def valid_url(url):
    if not isinstance(url, str) or any(ord(c) < 33 for c in url):
        raise ValueError('Ungueltige Medienadresse')
    p = urllib.parse.urlsplit(url)
    if p.scheme not in ('https', 'http') or not p.hostname or p.username or p.password:
        raise ValueError('Keine erlaubte HTTP/HTTPS-Adresse')
    _ = p.port
    return url


def https_443(p):
    """Zerlegte Adresse (urlsplit) nutzt HTTPS auf dem Standardport."""
    return p.scheme == 'https' and p.port in (None, 443)


def allowed_page(url, hosts):
    valid_url(url)
    p = urllib.parse.urlsplit(url)
    if not https_443(p) or p.hostname not in hosts:
        raise ValueError('VOE-Weiterleitung ausserhalb der konfigurierten HTTPS-Hosts')
    return url


class Redirect(urllib.request.HTTPRedirectHandler):
    def __init__(self, hosts):
        super().__init__()
        self.hosts = hosts

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        allowed_page(newurl, self.hosts)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def parse_page(text, url):
    from bs4 import BeautifulSoup
    from voe_dl.sources import SOURCE_METHODS
    soup = BeautifulSoup(text, 'html.parser')
    tag = soup.find('meta', attrs={'property': 'og:title'}) or soup.find('meta', attrs={'name': 'og:title'})
    title = tag.get('content', '') if tag else ''
    if not title and soup.title:
        title = soup.title.get_text()
    # Upstream's diagnostics may contain signed URLs: discard in memory.
    with contextlib.redirect_stdout(io.StringIO()):
        for method in SOURCE_METHODS:
            data = method(soup, text, url)
            if not data:
                continue
            if isinstance(data, str):
                data = {'mp4': data}
            for key in ('mp4', 'hls'):
                media = data.get(key)
                if not isinstance(media, str) or not media:
                    continue
                if not media.startswith(('http://', 'https://', '//')):
                    media = base64.b64decode(media, validate=True).decode('utf-8')
                if media.startswith('//'):
                    media = 'https:' + media
                return {'title': html.unescape(title), 'url': valid_url(html.unescape(media))}
    return None


# Spiegel, deren Seite /<id> das Video nicht immer einbindet; /e/<id> (Einbettungsseite) schon.
EMBED_HOSTS = {'caseyseemavoid.com'}


def embed_url(url):
    """https://caseyseemavoid.com/<id> -> https://caseyseemavoid.com/e/<id>, sonst None."""
    p = urllib.parse.urlsplit(url)
    if p.hostname not in EMBED_HOSTS:
        return None
    m = re.fullmatch(f'/({EMBED_ID_RE})/?', p.path)
    if not m:
        return None
    return urllib.parse.urlunsplit((p.scheme, p.netloc, '/e/' + m.group(1), p.query, ''))


def resolve(url, hosts):
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), Redirect(hosts))
    visited = set()
    for _ in range(MAX_PAGE_STEPS):
        allowed_page(url, hosts)
        if url in visited:
            raise ValueError('VOE-Weiterleitungsschleife')
        visited.add(url)
        req = urllib.request.Request(url, headers={'User-Agent': UA, 'Referer': VOE_REFERER})
        with opener.open(req, timeout=20) as response:
            raw = response.read(2 * 1024 * 1024 + 1)
            if len(raw) > 2 * 1024 * 1024:
                raise ValueError('VOE-Seite zu gross')
            text = raw.decode('utf-8', errors='replace')
            url = response.url
        match = re.search(r'''(?:window\.)?location(?:\.href)?\s*=\s*["']([^"']+)["']|(?:window\.)?location\.(?:replace|assign)\(\s*["']([^"']+)["']''', text)
        if match:
            url = urllib.parse.urljoin(url, match.group(1) or match.group(2))
            continue
        result = parse_page(text, url)
        if result:
            return result
        embed = embed_url(url)
        if embed and embed not in visited:
            url = embed   # Seite ohne eingebundenes Video: einmal die /e/-Fassung versuchen
            continue
        raise ValueError('Keine eindeutige unterstuetzte Medienquelle; keine Schutzumgehung')
    raise ValueError('Zu viele VOE-Weiterleitungen')


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def public_host(host):
    """Nur oeffentliche Ziele: keine lokalen, privaten oder reservierten Adressen (auch nach DNS)."""
    try:
        infos = socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)
    except OSError:
        raise ValueError('Weiterleitungsziel nicht aufloesbar')
    addresses = {ipaddress.ip_address(info[4][0].split('%')[0]) for info in infos}
    if not addresses or not all(a.is_global for a in addresses):
        raise ValueError('Weiterleitung auf lokale/private Adresse verweigert')


def follow(url, hosts, check_host=public_host):
    """Folgt echten HTTP-Weiterleitungen (3xx) bis zu einer VOE-Adresse aus hosts.

    Kein JavaScript, keine Cookies, kein Referer, nur HTTPS, hoechstens MAX_HOPS Schritte.
    Endet die Kette nicht bei einem konfigurierten VOE-Host, wird abgebrochen.
    """
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    for _ in range(MAX_HOPS + 1):
        valid_url(url)
        p = urllib.parse.urlsplit(url)
        if p.hostname in hosts:
            return allowed_page(url, hosts)
        if not https_443(p):
            raise ValueError('Weiterleitung nur ueber HTTPS')
        check_host(p.hostname)
        req = urllib.request.Request(url, headers={'User-Agent': UA})
        try:
            with opener.open(req, timeout=20) as response:
                code, location = response.status, None
        except urllib.error.HTTPError as exc:
            code, location = exc.code, exc.headers.get('Location')
            exc.close()
        if code not in (301, 302, 303, 307, 308) or not location:
            raise ValueError('Keine HTTP-Weiterleitung zu VOE (JavaScript-Weiterleitungen werden nicht ausgefuehrt)')
        url = urllib.parse.urljoin(url, location)
    raise ValueError('Zu viele Weiterleitungen')


if __name__ == '__main__':
    # -I excludes the script directory; explicitly admit only this installed source.
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    try:
        hosts = json.loads(sys.argv[2])
        start = sys.argv[1]
        if urllib.parse.urlsplit(start).hostname not in hosts:
            start = follow(start, hosts)
        print(json.dumps(resolve(start, hosts), ensure_ascii=False))
    except Exception:
        # Never include the signed address or response body in persistent output.
        print('VOE_RESOLUTION_FAILED: Aufloesung fehlgeschlagen (Hostliste/Seitenformat/Erreichbarkeit pruefen).', file=sys.stderr)
        sys.exit(4)
