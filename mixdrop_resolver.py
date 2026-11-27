#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""MixDrop: Medienadresse aus der Einbettungsseite lesen - gleiche Schranken wie voe_resolver.

Kein eval, keine JavaScript-Ausfuehrung, keine Cookies, keine Downloads, keine Debug-Dateien.
MixDrop verpackt die Adresse mit dem verbreiteten "p,a,c,k,e,d"-Packer; der wird hier nur als Text
entschluesselt (Woerter gegen eine Tabelle tauschen), nie ausgefuehrt.
"""
import html
import json
from pathlib import Path
import re
import sys
import urllib.parse
import urllib.request

if __name__ == '__main__':
    # -I excludes the script directory; explicitly admit only this installed source.
    sys.path.insert(0, str(Path(__file__).resolve().parent))

from voe_resolver import UA, Redirect, https_443, valid_url

MAX_PAGE_BYTES = 2 * 1024 * 1024
MAX_PAGE_STEPS = 2   # Dateiseite /f/<id> wird vorher auf die Einbettungsseite /e/<id> umgestellt
ID_RE = '[A-Za-z0-9]+'
PACKED_RE = re.compile(
    r"eval\(function\(p,a,c,k,e,[dr]\)\{.*?\}\(\s*'(?P<payload>(?:\\.|[^'\\])*)'\s*,\s*(?P<radix>\d+)\s*,"
    r"\s*(?P<count>\d+)\s*,\s*'(?P<symtab>(?:\\.|[^'\\])*)'\.split\('\|'\)", re.S)
WURL_RE = re.compile(r'''(?:MDCore\.)?wurl\s*=\s*["']([^"']+)["']''')
DIGITS = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ'


def allowed_page(url, hosts):
    valid_url(url)
    p = urllib.parse.urlsplit(url)
    if not https_443(p) or p.hostname not in hosts:
        raise ValueError('MixDrop-Seite ausserhalb der konfigurierten HTTPS-Hosts')
    return url


def embed_url(url):
    """https://<host>/f/<id> oder /e/<id> -> https://<host>/e/<id>; anderes -> ValueError."""
    p = urllib.parse.urlsplit(url)
    m = re.fullmatch(f'/(?:e|f)/({ID_RE})(?:/.*)?', p.path)
    if not m:
        raise ValueError('Kein MixDrop-Videolink (/e/<id> oder /f/<id>)')
    return urllib.parse.urlunsplit(('https', p.netloc, '/e/' + m.group(1), '', ''))


def _number(word, radix):
    """Zahl eines Packer-Worts (Basis bis 62, Ziffernfolge wie beim Packer)."""
    if radix <= 36:
        return int(word, radix)
    value = 0
    for ch in word:
        digit = DIGITS.index(ch)
        if digit >= radix:
            raise ValueError
        value = value * radix + digit
    return value


def unpack(script):
    """p,a,c,k,e,d-Packer als Text aufloesen. Keine Ausfuehrung: nur Woerter durch Tabelleneintraege ersetzen."""
    m = PACKED_RE.search(script)
    if not m:
        return None
    payload = m.group('payload').replace("\\'", "'").replace('\\\\', '\\')
    radix, count = int(m.group('radix')), int(m.group('count'))
    symtab = m.group('symtab').split('|')
    if not 2 <= radix <= 62 or count != len(symtab):
        raise ValueError('Unbekanntes Packer-Format')

    def swap(match):
        word = match.group(0)
        try:
            index = _number(word, radix)
        except ValueError:
            return word
        return symtab[index] if index < len(symtab) and symtab[index] else word

    return re.sub(r'\b\w+\b', swap, payload)


def parse_page(text):
    """Titel und Medienadresse aus der Einbettungsseite; None, wenn keine Adresse zu finden ist."""
    title = ''
    m = re.search(r'<title>(.*?)</title>', text, re.S | re.I)
    if m:
        title = html.unescape(m.group(1)).strip()
        title = re.sub(r'^\s*MixDrop\s*[-|:]\s*(?:Watch\s+)?', '', title, flags=re.I).strip()
    for block in re.findall(r'<script[^>]*>(.*?)</script>', text, re.S | re.I):
        unpacked = unpack(block)
        if not unpacked:
            continue
        found = WURL_RE.search(unpacked)
        if found:
            media = found.group(1)
            if media.startswith('//'):
                media = 'https:' + media
            media = valid_url(html.unescape(media))
            if urllib.parse.urlsplit(media).scheme != 'https':
                raise ValueError('MixDrop-Medienadresse nicht ueber HTTPS')
            return {'title': title, 'url': media}
    return None


def resolve(url, hosts):
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), Redirect(hosts))
    url = embed_url(allowed_page(url, hosts))
    for _ in range(MAX_PAGE_STEPS):
        allowed_page(url, hosts)
        p = urllib.parse.urlsplit(url)
        req = urllib.request.Request(url, headers={'User-Agent': UA, 'Referer': f'https://{p.netloc}/'})
        with opener.open(req, timeout=20) as response:
            raw = response.read(MAX_PAGE_BYTES + 1)
            if len(raw) > MAX_PAGE_BYTES:
                raise ValueError('MixDrop-Seite zu gross')
            text = raw.decode('utf-8', errors='replace')
            final = response.url
        allowed_page(final, hosts)
        result = parse_page(text)
        if result:
            result['referer'] = 'https://' + urllib.parse.urlsplit(final).netloc + '/'
            return result
        if final != url:
            url = embed_url(final)   # auf einen anderen Spiegel weitergeleitet: dort einmal die /e/-Seite
            continue
        break
    raise ValueError('Keine Medienadresse auf der MixDrop-Seite; keine Schutzumgehung')


if __name__ == '__main__':
    try:
        print(json.dumps(resolve(sys.argv[1], json.loads(sys.argv[2])), ensure_ascii=False))
    except Exception:
        # Never include the signed address or response body in persistent output.
        print('MIXDROP_RESOLUTION_FAILED: Aufloesung fehlgeschlagen (Hostliste/Seitenformat/Erreichbarkeit pruefen).', file=sys.stderr)
        sys.exit(4)
