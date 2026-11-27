"""MixDrop-Baustein und die Zuordnung von /e/-Links (ohne Netz, mit Attrappen)."""
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import grab as g
import mixdrop_resolver as md
from helpers import RecordingNet, ScriptedRunner, write_config

CONFIG = g.load_config(Path(g.__file__).with_name('config.default.toml'))
SIGNED = 'https://s-delivery9.mxcontent.net/v/abc.mp4?s=geheim&e=9'


def packed(media='//s-delivery9.mxcontent.net/v/abc.mp4?s=geheim&e=9'):
    """Ein mit dem p,a,c,k,e,d-Packer verpacktes MixDrop-Skript (Woerter 0..2 stehen fuer die Tabelle)."""
    payload = '0.1="' + media + '";2.3();'
    symtab = 'MDCore|wurl|MDPlayer|play'
    return ("eval(function(p,a,c,k,e,d){e=function(c){return c};if(!''.replace(/^/,String)){while(c--)"
            "d[c]=k[c]||c;k=[function(e){return d[e]}];e=function(){return'\\\\w+'};c=1};while(c--)if(k[c])"
            "p=p.replace(new RegExp('\\\\b'+e(c)+'\\\\b','g'),k[c]);return p}('" + payload + "',36,4,'"
            + symtab + "'.split('|'),0,{}))")


def page(media=None, title='MixDrop - Watch Ein.Freier.Film.mp4'):
    return (f'<html><head><title>{title}</title></head><body><script>var x=1;</script>'
            f'<script>{packed(media) if media is not None else packed()}</script></body></html>')


class FakeResponse:
    def __init__(self, url, body):
        self.url, self.body = url, body.encode('utf-8') if isinstance(body, str) else body

    def read(self, n=-1):
        return self.body if n < 0 else self.body[:n]

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


class FakeOpener:
    def __init__(self, pages):
        self.pages, self.requests = pages, []

    def open(self, req, timeout=None):
        self.requests.append((req.full_url, dict(req.header_items()), timeout))
        final, body = self.pages[req.full_url]
        return FakeResponse(final, body)


class TestUnpack(unittest.TestCase):
    def test_unpack_reads_wurl_without_executing(self):
        text = md.unpack(packed())
        self.assertIn('MDCore.wurl="//s-delivery9.mxcontent.net/v/abc.mp4?s=geheim&e=9"', text)
        self.assertIsNone(md.unpack('var harmlos = 1;'))
        broken = packed().replace(",36,4,'", ",36,9,'")   # Tabellenlaenge passt nicht
        with self.assertRaises(ValueError):
            md.unpack(broken)

    def test_parse_page_title_and_https_only(self):
        result = md.parse_page(page())
        self.assertEqual(result, {'title': 'Ein.Freier.Film.mp4', 'url': SIGNED})
        with self.assertRaises(ValueError):
            md.parse_page(page('http://s-delivery9.mxcontent.net/v/abc.mp4'))   # kein Abruf ohne HTTPS
        self.assertIsNone(md.parse_page('<html><script>var x=1;</script></html>'))


class TestResolve(unittest.TestCase):
    HOSTS = ['mxdrop.click', 'mixdrop.co']

    def run_resolve(self, url, pages):
        opener = FakeOpener(pages)
        with patch.object(md.urllib.request, 'build_opener', lambda *handlers: opener):
            result = md.resolve(url, self.HOSTS)
        return result, opener.requests

    def test_file_page_becomes_embed_page_with_host_referer(self):
        result, requests = self.run_resolve('https://mxdrop.click/f/xo8zdf6828dnds',
                                            {'https://mxdrop.click/e/xo8zdf6828dnds': ('https://mxdrop.click/e/xo8zdf6828dnds', page())})
        self.assertEqual(result, {'title': 'Ein.Freier.Film.mp4', 'url': SIGNED, 'referer': 'https://mxdrop.click/'})
        (url, headers, timeout), = requests
        self.assertEqual(url, 'https://mxdrop.click/e/xo8zdf6828dnds')
        self.assertEqual(headers.get('Referer'), 'https://mxdrop.click/')
        self.assertEqual(headers.get('User-agent'), md.UA)
        self.assertNotIn('Cookie', headers)
        self.assertEqual(timeout, 20)

    def test_refuses_foreign_hosts_http_and_huge_pages(self):
        for url in ('https://evil.example/e/abc', 'http://mxdrop.click/e/abc', 'https://mxdrop.click:8443/e/abc',
                    'https://mxdrop.click/other/abc'):
            with self.assertRaises(ValueError, msg=url):
                self.run_resolve(url, {})
        huge = 'x' * (md.MAX_PAGE_BYTES + 1)
        with self.assertRaises(ValueError):
            self.run_resolve('https://mxdrop.click/e/abc', {'https://mxdrop.click/e/abc': ('https://mxdrop.click/e/abc', huge)})
        # Weiterleitung auf einen Host ausserhalb der Liste
        with self.assertRaises(ValueError):
            self.run_resolve('https://mxdrop.click/e/abc', {'https://mxdrop.click/e/abc': ('https://evil.example/e/abc', page())})

    def test_redirect_to_other_mirror_is_followed_once(self):
        pages = {'https://mxdrop.click/e/abc': ('https://mixdrop.co/e/abc', '<html>kein Skript</html>'),
                 'https://mixdrop.co/e/abc': ('https://mixdrop.co/e/abc', page())}
        result, requests = self.run_resolve('https://mxdrop.click/e/abc', pages)
        self.assertEqual(result['referer'], 'https://mixdrop.co/')
        self.assertEqual([r[0] for r in requests], ['https://mxdrop.click/e/abc', 'https://mixdrop.co/e/abc'])

    def test_redirect_handler_only_allows_listed_https_hosts(self):
        handler = md.Redirect(self.HOSTS)
        with self.assertRaises(ValueError):
            handler.redirect_request(None, None, 302, 'Found', {}, 'https://evil.example/e/abc')


class TestResolveItem(unittest.TestCase):
    def answer(self, **data):
        base = {'url': SIGNED, 'title': 'Ein.Freier.Film.mp4', 'referer': 'https://mxdrop.click/'}
        base.update(data)
        return g.Result(0, json.dumps(base))

    def test_mixdrop_link_uses_only_the_mixdrop_resolver(self):
        runner, net = ScriptedRunner([self.answer()]), RecordingNet()
        item = g.resolve_item('https://mxdrop.click/e/xo8zdf6828dnds', None, CONFIG, runner, net, Path('.'), '1.1.1.1')
        (argv, stdin), = runner.calls
        self.assertTrue(str(argv[2]).endswith('mixdrop_resolver.py'))
        self.assertEqual(argv[3], 'https://mxdrop.click/e/xo8zdf6828dnds')
        self.assertEqual(json.loads(argv[4]), CONFIG['mixdrop_hosts'])
        self.assertEqual(net.calls, [])   # einziger Netzschritt direkt nach der Pruefung des Aufrufers
        self.assertEqual((item.name, item.referer, item.voe, item.info), ('Ein.Freier.Film', 'https://mxdrop.click/', False, None))
        self.assertEqual(item.media_hosts, {'s-delivery9.mxcontent.net'})
        self.assertNotIn('voe', ' '.join(map(str, argv)))   # VOE erfaehrt nichts

    def test_mixdrop_failures_are_not_fatal_and_invalid_output_is_refused(self):
        with self.assertRaises(g.Failure) as caught:
            g.resolve_item('https://mxdrop.click/e/abc', None, CONFIG, ScriptedRunner([g.Result(4, '', 'x')]), RecordingNet(), Path('.'), None)
        self.assertEqual((caught.exception.code, caught.exception.ident), (4, 'MIXDROP_RESOLUTION_FAILED'))
        for bad in (self.answer(url='http://s.example/a.mp4'), self.answer(referer='https://evil.example/'),
                    self.answer(referer='https://mxdrop.click/e/abc'), g.Result(0, 'kein json')):
            with self.assertRaises(g.Failure) as caught:
                g.resolve_item('https://mxdrop.click/e/abc', None, CONFIG, ScriptedRunner([bad]), RecordingNet(), Path('.'), None)
            self.assertEqual((caught.exception.code, caught.exception.ident), (4, 'MIXDROP_RESOLUTION_INVALID'))

    def test_unknown_e_link_tries_normal_way_first_and_voe_last(self):
        """Unbekannte Seite mit /e/<id>: erst yt-dlp, dann Weiterleitung, VOE erst zuletzt - mit Pruefung davor."""
        voe_ok = g.Result(0, json.dumps({'url': 'https://cdn.voe.example/a.mp4', 'title': 'VOE Titel'}))
        runner = ScriptedRunner([g.Result(1, '', 'ERROR: Unsupported URL'), g.Result(1, '', 'ERROR: generic failed'),
                                 g.Result(4, '', 'kein Redirect'), voe_ok])
        net = RecordingNet()
        with patch.object(g, 'SESSION', g.Session()):
            item = g.resolve_item('https://neuer-spiegel.example/e/abc123', None, CONFIG, runner, net, Path('.'), '1.1.1.1')
        self.assertEqual(net.calls, ['IPv4 vor Generic-Aufloesung', 'IPv4 vor Weiterleitungs-Aufloesung', 'IPv4 vor VOE-Aufloesung'])
        self.assertEqual(runner.calls[2][0][3], 'https://neuer-spiegel.example/e/abc123')   # Weiterleitung: Originallink
        self.assertEqual(runner.calls[3][0][3], 'https://voe.sx/e/abc123')                  # VOE erst ganz zuletzt
        self.assertTrue(item.voe)

    def test_unknown_e_link_never_reaches_voe_if_resolved_otherwise(self):
        info = {'title': 'Titel', 'url': 'https://cdn.site.example/a.mp4'}
        runner = ScriptedRunner([g.Result(0, json.dumps(info))])
        item = g.resolve_item('https://anderer.example/e/abc123', None, CONFIG, runner, RecordingNet(), Path('.'), None)
        self.assertEqual(len(runner.calls), 1)
        self.assertFalse(item.voe)

    def test_known_voe_host_still_goes_straight_to_voe(self):
        voe_ok = g.Result(0, json.dumps({'url': 'https://cdn.voe.example/a.mp4', 'title': 'VOE Titel'}))
        runner = ScriptedRunner([voe_ok])
        item = g.resolve_item('https://voe.sx/e/abc123', None, CONFIG, runner, RecordingNet(), Path('.'), None)
        self.assertEqual(len(runner.calls), 1)
        self.assertTrue(item.voe)


class TestConfig(unittest.TestCase):
    def test_mixdrop_hosts_optional_and_validated(self):
        def without(text):
            return '\n'.join(l for l in text.splitlines() if not l.startswith('mixdrop_hosts'))
        old = g.load_config(write_config(self, without))
        self.assertEqual(old['mixdrop_hosts'], list(g.MIXDROP_HOSTS))
        self.assertIn('mxdrop.click', old['mixdrop_hosts'])
        for change in (lambda t: t.replace('mixdrop_hosts = [', 'mixdrop_hosts = [1, '),
                       lambda t: t + '\nunbekannt = 1\n'):
            with self.assertRaises(g.Failure) as caught:
                g.load_config(write_config(self, change))
            self.assertEqual(caught.exception.ident, 'CONFIG_INVALID')


if __name__ == '__main__':
    unittest.main()
