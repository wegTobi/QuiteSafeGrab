"""Gemeinsame Testhelfer: Zustand der Oberflaeche, Ereignisse, nachgestellte Netzpruefung und Prozesse.

Nur fuer Tests. Alles laeuft offline mit Attrappen (keine echten Prozesse, kein Netz).
"""
import contextlib
import io
import json
from pathlib import Path
import sys
import tempfile
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import grab as g

CONFIG_PATH = Path(g.__file__).with_name('config.default.toml')


def temp_dir(case):
    """Temporaerer Ordner, der nach dem Test aufgeraeumt wird."""
    directory = tempfile.TemporaryDirectory()
    case.addCleanup(directory.cleanup)
    return Path(directory.name)


def write_config(case, change=lambda text: text, name='config.toml', directory=None):
    """config.default.toml, mit change(text) veraendert, als Datei in einem Temp-Ordner (oder directory)."""
    path = Path(directory or temp_dir(case)) / name
    path.write_text(change(CONFIG_PATH.read_text(encoding='utf-8')), encoding='utf-8')
    return path


def make_state(case):
    """ui.State mit der Vorgabe-Konfiguration und eigenem Speicherordner (wird aufgeraeumt)."""
    import ui
    config = g.load_config(CONFIG_PATH)
    config['storage'] = str(temp_dir(case))
    return ui.State(config, CONFIG_PATH)


class Captured:
    """Mitgeschriebene Ausgabe; events = die geparsten @@QSGRAB-Zeilen."""
    def __init__(self):
        self.buffer = io.StringIO()

    @property
    def output(self):
        return self.buffer.getvalue()

    @property
    def events(self):
        return [json.loads(line[len(g.EVENT_PREFIX):]) for line in self.output.splitlines() if line.startswith(g.EVENT_PREFIX)]


@contextlib.contextmanager
def capture_events():
    """Frische Session mit --events; stdout wird mitgeschrieben."""
    session = g.Session()
    session.events = True
    captured = Captured()
    with patch.object(g, 'SESSION', session), contextlib.redirect_stdout(captured.buffer):
        yield captured


class RecordingNet:
    """Merkt sich die Labels aller Pruefpunkte; beim fail_on-ten Pruefpunkt (1-basiert) Sicherheitsabbruch (Exit 2)."""
    skip = False

    def __init__(self, fail_on=None, ip='1.1.1.1', ident='EXIT_IP_CHANGED'):
        self.fail_on, self.ip, self.ident = fail_on, ip, ident
        self.calls = []

    def check(self, label, expected=None):
        self.calls.append(label)
        if len(self.calls) == self.fail_on:
            g.fail(2, self.ident, 'simulierter Sicherheitsabbruch')
        return self.ip


class ScriptedRunner:
    """Antwortet der Reihe nach (Result oder Funktion argv, kw -> Result); calls = [(argv, input_text)]."""
    def __init__(self, answers):
        self.answers = list(answers)
        self.calls = []

    def run(self, argv, **kw):
        self.calls.append((argv, kw.get('input_text')))
        answer = self.answers.pop(0)
        return answer(argv, kw) if callable(answer) else answer


def nslookup_runner(text):
    """Runner, der auf jeden Aufruf mit derselben nslookup-Ausgabe antwortet."""
    class Runner(ScriptedRunner):
        def run(self, argv, **kw):
            self.calls.append((argv, kw.get('input_text')))
            return g.Result(0, text)
    return Runner([])
