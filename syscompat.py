# SPDX-License-Identifier: GPL-3.0-only
"""Windows-Bausteine fuer Quite Safe Grab (das Programm startet nur unter Windows; die Pi-Fassung
liegt in pi-grab-master): Dateisperren, Prozessbaum beenden, Verknuepfungs-/Reparse-Point-Erkennung,
atomares Veroeffentlichen ohne Ueberschreiben und reservierte Windows-Dateinamen.
"""
import ctypes
from ctypes import wintypes
import errno
import msvcrt
import os
from pathlib import Path
import subprocess
import sys
import time

FILE_ATTRIBUTE_REPARSE_POINT = 0x400
CREATE_NO_WINDOW = 0x08000000
SYSTEM32 = Path(os.environ.get('SystemRoot', r'C:\Windows')) / 'System32'

# --- reservierte Windows-Namen (gelten auf jedem System, damit Ergebnisse portabel bleiben)
RESERVED_NAMES = {'CON', 'PRN', 'AUX', 'NUL', 'CONIN$', 'CONOUT$'}
RESERVED_NAMES |= {f'COM{i}' for i in range(1, 10)} | {f'LPT{i}' for i in range(1, 10)}
RESERVED_NAMES |= {'COM\u00b9', 'COM\u00b2', 'COM\u00b3', 'LPT\u00b9', 'LPT\u00b2', 'LPT\u00b3'}


def safe_basename(name):
    """Stellt einem reservierten Geraetenamen (auch 'CON.txt') einen Unterstrich voran."""
    stem = name.split('.', 1)[0].rstrip(' ').upper()
    return '_' + name if stem in RESERVED_NAMES else name


def real_exe():
    """Pfad des tatsaechlich laufenden Programms (Firewallregeln gelten fuer dieses Image).

    Mit der eigenen Laufzeit aus setup.ps1 ist das python/python.exe. Laeuft Quite Safe Grab doch einmal
    in einem venv, startet dessen Starter das Basis-python.exe als Kindprozess; sys.executable zeigt
    dann auf den Starter, die Firewall sieht aber das Basis-python.exe - deshalb hier das echte Image.
    """
    buffer = ctypes.create_unicode_buffer(32768)
    if ctypes.windll.kernel32.GetModuleFileNameW(None, buffer, len(buffer)):
        return buffer.value
    return sys.executable


# --- Verknuepfungen
def is_reparse_or_link(path):
    """Symlink, Junction oder anderer Reparse-Point (lstat, folgt nichts)."""
    try:
        st = os.lstat(path)
    except OSError:
        return False
    return bool(getattr(st, 'st_file_attributes', 0) & FILE_ATTRIBUTE_REPARSE_POINT) or os.path.islink(path)


# --- Dateisperre
def locked_file(path):
    """Exklusive, nicht blockierende Sperre auf eine Datei; Konflikt -> BlockingIOError."""
    if os.path.islink(path):
        raise OSError(errno.ELOOP, 'Verknuepfung als Sperrdatei')
    fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_BINARY, 0o600)
    try:
        msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
    except OSError as exc:
        os.close(fd)
        raise BlockingIOError(str(exc)) from exc
    except BaseException:
        os.close(fd)
        raise
    return os.fdopen(fd, 'r+b', buffering=0)


# --- Veroeffentlichen ohne Ueberschreiben
def move_noreplace(source, target, retries=10):
    """Verschiebt source nach target, scheitert mit FileExistsError statt zu ueberschreiben.

    os.rename ueberschreibt unter Windows nie und ist auf NTFS atomar. Virenscanner
    halten frisch geschriebene Dateien kurz fest (PermissionError): wenige Wiederholungen.
    Ein Verzeichnis-fsync danach ist unter Windows nicht moeglich und nicht noetig (NTFS-Journal).
    """
    for attempt in range(retries):
        try:
            os.rename(source, target)
            return
        except PermissionError:
            if Path(target).exists():
                raise FileExistsError(errno.EEXIST, 'Ziel existiert', str(target))
            if attempt == retries - 1:
                raise
            time.sleep(0.3)


# --- Prozessbaum
class _IoCounters(ctypes.Structure):
    _fields_ = [(n, ctypes.c_ulonglong) for n in (
        'ReadOperationCount', 'WriteOperationCount', 'OtherOperationCount',
        'ReadTransferCount', 'WriteTransferCount', 'OtherTransferCount')]


class _BasicLimits(ctypes.Structure):
    _fields_ = [('PerProcessUserTimeLimit', ctypes.c_int64), ('PerJobUserTimeLimit', ctypes.c_int64),
                ('LimitFlags', wintypes.DWORD), ('MinimumWorkingSetSize', ctypes.c_size_t),
                ('MaximumWorkingSetSize', ctypes.c_size_t), ('ActiveProcessLimit', wintypes.DWORD),
                ('Affinity', ctypes.c_size_t), ('PriorityClass', wintypes.DWORD),
                ('SchedulingClass', wintypes.DWORD)]


class _ExtendedLimits(ctypes.Structure):
    _fields_ = [('BasicLimitInformation', _BasicLimits), ('IoInfo', _IoCounters),
                ('ProcessMemoryLimit', ctypes.c_size_t), ('JobMemoryLimit', ctypes.c_size_t),
                ('PeakProcessMemoryUsed', ctypes.c_size_t), ('PeakJobMemoryUsed', ctypes.c_size_t)]


_k32 = ctypes.WinDLL('kernel32', use_last_error=True)
_k32.CreateJobObjectW.restype = wintypes.HANDLE
_k32.CreateJobObjectW.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR]
_k32.SetInformationJobObject.restype = wintypes.BOOL
_k32.SetInformationJobObject.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD]
_k32.AssignProcessToJobObject.restype = wintypes.BOOL
_k32.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
_k32.TerminateJobObject.restype = wintypes.BOOL
_k32.TerminateJobObject.argtypes = [wintypes.HANDLE, wintypes.UINT]
_k32.CloseHandle.restype = wintypes.BOOL
_k32.CloseHandle.argtypes = [wintypes.HANDLE]
_JOB_OBJECT_EXTENDED_LIMIT_INFORMATION = 9
_JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x2000


def popen_kwargs():
    """Zusatzargumente fuer subprocess.Popen: kein Konsolenfenster."""
    return {'creationflags': CREATE_NO_WINDOW}


class ProcessTree:
    """Beendet einen Prozess samt aller Nachkommen.

    Job-Objekt mit KILL_ON_JOB_CLOSE; scheitert die Einrichtung, bleibt
    taskkill /T als Ausweichweg.
    """

    def __init__(self, proc):
        self.proc = proc
        self.job = None
        try:
            job = _k32.CreateJobObjectW(None, None)
            if not job:
                raise OSError('CreateJobObject')
            info = _ExtendedLimits()
            info.BasicLimitInformation.LimitFlags = _JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
            if not _k32.SetInformationJobObject(job, _JOB_OBJECT_EXTENDED_LIMIT_INFORMATION,
                                                ctypes.byref(info), ctypes.sizeof(info)):
                raise OSError('SetInformationJobObject')
            if not _k32.AssignProcessToJobObject(job, int(proc._handle)):
                raise OSError('AssignProcessToJobObject')
            self.job = job
        except (OSError, AttributeError):
            if 'job' in locals() and job:
                _k32.CloseHandle(job)
            self.job = None

    def kill(self):
        if self.job:
            _k32.TerminateJobObject(self.job, 1)
        else:
            try:
                subprocess.run([str(SYSTEM32 / 'taskkill.exe'), '/T', '/F', '/PID', str(self.proc.pid)],
                               stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                               timeout=15, creationflags=CREATE_NO_WINDOW)
            except (OSError, subprocess.SubprocessError):
                pass

    def close(self):
        """Beendet Nachkommen, die den Hauptprozess ueberlebt haben, und gibt das Handle frei."""
        self.kill()
        if self.job:
            _k32.CloseHandle(self.job)
            self.job = None


def child_env(workdir=None):
    """Enge Umgebung fuer Kindprozesse: keine Proxy-/Python-/Konfigurationsvariablen."""
    keep = ('SYSTEMROOT', 'SYSTEMDRIVE', 'WINDIR', 'COMSPEC', 'PATHEXT', 'TEMP', 'TMP', 'NUMBER_OF_PROCESSORS',
            'PROCESSOR_ARCHITECTURE')
    env = {k.upper(): v for k, v in os.environ.items() if k.upper() in keep}
    root = env.get('SYSTEMROOT', r'C:\Windows')
    env['PATH'] = os.path.join(root, 'System32') + os.pathsep + root
    env.update(YTDLP_NO_PLUGINS='1', PYTHONNOUSERSITE='1', PYTHONDONTWRITEBYTECODE='1',
               PYTHONUTF8='1', PYTHONIOENCODING='utf-8')
    if workdir:
        workdir = Path(workdir)
        env.update(TMPDIR=str(workdir), TMP=str(workdir), TEMP=str(workdir))
    return env
