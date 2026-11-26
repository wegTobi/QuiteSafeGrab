# SPDX-License-Identifier: GPL-3.0-only
"""Verwaltung der QuiteSafeGrab-Netzsperre (Windows-Firewallregeln).

  qsgrab.cmd firewall status   zeigt, ob die Regeln zur aktuellen VPN-Adresse passen (kein Admin noetig)
  qsgrab.cmd firewall apply    legt die Regeln an/erneuert sie (fragt per UAC nach Administratorrechten)
  qsgrab.cmd firewall remove   entfernt alle QuiteSafeGrab-Regeln (Administrator)

Die VPN muss fuer 'apply' verbunden sein: ihre IPv4-Adresse ist die einzige erlaubte Quelladresse.
Aendert sich diese Adresse (anderes Protokoll/Konto), 'apply' erneut ausfuehren.
Es werden ausschliesslich Regeln mit dem Namen QuiteSafeGrab-* angelegt oder entfernt.
"""
import argparse
import contextlib
import ctypes
import io
import time
import subprocess
import sys
from pathlib import Path

if '--elevated' in sys.argv:
    # Sofort sichtbar, bevor die uebrigen Module laden: der Nutzer soll wissen, was dieses Fenster tut.
    with contextlib.suppress(Exception):
        ctypes.windll.kernel32.SetConsoleTitleW('Quite Safe Grab - Netzsperre (Administrator)')
    print('\n  Quite Safe Grab - Netzsperre wird eingerichtet\n'
          '  ==============================================\n\n'
          '  Bitte warten und nichts druecken. Das dauert meist 5 bis 20 Sekunden.\n'
          '  Dieses Fenster meldet sich am Ende mit FERTIG oder FEHLER.\n', flush=True)

sys.path.insert(0, str(Path(__file__).resolve().parent))
import grab as g
import winguard


def is_admin():
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except (AttributeError, OSError):
        return False


def powershell(script, timeout=120):
    r = subprocess.run([g.POWERSHELL] + winguard.powershell_args(script), capture_output=True, timeout=timeout,
                       stdin=subprocess.DEVNULL, creationflags=0x08000000)
    return r.returncode, r.stdout.decode('utf-8', errors='replace'), r.stderr.decode('utf-8', errors='replace')


def query(config):
    code, out, err = powershell(winguard.STATE_SCRIPT, 60)
    if code != 0:
        raise SystemExit('Abfrage fehlgeschlagen: ' + g.safe_text(err.strip()[:300]))
    try:
        state = winguard.parse_state(out)
    except ValueError as exc:
        raise SystemExit(str(exc))
    vpn = winguard.vpn_adapters(state, config['vpn_adapter_patterns'])
    return state, vpn, winguard.vpn_ipv4(vpn)


STATUS_OK, STATUS_PROBLEM, STATUS_NO_VPN = 0, 2, 3


def status(config):
    """0 = Netzsperre passt, 2 = fehlt/passt nicht, 3 = kein VPN verbunden (nicht pruefbar)."""
    state, vpn, ips = query(config)
    print('VPN-Adapter: ' + (', '.join(a['name'] for a in vpn) or 'KEINER aktiv'))
    print('VPN-Adresse(n): ' + (', '.join(ips) or '-'))
    programs = g.guard_programs()
    for program in programs:
        print('  Programm: ' + program)
    if not ips:
        print('ERGEBNIS: nicht pruefbar ohne aktive VPN-Adresse.')
        return STATUS_NO_VPN
    problem = winguard.check_rules(state, programs, ips)
    print('ERGEBNIS: ' + ('Netzsperre vollstaendig und passend.' if problem is None else f'{problem[0]}: {problem[1]}'))
    return STATUS_OK if problem is None else STATUS_PROBLEM


def step(text):
    print(f'  ... {text}', flush=True)


def apply(config, config_path, elevated):
    if not is_admin():
        return relaunch('apply', config_path)
    step('Lese Netzwerkadapter und vorhandene Regeln (einige Sekunden)')
    state, vpn, ips = query(config)
    if not ips:
        print('\n  FEHLER: Kein verbundenes VPN gefunden. Bitte VPN verbinden und die Einrichtung erneut starten.')
        return finish(elevated, 2)
    step('Lege die Firewall-Regeln an')
    script = winguard.build_apply_script(g.guard_programs(), ips)
    code, out, err = powershell(script)
    if code != 0:
        print('\n  FEHLER: Regeln konnten nicht angelegt werden: ' + g.safe_text(err.strip()[:500]))
        return finish(elevated, 2)
    step('Pruefe das Ergebnis')
    if elevated:
        with contextlib.redirect_stdout(io.StringIO()):
            result = status(config)
        print('\n  FERTIG: Netzsperre angelegt und geprueft.' if result == 0 else '\n  FEHLER: Netzsperre angelegt, Pruefung aber nicht bestanden.')
    else:
        print('Regeln angelegt fuer VPN-Adresse(n): ' + ', '.join(ips))
        result = status(config)
    return finish(elevated, result)


def remove(config_path, elevated):
    if not is_admin():
        return relaunch('remove', config_path)
    step('Entferne die Firewall-Regeln')
    code, out, err = powershell(winguard.build_remove_script())
    print('\n  FERTIG: Regeln entfernt.' if code == 0 else '\n  FEHLER: Entfernen fehlgeschlagen: ' + g.safe_text(err.strip()[:500]))
    return finish(elevated, 0 if code == 0 else 2)


def drain_keys():
    """Vorher (zu frueh) gedrueckte Tasten verwerfen."""
    try:
        import msvcrt
        while msvcrt.kbhit():
            msvcrt.getwch()
    except (ImportError, OSError):
        pass


def finish(elevated, code, seconds=8):
    """Im Administrator-Fenster: Erfolg schliesst nach Countdown selbst, Fehler wartet auf Enter."""
    if not elevated:
        return code
    drain_keys()
    if code != 0:
        input('\n  Bitte die Meldung oben lesen, dann Enter druecken, um das Fenster zu schliessen ...')
        return code
    try:
        import msvcrt
    except ImportError:
        return code
    for left in range(seconds, 0, -1):
        print(f'\r  Dieses Fenster schliesst sich in {left} Sekunden von selbst (oder Enter druecken). ', end='', flush=True)
        deadline = time.monotonic() + 1
        while time.monotonic() < deadline:
            if msvcrt.kbhit() and msvcrt.getwch() in '\r\n':
                return code
            time.sleep(0.05)
    return code


def relaunch_script(action, config_path):
    params = subprocess.list2cmdline(['-I', str(Path(__file__).resolve()), action, '--config', str(config_path), '--elevated'])
    return (f"Start-Process -FilePath {winguard.ps_quote(sys.executable)} "
            f"-ArgumentList {winguard.ps_quote(params)} -Verb RunAs -Wait")


def relaunch(action, config_path):
    """Startet dieses Programm erhoeht neu (UAC-Abfrage), mit derselben Konfiguration, und wartet darauf."""
    code, out, err = powershell(relaunch_script(action, config_path), 1800)
    if code != 0:
        print('Erhoehter Start abgebrochen oder fehlgeschlagen.')
        return 2
    print('Pruefe Ergebnis ...')
    return status(g.load_config(config_path)) if action == 'apply' else 0


def main(argv=None):
    parser = argparse.ArgumentParser(description='QuiteSafeGrab-Netzsperre (Windows-Firewall) verwalten.')
    parser.add_argument('action', choices=('status', 'apply', 'remove'))
    parser.add_argument('--config', default=str(Path(g.__file__).with_name('config.toml')))
    parser.add_argument('--elevated', action='store_true', help=argparse.SUPPRESS)
    args = parser.parse_args(argv)
    if sys.platform != 'win32':
        print('Nur unter Windows.', file=sys.stderr)
        return 1
    try:
        config = g.load_config(args.config)
        if args.action == 'status':
            return status(config)
        if args.action == 'apply':
            return apply(config, args.config, args.elevated)
        return remove(args.config, args.elevated)
    except g.Failure as exc:
        g.error(exc)
        return finish(args.elevated, exc.code)
    except SystemExit as exc:
        print(exc, file=sys.stderr)
        return finish(args.elevated, 2)


if __name__ == '__main__':
    sys.exit(main())
