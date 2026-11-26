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
import ctypes
import subprocess
import sys
from pathlib import Path

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


def status(config):
    state, vpn, ips = query(config)
    print('VPN-Adapter: ' + (', '.join(a['name'] for a in vpn) or 'KEINER aktiv'))
    print('VPN-Adresse(n): ' + (', '.join(ips) or '-'))
    programs = g.guard_programs()
    for program in programs:
        print('  Programm: ' + program)
    if not ips:
        print('ERGEBNIS: nicht pruefbar ohne aktive VPN-Adresse.')
        return 2
    problem = winguard.check_rules(state, programs, ips)
    print('ERGEBNIS: ' + ('Netzsperre vollstaendig und passend.' if problem is None else f'{problem[0]}: {problem[1]}'))
    return 0 if problem is None else 2


def apply(config, elevated):
    if not is_admin():
        return relaunch('apply')
    state, vpn, ips = query(config)
    if not ips:
        print('Keine aktive VPN-Adresse. Proton verbinden und erneut ausfuehren.')
        return finish(elevated, 2)
    script = winguard.build_apply_script(g.guard_programs(), ips)
    code, out, err = powershell(script)
    if code != 0:
        print('Regeln konnten nicht angelegt werden: ' + g.safe_text(err.strip()[:500]))
        return finish(elevated, 2)
    print('Regeln angelegt fuer VPN-Adresse(n): ' + ', '.join(ips))
    return finish(elevated, status(config))


def remove(elevated):
    if not is_admin():
        return relaunch('remove')
    code, out, err = powershell(winguard.build_remove_script())
    print('QuiteSafeGrab-Regeln entfernt.' if code == 0 else 'Entfernen fehlgeschlagen: ' + g.safe_text(err.strip()[:500]))
    return finish(elevated, 0 if code == 0 else 2)


def finish(elevated, code):
    if elevated:
        input('Enter zum Schliessen ...')
    return code


def relaunch(action):
    """Startet dieses Programm erhoeht neu (UAC-Abfrage) und wartet darauf."""
    params = subprocess.list2cmdline(['-I', str(Path(__file__).resolve()), action, '--elevated'])
    script = (f"Start-Process -FilePath {winguard.ps_quote(sys.executable)} "
              f"-ArgumentList {winguard.ps_quote(params)} -Verb RunAs -Wait")
    code, out, err = powershell(script, 600)
    if code != 0:
        print('Erhoehter Start abgebrochen oder fehlgeschlagen.')
        return 2
    print('Pruefe Ergebnis ...')
    config = g.load_config(Path(g.__file__).with_name('config.toml'))
    return status(config) if action == 'apply' else 0


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
            return apply(config, args.elevated)
        return remove(args.elevated)
    except g.Failure as exc:
        g.error(exc)
        return exc.code
    except SystemExit as exc:
        print(exc, file=sys.stderr)
        return 2


if __name__ == '__main__':
    sys.exit(main())
