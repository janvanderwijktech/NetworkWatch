"""Hostacties via vaste argumentlijsten: nooit shell=True of netwerkdata als code."""
import ipaddress
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys

ACTIONS = {
    21: ('FTP openen in terminal', 'ftp'),
    22: ('SSH-sessie starten', 'ssh'),
    23: ('Telnet-sessie starten', 'telnet'),
    80: ('HTTP openen in browser', 'http'),
    443: ('HTTPS openen in browser', 'https'),
    445: ('SMB-shares openen', 'smb'),
    5900: ('VNC-sessie starten', 'vnc'),
    8080: ('HTTP openen in browser', 'http'),
    8443: ('HTTPS openen in browser', 'https'),
}
TERMINALS = (
    ('kitty', ()), ('alacritty', ('-e',)), ('foot', ('--',)),
    ('gnome-terminal', ('--',)), ('konsole', ('-e',)),
    ('xfce4-terminal', ('--execute',)), ('xterm', ('-e',)),
    ('x-terminal-emulator', ('-e',)),
)


def available_actions(host):
    """Alleen bevestigde open TCP-poorten, gesorteerd en ontdubbeld."""
    ports = {r['port'] for r in json.loads(host.get('port_results') or '[]')
             if r.get('protocol') == 'tcp' and r.get('state') == 'open'}
    return [(port, *ACTIONS[port]) for port in sorted(ports.intersection(ACTIONS))]


def require(program):
    path = shutil.which(program)
    if path is None:
        raise ValueError(f'Het programma {program} ontbreekt. Installeer deze client en probeer opnieuw.')
    return path


def terminal_command(client):
    # Een kleine Python-runner houdt de terminal open na afloop/fouten.
    command = [sys.executable, str(Path(__file__).resolve()), *client]
    for program, options in TERMINALS:
        binary = shutil.which(program)
        if binary:
            return [binary, *options, *command]
    raise ValueError('Geen ondersteunde terminal gevonden. Installeer bijvoorbeeld kitty of xterm.')


def action_command(ip, port, kind, username=''):
    ip = str(ipaddress.IPv4Address(ip))
    if port not in ACTIONS or ACTIONS[port][1] != kind:
        raise ValueError('Onbekende combinatie van poort en actie.')
    if kind in ('http', 'https', 'smb'):
        url = f'smb://{ip}/' if kind == 'smb' else f'{kind}://{ip}:{port}/'
        return [require('xdg-open'), url]
    if kind == 'ssh':
        username = username.strip()
        if username and not re.fullmatch(r'[A-Za-z0-9_][A-Za-z0-9_.@\\$-]{0,127}', username):
            raise ValueError('Ongeldige SSH-gebruikersnaam. Gebruik geen spaties of shelltekens.')
        client = [require('ssh'), '-p', str(port)]
        if username:
            client += ['-l', username]
        client += [ip]
        return terminal_command(client)
    if kind == 'telnet':
        return terminal_command([require('telnet'), ip, str(port)])
    if kind == 'ftp':
        return terminal_command([require('ftp'), ip, str(port)])
    if kind == 'vnc':
        return [require('vncviewer'), f'{ip}::{port}']
    raise ValueError('Onbekende actie.')


def launch_action(ip, port, kind, username=''):
    return subprocess.Popen(action_command(ip, port, kind, username),
                            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL, start_new_session=True)


def run_in_terminal(argv):
    """Terminal blijft zichtbaar, ook bij een ontbrekende/bereikbaarheidsfout."""
    try:
        code = subprocess.call(argv)
        print(f'\nSessie beëindigd (exitcode {code}).')
    except OSError as exc:
        print(f'Client kon niet worden gestart: {exc}')
    try:
        input('Druk op Enter om dit venster te sluiten…')
    except (EOFError, KeyboardInterrupt):
        pass


if __name__ == '__main__' and len(sys.argv) > 1:
    run_in_terminal(sys.argv[1:])
