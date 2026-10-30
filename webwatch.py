#!/usr/bin/env python3
"""NetworkWatch Web: lokale browserbediening, met dezelfde Linux-scanner/opslag."""
from __future__ import annotations

import argparse
import copy
import csv
import fcntl
import hmac
from http.cookies import CookieError, SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import io
import ipaddress
import json
import math
import os
from pathlib import Path
import secrets
import signal
import threading
import time
import tempfile
import urllib.parse
import uuid

from core import (Dispatcher, Store, default_config, interfaces, mac_address, now,
                  post, save_config, scan, scope, validate_config, validate_trigger)
from host_actions import available_actions, launch_action
from ports import decode_results, port_summary

ASSETS = Path(__file__).resolve().parent / 'web'
MAX_BODY = 128 * 1024


class Conflict(ValueError):
    pass


def checked_config(value):
    """De browser mag uitsluitend de bestaande instellingen wijzigen."""
    defaults = default_config()
    if not isinstance(value, dict) or set(value) != set(defaults):
        raise ValueError('Onvolledige of onbekende instellingen. Open het venster opnieuw.')
    value = copy.deepcopy(value)
    for key in ('profile', 'interface', 'network', 'guard_host'):
        if not isinstance(value[key], str) or len(value[key]) > 300:
            raise ValueError(f'Ongeldige waarde voor {key}.')
        value[key] = value[key].strip()
    for key in ('interval', 'misses'):
        if type(value[key]) is not int:
            raise ValueError(f'{key} moet een geheel getal zijn.')
    for key in ('gateway_guard', 'dns', 'sound', 'port_scan', 'udp_scan', 'os_scan'):
        if type(value[key]) is not bool:
            raise ValueError(f'{key} moet aan of uit zijn.')
    if type(value['port_timeout']) not in (int, float) or not math.isfinite(value['port_timeout']):
        raise ValueError('Ongeldige poorttimeout.')
    for key in ('unknown', 'offline'):
        t = value[key]
        if not isinstance(t, dict) or set(t) != {'enabled', 'url', 'mode', 'headers', 'body'}:
            raise ValueError('Ongeldige triggerinstellingen.')
        if type(t['enabled']) is not bool or not isinstance(t['url'], str):
            raise ValueError('Ongeldige triggerinstellingen.')
        validate_trigger(t)
    validate_config(value)
    return value


def demo_scan(_config):
    rows = []
    for suffix, name, vendor, ports, os_guess in (
        (1, 'router.lan', 'MikroTik', [22, 80, 443], 'Onbekend'),
        (25, 'docker.lan', 'Intel', [22, 443, 8080], 'Linux (Debian)'),
        (50, 'laptop.lan', 'HP', [22], 'Linux'),
        (110, 'telefoon.lan', 'Privé MAC-adres', [], 'Onbekend'),
    ):
        rows.append({'ip': f'192.0.2.{suffix}', 'mac': f'02:00:00:00:00:{suffix:02x}',
                     'hostname': name, 'vendor': vendor, 'os_guess': os_guess,
                     'os_evidence': 'Voorbeeldgegevens; er is geen apparaat benaderd.',
                     'os_checked': now(), 'port_checked': now(),
                     'port_results': json.dumps([{'port': p, 'protocol': 'tcp', 'state': 'open',
                                                  'reason': 'Voorbeeldmeting'} for p in ports])})
    return rows


class Monitor:
    """Eén scanner; SQLite-verbindingen horen steeds bij de aanroepende thread."""

    def __init__(self, folder, *, demo=False, local_actions=False, scanner=None):
        self.folder = Path(folder)
        self.folder.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.config_path = self.folder / 'config.json'
        self.db_path = self.folder / 'devices.sqlite3'
        self.config = default_config()
        if self.config_path.exists():
            self.config.update(json.loads(self.config_path.read_text()))
        self.demo = demo
        self.local_actions = local_actions and not demo
        self.scanner = scanner or (demo_scan if demo else scan)
        self.mutex = threading.RLock()
        self.stopped = threading.Event()
        self.busy = False
        self.paused = False
        self.next_scan = None
        self.revision = uuid.uuid4().hex
        self.scan_serial = 0
        self.alerts = []
        self.status = 'Open Instellingen & triggers en kies je netwerk.'
        self.worker = None
        self.scheduler = None
        self.dispatcher = None
        store = Store(self.db_path)
        try:
            if demo:
                self.config.update(profile='Voorbeeldnetwerk', interface='demo0', network='192.0.2.0/24')
                store.apply_scan(self.config, demo_scan(self.config))
                store.edit(scope(self.config), '02:00:00:00:00:01', 'Router', True, True)
                store.edit(scope(self.config), '02:00:00:00:00:19', 'Docker-server', True, True)
                self.status = 'Demomodus · voorbeeldgegevens, geen echte netwerkscans of POST-verzoeken.'
        finally:
            store.close()

    def start(self):
        if not self.demo:
            self.dispatcher = Dispatcher(self.db_path, self.stopped)
            self.dispatcher.start()
        self.scheduler = threading.Thread(target=self._schedule, daemon=True)
        self.scheduler.start()
        try:
            validate_config(self.config)
        except (ValueError, KeyError, TypeError):
            return
        if not self.demo:
            self.request_scan()

    def close(self):
        self.stopped.set()
        for thread in (self.scheduler, self.worker, self.dispatcher):
            if thread:
                thread.join(timeout=12 if thread is self.dispatcher else 2)

    def _schedule(self):
        while not self.stopped.wait(0.5):
            with self.mutex:
                due = (not self.paused and not self.busy and self.next_scan is not None
                       and time.monotonic() >= self.next_scan)
                if due:
                    try:
                        self.request_scan()
                    except (ValueError, Conflict) as exc:
                        self.next_scan = None
                        self.status = str(exc)

    def request_scan(self):
        with self.mutex:
            if self.busy:
                raise Conflict('Er loopt al een scan.')
            if self.stopped.is_set():
                raise Conflict('De server wordt afgesloten.')
            validate_config(self.config)
            self.busy = True
            self.next_scan = None
            self.status = 'Netwerkscan bezig: apparaten, hostnamen, poorten en OS-indicaties…'
            c = copy.deepcopy(self.config)
            self.worker = threading.Thread(target=self._scan, args=(c,), daemon=True)
            self.worker.start()

    def _scan(self, config):
        alerts = []
        try:
            rows = self.scanner(config)
            with self.mutex:
                if self.stopped.is_set():
                    return
                store = Store(self.db_path)
                try:
                    alerts = store.apply_scan(config, rows)
                finally:
                    store.close()
                self.status = f'{now()} · Scan klaar: {len(rows)} apparaten; {len(alerts)} meldingen.'
        except Exception as exc:
            with self.mutex:
                self.status = f'Scan mislukt — geen statuswijzigingen: {str(exc)[:800]}'
        finally:
            with self.mutex:
                self.busy = False
                self.scan_serial += 1
                self.alerts = alerts
                self.next_scan = (time.monotonic() + config['interval']
                                  if config['interval'] and not self.stopped.is_set() else None)

    def settings(self):
        with self.mutex:
            return {'config': copy.deepcopy(self.config), 'revision': self.revision}

    def set_settings(self, data):
        config = checked_config(data.get('config'))
        with self.mutex:
            if self.busy:
                raise Conflict('Wacht tot de scan klaar is voordat je instellingen opslaat.')
            if data.get('revision') != self.revision:
                raise Conflict('Instellingen zijn elders gewijzigd. Open het venster opnieuw.')
            save_config(self.config_path, config)
            self.config = config
            self.revision = uuid.uuid4().hex
            self.next_scan = time.monotonic() + config['interval'] if config['interval'] else None
            self.status = 'Instellingen opgeslagen. Klik op Scan nu.'

    def state(self):
        with self.mutex:
            store = Store(self.db_path)
            try:
                hosts = store.hosts(scope(self.config))
                events = [dict(r) for r in store.db.execute('''SELECT e.id,e.time,e.kind,e.message,
                    o.status AS http_status,o.result,o.attempts FROM events e
                    LEFT JOIN outbox o ON e.id=o.id WHERE e.scope=?
                    ORDER BY e.time DESC,e.rowid DESC LIMIT 500''', (scope(self.config),))]
            finally:
                store.close()
            for host in hosts:
                host['id'] = host['mac']
                host['mac'] = mac_address(host)
                host['ports'] = decode_results(host['port_results'])
                host['open_ports'], host['udp_uncertain'] = port_summary(host['port_results'])
                host['actions'] = [{'port': p, 'label': label, 'kind': kind}
                                   for p, label, kind in available_actions(host)]
            return {'hosts': hosts, 'events': events, 'scope': scope(self.config),
                    'profile': self.config['profile'], 'interface': self.config['interface'],
                    'network': self.config['network'], 'scan_mode': self.config.get('scan_mode', 'arp'),
                    'sound': self.config['sound'], 'busy': self.busy, 'paused': self.paused,
                    'next_scan_in': (max(0, math.ceil(self.next_scan - time.monotonic()))
                                     if self.next_scan is not None else None),
                    'status': self.status, 'scan_serial': self.scan_serial, 'alerts': self.alerts,
                    'demo': self.demo, 'local_actions': self.local_actions}

    def edit_host(self, data):
        if not isinstance(data.get('label'), str) or len(data['label']) > 1000:
            raise ValueError('Vul een naam van maximaal 1000 tekens in.')
        if type(data.get('known')) is not bool or type(data.get('monitor')) is not bool:
            raise ValueError('Ongeldige apparaatstatus.')
        if data['monitor'] and not data['known']:
            raise ValueError('Markeer het apparaat eerst als vertrouwd om het te bewaken.')
        with self.mutex:
            if data.get('scope') != scope(self.config):
                raise Conflict('Het netwerkprofiel is gewijzigd. Vernieuw het overzicht.')
            store = Store(self.db_path)
            try:
                if not any(h['mac'] == data.get('id') for h in store.hosts(scope(self.config))):
                    raise ValueError('Apparaat niet gevonden in dit profiel.')
                store.edit(scope(self.config), data['id'], data['label'], data['known'], data['monitor'])
            finally:
                store.close()

    def set_paused(self, value):
        if type(value) is not bool:
            raise ValueError('Ongeldige pauzewaarde.')
        with self.mutex:
            self.paused = value

    def test_trigger(self, data):
        trigger = data.get('trigger')
        if not isinstance(trigger, dict):
            raise ValueError('Ongeldige trigger.')
        validate_trigger(trigger)
        if not trigger.get('url'):
            raise ValueError('Vul eerst een URL in.')
        if self.demo:
            return {'ok': True, 'message': 'Demo: geen POST verstuurd.'}
        with self.mutex:
            config = copy.deepcopy(self.config)
        kind = data.get('kind')
        if kind not in ('unknown', 'offline'):
            raise ValueError('Onbekende trigger.')
        payload = {'event_id': str(uuid.uuid4()), 'event': kind, 'ip': '192.0.2.123',
                   'mac': '', 'device_id': 'ip:192.0.2.123', 'name': 'TEST apparaat',
                   'hostname': 'test-host', 'vendor': 'TEST', 'message': f'TEST: {kind}',
                   'timestamp': now(), 'network': config['network'], 'profile': config['profile']}
        ok, result = post(trigger, payload)
        return {'ok': ok, 'message': ('Geslaagd: ' if ok else 'Mislukt: ') + result}

    def host_action(self, data):
        if not self.local_actions:
            raise ValueError('Serverclients zijn uitgeschakeld. Gebruik een browserlink of kopieer het commando.')
        with self.mutex:
            if data.get('scope') != scope(self.config):
                raise Conflict('Het netwerkprofiel is gewijzigd.')
            store = Store(self.db_path)
            try:
                host = next((h for h in store.hosts(scope(self.config)) if h['mac'] == data.get('id')), None)
            finally:
                store.close()
            if host is None or (data.get('port'), data.get('kind')) not in {
                    (p, k) for p, _, k in available_actions(host)}:
                raise ValueError('Deze actie hoort niet bij een bevestigde open poort.')
            username = data.get('username', '')
            if not isinstance(username, str):
                raise ValueError('Ongeldige gebruikersnaam.')
            process = launch_action(host['ip'], data['port'], data['kind'], username)
            code = process.poll()
            if code is not None and code != 0:
                raise ValueError('De serverclient kon niet worden gestart.')
        return {'message': 'Client gestart op de Linux-computer waarop NetworkWatch draait.'}


def export_csv(state):
    out = io.StringIO(newline='')
    rows = []
    for host in state['hosts']:
        row = {k: v for k, v in host.items() if k not in ('id', 'ports', 'actions')}
        row['device_id'] = host['id']
        rows.append(row)
    fields = list(rows[0]) if rows else ['ip', 'mac', 'device_id', 'label', 'known', 'online']
    writer = csv.DictWriter(out, fieldnames=fields, delimiter=';')
    writer.writeheader()
    for row in rows:
        writer.writerow({k: "'" + v if isinstance(v, str) and v.startswith(
            ('=', '+', '-', '@', '\t', '\r')) else v for k, v in row.items()})
    return out.getvalue().encode('utf-8-sig')


class WebServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, address, monitor, *, token='', allowed_hosts=()):
        super().__init__(address, Handler)
        self.monitor = monitor
        self.token = token
        self.csrf = secrets.token_urlsafe(32)
        self.sessions = {}
        self.session_lock = threading.Lock()
        self.allowed_hosts = {address[0], 'localhost', '127.0.0.1', *allowed_hosts} - {'0.0.0.0'}


class Handler(BaseHTTPRequestHandler):
    server_version = 'NetworkWatchWeb/1.0'

    def setup(self):
        super().setup()
        self.connection.settimeout(15)

    def log_message(self, *_args):
        # Geen URL's, tokens, headers of requestbodies in de accesslog.
        pass

    def respond(self, status, body, content_type='application/json; charset=utf-8', headers=None):
        if isinstance(body, dict):
            body = json.dumps(body, ensure_ascii=False).encode('utf-8')
        self.send_response(status)
        self.send_header('Content-Type', content_type)
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Cache-Control', 'no-store')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('Referrer-Policy', 'no-referrer')
        self.send_header('Content-Security-Policy', "default-src 'self'; script-src 'self'; style-src 'self'; "
                         "img-src 'self' data:; connect-src 'self'; object-src 'none'; "
                         "base-uri 'none'; form-action 'self'; frame-ancestors 'none'")
        for key, value in (headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def valid_host(self):
        try:
            parsed = urllib.parse.urlsplit('http://' + self.headers.get('Host', ''))
            parsed.port  # Laat urllib ook ongeldige poortnotaties afwijzen.
            return (parsed.hostname in self.server.allowed_hosts and not parsed.username and
                    not parsed.password)
        except ValueError:
            return False

    def authenticated(self):
        if not self.server.token:
            return True
        try:
            cookie = SimpleCookie(self.headers.get('Cookie', ''))
            session = cookie['nw_session'].value
        except (CookieError, KeyError, ValueError):
            return False
        with self.server.session_lock:
            expires = self.server.sessions.get(session, 0)
        return expires > time.time()

    def do_GET(self):
        if not self.valid_host() or self.headers.get('Sec-Fetch-Site') == 'cross-site':
            return self.respond(403, {'error': 'Onbekende host of externe website.'})
        path = urllib.parse.urlsplit(self.path).path
        if path == '/api/auth':
            authenticated = self.authenticated()
            return self.respond(200, {'authenticated': authenticated,
                                     'requires_token': bool(self.server.token),
                                     'csrf': self.server.csrf if authenticated else None})
        if path.startswith('/api/') and not self.authenticated():
            return self.respond(401, {'error': 'Meld je aan met de toegangscode.'})
        monitor = self.server.monitor
        try:
            if path == '/api/state':
                return self.respond(200, monitor.state())
            if path == '/api/settings':
                return self.respond(200, monitor.settings())
            if path == '/api/interfaces':
                return self.respond(200, {'interfaces': [] if monitor.demo else interfaces()})
            if path == '/api/export':
                return self.respond(200, export_csv(monitor.state()), 'text/csv; charset=utf-8',
                                    {'Content-Disposition': 'attachment; filename="networkwatch-apparaten.csv"'})
            assets = {'/': ('index.html', 'text/html; charset=utf-8'),
                      '/app.js': ('app.js', 'text/javascript; charset=utf-8'),
                      '/style.css': ('style.css', 'text/css; charset=utf-8')}
            if path in assets:
                filename, mime = assets[path]
                return self.respond(200, (ASSETS / filename).read_bytes(), mime)
            self.respond(404, {'error': 'Niet gevonden.'})
        except Exception:
            self.respond(500, {'error': 'Ophalen mislukt. Controleer de Linux-server en netwerkhulpmiddelen.'})

    def do_POST(self):
        origin = self.headers.get('Origin')
        parsed_origin = urllib.parse.urlsplit(origin or '')
        if (not self.valid_host() or self.headers.get('Sec-Fetch-Site') == 'cross-site' or
                (origin and (parsed_origin.scheme not in ('http', 'https') or
                             parsed_origin.netloc != self.headers.get('Host')))):
            return self.respond(403, {'error': 'Externe websites mogen geen opdrachten geven.'})
        path = urllib.parse.urlsplit(self.path).path
        if path != '/api/login' and not self.authenticated():
            return self.respond(401, {'error': 'Meld je opnieuw aan.'})
        if path != '/api/login' and not hmac.compare_digest(
                self.headers.get('X-CSRF-Token', '').encode('utf-8'), self.server.csrf.encode('ascii')):
            return self.respond(403, {'error': 'Ongeldig verzoek. Vernieuw de pagina.'})
        try:
            length = int(self.headers.get('Content-Length', '0'))
            if not 0 < length <= MAX_BODY or self.headers.get_content_type() != 'application/json':
                return self.respond(400, {'error': 'Verwacht een begrensd JSON-verzoek.'})
            data = json.loads(self.rfile.read(length))
            if not isinstance(data, dict):
                raise ValueError('Verwacht een JSON-object.')
            if path == '/api/login':
                supplied = data.get('token', '')
                if not isinstance(supplied, str) or not hmac.compare_digest(
                        supplied.encode('utf-8'), self.server.token.encode('utf-8')):
                    return self.respond(401, {'error': 'Onjuiste toegangscode.'})
                session = secrets.token_urlsafe(32)
                with self.server.session_lock:
                    self.server.sessions = {s: e for s, e in self.server.sessions.items() if e > time.time()}
                    if len(self.server.sessions) >= 128:
                        return self.respond(429, {'error': 'Te veel actieve sessies.'})
                    self.server.sessions[session] = time.time() + 8 * 3600
                return self.respond(200, {'csrf': self.server.csrf}, headers={
                    'Set-Cookie': f'nw_session={session}; HttpOnly; SameSite=Strict; Path=/; Max-Age=28800'})
            if path == '/api/logout':
                cookie = SimpleCookie(self.headers.get('Cookie', ''))
                if 'nw_session' in cookie:
                    with self.server.session_lock:
                        self.server.sessions.pop(cookie['nw_session'].value, None)
                return self.respond(200, {'ok': True}, headers={
                    'Set-Cookie': 'nw_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0'})
            monitor = self.server.monitor
            if path == '/api/scan':
                monitor.request_scan()
                return self.respond(202, {'ok': True})
            if path == '/api/pause':
                monitor.set_paused(data.get('paused'))
            elif path == '/api/settings':
                monitor.set_settings(data)
            elif path == '/api/host':
                monitor.edit_host(data)
            elif path == '/api/trigger-test':
                return self.respond(200, monitor.test_trigger(data))
            elif path == '/api/action':
                return self.respond(200, monitor.host_action(data))
            else:
                return self.respond(404, {'error': 'Niet gevonden.'})
            self.respond(200, {'ok': True})
        except Conflict as exc:
            self.respond(409, {'error': str(exc)})
        except (ValueError, KeyError, TypeError) as exc:
            self.respond(400, {'error': str(exc)[:300]})
        except Exception:
            self.respond(500, {'error': 'Opdracht mislukt. Controleer de Linux-server.'})


def main():
    parser = argparse.ArgumentParser(description='NetworkWatch bedienen in je browser.')
    parser.add_argument('--host', default='127.0.0.1', help='IPv4-listenadres, standaard alleen lokaal.')
    parser.add_argument('--port', type=int, default=8765)
    parser.add_argument('--allowed-host', action='append', default=[], help='Extra toegestane hostnaam bij LAN/proxy.')
    parser.add_argument('--data-dir', type=Path, help='Standaard dezelfde map als de desktopapp.')
    parser.add_argument('--allow-local-actions', action='store_true', help='Sta desktopclients op de server toe.')
    parser.add_argument('--demo', action='store_true', help='Tijdelijke voorbeeldgegevens, geen netwerkscans of POSTs.')
    args = parser.parse_args()
    token = os.environ.get('NETWORKWATCH_WEB_TOKEN', '')
    try:
        address = ipaddress.IPv4Address(args.host)
    except ValueError:
        parser.error('--host moet een IPv4-adres zijn.')
    if not address.is_loopback and len(token) < 32:
        parser.error('Voor LAN-toegang: stel NETWORKWATCH_WEB_TOKEN in op minimaal 32 tekens.')
    if args.host == '0.0.0.0' and not args.allowed_host:
        parser.error('Geef bij 0.0.0.0 ook --allowed-host met het server-IP of de DNS-naam op.')
    os.umask(0o077)
    demo_dir = tempfile.TemporaryDirectory(prefix='networkwatch-demo-') if args.demo else None
    folder = (Path(demo_dir.name) if demo_dir else args.data_dir or
              Path(os.environ.get('XDG_DATA_HOME', str(Path.home() / '.local/share'))) / 'netwerkwacht')
    folder.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(folder, 0o700)
    lock = (folder / 'app.lock').open('w')
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        parser.exit(1, 'NetworkWatch draait al met deze gegevensmap. Sluit die instantie eerst af.\n')
    monitor = Monitor(folder, demo=args.demo, local_actions=args.allow_local_actions)
    server = None
    try:
        server = WebServer((args.host, args.port), monitor, token=token, allowed_hosts=args.allowed_host)
        monitor.start()
        print(f'NetworkWatch Web: http://{args.host}:{server.server_port}', flush=True)
        print('Ctrl+C stopt de server en de bewaking.', flush=True)
        def stop_server(_signum, _frame):
            threading.Thread(target=server.shutdown, daemon=True).start()
        signal.signal(signal.SIGTERM, stop_server)
        server.serve_forever(poll_interval=0.3)
    except KeyboardInterrupt:
        pass
    finally:
        if server:
            server.server_close()
        monitor.close()
        lock.close()
        if demo_dir:
            demo_dir.cleanup()


if __name__ == '__main__':
    main()
