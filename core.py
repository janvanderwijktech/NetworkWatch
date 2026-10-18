"""NetwerkWacht: Linux ARP discovery, durable state and HTTP notifications."""
from __future__ import annotations
import concurrent.futures
import datetime as dt
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import sqlite3
import subprocess
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from ports import scan_ports


def now():
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec='seconds')


def default_config():
    trigger = {'enabled': False, 'url': '', 'mode': 'json', 'headers': {},
               'body': {'event': '{event}', 'ip': '{ip}', 'mac': '{mac}',
                        'name': '{name}', 'message': '{message}', 'event_id': '{event_id}'}}
    return {'profile': 'Mijn netwerk', 'interface': '', 'network': '', 'interval': 300,
            'misses': 3, 'gateway_guard': True, 'dns': True, 'sound': True,
            'port_scan': True, 'udp_scan': True, 'port_timeout': 0.8,
            'unknown': dict(trigger), 'offline': dict(trigger)}


def run(args, timeout=10):
    p = subprocess.run(args, capture_output=True, text=True, timeout=timeout,
                       env={**os.environ, 'LC_ALL': 'C'})
    if p.returncode:
        raise RuntimeError((p.stderr.strip() or p.stdout.strip() or 'Opdracht mislukt')[:800])
    return p.stdout


def interfaces():
    result = []
    for link in json.loads(run(['ip', '-j', 'address', 'show'])):
        if link['ifname'] == 'lo':
            continue
        for addr in link.get('addr_info', []):
            if addr.get('family') == 'inet':
                iface = ipaddress.ip_interface(f"{addr['local']}/{addr['prefixlen']}")
                result.append({'interface': link['ifname'], 'network': str(iface.network),
                               'ip': addr['local'], 'mac': link.get('address', '').lower(),
                               'up': 'UP' in link.get('flags', []),
                               'carrier': 'LOWER_UP' in link.get('flags', [])})
    return result


def validate_trigger(t):
    if t['mode'] not in ('json', 'form'):
        raise ValueError('Kies JSON of form.')
    if not isinstance(t['headers'], dict) or not all(isinstance(k, str) and isinstance(v, str)
                                                   for k, v in t['headers'].items()):
        raise ValueError('Headers moeten een JSON-object met tekstwaarden zijn.')
    if any('\n' in k+v or '\r' in k+v for k, v in t['headers'].items()):
        raise ValueError('Headers mogen geen regelovergangen bevatten.')
    if not isinstance(t['body'], dict):
        raise ValueError('De body moet een JSON-object zijn.')
    if t['mode'] == 'form' and any(isinstance(v, (dict, list)) for v in t['body'].values()):
        raise ValueError('Formuliervelden mogen geen geneste objecten bevatten.')
    if t['enabled'] or t['url']:
        u = urllib.parse.urlsplit(t['url'])
        if u.scheme not in ('http', 'https') or not u.hostname or u.username or u.password:
            raise ValueError('Gebruik een HTTP(S)-URL zonder gebruikersnaam/wachtwoord in de URL.')


def validate_config(c):
    if not c['profile'].strip() or not c['interface'].strip():
        raise ValueError('Vul een profielnaam en netwerkinterface in.')
    net = ipaddress.ip_network(c['network'], strict=True)
    if net.version != 4 or net.num_addresses > 4096:
        raise ValueError('Kies een IPv4-subnet van maximaal 4096 adressen (/20 of kleiner).')
    if c['interval'] != 0 and not 15 <= c['interval'] <= 86400:
        raise ValueError('Scaninterval: 0 (handmatig), of 15 t/m 86400 seconden.')
    if not 1 <= c['misses'] <= 100:
        raise ValueError('Gemiste scans: 1 t/m 100.')
    if not 0.1 <= c.get('port_timeout', 0.8) <= 5:
        raise ValueError('Poorttimeout: 0.1 t/m 5 seconden.')
    for key in ('unknown', 'offline'):
        validate_trigger(c[key])


def scope(c):
    return json.dumps([c['profile'], c['interface'], c['network']], ensure_ascii=False)


def save_config(path, config):
    validate_config(config)
    tmp = path.with_suffix('.tmp')
    with open(tmp, 'w', encoding='utf-8') as f:
        os.chmod(tmp, 0o600)
        json.dump(config, f, ensure_ascii=False, indent=2)
    os.replace(tmp, path)


def parse_arp(output, network):
    rows = {}
    for line in output.splitlines():
        m = re.match(r'^(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})\s*(.*)$', line)
        if m and ipaddress.ip_address(m[1]) in ipaddress.ip_network(network):
            mac = m[2].lower()
            rows[mac] = {'ip': m[1], 'mac': mac, 'vendor': m[3].strip(), 'hostname': ''}
    return list(rows.values())


def scan(c):
    """Only successful, connected, complete ARP scans may change presence state."""
    validate_config(c)
    binary = shutil.which('arp-scan')
    if not binary:
        raise RuntimeError('arp-scan ontbreekt. Zie README.md voor installatie.')
    def local():
        matches = [x for x in interfaces() if x['interface'] == c['interface']
                   and ipaddress.ip_network(c['network']).subnet_of(ipaddress.ip_network(x['network']))
                   and ipaddress.ip_address(x['ip']) in ipaddress.ip_network(c['network'])]
        if not matches or not matches[0]['up'] or not matches[0]['carrier']:
            raise RuntimeError('Interface is niet verbonden of dit subnet hoort niet bij de interface.')
        return matches[0]
    before = local()
    output = run([binary, '--interface', c['interface'], '--retry=3', c['network']], timeout=180)
    if not re.search(r'Ending arp-scan.*\d+ hosts scanned', output):
        raise RuntimeError('Onvolledige arp-scan uitvoer; apparaatstatussen blijven ongewijzigd.')
    after = local()
    if before != after:
        raise RuntimeError('Netwerk veranderde tijdens de scan; resultaten genegeerd.')
    rows = parse_arp(output, c['network'])
    if c['gateway_guard']:
        routes = json.loads(run(['ip', '-j', 'route', 'show', 'default', 'dev', c['interface']]))
        gateways = {r['gateway'] for r in routes if r.get('gateway') and
                    ipaddress.ip_address(r['gateway']) in ipaddress.ip_network(c['network'])}
        if not gateways:
            raise RuntimeError('Geen gateway in dit subnet. Controleer het subnet of schakel gatewaycontrole uit.')
        if not gateways.intersection(r['ip'] for r in rows):
            raise RuntimeError('Gateway niet gezien: mogelijk netwerkprobleem. Geen offline-meldingen verstuurd.')
    # De eigen machine antwoordt doorgaans niet op haar eigen ARP-aanvragen.
    rows = [r for r in rows if r['mac'] != before['mac']]
    rows.append({'ip': before['ip'], 'mac': before['mac'], 'vendor': 'Deze computer',
                 'hostname': os.uname().nodename})
    if c['dns']:
        def resolve(row):
            if row['hostname']:
                return
            try:
                answer = run(['getent', 'hosts', row['ip']], timeout=1.5).split()
                if len(answer) > 1:
                    row['hostname'] = answer[1]
            except (OSError, RuntimeError, subprocess.TimeoutExpired):
                pass
        with concurrent.futures.ThreadPoolExecutor(max_workers=16) as pool:
            list(pool.map(resolve, rows))
    if c.get('port_scan', True):
        scan_ports(rows, c, source_ip=before['ip'])
        checked = now()
        for row in rows:
            row['port_checked'] = checked
    if local() != before:
        raise RuntimeError('Verbinding gewijzigd tijdens controle; scan genegeerd.')
    return rows


class Store:
    def __init__(self, path):
        self.db = sqlite3.connect(path, timeout=15)
        self.db.row_factory = sqlite3.Row
        self.db.execute('PRAGMA journal_mode=WAL')
        self.db.executescript('''
        CREATE TABLE IF NOT EXISTS hosts (
          scope TEXT, mac TEXT, ip TEXT, hostname TEXT, vendor TEXT,
          label TEXT DEFAULT '', known INTEGER DEFAULT 0, monitor INTEGER DEFAULT 0,
          online INTEGER DEFAULT 1, misses INTEGER DEFAULT 0,
          first_seen TEXT, last_seen TEXT, PRIMARY KEY(scope, mac));
        CREATE TABLE IF NOT EXISTS events (
          id TEXT PRIMARY KEY, time TEXT, scope TEXT, kind TEXT, mac TEXT, message TEXT);
        CREATE TABLE IF NOT EXISTS outbox (
          id TEXT PRIMARY KEY, trigger TEXT, payload TEXT, status TEXT DEFAULT 'pending',
          attempts INTEGER DEFAULT 0, due REAL DEFAULT 0, result TEXT DEFAULT '');
        ''')
        # Additieve migratie: bestaande apparaten en vertrouwensstatus blijven staan.
        columns = {r[1] for r in self.db.execute('PRAGMA table_info(hosts)')}
        for column in ('port_results', 'port_checked'):
            if column not in columns:
                self.db.execute(f"ALTER TABLE hosts ADD COLUMN {column} TEXT DEFAULT ''")
        self.db.commit()

    def hosts(self, s):
        return [dict(r) for r in self.db.execute('SELECT * FROM hosts WHERE scope=?', (s,))]

    def edit(self, s, mac, label, known, monitor):
        with self.db:
            self.db.execute('UPDATE hosts SET label=?,known=?,monitor=? WHERE scope=? AND mac=?',
                            (label, int(known), int(monitor and known), s, mac))

    def add_event(self, s, kind, h, config, stamp):
        eid = str(uuid.uuid4())
        name = h.get('label') or h.get('hostname') or h['ip']
        message = (f'Onbekend apparaat gevonden: {name} ({h["ip"]}, {h["mac"]})' if kind == 'unknown'
                   else f'Bekend apparaat offline: {name} ({h["ip"]}, {h["mac"]})')
        self.db.execute('INSERT INTO events VALUES (?,?,?,?,?,?)',
                        (eid, stamp, s, kind, h['mac'], message))
        payload = {'event_id': eid, 'event': kind, 'timestamp': stamp, 'ip': h['ip'],
                   'mac': h['mac'], 'name': name, 'hostname': h.get('hostname', ''),
                   'vendor': h.get('vendor', ''), 'message': message,
                   'profile': config['profile'], 'network': config['network']}
        t = config[kind]
        if t['enabled']:
            self.db.execute('INSERT INTO outbox (id,trigger,payload) VALUES (?,?,?)',
                            (eid, json.dumps(t), json.dumps(payload)))
        return message

    def apply_scan(self, config, rows):
        s, stamp, messages = scope(config), now(), []
        existing = {h['mac']: h for h in self.hosts(s)}
        seen = {r['mac'] for r in rows}
        with self.db:
            for h in rows:
                old = existing.get(h['mac'])
                if old is None:
                    self.db.execute('''INSERT INTO hosts
                      (scope,mac,ip,hostname,vendor,first_seen,last_seen) VALUES (?,?,?,?,?,?,?)''',
                      (s, h['mac'], h['ip'], h['hostname'], h['vendor'], stamp, stamp))
                    messages.append(self.add_event(s, 'unknown', h, config, stamp))
                else:
                    self.db.execute('''UPDATE hosts SET ip=?,hostname=?,vendor=?,online=1,
                      misses=0,last_seen=? WHERE scope=? AND mac=?''',
                      (h['ip'], h['hostname'] or old['hostname'], h['vendor'], stamp, s, h['mac']))
                    if not old['online'] and not old['known']:
                        messages.append(self.add_event(s, 'unknown', {**old, **h}, config, stamp))
                if 'port_results' in h:
                    self.db.execute('UPDATE hosts SET port_results=?,port_checked=? WHERE scope=? AND mac=?',
                                    (h['port_results'], h['port_checked'], s, h['mac']))
                elif old and old['ip'] != h['ip']:
                    self.db.execute("UPDATE hosts SET port_results='',port_checked='' WHERE scope=? AND mac=?",
                                    (s, h['mac']))
            for mac, h in existing.items():
                if mac in seen:
                    continue
                misses = h['misses'] + 1
                offline = misses >= config['misses']
                self.db.execute('UPDATE hosts SET misses=?,online=? WHERE scope=? AND mac=?',
                                (misses, 0 if offline else h['online'], s, mac))
                if offline and h['online'] and h['known'] and h['monitor']:
                    messages.append(self.add_event(s, 'offline', h, config, stamp))
        return messages

    def close(self):
        self.db.close()


PLACEHOLDER = re.compile(r'\{([a-z_]+)\}')
def substitute(value, payload):
    if isinstance(value, str):
        return PLACEHOLDER.sub(lambda m: str(payload.get(m[1], m[0])), value)
    if isinstance(value, dict):
        return {k: substitute(v, payload) for k, v in value.items()}
    if isinstance(value, list):
        return [substitute(v, payload) for v in value]
    return value


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def post(trigger, payload):
    validate_trigger(trigger)
    body = substitute(trigger['body'], payload)
    if trigger['mode'] == 'json':
        data = json.dumps(body, ensure_ascii=False).encode('utf-8')
        content_type = 'application/json; charset=utf-8'
    else:
        data = urllib.parse.urlencode(body).encode('utf-8')
        content_type = 'application/x-www-form-urlencoded'
    headers = {'Content-Type': content_type, 'User-Agent': 'NetwerkWacht/1.0',
               'X-NetwerkWacht-Event-ID': payload['event_id'], **trigger['headers']}
    request = urllib.request.Request(trigger['url'], data=data, headers=headers, method='POST')
    try:
        # Geen proxy uit omgevingsvariabelen en geen redirects met geheime headers.
        with urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect()).open(
                request, timeout=10) as response:
            return 200 <= response.status < 300, f'HTTP {response.status}'
    except urllib.error.HTTPError as e:
        return False, f'HTTP {e.code}'
    except Exception as e:
        # Geen URL, requestbody of tokens in het log.
        return False, type(e).__name__


class Dispatcher(threading.Thread):
    """Durable outbox; at-least-once delivery, up to four total attempts."""
    def __init__(self, path, stop):
        super().__init__(daemon=True)
        self.path, self.stop = path, stop

    def run(self):
        store = Store(self.path)
        try:
            while not self.stop.is_set():
                row = store.db.execute("SELECT * FROM outbox WHERE status='pending' AND due<=? ORDER BY due LIMIT 1",
                                       (time.time(),)).fetchone()
                if row is None:
                    self.stop.wait(1)
                    continue
                ok, result = post(json.loads(row['trigger']), json.loads(row['payload']))
                attempt = row['attempts'] + 1
                status = 'sent' if ok else ('failed' if attempt >= 4 else 'pending')
                with store.db:
                    store.db.execute('UPDATE outbox SET status=?,attempts=?,due=?,result=? WHERE id=?',
                                     (status, attempt, time.time() + 10 * 3**(attempt-1), result, row['id']))
                    # Afgeronde requests hoeven geen kopie van de geheime headers te bewaren.
                    if status != 'pending':
                        store.db.execute("UPDATE outbox SET trigger='{}' WHERE id=?", (row['id'],))
        finally:
            store.close()
