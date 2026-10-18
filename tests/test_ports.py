import json
from pathlib import Path
import socket
import sqlite3
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from ports import TCP_PORTS, UDP_PORTS, check_port, port_summary, scan_ports
from core import Store, default_config, scope


class PortTests(unittest.TestCase):
    def test_exact_requested_port_set(self):
        self.assertEqual(set(TCP_PORTS), {20,21,22,23,25,53,80,110,135,139,143,389,443,445,465,993,995,3306,5432,5900,6379,8080,8443})
        self.assertEqual(set(UDP_PORTS), {53,67,68,123,137,138,161,389,514})

    def test_tcp_local_listener_is_open(self):
        with socket.socket() as server:
            server.bind(('127.0.0.1', 0))
            server.listen()
            self.assertEqual(check_port('127.0.0.1', server.getsockname()[1], 'tcp')['state'], 'open')

    def test_tcp_bound_non_listener_is_closed(self):
        with socket.socket() as server:
            server.bind(('127.0.0.1', 0))
            self.assertEqual(check_port('127.0.0.1', server.getsockname()[1], 'tcp')['state'], 'closed')

    def test_udp_reply_is_open(self):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as server:
            server.bind(('127.0.0.1', 0))
            server.settimeout(2)
            def respond():
                data, address = server.recvfrom(4096)
                server.sendto(b'reply', address)
            worker = threading.Thread(target=respond)
            worker.start()
            result = check_port('127.0.0.1', server.getsockname()[1], 'udp', 0.3)
            worker.join(3)
            self.assertEqual(result['state'], 'open')

    def test_udp_silent_open_socket_remains_uncertain(self):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as server:
            server.bind(('127.0.0.1', 0))
            result = check_port('127.0.0.1', server.getsockname()[1], 'udp', 0.03)
            self.assertEqual(result['state'], 'uncertain')
            opened, uncertain = port_summary(json.dumps([result]))
            self.assertEqual(opened, 'Geen open poorten bevestigd')
            self.assertIn(str(server.getsockname()[1]), uncertain)

    def test_unknown_udp_does_not_appear_in_open_summary(self):
        rows = [{'port': 22, 'protocol': 'tcp', 'state': 'open'},
                {'port': 161, 'protocol': 'udp', 'state': 'uncertain'}]
        self.assertEqual(port_summary(json.dumps(rows)), ('22/tcp SSH', '161'))

    def test_udp_setting_and_all_host_results(self):
        rows = [{'ip': '192.0.2.1'}, {'ip': '192.0.2.2'}]
        with patch('ports.check_port', side_effect=lambda ip, p, proto, *a:
                   {'port': p, 'protocol': proto, 'state': 'closed', 'reason': 'test'}) as probe:
            scan_ports(rows, {'udp_scan': False})
            self.assertEqual(probe.call_count, 46)
            self.assertTrue(all(len(json.loads(row['port_results'])) == 23 for row in rows))

    def test_migration_persistence_and_ip_change(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'db'
            # Oud schema uit versie 1.2, met een al vertrouwd apparaat.
            db = sqlite3.connect(path)
            db.execute('''CREATE TABLE hosts (scope TEXT, mac TEXT, ip TEXT, hostname TEXT, vendor TEXT,
              label TEXT DEFAULT '', known INTEGER DEFAULT 0, monitor INTEGER DEFAULT 0,
              online INTEGER DEFAULT 1, misses INTEGER DEFAULT 0, first_seen TEXT, last_seen TEXT,
              PRIMARY KEY(scope, mac))''')
            c = default_config()
            db.execute('INSERT INTO hosts(scope,mac,ip,hostname,vendor,known) VALUES (?,?,?,?,?,?)',
                       (scope(c), '00:11:22:33:44:55', '192.0.2.1', 'NAS', 'Test', 1))
            db.commit()
            db.close()
            store = Store(path)
            host = store.hosts(scope(c))[0]
            self.assertEqual((host['known'], host['port_results']), (1, ''))
            host.update(port_results='[{"port":22,"protocol":"tcp","state":"open"}]', port_checked='2026-10-17T12:00:00Z')
            store.apply_scan(c, [host])
            store.close()
            store = Store(path)
            host = store.hosts(scope(c))[0]
            self.assertIn('22', host['port_results'])
            host.pop('port_results')
            host.pop('port_checked')
            host['ip'] = '192.0.2.2'
            store.apply_scan(c, [host])
            self.assertEqual(store.hosts(scope(c))[0]['port_results'], '')
            self.assertEqual(store.hosts(scope(c))[0]['known'], 1)
            store.close()
