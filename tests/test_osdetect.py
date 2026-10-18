import json
from pathlib import Path
import socket
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from osdetect import classify_banners, detect_hosts, read_banner
from core import Store, default_config, scope


class OSDetectionTests(unittest.TestCase):
    def test_explicit_linux_windows_bsd_and_darwin(self):
        cases = [('SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13', 'Linux (Ubuntu)'),
                 ('SSH-2.0-OpenSSH_9.2p1 Debian-2', 'Linux (Debian)'),
                 ('SSH-2.0-OpenSSH_for_Windows_9.5', 'Windows'),
                 ('Microsoft-IIS/10.0', 'Windows'), ('Apache/2.4 (FreeBSD)', 'FreeBSD'),
                 ('Apache/2.4 (Darwin)', 'Darwin/macOS')]
        for banner, expected in cases:
            with self.subTest(banner=banner):
                self.assertEqual(classify_banners([(22, banner)])[0], expected)

    def test_generic_services_do_not_prove_os(self):
        for banner in ('SSH-2.0-OpenSSH_9.9', 'nginx', 'Apache/2.4', 'Samba', ''):
            self.assertEqual(classify_banners([(22, banner)])[0], 'Onbekend')

    def test_conflicting_evidence_is_not_silently_ranked(self):
        self.assertEqual(classify_banners([(22, 'Debian'), (80, 'Microsoft-IIS')])[0], 'Onzeker (tegenstrijdig)')
        self.assertEqual(classify_banners([(22, 'Ubuntu'), (80, 'Debian')])[0], 'Onzeker (tegenstrijdig)')

    def test_compatible_evidence_selects_specific_os(self):
        self.assertEqual(classify_banners([(22, 'Ubuntu'), (80, 'Linux')])[0], 'Linux (Ubuntu)')

    def test_only_fresh_open_candidate_ports_are_probed(self):
        rows = [{'ip': '192.0.2.2', 'port_results': json.dumps([
            {'port': 22, 'protocol': 'tcp', 'state': 'open'},
            {'port': 80, 'protocol': 'tcp', 'state': 'closed'}])}]
        with patch('osdetect.read_banner', return_value='SSH-2.0-OpenSSH_9 Debian') as read:
            detect_hosts(rows, {}, '192.0.2.1')
            read.assert_called_once_with('192.0.2.2', 22, 0.8, '192.0.2.1')
        self.assertEqual(rows[0]['os_guess'], 'Linux (Debian)')

    def test_local_os_does_not_need_network(self):
        rows = [{'ip': '192.0.2.1'}]
        with patch('osdetect.platform.system', return_value='Linux'), patch('osdetect.read_banner') as read:
            detect_hosts(rows, {}, '192.0.2.1')
            read.assert_not_called()
        self.assertEqual(rows[0]['os_guess'], 'Linux (lokaal)')

    def test_disabled_port_scan_still_allows_banner_detection(self):
        rows = [{'ip': '192.0.2.2'}]
        with patch('osdetect.read_banner', return_value='') as read:
            detect_hosts(rows, {}, '192.0.2.1')
            self.assertEqual(read.call_count, 4)
        self.assertEqual(rows[0]['os_guess'], 'Onbekend')

    def test_http_body_is_not_used_as_os_evidence(self):
        fake = unittest.mock.MagicMock()
        fake.__enter__.return_value = fake
        fake.recv.return_value = b'HTTP/1.1 200 OK\r\nServer: nginx\r\n\r\nUbuntu Windows Debian'
        with patch('osdetect.socket.socket', return_value=fake):
            banner = read_banner('192.0.2.2', 80)
        self.assertEqual(banner, 'nginx')
        self.assertEqual(classify_banners([(80, banner)])[0], 'Onbekend')
        self.assertTrue(fake.sendall.call_args[0][0].startswith(b'HEAD / HTTP/1.0'))

    def test_local_tcp_server_banner_and_bounded_read(self):
        # Werkelijke socketcommunicatie, plus splitsing van een SSH-regel.
        with socket.socket() as server:
            server.bind(('127.0.0.1', 0))
            server.listen()
            server.settimeout(2)
            port = server.getsockname()[1]
            def serve():
                connection, _ = server.accept()
                with connection:
                    connection.sendall(b'SSH-2.0-OpenSSH_9.2 Debian-2\r\n')
            thread = threading.Thread(target=serve)
            thread.start()
            # Vertaal alleen het connect-doel naar de tijdelijke testpoort.
            original_socket = socket.socket
            class TestSocket(original_socket):
                def connect(self, address):
                    return super().connect((address[0], port))
            with patch('osdetect.socket.socket', TestSocket):
                banner = read_banner('127.0.0.1', 22)
            thread.join(3)
        self.assertEqual(classify_banners([(22, banner)])[0], 'Linux (Debian)')

    def test_additive_migration_persistence_and_no_stale_os_on_ip_change(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'db'
            store = Store(path)
            c = default_config()
            host = {'ip': '192.0.2.2', 'mac': '00:11:22:33:44:55', 'hostname': 'test', 'vendor': '',
                    'os_guess': 'Linux (Debian)', 'os_evidence': '22/tcp: Debian', 'os_checked': 'test time'}
            store.apply_scan(c, [host])
            store.edit(scope(c), host['mac'], 'NAS', True, True)
            store.close()
            store = Store(path)
            row = store.hosts(scope(c))[0]
            self.assertEqual((row['os_guess'], row['known']), ('Linux (Debian)', 1))
            host = {k: v for k, v in host.items() if not k.startswith('os_')}
            host['ip'] = '192.0.2.3'
            store.apply_scan(c, [host])
            row = store.hosts(scope(c))[0]
            self.assertEqual((row['os_guess'], row['os_checked'], row['known']), ('', '', 1))
            store.close()
