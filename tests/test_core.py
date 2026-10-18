import json
from pathlib import Path
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch
from http.server import BaseHTTPRequestHandler, HTTPServer
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import core


def host(ip='192.168.2.10', mac='00:11:22:33:44:55', name='pc'):
    return {'ip': ip, 'mac': mac, 'hostname': name, 'vendor': 'Vendor'}


class StateTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.store = core.Store(Path(self.temp.name) / 'db.sqlite')
        self.c = core.default_config()
        self.c.update(interface='eth0', network='192.168.2.0/24')
        self.c['unknown'] = {**self.c['unknown'], 'enabled': True, 'url': 'http://localhost/hook'}
        self.c['offline'] = {**self.c['offline'], 'enabled': True, 'url': 'http://localhost/hook'}

    def tearDown(self):
        self.store.close()
        self.temp.cleanup()

    def test_unknown_once_and_reappearance(self):
        self.assertEqual(len(self.store.apply_scan(self.c, [host()])), 1)
        self.assertEqual(self.store.apply_scan(self.c, [host()]), [])
        for _ in range(3):
            self.store.apply_scan(self.c, [])
        self.assertEqual(len(self.store.apply_scan(self.c, [host()])), 1)

    def test_offline_threshold_rearm_and_no_spam(self):
        self.store.apply_scan(self.c, [host()])
        self.store.edit(core.scope(self.c), host()['mac'], 'NAS', True, True)
        for _ in range(2):
            self.assertEqual(self.store.apply_scan(self.c, []), [])
        self.assertEqual(len(self.store.apply_scan(self.c, [])), 1)
        self.assertEqual(self.store.apply_scan(self.c, []), [])
        self.assertEqual(self.store.apply_scan(self.c, [host()]), [])
        for _ in range(2):
            self.store.apply_scan(self.c, [])
        self.assertEqual(len(self.store.apply_scan(self.c, [])), 1)

    def test_known_without_monitor_does_not_alert(self):
        self.store.apply_scan(self.c, [host()])
        self.store.edit(core.scope(self.c), host()['mac'], '', True, False)
        for _ in range(5):
            self.assertEqual(self.store.apply_scan(self.c, []), [])

    def test_mac_identity_survives_ip_change_and_restart(self):
        self.store.apply_scan(self.c, [host()])
        self.store.edit(core.scope(self.c), host()['mac'], 'NAS', True, True)
        path = Path(self.temp.name) / 'db.sqlite'
        self.store.close()
        self.store = core.Store(path)
        self.assertEqual(self.store.apply_scan(self.c, [host(ip='192.168.2.99')]), [])
        h = self.store.hosts(core.scope(self.c))[0]
        self.assertEqual((h['ip'], h['label'], h['known']), ('192.168.2.99', 'NAS', 1))

    def test_different_mac_on_same_ip_is_unknown(self):
        self.store.apply_scan(self.c, [host()])
        self.store.edit(core.scope(self.c), host()['mac'], '', True, False)
        self.assertEqual(len(self.store.apply_scan(self.c, [host(mac='00:11:22:33:44:66')])), 1)

    def test_profiles_are_isolated(self):
        self.store.apply_scan(self.c, [host()])
        self.c['profile'] = 'Ander netwerk'
        self.assertEqual(len(self.store.apply_scan(self.c, [host()])), 1)
        self.assertEqual(len(self.store.hosts(core.scope(self.c))), 1)

    def test_scan_transaction_rolls_back_on_outbox_error(self):
        with patch.object(self.store, 'add_event', side_effect=RuntimeError('disk failure')):
            with self.assertRaises(RuntimeError):
                self.store.apply_scan(self.c, [host()])
        self.assertEqual(self.store.hosts(core.scope(self.c)), [])

    def test_short_miss_resets_on_return(self):
        self.store.apply_scan(self.c, [host()])
        self.store.apply_scan(self.c, [])
        self.store.apply_scan(self.c, [host()])
        self.assertEqual(self.store.hosts(core.scope(self.c))[0]['misses'], 0)


class ScannerTests(unittest.TestCase):
    def test_parser_deduplicates_and_filters(self):
        output = ('192.168.2.10\t00:11:22:33:44:55\tVendor\n'
                  '192.168.2.10\t00:11:22:33:44:55\tVendor\n'
                  '10.0.0.1\t00:11:22:33:44:66\tOther\nWARNING: text')
        self.assertEqual(len(core.parse_arp(output, '192.168.2.0/24')), 1)

    def config(self):
        c = core.default_config()
        c.update(interface='eth0', network='192.168.2.0/24', dns=False, port_scan=False)
        return c

    def local(self):
        return [{'interface': 'eth0', 'network': '192.168.2.0/24', 'ip': '192.168.2.2',
                 'mac': '00:00:00:00:00:02', 'up': True, 'carrier': True}]

    @patch('core.shutil.which', return_value='/usr/bin/arp-scan')
    def test_missing_gateway_rejects_complete_scan(self, _):
        output = 'Ending arp-scan 1.10.0: 256 hosts scanned in 2 seconds. 0 responded'
        with patch('core.interfaces', return_value=self.local()), patch('core.run', side_effect=[output, '[{"gateway":"192.168.2.1"}]']):
            with self.assertRaisesRegex(RuntimeError, 'Gateway niet gezien'):
                core.scan(self.config())

    @patch('core.shutil.which', return_value='/usr/bin/arp-scan')
    def test_success_includes_local_host(self, _):
        output = '192.168.2.1\t00:00:00:00:00:01\tRouter\nEnding arp-scan 1.10.0: 256 hosts scanned in 2 seconds.'
        with patch('core.interfaces', return_value=self.local()), patch('core.run', side_effect=[output, '[{"gateway":"192.168.2.1"}]']):
            self.assertEqual(len(core.scan(self.config())), 2)

    @patch('core.shutil.which', return_value='/usr/bin/arp-scan')
    def test_disconnected_interface_rejected(self, _):
        local = self.local()
        local[0]['carrier'] = False
        with patch('core.interfaces', return_value=local), patch('core.run') as run:
            with self.assertRaises(RuntimeError):
                core.scan(self.config())
            run.assert_not_called()

    @patch('core.shutil.which', return_value='/usr/bin/arp-scan')
    def test_truncated_output_rejected(self, _):
        with patch('core.interfaces', return_value=self.local()), patch('core.run', return_value='partial'):
            with self.assertRaisesRegex(RuntimeError, 'Onvolledige'):
                core.scan(self.config())

    def test_reject_large_and_nonlocal_style_targets(self):
        for subnet in ['192.168.0.0/16', '::/64', '--help', '192.168.2.12/24']:
            c = self.config()
            c['network'] = subnet
            with self.assertRaises(ValueError):
                core.validate_config(c)


class HttpTests(unittest.TestCase):
    def test_placeholder_values_cannot_break_json(self):
        name = 'quotes " slash \\ newline\n {ip}'
        result = core.substitute({'name': '{name}'}, {'name': name, 'ip': '1.2.3.4'})
        self.assertEqual(json.loads(json.dumps(result))['name'], name)

    def test_real_local_json_and_form_and_redirect_refusal(self):
        received = []
        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                received.append((self.path, self.headers, self.rfile.read(int(self.headers['Content-Length']))))
                self.send_response(302 if self.path == '/redirect' else 204)
                if self.path == '/redirect':
                    self.send_header('Location', '/leak')
                self.end_headers()
            def log_message(self, *_):
                pass
        server = HTTPServer(('127.0.0.1', 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            t = core.default_config()['unknown']
            t.update(url=f'http://127.0.0.1:{server.server_port}/hook', enabled=True,
                     body={'message': '{message}'})
            payload = {'message': 'Hallo & Jan "', 'event_id': 'unique-test'}
            self.assertTrue(core.post(t, payload)[0])
            self.assertEqual(json.loads(received[-1][2]), {'message': payload['message']})
            self.assertEqual(received[-1][1]['X-NetwerkWacht-Event-ID'], 'unique-test')
            t['mode'] = 'form'
            self.assertTrue(core.post(t, payload)[0])
            self.assertEqual(core.urllib.parse.parse_qs(received[-1][2].decode()), {'message': [payload['message']]})
            t['url'] = t['url'].replace('/hook', '/redirect')
            self.assertFalse(core.post(t, payload)[0])
            self.assertEqual(len(received), 3)
        finally:
            server.shutdown()
            server.server_close()
            thread.join()

    def test_dispatcher_durable_delivery(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'db'
            store = core.Store(path)
            c = core.default_config()
            c['unknown'] = {**c['unknown'], 'enabled': True, 'url': 'http://localhost/test'}
            store.apply_scan(c, [host()])
            store.close()
            stopped = threading.Event()
            called = threading.Event()
            def deliver(t, p):
                stopped.set()
                called.set()
                return True, 'HTTP 204'
            with patch('core.post', side_effect=deliver):
                worker = core.Dispatcher(path, stopped)
                worker.start()
                self.assertTrue(called.wait(3))
                worker.join(3)
            store = core.Store(path)
            row = store.db.execute('SELECT * FROM outbox').fetchone()
            self.assertEqual((row['status'], row['attempts'], row['trigger']), ('sent', 1, '{}'))
            store.close()

    def test_failed_delivery_is_scheduled_again(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'db'
            store = core.Store(path)
            c = core.default_config()
            c['unknown'] = {**c['unknown'], 'enabled': True, 'url': 'http://localhost/test'}
            store.apply_scan(c, [host()])
            stopped = threading.Event()
            def fail(*_):
                stopped.set()
                return False, 'HTTP 503'
            with patch('core.post', side_effect=fail):
                worker = core.Dispatcher(path, stopped)
                worker.start()
                worker.join(3)
            row = store.db.execute('SELECT * FROM outbox').fetchone()
            self.assertEqual((row['status'], row['attempts']), ('pending', 1))
            self.assertGreater(row['due'], core.time.time())
            store.close()


if __name__ == '__main__':
    unittest.main()
