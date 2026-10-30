"""Test de web-API op loopback, met gesimuleerde discovery en echte SQLite."""
import copy
import csv
import http.client
import io
import json
from pathlib import Path
import sys
import tempfile
import threading
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from core import Store, scope
from webwatch import Monitor, WebServer, checked_config, demo_scan


class WebTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.monitor = Monitor(self.tmp.name, demo=True)
        self.server = WebServer(('127.0.0.1', 0), self.monitor)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.csrf = self.server.csrf
        self.cookie = ''

    def tearDown(self):
        self.monitor.close()
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(2)
        self.tmp.cleanup()

    def request(self, path, data=None, *, headers=None, raw=False):
        conn = http.client.HTTPConnection('127.0.0.1', self.server.server_port, timeout=5)
        request_headers = {'Cookie': self.cookie}
        if data is not None:
            request_headers.update({'Content-Type': 'application/json', 'X-CSRF-Token': self.csrf})
        request_headers.update(headers or {})
        body = None if data is None else json.dumps(data)
        try:
            conn.request('GET' if data is None else 'POST', path, body=body, headers=request_headers)
            response = conn.getresponse()
            result = response.read()
            return response.status, dict(response.getheaders()), result if raw else json.loads(result)
        finally:
            conn.close()

    def test_real_state_without_secrets_and_static_assets(self):
        self.monitor.config['unknown']['headers'] = {'Authorization': 'PRIVATE_TOKEN'}
        code, _, state = self.request('/api/state')
        self.assertEqual(code, 200)
        self.assertEqual(len(state['hosts']), 4)
        self.assertNotIn('PRIVATE_TOKEN', json.dumps(state))
        for path in ('/', '/app.js', '/style.css'):
            code, headers, content = self.request(path, raw=True)
            self.assertEqual(code, 200)
            self.assertTrue(content)
            self.assertEqual(headers['Cache-Control'], 'no-store')
            self.assertIn("frame-ancestors 'none'", headers['Content-Security-Policy'])
        self.assertEqual(self.request('/../core.py')[0], 404)

    def test_rebinding_cross_site_and_csrf_are_blocked(self):
        self.assertEqual(self.request('/api/state', headers={'Host': 'evil.example:8765'})[0], 403)
        self.assertEqual(self.request('/api/state', headers={'Sec-Fetch-Site': 'cross-site'})[0], 403)
        self.assertEqual(self.request('/api/scan', {}, headers={'X-CSRF-Token': ''})[0], 403)
        self.assertEqual(self.request('/api/pause', {'paused': True}, headers={'Origin': 'https://evil.example'})[0], 403)
        self.assertFalse(self.monitor.paused)

    def test_login_protects_state_settings_and_actions_then_logout(self):
        self.server.token = 'a-long-test-access-code-only-for-tests'
        self.assertEqual(self.request('/api/state')[0], 401)
        self.assertEqual(self.request('/api/settings')[0], 401)
        self.assertEqual(self.request('/api/scan', {})[0], 401)
        self.assertIsNone(self.request('/api/auth')[2]['csrf'])
        self.assertEqual(self.request('/api/login', {'token': 'wrong'})[0], 401)
        code, headers, result = self.request('/api/login', {'token': self.server.token})
        self.assertEqual(code, 200)
        self.assertIn('HttpOnly', headers['Set-Cookie'])
        self.assertIn('SameSite=Strict', headers['Set-Cookie'])
        self.cookie = headers['Set-Cookie'].split(';')[0]
        self.csrf = result['csrf']
        self.assertEqual(self.request('/api/state')[0], 200)
        self.assertEqual(self.request('/api/logout', {})[0], 200)
        self.assertEqual(self.request('/api/state')[0], 401)

    def test_settings_save_conflict_validation_and_restart(self):
        _, _, settings = self.request('/api/settings')
        settings['config']['profile'] = 'Thuis in de browser'
        self.assertEqual(self.request('/api/settings', settings)[0], 200)
        self.assertEqual(self.request('/api/settings', settings)[0], 409)
        loaded = Monitor(self.tmp.name)
        self.assertEqual(loaded.config['profile'], 'Thuis in de browser')
        _, _, settings = self.request('/api/settings')
        settings['config']['misses'] = True
        self.assertEqual(self.request('/api/settings', settings)[0], 400)
        self.assertEqual(self.monitor.config['misses'], 3)
        loaded.close()

    def test_single_scan_busy_guard_and_nonblocking_state(self):
        started, release = threading.Event(), threading.Event()
        def scanner(c):
            started.set()
            release.wait(3)
            return demo_scan(c)
        self.monitor.scanner = scanner
        try:
            self.assertEqual(self.request('/api/scan', {})[0], 202)
            self.assertTrue(started.wait(1))
            self.assertTrue(self.request('/api/state')[2]['busy'])
            self.assertEqual(self.request('/api/scan', {})[0], 409)
            self.assertEqual(self.request('/api/settings', self.monitor.settings())[0], 409)
        finally:
            release.set()
            self.monitor.worker.join(3)
        self.assertFalse(self.monitor.busy)
        self.assertEqual(self.monitor.scan_serial, 1)
        self.assertEqual(len(self.monitor.state()['hosts']), 4)

    def test_failed_scan_never_marks_hosts_offline(self):
        before = copy.deepcopy(self.monitor.state()['hosts'])
        self.monitor.scanner = Mock(side_effect=RuntimeError('Geen verbinding'))
        self.monitor.request_scan()
        self.monitor.worker.join(3)
        self.assertEqual(self.monitor.state()['hosts'], before)
        self.assertIn('geen statuswijzigingen', self.monitor.status)

    def test_shutdown_discards_unfinished_scan(self):
        started, release = threading.Event(), threading.Event()
        def scanner(_):
            started.set()
            release.wait(3)
            return []
        self.monitor.scanner = scanner
        before = copy.deepcopy(self.monitor.state()['hosts'])
        self.monitor.request_scan()
        self.assertTrue(started.wait(1))
        self.monitor.stopped.set()
        release.set()
        self.monitor.worker.join(3)
        self.assertEqual(self.monitor.state()['hosts'], before)

    def test_edit_known_monitor_and_scope_guard(self):
        state = self.monitor.state()
        host = state['hosts'][-1]
        data = {'scope': state['scope'], 'id': host['id'], 'label': 'Mijn telefoon', 'known': True, 'monitor': True}
        self.assertEqual(self.request('/api/host', data)[0], 200)
        saved = next(h for h in self.monitor.state()['hosts'] if h['id'] == host['id'])
        self.assertEqual((saved['label'], saved['known'], saved['monitor']), ('Mijn telefoon', 1, 1))
        self.assertEqual(self.request('/api/host', {**data, 'known': False})[0], 400)
        self.assertEqual(self.request('/api/host', {**data, 'scope': 'old profile'})[0], 409)
        self.assertEqual(self.request('/api/host', {**data, 'known': False, 'monitor': False})[0], 200)

    def test_ip_export_has_identity_but_no_fake_mac_and_neutralizes_formula(self):
        self.monitor.config.update(scan_mode='ip', guard_host='192.0.2.1')
        row = {'ip': '192.0.2.100', 'mac': 'ip:192.0.2.100', 'hostname': '=BAD()', 'vendor': ''}
        store = Store(self.monitor.db_path)
        try:
            store.apply_scan(self.monitor.config, [row])
        finally:
            store.close()
        code, headers, content = self.request('/api/export', raw=True)
        self.assertEqual(code, 200)
        rows = list(csv.DictReader(io.StringIO(content.decode('utf-8-sig')), delimiter=';'))
        self.assertEqual(rows[0]['mac'], '')
        self.assertEqual(rows[0]['device_id'], row['mac'])
        self.assertEqual(rows[0]['hostname'], "'=BAD()")
        self.assertIn('attachment', headers['Content-Disposition'])

    def test_actions_require_enabled_server_and_confirmed_port(self):
        state = self.monitor.state()
        host = state['hosts'][0]
        action = {'id': host['id'], 'scope': state['scope'], 'port': 22, 'kind': 'ssh', 'username': 'jan'}
        with patch('webwatch.launch_action', return_value=Mock(poll=lambda: None)) as launch:
            self.assertEqual(self.request('/api/action', action)[0], 400)
            self.monitor.local_actions = True
            self.assertEqual(self.request('/api/action', {**action, 'port': 23})[0], 400)
            self.assertEqual(self.request('/api/action', action)[0], 200)
            launch.assert_called_once_with(host['ip'], 22, 'ssh', 'jan')

    def test_demo_trigger_never_sends_post(self):
        trigger = self.monitor.config['unknown']
        trigger['url'] = 'http://localhost/hook'
        with patch('webwatch.post') as send:
            code, _, result = self.request('/api/trigger-test', {'kind': 'unknown', 'trigger': trigger})
            self.assertEqual(code, 200)
            self.assertIn('geen POST', result['message'])
            send.assert_not_called()

    def test_pause_and_real_test_post_with_explicit_button_request(self):
        self.assertEqual(self.request('/api/pause', {'paused': True})[0], 200)
        self.assertTrue(self.monitor.paused)
        self.assertEqual(self.request('/api/pause', {'paused': 'yes'})[0], 400)
        self.monitor.demo = False
        trigger = copy.deepcopy(self.monitor.config['offline'])
        trigger['url'] = 'http://localhost/hook'
        with patch('webwatch.post', return_value=(True, 'HTTP 204')) as send:
            result = self.request('/api/trigger-test', {'kind': 'offline', 'trigger': trigger})
            self.assertEqual(result[0], 200)
            self.assertTrue(result[2]['ok'])
            self.assertEqual(send.call_args.args[1]['event'], 'offline')
            self.assertEqual(send.call_args.args[1]['ip'], '192.0.2.123')

    def test_strict_config_rejects_extra_keys_and_wrong_types(self):
        config = self.monitor.settings()['config']
        for bad in ({**config, 'extra': 1}, {**config, 'dns': 'yes'},
                    {**config, 'port_timeout': float('nan')}, {**config, 'port_timeout': True}):
            with self.assertRaises(ValueError):
                checked_config(bad)


if __name__ == '__main__':
    unittest.main()
