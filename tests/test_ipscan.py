"""IP-scan en identiteit testen zonder het echte netwerk te scannen."""
import json
from pathlib import Path
from types import SimpleNamespace
import sys
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import core
import ipscan


def config():
    c = core.default_config()
    c.update(scan_mode='ip', interface='eth0', network='192.168.2.0/30',
             guard_host='192.168.2.1', dns=False, port_scan=False, os_scan=False)
    return c


LOCAL = {'interface': 'eth0', 'network': '100.115.92.24/30', 'ip': '100.115.92.26',
         'mac': '00:11:22:33:44:55', 'up': True, 'carrier': True}
ROUTE = {'dev': 'eth0', 'gateway': '100.115.92.25', 'prefsrc': LOCAL['ip']}


class ProbeTests(unittest.TestCase):
    @patch('ipscan.check_port')
    @patch('ipscan.subprocess.run', return_value=SimpleNamespace(returncode=0))
    def test_ping_response_needs_no_tcp(self, ping, tcp):
        self.assertTrue(ipscan.probe_host('192.168.2.1', LOCAL['ip'], '/bin/ping', 0.8))
        tcp.assert_not_called()
        self.assertIn(LOCAL['ip'], ping.call_args.args[0])
        self.assertEqual(ping.call_args.kwargs['timeout'], 3)

    @patch('ipscan.subprocess.run', return_value=SimpleNamespace(returncode=1))
    def test_tcp_open_or_refused_proves_presence(self, _):
        for state in ('open', 'closed'):
            with self.subTest(state=state), patch('ipscan.check_port', return_value={'state': state}):
                self.assertTrue(ipscan.probe_host('192.168.2.1', LOCAL['ip'], '/bin/ping', 0.8))

    @patch('ipscan.check_port', return_value={'state': 'uncertain'})
    @patch('ipscan.subprocess.run', return_value=SimpleNamespace(returncode=1))
    def test_no_answers_is_not_online(self, _, tcp):
        self.assertFalse(ipscan.probe_host('192.168.2.2', LOCAL['ip'], '/bin/ping', 0.8))
        self.assertEqual(tcp.call_count, len(ipscan.DISCOVERY_PORTS))

    @patch('ipscan.check_port')
    @patch('ipscan.subprocess.run', return_value=SimpleNamespace(returncode=2))
    def test_ping_tool_failure_aborts(self, _, tcp):
        with self.assertRaisesRegex(RuntimeError, 'Ping kan niet'):
            ipscan.probe_host('192.168.2.1', LOCAL['ip'], '/bin/ping', 0.8)
        tcp.assert_not_called()

    @patch('ipscan.check_port', return_value={'state': 'error'})
    @patch('ipscan.subprocess.run', return_value=SimpleNamespace(returncode=1))
    def test_local_socket_failure_aborts(self, _, tcp):
        with self.assertRaisesRegex(RuntimeError, 'socketfout'):
            ipscan.probe_host('192.168.2.1', LOCAL['ip'], '/bin/ping', 0.8)


class DiscoveryTests(unittest.TestCase):
    @patch('ipscan.shutil.which', return_value='/bin/ping')
    def test_remote_subnet_can_be_scanned_from_container(self, _):
        routes = Mock(return_value=json.dumps([ROUTE]))
        get_interfaces = Mock(return_value=[dict(LOCAL)])
        with patch('ipscan.probe_host', return_value=True):
            rows, before, route = ipscan.discover(config(), get_interfaces, routes)
        self.assertEqual({r['ip'] for r in rows}, {'192.168.2.1', '192.168.2.2'})
        self.assertEqual({r['mac'] for r in rows}, {'ip:192.168.2.1', 'ip:192.168.2.2'})
        self.assertEqual(before['ip'], LOCAL['ip'])
        self.assertEqual(route, ROUTE)
        self.assertTrue(all(not r['vendor'] for r in rows))

    @patch('ipscan.shutil.which', return_value=None)
    def test_missing_ping_is_reported(self, _):
        with self.assertRaisesRegex(RuntimeError, 'ping ontbreekt'):
            ipscan.discover(config(), Mock(), Mock())

    @patch('ipscan.shutil.which', return_value='/bin/ping')
    def test_wrong_interface_route_is_rejected(self, _):
        routes = Mock(return_value=json.dumps([{**ROUTE, 'dev': 'wlan0'}]))
        with patch('ipscan.probe_host') as probe:
            with self.assertRaisesRegex(RuntimeError, 'Geen route'):
                ipscan.discover(config(), lambda: [dict(LOCAL)], routes)
            probe.assert_not_called()

    @patch('ipscan.shutil.which', return_value='/bin/ping')
    def test_disconnected_interface_is_rejected(self, _):
        with self.assertRaisesRegex(RuntimeError, 'niet verbonden'):
            ipscan.discover(config(), lambda: [{**LOCAL, 'carrier': False}],
                            lambda _: json.dumps([ROUTE]))

    @patch('ipscan.shutil.which', return_value='/bin/ping')
    def test_missing_guard_aborts_before_scan(self, _):
        with patch('ipscan.probe_host', return_value=False) as probe:
            with self.assertRaisesRegex(RuntimeError, 'Controlehost'):
                ipscan.discover(config(), lambda: [dict(LOCAL)], lambda _: json.dumps([ROUTE]))
            self.assertEqual(probe.call_count, 1)

    @patch('ipscan.shutil.which', return_value='/bin/ping')
    def test_guard_failure_after_scan_rejects_results(self, _):
        calls = []
        def answer(ip, *_):
            calls.append(ip)
            return len(calls) < 4
        with patch('ipscan.probe_host', side_effect=answer):
            with self.assertRaisesRegex(RuntimeError, 'Controlehost'):
                ipscan.discover(config(), lambda: [dict(LOCAL)], lambda _: json.dumps([ROUTE]))
        self.assertEqual(len(calls), 4)

    @patch('ipscan.shutil.which', return_value='/bin/ping')
    def test_route_change_rejects_scan(self, _):
        routes = Mock(side_effect=[json.dumps([ROUTE]), json.dumps([{**ROUTE, 'gateway': '100.115.92.29'}])])
        with patch('ipscan.probe_host', return_value=True):
            with self.assertRaisesRegex(RuntimeError, 'route gewijzigd'):
                ipscan.discover(config(), lambda: [dict(LOCAL)], routes)

    @patch('ipscan.shutil.which', return_value='/bin/ping')
    def test_empty_scan_allowed_when_guard_explicitly_disabled(self, _):
        c = {**config(), 'gateway_guard': False, 'guard_host': ''}
        with patch('ipscan.probe_host', return_value=False) as probe:
            rows, _, _ = ipscan.discover(c, lambda: [dict(LOCAL)], lambda _: json.dumps([ROUTE]))
        self.assertEqual(rows, [])
        self.assertEqual(probe.call_count, 2)

    @patch('ipscan.shutil.which', return_value='/bin/ping')
    def test_final_verification_checks_guard(self, _):
        with patch('ipscan.probe_host', return_value=False):
            with self.assertRaisesRegex(RuntimeError, 'Controlehost'):
                ipscan.verify_connection(config(), LOCAL, ROUTE, lambda: [dict(LOCAL)],
                                         lambda _: json.dumps([ROUTE]))

    def test_final_verification_rejects_changed_route(self):
        with self.assertRaisesRegex(RuntimeError, 'route gewijzigd'):
            ipscan.verify_connection(config(), LOCAL, ROUTE, lambda: [dict(LOCAL)],
                                     lambda _: json.dumps([{**ROUTE, 'dev': 'wlan0'}]))


class IntegrationTests(unittest.TestCase):
    def test_guard_must_be_valid_and_in_target_network(self):
        for value in ('', 'invalid', '10.0.0.1', '::1'):
            with self.subTest(value=value), self.assertRaises(ValueError):
                core.validate_config({**config(), 'guard_host': value})
        core.validate_config(config())
        core.validate_config({**config(), 'gateway_guard': False, 'guard_host': ''})

    def test_old_scopes_and_ip_scopes_are_separate(self):
        c = config()
        old = [c['profile'], c['interface'], c['network']]
        self.assertEqual(json.loads(core.scope({**c, 'scan_mode': 'arp'})), old)
        legacy = dict(c)
        del legacy['scan_mode']
        self.assertEqual(core.scope(legacy), core.scope({**c, 'scan_mode': 'arp'}))
        self.assertEqual(json.loads(core.scope(c)), old + ['ip'])

    def test_unknown_mode_is_rejected(self):
        with self.assertRaises(ValueError):
            core.validate_config({**config(), 'scan_mode': 'invalid'})

    @patch('core.verify_connection')
    @patch('core.enrich')
    @patch('core.discover_ip', return_value=([{'ip': '192.168.2.1'}], LOCAL, ROUTE))
    def test_ip_mode_uses_discovery_then_same_enrichment(self, discover, enrich, verify):
        c = config()
        rows = core.scan(c)
        self.assertEqual(rows, [{'ip': '192.168.2.1'}])
        enrich.assert_called_once_with(rows, c, LOCAL['ip'])
        verify.assert_called_once_with(c, LOCAL, ROUTE, core.interfaces, core.run)

    def test_ip_identity_persists_trust_without_fake_mac_in_webhooks(self):
        c = config()
        c['unknown'] = {**c['unknown'], 'enabled': True, 'url': 'http://localhost/test'}
        c['offline'] = {**c['offline'], 'enabled': True, 'url': 'http://localhost/test'}
        store = core.Store(':memory:')
        try:
            a = {'ip': '192.168.2.1', 'mac': 'ip:192.168.2.1', 'hostname': '', 'vendor': ''}
            b = {'ip': '192.168.2.2', 'mac': 'ip:192.168.2.2', 'hostname': '', 'vendor': ''}
            self.assertEqual(len(store.apply_scan(c, [a, b])), 2)
            store.edit(core.scope(c), a['mac'], 'Router', True, True)
            self.assertEqual(store.apply_scan(c, [a, b]), [])
            for _ in range(c['misses']):
                store.apply_scan(c, [b])
            events = [json.loads(r['payload']) for r in store.db.execute('SELECT payload FROM outbox')]
            self.assertEqual(len(events), 3)
            self.assertEqual(events[-1]['event'], 'offline')
            self.assertTrue(all(p['mac'] == '' for p in events))
            self.assertTrue(all(p['device_id'].startswith('ip:') for p in events))
            self.assertTrue(all('ip:192' not in p['message'] for p in events))
            self.assertEqual(store.apply_scan(c, [a, b]), [])
            row = next(h for h in store.hosts(core.scope(c)) if h['mac'] == a['mac'])
            self.assertEqual((row['known'], row['label'], row['online']), (1, 'Router', 1))
            self.assertEqual(core.mac_address(row), '')
            self.assertEqual(core.mac_address({'mac': LOCAL['mac']}), LOCAL['mac'])
        finally:
            store.close()


if __name__ == '__main__':
    unittest.main()
