import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from host_actions import available_actions, action_command, launch_action


def installed(name):
    return '/usr/bin/' + name if name in ('kitty', 'ssh', 'telnet', 'ftp', 'vncviewer', 'xdg-open') else None


class HostActionTests(unittest.TestCase):
    def test_only_supported_confirmed_open_tcp_ports(self):
        rows = [{'port': 22, 'protocol': 'tcp', 'state': 'open'},
                {'port': 22, 'protocol': 'tcp', 'state': 'open'},
                {'port': 23, 'protocol': 'tcp', 'state': 'closed'},
                {'port': 80, 'protocol': 'tcp', 'state': 'uncertain'},
                {'port': 443, 'protocol': 'udp', 'state': 'open'},
                {'port': 993, 'protocol': 'tcp', 'state': 'open'}]
        self.assertEqual(available_actions({'port_results': json.dumps(rows)}), [(22, 'SSH-sessie starten', 'ssh')])
        self.assertEqual(available_actions({}), [])

    @patch('host_actions.shutil.which', side_effect=installed)
    def test_ssh_username_is_separate_argument(self, _):
        command = action_command('192.168.2.25', 22, 'ssh', 'jan')
        self.assertEqual(command[0], '/usr/bin/kitty')
        self.assertEqual(command[-6:], ['/usr/bin/ssh', '-p', '22', '-l', 'jan', '192.168.2.25'])

    @patch('host_actions.shutil.which', side_effect=installed)
    def test_optional_username_uses_client_default(self, _):
        self.assertEqual(action_command('192.168.2.25', 22, 'ssh')[-4:], ['/usr/bin/ssh', '-p', '22', '192.168.2.25'])

    @patch('host_actions.shutil.which', side_effect=installed)
    def test_reject_injection_and_mismatched_service(self, _):
        for ip, port, kind, user in [('host; touch /tmp/x', 22, 'ssh', ''),
                                     ('192.0.2.1', 22, 'ssh', 'jan; whoami'),
                                     ('192.0.2.1', 22, 'http', '')]:
            with self.assertRaises(ValueError):
                action_command(ip, port, kind, user)

    @patch('host_actions.shutil.which', side_effect=installed)
    def test_http_and_https_alt_ports(self, _):
        self.assertEqual(action_command('192.0.2.1', 8080, 'http'), ['/usr/bin/xdg-open', 'http://192.0.2.1:8080/'])
        self.assertEqual(action_command('192.0.2.1', 8443, 'https'), ['/usr/bin/xdg-open', 'https://192.0.2.1:8443/'])

    @patch('host_actions.shutil.which', side_effect=installed)
    def test_ftp_telnet_smb_and_vnc(self, _):
        self.assertEqual(action_command('192.0.2.1', 21, 'ftp')[-3:], ['/usr/bin/ftp', '192.0.2.1', '21'])
        self.assertEqual(action_command('192.0.2.1', 23, 'telnet')[-3:], ['/usr/bin/telnet', '192.0.2.1', '23'])
        self.assertEqual(action_command('192.0.2.1', 445, 'smb'), ['/usr/bin/xdg-open', 'smb://192.0.2.1/'])
        self.assertEqual(action_command('192.0.2.1', 5900, 'vnc'), ['/usr/bin/vncviewer', '192.0.2.1::5900'])

    @patch('host_actions.shutil.which', return_value=None)
    def test_missing_client_is_explained(self, _):
        with self.assertRaisesRegex(ValueError, 'ssh ontbreekt'):
            action_command('192.0.2.1', 22, 'ssh')

    def test_gnome_terminal_fallback(self):
        with patch('host_actions.shutil.which', side_effect=lambda name: '/usr/bin/' + name if name in ('ssh', 'gnome-terminal') else None):
            command = action_command('192.0.2.1', 22, 'ssh')
        self.assertEqual(command[:2], ['/usr/bin/gnome-terminal', '--'])

    @patch('host_actions.shutil.which', side_effect=installed)
    @patch('host_actions.subprocess.Popen')
    def test_launch_is_detached_and_does_not_use_shell(self, popen, _):
        launch_action('192.0.2.1', 80, 'http')
        args, kwargs = popen.call_args
        self.assertEqual(args[0], ['/usr/bin/xdg-open', 'http://192.0.2.1:80/'])
        self.assertFalse(kwargs.get('shell', False))
        self.assertTrue(kwargs['start_new_session'])

class ContextMenuTests(unittest.TestCase):
    def test_popup_stays_alive_and_selects_right_clicked_host(self):
        from types import SimpleNamespace
        from unittest.mock import Mock
        from netwerkwacht import App
        tree, store, menu = Mock(), Mock(), Mock()
        tree.identify_region.return_value = 'cell'
        tree.identify_row.return_value = 'aa:bb:cc:dd:ee:ff'
        host = {'mac': 'aa:bb:cc:dd:ee:ff', 'ip': '192.0.2.1', 'label': '', 'hostname': '',
                'port_checked': 'test', 'online': 1, 'misses': 0,
                'port_results': '[{"port":22,"protocol":"tcp","state":"open"}]'}
        store.hosts.return_value = [host]
        app = SimpleNamespace(tree=tree, store=store, config={'profile':'Test','interface':'eth0','network':'192.0.2.0/24'},
                              port_details=Mock(), edit_host=Mock())
        event = SimpleNamespace(x=1, y=2, x_root=100, y_root=200)
        with patch('netwerkwacht.tk.Menu', return_value=menu):
            self.assertEqual(App.host_menu(app, event), 'break')
        tree.selection_set.assert_called_once_with(host['mac'])
        menu.tk_popup.assert_called_once_with(100, 200)
        menu.destroy.assert_not_called()
        self.assertIs(app._host_popup, menu)

    def test_cancel_ssh_dialog_starts_nothing(self):
        from types import SimpleNamespace
        from netwerkwacht import App
        with patch('netwerkwacht.simpledialog.askstring', return_value=None), patch('netwerkwacht.launch_action') as launch:
            App.open_host_action(SimpleNamespace(), {'ip': '192.0.2.1'}, 22, 'ssh')
            launch.assert_not_called()
