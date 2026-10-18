"""Controleer GUI-callbacks met echte opslag, zonder displayserver."""
import sys
from pathlib import Path
from types import SimpleNamespace, MethodType
from unittest.mock import Mock
import tempfile
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from core import Store, default_config, scope
from netwerkwacht import App


class CheckboxTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = Store(Path(self.tmp.name) / 'db')
        self.config = default_config()
        self.mac = '00:11:22:33:44:55'
        self.store.apply_scan(self.config, [{'mac': self.mac, 'ip': '192.168.2.10',
                                           'hostname': 'NAS', 'vendor': 'Test'}])
        tree = Mock()
        tree.identify_region.return_value = 'tree'
        tree.identify_column.return_value = '#0'
        tree.identify_row.return_value = self.mac
        tree.selection.return_value = (self.mac,)
        tree.xview.return_value = (0, 1)
        tree.yview.return_value = (0, 1)
        self.app = SimpleNamespace(tree=tree, store=self.store, config=self.config,
                                   refresh=Mock(), status=Mock(), edit_host=Mock())
        self.app.toggle_known = MethodType(App.toggle_known, self.app)
        self.event = SimpleNamespace(x=35, y=45)

    def tearDown(self):
        self.store.close()
        self.tmp.cleanup()

    def row(self):
        return self.store.hosts(scope(self.config))[0]

    def test_mouse_click_checks_and_unchecks_and_persists(self):
        self.assertEqual(App.on_device_click(self.app, self.event), 'break')
        self.assertEqual(self.row()['known'], 1)
        App.on_device_click(self.app, self.event)
        self.assertEqual(self.row()['known'], 0)

    def test_heading_and_other_columns_do_not_toggle(self):
        self.app.tree.identify_region.return_value = 'heading'
        App.on_device_click(self.app, self.event)
        self.app.tree.identify_region.return_value = 'cell'
        self.app.tree.identify_column.return_value = '#1'
        App.on_device_click(self.app, self.event)
        self.assertEqual(self.row()['known'], 0)

    def test_double_click_does_not_toggle_back_or_open_editor(self):
        App.on_device_click(self.app, self.event)
        App.on_device_double_click(self.app, self.event)
        self.assertEqual(self.row()['known'], 1)
        self.app.edit_host.assert_not_called()

    def test_space_unchecks_and_disables_monitor_preserving_label(self):
        self.store.edit(scope(self.config), self.mac, 'Mijn NAS', True, True)
        App.on_device_space(self.app, self.event)
        row = self.row()
        self.assertEqual((row['known'], row['monitor'], row['label']), (0, 0, 'Mijn NAS'))

    def test_double_click_other_cell_opens_editor(self):
        self.app.tree.identify_region.return_value = 'cell'
        self.app.tree.identify_column.return_value = '#1'
        App.on_device_double_click(self.app, self.event)
        self.app.edit_host.assert_called_once()
