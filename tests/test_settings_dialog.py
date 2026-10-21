"""Exercise the real settings widgets on Xvfb, without scanning any network."""
import json
import os
from pathlib import Path
import sys
import tempfile
import tkinter as tk
from tkinter import ttk
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from core import default_config, save_config
from netwerkwacht import App, SettingsNotebook


@unittest.skipUnless(os.environ.get('DISPLAY'), 'Real widget tests require a display (xvfb-run).')
class SettingsDialogTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = tk.Tk()
        ttk.Style(self.root).theme_use('clam')
        self.root.geometry('1000x700+40+40')
        self.root.busy = False
        self.root.config = default_config()
        self.root.config.update(interface='eth0', network='192.168.2.0/24')
        self.root.config_path = Path(self.tmp.name) / 'config.json'
        save_config(self.root.config_path, self.root.config)
        self.original = self.root.config_path.read_bytes()
        self.root.refresh = Mock()
        self.root.status = tk.StringVar(master=self.root)
        self.root.update()
        self.errors = []
        self.root.report_callback_exception = lambda *args: self.errors.append(args)
        self.interfaces = patch('netwerkwacht.interfaces', return_value=[])
        self.interfaces.start()
        App.settings(self.root)
        self.win = self.root.settings_window
        self.tabs = next(w for w in self.win.winfo_children() if isinstance(w, SettingsNotebook))
        self.root.update()

    def tearDown(self):
        self.interfaces.stop()
        self.root.destroy()
        self.tmp.cleanup()

    def click_tab(self, index):
        # Find the real rendered tab, so the test also covers hit testing.
        for x in range(self.tabs.winfo_width()):
            try:
                found = self.tabs.index(f'@{x},10')
            except tk.TclError:
                continue
            if found == index:
                self.tabs.event_generate('<ButtonPress-1>', x=x, y=10)
                self.tabs.event_generate('<ButtonRelease-1>', x=x, y=10)
                self.root.update()
                return
        self.fail(f'Tab {index} has no clickable header')

    def profile_entry(self):
        page = self.win.nametowidget(self.tabs.tabs()[0])
        return next(w for w in page.body.winfo_children() if isinstance(w, ttk.Entry))

    def test_all_five_tabs_select_by_mouse_and_show_their_content(self):
        self.assertEqual(len(self.tabs.tabs()), 5)
        self.assertEqual(self.win.grab_current(), self.win)
        for index in (1, 2, 3, 4, 0):
            self.click_tab(index)
            self.assertEqual(self.tabs.index(self.tabs.select()), index)
            page = self.win.nametowidget(self.tabs.select())
            self.assertTrue(page.body.winfo_ismapped())
        self.assertEqual(self.errors, [])

    def test_mouse_selection_works_without_notebook_class_binding(self):
        # A widget-level handler must still work when the class binding is absent.
        self.tabs.bindtags(tuple(t for t in self.tabs.bindtags() if t != 'TNotebook'))
        self.click_tab(3)
        self.assertEqual(self.tabs.index(self.tabs.select()), 3)
        self.click_tab(0)
        self.assertEqual(self.tabs.index(self.tabs.select()), 0)
        self.assertEqual(self.errors, [])

    def test_buttons_stay_visible_when_window_is_small(self):
        self.win.geometry('640x380')
        self.root.update()
        for name in ('cancel', 'save'):
            button = self.win.nametowidget(f'{self.win}.actions.{name}')
            self.assertTrue(button.winfo_ismapped())
            top = button.winfo_rooty() - self.win.winfo_rooty()
            self.assertGreaterEqual(top, 0)
            self.assertLessEqual(top + button.winfo_height(), self.win.winfo_height())
        self.assertEqual(self.errors, [])

    def test_cancel_discards_edits_even_with_invalid_trigger_json(self):
        entry = self.profile_entry()
        entry.delete(0, 'end')
        entry.insert(0, 'Discard this profile')
        self.click_tab(3)
        page = self.win.nametowidget(self.tabs.select())
        editor = next(w for w in page.body.winfo_children() if isinstance(w, tk.Text))
        editor.delete('1.0', 'end')
        editor.insert('1.0', 'invalid JSON')
        self.win.nametowidget(f'{self.win}.actions.cancel').invoke()
        self.root.update()
        self.assertFalse(self.root.settings_open)
        self.assertIsNone(self.root.settings_window)
        self.assertEqual(self.root.config['profile'], 'Mijn netwerk')
        self.assertEqual(self.root.config_path.read_bytes(), self.original)
        self.root.refresh.assert_not_called()
        self.assertIsNone(self.root.grab_current())
        self.assertEqual(self.errors, [])

    def test_escape_discards_edits_and_reopening_does_not_duplicate(self):
        App.settings(self.root)
        self.assertIs(self.root.settings_window, self.win)
        entry = self.profile_entry()
        entry.delete(0, 'end')
        entry.insert(0, 'Discard on Escape')
        self.win.focus_force()
        self.root.update()
        self.win.event_generate('<Escape>')
        self.root.update()
        self.assertFalse(self.root.settings_open)
        self.assertEqual(self.root.config_path.read_bytes(), self.original)
        App.settings(self.root)
        self.assertIsNot(self.root.settings_window, self.win)
        self.assertTrue(self.root.settings_open)
        self.assertEqual(self.errors, [])

    def test_save_still_persists_settings(self):
        entry = self.profile_entry()
        entry.delete(0, 'end')
        entry.insert(0, 'Saved profile')
        self.win.nametowidget(f'{self.win}.actions.save').invoke()
        self.root.update()
        saved = json.loads(self.root.config_path.read_text())
        self.assertEqual(saved['profile'], 'Saved profile')
        self.assertEqual(self.root.config['profile'], 'Saved profile')
        self.root.refresh.assert_called_once()
        self.assertFalse(self.root.settings_open)
        self.assertEqual(self.errors, [])


if __name__ == '__main__':
    unittest.main()
