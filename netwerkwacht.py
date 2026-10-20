#!/usr/bin/env python3
"""Start met python3 netwerkwacht.py. Geen pip-afhankelijkheden."""
import csv
import fcntl
import ipaddress
import json
import os
from pathlib import Path
import queue
import shutil
import subprocess
import threading
import time
import tkinter as tk
from tkinter import ttk, messagebox, filedialog, simpledialog
import uuid
from host_actions import available_actions, launch_action
from ports import TCP_PORTS, UDP_PORTS, decode_results, port_summary

from core import (Store, Dispatcher, default_config, interfaces, now, post,
                  save_config, scan, scope, validate_config, validate_trigger)


class ScrollableSettingsPage(ttk.Frame):
    """Keep settings accessible when the display is smaller than the form."""

    def __init__(self, parent, padding=16):
        super().__init__(parent)
        self.rowconfigure(0, weight=1)
        self.columnconfigure(0, weight=1)
        self.canvas = tk.Canvas(self, width=1, height=1, highlightthickness=0)
        vertical = ttk.Scrollbar(self, orient='vertical', command=self.canvas.yview)
        horizontal = ttk.Scrollbar(self, orient='horizontal', command=self.canvas.xview)
        self.canvas.configure(yscrollcommand=vertical.set, xscrollcommand=horizontal.set)
        self.canvas.grid(row=0, column=0, sticky='nsew')
        vertical.grid(row=0, column=1, sticky='ns')
        horizontal.grid(row=1, column=0, sticky='ew')
        self.body = ttk.Frame(self.canvas, padding=padding)
        self.body_id = self.canvas.create_window(0, 0, anchor='nw', window=self.body)
        self.body.bind('<Configure>', self._resize)
        self.canvas.bind('<Configure>', self._resize)

    def _resize(self, _event=None):
        width = max(self.canvas.winfo_width(), self.body.winfo_reqwidth())
        if int(float(self.canvas.itemcget(self.body_id, 'width'))) != width:
            self.canvas.itemconfigure(self.body_id, width=width)
        self.canvas.configure(scrollregion=self.canvas.bbox('all'))

    def reveal(self, widget):
        if not str(widget).startswith(str(self.body) + '.'):
            return
        top = widget.winfo_rooty() - self.body.winfo_rooty()
        bottom = top + widget.winfo_height()
        visible_top = self.canvas.canvasy(0)
        height = self.canvas.winfo_height()
        total = max(1, self.body.winfo_height())
        if top < visible_top:
            self.canvas.yview_moveto(max(0, top - 8) / total)
        elif bottom > visible_top + height:
            self.canvas.yview_moveto(max(0, bottom - height + 8) / total)


class App(tk.Tk):
    def __init__(self, folder):
        super().__init__()
        self.title('NetworkWatch 1.5 • Linux netwerkmonitor')
        self.geometry('1250x760')
        self.minsize(900, 550)
        self.folder = folder
        self.config_path = folder / 'config.json'
        self.db_path = folder / 'devices.sqlite3'
        self.config = default_config()
        if self.config_path.exists():
            try:
                self.config.update(json.loads(self.config_path.read_text()))
            except (ValueError, OSError) as e:
                messagebox.showerror('Instellingen', f'Instellingen konden niet worden gelezen: {e}')
                self.destroy()
                raise SystemExit(1)
        self.store = Store(self.db_path)
        self.messages = queue.Queue()
        self.busy = False
        self.next_scan = None
        self.paused = tk.BooleanVar(value=False)
        self.stop_event = threading.Event()
        self.dispatcher = Dispatcher(self.db_path, self.stop_event)
        self.dispatcher.start()
        self.sort_key, self.reverse = 'ip', False
        self.build()
        self.protocol('WM_DELETE_WINDOW', self.close)
        self.refresh()
        self.after(150, self.poll)
        if not self.config['interface']:
            self.after(250, self.settings)
        else:
            self.after(250, self.start_scan)

    def build(self):
        style = ttk.Style(self)
        style.theme_use('clam')
        style.configure('Treeview', rowheight=29, font=('Sans', 10))
        style.configure('Treeview.Heading', font=('Sans', 10, 'bold'))
        style.configure('TButton', padding=7)
        style.configure('Title.TLabel', font=('Sans', 23, 'bold'))
        outer = ttk.Frame(self, padding=18)
        outer.pack(fill='both', expand=True)
        ttk.Label(outer, text='NetworkWatch 1.5', style='Title.TLabel').pack(anchor='w')
        self.summary = tk.StringVar()
        ttk.Label(outer, textvariable=self.summary).pack(anchor='w', pady=(4, 14))
        bar = ttk.Frame(outer)
        bar.pack(fill='x')
        self.scan_button = ttk.Button(bar, text='▶ Scan nu', command=self.start_scan)
        self.scan_button.pack(side='left')
        self.settings_button = ttk.Button(bar, text='Instellingen & triggers', command=self.settings)
        self.settings_button.pack(side='left', padx=8)
        ttk.Button(bar, text='Apparaat bewerken', command=self.edit_host).pack(side='left')
        ttk.Button(bar, text='Exporteer CSV', command=self.export).pack(side='left', padx=8)
        ttk.Button(bar, text='Poortdetails', command=self.port_details).pack(side='left')
        ttk.Checkbutton(bar, text='Pauzeer scans', variable=self.paused).pack(side='right')
        self.tabs = ttk.Notebook(outer)
        self.tabs.pack(fill='both', expand=True, pady=14)
        devices = ttk.Frame(self.tabs, padding=8)
        self.tabs.add(devices, text='Apparaten')
        filters = ttk.Frame(devices)
        filters.pack(fill='x', pady=(0, 10))
        ttk.Label(filters, text='Zoeken:').pack(side='left')
        self.search = tk.StringVar()
        ttk.Entry(filters, textvariable=self.search, width=32).pack(side='left', padx=8)
        self.search.trace_add('write', lambda *_: self.refresh())
        self.filter = tk.StringVar(value='Alle apparaten')
        ttk.Combobox(filters, textvariable=self.filter, state='readonly', width=23,
                     values=['Alle apparaten', 'Onbekend', 'Online', 'Offline', 'Offlinebewaking']).pack(side='left')
        self.filter.trace_add('write', lambda *_: self.refresh())
        columns = ('state', 'monitor', 'ip', 'os_guess', 'port_open', 'udp_uncertain', 'port_checked', 'mac', 'label', 'hostname', 'vendor', 'last_seen')
        labels = ('Status', 'Bewaken', 'IP-adres', 'Vermoedelijk OS', 'Open poorten (bevestigd)', 'UDP onzeker', 'Poortcheck (UTC)', 'MAC-adres', 'Eigen naam', 'Hostnaam', 'Fabrikant', 'Laatst gezien (UTC)')
        widths = (125, 70, 120, 190, 390, 180, 180, 150, 140, 150, 150, 175)
        frame = ttk.Frame(devices)
        frame.pack(fill='both', expand=True)
        self.tree = ttk.Treeview(frame, columns=columns, show='tree headings', selectmode='browse')
        # Tk ondersteunt afbeeldingen alleen in de boomkolom (#0). Gebruik die
        # als eerste kolom Bekend, met eigen pixels in plaats van fontsymbolen.
        self.known_images = {False: self.checkbox_image(False), True: self.checkbox_image(True)}
        self.tree.heading('#0', text='Bekend', command=lambda: self.sort('known'))
        self.tree.column('#0', width=85, minwidth=75, stretch=False)
        for col, label, width in zip(columns, labels, widths):
            self.tree.heading(col, text=label, command=lambda c=col: self.sort(c))
            self.tree.column(col, width=width, minwidth=55, stretch=False)
        self.tree.tag_configure('unknown', foreground='#b42318')
        self.tree.tag_configure('known', foreground='#167044')
        self.tree.tag_configure('offline', foreground='#697586')
        y = ttk.Scrollbar(frame, orient='vertical', command=self.tree.yview)
        x = ttk.Scrollbar(frame, orient='horizontal', command=self.tree.xview)
        self.tree.configure(yscrollcommand=y.set, xscrollcommand=x.set)
        self.tree.grid(row=0, column=0, sticky='nsew')
        y.grid(row=0, column=1, sticky='ns')
        x.grid(row=1, column=0, sticky='ew')
        frame.rowconfigure(0, weight=1)
        frame.columnconfigure(0, weight=1)
        self.tree.bind('<Button-1>', self.on_device_click)
        self.tree.bind('<Double-1>', self.on_device_double_click)
        self.tree.bind('<space>', self.on_device_space)
        self.tree.bind('<Button-3>', self.host_menu)
        ttk.Label(devices, text='Klik op het vakje in Bekend om een apparaat te herkennen. '
                  'Rechtsklik voor verbindingen; spatie wisselt de geselecteerde rij.').pack(anchor='w', pady=(8, 0))
        log = ttk.Frame(self.tabs, padding=8)
        self.tabs.add(log, text='Gebeurtenissen & HTTP-status')
        self.events = ttk.Treeview(log, columns=('time', 'kind', 'message', 'http'), show='headings')
        for col, label, width in [('time', 'UTC', 180), ('kind', 'Event', 80),
                                  ('message', 'Melding', 570), ('http', 'HTTP-status', 220)]:
            self.events.heading(col, text=label)
            self.events.column(col, width=width)
        self.events.pack(side='left', fill='both', expand=True)
        scrollbar = ttk.Scrollbar(log, command=self.events.yview)
        scrollbar.pack(side='right', fill='y')
        self.events.configure(yscrollcommand=scrollbar.set)
        footer = ttk.Frame(outer)
        footer.pack(fill='x')
        self.status = tk.StringVar(value='Kies de netwerkinterface bij Instellingen.')
        ttk.Label(footer, textvariable=self.status, wraplength=1000).pack(anchor='w')
        self.countdown = tk.StringVar()
        ttk.Label(footer, textvariable=self.countdown).pack(anchor='w', pady=4)
        self.progress = ttk.Progressbar(footer, mode='indeterminate')
        self.progress.pack(fill='x')

    def host_menu(self, event):
        if self.tree.identify_region(event.x, event.y) not in ('cell', 'tree'):
            return
        mac = self.tree.identify_row(event.y)
        if not mac:
            return
        self.tree.selection_set(mac)
        self.tree.focus(mac)
        self.tree.focus_set()
        host = next((h for h in self.store.hosts(scope(self.config)) if h['mac'] == mac), None)
        if host is None:
            return
        if getattr(self, '_host_popup', None) is not None:
            self._host_popup.destroy()
        menu = self._host_popup = tk.Menu(self, tearoff=False)
        menu.add_command(label=f"{host['label'] or host['hostname'] or host['ip']} — {host['ip']}", state='disabled')
        menu.add_command(label='Poortmeting: ' + (host['port_checked'] or 'nog niet uitgevoerd'), state='disabled')
        if not host['online'] or host['misses']:
            menu.add_command(label='Niet gezien in laatste scan; acties gebruiken eerdere poortmeting', state='disabled')
        menu.add_separator()
        actions = available_actions(host)
        for port, label, kind in actions:
            menu.add_command(label=f'{label} ({port}/tcp)',
                command=lambda p=port, k=kind, h=dict(host): self.open_host_action(h, p, k))
        if not actions:
            menu.add_command(label='Geen open poorten met een beschikbare snelactie', state='disabled')
        menu.add_separator()
        menu.add_command(label='IP-adres kopiëren', command=lambda: self.copy_host_ip(host['ip']))
        menu.add_command(label='Poortdetails', command=self.port_details)
        menu.add_command(label='Apparaat bewerken', command=self.edit_host)
        try:
            menu.tk_popup(event.x_root, event.y_root)
        finally:
            menu.grab_release()
        return 'break'

    def copy_host_ip(self, ip):
        self.clipboard_clear()
        self.clipboard_append(ip)
        self.status.set(f'IP-adres gekopieerd: {ip}')

    def open_host_action(self, host, port, kind):
        username = ''
        if kind == 'ssh':
            username = simpledialog.askstring('SSH-sessie',
                f"Verbinden met {host['ip']}:{port}\nGebruikersnaam (leeg = standaard van SSH):", parent=self)
            if username is None:
                return
        try:
            process = launch_action(host['ip'], port, kind, username)
        except (ValueError, OSError) as exc:
            messagebox.showerror('Verbinding starten', str(exc), parent=self)
            return
        self.status.set(f'Startopdracht verstuurd: {kind.upper()} naar {host["ip"]}:{port}')
        def check_started():
            code = process.poll()
            if code is not None and code != 0:
                messagebox.showerror('Verbinding starten',
                    f'De lokale client/opener stopte met exitcode {code}. '
                    'Controleer of een geschikte applicatie is geïnstalleerd en ingesteld.', parent=self)
        self.after(1200, check_started)

    def checkbox_image(self, checked):
        image = tk.PhotoImage(master=self, width=22, height=22)
        image.put('#526477', to=(1, 1, 21, 21))
        image.put('#16834a' if checked else '#ffffff', to=(3, 3, 19, 19))
        if checked:
            # Een wit vinkje, getekend met pixels: onafhankelijk van lettertypes.
            for x, y in [(5, 10), (6, 11), (7, 12), (8, 13), (9, 12),
                         (10, 11), (11, 10), (12, 9), (13, 8), (14, 7), (15, 6)]:
                image.put('#ffffff', to=(x, y, x + 2, y + 3))
        return image

    def sort(self, key):
        self.reverse = not self.reverse if key == self.sort_key else False
        self.sort_key = key
        self.refresh()

    def on_device_click(self, event):
        if (self.tree.identify_region(event.x, event.y) == 'tree'
                and self.tree.identify_column(event.x) == '#0'):
            mac = self.tree.identify_row(event.y)
            if mac:
                self.tree.selection_set(mac)
                self.tree.focus(mac)
                self.tree.focus_set()
                self.toggle_known(mac)
            return 'break'

    def on_device_double_click(self, event):
        # De eerste klik heeft het vakje al omgezet: niet opnieuw omzetten.
        if self.tree.identify_region(event.x, event.y) not in ('cell', 'tree'):
            return 'break'
        if self.tree.identify_column(event.x) != '#0':
            mac = self.tree.identify_row(event.y)
            if mac:
                self.tree.selection_set(mac)
                if self.tree.identify_column(event.x) in ('#5', '#6', '#7'):
                    self.port_details()
                else:
                    self.edit_host()
        return 'break'

    def on_device_space(self, _event):
        selected = self.tree.selection()
        if selected:
            self.toggle_known(selected[0])
        return 'break'

    def toggle_known(self, mac):
        h = next((h for h in self.store.hosts(scope(self.config)) if h['mac'] == mac), None)
        if h is None:
            return
        known = not h['known']
        # Gebruik dezelfde opslagregels als het bewerkvenster. Onbekende
        # apparaten mogen geen offlinebewaking houden.
        self.store.edit(scope(self.config), mac, h['label'], known, h['monitor'])
        x, y = self.tree.xview()[0], self.tree.yview()[0]
        self.refresh()
        self.tree.xview_moveto(x)
        self.tree.yview_moveto(y)
        if self.tree.exists(mac):
            self.tree.focus(mac)
        name = h['label'] or h['hostname'] or h['ip']
        self.status.set(f"{name}: {'bekend' if known else 'onbekend'} — opgeslagen."
                        + (' Offlinebewaking uitgeschakeld.' if not known and h['monitor'] else ''))

    def refresh(self):
        hosts = self.store.hosts(scope(self.config))
        online = sum(h['online'] for h in hosts)
        unknown = sum(not h['known'] for h in hosts)
        self.summary.set(f"{self.config['profile']}  •  {self.config['interface'] or 'Geen interface'}  •  "
                         f"{self.config['network']}    |    {online} online    {unknown} onbekend    {len(hosts)} opgeslagen")
        selected = self.tree.selection()
        self.tree.delete(*self.tree.get_children())
        def key(h):
            if self.sort_key == 'ip':
                return int(ipaddress.ip_address(h['ip']))
            if self.sort_key in ('port_open', 'udp_uncertain'):
                return port_summary(h['port_results'])[0 if self.sort_key == 'port_open' else 1]
            if self.sort_key == 'state':
                return (h['online'], -h['misses'])
            return h.get(self.sort_key, '')
        for h in sorted(hosts, key=key, reverse=self.reverse):
            if self.search.get().lower() not in ' '.join(map(str, h.values())).lower():
                continue
            f = self.filter.get()
            if ((f == 'Onbekend' and h['known']) or (f == 'Online' and not h['online'])
                    or (f == 'Offline' and h['online']) or (f == 'Offlinebewaking' and not h['monitor'])):
                continue
            state = 'Offline' if not h['online'] else ('Online' if not h['misses'] else f"Gemist ({h['misses']})")
            tag = 'offline' if not h['online'] else ('known' if h['known'] else 'unknown')
            opened, uncertain = port_summary(h['port_results'])
            if h['port_checked'] and (not h['online'] or h['misses']):
                opened = 'Laatste: ' + opened
            self.tree.insert('', 'end', iid=h['mac'], tags=(tag,),
                image=self.known_images[bool(h['known'])], values=(state,
                'Ja' if h['monitor'] else 'Nee', h['ip'],
                ('Laatste: ' if h['os_checked'] and (not h['online'] or h['misses']) else '')
                + (h['os_guess'] or 'Nog niet gecontroleerd'), opened, uncertain, h['port_checked'], h['mac'],
                h['label'], h['hostname'], h['vendor'], h['last_seen']))
        if selected and self.tree.exists(selected[0]):
            self.tree.selection_set(selected)
        self.refresh_events()

    def refresh_events(self):
        self.events.delete(*self.events.get_children())
        rows = self.store.db.execute('''SELECT e.*,o.status,o.result,o.attempts FROM events e
          LEFT JOIN outbox o ON e.id=o.id WHERE e.scope=? ORDER BY e.time DESC,e.rowid DESC LIMIT 500''',
          (scope(self.config),))
        for r in rows:
            http = 'Trigger uit' if not r['status'] else f"{r['status']} ({r['attempts']}×) {r['result']}"
            self.events.insert('', 'end', values=(r['time'], r['kind'], r['message'], http))

    def start_scan(self):
        if self.busy or getattr(self, 'settings_open', False):
            return
        try:
            validate_config(self.config)
        except Exception as e:
            messagebox.showerror('Instellingen nodig', str(e))
            return
        self.busy = True
        self.next_scan = None
        self.scan_button.state(['disabled'])
        self.settings_button.state(['disabled'])
        self.progress.start(12)
        self.status.set('Netwerkscan bezig: ARP-detectie, hostnamen en (indien aan) TCP/UDP-poortcontrole en OS-herkenning…')
        config = json.loads(json.dumps(self.config))
        def worker():
            try:
                self.messages.put(('scan', scan(config)))
            except Exception as e:
                self.messages.put(('error', str(e)))
        threading.Thread(target=worker, daemon=True).start()

    def poll(self):
        try:
            while True:
                kind, data = self.messages.get_nowait()
                if kind == 'test':
                    messagebox.showinfo('HTTP-test', data)
                    continue
                self.busy = False
                self.progress.stop()
                self.scan_button.state(['!disabled'])
                self.settings_button.state(['!disabled'])
                self.next_scan = time.monotonic() + self.config['interval'] if self.config['interval'] else None
                if kind == 'error':
                    self.status.set(f'Scan mislukt — geen statuswijzigingen: {data}')
                else:
                    try:
                        alerts = self.store.apply_scan(self.config, data)
                        self.status.set(f'{now()} • Scan klaar: {len(data)} apparaten gevonden; {len(alerts)} meldingen.')
                        if alerts and self.config['sound']:
                            self.bell()
                        if alerts:
                            self.title(f'({len(alerts)} meldingen) NetworkWatch 1.5')
                            if shutil.which('notify-send'):
                                def notify(text='\n'.join(alerts[:5])):
                                    try:
                                        subprocess.run(['notify-send', 'NetworkWatch', text], timeout=5,
                                                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                                    except (OSError, subprocess.TimeoutExpired):
                                        pass
                                threading.Thread(target=notify, daemon=True).start()
                        self.refresh()
                    except Exception as e:
                        self.status.set(f'Opslag mislukt: {e}')
        except queue.Empty:
            pass
        if self.paused.get():
            self.countdown.set('Automatische scans gepauzeerd. HTTP-wachtrij blijft actief.')
        elif self.busy:
            self.countdown.set('Scannen…')
        elif self.next_scan is not None:
            left = max(0, int(self.next_scan - time.monotonic()))
            self.countdown.set(f'Volgende scan over {left // 60:02}:{left % 60:02}')
            if time.monotonic() >= self.next_scan:
                self.start_scan()
        else:
            self.countdown.set('Handmatige scanmodus')
        if int(time.monotonic()) % 5 == 0:
            self.refresh_events()
        self.after(500, self.poll)

    def port_details(self):
        selected = self.tree.selection()
        if not selected:
            return
        h = next((h for h in self.store.hosts(scope(self.config)) if h['mac'] == selected[0]), None)
        if h is None:
            return
        win = tk.Toplevel(self)
        win.title(f"Poortdetails — {h['label'] or h['hostname'] or h['ip']}")
        win.geometry('850x590')
        ttk.Label(win, padding=12, text=f"{h['ip']}  •  {h['mac']}\nLaatste poortcheck (UTC): "
            + (h['port_checked'] or 'Nog niet gecontroleerd')
            + '\nDit zijn meetresultaten op dat tijdstip; servicebenamingen zijn indicatief.').pack(anchor='w')
        frame = ttk.Frame(win, padding=12)
        frame.pack(fill='both', expand=True)
        tree = ttk.Treeview(frame, columns=('port', 'protocol', 'service', 'state', 'reason'), show='headings')
        for key, label, width in [('port', 'Poort', 60), ('protocol', 'Protocol', 70),
                                  ('service', 'Gebruikelijke service', 155), ('state', 'Status', 90),
                                  ('reason', 'Toelichting', 360)]:
            tree.heading(key, text=label)
            tree.column(key, width=width)
        scroll = ttk.Scrollbar(frame, command=tree.yview)
        tree.configure(yscrollcommand=scroll.set)
        scroll.pack(side='right', fill='y')
        tree.pack(fill='both', expand=True)
        states = {'open': 'Open', 'closed': 'Gesloten', 'uncertain': 'Onzeker', 'error': 'Fout'}
        for r in sorted(decode_results(h['port_results']), key=lambda r: (r['port'], r['protocol'])):
            service = (TCP_PORTS if r['protocol'] == 'tcp' else UDP_PORTS).get(r['port'], '')
            tree.insert('', 'end', values=(r['port'], r['protocol'].upper(), service,
                                          states[r['state']], r['reason']))

    def edit_host(self):
        selected = self.tree.selection()
        if not selected:
            return
        h = next(h for h in self.store.hosts(scope(self.config)) if h['mac'] == selected[0])
        win = tk.Toplevel(self)
        win.title('Apparaat herkennen en bewaken')
        win.transient(self)
        win.grab_set()
        form = ttk.Frame(win, padding=20)
        form.pack(fill='both', expand=True)
        ttk.Label(form, text=f"{h['ip']}   •   {h['mac']}\n{h['hostname']}\n{h['vendor']}").pack(anchor='w')
        ttk.Label(form, wraplength=560, text=f"Vermoedelijk OS: {h['os_guess'] or 'Nog niet gecontroleerd'}\n"
            f"Controle (UTC): {h['os_checked'] or '—'}\n{h['os_evidence']}\n"
            'Netwerkindicaties kunnen ook van een container of proxy afkomstig zijn.').pack(anchor='w', pady=10)
        ttk.Label(form, text='Eigen naam / opmerking:').pack(anchor='w', pady=(14, 3))
        label = tk.StringVar(value=h['label'])
        ttk.Entry(form, textvariable=label, width=50).pack(fill='x')
        known = tk.BooleanVar(value=h['known'])
        monitor = tk.BooleanVar(value=h['monitor'])
        ttk.Checkbutton(form, text='Ik herken dit apparaat (vertrouwd)', variable=known).pack(anchor='w', pady=8)
        ttk.Checkbutton(form, text='Waarschuw als dit bekende apparaat offline gaat', variable=monitor).pack(anchor='w')
        ttk.Label(form, text='Bewaking vereist “vertrouwd”. Alleen de overgang naar offline geeft een melding.').pack(pady=10)
        def save():
            if monitor.get() and not known.get():
                messagebox.showerror('Bewaking', 'Markeer dit apparaat eerst als vertrouwd.', parent=win)
                return
            self.store.edit(scope(self.config), h['mac'], label.get(), known.get(), monitor.get())
            self.refresh()
            win.destroy()
        ttk.Button(form, text='Opslaan', command=save).pack(anchor='e')

    def settings(self):
        if self.busy:
            return
        win = tk.Toplevel(self)
        self.settings_open = True
        win.bind('<Destroy>', lambda e: setattr(self, 'settings_open', False) if e.widget is win else None)
        win.title('Netwerk en HTTP-triggers')
        width = min(820, max(1, win.winfo_screenwidth() - 80))
        height = min(740, max(1, win.winfo_screenheight() - 140))
        win.geometry(f'{width}x{height}')
        win.minsize(min(360, width), min(260, height))
        win.transient(self)
        win.grab_set()
        # Reserve the footer before allocating space to the notebook.
        footer = ttk.Frame(win, padding=(12, 8, 12, 12))
        footer.pack(side='bottom', fill='x')
        tabs = ttk.Notebook(win)
        tabs.pack(side='top', fill='both', expand=True, padx=12, pady=(12, 0))
        tabs.enable_traversal()

        def add_page(title, padding=16):
            page = ScrollableSettingsPage(tabs, padding=padding)
            tabs.add(page, text=title)
            return page.body

        def scroll(event):
            if isinstance(event.widget, tk.Text) or not tabs.select():
                return
            page = win.nametowidget(tabs.select())
            if page.body.winfo_height() <= page.canvas.winfo_height():
                return
            if event.num == 4:
                direction = -1
            elif event.num == 5:
                direction = 1
            elif event.delta:
                direction = -1 if event.delta > 0 else 1
            else:
                return
            page.canvas.yview_scroll(direction * 3, 'units')
            return 'break'

        def reveal_focus(event):
            if tabs.select():
                win.nametowidget(tabs.select()).reveal(event.widget)

        for sequence in ('<MouseWheel>', '<Button-4>', '<Button-5>'):
            win.bind(sequence, scroll)
        win.bind('<FocusIn>', reveal_focus)
        win.bind('<Escape>', lambda _event: win.destroy())
        base = add_page('Netwerk')
        fields = {}
        for row, (key, label) in enumerate([('profile', 'Netwerkprofiel (aparte vertrouwenslijst)'),
                ('interface', 'Interface'), ('network', 'IPv4-subnet (CIDR)'),
                ('interval', 'Scaninterval in seconden (0 = handmatig)'),
                ('misses', 'Offline na aantal gemiste scans')]):
            ttk.Label(base, text=label).grid(row=row, column=0, sticky='w', pady=7)
            fields[key] = tk.StringVar(value=str(self.config[key]))
            ttk.Entry(base, textvariable=fields[key], width=32).grid(row=row, column=1, sticky='ew', padx=10)
        try:
            choices = interfaces()
        except Exception as e:
            choices = []
            ttk.Label(base, text=f'Interfaces ophalen mislukt: {e}', wraplength=650).grid(row=5, column=0, columnspan=2)
        selection = ttk.Combobox(base, state='readonly', width=60,
            values=[f"{x['interface']} • {x['ip']} • {x['network']}" for x in choices])
        selection.grid(row=6, column=0, columnspan=2, pady=14, sticky='ew')
        def choose(_):
            x = choices[selection.current()]
            fields['interface'].set(x['interface'])
            fields['network'].set(x['network'])
        selection.bind('<<ComboboxSelected>>', choose)
        for row, (key, label) in enumerate([('gateway_guard', 'Negeer scan als de gateway niet wordt gezien (aanbevolen)'),
                ('dns', 'Hostnamen opzoeken (kan scan vertragen)'), ('sound', 'Geluid bij nieuwe melding')], start=7):
            fields[key] = tk.BooleanVar(value=self.config[key])
            ttk.Checkbutton(base, text=label, variable=fields[key]).grid(row=row, column=0, columnspan=2, sticky='w', pady=7)
        ttk.Label(base, wraplength=700, text='Alleen het direct aangesloten IPv4-netwerk wordt gescand (maximaal /20). '
            'Kies een andere profielnaam voor een ander netwerk, ook als het dezelfde IP-reeks heeft. '
            'Instellingen worden na Opslaan gebruikt; klik daarna op Scan nu.\n\n'
            'Een ARP-scan duurt meestal enkele seconden. Apparaten in slaapstand kunnen offline lijken. '
            'De gatewaycontrole voorkomt veel valse offline-meldingen bij verbindingsproblemen.').grid(row=10, column=0, columnspan=2, pady=20)
        ports_page = add_page('Poortcontrole')
        for key, label in [('port_scan', 'Controleer de gevonden hosts op TCP-poorten'),
                           ('udp_scan', 'Controleer daarbij ook UDP-poorten')]:
            fields[key] = tk.BooleanVar(value=self.config.get(key, True))
            ttk.Checkbutton(ports_page, text=label, variable=fields[key]).pack(anchor='w', pady=8)
        ttk.Label(ports_page, text='Timeout per poort in seconden (0.1–5):').pack(anchor='w', pady=(15, 4))
        fields['port_timeout'] = tk.StringVar(value=str(self.config.get('port_timeout', 0.8)))
        ttk.Entry(ports_page, textvariable=fields['port_timeout'], width=12).pack(anchor='w')
        ttk.Label(ports_page, wraplength=720, text='TCP: ' + ', '.join(map(str, TCP_PORTS)) +
            '\n\nUDP: ' + ', '.join(map(str, UDP_PORTS)) +
            '\n\nOpen = een TCP-verbinding of UDP-antwoord bevestigd. Geen UDP-antwoord is onzeker, '
            'niet automatisch open of dicht. Voor DNS en NTP wordt een protocolvraag gebruikt; '
            'voor de overige UDP-poorten een lege probe.\n\n'
            'De controle draait na iedere netwerkscan. UDP krijgt twee pogingen. Bij veel apparaten '
            'kan een scan tientallen seconden of langer duren. Er zijn maximaal 32 verbindingen tegelijk. '
            'Servicenamen zijn gebruikelijke poortnamen, geen vastgestelde software.\n\n'
            'Poortdetails toont de status van elke gecontroleerde poort. Bestaande resultaten blijven '
            'zichtbaar met hun tijdstip als je poortcontrole uitschakelt.').pack(anchor='w', pady=20)
        os_page = add_page('OS-herkenning')
        fields['os_scan'] = tk.BooleanVar(value=self.config.get('os_scan', True))
        ttk.Checkbutton(os_page, text='Probeer het besturingssysteem te herkennen',
                        variable=fields['os_scan']).pack(anchor='w', pady=8)
        ttk.Label(os_page, wraplength=700, text='Zoekt naar OS-aanwijzingen in SSH- en FTP-banners '
            '(22/21) en de HTTP-serverheader (80/8080). Er worden geen inlogpogingen gedaan. '
            'Voor HTTP wordt HEAD / opgevraagd. HTTPS en andere poorten worden niet gebruikt.\n\n'
            'Open poorten of fabrikanten alleen leveren geen OS-gok op. Zonder aanwijzing staat er '
            'Onbekend. Verschillende OS-aanwijzingen geven Onzeker (tegenstrijdig). '
            'De eigen computer wordt lokaal herkend.\n\n'
            'Dit is beperkte servicebannerherkenning, geen Nmap TCP/IP-fingerprinting. '
            'Banners kunnen aangepast zijn of uit een container/proxy komen. Het resultaat '
            'bevestigt dus niet het OS van de fysieke host.\n\n'
            'Bij ingeschakelde poortcontrole worden alleen de relevante open poorten benaderd. '
            'Zonder poortcontrole worden de vier poorten rechtstreeks geprobeerd. '
            'De timeout van Poortcontrole wordt gebruikt.\n\n'
            'Via Apparaat bewerken zie je de aanwijzing en het tijdstip. Bij uitzetten blijven '
            'eerdere resultaten bewaard met hun oude tijdstip.').pack(anchor='w', pady=12)
        trigger_widgets = {}
        for key, label in [('unknown', 'Onbekend apparaat'), ('offline', 'Bekend apparaat offline')]:
            page = add_page(label, padding=14)
            t = self.config[key]
            enabled = tk.BooleanVar(value=t['enabled'])
            ttk.Checkbutton(page, text='HTTP-POST-trigger inschakelen', variable=enabled).pack(anchor='w')
            ttk.Label(page, text='URL').pack(anchor='w', pady=(10, 2))
            url = tk.StringVar(value=t['url'])
            ttk.Entry(page, textvariable=url).pack(fill='x')
            mode = tk.StringVar(value=t['mode'])
            ttk.Label(page, text='Verzenden als').pack(anchor='w', pady=(10, 2))
            ttk.Combobox(page, state='readonly', textvariable=mode, values=['json', 'form'], width=15).pack(anchor='w')
            ttk.Label(page, text='Headers (JSON-object; bijv. {"Authorization": "Bearer TOKEN"})').pack(anchor='w', pady=(10, 2))
            headers = tk.Text(page, height=4, wrap='word')
            headers.insert('1.0', json.dumps(t['headers'], indent=2, ensure_ascii=False))
            headers.pack(fill='x')
            ttk.Label(page, text='Body (JSON-object; bij form wordt dit omgezet naar formuliervelden)').pack(anchor='w', pady=(10, 2))
            body = tk.Text(page, height=11, wrap='word')
            body.insert('1.0', json.dumps(t['body'], indent=2, ensure_ascii=False))
            body.pack(fill='both', expand=True)
            ttk.Label(page, wraplength=720, text='Velden: {event}, {ip}, {mac}, {name}, {hostname}, {vendor}, {message}, '
                '{timestamp}, {event_id}, {network}, {profile}. Tokens staan lokaal in config.json; deel dit bestand niet.').pack(anchor='w', pady=8)
            trigger_widgets[key] = (enabled, url, mode, headers, body)
            ttk.Button(page, text='Verstuur echte test-POST', command=lambda k=key: test(k)).pack(anchor='e')
        def read_trigger(key):
            enabled, url, mode, headers, body = trigger_widgets[key]
            t = {'enabled': enabled.get(), 'url': url.get().strip(), 'mode': mode.get(),
                 'headers': json.loads(headers.get('1.0', 'end')), 'body': json.loads(body.get('1.0', 'end'))}
            validate_trigger(t)
            return t
        def test(key):
            try:
                t = read_trigger(key)
                if not t['url']:
                    raise ValueError('Vul eerst een URL in.')
            except Exception as e:
                messagebox.showerror('Trigger', str(e), parent=win)
                return
            payload = {'event_id': str(uuid.uuid4()), 'event': key, 'ip': '192.0.2.123',
                'mac': '02:00:00:00:00:01', 'name': 'TEST apparaat', 'hostname': 'test-host',
                'vendor': 'TEST', 'message': f'TEST: {key}', 'timestamp': now(),
                'network': fields['network'].get(), 'profile': fields['profile'].get()}
            def work():
                ok, status = post(t, payload)
                self.messages.put(('test', f"{'Geslaagd' if ok else 'Mislukt'}: {status}"))
            threading.Thread(target=work, daemon=True).start()
        def save():
            try:
                c = {k: v.get() for k, v in fields.items()}
                c['interval'], c['misses'] = int(c['interval']), int(c['misses'])
                c['port_timeout'] = float(c['port_timeout'].replace(',', '.'))
                for key in ('unknown', 'offline'):
                    c[key] = read_trigger(key)
                save_config(self.config_path, c)
                self.config = c
                self.next_scan = time.monotonic() + c['interval'] if c['interval'] else None
                self.refresh()
                self.status.set('Instellingen opgeslagen. Klik op Scan nu.')
                win.destroy()
            except Exception as e:
                messagebox.showerror('Instellingen', str(e), parent=win)
        ttk.Button(footer, text='Opslaan', command=save).pack(side='right', padx=(8, 0))
        ttk.Button(footer, text='Annuleren', command=win.destroy).pack(side='right')

    def export(self):
        filename = filedialog.asksaveasfilename(defaultextension='.csv', initialfile='netwerkwacht-apparaten.csv',
                                              filetypes=[('CSV', '*.csv')])
        if not filename:
            return
        hosts = self.store.hosts(scope(self.config))
        if not hosts:
            messagebox.showinfo('Export', 'Nog geen apparaten om te exporteren.')
            return
        for h in hosts:
            h['open_ports'], h['udp_uncertain'] = port_summary(h['port_results'])
        def safe(v):
            return "'" + v if isinstance(v, str) and v.startswith(('=', '+', '-', '@', '\t', '\r')) else v
        try:
            with open(filename, 'w', newline='', encoding='utf-8-sig') as f:
                writer = csv.DictWriter(f, fieldnames=list(hosts[0]), delimiter=';')
                writer.writeheader()
                writer.writerows({k: safe(v) for k, v in h.items()} for h in hosts)
            self.status.set(f'CSV opgeslagen: {filename}')
        except OSError as e:
            messagebox.showerror('Export mislukt', str(e))

    def close(self):
        if not messagebox.askyesno('NetworkWatch afsluiten',
                'Afsluiten stopt de bewaking. Wil je NetworkWatch afsluiten?'):
            return
        self.stop_event.set()
        self.store.close()
        self.destroy()


def main():
    os.umask(0o077)
    folder = Path(os.environ.get('XDG_DATA_HOME', str(Path.home() / '.local/share'))) / 'netwerkwacht'
    folder.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(folder, 0o700)
    lock = open(folder / 'app.lock', 'w')
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        print('NetworkWatch draait al voor deze gebruiker.')
        return
    app = App(folder)
    app.mainloop()
    # Wacht kort op een actieve HTTP-call, zodat de outbox netjes wordt bijgewerkt.
    app.dispatcher.join(timeout=12)
    lock.close()


if __name__ == '__main__':
    main()
