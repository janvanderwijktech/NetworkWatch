'use strict';
const $ = id => document.getElementById(id);
const text = (id, value) => { $(id).textContent = value ?? ''; };
const node = (tag, value, cls) => { const n = document.createElement(tag); if (value !== undefined) n.textContent = value; if (cls) n.className = cls; return n; };
let csrf = '', state = null, settingsRevision = null, editing = null, action = null;
let currentView = 'devices', sortKey = 'ip', reverseSort = false, signature = '', pollTimer = null;
let lastSerial = null, notifications = false, audio = null, toastTimer = null;

async function api(path, data) {
  const options = {credentials: 'same-origin', cache: 'no-store'};
  if (data !== undefined) Object.assign(options, {method: 'POST', headers: {'Content-Type': 'application/json', 'X-CSRF-Token': csrf}, body: JSON.stringify(data)});
  const response = await fetch(path, options);
  const result = await response.json();
  if (response.status === 401) showLogin();
  if (!response.ok) throw new Error(result.error || 'Het verzoek is mislukt.');
  return result;
}
function toast(message) { text('toast', message); $('toast').hidden = false; clearTimeout(toastTimer); toastTimer = setTimeout(() => { $('toast').hidden = true; }, 5500); }
function showLogin() { $('app').hidden = true; $('login-screen').hidden = false; if (pollTimer) clearTimeout(pollTimer); pollTimer = null; }
function showApp() { $('login-screen').hidden = true; $('app').hidden = false; }
function stamp(value) { if (!value) return 'Nog niet gecontroleerd'; const d = new Date(value); return Number.isNaN(d.valueOf()) ? value : d.toLocaleString('nl-NL', {day:'2-digit',month:'short',hour:'2-digit',minute:'2-digit'}); }
function badge(value, kind) { return node('span', value, 'badge ' + kind); }
function hostName(h) { return h.label || h.hostname || h.ip; }
function validIP(ip) { const parts = ip.split('.'); return parts.length === 4 && parts.every(p => /^\d{1,3}$/.test(p) && +p <= 255); }
function showView(view) {
  currentView = view;
  $('devices-view').hidden = view !== 'devices'; $('events-view').hidden = view !== 'events';
  text('breadcrumb-page', view === 'devices' ? 'Apparaten' : 'Gebeurtenissen');
  document.querySelectorAll('[data-view]').forEach(b => b.classList.toggle('active', b.dataset.view === view));
}

async function refresh() {
  const next = await api('/api/state');
  state = next;
  $('connection-warning').hidden = true;
  $('demo-banner').hidden = !state.demo;
  text('network-label', [state.profile, state.network || 'Nog geen subnet', state.interface || 'Geen interface', state.scan_mode.toUpperCase()].join('  ·  '));
  text('nav-count', state.hosts.length); text('total-count', state.hosts.length);
  text('online-count', state.hosts.filter(h => h.online).length);
  text('offline-count', state.hosts.filter(h => !h.online).length);
  text('unknown-count', state.hosts.filter(h => !h.known).length);
  $('scan-button').disabled = state.busy;
  $('settings-save').disabled = state.busy;
  $('paused').checked = state.paused;
  $('scan-dot').classList.toggle('spinning', state.busy);
  text('scan-state', state.busy ? 'Scan wordt uitgevoerd' : state.paused ? 'Automatische scans gepauzeerd' : 'Scanner beschikbaar');
  text('countdown', state.busy ? 'Bezig…' : state.paused ? 'Handmatig scannen blijft mogelijk' : state.next_scan_in === null ? 'Handmatige scanmodus' : `Volgende scan over ${Math.floor(state.next_scan_in / 60).toString().padStart(2, '0')}:${(state.next_scan_in % 60).toString().padStart(2, '0')}`);
  text('status-text', state.status); text('updated-at', 'Bijgewerkt om ' + new Date().toLocaleTimeString('nl-NL', {hour:'2-digit',minute:'2-digit'}));
  const newSignature = JSON.stringify([state.scope, state.hosts, state.events]);
  if (newSignature !== signature) { signature = newSignature; renderHosts(); renderEvents(); }
  if (lastSerial !== null && state.scan_serial !== lastSerial && state.alerts.length) {
    toast(state.alerts.slice(0, 2).join('\n') + (state.alerts.length > 2 ? ` (+${state.alerts.length - 2})` : ''));
    if (notifications) {
      if ('Notification' in window && Notification.permission === 'granted') new Notification('NetworkWatch', {body: state.alerts.slice(0, 3).join('\n')});
      if (state.sound && audio) {
        const oscillator = audio.createOscillator(), gain = audio.createGain();
        oscillator.connect(gain); gain.connect(audio.destination); oscillator.frequency.value = 650; gain.gain.value = 0.035;
        oscillator.start(); oscillator.stop(audio.currentTime + 0.16);
      }
    }
  }
  lastSerial = state.scan_serial;
}
async function poll() {
  try { await refresh(); }
  catch (error) { if (!$('app').hidden) { text('connection-warning', 'Verbinding met de scanner onderbroken. ' + error.message); $('connection-warning').hidden = false; } }
  if (!$('app').hidden) pollTimer = setTimeout(poll, 2000);
}

function renderHosts() {
  if (!state) return;
  const search = $('search').value.trim().toLocaleLowerCase('nl'), filter = $('filter').value;
  let hosts = state.hosts.filter(h => [h.label, h.hostname, h.ip, h.mac, h.vendor, h.os_guess, h.open_ports].join(' ').toLocaleLowerCase('nl').includes(search));
  hosts = hosts.filter(h => filter === 'all' || (filter === 'unknown' && !h.known) || (filter === 'online' && h.online) || (filter === 'offline' && !h.online) || (filter === 'monitor' && h.monitor));
  const value = h => sortKey === 'ip' ? h.ip.split('.').reduce((a, b) => a * 256 + Number(b), 0) : sortKey === 'name' ? hostName(h).toLowerCase() : sortKey === 'state' ? h.online * 1000 - h.misses : h[sortKey] ?? '';
  hosts.sort((a,b) => { const x = value(a), y = value(b); return (typeof x === 'string' ? x.localeCompare(y, 'nl') : x-y) * (reverseSort ? -1 : 1); });
  const body = $('hosts-body'); body.replaceChildren();
  for (const h of hosts) {
    const row = document.createElement('tr'); row.dataset.id = h.id;
    let td = row.insertCell();
    const checkbox = document.createElement('input'); checkbox.type = 'checkbox'; checkbox.checked = Boolean(h.known); checkbox.dataset.known = h.id; checkbox.setAttribute('aria-label', hostName(h) + ' als bekend markeren'); td.append(checkbox);
    td = row.insertCell(); td.className = 'name-cell'; td.append(node('span', hostName(h), 'device-name'));
    td.append(node('span', h.hostname && h.label ? h.hostname : h.monitor ? 'Offlinebewaking aan' : h.known ? 'Vertrouwd apparaat' : 'Nog niet herkend', 'device-sub'));
    td = row.insertCell(); td.className = 'mono ip-cell'; td.textContent = h.ip;
    td = row.insertCell(); td.append(badge(!h.online ? 'Offline' : h.misses ? `Gemist (${h.misses})` : 'Online', !h.online ? 'offline' : h.misses ? 'missed' : 'online'));
    td = row.insertCell(); td.textContent = (h.os_checked && (!h.online || h.misses) ? 'Laatste: ' : '') + (h.os_guess || 'Nog niet gecontroleerd');
    td = row.insertCell(); td.className = 'ports-cell';
    const opened = h.ports.filter(p => p.state === 'open');
    if (h.port_checked && (!h.online || h.misses)) td.append(node('small', 'Laatste meting: '));
    for (const p of opened.slice(0, 4)) td.append(node('span', `${p.port}/${p.protocol}`, 'port-chip'));
    if (opened.length > 4) { const more = node('button', `+${opened.length - 4}`, 'port-more'); more.dataset.ports = h.id; td.append(more); }
    if (!opened.length) td.append(node('span', h.port_checked ? 'Geen open poorten bevestigd' : 'Nog niet gecontroleerd', 'device-sub'));
    if (h.udp_uncertain && !['Geen', 'Niet gecontroleerd'].includes(h.udp_uncertain)) td.append(node('span', 'UDP onzeker: ' + h.udp_uncertain, 'device-sub'));
    td.title = h.open_ports;
    td = row.insertCell(); td.append(node('span', h.mac || 'Onbekend (IP-scan)', 'mono')); td.append(node('span', h.vendor || 'Fabrikant onbekend', 'device-sub'));
    td = row.insertCell(); td.textContent = stamp(h.last_seen); td.title = h.last_seen;
    td = row.insertCell(); const menu = node('button', '⋯', 'row-menu-button'); menu.dataset.menu = h.id; menu.setAttribute('aria-label', 'Acties voor ' + hostName(h)); td.append(menu);
    body.append(row);
  }
  text('visible-count', `${hosts.length} van ${state.hosts.length} apparaten`);
  $('empty-state').hidden = hosts.length !== 0;
  text('empty-title', state.hosts.length ? 'Geen overeenkomende apparaten' : 'Nog geen apparaten');
  text('empty-copy', state.hosts.length ? 'Probeer een andere zoekterm of filter.' : 'Kies je interface en subnet in Instellingen & triggers. Start daarna een scan.');
  $('empty-settings').hidden = state.hosts.length > 0;
  text('table-caption', state.scan_mode === 'ip' ? 'Herkenning op IP-adres · gebruik vaste DHCP-toewijzingen.' : 'Herken apparaten en houd je netwerk overzichtelijk.');
}
function renderEvents() {
  $('events-body').replaceChildren();
  for (const event of state.events) {
    const row = document.createElement('tr');
    row.insertCell().textContent = stamp(event.time);
    row.insertCell().append(badge(event.kind === 'unknown' ? 'Onbekend' : 'Offline', event.kind === 'unknown' ? 'unknown' : 'offline'));
    row.insertCell().textContent = event.message;
    row.insertCell().textContent = event.http_status ? `${event.http_status} (${event.attempts}×) ${event.result || ''}` : 'Trigger uit';
    $('events-body').append(row);
  }
  $('events-empty').hidden = Boolean(state.events.length);
}
function getHost(id) { return state?.hosts.find(h => h.id === id); }
async function saveHost(h, changes) {
  await api('/api/host', {id: h.id, scope: state.scope, label: h.label, known: Boolean(h.known), monitor: Boolean(h.monitor), ...changes});
  await refresh();
}
function openEditor(id) {
  const h = getHost(id); if (!h) return;
  editing = {id, scope: state.scope};
  text('edit-address', h.ip + '  ·  ' + (h.mac || 'MAC onbekend (IP-scan)'));
  text('edit-vendor', [h.hostname, h.vendor].filter(Boolean).join(' · '));
  $('edit-label').value = h.label;
  $('edit-known').checked = Boolean(h.known); $('edit-monitor').checked = Boolean(h.monitor); $('edit-monitor').disabled = !h.known;
  $('edit-ip-note').hidden = state.scan_mode !== 'ip';
  text('edit-os', h.os_guess || 'Nog niet gecontroleerd'); text('edit-evidence', h.os_evidence);
  text('edit-os-time', 'Laatste OS-controle: ' + stamp(h.os_checked)); text('edit-error', '');
  $('edit-dialog').showModal();
}
function openPorts(id) {
  const h = getHost(id); if (!h) return;
  text('ports-address', hostName(h) + ' · ' + h.ip); text('ports-time', 'Laatste controle: ' + stamp(h.port_checked) + '. Dit is een meting op dat tijdstip.');
  $('ports-body').replaceChildren();
  const names = {open: 'Open', closed: 'Gesloten', uncertain: 'Onzeker', error: 'Fout'};
  for (const p of [...h.ports].sort((a,b) => a.port-b.port || a.protocol.localeCompare(b.protocol))) {
    const row = document.createElement('tr'); row.insertCell().textContent = p.port; row.insertCell().textContent = p.protocol.toUpperCase(); row.insertCell().textContent = names[p.state] || p.state; row.insertCell().textContent = p.reason; $('ports-body').append(row);
  }
  $('ports-empty').hidden = h.ports.length > 0; $('ports-dialog').showModal();
}
async function copyText(value) { try { await navigator.clipboard.writeText(value); toast('Gekopieerd naar het klembord.'); } catch { toast('Selecteer en kopieer de tekst met Ctrl+C: ' + value); } }
function closeMenu() { $('host-menu').hidden = true; }
function openMenu(id, x, y) {
  const h = getHost(id); if (!h || !validIP(h.ip)) return;
  const menu = $('host-menu'); menu.replaceChildren();
  menu.append(node('div', hostName(h) + ' · ' + h.ip, 'menu-heading'));
  menu.append(node('div', 'Poortmeting: ' + stamp(h.port_checked), 'menu-heading'));
  if (!h.online || h.misses) menu.append(node('div', 'Acties gebruiken een eerdere meting.', 'menu-heading'));
  for (const a of h.actions) {
    if (a.kind === 'http' || a.kind === 'https') {
      const link = node('a', `${a.kind.toUpperCase()} openen (${a.port})`); link.href = `${a.kind}://${h.ip}:${a.port}/`; link.target = '_blank'; link.rel = 'noopener noreferrer'; link.addEventListener('click', closeMenu); menu.append(link);
    } else {
      const button = node('button', `${a.label} (${a.port})`); button.type = 'button'; button.addEventListener('click', () => { closeMenu(); openAction(h, a); }); menu.append(button);
    }
  }
  if (!h.actions.length) menu.append(node('div', 'Geen snelacties bij de gemeten poorten.', 'menu-heading'));
  menu.append(document.createElement('hr'));
  for (const [label, fn] of [['IP-adres kopiëren', () => copyText(h.ip)], ['Poortdetails', () => openPorts(h.id)], ['Apparaat bewerken', () => openEditor(h.id)]]) {
    const button = node('button', label); button.type = 'button'; button.addEventListener('click', () => { closeMenu(); fn(); }); menu.append(button);
  }
  menu.hidden = false; menu.style.left = Math.max(8, Math.min(x, innerWidth-menu.offsetWidth-8)) + 'px'; menu.style.top = Math.max(8, Math.min(y, innerHeight-menu.offsetHeight-8)) + 'px';
  menu.querySelector('button,a')?.focus();
}
function commandForAction() {
  if (!action) return '';
  const {host: h, item: a} = action, user = $('action-user').value.trim();
  if (user && !/^[A-Za-z0-9_][A-Za-z0-9_.@$-]{0,127}$/.test(user)) throw new Error('Gebruik een geldige SSH-gebruikersnaam zonder spaties of shelltekens.');
  if (a.kind === 'ssh') return `ssh -p ${a.port}${user ? " -l '" + user + "'" : ''} ${h.ip}`;
  if (a.kind === 'telnet') return `telnet ${h.ip} ${a.port}`;
  if (a.kind === 'ftp') return `ftp ${h.ip} ${a.port}`;
  if (a.kind === 'vnc') return `vncviewer ${h.ip}::${a.port}`;
  return `smb://${h.ip}/`;
}
function openAction(h, item) {
  action = {host: h, item, scope: state.scope}; text('action-title', item.label); text('action-target', h.ip + ':' + item.port); text('action-error', '');
  $('action-user').value = ''; $('action-user-label').hidden = item.kind !== 'ssh'; $('action-command').value = commandForAction();
  $('launch-action').disabled = !state.local_actions;
  $('launch-action').title = state.local_actions ? 'Start een desktopclient op de scannercomputer' : 'Start de webservice met --allow-local-actions op een grafische Linux-desktop om dit toe te staan.';
  $('action-dialog').showModal();
}

const configStrings = ['profile','interface','network','scan_mode','guard_host'];
const configNumbers = ['interval','misses','port_timeout'];
const configBools = ['gateway_guard','dns','sound','port_scan','udp_scan','os_scan'];
function makeTriggerForm(key) {
  // Alleen deze twee vaste sleutels worden in het statische HTML-sjabloon gebruikt.
  const root = $('trigger-' + key);
  root.className = 'trigger-fields';
  root.innerHTML = `<label class="check-row"><input type="checkbox" id="${key}-enabled">HTTP-POST-trigger inschakelen</label><label>URL<input id="${key}-url" type="url" placeholder="https://jouw-server.example/webhook"></label><label>Verzenden als<select id="${key}-mode"><option value="json">JSON</option><option value="form">Formuliervelden</option></select></label><label>Headers (JSON-object)<textarea id="${key}-headers" spellcheck="false"></textarea></label><label>Body (JSON-object)<textarea id="${key}-body" class="trigger-body" spellcheck="false"></textarea></label><p class="note">Invulvelden: {event}, {ip}, {mac}, {device_id}, {name}, {hostname}, {vendor}, {message}, {timestamp}, {event_id}, {network}, {profile}. In IP-modus blijven MAC en fabrikant onbekend. Tokens worden op de Linux-computer bewaard. De testknop verstuurt direct een echte POST zonder je instellingen op te slaan.</p><button type="button" class="button" id="${key}-test">Verstuur echte test-POST</button><p id="${key}-test-result" class="muted" role="status"></p>`;
  $(key + '-test').addEventListener('click', async () => {
    const button = $(key + '-test'); button.disabled = true;
    try { text(key + '-test-result', 'Versturen…'); const result = await api('/api/trigger-test', {kind: key, trigger: readTrigger(key)}); text(key + '-test-result', result.message); }
    catch (error) { text(key + '-test-result', error.message); }
    finally { button.disabled = false; }
  });
}
function readTrigger(key) { return {enabled: $(key + '-enabled').checked, url: $(key + '-url').value.trim(), mode: $(key + '-mode').value, headers: JSON.parse($(key + '-headers').value), body: JSON.parse($(key + '-body').value)}; }
function selectSettingsTab(key) {
  document.querySelectorAll('[data-settings-tab]').forEach(button => { const selected = button.dataset.settingsTab === key; button.setAttribute('aria-selected', String(selected)); button.tabIndex = selected ? 0 : -1; });
  document.querySelectorAll('.settings-page').forEach(page => { page.hidden = page.id !== 'settings-' + key; });
}
async function openSettings() {
  try {
    const result = await api('/api/settings'); settingsRevision = result.revision;
    for (const key of [...configStrings, ...configNumbers]) $('cfg-' + key).value = result.config[key];
    for (const key of configBools) $('cfg-' + key).checked = result.config[key];
    for (const key of ['unknown','offline']) {
      const t = result.config[key]; $(key + '-enabled').checked = t.enabled; $(key + '-url').value = t.url; $(key + '-mode').value = t.mode;
      $(key + '-headers').value = JSON.stringify(t.headers, null, 2); $(key + '-body').value = JSON.stringify(t.body, null, 2); text(key + '-test-result', '');
    }
    text('settings-error', ''); selectSettingsTab('network'); $('settings-dialog').showModal();
    const picker = $('interface-picker'); picker.replaceChildren(new Option('Selecteer een interface…', ''));
    try { const result = await api('/api/interfaces'); for (const item of result.interfaces) { const option = new Option(`${item.interface} · ${item.ip} · ${item.network}`, item.interface); option.dataset.network = item.network; picker.append(option); } }
    catch (error) { text('settings-error', 'Interfaces ophalen: ' + error.message + ' Je kunt de interface ook zelf invullen.'); }
  } catch (error) { toast(error.message); }
}

document.querySelectorAll('[data-close]').forEach(button => button.addEventListener('click', () => button.closest('dialog').close()));
document.querySelectorAll('[data-view]').forEach(button => button.addEventListener('click', () => showView(button.dataset.view)));
document.querySelectorAll('[data-settings-tab]').forEach(button => {
  button.addEventListener('click', () => selectSettingsTab(button.dataset.settingsTab));
  button.addEventListener('keydown', event => {
    if (!['ArrowLeft','ArrowRight','Home','End'].includes(event.key)) return;
    event.preventDefault(); const tabs = [...document.querySelectorAll('[data-settings-tab]')], index = tabs.indexOf(button);
    const next = event.key === 'Home' ? 0 : event.key === 'End' ? tabs.length - 1 : (index + (event.key === 'ArrowRight' ? 1 : -1) + tabs.length) % tabs.length;
    tabs[next].click(); tabs[next].focus();
  });
});
for (const id of ['settings-button','settings-sidebar','empty-settings']) $(id).addEventListener('click', openSettings);
for (const key of ['unknown','offline']) makeTriggerForm(key);
$('interface-picker').addEventListener('change', event => { const option = event.target.selectedOptions[0]; if (option.value) { $('cfg-interface').value = option.value; if ($('cfg-scan_mode').value === 'arp') $('cfg-network').value = option.dataset.network; } });
$('settings-form').addEventListener('submit', async event => {
  event.preventDefault(); const button = $('settings-save'); button.disabled = true;
  try {
    const config = {};
    for (const key of configStrings) config[key] = $('cfg-' + key).value.trim();
    for (const key of configNumbers) config[key] = Number($('cfg-' + key).value);
    for (const key of configBools) config[key] = $('cfg-' + key).checked;
    for (const key of ['unknown','offline']) config[key] = readTrigger(key);
    await api('/api/settings', {config, revision: settingsRevision}); $('settings-dialog').close(); await refresh(); toast('Instellingen opgeslagen.');
  } catch (error) { text('settings-error', error.message); $('settings-error').scrollIntoView({block:'nearest'}); }
  finally { button.disabled = Boolean(state?.busy); }
});
$('edit-known').addEventListener('change', event => { $('edit-monitor').disabled = !event.target.checked; if (!event.target.checked) $('edit-monitor').checked = false; });
$('edit-form').addEventListener('submit', async event => {
  event.preventDefault(); $('edit-save').disabled = true;
  try { await api('/api/host', {...editing, label: $('edit-label').value, known: $('edit-known').checked, monitor: $('edit-monitor').checked}); $('edit-dialog').close(); await refresh(); toast('Apparaat opgeslagen.'); }
  catch (error) { text('edit-error', error.message); }
  finally { $('edit-save').disabled = false; }
});
$('search').addEventListener('input', renderHosts); $('filter').addEventListener('change', renderHosts);
document.querySelectorAll('[data-sort]').forEach(button => button.addEventListener('click', () => { reverseSort = button.dataset.sort === sortKey ? !reverseSort : false; sortKey = button.dataset.sort; renderHosts(); }));
$('hosts-body').addEventListener('change', async event => {
  const id = event.target.dataset.known; if (!id) return; const h = getHost(id); event.target.disabled = true;
  try { await saveHost(h, {known: event.target.checked, monitor: event.target.checked && Boolean(h.monitor)}); }
  catch (error) { toast(error.message); renderHosts(); }
});
$('hosts-body').addEventListener('click', event => { const button = event.target.closest('button'); if (!button) return; if (button.dataset.menu) { const rect = button.getBoundingClientRect(); openMenu(button.dataset.menu, rect.right - 265, rect.bottom + 5); } else if (button.dataset.ports) openPorts(button.dataset.ports); });
$('hosts-body').addEventListener('contextmenu', event => { const row = event.target.closest('tr'); if (row) { event.preventDefault(); openMenu(row.dataset.id, event.clientX, event.clientY); } });
$('hosts-body').addEventListener('dblclick', event => { if (event.target.closest('input,button,a')) return; const row = event.target.closest('tr'); if (row) openEditor(row.dataset.id); });
document.addEventListener('pointerdown', event => { if (!event.target.closest('#host-menu,.row-menu-button')) closeMenu(); });
document.addEventListener('keydown', event => { if (event.key === 'Escape') closeMenu(); });
$('scan-button').addEventListener('click', async () => { $('scan-button').disabled = true; try { await api('/api/scan', {}); await refresh(); } catch (error) { toast(error.message); $('scan-button').disabled = false; } });
$('paused').addEventListener('change', async event => { try { await api('/api/pause', {paused: event.target.checked}); await refresh(); } catch (error) { toast(error.message); event.target.checked = Boolean(state?.paused); } });
$('notifications').addEventListener('click', async () => {
  if (notifications) { notifications = false; text('notifications', 'Meldingen aanzetten'); return; }
  const Audio = window.AudioContext || window.webkitAudioContext;
  if (Audio) { audio = audio || new Audio(); await audio.resume(); }
  if ('Notification' in window && Notification.permission === 'default') await Notification.requestPermission();
  notifications = true; text('notifications', 'Meldingen aan'); toast('Meldingen staan voor deze browsertab aan.');
});
$('action-user').addEventListener('input', () => { try { $('action-command').value = commandForAction(); text('action-error', ''); } catch (error) { $('action-command').value = ''; text('action-error', error.message); } });
$('copy-command').addEventListener('click', () => { try { const command = commandForAction(); $('action-command').select(); copyText(command); } catch (error) { text('action-error', error.message); } });
$('action-form').addEventListener('submit', async event => {
  event.preventDefault(); $('launch-action').disabled = true;
  try { commandForAction(); const result = await api('/api/action', {id: action.host.id, scope: action.scope, port: action.item.port, kind: action.item.kind, username: $('action-user').value.trim()}); $('action-dialog').close(); toast(result.message); }
  catch (error) { text('action-error', error.message); }
  finally { $('launch-action').disabled = !state.local_actions; }
});
$('login-form').addEventListener('submit', async event => {
  event.preventDefault();
  try { const result = await api('/api/login', {token: $('login-token').value}); $('login-token').value = ''; csrf = result.csrf; text('login-error', ''); $('logout-button').hidden = false; showApp(); poll(); }
  catch (error) { text('login-error', error.message); }
});
$('logout-button').addEventListener('click', async () => { try { await api('/api/logout', {}); showLogin(); } catch (error) { toast(error.message); } });
async function bootstrap() {
  try { const result = await api('/api/auth'); if (!result.authenticated) return showLogin(); csrf = result.csrf; $('logout-button').hidden = !result.requires_token; showApp(); poll(); }
  catch (error) { showApp(); text('connection-warning', 'Kan de webservice niet bereiken. Vernieuw de pagina zodra de server draait.'); $('connection-warning').hidden = false; }
}
bootstrap();
