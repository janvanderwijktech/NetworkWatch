"""IPv4-discovery via gerouteerde ping/TCP-verbindingen, ook vanuit Crostini.

Geen ARP of verzonnen MAC-adressen. De interne opslagsleutel 'ip:<adres>'
onderscheidt apparaten in een apart IP-profiel; openbare MAC-velden blijven leeg.
"""
import concurrent.futures
import ipaddress
import json
import os
import shutil
import subprocess

from ports import check_port

# Ook gebruikt als ping door een host wordt geblokkeerd. Een TCP-RST bevestigt
# bereikbaarheid, maar betekent nadrukkelijk niet dat de poort open is.
DISCOVERY_PORTS = (22, 80, 443, 445, 3389, 8080, 21, 23, 53, 5900, 8443)


def probe_host(ip, source_ip, ping_binary, timeout):
    result = subprocess.run(
        [ping_binary, '-n', '-I', source_ip, '-c', '1', '-W', '1', '-w', '2', ip],
        capture_output=True, text=True, timeout=3,
        env={**os.environ, 'LC_ALL': 'C'})
    if result.returncode == 0:
        return True
    if result.returncode != 1:
        raise RuntimeError('Ping kan niet worden uitgevoerd. Controleer iputils-ping en de netwerkrechten.')
    for port in DISCOVERY_PORTS:
        state = check_port(ip, port, 'tcp', timeout, source_ip)['state']
        if state in ('open', 'closed'):
            return True
        if state == 'error':
            raise RuntimeError('Lokale socketfout tijdens IP-detectie; scan genegeerd.')
    return False


def discover(config, get_interfaces, run):
    """Een volledige scan met dezelfde interface/route en controlehost voor/na."""
    binary = shutil.which('ping')
    if not binary:
        raise RuntimeError('ping ontbreekt. Installeer iputils-ping (Debian) of iputils (Arch).')
    network = ipaddress.IPv4Network(config['network'])
    first = str(next(network.hosts()))
    guard = config.get('guard_host', '').strip()

    def connection():
        local = [x for x in get_interfaces() if x['interface'] == config['interface']
                 and x['up'] and x['carrier']]
        routes = json.loads(run(['ip', '-j', 'route', 'get', first]))
        if not routes or routes[0].get('dev') != config['interface']:
            raise RuntimeError('Geen route naar dit subnet via de gekozen interface.')
        route = routes[0]
        source = route.get('prefsrc') or route.get('src')
        source_row = next((x for x in local if x['ip'] == source), None)
        if source_row is None:
            raise RuntimeError('De gekozen interface is niet verbonden of heeft geen bruikbaar IPv4-adres.')
        return source_row, route

    before, route_before = connection()
    source_ip = before['ip']
    timeout = config.get('port_timeout', 0.8)

    def guard_ok():
        if config['gateway_guard'] and not probe_host(guard, source_ip, binary, timeout):
            raise RuntimeError('Controlehost niet bereikbaar: scan genegeerd; geen offline-meldingen.')

    guard_ok()

    def scan_host(address):
        ip = str(address)
        if probe_host(ip, source_ip, binary, timeout):
            return {'ip': ip, 'mac': 'ip:' + ip, 'hostname': '', 'vendor': ''}

    # Maximaal 32 actieve pingprocessen/sockets; geen raw sockets of nmap vereist.
    with concurrent.futures.ThreadPoolExecutor(max_workers=32) as pool:
        rows = [row for row in pool.map(scan_host, network.hosts()) if row]
    if connection() != (before, route_before):
        raise RuntimeError('Verbinding of route gewijzigd tijdens IP-scan; resultaten genegeerd.')
    guard_ok()
    return rows, before, route_before


def verify_connection(config, before, route_before, get_interfaces, run):
    """Ook na hostnaam-, poort- en OS-controles geen gewijzigde route accepteren."""
    first = str(next(ipaddress.IPv4Network(config['network']).hosts()))
    local = get_interfaces()
    routes = json.loads(run(['ip', '-j', 'route', 'get', first]))
    if before not in local or not routes or routes[0] != route_before:
        raise RuntimeError('Verbinding of route gewijzigd tijdens controle; scan genegeerd.')
    if config['gateway_guard']:
        binary = shutil.which('ping')
        if not binary or not probe_host(config['guard_host'].strip(), before['ip'], binary,
                                        config.get('port_timeout', 0.8)):
            raise RuntimeError('Controlehost niet bereikbaar na controle; scan genegeerd.')
