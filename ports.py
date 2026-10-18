"""Begrensde TCP-connect/UDP-controle, zonder raw-socketrechten of extra pakketten."""
import concurrent.futures
import errno
import json
import os
import socket

TCP_PORTS = {
    20: 'FTP Data', 21: 'FTP Control', 22: 'SSH', 23: 'Telnet', 25: 'SMTP',
    53: 'DNS', 80: 'HTTP', 110: 'POP3', 135: 'RPC', 139: 'NetBIOS Session',
    143: 'IMAP', 389: 'LDAP', 443: 'HTTPS', 445: 'SMB', 465: 'SMTPS',
    993: 'IMAPS', 995: 'POP3S', 3306: 'MySQL', 5432: 'PostgreSQL',
    5900: 'VNC', 6379: 'Redis', 8080: 'HTTP Alternate', 8443: 'HTTPS Alternate',
}
UDP_PORTS = {
    53: 'DNS', 67: 'DHCP Server', 68: 'DHCP Client', 123: 'NTP',
    137: 'NetBIOS Name', 138: 'NetBIOS Datagram', 161: 'SNMP',
    389: 'LDAP', 514: 'Syslog',
}


def udp_probe(port):
    if port == 53:
        # DNS root NS-vraag, recursion desired uit; geen zone transfer.
        return os.urandom(2) + b'\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x01'
    if port == 123:
        # NTP v4 client time request, geen management- of control-opdracht.
        return b'\x23' + b'\x00' * 47
    # Geen broadcast, DHCP-leaseaanvraag, SNMP-communityguess of syslogbericht.
    # Veel UDP-services negeren deze lege probe: expliciet onzeker weergeven.
    return b''


def check_port(ip, port, protocol, timeout=0.8, source_ip=None):
    result = {'port': port, 'protocol': protocol, 'state': 'error', 'reason': ''}
    try:
        kind = socket.SOCK_STREAM if protocol == 'tcp' else socket.SOCK_DGRAM
        with socket.socket(socket.AF_INET, kind) as sock:
            sock.settimeout(timeout)
            if source_ip:
                sock.bind((source_ip, 0))
            sock.connect((ip, port))
            if protocol == 'tcp':
                result.update(state='open', reason='TCP-verbinding geaccepteerd')
            else:
                for attempt in range(2):
                    sock.send(udp_probe(port))
                    try:
                        sock.recv(4096)
                        result.update(state='open', reason='UDP-antwoord ontvangen')
                        break
                    except socket.timeout:
                        if attempt == 1:
                            result.update(state='uncertain', reason='Geen UDP-antwoord na twee probes')
    except ConnectionRefusedError:
        result.update(state='closed', reason='Verbinding geweigerd / port unreachable')
    except socket.timeout:
        result.update(state='uncertain', reason='Timeout; mogelijk filtering of pakketverlies')
    except OSError as exc:
        if exc.errno in (errno.ENETUNREACH, errno.EHOSTUNREACH, errno.EACCES, errno.EPERM):
            result.update(state='uncertain', reason='Niet bereikbaar of geblokkeerd')
        else:
            result.update(state='error', reason=f'Lokale socketfout ({exc.errno})')
    return result


def scan_ports(rows, config, source_ip=None):
    """Maximaal 32 hosts tegelijk, per host één socket; geen enorme taakqueue."""
    selected = [(p, 'tcp') for p in TCP_PORTS]
    if config.get('udp_scan', True):
        selected += [(p, 'udp') for p in UDP_PORTS]
    def scan_host(row):
        results = [check_port(row['ip'], p, proto, config.get('port_timeout', 0.8), source_ip)
                   for p, proto in selected]
        row['port_results'] = json.dumps(results, ensure_ascii=False)
    with concurrent.futures.ThreadPoolExecutor(max_workers=32) as pool:
        list(pool.map(scan_host, rows))


def decode_results(value):
    return json.loads(value) if value else []


def port_summary(value):
    results = decode_results(value)
    if not results:
        return 'Nog niet gecontroleerd', ''
    def label(r):
        service = (TCP_PORTS if r['protocol'] == 'tcp' else UDP_PORTS).get(r['port'], '')
        return f"{r['port']}/{r['protocol']} {service}".strip()
    opened = ', '.join(label(r) for r in results if r['state'] == 'open') or 'Geen open poorten bevestigd'
    if any(r['state'] == 'error' for r in results):
        opened += ' [controlefouten; zie details]'
    uncertain = ', '.join(str(r['port']) for r in results
                          if r['protocol'] == 'udp' and r['state'] == 'uncertain')
    return opened, uncertain or ('Geen' if any(r['protocol'] == 'udp' for r in results) else 'Niet gecontroleerd')
