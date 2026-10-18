"""Conservatieve OS-indicaties uit servicebanners, zonder login of raw sockets.

Een banner kan van een container, proxy of aangepaste server komen. Het resultaat
is daarom een aanwijzing over de serviceomgeving, geen bevestiging van het host-OS.
"""
import concurrent.futures
import ipaddress
import json
import platform
import re
import socket
import time

PROBE_PORTS = (22, 21, 80, 8080)


def read_banner(ip, port, timeout=0.8, source_ip=None):
    """Begrensd lezen (max. 4096 bytes en een totale deadline per verbinding)."""
    deadline = time.monotonic() + timeout
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            if source_ip:
                sock.bind((source_ip, 0))
            sock.connect((ip, port))
            if port in (80, 8080):
                sock.settimeout(max(0.001, deadline - time.monotonic()))
                sock.sendall(f'HEAD / HTTP/1.0\r\nHost: {ip}\r\nConnection: close\r\n\r\n'.encode('ascii'))
            data = bytearray()
            while len(data) < 4096:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                sock.settimeout(remaining)
                chunk = sock.recv(4096 - len(data))
                if not chunk:
                    break
                data.extend(chunk)
                if (port in (80, 8080) and b'\r\n\r\n' in data) or (port in (21, 22) and b'\n' in data):
                    break
    except OSError:
        return ''
    text = data.decode('utf-8', errors='replace')
    if port in (80, 8080):
        # Alleen de serverheader; geen paginainhoud of andere headers bewaren.
        if not text.startswith('HTTP/'):
            return ''
        header = text.split('\r\n\r\n', 1)[0]
        match = re.search(r'^Server:\s*([^\r\n]+)', header, re.I | re.M)
        text = match[1] if match else ''
    elif port == 22:
        text = next((line for line in text.splitlines() if line.startswith('SSH-')), '')
    elif not text.startswith('220'):
        return ''
    return ''.join(c for c in text[:200] if c.isprintable())


def classify_banners(banners):
    """Geen gok op basis van poort, fabrikant, OpenSSH, Apache of nginx alleen."""
    matches = []
    rules = [
        (r'openssh_for_windows|microsoft-iis|\bwindows\b|\bwin32\b|\bwin64\b', 'Windows', 'Windows'),
        (r'\bubuntu\b', 'Linux', 'Linux (Ubuntu)'),
        (r'\bdebian\b', 'Linux', 'Linux (Debian)'),
        (r'\balpine\b', 'Linux', 'Linux (Alpine)'),
        (r'\bcentos\b', 'Linux', 'Linux (CentOS)'),
        (r'\bfedora\b', 'Linux', 'Linux (Fedora)'),
        (r'\blinux\b', 'Linux', 'Linux'),
        (r'\bfreebsd\b', 'FreeBSD', 'FreeBSD'),
        (r'\bopenbsd\b', 'OpenBSD', 'OpenBSD'),
        (r'\bnetbsd\b', 'NetBSD', 'NetBSD'),
        (r'\bdarwin\b|\bmacos\b|\bmac os x\b', 'Darwin/macOS', 'Darwin/macOS'),
    ]
    for port, banner in banners:
        for pattern, family, label in rules:
            if re.search(pattern, banner, re.I):
                matches.append((family, label, f'{port}/tcp: {banner}'))
    if not matches:
        return 'Onbekend', 'Geen herkenbare OS-aanwijzing ontvangen.'
    families = {m[0] for m in matches}
    evidence = '; '.join(dict.fromkeys(m[2] for m in matches))[:700]
    if len(families) > 1:
        return 'Onzeker (tegenstrijdig)', evidence
    specific = {m[1] for m in matches if m[1] != m[0]}
    if len(specific) > 1:
        return 'Onzeker (tegenstrijdig)', evidence
    return (next(iter(specific)) if specific else matches[0][1]), evidence


def detect_hosts(rows, config, source_ip):
    def detect(row):
        if row['ip'] == source_ip:
            row.update(os_guess=f'{platform.system()} (lokaal)',
                       os_evidence='Lokaal uitgelezen via platform.system(); geen netwerkinschatting.')
            return
        ipaddress.IPv4Address(row['ip'])
        ports = PROBE_PORTS
        if 'port_results' in row:
            opened = {r['port'] for r in json.loads(row['port_results'])
                      if r['protocol'] == 'tcp' and r['state'] == 'open'}
            ports = [p for p in ports if p in opened]
        banners = [(p, read_banner(row['ip'], p, config.get('port_timeout', 0.8), source_ip))
                   for p in ports]
        row['os_guess'], row['os_evidence'] = classify_banners(banners)
    with concurrent.futures.ThreadPoolExecutor(max_workers=16) as pool:
        list(pool.map(detect, rows))
