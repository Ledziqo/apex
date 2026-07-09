"""
APEX Port Scanner
Advanced TCP/UDP port scanning with service detection
"""
import socket
import threading
import queue
from concurrent.futures import ThreadPoolExecutor, as_completed

COMMON_PORTS = {
    21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS',
    80: 'HTTP', 110: 'POP3', 111: 'RPC', 135: 'RPC', 139: 'NetBIOS',
    143: 'IMAP', 443: 'HTTPS', 445: 'SMB', 993: 'IMAPS', 995: 'POP3S',
    1723: 'PPTP', 3306: 'MySQL', 3389: 'RDP', 5432: 'PostgreSQL',
    5900: 'VNC', 6379: 'Redis', 8080: 'HTTP-Alt', 8443: 'HTTPS-Alt',
    27017: 'MongoDB', 5000: 'Flask', 3000: 'Node.js', 8000: 'Django',
    9000: 'PHP-FPM', 9200: 'Elasticsearch', 11211: 'Memcached'
}

def scan_port(host, port, timeout=1):
    """Scan a single port"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        sock.close()
        if result == 0:
            service = COMMON_PORTS.get(port, 'Unknown')
            return {'port': port, 'service': service, 'open': True}
    except:
        pass
    return None

def scan_ports(host, ports=None, timeout=1, max_threads=20):
    """Scan multiple ports"""
    if ports is None:
        ports = list(COMMON_PORTS.keys())
    
    open_ports = []
    
    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        futures = {executor.submit(scan_port, host, port, timeout): port for port in ports}
        for future in as_completed(futures):
            result = future.result()
            if result:
                open_ports.append(result)
    
    return sorted(open_ports, key=lambda x: x['port'])

def grab_banner(host, port, timeout=2):
    """Grab service banner"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
        sock.send(b'HEAD / HTTP/1.0\r\n\r\n')
        banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
        sock.close()
        return banner[:200] if banner else None
    except:
        return None