"""
APEX Open Redirect + OAuth Hijacking Scanner
"""
import requests
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse, urljoin


def scan_oauth(target_url, discovered):
    """Scan for Open Redirect and OAuth vulnerabilities."""
    vulns = []
    sess = requests.Session()
    sess.verify = False

    # Open redirect payloads
    redirect_payloads = [
        'https://evil.com',
        '//evil.com',
        'https:evil.com',
        '\\\\evil.com',
        'https://evil.com%40target.com',
        'https://target.com.evil.com',
        'javascript:alert(1)',
        'data:text/html,<script>alert(1)</script>',
    ]

    redirect_params = ['redirect', 'redirect_uri', 'redirect_url', 'return', 'return_url',
                       'return_to', 'next', 'url', 'target', 'goto', 'continue', 'callback',
                       'forward', 'redir', 'origin', 'fallback', 'dest', 'destination']

    # Test URL parameters for open redirect
    for page in discovered.get('pages', [])[:10]:
        parsed = urlparse(page)
        if parsed.query:
            params = parse_qs(parsed.query)
            for param in list(params.keys())[:10]:
                if param.lower() in redirect_params:
                    for payload in redirect_payloads[:4]:
                        try:
                            test_params = params.copy()
                            test_params[param] = [payload]
                            new_query = urlencode(test_params, doseq=True)
                            test_url = urlunparse(parsed._replace(query=new_query))
                            r = sess.get(test_url, timeout=5, allow_redirects=False)

                            if r.status_code in [301, 302, 303, 307, 308]:
                                location = r.headers.get('Location', '')
                                if 'evil.com' in location or payload in location:
                                    vulns.append({
                                        'type': 'open_redirect',
                                        'endpoint': page, 'parameter': param,
                                        'payload': payload,
                                        'result': f'Redirects to: {location}',
                                        'confirmed': True, 'severity': 'medium',
                                        'target': target_url,
                                        'description': f'Open redirect via {param}.'
                                    })
                                    break
                        except:
                            pass

    # Check for OAuth endpoints
    oauth_paths = ['/oauth/authorize', '/oauth/token', '/oauth2/authorize', '/oauth2/token',
                   '/authorize', '/auth', '/login/oauth', '/connect/authorize',
                   '/api/oauth/authorize', '/api/auth']
    for page in discovered.get('pages', [])[:5]:
        for oa_path in oauth_paths:
            try:
                url = urljoin(target_url, oa_path)
                r = sess.get(url, timeout=5, allow_redirects=False)
                if r.status_code in [200, 302, 400, 401]:
                    # Check for OAuth indicators
                    if any(kw in r.text.lower() for kw in ['oauth', 'client_id', 'response_type', 'grant_type', 'authorize']):
                        # Test redirect_uri manipulation
                        for payload in redirect_payloads[:3]:
                            try:
                                test_url = f"{url}?client_id=test&redirect_uri={payload}&response_type=code"
                                r2 = sess.get(test_url, timeout=5, allow_redirects=False)
                                if r2.status_code in [301, 302, 303]:
                                    location = r2.headers.get('Location', '')
                                    if 'evil.com' in location:
                                        vulns.append({
                                            'type': 'oauth', 'subtype': 'redirect_uri_hijack',
                                            'endpoint': url,
                                            'parameter': 'redirect_uri',
                                            'payload': payload,
                                            'result': f'OAuth redirect_uri hijack — redirects to {location}',
                                            'confirmed': True, 'severity': 'critical',
                                            'target': target_url,
                                            'description': 'OAuth redirect_uri not validated — token theft possible.'
                                        })
                                        break
                            except:
                                pass
                        vulns.append({
                            'type': 'oauth', 'subtype': 'endpoint',
                            'endpoint': url,
                            'parameter': 'N/A',
                            'payload': 'OAuth endpoint detected',
                            'result': 'OAuth authorization endpoint found',
                            'confirmed': True, 'severity': 'medium',
                            'target': target_url,
                            'description': 'OAuth endpoint discovered — test redirect_uri validation.'
                        })
                        break
            except:
                pass

    return vulns