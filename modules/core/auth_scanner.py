"""
APEX Auth-Aware Scanner
Login with credentials, scan authenticated surfaces, test privilege escalation
"""
import requests
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup


class AuthScanner:
    """Handles authenticated scanning and privilege escalation testing."""

    def __init__(self):
        self.authenticated_session = None
        self.auth_cookies = {}
        self.logged_in = False
        self.login_url = None

    def login_form(self, target_url, username, password, username_field='username', password_field='password', login_path='/login'):
        """Login to a target using form-based authentication."""
        self.authenticated_session = requests.Session()
        self.authenticated_session.verify = False
        self.authenticated_session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/131.0.0.0 Safari/537.36'
        })

        login_url = urljoin(target_url, login_path)

        try:
            # Get login page to extract CSRF token
            r = self.authenticated_session.get(login_url, timeout=10)
            soup = BeautifulSoup(r.text, 'html.parser')

            # Find CSRF token
            csrf_token = None
            for inp in soup.find_all('input', type='hidden'):
                name = inp.get('name', '').lower()
                if name in ['csrf', 'csrf_token', '_token', 'authenticity_token', 'xsrf', 'nonce']:
                    csrf_token = inp.get('value', '')
                    break

            # Build login data
            data = {username_field: username, password_field: password}
            if csrf_token:
                data['csrf_token'] = csrf_token
                data['_token'] = csrf_token

            # Submit login
            r = self.authenticated_session.post(login_url, data=data, timeout=10, allow_redirects=True)

            # Check if login succeeded
            if r.status_code == 200:
                # Check for common login success indicators
                if any(kw in r.text.lower() for kw in ['logout', 'sign out', 'dashboard', 'welcome', 'my account', 'profile']):
                    self.logged_in = True
                    self.auth_cookies = dict(self.authenticated_session.cookies)
                    self.login_url = login_url
                    return {'success': True, 'message': 'Login successful', 'cookies': self.auth_cookies}

                # Check if we got redirected away from login
                if login_url not in r.url and 'login' not in r.url.lower():
                    self.logged_in = True
                    self.auth_cookies = dict(self.authenticated_session.cookies)
                    self.login_url = login_url
                    return {'success': True, 'message': 'Login successful (redirect detected)', 'cookies': self.auth_cookies}

            return {'success': False, 'message': 'Login failed - no success indicators found'}

        except Exception as e:
            return {'success': False, 'message': f'Login error: {str(e)}'}

    def login_with_cookies(self, target_url, cookies_dict):
        """Login using pre-existing session cookies."""
        self.authenticated_session = requests.Session()
        self.authenticated_session.verify = False
        self.authenticated_session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/131.0.0.0 Safari/537.36'
        })

        for name, value in cookies_dict.items():
            self.authenticated_session.cookies.set(name, value, domain=urlparse(target_url).netloc)

        # Verify the session works
        try:
            r = self.authenticated_session.get(target_url, timeout=10)
            if r.status_code == 200:
                self.logged_in = True
                self.auth_cookies = cookies_dict
                return {'success': True, 'message': 'Cookie session active'}
        except:
            pass

        return {'success': False, 'message': 'Cookie session invalid'}

    def scan_authenticated(self, target_url, discovered_endpoints=None):
        """Scan authenticated surfaces for additional vulnerabilities."""
        if not self.logged_in or not self.authenticated_session:
            return {'error': 'Not authenticated'}

        results = {
            'accessible_endpoints': [],
            'privilege_escalation': [],
            'idor_candidates': [],
            'hidden_admin_panels': [],
        }

        # Common authenticated endpoints
        auth_endpoints = [
            '/admin', '/dashboard', '/profile', '/settings', '/account',
            '/users', '/user/list', '/admin/users', '/manage',
            '/api/admin', '/api/users', '/api/me',
            '/orders', '/invoices', '/billing',
            '/reports', '/analytics', '/logs',
            '/config', '/configuration', '/system',
        ]

        for ep in auth_endpoints:
            try:
                url = urljoin(target_url, ep)
                r = self.authenticated_session.get(url, timeout=5, allow_redirects=False)
                if r.status_code == 200:
                    results['accessible_endpoints'].append({
                        'url': url,
                        'status': r.status_code,
                        'title': self._extract_title(r.text),
                    })
            except:
                pass

        # Test privilege escalation
        results['privilege_escalation'] = self._test_privilege_escalation(target_url)

        # Find IDOR candidates
        results['idor_candidates'] = self._find_idor_candidates(target_url, discovered_endpoints or [])

        return results

    def _test_privilege_escalation(self, target_url):
        """Test for horizontal and vertical privilege escalation."""
        findings = []

        # Test accessing other users' data
        test_endpoints = [
            '/api/users/1', '/api/users/2', '/api/users/admin',
            '/admin/users', '/api/admin/users',
            '/profile/1', '/profile/2',
            '/account/1', '/account/2',
        ]

        for ep in test_endpoints:
            try:
                url = urljoin(target_url, ep)
                r = self.authenticated_session.get(url, timeout=5)
                if r.status_code == 200 and len(r.text) > 100:
                    # Check if we can see other users' data
                    if any(kw in r.text.lower() for kw in ['email', 'password', 'role', 'admin', 'user']):
                        findings.append({
                            'endpoint': url,
                            'type': 'potential_privilege_escalation',
                            'detail': 'Accessible user data endpoint',
                        })
            except:
                pass

        # Test role manipulation
        role_endpoints = ['/api/me', '/api/user', '/api/profile']
        for ep in role_endpoints:
            try:
                url = urljoin(target_url, ep)
                r = self.authenticated_session.get(url, timeout=5)
                if r.status_code == 200 and 'role' in r.text.lower():
                    findings.append({
                        'endpoint': url,
                        'type': 'role_exposed',
                        'detail': 'User role visible in API response - test role manipulation',
                    })
            except:
                pass

        return findings

    def _find_idor_candidates(self, target_url, endpoints):
        """Find potential IDOR (Insecure Direct Object Reference) candidates."""
        candidates = []
        import re

        for ep in endpoints[:20]:
            # Look for numeric IDs in URLs
            if re.search(r'/(\d+)/', ep) or re.search(r'[?&]id=\d+', ep):
                candidates.append({
                    'endpoint': ep,
                    'type': 'idor_candidate',
                    'detail': 'Numeric identifier found - test with different IDs',
                })

        return candidates

    def _extract_title(self, html):
        """Extract page title from HTML."""
        try:
            start = html.find('<title>')
            end = html.find('</title>', start)
            if start > -1 and end > start:
                return html[start + 7:end].strip()[:100]
        except:
            pass
        return ''

    def compare_scan_results(self, unauthenticated_vulns, authenticated_vulns):
        """Compare unauthenticated vs authenticated scan results."""
        comparison = {
            'new_vulns': [],
            'elevated_severity': [],
            'summary': '',
        }

        unauth_types = {v.get('type'): v for v in unauthenticated_vulns}
        auth_types = {v.get('type'): v for v in authenticated_vulns}

        # Find vulns only visible when authenticated
        for vtype, vuln in auth_types.items():
            if vtype not in unauth_types:
                comparison['new_vulns'].append(vuln)

        if comparison['new_vulns']:
            comparison['summary'] = f'{len(comparison["new_vulns"])} new vulnerabilities found behind authentication'
        else:
            comparison['summary'] = 'No additional vulnerabilities found behind authentication'

        return comparison


    def import_from_curl(self, curl_command):
        """Parse a curl command or raw HTTP request to extract cookies, headers, and URL.
        Auto-configures the authenticated session."""
        import re
        
        result = {
            'success': False,
            'cookies': {},
            'headers': {},
            'target_url': '',
            'method': 'GET',
            'post_data': None
        }
        
        try:
            # Extract URL
            url_match = re.search(r"(?:curl\s+(?:.*\s+)?)?['\"]?(https?://[^\s'\"]+)", curl_command)
            if url_match:
                result['target_url'] = url_match.group(1)
            
            # Extract cookies from -b or --cookie
            cookie_match = re.search(r"(?:-b|--cookie)\s+['\"]?([^'\"]+)", curl_command)
            if cookie_match:
                cookie_str = cookie_match.group(1)
                for pair in cookie_str.split(';'):
                    pair = pair.strip()
                    if '=' in pair:
                        k, v = pair.split('=', 1)
                        result['cookies'][k.strip()] = v.strip()
            
            # Extract Cookie: header from -H
            header_cookies = re.findall(r"-H\s+['\"]Cookie:\s*([^'\"]+)", curl_command, re.IGNORECASE)
            for hc in header_cookies:
                for pair in hc.split(';'):
                    pair = pair.strip()
                    if '=' in pair:
                        k, v = pair.split('=', 1)
                        result['cookies'][k.strip()] = v.strip()
            
            # Extract headers from -H
            headers = re.findall(r"-H\s+['\"]([^'\"]+)", curl_command)
            for h in headers:
                if ':' in h:
                    k, v = h.split(':', 1)
                    k = k.strip()
                    if k.lower() != 'cookie':
                        result['headers'][k] = v.strip()
            
            # Extract data from -d or --data
            data_match = re.search(r"(?:-d|--data(?:-raw)?)\s+['\"]([^'\"]+)", curl_command)
            if data_match:
                result['post_data'] = data_match.group(1)
                result['method'] = 'POST'
            
            # Extract method from -X
            method_match = re.search(r"-X\s+['\"]?(\w+)", curl_command)
            if method_match:
                result['method'] = method_match.group(1).upper()
            
            if result['cookies'] or result['headers']:
                result['success'] = True
                # Auto-configure authenticated session
                self.auth_cookies = result['cookies']
                self.authenticated_session = requests.Session()
                self.authenticated_session.verify = False
                for k, v in result['headers'].items():
                    self.authenticated_session.headers[k] = v
                for k, v in result['cookies'].items():
                    self.authenticated_session.cookies.set(k, v)
                self.logged_in = True
                self.login_url = result['target_url']
            
            return result
        except Exception as e:
            return {'success': False, 'error': str(e)}


# Global instance
auth_scanner = AuthScanner()
