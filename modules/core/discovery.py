"""
APEX Deep Discovery Module
Parameter mining, JS extraction, API endpoint fuzzing, hidden file discovery
"""
import re
import json
import requests
from urllib.parse import urljoin, urlparse, parse_qs
from bs4 import BeautifulSoup


class DeepDiscovery:
    """Deep parameter and endpoint discovery beyond basic crawling."""

    def __init__(self):
        self.discovered_params = set()
        self.discovered_endpoints = set()
        self.discovered_js_files = set()
        self.discovered_api_endpoints = set()

    def extract_params_from_js(self, js_content, base_url=''):
        """Extract potential parameters from JavaScript files."""
        params = set()
        # Find fetch/axios/ajax calls
        patterns = [
            r'fetch\(["\']([^"\']+)["\']',
            r'axios\.(?:get|post|put|delete|patch)\(["\']([^"\']+)["\']',
            r'\$\.(?:ajax|get|post|put)\(\{?\s*url:\s*["\']([^"\']+)["\']',
            r'\.get\(["\']([^"\']+)["\']',
            r'\.post\(["\']([^"\']+)["\']',
            r'XMLHttpRequest.*?\.open\(["\'](?:GET|POST|PUT|DELETE)["\'],\s*["\']([^"\']+)["\']',
            # URL construction
            r'["\']([^"\']*\?(?:[^"\']*=(?:[^"\']*&?)+)[^"\']*)["\']',
            # Query params
            r'[?&]([a-zA-Z_][a-zA-Z0-9_]*)=',
            # JSON keys that look like params
            r'"([a-zA-Z_][a-zA-Z0-9_]{2,30})"\s*:',
        ]
        for pattern in patterns:
            matches = re.findall(pattern, js_content, re.IGNORECASE)
            for match in matches:
                if len(match) > 1 and len(match) < 200:
                    if '?' in match:
                        parsed = urlparse(match)
                        for param in parse_qs(parsed.query).keys():
                            params.add(param)
                        self.discovered_endpoints.add(urljoin(base_url, parsed.path) if base_url else match)
                    elif match.startswith('/') or match.startswith('http'):
                        self.discovered_endpoints.add(urljoin(base_url, match) if base_url else match)
                    else:
                        params.add(match)
        return params

    def extract_params_from_html(self, html_content, base_url=''):
        """Deep parameter extraction from HTML beyond just forms."""
        params = set()
        soup = BeautifulSoup(html_content, 'html.parser')

        # Standard forms
        for form in soup.find_all('form'):
            action = form.get('action', '')
            if action:
                self.discovered_endpoints.add(urljoin(base_url, action))
            for inp in form.find_all(['input', 'textarea', 'select']):
                name = inp.get('name', '')
                if name:
                    params.add(name)

        # Hidden inputs
        for inp in soup.find_all('input', type='hidden'):
            name = inp.get('name', '')
            if name:
                params.add(name)

        # Data attributes
        for el in soup.find_all(attrs={'data-url': True}):
            self.discovered_endpoints.add(urljoin(base_url, el['data-url']))
        for el in soup.find_all(attrs={'data-endpoint': True}):
            self.discovered_endpoints.add(urljoin(base_url, el['data-endpoint']))
        for el in soup.find_all(attrs={'data-api': True}):
            self.discovered_endpoints.add(urljoin(base_url, el['data-api']))

        # Inline JS extraction
        for script in soup.find_all('script'):
            if script.string:
                js_params = self.extract_params_from_js(script.string, base_url)
                params.update(js_params)

        # HTML comments
        for comment in soup.find_all(string=lambda text: isinstance(text, str) and '<!--' in text):
            # Extract URLs from comments
            urls = re.findall(r'(?:https?://|/)[^\s<>"\']+', str(comment))
            for url in urls:
                if '?' in url:
                    parsed = urlparse(url)
                    for param in parse_qs(parsed.query).keys():
                        params.add(param)

        # Meta tags
        for meta in soup.find_all('meta', attrs={'content': True}):
            content = meta['content']
            if 'url=' in content or 'http' in content:
                urls = re.findall(r'(?:https?://|/)[^\s<>"\']+', content)
                for url in urls:
                    self.discovered_endpoints.add(urljoin(base_url, url))

        return params

    def extract_api_endpoints(self, html_content, js_content='', base_url=''):
        """Discover API endpoints from HTML and JS."""
        endpoints = set()

        # From HTML
        patterns_html = [
            r'(?:api|graphql|swagger|openapi|docs|redoc)[^\s"\'<>]*',
            r'/api/v\d+/[^\s"\'<>]+',
            r'/graphql[^\s"\'<>]*',
            r'/swagger[^\s"\'<>]*',
        ]
        for pattern in patterns_html:
            matches = re.findall(pattern, html_content, re.IGNORECASE)
            for match in matches:
                if match.startswith('/'):
                    endpoints.add(urljoin(base_url, match))
                elif match.startswith('http'):
                    endpoints.add(match)

        # From JS
        if js_content:
            patterns_js = [
                r'(?:baseURL|apiUrl|api_url|API_URL|endpoint)\s*[:=]\s*["\']([^"\']+)["\']',
                r'["\']((?:/api|/graphql|/v\d)/[^"\']+)["\']',
                r'fetch\(["\']([^"\']*(?:api|graphql|v\d)[^"\']*)["\']',
            ]
            for pattern in patterns_js:
                matches = re.findall(pattern, js_content, re.IGNORECASE)
                for match in matches:
                    if match.startswith('/'):
                        endpoints.add(urljoin(base_url, match))
                    elif match.startswith('http'):
                        endpoints.add(match)

        return endpoints

    def fuzz_api_endpoints(self, base_url, known_endpoints, session=None):
        """Fuzz for sibling API endpoints based on known ones."""
        if not session:
            session = requests.Session()
            session.verify = False

        discovered = set()
        fuzz_patterns = []

        for endpoint in known_endpoints:
            # From /api/users/1 → try /api/users/2, /api/users/admin, /api/users
            parts = endpoint.rstrip('/').split('/')
            for i, part in enumerate(parts):
                if part.isdigit():
                    # Try incrementing IDs
                    for offset in range(-3, 4):
                        if offset == 0:
                            continue
                        new_parts = parts.copy()
                        new_parts[i] = str(int(part) + offset)
                        fuzz_patterns.append('/'.join(new_parts))
                    # Try common words
                    for word in ['admin', 'me', 'self', 'all', 'list', 'new', 'create']:
                        new_parts = parts.copy()
                        new_parts[i] = word
                        fuzz_patterns.append('/'.join(new_parts))

            # Try common suffixes
            for suffix in ['/edit', '/delete', '/update', '/view', '/details', '/info', '/config']:
                fuzz_patterns.append(endpoint.rstrip('/') + suffix)

            # Try parent paths
            parent = '/'.join(parts[:-1])
            if parent:
                fuzz_patterns.append(parent)
                for child in ['admin', 'config', 'settings', 'users', 'accounts', 'debug', 'test']:
                    fuzz_patterns.append(f'{parent}/{child}')

        # Deduplicate and test
        fuzz_patterns = list(set(fuzz_patterns))[:50]  # Limit to 50
        for pattern in fuzz_patterns:
            try:
                url = urljoin(base_url, pattern)
                r = session.get(url, timeout=5, allow_redirects=False)
                if r.status_code in [200, 201, 301, 302, 401, 403]:
                    discovered.add(url)
            except:
                pass

        return discovered

    def discover_js_files(self, html_content, base_url=''):
        """Find all JavaScript files referenced in HTML."""
        js_files = set()
        soup = BeautifulSoup(html_content, 'html.parser')

        for script in soup.find_all('script', src=True):
            src = script['src']
            full_url = urljoin(base_url, src)
            js_files.add(full_url)

        # Also find JS in inline event handlers
        for el in soup.find_all(attrs={'onclick': True}):
            pass  # Could extract but usually not useful

        # Find webpack chunks
        webpack_pattern = r'(?:static/js/|js/|chunks/)[^\s"\'<>]+\.js'
        matches = re.findall(webpack_pattern, html_content)
        for match in matches:
            js_files.add(urljoin(base_url, match))

        return js_files

    def discover_sensitive_files(self, base_url, session=None):
        """Discover sensitive files like .git, .env, backups."""
        if not session:
            session = requests.Session()
            session.verify = False

        sensitive_paths = [
            '/.git/HEAD', '/.git/config', '/.git/index',
            '/.env', '/.env.local', '/.env.production', '/.env.backup',
            '/.aws/credentials', '/.dockercfg',
            '/wp-config.php', '/wp-config.php.bak', '/wp-config.php~',
            '/config.php', '/config.php.bak', '/config.php~',
            '/.htaccess', '/.htpasswd',
            '/backup/', '/backups/', '/db_backup/', '/database/',
            '/adminer.php', '/phpinfo.php', '/info.php', '/test.php',
            '/debug/', '/console/', '/status',
            '/server-status', '/server-info',
            '/.DS_Store', '/.svn/entries', '/.hg/store/',
            '/sitemap.xml', '/robots.txt',
            '/crossdomain.xml', '/clientaccesspolicy.xml',
            '/.well-known/security.txt',
            '/web.config', '/web.config.bak',
            '/package.json', '/package-lock.json', '/yarn.lock',
            '/composer.json', '/composer.lock', '/Gemfile', '/Gemfile.lock',
            '/Dockerfile', '/docker-compose.yml', '/.dockerignore',
            '/README.md', '/CHANGELOG.md', '/LICENSE',
        ]

        found = []
        for path in sensitive_paths:
            try:
                url = urljoin(base_url, path)
                r = session.get(url, timeout=5, allow_redirects=False)
                if r.status_code in [200, 301, 302, 401]:
                    found.append({
                        'url': url,
                        'status': r.status_code,
                        'size': len(r.content),
                        'type': r.headers.get('Content-Type', 'unknown'),
                    })
            except:
                pass

        return found

    def mine_headers_for_params(self, headers):
        """Extract potential parameters from response headers."""
        params = set()
        interesting_headers = [
            'X-Powered-By', 'Server', 'X-AspNet-Version', 'X-AspNetMvc-Version',
            'X-Generator', 'X-Drupal-Cache', 'X-Drupal-Dynamic-Cache',
            'X-Frame-Options', 'X-Content-Type-Options', 'Content-Security-Policy',
            'X-XSS-Protection', 'Strict-Transport-Security',
        ]
        for header in interesting_headers:
            if header in headers:
                params.add(f'HEADER:{header}')
        return params

    def full_discovery(self, target_url, session=None):
        """Run full deep discovery on a target."""
        if not session:
            session = requests.Session()
            session.verify = False

        result = {
            'params': set(),
            'endpoints': set(),
            'api_endpoints': set(),
            'js_files': set(),
            'sensitive_files': [],
            'header_params': set(),
        }

        try:
            r = session.get(target_url, timeout=10)
            html = r.text
            headers = dict(r.headers)

            # Extract from HTML
            result['params'].update(self.extract_params_from_html(html, target_url))
            result['js_files'].update(self.discover_js_files(html, target_url))
            result['api_endpoints'].update(self.extract_api_endpoints(html, '', target_url))
            result['header_params'].update(self.mine_headers_for_params(headers))

            # Fetch and analyze JS files
            for js_url in list(result['js_files'])[:10]:  # Limit to 10 JS files
                try:
                    js_r = session.get(js_url, timeout=5)
                    if js_r.status_code == 200:
                        js_params = self.extract_params_from_js(js_r.text, target_url)
                        result['params'].update(js_params)
                        result['api_endpoints'].update(self.extract_api_endpoints('', js_r.text, target_url))
                except:
                    pass

            # Fuzz API endpoints
            fuzzed = self.fuzz_api_endpoints(target_url, result['api_endpoints'], session)
            result['api_endpoints'].update(fuzzed)

            # Discover sensitive files
            result['sensitive_files'] = self.discover_sensitive_files(target_url, session)

        except Exception as e:
            result['error'] = str(e)

        # Convert sets to lists for JSON serialization
        return {
            'params': list(result['params']),
            'endpoints': list(result['endpoints']),
            'api_endpoints': list(result['api_endpoints']),
            'js_files': list(result['js_files']),
            'sensitive_files': result['sensitive_files'],
            'header_params': list(result['header_params']),
        }


# Global instance
discovery = DeepDiscovery()