"""
APEX v3.0 — Browser Proxy Engine
Fetches pages through VPN/Tor/Proxy, rewrites links to stay proxied,
injects APEX toolbar for one-click scan/exploit.
"""

import re
import requests
import urllib3
from urllib.parse import urljoin, urlparse, urlunparse
from bs4 import BeautifulSoup

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class BrowserProxy:
    """Proxied browser engine that fetches pages through anonymity layers."""

    def __init__(self):
        self.session = None
        self.history = []
        self.current_url = None

    def _get_proxied_session(self):
        """Create a session routed through active anonymity layer."""
        session = requests.Session()
        session.verify = False
        session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.9',
            'Accept-Encoding': 'gzip, deflate, br',
            'Cache-Control': 'no-cache',
            'Sec-Fetch-Dest': 'document',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-Site': 'none',
            'Sec-Fetch-User': '?1',
            'Upgrade-Insecure-Requests': '1',
        })

        # Route through Tor if enabled
        try:
            from config import Config
            if Config.TOR_ENABLED:
                session.proxies = {
                    'http': f'socks5h://127.0.0.1:{Config.TOR_SOCKS_PORT}',
                    'https': f'socks5h://127.0.0.1:{Config.TOR_SOCKS_PORT}'
                }
                return session
            if Config.PROXY_ENABLED:
                import os, random
                if os.path.exists(Config.PROXY_LIST_FILE):
                    with open(Config.PROXY_LIST_FILE, 'r') as f:
                        proxies = [l.strip() for l in f if l.strip() and not l.startswith('#')]
                    if proxies:
                        proxy = random.choice(proxies)
                        session.proxies = {'http': proxy, 'https': proxy}
        except:
            pass

        return session

    def fetch_page(self, url):
        """Fetch a page through the proxy and return processed HTML."""
        if not url.startswith('http'):
            url = 'https://' + url

        self.session = self._get_proxied_session()
        self.current_url = url

        try:
            r = self.session.get(url, timeout=15, allow_redirects=True)
            final_url = r.url
            content_type = r.headers.get('Content-Type', '')

            # Handle non-HTML responses
            if 'text/html' not in content_type and 'application/xhtml' not in content_type:
                return {
                    'success': True,
                    'url': final_url,
                    'status_code': r.status_code,
                    'content_type': content_type,
                    'html': f'<html><body><pre>Non-HTML content: {content_type}</pre></body></html>',
                    'raw_headers': dict(r.headers),
                    'is_html': False
                }

            html = r.text

            # Rewrite links to stay proxied
            html = self._rewrite_links(html, final_url)

            # Extract page info for AI
            page_info = self._extract_page_info(html, final_url, r)

            self.history.append({
                'url': final_url,
                'title': page_info.get('title', ''),
                'status': r.status_code,
                'timestamp': __import__('datetime').datetime.now().isoformat()
            })

            return {
                'success': True,
                'url': final_url,
                'status_code': r.status_code,
                'content_type': content_type,
                'html': html,
                'page_info': page_info,
                'raw_headers': dict(r.headers),
                'is_html': True
            }

        except requests.exceptions.SSLError:
            # Try without SSL verification
            try:
                r = self.session.get(url, timeout=15, verify=False, allow_redirects=True)
                html = self._rewrite_links(r.text, r.url)
                page_info = self._extract_page_info(html, r.url, r)
                return {
                    'success': True,
                    'url': r.url,
                    'status_code': r.status_code,
                    'html': html,
                    'page_info': page_info,
                    'is_html': True
                }
            except Exception as e:
                return {'success': False, 'error': f'SSL Error: {str(e)}', 'url': url}

        except requests.exceptions.ConnectionError:
            return {'success': False, 'error': 'Connection failed — target may be down or blocking', 'url': url}

        except requests.exceptions.Timeout:
            return {'success': False, 'error': 'Request timed out after 15 seconds', 'url': url}

        except Exception as e:
            return {'success': False, 'error': str(e), 'url': url}

    def _rewrite_links(self, html, base_url):
        """Rewrite all links to go through the proxy."""
        soup = BeautifulSoup(html, 'html.parser')
        parsed_base = urlparse(base_url)

        # Rewrite <a href>
        for tag in soup.find_all('a', href=True):
            href = tag['href']
            if not href.startswith(('#', 'javascript:', 'mailto:', 'tel:')):
                absolute = urljoin(base_url, href)
                tag['href'] = f"javascript:apexNavigate('{absolute}')"
                tag['data-original-href'] = absolute

        # Rewrite <form action>
        for tag in soup.find_all('form', action=True):
            action = tag['action']
            if action and not action.startswith('#'):
                absolute = urljoin(base_url, action)
                tag['data-original-action'] = absolute
                tag['action'] = '#'
                tag['onsubmit'] = f"apexSubmitForm(this, '{absolute}'); return false;"

        # Rewrite <img src>, <link href>, <script src>
        for tag in soup.find_all(['img', 'script', 'link', 'iframe'], src=True):
            src = tag['src']
            if src and not src.startswith(('data:', '#')):
                absolute = urljoin(base_url, src)
                tag['data-original-src'] = absolute
                # Keep original src for resources (they load directly)

        return str(soup)

    def _extract_page_info(self, html, url, response):
        """Extract useful info from the page for AI analysis."""
        soup = BeautifulSoup(html, 'html.parser')

        # Title
        title = ''
        if soup.title:
            title = soup.title.string or ''

        # Forms
        forms = []
        for form in soup.find_all('form'):
            action = form.get('action', '')
            method = form.get('method', 'get').lower()
            inputs = []
            for inp in form.find_all(['input', 'textarea', 'select']):
                name = inp.get('name', '')
                if name:
                    inputs.append({
                        'name': name,
                        'type': inp.get('type', 'text'),
                        'tag': inp.name
                    })
            forms.append({
                'action': urljoin(url, action) if action else url,
                'method': method,
                'inputs': inputs,
                'has_csrf': any(
                    i['name'].lower() in ['csrf', 'csrf_token', '_token', 'authenticity_token', 'nonce']
                    for i in inputs
                )
            })

        # Links count
        links = len(soup.find_all('a', href=True))

        # Scripts
        scripts = []
        for script in soup.find_all('script', src=True):
            scripts.append(urljoin(url, script['src']))

        # Meta tags
        meta = {}
        for tag in soup.find_all('meta'):
            name = tag.get('name', tag.get('property', ''))
            content = tag.get('content', '')
            if name and content:
                meta[name] = content

        # Server header
        server = response.headers.get('Server', '')
        powered_by = response.headers.get('X-Powered-By', '')

        # Tech detection
        tech = []
        text_lower = html.lower()
        if 'wp-content' in text_lower or 'wordpress' in text_lower:
            tech.append('WordPress')
        if 'drupal' in text_lower:
            tech.append('Drupal')
        if 'joomla' in text_lower:
            tech.append('Joomla')
        if 'laravel' in text_lower or 'csrf-token' in text_lower:
            tech.append('Laravel')
        if 'react' in text_lower or '__react' in text_lower:
            tech.append('React')
        if 'vue' in text_lower or 'v-bind' in text_lower:
            tech.append('Vue.js')
        if 'angular' in text_lower or 'ng-app' in text_lower:
            tech.append('Angular')
        if 'jquery' in text_lower:
            tech.append('jQuery')
        if 'bootstrap' in text_lower:
            tech.append('Bootstrap')
        if 'cloudflare' in str(response.headers).lower():
            tech.append('Cloudflare')

        return {
            'title': title,
            'forms_count': len(forms),
            'forms': forms,
            'links_count': links,
            'scripts_count': len(scripts),
            'scripts': scripts[:10],
            'meta': meta,
            'server': server,
            'powered_by': powered_by,
            'detected_tech': tech,
            'status_code': response.status_code,
            'content_length': len(html),
        }

    def get_history(self):
        """Return browsing history."""
        return {
            'total': len(self.history),
            'history': self.history[-50:]
        }

    def clear_history(self):
        """Clear browsing history."""
        self.history = []
        return {'success': True}


# Singleton instance
browser_proxy = BrowserProxy()