"""
APEX JavaScript Rendering Engine
Headless browser for SPA crawling, dynamic content discovery
"""
import time
from urllib.parse import urljoin, urlparse


class JSRenderer:
    """Renders JavaScript-heavy pages using headless browser for SPA discovery."""

    def __init__(self):
        self.driver = None
        self.available = False
        self._init_driver()

    def _init_driver(self):
        """Initialize headless browser if available."""
        try:
            from selenium import webdriver
            from selenium.webdriver.chrome.options import Options
            options = Options()
            options.add_argument('--headless=new')
            options.add_argument('--no-sandbox')
            options.add_argument('--disable-dev-shm-usage')
            options.add_argument('--disable-gpu')
            options.add_argument('--window-size=1920,1080')
            options.add_argument('--disable-web-security')
            options.add_argument('--disable-features=VizDisplayCompositor')
            self.driver = webdriver.Chrome(options=options)
            self.driver.set_page_load_timeout(15)
            self.available = True
        except Exception:
            self.available = False

    def render_page(self, url, wait_time=3):
        """Render a page with JavaScript and return the final DOM."""
        if not self.available:
            return None

        try:
            self.driver.get(url)
            time.sleep(wait_time)  # Wait for JS to execute

            # Scroll to trigger lazy loading
            self.driver.execute_script("window.scrollTo(0, document.body.scrollHeight);")
            time.sleep(1)
            self.driver.execute_script("window.scrollTo(0, 0);")
            time.sleep(0.5)

            html = self.driver.page_source
            current_url = self.driver.current_url
            return {'html': html, 'url': current_url}
        except Exception:
            return None

    def discover_dynamic_content(self, target_url):
        """Discover dynamically loaded content from SPA."""
        if not self.available:
            return {'error': 'JS renderer not available (install selenium + chromedriver)'}

        result = {
            'rendered_urls': [],
            'api_calls': [],
            'dynamic_links': [],
            'forms': [],
            'hidden_elements': [],
        }

        rendered = self.render_page(target_url)
        if not rendered:
            return {'error': 'Failed to render page'}

        try:
            # Extract all links from rendered DOM
            links = self.driver.execute_script("""
                var links = [];
                document.querySelectorAll('a[href]').forEach(function(a) {
                    links.push(a.href);
                });
                return links;
            """)
            result['dynamic_links'] = list(set(links))[:50]

            # Extract API calls from network (limited)
            api_patterns = self.driver.execute_script("""
                var apis = [];
                var scripts = document.querySelectorAll('script');
                scripts.forEach(function(s) {
                    if (s.textContent) {
                        var matches = s.textContent.match(/(?:fetch|axios\.(?:get|post|put|delete)|\.get|\.post)\\(['"]([^'"]+)['"]/g);
                        if (matches) apis = apis.concat(matches);
                    }
                });
                return apis;
            """)
            result['api_calls'] = list(set(api_patterns))[:30]

            # Extract forms
            forms = self.driver.execute_script("""
                var forms = [];
                document.querySelectorAll('form').forEach(function(f) {
                    var inputs = [];
                    f.querySelectorAll('input, textarea, select').forEach(function(i) {
                        inputs.push({name: i.name, type: i.type});
                    });
                    forms.push({action: f.action, method: f.method, inputs: inputs});
                });
                return forms;
            """)
            result['forms'] = forms[:20]

            # Find hidden admin/API endpoints
            hidden = self.driver.execute_script("""
                var hidden = [];
                // Check data attributes
                document.querySelectorAll('[data-url], [data-endpoint], [data-api], [data-admin]').forEach(function(el) {
                    hidden.push(el.getAttribute('data-url') || el.getAttribute('data-endpoint') || el.getAttribute('data-api') || el.getAttribute('data-admin'));
                });
                // Check window/config objects
                try {
                    if (window.config) hidden.push(JSON.stringify(window.config));
                    if (window.APP_CONFIG) hidden.push(JSON.stringify(window.APP_CONFIG));
                    if (window.env) hidden.push(JSON.stringify(window.env));
                } catch(e) {}
                return hidden;
            """)
            result['hidden_elements'] = hidden[:20]

            # Get all rendered URLs
            result['rendered_urls'].append(rendered['url'])

        except Exception as e:
            result['error'] = str(e)

        return result

    def crawl_spa(self, target_url, max_pages=20):
        """Crawl a Single Page Application by clicking through routes."""
        if not self.available:
            return {'error': 'JS renderer not available'}

        discovered = {
            'pages': [],
            'api_endpoints': set(),
            'forms': [],
        }

        try:
            self.driver.get(target_url)
            time.sleep(3)

            # Find all router links
            links = self.driver.execute_script("""
                var links = [];
                document.querySelectorAll('a[href^="/"], a[href^="' + window.location.origin + '"]').forEach(function(a) {
                    if (!a.href.includes('#') && !a.href.includes('javascript:')) {
                        links.push(a.href);
                    }
                });
                return [...new Set(links)].slice(0, 50);
            """)

            for link in links[:max_pages]:
                try:
                    self.driver.get(link)
                    time.sleep(1)
                    discovered['pages'].append({
                        'url': self.driver.current_url,
                        'title': self.driver.title,
                    })

                    # Extract API calls from this page
                    apis = self.driver.execute_script("""
                        var apis = [];
                        var scripts = document.querySelectorAll('script');
                        scripts.forEach(function(s) {
                            if (s.textContent) {
                                var matches = s.textContent.match(/['"`](\/api\/[^'"`]+)['"`]/g);
                                if (matches) apis = apis.concat(matches.map(m => m.replace(/['"`]/g, '')));
                            }
                        });
                        return [...new Set(apis)];
                    """)
                    for api in apis:
                        discovered['api_endpoints'].add(urljoin(target_url, api))

                except:
                    pass

        except Exception as e:
            discovered['error'] = str(e)

        discovered['api_endpoints'] = list(discovered['api_endpoints'])
        return discovered

    def close(self):
        """Close the browser driver."""
        if self.driver:
            try:
                self.driver.quit()
            except:
                pass
            self.driver = None
            self.available = False


# Global instance
js_renderer = JSRenderer()