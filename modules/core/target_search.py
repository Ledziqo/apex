"""
APEX v3.0 — Target Search Engine
Hacker-focused search engine for finding exploitable targets.
Searches via DuckDuckGo, supports dork queries, tech stack filtering.
"""

import re
import json
import requests
import urllib3
from urllib.parse import quote, urlparse
from bs4 import BeautifulSoup

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class TargetSearch:
    """Hacker search engine for discovering vulnerable targets."""

    def __init__(self):
        self.session = requests.Session()
        self.session.verify = False
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.9',
        })
        self.search_history = []

        # Pre-built dork queries
        self.dork_templates = {
            'admin_panels': [
                'intitle:"admin panel" inurl:admin',
                'intitle:"login" inurl:admin',
                'inurl:phpmyadmin',
                'inurl:admin/login',
                'intitle:"control panel"',
            ],
            'exposed_files': [
                'intitle:"index of" ".env"',
                'intitle:"index of" "backup"',
                'intitle:"index of" ".git"',
                'inurl:phpinfo.php',
                'intitle:"index of" "wp-config.php"',
            ],
            'vulnerable_tech': [
                'inurl:wp-content/plugins/',
                'inurl:/wp-json/wp/v2/users',
                'inurl:".php?page="',
                'inurl:"?id=" ext:php',
                'inurl:"?file=" ext:php',
            ],
            'iot_cameras': [
                'intitle:"webcamXP"',
                'intitle:"Live View / - AXIS"',
                'inurl:/view/view.shtml',
                'intitle:"Network Camera"',
            ],
            'login_pages': [
                'intitle:"login" inurl:/login',
                'inurl:/signin',
                'intitle:"sign in" inurl:/auth',
                'inurl:/oauth/authorize',
            ],
            'api_endpoints': [
                'inurl:/api/v1',
                'inurl:/graphql',
                'inurl:/swagger',
                'inurl:/openapi.json',
                'intitle:"API Documentation"',
            ],
            'database_exposure': [
                'inurl:/phpmyadmin/index.php',
                'inurl:/adminer.php',
                'intitle:"phpMyAdmin"',
                'inurl:".sql" intitle:"index of"',
            ],
            'dev_environments': [
                'inurl:dev.',
                'inurl:staging.',
                'inurl:test.',
                'intitle:"development server"',
            ],
        }

    def search(self, query, search_type='web', max_results=20):
        """Search for targets using DuckDuckGo."""
        results = []

        try:
            # Use DuckDuckGo HTML search (no API key needed)
            encoded_query = quote(query)
            search_url = f'https://html.duckduckgo.com/html/?q={encoded_query}'

            r = self.session.get(search_url, timeout=10)
            soup = BeautifulSoup(r.text, 'html.parser')

            for result in soup.find_all('div', class_='result'):
                if len(results) >= max_results:
                    break

                title_elem = result.find('a', class_='result__a')
                snippet_elem = result.find('a', class_='result__snippet')
                url_elem = result.find('a', class_='result__url')

                if title_elem:
                    title = title_elem.get_text(strip=True)
                    link = title_elem.get('href', '')
                    snippet = snippet_elem.get_text(strip=True) if snippet_elem else ''
                    display_url = url_elem.get_text(strip=True) if url_elem else ''

                    # Clean up link
                    if link.startswith('//'):
                        link = 'https:' + link

                    if link and not link.startswith(('javascript:', '#')):
                        results.append({
                            'title': title,
                            'url': link,
                            'snippet': snippet,
                            'display_url': display_url,
                            'domain': urlparse(link).netloc if link else '',
                        })

            self.search_history.append({
                'query': query,
                'type': search_type,
                'results_count': len(results),
                'timestamp': __import__('datetime').datetime.now().isoformat()
            })

            return {
                'success': True,
                'query': query,
                'results': results,
                'count': len(results),
                'source': 'duckduckgo'
            }

        except Exception as e:
            # Fallback: return pre-built dork results
            return self._fallback_search(query, max_results)

    def _fallback_search(self, query, max_results):
        """Fallback search when DuckDuckGo is unavailable."""
        results = []

        # Check if query matches any dork templates
        query_lower = query.lower()
        for category, dorks in self.dork_templates.items():
            for dork in dorks:
                if any(word in query_lower for word in dork.lower().split()):
                    results.append({
                        'title': f'[DORK] {dork}',
                        'url': f'https://duckduckgo.com/?q={quote(dork)}',
                        'snippet': f'Pre-built dork for {category.replace("_", " ")}',
                        'display_url': f'dork:{category}',
                        'domain': 'duckduckgo.com',
                    })

        if not results:
            # Generate search URLs for common engines
            encoded = quote(query)
            results = [
                {
                    'title': f'Search DuckDuckGo: {query}',
                    'url': f'https://duckduckgo.com/?q={encoded}',
                    'snippet': 'Open in DuckDuckGo',
                    'display_url': 'duckduckgo.com',
                    'domain': 'duckduckgo.com',
                },
                {
                    'title': f'Search Google: {query}',
                    'url': f'https://www.google.com/search?q={encoded}',
                    'snippet': 'Open in Google',
                    'display_url': 'google.com',
                    'domain': 'google.com',
                },
                {
                    'title': f'Search Shodan: {query}',
                    'url': f'https://www.shodan.io/search?query={encoded}',
                    'snippet': 'Open in Shodan (IoT/Server search)',
                    'display_url': 'shodan.io',
                    'domain': 'shodan.io',
                },
            ]

        return {
            'success': True,
            'query': query,
            'results': results[:max_results],
            'count': len(results[:max_results]),
            'source': 'fallback'
        }

    def search_dork(self, dork_type, max_results=20):
        """Search using a pre-built dork query."""
        if dork_type in self.dork_templates:
            dorks = self.dork_templates[dork_type]
            all_results = []
            for dork in dorks[:3]:  # Search first 3 dorks
                result = self.search(dork, 'dork', max_results // 3)
                if result.get('results'):
                    all_results.extend(result['results'])
            return {
                'success': True,
                'dork_type': dork_type,
                'dorks_used': dorks[:3],
                'results': all_results[:max_results],
                'count': len(all_results[:max_results]),
            }
        return {'success': False, 'error': f'Unknown dork type: {dork_type}'}

    def get_dork_categories(self):
        """Return all available dork categories."""
        return {
            'categories': list(self.dork_templates.keys()),
            'total_dorks': sum(len(d) for d in self.dork_templates.values()),
            'dorks': self.dork_templates
        }

    def search_by_tech(self, technology, max_results=20):
        """Search for sites using a specific technology."""
        tech_queries = {
            'wordpress': 'inurl:wp-content "WordPress"',
            'joomla': 'inurl:index.php?option=com_',
            'drupal': 'inurl:sites/default/files',
            'magento': 'inurl:index.php/magento',
            'shopify': 'site:myshopify.com',
            'laravel': 'inurl:".env" laravel',
            'django': 'intitle:"Django administration"',
            'php': 'ext:php inurl:"?id="',
            'asp': 'ext:asp inurl:"?id="',
            'apache': 'intitle:"Apache HTTP Server"',
            'nginx': 'intitle:"Welcome to nginx"',
            'iis': 'intitle:"IIS Windows Server"',
            'tomcat': 'intitle:"Apache Tomcat"',
            'jenkins': 'intitle:"Dashboard [Jenkins]"',
            'gitlab': 'intitle:"GitLab"',
            'jira': 'intitle:"System Dashboard - JIRA"',
        }

        query = tech_queries.get(technology.lower(), f'site:*{technology}*')
        return self.search(query, 'tech', max_results)

    def get_search_history(self):
        """Return search history."""
        return {
            'total': len(self.search_history),
            'history': self.search_history[-20:]
        }


# Singleton instance
target_search = TargetSearch()