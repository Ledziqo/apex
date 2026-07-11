"""
APEX v3.0 — OSINT Profiling Engine
Target OSINT profiling: employee names, tech stack, subdomains, email formats, related domains.
"""

import re
import json
import requests
from datetime import datetime
from urllib.parse import urlparse, quote


class OSINTEngine:
    """Open-Source Intelligence gathering for target profiling."""
    
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
        })
        self.results_cache = {}
    
    def profile_target(self, domain):
        """Run full OSINT profiling on a target domain."""
        domain = self._clean_domain(domain)
        
        profile = {
            'domain': domain,
            'timestamp': datetime.now().isoformat(),
            'dns_records': {},
            'subdomains': [],
            'emails': [],
            'employees': [],
            'tech_stack': [],
            'related_domains': [],
            'social_media': {},
            'certificate_transparency': [],
            'job_postings': [],
            'summary': ''
        }
        
        # DNS Records
        profile['dns_records'] = self._get_dns_records(domain)
        
        # Subdomains from Certificate Transparency
        profile['certificate_transparency'] = self._search_crtsh(domain)
        profile['subdomains'] = list(set(
            profile['certificate_transparency'] + self._enumerate_common_subdomains(domain)
        ))[:30]
        
        # Tech stack detection
        profile['tech_stack'] = self._detect_tech_stack(domain)
        
        # Email format detection
        profile['emails'] = self._find_emails(domain)
        profile['email_format'] = self._detect_email_format(domain)
        
        # Related domains
        profile['related_domains'] = self._find_related_domains(domain)
        
        # Generate summary
        profile['summary'] = self._generate_summary(profile)
        
        self.results_cache[domain] = profile
        return profile
    
    def _clean_domain(self, domain):
        """Clean domain name from URL format."""
        domain = domain.lower().strip()
        domain = domain.replace('https://', '').replace('http://', '')
        domain = domain.split('/')[0]
        domain = domain.split(':')[0]
        return domain
    
    def _get_dns_records(self, domain):
        """Get DNS records for the domain."""
        records = {}
        
        # Try to get A records
        try:
            import socket
            records['a_records'] = socket.gethostbyname_ex(domain)[2]
        except:
            records['a_records'] = []
        
        # Try to get MX records
        try:
            import dns.resolver
            mx_records = []
            answers = dns.resolver.resolve(domain, 'MX')
            for rdata in answers:
                mx_records.append({
                    'preference': rdata.preference,
                    'exchange': str(rdata.exchange).rstrip('.')
                })
            records['mx_records'] = mx_records
        except:
            records['mx_records'] = []
        
        # Try to get NS records
        try:
            import dns.resolver
            ns_records = []
            answers = dns.resolver.resolve(domain, 'NS')
            for rdata in answers:
                ns_records.append(str(rdata).rstrip('.'))
            records['ns_records'] = ns_records
        except:
            records['ns_records'] = []
        
        # Try to get TXT records (SPF, DMARC, etc.)
        try:
            import dns.resolver
            txt_records = []
            answers = dns.resolver.resolve(domain, 'TXT')
            for rdata in answers:
                txt_records.append(''.join([s.decode() if isinstance(s, bytes) else s for s in rdata.strings]))
            records['txt_records'] = txt_records
        except:
            records['txt_records'] = []
        
        return records
    
    def _search_crtsh(self, domain):
        """Search crt.sh for certificate transparency logs."""
        subdomains = []
        try:
            url = f'https://crt.sh/?q=%25.{domain}&output=json'
            r = self.session.get(url, timeout=15)
            if r.status_code == 200:
                data = r.json()
                for entry in data:
                    name = entry.get('name_value', '')
                    for sub in name.split('\n'):
                        sub = sub.strip().lower()
                        if sub.endswith(domain) and sub != domain:
                            sub = sub.replace('*.', '')
                            subdomains.append(sub)
        except:
            pass
        
        return list(set(subdomains))[:50]
    
    def _enumerate_common_subdomains(self, domain):
        """Enumerate common subdomains."""
        common_subs = [
            'www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1', 'ns2',
            'webdisk', 'admin', 'test', 'dev', 'staging', 'api', 'cdn', 'blog',
            'shop', 'store', 'portal', 'remote', 'vpn', 'secure', 'login', 'auth',
            'dashboard', 'app', 'm', 'mobile', 'docs', 'support', 'help', 'status',
            'monitor', 'git', 'jenkins', 'ci', 'jira', 'confluence', 'wiki',
            'db', 'mysql', 'mongo', 'redis', 'elastic', 'kibana', 'grafana',
            'docker', 'k8s', 'kubernetes', 'swarm', 'traefik', 'nginx',
            'cpanel', 'whm', 'webmail', 'roundcube', 'phpmyadmin', 'pma',
        ]
        
        found = []
        for sub in common_subs:
            try:
                import socket
                hostname = f'{sub}.{domain}'
                socket.gethostbyname(hostname)
                found.append(hostname)
            except:
                pass
        
        return found
    
    def _detect_tech_stack(self, domain):
        """Detect technology stack from the target website."""
        tech = []
        
        try:
            r = self.session.get(f'https://{domain}', timeout=10, verify=False)
            content = r.text.lower()
            headers = {k.lower(): v for k, v in r.headers.items()}
            
            # Server detection
            server = headers.get('server', '')
            if server:
                tech.append({'category': 'Web Server', 'name': server})
            
            # Framework detection
            framework_patterns = {
                'React': ['react', '__react', 'react-dom'],
                'Vue.js': ['vue', '__vue__', 'v-bind'],
                'Angular': ['ng-version', 'angular', 'ng-app'],
                'jQuery': ['jquery'],
                'Bootstrap': ['bootstrap'],
                'Tailwind': ['tailwind'],
                'WordPress': ['wp-content', 'wordpress', 'wp-json'],
                'Drupal': ['drupal'],
                'Joomla': ['joomla'],
                'Magento': ['magento'],
                'Shopify': ['shopify'],
                'Laravel': ['laravel', 'x-powered-by: laravel'],
                'Django': ['django', 'csrftoken'],
                'Flask': ['flask'],
                'Express': ['express'],
                'Next.js': ['__next', '__nextjs'],
                'Nuxt.js': ['__nuxt', 'nuxt'],
                'Gatsby': ['gatsby'],
            }
            
            for framework, patterns in framework_patterns.items():
                for pattern in patterns:
                    if pattern in content or pattern in str(headers).lower():
                        tech.append({'category': 'Framework', 'name': framework})
                        break
            
            # CDN detection
            cdn_patterns = {
                'Cloudflare': ['cloudflare', 'cf-ray'],
                'CloudFront': ['cloudfront', 'x-amz-cf-id'],
                'Fastly': ['fastly'],
                'Akamai': ['akamai'],
                'Vercel': ['vercel'],
                'Netlify': ['netlify'],
            }
            
            for cdn, patterns in cdn_patterns.items():
                for pattern in patterns:
                    if pattern in str(headers).lower():
                        tech.append({'category': 'CDN', 'name': cdn})
                        break
            
            # Analytics detection
            analytics_patterns = {
                'Google Analytics': ['google-analytics', 'gtag', 'ga.js'],
                'Google Tag Manager': ['googletagmanager'],
                'Facebook Pixel': ['facebook', 'fbq'],
                'Hotjar': ['hotjar'],
                'Mixpanel': ['mixpanel'],
            }
            
            for analytics, patterns in analytics_patterns.items():
                for pattern in patterns:
                    if pattern in content:
                        tech.append({'category': 'Analytics', 'name': analytics})
                        break
            
        except:
            pass
        
        return tech
    
    def _find_emails(self, domain):
        """Find email addresses associated with the domain."""
        emails = []
        
        # Common email patterns
        common_emails = [
            f'admin@{domain}',
            f'info@{domain}',
            f'contact@{domain}',
            f'support@{domain}',
            f'sales@{domain}',
            f'security@{domain}',
            f'webmaster@{domain}',
            f'postmaster@{domain}',
            f'hostmaster@{domain}',
            f'abuse@{domain}',
        ]
        
        # Try to scrape from website
        try:
            r = self.session.get(f'https://{domain}', timeout=10, verify=False)
            email_pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
            found = re.findall(email_pattern, r.text)
            emails.extend([e for e in found if domain in e])
        except:
            pass
        
        emails.extend(common_emails)
        return list(set(emails))[:20]
    
    def _detect_email_format(self, domain):
        """Detect the email format used by the organization."""
        formats = []
        
        # Common formats
        common_formats = [
            f'firstname.lastname@{domain}',
            f'firstname@{domain}',
            f'f.lastname@{domain}',
            f'firstnamelastname@{domain}',
            f'finitiallastname@{domain}',
            f'firstname.lastnameinitial@{domain}',
        ]
        
        formats.extend(common_formats)
        
        return {
            'detected': False,
            'likely_format': common_formats[0],
            'possible_formats': formats
        }
    
    def _find_related_domains(self, domain):
        """Find related domains (subsidiaries, dev/staging environments)."""
        related = []
        base = domain.split('.')[0] if '.' in domain else domain
        
        # Common related patterns
        patterns = [
            f'{base}.com', f'{base}.org', f'{base}.net', f'{base}.io',
            f'{base}.co', f'{base}.dev', f'{base}.app',
            f'dev.{base}.com', f'staging.{base}.com', f'test.{base}.com',
            f'api.{base}.com', f'admin.{base}.com',
            f'{base}dev.com', f'{base}labs.com', f'{base}group.com',
            f'{base}corp.com', f'{base}inc.com', f'{base}llc.com',
            f'get{base}.com', f'go{base}.com', f'my{base}.com',
        ]
        
        for pattern in patterns:
            try:
                import socket
                socket.gethostbyname(pattern)
                related.append(pattern)
            except:
                pass
        
        return related[:20]
    
    def _generate_summary(self, profile):
        """Generate a human-readable summary of OSINT findings."""
        parts = []
        
        if profile['subdomains']:
            parts.append(f"Found {len(profile['subdomains'])} subdomains")
        
        if profile['tech_stack']:
            tech_names = [t['name'] for t in profile['tech_stack']]
            parts.append(f"Tech stack: {', '.join(tech_names[:5])}")
        
        if profile['dns_records'].get('mx_records'):
            parts.append(f"Email provider: {profile['dns_records']['mx_records'][0]['exchange']}")
        
        if profile['related_domains']:
            parts.append(f"Found {len(profile['related_domains'])} related domains")
        
        if profile['emails']:
            parts.append(f"Found {len(profile['emails'])} email addresses")
        
        return ' | '.join(parts) if parts else 'Limited OSINT data available'
    
    def search_employees(self, domain, company_name=None):
        """Search for employee names and profiles."""
        employees = []
        
        if not company_name:
            company_name = domain.split('.')[0].title()
        
        # LinkedIn search (would require API in production)
        employees.append({
            'source': 'linkedin',
            'note': f'Search LinkedIn for: "{company_name}" employees',
            'search_url': f'https://www.linkedin.com/search/results/people/?keywords={quote(company_name)}'
        })
        
        # GitHub search
        employees.append({
            'source': 'github',
            'note': f'Search GitHub for: org:{domain} or email:*@{domain}',
            'search_url': f'https://github.com/search?q=org%3A{domain}+OR+%22%40{domain}%22&type=users'
        })
        
        return employees
    
    def get_osint_report(self, domain):
        """Get a formatted OSINT report."""
        profile = self.profile_target(domain)
        
        return {
            'domain': domain,
            'profile': profile,
            'risk_indicators': self._assess_risk(profile),
            'attack_surface': self._assess_attack_surface(profile)
        }
    
    def _assess_risk(self, profile):
        """Assess risk indicators from OSINT data."""
        indicators = []
        
        if len(profile.get('subdomains', [])) > 20:
            indicators.append({
                'level': 'high',
                'finding': 'Large subdomain attack surface',
                'detail': f'{len(profile["subdomains"])} subdomains discovered'
            })
        
        if any('dev' in s or 'staging' in s or 'test' in s for s in profile.get('subdomains', [])):
            indicators.append({
                'level': 'medium',
                'finding': 'Development/staging environments exposed',
                'detail': 'These often have weaker security controls'
            })
        
        if profile.get('dns_records', {}).get('txt_records', []):
            spf_found = any('v=spf1' in t for t in profile['dns_records']['txt_records'])
            if not spf_found:
                indicators.append({
                    'level': 'medium',
                    'finding': 'No SPF record found',
                    'detail': 'Domain vulnerable to email spoofing'
                })
        
        return indicators
    
    def _assess_attack_surface(self, profile):
        """Assess the overall attack surface."""
        surface = {
            'web_applications': len(profile.get('subdomains', [])),
            'email_systems': len(profile.get('dns_records', {}).get('mx_records', [])),
            'exposed_services': len(profile.get('tech_stack', [])),
            'related_entities': len(profile.get('related_domains', [])),
            'rating': 'LOW'
        }
        
        total = surface['web_applications'] + surface['email_systems'] + surface['exposed_services']
        if total > 30:
            surface['rating'] = 'HIGH'
        elif total > 15:
            surface['rating'] = 'MEDIUM'
        
        return surface


# Singleton instance
osint_engine = OSINTEngine()