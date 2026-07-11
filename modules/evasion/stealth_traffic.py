"""
APEX v3.0 — Stealth Traffic Engine
Human-like traffic patterns to evade detection and rate limiting.
"""

import time
import random
import math
from datetime import datetime


class StealthTraffic:
    """Generates human-like traffic patterns to avoid detection."""
    
    def __init__(self):
        self.request_count = 0
        self.session_start = datetime.now()
        self.behavior_profile = self._generate_behavior_profile()
        self.noise_requests = [
            '/favicon.ico', '/robots.txt', '/sitemap.xml',
            '/assets/main.css', '/assets/app.js', '/images/logo.png',
            '/api/health', '/.well-known/security.txt',
            '/static/css/bootstrap.min.css', '/static/js/jquery.min.js'
        ]
    
    def _generate_behavior_profile(self):
        """Generate a unique behavior profile to mimic different user types."""
        profiles = [
            {
                'name': 'security_researcher',
                'avg_delay': 1.5,
                'burst_probability': 0.1,
                'noise_ratio': 0.3,
                'session_duration': 1800,  # 30 min
                'think_time_mean': 3.0,
                'think_time_std': 1.5
            },
            {
                'name': 'developer',
                'avg_delay': 0.8,
                'burst_probability': 0.2,
                'noise_ratio': 0.2,
                'session_duration': 3600,
                'think_time_mean': 2.0,
                'think_time_std': 1.0
            },
            {
                'name': 'normal_user',
                'avg_delay': 2.5,
                'burst_probability': 0.05,
                'noise_ratio': 0.4,
                'session_duration': 900,
                'think_time_mean': 5.0,
                'think_time_std': 3.0
            }
        ]
        return random.choice(profiles)
    
    def human_delay(self, context='navigation'):
        """Apply a human-like delay between requests."""
        profile = self.behavior_profile
        
        # Different delay patterns based on context
        if context == 'navigation':
            # User clicking around - moderate delays
            base_delay = random.gauss(profile['think_time_mean'], profile['think_time_std'])
        elif context == 'form_submission':
            # User filling a form - longer delay
            base_delay = random.gauss(profile['think_time_mean'] * 2, profile['think_time_std'] * 1.5)
        elif context == 'page_load':
            # Page resources loading - short delays
            base_delay = random.uniform(0.1, 0.5)
        elif context == 'scan':
            # Scanning but trying to look human
            base_delay = random.gauss(profile['avg_delay'], 0.5)
        else:
            base_delay = random.uniform(0.5, 3.0)
        
        # Ensure minimum delay
        delay = max(0.1, base_delay)
        
        # Add occasional micro-bursts (rapid requests like a real user)
        if random.random() < profile['burst_probability']:
            delay = random.uniform(0.05, 0.2)
        
        # Add jitter
        jitter = random.uniform(-0.2, 0.2) * delay
        delay = max(0.05, delay + jitter)
        
        time.sleep(delay)
        self.request_count += 1
        
        return delay
    
    def randomize_request_order(self, requests_list):
        """Randomize the order of requests to avoid predictable patterns."""
        # Keep some sequential but shuffle most
        if len(requests_list) <= 3:
            return requests_list
        
        # Keep first request (usually the main page)
        first = requests_list[0]
        rest = requests_list[1:]
        random.shuffle(rest)
        
        return [first] + rest
    
    def inject_noise_requests(self, target_url, count=2):
        """Inject random noise requests between actual attack requests."""
        noise = []
        for _ in range(count):
            path = random.choice(self.noise_requests)
            noise.append({
                'url': target_url.rstrip('/') + path,
                'type': 'noise',
                'method': 'GET',
                'headers': self._get_noise_headers()
            })
        return noise
    
    def _get_noise_headers(self):
        """Generate realistic browser headers for noise requests."""
        user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0',
        ]
        
        return {
            'User-Agent': random.choice(user_agents),
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': random.choice(['en-US,en;q=0.9', 'en-GB,en;q=0.8', 'en;q=0.9']),
            'Accept-Encoding': 'gzip, deflate, br',
            'Cache-Control': random.choice(['no-cache', 'max-age=0']),
            'Connection': 'keep-alive',
            'Sec-Fetch-Dest': 'document',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-Site': 'none',
            'Sec-Fetch-User': '?1',
        }
    
    def get_browser_tls_fingerprint(self):
        """Return a realistic browser TLS fingerprint configuration."""
        return {
            'cipher_suites': [
                'TLS_AES_128_GCM_SHA256',
                'TLS_AES_256_GCM_SHA384',
                'TLS_CHACHA20_POLY1305_SHA256'
            ],
            'extensions': [
                'server_name',
                'extended_master_secret',
                'renegotiation_info',
                'supported_groups',
                'ec_point_formats',
                'session_ticket',
                'application_layer_protocol_negotiation',
                'status_request',
                'signature_algorithms',
                'signed_certificate_timestamp'
            ],
            'tls_version': 'TLS 1.3',
            'ja3_hash': self._generate_ja3_like()
        }
    
    def _generate_ja3_like(self):
        """Generate a JA3-like fingerprint hash."""
        import hashlib
        components = [
            '771',  # TLS 1.2
            '4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53',
            '0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513-21-41',
            '29-23-24',
            '0'
        ]
        fingerprint = ','.join(components)
        return hashlib.md5(fingerprint.encode()).hexdigest()
    
    def simulate_human_session(self, target_url, duration_seconds=60):
        """Simulate a human browsing session on the target."""
        start_time = time.time()
        pages_visited = 0
        
        common_paths = ['/', '/about', '/contact', '/login', '/register', '/blog', '/products']
        
        while time.time() - start_time < duration_seconds:
            path = random.choice(common_paths)
            url = target_url.rstrip('/') + path
            
            # Simulate page view
            self.human_delay('navigation')
            pages_visited += 1
            
            # Simulate reading the page
            read_time = random.gauss(5, 3)
            time.sleep(max(1, read_time))
            
            # Occasionally simulate clicking a link
            if random.random() < 0.3:
                self.human_delay('navigation')
        
        return {
            'pages_visited': pages_visited,
            'duration': time.time() - start_time,
            'profile': self.behavior_profile['name']
        }
    
    def get_traffic_stats(self):
        """Return traffic statistics."""
        elapsed = (datetime.now() - self.session_start).total_seconds()
        return {
            'total_requests': self.request_count,
            'session_duration_seconds': elapsed,
            'requests_per_minute': (self.request_count / max(1, elapsed)) * 60,
            'behavior_profile': self.behavior_profile['name'],
            'noise_ratio': self.behavior_profile['noise_ratio']
        }


# Singleton instance
stealth_traffic = StealthTraffic()