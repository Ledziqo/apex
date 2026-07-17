"""
APEX Proxy Manager
Handles proxy chain, rotation, health checking, and kill switch
"""
import os
import random
import time
import threading
import requests
from config import Config

# GitHub proxy list sources (proxifly free-proxy-list repo)
PROXY_GITHUB_URLS = {
    'socks5': 'https://raw.githubusercontent.com/proxifly/free-proxy-list/main/proxies/socks5/data.txt',
    'socks4': 'https://raw.githubusercontent.com/proxifly/free-proxy-list/main/proxies/socks4/data.txt',
    'http': 'https://raw.githubusercontent.com/proxifly/free-proxy-list/main/proxies/http/data.txt',
    'https': 'https://raw.githubusercontent.com/proxifly/free-proxy-list/main/proxies/https/data.txt',
    'all': 'https://raw.githubusercontent.com/proxifly/free-proxy-list/main/proxies/all/data.txt',
}

class ProxyManager:
    def __init__(self):
        self.proxies = []
        self.active_proxy = None
        self.kill_switch = False
        self.load_proxies()
    
    def load_proxies(self):
        """Load proxies from file"""
        proxy_file = Config.PROXY_LIST_FILE
        if os.path.exists(proxy_file):
            with open(proxy_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        self.proxies.append(line)

    def fetch_from_github(self, proxy_type='all', replace=True):
        """Fetch proxies from proxifly free-proxy-list GitHub repo.
        
        Args:
            proxy_type: Type of proxies to fetch ('socks5', 'socks4', 'http', 'https', 'all')
            replace: If True, clears existing proxies before fetching (default: True)
        """
        url = PROXY_GITHUB_URLS.get(proxy_type, PROXY_GITHUB_URLS['all'])
        try:
            r = requests.get(url, timeout=15)
            if r.status_code != 200:
                return {'success': False, 'error': f'HTTP {r.status_code}', 'count': 0}
            
            lines = r.text.strip().split('\n')
            fetched = [line.strip() for line in lines if line.strip() and not line.startswith('#')]
            
            if replace:
                # Replace mode: clear existing proxies and use only fresh ones
                self.proxies = list(fetched)
                new_count = len(fetched)
            else:
                # Append mode: add to existing proxies (avoid duplicates)
                existing = set(self.proxies)
                new_count = 0
                for proxy in fetched:
                    if proxy not in existing:
                        self.proxies.append(proxy)
                        existing.add(proxy)
                        new_count += 1
            
            # Save to file
            proxy_file = Config.PROXY_LIST_FILE
            os.makedirs(os.path.dirname(proxy_file), exist_ok=True)
            with open(proxy_file, 'w') as f:
                f.write('\n'.join(self.proxies))
            
            return {
                'success': True,
                'count': len(fetched),
                'new': new_count,
                'total': len(self.proxies),
                'source': url,
                'mode': 'replace' if replace else 'append'
            }
        except Exception as e:
            return {'success': False, 'error': str(e), 'count': 0}
    
    def get_proxy(self):
        """Get a working proxy"""
        if not Config.PROXY_ENABLED or not self.proxies:
            return None
        
        # Rotate proxy
        if len(self.proxies) > 1:
            self.active_proxy = random.choice(self.proxies)
        elif len(self.proxies) == 1:
            self.active_proxy = self.proxies[0]
        
        if self.active_proxy:
            return {
                'http': self.active_proxy,
                'https': self.active_proxy
            }
        return None
    
    def check_proxy(self, proxy):
        """Test if a proxy is working"""
        try:
            test_url = 'http://httpbin.org/ip'
            proxies = {'http': proxy, 'https': proxy}
            r = requests.get(test_url, proxies=proxies, timeout=5)
            return r.status_code == 200
        except:
            return False
    
    def health_check(self):
        """Check all proxies and remove dead ones"""
        working = []
        for proxy in self.proxies:
            if self.check_proxy(proxy):
                working.append(proxy)
        self.proxies = working
        return len(working)
    
    def enable_kill_switch(self):
        """Enable kill switch - stops all traffic if proxy fails"""
        self.kill_switch = True
    
    def disable_kill_switch(self):
        """Disable kill switch"""
        self.kill_switch = False

    def check_proxy_health(self):
        """Check health of all proxies and return status for each."""
        results = []
        healthy_count = 0
        
        for proxy in self.proxies[:10]:  # Check up to 10
            status = self.check_proxy(proxy)
            results.append({
                'proxy': proxy[:50] + '...' if len(proxy) > 50 else proxy,
                'healthy': status,
                'response_time': status.get('response_time', 0) if status else 0
            })
            if status:
                healthy_count += 1
        
        # Auto-rotate dead proxies out
        if healthy_count < len(self.proxies):
            self.proxies = [p for p in self.proxies if self.check_proxy(p)]
        
        return {
            'total': len(self.proxies),
            'healthy': healthy_count,
            'dead': len(self.proxies) - healthy_count,
            'proxies': results,
            'auto_rotated': healthy_count < len(self.proxies)
        }
    
    def rotate_proxy(self):
        """Force rotate to a different proxy."""
        if len(self.proxies) > 1:
            current = self.active_proxy
            available = [p for p in self.proxies if p != current]
            if available:
                self.active_proxy = random.choice(available)
                return self.active_proxy
        return None


proxy_manager = ProxyManager()
