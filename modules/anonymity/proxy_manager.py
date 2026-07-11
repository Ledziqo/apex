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
