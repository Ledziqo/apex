"""
APEX Tor Manager
Handles Tor integration for anonymous scanning
"""
import os
import socket
import requests
from config import Config

class TorManager:
    def __init__(self):
        self.enabled = False
        self.socks_port = Config.TOR_SOCKS_PORT
    
    def enable(self):
        """Enable Tor routing"""
        self.enabled = True
        Config.TOR_ENABLED = True
        return True
    
    def disable(self):
        """Disable Tor routing"""
        self.enabled = False
        Config.TOR_ENABLED = False
        return True
    
    def get_tor_session(self):
        """Get a requests session routed through Tor"""
        if not self.enabled:
            return requests
        
        session = requests.Session()
        session.proxies = {
            'http': f'socks5h://127.0.0.1:{self.socks_port}',
            'https': f'socks5h://127.0.0.1:{self.socks_port}'
        }
        return session
    
    def check_tor(self):
        """Check if Tor is running"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            result = sock.connect_ex(('127.0.0.1', self.socks_port))
            sock.close()
            return result == 0
        except:
            return False
    
    def get_tor_ip(self):
        """Get current Tor exit node IP"""
        try:
            session = self.get_tor_session()
            r = session.get('http://httpbin.org/ip', timeout=10)
            return r.json().get('origin', 'Unknown')
        except:
            return 'Unknown'

# Global instance
tor_manager = TorManager()