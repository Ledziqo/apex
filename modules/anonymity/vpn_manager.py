"""
APEX VPN Manager
Detects and verifies VPN connectivity
"""
import os
import subprocess
import socket
import requests
import re
import shutil
import time
from config import Config


class VPNManager:
    def __init__(self):
        self.enabled = False
        self.interface = Config.VPN_INTERFACE
        self.current_ip = None
        self.original_ip = None
        self._warp_cli_path = None

    def _find_warp_cli(self):
        """Find warp-cli binary in common locations (handles systemd limited PATH)"""
        if self._warp_cli_path:
            return self._warp_cli_path
        
        # Check common locations
        possible_paths = [
            'warp-cli',  # Default PATH
            '/usr/bin/warp-cli',
            '/usr/local/bin/warp-cli',
            '/opt/warp-cli/bin/warp-cli',
            '/snap/bin/warp-cli',
            '/usr/sbin/warp-cli',
        ]
        
        for path in possible_paths:
            try:
                result = subprocess.run([path, 'status'], capture_output=True, text=True, timeout=5)
                if result.returncode == 0 or 'Connected' in result.stdout or 'Status' in result.stdout:
                    self._warp_cli_path = path
                    return path
            except:
                continue
        
        # Also try shutil.which as fallback
        try:
            found = shutil.which('warp-cli')
            if found:
                self._warp_cli_path = found
                return found
        except:
            pass
        
        # Last resort: use find command to locate warp-cli anywhere on the filesystem
        try:
            result = subprocess.run(
                ['find', '/', '-name', 'warp-cli', '-type', 'f', '-maxdepth', '5', '2>/dev/null'],
                capture_output=True, text=True, timeout=10, shell=True
            )
            if result.stdout.strip():
                found_path = result.stdout.strip().split('\n')[0]
                self._warp_cli_path = found_path
                return found_path
        except:
            pass
        
        return None

    def _check_warp_service(self):
        """Check if warp-svc systemd service is running"""
        try:
            result = subprocess.run(
                ['systemctl', 'is-active', 'warp-svc'],
                capture_output=True, text=True, timeout=5
            )
            return result.stdout.strip() == 'active'
        except:
            return False

    def connect_warp(self):
        """Connect to Cloudflare Warp VPN"""
        warp_cli = self._find_warp_cli()
        if not warp_cli:
            return {'success': False, 'message': 'warp-cli not found on system'}
        try:
            # First check if already connected
            result = subprocess.run([warp_cli, 'status'], capture_output=True, text=True, timeout=5)
            if 'Connected' in result.stdout:
                return {'success': True, 'message': 'Already connected to Warp'}
            # Try to connect
            subprocess.run([warp_cli, 'connect'], capture_output=True, text=True, timeout=10)
            time.sleep(2)
            # Verify
            result = subprocess.run([warp_cli, 'status'], capture_output=True, text=True, timeout=5)
            if 'Connected' in result.stdout:
                self.enabled = True
                Config.VPN_ENABLED = True
                self.interface = 'CloudflareWarp'
                self.current_ip = self._get_public_ip()
                return {'success': True, 'message': 'Warp connected successfully', 'ip': self.current_ip}
            return {'success': False, 'message': 'Warp connect command ran but status not confirmed'}
        except Exception as e:
            return {'success': False, 'message': f'Warp connect failed: {str(e)}'}

    def disconnect_warp(self):
        """Disconnect from Cloudflare Warp VPN"""
        warp_cli = self._find_warp_cli()
        if not warp_cli:
            return {'success': False, 'message': 'warp-cli not found'}
        try:
            subprocess.run([warp_cli, 'disconnect'], capture_output=True, text=True, timeout=10)
            self.enabled = False
            Config.VPN_ENABLED = False
            return {'success': True, 'message': 'Warp disconnected'}
        except Exception as e:
            return {'success': False, 'message': str(e)}

    def enable(self):
        """Enable VPN routing"""
        self.enabled = True
        Config.VPN_ENABLED = True
        # Store original IP for comparison (before VPN connects)
        if not self.original_ip:
            self.original_ip = self._get_public_ip()
        # Give VPN a moment to establish, then get current IP
        time.sleep(2)
        self.current_ip = self._get_public_ip()
        return self.is_vpn_active()

    def connect_and_verify(self, max_wait=30):
        """Connect Warp VPN and verify IP actually changed.
        
        This is the REAL fix — it doesn't just check if warp-cli says 'Connected',
        it actually verifies the public IP changed before returning success.
        
        Args:
            max_wait: Maximum seconds to wait for IP change (default 30)
        """
        if not self.original_ip:
            self.original_ip = self._get_public_ip()
        
        # Step 1: Try to connect Warp
        warp_cli = self._find_warp_cli()
        if not warp_cli:
            return {'success': False, 'message': 'warp-cli not found on system'}
        
        # Check if already connected
        try:
            result = subprocess.run([warp_cli, 'status'], capture_output=True, text=True, timeout=5)
            already_connected = 'Connected' in result.stdout
        except:
            already_connected = False
        
        if not already_connected:
            try:
                subprocess.run([warp_cli, 'connect'], capture_output=True, text=True, timeout=10)
            except Exception as e:
                return {'success': False, 'message': f'warp-cli connect failed: {str(e)}'}
        
        # Step 2: Poll until IP changes or timeout
        start_time = time.time()
        while time.time() - start_time < max_wait:
            current_ip = self._get_public_ip()
            if current_ip and current_ip != self.original_ip and current_ip != 'Unknown':
                # IP changed — VPN is actually working
                self.enabled = True
                Config.VPN_ENABLED = True
                self.current_ip = current_ip
                self.interface = 'CloudflareWarp'
                return {
                    'success': True,
                    'message': f'VPN connected and verified — IP changed from {self.original_ip} to {current_ip}',
                    'original_ip': self.original_ip,
                    'current_ip': current_ip,
                    'protected': True
                }
            time.sleep(2)
        
        # Step 3: Timeout — IP never changed
        final_ip = self._get_public_ip()
        return {
            'success': False,
            'message': f'VPN connect timed out after {max_wait}s — IP still {final_ip} (same as original {self.original_ip})',
            'original_ip': self.original_ip,
            'current_ip': final_ip,
            'protected': False
        }

    def disable(self):
        """Disable VPN routing"""
        self.enabled = False
        Config.VPN_ENABLED = False
        self.current_ip = self._get_public_ip()
        return True

    def is_vpn_active(self):
        """Check if VPN interface is actually up and routing traffic"""
        if not self.enabled:
            return False

        # PRIMARY METHOD: Compare public IP before/after VPN
        # This is the most reliable check — if IPs differ, traffic is routing through VPN
        if self.original_ip and self.current_ip:
            if self.original_ip != self.current_ip:
                return True

        # Method 1: Check Warp CLI status (most reliable for Cloudflare Warp)
        warp_cli = self._find_warp_cli()
        if warp_cli:
            try:
                result = subprocess.run([warp_cli, 'status'], capture_output=True, text=True, timeout=5)
                if 'Connected' in result.stdout or 'connected' in result.stdout:
                    self.interface = 'CloudflareWarp'
                    return True
            except:
                pass
        
        # Method 1b: Check warp-svc systemd service as fallback
        if self._check_warp_service():
            self.interface = 'CloudflareWarp'
            return True

        # Method 2: Check for ANY VPN interface via ip link show (robust parsing)
        try:
            result = subprocess.run(['ip', 'link', 'show'], capture_output=True, text=True, timeout=3)
            vpn_keywords = ['tun', 'wg', 'warp', 'cloudflare', 'utun', 'CloudflareWarp']
            for line in result.stdout.split('\n'):
                line_lower = line.lower()
                # Check if any VPN keyword is in this line AND the interface is UP
                if any(kw in line_lower for kw in vpn_keywords) and 'up' in line_lower and 'state up' in line_lower:
                    # Extract interface name - format: "3: interface_name: <BROADCAST,MULTICAST,UP>"
                    match = re.match(r'\d+:\s+([^:@\s]+)', line)
                    if match:
                        self.interface = match.group(1)
                        return True
        except:
            pass

        # Method 3: Check specific configured interface
        try:
            result = subprocess.run(
                ['ip', 'link', 'show', self.interface],
                capture_output=True, text=True, timeout=3
            )
            if 'UP' in result.stdout and 'state UP' in result.stdout:
                return True
        except:
            pass

        # Method 4: Check /sys/class/net for VPN interfaces (Linux)
        for iface_name in ['tun0', 'wg0', 'warp', 'CloudflareWarp']:
            if os.path.exists(f'/sys/class/net/{iface_name}'):
                try:
                    with open(f'/sys/class/net/{iface_name}/operstate', 'r') as f:
                        if f.read().strip() == 'up':
                            self.interface = iface_name
                            return True
                except:
                    pass

        # Method 5: Check /proc/net/dev for VPN interfaces (universal Linux fallback)
        try:
            with open('/proc/net/dev', 'r') as f:
                content = f.read()
            vpn_keywords = ['tun', 'wg', 'warp', 'cloudflare', 'utun', 'CloudflareWarp']
            for line in content.split('\n')[2:]:  # Skip header lines
                if line.strip():
                    iface = line.split(':')[0].strip()
                    iface_lower = iface.lower()
                    if any(kw in iface_lower for kw in vpn_keywords):
                        self.interface = iface
                        return True
        except:
            pass

        return False

    def _get_public_ip(self):
        """Get current public IP address"""
        try:
            r = requests.get('https://api.ipify.org?format=json', timeout=5)
            return r.json().get('ip', 'Unknown')
        except:
            try:
                r = requests.get('https://httpbin.org/ip', timeout=5)
                return r.json().get('origin', 'Unknown')
            except:
                return 'Unknown'

    def get_status(self):
        """Get detailed VPN status"""
        return {
            'enabled': self.enabled,
            'interface': self.interface,
            'active': self.is_vpn_active(),
            'current_ip': self.current_ip or self._get_public_ip(),
            'original_ip': self.original_ip
        }

    def get_vpn_session(self):
        """Get a requests session — VPN routing is handled at OS level"""
        if not self.enabled or not self.is_vpn_active():
            return None
        # VPN routes at OS level, so no special proxy config needed
        session = requests.Session()
        session.verify = False
        return session

    def verify_protection(self):
        """Verify that traffic is actually going through VPN by comparing IPs"""
        if not self.enabled:
            return {'protected': False, 'reason': 'VPN not enabled'}
        
        # Get current public IP
        current_ip = self._get_public_ip()
        self.current_ip = current_ip
        
        # Store original IP if not set
        if not self.original_ip:
            self.original_ip = self._get_public_ip()
        
        # Check if Warp CLI says connected
        warp_connected = False
        warp_cli = self._find_warp_cli()
        if warp_cli:
            try:
                result = subprocess.run([warp_cli, 'status'], capture_output=True, text=True, timeout=5)
                warp_connected = 'Connected' in result.stdout or 'connected' in result.stdout
            except:
                pass
        
        # If Warp says connected, check if IP actually changed
        if warp_connected:
            self.interface = 'CloudflareWarp'
            if self.original_ip and current_ip != self.original_ip:
                # IP changed — VPN is actually working
                return {
                    'protected': True,
                    'current_ip': current_ip,
                    'original_ip': self.original_ip,
                    'interface': self.interface,
                    'method': 'warp-cli'
                }
            else:
                # Warp says connected but IP didn't change — not actually routing
                return {
                    'protected': False,
                    'current_ip': current_ip,
                    'original_ip': self.original_ip,
                    'interface': self.interface,
                    'method': 'warp-cli',
                    'reason': f'Warp connected but IP unchanged ({current_ip}) — traffic not routing through VPN'
                }
        
        # Fallback: check warp-svc systemd service
        if self._check_warp_service():
            self.interface = 'CloudflareWarp'
            if self.original_ip and current_ip != self.original_ip:
                return {
                    'protected': True,
                    'current_ip': current_ip,
                    'original_ip': self.original_ip,
                    'interface': self.interface,
                    'method': 'warp-svc'
                }
            else:
                return {
                    'protected': False,
                    'current_ip': current_ip,
                    'original_ip': self.original_ip,
                    'interface': self.interface,
                    'method': 'warp-svc',
                    'reason': f'Warp service active but IP unchanged ({current_ip})'
                }
        
        if not self.is_vpn_active():
            return {'protected': False, 'reason': 'VPN interface not detected'}
        
        # Generic VPN check — compare IPs
        if self.original_ip and current_ip == self.original_ip:
            return {'protected': False, 'reason': f'IP unchanged ({current_ip}) — VPN may not be routing traffic'}
        
        return {
            'protected': True,
            'current_ip': current_ip,
            'original_ip': self.original_ip,
            'interface': self.interface
        }

    def start_openvpn(self, config_path):
        """Start OpenVPN with a config file (Linux only)"""
        try:
            subprocess.Popen(['openvpn', '--config', config_path, '--daemon'],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            time.sleep(3)
            self.enable()
            return self.is_vpn_active()
        except:
            return False

    def start_wireguard(self, config_path):
        """Start WireGuard with a config file (Linux only)"""
        try:
            subprocess.Popen(['wg-quick', 'up', config_path],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            time.sleep(3)
            self.enable()
            return self.is_vpn_active()
        except:
            return False

    def enable_kill_switch(self):
        """Block all non-VPN traffic using firewall rules"""
        if not self.is_vpn_active():
            return False
        try:
            # Linux iptables kill switch
            subprocess.run(['iptables', '-A', 'OUTPUT', '-o', self.interface, '-j', 'ACCEPT'],
                         capture_output=True, timeout=3)
            subprocess.run(['iptables', '-A', 'OUTPUT', '-o', 'lo', '-j', 'ACCEPT'],
                         capture_output=True, timeout=3)
            subprocess.run(['iptables', '-A', 'OUTPUT', '-j', 'DROP'],
                         capture_output=True, timeout=3)
            return True
        except:
            pass
        
        try:
            # Windows firewall kill switch
            subprocess.run(['netsh', 'advfirewall', 'firewall', 'add', 'rule',
                          'name="APEX Kill Switch"', 'dir=out', 'action=block',
                          'remoteip=any'], capture_output=True, timeout=3)
            return True
        except:
            pass
        
        return False

    def disable_kill_switch(self):
        """Remove firewall kill switch rules"""
        try:
            subprocess.run(['iptables', '-F', 'OUTPUT'], capture_output=True, timeout=3)
            subprocess.run(['iptables', '-A', 'OUTPUT', '-j', 'ACCEPT'], capture_output=True, timeout=3)
            return True
        except:
            pass
        
        try:
            subprocess.run(['netsh', 'advfirewall', 'firewall', 'delete', 'rule',
                          'name="APEX Kill Switch"'], capture_output=True, timeout=3)
            return True
        except:
            pass
        
        return False

    def monitor_connection(self, callback=None):
        """Monitor VPN connection in a background thread. Calls callback if VPN drops."""
        import threading
        def _monitor():
            while self.enabled:
                if not self.is_vpn_active():
                    if callback:
                        callback()
                    self.disable()
                    break
                time.sleep(3)
        t = threading.Thread(target=_monitor, daemon=True)
        t.start()
        return t


# Global instance
vpn_manager = VPNManager()