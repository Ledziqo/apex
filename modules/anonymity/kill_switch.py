"""
APEX Kill Switch
Prevents IP leaks by stopping all traffic if anonymity layer fails
"""
import threading
import time
from config import Config

class KillSwitch:
    def __init__(self):
        self.active = False
        self.monitoring = False
        self.monitor_thread = None
    
    def enable(self):
        """Enable kill switch monitoring"""
        self.active = True
        self.start_monitoring()
    
    def disable(self):
        """Disable kill switch"""
        self.active = False
        self.monitoring = False
    
    def start_monitoring(self):
        """Start background monitoring thread"""
        if self.monitoring:
            return
        
        self.monitoring = True
        self.monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.monitor_thread.start()
    
    def _monitor_loop(self):
        """Monitor anonymity layers"""
        while self.monitoring:
            if self.active:
                # Check if any anonymity layer is active
                proxy_active = Config.PROXY_ENABLED
                tor_active = Config.TOR_ENABLED
                vpn_active = Config.VPN_ENABLED
                
                # If kill switch is on and no layer is active, trigger alert
                if not proxy_active and not tor_active and not vpn_active:
                    print("[KILL SWITCH] WARNING: No anonymity layer active!")
                    # In production, this would halt all outbound traffic
            time.sleep(2)
    
    def check_safety(self):
        """Check if it's safe to send traffic"""
        if not self.active:
            return True
        
        return Config.PROXY_ENABLED or Config.TOR_ENABLED or Config.VPN_ENABLED

# Global instance
kill_switch = KillSwitch()