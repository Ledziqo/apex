"""
APEX v4.0 — Out-of-Band Callback Server
Catches blind XSS, blind SSRF, blind SQLi callbacks
"""
import threading, socket, requests, json, time
from http.server import HTTPServer, BaseHTTPRequestHandler
from datetime import datetime


class OOBHandler(BaseHTTPRequestHandler):
    """Handles incoming OOB callbacks from blind vulnerabilities."""
    callbacks = []
    
    def do_GET(self):
        OOBHandler.callbacks.append({
            'timestamp': datetime.now().isoformat(),
            'path': self.path,
            'headers': dict(self.headers),
            'client_ip': self.client_address[0],
        })
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b'OK')
    
    def do_POST(self):
        content_length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(content_length) if content_length > 0 else b''
        OOBHandler.callbacks.append({
            'timestamp': datetime.now().isoformat(),
            'path': self.path,
            'headers': dict(self.headers),
            'body': body.decode('utf-8', errors='replace')[:500],
            'client_ip': self.client_address[0],
        })
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b'OK')
    
    def log_message(self, format, *args):
        pass  # Suppress logs


class OOBServer:
    """Manages the OOB callback server for blind vulnerability detection."""
    
    def __init__(self, port=9999):
        self.port = port
        self.server = None
        self.thread = None
        self.running = False
        self.callback_url = f'http://localhost:{port}/'
    
    def start(self):
        """Start the OOB callback server in a background thread."""
        if self.running:
            return True
        try:
            self.server = HTTPServer(('0.0.0.0', self.port), OOBHandler)
            self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
            self.thread.start()
            self.running = True
            return True
        except Exception as e:
            print(f"[OOB] Failed to start: {e}")
            return False
    
    def stop(self):
        """Stop the OOB server."""
        if self.server:
            self.server.shutdown()
            self.running = False
    
    def get_callbacks(self, clear=True):
        """Get all received callbacks and optionally clear them."""
        callbacks = list(OOBHandler.callbacks)
        if clear:
            OOBHandler.callbacks.clear()
        return callbacks
    
    def wait_for_callback(self, timeout=10):
        """Wait for a callback to arrive within timeout seconds."""
        start = time.time()
        initial_count = len(OOBHandler.callbacks)
        while time.time() - start < timeout:
            if len(OOBHandler.callbacks) > initial_count:
                return OOBHandler.callbacks[-1]
            time.sleep(0.5)
        return None


# Global instance
oob_server = OOBServer()
