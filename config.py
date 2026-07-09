import os

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY', 'apex-red-team-secret-key-2024')
    SQLALCHEMY_DATABASE_URI = 'sqlite:///data/apex.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # APEX Login
    APEX_EMAIL = 'Apex@gmail.com'
    APEX_PASSWORD = 'Apex2005'
    
    # Scan Settings
    MAX_CONCURRENT_SCANS = 1
    SCAN_TIMEOUT = 300
    REQUEST_DELAY_MIN = 0.5
    REQUEST_DELAY_MAX = 2.0
    
    # Proxy Settings
    PROXY_ENABLED = False
    PROXY_LIST_FILE = 'data/proxies.txt'
    PROXY_ROTATE_INTERVAL = 5
    
    # Tor Settings
    TOR_ENABLED = False
    TOR_SOCKS_PORT = 9050
    TOR_CONTROL_PORT = 9051
    
    # VPN Settings
    VPN_ENABLED = False
    VPN_INTERFACE = 'tun0'
    
    # Upload Settings
    UPLOAD_FOLDER = 'data/uploads'
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024
    
    # Report Settings
    REPORT_FOLDER = 'reports'
    
    # Wordlists
    WORDLIST_DIR = 'payloads'
    
    # C2 Settings
    C2_LISTEN_HOST = '0.0.0.0'
    C2_LISTEN_PORT = 8443