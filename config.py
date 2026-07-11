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
    CRAWL_DEPTH = 3
    CRAWL_MAX_PAGES = 50
    CRAWL_COMMON_PATHS = True
    
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

    # AI Settings (OpenAI-compatible — works with Ollama, Groq, OpenRouter, etc.)
    AI_ENABLED = True
    AI_API_KEY = os.environ.get('AI_API_KEY', 'ollama')
    AI_BASE_URL = os.environ.get('AI_BASE_URL', 'http://localhost:11434/v1')
    AI_MODEL = os.environ.get('AI_MODEL', 'llama3.2')
    AI_MAX_TOKENS = 2000
    AI_TEMPERATURE = 0.7

    # Webhook Settings
    DISCORD_WEBHOOK_URL = os.environ.get('DISCORD_WEBHOOK_URL', '')
    TELEGRAM_BOT_TOKEN = os.environ.get('TELEGRAM_BOT_TOKEN', '')
    TELEGRAM_CHAT_ID = os.environ.get('TELEGRAM_CHAT_ID', '')

    # Session Settings
    SESSION_DIR = 'data/sessions'
    SESSION_AUTO_SAVE_INTERVAL = 30

    # JS Rendering (SPA crawling)
    JS_RENDER_ENABLED = True

    # Auth-Aware Scanning
    AUTH_ENABLED = False
    AUTH_USERNAME = ''
    AUTH_PASSWORD = ''
    AUTH_LOGIN_PATH = '/login'
    AUTH_COOKIES = ''

    # Adaptive Rate Limiting
    RATE_LIMIT_ENABLED = True
    RATE_LIMIT_MAX_BACKOFF = 30

    # v3.0 — NUKE Engine
    NUKE_ENABLED = True
    BATCH_SCAN_THREADS = 5

    # v3.0 — UI Settings
    THEME = 'dark'  # dark/light
    CHART_ENABLED = True

    # v3.0 — PoC Generator
    POC_AUTO_GENERATE = True

    # v3.0 — Per-Vuln Webhooks
    PER_VULN_WEBHOOK = False
