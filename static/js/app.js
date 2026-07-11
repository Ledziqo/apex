// ============================================================
// APEX — Hacker's Co-Pilot
// Dashboard JavaScript
// ============================================================

var socket = null;
try {
    if (typeof io !== 'undefined') {
        socket = io();
    }
} catch(e) {
    console.warn('Socket.io not available, running in offline mode');
}
let currentScanId = null;
let vulnerabilities = [];
let selectedVulns = new Set();
let proxyEnabled = false, torEnabled = false, vpnEnabled = false;
let activeTab = 'overview';
let scanHistory = [];
let lootData = { credentials: [], databases: [], files: [] };
let exploitSteps = [];
let currentExploitId = null;
let aiSettings = { api_key: 'ollama', base_url: 'http://localhost:11434/v1', model: 'llama3.2' };

// ============================================================
// INIT
// ============================================================
document.addEventListener('DOMContentLoaded', () => {
    loadSettings();
    setupKeyboardShortcuts();
    socket.emit('request_feed');
    loadHistory();
});

// ============================================================
// SOCKET EVENTS
// ============================================================
socket.on('connect', () => {
    document.getElementById('connectionStatus').classList.remove('offline');
    document.getElementById('connectionText').textContent = 'CONNECTED';
});

socket.on('disconnect', () => {
    document.getElementById('connectionStatus').classList.add('offline');
    document.getElementById('connectionText').textContent = 'DISCONNECTED';
});

socket.on('feed_update', (e) => addFeed(e));
socket.on('feed_history', (h) => h.forEach(e => addFeed(e)));

socket.on('progress_update', (d) => {
    if (d.scan_id === currentScanId) {
        const bar = document.getElementById('progressBar');
        const fill = document.getElementById('progressFill');
        bar.style.display = 'block';
        fill.style.width = d.progress + '%';
    }
});

socket.on('scan_complete', (d) => {
    vulnerabilities = d.vulnerabilities || [];
    selectedVulns.clear();
    updateVulnBadge(vulnerabilities.length);
    renderVulns(d.vulnerabilities, d.summary);
    document.getElementById('scanBtn').disabled = false;
    document.getElementById('nukeBtn').disabled = false;
    document.getElementById('scanStatus').innerHTML = '<span class="badge badge-success">COMPLETE</span>';
    document.getElementById('progressBar').style.display = 'none';
    updateStats();
    loadHistory();
    toast('Scan complete — ' + vulnerabilities.length + ' vulnerabilities found', 'success');
});

socket.on('exploit_step', (d) => {
    addExploitStep(d);
});

socket.on('exploit_complete', (d) => {
    document.getElementById('nukeBtn').disabled = false;
    document.getElementById('scanStatus').innerHTML = '<span class="badge badge-success">DONE</span>';
    updateStats();
    toast(`Exploitation complete — ${d.success}/${d.success + d.failed} successful`, d.success > 0 ? 'success' : 'warning');
});

// ============================================================
// NAVIGATION
// ============================================================
function switchTab(tab) {
    activeTab = tab;
    document.querySelectorAll('.tab-content').forEach(t => t.classList.remove('active'));
    document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
    const tabEl = document.getElementById('tab-' + tab);
    if (tabEl) tabEl.classList.add('active');
    const navEl = document.querySelector(`.nav-item[data-tab="${tab}"]`);
    if (navEl) navEl.classList.add('active');
    if (tab === 'history') loadHistory();
    if (tab === 'settings') loadSettingsToForm();
}

function toggleSidebar() {
    document.getElementById('sidebar').classList.toggle('collapsed');
}

function toggleAiSidebar() {
    document.getElementById('aiSidebar').classList.toggle('collapsed');
}

// ============================================================
// TARGET & SCAN
// ============================================================
function startScan(type) {
    const target = document.getElementById('targetInput').value.trim();
    if (!target) { toast('Enter a target URL', 'error'); return; }
    document.getElementById('scanBtn').disabled = true;
    document.getElementById('nukeBtn').disabled = true;
    document.getElementById('progressBar').style.display = 'block';
    document.getElementById('progressFill').style.width = '0%';
    document.getElementById('scanStatus').innerHTML = '<span class="badge badge-running">SCANNING</span>';
    document.getElementById('resultsPanel').innerHTML = '<div class="empty-state"><div class="empty-icon">🔍</div>[ SCANNING ] Analyzing target...</div>';
    document.getElementById('liveFeed').innerHTML = '';
    document.getElementById('exploitMonitor').innerHTML = '<div class="empty-state"><div class="empty-icon">💣</div>Awaiting exploitation...</div>';
    document.getElementById('nextStepsPanel').innerHTML = '';
    vulnerabilities = [];
    selectedVulns.clear();
    exploitSteps = [];
    updateVulnBadge(0);
    switchTab('exploit');
    fetch('/api/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target, scan_type: type })
    }).then(r => r.json()).then(d => { currentScanId = d.scan_id; })
      .catch(() => {
          addFeed({ timestamp: time(), message: 'SCAN FAILED TO START', level: 'error' });
          document.getElementById('scanBtn').disabled = false;
          toast('Scan failed to start', 'error');
      });
}

function startNuke() {
    if (vulnerabilities.length === 0) { toast('No vulnerabilities to exploit', 'warning'); return; }
    selectedVulns = new Set(vulnerabilities.map((_, i) => i));
    runExploits();
}

// ============================================================
// FEED
// ============================================================
function addFeed(entry) {
    const feed = document.getElementById('liveFeed');
    if (feed.querySelector('.empty-state')) feed.innerHTML = '';
    const div = document.createElement('div');
    div.className = 'feed-line';
    div.innerHTML = `<span class="ts">[${entry.timestamp}]</span><span class="lvl-${entry.level}">${escapeHtml(entry.message)}</span>`;
    feed.appendChild(div);
    feed.scrollTop = feed.scrollHeight;
}

// ============================================================
// ANONYMITY
// ============================================================
function toggleAnon(type) {
    const toggles = { proxy: 'proxyToggle', tor: 'torToggle', vpn: 'vpnToggle' };
    const states = { proxy: proxyEnabled, tor: torEnabled, vpn: vpnEnabled };
    const newState = !states[type];
    if (type === 'proxy') proxyEnabled = newState;
    if (type === 'tor') torEnabled = newState;
    if (type === 'vpn') vpnEnabled = newState;
    const el = document.getElementById(toggles[type]);
    el.classList.toggle('active', newState);
    fetch(`/api/${type}/toggle`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ enabled: newState })
    });
    toast(`${type.toUpperCase()} ${newState ? 'ENABLED' : 'DISABLED'}`, 'info');
}

// ============================================================
// VULNERABILITIES
// ============================================================
function renderVulns(vulns, summary) {
    const panel = document.getElementById('resultsPanel');
    updateVulnBadge(vulns ? vulns.length : 0);
    if (!vulns || vulns.length === 0) {
        panel.innerHTML = '<div class="empty-state"><div class="empty-icon">🛡️</div>No vulnerabilities detected</div>';
        return;
    }
    const order = { critical: 0, high: 1, medium: 2, low: 3 };
    vulns.sort((a, b) => (order[a.severity] || 4) - (order[b.severity] || 4));
    let html = '<div class="flex flex-wrap gap-2 mb-3">';
    if (summary.critical) html += `<span class="badge badge-critical">CRITICAL ${summary.critical}</span>`;
    if (summary.high) html += `<span class="badge badge-high">HIGH ${summary.high}</span>`;
    if (summary.medium) html += `<span class="badge badge-medium">MEDIUM ${summary.medium}</span>`;
    if (summary.low) html += `<span class="badge badge-low">LOW ${summary.low}</span>`;
    html += '</div>';
    html += '<div style="max-height:350px;overflow-y:auto;">';
    html += '<table class="data-table"><thead><tr><th width="30">#</th><th>TYPE</th><th>SEVERITY</th><th>ENDPOINT</th><th>PARAMETER</th><th>PAYLOAD</th></tr></thead><tbody>';
    vulns.forEach((v, i) => {
        const sel = selectedVulns.has(i);
        const sevClass = v.severity === 'critical' ? 'badge-critical' : v.severity === 'high' ? 'badge-high' : v.severity === 'medium' ? 'badge-medium' : 'badge-low';
        html += `<tr class="${sel ? 'selected' : ''} cursor-pointer" onclick="toggleVuln(${i}, this)">
            <td><input type="checkbox" ${sel ? 'checked' : ''} onclick="event.stopPropagation();toggleVuln(${i}, this.closest('tr'))" style="accent-color:var(--orange);cursor:pointer;"></td>
            <td style="font-weight:600;">${(v.type || 'UNKNOWN').toUpperCase()}</td>
            <td><span class="badge ${sevClass}">${(v.severity || 'low').toUpperCase()}</span></td>
            <td class="truncate" style="max-width:180px;" title="${escapeHtml(v.endpoint || 'N/A')}">${escapeHtml(v.endpoint || 'N/A')}</td>
            <td>${escapeHtml(v.parameter || 'N/A')}</td>
            <td class="truncate text-mono" style="max-width:150px;font-size:10px;" title="${escapeHtml((v.payload || '').substring(0, 200))}">${escapeHtml((v.payload || '').substring(0, 60))}</td>
        </tr>`;
    });
    html += '</tbody></table></div>';
    html += `<div class="flex flex-wrap gap-2 mt-3">
        <button class="btn btn-primary" onclick="runExploits()" id="exploitBtn">💣 EXPLOIT (${selectedVulns.size})</button>
        <button class="btn" onclick="selectAllVulns()">SELECT ALL</button>
        <button class="btn" onclick="clearAllVulns()">CLEAR</button>
        <button class="btn btn-sm" onclick="exportVulns()">📥 EXPORT</button>
    </div>`;
    panel.innerHTML = html;
}

function toggleVuln(index, row) {
    if (selectedVulns.has(index)) { selectedVulns.delete(index); row.classList.remove('selected'); row.querySelector('input').checked = false; }
    else { selectedVulns.add(index); row.classList.add('selected'); row.querySelector('input').checked = true; }
    updateExploitBtn();
}

function selectAllVulns() { vulnerabilities.forEach((_, i) => selectedVulns.add(i)); renderVulns(vulnerabilities, getSummary()); }
function clearAllVulns() { selectedVulns.clear(); renderVulns(vulnerabilities, getSummary()); }

function getSummary() {
    const s = { critical: 0, high: 0, medium: 0, low: 0 };
    vulnerabilities.forEach(v => { if (s[v.severity] !== undefined) s[v.severity]++; });
    return s;
}

function updateExploitBtn() {
    const btn = document.getElementById('exploitBtn');
    if (btn) { btn.textContent = `💣 EXPLOIT (${selectedVulns.size})`; btn.disabled = selectedVulns.size === 0; }
}

function updateVulnBadge(count) {
    const badge = document.getElementById('vulnBadge');
    if (badge) { badge.textContent = count; badge.style.display = count > 0 ? 'inline' : 'none'; }
}

function exportVulns() {
    const data = JSON.stringify(vulnerabilities, null, 2);
    const blob = new Blob([data], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url; a.download = 'apex_vulnerabilities.json'; a.click();
    URL.revokeObjectURL(url);
    toast('Vulnerabilities exported', 'success');
}

// ============================================================
// EXPLOITS
// ============================================================
function runExploits() {
    if (selectedVulns.size === 0) { toast('Select vulnerabilities first', 'warning'); return; }
    const selected = Array.from(selectedVulns).map(i => vulnerabilities[i]);
    document.getElementById('nukeBtn').disabled = true;
    document.getElementById('scanStatus').innerHTML = '<span class="badge badge-running">EXPLOITING</span>';
    document.getElementById('exploitMonitor').innerHTML = '';
    document.getElementById('nextStepsPanel').innerHTML = '';
    exploitSteps = [];
    switchTab('exploit');
    fetch('/api/exploit', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ scan_id: currentScanId, vulnerabilities: selected })
    }).then(r => r.json()).then(d => { currentExploitId = d.exploit_id; })
      .catch(() => {
          addFeed({ timestamp: time(), message: 'EXPLOIT FAILED', level: 'error' });
          document.getElementById('nukeBtn').disabled = false;
          toast('Exploit failed to start', 'error');
      });
}

function addExploitStep(step) {
    exploitSteps.push(step);
    const monitor = document.getElementById('exploitMonitor');
    if (monitor.querySelector('.empty-state')) monitor.innerHTML = '';
    const div = document.createElement('div');
    const cls = step.phase === 'phase' ? 'phase-start' : step.phase === 'command' ? 'command' : step.phase === 'response' ? 'response' : step.phase === 'error' ? 'error' : '';
    div.className = 'exploit-step ' + cls;
    let html = `<div class="step-header"><span class="step-time">[${step.timestamp || time()}]</span><span class="step-label">${escapeHtml(step.label || '')}</span></div>`;
    if (step.command) html += `<div class="step-cmd">${escapeHtml(step.command)}<span class="copy-cmd" onclick="copyText('${escapeAttr(step.command)}')">📋</span></div>`;
    if (step.payload) html += `<div class="step-cmd">Payload: ${escapeHtml(step.payload)}<span class="copy-cmd" onclick="copyText('${escapeAttr(step.payload)}')">📋</span></div>`;
    if (step.url) html += `<div class="step-cmd">URL: ${escapeHtml(step.url)}<span class="copy-cmd" onclick="copyText('${escapeAttr(step.url)}')">📋</span></div>`;
    if (step.result) html += `<div class="step-result ${step.success ? 'success' : step.error ? 'error' : ''}">${escapeHtml(step.result)}</div>`;
    if (step.details) {
        step.details.forEach(d => { html += `<div class="step-result">→ ${escapeHtml(d)}</div>`; });
    }
    div.innerHTML = html;
    monitor.appendChild(div);
    monitor.scrollTop = monitor.scrollHeight;
}

// ============================================================
// AI CHAT
// ============================================================
function sendAiMessage() {
    const input = document.getElementById('aiChatInput');
    const msg = input.value.trim();
    if (!msg) return;
    addChatMessage('user', msg);
    input.value = '';
    showTyping();
    const context = {
        target: document.getElementById('targetInput').value,
        vulnerabilities: vulnerabilities.slice(0, 20).map(v => ({ type: v.type, severity: v.severity, endpoint: v.endpoint, parameter: v.parameter, description: v.description })),
        exploitSteps: exploitSteps.slice(-10),
        scanId: currentScanId
    };
    fetch('/api/ai/chat', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ message: msg, context, settings: aiSettings })
    }).then(r => r.json()).then(d => {
        hideTyping();
        if (d.error) { addChatMessage('ai', '⚠️ ' + d.error); return; }
        addChatMessage('ai', d.response);
    }).catch(() => {
        hideTyping();
        addChatMessage('ai', '⚠️ AI connection failed. Check your API settings in the Settings tab.');
    });
}

function addChatMessage(role, text) {
    const container = document.getElementById('aiChatMessages');
    const div = document.createElement('div');
    div.className = 'chat-msg ' + role;
    // Simple markdown-like code blocks
    let html = text.replace(/```(\w*)\n?([\s\S]*?)```/g, (_, lang, code) => {
        return `<pre><span class="copy-btn" onclick="copyText('${escapeAttr(code.trim())}')">📋</span>${escapeHtml(code.trim())}</pre>`;
    });
    html = html.replace(/`([^`]+)`/g, '<code style="background:#0d1114;padding:1px 5px;border-radius:3px;font-family:var(--font-mono);font-size:11px;">$1</code>');
    html = html.replace(/\n/g, '<br>');
    div.innerHTML = html + `<div class="msg-time">${time()}</div>`;
    container.appendChild(div);
    container.scrollTop = container.scrollHeight;
}

function showTyping() {
    const container = document.getElementById('aiChatMessages');
    const div = document.createElement('div');
    div.className = 'chat-typing';
    div.id = 'typingIndicator';
    div.innerHTML = 'AI thinking <div class="dots"><span></span><span></span><span></span></div>';
    container.appendChild(div);
    container.scrollTop = container.scrollHeight;
}

function hideTyping() {
    const el = document.getElementById('typingIndicator');
    if (el) el.remove();
}

function handleAiKeydown(e) {
    if (e.key === 'Enter' && !e.shiftKey) {
        e.preventDefault();
        sendAiMessage();
    }
}

// ============================================================
// TOOLS
// ============================================================
function openTool(tool) {
    const overlay = document.getElementById('modalOverlay');
    const content = document.getElementById('modalContent');
    overlay.classList.add('active');
    switch (tool) {
        case 'c2':
            content.innerHTML = `<h3>💀 C2 BEACON GENERATOR</h3>
                <label>Server URL</label><input type="text" id="c2Server" placeholder="https://your-c2-server.com">
                <label>Payload Type</label><select id="c2Type"><option value="python">Python</option><option value="bash">Bash</option><option value="powershell">PowerShell</option><option value="php">PHP</option></select>
                <label>Sleep (seconds)</label><input type="number" id="c2Sleep" value="5">
                <div class="modal-actions">
                    <button class="btn btn-primary" onclick="generateC2()">GENERATE</button>
                    <button class="btn" onclick="closeModal()">CLOSE</button>
                </div>
                <textarea id="c2Output" readonly placeholder="Payload will appear here..." style="margin-top:10px;"></textarea>`;
            break;
        case 'ransomware':
            content.innerHTML = `<h3>🔒 RANSOMWARE CONTROL</h3>
                <label>Target Directory</label><input type="text" id="ransomDir" value="/var/www/html">
                <label>Max Files</label><input type="number" id="ransomMax" value="50">
                <div class="modal-actions">
                    <button class="btn btn-primary" onclick="execRansomware(false)">SIMULATE</button>
                    <button class="btn btn-danger" onclick="execRansomware(true)">FULL ATTACK</button>
                    <button class="btn" onclick="closeModal()">CLOSE</button>
                </div>
                <hr>
                <label>Decrypt Directory</label><input type="text" id="decryptDir" placeholder="/path/to/encrypted">
                <label>Encryption Key</label><input type="text" id="decryptKey" placeholder="Key...">
                <button class="btn btn-success" onclick="decryptRansomware()">DECRYPT</button>
                <textarea id="ransomOutput" readonly placeholder="Results..." style="margin-top:10px;"></textarea>`;
            break;
        case 'bruteforce':
            content.innerHTML = `<h3>🔑 BRUTEFORCE</h3>
                <label>Type</label><select id="bfType"><option value="http">HTTP Form</option><option value="ssh">SSH</option><option value="ftp">FTP</option></select>
                <label>Target</label><input type="text" id="bfTarget" placeholder="URL or IP">
                <label>Username Field (HTTP)</label><input type="text" id="bfUserField" value="username">
                <label>Password Field (HTTP)</label><input type="text" id="bfPassField" value="password">
                <div class="modal-actions">
                    <button class="btn btn-primary" onclick="runBruteforce()">START</button>
                    <button class="btn" onclick="closeModal()">CLOSE</button>
                </div>
                <textarea id="bfOutput" readonly placeholder="Results..." style="margin-top:10px;"></textarea>`;
            break;
        case 'phishing':
            content.innerHTML = `<h3>🎣 PHISHING GENERATOR</h3>
                <label>Template</label><select id="phishTemplate">
                    <option value="google">Google</option><option value="facebook">Facebook</option><option value="instagram">Instagram</option>
                    <option value="microsoft">Microsoft 365</option><option value="twitter">Twitter/X</option><option value="linkedin">LinkedIn</option>
                    <option value="netflix">Netflix</option><option value="paypal">PayPal</option><option value="github">GitHub</option>
                    <option value="wordpress">WordPress</option><option value="custom">Custom Clone</option>
                </select>
                <label>Custom URL (if custom)</label><input type="text" id="phishCustomUrl" placeholder="https://target.com/login">
                <div class="modal-actions">
                    <button class="btn btn-primary" onclick="generatePhish()">GENERATE</button>
                    <button class="btn" onclick="closeModal()">CLOSE</button>
                </div>
                <textarea id="phishOutput" readonly placeholder="HTML will appear here..." style="margin-top:10px;"></textarea>`;
            break;
        case 'cloud':
            content.innerHTML = `<h3>☁️ CLOUD ATTACK</h3>
                <div class="modal-actions">
                    <button class="btn btn-primary" onclick="cloudAction('steal_aws')">STEAL AWS</button>
                    <button class="btn btn-primary" onclick="cloudAction('steal_azure')">STEAL AZURE</button>
                    <button class="btn btn-primary" onclick="cloudAction('steal_gcp')">STEAL GCP</button>
                    <button class="btn btn-danger" onclick="cloudAction('scan_all')">SCAN ALL</button>
                    <button class="btn" onclick="closeModal()">CLOSE</button>
                </div>
                <textarea id="cloudOutput" readonly placeholder="Results..." style="margin-top:10px;"></textarea>`;
            break;
        case 'creds':
            content.innerHTML = `<h3>🔓 CREDENTIAL DUMP</h3>
                <label>Technique</label><select id="credTechnique">
                    <option value="sekurlsa">Mimikatz - Sekurlsa</option><option value="lsa">Mimikatz - LSA</option>
                    <option value="dcsync">Mimikatz - DCSync</option><option value="kerberos">Mimikatz - Kerberos</option>
                    <option value="token">Mimikatz - Token</option>
                    <option value="powershell">PowerShell Cred Dump</option>
                </select>
                <div class="modal-actions">
                    <button class="btn btn-primary" onclick="generateCredScript()">GENERATE</button>
                    <button class="btn" onclick="closeModal()">CLOSE</button>
                </div>
                <textarea id="credOutput" readonly placeholder="Script will appear here..." style="margin-top:10px;"></textarea>`;
            break;
        case 'admin_finder':
            content.innerHTML = `<h3>🔍 ADMIN PANEL FINDER</h3>
                <label>Target URL</label><input type="text" id="adminFinderTarget" placeholder="https://target.com" value="${document.getElementById('targetInput').value}">
                <div class="modal-actions">
                    <button class="btn btn-primary" onclick="runAdminFinder()">🔍 SCAN</button>
                    <button class="btn" onclick="closeModal()">CLOSE</button>
                </div>
                <div id="adminFinderResults" style="max-height:400px;overflow-y:auto;margin-top:10px;font-size:11px;"></div>`;
            break;
        case 'sensitive_files':
            content.innerHTML = `<h3>📄 SENSITIVE FILE DISCOVERY</h3>
                <label>Target URL</label><input type="text" id="sensitiveFilesTarget" placeholder="https://target.com" value="${document.getElementById('targetInput').value}">
                <div class="modal-actions">
                    <button class="btn btn-primary" onclick="runSensitiveFiles()">🔍 SCAN</button>
                    <button class="btn" onclick="closeModal()">CLOSE</button>
                </div>
                <div id="sensitiveFilesResults" style="max-height:400px;overflow-y:auto;margin-top:10px;font-size:11px;"></div>`;
            break;
        case 'nosqli':
            content.innerHTML = `<h3>🗄️ NoSQL INJECTION SCANNER</h3>
                <label>Target URL</label><input type="text" id="nosqliTarget" placeholder="https://target.com" value="${document.getElementById('targetInput').value}">
                <div class="modal-actions">
                    <button class="btn btn-primary" onclick="runNosqliScan()">🔍 SCAN</button>
                    <button class="btn" onclick="closeModal()">CLOSE</button>
                </div>
                <div id="nosqliResults" style="max-height:400px;overflow-y:auto;margin-top:10px;font-size:11px;"></div>`;
            break;
        case 'api_hack':
            content.innerHTML = `<h3>🔌 API HACKING SUITE</h3>
                <label>Target URL</label><input type="text" id="apiHackTarget" placeholder="https://target.com" value="${document.getElementById('targetInput').value}">
                <div class="modal-actions">
                    <button class="btn btn-primary" onclick="runApiHack()">🔍 SCAN</button>
                    <button class="btn" onclick="closeModal()">CLOSE</button>
                </div>
                <div id="apiHackResults" style="max-height:400px;overflow-y:auto;margin-top:10px;font-size:11px;"></div>`;
            break;
        case 'xxe':
            content.innerHTML = `<h3>📋 XXE INJECTION SCANNER</h3>
                <label>Target URL</label><input type="text" id="xxeTarget" placeholder="https://target.com" value="${document.getElementById('targetInput').value}">
                <div class="modal-actions">
                    <button class="btn btn-primary" onclick="runXxeScan()">🔍 SCAN</button>
                    <button class="btn" onclick="closeModal()">CLOSE</button>
                </div>
                <div id="xxeResults" style="max-height:400px;overflow-y:auto;margin-top:10px;font-size:11px;"></div>`;
            break;
        case 'smuggling':
            content.innerHTML = `<h3>📦 HTTP REQUEST SMUGGLING</h3>
                <label>Target URL</label><input type="text" id="smugglingTarget" placeholder="https://target.com" value="${document.getElementById('targetInput').value}">
                <div class="modal-actions">
                    <button class="btn btn-primary" onclick="runSmugglingScan()">🔍 SCAN</button>
                    <button class="btn" onclick="closeModal()">CLOSE</button>
                </div>
                <div id="smugglingResults" style="max-height:400px;overflow-y:auto;margin-top:10px;font-size:11px;"></div>`;
            break;
        case 'oauth':
            content.innerHTML = `<h3>🔐 OAUTH HIJACK SCANNER</h3>
                <label>Target URL</label><input type="text" id="oauthTarget" placeholder="https://target.com" value="${document.getElementById('targetInput').value}">
                <div class="modal-actions">
                    <button class="btn btn-primary" onclick="runOauthScan()">🔍 SCAN</button>
                    <button class="btn" onclick="closeModal()">CLOSE</button>
                </div>
                <div id="oauthResults" style="max-height:400px;overflow-y:auto;margin-top:10px;font-size:11px;"></div>`;
            break;
        case 'proto_pollution':
            content.innerHTML = `<h3>🧬 PROTOTYPE POLLUTION</h3>
                <label>Target URL</label><input type="text" id="protoTarget" placeholder="https://target.com" value="${document.getElementById('targetInput').value}">
                <div class="modal-actions">
                    <button class="btn btn-primary" onclick="runProtoScan()">🔍 SCAN</button>
                    <button class="btn" onclick="closeModal()">CLOSE</button>
                </div>
                <div id="protoResults" style="max-height:400px;overflow-y:auto;margin-top:10px;font-size:11px;"></div>`;
            break;
        case 'exploit_chains':
            content.innerHTML = `<h3>⛓️ AUTOMATED EXPLOIT CHAINS</h3>
                <label>Target URL</label><input type="text" id="chainTarget" placeholder="https://target.com" value="${document.getElementById('targetInput').value}">
                <div class="modal-actions">
                    <button class="btn btn-danger" onclick="runExploitChains()">⚡ EXECUTE CHAINS</button>
                    <button class="btn" onclick="closeModal()">CLOSE</button>
                </div>
                <div id="chainResults" style="max-height:400px;overflow-y:auto;margin-top:10px;font-size:11px;"></div>`;
            break;
        case 'waf_evasion':
            content.innerHTML = `<h3>🛡️ WAF EVASION ENCODER</h3>
                <label>Payload</label><textarea id="wafPayload" placeholder="Enter payload..."><script>alert(1)</script></textarea>
                <label>Vuln Type</label><select id="wafVulnType"><option value="xss">XSS</option><option value="sqli">SQLi</option><option value="cmdi">Command Injection</option><option value="lfi">LFI</option></select>
                <label>WAF (optional)</label><select id="wafType"><option value="">Auto-detect</option><option value="Cloudflare">Cloudflare</option><option value="AWS WAF">AWS WAF</option><option value="ModSecurity">ModSecurity</option></select>
                <div class="modal-actions">
                    <button class="btn btn-primary" onclick="runWafEvasion()">🛡️ ENCODE</button>
                    <button class="btn" onclick="closeModal()">CLOSE</button>
                </div>
                <textarea id="wafOutput" readonly placeholder="Encoded payloads..." style="margin-top:10px;"></textarea>`;
            break;
    }
}

function closeModal() { document.getElementById('modalOverlay').classList.remove('active'); }

// Tool Actions
function generateC2() {
    const server = document.getElementById('c2Server').value;
    if (!server) return;
    fetch('/api/c2/generate_payload', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ c2_server: server, payload_type: document.getElementById('c2Type').value, sleep_time: parseInt(document.getElementById('c2Sleep').value) || 5 })
    }).then(r => r.json()).then(d => { document.getElementById('c2Output').value = d.payload; toast('Payload generated', 'success'); });
}

function execRansomware(full) {
    fetch('/api/ransomware/execute', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target_directory: document.getElementById('ransomDir').value, max_files: parseInt(document.getElementById('ransomMax').value) || 50, full_attack: full })
    }).then(r => r.json()).then(d => { document.getElementById('ransomOutput').value = JSON.stringify(d, null, 2); });
}

function decryptRansomware() {
    fetch('/api/ransomware/decrypt', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target_directory: document.getElementById('decryptDir').value, encryption_key: document.getElementById('decryptKey').value })
    }).then(r => r.json()).then(d => { document.getElementById('ransomOutput').value = JSON.stringify(d, null, 2); });
}

function runBruteforce() {
    const type = document.getElementById('bfType').value;
    const target = document.getElementById('bfTarget').value;
    if (!target) return;
    const body = { host: target, target_url: target, username_field: document.getElementById('bfUserField').value, password_field: document.getElementById('bfPassField').value };
    fetch(`/api/bruteforce/${type}`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body)
    }).then(r => r.json()).then(d => { document.getElementById('bfOutput').value = JSON.stringify(d, null, 2); });
}

function generatePhish() {
    const template = document.getElementById('phishTemplate').value;
    const customUrl = document.getElementById('phishCustomUrl').value;
    const endpoint = template === 'custom' ? '/api/phishing/clone' : '/api/phishing/generate';
    const body = template === 'custom' ? { target_url: customUrl } : { template };
    fetch(endpoint, {
        method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body)
    }).then(r => r.json()).then(d => { document.getElementById('phishOutput').value = d.html || JSON.stringify(d, null, 2); });
}

function cloudAction(action) {
    fetch(`/api/cloud/${action}`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}' })
        .then(r => r.json()).then(d => { document.getElementById('cloudOutput').value = JSON.stringify(d, null, 2); });
}

function generateCredScript() {
    const technique = document.getElementById('credTechnique').value;
    const endpoint = technique === 'powershell' ? '/api/creds/powershell' : '/api/creds/mimikatz';
    const body = technique === 'powershell' ? {} : { technique };
    fetch(endpoint, {
        method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body)
    }).then(r => r.json()).then(d => { document.getElementById('credOutput').value = d.script || d.commands?.join('\n') || JSON.stringify(d, null, 2); });
}

// ============================================================
// HISTORY
// ============================================================
function loadHistory() {
    fetch('/api/history')
        .then(r => r.json())
        .then(data => {
            scanHistory = data;
            renderHistory(data);
        });
}

function renderHistory(data) {
    const panel = document.getElementById('historyPanel');
    if (!data || data.length === 0) {
        panel.innerHTML = '<div class="empty-state"><div class="empty-icon">📜</div>No scan history</div>';
        return;
    }
    let html = '<table class="data-table"><thead><tr><th>TARGET</th><th>DATE</th><th>VULNS</th><th>CRIT</th><th>HIGH</th><th>STATUS</th><th>ACTIONS</th></tr></thead><tbody>';
    data.forEach(h => {
        const statusBadge = h.status === 'completed' ? 'badge-success' : h.status === 'failed' ? 'badge-failed' : 'badge-running';
        html += `<tr>
            <td class="truncate" style="max-width:200px;" title="${escapeHtml(h.target)}">${escapeHtml(h.target)}</td>
            <td style="font-size:10px;">${h.started ? new Date(h.started).toLocaleDateString() : 'N/A'}</td>
            <td>${h.vulns_found || 0}</td>
            <td><span class="badge badge-critical">${h.critical || 0}</span></td>
            <td><span class="badge badge-high">${h.high || 0}</span></td>
            <td><span class="badge ${statusBadge}">${h.status || 'unknown'}</span></td>
            <td><button class="btn btn-xs" onclick="loadHistoryDetail('${h.id}')">VIEW</button></td>
        </tr>`;
    });
    html += '</tbody></table>';
    panel.innerHTML = html;
}

function loadHistoryDetail(scanId) {
    fetch('/api/history/' + scanId)
        .then(r => r.json())
        .then(d => {
            if (d.vulns_json) {
                try {
                    const vulns = typeof d.vulns_json === 'string' ? JSON.parse(d.vulns_json) : d.vulns_json;
                    vulnerabilities = vulns;
                    selectedVulns.clear();
                    const summary = { critical: d.critical || 0, high: d.high || 0, medium: d.medium || 0, low: d.low || 0 };
                    renderVulns(vulns, summary);
                    switchTab('exploit');
                    toast('Loaded scan: ' + d.target, 'info');
                } catch(e) { toast('Failed to parse scan data', 'error'); }
            }
        });
}

// ============================================================
// SETTINGS
// ============================================================
function loadSettings() {
    const saved = localStorage.getItem('apex_ai_settings');
    if (saved) {
        try { aiSettings = JSON.parse(saved); } catch(e) {}
    }
}

function loadSettingsToForm() {
    document.getElementById('settingApiKey').value = aiSettings.api_key || '';
    document.getElementById('settingBaseUrl').value = aiSettings.base_url || '';
    document.getElementById('settingModel').value = aiSettings.model || 'gpt-4o-mini';
}

function saveSettings() {
    aiSettings.api_key = document.getElementById('settingApiKey').value;
    aiSettings.base_url = document.getElementById('settingBaseUrl').value;
    aiSettings.model = document.getElementById('settingModel').value;
    localStorage.setItem('apex_ai_settings', JSON.stringify(aiSettings));
    // Also save to server
    fetch('/api/ai/settings', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(aiSettings)
    });
    toast('Settings saved', 'success');
}

function testAiConnection() {
    saveSettings();
    fetch('/api/ai/test', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(aiSettings)
    }).then(r => r.json()).then(d => {
        if (d.success) toast('AI connection successful! Model: ' + d.model, 'success');
        else toast('AI connection failed: ' + (d.error || 'Unknown error'), 'error');
    }).catch(() => toast('AI connection failed', 'error'));
}

// ============================================================
// STATS
// ============================================================
function updateStats() {
    fetch('/api/history')
        .then(r => r.json())
        .then(data => {
            const totalScans = data.length;
            const totalVulns = data.reduce((s, h) => s + (h.vulns_found || 0), 0);
            const totalExploits = data.reduce((s, h) => s + (h.exploits_success || 0), 0);
            document.getElementById('statScans').textContent = totalScans;
            document.getElementById('statVulns').textContent = totalVulns;
            document.getElementById('statExploits').textContent = totalExploits;
        });
}

// ============================================================
// UTILITY
// ============================================================
function time() { return new Date().toTimeString().slice(0, 8); }

function escapeHtml(str) {
    if (!str) return '';
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
}

function escapeAttr(str) {
    if (!str) return '';
    return str.replace(/'/g, "\\'").replace(/"/g, '"').replace(/</g, '<').replace(/>/g, '>');
}

function copyText(text) {
    navigator.clipboard.writeText(text).then(() => {
        toast('Copied to clipboard', 'info');
    }).catch(() => {
        // Fallback
        const ta = document.createElement('textarea');
        ta.value = text;
        document.body.appendChild(ta);
        ta.select();
        document.execCommand('copy');
        document.body.removeChild(ta);
        toast('Copied to clipboard', 'info');
    });
}

function toast(message, type) {
    const container = document.getElementById('toastContainer');
    const div = document.createElement('div');
    div.className = 'toast ' + type;
    const icons = { success: '✅', error: '❌', warning: '⚠️', info: 'ℹ️' };
    div.innerHTML = `${icons[type] || ''} ${message}`;
    container.appendChild(div);
    setTimeout(() => { div.style.opacity = '0'; div.style.transition = 'opacity 0.3s'; setTimeout(() => div.remove(), 300); }, 3500);
}

function setupKeyboardShortcuts() {
    document.addEventListener('keydown', (e) => {
        if (e.ctrlKey && e.key === 'Enter') { e.preventDefault(); startScan('full'); }
        if (e.ctrlKey && e.shiftKey && e.key === 'N') { e.preventDefault(); startNuke(); }
        if (e.ctrlKey && e.key === 'k') { e.preventDefault(); document.getElementById('aiChatInput').focus(); }
        if (e.key === 'Escape') { closeModal(); }
    });
}

// Modal overlay click
document.addEventListener('click', (e) => {
    if (e.target.id === 'modalOverlay') closeModal();
});

// Initial stats load
updateStats();

// ============================================================
// ANONYMITY REPORT
// ============================================================
function refreshAnonymityReport() {
    const panel = document.getElementById('anonymityReportPanel');
    if (!panel) return;
    panel.innerHTML = '<div class="empty-state"><div class="empty-icon">🔄</div>Loading anonymity status...</div>';
    
    fetch('/api/opsec/full_report')
        .then(r => r.json())
        .then(report => {
            renderAnonymityReport(report);
        })
        .catch(() => {
            panel.innerHTML = '<div class="empty-state"><div class="empty-icon">❌</div>Failed to load anonymity report</div>';
        });
}

function renderAnonymityReport(report) {
    const panel = document.getElementById('anonymityReportPanel');
    if (!panel) return;
    
    let html = '';
    
    // Overall status banner
    html += `<div style="background:${report.status_color}15;border:1px solid ${report.status_color}40;border-radius:8px;padding:12px 16px;margin-bottom:12px;display:flex;align-items:center;gap:12px;">
        <div style="font-size:28px;">${report.status_text.split(' ')[0]}</div>
        <div>
            <div style="font-size:16px;font-weight:700;color:${report.status_color};">${report.status_text}</div>
            <div style="font-size:10px;color:var(--text-muted);">Current IP: ${escapeHtml(report.current_ip)} | Real IP: ${escapeHtml(report.real_ip)}</div>
        </div>
    </div>`;
    
    // Active layers
    if (report.layers && report.layers.length > 0) {
        html += '<div style="display:flex;gap:8px;margin-bottom:12px;flex-wrap:wrap;">';
        report.layers.forEach(l => {
            html += `<span style="background:var(--success);color:#000;padding:3px 10px;border-radius:12px;font-size:10px;font-weight:700;">${l.icon} ${l.name}</span>`;
        });
        html += '</div>';
    }
    
    // Checks grid
    if (report.checks) {
        html += '<div style="display:grid;grid-template-columns:1fr 1fr;gap:6px;margin-bottom:12px;">';
        Object.values(report.checks).forEach(check => {
            const bgColor = check.active ? 'var(--success)' : 'var(--danger)';
            html += `<div style="background:var(--bg-primary);border:1px solid var(--border);border-radius:6px;padding:8px 10px;">
                <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:3px;">
                    <span style="font-size:10px;font-weight:600;">${check.name}</span>
                    <span style="font-size:10px;">${check.status}</span>
                </div>
                <div style="font-size:9px;color:var(--text-muted);">${escapeHtml(check.detail || '')}</div>
            </div>`;
        });
        html += '</div>';
    }
    
    // Warnings
    if (report.warnings && report.warnings.length > 0) {
        html += '<div style="margin-bottom:12px;">';
        report.warnings.forEach(w => {
            html += `<div style="background:rgba(239,68,68,0.1);border:1px solid rgba(239,68,68,0.3);border-radius:4px;padding:6px 10px;margin-bottom:4px;font-size:10px;color:#ef4444;">⚠️ ${escapeHtml(w)}</div>`;
        });
        html += '</div>';
    }
    
    // Recommendations
    if (report.recommendations && report.recommendations.length > 0) {
        html += '<div style="font-size:10px;font-weight:600;margin-bottom:4px;color:var(--text-secondary);">RECOMMENDATIONS:</div>';
        report.recommendations.forEach(r => {
            html += `<div style="font-size:10px;color:var(--text-muted);padding:2px 0;">→ ${escapeHtml(r)}</div>`;
        });
    }
    
    // IP match warning
    if (report.ip_match === true) {
        html += `<div style="background:rgba(239,68,68,0.15);border:1px solid #ef4444;border-radius:6px;padding:8px 12px;margin-top:8px;font-size:10px;color:#ef4444;font-weight:600;">
            🔴 CRITICAL: Your visible IP matches your real IP — you are NOT hidden!
        </div>`;
    } else if (report.ip_match === false) {
        html += `<div style="background:rgba(16,185,129,0.1);border:1px solid rgba(16,185,129,0.3);border-radius:6px;padding:8px 12px;margin-top:8px;font-size:10px;color:#10b981;font-weight:600;">
            🟢 IPs differ — your real IP is hidden
        </div>`;
    }
    
    panel.innerHTML = html;
}

// Auto-load anonymity report on page load
document.addEventListener('DOMContentLoaded', () => {
    setTimeout(refreshAnonymityReport, 500);
});

// Refresh every 30 seconds
setInterval(refreshAnonymityReport, 30000);

// ============================================================
// CHAINS
// ============================================================
function loadChainTemplates() {
    fetch('/api/chains/templates')
        .then(r => r.json())
        .then(d => {
            const panel = document.getElementById('chainsPanel');
            if (!d.templates || d.templates.length === 0) {
                panel.innerHTML = '<div class="empty-state"><div class="empty-icon">⛓️</div>No chain templates available</div>';
                return;
            }
            let html = '';
            d.templates.forEach(t => {
                html += `<div class="card mb-2" style="cursor:pointer;" onclick="executeChain('${t.name}')">
                    <div class="card-header">⛓️ ${t.name}</div>
                    <div class="card-body" style="font-size:11px;color:var(--text-muted);">Steps: ${t.steps.join(' → ')}</div>
                </div>`;
            });
            html += `<button class="btn btn-primary btn-sm mt-2" onclick="executeChain('full_takeover')">⚡ QUICK: Full Takeover</button>`;
            panel.innerHTML = html;
        });
}

function executeChain(chainName) {
    const target = document.getElementById('targetInput').value.trim();
    if (!target) { toast('Enter a target URL first', 'error'); return; }
    document.getElementById('chainMonitor').innerHTML = '';
    switchTab('chains');
    fetch('/api/chains/execute', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ chain_name: chainName, target, vulnerabilities })
    }).then(r => r.json()).then(d => {
        toast('Chain started: ' + chainName, 'info');
    });
}

// Override addExploitStep to also populate chainMonitor
const origAddExploitStep = addExploitStep;
addExploitStep = function(step) {
    origAddExploitStep(step);
    const chainMon = document.getElementById('chainMonitor');
    if (chainMon && step.exploit_id && step.exploit_id.startsWith('chain_')) {
        if (chainMon.querySelector('.empty-state')) chainMon.innerHTML = '';
        const div = document.createElement('div');
        const cls = step.phase === 'phase' ? 'phase-start' : step.phase === 'command' ? 'command' : step.phase === 'response' ? 'response' : step.phase === 'error' ? 'error' : '';
        div.className = 'exploit-step ' + cls;
        let html = `<div class="step-header"><span class="step-time">[${step.timestamp || time()}]</span><span class="step-label">${escapeHtml(step.label || '')}</span></div>`;
        if (step.command) html += `<div class="step-cmd">${escapeHtml(step.command)}<span class="copy-cmd" onclick="copyText('${escapeAttr(step.command)}')">📋</span></div>`;
        if (step.result) html += `<div class="step-result ${step.success ? 'success' : step.error ? 'error' : ''}">${escapeHtml(step.result)}</div>`;
        if (step.details) step.details.forEach(d => { html += `<div class="step-result">→ ${escapeHtml(d)}</div>`; });
        div.innerHTML = html;
        chainMon.appendChild(div);
        chainMon.scrollTop = chainMon.scrollHeight;
    }
};

// ============================================================
// TARGET QUEUE
// ============================================================
function addToQueue() {
    const target = document.getElementById('queueTargetInput').value.trim();
    if (!target) { toast('Enter a target URL', 'error'); return; }
    fetch('/api/queue/add', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target })
    }).then(r => r.json()).then(d => {
        document.getElementById('queueTargetInput').value = '';
        loadQueue();
        toast('Added to queue: ' + target, 'success');
    });
}

function loadQueue() {
    fetch('/api/queue/list')
        .then(r => r.json())
        .then(d => {
            const list = document.getElementById('queueList');
            if (!d.queue || d.queue.length === 0) {
                list.innerHTML = '<div class="empty-state" style="padding:10px;">Queue empty</div>';
                return;
            }
            let html = '<div style="max-height:200px;overflow-y:auto;">';
            d.queue.forEach((item, i) => {
                const statusIcon = item.status === 'completed' ? '✅' : item.status === 'scanning' ? '🔄' : item.status === 'failed' ? '❌' : '⏳';
                html += `<div style="padding:6px 8px;border-bottom:1px solid var(--border);font-size:11px;display:flex;justify-content:space-between;">
                    <span>${statusIcon} ${escapeHtml(item.target)}</span>
                    <span style="color:var(--text-muted);">${item.status}</span>
                </div>`;
            });
            html += '</div>';
            if (d.running) html += '<div style="color:var(--warning);font-size:10px;margin-top:4px;">⏳ Queue is running...</div>';
            list.innerHTML = html;
        });
}

function startQueue() {
    fetch('/api/queue/start', { method: 'POST' })
        .then(r => r.json())
        .then(d => {
            if (d.error) { toast(d.error, 'error'); return; }
            toast('Queue started — ' + d.queue_size + ' targets', 'success');
            loadQueue();
        });
}

function clearQueue() {
    fetch('/api/queue/clear', { method: 'POST' })
        .then(() => { loadQueue(); toast('Queue cleared', 'info'); });
}

// ============================================================
// PAYLOAD FORGE
// ============================================================
function openTool(tool) {
    const overlay = document.getElementById('modalOverlay');
    const content = document.getElementById('modalContent');
    overlay.classList.add('active');
    if (tool === 'payload_forge') {
        content.innerHTML = `<h3>🔧 PAYLOAD FORGE</h3>
            <label>Raw Payload</label><textarea id="forgeInput" placeholder="Enter your payload here..."><script>alert('XSS')</script></textarea>
            <label>Encoding</label><select id="forgeEncoding">
                <option value="base64">Base64</option><option value="url">URL Encode</option><option value="hex">Hex</option>
                <option value="html_entities">HTML Entities</option><option value="unicode_escape">Unicode Escape</option>
                <option value="double_url">Double URL Encode</option><option value="js_escape">JS Escape</option>
                <option value="xor_5">XOR (key=5)</option><option value="case_swap">Case Swap</option>
                <option value="comment_inject">SQL Comment Inject</option><option value="tab_inject">Tab Inject</option>
            </select>
            <div class="modal-actions">
                <button class="btn btn-primary" onclick="encodePayload()">🔧 ENCODE</button>
                <button class="btn" onclick="closeModal()">CLOSE</button>
            </div>
            <label style="margin-top:10px;">Encoded Output</label>
            <textarea id="forgeOutput" readonly placeholder="Encoded payload will appear here..."></textarea>`;
        return;
    }
    // ... rest of existing openTool cases
    switch (tool) {
        case 'c2':
            content.innerHTML = `<h3>💀 C2 BEACON GENERATOR</h3>
                <label>Server URL</label><input type="text" id="c2Server" placeholder="https://your-c2-server.com">
                <label>Payload Type</label><select id="c2Type"><option value="python">Python</option><option value="bash">Bash</option><option value="powershell">PowerShell</option><option value="php">PHP</option></select>
                <label>Sleep (seconds)</label><input type="number" id="c2Sleep" value="5">
                <div class="modal-actions"><button class="btn btn-primary" onclick="generateC2()">GENERATE</button><button class="btn" onclick="closeModal()">CLOSE</button></div>
                <textarea id="c2Output" readonly placeholder="Payload will appear here..." style="margin-top:10px;"></textarea>`;
            break;
        case 'ransomware':
            content.innerHTML = `<h3>🔒 RANSOMWARE CONTROL</h3>
                <label>Target Directory</label><input type="text" id="ransomDir" value="/var/www/html">
                <label>Max Files</label><input type="number" id="ransomMax" value="50">
                <div class="modal-actions"><button class="btn btn-primary" onclick="execRansomware(false)">SIMULATE</button><button class="btn btn-danger" onclick="execRansomware(true)">FULL ATTACK</button><button class="btn" onclick="closeModal()">CLOSE</button></div>
                <hr><label>Decrypt Directory</label><input type="text" id="decryptDir" placeholder="/path/to/encrypted">
                <label>Encryption Key</label><input type="text" id="decryptKey" placeholder="Key...">
                <button class="btn btn-success" onclick="decryptRansomware()">DECRYPT</button>
                <textarea id="ransomOutput" readonly placeholder="Results..." style="margin-top:10px;"></textarea>`;
            break;
        case 'bruteforce':
            content.innerHTML = `<h3>🔑 BRUTEFORCE</h3>
                <label>Type</label><select id="bfType"><option value="http">HTTP Form</option><option value="ssh">SSH</option><option value="ftp">FTP</option></select>
                <label>Target</label><input type="text" id="bfTarget" placeholder="URL or IP">
                <label>Username Field (HTTP)</label><input type="text" id="bfUserField" value="username">
                <label>Password Field (HTTP)</label><input type="text" id="bfPassField" value="password">
                <div class="modal-actions"><button class="btn btn-primary" onclick="runBruteforce()">START</button><button class="btn" onclick="closeModal()">CLOSE</button></div>
                <textarea id="bfOutput" readonly placeholder="Results..." style="margin-top:10px;"></textarea>`;
            break;
        case 'phishing':
            content.innerHTML = `<h3>🎣 PHISHING GENERATOR</h3>
                <label>Template</label><select id="phishTemplate">
                    <option value="google">Google</option><option value="facebook">Facebook</option><option value="instagram">Instagram</option>
                    <option value="microsoft">Microsoft 365</option><option value="twitter">Twitter/X</option><option value="linkedin">LinkedIn</option>
                    <option value="netflix">Netflix</option><option value="paypal">PayPal</option><option value="github">GitHub</option>
                    <option value="wordpress">WordPress</option><option value="custom">Custom Clone</option></select>
                <label>Custom URL (if custom)</label><input type="text" id="phishCustomUrl" placeholder="https://target.com/login">
                <div class="modal-actions"><button class="btn btn-primary" onclick="generatePhish()">GENERATE</button><button class="btn" onclick="closeModal()">CLOSE</button></div>
                <textarea id="phishOutput" readonly placeholder="HTML will appear here..." style="margin-top:10px;"></textarea>`;
            break;
        case 'cloud':
            content.innerHTML = `<h3>☁️ CLOUD ATTACK</h3>
                <div class="modal-actions"><button class="btn btn-primary" onclick="cloudAction('steal_aws')">STEAL AWS</button><button class="btn btn-primary" onclick="cloudAction('steal_azure')">STEAL AZURE</button><button class="btn btn-primary" onclick="cloudAction('steal_gcp')">STEAL GCP</button><button class="btn btn-danger" onclick="cloudAction('scan_all')">SCAN ALL</button><button class="btn" onclick="closeModal()">CLOSE</button></div>
                <textarea id="cloudOutput" readonly placeholder="Results..." style="margin-top:10px;"></textarea>`;
            break;
        case 'creds':
            content.innerHTML = `<h3>🔓 CREDENTIAL DUMP</h3>
                <label>Technique</label><select id="credTechnique">
                    <option value="sekurlsa">Mimikatz - Sekurlsa</option><option value="lsa">Mimikatz - LSA</option>
                    <option value="dcsync">Mimikatz - DCSync</option><option value="kerberos">Mimikatz - Kerberos</option>
                    <option value="token">Mimikatz - Token</option><option value="powershell">PowerShell Cred Dump</option></select>
                <div class="modal-actions"><button class="btn btn-primary" onclick="generateCredScript()">GENERATE</button><button class="btn" onclick="closeModal()">CLOSE</button></div>
                <textarea id="credOutput" readonly placeholder="Script will appear here..." style="margin-top:10px;"></textarea>`;
            break;
    }
}

function encodePayload() {
    const payload = document.getElementById('forgeInput').value;
    const encoding = document.getElementById('forgeEncoding').value;
    if (!payload) return;
    fetch('/api/payload/encode', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ payload, encoding })
    }).then(r => r.json()).then(d => {
        document.getElementById('forgeOutput').value = d.encoded || d.error || 'Error';
        if (d.encoded) toast('Payload encoded: ' + encoding, 'success');
    });
}

// ============================================================
// SESSIONS
// ============================================================
function saveSession() {
    const name = document.getElementById('sessionName').value.trim() || 'session_' + Date.now();
    const data = {
        target: document.getElementById('targetInput').value,
        vulnerabilities,
        exploitSteps,
        scanId: currentScanId,
        aiSettings
    };
    fetch('/api/session/save', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name, data })
    }).then(r => r.json()).then(() => {
        toast('Session saved: ' + name, 'success');
        loadSessionList();
    });
}

function loadSessionList() {
    fetch('/api/session/list')
        .then(r => r.json())
        .then(d => {
            const list = document.getElementById('sessionList');
            if (!d.sessions || d.sessions.length === 0) {
                list.innerHTML = '<div class="empty-state" style="padding:10px;">No saved sessions</div>';
                return;
            }
            let html = '';
            d.sessions.forEach(s => {
                html += `<div style="padding:6px 8px;border-bottom:1px solid var(--border);font-size:11px;display:flex;justify-content:space-between;align-items:center;">
                    <span>💾 ${escapeHtml(s.name)} <span style="color:var(--text-muted);font-size:9px;">${s.saved_at}</span></span>
                    <span><button class="btn btn-xs btn-primary" onclick="loadSession('${s.name}')">LOAD</button> <button class="btn btn-xs" onclick="deleteSession('${s.name}')">DEL</button></span>
                </div>`;
            });
            list.innerHTML = html;
        });
}

function loadSession(name) {
    fetch('/api/session/load/' + name)
        .then(r => r.json())
        .then(d => {
            if (d.error) { toast(d.error, 'error'); return; }
            const s = d.data;
            if (s.target) document.getElementById('targetInput').value = s.target;
            if (s.vulnerabilities) { vulnerabilities = s.vulnerabilities; renderVulns(vulnerabilities, getSummary()); }
            if (s.aiSettings) aiSettings = s.aiSettings;
            toast('Session loaded: ' + name, 'success');
            switchTab('exploit');
        });
}

function deleteSession(name) {
    fetch('/api/session/delete/' + name, { method: 'DELETE' })
        .then(() => { loadSessionList(); toast('Session deleted', 'info'); });
}

// ============================================================
// WEBHOOKS
// ============================================================
function saveWebhookSettings() {
    const data = {
        discord_url: document.getElementById('settingDiscordUrl').value,
        telegram_token: document.getElementById('settingTelegramToken').value,
        telegram_chat_id: document.getElementById('settingTelegramChatId').value
    };
    fetch('/api/webhooks/settings', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(data)
    }).then(() => toast('Webhook settings saved', 'success'));
}

function testWebhooks() {
    saveWebhookSettings();
    const data = {
        discord_url: document.getElementById('settingDiscordUrl').value,
        telegram_token: document.getElementById('settingTelegramToken').value,
        telegram_chat_id: document.getElementById('settingTelegramChatId').value
    };
    fetch('/api/webhooks/test', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(data)
    }).then(r => r.json()).then(d => {
        if (d.success) toast('Test notification sent!', 'success');
        else toast('Failed: ' + (d.error || 'Unknown'), 'error');
    });
}

// ============================================================
// REPORT
// ============================================================
function generateReport() {
    const target = document.getElementById('targetInput').value || 'Unknown';
    fetch('/api/report/generate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target, vulnerabilities, exploits: exploitSteps })
    }).then(r => r.json()).then(d => {
        toast('Report generated: ' + d.report_id, 'success');
        window.open('/' + d.filepath, '_blank');
    });
}

// ============================================================
// SCREENSHOT
// ============================================================
function captureScreenshot(url) {
    const target = url || document.getElementById('targetInput').value;
    if (!target) { toast('Enter a URL', 'error'); return; }
    fetch('/api/screenshot/capture', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: target })
    }).then(r => r.json()).then(d => {
        if (d.success) {
            toast('Screenshot captured!', 'success');
            const lootPanel = document.getElementById('lootPanel');
            if (lootPanel.querySelector('.empty-state')) lootPanel.innerHTML = '';
            lootPanel.innerHTML += `<div class="card mb-2"><div class="card-body">
                <img src="${d.url}" style="max-width:100%;border-radius:4px;" alt="Screenshot">
                <div style="font-size:10px;color:var(--text-muted);margin-top:4px;">${d.filename}</div>
            </div></div>`;
        } else {
            toast('Screenshot failed: ' + (d.error || 'Unknown'), 'error');
        }
    });
}

// ============================================================
// SUBDOMAIN ENUMERATION
// ============================================================
function enumerateSubdomains() {
    const target = document.getElementById('targetInput').value.trim();
    if (!target) { toast('Enter a domain first', 'error'); return; }
    const domain = target.replace('https://', '').replace('http://', '').split('/')[0];
    fetch('/api/subdomains/enumerate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ domain })
    }).then(r => r.json()).then(d => {
        if (d.subdomains && d.subdomains.length > 0) {
            const targetPanel = document.getElementById('targetInfoPanel');
            let html = `<div class="card"><div class="card-header">🌐 Subdomains (${d.count})</div><div class="card-body">`;
            d.subdomains.forEach(s => {
                html += `<div style="padding:4px 0;font-size:11px;font-family:var(--font-mono);">🔗 ${escapeHtml(s)} <button class="btn btn-xs" onclick="document.getElementById('targetInput').value='https://${escapeHtml(s)}';toast('Target set','info')">SCAN</button></div>`;
            });
            html += '</div></div>';
            targetPanel.innerHTML = html;
            toast(`${d.count} subdomains found`, 'success');
        } else {
            toast('No subdomains found', 'warning');
        }
    });
}

// Load chains and sessions on tab switch
const origSwitchTab = switchTab;
switchTab = function(tab) {
    origSwitchTab(tab);
    if (tab === 'chains') { loadChainTemplates(); loadQueue(); }
    if (tab === 'settings') { loadSessionList(); }
    if (tab === 'target') { enumerateSubdomains(); }
};

// ============================================================
// NEW TOOL ACTIONS
// ============================================================
function runAdminFinder() {
    const target = document.getElementById('adminFinderTarget').value.trim();
    if (!target) { toast('Enter a target URL', 'error'); return; }
    const resultsDiv = document.getElementById('adminFinderResults');
    resultsDiv.innerHTML = '<div style="padding:10px;color:var(--warning);">🔍 Scanning 500+ paths...</div>';
    fetch('/api/scan/admin_panels', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target })
    }).then(r => r.json()).then(d => {
        if (d.error) { resultsDiv.innerHTML = `<div style="color:var(--danger);">Error: ${d.error}</div>`; return; }
        if (!d.panels || d.panels.length === 0) {
            resultsDiv.innerHTML = '<div style="padding:10px;">No admin panels found.</div>';
            return;
        }
        let html = `<div style="font-weight:600;margin-bottom:8px;">Found ${d.count} panels:</div>`;
        d.panels.forEach(p => {
            const typeColors = { admin_panel: 'var(--danger)', login_page: 'var(--warning)', database_admin: 'var(--danger)', devops_tool: 'var(--warning)', hosting_panel: 'var(--info)', file_manager: 'var(--warning)', api_docs: 'var(--info)', auth_required: 'var(--text-muted)', redirect_to_login: 'var(--text-muted)', forbidden: 'var(--text-muted)' };
            html += `<div style="padding:6px 8px;border-bottom:1px solid var(--border);display:flex;justify-content:space-between;align-items:center;">
                <div>
                    <span style="color:${typeColors[p.type] || 'var(--text-muted)'};font-weight:600;">[${p.type}]</span>
                    <a href="${escapeHtml(p.url)}" target="_blank" style="color:var(--text-primary);margin-left:8px;font-size:11px;">${escapeHtml(p.url)}</a>
                    ${p.title ? `<span style="color:var(--text-muted);margin-left:8px;font-size:10px;">${escapeHtml(p.title)}</span>` : ''}
                </div>
                <span style="font-size:10px;color:var(--text-muted);">${p.status}</span>
            </div>`;
        });
        resultsDiv.innerHTML = html;
        toast(`Admin finder: ${d.count} panels found`, 'success');
    }).catch(() => { resultsDiv.innerHTML = '<div style="color:var(--danger);">Scan failed</div>'; });
}

function runSensitiveFiles() {
    const target = document.getElementById('sensitiveFilesTarget').value.trim();
    if (!target) { toast('Enter a target URL', 'error'); return; }
    const resultsDiv = document.getElementById('sensitiveFilesResults');
    resultsDiv.innerHTML = '<div style="padding:10px;color:var(--warning);">🔍 Scanning sensitive files...</div>';
    fetch('/api/scan/sensitive_files', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target })
    }).then(r => r.json()).then(d => {
        if (d.error) { resultsDiv.innerHTML = `<div style="color:var(--danger);">Error: ${d.error}</div>`; return; }
        if (!d.files || d.files.length === 0) {
            resultsDiv.innerHTML = '<div style="padding:10px;">No sensitive files found.</div>';
            return;
        }
        let html = `<div style="font-weight:600;margin-bottom:8px;">Found ${d.count} files:</div>`;
        d.files.forEach(f => {
            const catColors = { git_exposure: 'var(--danger)', environment_file: 'var(--danger)', credential_file: 'var(--danger)', key_file: 'var(--danger)', config_file: 'var(--warning)', backup_file: 'var(--warning)', info_disclosure: 'var(--warning)', potential_backdoor: 'var(--danger)' };
            html += `<div style="padding:4px 8px;border-bottom:1px solid var(--border);font-size:10px;">
                <span style="color:${catColors[f.category] || 'var(--text-muted')};">[${f.category}]</span>
                <a href="${escapeHtml(f.url)}" target="_blank" style="color:var(--text-primary);margin-left:6px;">${escapeHtml(f.url)}</a>
                <span style="color:var(--text-muted);margin-left:6px;">${f.status} ${f.size}B</span>
                ${f.sensitive_content ? `<span style="color:var(--danger);margin-left:6px;">⚠️ ${f.sensitive_content}</span>` : ''}
            </div>`;
        });
        resultsDiv.innerHTML = html;
        toast(`Sensitive files: ${d.count} found`, 'success');
    }).catch(() => { resultsDiv.innerHTML = '<div style="color:var(--danger);">Scan failed</div>'; });
}

function runNosqliScan() {
    const target = document.getElementById('nosqliTarget').value.trim();
    if (!target) { toast('Enter a target URL', 'error'); return; }
    const resultsDiv = document.getElementById('nosqliResults');
    resultsDiv.innerHTML = '<div style="padding:10px;color:var(--warning);">🔍 Scanning for NoSQL injection...</div>';
    fetch('/api/scan/nosqli', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target })
    }).then(r => r.json()).then(d => {
        if (d.error) { resultsDiv.innerHTML = `<div style="color:var(--danger);">Error: ${d.error}</div>`; return; }
        if (!d.vulnerabilities || d.vulnerabilities.length === 0) {
            resultsDiv.innerHTML = '<div style="padding:10px;">No NoSQL injection vulnerabilities found.</div>';
            return;
        }
        let html = `<div style="font-weight:600;margin-bottom:8px;">Found ${d.count} vulnerabilities:</div>`;
        d.vulnerabilities.forEach(v => {
            html += `<div style="padding:6px 8px;border:1px solid var(--danger);border-radius:4px;margin-bottom:4px;font-size:10px;">
                <span style="color:var(--danger);font-weight:600;">⚠️ ${v.type.toUpperCase()}</span> — ${escapeHtml(v.result)}<br>
                <span style="color:var(--text-muted);">Endpoint: ${escapeHtml(v.endpoint)} | Param: ${escapeHtml(v.parameter)}</span>
            </div>`;
        });
        resultsDiv.innerHTML = html;
        toast(`NoSQLi: ${d.count} vulns found`, 'warning');
    }).catch(() => { resultsDiv.innerHTML = '<div style="color:var(--danger);">Scan failed</div>'; });
}

function runApiHack() {
    const target = document.getElementById('apiHackTarget').value.trim();
    if (!target) { toast('Enter a target URL', 'error'); return; }
    const resultsDiv = document.getElementById('apiHackResults');
    resultsDiv.innerHTML = '<div style="padding:10px;color:var(--warning);">🔍 Scanning APIs (GraphQL, JWT, OpenAPI)...</div>';
    fetch('/api/scan/api', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target })
    }).then(r => r.json()).then(d => {
        if (d.error) { resultsDiv.innerHTML = `<div style="color:var(--danger);">Error: ${d.error}</div>`; return; }
        if (!d.vulnerabilities || d.vulnerabilities.length === 0) {
            resultsDiv.innerHTML = '<div style="padding:10px;">No API vulnerabilities found.</div>';
            return;
        }
        let html = `<div style="font-weight:600;margin-bottom:8px;">Found ${d.count} issues:</div>`;
        d.vulnerabilities.forEach(v => {
            html += `<div style="padding:6px 8px;border:1px solid var(--warning);border-radius:4px;margin-bottom:4px;font-size:10px;">
                <span style="color:var(--warning);font-weight:600;">⚠️ ${v.type.toUpperCase()}</span> — ${escapeHtml(v.result)}<br>
                <span style="color:var(--text-muted);">${escapeHtml(v.endpoint)}</span>
            </div>`;
        });
        resultsDiv.innerHTML = html;
        toast(`API scan: ${d.count} issues found`, 'warning');
    }).catch(() => { resultsDiv.innerHTML = '<div style="color:var(--danger);">Scan failed</div>'; });
}

function runXxeScan() {
    const target = document.getElementById('xxeTarget').value.trim();
    if (!target) { toast('Enter a target URL', 'error'); return; }
    const resultsDiv = document.getElementById('xxeResults');
    resultsDiv.innerHTML = '<div style="padding:10px;color:var(--warning);">🔍 Scanning for XXE injection...</div>';
    fetch('/api/scan/xxe', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target })
    }).then(r => r.json()).then(d => {
        if (d.error) { resultsDiv.innerHTML = `<div style="color:var(--danger);">Error: ${d.error}</div>`; return; }
        if (!d.vulnerabilities || d.vulnerabilities.length === 0) {
            resultsDiv.innerHTML = '<div style="padding:10px;">No XXE vulnerabilities found.</div>';
            return;
        }
        let html = `<div style="font-weight:600;margin-bottom:8px;">Found ${d.count} vulnerabilities:</div>`;
        d.vulnerabilities.forEach(v => {
            html += `<div style="padding:6px 8px;border:1px solid var(--danger);border-radius:4px;margin-bottom:4px;font-size:10px;">
                <span style="color:var(--danger);font-weight:600;">⚠️ XXE (${v.subtype})</span> — ${escapeHtml(v.result)}<br>
                <span style="color:var(--text-muted);">${escapeHtml(v.endpoint)}</span>
            </div>`;
        });
        resultsDiv.innerHTML = html;
        toast(`XXE: ${d.count} vulns found`, 'warning');
    }).catch(() => { resultsDiv.innerHTML = '<div style="color:var(--danger);">Scan failed</div>'; });
}

function runSmugglingScan() {
    const target = document.getElementById('smugglingTarget').value.trim();
    if (!target) { toast('Enter a target URL', 'error'); return; }
    const resultsDiv = document.getElementById('smugglingResults');
    resultsDiv.innerHTML = '<div style="padding:10px;color:var(--warning);">🔍 Testing HTTP request smuggling...</div>';
    fetch('/api/scan/smuggling', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target })
    }).then(r => r.json()).then(d => {
        if (d.error) { resultsDiv.innerHTML = `<div style="color:var(--danger);">Error: ${d.error}</div>`; return; }
        if (!d.vulnerabilities || d.vulnerabilities.length === 0) {
            resultsDiv.innerHTML = '<div style="padding:10px;">No smuggling vulnerabilities detected.</div>';
            return;
        }
        let html = `<div style="font-weight:600;margin-bottom:8px;">Found ${d.count} issues:</div>`;
        d.vulnerabilities.forEach(v => {
            html += `<div style="padding:6px 8px;border:1px solid var(--danger);border-radius:4px;margin-bottom:4px;font-size:10px;">
                <span style="color:var(--danger);font-weight:600;">⚠️ ${v.subtype.toUpperCase()}</span> — ${escapeHtml(v.result)}
            </div>`;
        });
        resultsDiv.innerHTML = html;
        toast(`Smuggling: ${d.count} issues found`, 'warning');
    }).catch(() => { resultsDiv.innerHTML = '<div style="color:var(--danger);">Scan failed</div>'; });
}

function runOauthScan() {
    const target = document.getElementById('oauthTarget').value.trim();
    if (!target) { toast('Enter a target URL', 'error'); return; }
    const resultsDiv = document.getElementById('oauthResults');
    resultsDiv.innerHTML = '<div style="padding:10px;color:var(--warning);">🔍 Scanning for OAuth/Open Redirect...</div>';
    fetch('/api/scan/oauth', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target })
    }).then(r => r.json()).then(d => {
        if (d.error) { resultsDiv.innerHTML = `<div style="color:var(--danger);">Error: ${d.error}</div>`; return; }
        if (!d.vulnerabilities || d.vulnerabilities.length === 0) {
            resultsDiv.innerHTML = '<div style="padding:10px;">No OAuth/redirect vulnerabilities found.</div>';
            return;
        }
        let html = `<div style="font-weight:600;margin-bottom:8px;">Found ${d.count} issues:</div>`;
        d.vulnerabilities.forEach(v => {
            html += `<div style="padding:6px 8px;border:1px solid var(--warning);border-radius:4px;margin-bottom:4px;font-size:10px;">
                <span style="color:var(--warning);font-weight:600;">⚠️ ${v.type.toUpperCase()}</span> — ${escapeHtml(v.result)}<br>
                <span style="color:var(--text-muted);">${escapeHtml(v.endpoint)} | Param: ${escapeHtml(v.parameter)}</span>
            </div>`;
        });
        resultsDiv.innerHTML = html;
        toast(`OAuth: ${d.count} issues found`, 'warning');
    }).catch(() => { resultsDiv.innerHTML = '<div style="color:var(--danger);">Scan failed</div>'; });
}

function runProtoScan() {
    const target = document.getElementById('protoTarget').value.trim();
    if (!target) { toast('Enter a target URL', 'error'); return; }
    const resultsDiv = document.getElementById('protoResults');
    resultsDiv.innerHTML = '<div style="padding:10px;color:var(--warning);">🔍 Scanning for prototype pollution...</div>';
    fetch('/api/scan/prototype_pollution', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target })
    }).then(r => r.json()).then(d => {
        if (d.error) { resultsDiv.innerHTML = `<div style="color:var(--danger);">Error: ${d.error}</div>`; return; }
        if (!d.vulnerabilities || d.vulnerabilities.length === 0) {
            resultsDiv.innerHTML = '<div style="padding:10px;">No prototype pollution found.</div>';
            return;
        }
        let html = `<div style="font-weight:600;margin-bottom:8px;">Found ${d.count} vulnerabilities:</div>`;
        d.vulnerabilities.forEach(v => {
            html += `<div style="padding:6px 8px;border:1px solid var(--danger);border-radius:4px;margin-bottom:4px;font-size:10px;">
                <span style="color:var(--danger);font-weight:600;">⚠️ PROTOTYPE POLLUTION</span> — ${escapeHtml(v.result)}<br>
                <span style="color:var(--text-muted);">${escapeHtml(v.endpoint)} | Param: ${escapeHtml(v.parameter)}</span>
            </div>`;
        });
        resultsDiv.innerHTML = html;
        toast(`Proto Pollution: ${d.count} vulns found`, 'warning');
    }).catch(() => { resultsDiv.innerHTML = '<div style="color:var(--danger);">Scan failed</div>'; });
}

function runExploitChains() {
    const target = document.getElementById('chainTarget').value.trim();
    if (!target) { toast('Enter a target URL', 'error'); return; }
    if (vulnerabilities.length === 0) { toast('Run a scan first to find vulnerabilities', 'warning'); return; }
    const resultsDiv = document.getElementById('chainResults');
    resultsDiv.innerHTML = '<div style="padding:10px;color:var(--warning);">⛓️ Executing exploit chains...</div>';
    fetch('/api/exploit/chains', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target, vulnerabilities })
    }).then(r => r.json()).then(d => {
        if (d.error) { resultsDiv.innerHTML = `<div style="color:var(--danger);">Error: ${d.error}</div>`; return; }
        if (!d.chains || d.chains.length === 0) {
            resultsDiv.innerHTML = '<div style="padding:10px;">No applicable exploit chains found.</div>';
            return;
        }
        let html = '';
        d.chains.forEach(chain => {
            html += `<div style="border:1px solid var(--border);border-radius:6px;padding:10px;margin-bottom:8px;">
                <div style="font-weight:700;color:var(--orange);margin-bottom:6px;">⛓️ ${escapeHtml(chain.chain)}</div>`;
            if (chain.steps) {
                chain.steps.forEach(s => {
                    html += `<div style="padding:3px 0;font-size:10px;">
                        <span style="color:var(--text-muted);">Step ${s.step}:</span> ${escapeHtml(s.action)}
                        ${s.detail ? `<div style="color:var(--text-muted);margin-left:16px;">→ ${escapeHtml(s.detail)}</div>` : ''}
                    </div>`;
                });
            }
            html += '</div>';
        });
        resultsDiv.innerHTML = html;
        toast('Exploit chains executed', 'success');
    }).catch(() => { resultsDiv.innerHTML = '<div style="color:var(--danger);">Chain execution failed</div>'; });
}

function runWafEvasion() {
    const payload = document.getElementById('wafPayload').value.trim();
    const vulnType = document.getElementById('wafVulnType').value;
    const waf = document.getElementById('wafType').value || null;
    if (!payload) { toast('Enter a payload', 'error'); return; }
    fetch('/api/evasion/encode', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ payload, vuln_type: vulnType, waf, level: 2 })
    }).then(r => r.json()).then(d => {
        let output = `Original: ${d.original}\n\nEncoded: ${d.encoded}\n\n`;
        if (d.variants && d.variants.length > 0) {
            output += `Variants (${d.variants.length}):\n`;
            d.variants.forEach((v, i) => { output += `${i+1}. ${v}\n`; });
        }
        document.getElementById('wafOutput').value = output;
        toast('WAF evasion payloads generated', 'success');
    }).catch(() => { toast('Encoding failed', 'error'); });
}

// ============================================================
// APEX v3.0 — NEW FUNCTIONS
// Theme toggle, keyboard modal, chart.js, timeline, nuke, batch scan, proxy health, curl import, PoC
// ============================================================

// --- THEME TOGGLE ---
function toggleTheme() {
    const html = document.documentElement;
    const current = html.getAttribute('data-theme');
    const next = current === 'light' ? 'dark' : 'light';
    html.setAttribute('data-theme', next);
    localStorage.setItem('apex_theme', next);
    toast(`Theme: ${next.toUpperCase()}`, 'info');
}

function loadTheme() {
    const saved = localStorage.getItem('apex_theme') || 'dark';
    document.documentElement.setAttribute('data-theme', saved);
}

// --- KEYBOARD SHORTCUTS MODAL ---
function closeShortcutsModal() {
    document.getElementById('shortcutsModal').style.display = 'none';
}

function showShortcutsModal() {
    document.getElementById('shortcutsModal').style.display = 'flex';
}

// --- CHART.JS DONUT CHART ---
let vulnChart = null;

function updateVulnChart(critical, high, medium, low) {
    const canvas = document.getElementById('vulnChart');
    const empty = document.getElementById('vulnChartEmpty');
    
    if (critical + high + medium + low === 0) {
        if (vulnChart) { vulnChart.destroy(); vulnChart = null; }
        canvas.style.display = 'none';
        if (empty) empty.style.display = 'block';
        return;
    }
    
    canvas.style.display = 'block';
    if (empty) empty.style.display = 'none';
    
    if (vulnChart) vulnChart.destroy();
    
    vulnChart = new Chart(canvas, {
        type: 'doughnut',
        data: {
            labels: ['Critical', 'High', 'Medium', 'Low'],
            datasets: [{
                data: [critical, high, medium, low],
                backgroundColor: ['#ef4444', '#f97316', '#f59e0b', '#10b981'],
                borderColor: '#151820',
                borderWidth: 2,
                hoverBorderColor: '#f97316'
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: true,
            cutout: '60%',
            plugins: {
                legend: {
                    position: 'bottom',
                    labels: {
                        color: '#9ca0b0',
                        font: { size: 10, family: "'Inter', sans-serif" },
                        padding: 12,
                        usePointStyle: true
                    }
                }
            }
        }
    });
}

// --- SCAN TIMELINE ---
function addTimelineEntry(target, vulns, status) {
    const timeline = document.getElementById('scanTimeline');
    if (!timeline) return;
    
    if (timeline.querySelector('.empty-state')) timeline.innerHTML = '';
    
    const dotClass = status === 'completed' ? 'info' : 'medium';
    const time = new Date().toLocaleTimeString();
    
    const div = document.createElement('div');
    div.className = 'timeline-item';
    div.innerHTML = `
        <div class="timeline-dot ${dotClass}"></div>
        <div class="timeline-content">
            <div class="tl-target">${escapeHtml(target)}</div>
            <div class="tl-meta">${time} — ${vulns} vulns — ${status}</div>
        </div>
    `;
    timeline.insertBefore(div, timeline.firstChild);
    
    // Keep max 20 entries
    while (timeline.children.length > 20) timeline.removeChild(timeline.lastChild);
}

// --- NUKE MODE ---
function startNuke() {
    const target = document.getElementById('targetInput').value.trim();
    if (!target) { toast('Enter a target URL first', 'error'); return; }
    
    if (!confirm('☢️ NUKE MODE will execute the FULL autonomous kill chain:\n\n' +
        '1. Reconnaissance\n2. Fingerprinting\n3. Full scan (19 scanners)\n4. AI analysis\n' +
        '5. Auto-exploitation\n6. Persistence deployment\n7. Credential dumping\n' +
        '8. Data exfiltration\n9. Cover tracks\n10. Generate report\n\n' +
        'This is IRREVERSIBLE. Continue?')) return;
    
    document.getElementById('nukeBtn').disabled = true;
    document.getElementById('scanBtn').disabled = true;
    document.getElementById('scanStatus').innerHTML = '<span class="badge badge-running">☢️ NUKING...</span>';
    
    fetch('/api/nuke', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target, options: { auto_exploit: true, deploy_persistence: true, exfiltrate_data: true, cover_tracks: true, generate_report: true } })
    }).then(r => r.json()).then(d => {
        document.getElementById('nukeBtn').disabled = false;
        document.getElementById('scanBtn').disabled = false;
        document.getElementById('scanStatus').innerHTML = '<span class="badge badge-success">NUKE COMPLETE</span>';
        toast(`☢️ NUKE complete — ${d.vulnerabilities_found || 0} vulns, ${d.exploits_successful || 0} exploited`, 'success');
        addTimelineEntry(target, d.vulnerabilities_found || 0, 'nuked');
        updateStats();
        loadHistory();
    }).catch(e => {
        document.getElementById('nukeBtn').disabled = false;
        document.getElementById('scanBtn').disabled = false;
        document.getElementById('scanStatus').innerHTML = '<span class="badge badge-failed">NUKE FAILED</span>';
        toast('NUKE failed: ' + e.message, 'error');
    });
}

// --- BATCH SCAN ---
let batchQueue = [];

function startBatchScan() {
    const textarea = document.getElementById('batchTargets');
    const targets = textarea.value.split('\n').map(t => t.trim()).filter(t => t.length > 0);
    
    if (targets.length === 0) { toast('Enter at least one target', 'error'); return; }
    
    batchQueue = targets;
    document.getElementById('batchProgress').style.display = 'block';
    document.getElementById('batchStatus').textContent = `0 / ${targets.length} scanned`;
    document.getElementById('batchProgressFill').style.width = '0%';
    
    processBatchQueue();
}

function processBatchQueue() {
    if (batchQueue.length === 0) {
        document.getElementById('batchStatus').textContent = 'Batch scan complete!';
        toast('Batch scan complete', 'success');
        return;
    }
    
    const target = batchQueue.shift();
    const total = batchQueue.length + 1;
    const done = document.getElementById('batchStatus').dataset.done || 0;
    
    fetch('/api/scan/batch', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target, scan_type: 'full' })
    }).then(r => r.json()).then(d => {
        const completed = parseInt(done) + 1;
        document.getElementById('batchStatus').dataset.done = completed;
        document.getElementById('batchStatus').textContent = `${completed} / ${total + completed - 1} scanned`;
        document.getElementById('batchProgressFill').style.width = ((completed / (total + completed)) * 100) + '%';
        addTimelineEntry(target, d.vulns_found || 0, 'batch');
        processBatchQueue();
    }).catch(() => {
        processBatchQueue(); // Continue even on error
    });
}

function handleBatchFile(event) {
    const file = event.target.files[0];
    if (!file) return;
    
    const reader = new FileReader();
    reader.onload = function(e) {
        document.getElementById('batchTargets').value = e.target.result;
        toast(`Loaded ${file.name}`, 'success');
    };
    reader.readAsText(file);
}

// --- PROXY HEALTH CHECK ---
function checkProxyHealth() {
    fetch('/api/proxy/health')
        .then(r => r.json())
        .then(d => {
            const dot = document.getElementById('healthDot');
            if (!dot) return;
            dot.className = 'health-dot';
            if (d.healthy) {
                dot.classList.add('green');
                dot.title = `Proxy healthy — ${d.active_proxies || 0} active`;
            } else if (d.active_proxies > 0) {
                dot.classList.add('yellow');
                dot.title = `Some proxies down — ${d.active_proxies} active`;
            } else {
                dot.classList.add('red');
                dot.title = 'No healthy proxies';
            }
        })
        .catch(() => {
            const dot = document.getElementById('healthDot');
            if (dot) { dot.className = 'health-dot red'; dot.title = 'Proxy check failed'; }
        });
}

// --- CURL / RAW HTTP IMPORT ---
function importCurl() {
    const curlCmd = prompt('Paste curl command or raw HTTP request:');
    if (!curlCmd) return;
    
    fetch('/api/auth/import_curl', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ curl_command: curlCmd })
    }).then(r => r.json()).then(d => {
        if (d.success) {
            toast('Cookies imported successfully', 'success');
            if (d.cookies) {
                document.getElementById('targetInput').value = d.target_url || '';
            }
        } else {
            toast('Import failed: ' + (d.error || 'Unknown error'), 'error');
        }
    }).catch(() => toast('Import failed', 'error'));
}

// --- PoC DOWNLOAD ---
function downloadPoc(vulnIndex) {
    if (!vulnerabilities[vulnIndex]) { toast('Vulnerability not found', 'error'); return; }
    
    fetch('/api/poc/generate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ vulnerability: vulnerabilities[vulnIndex] })
    }).then(r => r.json()).then(d => {
        if (d.filepath) {
            window.open('/api/poc/download?file=' + encodeURIComponent(d.filepath), '_blank');
            toast('PoC generated: ' + d.filename, 'success');
        } else {
            toast('PoC generation failed', 'error');
        }
    }).catch(() => toast('PoC generation failed', 'error'));
}

// --- OSINT TOOL ---
function openOsintTool() {
    const target = document.getElementById('targetInput').value.trim();
    const domain = target ? target.replace(/https?:\/\//, '').split('/')[0] : '';
    
    const modal = document.getElementById('modalContent');
    modal.innerHTML = `
        <h3>🌐 OSINT PROFILER</h3>
        <label>Target Domain</label>
        <input type="text" id="osintDomain" value="${domain}" placeholder="example.com">
        <div class="modal-actions">
            <button class="btn btn-primary" onclick="runOsint()">🔍 PROFILE TARGET</button>
            <button class="btn" onclick="closeModal()">CLOSE</button>
        </div>
        <div id="osintResults" style="margin-top:12px;"></div>
    `;
    document.getElementById('modalOverlay').classList.add('active');
}

function runOsint() {
    const domain = document.getElementById('osintDomain').value.trim();
    if (!domain) { toast('Enter a domain', 'error'); return; }
    
    const resultsDiv = document.getElementById('osintResults');
    resultsDiv.innerHTML = '<div class="empty-state">Running OSINT...</div>';
    
    fetch('/api/osint/profile', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ domain })
    }).then(r => r.json()).then(d => {
        const p = d.profile || d;
        let html = '<div style="font-size:11px;">';
        html += `<p><strong>Summary:</strong> ${escapeHtml(p.summary || 'N/A')}</p>`;
        if (p.subdomains && p.subdomains.length > 0) {
            html += `<p><strong>Subdomains (${p.subdomains.length}):</strong> ${p.subdomains.slice(0,10).map(s => escapeHtml(s)).join(', ')}</p>`;
        }
        if (p.tech_stack && p.tech_stack.length > 0) {
            html += `<p><strong>Tech Stack:</strong> ${p.tech_stack.map(t => t.name).join(', ')}</p>`;
        }
        if (p.emails && p.emails.length > 0) {
            html += `<p><strong>Emails:</strong> ${p.emails.slice(0,5).join(', ')}</p>`;
        }
        if (p.related_domains && p.related_domains.length > 0) {
            html += `<p><strong>Related Domains:</strong> ${p.related_domains.slice(0,5).join(', ')}</p>`;
        }
        html += '</div>';
        resultsDiv.innerHTML = html;
        toast('OSINT profile complete', 'success');
    }).catch(() => {
        resultsDiv.innerHTML = '<div style="color:var(--danger);">OSINT profiling failed</div>';
    });
}

// --- PDF REPORT DOWNLOAD ---
function downloadPdfReport(scanId) {
    window.open('/api/report/pdf?scan_id=' + encodeURIComponent(scanId || currentScanId || ''), '_blank');
    toast('PDF report downloading...', 'info');
}

// --- SCAN COMPARE ---
function compareScans() {
    const scan1 = prompt('Enter first scan ID:');
    const scan2 = prompt('Enter second scan ID:');
    if (!scan1 || !scan2) return;
    
    fetch(`/api/scan/compare?scan1=${encodeURIComponent(scan1)}&scan2=${encodeURIComponent(scan2)}`)
        .then(r => r.json())
        .then(d => {
            const modal = document.getElementById('modalContent');
            modal.innerHTML = `
                <h3>📊 SCAN COMPARISON</h3>
                <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;font-size:11px;">
                    <div><strong>Scan 1:</strong> ${d.scan1?.vulns || 0} vulns</div>
                    <div><strong>Scan 2:</strong> ${d.scan2?.vulns || 0} vulns</div>
                </div>
                <p style="margin-top:8px;"><strong>New vulns:</strong> ${(d.new_vulns || []).length}</p>
                <p><strong>Fixed vulns:</strong> ${(d.fixed_vulns || []).length}</p>
                <div class="modal-actions"><button class="btn" onclick="closeModal()">CLOSE</button></div>
            `;
            document.getElementById('modalOverlay').classList.add('active');
        }).catch(() => toast('Comparison failed', 'error'));
}

// --- OVERRIDE: updateStats to include chart ---
const origUpdateStats = updateStats;
updateStats = function() {
    origUpdateStats();
    // Update donut chart
    if (vulnerabilities.length > 0) {
        const critical = vulnerabilities.filter(v => v.severity === 'critical').length;
        const high = vulnerabilities.filter(v => v.severity === 'high').length;
        const medium = vulnerabilities.filter(v => v.severity === 'medium').length;
        const low = vulnerabilities.filter(v => v.severity === 'low').length;
        updateVulnChart(critical, high, medium, low);
    }
};

// --- OVERRIDE: renderVulns to add PoC download buttons ---
const origRenderVulns = renderVulns;
renderVulns = function(vulns, summary) {
    origRenderVulns(vulns, summary);
    // Add PoC download buttons to vuln rows
    setTimeout(() => {
        const rows = document.querySelectorAll('#resultsPanel .vuln-row');
        rows.forEach((row, i) => {
            if (!row.querySelector('.poc-download-btn')) {
                const btn = document.createElement('span');
                btn.className = 'poc-download-btn';
                btn.textContent = '📄 PoC';
                btn.title = 'Download Proof of Concept';
                btn.onclick = (e) => { e.stopPropagation(); downloadPoc(i); };
                row.appendChild(btn);
            }
        });
    }, 100);
};

// --- OVERRIDE: setupKeyboardShortcuts to add new shortcuts ---
const origSetupKb = setupKeyboardShortcuts;
setupKeyboardShortcuts = function() {
    origSetupKb();
    document.addEventListener('keydown', function(e) {
        if (e.key === '?' && !e.ctrlKey && !e.metaKey && document.activeElement === document.body) {
            e.preventDefault();
            showShortcutsModal();
        }
        if (e.ctrlKey && e.key === 't') {
            e.preventDefault();
            toggleTheme();
        }
        if (e.ctrlKey && e.key === 'b') {
            e.preventDefault();
            switchTab('target');
            setTimeout(() => document.getElementById('batchTargets')?.focus(), 200);
        }
    });
};

// --- INIT v3.0 ---
document.addEventListener('DOMContentLoaded', function() {
    loadTheme();
    checkProxyHealth();
    setInterval(checkProxyHealth, 60000); // Check every 60s
});

// ============================================================
// APEX v3.0 — BROWSER FUNCTIONS
// ============================================================

let browserCurrentUrl = '';

// Listen for messages from the proxied iframe
window.addEventListener('message', function(e) {
    if (!e.data || !e.data.action) return;
    
    switch(e.data.action) {
        case 'apex_navigate':
            browserNavigate(e.data.url);
            break;
        case 'apex_scan':
            document.getElementById('targetInput').value = e.data.url;
            startScan('full');
            switchTab('exploit');
            toast('Scanning: ' + e.data.url, 'info');
            break;
        case 'apex_exploit':
            document.getElementById('targetInput').value = e.data.url;
            startScan('full');
            toast('Scanning then exploiting: ' + e.data.url, 'info');
            break;
        case 'apex_fingerprint':
            fetch('/api/core/fingerprint', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({target: e.data.url})
            }).then(r => r.json()).then(d => {
                const fp = d.fingerprint || {};
                const info = [];
                if (fp.server) info.push('Server: ' + fp.server);
                if (fp.language) info.push('Lang: ' + fp.language);
                if (fp.waf) info.push('WAF: ' + fp.waf);
                if (fp.database) info.push('DB: ' + fp.database);
                if (fp.cms) info.push('CMS: ' + fp.cms);
                document.getElementById('browserAiContent').innerHTML = 
                    '<strong>Fingerprint:</strong> ' + (info.join(' | ') || 'No data');
                document.getElementById('browserAiPanel').style.display = 'block';
                toast('Fingerprint complete', 'success');
            });
            break;
        case 'apex_ai_analyze':
            browserAnalyzePage(e.data.url);
            break;
    }
});

function browserNavigate(url, andScan) {
    if (!url) {
        url = document.getElementById('browserUrlInput').value.trim();
    }
    if (!url) { toast('Enter a URL', 'error'); return; }
    if (!url.startsWith('http')) url = 'https://' + url;
    
    browserCurrentUrl = url;
    document.getElementById('browserUrlInput').value = url;
    
    const loading = document.getElementById('browserLoading');
    const loadingUrl = document.getElementById('browserLoadingUrl');
    loading.style.display = 'flex';
    loadingUrl.textContent = url;
    
    fetch('/api/browser/proxy', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({url: url})
    }).then(r => r.json()).then(d => {
        loading.style.display = 'none';
        if (d.success && d.html) {
            const frame = document.getElementById('browserFrame');
            frame.srcdoc = d.html;
            document.getElementById('browserAiPanel').style.display = 'block';
            
            // Show page info
            const info = d.page_info || {};
            let aiText = `<strong>${escapeHtml(info.title || 'No title')}</strong> | `;
            aiText += `Status: ${info.status_code} | `;
            aiText += `Forms: ${info.forms_count} | Links: ${info.links_count}`;
            if (info.detected_tech && info.detected_tech.length > 0) {
                aiText += `<br>🖥️ Tech: ${info.detected_tech.join(', ')}`;
            }
            if (info.server) aiText += `<br>📡 Server: ${info.server}`;
            if (info.forms && info.forms.length > 0) {
                aiText += `<br>📝 Forms detected: ${info.forms.length}`;
                info.forms.forEach(f => {
                    const csrf = f.has_csrf ? '✅ CSRF' : '⚠️ NO CSRF';
                    aiText += `<br>  → ${f.method.toUpperCase()} ${f.action} (${f.inputs.length} inputs) ${csrf}`;
                });
            }
            document.getElementById('browserAiContent').innerHTML = aiText;
            
            if (andScan) {
                document.getElementById('targetInput').value = url;
                startScan('full');
                switchTab('exploit');
            }
            
            toast('Page loaded through VPN/Tor', 'success');
        } else {
            document.getElementById('browserFrame').srcdoc = 
                `<html><body style="background:#0f1117;color:#ef4444;font-family:monospace;padding:40px;text-align:center;">
                <h2>❌ Failed to load page</h2><p>${escapeHtml(d.error || 'Unknown error')}</p></body></html>`;
            toast('Failed: ' + (d.error || 'Unknown'), 'error');
        }
    }).catch(e => {
        loading.style.display = 'none';
        toast('Browser proxy error: ' + e.message, 'error');
    });
}

function browserSearch() {
    const query = document.getElementById('browserSearchInput').value.trim();
    const searchType = document.getElementById('browserSearchType').value;
    
    if (!query && searchType === 'web') {
        toast('Enter a search query', 'error');
        return;
    }
    
    const resultsDiv = document.getElementById('browserSearchResults');
    resultsDiv.style.display = 'block';
    resultsDiv.innerHTML = '<div style="padding:10px;color:var(--warning);">🔍 Searching...</div>';
    
    const body = searchType === 'web' 
        ? {query: query, type: 'web'}
        : {dork_type: searchType};
    
    const endpoint = searchType === 'web' ? '/api/browser/search' : '/api/browser/search/dork';
    
    fetch(endpoint, {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify(body)
    }).then(r => r.json()).then(d => {
        if (!d.results || d.results.length === 0) {
            resultsDiv.innerHTML = '<div style="padding:10px;color:var(--text-muted);">No results found.</div>';
            return;
        }
        
        let html = '';
        d.results.forEach((r, i) => {
            html += `<div class="browser-result-item">
                <div class="br-title">${escapeHtml(r.title || 'Untitled')}</div>
                <div class="br-url">${escapeHtml(r.url || r.display_url || '')}</div>
                ${r.snippet ? `<div class="br-snippet">${escapeHtml(r.snippet)}</div>` : ''}
                <div class="br-actions">
                    <button class="br-btn" onclick="browserNavigate('${escapeAttr(r.url)}')">🌐 BROWSE</button>
                    <button class="br-btn scan" onclick="document.getElementById('targetInput').value='${escapeAttr(r.url)}';startScan('full');switchTab('exploit');toast('Scanning: ${escapeAttr(r.url)}','info')">🔍 SCAN</button>
                </div>
            </div>`;
        });
        resultsDiv.innerHTML = html;
        toast(`Found ${d.count} results`, 'success');
    }).catch(() => {
        resultsDiv.innerHTML = '<div style="padding:10px;color:var(--danger);">Search failed</div>';
    });
}

function browserAnalyzePage(url) {
    if (!url) url = browserCurrentUrl;
    if (!url) { toast('No page loaded', 'error'); return; }
    
    document.getElementById('browserAiPanel').style.display = 'block';
    document.getElementById('browserAiContent').innerHTML = '🤖 Analyzing page...';
    
    fetch('/api/browser/analyze', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({url: url})
    }).then(r => r.json()).then(d => {
        if (d.analysis) {
            document.getElementById('browserAiContent').innerHTML = d.analysis;
        } else {
            document.getElementById('browserAiContent').innerHTML = 'No analysis available.';
        }
    }).catch(() => {
        document.getElementById('browserAiContent').innerHTML = 'AI analysis failed.';
    });
}
