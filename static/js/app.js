// ============================================================
// APEX — Dashboard JS
// ============================================================

var socket = null;
try { if (typeof io !== 'undefined') socket = io(); } catch(e) {}

var currentScanId = null;
var vulnerabilities = [];
var proxyEnabled = false, torEnabled = false, vpnEnabled = false;
var aiSettings = { api_key: 'ollama', base_url: 'https://api.ollama.com/v1', model: 'deepseek-v4-pro' };

// ============================================================
// INIT
// ============================================================
document.addEventListener('DOMContentLoaded', function() {
    loadAiSettings();
    loadHistory();
    if (socket) {
        socket.on('connect', function() {
            document.getElementById('connDot').style.background = 'var(--green)';
            document.getElementById('connText').textContent = 'ONLINE';
        });
        socket.on('disconnect', function() {
            document.getElementById('connDot').style.background = 'var(--red)';
            document.getElementById('connText').textContent = 'OFFLINE';
        });
        socket.on('scan_complete', function(d) {
            vulnerabilities = d.vulnerabilities || [];
            renderResults(d.vulnerabilities, d.summary);
            document.getElementById('scanBtn').disabled = false;
            document.getElementById('nukeBtn').disabled = false;
            document.getElementById('scanStatus').textContent = 'DONE';
            loadHistory();
            toast(vulnerabilities.length + ' vulnerabilities found', 'success');
        });
        socket.on('exploit_complete', function(d) {
            document.getElementById('nukeBtn').disabled = false;
            document.getElementById('scanStatus').textContent = 'DONE';
            toast('Exploit complete', 'success');
        });
        socket.emit('request_feed');
    }
});

// ============================================================
// NAVIGATION
// ============================================================
function switchTab(tab) {
    document.querySelectorAll('.tab').forEach(function(t) { t.classList.remove('active'); });
    document.querySelectorAll('.nav-item').forEach(function(n) { n.classList.remove('active'); });
    var tabEl = document.getElementById('tab-' + tab);
    if (tabEl) tabEl.classList.add('active');
    var navEl = document.querySelector('.nav-item[data-tab="' + tab + '"]');
    if (navEl) navEl.classList.add('active');
    if (tab === 'history') loadHistory();
    if (tab === 'settings') loadSettingsForm();
}

// ============================================================
// SCAN
// ============================================================
function startScan() {
    var target = document.getElementById('targetInput').value.trim();
    if (!target) { toast('Enter a target URL', 'error'); return; }
    document.getElementById('scanBtn').disabled = true;
    document.getElementById('nukeBtn').disabled = true;
    document.getElementById('scanStatus').textContent = 'SCANNING...';
    document.getElementById('resultsPanel').innerHTML = '<div class="empty">Scanning ' + escapeHtml(target) + '...</div>';
    vulnerabilities = [];
    fetch('/api/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target: target, scan_type: 'full' })
    }).then(function(r) { return r.json(); }).then(function(d) {
        currentScanId = d.scan_id;
    }).catch(function() {
        document.getElementById('scanBtn').disabled = false;
        document.getElementById('scanStatus').textContent = 'FAILED';
        toast('Scan failed', 'error');
    });
}

function startNuke() {
    var target = document.getElementById('targetInput').value.trim();
    if (!target) { toast('Enter a target URL', 'error'); return; }
    if (!confirm('NUKE will run full autonomous attack on ' + target + '. Continue?')) return;
    document.getElementById('nukeBtn').disabled = true;
    document.getElementById('scanBtn').disabled = true;
    document.getElementById('scanStatus').textContent = 'NUKING...';
    fetch('/api/nuke', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target: target, options: { auto_exploit: true, deploy_persistence: true, exfiltrate_data: true, cover_tracks: true, generate_report: true } })
    }).then(function(r) { return r.json(); }).then(function(d) {
        document.getElementById('nukeBtn').disabled = false;
        document.getElementById('scanBtn').disabled = false;
        document.getElementById('scanStatus').textContent = 'NUKE DONE';
        toast('NUKE complete — ' + (d.vulnerabilities_found || 0) + ' vulns', 'success');
        loadHistory();
    }).catch(function() {
        document.getElementById('nukeBtn').disabled = false;
        document.getElementById('scanBtn').disabled = false;
        document.getElementById('scanStatus').textContent = 'FAILED';
        toast('NUKE failed', 'error');
    });
}

// ============================================================
// RESULTS
// ============================================================
function renderResults(vulns, summary) {
    var panel = document.getElementById('resultsPanel');
    document.getElementById('vulnCount').textContent = vulns ? vulns.length : 0;
    if (!vulns || vulns.length === 0) {
        panel.innerHTML = '<div class="empty">No vulnerabilities found</div>';
        return;
    }
    var html = '';
    vulns.forEach(function(v, i) {
        var sev = v.severity || 'low';
        html += '<div class="vuln-item" onclick="exploitVuln(' + i + ')">';
        html += '<span class="sev ' + sev + '">' + sev.toUpperCase() + '</span>';
        html += '<span class="type">' + escapeHtml(v.type || 'UNKNOWN') + '</span>';
        html += '<span class="endpoint">' + escapeHtml(v.endpoint || '') + '</span>';
        html += '</div>';
    });
    panel.innerHTML = html;
}

function exploitVuln(index) {
    if (!vulnerabilities[index]) return;
    document.getElementById('scanStatus').textContent = 'EXPLOITING...';
    fetch('/api/exploit', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ scan_id: currentScanId, vulnerabilities: [vulnerabilities[index]] })
    }).then(function(r) { return r.json(); }).then(function() {
        toast('Exploit launched', 'info');
    }).catch(function() {
        toast('Exploit failed', 'error');
    });
}

// ============================================================
// ANONYMITY TOGGLES
// ============================================================
function toggleAnon(type) {
    var states = { proxy: proxyEnabled, tor: torEnabled, vpn: vpnEnabled };
    var newState = !states[type];
    if (type === 'proxy') proxyEnabled = newState;
    if (type === 'tor') torEnabled = newState;
    if (type === 'vpn') vpnEnabled = newState;
    var el = document.getElementById(type + 'Toggle');
    if (el) el.classList.toggle('active', newState);
    fetch('/api/' + type + '/toggle', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ enabled: newState })
    }).catch(function() {});
    toast(type.toUpperCase() + ' ' + (newState ? 'ON' : 'OFF'), 'info');
}

// ============================================================
// BROWSER
// ============================================================
var browserCurrentUrl = '';

function browserNavigate(url, andScan) {
    if (!url) url = document.getElementById('browserUrl').value.trim();
    if (!url) { toast('Enter a URL', 'error'); return; }
    if (!url.startsWith('http')) url = 'https://' + url;
    browserCurrentUrl = url;
    document.getElementById('browserUrl').value = url;
    var loading = document.getElementById('browserLoading');
    var loadingUrl = document.getElementById('browserLoadingUrl');
    loading.classList.add('show');
    loadingUrl.textContent = url;
    fetch('/api/browser/proxy', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: url })
    }).then(function(r) { return r.json(); }).then(function(d) {
        loading.classList.remove('show');
        if (d.success && d.html) {
            document.getElementById('browserFrame').srcdoc = d.html;
            if (andScan) {
                document.getElementById('targetInput').value = url;
                startScan();
            }
            toast('Page loaded', 'success');
        } else {
            document.getElementById('browserFrame').srcdoc = '<html><body style="background:#000;color:#e53935;font-family:monospace;padding:40px;text-align:center;"><h2>Failed</h2><p>' + escapeHtml(d.error || 'Unknown') + '</p></body></html>';
            toast('Failed: ' + (d.error || 'Unknown'), 'error');
        }
    }).catch(function(e) {
        loading.classList.remove('show');
        toast('Error: ' + e.message, 'error');
    });
}

// ============================================================
// AI CHAT
// ============================================================
function sendAi() {
    var input = document.getElementById('aiInput');
    var msg = input.value.trim();
    if (!msg) return;
    addAiMsg('user', msg);
    input.value = '';
    fetch('/api/ai/chat', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
            message: msg,
            context: {
                target: document.getElementById('targetInput').value,
                vulnerabilities: vulnerabilities.slice(0, 10)
            },
            settings: aiSettings
        })
    }).then(function(r) { return r.json(); }).then(function(d) {
        if (d.error) { addAiMsg('ai', 'Error: ' + d.error); return; }
        addAiMsg('ai', d.response || 'No response');
    }).catch(function() {
        addAiMsg('ai', 'AI connection failed. Check settings.');
    });
}

function addAiMsg(role, text) {
    var container = document.getElementById('aiMessages');
    var div = document.createElement('div');
    div.className = 'ai-msg ' + role;
    div.textContent = text;
    container.appendChild(div);
    container.scrollTop = container.scrollHeight;
}

// ============================================================
// HISTORY
// ============================================================
function loadHistory() {
    fetch('/api/history').then(function(r) { return r.json(); }).then(function(data) {
        var panel = document.getElementById('historyPanel');
        if (!data || data.length === 0) {
            panel.innerHTML = '<div class="empty">No scan history</div>';
            return;
        }
        var html = '<table class="history-table"><thead><tr><th>Target</th><th>Date</th><th>Vulns</th><th>Status</th><th></th></tr></thead><tbody>';
        data.forEach(function(h) {
            html += '<tr>';
            html += '<td>' + escapeHtml(h.target || '') + '</td>';
            html += '<td>' + (h.started ? new Date(h.started).toLocaleDateString() : '') + '</td>';
            html += '<td>' + (h.vulns_found || 0) + '</td>';
            html += '<td>' + (h.status || 'unknown') + '</td>';
            html += '<td><button class="btn btn-sm" onclick="loadHistoryDetail(\'' + h.id + '\')">VIEW</button></td>';
            html += '</tr>';
        });
        html += '</tbody></table>';
        panel.innerHTML = html;
    });
}

function loadHistoryDetail(scanId) {
    fetch('/api/history/' + scanId).then(function(r) { return r.json(); }).then(function(d) {
        if (d.vulns_json) {
            try {
                var vulns = typeof d.vulns_json === 'string' ? JSON.parse(d.vulns_json) : d.vulns_json;
                vulnerabilities = vulns;
                renderResults(vulns, {});
                switchTab('dashboard');
                toast('Loaded scan: ' + d.target, 'info');
            } catch(e) { toast('Failed to parse', 'error'); }
        }
    });
}

// ============================================================
// SETTINGS
// ============================================================
function loadAiSettings() {
    var saved = localStorage.getItem('apex_ai_settings');
    if (saved) { try { aiSettings = JSON.parse(saved); } catch(e) {} }
}

function loadSettingsForm() {
    document.getElementById('setApiKey').value = aiSettings.api_key || '';
    document.getElementById('setBaseUrl').value = aiSettings.base_url || '';
    document.getElementById('setModel').value = aiSettings.model || '';
    // Load ransomware/deface settings
    var ransom = localStorage.getItem('apex_ransom');
    if (ransom) {
        try {
            var r = JSON.parse(ransom);
            document.getElementById('setRansomImg').value = r.image || '';
            document.getElementById('setRansomMsg').value = r.message || '';
        } catch(e) {}
    }
    var deface = localStorage.getItem('apex_deface');
    if (deface) {
        try {
            var d = JSON.parse(deface);
            document.getElementById('setDefaceImg').value = d.image || '';
            document.getElementById('setDefaceMsg').value = d.message || '';
        } catch(e) {}
    }
}

function saveAiSettings() {
    aiSettings.api_key = document.getElementById('setApiKey').value;
    aiSettings.base_url = document.getElementById('setBaseUrl').value;
    aiSettings.model = document.getElementById('setModel').value;
    localStorage.setItem('apex_ai_settings', JSON.stringify(aiSettings));
    fetch('/api/ai/settings', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(aiSettings)
    });
    toast('AI settings saved', 'success');
}

function testAi() {
    saveAiSettings();
    fetch('/api/ai/test', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(aiSettings)
    }).then(function(r) { return r.json(); }).then(function(d) {
        if (d.success) toast('AI OK — ' + d.model, 'success');
        else toast('AI failed: ' + (d.error || 'Unknown'), 'error');
    }).catch(function() { toast('AI connection failed', 'error'); });
}

function saveRansomSettings() {
    var data = {
        image: document.getElementById('setRansomImg').value,
        message: document.getElementById('setRansomMsg').value
    };
    localStorage.setItem('apex_ransom', JSON.stringify(data));
    fetch('/api/settings/ransomware', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(data)
    });
    toast('Ransomware settings saved', 'success');
}

function saveDefaceSettings() {
    var data = {
        image: document.getElementById('setDefaceImg').value,
        message: document.getElementById('setDefaceMsg').value
    };
    localStorage.setItem('apex_deface', JSON.stringify(data));
    fetch('/api/settings/deface', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(data)
    });
    toast('Deface settings saved', 'success');
}

// ============================================================
// UTILITY
// ============================================================
function escapeHtml(str) {
    if (!str) return '';
    var div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
}

function toast(message, type) {
    var container = document.getElementById('toastContainer');
    var div = document.createElement('div');
    div.className = 'toast';
    div.textContent = message;
    container.appendChild(div);
    setTimeout(function() { div.remove(); }, 3000);
}