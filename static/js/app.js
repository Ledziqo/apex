// ============================================================
// APEX — Dashboard JS v3.0
// ============================================================

var socket = null;
try { if (typeof io !== 'undefined') socket = io(); } catch(e) {}

var currentScanId = null;
var vulnerabilities = [];
var proxyEnabled = false, torEnabled = false, vpnEnabled = false;
var aiSettings = { api_key: 'ollama', base_url: 'https://api.ollama.com/v1', model: 'qwen3.5' };
var allLogs = [];
var currentLogFilter = 'all';
var browserHistory = [];
var browserHistoryIndex = -1;
var scanSteps = []; // Live scan step display

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
            aiNarrate('scan_complete', d);
        });
        socket.on('exploit_complete', function(d) {
            document.getElementById('nukeBtn').disabled = false;
            document.getElementById('scanStatus').textContent = 'DONE';
            toast('Exploit complete', 'success');
            aiNarrate('exploit_complete', d);
        });
        socket.on('feed_update', function(entry) {
            allLogs.push(entry);
            renderLogs();
            aiNarrate('feed', entry);
        });
        socket.on('scan_step', function(step) {
            // Update or add scan step
            var found = false;
            for (var i = 0; i < scanSteps.length; i++) {
                if (scanSteps[i].scanner === step.scanner) {
                    scanSteps[i] = step;
                    found = true;
                    break;
                }
            }
            if (!found) {
                scanSteps.push(step);
            }
            renderScanSteps();
        });
        socket.on('feed_history', function(history) {
            allLogs = history || [];
            renderLogs();
        });
        socket.emit('request_feed');
    }
    // Load safety status
    loadSafetyStatus();
    setInterval(loadSafetyStatus, 30000);
    // Load dashboard safety panel
    loadDashSafety();
    setInterval(loadDashSafety, 30000);
    // Load dashboard live logs
    loadDashLogs();
    setInterval(loadDashLogs, 5000);
});

// ============================================================
// AI AUTO-NARRATION
// ============================================================
function aiNarrate(eventType, data) {
    var msg = '';
    if (eventType === 'scan_complete') {
        var s = data.summary || {};
        msg = 'Scan complete! Found ' + (data.vulnerabilities ? data.vulnerabilities.length : 0) + ' vulnerabilities — ' +
              (s.critical || 0) + ' critical, ' + (s.high || 0) + ' high, ' + (s.medium || 0) + ' medium, ' + (s.low || 0) + ' low.';
        if (s.critical > 0) msg += ' Prioritize exploiting the critical ones first.';
    } else if (eventType === 'exploit_complete') {
        msg = 'Exploitation finished. ' + (data.success || 0) + ' succeeded, ' + (data.failed || 0) + ' failed.';
    } else if (eventType === 'feed') {
        var level = data.level || 'info';
        var text = data.message || '';
        if (level === 'warning' && (text.includes('found') || text.includes('vulnerab'))) {
            msg = '⚠️ ' + text;
        } else if (level === 'success' && text.includes('SCAN COMPLETE')) {
            msg = '✅ ' + text;
        } else if (level === 'error') {
            msg = '❌ ' + text;
        }
    }
    if (msg) {
        addAiMsg('ai', msg);
    }
}

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
    if (tab === 'logs') renderLogs();
    if (tab === 'safety') loadSafetyStatus();
}

// ============================================================
// SCAN
// ============================================================
var scanPollInterval = null;

function startScan(targetOverride) {
    var target = targetOverride || document.getElementById('targetInput').value.trim();
    if (!target) { toast('Enter a target URL', 'error'); return; }
    if (!target.startsWith('http')) target = 'https://' + target;
    document.getElementById('targetInput').value = target;
    document.getElementById('scanBtn').disabled = true;
    document.getElementById('nukeBtn').disabled = true;
    document.getElementById('scanStatus').textContent = 'SCANNING...';
    document.getElementById('resultsPanel').innerHTML = '<div class="empty">Scanning ' + escapeHtml(target) + '...<br><small>This may take 30-60 seconds</small></div>';
    vulnerabilities = [];
    addAiMsg('ai', '🔍 Starting scan on ' + target + '... Crawling pages, testing parameters, checking for vulnerabilities.');
    
    // Clear any existing poll
    if (scanPollInterval) clearInterval(scanPollInterval);
    
    fetch('/api/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target: target, scan_type: 'full' })
    }).then(function(r) { return r.json(); }).then(function(d) {
        currentScanId = d.scan_id;
        // Start polling for status (fallback if WebSocket fails)
        scanPollInterval = setInterval(function() {
            fetch('/api/scan/' + currentScanId + '/status')
                .then(function(r) { return r.json(); })
                .then(function(s) {
                    if (s.status === 'completed') {
                        clearInterval(scanPollInterval);
                        vulnerabilities = s.vulnerabilities || [];
                        var crit = 0, high = 0, med = 0, low = 0;
                        vulnerabilities.forEach(function(v) {
                            if (v.severity === 'critical') crit++;
                            else if (v.severity === 'high') high++;
                            else if (v.severity === 'medium') med++;
                            else low++;
                        });
                        renderResults(vulnerabilities, {critical: crit, high: high, medium: med, low: low});
                        document.getElementById('scanBtn').disabled = false;
                        document.getElementById('nukeBtn').disabled = false;
                        document.getElementById('scanStatus').textContent = 'DONE';
                        loadHistory();
                        toast(vulnerabilities.length + ' vulnerabilities found', 'success');
                        aiNarrate('scan_complete', {vulnerabilities: vulnerabilities, summary: {critical: crit, high: high, medium: med, low: low}});
                    } else if (s.status === 'failed') {
                        clearInterval(scanPollInterval);
                        document.getElementById('scanBtn').disabled = false;
                        document.getElementById('nukeBtn').disabled = false;
                        document.getElementById('scanStatus').textContent = 'FAILED';
                        document.getElementById('resultsPanel').innerHTML = '<div class="empty">Scan failed: ' + escapeHtml(s.error || 'Unknown error') + '</div>';
                        toast('Scan failed', 'error');
                    } else {
                        document.getElementById('scanStatus').textContent = 'SCANNING... ' + (s.progress || 0) + '%';
                    }
                });
        }, 2000);
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
    addAiMsg('ai', '☢️ NUKE MODE activated on ' + target + ' — full autonomous kill chain in progress.');
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
    if (summary) {
        html += '<div class="results-summary">';
        html += '<span class="sev-badge crit">' + (summary.critical || 0) + ' CRIT</span> ';
        html += '<span class="sev-badge high">' + (summary.high || 0) + ' HIGH</span> ';
        html += '<span class="sev-badge med">' + (summary.medium || 0) + ' MED</span> ';
        html += '<span class="sev-badge low">' + (summary.low || 0) + ' LOW</span>';
        html += '</div>';
    }
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

function renderScanSteps() {
    var panel = document.getElementById('resultsPanel');
    if (!panel || scanSteps.length === 0) return;
    var html = '<div class="scan-steps">';
    scanSteps.forEach(function(step) {
        var icon = step.status === 'done' ? '✅' : (step.status === 'scanning' ? '🔄' : '⏳');
        var foundText = step.found > 0 ? ' (' + step.found + ' found)' : '';
        html += '<div class="scan-step scan-step-' + step.status + '">';
        html += '<span class="step-icon">' + icon + '</span>';
        html += '<span class="step-name">' + escapeHtml(step.scanner) + '</span>';
        html += '<span class="step-result">' + foundText + '</span>';
        html += '</div>';
    });
    html += '</div>';
    panel.innerHTML = html;
}

function exploitVuln(index) {
    if (!vulnerabilities[index]) return;
    document.getElementById('scanStatus').textContent = 'EXPLOITING...';
    addAiMsg('ai', '💣 Exploiting ' + (vulnerabilities[index].type || 'unknown').toUpperCase() + ' on ' + (vulnerabilities[index].endpoint || 'target') + '...');
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
// ANONYMITY TOGGLES (with real verification)
// ============================================================
function toggleAnon(type) {
    var states = { proxy: proxyEnabled, tor: torEnabled, vpn: vpnEnabled };
    var newState = !states[type];
    if (type === 'proxy') proxyEnabled = newState;
    if (type === 'tor') torEnabled = newState;
    if (type === 'vpn') vpnEnabled = newState;
    var el = document.getElementById(type + 'Toggle');
    if (el) el.classList.toggle('active', newState);
    
    // Always keep the toggle state — don't revert on errors
    toast(type.toUpperCase() + ' ' + (newState ? 'ON' : 'OFF'), 'info');
    
    fetch('/api/' + type + '/toggle', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ enabled: newState })
    }).then(function(r) { return r.json(); }).then(function(d) {
        // Verify it actually worked
        if (type === 'proxy') {
            fetch('/api/proxy/health').then(function(r){return r.json();}).then(function(h) {
                if (newState && !h.healthy) {
                    toast('⚠️ Proxy enabled but no healthy proxies found', 'warning');
                    addAiMsg('ai', '⚠️ Proxy toggled ON but no working proxies detected. Check your proxy list.');
                } else if (newState) {
                    toast('🟢 Proxy active — ' + h.active_proxies + ' healthy', 'success');
                    addAiMsg('ai', '🟢 Proxy enabled — ' + h.active_proxies + ' healthy proxies. Traffic is being routed.');
                }
            });
        }
        if (type === 'tor') {
            fetch('/api/opsec/tor_verify').then(function(r){return r.json();}).then(function(t) {
                if (newState && !t.tor_active) {
                    toast('⚠️ Tor enabled but circuit not verified', 'warning');
                    addAiMsg('ai', '⚠️ Tor toggled ON but circuit verification failed. Is Tor running?');
                } else if (newState) {
                    toast('🟢 Tor active — Exit: ' + t.exit_ip, 'success');
                    addAiMsg('ai', '🟢 Tor enabled — exit node IP: ' + t.exit_ip);
                }
            });
        }
        if (type === 'vpn') {
            // The toggle endpoint already verified Warp - trust its response
            if (newState && d.protected) {
                toast('🟢 VPN protected — ' + (d.current_ip || ''), 'success');
                addAiMsg('ai', '🟢 VPN enabled and verified — your IP is hidden.');
            } else if (newState && !d.protected) {
                toast('⚠️ VPN toggled ON but ' + (d.reason || 'not verified'), 'warning');
                addAiMsg('ai', '⚠️ VPN toggled ON but protection not verified. Run: warp-cli connect');
            }
        }
        loadSafetyStatus();
    }).catch(function() {
        // Toggle stays ON even if verification fails — user can still use it
        toast('⚠️ ' + type.toUpperCase() + ' toggled ON but verification failed', 'warning');
    });
}

// ============================================================
// BROWSER (real browser behavior)
// ============================================================
var browserCurrentUrl = '';

function resolveUrl(input) {
    input = input.trim();
    if (!input) return null;
    // Already a full URL
    if (input.startsWith('http://') || input.startsWith('https://')) return input;
    // Looks like a domain (contains a dot, no spaces)
    if (/^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(\/.*)?$/.test(input) && !/\s/.test(input)) {
        return 'https://' + input;
    }
    // IP address
    if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(:\d+)?(\/.*)?$/.test(input)) {
        return 'http://' + input;
    }
    // Everything else: treat as search query
    return 'https://duckduckgo.com/?q=' + encodeURIComponent(input);
}

function browserNavigate(url, andScan) {
    if (!url) url = document.getElementById('browserUrl').value.trim();
    if (!url) { toast('Enter a URL or search term', 'error'); return; }
    
    var resolved = resolveUrl(url);
    if (!resolved) { toast('Invalid URL', 'error'); return; }
    
    browserCurrentUrl = resolved;
    document.getElementById('browserUrl').value = resolved;
    
    // Add to history
    if (browserHistoryIndex < browserHistory.length - 1) {
        browserHistory = browserHistory.slice(0, browserHistoryIndex + 1);
    }
    browserHistory.push(resolved);
    browserHistoryIndex = browserHistory.length - 1;
    
    updateBrowserStatus();
    loadBrowserUrl(resolved, andScan);
}

function loadBrowserUrl(url, andScan) {
    var loading = document.getElementById('browserLoading');
    var loadingUrl = document.getElementById('browserLoadingUrl');
    loading.classList.add('show');
    loadingUrl.textContent = url;
    
    // Load URL directly in iframe — no proxying needed.
    // The iframe loads the real site in its own origin, so all JS/CSS/images work.
    var frame = document.getElementById('browserFrame');
    frame.src = url;
    
    // Poll for load completion
    var loadCheck = setInterval(function() {
        try {
            if (frame.contentDocument && frame.contentDocument.readyState === 'complete') {
                clearInterval(loadCheck);
                loading.classList.remove('show');
                updateBrowserStatus(true);
                if (andScan) {
                    document.getElementById('targetInput').value = url;
                    startScan(url);
                }
                toast('Page loaded', 'success');
            }
        } catch(e) {
            // Cross-origin restrictions - assume loaded after timeout
            clearInterval(loadCheck);
            loading.classList.remove('show');
            updateBrowserStatus(true);
            if (andScan) {
                document.getElementById('targetInput').value = url;
                startScan(url);
            }
            toast('Page loaded', 'success');
        }
    }, 500);
    
    // Safety timeout
    setTimeout(function() {
        clearInterval(loadCheck);
        loading.classList.remove('show');
    }, 15000);
}

function browserBack() {
    if (browserHistoryIndex > 0) {
        browserHistoryIndex--;
        var url = browserHistory[browserHistoryIndex];
        document.getElementById('browserUrl').value = url;
        browserCurrentUrl = url;
        loadBrowserUrl(url);
    }
}

function browserForward() {
    if (browserHistoryIndex < browserHistory.length - 1) {
        browserHistoryIndex++;
        var url = browserHistory[browserHistoryIndex];
        document.getElementById('browserUrl').value = url;
        browserCurrentUrl = url;
        loadBrowserUrl(url);
    }
}

function browserRefresh() {
    if (browserCurrentUrl) {
        loadBrowserUrl(browserCurrentUrl);
    }
}

function updateBrowserStatus(success) {
    var el = document.getElementById('browserStatus');
    if (success === true) {
        el.textContent = '🟢 PROXIED';
        el.style.color = '#10b981';
    } else if (success === false) {
        el.textContent = '🔴 ERROR';
        el.style.color = '#ef4444';
    } else {
        el.textContent = '';
    }
}

// ============================================================
// BROWSER ACTION BUTTONS
// ============================================================
function browserAction(action) {
    var url = browserCurrentUrl || document.getElementById('browserUrl').value.trim();
    if (!url) { toast('No URL loaded in browser', 'error'); return; }
    if (!url.startsWith('http')) url = resolveUrl(url);
    
    switch(action) {
        case 'scan':
            document.getElementById('targetInput').value = url;
            addAiMsg('ai', '🔍 Starting scan on ' + url + ' from browser...');
            startScan(url);
            break;
        case 'exploit':
            if (vulnerabilities.length === 0) {
                toast('No vulnerabilities to exploit. Run a scan first.', 'warning');
                addAiMsg('ai', '⚠️ No vulnerabilities loaded. Scan the page first, then exploit.');
                return;
            }
            document.getElementById('targetInput').value = url;
            addAiMsg('ai', '💣 Running exploits on ' + vulnerabilities.length + ' vulnerabilities found on ' + url + '...');
            fetch('/api/exploit', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ scan_id: currentScanId, vulnerabilities: vulnerabilities })
            }).then(function(r) { return r.json(); }).then(function() {
                toast('Exploits launched', 'info');
            });
            break;
        case 'fingerprint':
            addAiMsg('ai', '🖐️ Fingerprinting ' + url + '...');
            fetch('/api/core/fingerprint', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ target: url })
            }).then(function(r) { return r.json(); }).then(function(d) {
                if (d.fingerprint) {
                    var fp = d.fingerprint;
                    var info = '🖥️ **Fingerprint Results:**\n';
                    if (fp.server) info += '• Server: ' + fp.server + '\n';
                    if (fp.language) info += '• Language: ' + fp.language + '\n';
                    if (fp.framework) info += '• Framework: ' + fp.framework + '\n';
                    if (fp.cms) info += '• CMS: ' + fp.cms + '\n';
                    if (fp.waf) info += '• WAF: ' + fp.waf + '\n';
                    if (fp.database) info += '• Database: ' + fp.database + '\n';
                    if (fp.os) info += '• OS: ' + fp.os + '\n';
                    addAiMsg('ai', info);
                    toast('Fingerprint complete', 'success');
                }
            }).catch(function() { toast('Fingerprint failed', 'error'); });
            break;
        case 'analyze':
            addAiMsg('ai', '🤖 Analyzing ' + url + ' for vulnerabilities...');
            fetch('/api/browser/analyze', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ url: url })
            }).then(function(r) { return r.json(); }).then(function(d) {
                if (d.analysis) {
                    addAiMsg('ai', '📊 **Page Analysis:**\n' + d.analysis.replace(/<br>/g, '\n').replace(/<[^>]+>/g, ''));
                    toast('Analysis complete', 'success');
                }
            }).catch(function() { toast('Analysis failed', 'error'); });
            break;
    }
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
        if (d.target) {
            // Restore full context
            document.getElementById('targetInput').value = d.target;
            document.getElementById('browserUrl').value = d.target;
            browserCurrentUrl = d.target;
            browserHistory = [d.target];
            browserHistoryIndex = 0;
            
            // Load the target in browser
            loadBrowserUrl(d.target);
            
            // Show scan metadata in results
            var metaHtml = '<div class="results-summary" style="margin-bottom:10px;">';
            metaHtml += '<strong>📋 Restored Scan:</strong> ' + escapeHtml(d.target) + '<br>';
            metaHtml += '<small>Date: ' + (d.started || '?') + ' | Status: ' + (d.status || '?') + '</small><br>';
            metaHtml += '<span class="sev-badge crit">' + (d.critical || 0) + ' CRIT</span> ';
            metaHtml += '<span class="sev-badge high">' + (d.high || 0) + ' HIGH</span> ';
            metaHtml += '<span class="sev-badge med">' + (d.medium || 0) + ' MED</span> ';
            metaHtml += '<span class="sev-badge low">' + (d.low || 0) + ' LOW</span>';
            metaHtml += '</div>';
            
            if (d.vulns_json) {
                try {
                    var vulns = typeof d.vulns_json === 'string' ? JSON.parse(d.vulns_json) : d.vulns_json;
                    vulnerabilities = vulns;
                    var summary = { critical: d.critical || 0, high: d.high || 0, medium: d.medium || 0, low: d.low || 0 };
                    var panel = document.getElementById('resultsPanel');
                    document.getElementById('vulnCount').textContent = vulns.length;
                    var html = metaHtml;
                    vulns.forEach(function(v, i) {
                        var sev = v.severity || 'low';
                        html += '<div class="vuln-item" onclick="exploitVuln(' + i + ')">';
                        html += '<span class="sev ' + sev + '">' + sev.toUpperCase() + '</span>';
                        html += '<span class="type">' + escapeHtml(v.type || 'UNKNOWN') + '</span>';
                        html += '<span class="endpoint">' + escapeHtml(v.endpoint || '') + '</span>';
                        html += '</div>';
                    });
                    panel.innerHTML = html;
                    switchTab('dashboard');
                    addAiMsg('ai', '📜 Restored scan of ' + d.target + ' — ' + vulns.length + ' vulnerabilities (' + (d.critical||0) + ' critical, ' + (d.high||0) + ' high). Ready to continue where we left off.');
                    toast('Loaded scan: ' + d.target + ' — ' + vulns.length + ' vulns', 'info');
                } catch(e) { toast('Failed to parse', 'error'); }
            }
        }
    });
}

// ============================================================
// LOGS TAB
// ============================================================
function renderLogs() {
    var panel = document.getElementById('logsPanel');
    if (!panel) return;
    
    var searchTerm = '';
    var searchEl = document.getElementById('logSearch');
    if (searchEl) searchTerm = searchEl.value.toLowerCase();
    
    var filtered = allLogs.filter(function(log) {
        if (currentLogFilter !== 'all' && log.level !== currentLogFilter) return false;
        if (searchTerm && log.message && log.message.toLowerCase().indexOf(searchTerm) === -1) return false;
        return true;
    });
    
    if (filtered.length === 0) {
        panel.innerHTML = '<div class="empty">No logs match your filter</div>';
        return;
    }
    
    var html = '';
    filtered.slice(-200).forEach(function(log) {
        var levelClass = log.level || 'info';
        var icon = { info: 'ℹ️', success: '✅', warning: '⚠️', error: '❌', system: '🔺' }[levelClass] || '•';
        html += '<div class="log-entry log-' + levelClass + '">';
        html += '<span class="log-time">' + (log.timestamp || '') + '</span>';
        html += '<span class="log-icon">' + icon + '</span>';
        html += '<span class="log-msg">' + escapeHtml(log.message || '') + '</span>';
        html += '</div>';
    });
    panel.innerHTML = html;
    panel.scrollTop = panel.scrollHeight;
}

function filterLogs(filter) {
    if (filter) {
        currentLogFilter = filter;
        document.querySelectorAll('.log-filter').forEach(function(b) { b.classList.remove('active'); });
        var btn = document.querySelector('.log-filter[data-filter="' + filter + '"]');
        if (btn) btn.classList.add('active');
    }
    renderLogs();
}

// ============================================================
// SAFETY TAB
// ============================================================
function loadSafetyStatus() {
    fetch('/api/opsec/full_report').then(function(r) { return r.json(); }).then(function(d) {
        // Protection status
        var statusBig = document.getElementById('safetyStatusBig');
        var dot = document.getElementById('safetyDot');
        var statusText = document.getElementById('safetyStatusText');
        if (d.status === 'protected') {
            dot.style.background = '#10b981';
            dot.style.boxShadow = '0 0 12px rgba(16,185,129,0.5)';
            statusText.textContent = d.status_text || '🟢 PROTECTED';
            statusText.style.color = '#10b981';
        } else if (d.status === 'partial') {
            dot.style.background = '#f59e0b';
            dot.style.boxShadow = '0 0 12px rgba(245,158,11,0.5)';
            statusText.textContent = d.status_text || '🟡 PARTIALLY PROTECTED';
            statusText.style.color = '#f59e0b';
        } else {
            dot.style.background = '#ef4444';
            dot.style.boxShadow = '0 0 12px rgba(239,68,68,0.5)';
            statusText.textContent = d.status_text || '🔴 EXPOSED';
            statusText.style.color = '#ef4444';
        }
        
        // IP info
        document.getElementById('safetyCurrentIp').textContent = d.current_ip || 'Unknown';
        document.getElementById('safetyRealIp').textContent = d.real_ip || 'Unknown';
        var ipMatch = document.getElementById('safetyIpMatch');
        if (d.ip_match === true) {
            ipMatch.textContent = '⚠️ MATCH — Your real IP is exposed!';
            ipMatch.style.color = '#ef4444';
        } else if (d.ip_match === false) {
            ipMatch.textContent = '✅ HIDDEN — IPs are different';
            ipMatch.style.color = '#10b981';
        } else {
            ipMatch.textContent = '---';
            ipMatch.style.color = '#6b7280';
        }
        
        // Layer status
        var checks = d.checks || {};
        document.getElementById('safetyProxy').textContent = checks.proxy ? '🟢 Active' : '🔴 Inactive';
        document.getElementById('safetyProxy').style.color = checks.proxy ? '#10b981' : '#ef4444';
        document.getElementById('safetyTor').textContent = checks.tor ? '🟢 Active' : '🔴 Inactive';
        document.getElementById('safetyTor').style.color = checks.tor ? '#10b981' : '#ef4444';
        document.getElementById('safetyVpn').textContent = checks.vpn ? '🟢 Active' : '🔴 Inactive';
        document.getElementById('safetyVpn').style.color = checks.vpn ? '#10b981' : '#ef4444';
        document.getElementById('safetyDns').textContent = checks.dns_leak ? '⚠️ LEAKING' : '✅ Secure';
        document.getElementById('safetyDns').style.color = checks.dns_leak ? '#ef4444' : '#10b981';
        document.getElementById('safetyWebrtc').textContent = checks.webrtc_leak ? '⚠️ LEAKING' : '✅ Secure';
        document.getElementById('safetyWebrtc').style.color = checks.webrtc_leak ? '#ef4444' : '#10b981';
        
        // Warnings
        var warningsBody = document.getElementById('safetyWarningsBody');
        var warnings = d.warnings || [];
        if (warnings.length > 0) {
            var wh = '<ul class="warnings-list">';
            warnings.forEach(function(w) { wh += '<li>⚠️ ' + escapeHtml(w) + '</li>'; });
            wh += '</ul>';
            warningsBody.innerHTML = wh;
        } else {
            warningsBody.innerHTML = '<div class="empty" style="color:#10b981;">✅ No warnings — you are secure</div>';
        }
    }).catch(function() {
        document.getElementById('safetyStatusText').textContent = '⚠️ Cannot check status';
    });
}

// ============================================================
// EDITABLE PREVIEW MODALS
// ============================================================
var _previewType = ''; // 'ransomware' or 'deface'
var _previewData = {};

function openPreviewModal(title, html, type, data) {
    _previewType = type || '';
    _previewData = data || {};
    document.getElementById('previewModalTitle').textContent = title;
    document.getElementById('previewEditBtn').style.display = 'inline-block';
    document.getElementById('previewSaveBtn').style.display = 'none';
    document.getElementById('editorPane').style.display = 'none';
    document.getElementById('previewPane').style.display = 'block';
    var frame = document.getElementById('previewModalFrame');
    frame.srcdoc = html;
    document.getElementById('previewModal').classList.add('show');
}

function closePreviewModal() {
    document.getElementById('previewModal').classList.remove('show');
    document.getElementById('previewModalFrame').srcdoc = 'about:blank';
    _previewType = '';
    _previewData = {};
}

function togglePreviewEdit() {
    var editorPane = document.getElementById('editorPane');
    var previewPane = document.getElementById('previewPane');
    var editBtn = document.getElementById('previewEditBtn');
    var saveBtn = document.getElementById('previewSaveBtn');
    
    if (editorPane.style.display === 'none') {
        // Switch to edit mode
        editorPane.style.display = 'block';
        previewPane.style.display = 'none';
        editBtn.style.display = 'none';
        saveBtn.style.display = 'inline-block';
        buildEditorFields();
    } else {
        // Switch back to preview
        editorPane.style.display = 'none';
        previewPane.style.display = 'block';
        editBtn.style.display = 'inline-block';
        saveBtn.style.display = 'none';
    }
}

function buildEditorFields() {
    var fields = document.getElementById('editorFields');
    var html = '';
    
    if (_previewType === 'ransomware') {
        html += '<label>Title</label>';
        html += '<input type="text" id="editRansomTitle" value="' + escapeHtml(_previewData.title || 'YOUR FILES HAVE BEEN ENCRYPTED') + '">';
        html += '<label>Message</label>';
        html += '<textarea id="editRansomMsg" rows="6">' + escapeHtml(_previewData.message || 'All your files have been encrypted.') + '</textarea>';
        html += '<label>Image URL</label>';
        html += '<input type="text" id="editRansomImg" value="' + escapeHtml(_previewData.image_url || '') + '" placeholder="https://i.imgur.com/xxx.png">';
        html += '<label>Group Name</label>';
        html += '<input type="text" id="editRansomGroup" value="' + escapeHtml(_previewData.group_name || 'APEX') + '">';
        html += '<label>Encryption ID</label>';
        html += '<input type="text" id="editRansomEncId" value="' + escapeHtml(_previewData.encryption_id || 'APX-XXXX') + '">';
        html += '<label>File Count</label>';
        html += '<input type="text" id="editRansomFiles" value="' + escapeHtml(_previewData.file_count || '1,247') + '">';
        html += '<label>Total Size</label>';
        html += '<input type="text" id="editRansomSize" value="' + escapeHtml(_previewData.total_size || '45.3 MB') + '">';
    } else if (_previewType === 'deface') {
        html += '<label>Message</label>';
        html += '<textarea id="editDefaceMsg" rows="6">' + escapeHtml(_previewData.message || 'This site has been compromised.') + '</textarea>';
        html += '<label>Image URL</label>';
        html += '<input type="text" id="editDefaceImg" value="' + escapeHtml(_previewData.image_url || '') + '" placeholder="https://i.imgur.com/xxx.png">';
        html += '<label>Target URL</label>';
        html += '<input type="text" id="editDefaceTarget" value="' + escapeHtml(_previewData.target_url || 'https://example.com') + '">';
    }
    
    fields.innerHTML = html;
}

function savePreviewEdits() {
    if (_previewType === 'ransomware') {
        var data = {
            title: document.getElementById('editRansomTitle').value,
            message: document.getElementById('editRansomMsg').value,
            image_url: document.getElementById('editRansomImg').value,
            group_name: document.getElementById('editRansomGroup').value,
            encryption_id: document.getElementById('editRansomEncId').value,
            file_count: document.getElementById('editRansomFiles').value,
            total_size: document.getElementById('editRansomSize').value
        };
        _previewData = data;
        
        fetch('/api/ransomware/preview', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(data)
        }).then(function(r) { return r.json(); }).then(function(d) {
            // Update preview
            document.getElementById('previewModalFrame').srcdoc = d.html;
            // Switch back to preview
            document.getElementById('editorPane').style.display = 'none';
            document.getElementById('previewPane').style.display = 'block';
            document.getElementById('previewEditBtn').style.display = 'inline-block';
            document.getElementById('previewSaveBtn').style.display = 'none';
            toast('Ransomware preview updated', 'success');
        });
    } else if (_previewType === 'deface') {
        var data = {
            message: document.getElementById('editDefaceMsg').value,
            image_url: document.getElementById('editDefaceImg').value,
            target_url: document.getElementById('editDefaceTarget').value
        };
        _previewData = data;
        
        var html = '<!DOCTYPE html><html><head><meta charset="UTF-8"><style>' +
            '*{margin:0;padding:0;box-sizing:border-box;}' +
            'body{background:#0a0a0a;color:#e5e5e5;font-family:\'Courier New\',monospace;display:flex;align-items:center;justify-content:center;min-height:100vh;text-align:center;}' +
            '.deface-card{background:#0f0f0f;border:2px solid #e53935;padding:40px;max-width:600px;box-shadow:0 0 40px rgba(229,57,53,0.3);}' +
            '.deface-title{font-size:36px;font-weight:900;color:#e53935;letter-spacing:6px;text-shadow:0 0 20px rgba(229,57,53,0.5);margin-bottom:20px;}' +
            '.deface-msg{font-size:16px;color:#d4d4d4;line-height:1.8;margin-bottom:20px;}' +
            '.deface-img{max-width:300px;max-height:200px;border:2px solid #e53935;margin:20px 0;}' +
            '.deface-footer{font-size:12px;color:#6b7280;margin-top:20px;}' +
            '</style></head><body><div class="deface-card">' +
            '<div class="deface-title">🔺 HACKED</div>' +
            '<div class="deface-msg">' + escapeHtml(data.message) + '</div>' +
            (data.image_url ? '<img class="deface-img" src="' + escapeHtml(data.image_url) + '" alt="Deface">' : '') +
            '<div class="deface-footer">APEX v3.0 // Security breach detected</div>' +
            '</div></body></html>';
        
        document.getElementById('previewModalFrame').srcdoc = html;
        // Switch back to preview
        document.getElementById('editorPane').style.display = 'none';
        document.getElementById('previewPane').style.display = 'block';
        document.getElementById('previewEditBtn').style.display = 'inline-block';
        document.getElementById('previewSaveBtn').style.display = 'none';
        toast('Deface preview updated', 'success');
    }
}

function previewRansomware() {
    saveRansomSettings();
    var ransom = localStorage.getItem('apex_ransom');
    var data = {};
    if (ransom) { try { data = JSON.parse(ransom); } catch(e) {} }
    
    var payload = {
        title: 'YOUR FILES HAVE BEEN ENCRYPTED',
        message: data.message || 'All your files have been encrypted.',
        image_url: data.image || '',
        group_name: 'APEX',
        encryption_id: 'APX-' + Date.now().toString(36).toUpperCase(),
        file_count: '1,247',
        total_size: '45.3 MB'
    };
    
    fetch('/api/ransomware/preview', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
    }).then(function(r) { return r.json(); }).then(function(d) {
        openPreviewModal('🔒 Ransomware Note Preview', d.html, 'ransomware', payload);
    });
}

function previewDeface() {
    saveDefaceSettings();
    var deface = localStorage.getItem('apex_deface');
    var data = {};
    if (deface) { try { data = JSON.parse(deface); } catch(e) {} }
    
    var payload = {
        message: data.message || 'This site has been compromised.',
        image_url: data.image || '',
        target_url: 'https://example.com'
    };
    
    var html = '<!DOCTYPE html><html><head><meta charset="UTF-8"><style>' +
        '*{margin:0;padding:0;box-sizing:border-box;}' +
        'body{background:#0a0a0a;color:#e5e5e5;font-family:\'Courier New\',monospace;display:flex;align-items:center;justify-content:center;min-height:100vh;text-align:center;}' +
        '.deface-card{background:#0f0f0f;border:2px solid #e53935;padding:40px;max-width:600px;box-shadow:0 0 40px rgba(229,57,53,0.3);}' +
        '.deface-title{font-size:36px;font-weight:900;color:#e53935;letter-spacing:6px;text-shadow:0 0 20px rgba(229,57,53,0.5);margin-bottom:20px;}' +
        '.deface-msg{font-size:16px;color:#d4d4d4;line-height:1.8;margin-bottom:20px;}' +
        '.deface-img{max-width:300px;max-height:200px;border:2px solid #e53935;margin:20px 0;}' +
        '.deface-footer{font-size:12px;color:#6b7280;margin-top:20px;}' +
        '</style></head><body><div class="deface-card">' +
        '<div class="deface-title">🔺 HACKED</div>' +
        '<div class="deface-msg">' + escapeHtml(payload.message) + '</div>' +
        (payload.image_url ? '<img class="deface-img" src="' + escapeHtml(payload.image_url) + '" alt="Deface">' : '') +
        '<div class="deface-footer">APEX v3.0 // Security breach detected</div>' +
        '</div></body></html>';
    
    openPreviewModal('💉 XSS Deface Preview', html, 'deface', payload);
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
// PROXY SETTINGS
// ============================================================
function loadProxySettings() {
    fetch('/api/proxy/health').then(function(r) { return r.json(); }).then(function(d) {
        var statsEl = document.getElementById('proxyStats');
        if (statsEl) {
            statsEl.textContent = 'Total: ' + (d.total || 0) + ' | Healthy: ' + (d.healthy || 0) + ' | Dead: ' + (d.dead || 0);
            statsEl.style.color = (d.healthy || 0) > 0 ? '#10b981' : '#ef4444';
        }
    }).catch(function() {});
}

function saveProxySettings() {
    var proxyFile = document.getElementById('setProxyFile').value.trim() || 'data/proxies.txt';
    var proxyList = document.getElementById('setProxyList').value.trim();
    
    fetch('/api/proxy/settings', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ proxy_file: proxyFile, proxy_list: proxyList })
    }).then(function(r) { return r.json(); }).then(function(d) {
        if (d.success) {
            toast('Proxy settings saved — ' + (d.count || 0) + ' proxies loaded', 'success');
            loadProxySettings();
        } else {
            toast('Error: ' + (d.error || 'Unknown'), 'error');
        }
    }).catch(function() {
        toast('Failed to save proxy settings', 'error');
    });
}

function testProxies() {
    toast('Testing proxies...', 'info');
    fetch('/api/proxy/health').then(function(r) { return r.json(); }).then(function(d) {
        var statsEl = document.getElementById('proxyStats');
        if (statsEl) {
            statsEl.textContent = 'Total: ' + (d.total || 0) + ' | Healthy: ' + (d.healthy || 0) + ' | Dead: ' + (d.dead || 0);
            statsEl.style.color = (d.healthy || 0) > 0 ? '#10b981' : '#ef4444';
        }
        toast('Proxy test complete — ' + (d.healthy || 0) + ' working', d.healthy > 0 ? 'success' : 'warning');
    }).catch(function() {
        toast('Proxy test failed', 'error');
    });
}

// ============================================================
// DASHBOARD SAFETY PANEL
// ============================================================
function loadDashSafety() {
    fetch('/api/opsec/full_report').then(function(r) { return r.json(); }).then(function(d) {
        var checks = d.checks || {};
        // VPN
        var vpnEl = document.getElementById('dashSafetyVpn');
        if (vpnEl) {
            var vpnActive = checks.vpn && checks.vpn.active;
            vpnEl.textContent = vpnActive ? '🟢 Active' : '🔴 Inactive';
            vpnEl.style.color = vpnActive ? '#10b981' : '#ef4444';
        }
        // Tor
        var torEl = document.getElementById('dashSafetyTor');
        if (torEl) {
            var torActive = checks.tor && checks.tor.active;
            torEl.textContent = torActive ? '🟢 Active' : '🔴 Inactive';
            torEl.style.color = torActive ? '#10b981' : '#ef4444';
        }
        // Proxy
        var proxyEl = document.getElementById('dashSafetyProxy');
        if (proxyEl) {
            var proxyActive = checks.proxy && checks.proxy.active;
            proxyEl.textContent = proxyActive ? '🟢 Active' : '🔴 Inactive';
            proxyEl.style.color = proxyActive ? '#10b981' : '#ef4444';
        }
        // DNS
        var dnsEl = document.getElementById('dashSafetyDns');
        if (dnsEl) {
            var dnsActive = checks.dns && checks.dns.active;
            dnsEl.textContent = dnsActive ? '✅ Secure' : '🔴 Vulnerable';
            dnsEl.style.color = dnsActive ? '#10b981' : '#ef4444';
        }
        // Hidden IP (exit IP)
        var ipEl = document.getElementById('dashSafetyIp');
        if (ipEl) ipEl.textContent = d.current_ip || 'Unknown';
        // Real IP
        var realIpEl = document.getElementById('dashSafetyRealIp');
        if (realIpEl) realIpEl.textContent = d.real_ip || 'Unknown';
        // Overall status
        var overallEl = document.getElementById('dashSafetyOverall');
        if (overallEl) {
            overallEl.textContent = d.status_text || '🔴 EXPOSED';
            overallEl.style.color = d.status_color || '#ef4444';
        }
        // Badge
        var badgeEl = document.getElementById('dashSafetyStatus');
        if (badgeEl) {
            var activeLayers = d.layers ? d.layers.length : 0;
            badgeEl.textContent = activeLayers > 0 ? '🟢 ' + activeLayers + ' layer' + (activeLayers > 1 ? 's' : '') : '🔴 None';
            badgeEl.style.color = activeLayers > 0 ? '#10b981' : '#ef4444';
        }
    }).catch(function() {
        // Silently fail on dashboard
    });
}

// ============================================================
// DASHBOARD LIVE LOGS
// ============================================================
function loadDashLogs() {
    var panel = document.getElementById('dashLogsPanel');
    if (!panel) return;
    
    var countEl = document.getElementById('dashLogCount');
    if (countEl) countEl.textContent = allLogs.length;
    
    if (allLogs.length === 0) {
        panel.innerHTML = '<div class="empty">No logs yet. Start a scan to see activity.</div>';
        return;
    }
    
    var html = '';
    allLogs.slice(-50).forEach(function(log) {
        var levelClass = log.level || 'info';
        var icon = { info: 'ℹ️', success: '✅', warning: '⚠️', error: '❌', system: '🔺' }[levelClass] || '•';
        html += '<div class="log-entry log-' + levelClass + '">';
        html += '<span class="log-time">' + (log.timestamp || '') + '</span>';
        html += '<span class="log-icon">' + icon + '</span>';
        html += '<span class="log-msg">' + escapeHtml(log.message || '') + '</span>';
        html += '</div>';
    });
    panel.innerHTML = html;
    panel.scrollTop = panel.scrollHeight;
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
    div.className = 'toast toast-' + (type || 'info');
    div.textContent = message;
    container.appendChild(div);
    setTimeout(function() { div.remove(); }, 3000);
}