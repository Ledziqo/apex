// ============================================================
// APEX — Dashboard JS v4.0
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
var scanSteps = [];
var browserCollapsed = false;

// Results pagination state
var currentPage = 1;
var pageSize = 25;
var activeSevFilters = { critical: true, high: true, medium: true, low: true };

// ============================================================
// INIT
// ============================================================
document.addEventListener('DOMContentLoaded', function() {
    loadAiSettings();
    loadHistory();
    // Restore browser collapse state
    try {
        var saved = localStorage.getItem('apex_browser_collapsed');
        if (saved === 'true') {
            browserCollapsed = true;
            document.getElementById('browserBody').classList.add('collapsed');
            document.getElementById('browserCollapseBtn').classList.add('collapsed');
        }
    } catch(e) {}
    
    if (socket) {
        socket.on('connect', function() {
            document.getElementById('connDot').style.background = 'var(--green)';
            document.getElementById('connText').textContent = 'ONLINE';
            updateBottomStatusBar();
        });
        socket.on('disconnect', function() {
            document.getElementById('connDot').style.background = 'var(--red)';
            document.getElementById('connText').textContent = 'OFFLINE';
            updateBottomStatusBar();
        });
        socket.on('scan_complete', function(d) {
            vulnerabilities = d.vulnerabilities || [];
            renderResults(d.vulnerabilities, d.summary);
            document.getElementById('scanBtn').disabled = false;
            document.getElementById('nukeBtn').disabled = false;
            document.getElementById('scanStatus').textContent = 'DONE';
            document.getElementById('scanProgressBar').style.width = '100%';
            setTimeout(function() {
                document.getElementById('scanProgressBar').style.width = '0%';
            }, 2000);
            loadHistory();
            toast(vulnerabilities.length + ' vulnerabilities found', 'success');
            aiNarrate('scan_complete', d);
            updateBottomStatusBar();
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
            loadDashLogs();
            aiNarrate('feed', entry);
        });
        socket.on('scan_step', function(step) {
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
    loadSafetyStatus();
    setInterval(loadSafetyStatus, 30000);
    loadDashSafety();
    setInterval(loadDashSafety, 30000);
    loadDashLogs();
    setInterval(loadDashLogs, 5000);
    updateBottomStatusBar();
    setInterval(updateBottomStatusBar, 10000);
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
    document.getElementById('scanProgressBar').style.width = '10%';
    document.getElementById('resultsPanel').innerHTML = '<div class="empty">Scanning ' + escapeHtml(target) + '...<br><small>This may take 30-60 seconds</small></div>';
    vulnerabilities = [];
    addAiMsg('ai', '🔍 Starting scan on ' + target + '... Crawling pages, testing parameters, checking for vulnerabilities.');
    
    if (scanPollInterval) clearInterval(scanPollInterval);
    
    fetch('/api/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target: target, scan_type: 'full' })
    }).then(function(r) { return r.json(); }).then(function(d) {
        currentScanId = d.scan_id;
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
                        document.getElementById('scanProgressBar').style.width = '100%';
                        setTimeout(function() {
                            document.getElementById('scanProgressBar').style.width = '0%';
                        }, 2000);
                        loadHistory();
                        toast(vulnerabilities.length + ' vulnerabilities found', 'success');
                        aiNarrate('scan_complete', {vulnerabilities: vulnerabilities, summary: {critical: crit, high: high, medium: med, low: low}});
                        updateBottomStatusBar();
                    } else if (s.status === 'failed') {
                        clearInterval(scanPollInterval);
                        document.getElementById('scanBtn').disabled = false;
                        document.getElementById('nukeBtn').disabled = false;
                        document.getElementById('scanStatus').textContent = 'FAILED';
                        document.getElementById('scanProgressBar').style.width = '0%';
                        document.getElementById('resultsPanel').innerHTML = '<div class="empty">Scan failed: ' + escapeHtml(s.error || 'Unknown error') + '</div>';
                        toast('Scan failed', 'error');
                    } else {
                        document.getElementById('scanStatus').textContent = 'SCANNING... ' + (s.progress || 0) + '%';
                        document.getElementById('scanProgressBar').style.width = Math.min((s.progress || 0), 95) + '%';
                    }
                });
        }, 2000);
    }).catch(function() {
        document.getElementById('scanBtn').disabled = false;
        document.getElementById('scanStatus').textContent = 'FAILED';
        document.getElementById('scanProgressBar').style.width = '0%';
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
    document.getElementById('scanProgressBar').style.width = '10%';
    addAiMsg('ai', '☢️ NUKE MODE activated on ' + target + ' — full autonomous kill chain in progress.');
    fetch('/api/nuke', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target: target, options: { auto_exploit: true, deploy_persistence: true, exfiltrate_data: true, cover_tracks: true, generate_report: true } })
    }).then(function(r) { return r.json(); }).then(function(d) {
        document.getElementById('nukeBtn').disabled = false;
        document.getElementById('scanBtn').disabled = false;
        document.getElementById('scanStatus').textContent = 'NUKE DONE';
        document.getElementById('scanProgressBar').style.width = '100%';
        setTimeout(function() {
            document.getElementById('scanProgressBar').style.width = '0%';
        }, 2000);
        toast('NUKE complete — ' + (d.vulnerabilities_found || 0) + ' vulns', 'success');
        loadHistory();
        updateBottomStatusBar();
    }).catch(function() {
        document.getElementById('nukeBtn').disabled = false;
        document.getElementById('scanBtn').disabled = false;
        document.getElementById('scanStatus').textContent = 'FAILED';
        document.getElementById('scanProgressBar').style.width = '0%';
        toast('NUKE failed', 'error');
    });
}

// ============================================================
// RESULTS — Table with pagination, filters, export
// ============================================================
function renderResults(vulns, summary) {
    vulnerabilities = vulns || [];
    document.getElementById('vulnCount').textContent = vulnerabilities.length;
    
    var exportBar = document.getElementById('resultsExportBar');
    if (exportBar) exportBar.style.display = vulnerabilities.length > 0 ? 'flex' : 'none';
    
    var sevFilters = document.getElementById('severityFilters');
    if (sevFilters) sevFilters.style.display = vulnerabilities.length > 0 ? 'flex' : 'none';
    
    activeSevFilters = { critical: true, high: true, medium: true, low: true };
    currentPage = 1;
    
    renderFilteredResults();
}

function getFilteredVulns() {
    return vulnerabilities.filter(function(v) {
        var sev = v.severity || 'low';
        return activeSevFilters[sev] === true;
    });
}

function renderFilteredResults() {
    var filtered = getFilteredVulns();
    var panel = document.getElementById('resultsPanel');
    var pagination = document.getElementById('resultsPagination');
    
    if (filtered.length === 0) {
        panel.innerHTML = '<div class="empty">No vulnerabilities match current filters</div>';
        if (pagination) pagination.style.display = 'none';
        return;
    }
    
    var totalPages = Math.ceil(filtered.length / pageSize);
    if (currentPage > totalPages) currentPage = totalPages;
    if (currentPage < 1) currentPage = 1;
    var start = (currentPage - 1) * pageSize;
    var end = Math.min(start + pageSize, filtered.length);
    var pageItems = filtered.slice(start, end);
    
    var html = '<table class="results-table">';
    html += '<thead><tr>';
    html += '<th class="sev-cell">Severity</th>';
    html += '<th class="type-cell">Type</th>';
    html += '<th class="endpoint-cell">Endpoint</th>';
    html += '<th class="param-cell">Parameter</th>';
    html += '<th class="payload-cell">Payload</th>';
    html += '<th class="actions-cell">Actions</th>';
    html += '</tr></thead><tbody>';
    
    pageItems.forEach(function(v, i) {
        var sev = v.severity || 'low';
        var globalIdx = vulnerabilities.indexOf(v);
        html += '<tr onclick="showVulnDetail(' + globalIdx + ')">';
        html += '<td class="sev-cell"><span class="sev-badge ' + sev + '">' + sev.toUpperCase() + '</span></td>';
        html += '<td class="type-cell">' + escapeHtml(v.type || 'UNKNOWN') + '</td>';
        html += '<td class="endpoint-cell" title="' + escapeHtml(v.endpoint || '') + '">' + escapeHtml(v.endpoint || '') + '</td>';
        html += '<td class="param-cell" title="' + escapeHtml(v.parameter || '') + '">' + escapeHtml(v.parameter || '-') + '</td>';
        html += '<td class="payload-cell" title="' + escapeHtml(v.payload || '') + '">' + escapeHtml((v.payload || '').substring(0, 60)) + '</td>';
        html += '<td class="actions-cell">';
        html += '<button class="action-btn" onclick="event.stopPropagation();exploitVuln(' + globalIdx + ')" title="Exploit">💣</button>';
        html += '<button class="action-btn" onclick="event.stopPropagation();downloadPoc(vulnerabilities[' + globalIdx + '])" title="Download PoC">📄</button>';
        html += '<button class="action-btn copy-btn" onclick="event.stopPropagation();copyVulnRow(' + globalIdx + ')" title="Copy">📋</button>';
        html += '</td>';
        html += '</tr>';
    });
    
    html += '</tbody></table>';
    panel.innerHTML = html;
    
    if (totalPages > 1) {
        pagination.style.display = 'flex';
        var phtml = '';
        phtml += '<button class="page-btn" onclick="changePage(1)" ' + (currentPage === 1 ? 'disabled' : '') + '>⏮</button>';
        phtml += '<button class="page-btn" onclick="changePage(' + (currentPage - 1) + ')" ' + (currentPage === 1 ? 'disabled' : '') + '>◀</button>';
        
        var startPage = Math.max(1, currentPage - 2);
        var endPage = Math.min(totalPages, startPage + 4);
        for (var p = startPage; p <= endPage; p++) {
            phtml += '<button class="page-btn' + (p === currentPage ? ' active' : '') + '" onclick="changePage(' + p + ')">' + p + '</button>';
        }
        
        phtml += '<button class="page-btn" onclick="changePage(' + (currentPage + 1) + ')" ' + (currentPage === totalPages ? 'disabled' : '') + '>▶</button>';
        phtml += '<button class="page-btn" onclick="changePage(' + totalPages + ')" ' + (currentPage === totalPages ? 'disabled' : '') + '>⏭</button>';
        phtml += '<span class="page-info">' + start + '-' + end + ' of ' + filtered.length + '</span>';
        pagination.innerHTML = phtml;
    } else {
        pagination.style.display = 'none';
    }
}

function changePage(page) {
    var filtered = getFilteredVulns();
    var totalPages = Math.ceil(filtered.length / pageSize);
    if (page < 1 || page > totalPages) return;
    currentPage = page;
    renderFilteredResults();
}

function toggleSevFilter(sev) {
    activeSevFilters[sev] = !activeSevFilters[sev];
    var chip = document.querySelector('.sev-chip[data-sev="' + sev + '"]');
    if (chip) chip.classList.toggle('active');
    currentPage = 1;
    renderFilteredResults();
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
// VULNERABILITY DETAIL MODAL
// ============================================================
function showVulnDetail(index) {
    var v = vulnerabilities[index];
    if (!v) return;
    
    document.getElementById('vulnDetailTitle').textContent = '💣 ' + (v.type || 'Vulnerability').toUpperCase() + ' — ' + (v.severity || 'low').toUpperCase();
    
    var body = document.getElementById('vulnDetailBody');
    var html = '';
    
    html += '<div class="vuln-detail-field"><label>Severity</label><div class="value"><span class="sev-badge ' + (v.severity || 'low') + '">' + (v.severity || 'low').toUpperCase() + '</span></div></div>';
    html += '<div class="vuln-detail-field"><label>Type</label><div class="value">' + escapeHtml(v.type || 'Unknown') + '</div></div>';
    html += '<div class="vuln-detail-field"><label>Endpoint</label><div class="value">' + escapeHtml(v.endpoint || 'N/A') + '</div></div>';
    html += '<div class="vuln-detail-field"><label>Parameter</label><div class="value">' + escapeHtml(v.parameter || 'N/A') + '</div></div>';
    html += '<div class="vuln-detail-field"><label>Payload</label><div class="value code">' + escapeHtml(v.payload || 'N/A') + '</div></div>';
    if (v.evidence) {
        html += '<div class="vuln-detail-field"><label>Evidence</label><div class="value code">' + escapeHtml(v.evidence) + '</div></div>';
    }
    if (v.remediation) {
        html += '<div class="vuln-detail-field"><label>Remediation</label><div class="value">' + escapeHtml(v.remediation) + '</div></div>';
    }
    if (v.cve) {
        html += '<div class="vuln-detail-field"><label>CVE</label><div class="value">' + escapeHtml(v.cve) + '</div></div>';
    }
    if (v.cvss) {
        html += '<div class="vuln-detail-field"><label>CVSS Score</label><div class="value">' + escapeHtml(v.cvss) + '</div></div>';
    }
    
    body.innerHTML = html;
    
    var actions = document.getElementById('vulnDetailActions');
    actions.innerHTML = '';
    
    var exploitBtn = document.createElement('button');
    exploitBtn.className = 'btn btn-red';
    exploitBtn.innerHTML = '💣 EXPLOIT';
    exploitBtn.onclick = function() { closeVulnDetail(); exploitVuln(index); };
    actions.appendChild(exploitBtn);
    
    var pocBtn = document.createElement('button');
    pocBtn.className = 'btn btn-orange';
    pocBtn.innerHTML = '📄 DOWNLOAD PoC';
    pocBtn.onclick = function() { downloadPoc(v); };
    actions.appendChild(pocBtn);
    
    var copyBtn = document.createElement('button');
    copyBtn.className = 'btn';
    copyBtn.innerHTML = '📋 COPY DETAILS';
    copyBtn.onclick = function() { copyVulnDetails(index); };
    actions.appendChild(copyBtn);
    
    document.getElementById('vulnDetailModal').classList.add('show');
}

function closeVulnDetail() {
    document.getElementById('vulnDetailModal').classList.remove('show');
}

// ============================================================
// COPY & EXPORT
// ============================================================
function copyVulnRow(index) {
    var v = vulnerabilities[index];
    if (!v) return;
    var text = (v.severity || 'low').toUpperCase() + ' | ' + (v.type || 'UNKNOWN') + ' | ' + (v.endpoint || '') + ' | ' + (v.parameter || '') + ' | ' + (v.payload || '');
    copyToClipboard(text);
}

function copyVulnDetails(index) {
    var v = vulnerabilities[index];
    if (!v) return;
    var text = 'Type: ' + (v.type || 'Unknown') + '\nSeverity: ' + (v.severity || 'low') + '\nEndpoint: ' + (v.endpoint || 'N/A') + '\nParameter: ' + (v.parameter || 'N/A') + '\nPayload: ' + (v.payload || 'N/A');
    if (v.evidence) text += '\nEvidence: ' + v.evidence;
    if (v.remediation) text += '\nRemediation: ' + v.remediation;
    copyToClipboard(text);
}

function copyToClipboard(text) {
    if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(text).then(function() {
            showCopyTooltip('✅ Copied!');
        }).catch(function() {
            fallbackCopy(text);
        });
    } else {
        fallbackCopy(text);
    }
}

function fallbackCopy(text) {
    var ta = document.createElement('textarea');
    ta.value = text;
    ta.style.position = 'fixed';
    ta.style.opacity = '0';
    document.body.appendChild(ta);
    ta.select();
    try { document.execCommand('copy'); showCopyTooltip('✅ Copied!'); } catch(e) {}
    document.body.removeChild(ta);
}

function showCopyTooltip(text) {
    var el = document.createElement('div');
    el.className = 'copy-tooltip';
    el.textContent = text;
    el.style.top = '50%';
    el.style.left = '50%';
    el.style.transform = 'translate(-50%, -50%)';
    document.body.appendChild(el);
    setTimeout(function() { el.remove(); }, 1500);
}

function exportResultsCSV() {
    if (vulnerabilities.length === 0) { toast('No results to export', 'warning'); return; }
    var csv = 'Severity,Type,Endpoint,Parameter,Payload,Evidence\n';
    vulnerabilities.forEach(function(v) {
        csv += (v.severity || 'low') + ',' + 
               '"' + (v.type || '') + '",' + 
               '"' + (v.endpoint || '') + '",' + 
               '"' + (v.parameter || '') + '",' + 
               '"' + (v.payload || '').replace(/"/g, '""') + '",' + 
               '"' + (v.evidence || '').replace(/"/g, '""') + '"\n';
    });
    downloadFile(csv, 'apex_results.csv', 'text/csv');
    toast('CSV exported', 'success');
}

function exportResultsJSON() {
    if (vulnerabilities.length === 0) { toast('No results to export', 'warning'); return; }
    var json = JSON.stringify(vulnerabilities, null, 2);
    downloadFile(json, 'apex_results.json', 'application/json');
    toast('JSON exported', 'success');
}

function downloadFile(content, filename, mimeType) {
    var blob = new Blob([content], { type: mimeType });
    var url = URL.createObjectURL(blob);
    var a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
}

// ============================================================
// TARGET INPUT HISTORY
// ============================================================
function showTargetHistory() {
    fetch('/api/history').then(function(r) { return r.json(); }).then(function(data) {
        var dropdown = document.getElementById('targetHistoryDropdown');
        if (!data || data.length === 0) {
            dropdown.classList.remove('show');
            return;
        }
        var html = '';
        data.slice(0, 10).forEach(function(h, idx) {
            var safeUrl = (h.target || '').replace(/'/g, "\\'").replace(/"/g, '"');
            html += '<div class="target-history-item" data-url="' + safeUrl + '">' + escapeHtml(h.target || '') + '</div>';
        });
        dropdown.innerHTML = html;
        dropdown.querySelectorAll('.target-history-item').forEach(function(el) {
            el.addEventListener('click', function() {
                selectTargetHistory(el.getAttribute('data-url'));
            });
        });
        dropdown.classList.add('show');
    }).catch(function() {});
}

function hideTargetHistory() {
    setTimeout(function() {
        var dropdown = document.getElementById('targetHistoryDropdown');
        if (dropdown) dropdown.classList.remove('show');
    }, 200);
}

function selectTargetHistory(url) {
    document.getElementById('targetInput').value = url;
    var dropdown = document.getElementById('targetHistoryDropdown');
    if (dropdown) dropdown.classList.remove('show');
}

// ============================================================
// BROWSER COLLAPSE
// ============================================================
function toggleBrowser() {
    browserCollapsed = !browserCollapsed;
    var body = document.getElementById('browserBody');
    var btn = document.getElementById('browserCollapseBtn');
    if (browserCollapsed) {
        body.classList.add('collapsed');
        btn.classList.add('collapsed');
    } else {
        body.classList.remove('collapsed');
        btn.classList.remove('collapsed');
    }
    try { localStorage.setItem('apex_browser_collapsed', browserCollapsed ? 'true' : 'false'); } catch(e) {}
}

// ============================================================
// ANONYMITY TOGGLES — Now in Safety Card
// ============================================================
function toggleAnon(type) {
    var states = { proxy: proxyEnabled, tor: torEnabled, vpn: vpnEnabled };
    var newState = !states[type];
    if (type === 'proxy') proxyEnabled = newState;
    if (type === 'tor') torEnabled = newState;
    if (type === 'vpn') vpnEnabled = newState;
    
    // Update the safety card toggle button
    var el = document.getElementById(type + 'Toggle');
    if (el) {
        el.classList.toggle('active', newState);
        el.textContent = newState ? 'ON' : 'OFF';
    }
    
    // Also update the topbar toggle if it exists (for backward compat)
    var topbarEl = document.querySelector('.topbar #' + type + 'Toggle');
    if (topbarEl) topbarEl.classList.toggle('active', newState);
    
    toast(type.toUpperCase() + ' ' + (newState ? 'ON' : 'OFF'), 'info');
    
    fetch('/api/' + type + '/toggle', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ enabled: newState })
    }).then(function(r) { return r.json(); }).then(function(d) {
        if (type === 'proxy') {
            fetch('/api/proxy/health').then(function(r){return r.json();}).then(function(h) {
                // Only warn if proxies ARE loaded but none are healthy
                if (newState && h.total > 0 && !h.healthy) {
                    toast('⚠️ Proxy enabled but no healthy proxies found', 'warning');
                    addAiMsg('ai', '⚠️ Proxy toggled ON but no working proxies detected. Check your proxy list.');
                } else if (newState && h.healthy > 0) {
                    toast('🟢 Proxy active — ' + h.healthy + ' healthy', 'success');
                    addAiMsg('ai', '🟢 Proxy enabled — ' + h.healthy + ' healthy proxies. Traffic is being routed.');
                } else if (newState && h.total === 0) {
                    toast('ℹ️ Proxy toggled ON — no proxies loaded yet. Add proxies in Settings.', 'info');
                    addAiMsg('ai', 'ℹ️ Proxy toggled ON but no proxies loaded. Add proxy list in Settings.');
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
            if (newState && d.protected) {
                toast('🟢 VPN protected — ' + (d.current_ip || ''), 'success');
                addAiMsg('ai', '🟢 VPN enabled and verified — your IP is hidden.');
            } else if (newState && !d.protected) {
                toast('⚠️ VPN toggled ON but ' + (d.reason || 'not verified'), 'warning');
                addAiMsg('ai', '⚠️ VPN toggled ON but protection not verified. Run: warp-cli connect');
            }
        }
        loadSafetyStatus();
        loadDashSafety();
        updateBottomStatusBar();
    }).catch(function() {
        toast('⚠️ ' + type.toUpperCase() + ' toggled ON but verification failed', 'warning');
    });
}

// ============================================================
// BROWSER
// ============================================================
var browserCurrentUrl = '';

function resolveUrl(input) {
    input = input.trim();
    if (!input) return null;
    if (input.startsWith('http://') || input.startsWith('https://')) return input;
    if (/^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(\/.*)?$/.test(input) && !/\s/.test(input)) {
        return 'https://' + input;
    }
    if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(:\d+)?(\/.*)?$/.test(input)) {
        return 'http://' + input;
    }
    return 'https://duckduckgo.com/?q=' + encodeURIComponent(input);
}

function browserNavigate(url, andScan) {
    if (!url) url = document.getElementById('browserUrl').value.trim();
    if (!url) { toast('Enter a URL or search term', 'error'); return; }
    
    var resolved = resolveUrl(url);
    if (!resolved) { toast('Invalid URL', 'error'); return; }
    
    browserCurrentUrl = resolved;
    document.getElementById('browserUrl').value = resolved;
    
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
    
    var frame = document.getElementById('browserFrame');
    frame.src = url;
    
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
            document.getElementById('targetInput').value = d.target;
            document.getElementById('browserUrl').value = d.target;
            browserCurrentUrl = d.target;
            browserHistory = [d.target];
            browserHistoryIndex = 0;
            
            loadBrowserUrl(d.target);
            
            if (d.vulns_json) {
                try {
                    var vulns = typeof d.vulns_json === 'string' ? JSON.parse(d.vulns_json) : d.vulns_json;
                    vulnerabilities = vulns;
                    var summary = { critical: d.critical || 0, high: d.high || 0, medium: d.medium || 0, low: d.low || 0 };
                    renderResults(vulns, summary);
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
var _previewType = '';
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
        editorPane.style.display = 'block';
        previewPane.style.display = 'none';
        editBtn.style.display = 'none';
        saveBtn.style.display = 'inline-block';
        buildEditorFields();
    } else {
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
            document.getElementById('previewModalFrame').srcdoc = d.html;
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
// HACK IT
// ============================================================
function hackIt() {
    var target = document.getElementById('targetInput').value.trim();
    if (!target) { toast('Enter a target URL', 'error'); return; }
    if (!target.startsWith('http')) target = 'https://' + target;
    document.getElementById('targetInput').value = target;
    
    var btn = document.getElementById('hackItBtn');
    btn.disabled = true;
    btn.textContent = '⏳ HACKING...';
    document.getElementById('scanBtn').disabled = true;
    document.getElementById('nukeBtn').disabled = true;
    document.getElementById('scanStatus').textContent = 'HACKING...';
    document.getElementById('scanProgressBar').style.width = '10%';
    
    addAiMsg('ai', '☢️ HACK IT initiated on ' + target + ' — full autonomous attack chain running...');
    toast('☢️ HACK IT initiated on ' + target, 'info');
    
    fetch('/api/autopilot/hack', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target: target, options: { auto_exploit: true, deploy_persistence: true, exfiltrate_data: true, cover_tracks: true } })
    }).then(function(r) { return r.json(); }).then(function(d) {
        if (d.status === 'started') {
            addAiMsg('ai', '✅ HACK IT mission launched — monitoring live feed for results...');
            var statusInterval = setInterval(function() {
                fetch('/api/autopilot/status')
                    .then(function(r) { return r.json(); })
                    .then(function(s) {
                        if (s.mission && s.mission.status === 'completed') {
                            clearInterval(statusInterval);
                            btn.disabled = false;
                            btn.textContent = '☢️ HACK IT';
                            document.getElementById('scanBtn').disabled = false;
                            document.getElementById('nukeBtn').disabled = false;
                            document.getElementById('scanStatus').textContent = 'HACK COMPLETE';
                            document.getElementById('scanProgressBar').style.width = '100%';
                            setTimeout(function() {
                                document.getElementById('scanProgressBar').style.width = '0%';
                            }, 2000);
                            var summary = s.mission.summary || {};
                            addAiMsg('ai', '🏁 MISSION COMPLETE! Found ' + (summary.vulnerabilities_found || 0) + ' vulns, exploited ' + (summary.exploits_succeeded || 0) + ', deployed ' + (summary.backdoors_deployed || 0) + ' backdoors, stole ' + (summary.records_stolen || 0) + ' records.');
                            toast('🏁 HACK IT complete!', 'success');
                            updateBottomStatusBar();
                        } else if (s.mission && s.mission.status === 'failed') {
                            clearInterval(statusInterval);
                            btn.disabled = false;
                            btn.textContent = '☢️ HACK IT';
                            document.getElementById('scanBtn').disabled = false;
                            document.getElementById('nukeBtn').disabled = false;
                            document.getElementById('scanStatus').textContent = 'FAILED';
                            document.getElementById('scanProgressBar').style.width = '0%';
                            addAiMsg('ai', '❌ HACK IT failed: ' + (s.mission.error || 'Unknown error'));
                            toast('HACK IT failed', 'error');
                        } else if (s.mission && s.mission.progress) {
                            document.getElementById('scanProgressBar').style.width = Math.min(s.mission.progress, 95) + '%';
                        }
                    });
            }, 3000);
        } else {
            btn.disabled = false;
            btn.textContent = '☢️ HACK IT';
            document.getElementById('scanBtn').disabled = false;
            document.getElementById('nukeBtn').disabled = false;
            toast('HACK IT failed to start', 'error');
        }
    }).catch(function() {
        btn.disabled = false;
        btn.textContent = '☢️ HACK IT';
        document.getElementById('scanBtn').disabled = false;
        document.getElementById('nukeBtn').disabled = false;
        toast('HACK IT request failed', 'error');
    });
}

// ============================================================
// CONNECT WARP
// ============================================================
function connectWarp() {
    var btn = document.getElementById('connectWarpBtn');
    btn.disabled = true;
    btn.textContent = '⏳ CONNECTING...';
    toast('Connecting to Cloudflare Warp...', 'info');
    fetch('/api/vpn/connect', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' }
    }).then(function(r) { return r.json(); }).then(function(d) {
        btn.disabled = false;
        if (d.success) {
            btn.textContent = '✅ CONNECTED';
            toast('🟢 Warp connected — ' + (d.ip || ''), 'success');
            addAiMsg('ai', '🟢 Warp VPN connected — IP: ' + (d.ip || '?'));
            vpnEnabled = true;
            var vpnToggle = document.getElementById('vpnToggle');
            if (vpnToggle) {
                vpnToggle.classList.add('active');
                vpnToggle.textContent = 'ON';
            }
            loadSafetyStatus();
            loadDashSafety();
            updateBottomStatusBar();
        } else {
            btn.textContent = '🛡️ WARP';
            toast('🔴 Warp connect failed: ' + (d.message || 'Unknown'), 'error');
            addAiMsg('ai', '🔴 Warp connection failed: ' + (d.message || 'Unknown'));
        }
    }).catch(function() {
        btn.disabled = false;
        btn.textContent = '🛡️ WARP';
        toast('Warp connection request failed', 'error');
    });
}

// ============================================================
// FETCH PROXIES FROM GITHUB
// ============================================================
function fetchProxiesFromGithub() {
    var proxyType = document.getElementById('proxyGithubType').value;
    var resultEl = document.getElementById('proxyFetchResult');
    resultEl.textContent = '⏳ Fetching ' + proxyType + ' proxies from GitHub...';
    resultEl.style.color = '#f59e0b';
    toast('Fetching ' + proxyType + ' proxies from GitHub...', 'info');
    fetch('/api/proxy/fetch_github', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ proxy_type: proxyType, replace: true })
    }).then(function(r) { return r.json(); }).then(function(d) {
        if (d.success) {
            resultEl.textContent = '✅ Fetched ' + d.count + ' proxies (' + d.mode + ' mode) — ' + d.total + ' total loaded';
            resultEl.style.color = '#10b981';
            toast('✅ ' + d.count + ' proxies fetched from GitHub', 'success');
            addAiMsg('ai', '📥 Fetched ' + d.count + ' ' + proxyType + ' proxies from proxifly GitHub repo (' + d.mode + ' mode). ' + d.total + ' proxies loaded.');
            loadProxySettings();
        } else {
            resultEl.textContent = '❌ Failed: ' + (d.error || 'Unknown error');
            resultEl.style.color = '#ef4444';
            toast('GitHub proxy fetch failed', 'error');
        }
    }).catch(function() {
        resultEl.textContent = '❌ Network error fetching proxies';
        resultEl.style.color = '#ef4444';
        toast('GitHub proxy fetch network error', 'error');
    });
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
// DASHBOARD SAFETY PANEL — Compact Card
// ============================================================
function loadDashSafety() {
    fetch('/api/opsec/full_report').then(function(r) { return r.json(); }).then(function(d) {
        var checks = d.checks || {};
        
        // VPN
        var vpnActive = checks.vpn && checks.vpn.active;
        var vpnDot = document.getElementById('dashSafetyVpnDot');
        if (vpnDot) {
            vpnDot.className = 'safety-compact-dot ' + (vpnActive ? 'active' : 'inactive');
        }
        
        // Tor
        var torActive = checks.tor && checks.tor.active;
        var torDot = document.getElementById('dashSafetyTorDot');
        if (torDot) {
            torDot.className = 'safety-compact-dot ' + (torActive ? 'active' : 'inactive');
        }
        
        // Proxy
        var proxyActive = checks.proxy && checks.proxy.active;
        var proxyDot = document.getElementById('dashSafetyProxyDot');
        if (proxyDot) {
            proxyDot.className = 'safety-compact-dot ' + (proxyActive ? 'active' : 'inactive');
        }
        
        // Hidden IP — show the actual exit IP so user can verify it's really working
        var ipEl = document.getElementById('dashSafetyHiddenIp');
        if (ipEl) {
            ipEl.textContent = d.current_ip || '---';
        }
        
        // Badge
        var badgeEl = document.getElementById('dashSafetyStatus');
        if (badgeEl) {
            var activeLayers = 0;
            if (vpnActive) activeLayers++;
            if (torActive) activeLayers++;
            if (proxyActive) activeLayers++;
            badgeEl.textContent = activeLayers > 0 ? '🟢 ' + activeLayers + ' layer' + (activeLayers > 1 ? 's' : '') : '🔴 None';
            badgeEl.style.color = activeLayers > 0 ? '#10b981' : '#ef4444';
        }
        
        // Sync toggle button states with actual backend state
        var vpnToggle = document.getElementById('vpnToggle');
        if (vpnToggle) {
            vpnToggle.classList.toggle('active', vpnActive);
            vpnToggle.textContent = vpnActive ? 'ON' : 'OFF';
        }
        var torToggle = document.getElementById('torToggle');
        if (torToggle) {
            torToggle.classList.toggle('active', torActive);
            torToggle.textContent = torActive ? 'ON' : 'OFF';
        }
        var proxyToggle = document.getElementById('proxyToggle');
        if (proxyToggle) {
            proxyToggle.classList.toggle('active', proxyActive);
            proxyToggle.textContent = proxyActive ? 'ON' : 'OFF';
        }
        
        // Sync state variables
        vpnEnabled = vpnActive;
        torEnabled = torActive;
        proxyEnabled = proxyActive;
    }).catch(function() {});
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
// BOTTOM STATUS BAR
// ============================================================
function updateBottomStatusBar() {
    var connDot = document.getElementById('bottomConnDot');
    var connText = document.getElementById('bottomConnText');
    if (connDot) {
        var isOnline = document.getElementById('connText').textContent === 'ONLINE';
        connDot.className = 'bottom-status-dot ' + (isOnline ? 'online' : 'offline');
    }
    if (connText) {
        connText.textContent = document.getElementById('connText').textContent;
    }
    
    var layersEl = document.getElementById('bottomLayers');
    if (layersEl) {
        var count = 0;
        if (proxyEnabled) count++;
        if (torEnabled) count++;
        if (vpnEnabled) count++;
        layersEl.textContent = count + ' layer' + (count !== 1 ? 's' : '');
    }
    
    var lastScanEl = document.getElementById('bottomLastScan');
    if (lastScanEl && vulnerabilities.length > 0) {
        lastScanEl.textContent = vulnerabilities.length + ' vulns found';
    }
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

// ============================================================
// THEME TOGGLE
// ============================================================
function toggleTheme() {
    var current = localStorage.getItem('apex_theme') || 'dark';
    var next = current === 'dark' ? 'light' : 'dark';
    setTheme(next);
}

function setTheme(theme) {
    document.documentElement.setAttribute('data-theme', theme);
    localStorage.setItem('apex_theme', theme);
    var btn = document.getElementById('themeToggleBtn');
    if (btn) btn.textContent = theme === 'dark' ? '🌙' : '☀️';
}

(function() {
    var saved = localStorage.getItem('apex_theme') || 'dark';
    setTheme(saved);
})();

// ============================================================
// GHOST MODE TOGGLE
// ============================================================
function toggleGhostMode() {
    var toggle = document.getElementById('ghostToggle');
    if (!toggle) return;
    
    var isActive = toggle.classList.contains('active');
    var url = isActive ? '/api/ghost/deactivate' : '/api/ghost/activate';
    
    fetch(url, { method: 'POST' })
        .then(function(r) { return r.json(); })
        .then(function(d) {
            if (d.status === 'activated' || d.status === 'deactivated') {
                toggle.classList.toggle('active');
                toast('Ghost Mode ' + d.status.toUpperCase(), d.status === 'activated' ? 'success' : 'info');
                addAiMsg('ai', '👻 Ghost Mode ' + d.status.toUpperCase() + ' — ' + d.layers_active + '/' + d.layers_total + ' stealth layers active');
            }
        })
        .catch(function() {
            toggle.classList.toggle('active');
            toast('Ghost Mode toggled (local)', 'info');
        });
}

// ============================================================
// WORM MODE TOGGLE
// ============================================================
function toggleWormMode() {
    var toggle = document.getElementById('wormToggle');
    if (!toggle) return;
    
    var isActive = toggle.classList.contains('active');
    var url = isActive ? '/api/worm/deactivate' : '/api/worm/activate';
    var target = document.getElementById('targetInput').value.trim() || 'https://example.com';
    var body = isActive ? {} : { targets: [target], max_depth: 2, max_hosts: 20, stealth: true };
    
    fetch(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body)
    })
    .then(function(r) { return r.json(); })
    .then(function(d) {
        if (d.status === 'worm_active' || d.status === 'deactivated') {
            toggle.classList.toggle('active');
            toast('🧬 Worm Mode ' + (d.status === 'worm_active' ? 'ACTIVATED' : 'DEACTIVATED'), d.status === 'worm_active' ? 'warning' : 'info');
            addAiMsg('ai', '🧬 Worm Mode ' + (d.status === 'worm_active' ? 'ACTIVATED — propagating from ' + target : 'DEACTIVATED'));
        } else if (d.error) {
            toast('Worm: ' + d.error, 'error');
        }
    })
    .catch(function() {
        toggle.classList.toggle('active');
        toast('Worm mode toggled (local)', 'info');
    });
}

// ============================================================
// PROXY HEALTH CHECK
// ============================================================
function loadProxyHealth() {
    fetch('/api/proxy/health')
        .then(function(r) { return r.json(); })
        .then(function(d) {
            var countEl = document.getElementById('proxyHealthCount');
            var bodyEl = document.getElementById('proxyHealthBody');
            if (countEl) countEl.textContent = (d.healthy || 0) + '/' + (d.total || 0);
            if (!bodyEl) return;
            
            if (!d.proxies || d.proxies.length === 0) {
                bodyEl.innerHTML = '<div class="empty">No proxies loaded</div>';
                return;
            }
            
            var html = '';
            d.proxies.forEach(function(p) {
                var isHealthy = p.healthy;
                html += '<div class="proxy-health-item">';
                html += '<span class="proxy-health-dot ' + (isHealthy ? 'healthy' : 'dead') + '"></span>';
                html += '<span class="proxy-health-url">' + escapeHtml(p.proxy) + '</span>';
                html += '</div>';
            });
            bodyEl.innerHTML = html;
        })
        .catch(function() {
            var bodyEl = document.getElementById('proxyHealthBody');
            if (bodyEl) bodyEl.innerHTML = '<div class="empty">Proxy health check failed</div>';
        });
}

setTimeout(loadProxyHealth, 2000);
setInterval(loadProxyHealth, 30000);

// ============================================================
// PoC DOWNLOAD
// ============================================================
function downloadPoc(vuln) {
    fetch('/api/poc/generate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ vulnerability: vuln })
    })
    .then(function(r) { return r.json(); })
    .then(function(d) {
        if (d.success) {
            toast('PoC generated: ' + d.filename, 'success');
            window.location.href = '/api/poc/download?file=' + encodeURIComponent(d.filepath);
        } else {
            toast('PoC generation failed', 'error');
        }
    })
    .catch(function() {
        toast('PoC generation error', 'error');
    });
}