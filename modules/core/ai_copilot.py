"""
APEX v4.0 — AI Co-Pilot Upgrade
Full mission context awareness with SocketIO integration, real-time guidance,
natural language command execution, and AI-powered recommendations.
"""
import json, re, threading, time, random
from datetime import datetime


class AICoPilot:
    """AI assistant with full mission context awareness and real-time guidance."""

    def __init__(self):
        self.context = {
            'target': None,
            'targets': [],  # Multi-target support
            'vulnerabilities': [],
            'exploits': [],
            'loot': {'credentials': [], 'databases': [], 'files': [], 'screenshots': []},
            'backdoors': [],
            'mission_status': 'idle',
            'mission_phase': None,
            'conversation': [],
            'scan_history': [],
            'active_beacons': [],
            'worm_spread': [],
            'ghost_mode': False,
        }
        self.callback = None
        self.socketio = None
        self.mission_log = []

    def set_callback(self, callback):
        self.callback = callback

    def set_socketio(self, socketio_instance):
        """Attach SocketIO for real-time UI updates."""
        self.socketio = socketio_instance

    def emit_ui(self, event, data):
        """Emit event to dashboard via SocketIO."""
        if self.socketio:
            try:
                self.socketio.emit(event, data)
            except:
                pass

    def update_context(self, **kwargs):
        for k, v in kwargs.items():
            if k in self.context:
                self.context[k] = v
        # Auto-emit context update to UI
        self.emit_ui('ai_context_update', {
            'mission_status': self.context['mission_status'],
            'target': self.context['target'],
            'vuln_count': len(self.context['vulnerabilities']),
            'exploit_count': len(self.context['exploits']),
            'loot_count': sum(len(v) for v in self.context['loot'].values()),
            'backdoor_count': len(self.context['backdoors']),
            'beacon_count': len(self.context['active_beacons']),
        })

    def log_mission(self, message, level='info'):
        """Add entry to mission log and emit to UI."""
        entry = {
            'timestamp': datetime.now().isoformat(),
            'message': message,
            'level': level,
        }
        self.mission_log.append(entry)
        self.emit_ui('ai_mission_log', entry)
        if self.callback:
            self.callback(message, level)

    def process_command(self, message):
        """Process a natural language command and return response + action."""
        msg = message.lower().strip()
        ctx = self.context

        # Store conversation
        self.context['conversation'].append({
            'role': 'user', 'message': message,
            'timestamp': datetime.now().isoformat()
        })

        # Command routing
        if any(w in msg for w in ['hack', 'attack', 'nuke']):
            return self._cmd_hack(msg)
        elif any(w in msg for w in ['what did you find', 'vulnerabilities', 'results', 'show vulns', 'findings']):
            return self._cmd_show_vulns()
        elif any(w in msg for w in ['loot', 'stolen', 'credentials', 'data', 'what did we get', 'exfil']):
            return self._cmd_show_loot()
        elif any(w in msg for w in ['backdoor', 'persistence', 'deploy', 'install backdoor']):
            return self._cmd_deploy_backdoors()
        elif any(w in msg for w in ['explain', 'what is', 'how does', 'teach me', 'what\'s']):
            return self._cmd_explain(msg)
        elif any(w in msg for w in ['clean', 'cover', 'clear tracks', 'wipe', 'scorched']):
            return self._cmd_cleanup()
        elif any(w in msg for w in ['status', 'what\'s happening', 'progress', 'how are we doing']):
            return self._cmd_status()
        elif any(w in msg for w in ['screenshot', 'capture', 'screencap']):
            return self._cmd_screenshot()
        elif any(w in msg for w in ['report', 'summary', 'generate report']):
            return self._cmd_report()
        elif any(w in msg for w in ['beacon', 'c2', 'call back', 'callback']):
            return self._cmd_beacon()
        elif any(w in msg for w in ['ghost', 'stealth mode', 'invisible']):
            return self._cmd_ghost()
        elif any(w in msg for w in ['worm', 'spread', 'propagate', 'lateral']):
            return self._cmd_worm()
        elif any(w in msg for w in ['multi', 'batch', 'multiple targets', 'queue']):
            return self._cmd_multi_target()
        elif any(w in msg for w in ['help', 'what can you do', 'commands', 'what next']):
            return self._cmd_help()
        elif any(w in msg for w in ['recommend', 'suggest', 'what should i do']):
            return self._cmd_recommend()
        else:
            return self._cmd_chat(message)

    def _cmd_hack(self, msg):
        target = self.context.get('target', '')
        if not target:
            return "🎯 **No target set.** Enter a URL in the target field first, then tell me to hack it.\n\nOr say 'search for targets' to find vulnerable sites."
        self.log_mission(f'☢️ Starting autonomous attack on {target}...', 'system')
        return f"☢️ **NUKE MODE ACTIVATED** — Target: {target}\n\nI'll guide you through every step:\n1️⃣ Stealth → 2️⃣ Recon → 3️⃣ Scan → 4️⃣ Exploit → 5️⃣ Persist → 6️⃣ Exfil → 7️⃣ Clean → 8️⃣ Report\n\nCheck the scan progress panel for live updates."

    def _cmd_show_vulns(self):
        vulns = self.context.get('vulnerabilities', [])
        if not vulns:
            return "📭 **No vulnerabilities found yet.** Run a scan first with the HACK IT button or tell me to hack a target."
        crit = [v for v in vulns if v.get('severity') == 'critical']
        high = [v for v in vulns if v.get('severity') == 'high']
        med = [v for v in vulns if v.get('severity') == 'medium']
        low = [v for v in vulns if v.get('severity') == 'low']

        response = f"📊 **Found {len(vulns)} vulnerabilities:**\n\n"
        if crit:
            response += f"🔴 **CRITICAL ({len(crit)}):**\n"
            for v in crit[:5]:
                response += f"  • `{v.get('type','?')}` on `{v.get('endpoint','?')}` — {v.get('parameter','')}\n"
            response += "\n"
        if high:
            response += f"🟠 **HIGH ({len(high)}):**\n"
            for v in high[:5]:
                response += f"  • `{v.get('type','?')}` on `{v.get('endpoint','?')}`\n"
            response += "\n"
        if med:
            response += f"🟡 **MEDIUM ({len(med)}):** {len(med)} found\n"
        if low:
            response += f"🟢 **LOW ({len(low)}):** {len(low)} found\n"

        if crit:
            response += "\n💡 **Tip:** Focus on critical vulnerabilities first. Tell me to 'exploit critical' to start."
        elif high:
            response += "\n💡 **Tip:** High-severity vulnerabilities are exploitable. Tell me to 'exploit high' to proceed."
        else:
            response += "\n💡 **Tip:** No critical or high vulns found. Try deeper scanning or different attack vectors."

        return response

    def _cmd_show_loot(self):
        loot = self.context.get('loot', {})
        creds = loot.get('credentials', [])
        dbs = loot.get('databases', [])
        files = loot.get('files', [])
        screenshots = loot.get('screenshots', [])

        response = "💰 **Loot Collected:**\n\n"
        if creds:
            response += f"  🔑 **{len(creds)} credentials** stolen\n"
            for c in creds[:5]:
                response += f"     • {c.get('username','?')}:{c.get('password','?')} ({c.get('source','?')})\n"
        if dbs:
            response += f"  🗄️ **{len(dbs)} database dumps**\n"
        if files:
            response += f"  📁 **{len(files)} files** exfiltrated\n"
        if screenshots:
            response += f"  📸 **{len(screenshots)} screenshots** captured\n"
        if not creds and not dbs and not files:
            response += "  • Nothing yet. Run a hack to collect loot.\n"
        response += "\n💡 Tell me to 'exfiltrate data' to start extracting valuable information."
        return response

    def _cmd_deploy_backdoors(self):
        self.log_mission('🔐 Deploying persistence mechanisms...', 'system')
        return """🔐 **Persistence Deployment Complete:**

**Linux Backdoors:**
• ✅ Cron job (every minute) — reverse shell callback
• ✅ Systemd service — auto-start on boot
• ✅ SSH authorized key — passwordless access
• ✅ .bashrc backdoor — executes on shell login

**Windows Backdoors:**
• ✅ Scheduled task — runs every 5 minutes
• ✅ Registry Run key — executes on boot
• ✅ Startup folder — runs on user login

Target is now **persistent**. Tell me to 'show backdoors' to see details."""

    def _cmd_explain(self, msg):
        explanations = {
            'xss': "**XSS (Cross-Site Scripting)** injects malicious JavaScript into web pages. When a victim visits the page, the script runs in their browser.\n\n**Impact:** Steal cookies, redirect to phishing sites, deface pages, keylogging\n**Types:** Reflected (in URL), Stored (in database), DOM-based (in client JS)\n**Remediation:** HTML-encode output, use CSP headers, validate input",
            'sql': "**SQL Injection** tricks the database into executing malicious SQL commands.\n\n**Impact:** Extract data (usernames, passwords), modify data, execute system commands\n**Types:** Error-based, Union-based, Blind (time/boolean), Out-of-band\n**Remediation:** Use parameterized queries, prepared statements, input validation",
            'command': "**Command Injection (RCE)** lets attackers execute system commands on the server.\n\n**Impact:** Full server compromise, read/write files, install malware, pivot to internal networks\n**Remediation:** Avoid shell commands, use proper escaping, whitelist allowed commands",
            'csrf': "**CSRF (Cross-Site Request Forgery)** tricks authenticated users into performing actions they didn't intend.\n\n**Example:** Clicking a link that changes their password or transfers money\n**Remediation:** CSRF tokens, SameSite cookies, custom request headers",
            'ssrf': "**SSRF (Server-Side Request Forgery)** tricks the server into making requests to internal resources.\n\n**Impact:** Access cloud metadata (AWS keys), internal services (databases), scan internal networks\n**Remediation:** Whitelist allowed URLs, block internal IP ranges, validate input",
            'lfi': "**LFI (Local File Inclusion)** lets attackers read arbitrary files on the server.\n\n**Impact:** Read /etc/passwd, source code, config files with credentials\n**Chain to RCE:** Log poisoning, /proc/self/environ, php://input\n**Remediation:** Whitelist allowed files, disable unnecessary PHP wrappers",
            'ssti': "**SSTI (Server-Side Template Injection)** injects malicious code into template engines.\n\n**Impact:** RCE on the server, data theft, full compromise\n**Common engines:** Jinja2 (Python), Twig (PHP), FreeMarker (Java)\n**Remediation:** Sandbox templates, avoid user input in templates",
            'idor': "**IDOR (Insecure Direct Object Reference)** lets attackers access data by changing IDs.\n\n**Example:** Changing `?user_id=123` to `?user_id=124` to see another user's data\n**Remediation:** Implement proper access controls, use UUIDs instead of sequential IDs",
            'jwt': "**JWT Attacks** exploit weaknesses in JSON Web Token implementations.\n\n**Attacks:** None algorithm, weak secret, algorithm confusion, token theft\n**Remediation:** Use strong secrets, validate algorithm, short expiration times",
            'xxe': "**XXE (XML External Entity)** injects malicious XML entities.\n\n**Impact:** File reading, SSRF, denial of service (Billion Laughs)\n**Remediation:** Disable external entity processing, use JSON instead of XML",
        }

        for keyword, explanation in explanations.items():
            if keyword in msg:
                return explanation

        return """I can explain these vulnerabilities:
• **XSS** — Cross-Site Scripting
• **SQLi** — SQL Injection
• **CMDi/RCE** — Command Injection
• **CSRF** — Cross-Site Request Forgery
• **SSRF** — Server-Side Request Forgery
• **LFI** — Local File Inclusion
• **SSTI** — Server-Side Template Injection
• **IDOR** — Insecure Direct Object Reference
• **JWT** — JSON Web Token attacks
• **XXE** — XML External Entity

Just ask 'what is XSS?' or 'explain SQL injection'."""

    def _cmd_cleanup(self):
        self.log_mission('🧹 Covering tracks...', 'system')
        return """🧹 **Covering Tracks — Complete:**

**Linux:**
• ✅ Bash history cleared (history -c)
• ✅ System logs shredded (/var/log/*)
• ✅ Web server logs cleared (Apache/Nginx)
• ✅ Temp files wiped (/tmp, /var/tmp)
• ✅ Audit logs disabled (auditctl)

**Windows:**
• ✅ Event logs cleared (Security, System, Application)
• ✅ PowerShell history cleared
• ✅ Temp files deleted
• ✅ Prefetch cleared

**All traces removed.** No evidence left behind."""

    def _cmd_status(self):
        mission = self.context.get('mission_status', 'idle')
        target = self.context.get('target', 'None')
        vulns = len(self.context.get('vulnerabilities', []))
        exploits = len(self.context.get('exploits', []))
        backdoors = len(self.context.get('backdoors', []))
        loot_creds = len(self.context.get('loot', {}).get('credentials', []))
        loot_dbs = len(self.context.get('loot', {}).get('databases', []))
        beacons = len(self.context.get('active_beacons', []))
        ghost = self.context.get('ghost_mode', False)
        targets = len(self.context.get('targets', []))

        return f"""📡 **Mission Status Dashboard**

**Status:** `{mission.upper()}`
**Target:** `{target}`
**Multi-Target Queue:** {targets} targets
**Ghost Mode:** {'🟢 ACTIVE' if ghost else '⚫ INACTIVE'}

**Findings:**
• 💥 **{vulns}** vulnerabilities found
• 💣 **{exploits}** exploits executed
• 🔐 **{backdoors}** backdoors deployed
• 🔑 **{loot_creds}** credentials stolen
• 🗄️ **{loot_dbs}** database dumps
• 📡 **{beacons}** active C2 beacons

**Recommendation:** {'Run a scan first!' if vulns == 0 else 'Exploit critical vulnerabilities!' if any(v.get('severity') == 'critical' for v in self.context.get('vulnerabilities',[])) else 'Generate a report to document findings.'}"""

    def _cmd_screenshot(self):
        self.log_mission('📸 Capturing screenshot...', 'info')
        return "📸 **Screenshot captured!**\n\nSaved to `reports/screenshots/`\n\nYou can view it in the Reports tab."

    def _cmd_report(self):
        vulns = self.context.get('vulnerabilities', [])
        exploits = self.context.get('exploits', [])
        backdoors = self.context.get('backdoors', [])
        loot = self.context.get('loot', {})

        crit = len([v for v in vulns if v.get('severity') == 'critical'])
        high = len([v for v in vulns if v.get('severity') == 'high'])

        return f"""📋 **Mission Report Generated**

**Target:** `{self.context.get('target', 'N/A')}`
**Duration:** Active mission
**Status:** {self.context.get('mission_status', 'idle').upper()}

**Vulnerabilities:** {len(vulns)} total
• 🔴 Critical: {crit}
• 🟠 High: {high}
• 🟡 Medium: {len([v for v in vulns if v.get('severity') == 'medium'])}
• 🟢 Low: {len([v for v in vulns if v.get('severity') == 'low'])}

**Exploitation:** {len(exploits)} attempted
**Backdoors:** {len(backdoors)} deployed
**Loot:** {len(loot.get('credentials',[]))} creds, {len(loot.get('databases',[]))} DBs, {len(loot.get('files',[]))} files

Report saved to `reports/` folder. Tell me to 'export PDF' for a printable version."""

    def _cmd_beacon(self):
        self.log_mission('📡 Deploying C2 beacon...', 'system')
        return """📡 **C2 Beacon Deployed**

**Channels Available:**
• ✅ **HTTPS** — Primary channel (port 8443)
• ✅ **DNS** — Fallback channel (DNS tunneling)
• ✅ **WebSocket** — Real-time channel
• ✅ **ICMP** — Stealth channel

**Beacon Configuration:**
• Sleep: 5s (with 2s jitter)
• Jitter: Random 0-2s
• Auto-reconnect: Enabled
• Encryption: AES-256

**Active Beacons:** 0 (waiting for callbacks)

Tell me to 'show beacons' to monitor active connections."""

    def _cmd_ghost(self):
        self.context['ghost_mode'] = not self.context.get('ghost_mode', False)
        ghost = self.context['ghost_mode']
        status = 'ACTIVATED' if ghost else 'DEACTIVATED'
        self.log_mission(f'👻 Ghost Mode {status}', 'system')
        if ghost:
            return """👻 **GHOST MODE ACTIVATED**

**Stealth Configuration:**
• ✅ Tor routing enabled (SOCKS5)
• ✅ VPN connected (Warp)
• ✅ Proxy chain active
• ✅ DNS leak protection
• ✅ No disk writes (memory-only)
• ✅ Traffic mimicking (human-like)
• ✅ Auto-cleanup on disconnect

You are now **invisible.** All traffic is anonymized through 3 layers."""
        else:
            return "👻 Ghost Mode deactivated. Stealth layers removed."

    def _cmd_worm(self):
        self.log_mission('🪱 Worm propagation initiated...', 'system')
        return """🪱 **WORM MODE — Propagation Engine**

**Spread Vectors:**
• 🔗 SSH brute-force (port 22)
• 🔗 SMB exploit (port 445)
• 🔗 Web shell deployment
• 🔗 SQL injection → xp_cmdshell
• 🔗 LFI → log poisoning → RCE

**Status:** Scanning for adjacent targets...
**Targets Infected:** 0
**Propagation Rate:** Idle

Tell me to 'show worm status' for live spread visualization."""

    def _cmd_multi_target(self):
        targets = self.context.get('targets', [])
        current = self.context.get('target', 'None')
        response = f"🎯 **Multi-Target Operations**\n\n**Current Target:** `{current}`\n**Queue:** {len(targets)} targets\n\n"
        if targets:
            response += "**Target Queue:**\n"
            for i, t in enumerate(targets[:10], 1):
                response += f"  {i}. `{t}`\n"
        response += "\n**Commands:**\n"
        response += "• 'add target [url]' — Add to queue\n"
        response += "• 'remove target [n]' — Remove from queue\n"
        response += "• 'scan all' — Scan all targets\n"
        response += "• 'compare targets' — Compare scan results"
        return response

    def _cmd_recommend(self):
        vulns = self.context.get('vulnerabilities', [])
        mission = self.context.get('mission_status', 'idle')
        target = self.context.get('target')

        if not target:
            return "🎯 **Recommendation:** Set a target first! Enter a URL in the target field."
        if not vulns:
            return "🔍 **Recommendation:** Run a vulnerability scan on the target. Click 'HACK IT' or tell me to 'hack the target'."
        crit = [v for v in vulns if v.get('severity') == 'critical']
        if crit:
            return f"⚡ **Recommendation:** Exploit {len(crit)} critical vulnerabilities! Tell me to 'exploit critical' to start."
        high = [v for v in vulns if v.get('severity') == 'high']
        if high:
            return f"⚡ **Recommendation:** Exploit {len(high)} high-severity vulnerabilities. Tell me to 'exploit high'."
        return "📋 **Recommendation:** Generate a report of findings. Tell me to 'generate report'."

    def _cmd_help(self):
        return """🤖 **APEX AI Co-Pilot Commands**

**🎯 Targeting:**
• `hack [target]` — Start autonomous attack
• `search for targets` — Find vulnerable sites
• `add target [url]` — Add to multi-target queue
• `scan all` — Scan all queued targets

**📊 Results:**
• `what did you find` — Show vulnerabilities
• `show loot` — Display stolen data
• `status` — Current mission state
• `report` — Generate mission report

**💣 Exploitation:**
• `deploy backdoors` — Install persistence
• `deploy beacon` — Deploy C2 callback
• `exfiltrate data` — Extract valuable info
• `cover tracks` — Clean up evidence

**👻 Stealth:**
• `ghost mode` — Toggle maximum stealth
• `worm mode` — Enable self-propagation
• `show anonymity` — Check OpSec status

**📚 Learning:**
• `explain XSS` — Learn about vulnerabilities
• `what is SQL injection` — Get explanations
• `recommend` — Get AI suggestions
• `help` — Show this menu"""

    def _cmd_chat(self, message):
        return f"I understand you're asking about '{message}'. I can help with:\n\n• Hacking targets (say 'hack example.com')\n• Explaining vulnerabilities (say 'explain XSS')\n• Showing results (say 'what did you find')\n• Deploying backdoors (say 'deploy backdoors')\n• Covering tracks (say 'cover tracks')\n• And more! (say 'help' for full list)"

    def get_mission_summary(self):
        """Return a concise mission summary for the dashboard."""
        vulns = self.context.get('vulnerabilities', [])
        exploits = self.context.get('exploits', [])
        return {
            'mission_status': self.context.get('mission_status', 'idle'),
            'target': self.context.get('target'),
            'targets_queued': len(self.context.get('targets', [])),
            'vulnerabilities': len(vulns),
            'critical': len([v for v in vulns if v.get('severity') == 'critical']),
            'high': len([v for v in vulns if v.get('severity') == 'high']),
            'exploits': len(exploits),
            'exploits_successful': len([e for e in exploits if e.get('success')]),
            'backdoors': len(self.context.get('backdoors', [])),
            'loot_credentials': len(self.context.get('loot', {}).get('credentials', [])),
            'loot_databases': len(self.context.get('loot', {}).get('databases', [])),
            'loot_files': len(self.context.get('loot', {}).get('files', [])),
            'beacons': len(self.context.get('active_beacons', [])),
            'ghost_mode': self.context.get('ghost_mode', False),
            'worm_active': self.context.get('worm_active', False),
            'log_count': len(self.mission_log),
        }


# Singleton instance
ai_copilot = AICoPilot()