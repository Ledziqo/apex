# 🔺 APEX v3.0 — ULTIMATE BUILD PLAN

## Current State (v2.0 — ALREADY BUILT)

### Core Engine
- `modules/core/engine.py` — Adaptive Intelligence (fingerprints 30+ technologies, selects optimal payloads per framework/DB/WAF, learns from responses)
- `modules/core/discovery.py` — Deep Discovery (JS param mining, API endpoint fuzzing, sensitive file discovery, header mining)
- `modules/core/payload_forge.py` — Multi-Vector Payloads (polyglot, context chains, blind confirmation, 9 encoding chains, JWT/GraphQL/NoSQL/XXE/Smuggling payload generators)
- `modules/core/auth_scanner.py` — Auth-Aware Scanner (form login, cookie injection, privilege escalation testing, IDOR detection)
- `modules/core/js_renderer.py` — JS Rendering Engine (headless Chrome via Selenium for SPA crawling)

### Evasion
- `modules/evasion/opsec.py` — OpSec Suite (70+ UAs, jitter, DNS protection, Tor verification, anonymity report, log cleaner)
- `modules/evasion/waf_evasion.py` — WAF Evasion (14 encoding techniques, Cloudflare/AWS/ModSecurity bypasses, parameter pollution, IP spoofing)

### Scanners (19 total)
- `modules/scanners/xss_scanner.py` — XSS (reflected, DOM, context-aware)
- `modules/scanners/sqli_scanner.py` — SQLi (error-based, time-based, boolean-based)
- `modules/scanners/nosqli_scanner.py` — NoSQL Injection (MongoDB, Redis, Firebase)
- `modules/scanners/api_scanner.py` — API Hacking (GraphQL introspection, JWT none-algorithm, Mass Assignment, OpenAPI)
- `modules/scanners/xxe_scanner.py` — XXE Injection (in-band, file read, SSRF via XXE, billion laughs)
- `modules/scanners/prototype_pollution.py` — Prototype Pollution
- `modules/scanners/smuggling_scanner.py` — HTTP Request Smuggling (CL.TE, TE.CL)
- `modules/scanners/oauth_scanner.py` — Open Redirect + OAuth Hijacking
- Plus 11 original scanners in `app.py` (CMDi, LFI, CSRF, SSRF, SSTI, CORS, File Upload, IDOR, JWT)

### Recon
- `modules/recon/admin_panel_finder.py` — 500+ paths, 30-thread concurrent, response fingerprinting
- `modules/recon/sensitive_files.py` — 200+ paths, .git/.env/backups/keys/configs
- `modules/recon/subdomain_enum.py` — Subdomain enumeration
- `modules/recon/port_scanner.py` — Port scanning

### Exploitation
- `modules/exploitation/exploit_chains.py` — Auto chains (XSS→CSRF, SQLi→Admin, SSRF→Cloud, LFI→RCE, Upload→RCE, SSTI→RCE)
- `modules/exploitation/xss_deface.py` — XSS defacement
- `modules/post_exploit/ransomware.py` — Ransomware simulation/execution

### Other Modules
- `modules/c2/beacon.py` — C2 beacon generator
- `modules/bruteforce/login_bruteforce.py` — HTTP/SSH/FTP bruteforce
- `modules/social/phishing_gen.py` — Phishing page generator
- `modules/cloud/aws_azure_gcp.py` — Cloud credential theft
- `modules/windows_ad/credential_dump.py` — Mimikatz/Kerberoast scripts
- `modules/reporting/report_gen.py` — HTML report generation
- `modules/anonymity/vpn_manager.py` — VPN management + kill switch
- `modules/anonymity/proxy_manager.py` — Proxy chain rotation
- `modules/anonymity/tor_manager.py` — Tor SOCKS5 routing
- `modules/anonymity/kill_switch.py` — Firewall kill switch

### Frontend
- `templates/dashboard.html` — 18 tool cards, anonymity report panel, exploit monitor, AI sidebar
- `templates/landing.html` — Login page
- `static/js/app.js` — Full dashboard JS with all tool modals and action functions
- `static/css/style.css` — Dark theme styling

### Backend
- `app.py` — Flask app with 50+ API endpoints, adaptive rate limiting, all scanners wired into `run_full_scan()`
- `config.py` — All configuration (JS render, auth, rate limiting, AI, webhooks)
- `requirements.txt` — All Python dependencies

---

## 🔨 TO BUILD — v3.0 FINAL PHASE (28 items)

### NEW FILES TO CREATE (10)

#### 1. `modules/reporting/poc_generator.py`
Auto-generate proof-of-concept HTML files:
- XSS PoC: Working reflected XSS page with the payload
- CSRF PoC: Auto-submitting form that exploits CSRF
- Open Redirect PoC: Redirect demonstration URL
- Downloadable from vuln table in dashboard

#### 2. `modules/core/ai_strategist.py`
AI Attack Strategist + Vulnerability Chain Predictor:
- Analyzes scan results autonomously
- Decides which vulns to exploit first
- Adapts strategy when payloads get blocked
- Suggests lateral movement paths
- Predicts exploit chains with confidence scores
- "I found SQLi on /login. Exploiting now... Extracted 1,247 user records..."

#### 3. `modules/core/polymorphic_engine.py`
Signature-proof payload mutations:
- Variable names randomized per request
- String obfuscation (XOR, base64, ROT13)
- Junk code injection
- Encoding chain randomization
- No two requests look the same

#### 4. `modules/evasion/stealth_traffic.py`
Human-like traffic patterns:
- Random delays between 0.1s-5s
- Real browser TLS fingerprints
- Randomize request order
- Add random noise requests between attacks
- Looks like a human researcher

#### 5. `modules/evasion/defense_evasion.py`
Auto-adapt to defenses:
- Detect 403/406 → auto-switch to evasion payloads
- Detect rate limiting → auto-throttle
- Detect IP ban → auto-rotate proxy/VPN
- Detect WAF → auto-apply WAF-specific bypasses
- Never stops, just adapts

#### 6. `modules/post_exploit/persistence.py`
Auto-deploy persistence after exploitation:
- Deploy PHP/ASPX web shells
- Add SSH authorized_keys
- Create cron jobs / scheduled tasks
- Install C2 beacon for callback
- Create hidden admin accounts in app database

#### 7. `modules/core/nuke_engine.py`
One-click autonomous kill chain orchestrator:
```
Target URL → Recon → Fingerprint → Scan ALL 19 scanners →
Auto-select critical vulns → Exploit → Deploy persistence →
Dump credentials → Exfiltrate data → Cover tracks → Generate report
```

#### 8. `modules/post_exploit/exfiltrator.py`
Intelligent data exfiltration:
- Find and prioritize: databases, configs, .env, source code, customer data
- Compress, encrypt, chunk into small pieces
- Exfiltrate over DNS, HTTPS, or WebSocket
- Auto-detect best exfiltration path

#### 9. `modules/post_exploit/cleaner.py`
Self-destruct & anti-forensics:
- Clear all logs (auth.log, syslog, access.log, bash history)
- Remove uploaded files and shells
- Wipe command history
- Remove cron jobs and persistence
- One-click "scorched earth"

#### 10. `modules/recon/osint.py`
Target OSINT profiling:
- Employee names/emails from LinkedIn
- Tech stack from job postings
- Subdomains from certificate transparency logs
- Email format detection
- Related domains (subsidiaries, dev/staging)

---

### FILES TO UPGRADE (11)

#### 11. `templates/landing.html`
- Matrix rain canvas animation background
- Terminal typing effect: "APEX v3.0 // Initializing attack surface..."
- Glowing red APEX logo
- Professional dark theme

#### 12. `templates/dashboard.html`
- Tools tab reorganization with category sections (Recon, Injection, API/Web, Exploitation, Utilities)
- Vulnerability donut chart (Chart.js CDN)
- Scan progress timeline (vertical step tracker)
- Dark/light theme toggle button
- NUKE button in topbar
- Batch scan file upload area
- Proxy health indicator dots

#### 13. `static/css/style.css`
- Dark/light theme CSS variables
- Matrix rain animation keyframes
- Scan timeline styles
- Donut chart container styles
- Theme transition animations

#### 14. `static/js/app.js`
- Theme toggle function (localStorage)
- Keyboard shortcut modal (`?` key)
- Chart.js donut chart rendering + real-time updates
- Scan timeline rendering
- NUKE mode function (calls /api/nuke)
- Batch scan file upload + queue
- Proxy health check function
- Curl/HTTP import function
- PoC download buttons on vuln table

#### 15. `app.py`
New endpoints:
- `POST /api/nuke` — Autonomous nuke mode
- `POST /api/scan/batch` — Multi-target batch scanning
- `GET /api/poc/generate` — Generate PoC files
- `GET /api/scan/compare` — Compare two scans
- `GET /api/report/pdf` — Export PDF report
- `POST /api/auth/import_curl` — Import cookies from curl
- `GET /api/proxy/health` — Proxy health check
- CWE auto-tagging on all vuln results
- Per-vuln Discord/Slack webhook notifications
- Import all new modules

#### 16. `modules/anonymity/proxy_manager.py`
- `check_proxy_health()` — Test each proxy against httpbin.org/ip
- Return green/red status for each proxy
- Auto-rotate dead proxies out

#### 17. `modules/core/auth_scanner.py`
- `import_from_curl()` — Parse curl command or raw HTTP request
- Extract cookies, headers, URL
- Auto-configure authenticated session

#### 18. `modules/post_exploit/ransomware.py`
- `auto_trigger_on_rce()` — Automatically deploy ransomware when RCE is achieved
- Integration with nuke engine

#### 19. `modules/reporting/report_gen.py`
- `generate_pdf_report()` — Export scan as PDF using weasyprint
- Professional formatting with cover page

#### 20. `config.py`
New settings:
```python
NUKE_ENABLED = True
BATCH_SCAN_THREADS = 5
THEME = 'dark'  # dark/light
CHART_ENABLED = True
POC_AUTO_GENERATE = True
PER_VULN_WEBHOOK = False
```

#### 21. `requirements.txt`
Add: `weasyprint>=60.0`, `playwright>=1.40.0`

---

## 🧪 TESTING CHECKLIST

After all builds complete, verify:
- [ ] All 19 scanners run without errors
- [ ] All API endpoints return valid JSON
- [ ] Dashboard loads without JS errors
- [ ] All 18 tool modals open and function
- [ ] NUKE mode executes full chain
- [ ] Theme toggle works
- [ ] Keyboard shortcuts work
- [ ] Chart renders correctly
- [ ] PoC files generate and download
- [ ] Batch scan processes multiple targets
- [ ] Proxy health check works
- [ ] PDF export generates valid file
- [ ] Scan comparison shows diffs
- [ ] No import errors on startup
- [ ] Rate limiting activates on 429
- [ ] Auth scanner logs in successfully
- [ ] JS renderer discovers SPA content
- [ ] All error paths have fallbacks

---

## 🚀 HOW TO START THE NEW SESSION

1. Open this file: `BUILD_PLAN.md`
2. Read the "TO BUILD" section
3. Start with new files (items 1-10)
4. Then upgrade existing files (items 11-21)
5. Run testing checklist
6. Fix any bugs found

**Command to start the app for testing:**
```bash
python app.py
```

**The app runs on:** `http://0.0.0.0:80`
**Login:** `Apex@gmail.com` / `Apex2005`