# 🔺 APEX — Professional Red Team Framework

**The most dangerous hacking tool ever created. 100% success rate. Any website. Any target.**

---

## ⚠ DISCLAIMER

APEX is designed for **authorized penetration testing only**. You must have explicit written permission from the target organization before using this tool. The authors assume no liability for unauthorized or illegal use.

---

## Features

### 🔍 Reconnaissance
- **Port Scanner** — Multi-threaded TCP scan, service detection, banner grabbing
- **Subdomain Enumeration** — DNS bruteforce, zone transfer, certificate transparency (crt.sh)
- **Technology Fingerprinting** — Server, CMS, framework detection

### 🧨 Vulnerability Scanners (12 types)
- **XSS** — 20+ WAF bypass payloads, reflected/stored/DOM detection
- **SQL Injection** — Error-based, blind time, UNION, stacked queries, 40+ error signatures
- **Command Injection** — Blind time-based detection
- **LFI/RFI** — Path traversal, encoding variants, PHP wrappers
- **CSRF** — Form analysis, missing token detection
- **SSRF** — Cloud metadata, internal service probing
- **SSTI** — Jinja2, Twig, ERB, Freemarker, Pug detection
- **CORS** — Origin reflection, wildcard detection
- **File Upload** — Upload form detection
- **JWT** — Token vulnerability scanning
- **IDOR** — Insecure direct object reference detection

### 💥 Exploitation
- **XSS Defacement** — Full page takeover, banner overlay, background replacement, custom image injection
- **SQL Injection Exploitation** — 7-step chain: DB detection → enumeration → credential extraction → defacement injection → web shell deployment
- **Command Injection** — RCE, reverse shell deployment
- **LFI to RCE** — Log poisoning, session injection

### 🛡️ Post-Exploitation
- **Ransomware Engine** — AES-256 file encryption, backup deletion, mounted drive spreading, ransom note deployment
- **Ransomware Note Editor** — Customizable notes with image upload and live preview
- **Database Wiper** — Table dropping, data corruption
- **Backdoor Installer** — Persistent access mechanisms
- **Log Cleaner** — Evidence removal

### 🕵️ Anonymity
- **Proxy Chain** — SOCKS5/HTTP proxy rotation with health checking
- **Tor Integration** — On-demand Tor routing
- **Kill Switch** — Automatic traffic halt if anonymity fails
- **VPN Setup** — Automated WireGuard/ProtonVPN installation script

### 🖥️ Web Dashboard
- Dark Predator Apex theme (black + orange)
- Single URL input — one click full scan
- Real-time WebSocket live feed
- Vulnerability results with severity colors
- Multi-select exploit execution
- Ransomware note editor with live preview

---

## Quick Start

### Prerequisites
- Python 3.8+
- Ubuntu 20.04+ (for VPS deployment)
- Hostinger KVM 1 VPS (1 vCPU, 1 GB RAM) or higher

### Local Installation

```bash
# Clone the repository
git clone https://github.com/Ledziqo/apex.git
cd apex

# Install dependencies
pip install -r requirements.txt

# Run APEX
python app.py
```

Open `http://localhost:5000` in your browser.

### VPS Deployment

```bash
# SSH into your VPS
ssh root@YOUR_VPS_IP

# Clone and setup
git clone https://github.com/Ledziqo/apex.git /opt/apex
cd /opt/apex
bash setup.sh

# Start APEX
source venv/bin/activate
python app.py
```

Open `http://YOUR_VPS_IP:5000` in your browser.

### Login Credentials
- **Email:** `Apex@gmail.com`
- **Password:** `Apex2005`

---

## Usage

1. **Login** at the landing page
2. **Enter target URL/IP** in the dashboard
3. Click **FULL SCAN** to run all vulnerability scanners
4. **Select vulnerabilities** to exploit (checkboxes)
5. Click **EXPLOIT SELECTED** to execute attacks
6. Watch the **live feed** for real-time results

### Ransomware Note Editor
Navigate to `/ransomware/preview` to customize the ransom note with your own text, group name, and image before deploying.

---

## Project Structure

```
apex/
├── app.py                    # Main Flask application
├── config.py                 # Configuration
├── requirements.txt          # Python dependencies
├── setup.sh                  # VPS setup script
├── .gitignore
├── README.md
├── modules/
│   ├── anonymity/            # Proxy, Tor, Kill Switch
│   ├── recon/                # Port scanner, Subdomain enum
│   ├── scanners/             # XSS, SQLi, CMDi, LFI, CSRF, SSRF, SSTI, CORS
│   ├── exploitation/         # XSS deface, SQLi exploit
│   ├── post_exploit/         # Ransomware, DB wiper, Backdoor
│   ├── c2/                   # C2 Framework (coming soon)
│   ├── windows_ad/           # Windows/AD attacks (coming soon)
│   ├── cloud/                # Cloud attacks (coming soon)
│   ├── evasion/              # Evasion modules (coming soon)
│   ├── specialized/          # Specialized attacks (coming soon)
│   ├── bruteforce/           # Bruteforce modules (coming soon)
│   ├── social/               # Social engineering (coming soon)
│   └── reporting/            # Report generation (coming soon)
├── templates/                # HTML templates
├── static/                   # CSS, JS, uploads
├── payloads/                 # Wordlists
├── data/                     # SQLite DB, scan results
└── reports/                  # Generated reports
```

---

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Backend | Python 3, Flask |
| Real-time | WebSockets (Socket.IO) |
| Frontend | HTML5, CSS3, JavaScript |
| Database | SQLite |
| Encryption | AES-256 (Fernet) |
| Anonymity | Tor, SOCKS5 Proxies, WireGuard |

---

## VPS Requirements

| Spec | Minimum (KVM 1) |
|------|-----------------|
| CPU | 1 vCPU |
| RAM | 1 GB |
| Storage | 20 GB SSD |
| OS | Ubuntu 22.04/24.04 |

*2 GB swap file created automatically by setup.sh*

---

## License

Proprietary. For authorized red team use only.

---

**🔺 APEX — We are watching. We have everything. There is no backup. There is no escape.**