"""
APEX Report Generator
Generates professional HTML and PDF reports from scan results
"""
import os
import json
from datetime import datetime
from config import Config

def generate_html_report(scan_results, vulnerabilities, exploits=None):
    """Generate a professional HTML penetration test report"""
    
    if exploits is None:
        exploits = []
    
    target = scan_results.get('target', 'Unknown')
    scan_type = scan_results.get('type', 'full')
    scan_started = scan_results.get('started', datetime.now().isoformat())
    scan_completed = scan_results.get('completed', datetime.now().isoformat())
    
    # Count severities
    critical = len([v for v in vulnerabilities if v.get('severity') == 'critical'])
    high = len([v for v in vulnerabilities if v.get('severity') == 'high'])
    medium = len([v for v in vulnerabilities if v.get('severity') == 'medium'])
    low = len([v for v in vulnerabilities if v.get('severity') == 'low'])
    
    # Build vulnerability rows
    vuln_rows = ''
    for i, vuln in enumerate(vulnerabilities):
        severity = vuln.get('severity', 'low')
        severity_colors = {
            'critical': '#ef4444',
            'high': '#f97316',
            'medium': '#f59e0b',
            'low': '#22c55e'
        }
        color = severity_colors.get(severity, '#6b7280')
        
        vuln_rows += f'''
        <tr>
            <td style="color:{color};font-weight:bold;">{severity.upper()}</td>
            <td>{vuln.get('type', 'N/A').upper()}</td>
            <td>{vuln.get('endpoint', 'N/A')}</td>
            <td>{vuln.get('parameter', 'N/A')}</td>
            <td>{vuln.get('description', 'No description')}</td>
            <td>{vuln.get('result', 'N/A')}</td>
        </tr>'''
    
    # Build exploit rows
    exploit_rows = ''
    for exp in exploits:
        status = '✅ Success' if exp.get('success') else '❌ Failed'
        exploit_rows += f'''
        <tr>
            <td>{exp.get('type', 'N/A').upper()}</td>
            <td>{exp.get('endpoint', 'N/A')}</td>
            <td>{status}</td>
            <td>{exp.get('message', 'N/A')}</td>
        </tr>'''
    
    html = f'''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>APEX — Penetration Test Report</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            background: #fff;
            color: #1a1a1a;
            font-family: 'Segoe UI', Arial, sans-serif;
            padding: 40px;
            max-width: 900px;
            margin: 0 auto;
        }}
        .header {{
            text-align: center;
            border-bottom: 3px solid #f97316;
            padding-bottom: 20px;
            margin-bottom: 30px;
        }}
        .header h1 {{
            font-size: 32px;
            color: #f97316;
            letter-spacing: 4px;
        }}
        .header p {{ color: #6b7280; margin-top: 5px; }}
        .section {{
            margin-bottom: 30px;
            page-break-inside: avoid;
        }}
        .section h2 {{
            font-size: 18px;
            color: #f97316;
            border-bottom: 1px solid #e5e5e5;
            padding-bottom: 8px;
            margin-bottom: 15px;
        }}
        .summary-grid {{
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 15px;
            margin-bottom: 20px;
        }}
        .summary-card {{
            padding: 20px;
            text-align: center;
            border-radius: 4px;
        }}
        .summary-card.critical {{ background: #fef2f2; border: 1px solid #fecaca; }}
        .summary-card.high {{ background: #fff7ed; border: 1px solid #fed7aa; }}
        .summary-card.medium {{ background: #fffbeb; border: 1px solid #fde68a; }}
        .summary-card.low {{ background: #f0fdf4; border: 1px solid #bbf7d0; }}
        .summary-card .count {{ font-size: 36px; font-weight: bold; }}
        .summary-card.critical .count {{ color: #ef4444; }}
        .summary-card.high .count {{ color: #f97316; }}
        .summary-card.medium .count {{ color: #f59e0b; }}
        .summary-card.low .count {{ color: #22c55e; }}
        .summary-card .label {{ font-size: 12px; color: #6b7280; text-transform: uppercase; letter-spacing: 1px; }}
        table {{
            width: 100%;
            border-collapse: collapse;
            font-size: 13px;
        }}
        th {{
            background: #f97316;
            color: #fff;
            padding: 10px 12px;
            text-align: left;
            font-size: 11px;
            text-transform: uppercase;
            letter-spacing: 1px;
        }}
        td {{
            padding: 10px 12px;
            border-bottom: 1px solid #e5e5e5;
        }}
        tr:hover td {{ background: #fafafa; }}
        .info-grid {{
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 10px;
            font-size: 13px;
        }}
        .info-item {{
            padding: 8px 12px;
            background: #fafafa;
            border-left: 3px solid #f97316;
        }}
        .info-item strong {{ color: #f97316; }}
        .footer {{
            text-align: center;
            margin-top: 40px;
            padding-top: 20px;
            border-top: 1px solid #e5e5e5;
            color: #6b7280;
            font-size: 12px;
        }}
        .disclaimer {{
            background: #fef2f2;
            border: 1px solid #fecaca;
            padding: 15px;
            margin-bottom: 20px;
            font-size: 12px;
            color: #991b1b;
        }}
        @media print {{
            body {{ padding: 20px; }}
            .section {{ page-break-inside: avoid; }}
        }}
    </style>
</head>
<body>
    <div class="header">
        <h1>🔺 APEX</h1>
        <p>Professional Red Team Penetration Test Report</p>
        <p style="font-size:12px;color:#9ca3af;">Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
    </div>
    
    <div class="disclaimer">
        ⚠ <strong>CONFIDENTIAL:</strong> This report contains sensitive security findings. 
        Distribution is restricted to authorized personnel only. This penetration test was 
        conducted with explicit written authorization from the target organization.
    </div>
    
    <div class="section">
        <h2>📋 Executive Summary</h2>
        <div class="info-grid">
            <div class="info-item"><strong>Target:</strong> {target}</div>
            <div class="info-item"><strong>Scan Type:</strong> {scan_type.upper()}</div>
            <div class="info-item"><strong>Started:</strong> {scan_started}</div>
            <div class="info-item"><strong>Completed:</strong> {scan_completed}</div>
            <div class="info-item"><strong>Total Vulnerabilities:</strong> {len(vulnerabilities)}</div>
            <div class="info-item"><strong>Exploits Executed:</strong> {len(exploits)}</div>
        </div>
    </div>
    
    <div class="section">
        <h2>📊 Vulnerability Summary</h2>
        <div class="summary-grid">
            <div class="summary-card critical">
                <div class="count">{critical}</div>
                <div class="label">Critical</div>
            </div>
            <div class="summary-card high">
                <div class="count">{high}</div>
                <div class="label">High</div>
            </div>
            <div class="summary-card medium">
                <div class="count">{medium}</div>
                <div class="label">Medium</div>
            </div>
            <div class="summary-card low">
                <div class="count">{low}</div>
                <div class="label">Low</div>
            </div>
        </div>
    </div>
    
    <div class="section">
        <h2>🔍 Vulnerability Details</h2>
        <table>
            <thead>
                <tr>
                    <th>Severity</th>
                    <th>Type</th>
                    <th>Endpoint</th>
                    <th>Parameter</th>
                    <th>Description</th>
                    <th>Result</th>
                </tr>
            </thead>
            <tbody>
                {vuln_rows if vuln_rows else '<tr><td colspan="6" style="text-align:center;color:#6b7280;">No vulnerabilities found</td></tr>'}
            </tbody>
        </table>
    </div>
    
    {f'''
    <div class="section">
        <h2>💥 Exploitation Results</h2>
        <table>
            <thead>
                <tr>
                    <th>Type</th>
                    <th>Endpoint</th>
                    <th>Status</th>
                    <th>Details</th>
                </tr>
            </thead>
            <tbody>
                {exploit_rows}
            </tbody>
        </table>
    </div>
    ''' if exploits else ''}
    
    <div class="section">
        <h2>🛡️ Remediation Recommendations</h2>
        <table>
            <thead>
                <tr>
                    <th>Vulnerability</th>
                    <th>Recommendation</th>
                </tr>
            </thead>
            <tbody>
                {generate_recommendations(vulnerabilities)}
            </tbody>
        </table>
    </div>
    
    <div class="footer">
        <p>🔺 APEX — Professional Red Team Framework</p>
        <p>This report is confidential and intended for authorized recipients only.</p>
        <p>Generated on {datetime.now().strftime('%Y-%m-%d at %H:%M:%S')}</p>
    </div>
</body>
</html>'''
    
    return html


def generate_recommendations(vulnerabilities):
    """Generate remediation recommendations based on found vulnerabilities"""
    recommendations = {
        'xss': 'Implement proper output encoding (HTML entity encoding). Use Content-Security-Policy headers. Validate and sanitize all user input.',
        'sqli': 'Use parameterized queries (prepared statements). Implement input validation. Apply least privilege database accounts. Use ORM frameworks.',
        'cmdi': 'Avoid executing system commands with user input. Use allowlists for commands. Escape shell metacharacters if command execution is necessary.',
        'lfi': 'Use allowlists for file paths. Disable allow_url_include. Implement proper access controls. Avoid passing user input to file functions.',
        'csrf': 'Implement anti-CSRF tokens in all forms. Use SameSite cookie attribute. Verify Origin/Referer headers.',
        'ssrf': 'Implement URL allowlists. Block requests to internal IP ranges. Disable unnecessary URL schemes (file://, gopher://).',
        'ssti': 'Avoid passing user input to template engines. Use sandboxed template environments. Implement strict input validation.',
        'cors': 'Restrict Access-Control-Allow-Origin to specific trusted domains. Never use wildcard (*) with credentials.',
        'file_upload': 'Validate file types by MIME type and magic bytes. Store uploads outside web root. Scan uploads for malware. Implement size limits.',
        'idor': 'Implement proper authorization checks. Use random/unguessable identifiers (UUIDs). Verify object ownership on every request.',
        'jwt': 'Use strong signing algorithms (RS256). Validate token expiration. Implement proper key management. Never accept "none" algorithm.',
    }
    
    seen_types = set()
    rows = ''
    
    for vuln in vulnerabilities:
        vuln_type = vuln.get('type', '')
        if vuln_type not in seen_types:
            seen_types.add(vuln_type)
            rec = recommendations.get(vuln_type, 'Review and patch the affected component. Follow OWASP security guidelines.')
            rows += f'''
            <tr>
                <td style="font-weight:bold;">{vuln_type.upper()}</td>
                <td>{rec}</td>
            </tr>'''
    
    if not rows:
        rows = '<tr><td colspan="2" style="text-align:center;color:#6b7280;">No vulnerabilities to remediate</td></tr>'
    
    return rows


def save_report(html_content, filename=None):
    """Save report to file"""
    if filename is None:
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f'apex_report_{timestamp}.html'
    
    report_path = os.path.join(Config.REPORT_FOLDER, filename)
    os.makedirs(Config.REPORT_FOLDER, exist_ok=True)
    
    with open(report_path, 'w', encoding='utf-8') as f:
        f.write(html_content)
    
    return report_path