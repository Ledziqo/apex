"""
APEX v3.0 — AI Attack Strategist & Vulnerability Chain Predictor
Autonomously analyzes scan results, decides attack priorities, and predicts exploit chains.
"""

import json
import random
from datetime import datetime


class AIStrategist:
    """AI-powered attack strategist that analyzes vulnerabilities and suggests optimal attack paths."""
    
    def __init__(self):
        self.attack_history = []
        self.chain_templates = {
            'xss_to_csrf': {
                'name': 'XSS → CSRF',
                'description': 'Use XSS to bypass CSRF protections by reading tokens from the DOM',
                'steps': ['exploit_xss', 'extract_csrf_token', 'forge_request', 'execute_csrf'],
                'confidence': 0.85
            },
            'sqli_to_admin': {
                'name': 'SQLi → Admin Access',
                'description': 'Extract admin credentials from database, then login to admin panel',
                'steps': ['exploit_sqli', 'dump_users_table', 'crack_hashes', 'login_admin'],
                'confidence': 0.90
            },
            'ssrf_to_cloud': {
                'name': 'SSRF → Cloud Metadata',
                'description': 'Use SSRF to access cloud metadata service and steal IAM credentials',
                'steps': ['exploit_ssrf', 'access_metadata', 'steal_credentials', 'access_cloud'],
                'confidence': 0.80
            },
            'lfi_to_rce': {
                'name': 'LFI → RCE',
                'description': 'Chain LFI with log poisoning or /proc/self/environ to achieve RCE',
                'steps': ['exploit_lfi', 'poison_logs', 'include_logs', 'execute_command'],
                'confidence': 0.75
            },
            'upload_to_rce': {
                'name': 'File Upload → RCE',
                'description': 'Upload a web shell via file upload vulnerability, then execute commands',
                'steps': ['exploit_upload', 'upload_shell', 'access_shell', 'execute_command'],
                'confidence': 0.88
            },
            'ssti_to_rce': {
                'name': 'SSTI → RCE',
                'description': 'Exploit Server-Side Template Injection to achieve remote code execution',
                'steps': ['exploit_ssti', 'escalate_to_rce', 'execute_command', 'deploy_persistence'],
                'confidence': 0.82
            },
            'idor_to_data_breach': {
                'name': 'IDOR → Data Breach',
                'description': 'Enumerate IDs to access unauthorized data from other users',
                'steps': ['exploit_idor', 'enumerate_ids', 'extract_data', 'exfiltrate'],
                'confidence': 0.78
            },
            'jwt_to_account_takeover': {
                'name': 'JWT → Account Takeover',
                'description': 'Forge JWT tokens to impersonate other users including admins',
                'steps': ['exploit_jwt', 'forge_token', 'impersonate_user', 'escalate_privileges'],
                'confidence': 0.83
            }
        }
    
    def analyze_scan_results(self, vulnerabilities, target_info=None):
        """Analyze scan results and return prioritized attack strategy."""
        if not vulnerabilities:
            return {
                'status': 'no_vulns',
                'message': 'No vulnerabilities found. Consider deeper recon or different attack vectors.',
                'recommendations': [
                    'Run deeper discovery on the target',
                    'Try subdomain enumeration',
                    'Check for exposed APIs',
                    'Attempt OSINT profiling'
                ]
            }
        
        # Categorize vulnerabilities
        critical = [v for v in vulnerabilities if v.get('severity') == 'critical']
        high = [v for v in vulnerabilities if v.get('severity') == 'high']
        medium = [v for v in vulnerabilities if v.get('severity') == 'medium']
        low = [v for v in vulnerabilities if v.get('severity') == 'low']
        
        # Group by type
        vuln_types = {}
        for v in vulnerabilities:
            vtype = v.get('type', 'unknown')
            if vtype not in vuln_types:
                vuln_types[vtype] = []
            vuln_types[vtype].append(v)
        
        # Predict possible exploit chains
        predicted_chains = self._predict_chains(vuln_types)
        
        # Determine attack priority
        priority_targets = []
        if critical:
            priority_targets = critical[:3]
        elif high:
            priority_targets = high[:3]
        elif medium:
            priority_targets = medium[:3]
        
        # Generate step-by-step attack plan
        attack_plan = self._generate_attack_plan(priority_targets, predicted_chains, vuln_types)
        
        # Generate AI-style narrative
        narrative = self._generate_narrative(vulnerabilities, predicted_chains, target_info)
        
        return {
            'status': 'analyzed',
            'total_vulns': len(vulnerabilities),
            'critical': len(critical),
            'high': len(high),
            'medium': len(medium),
            'low': len(low),
            'vuln_types': list(vuln_types.keys()),
            'priority_targets': priority_targets,
            'predicted_chains': predicted_chains,
            'attack_plan': attack_plan,
            'narrative': narrative,
            'timestamp': datetime.now().isoformat()
        }
    
    def _predict_chains(self, vuln_types):
        """Predict which exploit chains are possible based on found vulnerabilities."""
        available_chains = []
        
        # XSS + CSRF chain
        if 'xss' in vuln_types and 'csrf' in vuln_types:
            chain = self.chain_templates['xss_to_csrf'].copy()
            chain['available'] = True
            chain['reason'] = f'Found {len(vuln_types["xss"])} XSS and {len(vuln_types["csrf"])} CSRF vulnerabilities'
            available_chains.append(chain)
        
        # SQLi chain
        if 'sqli' in vuln_types:
            chain = self.chain_templates['sqli_to_admin'].copy()
            chain['available'] = True
            chain['reason'] = f'Found {len(vuln_types["sqli"])} SQL injection vulnerabilities'
            available_chains.append(chain)
        
        # SSRF chain
        if 'ssrf' in vuln_types:
            chain = self.chain_templates['ssrf_to_cloud'].copy()
            chain['available'] = True
            chain['reason'] = f'Found {len(vuln_types["ssrf"])} SSRF vulnerabilities'
            available_chains.append(chain)
        
        # LFI chain
        if 'lfi' in vuln_types:
            chain = self.chain_templates['lfi_to_rce'].copy()
            chain['available'] = True
            chain['reason'] = f'Found {len(vuln_types["lfi"])} LFI vulnerabilities'
            available_chains.append(chain)
        
        # File upload chain
        if 'file_upload' in vuln_types:
            chain = self.chain_templates['upload_to_rce'].copy()
            chain['available'] = True
            chain['reason'] = f'Found {len(vuln_types["file_upload"])} file upload vulnerabilities'
            available_chains.append(chain)
        
        # SSTI chain
        if 'ssti' in vuln_types:
            chain = self.chain_templates['ssti_to_rce'].copy()
            chain['available'] = True
            chain['reason'] = f'Found {len(vuln_types["ssti"])} SSTI vulnerabilities'
            available_chains.append(chain)
        
        # IDOR chain
        if 'idor' in vuln_types:
            chain = self.chain_templates['idor_to_data_breach'].copy()
            chain['available'] = True
            chain['reason'] = f'Found {len(vuln_types["idor"])} IDOR vulnerabilities'
            available_chains.append(chain)
        
        # JWT chain
        if 'jwt' in vuln_types:
            chain = self.chain_templates['jwt_to_account_takeover'].copy()
            chain['available'] = True
            chain['reason'] = f'Found {len(vuln_types["jwt"])} JWT vulnerabilities'
            available_chains.append(chain)
        
        # Sort by confidence
        available_chains.sort(key=lambda c: c.get('confidence', 0), reverse=True)
        
        return available_chains
    
    def _generate_attack_plan(self, priority_targets, predicted_chains, vuln_types):
        """Generate a step-by-step attack plan."""
        plan = {
            'phase1': {
                'name': 'Initial Exploitation',
                'description': 'Exploit the highest-severity vulnerabilities first',
                'actions': []
            },
            'phase2': {
                'name': 'Privilege Escalation',
                'description': 'Escalate access using chained exploits',
                'actions': []
            },
            'phase3': {
                'name': 'Persistence & Exfiltration',
                'description': 'Maintain access and extract valuable data',
                'actions': []
            }
        }
        
        # Phase 1: Exploit priority targets
        for i, vuln in enumerate(priority_targets):
            plan['phase1']['actions'].append({
                'step': i + 1,
                'vuln_type': vuln.get('type', 'unknown'),
                'endpoint': vuln.get('endpoint', 'N/A'),
                'parameter': vuln.get('parameter', 'N/A'),
                'severity': vuln.get('severity', 'unknown'),
                'action': f'Exploit {vuln.get("type", "unknown").upper()} on {vuln.get("endpoint", "N/A")}',
                'expected_result': 'Gain initial foothold or extract sensitive data'
            })
        
        # Phase 2: Chain exploits
        for i, chain in enumerate(predicted_chains[:3]):
            plan['phase2']['actions'].append({
                'step': len(plan['phase1']['actions']) + i + 1,
                'chain_name': chain['name'],
                'confidence': f"{chain.get('confidence', 0) * 100:.0f}%",
                'action': f'Execute {chain["name"]} attack chain',
                'expected_result': chain.get('description', 'Escalate access')
            })
        
        # Phase 3: Post-exploitation
        post_actions = [
            {'action': 'Deploy persistence mechanism (web shell / SSH key / cron)', 'tool': 'persistence'},
            {'action': 'Dump credentials from compromised system', 'tool': 'cred_dump'},
            {'action': 'Exfiltrate sensitive data (databases, configs, source code)', 'tool': 'exfiltrator'},
            {'action': 'Cover tracks and clean logs', 'tool': 'cleaner'},
            {'action': 'Generate comprehensive attack report', 'tool': 'report_gen'}
        ]
        for i, action in enumerate(post_actions):
            plan['phase3']['actions'].append({
                'step': len(plan['phase1']['actions']) + len(plan['phase2']['actions']) + i + 1,
                **action
            })
        
        return plan
    
    def _generate_narrative(self, vulnerabilities, predicted_chains, target_info=None):
        """Generate an AI-style narrative summary of findings."""
        total = len(vulnerabilities)
        critical = len([v for v in vulnerabilities if v.get('severity') == 'critical'])
        high = len([v for v in vulnerabilities if v.get('severity') == 'high'])
        
        narratives = []
        
        if critical > 0:
            narratives.append(f"🔴 CRITICAL: Found {critical} critical vulnerabilities. Immediate exploitation recommended.")
        
        if high > 0:
            narratives.append(f"🟠 HIGH: {high} high-severity vulnerabilities detected. High probability of successful exploitation.")
        
        if predicted_chains:
            top_chain = predicted_chains[0]
            narratives.append(f"⛓️ Best attack chain: {top_chain['name']} (confidence: {top_chain.get('confidence', 0) * 100:.0f}%)")
            narratives.append(f"   → {top_chain.get('description', '')}")
        
        if total == 0:
            narratives.append("No vulnerabilities found. The target appears well-hardened. Consider deeper recon or OSINT profiling.")
        elif total < 5:
            narratives.append(f"Found {total} vulnerabilities. Target has some security but gaps exist.")
        elif total < 15:
            narratives.append(f"Found {total} vulnerabilities. Target has significant security weaknesses.")
        else:
            narratives.append(f"Found {total} vulnerabilities. Target is critically vulnerable — full compromise likely.")
        
        # Add specific recommendations
        vuln_types = set(v.get('type', '') for v in vulnerabilities)
        if 'sqli' in vuln_types:
            narratives.append("💡 SQLi found — prioritize database extraction for maximum impact.")
        if 'xss' in vuln_types:
            narratives.append("💡 XSS found — can be used for session hijacking or phishing.")
        if 'cmdi' in vuln_types or 'lfi' in vuln_types or 'ssti' in vuln_types:
            narratives.append("💡 RCE-capable vulnerability found — full system compromise possible.")
        
        return '\n'.join(narratives)
    
    def suggest_next_steps(self, current_phase, vulnerabilities, exploit_results=None):
        """Suggest next steps based on current attack phase."""
        suggestions = {
            'recon': [
                'Run full vulnerability scan on the target',
                'Perform subdomain enumeration',
                'Check for exposed API endpoints',
                'Run admin panel finder',
                'Discover sensitive files (.git, .env, backups)'
            ],
            'scanning': [
                'Review all found vulnerabilities',
                'Prioritize critical and high severity findings',
                'Check for exploit chains (e.g., XSS→CSRF, SQLi→Admin)',
                'Verify vulnerabilities are not false positives'
            ],
            'exploitation': [
                'Exploit critical vulnerabilities first',
                'Use the AI strategist to predict optimal attack chains',
                'Monitor exploit results in real-time',
                'If blocked, try WAF evasion techniques'
            ],
            'post_exploit': [
                'Deploy persistence (web shell, SSH key, cron job)',
                'Dump credentials from compromised systems',
                'Exfiltrate valuable data',
                'Perform lateral movement to other systems',
                'Cover tracks and clean logs'
            ],
            'complete': [
                'Generate comprehensive PDF report',
                'Generate PoC files for each vulnerability',
                'Review and document all findings',
                'Provide remediation recommendations to client'
            ]
        }
        
        phase_suggestions = suggestions.get(current_phase, suggestions['scanning'])
        
        # Add context-aware suggestions
        if vulnerabilities:
            critical_count = len([v for v in vulnerabilities if v.get('severity') == 'critical'])
            if critical_count > 0 and current_phase == 'scanning':
                phase_suggestions.insert(0, f'⚡ {critical_count} CRITICAL vulnerabilities found — exploit immediately!')
        
        return {
            'current_phase': current_phase,
            'suggestions': phase_suggestions,
            'timestamp': datetime.now().isoformat()
        }
    
    def predict_exploit_success(self, vuln):
        """Predict the likelihood of successful exploitation for a given vulnerability."""
        vuln_type = vuln.get('type', '').lower()
        confirmed = vuln.get('confirmed', False)
        
        base_confidence = {
            'sqli': 0.90,
            'xss': 0.85,
            'cmdi': 0.88,
            'lfi': 0.75,
            'ssti': 0.80,
            'ssrf': 0.70,
            'csrf': 0.65,
            'cors': 0.60,
            'file_upload': 0.78,
            'idor': 0.72,
            'jwt': 0.68,
            'xxe': 0.82,
            'nosqli': 0.85,
            'prototype_pollution': 0.55,
            'smuggling': 0.50,
            'oauth': 0.60
        }.get(vuln_type, 0.50)
        
        if confirmed:
            base_confidence += 0.10
        
        # Adjust based on context
        context = vuln.get('context', '')
        if context == 'script_tag':
            base_confidence += 0.05  # Script context is more exploitable
        elif context == 'html_comment':
            base_confidence -= 0.10  # Comment context is harder
        
        return min(0.99, max(0.10, base_confidence))
    
    def get_attack_summary(self, scan_results):
        """Generate a concise attack summary for the dashboard."""
        vulns = scan_results.get('vulnerabilities', [])
        analysis = self.analyze_scan_results(vulns)
        
        return {
            'total_vulns': analysis['total_vulns'],
            'severity_breakdown': {
                'critical': analysis['critical'],
                'high': analysis['high'],
                'medium': analysis['medium'],
                'low': analysis['low']
            },
            'top_chains': [c['name'] for c in analysis['predicted_chains'][:3]],
            'narrative': analysis['narrative'],
            'recommended_action': 'EXPLOIT' if analysis['critical'] > 0 else 'SCAN_DEEPER' if analysis['total_vulns'] == 0 else 'ANALYZE'
        }


# Singleton instance
ai_strategist = AIStrategist()