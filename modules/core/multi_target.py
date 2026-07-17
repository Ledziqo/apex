"""
APEX v4.0 — Multi-Target Expansion Engine
Batch scanning, target queue management, results aggregation, and scan comparison.
"""
import os, json, time, threading, random
from datetime import datetime
from urllib.parse import urlparse


class MultiTargetEngine:
    """Manages multi-target scanning, queuing, and results aggregation."""

    def __init__(self):
        self.targets = []  # List of target dicts
        self.queue = []    # Pending targets
        self.results = {}  # target_url -> scan results
        self.running = False
        self.max_concurrent = 5
        self.callback = None
        self.socketio = None

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

    def add_target(self, url, label=None):
        """Add a target to the queue."""
        if not url.startswith('http'):
            url = 'https://' + url
        target = {
            'url': url,
            'label': label or urlparse(url).netloc,
            'added': datetime.now().isoformat(),
            'status': 'queued',
            'scan_id': None,
            'vulnerabilities': [],
            'fingerprint': None,
        }
        self.targets.append(target)
        self.queue.append(target)
        return target

    def remove_target(self, index_or_url):
        """Remove a target from the queue."""
        if isinstance(index_or_url, int):
            if 0 <= index_or_url < len(self.targets):
                t = self.targets.pop(index_or_url)
                self.queue = [q for q in self.queue if q['url'] != t['url']]
                return t
        else:
            self.targets = [t for t in self.targets if t['url'] != index_or_url]
            self.queue = [q for q in self.queue if q['url'] != index_or_url]
        return None

    def clear_targets(self):
        """Clear all targets."""
        self.targets = []
        self.queue = []
        self.results = {}

    def get_targets(self):
        """Return all targets with status."""
        return {
            'total': len(self.targets),
            'queued': len(self.queue),
            'completed': len([t for t in self.targets if t['status'] == 'completed']),
            'scanning': len([t for t in self.targets if t['status'] == 'scanning']),
            'failed': len([t for t in self.targets if t['status'] == 'failed']),
            'targets': self.targets,
        }

    def scan_all(self, scan_func, scan_type='full'):
        """Scan all queued targets using the provided scan function."""
        if self.running:
            return {'error': 'Batch scan already running'}

        self.running = True
        thread = threading.Thread(target=self._batch_scan, args=(scan_func, scan_type))
        thread.daemon = True
        thread.start()
        return {'status': 'started', 'targets': len(self.queue)}

    def _batch_scan(self, scan_func, scan_type):
        """Execute batch scan across all targets."""
        results = {}
        total = len(self.queue)
        completed = 0

        for target in self.queue:
            if not self.running:
                break

            target['status'] = 'scanning'
            self.emit('batch_update', self.get_targets())

            try:
                # Run scan on this target
                vulns = scan_func(target['url'], scan_type)
                target['status'] = 'completed'
                target['vulnerabilities'] = vulns
                target['completed_at'] = datetime.now().isoformat()
                results[target['url']] = {
                    'vulnerabilities': vulns,
                    'count': len(vulns),
                    'critical': len([v for v in vulns if v.get('severity') == 'critical']),
                    'high': len([v for v in vulns if v.get('severity') == 'high']),
                }
            except Exception as e:
                target['status'] = 'failed'
                target['error'] = str(e)
                results[target['url']] = {'error': str(e), 'count': 0}

            completed += 1
            self.emit('batch_progress', {
                'completed': completed,
                'total': total,
                'percent': int((completed / total) * 100),
            })

        self.results = results
        self.running = False
        self.emit('batch_complete', {
            'total': total,
            'completed': completed,
            'results': results,
            'summary': self.get_aggregated_summary(),
        })

    def get_aggregated_summary(self):
        """Get aggregated results across all targets."""
        all_vulns = []
        target_summaries = []

        for t in self.targets:
            vulns = t.get('vulnerabilities', [])
            all_vulns.extend(vulns)
            target_summaries.append({
                'url': t['url'],
                'label': t.get('label', ''),
                'status': t['status'],
                'total': len(vulns),
                'critical': len([v for v in vulns if v.get('severity') == 'critical']),
                'high': len([v for v in vulns if v.get('severity') == 'high']),
                'medium': len([v for v in vulns if v.get('severity') == 'medium']),
                'low': len([v for v in vulns if v.get('severity') == 'low']),
            })

        return {
            'total_targets': len(self.targets),
            'total_vulnerabilities': len(all_vulns),
            'total_critical': len([v for v in all_vulns if v.get('severity') == 'critical']),
            'total_high': len([v for v in all_vulns if v.get('severity') == 'high']),
            'targets': target_summaries,
            'most_vulnerable': max(target_summaries, key=lambda x: x['total']) if target_summaries else None,
        }

    def compare_scans(self, url1, url2):
        """Compare scan results between two targets."""
        r1 = self.results.get(url1, {})
        r2 = self.results.get(url2, {})

        v1 = r1.get('vulnerabilities', [])
        v2 = r2.get('vulnerabilities', [])

        # Find common vuln types
        types1 = set(v.get('type', '') for v in v1)
        types2 = set(v.get('type', '') for v in v2)
        common = types1 & types2
        only_in_1 = types1 - types2
        only_in_2 = types2 - types1

        return {
            'target1': url1,
            'target2': url2,
            'vulns1': len(v1),
            'vulns2': len(v2),
            'common_types': list(common),
            'unique_to_target1': list(only_in_1),
            'unique_to_target2': list(only_in_2),
            'severity_comparison': {
                'critical': {
                    'target1': len([v for v in v1 if v.get('severity') == 'critical']),
                    'target2': len([v for v in v2 if v.get('severity') == 'critical']),
                },
                'high': {
                    'target1': len([v for v in v1 if v.get('severity') == 'high']),
                    'target2': len([v for v in v2 if v.get('severity') == 'high']),
                },
            }
        }

    def stop_batch(self):
        """Stop the current batch scan."""
        self.running = False
        return {'status': 'stopped'}


# Singleton instance
multi_target = MultiTargetEngine()