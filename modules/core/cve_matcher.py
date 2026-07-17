"""
APEX v4.0 — CVE Matcher
Cross-references detected tech stack with known CVEs from exploit-db
"""
import requests
import re
import json
from datetime import datetime

# Known vulnerable software signatures
CVE_DATABASE = {
    'apache': {
        '2.4.49': {'cve': 'CVE-2021-41773', 'type': 'path_traversal', 'severity': 'critical', 'desc': 'Apache HTTP Server path traversal leading to RCE'},
        '2.4.50': {'cve': 'CVE-2021-42013', 'type': 'path_traversal', 'severity': 'critical', 'desc': 'Apache HTTP Server path traversal leading to RCE'},
        '2.2.': {'cve': 'CVE-2011-3192', 'type': 'dos', 'severity': 'high', 'desc': 'Apache HTTP Server byte range denial of service'},
        '1.3.': {'cve': 'CVE-2004-0113', 'type': 'multiple', 'severity': 'critical', 'desc': 'Apache HTTP Server multiple vulnerabilities'},
    },
    'nginx': {
        '1.20.0': {'cve': 'CVE-2021-23017', 'type': 'dns_resolution', 'severity': 'high', 'desc': 'nginx DNS resolution vulnerability'},
        '1.16.': {'cve': 'CVE-2019-9511', 'type': 'http2', 'severity': 'high', 'desc': 'nginx HTTP/2 request smuggling'},
        '0.8.': {'cve': 'CVE-2009-3898', 'type': 'dos', 'severity': 'medium', 'desc': 'nginx NULL pointer dereference'},
    },
    'php': {
        '8.1.': {'cve': 'CVE-2022-31626', 'type': 'bypass', 'severity': 'high', 'desc': 'PHP password_verify timing attack'},
        '7.4.': {'cve': 'CVE-2020-7071', 'type': 'bypass', 'severity': 'high', 'desc': 'PHP URL validation bypass'},
        '7.3.': {'cve': 'CVE-2019-11043', 'type': 'rce', 'severity': 'critical', 'desc': 'PHP-FPM RCE via fastcgi'},
        '5.6.': {'cve': 'CVE-2018-5711', 'type': 'dos', 'severity': 'high', 'desc': 'PHP phar deserialization'},
        '5.4.': {'cve': 'CVE-2013-1643', 'type': 'rce', 'severity': 'critical', 'desc': 'PHP SOAP RCE'},
    },
    'wordpress': {
        '6.0.': {'cve': 'CVE-2022-3590', 'type': 'sqli', 'severity': 'critical', 'desc': 'WordPress SQL injection via shortcode'},
        '5.8.': {'cve': 'CVE-2021-39200', 'type': 'info_disclosure', 'severity': 'high', 'desc': 'WordPress information disclosure'},
        '5.7.': {'cve': 'CVE-2021-29447', 'type': 'xxe', 'severity': 'high', 'desc': 'WordPress XXE via media upload'},
        '5.6.': {'cve': 'CVE-2021-24145', 'type': 'rce', 'severity': 'critical', 'desc': 'WordPress RCE via phar deserialization'},
        '4.9.': {'cve': 'CVE-2018-1000222', 'type': 'xss', 'severity': 'high', 'desc': 'WordPress stored XSS'},
        '4.7.': {'cve': 'CVE-2017-1001000', 'type': 'rce', 'severity': 'critical', 'desc': 'WordPress REST API RCE'},
    },
    'joomla': {
        '4.0.': {'cve': 'CVE-2021-23132', 'type': 'xss', 'severity': 'high', 'desc': 'Joomla stored XSS'},
        '3.9.': {'cve': 'CVE-2020-11890', 'type': 'sqli', 'severity': 'critical', 'desc': 'Joomla SQL injection'},
        '3.8.': {'cve': 'CVE-2018-8045', 'type': 'sqli', 'severity': 'critical', 'desc': 'Joomla SQL injection'},
    },
    'drupal': {
        '9.0.': {'cve': 'CVE-2020-13671', 'type': 'xss', 'severity': 'high', 'desc': 'Drupal stored XSS'},
        '8.9.': {'cve': 'CVE-2020-13666', 'type': 'csrf', 'severity': 'high', 'desc': 'Drupal CSRF bypass'},
        '8.8.': {'cve': 'CVE-2020-11022', 'type': 'xss', 'severity': 'high', 'desc': 'Drupal XSS via jQuery'},
        '7.58': {'cve': 'CVE-2018-7600', 'type': 'rce', 'severity': 'critical', 'desc': 'Drupalgeddon2 RCE'},
        '7.0.': {'cve': 'CVE-2014-3704', 'type': 'sqli', 'severity': 'critical', 'desc': 'Drupal SQL injection'},
    },
    'mysql': {
        '8.0.': {'cve': 'CVE-2022-21367', 'type': 'dos', 'severity': 'medium', 'desc': 'MySQL denial of service'},
        '5.7.': {'cve': 'CVE-2021-35604', 'type': 'dos', 'severity': 'medium', 'desc': 'MySQL denial of service'},
        '5.6.': {'cve': 'CVE-2020-2922', 'type': 'auth_bypass', 'severity': 'high', 'desc': 'MySQL authentication bypass'},
        '5.5.': {'cve': 'CVE-2018-3081', 'type': 'priv_esc', 'severity': 'high', 'desc': 'MySQL privilege escalation'},
        '5.1.': {'cve': 'CVE-2012-2122', 'type': 'auth_bypass', 'severity': 'critical', 'desc': 'MySQL authentication bypass'},
    },
    'openssh': {
        '8.9.': {'cve': 'CVE-2022-27107', 'type': 'dos', 'severity': 'medium', 'desc': 'OpenSSH denial of service'},
        '8.0.': {'cve': 'CVE-2019-16905', 'type': 'rce', 'severity': 'critical', 'desc': 'OpenSSH RCE via scp'},
        '7.7.': {'cve': 'CVE-2018-15473', 'type': 'user_enum', 'severity': 'medium', 'desc': 'OpenSSH username enumeration'},
        '7.2.': {'cve': 'CVE-2016-6210', 'type': 'user_enum', 'severity': 'medium', 'desc': 'OpenSSH username enumeration'},
    },
    'openssl': {
        '1.1.1': {'cve': 'CVE-2022-3602', 'type': 'buffer_overflow', 'severity': 'critical', 'desc': 'OpenSSL X.509 buffer overflow'},
        '1.0.2': {'cve': 'CVE-2016-6304', 'type': 'dos', 'severity': 'high', 'desc': 'OpenSSL OCSP denial of service'},
        '1.0.1': {'cve': 'CVE-2014-0160', 'type': 'heartbleed', 'severity': 'critical', 'desc': 'Heartbleed - memory leak'},
        '0.9.8': {'cve': 'CVE-2014-0224', 'type': 'mitm', 'severity': 'high', 'desc': 'OpenSSL MITM vulnerability'},
    },
    'iis': {
        '10.0': {'cve': 'CVE-2021-31166', 'type': 'rce', 'severity': 'critical', 'desc': 'IIS HTTP.sys RCE'},
        '8.5': {'cve': 'CVE-2015-1635', 'type': 'rce', 'severity': 'critical', 'desc': 'IIS HTTP.sys RCE'},
        '7.5': {'cve': 'CVE-2010-3972', 'type': 'rce', 'severity': 'critical', 'desc': 'IIS FTP service RCE'},
        '6.0': {'cve': 'CVE-2017-7269', 'type': 'rce', 'severity': 'critical', 'desc': 'IIS WebDAV RCE'},
    },
    'tomcat': {
        '9.0.': {'cve': 'CVE-2022-22965', 'type': 'rce', 'severity': 'critical', 'desc': 'Spring4Shell via Tomcat'},
        '8.5.': {'cve': 'CVE-2020-1938', 'type': 'lfi', 'severity': 'critical', 'desc': 'Ghostcat - AJP file read'},
        '7.0.': {'cve': 'CVE-2019-0232', 'type': 'rce', 'severity': 'critical', 'desc': 'Tomcat CGIServlet RCE'},
    },
    'jenkins': {
        '2.0.': {'cve': 'CVE-2022-45378', 'type': 'rce', 'severity': 'critical', 'desc': 'Jenkins RCE via XStream'},
        '1.0.': {'cve': 'CVE-2019-1003000', 'type': 'rce', 'severity': 'critical', 'desc': 'Jenkins RCE via sandbox bypass'},
    },
    'elasticsearch': {
        '7.0.': {'cve': 'CVE-2021-44228', 'type': 'rce', 'severity': 'critical', 'desc': 'Log4Shell via Elasticsearch'},
        '6.8.': {'cve': 'CVE-2020-7021', 'type': 'info_disclosure', 'severity': 'high', 'desc': 'Elasticsearch information disclosure'},
        '1.4.': {'cve': 'CVE-2015-1427', 'type': 'rce', 'severity': 'critical', 'desc': 'Elasticsearch Groovy RCE'},
    },
    'mongodb': {
        '3.6.': {'cve': 'CVE-2019-2391', 'type': 'auth_bypass', 'severity': 'high', 'desc': 'MongoDB authentication bypass'},
        '2.6.': {'cve': 'CVE-2013-1892', 'type': 'auth_bypass', 'severity': 'critical', 'desc': 'MongoDB no-auth access'},
    },
    'redis': {
        '6.0.': {'cve': 'CVE-2021-32675', 'type': 'lua_sandbox', 'severity': 'high', 'desc': 'Redis Lua sandbox escape'},
        '5.0.': {'cve': 'CVE-2020-14147', 'type': 'rce', 'severity': 'critical', 'desc': 'Redis RCE via Lua'},
        '2.8.': {'cve': 'CVE-2015-4335', 'type': 'rce', 'severity': 'critical', 'desc': 'Redis RCE via EVAL'},
    },
    'rails': {
        '6.0.': {'cve': 'CVE-2020-8163', 'type': 'rce', 'severity': 'critical', 'desc': 'Rails RCE via code injection'},
        '5.2.': {'cve': 'CVE-2020-8162', 'type': 'rce', 'severity': 'critical', 'desc': 'Rails RCE via file download'},
        '4.2.': {'cve': 'CVE-2016-2098', 'type': 'rce', 'severity': 'critical', 'desc': 'Rails RCE via inline erb'},
    },
    'django': {
        '3.2.': {'cve': 'CVE-2021-35042', 'type': 'sqli', 'severity': 'high', 'desc': 'Django SQL injection'},
        '3.0.': {'cve': 'CVE-2020-7471', 'type': 'sqli', 'severity': 'high', 'desc': 'Django SQL injection via StringAgg'},
        '2.2.': {'cve': 'CVE-2019-14234', 'type': 'sqli', 'severity': 'high', 'desc': 'Django SQL injection'},
        '1.11.': {'cve': 'CVE-2018-14574', 'type': 'open_redirect', 'severity': 'medium', 'desc': 'Django open redirect'},
    },
    'node': {
        '18.0.': {'cve': 'CVE-2022-32213', 'type': 'dos', 'severity': 'high', 'desc': 'Node.js HTTP request smuggling'},
        '16.0.': {'cve': 'CVE-2022-21824', 'type': 'dos', 'severity': 'high', 'desc': 'Node.js HTTP request smuggling'},
        '14.0.': {'cve': 'CVE-2021-22930', 'type': 'dos', 'severity': 'high', 'desc': 'Node.js HTTP request smuggling'},
        '12.0.': {'cve': 'CVE-2020-8174', 'type': 'dos', 'severity': 'high', 'desc': 'Node.js HTTP request smuggling'},
        '10.0.': {'cve': 'CVE-2019-15604', 'type': 'dos', 'severity': 'high', 'desc': 'Node.js HTTP request smuggling'},
    },
    'express': {
        '4.0.': {'cve': 'CVE-2022-24999', 'type': 'qs', 'severity': 'high', 'desc': 'Express qs prototype pollution'},
        '3.0.': {'cve': 'CVE-2014-6394', 'type': 'rce', 'severity': 'critical', 'desc': 'Express RCE via session'},
    },
    'struts': {
        '2.5.': {'cve': 'CVE-2017-5638', 'type': 'rce', 'severity': 'critical', 'desc': 'Struts2 RCE via Content-Type'},
        '2.3.': {'cve': 'CVE-2017-9791', 'type': 'rce', 'severity': 'critical', 'desc': 'Struts2 RCE via OGNL'},
    },
    'jboss': {
        '7.0.': {'cve': 'CVE-2017-12149', 'type': 'rce', 'severity': 'critical', 'desc': 'JBoss RCE via HTTP'},
        '6.0.': {'cve': 'CVE-2015-7501', 'type': 'rce', 'severity': 'critical', 'desc': 'JBoss RCE via deserialization'},
    },
    'weblogic': {
        '12.2.': {'cve': 'CVE-2020-14882', 'type': 'rce', 'severity': 'critical', 'desc': 'WebLogic RCE via console'},
        '12.1.': {'cve': 'CVE-2019-2725', 'type': 'rce', 'severity': 'critical', 'desc': 'WebLogic RCE via wls9-async'},
        '10.3.': {'cve': 'CVE-2017-10271', 'type': 'rce', 'severity': 'critical', 'desc': 'WebLogic RCE via XMLDecoder'},
    },
    'vbulletin': {
        '5.6.': {'cve': 'CVE-2020-17496', 'type': 'rce', 'severity': 'critical', 'desc': 'vBulletin RCE via widget'},
        '5.5.': {'cve': 'CVE-2019-16759', 'type': 'rce', 'severity': 'critical', 'desc': 'vBulletin RCE via widgetConfig'},
    },
    'phpmyadmin': {
        '5.0.': {'cve': 'CVE-2020-26935', 'type': 'sqli', 'severity': 'high', 'desc': 'phpMyAdmin SQL injection'},
        '4.9.': {'cve': 'CVE-2020-0554', 'type': 'xss', 'severity': 'high', 'desc': 'phpMyAdmin XSS'},
        '4.8.': {'cve': 'CVE-2018-19968', 'type': 'rce', 'severity': 'critical', 'desc': 'phpMyAdmin RCE via SQL'},
    },
}


class CVEMatcher:
    """Matches detected software versions against known CVEs."""
    
    def match(self, software, version):
        """Check if a software version has known CVEs."""
        results = []
        if not software or not version:
            return results
        software = software.lower().strip()
        version = version.lower().strip()
        
        for sw_name, versions in CVE_DATABASE.items():
            if sw_name in software:
                for ver_pattern, cve_info in versions.items():
                    if version.startswith(ver_pattern.rstrip('.')) or ver_pattern.rstrip('.') in version:
                        results.append({
                            **cve_info,
                            'software': sw_name,
                            'detected_version': version,
                            'matched_pattern': ver_pattern,
                        })
        return results
    
    def match_fingerprint(self, fingerprint):
        """Match an entire fingerprint dict against CVEs."""
        all_cves = []
        for key, value in fingerprint.items():
            if isinstance(value, str) and value and value != 'Unknown':
                cves = self.match(key, value)
                all_cves.extend(cves)
        return all_cves
    
    def search_exploitdb(self, cve_id):
        """Search exploit-db for a specific CVE."""
        try:
            r = requests.get(f'https://www.exploit-db.com/search?cve={cve_id}', timeout=10, headers={
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            })
            if r.status_code == 200:
                return {'found': True, 'url': f'https://www.exploit-db.com/search?cve={cve_id}'}
        except:
            pass
        return {'found': False}


# Global instance
cve_matcher = CVEMatcher()
