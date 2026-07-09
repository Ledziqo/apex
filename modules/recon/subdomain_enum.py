"""
APEX Subdomain Enumerator
DNS bruteforce, zone transfer, certificate transparency
"""
import socket
import dns.resolver
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed

COMMON_SUBDOMAINS = [
    'www', 'mail', 'admin', 'api', 'dev', 'staging', 'blog', 'shop',
    'cdn', 'app', 'test', 'portal', 'secure', 'vpn', 'remote', 'webmail',
    'ftp', 'ns1', 'ns2', 'dns', 'mx', 'smtp', 'pop', 'imap', 'db',
    'mysql', 'mongo', 'redis', 'elastic', 'kibana', 'grafana', 'jenkins',
    'git', 'gitlab', 'jira', 'confluence', 'wiki', 'docs', 'status',
    'monitor', 'logs', 'backup', 'assets', 'static', 'media', 'files',
    'upload', 'download', 'mobile', 'm', 'beta', 'demo', 'sandbox',
    'old', 'new', 'v1', 'v2', 'api2', 'internal', 'external', 'partner',
    'affiliate', 'careers', 'jobs', 'support', 'help', 'kb', 'knowledge'
]

def dns_bruteforce(domain, wordlist=None, max_threads=20):
    """Bruteforce subdomains using DNS resolution"""
    if wordlist is None:
        wordlist = COMMON_SUBDOMAINS
    
    found = []
    
    def check_sub(sub):
        hostname = f"{sub}.{domain}"
        try:
            socket.gethostbyname(hostname)
            return hostname
        except:
            return None
    
    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        futures = {executor.submit(check_sub, sub): sub for sub in wordlist}
        for future in as_completed(futures):
            result = future.result()
            if result:
                found.append(result)
    
    return sorted(found)

def dns_zone_transfer(domain):
    """Attempt DNS zone transfer"""
    try:
        ns_records = dns.resolver.resolve(domain, 'NS')
        for ns in ns_records:
            ns_server = str(ns).rstrip('.')
            try:
                z = dns.zone.from_xfr(dns.query.xfr(ns_server, domain))
                return [str(name) + '.' + domain for name in z.nodes.keys()]
            except:
                continue
    except:
        pass
    return []

def crtsh_enum(domain):
    """Query crt.sh for certificate transparency logs"""
    try:
        url = f"https://crt.sh/?q=%25.{domain}&output=json"
        r = requests.get(url, timeout=10, headers={'User-Agent': 'Mozilla/5.0'})
        if r.status_code == 200:
            data = r.json()
            subdomains = set()
            for entry in data:
                name = entry.get('name_value', '')
                for sub in name.split('\n'):
                    sub = sub.strip().lower()
                    if sub.endswith(domain) and '*' not in sub:
                        subdomains.add(sub)
            return sorted(list(subdomains))
    except:
        pass
    return []

def enumerate_subdomains(domain):
    """Full subdomain enumeration"""
    domain = domain.replace('https://', '').replace('http://', '').split('/')[0].split(':')[0]
    
    all_subs = set()
    
    # DNS bruteforce
    all_subs.update(dns_bruteforce(domain))
    
    # Certificate transparency
    all_subs.update(crtsh_enum(domain))
    
    # Zone transfer
    all_subs.update(dns_zone_transfer(domain))
    
    return sorted(list(all_subs))