---
title: Wargames.MY 2024 - Writeups
date: 2024-12-29
draft: false
description: "This page contains writeups for the Wargames.MY 2024 CTF, covering challenges across categories like Crypto, Forensic, and Misc. The challenges involve solving puzzles such as decrypting ROT13-encoded passwords, analyzing PCAP files to extract hidden messages, decrypting SMB traffic to uncover stolen data, repairing corrupted JPEG images, and rearranging metadata from a .dcm file to form a flag."
summary: "This page contains writeups for Wargames.MY 2024 CTF, covering challenges in Crypto, Forensic, and Misc categories. Solutions involve decrypting ROT13-encoded passwords, extracting flags from ICMP packets, decrypting SMB traffic using NTLM hashes, repairing corrupted JPEG images, and rearranging metadata from a .dcm file based on given indices. Each solution uses tools like CyberChef, Wireshark, Hashcat, and Python scripts."
tags: ["ctf"]
categories: ["ctf"]
---

## Crypto
### Credentials
> We found a leak of a blackmarket website's login credentials. Can you find the password of the user osman and successfully decrypt it?
> 
> Hint: The first user in user.txt corresponds to the first password in passwords.txt

![](https://i.imgur.com/bqzzlnG.png)

Flag: `WGMY{b6d180d9c302d8a8daad1f2174a0b212}`

For this challenge there are 2 files provided `passwd.txt` and `user.txt`.
**user.txt**
```text
osman
```
**passwd.txt**
```text
ZJPB{e6g180g9f302g8d8gddg1i2174d0e212}
```

I search for user `osman` from the `user.txt` which appeared on line 337.  On the `passwd.txt` file's line 337, I found the corresponding password for the user `osman` which is `ZJPB{e6g180g9f302g8d8gddg1i2174d0e212}`. 

This password appears to be encoded using ROT13. To decode it, I used [CyberChef ROT13 Brute Force](https://cyberchef.org/#recipe=ROT13_Brute_Force(true,true,false,100,0,true,'wgmy')&input=WkpQQntlNmcxODBnOWYzMDJnOGQ4Z2RkZzFpMjE3NGQwZTIxMn0) to decode it, with the known plaintext of `wgmy`.
 
![](https://i.imgur.com/Mbm5Fpz.png)

---

## Forensic
### I Cant Manipulate People
> Partial traffic packet captured from hacked machine, can you analyze the provided pcap file to extract the message from the packet perhaps by reading the packet data?
> 
> Hint: Attacker too noob to ping not in sequence

![](https://i.imgur.com/YDFlqCz.png)

Flag: `WGMY{1e3b71d57e466ab71b43c2641a4b34f4}`

Given a `traffic.pcap` file, it can be observed in Wireshark that the source is sending a large number of ping requests to `192.168.0.1` with the following information: `Echo (ping) request id=0x0000, seq=0/0, ttl=64 (no response found!)`. By examining the packet, we see that the data section of each packet consists of only 1 byte.

To filter and view only ICMP Echo requests, apply the filter `icmp.type == 8`. Then, modify the protocol preferences by right-clicking on any packet and selecting `Protocol Preferences > Data > Show Data as Text`. This will display the entire data section of the ping packet, where the flag is visible.

![](https://i.imgur.com/VvWTsqf.png)

An alternative way to obtain the flag is by using Tshark. The following command can be run in the terminal:

```bash
tshark -r traffic.pcap -Y "icmp.type == 8" -T fields -e data | xxd -r -p
```

![](https://i.imgur.com/9wfl2Na.png)

---

### Oh Man
> We received a PCAP file from an admin who suspects an attacker exfiltrated sensitive data. Can you analyze the PCAP file and uncover what was stolen?
> 
> Zip Password: `wgmy`
> 
> Hint: Investigate the tool used by the attacker

![](https://i.imgur.com/0s6npML.png)

Flag: `wgmy{fbba48bee397414246f864fe4d2925e4}`

We are given a `PCAP` file containing encrypted SMB traffic. Our goal is to decrypt the SMB traffic in order to obtain the transferred file. After researching online, I found this [write-up](https://medium.com/maverislabs/decrypting-smb3-traffic-with-just-a-pcap-absolutely-maybe-712ed23ff6a2) that explains how to decrypt SMB traffic.

![](https://i.imgur.com/OMbWMmd.png)

**What We Need to Decrypt the SMB Traffic**
To decrypt the traffic from the `PCAP` file, we need the following information:
1. **Domain**
2. **Username**
3. **Password/NTLM Hash** (can be cracked)
4. **NTProofStr**
5. **NTLM Server Challenge**
6. **Encrypted Session Key**
7. **Session ID**

#### 1. Obtain the data from the Session Setup Packet
From the _Session Setup Request, NTLMSSP_AUTH_ packet, we can extract the following data:
- **Domain**: `DESKTOP-PMNU0JK`
- **Username**: `Administrator`
- **Encrypted Session Key**: `12140eb776cb74a339c9c75b152c52fd`

![](https://i.imgur.com/TrXvDay.png)

Next, we extract the **NTProofStr** and the remaining **NTLM Response Data**:
- **NTProofStr**: `ae62a57caaa5dd94b68def8fb1c192f3`
- **Remaining NTLM Response Data**: 
```
01010000000000008675779b2e57db01376f686e57504d770000000002001e004400450053004b0054004f0050002d0050004d004e00550030004a004b0001001e004400450053004b0054004f0050002d0050004d004e00550030004a004b0004001e004400450053004b0054004f0050002d0050004d004e00550030004a004b0003001e004400450053004b0054004f0050002d0050004d004e00550030004a004b00070008008675779b2e57db010900280063006900660073002f004400450053004b0054004f0050002d0050004d004e00550030004a004b000000000000000000
```

![](https://i.imgur.com/kuT6B27.png)

- **Session ID**: `65000000000c0000`
  To convert this, use [CyberChef](https://cyberchef.org/#recipe=Swap_endianness('Hex',8,true)Remove_whitespace(true,true,true,true,true,false)&input=MHgwMDAwMGMwMDAwMDAwMDY1) to swap the endianness.

![](https://i.imgur.com/UsAEOKs.png)

From the _Session Setup Response, NTLMSSP_CHALLENGE_ packet, we obtain the **NTLM Server Challenge**:
- **NTLM Server Challenge**: `7aaff6ea26301fc3`

![](https://i.imgur.com/gJBZwxg.png)

#### 2. Crack the Password Using the NTLM Data
Now that we have all the required data, we can construct the hash to crack the password using HashCat. The format is:
```
Username::Domain:NTLMServerChallenge:NTProofStr:RemainingNTLMResponseData
```
**Hash**
```
Administrator::DESKTOP-PMNU0JK:7aaff6ea26301fc3:ae62a57caaa5dd94b68def8fb1c192f3:01010000000000008675779b2e57db01376f686e57504d770000000002001e004400450053004b0054004f0050002d0050004d004e00550030004a004b0001001e004400450053004b0054004f0050002d0050004d004e00550030004a004b0004001e004400450053004b0054004f0050002d0050004d004e00550030004a004b0003001e004400450053004b0054004f0050002d0050004d004e00550030004a004b00070008008675779b2e57db010900280063006900660073002f004400450053004b0054004f0050002d0050004d004e00550030004a004b000000000000000000
```

Once the hash is constructed, you can use HashCat to crack the password. The cracked password is `password<3`.

![](https://i.imgur.com/1T1jp2I.png)

#### 3. Obtain the Random Session Key
With the data obtained from the packet and the cracked password, we can calculate the random session key using the following Python script:
**Get Random Session Key.py**
```python
import hashlib
import hmac
import argparse

try:
    from Cryptodome.Cipher import ARC4
    from Cryptodome.Cipher import DES
    from Cryptodome.Hash import MD4
except Exception:
    print("Warning: You don't have any crypto installed. You need pycryptodomex")
    print("See https://pypi.org/project/pycryptodomex/")

def generateEncryptedSessionKey(keyExchangeKey, exportedSessionKey):
    cipher = ARC4.new(keyExchangeKey)
    cipher_encrypt = cipher.encrypt
    sessionKey = cipher_encrypt(exportedSessionKey)
    return sessionKey

parser = argparse.ArgumentParser(description="Calculate the Random Session Key based on data from a PCAP (maybe).")
parser.add_argument("-u", "--user", required=True, help="User name")
parser.add_argument("-d", "--domain", required=True, help="Domain name")
parser.add_argument("-p", "--password", required=True, help="Password of User")
parser.add_argument("-n", "--ntproofstr", required=True, help="NTProofStr. This can be found in PCAP (provide Hex Stream)")
parser.add_argument("-k", "--key", required=True, help="Encrypted Session Key. This can be found in PCAP (provide Hex Stream)")
parser.add_argument("-v", "--verbose", action="store_true", help="increase output verbosity")

args = parser.parse_args()

user = str(args.user).upper().encode('utf-16le')
domain = str(args.domain).upper().encode('utf-16le')

# Create 'NTLM' Hash of password
passw = args.password.encode('utf-16le')
hash1 = hashlib.new('md4', passw)
password = hash1.digest()

# Calculate the ResponseNTKey
h = hmac.new(password, digestmod=hashlib.md5)
h.update(user + domain)
respNTKey = h.digest()

# Use NTProofSTR and ResponseNTKey to calculate Key Exchange Key
NTproofStr = bytes.fromhex(args.ntproofstr)
h = hmac.new(respNTKey, digestmod=hashlib.md5)
h.update(NTproofStr)
KeyExchKey = h.digest()

# Calculate the Random Session Key by decrypting Encrypted Session Key with Key Exchange Key via RC4
RsessKey = generateEncryptedSessionKey(KeyExchKey, bytes.fromhex(args.key))

if args.verbose:
    print("USER WORK: " + user.decode('utf-16le') + " " + domain.decode('utf-16le'))
    print("PASS HASH: " + password.hex())
    print("RESP NT:   " + respNTKey.hex())
    print("NT PROOF:  " + NTproofStr.hex())
    print("KeyExKey:  " + KeyExchKey.hex())    

print("Random SK: " + RsessKey.hex())
```

Running the script with the correct parameters gives us the **Random Session Key**: `4147454a48564a4373437649574e504c`

![](https://i.imgur.com/rDZlwZC.png)

#### 4. Decrypt the SMB Traffic in WireShark
To decrypt the SMB traffic in Wireshark:
Go to `Edit > Preferences > Protocols > SMB2 > Secret session keys for decryption > Edit`

![](https://i.imgur.com/4ch2cHi.png)

#### 5. Extract the files
Once decrypted, we can extract the files using:
`File > Export Objects > SMB > Save All`

![](https://i.imgur.com/IbkE8cP.png)

#### 6. Analyze the Extracted Files
**wqpiZo**
```
"lsass.exe","840","Services","0","24,332 K","Unknown","NT AUTHORITY\SYSTEM","0:00:00","N/A"
```

**RxHmEj**
```
The minidump has an invalid signature, restore it running:
scripts/restore_signature 20241225_1939.log
Done, to get the secretz run:
python3 -m pypykatz lsa minidump 20241225_1939.log

python3 -m pypykatz lsa minidump 20241225_1939.log
```

**20241225_1939.log**
![](https://i.imgur.com/5E99tbB.png)

**nano.exe**
This is identified as `nanodump.exe` from [VirusTotal Scan](https://www.virustotal.com/gui/file/bc21f289cc113a77ca1f48900a321d8f0eff024634a9255becc8afda66c213bd/details), which can be found on [GitHub](https://github.com/fortra/nanodump).

Now we know that the `20241225_1939.log` can be used to get the minidump, then the next step is to restore the log file as the signature seems to be invalid MiniDump log file.

The method I used to restore is by downloading the `scripts/restore_signature` from the [NanoDump's GitHub](https://github.com/fortra/nanodump)  and run the script on the log file.

![](https://i.imgur.com/sXp9ZeW.png)

#### 7. Get the flag
The flag can be obtained by running the pypykatz module and read the mini dump.

![](https://i.imgur.com/Qhwswlj.png)

---

### Unwanted Meow
> Uh.. Oh.. Help me, I just browsing funny cats memes, when I click download cute cat picture, the file that been download seems little bit wierd. I accidently run the file making my files shredded. Ughh now I hate cat meowing at me.
> 
> Hint: We don't want meow here.

![](https://i.imgur.com/e1NxOCf.png)

Flag: `WGMY{4a4be40c96ac6314e91d93f38043a634}`

We are given a file named `flag.shredded`, which is a JPEG image file, but it appears to be corrupted.

![](https://i.imgur.com/BwbqBNV.png)

After opening the file in a text editor, it can be seen that the word `meow` is repeatedly placed throughout the file. To recover the image, I removed the `meow` entries and then added the `.jpeg` extension to the file.
![](https://i.imgur.com/Bcs2mil.png)

After this, the recovered image is still partially corrupted. To repair it, I used [JPEG Medic](https://www.jpegmedic.com/tools/jpegmedic/) to fix the image.

![](https://i.imgur.com/bbQbMLF.png)

After tinkering with JPEG Medic for a while, I was able to see part of the flag, even though the image was not fully recovered. The flag was visible in the partially restored image.

![](https://i.imgur.com/dEALXr4.png)

Upon reviewing other writeups for this challenge, I realized that the intended solution was actually hidden in plain sight, which I had not noticed earlier. Instead of repairing the image, the flag could have been obtained simply by removing the additional `meow` entries and viewing the image directly.

![](https://i.imgur.com/c1YkbOg.png)

After removing the second set of `meow` entries, the image was fully recovered, and the flag can be successfully obtained.

![](https://i.imgur.com/MJT8JWj.jpeg)

---

## Misc
### The DCM Meta
> [25, 10, 0, 3, 17, 19, 23, 27, 4, 13, 20, 8, 24, 21, 31, 15, 7, 29, 6, 1, 9, 30, 22, 5, 28, 18, 26, 11, 2, 14, 16, 12]
> 
> Hint: The element is the number in the list, combine for the flag. Wrap in wgmy{}

![](https://i.imgur.com/B2Gc7oG.png)

Flag: `WGMY{51fadeb6cc77504db336850d53623177}`

We are given a file with a `.dcm` extension, but the file itself only contains data.

![](https://i.imgur.com/WyD3cJj.png)

I used [CyberChef](https://cyberchef.org/#recipe=Regular_expression('User%20defined','%5C%5Cw',true,true,false,false,false,false,'List%20matches')) to extract all the words. From the indices provided in the description, the largest index is 31, which indicates that the data can only have 32 characters. Therefore, I also removed the padding `WGMY`. The extracted data is: `f63acd3b78127c1d7d3e700b55665354`

![](https://i.imgur.com/PjiUmHs.png)

Next, to obtain the actual flag, we use the indices provided in the challenge description: `[25, 10, 0, 3, 17, 19, 23, 27, 4, 13, 20, 8, 24, 21, 31, 15, 7, 29, 6, 1, 9, 30, 22, 5, 28, 18, 26, 11, 2, 14, 16, 12]`

By following these indices, we can rearrange the characters in the extracted string. To automate this process, I create a Python script:
**flag.py**
```python
element = "f63acd3b78127c1d7d3e700b55665354"
indices = [25, 10, 0, 3, 17, 19, 23, 27, 4, 13, 20, 8, 24, 21, 31, 15, 7, 29, 6, 1, 9, 30, 22, 5, 28, 18, 26, 11, 2, 14, 16, 12]

result = ''.join([element[i] for i in indices])

print("WGMY{"+result+"}")
```

![](https://i.imgur.com/PwjvaGM.png)

Fun Fact: 
*I asked ChatGPT to help me rearrange the extracted string using the indices provided. Unfortunately, I trusted ChatGPT without verifying the result, as it turns out, the output it provided was incorrect. Lesson learned: don't trust ChatGPT too much 😂*

![](https://i.imgur.com/5iUCmKQ.png)
