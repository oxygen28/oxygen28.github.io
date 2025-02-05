---
title: Cyber Apocalypse 2024 - Writeup
date: 2024-03-13
draft: false
description: Cyber Apocalypse 2024 writeup
summary: This is a CTF writeup for Cyber Apocalypse 2024.
tags: ["ctf"]
---

## Crypto
### Dynastic
> You find yourself trapped inside a sealed gas chamber, and suddenly, the air is pierced by the sound of a distorted voice played through a pre-recorded tape. Through this eerie transmission, you discover that within the next 15 minutes, this very chamber will be inundated with lethal hydrogen cyanide. As the tape’s message concludes, a sudden mechanical whirring fills the chamber, followed by the ominous ticking of a clock. You realise that each beat is one step closer to death. Darkness envelops you, your right hand restrained by handcuffs, and the exit door is locked. Your situation deteriorates as you realise that both the door and the handcuffs demand the same passcode to unlock. Panic is a luxury you cannot afford; swift action is imperative. As you explore your surroundings, your trembling fingers encounter a torch. Instantly, upon flipping the switch, the chamber is bathed in a dim glow, unveiling cryptic letters etched into the walls and a disturbing image of a Roman emperor drawn in blood. Decrypting the letters will provide you the key required to unlock the locks. Use the torch wisely as its battery is almost drained out!

![](https://i.imgur.com/AafS5aD.png)

Flag: `HTB{DID_YOU_KNOW_ABOUT_THE_TRITHEMIUS_CIPHER?!_IT_IS_SIMILAR_TO_CAESAR_CIPHER}`

For this challenge, there are 2 files. The output file and also the source code.
##### Output.txt
```txt
Make sure you wrap the decrypted text with the HTB flag format :-]
DJF_CTA_SWYH_NPDKK_MBZ_QPHTIGPMZY_KRZSQE?!_ZL_CN_PGLIMCU_YU_KJODME_RYGZXL
```
##### Source.py
```python
from secret import FLAG
from random import randint

def to_identity_map(a):
    return ord(a) - 0x41

def from_identity_map(a):
    return chr(a % 26 + 0x41)

def encrypt(m):
    c = ''
    for i in range(len(m)):
        ch = m[i]
        if not ch.isalpha():
            ech = ch
        else:
            chi = to_identity_map(ch)
            ech = from_identity_map(chi + i)
        c += ech
    return c

with open('output.txt', 'w') as f:
    f.write('Make sure you wrap the decrypted text with the HTB flag format :-]\n')
    f.write(encrypt(FLAG))
```

This is a simple algorithm to encrypt the data. Here's how it works:
1. It will iterate through all of the data one by one.
2. Check if the character is alphabet letters, 
   - *True*: Minus the hex value of that ASCII character with 0x41, and then get the value of modulo 26 of the minus value and add 0x41 to it. After that, add the value with the current number of iteration. Then append the value into a variable X.
   - *False*: Append that value into a variable X.
3. Append the value from above into the variable Crypt.
4. Return the value Crypt.

The solution is very simple, just by reversing the steps used to encrypt the flag and the flag can be obtained.
##### Solution.py
```python
#from secret import FLAG
#from random import randint

def to_identity_map(a):
    return ord(a) - 0x41

def from_identity_map(a):
    return chr(a % 26 + 0x41)

def encrypt(m):
    c = ''
    for i in range(len(m)):
        ch = m[i]
        if not ch.isalpha(): # If not a character
            ech = ch
        else: #If it's a character
            chi = to_identity_map(ch)
            ech = from_identity_map(chi + i)
        c += ech
    return c

def decrypt(flag):
	unencrypted_text = ''
	for i in range(len(flag)):
		char = flag[i]
		if not char.isalpha():
			dchar = char
		else:
			ichar = to_identity_map(char)
			dchar = from_identity_map(ichar - i)
		unencrypted_text += dchar
	return unencrypted_text

#with open('output.txt', 'w') as f:
#    f.write('Make sure you wrap the decrypted text with the HTB flag #format :-]\n')
#    f.write(encrypt(FLAG))
flag = "DJF_CTA_SWYH_NPDKK_MBZ_QPHTIGPMZY_KRZSQE?!_ZL_CN_PGLIMCU_YU_KJODME_RYGZXL"

print("HTB{".decrypt(flag)."}")
```

![](https://i.imgur.com/TvLpwXw.png)

---

### Iced Tea
> Locked within a cabin crafted entirely from ice, you're enveloped in a chilling silence. Your eyes land upon an old notebook, its pages adorned with thousands of cryptic mathematical symbols. Tasked with deciphering these enigmatic glyphs to secure your escape, you set to work, your fingers tracing each intricate curve and line with determination. As you delve deeper into the mysterious symbols, you notice that patterns appear in several pages and a glimmer of hope begins to emerge. Time is flying and the temperature is dropping, will you make it before you become one with the cabin?

![](https://i.imgur.com/lnb4AQ1.png)

Flag: `HTB{th1s_1s_th3_t1ny_3ncryp710n_4lg0r1thm_y0u_m1ght_h4v3_4lr34dy_s7umbl3d_up0n_1t_1f_y0u_d0_r3v3rs1ng}`

Given 2 file, one output and one source as shown below. 
##### Output.txt
```
Key : 850c1413787c389e0b34437a6828a1b2
Ciphertext : b36c62d96d9daaa90634242e1e6c76556d020de35f7a3b248ed71351cc3f3da97d4d8fd0ebc5c06a655eb57f2b250dcb2b39c8b2000297f635ce4a44110ec66596c50624d6ab582b2fd92228a21ad9eece4729e589aba644393f57736a0b870308ff00d778214f238056b8cf5721a843
```
##### Source.py
```python
import os
from secret import FLAG
from Crypto.Util.Padding import pad
from Crypto.Util.number import bytes_to_long as b2l, long_to_bytes as l2b
from enum import Enum

class Mode(Enum):
    ECB = 0x01
    CBC = 0x02

class Cipher:
    def __init__(self, key, iv=None):
        self.BLOCK_SIZE = 64
        self.KEY = [b2l(key[i:i+self.BLOCK_SIZE//16]) for i in range(0, len(key), self.BLOCK_SIZE//16)]
        self.DELTA = 0x9e3779b9
        self.IV = iv
        if self.IV:
            self.mode = Mode.CBC
        else:
            self.mode = Mode.ECB
    
    def _xor(self, a, b):
        return b''.join(bytes([_a ^ _b]) for _a, _b in zip(a, b))

    def encrypt(self, msg):
        msg = pad(msg, self.BLOCK_SIZE//8)
        blocks = [msg[i:i+self.BLOCK_SIZE//8] for i in range(0, len(msg), self.BLOCK_SIZE//8)]
        
        ct = b''
        if self.mode == Mode.ECB:
            for pt in blocks:
                ct += self.encrypt_block(pt)
        elif self.mode == Mode.CBC:
            X = self.IV
            for pt in blocks:
                enc_block = self.encrypt_block(self._xor(X, pt))
                ct += enc_block
                X = enc_block
        return ct

    def encrypt_block(self, msg):
        m0 = b2l(msg[:4])
        m1 = b2l(msg[4:])
        K = self.KEY
        msk = (1 << (self.BLOCK_SIZE//2)) - 1

        s = 0
        for i in range(32):
            s += self.DELTA
            m0 += ((m1 << 4) + K[0]) ^ (m1 + s) ^ ((m1 >> 5) + K[1])
            m0 &= msk
            m1 += ((m0 << 4) + K[2]) ^ (m0 + s) ^ ((m0 >> 5) + K[3])
            m1 &= msk
        
        m = ((m0 << (self.BLOCK_SIZE//2)) + m1) & ((1 << self.BLOCK_SIZE) - 1) # m = m0 || m1

        return l2b(m)



if __name__ == '__main__':
    KEY = os.urandom(16)
    cipher = Cipher(KEY)
    ct = cipher.encrypt(FLAG)
    with open('output.txt', 'w') as f:
        f.write(f'Key : {KEY.hex()}\nCiphertext : {ct.hex()}')


```

By the name of the challenge, I begin with searching "Iced Tea encryption" on Google and I found out a Wiki [page](https://en.wikipedia.org/wiki/XTEA) explaining the eXtended Tiny Encryption Algorithm. The cipher code was similar to the one provided 
![](https://i.imgur.com/CVNLPh4.png)

I used ChatGPT to help me understand the code and come with the following script to decrypt the flag.
```python
from Crypto.Util.Padding import unpad
from Crypto.Util.number import bytes_to_long as b2l, long_to_bytes as l2b
from enum import Enum
import os

class Mode(Enum):
    ECB = 0x01
    CBC = 0x02

class Cipher:
    def __init__(self, key, iv=None):
        self.BLOCK_SIZE = 64
        self.KEY = [b2l(key[i:i+self.BLOCK_SIZE//16]) for i in range(0, len(key), self.BLOCK_SIZE//16)]
        self.DELTA = 0x9e3779b9
        self.IV = iv
        if self.IV:
            self.mode = Mode.CBC
        else:
            self.mode = Mode.ECB
    
    def _xor(self, a, b):
        return b''.join(bytes([_a ^ _b]) for _a, _b in zip(a, b))

    def decrypt(self, ct):
        blocks = [ct[i:i+self.BLOCK_SIZE//8] for i in range(0, len(ct), self.BLOCK_SIZE//8)]
        
        pt = b''
        if self.mode == Mode.ECB:
            for ct_block in blocks:
                pt += self.decrypt_block(ct_block)
        elif self.mode == Mode.CBC:
            X = self.IV
            for ct_block in blocks:
                pt_block = self._xor(X, self.decrypt_block(ct_block))
                pt += pt_block
                X = ct_block
        return pt

    def decrypt_block(self, ct):
        c = b2l(ct)
        m0 = c >> (self.BLOCK_SIZE//2)
        m1 = c & ((1 << (self.BLOCK_SIZE//2)) - 1)
        K = self.KEY
        msk = (1 << (self.BLOCK_SIZE//2)) - 1

        s = self.DELTA << 5
        for i in range(32):
            m1 -= ((m0 << 4) + K[2]) ^ (m0 + s) ^ ((m0 >> 5) + K[3])
            m1 &= msk
            m0 -= ((m1 << 4) + K[0]) ^ (m1 + s) ^ ((m1 >> 5) + K[1])
            m0 &= msk
            s -= self.DELTA
        
        m = ((m0 << (self.BLOCK_SIZE//2)) + m1) & ((1 << self.BLOCK_SIZE) - 1) # m = m0 || m1

        return l2b(m)

# Parse Key and Ciphertext from file
with open('output.txt', 'r') as f:
    lines = f.readlines()
    KEY = bytes.fromhex(lines[0].split(":")[1].strip())
    ct_hex = lines[1].split(":")[1].strip()

# Initialize Cipher object with Key
cipher = Cipher(KEY)

# Decrypt Ciphertext
ct = bytes.fromhex(ct_hex)
pt = cipher.decrypt(ct)

# Remove Padding
pt = unpad(pt, cipher.BLOCK_SIZE//8)

print("Decrypted plaintext:", pt.decode())

```

![](https://i.imgur.com/0zpz8CT.png)

---

### Makeshift
> Weak and starved, you struggle to plod on. Food is a commodity at this stage, but you can’t lose your alertness - to do so would spell death. You realise that to survive you will need a weapon, both to kill and to hunt, but the field is bare of stones. As you drop your body to the floor, something sharp sticks out of the undergrowth and into your thigh. As you grab a hold and pull it out, you realise it’s a long stick; not the finest of weapons, but once sharpened could be the difference between dying of hunger and dying with honour in combat.

![](https://i.imgur.com/ffHvLnU.png)


Flag: `HTB{4_b3tTeR_w3apOn_i5_n3edeD!?!}`

For this challenge we are given an output file and a source file as below.
##### Output.txt
```
!?}De!e3d_5n_nipaOw_3eTR3bt4{_THB
```
##### Source.py
```python
from secret import FLAG

flag = FLAG[::-1]
new_flag = ''

for i in range(0, len(flag), 3):
    new_flag += flag[i+1]
    new_flag += flag[i+2]
    new_flag += flag[i]

print(new_flag)

```

It is a simple algorithm which works as follow:
1. Inverse the value of the flag.
2. Create a variable called new_flag.
3. In a for loop, iterate every 3 step until it reached the end of the value of the flag and append the value in the order of *2nd*, *3rd*, and *1st* position. (Let's say there's a string of "ABC" the algorithm will append the string in such order "BCA").

| Pos | Original Value | Value After |
| --- | -------------- | ----------- |
| 1   | A              | B           |
| 2   | B              | C           |
| 3   | C              | A           |

After knowing that, I started writing the script to reverse the algorithm, which is by appending the value of the given string in the order of *3rd*, *1st*, and *2nd* position to obtain the value and inverse it to obtain the original flag.
```python
new_flag = "!?}De!e3d_5n_nipaOw_3eTR3bt4{_THB"
old_flag = ""
for i in range (0,len(new_flag),3):
	old_flag += new_flag[i+2]
	old_flag += new_flag[i]
	old_flag += new_flag[i+1]
	
print(old_flag[::-1])
```

![](https://i.imgur.com/W6Zpv3v.png)

---

### Primary Knowledge
> Surrounded by an untamed forest and the serene waters of the Primus river, your sole objective is surviving for 24 hours. Yet, survival is far from guaranteed as the area is full of Rattlesnakes, Spiders and Alligators and the weather fluctuates unpredictably, shifting from scorching heat to torrential downpours with each passing hour. Threat is compounded by the existence of a virtual circle which shrinks every minute that passes. Anything caught beyond its bounds, is consumed by flames, leaving only ashes in its wake. As the time sleeps away, you need to prioritise your actions secure your surviving tools. Every decision becomes a matter of life and death. Will you focus on securing a shelter to sleep, protect yourself against the dangers of the wilderness, or seek out means of navigating the Primus’ waters?

![](https://i.imgur.com/DSXRs2V.png)


Flag: `HTB{0h_d4mn_4ny7h1ng_r41s3d_t0_0_1s_1!!!}`

We are given 2 file, one output.txt and one source.py as follow:
##### Output.txt
```
n = 144595784022187052238125262458232959109987136704231245881870735843030914418780422519197073054193003090872912033596512666042758783502695953159051463566278382720140120749528617388336646147072604310690631290350467553484062369903150007357049541933018919332888376075574412714397536728967816658337874664379646535347
e = 65537
c = 15114190905253542247495696649766224943647565245575793033722173362381895081574269185793855569028304967185492350704248662115269163914175084627211079781200695659317523835901228170250632843476020488370822347715086086989906717932813405479321939826364601353394090531331666739056025477042690259429336665430591623215
```

##### Source.py
```python
import math
from Crypto.Util.number import getPrime, bytes_to_long
from secret import FLAG

m = bytes_to_long(FLAG)

n = math.prod([getPrime(1024) for _ in range(2**0)])
e = 0x10001
c = pow(m, e, n)

with open('output.txt', 'w') as f:
    f.write(f'{n = }\n')
    f.write(f'{e = }\n')
    f.write(f'{c = }\n')
```

I noticed that the source code reassemble RSA encryption algorithm. The output provided the value of n, e and c. The value of n seems to be single value of prime number with the for loop (multiplied to 0). Hence I wrote the code to decrypt the value of the flag as below.

##### Solution.py
```python
from Crypto.Util.number import inverse, long_to_bytes

n = 144595784022187052238125262458232959109987136704231245881870735843030914418780422519197073054193003090872912033596512666042758783502695953159051463566278382720140120749528617388336646147072604310690631290350467553484062369903150007357049541933018919332888376075574412714397536728967816658337874664379646535347
e = 65537
c = 15114190905253542247495696649766224943647565245575793033722173362381895081574269185793855569028304967185492350704248662115269163914175084627211079781200695659317523835901228170250632843476020488370822347715086086989906717932813405479321939826364601353394090531331666739056025477042690259429336665430591623215

# Calculate the modular inverse of e modulo (p-1)(q-1)
# Assuming n is the product of two large primes p and q
# Since we don't know p and q, we can't directly calculate phi(n), so we'll use the alternative approach
d = inverse(e, (n - 1))

# Decrypt the ciphertext
m = pow(c, d, n)

print("Decrypted message (m):", long_to_bytes(m))
```

![](https://i.imgur.com/uX1TPgS.png)

---

## Forensic
### Urgent
> In the midst of Cybercity's "Fray," a phishing attack targets its factions, sparking chaos. As they decode the email, cyber sleuths race to trace its source, under a tight deadline. Their mission: unmask the attacker and restore order to the city. In the neon-lit streets, the battle for cyber justice unfolds, determining the factions' destiny.

![](https://i.imgur.com/oOTGsaH.png)

Flag: `HTB{4n0th3r_d4y_4n0th3r_ph1shi1ng_4tt3mpT}`

The files given for this challenge was a file Electric Mail Format file extension. I then search for more information about this file extension and I came across [emlAnalyzer](https://github.com/wahlflo/eml_analyzer) tool to view the content of the EML file and also extracting data from it.

After installing the tool, I started reading the help guide and learn how to use the tool. I first started analyze the file and found out that there's a HTML attachment.
![](https://i.imgur.com/Dm2zJAS.png)

Upon further reading on the help guide, the emlAnlayzer can also extract the attachment from the EML file. So I proceed to extract the HTML file out.
![](https://i.imgur.com/cq5DHJA.png)

I then open the extracted HTML file in the browser but it shows 404 Not Found. I then proceed to view the source of the HTML file itself and found something.
![](https://i.imgur.com/rgtUCtI.png)

It is an encoded JavaScript code. Since the code was not heavily obfuscated I can easily decode the encoded script.
![](https://i.imgur.com/O0Ywbk4.png)

I just use the console of the browser and use the `console.log()` and `unescape()` function to obtain the flag.
![](https://i.imgur.com/DgZ5qdL.png)

I also noticed that the flag can be obtained via the Inspect Element tool of the browser.![](https://i.imgur.com/XLmoy4R.png)

Other than that, I also found out that the EML file is an ASCII text file and I output the content of the file and got a Base64 encoded data of the attachment.
![](https://i.imgur.com/QxvQ5uh.png)

![](https://i.imgur.com/J3sPuCw.png)

I proceed to use [CyberChef](https://gchq.github.io/CyberChef/)to decode the Base64 data, and I obtained the same value as when I view the page source of the HTML file.
![](https://i.imgur.com/wDZqjns.png)

---

### Phreaky
> In the shadowed realm where the Phreaks hold sway,
A mole lurks within, leading them astray.
Sending keys to the Talents, so sly and so slick,
A network packet capture must reveal the trick.
Through data and bytes, the sleuth seeks the sign,
Decrypting messages, crossing the line.
The traitor unveiled, with nowhere to hide,
Betrayal confirmed, they'd no longer abide.

![](https://i.imgur.com/arVPHF0.png)

Flag: `HTB{Th3Phr3aksReadyT0Att4ck}`

The file given is a PCAP file, hence I opened it using WireShark to analyze it. First I open up the Capture File Properties to identify what am I dealing with.
![Capture File Properties](https://i.imgur.com/gL8arNf.png)

I then dig into the Protocol Hierarchy Statistics and found out that most of there's a huge portion in Internet Message Format and HTTP. So I then applied the filter to filter the IMF protocol first.
![](https://i.imgur.com/COmphmL.png)

I found out that there's plain text data of the password and also filename, and I noticed that the file type is in ZIP format. I then search online on how to extract file from WireShark and found [this](https://youtu.be/Fn__yRYW6Wo?si=Vb2-AJyLFGH5g4ID) video on YouTube which guide on how to export the data from WireShark. I also note down all of the filename and password for the extraction of data later.
![](https://i.imgur.com/ach8zqs.png)

I then proceed to export the file from WireShark and noticed that the content type of the exports are EML.
![](https://i.imgur.com/zvKPl9m.png)

I proceed to use the [emlAnalyzer](https://github.com/wahlflo/eml_analyzer) to extract the ZIP file from the all of the exported EML file from WireShark earlier.
![](https://i.imgur.com/FH7JMkp.png)

Here's where the filename and password from earlier comes in handy. I just pasted the password to extract the file for each of the ZIP file extracted and I got these PDF fragments.
![](https://i.imgur.com/BnRMY8U.png)

So, I just use a simple command to combine all these PDF fragments into one combined PDF file.
![](https://i.imgur.com/leZ7fFd.png)

After that, I open up the combined pdf and found the flag.
![](https://i.imgur.com/TWLzM2M.png)

---

## Hardware
### Maze
> In a world divided by factions, "AM," a young hacker from the Phreaks, found himself falling in love with "echo," a talented security researcher from the Revivalists. Despite the different backgrounds, you share a common goal: dismantling The Fray. You still remember the first interaction where you both independently hacked into The Fray's systems and stumbled upon the same vulnerability in a printer. Leaving behind your hacker handles, "AM" and "echo," you connected through IRC channels and began plotting your rebellion together. Now, it's finally time to analyze the printer's filesystem. What can you find?

![](https://i.imgur.com/dEo19eF.png)

Flag: `HTB{1n7323571n9_57uff_1n51d3_4_p21n732}`

Given the file system to the printer. I first list out the directories of the file system to see what folders do I have.
![](https://i.imgur.com/MCd5xNT.png)

The saveDevice seems to be interesting folder and might hold some data used by the to printer documents. Hence, I started digging into the the directory.
![](https://i.imgur.com/m1zue9E.png)

I came across this PDF file while digging through the file system and I opened it with a PDF viewer and managed to find the flag in the PDF.
![[Pasted image 20240310035535.png]]

---

## Misc
### Stop Drop and Roll
> The Fray: The Video Game is one of the greatest hits of the last... well, we don't remember quite how long. Our "computers" these days can't run much more than that, and it has a tendency to get repetitive...

![](https://i.imgur.com/8ZyPfgM.png)

Flag: `HTB{1_wiLl_sT0p_dR0p_4nD_r0Ll_mY_w4Y_oUt!}`

Given a docker instance, I used `netcat` to access the docker instance and I am greeted with the prompt below.
![](https://i.imgur.com/FHih3Np.png)

![](https://i.imgur.com/KQqT1hJ.png)
I started to type in the response with the instruction given above, however I do feel like this is going to be tough by manually inputting the response. As the description of the challenge mentioned that the program would be repetitive. Therefore, my first thought would be creating a script to automate the response.

```python
import socket
import time

def play_game():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect(('83.136.254.167', 31113))  # Connect to the game server
        
        # Start the game
        data = s.recv(1024).decode()  # Receive initial message
        print(data)  # Print the initial message
        # Confirm readiness
        s.sendall(b'y\n')  # Send 'y' to confirm readiness
        time.sleep(1) # Delay before starting the confirmation
        
        # Repeat the response process until no data received.
        while True:
            data = s.recv(1024).decode()  # Receive game scenario
            if not data:  # If no data received, break the loop
                break
            print(data)  # Print the game scenario
            scenarios = data.strip().split(', ')  # Split the scenario into individual elements
            print("Scenarios:",scenarios)
            response = ""  # Initialize response string
            for scenario in scenarios:
                if "FIRE" in scenario:
                    response += "ROLL-"  # If scenario contains FIRE, append ROLL to response
                elif "GORGE" in scenario:
                    response += "STOP-"  # If scenario contains GORGE, append STOP to response
                elif "PHREAK" in scenario:
                    response += "DROP-"  # If scenario is PHREAK, append DROP to response
            response = response[:-1]  # Remove the last '-' from the response
            print("Response:", response)  # Print the response
            s.sendall(response.encode() + b'\n')  # Send the response to the server
            time.sleep(1) # Delay for 1 second
            

if __name__ == "__main__":
    play_game()  # Call the play_game function to start the game

```

![](https://i.imgur.com/eRKUFKP.gif)

After few minutes of running the script I got the flag.
![](https://i.imgur.com/hL6e7Cf.png)

---

## Rev
### Lootstash
> A giant stash of powerful weapons and gear have been dropped into the arena - but there's one item you have in mind. Can you filter through the stack to get to the one thing you really need?

![](https://i.imgur.com/hYdh5QO.png)

Flag: `HTB{n33dl3_1n_a_l00t_stack}`

The file given is an ELF file, and the description of the challenge mentioned about filter through the stack.
![](https://i.imgur.com/kAwo7M1.png)

So what I did was using `strings` to get the string value of the file and use `grep` to filter the keyword of the flag which is HTB and that is how I obtained the flag.
![](https://i.imgur.com/1EmmLHI.png)
