---
title: Kembara Tuah 3108 - Writeup
date: 2024-09-02
draft: false
description: Wargames CTF writeup
summary: "This is a CTF writeup for Kembara Tuah 3108 CTF."
tags: ["ctf"]
---

## Crypto
### Mesej Rahsia
> Tak susah pun, run je script

![](https://i.imgur.com/wwH04a4.png)

Flag: `3108{substitute_cipher_text}`

For this challenge, we are given a python script.
##### secretMessenger.py
```python
a,b,c,d,e,f,g,h,i,j,k,l,m,n,o,p,q,r,s,t,u,v,w,x,y,z='j','b','a','c','m','n','i','p','o','q','r','t','x','z','v','s','u','y','h','g','d','e','f','k','l','w'
flag=((3108,"{",p,q,b,p,l,g,l,q,l,v,"_",d,g,h,s,v,k,"_",l,v,m,l,"}")[::-1])
```

From the script we can see there's the flag variable set to the predefined variables in reverse.

Then what we can do is remove the slice notation and join the flag  and print it out. 
##### Solution.py
```python
a,b,c,d,e,f,g,h,i,j,k,l,m,n,o,p,q,r,s,t,u,v,w,x,y,z='j','b','a','c','m','n','i','p','o','q','r','t','x','z','v','s','u','y','h','g','d','e','f','k','l','w'
flag="".join(str(i) for i in (3108,"{",p,q,b,p,l,g,l,q,l,v,"_",d,g,h,s,v,k,"_",l,v,m,l,"}"))
print(flag)
```

![](https://i.imgur.com/FpXb5wc.png)

---

### Syah Sesat
> Semasa Syah berada di Muzium Kota Kayang, dia telah menyaksikan sebuah persembahan Gambus yang dipersembahkan oleh seorang pemuzik dari Sabah yang berkunjung ke muzium tersebut. Lagu yang dipersembahkan ketika itu bertajuk Ampuk Ampuk Bulan. Kagum akan persembahan tersebut, beliau telah meninggalkan satu pesanan di bawah bersama kunci. Bolehkan anda merungkaikan pesanan tersebut dan mendapatkan Flag?
> 
> Cipher : }AYPF_KYMSOL_TOMMNG{8013EJVWASCUQOYOAGNURBETMYUIBMTNHGMALKGZTXUBDPS 
> Key : AMPUKAMPUKBULAN

![](https://i.imgur.com/DLPTEpF.png)

Flag: `3108{GAMBUS_BUDAYA_LAMA}`

For this challenge, we are given a cipher text and a key.
##### Cipher Text
```
}AYPF_KYMSOL_TOMMNG{8013EJVWASCUQOYOAGNURBETMYUIBMTNHGMALKGZTXUBDPS
```
##### Key
```
AMPUKAMPUKBULAN
```

Given the cipher text and key, using [CyberChef](https://gchq.github.io/CyberChef/#recipe=Vigen%C3%A8re_Decode('AMPUKAMPUKBULAN')Reverse('Character')&input=fUFZUEZfS1lNU09MX1RPTU1OR3s4MDEzRUpWV0FTQ1VRT1lPQUdOVVJCRVRNWVVJQk1UTkhHTUFMS0daVFhVQkRQUw&oeol=FF) I tried to decode it using  Vigenère cipher and the output was noticeably reversed. So I reverse it and the flag can be seen.

![](https://i.imgur.com/i8iJjE3.png)

---

### Tanpa Nama 3
![](https://i.imgur.com/fRf6dCp.png)

Flag: `3108{S1MPL3_CRPYT0_CHALLENGE}`

For this challenge we are given a python script.
##### cryptochalle.py
```python
def xor_with_binary(binary_str, xor_str):
    binaries = binary_str.split()
    xor_num = int(xor_str, 2)
    xor_results = []
    for b in binaries:
        num = int(b, 2)
        result_num = num ^ xor_num
        xor_results.append(format(result_num, '08b'))
    return ' '.join(xor_results)

binary_str = "01010110 01010100 01010101 01011101 00011110 00110110 01010100 00101000 00110101 00101001 01010110 00111010 00100110 00110111 00110101 00111100 00110001 01010101 00111010 00100110 00101101 00100100 00101001 00101001 00100000 00101011 00100010 00100000 00011000"
xor_str = "01100101"
```

The function is XORing the binary_str with xor_str, what I did was place the arguments with the variables provided and print the output. Which I throw into [CyberChef](https://gchq.github.io/CyberChef/#recipe=From_Binary('Space',8)&input=MDAxMTAwMTEgMDAxMTAwMDEgMDAxMTAwMDAgMDAxMTEwMDAgMDExMTEwMTEgMDEwMTAwMTEgMDAxMTAwMDEgMDEwMDExMDEgMDEwMTAwMDAgMDEwMDExMDAgMDAxMTAwMTEgMDEwMTExMTEgMDEwMDAwMTEgMDEwMTAwMTAgMDEwMTAwMDAgMDEwMTEwMDEgMDEwMTAxMDAgMDAxMTAwMDAgMDEwMTExMTEgMDEwMDAwMTEgMDEwMDEwMDAgMDEwMDAwMDEgMDEwMDExMDAgMDEwMDExMDAgMDEwMDAxMDEgMDEwMDExMTAgMDEwMDAxMTEgMDEwMDAxMDEgMDExMTExMDEg&oeol=FF) and convert the binary string.

![](https://i.imgur.com/bbEMMyv.png)

---

### zZzZz
> ZZZZZ ZZZzZ ZZZZZ ZZZZZ ZzZZz ZZZZ ZZZ ZZ ZZZZZ ZZzZZ ZZzZZ ZzZZ ZZZZZZ ZZzZZ

![](https://i.imgur.com/V5nAFx8.png)

Flag: `3108{700ef4a79959615b67ea5297e725c06e}`

We were asked who the name of the Laksamana that killed Sultan Mahmud in 1699 and quick google search says that its *Laksamana Bentan* and submitting the answer shows the hex string.
![](https://i.imgur.com/yVhpu3A.png)

##### Hex string
```
0x33z0x31z0x30z0x380x7bz0x37z0x30z0x30z0x650x66z0x34z0x61z0x37z0x39z0x39z0x350x39z0x360x31z0x350x62z0x360x37z0x650x61z0x35z0x32z0x39z0x37z0x65z0x37z0x32z0x350x63z0x300x36z0x65z0x7dz
```

Using [CyberChef](https://gchq.github.io/CyberChef/#recipe=From_Hex('Auto')&input=MHgzM3oweDMxejB4MzB6MHgzODB4N2J6MHgzN3oweDMwejB4MzB6MHg2NTB4NjZ6MHgzNHoweDYxejB4Mzd6MHgzOXoweDM5ejB4MzUweDM5ejB4MzYweDMxejB4MzUweDYyejB4MzYweDM3ejB4NjUweDYxejB4MzV6MHgzMnoweDM5ejB4Mzd6MHg2NXoweDM3ejB4MzJ6MHgzNTB4NjN6MHgzMDB4MzZ6MHg2NXoweDdkeg&oeol=FF)to convert the hex will show us the flag
![](https://i.imgur.com/UXXesvp.png)

---

## Forensic
### Daerah Sabah & Sarawak
> Setiap negeri mempunyai daerah. Begitu juga negeri Sabah dan Sarawak mempunyai daerah tersendiri. Cari 'flag' yang mengandungi bilangan daerah Sabah dan Sarawak di dalam file tersebut.

![](https://i.imgur.com/uQlH1Fg.png)

Flag: `3108{S4B4H_27_D43RAH_S4R4W4K_40_D43R4H} `

We are given a zip file

![](https://i.imgur.com/caFKoMD.png)

Then I proceed to unzip the zip file and obtained 3 jpg file.

![](https://i.imgur.com/Xv3Hhlt.png)

These images does not show anything, so I tried to use [Stegoveritas](https://github.com/bannsec/stegoVeritas)to extract the *3.jpg* because it feels weird to have AI generated image to mix with the rest normal looking images. Also the file size seems to be larger than the rest that might indicate something is hidden within the image itself.

![](https://i.imgur.com/x1j2f7E.png)

![](https://i.imgur.com/CyuX0M3.png)

Stegoveritas managed to find an archived file hidden in the *3.jpg* extracted the file out.
![](https://i.imgur.com/0EIfvUQ.png)

I checked the file and it's a RAR archive file, I then proceed to extract the file and obtained a text file and a zip file.
![](https://i.imgur.com/TQ0XHUQ.png)

The *Daerah_Sabah&Sarawak.txt* contains the names of all the Town and City in Sabah and Sarawak.
![](https://i.imgur.com/pO2NqvE.png)

The *file.zip* however is AES encrypted. Which got me thinking that the given text file might be the wordlist that can be use for bruteforce.
![](https://i.imgur.com/7RZFhUB.png)

The password can be obtained by using *zip2john* and run JohnTheRipper using the wordlist above.
![](https://i.imgur.com/y5hGLFv.png)

After extracting the file, the flag can be obtained.

![](https://i.imgur.com/8qcnifm.png)

---

### Kontras
> Sekarang anda tidak dapat membaca dengan betul. Sejarah ringkas ini mempunyai beberapa data kritikal di dalamnya, beberapa daripadanya telah disunting dengan betul, manakala ada yang tidak. Bolehkah anda mencari kunci penting yang tidak disunting dengan betul?

![](https://i.imgur.com/nGRsWL9.png)

Flag: `3108{Peghak_Darul_ridzuAn}`

We are given a PDF file that seems to have redacted words. However, the PDF is not properly redacted and the text can still be highlighted and copied (*which is not supposed to happen*)
![](https://i.imgur.com/4M1bB7U.png)

I just copied the whole text to notepad and find the keyword `3108{` 

![](https://i.imgur.com/KKSLRcX.png)

---

### Lahad Datu
> Scott seorang bangsa Melayu kacukan darah British ingin mengetahui peristiwa hitam yang berlaku di Sabah yang ada di dalam dokumen "Lahad Datu". Tetapi dokumen tersebut mempunyai kata laluan. Bantu Scott untuk membuka dokumen berkenaan.

![](https://i.imgur.com/mMc7GNB.png)

Flag: `3108{0P3R4S1_D4UL4T}`

We are given an encrypted Word document. 

![](https://i.imgur.com/smeTOEU.png)

Without any hint given,  I tried to brute-force the password using JohnTheRipper with common wordlist. The brute-force process was rather quick and I used the password to open the Word document.
![](https://i.imgur.com/5Sp1Eky.png)

![](https://i.imgur.com/Rc6u1A5.png)

There's the flag at the bottom, but is it the real flag? Seems like gibberish to me, hence I notice the *JamalulKiramIII* that was bolded and thought that it might be used to decode the flag. So I go over to trusty [CyberChef](https://gchq.github.io/CyberChef/#recipe=Vigen%C3%A8re_Decode('JamalulKiramIII')&input=MzEwOHswWTNSNEUxX0Q0RkY0RX0)and used the Vigenère module to decode the flag.
![](https://i.imgur.com/Lh5U7XS.png)

---

### Pahlawan Lagenda
> Penyerang telah mencuba merosakkan dan menyembunyikan sesuatu di dalam data hikayat Hang Tuah yang sangat besar pada masa lalu, mungkin mereka masih melakukannya. Muat turun data di sini.

![](https://i.imgur.com/DBlJU9O.png)

Flag: `3108{gr3p_15_@w3s0m3_l4ks4m4n4}`

We are given a text file which is full of text, so I go ahead and CTRL+F the flag keyword `3108{`
![](https://i.imgur.com/U5wxgDn.png)

The flag can be obtained.

![](https://i.imgur.com/28H1xmh.png)

---

## Linux
### Cer Cari
> Setiap negeri mempunyai tarikh penting. CerCari Tarikh penting bagi negeri Sabah.

![](https://i.imgur.com/423MIY8.png)

Flag: `3108{S4b4h_1963}`

We are given a file with a bunch of strings with the flag format. However the hint is given in the description saying it's an important date for Sabah. Which got me thinking what could be more important than 1963 (formation of Malaysia). 

![](https://i.imgur.com/DeazHnx.png)

Grepping the keyword 1963 shows a match, which means the flag might be correct and it is indeed correct.

![](https://i.imgur.com/xSKudR6.png)

---

### Makanan Popular
> Sarawak mempunyai pelbagai makanan tradisional yang menarik. Cuba cari makanan tradisional yang popular di Sarawak di dalam file yang disediakan.

![](https://i.imgur.com/oCldYcu.png)

Flag: `3108{L4KS4_S4R4W4K}`

We are given an ELF executable file.

![](https://i.imgur.com/osuuago.png)

Hence, I tried running the file and got an output saying that I should try using strings. Which means that the flag can be grep.

![](https://i.imgur.com/mdKJ3Vu.png)

And we got my favourite food Laksa Sarawak!

![](https://i.imgur.com/qJFdDdz.png)

---

## Reverse
### Asal Nama Sabah
> Setiap negeri mempunyai asal nama negeri tersebut. Begitu juga dengan negeri Sabah. Sabah juga mempunyai nama asal negeri tersebut yang popular di kalangan masyarakat tempatan.

![](https://i.imgur.com/Aw97YoB.png)

Flag: `3108{S4B4H_S4PP4H}`

We are given an executable file for this challenge. I go ahead and throw the file to [DogBolt](https://dogbolt.org/?id=07d3a82f-ca8a-4e27-bd49-f3956982db49)(great platform to test various decompilers). After decompiling, I chose the Hex-Rays decompiler as it seems to be more readable.

The function that we should put our focus on is this *check_flag* function.

![](https://i.imgur.com/mAS3f5W.png)

Basically the each character from `s2` will be XORed with each character from `s`. With that I used ChatGPT to help me craft the script to decode the flag.
##### Solution.py
```python
s = "namaasalsabah"
s2 = "5d505d591a20552e47293d325c3e3159291c"
v4 = len(s) #13

# Convert hex string to a list of integers
s2_bytes = [int(s2[i:i+2], 16) for i in range(0, len(s2), 2)]

# XOR with corresponding characters from s
decoded_bytes = [s2_bytes[i] ^ ord(s[i % v4]) for i in range(len(s2_bytes))]

# Convert decoded bytes back to a string
decoded_string = ''.join(chr(b) for b in decoded_bytes)
print("Decoded flag:", decoded_string)
```

![](https://i.imgur.com/YNeEixF.png)

---

### Berenang Ke Tepian
> Berakit, berakitlah ke hulu Berenang, berenangku ke tepian Bersakit, biar kusakit dahulu Bersenang denganmu kemudian
> 
> Kelip-kelip kusangkakan api Sinar matahari membawa cahaya Kau hilang ghaib, sangkaku kaubenci Kiranya sengaja nak menduga

![](https://i.imgur.com/jUftMDS.png)

Flag: `3108{s1mpl3_p3ngundur4n}`

We are given an ELF executable and the NetCat connection to obtain the real flag.
![](https://i.imgur.com/i8MJf2W.png)

I uploaded the binary to [DogBolt](https://dogbolt.org/?id=c3b1ca86-5bbb-4bcd-8552-53b71bf68978#Hex-Rays=156&BinaryNinja=240) to decompile to understand the code and found something interesting. Which is the *Sleep* timer that is being applied given that the character is correct. If the character is wrong, then it will terminate without the *Sleep* timer being imposed. That means, we can exploit this functionality to brute-force the flag, this exploit is also known as Side Channel Attack (watch this [video](https://youtu.be/YRohz9VO1YY?si=P5032ZUSKD6Peuqq) to understand side channel attack)

![](https://i.imgur.com/sYTFw1z.png)

Now knowing that I asked ChatGPT to help me create a script to perform the attack. I set the flag length to 100 because I'm not sure how long the flag was and I just did it the "dirty" way. The brute-force process took a long time, there should be better solution to this.
```python
import socket
import time
import string

def send_input_and_measure_time(input_string, remote_ip, remote_port):
    """Send input to the remote service and measure the time taken for a response."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    try:
        s.connect((remote_ip, remote_port))
        s.sendall((input_string + '\n').encode())
        
        start_time = time.perf_counter()
        response = receive_response(s)
        end_time = time.perf_counter()
        
        response_time = end_time - start_time
        
    finally:
        s.close()
    
    return response_time, response

def receive_response(sock):
    """Receive the full response from the server."""
    response = b''
    while True:
        chunk = sock.recv(4096)
        if not chunk:
            break
        response += chunk
        if b'\n' in response:
            break
    return response.decode()

def find_flag_character(position, current_flag, remote_ip, remote_port):
    """Determine the best character for the given position in the flag."""
    characters = string.ascii_letters + string.digits + string.punctuation
    best_char = ''
    max_time = 0
    
    for char in characters:
        guess = current_flag + char
        response_time, _ = send_input_and_measure_time(guess, remote_ip, remote_port)
        if response_time > max_time:
            max_time = response_time
            best_char = char
    
    return best_char

def recover_flag(remote_ip, remote_port, known_prefix):
    """Recover the full flag by guessing each character, starting from a known prefix."""
    flag = known_prefix
    flag_length = 100  # Initial guess for the length of the flag
    
    for i in range(len(known_prefix), flag_length):
        flag += find_flag_character(i, flag, remote_ip, remote_port)
        print(f"Flag so far: {flag}")
    
    print(f"Recovered Flag: {flag}")

# Example usage
remote_ip = '103.28.91.24'  # Remote IP address
remote_port = 10020          # Remote port
known_prefix = "3108{"  # Known initial part of the flag
recover_flag(remote_ip, remote_port, known_prefix)
```

The flag can be obtained after the brute-force process finished.

![](https://i.imgur.com/lwCJ9xj.png)

---

### Ilmu Hisab
> Mampukah tuan hamba mengira?

![](https://i.imgur.com/lIEQzHF.png)

Flag: `3108{n0mb0r_k3r4mat}`

We are given an ELF file to reverse and NetCat connection to get the actual flag.
![](https://i.imgur.com/FTdhG57.png)

Using [DogBolt](https://dogbolt.org/?id=1e45d5b6-d3ee-4bf3-ab36-d037be422064#Hex-Rays=272&BinaryNinja=240)we can look at the decompiled code. At which we would put our attention to the function `addtwonumber` which will accept two values where
`v9` = first value
`v10` = second value

![](https://i.imgur.com/k5dECPw.png)

Notice that the first highlighted If statement checks if the the value of `v9` is less than `MAX Numeric Limit - 83647`. 

Then the second highlighted If statement checks 
If the value of `v9` = 1337 AND `v10` greater than 7331 AND the sum of both value needs to be less than 0. (Impossible)
OR
If the value of `v9` less than 0 AND `v10` less than 0 AND sum of both more than 0 (Impossible)

The If statement seems to be impossible to achieve *merdeka* function. But not with Integer Overflow. (Watch this video: [Overflow in Signed and Unsigned Numbers](https://youtu.be/7towQUO9aZI?si=Zy4yzxgvuegIzmum&t=345))

To obtain merderka function. We can add `v9 + v10 > 2147483647` which is the *MAX Numeric Limit*. Using the first condition where `v9` = 1337 AND `v10` greater than 7331 to perform the overflow. Since we know that `v9` cannot be changed, we need to find `v10`.
`v10 = 2147483657 - 1336 = 2147482321`

With that we can reach *merdeka* function which will reveal the flag.

![](https://i.imgur.com/8hc7wYL.png)

---

### Sarawak Kita
> Ada pendapat yang menyatakan bahawa Kuching mendapat nama sempena sebatang sungai kecil, Sungai Kuching yang mengalir di antara Muzium Cina dan Kuil Tua Pek Kong. Sungai Kuching pula barangkali memperoleh nama daripada Kucing Hutan yang kerap mengunjunginya. Sungai tersebut juga berhampiran dengan sebuah bukit yang banyak ditumbuhi oleh pokok Buah Mata Kucing. Lantaran tersebut ianya diberi nama Bukit Mata Kucing. Tapi ini bukan tentang kisah Kuching, ini kisah bagaimana ingin mendapatkan 'flag' di dalam document yang berbahaya.

![](https://i.imgur.com/dcU2nVK.png)

Flag: `3108{Kuch1ng_1bu_N3g3r1_S4r4w4k}`

We are given a Word Document, using [oleid](https://github.com/decalage2/oletools/wiki/oleid)it can be seen that the document contains VBA macros
![](https://i.imgur.com/ZDUpAGV.png)

With that I used [olevba](https://github.com/decalage2/oletools/wiki/olevba) to read the VBA code, and found a Base64 hash
![](https://i.imgur.com/OlwJFZV.png)

As always I will use the trusty [CyberChef](https://gchq.github.io/CyberChef/#recipe=From_Base64('A-Za-z0-9%2B/%3D',true,false)Remove_null_bytes()&input=TXdBeEFEQUFPQUI3QUVzQWRRQmpBR2dBTVFCdUFHY0FYd0F4QUdJQWRRQmZBRTRBTXdCbkFETUFjZ0F4QUY4QVV3QTBBSElBTkFCM0FEUUFhd0I5QUE9PQ) to decode the Base64 and obtained the flag.
![](https://i.imgur.com/hc4crqg.png)

This [article](https://intezer.com/blog/malware-analysis/analyze-malicious-microsoft-office-files/)from Intezer explains in detail how to analyze Microsoft Office files.

---

## Web
### Selangorku
> Hi semua saya @AnakSelangor86. Saya seorang Web Developer yang mempunyai semangat patriotik yang tinggi terhadap kemerdekaan terutamanya negeri selangor saya ada cipta satu website mengenai selangor dan hanya orang tertentu sahaja bole access ke website tersebut :)
> 
> selamat mencubaa perwira!!!!

![](https://i.imgur.com/iE1Y2Cm.png)


Flag: `3108{S3lang0r_temp4t_kelahiran_ku}`

Trying to access the webpage will give us 403 Forbidden. I then go and search online for any possible solution and found this [writeup](https://ctftime.org/writeup/10788)
![](https://i.imgur.com/oHUurJq.png)

Then I tried using Curl with X-Forwarderd-For header to local host.
```
curl -v <url> -H 'X-Forwarded-For: 127.0.0.1'
```

Which I am able to access the site and it shows a list of html files. I tried to access it using the above method and found the flag at the hulu_selangor.html 
![](https://i.imgur.com/TqAi0FK.png)

![](https://i.imgur.com/vgdgHlh.png)

I found this to be quite similar and very helpful resource [Cyber Plumber Handbook](https://github.com/opsdisk/the_cyber_plumbers_handbook/blob/master/cph_version_1.4_20210829.pdf), which teach about ways to navigate around the network using SSH and port redirection.