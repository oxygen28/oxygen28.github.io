
---

title: idekCTF 2025

  

date: 2025-08-04

  

draft: false

  

description: "This page contain writeup for SOC intern tasking of misc challenge from the idekCTF 2025."

  

summary: "This page contains idekCTF 2025 writeups, covering SOC intern tasking in the misc category."

  

tags: ["ctf"]

  

categories: ["ctf"]

  

---
# SOC intern tasking
>You are a brand new intern on the job, and, day one, some crucial data got stolen from your servers. You see a strange IP and some strange requests, but you can't quite figure out what he stole. You have til the end of the day to figure it out, or you're fired!

Flag: `idek{th1nk1ng_l1k3_a_r3d_t3amer}`

#ctf #foresnic #misc #pcap

*Disclaimer: I did not manage to solve this during the CTF, but here's what I've learned so far.*
## evil.pcapng
We are given a packet capture of a exfiltration traffic. Starting off there's a GET request to `143.198.13.84/instructions.png`.
![](https://i.imgur.com/QC9SiO7.png)

Let's preview that image by `File > Export Objects > HTTP > (Select instructions.png and preview)`. It says to not forget about the reverse proxy. The team did some stego checks and found nothing in the image as well.
![](https://i.imgur.com/eJAgCEp.png)

After that, it is observed that multiple GET requests to `143.198.13.84` with different user agents are responded with the `status 404`. It could be that these requested path does not exists. 
*However do note that the request to `/instructions.png` is responded with `status 200`.*
![](https://i.imgur.com/6BkfkY7.png)


There's also a GET request to `143.198.13.84/password.txt` but it was responded with `404 Not Found`. The user agent used here is CURL, which may or may not indicate hands on keyboard activity by the attacker. But it is worth noting that the path `/password.txt` might be something important. 
![](https://i.imgur.com/5y2kEKq.png)


Looking through the entire packet capture, towards `143.198.13.84` there's only GET request. So the data exfiltration should be through the path requested, but how do we filter it? 

*found the Trend Micro Easter egg here : )*
![](https://i.imgur.com/RGrvEwI.png)


Let's first try with navigating to `143.198.13.84/instructions.png` from the browser, weird that it shows as `404 Not Found` as the packet capture shows response `status 200`.
![](https://i.imgur.com/9a5N8PN.png)

After changing the user agent to `my-python-requests-useragent` as observed in the packet capture and we can successfully view the `instructions.png`.
![](https://i.imgur.com/ppz5MEs.png)

Now let's try accessing the `password.txt` and it can be accessed without throwing the `404 Not Found`. The password `verysecureidek2025themedpassword` might be used for the encryption of the exfiltrated data.
![](https://i.imgur.com/mV13AWD.png)

Knowing that the user agent might be the key factor here, we can use the `my-python-requests-useragent` user agent as filter criteria and extract all the GET request path. ![](https://i.imgur.com/fbZXntE.png)

I am going to use *tshark* to aid with the path extractions, and remove the `instructions.png`, do note that this is mixture of of URL encoded and ASCII path.
```shell
tshark -r evil.pcapng -Y 'http.user_agent contains "my-python-requests-useragent"' -T fields -e http.request.uri | grep -v '^/instructions\.png$' | sed 's/[\/%]//g' | tr -d '\n'

1F01171208110BD1C0EX0A0245E01Y062B093A1FV002F1540121A0A0019 
```

Using [CyberChef](<https://cyberchef.org/#recipe=URL_Encode(false)From_Hex('Auto')XOR(%7B'option':'Latin1','string':'verysecureidek2025themedpassword'%7D,'Standard',false)&input=MWYwMTE3MTIwODExMGI0NDFjMGU1ODBhMDIzNDVlMDE1OTA2MmIwOTNhMWY1NjAwMmYxNTQwMTIxYTBhMDAxOQ>), we can URL Encode the entire request path, convert from hex to raw and finally XOR it with the password obtained earlier.
![](https://i.imgur.com/WNw2G0u.png)

This challenge is fun I would say, just that we didn't thought of trying to access the site with different user agents which emphasize on thinking outside the box mentality. This technique is commonly used by threat actor to deter with investigation, so kudos to the challenge author for this awesome challenge.