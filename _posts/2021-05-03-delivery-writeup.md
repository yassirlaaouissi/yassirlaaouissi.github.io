---
layout: post
title: "Delivery Writeup - HackTheBox"
category: HackTheBox
---


# HTB lab Machine - Delivery

I started of reverting the machine, and then ran my self made script https://github.com/yassirlaaouissi/EZEA. The exact results can be found in the results/10.129.139.154 folder that I have attached to this post.

## Enumeration summary

```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 9c:40:fa:85:9b:01:ac:ac:0e:bc:0c:19:51:8a:ee:27 (RSA)
|   256 5a:0c:c0:3b:9b:76:55:2e:6e:c4:f4:b9:5d:76:17:09 (ECDSA)
|_  256 b7:9d:f7:48:9d:a2:f2:76:30:fd:42:d3:35:3a:80:8c (ED25519)

80/tcp open  http    nginx 1.14.2
|_http-server-header: nginx/1.14.2
|_http-title: Welcome
|     Path: http://10.129.139.154:80/
|     Form id: demo-name
|_    Form action: #
```

![image-20210501111926748](https://raw.githubusercontent.com/yassirlaaouissi/yassirlaaouissi.github.io/master/_screenshots/image-20210501111926748.png)

```
Summary   : nginx[1.14.2], JQuery, Script, HTML5, Email[jane@untitled.tld], HTTPServer[nginx/1.14.2]
```

```
8065/tcp open  unknown syn-ack ttl 63
| fingerprint-strings: 
|   GenericLines, Hello, Help, RTSPRequest, SSLSessionReq: 
|     HTTP/1.1 400 Bad Request
|     Content-Type: text/plain; charset=utf-8
|     Connection: close
|     Request
|   GetRequest: 
|     HTTP/1.0 200 OK
|     Accept-Ranges: bytes
|     Cache-Control: no-cache, max-age=31556926, public
|     Content-Length: 3108
|     Content-Security-Policy: frame-ancestors 'self'; script-src 'self' cdn.rudderlabs.com
|     Content-Type: text/html; charset=utf-8
|     Last-Modified: Sat, 01 May 2021 15:15:09 GMT
|     X-Frame-Options: SAMEORIGIN
|     X-Request-Id: 3hhdtpk7ebdxbkgk8t6r5ois5y
|     X-Version-Id: 5.30.0.5.30.1.57fb31b889bf81d99d8af8176d4bbaaa.false
|     Date: Sat, 01 May 2021 15:16:22 GMT
|     <!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1,maximum-scale=1,user-scalable=0"><meta name="robots" content="noindex, nofollow"><meta name="referrer" content="no-referrer"><title>Mattermost</title><meta name="mobile-web-app-capable" content="yes"><meta name="application-name" content="Mattermost"><meta name="format-detection" content="telephone=no"><link re
|   HTTPOptions: 
|     HTTP/1.0 405 Method Not Allowed
|     Date: Sat, 01 May 2021 15:16:22 GMT
|_    Content-Length: 0
```

![image-20210501112515956](https://raw.githubusercontent.com/yassirlaaouissi/yassirlaaouissi.github.io/master/_screenshots/image-20210501112515956.png)

```
/images               (Status: 301) [Size: 185] [--> http://10.129.139.154/images/]

/assets               (Status: 301) [Size: 185] [--> http://10.129.139.154/assets/]

/error                (Status: 301) [Size: 185] [--> http://10.129.139.154/error/] 
===============================================================
```



## Exploitation

Added delivery to /etc/hosts:

```
10.129.139.154	delivery	delivery.htb
10.129.139.154	delivery	helpdesk.delivery.htb

```

Found this:

![image-20210501121706688](https://raw.githubusercontent.com/yassirlaaouissi/yassirlaaouissi.github.io/master/_screenshots/image-20210501121706688.png)

So I tried to get an .htb email address. And I noticed that if you submit a ticket in the helpdesk you get a .htb email address.

![image-20210501121956530](https://raw.githubusercontent.com/yassirlaaouissi/yassirlaaouissi.github.io/master/_screenshots/image-20210501121956530.png)

After submitting the ticket you get a .htb email:

![image-20210501122021937](https://raw.githubusercontent.com/yassirlaaouissi/yassirlaaouissi.github.io/master/_screenshots/image-20210501122021937.png)

That is the moment you go to mattermost and create a mattermost account with it:

![image-20210501123320701](https://raw.githubusercontent.com/yassirlaaouissi/yassirlaaouissi.github.io/master/_screenshots/image-20210501123320701.png)

The confirmation link will be placed in the support ticket:

![image-20210501123401536](https://raw.githubusercontent.com/yassirlaaouissi/yassirlaaouissi.github.io/master/_screenshots/image-20210501123401536.png)

Enter the link and log in. There you go:

![image-20210501123516670](https://raw.githubusercontent.com/yassirlaaouissi/yassirlaaouissi.github.io/master/_screenshots/image-20210501123516670.png)

More straight forward cant be from here:

![image-20210501123743864](https://raw.githubusercontent.com/yassirlaaouissi/yassirlaaouissi.github.io/master/_screenshots/image-20210501123743864.png)

and this:

![image-20210501123813041](https://raw.githubusercontent.com/yassirlaaouissi/yassirlaaouissi.github.io/master/_screenshots/image-20210501123813041.png)

SSH and you've got user. Lets do some linpeas:

```
[+] Sudo version
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#sudo-version
Sudo version 1.8.27

```

```
[+] Cron jobs
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#scheduled-cron-jobs

* * * * *	root	/root/mail.sh
```

Eventhough it seems apealing, this is a rabit hole. Instead imma stick to those hashes mentioned in the mattermost.

After some failed attempts, the `maildeliverer` can’t log into the database, and `root` account is password protected. We’ll need to hunt for the database credentials on the system.

The MatterMost configuration file is located in `/opt/mattermost/config/config.json` and contains credentials to the MySQL database under *SqlSettings*. The username and pass are in plain-text and can be used to log in to the database.

​    [     ![img](https://drt.sh/posts/htb-delivery/mattermost-config.png)     ](https://drt.sh/posts/htb-delivery/mattermost-config.png)      

Access the database by executing

```bash
mysql -u mmuser -D mattermost -p Crack_The_MM_Admin_PW
```

Obtain the username and password of the only other user on the MatterMost instance.

```sql
SELECT username, password FROM Users WHERE username = 'root';
```

```
MariaDB [mattermost]> SELECT username, password FROM Users WHERE username = 'root';
+----------+--------------------------------------------------------------+
| username | password                                                     |
+----------+--------------------------------------------------------------+
| root     | $2a$10$VM6EeymRxJ29r8Wjkr8Dtev0O.1STWb4.4ScG.anuu7v0EFJwgjjO |
+----------+--------------------------------------------------------------+
1 row in set (0.000 sec)

MariaDB [mattermost]> 

```

A bit of hashcat will reveal the password "PleaseSubscribe!21" for this hash. Aka we root:

![image-20210501130401880](https://raw.githubusercontent.com/yassirlaaouissi/yassirlaaouissi.github.io/master/_screenshots/image-20210501130401880.png)

## Final thoughts

This was a shitbox, tbh this is fun for CTF's but not OSCP like. So imma stick to TJNull's list from now on.

