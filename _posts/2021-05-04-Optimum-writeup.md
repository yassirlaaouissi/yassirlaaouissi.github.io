---
layout: post
title: "Optimum Writeup - HackTheBox"
category: HackTheBox
---
#  HTB lab Machine - Optimum

I started of reverting the machine, and then ran my self made script https://github.com/yassirlaaouissi/EZEA. The exact results can be found in the results/10.129.1.127 folder that I have attached to this post.

## Enumeration summary

```
PORT   STATE SERVICE VERSION

80/tcp open  http    HttpFileServer httpd 2.3
|_http-aspnet-debug: ERROR: Script execution failed (use -d to debug)
|_http-csrf: Couldn't find any CSRF vulnerabilities.
|_http-dombased-xss: Couldn't find any DOM based XSS.
| http-fileupload-exploiter: 
|   
|_    Couldn't find a file-type field.
| http-method-tamper: 
|   VULNERABLE:
|   Authentication bypass by HTTP verb tampering
|     State: VULNERABLE (Exploitable)
|       This web server contains password protected resources vulnerable to authentication bypass
|       vulnerabilities via HTTP verb tampering. This is often found in web servers that only limit access to the
|        common HTTP methods and in misconfigured .htaccess files.
|              
|     Extra information:
|       
|   URIs suspected to be vulnerable to HTTP verb tampering:
|     /~login [GENERIC]
|   
|     References:
|       http://www.mkit.com.ar/labs/htexploit/
|       http://www.imperva.com/resources/glossary/http_verb_tampering.html
|       http://capec.mitre.org/data/definitions/274.html
|_      https://www.owasp.org/index.php/Testing_for_HTTP_Methods_and_XST_%28OWASP-CM-008%29

|_http-server-header: HFS 2.3
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
| http-vuln-cve2011-3192: 
|   VULNERABLE:
|   Apache byterange filter DoS
|     State: VULNERABLE
|     IDs:  BID:49303  CVE:CVE-2011-3192
|       The Apache web server is vulnerable to a denial of service attack when numerous
|       overlapping byte ranges are requested.
|     Disclosure date: 2011-08-19
|     References:
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2011-3192
|       https://www.securityfocus.com/bid/49303
|       https://www.tenable.com/plugins/nessus/55976
|_      https://seclists.org/fulldisclosure/2011/Aug/175

Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

```

## Exploitation

Used this exploit before: https://www.exploit-db.com/exploits/49125

Lets use it again. All it requires is for you to edit the right lhost and lport, set up a simplehttpserver on port 80 on your lhost that server nc.exe, and run the script multiple times:

![image-20210504114120956](https://raw.githubusercontent.com/yassirlaaouissi/yassirlaaouissi.github.io/master/_screenshots/image-20210504114120956.png)

Lets do some privesc:

```
C:\Users\kostas\Desktop>systeminfo
systeminfo

Host Name:                 OPTIMUM
OS Name:                   Microsoft Windows Server 2012 R2 Standard
OS Version:                6.3.9600 N/A Build 9600
OS Manufacturer:           Microsoft Corporation
OS Configuration:          Standalone Server
OS Build Type:             Multiprocessor Free
Registered Owner:          Windows User
Registered Organization:   
Product ID:                00252-70000-00000-AA535
Original Install Date:     18/3/2017, 1:51:36 ��
System Boot Time:          11/5/2021, 3:24:47 ��
System Manufacturer:       VMware, Inc.
System Model:              VMware Virtual Platform
System Type:               x64-based PC
Processor(s):              1 Processor(s) Installed.
                           [01]: AMD64 Family 23 Model 49 Stepping 0 AuthenticAMD ~2994 Mhz
BIOS Version:              Phoenix Technologies LTD 6.00, 12/12/2018
Windows Directory:         C:\Windows
System Directory:          C:\Windows\system32
Boot Device:               \Device\HarddiskVolume1
System Locale:             el;Greek
Input Locale:              en-us;English (United States)
Time Zone:                 (UTC+02:00) Athens, Bucharest
Total Physical Memory:     4.095 MB
Available Physical Memory: 3.417 MB
Virtual Memory: Max Size:  5.503 MB
Virtual Memory: Available: 4.913 MB
Virtual Memory: In Use:    590 MB
Page File Location(s):     C:\pagefile.sys
Domain:                    HTB
Logon Server:              \\OPTIMUM
Hotfix(s):                 31 Hotfix(s) Installed.
                           [01]: KB2959936
                           [02]: KB2896496
                           [03]: KB2919355
                           [04]: KB2920189
                           [05]: KB2928120
                           [06]: KB2931358
                           [07]: KB2931366
                           [08]: KB2933826
                           [09]: KB2938772
                           [10]: KB2949621
                           [11]: KB2954879
                           [12]: KB2958262
                           [13]: KB2958263
                           [14]: KB2961072
                           [15]: KB2965500
                           [16]: KB2966407
                           [17]: KB2967917
                           [18]: KB2971203
                           [19]: KB2971850
                           [20]: KB2973351
                           [21]: KB2973448
                           [22]: KB2975061
                           [23]: KB2976627
                           [24]: KB2977629
                           [25]: KB2981580
                           [26]: KB2987107
                           [27]: KB2989647
                           [28]: KB2998527
                           [29]: KB3000850
                           [30]: KB3003057
                           [31]: KB3014442
Network Card(s):           1 NIC(s) Installed.
                           [01]: vmxnet3 Ethernet Adapter
                                 Connection Name: Ethernet0 2
                                 DHCP Enabled:    Yes
                                 DHCP Server:     10.129.0.1
                                 IP address(es)
                                 [01]: 10.129.1.127
                                 [02]: fe80::e0fe:ad6b:24d4:868e
                                 [03]: dead:beef::e0fe:ad6b:24d4:868e
Hyper-V Requirements:      A hypervisor has been detected. Features required for Hyper-V will not be displayed.
```

Thats when I installed a windows-exploit-suggester: 

```
root@kali:/home/kali/Desktop/DownloadedScripts# wget https://raw.githubusercontent.com/AonCyberLabs/Windows-Exploit-Suggester/f34dcc186697ac58c54ebe1d32c7695e040d0ecb/windows-exploit-suggester.py
```

```
kali@kali:~/Desktop/DownloadedScripts$ python2 windows-exploit-suggester.py --database 2021-05-04-mssb.xls --systeminfo sysinfo.txt --quiet
[*] initiating winsploit version 3.3...
[*] database file detected as xls or xlsx based on extension
[*] attempting to read from the systeminfo input file
[+] systeminfo input file read successfully (utf-8)
[*] querying database file for potential vulnerabilities
[*] comparing the 31 hotfix(es) against the 266 potential bulletins(s) with a database of 137 known exploits
[*] there are now 246 remaining vulns
[+] [E] exploitdb PoC, [M] Metasploit module, [*] missing bulletin
[+] windows version identified as 'Windows 2012 R2 64-bit'
[*] 
[E] MS16-135: Security Update for Windows Kernel-Mode Drivers (3199135) - Important
[E] MS16-098: Security Update for Windows Kernel-Mode Drivers (3178466) - Important
[M] MS16-075: Security Update for Windows SMB Server (3164038) - Important
[E] MS16-074: Security Update for Microsoft Graphics Component (3164036) - Important
[E] MS16-063: Cumulative Security Update for Internet Explorer (3163649) - Critical
[E] MS16-032: Security Update for Secondary Logon to Address Elevation of Privile (3143141) - Important
[M] MS16-016: Security Update for WebDAV to Address Elevation of Privilege (3136041) - Important
[E] MS16-014: Security Update for Microsoft Windows to Address Remote Code Execution (3134228) - Important
[E] MS16-007: Security Update for Microsoft Windows to Address Remote Code Execution (3124901) - Important
[E] MS15-132: Security Update for Microsoft Windows to Address Remote Code Execution (3116162) - Important
[E] MS15-112: Cumulative Security Update for Internet Explorer (3104517) - Critical
[E] MS15-111: Security Update for Windows Kernel to Address Elevation of Privilege (3096447) - Important
[E] MS15-102: Vulnerabilities in Windows Task Management Could Allow Elevation of Privilege (3089657) - Important
[E] MS15-097: Vulnerabilities in Microsoft Graphics Component Could Allow Remote Code Execution (3089656) - Critical
[M] MS15-078: Vulnerability in Microsoft Font Driver Could Allow Remote Code Execution (3079904) - Critical
[E] MS15-052: Vulnerability in Windows Kernel Could Allow Security Feature Bypass (3050514) - Important
[M] MS15-051: Vulnerabilities in Windows Kernel-Mode Drivers Could Allow Elevation of Privilege (3057191) - Important
[E] MS15-010: Vulnerabilities in Windows Kernel-Mode Driver Could Allow Remote Code Execution (3036220) - Critical
[E] MS15-001: Vulnerability in Windows Application Compatibility Cache Could Allow Elevation of Privilege (3023266) - Important
[E] MS14-068: Vulnerability in Kerberos Could Allow Elevation of Privilege (3011780) - Critical
[M] MS14-064: Vulnerabilities in Windows OLE Could Allow Remote Code Execution (3011443) - Critical
[M] MS14-060: Vulnerability in Windows OLE Could Allow Remote Code Execution (3000869) - Important
[M] MS14-058: Vulnerabilities in Kernel-Mode Driver Could Allow Remote Code Execution (3000061) - Critical
[E] MS13-101: Vulnerabilities in Windows Kernel-Mode Drivers Could Allow Elevation of Privilege (2880430) - Important
[M] MS13-090: Cumulative Security Update of ActiveX Kill Bits (2900986) - Critical
[*] done
kali@kali:~/Desktop/DownloadedScripts$ 

```

Tried the first one, found exe here: https://github.com/SecWiki/windows-kernel-exploits/blob/master/MS16-135/40823/SetWindowLongPtr_Exploit.exe

But it did not work, so I tried the second one: https://www.exploit-db.com/exploits/41020/ Exe here: https://github.com/offensive-security/exploitdb-bin-sploits/raw/master/bin-sploits/41020.exe 

Run and root:

![image-20210504130615825](https://raw.githubusercontent.com/yassirlaaouissi/yassirlaaouissi.github.io/master/_screenshots/image-20210504130615825.png)

## Final thoughts

Nice OSCP 20 pointer.
