---
layout: post
title: "I passed OSCP, and here is how you should(nt) do it"
category: OSCP
---

Hello everyone, I have succesfully passed my second OSCP exam on the 15th of july ([https://www.credly.com/badges/17f00c63-bed3-42ea-bc6d-0a01d0219e1b](https://www.credly.com/badges/17f00c63-bed3-42ea-bc6d-0a01d0219e1b)). I promised to make a post on the path I took during OSCP. But first here are some quick stats:

- 2 exam attempts.
    - First attempt 57,5 points (I assume), sadly realized I could have gotten this first attempt during my second attempt.
    - Second attempt 87,5 points.
        - Report was around 50 A4 pages.
- ~30 PWK lab machines, all of which in public network
- ~25 HackTheBox Machines, using VIP+
    - Check [https://yassirlaaouissi.github.io/](https://yassirlaaouissi.github.io/) for writeups.
- ~10 Proving Grounds Practice machines
- 90 days of lab time

My path took me from the 8th of febuary 2021 untill the 15th of july 2021, which is an insane amount of time. But I got 30 ECTS for my BSc + OSCP cert. So I have no complaints xD

## Background

I am a 19 years old guy who is working parttime in a Security Operations Center @Fox-IT in Delft, The Netherlands. I am just done with my 3rd year of my Bachelor of Science in Computer Science (Specializing in Forensic IT). The school + job provided the amazing oppertunity to get OSCP certified and get 30 ECTS as part of my minor for my BSc.

In my freetime I do some gaming and like football (its football, dont argue). I like Ajax and games like CSGO and Rocket League. I make some scripting stuff and post that on my github, and I have a blog in which I keep track of my Cyber Security endeavours:

- Blog: [https://yassirlaaouissi.github.io/](https://yassirlaaouissi.github.io/)
- Github: [https://github.com/yassirlaaouissi](https://github.com/yassirlaaouissi)

## HackTheBox

I knew hackthebox before I started OSCP and had done 1 or 2 machines prior to enrolling OSCP. It was kinda unplanned to start with HackTheBox machines. This came together because **when enrolling OSCP it takes you 2 week to get actual access to the course.** Which was a little frustrating, but I was hyped at the start of this journey. I subscribed to HackTheBox VIP+ which is veryyyyy nice if you are doing OSCP. This allowed me to, for instance, spawn personal instances. Aka no interference from other HackTheBox users. And do some retired machines, which is also very nice.

I started doing some machines from TJNull's list, and continued doing so along the way of my OSCP:

- [https://docs.google.com/spreadsheets/d/1dwSMIAPIam0PuRBkCiDI88pU3yzrqqHkDtBngUHNCw8/edit#gid=1839402159](https://docs.google.com/spreadsheets/d/1dwSMIAPIam0PuRBkCiDI88pU3yzrqqHkDtBngUHNCw8/edit#gid=1839402159)

I feel like HackTheBox is a nice platform with an infrastructure that is in some cases better than for example the PWK labs (more about this later). But just like the PWK lab the boxes in this platform are either very CTF like, or just not at the level of the OSCP exam. Therefore when I finally had access to the PWK Lab I decided to try to read the course material and do the public network.

## The PWK book/video's

I did not spend much time on the book/video's. There are basicly copies of eachother. I am not a visual learner, more like a practical learner. Hence my choice to do OSCP and not some silly cert like CEH or a very hard cert like Sans offers. Anywho, the excercises in the book are somewhat dated and are only handy if you have low to none knowledge about linux or pentesting in general. So I decided to skip them after trying some.

This may sound wrong, but there are plenty of resources out there that give a better view of the OSCP course material than the OSCP book and video's. Here is just a list of examples:

- Windows Privilege Escalation - [https://www.fuzzysecurity.com/tutorials/16.html](https://www.fuzzysecurity.com/tutorials/16.html)
- Linux Privilege Escalation - [https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/](https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/)
- hakluke's OSCP guide pt. 1 - [https://medium.com/@hakluke/haklukes-ultimate-oscp-guide-part-1-is-oscp-for-you-b57cbcce7440](https://medium.com/@hakluke/haklukes-ultimate-oscp-guide-part-1-is-oscp-for-you-b57cbcce7440)
- hakluke's OSCP guide pt. 2 - [https://medium.com/@hakluke/haklukes-ultimate-oscp-guide-part-2-workflow-and-documentation-tips-9dd335204a48](https://medium.com/@hakluke/haklukes-ultimate-oscp-guide-part-2-workflow-and-documentation-tips-9dd335204a48)
- hakluke's OSCP guide pt. 3 - [https://medium.com/@hakluke/haklukes-ultimate-oscp-guide-part-3-practical-hacking-tips-and-tricks-c38486f5fc97](https://medium.com/@hakluke/haklukes-ultimate-oscp-guide-part-3-practical-hacking-tips-and-tricks-c38486f5fc97)
- Abatchy's OSCP guide - [https://www.abatchy.com/2017/03/how-to-prepare-for-pwkoscp-noob](https://www.abatchy.com/2017/03/how-to-prepare-for-pwkoscp-noob)
- TJnull's OSCP study guide - [https://www.netsecfocus.com/oscp/2019/03/29/The_Journey_to_Try_Harder-_TJNulls_Preparation_Guide_for_PWK_OSCP.html](https://www.netsecfocus.com/oscp/2019/03/29/The_Journey_to_Try_Harder-_TJNulls_Preparation_Guide_for_PWK_OSCP.html)
- James Hall's OSCP Prep - [https://411hall.github.io/OSCP-Preparation/](https://411hall.github.io/OSCP-Preparation/)
- KongWenBin OSCP Review - [https://kongwenbin.wordpress.com/2017/02/23/officially-oscp-certified/](https://kongwenbin.wordpress.com/2017/02/23/officially-oscp-certified/)

I basicly wasted two weeks of my lab time on the course material. 

## The Enumeration tool

I was so done with OffSec's idea of a good course material that I just followed the general tips on forums like here on this subreddit:

> OSCP Is about developing your own workflow and getting gut in pentesting hackerino master 1337 stuff

So I started making an enumeration tool. **Spoiler:** I lended some code from other pentesting devs.

All I did is form it into one terminal window, and add some nice styling to it. Here is the link, feel free to check it out:

- [https://github.com/yassirlaaouissi/EZEA](https://github.com/yassirlaaouissi/EZEA)

 huge thanks to these people:

- [https://github.com/4ut0m4t0n/alacarte](https://github.com/4ut0m4t0n/alacarte)
- [https://github.com/Tib3rius/AutoRecon](https://github.com/Tib3rius/AutoRecon)
- [https://github.com/21y4d/nmapAutomator](https://github.com/21y4d/nmapAutomator)

I spent around two weeks on forming this bash application, which gave me some bash experience. And a nice tool I could use to automate some of the enumeration process. **Though huge disclaimer:**  Do not think this is the only enumeration you have to do on the machines you are scanning with this tool. No matter how good the autoenumerator is, you have to learn yourself to do some manual enumeration.

## The PWK Lab machines

I only did the PWK Public network machines in the lab, which has its (dis-)adventages. I did this purely out of time-neccesity since at this point I have 60 days of labtime left. As I said before, I did 30 machines in the PWK lab, but along side those machines I did some HackTheBox machines. I started the PWK lab with the learning path [https://help.offensive-security.com/hc/en-us/articles/360050473812-PWK-Labs-Learning-Path](https://help.offensive-security.com/hc/en-us/articles/360050473812-PWK-Labs-Learning-Path).

The PWK lab knows some subnets which can be obtained while doing the public network. Even though I like the idea of training for pivoting, I don’t see any direct value for the exam. I know it might sound stupid, but at this point I was not gonna waste any time on learning the specific methods for the subnets. The subnets are very useful for the real world type of scenario’s. Though I had roughly 40 days left until my exam, and I would rather spend that time on something else.

## Buffer Overflow

We can be short about this, just do this TryHackMe room:

- https://tryhackme.com/room/bufferoverflowprep

I did this, and it was doable within a week. Did some more hackthebox machines after I was done. And then my first attempt started.

## First attempt

I started at 09:00 Amsterdam time. My planning was as follows:

1. Start scanning and exploiting 25 pointer (not the BOF)
2. While exploiting 25 pointer scan 20 pointer #1.
3. Exploit 20 pointer #1 and start scanning 20 pointer #2.
4. Exploit 20 pointer #2 and scan 10 pointer.
5. Exploit 10 pointer and scan BOF.
6. Exploit BOF.

Got 57,5 points. Which made me sad. All I needed was privesc on a windows 25 pointer or a complete 20 pointer. I later came to realise I did everything right on the 20 pointer, except the firewall. I used port 443 for my reverse shell. Yet 443 was not an open port on that very machine. Instead I should have used port 80 and it would get me the exam since privesc was a joke on this machine. I knew this because I got this machine on my second attempt as well, and the only thing I did different was the ports.

From my first attempt I learned not to go by general assumptions and maybe needed to do some more practice on windows privesc. And I also learned that PWK lab and HackTheBox were not a good indication of the exam machines. They are good practice, but not enough to pass.

## Proving Grounds Practice

After my first attempt I was pretty dismotivated and felt like I could have gotten the first attempt if I were not so stressed. But I knew I had to do something to get my second attempt. So I decided to have a look at proving grounds practice, which is the payed subscription within proving grounds. The community said it was a better representation of the exam machines, which I can stand behind. The level of proving grounds is indeed more challenging, but more adaptable to the exam machines. I ended up doing 9 machines, most of which windows machines due to my privesc issues on my first attempt. Writeups are not yet published on my blog, but will probably do that in the future. For those planning on doing PG Practice machines, follow TJ Nulls' list. Its amazing, huge shoutout to the fellow.

## Second attempt

I had my second attempt on the 14th of july at 09:00. Applied the same strategy at first. But then I realised the BOF and the 20 pointer I had on my first attempt, were exactly the same. So I did those, and thats when I realised the mistake I made on my first attempt with the 20 pointer. Which placed me at 45 points. After that I spent time on the other machines, which gave me a comfortable 87,5 points after 12 hours exam. Again I did not get privesc on a windows 25 pointer. But I had peace with that. I made sure I noted everything and went onto reporting the next day. I used this template:

- [https://github.com/whoisflynn/OSCP-Exam-Report-Template](https://github.com/whoisflynn/OSCP-Exam-Report-Template)

Props to OffSec on grading my exam within around 24 hours. Thats sick fast, my report was 50+ pages.

## Points of critisism

Some of you might recognize my posts by their furious rants about what OffSec does wrong and could do better. Ofcourse, I have no harsh feelings. They are trying, just trying to contribute to making it go a little better. Here are some things I found frustrating during the course of my cheesely named "OSCP Journey":

1. Give out personal instances in the PWK lab machines
    1. This will ultimately save you support time, and enhance the students experience. HackTheBox does this for a very competitive price of 15$ a month, I dont see why a ~1300$ course cant do that.
2. The book is dated (eventhough you updated it in early 2020)
    1. I  encountered excercises with incompatibility issues with the default Kali VM for various excercises. Issues you would also have with the default Kali VM in mid 2019. FYI; the default Kali VM is made and distributed by the same organization that makes the PWK course material.
3. The PWK lab is not representable for the OSCP Exam
    1. The machines are cool, but they are not suited as an accurate representation of the OSCP exam level. Maybe make the book free (since its worthless already) and add some Proving Grounds boxes to the PWK lab.
4. The proctorers, helpdesk and other live chat employees cant answer any question that is even the slightest usefull to a student.
    1. During the course and the exam attempts I encountered many cases in which a student admin or other live chat employee could not answer any of my questions and reffered me to an emailaddress. Which ultimately leads to 2-3 business day waiting time (doesnt count for the exam). Which is somewhat annoying, please educate your staff instead of disallowing them to answer questions.

Offensive Security is as earlier said a decent Certificate Issuer, but they are not making the most of their monopoly position in the field. They should keep up all the other good stuff and improve where possible.

## Final note

I am gonna take a big break from Offensive Security and focus on my bachelor of science. After that I am probably gonna go for my MSc, I think my paths will cross again with OffSec. If I do a course again it will probably me OSEP or OSWE, but I do like the idea of exploit developement. So maybe, just maybe i'll do OSED after I am dont with OSEP and OSWE. 

To those that are still in the process of getting OSCP certified, the best of luck!

> Try ~~Harder~~ Simpeler!
