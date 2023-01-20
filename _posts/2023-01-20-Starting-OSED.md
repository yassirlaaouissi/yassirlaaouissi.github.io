---
layout: post
title: "Starting OSED"
category: Reversing, Exploit Developement, OSED
---

Hello again,

Today I am starting with a new course; Offensive Security Exploit Developer (EXP-301):

- [https://www.offensive-security.com/courses/exp-301/](https://www.offensive-security.com/courses/exp-301/)

This course focusses on exploit developement for Windows user mode applications and spiked my interest over te past few months. Some of you might know I have done OSCP in the past, it was fun. I liked the Buffer Overflow part very much. But I felt like I did not have enough knowledge to go about bypassing memory restrictions, or even replicating the steps in a real life scenario.

Meanwhile I also developed an interest in reverse engineering. I competed in last years FlareOn CTF (see other blogpost), hosted by mandiant. I really enjoyed that, eventhough I am utterly wack in reversing. Also I started to follow VX-Underground over the past two years, which made me wanting to reverse some malware. And I am starting to develop an interest in game cheat developement and anti-cheat evasion on GuidedHacking. These interests combined, with a very nice employer allowed me to make the decision to start OSED on a LearnOne subscription basis.

The course centers around a couple of topics:

1. EIP & SEH overwrites
2. Egghunters & Custom shellcode
3. Basic Reverse engineering in IDA free
4. DEP bypass
5. ROP
6. Advanced ROP
7. ASLR bypass
8. Read/write primitives

Note that the course is not limited to these subjects, its just a rough outline of the course. What interested me is when I read this in the course material:

> While the majority of Windows operating systems in use today are 64-bit, many applications are 32-bit. This is possible on the Windows platform due to the *Windows on Windows 64*
> (*wow64*) implementation.
 

This is something I did not know about Windows. I guess I should also mention that my knowledge in Windows internals is not up to par in my opinion. So I would like to learn more about that in a more practical manner.

Offensive Security advices to read the book and watch the video’s, along with doing the excercises. Back when I did OSCP I had 90 days, so I attempted the book but I skipped along big parts of it since the time constraints forced me to jump into the labs ASAP.

Now I have a years time, so I am going to take my time on things. I remember from OSCP that some excercises were outdated, I hope thats not the case with OSED. I want to try and do every excercises, including the “extra miles”. The extra miles are known to be extra challenging, and prepare you even better for the exam.

Exam contains three boxes (AKA binaries to exploit). You have to get at least 2 out of 3 to get the required 60 out of 100 points. you have ~48 hours to complete the boxes. Exams are proctored. After exam you have 24 hours to make the report.

I’ll be blogging about my proces along the way, so stay tuned. I will also be more active in the Offensive Security discord.
