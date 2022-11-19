---
layout: post
title: "FlareOn 9 - Writeup"
category: Reversing
---

Hi everyone, has been a while since I made a blogpost. Decided I wanted to compete in Flare-on 9 CTF.  Last years people got a bad ass price for reversing every challenge: [https://www.mandiant.com/resources/blog/flare-on-8-challenge-solutions](https://www.mandiant.com/resources/blog/flare-on-8-challenge-solutions)

For my setup I used The Flare-VM, which is a Windows 10 VM with a bunch of tools installed by these scripts:

- https://github.com/mandiant/flare-vm

Put it on a host-only adapter together with my remnux VM that simulates network traffic with inetsim. I basicly used the same setup as used in the PMAT course of HuskyHacks:

- [https://www.youtube.com/watch?v=qA0YcYMRWyI](https://www.youtube.com/watch?v=qA0YcYMRWyI)

Lets start bozo’s and beanheads.

## Challenge 1: Flaredle

Name is funny, because its supposed to represent a hype in 2022 called wordles. This was the challenge description:

![Untitled](https://raw.githubusercontent.com/yassirlaaouissi/yassirlaaouissi.github.io/master/_screenshots/flareon.png)

I know, you see 3 attempts, but that is because I am unable to type. And I am starting flare-on this year early in the morning. The website on the link looks like this:

![Untitled](https://raw.githubusercontent.com/yassirlaaouissi/yassirlaaouissi.github.io/master/_screenshots/flareon1.png)

Looks very cool, but I am for now more interested in the 7z file. It appears to contain HTML,CSS and JS of the webapp we saw on the link:

![Untitled](https://raw.githubusercontent.com/yassirlaaouissi/yassirlaaouissi.github.io/master/_screenshots/flareon2.png)

Lets see what they are on about in an IDE. Starting with the HTML file, it refers to the `script.js` file:

![Untitled](https://raw.githubusercontent.com/yassirlaaouissi/yassirlaaouissi.github.io/master/_screenshots/flareon3.png)

Looking at the top of the `script.js`file we see the following reference to `words.js`:

![Untitled](https://raw.githubusercontent.com/yassirlaaouissi/yassirlaaouissi.github.io/master/_screenshots/flareon4.png)

Looking at the top arrow, you see the `words.js` file is called. The middle arrow points to an integer value that is used as an index number for a list on line 9 at the bottom arrow. So I expect to see a list in `words.js`: 

![Untitled](https://raw.githubusercontent.com/yassirlaaouissi/yassirlaaouissi.github.io/master/_screenshots/flareon5.png)

Damn, that seems way to straight forward, let’s log the 57th entry in console:

![Untitled](https://raw.githubusercontent.com/yassirlaaouissi/yassirlaaouissi.github.io/master/_screenshots/flareon6.png)

Spin up an HTTP server with the webapp files in them:

![Untitled](https://raw.githubusercontent.com/yassirlaaouissi/yassirlaaouissi.github.io/master/_screenshots/flareon7.png)

There you have the string:

![Untitled](https://raw.githubusercontent.com/yassirlaaouissi/yassirlaaouissi.github.io/master/_screenshots/flareon8.png)

All flags end with `@flare-on.com`as can be seen in `scripts.js`:

![Untitled](https://raw.githubusercontent.com/yassirlaaouissi/yassirlaaouissi.github.io/master/_screenshots/flareon9.png)

Which makes the flag `flareonisallaboutcats@flare-on.com`

## Challenge 2: Pixel Poker

Lol yeah the first challenge was indeed a captcha:

![Untitled](https://raw.githubusercontent.com/yassirlaaouissi/yassirlaaouissi.github.io/master/_screenshots/flareon10.png)

First EXE of the day:

![Untitled](https://raw.githubusercontent.com/yassirlaaouissi/yassirlaaouissi.github.io/master/_screenshots/flareon11.png)

Lets see what the readme is about:

![Untitled](https://raw.githubusercontent.com/yassirlaaouissi/yassirlaaouissi.github.io/master/_screenshots/flareon12.png)

lol, sounds intense to find the **right** pixel. Lets start with some PEStudio on the EXE:

![Untitled](https://raw.githubusercontent.com/yassirlaaouissi/yassirlaaouissi.github.io/master/_screenshots/flareon13.png)

32 bits, C++, nice. This is what the program looks like when you start it:

![Untitled](https://raw.githubusercontent.com/yassirlaaouissi/yassirlaaouissi.github.io/master/_screenshots/flareon14.png)

If you hover over the pixels, the title of the window changes to the X and Y coordinates. Also when you click, the attempts on the right side of the string change accordingly. Maximum is 10 tries, then it pops up a window with “womp womp” and closes the window. PEStudio points out the following title format:

![Untitled](https://raw.githubusercontent.com/yassirlaaouissi/yassirlaaouissi.github.io/master/_screenshots/flareon15.png)

Make a zip out of the exe:

![Untitled](https://raw.githubusercontent.com/yassirlaaouissi/yassirlaaouissi.github.io/master/_screenshots/flareon16.png)

Two different bitmaps:

![Untitled](https://raw.githubusercontent.com/yassirlaaouissi/yassirlaaouissi.github.io/master/_screenshots/flareon17.png)

Compare them online ([https://www.diffchecker.com/image-diff/](https://www.diffchecker.com/image-diff/)):

![Untitled](https://raw.githubusercontent.com/yassirlaaouissi/yassirlaaouissi.github.io/master/_screenshots/flareon18.png)

Flag = `w1nN3r_W!NneR_cHick3n_d1nNer@flare-on.com`

Good ol’ extension swapping, who would have guessed.

## Challenge 3: Magic 8 ball

No nonsense description:

![Untitled](https://raw.githubusercontent.com/yassirlaaouissi/yassirlaaouissi.github.io/master/_screenshots/flareon19.png)

Huhm weird, `gimme flag pls?` 

![Untitled](https://raw.githubusercontent.com/yassirlaaouissi/yassirlaaouissi.github.io/master/_screenshots/flareon20.png)

Function `0x4024e0` has some interesting if statements:

```jsx
label_2:
    if (*((edi + 0x159)) != 0) {
        eax = *((esi + 0x14));
        ecx = esi;
        if (eax >= 0x10) {
            ecx = *(esi);
        }
        if (*(ecx) != 0x4c) {
            goto label_3;
        }
        ecx = esi;
        if (eax >= 0x10) {
            ecx = *(esi);
        }
        if (*((ecx + 1)) != 0x4c) {
            goto label_3;
        }
        ecx = esi;
        if (eax >= 0x10) {
            ecx = *(esi);
        }
        if (*((ecx + 2)) != 0x55) {
            goto label_3;
        }
        ecx = esi;
        if (eax >= 0x10) {
            ecx = *(esi);
        }
        if (*((ecx + 3)) != 0x52) {
            goto label_3;
        }
        ecx = esi;
        if (eax >= 0x10) {
            ecx = *(esi);
        }
        if (*((ecx + 4)) != 0x55) {
            goto label_3;
        }
        ecx = esi;
        if (eax >= 0x10) {
            ecx = *(esi);
        }
        if (*((ecx + 5)) != 0x4c) {
            goto label_3;
        }
        ecx = esi;
        if (eax >= 0x10) {
            ecx = *(esi);
        }
        if (*((ecx + 6)) != 0x44) {
            goto label_3;
        }
        ecx = esi;
        if (eax >= 0x10) {
            ecx = *(esi);
        }
        if (*((ecx + 7)) != 0x55) {
            goto label_3;
        }
        ecx = esi;
        if (eax >= 0x10) {
            ecx = *(esi);
        }
        if (*((ecx + 8)) != 0x4c) {
            goto label_3;
        }
        ecx = edi + 0xf8;
        if (*((edi + 0x10c)) >= 0x10) {
            ecx = *(ecx);
        }
        eax = uint32_t (*strncmp)(void, void, void) (ecx, edi + 0x5c, 0xf);
        if (eax != 0) {
            goto label_3;
        }
        ecx = esp;
        fcn_00401220 (esi);
        ecx = edi;
        fcn_00401a10 ();
    }
```

Notice that between each if statement there is a `0x10`. You can delete those leaving you with this:

```jsx
label_2:
    if (*((edi + 0x159)) != 0) {
        eax = *((esi + 0x14));
        ecx = esi;

        if (*(ecx) != 0x4c) {
            goto label_3;
        }
        ecx = esi;

        if (*((ecx + 1)) != 0x4c) {
            goto label_3;
        }
        ecx = esi;

        if (*((ecx + 2)) != 0x55) {
            goto label_3;
        }

        if (*((ecx + 3)) != 0x52) {
            goto label_3;
        }
        ecx = esi;

        if (*((ecx + 4)) != 0x55) {
            goto label_3;
        }
        ecx = esi;

        if (*((ecx + 5)) != 0x4c) {
            goto label_3;
        }
        ecx = esi;

        if (*((ecx + 6)) != 0x44) {
            goto label_3;
        }
        ecx = esi;

        if (*((ecx + 7)) != 0x55) {
            goto label_3;
        }
        ecx = esi;

        if (*((ecx + 8)) != 0x4c) {
            goto label_3;
        }
        ecx = edi + 0xf8;

        eax = uint32_t (*strncmp)(void, void, void) (ecx, edi + 0x5c, 0xf);
        if (eax != 0) {
            goto label_3;
        }
        ecx = esp;
        fcn_00401220 (esi);
        ecx = edi;
        fcn_00401a10 ();
    }
```

Translating the hexadecimal in the if statements amounts to keystrokes:

![Untitled](https://raw.githubusercontent.com/yassirlaaouissi/yassirlaaouissi.github.io/master/_screenshots/flareon21.png)

Decoding all the keystrokes will give you: `L L U R U L D U L`.

Enter `gimme flag pls?` and start doing the shuffle with your arroy keys `L L U R U L D U L`

![Untitled](https://raw.githubusercontent.com/yassirlaaouissi/yassirlaaouissi.github.io/master/_screenshots/flareon22.png)

ez katka, that challenge was do-able.

# Challenge 4: ****darn_mice****

Sounds like some debugger action here:

![Untitled](https://raw.githubusercontent.com/yassirlaaouissi/yassirlaaouissi.github.io/master/_screenshots/flareon23.png)

Pretty straight forward only an exe:

![Untitled](https://raw.githubusercontent.com/yassirlaaouissi/yassirlaaouissi.github.io/master/_screenshots/flareon24.png)

Interesting strings:

![Untitled](https://raw.githubusercontent.com/yassirlaaouissi/yassirlaaouissi.github.io/master/_screenshots/flareon25.png)

32 bits C++:

![Untitled](https://raw.githubusercontent.com/yassirlaaouissi/yassirlaaouissi.github.io/master/_screenshots/flareon26.png)

Only bcrypt and kernel?

![Untitled](https://raw.githubusercontent.com/yassirlaaouissi/yassirlaaouissi.github.io/master/_screenshots/flareon27.png)

Nice !

![Untitled](https://raw.githubusercontent.com/yassirlaaouissi/yassirlaaouissi.github.io/master/_screenshots/flareon28.png)

These imports:

![Untitled](https://raw.githubusercontent.com/yassirlaaouissi/yassirlaaouissi.github.io/master/_screenshots/flareon29.png)

The program is cli and only takes one argument:

![Untitled](https://raw.githubusercontent.com/yassirlaaouissi/yassirlaaouissi.github.io/master/_screenshots/flareon30.png)

1280 seems more interesting:

![Untitled](https://raw.githubusercontent.com/yassirlaaouissi/yassirlaaouissi.github.io/master/_screenshots/flareon31.png)

You can only enter 36 characters, and it has to start with salty:

![Untitled](https://raw.githubusercontent.com/yassirlaaouissi/yassirlaaouissi.github.io/master/_screenshots/flareon32.png)

lol what, only S does shit:

![Untitled](https://raw.githubusercontent.com/yassirlaaouissi/yassirlaaouissi.github.io/master/_screenshots/flareon33.png)

This list of keycodes looks interesting:

![Untitled](https://raw.githubusercontent.com/yassirlaaouissi/yassirlaaouissi.github.io/master/_screenshots/flareon34.png)

This works:

![Untitled](https://raw.githubusercontent.com/yassirlaaouissi/yassirlaaouissi.github.io/master/_screenshots/flareon35.png)

but other characters dont work, this was manual bruteforce, wasted way to much time at this.

Look like the more characters I add, the more Nibble it prints:

![Untitled](https://raw.githubusercontent.com/yassirlaaouissi/yassirlaaouissi.github.io/master/_screenshots/flareon36.png)

Set of predifened bytes, + give bytes makes existence of 1 byte. With return you can go back to previous function, which in our case means we continue the for loop and print Nibble. `pcVar4` is being executed and is the product of `keycode[FOR_LOOP_INDEX]` + `param_1[FOR_LOOP_INDEX]`. `param_1` is the first command line argument you give. So we can create return instruction to go back to the previous function if we want to. `0xC3`is a return statement in x86. The only thing you do is `0xC3` - `hex(keycode_list[entrynum])` and that will give you the following string:

> see three, C3 C3 C3 C3 C3 C3 C3! XD
> 

Give that as input to `ret`each for loop itteration, and it will show the key:

![Untitled](https://raw.githubusercontent.com/yassirlaaouissi/yassirlaaouissi.github.io/master/_screenshots/flareon37.png)

Oh right, its windows got ehm:

![Untitled](https://raw.githubusercontent.com/yassirlaaouissi/yassirlaaouissi.github.io/master/_screenshots/flareon38.png)

How I felt about windows after this challenge:

![Untitled](https://raw.githubusercontent.com/yassirlaaouissi/yassirlaaouissi.github.io/master/_screenshots/flareon39.png)

# Challenge 5: T8

Fuck you mandiant xD

![Untitled](https://raw.githubusercontent.com/yassirlaaouissi/yassirlaaouissi.github.io/master/_screenshots/flareon40.png)

Finally a PCAP, i love pcap. It makes me feel warm inside, maybe I need to poop a little:

![Untitled](https://raw.githubusercontent.com/yassirlaaouissi/yassirlaaouissi.github.io/master/_screenshots/flareon41.png)

Okay maybe its not a pcap, not very cash money of you mandiant:

![Untitled](https://raw.githubusercontent.com/yassirlaaouissi/yassirlaaouissi.github.io/master/_screenshots/flareon42.png)

okay maybe it is lol, 2 Base64 strings as 200 OK response:

![Untitled](https://raw.githubusercontent.com/yassirlaaouissi/yassirlaaouissi.github.io/master/_screenshots/flareon43.png)

Decoding amounts to nothing yet. The user agents are different, idk why:

![Untitled](https://raw.githubusercontent.com/yassirlaaouissi/yassirlaaouissi.github.io/master/_screenshots/flareon44.png)

![Untitled](https://raw.githubusercontent.com/yassirlaaouissi/yassirlaaouissi.github.io/master/_screenshots/flareon45.png)

This is the main, the variables are quite interesting:

![Untitled](https://raw.githubusercontent.com/yassirlaaouissi/yassirlaaouissi.github.io/master/_screenshots/flareon46.png)

![Untitled](https://raw.githubusercontent.com/yassirlaaouissi/yassirlaaouissi.github.io/master/_screenshots/flareon47.png)

This one probably has to do with an HTTP POST request as we saw in the PCAP:

![Untitled](https://raw.githubusercontent.com/yassirlaaouissi/yassirlaaouissi.github.io/master/_screenshots/flareon48.png)

In the main function I found this sleep function of 12 hours:

![Untitled](https://raw.githubusercontent.com/yassirlaaouissi/yassirlaaouissi.github.io/master/_screenshots/flareon49.png)

Needed to note down what location its stored at:

![Untitled](https://raw.githubusercontent.com/yassirlaaouissi/yassirlaaouissi.github.io/master/_screenshots/flareon50.png)

I can also try and edit iVar6 in debugger:

![Untitled](https://raw.githubusercontent.com/yassirlaaouissi/yassirlaaouissi.github.io/master/_screenshots/flareon51.png)

I patched the binary by making this a JMP instruction. This way it will bypass the sleep and go straight to business:

![Untitled](https://raw.githubusercontent.com/yassirlaaouissi/yassirlaaouissi.github.io/master/_screenshots/flareon52.png)

I exported the PE and ran it. Ran wireshark to capture incomming traffic:

![Untitled](https://raw.githubusercontent.com/yassirlaaouissi/yassirlaaouissi.github.io/master/_screenshots/flareon53.png)

XOR this string with 11 and you will get the .com that is supposed to be behind flare-on:

![Untitled](https://raw.githubusercontent.com/yassirlaaouissi/yassirlaaouissi.github.io/master/_screenshots/flareon54.png)

That string was used in this variable in the main:

![Untitled](https://raw.githubusercontent.com/yassirlaaouissi/yassirlaaouissi.github.io/master/_screenshots/flareon55.png)

Obfuscated with XOR 11 because this:

![Untitled](https://raw.githubusercontent.com/yassirlaaouissi/yassirlaaouissi.github.io/master/_screenshots/flareon56.png)

Retyped this as a list (wchar_t[16]);

![Untitled](https://raw.githubusercontent.com/yassirlaaouissi/yassirlaaouissi.github.io/master/_screenshots/flareon57.png)

He is a pirate (ahoy)?

![Untitled](https://raw.githubusercontent.com/yassirlaaouissi/yassirlaaouissi.github.io/master/_screenshots/flareon58.png)

I was goofing around hitting my head to the wall. But then it all hit me, what if I just convert the digits from the PCAP to ascii and display the output by patching the binary. So I patched the instruction for p2

![Untitled](https://raw.githubusercontent.com/yassirlaaouissi/yassirlaaouissi.github.io/master/_screenshots/flareon59.png)

This way when the digits_to_ascii function gets executed it will get `11950` as digits to translate to ascii. Now all I have to do is figure out a way for it to shit out the ascii characters. I found the function that generates the pseudo-random integer, I could patch what it returns to a hardcoded value:

![Untitled](https://raw.githubusercontent.com/yassirlaaouissi/yassirlaaouissi.github.io/master/_screenshots/flareon60.png)

Instead of moving ECX to EAX you could just move `0x2EAE` into the EAX, because that is the hex value of `11950` from the useragent in the PCAP:

![Untitled](https://raw.githubusercontent.com/yassirlaaouissi/yassirlaaouissi.github.io/master/_screenshots/flareon61.png)

Export the binary and lets run and pull PCAP…. nvm I kind of exceeded the buffer the PCAP showed no request. Lets patch it better now:

![Untitled](https://raw.githubusercontent.com/yassirlaaouissi/yassirlaaouissi.github.io/master/_screenshots/flareon62.png)

Pulling a PCAP:

![Untitled](https://raw.githubusercontent.com/yassirlaaouissi/yassirlaaouissi.github.io/master/_screenshots/flareon63.png)

Okay the request is now the same. Lets see if we can replicate the response with inetsim. Idk why but I think the t8 binary does some magic with the response as well. Especially since it does something with this in the Windows API:

![Untitled](https://raw.githubusercontent.com/yassirlaaouissi/yassirlaaouissi.github.io/master/_screenshots/flareon64.png)

To make a custom response I made the following python script:

```python
from http.server import BaseHTTPRequestHandler, HTTPServer
import time

class RequestHandler(BaseHTTPRequestHandler):
	sys_version = ""
	server_version = "Apache On 9 "
	def date_time_string(self,timestamp=0):
		return "Tue, 14 Jun 2022 16:14:36 GMT"
	def do_POST(self):
		message = "TdQdBRa1nxGU06dbB27E7SQ7TJ2+cd7zstLXRQcLbmh2nTvDm1p5IfT/Cu0JxShk6tHQBRWwPlo9zA1dISfslkLgGDs41WK12ibWIflqLE4Yq3OYIEnLNjwVHrjL2U4Lu3ms+HQc4nfMWXPgcOHb4fhokk93/AJd5GTuC5z+4YsmgRh1Z90yinLBKB+fmGUyagT6gon/KHmJdvAOQ8nAnl8K/0XG+8zYQbZRwgY6tHvvpfyn9OXCyuct5/cOi8KWgALvVHQWafrp8qB/JtT+t5zmnezQlp3zPL4sj2CJfcUTK5copbZCyHexVD4jJN+LezJEtrDXP1DJNg=="
		self.protocol_version = "HTTP/1.0"
		self.send_response(200)
		self.end_headers()
		self.wfile.write(bytes(message, "utf8"))
		return
def run():
	server = ('', 80)
	httpd = HTTPServer(server, RequestHandler)
	httpd.serve_forever()
run()
```

I also eddited the hosts file of my flare VM because it checks DNS. inetsim handles DNS for me now, but when i am gonna run my custom python script imma disable inetsim. And then the binary wont run. The first request/response works now:

![Untitled](https://raw.githubusercontent.com/yassirlaaouissi/yassirlaaouissi.github.io/master/_screenshots/flareon65.png)

Though the second request/response is not the same as the original pcap. It has got the second request, but my script gives back the first response:

![Untitled](https://raw.githubusercontent.com/yassirlaaouissi/yassirlaaouissi.github.io/master/_screenshots/flareon66.png)

So I changed my script to this:

```python
from http.server import BaseHTTPRequestHandler, HTTPServer
import time

class RequestHandler(BaseHTTPRequestHandler):
	sys_version = ""
	server_version = "Apache On 9 "
	def date_time_string(self,timestamp=0):
		return "Tue, 14 Jun 2022 16:14:36 GMT"
	def do_POST(self):
		if "; CLR" in str(self.headers):
			print("Request 2")
			message = "F1KFlZbNGuKQxrTD/ORwudM8S8kKiL5F906YlR8TKd8XrKPeDYZ0HouiBamyQf9/Ns7u3C2UEMLoCA0B8EuZp1FpwnedVjPSdZFjkieYqWzKA7up+LYe9B4dmAUM2lYkmBSqPJYT6nEg27n3X656MMOxNIHt0HsOD0d+"
		else:
			print("Request 1")
			message = "TdQdBRa1nxGU06dbB27E7SQ7TJ2+cd7zstLXRQcLbmh2nTvDm1p5IfT/Cu0JxShk6tHQBRWwPlo9zA1dISfslkLgGDs41WK12ibWIflqLE4Yq3OYIEnLNjwVHrjL2U4Lu3ms+HQc4nfMWXPgcOHb4fhokk93/AJd5GTuC5z+4YsmgRh1Z90yinLBKB+fmGUyagT6gon/KHmJdvAOQ8nAnl8K/0XG+8zYQbZRwgY6tHvvpfyn9OXCyuct5/cOi8KWgALvVHQWafrp8qB/JtT+t5zmnezQlp3zPL4sj2CJfcUTK5copbZCyHexVD4jJN+LezJEtrDXP1DJNg=="
		self.protocol_version = "HTTP/1.0"
		self.send_response(200)
		self.end_headers()
		self.wfile.write(bytes(message, "utf8"))
		return
def run():
	server = ('', 80)
	httpd = HTTPServer(server, RequestHandler)
	httpd.serve_forever()
run()
```

I execute:

![Untitled](https://raw.githubusercontent.com/yassirlaaouissi/yassirlaaouissi.github.io/master/_screenshots/flareon67.png)

Okay fuck, so the PCAP looks excactly the same as the original PCAP ofcourse. But now I need to know which jump in asm triggers this dialog box. Actually since I saw no GDI32 imports, I think those base64 strings are some kinds of shellcode to render that dialogue box. Which means I am even more lost on where the fuck this dialog box comes from xDDDDDD Back to square one….

Nvm all you have to do is run it in a debugger and inspect the stack, I spent way to much time looking for the key:

![Untitled](https://raw.githubusercontent.com/yassirlaaouissi/yassirlaaouissi.github.io/master/_screenshots/flareon68.png)

Flag is: [`i_s33_you_m00n@flare-on.com`](mailto:i_s33_you_m00n@flare-on.com)

# Challenge 6: a la mode

ooeeeeeh nice, finally something that is not C++

![Untitled](https://raw.githubusercontent.com/yassirlaaouissi/yassirlaaouissi.github.io/master/_screenshots/flareon69.png)

All there is is a DLL and this text file:

![Untitled](https://raw.githubusercontent.com/yassirlaaouissi/yassirlaaouissi.github.io/master/_screenshots/flareon70.png)

dnSpy gimme something related to named pipes?

![Untitled](https://raw.githubusercontent.com/yassirlaaouissi/yassirlaaouissi.github.io/master/_screenshots/flareon71.png)

These look like weird strings:

![Untitled](https://raw.githubusercontent.com/yassirlaaouissi/yassirlaaouissi.github.io/master/_screenshots/flareon72.png)

Furthermore all these strings are supplied to the same function:

![Untitled](https://raw.githubusercontent.com/yassirlaaouissi/yassirlaaouissi.github.io/master/_screenshots/flareon73.png)

Looking at that function you can see the strings get XOR-ed with `0x17:`

![Untitled](https://raw.githubusercontent.com/yassirlaaouissi/yassirlaaouissi.github.io/master/_screenshots/flareon74.png)

These strings: translate to the following:

```python
xe~mvc~xy7Qv~{rs
	hex: 78657e6d76637e78793751767e7b7273
	hex-to-xor-17: "orization Failed"

KK9Kg~grKQ{verXy
	hex: 4b4b394b677e67724b517b7665725879
	hex-to-xor-17: "\\.\pipe\FlareOn"

TxyyrtcYvzrsG~gr
	hex: 5478797972746359767a7273477e6772
	hex-to-xor-17: "ConnectNamedPipe"

TervcrYvzrsG~grV
	hex: 54657276637259767a7273477e677256
	hex-to-xor-17: "CreateNamedPipeA"

S~dtxyyrtcYvzrsG~gr
	hex: 537e647478797972746359767a7273477e6772
	hex-to-xor-17: "DisconnectNamedPipe"

Q~{rUbqqred
	hex: 517e7b7255627171726564
	hex-to-xor-17: "FileBuffers"

Prc[vdcReexe
	hex: 5072635b7664635265657865
	hex-to-xor-17: "GetLastError"

PrcGextrdd_rvg
	hex: 507263476578747264645f727667
	hex-to-xor-17: "GetProcessHeap"

{dcetzgV
	hex: 7b646365747a6756
	hex-to-xor-17: "lstrcmpA"

ErvsQ~{r
	hex: 45727673517e7b72
	hex-to-xor-17: "ReadFile"

@e~crQ~{r
	hex: 40657e6372517e7b72
	hex-to-xor-17: "WriteFile"

```

So these are all just API names. Why the shit is this being XOR-ed then.

Looks a lot better now:

![Untitled](https://raw.githubusercontent.com/yassirlaaouissi/yassirlaaouissi.github.io/master/_screenshots/flareon75.png)

Whoops I forgot these three:

![Untitled](https://raw.githubusercontent.com/yassirlaaouissi/yassirlaaouissi.github.io/master/_screenshots/flareon76.png)

Fixed:

![Untitled](https://raw.githubusercontent.com/yassirlaaouissi/yassirlaaouissi.github.io/master/_screenshots/flareon77.png)

To make it more human friendly:

![Untitled](https://raw.githubusercontent.com/yassirlaaouissi/yassirlaaouissi.github.io/master/_screenshots/flareon78.png)

Now if you go back to the function that calls `main_function_caller` you see the following renamed global variable:

![Untitled](https://raw.githubusercontent.com/yassirlaaouissi/yassirlaaouissi.github.io/master/_screenshots/flareon79.png)

what does this 1094 do then? I guess it just creates a named pipe:

![Untitled](https://raw.githubusercontent.com/yassirlaaouissi/yassirlaaouissi.github.io/master/_screenshots/flareon80.png)

Idk its use for now, maybe later it will be usefull. Though towards the end it does a call to 10001000:

![Untitled](https://raw.githubusercontent.com/yassirlaaouissi/yassirlaaouissi.github.io/master/_screenshots/flareon81.png)

What is this then, it only takes two variables??? If you look in the function 10001000 it looks like a standard crypto compare function:

![Untitled](https://raw.githubusercontent.com/yassirlaaouissi/yassirlaaouissi.github.io/master/_screenshots/flareon82.png)

You can remake a script that does the same steps:

```c
#include <cstdint>

int main() {
    uint8_t iv[8] = { 0x55, 0x8b, 0xec, 0x83, 0xec, 0x20, 0xeb, 0xfe, };
	uint8_t dest[12] = { 0x3e, 0x39, 0x51, 0xfb, 0xa2, 0x11, 0xf7, 0xb9, 0x2c, 0x00, 0x00, 0x00, };
	uint8_t flag[32] = { 0xe1, 0x60, 0xa1, 0x18, 0x93, 0x2e, 0x96, 0xad, 0x73, 0xbb, 0x4a, 0x92, 0xde, 0x18, 0x0a, 0xaa, 0x41, 0x74, 0xad, 0xc0, 0x1d, 0x9f, 0x3f, 0x19, 0xff, 0x2b, 0x02, 0xdb, 0xd1, 0xcd, 0x1a, 0x00, };

    uint8_t iVar1;
	uint8_t iVar2;
    uint32_t offset;
    uint8_t iVar3;
	uint8_t uVar3;
	uint32_t iVar4;
	uint32_t uVar4;
	uint32_t uVar2;

    uint32_t table[258] = { 0 };

    table[0] = 0;
    table[1] = 0;

    offset = 0;

    do {
        table[offset + 2] = offset;
        table[offset + 2 + 1] = offset + 1;
        table[offset + 2 + 2] = offset + 2;
        table[offset + 2 + 3] = offset + 3;
        offset = offset + 4;
    } while (offset < 256);

	iVar2 = 0;
    uVar3 = 0;
    offset = 0;
	iVar4 = 0;

	do {
		offset = table[iVar4 + 2];
		uVar3 = (uint8_t) (iv[iVar2] + (char) uVar3 + (char) offset);
		table[iVar4 + 2] = table[uVar3 + 2];
		iVar1 = iVar2 + 1;
		table[uVar3 + 2] = offset;
		iVar4 = iVar4 + 1;
		iVar2 = 0;
		if (iVar1 < 8) {
			iVar2 = iVar1;
		}
	} while (iVar4 < 256);

	uint32_t i;
	uint8_t uVar1;
	char cVar3;

	i = 0;
	uint8_t local_4;
	local_4 = table[1];
	uVar4 = table[0];

	if (0 < 9) {
		do {
			uVar4 = (char) uVar4 + 1;
			uVar1 = table[uVar4 + 2];
			cVar3 = (char)uVar1;
			local_4 = (uint8_t) ((char) uVar1 + (char)local_4);
			uVar2 = table[local_4 + 2];
			table[uVar4 + 2] = uVar2;
			table[local_4 + 2] = uVar1;
			dest[i] = dest[i] ^ table[(uint8_t)(cVar3 + (char) uVar2) + 2];
			i = i + 1;
		} while (i < 9);
	}

	table[0] = uVar4;
	table[1] = local_4;

	printf("%s\\n", dest);

	// for (i = 0; i < 8; i++) {
	// 	printf("%c", dest[i]);
	// }

	i = 0;
	local_4 = table[1];
	uVar4 = table[0];

	if (0 < 0x1f) {
		do {
			uVar4 = uVar4 + 1;
			uVar1 = table[uVar4 + 2];
			cVar3 = (char)uVar1;
			local_4 = (uint8_t) ((char) uVar1 + (char)local_4);
			uVar2 = table[local_4 + 2];
			table[uVar4 + 2] = uVar2;
			table[local_4 + 2] = uVar1;
			flag[i] = flag[i] ^ table[(uint8_t)(cVar3 + (char) uVar2) + 2];
			i = i + 1;
		} while (i < 0x1f);
	}

	table[0] = uVar4;
	table[1] = local_4;

	for (i = 0; i < 0x1f; i++) {
		printf("%c", flag[i]);
	}

    return 0;
}

```

Compile it with these instructions:

```c
cl /EHsc main.cpp
```

Run it:

![Untitled](https://raw.githubusercontent.com/yassirlaaouissi/yassirlaaouissi.github.io/master/_screenshots/flareon83.png)

Done, fuck this shit.

## Challenge 7: anode

Aight letsgo to challenge 7:

![Untitled](https://raw.githubusercontent.com/yassirlaaouissi/yassirlaaouissi.github.io/master/_screenshots/flareon84.png)

The name and EXE in the zip makes me think of nodejs for some reason:

 

![Untitled](https://raw.githubusercontent.com/yassirlaaouissi/yassirlaaouissi.github.io/master/_screenshots/flareon85.png)

![Untitled](https://raw.githubusercontent.com/yassirlaaouissi/yassirlaaouissi.github.io/master/_screenshots/flareon86.png)

I got a feeling that this is gonna take a while for ghidra (me from the future; it took me a long fucking time):

![Untitled](https://raw.githubusercontent.com/yassirlaaouissi/yassirlaaouissi.github.io/master/_screenshots/flareon87.png)

So while we wait, allow me to make a segway to our sponsor, NORDVPN

![Untitled](https://raw.githubusercontent.com/yassirlaaouissi/yassirlaaouissi.github.io/master/_screenshots/flareon88.png)

Oh wow, look what I found with strings:

![Untitled](https://raw.githubusercontent.com/yassirlaaouissi/yassirlaaouissi.github.io/master/_screenshots/flareon89.png)

I guess if this is in resources we could just apply the same trick we used in an earlier challenge:

![Untitled](https://raw.githubusercontent.com/yassirlaaouissi/yassirlaaouissi.github.io/master/_screenshots/flareon90.png)

Lol nope nvm :( Lets see what that JS file is about. Apperantly the flag must be 44 characters:

![Untitled](https://raw.githubusercontent.com/yassirlaaouissi/yassirlaaouissi.github.io/master/_screenshots/flareon91.png)

After that check you can see it pushes each character to a list called `b[]` as a characterCode. In order to get Congrats in the console.log you need to have every item in B matching the items in target:

![Untitled](https://raw.githubusercontent.com/yassirlaaouissi/yassirlaaouissi.github.io/master/_screenshots/flareon92.png)

Target contains 44 items, which are character codes for the following string. I was digging a bit for that `var state = 1337` in order to find the seed for `math.random` and then I found this:

![Untitled](https://raw.githubusercontent.com/yassirlaaouissi/yassirlaaouissi.github.io/master/_screenshots/flareon93.png)

Why the fuck does it start a socket on port 1337? Idk why, anywho I think that math.random is very broken. It must have some kind of seed that makes the number not so random.  Then it became a bit clearer what to do, you can inject your own JS into the binary. But this binary checks for the size of the script. Therefore a dear friend of mine called Yoran speedran this script to patch the binary:

```c
Usage: ./patch.py anode.exe resource.js anode-new.exe 
```

```python
#!/usr/bin/env python3

import sys
import os
import struct
from math import floor

FOOTER_STRUCT = "<dd"
FOOTER_STRUCT_SZ = struct.calcsize(FOOTER_STRUCT)

FOOTER_MAGIC = b"<nexe~~sentinel>"

def main(args):
    infile = args[0]
    patchfile = args[1]
    outfile = args[2]

    infile_sz = os.path.getsize(infile)

    with open(infile, "rb") as infile_stream:
        infile_stream.seek(infile_sz - FOOTER_STRUCT_SZ)
        content_sz, resource_sz = [ floor(x) for x in struct.unpack_from(FOOTER_STRUCT, infile_stream.read()) ]

        # seek back to the packed footer
        infile_stream.seek(0 - len(FOOTER_MAGIC) - FOOTER_STRUCT_SZ, os.SEEK_CUR)

        # from there, seek back to the beginning of the content payload
        infile_stream.seek(0 - (content_sz + resource_sz), os.SEEK_CUR)

        # now we can read both the content and resource payloads
        content_buf = infile_stream.read(content_sz)
        resource_buf = infile_stream.read(resource_sz)

    print("Content size: {}".format(content_sz))
    print("Resource size: {}".format(resource_sz))

    print("Retrieved content size: {}".format(len(content_buf)))
    print("Retrieved resource size: {}".format(len(resource_buf)))

    with open(patchfile, "rb") as patchfile_stream:
        patch = patchfile_stream.read()

    with open(outfile, "wb") as outfile_stream:
        with open(infile, "rb") as infile_stream:
            remainder = infile_sz - content_sz - resource_sz - len(FOOTER_MAGIC) - FOOTER_STRUCT_SZ
            while remainder > 0:
                buf = infile_stream.read(min(remainder, 8192 * 1024))
                outfile_stream.write(buf)
                remainder -= len(buf)
                print(remainder)
        
        patch_sz = len(patch)
        content_buf = content_buf.replace(str(resource_sz).encode(), str(patch_sz).encode())
        outfile_stream.write(content_buf)
        outfile_stream.write(patch)
        outfile_stream.write(FOOTER_MAGIC)
        outfile_stream.write(struct.pack(FOOTER_STRUCT, len(content_buf), patch_sz))

if __name__ == "__main__":
    main(sys.argv[1:])
```

Soooo, all this requires us to do is writeing a similiar JS file with magic stuff we want it to do. I rewrote the JS file to this:

```python
const readline = require('readline').createInterface({
  input: process.stdin,
  output: process.stdout,
});
readline.question(`Enter flag: `, flag => {
  readline.close();
  if (flag.length !== 44) {
    console.log("Try again.");
    process.exit(0);
  }
  var b = [];
  for (var i = 0; i < flag.length; i++) {
    b.push(flag.charCodeAt(i));
    //b.push(0);
  }
  console.log(b)
  // something strange is happening...
  //if (1n) {
  //  console.log("uh-oh, math is too correct...");
  //  process.exit(0);
  // }
  var state = 1337;
  var calcs = []
  while (true) {
    state ^= Math.floor(Math.random() * (2**30));
    switch (state) {
      case 306211:
        if (Math.random() < 0.5) {
          calcs += "^b[30] -= b[34] + b[23] + b[5] + b[37] + b[33] + b[12] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[30] &= 0xFF;"
        } else {
          calcs += "^b[26] -= b[24] + b[41] + b[13] + b[43] + b[6] + b[30] + 225;"
          calcs += "^b[26] &= 0xFF;"
        }
        state = 868071080;
        continue;
      case 311489:
        if (Math.random() < 0.5) {
          calcs += "^b[10] -= b[32] + b[1] + b[20] + b[30] + b[23] + b[9] + 115;"
          calcs += "^b[10] &= 0xFF;"
        } else {
          calcs += "^b[7] ^= (b[18] + b[14] + b[11] + b[25] + b[31] + b[21] + 19) & 0xFF;"
        }
        state = 22167546;
        continue;
      case 755154:
        if (93909087n) {
          calcs += "^b[4] -= b[42] + b[6] + b[26] + b[39] + b[35] + b[16] + 80;"
          calcs += "^b[4] &= 0xFF;"
        } else {
          calcs += "^b[16] += b[36] + b[2] + b[29] + b[10] + b[12] + b[18] + 202;"
          calcs += "^b[16] &= 0xFF;"
        }
        state = 857247560;
        continue;
      case 832320:
        if (720624460) {
          calcs += "^b[40] -= b[12] + b[9] + b[27] + b[39] + b[26] + b[4] + 199;"
          calcs += "^b[40] &= 0xFF;"
        } else {
          calcs += "^b[11] ^= (b[30] + b[38] + b[6] + b[22] + b[3] + b[18] + 218) & 0xFF;"
        }
        state = 420839059;
        continue;
      case 3396517:
        if (70881172) {
          calcs += "^b[9] ^= (b[12] + b[32] + b[28] + b[43] + b[16] + b[27] + " + Math.floor(Math.random() * 256) + ") & 0xFF;"
        } else {
          calcs += "^b[23] += b[34] + b[7] + b[32] + b[2] + b[12] + b[11] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[23] &= 0xFF;"
        }
        state = 981691089;
        continue;
      case 4634906:
        if (35127076n) {
          calcs += "^b[24] += b[39] + b[14] + b[18] + b[36] + b[15] + b[27] + 142;"
          calcs += "^b[24] &= 0xFF;"
        } else {
          calcs += "^b[8] ^= (b[1] + b[39] + b[16] + b[38] + b[40] + b[25] + 144) & 0xFF;"
        }
        state = 1009116244;
        continue;
      case 7607673:
        if (254681112) {
          calcs += "^b[12] += b[10] + b[38] + b[16] + b[31] + b[43] + b[26] + 96;"
          calcs += "^b[12] &= 0xFF;"
        } else {
          calcs += "^b[27] += b[18] + b[23] + b[22] + b[8] + b[2] + b[9] + 98;"
          calcs += "^b[27] &= 0xFF;"
        }
        state = 801997414;
        continue;
      case 8385273:
        if (738704438) {
          calcs += "^b[28] += b[41] + b[43] + b[4] + b[6] + b[38] + b[10] + 43;"
          calcs += "^b[28] &= 0xFF;"
        } else {
          calcs += "^b[10] -= b[9] + b[32] + b[42] + b[41] + b[21] + b[8] + 100;"
          calcs += "^b[10] &= 0xFF;"
        }
        state = 395953466;
        continue;
      case 8624110:
        if (794146476) {
          calcs += "^b[24] -= b[11] + b[16] + b[38] + b[1] + b[23] + b[17] + 168;"
          calcs += "^b[24] &= 0xFF;"
        } else {
          calcs += "^b[24] -= b[22] + b[38] + b[33] + b[36] + b[15] + b[43] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[24] &= 0xFF;"
        }
        state = 855479214;
        continue;
      case 8969443:
        if (Math.random() < 0.5) {
          calcs += "^b[1] += b[2] + b[28] + b[40] + b[37] + b[34] + b[11] + 25;"
          calcs += "^b[1] &= 0xFF;"
        } else {
          calcs += "^b[11] += b[12] + b[27] + b[21] + b[34] + b[8] + b[9] + 86;"
          calcs += "^b[11] &= 0xFF;"
        }
        state = 1021591257;
        continue;
      case 10705897:
        if (82750014n) {
          calcs += "^b[37] += b[8] + b[6] + b[10] + b[2] + b[36] + b[14] + 116;"
          calcs += "^b[37] &= 0xFF;"
        } else {
          calcs += "^b[38] += b[5] + b[10] + b[40] + b[19] + b[33] + b[29] + 48;"
          calcs += "^b[38] &= 0xFF;"
        }
        state = 633534954;
        continue;
      case 13789280:
        if (63441291n) {
          calcs += "^b[9] -= b[1] + b[37] + b[40] + b[15] + b[11] + b[10] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[9] &= 0xFF;"
        } else {
          calcs += "^b[3] -= b[31] + b[37] + b[33] + b[7] + b[23] + b[32] + 157;"
          calcs += "^b[3] &= 0xFF;"
        }
        state = 73809693;
        continue;
      case 15648489:
        if (Math.random() < 0.5) {
          calcs += "^b[25] -= b[33] + b[26] + b[2] + b[29] + b[17] + b[4] + 52;"
          calcs += "^b[25] &= 0xFF;"
        } else {
          calcs += "^b[12] += b[2] + b[25] + b[28] + b[6] + b[34] + b[7] + 222;"
          calcs += "^b[12] &= 0xFF;"
        }
        state = 289786620;
        continue;
      case 16997611:
        if (51321786n) {
          calcs += "^b[37] -= b[28] + b[31] + b[17] + b[42] + b[16] + b[40] + 244;"
          calcs += "^b[37] &= 0xFF;"
        } else {
          calcs += "^b[5] ^= (b[35] + b[39] + b[40] + b[16] + b[10] + b[13] + " + Math.floor(Math.random() * 256) + ") & 0xFF;"
        }
        state = 919058588;
        continue;
      case 17290114:
        if (Math.random() < 0.5) {
          calcs += "^b[5] -= b[20] + b[43] + b[9] + b[3] + b[40] + b[25] + 50;"
          calcs += "^b[5] &= 0xFF;"
        } else {
          calcs += "^b[40] += b[24] + b[16] + b[5] + b[33] + b[35] + b[14] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[40] &= 0xFF;"
        }
        state = 372794266;
        continue;
      case 18752034:
        if (Math.random() < 0.5) {
          calcs += "^b[9] += b[4] + b[43] + b[39] + b[16] + b[15] + b[22] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[9] &= 0xFF;"
        } else {
          calcs += "^b[22] -= b[21] + b[1] + b[9] + b[27] + b[42] + b[32] + 120;"
          calcs += "^b[22] &= 0xFF;"
        }
        state = 343127230;
        continue;
      case 19165082:
        if (256406096) {
          calcs += "^b[39] += b[3] + b[26] + b[19] + b[31] + b[37] + b[8] + 23;"
          calcs += "^b[39] &= 0xFF;"
        } else {
          calcs += "^b[33] -= b[30] + b[12] + b[32] + b[34] + b[18] + b[40] + 2;"
          calcs += "^b[33] &= 0xFF;"
        }
        state = 302103001;
        continue;
      case 20347334:
        if (157077096) {
          calcs += "^b[35] += b[4] + b[25] + b[42] + b[41] + b[17] + b[10] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[35] &= 0xFF;"
        } else {
          calcs += "^b[21] ^= (b[2] + b[3] + b[12] + b[16] + b[6] + b[15] + 100) & 0xFF;"
        }
        state = 302039243;
        continue;
      case 22221850:
        if (1052707195) {
          calcs += "^b[13] ^= (b[30] + b[33] + b[28] + b[32] + b[12] + b[41] + " + Math.floor(Math.random() * 256) + ") & 0xFF;"
        } else {
          calcs += "^b[2] ^= (b[29] + b[1] + b[26] + b[42] + b[12] + b[10] + 81) & 0xFF;"
        }
        state = 554472923;
        continue;
      case 22756596:
        if (572655368) {
          calcs += "^b[15] ^= (b[2] + b[3] + b[17] + b[10] + b[13] + b[24] + 118) & 0xFF;"
        } else {
          calcs += "^b[1] ^= (b[16] + b[36] + b[17] + b[39] + b[35] + b[9] + 108) & 0xFF;"
        }
        state = 399237037;
        continue;
      case 24385348:
        if (Math.random() < 0.5) {
          calcs += "^b[11] ^= (b[31] + b[20] + b[13] + b[27] + b[24] + b[21] + 114) & 0xFF;"
        } else {
          calcs += "^b[42] += b[10] + b[12] + b[19] + b[30] + b[5] + b[11] + 156;"
          calcs += "^b[42] &= 0xFF;"
        }
        state = 1056987786;
        continue;
      case 24833479:
        if (Math.random() < 0.5) {
          calcs += "^b[31] += b[8] + b[5] + b[3] + b[13] + b[6] + b[39] + 14;"
          calcs += "^b[31] &= 0xFF;"
        } else {
          calcs += "^b[39] += b[24] + b[12] + b[9] + b[25] + b[42] + b[37] + 160;"
          calcs += "^b[39] &= 0xFF;"
        }
        state = 750166606;
        continue;
      case 27587950:
        if (57380710n) {
          calcs += "^b[38] += b[1] + b[8] + b[31] + b[39] + b[7] + b[18] + 150;"
          calcs += "^b[38] &= 0xFF;"
        } else {
          calcs += "^b[17] -= b[34] + b[35] + b[16] + b[9] + b[14] + b[8] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[17] &= 0xFF;"
        }
        state = 620289833;
        continue;
      case 27798221:
        if (Math.random() < 0.5) {
          calcs += "^b[14] ^= (b[31] + b[42] + b[35] + b[4] + b[11] + b[19] + 206) & 0xFF;"
        } else {
          calcs += "^b[29] += b[39] + b[36] + b[23] + b[31] + b[5] + b[26] + 105;"
          calcs += "^b[29] &= 0xFF;"
        }
        state = 894374157;
        continue;
      case 28799325:
        if (62542139n) {
          calcs += "^b[25] -= b[31] + b[29] + b[8] + b[36] + b[23] + b[40] + 216;"
          calcs += "^b[25] &= 0xFF;"
        } else {
          calcs += "^b[4] -= b[40] + b[9] + b[23] + b[38] + b[18] + b[6] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[4] &= 0xFF;"
        }
        state = 984870261;
        continue;
      case 28925148:
        if (Math.random() < 0.5) {
          calcs += "^b[34] -= b[24] + b[36] + b[5] + b[6] + b[22] + b[11] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[34] &= 0xFF;"
        } else {
          calcs += "^b[26] += b[16] + b[36] + b[33] + b[2] + b[13] + b[20] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[26] &= 0xFF;"
        }
        state = 909491047;
        continue;
      case 30908364:
        if (35931224n) {
          calcs += "^b[14] ^= (b[30] + b[15] + b[38] + b[22] + b[16] + b[35] + 132) & 0xFF;"
        } else {
          calcs += "^b[35] ^= (b[37] + b[43] + b[27] + b[22] + b[31] + b[15] + 150) & 0xFF;"
        }
        state = 1062403814;
        continue;
      case 34833634:
        if (375677031) {
          calcs += "^b[37] += b[35] + b[19] + b[32] + b[7] + b[41] + b[0] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[37] &= 0xFF;"
        } else {
          calcs += "^b[5] += b[11] + b[20] + b[24] + b[37] + b[33] + b[38] + 113;"
          calcs += "^b[5] &= 0xFF;"
        }
        state = 740484943;
        continue;
      case 34947844:
        if (447103476) {
          calcs += "^b[14] += b[23] + b[4] + b[27] + b[20] + b[29] + b[0] + 166;"
          calcs += "^b[14] &= 0xFF;"
        } else {
          calcs += "^b[8] += b[1] + b[25] + b[39] + b[34] + b[24] + b[9] + 172;"
          calcs += "^b[8] &= 0xFF;"
        }
        state = 843006226;
        continue;
      case 34972620:
        if (345553606) {
          calcs += "^b[23] += b[10] + b[40] + b[26] + b[0] + b[28] + b[19] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[23] &= 0xFF;"
        } else {
          calcs += "^b[42] += b[1] + b[29] + b[8] + b[32] + b[23] + b[16] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[42] &= 0xFF;"
        }
        state = 299526397;
        continue;
      case 38681753:
        if (Math.random() < 0.5) {
          calcs += "^b[15] += b[36] + b[13] + b[25] + b[9] + b[0] + b[24] + 18;"
          calcs += "^b[15] &= 0xFF;"
        } else {
          calcs += "^b[41] += b[33] + b[12] + b[27] + b[40] + b[9] + b[4] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[41] &= 0xFF;"
        }
        state = 277618656;
        continue;
      case 39901217:
        if (781285820) {
          calcs += "^b[10] ^= (b[30] + b[33] + b[41] + b[12] + b[26] + b[31] + 216) & 0xFF;"
        } else {
          calcs += "^b[34] -= b[43] + b[0] + b[24] + b[6] + b[36] + b[41] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[34] &= 0xFF;"
        }
        state = 465346590;
        continue;
      case 39933208:
        if (927103657) {
          calcs += "^b[18] -= b[2] + b[10] + b[6] + b[19] + b[9] + b[15] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[18] &= 0xFF;"
        } else {
          calcs += "^b[23] -= b[32] + b[13] + b[35] + b[34] + b[14] + b[1] + 195;"
          calcs += "^b[23] &= 0xFF;"
        }
        state = 374789219;
        continue;
      case 42721917:
        if (69259497n) {
          calcs += "^b[28] ^= (b[10] + b[34] + b[31] + b[29] + b[17] + b[11] + " + Math.floor(Math.random() * 256) + ") & 0xFF;"
        } else {
          calcs += "^b[7] += b[4] + b[34] + b[24] + b[30] + b[35] + b[20] + 225;"
          calcs += "^b[7] &= 0xFF;"
        }
        state = 278335386;
        continue;
      case 44075365:
        if (419589377) {
          calcs += "^b[24] ^= (b[32] + b[6] + b[39] + b[21] + b[16] + b[15] + " + Math.floor(Math.random() * 256) + ") & 0xFF;"
        } else {
          calcs += "^b[18] -= b[25] + b[39] + b[0] + b[35] + b[42] + b[6] + 84;"
          calcs += "^b[18] &= 0xFF;"
        }
        state = 773690009;
        continue;
      case 45845929:
        if (893934628) {
          calcs += "^b[30] += b[13] + b[41] + b[10] + b[19] + b[24] + b[2] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[30] &= 0xFF;"
        } else {
          calcs += "^b[8] += b[30] + b[1] + b[37] + b[6] + b[26] + b[10] + 198;"
          calcs += "^b[8] &= 0xFF;"
        }
        state = 345530955;
        continue;
      case 46607160:
        if (Math.random() < 0.5) {
          calcs += "^b[6] += b[43] + b[36] + b[42] + b[4] + b[19] + b[24] + 91;"
          calcs += "^b[6] &= 0xFF;"
        } else {
          calcs += "^b[13] -= b[7] + b[34] + b[31] + b[25] + b[14] + b[6] + 174;"
          calcs += "^b[13] &= 0xFF;"
        }
        state = 996693809;
        continue;
      case 46747763:
        if (76892474n) {
          calcs += "^b[23] -= b[32] + b[11] + b[36] + b[20] + b[35] + b[34] + 25;"
          calcs += "^b[23] &= 0xFF;"
        } else {
          calcs += "^b[1] -= b[0] + b[22] + b[29] + b[31] + b[18] + b[9] + 50;"
          calcs += "^b[1] &= 0xFF;"
        }
        state = 648867131;
        continue;
      case 46928954:
        if (Math.random() < 0.5) {
          calcs += "^b[17] += b[3] + b[13] + b[37] + b[25] + b[8] + b[0] + 53;"
          calcs += "^b[17] &= 0xFF;"
        } else {
          calcs += "^b[25] ^= (b[2] + b[27] + b[23] + b[4] + b[34] + b[0] + 133) & 0xFF;"
        }
        state = 240398672;
        continue;
      case 48246086:
        if (588937531) {
          calcs += "^b[11] -= b[26] + b[13] + b[17] + b[10] + b[14] + b[42] + 62;"
          calcs += "^b[11] &= 0xFF;"
        } else {
          calcs += "^b[35] += b[37] + b[23] + b[18] + b[26] + b[20] + b[30] + 140;"
          calcs += "^b[35] &= 0xFF;"
        }
        state = 794163495;
        continue;
      case 49148585:
        if (417990032) {
          calcs += "^b[1] -= b[9] + b[24] + b[17] + b[40] + b[14] + b[26] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[1] &= 0xFF;"
        } else {
          calcs += "^b[4] ^= (b[22] + b[2] + b[17] + b[1] + b[9] + b[40] + " + Math.floor(Math.random() * 256) + ") & 0xFF;"
        }
        state = 487330863;
        continue;
      case 49324191:
        if (95502376n) {
          calcs += "^b[26] -= b[27] + b[9] + b[21] + b[39] + b[6] + b[25] + 65;"
          calcs += "^b[26] &= 0xFF;"
        } else {
          calcs += "^b[19] -= b[24] + b[30] + b[42] + b[11] + b[43] + b[17] + 163;"
          calcs += "^b[19] &= 0xFF;"
        }
        state = 71981081;
        continue;
      case 50858850:
        if (796808282) {
          calcs += "^b[21] -= b[8] + b[14] + b[15] + b[0] + b[26] + b[10] + 71;"
          calcs += "^b[21] &= 0xFF;"
        } else {
          calcs += "^b[12] ^= (b[19] + b[16] + b[28] + b[14] + b[40] + b[33] + 158) & 0xFF;"
        }
        state = 465897814;
        continue;
      case 54109746:
        if (Math.random() < 0.5) {
          calcs += "^b[20] ^= (b[40] + b[15] + b[25] + b[34] + b[19] + b[42] + 251) & 0xFF;"
        } else {
          calcs += "^b[3] -= b[29] + b[39] + b[8] + b[19] + b[10] + b[5] + 132;"
          calcs += "^b[3] &= 0xFF;"
        }
        state = 551432967;
        continue;
      case 59933137:
        if (13822198n) {
          calcs += "^b[27] += b[5] + b[28] + b[42] + b[4] + b[38] + b[3] + 221;"
          calcs += "^b[27] &= 0xFF;"
        } else {
          calcs += "^b[0] ^= (b[26] + b[4] + b[34] + b[16] + b[15] + b[7] + 115) & 0xFF;"
        }
        state = 762796303;
        continue;
      case 61896397:
        if (17375720n) {
          calcs += "^b[31] -= b[29] + b[40] + b[13] + b[24] + b[43] + b[30] + 59;"
          calcs += "^b[31] &= 0xFF;"
        } else {
          calcs += "^b[33] += b[17] + b[11] + b[40] + b[2] + b[20] + b[42] + 39;"
          calcs += "^b[33] &= 0xFF;"
        }
        state = 620414172;
        continue;
      case 62103505:
        if (Math.random() < 0.5) {
          calcs += "^b[6] ^= (b[35] + b[37] + b[7] + b[31] + b[29] + b[15] + 217) & 0xFF;"
        } else {
          calcs += "^b[25] ^= (b[3] + b[37] + b[35] + b[23] + b[24] + b[27] + 77) & 0xFF;"
        }
        state = 1029688904;
        continue;
      case 62120866:
        if (82193589n) {
                      calcs += "^b[19] += b[21] + b[17] + b[10] + b[33] + b[28] + b[34] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[19] &= 0xFF;"
        } else {
          calcs += "^b[42] ^= (b[8] + b[4] + b[28] + b[10] + b[33] + b[6] + 226) & 0xFF;"
        }
        state = 900361163;
        continue;
      case 62123647:
        if (10182515n) {
          calcs += "^b[5] -= b[39] + b[26] + b[32] + b[13] + b[40] + b[31] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[5] &= 0xFF;"
        } else {
          calcs += "^b[41] ^= (b[24] + b[30] + b[0] + b[26] + b[25] + b[3] + 85) & 0xFF;"
        }
        state = 9530685;
        continue;
      case 62823208:
        if (55503888n) {
          calcs += "^b[16] -= b[13] + b[41] + b[6] + b[15] + b[20] + b[10] + 21;"
          calcs += "^b[16] &= 0xFF;"
        } else {
          calcs += "^b[8] -= b[11] + b[9] + b[32] + b[5] + b[22] + b[42] + 4;"
          calcs += "^b[8] &= 0xFF;"
        }
        state = 71885864;
        continue;
      case 64944481:
        if (Math.random() < 0.5) {
          calcs += "^b[30] += b[13] + b[3] + b[31] + b[16] + b[7] + b[34] + 200;"
          calcs += "^b[30] &= 0xFF;"
        } else {
          calcs += "^b[8] += b[2] + b[14] + b[13] + b[15] + b[7] + b[9] + 91;"
          calcs += "^b[8] &= 0xFF;"
        }
        state = 1069782404;
        continue;
      case 65487162:
        if (92018218n) {
          calcs += "^b[24] -= b[33] + b[37] + b[21] + b[1] + b[36] + b[12] + 29;"
          calcs += "^b[24] &= 0xFF;"
        } else {
          calcs += "^b[17] -= b[3] + b[5] + b[14] + b[40] + b[27] + b[24] + 29;"
          calcs += "^b[17] &= 0xFF;"
        }
        state = 595543388;
        continue;
      case 67023845:
        if (Math.random() < 0.5) {
          calcs += "^b[19] += b[31] + b[26] + b[18] + b[27] + b[22] + b[5] + 222;"
          calcs += "^b[19] &= 0xFF;"
        } else {
          calcs += "^b[20] += b[35] + b[19] + b[11] + b[14] + b[12] + b[25] + 29;"
          calcs += "^b[20] &= 0xFF;"
        }
        state = 553195647;
        continue;
      case 67652373:
        if (824219142) {
          calcs += "^b[13] ^= (b[8] + b[24] + b[29] + b[10] + b[12] + b[20] + 19) & 0xFF;"
        } else {
          calcs += "^b[43] ^= (b[11] + b[17] + b[36] + b[26] + b[30] + b[8] + 200) & 0xFF;"
        }
        state = 319612083;
        continue;
      case 68328143:
        if (802998580) {
          calcs += "^b[12] += b[37] + b[17] + b[6] + b[23] + b[5] + b[14] + 88;"
          calcs += "^b[12] &= 0xFF;"
        } else {
          calcs += "^b[12] -= b[21] + b[23] + b[0] + b[32] + b[28] + b[17] + 252;"
          calcs += "^b[12] &= 0xFF;"
        }
        state = 958557393;
        continue;
      case 69352640:
        if (56702756) {
          calcs += "^b[3] ^= (b[14] + b[35] + b[9] + b[16] + b[38] + b[27] + 168) & 0xFF;"
        } else {
          calcs += "^b[39] ^= (b[1] + b[38] + b[10] + b[5] + b[23] + b[19] + 138) & 0xFF;"
        }
        state = 183100909;
        continue;
      case 70871791:
        if (Math.random() < 0.5) {
          calcs += "^b[9] += b[14] + b[38] + b[21] + b[30] + b[8] + b[40] + 179;"
          calcs += "^b[9] &= 0xFF;"
        } else {
          calcs += "^b[2] += b[40] + b[42] + b[9] + b[28] + b[14] + b[30] + 126;"
          calcs += "^b[2] &= 0xFF;"
        }
        state = 561771291;
        continue;
      case 72161969:
        if (Math.random() < 0.5) {
          calcs += "^b[5] += b[30] + b[23] + b[6] + b[24] + b[15] + b[18] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[5] &= 0xFF;"
        } else {
          calcs += "^b[10] += b[1] + b[6] + b[3] + b[15] + b[38] + b[35] + 252;"
          calcs += "^b[10] &= 0xFF;"
        }
        state = 743467963;
        continue;
      case 72439384:
        if (70328947n) {
          calcs += "^b[24] -= b[8] + b[35] + b[21] + b[9] + b[2] + b[22] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[24] &= 0xFF;"
        } else {
          calcs += "^b[6] += b[36] + b[18] + b[31] + b[1] + b[43] + b[5] + 4;"
          calcs += "^b[6] &= 0xFF;"
        }
        state = 565201962;
        continue;
      case 72654807:
        if (639707451) {
          calcs += "^b[18] -= b[5] + b[11] + b[28] + b[8] + b[19] + b[24] + 10;"
          calcs += "^b[18] &= 0xFF;"
        } else {
          calcs += "^b[21] += b[24] + b[22] + b[26] + b[0] + b[36] + b[6] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[21] &= 0xFF;"
        }
        state = 200999436;
        continue;
      case 73566854:
        if (29773184n) {
          calcs += "^b[16] -= b[38] + b[2] + b[13] + b[22] + b[40] + b[7] + 98;"
          calcs += "^b[16] &= 0xFF;"
        } else {
          calcs += "^b[25] -= b[17] + b[0] + b[37] + b[39] + b[11] + b[28] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[25] &= 0xFF;"
        }
        state = 647560898;
        continue;
      case 74663331:
        if (Math.random() < 0.5) {
          calcs += "^b[3] -= b[4] + b[16] + b[36] + b[24] + b[19] + b[12] + 53;"
          calcs += "^b[3] &= 0xFF;"
        } else {
          calcs += "^b[14] -= b[3] + b[12] + b[22] + b[19] + b[35] + b[38] + 115;"
          calcs += "^b[14] &= 0xFF;"
        }
        state = 120002893;
        continue;
      case 74705707:
        if (56658661n) {
          calcs += "^b[7] += b[29] + b[21] + b[22] + b[3] + b[1] + b[38] + 169;"
          calcs += "^b[7] &= 0xFF;"
        } else {
          calcs += "^b[26] -= b[29] + b[20] + b[22] + b[5] + b[13] + b[27] + 202;"
          calcs += "^b[26] &= 0xFF;"
        }
        state = 241317555;
        continue;
      case 75488718:
        if (55862869n) {
          calcs += "^b[6] ^= (b[26] + b[43] + b[28] + b[36] + b[25] + b[30] + 159) & 0xFF;"
        } else {
          calcs += "^b[12] ^= (b[7] + b[38] + b[20] + b[21] + b[1] + b[36] + 136) & 0xFF;"
        }
        state = 585049676;
        continue;
      case 76812692:
        if (205705560) {
          calcs += "^b[38] += b[21] + b[37] + b[13] + b[28] + b[16] + b[39] + 8;"
          calcs += "^b[38] &= 0xFF;"
        } else {
          calcs += "^b[21] -= b[31] + b[13] + b[2] + b[15] + b[34] + b[37] + 41;"
          calcs += "^b[21] &= 0xFF;"
        }
        state = 850695262;
        continue;
      case 76961033:
        if (31646617n) {
          calcs += "^b[24] ^= (b[17] + b[38] + b[32] + b[14] + b[35] + b[28] + 96) & 0xFF;"
        } else {
          calcs += "^b[33] ^= (b[8] + b[26] + b[23] + b[0] + b[30] + b[9] + 207) & 0xFF;"
        }
        state = 1037693180;
        continue;
      case 77583880:
        if (62485669n) {
          calcs += "^b[10] -= b[41] + b[29] + b[42] + b[37] + b[4] + b[23] + 211;"
          calcs += "^b[10] &= 0xFF;"
        } else {
          calcs += "^b[1] ^= (b[29] + b[38] + b[34] + b[42] + b[13] + b[41] + 214) & 0xFF;"
        }
        state = 296344129;
        continue;
      case 77910142:
        if (600975230) {
          calcs += "^b[38] += b[24] + b[26] + b[22] + b[3] + b[11] + b[12] + 33;"
          calcs += "^b[38] &= 0xFF;"
        } else {
          calcs += "^b[10] -= b[32] + b[39] + b[7] + b[21] + b[30] + b[1] + 90;"
          calcs += "^b[10] &= 0xFF;"
        }
        state = 782879555;
        continue;
      case 78399834:
        if (56847919n) {
          calcs += "^b[1] -= b[30] + b[27] + b[38] + b[28] + b[11] + b[0] + 42;"
          calcs += "^b[1] &= 0xFF;"
        } else {
          calcs += "^b[41] -= b[42] + b[29] + b[35] + b[11] + b[6] + b[34] + 83;"
          calcs += "^b[41] &= 0xFF;"
        }
        state = 513256234;
        continue;
      case 79593073:
        if (Math.random() < 0.5) {
          calcs += "^b[32] ^= (b[33] + b[12] + b[21] + b[7] + b[36] + b[2] + 173) & 0xFF;"
        } else {
          calcs += "^b[37] += b[29] + b[35] + b[20] + b[22] + b[43] + b[32] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[37] &= 0xFF;"
        }
        state = 384670766;
        continue;
      case 81117788:
        if (801248195) {
          calcs += "^b[30] -= b[32] + b[19] + b[29] + b[5] + b[16] + b[21] + 34;"
          calcs += "^b[30] &= 0xFF;"
        } else {
          calcs += "^b[3] -= b[38] + b[9] + b[11] + b[8] + b[34] + b[7] + 167;"
          calcs += "^b[3] &= 0xFF;"
        }
        state = 999933095;
        continue;
      case 82799741:
        if (Math.random() < 0.5) {
          calcs += "^b[4] -= b[21] + b[9] + b[40] + b[6] + b[12] + b[28] + 181;"
          calcs += "^b[4] &= 0xFF;"
        } else {
          calcs += "^b[29] += b[23] + b[31] + b[18] + b[15] + b[11] + b[37] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[29] &= 0xFF;"
        }
        state = 385701510;
        continue;
      case 84809963:
        if (Math.random() < 0.5) {
          calcs += "^b[26] += b[8] + b[12] + b[33] + b[39] + b[19] + b[29] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[26] &= 0xFF;"
        } else {
          calcs += "^b[32] ^= (b[23] + b[14] + b[39] + b[41] + b[42] + b[18] + " + Math.floor(Math.random() * 256) + ") & 0xFF;"
        }
        state = 504774667;
        continue;
      case 85080588:
        if (762957074) {
          calcs += "^b[10] += b[9] + b[30] + b[24] + b[32] + b[42] + b[25] + 245;"
          calcs += "^b[10] &= 0xFF;"
        } else {
          calcs += "^b[29] += b[13] + b[1] + b[28] + b[14] + b[41] + b[26] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[29] &= 0xFF;"
        }
        state = 670620031;
        continue;
      case 86006683:
        if (26903160n) {
          calcs += "^b[22] += b[29] + b[42] + b[40] + b[38] + b[8] + b[6] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[22] &= 0xFF;"
        } else {
          calcs += "^b[38] += b[6] + b[32] + b[40] + b[20] + b[2] + b[35] + 35;"
          calcs += "^b[38] &= 0xFF;"
        }
        state = 73230932;
        continue;
      case 86029451:
        if (28417424n) {
          calcs += "^b[4] ^= (b[42] + b[8] + b[12] + b[1] + b[16] + b[41] + 71) & 0xFF;"
        } else {
          calcs += "^b[24] ^= (b[31] + b[0] + b[27] + b[28] + b[14] + b[34] + 22) & 0xFF;"
        }
        state = 657193974;
        continue;
      case 89525183:
        if (Math.random() < 0.5) {
          calcs += "^b[16] += b[8] + b[41] + b[28] + b[0] + b[21] + b[34] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[16] &= 0xFF;"
        } else {
          calcs += "^b[25] += b[16] + b[21] + b[28] + b[35] + b[14] + b[37] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[25] &= 0xFF;"
        }
        state = 845956452;
        continue;
      case 90236103:
        if (69736832n) {
          calcs += "^b[39] += b[24] + b[41] + b[16] + b[18] + b[14] + b[36] + 176;"
          calcs += "^b[39] &= 0xFF;"
        } else {
          calcs += "^b[42] += b[43] + b[24] + b[7] + b[35] + b[30] + b[3] + 1;"
          calcs += "^b[42] &= 0xFF;"
        }
        state = 507899681;
        continue;
      case 90412683:
        if (24252696n) {
          calcs += "^b[38] ^= (b[25] + b[40] + b[30] + b[15] + b[5] + b[2] + 46) & 0xFF;"
        } else {
          calcs += "^b[25] += b[15] + b[16] + b[29] + b[37] + b[1] + b[40] + 24;"
          calcs += "^b[25] &= 0xFF;"
        }
        state = 1013386123;
        continue;
      case 93408349:
        if (1031269396) {
          calcs += "^b[35] += b[25] + b[2] + b[10] + b[12] + b[21] + b[31] + 252;"
          calcs += "^b[35] &= 0xFF;"
        } else {
          calcs += "^b[27] -= b[13] + b[36] + b[10] + b[40] + b[35] + b[42] + 138;"
          calcs += "^b[27] &= 0xFF;"
        }
        state = 57422384;
        continue;
      case 93795926:
        if (354560856) {
          calcs += "^b[17] += b[8] + b[26] + b[24] + b[0] + b[19] + b[40] + 59;"
          calcs += "^b[17] &= 0xFF;"
        } else {
          calcs += "^b[22] ^= (b[1] + b[5] + b[10] + b[3] + b[12] + b[16] + 207) & 0xFF;"
        }
        state = 963963899;
        continue;
      case 94971741:
        if (1003392644) {
          calcs += "^b[27] -= b[37] + b[35] + b[33] + b[32] + b[24] + b[20] + 156;"
          calcs += "^b[27] &= 0xFF;"
        } else {
          calcs += "^b[3] ^= (b[22] + b[15] + b[43] + b[26] + b[13] + b[41] + 238) & 0xFF;"
        }
        state = 704120363;
        continue;
      case 95593244:
        if (581345812) {
          calcs += "^b[27] += b[5] + b[42] + b[17] + b[16] + b[8] + b[18] + 55;"
          calcs += "^b[27] &= 0xFF;"
        } else {
          calcs += "^b[33] ^= (b[39] + b[15] + b[37] + b[20] + b[5] + b[29] + 42) & 0xFF;"
        }
        state = 1059203392;
        continue;
      case 95732224:
        if (54814413n) {
          calcs += "^b[37] -= b[13] + b[12] + b[18] + b[35] + b[11] + b[2] + 24;"
          calcs += "^b[37] &= 0xFF;"
        } else {
          calcs += "^b[19] ^= (b[13] + b[36] + b[38] + b[1] + b[2] + b[24] + " + Math.floor(Math.random() * 256) + ") & 0xFF;"
        }
        state = 42840541;
        continue;
      case 96456627:
        if (576136258) {
          calcs += "^b[24] += b[35] + b[10] + b[42] + b[2] + b[41] + b[34] + 230;"
          calcs += "^b[24] &= 0xFF;"
        } else {
          calcs += "^b[1] -= b[36] + b[28] + b[19] + b[30] + b[21] + b[17] + 98;"
          calcs += "^b[1] &= 0xFF;"
        }
        state = 914544092;
        continue;
      case 96633871:
        if (837439616) {
          calcs += "^b[3] -= b[16] + b[5] + b[28] + b[29] + b[13] + b[36] + 15;"
          calcs += "^b[3] &= 0xFF;"
        } else {
          calcs += "^b[9] += b[7] + b[19] + b[29] + b[30] + b[38] + b[13] + 60;"
          calcs += "^b[9] &= 0xFF;"
        }
        state = 583517047;
        continue;
      case 96720363:
        if (751417871) {
          calcs += "^b[14] += b[25] + b[22] + b[41] + b[16] + b[37] + b[33] + 24;"
          calcs += "^b[14] &= 0xFF;"
        } else {
          calcs += "^b[30] -= b[33] + b[40] + b[38] + b[19] + b[36] + b[16] + 196;"
          calcs += "^b[30] &= 0xFF;"
        }
        state = 1007008023;
        continue;
      case 98917269:
        if (41809322n) {
          calcs += "^b[26] += b[8] + b[15] + b[16] + b[17] + b[39] + b[42] + 151;"
          calcs += "^b[26] &= 0xFF;"
        } else {
          calcs += "^b[23] += b[29] + b[20] + b[26] + b[28] + b[38] + b[14] + 39;"
          calcs += "^b[23] &= 0xFF;"
        }
        state = 565836977;
        continue;
      case 100256691:
        if (288189111) {
          calcs += "^b[9] += b[28] + b[2] + b[24] + b[7] + b[14] + b[40] + 223;"
          calcs += "^b[9] &= 0xFF;"
        } else {
          calcs += "^b[5] += b[6] + b[36] + b[20] + b[33] + b[23] + b[26] + 186;"
          calcs += "^b[5] &= 0xFF;"
        }
        state = 278446337;
        continue;
      case 100604142:
        if (Math.random() < 0.5) {
          calcs += "^b[30] ^= (b[35] + b[42] + b[39] + b[19] + b[17] + b[18] + 118) & 0xFF;"
        } else {
          calcs += "^b[7] ^= (b[26] + b[4] + b[20] + b[34] + b[9] + b[38] + 2) & 0xFF;"
        }
        state = 256573723;
        continue;
      case 100730117:
        if (423881324) {
          calcs += "^b[7] -= b[12] + b[27] + b[25] + b[16] + b[29] + b[13] + 146;"
          calcs += "^b[7] &= 0xFF;"
        } else {
          calcs += "^b[39] += b[18] + b[27] + b[15] + b[20] + b[28] + b[9] + 242;"
          calcs += "^b[39] &= 0xFF;"
        }
        state = 291298603;
        continue;
      case 100941470:
        if (61552821n) {
          calcs += "^b[10] += b[35] + b[24] + b[36] + b[12] + b[18] + b[7] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[10] &= 0xFF;"
        } else {
          calcs += "^b[4] += b[23] + b[19] + b[28] + b[41] + b[31] + b[43] + 205;"
          calcs += "^b[4] &= 0xFF;"
        }
        state = 477286010;
        continue;
      case 100980325:
        if (339440603) {
          calcs += "^b[33] -= b[23] + b[19] + b[12] + b[38] + b[0] + b[15] + 136;"
          calcs += "^b[33] &= 0xFF;"
        } else {
          calcs += "^b[43] += b[1] + b[24] + b[31] + b[29] + b[35] + b[42] + 3;"
          calcs += "^b[43] &= 0xFF;"
        }
        state = 448764168;
        continue;
      case 102772698:
        if (94641526) {
          calcs += "^b[22] -= b[11] + b[3] + b[29] + b[10] + b[36] + b[28] + 48;"
          calcs += "^b[22] &= 0xFF;"
        } else {
          calcs += "^b[24] ^= (b[38] + b[40] + b[42] + b[25] + b[13] + b[43] + 64) & 0xFF;"
        }
        state = 190977891;
        continue;
      case 103663748:
        if (Math.random() < 0.5) {
          calcs += "^b[19] ^= (b[27] + b[4] + b[28] + b[18] + b[8] + b[3] + 162) & 0xFF;"
        } else {
          calcs += "^b[7] ^= (b[31] + b[32] + b[1] + b[36] + b[12] + b[40] + 68) & 0xFF;"
        }
        state = 535511042;
        continue;
      case 103901370:
        if (466215850) {
          calcs += "^b[30] ^= (b[10] + b[6] + b[14] + b[9] + b[28] + b[27] + 98) & 0xFF;"
        } else {
          calcs += "^b[23] += b[0] + b[25] + b[10] + b[26] + b[38] + b[24] + 236;"
          calcs += "^b[23] &= 0xFF;"
        }
        state = 345722137;
        continue;
      case 104812740:
        if (282147743) {
          calcs += "^b[27] ^= (b[28] + b[17] + b[3] + b[8] + b[18] + b[36] + 245) & 0xFF;"
        } else {
          calcs += "^b[41] += b[33] + b[9] + b[34] + b[26] + b[3] + b[14] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[41] &= 0xFF;"
        }
        state = 625809930;
        continue;
      case 105007401:
        if (369756360) {
          calcs += "^b[17] -= b[42] + b[25] + b[26] + b[19] + b[35] + b[4] + 55;"
          calcs += "^b[17] &= 0xFF;"
        } else {
          calcs += "^b[12] += b[39] + b[11] + b[40] + b[18] + b[8] + b[17] + 210;"
          calcs += "^b[12] &= 0xFF;"
        }
        state = 203996210;
        continue;
      case 105766033:
        if (73139772n) {
          calcs += "^b[3] -= b[12] + b[8] + b[4] + b[42] + b[30] + b[13] + 44;"
          calcs += "^b[3] &= 0xFF;"
        } else {
          calcs += "^b[33] += b[21] + b[13] + b[25] + b[29] + b[36] + b[18] + 139;"
          calcs += "^b[33] &= 0xFF;"
        }
        state = 200659076;
        continue;
      case 105837962:
        if (25999949n) {
          calcs += "^b[6] += b[27] + b[2] + b[33] + b[29] + b[12] + b[25] + 252;"
          calcs += "^b[6] &= 0xFF;"
        } else {
          calcs += "^b[40] ^= (b[13] + b[15] + b[22] + b[24] + b[43] + b[39] + " + Math.floor(Math.random() * 256) + ") & 0xFF;"
        }
        state = 548604337;
        continue;
      case 107012627:
        if (843375165) {
          calcs += "^b[19] -= b[26] + b[43] + b[15] + b[22] + b[35] + b[25] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[19] &= 0xFF;"
        } else {
          calcs += "^b[12] -= b[1] + b[33] + b[11] + b[10] + b[37] + b[8] + 155;"
          calcs += "^b[12] &= 0xFF;"
        }
        state = 706921542;
        continue;
      case 107361852:
        if (71427674n) {
          calcs += "^b[41] += b[3] + b[14] + b[19] + b[6] + b[13] + b[25] + 168;"
          calcs += "^b[41] &= 0xFF;"
        } else {
          calcs += "^b[2] ^= (b[32] + b[41] + b[24] + b[22] + b[17] + b[21] + " + Math.floor(Math.random() * 256) + ") & 0xFF;"
        }
        state = 533630845;
        continue;
      case 107684849:
        if (Math.random() < 0.5) {
          calcs += "^b[31] ^= (b[16] + b[13] + b[28] + b[21] + b[0] + b[27] + " + Math.floor(Math.random() * 256) + ") & 0xFF;"
        } else {
          calcs += "^b[42] ^= (b[43] + b[41] + b[15] + b[4] + b[21] + b[29] + " + Math.floor(Math.random() * 256) + ") & 0xFF;"
        }
        state = 353740394;
        continue;
      case 107948494:
        if (70229755n) {
          calcs += "^b[13] -= b[34] + b[1] + b[31] + b[15] + b[12] + b[8] + 206;"
          calcs += "^b[13] &= 0xFF;"
        } else {
          calcs += "^b[20] += b[8] + b[11] + b[41] + b[14] + b[9] + b[40] + 69;"
          calcs += "^b[20] &= 0xFF;"
        }
        state = 625310147;
        continue;
      case 108953795:
        if (Math.random() < 0.5) {
          calcs += "^b[28] += b[40] + b[43] + b[5] + b[21] + b[3] + b[24] + 231;"
          calcs += "^b[28] &= 0xFF;"
        } else {
          calcs += "^b[35] -= b[32] + b[42] + b[11] + b[0] + b[28] + b[14] + 229;"
          calcs += "^b[35] &= 0xFF;"
        }
        state = 471309236;
        continue;
      case 109814501:
        if (61688459n) {
          calcs += "^b[15] -= b[31] + b[14] + b[41] + b[18] + b[39] + b[21] + 4;"
          calcs += "^b[15] &= 0xFF;"
        } else {
          calcs += "^b[18] ^= (b[33] + b[23] + b[19] + b[34] + b[3] + b[42] + 133) & 0xFF;"
        }
        state = 625666051;
        continue;
      case 110286030:
        if (185368972) {
          calcs += "^b[2] += b[5] + b[34] + b[30] + b[39] + b[28] + b[21] + 199;"
          calcs += "^b[2] &= 0xFF;"
        } else {
          calcs += "^b[13] += b[25] + b[26] + b[22] + b[15] + b[19] + b[14] + 68;"
          calcs += "^b[13] &= 0xFF;"
        }
        state = 923831682;
        continue;
      case 110430724:
        if (Math.random() < 0.5) {
          calcs += "^b[42] ^= (b[3] + b[16] + b[27] + b[19] + b[13] + b[30] + 88) & 0xFF;"
        } else {
          calcs += "^b[10] += b[9] + b[39] + b[6] + b[32] + b[11] + b[35] + 18;"
          calcs += "^b[10] &= 0xFF;"
        }
        state = 342092904;
        continue;
      case 110713232:
        if (Math.random() < 0.5) {
          calcs += "^b[10] += b[39] + b[37] + b[32] + b[9] + b[29] + b[0] + 138;"
          calcs += "^b[10] &= 0xFF;"
        } else {
          calcs += "^b[37] ^= (b[24] + b[6] + b[33] + b[31] + b[12] + b[29] + 132) & 0xFF;"
        }
        state = 976020731;
        continue;
      case 111025682:
        if (Math.random() < 0.5) {
          calcs += "^b[42] -= b[35] + b[20] + b[11] + b[0] + b[31] + b[33] + 171;"
          calcs += "^b[42] &= 0xFF;"
        } else {
          calcs += "^b[16] += b[30] + b[0] + b[3] + b[34] + b[15] + b[21] + 26;"
          calcs += "^b[16] &= 0xFF;"
        }
        state = 92909967;
        continue;
      case 111161662:
        if (Math.random() < 0.5) {
          calcs += "^b[40] ^= (b[26] + b[25] + b[5] + b[36] + b[7] + b[22] + 225) & 0xFF;"
        } else {
          calcs += "^b[19] -= b[5] + b[4] + b[26] + b[1] + b[39] + b[16] + 76;"
          calcs += "^b[19] &= 0xFF;"
        }
        state = 554498806;
        continue;
      case 113700411:
        if (74917685n) {
          calcs += "^b[11] ^= (b[28] + b[15] + b[29] + b[34] + b[4] + b[41] + 142) & 0xFF;"
        } else {
          calcs += "^b[35] ^= (b[12] + b[18] + b[39] + b[0] + b[10] + b[3] + 148) & 0xFF;"
        }
        state = 753568692;
        continue;
      case 114492214:
        if (133555304) {
          calcs += "^b[26] ^= (b[19] + b[22] + b[36] + b[25] + b[35] + b[29] + 115) & 0xFF;"
        } else {
          calcs += "^b[7] ^= (b[16] + b[24] + b[28] + b[32] + b[4] + b[5] + " + Math.floor(Math.random() * 256) + ") & 0xFF;"
        }
        state = 593990082;
        continue;
      case 117244801:
        if (2243214) {
          calcs += "^b[32] += b[2] + b[14] + b[19] + b[43] + b[4] + b[30] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[32] &= 0xFF;"
        } else {
          calcs += "^b[32] -= b[4] + b[35] + b[22] + b[40] + b[28] + b[39] + 46;"
          calcs += "^b[32] &= 0xFF;"
        }
        state = 739966340;
        continue;
      case 118934062:
        if (822632380) {
          calcs += "^b[33] -= b[26] + b[12] + b[28] + b[43] + b[38] + b[22] + 59;"
          calcs += "^b[33] &= 0xFF;"
        } else {
          calcs += "^b[33] += b[11] + b[10] + b[29] + b[31] + b[42] + b[1] + 145;"
          calcs += "^b[33] &= 0xFF;"
        }
        state = 851877108;
        continue;
      case 120900299:
        if (976215988) {
          calcs += "^b[26] -= b[29] + b[10] + b[2] + b[13] + b[0] + b[5] + 27;"
          calcs += "^b[26] &= 0xFF;"
        } else {
          calcs += "^b[43] ^= (b[41] + b[14] + b[37] + b[38] + b[15] + b[10] + 217) & 0xFF;"
        }
        state = 1001894258;
        continue;
      case 122546316:
        if (24322464n) {
          calcs += "^b[18] ^= (b[14] + b[1] + b[20] + b[0] + b[6] + b[25] + 126) & 0xFF;"
        } else {
          calcs += "^b[5] -= b[22] + b[8] + b[12] + b[24] + b[37] + b[31] + 149;"
          calcs += "^b[5] &= 0xFF;"
        }
        state = 823812251;
        continue;
      case 124291036:
        if (71613682n) {
          calcs += "^b[2] += b[43] + b[27] + b[6] + b[32] + b[34] + b[14] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[2] &= 0xFF;"
        } else {
          calcs += "^b[12] -= b[8] + b[0] + b[3] + b[24] + b[33] + b[42] + 152;"
          calcs += "^b[12] &= 0xFF;"
        }
        state = 656479648;
        continue;
      case 124331859:
        if (909168317) {
          calcs += "^b[39] ^= (b[31] + b[21] + b[11] + b[25] + b[42] + b[27] + 96) & 0xFF;"
        } else {
          calcs += "^b[42] ^= (b[13] + b[2] + b[20] + b[16] + b[6] + b[34] + " + Math.floor(Math.random() * 256) + ") & 0xFF;"
        }
        state = 341128420;
        continue;
      case 124690486:
        if (77264479n) {
          calcs += "^b[13] -= b[30] + b[17] + b[4] + b[11] + b[29] + b[19] + 93;"
          calcs += "^b[13] &= 0xFF;"
        } else {
          calcs += "^b[6] ^= (b[24] + b[19] + b[12] + b[10] + b[8] + b[34] + 3) & 0xFF;"
        }
        state = 735389915;
        continue;
      case 125689889:
        if (81753748n) {
          calcs += "^b[13] += b[4] + b[24] + b[35] + b[34] + b[43] + b[32] + 26;"
          calcs += "^b[13] &= 0xFF;"
        } else {
          calcs += "^b[3] -= b[29] + b[14] + b[12] + b[39] + b[32] + b[28] + 145;"
          calcs += "^b[3] &= 0xFF;"
        }
        state = 22742525;
        continue;
      case 129013201:
        if (93110533n) {
          calcs += "^b[24] ^= (b[8] + b[30] + b[3] + b[41] + b[36] + b[7] + 136) & 0xFF;"
        } else {
          calcs += "^b[14] += b[5] + b[19] + b[11] + b[36] + b[26] + b[1] + 55;"
          calcs += "^b[14] &= 0xFF;"
        }
        state = 897709913;
        continue;
      case 129226256:
        if (691330426) {
          calcs += "^b[17] += b[26] + b[2] + b[5] + b[41] + b[16] + b[29] + 17;"
          calcs += "^b[17] &= 0xFF;"
        } else {
          calcs += "^b[8] -= b[40] + b[12] + b[41] + b[20] + b[5] + b[30] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[8] &= 0xFF;"
        }
        state = 210970895;
        continue;
      case 129895060:
        if (862732011) {
          calcs += "^b[1] += b[35] + b[20] + b[37] + b[28] + b[19] + b[36] + 82;"
          calcs += "^b[1] &= 0xFF;"
        } else {
          calcs += "^b[14] -= b[30] + b[5] + b[35] + b[41] + b[3] + b[17] + 119;"
          calcs += "^b[14] &= 0xFF;"
        }
        state = 613921509;
        continue;
      case 130000735:
        if (22750621n) {
          calcs += "^b[39] -= b[43] + b[35] + b[4] + b[37] + b[9] + b[32] + 223;"
          calcs += "^b[39] &= 0xFF;"
        } else {
          calcs += "^b[32] -= b[18] + b[13] + b[30] + b[33] + b[23] + b[35] + 80;"
          calcs += "^b[32] &= 0xFF;"
        }
        state = 628365389;
        continue;
      case 131273933:
        if (651761731) {
          calcs += "^b[2] ^= (b[18] + b[29] + b[1] + b[7] + b[31] + b[17] + 119) & 0xFF;"
        } else {
          calcs += "^b[6] -= b[30] + b[21] + b[2] + b[19] + b[35] + b[20] + 249;"
          calcs += "^b[6] &= 0xFF;"
        }
        state = 353570504;
        continue;
      case 132987555:
        if (228460182) {
          calcs += "^b[35] += b[1] + b[37] + b[3] + b[10] + b[28] + b[4] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[35] &= 0xFF;"
        } else {
          calcs += "^b[12] += b[13] + b[21] + b[20] + b[15] + b[31] + b[16] + 13;"
          calcs += "^b[12] &= 0xFF;"
        }
        state = 636639591;
        continue;
      case 134845953:
        if (51096671n) {
          calcs += "^b[42] += b[29] + b[14] + b[31] + b[22] + b[36] + b[33] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[42] &= 0xFF;"
        } else {
          calcs += "^b[21] += b[24] + b[11] + b[18] + b[35] + b[17] + b[23] + 242;"
          calcs += "^b[21] &= 0xFF;"
        }
        state = 817628987;
        continue;
      case 135863760:
        if (68677418n) {
          calcs += "^b[2] -= b[27] + b[43] + b[1] + b[19] + b[34] + b[30] + 91;"
          calcs += "^b[2] &= 0xFF;"
        } else {
          calcs += "^b[5] ^= (b[36] + b[41] + b[6] + b[26] + b[18] + b[4] + 29) & 0xFF;"
        }
        state = 924220962;
        continue;
      case 136698433:
        if (384726620) {
          calcs += "^b[24] += b[14] + b[38] + b[4] + b[12] + b[5] + b[0] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[24] &= 0xFF;"
        } else {
          calcs += "^b[1] ^= (b[21] + b[7] + b[37] + b[30] + b[28] + b[32] + 188) & 0xFF;"
        }
        state = 212469830;
        continue;
      case 137156820:
        if (92958307n) {
          calcs += "^b[5] += b[4] + b[7] + b[28] + b[43] + b[12] + b[26] + 54;"
          calcs += "^b[5] &= 0xFF;"
        } else {
          calcs += "^b[39] ^= (b[2] + b[13] + b[40] + b[8] + b[23] + b[14] + 143) & 0xFF;"
        }
        state = 579328230;
        continue;
      case 137590596:
        if (802464505) {
          calcs += "^b[33] ^= (b[19] + b[35] + b[24] + b[40] + b[30] + b[26] + 99) & 0xFF;"
        } else {
          calcs += "^b[41] ^= (b[28] + b[0] + b[23] + b[12] + b[37] + b[29] + " + Math.floor(Math.random() * 256) + ") & 0xFF;"
        }
        state = 875069506;
        continue;
      case 137630475:
        if (Math.random() < 0.5) {
          calcs += "^b[38] ^= (b[39] + b[2] + b[0] + b[31] + b[29] + b[5] + 160) & 0xFF;"
        } else {
          calcs += "^b[6] ^= (b[29] + b[32] + b[33] + b[21] + b[37] + b[13] + 49) & 0xFF;"
        }
        state = 768231765;
        continue;
      case 138090095:
        if (Math.random() < 0.5) {
          calcs += "^b[40] += b[17] + b[11] + b[23] + b[6] + b[10] + b[14] + 171;"
          calcs += "^b[40] &= 0xFF;"
        } else {
          calcs += "^b[3] ^= (b[1] + b[38] + b[15] + b[35] + b[25] + b[23] + " + Math.floor(Math.random() * 256) + ") & 0xFF;"
        }
        state = 587130542;
        continue;
      case 141811531:
        if (11783528n) {
          calcs += "^b[15] ^= (b[16] + b[10] + b[9] + b[6] + b[21] + b[26] + 223) & 0xFF;"
        } else {
          calcs += "^b[16] -= b[5] + b[15] + b[14] + b[6] + b[17] + b[33] + 51;"
          calcs += "^b[16] &= 0xFF;"
        }
        state = 205756057;
        continue;
      case 148008988:
        if (824341643) {
          calcs += "^b[11] += b[42] + b[6] + b[21] + b[9] + b[8] + b[7] + 135;"
          calcs += "^b[11] &= 0xFF;"
        } else {
          calcs += "^b[31] += b[2] + b[8] + b[32] + b[27] + b[18] + b[35] + 193;"
          calcs += "^b[31] &= 0xFF;"
        }
        state = 211673876;
        continue;
      case 149778348:
        if (372901593) {
          calcs += "^b[14] ^= (b[42] + b[15] + b[25] + b[38] + b[1] + b[0] + " + Math.floor(Math.random() * 256) + ") & 0xFF;"
        } else {
          calcs += "^b[16] -= b[15] + b[17] + b[42] + b[22] + b[32] + b[30] + 64;"
          calcs += "^b[16] &= 0xFF;"
        }
        state = 1006836235;
        continue;
      case 150199466:
        if (Math.random() < 0.5) {
          calcs += "^b[42] ^= (b[37] + b[35] + b[18] + b[36] + b[1] + b[14] + 95) & 0xFF;"
        } else {
          calcs += "^b[36] ^= (b[2] + b[41] + b[0] + b[11] + b[4] + b[38] + 190) & 0xFF;"
        }
        state = 41994990;
        continue;
      case 150806942:
        if (93610461n) {
          calcs += "^b[20] += b[42] + b[21] + b[32] + b[30] + b[33] + b[39] + 230;"
          calcs += "^b[20] &= 0xFF;"
        } else {
          calcs += "^b[22] += b[38] + b[34] + b[17] + b[25] + b[31] + b[0] + 242;"
          calcs += "^b[22] &= 0xFF;"
        }
        state = 1360917;
        continue;
      case 150911405:
        if (Math.random() < 0.5) {
          calcs += "^b[34] += b[11] + b[6] + b[35] + b[15] + b[36] + b[21] + 159;"
          calcs += "^b[34] &= 0xFF;"
        } else {
          calcs += "^b[13] ^= (b[19] + b[34] + b[27] + b[39] + b[23] + b[17] + 3) & 0xFF;"
        }
        state = 1053950993;
        continue;
      case 151729253:
        if (11042741n) {
          calcs += "^b[21] ^= (b[30] + b[4] + b[41] + b[6] + b[22] + b[9] + 224) & 0xFF;"
        } else {
          calcs += "^b[11] ^= (b[13] + b[34] + b[30] + b[32] + b[43] + b[25] + 129) & 0xFF;"
        }
        state = 144233693;
        continue;
      case 151969372:
        if (31121498n) {
          calcs += "^b[27] += b[28] + b[0] + b[33] + b[40] + b[1] + b[7] + 108;"
          calcs += "^b[27] &= 0xFF;"
        } else {
          calcs += "^b[39] += b[27] + b[20] + b[15] + b[29] + b[36] + b[16] + 196;"
          calcs += "^b[39] &= 0xFF;"
        }
        state = 768100694;
        continue;
      case 152320376:
        if (Math.random() < 0.5) {
          calcs += "^b[4] -= b[5] + b[36] + b[6] + b[8] + b[7] + b[35] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[4] &= 0xFF;"
        } else {
          calcs += "^b[12] += b[41] + b[21] + b[40] + b[31] + b[17] + b[9] + 143;"
          calcs += "^b[12] &= 0xFF;"
        }
        state = 149400501;
        continue;
      case 152458462:
        if (21140334n) {
          calcs += "^b[26] += b[40] + b[6] + b[36] + b[21] + b[19] + b[28] + 41;"
          calcs += "^b[26] &= 0xFF;"
        } else {
          calcs += "^b[0] -= b[35] + b[31] + b[5] + b[10] + b[39] + b[3] + 104;"
          calcs += "^b[0] &= 0xFF;"
        }
        state = 20673211;
        continue;
      case 154630273:
        if (150347198) {
          calcs += "^b[32] ^= (b[4] + b[34] + b[2] + b[5] + b[7] + b[37] + 113) & 0xFF;"
        } else {
          calcs += "^b[36] -= b[34] + b[10] + b[18] + b[14] + b[30] + b[7] + 71;"
          calcs += "^b[36] &= 0xFF;"
        }
        state = 497191526;
        continue;
      case 155874172:
        if (27695290n) {
          calcs += "^b[43] -= b[1] + b[32] + b[9] + b[4] + b[33] + b[22] + 217;"
          calcs += "^b[43] &= 0xFF;"
        } else {
          calcs += "^b[43] ^= (b[9] + b[42] + b[26] + b[19] + b[15] + b[8] + 79) & 0xFF;"
        }
        state = 472924099;
        continue;
      case 156265595:
        if (Math.random() < 0.5) {
          calcs += "^b[7] ^= (b[24] + b[2] + b[42] + b[33] + b[11] + b[13] + 36) & 0xFF;"
        } else {
          calcs += "^b[5] ^= (b[17] + b[31] + b[28] + b[9] + b[0] + b[34] + 142) & 0xFF;"
        }
        state = 925920849;
        continue;
      case 157380093:
        if (950484477) {
          calcs += "^b[22] ^= (b[32] + b[18] + b[16] + b[7] + b[27] + b[8] + 186) & 0xFF;"
        } else {
          calcs += "^b[12] ^= (b[25] + b[5] + b[15] + b[11] + b[1] + b[9] + 8) & 0xFF;"
        }
        state = 784521278;
        continue;
      case 158215884:
        if (10930022n) {
          calcs += "^b[4] ^= (b[36] + b[42] + b[22] + b[20] + b[15] + b[0] + 219) & 0xFF;"
        } else {
          calcs += "^b[18] -= b[8] + b[32] + b[13] + b[23] + b[43] + b[29] + 139;"
          calcs += "^b[18] &= 0xFF;"
        }
        state = 930444353;
        continue;
      case 158440818:
        if (Math.random() < 0.5) {
          calcs += "^b[11] ^= (b[5] + b[20] + b[14] + b[28] + b[42] + b[22] + 149) & 0xFF;"
        } else {
          calcs += "^b[11] ^= (b[9] + b[29] + b[14] + b[12] + b[5] + b[15] + " + Math.floor(Math.random() * 256) + ") & 0xFF;"
        }
        state = 68807763;
        continue;
      case 160122652:
        if (98910848) {
          calcs += "^b[26] ^= (b[14] + b[27] + b[38] + b[10] + b[37] + b[18] + 89) & 0xFF;"
        } else {
          calcs += "^b[25] ^= (b[10] + b[33] + b[24] + b[5] + b[12] + b[38] + 112) & 0xFF;"
        }
        state = 206050454;
        continue;
      case 160364872:
        if (407632658) {
          calcs += "^b[16] ^= (b[9] + b[41] + b[1] + b[4] + b[42] + b[29] + " + Math.floor(Math.random() * 256) + ") & 0xFF;"
        } else {
          calcs += "^b[27] -= b[10] + b[22] + b[17] + b[9] + b[24] + b[26] + 43;"
          calcs += "^b[27] &= 0xFF;"
        }
        state = 511113659;
        continue;
      case 162618506:
        if (36454975n) {
          calcs += "^b[6] += b[30] + b[37] + b[40] + b[9] + b[8] + b[25] + 39;"
          calcs += "^b[6] &= 0xFF;"
        } else {
          calcs += "^b[25] += b[34] + b[28] + b[19] + b[36] + b[0] + b[3] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[25] &= 0xFF;"
        }
        state = 10280958;
        continue;
      case 163000418:
        if (Math.random() < 0.5) {
          calcs += "^b[23] -= b[24] + b[43] + b[30] + b[37] + b[6] + b[36] + 58;"
          calcs += "^b[23] &= 0xFF;"
        } else {
          calcs += "^b[9] ^= (b[17] + b[42] + b[26] + b[5] + b[30] + b[22] + 181) & 0xFF;"
        }
        state = 467811485;
        continue;
      case 163327990:
        if (80981608n) {
          calcs += "^b[40] += b[37] + b[29] + b[8] + b[19] + b[0] + b[27] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[40] &= 0xFF;"
        } else {
          calcs += "^b[3] -= b[9] + b[26] + b[6] + b[29] + b[5] + b[20] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[3] &= 0xFF;"
        }
        state = 778318794;
        continue;
      case 163703821:
        if (30589913n) {
          calcs += "^b[7] ^= (b[6] + b[43] + b[37] + b[12] + b[38] + b[32] + 9) & 0xFF;"
        } else {
          calcs += "^b[41] ^= (b[30] + b[43] + b[14] + b[3] + b[34] + b[4] + 47) & 0xFF;"
        }
        state = 881680178;
        continue;
      case 164257914:
        if (Math.random() < 0.5) {
          calcs += "^b[36] += b[6] + b[43] + b[42] + b[2] + b[12] + b[31] + 245;"
          calcs += "^b[36] &= 0xFF;"
        } else {
          calcs += "^b[23] += b[21] + b[42] + b[18] + b[5] + b[7] + b[22] + 2;"
          calcs += "^b[23] &= 0xFF;"
        }
        state = 413794989;
        continue;
      case 165136772:
        if (1052278988) {
          calcs += "^b[10] ^= (b[12] + b[34] + b[5] + b[35] + b[18] + b[24] + 228) & 0xFF;"
        } else {
          calcs += "^b[27] -= b[0] + b[6] + b[21] + b[29] + b[38] + b[1] + 32;"
          calcs += "^b[27] &= 0xFF;"
        }
        state = 877411063;
        continue;
      case 167029715:
        if (762913095) {
          calcs += "^b[19] ^= (b[41] + b[21] + b[20] + b[24] + b[31] + b[5] + 197) & 0xFF;"
        } else {
          calcs += "^b[36] -= b[7] + b[3] + b[10] + b[5] + b[13] + b[2] + 23;"
          calcs += "^b[36] &= 0xFF;"
        }
        state = 177041070;
        continue;
      case 167118666:
        if (Math.random() < 0.5) {
          calcs += "^b[21] += b[23] + b[34] + b[14] + b[30] + b[39] + b[35] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[21] &= 0xFF;"
        } else {
          calcs += "^b[22] += b[6] + b[25] + b[18] + b[11] + b[40] + b[4] + 103;"
          calcs += "^b[22] &= 0xFF;"
        }
        state = 928095411;
        continue;
      case 167389661:
        if (Math.random() < 0.5) {
          calcs += "^b[6] -= b[2] + b[13] + b[39] + b[16] + b[11] + b[38] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[6] &= 0xFF;"
        } else {
          calcs += "^b[22] -= b[1] + b[40] + b[13] + b[17] + b[38] + b[20] + 151;"
          calcs += "^b[22] &= 0xFF;"
        }
        state = 348302371;
        continue;
      case 167821939:
        if (722316389) {
          calcs += "^b[30] -= b[29] + b[41] + b[0] + b[3] + b[21] + b[34] + 236;"
          calcs += "^b[30] &= 0xFF;"
        } else {
          calcs += "^b[28] += b[19] + b[37] + b[21] + b[20] + b[14] + b[23] + 72;"
          calcs += "^b[28] &= 0xFF;"
        }
        state = 219973336;
        continue;
      case 168874559:
        if (38875854n) {
          calcs += "^b[34] -= b[31] + b[11] + b[40] + b[28] + b[36] + b[12] + 173;"
          calcs += "^b[34] &= 0xFF;"
        } else {
          calcs += "^b[21] += b[32] + b[24] + b[34] + b[28] + b[15] + b[0] + 63;"
          calcs += "^b[21] &= 0xFF;"
        }
        state = 748280776;
        continue;
      case 169583868:
        if (456603541) {
          calcs += "^b[24] += b[17] + b[3] + b[25] + b[4] + b[33] + b[11] + 56;"
          calcs += "^b[24] &= 0xFF;"
        } else {
          calcs += "^b[23] -= b[14] + b[37] + b[42] + b[11] + b[28] + b[34] + 104;"
          calcs += "^b[23] &= 0xFF;"
        }
        state = 1048209677;
        continue;
      case 170126216:
        if (702042048) {
          calcs += "^b[4] += b[33] + b[8] + b[29] + b[26] + b[34] + b[19] + 54;"
          calcs += "^b[4] &= 0xFF;"
        } else {
          calcs += "^b[26] -= b[16] + b[8] + b[35] + b[4] + b[32] + b[22] + 55;"
          calcs += "^b[26] &= 0xFF;"
        }
        state = 825063852;
        continue;
      case 170255883:
        if (11255342n) {
          calcs += "^b[0] ^= (b[32] + b[31] + b[26] + b[4] + b[27] + b[10] + " + Math.floor(Math.random() * 256) + ") & 0xFF;"
        } else {
          calcs += "^b[0] ^= (b[17] + b[32] + b[8] + b[37] + b[14] + b[1] + " + Math.floor(Math.random() * 256) + ") & 0xFF;"
        }
        state = 183251124;
        continue;
      case 170938055:
        if (Math.random() < 0.5) {
          calcs += "^b[39] += b[15] + b[43] + b[20] + b[5] + b[6] + b[22] + 227;"
          calcs += "^b[39] &= 0xFF;"
        } else {
          calcs += "^b[25] -= b[2] + b[19] + b[29] + b[3] + b[14] + b[40] + 151;"
          calcs += "^b[25] &= 0xFF;"
        }
        state = 310460500;
        continue;
      case 170953037:
        if (Math.random() < 0.5) {
          calcs += "^b[25] += b[7] + b[21] + b[12] + b[24] + b[35] + b[42] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[25] &= 0xFF;"
        } else {
          calcs += "^b[25] += b[17] + b[12] + b[35] + b[39] + b[7] + b[4] + 120;"
          calcs += "^b[25] &= 0xFF;"
        }
        state = 195213298;
        continue;
      case 171560204:
        if (95901281n) {
          calcs += "^b[6] ^= (b[12] + b[33] + b[15] + b[35] + b[11] + b[2] + 164) & 0xFF;"
        } else {
          calcs += "^b[27] += b[37] + b[15] + b[3] + b[35] + b[26] + b[2] + 181;"
          calcs += "^b[27] &= 0xFF;"
        }
        state = 1033531864;
        continue;
      case 171959181:
        if (941297648) {
          calcs += "^b[15] ^= (b[0] + b[28] + b[38] + b[18] + b[6] + b[24] + " + Math.floor(Math.random() * 256) + ") & 0xFF;"
        } else {
          calcs += "^b[13] -= b[8] + b[21] + b[24] + b[23] + b[3] + b[27] + 201;"
          calcs += "^b[13] &= 0xFF;"
        }
        state = 2554649;
        continue;
      case 172327403:
        if (19191755n) {
          calcs += "^b[2] += b[24] + b[23] + b[43] + b[36] + b[6] + b[18] + 60;"
          calcs += "^b[2] &= 0xFF;"
        } else {
          calcs += "^b[30] ^= (b[40] + b[36] + b[43] + b[6] + b[11] + b[2] + 57) & 0xFF;"
        }
        state = 541134788;
        continue;
      case 173142711:
        if (315425082) {
          calcs += "^b[23] ^= (b[20] + b[5] + b[42] + b[19] + b[31] + b[3] + 211) & 0xFF;"
        } else {
          calcs += "^b[33] += b[17] + b[7] + b[26] + b[18] + b[36] + b[11] + 113;"
          calcs += "^b[33] &= 0xFF;"
        }
        state = 639473643;
        continue;
      case 174428270:
        if (897865398) {
          calcs += "^b[5] += b[17] + b[40] + b[8] + b[4] + b[15] + b[12] + 221;"
          calcs += "^b[5] &= 0xFF;"
        } else {
          calcs += "^b[32] += b[22] + b[25] + b[2] + b[43] + b[37] + b[28] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[32] &= 0xFF;"
        }
        state = 480041842;
        continue;
      case 176965404:
        if (Math.random() < 0.5) {
          calcs += "^b[10] -= b[38] + b[34] + b[35] + b[24] + b[5] + b[16] + 241;"
          calcs += "^b[10] &= 0xFF;"
        } else {
          calcs += "^b[1] -= b[32] + b[31] + b[34] + b[16] + b[28] + b[35] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[1] &= 0xFF;"
        }
        state = 942374808;
        continue;
      case 177511412:
        if (206667095) {
          calcs += "^b[12] += b[38] + b[35] + b[5] + b[0] + b[33] + b[6] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[12] &= 0xFF;"
        } else {
          calcs += "^b[3] -= b[42] + b[17] + b[24] + b[16] + b[41] + b[1] + 61;"
          calcs += "^b[3] &= 0xFF;"
        }
        state = 902795827;
        continue;
      case 177706338:
        if (63824188n) {
          calcs += "^b[2] ^= (b[23] + b[1] + b[14] + b[22] + b[38] + b[26] + " + Math.floor(Math.random() * 256) + ") & 0xFF;"
        } else {
          calcs += "^b[3] ^= (b[31] + b[13] + b[37] + b[39] + b[8] + b[29] + 76) & 0xFF;"
        }
        state = 634776425;
        continue;
      case 180361118:
        if (Math.random() < 0.5) {
          calcs += "^b[12] += b[17] + b[8] + b[37] + b[39] + b[22] + b[35] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[12] &= 0xFF;"
        } else {
          calcs += "^b[35] += b[32] + b[29] + b[42] + b[30] + b[43] + b[33] + 155;"
          calcs += "^b[35] &= 0xFF;"
        }
        state = 129696583;
        continue;
      case 181384715:
        if (Math.random() < 0.5) {
          calcs += "^b[19] ^= (b[26] + b[0] + b[40] + b[37] + b[23] + b[32] + 255) & 0xFF;"
        } else {
          calcs += "^b[5] ^= (b[27] + b[33] + b[10] + b[3] + b[42] + b[40] + " + Math.floor(Math.random() * 256) + ") & 0xFF;"
        }
        state = 110990963;
        continue;
      case 182615591:
        if (Math.random() < 0.5) {
          calcs += "^b[30] ^= (b[8] + b[21] + b[37] + b[17] + b[10] + b[24] + 32) & 0xFF;"
        } else {
          calcs += "^b[29] -= b[5] + b[7] + b[4] + b[40] + b[0] + b[39] + 41;"
          calcs += "^b[29] &= 0xFF;"
        }
        state = 565304124;
        continue;
      case 184001838:
        if (Math.random() < 0.5) {
          calcs += "^b[37] -= b[32] + b[29] + b[4] + b[19] + b[38] + b[9] + 252;"
          calcs += "^b[37] &= 0xFF;"
        } else {
          calcs += "^b[16] ^= (b[13] + b[41] + b[3] + b[40] + b[8] + b[14] + 17) & 0xFF;"
        }
        state = 526415422;
        continue;
      case 184226734:
        if (79685309n) {
          calcs += "^b[25] += b[22] + b[3] + b[0] + b[43] + b[40] + b[26] + 76;"
          calcs += "^b[25] &= 0xFF;"
        } else {
          calcs += "^b[5] -= b[42] + b[40] + b[11] + b[0] + b[8] + b[36] + 18;"
          calcs += "^b[5] &= 0xFF;"
        }
        state = 453999162;
        continue;
      case 184337331:
        if (85032682n) {
          calcs += "^b[34] ^= (b[35] + b[4] + b[22] + b[41] + b[36] + b[40] + 159) & 0xFF;"
        } else {
          calcs += "^b[38] += b[42] + b[19] + b[12] + b[40] + b[43] + b[27] + 44;"
          calcs += "^b[38] &= 0xFF;"
        }
        state = 297410300;
        continue;
      case 184565984:
        if (Math.random() < 0.5) {
          calcs += "^b[43] += b[6] + b[16] + b[5] + b[20] + b[37] + b[33] + 21;"
          calcs += "^b[43] &= 0xFF;"
        } else {
          calcs += "^b[6] -= b[16] + b[25] + b[36] + b[40] + b[31] + b[5] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[6] &= 0xFF;"
        }
        state = 666284843;
        continue;
      case 184938092:
        if (58279263n) {
          calcs += "^b[31] += b[43] + b[21] + b[9] + b[15] + b[0] + b[14] + 40;"
          calcs += "^b[31] &= 0xFF;"
        } else {
          calcs += "^b[22] += b[10] + b[37] + b[34] + b[12] + b[16] + b[2] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[22] &= 0xFF;"
        }
        state = 788352180;
        continue;
      case 185078700:
        break;
      case 188837611:
        if (509459627) {
          calcs += "^b[2] ^= (b[26] + b[29] + b[30] + b[33] + b[27] + b[1] + " + Math.floor(Math.random() * 256) + ") & 0xFF;"
        } else {
          calcs += "^b[35] -= b[43] + b[23] + b[22] + b[33] + b[30] + b[0] + 147;"
          calcs += "^b[35] &= 0xFF;"
        }
        state = 618073582;
        continue;
      case 190154779:
        if (Math.random() < 0.5) {
          calcs += "^b[23] ^= (b[5] + b[42] + b[17] + b[39] + b[8] + b[21] + 110) & 0xFF;"
        } else {
          calcs += "^b[36] += b[10] + b[24] + b[34] + b[28] + b[0] + b[3] + 178;"
          calcs += "^b[36] &= 0xFF;"
        }
        state = 225795742;
        continue;
      case 192326207:
        if (Math.random() < 0.5) {
          calcs += "^b[6] += b[26] + b[1] + b[14] + b[28] + b[39] + b[18] + 180;"
          calcs += "^b[6] &= 0xFF;"
        } else {
          calcs += "^b[18] += b[19] + b[6] + b[15] + b[40] + b[3] + b[32] + 191;"
          calcs += "^b[18] &= 0xFF;"
        }
        state = 71789518;
        continue;
      case 194022714:
        if (Math.random() < 0.5) {
          calcs += "^b[20] -= b[28] + b[43] + b[3] + b[29] + b[14] + b[39] + 113;"
          calcs += "^b[20] &= 0xFF;"
        } else {
          calcs += "^b[5] += b[8] + b[16] + b[38] + b[37] + b[1] + b[18] + 148;"
          calcs += "^b[5] &= 0xFF;"
        }
        state = 151702023;
        continue;
      case 194234029:
        if (Math.random() < 0.5) {
          calcs += "^b[22] += b[11] + b[42] + b[30] + b[20] + b[28] + b[4] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[22] &= 0xFF;"
        } else {
          calcs += "^b[6] ^= (b[8] + b[23] + b[28] + b[17] + b[32] + b[12] + 66) & 0xFF;"
        }
        state = 432353446;
        continue;
      case 194691887:
        if (75933549) {
          calcs += "^b[12] += b[22] + b[23] + b[1] + b[6] + b[37] + b[4] + 96;"
          calcs += "^b[12] &= 0xFF;"
        } else {
          calcs += "^b[33] -= b[28] + b[34] + b[27] + b[36] + b[3] + b[39] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[33] &= 0xFF;"
        }
        state = 397807652;
        continue;
      case 198364009:
        if (Math.random() < 0.5) {
          calcs += "^b[13] ^= (b[6] + b[31] + b[8] + b[15] + b[27] + b[3] + 46) & 0xFF;"
        } else {
          calcs += "^b[20] ^= (b[14] + b[7] + b[4] + b[0] + b[29] + b[8] + 172) & 0xFF;"
        }
        state = 311775975;
        continue;
      case 201264604:
        if (65033003n) {
          calcs += "^b[5] ^= (b[35] + b[9] + b[30] + b[8] + b[27] + b[26] + 113) & 0xFF;"
        } else {
          calcs += "^b[41] -= b[39] + b[3] + b[7] + b[21] + b[17] + b[29] + 117;"
          calcs += "^b[41] &= 0xFF;"
        }
        state = 100732102;
        continue;
      case 204547457:
        if (46005347n) {
          calcs += "^b[42] += b[16] + b[29] + b[3] + b[32] + b[4] + b[5] + 217;"
          calcs += "^b[42] &= 0xFF;"
        } else {
          calcs += "^b[19] ^= (b[12] + b[4] + b[16] + b[6] + b[9] + b[13] + 174) & 0xFF;"
        }
        state = 958409490;
        continue;
      case 206186554:
        if (78711938n) {
          calcs += "^b[33] ^= (b[30] + b[17] + b[31] + b[21] + b[23] + b[25] + 88) & 0xFF;"
        } else {
          calcs += "^b[37] += b[20] + b[11] + b[16] + b[31] + b[22] + b[0] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[37] &= 0xFF;"
        }
        state = 825535610;
        continue;
      case 208944610:
        if (193271221) {
          calcs += "^b[12] ^= (b[43] + b[25] + b[35] + b[39] + b[17] + b[3] + 98) & 0xFF;"
        } else {
          calcs += "^b[39] += b[24] + b[5] + b[41] + b[6] + b[8] + b[33] + 137;"
          calcs += "^b[39] &= 0xFF;"
        }
        state = 614635127;
        continue;
      case 209432887:
        if (93470664n) {
          calcs += "^b[34] += b[42] + b[35] + b[11] + b[29] + b[22] + b[20] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[34] &= 0xFF;"
        } else {
          calcs += "^b[10] ^= (b[29] + b[32] + b[8] + b[4] + b[30] + b[23] + " + Math.floor(Math.random() * 256) + ") & 0xFF;"
        }
        state = 1038100041;
        continue;
      case 209848935:
        if (28362108n) {
          calcs += "^b[19] -= b[36] + b[41] + b[28] + b[22] + b[12] + b[32] + 163;"
          calcs += "^b[19] &= 0xFF;"
        } else {
          calcs += "^b[17] += b[5] + b[16] + b[6] + b[18] + b[37] + b[29] + 159;"
          calcs += "^b[17] &= 0xFF;"
        }
        state = 536174126;
        continue;
      case 210975861:
        if (55514709) {
          calcs += "^b[18] -= b[0] + b[12] + b[19] + b[10] + b[29] + b[34] + 226;"
          calcs += "^b[18] &= 0xFF;"
        } else {
          calcs += "^b[39] += b[18] + b[16] + b[8] + b[19] + b[5] + b[23] + 36;"
          calcs += "^b[39] &= 0xFF;"
        }
        state = 1058358019;
        continue;
      case 211163838:
        if (42216406n) {
          calcs += "^b[23] ^= (b[33] + b[16] + b[31] + b[26] + b[15] + b[1] + 3) & 0xFF;"
        } else {
          calcs += "^b[32] ^= (b[6] + b[36] + b[41] + b[15] + b[31] + b[7] + 77) & 0xFF;"
        }
        state = 559549544;
        continue;
      case 211248456:
        if (856534920) {
          calcs += "^b[19] -= b[18] + b[26] + b[1] + b[42] + b[23] + b[25] + 164;"
          calcs += "^b[19] &= 0xFF;"
        } else {
          calcs += "^b[11] += b[15] + b[43] + b[24] + b[34] + b[16] + b[9] + 166;"
          calcs += "^b[11] &= 0xFF;"
        }
        state = 805733218;
        continue;
      case 213185957:
        if (26081165n) {
          calcs += "^b[23] ^= (b[30] + b[1] + b[2] + b[25] + b[42] + b[36] + 233) & 0xFF;"
        } else {
          calcs += "^b[29] -= b[37] + b[21] + b[17] + b[13] + b[33] + b[28] + 4;"
          calcs += "^b[29] &= 0xFF;"
        }
        state = 693640144;
        continue;
      case 217091233:
        if (933239764) {
          calcs += "^b[0] += b[31] + b[33] + b[25] + b[29] + b[43] + b[26] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[0] &= 0xFF;"
        } else {
          calcs += "^b[8] -= b[4] + b[19] + b[32] + b[43] + b[16] + b[27] + 75;"
          calcs += "^b[8] &= 0xFF;"
        }
        state = 430801263;
        continue;
      case 219024877:
        if (69768241n) {
          calcs += "^b[5] ^= (b[26] + b[37] + b[28] + b[13] + b[41] + b[15] + 44) & 0xFF;"
        } else {
          calcs += "^b[27] -= b[16] + b[1] + b[25] + b[34] + b[21] + b[30] + 43;"
          calcs += "^b[27] &= 0xFF;"
        }
        state = 986437216;
        continue;
      case 220609761:
        if (58258984n) {
          calcs += "^b[31] -= b[22] + b[30] + b[4] + b[35] + b[20] + b[26] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[31] &= 0xFF;"
        } else {
          calcs += "^b[27] -= b[10] + b[33] + b[16] + b[22] + b[25] + b[4] + 212;"
          calcs += "^b[27] &= 0xFF;"
        }
        state = 873207146;
        continue;
      case 220618710:
        if (92040774n) {
          calcs += "^b[34] ^= (b[19] + b[42] + b[22] + b[13] + b[8] + b[3] + 68) & 0xFF;"
        } else {
          calcs += "^b[10] -= b[20] + b[39] + b[25] + b[17] + b[26] + b[22] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[10] &= 0xFF;"
        }
        state = 620893593;
        continue;
      case 220984231:
        if (53390257n) {
          calcs += "^b[25] -= b[3] + b[24] + b[18] + b[15] + b[2] + b[12] + 33;"
          calcs += "^b[25] &= 0xFF;"
        } else {
          calcs += "^b[0] ^= (b[7] + b[24] + b[19] + b[38] + b[11] + b[36] + 155) & 0xFF;"
        }
        state = 860000418;
        continue;
      case 221619054:
        if (959659211) {
          calcs += "^b[35] -= b[9] + b[23] + b[12] + b[16] + b[36] + b[14] + 145;"
          calcs += "^b[35] &= 0xFF;"
        } else {
          calcs += "^b[24] ^= (b[29] + b[39] + b[20] + b[38] + b[37] + b[10] + 148) & 0xFF;"
        }
        state = 612933473;
        continue;
      case 221781532:
        if (72652111n) {
          calcs += "^b[26] ^= (b[35] + b[31] + b[12] + b[1] + b[15] + b[27] + " + Math.floor(Math.random() * 256) + ") & 0xFF;"
        } else {
          calcs += "^b[25] += b[40] + b[2] + b[18] + b[35] + b[15] + b[32] + 16;"
          calcs += "^b[25] &= 0xFF;"
        }
        state = 908639392;
        continue;
      case 224518174:
        if (21603730n) {
          calcs += "^b[36] ^= (b[28] + b[6] + b[34] + b[21] + b[41] + b[35] + 245) & 0xFF;"
        } else {
          calcs += "^b[23] += b[20] + b[15] + b[25] + b[32] + b[30] + b[10] + 242;"
          calcs += "^b[23] &= 0xFF;"
        }
        state = 884575876;
        continue;
      case 225422723:
        if (Math.random() < 0.5) {
          calcs += "^b[4] -= b[8] + b[24] + b[29] + b[30] + b[41] + b[43] + 121;"
          calcs += "^b[4] &= 0xFF;"
        } else {
          calcs += "^b[28] += b[7] + b[16] + b[42] + b[25] + b[24] + b[13] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[28] &= 0xFF;"
        }
        state = 189630997;
        continue;
      case 229494579:
        if (Math.random() < 0.5) {
          calcs += "^b[0] += b[33] + b[15] + b[10] + b[24] + b[19] + b[21] + 91;"
          calcs += "^b[0] &= 0xFF;"
        } else {
          calcs += "^b[4] += b[29] + b[33] + b[34] + b[20] + b[9] + b[17] + 77;"
          calcs += "^b[4] &= 0xFF;"
        }
        state = 472186968;
        continue;
      case 230205454:
        if (44456754n) {
          calcs += "^b[27] -= b[18] + b[31] + b[35] + b[1] + b[10] + b[23] + 88;"
          calcs += "^b[27] &= 0xFF;"
        } else {
          calcs += "^b[22] += b[5] + b[4] + b[2] + b[15] + b[25] + b[23] + 123;"
          calcs += "^b[22] &= 0xFF;"
        }
        state = 312893244;
        continue;
      case 230923361:
        if (Math.random() < 0.5) {
          calcs += "^b[5] += b[12] + b[13] + b[18] + b[35] + b[9] + b[15] + 115;"
          calcs += "^b[5] &= 0xFF;"
        } else {
          calcs += "^b[1] += b[36] + b[10] + b[37] + b[29] + b[30] + b[12] + 2;"
          calcs += "^b[1] &= 0xFF;"
        }
        state = 258957044;
        continue;
      case 230930038:
        if (386539893) {
          calcs += "^b[26] += b[4] + b[40] + b[10] + b[15] + b[42] + b[27] + 211;"
          calcs += "^b[26] &= 0xFF;"
        } else {
          calcs += "^b[40] -= b[8] + b[26] + b[31] + b[38] + b[32] + b[37] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[40] &= 0xFF;"
        }
        state = 746309371;
        continue;
      case 231432592:
        if (Math.random() < 0.5) {
          calcs += "^b[4] += b[43] + b[32] + b[12] + b[24] + b[3] + b[9] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[4] &= 0xFF;"
        } else {
          calcs += "^b[25] -= b[31] + b[7] + b[30] + b[38] + b[39] + b[29] + 174;"
          calcs += "^b[25] &= 0xFF;"
        }
        state = 987221748;
        continue;
      case 234522330:
        if (59337487n) {
          calcs += "^b[41] += b[2] + b[32] + b[15] + b[12] + b[26] + b[36] + 98;"
          calcs += "^b[41] &= 0xFF;"
        } else {
          calcs += "^b[29] -= b[38] + b[14] + b[34] + b[18] + b[43] + b[35] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[29] &= 0xFF;"
        }
        state = 1068988450;
        continue;
      case 237337400:
        if (804085173) {
          calcs += "^b[23] -= b[5] + b[19] + b[34] + b[11] + b[42] + b[29] + 250;"
          calcs += "^b[23] &= 0xFF;"
        } else {
          calcs += "^b[1] ^= (b[40] + b[42] + b[33] + b[23] + b[7] + b[19] + 10) & 0xFF;"
        }
        state = 201488550;
        continue;
      case 238161391:
        if (17051732n) {
          calcs += "^b[11] -= b[43] + b[24] + b[34] + b[5] + b[32] + b[17] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[11] &= 0xFF;"
        } else {
          calcs += "^b[28] += b[26] + b[18] + b[1] + b[5] + b[32] + b[19] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[28] &= 0xFF;"
        }
        state = 586451322;
        continue;
      case 238416598:
        if (372666475) {
          calcs += "^b[28] += b[25] + b[26] + b[11] + b[39] + b[18] + b[0] + 75;"
          calcs += "^b[28] &= 0xFF;"
        } else {
          calcs += "^b[36] ^= (b[18] + b[42] + b[9] + b[34] + b[12] + b[29] + 242) & 0xFF;"
        }
        state = 780905302;
        continue;
      case 242387230:
        if (19562795n) {
          calcs += "^b[10] += b[19] + b[43] + b[8] + b[13] + b[14] + b[38] + 116;"
          calcs += "^b[10] &= 0xFF;"
        } else {
          calcs += "^b[23] ^= (b[15] + b[41] + b[29] + b[12] + b[39] + b[24] + 173) & 0xFF;"
        }
        state = 175872557;
        continue;
      case 242494677:
        if (Math.random() < 0.5) {
          calcs += "^b[31] -= b[22] + b[41] + b[24] + b[34] + b[3] + b[37] + 95;"
          calcs += "^b[31] &= 0xFF;"
        } else {
          calcs += "^b[43] += b[16] + b[17] + b[22] + b[23] + b[31] + b[11] + 211;"
          calcs += "^b[43] &= 0xFF;"
        }
        state = 723841222;
        continue;
      case 243572122:
        if (653528729) {
          calcs += "^b[30] ^= (b[2] + b[1] + b[21] + b[9] + b[11] + b[7] + 145) & 0xFF;"
        } else {
          calcs += "^b[17] += b[29] + b[43] + b[1] + b[8] + b[32] + b[35] + 126;"
          calcs += "^b[17] &= 0xFF;"
        }
        state = 33640968;
        continue;
      case 244842414:
        if (Math.random() < 0.5) {
          calcs += "^b[39] ^= (b[34] + b[3] + b[1] + b[14] + b[42] + b[35] + 131) & 0xFF;"
        } else {
          calcs += "^b[5] -= b[15] + b[33] + b[18] + b[20] + b[3] + b[22] + 88;"
          calcs += "^b[5] &= 0xFF;"
        }
        state = 852100699;
        continue;
      case 246084964:
        if (693526256) {
          calcs += "^b[34] ^= (b[6] + b[0] + b[12] + b[25] + b[41] + b[43] + " + Math.floor(Math.random() * 256) + ") & 0xFF;"
        } else {
          calcs += "^b[4] -= b[37] + b[2] + b[27] + b[13] + b[21] + b[35] + 194;"
          calcs += "^b[4] &= 0xFF;"
        }
        state = 506894636;
        continue;
      case 246196592:
        if (Math.random() < 0.5) {
          calcs += "^b[9] ^= (b[1] + b[20] + b[23] + b[27] + b[13] + b[33] + 130) & 0xFF;"
        } else {
          calcs += "^b[24] -= b[36] + b[39] + b[27] + b[8] + b[14] + b[34] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[24] &= 0xFF;"
        }
        state = 467042858;
        continue;
      case 246665663:
        if (179082165) {
          calcs += "^b[13] += b[16] + b[33] + b[41] + b[1] + b[20] + b[12] + 104;"
          calcs += "^b[13] &= 0xFF;"
        } else {
          calcs += "^b[27] += b[13] + b[37] + b[23] + b[17] + b[2] + b[43] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[27] &= 0xFF;"
        }
        state = 618341793;
        continue;
      case 246675300:
        if (707107748) {
          calcs += "^b[2] ^= (b[9] + b[3] + b[42] + b[13] + b[38] + b[37] + 162) & 0xFF;"
        } else {
          calcs += "^b[18] ^= (b[1] + b[7] + b[23] + b[2] + b[37] + b[4] + 152) & 0xFF;"
        }
        state = 40772717;
        continue;
      case 249647999:
        if (48742755n) {
          calcs += "^b[8] -= b[7] + b[6] + b[28] + b[27] + b[18] + b[17] + 239;"
          calcs += "^b[8] &= 0xFF;"
        } else {
          calcs += "^b[11] += b[29] + b[21] + b[41] + b[30] + b[14] + b[23] + 20;"
          calcs += "^b[11] &= 0xFF;"
        }
        state = 1053090044;
        continue;
      case 250006002:
        if (55634345n) {
          calcs += "^b[12] ^= (b[38] + b[7] + b[43] + b[0] + b[37] + b[42] + 242) & 0xFF;"
        } else {
          calcs += "^b[40] -= b[13] + b[21] + b[8] + b[3] + b[10] + b[17] + 248;"
          calcs += "^b[40] &= 0xFF;"
        }
        state = 865238636;
        continue;
      case 252277940:
        if (Math.random() < 0.5) {
          calcs += "^b[20] ^= (b[12] + b[16] + b[11] + b[2] + b[18] + b[21] + 57) & 0xFF;"
        } else {
          calcs += "^b[38] -= b[25] + b[32] + b[36] + b[37] + b[26] + b[35] + 147;"
          calcs += "^b[38] &= 0xFF;"
        }
        state = 219958944;
        continue;
      case 254614724:
        if (Math.random() < 0.5) {
          calcs += "^b[26] ^= (b[32] + b[0] + b[13] + b[27] + b[43] + b[31] + 179) & 0xFF;"
        } else {
          calcs += "^b[35] += b[0] + b[29] + b[10] + b[24] + b[26] + b[32] + 229;"
          calcs += "^b[35] &= 0xFF;"
        }
        state = 112270672;
        continue;
      case 260248466:
        if (14496527n) {
          calcs += "^b[29] -= b[9] + b[5] + b[30] + b[38] + b[1] + b[28] + 221;"
          calcs += "^b[29] &= 0xFF;"
        } else {
          calcs += "^b[43] -= b[4] + b[20] + b[36] + b[25] + b[22] + b[7] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[43] &= 0xFF;"
        }
        state = 649829285;
        continue;
      case 261461743:
        if (Math.random() < 0.5) {
          calcs += "^b[31] -= b[14] + b[43] + b[19] + b[36] + b[41] + b[8] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[31] &= 0xFF;"
        } else {
          calcs += "^b[20] ^= (b[7] + b[23] + b[36] + b[43] + b[33] + b[25] + 177) & 0xFF;"
        }
        state = 719855432;
        continue;
      case 261889048:
        if (419825796) {
          calcs += "^b[1] -= b[35] + b[43] + b[16] + b[15] + b[13] + b[2] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[1] &= 0xFF;"
        } else {
          calcs += "^b[27] -= b[17] + b[28] + b[29] + b[2] + b[38] + b[9] + 9;"
          calcs += "^b[27] &= 0xFF;"
        }
        state = 240270477;
        continue;
      case 262657052:
        if (Math.random() < 0.5) {
          calcs += "^b[12] ^= (b[3] + b[22] + b[38] + b[29] + b[26] + b[4] + 213) & 0xFF;"
        } else {
          calcs += "^b[6] -= b[17] + b[13] + b[2] + b[28] + b[37] + b[15] + 95;"
          calcs += "^b[6] &= 0xFF;"
        }
        state = 351832632;
        continue;
      case 264634585:
        if (276553388) {
          calcs += "^b[13] -= b[11] + b[0] + b[40] + b[37] + b[8] + b[4] + 105;"
          calcs += "^b[13] &= 0xFF;"
        } else {
          calcs += "^b[37] -= b[39] + b[43] + b[28] + b[17] + b[24] + b[7] + 3;"
          calcs += "^b[37] &= 0xFF;"
        }
        state = 995713489;
        continue;
      case 266322968:
        if (65586349n) {
          calcs += "^b[10] ^= (b[20] + b[35] + b[3] + b[17] + b[1] + b[41] + 172) & 0xFF;"
        } else {
          calcs += "^b[42] -= b[32] + b[27] + b[40] + b[28] + b[33] + b[9] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[42] &= 0xFF;"
        }
        state = 796003565;
        continue;
      case 267460296:
        if (Math.random() < 0.5) {
          calcs += "^b[19] -= b[34] + b[15] + b[42] + b[20] + b[37] + b[33] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[19] &= 0xFF;"
        } else {
          calcs += "^b[5] -= b[29] + b[22] + b[2] + b[30] + b[19] + b[7] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[5] &= 0xFF;"
        }
        state = 455908408;
        continue;
      case 268121630:
        if (17167199n) {
          calcs += "^b[35] -= b[34] + b[41] + b[31] + b[42] + b[27] + b[19] + 135;"
          calcs += "^b[35] &= 0xFF;"
        } else {
          calcs += "^b[41] ^= (b[30] + b[13] + b[21] + b[0] + b[24] + b[1] + 247) & 0xFF;"
        }
        state = 913709221;
        continue;
      case 269695589:
        if (81888862n) {
          calcs += "^b[13] -= b[9] + b[8] + b[12] + b[22] + b[24] + b[19] + 142;"
          calcs += "^b[13] &= 0xFF;"
        } else {
          calcs += "^b[9] ^= (b[2] + b[13] + b[15] + b[42] + b[39] + b[4] + 52) & 0xFF;"
        }
        state = 1026937852;
        continue;
      case 271112798:
        if (401684922) {
          calcs += "^b[13] ^= (b[14] + b[30] + b[21] + b[39] + b[16] + b[17] + 63) & 0xFF;"
        } else {
          calcs += "^b[39] -= b[19] + b[17] + b[33] + b[22] + b[31] + b[10] + 166;"
          calcs += "^b[39] &= 0xFF;"
        }
        state = 270336697;
        continue;
      case 271627321:
        if (95572677n) {
          calcs += "^b[34] ^= (b[24] + b[19] + b[14] + b[9] + b[6] + b[1] + 162) & 0xFF;"
        } else {
          calcs += "^b[4] ^= (b[24] + b[17] + b[36] + b[13] + b[10] + b[41] + 197) & 0xFF;"
        }
        state = 802205526;
        continue;
      case 274221760:
        if (Math.random() < 0.5) {
          calcs += "^b[27] ^= (b[6] + b[24] + b[16] + b[19] + b[13] + b[14] + 35) & 0xFF;"
        } else {
          calcs += "^b[10] -= b[3] + b[21] + b[37] + b[30] + b[34] + b[29] + 240;"
          calcs += "^b[10] &= 0xFF;"
        }
        state = 492731019;
        continue;
      case 275097633:
        if (Math.random() < 0.5) {
          calcs += "^b[12] ^= (b[27] + b[41] + b[29] + b[26] + b[36] + b[31] + " + Math.floor(Math.random() * 256) + ") & 0xFF;"
        } else {
          calcs += "^b[9] += b[41] + b[31] + b[7] + b[36] + b[20] + b[42] + 182;"
          calcs += "^b[9] &= 0xFF;"
        }
        state = 543524764;
        continue;
      case 275378278:
        if (45412373n) {
          calcs += "^b[39] += b[0] + b[34] + b[21] + b[23] + b[17] + b[22] + 54;"
          calcs += "^b[39] &= 0xFF;"
        } else {
          calcs += "^b[38] += b[4] + b[32] + b[6] + b[26] + b[25] + b[22] + 44;"
          calcs += "^b[38] &= 0xFF;"
        }
        state = 210341530;
        continue;
      case 275423299:
        if (16039728n) {
          calcs += "^b[7] ^= (b[19] + b[3] + b[16] + b[1] + b[34] + b[33] + " + Math.floor(Math.random() * 256) + ") & 0xFF;"
        } else {
          calcs += "^b[0] ^= (b[20] + b[26] + b[24] + b[34] + b[19] + b[32] + 89) & 0xFF;"
        }
        state = 1003454329;
        continue;
      case 275553514:
        if (232479927) {
          calcs += "^b[42] -= b[21] + b[25] + b[29] + b[24] + b[6] + b[33] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[42] &= 0xFF;"
        } else {
          calcs += "^b[25] ^= (b[9] + b[26] + b[29] + b[23] + b[35] + b[24] + 65) & 0xFF;"
        }
        state = 284164352;
        continue;
      case 277251462:
        if (347510130) {
          calcs += "^b[0] ^= (b[38] + b[17] + b[43] + b[3] + b[35] + b[6] + 63) & 0xFF;"
        } else {
          calcs += "^b[33] ^= (b[43] + b[30] + b[42] + b[0] + b[8] + b[2] + 121) & 0xFF;"
        }
        state = 806104766;
        continue;
      case 277284985:
        if (Math.random() < 0.5) {
          calcs += "^b[22] -= b[28] + b[19] + b[39] + b[20] + b[14] + b[4] + 88;"
          calcs += "^b[22] &= 0xFF;"
        } else {
          calcs += "^b[35] ^= (b[0] + b[39] + b[17] + b[16] + b[1] + b[42] + 208) & 0xFF;"
        }
        state = 795669700;
        continue;
      case 279165449:
        if (Math.random() < 0.5) {
          calcs += "^b[5] ^= (b[16] + b[3] + b[1] + b[12] + b[17] + b[4] + 44) & 0xFF;"
        } else {
          calcs += "^b[25] -= b[20] + b[5] + b[21] + b[22] + b[17] + b[1] + 130;"
          calcs += "^b[25] &= 0xFF;"
        }
        state = 647961758;
        continue;
      case 280767414:
        if (Math.random() < 0.5) {
          calcs += "^b[11] += b[14] + b[0] + b[4] + b[20] + b[7] + b[27] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[11] &= 0xFF;"
        } else {
          calcs += "^b[3] += b[13] + b[7] + b[42] + b[5] + b[40] + b[39] + 239;"
          calcs += "^b[3] &= 0xFF;"
        }
        state = 419731386;
        continue;
      case 281004428:
        if (379750618) {
          calcs += "^b[33] -= b[39] + b[12] + b[34] + b[38] + b[8] + b[37] + 200;"
          calcs += "^b[33] &= 0xFF;"
        } else {
          calcs += "^b[34] -= b[5] + b[10] + b[15] + b[2] + b[25] + b[26] + 41;"
          calcs += "^b[34] &= 0xFF;"
        }
        state = 948650807;
        continue;
      case 282083183:
        if (Math.random() < 0.5) {
          calcs += "^b[38] += b[14] + b[6] + b[23] + b[27] + b[10] + b[42] + 54;"
          calcs += "^b[38] &= 0xFF;"
        } else {
          calcs += "^b[43] ^= (b[31] + b[1] + b[33] + b[13] + b[15] + b[3] + 216) & 0xFF;"
        }
        state = 41718568;
        continue;
      case 283679858:
        if (477182091) {
          calcs += "^b[31] += b[21] + b[41] + b[26] + b[27] + b[6] + b[43] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[31] &= 0xFF;"
        } else {
          calcs += "^b[6] ^= (b[23] + b[13] + b[20] + b[11] + b[40] + b[16] + 23) & 0xFF;"
        }
        state = 931354157;
        continue;
      case 285069999:
        if (Math.random() < 0.5) {
          calcs += "^b[14] += b[0] + b[28] + b[10] + b[6] + b[2] + b[8] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[14] &= 0xFF;"
        } else {
          calcs += "^b[20] ^= (b[24] + b[32] + b[29] + b[9] + b[6] + b[35] + 217) & 0xFF;"
        }
        state = 66690864;
        continue;
      case 287357895:
        if (Math.random() < 0.5) {
          calcs += "^b[5] ^= (b[17] + b[26] + b[15] + b[24] + b[40] + b[29] + " + Math.floor(Math.random() * 256) + ") & 0xFF;"
        } else {
          calcs += "^b[1] -= b[27] + b[6] + b[10] + b[23] + b[35] + b[22] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[1] &= 0xFF;"
        }
        state = 145686511;
        continue;
      case 287782403:
        if (12365573n) {
          calcs += "^b[33] ^= (b[16] + b[31] + b[13] + b[17] + b[6] + b[21] + 112) & 0xFF;"
        } else {
          calcs += "^b[40] ^= (b[33] + b[23] + b[24] + b[41] + b[31] + b[27] + 58) & 0xFF;"
        }
        state = 263494323;
        continue;
      case 288255168:
        if (972634646) {
          calcs += "^b[36] ^= (b[23] + b[35] + b[41] + b[15] + b[24] + b[17] + " + Math.floor(Math.random() * 256) + ") & 0xFF;"
        } else {
          calcs += "^b[0] -= b[15] + b[3] + b[29] + b[10] + b[20] + b[39] + 93;"
          calcs += "^b[0] &= 0xFF;"
        }
        state = 567345515;
        continue;
      case 288574193:
        if (Math.random() < 0.5) {
          calcs += "^b[34] += b[32] + b[2] + b[1] + b[42] + b[40] + b[31] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[34] &= 0xFF;"
        } else {
          calcs += "^b[22] ^= (b[29] + b[33] + b[20] + b[30] + b[0] + b[25] + 9) & 0xFF;"
        }
        state = 579458529;
        continue;
      case 288734789:
        if (Math.random() < 0.5) {
          calcs += "^b[18] += b[35] + b[2] + b[15] + b[13] + b[10] + b[27] + 210;"
          calcs += "^b[18] &= 0xFF;"
        } else {
          calcs += "^b[34] ^= (b[12] + b[0] + b[35] + b[9] + b[38] + b[30] + 1) & 0xFF;"
        }
        state = 235211605;
        continue;
      case 290491044:
        if (444003861) {
          calcs += "^b[21] -= b[5] + b[43] + b[39] + b[42] + b[9] + b[4] + 228;"
          calcs += "^b[21] &= 0xFF;"
        } else {
          calcs += "^b[12] -= b[15] + b[34] + b[31] + b[30] + b[37] + b[0] + 234;"
          calcs += "^b[12] &= 0xFF;"
        }
        state = 990371719;
        continue;
      case 291625724:
        if (42294967n) {
          calcs += "^b[7] -= b[41] + b[24] + b[26] + b[32] + b[15] + b[17] + 13;"
          calcs += "^b[7] &= 0xFF;"
        } else {
          calcs += "^b[15] ^= (b[1] + b[17] + b[43] + b[19] + b[11] + b[39] + 153) & 0xFF;"
        }
        state = 871413126;
        continue;
      case 292965864:
        if (88816545n) {
          calcs += "^b[42] += b[21] + b[3] + b[24] + b[39] + b[43] + b[18] + 213;"
          calcs += "^b[42] &= 0xFF;"
        } else {
          calcs += "^b[27] ^= (b[25] + b[29] + b[34] + b[13] + b[41] + b[5] + " + Math.floor(Math.random() * 256) + ") & 0xFF;"
        }
        state = 926464768;
        continue;
      case 293954309:
        if (283202612) {
          calcs += "^b[38] ^= (b[42] + b[9] + b[25] + b[35] + b[28] + b[27] + 51) & 0xFF;"
        } else {
          calcs += "^b[34] -= b[4] + b[3] + b[43] + b[38] + b[23] + b[7] + 236;"
          calcs += "^b[34] &= 0xFF;"
        }
        state = 985018515;
        continue;
      case 294180573:
        if (603296406) {
          calcs += "^b[4] ^= (b[18] + b[36] + b[10] + b[23] + b[35] + b[43] + 201) & 0xFF;"
        } else {
          calcs += "^b[41] -= b[27] + b[21] + b[24] + b[22] + b[28] + b[12] + 139;"
          calcs += "^b[41] &= 0xFF;"
        }
        state = 727215764;
        continue;
      case 294271724:
        if (72079500n) {
          calcs += "^b[25] -= b[18] + b[32] + b[12] + b[2] + b[27] + b[8] + 127;"
          calcs += "^b[25] &= 0xFF;"
        } else {
          calcs += "^b[4] ^= (b[22] + b[40] + b[23] + b[36] + b[28] + b[21] + 139) & 0xFF;"
        }
        state = 14196407;
        continue;
      case 294918952:
        if (33776471n) {
          calcs += "^b[10] += b[20] + b[16] + b[0] + b[17] + b[14] + b[5] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[10] &= 0xFF;"
        } else {
          calcs += "^b[42] += b[7] + b[13] + b[3] + b[6] + b[28] + b[5] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[42] &= 0xFF;"
        }
        state = 677579458;
        continue;
      case 296261627:
        if (Math.random() < 0.5) {
          calcs += "^b[21] -= b[1] + b[3] + b[8] + b[15] + b[39] + b[4] + 237;"
          calcs += "^b[21] &= 0xFF;"
        } else {
          calcs += "^b[3] ^= (b[34] + b[14] + b[33] + b[28] + b[15] + b[36] + " + Math.floor(Math.random() * 256) + ") & 0xFF;"
        }
        state = 786912410;
        continue;
      case 297638766:
        if (57257075n) {
          calcs += "^b[37] -= b[24] + b[39] + b[15] + b[10] + b[13] + b[35] + 225;"
          calcs += "^b[37] &= 0xFF;"
        } else {
          calcs += "^b[25] ^= (b[9] + b[5] + b[3] + b[14] + b[40] + b[41] + 157) & 0xFF;"
        }
        state = 594094305;
        continue;
      case 299520450:
        if (939457130) {
          calcs += "^b[7] ^= (b[22] + b[3] + b[9] + b[23] + b[21] + b[27] + 226) & 0xFF;"
        } else {
          calcs += "^b[37] += b[10] + b[15] + b[41] + b[36] + b[1] + b[38] + 181;"
          calcs += "^b[37] &= 0xFF;"
        }
        state = 944434393;
        continue;
      case 300912847:
        if (360549626) {
          calcs += "^b[26] ^= (b[29] + b[12] + b[24] + b[41] + b[9] + b[11] + 242) & 0xFF;"
        } else {
          calcs += "^b[8] ^= (b[21] + b[43] + b[14] + b[32] + b[26] + b[11] + 230) & 0xFF;"
        }
        state = 916753703;
        continue;
      case 302795555:
        if (623409292) {
          calcs += "^b[11] += b[35] + b[20] + b[5] + b[38] + b[13] + b[22] + 63;"
          calcs += "^b[11] &= 0xFF;"
        } else {
          calcs += "^b[16] -= b[25] + b[37] + b[42] + b[23] + b[3] + b[1] + 157;"
          calcs += "^b[16] &= 0xFF;"
        }
        state = 907929871;
        continue;
      case 304382579:
        if (Math.random() < 0.5) {
          calcs += "^b[31] ^= (b[11] + b[2] + b[42] + b[1] + b[26] + b[13] + 252) & 0xFF;"
        } else {
          calcs += "^b[43] += b[21] + b[17] + b[34] + b[38] + b[40] + b[29] + 248;"
          calcs += "^b[43] &= 0xFF;"
        }
        state = 162299957;
        continue;
      case 304625349:
        if (852763113) {
          calcs += "^b[29] += b[30] + b[3] + b[20] + b[8] + b[39] + b[36] + 43;"
          calcs += "^b[29] &= 0xFF;"
        } else {
          calcs += "^b[14] -= b[4] + b[5] + b[31] + b[15] + b[36] + b[40] + 67;"
          calcs += "^b[14] &= 0xFF;"
        }
        state = 68078983;
        continue;
      case 305375521:
        if (97867755n) {
          calcs += "^b[32] -= b[16] + b[21] + b[4] + b[17] + b[28] + b[22] + 18;"
          calcs += "^b[32] &= 0xFF;"
        } else {
          calcs += "^b[25] -= b[37] + b[40] + b[17] + b[21] + b[14] + b[33] + 52;"
          calcs += "^b[25] &= 0xFF;"
        }
        state = 838732416;
        continue;
      case 307715980:
        if (37421593n) {
          calcs += "^b[16] += b[15] + b[10] + b[26] + b[2] + b[17] + b[14] + 233;"
          calcs += "^b[16] &= 0xFF;"
        } else {
          calcs += "^b[18] -= b[23] + b[10] + b[2] + b[30] + b[6] + b[17] + 44;"
          calcs += "^b[18] &= 0xFF;"
        }
        state = 798465969;
        continue;
      case 308137512:
        if (84118768n) {
          calcs += "^b[34] += b[25] + b[28] + b[24] + b[31] + b[41] + b[2] + 60;"
          calcs += "^b[34] &= 0xFF;"
        } else {
          calcs += "^b[15] -= b[17] + b[29] + b[20] + b[9] + b[0] + b[43] + 229;"
          calcs += "^b[15] &= 0xFF;"
        }
        state = 302678208;
        continue;
      case 308307937:
        if (830173059) {
          calcs += "^b[16] -= b[41] + b[36] + b[5] + b[11] + b[21] + b[27] + 9;"
          calcs += "^b[16] &= 0xFF;"
        } else {
          calcs += "^b[17] -= b[34] + b[1] + b[14] + b[19] + b[29] + b[18] + 164;"
          calcs += "^b[17] &= 0xFF;"
        }
        state = 841512768;
        continue;
      case 308969481:
        if (61075735n) {
          calcs += "^b[31] -= b[33] + b[6] + b[1] + b[29] + b[23] + b[4] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[31] &= 0xFF;"
        } else {
          calcs += "^b[8] += b[41] + b[7] + b[32] + b[17] + b[40] + b[22] + 77;"
          calcs += "^b[8] &= 0xFF;"
        }
        state = 545102990;
        continue;
      case 310172561:
        if (59015155n) {
          calcs += "^b[26] -= b[23] + b[16] + b[41] + b[7] + b[27] + b[18] + 119;"
          calcs += "^b[26] &= 0xFF;"
        } else {
          calcs += "^b[20] ^= (b[5] + b[30] + b[18] + b[4] + b[7] + b[13] + 174) & 0xFF;"
        }
        state = 750063720;
        continue;
      case 310398609:
        if (Math.random() < 0.5) {
          calcs += "^b[40] += b[35] + b[42] + b[2] + b[24] + b[22] + b[0] + 14;"
          calcs += "^b[40] &= 0xFF;"
        } else {
          calcs += "^b[41] -= b[18] + b[30] + b[14] + b[38] + b[5] + b[26] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[41] &= 0xFF;"
        }
        state = 627325155;
        continue;
      case 310481047:
        if (619140230) {
          calcs += "^b[39] += b[41] + b[22] + b[17] + b[4] + b[0] + b[35] + 168;"
          calcs += "^b[39] &= 0xFF;"
        } else {
          calcs += "^b[34] -= b[2] + b[27] + b[31] + b[28] + b[18] + b[5] + 29;"
          calcs += "^b[34] &= 0xFF;"
        }
        state = 103230408;
        continue;
      case 311777325:
        if (Math.random() < 0.5) {
          calcs += "^b[42] += b[18] + b[37] + b[23] + b[21] + b[41] + b[38] + 64;"
          calcs += "^b[42] &= 0xFF;"
        } else {
          calcs += "^b[30] -= b[37] + b[35] + b[1] + b[10] + b[43] + b[36] + 152;"
          calcs += "^b[30] &= 0xFF;"
        }
        state = 947180378;
        continue;
      case 314005330:
        if (72635016n) {
          calcs += "^b[1] -= b[14] + b[10] + b[9] + b[33] + b[41] + b[15] + 240;"
          calcs += "^b[1] &= 0xFF;"
        } else {
          calcs += "^b[17] ^= (b[18] + b[42] + b[33] + b[21] + b[29] + b[7] + " + Math.floor(Math.random() * 256) + ") & 0xFF;"
        }
        state = 771896895;
        continue;
      case 316553773:
        if (64078358n) {
          calcs += "^b[23] += b[30] + b[6] + b[10] + b[40] + b[15] + b[37] + 35;"
          calcs += "^b[23] &= 0xFF;"
        } else {
          calcs += "^b[18] += b[42] + b[17] + b[26] + b[39] + b[4] + b[43] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[18] &= 0xFF;"
        }
        state = 962667923;
        continue;
      case 316759147:
        if (Math.random() < 0.5) {
          calcs += "^b[21] += b[42] + b[12] + b[8] + b[25] + b[27] + b[6] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[21] &= 0xFF;"
        } else {
          calcs += "^b[11] -= b[3] + b[20] + b[30] + b[18] + b[1] + b[17] + 21;"
          calcs += "^b[11] &= 0xFF;"
        }
        state = 120860048;
        continue;
      case 322224592:
        if (51026408n) {
          calcs += "^b[19] ^= (b[16] + b[10] + b[3] + b[5] + b[39] + b[0] + " + Math.floor(Math.random() * 256) + ") & 0xFF;"
        } else {
          calcs += "^b[41] ^= (b[42] + b[38] + b[1] + b[17] + b[24] + b[9] + 68) & 0xFF;"
        }
        state = 294571306;
        continue;
      case 323794006:
        if (398232492) {
          calcs += "^b[12] -= b[9] + b[10] + b[35] + b[4] + b[29] + b[11] + 198;"
          calcs += "^b[12] &= 0xFF;"
        } else {
          calcs += "^b[23] ^= (b[11] + b[15] + b[34] + b[8] + b[36] + b[16] + 62) & 0xFF;"
        }
        state = 428579655;
        continue;
      case 324375396:
        if (Math.random() < 0.5) {
          calcs += "^b[16] -= b[39] + b[1] + b[19] + b[10] + b[14] + b[26] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[16] &= 0xFF;"
        } else {
          calcs += "^b[30] += b[17] + b[26] + b[21] + b[4] + b[6] + b[28] + 84;"
          calcs += "^b[30] &= 0xFF;"
        }
        state = 357530869;
        continue;
      case 326353561:
        if (477283788) {
          calcs += "^b[24] -= b[41] + b[34] + b[27] + b[37] + b[36] + b[15] + 0;"
          calcs += "^b[24] &= 0xFF;"
        } else {
          calcs += "^b[22] -= b[33] + b[18] + b[11] + b[27] + b[41] + b[31] + 208;"
          calcs += "^b[22] &= 0xFF;"
        }
        state = 221435762;
        continue;
      case 326512739:
        if (57599802n) {
          calcs += "^b[24] ^= (b[15] + b[38] + b[27] + b[23] + b[21] + b[1] + 244) & 0xFF;"
        } else {
          calcs += "^b[15] ^= (b[2] + b[39] + b[21] + b[11] + b[10] + b[5] + " + Math.floor(Math.random() * 256) + ") & 0xFF;"
        }
        state = 881516063;
        continue;
      case 326894214:
        if (Math.random() < 0.5) {
          calcs += "^b[33] -= b[8] + b[10] + b[30] + b[31] + b[20] + b[42] + 105;"
          calcs += "^b[33] &= 0xFF;"
        } else {
          calcs += "^b[0] += b[21] + b[26] + b[20] + b[27] + b[33] + b[29] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[0] &= 0xFF;"
        }
        state = 469020671;
        continue;
      case 327658034:
        if (87861049) {
          calcs += "^b[35] ^= (b[8] + b[16] + b[9] + b[23] + b[29] + b[12] + " + Math.floor(Math.random() * 256) + ") & 0xFF;"
        } else {
          calcs += "^b[3] ^= (b[18] + b[9] + b[2] + b[35] + b[34] + b[30] + 185) & 0xFF;"
        }
        state = 936987221;
        continue;
      case 328293975:
        if (487164505) {
          calcs += "^b[31] += b[27] + b[6] + b[10] + b[40] + b[38] + b[17] + 15;"
          calcs += "^b[31] &= 0xFF;"
        } else {
          calcs += "^b[7] -= b[38] + b[42] + b[28] + b[6] + b[16] + b[25] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[7] &= 0xFF;"
        }
        state = 242015430;
        continue;
      case 332288104:
        if (83622609n) {
          calcs += "^b[34] ^= (b[42] + b[18] + b[9] + b[32] + b[3] + b[11] + 182) & 0xFF;"
        } else {
          calcs += "^b[27] -= b[30] + b[34] + b[0] + b[18] + b[16] + b[11] + 141;"
          calcs += "^b[27] &= 0xFF;"
        }
        state = 1014119894;
        continue;
      case 333008690:
        if (81927720n) {
          calcs += "^b[11] -= b[24] + b[13] + b[3] + b[6] + b[27] + b[7] + 206;"
          calcs += "^b[11] &= 0xFF;"
        } else {
          calcs += "^b[12] ^= (b[1] + b[18] + b[36] + b[13] + b[14] + b[33] + 207) & 0xFF;"
        }
        state = 962184579;
        continue;
      case 333278516:
        if (Math.random() < 0.5) {
          calcs += "^b[11] -= b[4] + b[37] + b[2] + b[32] + b[5] + b[1] + 102;"
          calcs += "^b[11] &= 0xFF;"
        } else {
          calcs += "^b[13] -= b[7] + b[18] + b[41] + b[2] + b[31] + b[3] + 214;"
          calcs += "^b[13] &= 0xFF;"
        }
        state = 573116411;
        continue;
      case 333327748:
        if (Math.random() < 0.5) {
          calcs += "^b[39] += b[37] + b[17] + b[14] + b[5] + b[10] + b[34] + 198;"
          calcs += "^b[39] &= 0xFF;"
        } else {
          calcs += "^b[16] ^= (b[11] + b[33] + b[22] + b[7] + b[0] + b[29] + " + Math.floor(Math.random() * 256) + ") & 0xFF;"
        }
        state = 503956735;
        continue;
      case 333413964:
        if (Math.random() < 0.5) {
          calcs += "^b[1] += b[13] + b[35] + b[18] + b[2] + b[5] + b[21] + 159;"
          calcs += "^b[1] &= 0xFF;"
        } else {
          calcs += "^b[2] += b[26] + b[41] + b[35] + b[1] + b[18] + b[34] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[2] &= 0xFF;"
        }
        state = 743277227;
        continue;
      case 333723469:
        if (311653695) {
          calcs += "^b[13] -= b[40] + b[43] + b[26] + b[38] + b[31] + b[41] + 77;"
          calcs += "^b[13] &= 0xFF;"
        } else {
          calcs += "^b[32] ^= (b[28] + b[16] + b[41] + b[36] + b[22] + b[33] + 146) & 0xFF;"
        }
        state = 681620340;
        continue;
      case 336652146:
        if (64507966n) {
          calcs += "^b[7] -= b[14] + b[33] + b[30] + b[6] + b[31] + b[16] + 185;"
          calcs += "^b[7] &= 0xFF;"
        } else {
          calcs += "^b[26] += b[23] + b[30] + b[43] + b[13] + b[20] + b[24] + 124;"
          calcs += "^b[26] &= 0xFF;"
        }
        state = 700219153;
        continue;
      case 337528737:
        if (65777729n) {
          calcs += "^b[31] -= b[4] + b[32] + b[10] + b[39] + b[37] + b[13] + 28;"
          calcs += "^b[31] &= 0xFF;"
        } else {
          calcs += "^b[11] += b[15] + b[21] + b[35] + b[19] + b[42] + b[24] + 152;"
          calcs += "^b[11] &= 0xFF;"
        }
        state = 444449293;
        continue;
      case 337619620:
        if (844294543) {
          calcs += "^b[32] ^= (b[0] + b[27] + b[39] + b[15] + b[24] + b[5] + 129) & 0xFF;"
        } else {
          calcs += "^b[34] -= b[21] + b[5] + b[41] + b[10] + b[24] + b[38] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[34] &= 0xFF;"
        }
        state = 648181894;
        continue;
      case 338410070:
        if (Math.random() < 0.5) {
          calcs += "^b[20] ^= (b[15] + b[7] + b[21] + b[26] + b[41] + b[9] + 93) & 0xFF;"
        } else {
          calcs += "^b[25] += b[29] + b[8] + b[18] + b[33] + b[23] + b[10] + 43;"
          calcs += "^b[25] &= 0xFF;"
        }
        state = 876061876;
        continue;
      case 338972092:
        if (488876856) {
          calcs += "^b[2] -= b[21] + b[17] + b[14] + b[7] + b[40] + b[1] + 191;"
          calcs += "^b[2] &= 0xFF;"
        } else {
          calcs += "^b[16] ^= (b[31] + b[22] + b[41] + b[14] + b[35] + b[37] + 74) & 0xFF;"
        }
        state = 750227539;
        continue;
      case 340838771:
        if (65067412n) {
          calcs += "^b[35] ^= (b[34] + b[36] + b[8] + b[19] + b[3] + b[14] + 74) & 0xFF;"
        } else {
          calcs += "^b[41] -= b[31] + b[25] + b[7] + b[36] + b[4] + b[1] + 33;"
          calcs += "^b[41] &= 0xFF;"
        }
        state = 1054455207;
        continue;
      case 340943616:
        if (480735617) {
          calcs += "^b[20] ^= (b[24] + b[21] + b[39] + b[27] + b[8] + b[32] + 168) & 0xFF;"
        } else {
          calcs += "^b[28] += b[0] + b[23] + b[14] + b[16] + b[20] + b[25] + 31;"
          calcs += "^b[28] &= 0xFF;"
        }
        state = 943639861;
        continue;
      case 343068132:
        if (Math.random() < 0.5) {
          calcs += "^b[43] += b[13] + b[27] + b[15] + b[12] + b[6] + b[5] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[43] &= 0xFF;"
        } else {
          calcs += "^b[43] += b[22] + b[29] + b[16] + b[28] + b[12] + b[38] + 87;"
          calcs += "^b[43] &= 0xFF;"
        }
        state = 604380114;
        continue;
      case 344569583:
        if (13706660n) {
          calcs += "^b[13] ^= (b[32] + b[35] + b[10] + b[16] + b[40] + b[22] + 187) & 0xFF;"
        } else {
          calcs += "^b[42] -= b[16] + b[0] + b[32] + b[23] + b[2] + b[24] + 228;"
          calcs += "^b[42] &= 0xFF;"
        }
        state = 55662707;
        continue;
      case 345294165:
        if (99319925n) {
          calcs += "^b[6] -= b[23] + b[39] + b[7] + b[22] + b[26] + b[21] + 223;"
          calcs += "^b[6] &= 0xFF;"
        } else {
          calcs += "^b[38] += b[43] + b[17] + b[14] + b[27] + b[0] + b[22] + 167;"
          calcs += "^b[38] &= 0xFF;"
        }
        state = 973059351;
        continue;
      case 345615088:
        if (100997494) {
          calcs += "^b[35] += b[23] + b[9] + b[20] + b[18] + b[42] + b[0] + 40;"
          calcs += "^b[35] &= 0xFF;"
        } else {
          calcs += "^b[41] ^= (b[17] + b[25] + b[9] + b[42] + b[36] + b[10] + 170) & 0xFF;"
        }
        state = 1050414580;
        continue;
      case 345757846:
        if (Math.random() < 0.5) {
          calcs += "^b[8] ^= (b[33] + b[32] + b[39] + b[12] + b[20] + b[7] + 34) & 0xFF;"
        } else {
          calcs += "^b[17] ^= (b[4] + b[29] + b[21] + b[43] + b[13] + b[3] + 100) & 0xFF;"
        }
        state = 324216333;
        continue;
      case 346115220:
        if (953618142) {
          calcs += "^b[6] ^= (b[35] + b[20] + b[32] + b[22] + b[24] + b[14] + 156) & 0xFF;"
        } else {
          calcs += "^b[28] += b[36] + b[26] + b[17] + b[5] + b[1] + b[13] + 245;"
          calcs += "^b[28] &= 0xFF;"
        }
        state = 1050865314;
        continue;
      case 346310778:
        if (26889902n) {
          calcs += "^b[21] -= b[40] + b[1] + b[9] + b[38] + b[34] + b[25] + 186;"
          calcs += "^b[21] &= 0xFF;"
        } else {
          calcs += "^b[36] -= b[2] + b[23] + b[8] + b[28] + b[19] + b[34] + 235;"
          calcs += "^b[36] &= 0xFF;"
        }
        state = 788772522;
        continue;
      case 346377456:
        if (Math.random() < 0.5) {
          calcs += "^b[34] -= b[41] + b[14] + b[13] + b[20] + b[17] + b[7] + 29;"
          calcs += "^b[34] &= 0xFF;"
        } else {
          calcs += "^b[28] -= b[22] + b[43] + b[36] + b[25] + b[16] + b[12] + 102;"
          calcs += "^b[28] &= 0xFF;"
        }
        state = 398388097;
        continue;
      case 347190308:
        if (Math.random() < 0.5) {
          calcs += "^b[40] += b[16] + b[24] + b[12] + b[5] + b[26] + b[38] + 53;"
          calcs += "^b[40] &= 0xFF;"
        } else {
          calcs += "^b[34] += b[9] + b[24] + b[14] + b[5] + b[40] + b[7] + 158;"
          calcs += "^b[34] &= 0xFF;"
        }
        state = 916116227;
        continue;
      case 348173505:
        if (593370103) {
          calcs += "^b[16] -= b[10] + b[42] + b[23] + b[38] + b[2] + b[28] + 182;"
          calcs += "^b[16] &= 0xFF;"
        } else {
          calcs += "^b[28] += b[12] + b[26] + b[3] + b[22] + b[41] + b[36] + 178;"
          calcs += "^b[28] &= 0xFF;"
        }
        state = 902345362;
        continue;
      case 351641283:
        if (839941505) {
          calcs += "^b[32] += b[26] + b[29] + b[36] + b[9] + b[42] + b[4] + 155;"
          calcs += "^b[32] &= 0xFF;"
        } else {
          calcs += "^b[10] -= b[23] + b[32] + b[37] + b[28] + b[39] + b[21] + 233;"
          calcs += "^b[10] &= 0xFF;"
        }
        state = 859857603;
        continue;
      case 353246766:
        if (Math.random() < 0.5) {
          calcs += "^b[32] += b[7] + b[36] + b[14] + b[0] + b[10] + b[31] + 104;"
          calcs += "^b[32] &= 0xFF;"
        } else {
          calcs += "^b[12] -= b[23] + b[2] + b[10] + b[5] + b[30] + b[27] + 195;"
          calcs += "^b[12] &= 0xFF;"
        }
        state = 931163953;
        continue;
      case 354670641:
        if (890018195) {
          calcs += "^b[37] -= b[36] + b[43] + b[1] + b[7] + b[28] + b[9] + 48;"
          calcs += "^b[37] &= 0xFF;"
        } else {
          calcs += "^b[22] -= b[21] + b[32] + b[36] + b[31] + b[33] + b[12] + 209;"
          calcs += "^b[22] &= 0xFF;"
        }
        state = 940005195;
        continue;
      case 355872836:
        if (660850287) {
          calcs += "^b[15] += b[21] + b[24] + b[0] + b[8] + b[23] + b[11] + 177;"
          calcs += "^b[15] &= 0xFF;"
        } else {
          calcs += "^b[22] ^= (b[32] + b[13] + b[42] + b[12] + b[33] + b[25] + 4) & 0xFF;"
        }
        state = 839318347;
        continue;
      case 355878506:
        if (36769050n) {
          calcs += "^b[6] ^= (b[41] + b[28] + b[20] + b[36] + b[40] + b[13] + 212) & 0xFF;"
        } else {
          calcs += "^b[2] ^= (b[12] + b[11] + b[39] + b[31] + b[43] + b[36] + " + Math.floor(Math.random() * 256) + ") & 0xFF;"
        }
        state = 899648181;
        continue;
      case 356968013:
        if (86808995n) {
          calcs += "^b[25] -= b[42] + b[24] + b[41] + b[14] + b[36] + b[17] + 58;"
          calcs += "^b[25] &= 0xFF;"
        } else {
          calcs += "^b[2] ^= (b[35] + b[18] + b[25] + b[39] + b[23] + b[14] + 230) & 0xFF;"
        }
        state = 308945835;
        continue;
      case 357341428:
        if (29320591n) {
          calcs += "^b[35] ^= (b[2] + b[18] + b[4] + b[1] + b[24] + b[21] + 103) & 0xFF;"
        } else {
          calcs += "^b[14] ^= (b[0] + b[21] + b[12] + b[31] + b[11] + b[5] + " + Math.floor(Math.random() * 256) + ") & 0xFF;"
        }
        state = 206476859;
        continue;
      case 358432243:
        if (Math.random() < 0.5) {
          calcs += "^b[38] -= b[16] + b[22] + b[43] + b[11] + b[13] + b[5] + 23;"
          calcs += "^b[38] &= 0xFF;"
        } else {
          calcs += "^b[23] += b[7] + b[30] + b[27] + b[35] + b[43] + b[10] + 164;"
          calcs += "^b[23] &= 0xFF;"
        }
        state = 620986063;
        continue;
      case 364059800:
        if (439881210) {
          calcs += "^b[14] -= b[18] + b[24] + b[22] + b[32] + b[41] + b[9] + 6;"
          calcs += "^b[14] &= 0xFF;"
        } else {
          calcs += "^b[15] -= b[25] + b[43] + b[8] + b[19] + b[42] + b[36] + 163;"
          calcs += "^b[15] &= 0xFF;"
        }
        state = 637537818;
        continue;
      case 365857434:
        if (Math.random() < 0.5) {
          calcs += "^b[18] -= b[14] + b[23] + b[13] + b[37] + b[20] + b[32] + 70;"
          calcs += "^b[18] &= 0xFF;"
        } else {
          calcs += "^b[7] ^= (b[41] + b[42] + b[5] + b[39] + b[33] + b[18] + " + Math.floor(Math.random() * 256) + ") & 0xFF;"
        }
        state = 306782152;
        continue;
      case 366327144:
        if (60557216n) {
          calcs += "^b[9] += b[27] + b[39] + b[31] + b[43] + b[22] + b[28] + 229;"
          calcs += "^b[9] &= 0xFF;"
        } else {
          calcs += "^b[23] ^= (b[28] + b[0] + b[14] + b[1] + b[18] + b[17] + 45) & 0xFF;"
        }
        state = 159027065;
        continue;
      case 376132195:
        if (39731571n) {
          calcs += "^b[7] ^= (b[10] + b[16] + b[2] + b[11] + b[13] + b[33] + 131) & 0xFF;"
        } else {
          calcs += "^b[41] -= b[27] + b[6] + b[15] + b[42] + b[7] + b[17] + 162;"
          calcs += "^b[41] &= 0xFF;"
        }
        state = 467271741;
        continue;
      case 376310042:
        if (Math.random() < 0.5) {
          calcs += "^b[40] ^= (b[35] + b[9] + b[27] + b[28] + b[3] + b[36] + 118) & 0xFF;"
        } else {
          calcs += "^b[6] -= b[2] + b[41] + b[37] + b[12] + b[14] + b[33] + 57;"
          calcs += "^b[6] &= 0xFF;"
        }
        state = 1005231032;
        continue;
      case 376455206:
        if (Math.random() < 0.5) {
          calcs += "^b[34] += b[32] + b[5] + b[20] + b[17] + b[15] + b[19] + 25;"
          calcs += "^b[34] &= 0xFF;"
        } else {
          calcs += "^b[17] -= b[16] + b[43] + b[31] + b[15] + b[41] + b[21] + 248;"
          calcs += "^b[17] &= 0xFF;"
        }
        state = 488570004;
        continue;
      case 377623173:
        if (Math.random() < 0.5) {
          calcs += "^b[25] ^= (b[10] + b[19] + b[34] + b[40] + b[12] + b[6] + " + Math.floor(Math.random() * 256) + ") & 0xFF;"
        } else {
          calcs += "^b[30] ^= (b[19] + b[9] + b[25] + b[11] + b[18] + b[23] + 2) & 0xFF;"
        }
        state = 793835102;
        continue;
      case 377916788:
        if (922263820) {
          calcs += "^b[8] ^= (b[32] + b[26] + b[21] + b[1] + b[30] + b[41] + 172) & 0xFF;"
        } else {
          calcs += "^b[32] += b[42] + b[43] + b[34] + b[17] + b[5] + b[0] + 94;"
          calcs += "^b[32] &= 0xFF;"
        }
        state = 735781200;
        continue;
      case 379529415:
        if (31575299n) {
          calcs += "^b[24] -= b[1] + b[6] + b[28] + b[4] + b[13] + b[9] + 56;"
          calcs += "^b[24] &= 0xFF;"
        } else {
          calcs += "^b[42] -= b[26] + b[43] + b[0] + b[21] + b[4] + b[20] + 173;"
          calcs += "^b[42] &= 0xFF;"
        }
        state = 54757828;
        continue;
      case 381813752:
        if (Math.random() < 0.5) {
          calcs += "^b[25] ^= (b[6] + b[43] + b[29] + b[27] + b[13] + b[14] + " + Math.floor(Math.random() * 256) + ") & 0xFF;"
        } else {
          calcs += "^b[16] += b[42] + b[29] + b[25] + b[0] + b[12] + b[26] + 92;"
          calcs += "^b[16] &= 0xFF;"
        }
        state = 958508071;
        continue;
      case 382922372:
        if (Math.random() < 0.5) {
          calcs += "^b[27] ^= (b[39] + b[14] + b[33] + b[22] + b[6] + b[28] + " + Math.floor(Math.random() * 256) + ") & 0xFF;"
        } else {
          calcs += "^b[22] += b[21] + b[29] + b[9] + b[38] + b[20] + b[18] + 213;"
          calcs += "^b[22] &= 0xFF;"
        }
        state = 15866745;
        continue;
      case 383403877:
        if (Math.random() < 0.5) {
          calcs += "^b[42] ^= (b[20] + b[38] + b[37] + b[12] + b[35] + b[41] + " + Math.floor(Math.random() * 256) + ") & 0xFF;"
        } else {
          calcs += "^b[32] -= b[29] + b[31] + b[24] + b[43] + b[12] + b[20] + 249;"
          calcs += "^b[32] &= 0xFF;"
        }
        state = 1058982649;
        continue;
      case 384516053:
        if (354815298) {
          calcs += "^b[18] += b[24] + b[0] + b[3] + b[13] + b[30] + b[22] + 34;"
          calcs += "^b[18] &= 0xFF;"
        } else {
          calcs += "^b[1] -= b[27] + b[4] + b[7] + b[21] + b[32] + b[31] + 165;"
          calcs += "^b[1] &= 0xFF;"
        }
        state = 735087160;
        continue;
      case 387100740:
        if (Math.random() < 0.5) {
          calcs += "^b[35] ^= (b[20] + b[41] + b[32] + b[8] + b[24] + b[11] + 111) & 0xFF;"
        } else {
          calcs += "^b[18] ^= (b[9] + b[21] + b[4] + b[2] + b[42] + b[5] + 103) & 0xFF;"
        }
        state = 718864653;
        continue;
      case 387974948:
        if (Math.random() < 0.5) {
          calcs += "^b[21] -= b[18] + b[13] + b[28] + b[31] + b[26] + b[29] + 93;"
          calcs += "^b[21] &= 0xFF;"
        } else {
          calcs += "^b[36] += b[30] + b[3] + b[32] + b[37] + b[24] + b[18] + 148;"
          calcs += "^b[36] &= 0xFF;"
        }
        state = 829863547;
        continue;
      case 388219024:
        if (66330494n) {
          calcs += "^b[13] ^= (b[37] + b[21] + b[22] + b[23] + b[31] + b[26] + 247) & 0xFF;"
        } else {
          calcs += "^b[4] -= b[9] + b[31] + b[41] + b[21] + b[8] + b[5] + 215;"
          calcs += "^b[4] &= 0xFF;"
        }
        state = 798136234;
        continue;
      case 388611681:
        if (942571809) {
          calcs += "^b[5] -= b[14] + b[0] + b[43] + b[41] + b[10] + b[20] + 219;"
          calcs += "^b[5] &= 0xFF;"
        } else {
          calcs += "^b[43] += b[40] + b[23] + b[21] + b[26] + b[6] + b[33] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[43] &= 0xFF;"
        }
        state = 116844593;
        continue;
      case 390035647:
        if (88803738n) {
          calcs += "^b[31] += b[42] + b[30] + b[1] + b[20] + b[40] + b[18] + 198;"
          calcs += "^b[31] &= 0xFF;"
        } else {
          calcs += "^b[15] += b[23] + b[8] + b[4] + b[38] + b[37] + b[29] + 82;"
          calcs += "^b[15] &= 0xFF;"
        }
        state = 1036870181;
        continue;
      case 391748300:
        if (892824005) {
          calcs += "^b[16] += b[21] + b[33] + b[35] + b[22] + b[31] + b[13] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[16] &= 0xFF;"
        } else {
          calcs += "^b[16] -= b[32] + b[4] + b[31] + b[8] + b[29] + b[14] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[16] &= 0xFF;"
        }
        state = 865534450;
        continue;
      case 392984751:
        if (620312508) {
          calcs += "^b[12] -= b[10] + b[26] + b[6] + b[19] + b[23] + b[41] + 127;"
          calcs += "^b[12] &= 0xFF;"
        } else {
          calcs += "^b[13] ^= (b[8] + b[22] + b[33] + b[29] + b[5] + b[17] + 167) & 0xFF;"
        }
        state = 853233897;
        continue;
      case 393219787:
        if (919953243) {
          calcs += "^b[3] ^= (b[19] + b[40] + b[12] + b[27] + b[8] + b[18] + 67) & 0xFF;"
        } else {
          calcs += "^b[30] -= b[6] + b[14] + b[28] + b[29] + b[24] + b[15] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[30] &= 0xFF;"
        }
        state = 231414023;
        continue;
      case 394460282:
        if (31684156n) {
          calcs += "^b[15] -= b[36] + b[16] + b[25] + b[33] + b[21] + b[43] + 226;"
          calcs += "^b[15] &= 0xFF;"
        } else {
          calcs += "^b[28] += b[40] + b[23] + b[20] + b[36] + b[22] + b[27] + 232;"
          calcs += "^b[28] &= 0xFF;"
        }
        state = 120145493;
        continue;
      case 394802322:
        if (67677057n) {
          calcs += "^b[36] ^= (b[40] + b[22] + b[17] + b[27] + b[0] + b[39] + " + Math.floor(Math.random() * 256) + ") & 0xFF;"
        } else {
          calcs += "^b[2] -= b[15] + b[41] + b[7] + b[29] + b[23] + b[24] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[2] &= 0xFF;"
        }
        state = 336616975;
        continue;
      case 395862207:
        if (638293354) {
          calcs += "^b[16] += b[17] + b[3] + b[38] + b[9] + b[11] + b[6] + 27;"
          calcs += "^b[16] &= 0xFF;"
        } else {
          calcs += "^b[9] += b[1] + b[10] + b[23] + b[22] + b[37] + b[21] + 129;"
          calcs += "^b[9] &= 0xFF;"
        }
        state = 907324772;
        continue;
      case 397157371:
        if (33892584n) {
          calcs += "^b[43] += b[28] + b[14] + b[12] + b[40] + b[16] + b[39] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[43] &= 0xFF;"
        } else {
          calcs += "^b[18] -= b[38] + b[20] + b[16] + b[24] + b[34] + b[26] + 49;"
          calcs += "^b[18] &= 0xFF;"
        }
        state = 165366900;
        continue;
      case 399226168:
        if (218386278) {
          calcs += "^b[5] ^= (b[41] + b[0] + b[39] + b[18] + b[23] + b[14] + 22) & 0xFF;"
        } else {
          calcs += "^b[16] ^= (b[41] + b[35] + b[32] + b[27] + b[42] + b[43] + 137) & 0xFF;"
        }
        state = 300948554;
        continue;
      case 400398773:
        if (Math.random() < 0.5) {
          calcs += "^b[9] += b[26] + b[20] + b[29] + b[25] + b[6] + b[12] + 183;"
          calcs += "^b[9] &= 0xFF;"
        } else {
          calcs += "^b[29] ^= (b[41] + b[39] + b[15] + b[0] + b[19] + b[12] + 213) & 0xFF;"
        }
        state = 419219886;
        continue;
      case 402456529:
        if (63651937n) {
          calcs += "^b[24] ^= (b[42] + b[18] + b[35] + b[2] + b[41] + b[27] + 91) & 0xFF;"
        } else {
          calcs += "^b[36] += b[30] + b[26] + b[3] + b[37] + b[4] + b[28] + 207;"
          calcs += "^b[36] &= 0xFF;"
        }
        state = 537912203;
        continue;
      case 402768593:
        if (365193231) {
          calcs += "^b[11] ^= (b[7] + b[28] + b[16] + b[9] + b[5] + b[10] + 36) & 0xFF;"
        } else {
          calcs += "^b[17] += b[18] + b[4] + b[15] + b[34] + b[16] + b[31] + 215;"
          calcs += "^b[17] &= 0xFF;"
        }
        state = 603034106;
        continue;
      case 406937840:
        if (Math.random() < 0.5) {
          calcs += "^b[11] += b[17] + b[25] + b[9] + b[2] + b[34] + b[18] + 115;"
          calcs += "^b[11] &= 0xFF;"
        } else {
          calcs += "^b[13] ^= (b[37] + b[3] + b[36] + b[17] + b[12] + b[2] + " + Math.floor(Math.random() * 256) + ") & 0xFF;"
        }
        state = 48873310;
        continue;
      case 407028537:
        if (351206548) {
          calcs += "^b[13] -= b[22] + b[14] + b[39] + b[9] + b[36] + b[4] + 212;"
          calcs += "^b[13] &= 0xFF;"
        } else {
          calcs += "^b[27] += b[16] + b[5] + b[12] + b[2] + b[43] + b[20] + 84;"
          calcs += "^b[27] &= 0xFF;"
        }
        state = 847042938;
        continue;
      case 408646337:
        if (60744659n) {
          calcs += "^b[6] ^= (b[2] + b[9] + b[16] + b[5] + b[10] + b[12] + 37) & 0xFF;"
        } else {
          calcs += "^b[28] ^= (b[8] + b[39] + b[18] + b[25] + b[13] + b[17] + 172) & 0xFF;"
        }
        state = 638885455;
        continue;
      case 409252293:
        if (52905300n) {
          calcs += "^b[22] ^= (b[6] + b[32] + b[27] + b[2] + b[13] + b[3] + 191) & 0xFF;"
        } else {
          calcs += "^b[31] += b[10] + b[28] + b[13] + b[1] + b[38] + b[12] + 162;"
          calcs += "^b[31] &= 0xFF;"
        }
        state = 514932023;
        continue;
      case 410002593:
        if (1050330741) {
          calcs += "^b[24] -= b[41] + b[11] + b[43] + b[26] + b[16] + b[42] + 156;"
          calcs += "^b[24] &= 0xFF;"
        } else {
          calcs += "^b[39] -= b[18] + b[28] + b[42] + b[40] + b[2] + b[11] + 91;"
          calcs += "^b[39] &= 0xFF;"
        }
        state = 316775632;
        continue;
      case 410332197:
        if (Math.random() < 0.5) {
          calcs += "^b[31] += b[21] + b[35] + b[22] + b[17] + b[7] + b[0] + 20;"
          calcs += "^b[31] &= 0xFF;"
        } else {
          calcs += "^b[15] ^= (b[30] + b[3] + b[18] + b[31] + b[27] + b[8] + 92) & 0xFF;"
        }
        state = 207481335;
        continue;
      case 410802044:
        if (11042713n) {
          calcs += "^b[3] ^= (b[14] + b[26] + b[33] + b[17] + b[32] + b[1] + 230) & 0xFF;"
        } else {
          calcs += "^b[42] ^= (b[20] + b[31] + b[38] + b[36] + b[0] + b[19] + " + Math.floor(Math.random() * 256) + ") & 0xFF;"
        }
        state = 936452181;
        continue;
      case 410923009:
        if (679203260) {
          calcs += "^b[34] += b[1] + b[41] + b[13] + b[30] + b[17] + b[33] + 42;"
          calcs += "^b[34] &= 0xFF;"
        } else {
          calcs += "^b[40] += b[39] + b[38] + b[24] + b[20] + b[1] + b[9] + 228;"
          calcs += "^b[40] &= 0xFF;"
        }
        state = 939859661;
        continue;
      case 412251143:
        if (62372014n) {
          calcs += "^b[11] -= b[26] + b[43] + b[14] + b[4] + b[30] + b[8] + 96;"
          calcs += "^b[11] &= 0xFF;"
        } else {
          calcs += "^b[36] += b[33] + b[13] + b[26] + b[27] + b[5] + b[24] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[36] &= 0xFF;"
        }
        state = 490551708;
        continue;
      case 412918289:
        if (808576349) {
          calcs += "^b[38] += b[22] + b[8] + b[3] + b[10] + b[7] + b[35] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[38] &= 0xFF;"
        } else {
          calcs += "^b[37] -= b[3] + b[31] + b[12] + b[28] + b[41] + b[2] + 222;"
          calcs += "^b[37] &= 0xFF;"
        }
        state = 356129539;
        continue;
      case 413054705:
        if (262554705) {
          calcs += "^b[21] -= b[24] + b[31] + b[10] + b[2] + b[22] + b[40] + 179;"
          calcs += "^b[21] &= 0xFF;"
        } else {
          calcs += "^b[23] -= b[22] + b[15] + b[20] + b[10] + b[37] + b[33] + 163;"
          calcs += "^b[23] &= 0xFF;"
        }
        state = 862239116;
        continue;
      case 413338388:
        if (Math.random() < 0.5) {
          calcs += "^b[19] -= b[38] + b[6] + b[28] + b[33] + b[39] + b[43] + 139;"
          calcs += "^b[19] &= 0xFF;"
        } else {
          calcs += "^b[19] ^= (b[0] + b[35] + b[14] + b[30] + b[21] + b[33] + 213) & 0xFF;"
        }
        state = 925193711;
        continue;
      case 413708432:
        if (Math.random() < 0.5) {
          calcs += "^b[18] += b[4] + b[9] + b[3] + b[12] + b[26] + b[1] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[18] &= 0xFF;"
        } else {
          calcs += "^b[11] += b[40] + b[33] + b[34] + b[28] + b[24] + b[35] + 172;"
          calcs += "^b[11] &= 0xFF;"
        }
        state = 938456085;
        continue;
      case 414443906:
        if (Math.random() < 0.5) {
          calcs += "^b[33] -= b[5] + b[41] + b[16] + b[32] + b[35] + b[36] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[33] &= 0xFF;"
        } else {
          calcs += "^b[29] ^= (b[37] + b[1] + b[15] + b[38] + b[8] + b[7] + 123) & 0xFF;"
        }
        state = 596977915;
        continue;
      case 414456846:
        if (13208116n) {
          calcs += "^b[6] -= b[30] + b[29] + b[14] + b[35] + b[15] + b[20] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[6] &= 0xFF;"
        } else {
          calcs += "^b[21] += b[13] + b[41] + b[19] + b[12] + b[34] + b[39] + 10;"
          calcs += "^b[21] &= 0xFF;"
        }
        state = 971106962;
        continue;
      case 415110917:
        if (971641145) {
          calcs += "^b[33] += b[13] + b[20] + b[16] + b[17] + b[24] + b[6] + 192;"
          calcs += "^b[33] &= 0xFF;"
        } else {
          calcs += "^b[35] += b[18] + b[17] + b[30] + b[15] + b[21] + b[6] + 215;"
          calcs += "^b[35] &= 0xFF;"
        }
        state = 274895311;
        continue;
      case 418085472:
        if (449660790) {
          calcs += "^b[42] -= b[35] + b[40] + b[1] + b[29] + b[30] + b[15] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[42] &= 0xFF;"
        } else {
          calcs += "^b[13] -= b[33] + b[28] + b[19] + b[27] + b[6] + b[12] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[13] &= 0xFF;"
        }
        state = 445117433;
        continue;
      case 419650888:
        if (804235477) {
          calcs += "^b[8] -= b[10] + b[37] + b[20] + b[15] + b[31] + b[38] + 146;"
          calcs += "^b[8] &= 0xFF;"
        } else {
          calcs += "^b[26] ^= (b[33] + b[15] + b[20] + b[37] + b[5] + b[36] + 78) & 0xFF;"
        }
        state = 369689767;
        continue;
      case 419988815:
        if (51896074n) {
          calcs += "^b[41] ^= (b[10] + b[17] + b[0] + b[1] + b[40] + b[5] + 80) & 0xFF;"
        } else {
          calcs += "^b[16] ^= (b[10] + b[37] + b[38] + b[27] + b[6] + b[18] + 208) & 0xFF;"
        }
        state = 723179055;
        continue;
      case 420148501:
        if (Math.random() < 0.5) {
          calcs += "^b[20] -= b[1] + b[8] + b[9] + b[32] + b[25] + b[0] + 58;"
          calcs += "^b[20] &= 0xFF;"
        } else {
          calcs += "^b[38] -= b[24] + b[23] + b[36] + b[32] + b[7] + b[2] + 136;"
          calcs += "^b[38] &= 0xFF;"
        }
        state = 931323440;
        continue;
      case 421002955:
        if (Math.random() < 0.5) {
          calcs += "^b[43] -= b[16] + b[1] + b[14] + b[32] + b[30] + b[7] + 150;"
          calcs += "^b[43] &= 0xFF;"
        } else {
          calcs += "^b[20] += b[3] + b[12] + b[40] + b[43] + b[15] + b[28] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[20] &= 0xFF;"
        }
        state = 346979242;
        continue;
      case 421677992:
        if (610991075) {
          calcs += "^b[30] -= b[17] + b[16] + b[2] + b[28] + b[3] + b[1] + 94;"
          calcs += "^b[30] &= 0xFF;"
        } else {
          calcs += "^b[43] += b[35] + b[40] + b[41] + b[36] + b[10] + b[39] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[43] &= 0xFF;"
        }
        state = 11258425;
        continue;
      case 422010113:
        if (14463569n) {
          calcs += "^b[11] += b[28] + b[17] + b[40] + b[37] + b[1] + b[0] + 45;"
          calcs += "^b[11] &= 0xFF;"
        } else {
          calcs += "^b[35] += b[13] + b[21] + b[32] + b[1] + b[10] + b[43] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[35] &= 0xFF;"
        }
        state = 207711035;
        continue;
      case 422356995:
        if (Math.random() < 0.5) {
          calcs += "^b[7] -= b[41] + b[40] + b[13] + b[19] + b[17] + b[38] + 45;"
          calcs += "^b[7] &= 0xFF;"
        } else {
          calcs += "^b[33] += b[2] + b[5] + b[23] + b[14] + b[19] + b[38] + 175;"
          calcs += "^b[33] &= 0xFF;"
        }
        state = 151665240;
        continue;
      case 425518304:
        if (27257617n) {
          calcs += "^b[27] -= b[17] + b[9] + b[20] + b[16] + b[38] + b[24] + 60;"
          calcs += "^b[27] &= 0xFF;"
        } else {
          calcs += "^b[43] -= b[18] + b[14] + b[4] + b[20] + b[40] + b[27] + 107;"
          calcs += "^b[43] &= 0xFF;"
        }
        state = 17949248;
        continue;
      case 425700802:
        if (614470116) {
          calcs += "^b[11] ^= (b[34] + b[13] + b[36] + b[15] + b[5] + b[40] + 60) & 0xFF;"
        } else {
          calcs += "^b[11] -= b[32] + b[8] + b[9] + b[34] + b[39] + b[19] + 185;"
          calcs += "^b[11] &= 0xFF;"
        }
        state = 417303028;
        continue;
      case 425993177:
        if (Math.random() < 0.5) {
          calcs += "^b[8] -= b[5] + b[14] + b[0] + b[11] + b[36] + b[35] + 211;"
          calcs += "^b[8] &= 0xFF;"
        } else {
          calcs += "^b[3] += b[5] + b[18] + b[10] + b[14] + b[43] + b[31] + 44;"
          calcs += "^b[3] &= 0xFF;"
        }
        state = 801284520;
        continue;
      case 426062705:
        if (Math.random() < 0.5) {
          calcs += "^b[21] += b[1] + b[30] + b[36] + b[43] + b[3] + b[25] + 219;"
          calcs += "^b[21] &= 0xFF;"
        } else {
          calcs += "^b[43] += b[4] + b[19] + b[16] + b[36] + b[35] + b[25] + 198;"
          calcs += "^b[43] &= 0xFF;"
        }
        state = 465688620;
        continue;
      case 427112169:
        if (62515986n) {
          calcs += "^b[41] ^= (b[5] + b[16] + b[21] + b[17] + b[19] + b[15] + 187) & 0xFF;"
        } else {
          calcs += "^b[15] -= b[26] + b[41] + b[19] + b[24] + b[21] + b[20] + 77;"
          calcs += "^b[15] &= 0xFF;"
        }
        state = 998851471;
        continue;
      case 429116243:
        if (449857890) {
          calcs += "^b[29] ^= (b[40] + b[43] + b[24] + b[3] + b[35] + b[42] + 27) & 0xFF;"
        } else {
          calcs += "^b[9] -= b[20] + b[19] + b[22] + b[5] + b[32] + b[35] + 151;"
          calcs += "^b[9] &= 0xFF;"
        }
        state = 929475057;
        continue;
      case 430915810:
        if (33047836n) {
          calcs += "^b[14] -= b[24] + b[16] + b[41] + b[28] + b[34] + b[5] + 255;"
          calcs += "^b[14] &= 0xFF;"
        } else {
          calcs += "^b[10] += b[12] + b[31] + b[35] + b[29] + b[19] + b[4] + 153;"
          calcs += "^b[10] &= 0xFF;"
        }
        state = 504733291;
        continue;
      case 431298389:
        if (20560274n) {
          calcs += "^b[20] ^= (b[34] + b[23] + b[21] + b[0] + b[25] + b[12] + 14) & 0xFF;"
        } else {
          calcs += "^b[42] -= b[5] + b[27] + b[38] + b[26] + b[41] + b[21] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[42] &= 0xFF;"
        }
        state = 434234745;
        continue;
      case 432599280:
        if (Math.random() < 0.5) {
          calcs += "^b[29] += b[6] + b[10] + b[31] + b[4] + b[19] + b[5] + 135;"
          calcs += "^b[29] &= 0xFF;"
        } else {
          calcs += "^b[26] -= b[8] + b[3] + b[27] + b[28] + b[6] + b[34] + 7;"
          calcs += "^b[26] &= 0xFF;"
        }
        state = 716406816;
        continue;
      case 432794620:
        if (Math.random() < 0.5) {
          calcs += "^b[27] ^= (b[17] + b[13] + b[28] + b[12] + b[24] + b[3] + 116) & 0xFF;"
        } else {
          calcs += "^b[20] ^= (b[39] + b[22] + b[2] + b[27] + b[3] + b[28] + 218) & 0xFF;"
        }
        state = 449054072;
        continue;
      case 433190983:
        if (Math.random() < 0.5) {
          calcs += "^b[43] -= b[28] + b[41] + b[5] + b[32] + b[36] + b[1] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[43] &= 0xFF;"
        } else {
          calcs += "^b[31] += b[4] + b[21] + b[19] + b[27] + b[37] + b[33] + 251;"
          calcs += "^b[31] &= 0xFF;"
        }
        state = 225013121;
        continue;
      case 435026594:
        if (37718035n) {
          calcs += "^b[4] ^= (b[16] + b[43] + b[41] + b[8] + b[3] + b[37] + 224) & 0xFF;"
        } else {
          calcs += "^b[19] += b[27] + b[15] + b[21] + b[26] + b[31] + b[33] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[19] &= 0xFF;"
        }
        state = 479609427;
        continue;
      case 435082171:
        if (432348810) {
          calcs += "^b[28] ^= (b[15] + b[8] + b[22] + b[33] + b[23] + b[9] + 195) & 0xFF;"
        } else {
          calcs += "^b[10] += b[5] + b[31] + b[18] + b[9] + b[24] + b[27] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[10] &= 0xFF;"
        }
        state = 716798066;
        continue;
      case 436308333:
        if (637554787) {
          calcs += "^b[41] -= b[5] + b[2] + b[39] + b[30] + b[20] + b[33] + 189;"
          calcs += "^b[41] &= 0xFF;"
        } else {
          calcs += "^b[6] -= b[20] + b[41] + b[0] + b[42] + b[12] + b[19] + 131;"
          calcs += "^b[6] &= 0xFF;"
        }
        state = 565356050;
        continue;
      case 436361812:
        if (38134580n) {
          calcs += "^b[2] -= b[36] + b[1] + b[26] + b[30] + b[6] + b[13] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[2] &= 0xFF;"
        } else {
          calcs += "^b[32] += b[18] + b[30] + b[15] + b[35] + b[11] + b[29] + 178;"
          calcs += "^b[32] &= 0xFF;"
        }
        state = 164111264;
        continue;
      case 436860761:
        if (25722626n) {
          calcs += "^b[13] ^= (b[38] + b[41] + b[31] + b[9] + b[1] + b[40] + 57) & 0xFF;"
        } else {
          calcs += "^b[39] -= b[23] + b[17] + b[21] + b[36] + b[20] + b[34] + 12;"
          calcs += "^b[39] &= 0xFF;"
        }
        state = 992124543;
        continue;
      case 438031715:
        if (72676851) {
          calcs += "^b[30] -= b[8] + b[43] + b[37] + b[4] + b[31] + b[20] + 97;"
          calcs += "^b[30] &= 0xFF;"
        } else {
          calcs += "^b[17] ^= (b[20] + b[32] + b[10] + b[38] + b[24] + b[29] + 57) & 0xFF;"
        }
        state = 780263901;
        continue;
      case 439230522:
        if (Math.random() < 0.5) {
          calcs += "^b[38] -= b[15] + b[13] + b[3] + b[22] + b[34] + b[12] + 184;"
          calcs += "^b[38] &= 0xFF;"
        } else {
          calcs += "^b[28] -= b[43] + b[38] + b[13] + b[27] + b[8] + b[17] + 90;"
          calcs += "^b[28] &= 0xFF;"
        }
        state = 318198986;
        continue;
      case 439858784:
        if (48127012n) {
          calcs += "^b[11] ^= (b[18] + b[37] + b[23] + b[5] + b[3] + b[7] + 53) & 0xFF;"
        } else {
          calcs += "^b[15] -= b[34] + b[39] + b[42] + b[43] + b[28] + b[9] + 202;"
          calcs += "^b[15] &= 0xFF;"
        }
        state = 810171096;
        continue;
      case 440354165:
        if (Math.random() < 0.5) {
          calcs += "^b[18] ^= (b[11] + b[5] + b[42] + b[38] + b[39] + b[41] + 129) & 0xFF;"
        } else {
          calcs += "^b[31] ^= (b[8] + b[33] + b[38] + b[40] + b[13] + b[16] + 112) & 0xFF;"
        }
        state = 1056735643;
        continue;
      case 440786193:
        if (67667498n) {
          calcs += "^b[39] -= b[4] + b[31] + b[22] + b[5] + b[17] + b[1] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[39] &= 0xFF;"
        } else {
          calcs += "^b[4] -= b[36] + b[16] + b[6] + b[3] + b[33] + b[23] + 217;"
          calcs += "^b[4] &= 0xFF;"
        }
        state = 688759459;
        continue;
      case 442381073:
        if (244973440) {
          calcs += "^b[32] ^= (b[37] + b[43] + b[30] + b[14] + b[29] + b[21] + 157) & 0xFF;"
        } else {
          calcs += "^b[19] += b[38] + b[8] + b[11] + b[35] + b[36] + b[29] + 241;"
          calcs += "^b[19] &= 0xFF;"
        }
        state = 762144692;
        continue;
      case 443632296:
        if (Math.random() < 0.5) {
          calcs += "^b[34] += b[35] + b[40] + b[13] + b[41] + b[23] + b[25] + 14;"
          calcs += "^b[34] &= 0xFF;"
        } else {
          calcs += "^b[24] ^= (b[21] + b[8] + b[37] + b[18] + b[26] + b[23] + 226) & 0xFF;"
        }
        state = 608591871;
        continue;
      case 444613685:
        if (Math.random() < 0.5) {
          calcs += "^b[26] ^= (b[18] + b[21] + b[8] + b[28] + b[12] + b[15] + 98) & 0xFF;"
        } else {
          calcs += "^b[7] += b[10] + b[2] + b[25] + b[27] + b[5] + b[23] + 165;"
          calcs += "^b[7] &= 0xFF;"
        }
        state = 365681559;
        continue;
      case 444826173:
        if (446404210) {
          calcs += "^b[43] ^= (b[17] + b[37] + b[31] + b[14] + b[5] + b[16] + " + Math.floor(Math.random() * 256) + ") & 0xFF;"
        } else {
          calcs += "^b[30] ^= (b[29] + b[4] + b[10] + b[40] + b[7] + b[9] + 189) & 0xFF;"
        }
        state = 906239198;
        continue;
      case 445253239:
        if (327650681) {
          calcs += "^b[28] += b[23] + b[10] + b[6] + b[1] + b[9] + b[39] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[28] &= 0xFF;"
        } else {
          calcs += "^b[0] += b[25] + b[13] + b[38] + b[31] + b[14] + b[30] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[0] &= 0xFF;"
        }
        state = 1024125547;
        continue;
      case 449523591:
        if (754273526) {
          calcs += "^b[21] += b[8] + b[35] + b[22] + b[2] + b[24] + b[18] + 150;"
          calcs += "^b[21] &= 0xFF;"
        } else {
          calcs += "^b[31] ^= (b[26] + b[43] + b[7] + b[37] + b[25] + b[34] + 192) & 0xFF;"
        }
        state = 733956233;
        continue;
      case 449801452:
        if (47269895n) {
          calcs += "^b[41] += b[6] + b[23] + b[20] + b[4] + b[28] + b[16] + 8;"
          calcs += "^b[41] &= 0xFF;"
        } else {
          calcs += "^b[12] -= b[26] + b[30] + b[17] + b[32] + b[22] + b[43] + 72;"
          calcs += "^b[12] &= 0xFF;"
        }
        state = 63589848;
        continue;
      case 451400056:
        if (73596086n) {
          calcs += "^b[16] ^= (b[4] + b[22] + b[18] + b[13] + b[8] + b[9] + 84) & 0xFF;"
        } else {
          calcs += "^b[38] += b[18] + b[5] + b[31] + b[19] + b[2] + b[15] + 112;"
          calcs += "^b[38] &= 0xFF;"
        }
        state = 357681166;
        continue;
      case 451948137:
        if (94497704n) {
          calcs += "^b[3] -= b[35] + b[28] + b[24] + b[7] + b[17] + b[6] + 202;"
          calcs += "^b[3] &= 0xFF;"
        } else {
          calcs += "^b[40] ^= (b[2] + b[8] + b[42] + b[30] + b[38] + b[21] + 222) & 0xFF;"
        }
        state = 822608816;
        continue;
      case 454175396:
        if (Math.random() < 0.5) {
          calcs += "^b[33] -= b[43] + b[9] + b[28] + b[10] + b[22] + b[31] + 125;"
          calcs += "^b[33] &= 0xFF;"
        } else {
          calcs += "^b[14] ^= (b[27] + b[4] + b[33] + b[22] + b[43] + b[5] + 82) & 0xFF;"
        }
        state = 628101179;
        continue;
      case 454239079:
        if (89679766) {
          calcs += "^b[4] ^= (b[6] + b[1] + b[24] + b[14] + b[3] + b[31] + " + Math.floor(Math.random() * 256) + ") & 0xFF;"
        } else {
          calcs += "^b[25] -= b[38] + b[26] + b[39] + b[33] + b[40] + b[20] + 129;"
          calcs += "^b[25] &= 0xFF;"
        }
        state = 11942341;
        continue;
      case 455195714:
        if (Math.random() < 0.5) {
          calcs += "^b[29] ^= (b[27] + b[23] + b[8] + b[14] + b[16] + b[10] + " + Math.floor(Math.random() * 256) + ") & 0xFF;"
        } else {
          calcs += "^b[34] -= b[41] + b[40] + b[30] + b[23] + b[26] + b[27] + 190;"
          calcs += "^b[34] &= 0xFF;"
        }
        state = 709748243;
        continue;
      case 457466717:
        if (1014689134) {
          calcs += "^b[23] += b[31] + b[2] + b[25] + b[16] + b[15] + b[0] + 245;"
          calcs += "^b[23] &= 0xFF;"
        } else {
          calcs += "^b[33] += b[12] + b[21] + b[4] + b[37] + b[7] + b[9] + 124;"
          calcs += "^b[33] &= 0xFF;"
        }
        state = 108637663;
        continue;
      case 458923952:
        if (Math.random() < 0.5) {
          calcs += "^b[21] ^= (b[36] + b[31] + b[1] + b[20] + b[43] + b[17] + " + Math.floor(Math.random() * 256) + ") & 0xFF;"
        } else {
          calcs += "^b[41] -= b[2] + b[43] + b[23] + b[8] + b[40] + b[7] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[41] &= 0xFF;"
        }
        state = 702149658;
        continue;
      case 460713018:
        if (Math.random() < 0.5) {
          calcs += "^b[11] += b[42] + b[27] + b[40] + b[0] + b[6] + b[26] + 177;"
          calcs += "^b[11] &= 0xFF;"
        } else {
          calcs += "^b[12] ^= (b[32] + b[14] + b[5] + b[30] + b[42] + b[33] + " + Math.floor(Math.random() * 256) + ") & 0xFF;"
        }
        state = 229819407;
        continue;
      case 461379671:
        if (47840585n) {
          calcs += "^b[41] -= b[28] + b[21] + b[25] + b[31] + b[2] + b[36] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[41] &= 0xFF;"
        } else {
          calcs += "^b[2] -= b[27] + b[25] + b[4] + b[13] + b[18] + b[15] + 204;"
          calcs += "^b[2] &= 0xFF;"
        }
        state = 486662911;
        continue;
      case 462197583:
        if (89691202n) {
          calcs += "^b[10] ^= (b[3] + b[11] + b[8] + b[26] + b[36] + b[6] + 6) & 0xFF;"
        } else {
          calcs += "^b[32] -= b[11] + b[19] + b[2] + b[5] + b[6] + b[35] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[32] &= 0xFF;"
        }
        state = 218242848;
        continue;
      case 462595729:
        if (93249648n) {
          calcs += "^b[37] ^= (b[39] + b[13] + b[18] + b[11] + b[31] + b[29] + 42) & 0xFF;"
        } else {
          calcs += "^b[12] -= b[29] + b[2] + b[32] + b[7] + b[6] + b[23] + 5;"
          calcs += "^b[12] &= 0xFF;"
        }
        state = 277174297;
        continue;
      case 463080223:
        if (Math.random() < 0.5) {
          calcs += "^b[27] ^= (b[23] + b[31] + b[37] + b[34] + b[12] + b[6] + 96) & 0xFF;"
        } else {
          calcs += "^b[17] -= b[20] + b[31] + b[1] + b[37] + b[32] + b[38] + 221;"
          calcs += "^b[17] &= 0xFF;"
        }
        state = 1003492583;
        continue;
      case 463157616:
        if (Math.random() < 0.5) {
          calcs += "^b[4] -= b[1] + b[17] + b[0] + b[15] + b[19] + b[41] + 192;"
          calcs += "^b[4] &= 0xFF;"
        } else {
          calcs += "^b[40] += b[30] + b[29] + b[16] + b[39] + b[9] + b[6] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[40] &= 0xFF;"
        }
        state = 168379940;
        continue;
      case 465610305:
        if (75946403n) {
          calcs += "^b[4] -= b[11] + b[36] + b[40] + b[38] + b[16] + b[6] + 149;"
          calcs += "^b[4] &= 0xFF;"
        } else {
          calcs += "^b[6] -= b[15] + b[25] + b[3] + b[33] + b[12] + b[20] + 94;"
          calcs += "^b[6] &= 0xFF;"
        }
        state = 540767803;
        continue;
      case 467053882:
        if (58120271n) {
          calcs += "^b[8] -= b[12] + b[6] + b[1] + b[21] + b[28] + b[25] + 55;"
          calcs += "^b[8] &= 0xFF;"
        } else {
          calcs += "^b[27] -= b[38] + b[18] + b[11] + b[16] + b[25] + b[40] + 250;"
          calcs += "^b[27] &= 0xFF;"
        }
        state = 975416110;
        continue;
      case 468600845:
        if (Math.random() < 0.5) {
          calcs += "^b[35] += b[5] + b[0] + b[14] + b[2] + b[20] + b[6] + 241;"
          calcs += "^b[35] &= 0xFF;"
        } else {
          calcs += "^b[25] += b[1] + b[21] + b[15] + b[35] + b[28] + b[7] + 214;"
          calcs += "^b[25] &= 0xFF;"
        }
        state = 934711763;
        continue;
      case 469496696:
        if (703534930) {
          calcs += "^b[21] ^= (b[8] + b[2] + b[11] + b[39] + b[36] + b[10] + 71) & 0xFF;"
        } else {
          calcs += "^b[14] += b[6] + b[26] + b[3] + b[23] + b[17] + b[43] + 15;"
          calcs += "^b[14] &= 0xFF;"
        }
        state = 163026493;
        continue;
      case 469950833:
        if (Math.random() < 0.5) {
          calcs += "^b[17] += b[23] + b[10] + b[35] + b[3] + b[19] + b[22] + 140;"
          calcs += "^b[17] &= 0xFF;"
        } else {
          calcs += "^b[25] -= b[34] + b[32] + b[43] + b[22] + b[39] + b[17] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[25] &= 0xFF;"
        }
        state = 65139032;
        continue;
      case 470915230:
        if (655599971) {
          calcs += "^b[4] -= b[22] + b[21] + b[31] + b[1] + b[34] + b[41] + 237;"
          calcs += "^b[4] &= 0xFF;"
        } else {
          calcs += "^b[38] -= b[14] + b[3] + b[35] + b[40] + b[6] + b[5] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[38] &= 0xFF;"
        }
        state = 115237491;
        continue;
      case 472968028:
        if (24605414n) {
          calcs += "^b[9] ^= (b[27] + b[15] + b[21] + b[36] + b[29] + b[25] + 178) & 0xFF;"
        } else {
          calcs += "^b[11] ^= (b[21] + b[28] + b[23] + b[7] + b[31] + b[26] + " + Math.floor(Math.random() * 256) + ") & 0xFF;"
        }
        state = 256880408;
        continue;
      case 472997066:
        if (886419875) {
          calcs += "^b[25] ^= (b[21] + b[43] + b[16] + b[1] + b[14] + b[39] + 186) & 0xFF;"
        } else {
          calcs += "^b[20] -= b[19] + b[7] + b[11] + b[33] + b[18] + b[1] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[20] &= 0xFF;"
        }
        state = 300099556;
        continue;
      case 475240679:
        if (Math.random() < 0.5) {
          calcs += "^b[40] -= b[42] + b[17] + b[38] + b[14] + b[41] + b[30] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[40] &= 0xFF;"
        } else {
          calcs += "^b[34] += b[10] + b[1] + b[13] + b[2] + b[7] + b[12] + 14;"
          calcs += "^b[34] &= 0xFF;"
        }
        state = 800650205;
        continue;
      case 475745844:
        if (64868979n) {
          calcs += "^b[13] -= b[29] + b[14] + b[15] + b[17] + b[2] + b[38] + 2;"
          calcs += "^b[13] &= 0xFF;"
        } else {
          calcs += "^b[27] += b[17] + b[7] + b[0] + b[1] + b[34] + b[14] + 128;"
          calcs += "^b[27] &= 0xFF;"
        }
        state = 474381926;
        continue;
      case 476113183:
        if (142127748) {
          calcs += "^b[34] ^= (b[10] + b[32] + b[3] + b[29] + b[8] + b[17] + 246) & 0xFF;"
        } else {
          calcs += "^b[7] += b[1] + b[32] + b[35] + b[21] + b[23] + b[4] + 89;"
          calcs += "^b[7] &= 0xFF;"
        }
        state = 527068867;
        continue;
      case 477914619:
        if (Math.random() < 0.5) {
          calcs += "^b[37] ^= (b[28] + b[5] + b[29] + b[0] + b[10] + b[41] + " + Math.floor(Math.random() * 256) + ") & 0xFF;"
        } else {
          calcs += "^b[1] -= b[32] + b[42] + b[41] + b[33] + b[39] + b[28] + 75;"
          calcs += "^b[1] &= 0xFF;"
        }
        state = 430080227;
        continue;
      case 478053888:
        if (Math.random() < 0.5) {
          calcs += "^b[14] -= b[40] + b[34] + b[43] + b[23] + b[18] + b[29] + 111;"
          calcs += "^b[14] &= 0xFF;"
        } else {
          calcs += "^b[3] ^= (b[17] + b[22] + b[20] + b[7] + b[12] + b[14] + 152) & 0xFF;"
        }
        state = 577331484;
        continue;
      case 478340892:
        if (Math.random() < 0.5) {
          calcs += "^b[5] += b[39] + b[18] + b[43] + b[8] + b[15] + b[14] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[5] &= 0xFF;"
        } else {
          calcs += "^b[31] ^= (b[3] + b[18] + b[16] + b[8] + b[28] + b[2] + 188) & 0xFF;"
        }
        state = 523416510;
        continue;
      case 479865795:
        if (Math.random() < 0.5) {
          calcs += "^b[7] ^= (b[19] + b[8] + b[34] + b[24] + b[37] + b[14] + 126) & 0xFF;"
        } else {
          calcs += "^b[37] ^= (b[6] + b[3] + b[31] + b[9] + b[42] + b[32] + 22) & 0xFF;"
        }
        state = 212840603;
        continue;
      case 479868974:
        if (42718766n) {
          calcs += "^b[41] -= b[32] + b[42] + b[15] + b[9] + b[17] + b[0] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[41] &= 0xFF;"
        } else {
          calcs += "^b[19] ^= (b[3] + b[30] + b[17] + b[15] + b[13] + b[18] + " + Math.floor(Math.random() * 256) + ") & 0xFF;"
        }
        state = 65570416;
        continue;
      case 479895768:
        if (89471903n) {
          calcs += "^b[26] ^= (b[24] + b[7] + b[11] + b[12] + b[38] + b[3] + " + Math.floor(Math.random() * 256) + ") & 0xFF;"
        } else {
          calcs += "^b[30] -= b[12] + b[25] + b[21] + b[7] + b[35] + b[18] + 252;"
          calcs += "^b[30] &= 0xFF;"
        }
        state = 143026402;
        continue;
      case 481236269:
        if (79766523n) {
          calcs += "^b[19] ^= (b[15] + b[0] + b[42] + b[4] + b[10] + b[33] + 73) & 0xFF;"
        } else {
          calcs += "^b[3] ^= (b[35] + b[2] + b[26] + b[24] + b[17] + b[14] + 66) & 0xFF;"
        }
        state = 329045785;
        continue;
      case 481264118:
        if (600803035) {
          calcs += "^b[33] -= b[17] + b[16] + b[39] + b[32] + b[21] + b[12] + 247;"
          calcs += "^b[33] &= 0xFF;"
        } else {
          calcs += "^b[24] += b[5] + b[42] + b[28] + b[18] + b[13] + b[43] + 10;"
          calcs += "^b[24] &= 0xFF;"
        }
        state = 832419112;
        continue;
      case 482034949:
        if (41347143n) {
          calcs += "^b[23] -= b[13] + b[17] + b[19] + b[34] + b[16] + b[25] + 81;"
          calcs += "^b[23] &= 0xFF;"
        } else {
          calcs += "^b[40] ^= (b[0] + b[36] + b[43] + b[31] + b[15] + b[27] + 217) & 0xFF;"
        }
        state = 144600737;
        continue;
      case 484432842:
        if (898392674) {
          calcs += "^b[14] ^= (b[30] + b[35] + b[39] + b[8] + b[1] + b[0] + 252) & 0xFF;"
        } else {
          calcs += "^b[28] += b[16] + b[25] + b[40] + b[23] + b[0] + b[24] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[28] &= 0xFF;"
        }
        state = 787080846;
        continue;
      case 485214937:
        if (42159721n) {
          calcs += "^b[21] ^= (b[7] + b[18] + b[19] + b[23] + b[5] + b[11] + 243) & 0xFF;"
        } else {
          calcs += "^b[24] -= b[10] + b[39] + b[23] + b[28] + b[14] + b[2] + 121;"
          calcs += "^b[24] &= 0xFF;"
        }
        state = 660465379;
        continue;
      case 485391444:
        if (34486563n) {
          calcs += "^b[3] ^= (b[34] + b[14] + b[7] + b[29] + b[43] + b[17] + 70) & 0xFF;"
        } else {
          calcs += "^b[40] += b[12] + b[8] + b[31] + b[28] + b[4] + b[2] + 26;"
          calcs += "^b[40] &= 0xFF;"
        }
        state = 447130134;
        continue;
      case 487366741:
        if (316085581) {
          calcs += "^b[5] -= b[43] + b[16] + b[4] + b[32] + b[37] + b[26] + 76;"
          calcs += "^b[5] &= 0xFF;"
        } else {
          calcs += "^b[27] -= b[12] + b[17] + b[9] + b[33] + b[3] + b[21] + 161;"
          calcs += "^b[27] &= 0xFF;"
        }
        state = 598678520;
        continue;
      case 487732442:
        if (Math.random() < 0.5) {
          calcs += "^b[5] += b[37] + b[29] + b[15] + b[13] + b[9] + b[35] + 74;"
          calcs += "^b[5] &= 0xFF;"
        } else {
          calcs += "^b[33] ^= (b[39] + b[12] + b[10] + b[18] + b[37] + b[15] + 22) & 0xFF;"
        }
        state = 185416230;
        continue;
      case 488117931:
        if (72782462) {
          calcs += "^b[29] += b[42] + b[36] + b[3] + b[16] + b[30] + b[5] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[29] &= 0xFF;"
        } else {
          calcs += "^b[34] += b[12] + b[20] + b[15] + b[38] + b[23] + b[11] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[34] &= 0xFF;"
        }
        state = 653944692;
        continue;
      case 489644900:
        if (Math.random() < 0.5) {
          calcs += "^b[15] -= b[12] + b[3] + b[28] + b[37] + b[32] + b[33] + 24;"
          calcs += "^b[15] &= 0xFF;"
        } else {
          calcs += "^b[33] -= b[43] + b[24] + b[16] + b[7] + b[17] + b[6] + 156;"
          calcs += "^b[33] &= 0xFF;"
        }
        state = 983139333;
        continue;
      case 492685924:
        if (Math.random() < 0.5) {
          calcs += "^b[37] ^= (b[23] + b[8] + b[1] + b[14] + b[43] + b[17] + " + Math.floor(Math.random() * 256) + ") & 0xFF;"
        } else {
          calcs += "^b[36] ^= (b[11] + b[9] + b[37] + b[32] + b[12] + b[27] + 20) & 0xFF;"
        }
        state = 523656839;
        continue;
      case 493010987:
        if (504291992) {
          calcs += "^b[38] += b[7] + b[31] + b[16] + b[22] + b[3] + b[6] + 131;"
          calcs += "^b[38] &= 0xFF;"
        } else {
          calcs += "^b[34] += b[2] + b[22] + b[15] + b[18] + b[7] + b[33] + 43;"
          calcs += "^b[34] &= 0xFF;"
        }
        state = 1017701949;
        continue;
      case 495535675:
        if (46430234n) {
          calcs += "^b[29] += b[43] + b[39] + b[38] + b[26] + b[28] + b[17] + 103;"
          calcs += "^b[29] &= 0xFF;"
        } else {
          calcs += "^b[5] -= b[35] + b[11] + b[28] + b[1] + b[7] + b[18] + 36;"
          calcs += "^b[5] &= 0xFF;"
        }
        state = 797290468;
        continue;
      case 495847681:
        if (85080805n) {
          calcs += "^b[9] -= b[33] + b[20] + b[43] + b[17] + b[15] + b[28] + 13;"
          calcs += "^b[9] &= 0xFF;"
        } else {
          calcs += "^b[43] += b[12] + b[22] + b[36] + b[32] + b[11] + b[17] + 12;"
          calcs += "^b[43] &= 0xFF;"
        }
        state = 84878614;
        continue;
      case 495921857:
        if (Math.random() < 0.5) {
          calcs += "^b[17] -= b[11] + b[32] + b[14] + b[16] + b[28] + b[9] + 167;"
          calcs += "^b[17] &= 0xFF;"
        } else {
          calcs += "^b[23] += b[11] + b[34] + b[39] + b[16] + b[28] + b[4] + 214;"
          calcs += "^b[23] &= 0xFF;"
        }
        state = 544245134;
        continue;
      case 496002193:
        if (98253584n) {
          calcs += "^b[3] ^= (b[5] + b[41] + b[30] + b[14] + b[7] + b[28] + 157) & 0xFF;"
        } else {
          calcs += "^b[33] ^= (b[35] + b[30] + b[36] + b[41] + b[3] + b[28] + 231) & 0xFF;"
        }
        state = 524554106;
        continue;
      case 497039019:
        if (43116320n) {
          calcs += "^b[32] -= b[8] + b[19] + b[43] + b[0] + b[2] + b[1] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[32] &= 0xFF;"
        } else {
          calcs += "^b[33] ^= (b[34] + b[32] + b[6] + b[16] + b[41] + b[10] + 87) & 0xFF;"
        }
        state = 25913363;
        continue;
      case 497278214:
        if (959009418) {
          calcs += "^b[12] += b[14] + b[13] + b[17] + b[22] + b[25] + b[38] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[12] &= 0xFF;"
        } else {
          calcs += "^b[39] += b[34] + b[2] + b[1] + b[43] + b[20] + b[9] + 79;"
          calcs += "^b[39] &= 0xFF;"
        }
        state = 616505830;
        continue;
      case 504039263:
        if (66702658n) {
          calcs += "^b[0] += b[17] + b[10] + b[16] + b[38] + b[22] + b[15] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[0] &= 0xFF;"
        } else {
          calcs += "^b[23] -= b[7] + b[37] + b[17] + b[29] + b[16] + b[33] + 209;"
          calcs += "^b[23] &= 0xFF;"
        }
        state = 75120729;
        continue;
      case 504478655:
        if (15907738n) {
          calcs += "^b[40] ^= (b[15] + b[39] + b[14] + b[17] + b[16] + b[9] + 206) & 0xFF;"
        } else {
          calcs += "^b[27] -= b[10] + b[38] + b[4] + b[26] + b[22] + b[12] + 228;"
          calcs += "^b[27] &= 0xFF;"
        }
        state = 776455031;
        continue;
      case 504890843:
        if (Math.random() < 0.5) {
          calcs += "^b[20] += b[34] + b[10] + b[12] + b[41] + b[18] + b[43] + 147;"
          calcs += "^b[20] &= 0xFF;"
        } else {
          calcs += "^b[19] -= b[37] + b[1] + b[17] + b[20] + b[23] + b[10] + 230;"
          calcs += "^b[19] &= 0xFF;"
        }
        state = 516579404;
        continue;
      case 505192518:
        if (470097413) {
          calcs += "^b[4] ^= (b[22] + b[19] + b[43] + b[13] + b[42] + b[23] + 56) & 0xFF;"
        } else {
          calcs += "^b[31] += b[13] + b[16] + b[43] + b[33] + b[35] + b[41] + 129;"
          calcs += "^b[31] &= 0xFF;"
        }
        state = 571842760;
        continue;
      case 505561575:
        if (Math.random() < 0.5) {
          calcs += "^b[34] ^= (b[9] + b[5] + b[31] + b[42] + b[1] + b[3] + 244) & 0xFF;"
        } else {
          calcs += "^b[23] ^= (b[41] + b[10] + b[8] + b[3] + b[0] + b[19] + 51) & 0xFF;"
        }
        state = 833272276;
        continue;
      case 506148129:
        if (80897206n) {
          calcs += "^b[37] ^= (b[2] + b[27] + b[7] + b[20] + b[22] + b[32] + 130) & 0xFF;"
        } else {
          calcs += "^b[18] -= b[43] + b[21] + b[23] + b[7] + b[11] + b[39] + 51;"
          calcs += "^b[18] &= 0xFF;"
        }
        state = 719135794;
        continue;
      case 506773855:
        if (54120581n) {
          calcs += "^b[11] -= b[42] + b[40] + b[38] + b[3] + b[26] + b[1] + 101;"
          calcs += "^b[11] &= 0xFF;"
        } else {
          calcs += "^b[42] -= b[21] + b[14] + b[22] + b[32] + b[34] + b[40] + 221;"
          calcs += "^b[42] &= 0xFF;"
        }
        state = 237054350;
        continue;
      case 506966062:
        if (Math.random() < 0.5) {
          calcs += "^b[5] += b[29] + b[23] + b[15] + b[0] + b[14] + b[28] + 198;"
          calcs += "^b[5] &= 0xFF;"
        } else {
          calcs += "^b[41] += b[19] + b[3] + b[12] + b[13] + b[9] + b[17] + 0;"
          calcs += "^b[41] &= 0xFF;"
        }
        state = 419926580;
        continue;
      case 507505767:
        if (274685363) {
          calcs += "^b[14] += b[24] + b[4] + b[25] + b[12] + b[29] + b[38] + 169;"
          calcs += "^b[14] &= 0xFF;"
        } else {
          calcs += "^b[6] ^= (b[12] + b[30] + b[10] + b[41] + b[3] + b[37] + 121) & 0xFF;"
        }
        state = 866756613;
        continue;
      case 508081179:
        if (Math.random() < 0.5) {
          calcs += "^b[38] ^= (b[25] + b[28] + b[12] + b[23] + b[20] + b[4] + 220) & 0xFF;"
        } else {
          calcs += "^b[38] -= b[30] + b[3] + b[22] + b[32] + b[1] + b[29] + 254;"
          calcs += "^b[38] &= 0xFF;"
        }
        state = 813166976;
        continue;
      case 508258165:
        if (Math.random() < 0.5) {
          calcs += "^b[11] -= b[3] + b[34] + b[1] + b[14] + b[20] + b[22] + 237;"
          calcs += "^b[11] &= 0xFF;"
        } else {
          calcs += "^b[31] -= b[40] + b[9] + b[21] + b[34] + b[7] + b[12] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[31] &= 0xFF;"
        }
        state = 78331563;
        continue;
      case 509219317:
        if (624740198) {
          calcs += "^b[43] ^= (b[28] + b[7] + b[5] + b[27] + b[31] + b[41] + 38) & 0xFF;"
        } else {
          calcs += "^b[23] += b[33] + b[15] + b[16] + b[41] + b[12] + b[25] + 182;"
          calcs += "^b[23] &= 0xFF;"
        }
        state = 353292093;
        continue;
      case 509314672:
        if (Math.random() < 0.5) {
          calcs += "^b[41] ^= (b[16] + b[14] + b[13] + b[18] + b[17] + b[10] + 101) & 0xFF;"
        } else {
          calcs += "^b[19] += b[28] + b[30] + b[4] + b[10] + b[15] + b[17] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[19] &= 0xFF;"
        }
        state = 291891829;
        continue;
      case 509659873:
        if (46683819) {
          calcs += "^b[14] ^= (b[41] + b[29] + b[2] + b[28] + b[3] + b[13] + 21) & 0xFF;"
        } else {
          calcs += "^b[22] ^= (b[6] + b[10] + b[5] + b[40] + b[17] + b[28] + 173) & 0xFF;"
        }
        state = 131731400;
        continue;
      case 510460050:
        if (72881791n) {
          calcs += "^b[21] -= b[34] + b[37] + b[22] + b[30] + b[9] + b[40] + 25;"
          calcs += "^b[21] &= 0xFF;"
        } else {
          calcs += "^b[13] -= b[26] + b[37] + b[30] + b[27] + b[22] + b[32] + 167;"
          calcs += "^b[13] &= 0xFF;"
        }
        state = 315739374;
        continue;
      case 512178077:
        if (732450855) {
          calcs += "^b[28] ^= (b[4] + b[6] + b[13] + b[41] + b[7] + b[24] + 100) & 0xFF;"
        } else {
          calcs += "^b[32] ^= (b[16] + b[4] + b[23] + b[8] + b[41] + b[29] + " + Math.floor(Math.random() * 256) + ") & 0xFF;"
        }
        state = 740993309;
        continue;
      case 513668468:
        if (Math.random() < 0.5) {
          calcs += "^b[21] -= b[7] + b[39] + b[40] + b[15] + b[0] + b[25] + 42;"
          calcs += "^b[21] &= 0xFF;"
        } else {
          calcs += "^b[20] ^= (b[2] + b[16] + b[34] + b[1] + b[36] + b[33] + 189) & 0xFF;"
        }
        state = 1056580359;
        continue;
      case 514347277:
        if (42732613n) {
          calcs += "^b[12] ^= (b[37] + b[8] + b[16] + b[20] + b[17] + b[1] + " + Math.floor(Math.random() * 256) + ") & 0xFF;"
        } else {
          calcs += "^b[33] ^= (b[10] + b[22] + b[2] + b[1] + b[30] + b[11] + " + Math.floor(Math.random() * 256) + ") & 0xFF;"
        }
        state = 385158166;
        continue;
      case 515148309:
        if (289376824) {
          calcs += "^b[39] += b[23] + b[12] + b[29] + b[16] + b[28] + b[43] + 50;"
          calcs += "^b[39] &= 0xFF;"
        } else {
          calcs += "^b[32] += b[38] + b[28] + b[42] + b[1] + b[35] + b[17] + 235;"
          calcs += "^b[32] &= 0xFF;"
        }
        state = 428711142;
        continue;
      case 516077630:
        if (882468081) {
          calcs += "^b[0] -= b[35] + b[19] + b[7] + b[40] + b[22] + b[33] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[0] &= 0xFF;"
        } else {
          calcs += "^b[0] ^= (b[32] + b[20] + b[30] + b[10] + b[37] + b[35] + 204) & 0xFF;"
        }
        state = 851529129;
        continue;
      case 517062528:
        if (107333336) {
          calcs += "^b[24] += b[33] + b[16] + b[25] + b[12] + b[28] + b[8] + 11;"
          calcs += "^b[24] &= 0xFF;"
        } else {
          calcs += "^b[37] ^= (b[28] + b[39] + b[41] + b[11] + b[10] + b[9] + 223) & 0xFF;"
        }
        state = 611428905;
        continue;
      case 518976161:
        if (Math.random() < 0.5) {
          calcs += "^b[6] += b[13] + b[43] + b[8] + b[14] + b[17] + b[2] + 135;"
          calcs += "^b[6] &= 0xFF;"
        } else {
          calcs += "^b[12] ^= (b[42] + b[25] + b[19] + b[7] + b[16] + b[43] + 245) & 0xFF;"
        }
        state = 344022322;
        continue;
      case 522741887:
        if (641476389) {
          calcs += "^b[39] += b[9] + b[5] + b[43] + b[25] + b[18] + b[27] + 206;"
          calcs += "^b[39] &= 0xFF;"
        } else {
          calcs += "^b[27] -= b[1] + b[26] + b[10] + b[29] + b[14] + b[4] + 32;"
          calcs += "^b[27] &= 0xFF;"
        }
        state = 107869899;
        continue;
      case 522895656:
        if (299124257) {
          calcs += "^b[26] -= b[24] + b[6] + b[3] + b[23] + b[31] + b[41] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[26] &= 0xFF;"
        } else {
          calcs += "^b[14] += b[39] + b[4] + b[25] + b[27] + b[35] + b[7] + 0;"
          calcs += "^b[14] &= 0xFF;"
        }
        state = 428160326;
        continue;
      case 525162538:
        if (292477912) {
          calcs += "^b[40] -= b[27] + b[20] + b[12] + b[33] + b[16] + b[29] + 193;"
          calcs += "^b[40] &= 0xFF;"
        } else {
          calcs += "^b[8] ^= (b[12] + b[10] + b[3] + b[2] + b[34] + b[31] + 203) & 0xFF;"
        }
        state = 842785514;
        continue;
      case 525513317:
        if (1045931426) {
          calcs += "^b[33] += b[35] + b[8] + b[12] + b[18] + b[14] + b[17] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[33] &= 0xFF;"
        } else {
          calcs += "^b[43] -= b[22] + b[17] + b[6] + b[10] + b[2] + b[5] + 126;"
          calcs += "^b[43] &= 0xFF;"
        }
        state = 629047482;
        continue;
      case 526095888:
        if (54386730n) {
          calcs += "^b[19] += b[31] + b[15] + b[6] + b[20] + b[26] + b[25] + 254;"
          calcs += "^b[19] &= 0xFF;"
        } else {
          calcs += "^b[1] -= b[42] + b[28] + b[9] + b[29] + b[14] + b[3] + 245;"
          calcs += "^b[1] &= 0xFF;"
        }
        state = 120434431;
        continue;
      case 527194655:
        if (Math.random() < 0.5) {
          calcs += "^b[41] ^= (b[4] + b[8] + b[26] + b[43] + b[18] + b[24] + 1) & 0xFF;"
        } else {
          calcs += "^b[33] ^= (b[40] + b[20] + b[19] + b[16] + b[5] + b[37] + 240) & 0xFF;"
        }
        state = 117035775;
        continue;
      case 527233541:
        if (413972649) {
          calcs += "^b[43] -= b[8] + b[9] + b[22] + b[33] + b[41] + b[1] + 156;"
          calcs += "^b[43] &= 0xFF;"
        } else {
          calcs += "^b[18] += b[22] + b[13] + b[43] + b[2] + b[14] + b[4] + 10;"
          calcs += "^b[18] &= 0xFF;"
        }
        state = 539733327;
        continue;
      case 527739369:
        if (909199331) {
          calcs += "^b[10] ^= (b[16] + b[38] + b[22] + b[3] + b[1] + b[7] + 209) & 0xFF;"
        } else {
          calcs += "^b[39] ^= (b[15] + b[14] + b[31] + b[23] + b[27] + b[41] + " + Math.floor(Math.random() * 256) + ") & 0xFF;"
        }
        state = 681218012;
        continue;
      case 527973694:
        if (739335238) {
          calcs += "^b[16] += b[1] + b[5] + b[4] + b[37] + b[27] + b[43] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[16] &= 0xFF;"
        } else {
          calcs += "^b[21] -= b[8] + b[30] + b[13] + b[22] + b[0] + b[5] + 34;"
          calcs += "^b[21] &= 0xFF;"
        }
        state = 383562953;
        continue;
      case 528361686:
        if (96633358n) {
          calcs += "^b[42] ^= (b[0] + b[22] + b[21] + b[39] + b[27] + b[32] + 119) & 0xFF;"
        } else {
          calcs += "^b[38] += b[22] + b[26] + b[9] + b[29] + b[40] + b[1] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[38] &= 0xFF;"
        }
        state = 527147759;
        continue;
      case 529404720:
        if (468566471) {
          calcs += "^b[11] += b[24] + b[9] + b[39] + b[33] + b[0] + b[22] + 22;"
          calcs += "^b[11] &= 0xFF;"
        } else {
          calcs += "^b[18] -= b[5] + b[42] + b[22] + b[0] + b[23] + b[28] + 19;"
          calcs += "^b[18] &= 0xFF;"
        }
        state = 338562817;
        continue;
      case 529667627:
        if (34842670n) {
          calcs += "^b[40] -= b[29] + b[0] + b[14] + b[10] + b[15] + b[31] + 244;"
          calcs += "^b[40] &= 0xFF;"
        } else {
          calcs += "^b[32] ^= (b[30] + b[18] + b[21] + b[19] + b[0] + b[4] + 37) & 0xFF;"
        }
        state = 698292025;
        continue;
      case 530885266:
        if (83924104n) {
          calcs += "^b[26] -= b[25] + b[2] + b[16] + b[19] + b[23] + b[32] + 119;"
          calcs += "^b[26] &= 0xFF;"
        } else {
          calcs += "^b[39] += b[26] + b[19] + b[3] + b[14] + b[33] + b[29] + 47;"
          calcs += "^b[39] &= 0xFF;"
        }
        state = 323709686;
        continue;
      case 530940714:
        if (333972956) {
          calcs += "^b[20] -= b[38] + b[12] + b[2] + b[39] + b[42] + b[18] + 166;"
          calcs += "^b[20] &= 0xFF;"
        } else {
          calcs += "^b[32] += b[26] + b[15] + b[4] + b[21] + b[6] + b[29] + 27;"
          calcs += "^b[32] &= 0xFF;"
        }
        state = 796549726;
        continue;
      case 531048198:
        if (77940094n) {
          calcs += "^b[39] ^= (b[12] + b[16] + b[35] + b[0] + b[41] + b[2] + 229) & 0xFF;"
        } else {
          calcs += "^b[16] ^= (b[26] + b[25] + b[20] + b[2] + b[37] + b[0] + 129) & 0xFF;"
        }
        state = 181616358;
        continue;
      case 533103436:
        if (65086260n) {
          calcs += "^b[41] ^= (b[5] + b[40] + b[39] + b[2] + b[3] + b[31] + 16) & 0xFF;"
        } else {
          calcs += "^b[36] -= b[1] + b[30] + b[11] + b[22] + b[16] + b[14] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[36] &= 0xFF;"
        }
        state = 1055933180;
        continue;
      case 533553662:
        if (311223286) {
          calcs += "^b[20] -= b[43] + b[28] + b[11] + b[10] + b[42] + b[22] + 137;"
          calcs += "^b[20] &= 0xFF;"
        } else {
          calcs += "^b[28] ^= (b[23] + b[19] + b[38] + b[31] + b[32] + b[18] + 118) & 0xFF;"
        }
        state = 886427273;
        continue;
      case 533941089:
        if (69372947n) {
          calcs += "^b[29] += b[12] + b[26] + b[2] + b[14] + b[21] + b[36] + 110;"
          calcs += "^b[29] &= 0xFF;"
        } else {
          calcs += "^b[27] -= b[14] + b[28] + b[34] + b[16] + b[41] + b[31] + 225;"
          calcs += "^b[27] &= 0xFF;"
        }
        state = 416679206;
        continue;
      case 533953311:
        if (49659177n) {
          calcs += "^b[35] -= b[39] + b[19] + b[4] + b[15] + b[41] + b[31] + 98;"
          calcs += "^b[35] &= 0xFF;"
        } else {
          calcs += "^b[27] -= b[21] + b[18] + b[38] + b[1] + b[40] + b[12] + 174;"
          calcs += "^b[27] &= 0xFF;"
        }
        state = 1005986656;
        continue;
      case 535029726:
        if (712958263) {
          calcs += "^b[11] += b[27] + b[31] + b[26] + b[24] + b[9] + b[32] + 56;"
          calcs += "^b[11] &= 0xFF;"
        } else {
          calcs += "^b[42] ^= (b[43] + b[39] + b[36] + b[3] + b[26] + b[23] + " + Math.floor(Math.random() * 256) + ") & 0xFF;"
        }
        state = 366542916;
        continue;
      case 536345467:
        if (49354738n) {
          calcs += "^b[34] ^= (b[4] + b[10] + b[41] + b[7] + b[23] + b[11] + 238) & 0xFF;"
        } else {
          calcs += "^b[16] += b[34] + b[25] + b[24] + b[23] + b[42] + b[14] + 168;"
          calcs += "^b[16] &= 0xFF;"
        }
        state = 566051337;
        continue;
      case 537237003:
        if (33162942n) {
          calcs += "^b[13] ^= (b[1] + b[38] + b[24] + b[40] + b[35] + b[2] + " + Math.floor(Math.random() * 256) + ") & 0xFF;"
        } else {
          calcs += "^b[24] -= b[39] + b[14] + b[26] + b[12] + b[13] + b[41] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[24] &= 0xFF;"
        }
        state = 890665433;
        continue;
      case 537347423:
        if (Math.random() < 0.5) {
          calcs += "^b[33] ^= (b[34] + b[36] + b[2] + b[8] + b[20] + b[22] + 40) & 0xFF;"
        } else {
          calcs += "^b[3] ^= (b[13] + b[29] + b[8] + b[11] + b[38] + b[21] + 140) & 0xFF;"
        }
        state = 723908396;
        continue;
      case 540405567:
        if (10151601n) {
          calcs += "^b[16] ^= (b[32] + b[39] + b[13] + b[21] + b[20] + b[2] + 28) & 0xFF;"
        } else {
          calcs += "^b[6] += b[20] + b[13] + b[31] + b[26] + b[43] + b[7] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[6] &= 0xFF;"
        }
        state = 689542006;
        continue;
      case 541057851:
        if (Math.random() < 0.5) {
          calcs += "^b[15] -= b[33] + b[16] + b[11] + b[3] + b[14] + b[38] + 250;"
          calcs += "^b[15] &= 0xFF;"
        } else {
          calcs += "^b[9] += b[31] + b[37] + b[29] + b[27] + b[11] + b[13] + 216;"
          calcs += "^b[9] &= 0xFF;"
        }
        state = 290173932;
        continue;
      case 542039106:
        if (1062580192) {
          calcs += "^b[28] ^= (b[13] + b[3] + b[36] + b[26] + b[40] + b[16] + " + Math.floor(Math.random() * 256) + ") & 0xFF;"
        } else {
          calcs += "^b[43] += b[10] + b[15] + b[28] + b[29] + b[27] + b[26] + 168;"
          calcs += "^b[43] &= 0xFF;"
        }
        state = 198158056;
        continue;
      case 542432804:
        if (63018993n) {
          calcs += "^b[1] -= b[41] + b[33] + b[32] + b[17] + b[35] + b[2] + 65;"
          calcs += "^b[1] &= 0xFF;"
        } else {
          calcs += "^b[16] -= b[7] + b[19] + b[39] + b[4] + b[36] + b[34] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[16] &= 0xFF;"
        }
        state = 1037670780;
        continue;
      case 543401869:
        if (379629600) {
          calcs += "^b[11] -= b[1] + b[17] + b[28] + b[18] + b[35] + b[37] + 76;"
          calcs += "^b[11] &= 0xFF;"
        } else {
          calcs += "^b[14] -= b[30] + b[33] + b[8] + b[1] + b[10] + b[26] + 203;"
          calcs += "^b[14] &= 0xFF;"
        }
        state = 1006148099;
        continue;
      case 547061522:
        if (775060694) {
          calcs += "^b[33] += b[32] + b[19] + b[4] + b[28] + b[11] + b[15] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[33] &= 0xFF;"
        } else {
          calcs += "^b[35] ^= (b[12] + b[20] + b[21] + b[18] + b[13] + b[14] + 241) & 0xFF;"
        }
        state = 449033011;
        continue;
      case 549494432:
        if (735134521) {
          calcs += "^b[4] += b[38] + b[26] + b[18] + b[33] + b[25] + b[41] + 55;"
          calcs += "^b[4] &= 0xFF;"
        } else {
          calcs += "^b[18] ^= (b[32] + b[30] + b[26] + b[22] + b[9] + b[33] + 19) & 0xFF;"
        }
        state = 578604559;
        continue;
      case 551829021:
        if (314069234) {
          calcs += "^b[18] ^= (b[20] + b[15] + b[1] + b[12] + b[39] + b[21] + 97) & 0xFF;"
        } else {
          calcs += "^b[32] += b[29] + b[21] + b[6] + b[4] + b[39] + b[42] + 251;"
          calcs += "^b[32] &= 0xFF;"
        }
        state = 899931277;
        continue;
      case 553402117:
        if (26378540n) {
          calcs += "^b[14] -= b[35] + b[18] + b[2] + b[22] + b[33] + b[25] + 213;"
          calcs += "^b[14] &= 0xFF;"
        } else {
          calcs += "^b[4] ^= (b[27] + b[32] + b[9] + b[26] + b[0] + b[22] + 3) & 0xFF;"
        }
        state = 14136054;
        continue;
      case 554560760:
        if (318838448) {
          calcs += "^b[36] ^= (b[5] + b[29] + b[38] + b[0] + b[11] + b[33] + 237) & 0xFF;"
        } else {
          calcs += "^b[33] += b[34] + b[30] + b[39] + b[37] + b[13] + b[4] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[33] &= 0xFF;"
        }
        state = 686518099;
        continue;
      case 554792969:
        if (Math.random() < 0.5) {
          calcs += "^b[34] += b[37] + b[2] + b[43] + b[28] + b[16] + b[30] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[34] &= 0xFF;"
        } else {
          calcs += "^b[43] -= b[26] + b[31] + b[27] + b[15] + b[3] + b[2] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[43] &= 0xFF;"
        }
        state = 35618104;
        continue;
      case 555231932:
        if (Math.random() < 0.5) {
          calcs += "^b[43] -= b[12] + b[26] + b[7] + b[22] + b[6] + b[36] + 171;"
          calcs += "^b[43] &= 0xFF;"
        } else {
          calcs += "^b[27] ^= (b[19] + b[2] + b[40] + b[14] + b[9] + b[36] + 147) & 0xFF;"
        }
        state = 199784487;
        continue;
      case 555609705:
        if (16585972n) {
          calcs += "^b[5] += b[28] + b[42] + b[41] + b[4] + b[27] + b[29] + 58;"
          calcs += "^b[5] &= 0xFF;"
        } else {
          calcs += "^b[14] ^= (b[17] + b[37] + b[26] + b[33] + b[3] + b[30] + 57) & 0xFF;"
        }
        state = 792426478;
        continue;
      case 556468793:
        if (89742293n) {
          calcs += "^b[42] ^= (b[39] + b[34] + b[12] + b[22] + b[19] + b[7] + " + Math.floor(Math.random() * 256) + ") & 0xFF;"
        } else {
          calcs += "^b[33] ^= (b[27] + b[25] + b[4] + b[20] + b[16] + b[26] + 206) & 0xFF;"
        }
        state = 15344400;
        continue;
      case 557105857:
        if (310911925) {
          calcs += "^b[40] ^= (b[20] + b[38] + b[12] + b[11] + b[25] + b[5] + 85) & 0xFF;"
        } else {
          calcs += "^b[39] += b[28] + b[8] + b[36] + b[42] + b[11] + b[13] + 68;"
          calcs += "^b[39] &= 0xFF;"
        }
        state = 209310950;
        continue;
      case 558792733:
        if (687814616) {
          calcs += "^b[40] -= b[32] + b[5] + b[6] + b[19] + b[10] + b[25] + 165;"
          calcs += "^b[40] &= 0xFF;"
        } else {
          calcs += "^b[14] += b[20] + b[11] + b[21] + b[38] + b[28] + b[6] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[14] &= 0xFF;"
        }
        state = 674074337;
        continue;
      case 560046327:
        if (Math.random() < 0.5) {
          calcs += "^b[28] -= b[0] + b[37] + b[38] + b[2] + b[14] + b[35] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[28] &= 0xFF;"
        } else {
          calcs += "^b[5] += b[25] + b[38] + b[18] + b[34] + b[24] + b[20] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[5] &= 0xFF;"
        }
        state = 254183340;
        continue;
      case 560687081:
        if (548224734) {
          calcs += "^b[20] -= b[11] + b[23] + b[2] + b[40] + b[26] + b[42] + 150;"
          calcs += "^b[20] &= 0xFF;"
        } else {
          calcs += "^b[26] -= b[23] + b[24] + b[34] + b[11] + b[15] + b[3] + 125;"
          calcs += "^b[26] &= 0xFF;"
        }
        state = 72472653;
        continue;
      case 561687718:
        if (Math.random() < 0.5) {
          calcs += "^b[7] -= b[19] + b[32] + b[13] + b[29] + b[35] + b[43] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[7] &= 0xFF;"
        } else {
          calcs += "^b[8] ^= (b[39] + b[36] + b[30] + b[29] + b[4] + b[12] + 210) & 0xFF;"
        }
        state = 274096784;
        continue;
      case 562103074:
        if (Math.random() < 0.5) {
          calcs += "^b[31] += b[18] + b[27] + b[4] + b[7] + b[2] + b[1] + 49;"
          calcs += "^b[31] &= 0xFF;"
        } else {
          calcs += "^b[28] ^= (b[40] + b[17] + b[20] + b[35] + b[1] + b[6] + " + Math.floor(Math.random() * 256) + ") & 0xFF;"
        }
        state = 317299350;
        continue;
      case 562827068:
        if (Math.random() < 0.5) {
          calcs += "^b[41] ^= (b[4] + b[20] + b[27] + b[2] + b[43] + b[14] + 188) & 0xFF;"
        } else {
          calcs += "^b[11] += b[17] + b[6] + b[7] + b[32] + b[3] + b[33] + 162;"
          calcs += "^b[11] &= 0xFF;"
        }
        state = 184931823;
        continue;
      case 563644357:
        if (26552054n) {
          calcs += "^b[30] ^= (b[43] + b[42] + b[19] + b[3] + b[11] + b[23] + 221) & 0xFF;"
        } else {
          calcs += "^b[20] ^= (b[36] + b[42] + b[19] + b[35] + b[31] + b[7] + 177) & 0xFF;"
        }
        state = 1007616046;
        continue;
      case 564468417:
        if (Math.random() < 0.5) {
          calcs += "^b[21] += b[30] + b[35] + b[32] + b[5] + b[27] + b[41] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[21] &= 0xFF;"
        } else {
          calcs += "^b[38] ^= (b[20] + b[9] + b[32] + b[2] + b[17] + b[3] + 160) & 0xFF;"
        }
        state = 927050473;
        continue;
      case 564903350:
        if (95267329n) {
          calcs += "^b[29] += b[34] + b[20] + b[11] + b[42] + b[8] + b[4] + 206;"
          calcs += "^b[29] &= 0xFF;"
        } else {
          calcs += "^b[13] += b[14] + b[35] + b[43] + b[3] + b[16] + b[31] + 210;"
          calcs += "^b[13] &= 0xFF;"
        }
        state = 50284561;
        continue;
      case 565632760:
        if (339196849) {
          calcs += "^b[20] += b[32] + b[27] + b[24] + b[15] + b[29] + b[23] + 216;"
          calcs += "^b[20] &= 0xFF;"
        } else {
          calcs += "^b[17] ^= (b[21] + b[31] + b[9] + b[10] + b[1] + b[18] + " + Math.floor(Math.random() * 256) + ") & 0xFF;"
        }
        state = 563121711;
        continue;
      case 566073241:
        if (Math.random() < 0.5) {
          calcs += "^b[33] += b[18] + b[31] + b[4] + b[9] + b[35] + b[10] + 49;"
          calcs += "^b[33] &= 0xFF;"
        } else {
          calcs += "^b[34] -= b[20] + b[26] + b[1] + b[21] + b[12] + b[28] + 37;"
          calcs += "^b[34] &= 0xFF;"
        }
        state = 477963635;
        continue;
      case 566575688:
        if (31552222n) {
          calcs += "^b[34] += b[43] + b[38] + b[21] + b[19] + b[27] + b[22] + 45;"
          calcs += "^b[34] &= 0xFF;"
        } else {
          calcs += "^b[2] ^= (b[8] + b[28] + b[29] + b[26] + b[37] + b[39] + 54) & 0xFF;"
        }
        state = 259570273;
        continue;
      case 568152286:
        if (44960329n) {
          calcs += "^b[22] ^= (b[42] + b[30] + b[35] + b[29] + b[31] + b[17] + 146) & 0xFF;"
        } else {
          calcs += "^b[37] ^= (b[25] + b[1] + b[15] + b[42] + b[3] + b[40] + 77) & 0xFF;"
        }
        state = 748081104;
        continue;
      case 570515134:
        if (979576217) {
          calcs += "^b[36] ^= (b[23] + b[6] + b[35] + b[12] + b[37] + b[42] + 82) & 0xFF;"
        } else {
          calcs += "^b[12] += b[40] + b[9] + b[38] + b[37] + b[36] + b[31] + 169;"
          calcs += "^b[12] &= 0xFF;"
        }
        state = 789323608;
        continue;
      case 572264589:
        if (166324608) {
          calcs += "^b[15] ^= (b[24] + b[23] + b[35] + b[30] + b[27] + b[21] + " + Math.floor(Math.random() * 256) + ") & 0xFF;"
        } else {
          calcs += "^b[29] -= b[42] + b[12] + b[2] + b[24] + b[6] + b[39] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[29] &= 0xFF;"
        }
        state = 447942078;
        continue;
      case 572340455:
        if (Math.random() < 0.5) {
          calcs += "^b[18] += b[22] + b[24] + b[25] + b[40] + b[27] + b[42] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[18] &= 0xFF;"
        } else {
          calcs += "^b[4] += b[42] + b[8] + b[39] + b[2] + b[33] + b[40] + 238;"
          calcs += "^b[4] &= 0xFF;"
        }
        state = 585321356;
        continue;
      case 572478164:
        if (231317713) {
          calcs += "^b[26] += b[24] + b[27] + b[2] + b[16] + b[13] + b[17] + 8;"
          calcs += "^b[26] &= 0xFF;"
        } else {
          calcs += "^b[35] ^= (b[4] + b[0] + b[29] + b[18] + b[28] + b[22] + 218) & 0xFF;"
        }
        state = 412568688;
        continue;
      case 574228050:
        if (868513606) {
          calcs += "^b[18] += b[22] + b[2] + b[36] + b[0] + b[23] + b[10] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[18] &= 0xFF;"
        } else {
          calcs += "^b[34] ^= (b[23] + b[28] + b[8] + b[20] + b[33] + b[5] + 71) & 0xFF;"
        }
        state = 716822359;
        continue;
      case 574604877:
        if (69552519) {
          calcs += "^b[13] ^= (b[12] + b[30] + b[24] + b[35] + b[42] + b[25] + 30) & 0xFF;"
        } else {
          calcs += "^b[5] += b[0] + b[12] + b[27] + b[2] + b[1] + b[35] + 45;"
          calcs += "^b[5] &= 0xFF;"
        }
        state = 967061579;
        continue;
      case 576084841:
        if (Math.random() < 0.5) {
          calcs += "^b[33] += b[34] + b[4] + b[21] + b[12] + b[8] + b[14] + 197;"
          calcs += "^b[33] &= 0xFF;"
        } else {
          calcs += "^b[29] -= b[40] + b[39] + b[8] + b[19] + b[37] + b[11] + 9;"
          calcs += "^b[29] &= 0xFF;"
        }
        state = 594479345;
        continue;
      case 576314831:
        if (Math.random() < 0.5) {
          calcs += "^b[14] ^= (b[32] + b[41] + b[35] + b[40] + b[9] + b[22] + 63) & 0xFF;"
        } else {
          calcs += "^b[20] ^= (b[2] + b[40] + b[1] + b[41] + b[11] + b[38] + 151) & 0xFF;"
        }
        state = 48990882;
        continue;
      case 576642022:
        if (62603993n) {
          calcs += "^b[3] += b[39] + b[2] + b[43] + b[24] + b[5] + b[23] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[3] &= 0xFF;"
        } else {
          calcs += "^b[43] -= b[22] + b[36] + b[21] + b[13] + b[6] + b[8] + 202;"
          calcs += "^b[43] &= 0xFF;"
        }
        state = 581077939;
        continue;
      case 577785340:
        if (165327969) {
          calcs += "^b[10] -= b[31] + b[29] + b[28] + b[26] + b[18] + b[22] + 107;"
          calcs += "^b[10] &= 0xFF;"
        } else {
          calcs += "^b[27] -= b[7] + b[1] + b[42] + b[29] + b[32] + b[16] + 128;"
          calcs += "^b[27] &= 0xFF;"
        }
        state = 915743214;
        continue;
      case 578359911:
        if (320874086) {
          calcs += "^b[36] ^= (b[26] + b[23] + b[38] + b[28] + b[13] + b[11] + 113) & 0xFF;"
        } else {
          calcs += "^b[33] += b[4] + b[27] + b[32] + b[43] + b[42] + b[36] + 209;"
          calcs += "^b[33] &= 0xFF;"
        }
        state = 409377776;
        continue;
      case 578413895:
        if (Math.random() < 0.5) {
          calcs += "^b[6] -= b[28] + b[7] + b[35] + b[4] + b[21] + b[27] + 125;"
          calcs += "^b[6] &= 0xFF;"
        } else {
          calcs += "^b[1] ^= (b[12] + b[17] + b[21] + b[38] + b[34] + b[39] + 199) & 0xFF;"
        }
        state = 692575212;
        continue;
      case 578961221:
        if (58528544n) {
          calcs += "^b[40] ^= (b[7] + b[4] + b[6] + b[31] + b[16] + b[35] + 33) & 0xFF;"
        } else {
          calcs += "^b[37] ^= (b[33] + b[7] + b[1] + b[35] + b[36] + b[19] + 206) & 0xFF;"
        }
        state = 270652468;
        continue;
      case 580191415:
        if (Math.random() < 0.5) {
          calcs += "^b[33] += b[25] + b[12] + b[14] + b[34] + b[4] + b[36] + 185;"
          calcs += "^b[33] &= 0xFF;"
        } else {
          calcs += "^b[12] ^= (b[33] + b[5] + b[0] + b[38] + b[27] + b[37] + 160) & 0xFF;"
        }
        state = 308723491;
        continue;
      case 580712029:
        if (899628882) {
          calcs += "^b[16] ^= (b[37] + b[14] + b[38] + b[3] + b[23] + b[31] + " + Math.floor(Math.random() * 256) + ") & 0xFF;"
        } else {
          calcs += "^b[9] += b[37] + b[41] + b[4] + b[20] + b[0] + b[18] + 175;"
          calcs += "^b[9] &= 0xFF;"
        }
        state = 37616705;
        continue;
      case 581736057:
        if (1035931366) {
          calcs += "^b[43] += b[20] + b[38] + b[23] + b[31] + b[32] + b[2] + 73;"
          calcs += "^b[43] &= 0xFF;"
        } else {
          calcs += "^b[6] ^= (b[36] + b[13] + b[4] + b[38] + b[16] + b[14] + 53) & 0xFF;"
        }
        state = 78689437;
        continue;
      case 582215318:
        if (167363775) {
          calcs += "^b[18] ^= (b[31] + b[40] + b[4] + b[2] + b[36] + b[43] + 107) & 0xFF;"
        } else {
          calcs += "^b[31] ^= (b[28] + b[32] + b[14] + b[26] + b[18] + b[35] + 246) & 0xFF;"
        }
        state = 929898000;
        continue;
      case 582631280:
        if (Math.random() < 0.5) {
          calcs += "^b[13] += b[5] + b[19] + b[4] + b[33] + b[21] + b[23] + 189;"
          calcs += "^b[13] &= 0xFF;"
        } else {
          calcs += "^b[13] ^= (b[34] + b[25] + b[40] + b[6] + b[39] + b[17] + 19) & 0xFF;"
        }
        state = 490243398;
        continue;
      case 583775143:
        if (811609953) {
          calcs += "^b[31] += b[23] + b[43] + b[37] + b[32] + b[19] + b[11] + 188;"
          calcs += "^b[31] &= 0xFF;"
        } else {
          calcs += "^b[4] ^= (b[8] + b[33] + b[19] + b[12] + b[25] + b[15] + 101) & 0xFF;"
        }
        state = 661538186;
        continue;
      case 585159232:
        if (76612926n) {
          calcs += "^b[39] -= b[6] + b[26] + b[22] + b[12] + b[14] + b[11] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[39] &= 0xFF;"
        } else {
          calcs += "^b[34] -= b[33] + b[41] + b[11] + b[15] + b[32] + b[31] + 254;"
          calcs += "^b[34] &= 0xFF;"
        }
        state = 814764410;
        continue;
      case 585872335:
        if (Math.random() < 0.5) {
          calcs += "^b[3] ^= (b[4] + b[30] + b[13] + b[42] + b[16] + b[43] + 240) & 0xFF;"
        } else {
          calcs += "^b[36] += b[9] + b[3] + b[31] + b[41] + b[8] + b[22] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[36] &= 0xFF;"
        }
        state = 765137136;
        continue;
      case 586332565:
        if (825998263) {
          calcs += "^b[7] += b[16] + b[22] + b[40] + b[12] + b[31] + b[30] + 5;"
          calcs += "^b[7] &= 0xFF;"
        } else {
          calcs += "^b[15] ^= (b[2] + b[43] + b[3] + b[5] + b[0] + b[35] + 10) & 0xFF;"
        }
        state = 1031907891;
        continue;
      case 586678375:
        if (77156621n) {
          calcs += "^b[11] ^= (b[17] + b[13] + b[40] + b[26] + b[24] + b[8] + " + Math.floor(Math.random() * 256) + ") & 0xFF;"
        } else {
          calcs += "^b[13] ^= (b[41] + b[12] + b[22] + b[28] + b[42] + b[40] + " + Math.floor(Math.random() * 256) + ") & 0xFF;"
        }
        state = 428507411;
        continue;
      case 588207953:
        if (Math.random() < 0.5) {
          calcs += "^b[38] ^= (b[30] + b[0] + b[1] + b[40] + b[6] + b[39] + 113) & 0xFF;"
        } else {
          calcs += "^b[24] ^= (b[14] + b[33] + b[2] + b[26] + b[19] + b[8] + 75) & 0xFF;"
        }
        state = 497816624;
        continue;
      case 588222361:
        if (Math.random() < 0.5) {
          calcs += "^b[8] += b[20] + b[37] + b[25] + b[4] + b[41] + b[38] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[8] &= 0xFF;"
        } else {
          calcs += "^b[16] ^= (b[11] + b[30] + b[37] + b[26] + b[6] + b[33] + 43) & 0xFF;"
        }
        state = 651965560;
        continue;
      case 589379043:
        if (Math.random() < 0.5) {
          calcs += "^b[33] += b[21] + b[9] + b[31] + b[6] + b[20] + b[11] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[33] &= 0xFF;"
        } else {
          calcs += "^b[34] ^= (b[38] + b[33] + b[13] + b[26] + b[6] + b[5] + 67) & 0xFF;"
        }
        state = 713170640;
        continue;
      case 590666725:
        if (19494224n) {
          calcs += "^b[23] -= b[0] + b[35] + b[11] + b[34] + b[13] + b[27] + 241;"
          calcs += "^b[23] &= 0xFF;"
        } else {
          calcs += "^b[38] ^= (b[17] + b[28] + b[4] + b[18] + b[11] + b[3] + 133) & 0xFF;"
        }
        state = 896388973;
        continue;
      case 591243892:
        if (40429544n) {
          calcs += "^b[10] += b[24] + b[28] + b[12] + b[3] + b[34] + b[8] + 83;"
          calcs += "^b[10] &= 0xFF;"
        } else {
          calcs += "^b[24] ^= (b[9] + b[0] + b[28] + b[27] + b[21] + b[33] + " + Math.floor(Math.random() * 256) + ") & 0xFF;"
        }
        state = 593902528;
        continue;
      case 593231004:
        if (Math.random() < 0.5) {
          calcs += "^b[35] -= b[39] + b[12] + b[36] + b[2] + b[9] + b[30] + 167;"
          calcs += "^b[35] &= 0xFF;"
        } else {
          calcs += "^b[16] += b[43] + b[4] + b[3] + b[35] + b[14] + b[31] + 187;"
          calcs += "^b[16] &= 0xFF;"
        }
        state = 220027931;
        continue;
      case 594440623:
        if (88077007n) {
          calcs += "^b[3] -= b[26] + b[35] + b[23] + b[36] + b[10] + b[5] + 33;"
          calcs += "^b[3] &= 0xFF;"
        } else {
          calcs += "^b[0] += b[24] + b[29] + b[41] + b[6] + b[19] + b[13] + 57;"
          calcs += "^b[0] &= 0xFF;"
        }
        state = 940304756;
        continue;
      case 596471964:
        if (958012310) {
          calcs += "^b[39] += b[23] + b[34] + b[11] + b[26] + b[18] + b[27] + 88;"
          calcs += "^b[39] &= 0xFF;"
        } else {
          calcs += "^b[11] ^= (b[40] + b[18] + b[21] + b[31] + b[5] + b[15] + 125) & 0xFF;"
        }
        state = 960293800;
        continue;
      case 598167998:
        if (72917820n) {
          calcs += "^b[7] += b[1] + b[26] + b[15] + b[24] + b[13] + b[31] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[7] &= 0xFF;"
        } else {
          calcs += "^b[13] -= b[2] + b[17] + b[41] + b[14] + b[1] + b[18] + 68;"
          calcs += "^b[13] &= 0xFF;"
        }
        state = 1019853179;
        continue;
      case 598261111:
        if (Math.random() < 0.5) {
          calcs += "^b[3] += b[0] + b[4] + b[40] + b[37] + b[27] + b[18] + 99;"
          calcs += "^b[3] &= 0xFF;"
        } else {
          calcs += "^b[7] ^= (b[5] + b[37] + b[18] + b[12] + b[27] + b[21] + " + Math.floor(Math.random() * 256) + ") & 0xFF;"
        }
        state = 3871500;
        continue;
      case 602845621:
        if (Math.random() < 0.5) {
          calcs += "^b[4] -= b[14] + b[8] + b[32] + b[27] + b[35] + b[36] + 124;"
          calcs += "^b[4] &= 0xFF;"
        } else {
          calcs += "^b[31] += b[29] + b[22] + b[15] + b[10] + b[36] + b[18] + 227;"
          calcs += "^b[31] &= 0xFF;"
        }
        state = 646498467;
        continue;
      case 604377705:
        if (63685605n) {
          calcs += "^b[31] ^= (b[1] + b[16] + b[23] + b[25] + b[29] + b[4] + 2) & 0xFF;"
        } else {
          calcs += "^b[33] += b[38] + b[9] + b[6] + b[28] + b[37] + b[32] + 174;"
          calcs += "^b[33] &= 0xFF;"
        }
        state = 92754704;
        continue;
      case 605458814:
        if (226426204) {
          calcs += "^b[14] += b[23] + b[25] + b[33] + b[8] + b[13] + b[31] + 132;"
          calcs += "^b[14] &= 0xFF;"
        } else {
          calcs += "^b[39] += b[42] + b[10] + b[3] + b[41] + b[14] + b[26] + 177;"
          calcs += "^b[39] &= 0xFF;"
        }
        state = 37622359;
        continue;
      case 606417521:
        if (95776195n) {
          calcs += "^b[42] ^= (b[3] + b[8] + b[11] + b[31] + b[20] + b[15] + 1) & 0xFF;"
        } else {
          calcs += "^b[29] += b[10] + b[28] + b[19] + b[38] + b[1] + b[31] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[29] &= 0xFF;"
        }
        state = 274960738;
        continue;
      case 607021784:
        if (51319275n) {
          calcs += "^b[23] -= b[16] + b[12] + b[33] + b[43] + b[24] + b[41] + 233;"
          calcs += "^b[23] &= 0xFF;"
        } else {
          calcs += "^b[36] -= b[7] + b[21] + b[15] + b[29] + b[31] + b[2] + 130;"
          calcs += "^b[36] &= 0xFF;"
        }
        state = 864278364;
        continue;
      case 607284248:
        if (2932515) {
          calcs += "^b[30] -= b[4] + b[3] + b[13] + b[38] + b[7] + b[31] + 90;"
          calcs += "^b[30] &= 0xFF;"
        } else {
          calcs += "^b[23] += b[18] + b[1] + b[38] + b[22] + b[20] + b[4] + 124;"
          calcs += "^b[23] &= 0xFF;"
        }
        state = 271342539;
        continue;
      case 607680747:
        if (Math.random() < 0.5) {
          calcs += "^b[16] += b[13] + b[41] + b[6] + b[3] + b[29] + b[39] + 206;"
          calcs += "^b[16] &= 0xFF;"
        } else {
          calcs += "^b[39] += b[29] + b[17] + b[11] + b[14] + b[37] + b[12] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[39] &= 0xFF;"
        }
        state = 348572019;
        continue;
      case 609213482:
        if (63582671n) {
          calcs += "^b[5] ^= (b[36] + b[13] + b[3] + b[12] + b[2] + b[39] + 175) & 0xFF;"
        } else {
          calcs += "^b[21] += b[32] + b[16] + b[27] + b[17] + b[10] + b[15] + 37;"
          calcs += "^b[21] &= 0xFF;"
        }
        state = 56000485;
        continue;
      case 610067499:
        if (16096322n) {
          calcs += "^b[7] -= b[11] + b[43] + b[13] + b[8] + b[19] + b[23] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[7] &= 0xFF;"
        } else {
          calcs += "^b[34] += b[16] + b[38] + b[1] + b[42] + b[14] + b[9] + 192;"
          calcs += "^b[34] &= 0xFF;"
        }
        state = 30360870;
        continue;
      case 610287656:
        if (Math.random() < 0.5) {
          calcs += "^b[9] ^= (b[4] + b[11] + b[37] + b[14] + b[41] + b[33] + 247) & 0xFF;"
        } else {
          calcs += "^b[2] ^= (b[15] + b[40] + b[14] + b[19] + b[8] + b[25] + " + Math.floor(Math.random() * 256) + ") & 0xFF;"
        }
        state = 386676293;
        continue;
      case 610501194:
        if (483948646) {
          calcs += "^b[0] += b[18] + b[32] + b[30] + b[39] + b[37] + b[1] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[0] &= 0xFF;"
        } else {
          calcs += "^b[41] += b[13] + b[30] + b[12] + b[1] + b[22] + b[16] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[41] &= 0xFF;"
        }
        state = 444526998;
        continue;
      case 610772468:
        if (Math.random() < 0.5) {
          calcs += "^b[28] += b[43] + b[23] + b[7] + b[18] + b[25] + b[30] + 99;"
          calcs += "^b[28] &= 0xFF;"
        } else {
          calcs += "^b[0] ^= (b[21] + b[1] + b[27] + b[17] + b[8] + b[31] + " + Math.floor(Math.random() * 256) + ") & 0xFF;"
        }
        state = 926668633;
        continue;
      case 613252913:
        if (366977379) {
          calcs += "^b[18] -= b[19] + b[11] + b[38] + b[5] + b[14] + b[26] + 52;"
          calcs += "^b[18] &= 0xFF;"
        } else {
          calcs += "^b[21] ^= (b[20] + b[38] + b[14] + b[15] + b[1] + b[13] + 81) & 0xFF;"
        }
        state = 109283112;
        continue;
      case 613597816:
        if (206260547) {
          calcs += "^b[36] += b[20] + b[14] + b[3] + b[41] + b[10] + b[31] + 237;"
          calcs += "^b[36] &= 0xFF;"
        } else {
          calcs += "^b[42] += b[36] + b[41] + b[12] + b[21] + b[19] + b[23] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[42] &= 0xFF;"
        }
        state = 786401873;
        continue;
      case 613821870:
        if (Math.random() < 0.5) {
          calcs += "^b[19] ^= (b[12] + b[1] + b[34] + b[8] + b[4] + b[37] + 22) & 0xFF;"
        } else {
          calcs += "^b[28] += b[13] + b[38] + b[12] + b[17] + b[7] + b[22] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[28] &= 0xFF;"
        }
        state = 538093015;
        continue;
      case 615167515:
        if (325293838) {
          calcs += "^b[10] ^= (b[36] + b[1] + b[15] + b[31] + b[14] + b[32] + 177) & 0xFF;"
        } else {
          calcs += "^b[5] -= b[31] + b[43] + b[1] + b[8] + b[6] + b[41] + 246;"
          calcs += "^b[5] &= 0xFF;"
        }
        state = 409990561;
        continue;
      case 617252180:
        if (Math.random() < 0.5) {
          calcs += "^b[10] -= b[37] + b[36] + b[26] + b[9] + b[24] + b[7] + 86;"
          calcs += "^b[10] &= 0xFF;"
        } else {
          calcs += "^b[21] += b[4] + b[33] + b[30] + b[16] + b[27] + b[5] + 192;"
          calcs += "^b[21] &= 0xFF;"
        }
        state = 104808741;
        continue;
      case 617270605:
        if (40813803n) {
          calcs += "^b[4] -= b[28] + b[38] + b[37] + b[5] + b[32] + b[13] + 47;"
          calcs += "^b[4] &= 0xFF;"
        } else {
          calcs += "^b[15] -= b[38] + b[43] + b[7] + b[11] + b[22] + b[18] + 164;"
          calcs += "^b[15] &= 0xFF;"
        }
        state = 233632316;
        continue;
      case 618349901:
        if (26484079n) {
          calcs += "^b[11] ^= (b[24] + b[26] + b[20] + b[28] + b[15] + b[35] + " + Math.floor(Math.random() * 256) + ") & 0xFF;"
        } else {
          calcs += "^b[19] -= b[22] + b[18] + b[8] + b[10] + b[34] + b[14] + 150;"
          calcs += "^b[19] &= 0xFF;"
        }
        state = 886795061;
        continue;
      case 618469040:
        if (898758855) {
          calcs += "^b[21] += b[12] + b[27] + b[43] + b[38] + b[36] + b[16] + 206;"
          calcs += "^b[21] &= 0xFF;"
        } else {
          calcs += "^b[20] -= b[6] + b[41] + b[42] + b[28] + b[30] + b[12] + 226;"
          calcs += "^b[20] &= 0xFF;"
        }
        state = 243547964;
        continue;
      case 619249680:
        if (48705217n) {
          calcs += "^b[21] -= b[4] + b[31] + b[25] + b[22] + b[2] + b[3] + 237;"
          calcs += "^b[21] &= 0xFF;"
        } else {
          calcs += "^b[1] ^= (b[7] + b[15] + b[29] + b[26] + b[37] + b[18] + 154) & 0xFF;"
        }
        state = 469446573;
        continue;
      case 619255339:
        if (Math.random() < 0.5) {
          calcs += "^b[8] += b[31] + b[12] + b[36] + b[11] + b[13] + b[43] + 149;"
          calcs += "^b[8] &= 0xFF;"
        } else {
          calcs += "^b[34] += b[30] + b[17] + b[38] + b[41] + b[5] + b[42] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[34] &= 0xFF;"
        }
        state = 562829538;
        continue;
      case 620144002:
        if (575631725) {
          calcs += "^b[11] -= b[24] + b[43] + b[29] + b[7] + b[35] + b[20] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[11] &= 0xFF;"
        } else {
          calcs += "^b[40] ^= (b[35] + b[22] + b[9] + b[31] + b[23] + b[12] + " + Math.floor(Math.random() * 256) + ") & 0xFF;"
        }
        state = 188924010;
        continue;
      case 623102886:
        if (215125179) {
          calcs += "^b[18] += b[36] + b[23] + b[30] + b[7] + b[37] + b[6] + 255;"
          calcs += "^b[18] &= 0xFF;"
        } else {
          calcs += "^b[43] -= b[36] + b[23] + b[15] + b[21] + b[32] + b[38] + 79;"
          calcs += "^b[43] &= 0xFF;"
        }
        state = 233083443;
        continue;
      case 624024080:
        if (Math.random() < 0.5) {
          calcs += "^b[12] -= b[4] + b[24] + b[1] + b[18] + b[40] + b[33] + 48;"
          calcs += "^b[12] &= 0xFF;"
        } else {
          calcs += "^b[22] -= b[41] + b[21] + b[8] + b[10] + b[27] + b[31] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[22] &= 0xFF;"
        }
        state = 1036651800;
        continue;
      case 624483777:
        if (Math.random() < 0.5) {
          calcs += "^b[12] -= b[18] + b[2] + b[17] + b[7] + b[41] + b[32] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[12] &= 0xFF;"
        } else {
          calcs += "^b[15] -= b[28] + b[4] + b[23] + b[16] + b[17] + b[20] + 168;"
          calcs += "^b[15] &= 0xFF;"
        }
        state = 330849011;
        continue;
      case 625706758:
        if (185443289) {
          calcs += "^b[5] ^= (b[21] + b[38] + b[28] + b[43] + b[42] + b[33] + 1) & 0xFF;"
        } else {
          calcs += "^b[43] += b[26] + b[3] + b[25] + b[0] + b[31] + b[21] + 81;"
          calcs += "^b[43] &= 0xFF;"
        }
        state = 828428928;
        continue;
      case 627583527:
        if (Math.random() < 0.5) {
          calcs += "^b[6] -= b[30] + b[19] + b[40] + b[22] + b[26] + b[10] + 35;"
          calcs += "^b[6] &= 0xFF;"
        } else {
          calcs += "^b[35] ^= (b[14] + b[24] + b[26] + b[32] + b[7] + b[19] + " + Math.floor(Math.random() * 256) + ") & 0xFF;"
        }
        state = 358665688;
        continue;
      case 627838396:
        if (Math.random() < 0.5) {
          calcs += "^b[39] -= b[26] + b[2] + b[35] + b[11] + b[23] + b[14] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[39] &= 0xFF;"
        } else {
          calcs += "^b[20] += b[34] + b[25] + b[10] + b[3] + b[31] + b[37] + 136;"
          calcs += "^b[20] &= 0xFF;"
        }
        state = 859357642;
        continue;
      case 629242776:
        if (497580571) {
          calcs += "^b[16] ^= (b[37] + b[41] + b[6] + b[0] + b[20] + b[40] + 1) & 0xFF;"
        } else {
          calcs += "^b[11] += b[5] + b[30] + b[23] + b[35] + b[26] + b[41] + 80;"
          calcs += "^b[11] &= 0xFF;"
        }
        state = 429343547;
        continue;
      case 630925076:
        if (894602643) {
          calcs += "^b[16] ^= (b[5] + b[35] + b[12] + b[29] + b[9] + b[36] + " + Math.floor(Math.random() * 256) + ") & 0xFF;"
        } else {
          calcs += "^b[10] -= b[12] + b[16] + b[30] + b[9] + b[34] + b[13] + 121;"
          calcs += "^b[10] &= 0xFF;"
        }
        state = 663095210;
        continue;
      case 631842634:
        if (88975787n) {
          calcs += "^b[42] += b[31] + b[14] + b[24] + b[28] + b[11] + b[10] + 23;"
          calcs += "^b[42] &= 0xFF;"
        } else {
          calcs += "^b[41] ^= (b[2] + b[38] + b[5] + b[9] + b[23] + b[31] + " + Math.floor(Math.random() * 256) + ") & 0xFF;"
        }
        state = 34893457;
        continue;
      case 631991648:
        if (33861635n) {
          calcs += "^b[13] += b[39] + b[5] + b[27] + b[43] + b[23] + b[31] + 30;"
          calcs += "^b[13] &= 0xFF;"
        } else {
          calcs += "^b[23] += b[38] + b[34] + b[9] + b[36] + b[1] + b[3] + 112;"
          calcs += "^b[23] &= 0xFF;"
        }
        state = 116368186;
        continue;
      case 632677318:
        if (116397922) {
          calcs += "^b[34] -= b[16] + b[22] + b[17] + b[6] + b[15] + b[32] + 5;"
          calcs += "^b[34] &= 0xFF;"
        } else {
          calcs += "^b[8] += b[36] + b[38] + b[6] + b[33] + b[27] + b[32] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[8] &= 0xFF;"
        }
        state = 848123506;
        continue;
      case 633013038:
        if (Math.random() < 0.5) {
          calcs += "^b[34] -= b[6] + b[41] + b[33] + b[2] + b[31] + b[24] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[34] &= 0xFF;"
        } else {
          calcs += "^b[30] ^= (b[14] + b[19] + b[24] + b[22] + b[6] + b[10] + 80) & 0xFF;"
        }
        state = 159141862;
        continue;
      case 633234283:
        if (172370898) {
          calcs += "^b[11] ^= (b[4] + b[21] + b[31] + b[28] + b[41] + b[30] + 50) & 0xFF;"
        } else {
          calcs += "^b[6] += b[17] + b[7] + b[32] + b[39] + b[31] + b[14] + 1;"
          calcs += "^b[6] &= 0xFF;"
        }
        state = 848576990;
        continue;
      case 633718801:
        if (436903069) {
          calcs += "^b[37] -= b[35] + b[30] + b[18] + b[20] + b[24] + b[13] + 32;"
          calcs += "^b[37] &= 0xFF;"
        } else {
          calcs += "^b[5] += b[26] + b[22] + b[39] + b[0] + b[36] + b[4] + 1;"
          calcs += "^b[5] &= 0xFF;"
        }
        state = 469553896;
        continue;
      case 635066656:
        if (13205359n) {
          calcs += "^b[33] -= b[12] + b[5] + b[42] + b[2] + b[21] + b[15] + 201;"
          calcs += "^b[33] &= 0xFF;"
        } else {
          calcs += "^b[36] ^= (b[35] + b[5] + b[6] + b[37] + b[17] + b[4] + " + Math.floor(Math.random() * 256) + ") & 0xFF;"
        }
        state = 413758209;
        continue;
      case 635490398:
        if (Math.random() < 0.5) {
          calcs += "^b[28] -= b[7] + b[12] + b[18] + b[30] + b[27] + b[10] + 24;"
          calcs += "^b[28] &= 0xFF;"
        } else {
          calcs += "^b[6] ^= (b[5] + b[30] + b[4] + b[39] + b[23] + b[18] + 216) & 0xFF;"
        }
        state = 881210763;
        continue;
      case 635714957:
        if (821608104) {
          calcs += "^b[9] += b[36] + b[23] + b[18] + b[0] + b[17] + b[15] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[9] &= 0xFF;"
        } else {
          calcs += "^b[40] += b[13] + b[3] + b[43] + b[31] + b[22] + b[25] + 49;"
          calcs += "^b[40] &= 0xFF;"
        }
        state = 209721591;
        continue;
      case 636356544:
        if (Math.random() < 0.5) {
          calcs += "^b[23] += b[3] + b[28] + b[4] + b[27] + b[25] + b[10] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[23] &= 0xFF;"
        } else {
          calcs += "^b[27] -= b[15] + b[24] + b[39] + b[35] + b[28] + b[29] + 155;"
          calcs += "^b[27] &= 0xFF;"
        }
        state = 1069796829;
        continue;
      case 638017835:
        if (Math.random() < 0.5) {
          calcs += "^b[11] += b[2] + b[6] + b[43] + b[25] + b[35] + b[26] + 210;"
          calcs += "^b[11] &= 0xFF;"
        } else {
          calcs += "^b[15] += b[36] + b[14] + b[31] + b[0] + b[7] + b[10] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[15] &= 0xFF;"
        }
        state = 688954724;
        continue;
      case 638200464:
        if (83839119n) {
          calcs += "^b[20] += b[16] + b[41] + b[24] + b[25] + b[19] + b[43] + 117;"
          calcs += "^b[20] &= 0xFF;"
        } else {
          calcs += "^b[35] += b[30] + b[7] + b[3] + b[40] + b[20] + b[34] + 255;"
          calcs += "^b[35] &= 0xFF;"
        }
        state = 923299951;
        continue;
      case 639015755:
        if (Math.random() < 0.5) {
          calcs += "^b[20] += b[36] + b[42] + b[12] + b[24] + b[10] + b[14] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[20] &= 0xFF;"
        } else {
          calcs += "^b[16] ^= (b[25] + b[38] + b[43] + b[0] + b[9] + b[15] + 214) & 0xFF;"
        }
        state = 351723496;
        continue;
      case 639995512:
        if (298240906) {
          calcs += "^b[2] -= b[13] + b[43] + b[15] + b[20] + b[31] + b[40] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[2] &= 0xFF;"
        } else {
          calcs += "^b[8] += b[13] + b[4] + b[36] + b[28] + b[17] + b[39] + 118;"
          calcs += "^b[8] &= 0xFF;"
        }
        state = 56462499;
        continue;
      case 640695661:
        if (773031528) {
          calcs += "^b[0] += b[35] + b[27] + b[26] + b[6] + b[37] + b[39] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[0] &= 0xFF;"
        } else {
          calcs += "^b[13] -= b[27] + b[28] + b[15] + b[40] + b[14] + b[8] + 70;"
          calcs += "^b[13] &= 0xFF;"
        }
        state = 1026335212;
        continue;
      case 640966734:
        if (Math.random() < 0.5) {
          calcs += "^b[43] += b[13] + b[2] + b[35] + b[18] + b[32] + b[33] + 61;"
          calcs += "^b[43] &= 0xFF;"
        } else {
          calcs += "^b[14] -= b[33] + b[36] + b[8] + b[6] + b[9] + b[43] + 114;"
          calcs += "^b[14] &= 0xFF;"
        }
        state = 656625414;
        continue;
      case 641186517:
        if (Math.random() < 0.5) {
          calcs += "^b[34] += b[26] + b[0] + b[30] + b[18] + b[29] + b[39] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[34] &= 0xFF;"
        } else {
          calcs += "^b[10] -= b[25] + b[0] + b[28] + b[35] + b[5] + b[30] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[10] &= 0xFF;"
        }
        state = 1036876601;
        continue;
      case 641228928:
        if (942556861) {
          calcs += "^b[25] ^= (b[38] + b[39] + b[2] + b[42] + b[21] + b[27] + 32) & 0xFF;"
        } else {
          calcs += "^b[14] ^= (b[32] + b[30] + b[20] + b[11] + b[3] + b[41] + " + Math.floor(Math.random() * 256) + ") & 0xFF;"
        }
        state = 81518900;
        continue;
      case 642986604:
        if (Math.random() < 0.5) {
          calcs += "^b[20] ^= (b[26] + b[32] + b[10] + b[2] + b[14] + b[21] + 195) & 0xFF;"
        } else {
          calcs += "^b[28] ^= (b[41] + b[26] + b[27] + b[37] + b[21] + b[6] + " + Math.floor(Math.random() * 256) + ") & 0xFF;"
        }
        state = 800885008;
        continue;
      case 643486477:
        if (59362548n) {
          calcs += "^b[26] -= b[7] + b[8] + b[17] + b[31] + b[29] + b[3] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[26] &= 0xFF;"
        } else {
          calcs += "^b[22] += b[43] + b[18] + b[23] + b[42] + b[17] + b[33] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[22] &= 0xFF;"
        }
        state = 240796634;
        continue;
      case 644273762:
        if (905282220) {
          calcs += "^b[16] -= b[36] + b[35] + b[15] + b[39] + b[21] + b[3] + 95;"
          calcs += "^b[16] &= 0xFF;"
        } else {
          calcs += "^b[26] -= b[15] + b[43] + b[11] + b[16] + b[28] + b[30] + 150;"
          calcs += "^b[26] &= 0xFF;"
        }
        state = 445266410;
        continue;
      case 644692480:
        if (Math.random() < 0.5) {
          calcs += "^b[11] ^= (b[36] + b[0] + b[6] + b[21] + b[32] + b[18] + 134) & 0xFF;"
        } else {
          calcs += "^b[9] ^= (b[38] + b[1] + b[4] + b[8] + b[39] + b[24] + 95) & 0xFF;"
        }
        state = 694856073;
        continue;
      case 644893890:
        if (56320674n) {
          calcs += "^b[11] -= b[6] + b[19] + b[33] + b[43] + b[3] + b[21] + 60;"
          calcs += "^b[11] &= 0xFF;"
        } else {
          calcs += "^b[28] += b[24] + b[26] + b[38] + b[16] + b[14] + b[43] + 119;"
          calcs += "^b[28] &= 0xFF;"
        }
        state = 338601963;
        continue;
      case 644948966:
        if (Math.random() < 0.5) {
          calcs += "^b[29] += b[10] + b[1] + b[9] + b[30] + b[18] + b[37] + 138;"
          calcs += "^b[29] &= 0xFF;"
        } else {
          calcs += "^b[18] ^= (b[17] + b[23] + b[35] + b[0] + b[41] + b[5] + 77) & 0xFF;"
        }
        state = 194721612;
        continue;
      case 647939351:
        if (Math.random() < 0.5) {
          calcs += "^b[16] -= b[35] + b[11] + b[36] + b[29] + b[10] + b[26] + 70;"
          calcs += "^b[16] &= 0xFF;"
        } else {
          calcs += "^b[8] += b[30] + b[22] + b[17] + b[0] + b[27] + b[21] + 117;"
          calcs += "^b[8] &= 0xFF;"
        }
        state = 59076117;
        continue;
      case 648641891:
        if (408308558) {
          calcs += "^b[39] ^= (b[7] + b[32] + b[11] + b[35] + b[10] + b[17] + 101) & 0xFF;"
        } else {
          calcs += "^b[25] ^= (b[26] + b[5] + b[0] + b[31] + b[6] + b[39] + 207) & 0xFF;"
        }
        state = 215228651;
        continue;
      case 648694757:
        if (35072631n) {
          calcs += "^b[4] -= b[38] + b[0] + b[13] + b[16] + b[3] + b[18] + 170;"
          calcs += "^b[4] &= 0xFF;"
        } else {
          calcs += "^b[11] ^= (b[25] + b[14] + b[10] + b[15] + b[23] + b[38] + " + Math.floor(Math.random() * 256) + ") & 0xFF;"
        }
        state = 439715360;
        continue;
      case 650908334:
        if (632156730) {
          calcs += "^b[1] ^= (b[3] + b[12] + b[11] + b[4] + b[28] + b[31] + " + Math.floor(Math.random() * 256) + ") & 0xFF;"
        } else {
          calcs += "^b[42] ^= (b[12] + b[43] + b[37] + b[6] + b[19] + b[40] + " + Math.floor(Math.random() * 256) + ") & 0xFF;"
        }
        state = 722855241;
        continue;
      case 651944800:
        if (97668371n) {
          calcs += "^b[39] ^= (b[18] + b[42] + b[32] + b[14] + b[29] + b[10] + 96) & 0xFF;"
        } else {
          calcs += "^b[1] ^= (b[25] + b[41] + b[12] + b[36] + b[34] + b[5] + 14) & 0xFF;"
        }
        state = 720801952;
        continue;
      case 652341782:
        if (852347526) {
          calcs += "^b[27] -= b[38] + b[37] + b[15] + b[0] + b[19] + b[40] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[27] &= 0xFF;"
        } else {
          calcs += "^b[41] -= b[25] + b[0] + b[40] + b[8] + b[5] + b[26] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[41] &= 0xFF;"
        }
        state = 422798983;
        continue;
      case 652355755:
        if (976614841) {
          calcs += "^b[5] += b[43] + b[40] + b[19] + b[26] + b[29] + b[17] + 102;"
          calcs += "^b[5] &= 0xFF;"
        } else {
          calcs += "^b[39] ^= (b[41] + b[25] + b[43] + b[30] + b[11] + b[1] + 63) & 0xFF;"
        }
        state = 617635709;
        continue;
      case 652875761:
        if (416219648) {
          calcs += "^b[38] ^= (b[31] + b[9] + b[8] + b[12] + b[14] + b[16] + 224) & 0xFF;"
        } else {
          calcs += "^b[23] ^= (b[17] + b[16] + b[3] + b[30] + b[24] + b[43] + " + Math.floor(Math.random() * 256) + ") & 0xFF;"
        }
        state = 856977353;
        continue;
      case 653960194:
        if (604879063) {
          calcs += "^b[29] += b[7] + b[3] + b[34] + b[26] + b[19] + b[21] + 147;"
          calcs += "^b[29] &= 0xFF;"
        } else {
          calcs += "^b[43] += b[40] + b[19] + b[26] + b[4] + b[10] + b[7] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[43] &= 0xFF;"
        }
        state = 440659815;
        continue;
      case 654069315:
        if (Math.random() < 0.5) {
          calcs += "^b[43] -= b[39] + b[2] + b[7] + b[3] + b[24] + b[41] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[43] &= 0xFF;"
        } else {
          calcs += "^b[12] += b[0] + b[13] + b[28] + b[38] + b[43] + b[1] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[12] &= 0xFF;"
        }
        state = 920953908;
        continue;
      case 657379399:
        if (Math.random() < 0.5) {
          calcs += "^b[18] += b[11] + b[16] + b[1] + b[23] + b[28] + b[34] + 35;"
          calcs += "^b[18] &= 0xFF;"
        } else {
          calcs += "^b[36] -= b[39] + b[34] + b[20] + b[4] + b[17] + b[26] + 178;"
          calcs += "^b[36] &= 0xFF;"
        }
        state = 631856256;
        continue;
      case 657690603:
        if (50326544n) {
          calcs += "^b[15] -= b[28] + b[7] + b[29] + b[13] + b[0] + b[22] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[15] &= 0xFF;"
        } else {
          calcs += "^b[37] -= b[42] + b[4] + b[0] + b[35] + b[13] + b[25] + 225;"
          calcs += "^b[37] &= 0xFF;"
        }
        state = 772757637;
        continue;
      case 658314850:
        if (79341258n) {
          calcs += "^b[3] -= b[41] + b[23] + b[38] + b[24] + b[30] + b[39] + 192;"
          calcs += "^b[3] &= 0xFF;"
        } else {
          calcs += "^b[30] ^= (b[43] + b[38] + b[12] + b[33] + b[34] + b[11] + 8) & 0xFF;"
        }
        state = 140504036;
        continue;
      case 659273600:
        if (Math.random() < 0.5) {
          calcs += "^b[18] -= b[32] + b[0] + b[43] + b[7] + b[20] + b[22] + 86;"
          calcs += "^b[18] &= 0xFF;"
        } else {
          calcs += "^b[18] += b[31] + b[6] + b[17] + b[12] + b[11] + b[19] + 220;"
          calcs += "^b[18] &= 0xFF;"
        }
        state = 858930996;
        continue;
      case 659598115:
        if (888464228) {
          calcs += "^b[31] -= b[35] + b[19] + b[42] + b[25] + b[5] + b[41] + 183;"
          calcs += "^b[31] &= 0xFF;"
        } else {
          calcs += "^b[8] -= b[10] + b[36] + b[38] + b[20] + b[39] + b[41] + 105;"
          calcs += "^b[8] &= 0xFF;"
        }
        state = 756680650;
        continue;
      case 659612427:
        if (314962921) {
          calcs += "^b[18] += b[29] + b[9] + b[24] + b[43] + b[0] + b[40] + 30;"
          calcs += "^b[18] &= 0xFF;"
        } else {
          calcs += "^b[1] += b[32] + b[4] + b[0] + b[5] + b[17] + b[2] + 159;"
          calcs += "^b[1] &= 0xFF;"
        }
        state = 922136400;
        continue;
      case 660852152:
        if (Math.random() < 0.5) {
          calcs += "^b[42] += b[43] + b[7] + b[18] + b[20] + b[2] + b[9] + 43;"
          calcs += "^b[42] &= 0xFF;"
        } else {
          calcs += "^b[26] -= b[2] + b[40] + b[35] + b[9] + b[33] + b[23] + 97;"
          calcs += "^b[26] &= 0xFF;"
        }
        state = 446247064;
        continue;
      case 661359257:
        if (Math.random() < 0.5) {
          calcs += "^b[3] += b[9] + b[12] + b[0] + b[40] + b[23] + b[21] + 227;"
          calcs += "^b[3] &= 0xFF;"
        } else {
          calcs += "^b[41] += b[24] + b[30] + b[13] + b[23] + b[5] + b[17] + 64;"
          calcs += "^b[41] &= 0xFF;"
        }
        state = 38718632;
        continue;
      case 662440992:
        if (Math.random() < 0.5) {
          calcs += "^b[6] ^= (b[31] + b[21] + b[28] + b[13] + b[42] + b[35] + 156) & 0xFF;"
        } else {
          calcs += "^b[23] += b[17] + b[34] + b[39] + b[3] + b[21] + b[26] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[23] &= 0xFF;"
        }
        state = 624840521;
        continue;
      case 662940026:
        if (47631812n) {
          calcs += "^b[15] -= b[27] + b[42] + b[10] + b[20] + b[19] + b[29] + 238;"
          calcs += "^b[15] &= 0xFF;"
        } else {
          calcs += "^b[30] ^= (b[17] + b[15] + b[18] + b[43] + b[29] + b[16] + 27) & 0xFF;"
        }
        state = 1042806170;
        continue;
      case 663555074:
        if (Math.random() < 0.5) {
          calcs += "^b[23] += b[42] + b[33] + b[32] + b[19] + b[3] + b[35] + 112;"
          calcs += "^b[23] &= 0xFF;"
        } else {
          calcs += "^b[35] += b[41] + b[40] + b[27] + b[23] + b[31] + b[37] + 213;"
          calcs += "^b[35] &= 0xFF;"
        }
        state = 682380126;
        continue;
      case 664160105:
        if (85595404n) {
          calcs += "^b[15] += b[24] + b[16] + b[38] + b[22] + b[18] + b[19] + 18;"
          calcs += "^b[15] &= 0xFF;"
        } else {
          calcs += "^b[31] -= b[28] + b[22] + b[8] + b[3] + b[38] + b[23] + 0;"
          calcs += "^b[31] &= 0xFF;"
        }
        state = 262546450;
        continue;
      case 665367266:
        if (Math.random() < 0.5) {
          calcs += "^b[43] -= b[32] + b[34] + b[16] + b[29] + b[39] + b[4] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[43] &= 0xFF;"
        } else {
          calcs += "^b[24] -= b[10] + b[11] + b[14] + b[17] + b[1] + b[20] + 161;"
          calcs += "^b[24] &= 0xFF;"
        }
        state = 83618854;
        continue;
      case 667976664:
        if (604457272) {
          calcs += "^b[15] -= b[41] + b[29] + b[17] + b[31] + b[37] + b[5] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[15] &= 0xFF;"
        } else {
          calcs += "^b[18] -= b[29] + b[0] + b[14] + b[21] + b[24] + b[2] + 70;"
          calcs += "^b[18] &= 0xFF;"
        }
        state = 968886840;
        continue;
      case 668502108:
        if (63895761n) {
          calcs += "^b[15] ^= (b[1] + b[10] + b[21] + b[29] + b[30] + b[18] + 61) & 0xFF;"
        } else {
          calcs += "^b[25] += b[41] + b[17] + b[14] + b[10] + b[35] + b[2] + 41;"
          calcs += "^b[25] &= 0xFF;"
        }
        state = 958689612;
        continue;
      case 668741963:
        if (Math.random() < 0.5) {
          calcs += "^b[43] += b[33] + b[20] + b[5] + b[29] + b[42] + b[7] + 7;"
          calcs += "^b[43] &= 0xFF;"
        } else {
          calcs += "^b[15] ^= (b[36] + b[23] + b[31] + b[0] + b[20] + b[5] + 20) & 0xFF;"
        }
        state = 37306313;
        continue;
      case 668916821:
        if (521046947) {
          calcs += "^b[10] += b[5] + b[14] + b[25] + b[38] + b[26] + b[20] + 130;"
          calcs += "^b[10] &= 0xFF;"
        } else {
          calcs += "^b[19] -= b[7] + b[41] + b[32] + b[18] + b[1] + b[23] + 19;"
          calcs += "^b[19] &= 0xFF;"
        }
        state = 295760848;
        continue;
      case 669523539:
        if (Math.random() < 0.5) {
          calcs += "^b[15] += b[28] + b[16] + b[1] + b[8] + b[3] + b[19] + 5;"
          calcs += "^b[15] &= 0xFF;"
        } else {
          calcs += "^b[5] += b[28] + b[9] + b[25] + b[27] + b[32] + b[21] + 108;"
          calcs += "^b[5] &= 0xFF;"
        }
        state = 802679489;
        continue;
      case 671130340:
        if (44289887n) {
          calcs += "^b[23] ^= (b[18] + b[10] + b[20] + b[17] + b[4] + b[38] + 214) & 0xFF;"
        } else {
          calcs += "^b[1] -= b[37] + b[40] + b[30] + b[6] + b[38] + b[19] + 192;"
          calcs += "^b[1] &= 0xFF;"
        }
        state = 311481896;
        continue;
      case 671468345:
        if (78983600n) {
          calcs += "^b[18] += b[19] + b[28] + b[40] + b[22] + b[5] + b[17] + 162;"
          calcs += "^b[18] &= 0xFF;"
        } else {
          calcs += "^b[10] ^= (b[5] + b[33] + b[37] + b[20] + b[18] + b[6] + 232) & 0xFF;"
        }
        state = 901814663;
        continue;
      case 672968190:
        if (Math.random() < 0.5) {
          calcs += "^b[37] ^= (b[22] + b[28] + b[32] + b[41] + b[2] + b[19] + 59) & 0xFF;"
        } else {
          calcs += "^b[31] += b[40] + b[21] + b[2] + b[43] + b[4] + b[0] + 116;"
          calcs += "^b[31] &= 0xFF;"
        }
        state = 279283983;
        continue;
      case 673415921:
        if (549939447) {
          calcs += "^b[43] -= b[28] + b[36] + b[13] + b[16] + b[41] + b[19] + 14;"
          calcs += "^b[43] &= 0xFF;"
        } else {
          calcs += "^b[22] += b[37] + b[26] + b[14] + b[41] + b[30] + b[6] + 248;"
          calcs += "^b[22] &= 0xFF;"
        }
        state = 405450021;
        continue;
      case 674866669:
        if (15952499n) {
          calcs += "^b[8] ^= (b[4] + b[13] + b[43] + b[26] + b[9] + b[21] + " + Math.floor(Math.random() * 256) + ") & 0xFF;"
        } else {
          calcs += "^b[4] += b[5] + b[28] + b[39] + b[15] + b[6] + b[3] + 154;"
          calcs += "^b[4] &= 0xFF;"
        }
        state = 815863967;
        continue;
      case 676900802:
        if (Math.random() < 0.5) {
          calcs += "^b[8] += b[14] + b[40] + b[10] + b[1] + b[28] + b[6] + 110;"
          calcs += "^b[8] &= 0xFF;"
        } else {
          calcs += "^b[30] -= b[33] + b[42] + b[2] + b[39] + b[1] + b[14] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[30] &= 0xFF;"
        }
        state = 581381813;
        continue;
      case 679907763:
        if (Math.random() < 0.5) {
          calcs += "^b[30] ^= (b[17] + b[5] + b[35] + b[26] + b[0] + b[11] + 197) & 0xFF;"
        } else {
          calcs += "^b[20] += b[34] + b[11] + b[21] + b[0] + b[43] + b[13] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[20] &= 0xFF;"
        }
        state = 91915693;
        continue;
      case 680818939:
        if (14322765) {
          calcs += "^b[20] += b[37] + b[7] + b[18] + b[1] + b[8] + b[28] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[20] &= 0xFF;"
        } else {
          calcs += "^b[9] += b[18] + b[4] + b[7] + b[13] + b[29] + b[26] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[9] &= 0xFF;"
        }
        state = 285191804;
        continue;
      case 682257123:
        if (Math.random() < 0.5) {
          calcs += "^b[21] += b[10] + b[17] + b[34] + b[14] + b[4] + b[43] + 30;"
          calcs += "^b[21] &= 0xFF;"
        } else {
          calcs += "^b[36] += b[37] + b[30] + b[5] + b[2] + b[42] + b[29] + 103;"
          calcs += "^b[36] &= 0xFF;"
        }
        state = 989947333;
        continue;
      case 686997760:
        if (Math.random() < 0.5) {
          calcs += "^b[33] += b[15] + b[4] + b[12] + b[18] + b[23] + b[16] + 224;"
          calcs += "^b[33] &= 0xFF;"
        } else {
          calcs += "^b[6] ^= (b[14] + b[34] + b[37] + b[12] + b[24] + b[25] + " + Math.floor(Math.random() * 256) + ") & 0xFF;"
        }
        state = 718964675;
        continue;
      case 687112427:
        if (251903815) {
          calcs += "^b[9] -= b[33] + b[21] + b[31] + b[23] + b[20] + b[37] + 125;"
          calcs += "^b[9] &= 0xFF;"
        } else {
          calcs += "^b[31] ^= (b[38] + b[0] + b[11] + b[29] + b[4] + b[42] + 220) & 0xFF;"
        }
        state = 525709580;
        continue;
      case 689966138:
        if (673751904) {
          calcs += "^b[18] += b[15] + b[0] + b[12] + b[23] + b[32] + b[31] + 242;"
          calcs += "^b[18] &= 0xFF;"
        } else {
          calcs += "^b[28] ^= (b[10] + b[37] + b[8] + b[12] + b[17] + b[30] + 58) & 0xFF;"
        }
        state = 693919401;
        continue;
      case 690810179:
        if (470067365) {
          calcs += "^b[37] ^= (b[5] + b[10] + b[25] + b[23] + b[29] + b[2] + 224) & 0xFF;"
        } else {
          calcs += "^b[25] += b[10] + b[31] + b[30] + b[21] + b[3] + b[40] + 227;"
          calcs += "^b[25] &= 0xFF;"
        }
        state = 358221569;
        continue;
      case 690944261:
        if (89710082n) {
          calcs += "^b[26] += b[29] + b[27] + b[2] + b[3] + b[5] + b[9] + 244;"
          calcs += "^b[26] &= 0xFF;"
        } else {
          calcs += "^b[37] -= b[28] + b[25] + b[17] + b[43] + b[31] + b[32] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[37] &= 0xFF;"
        }
        state = 392099329;
        continue;
      case 691686948:
        if (Math.random() < 0.5) {
          calcs += "^b[24] -= b[9] + b[0] + b[6] + b[18] + b[10] + b[14] + 202;"
          calcs += "^b[24] &= 0xFF;"
        } else {
          calcs += "^b[16] += b[38] + b[6] + b[21] + b[34] + b[27] + b[10] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[16] &= 0xFF;"
        }
        state = 154011094;
        continue;
      case 692337316:
        if (Math.random() < 0.5) {
          calcs += "^b[7] -= b[36] + b[10] + b[29] + b[27] + b[22] + b[28] + 183;"
          calcs += "^b[7] &= 0xFF;"
        } else {
          calcs += "^b[26] += b[9] + b[2] + b[43] + b[10] + b[18] + b[11] + 190;"
          calcs += "^b[26] &= 0xFF;"
        }
        state = 998016485;
        continue;
      case 694178482:
        if (Math.random() < 0.5) {
          calcs += "^b[31] -= b[14] + b[29] + b[42] + b[40] + b[30] + b[33] + 202;"
          calcs += "^b[31] &= 0xFF;"
        } else {
          calcs += "^b[35] += b[31] + b[37] + b[38] + b[21] + b[28] + b[11] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[35] &= 0xFF;"
        }
        state = 840687699;
        continue;
      case 694236448:
        if (79037095n) {
          calcs += "^b[14] ^= (b[27] + b[11] + b[31] + b[38] + b[16] + b[19] + 72) & 0xFF;"
        } else {
          calcs += "^b[7] += b[9] + b[18] + b[41] + b[1] + b[27] + b[2] + 19;"
          calcs += "^b[7] &= 0xFF;"
        }
        state = 875466494;
        continue;
      case 694925458:
        if (430396022) {
          calcs += "^b[9] ^= (b[33] + b[32] + b[2] + b[19] + b[15] + b[36] + " + Math.floor(Math.random() * 256) + ") & 0xFF;"
        } else {
          calcs += "^b[7] += b[3] + b[0] + b[14] + b[31] + b[40] + b[5] + 226;"
          calcs += "^b[7] &= 0xFF;"
        }
        state = 253379921;
        continue;
      case 695348820:
        if (Math.random() < 0.5) {
          calcs += "^b[39] ^= (b[11] + b[23] + b[31] + b[20] + b[42] + b[30] + 94) & 0xFF;"
        } else {
          calcs += "^b[2] ^= (b[40] + b[18] + b[1] + b[20] + b[23] + b[35] + 176) & 0xFF;"
        }
        state = 443107925;
        continue;
      case 695393418:
        if (Math.random() < 0.5) {
          calcs += "^b[4] ^= (b[38] + b[9] + b[12] + b[31] + b[16] + b[7] + 47) & 0xFF;"
        } else {
          calcs += "^b[6] += b[36] + b[29] + b[27] + b[23] + b[3] + b[19] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[6] &= 0xFF;"
        }
        state = 420210625;
        continue;
      case 696914010:
        if (824577734) {
          calcs += "^b[0] ^= (b[32] + b[37] + b[1] + b[18] + b[8] + b[3] + " + Math.floor(Math.random() * 256) + ") & 0xFF;"
        } else {
          calcs += "^b[40] ^= (b[10] + b[30] + b[6] + b[27] + b[39] + b[9] + 254) & 0xFF;"
        }
        state = 485888781;
        continue;
      case 699096503:
        if (40576212n) {
          calcs += "^b[43] += b[28] + b[32] + b[27] + b[18] + b[16] + b[31] + 15;"
          calcs += "^b[43] &= 0xFF;"
        } else {
          calcs += "^b[39] += b[0] + b[18] + b[21] + b[22] + b[31] + b[6] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[39] &= 0xFF;"
        }
        state = 542565287;
        continue;
      case 700493929:
        if (Math.random() < 0.5) {
          calcs += "^b[10] -= b[17] + b[25] + b[43] + b[12] + b[30] + b[4] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[10] &= 0xFF;"
        } else {
          calcs += "^b[18] += b[41] + b[12] + b[19] + b[4] + b[9] + b[21] + 22;"
          calcs += "^b[18] &= 0xFF;"
        }
        state = 209770528;
        continue;
      case 700644156:
        if (799352716) {
          calcs += "^b[3] -= b[39] + b[35] + b[17] + b[40] + b[12] + b[20] + 250;"
          calcs += "^b[3] &= 0xFF;"
        } else {
          calcs += "^b[24] ^= (b[41] + b[19] + b[4] + b[16] + b[37] + b[20] + 80) & 0xFF;"
        }
        state = 922747286;
        continue;
      case 703070146:
        if (246078512) {
          calcs += "^b[33] += b[22] + b[38] + b[17] + b[24] + b[23] + b[31] + 187;"
          calcs += "^b[33] &= 0xFF;"
        } else {
          calcs += "^b[13] ^= (b[14] + b[35] + b[22] + b[4] + b[23] + b[20] + 101) & 0xFF;"
        }
        state = 859962578;
        continue;
      case 703638644:
        if (826923791) {
          calcs += "^b[8] -= b[17] + b[31] + b[30] + b[19] + b[40] + b[39] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[8] &= 0xFF;"
        } else {
          calcs += "^b[9] += b[13] + b[1] + b[5] + b[8] + b[11] + b[32] + 52;"
          calcs += "^b[9] &= 0xFF;"
        }
        state = 174326191;
        continue;
      case 703648569:
        if (811838484) {
          calcs += "^b[9] ^= (b[31] + b[13] + b[38] + b[17] + b[12] + b[29] + 172) & 0xFF;"
        } else {
          calcs += "^b[25] += b[31] + b[36] + b[12] + b[5] + b[9] + b[3] + 94;"
          calcs += "^b[25] &= 0xFF;"
        }
        state = 192873313;
        continue;
      case 703712893:
        if (157809807) {
          calcs += "^b[11] -= b[18] + b[31] + b[10] + b[37] + b[34] + b[21] + 38;"
          calcs += "^b[11] &= 0xFF;"
        } else {
          calcs += "^b[9] += b[5] + b[15] + b[19] + b[27] + b[17] + b[25] + 161;"
          calcs += "^b[9] &= 0xFF;"
        }
        state = 457346847;
        continue;
      case 704462675:
        if (Math.random() < 0.5) {
          calcs += "^b[17] ^= (b[41] + b[14] + b[43] + b[6] + b[7] + b[28] + 196) & 0xFF;"
        } else {
          calcs += "^b[38] += b[18] + b[13] + b[28] + b[41] + b[22] + b[26] + 9;"
          calcs += "^b[38] &= 0xFF;"
        }
        state = 476949533;
        continue;
      case 705428670:
        if (23225055n) {
          calcs += "^b[17] ^= (b[24] + b[7] + b[35] + b[31] + b[28] + b[29] + 64) & 0xFF;"
        } else {
          calcs += "^b[37] += b[28] + b[43] + b[14] + b[13] + b[2] + b[16] + 210;"
          calcs += "^b[37] &= 0xFF;"
        }
        state = 243078604;
        continue;
      case 706248766:
        if (Math.random() < 0.5) {
          calcs += "^b[33] ^= (b[3] + b[16] + b[35] + b[6] + b[12] + b[34] + 213) & 0xFF;"
        } else {
          calcs += "^b[25] += b[6] + b[4] + b[7] + b[3] + b[26] + b[12] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[25] &= 0xFF;"
        }
        state = 40024592;
        continue;
      case 708088836:
        if (Math.random() < 0.5) {
          calcs += "^b[28] ^= (b[13] + b[9] + b[35] + b[23] + b[18] + b[39] + 117) & 0xFF;"
        } else {
          calcs += "^b[17] ^= (b[3] + b[34] + b[36] + b[5] + b[9] + b[33] + 53) & 0xFF;"
        }
        state = 22699493;
        continue;
      case 710626576:
        if (836463217) {
          calcs += "^b[26] += b[22] + b[1] + b[12] + b[0] + b[40] + b[19] + 174;"
          calcs += "^b[26] &= 0xFF;"
        } else {
          calcs += "^b[0] ^= (b[41] + b[16] + b[15] + b[39] + b[18] + b[9] + 175) & 0xFF;"
        }
        state = 304984812;
        continue;
      case 711458388:
        if (82803055n) {
          calcs += "^b[6] -= b[10] + b[34] + b[17] + b[28] + b[26] + b[13] + 142;"
          calcs += "^b[6] &= 0xFF;"
        } else {
          calcs += "^b[8] += b[6] + b[10] + b[9] + b[2] + b[37] + b[38] + 213;"
          calcs += "^b[8] &= 0xFF;"
        }
        state = 280600972;
        continue;
      case 714437222:
        if (Math.random() < 0.5) {
          calcs += "^b[27] += b[29] + b[16] + b[33] + b[18] + b[19] + b[35] + 222;"
          calcs += "^b[27] &= 0xFF;"
        } else {
          calcs += "^b[9] += b[17] + b[34] + b[18] + b[26] + b[42] + b[13] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[9] &= 0xFF;"
        }
        state = 908578754;
        continue;
      case 715652268:
        if (Math.random() < 0.5) {
          calcs += "^b[40] ^= (b[42] + b[31] + b[25] + b[26] + b[21] + b[28] + 35) & 0xFF;"
        } else {
          calcs += "^b[26] -= b[6] + b[10] + b[7] + b[2] + b[11] + b[32] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[26] &= 0xFF;"
        }
        state = 16449040;
        continue;
      case 716459371:
        if (Math.random() < 0.5) {
          calcs += "^b[10] ^= (b[18] + b[1] + b[20] + b[11] + b[31] + b[41] + 10) & 0xFF;"
        } else {
          calcs += "^b[11] ^= (b[21] + b[42] + b[26] + b[40] + b[22] + b[30] + 169) & 0xFF;"
        }
        state = 183777945;
        continue;
      case 716894268:
        if (Math.random() < 0.5) {
          calcs += "^b[18] ^= (b[36] + b[26] + b[27] + b[7] + b[14] + b[15] + 22) & 0xFF;"
        } else {
          calcs += "^b[40] += b[8] + b[9] + b[38] + b[33] + b[27] + b[7] + 66;"
          calcs += "^b[40] &= 0xFF;"
        }
        state = 816060033;
        continue;
      case 717447985:
        if (781719997) {
          calcs += "^b[22] -= b[27] + b[41] + b[18] + b[36] + b[2] + b[3] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[22] &= 0xFF;"
        } else {
          calcs += "^b[32] += b[10] + b[26] + b[4] + b[7] + b[43] + b[2] + 145;"
          calcs += "^b[32] &= 0xFF;"
        }
        state = 950032801;
        continue;
      case 717701475:
        if (Math.random() < 0.5) {
          calcs += "^b[6] += b[37] + b[38] + b[32] + b[26] + b[22] + b[14] + 92;"
          calcs += "^b[6] &= 0xFF;"
        } else {
          calcs += "^b[13] += b[11] + b[41] + b[17] + b[6] + b[22] + b[8] + 130;"
          calcs += "^b[13] &= 0xFF;"
        }
        state = 949761243;
        continue;
      case 717893810:
        if (107934763) {
          calcs += "^b[33] ^= (b[11] + b[43] + b[25] + b[37] + b[19] + b[36] + 207) & 0xFF;"
        } else {
          calcs += "^b[13] += b[17] + b[40] + b[32] + b[21] + b[5] + b[12] + 5;"
          calcs += "^b[13] &= 0xFF;"
        }
        state = 575406215;
        continue;
      case 718127991:
        if (Math.random() < 0.5) {
          calcs += "^b[32] ^= (b[36] + b[41] + b[5] + b[3] + b[30] + b[35] + 126) & 0xFF;"
        } else {
          calcs += "^b[25] += b[12] + b[27] + b[43] + b[10] + b[36] + b[24] + 15;"
          calcs += "^b[25] &= 0xFF;"
        }
        state = 874900017;
        continue;
      case 718295275:
        if (869773898) {
          calcs += "^b[23] ^= (b[12] + b[4] + b[31] + b[42] + b[35] + b[41] + " + Math.floor(Math.random() * 256) + ") & 0xFF;"
        } else {
          calcs += "^b[32] ^= (b[41] + b[30] + b[5] + b[23] + b[28] + b[39] + 217) & 0xFF;"
        }
        state = 1032188356;
        continue;
      case 719294338:
        if (155480875) {
          calcs += "^b[32] -= b[26] + b[13] + b[28] + b[15] + b[9] + b[7] + 49;"
          calcs += "^b[32] &= 0xFF;"
        } else {
          calcs += "^b[24] += b[29] + b[40] + b[37] + b[33] + b[28] + b[43] + 128;"
          calcs += "^b[24] &= 0xFF;"
        }
        state = 496498620;
        continue;
      case 719604778:
        if (48467378n) {
          calcs += "^b[40] ^= (b[15] + b[5] + b[34] + b[17] + b[36] + b[23] + 221) & 0xFF;"
        } else {
          calcs += "^b[14] ^= (b[25] + b[4] + b[33] + b[9] + b[17] + b[0] + " + Math.floor(Math.random() * 256) + ") & 0xFF;"
        }
        state = 394356229;
        continue;
      case 721440911:
        if (72730479n) {
          calcs += "^b[1] += b[37] + b[20] + b[11] + b[15] + b[8] + b[27] + 26;"
          calcs += "^b[1] &= 0xFF;"
        } else {
          calcs += "^b[22] ^= (b[34] + b[4] + b[9] + b[18] + b[28] + b[31] + 222) & 0xFF;"
        }
        state = 948854573;
        continue;
      case 721721344:
        if (12408061n) {
          calcs += "^b[13] += b[31] + b[43] + b[26] + b[41] + b[24] + b[42] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[13] &= 0xFF;"
        } else {
          calcs += "^b[9] += b[21] + b[0] + b[27] + b[6] + b[36] + b[24] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[9] &= 0xFF;"
        }
        state = 906715513;
        continue;
      case 724665382:
        if (Math.random() < 0.5) {
          calcs += "^b[1] ^= (b[17] + b[35] + b[21] + b[3] + b[22] + b[41] + 5) & 0xFF;"
        } else {
          calcs += "^b[9] += b[5] + b[43] + b[42] + b[7] + b[1] + b[28] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[9] &= 0xFF;"
        }
        state = 711141192;
        continue;
      case 724809866:
        if (878045687) {
          calcs += "^b[42] ^= (b[15] + b[19] + b[2] + b[1] + b[40] + b[9] + 207) & 0xFF;"
        } else {
          calcs += "^b[1] += b[20] + b[2] + b[25] + b[31] + b[4] + b[18] + 7;"
          calcs += "^b[1] &= 0xFF;"
        }
        state = 972963306;
        continue;
      case 726887314:
        if (589762261) {
          calcs += "^b[17] += b[24] + b[13] + b[23] + b[27] + b[20] + b[30] + 199;"
          calcs += "^b[17] &= 0xFF;"
        } else {
          calcs += "^b[43] ^= (b[34] + b[28] + b[20] + b[31] + b[7] + b[5] + " + Math.floor(Math.random() * 256) + ") & 0xFF;"
        }
        state = 451022489;
        continue;
      case 727581920:
        if (Math.random() < 0.5) {
          calcs += "^b[36] -= b[38] + b[4] + b[40] + b[28] + b[24] + b[21] + 194;"
          calcs += "^b[36] &= 0xFF;"
        } else {
          calcs += "^b[14] ^= (b[38] + b[43] + b[18] + b[22] + b[17] + b[35] + 133) & 0xFF;"
        }
        state = 570311642;
        continue;
      case 728063058:
        if (808590105) {
          calcs += "^b[15] ^= (b[33] + b[8] + b[16] + b[9] + b[38] + b[22] + 163) & 0xFF;"
        } else {
          calcs += "^b[31] -= b[39] + b[35] + b[34] + b[43] + b[38] + b[20] + 173;"
          calcs += "^b[31] &= 0xFF;"
        }
        state = 248270043;
        continue;
      case 728604419:
        if (Math.random() < 0.5) {
          calcs += "^b[29] ^= (b[19] + b[0] + b[11] + b[25] + b[4] + b[36] + 32) & 0xFF;"
        } else {
          calcs += "^b[20] += b[7] + b[32] + b[0] + b[18] + b[38] + b[29] + 45;"
          calcs += "^b[20] &= 0xFF;"
        }
        state = 740606242;
        continue;
      case 728750373:
        if (50562265n) {
          calcs += "^b[38] += b[20] + b[30] + b[31] + b[8] + b[37] + b[33] + 54;"
          calcs += "^b[38] &= 0xFF;"
        } else {
          calcs += "^b[2] ^= (b[37] + b[8] + b[24] + b[29] + b[11] + b[41] + 24) & 0xFF;"
        }
        state = 68986913;
        continue;
      case 734932685:
        if (97460879) {
          calcs += "^b[32] += b[20] + b[31] + b[7] + b[21] + b[41] + b[13] + 134;"
          calcs += "^b[32] &= 0xFF;"
        } else {
          calcs += "^b[2] += b[15] + b[16] + b[6] + b[34] + b[39] + b[12] + 131;"
          calcs += "^b[2] &= 0xFF;"
        }
        state = 618745399;
        continue;
      case 735283656:
        if (50627304n) {
          calcs += "^b[4] -= b[2] + b[31] + b[11] + b[16] + b[8] + b[23] + 245;"
          calcs += "^b[4] &= 0xFF;"
        } else {
          calcs += "^b[29] -= b[36] + b[30] + b[13] + b[22] + b[16] + b[10] + 195;"
          calcs += "^b[29] &= 0xFF;"
        }
        state = 728781020;
        continue;
      case 737600074:
        if (Math.random() < 0.5) {
          calcs += "^b[34] -= b[19] + b[7] + b[18] + b[17] + b[31] + b[23] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[34] &= 0xFF;"
        } else {
          calcs += "^b[3] -= b[31] + b[37] + b[34] + b[25] + b[11] + b[13] + 6;"
          calcs += "^b[3] &= 0xFF;"
        }
        state = 715943837;
        continue;
      case 738234691:
        if (Math.random() < 0.5) {
          calcs += "^b[34] -= b[36] + b[4] + b[30] + b[43] + b[22] + b[37] + 19;"
          calcs += "^b[34] &= 0xFF;"
        } else {
          calcs += "^b[13] ^= (b[27] + b[19] + b[31] + b[38] + b[43] + b[23] + 33) & 0xFF;"
        }
        state = 730006451;
        continue;
      case 738349727:
        if (1029881146) {
          calcs += "^b[38] ^= (b[26] + b[30] + b[35] + b[11] + b[14] + b[39] + 22) & 0xFF;"
        } else {
          calcs += "^b[39] ^= (b[9] + b[18] + b[20] + b[15] + b[40] + b[10] + " + Math.floor(Math.random() * 256) + ") & 0xFF;"
        }
        state = 260627984;
        continue;
      case 738393887:
        if (31405760n) {
          calcs += "^b[18] += b[26] + b[6] + b[37] + b[36] + b[33] + b[5] + 177;"
          calcs += "^b[18] &= 0xFF;"
        } else {
          calcs += "^b[33] += b[40] + b[9] + b[3] + b[34] + b[42] + b[36] + 129;"
          calcs += "^b[33] &= 0xFF;"
        }
        state = 901504696;
        continue;
      case 740369788:
        if (282301570) {
          calcs += "^b[15] -= b[33] + b[5] + b[31] + b[6] + b[12] + b[36] + 131;"
          calcs += "^b[15] &= 0xFF;"
        } else {
          calcs += "^b[41] += b[1] + b[4] + b[10] + b[16] + b[13] + b[11] + 6;"
          calcs += "^b[41] &= 0xFF;"
        }
        state = 732745038;
        continue;
      case 741568164:
        if (161224872) {
          calcs += "^b[3] -= b[36] + b[42] + b[38] + b[25] + b[17] + b[4] + 227;"
          calcs += "^b[3] &= 0xFF;"
        } else {
          calcs += "^b[2] ^= (b[1] + b[40] + b[32] + b[37] + b[21] + b[35] + " + Math.floor(Math.random() * 256) + ") & 0xFF;"
        }
        state = 1024767413;
        continue;
      case 742853454:
        if (217661996) {
          calcs += "^b[21] ^= (b[33] + b[3] + b[40] + b[1] + b[37] + b[15] + 98) & 0xFF;"
        } else {
          calcs += "^b[16] -= b[5] + b[27] + b[21] + b[8] + b[22] + b[28] + 254;"
          calcs += "^b[16] &= 0xFF;"
        }
        state = 636024289;
        continue;
      case 742863292:
        if (60469374n) {
          calcs += "^b[21] ^= (b[12] + b[43] + b[41] + b[37] + b[11] + b[26] + " + Math.floor(Math.random() * 256) + ") & 0xFF;"
        } else {
          calcs += "^b[41] ^= (b[43] + b[40] + b[42] + b[16] + b[19] + b[33] + 95) & 0xFF;"
        }
        state = 267194974;
        continue;
      case 745685328:
        if (308460658) {
          calcs += "^b[4] ^= (b[13] + b[42] + b[41] + b[43] + b[22] + b[12] + 30) & 0xFF;"
        } else {
          calcs += "^b[37] ^= (b[39] + b[32] + b[40] + b[5] + b[41] + b[10] + 146) & 0xFF;"
        }
        state = 999651373;
        continue;
      case 746082457:
        if (114873052) {
          calcs += "^b[22] ^= (b[42] + b[11] + b[20] + b[41] + b[14] + b[6] + 151) & 0xFF;"
        } else {
          calcs += "^b[11] ^= (b[8] + b[33] + b[17] + b[27] + b[2] + b[28] + 196) & 0xFF;"
        }
        state = 771350879;
        continue;
      case 746695087:
        if (Math.random() < 0.5) {
          calcs += "^b[35] ^= (b[19] + b[24] + b[39] + b[42] + b[28] + b[4] + 184) & 0xFF;"
        } else {
          calcs += "^b[25] ^= (b[22] + b[6] + b[26] + b[23] + b[42] + b[10] + 52) & 0xFF;"
        }
        state = 394346422;
        continue;
      case 747124022:
        if (65982759n) {
          calcs += "^b[40] += b[28] + b[1] + b[5] + b[38] + b[33] + b[31] + 67;"
          calcs += "^b[40] &= 0xFF;"
        } else {
          calcs += "^b[22] ^= (b[34] + b[42] + b[20] + b[14] + b[1] + b[7] + 41) & 0xFF;"
        }
        state = 286357295;
        continue;
      case 747515263:
        if (135963965) {
          calcs += "^b[27] += b[23] + b[34] + b[12] + b[26] + b[16] + b[32] + 42;"
          calcs += "^b[27] &= 0xFF;"
        } else {
          calcs += "^b[36] -= b[1] + b[33] + b[27] + b[20] + b[42] + b[17] + 173;"
          calcs += "^b[36] &= 0xFF;"
        }
        state = 108234550;
        continue;
      case 747625031:
        if (22180196) {
          calcs += "^b[4] -= b[6] + b[16] + b[10] + b[43] + b[36] + b[35] + 214;"
          calcs += "^b[4] &= 0xFF;"
        } else {
          calcs += "^b[38] += b[37] + b[13] + b[8] + b[23] + b[22] + b[27] + 86;"
          calcs += "^b[38] &= 0xFF;"
        }
        state = 34575358;
        continue;
      case 748439402:
        if (Math.random() < 0.5) {
          calcs += "^b[29] -= b[19] + b[32] + b[6] + b[40] + b[14] + b[8] + 162;"
          calcs += "^b[29] &= 0xFF;"
        } else {
          calcs += "^b[39] += b[33] + b[2] + b[37] + b[28] + b[1] + b[22] + 38;"
          calcs += "^b[39] &= 0xFF;"
        }
        state = 378838591;
        continue;
      case 750243255:
        if (697637626) {
          calcs += "^b[31] += b[24] + b[39] + b[30] + b[27] + b[11] + b[34] + 174;"
          calcs += "^b[31] &= 0xFF;"
        } else {
          calcs += "^b[16] ^= (b[24] + b[29] + b[6] + b[35] + b[0] + b[9] + 70) & 0xFF;"
        }
        state = 253123439;
        continue;
      case 752415474:
        if (84999181n) {
          calcs += "^b[0] ^= (b[31] + b[6] + b[22] + b[25] + b[19] + b[4] + 133) & 0xFF;"
        } else {
          calcs += "^b[42] -= b[24] + b[9] + b[29] + b[41] + b[23] + b[33] + 28;"
          calcs += "^b[42] &= 0xFF;"
        }
        state = 491479638;
        continue;
      case 752876803:
        if (Math.random() < 0.5) {
          calcs += "^b[23] += b[25] + b[41] + b[40] + b[5] + b[34] + b[38] + 111;"
          calcs += "^b[23] &= 0xFF;"
        } else {
          calcs += "^b[2] -= b[29] + b[9] + b[11] + b[19] + b[0] + b[27] + 89;"
          calcs += "^b[2] &= 0xFF;"
        }
        state = 418849118;
        continue;
      case 753140202:
        if (66254653n) {
          calcs += "^b[9] ^= (b[12] + b[1] + b[11] + b[33] + b[4] + b[8] + " + Math.floor(Math.random() * 256) + ") & 0xFF;"
        } else {
          calcs += "^b[2] += b[41] + b[12] + b[4] + b[6] + b[31] + b[28] + 90;"
          calcs += "^b[2] &= 0xFF;"
        }
        state = 128078743;
        continue;
      case 754053251:
        if (Math.random() < 0.5) {
          calcs += "^b[5] -= b[33] + b[23] + b[15] + b[39] + b[2] + b[31] + 222;"
          calcs += "^b[5] &= 0xFF;"
        } else {
          calcs += "^b[31] += b[35] + b[13] + b[2] + b[39] + b[40] + b[11] + 80;"
          calcs += "^b[31] &= 0xFF;"
        }
        state = 203627414;
        continue;
      case 754246359:
        if (33102920) {
          calcs += "^b[4] += b[15] + b[2] + b[12] + b[5] + b[6] + b[16] + 139;"
          calcs += "^b[4] &= 0xFF;"
        } else {
          calcs += "^b[6] += b[11] + b[38] + b[32] + b[41] + b[24] + b[40] + 79;"
          calcs += "^b[6] &= 0xFF;"
        }
        state = 908502221;
        continue;
      case 754435174:
        if (786480690) {
          calcs += "^b[1] -= b[43] + b[39] + b[4] + b[41] + b[5] + b[0] + 149;"
          calcs += "^b[1] &= 0xFF;"
        } else {
          calcs += "^b[3] -= b[23] + b[36] + b[41] + b[17] + b[18] + b[22] + 172;"
          calcs += "^b[3] &= 0xFF;"
        }
        state = 692626545;
        continue;
      case 756608088:
        if (25242983n) {
          calcs += "^b[6] ^= (b[28] + b[9] + b[22] + b[21] + b[0] + b[4] + 89) & 0xFF;"
        } else {
          calcs += "^b[38] -= b[0] + b[1] + b[27] + b[36] + b[31] + b[17] + 247;"
          calcs += "^b[38] &= 0xFF;"
        }
        state = 921995790;
        continue;
      case 757641439:
        if (505551856) {
          calcs += "^b[41] -= b[12] + b[27] + b[31] + b[28] + b[42] + b[26] + 63;"
          calcs += "^b[41] &= 0xFF;"
        } else {
          calcs += "^b[22] += b[39] + b[27] + b[19] + b[9] + b[7] + b[1] + 84;"
          calcs += "^b[22] &= 0xFF;"
        }
        state = 919384361;
        continue;
      case 758478334:
        if (43384771n) {
          calcs += "^b[43] -= b[15] + b[25] + b[14] + b[8] + b[29] + b[31] + 30;"
          calcs += "^b[43] &= 0xFF;"
        } else {
          calcs += "^b[36] -= b[5] + b[41] + b[23] + b[27] + b[16] + b[31] + 110;"
          calcs += "^b[36] &= 0xFF;"
        }
        state = 475120120;
        continue;
      case 759656823:
        if (505461787) {
          calcs += "^b[39] += b[9] + b[35] + b[1] + b[28] + b[6] + b[10] + 187;"
          calcs += "^b[39] &= 0xFF;"
        } else {
          calcs += "^b[27] += b[13] + b[14] + b[35] + b[37] + b[23] + b[31] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[27] &= 0xFF;"
        }
        state = 946348328;
        continue;
      case 760544713:
        if (142754310) {
          calcs += "^b[43] += b[15] + b[31] + b[8] + b[3] + b[42] + b[30] + 102;"
          calcs += "^b[43] &= 0xFF;"
        } else {
          calcs += "^b[6] += b[33] + b[12] + b[41] + b[15] + b[19] + b[11] + 154;"
          calcs += "^b[6] &= 0xFF;"
        }
        state = 610917268;
        continue;
      case 761621198:
        if (Math.random() < 0.5) {
          calcs += "^b[8] += b[41] + b[24] + b[2] + b[6] + b[1] + b[31] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[8] &= 0xFF;"
        } else {
          calcs += "^b[18] -= b[37] + b[15] + b[16] + b[27] + b[14] + b[0] + 161;"
          calcs += "^b[18] &= 0xFF;"
        }
        state = 403438631;
        continue;
      case 764848634:
        if (25710910n) {
          calcs += "^b[0] ^= (b[21] + b[10] + b[29] + b[30] + b[13] + b[17] + 60) & 0xFF;"
        } else {
          calcs += "^b[16] ^= (b[14] + b[5] + b[24] + b[39] + b[36] + b[29] + " + Math.floor(Math.random() * 256) + ") & 0xFF;"
        }
        state = 456603755;
        continue;
      case 767096117:
        if (13616352n) {
          calcs += "^b[25] += b[5] + b[21] + b[14] + b[18] + b[0] + b[41] + 170;"
          calcs += "^b[25] &= 0xFF;"
        } else {
          calcs += "^b[24] -= b[43] + b[5] + b[36] + b[9] + b[30] + b[3] + 160;"
          calcs += "^b[24] &= 0xFF;"
        }
        state = 120549532;
        continue;
      case 768056640:
        if (Math.random() < 0.5) {
          calcs += "^b[18] += b[12] + b[0] + b[23] + b[38] + b[37] + b[24] + 223;"
          calcs += "^b[18] &= 0xFF;"
        } else {
          calcs += "^b[22] += b[31] + b[37] + b[17] + b[14] + b[15] + b[2] + 92;"
          calcs += "^b[22] &= 0xFF;"
        }
        state = 623836773;
        continue;
      case 769036486:
        if (Math.random() < 0.5) {
          calcs += "^b[36] += b[16] + b[12] + b[10] + b[32] + b[19] + b[5] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[36] &= 0xFF;"
        } else {
          calcs += "^b[38] ^= (b[22] + b[36] + b[17] + b[14] + b[35] + b[25] + 55) & 0xFF;"
        }
        state = 580938788;
        continue;
      case 770907936:
        if (Math.random() < 0.5) {
          calcs += "^b[43] += b[8] + b[39] + b[2] + b[40] + b[37] + b[10] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[43] &= 0xFF;"
        } else {
          calcs += "^b[32] -= b[4] + b[37] + b[3] + b[36] + b[6] + b[38] + 250;"
          calcs += "^b[32] &= 0xFF;"
        }
        state = 300529284;
        continue;
      case 771105345:
        if (16397822n) {
          calcs += "^b[21] -= b[9] + b[20] + b[43] + b[33] + b[24] + b[3] + 54;"
          calcs += "^b[21] &= 0xFF;"
        } else {
          calcs += "^b[43] += b[41] + b[14] + b[0] + b[35] + b[34] + b[13] + 16;"
          calcs += "^b[43] &= 0xFF;"
        }
        state = 778057547;
        continue;
      case 772657164:
        if (Math.random() < 0.5) {
          calcs += "^b[13] -= b[10] + b[17] + b[39] + b[18] + b[22] + b[14] + 6;"
          calcs += "^b[13] &= 0xFF;"
        } else {
          calcs += "^b[11] ^= (b[25] + b[18] + b[38] + b[35] + b[39] + b[34] + " + Math.floor(Math.random() * 256) + ") & 0xFF;"
        }
        state = 392668663;
        continue;
      case 772702548:
        if (857553112) {
          calcs += "^b[28] += b[21] + b[2] + b[41] + b[3] + b[8] + b[24] + 40;"
          calcs += "^b[28] &= 0xFF;"
        } else {
          calcs += "^b[0] ^= (b[6] + b[24] + b[12] + b[35] + b[18] + b[20] + 222) & 0xFF;"
        }
        state = 740583470;
        continue;
      case 773635926:
        if (825147063) {
          calcs += "^b[43] -= b[39] + b[3] + b[29] + b[38] + b[7] + b[0] + 243;"
          calcs += "^b[43] &= 0xFF;"
        } else {
          calcs += "^b[40] ^= (b[30] + b[32] + b[11] + b[24] + b[2] + b[7] + " + Math.floor(Math.random() * 256) + ") & 0xFF;"
        }
        state = 616957437;
        continue;
      case 776373276:
        if (423205447) {
          calcs += "^b[30] -= b[25] + b[34] + b[4] + b[11] + b[6] + b[5] + 181;"
          calcs += "^b[30] &= 0xFF;"
        } else {
          calcs += "^b[21] += b[39] + b[6] + b[0] + b[33] + b[8] + b[40] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[21] &= 0xFF;"
        }
        state = 1006005727;
        continue;
      case 779328580:
        if (1022791685) {
          calcs += "^b[18] ^= (b[35] + b[0] + b[8] + b[16] + b[1] + b[6] + " + Math.floor(Math.random() * 256) + ") & 0xFF;"
        } else {
          calcs += "^b[40] ^= (b[30] + b[28] + b[20] + b[33] + b[9] + b[22] + " + Math.floor(Math.random() * 256) + ") & 0xFF;"
        }
        state = 778837714;
        continue;
      case 779958856:
        if (66892556n) {
          calcs += "^b[39] ^= (b[3] + b[12] + b[37] + b[15] + b[26] + b[18] + 204) & 0xFF;"
        } else {
          calcs += "^b[8] += b[16] + b[38] + b[27] + b[21] + b[31] + b[3] + 10;"
          calcs += "^b[8] &= 0xFF;"
        }
        state = 829615148;
        continue;
      case 780429714:
        if (19238184n) {
          calcs += "^b[26] ^= (b[40] + b[39] + b[1] + b[36] + b[4] + b[42] + " + Math.floor(Math.random() * 256) + ") & 0xFF;"
        } else {
          calcs += "^b[39] -= b[8] + b[14] + b[41] + b[13] + b[15] + b[33] + 164;"
          calcs += "^b[39] &= 0xFF;"
        }
        state = 624047744;
        continue;
      case 780480466:
        if (869806366) {
          calcs += "^b[32] += b[41] + b[27] + b[17] + b[38] + b[9] + b[25] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[32] &= 0xFF;"
        } else {
          calcs += "^b[7] += b[6] + b[35] + b[1] + b[40] + b[36] + b[33] + 95;"
          calcs += "^b[7] &= 0xFF;"
        }
        state = 954247137;
        continue;
      case 781937258:
        if (540383326) {
          calcs += "^b[28] -= b[40] + b[3] + b[32] + b[34] + b[42] + b[20] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[28] &= 0xFF;"
        } else {
          calcs += "^b[41] ^= (b[31] + b[36] + b[2] + b[42] + b[43] + b[4] + " + Math.floor(Math.random() * 256) + ") & 0xFF;"
        }
        state = 897885654;
        continue;
      case 784248654:
        if (8301924) {
          calcs += "^b[18] -= b[41] + b[21] + b[32] + b[3] + b[7] + b[27] + 238;"
          calcs += "^b[18] &= 0xFF;"
        } else {
          calcs += "^b[6] += b[43] + b[35] + b[2] + b[27] + b[21] + b[30] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[6] &= 0xFF;"
        }
        state = 125306521;
        continue;
      case 784551218:
        if (62812649n) {
          calcs += "^b[21] ^= (b[32] + b[23] + b[39] + b[17] + b[33] + b[29] + " + Math.floor(Math.random() * 256) + ") & 0xFF;"
        } else {
          calcs += "^b[40] -= b[27] + b[21] + b[22] + b[28] + b[11] + b[15] + 134;"
          calcs += "^b[40] &= 0xFF;"
        }
        state = 917712377;
        continue;
      case 784888727:
        if (378672444) {
          calcs += "^b[25] ^= (b[37] + b[5] + b[4] + b[7] + b[38] + b[26] + " + Math.floor(Math.random() * 256) + ") & 0xFF;"
        } else {
          calcs += "^b[28] += b[11] + b[22] + b[17] + b[0] + b[8] + b[31] + 109;"
          calcs += "^b[28] &= 0xFF;"
        }
        state = 940496708;
        continue;
      case 785338584:
        if (83354649n) {
          calcs += "^b[30] += b[28] + b[29] + b[20] + b[5] + b[14] + b[24] + 107;"
          calcs += "^b[30] &= 0xFF;"
        } else {
          calcs += "^b[2] += b[39] + b[43] + b[38] + b[6] + b[18] + b[5] + 22;"
          calcs += "^b[2] &= 0xFF;"
        }
        state = 410681826;
        continue;
      case 786459983:
        if (62104356n) {
          calcs += "^b[24] -= b[9] + b[4] + b[28] + b[23] + b[3] + b[14] + 217;"
          calcs += "^b[24] &= 0xFF;"
        } else {
          calcs += "^b[32] += b[9] + b[6] + b[40] + b[22] + b[4] + b[13] + 162;"
          calcs += "^b[32] &= 0xFF;"
        }
        state = 190067285;
        continue;
      case 787067102:
        if (17308771n) {
          calcs += "^b[22] -= b[13] + b[6] + b[1] + b[23] + b[43] + b[32] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[22] &= 0xFF;"
        } else {
          calcs += "^b[14] += b[23] + b[0] + b[10] + b[42] + b[38] + b[2] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[14] &= 0xFF;"
        }
        state = 976615861;
        continue;
      case 789883991:
        if (Math.random() < 0.5) {
          calcs += "^b[17] += b[26] + b[12] + b[4] + b[18] + b[29] + b[25] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[17] &= 0xFF;"
        } else {
          calcs += "^b[41] ^= (b[2] + b[1] + b[19] + b[17] + b[15] + b[3] + " + Math.floor(Math.random() * 256) + ") & 0xFF;"
        }
        state = 965410634;
        continue;
      case 790738357:
        if (657295693) {
          calcs += "^b[5] -= b[19] + b[31] + b[39] + b[38] + b[0] + b[36] + 62;"
          calcs += "^b[5] &= 0xFF;"
        } else {
          calcs += "^b[30] += b[17] + b[24] + b[8] + b[9] + b[16] + b[18] + 104;"
          calcs += "^b[30] &= 0xFF;"
        }
        state = 790778736;
        continue;
      case 791903896:
        if (64085983n) {
          calcs += "^b[18] += b[39] + b[9] + b[29] + b[33] + b[32] + b[3] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[18] &= 0xFF;"
        } else {
          calcs += "^b[35] ^= (b[3] + b[22] + b[4] + b[14] + b[41] + b[10] + 230) & 0xFF;"
        }
        state = 478242659;
        continue;
      case 793300376:
        if (56756954n) {
          calcs += "^b[16] += b[23] + b[1] + b[0] + b[14] + b[37] + b[36] + 69;"
          calcs += "^b[16] &= 0xFF;"
        } else {
          calcs += "^b[43] += b[11] + b[15] + b[33] + b[35] + b[21] + b[25] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[43] &= 0xFF;"
        }
        state = 1039563113;
        continue;
      case 793788927:
        if (26014551n) {
          calcs += "^b[26] -= b[18] + b[1] + b[32] + b[39] + b[0] + b[7] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[26] &= 0xFF;"
        } else {
          calcs += "^b[0] -= b[30] + b[24] + b[37] + b[38] + b[14] + b[25] + 43;"
          calcs += "^b[0] &= 0xFF;"
        }
        state = 149837851;
        continue;
      case 797141609:
        if (Math.random() < 0.5) {
          calcs += "^b[18] -= b[8] + b[33] + b[11] + b[36] + b[25] + b[31] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[18] &= 0xFF;"
        } else {
          calcs += "^b[23] += b[36] + b[26] + b[8] + b[4] + b[10] + b[7] + 147;"
          calcs += "^b[23] &= 0xFF;"
        }
        state = 1017148224;
        continue;
      case 797360669:
        if (58321764n) {
          calcs += "^b[10] += b[39] + b[5] + b[42] + b[19] + b[36] + b[0] + 176;"
          calcs += "^b[10] &= 0xFF;"
        } else {
          calcs += "^b[1] += b[14] + b[33] + b[4] + b[34] + b[13] + b[18] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[1] &= 0xFF;"
        }
        state = 112359771;
        continue;
      case 797682017:
        if (Math.random() < 0.5) {
          calcs += "^b[36] ^= (b[42] + b[6] + b[11] + b[40] + b[33] + b[7] + 207) & 0xFF;"
        } else {
          calcs += "^b[31] ^= (b[13] + b[23] + b[21] + b[16] + b[32] + b[33] + 48) & 0xFF;"
        }
        state = 966366253;
        continue;
      case 797748313:
        if (Math.random() < 0.5) {
          calcs += "^b[25] -= b[11] + b[17] + b[34] + b[36] + b[4] + b[41] + 109;"
          calcs += "^b[25] &= 0xFF;"
        } else {
          calcs += "^b[22] ^= (b[26] + b[31] + b[9] + b[15] + b[14] + b[17] + " + Math.floor(Math.random() * 256) + ") & 0xFF;"
        }
        state = 1017282126;
        continue;
      case 798743267:
        if (923972252) {
          calcs += "^b[1] ^= (b[2] + b[30] + b[29] + b[20] + b[37] + b[12] + 46) & 0xFF;"
        } else {
          calcs += "^b[33] += b[27] + b[9] + b[21] + b[38] + b[23] + b[5] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[33] &= 0xFF;"
        }
        state = 663527695;
        continue;
      case 799331279:
        if (94155583n) {
          calcs += "^b[34] += b[15] + b[18] + b[26] + b[22] + b[38] + b[1] + 130;"
          calcs += "^b[34] &= 0xFF;"
        } else {
          calcs += "^b[15] += b[32] + b[31] + b[9] + b[20] + b[36] + b[18] + 132;"
          calcs += "^b[15] &= 0xFF;"
        }
        state = 470325773;
        continue;
      case 800362995:
        if (83638494n) {
          calcs += "^b[14] ^= (b[23] + b[20] + b[9] + b[27] + b[2] + b[32] + 187) & 0xFF;"
        } else {
          calcs += "^b[27] ^= (b[29] + b[21] + b[26] + b[33] + b[10] + b[31] + 111) & 0xFF;"
        }
        state = 1046932675;
        continue;
      case 800418041:
        if (1014699138) {
          calcs += "^b[26] -= b[43] + b[2] + b[13] + b[34] + b[3] + b[37] + 164;"
          calcs += "^b[26] &= 0xFF;"
        } else {
          calcs += "^b[11] -= b[16] + b[9] + b[43] + b[21] + b[7] + b[25] + 219;"
          calcs += "^b[11] &= 0xFF;"
        }
        state = 491600773;
        continue;
      case 800562337:
        if (86330299n) {
          calcs += "^b[8] ^= (b[33] + b[18] + b[35] + b[41] + b[39] + b[36] + 142) & 0xFF;"
        } else {
          calcs += "^b[26] -= b[2] + b[1] + b[17] + b[29] + b[10] + b[0] + 30;"
          calcs += "^b[26] &= 0xFF;"
        }
        state = 587165694;
        continue;
      case 805377128:
        if (79102690n) {
          calcs += "^b[25] -= b[9] + b[26] + b[41] + b[43] + b[5] + b[20] + 3;"
          calcs += "^b[25] &= 0xFF;"
        } else {
          calcs += "^b[5] += b[21] + b[2] + b[19] + b[16] + b[6] + b[23] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[5] &= 0xFF;"
        }
        state = 382251608;
        continue;
      case 805449259:
        if (Math.random() < 0.5) {
          calcs += "^b[15] -= b[13] + b[42] + b[32] + b[39] + b[34] + b[28] + 116;"
          calcs += "^b[15] &= 0xFF;"
        } else {
          calcs += "^b[2] -= b[29] + b[11] + b[17] + b[33] + b[15] + b[40] + 207;"
          calcs += "^b[2] &= 0xFF;"
        }
        state = 517174329;
        continue;
      case 805877939:
        if (178794287) {
          calcs += "^b[26] += b[35] + b[40] + b[43] + b[28] + b[18] + b[21] + 201;"
          calcs += "^b[26] &= 0xFF;"
        } else {
          calcs += "^b[26] += b[35] + b[37] + b[34] + b[43] + b[4] + b[19] + 244;"
          calcs += "^b[26] &= 0xFF;"
        }
        state = 874470674;
        continue;
      case 806112829:
        if (66941747n) {
          calcs += "^b[21] -= b[29] + b[20] + b[33] + b[0] + b[39] + b[27] + 230;"
          calcs += "^b[21] &= 0xFF;"
        } else {
          calcs += "^b[12] ^= (b[9] + b[23] + b[34] + b[14] + b[13] + b[10] + 147) & 0xFF;"
        }
        state = 807116734;
        continue;
      case 806248070:
        if (1073448998) {
          calcs += "^b[13] ^= (b[24] + b[17] + b[29] + b[14] + b[27] + b[31] + 48) & 0xFF;"
        } else {
          calcs += "^b[11] ^= (b[15] + b[36] + b[35] + b[38] + b[21] + b[43] + 45) & 0xFF;"
        }
        state = 291619859;
        continue;
      case 807171433:
        if (829909768) {
          calcs += "^b[1] -= b[30] + b[11] + b[24] + b[29] + b[36] + b[18] + 213;"
          calcs += "^b[1] &= 0xFF;"
        } else {
          calcs += "^b[5] ^= (b[20] + b[25] + b[35] + b[42] + b[18] + b[12] + 137) & 0xFF;"
        }
        state = 354099766;
        continue;
      case 810628019:
        if (87396112n) {
          calcs += "^b[17] += b[11] + b[26] + b[14] + b[30] + b[28] + b[12] + 137;"
          calcs += "^b[17] &= 0xFF;"
        } else {
          calcs += "^b[15] += b[21] + b[42] + b[25] + b[1] + b[18] + b[32] + 251;"
          calcs += "^b[15] &= 0xFF;"
        }
        state = 172627353;
        continue;
      case 811423735:
        if (403559033) {
          calcs += "^b[25] ^= (b[38] + b[33] + b[24] + b[40] + b[13] + b[32] + 63) & 0xFF;"
        } else {
          calcs += "^b[12] += b[14] + b[31] + b[17] + b[5] + b[22] + b[11] + 29;"
          calcs += "^b[12] &= 0xFF;"
        }
        state = 900748558;
        continue;
      case 811858629:
        if (Math.random() < 0.5) {
          calcs += "^b[29] ^= (b[34] + b[20] + b[30] + b[35] + b[8] + b[5] + 90) & 0xFF;"
        } else {
          calcs += "^b[40] += b[33] + b[12] + b[5] + b[27] + b[38] + b[2] + 118;"
          calcs += "^b[40] &= 0xFF;"
        }
        state = 2533527;
        continue;
      case 811872807:
        if (662232298) {
          calcs += "^b[9] -= b[21] + b[23] + b[14] + b[25] + b[43] + b[10] + 58;"
          calcs += "^b[9] &= 0xFF;"
        } else {
          calcs += "^b[21] -= b[16] + b[41] + b[5] + b[30] + b[20] + b[32] + 51;"
          calcs += "^b[21] &= 0xFF;"
        }
        state = 964411127;
        continue;
      case 812348187:
        if (112807228) {
          calcs += "^b[32] -= b[33] + b[9] + b[40] + b[15] + b[20] + b[24] + 105;"
          calcs += "^b[32] &= 0xFF;"
        } else {
          calcs += "^b[18] ^= (b[9] + b[25] + b[13] + b[29] + b[0] + b[24] + 21) & 0xFF;"
        }
        state = 576985818;
        continue;
      case 813144274:
        if (640866493) {
          calcs += "^b[4] += b[32] + b[28] + b[30] + b[42] + b[24] + b[34] + 208;"
          calcs += "^b[4] &= 0xFF;"
        } else {
          calcs += "^b[0] += b[37] + b[26] + b[14] + b[22] + b[21] + b[12] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[0] &= 0xFF;"
        }
        state = 303626156;
        continue;
      case 813512048:
        if (73234172n) {
          calcs += "^b[2] ^= (b[17] + b[30] + b[20] + b[3] + b[11] + b[25] + 212) & 0xFF;"
        } else {
          calcs += "^b[4] ^= (b[42] + b[18] + b[12] + b[5] + b[16] + b[37] + " + Math.floor(Math.random() * 256) + ") & 0xFF;"
        }
        state = 1033659483;
        continue;
      case 814323669:
        if (1017264808) {
          calcs += "^b[2] += b[26] + b[18] + b[14] + b[40] + b[34] + b[29] + 126;"
          calcs += "^b[2] &= 0xFF;"
        } else {
          calcs += "^b[33] += b[4] + b[41] + b[18] + b[43] + b[28] + b[25] + 2;"
          calcs += "^b[33] &= 0xFF;"
        }
        state = 687416720;
        continue;
      case 814967729:
        if (320507011) {
          calcs += "^b[15] ^= (b[31] + b[11] + b[18] + b[30] + b[4] + b[40] + 189) & 0xFF;"
        } else {
          calcs += "^b[26] -= b[4] + b[11] + b[31] + b[32] + b[28] + b[16] + 165;"
          calcs += "^b[26] &= 0xFF;"
        }
        state = 788749664;
        continue;
      case 816828515:
        if (277611201) {
          calcs += "^b[20] ^= (b[19] + b[13] + b[25] + b[39] + b[28] + b[36] + 178) & 0xFF;"
        } else {
          calcs += "^b[28] -= b[1] + b[9] + b[6] + b[43] + b[3] + b[10] + 51;"
          calcs += "^b[28] &= 0xFF;"
        }
        state = 812491792;
        continue;
      case 817291488:
        if (494633775) {
          calcs += "^b[28] ^= (b[1] + b[9] + b[7] + b[32] + b[18] + b[42] + 240) & 0xFF;"
        } else {
          calcs += "^b[38] += b[4] + b[29] + b[22] + b[2] + b[14] + b[37] + 224;"
          calcs += "^b[38] &= 0xFF;"
        }
        state = 199536660;
        continue;
      case 818621328:
        if (979366561) {
          calcs += "^b[22] += b[34] + b[39] + b[18] + b[9] + b[24] + b[0] + 74;"
          calcs += "^b[22] &= 0xFF;"
        } else {
          calcs += "^b[2] ^= (b[32] + b[25] + b[29] + b[23] + b[11] + b[7] + 58) & 0xFF;"
        }
        state = 693801922;
        continue;
      case 818877870:
        if (779676322) {
          calcs += "^b[14] -= b[35] + b[18] + b[20] + b[33] + b[2] + b[3] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[14] &= 0xFF;"
        } else {
          calcs += "^b[18] -= b[41] + b[12] + b[21] + b[27] + b[24] + b[6] + 193;"
          calcs += "^b[18] &= 0xFF;"
        }
        state = 92859514;
        continue;
      case 818884951:
        if (1038928111) {
          calcs += "^b[41] -= b[24] + b[26] + b[19] + b[8] + b[12] + b[6] + 228;"
          calcs += "^b[41] &= 0xFF;"
        } else {
          calcs += "^b[28] += b[40] + b[23] + b[19] + b[20] + b[13] + b[43] + 220;"
          calcs += "^b[28] &= 0xFF;"
        }
        state = 859561268;
        continue;
      case 819632228:
        if (Math.random() < 0.5) {
          calcs += "^b[26] += b[14] + b[39] + b[18] + b[38] + b[23] + b[3] + 212;"
          calcs += "^b[26] &= 0xFF;"
        } else {
          calcs += "^b[29] ^= (b[31] + b[38] + b[2] + b[43] + b[15] + b[33] + 61) & 0xFF;"
        }
        state = 633227651;
        continue;
      case 820331184:
        if (37573668n) {
          calcs += "^b[2] += b[27] + b[28] + b[20] + b[15] + b[22] + b[36] + 79;"
          calcs += "^b[2] &= 0xFF;"
        } else {
          calcs += "^b[21] -= b[22] + b[2] + b[33] + b[28] + b[10] + b[31] + 98;"
          calcs += "^b[21] &= 0xFF;"
        }
        state = 190025954;
        continue;
      case 823596773:
        if (Math.random() < 0.5) {
          calcs += "^b[0] ^= (b[20] + b[18] + b[34] + b[43] + b[26] + b[2] + 224) & 0xFF;"
        } else {
          calcs += "^b[42] ^= (b[11] + b[7] + b[23] + b[13] + b[37] + b[43] + 216) & 0xFF;"
        }
        state = 888771028;
        continue;
      case 823741785:
        if (708381980) {
          calcs += "^b[7] += b[32] + b[31] + b[38] + b[9] + b[11] + b[23] + 161;"
          calcs += "^b[7] &= 0xFF;"
        } else {
          calcs += "^b[36] -= b[8] + b[7] + b[27] + b[43] + b[24] + b[15] + 174;"
          calcs += "^b[36] &= 0xFF;"
        }
        state = 956927383;
        continue;
      case 824267648:
        if (78309846n) {
          calcs += "^b[22] -= b[29] + b[7] + b[32] + b[34] + b[4] + b[36] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[22] &= 0xFF;"
        } else {
          calcs += "^b[30] -= b[22] + b[29] + b[18] + b[17] + b[35] + b[6] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[30] &= 0xFF;"
        }
        state = 605829637;
        continue;
      case 824342282:
        if (45885881n) {
          calcs += "^b[4] -= b[36] + b[39] + b[23] + b[24] + b[37] + b[5] + 157;"
          calcs += "^b[4] &= 0xFF;"
        } else {
          calcs += "^b[3] -= b[37] + b[33] + b[6] + b[19] + b[22] + b[21] + 15;"
          calcs += "^b[3] &= 0xFF;"
        }
        state = 110180607;
        continue;
      case 827518754:
        if (Math.random() < 0.5) {
          calcs += "^b[35] ^= (b[24] + b[43] + b[21] + b[2] + b[34] + b[40] + 28) & 0xFF;"
        } else {
          calcs += "^b[7] ^= (b[43] + b[20] + b[16] + b[11] + b[13] + b[1] + 210) & 0xFF;"
        }
        state = 84285850;
        continue;
      case 828950227:
        if (18378014n) {
          calcs += "^b[0] ^= (b[7] + b[11] + b[4] + b[23] + b[42] + b[14] + 73) & 0xFF;"
        } else {
          calcs += "^b[30] += b[2] + b[1] + b[4] + b[24] + b[5] + b[12] + 220;"
          calcs += "^b[30] &= 0xFF;"
        }
        state = 339810937;
        continue;
      case 829813710:
        if (Math.random() < 0.5) {
          calcs += "^b[12] ^= (b[20] + b[27] + b[40] + b[34] + b[23] + b[21] + 195) & 0xFF;"
        } else {
          calcs += "^b[40] ^= (b[35] + b[22] + b[17] + b[2] + b[20] + b[18] + 80) & 0xFF;"
        }
        state = 109608343;
        continue;
      case 830396152:
        if (Math.random() < 0.5) {
          calcs += "^b[7] ^= (b[23] + b[6] + b[21] + b[43] + b[26] + b[22] + 145) & 0xFF;"
        } else {
          calcs += "^b[24] ^= (b[11] + b[25] + b[36] + b[21] + b[2] + b[7] + 127) & 0xFF;"
        }
        state = 209126072;
        continue;
      case 831762542:
        if (935391580) {
          calcs += "^b[0] -= b[41] + b[2] + b[40] + b[9] + b[3] + b[7] + 255;"
          calcs += "^b[0] &= 0xFF;"
        } else {
          calcs += "^b[33] ^= (b[4] + b[43] + b[36] + b[16] + b[41] + b[18] + 146) & 0xFF;"
        }
        state = 1039585871;
        continue;
      case 831977705:
        if (58133538n) {
          calcs += "^b[0] ^= (b[26] + b[43] + b[25] + b[6] + b[33] + b[39] + 126) & 0xFF;"
        } else {
          calcs += "^b[35] += b[3] + b[12] + b[36] + b[28] + b[7] + b[41] + 227;"
          calcs += "^b[35] &= 0xFF;"
        }
        state = 585745858;
        continue;
      case 832291230:
        if (Math.random() < 0.5) {
          calcs += "^b[0] -= b[34] + b[3] + b[41] + b[28] + b[29] + b[36] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[0] &= 0xFF;"
        } else {
          calcs += "^b[29] += b[12] + b[28] + b[39] + b[2] + b[30] + b[14] + 128;"
          calcs += "^b[29] &= 0xFF;"
        }
        state = 157390982;
        continue;
      case 834936404:
        if (1015569248) {
          calcs += "^b[20] += b[32] + b[24] + b[15] + b[30] + b[16] + b[5] + 55;"
          calcs += "^b[20] &= 0xFF;"
        } else {
          calcs += "^b[0] += b[39] + b[5] + b[14] + b[43] + b[25] + b[36] + 164;"
          calcs += "^b[0] &= 0xFF;"
        }
        state = 145715616;
        continue;
      case 835741624:
        if (45808178n) {
          calcs += "^b[6] -= b[11] + b[8] + b[37] + b[39] + b[12] + b[33] + 185;"
          calcs += "^b[6] &= 0xFF;"
        } else {
          calcs += "^b[23] += b[26] + b[37] + b[5] + b[12] + b[34] + b[39] + 90;"
          calcs += "^b[23] &= 0xFF;"
        }
        state = 452747552;
        continue;
      case 836184180:
        if (1052269683) {
          calcs += "^b[42] -= b[40] + b[36] + b[22] + b[27] + b[5] + b[13] + 142;"
          calcs += "^b[42] &= 0xFF;"
        } else {
          calcs += "^b[42] -= b[23] + b[28] + b[39] + b[16] + b[17] + b[2] + 49;"
          calcs += "^b[42] &= 0xFF;"
        }
        state = 706884477;
        continue;
      case 837292277:
        if (52531050n) {
          calcs += "^b[31] += b[8] + b[42] + b[38] + b[19] + b[22] + b[25] + 138;"
          calcs += "^b[31] &= 0xFF;"
        } else {
          calcs += "^b[19] -= b[27] + b[25] + b[34] + b[14] + b[11] + b[28] + 139;"
          calcs += "^b[19] &= 0xFF;"
        }
        state = 537574977;
        continue;
      case 838818428:
        if (54642374n) {
          calcs += "^b[3] ^= (b[2] + b[26] + b[25] + b[36] + b[42] + b[23] + 150) & 0xFF;"
        } else {
          calcs += "^b[3] ^= (b[19] + b[31] + b[1] + b[26] + b[6] + b[36] + 149) & 0xFF;"
        }
        state = 757570921;
        continue;
      case 839201324:
        if (Math.random() < 0.5) {
          calcs += "^b[9] += b[27] + b[19] + b[33] + b[24] + b[10] + b[17] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[9] &= 0xFF;"
        } else {
          calcs += "^b[11] -= b[12] + b[27] + b[40] + b[37] + b[16] + b[14] + 190;"
          calcs += "^b[11] &= 0xFF;"
        }
        state = 693243499;
        continue;
      case 839728295:
        if (379163964) {
          calcs += "^b[7] -= b[14] + b[41] + b[37] + b[34] + b[3] + b[5] + 152;"
          calcs += "^b[7] &= 0xFF;"
        } else {
          calcs += "^b[27] -= b[15] + b[14] + b[1] + b[28] + b[18] + b[13] + 139;"
          calcs += "^b[27] &= 0xFF;"
        }
        state = 156129988;
        continue;
      case 843507186:
        if (70702504n) {
          calcs += "^b[28] += b[41] + b[9] + b[22] + b[29] + b[18] + b[14] + 14;"
          calcs += "^b[28] &= 0xFF;"
        } else {
          calcs += "^b[4] += b[7] + b[36] + b[25] + b[22] + b[30] + b[42] + 121;"
          calcs += "^b[4] &= 0xFF;"
        }
        state = 747622287;
        continue;
      case 843821990:
        if (Math.random() < 0.5) {
          calcs += "^b[0] ^= (b[12] + b[30] + b[6] + b[17] + b[4] + b[20] + 92) & 0xFF;"
        } else {
          calcs += "^b[28] -= b[18] + b[17] + b[40] + b[12] + b[24] + b[2] + 116;"
          calcs += "^b[28] &= 0xFF;"
        }
        state = 826598582;
        continue;
      case 846465521:
        if (Math.random() < 0.5) {
          calcs += "^b[25] -= b[16] + b[15] + b[13] + b[24] + b[3] + b[7] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[25] &= 0xFF;"
        } else {
          calcs += "^b[19] ^= (b[8] + b[3] + b[22] + b[30] + b[26] + b[2] + 4) & 0xFF;"
        }
        state = 539175862;
        continue;
      case 847448000:
        if (Math.random() < 0.5) {
          calcs += "^b[39] ^= (b[13] + b[29] + b[1] + b[3] + b[22] + b[16] + 37) & 0xFF;"
        } else {
          calcs += "^b[19] += b[26] + b[27] + b[29] + b[32] + b[14] + b[21] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[19] &= 0xFF;"
        }
        state = 1029815228;
        continue;
      case 847930810:
        if (Math.random() < 0.5) {
          calcs += "^b[15] ^= (b[5] + b[24] + b[22] + b[34] + b[8] + b[25] + 210) & 0xFF;"
        } else {
          calcs += "^b[36] += b[19] + b[12] + b[38] + b[14] + b[42] + b[41] + 10;"
          calcs += "^b[36] &= 0xFF;"
        }
        state = 73190189;
        continue;
      case 848118829:
        if (277861827) {
          calcs += "^b[31] -= b[11] + b[37] + b[3] + b[30] + b[17] + b[8] + 72;"
          calcs += "^b[31] &= 0xFF;"
        } else {
          calcs += "^b[8] ^= (b[1] + b[12] + b[11] + b[17] + b[37] + b[2] + 55) & 0xFF;"
        }
        state = 550028400;
        continue;
      case 848323846:
        if (353491624) {
          calcs += "^b[42] += b[20] + b[34] + b[22] + b[16] + b[39] + b[38] + 196;"
          calcs += "^b[42] &= 0xFF;"
        } else {
          calcs += "^b[34] -= b[28] + b[8] + b[13] + b[16] + b[24] + b[1] + 237;"
          calcs += "^b[34] &= 0xFF;"
        }
        state = 823142988;
        continue;
      case 848669108:
        if (Math.random() < 0.5) {
          calcs += "^b[20] += b[21] + b[0] + b[32] + b[13] + b[8] + b[11] + 37;"
          calcs += "^b[20] &= 0xFF;"
        } else {
          calcs += "^b[14] += b[32] + b[1] + b[4] + b[6] + b[16] + b[33] + 70;"
          calcs += "^b[14] &= 0xFF;"
        }
        state = 562978730;
        continue;
      case 849052831:
        if (58722981n) {
          calcs += "^b[32] += b[1] + b[8] + b[21] + b[43] + b[36] + b[30] + 126;"
          calcs += "^b[32] &= 0xFF;"
        } else {
          calcs += "^b[23] += b[13] + b[24] + b[18] + b[36] + b[34] + b[14] + 232;"
          calcs += "^b[23] &= 0xFF;"
        }
        state = 616958451;
        continue;
      case 849670022:
        if (44976030n) {
          calcs += "^b[18] ^= (b[28] + b[23] + b[35] + b[29] + b[13] + b[24] + 57) & 0xFF;"
        } else {
          calcs += "^b[18] ^= (b[8] + b[23] + b[27] + b[30] + b[25] + b[32] + 74) & 0xFF;"
        }
        state = 1014090476;
        continue;
      case 851842599:
        if (Math.random() < 0.5) {
          calcs += "^b[17] -= b[31] + b[10] + b[41] + b[43] + b[16] + b[11] + 98;"
          calcs += "^b[17] &= 0xFF;"
        } else {
          calcs += "^b[30] ^= (b[34] + b[4] + b[2] + b[13] + b[12] + b[35] + 110) & 0xFF;"
        }
        state = 641913492;
        continue;
      case 852370076:
        if (51835112n) {
          calcs += "^b[6] -= b[27] + b[26] + b[3] + b[13] + b[32] + b[20] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[6] &= 0xFF;"
        } else {
          calcs += "^b[25] += b[13] + b[34] + b[7] + b[39] + b[19] + b[5] + 96;"
          calcs += "^b[25] &= 0xFF;"
        }
        state = 120623554;
        continue;
      case 852933629:
        if (97919922n) {
          calcs += "^b[42] -= b[0] + b[7] + b[22] + b[14] + b[24] + b[33] + 163;"
          calcs += "^b[42] &= 0xFF;"
        } else {
          calcs += "^b[43] ^= (b[20] + b[34] + b[21] + b[6] + b[17] + b[16] + 92) & 0xFF;"
        }
        state = 360676433;
        continue;
      case 856154656:
        if (Math.random() < 0.5) {
          calcs += "^b[33] += b[29] + b[1] + b[18] + b[15] + b[34] + b[2] + 94;"
          calcs += "^b[33] &= 0xFF;"
        } else {
          calcs += "^b[7] ^= (b[5] + b[40] + b[15] + b[22] + b[1] + b[10] + 209) & 0xFF;"
        }
        state = 173309449;
        continue;
      case 856589568:
        if (138968097) {
          calcs += "^b[28] ^= (b[30] + b[13] + b[39] + b[2] + b[7] + b[8] + 19) & 0xFF;"
        } else {
          calcs += "^b[32] += b[40] + b[41] + b[19] + b[7] + b[36] + b[18] + 29;"
          calcs += "^b[32] &= 0xFF;"
        }
        state = 825154919;
        continue;
      case 857076787:
        if (Math.random() < 0.5) {
          calcs += "^b[7] ^= (b[29] + b[41] + b[34] + b[9] + b[32] + b[16] + " + Math.floor(Math.random() * 256) + ") & 0xFF;"
        } else {
          calcs += "^b[31] -= b[35] + b[37] + b[5] + b[42] + b[33] + b[41] + 16;"
          calcs += "^b[31] &= 0xFF;"
        }
        state = 552909367;
        continue;
      case 858931501:
        if (88828338n) {
          calcs += "^b[1] += b[32] + b[28] + b[16] + b[2] + b[29] + b[37] + 132;"
          calcs += "^b[1] &= 0xFF;"
        } else {
          calcs += "^b[43] ^= (b[31] + b[10] + b[36] + b[24] + b[9] + b[27] + 11) & 0xFF;"
        }
        state = 924359637;
        continue;
      case 860011824:
        if (79631691n) {
          calcs += "^b[43] ^= (b[9] + b[6] + b[0] + b[20] + b[40] + b[39] + 115) & 0xFF;"
        } else {
          calcs += "^b[8] += b[30] + b[19] + b[3] + b[13] + b[35] + b[18] + 222;"
          calcs += "^b[8] &= 0xFF;"
        }
        state = 220262346;
        continue;
      case 860260968:
        if (913529630) {
          calcs += "^b[41] -= b[2] + b[12] + b[28] + b[9] + b[16] + b[26] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[41] &= 0xFF;"
        } else {
          calcs += "^b[8] ^= (b[13] + b[26] + b[10] + b[4] + b[32] + b[21] + 142) & 0xFF;"
        }
        state = 295831432;
        continue;
      case 860441400:
        if (916316270) {
          calcs += "^b[1] ^= (b[7] + b[40] + b[25] + b[37] + b[30] + b[18] + 215) & 0xFF;"
        } else {
          calcs += "^b[39] -= b[40] + b[2] + b[22] + b[25] + b[10] + b[13] + 94;"
          calcs += "^b[39] &= 0xFF;"
        }
        state = 450749684;
        continue;
      case 861075392:
        if (28208555n) {
          calcs += "^b[40] += b[11] + b[28] + b[42] + b[20] + b[27] + b[13] + 142;"
          calcs += "^b[40] &= 0xFF;"
        } else {
          calcs += "^b[23] += b[29] + b[0] + b[4] + b[18] + b[39] + b[36] + 111;"
          calcs += "^b[23] &= 0xFF;"
        }
        state = 44718802;
        continue;
      case 861510777:
        if (46567275n) {
          calcs += "^b[10] -= b[41] + b[9] + b[25] + b[20] + b[28] + b[27] + 235;"
          calcs += "^b[10] &= 0xFF;"
        } else {
          calcs += "^b[20] += b[28] + b[15] + b[21] + b[33] + b[14] + b[9] + 201;"
          calcs += "^b[20] &= 0xFF;"
        }
        state = 79140047;
        continue;
      case 861726887:
        if (Math.random() < 0.5) {
          calcs += "^b[24] += b[8] + b[33] + b[10] + b[36] + b[18] + b[11] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[24] &= 0xFF;"
        } else {
          calcs += "^b[19] ^= (b[3] + b[6] + b[5] + b[33] + b[32] + b[10] + 194) & 0xFF;"
        }
        state = 100909921;
        continue;
      case 862518440:
        if (Math.random() < 0.5) {
          calcs += "^b[1] += b[3] + b[28] + b[42] + b[41] + b[27] + b[7] + 98;"
          calcs += "^b[1] &= 0xFF;"
        } else {
          calcs += "^b[7] -= b[23] + b[4] + b[20] + b[22] + b[0] + b[11] + 113;"
          calcs += "^b[7] &= 0xFF;"
        }
        state = 717799117;
        continue;
      case 862632486:
        if (986135796) {
          calcs += "^b[43] ^= (b[13] + b[8] + b[35] + b[18] + b[2] + b[32] + " + Math.floor(Math.random() * 256) + ") & 0xFF;"
        } else {
          calcs += "^b[0] ^= (b[40] + b[36] + b[42] + b[23] + b[17] + b[34] + " + Math.floor(Math.random() * 256) + ") & 0xFF;"
        }
        state = 1073280106;
        continue;
      case 864991412:
        if (995008496) {
          calcs += "^b[17] += b[15] + b[38] + b[2] + b[35] + b[34] + b[39] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[17] &= 0xFF;"
        } else {
          calcs += "^b[33] += b[16] + b[29] + b[3] + b[37] + b[30] + b[41] + 204;"
          calcs += "^b[33] &= 0xFF;"
        }
        state = 705243277;
        continue;
      case 865663178:
        if (Math.random() < 0.5) {
          calcs += "^b[39] -= b[0] + b[37] + b[12] + b[4] + b[29] + b[22] + 114;"
          calcs += "^b[39] &= 0xFF;"
        } else {
          calcs += "^b[18] -= b[10] + b[5] + b[25] + b[35] + b[34] + b[20] + 228;"
          calcs += "^b[18] &= 0xFF;"
        }
        state = 815767968;
        continue;
      case 866514753:
        if (61186797n) {
          calcs += "^b[42] += b[8] + b[9] + b[31] + b[32] + b[20] + b[17] + 135;"
          calcs += "^b[42] &= 0xFF;"
        } else {
          calcs += "^b[25] -= b[37] + b[8] + b[39] + b[17] + b[9] + b[43] + 3;"
          calcs += "^b[25] &= 0xFF;"
        }
        state = 134900190;
        continue;
      case 867656279:
        if (47870775n) {
          calcs += "^b[3] -= b[34] + b[43] + b[8] + b[1] + b[14] + b[30] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[3] &= 0xFF;"
        } else {
          calcs += "^b[19] ^= (b[42] + b[12] + b[25] + b[8] + b[28] + b[11] + 49) & 0xFF;"
        }
        state = 1018641108;
        continue;
      case 872415933:
        if (Math.random() < 0.5) {
          calcs += "^b[28] -= b[22] + b[23] + b[10] + b[20] + b[11] + b[0] + 191;"
          calcs += "^b[28] &= 0xFF;"
        } else {
          calcs += "^b[37] += b[16] + b[38] + b[1] + b[19] + b[33] + b[25] + 125;"
          calcs += "^b[37] &= 0xFF;"
        }
        state = 291220038;
        continue;
      case 874527885:
        if (85573290n) {
          calcs += "^b[32] -= b[4] + b[22] + b[25] + b[13] + b[27] + b[1] + 79;"
          calcs += "^b[32] &= 0xFF;"
        } else {
          calcs += "^b[3] ^= (b[41] + b[28] + b[4] + b[37] + b[14] + b[24] + 235) & 0xFF;"
        }
        state = 626533280;
        continue;
      case 875167420:
        if (Math.random() < 0.5) {
          calcs += "^b[0] ^= (b[19] + b[25] + b[10] + b[18] + b[13] + b[43] + 141) & 0xFF;"
        } else {
          calcs += "^b[21] += b[29] + b[3] + b[17] + b[22] + b[41] + b[18] + 133;"
          calcs += "^b[21] &= 0xFF;"
        }
        state = 947679299;
        continue;
      case 875196562:
        if (863169366) {
          calcs += "^b[34] += b[6] + b[43] + b[35] + b[1] + b[31] + b[28] + 122;"
          calcs += "^b[34] &= 0xFF;"
        } else {
          calcs += "^b[35] -= b[33] + b[31] + b[40] + b[41] + b[0] + b[32] + 134;"
          calcs += "^b[35] &= 0xFF;"
        }
        state = 206024304;
        continue;
      case 876140638:
        if (Math.random() < 0.5) {
          calcs += "^b[33] ^= (b[4] + b[39] + b[6] + b[5] + b[1] + b[34] + 129) & 0xFF;"
        } else {
          calcs += "^b[3] -= b[8] + b[40] + b[10] + b[39] + b[16] + b[28] + 98;"
          calcs += "^b[3] &= 0xFF;"
        }
        state = 908241978;
        continue;
      case 880735562:
        if (864008641) {
          calcs += "^b[5] += b[1] + b[24] + b[18] + b[34] + b[43] + b[8] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[5] &= 0xFF;"
        } else {
          calcs += "^b[24] ^= (b[23] + b[19] + b[1] + b[13] + b[3] + b[2] + 245) & 0xFF;"
        }
        state = 689259308;
        continue;
      case 881121355:
        if (1026376468) {
          calcs += "^b[35] -= b[24] + b[21] + b[27] + b[16] + b[1] + b[25] + 206;"
          calcs += "^b[35] &= 0xFF;"
        } else {
          calcs += "^b[42] ^= (b[43] + b[6] + b[18] + b[1] + b[12] + b[23] + 96) & 0xFF;"
        }
        state = 814791371;
        continue;
      case 881412225:
        if (152230884) {
          calcs += "^b[26] -= b[11] + b[0] + b[4] + b[29] + b[18] + b[10] + 32;"
          calcs += "^b[26] &= 0xFF;"
        } else {
          calcs += "^b[0] -= b[43] + b[4] + b[5] + b[29] + b[6] + b[24] + 208;"
          calcs += "^b[0] &= 0xFF;"
        }
        state = 687219669;
        continue;
      case 881440612:
        if (159908227) {
          calcs += "^b[3] ^= (b[12] + b[41] + b[34] + b[23] + b[1] + b[36] + 109) & 0xFF;"
        } else {
          calcs += "^b[17] -= b[16] + b[19] + b[4] + b[9] + b[36] + b[11] + 80;"
          calcs += "^b[17] &= 0xFF;"
        }
        state = 172219356;
        continue;
      case 881848114:
        if (185191464) {
          calcs += "^b[40] -= b[39] + b[30] + b[4] + b[41] + b[38] + b[35] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[40] &= 0xFF;"
        } else {
          calcs += "^b[39] += b[42] + b[37] + b[40] + b[30] + b[3] + b[29] + 55;"
          calcs += "^b[39] &= 0xFF;"
        }
        state = 760718050;
        continue;
      case 882184715:
        if (70257542n) {
          calcs += "^b[14] -= b[35] + b[20] + b[10] + b[4] + b[16] + b[28] + 173;"
          calcs += "^b[14] &= 0xFF;"
        } else {
          calcs += "^b[18] -= b[30] + b[35] + b[15] + b[41] + b[34] + b[22] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[18] &= 0xFF;"
        }
        state = 573249288;
        continue;
      case 882237139:
        if (73870344n) {
          calcs += "^b[18] -= b[13] + b[0] + b[42] + b[43] + b[12] + b[21] + 130;"
          calcs += "^b[18] &= 0xFF;"
        } else {
          calcs += "^b[4] ^= (b[41] + b[37] + b[19] + b[0] + b[18] + b[43] + 248) & 0xFF;"
        }
        state = 1035749047;
        continue;
      case 887720569:
        if (955008247) {
          calcs += "^b[11] -= b[42] + b[26] + b[29] + b[30] + b[33] + b[0] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[11] &= 0xFF;"
        } else {
          calcs += "^b[12] ^= (b[5] + b[8] + b[25] + b[3] + b[7] + b[13] + 145) & 0xFF;"
        }
        state = 63390636;
        continue;
      case 888027124:
        if (35518629n) {
          calcs += "^b[18] -= b[19] + b[6] + b[34] + b[32] + b[20] + b[39] + 211;"
          calcs += "^b[18] &= 0xFF;"
        } else {
          calcs += "^b[27] -= b[13] + b[31] + b[1] + b[23] + b[43] + b[17] + 248;"
          calcs += "^b[27] &= 0xFF;"
        }
        state = 31680780;
        continue;
      case 889551494:
        if (58238441n) {
          calcs += "^b[21] -= b[23] + b[33] + b[27] + b[28] + b[2] + b[25] + 52;"
          calcs += "^b[21] &= 0xFF;"
        } else {
          calcs += "^b[1] ^= (b[21] + b[5] + b[27] + b[36] + b[9] + b[23] + 51) & 0xFF;"
        }
        state = 444475662;
        continue;
      case 891821885:
        if (639214279) {
          calcs += "^b[21] ^= (b[27] + b[13] + b[17] + b[34] + b[40] + b[14] + " + Math.floor(Math.random() * 256) + ") & 0xFF;"
        } else {
          calcs += "^b[28] ^= (b[5] + b[19] + b[41] + b[23] + b[34] + b[32] + 227) & 0xFF;"
        }
        state = 994661253;
        continue;
      case 892268737:
        if (497933808) {
          calcs += "^b[23] += b[16] + b[22] + b[17] + b[37] + b[3] + b[29] + 52;"
          calcs += "^b[23] &= 0xFF;"
        } else {
          calcs += "^b[5] ^= (b[20] + b[31] + b[40] + b[10] + b[39] + b[16] + 196) & 0xFF;"
        }
        state = 926975771;
        continue;
      case 892829538:
        if (Math.random() < 0.5) {
          calcs += "^b[1] -= b[0] + b[6] + b[4] + b[30] + b[36] + b[40] + 69;"
          calcs += "^b[1] &= 0xFF;"
        } else {
          calcs += "^b[13] += b[12] + b[41] + b[29] + b[27] + b[7] + b[5] + 91;"
          calcs += "^b[13] &= 0xFF;"
        }
        state = 463297346;
        continue;
      case 895117942:
        if (700243138) {
          calcs += "^b[33] -= b[16] + b[2] + b[43] + b[1] + b[35] + b[34] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[33] &= 0xFF;"
        } else {
          calcs += "^b[13] ^= (b[20] + b[26] + b[37] + b[9] + b[29] + b[16] + 195) & 0xFF;"
        }
        state = 7499478;
        continue;
      case 895572296:
        if (Math.random() < 0.5) {
          calcs += "^b[15] ^= (b[12] + b[27] + b[32] + b[35] + b[40] + b[0] + " + Math.floor(Math.random() * 256) + ") & 0xFF;"
        } else {
          calcs += "^b[24] += b[33] + b[38] + b[21] + b[42] + b[23] + b[17] + 94;"
          calcs += "^b[24] &= 0xFF;"
        }
        state = 302957949;
        continue;
      case 897152026:
        if (83052088) {
          calcs += "^b[29] -= b[30] + b[34] + b[15] + b[42] + b[23] + b[16] + 4;"
          calcs += "^b[29] &= 0xFF;"
        } else {
          calcs += "^b[8] += b[12] + b[16] + b[14] + b[4] + b[34] + b[23] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[8] &= 0xFF;"
        }
        state = 386052172;
        continue;
      case 897254511:
        if (99197999n) {
          calcs += "^b[0] -= b[13] + b[33] + b[34] + b[27] + b[21] + b[24] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[0] &= 0xFF;"
        } else {
          calcs += "^b[9] += b[38] + b[29] + b[25] + b[2] + b[32] + b[21] + 73;"
          calcs += "^b[9] &= 0xFF;"
        }
        state = 696295201;
        continue;
      case 897843229:
        if (378121307) {
          calcs += "^b[30] ^= (b[35] + b[3] + b[20] + b[26] + b[37] + b[32] + 10) & 0xFF;"
        } else {
          calcs += "^b[29] ^= (b[14] + b[1] + b[18] + b[20] + b[17] + b[34] + " + Math.floor(Math.random() * 256) + ") & 0xFF;"
        }
        state = 662540068;
        continue;
      case 898171258:
        if (Math.random() < 0.5) {
          calcs += "^b[4] += b[35] + b[24] + b[25] + b[36] + b[29] + b[20] + 234;"
          calcs += "^b[4] &= 0xFF;"
        } else {
          calcs += "^b[29] -= b[2] + b[18] + b[36] + b[27] + b[0] + b[33] + 254;"
          calcs += "^b[29] &= 0xFF;"
        }
        state = 700848921;
        continue;
      case 898191023:
        if (80740723n) {
          calcs += "^b[33] -= b[16] + b[13] + b[1] + b[29] + b[30] + b[40] + 77;"
          calcs += "^b[33] &= 0xFF;"
        } else {
          calcs += "^b[43] -= b[21] + b[36] + b[6] + b[27] + b[37] + b[24] + 237;"
          calcs += "^b[43] &= 0xFF;"
        }
        state = 283987884;
        continue;
      case 899494737:
        if (57773420n) {
          calcs += "^b[30] ^= (b[23] + b[12] + b[3] + b[28] + b[2] + b[18] + 53) & 0xFF;"
        } else {
          calcs += "^b[35] += b[38] + b[34] + b[24] + b[28] + b[5] + b[23] + 226;"
          calcs += "^b[35] &= 0xFF;"
        }
        state = 458610491;
        continue;
      case 899930749:
        if (Math.random() < 0.5) {
          calcs += "^b[11] ^= (b[2] + b[21] + b[40] + b[42] + b[43] + b[35] + " + Math.floor(Math.random() * 256) + ") & 0xFF;"
        } else {
          calcs += "^b[26] -= b[38] + b[36] + b[35] + b[24] + b[3] + b[1] + 26;"
          calcs += "^b[26] &= 0xFF;"
        }
        state = 445153744;
        continue;
      case 900576857:
        if (238361334) {
          calcs += "^b[34] += b[42] + b[11] + b[1] + b[19] + b[4] + b[18] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[34] &= 0xFF;"
        } else {
          calcs += "^b[27] ^= (b[31] + b[7] + b[29] + b[33] + b[25] + b[38] + 60) & 0xFF;"
        }
        state = 391179986;
        continue;
      case 900591134:
        if (38067744n) {
          calcs += "^b[32] ^= (b[0] + b[40] + b[41] + b[24] + b[22] + b[3] + 232) & 0xFF;"
        } else {
          calcs += "^b[12] ^= (b[10] + b[15] + b[16] + b[34] + b[27] + b[14] + 89) & 0xFF;"
        }
        state = 881590759;
        continue;
      case 900739574:
        if (16520121n) {
          calcs += "^b[32] += b[7] + b[37] + b[29] + b[16] + b[3] + b[25] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[32] &= 0xFF;"
        } else {
          calcs += "^b[14] -= b[18] + b[0] + b[42] + b[4] + b[6] + b[41] + 130;"
          calcs += "^b[14] &= 0xFF;"
        }
        state = 733065495;
        continue;
      case 901371023:
        if (222235966) {
          calcs += "^b[12] ^= (b[34] + b[26] + b[5] + b[32] + b[36] + b[8] + " + Math.floor(Math.random() * 256) + ") & 0xFF;"
        } else {
          calcs += "^b[6] -= b[33] + b[11] + b[20] + b[15] + b[1] + b[31] + 62;"
          calcs += "^b[6] &= 0xFF;"
        }
        state = 1056362419;
        continue;
      case 901377278:
        if (Math.random() < 0.5) {
          calcs += "^b[15] ^= (b[32] + b[26] + b[30] + b[28] + b[40] + b[38] + 179) & 0xFF;"
        } else {
          calcs += "^b[9] += b[14] + b[2] + b[38] + b[20] + b[12] + b[35] + 108;"
          calcs += "^b[9] &= 0xFF;"
        }
        state = 404533668;
        continue;
      case 903508757:
        if (788010403) {
          calcs += "^b[36] -= b[3] + b[31] + b[12] + b[16] + b[24] + b[43] + 185;"
          calcs += "^b[36] &= 0xFF;"
        } else {
          calcs += "^b[42] ^= (b[14] + b[6] + b[29] + b[16] + b[10] + b[43] + " + Math.floor(Math.random() * 256) + ") & 0xFF;"
        }
        state = 66245927;
        continue;
      case 906680424:
        if (Math.random() < 0.5) {
          calcs += "^b[10] += b[13] + b[27] + b[23] + b[38] + b[2] + b[18] + 18;"
          calcs += "^b[10] &= 0xFF;"
        } else {
          calcs += "^b[1] ^= (b[0] + b[36] + b[39] + b[25] + b[30] + b[28] + 186) & 0xFF;"
        }
        state = 828506322;
        continue;
      case 907717109:
        if (895984808) {
          calcs += "^b[7] ^= (b[23] + b[8] + b[16] + b[39] + b[31] + b[34] + " + Math.floor(Math.random() * 256) + ") & 0xFF;"
        } else {
          calcs += "^b[25] ^= (b[43] + b[5] + b[32] + b[38] + b[35] + b[21] + " + Math.floor(Math.random() * 256) + ") & 0xFF;"
        }
        state = 556046909;
        continue;
      case 908446718:
        if (26273804n) {
          calcs += "^b[24] ^= (b[39] + b[38] + b[0] + b[20] + b[5] + b[10] + 158) & 0xFF;"
        } else {
          calcs += "^b[1] ^= (b[35] + b[23] + b[37] + b[25] + b[20] + b[32] + 88) & 0xFF;"
        }
        state = 294000735;
        continue;
      case 909404652:
        if (30056150n) {
          calcs += "^b[27] -= b[43] + b[35] + b[6] + b[22] + b[12] + b[42] + 49;"
          calcs += "^b[27] &= 0xFF;"
        } else {
          calcs += "^b[22] += b[10] + b[29] + b[24] + b[23] + b[5] + b[12] + 161;"
          calcs += "^b[22] &= 0xFF;"
        }
        state = 408191047;
        continue;
      case 913546258:
        if (Math.random() < 0.5) {
          calcs += "^b[8] += b[41] + b[25] + b[32] + b[1] + b[15] + b[6] + 182;"
          calcs += "^b[8] &= 0xFF;"
        } else {
          calcs += "^b[31] ^= (b[16] + b[29] + b[11] + b[7] + b[26] + b[25] + 12) & 0xFF;"
        }
        state = 659809382;
        continue;
      case 914596104:
        if (Math.random() < 0.5) {
          calcs += "^b[21] ^= (b[5] + b[27] + b[17] + b[2] + b[9] + b[6] + 122) & 0xFF;"
        } else {
          calcs += "^b[29] += b[33] + b[35] + b[23] + b[13] + b[15] + b[19] + 105;"
          calcs += "^b[29] &= 0xFF;"
        }
        state = 215751625;
        continue;
      case 915580084:
        if (629393213) {
          calcs += "^b[36] += b[43] + b[21] + b[38] + b[33] + b[20] + b[26] + 170;"
          calcs += "^b[36] &= 0xFF;"
        } else {
          calcs += "^b[23] ^= (b[27] + b[35] + b[43] + b[19] + b[12] + b[20] + 111) & 0xFF;"
        }
        state = 412101769;
        continue;
      case 915985451:
        if (70134898n) {
          calcs += "^b[34] -= b[15] + b[29] + b[5] + b[2] + b[39] + b[0] + 153;"
          calcs += "^b[34] &= 0xFF;"
        } else {
          calcs += "^b[40] ^= (b[7] + b[18] + b[10] + b[8] + b[38] + b[30] + 56) & 0xFF;"
        }
        state = 944009572;
        continue;
      case 916126752:
        if (Math.random() < 0.5) {
          calcs += "^b[25] ^= (b[26] + b[32] + b[12] + b[27] + b[28] + b[7] + 178) & 0xFF;"
        } else {
          calcs += "^b[36] += b[31] + b[15] + b[3] + b[5] + b[6] + b[10] + 179;"
          calcs += "^b[36] &= 0xFF;"
        }
        state = 298541990;
        continue;
      case 916517681:
        if (270906257) {
          calcs += "^b[11] -= b[28] + b[40] + b[14] + b[37] + b[8] + b[13] + 168;"
          calcs += "^b[11] &= 0xFF;"
        } else {
          calcs += "^b[6] += b[24] + b[36] + b[43] + b[29] + b[16] + b[10] + 182;"
          calcs += "^b[6] &= 0xFF;"
        }
        state = 71229022;
        continue;
      case 916699096:
        if (76348309n) {
          calcs += "^b[38] ^= (b[29] + b[9] + b[15] + b[33] + b[32] + b[3] + 187) & 0xFF;"
        } else {
          calcs += "^b[27] ^= (b[30] + b[19] + b[18] + b[23] + b[11] + b[25] + " + Math.floor(Math.random() * 256) + ") & 0xFF;"
        }
        state = 705074829;
        continue;
      case 917008021:
        if (311158600) {
          calcs += "^b[19] -= b[21] + b[10] + b[37] + b[40] + b[23] + b[27] + 116;"
          calcs += "^b[19] &= 0xFF;"
        } else {
          calcs += "^b[35] ^= (b[1] + b[29] + b[25] + b[5] + b[16] + b[10] + " + Math.floor(Math.random() * 256) + ") & 0xFF;"
        }
        state = 386755595;
        continue;
      case 922049847:
        if (Math.random() < 0.5) {
          calcs += "^b[38] -= b[26] + b[22] + b[3] + b[43] + b[33] + b[13] + 10;"
          calcs += "^b[38] &= 0xFF;"
        } else {
          calcs += "^b[13] ^= (b[0] + b[29] + b[26] + b[14] + b[15] + b[7] + 31) & 0xFF;"
        }
        state = 995642932;
        continue;
      case 922670184:
        if (64596098) {
          calcs += "^b[37] ^= (b[20] + b[32] + b[18] + b[28] + b[7] + b[25] + 2) & 0xFF;"
        } else {
          calcs += "^b[34] += b[33] + b[2] + b[32] + b[6] + b[3] + b[21] + 216;"
          calcs += "^b[34] &= 0xFF;"
        }
        state = 3058241;
        continue;
      case 923850245:
        if (72387310n) {
          calcs += "^b[32] += b[1] + b[2] + b[18] + b[43] + b[27] + b[29] + 127;"
          calcs += "^b[32] &= 0xFF;"
        } else {
          calcs += "^b[26] ^= (b[19] + b[37] + b[12] + b[22] + b[43] + b[25] + " + Math.floor(Math.random() * 256) + ") & 0xFF;"
        }
        state = 873425347;
        continue;
      case 923876614:
        if (29192855n) {
          calcs += "^b[39] ^= (b[9] + b[24] + b[40] + b[42] + b[8] + b[38] + 252) & 0xFF;"
        } else {
          calcs += "^b[39] ^= (b[38] + b[37] + b[22] + b[32] + b[26] + b[9] + 229) & 0xFF;"
        }
        state = 858216126;
        continue;
      case 925520064:
        if (Math.random() < 0.5) {
          calcs += "^b[10] -= b[6] + b[4] + b[5] + b[14] + b[25] + b[9] + 78;"
          calcs += "^b[10] &= 0xFF;"
        } else {
          calcs += "^b[36] += b[6] + b[21] + b[18] + b[31] + b[15] + b[7] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[36] &= 0xFF;"
        }
        state = 212640615;
        continue;
      case 926634219:
        if (Math.random() < 0.5) {
          calcs += "^b[7] -= b[42] + b[12] + b[1] + b[9] + b[36] + b[18] + 84;"
          calcs += "^b[7] &= 0xFF;"
        } else {
          calcs += "^b[32] += b[38] + b[20] + b[26] + b[35] + b[24] + b[14] + 217;"
          calcs += "^b[32] &= 0xFF;"
        }
        state = 896030833;
        continue;
      case 927296609:
        if (70785154) {
          calcs += "^b[15] -= b[11] + b[31] + b[41] + b[21] + b[8] + b[5] + 247;"
          calcs += "^b[15] &= 0xFF;"
        } else {
          calcs += "^b[7] += b[29] + b[38] + b[39] + b[26] + b[23] + b[36] + 86;"
          calcs += "^b[7] &= 0xFF;"
        }
        state = 427618707;
        continue;
      case 927672194:
        if (Math.random() < 0.5) {
          calcs += "^b[18] -= b[11] + b[27] + b[32] + b[8] + b[37] + b[4] + 51;"
          calcs += "^b[18] &= 0xFF;"
        } else {
          calcs += "^b[1] ^= (b[21] + b[2] + b[4] + b[35] + b[36] + b[40] + 66) & 0xFF;"
        }
        state = 294875064;
        continue;
      case 929229353:
        if (Math.random() < 0.5) {
          calcs += "^b[37] += b[18] + b[29] + b[11] + b[28] + b[13] + b[3] + 248;"
          calcs += "^b[37] &= 0xFF;"
        } else {
          calcs += "^b[39] += b[29] + b[18] + b[31] + b[23] + b[21] + b[0] + 45;"
          calcs += "^b[39] &= 0xFF;"
        }
        state = 775086306;
        continue;
      case 930229865:
        if (187629038) {
          calcs += "^b[21] -= b[12] + b[42] + b[26] + b[13] + b[27] + b[3] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[21] &= 0xFF;"
        } else {
          calcs += "^b[19] += b[9] + b[41] + b[42] + b[31] + b[32] + b[15] + 14;"
          calcs += "^b[19] &= 0xFF;"
        }
        state = 885910004;
        continue;
      case 931486041:
        if (141053168) {
          calcs += "^b[20] -= b[31] + b[40] + b[8] + b[37] + b[29] + b[18] + 133;"
          calcs += "^b[20] &= 0xFF;"
        } else {
          calcs += "^b[38] ^= (b[6] + b[42] + b[15] + b[31] + b[36] + b[7] + 155) & 0xFF;"
        }
        state = 341906838;
        continue;
      case 932044333:
        if (14067390n) {
          calcs += "^b[12] -= b[30] + b[29] + b[10] + b[25] + b[33] + b[23] + 180;"
          calcs += "^b[12] &= 0xFF;"
        } else {
          calcs += "^b[14] ^= (b[34] + b[41] + b[13] + b[28] + b[1] + b[21] + 163) & 0xFF;"
        }
        state = 739154907;
        continue;
      case 932811414:
        if (551698634) {
          calcs += "^b[29] -= b[42] + b[25] + b[34] + b[35] + b[3] + b[22] + 89;"
          calcs += "^b[29] &= 0xFF;"
        } else {
          calcs += "^b[20] += b[30] + b[8] + b[11] + b[34] + b[21] + b[0] + 118;"
          calcs += "^b[20] &= 0xFF;"
        }
        state = 325335257;
        continue;
      case 933425415:
        if (62291502n) {
          calcs += "^b[30] ^= (b[27] + b[40] + b[17] + b[43] + b[16] + b[6] + 73) & 0xFF;"
        } else {
          calcs += "^b[26] -= b[21] + b[12] + b[19] + b[40] + b[5] + b[25] + 19;"
          calcs += "^b[26] &= 0xFF;"
        }
        state = 789581177;
        continue;
      case 933907593:
        if (54935273) {
          calcs += "^b[13] += b[17] + b[8] + b[7] + b[42] + b[3] + b[32] + 189;"
          calcs += "^b[13] &= 0xFF;"
        } else {
          calcs += "^b[18] ^= (b[41] + b[15] + b[32] + b[16] + b[26] + b[23] + 205) & 0xFF;"
        }
        state = 706840833;
        continue;
      case 934739973:
        if (Math.random() < 0.5) {
          calcs += "^b[20] += b[7] + b[37] + b[5] + b[0] + b[34] + b[17] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[20] &= 0xFF;"
        } else {
          calcs += "^b[35] -= b[25] + b[23] + b[41] + b[26] + b[0] + b[20] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[35] &= 0xFF;"
        }
        state = 1064137877;
        continue;
      case 934870917:
        if (12180354n) {
          calcs += "^b[14] -= b[28] + b[12] + b[36] + b[39] + b[37] + b[40] + 87;"
          calcs += "^b[14] &= 0xFF;"
        } else {
          calcs += "^b[23] ^= (b[25] + b[32] + b[30] + b[16] + b[1] + b[43] + 75) & 0xFF;"
        }
        state = 306905017;
        continue;
      case 934956011:
        if (812385208) {
          calcs += "^b[39] -= b[30] + b[19] + b[18] + b[2] + b[22] + b[25] + 181;"
          calcs += "^b[39] &= 0xFF;"
        } else {
          calcs += "^b[19] -= b[38] + b[31] + b[9] + b[35] + b[29] + b[39] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[19] &= 0xFF;"
        }
        state = 296633824;
        continue;
      case 935030589:
        if (750736072) {
          calcs += "^b[24] ^= (b[13] + b[25] + b[8] + b[17] + b[12] + b[30] + 163) & 0xFF;"
        } else {
          calcs += "^b[10] += b[15] + b[21] + b[0] + b[42] + b[31] + b[9] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[10] &= 0xFF;"
        }
        state = 894072943;
        continue;
      case 936214335:
        if (92001583n) {
          calcs += "^b[28] ^= (b[0] + b[6] + b[22] + b[7] + b[39] + b[2] + 151) & 0xFF;"
        } else {
          calcs += "^b[24] ^= (b[29] + b[1] + b[2] + b[21] + b[31] + b[9] + " + Math.floor(Math.random() * 256) + ") & 0xFF;"
        }
        state = 865297185;
        continue;
      case 938822551:
        if (46888413n) {
          calcs += "^b[14] += b[43] + b[6] + b[0] + b[26] + b[2] + b[20] + 116;"
          calcs += "^b[14] &= 0xFF;"
        } else {
          calcs += "^b[4] += b[34] + b[7] + b[2] + b[39] + b[5] + b[43] + 139;"
          calcs += "^b[4] &= 0xFF;"
        }
        state = 583795792;
        continue;
      case 940416943:
        if (63696991n) {
          calcs += "^b[12] ^= (b[7] + b[28] + b[36] + b[42] + b[17] + b[13] + " + Math.floor(Math.random() * 256) + ") & 0xFF;"
        } else {
          calcs += "^b[8] += b[3] + b[20] + b[16] + b[17] + b[22] + b[24] + 15;"
          calcs += "^b[8] &= 0xFF;"
        }
        state = 427183539;
        continue;
      case 940887364:
        if (981305315) {
          calcs += "^b[29] ^= (b[22] + b[16] + b[4] + b[33] + b[20] + b[9] + 204) & 0xFF;"
        } else {
          calcs += "^b[24] -= b[37] + b[42] + b[7] + b[5] + b[22] + b[11] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[24] &= 0xFF;"
        }
        state = 202412843;
        continue;
      case 942994641:
        if (53464414n) {
          calcs += "^b[11] -= b[22] + b[29] + b[38] + b[40] + b[1] + b[0] + 171;"
          calcs += "^b[11] &= 0xFF;"
        } else {
          calcs += "^b[31] -= b[19] + b[4] + b[43] + b[41] + b[36] + b[7] + 105;"
          calcs += "^b[31] &= 0xFF;"
        }
        state = 368791401;
        continue;
      case 943408141:
        if (813203056) {
          calcs += "^b[37] -= b[18] + b[2] + b[8] + b[35] + b[15] + b[34] + 173;"
          calcs += "^b[37] &= 0xFF;"
        } else {
          calcs += "^b[0] ^= (b[11] + b[37] + b[33] + b[36] + b[38] + b[3] + " + Math.floor(Math.random() * 256) + ") & 0xFF;"
        }
        state = 1071572916;
        continue;
      case 943451716:
        if (62464654n) {
          calcs += "^b[31] -= b[35] + b[39] + b[27] + b[41] + b[7] + b[42] + 225;"
          calcs += "^b[31] &= 0xFF;"
        } else {
          calcs += "^b[4] += b[8] + b[13] + b[3] + b[34] + b[22] + b[14] + 246;"
          calcs += "^b[4] &= 0xFF;"
        }
        state = 552719392;
        continue;
      case 944233129:
        if (305302826) {
          calcs += "^b[38] ^= (b[20] + b[8] + b[31] + b[30] + b[14] + b[32] + 168) & 0xFF;"
        } else {
          calcs += "^b[12] += b[7] + b[31] + b[37] + b[14] + b[29] + b[9] + 180;"
          calcs += "^b[12] &= 0xFF;"
        }
        state = 424126643;
        continue;
      case 946927507:
        if (575865303) {
          calcs += "^b[23] += b[13] + b[15] + b[29] + b[20] + b[3] + b[10] + 241;"
          calcs += "^b[23] &= 0xFF;"
        } else {
          calcs += "^b[2] -= b[10] + b[36] + b[13] + b[22] + b[27] + b[14] + 61;"
          calcs += "^b[2] &= 0xFF;"
        }
        state = 249324802;
        continue;
      case 947199551:
        if (61082285n) {
          calcs += "^b[1] ^= (b[22] + b[43] + b[37] + b[11] + b[27] + b[15] + 99) & 0xFF;"
        } else {
          calcs += "^b[0] += b[10] + b[3] + b[19] + b[5] + b[31] + b[2] + 135;"
          calcs += "^b[0] &= 0xFF;"
        }
        state = 422022133;
        continue;
      case 950500871:
        if (72963199n) {
          calcs += "^b[25] += b[33] + b[17] + b[37] + b[34] + b[43] + b[40] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[25] &= 0xFF;"
        } else {
          calcs += "^b[32] ^= (b[4] + b[14] + b[43] + b[42] + b[9] + b[27] + 187) & 0xFF;"
        }
        state = 672902766;
        continue;
      case 951171326:
        if (69325676n) {
          calcs += "^b[30] += b[38] + b[4] + b[34] + b[33] + b[22] + b[43] + 49;"
          calcs += "^b[30] &= 0xFF;"
        } else {
          calcs += "^b[19] -= b[36] + b[41] + b[40] + b[24] + b[33] + b[10] + 138;"
          calcs += "^b[19] &= 0xFF;"
        }
        state = 825357574;
        continue;
      case 953701085:
        if (Math.random() < 0.5) {
          calcs += "^b[40] ^= (b[39] + b[17] + b[41] + b[35] + b[9] + b[19] + 221) & 0xFF;"
        } else {
          calcs += "^b[22] ^= (b[0] + b[36] + b[28] + b[14] + b[4] + b[18] + 25) & 0xFF;"
        }
        state = 172654831;
        continue;
      case 956147074:
        if (12485691n) {
          calcs += "^b[17] += b[25] + b[23] + b[12] + b[43] + b[39] + b[19] + 16;"
          calcs += "^b[17] &= 0xFF;"
        } else {
          calcs += "^b[22] ^= (b[17] + b[0] + b[40] + b[34] + b[4] + b[5] + 36) & 0xFF;"
        }
        state = 131998784;
        continue;
      case 957436102:
        if (Math.random() < 0.5) {
          calcs += "^b[29] -= b[0] + b[41] + b[34] + b[24] + b[17] + b[3] + 7;"
          calcs += "^b[29] &= 0xFF;"
        } else {
          calcs += "^b[28] ^= (b[1] + b[23] + b[37] + b[31] + b[43] + b[42] + " + Math.floor(Math.random() * 256) + ") & 0xFF;"
        }
        state = 10023459;
        continue;
      case 958174320:
        if (324755369) {
          calcs += "^b[27] -= b[35] + b[3] + b[17] + b[34] + b[7] + b[31] + 72;"
          calcs += "^b[27] &= 0xFF;"
        } else {
          calcs += "^b[22] += b[3] + b[21] + b[6] + b[18] + b[43] + b[0] + 13;"
          calcs += "^b[22] &= 0xFF;"
        }
        state = 237862146;
        continue;
      case 959452706:
        if (513885887) {
          calcs += "^b[21] ^= (b[11] + b[29] + b[30] + b[7] + b[20] + b[16] + 230) & 0xFF;"
        } else {
          calcs += "^b[16] += b[5] + b[21] + b[39] + b[25] + b[43] + b[8] + 100;"
          calcs += "^b[16] &= 0xFF;"
        }
        state = 323232511;
        continue;
      case 959614683:
        if (93578063n) {
          calcs += "^b[39] ^= (b[30] + b[13] + b[42] + b[17] + b[37] + b[1] + 213) & 0xFF;"
        } else {
          calcs += "^b[23] ^= (b[5] + b[10] + b[31] + b[36] + b[42] + b[30] + 84) & 0xFF;"
        }
        state = 329532238;
        continue;
      case 960357655:
        if (32760615) {
          calcs += "^b[36] += b[32] + b[6] + b[9] + b[42] + b[38] + b[25] + 193;"
          calcs += "^b[36] &= 0xFF;"
        } else {
          calcs += "^b[15] ^= (b[20] + b[3] + b[36] + b[7] + b[9] + b[39] + " + Math.floor(Math.random() * 256) + ") & 0xFF;"
        }
        state = 653166564;
        continue;
      case 960991331:
        if (95628851n) {
          calcs += "^b[3] ^= (b[0] + b[38] + b[29] + b[1] + b[11] + b[16] + 57) & 0xFF;"
        } else {
          calcs += "^b[38] += b[10] + b[18] + b[39] + b[0] + b[35] + b[37] + 69;"
          calcs += "^b[38] &= 0xFF;"
        }
        state = 1019638033;
        continue;
      case 961374201:
        if (56599935n) {
          calcs += "^b[10] -= b[33] + b[17] + b[36] + b[30] + b[24] + b[40] + 23;"
          calcs += "^b[10] &= 0xFF;"
        } else {
          calcs += "^b[21] -= b[20] + b[13] + b[41] + b[1] + b[7] + b[33] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[21] &= 0xFF;"
        }
        state = 828519420;
        continue;
      case 961924244:
        if (Math.random() < 0.5) {
          calcs += "^b[6] += b[34] + b[1] + b[29] + b[26] + b[39] + b[22] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[6] &= 0xFF;"
        } else {
          calcs += "^b[23] += b[15] + b[32] + b[35] + b[0] + b[8] + b[22] + 146;"
          calcs += "^b[23] &= 0xFF;"
        }
        state = 927770297;
        continue;
      case 962077432:
        if (378371632) {
          calcs += "^b[16] -= b[5] + b[0] + b[31] + b[4] + b[38] + b[33] + 60;"
          calcs += "^b[16] &= 0xFF;"
        } else {
          calcs += "^b[14] ^= (b[41] + b[5] + b[40] + b[33] + b[35] + b[10] + 94) & 0xFF;"
        }
        state = 174373421;
        continue;
      case 963449270:
        if (Math.random() < 0.5) {
          calcs += "^b[14] += b[40] + b[33] + b[29] + b[36] + b[20] + b[42] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[14] &= 0xFF;"
        } else {
          calcs += "^b[30] -= b[35] + b[40] + b[33] + b[4] + b[18] + b[29] + 149;"
          calcs += "^b[30] &= 0xFF;"
        }
        state = 384192227;
        continue;
      case 965140015:
        if (Math.random() < 0.5) {
          calcs += "^b[34] -= b[19] + b[30] + b[10] + b[18] + b[11] + b[15] + 126;"
          calcs += "^b[34] &= 0xFF;"
        } else {
          calcs += "^b[12] += b[23] + b[43] + b[17] + b[19] + b[3] + b[30] + 82;"
          calcs += "^b[12] &= 0xFF;"
        }
        state = 1027772866;
        continue;
      case 965766581:
        if (Math.random() < 0.5) {
          calcs += "^b[14] += b[24] + b[26] + b[11] + b[19] + b[6] + b[17] + 150;"
          calcs += "^b[14] &= 0xFF;"
        } else {
          calcs += "^b[35] -= b[32] + b[36] + b[9] + b[17] + b[37] + b[26] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[35] &= 0xFF;"
        }
        state = 408850718;
        continue;
      case 967654317:
        if (580972453) {
          calcs += "^b[21] -= b[25] + b[31] + b[39] + b[24] + b[17] + b[18] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[21] &= 0xFF;"
        } else {
          calcs += "^b[26] -= b[31] + b[22] + b[40] + b[23] + b[4] + b[25] + 15;"
          calcs += "^b[26] &= 0xFF;"
        }
        state = 490898484;
        continue;
      case 968134268:
        if (90448955n) {
          calcs += "^b[37] -= b[30] + b[21] + b[35] + b[13] + b[19] + b[26] + 208;"
          calcs += "^b[37] &= 0xFF;"
        } else {
          calcs += "^b[20] ^= (b[0] + b[17] + b[24] + b[37] + b[2] + b[6] + " + Math.floor(Math.random() * 256) + ") & 0xFF;"
        }
        state = 163298870;
        continue;
      case 968337128:
        if (12970189) {
          calcs += "^b[26] -= b[13] + b[3] + b[18] + b[40] + b[10] + b[8] + 191;"
          calcs += "^b[26] &= 0xFF;"
        } else {
          calcs += "^b[31] -= b[29] + b[17] + b[0] + b[13] + b[5] + b[40] + 136;"
          calcs += "^b[31] &= 0xFF;"
        }
        state = 538008977;
        continue;
      case 969714121:
        if (Math.random() < 0.5) {
          calcs += "^b[6] ^= (b[16] + b[2] + b[25] + b[1] + b[28] + b[3] + 185) & 0xFF;"
        } else {
          calcs += "^b[2] -= b[21] + b[30] + b[16] + b[41] + b[10] + b[11] + 235;"
          calcs += "^b[2] &= 0xFF;"
        }
        state = 998411271;
        continue;
      case 970962237:
        if (343016624) {
          calcs += "^b[0] -= b[2] + b[35] + b[21] + b[37] + b[31] + b[24] + 159;"
          calcs += "^b[0] &= 0xFF;"
        } else {
          calcs += "^b[22] += b[16] + b[36] + b[10] + b[41] + b[11] + b[15] + 18;"
          calcs += "^b[22] &= 0xFF;"
        }
        state = 915555692;
        continue;
      case 971183007:
        if (Math.random() < 0.5) {
          calcs += "^b[25] ^= (b[29] + b[41] + b[32] + b[27] + b[3] + b[33] + 34) & 0xFF;"
        } else {
          calcs += "^b[30] ^= (b[14] + b[35] + b[34] + b[9] + b[36] + b[10] + 118) & 0xFF;"
        }
        state = 633388402;
        continue;
      case 971907876:
        if (572913008) {
          calcs += "^b[35] += b[30] + b[4] + b[20] + b[15] + b[32] + b[40] + 214;"
          calcs += "^b[35] &= 0xFF;"
        } else {
          calcs += "^b[20] ^= (b[28] + b[7] + b[15] + b[3] + b[12] + b[19] + 246) & 0xFF;"
        }
        state = 426931476;
        continue;
      case 972033212:
        if (51692245n) {
          calcs += "^b[25] -= b[14] + b[9] + b[24] + b[7] + b[26] + b[18] + 92;"
          calcs += "^b[25] &= 0xFF;"
        } else {
          calcs += "^b[23] ^= (b[11] + b[32] + b[35] + b[5] + b[10] + b[18] + 150) & 0xFF;"
        }
        state = 515834590;
        continue;
      case 972593536:
        if (19020555n) {
          calcs += "^b[22] += b[41] + b[28] + b[25] + b[26] + b[0] + b[23] + 162;"
          calcs += "^b[22] &= 0xFF;"
        } else {
          calcs += "^b[4] += b[30] + b[14] + b[36] + b[32] + b[20] + b[0] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[4] &= 0xFF;"
        }
        state = 172583856;
        continue;
      case 975388468:
        if (128832933) {
          calcs += "^b[41] += b[33] + b[26] + b[37] + b[7] + b[22] + b[18] + 4;"
          calcs += "^b[41] &= 0xFF;"
        } else {
          calcs += "^b[15] ^= (b[42] + b[21] + b[12] + b[34] + b[26] + b[22] + 30) & 0xFF;"
        }
        state = 162438337;
        continue;
      case 975988778:
        if (259368239) {
          calcs += "^b[20] += b[27] + b[22] + b[25] + b[17] + b[10] + b[14] + 34;"
          calcs += "^b[20] &= 0xFF;"
        } else {
          calcs += "^b[26] += b[16] + b[38] + b[12] + b[25] + b[24] + b[0] + 68;"
          calcs += "^b[26] &= 0xFF;"
        }
        state = 13899054;
        continue;
      case 976014478:
        if (619391634) {
          calcs += "^b[26] ^= (b[18] + b[40] + b[16] + b[15] + b[30] + b[33] + 25) & 0xFF;"
        } else {
          calcs += "^b[34] += b[1] + b[43] + b[3] + b[41] + b[38] + b[31] + 168;"
          calcs += "^b[34] &= 0xFF;"
        }
        state = 1016166149;
        continue;
      case 976505001:
        if (62600601n) {
          calcs += "^b[16] += b[20] + b[35] + b[30] + b[1] + b[8] + b[37] + 181;"
          calcs += "^b[16] &= 0xFF;"
        } else {
          calcs += "^b[41] -= b[20] + b[0] + b[33] + b[17] + b[30] + b[32] + 1;"
          calcs += "^b[41] &= 0xFF;"
        }
        state = 329325674;
        continue;
      case 977373188:
        if (52740692n) {
          calcs += "^b[14] -= b[7] + b[16] + b[5] + b[26] + b[21] + b[28] + 65;"
          calcs += "^b[14] &= 0xFF;"
        } else {
          calcs += "^b[18] ^= (b[9] + b[8] + b[20] + b[42] + b[12] + b[15] + 32) & 0xFF;"
        }
        state = 553125374;
        continue;
      case 979486492:
        if (45112725n) {
          calcs += "^b[27] ^= (b[34] + b[10] + b[36] + b[22] + b[25] + b[31] + 175) & 0xFF;"
        } else {
          calcs += "^b[43] += b[29] + b[35] + b[36] + b[2] + b[33] + b[28] + 236;"
          calcs += "^b[43] &= 0xFF;"
        }
        state = 731637595;
        continue;
      case 980186436:
        if (66114638n) {
          calcs += "^b[20] ^= (b[32] + b[30] + b[16] + b[34] + b[29] + b[8] + 22) & 0xFF;"
        } else {
          calcs += "^b[9] -= b[10] + b[18] + b[25] + b[31] + b[7] + b[40] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[9] &= 0xFF;"
        }
        state = 1021362401;
        continue;
      case 980801854:
        if (Math.random() < 0.5) {
          calcs += "^b[41] ^= (b[28] + b[7] + b[11] + b[8] + b[20] + b[9] + " + Math.floor(Math.random() * 256) + ") & 0xFF;"
        } else {
          calcs += "^b[17] ^= (b[28] + b[14] + b[16] + b[31] + b[41] + b[43] + 36) & 0xFF;"
        }
        state = 1067845410;
        continue;
      case 981432595:
        if (24002080n) {
          calcs += "^b[41] -= b[17] + b[20] + b[19] + b[38] + b[18] + b[29] + 30;"
          calcs += "^b[41] &= 0xFF;"
        } else {
          calcs += "^b[23] += b[18] + b[17] + b[2] + b[6] + b[13] + b[41] + 46;"
          calcs += "^b[23] &= 0xFF;"
        }
        state = 494370317;
        continue;
      case 981450373:
        if (Math.random() < 0.5) {
          calcs += "^b[13] += b[25] + b[35] + b[16] + b[39] + b[23] + b[28] + 2;"
          calcs += "^b[13] &= 0xFF;"
        } else {
          calcs += "^b[22] += b[37] + b[10] + b[38] + b[39] + b[40] + b[23] + 205;"
          calcs += "^b[22] &= 0xFF;"
        }
        state = 223621298;
        continue;
      case 982330101:
        if (848284052) {
          calcs += "^b[13] ^= (b[25] + b[30] + b[29] + b[17] + b[9] + b[11] + 85) & 0xFF;"
        } else {
          calcs += "^b[0] -= b[43] + b[42] + b[30] + b[40] + b[11] + b[29] + 98;"
          calcs += "^b[0] &= 0xFF;"
        }
        state = 685117268;
        continue;
      case 982360340:
        if (383767699) {
          calcs += "^b[37] -= b[12] + b[9] + b[40] + b[18] + b[35] + b[38] + 50;"
          calcs += "^b[37] &= 0xFF;"
        } else {
          calcs += "^b[17] ^= (b[10] + b[0] + b[43] + b[36] + b[26] + b[33] + 175) & 0xFF;"
        }
        state = 898507949;
        continue;
      case 983134450:
        if (Math.random() < 0.5) {
          calcs += "^b[8] -= b[7] + b[23] + b[20] + b[13] + b[1] + b[36] + 64;"
          calcs += "^b[8] &= 0xFF;"
        } else {
          calcs += "^b[21] ^= (b[9] + b[5] + b[38] + b[14] + b[43] + b[7] + 217) & 0xFF;"
        }
        state = 292002073;
        continue;
      case 984240743:
        if (8246483) {
          calcs += "^b[20] -= b[27] + b[36] + b[23] + b[19] + b[31] + b[32] + 210;"
          calcs += "^b[20] &= 0xFF;"
        } else {
          calcs += "^b[34] ^= (b[30] + b[6] + b[13] + b[35] + b[3] + b[26] + 241) & 0xFF;"
        }
        state = 356704383;
        continue;
      case 984396248:
        if (Math.random() < 0.5) {
          calcs += "^b[23] ^= (b[39] + b[33] + b[27] + b[43] + b[12] + b[2] + 78) & 0xFF;"
        } else {
          calcs += "^b[15] -= b[21] + b[27] + b[36] + b[40] + b[37] + b[20] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[15] &= 0xFF;"
        }
        state = 958145418;
        continue;
      case 984960420:
        if (Math.random() < 0.5) {
          calcs += "^b[28] ^= (b[41] + b[20] + b[12] + b[22] + b[11] + b[38] + 171) & 0xFF;"
        } else {
          calcs += "^b[1] -= b[12] + b[17] + b[2] + b[36] + b[4] + b[35] + 13;"
          calcs += "^b[1] &= 0xFF;"
        }
        state = 252555670;
        continue;
      case 986654093:
        if (740095820) {
          calcs += "^b[33] += b[23] + b[43] + b[14] + b[19] + b[38] + b[17] + 227;"
          calcs += "^b[33] &= 0xFF;"
        } else {
          calcs += "^b[11] ^= (b[25] + b[10] + b[9] + b[2] + b[8] + b[26] + 44) & 0xFF;"
        }
        state = 389482423;
        continue;
      case 987159526:
        if (67930109n) {
          calcs += "^b[20] -= b[40] + b[10] + b[19] + b[24] + b[0] + b[11] + 147;"
          calcs += "^b[20] &= 0xFF;"
        } else {
          calcs += "^b[40] += b[42] + b[0] + b[6] + b[31] + b[33] + b[30] + 0;"
          calcs += "^b[40] &= 0xFF;"
        }
        state = 462226532;
        continue;
      case 987447585:
        if (31410266n) {
          calcs += "^b[38] += b[2] + b[5] + b[24] + b[8] + b[11] + b[20] + 115;"
          calcs += "^b[38] &= 0xFF;"
        } else {
          calcs += "^b[24] -= b[5] + b[29] + b[33] + b[1] + b[0] + b[6] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[24] &= 0xFF;"
        }
        state = 346635123;
        continue;
      case 992775814:
        if (186069466) {
          calcs += "^b[30] ^= (b[5] + b[36] + b[1] + b[19] + b[25] + b[27] + 7) & 0xFF;"
        } else {
          calcs += "^b[37] += b[30] + b[10] + b[11] + b[2] + b[34] + b[41] + 206;"
          calcs += "^b[37] &= 0xFF;"
        }
        state = 904444081;
        continue;
      case 996305121:
        if (995188177) {
          calcs += "^b[38] += b[18] + b[4] + b[27] + b[25] + b[14] + b[40] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[38] &= 0xFF;"
        } else {
          calcs += "^b[11] -= b[24] + b[9] + b[13] + b[33] + b[39] + b[22] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[11] &= 0xFF;"
        }
        state = 64857213;
        continue;
      case 996361116:
        if (Math.random() < 0.5) {
          calcs += "^b[2] -= b[16] + b[37] + b[40] + b[27] + b[14] + b[4] + 110;"
          calcs += "^b[2] &= 0xFF;"
        } else {
          calcs += "^b[40] -= b[22] + b[0] + b[28] + b[17] + b[31] + b[11] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[40] &= 0xFF;"
        }
        state = 269458850;
        continue;
      case 998309844:
        if (253411493) {
          calcs += "^b[23] -= b[2] + b[1] + b[25] + b[31] + b[10] + b[41] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[23] &= 0xFF;"
        } else {
          calcs += "^b[5] -= b[28] + b[39] + b[25] + b[43] + b[15] + b[7] + 203;"
          calcs += "^b[5] &= 0xFF;"
        }
        state = 653106531;
        continue;
      case 998903508:
        if (Math.random() < 0.5) {
          calcs += "^b[19] += b[6] + b[14] + b[35] + b[39] + b[21] + b[42] + 253;"
          calcs += "^b[19] &= 0xFF;"
        } else {
          calcs += "^b[19] += b[33] + b[34] + b[38] + b[2] + b[14] + b[22] + 92;"
          calcs += "^b[19] &= 0xFF;"
        }
        state = 562578026;
        continue;
      case 999324458:
        if (112278826) {
          calcs += "^b[33] -= b[0] + b[36] + b[23] + b[34] + b[37] + b[29] + 253;"
          calcs += "^b[33] &= 0xFF;"
        } else {
          calcs += "^b[7] -= b[30] + b[35] + b[16] + b[23] + b[40] + b[22] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[7] &= 0xFF;"
        }
        state = 770651828;
        continue;
      case 1001050053:
        if (15391122n) {
          calcs += "^b[2] += b[6] + b[23] + b[22] + b[31] + b[26] + b[37] + 120;"
          calcs += "^b[2] &= 0xFF;"
        } else {
          calcs += "^b[3] ^= (b[28] + b[41] + b[27] + b[1] + b[15] + b[26] + 116) & 0xFF;"
        }
        state = 522159053;
        continue;
      case 1002376488:
        if (Math.random() < 0.5) {
          calcs += "^b[4] -= b[10] + b[21] + b[40] + b[19] + b[38] + b[14] + 129;"
          calcs += "^b[4] &= 0xFF;"
        } else {
          calcs += "^b[4] ^= (b[22] + b[25] + b[28] + b[6] + b[7] + b[24] + 23) & 0xFF;"
        }
        state = 245087473;
        continue;
      case 1003847695:
        if (388975924) {
          calcs += "^b[36] ^= (b[28] + b[5] + b[23] + b[4] + b[15] + b[31] + 216) & 0xFF;"
        } else {
          calcs += "^b[24] -= b[34] + b[12] + b[14] + b[41] + b[21] + b[11] + 223;"
          calcs += "^b[24] &= 0xFF;"
        }
        state = 101627354;
        continue;
      case 1004734575:
        if (26382457n) {
          calcs += "^b[32] += b[18] + b[14] + b[23] + b[35] + b[42] + b[39] + 145;"
          calcs += "^b[32] &= 0xFF;"
        } else {
          calcs += "^b[27] -= b[41] + b[26] + b[11] + b[22] + b[17] + b[16] + 244;"
          calcs += "^b[27] &= 0xFF;"
        }
        state = 797717963;
        continue;
      case 1006187624:
        if (Math.random() < 0.5) {
          calcs += "^b[30] ^= (b[18] + b[9] + b[37] + b[25] + b[32] + b[35] + 0) & 0xFF;"
        } else {
          calcs += "^b[27] += b[8] + b[11] + b[32] + b[3] + b[24] + b[16] + 126;"
          calcs += "^b[27] &= 0xFF;"
        }
        state = 502464297;
        continue;
      case 1006204370:
        if (250293893) {
          calcs += "^b[20] += b[18] + b[5] + b[17] + b[4] + b[1] + b[24] + 207;"
          calcs += "^b[20] &= 0xFF;"
        } else {
          calcs += "^b[40] -= b[21] + b[3] + b[14] + b[13] + b[20] + b[5] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[40] &= 0xFF;"
        }
        state = 639983618;
        continue;
      case 1007745471:
        if (758792626) {
          calcs += "^b[14] ^= (b[17] + b[18] + b[13] + b[29] + b[35] + b[38] + 26) & 0xFF;"
        } else {
          calcs += "^b[35] -= b[4] + b[29] + b[25] + b[9] + b[6] + b[3] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[35] &= 0xFF;"
        }
        state = 754946132;
        continue;
      case 1007784734:
        if (349045045) {
          calcs += "^b[11] += b[27] + b[31] + b[2] + b[7] + b[43] + b[38] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[11] &= 0xFF;"
        } else {
          calcs += "^b[29] ^= (b[24] + b[9] + b[33] + b[36] + b[28] + b[17] + " + Math.floor(Math.random() * 256) + ") & 0xFF;"
        }
        state = 37958807;
        continue;
      case 1009568819:
        if (163685368) {
          calcs += "^b[41] ^= (b[4] + b[1] + b[25] + b[16] + b[10] + b[33] + " + Math.floor(Math.random() * 256) + ") & 0xFF;"
        } else {
          calcs += "^b[19] ^= (b[26] + b[28] + b[24] + b[20] + b[29] + b[30] + 198) & 0xFF;"
        }
        state = 490009395;
        continue;
      case 1009817857:
        if (18234293n) {
          calcs += "^b[22] += b[29] + b[0] + b[8] + b[43] + b[38] + b[10] + 149;"
          calcs += "^b[22] &= 0xFF;"
        } else {
          calcs += "^b[40] += b[1] + b[9] + b[18] + b[17] + b[33] + b[39] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[40] &= 0xFF;"
        }
        state = 916573862;
        continue;
      case 1010317137:
        if (10319998n) {
          calcs += "^b[3] -= b[38] + b[37] + b[22] + b[10] + b[8] + b[25] + 181;"
          calcs += "^b[3] &= 0xFF;"
        } else {
          calcs += "^b[7] ^= (b[31] + b[28] + b[17] + b[14] + b[30] + b[41] + 64) & 0xFF;"
        }
        state = 682318978;
        continue;
      case 1010356043:
        if (Math.random() < 0.5) {
          calcs += "^b[42] += b[4] + b[5] + b[35] + b[12] + b[22] + b[19] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[42] &= 0xFF;"
        } else {
          calcs += "^b[29] -= b[37] + b[23] + b[22] + b[24] + b[26] + b[10] + 7;"
          calcs += "^b[29] &= 0xFF;"
        }
        state = 1031173583;
        continue;
      case 1012665353:
        if (270968034) {
          calcs += "^b[30] += b[15] + b[3] + b[32] + b[33] + b[39] + b[17] + 62;"
          calcs += "^b[30] &= 0xFF;"
        } else {
          calcs += "^b[1] += b[4] + b[25] + b[41] + b[21] + b[22] + b[10] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[1] &= 0xFF;"
        }
        state = 567106632;
        continue;
      case 1013605951:
        if (Math.random() < 0.5) {
          calcs += "^b[26] -= b[34] + b[12] + b[28] + b[15] + b[23] + b[0] + 52;"
          calcs += "^b[26] &= 0xFF;"
        } else {
          calcs += "^b[23] -= b[30] + b[36] + b[5] + b[7] + b[22] + b[39] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[23] &= 0xFF;"
        }
        state = 1014671117;
        continue;
      case 1014985015:
        if (955930035) {
          calcs += "^b[7] ^= (b[35] + b[18] + b[5] + b[42] + b[43] + b[6] + 247) & 0xFF;"
        } else {
          calcs += "^b[3] += b[6] + b[26] + b[32] + b[22] + b[39] + b[25] + 119;"
          calcs += "^b[3] &= 0xFF;"
        }
        state = 898056003;
        continue;
      case 1017668994:
        if (899322950) {
          calcs += "^b[28] ^= (b[21] + b[24] + b[4] + b[11] + b[26] + b[36] + 94) & 0xFF;"
        } else {
          calcs += "^b[18] ^= (b[2] + b[41] + b[31] + b[4] + b[6] + b[13] + 157) & 0xFF;"
        }
        state = 850415905;
        continue;
      case 1020092396:
        if (Math.random() < 0.5) {
          calcs += "^b[10] ^= (b[26] + b[29] + b[19] + b[31] + b[39] + b[28] + 142) & 0xFF;"
        } else {
          calcs += "^b[22] ^= (b[19] + b[24] + b[25] + b[12] + b[10] + b[7] + 249) & 0xFF;"
        }
        state = 644418210;
        continue;
      case 1020638245:
        if (341042742) {
          calcs += "^b[9] += b[10] + b[4] + b[20] + b[28] + b[43] + b[24] + 29;"
          calcs += "^b[9] &= 0xFF;"
        } else {
          calcs += "^b[8] -= b[41] + b[23] + b[11] + b[17] + b[5] + b[39] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[8] &= 0xFF;"
        }
        state = 656679814;
        continue;
      case 1020799775:
        if (71122535n) {
          calcs += "^b[40] += b[10] + b[25] + b[4] + b[13] + b[38] + b[21] + 84;"
          calcs += "^b[40] &= 0xFF;"
        } else {
          calcs += "^b[42] ^= (b[25] + b[34] + b[32] + b[0] + b[5] + b[17] + " + Math.floor(Math.random() * 256) + ") & 0xFF;"
        }
        state = 413962209;
        continue;
      case 1021595414:
        if (Math.random() < 0.5) {
          calcs += "^b[26] += b[2] + b[21] + b[0] + b[40] + b[5] + b[24] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[26] &= 0xFF;"
        } else {
          calcs += "^b[10] ^= (b[4] + b[2] + b[18] + b[38] + b[22] + b[27] + 40) & 0xFF;"
        }
        state = 880786011;
        continue;
      case 1022290916:
        if (95886560n) {
          calcs += "^b[14] += b[35] + b[22] + b[0] + b[1] + b[42] + b[25] + 206;"
          calcs += "^b[14] &= 0xFF;"
        } else {
          calcs += "^b[33] ^= (b[6] + b[23] + b[22] + b[8] + b[37] + b[16] + 3) & 0xFF;"
        }
        state = 916520749;
        continue;
      case 1022867386:
        if (971264745) {
          calcs += "^b[38] ^= (b[25] + b[17] + b[43] + b[42] + b[14] + b[8] + " + Math.floor(Math.random() * 256) + ") & 0xFF;"
        } else {
          calcs += "^b[18] += b[13] + b[28] + b[30] + b[22] + b[1] + b[11] + 104;"
          calcs += "^b[18] &= 0xFF;"
        }
        state = 900279088;
        continue;
      case 1023914457:
        if (Math.random() < 0.5) {
          calcs += "^b[11] -= b[15] + b[36] + b[39] + b[37] + b[29] + b[28] + 120;"
          calcs += "^b[11] &= 0xFF;"
        } else {
          calcs += "^b[30] ^= (b[16] + b[40] + b[42] + b[32] + b[2] + b[41] + " + Math.floor(Math.random() * 256) + ") & 0xFF;"
        }
        state = 448550515;
        continue;
      case 1025916139:
        if (485162058) {
          calcs += "^b[13] += b[30] + b[18] + b[40] + b[26] + b[22] + b[29] + 57;"
          calcs += "^b[13] &= 0xFF;"
        } else {
          calcs += "^b[9] += b[2] + b[29] + b[42] + b[19] + b[31] + b[40] + 131;"
          calcs += "^b[9] &= 0xFF;"
        }
        state = 1056280566;
        continue;
      case 1027336899:
        if (Math.random() < 0.5) {
          calcs += "^b[18] -= b[21] + b[5] + b[40] + b[34] + b[43] + b[41] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[18] &= 0xFF;"
        } else {
          calcs += "^b[34] ^= (b[6] + b[3] + b[20] + b[39] + b[32] + b[43] + 11) & 0xFF;"
        }
        state = 378864171;
        continue;
      case 1027590517:
        if (896562078) {
          calcs += "^b[39] -= b[1] + b[28] + b[11] + b[6] + b[4] + b[23] + 187;"
          calcs += "^b[39] &= 0xFF;"
        } else {
          calcs += "^b[43] += b[32] + b[27] + b[4] + b[25] + b[8] + b[11] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[43] &= 0xFF;"
        }
        state = 198957017;
        continue;
      case 1030212277:
        if (Math.random() < 0.5) {
          calcs += "^b[17] += b[35] + b[3] + b[13] + b[19] + b[6] + b[36] + 120;"
          calcs += "^b[17] &= 0xFF;"
        } else {
          calcs += "^b[9] -= b[27] + b[26] + b[37] + b[12] + b[31] + b[30] + 208;"
          calcs += "^b[9] &= 0xFF;"
        }
        state = 503819895;
        continue;
      case 1030660026:
        if (Math.random() < 0.5) {
          calcs += "^b[7] -= b[8] + b[0] + b[12] + b[28] + b[40] + b[32] + 7;"
          calcs += "^b[7] &= 0xFF;"
        } else {
          calcs += "^b[33] -= b[14] + b[35] + b[41] + b[0] + b[6] + b[8] + 45;"
          calcs += "^b[33] &= 0xFF;"
        }
        state = 779013490;
        continue;
      case 1030774184:
        if (869017612) {
          calcs += "^b[36] ^= (b[34] + b[23] + b[11] + b[39] + b[1] + b[41] + " + Math.floor(Math.random() * 256) + ") & 0xFF;"
        } else {
          calcs += "^b[29] -= b[37] + b[9] + b[0] + b[16] + b[2] + b[28] + 203;"
          calcs += "^b[29] &= 0xFF;"
        }
        state = 774025472;
        continue;
      case 1031385455:
        if (71620143n) {
          calcs += "^b[14] ^= (b[0] + b[7] + b[13] + b[39] + b[21] + b[22] + " + Math.floor(Math.random() * 256) + ") & 0xFF;"
        } else {
          calcs += "^b[10] -= b[33] + b[41] + b[14] + b[6] + b[12] + b[42] + 110;"
          calcs += "^b[10] &= 0xFF;"
        }
        state = 1031693647;
        continue;
      case 1031764577:
        if (109808949) {
          calcs += "^b[33] += b[12] + b[40] + b[36] + b[32] + b[29] + b[31] + 1;"
          calcs += "^b[33] &= 0xFF;"
        } else {
          calcs += "^b[3] -= b[13] + b[30] + b[9] + b[28] + b[32] + b[38] + 241;"
          calcs += "^b[3] &= 0xFF;"
        }
        state = 969748666;
        continue;
      case 1032070313:
        if (655549483) {
          calcs += "^b[22] ^= (b[2] + b[1] + b[42] + b[0] + b[40] + b[32] + 249) & 0xFF;"
        } else {
          calcs += "^b[35] -= b[19] + b[17] + b[37] + b[26] + b[10] + b[13] + 230;"
          calcs += "^b[35] &= 0xFF;"
        }
        state = 1048423734;
        continue;
      case 1032477597:
        if (80270086n) {
          calcs += "^b[8] += b[21] + b[2] + b[30] + b[15] + b[41] + b[31] + 202;"
          calcs += "^b[8] &= 0xFF;"
        } else {
          calcs += "^b[36] -= b[38] + b[17] + b[14] + b[26] + b[32] + b[40] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[36] &= 0xFF;"
        }
        state = 1030500729;
        continue;
      case 1032623622:
        if (Math.random() < 0.5) {
          calcs += "^b[7] += b[0] + b[15] + b[16] + b[30] + b[18] + b[12] + 60;"
          calcs += "^b[7] &= 0xFF;"
        } else {
          calcs += "^b[5] -= b[19] + b[9] + b[32] + b[7] + b[18] + b[24] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[5] &= 0xFF;"
        }
        state = 220941052;
        continue;
      case 1032872541:
        if (93895156n) {
          calcs += "^b[22] += b[24] + b[42] + b[16] + b[18] + b[7] + b[27] + 116;"
          calcs += "^b[22] &= 0xFF;"
        } else {
          calcs += "^b[5] += b[15] + b[20] + b[28] + b[38] + b[35] + b[16] + 190;"
          calcs += "^b[5] &= 0xFF;"
        }
        state = 527699122;
        continue;
      case 1033010155:
        if (95198055n) {
          calcs += "^b[18] ^= (b[30] + b[23] + b[36] + b[40] + b[10] + b[33] + 192) & 0xFF;"
        } else {
          calcs += "^b[18] += b[4] + b[28] + b[23] + b[19] + b[25] + b[3] + 232;"
          calcs += "^b[18] &= 0xFF;"
        }
        state = 549402220;
        continue;
      case 1034586722:
        if (897353558) {
          calcs += "^b[9] ^= (b[18] + b[37] + b[13] + b[33] + b[22] + b[27] + 182) & 0xFF;"
        } else {
          calcs += "^b[13] -= b[22] + b[4] + b[26] + b[5] + b[10] + b[7] + 76;"
          calcs += "^b[13] &= 0xFF;"
        }
        state = 564568308;
        continue;
      case 1035069239:
        if (476687695) {
          calcs += "^b[18] -= b[13] + b[38] + b[24] + b[8] + b[2] + b[30] + 219;"
          calcs += "^b[18] &= 0xFF;"
        } else {
          calcs += "^b[17] -= b[2] + b[34] + b[10] + b[20] + b[13] + b[37] + 205;"
          calcs += "^b[17] &= 0xFF;"
        }
        state = 980409186;
        continue;
      case 1035147988:
        if (Math.random() < 0.5) {
          calcs += "^b[8] += b[18] + b[41] + b[1] + b[3] + b[16] + b[43] + 139;"
          calcs += "^b[8] &= 0xFF;"
        } else {
          calcs += "^b[6] += b[43] + b[33] + b[31] + b[3] + b[19] + b[41] + 244;"
          calcs += "^b[6] &= 0xFF;"
        }
        state = 297178418;
        continue;
      case 1036669856:
        if (Math.random() < 0.5) {
          calcs += "^b[8] ^= (b[39] + b[10] + b[15] + b[14] + b[19] + b[0] + 177) & 0xFF;"
        } else {
          calcs += "^b[5] += b[35] + b[4] + b[33] + b[21] + b[36] + b[31] + 225;"
          calcs += "^b[5] &= 0xFF;"
        }
        state = 452259210;
        continue;
      case 1037327395:
        if (Math.random() < 0.5) {
          calcs += "^b[2] -= b[4] + b[34] + b[19] + b[37] + b[26] + b[30] + 45;"
          calcs += "^b[2] &= 0xFF;"
        } else {
          calcs += "^b[38] += b[27] + b[5] + b[3] + b[19] + b[2] + b[18] + 8;"
          calcs += "^b[38] &= 0xFF;"
        }
        state = 318932189;
        continue;
      case 1038162449:
        if (68176465) {
          calcs += "^b[10] += b[19] + b[6] + b[30] + b[12] + b[2] + b[9] + 229;"
          calcs += "^b[10] &= 0xFF;"
        } else {
          calcs += "^b[15] -= b[14] + b[16] + b[36] + b[40] + b[10] + b[3] + 204;"
          calcs += "^b[15] &= 0xFF;"
        }
        state = 841404255;
        continue;
      case 1043589810:
        if (Math.random() < 0.5) {
          calcs += "^b[4] ^= (b[43] + b[8] + b[16] + b[27] + b[6] + b[0] + 114) & 0xFF;"
        } else {
          calcs += "^b[7] += b[21] + b[25] + b[38] + b[43] + b[42] + b[41] + 22;"
          calcs += "^b[7] &= 0xFF;"
        }
        state = 345784016;
        continue;
      case 1045321173:
        if (80349184n) {
          calcs += "^b[21] -= b[5] + b[9] + b[19] + b[7] + b[26] + b[18] + 114;"
          calcs += "^b[21] &= 0xFF;"
        } else {
          calcs += "^b[14] ^= (b[21] + b[3] + b[35] + b[19] + b[23] + b[20] + 96) & 0xFF;"
        }
        state = 248744368;
        continue;
      case 1045388446:
        if (Math.random() < 0.5) {
          calcs += "^b[33] += b[40] + b[17] + b[43] + b[21] + b[36] + b[23] + 76;"
          calcs += "^b[33] &= 0xFF;"
        } else {
          calcs += "^b[20] -= b[37] + b[30] + b[12] + b[15] + b[6] + b[7] + 88;"
          calcs += "^b[20] &= 0xFF;"
        }
        state = 204284567;
        continue;
      case 1048216731:
        if (77511183n) {
          calcs += "^b[18] -= b[7] + b[12] + b[5] + b[26] + b[9] + b[6] + 196;"
          calcs += "^b[18] &= 0xFF;"
        } else {
          calcs += "^b[22] += b[16] + b[18] + b[7] + b[23] + b[1] + b[27] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[22] &= 0xFF;"
        }
        state = 598763014;
        continue;
      case 1050270889:
        if (Math.random() < 0.5) {
          calcs += "^b[39] -= b[12] + b[36] + b[0] + b[41] + b[38] + b[35] + 102;"
          calcs += "^b[39] &= 0xFF;"
        } else {
          calcs += "^b[16] += b[3] + b[30] + b[5] + b[36] + b[27] + b[28] + 30;"
          calcs += "^b[16] &= 0xFF;"
        }
        state = 649908962;
        continue;
      case 1050297000:
        if (Math.random() < 0.5) {
          calcs += "^b[40] += b[22] + b[4] + b[28] + b[3] + b[18] + b[23] + 3;"
          calcs += "^b[40] &= 0xFF;"
        } else {
          calcs += "^b[0] ^= (b[19] + b[7] + b[16] + b[35] + b[25] + b[17] + " + Math.floor(Math.random() * 256) + ") & 0xFF;"
        }
        state = 1038369278;
        continue;
      case 1051637796:
        if (709602957) {
          calcs += "^b[31] -= b[40] + b[17] + b[29] + b[22] + b[23] + b[7] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[31] &= 0xFF;"
        } else {
          calcs += "^b[11] += b[43] + b[37] + b[41] + b[18] + b[29] + b[33] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[11] &= 0xFF;"
        }
        state = 427285211;
        continue;
      case 1052448154:
        if (Math.random() < 0.5) {
          calcs += "^b[5] += b[30] + b[35] + b[37] + b[25] + b[0] + b[10] + 27;"
          calcs += "^b[5] &= 0xFF;"
        } else {
          calcs += "^b[9] ^= (b[30] + b[12] + b[23] + b[2] + b[13] + b[34] + 165) & 0xFF;"
        }
        state = 86264343;
        continue;
      case 1054182512:
        if (Math.random() < 0.5) {
          calcs += "^b[14] ^= (b[4] + b[35] + b[26] + b[1] + b[0] + b[7] + 81) & 0xFF;"
        } else {
          calcs += "^b[4] += b[10] + b[17] + b[21] + b[36] + b[1] + b[13] + 155;"
          calcs += "^b[4] &= 0xFF;"
        }
        state = 420579324;
        continue;
      case 1055058931:
        if (344970600) {
          calcs += "^b[32] ^= (b[33] + b[42] + b[30] + b[8] + b[6] + b[17] + 170) & 0xFF;"
        } else {
          calcs += "^b[19] ^= (b[16] + b[17] + b[11] + b[12] + b[37] + b[31] + 52) & 0xFF;"
        }
        state = 339565981;
        continue;
      case 1056873066:
        if (Math.random() < 0.5) {
          calcs += "^b[18] += b[17] + b[43] + b[26] + b[10] + b[30] + b[16] + 6;"
          calcs += "^b[18] &= 0xFF;"
        } else {
          calcs += "^b[7] -= b[8] + b[23] + b[25] + b[17] + b[33] + b[28] + 77;"
          calcs += "^b[7] &= 0xFF;"
        }
        state = 580258836;
        continue;
      case 1056913712:
        if (Math.random() < 0.5) {
          calcs += "^b[29] ^= (b[24] + b[6] + b[31] + b[41] + b[42] + b[22] + 12) & 0xFF;"
        } else {
          calcs += "^b[1] -= b[20] + b[32] + b[25] + b[35] + b[10] + b[18] + 147;"
          calcs += "^b[1] &= 0xFF;"
        }
        state = 320204800;
        continue;
      case 1058172980:
        if (Math.random() < 0.5) {
          calcs += "^b[40] -= b[17] + b[26] + b[34] + b[13] + b[27] + b[6] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[40] &= 0xFF;"
        } else {
          calcs += "^b[35] += b[6] + b[1] + b[37] + b[15] + b[40] + b[25] + 133;"
          calcs += "^b[35] &= 0xFF;"
        }
        state = 342467768;
        continue;
      case 1059150294:
        if (Math.random() < 0.5) {
          calcs += "^b[13] += b[16] + b[21] + b[6] + b[9] + b[26] + b[34] + 247;"
          calcs += "^b[13] &= 0xFF;"
        } else {
          calcs += "^b[32] ^= (b[18] + b[11] + b[42] + b[1] + b[27] + b[14] + 241) & 0xFF;"
        }
        state = 573062015;
        continue;
      case 1060070784:
        if (Math.random() < 0.5) {
          calcs += "^b[9] ^= (b[43] + b[21] + b[32] + b[33] + b[25] + b[42] + " + Math.floor(Math.random() * 256) + ") & 0xFF;"
        } else {
          calcs += "^b[34] += b[14] + b[10] + b[4] + b[29] + b[12] + b[30] + 205;"
          calcs += "^b[34] &= 0xFF;"
        }
        state = 1032232784;
        continue;
      case 1066734042:
        if (769282608) {
          calcs += "^b[25] ^= (b[42] + b[5] + b[6] + b[12] + b[15] + b[22] + " + Math.floor(Math.random() * 256) + ") & 0xFF;"
        } else {
          calcs += "^b[6] += b[4] + b[40] + b[15] + b[37] + b[12] + b[23] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[6] &= 0xFF;"
        }
        state = 826829071;
        continue;
      case 1066991154:
        if (717298020) {
          calcs += "^b[27] += b[38] + b[12] + b[7] + b[18] + b[26] + b[30] + 79;"
          calcs += "^b[27] &= 0xFF;"
        } else {
          calcs += "^b[4] ^= (b[37] + b[43] + b[15] + b[8] + b[2] + b[10] + 199) & 0xFF;"
        }
        state = 51803158;
        continue;
      case 1067849720:
        if (19983457n) {
          calcs += "^b[35] -= b[4] + b[41] + b[23] + b[2] + b[14] + b[9] + 245;"
          calcs += "^b[35] &= 0xFF;"
        } else {
          calcs += "^b[37] -= b[18] + b[14] + b[30] + b[10] + b[22] + b[5] + 175;"
          calcs += "^b[37] &= 0xFF;"
        }
        state = 371460526;
        continue;
      case 1067938463:
        if (722589847) {
          calcs += "^b[12] ^= (b[40] + b[25] + b[19] + b[16] + b[20] + b[27] + 147) & 0xFF;"
        } else {
          calcs += "^b[40] -= b[2] + b[17] + b[26] + b[8] + b[24] + b[23] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[40] &= 0xFF;"
        }
        state = 382387218;
        continue;
      case 1068427493:
        if (832507300) {
          calcs += "^b[34] += b[39] + b[18] + b[15] + b[43] + b[2] + b[17] + 102;"
          calcs += "^b[34] &= 0xFF;"
        } else {
          calcs += "^b[1] += b[5] + b[17] + b[20] + b[43] + b[39] + b[25] + 81;"
          calcs += "^b[1] &= 0xFF;"
        }
        state = 211738091;
        continue;
      case 1069041735:
        if (98837473n) {
          calcs += "^b[42] += b[9] + b[26] + b[14] + b[31] + b[43] + b[34] + 103;"
          calcs += "^b[42] &= 0xFF;"
        } else {
          calcs += "^b[36] ^= (b[12] + b[21] + b[34] + b[29] + b[28] + b[7] + 141) & 0xFF;"
        }
        state = 662693666;
        continue;
      case 1069471290:
        if (Math.random() < 0.5) {
          calcs += "^b[39] -= b[30] + b[27] + b[6] + b[31] + b[13] + b[42] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[39] &= 0xFF;"
        } else {
          calcs += "^b[12] += b[13] + b[22] + b[15] + b[16] + b[10] + b[11] + 14;"
          calcs += "^b[12] &= 0xFF;"
        }
        state = 763623205;
        continue;
      case 1071145532:
        if (75430430n) {
          calcs += "^b[30] -= b[25] + b[34] + b[36] + b[6] + b[41] + b[11] + 108;"
          calcs += "^b[30] &= 0xFF;"
        } else {
          calcs += "^b[10] -= b[30] + b[42] + b[20] + b[18] + b[17] + b[23] + 146;"
          calcs += "^b[10] &= 0xFF;"
        }
        state = 584411822;
        continue;
      case 1071248168:
        if (56916210n) {
          calcs += "^b[41] -= b[11] + b[27] + b[37] + b[2] + b[18] + b[35] + " + Math.floor(Math.random() * 256) + ";"
          calcs += "^b[41] &= 0xFF;"
        } else {
          calcs += "^b[11] += b[21] + b[25] + b[13] + b[15] + b[7] + b[36] + 236;"
          calcs += "^b[11] &= 0xFF;"
        }
        state = 290861842;
        continue;
      case 1071664271:
        if (Math.random() < 0.5) {
          calcs += "^b[17] += b[0] + b[35] + b[12] + b[42] + b[14] + b[3] + 8;"
          calcs += "^b[17] &= 0xFF;"
        } else {
          calcs += "^b[18] ^= (b[20] + b[23] + b[6] + b[12] + b[4] + b[25] + " + Math.floor(Math.random() * 256) + ") & 0xFF;"
        }
        state = 175099911;
        continue;
      case 1071767211:
        if (Math.random() < 0.5) {
          calcs += "^b[30] ^= (b[42] + b[9] + b[2] + b[36] + b[12] + b[16] + 241) & 0xFF;"
        } else {
          calcs += "^b[20] ^= (b[41] + b[2] + b[40] + b[21] + b[36] + b[17] + 37) & 0xFF;"
        }
        state = 109621765;
        continue;
      default:
        console.log("uh-oh, math.random() is too random...");
        console.log(b)
        console.log(calcs)
        process.exit(0);
    }
    break;
  }
  var target = [106, 196, 106, 178, 174, 102, 31, 91, 66, 255, 86, 196, 74, 139, 219, 166, 106, 4, 211, 68, 227, 72, 156, 38, 239, 153, 223, 225, 73, 171, 51, 4, 234, 50, 207, 82, 18, 111, 180, 212, 81, 189, 73, 76];
  console.log("target")
  console.log(target)
  console.log("b")
  console.log(b)
  console.log("calcs")
  console.log(calcs)

  if (b.every((x,i) => x === target[i])) {
    console.log('Congrats!');
  } else {
    console.log('Try again.');
  }
});
```

Executing the new anode binary will give me the following computations executed on `b[]` that forms `target[]`:

```python
b[29] -= b[37] + b[23] + b[22] + b[24] + b[26] + b[10] + 7;
b[29] &= 0xFF;
b[39] += b[34] + b[2] + b[1] + b[43] + b[20] + b[9] + 79;
b[39] &= 0xFF;
b[19] ^= (b[26] + b[0] + b[40] + b[37] + b[23] + b[32] + 255) & 0xFF;
b[28] ^= (b[1] + b[23] + b[37] + b[31] + b[43] + b[42] + 245) & 0xFF;
b[39] += b[42] + b[10] + b[3] + b[41] + b[14] + b[26] + 177;
b[39] &= 0xFF;
b[9] -= b[20] + b[19] + b[22] + b[5] + b[32] + b[35] + 151;
b[9] &= 0xFF;
b[14] -= b[4] + b[5] + b[31] + b[15] + b[36] + b[40] + 67;
b[14] &= 0xFF;
b[33] += b[25] + b[12] + b[14] + b[34] + b[4] + b[36] + 185;
b[33] &= 0xFF;
b[12] -= b[21] + b[23] + b[0] + b[32] + b[28] + b[17] + 252;
b[12] &= 0xFF;
b[43] += b[10] + b[15] + b[28] + b[29] + b[27] + b[26] + 168;
b[43] &= 0xFF;
b[18] ^= (b[32] + b[30] + b[26] + b[22] + b[9] + b[33] + 19) & 0xFF;
b[8] += b[18] + b[41] + b[1] + b[3] + b[16] + b[43] + 139;
b[8] &= 0xFF;
b[34] += b[2] + b[22] + b[15] + b[18] + b[7] + b[33] + 43;
b[34] &= 0xFF;
b[0] -= b[15] + b[3] + b[29] + b[10] + b[20] + b[39] + 93;
b[0] &= 0xFF;
b[12] += b[41] + b[21] + b[40] + b[31] + b[17] + b[9] + 143;
b[12] &= 0xFF;
b[26] -= b[15] + b[43] + b[11] + b[16] + b[28] + b[30] + 150;
b[26] &= 0xFF;
b[11] += b[43] + b[37] + b[41] + b[18] + b[29] + b[33] + 56;
b[11] &= 0xFF;
b[25] -= b[3] + b[24] + b[18] + b[15] + b[2] + b[12] + 33;
b[25] &= 0xFF;
b[31] -= b[14] + b[43] + b[19] + b[36] + b[41] + b[8] + 106;
b[31] &= 0xFF;
b[31] -= b[19] + b[4] + b[43] + b[41] + b[36] + b[7] + 105;
b[31] &= 0xFF;
b[10] += b[15] + b[21] + b[0] + b[42] + b[31] + b[9] + 61;
b[10] &= 0xFF;
b[10] -= b[12] + b[16] + b[30] + b[9] + b[34] + b[13] + 121;
b[10] &= 0xFF;
b[5] -= b[33] + b[23] + b[15] + b[39] + b[2] + b[31] + 222;
b[5] &= 0xFF;
b[40] ^= (b[15] + b[39] + b[14] + b[17] + b[16] + b[9] + 206) & 0xFF;
b[16] ^= (b[31] + b[22] + b[41] + b[14] + b[35] + b[37] + 74) & 0xFF;
b[2] -= b[29] + b[9] + b[11] + b[19] + b[0] + b[27] + 89;
b[2] &= 0xFF;
b[15] -= b[28] + b[7] + b[29] + b[13] + b[0] + b[22] + 189;
b[15] &= 0xFF;
b[24] -= b[34] + b[12] + b[14] + b[41] + b[21] + b[11] + 223;
b[24] &= 0xFF;
b[33] += b[4] + b[27] + b[32] + b[43] + b[42] + b[36] + 209;
b[33] &= 0xFF;
b[19] += b[6] + b[14] + b[35] + b[39] + b[21] + b[42] + 253;
b[19] &= 0xFF;
b[41] -= b[27] + b[6] + b[15] + b[42] + b[7] + b[17] + 162;
b[41] &= 0xFF;
b[16] += b[34] + b[25] + b[24] + b[23] + b[42] + b[14] + 168;
b[16] &= 0xFF;
b[23] ^= (b[39] + b[33] + b[27] + b[43] + b[12] + b[2] + 78) & 0xFF;
b[6] -= b[20] + b[41] + b[0] + b[42] + b[12] + b[19] + 131;
b[6] &= 0xFF;
b[5] -= b[20] + b[43] + b[9] + b[3] + b[40] + b[25] + 50;
b[5] &= 0xFF;
b[8] += b[2] + b[14] + b[13] + b[15] + b[7] + b[9] + 91;
b[8] &= 0xFF;
b[15] -= b[25] + b[43] + b[8] + b[19] + b[42] + b[36] + 163;
b[15] &= 0xFF;
b[42] ^= (b[43] + b[39] + b[36] + b[3] + b[26] + b[23] + 7) & 0xFF;
b[20] += b[28] + b[15] + b[21] + b[33] + b[14] + b[9] + 201;
b[20] &= 0xFF;
b[42] += b[18] + b[37] + b[23] + b[21] + b[41] + b[38] + 64;
b[42] &= 0xFF;
b[4] -= b[36] + b[16] + b[6] + b[3] + b[33] + b[23] + 217;
b[4] &= 0xFF;
b[28] += b[41] + b[9] + b[22] + b[29] + b[18] + b[14] + 14;
b[28] &= 0xFF;
b[1] ^= (b[40] + b[42] + b[33] + b[23] + b[7] + b[19] + 10) & 0xFF;
b[4] ^= (b[37] + b[43] + b[15] + b[8] + b[2] + b[10] + 199) & 0xFF;
b[21] += b[10] + b[17] + b[34] + b[14] + b[4] + b[43] + 30;
b[21] &= 0xFF;
b[23] -= b[30] + b[36] + b[5] + b[7] + b[22] + b[39] + 221;
b[23] &= 0xFF;
b[35] -= b[4] + b[29] + b[25] + b[9] + b[6] + b[3] + 198;
b[35] &= 0xFF;
b[23] += b[17] + b[34] + b[39] + b[3] + b[21] + b[26] + 251;
b[23] &= 0xFF;
b[38] ^= (b[25] + b[28] + b[12] + b[23] + b[20] + b[4] + 220) & 0xFF;
b[16] -= b[5] + b[27] + b[21] + b[8] + b[22] + b[28] + 254;
b[16] &= 0xFF;
b[5] += b[29] + b[23] + b[15] + b[0] + b[14] + b[28] + 198;
b[5] &= 0xFF;
b[26] ^= (b[32] + b[0] + b[13] + b[27] + b[43] + b[31] + 179) & 0xFF;
b[6] ^= (b[12] + b[30] + b[10] + b[41] + b[3] + b[37] + 121) & 0xFF;
b[40] += b[1] + b[9] + b[18] + b[17] + b[33] + b[39] + 146;
b[40] &= 0xFF;
b[15] += b[36] + b[13] + b[25] + b[9] + b[0] + b[24] + 18;
b[15] &= 0xFF;
b[33] -= b[8] + b[10] + b[30] + b[31] + b[20] + b[42] + 105;
b[33] &= 0xFF;
b[4] ^= (b[8] + b[33] + b[19] + b[12] + b[25] + b[15] + 101) & 0xFF;
b[38] ^= (b[39] + b[2] + b[0] + b[31] + b[29] + b[5] + 160) & 0xFF;
b[43] += b[40] + b[19] + b[26] + b[4] + b[10] + b[7] + 56;
b[43] &= 0xFF;
b[34] -= b[41] + b[14] + b[13] + b[20] + b[17] + b[7] + 29;
b[34] &= 0xFF;
b[40] ^= (b[26] + b[25] + b[5] + b[36] + b[7] + b[22] + 225) & 0xFF;
b[24] ^= (b[31] + b[0] + b[27] + b[28] + b[14] + b[34] + 22) & 0xFF;
b[25] -= b[42] + b[24] + b[41] + b[14] + b[36] + b[17] + 58;
b[25] &= 0xFF;
b[5] -= b[28] + b[39] + b[25] + b[43] + b[15] + b[7] + 203;
b[5] &= 0xFF;
b[25] += b[34] + b[28] + b[19] + b[36] + b[0] + b[3] + 18;
b[25] &= 0xFF;
b[18] -= b[23] + b[10] + b[2] + b[30] + b[6] + b[17] + 44;
b[18] &= 0xFF;
b[0] ^= (b[12] + b[30] + b[6] + b[17] + b[4] + b[20] + 92) & 0xFF;
b[30] ^= (b[34] + b[4] + b[2] + b[13] + b[12] + b[35] + 110) & 0xFF;
b[20] += b[42] + b[21] + b[32] + b[30] + b[33] + b[39] + 230;
b[20] &= 0xFF;
b[6] ^= (b[12] + b[33] + b[15] + b[35] + b[11] + b[2] + 164) & 0xFF;
b[40] -= b[22] + b[0] + b[28] + b[17] + b[31] + b[11] + 8;
b[40] &= 0xFF;
b[41] ^= (b[28] + b[0] + b[23] + b[12] + b[37] + b[29] + 140) & 0xFF;
b[12] += b[23] + b[43] + b[17] + b[19] + b[3] + b[30] + 82;
b[12] &= 0xFF;
b[41] ^= (b[17] + b[25] + b[9] + b[42] + b[36] + b[10] + 170) & 0xFF;
b[28] ^= (b[41] + b[26] + b[27] + b[37] + b[21] + b[6] + 153) & 0xFF;
b[11] ^= (b[8] + b[33] + b[17] + b[27] + b[2] + b[28] + 196) & 0xFF;
b[3] += b[6] + b[26] + b[32] + b[22] + b[39] + b[25] + 119;
b[3] &= 0xFF;
b[11] += b[42] + b[27] + b[40] + b[0] + b[6] + b[26] + 177;
b[11] &= 0xFF;
b[12] ^= (b[19] + b[16] + b[28] + b[14] + b[40] + b[33] + 158) & 0xFF;
b[21] -= b[22] + b[2] + b[33] + b[28] + b[10] + b[31] + 98;
b[21] &= 0xFF;
b[3] -= b[23] + b[36] + b[41] + b[17] + b[18] + b[22] + 172;
b[3] &= 0xFF;
b[6] ^= (b[8] + b[23] + b[28] + b[17] + b[32] + b[12] + 66) & 0xFF;
b[20] -= b[6] + b[41] + b[42] + b[28] + b[30] + b[12] + 226;
b[20] &= 0xFF;
b[28] += b[36] + b[26] + b[17] + b[5] + b[1] + b[13] + 245;
b[28] &= 0xFF;
b[42] += b[29] + b[14] + b[31] + b[22] + b[36] + b[33] + 60;
b[42] &= 0xFF;
b[27] ^= (b[39] + b[14] + b[33] + b[22] + b[6] + b[28] + 28) & 0xFF;
b[18] += b[26] + b[6] + b[37] + b[36] + b[33] + b[5] + 177;
b[18] &= 0xFF;
b[10] += b[13] + b[27] + b[23] + b[38] + b[2] + b[18] + 18;
b[10] &= 0xFF;
b[18] -= b[21] + b[5] + b[40] + b[34] + b[43] + b[41] + 87;
b[18] &= 0xFF;
b[27] -= b[0] + b[6] + b[21] + b[29] + b[38] + b[1] + 32;
b[27] &= 0xFF;
b[36] += b[9] + b[3] + b[31] + b[41] + b[8] + b[22] + 42;
b[36] &= 0xFF;
b[3] ^= (b[14] + b[26] + b[33] + b[17] + b[32] + b[1] + 230) & 0xFF;
b[21] ^= (b[2] + b[3] + b[12] + b[16] + b[6] + b[15] + 100) & 0xFF;
b[5] ^= (b[17] + b[31] + b[28] + b[9] + b[0] + b[34] + 142) & 0xFF;
b[43] -= b[18] + b[14] + b[4] + b[20] + b[40] + b[27] + 107;
b[43] &= 0xFF;
b[17] -= b[34] + b[1] + b[14] + b[19] + b[29] + b[18] + 164;
b[17] &= 0xFF;
b[33] -= b[43] + b[24] + b[16] + b[7] + b[17] + b[6] + 156;
b[33] &= 0xFF;
b[13] += b[31] + b[43] + b[26] + b[41] + b[24] + b[42] + 128;
b[13] &= 0xFF;
b[19] ^= (b[16] + b[10] + b[3] + b[5] + b[39] + b[0] + 156) & 0xFF;
b[43] -= b[4] + b[20] + b[36] + b[25] + b[22] + b[7] + 174;
b[43] &= 0xFF;
b[39] += b[28] + b[8] + b[36] + b[42] + b[11] + b[13] + 68;
b[39] &= 0xFF;
b[34] ^= (b[35] + b[4] + b[22] + b[41] + b[36] + b[40] + 159) & 0xFF;
b[22] ^= (b[6] + b[10] + b[5] + b[40] + b[17] + b[28] + 173) & 0xFF;
b[28] -= b[22] + b[23] + b[10] + b[20] + b[11] + b[0] + 191;
b[28] &= 0xFF;
b[17] += b[29] + b[43] + b[1] + b[8] + b[32] + b[35] + 126;
b[17] &= 0xFF;
b[41] ^= (b[31] + b[36] + b[2] + b[42] + b[43] + b[4] + 72) & 0xFF;
b[5] ^= (b[36] + b[41] + b[6] + b[26] + b[18] + b[4] + 29) & 0xFF;
b[25] += b[41] + b[17] + b[14] + b[10] + b[35] + b[2] + 41;
b[25] &= 0xFF;
b[6] -= b[33] + b[11] + b[20] + b[15] + b[1] + b[31] + 62;
b[6] &= 0xFF;
b[29] ^= (b[14] + b[1] + b[18] + b[20] + b[17] + b[34] + 192) & 0xFF;
b[12] ^= (b[42] + b[25] + b[19] + b[7] + b[16] + b[43] + 245) & 0xFF;
b[6] ^= (b[36] + b[13] + b[4] + b[38] + b[16] + b[14] + 53) & 0xFF;
b[27] ^= (b[29] + b[21] + b[26] + b[33] + b[10] + b[31] + 111) & 0xFF;
b[25] -= b[37] + b[40] + b[17] + b[21] + b[14] + b[33] + 52;
b[25] &= 0xFF;
b[24] -= b[36] + b[39] + b[27] + b[8] + b[14] + b[34] + 181;
b[24] &= 0xFF;
b[7] ^= (b[5] + b[37] + b[18] + b[12] + b[27] + b[21] + 181) & 0xFF;
b[28] -= b[7] + b[12] + b[18] + b[30] + b[27] + b[10] + 24;
b[28] &= 0xFF;
b[40] ^= (b[30] + b[32] + b[11] + b[24] + b[2] + b[7] + 205) & 0xFF;
b[9] += b[14] + b[38] + b[21] + b[30] + b[8] + b[40] + 179;
b[9] &= 0xFF;
b[9] += b[13] + b[1] + b[5] + b[8] + b[11] + b[32] + 52;
b[9] &= 0xFF;
b[11] -= b[24] + b[13] + b[3] + b[6] + b[27] + b[7] + 206;
b[11] &= 0xFF;
b[4] -= b[2] + b[31] + b[11] + b[16] + b[8] + b[23] + 245;
b[4] &= 0xFF;
b[9] += b[2] + b[29] + b[42] + b[19] + b[31] + b[40] + 131;
b[9] &= 0xFF;
b[38] ^= (b[20] + b[9] + b[32] + b[2] + b[17] + b[3] + 160) & 0xFF;
b[17] ^= (b[24] + b[7] + b[35] + b[31] + b[28] + b[29] + 64) & 0xFF;
b[39] ^= (b[12] + b[16] + b[35] + b[0] + b[41] + b[2] + 229) & 0xFF;
b[42] -= b[26] + b[43] + b[0] + b[21] + b[4] + b[20] + 173;
b[42] &= 0xFF;
b[1] += b[37] + b[20] + b[11] + b[15] + b[8] + b[27] + 26;
b[1] &= 0xFF;
b[35] += b[18] + b[17] + b[30] + b[15] + b[21] + b[6] + 215;
b[35] &= 0xFF;
b[16] ^= (b[32] + b[39] + b[13] + b[21] + b[20] + b[2] + 28) & 0xFF;
b[4] -= b[28] + b[38] + b[37] + b[5] + b[32] + b[13] + 47;
b[4] &= 0xFF;
b[32] += b[29] + b[21] + b[6] + b[4] + b[39] + b[42] + 251;
b[32] &= 0xFF;
b[23] ^= (b[33] + b[16] + b[31] + b[26] + b[15] + b[1] + 3) & 0xFF;
b[41] += b[13] + b[30] + b[12] + b[1] + b[22] + b[16] + 211;
b[41] &= 0xFF;
b[31] ^= (b[8] + b[33] + b[38] + b[40] + b[13] + b[16] + 112) & 0xFF;
b[4] += b[35] + b[24] + b[25] + b[36] + b[29] + b[20] + 234;
b[4] &= 0xFF;
b[10] ^= (b[4] + b[2] + b[18] + b[38] + b[22] + b[27] + 40) & 0xFF;
b[27] -= b[13] + b[36] + b[10] + b[40] + b[35] + b[42] + 138;
b[27] &= 0xFF;
b[7] ^= (b[23] + b[6] + b[21] + b[43] + b[26] + b[22] + 145) & 0xFF;
b[18] ^= (b[1] + b[7] + b[23] + b[2] + b[37] + b[4] + 152) & 0xFF;
b[13] -= b[33] + b[28] + b[19] + b[27] + b[6] + b[12] + 240;
b[13] &= 0xFF;
b[41] ^= (b[30] + b[13] + b[21] + b[0] + b[24] + b[1] + 247) & 0xFF;
b[14] -= b[30] + b[5] + b[35] + b[41] + b[3] + b[17] + 119;
b[14] &= 0xFF;
b[30] -= b[6] + b[14] + b[28] + b[29] + b[24] + b[15] + 108;
b[30] &= 0xFF;
b[37] -= b[24] + b[39] + b[15] + b[10] + b[13] + b[35] + 225;
b[37] &= 0xFF;
b[3] -= b[38] + b[37] + b[22] + b[10] + b[8] + b[25] + 181;
b[3] &= 0xFF;
b[31] -= b[35] + b[37] + b[5] + b[42] + b[33] + b[41] + 16;
b[31] &= 0xFF;
b[12] += b[14] + b[31] + b[17] + b[5] + b[22] + b[11] + 29;
b[12] &= 0xFF;
b[24] -= b[9] + b[4] + b[28] + b[23] + b[3] + b[14] + 217;
b[24] &= 0xFF;
b[30] ^= (b[42] + b[9] + b[2] + b[36] + b[12] + b[16] + 241) & 0xFF;
b[27] -= b[15] + b[14] + b[1] + b[28] + b[18] + b[13] + 139;
b[27] &= 0xFF;
b[32] += b[7] + b[37] + b[29] + b[16] + b[3] + b[25] + 62;
b[32] &= 0xFF;
b[40] += b[11] + b[28] + b[42] + b[20] + b[27] + b[13] + 142;
b[40] &= 0xFF;
b[20] += b[30] + b[8] + b[11] + b[34] + b[21] + b[0] + 118;
b[20] &= 0xFF;
b[41] += b[1] + b[4] + b[10] + b[16] + b[13] + b[11] + 6;
b[41] &= 0xFF;
b[36] += b[10] + b[24] + b[34] + b[28] + b[0] + b[3] + 178;
b[36] &= 0xFF;
b[26] -= b[25] + b[2] + b[16] + b[19] + b[23] + b[32] + 119;
b[26] &= 0xFF;
b[37] ^= (b[2] + b[27] + b[7] + b[20] + b[22] + b[32] + 130) & 0xFF;
b[22] -= b[28] + b[19] + b[39] + b[20] + b[14] + b[4] + 88;
b[22] &= 0xFF;
b[23] -= b[14] + b[37] + b[42] + b[11] + b[28] + b[34] + 104;
b[23] &= 0xFF;
b[36] ^= (b[40] + b[22] + b[17] + b[27] + b[0] + b[39] + 200) & 0xFF;
b[4] ^= (b[42] + b[18] + b[12] + b[5] + b[16] + b[37] + 98) & 0xFF;
b[23] ^= (b[27] + b[35] + b[43] + b[19] + b[12] + b[20] + 111) & 0xFF;
b[30] ^= (b[18] + b[9] + b[37] + b[25] + b[32] + b[35] + 0) & 0xFF;
b[5] ^= (b[35] + b[9] + b[30] + b[8] + b[27] + b[26] + 113) & 0xFF;
b[27] += b[18] + b[23] + b[22] + b[8] + b[2] + b[9] + 98;
b[27] &= 0xFF;
b[4] ^= (b[24] + b[17] + b[36] + b[13] + b[10] + b[41] + 197) & 0xFF;
b[23] += b[13] + b[24] + b[18] + b[36] + b[34] + b[14] + 232;
b[23] &= 0xFF;
b[11] += b[17] + b[6] + b[7] + b[32] + b[3] + b[33] + 162;
b[11] &= 0xFF;
b[18] += b[4] + b[9] + b[3] + b[12] + b[26] + b[1] + 145;
b[18] &= 0xFF;
b[25] -= b[9] + b[26] + b[41] + b[43] + b[5] + b[20] + 3;
b[25] &= 0xFF;
b[29] -= b[5] + b[7] + b[4] + b[40] + b[0] + b[39] + 41;
b[29] &= 0xFF;
b[19] += b[38] + b[8] + b[11] + b[35] + b[36] + b[29] + 241;
b[19] &= 0xFF;
b[43] += b[8] + b[39] + b[2] + b[40] + b[37] + b[10] + 152;
b[43] &= 0xFF;
b[28] += b[19] + b[37] + b[21] + b[20] + b[14] + b[23] + 72;
b[28] &= 0xFF;
b[29] += b[10] + b[28] + b[19] + b[38] + b[1] + b[31] + 224;
b[29] &= 0xFF;
b[31] -= b[14] + b[29] + b[42] + b[40] + b[30] + b[33] + 202;
b[31] &= 0xFF;
b[12] -= b[30] + b[29] + b[10] + b[25] + b[33] + b[23] + 180;
b[12] &= 0xFF;
b[43] += b[32] + b[27] + b[4] + b[25] + b[8] + b[11] + 80;
b[43] &= 0xFF;
b[5] += b[4] + b[7] + b[28] + b[43] + b[12] + b[26] + 54;
b[5] &= 0xFF;
b[15] -= b[17] + b[29] + b[20] + b[9] + b[0] + b[43] + 229;
b[15] &= 0xFF;
b[23] ^= (b[15] + b[41] + b[29] + b[12] + b[39] + b[24] + 173) & 0xFF;
b[2] -= b[36] + b[1] + b[26] + b[30] + b[6] + b[13] + 234;
b[2] &= 0xFF;
b[29] ^= (b[24] + b[9] + b[33] + b[36] + b[28] + b[17] + 123) & 0xFF;
b[9] ^= (b[2] + b[13] + b[15] + b[42] + b[39] + b[4] + 52) & 0xFF;
b[0] ^= (b[17] + b[32] + b[8] + b[37] + b[14] + b[1] + 132) & 0xFF;
b[33] ^= (b[4] + b[43] + b[36] + b[16] + b[41] + b[18] + 146) & 0xFF;
b[33] ^= (b[8] + b[26] + b[23] + b[0] + b[30] + b[9] + 207) & 0xFF;
b[1] ^= (b[12] + b[17] + b[21] + b[38] + b[34] + b[39] + 199) & 0xFF;
b[3] ^= (b[34] + b[14] + b[33] + b[28] + b[15] + b[36] + 3) & 0xFF;
b[15] ^= (b[32] + b[26] + b[30] + b[28] + b[40] + b[38] + 179) & 0xFF;
b[13] ^= (b[37] + b[21] + b[22] + b[23] + b[31] + b[26] + 247) & 0xFF;
b[1] -= b[14] + b[10] + b[9] + b[33] + b[41] + b[15] + 240;
b[1] &= 0xFF;
b[37] -= b[18] + b[14] + b[30] + b[10] + b[22] + b[5] + 175;
b[37] &= 0xFF;
b[15] -= b[26] + b[41] + b[19] + b[24] + b[21] + b[20] + 77;
b[15] &= 0xFF;
b[43] ^= (b[41] + b[14] + b[37] + b[38] + b[15] + b[10] + 217) & 0xFF;
b[20] += b[34] + b[11] + b[21] + b[0] + b[43] + b[13] + 213;
b[20] &= 0xFF;
b[19] += b[26] + b[27] + b[29] + b[32] + b[14] + b[21] + 34;
b[19] &= 0xFF;
b[16] ^= (b[41] + b[35] + b[32] + b[27] + b[42] + b[43] + 137) & 0xFF;
b[5] += b[8] + b[16] + b[38] + b[37] + b[1] + b[18] + 148;
b[5] &= 0xFF;
b[24] += b[29] + b[40] + b[37] + b[33] + b[28] + b[43] + 128;
b[24] &= 0xFF;
b[14] ^= (b[38] + b[43] + b[18] + b[22] + b[17] + b[35] + 133) & 0xFF;
b[3] -= b[34] + b[43] + b[8] + b[1] + b[14] + b[30] + 74;
b[3] &= 0xFF;
b[4] ^= (b[22] + b[2] + b[17] + b[1] + b[9] + b[40] + 26) & 0xFF;
b[43] += b[28] + b[32] + b[27] + b[18] + b[16] + b[31] + 15;
b[43] &= 0xFF;
b[12] ^= (b[3] + b[22] + b[38] + b[29] + b[26] + b[4] + 213) & 0xFF;
b[8] -= b[41] + b[23] + b[11] + b[17] + b[5] + b[39] + 125;
b[8] &= 0xFF;
b[29] -= b[19] + b[32] + b[6] + b[40] + b[14] + b[8] + 162;
b[29] &= 0xFF;
b[41] ^= (b[2] + b[1] + b[19] + b[17] + b[15] + b[3] + 86) & 0xFF;
b[1] += b[32] + b[4] + b[0] + b[5] + b[17] + b[2] + 159;
b[1] &= 0xFF;
b[5] ^= (b[20] + b[31] + b[40] + b[10] + b[39] + b[16] + 196) & 0xFF;
b[24] += b[5] + b[42] + b[28] + b[18] + b[13] + b[43] + 10;
b[24] &= 0xFF;
b[22] -= b[21] + b[32] + b[36] + b[31] + b[33] + b[12] + 209;
b[22] &= 0xFF;
b[34] -= b[43] + b[0] + b[24] + b[6] + b[36] + b[41] + 156;
b[34] &= 0xFF;
b[13] -= b[7] + b[18] + b[41] + b[2] + b[31] + b[3] + 214;
b[13] &= 0xFF;
b[25] += b[7] + b[21] + b[12] + b[24] + b[35] + b[42] + 5;
b[25] &= 0xFF;
b[11] ^= (b[18] + b[37] + b[23] + b[5] + b[3] + b[7] + 53) & 0xFF;
b[13] -= b[8] + b[21] + b[24] + b[23] + b[3] + b[27] + 201;
b[13] &= 0xFF;
b[18] += b[31] + b[6] + b[17] + b[12] + b[11] + b[19] + 220;
b[18] &= 0xFF;
b[20] += b[34] + b[10] + b[12] + b[41] + b[18] + b[43] + 147;
b[20] &= 0xFF;
b[33] ^= (b[35] + b[30] + b[36] + b[41] + b[3] + b[28] + 231) & 0xFF;
b[9] += b[27] + b[39] + b[31] + b[43] + b[22] + b[28] + 229;
b[9] &= 0xFF;
b[1] -= b[27] + b[4] + b[7] + b[21] + b[32] + b[31] + 165;
b[1] &= 0xFF;
b[24] ^= (b[15] + b[38] + b[27] + b[23] + b[21] + b[1] + 244) & 0xFF;
b[36] ^= (b[12] + b[21] + b[34] + b[29] + b[28] + b[7] + 141) & 0xFF;
b[35] += b[32] + b[29] + b[42] + b[30] + b[43] + b[33] + 155;
b[35] &= 0xFF;
b[18] -= b[41] + b[12] + b[21] + b[27] + b[24] + b[6] + 193;
b[18] &= 0xFF;
b[26] -= b[8] + b[3] + b[27] + b[28] + b[6] + b[34] + 7;
b[26] &= 0xFF;
b[13] -= b[22] + b[4] + b[26] + b[5] + b[10] + b[7] + 76;
b[13] &= 0xFF;
b[25] ^= (b[26] + b[32] + b[12] + b[27] + b[28] + b[7] + 178) & 0xFF;
b[9] += b[18] + b[4] + b[7] + b[13] + b[29] + b[26] + 117;
b[9] &= 0xFF;
b[14] ^= (b[0] + b[7] + b[13] + b[39] + b[21] + b[22] + 251) & 0xFF;
b[6] += b[43] + b[35] + b[2] + b[27] + b[21] + b[30] + 212;
b[6] &= 0xFF;
b[5] += b[26] + b[22] + b[39] + b[0] + b[36] + b[4] + 1;
b[5] &= 0xFF;
b[23] ^= (b[11] + b[15] + b[34] + b[8] + b[36] + b[16] + 62) & 0xFF;
b[9] += b[4] + b[43] + b[39] + b[16] + b[15] + b[22] + 183;
b[9] &= 0xFF;
b[8] += b[12] + b[16] + b[14] + b[4] + b[34] + b[23] + 244;
b[8] &= 0xFF;
b[7] -= b[14] + b[33] + b[30] + b[6] + b[31] + b[16] + 185;
b[7] &= 0xFF;
b[36] ^= (b[42] + b[6] + b[11] + b[40] + b[33] + b[7] + 207) & 0xFF;
b[11] += b[15] + b[43] + b[24] + b[34] + b[16] + b[9] + 166;
b[11] &= 0xFF;
b[33] += b[12] + b[21] + b[4] + b[37] + b[7] + b[9] + 124;
b[33] &= 0xFF;
b[12] ^= (b[25] + b[5] + b[15] + b[11] + b[1] + b[9] + 8) & 0xFF;
b[21] += b[32] + b[24] + b[34] + b[28] + b[15] + b[0] + 63;
b[21] &= 0xFF;
b[37] -= b[39] + b[43] + b[28] + b[17] + b[24] + b[7] + 3;
b[37] &= 0xFF;
b[28] += b[0] + b[23] + b[14] + b[16] + b[20] + b[25] + 31;
b[28] &= 0xFF;
b[12] ^= (b[9] + b[23] + b[34] + b[14] + b[13] + b[10] + 147) & 0xFF;
b[9] += b[1] + b[10] + b[23] + b[22] + b[37] + b[21] + 129;
b[9] &= 0xFF;
b[5] -= b[29] + b[22] + b[2] + b[30] + b[19] + b[7] + 181;
b[5] &= 0xFF;
b[38] += b[37] + b[13] + b[8] + b[23] + b[22] + b[27] + 86;
b[38] &= 0xFF;
b[34] ^= (b[42] + b[18] + b[9] + b[32] + b[3] + b[11] + 182) & 0xFF;
b[29] -= b[38] + b[14] + b[34] + b[18] + b[43] + b[35] + 135;
b[29] &= 0xFF;
b[0] ^= (b[11] + b[37] + b[33] + b[36] + b[38] + b[3] + 123) & 0xFF;
b[4] -= b[37] + b[2] + b[27] + b[13] + b[21] + b[35] + 194;
b[4] &= 0xFF;
b[27] ^= (b[17] + b[13] + b[28] + b[12] + b[24] + b[3] + 116) & 0xFF;
b[26] -= b[4] + b[11] + b[31] + b[32] + b[28] + b[16] + 165;
b[26] &= 0xFF;
b[21] ^= (b[20] + b[38] + b[14] + b[15] + b[1] + b[13] + 81) & 0xFF;
b[5] += b[11] + b[20] + b[24] + b[37] + b[33] + b[38] + 113;
b[5] &= 0xFF;
b[1] -= b[32] + b[31] + b[34] + b[16] + b[28] + b[35] + 141;
b[1] &= 0xFF;
b[40] += b[22] + b[4] + b[28] + b[3] + b[18] + b[23] + 3;
b[40] &= 0xFF;
b[38] ^= (b[17] + b[28] + b[4] + b[18] + b[11] + b[3] + 133) & 0xFF;
b[22] += b[29] + b[42] + b[40] + b[38] + b[8] + b[6] + 131;
b[22] &= 0xFF;
b[5] -= b[19] + b[9] + b[32] + b[7] + b[18] + b[24] + 241;
b[5] &= 0xFF;
b[15] ^= (b[2] + b[43] + b[3] + b[5] + b[0] + b[35] + 10) & 0xFF;
b[40] -= b[27] + b[21] + b[22] + b[28] + b[11] + b[15] + 134;
b[40] &= 0xFF;
b[39] -= b[23] + b[17] + b[21] + b[36] + b[20] + b[34] + 12;
b[39] &= 0xFF;
b[16] += b[38] + b[6] + b[21] + b[34] + b[27] + b[10] + 35;
b[16] &= 0xFF;
b[38] -= b[0] + b[1] + b[27] + b[36] + b[31] + b[17] + 247;
b[38] &= 0xFF;
b[35] += b[5] + b[0] + b[14] + b[2] + b[20] + b[6] + 241;
b[35] &= 0xFF;
b[30] -= b[35] + b[40] + b[33] + b[4] + b[18] + b[29] + 149;
b[30] &= 0xFF;
b[30] ^= (b[43] + b[42] + b[19] + b[3] + b[11] + b[23] + 221) & 0xFF;
b[40] -= b[8] + b[26] + b[31] + b[38] + b[32] + b[37] + 187;
b[40] &= 0xFF;
b[10] += b[39] + b[37] + b[32] + b[9] + b[29] + b[0] + 138;
b[10] &= 0xFF;
b[42] ^= (b[20] + b[38] + b[37] + b[12] + b[35] + b[41] + 155) & 0xFF;
b[0] -= b[43] + b[4] + b[5] + b[29] + b[6] + b[24] + 208;
b[0] &= 0xFF;
b[35] ^= (b[2] + b[18] + b[4] + b[1] + b[24] + b[21] + 103) & 0xFF;
b[9] -= b[27] + b[26] + b[37] + b[12] + b[31] + b[30] + 208;
b[9] &= 0xFF;
b[21] += b[23] + b[34] + b[14] + b[30] + b[39] + b[35] + 241;
b[21] &= 0xFF;
b[1] += b[5] + b[17] + b[20] + b[43] + b[39] + b[25] + 81;
b[1] &= 0xFF;
b[13] ^= (b[27] + b[19] + b[31] + b[38] + b[43] + b[23] + 33) & 0xFF;
b[30] ^= (b[40] + b[36] + b[43] + b[6] + b[11] + b[2] + 57) & 0xFF;
b[10] -= b[37] + b[36] + b[26] + b[9] + b[24] + b[7] + 86;
b[10] &= 0xFF;
b[40] ^= (b[33] + b[23] + b[24] + b[41] + b[31] + b[27] + 58) & 0xFF;
b[0] ^= (b[32] + b[20] + b[30] + b[10] + b[37] + b[35] + 204) & 0xFF;
b[7] += b[3] + b[0] + b[14] + b[31] + b[40] + b[5] + 226;
b[7] &= 0xFF;
b[16] -= b[35] + b[11] + b[36] + b[29] + b[10] + b[26] + 70;
b[16] &= 0xFF;
b[35] ^= (b[14] + b[24] + b[26] + b[32] + b[7] + b[19] + 139) & 0xFF;
b[11] -= b[3] + b[20] + b[30] + b[18] + b[1] + b[17] + 21;
b[11] &= 0xFF;
b[43] += b[13] + b[27] + b[15] + b[12] + b[6] + b[5] + 69;
b[43] &= 0xFF;
b[42] += b[16] + b[29] + b[3] + b[32] + b[4] + b[5] + 217;
b[42] &= 0xFF;
b[8] += b[14] + b[40] + b[10] + b[1] + b[28] + b[6] + 110;
b[8] &= 0xFF;
b[32] ^= (b[0] + b[40] + b[41] + b[24] + b[22] + b[3] + 232) & 0xFF;
b[20] += b[36] + b[42] + b[12] + b[24] + b[10] + b[14] + 70;
b[20] &= 0xFF;
b[2] ^= (b[15] + b[40] + b[14] + b[19] + b[8] + b[25] + 156) & 0xFF;
b[18] ^= (b[41] + b[15] + b[32] + b[16] + b[26] + b[23] + 205) & 0xFF;
b[35] -= b[39] + b[12] + b[36] + b[2] + b[9] + b[30] + 167;
b[35] &= 0xFF;
b[21] -= b[5] + b[9] + b[19] + b[7] + b[26] + b[18] + 114;
b[21] &= 0xFF;
b[23] -= b[24] + b[43] + b[30] + b[37] + b[6] + b[36] + 58;
b[23] &= 0xFF;
b[40] ^= (b[35] + b[22] + b[17] + b[2] + b[20] + b[18] + 80) & 0xFF;
b[34] += b[33] + b[2] + b[32] + b[6] + b[3] + b[21] + 216;
b[34] &= 0xFF;
b[30] += b[17] + b[24] + b[8] + b[9] + b[16] + b[18] + 104;
b[30] &= 0xFF;
b[18] ^= (b[30] + b[23] + b[36] + b[40] + b[10] + b[33] + 192) & 0xFF;
b[6] ^= (b[35] + b[37] + b[7] + b[31] + b[29] + b[15] + 217) & 0xFF;
b[18] -= b[25] + b[39] + b[0] + b[35] + b[42] + b[6] + 84;
b[18] &= 0xFF;
b[25] ^= (b[26] + b[5] + b[0] + b[31] + b[6] + b[39] + 207) & 0xFF;
b[13] ^= (b[20] + b[26] + b[37] + b[9] + b[29] + b[16] + 195) & 0xFF;
b[24] -= b[37] + b[42] + b[7] + b[5] + b[22] + b[11] + 177;
b[24] &= 0xFF;
b[18] += b[12] + b[0] + b[23] + b[38] + b[37] + b[24] + 223;
b[18] &= 0xFF;
b[41] ^= (b[10] + b[17] + b[0] + b[1] + b[40] + b[5] + 80) & 0xFF;
b[32] -= b[8] + b[19] + b[43] + b[0] + b[2] + b[1] + 120;
b[32] &= 0xFF;
b[10] -= b[32] + b[1] + b[20] + b[30] + b[23] + b[9] + 115;
b[10] &= 0xFF;
b[14] -= b[28] + b[12] + b[36] + b[39] + b[37] + b[40] + 87;
b[14] &= 0xFF;
b[26] += b[8] + b[12] + b[33] + b[39] + b[19] + b[29] + 210;
b[26] &= 0xFF;
b[16] -= b[32] + b[4] + b[31] + b[8] + b[29] + b[14] + 218;
b[16] &= 0xFF;
b[25] += b[6] + b[4] + b[7] + b[3] + b[26] + b[12] + 131;
b[25] &= 0xFF;
b[14] ^= (b[32] + b[41] + b[35] + b[40] + b[9] + b[22] + 63) & 0xFF;
b[8] ^= (b[1] + b[12] + b[11] + b[17] + b[37] + b[2] + 55) & 0xFF;
b[39] -= b[19] + b[17] + b[33] + b[22] + b[31] + b[10] + 166;
b[39] &= 0xFF;
b[43] ^= (b[20] + b[34] + b[21] + b[6] + b[17] + b[16] + 92) & 0xFF;
b[4] ^= (b[22] + b[25] + b[28] + b[6] + b[7] + b[24] + 23) & 0xFF;
b[28] ^= (b[5] + b[19] + b[41] + b[23] + b[34] + b[32] + 227) & 0xFF;
b[19] += b[31] + b[26] + b[18] + b[27] + b[22] + b[5] + 222;
b[19] &= 0xFF;
b[3] ^= (b[1] + b[38] + b[15] + b[35] + b[25] + b[23] + 225) & 0xFF;
b[43] += b[40] + b[23] + b[21] + b[26] + b[6] + b[33] + 76;
b[43] &= 0xFF;
b[22] += b[37] + b[10] + b[38] + b[39] + b[40] + b[23] + 205;
b[22] &= 0xFF;
b[14] ^= (b[27] + b[4] + b[33] + b[22] + b[43] + b[5] + 82) & 0xFF;
b[32] += b[38] + b[28] + b[42] + b[1] + b[35] + b[17] + 235;
b[32] &= 0xFF;
b[37] += b[29] + b[35] + b[20] + b[22] + b[43] + b[32] + 2;
b[37] &= 0xFF;
b[10] -= b[32] + b[39] + b[7] + b[21] + b[30] + b[1] + 90;
b[10] &= 0xFF;
b[17] ^= (b[21] + b[31] + b[9] + b[10] + b[1] + b[18] + 179) & 0xFF;
b[14] -= b[3] + b[12] + b[22] + b[19] + b[35] + b[38] + 115;
b[14] &= 0xFF;
b[33] ^= (b[27] + b[25] + b[4] + b[20] + b[16] + b[26] + 206) & 0xFF;
b[13] -= b[26] + b[37] + b[30] + b[27] + b[22] + b[32] + 167;
b[13] &= 0xFF;
b[31] ^= (b[38] + b[0] + b[11] + b[29] + b[4] + b[42] + 220) & 0xFF;
b[18] ^= (b[2] + b[41] + b[31] + b[4] + b[6] + b[13] + 157) & 0xFF;
b[27] -= b[16] + b[1] + b[25] + b[34] + b[21] + b[30] + 43;
b[27] &= 0xFF;
b[27] += b[13] + b[14] + b[35] + b[37] + b[23] + b[31] + 185;
b[27] &= 0xFF;
b[23] += b[38] + b[34] + b[9] + b[36] + b[1] + b[3] + 112;
b[23] &= 0xFF;
b[11] ^= (b[25] + b[18] + b[38] + b[35] + b[39] + b[34] + 134) & 0xFF;
b[30] ^= (b[14] + b[19] + b[24] + b[22] + b[6] + b[10] + 80) & 0xFF;
b[43] ^= (b[31] + b[10] + b[36] + b[24] + b[9] + b[27] + 11) & 0xFF;
b[3] ^= (b[18] + b[9] + b[2] + b[35] + b[34] + b[30] + 185) & 0xFF;
b[27] -= b[17] + b[28] + b[29] + b[2] + b[38] + b[9] + 9;
b[27] &= 0xFF;
b[17] -= b[20] + b[31] + b[1] + b[37] + b[32] + b[38] + 221;
b[17] &= 0xFF;
b[32] += b[10] + b[26] + b[4] + b[7] + b[43] + b[2] + 145;
b[32] &= 0xFF;
b[33] += b[34] + b[4] + b[21] + b[12] + b[8] + b[14] + 197;
b[33] &= 0xFF;
b[26] ^= (b[18] + b[21] + b[8] + b[28] + b[12] + b[15] + 98) & 0xFF;
b[11] += b[29] + b[21] + b[41] + b[30] + b[14] + b[23] + 20;
b[11] &= 0xFF;
b[9] += b[26] + b[20] + b[29] + b[25] + b[6] + b[12] + 183;
b[9] &= 0xFF;
b[17] += b[23] + b[10] + b[35] + b[3] + b[19] + b[22] + 140;
b[17] &= 0xFF;
b[1] += b[36] + b[10] + b[37] + b[29] + b[30] + b[12] + 2;
b[1] &= 0xFF;
b[22] += b[39] + b[27] + b[19] + b[9] + b[7] + b[1] + 84;
b[22] &= 0xFF;
b[28] += b[16] + b[25] + b[40] + b[23] + b[0] + b[24] + 198;
b[28] &= 0xFF;
b[21] ^= (b[12] + b[43] + b[41] + b[37] + b[11] + b[26] + 19) & 0xFF;
b[14] -= b[30] + b[33] + b[8] + b[1] + b[10] + b[26] + 203;
b[14] &= 0xFF;
b[25] += b[12] + b[27] + b[43] + b[10] + b[36] + b[24] + 15;
b[25] &= 0xFF;
b[38] -= b[25] + b[32] + b[36] + b[37] + b[26] + b[35] + 147;
b[38] &= 0xFF;
b[34] += b[42] + b[35] + b[11] + b[29] + b[22] + b[20] + 223;
b[34] &= 0xFF;
b[40] -= b[42] + b[17] + b[38] + b[14] + b[41] + b[30] + 197;
b[40] &= 0xFF;
b[0] ^= (b[41] + b[16] + b[15] + b[39] + b[18] + b[9] + 175) & 0xFF;
b[33] ^= (b[40] + b[20] + b[19] + b[16] + b[5] + b[37] + 240) & 0xFF;
b[3] ^= (b[28] + b[41] + b[27] + b[1] + b[15] + b[26] + 116) & 0xFF;
b[41] -= b[42] + b[29] + b[35] + b[11] + b[6] + b[34] + 83;
b[41] &= 0xFF;
b[12] -= b[4] + b[24] + b[1] + b[18] + b[40] + b[33] + 48;
b[12] &= 0xFF;
b[7] += b[1] + b[32] + b[35] + b[21] + b[23] + b[4] + 89;
b[7] &= 0xFF;
b[40] += b[16] + b[24] + b[12] + b[5] + b[26] + b[38] + 53;
b[40] &= 0xFF;
b[13] += b[12] + b[41] + b[29] + b[27] + b[7] + b[5] + 91;
b[13] &= 0xFF;
b[5] += b[30] + b[23] + b[6] + b[24] + b[15] + b[18] + 38;
b[5] &= 0xFF;
b[16] += b[42] + b[29] + b[25] + b[0] + b[12] + b[26] + 92;
b[16] &= 0xFF;
b[12] += b[7] + b[31] + b[37] + b[14] + b[29] + b[9] + 180;
b[12] &= 0xFF;
b[17] -= b[11] + b[32] + b[14] + b[16] + b[28] + b[9] + 167;
b[17] &= 0xFF;
b[33] += b[16] + b[29] + b[3] + b[37] + b[30] + b[41] + 204;
b[33] &= 0xFF;
b[18] ^= (b[9] + b[21] + b[4] + b[2] + b[42] + b[5] + 103) & 0xFF;
b[15] ^= (b[42] + b[21] + b[12] + b[34] + b[26] + b[22] + 30) & 0xFF;
b[4] ^= (b[16] + b[43] + b[41] + b[8] + b[3] + b[37] + 224) & 0xFF;
b[2] += b[26] + b[41] + b[35] + b[1] + b[18] + b[34] + 75;
b[2] &= 0xFF;
b[34] += b[32] + b[5] + b[20] + b[17] + b[15] + b[19] + 25;
b[34] &= 0xFF;
b[35] += b[6] + b[1] + b[37] + b[15] + b[40] + b[25] + 133;
b[35] &= 0xFF;
b[3] ^= (b[35] + b[2] + b[26] + b[24] + b[17] + b[14] + 66) & 0xFF;
b[24] -= b[22] + b[38] + b[33] + b[36] + b[15] + b[43] + 57;
b[24] &= 0xFF;
b[2] ^= (b[32] + b[25] + b[29] + b[23] + b[11] + b[7] + 58) & 0xFF;
b[10] += b[5] + b[31] + b[18] + b[9] + b[24] + b[27] + 246;
b[10] &= 0xFF;
b[6] += b[43] + b[36] + b[42] + b[4] + b[19] + b[24] + 91;
b[6] &= 0xFF;
b[37] ^= (b[39] + b[32] + b[40] + b[5] + b[41] + b[10] + 146) & 0xFF;
b[33] -= b[12] + b[5] + b[42] + b[2] + b[21] + b[15] + 201;
b[33] &= 0xFF;
b[15] ^= (b[12] + b[27] + b[32] + b[35] + b[40] + b[0] + 212) & 0xFF;
b[20] -= b[40] + b[10] + b[19] + b[24] + b[0] + b[11] + 147;
b[20] &= 0xFF;
b[25] -= b[33] + b[26] + b[2] + b[29] + b[17] + b[4] + 52;
b[25] &= 0xFF;
b[42] += b[43] + b[24] + b[7] + b[35] + b[30] + b[3] + 1;
b[42] &= 0xFF;
b[36] -= b[7] + b[21] + b[15] + b[29] + b[31] + b[2] + 130;
b[36] &= 0xFF;
b[11] += b[2] + b[6] + b[43] + b[25] + b[35] + b[26] + 210;
b[11] &= 0xFF;
b[34] -= b[33] + b[41] + b[11] + b[15] + b[32] + b[31] + 254;
b[34] &= 0xFF;
b[8] ^= (b[12] + b[10] + b[3] + b[2] + b[34] + b[31] + 203) & 0xFF;
b[12] ^= (b[7] + b[38] + b[20] + b[21] + b[1] + b[36] + 136) & 0xFF;
b[33] += b[34] + b[30] + b[39] + b[37] + b[13] + b[4] + 182;
b[33] &= 0xFF;
b[39] -= b[40] + b[2] + b[22] + b[25] + b[10] + b[13] + 94;
b[39] &= 0xFF;
b[1] ^= (b[25] + b[41] + b[12] + b[36] + b[34] + b[5] + 14) & 0xFF;
b[2] -= b[21] + b[30] + b[16] + b[41] + b[10] + b[11] + 235;
b[2] &= 0xFF;
b[9] -= b[33] + b[20] + b[43] + b[17] + b[15] + b[28] + 13;
b[9] &= 0xFF;
b[0] ^= (b[21] + b[1] + b[27] + b[17] + b[8] + b[31] + 92) & 0xFF;
b[27] ^= (b[19] + b[2] + b[40] + b[14] + b[9] + b[36] + 147) & 0xFF;
b[33] ^= (b[39] + b[12] + b[10] + b[18] + b[37] + b[15] + 22) & 0xFF;
b[35] ^= (b[19] + b[24] + b[39] + b[42] + b[28] + b[4] + 184) & 0xFF;
b[40] ^= (b[35] + b[22] + b[9] + b[31] + b[23] + b[12] + 7) & 0xFF;
b[25] -= b[37] + b[8] + b[39] + b[17] + b[9] + b[43] + 3;
b[25] &= 0xFF;
b[35] -= b[43] + b[23] + b[22] + b[33] + b[30] + b[0] + 147;
b[35] &= 0xFF;
b[39] -= b[43] + b[35] + b[4] + b[37] + b[9] + b[32] + 223;
b[39] &= 0xFF;
b[39] ^= (b[9] + b[18] + b[20] + b[15] + b[40] + b[10] + 175) & 0xFF;
b[25] ^= (b[9] + b[26] + b[29] + b[23] + b[35] + b[24] + 65) & 0xFF;
b[29] -= b[42] + b[12] + b[2] + b[24] + b[6] + b[39] + 200;
b[29] &= 0xFF;
b[36] += b[30] + b[3] + b[32] + b[37] + b[24] + b[18] + 148;
b[36] &= 0xFF;
b[34] ^= (b[12] + b[0] + b[35] + b[9] + b[38] + b[30] + 1) & 0xFF;
b[25] -= b[18] + b[32] + b[12] + b[2] + b[27] + b[8] + 127;
b[25] &= 0xFF;
b[23] ^= (b[11] + b[32] + b[35] + b[5] + b[10] + b[18] + 150) & 0xFF;
b[9] += b[5] + b[15] + b[19] + b[27] + b[17] + b[25] + 161;
b[9] &= 0xFF;
b[38] ^= (b[29] + b[9] + b[15] + b[33] + b[32] + b[3] + 187) & 0xFF;
b[43] -= b[36] + b[23] + b[15] + b[21] + b[32] + b[38] + 79;
b[43] &= 0xFF;
b[8] -= b[10] + b[36] + b[38] + b[20] + b[39] + b[41] + 105;
b[8] &= 0xFF;
b[34] ^= (b[9] + b[5] + b[31] + b[42] + b[1] + b[3] + 244) & 0xFF;
b[41] += b[33] + b[9] + b[34] + b[26] + b[3] + b[14] + 28;
b[41] &= 0xFF;
b[31] ^= (b[1] + b[16] + b[23] + b[25] + b[29] + b[4] + 2) & 0xFF;
b[42] -= b[23] + b[28] + b[39] + b[16] + b[17] + b[2] + 49;
b[42] &= 0xFF;
b[35] += b[37] + b[23] + b[18] + b[26] + b[20] + b[30] + 140;
b[35] &= 0xFF;
b[33] -= b[14] + b[35] + b[41] + b[0] + b[6] + b[8] + 45;
b[33] &= 0xFF;
b[10] ^= (b[3] + b[11] + b[8] + b[26] + b[36] + b[6] + 6) & 0xFF;
b[18] += b[22] + b[24] + b[25] + b[40] + b[27] + b[42] + 196;
b[18] &= 0xFF;
b[38] += b[10] + b[18] + b[39] + b[0] + b[35] + b[37] + 69;
b[38] &= 0xFF;
b[24] -= b[33] + b[37] + b[21] + b[1] + b[36] + b[12] + 29;
b[24] &= 0xFF;
b[22] ^= (b[29] + b[33] + b[20] + b[30] + b[0] + b[25] + 9) & 0xFF;
b[12] -= b[23] + b[2] + b[10] + b[5] + b[30] + b[27] + 195;
b[12] &= 0xFF;
b[22] ^= (b[6] + b[32] + b[27] + b[2] + b[13] + b[3] + 191) & 0xFF;
b[31] += b[42] + b[30] + b[1] + b[20] + b[40] + b[18] + 198;
b[31] &= 0xFF;
b[34] ^= (b[30] + b[6] + b[13] + b[35] + b[3] + b[26] + 241) & 0xFF;
b[39] ^= (b[1] + b[38] + b[10] + b[5] + b[23] + b[19] + 138) & 0xFF;
b[38] += b[2] + b[5] + b[24] + b[8] + b[11] + b[20] + 115;
b[38] &= 0xFF;
b[33] -= b[30] + b[12] + b[32] + b[34] + b[18] + b[40] + 2;
b[33] &= 0xFF;
b[13] += b[11] + b[41] + b[17] + b[6] + b[22] + b[8] + 130;
b[13] &= 0xFF;
b[33] += b[27] + b[9] + b[21] + b[38] + b[23] + b[5] + 150;
b[33] &= 0xFF;
b[5] += b[39] + b[18] + b[43] + b[8] + b[15] + b[14] + 95;
b[5] &= 0xFF;
b[6] -= b[10] + b[34] + b[17] + b[28] + b[26] + b[13] + 142;
b[6] &= 0xFF;
b[3] -= b[37] + b[33] + b[6] + b[19] + b[22] + b[21] + 15;
b[3] &= 0xFF;
b[11] ^= (b[40] + b[18] + b[21] + b[31] + b[5] + b[15] + 125) & 0xFF;
b[21] -= b[40] + b[1] + b[9] + b[38] + b[34] + b[25] + 186;
b[21] &= 0xFF;
b[15] ^= (b[20] + b[3] + b[36] + b[7] + b[9] + b[39] + 218) & 0xFF;
b[28] += b[12] + b[26] + b[3] + b[22] + b[41] + b[36] + 178;
b[28] &= 0xFF;
b[7] -= b[38] + b[42] + b[28] + b[6] + b[16] + b[25] + 127;
b[7] &= 0xFF;
b[39] ^= (b[30] + b[13] + b[42] + b[17] + b[37] + b[1] + 213) & 0xFF;
b[1] -= b[36] + b[28] + b[19] + b[30] + b[21] + b[17] + 98;
b[1] &= 0xFF;
b[41] ^= (b[5] + b[40] + b[39] + b[2] + b[3] + b[31] + 16) & 0xFF;
b[14] ^= (b[25] + b[4] + b[33] + b[9] + b[17] + b[0] + 221) & 0xFF;
b[34] += b[14] + b[10] + b[4] + b[29] + b[12] + b[30] + 205;
b[34] &= 0xFF;
b[27] -= b[41] + b[26] + b[11] + b[22] + b[17] + b[16] + 244;
b[27] &= 0xFF;
b[26] ^= (b[33] + b[15] + b[20] + b[37] + b[5] + b[36] + 78) & 0xFF;
b[25] += b[31] + b[36] + b[12] + b[5] + b[9] + b[3] + 94;
b[25] &= 0xFF;
b[32] -= b[4] + b[22] + b[25] + b[13] + b[27] + b[1] + 79;
b[32] &= 0xFF;
b[3] += b[5] + b[18] + b[10] + b[14] + b[43] + b[31] + 44;
b[3] &= 0xFF;
b[13] -= b[34] + b[1] + b[31] + b[15] + b[12] + b[8] + 206;
b[13] &= 0xFF;
b[11] += b[14] + b[0] + b[4] + b[20] + b[7] + b[27] + 253;
b[11] &= 0xFF;
b[21] += b[29] + b[3] + b[17] + b[22] + b[41] + b[18] + 133;
b[21] &= 0xFF;
b[9] += b[37] + b[41] + b[4] + b[20] + b[0] + b[18] + 175;
b[9] &= 0xFF;
b[41] ^= (b[2] + b[38] + b[5] + b[9] + b[23] + b[31] + 230) & 0xFF;
b[18] += b[19] + b[6] + b[15] + b[40] + b[3] + b[32] + 191;
b[18] &= 0xFF;
b[26] += b[8] + b[15] + b[16] + b[17] + b[39] + b[42] + 151;
b[26] &= 0xFF;
b[42] ^= (b[37] + b[35] + b[18] + b[36] + b[1] + b[14] + 95) & 0xFF;
b[40] ^= (b[10] + b[30] + b[6] + b[27] + b[39] + b[9] + 254) & 0xFF;
b[29] -= b[37] + b[9] + b[0] + b[16] + b[2] + b[28] + 203;
b[29] &= 0xFF;
b[23] += b[33] + b[15] + b[16] + b[41] + b[12] + b[25] + 182;
b[23] &= 0xFF;
b[20] ^= (b[40] + b[15] + b[25] + b[34] + b[19] + b[42] + 251) & 0xFF;
b[14] += b[20] + b[11] + b[21] + b[38] + b[28] + b[6] + 166;
b[14] &= 0xFF;
b[26] ^= (b[24] + b[7] + b[11] + b[12] + b[38] + b[3] + 20) & 0xFF;
b[12] ^= (b[5] + b[8] + b[25] + b[3] + b[7] + b[13] + 145) & 0xFF;
b[12] -= b[26] + b[30] + b[17] + b[32] + b[22] + b[43] + 72;
b[12] &= 0xFF;
b[19] ^= (b[8] + b[3] + b[22] + b[30] + b[26] + b[2] + 4) & 0xFF;
b[24] -= b[10] + b[39] + b[23] + b[28] + b[14] + b[2] + 121;
b[24] &= 0xFF;
b[26] -= b[18] + b[1] + b[32] + b[39] + b[0] + b[7] + 200;
b[26] &= 0xFF;
b[8] += b[41] + b[25] + b[32] + b[1] + b[15] + b[6] + 182;
b[8] &= 0xFF;
b[37] += b[8] + b[6] + b[10] + b[2] + b[36] + b[14] + 116;
b[37] &= 0xFF;
b[6] ^= (b[23] + b[13] + b[20] + b[11] + b[40] + b[16] + 23) & 0xFF;
b[41] -= b[17] + b[20] + b[19] + b[38] + b[18] + b[29] + 30;
b[41] &= 0xFF;
b[11] ^= (b[31] + b[20] + b[13] + b[27] + b[24] + b[21] + 114) & 0xFF;
b[41] += b[24] + b[30] + b[13] + b[23] + b[5] + b[17] + 64;
b[41] &= 0xFF;
b[34] ^= (b[19] + b[42] + b[22] + b[13] + b[8] + b[3] + 68) & 0xFF;
b[38] ^= (b[22] + b[36] + b[17] + b[14] + b[35] + b[25] + 55) & 0xFF;
b[4] += b[5] + b[28] + b[39] + b[15] + b[6] + b[3] + 154;
b[4] &= 0xFF;
b[34] -= b[4] + b[3] + b[43] + b[38] + b[23] + b[7] + 236;
b[34] &= 0xFF;
b[0] ^= (b[7] + b[11] + b[4] + b[23] + b[42] + b[14] + 73) & 0xFF;
b[9] += b[7] + b[19] + b[29] + b[30] + b[38] + b[13] + 60;
b[9] &= 0xFF;
b[40] ^= (b[13] + b[15] + b[22] + b[24] + b[43] + b[39] + 144) & 0xFF;
b[6] ^= (b[2] + b[9] + b[16] + b[5] + b[10] + b[12] + 37) & 0xFF;
b[30] ^= (b[23] + b[12] + b[3] + b[28] + b[2] + b[18] + 53) & 0xFF;
b[41] -= b[25] + b[0] + b[40] + b[8] + b[5] + b[26] + 80;
b[41] &= 0xFF;
b[39] ^= (b[41] + b[25] + b[43] + b[30] + b[11] + b[1] + 63) & 0xFF;
b[18] ^= (b[28] + b[23] + b[35] + b[29] + b[13] + b[24] + 57) & 0xFF;
b[21] -= b[16] + b[41] + b[5] + b[30] + b[20] + b[32] + 51;
b[21] &= 0xFF;
b[40] += b[39] + b[38] + b[24] + b[20] + b[1] + b[9] + 228;
b[40] &= 0xFF;
b[31] += b[29] + b[22] + b[15] + b[10] + b[36] + b[18] + 227;
b[31] &= 0xFF;
b[19] -= b[38] + b[31] + b[9] + b[35] + b[29] + b[39] + 51;
b[19] &= 0xFF;
b[35] ^= (b[1] + b[29] + b[25] + b[5] + b[16] + b[10] + 221) & 0xFF;
b[2] += b[39] + b[43] + b[38] + b[6] + b[18] + b[5] + 22;
b[2] &= 0xFF;
b[14] += b[6] + b[26] + b[3] + b[23] + b[17] + b[43] + 15;
b[14] &= 0xFF;
b[33] += b[18] + b[31] + b[4] + b[9] + b[35] + b[10] + 49;
b[33] &= 0xFF;
b[33] -= b[5] + b[41] + b[16] + b[32] + b[35] + b[36] + 200;
b[33] &= 0xFF;
b[22] ^= (b[32] + b[13] + b[42] + b[12] + b[33] + b[25] + 4) & 0xFF;
b[36] -= b[1] + b[33] + b[27] + b[20] + b[42] + b[17] + 173;
b[36] &= 0xFF;
b[32] ^= (b[28] + b[16] + b[41] + b[36] + b[22] + b[33] + 146) & 0xFF;
b[5] -= b[15] + b[33] + b[18] + b[20] + b[3] + b[22] + 88;
b[5] &= 0xFF;
b[10] ^= (b[18] + b[1] + b[20] + b[11] + b[31] + b[41] + 10) & 0xFF;
b[23] += b[3] + b[28] + b[4] + b[27] + b[25] + b[10] + 21;
b[23] &= 0xFF;
b[36] ^= (b[28] + b[6] + b[34] + b[21] + b[41] + b[35] + 245) & 0xFF;
b[22] += b[3] + b[21] + b[6] + b[18] + b[43] + b[0] + 13;
b[22] &= 0xFF;
b[30] -= b[33] + b[40] + b[38] + b[19] + b[36] + b[16] + 196;
b[30] &= 0xFF;
b[7] ^= (b[19] + b[3] + b[16] + b[1] + b[34] + b[33] + 110) & 0xFF;
b[37] += b[10] + b[15] + b[41] + b[36] + b[1] + b[38] + 181;
b[37] &= 0xFF;
b[31] -= b[29] + b[40] + b[13] + b[24] + b[43] + b[30] + 59;
b[31] &= 0xFF;
b[35] ^= (b[12] + b[18] + b[39] + b[0] + b[10] + b[3] + 148) & 0xFF;
b[15] ^= (b[1] + b[17] + b[43] + b[19] + b[11] + b[39] + 153) & 0xFF;
b[4] ^= (b[36] + b[42] + b[22] + b[20] + b[15] + b[0] + 219) & 0xFF;
b[13] -= b[27] + b[28] + b[15] + b[40] + b[14] + b[8] + 70;
b[13] &= 0xFF;
b[22] += b[43] + b[18] + b[23] + b[42] + b[17] + b[33] + 225;
b[22] &= 0xFF;
b[21] -= b[8] + b[30] + b[13] + b[22] + b[0] + b[5] + 34;
b[21] &= 0xFF;
b[23] += b[0] + b[25] + b[10] + b[26] + b[38] + b[24] + 236;
b[23] &= 0xFF;
b[27] += b[29] + b[16] + b[33] + b[18] + b[19] + b[35] + 222;
b[27] &= 0xFF;
b[32] += b[40] + b[41] + b[19] + b[7] + b[36] + b[18] + 29;
b[32] &= 0xFF;
b[36] -= b[8] + b[7] + b[27] + b[43] + b[24] + b[15] + 174;
b[36] &= 0xFF;
b[40] -= b[13] + b[21] + b[8] + b[3] + b[10] + b[17] + 248;
b[40] &= 0xFF;
b[9] ^= (b[27] + b[15] + b[21] + b[36] + b[29] + b[25] + 178) & 0xFF;
b[3] -= b[8] + b[40] + b[10] + b[39] + b[16] + b[28] + 98;
b[3] &= 0xFF;
b[38] += b[1] + b[8] + b[31] + b[39] + b[7] + b[18] + 150;
b[38] &= 0xFF;
b[6] -= b[30] + b[21] + b[2] + b[19] + b[35] + b[20] + 249;
b[6] &= 0xFF;
b[15] -= b[13] + b[42] + b[32] + b[39] + b[34] + b[28] + 116;
b[15] &= 0xFF;
b[27] -= b[14] + b[28] + b[34] + b[16] + b[41] + b[31] + 225;
b[27] &= 0xFF;
b[29] ^= (b[31] + b[38] + b[2] + b[43] + b[15] + b[33] + 61) & 0xFF;
b[37] += b[18] + b[29] + b[11] + b[28] + b[13] + b[3] + 248;
b[37] &= 0xFF;
b[19] += b[9] + b[41] + b[42] + b[31] + b[32] + b[15] + 14;
b[19] &= 0xFF;
b[35] += b[13] + b[21] + b[32] + b[1] + b[10] + b[43] + 148;
b[35] &= 0xFF;
b[10] += b[24] + b[28] + b[12] + b[3] + b[34] + b[8] + 83;
b[10] &= 0xFF;
b[24] ^= (b[39] + b[38] + b[0] + b[20] + b[5] + b[10] + 158) & 0xFF;
b[0] ^= (b[6] + b[24] + b[12] + b[35] + b[18] + b[20] + 222) & 0xFF;
b[16] ^= (b[11] + b[33] + b[22] + b[7] + b[0] + b[29] + 8) & 0xFF;
b[5] -= b[39] + b[26] + b[32] + b[13] + b[40] + b[31] + 242;
b[5] &= 0xFF;
b[8] ^= (b[33] + b[18] + b[35] + b[41] + b[39] + b[36] + 142) & 0xFF;
b[15] += b[28] + b[16] + b[1] + b[8] + b[3] + b[19] + 5;
b[15] &= 0xFF;
b[19] -= b[36] + b[41] + b[40] + b[24] + b[33] + b[10] + 138;
b[19] &= 0xFF;
b[1] -= b[12] + b[17] + b[2] + b[36] + b[4] + b[35] + 13;
b[1] &= 0xFF;
b[6] ^= (b[41] + b[28] + b[20] + b[36] + b[40] + b[13] + 212) & 0xFF;
b[25] += b[16] + b[21] + b[28] + b[35] + b[14] + b[37] + 212;
b[25] &= 0xFF;
b[38] += b[4] + b[29] + b[22] + b[2] + b[14] + b[37] + 224;
b[38] &= 0xFF;
b[1] ^= (b[21] + b[5] + b[27] + b[36] + b[9] + b[23] + 51) & 0xFF;
b[16] -= b[39] + b[1] + b[19] + b[10] + b[14] + b[26] + 225;
b[16] &= 0xFF;
b[18] -= b[10] + b[5] + b[25] + b[35] + b[34] + b[20] + 228;
b[18] &= 0xFF;
b[25] ^= (b[29] + b[41] + b[32] + b[27] + b[3] + b[33] + 34) & 0xFF;
b[8] -= b[4] + b[19] + b[32] + b[43] + b[16] + b[27] + 75;
b[8] &= 0xFF;
b[3] -= b[31] + b[37] + b[34] + b[25] + b[11] + b[13] + 6;
b[3] &= 0xFF;
b[6] += b[36] + b[29] + b[27] + b[23] + b[3] + b[19] + 190;
b[6] &= 0xFF;
b[20] += b[7] + b[37] + b[5] + b[0] + b[34] + b[17] + 57;
b[20] &= 0xFF;
b[1] += b[20] + b[2] + b[25] + b[31] + b[4] + b[18] + 7;
b[1] &= 0xFF;
b[34] -= b[5] + b[10] + b[15] + b[2] + b[25] + b[26] + 41;
b[34] &= 0xFF;
b[23] ^= (b[17] + b[16] + b[3] + b[30] + b[24] + b[43] + 7) & 0xFF;
b[35] ^= (b[4] + b[0] + b[29] + b[18] + b[28] + b[22] + 218) & 0xFF;
b[40] -= b[2] + b[17] + b[26] + b[8] + b[24] + b[23] + 239;
b[40] &= 0xFF;
b[21] ^= (b[36] + b[31] + b[1] + b[20] + b[43] + b[17] + 224) & 0xFF;
b[12] -= b[18] + b[2] + b[17] + b[7] + b[41] + b[32] + 165;
b[12] &= 0xFF;
b[3] ^= (b[13] + b[29] + b[8] + b[11] + b[38] + b[21] + 140) & 0xFF;
b[14] += b[24] + b[26] + b[11] + b[19] + b[6] + b[17] + 150;
b[14] &= 0xFF;
b[38] -= b[15] + b[13] + b[3] + b[22] + b[34] + b[12] + 184;
b[38] &= 0xFF;
b[14] -= b[35] + b[20] + b[10] + b[4] + b[16] + b[28] + 173;
b[14] &= 0xFF;
b[39] += b[18] + b[27] + b[15] + b[20] + b[28] + b[9] + 242;
b[39] &= 0xFF;
b[8] += b[36] + b[38] + b[6] + b[33] + b[27] + b[32] + 188;
b[8] &= 0xFF;
b[6] += b[17] + b[7] + b[32] + b[39] + b[31] + b[14] + 1;
b[6] &= 0xFF;
b[34] += b[37] + b[2] + b[43] + b[28] + b[16] + b[30] + 214;
b[34] &= 0xFF;
b[34] -= b[28] + b[8] + b[13] + b[16] + b[24] + b[1] + 237;
b[34] &= 0xFF;
b[36] -= b[5] + b[41] + b[23] + b[27] + b[16] + b[31] + 110;
b[36] &= 0xFF;
b[4] -= b[8] + b[24] + b[29] + b[30] + b[41] + b[43] + 121;
b[4] &= 0xFF;
b[31] -= b[39] + b[35] + b[34] + b[43] + b[38] + b[20] + 173;
b[31] &= 0xFF;
b[16] += b[13] + b[41] + b[6] + b[3] + b[29] + b[39] + 206;
b[16] &= 0xFF;
b[9] += b[31] + b[37] + b[29] + b[27] + b[11] + b[13] + 216;
b[9] &= 0xFF;
b[24] -= b[43] + b[5] + b[36] + b[9] + b[30] + b[3] + 160;
b[24] &= 0xFF;
b[24] ^= (b[23] + b[19] + b[1] + b[13] + b[3] + b[2] + 245) & 0xFF;
b[3] -= b[31] + b[37] + b[33] + b[7] + b[23] + b[32] + 157;
b[3] &= 0xFF;
b[27] -= b[21] + b[18] + b[38] + b[1] + b[40] + b[12] + 174;
b[27] &= 0xFF;
b[22] += b[41] + b[28] + b[25] + b[26] + b[0] + b[23] + 162;
b[22] &= 0xFF;
b[18] += b[17] + b[43] + b[26] + b[10] + b[30] + b[16] + 6;
b[18] &= 0xFF;
b[4] += b[29] + b[33] + b[34] + b[20] + b[9] + b[17] + 77;
b[4] &= 0xFF;
b[21] ^= (b[30] + b[4] + b[41] + b[6] + b[22] + b[9] + 224) & 0xFF;
b[3] -= b[29] + b[14] + b[12] + b[39] + b[32] + b[28] + 145;
b[3] &= 0xFF;
b[27] ^= (b[25] + b[29] + b[34] + b[13] + b[41] + b[5] + 145) & 0xFF;
b[39] ^= (b[11] + b[23] + b[31] + b[20] + b[42] + b[30] + 94) & 0xFF;
b[4] -= b[11] + b[36] + b[40] + b[38] + b[16] + b[6] + 149;
b[4] &= 0xFF;
b[11] += b[5] + b[30] + b[23] + b[35] + b[26] + b[41] + 80;
b[11] &= 0xFF;
b[27] -= b[43] + b[35] + b[6] + b[22] + b[12] + b[42] + 49;
b[27] &= 0xFF;
b[33] += b[17] + b[7] + b[26] + b[18] + b[36] + b[11] + 113;
b[33] &= 0xFF;
b[35] += b[30] + b[7] + b[3] + b[40] + b[20] + b[34] + 255;
b[35] &= 0xFF;
b[29] ^= (b[34] + b[20] + b[30] + b[35] + b[8] + b[5] + 90) & 0xFF;
b[3] -= b[13] + b[30] + b[9] + b[28] + b[32] + b[38] + 241;
b[3] &= 0xFF;
b[18] -= b[14] + b[23] + b[13] + b[37] + b[20] + b[32] + 70;
b[18] &= 0xFF;
b[29] += b[13] + b[1] + b[28] + b[14] + b[41] + b[26] + 3;
b[29] &= 0xFF;
b[8] -= b[40] + b[12] + b[41] + b[20] + b[5] + b[30] + 146;
b[8] &= 0xFF;
b[3] ^= (b[19] + b[31] + b[1] + b[26] + b[6] + b[36] + 149) & 0xFF;
b[0] -= b[43] + b[42] + b[30] + b[40] + b[11] + b[29] + 98;
b[0] &= 0xFF;
b[23] += b[18] + b[1] + b[38] + b[22] + b[20] + b[4] + 124;
b[23] &= 0xFF;
b[7] -= b[30] + b[35] + b[16] + b[23] + b[40] + b[22] + 160;
b[7] &= 0xFF;
b[38] += b[22] + b[26] + b[9] + b[29] + b[40] + b[1] + 10;
b[38] &= 0xFF;
b[7] -= b[41] + b[40] + b[13] + b[19] + b[17] + b[38] + 45;
b[7] &= 0xFF;
b[7] -= b[11] + b[43] + b[13] + b[8] + b[19] + b[23] + 19;
b[7] &= 0xFF;
b[26] += b[9] + b[2] + b[43] + b[10] + b[18] + b[11] + 190;
b[26] &= 0xFF;
b[33] += b[21] + b[13] + b[25] + b[29] + b[36] + b[18] + 139;
b[33] &= 0xFF;
b[38] ^= (b[6] + b[42] + b[15] + b[31] + b[36] + b[7] + 155) & 0xFF;
b[34] += b[11] + b[6] + b[35] + b[15] + b[36] + b[21] + 159;
b[34] &= 0xFF;
b[17] ^= (b[10] + b[0] + b[43] + b[36] + b[26] + b[33] + 175) & 0xFF;
b[32] += b[22] + b[25] + b[2] + b[43] + b[37] + b[28] + 77;
b[32] &= 0xFF;
b[4] += b[23] + b[19] + b[28] + b[41] + b[31] + b[43] + 205;
b[4] &= 0xFF;
b[14] -= b[24] + b[16] + b[41] + b[28] + b[34] + b[5] + 255;
b[14] &= 0xFF;
b[43] += b[1] + b[24] + b[31] + b[29] + b[35] + b[42] + 3;
b[43] &= 0xFF;
b[25] -= b[11] + b[17] + b[34] + b[36] + b[4] + b[41] + 109;
b[25] &= 0xFF;
b[6] -= b[11] + b[8] + b[37] + b[39] + b[12] + b[33] + 185;
b[6] &= 0xFF;
b[27] += b[16] + b[5] + b[12] + b[2] + b[43] + b[20] + 84;
b[27] &= 0xFF;
b[9] += b[41] + b[31] + b[7] + b[36] + b[20] + b[42] + 182;
b[9] &= 0xFF;
b[1] -= b[27] + b[6] + b[10] + b[23] + b[35] + b[22] + 110;
b[1] &= 0xFF;
b[27] += b[13] + b[37] + b[23] + b[17] + b[2] + b[43] + 254;
b[27] &= 0xFF;
b[28] += b[40] + b[23] + b[19] + b[20] + b[13] + b[43] + 220;
b[28] &= 0xFF;
b[9] += b[38] + b[29] + b[25] + b[2] + b[32] + b[21] + 73;
b[9] &= 0xFF;
b[8] += b[30] + b[19] + b[3] + b[13] + b[35] + b[18] + 222;
b[8] &= 0xFF;
b[18] ^= (b[36] + b[26] + b[27] + b[7] + b[14] + b[15] + 22) & 0xFF;
b[8] ^= (b[33] + b[32] + b[39] + b[12] + b[20] + b[7] + 34) & 0xFF;
b[13] += b[25] + b[26] + b[22] + b[15] + b[19] + b[14] + 68;
b[13] &= 0xFF;
b[19] ^= (b[12] + b[1] + b[34] + b[8] + b[4] + b[37] + 22) & 0xFF;
b[18] += b[41] + b[12] + b[19] + b[4] + b[9] + b[21] + 22;
b[18] &= 0xFF;
b[20] += b[21] + b[0] + b[32] + b[13] + b[8] + b[11] + 37;
b[20] &= 0xFF;
b[33] ^= (b[39] + b[15] + b[37] + b[20] + b[5] + b[29] + 42) & 0xFF;
b[24] ^= (b[29] + b[39] + b[20] + b[38] + b[37] + b[10] + 148) & 0xFF;
b[11] ^= (b[24] + b[26] + b[20] + b[28] + b[15] + b[35] + 7) & 0xFF;
b[26] += b[16] + b[36] + b[33] + b[2] + b[13] + b[20] + 17;
b[26] &= 0xFF;
b[13] ^= (b[32] + b[35] + b[10] + b[16] + b[40] + b[22] + 187) & 0xFF;
b[27] -= b[7] + b[1] + b[42] + b[29] + b[32] + b[16] + 128;
b[27] &= 0xFF;
b[15] ^= (b[36] + b[23] + b[31] + b[0] + b[20] + b[5] + 20) & 0xFF;
b[37] -= b[3] + b[31] + b[12] + b[28] + b[41] + b[2] + 222;
b[37] &= 0xFF;
b[25] -= b[2] + b[19] + b[29] + b[3] + b[14] + b[40] + 151;
b[25] &= 0xFF;
b[8] += b[1] + b[25] + b[39] + b[34] + b[24] + b[9] + 172;
b[8] &= 0xFF;
b[2] ^= (b[29] + b[1] + b[26] + b[42] + b[12] + b[10] + 81) & 0xFF;
b[24] ^= (b[8] + b[30] + b[3] + b[41] + b[36] + b[7] + 136) & 0xFF;
b[25] ^= (b[43] + b[5] + b[32] + b[38] + b[35] + b[21] + 32) & 0xFF;
b[30] ^= (b[27] + b[40] + b[17] + b[43] + b[16] + b[6] + 73) & 0xFF;
b[24] += b[39] + b[14] + b[18] + b[36] + b[15] + b[27] + 142;
b[24] &= 0xFF;
b[8] += b[3] + b[20] + b[16] + b[17] + b[22] + b[24] + 15;
b[8] &= 0xFF;
b[17] ^= (b[20] + b[32] + b[10] + b[38] + b[24] + b[29] + 57) & 0xFF;
b[25] -= b[17] + b[0] + b[37] + b[39] + b[11] + b[28] + 228;
b[25] &= 0xFF;
b[32] ^= (b[18] + b[11] + b[42] + b[1] + b[27] + b[14] + 241) & 0xFF;
b[40] += b[12] + b[8] + b[31] + b[28] + b[4] + b[2] + 26;
b[40] &= 0xFF;
b[16] ^= (b[13] + b[41] + b[3] + b[40] + b[8] + b[14] + 17) & 0xFF;
b[43] += b[26] + b[3] + b[25] + b[0] + b[31] + b[21] + 81;
b[43] &= 0xFF;
b[31] += b[13] + b[16] + b[43] + b[33] + b[35] + b[41] + 129;
b[31] &= 0xFF;
b[38] -= b[14] + b[3] + b[35] + b[40] + b[6] + b[5] + 122;
b[38] &= 0xFF;
b[17] += b[3] + b[13] + b[37] + b[25] + b[8] + b[0] + 53;
b[17] &= 0xFF;
b[39] -= b[8] + b[14] + b[41] + b[13] + b[15] + b[33] + 164;
b[39] &= 0xFF;
b[29] += b[43] + b[39] + b[38] + b[26] + b[28] + b[17] + 103;
b[29] &= 0xFF;
b[25] -= b[31] + b[7] + b[30] + b[38] + b[39] + b[29] + 174;
b[25] &= 0xFF;
b[38] -= b[24] + b[23] + b[36] + b[32] + b[7] + b[2] + 136;
b[38] &= 0xFF;
b[4] -= b[42] + b[6] + b[26] + b[39] + b[35] + b[16] + 80;
b[4] &= 0xFF;
b[19] ^= (b[13] + b[36] + b[38] + b[1] + b[2] + b[24] + 210) & 0xFF;
b[6] += b[24] + b[36] + b[43] + b[29] + b[16] + b[10] + 182;
b[6] &= 0xFF;
b[20] ^= (b[28] + b[7] + b[15] + b[3] + b[12] + b[19] + 246) & 0xFF;
b[30] ^= (b[17] + b[15] + b[18] + b[43] + b[29] + b[16] + 27) & 0xFF;
b[27] ^= (b[6] + b[24] + b[16] + b[19] + b[13] + b[14] + 35) & 0xFF;
b[4] += b[34] + b[7] + b[2] + b[39] + b[5] + b[43] + 139;
b[4] &= 0xFF;
b[39] += b[27] + b[20] + b[15] + b[29] + b[36] + b[16] + 196;
b[39] &= 0xFF;
b[7] += b[6] + b[35] + b[1] + b[40] + b[36] + b[33] + 95;
b[7] &= 0xFF;
b[27] -= b[1] + b[26] + b[10] + b[29] + b[14] + b[4] + 32;
b[27] &= 0xFF;
b[8] ^= (b[13] + b[26] + b[10] + b[4] + b[32] + b[21] + 142) & 0xFF;
b[20] ^= (b[24] + b[32] + b[29] + b[9] + b[6] + b[35] + 217) & 0xFF;
b[32] += b[42] + b[43] + b[34] + b[17] + b[5] + b[0] + 94;
b[32] &= 0xFF;
b[19] ^= (b[3] + b[6] + b[5] + b[33] + b[32] + b[10] + 194) & 0xFF;
b[0] ^= (b[20] + b[18] + b[34] + b[43] + b[26] + b[2] + 224) & 0xFF;
b[42] ^= (b[14] + b[6] + b[29] + b[16] + b[10] + b[43] + 254) & 0xFF;
b[42] ^= (b[13] + b[2] + b[20] + b[16] + b[6] + b[34] + 159) & 0xFF;
b[14] ^= (b[41] + b[5] + b[40] + b[33] + b[35] + b[10] + 94) & 0xFF;
b[22] ^= (b[0] + b[36] + b[28] + b[14] + b[4] + b[18] + 25) & 0xFF;
b[11] ^= (b[36] + b[0] + b[6] + b[21] + b[32] + b[18] + 134) & 0xFF;
b[8] += b[13] + b[4] + b[36] + b[28] + b[17] + b[39] + 118;
b[8] &= 0xFF;
b[32] -= b[4] + b[35] + b[22] + b[40] + b[28] + b[39] + 46;
b[32] &= 0xFF;
b[31] -= b[22] + b[41] + b[24] + b[34] + b[3] + b[37] + 95;
b[31] &= 0xFF;
b[19] ^= (b[26] + b[28] + b[24] + b[20] + b[29] + b[30] + 198) & 0xFF;
b[5] += b[6] + b[36] + b[20] + b[33] + b[23] + b[26] + 186;
b[5] &= 0xFF;
b[22] -= b[33] + b[18] + b[11] + b[27] + b[41] + b[31] + 208;
b[22] &= 0xFF;
b[26] += b[16] + b[38] + b[12] + b[25] + b[24] + b[0] + 68;
b[26] &= 0xFF;
b[38] += b[4] + b[32] + b[6] + b[26] + b[25] + b[22] + 44;
b[38] &= 0xFF;
b[14] ^= (b[32] + b[30] + b[20] + b[11] + b[3] + b[41] + 154) & 0xFF;
b[40] -= b[21] + b[3] + b[14] + b[13] + b[20] + b[5] + 5;
b[40] &= 0xFF;
b[31] ^= (b[26] + b[43] + b[7] + b[37] + b[25] + b[34] + 192) & 0xFF;
b[6] += b[4] + b[40] + b[15] + b[37] + b[12] + b[23] + 160;
b[6] &= 0xFF;
b[31] += b[21] + b[35] + b[22] + b[17] + b[7] + b[0] + 20;
b[31] &= 0xFF;
b[13] ^= (b[14] + b[35] + b[22] + b[4] + b[23] + b[20] + 101) & 0xFF;
b[31] ^= (b[28] + b[32] + b[14] + b[26] + b[18] + b[35] + 246) & 0xFF;
b[34] ^= (b[23] + b[28] + b[8] + b[20] + b[33] + b[5] + 71) & 0xFF;
b[2] ^= (b[8] + b[28] + b[29] + b[26] + b[37] + b[39] + 54) & 0xFF;
b[21] += b[1] + b[30] + b[36] + b[43] + b[3] + b[25] + 219;
b[21] &= 0xFF;
b[26] -= b[23] + b[16] + b[41] + b[7] + b[27] + b[18] + 119;
b[26] &= 0xFF;
b[33] += b[11] + b[10] + b[29] + b[31] + b[42] + b[1] + 145;
b[33] &= 0xFF;
b[28] += b[40] + b[23] + b[20] + b[36] + b[22] + b[27] + 232;
b[28] &= 0xFF;
b[43] += b[11] + b[15] + b[33] + b[35] + b[21] + b[25] + 197;
b[43] &= 0xFF;
b[32] ^= (b[16] + b[4] + b[23] + b[8] + b[41] + b[29] + 142) & 0xFF;
b[33] -= b[16] + b[13] + b[1] + b[29] + b[30] + b[40] + 77;
b[33] &= 0xFF;
b[20] += b[3] + b[12] + b[40] + b[43] + b[15] + b[28] + 205;
b[20] &= 0xFF;
b[24] ^= (b[14] + b[33] + b[2] + b[26] + b[19] + b[8] + 75) & 0xFF;
b[37] -= b[30] + b[21] + b[35] + b[13] + b[19] + b[26] + 208;
b[37] &= 0xFF;
b[25] += b[40] + b[2] + b[18] + b[35] + b[15] + b[32] + 16;
b[25] &= 0xFF;
b[8] -= b[12] + b[6] + b[1] + b[21] + b[28] + b[25] + 55;
b[8] &= 0xFF;
b[30] ^= (b[29] + b[4] + b[10] + b[40] + b[7] + b[9] + 189) & 0xFF;
b[4] -= b[38] + b[0] + b[13] + b[16] + b[3] + b[18] + 170;
b[4] &= 0xFF;
b[25] += b[10] + b[31] + b[30] + b[21] + b[3] + b[40] + 227;
b[25] &= 0xFF;
b[4] -= b[1] + b[17] + b[0] + b[15] + b[19] + b[41] + 192;
b[4] &= 0xFF;
b[8] += b[30] + b[1] + b[37] + b[6] + b[26] + b[10] + 198;
b[8] &= 0xFF;
b[20] -= b[19] + b[7] + b[11] + b[33] + b[18] + b[1] + 177;
b[20] &= 0xFF;
b[11] -= b[6] + b[19] + b[33] + b[43] + b[3] + b[21] + 60;
b[11] &= 0xFF;
b[31] += b[4] + b[21] + b[19] + b[27] + b[37] + b[33] + 251;
b[31] &= 0xFF;
b[10] -= b[9] + b[32] + b[42] + b[41] + b[21] + b[8] + 100;
b[10] &= 0xFF;
b[20] += b[34] + b[25] + b[10] + b[3] + b[31] + b[37] + 136;
b[20] &= 0xFF;
b[1] -= b[37] + b[40] + b[30] + b[6] + b[38] + b[19] + 192;
b[1] &= 0xFF;
b[34] -= b[15] + b[29] + b[5] + b[2] + b[39] + b[0] + 153;
b[34] &= 0xFF;
b[10] -= b[23] + b[32] + b[37] + b[28] + b[39] + b[21] + 233;
b[10] &= 0xFF;
b[4] += b[8] + b[13] + b[3] + b[34] + b[22] + b[14] + 246;
b[4] &= 0xFF;
b[36] += b[6] + b[21] + b[18] + b[31] + b[15] + b[7] + 176;
b[36] &= 0xFF;
b[42] += b[43] + b[7] + b[18] + b[20] + b[2] + b[9] + 43;
b[42] &= 0xFF;
b[24] ^= (b[38] + b[40] + b[42] + b[25] + b[13] + b[43] + 64) & 0xFF;
b[11] ^= (b[5] + b[20] + b[14] + b[28] + b[42] + b[22] + 149) & 0xFF;
b[1] -= b[20] + b[32] + b[25] + b[35] + b[10] + b[18] + 147;
b[1] &= 0xFF;
b[27] += b[17] + b[7] + b[0] + b[1] + b[34] + b[14] + 128;
b[27] &= 0xFF;
b[12] -= b[1] + b[33] + b[11] + b[10] + b[37] + b[8] + 155;
b[12] &= 0xFF;
b[6] ^= (b[24] + b[19] + b[12] + b[10] + b[8] + b[34] + 3) & 0xFF;
b[33] += b[40] + b[17] + b[43] + b[21] + b[36] + b[23] + 76;
b[33] &= 0xFF;
b[10] += b[9] + b[39] + b[6] + b[32] + b[11] + b[35] + 18;
b[10] &= 0xFF;
b[10] -= b[25] + b[0] + b[28] + b[35] + b[5] + b[30] + 240;
b[10] &= 0xFF;
b[21] -= b[4] + b[31] + b[25] + b[22] + b[2] + b[3] + 237;
b[21] &= 0xFF;
b[28] ^= (b[13] + b[9] + b[35] + b[23] + b[18] + b[39] + 117) & 0xFF;
b[22] += b[37] + b[26] + b[14] + b[41] + b[30] + b[6] + 248;
b[22] &= 0xFF;
b[34] += b[30] + b[17] + b[38] + b[41] + b[5] + b[42] + 170;
b[34] &= 0xFF;
b[22] -= b[13] + b[6] + b[1] + b[23] + b[43] + b[32] + 120;
b[22] &= 0xFF;
b[0] += b[17] + b[10] + b[16] + b[38] + b[22] + b[15] + 112;
b[0] &= 0xFF;
b[0] ^= (b[21] + b[10] + b[29] + b[30] + b[13] + b[17] + 60) & 0xFF;
b[23] += b[36] + b[26] + b[8] + b[4] + b[10] + b[7] + 147;
b[23] &= 0xFF;
b[32] ^= (b[41] + b[30] + b[5] + b[23] + b[28] + b[39] + 217) & 0xFF;
b[0] -= b[34] + b[3] + b[41] + b[28] + b[29] + b[36] + 187;
b[0] &= 0xFF;
b[0] ^= (b[26] + b[4] + b[34] + b[16] + b[15] + b[7] + 115) & 0xFF;
b[43] ^= (b[11] + b[17] + b[36] + b[26] + b[30] + b[8] + 200) & 0xFF;
b[5] -= b[31] + b[43] + b[1] + b[8] + b[6] + b[41] + 246;
b[5] &= 0xFF;
b[30] ^= (b[43] + b[38] + b[12] + b[33] + b[34] + b[11] + 8) & 0xFF;
b[21] ^= (b[5] + b[27] + b[17] + b[2] + b[9] + b[6] + 122) & 0xFF;
b[16] += b[30] + b[0] + b[3] + b[34] + b[15] + b[21] + 26;
b[16] &= 0xFF;
b[14] -= b[35] + b[18] + b[2] + b[22] + b[33] + b[25] + 213;
b[14] &= 0xFF;
b[3] -= b[26] + b[35] + b[23] + b[36] + b[10] + b[5] + 33;
b[3] &= 0xFF;
b[12] += b[40] + b[9] + b[38] + b[37] + b[36] + b[31] + 169;
b[12] &= 0xFF;
b[42] += b[36] + b[41] + b[12] + b[21] + b[19] + b[23] + 89;
b[42] &= 0xFF;
b[0] += b[39] + b[5] + b[14] + b[43] + b[25] + b[36] + 164;
b[0] &= 0xFF;
b[30] ^= (b[16] + b[40] + b[42] + b[32] + b[2] + b[41] + 149) & 0xFF;
b[22] -= b[1] + b[40] + b[13] + b[17] + b[38] + b[20] + 151;
b[22] &= 0xFF;
b[23] += b[15] + b[32] + b[35] + b[0] + b[8] + b[22] + 146;
b[23] &= 0xFF;
b[26] -= b[31] + b[22] + b[40] + b[23] + b[4] + b[25] + 15;
b[26] &= 0xFF;
b[28] ^= (b[23] + b[19] + b[38] + b[31] + b[32] + b[18] + 118) & 0xFF;
b[7] += b[4] + b[34] + b[24] + b[30] + b[35] + b[20] + 225;
b[7] &= 0xFF;
b[12] -= b[8] + b[0] + b[3] + b[24] + b[33] + b[42] + 152;
b[12] &= 0xFF;
b[31] -= b[33] + b[6] + b[1] + b[29] + b[23] + b[4] + 89;
b[31] &= 0xFF;
b[23] += b[30] + b[6] + b[10] + b[40] + b[15] + b[37] + 35;
b[23] &= 0xFF;
b[25] -= b[20] + b[5] + b[21] + b[22] + b[17] + b[1] + 130;
b[25] &= 0xFF;
b[6] -= b[16] + b[25] + b[36] + b[40] + b[31] + b[5] + 50;
b[6] &= 0xFF;
b[42] -= b[24] + b[9] + b[29] + b[41] + b[23] + b[33] + 28;
b[42] &= 0xFF;
b[2] -= b[10] + b[36] + b[13] + b[22] + b[27] + b[14] + 61;
b[2] &= 0xFF;
b[1] -= b[32] + b[42] + b[41] + b[33] + b[39] + b[28] + 75;
b[1] &= 0xFF;
b[37] ^= (b[33] + b[7] + b[1] + b[35] + b[36] + b[19] + 206) & 0xFF;
b[11] -= b[24] + b[9] + b[13] + b[33] + b[39] + b[22] + 116;
b[11] &= 0xFF;
b[14] += b[39] + b[4] + b[25] + b[27] + b[35] + b[7] + 0;
b[14] &= 0xFF;
b[32] ^= (b[4] + b[14] + b[43] + b[42] + b[9] + b[27] + 187) & 0xFF;
b[39] -= b[30] + b[27] + b[6] + b[31] + b[13] + b[42] + 106;
b[39] &= 0xFF;
b[22] -= b[29] + b[7] + b[32] + b[34] + b[4] + b[36] + 113;
b[22] &= 0xFF;
b[17] -= b[2] + b[34] + b[10] + b[20] + b[13] + b[37] + 205;
b[17] &= 0xFF;
b[21] -= b[31] + b[13] + b[2] + b[15] + b[34] + b[37] + 41;
b[21] &= 0xFF;
b[13] += b[14] + b[35] + b[43] + b[3] + b[16] + b[31] + 210;
b[13] &= 0xFF;
b[35] ^= (b[37] + b[43] + b[27] + b[22] + b[31] + b[15] + 150) & 0xFF;
b[3] ^= (b[17] + b[22] + b[20] + b[7] + b[12] + b[14] + 152) & 0xFF;
b[11] ^= (b[30] + b[38] + b[6] + b[22] + b[3] + b[18] + 218) & 0xFF;
b[7] ^= (b[16] + b[24] + b[28] + b[32] + b[4] + b[5] + 246) & 0xFF;
b[35] ^= (b[24] + b[43] + b[21] + b[2] + b[34] + b[40] + 28) & 0xFF;
b[5] += b[25] + b[38] + b[18] + b[34] + b[24] + b[20] + 89;
b[5] &= 0xFF;
b[3] -= b[38] + b[9] + b[11] + b[8] + b[34] + b[7] + 167;
b[3] &= 0xFF;
b[32] += b[1] + b[2] + b[18] + b[43] + b[27] + b[29] + 127;
b[32] &= 0xFF;
b[33] += b[21] + b[9] + b[31] + b[6] + b[20] + b[11] + 1;
b[33] &= 0xFF;
b[23] += b[34] + b[7] + b[32] + b[2] + b[12] + b[11] + 30;
b[23] &= 0xFF;
b[41] -= b[27] + b[21] + b[24] + b[22] + b[28] + b[12] + 139;
b[41] &= 0xFF;
b[31] -= b[29] + b[17] + b[0] + b[13] + b[5] + b[40] + 136;
b[31] &= 0xFF;
b[42] ^= (b[43] + b[6] + b[18] + b[1] + b[12] + b[23] + 96) & 0xFF;
b[5] += b[15] + b[20] + b[28] + b[38] + b[35] + b[16] + 190;
b[5] &= 0xFF;
b[6] -= b[30] + b[29] + b[14] + b[35] + b[15] + b[20] + 20;
b[6] &= 0xFF;
b[33] -= b[28] + b[34] + b[27] + b[36] + b[3] + b[39] + 238;
b[33] &= 0xFF;
b[40] ^= (b[30] + b[28] + b[20] + b[33] + b[9] + b[22] + 84) & 0xFF;
b[26] += b[29] + b[27] + b[2] + b[3] + b[5] + b[9] + 244;
b[26] &= 0xFF;
b[42] += b[7] + b[13] + b[3] + b[6] + b[28] + b[5] + 243;
b[42] &= 0xFF;
b[20] ^= (b[34] + b[23] + b[21] + b[0] + b[25] + b[12] + 14) & 0xFF;
b[24] -= b[8] + b[35] + b[21] + b[9] + b[2] + b[22] + 20;
b[24] &= 0xFF;
b[38] += b[27] + b[5] + b[3] + b[19] + b[2] + b[18] + 8;
b[38] &= 0xFF;
b[31] += b[8] + b[42] + b[38] + b[19] + b[22] + b[25] + 138;
b[31] &= 0xFF;
b[39] -= b[18] + b[28] + b[42] + b[40] + b[2] + b[11] + 91;
b[39] &= 0xFF;
b[0] ^= (b[40] + b[36] + b[42] + b[23] + b[17] + b[34] + 149) & 0xFF;
b[23] -= b[32] + b[13] + b[35] + b[34] + b[14] + b[1] + 195;
b[23] &= 0xFF;
b[20] ^= (b[14] + b[7] + b[4] + b[0] + b[29] + b[8] + 172) & 0xFF;
b[2] ^= (b[32] + b[41] + b[24] + b[22] + b[17] + b[21] + 18) & 0xFF;
b[21] += b[32] + b[16] + b[27] + b[17] + b[10] + b[15] + 37;
b[21] &= 0xFF;
b[27] -= b[13] + b[31] + b[1] + b[23] + b[43] + b[17] + 248;
b[27] &= 0xFF;
b[18] -= b[29] + b[0] + b[14] + b[21] + b[24] + b[2] + 70;
b[18] &= 0xFF;
b[39] ^= (b[38] + b[37] + b[22] + b[32] + b[26] + b[9] + 229) & 0xFF;
b[5] ^= (b[20] + b[25] + b[35] + b[42] + b[18] + b[12] + 137) & 0xFF;
b[42] -= b[32] + b[27] + b[40] + b[28] + b[33] + b[9] + 74;
b[42] &= 0xFF;
b[30] -= b[34] + b[23] + b[5] + b[37] + b[33] + b[12] + 60;
b[30] &= 0xFF;
b[11] += b[17] + b[25] + b[9] + b[2] + b[34] + b[18] + 115;
b[11] &= 0xFF;
b[32] += b[26] + b[15] + b[4] + b[21] + b[6] + b[29] + 27;
b[32] &= 0xFF;
b[26] -= b[29] + b[20] + b[22] + b[5] + b[13] + b[27] + 202;
b[26] &= 0xFF;
b[18] += b[13] + b[28] + b[30] + b[22] + b[1] + b[11] + 104;
b[18] &= 0xFF;
b[43] += b[29] + b[35] + b[36] + b[2] + b[33] + b[28] + 236;
b[43] &= 0xFF;
b[1] ^= (b[16] + b[36] + b[17] + b[39] + b[35] + b[9] + 108) & 0xFF;
b[9] += b[27] + b[19] + b[33] + b[24] + b[10] + b[17] + 159;
b[9] &= 0xFF;
b[7] -= b[19] + b[32] + b[13] + b[29] + b[35] + b[43] + 62;
b[7] &= 0xFF;
b[11] -= b[16] + b[9] + b[43] + b[21] + b[7] + b[25] + 219;
b[11] &= 0xFF;
b[16] ^= (b[11] + b[30] + b[37] + b[26] + b[6] + b[33] + 43) & 0xFF;
b[12] -= b[29] + b[2] + b[32] + b[7] + b[6] + b[23] + 5;
b[12] &= 0xFF;
b[43] -= b[32] + b[34] + b[16] + b[29] + b[39] + b[4] + 243;
b[43] &= 0xFF;
b[39] += b[24] + b[5] + b[41] + b[6] + b[8] + b[33] + 137;
b[39] &= 0xFF;
b[3] ^= (b[22] + b[15] + b[43] + b[26] + b[13] + b[41] + 238) & 0xFF;
b[26] -= b[23] + b[24] + b[34] + b[11] + b[15] + b[3] + 125;
b[26] &= 0xFF;
b[11] ^= (b[2] + b[21] + b[40] + b[42] + b[43] + b[35] + 255) & 0xFF;
b[7] ^= (b[6] + b[43] + b[37] + b[12] + b[38] + b[32] + 9) & 0xFF;
b[28] -= b[1] + b[9] + b[6] + b[43] + b[3] + b[10] + 51;
b[28] &= 0xFF;
b[36] ^= (b[11] + b[9] + b[37] + b[32] + b[12] + b[27] + 20) & 0xFF;
b[13] ^= (b[34] + b[25] + b[40] + b[6] + b[39] + b[17] + 19) & 0xFF;
b[37] ^= (b[6] + b[3] + b[31] + b[9] + b[42] + b[32] + 22) & 0xFF;
b[27] -= b[12] + b[17] + b[9] + b[33] + b[3] + b[21] + 161;
b[27] &= 0xFF;
b[11] ^= (b[25] + b[10] + b[9] + b[2] + b[8] + b[26] + 44) & 0xFF;
b[7] ^= (b[31] + b[32] + b[1] + b[36] + b[12] + b[40] + 68) & 0xFF;
b[13] += b[17] + b[40] + b[32] + b[21] + b[5] + b[12] + 5;
b[13] &= 0xFF;
b[25] -= b[38] + b[26] + b[39] + b[33] + b[40] + b[20] + 129;
b[25] &= 0xFF;
b[3] -= b[35] + b[28] + b[24] + b[7] + b[17] + b[6] + 202;
b[3] &= 0xFF;
b[8] += b[16] + b[38] + b[27] + b[21] + b[31] + b[3] + 10;
b[8] &= 0xFF;
b[43] ^= (b[34] + b[28] + b[20] + b[31] + b[7] + b[5] + 175) & 0xFF;
b[1] ^= (b[22] + b[43] + b[37] + b[11] + b[27] + b[15] + 99) & 0xFF;
b[29] ^= (b[19] + b[0] + b[11] + b[25] + b[4] + b[36] + 32) & 0xFF;
b[34] -= b[2] + b[27] + b[31] + b[28] + b[18] + b[5] + 29;
b[34] &= 0xFF;
b[22] += b[5] + b[4] + b[2] + b[15] + b[25] + b[23] + 123;
b[22] &= 0xFF;
b[11] -= b[43] + b[24] + b[34] + b[5] + b[32] + b[17] + 15;
b[11] &= 0xFF;
b[25] += b[15] + b[16] + b[29] + b[37] + b[1] + b[40] + 24;
b[25] &= 0xFF;
b[25] += b[22] + b[3] + b[0] + b[43] + b[40] + b[26] + 76;
b[25] &= 0xFF;
b[19] += b[31] + b[15] + b[6] + b[20] + b[26] + b[25] + 254;
b[19] &= 0xFF;
b[40] -= b[29] + b[0] + b[14] + b[10] + b[15] + b[31] + 244;
b[40] &= 0xFF;
b[35] ^= (b[12] + b[20] + b[21] + b[18] + b[13] + b[14] + 241) & 0xFF;
b[12] += b[39] + b[11] + b[40] + b[18] + b[8] + b[17] + 210;
b[12] &= 0xFF;
b[1] ^= (b[29] + b[38] + b[34] + b[42] + b[13] + b[41] + 214) & 0xFF;
b[28] += b[11] + b[22] + b[17] + b[0] + b[8] + b[31] + 109;
b[28] &= 0xFF;
b[27] -= b[10] + b[22] + b[17] + b[9] + b[24] + b[26] + 43;
b[27] &= 0xFF;
b[26] -= b[27] + b[9] + b[21] + b[39] + b[6] + b[25] + 65;
b[26] &= 0xFF;
b[24] -= b[39] + b[14] + b[26] + b[12] + b[13] + b[41] + 108;
b[24] &= 0xFF;
b[16] ^= (b[4] + b[22] + b[18] + b[13] + b[8] + b[9] + 84) & 0xFF;
b[23] += b[42] + b[33] + b[32] + b[19] + b[3] + b[35] + 112;
b[23] &= 0xFF;
b[1] += b[2] + b[28] + b[40] + b[37] + b[34] + b[11] + 25;
b[1] &= 0xFF;
b[42] ^= (b[25] + b[34] + b[32] + b[0] + b[5] + b[17] + 127) & 0xFF;
b[24] ^= (b[41] + b[19] + b[4] + b[16] + b[37] + b[20] + 80) & 0xFF;
b[42] ^= (b[8] + b[4] + b[28] + b[10] + b[33] + b[6] + 226) & 0xFF;
b[14] ^= (b[17] + b[37] + b[26] + b[33] + b[3] + b[30] + 57) & 0xFF;
b[37] += b[30] + b[10] + b[11] + b[2] + b[34] + b[41] + 206;
b[37] &= 0xFF;
b[8] ^= (b[39] + b[10] + b[15] + b[14] + b[19] + b[0] + 177) & 0xFF;
b[35] += b[3] + b[12] + b[36] + b[28] + b[7] + b[41] + 227;
b[35] &= 0xFF;
b[29] ^= (b[27] + b[23] + b[8] + b[14] + b[16] + b[10] + 250) & 0xFF;
b[14] ^= (b[4] + b[35] + b[26] + b[1] + b[0] + b[7] + 81) & 0xFF;
b[29] += b[23] + b[31] + b[18] + b[15] + b[11] + b[37] + 58;
b[29] &= 0xFF;
b[3] ^= (b[31] + b[13] + b[37] + b[39] + b[8] + b[29] + 76) & 0xFF;
b[16] -= b[25] + b[37] + b[42] + b[23] + b[3] + b[1] + 157;
b[16] &= 0xFF;
b[40] += b[35] + b[42] + b[2] + b[24] + b[22] + b[0] + 14;
b[40] &= 0xFF;
b[26] += b[35] + b[37] + b[34] + b[43] + b[4] + b[19] + 244;
b[26] &= 0xFF;
b[11] -= b[42] + b[40] + b[38] + b[3] + b[26] + b[1] + 101;
b[11] &= 0xFF;
b[18] -= b[11] + b[27] + b[32] + b[8] + b[37] + b[4] + 51;
b[18] &= 0xFF;
b[14] ^= (b[27] + b[11] + b[31] + b[38] + b[16] + b[19] + 72) & 0xFF;
b[38] += b[43] + b[17] + b[14] + b[27] + b[0] + b[22] + 167;
b[38] &= 0xFF;
b[18] -= b[38] + b[20] + b[16] + b[24] + b[34] + b[26] + 49;
b[18] &= 0xFF;
b[22] += b[10] + b[37] + b[34] + b[12] + b[16] + b[2] + 92;
b[22] &= 0xFF;
b[7] ^= (b[26] + b[4] + b[20] + b[34] + b[9] + b[38] + 2) & 0xFF;
b[40] ^= (b[35] + b[9] + b[27] + b[28] + b[3] + b[36] + 118) & 0xFF;
b[18] += b[19] + b[28] + b[40] + b[22] + b[5] + b[17] + 162;
b[18] &= 0xFF;
b[21] += b[24] + b[22] + b[26] + b[0] + b[36] + b[6] + 234;
b[21] &= 0xFF;
b[31] += b[2] + b[8] + b[32] + b[27] + b[18] + b[35] + 193;
b[31] &= 0xFF;
b[36] += b[30] + b[26] + b[3] + b[37] + b[4] + b[28] + 207;
b[36] &= 0xFF;
b[27] -= b[10] + b[33] + b[16] + b[22] + b[25] + b[4] + 212;
b[27] &= 0xFF;
b[16] ^= (b[24] + b[29] + b[6] + b[35] + b[0] + b[9] + 70) & 0xFF;
b[2] += b[15] + b[16] + b[6] + b[34] + b[39] + b[12] + 131;
b[2] &= 0xFF;
b[12] -= b[15] + b[34] + b[31] + b[30] + b[37] + b[0] + 234;
b[12] &= 0xFF;
b[15] += b[21] + b[42] + b[25] + b[1] + b[18] + b[32] + 251;
b[15] &= 0xFF;
b[14] -= b[7] + b[16] + b[5] + b[26] + b[21] + b[28] + 65;
b[14] &= 0xFF;
b[11] -= b[3] + b[34] + b[1] + b[14] + b[20] + b[22] + 237;
b[11] &= 0xFF;
b[18] ^= (b[33] + b[23] + b[19] + b[34] + b[3] + b[42] + 133) & 0xFF;
b[35] -= b[33] + b[31] + b[40] + b[41] + b[0] + b[32] + 134;
b[35] &= 0xFF;
b[7] += b[21] + b[25] + b[38] + b[43] + b[42] + b[41] + 22;
b[7] &= 0xFF;
b[7] -= b[23] + b[4] + b[20] + b[22] + b[0] + b[11] + 113;
b[7] &= 0xFF;
b[34] -= b[21] + b[5] + b[41] + b[10] + b[24] + b[38] + 122;
b[34] &= 0xFF;
b[21] -= b[20] + b[13] + b[41] + b[1] + b[7] + b[33] + 140;
b[21] &= 0xFF;
b[9] ^= (b[30] + b[12] + b[23] + b[2] + b[13] + b[34] + 165) & 0xFF;
b[43] -= b[1] + b[32] + b[9] + b[4] + b[33] + b[22] + 217;
b[43] &= 0xFF;
b[7] += b[29] + b[38] + b[39] + b[26] + b[23] + b[36] + 86;
b[7] &= 0xFF;
b[22] ^= (b[34] + b[42] + b[20] + b[14] + b[1] + b[7] + 41) & 0xFF;
b[9] -= b[10] + b[18] + b[25] + b[31] + b[7] + b[40] + 123;
b[9] &= 0xFF;
b[22] ^= (b[17] + b[0] + b[40] + b[34] + b[4] + b[5] + 36) & 0xFF;
b[34] += b[1] + b[43] + b[3] + b[41] + b[38] + b[31] + 168;
b[34] &= 0xFF;
b[18] -= b[5] + b[42] + b[22] + b[0] + b[23] + b[28] + 19;
b[18] &= 0xFF;
b[18] -= b[37] + b[15] + b[16] + b[27] + b[14] + b[0] + 161;
b[18] &= 0xFF;
b[3] += b[39] + b[2] + b[43] + b[24] + b[5] + b[23] + 6;
b[3] &= 0xFF;
b[13] ^= (b[8] + b[22] + b[33] + b[29] + b[5] + b[17] + 167) & 0xFF;
b[1] -= b[41] + b[33] + b[32] + b[17] + b[35] + b[2] + 65;
b[1] &= 0xFF;
b[20] ^= (b[2] + b[16] + b[34] + b[1] + b[36] + b[33] + 189) & 0xFF;
b[23] += b[21] + b[42] + b[18] + b[5] + b[7] + b[22] + 2;
b[23] &= 0xFF;
b[37] += b[20] + b[11] + b[16] + b[31] + b[22] + b[0] + 194;
b[37] &= 0xFF;
b[16] += b[5] + b[21] + b[39] + b[25] + b[43] + b[8] + 100;
b[16] &= 0xFF;
b[30] ^= (b[19] + b[9] + b[25] + b[11] + b[18] + b[23] + 2) & 0xFF;
b[35] -= b[19] + b[17] + b[37] + b[26] + b[10] + b[13] + 230;
b[35] &= 0xFF;
b[11] -= b[26] + b[43] + b[14] + b[4] + b[30] + b[8] + 96;
b[11] &= 0xFF;
b[22] += b[16] + b[36] + b[10] + b[41] + b[11] + b[15] + 18;
b[22] &= 0xFF;
b[32] += b[38] + b[20] + b[26] + b[35] + b[24] + b[14] + 217;
b[32] &= 0xFF;
b[15] ^= (b[5] + b[24] + b[22] + b[34] + b[8] + b[25] + 210) & 0xFF;
b[34] += b[12] + b[20] + b[15] + b[38] + b[23] + b[11] + 48;
b[34] &= 0xFF;
b[36] -= b[34] + b[10] + b[18] + b[14] + b[30] + b[7] + 71;
b[36] &= 0xFF;
b[43] += b[35] + b[40] + b[41] + b[36] + b[10] + b[39] + 136;
b[43] &= 0xFF;
b[28] ^= (b[0] + b[6] + b[22] + b[7] + b[39] + b[2] + 151) & 0xFF;
b[8] ^= (b[21] + b[43] + b[14] + b[32] + b[26] + b[11] + 230) & 0xFF;
b[41] -= b[28] + b[21] + b[25] + b[31] + b[2] + b[36] + 37;
b[41] &= 0xFF;
b[17] -= b[16] + b[19] + b[4] + b[9] + b[36] + b[11] + 80;
b[17] &= 0xFF;
b[36] -= b[39] + b[34] + b[20] + b[4] + b[17] + b[26] + 178;
b[36] &= 0xFF;
b[19] -= b[36] + b[41] + b[28] + b[22] + b[12] + b[32] + 163;
b[19] &= 0xFF;
b[12] += b[13] + b[21] + b[20] + b[15] + b[31] + b[16] + 13;
b[12] &= 0xFF;
b[43] ^= (b[31] + b[1] + b[33] + b[13] + b[15] + b[3] + 216) & 0xFF;
b[33] ^= (b[43] + b[30] + b[42] + b[0] + b[8] + b[2] + 121) & 0xFF;
b[43] += b[41] + b[14] + b[0] + b[35] + b[34] + b[13] + 16;
b[43] &= 0xFF;
b[11] += b[15] + b[21] + b[35] + b[19] + b[42] + b[24] + 152;
b[11] &= 0xFF;
b[1] -= b[0] + b[22] + b[29] + b[31] + b[18] + b[9] + 50;
b[1] &= 0xFF;
b[2] += b[41] + b[12] + b[4] + b[6] + b[31] + b[28] + 90;
b[2] &= 0xFF;
b[16] -= b[15] + b[17] + b[42] + b[22] + b[32] + b[30] + 64;
b[16] &= 0xFF;
b[7] += b[1] + b[26] + b[15] + b[24] + b[13] + b[31] + 2;
b[7] &= 0xFF;
b[40] ^= (b[0] + b[36] + b[43] + b[31] + b[15] + b[27] + 217) & 0xFF;
b[1] += b[4] + b[25] + b[41] + b[21] + b[22] + b[10] + 216;
b[1] &= 0xFF;
b[6] += b[11] + b[38] + b[32] + b[41] + b[24] + b[40] + 79;
b[6] &= 0xFF;
b[41] -= b[11] + b[27] + b[37] + b[2] + b[18] + b[35] + 25;
b[41] &= 0xFF;
b[16] -= b[13] + b[41] + b[6] + b[15] + b[20] + b[10] + 21;
b[16] &= 0xFF;
b[5] += b[0] + b[12] + b[27] + b[2] + b[1] + b[35] + 45;
b[5] &= 0xFF;
b[1] ^= (b[21] + b[7] + b[37] + b[30] + b[28] + b[32] + 188) & 0xFF;
b[1] ^= (b[17] + b[35] + b[21] + b[3] + b[22] + b[41] + 5) & 0xFF;
b[18] ^= (b[9] + b[25] + b[13] + b[29] + b[0] + b[24] + 21) & 0xFF;
b[43] += b[13] + b[2] + b[35] + b[18] + b[32] + b[33] + 61;
b[43] &= 0xFF;
b[4] -= b[40] + b[9] + b[23] + b[38] + b[18] + b[6] + 123;
b[4] &= 0xFF;
b[17] += b[0] + b[35] + b[12] + b[42] + b[14] + b[3] + 8;
b[17] &= 0xFF;
b[31] += b[40] + b[21] + b[2] + b[43] + b[4] + b[0] + 116;
b[31] &= 0xFF;
b[22] ^= (b[42] + b[30] + b[35] + b[29] + b[31] + b[17] + 146) & 0xFF;
b[26] -= b[16] + b[8] + b[35] + b[4] + b[32] + b[22] + 55;
b[26] &= 0xFF;
b[17] += b[18] + b[4] + b[15] + b[34] + b[16] + b[31] + 215;
b[17] &= 0xFF;
b[13] ^= (b[41] + b[12] + b[22] + b[28] + b[42] + b[40] + 246) & 0xFF;
b[23] += b[7] + b[30] + b[27] + b[35] + b[43] + b[10] + 164;
b[23] &= 0xFF;
b[28] += b[40] + b[43] + b[5] + b[21] + b[3] + b[24] + 231;
b[28] &= 0xFF;
b[42] ^= (b[12] + b[43] + b[37] + b[6] + b[19] + b[40] + 94) & 0xFF;
b[31] += b[8] + b[5] + b[3] + b[13] + b[6] + b[39] + 14;
b[31] &= 0xFF;
b[1] += b[14] + b[33] + b[4] + b[34] + b[13] + b[18] + 90;
b[1] &= 0xFF;
b[31] ^= (b[16] + b[13] + b[28] + b[21] + b[0] + b[27] + 130) & 0xFF;
b[19] -= b[7] + b[41] + b[32] + b[18] + b[1] + b[23] + 19;
b[19] &= 0xFF;
b[39] ^= (b[15] + b[14] + b[31] + b[23] + b[27] + b[41] + 117) & 0xFF;
b[29] += b[10] + b[1] + b[9] + b[30] + b[18] + b[37] + 138;
b[29] &= 0xFF;
b[0] += b[25] + b[13] + b[38] + b[31] + b[14] + b[30] + 248;
b[0] &= 0xFF;
b[31] ^= (b[11] + b[2] + b[42] + b[1] + b[26] + b[13] + 252) & 0xFF;
b[17] ^= (b[28] + b[14] + b[16] + b[31] + b[41] + b[43] + 36) & 0xFF;
b[5] ^= (b[35] + b[39] + b[40] + b[16] + b[10] + b[13] + 108) & 0xFF;
b[18] -= b[13] + b[0] + b[42] + b[43] + b[12] + b[21] + 130;
b[18] &= 0xFF;
b[25] += b[29] + b[8] + b[18] + b[33] + b[23] + b[10] + 43;
b[25] &= 0xFF;
b[8] += b[21] + b[2] + b[30] + b[15] + b[41] + b[31] + 202;
b[8] &= 0xFF;
b[26] -= b[6] + b[10] + b[7] + b[2] + b[11] + b[32] + 127;
b[26] &= 0xFF;
b[33] += b[15] + b[4] + b[12] + b[18] + b[23] + b[16] + 224;
b[33] &= 0xFF;
b[28] ^= (b[40] + b[17] + b[20] + b[35] + b[1] + b[6] + 127) & 0xFF;
b[36] -= b[7] + b[3] + b[10] + b[5] + b[13] + b[2] + 23;
b[36] &= 0xFF;
b[0] += b[37] + b[26] + b[14] + b[22] + b[21] + b[12] + 221;
b[0] &= 0xFF;
b[6] += b[33] + b[12] + b[41] + b[15] + b[19] + b[11] + 154;
b[6] &= 0xFF;
b[26] += b[40] + b[6] + b[36] + b[21] + b[19] + b[28] + 41;
b[26] &= 0xFF;
b[14] += b[35] + b[22] + b[0] + b[1] + b[42] + b[25] + 206;
b[14] &= 0xFF;
b[3] -= b[42] + b[17] + b[24] + b[16] + b[41] + b[1] + 61;
b[3] &= 0xFF;
b[43] -= b[22] + b[17] + b[6] + b[10] + b[2] + b[5] + 126;
b[43] &= 0xFF;
b[16] += b[20] + b[35] + b[30] + b[1] + b[8] + b[37] + 181;
b[16] &= 0xFF;
b[15] += b[24] + b[16] + b[38] + b[22] + b[18] + b[19] + 18;
b[15] &= 0xFF;
b[16] -= b[5] + b[15] + b[14] + b[6] + b[17] + b[33] + 51;
b[16] &= 0xFF;
b[11] ^= (b[15] + b[36] + b[35] + b[38] + b[21] + b[43] + 45) & 0xFF;
b[18] += b[39] + b[9] + b[29] + b[33] + b[32] + b[3] + 135;
b[18] &= 0xFF;
b[40] += b[37] + b[29] + b[8] + b[19] + b[0] + b[27] + 172;
b[40] &= 0xFF;
b[15] -= b[14] + b[16] + b[36] + b[40] + b[10] + b[3] + 204;
b[15] &= 0xFF;
b[36] ^= (b[18] + b[42] + b[9] + b[34] + b[12] + b[29] + 242) & 0xFF;
b[39] -= b[12] + b[36] + b[0] + b[41] + b[38] + b[35] + 102;
b[39] &= 0xFF;
b[18] += b[22] + b[13] + b[43] + b[2] + b[14] + b[4] + 10;
b[18] &= 0xFF;
b[42] += b[1] + b[29] + b[8] + b[32] + b[23] + b[16] + 49;
b[42] &= 0xFF;
b[5] -= b[22] + b[8] + b[12] + b[24] + b[37] + b[31] + 149;
b[5] &= 0xFF;
b[19] += b[28] + b[30] + b[4] + b[10] + b[15] + b[17] + 131;
b[19] &= 0xFF;
b[2] ^= (b[1] + b[40] + b[32] + b[37] + b[21] + b[35] + 186) & 0xFF;
b[28] ^= (b[10] + b[37] + b[8] + b[12] + b[17] + b[30] + 58) & 0xFF;
b[19] ^= (b[16] + b[17] + b[11] + b[12] + b[37] + b[31] + 52) & 0xFF;
b[27] ^= (b[31] + b[7] + b[29] + b[33] + b[25] + b[38] + 60) & 0xFF;
b[15] += b[32] + b[31] + b[9] + b[20] + b[36] + b[18] + 132;
b[15] &= 0xFF;
b[21] ^= (b[9] + b[5] + b[38] + b[14] + b[43] + b[7] + 217) & 0xFF;
b[25] ^= (b[10] + b[33] + b[24] + b[5] + b[12] + b[38] + 112) & 0xFF;
b[7] ^= (b[5] + b[40] + b[15] + b[22] + b[1] + b[10] + 209) & 0xFF;
b[10] ^= (b[26] + b[29] + b[19] + b[31] + b[39] + b[28] + 142) & 0xFF;
b[33] += b[4] + b[41] + b[18] + b[43] + b[28] + b[25] + 2;
b[33] &= 0xFF;
b[35] ^= (b[34] + b[36] + b[8] + b[19] + b[3] + b[14] + 74) & 0xFF;
b[12] += b[0] + b[13] + b[28] + b[38] + b[43] + b[1] + 89;
b[12] &= 0xFF;
b[25] += b[13] + b[34] + b[7] + b[39] + b[19] + b[5] + 96;
b[25] &= 0xFF;
b[23] -= b[22] + b[15] + b[20] + b[10] + b[37] + b[33] + 163;
b[23] &= 0xFF;
b[22] ^= (b[1] + b[5] + b[10] + b[3] + b[12] + b[16] + 207) & 0xFF;
b[39] += b[42] + b[37] + b[40] + b[30] + b[3] + b[29] + 55;
b[39] &= 0xFF;
b[29] += b[39] + b[36] + b[23] + b[31] + b[5] + b[26] + 105;
b[29] &= 0xFF;
b[13] ^= (b[0] + b[29] + b[26] + b[14] + b[15] + b[7] + 31) & 0xFF;
b[33] ^= (b[10] + b[22] + b[2] + b[1] + b[30] + b[11] + 154) & 0xFF;
b[37] ^= (b[28] + b[39] + b[41] + b[11] + b[10] + b[9] + 223) & 0xFF;
b[23] ^= (b[30] + b[1] + b[2] + b[25] + b[42] + b[36] + 233) & 0xFF;
b[30] -= b[25] + b[34] + b[36] + b[6] + b[41] + b[11] + 108;
b[30] &= 0xFF;
b[19] ^= (b[3] + b[30] + b[17] + b[15] + b[13] + b[18] + 241) & 0xFF;
b[38] += b[20] + b[30] + b[31] + b[8] + b[37] + b[33] + 54;
b[38] &= 0xFF;
b[17] ^= (b[41] + b[14] + b[43] + b[6] + b[7] + b[28] + 196) & 0xFF;
b[40] += b[13] + b[3] + b[43] + b[31] + b[22] + b[25] + 49;
b[40] &= 0xFF;
b[19] ^= (b[0] + b[35] + b[14] + b[30] + b[21] + b[33] + 213) & 0xFF;
b[11] -= b[32] + b[8] + b[9] + b[34] + b[39] + b[19] + 185;
b[11] &= 0xFF;
b[21] += b[39] + b[6] + b[0] + b[33] + b[8] + b[40] + 179;
b[21] &= 0xFF;
b[34] += b[35] + b[40] + b[13] + b[41] + b[23] + b[25] + 14;
b[34] &= 0xFF;
b[22] += b[16] + b[18] + b[7] + b[23] + b[1] + b[27] + 50;
b[22] &= 0xFF;
b[39] += b[18] + b[16] + b[8] + b[19] + b[5] + b[23] + 36;
b[39] &= 0xFF;
```

You can reverse those with `tac` , after that you need to reverse the operations. + —> - and - —> +:

```python
var b = [106, 196, 106, 178, 174, 102, 31, 91, 66, 255, 86, 196, 74, 139, 219, 166, 106, 4, 211, 68, 227, 72, 156, 38, 239, 153, 223, 225, 73, 171, 51, 4, 234, 50, 207, 82, 18, 111, 180, 212, 81, 189, 73, 76]
b[39] = (b[39] - (b[18] + b[16] + b[8] + b[19] + b[5] + b[23] + 36)) & 255;
b[22] = (b[22] - (b[16] + b[18] + b[7] + b[23] + b[1] + b[27] + 50)) & 255;
b[34] = (b[34] - (b[35] + b[40] + b[13] + b[41] + b[23] + b[25] + 14)) & 255;
b[21] = (b[21] - (b[39] + b[6] + b[0] + b[33] + b[8] + b[40] + 179)) & 255;
b[11] = (b[11] + (b[32] + b[8] + b[9] + b[34] + b[39] + b[19] + 185)) & 255;
b[19] ^= (b[0] + b[35] + b[14] + b[30] + b[21] + b[33] + 213) & 0xFF;
b[40] = (b[40] - (b[13] + b[3] + b[43] + b[31] + b[22] + b[25] + 49)) & 255;
b[17] ^= (b[41] + b[14] + b[43] + b[6] + b[7] + b[28] + 196) & 0xFF;
b[38] = (b[38] - (b[20] + b[30] + b[31] + b[8] + b[37] + b[33] + 54)) & 255;
b[19] ^= (b[3] + b[30] + b[17] + b[15] + b[13] + b[18] + 241) & 0xFF;
b[30] = (b[30] + (b[25] + b[34] + b[36] + b[6] + b[41] + b[11] + 108)) & 255;
b[23] ^= (b[30] + b[1] + b[2] + b[25] + b[42] + b[36] + 233) & 0xFF;
b[37] ^= (b[28] + b[39] + b[41] + b[11] + b[10] + b[9] + 223) & 0xFF;
b[33] ^= (b[10] + b[22] + b[2] + b[1] + b[30] + b[11] + 154) & 0xFF;
b[13] ^= (b[0] + b[29] + b[26] + b[14] + b[15] + b[7] + 31) & 0xFF;
b[29] = (b[29] - (b[39] + b[36] + b[23] + b[31] + b[5] + b[26] + 105)) & 255;
b[39] = (b[39] - (b[42] + b[37] + b[40] + b[30] + b[3] + b[29] + 55)) & 255;
b[22] ^= (b[1] + b[5] + b[10] + b[3] + b[12] + b[16] + 207) & 0xFF;
b[23] = (b[23] + (b[22] + b[15] + b[20] + b[10] + b[37] + b[33] + 163)) & 255;
b[25] = (b[25] - (b[13] + b[34] + b[7] + b[39] + b[19] + b[5] + 96)) & 255;
b[12] = (b[12] - (b[0] + b[13] + b[28] + b[38] + b[43] + b[1] + 89)) & 255;
b[35] ^= (b[34] + b[36] + b[8] + b[19] + b[3] + b[14] + 74) & 0xFF;
b[33] = (b[33] - (b[4] + b[41] + b[18] + b[43] + b[28] + b[25] + 2)) & 255;
b[10] ^= (b[26] + b[29] + b[19] + b[31] + b[39] + b[28] + 142) & 0xFF;
b[7] ^= (b[5] + b[40] + b[15] + b[22] + b[1] + b[10] + 209) & 0xFF;
b[25] ^= (b[10] + b[33] + b[24] + b[5] + b[12] + b[38] + 112) & 0xFF;
b[21] ^= (b[9] + b[5] + b[38] + b[14] + b[43] + b[7] + 217) & 0xFF;
b[15] = (b[15] - (b[32] + b[31] + b[9] + b[20] + b[36] + b[18] + 132)) & 255;
b[27] ^= (b[31] + b[7] + b[29] + b[33] + b[25] + b[38] + 60) & 0xFF;
b[19] ^= (b[16] + b[17] + b[11] + b[12] + b[37] + b[31] + 52) & 0xFF;
b[28] ^= (b[10] + b[37] + b[8] + b[12] + b[17] + b[30] + 58) & 0xFF;
b[2] ^= (b[1] + b[40] + b[32] + b[37] + b[21] + b[35] + 186) & 0xFF;
b[19] = (b[19] - (b[28] + b[30] + b[4] + b[10] + b[15] + b[17] + 131)) & 255;
b[5] = (b[5] + (b[22] + b[8] + b[12] + b[24] + b[37] + b[31] + 149)) & 255;
b[42] = (b[42] - (b[1] + b[29] + b[8] + b[32] + b[23] + b[16] + 49)) & 255;
b[18] = (b[18] - (b[22] + b[13] + b[43] + b[2] + b[14] + b[4] + 10)) & 255;
b[39] = (b[39] + (b[12] + b[36] + b[0] + b[41] + b[38] + b[35] + 102)) & 255;
b[36] ^= (b[18] + b[42] + b[9] + b[34] + b[12] + b[29] + 242) & 0xFF;
b[15] = (b[15] + (b[14] + b[16] + b[36] + b[40] + b[10] + b[3] + 204)) & 255;
b[40] = (b[40] - (b[37] + b[29] + b[8] + b[19] + b[0] + b[27] + 172)) & 255;
b[18] = (b[18] - (b[39] + b[9] + b[29] + b[33] + b[32] + b[3] + 135)) & 255;
b[11] ^= (b[15] + b[36] + b[35] + b[38] + b[21] + b[43] + 45) & 0xFF;
b[16] = (b[16] + (b[5] + b[15] + b[14] + b[6] + b[17] + b[33] + 51)) & 255;
b[15] = (b[15] - (b[24] + b[16] + b[38] + b[22] + b[18] + b[19] + 18)) & 255;
b[16] = (b[16] - (b[20] + b[35] + b[30] + b[1] + b[8] + b[37] + 181)) & 255;
b[43] = (b[43] + (b[22] + b[17] + b[6] + b[10] + b[2] + b[5] + 126)) & 255;
b[3] = (b[3] + (b[42] + b[17] + b[24] + b[16] + b[41] + b[1] + 61)) & 255;
b[14] = (b[14] - (b[35] + b[22] + b[0] + b[1] + b[42] + b[25] + 206)) & 255;
b[26] = (b[26] - (b[40] + b[6] + b[36] + b[21] + b[19] + b[28] + 41)) & 255;
b[6] = (b[6] - (b[33] + b[12] + b[41] + b[15] + b[19] + b[11] + 154)) & 255;
b[0] = (b[0] - (b[37] + b[26] + b[14] + b[22] + b[21] + b[12] + 221)) & 255;
b[36] = (b[36] + (b[7] + b[3] + b[10] + b[5] + b[13] + b[2] + 23)) & 255;
b[28] ^= (b[40] + b[17] + b[20] + b[35] + b[1] + b[6] + 127) & 0xFF;
b[33] = (b[33] - (b[15] + b[4] + b[12] + b[18] + b[23] + b[16] + 224)) & 255;
b[26] = (b[26] + (b[6] + b[10] + b[7] + b[2] + b[11] + b[32] + 127)) & 255;
b[8] = (b[8] - (b[21] + b[2] + b[30] + b[15] + b[41] + b[31] + 202)) & 255;
b[25] = (b[25] - (b[29] + b[8] + b[18] + b[33] + b[23] + b[10] + 43)) & 255;
b[18] = (b[18] + (b[13] + b[0] + b[42] + b[43] + b[12] + b[21] + 130)) & 255;
b[5] ^= (b[35] + b[39] + b[40] + b[16] + b[10] + b[13] + 108) & 0xFF;
b[17] ^= (b[28] + b[14] + b[16] + b[31] + b[41] + b[43] + 36) & 0xFF;
b[31] ^= (b[11] + b[2] + b[42] + b[1] + b[26] + b[13] + 252) & 0xFF;
b[0] = (b[0] - (b[25] + b[13] + b[38] + b[31] + b[14] + b[30] + 248)) & 255;
b[29] = (b[29] - (b[10] + b[1] + b[9] + b[30] + b[18] + b[37] + 138)) & 255;
b[39] ^= (b[15] + b[14] + b[31] + b[23] + b[27] + b[41] + 117) & 0xFF;
b[19] = (b[19] + (b[7] + b[41] + b[32] + b[18] + b[1] + b[23] + 19)) & 255;
b[31] ^= (b[16] + b[13] + b[28] + b[21] + b[0] + b[27] + 130) & 0xFF;
b[1] = (b[1] - (b[14] + b[33] + b[4] + b[34] + b[13] + b[18] + 90)) & 255;
b[31] = (b[31] - (b[8] + b[5] + b[3] + b[13] + b[6] + b[39] + 14)) & 255;
b[42] ^= (b[12] + b[43] + b[37] + b[6] + b[19] + b[40] + 94) & 0xFF;
b[28] = (b[28] - (b[40] + b[43] + b[5] + b[21] + b[3] + b[24] + 231)) & 255;
b[23] = (b[23] - (b[7] + b[30] + b[27] + b[35] + b[43] + b[10] + 164)) & 255;
b[13] ^= (b[41] + b[12] + b[22] + b[28] + b[42] + b[40] + 246) & 0xFF;
b[17] = (b[17] - (b[18] + b[4] + b[15] + b[34] + b[16] + b[31] + 215)) & 255;
b[26] = (b[26] + (b[16] + b[8] + b[35] + b[4] + b[32] + b[22] + 55)) & 255;
b[22] ^= (b[42] + b[30] + b[35] + b[29] + b[31] + b[17] + 146) & 0xFF;
b[31] = (b[31] - (b[40] + b[21] + b[2] + b[43] + b[4] + b[0] + 116)) & 255;
b[17] = (b[17] - (b[0] + b[35] + b[12] + b[42] + b[14] + b[3] + 8)) & 255;
b[4] = (b[4] + (b[40] + b[9] + b[23] + b[38] + b[18] + b[6] + 123)) & 255;
b[43] = (b[43] - (b[13] + b[2] + b[35] + b[18] + b[32] + b[33] + 61)) & 255;
b[18] ^= (b[9] + b[25] + b[13] + b[29] + b[0] + b[24] + 21) & 0xFF;
b[1] ^= (b[17] + b[35] + b[21] + b[3] + b[22] + b[41] + 5) & 0xFF;
b[1] ^= (b[21] + b[7] + b[37] + b[30] + b[28] + b[32] + 188) & 0xFF;
b[5] = (b[5] - (b[0] + b[12] + b[27] + b[2] + b[1] + b[35] + 45)) & 255;
b[16] = (b[16] + (b[13] + b[41] + b[6] + b[15] + b[20] + b[10] + 21)) & 255;
b[41] = (b[41] + (b[11] + b[27] + b[37] + b[2] + b[18] + b[35] + 25)) & 255;
b[6] = (b[6] - (b[11] + b[38] + b[32] + b[41] + b[24] + b[40] + 79)) & 255;
b[1] = (b[1] - (b[4] + b[25] + b[41] + b[21] + b[22] + b[10] + 216)) & 255;
b[40] ^= (b[0] + b[36] + b[43] + b[31] + b[15] + b[27] + 217) & 0xFF;
b[7] = (b[7] - (b[1] + b[26] + b[15] + b[24] + b[13] + b[31] + 2)) & 255;
b[16] = (b[16] + (b[15] + b[17] + b[42] + b[22] + b[32] + b[30] + 64)) & 255;
b[2] = (b[2] - (b[41] + b[12] + b[4] + b[6] + b[31] + b[28] + 90)) & 255;
b[1] = (b[1] + (b[0] + b[22] + b[29] + b[31] + b[18] + b[9] + 50)) & 255;
b[11] = (b[11] - (b[15] + b[21] + b[35] + b[19] + b[42] + b[24] + 152)) & 255;
b[43] = (b[43] - (b[41] + b[14] + b[0] + b[35] + b[34] + b[13] + 16)) & 255;
b[33] ^= (b[43] + b[30] + b[42] + b[0] + b[8] + b[2] + 121) & 0xFF;
b[43] ^= (b[31] + b[1] + b[33] + b[13] + b[15] + b[3] + 216) & 0xFF;
b[12] = (b[12] - (b[13] + b[21] + b[20] + b[15] + b[31] + b[16] + 13)) & 255;
b[19] = (b[19] + (b[36] + b[41] + b[28] + b[22] + b[12] + b[32] + 163)) & 255;
b[36] = (b[36] + (b[39] + b[34] + b[20] + b[4] + b[17] + b[26] + 178)) & 255;
b[17] = (b[17] + (b[16] + b[19] + b[4] + b[9] + b[36] + b[11] + 80)) & 255;
b[41] = (b[41] + (b[28] + b[21] + b[25] + b[31] + b[2] + b[36] + 37)) & 255;
b[8] ^= (b[21] + b[43] + b[14] + b[32] + b[26] + b[11] + 230) & 0xFF;
b[28] ^= (b[0] + b[6] + b[22] + b[7] + b[39] + b[2] + 151) & 0xFF;
b[43] = (b[43] - (b[35] + b[40] + b[41] + b[36] + b[10] + b[39] + 136)) & 255;
b[36] = (b[36] + (b[34] + b[10] + b[18] + b[14] + b[30] + b[7] + 71)) & 255;
b[34] = (b[34] - (b[12] + b[20] + b[15] + b[38] + b[23] + b[11] + 48)) & 255;
b[15] ^= (b[5] + b[24] + b[22] + b[34] + b[8] + b[25] + 210) & 0xFF;
b[32] = (b[32] - (b[38] + b[20] + b[26] + b[35] + b[24] + b[14] + 217)) & 255;
b[22] = (b[22] - (b[16] + b[36] + b[10] + b[41] + b[11] + b[15] + 18)) & 255;
b[11] = (b[11] + (b[26] + b[43] + b[14] + b[4] + b[30] + b[8] + 96)) & 255;
b[35] = (b[35] + (b[19] + b[17] + b[37] + b[26] + b[10] + b[13] + 230)) & 255;
b[30] ^= (b[19] + b[9] + b[25] + b[11] + b[18] + b[23] + 2) & 0xFF;
b[16] = (b[16] - (b[5] + b[21] + b[39] + b[25] + b[43] + b[8] + 100)) & 255;
b[37] = (b[37] - (b[20] + b[11] + b[16] + b[31] + b[22] + b[0] + 194)) & 255;
b[23] = (b[23] - (b[21] + b[42] + b[18] + b[5] + b[7] + b[22] + 2)) & 255;
b[20] ^= (b[2] + b[16] + b[34] + b[1] + b[36] + b[33] + 189) & 0xFF;
b[1] = (b[1] + (b[41] + b[33] + b[32] + b[17] + b[35] + b[2] + 65)) & 255;
b[13] ^= (b[8] + b[22] + b[33] + b[29] + b[5] + b[17] + 167) & 0xFF;
b[3] = (b[3] - (b[39] + b[2] + b[43] + b[24] + b[5] + b[23] + 6)) & 255;
b[18] = (b[18] + (b[37] + b[15] + b[16] + b[27] + b[14] + b[0] + 161)) & 255;
b[18] = (b[18] + (b[5] + b[42] + b[22] + b[0] + b[23] + b[28] + 19)) & 255;
b[34] = (b[34] - (b[1] + b[43] + b[3] + b[41] + b[38] + b[31] + 168)) & 255;
b[22] ^= (b[17] + b[0] + b[40] + b[34] + b[4] + b[5] + 36) & 0xFF;
b[9] = (b[9] + (b[10] + b[18] + b[25] + b[31] + b[7] + b[40] + 123)) & 255;
b[22] ^= (b[34] + b[42] + b[20] + b[14] + b[1] + b[7] + 41) & 0xFF;
b[7] = (b[7] - (b[29] + b[38] + b[39] + b[26] + b[23] + b[36] + 86)) & 255;
b[43] = (b[43] + (b[1] + b[32] + b[9] + b[4] + b[33] + b[22] + 217)) & 255;
b[9] ^= (b[30] + b[12] + b[23] + b[2] + b[13] + b[34] + 165) & 0xFF;
b[21] = (b[21] + (b[20] + b[13] + b[41] + b[1] + b[7] + b[33] + 140)) & 255;
b[34] = (b[34] + (b[21] + b[5] + b[41] + b[10] + b[24] + b[38] + 122)) & 255;
b[7] = (b[7] + (b[23] + b[4] + b[20] + b[22] + b[0] + b[11] + 113)) & 255;
b[7] = (b[7] - (b[21] + b[25] + b[38] + b[43] + b[42] + b[41] + 22)) & 255;
b[35] = (b[35] + (b[33] + b[31] + b[40] + b[41] + b[0] + b[32] + 134)) & 255;
b[18] ^= (b[33] + b[23] + b[19] + b[34] + b[3] + b[42] + 133) & 0xFF;
b[11] = (b[11] + (b[3] + b[34] + b[1] + b[14] + b[20] + b[22] + 237)) & 255;
b[14] = (b[14] + (b[7] + b[16] + b[5] + b[26] + b[21] + b[28] + 65)) & 255;
b[15] = (b[15] - (b[21] + b[42] + b[25] + b[1] + b[18] + b[32] + 251)) & 255;
b[12] = (b[12] + (b[15] + b[34] + b[31] + b[30] + b[37] + b[0] + 234)) & 255;
b[2] = (b[2] - (b[15] + b[16] + b[6] + b[34] + b[39] + b[12] + 131)) & 255;
b[16] ^= (b[24] + b[29] + b[6] + b[35] + b[0] + b[9] + 70) & 0xFF;
b[27] = (b[27] + (b[10] + b[33] + b[16] + b[22] + b[25] + b[4] + 212)) & 255;
b[36] = (b[36] - (b[30] + b[26] + b[3] + b[37] + b[4] + b[28] + 207)) & 255;
b[31] = (b[31] - (b[2] + b[8] + b[32] + b[27] + b[18] + b[35] + 193)) & 255;
b[21] = (b[21] - (b[24] + b[22] + b[26] + b[0] + b[36] + b[6] + 234)) & 255;
b[18] = (b[18] - (b[19] + b[28] + b[40] + b[22] + b[5] + b[17] + 162)) & 255;
b[40] ^= (b[35] + b[9] + b[27] + b[28] + b[3] + b[36] + 118) & 0xFF;
b[7] ^= (b[26] + b[4] + b[20] + b[34] + b[9] + b[38] + 2) & 0xFF;
b[22] = (b[22] - (b[10] + b[37] + b[34] + b[12] + b[16] + b[2] + 92)) & 255;
b[18] = (b[18] + (b[38] + b[20] + b[16] + b[24] + b[34] + b[26] + 49)) & 255;
b[38] = (b[38] - (b[43] + b[17] + b[14] + b[27] + b[0] + b[22] + 167)) & 255;
b[14] ^= (b[27] + b[11] + b[31] + b[38] + b[16] + b[19] + 72) & 0xFF;
b[18] = (b[18] + (b[11] + b[27] + b[32] + b[8] + b[37] + b[4] + 51)) & 255;
b[11] = (b[11] + (b[42] + b[40] + b[38] + b[3] + b[26] + b[1] + 101)) & 255;
b[26] = (b[26] - (b[35] + b[37] + b[34] + b[43] + b[4] + b[19] + 244)) & 255;
b[40] = (b[40] - (b[35] + b[42] + b[2] + b[24] + b[22] + b[0] + 14)) & 255;
b[16] = (b[16] + (b[25] + b[37] + b[42] + b[23] + b[3] + b[1] + 157)) & 255;
b[3] ^= (b[31] + b[13] + b[37] + b[39] + b[8] + b[29] + 76) & 0xFF;
b[29] = (b[29] - (b[23] + b[31] + b[18] + b[15] + b[11] + b[37] + 58)) & 255;
b[14] ^= (b[4] + b[35] + b[26] + b[1] + b[0] + b[7] + 81) & 0xFF;
b[29] ^= (b[27] + b[23] + b[8] + b[14] + b[16] + b[10] + 250) & 0xFF;
b[35] = (b[35] - (b[3] + b[12] + b[36] + b[28] + b[7] + b[41] + 227)) & 255;
b[8] ^= (b[39] + b[10] + b[15] + b[14] + b[19] + b[0] + 177) & 0xFF;
b[37] = (b[37] - (b[30] + b[10] + b[11] + b[2] + b[34] + b[41] + 206)) & 255;
b[14] ^= (b[17] + b[37] + b[26] + b[33] + b[3] + b[30] + 57) & 0xFF;
b[42] ^= (b[8] + b[4] + b[28] + b[10] + b[33] + b[6] + 226) & 0xFF;
b[24] ^= (b[41] + b[19] + b[4] + b[16] + b[37] + b[20] + 80) & 0xFF;
b[42] ^= (b[25] + b[34] + b[32] + b[0] + b[5] + b[17] + 127) & 0xFF;
b[1] = (b[1] - (b[2] + b[28] + b[40] + b[37] + b[34] + b[11] + 25)) & 255;
b[23] = (b[23] - (b[42] + b[33] + b[32] + b[19] + b[3] + b[35] + 112)) & 255;
b[16] ^= (b[4] + b[22] + b[18] + b[13] + b[8] + b[9] + 84) & 0xFF;
b[24] = (b[24] + (b[39] + b[14] + b[26] + b[12] + b[13] + b[41] + 108)) & 255;
b[26] = (b[26] + (b[27] + b[9] + b[21] + b[39] + b[6] + b[25] + 65)) & 255;
b[27] = (b[27] + (b[10] + b[22] + b[17] + b[9] + b[24] + b[26] + 43)) & 255;
b[28] = (b[28] - (b[11] + b[22] + b[17] + b[0] + b[8] + b[31] + 109)) & 255;
b[1] ^= (b[29] + b[38] + b[34] + b[42] + b[13] + b[41] + 214) & 0xFF;
b[12] = (b[12] - (b[39] + b[11] + b[40] + b[18] + b[8] + b[17] + 210)) & 255;
b[35] ^= (b[12] + b[20] + b[21] + b[18] + b[13] + b[14] + 241) & 0xFF;
b[40] = (b[40] + (b[29] + b[0] + b[14] + b[10] + b[15] + b[31] + 244)) & 255;
b[19] = (b[19] - (b[31] + b[15] + b[6] + b[20] + b[26] + b[25] + 254)) & 255;
b[25] = (b[25] - (b[22] + b[3] + b[0] + b[43] + b[40] + b[26] + 76)) & 255;
b[25] = (b[25] - (b[15] + b[16] + b[29] + b[37] + b[1] + b[40] + 24)) & 255;
b[11] = (b[11] + (b[43] + b[24] + b[34] + b[5] + b[32] + b[17] + 15)) & 255;
b[22] = (b[22] - (b[5] + b[4] + b[2] + b[15] + b[25] + b[23] + 123)) & 255;
b[34] = (b[34] + (b[2] + b[27] + b[31] + b[28] + b[18] + b[5] + 29)) & 255;
b[29] ^= (b[19] + b[0] + b[11] + b[25] + b[4] + b[36] + 32) & 0xFF;
b[1] ^= (b[22] + b[43] + b[37] + b[11] + b[27] + b[15] + 99) & 0xFF;
b[43] ^= (b[34] + b[28] + b[20] + b[31] + b[7] + b[5] + 175) & 0xFF;
b[8] = (b[8] - (b[16] + b[38] + b[27] + b[21] + b[31] + b[3] + 10)) & 255;
b[3] = (b[3] + (b[35] + b[28] + b[24] + b[7] + b[17] + b[6] + 202)) & 255;
b[25] = (b[25] + (b[38] + b[26] + b[39] + b[33] + b[40] + b[20] + 129)) & 255;
b[13] = (b[13] - (b[17] + b[40] + b[32] + b[21] + b[5] + b[12] + 5)) & 255;
b[7] ^= (b[31] + b[32] + b[1] + b[36] + b[12] + b[40] + 68) & 0xFF;
b[11] ^= (b[25] + b[10] + b[9] + b[2] + b[8] + b[26] + 44) & 0xFF;
b[27] = (b[27] + (b[12] + b[17] + b[9] + b[33] + b[3] + b[21] + 161)) & 255;
b[37] ^= (b[6] + b[3] + b[31] + b[9] + b[42] + b[32] + 22) & 0xFF;
b[13] ^= (b[34] + b[25] + b[40] + b[6] + b[39] + b[17] + 19) & 0xFF;
b[36] ^= (b[11] + b[9] + b[37] + b[32] + b[12] + b[27] + 20) & 0xFF;
b[28] = (b[28] + (b[1] + b[9] + b[6] + b[43] + b[3] + b[10] + 51)) & 255;
b[7] ^= (b[6] + b[43] + b[37] + b[12] + b[38] + b[32] + 9) & 0xFF;
b[11] ^= (b[2] + b[21] + b[40] + b[42] + b[43] + b[35] + 255) & 0xFF;
b[26] = (b[26] + (b[23] + b[24] + b[34] + b[11] + b[15] + b[3] + 125)) & 255;
b[3] ^= (b[22] + b[15] + b[43] + b[26] + b[13] + b[41] + 238) & 0xFF;
b[39] = (b[39] - (b[24] + b[5] + b[41] + b[6] + b[8] + b[33] + 137)) & 255;
b[43] = (b[43] + (b[32] + b[34] + b[16] + b[29] + b[39] + b[4] + 243)) & 255;
b[12] = (b[12] + (b[29] + b[2] + b[32] + b[7] + b[6] + b[23] + 5)) & 255;
b[16] ^= (b[11] + b[30] + b[37] + b[26] + b[6] + b[33] + 43) & 0xFF;
b[11] = (b[11] + (b[16] + b[9] + b[43] + b[21] + b[7] + b[25] + 219)) & 255;
b[7] = (b[7] + (b[19] + b[32] + b[13] + b[29] + b[35] + b[43] + 62)) & 255;
b[9] = (b[9] - (b[27] + b[19] + b[33] + b[24] + b[10] + b[17] + 159)) & 255;
b[1] ^= (b[16] + b[36] + b[17] + b[39] + b[35] + b[9] + 108) & 0xFF;
b[43] = (b[43] - (b[29] + b[35] + b[36] + b[2] + b[33] + b[28] + 236)) & 255;
b[18] = (b[18] - (b[13] + b[28] + b[30] + b[22] + b[1] + b[11] + 104)) & 255;
b[26] = (b[26] + (b[29] + b[20] + b[22] + b[5] + b[13] + b[27] + 202)) & 255;
b[32] = (b[32] - (b[26] + b[15] + b[4] + b[21] + b[6] + b[29] + 27)) & 255;
b[11] = (b[11] - (b[17] + b[25] + b[9] + b[2] + b[34] + b[18] + 115)) & 255;
b[30] = (b[30] + (b[34] + b[23] + b[5] + b[37] + b[33] + b[12] + 60)) & 255;
b[42] = (b[42] + (b[32] + b[27] + b[40] + b[28] + b[33] + b[9] + 74)) & 255;
b[5] ^= (b[20] + b[25] + b[35] + b[42] + b[18] + b[12] + 137) & 0xFF;
b[39] ^= (b[38] + b[37] + b[22] + b[32] + b[26] + b[9] + 229) & 0xFF;
b[18] = (b[18] + (b[29] + b[0] + b[14] + b[21] + b[24] + b[2] + 70)) & 255;
b[27] = (b[27] + (b[13] + b[31] + b[1] + b[23] + b[43] + b[17] + 248)) & 255;
b[21] = (b[21] - (b[32] + b[16] + b[27] + b[17] + b[10] + b[15] + 37)) & 255;
b[2] ^= (b[32] + b[41] + b[24] + b[22] + b[17] + b[21] + 18) & 0xFF;
b[20] ^= (b[14] + b[7] + b[4] + b[0] + b[29] + b[8] + 172) & 0xFF;
b[23] = (b[23] + (b[32] + b[13] + b[35] + b[34] + b[14] + b[1] + 195)) & 255;
b[0] ^= (b[40] + b[36] + b[42] + b[23] + b[17] + b[34] + 149) & 0xFF;
b[39] = (b[39] + (b[18] + b[28] + b[42] + b[40] + b[2] + b[11] + 91)) & 255;
b[31] = (b[31] - (b[8] + b[42] + b[38] + b[19] + b[22] + b[25] + 138)) & 255;
b[38] = (b[38] - (b[27] + b[5] + b[3] + b[19] + b[2] + b[18] + 8)) & 255;
b[24] = (b[24] + (b[8] + b[35] + b[21] + b[9] + b[2] + b[22] + 20)) & 255;
b[20] ^= (b[34] + b[23] + b[21] + b[0] + b[25] + b[12] + 14) & 0xFF;
b[42] = (b[42] - (b[7] + b[13] + b[3] + b[6] + b[28] + b[5] + 243)) & 255;
b[26] = (b[26] - (b[29] + b[27] + b[2] + b[3] + b[5] + b[9] + 244)) & 255;
b[40] ^= (b[30] + b[28] + b[20] + b[33] + b[9] + b[22] + 84) & 0xFF;
b[33] = (b[33] + (b[28] + b[34] + b[27] + b[36] + b[3] + b[39] + 238)) & 255;
b[6] = (b[6] + (b[30] + b[29] + b[14] + b[35] + b[15] + b[20] + 20)) & 255;
b[5] = (b[5] - (b[15] + b[20] + b[28] + b[38] + b[35] + b[16] + 190)) & 255;
b[42] ^= (b[43] + b[6] + b[18] + b[1] + b[12] + b[23] + 96) & 0xFF;
b[31] = (b[31] + (b[29] + b[17] + b[0] + b[13] + b[5] + b[40] + 136)) & 255;
b[41] = (b[41] + (b[27] + b[21] + b[24] + b[22] + b[28] + b[12] + 139)) & 255;
b[23] = (b[23] - (b[34] + b[7] + b[32] + b[2] + b[12] + b[11] + 30)) & 255;
b[33] = (b[33] - (b[21] + b[9] + b[31] + b[6] + b[20] + b[11] + 1)) & 255;
b[32] = (b[32] - (b[1] + b[2] + b[18] + b[43] + b[27] + b[29] + 127)) & 255;
b[3] = (b[3] + (b[38] + b[9] + b[11] + b[8] + b[34] + b[7] + 167)) & 255;
b[5] = (b[5] - (b[25] + b[38] + b[18] + b[34] + b[24] + b[20] + 89)) & 255;
b[35] ^= (b[24] + b[43] + b[21] + b[2] + b[34] + b[40] + 28) & 0xFF;
b[7] ^= (b[16] + b[24] + b[28] + b[32] + b[4] + b[5] + 246) & 0xFF;
b[11] ^= (b[30] + b[38] + b[6] + b[22] + b[3] + b[18] + 218) & 0xFF;
b[3] ^= (b[17] + b[22] + b[20] + b[7] + b[12] + b[14] + 152) & 0xFF;
b[35] ^= (b[37] + b[43] + b[27] + b[22] + b[31] + b[15] + 150) & 0xFF;
b[13] = (b[13] - (b[14] + b[35] + b[43] + b[3] + b[16] + b[31] + 210)) & 255;
b[21] = (b[21] + (b[31] + b[13] + b[2] + b[15] + b[34] + b[37] + 41)) & 255;
b[17] = (b[17] + (b[2] + b[34] + b[10] + b[20] + b[13] + b[37] + 205)) & 255;
b[22] = (b[22] + (b[29] + b[7] + b[32] + b[34] + b[4] + b[36] + 113)) & 255;
b[39] = (b[39] + (b[30] + b[27] + b[6] + b[31] + b[13] + b[42] + 106)) & 255;
b[32] ^= (b[4] + b[14] + b[43] + b[42] + b[9] + b[27] + 187) & 0xFF;
b[14] = (b[14] - (b[39] + b[4] + b[25] + b[27] + b[35] + b[7] + 0)) & 255;
b[11] = (b[11] + (b[24] + b[9] + b[13] + b[33] + b[39] + b[22] + 116)) & 255;
b[37] ^= (b[33] + b[7] + b[1] + b[35] + b[36] + b[19] + 206) & 0xFF;
b[1] = (b[1] + (b[32] + b[42] + b[41] + b[33] + b[39] + b[28] + 75)) & 255;
b[2] = (b[2] + (b[10] + b[36] + b[13] + b[22] + b[27] + b[14] + 61)) & 255;
b[42] = (b[42] + (b[24] + b[9] + b[29] + b[41] + b[23] + b[33] + 28)) & 255;
b[6] = (b[6] + (b[16] + b[25] + b[36] + b[40] + b[31] + b[5] + 50)) & 255;
b[25] = (b[25] + (b[20] + b[5] + b[21] + b[22] + b[17] + b[1] + 130)) & 255;
b[23] = (b[23] - (b[30] + b[6] + b[10] + b[40] + b[15] + b[37] + 35)) & 255;
b[31] = (b[31] + (b[33] + b[6] + b[1] + b[29] + b[23] + b[4] + 89)) & 255;
b[12] = (b[12] + (b[8] + b[0] + b[3] + b[24] + b[33] + b[42] + 152)) & 255;
b[7] = (b[7] - (b[4] + b[34] + b[24] + b[30] + b[35] + b[20] + 225)) & 255;
b[28] ^= (b[23] + b[19] + b[38] + b[31] + b[32] + b[18] + 118) & 0xFF;
b[26] = (b[26] + (b[31] + b[22] + b[40] + b[23] + b[4] + b[25] + 15)) & 255;
b[23] = (b[23] - (b[15] + b[32] + b[35] + b[0] + b[8] + b[22] + 146)) & 255;
b[22] = (b[22] + (b[1] + b[40] + b[13] + b[17] + b[38] + b[20] + 151)) & 255;
b[30] ^= (b[16] + b[40] + b[42] + b[32] + b[2] + b[41] + 149) & 0xFF;
b[0] = (b[0] - (b[39] + b[5] + b[14] + b[43] + b[25] + b[36] + 164)) & 255;
b[42] = (b[42] - (b[36] + b[41] + b[12] + b[21] + b[19] + b[23] + 89)) & 255;
b[12] = (b[12] - (b[40] + b[9] + b[38] + b[37] + b[36] + b[31] + 169)) & 255;
b[3] = (b[3] + (b[26] + b[35] + b[23] + b[36] + b[10] + b[5] + 33)) & 255;
b[14] = (b[14] + (b[35] + b[18] + b[2] + b[22] + b[33] + b[25] + 213)) & 255;
b[16] = (b[16] - (b[30] + b[0] + b[3] + b[34] + b[15] + b[21] + 26)) & 255;
b[21] ^= (b[5] + b[27] + b[17] + b[2] + b[9] + b[6] + 122) & 0xFF;
b[30] ^= (b[43] + b[38] + b[12] + b[33] + b[34] + b[11] + 8) & 0xFF;
b[5] = (b[5] + (b[31] + b[43] + b[1] + b[8] + b[6] + b[41] + 246)) & 255;
b[43] ^= (b[11] + b[17] + b[36] + b[26] + b[30] + b[8] + 200) & 0xFF;
b[0] ^= (b[26] + b[4] + b[34] + b[16] + b[15] + b[7] + 115) & 0xFF;
b[0] = (b[0] + (b[34] + b[3] + b[41] + b[28] + b[29] + b[36] + 187)) & 255;
b[32] ^= (b[41] + b[30] + b[5] + b[23] + b[28] + b[39] + 217) & 0xFF;
b[23] = (b[23] - (b[36] + b[26] + b[8] + b[4] + b[10] + b[7] + 147)) & 255;
b[0] ^= (b[21] + b[10] + b[29] + b[30] + b[13] + b[17] + 60) & 0xFF;
b[0] = (b[0] - (b[17] + b[10] + b[16] + b[38] + b[22] + b[15] + 112)) & 255;
b[22] = (b[22] + (b[13] + b[6] + b[1] + b[23] + b[43] + b[32] + 120)) & 255;
b[34] = (b[34] - (b[30] + b[17] + b[38] + b[41] + b[5] + b[42] + 170)) & 255;
b[22] = (b[22] - (b[37] + b[26] + b[14] + b[41] + b[30] + b[6] + 248)) & 255;
b[28] ^= (b[13] + b[9] + b[35] + b[23] + b[18] + b[39] + 117) & 0xFF;
b[21] = (b[21] + (b[4] + b[31] + b[25] + b[22] + b[2] + b[3] + 237)) & 255;
b[10] = (b[10] + (b[25] + b[0] + b[28] + b[35] + b[5] + b[30] + 240)) & 255;
b[10] = (b[10] - (b[9] + b[39] + b[6] + b[32] + b[11] + b[35] + 18)) & 255;
b[33] = (b[33] - (b[40] + b[17] + b[43] + b[21] + b[36] + b[23] + 76)) & 255;
b[6] ^= (b[24] + b[19] + b[12] + b[10] + b[8] + b[34] + 3) & 0xFF;
b[12] = (b[12] + (b[1] + b[33] + b[11] + b[10] + b[37] + b[8] + 155)) & 255;
b[27] = (b[27] - (b[17] + b[7] + b[0] + b[1] + b[34] + b[14] + 128)) & 255;
b[1] = (b[1] + (b[20] + b[32] + b[25] + b[35] + b[10] + b[18] + 147)) & 255;
b[11] ^= (b[5] + b[20] + b[14] + b[28] + b[42] + b[22] + 149) & 0xFF;
b[24] ^= (b[38] + b[40] + b[42] + b[25] + b[13] + b[43] + 64) & 0xFF;
b[42] = (b[42] - (b[43] + b[7] + b[18] + b[20] + b[2] + b[9] + 43)) & 255;
b[36] = (b[36] - (b[6] + b[21] + b[18] + b[31] + b[15] + b[7] + 176)) & 255;
b[4] = (b[4] - (b[8] + b[13] + b[3] + b[34] + b[22] + b[14] + 246)) & 255;
b[10] = (b[10] + (b[23] + b[32] + b[37] + b[28] + b[39] + b[21] + 233)) & 255;
b[34] = (b[34] + (b[15] + b[29] + b[5] + b[2] + b[39] + b[0] + 153)) & 255;
b[1] = (b[1] + (b[37] + b[40] + b[30] + b[6] + b[38] + b[19] + 192)) & 255;
b[20] = (b[20] - (b[34] + b[25] + b[10] + b[3] + b[31] + b[37] + 136)) & 255;
b[10] = (b[10] + (b[9] + b[32] + b[42] + b[41] + b[21] + b[8] + 100)) & 255;
b[31] = (b[31] - (b[4] + b[21] + b[19] + b[27] + b[37] + b[33] + 251)) & 255;
b[11] = (b[11] + (b[6] + b[19] + b[33] + b[43] + b[3] + b[21] + 60)) & 255;
b[20] = (b[20] + (b[19] + b[7] + b[11] + b[33] + b[18] + b[1] + 177)) & 255;
b[8] = (b[8] - (b[30] + b[1] + b[37] + b[6] + b[26] + b[10] + 198)) & 255;
b[4] = (b[4] + (b[1] + b[17] + b[0] + b[15] + b[19] + b[41] + 192)) & 255;
b[25] = (b[25] - (b[10] + b[31] + b[30] + b[21] + b[3] + b[40] + 227)) & 255;
b[4] = (b[4] + (b[38] + b[0] + b[13] + b[16] + b[3] + b[18] + 170)) & 255;
b[30] ^= (b[29] + b[4] + b[10] + b[40] + b[7] + b[9] + 189) & 0xFF;
b[8] = (b[8] + (b[12] + b[6] + b[1] + b[21] + b[28] + b[25] + 55)) & 255;
b[25] = (b[25] - (b[40] + b[2] + b[18] + b[35] + b[15] + b[32] + 16)) & 255;
b[37] = (b[37] + (b[30] + b[21] + b[35] + b[13] + b[19] + b[26] + 208)) & 255;
b[24] ^= (b[14] + b[33] + b[2] + b[26] + b[19] + b[8] + 75) & 0xFF;
b[20] = (b[20] - (b[3] + b[12] + b[40] + b[43] + b[15] + b[28] + 205)) & 255;
b[33] = (b[33] + (b[16] + b[13] + b[1] + b[29] + b[30] + b[40] + 77)) & 255;
b[32] ^= (b[16] + b[4] + b[23] + b[8] + b[41] + b[29] + 142) & 0xFF;
b[43] = (b[43] - (b[11] + b[15] + b[33] + b[35] + b[21] + b[25] + 197)) & 255;
b[28] = (b[28] - (b[40] + b[23] + b[20] + b[36] + b[22] + b[27] + 232)) & 255;
b[33] = (b[33] - (b[11] + b[10] + b[29] + b[31] + b[42] + b[1] + 145)) & 255;
b[26] = (b[26] + (b[23] + b[16] + b[41] + b[7] + b[27] + b[18] + 119)) & 255;
b[21] = (b[21] - (b[1] + b[30] + b[36] + b[43] + b[3] + b[25] + 219)) & 255;
b[2] ^= (b[8] + b[28] + b[29] + b[26] + b[37] + b[39] + 54) & 0xFF;
b[34] ^= (b[23] + b[28] + b[8] + b[20] + b[33] + b[5] + 71) & 0xFF;
b[31] ^= (b[28] + b[32] + b[14] + b[26] + b[18] + b[35] + 246) & 0xFF;
b[13] ^= (b[14] + b[35] + b[22] + b[4] + b[23] + b[20] + 101) & 0xFF;
b[31] = (b[31] - (b[21] + b[35] + b[22] + b[17] + b[7] + b[0] + 20)) & 255;
b[6] = (b[6] - (b[4] + b[40] + b[15] + b[37] + b[12] + b[23] + 160)) & 255;
b[31] ^= (b[26] + b[43] + b[7] + b[37] + b[25] + b[34] + 192) & 0xFF;
b[40] = (b[40] + (b[21] + b[3] + b[14] + b[13] + b[20] + b[5] + 5)) & 255;
b[14] ^= (b[32] + b[30] + b[20] + b[11] + b[3] + b[41] + 154) & 0xFF;
b[38] = (b[38] - (b[4] + b[32] + b[6] + b[26] + b[25] + b[22] + 44)) & 255;
b[26] = (b[26] - (b[16] + b[38] + b[12] + b[25] + b[24] + b[0] + 68)) & 255;
b[22] = (b[22] + (b[33] + b[18] + b[11] + b[27] + b[41] + b[31] + 208)) & 255;
b[5] = (b[5] - (b[6] + b[36] + b[20] + b[33] + b[23] + b[26] + 186)) & 255;
b[19] ^= (b[26] + b[28] + b[24] + b[20] + b[29] + b[30] + 198) & 0xFF;
b[31] = (b[31] + (b[22] + b[41] + b[24] + b[34] + b[3] + b[37] + 95)) & 255;
b[32] = (b[32] + (b[4] + b[35] + b[22] + b[40] + b[28] + b[39] + 46)) & 255;
b[8] = (b[8] - (b[13] + b[4] + b[36] + b[28] + b[17] + b[39] + 118)) & 255;
b[11] ^= (b[36] + b[0] + b[6] + b[21] + b[32] + b[18] + 134) & 0xFF;
b[22] ^= (b[0] + b[36] + b[28] + b[14] + b[4] + b[18] + 25) & 0xFF;
b[14] ^= (b[41] + b[5] + b[40] + b[33] + b[35] + b[10] + 94) & 0xFF;
b[42] ^= (b[13] + b[2] + b[20] + b[16] + b[6] + b[34] + 159) & 0xFF;
b[42] ^= (b[14] + b[6] + b[29] + b[16] + b[10] + b[43] + 254) & 0xFF;
b[0] ^= (b[20] + b[18] + b[34] + b[43] + b[26] + b[2] + 224) & 0xFF;
b[19] ^= (b[3] + b[6] + b[5] + b[33] + b[32] + b[10] + 194) & 0xFF;
b[32] = (b[32] - (b[42] + b[43] + b[34] + b[17] + b[5] + b[0] + 94)) & 255;
b[20] ^= (b[24] + b[32] + b[29] + b[9] + b[6] + b[35] + 217) & 0xFF;
b[8] ^= (b[13] + b[26] + b[10] + b[4] + b[32] + b[21] + 142) & 0xFF;
b[27] = (b[27] + (b[1] + b[26] + b[10] + b[29] + b[14] + b[4] + 32)) & 255;
b[7] = (b[7] - (b[6] + b[35] + b[1] + b[40] + b[36] + b[33] + 95)) & 255;
b[39] = (b[39] - (b[27] + b[20] + b[15] + b[29] + b[36] + b[16] + 196)) & 255;
b[4] = (b[4] - (b[34] + b[7] + b[2] + b[39] + b[5] + b[43] + 139)) & 255;
b[27] ^= (b[6] + b[24] + b[16] + b[19] + b[13] + b[14] + 35) & 0xFF;
b[30] ^= (b[17] + b[15] + b[18] + b[43] + b[29] + b[16] + 27) & 0xFF;
b[20] ^= (b[28] + b[7] + b[15] + b[3] + b[12] + b[19] + 246) & 0xFF;
b[6] = (b[6] - (b[24] + b[36] + b[43] + b[29] + b[16] + b[10] + 182)) & 255;
b[19] ^= (b[13] + b[36] + b[38] + b[1] + b[2] + b[24] + 210) & 0xFF;
b[4] = (b[4] + (b[42] + b[6] + b[26] + b[39] + b[35] + b[16] + 80)) & 255;
b[38] = (b[38] + (b[24] + b[23] + b[36] + b[32] + b[7] + b[2] + 136)) & 255;
b[25] = (b[25] + (b[31] + b[7] + b[30] + b[38] + b[39] + b[29] + 174)) & 255;
b[29] = (b[29] - (b[43] + b[39] + b[38] + b[26] + b[28] + b[17] + 103)) & 255;
b[39] = (b[39] + (b[8] + b[14] + b[41] + b[13] + b[15] + b[33] + 164)) & 255;
b[17] = (b[17] - (b[3] + b[13] + b[37] + b[25] + b[8] + b[0] + 53)) & 255;
b[38] = (b[38] + (b[14] + b[3] + b[35] + b[40] + b[6] + b[5] + 122)) & 255;
b[31] = (b[31] - (b[13] + b[16] + b[43] + b[33] + b[35] + b[41] + 129)) & 255;
b[43] = (b[43] - (b[26] + b[3] + b[25] + b[0] + b[31] + b[21] + 81)) & 255;
b[16] ^= (b[13] + b[41] + b[3] + b[40] + b[8] + b[14] + 17) & 0xFF;
b[40] = (b[40] - (b[12] + b[8] + b[31] + b[28] + b[4] + b[2] + 26)) & 255;
b[32] ^= (b[18] + b[11] + b[42] + b[1] + b[27] + b[14] + 241) & 0xFF;
b[25] = (b[25] + (b[17] + b[0] + b[37] + b[39] + b[11] + b[28] + 228)) & 255;
b[17] ^= (b[20] + b[32] + b[10] + b[38] + b[24] + b[29] + 57) & 0xFF;
b[8] = (b[8] - (b[3] + b[20] + b[16] + b[17] + b[22] + b[24] + 15)) & 255;
b[24] = (b[24] - (b[39] + b[14] + b[18] + b[36] + b[15] + b[27] + 142)) & 255;
b[30] ^= (b[27] + b[40] + b[17] + b[43] + b[16] + b[6] + 73) & 0xFF;
b[25] ^= (b[43] + b[5] + b[32] + b[38] + b[35] + b[21] + 32) & 0xFF;
b[24] ^= (b[8] + b[30] + b[3] + b[41] + b[36] + b[7] + 136) & 0xFF;
b[2] ^= (b[29] + b[1] + b[26] + b[42] + b[12] + b[10] + 81) & 0xFF;
b[8] = (b[8] - (b[1] + b[25] + b[39] + b[34] + b[24] + b[9] + 172)) & 255;
b[25] = (b[25] + (b[2] + b[19] + b[29] + b[3] + b[14] + b[40] + 151)) & 255;
b[37] = (b[37] + (b[3] + b[31] + b[12] + b[28] + b[41] + b[2] + 222)) & 255;
b[15] ^= (b[36] + b[23] + b[31] + b[0] + b[20] + b[5] + 20) & 0xFF;
b[27] = (b[27] + (b[7] + b[1] + b[42] + b[29] + b[32] + b[16] + 128)) & 255;
b[13] ^= (b[32] + b[35] + b[10] + b[16] + b[40] + b[22] + 187) & 0xFF;
b[26] = (b[26] - (b[16] + b[36] + b[33] + b[2] + b[13] + b[20] + 17)) & 255;
b[11] ^= (b[24] + b[26] + b[20] + b[28] + b[15] + b[35] + 7) & 0xFF;
b[24] ^= (b[29] + b[39] + b[20] + b[38] + b[37] + b[10] + 148) & 0xFF;
b[33] ^= (b[39] + b[15] + b[37] + b[20] + b[5] + b[29] + 42) & 0xFF;
b[20] = (b[20] - (b[21] + b[0] + b[32] + b[13] + b[8] + b[11] + 37)) & 255;
b[18] = (b[18] - (b[41] + b[12] + b[19] + b[4] + b[9] + b[21] + 22)) & 255;
b[19] ^= (b[12] + b[1] + b[34] + b[8] + b[4] + b[37] + 22) & 0xFF;
b[13] = (b[13] - (b[25] + b[26] + b[22] + b[15] + b[19] + b[14] + 68)) & 255;
b[8] ^= (b[33] + b[32] + b[39] + b[12] + b[20] + b[7] + 34) & 0xFF;
b[18] ^= (b[36] + b[26] + b[27] + b[7] + b[14] + b[15] + 22) & 0xFF;
b[8] = (b[8] - (b[30] + b[19] + b[3] + b[13] + b[35] + b[18] + 222)) & 255;
b[9] = (b[9] - (b[38] + b[29] + b[25] + b[2] + b[32] + b[21] + 73)) & 255;
b[28] = (b[28] - (b[40] + b[23] + b[19] + b[20] + b[13] + b[43] + 220)) & 255;
b[27] = (b[27] - (b[13] + b[37] + b[23] + b[17] + b[2] + b[43] + 254)) & 255;
b[1] = (b[1] + (b[27] + b[6] + b[10] + b[23] + b[35] + b[22] + 110)) & 255;
b[9] = (b[9] - (b[41] + b[31] + b[7] + b[36] + b[20] + b[42] + 182)) & 255;
b[27] = (b[27] - (b[16] + b[5] + b[12] + b[2] + b[43] + b[20] + 84)) & 255;
b[6] = (b[6] + (b[11] + b[8] + b[37] + b[39] + b[12] + b[33] + 185)) & 255;
b[25] = (b[25] + (b[11] + b[17] + b[34] + b[36] + b[4] + b[41] + 109)) & 255;
b[43] = (b[43] - (b[1] + b[24] + b[31] + b[29] + b[35] + b[42] + 3)) & 255;
b[14] = (b[14] + (b[24] + b[16] + b[41] + b[28] + b[34] + b[5] + 255)) & 255;
b[4] = (b[4] - (b[23] + b[19] + b[28] + b[41] + b[31] + b[43] + 205)) & 255;
b[32] = (b[32] - (b[22] + b[25] + b[2] + b[43] + b[37] + b[28] + 77)) & 255;
b[17] ^= (b[10] + b[0] + b[43] + b[36] + b[26] + b[33] + 175) & 0xFF;
b[34] = (b[34] - (b[11] + b[6] + b[35] + b[15] + b[36] + b[21] + 159)) & 255;
b[38] ^= (b[6] + b[42] + b[15] + b[31] + b[36] + b[7] + 155) & 0xFF;
b[33] = (b[33] - (b[21] + b[13] + b[25] + b[29] + b[36] + b[18] + 139)) & 255;
b[26] = (b[26] - (b[9] + b[2] + b[43] + b[10] + b[18] + b[11] + 190)) & 255;
b[7] = (b[7] + (b[11] + b[43] + b[13] + b[8] + b[19] + b[23] + 19)) & 255;
b[7] = (b[7] + (b[41] + b[40] + b[13] + b[19] + b[17] + b[38] + 45)) & 255;
b[38] = (b[38] - (b[22] + b[26] + b[9] + b[29] + b[40] + b[1] + 10)) & 255;
b[7] = (b[7] + (b[30] + b[35] + b[16] + b[23] + b[40] + b[22] + 160)) & 255;
b[23] = (b[23] - (b[18] + b[1] + b[38] + b[22] + b[20] + b[4] + 124)) & 255;
b[0] = (b[0] + (b[43] + b[42] + b[30] + b[40] + b[11] + b[29] + 98)) & 255;
b[3] ^= (b[19] + b[31] + b[1] + b[26] + b[6] + b[36] + 149) & 0xFF;
b[8] = (b[8] + (b[40] + b[12] + b[41] + b[20] + b[5] + b[30] + 146)) & 255;
b[29] = (b[29] - (b[13] + b[1] + b[28] + b[14] + b[41] + b[26] + 3)) & 255;
b[18] = (b[18] + (b[14] + b[23] + b[13] + b[37] + b[20] + b[32] + 70)) & 255;
b[3] = (b[3] + (b[13] + b[30] + b[9] + b[28] + b[32] + b[38] + 241)) & 255;
b[29] ^= (b[34] + b[20] + b[30] + b[35] + b[8] + b[5] + 90) & 0xFF;
b[35] = (b[35] - (b[30] + b[7] + b[3] + b[40] + b[20] + b[34] + 255)) & 255;
b[33] = (b[33] - (b[17] + b[7] + b[26] + b[18] + b[36] + b[11] + 113)) & 255;
b[27] = (b[27] + (b[43] + b[35] + b[6] + b[22] + b[12] + b[42] + 49)) & 255;
b[11] = (b[11] - (b[5] + b[30] + b[23] + b[35] + b[26] + b[41] + 80)) & 255;
b[4] = (b[4] + (b[11] + b[36] + b[40] + b[38] + b[16] + b[6] + 149)) & 255;
b[39] ^= (b[11] + b[23] + b[31] + b[20] + b[42] + b[30] + 94) & 0xFF;
b[27] ^= (b[25] + b[29] + b[34] + b[13] + b[41] + b[5] + 145) & 0xFF;
b[3] = (b[3] + (b[29] + b[14] + b[12] + b[39] + b[32] + b[28] + 145)) & 255;
b[21] ^= (b[30] + b[4] + b[41] + b[6] + b[22] + b[9] + 224) & 0xFF;
b[4] = (b[4] - (b[29] + b[33] + b[34] + b[20] + b[9] + b[17] + 77)) & 255;
b[18] = (b[18] - (b[17] + b[43] + b[26] + b[10] + b[30] + b[16] + 6)) & 255;
b[22] = (b[22] - (b[41] + b[28] + b[25] + b[26] + b[0] + b[23] + 162)) & 255;
b[27] = (b[27] + (b[21] + b[18] + b[38] + b[1] + b[40] + b[12] + 174)) & 255;
b[3] = (b[3] + (b[31] + b[37] + b[33] + b[7] + b[23] + b[32] + 157)) & 255;
b[24] ^= (b[23] + b[19] + b[1] + b[13] + b[3] + b[2] + 245) & 0xFF;
b[24] = (b[24] + (b[43] + b[5] + b[36] + b[9] + b[30] + b[3] + 160)) & 255;
b[9] = (b[9] - (b[31] + b[37] + b[29] + b[27] + b[11] + b[13] + 216)) & 255;
b[16] = (b[16] - (b[13] + b[41] + b[6] + b[3] + b[29] + b[39] + 206)) & 255;
b[31] = (b[31] + (b[39] + b[35] + b[34] + b[43] + b[38] + b[20] + 173)) & 255;
b[4] = (b[4] + (b[8] + b[24] + b[29] + b[30] + b[41] + b[43] + 121)) & 255;
b[36] = (b[36] + (b[5] + b[41] + b[23] + b[27] + b[16] + b[31] + 110)) & 255;
b[34] = (b[34] + (b[28] + b[8] + b[13] + b[16] + b[24] + b[1] + 237)) & 255;
b[34] = (b[34] - (b[37] + b[2] + b[43] + b[28] + b[16] + b[30] + 214)) & 255;
b[6] = (b[6] - (b[17] + b[7] + b[32] + b[39] + b[31] + b[14] + 1)) & 255;
b[8] = (b[8] - (b[36] + b[38] + b[6] + b[33] + b[27] + b[32] + 188)) & 255;
b[39] = (b[39] - (b[18] + b[27] + b[15] + b[20] + b[28] + b[9] + 242)) & 255;
b[14] = (b[14] + (b[35] + b[20] + b[10] + b[4] + b[16] + b[28] + 173)) & 255;
b[38] = (b[38] + (b[15] + b[13] + b[3] + b[22] + b[34] + b[12] + 184)) & 255;
b[14] = (b[14] - (b[24] + b[26] + b[11] + b[19] + b[6] + b[17] + 150)) & 255;
b[3] ^= (b[13] + b[29] + b[8] + b[11] + b[38] + b[21] + 140) & 0xFF;
b[12] = (b[12] + (b[18] + b[2] + b[17] + b[7] + b[41] + b[32] + 165)) & 255;
b[21] ^= (b[36] + b[31] + b[1] + b[20] + b[43] + b[17] + 224) & 0xFF;
b[40] = (b[40] + (b[2] + b[17] + b[26] + b[8] + b[24] + b[23] + 239)) & 255;
b[35] ^= (b[4] + b[0] + b[29] + b[18] + b[28] + b[22] + 218) & 0xFF;
b[23] ^= (b[17] + b[16] + b[3] + b[30] + b[24] + b[43] + 7) & 0xFF;
b[34] = (b[34] + (b[5] + b[10] + b[15] + b[2] + b[25] + b[26] + 41)) & 255;
b[1] = (b[1] - (b[20] + b[2] + b[25] + b[31] + b[4] + b[18] + 7)) & 255;
b[20] = (b[20] - (b[7] + b[37] + b[5] + b[0] + b[34] + b[17] + 57)) & 255;
b[6] = (b[6] - (b[36] + b[29] + b[27] + b[23] + b[3] + b[19] + 190)) & 255;
b[3] = (b[3] + (b[31] + b[37] + b[34] + b[25] + b[11] + b[13] + 6)) & 255;
b[8] = (b[8] + (b[4] + b[19] + b[32] + b[43] + b[16] + b[27] + 75)) & 255;
b[25] ^= (b[29] + b[41] + b[32] + b[27] + b[3] + b[33] + 34) & 0xFF;
b[18] = (b[18] + (b[10] + b[5] + b[25] + b[35] + b[34] + b[20] + 228)) & 255;
b[16] = (b[16] + (b[39] + b[1] + b[19] + b[10] + b[14] + b[26] + 225)) & 255;
b[1] ^= (b[21] + b[5] + b[27] + b[36] + b[9] + b[23] + 51) & 0xFF;
b[38] = (b[38] - (b[4] + b[29] + b[22] + b[2] + b[14] + b[37] + 224)) & 255;
b[25] = (b[25] - (b[16] + b[21] + b[28] + b[35] + b[14] + b[37] + 212)) & 255;
b[6] ^= (b[41] + b[28] + b[20] + b[36] + b[40] + b[13] + 212) & 0xFF;
b[1] = (b[1] + (b[12] + b[17] + b[2] + b[36] + b[4] + b[35] + 13)) & 255;
b[19] = (b[19] + (b[36] + b[41] + b[40] + b[24] + b[33] + b[10] + 138)) & 255;
b[15] = (b[15] - (b[28] + b[16] + b[1] + b[8] + b[3] + b[19] + 5)) & 255;
b[8] ^= (b[33] + b[18] + b[35] + b[41] + b[39] + b[36] + 142) & 0xFF;
b[5] = (b[5] + (b[39] + b[26] + b[32] + b[13] + b[40] + b[31] + 242)) & 255;
b[16] ^= (b[11] + b[33] + b[22] + b[7] + b[0] + b[29] + 8) & 0xFF;
b[0] ^= (b[6] + b[24] + b[12] + b[35] + b[18] + b[20] + 222) & 0xFF;
b[24] ^= (b[39] + b[38] + b[0] + b[20] + b[5] + b[10] + 158) & 0xFF;
b[10] = (b[10] - (b[24] + b[28] + b[12] + b[3] + b[34] + b[8] + 83)) & 255;
b[35] = (b[35] - (b[13] + b[21] + b[32] + b[1] + b[10] + b[43] + 148)) & 255;
b[19] = (b[19] - (b[9] + b[41] + b[42] + b[31] + b[32] + b[15] + 14)) & 255;
b[37] = (b[37] - (b[18] + b[29] + b[11] + b[28] + b[13] + b[3] + 248)) & 255;
b[29] ^= (b[31] + b[38] + b[2] + b[43] + b[15] + b[33] + 61) & 0xFF;
b[27] = (b[27] + (b[14] + b[28] + b[34] + b[16] + b[41] + b[31] + 225)) & 255;
b[15] = (b[15] + (b[13] + b[42] + b[32] + b[39] + b[34] + b[28] + 116)) & 255;
b[6] = (b[6] + (b[30] + b[21] + b[2] + b[19] + b[35] + b[20] + 249)) & 255;
b[38] = (b[38] - (b[1] + b[8] + b[31] + b[39] + b[7] + b[18] + 150)) & 255;
b[3] = (b[3] + (b[8] + b[40] + b[10] + b[39] + b[16] + b[28] + 98)) & 255;
b[9] ^= (b[27] + b[15] + b[21] + b[36] + b[29] + b[25] + 178) & 0xFF;
b[40] = (b[40] + (b[13] + b[21] + b[8] + b[3] + b[10] + b[17] + 248)) & 255;
b[36] = (b[36] + (b[8] + b[7] + b[27] + b[43] + b[24] + b[15] + 174)) & 255;
b[32] = (b[32] - (b[40] + b[41] + b[19] + b[7] + b[36] + b[18] + 29)) & 255;
b[27] = (b[27] - (b[29] + b[16] + b[33] + b[18] + b[19] + b[35] + 222)) & 255;
b[23] = (b[23] - (b[0] + b[25] + b[10] + b[26] + b[38] + b[24] + 236)) & 255;
b[21] = (b[21] + (b[8] + b[30] + b[13] + b[22] + b[0] + b[5] + 34)) & 255;
b[22] = (b[22] - (b[43] + b[18] + b[23] + b[42] + b[17] + b[33] + 225)) & 255;
b[13] = (b[13] + (b[27] + b[28] + b[15] + b[40] + b[14] + b[8] + 70)) & 255;
b[4] ^= (b[36] + b[42] + b[22] + b[20] + b[15] + b[0] + 219) & 0xFF;
b[15] ^= (b[1] + b[17] + b[43] + b[19] + b[11] + b[39] + 153) & 0xFF;
b[35] ^= (b[12] + b[18] + b[39] + b[0] + b[10] + b[3] + 148) & 0xFF;
b[31] = (b[31] + (b[29] + b[40] + b[13] + b[24] + b[43] + b[30] + 59)) & 255;
b[37] = (b[37] - (b[10] + b[15] + b[41] + b[36] + b[1] + b[38] + 181)) & 255;
b[7] ^= (b[19] + b[3] + b[16] + b[1] + b[34] + b[33] + 110) & 0xFF;
b[30] = (b[30] + (b[33] + b[40] + b[38] + b[19] + b[36] + b[16] + 196)) & 255;
b[22] = (b[22] - (b[3] + b[21] + b[6] + b[18] + b[43] + b[0] + 13)) & 255;
b[36] ^= (b[28] + b[6] + b[34] + b[21] + b[41] + b[35] + 245) & 0xFF;
b[23] = (b[23] - (b[3] + b[28] + b[4] + b[27] + b[25] + b[10] + 21)) & 255;
b[10] ^= (b[18] + b[1] + b[20] + b[11] + b[31] + b[41] + 10) & 0xFF;
b[5] = (b[5] + (b[15] + b[33] + b[18] + b[20] + b[3] + b[22] + 88)) & 255;
b[32] ^= (b[28] + b[16] + b[41] + b[36] + b[22] + b[33] + 146) & 0xFF;
b[36] = (b[36] + (b[1] + b[33] + b[27] + b[20] + b[42] + b[17] + 173)) & 255;
b[22] ^= (b[32] + b[13] + b[42] + b[12] + b[33] + b[25] + 4) & 0xFF;
b[33] = (b[33] + (b[5] + b[41] + b[16] + b[32] + b[35] + b[36] + 200)) & 255;
b[33] = (b[33] - (b[18] + b[31] + b[4] + b[9] + b[35] + b[10] + 49)) & 255;
b[14] = (b[14] - (b[6] + b[26] + b[3] + b[23] + b[17] + b[43] + 15)) & 255;
b[2] = (b[2] - (b[39] + b[43] + b[38] + b[6] + b[18] + b[5] + 22)) & 255;
b[35] ^= (b[1] + b[29] + b[25] + b[5] + b[16] + b[10] + 221) & 0xFF;
b[19] = (b[19] + (b[38] + b[31] + b[9] + b[35] + b[29] + b[39] + 51)) & 255;
b[31] = (b[31] - (b[29] + b[22] + b[15] + b[10] + b[36] + b[18] + 227)) & 255;
b[40] = (b[40] - (b[39] + b[38] + b[24] + b[20] + b[1] + b[9] + 228)) & 255;
b[21] = (b[21] + (b[16] + b[41] + b[5] + b[30] + b[20] + b[32] + 51)) & 255;
b[18] ^= (b[28] + b[23] + b[35] + b[29] + b[13] + b[24] + 57) & 0xFF;
b[39] ^= (b[41] + b[25] + b[43] + b[30] + b[11] + b[1] + 63) & 0xFF;
b[41] = (b[41] + (b[25] + b[0] + b[40] + b[8] + b[5] + b[26] + 80)) & 255;
b[30] ^= (b[23] + b[12] + b[3] + b[28] + b[2] + b[18] + 53) & 0xFF;
b[6] ^= (b[2] + b[9] + b[16] + b[5] + b[10] + b[12] + 37) & 0xFF;
b[40] ^= (b[13] + b[15] + b[22] + b[24] + b[43] + b[39] + 144) & 0xFF;
b[9] = (b[9] - (b[7] + b[19] + b[29] + b[30] + b[38] + b[13] + 60)) & 255;
b[0] ^= (b[7] + b[11] + b[4] + b[23] + b[42] + b[14] + 73) & 0xFF;
b[34] = (b[34] + (b[4] + b[3] + b[43] + b[38] + b[23] + b[7] + 236)) & 255;
b[4] = (b[4] - (b[5] + b[28] + b[39] + b[15] + b[6] + b[3] + 154)) & 255;
b[38] ^= (b[22] + b[36] + b[17] + b[14] + b[35] + b[25] + 55) & 0xFF;
b[34] ^= (b[19] + b[42] + b[22] + b[13] + b[8] + b[3] + 68) & 0xFF;
b[41] = (b[41] - (b[24] + b[30] + b[13] + b[23] + b[5] + b[17] + 64)) & 255;
b[11] ^= (b[31] + b[20] + b[13] + b[27] + b[24] + b[21] + 114) & 0xFF;
b[41] = (b[41] + (b[17] + b[20] + b[19] + b[38] + b[18] + b[29] + 30)) & 255;
b[6] ^= (b[23] + b[13] + b[20] + b[11] + b[40] + b[16] + 23) & 0xFF;
b[37] = (b[37] - (b[8] + b[6] + b[10] + b[2] + b[36] + b[14] + 116)) & 255;
b[8] = (b[8] - (b[41] + b[25] + b[32] + b[1] + b[15] + b[6] + 182)) & 255;
b[26] = (b[26] + (b[18] + b[1] + b[32] + b[39] + b[0] + b[7] + 200)) & 255;
b[24] = (b[24] + (b[10] + b[39] + b[23] + b[28] + b[14] + b[2] + 121)) & 255;
b[19] ^= (b[8] + b[3] + b[22] + b[30] + b[26] + b[2] + 4) & 0xFF;
b[12] = (b[12] + (b[26] + b[30] + b[17] + b[32] + b[22] + b[43] + 72)) & 255;
b[12] ^= (b[5] + b[8] + b[25] + b[3] + b[7] + b[13] + 145) & 0xFF;
b[26] ^= (b[24] + b[7] + b[11] + b[12] + b[38] + b[3] + 20) & 0xFF;
b[14] = (b[14] - (b[20] + b[11] + b[21] + b[38] + b[28] + b[6] + 166)) & 255;
b[20] ^= (b[40] + b[15] + b[25] + b[34] + b[19] + b[42] + 251) & 0xFF;
b[23] = (b[23] - (b[33] + b[15] + b[16] + b[41] + b[12] + b[25] + 182)) & 255;
b[29] = (b[29] + (b[37] + b[9] + b[0] + b[16] + b[2] + b[28] + 203)) & 255;
b[40] ^= (b[10] + b[30] + b[6] + b[27] + b[39] + b[9] + 254) & 0xFF;
b[42] ^= (b[37] + b[35] + b[18] + b[36] + b[1] + b[14] + 95) & 0xFF;
b[26] = (b[26] - (b[8] + b[15] + b[16] + b[17] + b[39] + b[42] + 151)) & 255;
b[18] = (b[18] - (b[19] + b[6] + b[15] + b[40] + b[3] + b[32] + 191)) & 255;
b[41] ^= (b[2] + b[38] + b[5] + b[9] + b[23] + b[31] + 230) & 0xFF;
b[9] = (b[9] - (b[37] + b[41] + b[4] + b[20] + b[0] + b[18] + 175)) & 255;
b[21] = (b[21] - (b[29] + b[3] + b[17] + b[22] + b[41] + b[18] + 133)) & 255;
b[11] = (b[11] - (b[14] + b[0] + b[4] + b[20] + b[7] + b[27] + 253)) & 255;
b[13] = (b[13] + (b[34] + b[1] + b[31] + b[15] + b[12] + b[8] + 206)) & 255;
b[3] = (b[3] - (b[5] + b[18] + b[10] + b[14] + b[43] + b[31] + 44)) & 255;
b[32] = (b[32] + (b[4] + b[22] + b[25] + b[13] + b[27] + b[1] + 79)) & 255;
b[25] = (b[25] - (b[31] + b[36] + b[12] + b[5] + b[9] + b[3] + 94)) & 255;
b[26] ^= (b[33] + b[15] + b[20] + b[37] + b[5] + b[36] + 78) & 0xFF;
b[27] = (b[27] + (b[41] + b[26] + b[11] + b[22] + b[17] + b[16] + 244)) & 255;
b[34] = (b[34] - (b[14] + b[10] + b[4] + b[29] + b[12] + b[30] + 205)) & 255;
b[14] ^= (b[25] + b[4] + b[33] + b[9] + b[17] + b[0] + 221) & 0xFF;
b[41] ^= (b[5] + b[40] + b[39] + b[2] + b[3] + b[31] + 16) & 0xFF;
b[1] = (b[1] + (b[36] + b[28] + b[19] + b[30] + b[21] + b[17] + 98)) & 255;
b[39] ^= (b[30] + b[13] + b[42] + b[17] + b[37] + b[1] + 213) & 0xFF;
b[7] = (b[7] + (b[38] + b[42] + b[28] + b[6] + b[16] + b[25] + 127)) & 255;
b[28] = (b[28] - (b[12] + b[26] + b[3] + b[22] + b[41] + b[36] + 178)) & 255;
b[15] ^= (b[20] + b[3] + b[36] + b[7] + b[9] + b[39] + 218) & 0xFF;
b[21] = (b[21] + (b[40] + b[1] + b[9] + b[38] + b[34] + b[25] + 186)) & 255;
b[11] ^= (b[40] + b[18] + b[21] + b[31] + b[5] + b[15] + 125) & 0xFF;
b[3] = (b[3] + (b[37] + b[33] + b[6] + b[19] + b[22] + b[21] + 15)) & 255;
b[6] = (b[6] + (b[10] + b[34] + b[17] + b[28] + b[26] + b[13] + 142)) & 255;
b[5] = (b[5] - (b[39] + b[18] + b[43] + b[8] + b[15] + b[14] + 95)) & 255;
b[33] = (b[33] - (b[27] + b[9] + b[21] + b[38] + b[23] + b[5] + 150)) & 255;
b[13] = (b[13] - (b[11] + b[41] + b[17] + b[6] + b[22] + b[8] + 130)) & 255;
b[33] = (b[33] + (b[30] + b[12] + b[32] + b[34] + b[18] + b[40] + 2)) & 255;
b[38] = (b[38] - (b[2] + b[5] + b[24] + b[8] + b[11] + b[20] + 115)) & 255;
b[39] ^= (b[1] + b[38] + b[10] + b[5] + b[23] + b[19] + 138) & 0xFF;
b[34] ^= (b[30] + b[6] + b[13] + b[35] + b[3] + b[26] + 241) & 0xFF;
b[31] = (b[31] - (b[42] + b[30] + b[1] + b[20] + b[40] + b[18] + 198)) & 255;
b[22] ^= (b[6] + b[32] + b[27] + b[2] + b[13] + b[3] + 191) & 0xFF;
b[12] = (b[12] + (b[23] + b[2] + b[10] + b[5] + b[30] + b[27] + 195)) & 255;
b[22] ^= (b[29] + b[33] + b[20] + b[30] + b[0] + b[25] + 9) & 0xFF;
b[24] = (b[24] + (b[33] + b[37] + b[21] + b[1] + b[36] + b[12] + 29)) & 255;
b[38] = (b[38] - (b[10] + b[18] + b[39] + b[0] + b[35] + b[37] + 69)) & 255;
b[18] = (b[18] - (b[22] + b[24] + b[25] + b[40] + b[27] + b[42] + 196)) & 255;
b[10] ^= (b[3] + b[11] + b[8] + b[26] + b[36] + b[6] + 6) & 0xFF;
b[33] = (b[33] + (b[14] + b[35] + b[41] + b[0] + b[6] + b[8] + 45)) & 255;
b[35] = (b[35] - (b[37] + b[23] + b[18] + b[26] + b[20] + b[30] + 140)) & 255;
b[42] = (b[42] + (b[23] + b[28] + b[39] + b[16] + b[17] + b[2] + 49)) & 255;
b[31] ^= (b[1] + b[16] + b[23] + b[25] + b[29] + b[4] + 2) & 0xFF;
b[41] = (b[41] - (b[33] + b[9] + b[34] + b[26] + b[3] + b[14] + 28)) & 255;
b[34] ^= (b[9] + b[5] + b[31] + b[42] + b[1] + b[3] + 244) & 0xFF;
b[8] = (b[8] + (b[10] + b[36] + b[38] + b[20] + b[39] + b[41] + 105)) & 255;
b[43] = (b[43] + (b[36] + b[23] + b[15] + b[21] + b[32] + b[38] + 79)) & 255;
b[38] ^= (b[29] + b[9] + b[15] + b[33] + b[32] + b[3] + 187) & 0xFF;
b[9] = (b[9] - (b[5] + b[15] + b[19] + b[27] + b[17] + b[25] + 161)) & 255;
b[23] ^= (b[11] + b[32] + b[35] + b[5] + b[10] + b[18] + 150) & 0xFF;
b[25] = (b[25] + (b[18] + b[32] + b[12] + b[2] + b[27] + b[8] + 127)) & 255;
b[34] ^= (b[12] + b[0] + b[35] + b[9] + b[38] + b[30] + 1) & 0xFF;
b[36] = (b[36] - (b[30] + b[3] + b[32] + b[37] + b[24] + b[18] + 148)) & 255;
b[29] = (b[29] + (b[42] + b[12] + b[2] + b[24] + b[6] + b[39] + 200)) & 255;
b[25] ^= (b[9] + b[26] + b[29] + b[23] + b[35] + b[24] + 65) & 0xFF;
b[39] ^= (b[9] + b[18] + b[20] + b[15] + b[40] + b[10] + 175) & 0xFF;
b[39] = (b[39] + (b[43] + b[35] + b[4] + b[37] + b[9] + b[32] + 223)) & 255;
b[35] = (b[35] + (b[43] + b[23] + b[22] + b[33] + b[30] + b[0] + 147)) & 255;
b[25] = (b[25] + (b[37] + b[8] + b[39] + b[17] + b[9] + b[43] + 3)) & 255;
b[40] ^= (b[35] + b[22] + b[9] + b[31] + b[23] + b[12] + 7) & 0xFF;
b[35] ^= (b[19] + b[24] + b[39] + b[42] + b[28] + b[4] + 184) & 0xFF;
b[33] ^= (b[39] + b[12] + b[10] + b[18] + b[37] + b[15] + 22) & 0xFF;
b[27] ^= (b[19] + b[2] + b[40] + b[14] + b[9] + b[36] + 147) & 0xFF;
b[0] ^= (b[21] + b[1] + b[27] + b[17] + b[8] + b[31] + 92) & 0xFF;
b[9] = (b[9] + (b[33] + b[20] + b[43] + b[17] + b[15] + b[28] + 13)) & 255;
b[2] = (b[2] + (b[21] + b[30] + b[16] + b[41] + b[10] + b[11] + 235)) & 255;
b[1] ^= (b[25] + b[41] + b[12] + b[36] + b[34] + b[5] + 14) & 0xFF;
b[39] = (b[39] + (b[40] + b[2] + b[22] + b[25] + b[10] + b[13] + 94)) & 255;
b[33] = (b[33] - (b[34] + b[30] + b[39] + b[37] + b[13] + b[4] + 182)) & 255;
b[12] ^= (b[7] + b[38] + b[20] + b[21] + b[1] + b[36] + 136) & 0xFF;
b[8] ^= (b[12] + b[10] + b[3] + b[2] + b[34] + b[31] + 203) & 0xFF;
b[34] = (b[34] + (b[33] + b[41] + b[11] + b[15] + b[32] + b[31] + 254)) & 255;
b[11] = (b[11] - (b[2] + b[6] + b[43] + b[25] + b[35] + b[26] + 210)) & 255;
b[36] = (b[36] + (b[7] + b[21] + b[15] + b[29] + b[31] + b[2] + 130)) & 255;
b[42] = (b[42] - (b[43] + b[24] + b[7] + b[35] + b[30] + b[3] + 1)) & 255;
b[25] = (b[25] + (b[33] + b[26] + b[2] + b[29] + b[17] + b[4] + 52)) & 255;
b[20] = (b[20] + (b[40] + b[10] + b[19] + b[24] + b[0] + b[11] + 147)) & 255;
b[15] ^= (b[12] + b[27] + b[32] + b[35] + b[40] + b[0] + 212) & 0xFF;
b[33] = (b[33] + (b[12] + b[5] + b[42] + b[2] + b[21] + b[15] + 201)) & 255;
b[37] ^= (b[39] + b[32] + b[40] + b[5] + b[41] + b[10] + 146) & 0xFF;
b[6] = (b[6] - (b[43] + b[36] + b[42] + b[4] + b[19] + b[24] + 91)) & 255;
b[10] = (b[10] - (b[5] + b[31] + b[18] + b[9] + b[24] + b[27] + 246)) & 255;
b[2] ^= (b[32] + b[25] + b[29] + b[23] + b[11] + b[7] + 58) & 0xFF;
b[24] = (b[24] + (b[22] + b[38] + b[33] + b[36] + b[15] + b[43] + 57)) & 255;
b[3] ^= (b[35] + b[2] + b[26] + b[24] + b[17] + b[14] + 66) & 0xFF;
b[35] = (b[35] - (b[6] + b[1] + b[37] + b[15] + b[40] + b[25] + 133)) & 255;
b[34] = (b[34] - (b[32] + b[5] + b[20] + b[17] + b[15] + b[19] + 25)) & 255;
b[2] = (b[2] - (b[26] + b[41] + b[35] + b[1] + b[18] + b[34] + 75)) & 255;
b[4] ^= (b[16] + b[43] + b[41] + b[8] + b[3] + b[37] + 224) & 0xFF;
b[15] ^= (b[42] + b[21] + b[12] + b[34] + b[26] + b[22] + 30) & 0xFF;
b[18] ^= (b[9] + b[21] + b[4] + b[2] + b[42] + b[5] + 103) & 0xFF;
b[33] = (b[33] - (b[16] + b[29] + b[3] + b[37] + b[30] + b[41] + 204)) & 255;
b[17] = (b[17] + (b[11] + b[32] + b[14] + b[16] + b[28] + b[9] + 167)) & 255;
b[12] = (b[12] - (b[7] + b[31] + b[37] + b[14] + b[29] + b[9] + 180)) & 255;
b[16] = (b[16] - (b[42] + b[29] + b[25] + b[0] + b[12] + b[26] + 92)) & 255;
b[5] = (b[5] - (b[30] + b[23] + b[6] + b[24] + b[15] + b[18] + 38)) & 255;
b[13] = (b[13] - (b[12] + b[41] + b[29] + b[27] + b[7] + b[5] + 91)) & 255;
b[40] = (b[40] - (b[16] + b[24] + b[12] + b[5] + b[26] + b[38] + 53)) & 255;
b[7] = (b[7] - (b[1] + b[32] + b[35] + b[21] + b[23] + b[4] + 89)) & 255;
b[12] = (b[12] + (b[4] + b[24] + b[1] + b[18] + b[40] + b[33] + 48)) & 255;
b[41] = (b[41] + (b[42] + b[29] + b[35] + b[11] + b[6] + b[34] + 83)) & 255;
b[3] ^= (b[28] + b[41] + b[27] + b[1] + b[15] + b[26] + 116) & 0xFF;
b[33] ^= (b[40] + b[20] + b[19] + b[16] + b[5] + b[37] + 240) & 0xFF;
b[0] ^= (b[41] + b[16] + b[15] + b[39] + b[18] + b[9] + 175) & 0xFF;
b[40] = (b[40] + (b[42] + b[17] + b[38] + b[14] + b[41] + b[30] + 197)) & 255;
b[34] = (b[34] - (b[42] + b[35] + b[11] + b[29] + b[22] + b[20] + 223)) & 255;
b[38] = (b[38] + (b[25] + b[32] + b[36] + b[37] + b[26] + b[35] + 147)) & 255;
b[25] = (b[25] - (b[12] + b[27] + b[43] + b[10] + b[36] + b[24] + 15)) & 255;
b[14] = (b[14] + (b[30] + b[33] + b[8] + b[1] + b[10] + b[26] + 203)) & 255;
b[21] ^= (b[12] + b[43] + b[41] + b[37] + b[11] + b[26] + 19) & 0xFF;
b[28] = (b[28] - (b[16] + b[25] + b[40] + b[23] + b[0] + b[24] + 198)) & 255;
b[22] = (b[22] - (b[39] + b[27] + b[19] + b[9] + b[7] + b[1] + 84)) & 255;
b[1] = (b[1] - (b[36] + b[10] + b[37] + b[29] + b[30] + b[12] + 2)) & 255;
b[17] = (b[17] - (b[23] + b[10] + b[35] + b[3] + b[19] + b[22] + 140)) & 255;
b[9] = (b[9] - (b[26] + b[20] + b[29] + b[25] + b[6] + b[12] + 183)) & 255;
b[11] = (b[11] - (b[29] + b[21] + b[41] + b[30] + b[14] + b[23] + 20)) & 255;
b[26] ^= (b[18] + b[21] + b[8] + b[28] + b[12] + b[15] + 98) & 0xFF;
b[33] = (b[33] - (b[34] + b[4] + b[21] + b[12] + b[8] + b[14] + 197)) & 255;
b[32] = (b[32] - (b[10] + b[26] + b[4] + b[7] + b[43] + b[2] + 145)) & 255;
b[17] = (b[17] + (b[20] + b[31] + b[1] + b[37] + b[32] + b[38] + 221)) & 255;
b[27] = (b[27] + (b[17] + b[28] + b[29] + b[2] + b[38] + b[9] + 9)) & 255;
b[3] ^= (b[18] + b[9] + b[2] + b[35] + b[34] + b[30] + 185) & 0xFF;
b[43] ^= (b[31] + b[10] + b[36] + b[24] + b[9] + b[27] + 11) & 0xFF;
b[30] ^= (b[14] + b[19] + b[24] + b[22] + b[6] + b[10] + 80) & 0xFF;
b[11] ^= (b[25] + b[18] + b[38] + b[35] + b[39] + b[34] + 134) & 0xFF;
b[23] = (b[23] - (b[38] + b[34] + b[9] + b[36] + b[1] + b[3] + 112)) & 255;
b[27] = (b[27] - (b[13] + b[14] + b[35] + b[37] + b[23] + b[31] + 185)) & 255;
b[27] = (b[27] + (b[16] + b[1] + b[25] + b[34] + b[21] + b[30] + 43)) & 255;
b[18] ^= (b[2] + b[41] + b[31] + b[4] + b[6] + b[13] + 157) & 0xFF;
b[31] ^= (b[38] + b[0] + b[11] + b[29] + b[4] + b[42] + 220) & 0xFF;
b[13] = (b[13] + (b[26] + b[37] + b[30] + b[27] + b[22] + b[32] + 167)) & 255;
b[33] ^= (b[27] + b[25] + b[4] + b[20] + b[16] + b[26] + 206) & 0xFF;
b[14] = (b[14] + (b[3] + b[12] + b[22] + b[19] + b[35] + b[38] + 115)) & 255;
b[17] ^= (b[21] + b[31] + b[9] + b[10] + b[1] + b[18] + 179) & 0xFF;
b[10] = (b[10] + (b[32] + b[39] + b[7] + b[21] + b[30] + b[1] + 90)) & 255;
b[37] = (b[37] - (b[29] + b[35] + b[20] + b[22] + b[43] + b[32] + 2)) & 255;
b[32] = (b[32] - (b[38] + b[28] + b[42] + b[1] + b[35] + b[17] + 235)) & 255;
b[14] ^= (b[27] + b[4] + b[33] + b[22] + b[43] + b[5] + 82) & 0xFF;
b[22] = (b[22] - (b[37] + b[10] + b[38] + b[39] + b[40] + b[23] + 205)) & 255;
b[43] = (b[43] - (b[40] + b[23] + b[21] + b[26] + b[6] + b[33] + 76)) & 255;
b[3] ^= (b[1] + b[38] + b[15] + b[35] + b[25] + b[23] + 225) & 0xFF;
b[19] = (b[19] - (b[31] + b[26] + b[18] + b[27] + b[22] + b[5] + 222)) & 255;
b[28] ^= (b[5] + b[19] + b[41] + b[23] + b[34] + b[32] + 227) & 0xFF;
b[4] ^= (b[22] + b[25] + b[28] + b[6] + b[7] + b[24] + 23) & 0xFF;
b[43] ^= (b[20] + b[34] + b[21] + b[6] + b[17] + b[16] + 92) & 0xFF;
b[39] = (b[39] + (b[19] + b[17] + b[33] + b[22] + b[31] + b[10] + 166)) & 255;
b[8] ^= (b[1] + b[12] + b[11] + b[17] + b[37] + b[2] + 55) & 0xFF;
b[14] ^= (b[32] + b[41] + b[35] + b[40] + b[9] + b[22] + 63) & 0xFF;
b[25] = (b[25] - (b[6] + b[4] + b[7] + b[3] + b[26] + b[12] + 131)) & 255;
b[16] = (b[16] + (b[32] + b[4] + b[31] + b[8] + b[29] + b[14] + 218)) & 255;
b[26] = (b[26] - (b[8] + b[12] + b[33] + b[39] + b[19] + b[29] + 210)) & 255;
b[14] = (b[14] + (b[28] + b[12] + b[36] + b[39] + b[37] + b[40] + 87)) & 255;
b[10] = (b[10] + (b[32] + b[1] + b[20] + b[30] + b[23] + b[9] + 115)) & 255;
b[32] = (b[32] + (b[8] + b[19] + b[43] + b[0] + b[2] + b[1] + 120)) & 255;
b[41] ^= (b[10] + b[17] + b[0] + b[1] + b[40] + b[5] + 80) & 0xFF;
b[18] = (b[18] - (b[12] + b[0] + b[23] + b[38] + b[37] + b[24] + 223)) & 255;
b[24] = (b[24] + (b[37] + b[42] + b[7] + b[5] + b[22] + b[11] + 177)) & 255;
b[13] ^= (b[20] + b[26] + b[37] + b[9] + b[29] + b[16] + 195) & 0xFF;
b[25] ^= (b[26] + b[5] + b[0] + b[31] + b[6] + b[39] + 207) & 0xFF;
b[18] = (b[18] + (b[25] + b[39] + b[0] + b[35] + b[42] + b[6] + 84)) & 255;
b[6] ^= (b[35] + b[37] + b[7] + b[31] + b[29] + b[15] + 217) & 0xFF;
b[18] ^= (b[30] + b[23] + b[36] + b[40] + b[10] + b[33] + 192) & 0xFF;
b[30] = (b[30] - (b[17] + b[24] + b[8] + b[9] + b[16] + b[18] + 104)) & 255;
b[34] = (b[34] - (b[33] + b[2] + b[32] + b[6] + b[3] + b[21] + 216)) & 255;
b[40] ^= (b[35] + b[22] + b[17] + b[2] + b[20] + b[18] + 80) & 0xFF;
b[23] = (b[23] + (b[24] + b[43] + b[30] + b[37] + b[6] + b[36] + 58)) & 255;
b[21] = (b[21] + (b[5] + b[9] + b[19] + b[7] + b[26] + b[18] + 114)) & 255;
b[35] = (b[35] + (b[39] + b[12] + b[36] + b[2] + b[9] + b[30] + 167)) & 255;
b[18] ^= (b[41] + b[15] + b[32] + b[16] + b[26] + b[23] + 205) & 0xFF;
b[2] ^= (b[15] + b[40] + b[14] + b[19] + b[8] + b[25] + 156) & 0xFF;
b[20] = (b[20] - (b[36] + b[42] + b[12] + b[24] + b[10] + b[14] + 70)) & 255;
b[32] ^= (b[0] + b[40] + b[41] + b[24] + b[22] + b[3] + 232) & 0xFF;
b[8] = (b[8] - (b[14] + b[40] + b[10] + b[1] + b[28] + b[6] + 110)) & 255;
b[42] = (b[42] - (b[16] + b[29] + b[3] + b[32] + b[4] + b[5] + 217)) & 255;
b[43] = (b[43] - (b[13] + b[27] + b[15] + b[12] + b[6] + b[5] + 69)) & 255;
b[11] = (b[11] + (b[3] + b[20] + b[30] + b[18] + b[1] + b[17] + 21)) & 255;
b[35] ^= (b[14] + b[24] + b[26] + b[32] + b[7] + b[19] + 139) & 0xFF;
b[16] = (b[16] + (b[35] + b[11] + b[36] + b[29] + b[10] + b[26] + 70)) & 255;
b[7] = (b[7] - (b[3] + b[0] + b[14] + b[31] + b[40] + b[5] + 226)) & 255;
b[0] ^= (b[32] + b[20] + b[30] + b[10] + b[37] + b[35] + 204) & 0xFF;
b[40] ^= (b[33] + b[23] + b[24] + b[41] + b[31] + b[27] + 58) & 0xFF;
b[10] = (b[10] + (b[37] + b[36] + b[26] + b[9] + b[24] + b[7] + 86)) & 255;
b[30] ^= (b[40] + b[36] + b[43] + b[6] + b[11] + b[2] + 57) & 0xFF;
b[13] ^= (b[27] + b[19] + b[31] + b[38] + b[43] + b[23] + 33) & 0xFF;
b[1] = (b[1] - (b[5] + b[17] + b[20] + b[43] + b[39] + b[25] + 81)) & 255;
b[21] = (b[21] - (b[23] + b[34] + b[14] + b[30] + b[39] + b[35] + 241)) & 255;
b[9] = (b[9] + (b[27] + b[26] + b[37] + b[12] + b[31] + b[30] + 208)) & 255;
b[35] ^= (b[2] + b[18] + b[4] + b[1] + b[24] + b[21] + 103) & 0xFF;
b[0] = (b[0] + (b[43] + b[4] + b[5] + b[29] + b[6] + b[24] + 208)) & 255;
b[42] ^= (b[20] + b[38] + b[37] + b[12] + b[35] + b[41] + 155) & 0xFF;
b[10] = (b[10] - (b[39] + b[37] + b[32] + b[9] + b[29] + b[0] + 138)) & 255;
b[40] = (b[40] + (b[8] + b[26] + b[31] + b[38] + b[32] + b[37] + 187)) & 255;
b[30] ^= (b[43] + b[42] + b[19] + b[3] + b[11] + b[23] + 221) & 0xFF;
b[30] = (b[30] + (b[35] + b[40] + b[33] + b[4] + b[18] + b[29] + 149)) & 255;
b[35] = (b[35] - (b[5] + b[0] + b[14] + b[2] + b[20] + b[6] + 241)) & 255;
b[38] = (b[38] + (b[0] + b[1] + b[27] + b[36] + b[31] + b[17] + 247)) & 255;
b[16] = (b[16] - (b[38] + b[6] + b[21] + b[34] + b[27] + b[10] + 35)) & 255;
b[39] = (b[39] + (b[23] + b[17] + b[21] + b[36] + b[20] + b[34] + 12)) & 255;
b[40] = (b[40] + (b[27] + b[21] + b[22] + b[28] + b[11] + b[15] + 134)) & 255;
b[15] ^= (b[2] + b[43] + b[3] + b[5] + b[0] + b[35] + 10) & 0xFF;
b[5] = (b[5] + (b[19] + b[9] + b[32] + b[7] + b[18] + b[24] + 241)) & 255;
b[22] = (b[22] - (b[29] + b[42] + b[40] + b[38] + b[8] + b[6] + 131)) & 255;
b[38] ^= (b[17] + b[28] + b[4] + b[18] + b[11] + b[3] + 133) & 0xFF;
b[40] = (b[40] - (b[22] + b[4] + b[28] + b[3] + b[18] + b[23] + 3)) & 255;
b[1] = (b[1] + (b[32] + b[31] + b[34] + b[16] + b[28] + b[35] + 141)) & 255;
b[5] = (b[5] - (b[11] + b[20] + b[24] + b[37] + b[33] + b[38] + 113)) & 255;
b[21] ^= (b[20] + b[38] + b[14] + b[15] + b[1] + b[13] + 81) & 0xFF;
b[26] = (b[26] + (b[4] + b[11] + b[31] + b[32] + b[28] + b[16] + 165)) & 255;
b[27] ^= (b[17] + b[13] + b[28] + b[12] + b[24] + b[3] + 116) & 0xFF;
b[4] = (b[4] + (b[37] + b[2] + b[27] + b[13] + b[21] + b[35] + 194)) & 255;
b[0] ^= (b[11] + b[37] + b[33] + b[36] + b[38] + b[3] + 123) & 0xFF;
b[29] = (b[29] + (b[38] + b[14] + b[34] + b[18] + b[43] + b[35] + 135)) & 255;
b[34] ^= (b[42] + b[18] + b[9] + b[32] + b[3] + b[11] + 182) & 0xFF;
b[38] = (b[38] - (b[37] + b[13] + b[8] + b[23] + b[22] + b[27] + 86)) & 255;
b[5] = (b[5] + (b[29] + b[22] + b[2] + b[30] + b[19] + b[7] + 181)) & 255;
b[9] = (b[9] - (b[1] + b[10] + b[23] + b[22] + b[37] + b[21] + 129)) & 255;
b[12] ^= (b[9] + b[23] + b[34] + b[14] + b[13] + b[10] + 147) & 0xFF;
b[28] = (b[28] - (b[0] + b[23] + b[14] + b[16] + b[20] + b[25] + 31)) & 255;
b[37] = (b[37] + (b[39] + b[43] + b[28] + b[17] + b[24] + b[7] + 3)) & 255;
b[21] = (b[21] - (b[32] + b[24] + b[34] + b[28] + b[15] + b[0] + 63)) & 255;
b[12] ^= (b[25] + b[5] + b[15] + b[11] + b[1] + b[9] + 8) & 0xFF;
b[33] = (b[33] - (b[12] + b[21] + b[4] + b[37] + b[7] + b[9] + 124)) & 255;
b[11] = (b[11] - (b[15] + b[43] + b[24] + b[34] + b[16] + b[9] + 166)) & 255;
b[36] ^= (b[42] + b[6] + b[11] + b[40] + b[33] + b[7] + 207) & 0xFF;
b[7] = (b[7] + (b[14] + b[33] + b[30] + b[6] + b[31] + b[16] + 185)) & 255;
b[8] = (b[8] - (b[12] + b[16] + b[14] + b[4] + b[34] + b[23] + 244)) & 255;
b[9] = (b[9] - (b[4] + b[43] + b[39] + b[16] + b[15] + b[22] + 183)) & 255;
b[23] ^= (b[11] + b[15] + b[34] + b[8] + b[36] + b[16] + 62) & 0xFF;
b[5] = (b[5] - (b[26] + b[22] + b[39] + b[0] + b[36] + b[4] + 1)) & 255;
b[6] = (b[6] - (b[43] + b[35] + b[2] + b[27] + b[21] + b[30] + 212)) & 255;
b[14] ^= (b[0] + b[7] + b[13] + b[39] + b[21] + b[22] + 251) & 0xFF;
b[9] = (b[9] - (b[18] + b[4] + b[7] + b[13] + b[29] + b[26] + 117)) & 255;
b[25] ^= (b[26] + b[32] + b[12] + b[27] + b[28] + b[7] + 178) & 0xFF;
b[13] = (b[13] + (b[22] + b[4] + b[26] + b[5] + b[10] + b[7] + 76)) & 255;
b[26] = (b[26] + (b[8] + b[3] + b[27] + b[28] + b[6] + b[34] + 7)) & 255;
b[18] = (b[18] + (b[41] + b[12] + b[21] + b[27] + b[24] + b[6] + 193)) & 255;
b[35] = (b[35] - (b[32] + b[29] + b[42] + b[30] + b[43] + b[33] + 155)) & 255;
b[36] ^= (b[12] + b[21] + b[34] + b[29] + b[28] + b[7] + 141) & 0xFF;
b[24] ^= (b[15] + b[38] + b[27] + b[23] + b[21] + b[1] + 244) & 0xFF;
b[1] = (b[1] + (b[27] + b[4] + b[7] + b[21] + b[32] + b[31] + 165)) & 255;
b[9] = (b[9] - (b[27] + b[39] + b[31] + b[43] + b[22] + b[28] + 229)) & 255;
b[33] ^= (b[35] + b[30] + b[36] + b[41] + b[3] + b[28] + 231) & 0xFF;
b[20] = (b[20] - (b[34] + b[10] + b[12] + b[41] + b[18] + b[43] + 147)) & 255;
b[18] = (b[18] - (b[31] + b[6] + b[17] + b[12] + b[11] + b[19] + 220)) & 255;
b[13] = (b[13] + (b[8] + b[21] + b[24] + b[23] + b[3] + b[27] + 201)) & 255;
b[11] ^= (b[18] + b[37] + b[23] + b[5] + b[3] + b[7] + 53) & 0xFF;
b[25] = (b[25] - (b[7] + b[21] + b[12] + b[24] + b[35] + b[42] + 5)) & 255;
b[13] = (b[13] + (b[7] + b[18] + b[41] + b[2] + b[31] + b[3] + 214)) & 255;
b[34] = (b[34] + (b[43] + b[0] + b[24] + b[6] + b[36] + b[41] + 156)) & 255;
b[22] = (b[22] + (b[21] + b[32] + b[36] + b[31] + b[33] + b[12] + 209)) & 255;
b[24] = (b[24] - (b[5] + b[42] + b[28] + b[18] + b[13] + b[43] + 10)) & 255;
b[5] ^= (b[20] + b[31] + b[40] + b[10] + b[39] + b[16] + 196) & 0xFF;
b[1] = (b[1] - (b[32] + b[4] + b[0] + b[5] + b[17] + b[2] + 159)) & 255;
b[41] ^= (b[2] + b[1] + b[19] + b[17] + b[15] + b[3] + 86) & 0xFF;
b[29] = (b[29] + (b[19] + b[32] + b[6] + b[40] + b[14] + b[8] + 162)) & 255;
b[8] = (b[8] + (b[41] + b[23] + b[11] + b[17] + b[5] + b[39] + 125)) & 255;
b[12] ^= (b[3] + b[22] + b[38] + b[29] + b[26] + b[4] + 213) & 0xFF;
b[43] = (b[43] - (b[28] + b[32] + b[27] + b[18] + b[16] + b[31] + 15)) & 255;
b[4] ^= (b[22] + b[2] + b[17] + b[1] + b[9] + b[40] + 26) & 0xFF;
b[3] = (b[3] + (b[34] + b[43] + b[8] + b[1] + b[14] + b[30] + 74)) & 255;
b[14] ^= (b[38] + b[43] + b[18] + b[22] + b[17] + b[35] + 133) & 0xFF;
b[24] = (b[24] - (b[29] + b[40] + b[37] + b[33] + b[28] + b[43] + 128)) & 255;
b[5] = (b[5] - (b[8] + b[16] + b[38] + b[37] + b[1] + b[18] + 148)) & 255;
b[16] ^= (b[41] + b[35] + b[32] + b[27] + b[42] + b[43] + 137) & 0xFF;
b[19] = (b[19] - (b[26] + b[27] + b[29] + b[32] + b[14] + b[21] + 34)) & 255;
b[20] = (b[20] - (b[34] + b[11] + b[21] + b[0] + b[43] + b[13] + 213)) & 255;
b[43] ^= (b[41] + b[14] + b[37] + b[38] + b[15] + b[10] + 217) & 0xFF;
b[15] = (b[15] + (b[26] + b[41] + b[19] + b[24] + b[21] + b[20] + 77)) & 255;
b[37] = (b[37] + (b[18] + b[14] + b[30] + b[10] + b[22] + b[5] + 175)) & 255;
b[1] = (b[1] + (b[14] + b[10] + b[9] + b[33] + b[41] + b[15] + 240)) & 255;
b[13] ^= (b[37] + b[21] + b[22] + b[23] + b[31] + b[26] + 247) & 0xFF;
b[15] ^= (b[32] + b[26] + b[30] + b[28] + b[40] + b[38] + 179) & 0xFF;
b[3] ^= (b[34] + b[14] + b[33] + b[28] + b[15] + b[36] + 3) & 0xFF;
b[1] ^= (b[12] + b[17] + b[21] + b[38] + b[34] + b[39] + 199) & 0xFF;
b[33] ^= (b[8] + b[26] + b[23] + b[0] + b[30] + b[9] + 207) & 0xFF;
b[33] ^= (b[4] + b[43] + b[36] + b[16] + b[41] + b[18] + 146) & 0xFF;
b[0] ^= (b[17] + b[32] + b[8] + b[37] + b[14] + b[1] + 132) & 0xFF;
b[9] ^= (b[2] + b[13] + b[15] + b[42] + b[39] + b[4] + 52) & 0xFF;
b[29] ^= (b[24] + b[9] + b[33] + b[36] + b[28] + b[17] + 123) & 0xFF;
b[2] = (b[2] + (b[36] + b[1] + b[26] + b[30] + b[6] + b[13] + 234)) & 255;
b[23] ^= (b[15] + b[41] + b[29] + b[12] + b[39] + b[24] + 173) & 0xFF;
b[15] = (b[15] + (b[17] + b[29] + b[20] + b[9] + b[0] + b[43] + 229)) & 255;
b[5] = (b[5] - (b[4] + b[7] + b[28] + b[43] + b[12] + b[26] + 54)) & 255;
b[43] = (b[43] - (b[32] + b[27] + b[4] + b[25] + b[8] + b[11] + 80)) & 255;
b[12] = (b[12] + (b[30] + b[29] + b[10] + b[25] + b[33] + b[23] + 180)) & 255;
b[31] = (b[31] + (b[14] + b[29] + b[42] + b[40] + b[30] + b[33] + 202)) & 255;
b[29] = (b[29] - (b[10] + b[28] + b[19] + b[38] + b[1] + b[31] + 224)) & 255;
b[28] = (b[28] - (b[19] + b[37] + b[21] + b[20] + b[14] + b[23] + 72)) & 255;
b[43] = (b[43] - (b[8] + b[39] + b[2] + b[40] + b[37] + b[10] + 152)) & 255;
b[19] = (b[19] - (b[38] + b[8] + b[11] + b[35] + b[36] + b[29] + 241)) & 255;
b[29] = (b[29] + (b[5] + b[7] + b[4] + b[40] + b[0] + b[39] + 41)) & 255;
b[25] = (b[25] + (b[9] + b[26] + b[41] + b[43] + b[5] + b[20] + 3)) & 255;
b[18] = (b[18] - (b[4] + b[9] + b[3] + b[12] + b[26] + b[1] + 145)) & 255;
b[11] = (b[11] - (b[17] + b[6] + b[7] + b[32] + b[3] + b[33] + 162)) & 255;
b[23] = (b[23] - (b[13] + b[24] + b[18] + b[36] + b[34] + b[14] + 232)) & 255;
b[4] ^= (b[24] + b[17] + b[36] + b[13] + b[10] + b[41] + 197) & 0xFF;
b[27] = (b[27] - (b[18] + b[23] + b[22] + b[8] + b[2] + b[9] + 98)) & 255;
b[5] ^= (b[35] + b[9] + b[30] + b[8] + b[27] + b[26] + 113) & 0xFF;
b[30] ^= (b[18] + b[9] + b[37] + b[25] + b[32] + b[35] + 0) & 0xFF;
b[23] ^= (b[27] + b[35] + b[43] + b[19] + b[12] + b[20] + 111) & 0xFF;
b[4] ^= (b[42] + b[18] + b[12] + b[5] + b[16] + b[37] + 98) & 0xFF;
b[36] ^= (b[40] + b[22] + b[17] + b[27] + b[0] + b[39] + 200) & 0xFF;
b[23] = (b[23] + (b[14] + b[37] + b[42] + b[11] + b[28] + b[34] + 104)) & 255;
b[22] = (b[22] + (b[28] + b[19] + b[39] + b[20] + b[14] + b[4] + 88)) & 255;
b[37] ^= (b[2] + b[27] + b[7] + b[20] + b[22] + b[32] + 130) & 0xFF;
b[26] = (b[26] + (b[25] + b[2] + b[16] + b[19] + b[23] + b[32] + 119)) & 255;
b[36] = (b[36] - (b[10] + b[24] + b[34] + b[28] + b[0] + b[3] + 178)) & 255;
b[41] = (b[41] - (b[1] + b[4] + b[10] + b[16] + b[13] + b[11] + 6)) & 255;
b[20] = (b[20] - (b[30] + b[8] + b[11] + b[34] + b[21] + b[0] + 118)) & 255;
b[40] = (b[40] - (b[11] + b[28] + b[42] + b[20] + b[27] + b[13] + 142)) & 255;
b[32] = (b[32] - (b[7] + b[37] + b[29] + b[16] + b[3] + b[25] + 62)) & 255;
b[27] = (b[27] + (b[15] + b[14] + b[1] + b[28] + b[18] + b[13] + 139)) & 255;
b[30] ^= (b[42] + b[9] + b[2] + b[36] + b[12] + b[16] + 241) & 0xFF;
b[24] = (b[24] + (b[9] + b[4] + b[28] + b[23] + b[3] + b[14] + 217)) & 255;
b[12] = (b[12] - (b[14] + b[31] + b[17] + b[5] + b[22] + b[11] + 29)) & 255;
b[31] = (b[31] + (b[35] + b[37] + b[5] + b[42] + b[33] + b[41] + 16)) & 255;
b[3] = (b[3] + (b[38] + b[37] + b[22] + b[10] + b[8] + b[25] + 181)) & 255;
b[37] = (b[37] + (b[24] + b[39] + b[15] + b[10] + b[13] + b[35] + 225)) & 255;
b[30] = (b[30] + (b[6] + b[14] + b[28] + b[29] + b[24] + b[15] + 108)) & 255;
b[14] = (b[14] + (b[30] + b[5] + b[35] + b[41] + b[3] + b[17] + 119)) & 255;
b[41] ^= (b[30] + b[13] + b[21] + b[0] + b[24] + b[1] + 247) & 0xFF;
b[13] = (b[13] + (b[33] + b[28] + b[19] + b[27] + b[6] + b[12] + 240)) & 255;
b[18] ^= (b[1] + b[7] + b[23] + b[2] + b[37] + b[4] + 152) & 0xFF;
b[7] ^= (b[23] + b[6] + b[21] + b[43] + b[26] + b[22] + 145) & 0xFF;
b[27] = (b[27] + (b[13] + b[36] + b[10] + b[40] + b[35] + b[42] + 138)) & 255;
b[10] ^= (b[4] + b[2] + b[18] + b[38] + b[22] + b[27] + 40) & 0xFF;
b[4] = (b[4] - (b[35] + b[24] + b[25] + b[36] + b[29] + b[20] + 234)) & 255;
b[31] ^= (b[8] + b[33] + b[38] + b[40] + b[13] + b[16] + 112) & 0xFF;
b[41] = (b[41] - (b[13] + b[30] + b[12] + b[1] + b[22] + b[16] + 211)) & 255;
b[23] ^= (b[33] + b[16] + b[31] + b[26] + b[15] + b[1] + 3) & 0xFF;
b[32] = (b[32] - (b[29] + b[21] + b[6] + b[4] + b[39] + b[42] + 251)) & 255;
b[4] = (b[4] + (b[28] + b[38] + b[37] + b[5] + b[32] + b[13] + 47)) & 255;
b[16] ^= (b[32] + b[39] + b[13] + b[21] + b[20] + b[2] + 28) & 0xFF;
b[35] = (b[35] - (b[18] + b[17] + b[30] + b[15] + b[21] + b[6] + 215)) & 255;
b[1] = (b[1] - (b[37] + b[20] + b[11] + b[15] + b[8] + b[27] + 26)) & 255;
b[42] = (b[42] + (b[26] + b[43] + b[0] + b[21] + b[4] + b[20] + 173)) & 255;
b[39] ^= (b[12] + b[16] + b[35] + b[0] + b[41] + b[2] + 229) & 0xFF;
b[17] ^= (b[24] + b[7] + b[35] + b[31] + b[28] + b[29] + 64) & 0xFF;
b[38] ^= (b[20] + b[9] + b[32] + b[2] + b[17] + b[3] + 160) & 0xFF;
b[9] = (b[9] - (b[2] + b[29] + b[42] + b[19] + b[31] + b[40] + 131)) & 255;
b[4] = (b[4] + (b[2] + b[31] + b[11] + b[16] + b[8] + b[23] + 245)) & 255;
b[11] = (b[11] + (b[24] + b[13] + b[3] + b[6] + b[27] + b[7] + 206)) & 255;
b[9] = (b[9] - (b[13] + b[1] + b[5] + b[8] + b[11] + b[32] + 52)) & 255;
b[9] = (b[9] - (b[14] + b[38] + b[21] + b[30] + b[8] + b[40] + 179)) & 255;
b[40] ^= (b[30] + b[32] + b[11] + b[24] + b[2] + b[7] + 205) & 0xFF;
b[28] = (b[28] + (b[7] + b[12] + b[18] + b[30] + b[27] + b[10] + 24)) & 255;
b[7] ^= (b[5] + b[37] + b[18] + b[12] + b[27] + b[21] + 181) & 0xFF;
b[24] = (b[24] + (b[36] + b[39] + b[27] + b[8] + b[14] + b[34] + 181)) & 255;
b[25] = (b[25] + (b[37] + b[40] + b[17] + b[21] + b[14] + b[33] + 52)) & 255;
b[27] ^= (b[29] + b[21] + b[26] + b[33] + b[10] + b[31] + 111) & 0xFF;
b[6] ^= (b[36] + b[13] + b[4] + b[38] + b[16] + b[14] + 53) & 0xFF;
b[12] ^= (b[42] + b[25] + b[19] + b[7] + b[16] + b[43] + 245) & 0xFF;
b[29] ^= (b[14] + b[1] + b[18] + b[20] + b[17] + b[34] + 192) & 0xFF;
b[6] = (b[6] + (b[33] + b[11] + b[20] + b[15] + b[1] + b[31] + 62)) & 255;
b[25] = (b[25] - (b[41] + b[17] + b[14] + b[10] + b[35] + b[2] + 41)) & 255;
b[5] ^= (b[36] + b[41] + b[6] + b[26] + b[18] + b[4] + 29) & 0xFF;
b[41] ^= (b[31] + b[36] + b[2] + b[42] + b[43] + b[4] + 72) & 0xFF;
b[17] = (b[17] - (b[29] + b[43] + b[1] + b[8] + b[32] + b[35] + 126)) & 255;
b[28] = (b[28] + (b[22] + b[23] + b[10] + b[20] + b[11] + b[0] + 191)) & 255;
b[22] ^= (b[6] + b[10] + b[5] + b[40] + b[17] + b[28] + 173) & 0xFF;
b[34] ^= (b[35] + b[4] + b[22] + b[41] + b[36] + b[40] + 159) & 0xFF;
b[39] = (b[39] - (b[28] + b[8] + b[36] + b[42] + b[11] + b[13] + 68)) & 255;
b[43] = (b[43] + (b[4] + b[20] + b[36] + b[25] + b[22] + b[7] + 174)) & 255;
b[19] ^= (b[16] + b[10] + b[3] + b[5] + b[39] + b[0] + 156) & 0xFF;
b[13] = (b[13] - (b[31] + b[43] + b[26] + b[41] + b[24] + b[42] + 128)) & 255;
b[33] = (b[33] + (b[43] + b[24] + b[16] + b[7] + b[17] + b[6] + 156)) & 255;
b[17] = (b[17] + (b[34] + b[1] + b[14] + b[19] + b[29] + b[18] + 164)) & 255;
b[43] = (b[43] + (b[18] + b[14] + b[4] + b[20] + b[40] + b[27] + 107)) & 255;
b[5] ^= (b[17] + b[31] + b[28] + b[9] + b[0] + b[34] + 142) & 0xFF;
b[21] ^= (b[2] + b[3] + b[12] + b[16] + b[6] + b[15] + 100) & 0xFF;
b[3] ^= (b[14] + b[26] + b[33] + b[17] + b[32] + b[1] + 230) & 0xFF;
b[36] = (b[36] - (b[9] + b[3] + b[31] + b[41] + b[8] + b[22] + 42)) & 255;
b[27] = (b[27] + (b[0] + b[6] + b[21] + b[29] + b[38] + b[1] + 32)) & 255;
b[18] = (b[18] + (b[21] + b[5] + b[40] + b[34] + b[43] + b[41] + 87)) & 255;
b[10] = (b[10] - (b[13] + b[27] + b[23] + b[38] + b[2] + b[18] + 18)) & 255;
b[18] = (b[18] - (b[26] + b[6] + b[37] + b[36] + b[33] + b[5] + 177)) & 255;
b[27] ^= (b[39] + b[14] + b[33] + b[22] + b[6] + b[28] + 28) & 0xFF;
b[42] = (b[42] - (b[29] + b[14] + b[31] + b[22] + b[36] + b[33] + 60)) & 255;
b[28] = (b[28] - (b[36] + b[26] + b[17] + b[5] + b[1] + b[13] + 245)) & 255;
b[20] = (b[20] + (b[6] + b[41] + b[42] + b[28] + b[30] + b[12] + 226)) & 255;
b[6] ^= (b[8] + b[23] + b[28] + b[17] + b[32] + b[12] + 66) & 0xFF;
b[3] = (b[3] + (b[23] + b[36] + b[41] + b[17] + b[18] + b[22] + 172)) & 255;
b[21] = (b[21] + (b[22] + b[2] + b[33] + b[28] + b[10] + b[31] + 98)) & 255;
b[12] ^= (b[19] + b[16] + b[28] + b[14] + b[40] + b[33] + 158) & 0xFF;
b[11] = (b[11] - (b[42] + b[27] + b[40] + b[0] + b[6] + b[26] + 177)) & 255;
b[3] = (b[3] - (b[6] + b[26] + b[32] + b[22] + b[39] + b[25] + 119)) & 255;
b[11] ^= (b[8] + b[33] + b[17] + b[27] + b[2] + b[28] + 196) & 0xFF;
b[28] ^= (b[41] + b[26] + b[27] + b[37] + b[21] + b[6] + 153) & 0xFF;
b[41] ^= (b[17] + b[25] + b[9] + b[42] + b[36] + b[10] + 170) & 0xFF;
b[12] = (b[12] - (b[23] + b[43] + b[17] + b[19] + b[3] + b[30] + 82)) & 255;
b[41] ^= (b[28] + b[0] + b[23] + b[12] + b[37] + b[29] + 140) & 0xFF;
b[40] = (b[40] + (b[22] + b[0] + b[28] + b[17] + b[31] + b[11] + 8)) & 255;
b[6] ^= (b[12] + b[33] + b[15] + b[35] + b[11] + b[2] + 164) & 0xFF;
b[20] = (b[20] - (b[42] + b[21] + b[32] + b[30] + b[33] + b[39] + 230)) & 255;
b[30] ^= (b[34] + b[4] + b[2] + b[13] + b[12] + b[35] + 110) & 0xFF;
b[0] ^= (b[12] + b[30] + b[6] + b[17] + b[4] + b[20] + 92) & 0xFF;
b[18] = (b[18] + (b[23] + b[10] + b[2] + b[30] + b[6] + b[17] + 44)) & 255;
b[25] = (b[25] - (b[34] + b[28] + b[19] + b[36] + b[0] + b[3] + 18)) & 255;
b[5] = (b[5] + (b[28] + b[39] + b[25] + b[43] + b[15] + b[7] + 203)) & 255;
b[25] = (b[25] + (b[42] + b[24] + b[41] + b[14] + b[36] + b[17] + 58)) & 255;
b[24] ^= (b[31] + b[0] + b[27] + b[28] + b[14] + b[34] + 22) & 0xFF;
b[40] ^= (b[26] + b[25] + b[5] + b[36] + b[7] + b[22] + 225) & 0xFF;
b[34] = (b[34] + (b[41] + b[14] + b[13] + b[20] + b[17] + b[7] + 29)) & 255;
b[43] = (b[43] - (b[40] + b[19] + b[26] + b[4] + b[10] + b[7] + 56)) & 255;
b[38] ^= (b[39] + b[2] + b[0] + b[31] + b[29] + b[5] + 160) & 0xFF;
b[4] ^= (b[8] + b[33] + b[19] + b[12] + b[25] + b[15] + 101) & 0xFF;
b[33] = (b[33] + (b[8] + b[10] + b[30] + b[31] + b[20] + b[42] + 105)) & 255;
b[15] = (b[15] - (b[36] + b[13] + b[25] + b[9] + b[0] + b[24] + 18)) & 255;
b[40] = (b[40] - (b[1] + b[9] + b[18] + b[17] + b[33] + b[39] + 146)) & 255;
b[6] ^= (b[12] + b[30] + b[10] + b[41] + b[3] + b[37] + 121) & 0xFF;
b[26] ^= (b[32] + b[0] + b[13] + b[27] + b[43] + b[31] + 179) & 0xFF;
b[5] = (b[5] - (b[29] + b[23] + b[15] + b[0] + b[14] + b[28] + 198)) & 255;
b[16] = (b[16] + (b[5] + b[27] + b[21] + b[8] + b[22] + b[28] + 254)) & 255;
b[38] ^= (b[25] + b[28] + b[12] + b[23] + b[20] + b[4] + 220) & 0xFF;
b[23] = (b[23] - (b[17] + b[34] + b[39] + b[3] + b[21] + b[26] + 251)) & 255;
b[35] = (b[35] + (b[4] + b[29] + b[25] + b[9] + b[6] + b[3] + 198)) & 255;
b[23] = (b[23] + (b[30] + b[36] + b[5] + b[7] + b[22] + b[39] + 221)) & 255;
b[21] = (b[21] - (b[10] + b[17] + b[34] + b[14] + b[4] + b[43] + 30)) & 255;
b[4] ^= (b[37] + b[43] + b[15] + b[8] + b[2] + b[10] + 199) & 0xFF;
b[1] ^= (b[40] + b[42] + b[33] + b[23] + b[7] + b[19] + 10) & 0xFF;
b[28] = (b[28] - (b[41] + b[9] + b[22] + b[29] + b[18] + b[14] + 14)) & 255;
b[4] = (b[4] + (b[36] + b[16] + b[6] + b[3] + b[33] + b[23] + 217)) & 255;
b[42] = (b[42] - (b[18] + b[37] + b[23] + b[21] + b[41] + b[38] + 64)) & 255;
b[20] = (b[20] - (b[28] + b[15] + b[21] + b[33] + b[14] + b[9] + 201)) & 255;
b[42] ^= (b[43] + b[39] + b[36] + b[3] + b[26] + b[23] + 7) & 0xFF;
b[15] = (b[15] + (b[25] + b[43] + b[8] + b[19] + b[42] + b[36] + 163)) & 255;
b[8] = (b[8] - (b[2] + b[14] + b[13] + b[15] + b[7] + b[9] + 91)) & 255;
b[5] = (b[5] + (b[20] + b[43] + b[9] + b[3] + b[40] + b[25] + 50)) & 255;
b[6] = (b[6] + (b[20] + b[41] + b[0] + b[42] + b[12] + b[19] + 131)) & 255;
b[23] ^= (b[39] + b[33] + b[27] + b[43] + b[12] + b[2] + 78) & 0xFF;
b[16] = (b[16] - (b[34] + b[25] + b[24] + b[23] + b[42] + b[14] + 168)) & 255;
b[41] = (b[41] + (b[27] + b[6] + b[15] + b[42] + b[7] + b[17] + 162)) & 255;
b[19] = (b[19] - (b[6] + b[14] + b[35] + b[39] + b[21] + b[42] + 253)) & 255;
b[33] = (b[33] - (b[4] + b[27] + b[32] + b[43] + b[42] + b[36] + 209)) & 255;
b[24] = (b[24] + (b[34] + b[12] + b[14] + b[41] + b[21] + b[11] + 223)) & 255;
b[15] = (b[15] + (b[28] + b[7] + b[29] + b[13] + b[0] + b[22] + 189)) & 255;
b[2] = (b[2] + (b[29] + b[9] + b[11] + b[19] + b[0] + b[27] + 89)) & 255;
b[16] ^= (b[31] + b[22] + b[41] + b[14] + b[35] + b[37] + 74) & 0xFF;
b[40] ^= (b[15] + b[39] + b[14] + b[17] + b[16] + b[9] + 206) & 0xFF;
b[5] = (b[5] + (b[33] + b[23] + b[15] + b[39] + b[2] + b[31] + 222)) & 255;
b[10] = (b[10] + (b[12] + b[16] + b[30] + b[9] + b[34] + b[13] + 121)) & 255;
b[10] = (b[10] - (b[15] + b[21] + b[0] + b[42] + b[31] + b[9] + 61)) & 255;
b[31] = (b[31] + (b[19] + b[4] + b[43] + b[41] + b[36] + b[7] + 105)) & 255;
b[31] = (b[31] + (b[14] + b[43] + b[19] + b[36] + b[41] + b[8] + 106)) & 255;
b[25] = (b[25] + (b[3] + b[24] + b[18] + b[15] + b[2] + b[12] + 33)) & 255;
b[11] = (b[11] - (b[43] + b[37] + b[41] + b[18] + b[29] + b[33] + 56)) & 255;
b[26] = (b[26] + (b[15] + b[43] + b[11] + b[16] + b[28] + b[30] + 150)) & 255;
b[12] = (b[12] - (b[41] + b[21] + b[40] + b[31] + b[17] + b[9] + 143)) & 255;
b[0] = (b[0] + (b[15] + b[3] + b[29] + b[10] + b[20] + b[39] + 93)) & 255;
b[34] = (b[34] - (b[2] + b[22] + b[15] + b[18] + b[7] + b[33] + 43)) & 255;
b[8] = (b[8] - (b[18] + b[41] + b[1] + b[3] + b[16] + b[43] + 139)) & 255;
b[18] ^= (b[32] + b[30] + b[26] + b[22] + b[9] + b[33] + 19) & 0xFF;
b[43] = (b[43] - (b[10] + b[15] + b[28] + b[29] + b[27] + b[26] + 168)) & 255;
b[12] = (b[12] + (b[21] + b[23] + b[0] + b[32] + b[28] + b[17] + 252)) & 255;
b[33] = (b[33] - (b[25] + b[12] + b[14] + b[34] + b[4] + b[36] + 185)) & 255;
b[14] = (b[14] + (b[4] + b[5] + b[31] + b[15] + b[36] + b[40] + 67)) & 255;
b[9] = (b[9] + (b[20] + b[19] + b[22] + b[5] + b[32] + b[35] + 151)) & 255;
b[39] = (b[39] - (b[42] + b[10] + b[3] + b[41] + b[14] + b[26] + 177)) & 255;
b[28] ^= (b[1] + b[23] + b[37] + b[31] + b[43] + b[42] + 245) & 0xFF;
b[19] ^= (b[26] + b[0] + b[40] + b[37] + b[23] + b[32] + 255) & 0xFF;
b[39] = (b[39] - (b[34] + b[2] + b[1] + b[43] + b[20] + b[9] + 79)) & 255;
b[29] = (b[29] + (b[37] + b[23] + b[22] + b[24] + b[26] + b[10] + 7)) & 255;
console.log(String.fromCharCode(...b));
```

```python
FLARE 10/15/2022 8:16:46 PM
PS C:\Users\malware\Desktop > node solution.js
n0t_ju5t_A_j4vaSCriP7_ch4l1eng3@flare-on.com
```

FUCK IT I AM DONE, idk how this works still. I am fed up

## Challenge 8: backdoor

legend has it this is gonna be the hardest challenge of flareon9:

![Untitled](https://raw.githubusercontent.com/yassirlaaouissi/yassirlaaouissi.github.io/master/_screenshots/flareon94.png)

Seems like its a .net application:

![Untitled](https://raw.githubusercontent.com/yassirlaaouissi/yassirlaaouissi.github.io/master/_screenshots/flareon95.png)

Opened in dnSpy, and this is what the main does:

![Untitled](https://raw.githubusercontent.com/yassirlaaouissi/yassirlaaouissi.github.io/master/_screenshots/flareon96.png)

`flare_74` initializes the following items:

- `FLARE15.d_b = new List<byte>` , `FLARE15.pe_b = new List<byte>` , `FLARE15.gh_b = new List<byte>`, `FLARE15.rt_b = new List<byte>`& `FLARE15.cl_b = new List<byte>`Which are lists of numbers represented as bytes
- `FLARE15.d_m = new Dictionary<uint, int>` , `FLARE15.gs_m = new Dictionary<uint, int>` ,`FLARE15.cl_m = new Dictionary<uint, int>` ,`FLARE15.pe_m = new Dictionary<uint, int>` & `FLARE15.gh_m = new Dictionary<uint, int>` which are dictionaries consisting of UINT’s as keys and INT’s as values
- `FLARE15.c = new ObservableCollection<int>` which is a type of list with INT’s in it.

After the execution of `FLARE15.flare_74`, `Program.flared_38(args)` gets exectued. Aka `flared_38` gets the command line arguments passed as parameter. Sadly this function could not be decompiled by dnSpy correctly:

![Untitled](https://raw.githubusercontent.com/yassirlaaouissi/yassirlaaouissi.github.io/master/_screenshots/flareon97.png)

Some kind of overflow, maybe due to execution flow obfuscation :/ Lets see what the catch in the main does then. Initially `flare_70`recieves the error output and the command line arguments as parameters. Then it tries to execute `flared_70` with those params, but sadly also this function cant decompile. I am seeing a pattern. all functions starting with `flared_` cant decompile. Almost seems like those functions are obfuscated in a specific manner. Maybe these functions have intentionally been broken.

Maybe the whole idea is that the program goes from `main`—> `FLARE15.flare_70` —> `FLARE15.flare_71`. If you look at `FLARE15.flare_71`you can see it tries to get the function for each key:value in m:

![Untitled](https://raw.githubusercontent.com/yassirlaaouissi/yassirlaaouissi.github.io/master/_screenshots/flareon98.png)

Do mind that the value of the key in M must be between certain values. After the functions (tokens) have been resolved it sets the code that is supposed to be executed in this fashion:

![Untitled](https://raw.githubusercontent.com/yassirlaaouissi/yassirlaaouissi.github.io/master/_screenshots/flareon99.png)

I am curious what the contents of B would be. So lets try and replicate that. m —> FLARE15.wl_m. wl_m looks like this:

```python
FLARE15.wl_m = new Dictionary<uint, int>
	{
		{
			3U,
			167772389
		},
		{
			11U,
			167772323
		},
		{
			16U,
			167772324
		},
		{
			21U,
			167772390
		},
		{
			28U,
			100663475
		},
		{
			35U,
			100663481
		},
		{
			42U,
			16777263
		},
		{
			48U,
			67109184
		},
		{
			53U,
			167772306
		},
		{
			59U,
			100663424
		},
		{
			70U,
			100663477
		}
	};
```

As you can see none of these values will result in this being true:

```python
bool flag = value >= 1879048192 && value < 1879113727;
```

Therefore they will directly be passed on to get memberinfo:

```csharp
MemberInfo memberInfo = declaringType.Module.ResolveMember(value, null, null);
```

This will decode to the following dictionary:

```csharp
wl_m = new Dictionary<uint, int>
	{
		{
			3U,
			167772389 // 0xA0000E5 = StackTrace | .ctor | hasthis System.Void (System.Exception)
		},
		{
			11U,
			167772323 // 0xA0000A3 = StackTrace | GetFrame | hasthis System.Diagnostics.StackFrame (System.Int32)
		},
		{
			16U,
			167772324 // 0xA0000A4 = StackTrace | GetMethod | hasthis System.Reflection.MethodBase ()
		},
		{
			21U,
			167772390 // 0xA0000E6 = MemberInfo | get_MetadataToken | hasthis System.Int32 ()
		},
		{
			28U,
			100663475 //0x60000B3 = FLARE15.flare_66 | System.String (System.Int32) | t
		},
		{
			35U,
			100663481 // 0x60000B9 = FLARE15.flare_69 | System.Byte[] (System.String) | h
		},
		{
			42U,
			16777263 // 0x100002F = Byte (used in ToString())
		},
		{
			48U,
			67109184 // 0x4000140 = internal static readonly int C91849C78D4D52D51AE27BD136F927AE1418705C0A2BC9066D6F38125967F602;
		},
		{
			53U,
			167772306 // 0xA000092 = RuntimeHelpers | InitializeArray | System.Void(System.Array, System.RuntimeFieldHandle) 
		},
		{
			59U,
			100663424 // 0x6000080 = FLARE15.flare_46 | System.Byte[] (System.Byte[], System.Byte[]) | p
		},
		{
			70U,
			100663477 // 0x60000B5 = FLARE15.flare_67 | System.Object (System.Byte[], System,Int32, System.Object[]) | b
		}
	};
```

None of these have the name `RtFieldInfo` or  `RuntimeType` , therefore the tokens are decided as follows:

```csharp
bool flag4 = memberInfo.Name == ".ctor" || memberInfo.Name == ".cctor";
							if (flag4)
							{
								tokenFor = dynamicILInfo.GetTokenFor(((ConstructorInfo)memberInfo).MethodHandle, ((TypeInfo)((ConstructorInfo)memberInfo).DeclaringType).TypeHandle);
							}
							else
							{
								tokenFor = dynamicILInfo.GetTokenFor(((MethodInfo)memberInfo).MethodHandle, ((TypeInfo)((MethodInfo)memberInfo).DeclaringType).TypeHandle);
							}
						}
```

As you can see it utilizes this function: 

- [https://learn.microsoft.com/en-us/dotnet/api/system.reflection.emit.dynamicilinfo.gettokenfor?view=net-6.0#system-reflection-emit-dynamicilinfo-gettokenfor(system-runtimemethodhandle-system-runtimetypehandle)](https://learn.microsoft.com/en-us/dotnet/api/system.reflection.emit.dynamicilinfo.gettokenfor?view=net-6.0#system-reflection-emit-dynamicilinfo-gettokenfor(system-runtimemethodhandle-system-runtimetypehandle))

If you look at what this function returns you see the following:

> A token that can be embedded in the metadata and the MSIL stream for the associated dynamic method.
> 

Aka, `Token = 0x60000B5` for `name = FLARE15.flare_67` . Directly after token declaration, ththe contents of B are filled by this sequence of events:

```csharp
b[(int)key] = (byte)tokenFor;
b[(int)(key + 1U)] = (byte)(tokenFor >> 8);
b[(int)(key + 2U)] = (byte)(tokenFor >> 16);
b[(int)(key + 3U)] = (byte)(tokenFor >> 24);
```

Though if you look closely, `b[]` is an already initialized list of bytes. Furthermore, its also known as `FLARE15.wl_b[]` which is initialized in `FLARE15.flare_74`:

```csharp
FLARE15.wl_b = new List<byte>
	{
		0,
		2,
		115,
		210,
		91,
		118,
		145,
		10,
		6,
		22,
		111,
		214,
		250,
		98,
		120,
		111,
		1,
		32,
		216,
		164,
		111,
		116,
		180,
		252,
		125,
		11,
		7,
		40,
		13,
		133,
		229,
		201,
		12,
		8,
		40,
		157,
		90,
		105,
		252,
		13,
		26,
		141,
		225,
		92,
		24,
		151,
		37,
		208,
		81,
		66,
		113,
		247,
		40,
		49,
		171,
		223,
		109,
		9,
		40,
		58,
		74,
		2,
		192,
		19,
		4,
		17,
		4,
		7,
		3,
		40,
		92,
		181,
		106,
		133,
		19,
		5,
		17,
		5,
		19,
		6,
		43,
		0,
		17,
		6,
		42
	}.ToArray();
```

I wrote this C# script:

```csharp
using System;
using System.Collections;
using System.Collections.Generic;
					
public class Program
{
	public static void Main()
	{
		Dictionary<uint, int> wl_m;
		wl_m = new Dictionary<uint, int>
			{
				{
					3U,
					0xA0000E5
				},
				{
					11U,
					0xA0000A3
				},
				{
					16U,
					0xA0000A4
				},
				{
					21U,
					0xA0000E6
				},
				{
					28U,
					0x60000B3
				},
				{
					35U,
					0x60000B9
				},
				{
					42U,
					0x100002F
				},
				{
					48U,
					0x4000140
				},
				{
					53U,
					0xA000092
				},
				{
					59U,
					0x6000080
				},
				{
					70U,
					0x60000B5
				}
		};
		byte[] b;
		b = new List<byte>{
				0,
				2,
				115,
				210,
				91,
				118,
				145,
				10,
				6,
				22,
				111,
				214,
				250,
				98,
				120,
				111,
				1,
				32,
				216,
				164,
				111,
				116,
				180,
				252,
				125,
				11,
				7,
				40,
				13,
				133,
				229,
				201,
				12,
				8,
				40,
				157,
				90,
				105,
				252,
				13,
				26,
				141,
				225,
				92,
				24,
				151,
				37,
				208,
				81,
				66,
				113,
				247,
				40,
				49,
				171,
				223,
				109,
				9,
				40,
				58,
				74,
				2,
				192,
				19,
				4,
				17,
				4,
				7,
				3,
				40,
				92,
				181,
				106,
				133,
				19,
				5,
				17,
				5,
				19,
				6,
				43,
				0,
				17,
				6,
				42
		}.ToArray();
		
		foreach (var entry in wl_m){
			Console.WriteLine(entry);
			uint key = entry.Key;
			int tokenFor = entry.Value;
			b[(int)key] = (byte)tokenFor;
			b[(int)(key + 1U)] = (byte)(tokenFor >> 8);
			b[(int)(key + 2U)] = (byte)(tokenFor >> 16);
			b[(int)(key + 3U)] = (byte)(tokenFor >> 24);
		};

		
		//Console.Write((byte)tokenFor);
		
		
		foreach(var item in b)
		{
			Console.WriteLine(item);
		}

	}
}
```

Which resulted in `b[]` looking like this:

```csharp
0
2
115
229
0
0
10
10
6
22
111
163
0
0
10
111
164
0
0
10
111
230
0
0
10
11
7
40
179
0
0
6
12
8
40
185
0
0
6
13
26
141
47
0
0
1
37
208
64
1
0
4
40
146
0
0
10
9
40
128
0
0
6
19
4
17
4
7
3
40
181
0
0
6
19
5
17
5
19
6
43
0
17
6
42
```

After this bytecode is generated, it sets them using `dynamicILInfo.SetCode()` after which the bytecode is invoked by `dynamicMethod.Invoke(null, args)`.  The arguments passed on to the invokation are as follows:

![Untitled](https://raw.githubusercontent.com/yassirlaaouissi/yassirlaaouissi.github.io/master/_screenshots/flareon100.png)

`flare_70` gets called by main:

![Untitled](https://raw.githubusercontent.com/yassirlaaouissi/yassirlaaouissi.github.io/master/_screenshots/flareon101.png)

And the main gets the args from the Program:

![Untitled](https://raw.githubusercontent.com/yassirlaaouissi/yassirlaaouissi.github.io/master/_screenshots/flareon102.png)

Aka, `dynamicMethod.Invoke(null, args)` is actually `dynamicMethod.Invoke(null, command_line_args)`.

Long story short, those bytes represent functions that are executed within the namespace of the binary. Lets translate the new contents of `b[]` to the function that are executed. First we start of by converting byte to hex:

```csharp
0x00,0x02,0x73,0xe5,0x00,0x00,0x0a,0x0a,0x06,0x16,0x6f,0xa3,0x00,0x00,0x0a,0x6f,0xa4,0x00,0x00,0x0a,0x6f,0xe6,0x00,0x00,0x0a,0x0b,0x07,0x28,0xb3,0x00,0x00,0x06,0x0c,0x08,0x28,0xb9,0x00,0x00,0x06,0x0d,0x1a,0x8d,0x2f,0x00,0x00,0x01,0x25,0xd0,0x40,0x01,0x00,0x04,0x28,0x92,0x00,0x00,0x0a,0x09,0x28,0x80,0x00,0x00,0x06,0x13,0x04,0x11,0x04,0x07,0x03,0x28,0xb5,0x00,0x00,0x06,0x13,0x05,0x11,0x05,0x13,0x06,0x2b,0x00,0x11,0x06,0x2a
```

Then, since these are loaded and invoked by IL, we match hem with CIL instructions:

- [https://en.wikipedia.org/wiki/List_of_CIL_instructions](https://en.wikipedia.org/wiki/List_of_CIL_instructions)

```csharp
0x00 // No OPeration (NOP)

0x02 // ldarg.0 = Load argument 0 onto the stack.

0x73 // newobj <ctor> = Allocate an uninitialized object or value type and call ctor. CTOR = Constructor. The constructor identifier (<ctor>) is 0xe5,0x00,0x00,0x0a in this case. Which is 0a0000e5.0xA0000E5 = StackTrace | .ctor | hasthis System.Void (System.Exception)

0x0a // stloc.0 = Pop a value from stack into local variable 0.

0x06 // ldloc.0 = Load local variable 0 onto stack.

0x16 // ldc.i4.0 = Push 0 onto the stack as int32.

0x6f // callvirt <method> = Call a method associated with an object. The method they call = 0xa3,0x00,0x00,0x0a = 0a0000a3 0xA0000A3 = StackTrace | GetFrame | hasthis System.Diagnostics.StackFrame (System.Int32)

0x6f // callvirt <method> = Call a method associated with an object. The method they call = 0xa4,0x00,0x00,0x0a = 0a0000a4 0xA0000A4 = StackTrace | GetMethod | hasthis System.Reflection.MethodBase()

0x6f // callvirt <method> = Call a method associated with an object. The method they call = 0xe6,0x00,0x00,0x0a = 0a0000e6 0xA0000E6 = MemberInfo | get_MetadataToken | hasthis System.Int32()

0x0B // stloc.1 = Pop a value from stack into local variable 1.

0x07 // ldloc.1 = Load local variable 1 onto stack.

0x28 // call <method> =  Call method described by method. Method that is called = 0xb3,0x00,0x00,0x06 = 060000b3 0x60000B3 = FLARE15.flare_66 | System.String (System.Int32) | t

0x0C // stloc.2 Pop a value from stack into local variable 2.

0x08 // ldloc.2 = Load local variable 2 onto stack.

0x28 // call <method> =  Call method described by method. Method that is called = 0xb9,0x00,0x00,0x06 = 060000b9 0x60000B9 = FLARE15.flare_69 | System.Byte[] (System.String) | h

0x0D // stloc.3 = Pop a value from stack into local variable 3.

0x1A // ldc.i4.4 = Push 4 onto the stack as int32.

0x8D // newarr <etype> Create a new array with elements of type etype. The array it makes are filled with 0x2f,0x00,0x00,0x01 = 2f000001 = 0100002f = 0x100002F = Byte (used in ToString())

0x25 // dup = Duplicate the value on the top of the stack.

0xD0 // ldtoken <token> = Convert metadata token to its runtime representation. The input to convert = 0x40,0x01,0x00,0x04 = 40010004 = 04000140 --> 0x4000140 = internal static readonly int C91849C78D4D52D51AE27BD136F927AE1418705C0A2BC9066D6F38125967F602;

0x28 // call <method> =  Call method described by method. Method that is called = 0x92,0x00,0x00,0x0a = 0a000092 0xA000092 = RuntimeHelpers | InitializeArray | System.Void(System.Array, System.RuntimeFieldHandle)

0x09 // ldloc.3 = Load local variable 3 onto stack.

0x28 // call <method> =  Call method described by method. Method that is called = 0x80,0x00,0x00,0x06 = 06000080 0x6000080 = FLARE15.flare_46 | System.Byte[] (System.Byte[], System.Byte[]) | p

0x13 // stloc.s <uint8 (indx)> = Pop a value from stack into local variable indx, short form. indx = 0x04, also known as decimal 4

0x11 // ldloc.s <uint8 (indx)> = Load local variable of index indx onto stack, short form. indx = 0x04, also known as decimal 4

0x07 // ldloc.1 = Load local variable 1 onto stack.

0x03 // ldarg.1 = Load argument 1 onto the stack.

0x28 // call <method> =  Call method described by method. Method that is called = 0xb5,0x00,0x00,0x06 = 060000b5 0x60000B5 = FLARE15.flare_67 | System.Object (System.Byte[], System,Int32, System.Object[]) | b

0x13 // stloc.s <uint8 (indx)> = Pop a value from stack into local variable indx, short form. indx = 0x05, also known as decimal 5

0x11 // ldloc.s <uint8 (indx)> = Load local variable of index indx onto stack, short form. indx = 0x05, also known as decimal 5

0x13 // stloc.s <uint8 (indx)> = Pop a value from stack into local variable indx, short form. indx = 0x06, also known as decimal 6

0x2B // br.s <int8 (target)> = Branch to target, short form. target = 0x00 = 0

0x11 // ldloc.s <uint8 (indx)> = Load local variable of index indx onto stack, short form. indxx = 0x06 = 6

0x2A // RET, return, END of method
```

To summarize;

- The bytecode starts with `FLARE15.flare_66 | System.String (System.Int32)`
- `FLARE15.flare_69 | System.Byte[] (System.String)` is the function that follows
- An array filled with bytes is initialized, no contents yet.
- `FLARE15.flare_46 | System.Byte[] (System.Byte[], System.Byte[])` is being executed
- `FLARE15.flare_67 | System.Object (System.Byte[], System,Int32, System.Object[])` is being executed
- ret

Lets start with analysing flare_66. It takes an int as an argument, which happens to be the first command line argument. `flared_66`cant decode so it will go to the catch:

![Untitled](https://raw.githubusercontent.com/yassirlaaouissi/yassirlaaouissi.github.io/master/_screenshots/flareon103.png)

Catch  does the exact same steps we did before, but then with another array and dictionary. Lets cut to the chase, this is the CIL instructions you are gonna get:

```csharp
0x00,0xd0,0x1c,0x00,0x00,0x02,0x28,0x6c,0x00,0x00,0x0a,0x6f,0xb3,0x00,0x00,0x0a,0x0a,0x14,0x0b,0x14,0x0c,0x72,0x11,0x00,0x00,0x70,0x0d,0x72,0x11,0x00,0x00,0x70,0x13,0x04,0x06,0x02,0x6f,0xb4,0x00,0x00,0x0a,0x74,0x6c,0x00,0x00,0x01,0x0b,0x07,0x6f,0xb5,0x00,0x00,0x0a,0x0c,0x28,0xa5,0x00,0x00,0x0a,0x07,0x6f,0xb6,0x00,0x00,0x0a,0x13,0x0f,0x12,0x0f,0xfe,0x16,0x6f,0x00,0x00,0x01,0x6f,0x44,0x00,0x00,0x0a,0x6f,0x9d,0x00,0x00,0x0a,0x13,0x05,0x28,0xa5,0x00,0x00,0x0a,0x07,0x6f,0xb7,0x00,0x00,0x0a,0x6f,0x44,0x00,0x00,0x0a,0x6f,0x9d,0x00,0x00,0x0a,0x13,0x06,0x28,0xa5,0x00,0x00,0x0a,0x07,0x6f,0xb8,0x00,0x00,0x0a,0x13,0x10,0x12,0x10,0xfe,0x16,0x70,0x00,0x00,0x01,0x6f,0x44,0x00,0x00,0x0a,0x6f,0x9d,0x00,0x00,0x0a,0x13,0x07,0x00,0x07,0x6f,0xb9,0x00,0x00,0x0a,0x13,0x11,0x16,0x13,0x12,0x2b,0x2b,0x11,0x11,0x11,0x12,0x9a,0x13,0x13,0x00,0x11,0x04,0x11,0x13,0x6f,0xba,0x00,0x00,0x0a,0x25,0x2d,0x04,0x26,0x14,0x2b,0x05,0x6f,0x44,0x00,0x00,0x0a,0x28,0x28,0x00,0x00,0x0a,0x13,0x04,0x00,0x11,0x12,0x17,0x58,0x13,0x12,0x11,0x12,0x11,0x11,0x8e,0x69,0x32,0xcd,0x28,0xa5,0x00,0x00,0x0a,0x08,0x6f,0xbb,0x00,0x00,0x0a,0x13,0x14,0x12,0x14,0x28,0x3b,0x00,0x00,0x0a,0x6f,0x9d,0x00,0x00,0x0a,0x13,0x08,0x08,0x6f,0xbc,0x00,0x00,0x0a,0x8e,0x69,0x28,0xbd,0x00,0x00,0x0a,0x13,0x09,0x00,0x08,0x6f,0xbe,0x00,0x00,0x0a,0x6f,0xbf,0x00,0x00,0x0a,0x13,0x15,0x2b,0x25,0x11,0x15,0x6f,0xc0,0x00,0x00,0x0a,0x13,0x16,0x00,0x09,0x11,0x16,0x6f,0xc1,0x00,0x00,0x0a,0x25,0x2d,0x04,0x26,0x14,0x2b,0x05,0x6f,0x44,0x00,0x00,0x0a,0x28,0x28,0x00,0x00,0x0a,0x0d,0x00,0x11,0x15,0x6f,0xc2,0x00,0x00,0x0a,0x2d,0xd2,0xde,0x0d,0x11,0x15,0x2c,0x08,0x11,0x15,0x6f,0x46,0x00,0x00,0x0a,0x00,0xdc,0x28,0xa5,0x00,0x00,0x0a,0x09,0x6f,0x9d,0x00,0x00,0x0a,0x13,0x0a,0x28,0xa5,0x00,0x00,0x0a,0x11,0x04,0x6f,0x9d,0x00,0x00,0x0a,0x13,0x0b,0x28,0x81,0x00,0x00,0x0a,0x28,0x82,0x00,0x00,0x0a,0x13,0x0c,0x11,0x0c,0x11,0x09,0x6f,0xa6,0x00,0x00,0x0a,0x00,0x11,0x0c,0x11,0x05,0x6f,0xa6,0x00,0x00,0x0a,0x00,0x11,0x0c,0x11,0x06,0x6f,0xa6,0x00,0x00,0x0a,0x00,0x11,0x0c,0x11,0x08,0x6f,0xa6,0x00,0x00,0x0a,0x00,0x11,0x0c,0x11,0x0a,0x6f,0xa6,0x00,0x00,0x0a,0x00,0x11,0x0c,0x11,0x0b,0x6f,0xa6,0x00,0x00,0x0a,0x00,0x11,0x0c,0x11,0x07,0x6f,0xa6,0x00,0x00,0x0a,0x00,0x11,0x0c,0x6f,0x8f,0x00,0x00,0x0a,0x13,0x0d,0x11,0x0d,0x8e,0x69,0x18,0x5a,0x73,0xc3,0x00,0x00,0x0a,0x13,0x0e,0x16,0x13,0x17,0x2b,0x21,0x11,0x0e,0x11,0x0d,0x11,0x17,0x8f,0x2f,0x00,0x00,0x01,0x72,0x50,0x30,0x00,0x70,0x28,0xc4,0x00,0x00,0x0a,0x6f,0xc5,0x00,0x00,0x0a,0x26,0x11,0x17,0x17,0x58,0x13,0x17,0x11,0x17,0x11,0x0d,0x8e,0x69,0xfe,0x04,0x13,0x18,0x11,0x18,0x2d,0xd1,0x11,0x0e,0x6f,0x44,0x00,0x00,0x0a,0x13,0x19,0x2b,0x00,0x11,0x19,0x2a
```

This is where I stopped with Flare-On, here is the solution to challenge 8; [https://www.mandiant.com/sites/default/files/2022-11/08-backdoor.pdf](https://www.mandiant.com/sites/default/files/2022-11/08-backdoor.pdf). I made this tool to try and convert the CIL instructions:

- https://github.com/yassirlaaouissi/OP2CIL

But to be honest I learned way more than i expected by a long shot. I cut my losses and gained some insights. Before this flare-on I never opened ghidra or any other reversing related tool. So I am happy. Cya next time!
