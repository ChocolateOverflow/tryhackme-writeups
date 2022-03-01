# [Poster](https://tryhackme.com/room/poster)

First as usual, `nmap`.

```
# Nmap 7.92 scan initiated Tue Mar  1 13:02:51 2022 as: nmap -vvv -p 22,80,5432 -sCV -oA init 10.10.63.163
Nmap scan report for 10.10.63.163
Host is up, received conn-refused (0.26s latency).
Scanned at 2022-03-01 13:03:04 +07 for 17s

PORT     STATE SERVICE    REASON  VERSION
22/tcp   open  ssh        syn-ack OpenSSH 7.2p2 Ubuntu 4ubuntu2.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 71:ed:48:af:29:9e:30:c1:b6:1d:ff:b0:24:cc:6d:cb (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDGK2azIgGLY4GFFZlpgMpyOub/To5vmftSEWkjbtFkTBvc5tW/SpoDtjyNMT0JKJUmFJ2/vp6oIpwyIRtDa+oomuNL//exbp/i798hl8FFo4Zq5HsDvQCwNKZ0lfk0HGYgbXj6WAjohokSbkDY1U26FN/MKE2JxcXLcN8n1QmvVbP5p8zO/jgrXvX6DLv4eHxJjhzsBJ6DwFMchtBwy4CiTQsiCUcAyyua93LJO6NEnnM4SOwOUE/wyggCNPbwzB1wzPLAgaiU+M2gn9/XZGmlD+vWOBu3sruCB2PnRuM3cx27gDbbElR4KDIOq2ar66rV+yIZQoQ7KfVUNUFFCbRz
|   256 eb:3a:a3:4e:6f:10:00:ab:ef:fc:c5:2b:0e:db:40:57 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBN2f/wWkOMnH6rNZ+0m2p+PrzBVbz/vfQ/k9rx9W27i9DLBKmRM2b2ntmg8tSwHhZVTb/FvStJci9SIBLAqao00=
|   256 3e:41:42:35:38:05:d3:92:eb:49:39:c6:e3:ee:78:de (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKYg/uhFbBiQ1iu6NNNYtD/tRDbHmPXw4p/nYv+twijq
80/tcp   open  http       syn-ack Apache httpd 2.4.18 ((Ubuntu))
|_http-title: Poster CMS
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.18 (Ubuntu)
5432/tcp open  postgresql syn-ack PostgreSQL DB 9.5.8 - 9.5.10 or 9.5.17 - 9.5.21
| ssl-cert: Subject: commonName=ubuntu
| Issuer: commonName=ubuntu
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2020-07-29T00:54:25
| Not valid after:  2030-07-27T00:54:25
| MD5:   da57 3213 e9aa 9274 d0be c1b0 bbb2 0b09
| SHA-1: 4e03 8469 28f7 673b 2bb2 0440 4ba9 e4d2 a0d0 5dd5
| -----BEGIN CERTIFICATE-----
| MIICsjCCAZqgAwIBAgIJAIrmTOUt3qZtMA0GCSqGSIb3DQEBCwUAMBExDzANBgNV
| BAMMBnVidW50dTAeFw0yMDA3MjkwMDU0MjVaFw0zMDA3MjcwMDU0MjVaMBExDzAN
| BgNVBAMMBnVidW50dTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMca
| tkPhi1xPkNomQzkTX+XRDk0RPBxRJQm17+Q8sru8J72rToPVyZesM7v5M+ttfqlZ
| sHAevEv/iVb1D6hNPawU9kG61Ja9baHd1s31H7RjWxpMS2vZuiu6/oXNWpc4yinQ
| RDWgLqKhDzczacMWLxKkgh06H8DI04/4pCJ6pbf6gXFfVRrccOu1FmoVlWWdVeGd
| CZ2C8XOA1tEEE6UG9HI9Q2gd3AHOSex+ar3EnWm1LanYDQPJSXEgl/K2A9D5DQEw
| +xJxPnH9abqxUrLUDOxzbMpdqXfb0OHxy7jeBJhpd6DonAZTEACdsgh9SzssH4ac
| FOqjsJjfSzok3x3uBx0CAwEAAaMNMAswCQYDVR0TBAIwADANBgkqhkiG9w0BAQsF
| AAOCAQEAxGskqCN0uihEe1rpb7fveGYGMhDsFso9aYdJ4Q3CHJHX3leCN92nLCOq
| R9bTRgVjrvph00jO3+qhHzXCLbnpZXu9R9mPsfcDU/IFCFxMNmjRs4DkkzpGWAyp
| t5I18Zxh4JWJP7Mf1zc39z2Zk/IucAI5kMPMDJUWR/mjVFG/iZY8W+YlKsfvWblU
| tY4RYFhVy9JTVFYe5ZxghLxylYi+cbkGcPMj7qaOkDWIWhILZX1DDAb7cSfVd4rq
| 2ayWhA4Dh/FJkL2j+5mfAku0C7qMAqSlJTMRa6pTQjXeGafLDBoomQIIFnhWOITS
| fohtzsob6PyjssrRoqlRkJLJEJf2YQ==
|_-----END CERTIFICATE-----
|_ssl-date: TLS randomness does not represent time
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Tue Mar  1 13:03:21 2022 -- 1 IP address (1 host up) scanned in 29.43 seconds
```

We see that we have a web server on port 80 and PostgreSQL on port 5432. We can go to `msfconsole` to enumerate & exploit this.

Using the module `auxiliary/scanner/postgres/postgres_login`, we can get the password for the user `postgres`. Then, using the module `auxiliary/admin/postgres/postgres_sql` with the found credentials, we can execute SQL commands. The default `select version()` tells us the version is `9.5.21`. Using the module `auxiliary/scanner/postgres/postgres_hashdump`, we should be able to dump 6 hashes. The module `auxiliary/admin/postgres/postgres_readfile` should allow us to read files on the machine. Finally, the module `exploit/multi/postgres/postgres_copy_from_program_cmd_exec` should allow us to execute arbitrary commands and get a shell on the machine as `postgres`.

Checking `/home`, there's `/home/dark/credentials.txt` which holds dark's credentials we can use to `su - dark`.

Checking `sudo -l`, we see that dark can't run `sudo`. Looking at `/var/www/html`, the file `config.php` contains alison's credentials which can be used to `su - alison`.

Checking alison's `sudo` privileges ...

```sh
alison@ubuntu:~$ sudo -l
[sudo] password for alison:
Matching Defaults entries for alison on ubuntu:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User alison may run the following commands on ubuntu:
    (ALL : ALL) ALL
```

We can run anything as root so a simple `sudo su` should give us a root shell.
