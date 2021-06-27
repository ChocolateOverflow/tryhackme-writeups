# [Juicy Details](https://tryhackme.com/room/juicydetails)

## Reconnaissance

### What tools did the attacker use? (Order by the occurrence in the log)

Checking `access.log`, you can read through the logs carefully and try to find and recognize some popular tools, or you can grab all the user agents with `cut`

```sh
$ cat access.log | cut -d'"' -f6 | sort -u

-
curl/7.74.0
feroxbuster/2.2.1
Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)
Mozilla/5.0 (Hydra)
Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0
sqlmap/1.5.2#stable (http://sqlmap.org)
```

With the above user agents, find each of them in `access.log` to figure out the exact order required for the answer.

### What endpoint was vulnerable to a brute-force attack?

The "brute-force attack" here is Credential brute-forcing, which is done by `hydra`. Look for requests done by `Hydra` in `access.log` to see the endpoint `/rest/user/login`.

### What endpoint was vulnerable to SQL injection?

SQL injection is done my `sqlmap`. Again, look for requests done my `sqlmap` to see the endpoint `/rest/products/search`.

### What parameter was used for the SQL injection?

The parameter `q` can be seen in the requests made by `sqlmap` to the above endpoint.

### What endpoint did the attacker try to use to retrieve files? (Include the /)

You can see in the following request ...

```
::ffff:192.168.10.5 - - [11/Apr/2021:09:34:40 +0000] "GET /ftp/www-data.bak HTTP/1.1" 403 300 "-" "Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0"
```

... that `/ftp` was used to retrieve `www-data.bak`.

## Stolen data

### What section of the website did the attacker use to scrape user email addresses?

Looking near the beginning of `access.log`, just after the `nmap` scans, we can see the attacker browsing `/rest/products/*/reviews` (`*` is the product ID numbers). Since product reviews often come with usernames and the like, this was the prime target for getting user accounts.

### Was their brute-force attack successful? If so, what is the timestamp of the successful login? (Yay/Nay, 11/Apr/2021:09:xx:xx +0000)

We know the brute-forcing is done by `hydra` so let's filter those

```sh
$ grep Hydra access.log | sort -u
::ffff:192.168.10.5 - - [11/Apr/2021:09:16:27 +0000] "GET /rest/user/login HTTP/1.0" 500 - "-" "Mozilla/5.0 (Hydra)"
::ffff:192.168.10.5 - - [11/Apr/2021:09:16:28 +0000] "GET /rest/user/login HTTP/1.0" 500 - "-" "Mozilla/5.0 (Hydra)"
::ffff:192.168.10.5 - - [11/Apr/2021:09:16:28 +0000] "POST /rest/user/login HTTP/1.0" 401 26 "-" "Mozilla/5.0 (Hydra)"
::ffff:192.168.10.5 - - [11/Apr/2021:09:16:29 +0000] "GET /rest/user/login HTTP/1.0" 500 - "-" "Mozilla/5.0 (Hydra)"
::ffff:192.168.10.5 - - [11/Apr/2021:09:16:29 +0000] "POST /rest/user/login HTTP/1.0" 401 26 "-" "Mozilla/5.0 (Hydra)"
::ffff:192.168.10.5 - - [11/Apr/2021:09:16:30 +0000] "GET /rest/user/login HTTP/1.0" 500 - "-" "Mozilla/5.0 (Hydra)"
::ffff:192.168.10.5 - - [11/Apr/2021:09:16:30 +0000] "POST /rest/user/login HTTP/1.0" 401 26 "-" "Mozilla/5.0 (Hydra)"
::ffff:192.168.10.5 - - [11/Apr/2021:09:16:31 +0000] "GET /rest/user/login HTTP/1.0" 500 - "-" "Mozilla/5.0 (Hydra)"
::ffff:192.168.10.5 - - [11/Apr/2021:09:16:31 +0000] "POST /rest/user/login HTTP/1.0" 200 831 "-" "Mozilla/5.0 (Hydra)"
::ffff:192.168.10.5 - - [11/Apr/2021:09:16:31 +0000] "POST /rest/user/login HTTP/1.0" 401 26 "-" "Mozilla/5.0 (Hydra)"
::ffff:192.168.10.5 - - [11/Apr/2021:09:16:32 +0000] "POST /rest/user/login HTTP/1.0" 401 26 "-" "Mozilla/5.0 (Hydra)"
```

Here we can see 1 single request whose response code is `200`. This is the successful login.

### What user information was the attacker able to retrieve from the endpoint vulnerable to SQL injection?

Looking through queries by `sqlmap` doesn't reveal much, but queries by the attacker done manually right after `sqlmap`'s scan shows that the attack got emails and passwords

```
::ffff:192.168.10.5 - - [11/Apr/2021:09:31:04 +0000] "GET /rest/products/search?q=qwert%27))%20UNION%20SELECT%20id,%20email,%20password,%20%274%27,%20%275%27,%20%276%27,%20%277%27,%20%278%27,%20%279%27%20FROM%20Users-- HTTP/1.1" 200 - "-" "Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0"
::ffff:192.168.10.5 - - [11/Apr/2021:09:32:51 +0000] "GET /rest/products/search?q=qwert%27))%20UNION%20SELECT%20id,%20email,%20password,%20%274%27,%20%275%27,%20%276%27,%20%277%27,%20%278%27,%20%279%27%20FROM%20Users-- HTTP/1.1" 200 3742 "-" "curl/7.74.0"
```

### What files did they try to download from the vulnerable endpoint? (endpoint from the previous task, question #5)

Simply filter queries to `/ftp` to get the files in question

```sh
$ grep '/ftp' access.log
::ffff:192.168.10.5 - - [11/Apr/2021:09:34:33 +0000] "GET /ftp HTTP/1.1" 200 4852 "-" "feroxbuster/2.2.1"
::ffff:192.168.10.5 - - [11/Apr/2021:09:34:40 +0000] "GET /ftp/www-data.bak HTTP/1.1" 403 300 "-" "Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0"
::ffff:192.168.10.5 - - [11/Apr/2021:09:34:43 +0000] "GET /ftp/coupons_2013.md.bak HTTP/1.1" 403 78965 "-" ""Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0"
```

### What service and account name were used to retrieve files from the previous question? (service, username)

We know the service in question is `ftp` given the endpoint name, so we look into the FTP log `vsftpd.log`. Here, we can filter `OK` to get successful queries.

```sh
$ grep OK vsftpd.log
Sun Apr 11 08:15:58 2021 [pid 6526] [ftp] OK LOGIN: Client "::ffff:127.0.0.1", anon password "?"
Sun Apr 11 08:18:07 2021 [pid 6627] [ftp] OK LOGIN: Client "::ffff:127.0.0.1", anon password "ls"
Sun Apr 11 08:29:34 2021 [pid 6846] [ftp] OK LOGIN: Client "::ffff:192.168.10.5", anon password "IEUser@"
Sun Apr 11 08:29:34 2021 [pid 6840] [ftp] OK LOGIN: Client "::ffff:192.168.10.5", anon password "IEUser@"
Sun Apr 11 08:29:35 2021 [pid 6837] [ftp] OK LOGIN: Client "::ffff:192.168.10.5", anon password "IEUser@"
Sun Apr 11 09:08:34 2021 [pid 8020] [ftp] OK LOGIN: Client "::ffff:192.168.10.5", anon password "IEUser@"
Sun Apr 11 09:08:34 2021 [pid 8014] [ftp] OK LOGIN: Client "::ffff:192.168.10.5", anon password "IEUser@"
Sun Apr 11 09:08:35 2021 [pid 8013] [ftp] OK LOGIN: Client "::ffff:192.168.10.5", anon password "IEUser@"
Sun Apr 11 09:35:37 2021 [pid 8152] [ftp] OK LOGIN: Client "::ffff:192.168.10.5", anon password "?"
Sun Apr 11 09:35:45 2021 [pid 8154] [ftp] OK DOWNLOAD: Client "::ffff:192.168.10.5", "/www-data.bak", 2602 bytes, 544.81Kbyte/sec
Sun Apr 11 09:36:08 2021 [pid 8154] [ftp] OK DOWNLOAD: Client "::ffff:192.168.10.5", "/coupons_2013.md.bak", 131 bytes, 3.01Kbyte/sec
```

This gives us the user "anon", but that username isn't accepted. That's because the full name of this user is "anonymous", which is used for anonymous login in FTP (check the account `anonymous:anonymous` when you see an FTP server).

### What service and username were used to gain shell access to the server? (service, username)

Looking at the final log file `auth.log`, we can see the service `sshd` running and handling a lot of login attempts for the user `www-data`. If you look through the logs carefully or `grep` with "Accepted password", you'll see that the user `www-data` is successfully logged in after many failed attempts.

```sh
$ grep 'Accepted password' auth.log
Apr 11 09:41:19 thunt sshd[8260]: Accepted password for www-data from 192.168.10.5 port 40112 ssh2
Apr 11 09:41:32 thunt sshd[8494]: Accepted password for www-data from 192.168.10.5 port 40114 ssh2
```
