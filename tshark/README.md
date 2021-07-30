# [TShark](https://tryhackme.com/room/tshark)

## Task 2

> How many packets are in the dns.cap file?

Just reading lists all the packets which we can count with `wc`.

```sh
tshark -r dns.cap | wc -l
```

> How many A records are in the capture? (Including responses)

The filter for A records is `dns.qry.type == 1`

```sh
tshark -r dns.cap -Y 'dns.qry.type == 1' | wc -l
```

> Which A record was present the most?

We can use `sort` and `uniq -c` to count occurrences.

```sh
tshark -r dns.cap -Y 'dns.qry.type == 1' -T fields -e dns.qry.name | sort | uniq -c
```

## Task 3

> How many packets are in this capture?

```sh
tshark -r dnsexfil.pcap | wc -l
```

> How many DNS queries are in this pcap? (Not responses!)

To filter out responses, use the filter `dns.flags.response == 0`

```sh
tshark -r dnsexfil.pcap -Y 'dns.flags.response == 0' | wc -l
```

> What is the DNS transaction ID of the suspicious queries (in hex)?

Looking at the packets from the previous question, all the filtered packets are suspicious. To get DNS IDs, grab the field `dns.id`.

```sh
tshark -r dnsexfil.pcap -Y 'dns.flags.response == 0' -T fields -e 'dns.id'
```

> What is the string extracted from the DNS queries?

Looking at the DNS queries, each query has a different single letter for the subdomain which we can extract with `cut` and combine with `tr`.

```sh
tshark -r dnsexfil.pcap -Y 'dns.flags.response == 0' -T fields -e dns.qry.name | cut -d'.' -f1 | tr -d '\n'
```

> What is the flag?

The string looks like base64 but it's actually base32.

```sh
tshark -r dnsexfil.pcap -Y 'dns.flags.response == 0' -T fields -e dns.qry.name | cut -d'.' -f1 | tr -d '\n' | base32 -d
```
