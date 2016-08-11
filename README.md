I Can't Believe It's Not DNS!
===
"I Can't Believe It's Not DNS!" (ICBIND) is an authoritative DNS server for the 
ESP8266 written in MicroPython. 

Anti-features
---
* No storage of zone files, populated by AXFR.
* DNSSEC filtering.
* TSIG-less AXFR support!
* Notify handling.
* Highly optimized: no sanity checks.

Preamble
---
When I first received my ESP8266 I flashed the NodeMCU firmware on it. To make
myself familiar with the ESP and Lua tried writing an authoritative DNS server
for it. A crappy server only echoing the queries over TCP (UDP was broken on
NodeMCU) could do _almost_ 2 qps. That project quickly stopped.

I was excited when MicroPython came out and decided to start a similar project.
MicroPython was much more capable than Lua and I got 150 to 160 qps! Soon I hit
limitations on memory consumption and code size. To get it running I needed to
~~cut some corners~~ highly optimize the code.

Introduction
---
The code is contained in three files: boot.py establishes Wifi connection.
main.py contains the DNS server code and, trusted_networks.py has just a
dictionary of ESSID and password combinations. The latter is not included in
the git repository and you should create one yourself (see boot.py).

The other thing you need to edit before uploading the files is the first few
lines of main.py. There the zone as well as the master server to get it from are
defined.

For convenience a Makefile is included. Though in order to use it you probably
need to fiddle with it.

Modus Operandi
---
At boot ICBIND will select the strongest Wifi access point it has credentials
for and connect to it. It does _not_ start webrepl as that would prevent
main.py to load due to memory shortage.

Then the daemon will start. First it will transfer the zone via AXFR. When that
is done it starts to answer queries from its database. Finally when a notify is
received it will retransfer the zone.

Implementation Details
---
My personal domain is rather small. Less than 20 records or thereabouts. While
my TLD does not offer upload of DS records I _did_ sign my zone. As a result a
AXFR reply is about 13 KiB. After receiving the AXFR I tried to do something 
with that data: ENOMEM. Crud.

Python to the rescue! I can make an iterator that I would feed a socket which
would read from said socket and spit out parsed Resource records! Easy does it.
Except... DNS uses compression pointers. Compression pointers greatly reduce
the size of DNS packets by eliminating repeating of owner names of resource
records.  BUT we don't have enough memory to buffer the entire AXFR. We need a
plan.

Plan A
---
So a compression pointer is just an octet pointing back relative to its current
position right? (HINT: No it isn't you up mucking asshole codemonkey). So I
just need to keep a sliding window of the last 256 bytes! In reality a
compression pointer is 14 bits wide and absolute from the start of the message.
Most names will point to one of the very first resource records in the message.
So let us also keep a copy of the first 256 bytes. That surely must catch 99
percent of all cases, we just drop any record we can't resolve the pointer for.
Who cares!  Well, that is mostly true. But I wasn't satisfied with the amount
of records dropped in my small zone. So nothing else to do but store the AXFR
on flash you say? Oh you don't know me! It's personal now, I have a plan B.

Plan B
---
What if we don't resolve the compression pointers during the AXFR? That's right,
just let them sit unresolved for a bit. In the mean time drop all those pesky
DNSSEC records we are offered. Those are to big anyway and I really don't want to
deal with NSEC lookups on this tiny device. Also, while we are at it drop
anything other than class IN, that does not exist in my world. We end up with
just a small set of records.  But how do we resolve the owner names, we don't
have this data any more?

I know somebody who has this data... the master! You know what? With that set
of records in hand do _another_ AXFR a couple of bytes at the time and resolve
those pointers on the fly without the need to buffer anything longer than a
label (max 63 bytes). Of course compression pointers can be nested so we need
to repeat this process in a loop until every pointer is resolved!

Serving Queries
---
This is the easy part. Lets do as little as possible. When a query comes in we
chop of anything beyond the question section. BAM! We have most of our reply
done.  Fiddle a bit with the flags and section counts, assume query name is
uncompressed and append our resource record. Our database only contains TYPE and
RDATA. Query name?  Always a pointer to byte 12 in the packet. Class? always
IN. TLL? always 15 minutes, deal with it.

SOA Serial Management
---
Finally we need a mechanism to update our little DNS server if the zone has
changed. Serious software would keep track of the version of the zone via the
SOA serial number. Poll for a new version on set times, listen to notifies
from the master and make an intelligible decision when and how to update the zone.

We don't have the memory available to be intelligible. But we can listen for 
notify queries. If we receive a notify, any notify -  we optimized out any ACL or
checking of the zone name, we simply reboot(). The ESP8266 will powercycle and
the new version of the zone will be transferred and served. SOA serial 
management made easy!

Epilogue
---
This software is shit. It sort of mimics DNS but really it isn't. You should
not use this, I should not use this (but you know I will because DNS hosting
on my ESP8266 is freaking awesome!)

