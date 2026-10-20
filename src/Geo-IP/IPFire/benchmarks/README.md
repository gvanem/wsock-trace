# Benchmarks

This directory has the programs that compare lookups in libloc with lookups in
[libmaxminddb](https://github.com/maxmind/libmaxminddb), which reads databases in
the MaxMind DB format, and the results.

As a database in that format, we use DB-IP Lite, because like the IPFire Location
Database, it can be downloaded without an account. It needs two databases for the
country and the Autonomous System of an address. Both are read with
libmaxminddb, so that the results apply to all databases in that format.

## Results

All lookups return the country and the ASN, unless they say otherwise. libmaxminddb
needs two lookups for that, one in each database.

### C, one thread

| Lookup | libloc, database as published | libloc, database rewritten | libmaxminddb |
|---|--:|--:|--:|
| IPv4, country only | | | 373–487 ns |
| IPv4, country + ASN | 404 ns | 319–324 ns | 713–743 ns |
| IPv6, country only | | | 521–589 ns |
| IPv6, country + ASN | 1509 ns | 680–682 ns | 947–1117 ns |

"As published" is the IPFire Location Database of 2026-10-14. "Rewritten" is
the same data, written by the writer of this version of libloc, which stores the
tree depth-first, so that a lookup has to wait for memory less often. The
database is going to look like that once it is being written with this version.

The ranges are the results of up to three runs, which were a few minutes apart.

### C, more than one thread

Millions of lookups per second, country + ASN, with the rewritten database:

| Threads | 1 | 2 | 4 | 8 | 16 |
|---|--:|--:|--:|--:|--:|
| libloc, IPv4 | 2.5–2.6 | 4.0–4.3 | 6.7 | 7.9–8.6 | 8.2–9.3 |
| libmaxminddb, IPv4 | 1.1–1.3 | 2.4 | 3.1–4.7 | 5.9–7.5 | 7.3–8.5 |
| libloc, IPv6 | 1.3–1.4 | 2.1–2.5 | 3.3–4.6 | 5.7–7.4 | 7.4–8.5 |
| libmaxminddb, IPv6 | 0.9–1.0 | 1.6–1.8 | 2.6–3.2 | 4.6–5.0 | 5.0–8.0 |

The machine has 16 virtual CPUs, which it shares with other virtual machines, so
that the results for 8 and 16 threads vary a lot.

### Python

| Lookup | libloc, as published | libloc, rewritten | maxminddb |
|---|--:|--:|--:|
| IPv4, country only | | | 5.2–5.6 µs |
| IPv4, country + ASN | 0.72–0.83 µs | 0.75–0.89 µs | 6.4–7.7 µs |
| IPv6, country only | | | 6.3–6.7 µs |
| IPv6, country + ASN | 1.9–2.5 µs | 1.2–1.5 µs | 7.5–8.8 µs |

The maxminddb module uses its C extension (`MODE_MMAP_EXT`). It returns
everything that the database knows about an address as a dictionary.

In the same runs, before the address parser has been made faster (c5b15d4 and
77a6c8e), IPv4 lookups took 0.80–0.92 µs as published and 0.83–0.90 µs
rewritten. IPv6 lookups varied more from one run to the next than they changed.

### Size and memory

| | IPFire Location Database | DB-IP Lite |
|---|--:|--:|
| Files | 50.2 MB as published, 39.5 MB rewritten | 8.3 MB (country) + 9.6 MB (ASN) |
| In memory after 10 million lookups | 45.0 MiB as published, 34.9 MiB rewritten | 16.8 MiB |
| Opening | 0.3–0.5 ms | 0.4–0.8 ms (both) |

Both are mapped into memory, so that the memory is the page cache, which all
programs that use the same file share.

The IPFire Location Database is larger, because it knows more about every
network: whether it belongs to an anonymous proxy, a satellite provider or an
anycast network, or is on a list of networks that should be dropped, and it has
the names of all Autonomous Systems and countries. The format also stores the
network of every node in the tree in its own field, while the MaxMind DB format
stores it in the pointer to the node.

### Do they agree?

Of the addresses where both databases know the country or the ASN:

| | Same country | Same ASN |
|---|--:|--:|
| IPv4 | 96.5% of 171862 | 99.5% of 144090 |
| IPv6 | 51.8% of 199999 | 96.7% of 79552 |

Most of the IPv4 addresses with a different country are in the United States
according to one database, and in Canada according to the other.

The IPv6 addresses are random addresses in networks that have been allocated,
of which most are large and only used in small parts. The IPFire Location Database
returns the country that the Regional Internet Registry has allocated the network
to, which is EU for many networks in Europe, and AU for some of APNIC. DB-IP Lite
returns a country for every part of such a network. Neither of them is wrong,
but they rarely agree. This says nothing about which database is more accurate,
which this benchmark does not measure.

## How we measured

### Versions

| | Version |
|---|---|
| libloc | 0470acc (after 0.9.19), 93113c6 for Python |
| libmaxminddb | 1.12.2 (Debian package 1.12.2-1) |
| maxminddb for Python | 2.6.3 (Debian package 2.6.3-1+b1) |
| IPFire Location Database | 2026-10-14 04:34:25 UTC, as published |
| DB-IP Country Lite | 2026-10 (built 2026-10-01 01:36:12 UTC) |
| DB-IP ASN Lite | 2026-10 (built 2026-10-01 01:41:36 UTC) |
| Compiler | GCC 14.2.0 (Debian 14.2.0-19) |
| Python | 3.13.5 |
| Operating system | Debian GNU/Linux 13 (trixie), Linux 6.12.95+deb13-cloud-amd64 |

libloc and the benchmark have been built with the flags that Debian builds
packages with (`dpkg-buildflags`), which use `-O2`. libmaxminddb and the
maxminddb module are the packages of Debian.

Building libloc with `-O3`, or with link-time optimisation, made no difference
that could be measured.

### Machine

A virtual machine (KVM) with 16 virtual CPUs of an Intel Xeon E5-2690 v4 at
2.6 GHz (2 sockets with 8 cores, 32 MiB of L3 cache in total) and 125 GiB of
memory, which was also running other work. The load average was between 2.6 and
4.1 while the benchmarks in C were running, and between 1.8 and 4.3 for
Python. All files were in the page cache.

### Addresses

The same addresses are used for both libraries, and they are the same in every run:

* 1000000 random IPv4 addresses (200000 in Python), of which 86% have a country.
* 1000000 IPv6 addresses (200000 in Python), which are random addresses in a
  random network of the 851828 IPv6 networks that have a country in the IPFire
  Location Database. Random IPv6 addresses would almost all be in space that has
  never been allocated, where both databases find nothing very quickly.

In C, all addresses are being looked up five times, and we take the median. Every
lookup reads the country and the ASN of what it has found. In Python, we take the
fastest of three times, and the ranges are the results of three runs.

With more than one thread, every thread looks up its own part of the addresses.

The memory is what `/proc/self/smaps` says is resident of the database files.

## Running the benchmarks

You need libloc, libmaxminddb with its headers, the maxminddb module for Python,
an IPFire Location Database and both DB-IP Lite databases in the MaxMind DB format:

	curl -O https://location.ipfire.org/databases/1/location.db.xz
	curl -O https://download.db-ip.com/free/dbip-country-lite-2026-10.mmdb.gz
	curl -O https://download.db-ip.com/free/dbip-asn-lite-2026-10.mmdb.gz

	unxz location.db.xz
	gunzip dbip-*.mmdb.gz

Build and run the benchmark in C:

	gcc $(dpkg-buildflags --get CFLAGS) -o lookup lookup.c -lloc -lmaxminddb -lpthread
	./lookup location.db dbip-country-lite-2026-10.mmdb dbip-asn-lite-2026-10.mmdb

It takes a few minutes. Pass `libloc` or `mmdb` as the fourth argument to only
run the benchmarks of one of them.

Run the benchmark in Python:

	python3 lookup.py location.db dbip-country-lite-2026-10.mmdb dbip-asn-lite-2026-10.mmdb

DB-IP Lite is licensed under
[CC BY 4.0](https://creativecommons.org/licenses/by/4.0/) by
[DB-IP](https://db-ip.com).
