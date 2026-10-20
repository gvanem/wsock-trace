#!/usr/bin/python3
#
# Compares lookups in the Python module of libloc with the maxminddb module
#
#   lookup.py LOCATION.DB COUNTRY.MMDB ASN.MMDB
#
# See README.md for how to run it.
#

import ipaddress
import random
import sys
import time

import location
import maxminddb

# How many addresses we look up
N = 200000

# How often we look them all up, of which we take the fastest
ROUNDS = 3

path, country_path, asn_path = sys.argv[1:4]

random.seed(1)

db = location.Database(path)

country = maxminddb.open_database(country_path, maxminddb.MODE_MMAP_EXT)
asn = maxminddb.open_database(asn_path, maxminddb.MODE_MMAP_EXT)

# IPv4: anything
v4 = [str(ipaddress.IPv4Address(random.getrandbits(32))) for _ in range(N)]

# IPv6: addresses in networks that have been allocated, like in the C benchmark
networks = [n for n in db.search_networks(family=10, flatten=True) if n.country_code]

v6 = []
for _ in range(N):
	n = ipaddress.ip_network(str(random.choice(networks)))

	v6.append(str(n.network_address + random.getrandbits(n.max_prefixlen - n.prefixlen)))

def bench(name, fn, addresses):
	best = None

	for _ in range(ROUNDS):
		t = time.perf_counter()

		for a in addresses:
			fn(a)

		t = time.perf_counter() - t

		if best is None or t < best:
			best = t

	print("%-44s %6.0f ns/lookup" % (name, best / len(addresses) * 1e9))

def loc_both(a):
	n = db.lookup(a)
	if n:
		return n.country_code, n.asn

	return None, None

def mm_country(a):
	r = country.get(a)
	if r:
		return r["country"]["iso_code"]

def mm_both(a):
	c, n = None, None

	r = country.get(a)
	if r:
		c = r["country"]["iso_code"]

	r = asn.get(a)
	if r:
		n = r.get("autonomous_system_number")

	return c, n

print("location from %s, maxminddb %s (MODE_MMAP_EXT)" % (location.__file__, maxminddb.__version__))

for family, addresses in (("IPv4", v4), ("IPv6", v6)):
	bench("libloc: %s, country + ASN" % family, loc_both, addresses)
	bench("maxminddb: %s, country only" % family, mm_country, addresses)
	bench("maxminddb: %s, country + ASN" % family, mm_both, addresses)

for name, fn in (
	("libloc: open", lambda: location.Database(path)),
	("maxminddb: open both", lambda: (maxminddb.open_database(country_path, maxminddb.MODE_MMAP_EXT),
		maxminddb.open_database(asn_path, maxminddb.MODE_MMAP_EXT))),
):
	t = time.perf_counter()
	fn()
	print("%-44s %6.2f ms" % (name, (time.perf_counter() - t) * 1e3))

# How often both say the same, of the addresses where both know something
for family, addresses in (("IPv4", v4), ("IPv6", v6)):
	countries, same_countries, asns, same_asns = 0, 0, 0, 0

	for a in addresses:
		lc, ln = loc_both(a)
		mc, mn = mm_both(a)

		if lc and mc:
			countries += 1

			if lc == mc:
				same_countries += 1

		if ln and mn:
			asns += 1

			if ln == mn:
				same_asns += 1

	print("%s: the country is the same for %.1f%% of %d addresses, the ASN for %.1f%% of %d" % (
		family, same_countries * 100 / countries, countries, same_asns * 100 / asns, asns))
