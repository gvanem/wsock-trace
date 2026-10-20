/*
	libloc - A library to determine the location of someone on the Internet

	Copyright (C) 2026 IPFire Development Team <info@ipfire.org>

	This library is free software; you can redistribute it and/or
	modify it under the terms of the GNU Lesser General Public
	License as published by the Free Software Foundation; either
	version 2.1 of the License, or (at your option) any later version.

	This library is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
	Lesser General Public License for more details.
*/

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>

#ifdef _WIN32
  #include <ws2tcpip.h>
#else
  #include <sys/socket.h>
#endif

#include <libloc/libloc.h>
#include <libloc/as.h>
#include <libloc/as-list.h>
#include <libloc/country.h>
#include <libloc/country-list.h>
#include <libloc/database.h>
#include <libloc/network.h>
#include <libloc/writer.h>

static const struct {
	const char* network;
	const char* country_code;
	uint32_t asn;
	enum loc_network_flags flags;
} NETWORKS[] = {
	{ "192.0.2.0/24",       "DE", 64496, 0 },
	{ "198.51.100.0/24",    "US", 64497, LOC_NETWORK_FLAG_ANYCAST },
	{ "203.0.113.0/24",     "DE", 64497, LOC_NETWORK_FLAG_ANONYMOUS_PROXY },
	{ "2001:db8::/32",      "DE", 64496, 0 },
	{ "2001:db8:1000::/48", "US", 64498, 0 },
	{ NULL },
};

static const struct {
	uint32_t number;
	const char* name;
} ASES[] = {
	{ 64496, "Example One" },
	{ 64497, "Example Two" },
	{ 64498, "Example Three" },
	{ 0 },
};

static const struct {
	const char* code;
	const char* name;
} COUNTRIES[] = {
	{ "DE", "Germany" },
	{ "US", "United States of America" },
	{ NULL },
};

static int create_database(struct loc_ctx* ctx, struct loc_database** db) {
	struct loc_writer* writer = NULL;
	struct loc_network* network = NULL;
	struct loc_country* country = NULL;
	struct loc_as* as = NULL;
	FILE* f = NULL;
	int r;

	r = loc_writer_new(ctx, &writer, NULL, NULL);
	if (r)
		return r;

	for (unsigned int i = 0; NETWORKS[i].network; i++) {
		r = loc_writer_add_network(writer, &network, NETWORKS[i].network);
		if (r)
			goto ERROR;

		loc_network_set_country_code(network, NETWORKS[i].country_code);
		loc_network_set_asn(network, NETWORKS[i].asn);

		if (NETWORKS[i].flags)
			loc_network_set_flag(network, NETWORKS[i].flags);

		loc_network_unref(network);
	}

	for (unsigned int i = 0; ASES[i].number; i++) {
		r = loc_writer_add_as(writer, &as, ASES[i].number);
		if (r)
			goto ERROR;

		loc_as_set_name(as, ASES[i].name);
		loc_as_unref(as);
	}

	for (unsigned int i = 0; COUNTRIES[i].code; i++) {
		r = loc_writer_add_country(writer, &country, COUNTRIES[i].code);
		if (r)
			goto ERROR;

		loc_country_set_name(country, COUNTRIES[i].name);
		loc_country_unref(country);
	}

	f = tmpfile();
	if (!f) {
		r = -errno;
		goto ERROR;
	}

	r = loc_writer_write(writer, f, LOC_DATABASE_VERSION_UNSET);
	if (r)
		goto ERROR;

	r = loc_database_new(ctx, db, f);

ERROR:
	if (writer)
		loc_writer_unref(writer);
	if (f)
		fclose(f);

	return r;
}

/*
	Walks through all networks and checks that we got the expected number.

	With flattening, no network may overlap with the one before.
*/
static int count_networks(struct loc_database_enumerator* e, int flatten,
		const char* what, int expected) {
	struct loc_network* previous = NULL;
	struct loc_network* network = NULL;
	int count = 0;
	int r;

	for (;;) {
		r = loc_database_enumerator_next_network(e, &network);
		if (r) {
			fprintf(stderr, "%s: Could not fetch the next network: %s\n", what, strerror(-r));
			goto ERROR;
		}

		if (!network)
			break;

		count++;

		if (flatten && previous && loc_network_overlaps(previous, network)) {
			fprintf(stderr, "%s: %s overlaps with %s\n", what,
				loc_network_str(network), loc_network_str(previous));
			r = -EINVAL;
			goto ERROR;
		}

		if (previous)
			loc_network_unref(previous);

		previous = network;
		network = NULL;
	}

	if (count != expected) {
		fprintf(stderr, "%s: Got %d network(s), expected %d\n", what, count, expected);
		r = -EINVAL;
	}

ERROR:
	if (previous)
		loc_network_unref(previous);
	if (network)
		loc_network_unref(network);

	return r;
}

static int test_networks(struct loc_database* db, const char* what, int flags,
		const char* country_code, uint32_t asn, enum loc_network_flags flag, int family,
		int expected) {
	struct loc_database_enumerator* e = NULL;
	struct loc_country_list* countries = NULL;
	struct loc_as_list* asns = NULL;
	struct loc_country* country = NULL;
	struct loc_as* as = NULL;
	struct loc_ctx* ctx = NULL;
	int r;

	r = loc_database_enumerator_new(&e, db, LOC_DB_ENUMERATE_NETWORKS, flags);
	if (r)
		return r;

	r = loc_new(&ctx);
	if (r)
		goto ERROR;

	if (country_code) {
		r = loc_country_list_new(ctx, &countries);
		if (r)
			goto ERROR;

		r = loc_country_new(ctx, &country, country_code);
		if (r)
			goto ERROR;

		r = loc_country_list_append(countries, country);
		if (r)
			goto ERROR;

		r = loc_database_enumerator_set_countries(e, countries);
		if (r)
			goto ERROR;

		// We must get back what we have set
		struct loc_country_list* list = loc_database_enumerator_get_countries(e);
		if (list != countries) {
			fprintf(stderr, "%s: Got a different list of countries back\n", what);
			r = -EINVAL;
		}
		if (list)
			loc_country_list_unref(list);
		if (r)
			goto ERROR;
	}

	if (asn) {
		r = loc_as_list_new(ctx, &asns);
		if (r)
			goto ERROR;

		r = loc_as_new(ctx, &as, asn);
		if (r)
			goto ERROR;

		r = loc_as_list_append(asns, as);
		if (r)
			goto ERROR;

		r = loc_database_enumerator_set_asns(e, asns);
		if (r)
			goto ERROR;

		struct loc_as_list* list = loc_database_enumerator_get_asns(e);
		if (list != asns) {
			fprintf(stderr, "%s: Got a different list of ASNs back\n", what);
			r = -EINVAL;
		}
		if (list)
			loc_as_list_unref(list);
		if (r)
			goto ERROR;
	}

	if (flag) {
		r = loc_database_enumerator_set_flag(e, flag);
		if (r)
			goto ERROR;
	}

	if (family) {
		r = loc_database_enumerator_set_family(e, family);
		if (r)
			goto ERROR;
	}

	r = count_networks(e, flags & LOC_DB_ENUMERATOR_FLAGS_FLATTEN, what, expected);
	if (r)
		goto ERROR;

	// Remove the filters again
	r = loc_database_enumerator_set_countries(e, NULL);
	if (r)
		goto ERROR;

	r = loc_database_enumerator_set_asns(e, NULL);
	if (r)
		goto ERROR;

	if (loc_database_enumerator_get_countries(e) || loc_database_enumerator_get_asns(e)) {
		fprintf(stderr, "%s: The filters could not be removed\n", what);
		r = -EINVAL;
	}

ERROR:
	if (country)
		loc_country_unref(country);
	if (countries)
		loc_country_list_unref(countries);
	if (as)
		loc_as_unref(as);
	if (asns)
		loc_as_list_unref(asns);
	if (e)
		loc_database_enumerator_unref(e);
	if (ctx)
		loc_unref(ctx);

	return r;
}

static int test_ases(struct loc_database* db, const char* string, int expected) {
	struct loc_database_enumerator* e = NULL;
	struct loc_as* as = NULL;
	int count = 0;
	int r;

	r = loc_database_enumerator_new(&e, db, LOC_DB_ENUMERATE_ASES, 0);
	if (r)
		return r;

	r = loc_database_enumerator_set_string(e, string);
	if (r)
		goto ERROR;

	for (;;) {
		r = loc_database_enumerator_next_as(e, &as);
		if (r || !as)
			break;

		count++;
		loc_as_unref(as);
	}

	if (!r && count != expected) {
		fprintf(stderr, "Searching for ASes with '%s' found %d, expected %d\n",
			string, count, expected);
		r = -EINVAL;
	}

ERROR:
	loc_database_enumerator_unref(e);

	return r;
}

static int test_countries(struct loc_database* db) {
	struct loc_database_enumerator* e = NULL;
	struct loc_country* country = NULL;
	struct loc_network* network = NULL;
	int count = 0;
	int r;

	r = loc_database_enumerator_new(&e, db, LOC_DB_ENUMERATE_COUNTRIES, 0);
	if (r)
		return r;

	for (;;) {
		r = loc_database_enumerator_next_country(e, &country);
		if (r || !country)
			break;

		if (strcmp(loc_country_get_code(country), COUNTRIES[count].code) != 0) {
			fprintf(stderr, "Got country %s, expected %s\n",
				loc_country_get_code(country), COUNTRIES[count].code);
			r = -EINVAL;
		}

		count++;
		loc_country_unref(country);

		if (r)
			goto ERROR;
	}

	if (!r && count != 2) {
		fprintf(stderr, "Found %d countries, expected 2\n", count);
		r = -EINVAL;
		goto ERROR;
	}

	// An enumerator for countries does not return any networks, and it must say so
	// even if the caller has not reset the pointer
	struct loc_network* sentinel = (struct loc_network*)(uintptr_t)1;

	network = sentinel;

	r = loc_database_enumerator_next_network(e, &network);
	if (network == sentinel) {
		fprintf(stderr, "A country enumerator did not reset the network\n");
		network = NULL;
		r = -EINVAL;

	} else if (r || network) {
		fprintf(stderr, "A country enumerator returned a network\n");
		r = -EINVAL;
	}

ERROR:
	if (network)
		loc_network_unref(network);
	loc_database_enumerator_unref(e);

	return r;
}

static int test_lookup(struct loc_database* db) {
	struct loc_network* network = NULL;
	struct in6_addr address = {};
	int r;

	// 198.51.100.1 as an IPv4-mapped IPv6 address
	address.s6_addr[10] = 0xff;
	address.s6_addr[11] = 0xff;
	address.s6_addr[12] = 198;
	address.s6_addr[13] = 51;
	address.s6_addr[14] = 100;
	address.s6_addr[15] = 1;

	r = loc_database_lookup(db, &address, &network);
	if (r)
		return r;

	if (!network) {
		fprintf(stderr, "Could not find 198.51.100.1\n");
		return -ENOENT;
	}

	if (strcmp(loc_network_str(network), "198.51.100.0/24") != 0) {
		fprintf(stderr, "Found %s for 198.51.100.1\n", loc_network_str(network));
		r = -EINVAL;
	}

	loc_network_unref(network);

	return r;
}

int main(int argc, char** argv) {
	struct loc_database* db = NULL;
	struct loc_ctx* ctx = NULL;
	int r;

	r = loc_new(&ctx);
	if (r)
		exit(EXIT_FAILURE);

	loc_set_log_priority(ctx, LOG_DEBUG);

	r = create_database(ctx, &db);
	if (r) {
		fprintf(stderr, "Could not create the database: %s\n", strerror(-r));
		exit(EXIT_FAILURE);
	}

	const int flatten = LOC_DB_ENUMERATOR_FLAGS_FLATTEN;

	// The filters are combined with OR, and the family has to match on top
	if (test_networks(db, "All",     0, NULL, 0, 0, 0, 5)
			|| test_networks(db, "IPv4",    0, NULL, 0, 0, AF_INET, 3)
			|| test_networks(db, "IPv6",    0, NULL, 0, 0, AF_INET6, 2)
			|| test_networks(db, "DE",      0, "DE", 0, 0, 0, 3)
			|| test_networks(db, "DE IPv6", 0, "DE", 0, 0, AF_INET6, 1)
			|| test_networks(db, "AS64497", 0, NULL, 64497, 0, 0, 2)
			|| test_networks(db, "Anycast", 0, NULL, 0, LOC_NETWORK_FLAG_ANYCAST, 0, 1)
			|| test_networks(db, "US or AS64496", 0, "US", 64496, 0, 0, 4)
			|| test_networks(db, "Satellite", 0, NULL, 0, LOC_NETWORK_FLAG_SATELLITE_PROVIDER, 0, 0)

			// 2001:db8::/32 is split around 2001:db8:1000::/48 into 16 networks
			|| test_networks(db, "Flattened", flatten, NULL, 0, 0, 0, 20)
			|| test_networks(db, "Flattened DE", flatten, "DE", 0, 0, 0, 18)
			|| test_networks(db, "Flattened US", flatten, "US", 0, 0, 0, 2))
		exit(EXIT_FAILURE);

	if (test_ases(db, NULL, 3)
			|| test_ases(db, "example", 3)
			|| test_ases(db, "TWO", 1)
			|| test_ases(db, "nothing", 0))
		exit(EXIT_FAILURE);

	if (test_countries(db))
		exit(EXIT_FAILURE);

	if (test_lookup(db))
		exit(EXIT_FAILURE);

	loc_database_unref(db);
	loc_unref(ctx);

	return EXIT_SUCCESS;
}
