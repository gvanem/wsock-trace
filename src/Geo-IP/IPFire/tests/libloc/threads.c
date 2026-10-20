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
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <libloc/libloc.h>
#include <libloc/as.h>
#include <libloc/country.h>
#include <libloc/database.h>
#include <libloc/network.h>
#include <libloc/writer.h>

/*
	Uses one database from many threads at the same time, which is what
	everything that loads us into a daemon does.
*/

#define NUM_THREADS			8
#define NUM_ITERATIONS		2000

static const struct network {
	const char* network;
	const char* country_code;
	uint32_t asn;
} networks[] = {
	{ "10.0.0.0/8",       "DE", 64496 },
	{ "192.0.2.0/24",     "AT", 64497 },
	{ "198.51.100.0/24",  "FR", 64498 },
	{ "2001:db8::/32",    "GB", 64499 },
	{ "2001:db8:1::/48",  "US", 64500 },
	{ NULL },
};

static const struct lookup {
	const char* address;
	const char* network;
} lookups[] = {
	{ "10.1.2.3",         "10.0.0.0/8" },
	{ "192.0.2.1",        "192.0.2.0/24" },
	{ "198.51.100.255",   "198.51.100.0/24" },
	{ "203.0.113.1",      NULL },
	{ "2001:db8::1",      "2001:db8::/32" },
	{ "2001:db8:1::1",    "2001:db8:1::/48" },
	{ "2001:db9::1",      NULL },
	{ NULL },
};

static int test_lookups(struct loc_database* db) {
	struct loc_network* network = NULL;
	int r;

	for (const struct lookup* lookup = lookups; lookup->address; lookup++) {
		r = loc_database_lookup_from_string(db, lookup->address, &network);
		if (r) {
			fprintf(stderr, "Could not look up %s: %s\n", lookup->address, strerror(-r));
			return r;
		}

		const char* s = NULL;

		if (network)
			s = loc_network_str(network);

		if (!s != !lookup->network || (s && strcmp(s, lookup->network) != 0)) {
			fprintf(stderr, "Looked up %s and got %s, but expected %s\n",
				lookup->address, s, lookup->network);
			r = -EINVAL;
		}

		// The first address is being formatted for each call

		if (network && !loc_network_format_first_address(network))
			r = -EINVAL;

		if (network)
			loc_network_unref(network);

		if (r)
			return r;
	}

	return 0;
}

static int test_objects(struct loc_database* db) {
	struct loc_country* country = NULL;
	struct loc_as* as = NULL;
	int r;

	for (const struct network* n = networks; n->network; n++) {
		// Fetch the AS
		r = loc_database_get_as(db, &as, n->asn);
		if (r) {
			fprintf(stderr, "Could not find AS%u: %d\n", n->asn, r);
			return -ENOENT;
		}

		if (loc_as_get_number(as) != n->asn) {
			fprintf(stderr, "Searched for AS%u, but got AS%u\n", n->asn, loc_as_get_number(as));
			r = -EINVAL;
		}

		loc_as_unref(as);

		if (r)
			return r;

		// Fetch the country
		r = loc_database_get_country(db, &country, n->country_code);
		if (r || !country) {
			fprintf(stderr, "Could not find country %s: %d\n", n->country_code, r);
			return -ENOENT;
		}

		if (strcmp(loc_country_get_code(country), n->country_code) != 0) {
			fprintf(stderr, "Searched for %s, but got %s\n",
				n->country_code, loc_country_get_code(country));
			r = -EINVAL;
		}

		loc_country_unref(country);

		if (r)
			return r;
	}

	return 0;
}

static int test_enumerator(struct loc_database* db) {
	struct loc_database_enumerator* enumerator = NULL;
	struct loc_network* network = NULL;
	unsigned int counter = 0;
	int r;

	r = loc_database_enumerator_new(&enumerator, db, LOC_DB_ENUMERATE_NETWORKS, 0);
	if (r)
		return r;

	while (1) {
		r = loc_database_enumerator_next_network(enumerator, &network);
		if (r || !network)
			break;

		if (!loc_network_str(network))
			r = -EINVAL;

		loc_network_unref(network);

		if (r)
			break;

		counter++;
	}

	loc_database_enumerator_unref(enumerator);

	if (r)
		return r;

	// We must have seen all networks
	if (counter != (sizeof(networks) / sizeof(*networks)) - 1) {
		fprintf(stderr, "Enumerated %u network(s)\n", counter);
		return -EINVAL;
	}

	return 0;
}

static void* run(void* data) {
	struct loc_database* db = loc_database_ref(data);
	int r = 0;

	for (unsigned int i = 0; i < NUM_ITERATIONS; i++) {
		r = test_lookups(db);
		if (r)
			break;

		r = test_objects(db);
		if (r)
			break;

		// This is slower than everything else
		if (i % 10 == 0) {
			r = test_enumerator(db);
			if (r)
				break;
		}
	}

	loc_database_unref(db);

	if (r)
		return data;

	return NULL;
}

int main(int argc, char** argv) {
	struct loc_ctx* ctx = NULL;
	struct loc_writer* writer = NULL;
	struct loc_database* db = NULL;
	struct loc_network* network = NULL;
	struct loc_country* country = NULL;
	struct loc_as* as = NULL;
	pthread_t threads[NUM_THREADS];
	int failed = 0;
	int r;

	r = loc_new(&ctx);
	if (r < 0)
		exit(EXIT_FAILURE);

	// Create a database
	r = loc_writer_new(ctx, &writer, NULL, NULL);
	if (r < 0)
		exit(EXIT_FAILURE);

	for (const struct network* n = networks; n->network; n++) {
		r = loc_writer_add_network(writer, &network, n->network);
		if (r) {
			fprintf(stderr, "Could not add network %s: %d\n", n->network, r);
			exit(EXIT_FAILURE);
		}

		loc_network_set_country_code(network, n->country_code);
		loc_network_set_asn(network, n->asn);
		loc_network_unref(network);

		r = loc_writer_add_as(writer, &as, n->asn);
		if (r) {
			fprintf(stderr, "Could not add AS%u: %d\n", n->asn, r);
			exit(EXIT_FAILURE);
		}

		loc_as_unref(as);

		r = loc_writer_add_country(writer, &country, n->country_code);
		if (r) {
			fprintf(stderr, "Could not add country %s: %d\n", n->country_code, r);
			exit(EXIT_FAILURE);
		}

		loc_country_unref(country);
	}

	FILE* f = tmpfile();
	if (!f) {
		fprintf(stderr, "Could not open file for writing: %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	}

	r = loc_writer_write(writer, f, LOC_DATABASE_VERSION_UNSET);
	if (r) {
		fprintf(stderr, "Could not write database: %d\n", r);
		exit(EXIT_FAILURE);
	}

	loc_writer_unref(writer);

	// And open it again from disk
	r = loc_database_new(ctx, &db, f);
	if (r) {
		fprintf(stderr, "Could not open database: %d\n", r);
		exit(EXIT_FAILURE);
	}

	fclose(f);

	// Use it from all threads at once
	for (unsigned int i = 0; i < NUM_THREADS; i++) {
		r = pthread_create(&threads[i], NULL, run, db);
		if (r) {
			fprintf(stderr, "Could not create thread: %s\n", strerror(r));
			exit(EXIT_FAILURE);
		}
	}

	for (unsigned int i = 0; i < NUM_THREADS; i++) {
		void* result = NULL;

		r = pthread_join(threads[i], &result);
		if (r) {
			fprintf(stderr, "Could not join thread: %s\n", strerror(r));
			exit(EXIT_FAILURE);
		}

		if (result)
			failed++;
	}

	if (failed) {
		fprintf(stderr, "%d thread(s) have failed\n", failed);
		exit(EXIT_FAILURE);
	}

	loc_database_unref(db);
	loc_unref(ctx);

	return EXIT_SUCCESS;
}
