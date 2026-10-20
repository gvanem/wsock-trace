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

#include <arpa/inet.h>
#include <sys/mman.h>
#include <unistd.h>

#include <libloc/libloc.h>
#include <libloc/as.h>
#include <libloc/country.h>
#include <libloc/database.h>
#include <libloc/network.h>

#include "fuzz.h"

/*
	Opens whatever we are being given as a database and uses everything that
	reads from it: The meta data, searching for ASes and countries, looking up
	addresses and walking through all networks.
*/

// Don't walk through more objects than this, as the engine considers us hanging
// if a single input takes too long.
#define MAX_OBJECTS		4096

// Addresses that we look up in addition to the ones that we make from the input
static const char* addresses[] = {
	"::",
	"2001:db8::1",
	"ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
	"0.0.0.0",
	"10.0.0.1",
	"192.0.2.1",
	"255.255.255.255",
	NULL,
};

static void fuzz_lookup(struct loc_database* db, const struct in6_addr* address) {
	struct loc_network* network = NULL;
	int r;

	r = loc_database_lookup(db, address, &network);
	if (r || !network)
		return;

	// Use what we have found
	loc_network_str(network);
	loc_network_get_country_code(network);
	loc_network_get_asn(network);

	loc_network_unref(network);
}

static void fuzz_enumerate(struct loc_database* db,
		enum loc_database_enumerator_mode mode, int flags) {
	struct loc_database_enumerator* enumerator = NULL;
	struct loc_network* network = NULL;
	struct loc_country* country = NULL;
	struct loc_as* as = NULL;
	int r;

	r = loc_database_enumerator_new(&enumerator, db, mode, flags);
	if (r)
		return;

	for (unsigned int i = 0; i < MAX_OBJECTS; i++) {
		switch (mode) {
			case LOC_DB_ENUMERATE_NETWORKS:
			case LOC_DB_ENUMERATE_BOGONS:
				r = loc_database_enumerator_next_network(enumerator, &network);
				if (r || !network)
					goto END;

				loc_network_str(network);
				loc_network_unref(network);
				break;

			case LOC_DB_ENUMERATE_ASES:
				r = loc_database_enumerator_next_as(enumerator, &as);
				if (r || !as)
					goto END;

				loc_as_get_name(as);
				loc_as_unref(as);
				break;

			case LOC_DB_ENUMERATE_COUNTRIES:
				r = loc_database_enumerator_next_country(enumerator, &country);
				if (r || !country)
					goto END;

				loc_country_get_name(country);
				loc_country_unref(country);
				break;
		}
	}

END:
	loc_database_enumerator_unref(enumerator);
}

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
	struct loc_database* db = NULL;
	struct loc_country* country = NULL;
	struct loc_as* as = NULL;
	struct in6_addr address;
	FILE* f = NULL;
	int fd = -1;
	int r;

	// The database can only be opened from a file, so we create one in memory
	fd = memfd_create("libloc-fuzz", MFD_CLOEXEC);
	if (fd < 0)
		goto ERROR;

	// Write the data
	for (size_t offset = 0; offset < size;) {
		ssize_t bytes_written = write(fd, data + offset, size - offset);
		if (bytes_written < 0)
			goto ERROR;

		offset += bytes_written;
	}

	f = fdopen(fd, "r");
	if (!f)
		goto ERROR;

	// The stream owns the file descriptor now
	fd = -1;

	// Open the database
	r = loc_database_new(fuzz_ctx, &db, f);
	if (r)
		goto ERROR;

	// Read the meta data
	loc_database_created_at(db);
	loc_database_get_vendor(db);
	loc_database_get_description(db);
	loc_database_get_license(db);

	// Search for some ASes
	static const uint32_t asns[] = { 0, 1, 64496, 2147483648, 4294967295 };

	for (unsigned int i = 0; i < sizeof(asns) / sizeof(*asns); i++) {
		r = loc_database_get_as(db, &as, asns[i]);
		if (r == 0 && as) {
			loc_as_get_name(as);
			loc_as_unref(as);
		}
	}

	// Search for some countries
	static const char* codes[] = { "AA", "DE", "ZZ", NULL };

	for (const char** code = codes; *code; code++) {
		r = loc_database_get_country(db, &country, *code);
		if (r == 0 && country) {
			loc_country_get_name(country);
			loc_country_unref(country);
		}
	}

	// Look up some addresses
	for (const char** a = addresses; *a; a++) {
		r = inet_pton(AF_INET6, *a, &address);

		// Map IPv4 addresses
		if (r != 1) {
			memset(&address, 0, sizeof(address));
			address.s6_addr[10] = address.s6_addr[11] = 0xff;

			r = inet_pton(AF_INET, *a, &address.s6_addr[12]);
		}

		if (r == 1)
			fuzz_lookup(db, &address);
	}

	// Let the engine choose some more addresses from wherever it wants in the input
	for (size_t offset = 0; offset + sizeof(address) <= size && offset < 16 * sizeof(address);
			offset += sizeof(address)) {
		memcpy(&address, data + size - offset - sizeof(address), sizeof(address));

		fuzz_lookup(db, &address);
	}

	// Walk through everything
	fuzz_enumerate(db, LOC_DB_ENUMERATE_NETWORKS, 0);
	fuzz_enumerate(db, LOC_DB_ENUMERATE_NETWORKS, LOC_DB_ENUMERATOR_FLAGS_FLATTEN);
	fuzz_enumerate(db, LOC_DB_ENUMERATE_BOGONS, 0);
	fuzz_enumerate(db, LOC_DB_ENUMERATE_ASES, 0);
	fuzz_enumerate(db, LOC_DB_ENUMERATE_COUNTRIES, 0);

ERROR:
	if (db)
		loc_database_unref(db);
	if (f)
		fclose(f);
	if (fd >= 0)
		close(fd);

	return 0;
}
