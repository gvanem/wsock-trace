/*
	libloc - A library to determine the location of someone on the Internet

	Copyright (C) 2017 IPFire Development Team <info@ipfire.org>

	This program is free software; you can redistribute it and/or modify
	it under the terms of the GNU General Public License as published by
	the Free Software Foundation; either version 2 of the License, or
	(at your option) any later version.

	This program is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.
*/

#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <ctype.h>
#include <errno.h>
#include <unistd.h>
#include <syslog.h>

#ifdef _WIN32
  #include <ws2tcpip.h>
#else
error(1): wrong syntax
#endif

#include <libloc/libloc.h>
#include <libloc/compat.h>
#include <libloc/database.h>
#include <libloc/format.h>
#include <libloc/writer.h>

const char* VENDOR = "Test Vendor";
const char* DESCRIPTION =
	"Lorem ipsum dolor sit amet, consectetur adipiscing elit. "
	"Proin ultrices pulvinar dolor, et sollicitudin eros ultricies "
	"vitae. Nam in volutpat libero. Nulla facilisi. Pellentesque "
	"tempor felis enim. Integer congue nisi in maximus pretium. "
	"Pellentesque et turpis elementum, luctus mi at, interdum erat. "
	"Maecenas ut venenatis nunc.";
const char* LICENSE = "CC";

const char* networks[] = {
	"2001:db8::/32",
	"2001:db8:1000::/48",
	"2001:db8:2000::/48",
	"2001:db8:2020::/48",
	NULL,
};

// Single addresses, which are as deep in the tree as it gets
const char* hosts[] = {
	"2001:db8:ffff::1/128",
	"192.0.2.1/32",
	NULL,
};

static int lookup(struct loc_database* db, const char* address, const char* expected) {
	struct loc_network* network = NULL;
	int r;

	r = loc_database_lookup_from_string(db, address, &network);
	if (r) {
		fprintf(stderr, "Could not look up %s: %d\n", address, r);
		return 1;
	}

	const char* s = NULL;

	if (network)
		s = loc_network_str(network);

	// Check if we got what we expected
	if (!s != !expected || (s && strcmp(s, expected) != 0)) {
		fprintf(stderr, "Looked up %s and got %s, but expected %s\n", address, s, expected);
		r = 1;
	}

	if (network)
		loc_network_unref(network);

	return r;
}

static int attempt_to_open(struct loc_ctx* ctx, const char* path) {
	FILE* f = fopen(path, "rb");
	if (!f)
		return -1;

	struct loc_database* db;
	int r = loc_database_new(ctx, &db, f);

	if (r == 0) {
		fprintf(stderr, "Opening %s was unexpectedly successful\n", path);
		loc_database_unref(db);

		r = 1;
	}

	// Close the file again
	fclose(f);

	return r;
}

#define HEADER(field) \
	(sizeof(struct loc_database_magic) + offsetof(struct loc_database_header_v1, field))

static uint32_t read32(const char* data, size_t offset) {
	uint32_t value;

	memcpy(&value, data + offset, sizeof(value));

	return be32toh(value);
}

static void write32(char* data, size_t offset, uint32_t value) {
	value = htobe32(value);

	memcpy(data + offset, &value, sizeof(value));
}

/*
	Opens the database in data and uses everything that reads from it. Returns zero
	if the database could be opened and a negative number if it could not. If the
	database is broken in other ways we may fail, but we must not crash.
*/
static int use_database(struct loc_ctx* ctx, const char* data, size_t length) {
	struct loc_database_enumerator* enumerator = NULL;
	struct loc_database* db = NULL;
	struct loc_network* network = NULL;
	struct loc_country* country = NULL;
	struct loc_as* as = NULL;
	int r;

	FILE* f = tmpfile();
	if (!f) {
		fprintf(stderr, "Could not open a temporary file: %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	}

	if (fwrite(data, 1, length, f) < length || fflush(f)) {
		fprintf(stderr, "Could not write the database: %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	}

	r = loc_database_new(ctx, &db, f);
	fclose(f);
	if (r)
		return -1;

	// Search for an AS
	r = loc_database_get_as(db, &as, 64496);
	if (r == 0 && as)
		loc_as_unref(as);

	// Search for a country
	r = loc_database_get_country(db, &country, "DE");
	if (r == 0 && country)
		loc_country_unref(country);

	// Look up everything we know
	for (const char** n = networks; *n; n++) {
		char address[INET6_ADDRSTRLEN];

		// Remove the prefix
		snprintf(address, sizeof(address), "%.*s", (int)strcspn(*n, "/"), *n);

		r = loc_database_lookup_from_string(db, address, &network);
		if (r == 0 && network)
			loc_network_unref(network);
	}

	// Read all strings
	loc_database_get_vendor(db);
	loc_database_get_description(db);
	loc_database_get_license(db);

	// Walk through all networks
	r = loc_database_enumerator_new(&enumerator, db, LOC_DB_ENUMERATE_NETWORKS, 0);
	if (r == 0) {
		while (1) {
			r = loc_database_enumerator_next_network(enumerator, &network);
			if (r || !network)
				break;

			loc_network_unref(network);
		}

		loc_database_enumerator_unref(enumerator);
	}

	loc_database_unref(db);

	return 0;
}

/*
	Breaks the database in all sorts of ways and tries to read it
*/
static int test_malformed(struct loc_ctx* ctx, FILE* f) {
	// Fields in the header that are being overwritten
	const struct malformed {
		const char* name;
		size_t offset;
		enum {
			SET,
			ADD,
		} op;
		uint32_t value;
	} tests[] = {
		{ "AS section past the end",       HEADER(as_offset),           SET, 0xfffffff0 },
		{ "AS section too long",           HEADER(as_length),           SET, 0x40000000 },
		{ "Networks past the end",         HEADER(network_data_offset), SET, 0xfffffff0 },
		{ "Networks too long",             HEADER(network_data_length), SET, 0x40000000 },
		{ "Tree past the end",             HEADER(network_tree_offset), SET, 0xfffffff0 },
		{ "Tree too long",                 HEADER(network_tree_length), SET, 0x40000000 },
		{ "Tree is empty",                 HEADER(network_tree_length), SET, 0 },
		{ "Countries past the end",        HEADER(countries_offset),    SET, 0xfffffff0 },
		{ "Countries too long",            HEADER(countries_length),    SET, 0x40000000 },
		{ "Pool past the end",             HEADER(pool_offset),         SET, 0xfffffff0 },
		{ "Pool too long",                 HEADER(pool_length),         SET, 0x40000000 },
		{ "Pool is not terminated",        HEADER(pool_length),         ADD, (uint32_t)-1 },
		{ NULL },
	};
	char* data = NULL;
	char* copy = NULL;
	int r = 1;

	// Read the entire database
	if (fseek(f, 0, SEEK_END))
		goto ERROR;

	const long length = ftell(f);
	if (length <= 0)
		goto ERROR;

	rewind(f);

	data = malloc(length);
	copy = malloc(length);
	if (!data || !copy)
		goto ERROR;

	if (fread(data, 1, length, f) < (size_t)length)
		goto ERROR;

	// The database must work if we don't break it
	if (use_database(ctx, data, length)) {
		fprintf(stderr, "Could not open the copy of the database\n");
		goto ERROR;
	}

	// These must all be refused
	for (const struct malformed* test = tests; test->name; test++) {
		memcpy(copy, data, length);

		switch (test->op) {
			case SET:
				write32(copy, test->offset, test->value);
				break;

			case ADD:
				write32(copy, test->offset, read32(copy, test->offset) + test->value);
				break;
		}

		if (use_database(ctx, copy, length) == 0) {
			fprintf(stderr, "Malformed database was opened: %s\n", test->name);
			goto ERROR;
		}
	}

	// Truncating the database anywhere must not make us read past its end
	for (long l = 0; l < length; l += 61) {
		if (use_database(ctx, data, l) == 0 && l < (long)HEADER(padding)) {
			fprintf(stderr, "Opened a database of only %ld byte(s)\n", l);
			goto ERROR;
		}
	}

	// Let the first node below the root point to itself
	memcpy(copy, data, length);

	const size_t tree = read32(copy, HEADER(network_tree_offset));

	uint32_t node = read32(copy, tree + offsetof(struct loc_database_network_node_v1, zero));
	if (!node)
		node = read32(copy, tree + offsetof(struct loc_database_network_node_v1, one));

	if (!node) {
		fprintf(stderr, "The tree is empty\n");
		goto ERROR;
	}

	const size_t offset = tree + node * sizeof(struct loc_database_network_node_v1);

	write32(copy, offset + offsetof(struct loc_database_network_node_v1, zero), node);
	write32(copy, offset + offsetof(struct loc_database_network_node_v1, one), node);

	// We can open this, but must not run in circles
	use_database(ctx, copy, length);

	// The networks are gone, but the tree still points to them
	memcpy(copy, data, length);
	write32(copy, HEADER(network_data_length), 0);

	use_database(ctx, copy, length);

	// Success
	r = 0;

ERROR:
	if (r)
		fprintf(stderr, "Reading malformed databases failed\n");

	free(data);
	free(copy);

	return r;
}

int main(int argc, char** argv) {
	int err;

	struct loc_ctx* ctx;
	err = loc_new(&ctx);
	if (err < 0)
		exit(EXIT_FAILURE);

	// Enable debug logging
	loc_set_log_priority(ctx, LOG_DEBUG);

	// Try opening an empty file
	err = attempt_to_open(ctx, "/dev/null");
	if (err == 0)
		exit(EXIT_FAILURE);

	// Try opening a file with all zeroes
	err = attempt_to_open(ctx, "/dev/zero");
	if (err == 0)
		exit(EXIT_FAILURE);

	// Try opening a file with random data
	err = attempt_to_open(ctx, "/dev/urandom");
	if (err == 0)
		exit(EXIT_FAILURE);

	// Create a database
	struct loc_writer* writer;
	err = loc_writer_new(ctx, &writer, NULL, NULL);
	if (err < 0)
		exit(EXIT_FAILURE);

	// Set the vendor
	err = loc_writer_set_vendor(writer, VENDOR);
	if (err) {
		fprintf(stderr, "Could not set vendor\n");
		exit(EXIT_FAILURE);
	}

	// Retrieve vendor
	const char* vendor = loc_writer_get_vendor(writer);
	if (vendor) {
		printf("Vendor is: %s\n", vendor);
	} else {
		fprintf(stderr, "Could not retrieve vendor\n");
		exit(EXIT_FAILURE);
	}

	// Set a description
	err = loc_writer_set_description(writer, DESCRIPTION);
	if (err) {
		fprintf(stderr, "Could not set description\n");
		exit(EXIT_FAILURE);
	}

	// Retrieve description
	const char* description = loc_writer_get_description(writer);
	if (description) {
		printf("Description is: %s\n", description);
	} else {
		fprintf(stderr, "Could not retrieve description\n");
		exit(EXIT_FAILURE);
	}

	// Set a license
	err = loc_writer_set_license(writer, LICENSE);
	if (err) {
		fprintf(stderr, "Could not set license\n");
		exit(EXIT_FAILURE);
	}

	// Retrieve license
	const char* license = loc_writer_get_license(writer);
	if (license) {
		printf("License is: %s\n", license);
	} else {
		fprintf(stderr, "Could not retrieve license\n");
		exit(EXIT_FAILURE);
	}

	struct loc_network* network = NULL;

	// Add some networks
	const char** n = networks;
	while (*n) {
		err = loc_writer_add_network(writer, &network, *n);
		if (err) {
			fprintf(stderr, "Could not add network %s\n", *n);
			exit(EXIT_FAILURE);
		}

		// Set a country
		loc_network_set_country_code(network, "DE");
		loc_network_unref(network);

		// Next one
		n++;
	}

	// Add some hosts
	for (n = hosts; *n; n++) {
		err = loc_writer_add_network(writer, &network, *n);
		if (err) {
			fprintf(stderr, "Could not add network %s\n", *n);
			exit(EXIT_FAILURE);
		}

		// Make them different from the networks they are in
		loc_network_set_asn(network, 64496);
		loc_network_unref(network);
	}

	FILE* f = tmpfile();
	if (!f) {
		fprintf(stderr, "Could not open file for writing: %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	}

	err = loc_writer_write(writer, f, LOC_DATABASE_VERSION_UNSET);
	if (err) {
		fprintf(stderr, "Could not write database: %s\n", strerror(-err));
		exit(EXIT_FAILURE);
	}
	loc_writer_unref(writer);

	// And open it again from disk
	struct loc_database* db;
	err = loc_database_new(ctx, &db, f);
	if (err) {
		fprintf(stderr, "Could not open database: %s\n", strerror(-err));
		exit(EXIT_FAILURE);
	}

	// Try reading something from the database
	vendor = loc_database_get_vendor(db);
	if (!vendor) {
		fprintf(stderr, "Could not retrieve vendor\n");
		exit(EXIT_FAILURE);
	} else if (strcmp(vendor, VENDOR) != 0) {
		fprintf(stderr, "Vendor doesn't match: %s != %s\n", vendor, VENDOR);
		exit(EXIT_FAILURE);
	}

	// Look up the hosts, and what is right next to them
	if (lookup(db, "2001:db8:ffff::1", "2001:db8:ffff::1/128")
			|| lookup(db, "2001:db8:ffff::2", "2001:db8::/32")
			|| lookup(db, "192.0.2.1", "192.0.2.1/32")
			|| lookup(db, "192.0.2.2", NULL))
		exit(EXIT_FAILURE);

	// Enumerator
	struct loc_database_enumerator* enumerator;
	err = loc_database_enumerator_new(&enumerator, db, LOC_DB_ENUMERATE_NETWORKS, 0);
	if (err) {
		fprintf(stderr, "Could not initialise the enumerator: %d\n", err);
		exit(EXIT_FAILURE);
	}

	// Walk through all networks
	while (1) {
		err = loc_database_enumerator_next_network(enumerator, &network);
		if (err) {
			fprintf(stderr, "Error fetching the next network: %d\n", err);
			exit(EXIT_FAILURE);
		}

		if (!network)
			break;

		const char* s = loc_network_str(network);
		printf("Got network: %s\n", s);

		loc_network_unref(network);
	}

	// Free the enumerator
	loc_database_enumerator_unref(enumerator);

	// Close the database
	loc_database_unref(db);

	// Break it
	if (test_malformed(ctx, f))
		exit(EXIT_FAILURE);

	loc_unref(ctx);
	fclose(f);

	return EXIT_SUCCESS;
}
