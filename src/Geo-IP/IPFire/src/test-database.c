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

#include <libloc/libloc.h>
#include <libloc/database.h>
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

static int attempt_to_open(struct loc_ctx* ctx, char* path) {
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
		loc_network_set_country_code(network, "XX");

		// Next one
		n++;
	}

	FILE* f = tmpfile();
	if (!f) {
		fprintf(stderr, "Could not open file for writing: %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	}

	err = loc_writer_write(writer, f, LOC_DATABASE_VERSION_UNSET);
	if (err) {
		fprintf(stderr, "Could not write database: %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	}
	loc_writer_unref(writer);

	// And open it again from disk
	struct loc_database* db;
	err = loc_database_new(ctx, &db, f);
	if (err) {
		fprintf(stderr, "Could not open database: %s\n", strerror(errno));
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
	}

	// Free the enumerator
	loc_database_enumerator_unref(enumerator);

	// Close the database
	loc_database_unref(db);
	loc_unref(ctx);
	fclose(f);

	return EXIT_SUCCESS;
}
