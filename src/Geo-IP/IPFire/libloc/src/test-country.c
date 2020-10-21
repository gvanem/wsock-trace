/*
	libloc - A library to determine the location of someone on the Internet

	Copyright (C) 2019 IPFire Development Team <info@ipfire.org>

	This program is free software; you can redistribute it and/or modify
	it under the terms of the GNU General Public License as published by
	the Free Software Foundation; either version 2 of the License, or
	(at your option) any later version.

	This program is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.
*/

#include <errno.h>
#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>

#include <loc/libloc.h>
#include <loc/country.h>
#include <loc/database.h>
#include <loc/network.h>
#include <loc/writer.h>

int main(int argc, char** argv) {
	struct loc_country* country;
	int err;

	// Check some valid country codes
	if (!loc_country_code_is_valid("XX")) {
		fprintf(stderr, "Valid country code detected as invalid: %s\n", "XX");
		exit(EXIT_FAILURE);
	}

	// Check some invalid country codes
	if (loc_country_code_is_valid("X1")) {
		fprintf(stderr, "Invalid country code detected as valid: %s\n", "X1");
		exit(EXIT_FAILURE);
	}

	struct loc_ctx* ctx;
	err = loc_new(&ctx);
	if (err < 0)
		exit(EXIT_FAILURE);

	// Enable debug logging
	loc_set_log_priority(ctx, LOG_DEBUG);

	// Create a database
	struct loc_writer* writer;
	err = loc_writer_new(ctx, &writer, NULL, NULL);
	if (err < 0)
		exit(EXIT_FAILURE);

	// Create a country
	err = loc_writer_add_country(writer, &country, "XX");
	if (err) {
		fprintf(stderr, "Could not create country\n");
		exit(EXIT_FAILURE);
	}

	// Set name & continent
	loc_country_set_name(country, "Testistan");
	loc_country_set_continent_code(country, "YY");

	// Free country
	loc_country_unref(country);

	// Add another country
	err = loc_writer_add_country(writer, &country, "YY");
	if (err) {
		fprintf(stderr, "Could not create country: YY\n");
		exit(EXIT_FAILURE);
	}
	loc_country_unref(country);

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

	// Lookup an address in the subnet
	err = loc_database_get_country(db, &country, "YY");
	if (err) {
		fprintf(stderr, "Could not find country: YY (country: 0x%p)\n", country);
		loc_database_unref(db);
		loc_unref(ctx);
		exit(EXIT_FAILURE);
	}
	loc_country_unref(country);

	loc_database_unref(db);
	loc_unref(ctx);
	fclose(f);

	return EXIT_SUCCESS;
}
