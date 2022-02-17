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

#include <libloc/libloc.h>
#include <libloc/country.h>
#include <libloc/database.h>
#include <libloc/network.h>
#include <libloc/writer.h>

int main(int argc, char** argv) {
	struct loc_country* country;
	int flag;
	int err;

	// Check some valid country codes
	if (!loc_country_code_is_valid("DE")) {
		fprintf(stderr, "Valid country code detected as invalid: %s\n", "DE");
		exit(EXIT_FAILURE);
	}

	// Check some invalid country codes
	if (loc_country_code_is_valid("X1")) {
		fprintf(stderr, "Invalid country code detected as valid: %s\n", "X1");
		exit(EXIT_FAILURE);
	}

	// Test special country codes
	flag = loc_country_special_code_to_flag("XX");
	if (flag) {
		fprintf(stderr, "Unexpectedly received a flag for XX: %d\n", flag);
		exit(EXIT_FAILURE);
	}

	// A1
	flag = loc_country_special_code_to_flag("A1");
	if (flag != LOC_NETWORK_FLAG_ANONYMOUS_PROXY) {
		fprintf(stderr, "Got a wrong flag for A1: %d\n", flag);
		exit(EXIT_FAILURE);
	}

	// A2
	flag = loc_country_special_code_to_flag("A2");
	if (flag != LOC_NETWORK_FLAG_SATELLITE_PROVIDER) {
		fprintf(stderr, "Got a wrong flag for A2: %d\n", flag);
		exit(EXIT_FAILURE);
	}

	// A3
	flag = loc_country_special_code_to_flag("A3");
	if (flag != LOC_NETWORK_FLAG_ANYCAST) {
		fprintf(stderr, "Got a wrong flag for A3: %d\n", flag);
		exit(EXIT_FAILURE);
	}

	// XD
	flag = loc_country_special_code_to_flag("XD");
	if (flag != LOC_NETWORK_FLAG_DROP) {
		fprintf(stderr, "Got a wrong flag for XD: %d\n", flag);
		exit(EXIT_FAILURE);
	}

	// NULL input
	flag = loc_country_special_code_to_flag(NULL);
	if (flag >= 0) {
		fprintf(stderr, "loc_country_special_code_to_flag didn't throw an error for NULL\n");
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
	err = loc_writer_add_country(writer, &country, "DE");
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
		fprintf(stderr, "Could not find country: YY\n");
		exit(EXIT_FAILURE);
	}
	loc_country_unref(country);

	struct loc_network* network = NULL;

	// Create a test network
	err = loc_network_new_from_string(ctx, &network, "2001:db8::/64");
	if (err) {
		fprintf(stderr, "Could not create network: %s\n", strerror(-err));
		exit(EXIT_FAILURE);
	}

	// Set country code & flag
	loc_network_set_country_code(network, "YY");
	loc_network_set_flag(network, LOC_NETWORK_FLAG_ANONYMOUS_PROXY);

	// Check if this network matches its own country code
	err = loc_network_matches_country_code(network, "YY");
	if (!err) {
		fprintf(stderr, "Network does not match its own country code\n");
		exit(EXIT_FAILURE);
	}

	// Check if this network matches the special country code
	err = loc_network_matches_country_code(network, "A1");
	if (!err) {
		fprintf(stderr, "Network does not match the special country code A1\n");
		exit(EXIT_FAILURE);
	}

	// Check if this network does not match another special country code
	err = loc_network_matches_country_code(network, "A2");
	if (err) {
		fprintf(stderr, "Network matches another special country code A2\n");
		exit(EXIT_FAILURE);
	}

	loc_network_unref(network);

	loc_database_unref(db);
	loc_unref(ctx);
	fclose(f);

	return EXIT_SUCCESS;
}
