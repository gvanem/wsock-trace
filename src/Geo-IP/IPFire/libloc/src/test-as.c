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

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>

#include <loc/libloc.h>
#include <loc/database.h>
#include <loc/writer.h>

#define TEST_AS_COUNT 5000

int main(int argc, char** argv) {
	int err;

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

	char name[256];
	for (unsigned int i = 1; i <= TEST_AS_COUNT; i++) {
		struct loc_as* as;
		loc_writer_add_as(writer, &as, i);

		sprintf(name, "Test AS%u", i);
		loc_as_set_name(as, name);

		loc_as_unref(as);
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

	size_t as_count = loc_database_count_as(db);
	if (as_count != TEST_AS_COUNT) {
		fprintf(stderr, "Could not read all ASes\n");
		exit(EXIT_FAILURE);
	}

	struct loc_as* as;
	for (unsigned int i = 1; i <= 10; i++) {
		err = loc_database_get_as(db, &as, i);
		if (err) {
			fprintf(stderr, "Could not find AS%d\n", i);
			exit(EXIT_FAILURE);
		}

		loc_as_unref(as);
	}

	// Enumerator

	struct loc_database_enumerator* enumerator;
	err = loc_database_enumerator_new(&enumerator, db, LOC_DB_ENUMERATE_ASES);
	if (err) {
		fprintf(stderr, "Could not create a database enumerator\n");
		exit(EXIT_FAILURE);
	}

	loc_database_enumerator_set_string(enumerator, "10");

	err = loc_database_enumerator_next_as(enumerator, &as);
	if (err) {
		fprintf(stderr, "Could not enumerate next AS\n");
		exit(EXIT_FAILURE);
	}

	while (as) {
		printf("Found AS%d: %s\n", loc_as_get_number(as), loc_as_get_name(as));

		err = loc_database_enumerator_next_as(enumerator, &as);
		if (err) {
			fprintf(stderr, "Could not enumerate next AS\n");
			exit(EXIT_FAILURE);
		}
	}

	loc_database_enumerator_unref(enumerator);
	loc_database_unref(db);
	loc_unref(ctx);
	fclose(f);

	return EXIT_SUCCESS;
}
