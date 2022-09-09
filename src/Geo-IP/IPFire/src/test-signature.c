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

#ifndef ABS_SRCDIR
#define ABS_SRCDIR ".."
#endif

int main(int argc, char** argv) {
	int err;

	// Open public key
	FILE* public_key = fopen(ABS_SRCDIR "/examples/public-key.pem", "r");
	if (!public_key) {
		fprintf(stderr, "Could not open public key file: %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	}

	// Open private key
	FILE* private_key1 = fopen(ABS_SRCDIR "/examples/private-key.pem", "r");
	if (!private_key1) {
		fprintf(stderr, "Could not open private key file: %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	}

	FILE* private_key2 = fopen(ABS_SRCDIR "/examples/private-key.pem", "r");
	if (!private_key2) {
		fprintf(stderr, "Could not open private key file: %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	}

	struct loc_ctx* ctx;
	err = loc_new(&ctx);
	if (err < 0)
		exit(EXIT_FAILURE);

	// Enable debug logging
	loc_set_log_priority(ctx, LOG_DEBUG);

	// Create an empty database
	struct loc_writer* writer;
	err = loc_writer_new(ctx, &writer, private_key1, private_key2);
	if (err < 0)
		exit(EXIT_FAILURE);

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

	// Verify the database signature
	err = loc_database_verify(db, public_key);
	if (err) {
		fprintf(stderr, "Could not verify the database: %d\n", err);
		exit(EXIT_FAILURE);
	}

	// Open another public key
	public_key = freopen(ABS_SRCDIR "/src/signing-key.pem", "r", public_key);
	if (!public_key) {
		fprintf(stderr, "Could not open public key file: %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	}

	// Verify with an incorrect key
	err = loc_database_verify(db, public_key);
	if (err == 0) {
		fprintf(stderr, "Database was verified with an incorrect key: %d\n", err);
		exit(EXIT_FAILURE);
	}

	// Close the database
	loc_database_unref(db);
	loc_unref(ctx);
	fclose(f);

	fclose(private_key1);
	fclose(private_key2);
	fclose(public_key);

	return EXIT_SUCCESS;
}
