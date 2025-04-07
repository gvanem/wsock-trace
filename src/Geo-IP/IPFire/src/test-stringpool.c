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
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <ctype.h>
#include <errno.h>
#include <unistd.h>
#include <time.h>
#include <syslog.h>

#include <libloc/libloc.h>
#include <libloc/stringpool.h>

static const char* characters = "012345789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

static char* random_string(size_t size) {
	char* string = malloc(size + 1);

	char* p = string;
	for (unsigned int i = 0; i < size; i++) {
		*p++ = characters[rand() % strlen(characters)];
	}
	*p = '\0';

	return string;
}

int main(int argc, char** argv) {
	// Initialize the RNG
	time_t now = time(NULL);
	srand(now);

	int err;

	struct loc_ctx* ctx;
	err = loc_new(&ctx);
	if (err < 0)
		exit(EXIT_FAILURE);

	// Enable debug logging
	loc_set_log_priority(ctx, LOG_DEBUG);

	// Create the stringpool
	struct loc_stringpool* pool;
	err = loc_stringpool_new(ctx, &pool);
	if (err < 0)
		exit(EXIT_FAILURE);

	// Try reading some invalid string
	const char* s = loc_stringpool_get(pool, 100);
	if (s != NULL) {
		fprintf(stderr, "An unexpected string was returned: %s\n", s);
		exit(EXIT_FAILURE);
	}

	// Append a string
	off_t pos = loc_stringpool_add(pool, "ABC");
	if (pos < 0) {
		fprintf(stderr, "Could not add string: %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	}

	printf("Added string at %jd\n", (intmax_t)pos);

	// Must start at first byte
	if (pos != 0) {
		fprintf(stderr, "First string didn't start at the first byte\n");
		exit(EXIT_FAILURE);
	}

	// Append the same string again
	pos = loc_stringpool_add(pool, "ABC");
	if (pos != 0) {
		fprintf(stderr, "Same string was added at a different position again\n");
		exit(EXIT_FAILURE);
	}

	// Append another string
	pos = loc_stringpool_add(pool, "DEF");
	if (pos == 0) {
		fprintf(stderr, "Second string was added at the first address\n");
		exit(EXIT_FAILURE);
	}

	// Add 10000 random strings
	for (unsigned int i = 0; i < 10000; i++) {
		char* string = random_string(3);

		pos = loc_stringpool_add(pool, string);
		free(string);

		if (pos < 0) {
			fprintf(stderr, "Could not add string %u: %s\n", i, strerror(errno));
			exit(EXIT_FAILURE);
		}
	}

	// Dump pool
	loc_stringpool_dump(pool);

	loc_stringpool_unref(pool);
	loc_unref(ctx);

	return EXIT_SUCCESS;
}
