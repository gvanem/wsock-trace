/*
	libloc - A library to determine the location of someone on the Internet

	Copyright (C) 2022 IPFire Development Team <info@ipfire.org>

	This program is free software; you can redistribute it and/or modify
	it under the terms of the GNU General Public License as published by
	the Free Software Foundation; either version 2 of the License, or
	(at your option) any later version.

	This program is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.
*/

#include <stdlib.h>
#include <string.h>
#include <syslog.h>

#include <libloc/libloc.h>
#include <libloc/address.h>
#include <libloc/private.h>

static int perform_tests(struct loc_ctx* ctx, const int family) {
	struct in6_addr address = IN6ADDR_ANY_INIT;
	const char* e = NULL;
	const char* s = NULL;

	// Reset IP address
	loc_address_reset(&address, family);

	if (!loc_address_all_zeroes(&address)) {
		fprintf(stderr, "IP address isn't all zeroes\n");
		return 1;
	}

	if (loc_address_all_ones(&address)) {
		fprintf(stderr, "IP address isn't all ones\n");
		return 1;
	}

	switch (family) {
		case AF_INET6:
			e = "::";
			break;

		case AF_INET:
			e = "0.0.0.0";
			break;
	}

	// Convert this to a string a few times
	for (unsigned int i = 0; i < 100; i++) {
		s = loc_address_str(&address);

		printf("Iteration %d: %s\n", i, s);

		if (strcmp(s, e) != 0) {
			fprintf(stderr, "IP address was formatted in an invalid format: %s\n", s);
			return 1;
		}
	}

	// Increment the IP address
	loc_address_increment(&address);

	switch (family) {
		case AF_INET6:
			e = "::1";
			break;

		case AF_INET:
			e = "0.0.0.1";
			break;
	}

	s = loc_address_str(&address);

	printf("Incremented IP address to %s\n", s);

	if (strcmp(s, e) != 0) {
		printf("IP address has been incremented incorrectly: %s\n", s);
		return 1;
	}

	if (loc_address_all_zeroes(&address)) {
		printf("IP address shouldn't be all zeroes any more\n");
		return 1;
	}

	if (loc_address_all_ones(&address)) {
		printf("IP address shouldn't be all ones any more\n");
		return 1;
	}

	// Decrement the IP address
	loc_address_decrement(&address);

	s = loc_address_str(&address);

	printf("Incremented IP address to %s\n", s);

	if (!loc_address_all_zeroes(&address)) {
		printf("IP address hasn't been decremented correctly: %s\n",
			loc_address_str(&address));
		return 1;
	}

	return 0;
}

int main(int argc, char** argv) {
	struct loc_ctx* ctx = NULL;
	int r = EXIT_FAILURE;

	int err = loc_new(&ctx);
	if (err < 0)
		exit(r);

	// Enable debug logging
	loc_set_log_priority(ctx, LOG_DEBUG);

	// Perform all tests for IPv6
	r = perform_tests(ctx, AF_INET6);
	if (r)
		goto ERROR;

	// Perform all tests for IPv4
	r = perform_tests(ctx, AF_INET);
	if (r)
		goto ERROR;

ERROR:
	loc_unref(ctx);

	return r;
}
