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
	char buffer[LOC_ADDRESS_STRING_LENGTH];
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
		s = loc_address_format(&address, buffer, sizeof(buffer));

		printf("Iteration %u: %s\n", i, s);

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

	s = loc_address_format(&address, buffer, sizeof(buffer));

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

	s = loc_address_format(&address, buffer, sizeof(buffer));

	printf("Incremented IP address to %s\n", s);

	if (!loc_address_all_zeroes(&address)) {
		printf("IP address hasn't been decremented correctly: %s\n",
			loc_address_format(&address, buffer, sizeof(buffer)));
		return 1;
	}

	return 0;
}

static int test_parse(void) {
	const struct parse {
		const char* string;
		const char* address;
		unsigned int prefix;
	} tests[] = {
		// Valid
		{ "::", "::", 128 },
		{ "::/0", "::", 0 },
		{ "2001:db8::/32", "2001:db8::", 32 },
		{ "2001:db8::1/128", "2001:db8::1", 128 },
		{ "10.0.0.0/8", "10.0.0.0", 8 },
		{ "192.0.2.1", "192.0.2.1", 32 },
		{ "192.0.2.1/32", "192.0.2.1", 32 },
		{ "0.0.0.0/0", "0.0.0.0", 0 },
		{ "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128",
			"ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", 128 },

		// IPv4 addresses in IPv6 notation are IPv4 addresses
		{ "::ffff:192.0.2.1", "192.0.2.1", 32 },
		{ "::ffff:192.0.2.0/24", "192.0.2.0", 24 },

		// The longest possible input
		{ "0000:0000:0000:0000:0000:ffff:255.255.255.255/32", "255.255.255.255", 32 },

		// Invalid
		{ "", NULL, 0 },
		{ "/24", NULL, 0 },
		{ "example.org", NULL, 0 },
		{ "192.0.2.1/", NULL, 0 },
		{ "192.0.2.1/abc", NULL, 0 },
		{ "192.0.2.1/24x", NULL, 0 },
		{ "192.0.2.1/-1", NULL, 0 },
		{ "192.0.2.1/+24", NULL, 0 },
		{ "192.0.2.1/ 24", NULL, 0 },
		{ "192.0.2.1/33", NULL, 0 },
		{ "192.0.2.1/4294967320", NULL, 0 },
		{ "192.0.2.256", NULL, 0 },
		{ "2001:db8::/129", NULL, 0 },
		{ "2001:db8::/32/48", NULL, 0 },
		{ "::ffff:192.0.2.1/128", NULL, 0 },
		{ "0000:0000:0000:0000:0000:ffff:255.255.255.255/128", NULL, 0 },
		{ "0000:0000:0000:0000:0000:0000:0000:0000:0000:0000:0000/64", NULL, 0 },
		{ "0000:0000:0000:0000:0000:ffff:255.255.255.255/0032", NULL, 0 },
		{ "192.0.2.1:80", NULL, 0 },

		{ NULL },
	};
	char buffer[LOC_ADDRESS_STRING_LENGTH];
	struct in6_addr address;
	unsigned int prefix;
	int r;

	for (const struct parse* test = tests; test->string; test++) {
		r = loc_address_parse(&address, &prefix, test->string);

		// Invalid input must fail
		if (!test->address) {
			if (r == 0) {
				fprintf(stderr, "'%s' was parsed as %s/%u\n",
					test->string, loc_address_format(&address, buffer, sizeof(buffer)), prefix);
				return 1;
			}

			continue;
		}

		if (r) {
			fprintf(stderr, "Could not parse '%s'\n", test->string);
			return 1;
		}

		const char* s = loc_address_format(&address, buffer, sizeof(buffer));

		if (strcmp(s, test->address) != 0 || prefix != test->prefix) {
			fprintf(stderr, "'%s' was parsed as %s/%u instead of %s/%u\n",
				test->string, s, prefix, test->address, test->prefix);
			return 1;
		}
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

	// Parse some addresses
	r = test_parse();
	if (r)
		goto ERROR;

ERROR:
	loc_unref(ctx);

	return r;
}
