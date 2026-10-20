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
#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>

#include <libloc/libloc.h>
#include <libloc/address.h>
#include <libloc/network.h>
#include <libloc/network-list.h>

#define MAX_NETWORKS 64

static int test_summarize(struct loc_ctx* ctx) {
	const struct summarize {
		const char* first;
		const char* last;
		const char* networks[MAX_NETWORKS];
	} tests[] = {
		// An entire network
		{ "10.0.0.0", "10.0.0.255", { "10.0.0.0/24", NULL } },

		// A single address
		{ "10.0.0.1", "10.0.0.1", { "10.0.0.1/32", NULL } },
		{ "2001:db8::1", "2001:db8::1", { "2001:db8::1/128", NULL } },

		// Ranges that neither start nor end where a network does
		{ "10.0.0.1", "10.0.0.6", {
			"10.0.0.1/32", "10.0.0.2/31", "10.0.0.4/31", "10.0.0.6/32", NULL,
		} },
		{ "10.0.1.0", "10.0.15.255", {
			"10.0.1.0/24", "10.0.2.0/23", "10.0.4.0/22", "10.0.8.0/21", NULL,
		} },

		// Everything around 10.0.0.0/8
		{ "0.0.0.0", "9.255.255.255", { "0.0.0.0/5", "8.0.0.0/7", NULL } },
		{ "11.0.0.0", "255.255.255.255", {
			"11.0.0.0/8", "12.0.0.0/6", "16.0.0.0/4", "32.0.0.0/3", "64.0.0.0/2",
			"128.0.0.0/1", NULL,
		} },

		// Everything
		{ "0.0.0.0", "255.255.255.255", { "0.0.0.0/0", NULL } },
		{ "::", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", { "::/0", NULL } },

		// IPv6
		{ "2001:db8::", "2001:db8:1:ffff:ffff:ffff:ffff:ffff", { "2001:db8::/47", NULL } },
		{ "2001:db8:0:ffff:ffff:ffff:ffff:ffff", "2001:db8:1::", {
			"2001:db8:0:ffff:ffff:ffff:ffff:ffff/128", "2001:db8:1::/128", NULL,
		} },

		{ NULL },
	};
	struct loc_network_list* list = NULL;
	struct in6_addr first;
	struct in6_addr last;
	int r;

	for (const struct summarize* test = tests; test->first; test++) {
		r = loc_address_parse(&first, NULL, test->first);
		if (r)
			return r;

		r = loc_address_parse(&last, NULL, test->last);
		if (r)
			return r;

		r = loc_network_list_new(ctx, &list);
		if (r)
			return r;

		r = loc_network_list_summarize(ctx, &first, &last, &list);
		if (r) {
			fprintf(stderr, "Could not summarize %s - %s: %d\n", test->first, test->last, r);
			goto ERROR;
		}

		// Count how many networks we expect
		size_t expected = 0;
		while (test->networks[expected])
			expected++;

		if (loc_network_list_size(list) != expected) {
			fprintf(stderr, "Summarizing %s - %s returned %zu network(s), expected %zu\n",
				test->first, test->last, loc_network_list_size(list), expected);
			loc_network_list_dump(list);
			r = 1;
			goto ERROR;
		}

		// The list is sorted, and so is what we expect
		for (size_t i = 0; i < expected; i++) {
			struct loc_network* network = loc_network_list_get(list, i);

			r = strcmp(loc_network_str(network), test->networks[i]);
			if (r) {
				fprintf(stderr, "Summarizing %s - %s returned %s, expected %s\n",
					test->first, test->last, loc_network_str(network), test->networks[i]);
				r = 1;
			}

			loc_network_unref(network);

			if (r)
				goto ERROR;
		}

		loc_network_list_unref(list);
		list = NULL;
	}

	// The range must not be backwards
	r = loc_address_parse(&first, NULL, "10.0.0.2");
	if (r)
		return r;

	r = loc_address_parse(&last, NULL, "10.0.0.1");
	if (r)
		return r;

	r = loc_network_list_new(ctx, &list);
	if (r)
		return r;

	r = loc_network_list_summarize(ctx, &first, &last, &list);
	if (r == 0) {
		fprintf(stderr, "Summarized a range that ends before it starts\n");
		r = 1;
		goto ERROR;
	}

	r = 0;

ERROR:
	if (list)
		loc_network_list_unref(list);

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

	// Create a network
	struct loc_network* network1;
	err = loc_network_new_from_string(ctx, &network1, "2001:db8::/32");
	if (err) {
		fprintf(stderr, "Could not create the network1\n");
		exit(EXIT_FAILURE);
	}

	struct loc_network* subnet1;
	err = loc_network_new_from_string(ctx, &subnet1, "2001:db8:a::/48");
	if (err) {
		fprintf(stderr, "Could not create the subnet1\n");
		exit(EXIT_FAILURE);
	}

	struct loc_network* subnet2;
	err = loc_network_new_from_string(ctx, &subnet2, "2001:db8:b::/48");
	if (err) {
		fprintf(stderr, "Could not create the subnet2\n");
		exit(EXIT_FAILURE);
	}

	struct loc_network* subnet3;
	err = loc_network_new_from_string(ctx, &subnet3, "2001:db8:c::/48");
	if (err) {
		fprintf(stderr, "Could not create the subnet3\n");
		exit(EXIT_FAILURE);
	}

	struct loc_network* subnet4;
	err = loc_network_new_from_string(ctx, &subnet4, "2001:db8:d::/48");
	if (err) {
		fprintf(stderr, "Could not create the subnet4\n");
		exit(EXIT_FAILURE);
	}

	struct loc_network* subnet5;
	err = loc_network_new_from_string(ctx, &subnet5, "2001:db8:e::/48");
	if (err) {
		fprintf(stderr, "Could not create the subnet5\n");
		exit(EXIT_FAILURE);
	}

	struct loc_network* subnet6;
	err = loc_network_new_from_string(ctx, &subnet6, "2001:db8:1::/48");
	if (err) {
		fprintf(stderr, "Could not create the subnet6\n");
		exit(EXIT_FAILURE);
	}

	// Make a list with both subnets
	struct loc_network_list* subnets;
	err = loc_network_list_new(ctx, &subnets);
	if (err) {
		fprintf(stderr, "Could not create subnets list\n");
		exit(EXIT_FAILURE);
	}

	size_t size = loc_network_list_size(subnets);
	if (size > 0) {
		fprintf(stderr, "The list is not empty: %zu\n", size);
		exit(EXIT_FAILURE);
	}

	err = loc_network_list_push(subnets, subnet1);
	if (err) {
		fprintf(stderr, "Could not add subnet1 to subnets list\n");
		exit(EXIT_FAILURE);
	}

	if (loc_network_list_empty(subnets)) {
		fprintf(stderr, "The subnets list reports that it is empty\n");
		exit(EXIT_FAILURE);
	}

	err = loc_network_list_push(subnets, subnet2);
	if (err) {
		fprintf(stderr, "Could not add subnet2 to subnets list\n");
		exit(EXIT_FAILURE);
	}

	// Add the fourth one next
	err = loc_network_list_push(subnets, subnet4);
	if (err) {
		fprintf(stderr, "Could not add subnet4 to subnets list\n");
		exit(EXIT_FAILURE);
	}

	// Add the third one
	err = loc_network_list_push(subnets, subnet3);
	if (err) {
		fprintf(stderr, "Could not add subnet3 to subnets list\n");
		exit(EXIT_FAILURE);
	}

	// Add more subnets
	err = loc_network_list_push(subnets, subnet5);
	if (err) {
		fprintf(stderr, "Could not add subnet5 to subnets list\n");
		exit(EXIT_FAILURE);
	}

	err = loc_network_list_push(subnets, subnet6);
	if (err) {
		fprintf(stderr, "Could not add subnet6 to subnets list\n");
		exit(EXIT_FAILURE);
	}

	loc_network_list_dump(subnets);

	size = loc_network_list_size(subnets);
	if (size != 6) {
		fprintf(stderr, "Network list is reporting an incorrect size: %zu\n", size);
		exit(EXIT_FAILURE);
	}

	// Exclude subnet1 from network1
	struct loc_network_list* excluded = loc_network_exclude(network1, subnet1);
	if (!excluded) {
		fprintf(stderr, "Received an empty result from loc_network_exclude() for subnet1\n");
		exit(EXIT_FAILURE);
	}

	loc_network_list_dump(excluded);
	loc_network_list_unref(excluded);

	// Exclude all subnets from network1
	excluded = loc_network_exclude_list(network1, subnets);
	if (!excluded) {
		fprintf(stderr, "Received an empty result from loc_network_exclude() for subnets\n");
		exit(EXIT_FAILURE);
	}

	loc_network_list_dump(excluded);

	if (excluded)
		loc_network_list_unref(excluded);

	loc_network_list_unref(subnets);
	loc_network_unref(network1);
	loc_network_unref(subnet1);
	loc_network_unref(subnet2);
	loc_network_unref(subnet3);
	loc_network_unref(subnet4);
	loc_network_unref(subnet5);
	loc_network_unref(subnet6);

	// Summarize some ranges
	err = test_summarize(ctx);
	if (err)
		exit(EXIT_FAILURE);

	loc_unref(ctx);

	return EXIT_SUCCESS;
}
