/*
	libloc - A library to determine the location of someone on the Internet

	Copyright (C) 2026 IPFire Development Team <info@ipfire.org>

	This library is free software; you can redistribute it and/or
	modify it under the terms of the GNU Lesser General Public
	License as published by the Free Software Foundation; either
	version 2.1 of the License, or (at your option) any later version.

	This library is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
	Lesser General Public License for more details.
*/

#include <libloc/libloc.h>
#include <libloc/address.h>
#include <libloc/network.h>
#include <libloc/network-list.h>

#include "fuzz.h"

/*
	Parses whatever we are being given as an IP address or a network, and
	everything that we can do with a network after it has been parsed.
*/

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
	struct loc_network_list* list = NULL;
	struct loc_network* network = NULL;
	struct loc_network* subnet1 = NULL;
	struct loc_network* subnet2 = NULL;
	struct in6_addr address;
	char buffer[LOC_ADDRESS_STRING_LENGTH];
	unsigned int prefix = 0;
	char* string = NULL;
	char* rp = NULL;
	int r;

	// The parser wants a string
	string = strndup((const char*)data, size);
	if (!string)
		goto ERROR;

	// Parse the address
	r = loc_address_parse(&address, &prefix, string);
	if (r)
		goto ERROR;

	// The prefix must fit the address
	if (!loc_address_valid_prefix(&address, prefix))
		abort();

	// Format it again
	if (!loc_address_format(&address, buffer, sizeof(buffer)))
		abort();

	// Everything that we were able to parse must be a network
	r = loc_network_new_from_string(fuzz_ctx, &network, string);
	if (r)
		abort();

	if (!loc_network_str(network))
		abort();

	// Not all networks have a reverse pointer
	rp = loc_network_reverse_pointer(network, NULL);

	// Split the network in half, which only works if it has more than one address
	r = loc_network_subnets(network, &subnet1, &subnet2);
	if (r)
		goto ERROR;

	// Both halves have to be in the network
	if (!loc_network_is_subnet(network, subnet1) || !loc_network_is_subnet(network, subnet2))
		abort();

	// Removing one half from the network leaves us with the other one
	list = loc_network_exclude(network, subnet1);
	if (!list)
		goto ERROR;

	if (loc_network_list_size(list) != 1 || !loc_network_list_contains(list, subnet2))
		abort();

ERROR:
	if (list)
		loc_network_list_unref(list);
	if (subnet1)
		loc_network_unref(subnet1);
	if (subnet2)
		loc_network_unref(subnet2);
	if (network)
		loc_network_unref(network);
	if (string)
		free(string);
	if (rp)
		free(rp);

	return 0;
}
