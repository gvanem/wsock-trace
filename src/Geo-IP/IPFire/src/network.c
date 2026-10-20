/*
	libloc - A library to determine the location of someone on the Internet

	Copyright (C) 2017 IPFire Development Team <info@ipfire.org>

	This library is free software; you can redistribute it and/or
	modify it under the terms of the GNU Lesser General Public
	License as published by the Free Software Foundation; either
	version 2.1 of the License, or (at your option) any later version.

	This library is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
	Lesser General Public License for more details.
*/

#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef HAVE_ENDIAN_H
#  include <endian.h>
#endif

#include <libloc/libloc.h>
#include <libloc/address.h>
#include <libloc/compat.h>
#include <libloc/country.h>
#include <libloc/network.h>
#include <libloc/network-list.h>
#include <libloc/private.h>

struct loc_network {
	struct loc_ctx* ctx;
	loc_refcount_t refcount;

	int family;
	struct in6_addr first_address;
	struct in6_addr last_address;
	unsigned int prefix;

	char country_code[3];
	uint32_t asn;
	enum loc_network_flags flags;

	char string[INET6_ADDRSTRLEN + 4];

	// The first and last address as strings (only if somebody asked for them)
	char* first_address_string;
	char* last_address_string;
};

LOC_EXPORT int loc_network_new(struct loc_ctx* ctx, struct loc_network** network,
		struct in6_addr* address, unsigned int prefix) {
	char buffer[LOC_ADDRESS_STRING_LENGTH];
	struct loc_network* n = NULL;

	// Validate the prefix
	if (!loc_address_valid_prefix(address, prefix)) {
		ERROR(ctx, "Invalid prefix in %s: %u\n",
			loc_address_format(address, buffer, sizeof(buffer)), prefix);
		return -EINVAL;
	}

	// Allocate a new network
	n = calloc(1, sizeof(*n));
	if (!n)
		return -ENOMEM;

	n->ctx = loc_ref(ctx);
	n->refcount = 1;

	// Store the prefix
	if (IN6_IS_ADDR_V4MAPPED(address))
		n->prefix = prefix + 96;
	else
		n->prefix = prefix;

	// Convert the prefix into a bitmask
	const struct in6_addr bitmask = loc_prefix_to_bitmask(n->prefix);

	// Store the first and last address in the network
	n->first_address = loc_address_and(address, &bitmask);
	n->last_address  = loc_address_or(&n->first_address, &bitmask);

	// Set family
	n->family = loc_address_family(&n->first_address);

	DEBUG(n->ctx, "Network allocated at %p\n", n);
	*network = n;
	return 0;
}

LOC_EXPORT int loc_network_new_from_string(struct loc_ctx* ctx,
		struct loc_network** network, const char* string) {
	struct in6_addr address;
	unsigned int prefix;

	// Parse the input
	int r = loc_address_parse(&address, &prefix, string);
	if (r) {
		ERROR(ctx, "Could not parse network %s: %s\n", string, strerror(-r));
		return r;
	}

	// Create a new network
	return loc_network_new(ctx, network, &address, prefix);
}

LOC_EXPORT struct loc_network* loc_network_ref(struct loc_network* network) {
	loc_refcount_inc(&network->refcount);

	return network;
}

static void loc_network_free(struct loc_network* network) {
	DEBUG(network->ctx, "Releasing network at %p\n", network);

	if (network->first_address_string)
		free(network->first_address_string);
	if (network->last_address_string)
		free(network->last_address_string);

	loc_unref(network->ctx);
	free(network);
}

LOC_EXPORT struct loc_network* loc_network_unref(struct loc_network* network) {
	if (loc_refcount_dec(&network->refcount) > 0)
		return network;

	loc_network_free(network);
	return NULL;
}

/*
	Formats an address and stores the string with the network, so that it is
	valid for as long as the network is and nobody has to free it.
*/
static const char* loc_network_format_address(struct loc_network* network,
		char** string, const struct in6_addr* address) {
	char buffer[LOC_ADDRESS_STRING_LENGTH];

	// We only have to do this once
	if (!*string) {
		if (!loc_address_format(address, buffer, sizeof(buffer)))
			return NULL;

		*string = strdup(buffer);
	}

	return *string;
}

LOC_EXPORT const char* loc_network_str(struct loc_network* network) {
	char buffer[LOC_ADDRESS_STRING_LENGTH];

	if (!*network->string) {
		// Format the address
		const char* address = loc_address_format(&network->first_address, buffer, sizeof(buffer));
		if (!address)
			return NULL;

		// Fetch the prefix
		unsigned int prefix = loc_network_prefix(network);

		// Format the string
		int r = snprintf(network->string, sizeof(network->string) - 1,
			"%s/%u", address, prefix);
		if (r < 0) {
			ERROR(network->ctx, "Could not format network string: %s\n", LIBLOC_NETERR());
			*network->string = '\0';
			return NULL;
		}
	}

	return network->string;
}

LOC_EXPORT int loc_network_address_family(struct loc_network* network) {
	return network->family;
}

LOC_EXPORT unsigned int loc_network_prefix(struct loc_network* network) {
	switch (network->family) {
		case AF_INET6:
			return network->prefix;

		case AF_INET:
			return network->prefix - 96;
	}

	return 0;
}

unsigned int loc_network_raw_prefix(struct loc_network* network) {
	return network->prefix;
}

LOC_EXPORT const struct in6_addr* loc_network_get_first_address(struct loc_network* network) {
	return &network->first_address;
}

LOC_EXPORT const char* loc_network_format_first_address(struct loc_network* network) {
	return loc_network_format_address(network,
		&network->first_address_string, &network->first_address);
}

LOC_EXPORT const struct in6_addr* loc_network_get_last_address(struct loc_network* network) {
	return &network->last_address;
}

LOC_EXPORT const char* loc_network_format_last_address(struct loc_network* network) {
	return loc_network_format_address(network,
		&network->last_address_string, &network->last_address);
}

LOC_EXPORT int loc_network_matches_address(struct loc_network* network, const struct in6_addr* address) {
	// Address must be larger than the start address
	if (loc_address_cmp(&network->first_address, address) > 0)
		return 0;

	// Address must be smaller than the last address
	if (loc_address_cmp(&network->last_address, address) < 0)
		return 0;

	// The address is inside this network
	return 1;
}

LOC_EXPORT const char* loc_network_get_country_code(struct loc_network* network) {
	return network->country_code;
}

LOC_EXPORT int loc_network_set_country_code(struct loc_network* network, const char* country_code) {
	// Set empty country code
	if (!country_code || !*country_code) {
		*network->country_code = '\0';
		return 0;
	}

	// Check country code
	if (!loc_country_code_is_valid(country_code))
		return -EINVAL;

	loc_country_code_copy(network->country_code, country_code);

	return 0;
}

LOC_EXPORT int loc_network_matches_country_code(struct loc_network* network, const char* country_code) {
	// Search for any special flags
	const int flag = loc_country_special_code_to_flag(country_code);
	if (flag < 0)
		return flag;

	// If we found a flag, we will return whether it is set or not
	if (flag)
		return !!loc_network_has_flag(network, flag);

	// Check country code
	if (!loc_country_code_is_valid(country_code))
		return -EINVAL;

	// Check for an exact match
	return (network->country_code[0] == country_code[0])
		&& (network->country_code[1] == country_code[1]);
}

LOC_EXPORT uint32_t loc_network_get_asn(struct loc_network* network) {
	return network->asn;
}

LOC_EXPORT int loc_network_set_asn(struct loc_network* network, uint32_t asn) {
	network->asn = asn;

	return 0;
}

LOC_EXPORT int loc_network_has_flag(struct loc_network* network, uint32_t flag) {
	return network->flags & flag;
}

LOC_EXPORT int loc_network_set_flag(struct loc_network* network, uint32_t flag) {
	network->flags |= flag;

	return 0;
}

LOC_EXPORT int loc_network_cmp(struct loc_network* self, struct loc_network* other) {
	// Compare address
	int r = loc_address_cmp(&self->first_address, &other->first_address);
	if (r)
		return r;

	// Compare prefix
	if (self->prefix > other->prefix)
		return 1;
	else if (self->prefix < other->prefix)
		return -1;

	// Both networks are equal
	return 0;
}

int loc_network_properties_cmp(struct loc_network* self, struct loc_network* other) {
	int r;

	// Check country code
	r = loc_country_code_cmp(self->country_code, other->country_code);
	if (r)
		return r;

	// Check ASN
	if (self->asn > other->asn)
		return 1;
	else if (self->asn < other->asn)
		return -1;

	// Check flags
	if (self->flags > other->flags)
		return 1;
	else if (self->flags < other->flags)
		return -1;

	return 0;
}

LOC_EXPORT int loc_network_overlaps(struct loc_network* self, struct loc_network* other) {
	// Either of the start addresses must be in the other subnet
	if (loc_network_matches_address(self, &other->first_address))
		return 1;

	if (loc_network_matches_address(other, &self->first_address))
		return 1;

	// Or either of the end addresses is in the other subnet
	if (loc_network_matches_address(self, &other->last_address))
		return 1;

	if (loc_network_matches_address(other, &self->last_address))
		return 1;

	return 0;
}

LOC_EXPORT int loc_network_is_subnet(struct loc_network* self, struct loc_network* other) {
	// The prefix must be smaller (this avoids the more complex comparisons later)
	if (self->prefix > other->prefix)
		return 0;

	// If the start address of the other network is smaller than this network,
	// it cannot be a subnet.
	if (loc_address_cmp(&self->first_address, &other->first_address) > 0)
		return 0;

	// If the end address of the other network is greater than this network,
	// it cannot be a subnet.
	if (loc_address_cmp(&self->last_address, &other->last_address) < 0)
		return 0;

	return 1;
}

LOC_EXPORT int loc_network_subnets(struct loc_network* network,
		struct loc_network** subnet1, struct loc_network** subnet2) {
	int r;
	*subnet1 = NULL;
	*subnet2 = NULL;

	// New prefix length
	unsigned int prefix = loc_network_prefix(network) + 1;

	// Check if the new prefix is valid
	if (!loc_address_valid_prefix(&network->first_address, prefix)) {
		ERROR(network->ctx, "Invalid prefix: %u\n", prefix);
		return -EINVAL;
	}

	// Create the first half of the network
	r = loc_network_new(network->ctx, subnet1, &network->first_address, prefix);
	if (r)
		return r;

	// The next subnet starts after the first one
	struct in6_addr first_address = (*subnet1)->last_address;
	loc_address_increment(&first_address);

	// Create the second half of the network
	r = loc_network_new(network->ctx, subnet2, &first_address, prefix);
	if (r) {
		loc_network_unref(*subnet1);
		*subnet1 = NULL;

		return r;
	}

	// Copy country code
	const char* country_code = loc_network_get_country_code(network);
	if (country_code) {
		loc_network_set_country_code(*subnet1, country_code);
		loc_network_set_country_code(*subnet2, country_code);
	}

	// Copy ASN
	uint32_t asn = loc_network_get_asn(network);
	if (asn) {
		loc_network_set_asn(*subnet1, asn);
		loc_network_set_asn(*subnet2, asn);
	}

	// Copy flags
	loc_network_set_flag(*subnet1, network->flags);
	loc_network_set_flag(*subnet2, network->flags);

	return 0;
}

static int __loc_network_exclude(struct loc_network* network,
		struct loc_network* other, struct loc_network_list* list) {
	struct loc_network* subnet1 = NULL;
	struct loc_network* subnet2 = NULL;

	int r = loc_network_subnets(network, &subnet1, &subnet2);
	if (r)
		goto ERROR;

	if (loc_network_cmp(other, subnet1) == 0) {
		r = loc_network_list_push(list, subnet2);
		if (r)
			goto ERROR;

	} else if (loc_network_cmp(other, subnet2) == 0) {
		r = loc_network_list_push(list, subnet1);
		if (r)
			goto ERROR;

	} else  if (loc_network_is_subnet(subnet1, other)) {
		r = loc_network_list_push(list, subnet2);
		if (r)
			goto ERROR;

		r = __loc_network_exclude(subnet1, other, list);
		if (r)
			goto ERROR;

	} else if (loc_network_is_subnet(subnet2, other)) {
		r = loc_network_list_push(list, subnet1);
		if (r)
			goto ERROR;

		r = __loc_network_exclude(subnet2, other, list);
		if (r)
			goto ERROR;

	} else {
		ERROR(network->ctx, "We should never get here\n");
		r = -EINVAL;
		goto ERROR;
	}

ERROR:
	if (subnet1)
		loc_network_unref(subnet1);

	if (subnet2)
		loc_network_unref(subnet2);

	if (r)
		DEBUG(network->ctx, "%s has failed with %d\n", __FUNCTION__, r);

	return r;
}

static int __loc_network_exclude_to_list(struct loc_network* self,
		struct loc_network* other, struct loc_network_list* list) {
	// Other must be a subnet of self
	if (!loc_network_is_subnet(self, other)) {
		DEBUG(self->ctx, "Network %p is not contained in network %p\n", other, self);

		// Exit silently
		return 0;
	}

	// We cannot perform this operation if both networks equal
	if (loc_network_cmp(self, other) == 0) {
		DEBUG(self->ctx, "Networks %p and %p are equal\n", self, other);

		// Exit silently
		return 0;
	}

	return __loc_network_exclude(self, other, list);
}

LOC_EXPORT struct loc_network_list* loc_network_exclude(
		struct loc_network* self, struct loc_network* other) {
	struct loc_network_list* list;

	DEBUG(self->ctx, "Returning %s excluding %s...\n",
		loc_network_str(self), loc_network_str(other));

	// Create a new list with the result
	int r = loc_network_list_new(self->ctx, &list);
	if (r) {
		ERROR(self->ctx, "Could not create network list: %d\n", r);

		return NULL;
	}

	// If the networks do not overlap, nothing is being excluded
	if (!loc_network_overlaps(self, other))
		r = loc_network_list_push(list, self);
	else
		r = __loc_network_exclude_to_list(self, other, list);

	if (r) {
		loc_network_list_unref(list);

		return NULL;
	}

	// Return the result
	return list;
}

LOC_EXPORT struct loc_network_list* loc_network_exclude_list(
		struct loc_network* network, struct loc_network_list* list) {
	struct loc_network_list* to_check;

	// Create a new list with all networks to look at
	int r = loc_network_list_new(network->ctx, &to_check);
	if (r)
		return NULL;

	struct loc_network* subnet = NULL;
	struct loc_network_list* subnets = NULL;

	// Start with the whole network, which is being broken down below wherever
	// it overlaps with any of the networks on the list
	r = loc_network_list_push(to_check, network);
	if (r) {
		loc_network_list_unref(to_check);
		return NULL;
	}

	r = loc_network_list_new(network->ctx, &subnets);
	if (r) {
		loc_network_list_unref(to_check);
		return NULL;
	}

	off_t smallest_subnet = 0;

	while (!loc_network_list_empty(to_check)) {
		struct loc_network* subnet_to_check = loc_network_list_pop_first(to_check);

		// Check whether the subnet to check is part of the input list
		if (loc_network_list_contains(list, subnet_to_check)) {
			loc_network_unref(subnet_to_check);
			continue;
		}

		// Marks whether this subnet passed all checks
		int passed = 1;

		for (unsigned int i = smallest_subnet; i < loc_network_list_size(list); i++) {
			subnet = loc_network_list_get(list, i);

			// Drop this subnet if is a subnet of another subnet
			if (loc_network_is_subnet(subnet, subnet_to_check)) {
				passed = 0;
				loc_network_unref(subnet);
				break;
			}

			// Break it down if it overlaps
			if (loc_network_overlaps(subnet, subnet_to_check)) {
				passed = 0;

				__loc_network_exclude_to_list(subnet_to_check, subnet, to_check);

				loc_network_unref(subnet);
				break;
			}

			// If the subnet is strictly greater, we do not need to continue the search
			r = loc_network_cmp(subnet, subnet_to_check);
			if (r > 0) {
				loc_network_unref(subnet);
				break;

			// If it is strictly smaller, we can continue the search from here next
			// time because all networks that are to be checked can only be larger
			// than this one.
			} else if (r < 0) {
				smallest_subnet = i;
			}

			loc_network_unref(subnet);
		}

		if (passed)
			loc_network_list_push(subnets, subnet_to_check);

		loc_network_unref(subnet_to_check);
	}

	loc_network_list_unref(to_check);

	return subnets;
}

int loc_network_merge(struct loc_network** n,
		struct loc_network* n1, struct loc_network* n2) {
	struct loc_network* network = NULL;
	struct in6_addr address;
	int r;

	// Reset pointer
	*n = NULL;

	DEBUG(n1->ctx, "Attempting to merge %s and %s\n", loc_network_str(n1), loc_network_str(n2));

	// Family must match
	if (n1->family != n2->family)
		return 0;

	// The prefix must match, too
	if (n1->prefix != n2->prefix)
		return 0;

	// Cannot merge ::/0 or 0.0.0.0/0
	if (!n1->prefix || !n2->prefix)
		return 0;

	const size_t prefix = loc_network_prefix(n1);

	// How many bits do we need to represent this address?
	const size_t bitlength = loc_address_bit_length(&n1->first_address);

	// We cannot shorten this any more
	if (bitlength >= prefix) {
		DEBUG(n1->ctx, "Cannot shorten this any further because we need at least %zu bits,"
			" but only have %zu\n", bitlength, prefix);

		return 0;
	}

	// Increment the last address of the first network
	address = n1->last_address;
	loc_address_increment(&address);

	// If they don't match they are not neighbours
	if (loc_address_cmp(&address, &n2->first_address) != 0)
		return 0;

	// All properties must match, too
	if (loc_network_properties_cmp(n1, n2) != 0)
		return 0;

	// Create a new network object
	r = loc_network_new(n1->ctx, &network, &n1->first_address, prefix - 1);
	if (r)
		return r;

	// Copy everything else
	loc_country_code_copy(network->country_code, n1->country_code);
	network->asn = n1->asn;
	network->flags = n1->flags;

	// Return pointer
	*n = network;

	return 0;
}

int loc_network_to_database_v1(struct loc_network* network, struct loc_database_network_v1* dbobj) {
	// Add country code
	loc_country_code_copy(dbobj->country_code, network->country_code);

	// Add ASN
	dbobj->asn = htobe32(network->asn);

	// Flags
	dbobj->flags = htobe16(network->flags);

	return 0;
}

int loc_network_new_from_database_v1(struct loc_ctx* ctx, struct loc_network** network,
		struct in6_addr* address, unsigned int prefix, const struct loc_database_network_v1* dbobj) {
	char country_code[3] = "\0\0";

	// Adjust prefix for IPv4
	if (IN6_IS_ADDR_V4MAPPED(address))
		prefix -= 96;

	int r = loc_network_new(ctx, network, address, prefix);
	if (r) {
		ERROR(ctx, "Could not allocate a new network: %s\n", strerror(-r));
		return r;
	}

	// Import country code
	loc_country_code_copy(country_code, dbobj->country_code);

	r = loc_network_set_country_code(*network, country_code);
	if (r) {
		ERROR(ctx, "Could not set country code: %s\n", country_code);
		goto ERROR;
	}

	// Import ASN
	uint32_t asn = be32toh(dbobj->asn);
	r = loc_network_set_asn(*network, asn);
	if (r) {
		ERROR(ctx, "Could not set ASN: %u\n", asn);
		goto ERROR;
	}

	// Import flags
	int flags = be16toh(dbobj->flags);
	r = loc_network_set_flag(*network, flags);
	if (r) {
		ERROR(ctx, "Could not set flags: %d\n", flags);
		goto ERROR;
	}

	return 0;

ERROR:
	loc_network_unref(*network);
	*network = NULL;

	return r;
}

static char* loc_network_reverse_pointer6(struct loc_network* network, const char* suffix) {
	char* buffer = NULL;
	size_t length = 1;

	unsigned int prefix = loc_network_prefix(network);

	// Must border on a nibble
	if (prefix % 4) {
		errno = ENOTSUP;
		return NULL;
	}

	if (!suffix)
		suffix = "ip6.arpa.";

	const int nibbles = prefix / 4;

	// Make space for all nibbles
	length += nibbles * 2;

	// Make space for the star for wildcards
	if (prefix < 128)
		length += 2;

	// Make space for the suffix
	length += strlen(suffix);

	// Allocate the buffer
	buffer = malloc(length);
	if (!buffer)
		goto ERROR;

	char* p = buffer;

	// Add the asterisk
	if (prefix < 128) {
		*p++ = '*';

		if (nibbles || *suffix)
			*p++ = '.';
	}

	static const char hex[] = "0123456789abcdef";

	// Add nibbles
	for (int i = nibbles - 1; i >= 0; i--) {
		int nibble = loc_address_get_nibble(&network->first_address, i);

		// Check if the nibble is in range
		if (nibble < 0 || nibble > 0x0f) {
			errno = ERANGE;
			goto ERROR;
		}

		*p++ = hex[nibble];

		if (i > 0 || *suffix)
			*p++ = '.';
	}

	// Add suffix (may be empty)
	if (*suffix) {
		memcpy(p, suffix, strlen(suffix));
		p += strlen(suffix);
	}

	// Terminate the buffer
	*p = '\0';

	return buffer;

ERROR:
	if (buffer)
		free(buffer);

	return NULL;
}

static char* loc_network_reverse_pointer4(struct loc_network* network, const char* suffix) {
	char* buffer = NULL;
	size_t length = 1;

	unsigned int prefix = loc_network_prefix(network);

	// Must border on an octet
	if (prefix % 8) {
		errno = ENOTSUP;
		return NULL;
	}

	if (!suffix)
		suffix = "in-addr.arpa.";

	const int octets = prefix / 8;

	// Make space for all octets
	length += octets * 4;

	// Make space for the star
	if (prefix < 32)
		length += 2;

	// Make space for the suffix
	length += strlen(suffix);

	// Allocate the buffer
	buffer = malloc(length);
	if (!buffer)
		goto ERROR;

	char* p = buffer;

	// Add asterisk if needed (prefix < 32)
	if (prefix < 32) {
		*p++ = '*';

		if (octets || *suffix)
			*p++ = '.';
	}

	// Append octets in reverse order
	for (int i = octets - 1; i >= 0; i--) {
		int oct = loc_address_get_octet(&network->first_address, i);
		if (oct < 0) {
			errno = ERANGE;
			goto ERROR;
		}

		// Convert octet to decimal string
		p += sprintf(p, "%d", oct);

		// Dot between octets or before suffix
		if (i > 0 || *suffix)
			*p++ = '.';
	}

	// Add suffix (may be empty)
	if (*suffix) {
		memcpy(p, suffix, strlen(suffix));
		p += strlen(suffix);
	}

	// Terminate the buffer
	*p = '\0';

	return buffer;

ERROR:
	if (buffer)
		free(buffer);

	return NULL;
}

LOC_EXPORT char* loc_network_reverse_pointer(struct loc_network* network, const char* suffix) {
	switch (network->family) {
		case AF_INET6:
			return loc_network_reverse_pointer6(network, suffix);

		case AF_INET:
			return loc_network_reverse_pointer4(network, suffix);

		default:
			break;
	}

	return NULL;
}
