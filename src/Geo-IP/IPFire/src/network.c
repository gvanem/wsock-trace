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

#ifdef _WIN32
  static char err_buf[20];   // Add to the 'context'?
  #define GET_NETERR() _itoa (WSAGetLastError(), err_buf, 10)
#else
  #define GET_NETERR() strerror(errno)
#endif

struct loc_network {
	struct loc_ctx* ctx;
	int refcount;

	int family;
	struct in6_addr first_address;
	struct in6_addr last_address;
	unsigned int prefix;

	char country_code[3];
	uint32_t asn;
	enum loc_network_flags flags;

	char string[INET6_ADDRSTRLEN + 4];
};

LOC_EXPORT int loc_network_new(struct loc_ctx* ctx, struct loc_network** network,
		struct in6_addr* address, unsigned int prefix) {

	char abuf[100];
	DEBUG(ctx, "address: %s\n", inet_ntop(AF_INET6, address, abuf, sizeof(abuf)));

	// Validate the prefix
	if (!loc_address_valid_prefix(address, prefix)) {
		ERROR(ctx, "Invalid prefix in %s: %u\n", loc_address_str(address), prefix);
		errno = EINVAL;
		return 1;
	}

	struct loc_network* n = calloc(1, sizeof(*n));
	if (!n) {
		errno = ENOMEM;
		return 1;
	}

	n->ctx = loc_ref(ctx);
	n->refcount = 1;

	// Store the prefix
	if (IN6_IS_ADDR_V4MAPPED(address))
		n->prefix = prefix + 96;
	else
		n->prefix = prefix;

	// Convert the prefix into a bitmask
	struct in6_addr bitmask = loc_prefix_to_bitmask(n->prefix);

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
		ERROR(ctx, "Could not parse network %s: %m\n", string);
		return r;
	}

	// Create a new network
	return loc_network_new(ctx, network, &address, prefix);
}

LOC_EXPORT struct loc_network* loc_network_ref(struct loc_network* network) {
	network->refcount++;

	return network;
}

static void loc_network_free(struct loc_network* network) {
	DEBUG(network->ctx, "Releasing network at %p\n", network);

	loc_unref(network->ctx);
	free(network);
}

LOC_EXPORT struct loc_network* loc_network_unref(struct loc_network* network) {
	if (!network)
		return NULL;

	if (--network->refcount > 0)
		return network;

	loc_network_free(network);
	return NULL;
}

LOC_EXPORT const char* loc_network_str(struct loc_network* network) {
	if (!*network->string) {
		// Format the address
		const char* address = loc_address_str(&network->first_address);
		if (!address)
			return NULL;

		// Fetch the prefix
		unsigned int prefix = loc_network_prefix(network);

		// Format the string
		int r = snprintf(network->string, sizeof(network->string) - 1,
			"%s/%u", address, prefix);
		if (r < 0) {
			ERROR(network->ctx, "Could not format network string: %m\n");
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

LOC_EXPORT const struct in6_addr* loc_network_get_first_address(struct loc_network* network) {
	return &network->first_address;
}

LOC_EXPORT const char* loc_network_format_first_address(struct loc_network* network) {
	return loc_address_str(&network->first_address);
}

LOC_EXPORT const struct in6_addr* loc_network_get_last_address(struct loc_network* network) {
	return &network->last_address;
}

LOC_EXPORT const char* loc_network_format_last_address(struct loc_network* network) {
	return loc_address_str(&network->last_address);
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

	// If we found a flag, we will return whether it is set or not
	if (flag)
		return loc_network_has_flag(network, flag);

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
		ERROR(network->ctx, "Invalid prefix: %d\n", prefix);
		errno = EINVAL;
		return 1;
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
	if (r)
		return r;

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
		r = 1;
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

	for (unsigned int i = 0; i < loc_network_list_size(list); i++) {
		subnet = loc_network_list_get(list, i);

		// Find all excluded networks
		if (!loc_network_list_contains(to_check, subnet)) {
			r = __loc_network_exclude_to_list(network, subnet, to_check);
			if (r) {
				loc_network_list_unref(to_check);
				loc_network_unref(subnet);

				return NULL;
			}
		}

		// Cleanup
		loc_network_unref(subnet);
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

		if (passed) {
			r = loc_network_list_push(subnets, subnet_to_check);
		}

		loc_network_unref(subnet_to_check);
	}

	loc_network_list_unref(to_check);

	return subnets;
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
		ERROR(ctx, "Could not allocate a new network: %s", strerror(-r));
		return r;
	}

	// Import country code
	loc_country_code_copy(country_code, dbobj->country_code);

	r = loc_network_set_country_code(*network, country_code);
	if (r) {
		ERROR(ctx, "Could not set country code: %s\n", country_code);
		return r;
	}

	// Import ASN
	uint32_t asn = be32toh(dbobj->asn);
	r = loc_network_set_asn(*network, asn);
	if (r) {
		ERROR(ctx, "Could not set ASN: %d\n", asn);
		return r;
	}

	// Import flags
	int flags = be16toh(dbobj->flags);
	r = loc_network_set_flag(*network, flags);
	if (r) {
		ERROR(ctx, "Could not set flags: %d\n", flags);
		return r;
	}

	return 0;
}

struct loc_network_tree {
	struct loc_ctx* ctx;
	int refcount;

	struct loc_network_tree_node* root;
};

struct loc_network_tree_node {
	struct loc_ctx* ctx;
	int refcount;

	struct loc_network_tree_node* zero;
	struct loc_network_tree_node* one;

	struct loc_network* network;
};

int loc_network_tree_new(struct loc_ctx* ctx, struct loc_network_tree** tree) {
	struct loc_network_tree* t = calloc(1, sizeof(*t));
	if (!t)
		return -ENOMEM;

	t->ctx = loc_ref(ctx);
	t->refcount = 1;

	// Create the root node
	int r = loc_network_tree_node_new(ctx, &t->root);
	if (r) {
		loc_network_tree_unref(t);
		return r;
	}

	DEBUG(t->ctx, "Network tree allocated at %p\n", t);
	*tree = t;
	return 0;
}

struct loc_network_tree_node* loc_network_tree_get_root(struct loc_network_tree* tree) {
	return loc_network_tree_node_ref(tree->root);
}

static struct loc_network_tree_node* loc_network_tree_get_node(struct loc_network_tree_node* node, int path) {
	struct loc_network_tree_node** n;

	if (path == 0)
		n = &node->zero;
	else
		n = &node->one;

	// If the desired node doesn't exist, yet, we will create it
	if (*n == NULL) {
		int r = loc_network_tree_node_new(node->ctx, n);
		if (r)
			return NULL;
	}

	return *n;
}

static struct loc_network_tree_node* loc_network_tree_get_path(struct loc_network_tree* tree, const struct in6_addr* address, unsigned int prefix) {
	struct loc_network_tree_node* node = tree->root;

	for (unsigned int i = 0; i < prefix; i++) {
		// Check if the ith bit is one or zero
		node = loc_network_tree_get_node(node, loc_address_get_bit(address, i));
	}

	return node;
}

static int __loc_network_tree_walk(struct loc_ctx* ctx, struct loc_network_tree_node* node,
		int(*filter_callback)(struct loc_network* network, void* data),
		int(*callback)(struct loc_network* network, void* data), void* data) {
	int r;

	// Finding a network ends the walk here
	if (node->network) {
		if (filter_callback) {
			int f = filter_callback(node->network, data);
			if (f < 0)
				return f;

			// Skip network if filter function returns value greater than zero
			if (f > 0)
				return 0;
		}

		r = callback(node->network, data);
		if (r)
			return r;
	}

	// Walk down on the left side of the tree first
	if (node->zero) {
		r = __loc_network_tree_walk(ctx, node->zero, filter_callback, callback, data);
		if (r)
			return r;
	}

	// Then walk on the other side
	if (node->one) {
		r = __loc_network_tree_walk(ctx, node->one, filter_callback, callback, data);
		if (r)
			return r;
	}

	return 0;
}

int loc_network_tree_walk(struct loc_network_tree* tree,
		int(*filter_callback)(struct loc_network* network, void* data),
		int(*callback)(struct loc_network* network, void* data), void* data) {
	return __loc_network_tree_walk(tree->ctx, tree->root, filter_callback, callback, data);
}

static void loc_network_tree_free(struct loc_network_tree* tree) {
	DEBUG(tree->ctx, "Releasing network tree at %p\n", tree);

	loc_network_tree_node_unref(tree->root);

	loc_unref(tree->ctx);
	free(tree);
}

struct loc_network_tree* loc_network_tree_unref(struct loc_network_tree* tree) {
	if (--tree->refcount > 0)
		return tree;

	loc_network_tree_free(tree);
	return NULL;
}

static int __loc_network_tree_dump(struct loc_network* network, void* data) {
	DEBUG(network->ctx, "Dumping network at %p\n", network);

	const char* s = loc_network_str(network);
	if (!s)
		return 1;

	INFO(network->ctx, "%s\n", s);

	return 0;
}

int loc_network_tree_dump(struct loc_network_tree* tree) {
	DEBUG(tree->ctx, "Dumping network tree at %p\n", tree);

	return loc_network_tree_walk(tree, NULL, __loc_network_tree_dump, NULL);
}

int loc_network_tree_add_network(struct loc_network_tree* tree, struct loc_network* network) {
	DEBUG(tree->ctx, "Adding network %p to tree %p\n", network, tree);

	struct loc_network_tree_node* node = loc_network_tree_get_path(tree,
			&network->first_address, network->prefix);
	if (!node) {
		ERROR(tree->ctx, "Could not find a node\n");
		return -ENOMEM;
	}

	// Check if node has not been set before
	if (node->network) {
		DEBUG(tree->ctx, "There is already a network at this path\n");
		return -EBUSY;
	}

	// Point node to the network
	node->network = loc_network_ref(network);

	return 0;
}

static int __loc_network_tree_count(struct loc_network* network, void* data) {
	size_t* counter = (size_t*)data;

	// Increase the counter for each network
	counter++;

	return 0;
}

size_t loc_network_tree_count_networks(struct loc_network_tree* tree) {
	size_t counter = 0;

	int r = loc_network_tree_walk(tree, NULL, __loc_network_tree_count, &counter);
	if (r)
		return r;

	return counter;
}

static size_t __loc_network_tree_count_nodes(struct loc_network_tree_node* node) {
	size_t counter = 1;

	if (node->zero)
		counter += __loc_network_tree_count_nodes(node->zero);

	if (node->one)
		counter += __loc_network_tree_count_nodes(node->one);

	return counter;
}

size_t loc_network_tree_count_nodes(struct loc_network_tree* tree) {
	return __loc_network_tree_count_nodes(tree->root);
}

int loc_network_tree_node_new(struct loc_ctx* ctx, struct loc_network_tree_node** node) {
	struct loc_network_tree_node* n = calloc(1, sizeof(*n));
	if (!n)
		return -ENOMEM;

	n->ctx = loc_ref(ctx);
	n->refcount = 1;

	n->zero = n->one = NULL;

	DEBUG(n->ctx, "Network node allocated at %p\n", n);
	*node = n;
	return 0;
}

struct loc_network_tree_node* loc_network_tree_node_ref(struct loc_network_tree_node* node) {
	if (node)
		node->refcount++;

	return node;
}

static void loc_network_tree_node_free(struct loc_network_tree_node* node) {
	DEBUG(node->ctx, "Releasing network node at %p\n", node);

	if (node->network)
		loc_network_unref(node->network);

	if (node->zero)
		loc_network_tree_node_unref(node->zero);

	if (node->one)
		loc_network_tree_node_unref(node->one);

	loc_unref(node->ctx);
	free(node);
}

struct loc_network_tree_node* loc_network_tree_node_unref(struct loc_network_tree_node* node) {
	if (!node)
		return NULL;

	if (--node->refcount > 0)
		return node;

	loc_network_tree_node_free(node);
	return NULL;
}

struct loc_network_tree_node* loc_network_tree_node_get(struct loc_network_tree_node* node, unsigned int index) {
	if (index == 0)
		node = node->zero;
	else
		node = node->one;

	if (!node)
		return NULL;

	return loc_network_tree_node_ref(node);
}

int loc_network_tree_node_is_leaf(struct loc_network_tree_node* node) {
	return (!!node->network);
}

struct loc_network* loc_network_tree_node_get_network(struct loc_network_tree_node* node) {
	return loc_network_ref(node->network);
}
