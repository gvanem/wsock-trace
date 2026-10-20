/*
	libloc - A library to determine the location of someone on the Internet

	Copyright (C) 2020 IPFire Development Team <info@ipfire.org>

	This library is free software; you can redistribute it and/or
	modify it under the terms of the GNU Lesser General Public
	License as published by the Free Software Foundation; either
	version 2.1 of the License, or (at your option) any later version.

	This library is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
	Lesser General Public License for more details.
*/

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <libloc/libloc.h>
#include <libloc/address.h>
#include <libloc/network.h>
#include <libloc/private.h>

struct loc_network_list {
	struct loc_ctx* ctx;
	loc_refcount_t refcount;

	// The allocated space
	struct loc_network** data;
	size_t data_size;

	// The networks start somewhere in the allocated space, so that we can
	// remove the first one without moving all others
	struct loc_network** elements;
	size_t size;
};

// How many elements can be added at the end
static size_t loc_network_list_space(struct loc_network_list* list) {
	return list->data_size - (list->elements - list->data) - list->size;
}

/*
	Makes space for at least one more element at the end
*/
static int loc_network_list_grow(struct loc_network_list* list) {
	const size_t head = list->elements - list->data;

	// If at least half of the space is free at the start, move everything there
	if (head && head >= list->data_size / 2) {
		memmove(list->data, list->elements, sizeof(*list->elements) * list->size);
		list->elements = list->data;

		return 0;
	}

	size_t size = list->data_size * 2;
	if (size < 1024)
		size = 1024;

	DEBUG(list->ctx, "Growing network list %p by %zu to %zu\n",
		list, size, list->data_size + size);

	struct loc_network** data = reallocarray(list->data,
			list->data_size + size, sizeof(*list->data));
	if (!data)
		return -ENOMEM;

	list->data = data;
	list->data_size += size;
	list->elements = data + head;

	return 0;
}

LOC_EXPORT int loc_network_list_new(struct loc_ctx* ctx,
		struct loc_network_list** list) {
	struct loc_network_list* l = calloc(1, sizeof(*l));
	if (!l)
		return -ENOMEM;

	l->ctx = loc_ref(ctx);
	l->refcount = 1;

	DEBUG(l->ctx, "Network list allocated at %p\n", l);
	*list = l;
	return 0;
}

LOC_EXPORT struct loc_network_list* loc_network_list_ref(struct loc_network_list* list) {
	loc_refcount_inc(&list->refcount);

	return list;
}

static void loc_network_list_free(struct loc_network_list* list) {
	DEBUG(list->ctx, "Releasing network list at %p\n", list);

	// Remove all content
	loc_network_list_clear(list);

	loc_unref(list->ctx);
	free(list);
}

LOC_EXPORT struct loc_network_list* loc_network_list_unref(struct loc_network_list* list) {
	if (loc_refcount_dec(&list->refcount) > 0)
		return list;

	loc_network_list_free(list);
	return NULL;
}

LOC_EXPORT size_t loc_network_list_size(struct loc_network_list* list) {
	return list->size;
}

LOC_EXPORT int loc_network_list_empty(struct loc_network_list* list) {
	return list->size == 0;
}

LOC_EXPORT void loc_network_list_clear(struct loc_network_list* list) {
	if (!list->data)
		return;

	for (unsigned int i = 0; i < list->size; i++)
		loc_network_unref(list->elements[i]);

	free(list->data);
	list->data = NULL;
	list->data_size = 0;

	list->elements = NULL;
	list->size = 0;
}

LOC_EXPORT void loc_network_list_dump(struct loc_network_list* list) {
	struct loc_network* network;

	for (unsigned int i = 0; i < list->size; i++) {
		network = list->elements[i];

		INFO(list->ctx, "%4u: %s\n",
			i, loc_network_str(network));
	}
}

LOC_EXPORT struct loc_network* loc_network_list_get(struct loc_network_list* list, size_t index) {
	// Check index
	if (index >= list->size)
		return NULL;

	return loc_network_ref(list->elements[index]);
}

static off_t loc_network_list_find(struct loc_network_list* list,
		struct loc_network* network, int* found) {
	// Insert at the beginning for an empty list
	if (loc_network_list_empty(list))
		return 0;

	off_t lo = 0;
	off_t hi = list->size - 1;
	int result;

	// Since we are working on an ordered list, there is often a good chance that
	// the network we are looking for is at the end or has to go to the end.
	if (hi >= 0) {
		result = loc_network_cmp(network, list->elements[hi]);

		// Match, so we are done
		if (result == 0) {
			*found = 1;

			return hi;

		// This needs to be added after the last one
		} else if (result > 0) {
			*found = 0;

			return hi + 1;
		}
	}

#ifdef ENABLE_DEBUG
	// Save start time
	clock_t start = clock();
#endif

	off_t i = 0;

	while (lo <= hi) {
		i = (lo + hi) / 2;

		// Check if this is a match
		result = loc_network_cmp(network, list->elements[i]);

		if (result == 0) {
			*found = 1;

#ifdef ENABLE_DEBUG
			clock_t end = clock();

			// Log how fast this has been
			DEBUG(list->ctx, "Found network in %.4fms at %jd\n",
				(double)(end - start) / CLOCKS_PER_SEC * 1000, (intmax_t)i);
#endif

			return i;
		}

		if (result > 0) {
			lo = i + 1;
			i++;
		} else {
			hi = i - 1;
		}
	}

	*found = 0;

#ifdef ENABLE_DEBUG
	clock_t end = clock();

	// Log how fast this has been
	DEBUG(list->ctx, "Did not find network in %.4fms (last i = %jd)\n",
		(double)(end - start) / CLOCKS_PER_SEC * 1000, (intmax_t)i);
#endif

	return i;
}

LOC_EXPORT int loc_network_list_push(struct loc_network_list* list, struct loc_network* network) {
	int found = 0;

	off_t index = loc_network_list_find(list, network, &found);

	// The network has been found on the list. Nothing to do.
	if (found)
		return 0;

	DEBUG(list->ctx, "%p: Inserting network %p at index %jd\n",
		list, network, (intmax_t)index);

	// If there is space at the start and we are closer to it, we move all elements
	// before the new one towards the start. Otherwise, we move all after it.
	if (list->elements > list->data && (size_t)index < list->size / 2) {
		list->elements--;
		list->size++;

		memmove(list->elements, list->elements + 1, sizeof(*list->elements) * index);

	} else {
		// Check if we have space left
		if (!loc_network_list_space(list)) {
			int r = loc_network_list_grow(list);
			if (r)
				return r;
		}

		memmove(list->elements + index + 1, list->elements + index,
			sizeof(*list->elements) * (list->size - index));

		list->size++;
	}

	// Add the new element at the right place
	list->elements[index] = loc_network_ref(network);

	return 0;
}

LOC_EXPORT struct loc_network* loc_network_list_pop(struct loc_network_list* list) {
	// Return nothing when empty
	if (loc_network_list_empty(list)) {
		DEBUG(list->ctx, "%p: Popped empty stack\n", list);
		return NULL;
	}

	struct loc_network* network = list->elements[--list->size];

	DEBUG(list->ctx, "%p: Popping network %p from stack\n", list, network);

	return network;
}

LOC_EXPORT struct loc_network* loc_network_list_pop_first(struct loc_network_list* list) {
	// Return nothing when empty
	if (loc_network_list_empty(list)) {
		DEBUG(list->ctx, "%p: Popped empty stack\n", list);
		return NULL;
	}

	struct loc_network* network = list->elements[0];

	// The list starts at the next element now
	list->elements++;
	--list->size;

	// Start from the beginning again once the list is empty
	if (!list->size)
		list->elements = list->data;

	DEBUG(list->ctx, "%p: Popping network %p from stack\n", list, network);

	return network;
}

int loc_network_list_remove(struct loc_network_list* list, struct loc_network* network) {
	int found = 0;

	// Find the network on the list
	off_t index = loc_network_list_find(list, network, &found);

	// Nothing to do if the network wasn't found
	if (!found)
		return 0;

	// Dereference the network at the position
	loc_network_unref(list->elements[index]);

	// Move all other elements back
	for (unsigned int i = index; i < list->size - 1; i++)
		list->elements[i] = list->elements[i+1];

	// The list is shorter now
	--list->size;

	return 0;
}

LOC_EXPORT int loc_network_list_contains(struct loc_network_list* list, struct loc_network* network) {
	int found = 0;

	loc_network_list_find(list, network, &found);

	return found;
}

LOC_EXPORT int loc_network_list_merge(
		struct loc_network_list* self, struct loc_network_list* other) {
	int r;

	for (unsigned int i = 0; i < other->size; i++) {
		r = loc_network_list_push(self, other->elements[i]);
		if (r)
			return r;
	}

	return 0;
}

int loc_network_list_summarize(struct loc_ctx* ctx,
		const struct in6_addr* first, const struct in6_addr* last, struct loc_network_list** list) {
	int r;

	if (!list)
		return -EINVAL;

#ifdef ENABLE_DEBUG
	char buffer1[LOC_ADDRESS_STRING_LENGTH];
	char buffer2[LOC_ADDRESS_STRING_LENGTH];

	DEBUG(ctx, "Summarizing %s - %s\n",
		loc_address_format(first, buffer1, sizeof(buffer1)),
		loc_address_format(last, buffer2, sizeof(buffer2)));
#endif

	const int family1 = loc_address_family(first);
	const int family2 = loc_address_family(last);

	// Check if address families match
	if (family1 != family2) {
		ERROR(ctx, "Address families do not match\n");
		return -EINVAL;
	}

	// Check if the last address is larger than the first address
	if (loc_address_cmp(first, last) > 0) {
		ERROR(ctx, "The first address must not be larger than the last address\n");
		return -EINVAL;
	}

	struct loc_network* network = NULL;
	struct in6_addr start = *first;

	// How long is an address of this family?
	const unsigned int bit_length = loc_address_family_bit_length(family1);

	// IPv4 addresses are mapped to the end of the IPv6 address space
	const unsigned int offset = LOC_ADDRESS_MAX_BITS - bit_length;

	while (loc_address_cmp(&start, last) <= 0) {
		// The next network starts at the start address, so its prefix
		// cannot be any shorter than there are bits set in that address.
		unsigned int prefix = loc_address_bit_length(&start);

		// Make the network smaller until it ends before (or at) the last address
		for (; prefix < bit_length; prefix++) {
			const struct in6_addr bitmask = loc_prefix_to_bitmask(offset + prefix);
			const struct in6_addr end = loc_address_or(&start, &bitmask);

			if (loc_address_cmp(&end, last) <= 0)
				break;
		}

		// Create a network
		r = loc_network_new(ctx, &network, &start, prefix);
		if (r)
			return r;

		DEBUG(ctx, "Found network %s\n", loc_network_str(network));

		// Push network on the list
		r = loc_network_list_push(*list, network);
		if (r) {
			loc_network_unref(network);
			return r;
		}

		// The next network starts right after this one
		start = *loc_network_get_last_address(network);

		// The list holds its own reference
		loc_network_unref(network);

		// If we have reached the end of possible IP addresses, we stop
		if (loc_address_all_ones(&start))
			break;

		loc_address_increment(&start);
	}

	return 0;
}

void loc_network_list_remove_with_prefix_smaller_than(
		struct loc_network_list* list, const unsigned int prefix) {
	unsigned int p = 0;

	// Count how many networks were removed
	unsigned int removed = 0;

	for (unsigned int i = 0; i < list->size; i++) {
		// Fetch the prefix
		p = loc_network_prefix(list->elements[i]);

		if (p > prefix) {
			// Drop this network
			loc_network_unref(list->elements[i]);

			// Increment counter
			removed++;

			continue;
		}

		// Move pointers backwards to keep the list filled
		list->elements[i - removed] = list->elements[i];
	}

	// Adjust size
	list->size -= removed;

	return;
}
