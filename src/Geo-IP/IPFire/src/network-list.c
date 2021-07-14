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
#include <time.h>

#include <loc/libloc.h>
#include <loc/network.h>
#include <loc/private.h>

struct loc_network_list {
	struct loc_ctx* ctx;
	int refcount;

	struct loc_network** elements;
	size_t elements_size;

	size_t size;
};

static int loc_network_list_grow(struct loc_network_list* list, size_t size) {
	DEBUG(list->ctx, "Growing network list %p by %zu to %zu\n",
		list, size, list->elements_size + size);

	struct loc_network** elements = reallocarray(list->elements,
			list->elements_size + size, sizeof(*list->elements));
	if (!elements)
		return -errno;

	list->elements = elements;
	list->elements_size += size;

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
	list->refcount++;

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
	if (!list)
		return NULL;

	if (--list->refcount > 0)
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
	if (!list->elements)
		return;

	for (unsigned int i = 0; i < list->size; i++)
		loc_network_unref(list->elements[i]);

	free(list->elements);
	list->elements = NULL;
	list->elements_size = 0;

	list->size = 0;
}

LOC_EXPORT void loc_network_list_dump(struct loc_network_list* list) {
	struct loc_network* network;
	char* s;

	for (unsigned int i = 0; i < list->size; i++) {
		network = list->elements[i];

		s = loc_network_str(network);

		INFO(list->ctx, "%4d: %s\n", i, s);
		free(s);
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

	// Check if we have space left
	if (list->size >= list->elements_size) {
		int r = loc_network_list_grow(list, 64);
		if (r)
			return r;
	}

	// The list is now larger
	list->size++;

	// Move all elements out of the way
	for (unsigned int i = list->size - 1; i > (unsigned int)index; i--)
		list->elements[i] = list->elements[i - 1];

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

	// Move all elements to the top of the stack
	for (unsigned int i = 0; i < list->size - 1; i++) {
		list->elements[i] = list->elements[i+1];
	}

	// The list is shorter now
	--list->size;

	DEBUG(list->ctx, "%p: Popping network %p from stack\n", list, network);

	return network;
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
