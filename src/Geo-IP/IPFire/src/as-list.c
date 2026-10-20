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

#include <libloc/as.h>
#include <libloc/as-list.h>
#include <libloc/compat.h>
#include <libloc/private.h>

struct loc_as_list {
	struct loc_ctx* ctx;
	loc_refcount_t refcount;

	struct loc_as** elements;
	size_t elements_size;

	size_t size;

	// All AS numbers in the list in ascending order
	uint32_t* numbers;
};

static int loc_as_list_grow(struct loc_as_list* list) {
	size_t size = list->elements_size * 2;
	if (size < 1024)
		size = 1024;

	DEBUG(list->ctx, "Growing AS list %p by %zu to %zu\n",
		list, size, list->elements_size + size);

	struct loc_as** elements = reallocarray(list->elements,
			list->elements_size + size, sizeof(*list->elements));
	if (!elements)
		return -ENOMEM;

	list->elements = elements;

	uint32_t* numbers = reallocarray(list->numbers,
			list->elements_size + size, sizeof(*list->numbers));
	if (!numbers)
		return -ENOMEM;

	list->numbers = numbers;
	list->elements_size += size;

	return 0;
}

LOC_EXPORT int loc_as_list_new(struct loc_ctx* ctx,
		struct loc_as_list** list) {
	struct loc_as_list* l = calloc(1, sizeof(*l));
	if (!l)
		return -ENOMEM;

	l->ctx = loc_ref(ctx);
	l->refcount = 1;

	DEBUG(l->ctx, "AS list allocated at %p\n", l);
	*list = l;

	return 0;
}

LOC_EXPORT struct loc_as_list* loc_as_list_ref(struct loc_as_list* list) {
	loc_refcount_inc(&list->refcount);

	return list;
}

static void loc_as_list_free(struct loc_as_list* list) {
	DEBUG(list->ctx, "Releasing AS list at %p\n", list);

	loc_as_list_clear(list);

	loc_unref(list->ctx);
	free(list);
}

LOC_EXPORT struct loc_as_list* loc_as_list_unref(struct loc_as_list* list) {
	if (!list)
		return NULL;

	if (loc_refcount_dec(&list->refcount) > 0)
		return list;

	loc_as_list_free(list);
	return NULL;
}

LOC_EXPORT size_t loc_as_list_size(struct loc_as_list* list) {
	return list->size;
}

LOC_EXPORT int loc_as_list_empty(struct loc_as_list* list) {
	return list->size == 0;
}

LOC_EXPORT void loc_as_list_clear(struct loc_as_list* list) {
	if (!list->elements)
		return;

	for (unsigned int i = 0; i < list->size; i++)
		loc_as_unref(list->elements[i]);

	free(list->elements);
	list->elements = NULL;
	list->elements_size = 0;

	free(list->numbers);
	list->numbers = NULL;

	list->size = 0;
}

LOC_EXPORT struct loc_as* loc_as_list_get(struct loc_as_list* list, size_t index) {
	// Check index
	if (index >= list->size)
		return NULL;

	return loc_as_ref(list->elements[index]);
}

/*
	Returns the position of number in the sorted numbers, or where it would have to be
*/
static size_t loc_as_list_find(struct loc_as_list* list, uint32_t number) {
	size_t lo = 0;
	size_t hi = list->size;

	while (lo < hi) {
		size_t mid = lo + (hi - lo) / 2;

		if (list->numbers[mid] < number)
			lo = mid + 1;
		else
			hi = mid;
	}

	return lo;
}

static int loc_as_list_has_number(struct loc_as_list* list, uint32_t number, size_t* pos) {
	*pos = loc_as_list_find(list, number);

	return *pos < list->size && list->numbers[*pos] == number;
}

LOC_EXPORT int loc_as_list_append(
		struct loc_as_list* list, struct loc_as* as) {
	uint32_t number = loc_as_get_number(as);
	size_t pos;

	if (loc_as_list_has_number(list, number, &pos))
		return 0;

	// Check if we have space left
	if (list->size >= list->elements_size) {
		int r = loc_as_list_grow(list);
		if (r)
			return r;
	}

	DEBUG(list->ctx, "%p: Appending AS %p to list\n", list, as);

	// Insert the number where it belongs
	memmove(list->numbers + pos + 1, list->numbers + pos,
		(list->size - pos) * sizeof(*list->numbers));
	list->numbers[pos] = number;

	list->elements[list->size++] = loc_as_ref(as);

	return 0;
}

LOC_EXPORT int loc_as_list_contains(
		struct loc_as_list* list, struct loc_as* as) {
	return loc_as_list_contains_number(list, loc_as_get_number(as));
}

LOC_EXPORT int loc_as_list_contains_number(
		struct loc_as_list* list, uint32_t number) {
	size_t pos;

	return loc_as_list_has_number(list, number, &pos);
}

static int __loc_as_cmp(const void* as1, const void* as2) {
	return loc_as_cmp(*(struct loc_as**)as1, *(struct loc_as**)as2);
}

LOC_EXPORT void loc_as_list_sort(struct loc_as_list* list) {
	// There is nothing to sort in an empty list
	if (!list->size)
		return;

	// Sort everything
	qsort(list->elements, list->size, sizeof(*list->elements), __loc_as_cmp);
}
