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

#include <libloc/compat.h>
#include <libloc/country.h>
#include <libloc/country-list.h>
#include <libloc/private.h>

struct loc_country_list {
	struct loc_ctx* ctx;
	loc_refcount_t refcount;

	struct loc_country** elements;
	size_t elements_size;

	size_t size;

	// One bit for every country code that is in the list
	unsigned char codes[(26 * 26 + 7) / 8];
};

static unsigned int loc_country_list_code_index(const char* code) {
	return (code[0] - 'A') * 26 + (code[1] - 'A');
}

static void loc_country_list_set_code(struct loc_country_list* list, const char* code) {
	unsigned int i = loc_country_list_code_index(code);

	list->codes[i / 8] |= 1 << (i % 8);
}

static int loc_country_list_has_code(struct loc_country_list* list, const char* code) {
	unsigned int i = loc_country_list_code_index(code);

	return (list->codes[i / 8] >> (i % 8)) & 1;
}

static int loc_country_list_grow(struct loc_country_list* list) {
	size_t size = list->elements_size * 2;
	if (size < 1024)
		size = 1024;

	DEBUG(list->ctx, "Growing country list %p by %zu to %zu\n",
		list, size, list->elements_size + size);

	struct loc_country** elements = reallocarray(list->elements,
			list->elements_size + size, sizeof(*list->elements));
	if (!elements)
		return -ENOMEM;

	list->elements = elements;
	list->elements_size += size;

	return 0;
}

LOC_EXPORT int loc_country_list_new(struct loc_ctx* ctx,
		struct loc_country_list** list) {
	struct loc_country_list* l = calloc(1, sizeof(*l));
	if (!l)
		return -ENOMEM;

	l->ctx = loc_ref(ctx);
	l->refcount = 1;

	DEBUG(l->ctx, "Country list allocated at %p\n", l);
	*list = l;

	return 0;
}

LOC_EXPORT struct loc_country_list* loc_country_list_ref(struct loc_country_list* list) {
	loc_refcount_inc(&list->refcount);

	return list;
}

static void loc_country_list_free(struct loc_country_list* list) {
	DEBUG(list->ctx, "Releasing country list at %p\n", list);

	loc_country_list_clear(list);

	loc_unref(list->ctx);
	free(list);
}

LOC_EXPORT struct loc_country_list* loc_country_list_unref(struct loc_country_list* list) {
	if (loc_refcount_dec(&list->refcount) > 0)
		return list;

	loc_country_list_free(list);
	return NULL;
}

LOC_EXPORT size_t loc_country_list_size(struct loc_country_list* list) {
	return list->size;
}

LOC_EXPORT int loc_country_list_empty(struct loc_country_list* list) {
	return list->size == 0;
}

LOC_EXPORT void loc_country_list_clear(struct loc_country_list* list) {
	if (!list->elements)
		return;

	for (unsigned int i = 0; i < list->size; i++)
		loc_country_unref(list->elements[i]);

	free(list->elements);
	list->elements = NULL;
	list->elements_size = 0;

	list->size = 0;

	memset(list->codes, 0, sizeof(list->codes));
}

LOC_EXPORT struct loc_country* loc_country_list_get(struct loc_country_list* list, size_t index) {
	// Check index
	if (index >= list->size)
		return NULL;

	return loc_country_ref(list->elements[index]);
}

LOC_EXPORT int loc_country_list_append(
		struct loc_country_list* list, struct loc_country* country) {
	if (loc_country_list_contains(list, country))
		return 0;

	// Check if we have space left
	if (list->size >= list->elements_size) {
		int r = loc_country_list_grow(list);
		if (r)
			return r;
	}

	DEBUG(list->ctx, "%p: Appending country %p to list\n", list, country);

	list->elements[list->size++] = loc_country_ref(country);

	loc_country_list_set_code(list, loc_country_get_code(country));

	return 0;
}

LOC_EXPORT int loc_country_list_contains(
		struct loc_country_list* list, struct loc_country* country) {
	return loc_country_list_has_code(list, loc_country_get_code(country));
}

LOC_EXPORT int loc_country_list_contains_code(
		struct loc_country_list* list, const char* code) {
	// Invalid country codes would never match
	if (!loc_country_code_is_valid(code))
		return 0;

	return loc_country_list_has_code(list, code);
}

static int __loc_country_cmp(const void* country1, const void* country2) {
	return loc_country_cmp(*(struct loc_country**)country1, *(struct loc_country**)country2);
}

LOC_EXPORT void loc_country_list_sort(struct loc_country_list* list) {
	// There is nothing to sort in an empty list
	if (!list->size)
		return;

	// Sort everything
	qsort(list->elements, list->size, sizeof(*list->elements), __loc_country_cmp);
}
