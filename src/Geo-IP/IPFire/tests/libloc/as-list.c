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

#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>

#include <libloc/libloc.h>
#include <libloc/as.h>
#include <libloc/as-list.h>

#define ASSERT(condition) \
	do { \
		if (!(condition)) { \
			fprintf(stderr, "%s:%d: Assertion failed: %s\n", __FILE__, __LINE__, #condition); \
			exit(EXIT_FAILURE); \
		} \
	} while (0)

static const uint32_t NUMBERS[] = { 64500, 64496, 4200000000, 64511, 1 };

static void append(struct loc_ctx* ctx, struct loc_as_list* list, uint32_t number) {
	struct loc_as* as = NULL;

	ASSERT(loc_as_new(ctx, &as, number) == 0);
	ASSERT(loc_as_list_append(list, as) == 0);

	loc_as_unref(as);
}

int main(int argc, char** argv) {
	struct loc_as_list* list = NULL;
	struct loc_ctx* ctx = NULL;
	struct loc_as* as = NULL;

	ASSERT(loc_new(&ctx) == 0);
	loc_set_log_priority(ctx, LOG_DEBUG);

	ASSERT(loc_as_list_new(ctx, &list) == 0);

	// A new list is empty
	ASSERT(loc_as_list_empty(list));
	ASSERT(loc_as_list_size(list) == 0);
	ASSERT(loc_as_list_get(list, 0) == NULL);
	ASSERT(loc_as_list_contains_number(list, 64496) == 0);

	// Sorting or clearing an empty list does nothing
	loc_as_list_sort(list);
	loc_as_list_clear(list);
	ASSERT(loc_as_list_empty(list));

	for (unsigned int i = 0; i < sizeof(NUMBERS) / sizeof(*NUMBERS); i++)
		append(ctx, list, NUMBERS[i]);

	ASSERT(!loc_as_list_empty(list));
	ASSERT(loc_as_list_size(list) == 5);

	// Adding an AS a second time does not change anything
	append(ctx, list, 64496);
	ASSERT(loc_as_list_size(list) == 5);

	// Everything we have added must be there
	for (unsigned int i = 0; i < sizeof(NUMBERS) / sizeof(*NUMBERS); i++)
		ASSERT(loc_as_list_contains_number(list, NUMBERS[i]) == 1);

	ASSERT(loc_as_list_contains_number(list, 64497) == 0);

	// The list keeps the order in which we have added the ASes
	as = loc_as_list_get(list, 0);
	ASSERT(as && loc_as_get_number(as) == 64500);
	loc_as_unref(as);

	// Out of range
	ASSERT(loc_as_list_get(list, 5) == NULL);

	// Sort the list
	loc_as_list_sort(list);

	uint32_t previous = 0;

	for (size_t i = 0; i < loc_as_list_size(list); i++) {
		as = loc_as_list_get(list, i);
		ASSERT(as);

		ASSERT(loc_as_get_number(as) > previous);
		previous = loc_as_get_number(as);

		loc_as_unref(as);
	}

	ASSERT(previous == 4200000000);

	// A second reference keeps the list alive
	struct loc_as_list* ref = loc_as_list_ref(list);
	ASSERT(ref == list);
	ASSERT(loc_as_list_unref(list) == list);

	// Grow the list beyond what it has allocated at first
	for (uint32_t number = 100000; number < 102000; number++)
		append(ctx, list, number);

	ASSERT(loc_as_list_size(list) == 2005);
	ASSERT(loc_as_list_contains_number(list, 101999) == 1);

	// Clearing removes everything
	loc_as_list_clear(list);
	ASSERT(loc_as_list_empty(list));
	ASSERT(loc_as_list_contains_number(list, 64496) == 0);

	// The list can be used again after it has been cleared
	append(ctx, list, 64496);
	ASSERT(loc_as_list_size(list) == 1);

	loc_as_list_clear(list);

	// Add every third number backwards, and then the ones in between forwards
	for (uint32_t number = 3000; number > 0; number -= 3)
		append(ctx, list, number);

	for (uint32_t number = 1; number <= 3000; number += 3)
		append(ctx, list, number);

	ASSERT(loc_as_list_size(list) == 2000);

	for (uint32_t number = 0; number <= 3001; number++)
		ASSERT(loc_as_list_contains_number(list, number) == (number % 3 != 2 && number && number <= 3000));

	// Adding them again does not change anything
	append(ctx, list, 3000);
	append(ctx, list, 1);
	ASSERT(loc_as_list_size(list) == 2000);

	// The list still keeps the order in which we have added the ASes
	as = loc_as_list_get(list, 0);
	ASSERT(as && loc_as_get_number(as) == 3000);
	loc_as_unref(as);

	as = loc_as_list_get(list, 1000);
	ASSERT(as && loc_as_get_number(as) == 1);
	loc_as_unref(as);

	// The highest and lowest numbers
	append(ctx, list, 0);
	append(ctx, list, 4294967295);
	ASSERT(loc_as_list_contains_number(list, 0) == 1);
	ASSERT(loc_as_list_contains_number(list, 4294967295) == 1);
	ASSERT(loc_as_list_contains_number(list, 4294967294) == 0);

	ASSERT(loc_as_list_unref(list) == NULL);

	loc_unref(ctx);

	return EXIT_SUCCESS;
}
