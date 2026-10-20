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
#include <string.h>
#include <syslog.h>

#include <libloc/libloc.h>
#include <libloc/country.h>
#include <libloc/country-list.h>

#define ASSERT(condition) \
	do { \
		if (!(condition)) { \
			fprintf(stderr, "%s:%d: Assertion failed: %s\n", __FILE__, __LINE__, #condition); \
			exit(EXIT_FAILURE); \
		} \
	} while (0)

static const char* CODES[] = { "DE", "AT", "US", "CH", "FR", NULL };

static void append(struct loc_ctx* ctx, struct loc_country_list* list, const char* code) {
	struct loc_country* country = NULL;

	ASSERT(loc_country_new(ctx, &country, code) == 0);
	ASSERT(loc_country_list_append(list, country) == 0);

	loc_country_unref(country);
}

int main(int argc, char** argv) {
	struct loc_country_list* list = NULL;
	struct loc_country* country = NULL;
	struct loc_ctx* ctx = NULL;

	ASSERT(loc_new(&ctx) == 0);
	loc_set_log_priority(ctx, LOG_DEBUG);

	ASSERT(loc_country_list_new(ctx, &list) == 0);

	// A new list is empty
	ASSERT(loc_country_list_empty(list));
	ASSERT(loc_country_list_size(list) == 0);
	ASSERT(loc_country_list_get(list, 0) == NULL);
	ASSERT(loc_country_list_contains_code(list, "DE") == 0);

	// Sorting or clearing an empty list does nothing
	loc_country_list_sort(list);
	loc_country_list_clear(list);
	ASSERT(loc_country_list_empty(list));

	for (const char** code = CODES; *code; code++)
		append(ctx, list, *code);

	ASSERT(!loc_country_list_empty(list));
	ASSERT(loc_country_list_size(list) == 5);

	// Adding a country a second time does not change anything
	append(ctx, list, "DE");
	ASSERT(loc_country_list_size(list) == 5);

	// Everything we have added must be there
	for (const char** code = CODES; *code; code++)
		ASSERT(loc_country_list_contains_code(list, *code) == 1);

	ASSERT(loc_country_list_contains_code(list, "GB") == 0);

	// Invalid codes are never in a list
	ASSERT(loc_country_list_contains_code(list, "XYZ") == 0);
	ASSERT(loc_country_list_contains_code(list, "") == 0);

	// The list keeps the order in which we have added the countries
	country = loc_country_list_get(list, 0);
	ASSERT(country && strcmp(loc_country_get_code(country), "DE") == 0);
	loc_country_unref(country);

	// Out of range
	ASSERT(loc_country_list_get(list, 5) == NULL);

	// Sort the list
	loc_country_list_sort(list);

	const char* sorted[] = { "AT", "CH", "DE", "FR", "US" };

	for (size_t i = 0; i < loc_country_list_size(list); i++) {
		country = loc_country_list_get(list, i);
		ASSERT(country);

		ASSERT(strcmp(loc_country_get_code(country), sorted[i]) == 0);

		loc_country_unref(country);
	}

	// A second reference keeps the list alive
	struct loc_country_list* ref = loc_country_list_ref(list);
	ASSERT(ref == list);
	ASSERT(loc_country_list_unref(list) == list);

	// Clearing removes everything
	loc_country_list_clear(list);
	ASSERT(loc_country_list_empty(list));
	ASSERT(loc_country_list_contains_code(list, "DE") == 0);

	// The list can be used again after it has been cleared
	append(ctx, list, "DE");
	ASSERT(loc_country_list_size(list) == 1);

	loc_country_list_clear(list);

	// Add every other valid country code
	char code[3] = "AA";
	size_t size = 0;

	for (code[0] = 'A'; code[0] <= 'Z'; code[0]++) {
		for (code[1] = 'A'; code[1] <= 'Z'; code[1]++) {
			if (!loc_country_code_is_valid(code) || (code[0] + code[1]) % 2)
				continue;

			append(ctx, list, code);
			size++;
		}
	}

	ASSERT(loc_country_list_size(list) == size);

	// Only those must be in the list
	for (code[0] = 'A'; code[0] <= 'Z'; code[0]++) {
		for (code[1] = 'A'; code[1] <= 'Z'; code[1]++) {
			if (!loc_country_code_is_valid(code))
				ASSERT(loc_country_list_contains_code(list, code) == 0);
			else
				ASSERT(loc_country_list_contains_code(list, code) == !((code[0] + code[1]) % 2));
		}
	}

	// Lower case codes are never in a list
	ASSERT(loc_country_list_contains_code(list, "aa") == 0);

	ASSERT(loc_country_list_unref(list) == NULL);

	loc_unref(ctx);

	return EXIT_SUCCESS;
}
