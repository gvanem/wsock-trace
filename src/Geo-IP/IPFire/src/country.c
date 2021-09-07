/*
	libloc - A library to determine the location of someone on the Internet

	Copyright (C) 2019 IPFire Development Team <info@ipfire.org>

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

#include <libloc/libloc.h>
#include <libloc/compat.h>
#include <libloc/country.h>
#include <libloc/private.h>

struct loc_country {
	struct loc_ctx* ctx;
	int refcount;

	char* code;
	char* continent_code;

	char* name;
};

LOC_EXPORT int loc_country_new(struct loc_ctx* ctx, struct loc_country** country, const char* country_code) {
	// Check of the country code is valid
	if (!loc_country_code_is_valid(country_code)) {
		errno = EINVAL;
		return 1;
	}

	struct loc_country* c = calloc(1, sizeof(*c));
	if (!c)
		return -ENOMEM;

	c->ctx = loc_ref(ctx);
	c->refcount = 1;

	c->code = strdup(country_code);

	DEBUG(c->ctx, "Country %s allocated at %p\n", c->code, c);
	*country = c;

	return 0;
}

LOC_EXPORT struct loc_country* loc_country_ref(struct loc_country* country) {
	country->refcount++;

	return country;
}

static void loc_country_free(struct loc_country* country) {
	DEBUG(country->ctx, "Releasing country %s %p\n", country->code, country);

	if (country->code)
		free(country->code);

	if (country->continent_code)
		free(country->continent_code);

	if (country->name)
		free(country->name);

	loc_unref(country->ctx);
	free(country);
}

LOC_EXPORT struct loc_country* loc_country_unref(struct loc_country* country) {
	if (--country->refcount > 0)
		return NULL;

	loc_country_free(country);

	return NULL;
}

LOC_EXPORT const char* loc_country_get_code(struct loc_country* country) {
	return country->code;
}

LOC_EXPORT const char* loc_country_get_continent_code(struct loc_country* country) {
	return country->continent_code;
}

LOC_EXPORT int loc_country_set_continent_code(struct loc_country* country, const char* continent_code) {
	// XXX validate input

	// Free previous value
	if (country->continent_code)
		free(country->continent_code);

	country->continent_code = strdup(continent_code);

	return 0;
}

LOC_EXPORT const char* loc_country_get_name(struct loc_country* country) {
	return country->name;
}

LOC_EXPORT int loc_country_set_name(struct loc_country* country, const char* name) {
	if (country->name)
		free(country->name);

	if (name)
		country->name = strdup(name);

	return 0;
}

LOC_EXPORT int loc_country_cmp(struct loc_country* country1, struct loc_country* country2) {
	return strcmp(country1->code, country2->code);
}

int loc_country_new_from_database_v1(struct loc_ctx* ctx, struct loc_stringpool* pool,
		struct loc_country** country, const struct loc_database_country_v1* dbobj) {
	char buffer[3];

	// Read country code
	loc_country_code_copy(buffer, dbobj->code);

	// Terminate buffer
	buffer[2] = '\0';

	// Create a new country object
	int r = loc_country_new(ctx, country, buffer);
	if (r)
		return r;

	// Continent Code
	loc_country_code_copy(buffer, dbobj->continent_code);

	r = loc_country_set_continent_code(*country, buffer);
	if (r)
		goto FAIL;

	// Set name
	const char* name = loc_stringpool_get(pool, be32toh(dbobj->name));
	if (name) {
		r = loc_country_set_name(*country, name);
		if (r)
			goto FAIL;
	}

	return 0;

FAIL:
	loc_country_unref(*country);
	return r;
}

int loc_country_to_database_v1(struct loc_country* country,
		struct loc_stringpool* pool, struct loc_database_country_v1* dbobj) {
	// Add country code
	for (unsigned int i = 0; i < 2; i++) {
		dbobj->code[i] = country->code[i] ? country->code[i] : '\0';
	}

	// Add continent code
	if (country->continent_code) {
		for (unsigned int i = 0; i < 2; i++) {
			dbobj->continent_code[i] = country->continent_code[i] ? country->continent_code[i] : '\0';
		}
	}

	// Save the name string in the string pool
	off_t name = loc_stringpool_add(pool, country->name ? country->name : "");
	dbobj->name = htobe32(name);

	return 0;
}

LOC_EXPORT int loc_country_code_is_valid(const char* cc) {
	// It cannot be NULL
	if (!cc || !*cc)
		return 0;

	// It must be 2 characters long
	if (strlen(cc) != 2)
		return 0;

	// It must only contain A-Z
	for (unsigned int i = 0; i < 2; i++) {
		if (cc[i] < 'A' || cc[i] > 'Z')
			return 0;
	}

	// Looks valid
	return 1;
}
