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

#ifndef LIBLOC_COUNTRY_H
#define LIBLOC_COUNTRY_H

#include <libloc/libloc.h>
#include <libloc/format.h>
#include <libloc/stringpool.h>

struct loc_country;
int loc_country_new(struct loc_ctx* ctx, struct loc_country** country, const char* country_code);
struct loc_country* loc_country_ref(struct loc_country* country);
struct loc_country* loc_country_unref(struct loc_country* country);

const char* loc_country_get_code(struct loc_country* country);

const char* loc_country_get_continent_code(struct loc_country* country);
int loc_country_set_continent_code(struct loc_country* country, const char* continent_code);

const char* loc_country_get_name(struct loc_country* country);
int loc_country_set_name(struct loc_country* country, const char* name);

int loc_country_cmp(struct loc_country* country1, struct loc_country* country2);

int loc_country_code_is_valid(const char* cc);
int loc_country_special_code_to_flag(const char* cc);

#ifdef LIBLOC_PRIVATE

#include <string.h>

int loc_country_new_from_database_v1(struct loc_ctx* ctx, struct loc_stringpool* pool,
		struct loc_country** country, const struct loc_database_country_v1* dbobj);
int loc_country_to_database_v1(struct loc_country* country,
    struct loc_stringpool* pool, struct loc_database_country_v1* dbobj);

static inline void loc_country_code_copy(char* dst, const char* src) {
    for (unsigned int i = 0; i < 2; i++) {
        dst[i] = src[i];
    }
}

#endif

#endif
