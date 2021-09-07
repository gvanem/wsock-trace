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

#ifndef LIBLOC_AS_H
#define LIBLOC_AS_H

#include <stdint.h>

#include <libloc/libloc.h>
#include <libloc/format.h>
#include <libloc/stringpool.h>

struct loc_as;
int loc_as_new(struct loc_ctx* ctx, struct loc_as** as, uint32_t number);
struct loc_as* loc_as_ref(struct loc_as* as);
struct loc_as* loc_as_unref(struct loc_as* as);

uint32_t loc_as_get_number(struct loc_as* as);

const char* loc_as_get_name(struct loc_as* as);
int loc_as_set_name(struct loc_as* as, const char* name);

int loc_as_cmp(struct loc_as* as1, struct loc_as* as2);

#ifdef LIBLOC_PRIVATE

int loc_as_new_from_database_v1(struct loc_ctx* ctx, struct loc_stringpool* pool,
		struct loc_as** as, const struct loc_database_as_v1* dbobj);
int loc_as_to_database_v1(struct loc_as* as, struct loc_stringpool* pool,
		struct loc_database_as_v1* dbobj);

int loc_as_match_string(struct loc_as* as, const char* string);

#endif

#endif
