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

#ifndef LIBLOC_COUNTRY_LIST_H
#define LIBLOC_COUNTRY_LIST_H

#include <stdlib.h>

#include <libloc/libloc.h>
#include <libloc/country.h>

struct loc_country_list;

int loc_country_list_new(struct loc_ctx* ctx, struct loc_country_list** list);
struct loc_country_list* loc_country_list_ref(struct loc_country_list* list);
struct loc_country_list* loc_country_list_unref(struct loc_country_list* list);

size_t loc_country_list_size(struct loc_country_list* list);
int loc_country_list_empty(struct loc_country_list* list);
void loc_country_list_clear(struct loc_country_list* list);

struct loc_country* loc_country_list_get(struct loc_country_list* list, size_t index);
int loc_country_list_append(struct loc_country_list* list, struct loc_country* country);

int loc_country_list_contains(
	struct loc_country_list* list, struct loc_country* country);
int loc_country_list_contains_code(
	struct loc_country_list* list, const char* code);

void loc_country_list_sort(struct loc_country_list* list);

#endif
