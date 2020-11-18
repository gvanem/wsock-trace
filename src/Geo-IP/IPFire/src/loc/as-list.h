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

#ifndef LIBLOC_AS_LIST_H
#define LIBLOC_AS_LIST_H

#include <loc/as.h>
#include <loc/libloc.h>

struct loc_as_list;

int loc_as_list_new(struct loc_ctx* ctx, struct loc_as_list** list);
struct loc_as_list* loc_as_list_ref(struct loc_as_list* list);
struct loc_as_list* loc_as_list_unref(struct loc_as_list* list);

size_t loc_as_list_size(struct loc_as_list* list);
int loc_as_list_empty(struct loc_as_list* list);
void loc_as_list_clear(struct loc_as_list* list);

struct loc_as* loc_as_list_get(struct loc_as_list* list, size_t index);
int loc_as_list_append(struct loc_as_list* list, struct loc_as* as);

int loc_as_list_contains(
	struct loc_as_list* list, struct loc_as* as);
int loc_as_list_contains_number(
	struct loc_as_list* list, uint32_t number);

#endif
