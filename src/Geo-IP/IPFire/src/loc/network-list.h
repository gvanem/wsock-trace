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

#ifndef LIBLOC_NETWORK_LIST_H
#define LIBLOC_NETWORK_LIST_H

#include <loc/network.h>

struct loc_network_list;
int loc_network_list_new(struct loc_ctx* ctx, struct loc_network_list** list);
struct loc_network_list* loc_network_list_ref(struct loc_network_list* list);
struct loc_network_list* loc_network_list_unref(struct loc_network_list* list);
size_t loc_network_list_size(struct loc_network_list* list);
int loc_network_list_empty(struct loc_network_list* list);
void loc_network_list_clear(struct loc_network_list* list);
void loc_network_list_dump(struct loc_network_list* list);
struct loc_network* loc_network_list_get(struct loc_network_list* list, size_t index);
int loc_network_list_push(struct loc_network_list* list, struct loc_network* network);
struct loc_network* loc_network_list_pop(struct loc_network_list* list);
struct loc_network* loc_network_list_pop_first(struct loc_network_list* list);
int loc_network_list_contains(struct loc_network_list* list, struct loc_network* network);
int loc_network_list_merge(struct loc_network_list* self, struct loc_network_list* other);

#endif
