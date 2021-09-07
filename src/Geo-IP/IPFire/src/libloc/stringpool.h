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

#ifndef LIBLOC_STRINGPOOL_H
#define LIBLOC_STRINGPOOL_H

#ifdef LIBLOC_PRIVATE

#include <stddef.h>
#include <stdio.h>

#include <libloc/libloc.h>

struct loc_stringpool;
int loc_stringpool_new(struct loc_ctx* ctx, struct loc_stringpool** pool);
int loc_stringpool_open(struct loc_ctx* ctx, struct loc_stringpool** pool,
	FILE* f, size_t length, off_t offset);

struct loc_stringpool* loc_stringpool_ref(struct loc_stringpool* pool);
struct loc_stringpool* loc_stringpool_unref(struct loc_stringpool* pool);

const char* loc_stringpool_get(struct loc_stringpool* pool, off_t offset);
size_t loc_stringpool_get_size(struct loc_stringpool* pool);

off_t loc_stringpool_add(struct loc_stringpool* pool, const char* string);
void loc_stringpool_dump(struct loc_stringpool* pool);

size_t loc_stringpool_write(struct loc_stringpool* pool, FILE* f);

#endif
#endif
