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

#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#include <libloc/libloc.h>
#include <libloc/format.h>
#include <libloc/private.h>
#include <libloc/stringpool.h>

#define LOC_STRINGPOOL_BLOCK_SIZE	(512 * 1024)

struct loc_stringpool {
	struct loc_ctx* ctx;
	int refcount;

	// Reference to any mapped data
	const char* data;
	ssize_t length;

	// Reference to own storage
	char* blocks;
	size_t size;
};

static int loc_stringpool_grow(struct loc_stringpool* pool, const size_t size) {
	DEBUG(pool->ctx, "Growing string pool by %zu byte(s)\n", size);

	// Increment size
	pool->size += size;

	// Reallocate blocks
	pool->blocks = realloc(pool->blocks, pool->size);
	if (!pool->blocks) {
		ERROR(pool->ctx, "Could not grow string pool: %s\n", strerror(errno));
		return 1;
	}

	// Update data pointer
	pool->data = pool->blocks;

	return 0;
}

static off_t loc_stringpool_append(struct loc_stringpool* pool, const char* string) {
	if (!string) {
		errno = EINVAL;
		return -1;
	}

	DEBUG(pool->ctx, "Appending '%s' to string pool at %p\n", string, pool);

	// How much space to we need?
	const size_t length = strlen(string) + 1;

	// Make sure we have enough space
	if (pool->length + length > pool->size) {
		int r = loc_stringpool_grow(pool, LOC_STRINGPOOL_BLOCK_SIZE);
		if (r)
			return r;
	}

	off_t offset = pool->length;

	// Copy the string
	memcpy(pool->blocks + offset, string, length);

	// Update the length of the pool
	pool->length += length;

	return offset;
}

static void loc_stringpool_free(struct loc_stringpool* pool) {
	DEBUG(pool->ctx, "Releasing string pool %p\n", pool);

	// Free any data
	if (pool->blocks)
		free(pool->blocks);

	loc_unref(pool->ctx);
	free(pool);
}

int loc_stringpool_new(struct loc_ctx* ctx, struct loc_stringpool** pool) {
	struct loc_stringpool* p = calloc(1, sizeof(*p));
	if (!p)
		return 1;

	p->ctx = loc_ref(ctx);
	p->refcount = 1;

	*pool = p;

	return 0;
}

int loc_stringpool_open(struct loc_ctx* ctx, struct loc_stringpool** pool,
		const char* data, const size_t length) {
	struct loc_stringpool* p = NULL;

	// Allocate a new stringpool
	int r = loc_stringpool_new(ctx, &p);
	if (r)
		goto ERROR;

	// Store data and length
	p->data   = data;
	p->length = length;

	DEBUG(p->ctx, "Opened string pool at %p (%zu bytes)\n", p->data, p->length);

	*pool = p;
	return 0;

ERROR:
	if (p)
		loc_stringpool_free(p);

	return r;
}

struct loc_stringpool* loc_stringpool_ref(struct loc_stringpool* pool) {
	pool->refcount++;

	return pool;
}

struct loc_stringpool* loc_stringpool_unref(struct loc_stringpool* pool) {
	if (--pool->refcount > 0)
		return NULL;

	loc_stringpool_free(pool);

	return NULL;
}

const char* loc_stringpool_get(struct loc_stringpool* pool, off_t offset) {
	// Check boundaries
	if (offset < 0 || offset >= pool->length) {
		errno = ERANGE;
		return NULL;
	}

	// Return any data that we have in memory
	return pool->data + offset;
}

size_t loc_stringpool_get_size(struct loc_stringpool* pool) {
	return pool->length;
}

static off_t loc_stringpool_find(struct loc_stringpool* pool, const char* s) {
	if (!s || !*s) {
		errno = EINVAL;
		return -1;
	}

	off_t offset = 0;
	while (offset < pool->length) {
		const char* string = loc_stringpool_get(pool, offset);

		// Error!
		if (!string)
			return 1;

		// Is this a match?
		if (strcmp(s, string) == 0)
			return offset;

		// Shift offset
		offset += strlen(string) + 1;
	}

	// Nothing found
	errno = ENOENT;
	return -1;
}

off_t loc_stringpool_add(struct loc_stringpool* pool, const char* string) {
	off_t offset = loc_stringpool_find(pool, string);
	if (offset >= 0) {
		DEBUG(pool->ctx, "Found '%s' at position %jd\n", string, (intmax_t)offset);
		return offset;
	}

	return loc_stringpool_append(pool, string);
}

void loc_stringpool_dump(struct loc_stringpool* pool) {
	off_t offset = 0;

	while (offset < pool->length) {
		const char* string = loc_stringpool_get(pool, offset);
		if (!string)
			return;

		printf("%jd (%zu): %s\n", (intmax_t)offset, strlen(string), string);

		// Shift offset
		offset += strlen(string) + 1;
	}
}

size_t loc_stringpool_write(struct loc_stringpool* pool, FILE* f) {
	size_t size = loc_stringpool_get_size(pool);

	return fwrite(pool->data, sizeof(*pool->data), size, f);
}
