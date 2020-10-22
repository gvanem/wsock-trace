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

#include <loc/libloc.h>
#include <loc/format.h>
#include <loc/private.h>
#include <loc/stringpool.h>

enum loc_stringpool_mode {
	STRINGPOOL_DEFAULT,
	STRINGPOOL_MMAP,
};

struct loc_stringpool {
	struct loc_ctx* ctx;
	int refcount;

	enum loc_stringpool_mode mode;

	char* data;
	ssize_t length;

	char* pos;
};

static off_t loc_stringpool_get_offset(struct loc_stringpool* pool, const char* pos) {
	if (pos < pool->data)
		return -EFAULT;

	if (pos > (pool->data + pool->length))
		return -EFAULT;

	return pos - pool->data;
}

static char* __loc_stringpool_get(struct loc_stringpool* pool, off_t offset) {
	if (offset < 0 || offset >= pool->length)
		return NULL;

	return pool->data + offset;
}

static int loc_stringpool_grow(struct loc_stringpool* pool, size_t length) {
	DEBUG(pool->ctx, "Growing string pool to %zu bytes\n", length);

	// Save pos pointer
	off_t pos = loc_stringpool_get_offset(pool, pool->pos);

	// Reallocate data section
	pool->data = realloc(pool->data, length);
	if (!pool->data)
		return -ENOMEM;

	pool->length = length;

	// Restore pos
	pool->pos = __loc_stringpool_get(pool, pos);

	return 0;
}

static off_t loc_stringpool_append(struct loc_stringpool* pool, const char* string) {
	if (!string || !*string)
		return -EINVAL;

	DEBUG(pool->ctx, "Appending '%s' to string pool at %p\n", string, pool);

	// Make sure we have enough space
	int r = loc_stringpool_grow(pool, pool->length + strlen(string) + 1);
	if (r) {
		errno = r;
		return -1;
	}

	off_t offset = loc_stringpool_get_offset(pool, pool->pos);

	// Copy string byte by byte
	while (*string)
		*pool->pos++ = *string++;

	// Terminate the string
	*pool->pos++ = '\0';

	return offset;
}

static int __loc_stringpool_new(struct loc_ctx* ctx, struct loc_stringpool** pool, enum loc_stringpool_mode mode) {
	struct loc_stringpool* p = calloc(1, sizeof(*p));
	if (!p)
		return -ENOMEM;

	p->ctx = loc_ref(ctx);
	p->refcount = 1;

	// Save mode
	p->mode = mode;

	*pool = p;

	return 0;
}

LOC_EXPORT int loc_stringpool_new(struct loc_ctx* ctx, struct loc_stringpool** pool) {
	int r = __loc_stringpool_new(ctx, pool, STRINGPOOL_DEFAULT);
	if (r)
		return r;

	// Add an empty string to new string pools
	loc_stringpool_append(*pool, "");

	return r;
}

static int loc_stringpool_mmap(struct loc_stringpool* pool, FILE* f, size_t length, off_t offset) {
	if (pool->mode != STRINGPOOL_MMAP)
		return -EINVAL;

	DEBUG(pool->ctx, "Reading string pool starting from %jd (%zu bytes)\n", (intmax_t)offset, length);

	// Map file content into memory
	pool->data = pool->pos = mmap(NULL, length, PROT_READ,
		MAP_PRIVATE, fileno(f), offset);

	// Store size of section
	pool->length = length;

	if (pool->data == MAP_FAILED)
		return -errno;

	return 0;
}

LOC_EXPORT int loc_stringpool_open(struct loc_ctx* ctx, struct loc_stringpool** pool,
		FILE* f, size_t length, off_t offset) {
	int r = __loc_stringpool_new(ctx, pool, STRINGPOOL_MMAP);
	if (r)
		return r;

	// Map data into memory
	if (length > 0) {
		r = loc_stringpool_mmap(*pool, f, length, offset);
		if (r)
			return r;
	}

	return 0;
}

LOC_EXPORT struct loc_stringpool* loc_stringpool_ref(struct loc_stringpool* pool) {
	pool->refcount++;

	return pool;
}

static void loc_stringpool_free(struct loc_stringpool* pool) {
	DEBUG(pool->ctx, "Releasing string pool %p\n", pool);
	int r;

	switch (pool->mode) {
		case STRINGPOOL_DEFAULT:
			if (pool->data)
				free(pool->data);
			break;

		case STRINGPOOL_MMAP:
			if (pool->data) {
				r = munmap(pool->data, pool->length);
				if (r)
					ERROR(pool->ctx, "Could not unmap data at %p: %s\n",
						pool->data, strerror(errno));
			}
			break;
	}

	loc_unref(pool->ctx);
	free(pool);
}

LOC_EXPORT struct loc_stringpool* loc_stringpool_unref(struct loc_stringpool* pool) {
	if (--pool->refcount > 0)
		return NULL;

	loc_stringpool_free(pool);

	return NULL;
}

static off_t loc_stringpool_get_next_offset(struct loc_stringpool* pool, off_t offset) {
	const char* string = loc_stringpool_get(pool, offset);

	return offset + strlen(string) + 1;
}

LOC_EXPORT const char* loc_stringpool_get(struct loc_stringpool* pool, off_t offset) {
	return __loc_stringpool_get(pool, offset);
}

LOC_EXPORT size_t loc_stringpool_get_size(struct loc_stringpool* pool) {
	return loc_stringpool_get_offset(pool, pool->pos);
}

static off_t loc_stringpool_find(struct loc_stringpool* pool, const char* s) {
	if (!s || !*s)
		return -EINVAL;

	off_t offset = 0;
	while (offset < pool->length) {
		const char* string = loc_stringpool_get(pool, offset);
		if (!string)
			break;

		int r = strcmp(s, string);
		if (r == 0)
			return offset;

		offset = loc_stringpool_get_next_offset(pool, offset);
	}

	return -ENOENT;
}

LOC_EXPORT off_t loc_stringpool_add(struct loc_stringpool* pool, const char* string) {
	off_t offset = loc_stringpool_find(pool, string);
	if (offset >= 0) {
		DEBUG(pool->ctx, "Found '%s' at position %jd\n", string, (intmax_t)offset);
		return offset;
	}

	return loc_stringpool_append(pool, string);
}

LOC_EXPORT void loc_stringpool_dump(struct loc_stringpool* pool) {
	off_t offset = 0;

	while (offset < pool->length) {
		const char* string = loc_stringpool_get(pool, offset);
		if (!string)
			break;

		printf("%jd (%zu): %s\n", (intmax_t)offset, strlen(string), string);

		offset = loc_stringpool_get_next_offset(pool, offset);
	}
	fflush(stdout);
}

LOC_EXPORT size_t loc_stringpool_write(struct loc_stringpool* pool, FILE* f) {
	size_t size = loc_stringpool_get_size(pool);

	return fwrite(pool->data, sizeof(*pool->data), size, f);
}
