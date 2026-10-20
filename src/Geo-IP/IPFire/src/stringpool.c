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
	loc_refcount_t refcount;

	// Reference to any mapped data
	const char* data;
	ssize_t length;

	// Reference to own storage
	char* blocks;
	size_t size;

	// A hash table to find the strings that we have added. Slots hold the
	// offset of a string plus one, or zero if they are free.
	size_t* slots;
	size_t num_slots;
	size_t num_strings;
};

/*
	Makes sure that the pool can hold at least length bytes
*/
static int loc_stringpool_grow(struct loc_stringpool* pool, const size_t length) {
	// Nothing to do if we already have enough space
	if (length <= pool->size)
		return 0;

	// Allocate entire blocks
	const size_t blocks = (length + LOC_STRINGPOOL_BLOCK_SIZE - 1) / LOC_STRINGPOOL_BLOCK_SIZE;
	const size_t size = blocks * LOC_STRINGPOOL_BLOCK_SIZE;

	DEBUG(pool->ctx, "Growing string pool from %zu to %zu byte(s)\n", pool->size, size);

	// Reallocate blocks
	char* p = realloc(pool->blocks, size);
	if (!p) {
		ERROR(pool->ctx, "Could not grow string pool: %s\n", strerror(errno));
		return -ENOMEM;
	}

	// Update data pointer
	pool->blocks = p;
	pool->data   = p;
	pool->size   = size;

	return 0;
}

static off_t loc_stringpool_append(struct loc_stringpool* pool, const char* string) {
	int r;

	if (!string)
		return -EINVAL;

	DEBUG(pool->ctx, "Appending '%s' to string pool at %p\n", string, pool);

	// How much space to we need?
	const size_t length = strlen(string) + 1;

	// Make sure we have enough space, however long the string is
	r = loc_stringpool_grow(pool, pool->length + length);
	if (r < 0)
		return r;

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

	free(pool->slots);

	loc_unref(pool->ctx);
	free(pool);
}

int loc_stringpool_new(struct loc_ctx* ctx, struct loc_stringpool** pool) {
	struct loc_stringpool* p = calloc(1, sizeof(*p));
	if (!p)
		return -ENOMEM;

	p->ctx = loc_ref(ctx);
	p->refcount = 1;

	*pool = p;

	return 0;
}

int loc_stringpool_open(struct loc_ctx* ctx, struct loc_stringpool** pool,
		const char* data, const size_t length) {
	struct loc_stringpool* p = NULL;

	// The last string must be terminated or we would read past the end of the pool
	if (length && data[length - 1]) {
		ERROR(ctx, "The string pool is not terminated\n");
		return -EBADMSG;
	}

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
	loc_refcount_inc(&pool->refcount);

	return pool;
}

struct loc_stringpool* loc_stringpool_unref(struct loc_stringpool* pool) {
	if (loc_refcount_dec(&pool->refcount) > 0)
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

static size_t loc_stringpool_hash(const char* s) {
	size_t hash = 2166136261u;

	// FNV-1a
	for (const unsigned char* p = (const unsigned char*)s; *p; p++) {
		hash ^= *p;
		hash *= 16777619u;
	}

	return hash;
}

// Returns the slot that holds the string, or the free slot where it belongs
static size_t* loc_stringpool_slot(struct loc_stringpool* pool, const char* s) {
	size_t i = loc_stringpool_hash(s) & (pool->num_slots - 1);

	for (;;) {
		size_t* slot = &pool->slots[i];

		if (!*slot)
			return slot;

		if (strcmp(pool->data + *slot - 1, s) == 0)
			return slot;

		i = (i + 1) & (pool->num_slots - 1);
	}
}

static int loc_stringpool_grow_slots(struct loc_stringpool* pool) {
	size_t num_slots = 1024;

	if (pool->num_slots)
		num_slots = pool->num_slots * 2;

	size_t* slots = calloc(num_slots, sizeof(*slots));
	if (!slots)
		return -ENOMEM;

	size_t* old_slots = pool->slots;
	const size_t old_num_slots = pool->num_slots;

	pool->slots = slots;
	pool->num_slots = num_slots;

	// Put all strings into the new slots
	for (size_t i = 0; i < old_num_slots; i++) {
		if (old_slots[i])
			*loc_stringpool_slot(pool, pool->data + old_slots[i] - 1) = old_slots[i];
	}

	free(old_slots);

	return 0;
}

/*
	Adds a string, unless it is already in the pool, and returns its offset.

	Only strings that have been added can be found, so that this only works for
	pools that have been created with loc_stringpool_new().
*/
off_t loc_stringpool_add(struct loc_stringpool* pool, const char* string) {
	int r;

	if (!string)
		return -EINVAL;

	// Keep at least half of the slots free
	if (pool->num_strings * 2 >= pool->num_slots) {
		r = loc_stringpool_grow_slots(pool);
		if (r)
			return r;
	}

	size_t* slot = loc_stringpool_slot(pool, string);

	// We have this one already
	if (*slot) {
		DEBUG(pool->ctx, "Found '%s' at position %zu\n", string, *slot - 1);
		return *slot - 1;
	}

	off_t offset = loc_stringpool_append(pool, string);
	if (offset < 0)
		return offset;

	*slot = offset + 1;
	pool->num_strings++;

	return offset;
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
