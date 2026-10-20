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

#include <ctype.h>
#include <errno.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#ifdef HAVE_ENDIAN_H
#  include <endian.h>
#endif

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>

#include <libloc/libloc.h>
#include <libloc/address.h>
#include <libloc/as.h>
#include <libloc/as-list.h>
#include <libloc/compat.h>
#include <libloc/country.h>
#include <libloc/country-list.h>
#include <libloc/database.h>
#include <libloc/format.h>
#include <libloc/network.h>
#include <libloc/network-list.h>
#include <libloc/private.h>
#include <libloc/stringpool.h>

/*
 * Hacks around fopen() mode and the difference in
 * 'struct stat' on Windows and Linux.
 */
#ifdef _WIN32
  #define FOPEN_MODE          "rb"  // always open in binary mode
  #define MTIME_EQ(st1, st2)  ((st1).st_mtime == (st2).st_mtime)

  #ifndef S_ISREG
  #define S_ISREG(mode) (((mode) & S_IFMT) == S_IFREG)
  #endif

  #ifndef S_IWOTH
  #define S_IWOTH  0
  #endif
#else
  #define FOPEN_MODE          "re"  // set the FD_CLOEXEC flag on the underlying file descriptor.
  #define MTIME_EQ(st1, st2)  ((st1).st_mtim.tv_sec  == (st2).st_mtim.tv_sec) && \
                               (st1).st_mtim.tv_nsec == (st2).st_mtim.tv_nsec)
#endif

struct loc_database_file;

typedef int (*loc_database_match_as)
	(struct loc_database_file* db, uint32_t number, off_t i);
typedef int (*loc_database_match_country)
	(struct loc_database_file* db, const char* code, off_t i);

struct loc_database_objects {
	char* data;
	size_t length;
	size_t count;
};

struct loc_database_signature {
	const char* data;
	size_t length;
};

/*
	Looking up an address takes less than a microsecond and there are
	applications which do this from lots of threads at the same time. We need
	to know when nobody is reading from a file any more before we can unmap it,
	but if every lookup changed one counter, all of those threads would be
	waiting for each other to write to the same piece of memory, which costs
	more than the lookup itself.

	So there are many counters, far enough from each other that they are not
	sharing a cache line, and every thread uses the one that its ID points to.
	More than one thread may end up with the same counter, which is slower,
	but not wrong.
*/
// How often we check if a database has been replaced (in seconds)
#define LOC_DATABASE_RELOAD_INTERVAL	300

// There are 2^6 of them, see loc_database_acquire()
#define LOC_DATABASE_FILE_USERS		64

struct loc_database_file_users {
	atomic_ulong counter;
} __attribute__((aligned(64)));

/*
	Everything that we have read from one database file.

	This is separate from the database itself, so that the file can be replaced
	by another one while the database is being used.
*/
struct loc_database_file {
	struct loc_ctx* ctx;

	// References of whoever keeps the file for longer:
	// the database for as long as this is its file, and enumerators
	loc_refcount_t refcount;

	// Those who are in the middle of reading something from the file
	struct loc_database_file_users users[LOC_DATABASE_FILE_USERS];

	// Set once the file has been unmapped and closed
	atomic_flag released;

	// All files of a database are in a list
	struct loc_database_file* next;

	// What the file was when we opened it, to tell whether it has been replaced
	struct stat st;

	FILE* f;

	enum loc_database_version version;
	time_t created_at;

	// These are copies, so that whoever has asked for them
	// can use them for longer than the file is mapped.
	char* vendor;
	char* description;
	char* license;

	// Signatures
	struct loc_database_signature signature1;
	struct loc_database_signature signature2;

	// Data mapped into memory
	char* data;
	size_t length;

	struct loc_stringpool* pool;

	// Root for the IPv4 subtree for faster IPv4 search
	off_t rootv4;

	// ASes in the database
	struct loc_database_objects as_objects;

	// Network tree
	struct loc_database_objects network_node_objects;

	// Networks
	struct loc_database_objects network_objects;

	// Countries
	struct loc_database_objects country_objects;

	struct loc_database_callbacks {
		loc_database_match_as match_as;
		loc_database_match_country match_country;
	} callbacks;
};

// Every node that we have visited stays on the stack together with the node
// on the other side until we are done with everything below it.
struct loc_database {
	struct loc_ctx* ctx;
	loc_refcount_t refcount;

	// What we have read from the file. Never use this directly,
	// but call loc_database_acquire() and loc_database_release().
	_Atomic(struct loc_database_file*) file;

	// All files that we ever had. They are only being unmapped when we
	// replace them, and remain in this list until the database is freed.
	struct loc_database_file* files;

	// Where the database is, if we have opened it ourselves
	char* path;

	// Only one thread can replace the file at a time
	pthread_mutex_t lock;

	// How often we check if there is a new file (in seconds, zero for never),
	// and when we are going to do that the next time
	atomic_uint reload_interval;
	atomic_long next_reload;
};

#define MAX_STACK_DEPTH (2 * LOC_ADDRESS_MAX_BITS + 2)

struct loc_node_stack {
	off_t offset;
	int i; // Is this node 0 or 1?
	int depth;
};

struct loc_database_enumerator {
	struct loc_ctx* ctx;
	enum loc_database_enumerator_mode mode;
	loc_refcount_t refcount;

	// The database, and the file that it had when we were created
	struct loc_database* database;
	struct loc_database_file* db;

	// Search string
	char* string;
	struct loc_country_list* countries;
	struct loc_as_list* asns;
	enum loc_network_flags flags;
	int family;

	// Flatten output?
	int flatten;

	// Index of the AS we are looking at
	unsigned int as_index;

	// Index of the country we are looking at
	unsigned int country_index;

	// Network state
	struct in6_addr network_address;
	struct loc_node_stack network_stack[MAX_STACK_DEPTH];
	int network_stack_depth;
	uint64_t* networks_visited;

	// For subnet search and bogons
	struct loc_network_list* stack;
	struct loc_network_list* subnets;

	// For bogons
	struct in6_addr gap6_start;
	struct in6_addr gap4_start;
};

/*
	Checks if it is safe to read the buffer of size length starting at p.
*/
#define loc_database_check_boundaries(db, p) \
	__loc_database_check_boundaries(db, (const char*)p, sizeof(*p))

static inline int __loc_database_check_boundaries(struct loc_database_file* db,
		const char* p, const size_t length) {
	ssize_t offset = p - db->data;

	// Return if everything is within the boundary
	if ((likely(offset >= 0 && offset <= (ssize_t)(db->length - length))))
		return 0;

	DEBUG(db->ctx, "Database read check failed at %p for %zu byte(s)\n", p, length);
	DEBUG(db->ctx, "  p      = %p (offset = %zd, length = %zu)\n", p, offset, length);
	DEBUG(db->ctx, "  data   = %p (length = %zu)\n", db->data, db->length);
	DEBUG(db->ctx, "  end    = %p\n", db->data + db->length);
	DEBUG(db->ctx, "  overflow of %zd byte(s)\n", (ssize_t)(offset + length - db->length));

	// Otherwise raise EFAULT
	return -EFAULT;
}

/*
	Checks if a section which starts at offset is part of the database.

	The header only gives us offsets. They are being checked as numbers before
	they become pointers, as adding a large offset to where the database has
	been mapped ends up somewhere before it on 32 bit architectures.
*/
static int loc_database_check_section(struct loc_database_file* db,
		const off_t offset, const size_t length) {
	// The section must start in the database...
	if (offset < 0 || (uintmax_t)offset > db->length)
		return -EFAULT;

	// ... and it must end there
	if (length > db->length - (size_t)offset)
		return -EFAULT;

	return 0;
}

/*
	Returns a pointer to the n-th object
*/
static inline char* loc_database_object(struct loc_database_file* db,
		const struct loc_database_objects* objects, const size_t length, const off_t n) {
	int r;

	// Calculate offset
	const off_t offset = n * length;

	// Return a pointer to where the object lies
	char* object = objects->data + offset;

	// Check if the object is part of the memory
	r = __loc_database_check_boundaries(db, object, length);
	if (r < 0)
		return NULL;

	return object;
}

static int loc_database_version_supported(struct loc_database_file* db, uint8_t version) {
	switch (version) {
		// Supported versions
		case LOC_DATABASE_VERSION_1:
			return 0;

		default:
			ERROR(db->ctx, "Database version %d is not supported\n", version);
			return -ENOTSUP;
	}
}

static int loc_database_check_magic(struct loc_database_file* db) {
	const struct loc_database_magic* magic = NULL;
	int r;

	// Check if the database has been opened
	if (!db->data || !db->length) {
		ERROR(db->ctx, "The database has not been opened\n");
		return -ENOTSUP;
	}

	// The magic starts at the beginning of the database
	magic = (struct loc_database_magic*)db->data;

	// Check if we have enough data
	r = loc_database_check_boundaries(db, magic);
	if (r < 0) {
		ERROR(db->ctx, "Could not read enough data to validate magic bytes: %s\n",
			strerror(-r));
		DEBUG(db->ctx, "Read %zu bytes, but needed %zu\n", db->length, sizeof(*magic));
		return r;
	}

	// Compare magic bytes
	if (memcmp(magic->magic, LOC_DATABASE_MAGIC, sizeof(magic->magic)) == 0) {
		DEBUG(db->ctx, "Magic value matches\n");

		// Do we support this version?
		r = loc_database_version_supported(db, magic->version);
		if (r < 0)
			return r;

		// Parse version
		db->version = magic->version;

		return 0;
	}

	ERROR(db->ctx, "Unrecognized file type\n");
	return -ENOMSG;
}

/*
	Maps the entire database into memory
*/
static int loc_database_mmap(struct loc_database_file* db) {
	struct stat stat = { 0 };
	int fd = -EBADF;
	int r;

	// We must have a file
	if (!db->f)
		return -EBADF;

	// Get file descriptor
	fd = fileno(db->f);
	if (fd < 0) {
		ERROR(db->ctx, "Failed to fetch the file descriptor: %s\n", strerror(-errno));
		return -errno;
	}

	// Stat the database
	r = fstat(fd, &stat);
	if (r < 0) {
		ERROR(db->ctx, "Failed to stat the database: %s\n", strerror(-errno));
		return -errno;
	}

	// Remember which file this is
	db->st = stat;

	// Determine the length of the database
	db->length = stat.st_size;
	if (!db->length) {
		ERROR(db->ctx, "The database is empty\n");
		return -ENODATA;
	}

	// Map all data
	db->data = mmap(NULL, db->length, PROT_READ, MAP_SHARED, fd, 0);
	if (db->data == MAP_FAILED) {
		r = -errno;

		ERROR(db->ctx, "Could not map the database: %s\n", strerror(-errno));
		db->data = NULL;

		return r;
	}

	DEBUG(db->ctx, "Mapped database of %zu byte(s) at %p\n", db->length, db->data);

	// We don't tell the system that we are going to read randomly. That would
	// stop it from reading ahead, so that every page that is not in the page
	// cache would have to be read from disk on its own.

	return 0;
}

/*
	Maps arbitrary objects from the database into memory.
*/
static int loc_database_map_objects(struct loc_database_file* db, struct loc_database_objects* objects,
		const size_t size, const off_t offset, const size_t length) {
	int r;

	// Check if all objects are part of the mapped area
	r = loc_database_check_section(db, offset, length);
	if (r < 0) {
		ERROR(db->ctx, "Objects at %jd (%zu byte(s)) are not part of the database\n",
			(intmax_t)offset, length);
		return r;
	}

	// Store parameters
	objects->data   = db->data + offset;
	objects->length = length;
	objects->count  = objects->length / size;

	return 0;
}

static int loc_database_read_signature(int ver, struct loc_database_file* db,
		struct loc_database_signature* signature, const char* data, const size_t length) {
	// Check for a plausible signature length
	if (length > LOC_SIGNATURE_MAX_LENGTH) {
		ERROR(db->ctx, "Signature v%d too long: %zu\n", ver, length);
		return -EMSGSIZE;
	}

	// Store data & length
	signature->data = data;
	signature->length = length;

	DEBUG(db->ctx, "Read signature v%d of %zu byte(s) at %p\n",
		ver, signature->length, signature->data);

	hexdump(db->ctx, signature->data, signature->length);

	return 0;
}

/*
	Copies a string from the pool. If there is no such
	string, we don't have one either, which is not an error.
*/
static int loc_database_file_copy_string(struct loc_database_file* db,
		char** string, const off_t offset) {
	const char* s = loc_stringpool_get(db->pool, offset);

	if (s) {
		*string = strdup(s);
		if (!*string)
			return -ENOMEM;
	}

	return 0;
}

static int loc_database_read_header_v1(struct loc_database_file* db) {
	const struct loc_database_header_v1* header =
		(const struct loc_database_header_v1*)(db->data + LOC_DATABASE_MAGIC_SIZE);
	int r;

	DEBUG(db->ctx, "Reading header at %p\n", header);

	// Check if we can read the header
	r = loc_database_check_boundaries(db, header);
	if (r < 0) {
		ERROR(db->ctx, "Could not read enough data for header: %s\n", strerror(-r));
		return r;
	}

	// Dump the entire header
	hexdump(db->ctx, header, sizeof(*header));

	// Copy over data
	db->created_at  = be64toh(header->created_at);

	// Read signatures
	r = loc_database_read_signature(1, db, &db->signature1,
		header->signature1, be16toh(header->signature1_length));
	if (r)
		return r;

	r = loc_database_read_signature(2, db, &db->signature2,
		header->signature2, be16toh(header->signature2_length));
	if (r)
		return r;

	const off_t stringpool_offset = be32toh(header->pool_offset);
	size_t stringpool_length = be32toh(header->pool_length);

	// Check if the stringpool is part of the mapped area
	r = loc_database_check_section(db, stringpool_offset, stringpool_length);
	if (r < 0)
		return r;

	const char* stringpool_start = db->data + stringpool_offset;

	// Open the stringpool
	r = loc_stringpool_open(db->ctx, &db->pool, stringpool_start, stringpool_length);
	if (r)
		return r;

	// Copy the strings that describe the database
	r = loc_database_file_copy_string(db, &db->vendor, be32toh(header->vendor));
	if (r < 0)
		return r;

	r = loc_database_file_copy_string(db, &db->description, be32toh(header->description));
	if (r < 0)
		return r;

	r = loc_database_file_copy_string(db, &db->license, be32toh(header->license));
	if (r < 0)
		return r;

	// Map AS objects
	r = loc_database_map_objects(db, &db->as_objects,
		sizeof(struct loc_database_as_v1),
		be32toh(header->as_offset),
		be32toh(header->as_length));
	if (r)
		return r;

	// Map Network Nodes
	r = loc_database_map_objects(db, &db->network_node_objects,
		sizeof(struct loc_database_network_node_v1),
		be32toh(header->network_tree_offset),
		be32toh(header->network_tree_length));
	if (r)
		return r;

	// Map Networks
	r = loc_database_map_objects(db, &db->network_objects,
		sizeof(struct loc_database_network_v1),
		be32toh(header->network_data_offset),
		be32toh(header->network_data_length));
	if (r)
		return r;

	// Map countries
	r = loc_database_map_objects(db, &db->country_objects,
		sizeof(struct loc_database_country_v1),
		be32toh(header->countries_offset),
		be32toh(header->countries_length));
	if (r)
		return r;

	// The tree always has a root
	if (!db->network_node_objects.count) {
		ERROR(db->ctx, "The database does not have a network tree\n");
		return -EBADMSG;
	}

	return 0;
}

static int loc_database_read_header(struct loc_database_file* db) {
	DEBUG(db->ctx, "Database version is %u\n", db->version);

	switch (db->version) {
		case LOC_DATABASE_VERSION_1:
			return loc_database_read_header_v1(db);

		default:
			ERROR(db->ctx, "Incompatible database version: %u\n", db->version);
			return -ENOTSUP;
	}
}

static int loc_database_clone_handle(struct loc_database_file* db, FILE* f) {
	int r;

	// Fetch the FD of the original handle
	int fd = fileno(f);
	if (fd < 0) {
		ERROR(db->ctx, "Could not fetch the file descriptor: %s\n", strerror(-errno));
		return -errno;
	}

	// Clone file descriptor
	fd = dup(fd);
	if (fd < 0) {
		ERROR(db->ctx, "Could not duplicate file descriptor: %s\n", strerror(-errno));
		return -errno;
	}

	// Reopen the file so that we can keep our own file handle
	db->f = fdopen(fd, "rb");
	if (!db->f) {
		r = -errno;

		ERROR(db->ctx, "Could not re-open database file: %s\n", strerror(-errno));
		close(fd);

		return r;
	}

	return 0;
}

static int loc_database_match_as_v1(struct loc_database_file* db, uint32_t number, off_t i) {
	struct loc_database_as_v1* as_v1 = (struct loc_database_as_v1*)loc_database_object(db,
		&db->as_objects, sizeof(*as_v1), i);

	// All objects have been checked to be in the database when it was opened.
	// Should one of them be missing anyways, the search ends without a result.
	if (unlikely(!as_v1))
		return 1;

	const uint32_t n = be32toh(as_v1->number);

	// The difference of the two does not fit into an integer
	if (n > number)
		return 1;
	else if (n < number)
		return -1;

	return 0;
}

static int loc_database_match_country_v1(struct loc_database_file* db, const char* code, off_t i) {
	struct loc_database_country_v1* country_v1 = \
		(struct loc_database_country_v1*)loc_database_object(db, &db->country_objects, sizeof(*country_v1), i);

	// See loc_database_match_as_v1()
	if (unlikely(!country_v1))
		return 1;

	return loc_country_code_cmp(country_v1->code, code);
}

// IPv4 addresses are mapped into ::ffff:0:0/96
#define LOC_DATABASE_ROOTV4_LEVEL		96

/*
	Finds the node where all IPv4 addresses are, so that we don't have to walk
	down to there for every single one that we look up.

	This used to happen during the first lookup, but the database is being shared
	between threads and so nothing must change in it once it has been opened.
*/
static int loc_database_find_rootv4(struct loc_database_file* db) {
	const struct loc_database_network_node_v1* node_v1 = NULL;
	struct in6_addr address;
	off_t node_index = 0;

	// Start with 0.0.0.0
	loc_address_reset(&address, AF_INET);

	for (unsigned int level = 0; level < LOC_DATABASE_ROOTV4_LEVEL; level++) {
		node_v1 = (const struct loc_database_network_node_v1*)loc_database_object(db,
			&db->network_node_objects, sizeof(*node_v1), node_index);
		if (!node_v1)
			return -EFAULT;

		// Follow the path
		if (loc_address_get_bit(&address, level))
			node_index = be32toh(node_v1->one);
		else
			node_index = be32toh(node_v1->zero);

		// The tree ends here, so there are no IPv4 addresses in this database
		if (!node_index)
			return 0;

		// Check boundaries
		if ((size_t)node_index >= db->network_node_objects.count)
			return -ERANGE;
	}

	DEBUG(db->ctx, "IPv4 addresses start at node %jd\n", (intmax_t)node_index);

	db->rootv4 = node_index;

	return 0;
}

static int loc_database_file_open(struct loc_database_file* db, FILE* f) {
	int r;

	clock_t start = clock();

	// Clone the file handle
	r = loc_database_clone_handle(db, f);
	if (r)
		return r;

	// Map the database into memory
	r = loc_database_mmap(db);
	if (r)
		return r;

	// Read magic bytes
	r = loc_database_check_magic(db);
	if (r)
		return r;

	// Set the callbacks
	switch (db->version) {
		case LOC_DATABASE_VERSION_1:
			db->callbacks.match_as      = loc_database_match_as_v1;
			db->callbacks.match_country = loc_database_match_country_v1;
			break;

		default:
			return -ENOTSUP;
	}

	// Read the header
	r = loc_database_read_header(db);
	if (r)
		return r;

	// Find where the IPv4 addresses are
	r = loc_database_find_rootv4(db);
	if (r)
		return r;

	clock_t end = clock();

	INFO(db->ctx, "Opened database in %.4fms\n",
		(double)(end - start) / CLOCKS_PER_SEC * 1000);

	return 0;
}

/*
	Unmaps and closes the file, which only ever happens once
*/
static void loc_database_file_release(struct loc_database_file* db) {
	int r;

	if (atomic_flag_test_and_set(&db->released))
		return;

	DEBUG(db->ctx, "Releasing database file %p\n", db);

	// Unmap the entire database
	if (db->data) {
		r = munmap(db->data, db->length);
		if (r)
			ERROR(db->ctx, "Could not unmap the database: %s\n", strerror(-errno));

		db->data = NULL;
	}

	// Free the stringpool
	if (db->pool) {
		loc_stringpool_unref(db->pool);
		db->pool = NULL;
	}

	// Close database file
	if (db->f) {
		fclose(db->f);
		db->f = NULL;
	}
}

/*
	Releases the file if nobody has a reference and nobody is reading from it.

	This is being called by whoever might have been the last one. Somebody may
	start to use the file while we are looking, but only if it still is the file
	of the database, in which case the database has a reference.
*/
static void loc_database_file_try_release(struct loc_database_file* db) {
	if (atomic_load(&db->refcount) > 0)
		return;

	for (unsigned int i = 0; i < LOC_DATABASE_FILE_USERS; i++) {
		if (atomic_load(&db->users[i].counter) > 0)
			return;
	}

	loc_database_file_release(db);
}

static void loc_database_file_free(struct loc_database_file* db) {
	loc_database_file_release(db);

	if (db->vendor)
		free(db->vendor);
	if (db->description)
		free(db->description);
	if (db->license)
		free(db->license);

	loc_unref(db->ctx);
	free(db);
}

static int loc_database_file_new(struct loc_ctx* ctx, struct loc_database_file** file, FILE* f) {
	struct loc_database_file* db = NULL;
	int r;

	// Allocate the object
	db = calloc(1, sizeof(*db));
	if (!db)
		return -ENOMEM;

	// Reference context
	db->ctx = loc_ref(ctx);
	db->refcount = 1;

	DEBUG(db->ctx, "Database file allocated at %p\n", db);

	// Try to open the database
	r = loc_database_file_open(db, f);
	if (r)
		goto ERROR;

	*file = db;
	return 0;

ERROR:
	if (db)
		loc_database_file_free(db);

	return r;
}

static struct loc_database_file* loc_database_file_ref(struct loc_database_file* db) {
	loc_refcount_inc(&db->refcount);

	return db;
}

static struct loc_database_file* loc_database_file_unref(struct loc_database_file* db) {
	if (loc_refcount_dec(&db->refcount) > 0)
		return NULL;

	// Nobody keeps the file any more, but somebody might still be reading from it.
	// The object itself stays, it is being freed with the database.
	loc_database_file_try_release(db);
	return NULL;
}

/*
	Reads a clock that only moves forward, in seconds.

	This is being called for every lookup, so it has to be cheap: the coarse
	clock is only as accurate as the timer of the kernel, but reading it takes
	a handful of nanoseconds and never has to ask the kernel.
*/
static inline long loc_database_now(void) {
	struct timespec now = { 0 };

#ifdef CLOCK_MONOTONIC_COARSE
	clock_gettime(CLOCK_MONOTONIC_COARSE, &now);
#else
	clock_gettime(CLOCK_MONOTONIC, &now);
#endif

	return now.tv_sec;
}

/*
	Checks every once in a while if the database has been replaced.

	Almost always, this reads the clock and returns. Looking at the file is
	something that we cannot do for every lookup as it would take longer than
	the lookup itself.
*/
static inline void loc_database_check(struct loc_database* db) {
	// Don't do anything if we don't know where the file is, or if this is disabled
	const unsigned int interval = atomic_load_explicit(&db->reload_interval, memory_order_relaxed);
	if (!interval)
		return;

	const long now = loc_database_now();

	// Is it time?
	long next_reload = atomic_load_explicit(&db->next_reload, memory_order_relaxed);
	if (likely(now < next_reload))
		return;

	// Only one thread goes and looks. Everybody else carries on with what
	// we have and is not being held up.
	if (!atomic_compare_exchange_strong(&db->next_reload, (atomic_long*)&next_reload, now + interval))
		return;

	// Errors have been logged and we will try again later
	loc_database_reload(db);
}

/*
	Returns the file of the database to read from it. It cannot be unmapped
	until it has been passed to loc_database_release() together with the user
	that we return.
*/
static struct loc_database_file* loc_database_acquire(struct loc_database* db, unsigned int* user) {
	struct loc_database_file* file = NULL;

	// Is there a new file?
	loc_database_check(db);

	// Find the counter of this thread. The IDs of threads are addresses which
	// are often the same distance apart, so we multiply them by a large odd
	// number and take the highest bits, which spreads them evenly.
	//
	// pthread_t is an integer with glibc and a pointer with musl, and casting
	// the result of a function call directly upsets the compiler.
	const pthread_t self = pthread_self();
	const uint64_t thread = (uintptr_t)self;

	*user = (thread * UINT64_C(0x9e3779b97f4a7c15)) >> 58;

	for (;;) {
		file = atomic_load(&db->file);

		// Tell everyone that we are using the file
		atomic_fetch_add(&file->users[*user].counter, 1);

		// If this is still the file of the database, the database had a reference
		// when we became a user, and nobody releases a file which has users.
		if (file == atomic_load(&db->file))
			return file;

		// The file has been replaced in the meantime and we might have
		// been too late. Leave it alone and try again with the new one.
		atomic_fetch_sub(&file->users[*user].counter, 1);

		loc_database_file_try_release(file);
	}
}

static void loc_database_release(struct loc_database_file* file, const unsigned int user) {
	atomic_fetch_sub(&file->users[user].counter, 1);

	// If the database has replaced the file while we were using
	// it, we could be the last one who knows about it.
	if (atomic_load(&file->refcount) == 0)
		loc_database_file_try_release(file);
}

static void loc_database_free(struct loc_database* db) {
	struct loc_database_file* file = NULL;

	DEBUG(db->ctx, "Releasing database %p\n", db);

	// Nobody can be using any of the files any more
	while (db->files) {
		file = db->files;
		db->files = file->next;

		loc_database_file_free(file);
	}

	if (db->path)
		free(db->path);

	pthread_mutex_destroy(&db->lock);

	loc_unref(db->ctx);
	free(db);
}

LOC_EXPORT int loc_database_new(struct loc_ctx* ctx, struct loc_database** database, FILE* f) {
	struct loc_database_file* file = NULL;
	struct loc_database* db = NULL;
	int r;

	// Fail on invalid file handle
	if (!f)
		return -EINVAL;

	// Allocate the database object
	db = calloc(1, sizeof(*db));
	if (!db)
		return -ENOMEM;

	// Reference context
	db->ctx = loc_ref(ctx);
	db->refcount = 1;

	pthread_mutex_init(&db->lock, NULL);

	DEBUG(db->ctx, "Database object allocated at %p\n", db);

	// Read the file
	r = loc_database_file_new(db->ctx, &file, f);
	if (r)
		goto ERROR;

	// This is our file now
	db->files = file;
	atomic_init(&db->file, file);

	*database = db;
	return 0;

ERROR:
	if (db)
		loc_database_free(db);

	return r;
}

LOC_EXPORT int loc_database_open(struct loc_ctx* ctx, struct loc_database** database, const char* path) {
	struct loc_database* db = NULL;
	FILE* f = NULL;
	int r;

	if (!path)
		return -EINVAL;

	// Open the file
	f = fopen(path, FOPEN_MODE);
	if (!f)
		return -errno;

	// Create the database
	r = loc_database_new(ctx, &db, f);
	if (r)
		goto ERROR;

	// Remember where the database is
	db->path = strdup(path);
	if (!db->path) {
		r = -ENOMEM;
		goto ERROR;
	}

	// Check for a new file every once in a while
	r = loc_database_set_reload_interval(db, LOC_DATABASE_RELOAD_INTERVAL);
	if (r)
		goto ERROR;

	*database = db;

ERROR:
	if (r && db)
		loc_database_unref(db);

	// The database has its own copy of the file
	fclose(f);

	return r;
}

/*
	Checks if the file at the path of the database is not the one that we have
	any more, and if so, reads the new one and uses that from now on.

	Whoever is reading from the old file is not being disturbed. The old file is
	being unmapped when the last one is done, and enumerators keep it until they
	are being freed.

	Returns 0 if there was a new file, 1 if nothing has changed, and a negative
	error number if the new file could not be read, in which case we carry on
	with what we have.
*/
LOC_EXPORT int loc_database_reload(struct loc_database* db) {
	struct loc_database_file* file = NULL;
	struct loc_database_file* old = NULL;
	struct stat st = { 0 };
	FILE* f = NULL;
	int r;

	// We can only do this if we know where the database is
	if (!db->path)
		return -ENOTSUP;

	pthread_mutex_lock(&db->lock);

	// Open the file first, so that we check the file that we are going to read
	f = fopen(db->path, FOPEN_MODE);
	if (!f) {
		r = -errno;

		ERROR(db->ctx, "Could not open %s: %s\n", db->path, strerror(-r));
		goto ERROR;
	}

	r = fstat(fileno(f), &st);
	if (r < 0) {
		r = -errno;

		ERROR(db->ctx, "Could not stat %s: %s\n", db->path, strerror(-r));
		goto ERROR;
	}

	// Nobody else can replace the file while we are holding the lock
	old = atomic_load(&db->file);
	struct stat st_old = old->st;

	// Do we have this file already?
	if (st.st_dev == old->st.st_dev && st.st_ino == old->st.st_ino &&
	    st.st_size == old->st.st_size &&
	    MTIME_EQ(st, st_old)) {
		DEBUG(db->ctx, "%s has not changed\n", db->path);

		r = 1;
		goto ERROR;
	}

	/*
		We are not verifying the signature of the database here, because that
		takes too long, and we would not know the key anyways. Whoever has
		written the file is supposed to have done that.

		But we won't take a file that anybody could have written.
	*/
	if (!S_ISREG(st.st_mode)) {
		ERROR(db->ctx, "%s is not a regular file\n", db->path);

		r = -EINVAL;
		goto ERROR;
	}

	if (st.st_mode & S_IWOTH) {
		ERROR(db->ctx, "Refusing to load %s, because it is writable by everyone\n", db->path);

		r = -EPERM;
		goto ERROR;
	}

	// Read the new file
	r = loc_database_file_new(db->ctx, &file, f);
	if (r) {
		ERROR(db->ctx, "Could not read %s: %s\n", db->path, strerror(-r));
		goto ERROR;
	}

	// Add it to the list of all files
	file->next = db->files;
	db->files = file;

	// Everybody who starts reading something now gets the new file
	old = (struct loc_database_file*) atomic_exchange(&db->file, file);

	// Let go of the old file, which unmaps it as soon as nobody is using it any more
	loc_database_file_unref(old);

	INFO(db->ctx, "Loaded the new database from %s\n", db->path);

ERROR:
	if (f)
		fclose(f);

	pthread_mutex_unlock(&db->lock);

	return r;
}

/*
	Sets how often the database checks whether its file has been replaced.

	Zero turns this off for those who would like to call loc_database_reload()
	themselves, or who don't want the database to change.
*/
LOC_EXPORT int loc_database_set_reload_interval(struct loc_database* db, unsigned int interval) {
	// We have nothing to check if we don't know where the database is
	if (interval && !db->path)
		return -ENOTSUP;

	atomic_store(&db->next_reload, loc_database_now() + interval);
	atomic_store(&db->reload_interval, interval);

	return 0;
}

LOC_EXPORT struct loc_database* loc_database_ref(struct loc_database* db) {
	loc_refcount_inc(&db->refcount);

	return db;
}

LOC_EXPORT struct loc_database* loc_database_unref(struct loc_database* db) {
	if (loc_refcount_dec(&db->refcount) > 0)
		return NULL;

	loc_database_free(db);
	return NULL;
}

static int loc_database_file_verify(struct loc_database_file* db, FILE* f) {
	const struct loc_database_magic* magic =
		(const struct loc_database_magic*)db->data;
	struct loc_database_header_v1 header_v1 = { 0 };
	char* p = db->data;
	size_t l = db->length;
	int r;

	// Cannot do this when no signature is available
	if (!db->signature1.data && !db->signature2.data) {
		DEBUG(db->ctx, "No signature available to verify\n");
		return 1;
	}

	// Start the stopwatch
	clock_t start = clock();

	// Load public key
	EVP_PKEY* pkey = PEM_read_PUBKEY(f, NULL, NULL, NULL);
	if (!pkey) {
		ERROR(db->ctx, "Could not parse public key: %s\n",
			ERR_error_string(ERR_get_error(), NULL));

		return -EINVAL;
	}

	EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
	if (!mdctx) {
		r = -ENOMEM;
		goto CLEANUP;
	}

	// Initialise hash function. The databases are signed using SHA-256, which is
	// what OpenSSL chooses for our keys if it is not told. LibreSSL does not.
	r = EVP_DigestVerifyInit(mdctx, NULL, EVP_sha256(), NULL, pkey);
	if (r != 1) {
		ERROR(db->ctx, "Error initializing signature validation: %s\n",
			ERR_error_string(ERR_get_error(), NULL));
		r = -EIO;

		goto CLEANUP;
	}

	// Dump the magic
	hexdump(db->ctx, magic, sizeof(*magic));

	// Feed magic into the hash
	r = EVP_DigestVerifyUpdate(mdctx, magic, sizeof(*magic));
	if (r != 1) {
		ERROR(db->ctx, "%s\n", ERR_error_string(ERR_get_error(), NULL));
		r = -EIO;

		goto CLEANUP;
	}

	// Advance the pointer
	p += sizeof(*magic);
	l -= sizeof(*magic);

	// Read the header
	switch (db->version) {
		case LOC_DATABASE_VERSION_1:
			// Copy the header so that we can clear the signatures
			memcpy(&header_v1, db->data + sizeof(*magic), sizeof(header_v1));

			// Clear signatures
			memset(header_v1.signature1, '\0', sizeof(header_v1.signature1));
			header_v1.signature1_length = 0;
			memset(header_v1.signature2, '\0', sizeof(header_v1.signature2));
			header_v1.signature2_length = 0;

			// Dump the header
			hexdump(db->ctx, &header_v1, sizeof(header_v1));

			// Feed header into the hash
			r = EVP_DigestVerifyUpdate(mdctx, &header_v1, sizeof(header_v1));
			if (r != 1) {
				ERROR(db->ctx, "%s\n", ERR_error_string(ERR_get_error(), NULL));
				r = -EIO;

				goto CLEANUP;
			}

			// Advance the pointer
			p += sizeof(header_v1);
			l -= sizeof(header_v1);
			break;

		default:
			ERROR(db->ctx, "Cannot compute hash for database with format %u\n",
				db->version);
			r = -ENOTSUP;
			goto CLEANUP;
	}

	// Hash the rest of the payload
	r = EVP_DigestVerifyUpdate(mdctx, p, l);
	if (r != 1) {
		ERROR(db->ctx, "%s\n", ERR_error_string(ERR_get_error(), NULL));
		r = -EIO;

		goto CLEANUP;
	}

	int sig1_valid = 0;
	int sig2_valid = 0;

	// Check first signature
	if (db->signature1.length) {
		hexdump(db->ctx, db->signature1.data, db->signature1.length);

		r = EVP_DigestVerifyFinal(mdctx,
			(unsigned char*)db->signature1.data, db->signature1.length);

		if (r == 0) {
			DEBUG(db->ctx, "The first signature is invalid\n");
		} else if (r == 1) {
			DEBUG(db->ctx, "The first signature is valid\n");
			sig1_valid = 1;
		} else {
			ERROR(db->ctx, "Error verifying the first signature: %s\n",
				ERR_error_string(ERR_get_error(), NULL));
			r = -EIO;
			goto CLEANUP;
		}
	}

	// Check second signature only when the first one was invalid
	if (db->signature2.length) {
		hexdump(db->ctx, db->signature2.data, db->signature2.length);

		r = EVP_DigestVerifyFinal(mdctx,
			(unsigned char*)db->signature2.data, db->signature2.length);

		if (r == 0) {
			DEBUG(db->ctx, "The second signature is invalid\n");
		} else if (r == 1) {
			DEBUG(db->ctx, "The second signature is valid\n");
			sig2_valid = 1;
		} else {
			ERROR(db->ctx, "Error verifying the second signature: %s\n",
				ERR_error_string(ERR_get_error(), NULL));
			r = -EIO;
			goto CLEANUP;
		}
	}

	clock_t end = clock();
	INFO(db->ctx, "Signature checked in %.4fms\n",
		(double)(end - start) / CLOCKS_PER_SEC * 1000);

	// Check if at least one signature as okay
	if (sig1_valid || sig2_valid)
		r = 0;
	else
		r = 1;

CLEANUP:
	// Cleanup
	if (mdctx)
		EVP_MD_CTX_free(mdctx);
	EVP_PKEY_free(pkey);

#ifdef _WIN32
	(void) l;
	(void) p;
#endif

	return r;
}

static time_t loc_database_file_created_at(struct loc_database_file* db) {
	return db->created_at;
}

static const char* loc_database_file_get_vendor(struct loc_database_file* db) {
	return db->vendor;
}

static const char* loc_database_file_get_description(struct loc_database_file* db) {
	return db->description;
}

static const char* loc_database_file_get_license(struct loc_database_file* db) {
	return db->license;
}

static size_t loc_database_file_count_as(struct loc_database_file* db) {
	return db->as_objects.count;
}

// Returns the AS at position pos
static int loc_database_fetch_as(struct loc_database_file* db, struct loc_as** as, off_t pos) {
	struct loc_database_as_v1* as_v1 = NULL;
	int r;

	if ((size_t)pos >= db->as_objects.count)
		return -ERANGE;

	DEBUG(db->ctx, "Fetching AS at position %jd\n", (intmax_t)pos);

	switch (db->version) {
		case LOC_DATABASE_VERSION_1:
			// Find the object
			as_v1 = (struct loc_database_as_v1*)loc_database_object(db,
				&db->as_objects, sizeof(*as_v1), pos);
			if (!as_v1)
				return -EFAULT;

			r = loc_as_new_from_database_v1(db->ctx, db->pool, as, as_v1);
			break;

		default:
			return -ENOTSUP;
	}

	if (r == 0)
		DEBUG(db->ctx, "Got AS%u\n", loc_as_get_number(*as));

	return r;
}

// Performs a binary search to find the AS in the list
static int loc_database_file_get_as(struct loc_database_file* db, struct loc_as** as, uint32_t number) {
	int r;

	// Fail if the callback has not been set
	if (!db->callbacks.match_as)
		return -ENOTSUP;

	off_t lo = 0;
	off_t hi = db->as_objects.count - 1;

#ifdef ENABLE_DEBUG
	// Save start time
	clock_t start = clock();
#endif

	while (lo <= hi) {
		off_t i = (lo + hi) / 2;

		// Match the AS number
		r = db->callbacks.match_as(db, number, i);
		if (r < 0) {
			lo = i + 1;

		} else if (r > 0) {
			hi = i - 1;

		} else {
			// Fetch AS object
			r = loc_database_fetch_as(db, as, i);
			if (r)
				return r;

#ifdef ENABLE_DEBUG
			clock_t end = clock();

			// Log how fast this has been
			DEBUG(db->ctx, "Found AS%u in %.4fms\n", number,
				(double)(end - start) / CLOCKS_PER_SEC * 1000);
#endif

			return 0;
		}
	}

	// Nothing found
	*as = NULL;

	return 1;
}

// Returns the network at position pos
static int loc_database_fetch_network(struct loc_database_file* db, struct loc_network** network,
		struct in6_addr* address, unsigned int prefix, off_t pos) {
	struct loc_database_network_v1* network_v1 = NULL;
	int r;

	if ((size_t)pos >= db->network_objects.count) {
		DEBUG(db->ctx, "Network ID out of range: %jd/%jd\n",
			(intmax_t)pos, (intmax_t)db->network_objects.count);
		return -ERANGE;
	}

	DEBUG(db->ctx, "Fetching network at position %jd\n", (intmax_t)pos);

	switch (db->version) {
		case LOC_DATABASE_VERSION_1:
			// Read the object
			network_v1 = (struct loc_database_network_v1*)loc_database_object(db,
				&db->network_objects, sizeof(*network_v1), pos);
			if (!network_v1)
				return -EFAULT;

			r = loc_network_new_from_database_v1(db->ctx, network, address, prefix, network_v1);
			break;

		default:
			return -ENOTSUP;
	}

	if (r == 0)
		DEBUG(db->ctx, "Got network %s\n", loc_network_str(*network));

	return r;
}

static int __loc_database_node_is_leaf(const struct loc_database_network_node_v1* node) {
	return (node->network != htobe32(0xffffffff));
}

/*
	Walks down the tree along the address, and returns the most specific network
	that it passes. The path that leads to a node is the start address of its
	network, so that the network always contains the address.
*/
static int __loc_database_lookup(struct loc_database_file* db, const struct in6_addr* address,
		struct loc_network** network, off_t node_index, unsigned int level) {
	const struct loc_database_network_node_v1* node_v1 = NULL;

	// The most specific network that we have found so far
	off_t network_index = -1;
	unsigned int prefix = 0;

	for (;;) {
		// Fetch the next node
		node_v1 = (const struct loc_database_network_node_v1*)loc_database_object(db,
			&db->network_node_objects, sizeof(*node_v1), node_index);
		if (!node_v1)
			return -EFAULT;

		// Remember the network of this node
		if (__loc_database_node_is_leaf(node_v1)) {
			network_index = be32toh(node_v1->network);
			prefix = level;
		}

		// The tree cannot be any deeper than the address is long. Nodes at the
		// very bottom (i.e. /128 or /32) can only be leaves.
		if (unlikely(level >= LOC_ADDRESS_MAX_BITS))
			break;

		// Follow the path. Both children are read and the bit picks one, so
		// that we don't have to guess which way we will go.
		const uint32_t bit = loc_address_get_bit(address, level);

		node_index = be32toh((node_v1->zero & (bit - 1)) | (node_v1->one & -bit));

		// If the node index is zero, the tree ends here
		// and we cannot descend any further
		if (!node_index)
			break;

		// Check boundaries
		if (unlikely(((size_t)node_index >= db->network_node_objects.count)))
			return -ERANGE;

		level++;
	}

	DEBUG(db->ctx, "Tree ended at level %u\n", level);

	// We have not found anything
	if (network_index < 0)
		return 0;

	// The network starts at the address, without the bits after the prefix
	const struct in6_addr bitmask = loc_prefix_to_bitmask(prefix);
	struct in6_addr network_address = loc_address_and(address, &bitmask);

	return loc_database_fetch_network(db, network, &network_address, prefix, network_index);
}

static int loc_database_file_lookup(struct loc_database_file* db,
		const struct in6_addr* address, struct loc_network** network) {
	int r;

	// Where to start the search from
	off_t root = 0;
	unsigned int level = 0;

	// Reset the output pointer
	*network = NULL;

#ifdef ENABLE_DEBUG
	// Save start time
	clock_t start = clock();
#endif

	// Determine the address family
	const int family = loc_address_family(address);

	switch (family) {
		// Fast-path for IPv4 addresses
		case AF_INET:
			// Start the search at the root of the IPv4 subtree
			if (db->rootv4) {
				root = db->rootv4;
				level = LOC_DATABASE_ROOTV4_LEVEL;
			}
			break;
	}

	// Perform the lookup
	r = __loc_database_lookup(db, address, network, root, level);

#ifdef ENABLE_DEBUG
	clock_t end = clock();

	// Log how fast this has been
	DEBUG(db->ctx, "Executed network search in %.4fms\n",
		(double)(end - start) / CLOCKS_PER_SEC * 1000);
#endif

	return r;
}

static int loc_database_file_lookup_from_string(struct loc_database_file* db,
		const char* string, struct loc_network** network) {
	struct in6_addr address;

	int r = loc_address_parse(&address, NULL, string);
	if (r)
		return r;

	return loc_database_file_lookup(db, &address, network);
}

// Returns the country at position pos
static int loc_database_fetch_country(struct loc_database_file* db,
		struct loc_country** country, off_t pos) {
	struct loc_database_country_v1* country_v1 = NULL;
	int r;

	// Check if the country is within range
	if ((size_t)pos >= db->country_objects.count)
		return -ERANGE;

	DEBUG(db->ctx, "Fetching country at position %jd\n", (intmax_t)pos);

	switch (db->version) {
		case LOC_DATABASE_VERSION_1:
			// Read the object
			country_v1 = (struct loc_database_country_v1*)loc_database_object(db,
				&db->country_objects, sizeof(*country_v1), pos);
			if (!country_v1)
				return -EFAULT;

			r = loc_country_new_from_database_v1(db->ctx, db->pool, country, country_v1);
			break;

		default:
			return -ENOTSUP;
	}

	if (r == 0)
		DEBUG(db->ctx, "Got country %s\n", loc_country_get_code(*country));

	return r;
}

// Performs a binary search to find the country in the list
static int loc_database_file_get_country(struct loc_database_file* db,
		struct loc_country** country, const char* code) {
	int r;

	// Reset the output pointer
	*country = NULL;

	// Check if the country code is valid
	if (!loc_country_code_is_valid(code))
		return -EINVAL;

	// Fail if the callback has not been set
	if (!db->callbacks.match_country)
		return -ENOTSUP;

#ifdef ENABLE_DEBUG
	// Save start time
	clock_t start = clock();
#endif

	off_t lo = 0;
	off_t hi = db->country_objects.count - 1;

	while (lo <= hi) {
		off_t i = (lo + hi) / 2;

		// Match the country code
		r = db->callbacks.match_country(db, code, i);
		if (r < 0) {
			lo = i + 1;

		} else if (r > 0) {
			hi = i - 1;

		} else {
			// Fetch country object
			r = loc_database_fetch_country(db, country, i);
			if (r)
				return r;

#ifdef ENABLE_DEBUG
			clock_t end = clock();

			// Log how fast this has been
			DEBUG(db->ctx, "Found country %s in %.4fms\n", code,
				(double)(end - start) / CLOCKS_PER_SEC * 1000);
#endif

			return 0;
		}
	}

	// Nothing found
	*country = NULL;

	return 0;
}

/*
	What is being exported works on the file that the database has right now
*/

LOC_EXPORT int loc_database_verify(struct loc_database* db, FILE* f) {
	unsigned int user;
	int r;

	struct loc_database_file* file = loc_database_acquire(db, &user);

	r = loc_database_file_verify(file, f);

	loc_database_release(file, user);

	return r;
}

LOC_EXPORT time_t loc_database_created_at(struct loc_database* db) {
	unsigned int user;

	struct loc_database_file* file = loc_database_acquire(db, &user);

	const time_t created_at = loc_database_file_created_at(file);

	loc_database_release(file, user);

	return created_at;
}

/*
	These strings are copies which the file has until the
	database is being freed, even if it has been replaced.
*/
LOC_EXPORT const char* loc_database_get_vendor(struct loc_database* db) {
	unsigned int user;

	struct loc_database_file* file = loc_database_acquire(db, &user);

	const char* vendor = loc_database_file_get_vendor(file);

	loc_database_release(file, user);

	return vendor;
}

LOC_EXPORT const char* loc_database_get_description(struct loc_database* db) {
	unsigned int user;

	struct loc_database_file* file = loc_database_acquire(db, &user);

	const char* description = loc_database_file_get_description(file);

	loc_database_release(file, user);

	return description;
}

LOC_EXPORT const char* loc_database_get_license(struct loc_database* db) {
	unsigned int user;

	struct loc_database_file* file = loc_database_acquire(db, &user);

	const char* license = loc_database_file_get_license(file);

	loc_database_release(file, user);

	return license;
}

LOC_EXPORT size_t loc_database_count_as(struct loc_database* db) {
	unsigned int user;

	struct loc_database_file* file = loc_database_acquire(db, &user);

	const size_t count = loc_database_file_count_as(file);

	loc_database_release(file, user);

	return count;
}

LOC_EXPORT int loc_database_get_as(struct loc_database* db, struct loc_as** as, uint32_t number) {
	unsigned int user;
	int r;

	struct loc_database_file* file = loc_database_acquire(db, &user);

	r = loc_database_file_get_as(file, as, number);

	loc_database_release(file, user);

	return r;
}

LOC_EXPORT int loc_database_lookup(struct loc_database* db,
		const struct in6_addr* address, struct loc_network** network) {
	unsigned int user;
	int r;

	struct loc_database_file* file = loc_database_acquire(db, &user);

	r = loc_database_file_lookup(file, address, network);

	loc_database_release(file, user);

	return r;
}

LOC_EXPORT int loc_database_lookup_from_string(struct loc_database* db,
		const char* string, struct loc_network** network) {
	unsigned int user;
	int r;

	struct loc_database_file* file = loc_database_acquire(db, &user);

	r = loc_database_file_lookup_from_string(file, string, network);

	loc_database_release(file, user);

	return r;
}

LOC_EXPORT int loc_database_get_country(struct loc_database* db,
		struct loc_country** country, const char* code) {
	unsigned int user;
	int r;

	struct loc_database_file* file = loc_database_acquire(db, &user);

	r = loc_database_file_get_country(file, country, code);

	loc_database_release(file, user);

	return r;
}

// Enumerator

static void loc_database_enumerator_free(struct loc_database_enumerator* enumerator) {
	DEBUG(enumerator->ctx, "Releasing database enumerator %p\n", enumerator);

	// Release all references
	loc_database_file_unref(enumerator->db);
	loc_database_unref(enumerator->database);
	loc_unref(enumerator->ctx);

	if (enumerator->string)
		free(enumerator->string);

	if (enumerator->countries)
		loc_country_list_unref(enumerator->countries);

	if (enumerator->asns)
		loc_as_list_unref(enumerator->asns);

	// Free network search
	if (enumerator->networks_visited)
		free(enumerator->networks_visited);

	// Free subnet/bogons stack
	if (enumerator->stack)
		loc_network_list_unref(enumerator->stack);

	if (enumerator->subnets)
		loc_network_list_unref(enumerator->subnets);

	free(enumerator);
}

LOC_EXPORT int loc_database_enumerator_new(struct loc_database_enumerator** enumerator,
		struct loc_database* database, enum loc_database_enumerator_mode mode, int flags) {
	unsigned int user;
	int r;

	struct loc_database_enumerator* e = calloc(1, sizeof(*e));
	if (!e) {
		return -ENOMEM;
	}

	// We keep the file that the database has right now, so that we see the same
	// networks until we are done, even if the file is being replaced.
	struct loc_database_file* db = loc_database_acquire(database, &user);

	// Reference context
	e->ctx = loc_ref(db->ctx);
	e->db = loc_database_file_ref(db);

	// The file is ours now
	loc_database_release(db, user);

	// The database has to be there for as long as we have one of its files
	e->database = loc_database_ref(database);
	e->mode = mode;
	e->refcount = 1;

	// Flatten output?
	e->flatten = (flags & LOC_DB_ENUMERATOR_FLAGS_FLATTEN);

	// Initialise graph search
	e->network_stack_depth = 1;
	// One bit for each node
	e->networks_visited = calloc((db->network_node_objects.count + 63) / 64,
		sizeof(*e->networks_visited));
	if (!e->networks_visited) {
		ERROR(db->ctx, "Could not allocated visited networks: %s\n", strerror(-errno));
		r = -ENOMEM;
		goto ERROR;
	}

	// Allocate stack
	r = loc_network_list_new(e->ctx, &e->stack);
	if (r)
		goto ERROR;

	// Initialize bogon search
	loc_address_reset(&e->gap6_start, AF_INET6);
	loc_address_reset(&e->gap4_start, AF_INET);

	DEBUG(e->ctx, "Database enumerator object allocated at %p\n", e);

	*enumerator = e;
	return 0;

ERROR:
	if (e)
		loc_database_enumerator_free(e);

	return r;
}

LOC_EXPORT struct loc_database_enumerator* loc_database_enumerator_ref(struct loc_database_enumerator* enumerator) {
	loc_refcount_inc(&enumerator->refcount);

	return enumerator;
}

LOC_EXPORT struct loc_database_enumerator* loc_database_enumerator_unref(struct loc_database_enumerator* enumerator) {
	if (!enumerator)
		return NULL;

	if (loc_refcount_dec(&enumerator->refcount) > 0)
		return enumerator;

	loc_database_enumerator_free(enumerator);
	return NULL;
}

LOC_EXPORT int loc_database_enumerator_set_string(struct loc_database_enumerator* enumerator, const char* string) {
	char* s = NULL;

	// Copy the string and make it lowercase
	if (string) {
		s = strdup(string);
		if (!s)
			return -ENOMEM;

		for (char *p = s; *p; p++)
			*p = tolower((unsigned char)*p);
	}

	// Replace the previous string
	if (enumerator->string)
		free(enumerator->string);

	enumerator->string = s;

	return 0;
}

LOC_EXPORT struct loc_country_list* loc_database_enumerator_get_countries(
		struct loc_database_enumerator* enumerator) {
	if (!enumerator->countries)
		return NULL;

	return loc_country_list_ref(enumerator->countries);
}

LOC_EXPORT int loc_database_enumerator_set_countries(
		struct loc_database_enumerator* enumerator, struct loc_country_list* countries) {
	if (enumerator->countries) {
		loc_country_list_unref(enumerator->countries);
		enumerator->countries = NULL;
	}

	// Passing NULL removes the filter
	if (countries)
		enumerator->countries = loc_country_list_ref(countries);

	return 0;
}

LOC_EXPORT struct loc_as_list* loc_database_enumerator_get_asns(
		struct loc_database_enumerator* enumerator) {
	if (!enumerator->asns)
		return NULL;

	return loc_as_list_ref(enumerator->asns);
}

LOC_EXPORT int loc_database_enumerator_set_asns(
		struct loc_database_enumerator* enumerator, struct loc_as_list* asns) {
	if (enumerator->asns) {
		loc_as_list_unref(enumerator->asns);
		enumerator->asns = NULL;
	}

	// Passing NULL removes the filter
	if (asns)
		enumerator->asns = loc_as_list_ref(asns);

	return 0;
}

LOC_EXPORT int loc_database_enumerator_set_flag(
		struct loc_database_enumerator* enumerator, enum loc_network_flags flag) {
	enumerator->flags |= flag;

	return 0;
}

LOC_EXPORT int loc_database_enumerator_set_family(
		struct loc_database_enumerator* enumerator, int family) {
	enumerator->family = family;

	return 0;
}

LOC_EXPORT int loc_database_enumerator_next_as(
		struct loc_database_enumerator* enumerator, struct loc_as** as) {
	*as = NULL;

	// Do not do anything if not in AS mode
	if (enumerator->mode != LOC_DB_ENUMERATE_ASES)
		return 0;

	struct loc_database_file* db = enumerator->db;

	while (enumerator->as_index < db->as_objects.count) {
		// Fetch the next AS
		int r = loc_database_fetch_as(db, as, enumerator->as_index++);
		if (r)
			return r;

		r = loc_as_match_string(*as, enumerator->string);
		if (r == 1) {
			DEBUG(enumerator->ctx, "AS%u (%s) matches %s\n",
				loc_as_get_number(*as), loc_as_get_name(*as), enumerator->string);

			return 0;
		}

		// No match
		loc_as_unref(*as);
		*as = NULL;
	}

	// Reset the index
	enumerator->as_index = 0;

	// We have searched through all of them
	return 0;
}

static inline int loc_database_enumerator_visited(
		struct loc_database_enumerator* e, off_t offset) {
	return (e->networks_visited[offset / 64] >> (offset % 64)) & 1;
}

static inline void loc_database_enumerator_visit(
		struct loc_database_enumerator* e, off_t offset) {
	e->networks_visited[offset / 64] |= UINT64_C(1) << (offset % 64);
}

static int loc_database_enumerator_stack_push_node(
		struct loc_database_enumerator* e, off_t offset, int i, int depth) {
	// Do not add empty nodes
	if (!offset)
		return 0;

	// The tree cannot be deeper than an address is long
	if (depth > LOC_ADDRESS_MAX_BITS) {
		ERROR(e->ctx, "Node %jd is too deep in the tree: %d\n", (intmax_t)offset, depth);
		return -EBADMSG;
	}

	// Check if there is any space left on the stack
	// (the first element is at index one)
	if (e->network_stack_depth >= MAX_STACK_DEPTH - 1) {
		ERROR(e->ctx, "Maximum stack size reached: %d\n", e->network_stack_depth);
		return -ENOSPC;
	}

	// Check if the node is in range
	if (offset >= (off_t)e->db->network_node_objects.count) {
		ERROR(e->ctx, "Trying to add invalid node with offset %jd/%zu\n",
			(intmax_t)offset, e->db->network_node_objects.count);
		return -ERANGE;
	}

	// Increase stack size
	int s = ++e->network_stack_depth;

	DEBUG(e->ctx, "Added node %jd to stack (%d)\n", (intmax_t)offset, depth);

	e->network_stack[s].offset = offset;
	e->network_stack[s].i = i;
	e->network_stack[s].depth = depth;

	return 0;
}

static int loc_database_enumerator_match_network(
		struct loc_database_enumerator* enumerator, struct loc_network* network) {
	// If family is set, it must match
	if (enumerator->family && loc_network_address_family(network) != enumerator->family) {
		DEBUG(enumerator->ctx, "Filtered network %p because of family not matching\n", network);
		return 0;
	}

	// Match if no filter criteria is configured
	if (!enumerator->countries && !enumerator->asns && !enumerator->flags)
		return 1;

	// Check if the country code matches
	if (enumerator->countries && !loc_country_list_empty(enumerator->countries)) {
		const char* country_code = loc_network_get_country_code(network);

		if (loc_country_list_contains_code(enumerator->countries, country_code) > 0) {
			DEBUG(enumerator->ctx, "Matched network %p because of its country code\n", network);
			return 1;
		}
	}

	// Check if the ASN matches
	if (enumerator->asns && !loc_as_list_empty(enumerator->asns)) {
		uint32_t asn = loc_network_get_asn(network);

		if (loc_as_list_contains_number(enumerator->asns, asn) > 0) {
			DEBUG(enumerator->ctx, "Matched network %p because of its ASN\n", network);
			return 1;
		}
	}

	// Check if flags match
	if (enumerator->flags && loc_network_has_flag(network, enumerator->flags)) {
		DEBUG(enumerator->ctx, "Matched network %p because of its flags\n", network);
		return 1;
	}

	// Not a match
	return 0;
}

static int __loc_database_enumerator_next_network(
		struct loc_database_enumerator* enumerator, struct loc_network** network, int filter) {
	// Return top element from the stack
	while (1) {
		*network = loc_network_list_pop_first(enumerator->stack);

		// Stack is empty
		if (!*network)
			break;

		// Return everything if filter isn't enabled, or only return matches
		if (!filter || loc_database_enumerator_match_network(enumerator, *network))
			return 0;

		// Throw away anything that doesn't match
		loc_network_unref(*network);
		*network = NULL;
	}

	DEBUG(enumerator->ctx, "Called with a stack of %d nodes\n",
		enumerator->network_stack_depth);

	// Perform DFS
	while (enumerator->network_stack_depth > 0) {
		DEBUG(enumerator->ctx, "Stack depth: %d\n", enumerator->network_stack_depth);

		// Get object from top of the stack
		struct loc_node_stack* node = &enumerator->network_stack[enumerator->network_stack_depth];

		DEBUG(enumerator->ctx, "  Got node: %jd\n", (intmax_t)node->offset);

		// Remove the node from the stack if we have already visited it
		if (loc_database_enumerator_visited(enumerator, node->offset)) {
			enumerator->network_stack_depth--;
			continue;
		}

		// Mark the bits on the path correctly
		loc_address_set_bit(&enumerator->network_address,
			(node->depth > 0) ? node->depth - 1 : 0, node->i);

		DEBUG(enumerator->ctx, "Looking at node %jd\n", (intmax_t)node->offset);
		loc_database_enumerator_visit(enumerator, node->offset);

		// Pop node from top of the stack
		struct loc_database_network_node_v1* n =
			(struct loc_database_network_node_v1*)loc_database_object(enumerator->db,
				&enumerator->db->network_node_objects, sizeof(*n), node->offset);
		if (!n)
			return -EFAULT;

		// Add edges to stack
		int r = loc_database_enumerator_stack_push_node(enumerator,
			be32toh(n->one), 1, node->depth + 1);
		if (r)
			return r;

		r = loc_database_enumerator_stack_push_node(enumerator,
			be32toh(n->zero), 0, node->depth + 1);
		if (r)
			return r;

		// Check if this node is a leaf and has a network object
		if (__loc_database_node_is_leaf(n)) {
			off_t network_index = be32toh(n->network);

			DEBUG(enumerator->ctx, "Node has a network at %jd\n", (intmax_t)network_index);

			// Fetch the network object
			r = loc_database_fetch_network(enumerator->db, network,
				&enumerator->network_address, node->depth, network_index);

			// Break on any errors
			if (r)
				return r;

			// Return all networks when the filter is disabled, or check for match
			if (!filter || loc_database_enumerator_match_network(enumerator, *network))
				return 0;

			// Does not seem to be a match, so we cleanup and move on
			loc_network_unref(*network);
			*network = NULL;
		}
	}

	// Reached the end of the search
	return 0;
}

static int __loc_database_enumerator_next_network_flattened(
		struct loc_database_enumerator* enumerator, struct loc_network** network) {
	struct loc_network_list* excluded = NULL;
	struct loc_network* subnet = NULL;
	int r;

	// Networks that have subnets are being broken into smaller parts, which
	// are pushed onto the stack. Then we start again with the next network.
	while (1) {
		// Fetch the next network
		r = __loc_database_enumerator_next_network(enumerator, network, 1);
		if (r)
			return r;

		// End if we could not read another network
		if (!*network)
			return 0;

		// Create a list with all subnets
		if (!enumerator->subnets) {
			r = loc_network_list_new(enumerator->ctx, &enumerator->subnets);
			if (r)
				goto ERROR;
		}

		// Search all subnets from the database
		while (1) {
			// Fetch the next network in line
			r = __loc_database_enumerator_next_network(enumerator, &subnet, 0);
			if (r)
				goto ERROR;

			// End if we did not receive another subnet
			if (!subnet)
				break;

			// Collect all subnets in a list
			if (loc_network_is_subnet(*network, subnet)) {
				r = loc_network_list_push(enumerator->subnets, subnet);
				if (r)
					goto ERROR;

				loc_network_unref(subnet);
				subnet = NULL;
				continue;
			}

			// If this is not a subnet, we push it back onto the stack and break
			r = loc_network_list_push(enumerator->stack, subnet);
			if (r)
				goto ERROR;

			loc_network_unref(subnet);
			subnet = NULL;
			break;
		}

		DEBUG(enumerator->ctx, "Found %zu subnet(s)\n",
			loc_network_list_size(enumerator->subnets));

		// We can return the network if it has no subnets
		if (loc_network_list_empty(enumerator->subnets))
			return 0;

		// If the network has any subnets, we will break it into smaller parts
		// without the subnets.
		excluded = loc_network_exclude_list(*network, enumerator->subnets);
		if (!excluded) {
			r = -ENOMEM;
			goto ERROR;
		}

		// Merge subnets onto the stack
		r = loc_network_list_merge(enumerator->stack, enumerator->subnets);
		if (r)
			goto ERROR;

		// Push excluded list onto the stack
		r = loc_network_list_merge(enumerator->stack, excluded);
		if (r)
			goto ERROR;

		loc_network_list_clear(enumerator->subnets);
		loc_network_list_unref(excluded);
		excluded = NULL;

		// Drop the network and restart the whole process again to pick the next network
		loc_network_unref(*network);
		*network = NULL;
	}

ERROR:
	if (enumerator->subnets)
		loc_network_list_clear(enumerator->subnets);
	if (excluded)
		loc_network_list_unref(excluded);
	if (subnet)
		loc_network_unref(subnet);

	// Don't return a network together with an error
	loc_network_unref(*network);
	*network = NULL;

	return r;
}

/*
	This function finds all bogons (i.e. gaps) between the input networks
*/
static int __loc_database_enumerator_next_bogon(
		struct loc_database_enumerator* enumerator, struct loc_network** bogon) {
	int r;

	// Return top element from the stack
	while (1) {
		*bogon = loc_network_list_pop_first(enumerator->stack);

		// Stack is empty
		if (!*bogon)
			break;

		// Return result
		return 0;
	}

	struct loc_network* network = NULL;
	struct in6_addr* gap_start = NULL;
	struct in6_addr gap_end = IN6ADDR_ANY_INIT;

	while (1) {
		r = __loc_database_enumerator_next_network(enumerator, &network, 1);
		if (r)
			return r;

		// We have read the last network
		if (!network)
			goto FINISH;

		const char* country_code = loc_network_get_country_code(network);

		/*
			Skip anything that does not have a country code

			Even if a network is part of the routing table, and the database provides
			an ASN, this does not mean that this is a legitimate announcement.
		*/
		if (country_code && !*country_code) {
			loc_network_unref(network);
			continue;
		}

		// Determine the network family
		int family = loc_network_address_family(network);

		switch (family) {
			case AF_INET6:
				gap_start = &enumerator->gap6_start;
				break;

			case AF_INET:
				gap_start = &enumerator->gap4_start;
				break;

			default:
				ERROR(enumerator->ctx, "Unsupported network family %d\n", family);
				loc_network_unref(network);
				return -ENOTSUP;
		}

		const struct in6_addr* first_address = loc_network_get_first_address(network);
		const struct in6_addr* last_address = loc_network_get_last_address(network);

		// Skip if this network is a subnet of a former one
		if (loc_address_cmp(gap_start, last_address) >= 0) {
			loc_network_unref(network);
			continue;
		}

		// Search where the gap could end
		gap_end = *first_address;
		loc_address_decrement(&gap_end);

		// There is a gap
		if (loc_address_cmp(gap_start, &gap_end) <= 0) {
			r = loc_network_list_summarize(enumerator->ctx,
				gap_start, &gap_end, &enumerator->stack);
			if (r) {
				loc_network_unref(network);
				return r;
			}
		}

		// The gap now starts after this network
		*gap_start = *last_address;
		loc_address_increment(gap_start);

		loc_network_unref(network);

		// Try to return something
		*bogon = loc_network_list_pop_first(enumerator->stack);
		if (*bogon)
			break;
	}

	return 0;

FINISH:
	if (!loc_address_all_zeroes(&enumerator->gap6_start)) {
		r = loc_address_reset_last(&gap_end, AF_INET6);
		if (r)
			return r;

		if (loc_address_cmp(&enumerator->gap6_start, &gap_end) <= 0) {
			r = loc_network_list_summarize(enumerator->ctx,
				&enumerator->gap6_start, &gap_end, &enumerator->stack);
			if (r)
				return r;
		}

		// Reset start
		loc_address_reset(&enumerator->gap6_start, AF_INET6);
	}

	if (!loc_address_all_zeroes(&enumerator->gap4_start)) {
		r = loc_address_reset_last(&gap_end, AF_INET);
		if (r)
			return r;

		if (loc_address_cmp(&enumerator->gap4_start, &gap_end) <= 0) {
			r = loc_network_list_summarize(enumerator->ctx,
				&enumerator->gap4_start, &gap_end, &enumerator->stack);
			if (r)
				return r;
		}

		// Reset start
		loc_address_reset(&enumerator->gap4_start, AF_INET);
	}

	// Try to return something
	*bogon = loc_network_list_pop_first(enumerator->stack);

	return 0;
}

LOC_EXPORT int loc_database_enumerator_next_network(
		struct loc_database_enumerator* enumerator, struct loc_network** network) {
	*network = NULL;

	switch (enumerator->mode) {
		case LOC_DB_ENUMERATE_NETWORKS:
			// Flatten output?
			if (enumerator->flatten)
				return __loc_database_enumerator_next_network_flattened(enumerator, network);

			return __loc_database_enumerator_next_network(enumerator, network, 1);

		case LOC_DB_ENUMERATE_BOGONS:
			return __loc_database_enumerator_next_bogon(enumerator, network);

		default:
			return 0;
	}
}

LOC_EXPORT int loc_database_enumerator_next_country(
		struct loc_database_enumerator* enumerator, struct loc_country** country) {
	*country = NULL;

	// Do not do anything if not in country mode
	if (enumerator->mode != LOC_DB_ENUMERATE_COUNTRIES)
		return 0;

	struct loc_database_file* db = enumerator->db;

	while (enumerator->country_index < db->country_objects.count) {
		// Fetch the next country
		int r = loc_database_fetch_country(db, country, enumerator->country_index++);
		if (r)
			return r;

		// We do not filter here, so it always is a match
		return 0;
	}

	// Reset the index
	enumerator->country_index = 0;

	// We have searched through all of them
	return 0;
}
