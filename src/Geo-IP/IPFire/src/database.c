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
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#if !(defined(_WIN32) || (defined(__CYGWIN__) && defined(__USE_W32_SOCKETS)))
#  include <arpa/inet.h>
#  include <netinet/in.h>
#endif

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

struct loc_database_objects {
	char* data;
	size_t length;
	size_t count;
};

struct loc_database_signature {
	const char* data;
	size_t length;
};

struct loc_database {
	struct loc_ctx* ctx;
	int refcount;

	FILE* f;

	enum loc_database_version version;
	time_t created_at;
	off_t vendor;
	off_t description;
	off_t license;

	// Signatures
	struct loc_database_signature signature1;
	struct loc_database_signature signature2;

	// Data mapped into memory
	char* data;
	off_t length;

	struct loc_stringpool* pool;

	// ASes in the database
	struct loc_database_objects as_objects;

	// Network tree
	struct loc_database_objects network_node_objects;

	// Networks
	struct loc_database_objects network_objects;

	// Countries
	struct loc_database_objects country_objects;
};

#define MAX_STACK_DEPTH 256

struct loc_node_stack {
	off_t offset;
	int i; // Is this node 0 or 1?
	int depth;
};

struct loc_database_enumerator {
	struct loc_ctx* ctx;
	struct loc_database* db;
	enum loc_database_enumerator_mode mode;
	int refcount;

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
	unsigned int* networks_visited;

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

static inline int __loc_database_check_boundaries(struct loc_database* db,
		const char* p, const size_t length) {
	size_t offset = p - db->data;

	// Return if everything is within the boundary
	if (offset <= db->length - length)
		return 1;

	DEBUG(db->ctx, "Database read check failed at %p for %zu byte(s)\n", p, length);
	DEBUG(db->ctx, "  p      = %p (offset = %jd, length = %zu)\n", p, offset, length);
	DEBUG(db->ctx, "  data   = %p (length = %zu)\n", db->data, (size_t)db->length);
	DEBUG(db->ctx, "  end    = %p\n", db->data + db->length);
	DEBUG(db->ctx, "  overflow of %zu byte(s)\n", offset + length - db->length);

	// Otherwise raise EFAULT
	errno = EFAULT;
	return 0;
}

/*
	Returns a pointer to the n-th object
*/
static inline char* loc_database_object(struct loc_database* db,
		const struct loc_database_objects* objects, const size_t length, const off_t n) {
	// Calculate offset
	const off_t offset = n * length;

	// Return a pointer to where the object lies
	char* object = objects->data + offset;

	// Check if the object is part of the memory
	if (!__loc_database_check_boundaries(db, object, length))
		return NULL;

	return object;
}

static int loc_database_version_supported(struct loc_database* db, uint8_t version) {
	switch (version) {
		// Supported versions
		case LOC_DATABASE_VERSION_1:
			return 1;

		default:
			ERROR(db->ctx, "Database version %d is not supported\n", version);
			errno = ENOTSUP;
			return 0;
	}
}

static int loc_database_check_magic(struct loc_database* db) {
	struct loc_database_magic magic;

	// Read from file
	size_t bytes_read = fread(&magic, 1, sizeof(magic), db->f);

	// Check if we have been able to read enough data
	if (bytes_read < sizeof(magic)) {
		ERROR(db->ctx, "Could not read enough data to validate magic bytes\n");
		DEBUG(db->ctx, "Read %zu bytes, but needed %zu\n", bytes_read, sizeof(magic));
		goto ERROR;
	}

	// Compare magic bytes
	if (memcmp(magic.magic, LOC_DATABASE_MAGIC, sizeof(magic.magic)) == 0) {
		DEBUG(db->ctx, "Magic value matches\n");

		// Do we support this version?
		if (!loc_database_version_supported(db, magic.version))
			return 1;

		// Parse version
		db->version = magic.version;

		return 0;
	}

ERROR:
	ERROR(db->ctx, "Unrecognized file type\n");
	errno = ENOMSG;

	// Return an error
	return 1;
}

/*
	Maps the entire database into memory
*/
static int loc_database_mmap(struct loc_database* db) {
	int r;

	// Get file descriptor
	int fd = fileno(db->f);

	// Determine the length of the database
	db->length = lseek(fd, 0, SEEK_END);
	if (db->length < 0) {
		ERROR(db->ctx, "Could not determine the length of the database: %m\n");
		return 1;
	}

	rewind(db->f);

	// Map all data
	db->data = mmap(NULL, db->length, PROT_READ, MAP_SHARED, fd, 0);
	if (db->data == MAP_FAILED) {
		ERROR(db->ctx, "Could not map the database: %m\n");
		db->data = NULL;
		return 1;
	}

	DEBUG(db->ctx, "Mapped database of %zu byte(s) at %p\n", (size_t)db->length, db->data);

#if !defined(_WIN32) && !defined(__CYGWIN__)
	// Tell the system that we expect to read data randomly
	r = madvise(db->data, db->length, MADV_RANDOM);
	if (r) {
		ERROR(db->ctx, "madvise() failed: %m\n");
		return r;
	}
#endif

	return 0;
}

/*
	Maps arbitrary objects from the database into memory.
*/
static int loc_database_map_objects(struct loc_database* db, struct loc_database_objects* objects,
		const size_t size, const off_t offset, const size_t length) {
	// Store parameters
	objects->data   = db->data + offset;
	objects->length = length;
	objects->count  = objects->length / size;

	return 0;
}

static int loc_database_read_signature(struct loc_database* db,
		struct loc_database_signature* signature, const char* data, const size_t length) {
	// Check for a plausible signature length
	if (length > LOC_SIGNATURE_MAX_LENGTH) {
		ERROR(db->ctx, "Signature too long: %zu\n", length);
		errno = EINVAL;
		return 1;
	}

	// Store data & length
	signature->data = data;
	signature->length = length;

	DEBUG(db->ctx, "Read signature of %zu byte(s) at %p\n",
		signature->length, signature->data);

	hexdump(db->ctx, signature->data, signature->length);

	return 0;
}

static int loc_database_read_header_v1(struct loc_database* db) {
	const struct loc_database_header_v1* header =
		(const struct loc_database_header_v1*)(db->data + LOC_DATABASE_MAGIC_SIZE);
	int r;

	DEBUG(db->ctx, "Reading header at %p\n", header);

	// Check if we can read the header
	if (!loc_database_check_boundaries(db, header)) {
		ERROR(db->ctx, "Could not read enough data for header\n");
		return 1;
	}

	// Dump the entire header
	hexdump(db->ctx, header, sizeof(*header));

	// Copy over data
	db->created_at  = be64toh(header->created_at);
	db->vendor      = be32toh(header->vendor);
	db->description = be32toh(header->description);
	db->license     = be32toh(header->license);

	// Read signatures
	r = loc_database_read_signature(db, &db->signature1,
		header->signature1, be16toh(header->signature1_length));
	if (r)
		return r;

	r = loc_database_read_signature(db, &db->signature2,
		header->signature2, be16toh(header->signature2_length));
	if (r)
		return r;

	const char* stringpool_start = db->data + be32toh(header->pool_offset);
	size_t stringpool_length = be32toh(header->pool_length);

	// Check if the stringpool is part of the mapped area
	if (!__loc_database_check_boundaries(db, stringpool_start, stringpool_length))
		return 1;

	// Open the stringpool
	r = loc_stringpool_open(db->ctx, &db->pool, stringpool_start, stringpool_length);
	if (r)
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

	return 0;
}

static int loc_database_read_header(struct loc_database* db) {
	DEBUG(db->ctx, "Database version is %u\n", db->version);

	switch (db->version) {
		case LOC_DATABASE_VERSION_1:
			return loc_database_read_header_v1(db);

		default:
			ERROR(db->ctx, "Incompatible database version: %u\n", db->version);
			return 1;
	}
}

static int loc_database_clone_handle(struct loc_database* db, FILE* f) {
	// Fetch the FD of the original handle
	int fd = fileno(f);

	// Clone file descriptor
	fd = dup(fd);
	if (!fd) {
		ERROR(db->ctx, "Could not duplicate file descriptor\n");
		return 1;
	}

	// Reopen the file so that we can keep our own file handle
	db->f = fdopen(fd, "rb");
	if (!db->f) {
		ERROR(db->ctx, "Could not re-open database file\n");
		return 1;
	}

	// Rewind to the start of the file
	rewind(db->f);

	return 0;
}

static int loc_database_open(struct loc_database* db, FILE* f) {
	int r;

	clock_t start = clock();

	// Clone the file handle
	r = loc_database_clone_handle(db, f);
	if (r)
		return r;

	// Read magic bytes
	r = loc_database_check_magic(db);
	if (r)
		return r;

	// Map the database into memory
	r = loc_database_mmap(db);
	if (r)
		return r;

	// Read the header
	r = loc_database_read_header(db);
	if (r)
		return r;

	clock_t end = clock();

	INFO(db->ctx, "Opened database in %.4fms\n",
		(double)(end - start) / CLOCKS_PER_SEC * 1000);

	return 0;
}

static void loc_database_free(struct loc_database* db) {
	int r;

	DEBUG(db->ctx, "Releasing database %p\n", db);

	// Unmap the entire database
	if (db->data) {
		r = munmap(db->data, db->length);
		if (r)
			ERROR(db->ctx, "Could not unmap the database: %m\n");
	}

	// Free the stringpool
	if (db->pool)
		loc_stringpool_unref(db->pool);

	// Close database file
	if (db->f)
		fclose(db->f);

	loc_unref(db->ctx);
	free(db);
}

LOC_EXPORT int loc_database_new(struct loc_ctx* ctx, struct loc_database** database, FILE* f) {
	struct loc_database* db = NULL;
	int r = 1;

	// Fail on invalid file handle
	if (!f) {
		errno = EINVAL;
		return 1;
	}

	// Allocate the database object
	db = calloc(1, sizeof(*db));
	if (!db)
		goto ERROR;

	// Reference context
	db->ctx = loc_ref(ctx);
	db->refcount = 1;

	DEBUG(db->ctx, "Database object allocated at %p\n", db);

	// Try to open the database
	r = loc_database_open(db, f);
	if (r)
		goto ERROR;

	*database = db;
	return 0;

ERROR:
	if (db)
		loc_database_free(db);

	return r;
}

LOC_EXPORT struct loc_database* loc_database_ref(struct loc_database* db) {
	db->refcount++;

	return db;
}

LOC_EXPORT struct loc_database* loc_database_unref(struct loc_database* db) {
	if (--db->refcount > 0)
		return NULL;

	loc_database_free(db);
	return NULL;
}

LOC_EXPORT int loc_database_verify(struct loc_database* db, FILE* f) {
	size_t bytes_read = 0;

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

		return -1;
	}

	int r = 0;

	EVP_MD_CTX* mdctx = EVP_MD_CTX_new();

	// Initialise hash function
	r = EVP_DigestVerifyInit(mdctx, NULL, NULL, NULL, pkey);
	if (r != 1) {
		ERROR(db->ctx, "Error initializing signature validation: %s\n",
			ERR_error_string(ERR_get_error(), NULL));
		r = 1;

		goto CLEANUP;
	}

	// Reset file to start
	rewind(db->f);

	// Read magic
	struct loc_database_magic magic;
	bytes_read = fread(&magic, 1, sizeof(magic), db->f);
	if (bytes_read < sizeof(magic)) {
		ERROR(db->ctx, "Could not read header: %m\n");
		r = 1;
		goto CLEANUP;
	}

	hexdump(db->ctx, &magic, sizeof(magic));

	// Feed magic into the hash
	r = EVP_DigestVerifyUpdate(mdctx, &magic, sizeof(magic));
	if (r != 1) {
		ERROR(db->ctx, "%s\n", ERR_error_string(ERR_get_error(), NULL));
		r = 1;

		goto CLEANUP;
	}

	// Read the header
	struct loc_database_header_v1 header_v1;

	switch (db->version) {
		case LOC_DATABASE_VERSION_1:
			bytes_read = fread(&header_v1, 1, sizeof(header_v1), db->f);
			if (bytes_read < sizeof(header_v1)) {
				ERROR(db->ctx, "Could not read header\n");
				r = 1;

				goto CLEANUP;
			}

			// Clear signatures
			memset(header_v1.signature1, '\0', sizeof(header_v1.signature1));
			header_v1.signature1_length = 0;
			memset(header_v1.signature2, '\0', sizeof(header_v1.signature2));
			header_v1.signature2_length = 0;

			hexdump(db->ctx, &header_v1, sizeof(header_v1));

			// Feed header into the hash
			r = EVP_DigestVerifyUpdate(mdctx, &header_v1, sizeof(header_v1));
			if (r != 1) {
				ERROR(db->ctx, "%s\n", ERR_error_string(ERR_get_error(), NULL));
				r = 1;

				goto CLEANUP;
			}
			break;

		default:
			ERROR(db->ctx, "Cannot compute hash for database with format %d\n",
				db->version);
			r = -EINVAL;
			goto CLEANUP;
	}

	// Walk through the file in chunks of 64kB
	char buffer[64 * 1024];

	while (!feof(db->f)) {
		bytes_read = fread(buffer, 1, sizeof(buffer), db->f);

		hexdump(db->ctx, buffer, bytes_read);

		r = EVP_DigestVerifyUpdate(mdctx, buffer, bytes_read);
		if (r != 1) {
			ERROR(db->ctx, "%s\n", ERR_error_string(ERR_get_error(), NULL));
			r = 1;

			goto CLEANUP;
		}
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
			r = -1;
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
			r = -1;
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
	EVP_MD_CTX_free(mdctx);
	EVP_PKEY_free(pkey);

	return r;
}

LOC_EXPORT time_t loc_database_created_at(struct loc_database* db) {
	return db->created_at;
}

LOC_EXPORT const char* loc_database_get_vendor(struct loc_database* db) {
	return loc_stringpool_get(db->pool, db->vendor);
}

LOC_EXPORT const char* loc_database_get_description(struct loc_database* db) {
	return loc_stringpool_get(db->pool, db->description);
}

LOC_EXPORT const char* loc_database_get_license(struct loc_database* db) {
	return loc_stringpool_get(db->pool, db->license);
}

LOC_EXPORT size_t loc_database_count_as(struct loc_database* db) {
	return db->as_objects.count;
}

// Returns the AS at position pos
static int loc_database_fetch_as(struct loc_database* db, struct loc_as** as, off_t pos) {
	struct loc_database_as_v1* as_v1 = NULL;
	int r;

	if ((size_t)pos >= db->as_objects.count) {
		errno = ERANGE;
		return 1;
	}

	DEBUG(db->ctx, "Fetching AS at position %jd\n", (intmax_t)pos);

	switch (db->version) {
		case LOC_DATABASE_VERSION_1:
			// Find the object
			as_v1 = (struct loc_database_as_v1*)loc_database_object(db,
				&db->as_objects, sizeof(*as_v1), pos);
			if (!as_v1)
				return 1;

			r = loc_as_new_from_database_v1(db->ctx, db->pool, as, as_v1);
			break;

		default:
			errno = ENOTSUP;
			return 1;
	}

	if (r == 0)
		DEBUG(db->ctx, "Got AS%u\n", loc_as_get_number(*as));

	return r;
}

// Performs a binary search to find the AS in the list
LOC_EXPORT int loc_database_get_as(struct loc_database* db, struct loc_as** as, uint32_t number) {
	off_t lo = 0;
	off_t hi = db->as_objects.count - 1;

#ifdef ENABLE_DEBUG
	// Save start time
	clock_t start = clock();
#endif

	while (lo <= hi) {
		off_t i = (lo + hi) / 2;

		// Fetch AS in the middle between lo and hi
		int r = loc_database_fetch_as(db, as, i);
		if (r)
			return r;

		// Check if this is a match
		uint32_t as_number = loc_as_get_number(*as);
		if (as_number == number) {
#ifdef ENABLE_DEBUG
			clock_t end = clock();

			// Log how fast this has been
			DEBUG(db->ctx, "Found AS%u in %.4fms\n", as_number,
				(double)(end - start) / CLOCKS_PER_SEC * 1000);
#endif

			return 0;
		}

		// If it wasn't, we release the AS and
		// adjust our search pointers
		loc_as_unref(*as);

		if (as_number < number) {
			lo = i + 1;
		} else
			hi = i - 1;
	}

	// Nothing found
	*as = NULL;

	return 1;
}

// Returns the network at position pos
static int loc_database_fetch_network(struct loc_database* db, struct loc_network** network,
		struct in6_addr* address, unsigned int prefix, off_t pos) {
	struct loc_database_network_v1* network_v1 = NULL;
	int r;

	if ((size_t)pos >= db->network_objects.count) {
		DEBUG(db->ctx, "Network ID out of range: %jd/%jd\n",
			(intmax_t)pos, (intmax_t)db->network_objects.count);
		errno = ERANGE;
		return 1;
	}

	DEBUG(db->ctx, "Fetching network at position %jd\n", (intmax_t)pos);

	switch (db->version) {
		case LOC_DATABASE_VERSION_1:
			// Read the object
			network_v1 = (struct loc_database_network_v1*)loc_database_object(db,
				&db->network_objects, sizeof(*network_v1), pos);
			if (!network_v1)
				return 1;

			r = loc_network_new_from_database_v1(db->ctx, network, address, prefix, network_v1);
			break;

		default:
			errno = ENOTSUP;
			return 1;
	}

	if (r == 0)
		DEBUG(db->ctx, "Got network %s\n", loc_network_str(*network));

	return r;
}

static int __loc_database_node_is_leaf(const struct loc_database_network_node_v1* node) {
	return (node->network != htobe32(0xffffffff));
}

static int __loc_database_lookup_handle_leaf(struct loc_database* db, const struct in6_addr* address,
		struct loc_network** network, struct in6_addr* network_address, unsigned int prefix,
		const struct loc_database_network_node_v1* node) {
	off_t network_index = be32toh(node->network);

	DEBUG(db->ctx, "Handling leaf node at %jd\n", (intmax_t)network_index);

	// Fetch the network
	int r = loc_database_fetch_network(db, network, network_address, prefix, network_index);
	if (r) {
		ERROR(db->ctx, "Could not fetch network %jd from database: %m\n",
			(intmax_t)network_index);
		return r;
	}

	// Check if the given IP address is inside the network
	if (!loc_network_matches_address(*network, address)) {
		DEBUG(db->ctx, "Searched address is not part of the network\n");

		loc_network_unref(*network);
		*network = NULL;
		return 1;
	}

	// A network was found and the IP address matches
	return 0;
}

// Searches for an exact match along the path
static int __loc_database_lookup(struct loc_database* db, const struct in6_addr* address,
		struct loc_network** network, struct in6_addr* network_address,
		off_t node_index, unsigned int level) {
	struct loc_database_network_node_v1* node_v1 = NULL;

	int r;

	// Fetch the next node
	node_v1 = (struct loc_database_network_node_v1*)loc_database_object(db,
		&db->network_node_objects, sizeof(*node_v1), node_index);
	if (!node_v1)
		return 1;

	// Follow the path
	int bit = loc_address_get_bit(address, level);
	loc_address_set_bit(network_address, level, bit);

	if (bit == 0)
		node_index = be32toh(node_v1->zero);
	else
		node_index = be32toh(node_v1->one);

	// If the node index is zero, the tree ends here
	// and we cannot descend any further
	if (node_index > 0) {
		// Check boundaries
		if ((size_t)node_index >= db->network_node_objects.count) {
			errno = ERANGE;
			return 1;
		}

		// Move on to the next node
		r = __loc_database_lookup(db, address, network, network_address, node_index, level + 1);

		// End here if a result was found
		if (r == 0)
			return r;

		// Raise any errors
		else if (r < 0)
			return r;

		DEBUG(db->ctx, "No match found below level %u\n", level);
	} else {
		DEBUG(db->ctx, "Tree ended at level %u\n", level);
	}

	// If this node has a leaf, we will check if it matches
	if (__loc_database_node_is_leaf(node_v1)) {
		r = __loc_database_lookup_handle_leaf(db, address, network, network_address, level, node_v1);
		if (r <= 0)
			return r;
	}

	return 1;
}

LOC_EXPORT int loc_database_lookup(struct loc_database* db,
		const struct in6_addr* address, struct loc_network** network) {
	struct in6_addr network_address;
	memset(&network_address, 0, sizeof(network_address));

	*network = NULL;

#ifdef ENABLE_DEBUG
	// Save start time
	clock_t start = clock();
#endif

	int r = __loc_database_lookup(db, address, network, &network_address, 0, 0);

#ifdef ENABLE_DEBUG
	clock_t end = clock();

	// Log how fast this has been
	DEBUG(db->ctx, "Executed network search in %.4fms\n",
		(double)(end - start) / CLOCKS_PER_SEC * 1000);
#endif

	return r;
}

LOC_EXPORT int loc_database_lookup_from_string(struct loc_database* db,
		const char* string, struct loc_network** network) {
	struct in6_addr address;

	int r = loc_address_parse(&address, NULL, string);
	if (r)
		return r;

	return loc_database_lookup(db, &address, network);
}

// Returns the country at position pos
static int loc_database_fetch_country(struct loc_database* db,
		struct loc_country** country, off_t pos) {
	struct loc_database_country_v1* country_v1 = NULL;
	int r;

	// Check if the country is within range
	if ((size_t)pos >= db->country_objects.count) {
		errno = ERANGE;
		return 1;
	}

	DEBUG(db->ctx, "Fetching country at position %jd\n", (intmax_t)pos);

	switch (db->version) {
		case LOC_DATABASE_VERSION_1:
			// Read the object
			country_v1 = (struct loc_database_country_v1*)loc_database_object(db,
				&db->country_objects, sizeof(*country_v1), pos);
			if (!country_v1)
				return 1;

			r = loc_country_new_from_database_v1(db->ctx, db->pool, country, country_v1);
			break;

		default:
			errno = ENOTSUP;
			return 1;
	}

	if (r == 0)
		DEBUG(db->ctx, "Got country %s\n", loc_country_get_code(*country));

	return r;
}

// Performs a binary search to find the country in the list
LOC_EXPORT int loc_database_get_country(struct loc_database* db,
		struct loc_country** country, const char* code) {
	off_t lo = 0;
	off_t hi = db->country_objects.count - 1;

	// Check if the country code is valid
	if (!loc_country_code_is_valid(code)) {
		errno = EINVAL;
		return 1;
	}

#ifdef ENABLE_DEBUG
	// Save start time
	clock_t start = clock();
#endif

	while (lo <= hi) {
		off_t i = (lo + hi) / 2;

		// Fetch country in the middle between lo and hi
		int r = loc_database_fetch_country(db, country, i);
		if (r)
			return r;

		// Check if this is a match
		const char* cc = loc_country_get_code(*country);
		int result = strcmp(code, cc);

		if (result == 0) {
#ifdef ENABLE_DEBUG
			clock_t end = clock();

			// Log how fast this has been
			DEBUG(db->ctx, "Found country %s in %.4fms\n", cc,
				(double)(end - start) / CLOCKS_PER_SEC * 1000);
#endif

			return 0;
		}

		// If it wasn't, we release the country and
		// adjust our search pointers
		loc_country_unref(*country);

		if (result > 0) {
			lo = i + 1;
		} else
			hi = i - 1;
	}

	// Nothing found
	*country = NULL;

	return 0;
}

// Enumerator

static void loc_database_enumerator_free(struct loc_database_enumerator* enumerator) {
	DEBUG(enumerator->ctx, "Releasing database enumerator %p\n", enumerator);

	// Release all references
	loc_database_unref(enumerator->db);
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
		struct loc_database* db, enum loc_database_enumerator_mode mode, int flags) {
	int r;

	struct loc_database_enumerator* e = calloc(1, sizeof(*e));
	if (!e) {
		return -ENOMEM;
	}

	// Reference context
	e->ctx = loc_ref(db->ctx);
	e->db = loc_database_ref(db);
	e->mode = mode;
	e->refcount = 1;

	// Flatten output?
	e->flatten = (flags & LOC_DB_ENUMERATOR_FLAGS_FLATTEN);

	// Initialise graph search
	e->network_stack_depth = 1;
	e->networks_visited = calloc(db->network_node_objects.count, sizeof(*e->networks_visited));
	if (!e->networks_visited) {
		ERROR(db->ctx, "Could not allocated visited networks: %m\n");
		r = 1;
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
	enumerator->refcount++;

	return enumerator;
}

LOC_EXPORT struct loc_database_enumerator* loc_database_enumerator_unref(struct loc_database_enumerator* enumerator) {
	if (!enumerator)
		return NULL;

	if (--enumerator->refcount > 0)
		return enumerator;

	loc_database_enumerator_free(enumerator);
	return NULL;
}

LOC_EXPORT int loc_database_enumerator_set_string(struct loc_database_enumerator* enumerator, const char* string) {
	enumerator->string = strdup(string);

	// Make the string lowercase
	for (char *p = enumerator->string; p && *p; p++)
		*p = tolower(*p);

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
	if (enumerator->countries)
		loc_country_list_unref(enumerator->countries);

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
	if (enumerator->asns)
		loc_as_list_unref(enumerator->asns);

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

	struct loc_database* db = enumerator->db;

	while (enumerator->as_index < db->as_objects.count) {
		// Fetch the next AS
		int r = loc_database_fetch_as(db, as, enumerator->as_index++);
		if (r)
			return r;

		r = loc_as_match_string(*as, enumerator->string);
		if (r == 1) {
			DEBUG(enumerator->ctx, "AS%d (%s) matches %s\n",
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

static int loc_database_enumerator_stack_push_node(
		struct loc_database_enumerator* e, off_t offset, int i, int depth) {
	// Do not add empty nodes
	if (!offset)
		return 0;

	// Check if there is any space left on the stack
	if (e->network_stack_depth >= MAX_STACK_DEPTH) {
		ERROR(e->ctx, "Maximum stack size reached: %d\n", e->network_stack_depth);
		return 1;
	}

	// Check if the node is in range
	if (offset >= (off_t)e->db->network_node_objects.count) {
		ERROR(e->ctx, "Trying to add invalid node with offset %jd/%zu\n",
			(intmax_t)offset, (size_t)e->db->network_node_objects.count);
		errno = ERANGE;
		return 1;
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

		if (loc_country_list_contains_code(enumerator->countries, country_code)) {
			DEBUG(enumerator->ctx, "Matched network %p because of its country code\n", network);
			return 1;
		}
	}

	// Check if the ASN matches
	if (enumerator->asns && !loc_as_list_empty(enumerator->asns)) {
		uint32_t asn = loc_network_get_asn(network);

		if (loc_as_list_contains_number(enumerator->asns, asn)) {
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

	DEBUG(enumerator->ctx, "Called with a stack of %u nodes\n",
		enumerator->network_stack_depth);

	// Perform DFS
	while (enumerator->network_stack_depth > 0) {
		DEBUG(enumerator->ctx, "Stack depth: %u\n", enumerator->network_stack_depth);

		// Get object from top of the stack
		struct loc_node_stack* node = &enumerator->network_stack[enumerator->network_stack_depth];

		DEBUG(enumerator->ctx, "  Got node: %jd\n", (intmax_t)node->offset);

		// Remove the node from the stack if we have already visited it
		if (enumerator->networks_visited[node->offset]) {
			enumerator->network_stack_depth--;
			continue;
		}

		// Mark the bits on the path correctly
		loc_address_set_bit(&enumerator->network_address,
			(node->depth > 0) ? node->depth - 1 : 0, node->i);

		DEBUG(enumerator->ctx, "Looking at node %jd\n", (intmax_t)node->offset);
		enumerator->networks_visited[node->offset]++;

		// Pop node from top of the stack
		struct loc_database_network_node_v1* n =
			(struct loc_database_network_node_v1*)loc_database_object(enumerator->db,
				&enumerator->db->network_node_objects, sizeof(*n), node->offset);
		if (!n)
			return 1;

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
	// Fetch the next network
	int r = __loc_database_enumerator_next_network(enumerator, network, 1);
	if (r)
		return r;

	// End if we could not read another network
	if (!*network)
		return 0;

	struct loc_network* subnet = NULL;

	// Create a list with all subnets
	if (!enumerator->subnets) {
		r = loc_network_list_new(enumerator->ctx, &enumerator->subnets);
		if (r)
			return r;
	}

	// Search all subnets from the database
	while (1) {
		// Fetch the next network in line
		r = __loc_database_enumerator_next_network(enumerator, &subnet, 0);
		if (r) {
			loc_network_unref(subnet);
			loc_network_list_clear(enumerator->subnets);

			return r;
		}

		// End if we did not receive another subnet
		if (!subnet)
			break;

		// Collect all subnets in a list
		if (loc_network_is_subnet(*network, subnet)) {
			r = loc_network_list_push(enumerator->subnets, subnet);
			if (r) {
				loc_network_unref(subnet);
				loc_network_list_clear(enumerator->subnets);

				return r;
			}

			loc_network_unref(subnet);
			continue;
		}

		// If this is not a subnet, we push it back onto the stack and break
		r = loc_network_list_push(enumerator->stack, subnet);
		if (r) {
			loc_network_unref(subnet);
			loc_network_list_clear(enumerator->subnets);

			return r;
		}

		loc_network_unref(subnet);
		break;
	}

	DEBUG(enumerator->ctx, "Found %zu subnet(s)\n",
		loc_network_list_size(enumerator->subnets));

	// We can abort here if the network has no subnets
	if (loc_network_list_empty(enumerator->subnets)) {
		loc_network_list_clear(enumerator->subnets);

		return 0;
	}

	// If the network has any subnets, we will break it into smaller parts
	// without the subnets.
	struct loc_network_list* excluded = loc_network_exclude_list(*network, enumerator->subnets);
	if (!excluded) {
		loc_network_list_clear(enumerator->subnets);
		return 1;
	}

	// Merge subnets onto the stack
	r = loc_network_list_merge(enumerator->stack, enumerator->subnets);
	if (r) {
		loc_network_list_clear(enumerator->subnets);
		loc_network_list_unref(excluded);

		return r;
	}

	// Push excluded list onto the stack
	r = loc_network_list_merge(enumerator->stack, excluded);
	if (r) {
		loc_network_list_clear(enumerator->subnets);
		loc_network_list_unref(excluded);

		return r;
	}

	loc_network_list_clear(enumerator->subnets);
	loc_network_list_unref(excluded);

	// Drop the network and restart the whole process again to pick the next network
	loc_network_unref(*network);

	return __loc_database_enumerator_next_network_flattened(enumerator, network);
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
				errno = ENOTSUP;
				return 1;
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

	struct loc_database* db = enumerator->db;

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
