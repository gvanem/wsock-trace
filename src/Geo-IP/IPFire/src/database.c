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

#ifndef _WIN32
#  include <arpa/inet.h>
#  include <netinet/in.h>
#endif

#ifdef HAVE_ENDIAN_H
#  include <endian.h>
#endif

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>

#include <loc/libloc.h>
#include <loc/as.h>
#include <loc/as-list.h>
#include <loc/compat.h>
#include <loc/country.h>
#include <loc/country-list.h>
#include <loc/database.h>
#include <loc/format.h>
#include <loc/network.h>
#include <loc/private.h>
#include <loc/stringpool.h>

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
	char* signature1;
	size_t signature1_length;
	char* signature2;
	size_t signature2_length;

	// ASes in the database
	struct loc_database_as_v1* as_v1;
	size_t as_count;

	// Network tree
	struct loc_database_network_node_v1* network_nodes_v1;
	size_t network_nodes_count;

	// Networks
	struct loc_database_network_v1* networks_v1;
	size_t networks_count;

	// Countries
	struct loc_database_country_v1* countries_v1;
	size_t countries_count;

	struct loc_stringpool* pool;
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

	// For subnet search
	struct loc_network_list* stack;
};

static int loc_database_read_magic(struct loc_database* db) {
	struct loc_database_magic magic;

	// Read from file
	size_t bytes_read = fread(&magic, 1, sizeof(magic), db->f);

	// Check if we have been able to read enough data
	if (bytes_read < sizeof(magic)) {
		ERROR(db->ctx, "Could not read enough data to validate magic bytes\n");
		DEBUG(db->ctx, "Read %zu bytes, but needed %zu\n", bytes_read, sizeof(magic));
		return -ENOMSG;
	}

	// Compare magic bytes
	if (memcmp(LOC_DATABASE_MAGIC, magic.magic, strlen(LOC_DATABASE_MAGIC)) == 0) {
		DEBUG(db->ctx, "Magic value matches\n");

		// Parse version
		db->version = magic.version;

		return 0;
	}

	ERROR(db->ctx, "Unrecognized file type\n");

	// Return an error
	return 1;
}

static int loc_database_read_as_section_v1(struct loc_database* db,
		const struct loc_database_header_v1* header) {
	off_t as_offset  = be32toh(header->as_offset);
	size_t as_length = be32toh(header->as_length);

	DEBUG(db->ctx, "Reading AS section from %jd (%zu bytes)\n", (intmax_t)as_offset, as_length);

	if (as_length > 0) {
		db->as_v1 = mmap(NULL, as_length, PROT_READ,
			MAP_SHARED, fileno(db->f), as_offset);

		if (db->as_v1 == MAP_FAILED)
			return -errno;
	}

	db->as_count = as_length / sizeof(*db->as_v1);

	INFO(db->ctx, "Read %zu ASes from the database\n", db->as_count);

	return 0;
}

static int loc_database_read_network_nodes_section_v1(struct loc_database* db,
		const struct loc_database_header_v1* header) {
	off_t network_nodes_offset  = be32toh(header->network_tree_offset);
	size_t network_nodes_length = be32toh(header->network_tree_length);

	DEBUG(db->ctx, "Reading network nodes section from %jd (%zu bytes)\n",
		(intmax_t)network_nodes_offset, network_nodes_length);

	if (network_nodes_length > 0) {
		db->network_nodes_v1 = mmap(NULL, network_nodes_length, PROT_READ,
			MAP_SHARED, fileno(db->f), network_nodes_offset);

		if (db->network_nodes_v1 == MAP_FAILED)
			return -errno;
	}

	db->network_nodes_count = network_nodes_length / sizeof(*db->network_nodes_v1);

	INFO(db->ctx, "Read %zu network nodes from the database\n", db->network_nodes_count);

	return 0;
}

static int loc_database_read_networks_section_v1(struct loc_database* db,
		const struct loc_database_header_v1* header) {
	off_t networks_offset  = be32toh(header->network_data_offset);
	size_t networks_length = be32toh(header->network_data_length);

	DEBUG(db->ctx, "Reading networks section from %jd (%zu bytes)\n",
		(intmax_t)networks_offset, networks_length);

	if (networks_length > 0) {
		db->networks_v1 = mmap(NULL, networks_length, PROT_READ,
			MAP_SHARED, fileno(db->f), networks_offset);

		if (db->networks_v1 == MAP_FAILED)
			return -errno;
	}

	db->networks_count = networks_length / sizeof(*db->networks_v1);

	INFO(db->ctx, "Read %zu networks from the database\n", db->networks_count);

	return 0;
}

static int loc_database_read_countries_section_v1(struct loc_database* db,
		const struct loc_database_header_v1* header) {
	off_t countries_offset  = be32toh(header->countries_offset);
	size_t countries_length = be32toh(header->countries_length);

	DEBUG(db->ctx, "Reading countries section from %jd (%zu bytes)\n",
		(intmax_t)countries_offset, countries_length);

	if (countries_length > 0) {
		db->countries_v1 = mmap(NULL, countries_length, PROT_READ,
			MAP_SHARED, fileno(db->f), countries_offset);

		if (db->countries_v1 == MAP_FAILED)
			return -errno;
	}

	db->countries_count = countries_length / sizeof(*db->countries_v1);

	INFO(db->ctx, "Read %zu countries from the database\n",
		db->countries_count);

	return 0;
}

static int loc_database_read_signature(struct loc_database* db,
		char** dst, char* src, size_t length) {
	// Check for a plausible signature length
	if (length > LOC_SIGNATURE_MAX_LENGTH) {
		ERROR(db->ctx, "Signature too long: %u\n", length);
		return -EINVAL;
	}

	DEBUG(db->ctx, "Reading signature of %u bytes\n", length);

	// Allocate space
	*dst = malloc(length);
	if (!*dst)
		return -ENOMEM;

	// Copy payload
	memcpy(*dst, src, length);

	return 0;
}

static int loc_database_read_header_v1(struct loc_database* db) {
	struct loc_database_header_v1 header;
	int r;

	// Read from file
	size_t size = fread(&header, 1, sizeof(header), db->f);

	if (size < sizeof(header)) {
		ERROR(db->ctx, "Could not read enough data for header\n");
		return -ENOMSG;
	}

	// Copy over data
	db->created_at  = be64toh(header.created_at);
	db->vendor      = be32toh(header.vendor);
	db->description = be32toh(header.description);
	db->license     = be32toh(header.license);

	db->signature1_length = be16toh(header.signature1_length);
	db->signature2_length = be16toh(header.signature2_length);

	// Read signatures
	if (db->signature1_length) {
		r = loc_database_read_signature(db, &db->signature1,
			header.signature1, db->signature1_length);
		if (r)
			return r;
	}

	if (db->signature2_length) {
		r = loc_database_read_signature(db, &db->signature2,
			header.signature2, db->signature2_length);
		if (r)
			return r;
	}

	// Open pool
	off_t pool_offset  = be32toh(header.pool_offset);
	size_t pool_length = be32toh(header.pool_length);

	r = loc_stringpool_open(db->ctx, &db->pool,
		db->f, pool_length, pool_offset);
	if (r)
		return r;

	// AS section
	r = loc_database_read_as_section_v1(db, &header);
	if (r)
		return r;

	// Network Nodes
	r = loc_database_read_network_nodes_section_v1(db, &header);
	if (r)
		return r;

	// Networks
	r = loc_database_read_networks_section_v1(db, &header);
	if (r)
		return r;

	// countries
	r = loc_database_read_countries_section_v1(db, &header);
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

static int loc_database_read(struct loc_database* db, FILE* f) {
	clock_t start = clock();

	int fd = fileno(f);

	// Clone file descriptor
	fd = dup(fd);
	if (!fd) {
		ERROR(db->ctx, "Could not duplicate file descriptor\n");
		return -1;
	}

	// Reopen the file so that we can keep our own file handle
	db->f = fdopen(fd, "rb");
	if (!db->f) {
		ERROR(db->ctx, "Could not re-open database file\n");
		return -1;
	}

	// Rewind to the start of the file
	rewind(db->f);

	// Read magic bytes
	int r = loc_database_read_magic(db);
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

LOC_EXPORT int loc_database_new(struct loc_ctx* ctx, struct loc_database** database, FILE* f) {
	// Fail on invalid file handle
	if (!f)
		return -EINVAL;

	struct loc_database* db = calloc(1, sizeof(*db));
	if (!db)
		return -ENOMEM;

	// Reference context
	db->ctx = loc_ref(ctx);
	db->refcount = 1;

	DEBUG(db->ctx, "Database object allocated at %p\n", db);

	int r = loc_database_read(db, f);
	if (r) {
		loc_database_unref(db);
		return r;
	}

	*database = db;

	return 0;
}

LOC_EXPORT struct loc_database* loc_database_ref(struct loc_database* db) {
	db->refcount++;

	return db;
}

static void loc_database_free(struct loc_database* db) {
	int r;

	DEBUG(db->ctx, "Releasing database %p\n", db);

	// Removing all ASes
	if (db->as_v1) {
		r = munmap(db->as_v1, db->as_count * sizeof(*db->as_v1));
		if (r)
			ERROR(db->ctx, "Could not unmap AS section: %s\n", strerror(errno));
	}

	// Remove mapped network sections
	if (db->networks_v1) {
		r = munmap(db->networks_v1, db->networks_count * sizeof(*db->networks_v1));
		if (r)
			ERROR(db->ctx, "Could not unmap networks section: %s\n", strerror(errno));
	}

	// Remove mapped network nodes section
	if (db->network_nodes_v1) {
		r = munmap(db->network_nodes_v1, db->network_nodes_count * sizeof(*db->network_nodes_v1));
		if (r)
			ERROR(db->ctx, "Could not unmap network nodes section: %s\n", strerror(errno));
	}

	if (db->pool)
		loc_stringpool_unref(db->pool);

	// Free signature
	if (db->signature1)
		free(db->signature1);
	if (db->signature2)
		free(db->signature2);

	// Close database file
	if (db->f)
		fclose(db->f);

	loc_unref(db->ctx);
	free(db);
}

LOC_EXPORT struct loc_database* loc_database_unref(struct loc_database* db) {
	if (--db->refcount > 0)
		return NULL;

	loc_database_free(db);
	return NULL;
}

LOC_EXPORT int loc_database_verify(struct loc_database* db, FILE* f) {
	// Cannot do this when no signature is available
	if (!db->signature1 && !db->signature2) {
		DEBUG(db->ctx, "No signature available to verify\n");
		return 1;
	}

	// Start the stopwatch
	clock_t start = clock();

	// Load public key
	EVP_PKEY* pkey = PEM_read_PUBKEY(f, NULL, NULL, NULL);
	if (!pkey) {
		char* error = ERR_error_string(ERR_get_error(), NULL);
		ERROR(db->ctx, "Could not parse public key: %s\n", error);

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
	fread(&magic, 1, sizeof(magic), db->f);

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
	size_t bytes_read;

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

	// Check first signature
	if (db->signature1) {
		hexdump(db->ctx, db->signature1, db->signature1_length);

		r = EVP_DigestVerifyFinal(mdctx,
			(unsigned char*)db->signature1, db->signature1_length);

		if (r == 0) {
			DEBUG(db->ctx, "The first signature is invalid\n");
			r = 1;
		} else if (r == 1) {
			DEBUG(db->ctx, "The first signature is valid\n");
			r = 0;
		} else {
			ERROR(db->ctx, "Error verifying the first signature: %s\n",
				ERR_error_string(ERR_get_error(), NULL));
			r = -1;
		}
	}

	// Check second signature only when the first one was invalid
	if (r && db->signature2) {
		hexdump(db->ctx, db->signature2, db->signature2_length);

		r = EVP_DigestVerifyFinal(mdctx,
			(unsigned char*)db->signature2, db->signature2_length);

		if (r == 0) {
			DEBUG(db->ctx, "The second signature is invalid\n");
			r = 1;
		} else if (r == 1) {
			DEBUG(db->ctx, "The second signature is valid\n");
			r = 0;
		} else {
			ERROR(db->ctx, "Error verifying the second signature: %s\n",
				ERR_error_string(ERR_get_error(), NULL));
			r = -1;
		}
	}

	clock_t end = clock();
	DEBUG(db->ctx, "Signature checked in %.4fms\n",
		(double)(end - start) / CLOCKS_PER_SEC * 1000);

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
	return db->as_count;
}

// Returns the AS at position pos
static int loc_database_fetch_as(struct loc_database* db, struct loc_as** as, off_t pos) {
	if ((size_t)pos >= db->as_count)
		return -EINVAL;

	DEBUG(db->ctx, "Fetching AS at position %jd\n", (intmax_t)pos);

	int r;
	switch (db->version) {
		case LOC_DATABASE_VERSION_1:
			r = loc_as_new_from_database_v1(db->ctx, db->pool, as, db->as_v1 + pos);
			break;

		default:
			return -1;
	}

	if (r == 0) {
		DEBUG(db->ctx, "Got AS%u\n", loc_as_get_number(*as));
	}

	return r;
}

// Performs a binary search to find the AS in the list
LOC_EXPORT int loc_database_get_as(struct loc_database* db, struct loc_as** as, uint32_t number) {
	off_t lo = 0;
	off_t hi = db->as_count - 1;

	// Save start time
	clock_t start = clock();

	while (lo <= hi) {
		off_t i = (lo + hi) / 2;

		// Fetch AS in the middle between lo and hi
		int r = loc_database_fetch_as(db, as, i);
		if (r)
			return r;

		// Check if this is a match
		uint32_t as_number = loc_as_get_number(*as);
		if (as_number == number) {
			clock_t end = clock();

			// Log how fast this has been
			DEBUG(db->ctx, "Found AS%u in %.4fms\n", as_number,
				(double)(end - start) / CLOCKS_PER_SEC * 1000);

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
	if ((size_t)pos >= db->networks_count) {
		DEBUG(db->ctx, "Network ID out of range: %jd/%jd\n",
			(intmax_t)pos, (intmax_t)db->networks_count);
		return -EINVAL;
	}


	DEBUG(db->ctx, "Fetching network at position %jd\n", (intmax_t)pos);

	int r;
	switch (db->version) {
		case LOC_DATABASE_VERSION_1:
			r = loc_network_new_from_database_v1(db->ctx, network,
				address, prefix, db->networks_v1 + pos);
			break;

		default:
			return -1;
	}

	if (r == 0) {
		char* string = loc_network_str(*network);
		DEBUG(db->ctx, "Got network %s\n", string);
		free(string);
	}

	return r;
}

static int __loc_database_node_is_leaf(const struct loc_database_network_node_v1* node) {
	return (node->network != htobe32(0xffffffff));
}

static int __loc_database_lookup_handle_leaf(struct loc_database* db, const struct in6_addr* address,
		struct loc_network** network, struct in6_addr* network_address, unsigned int prefix,
		const struct loc_database_network_node_v1* node) {
	off_t network_index = be32toh(node->network);

	DEBUG(db->ctx, "Handling leaf node at %jd (%jd)\n", (intmax_t)(node - db->network_nodes_v1), (intmax_t)network_index);

	// Fetch the network
	int r = loc_database_fetch_network(db, network,
		network_address, prefix, network_index);
	if (r) {
		ERROR(db->ctx, "Could not fetch network %jd from database\n", (intmax_t)network_index);
		return r;
	}

	// Check if the given IP address is inside the network
	r = loc_network_match_address(*network, address);
	if (r) {
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
		const struct loc_database_network_node_v1* node, unsigned int level) {
	int r;
	off_t node_index;

	// Follow the path
	int bit = in6_addr_get_bit(address, level);
	in6_addr_set_bit(network_address, level, bit);

	if (bit == 0)
		node_index = be32toh(node->zero);
	else
		node_index = be32toh(node->one);

	// If the node index is zero, the tree ends here
	// and we cannot descend any further
	if (node_index > 0) {
		// Check boundaries
		if ((size_t)node_index >= db->network_nodes_count)
			return -EINVAL;

		// Move on to the next node
		r = __loc_database_lookup(db, address, network, network_address,
			db->network_nodes_v1 + node_index, level + 1);

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
	if (__loc_database_node_is_leaf(node)) {
		r = __loc_database_lookup_handle_leaf(db, address, network, network_address, level, node);
		if (r <= 0)
			return r;
	}

	return -ENODATA;
}

LOC_EXPORT int loc_database_lookup(struct loc_database* db,
		struct in6_addr* address, struct loc_network** network) {
	struct in6_addr network_address;
	memset(&network_address, 0, sizeof(network_address));

	*network = NULL;

	// Save start time
	clock_t start = clock();

	int r = __loc_database_lookup(db, address, network, &network_address,
		db->network_nodes_v1, 0);

	clock_t end = clock();

	// Log how fast this has been
	DEBUG(db->ctx, "Executed network search in %.4fms\n",
		(double)(end - start) / CLOCKS_PER_SEC * 1000);

	return r;
}

LOC_EXPORT int loc_database_lookup_from_string(struct loc_database* db,
		const char* string, struct loc_network** network) {
	struct in6_addr address;

	int r = loc_parse_address(db->ctx, string, &address);
	if (r)
		return r;

	return loc_database_lookup(db, &address, network);
}

// Returns the country at position pos
static int loc_database_fetch_country(struct loc_database* db,
		struct loc_country** country, off_t pos) {
	if ((size_t)pos >= db->countries_count)
		return -EINVAL;

	DEBUG(db->ctx, "Fetching country at position %jd\n", (intmax_t)pos);

	int r;
	switch (db->version) {
		case LOC_DATABASE_VERSION_1:
			r = loc_country_new_from_database_v1(db->ctx, db->pool, country, db->countries_v1 + pos);
			break;

		default:
			return -1;
	}

	if (r == 0) {
		DEBUG(db->ctx, "Got country %s\n", loc_country_get_code(*country));
	}

	return r;
}

// Performs a binary search to find the country in the list
LOC_EXPORT int loc_database_get_country(struct loc_database* db,
		struct loc_country** country, const char* code) {
	off_t lo = 0;
	off_t hi = db->countries_count - 1;

	// Save start time
	clock_t start = clock();

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
			clock_t end = clock();

			// Log how fast this has been
			DEBUG(db->ctx, "Found country %s in %.4fms\n", cc,
				(double)(end - start) / CLOCKS_PER_SEC * 1000);

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

	return 1;
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
	free(enumerator->networks_visited);

	// Free subnet stack
	if (enumerator->stack)
		loc_network_list_unref(enumerator->stack);

	free(enumerator);
}

LOC_EXPORT int loc_database_enumerator_new(struct loc_database_enumerator** enumerator,
		struct loc_database* db, enum loc_database_enumerator_mode mode, int flags) {
	struct loc_database_enumerator* e = calloc(1, sizeof(*e));
	if (!e)
		return -ENOMEM;

	// Reference context
	e->ctx = loc_ref(db->ctx);
	e->db = loc_database_ref(db);
	e->mode = mode;
	e->refcount = 1;

	// Flatten output?
	e->flatten = (flags & LOC_DB_ENUMERATOR_FLAGS_FLATTEN);

	// Initialise graph search
	e->network_stack_depth = 1;
	e->networks_visited = calloc(db->network_nodes_count, sizeof(*e->networks_visited));

	// Allocate stack
	int r = loc_network_list_new(e->ctx, &e->stack);
	if (r) {
		loc_database_enumerator_free(e);
		return r;
	}

	DEBUG(e->ctx, "Database enumerator object allocated at %p\n", e);

	*enumerator = e;
	return 0;
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
	for (char *p = enumerator->string; *p; p++)
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

	while (enumerator->as_index < db->as_count) {
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
		return -1;
	}

	// Increase stack size
	int s = ++e->network_stack_depth;

	DEBUG(e->ctx, "Added node %jd to stack (%d)\n", (intmax_t)offset, depth);

	e->network_stack[s].offset = offset;
	e->network_stack[s].i = i;
	e->network_stack[s].depth = depth;

	return 0;
}

static int loc_database_enumerator_filter_network(
		struct loc_database_enumerator* enumerator, struct loc_network* network) {
	// Skip if the family does not match
	if (enumerator->family && loc_network_address_family(network) != enumerator->family) {
		DEBUG(enumerator->ctx, "Filtered network %p because of family not matching\n", network);
		return 1;
	}

	// Skip if the country code does not match
	if (enumerator->countries && !loc_country_list_empty(enumerator->countries)) {
		const char* country_code = loc_network_get_country_code(network);

		if (!loc_country_list_contains_code(enumerator->countries, country_code)) {
			DEBUG(enumerator->ctx, "Filtered network %p because of country code not matching\n", network);
			return 1;
		}
	}

	// Skip if the ASN does not match
	if (enumerator->asns && !loc_as_list_empty(enumerator->asns)) {
		uint32_t asn = loc_network_get_asn(network);

		if (!loc_as_list_contains_number(enumerator->asns, asn)) {
			DEBUG(enumerator->ctx, "Filtered network %p because of ASN not matching\n", network);
			return 1;
		}
	}

	// Skip if flags do not match
	if (enumerator->flags && !loc_network_match_flag(network, enumerator->flags)) {
		DEBUG(enumerator->ctx, "Filtered network %p because of flags not matching\n", network);
		return 1;
	}

	// Do not filter
	return 0;
}

static int __loc_database_enumerator_next_network(
		struct loc_database_enumerator* enumerator, struct loc_network** network, int filter) {
	// Return top element from the stack
	while (1) {
		*network = loc_network_list_pop(enumerator->stack);

		// Stack is empty
		if (!*network)
			break;

		// Throw away any networks by filter
		if (filter && loc_database_enumerator_filter_network(enumerator, *network)) {
			loc_network_unref(*network);
			*network = NULL;
			continue;
		}

		// Return result
		return 0;
	}

	DEBUG(enumerator->ctx, "Called with a stack of %u nodes\n",
		enumerator->network_stack_depth);

	// Perform DFS
	while (enumerator->network_stack_depth > 0) {
		DEBUG(enumerator->ctx, "Stack depth: %u\n", enumerator->network_stack_depth);

		// Get object from top of the stack
		struct loc_node_stack* node = &enumerator->network_stack[enumerator->network_stack_depth];

		// Remove the node from the stack if we have already visited it
		if (enumerator->networks_visited[node->offset]) {
			enumerator->network_stack_depth--;
			continue;
		}

		// Mark the bits on the path correctly
		in6_addr_set_bit(&enumerator->network_address,
			(node->depth > 0) ? node->depth - 1 : 0, node->i);

		DEBUG(enumerator->ctx, "Looking at node %jd\n", (intmax_t)node->offset);
		enumerator->networks_visited[node->offset]++;

		// Pop node from top of the stack
		struct loc_database_network_node_v1* n =
			enumerator->db->network_nodes_v1 + node->offset;

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

			// Return all networks when the filter is disabled
			if (!filter)
				return 0;

			// Check if we are interested in this network
			if (loc_database_enumerator_filter_network(enumerator, *network)) {
				loc_network_unref(*network);
				*network = NULL;

				continue;
			}

			return 0;
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
	struct loc_network_list* subnets;

	// Create a list with all subnets
	r = loc_network_list_new(enumerator->ctx, &subnets);
	if (r)
		return r;

	// Search all subnets from the database
	while (1) {
		// Fetch the next network in line
		r = __loc_database_enumerator_next_network(enumerator, &subnet, 0);
		if (r)
			goto END;

		// End if we did not receive another subnet
		if (!subnet)
			break;

		// Collect all subnets in a list
		if (loc_network_is_subnet(*network, subnet)) {
			r = loc_network_list_push(subnets, subnet);
			if (r)
				goto END;

			loc_network_unref(subnet);
			continue;
		}

		// If this is not a subnet, we push it back onto the stack and break
		r = loc_network_list_push(enumerator->stack, subnet);
		if (r)
			goto END;

		loc_network_unref(subnet);
		break;
	}

	DEBUG(enumerator->ctx, "Found %zu subnet(s)\n", loc_network_list_size(subnets));

	// We can abort here if the network has no subnets
	if (loc_network_list_empty(subnets)) {
		loc_network_list_unref(subnets);

		return 0;
	}

	// If the network has any subnets, we will break it into smaller parts
	// without the subnets.
	struct loc_network_list* excluded = loc_network_exclude_list(*network, subnets);
	if (!excluded || loc_network_list_empty(excluded)) {
		r = 1;
		goto END;
	}

	// Replace network with the first one
	loc_network_unref(*network);

	*network = loc_network_list_pop_first(excluded);

	// Push the rest onto the stack
	loc_network_list_reverse(excluded);
	loc_network_list_merge(enumerator->stack, excluded);

	loc_network_list_unref(excluded);

END:
	if (subnet)
		loc_network_unref(subnet);

	loc_network_list_unref(subnets);

	return r;
}

LOC_EXPORT int loc_database_enumerator_next_network(
		struct loc_database_enumerator* enumerator, struct loc_network** network) {
	// Do not do anything if not in network mode
	if (enumerator->mode != LOC_DB_ENUMERATE_NETWORKS)
	return 0;

	// Flatten output?
	if (enumerator->flatten)
		return __loc_database_enumerator_next_network_flattened(enumerator, network);

	return __loc_database_enumerator_next_network(enumerator, network, 1);
}

LOC_EXPORT int loc_database_enumerator_next_country(
		struct loc_database_enumerator* enumerator, struct loc_country** country) {
	*country = NULL;

	// Do not do anything if not in country mode
	if (enumerator->mode != LOC_DB_ENUMERATE_COUNTRIES)
		return 0;

	struct loc_database* db = enumerator->db;

	while (enumerator->country_index < db->countries_count) {
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
