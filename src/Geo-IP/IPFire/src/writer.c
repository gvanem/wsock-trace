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

#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef HAVE_ENDIAN_H
#  include <endian.h>
#endif

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>

#include <libloc/libloc.h>
#include <libloc/address.h>
#include <libloc/as.h>
#include <libloc/compat.h>
#include <libloc/country.h>
#include <libloc/country-list.h>
#include <libloc/database.h>
#include <libloc/format.h>
#include <libloc/network.h>
#include <libloc/network-tree.h>
#include <libloc/private.h>
#include <libloc/writer.h>

struct loc_writer {
	struct loc_ctx* ctx;
	loc_refcount_t refcount;

	struct loc_stringpool* pool;
	off_t vendor;
	off_t description;
	off_t license;

	// Private keys to sign any databases
	EVP_PKEY* private_key1;
	EVP_PKEY* private_key2;

	// Signatures
	char signature1[LOC_SIGNATURE_MAX_LENGTH];
	size_t signature1_length;
	char signature2[LOC_SIGNATURE_MAX_LENGTH];
	size_t signature2_length;

	struct loc_network_tree* networks;

	// All ASes, sorted by their number
	struct loc_as** ases;
	size_t num_ases;
	size_t ases_size;

	struct loc_country_list* country_list;
};

static int parse_private_key(struct loc_writer* writer, EVP_PKEY** private_key, FILE* f) {
	// Free any previously loaded keys
	if (*private_key)
		EVP_PKEY_free(*private_key);

	// Read the key
	*private_key = PEM_read_PrivateKey(f, NULL, NULL, NULL);

	// Log any errors
	if (!*private_key) {
		char* error = ERR_error_string(ERR_get_error(), NULL);
		ERROR(writer->ctx, "Could not parse private key: %s\n", error);

		return -EINVAL;
	}

	return 0;
}

LOC_EXPORT int loc_writer_new(struct loc_ctx* ctx, struct loc_writer** writer,
		FILE* fkey1, FILE* fkey2) {
	struct loc_writer* w = calloc(1, sizeof(*w));
	if (!w)
		return -ENOMEM;

	w->ctx = loc_ref(ctx);
	w->refcount = 1;

	int r = loc_stringpool_new(ctx, &w->pool);
	if (r) {
		loc_writer_unref(w);
		return r;
	}

	// Add an empty string to the stringpool
	r = loc_stringpool_add(w->pool, "");
	if (r < 0) {
		loc_writer_unref(w);
		return r;
	}

	// Initialize the network tree
	r = loc_network_tree_new(ctx, &w->networks);
	if (r) {
		loc_writer_unref(w);
		return r;
	}

	// Initialize countries list
	r = loc_country_list_new(ctx, &w->country_list);
	if (r) {
		loc_writer_unref(w);
		return r;
	}

	// Load the private keys to sign databases
	if (fkey1) {
		r = parse_private_key(w, &w->private_key1, fkey1);
		if (r) {
			loc_writer_unref(w);
			return r;
		}
	}

	if (fkey2) {
		r = parse_private_key(w, &w->private_key2, fkey2);
		if (r) {
			loc_writer_unref(w);
			return r;
		}
	}

	*writer = w;
	return 0;
}

LOC_EXPORT struct loc_writer* loc_writer_ref(struct loc_writer* writer) {
	loc_refcount_inc(&writer->refcount);

	return writer;
}

static void loc_writer_free(struct loc_writer* writer) {
	DEBUG(writer->ctx, "Releasing writer at %p\n", writer);

	// Free private keys
	if (writer->private_key1)
		EVP_PKEY_free(writer->private_key1);
	if (writer->private_key2)
		EVP_PKEY_free(writer->private_key2);

	// Unref all AS
	if (writer->ases) {
		for (size_t i = 0; i < writer->num_ases; i++)
			loc_as_unref(writer->ases[i]);

		free(writer->ases);
	}

	// Unref all countries
	if (writer->country_list)
		loc_country_list_unref(writer->country_list);

	// Release network tree
	if (writer->networks)
		loc_network_tree_unref(writer->networks);

	// Unref the string pool
	if (writer->pool)
		loc_stringpool_unref(writer->pool);

	loc_unref(writer->ctx);
	free(writer);
}

LOC_EXPORT struct loc_writer* loc_writer_unref(struct loc_writer* writer) {
	if (loc_refcount_dec(&writer->refcount) > 0)
		return writer;

	loc_writer_free(writer);

	return NULL;
}

LOC_EXPORT const char* loc_writer_get_vendor(struct loc_writer* writer) {
	return loc_stringpool_get(writer->pool, writer->vendor);
}

LOC_EXPORT int loc_writer_set_vendor(struct loc_writer* writer, const char* vendor) {
	// Add the string to the string pool
	off_t offset = loc_stringpool_add(writer->pool, vendor);
	if (offset < 0)
		return offset;

	writer->vendor = offset;
	return 0;
}

LOC_EXPORT const char* loc_writer_get_description(struct loc_writer* writer) {
	return loc_stringpool_get(writer->pool, writer->description);
}

LOC_EXPORT int loc_writer_set_description(struct loc_writer* writer, const char* description) {
	// Add the string to the string pool
	off_t offset = loc_stringpool_add(writer->pool, description);
	if (offset < 0)
		return offset;

	writer->description = offset;
	return 0;
}

LOC_EXPORT const char* loc_writer_get_license(struct loc_writer* writer) {
	return loc_stringpool_get(writer->pool, writer->license);
}

LOC_EXPORT int loc_writer_set_license(struct loc_writer* writer, const char* license) {
	// Add the string to the string pool
	off_t offset = loc_stringpool_add(writer->pool, license);
	if (offset < 0)
		return offset;

	writer->license = offset;
	return 0;
}

/*
	Returns where the AS with number is, or where it would have to go
*/
static size_t loc_writer_find_as(struct loc_writer* writer, uint32_t number, int* found) {
	size_t lo = 0;
	size_t hi = writer->num_ases;

	*found = 0;

	while (lo < hi) {
		size_t i = lo + (hi - lo) / 2;

		const uint32_t n = loc_as_get_number(writer->ases[i]);

		if (n < number) {
			lo = i + 1;

		} else if (n > number) {
			hi = i;

		} else {
			*found = 1;
			return i;
		}
	}

	return lo;
}

LOC_EXPORT int loc_writer_add_as(struct loc_writer* writer, struct loc_as** as, uint32_t number) {
	struct loc_as** ases = NULL;
	int found = 0;
	int r;

	// Find where the AS goes
	const size_t index = loc_writer_find_as(writer, number, &found);

	// Return the AS if it has been added before
	if (found) {
		*as = loc_as_ref(writer->ases[index]);
		return 0;
	}

	// Make space for more ASes
	if (writer->num_ases >= writer->ases_size) {
		size_t size = 1024;

		if (writer->ases_size)
			size = writer->ases_size * 2;

		ases = reallocarray(writer->ases, size, sizeof(*writer->ases));
		if (!ases)
			return -errno;

		writer->ases = ases;
		writer->ases_size = size;
	}

	// Create a new AS object
	r = loc_as_new(writer->ctx, as, number);
	if (r)
		return r;

	// Move all ASes with a larger number out of the way. The importer adds them in
	// order, so that there usually is nothing to move.
	memmove(writer->ases + index + 1, writer->ases + index,
		sizeof(*writer->ases) * (writer->num_ases - index));

	writer->ases[index] = loc_as_ref(*as);
	writer->num_ases++;

	return 0;
}

LOC_EXPORT int loc_writer_add_network(struct loc_writer* writer, struct loc_network** network, const char* string) {
	int r;

	// Create a new network object
	r = loc_network_new_from_string(writer->ctx, network, string);
	if (r)
		return r;

	// Add it to the local tree
	r = loc_network_tree_add_network(writer->networks, *network);
	if (r) {
		loc_network_unref(*network);
		*network = NULL;
	}

	return r;
}

LOC_EXPORT int loc_writer_add_country(struct loc_writer* writer, struct loc_country** country, const char* country_code) {
	// Return the country if it has been added before
	if (loc_country_code_is_valid(country_code)) {
		for (size_t i = 0; i < loc_country_list_size(writer->country_list); i++) {
			*country = loc_country_list_get(writer->country_list, i);

			if (strcmp(loc_country_get_code(*country), country_code) == 0)
				return 0;

			loc_country_unref(*country);
		}
	}

	// Allocate a new country
	int r = loc_country_new(writer->ctx, country, country_code);
	if (r)
		return r;

	// Append it to the list
	r = loc_country_list_append(writer->country_list, *country);
	if (r) {
		loc_country_unref(*country);
		*country = NULL;
	}

	return r;
}

static void make_magic(struct loc_writer* writer, struct loc_database_magic* magic,
		enum loc_database_version version) {
	// Copy magic bytes
	for (unsigned int i = 0; i < strlen(LOC_DATABASE_MAGIC); i++)
		magic->magic[i] = LOC_DATABASE_MAGIC[i];

	// Set version
	magic->version = version;
}

static void align_page_boundary(off_t* offset, FILE* f) {
	// Move to next page boundary
	while (*offset % LOC_DATABASE_PAGE_SIZE > 0)
		*offset += fwrite("", 1, 1, f);
}

static int loc_database_write_pool(struct loc_writer* writer,
		struct loc_database_header_v1* header, off_t* offset, FILE* f) {
	// Save the offset of the pool section
	DEBUG(writer->ctx, "Pool starts at %jd bytes\n", (intmax_t)*offset);
	header->pool_offset = htobe32(*offset);

	// Write the pool
	size_t pool_length = loc_stringpool_write(writer->pool, f);
	*offset += pool_length;

	DEBUG(writer->ctx, "Pool has a length of %zu bytes\n", pool_length);
	header->pool_length = htobe32(pool_length);

	return 0;
}

static int loc_database_write_as_section(struct loc_writer* writer,
		struct loc_database_header_v1* header, off_t* offset, FILE* f) {
	DEBUG(writer->ctx, "AS section starts at %jd bytes\n", (intmax_t)*offset);
	header->as_offset = htobe32(*offset);

	struct loc_database_as_v1 block = { 0 };
	size_t block_length = 0;
	int r;

	// The ASes are sorted already
	for (size_t i = 0; i < writer->num_ases; i++) {
		// Convert AS into database format
		r = loc_as_to_database_v1(writer->ases[i], writer->pool, &block);
		if (r)
			return r;

		// Write to disk
		*offset += fwrite(&block, 1, sizeof(block), f);
		block_length += sizeof(block);
	}

	DEBUG(writer->ctx, "AS section has a length of %zu bytes\n", block_length);
	header->as_length = htobe32(block_length);

	align_page_boundary(offset, f);

	return 0;
}

/*
	The nodes of the tree are being written depth-first, so that a node is
	followed by its first child, and that child by its own first child.
	A lookup walks down the tree one bit at a time, and this way, it often
	finds the next node in the same cache line, or in the next one.

	The nodes that still have to be written are kept on a stack. Every level
	of the tree leaves at most one of them waiting for the others, so that
	the stack can never be deeper than the tree.
*/
struct node {
	struct loc_network_tree_node* node;

	// The index of the parent, and which of its children this node is
	uint32_t parent;
	int bit;
};

#define NODE_STACK_SIZE (LOC_ADDRESS_MAX_BITS + 2)

/*
	Many networks have the same country, ASN and flags. The address and the
	prefix are part of the tree, so that networks with the same data can all
	point to the same object, which we find in a hash table.
*/
struct network_data {
	struct loc_database_network_v1* objects;
	size_t num_objects;
	size_t objects_size;

	// Slots hold the index of an object plus one, or zero if they are free
	uint32_t* slots;
	size_t num_slots;
};

static size_t network_data_hash(const struct loc_database_network_v1* object) {
	const unsigned char* p = (const unsigned char*)object;
	size_t hash = 2166136261u;

	// FNV-1a
	for (size_t i = 0; i < sizeof(*object); i++) {
		hash ^= p[i];
		hash *= 16777619u;
	}

	return hash;
}

// Returns the slot that holds the object, or the free slot where it belongs
static uint32_t* network_data_slot(struct network_data* data,
		const struct loc_database_network_v1* object) {
	size_t i = network_data_hash(object) & (data->num_slots - 1);

	for (;;) {
		uint32_t* slot = &data->slots[i];

		if (!*slot)
			return slot;

		if (memcmp(&data->objects[*slot - 1], object, sizeof(*object)) == 0)
			return slot;

		i = (i + 1) & (data->num_slots - 1);
	}
}

static int network_data_grow(struct network_data* data) {
	size_t num_slots = 1024;

	if (data->num_slots)
		num_slots = data->num_slots * 2;

	uint32_t* slots = calloc(num_slots, sizeof(*slots));
	if (!slots)
		return -ENOMEM;

	free(data->slots);

	data->slots = slots;
	data->num_slots = num_slots;

	// Put all objects into the new slots
	for (size_t i = 0; i < data->num_objects; i++)
		*network_data_slot(data, &data->objects[i]) = i + 1;

	return 0;
}

// Stores the index of an object with the same data in index, and adds it if there is none
static int network_data_add(struct network_data* data,
		const struct loc_database_network_v1* object, uint32_t* index) {
	int r;

	// Keep at least half of the slots free
	if (data->num_objects * 2 >= data->num_slots) {
		r = network_data_grow(data);
		if (r)
			return r;
	}

	uint32_t* slot = network_data_slot(data, object);

	// We have this one already
	if (*slot) {
		*index = *slot - 1;
		return 0;
	}

	if (data->num_objects == data->objects_size) {
		size_t size = 1024;

		if (data->objects_size)
			size = data->objects_size * 2;

		struct loc_database_network_v1* objects = reallocarray(data->objects,
			size, sizeof(*objects));
		if (!objects)
			return -ENOMEM;

		data->objects = objects;
		data->objects_size = size;
	}

	memcpy(&data->objects[data->num_objects], object, sizeof(*object));
	*index = data->num_objects++;
	*slot = *index + 1;

	return 0;
}

static void network_data_free(struct network_data* data) {
	free(data->objects);
	free(data->slots);
}

static int loc_database_write_networks(struct loc_writer* writer,
		struct loc_database_header_v1* header, off_t* offset, FILE* f) {
	int r;

	// Write the network tree
	DEBUG(writer->ctx, "Network tree starts at %jd bytes\n", (intmax_t)*offset);
	header->network_tree_offset = htobe32(*offset);

	size_t network_tree_length = 0;
	size_t network_data_length = 0;

	uint32_t network_index = 0;

	struct loc_database_network_v1 db_network = { 0 };

	// The nodes that we have to write next
	struct node nodes[NODE_STACK_SIZE];
	unsigned int num_nodes = 0;

	// The nodes that we have written
	struct loc_database_network_node_v1* tree = NULL;
	size_t tree_length = 0;
	size_t tree_size = 0;

	// The data of all networks
	struct network_data networks = { 0 };

	// Cleanup the tree before writing it
	r = loc_network_tree_cleanup(writer->networks);
	if (r)
		return r;

	// Start with the root
	nodes[num_nodes++] = (struct node){
		.node = loc_network_tree_get_root(writer->networks),
		.bit  = -1,
	};

	// Take the last node from the stack until it is empty
	while (num_nodes) {
		struct node node = nodes[--num_nodes];

		DEBUG(writer->ctx, "Processing node %p\n", node.node);

		// Make space for the node
		if (tree_length == tree_size) {
			size_t size = 1024;

			if (tree_size)
				size = tree_size * 2;

			struct loc_database_network_node_v1* t = reallocarray(tree, size, sizeof(*tree));
			if (!t) {
				loc_network_tree_node_unref(node.node);
				r = -ENOMEM;
				goto ERROR;
			}

			tree = t;
			tree_size = size;
		}

		const uint32_t index = tree_length++;

		struct loc_database_network_node_v1* db_node = &tree[index];

		// The children will tell us where they are
		db_node->zero = 0;
		db_node->one  = 0;

		// Tell the parent where we are
		switch (node.bit) {
			case 0:
				tree[node.parent].zero = htobe32(index);
				break;

			case 1:
				tree[node.parent].one = htobe32(index);
				break;
		}

		if (loc_network_tree_node_is_leaf(node.node)) {
			struct loc_network* network = loc_network_tree_node_get_network(node.node);

			// The padding is being compared, too
			memset(&db_network, 0, sizeof(db_network));

			// Find the data of the network, or add it to be written out later
			r = loc_network_to_database_v1(network, &db_network);
			if (!r)
				r = network_data_add(&networks, &db_network, &network_index);

			loc_network_unref(network);

			if (r) {
				loc_network_tree_node_unref(node.node);
				goto ERROR;
			}

			db_node->network = htobe32(network_index);
		} else {
			db_node->network = htobe32(0xffffffff);
		}

		// Put the second child on the stack first, so that the first one comes next
		for (int bit = 1; bit >= 0; bit--) {
			struct loc_network_tree_node* child = loc_network_tree_node_get(node.node, bit);
			if (!child)
				continue;

			// This cannot happen with a tree that is not deeper than an address is long
			if (num_nodes == NODE_STACK_SIZE) {
				loc_network_tree_node_unref(child);
				loc_network_tree_node_unref(node.node);
				r = -EINVAL;
				goto ERROR;
			}

			nodes[num_nodes++] = (struct node){
				.node   = child,
				.parent = index,
				.bit    = bit,
			};
	}

		loc_network_tree_node_unref(node.node);
	}

	// Write the tree
	*offset += fwrite(tree, 1, sizeof(*tree) * tree_length, f);
	network_tree_length += sizeof(*tree) * tree_length;

	header->network_tree_length = htobe32(network_tree_length);

	align_page_boundary(offset, f);

	DEBUG(writer->ctx, "Networks data section starts at %jd bytes\n", (intmax_t)*offset);
	header->network_data_offset = htobe32(*offset);

	// We have now written the entire tree and have the data of all networks
	// in the order in which they are indexed
	for (size_t i = 0; i < networks.num_objects; i++) {
		*offset += fwrite(&networks.objects[i], 1, sizeof(*networks.objects), f);
		network_data_length += sizeof(*networks.objects);
	}

	header->network_data_length = htobe32(network_data_length);

	align_page_boundary(offset, f);

	// Success
	r = 0;

ERROR:
	// Free everything that is left on the stack
	while (num_nodes)
		loc_network_tree_node_unref(nodes[--num_nodes].node);

	network_data_free(&networks);
	free(tree);

	return r;
}

static int loc_database_write_countries(struct loc_writer* writer,
		struct loc_database_header_v1* header, off_t* offset, FILE* f) {
	DEBUG(writer->ctx, "Countries section starts at %jd bytes\n", (intmax_t)*offset);
	header->countries_offset = htobe32(*offset);

	// Sort the countries first as we are going to search for them
	loc_country_list_sort(writer->country_list);

	const size_t countries_count = loc_country_list_size(writer->country_list);
	int r;

	struct loc_database_country_v1 block = { 0 };
	size_t block_length = 0;

	for (unsigned int i = 0; i < countries_count; i++) {
		struct loc_country* country = loc_country_list_get(writer->country_list, i);
		if (!country)
			return -ENOENT;

		// Convert country into database format
		r = loc_country_to_database_v1(country, writer->pool, &block);
		if (r) {
			loc_country_unref(country);
			return r;
		}

		// Write to disk
		*offset += fwrite(&block, 1, sizeof(block), f);
		block_length += sizeof(block);

		// Unref country
		loc_country_unref(country);
	}

	DEBUG(writer->ctx, "Countries section has a length of %zu bytes\n", block_length);
	header->countries_length = htobe32(block_length);

	align_page_boundary(offset, f);

	return 0;
}

static int loc_writer_create_signature(struct loc_writer* writer,
		struct loc_database_header_v1* header, FILE* f, EVP_PKEY* private_key,
		char* signature, size_t* length) {
	size_t bytes_read = 0;

	DEBUG(writer->ctx, "Creating signature...\n");

	// Read file from the beginning
	int r = fseek(f, 0, SEEK_SET);
	if (r) {
		ERROR(writer->ctx, "Could not seek to the beginning of the database: %s\n", strerror(errno));
		return -errno;
	}

	// Create a new context for signing
	EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
	if (!mdctx)
		return -ENOMEM;

	// Initialise the context. We sign using SHA-256, which is what the
	// databases are being verified with.
	r = EVP_DigestSignInit(mdctx, NULL, EVP_sha256(), NULL, private_key);
	if (r != 1) {
		ERROR(writer->ctx, "%s\n", ERR_error_string(ERR_get_error(), NULL));
		r = -EIO;
		goto END;
	}
	(void) mdctx;

	// Read magic
	struct loc_database_magic magic;
	bytes_read = fread(&magic, 1, sizeof(magic), f);
	if (bytes_read < sizeof(magic)) {
		ERROR(writer->ctx, "Could not read header: %s\n", strerror(errno));
		r = -EIO;
		goto END;
	}

	hexdump(writer->ctx, &magic, sizeof(magic));

	// Feed magic into the signature
	r = EVP_DigestSignUpdate(mdctx, &magic, sizeof(magic));
	if (r != 1) {
		ERROR(writer->ctx, "%s\n", ERR_error_string(ERR_get_error(), NULL));
		r = -EIO;
		goto END;
	}

	hexdump(writer->ctx, header, sizeof(*header));

	// Feed the header into the signature
	r = EVP_DigestSignUpdate(mdctx, header, sizeof(*header));
	if (r != 1) {
		ERROR(writer->ctx, "%s\n", ERR_error_string(ERR_get_error(), NULL));
		r = -EIO;
		goto END;
	}

	// Skip header
	r = fseek(f, sizeof(*header), SEEK_CUR);
	if (r) {
		ERROR(writer->ctx, "Could not skip the header: %s\n", strerror(errno));
		r = -errno;
		goto END;
	}

	// Walk through the file in chunks of 64kB
	char buffer[64 * 1024];
	while (!feof(f)) {
		bytes_read = fread(buffer, 1, sizeof(buffer), f);

		if (ferror(f)) {
			ERROR(writer->ctx, "Error reading from file: %s\n", strerror(errno));
			r = -EIO;
			goto END;
		}

		hexdump(writer->ctx, buffer, bytes_read);

		r = EVP_DigestSignUpdate(mdctx, buffer, bytes_read);
		if (r != 1) {
			ERROR(writer->ctx, "%s\n", ERR_error_string(ERR_get_error(), NULL));
			r = -EIO;
			goto END;
		}
	}

	// Compute the signature
	r = EVP_DigestSignFinal(mdctx,
		(unsigned char*)signature, length);
	if (r != 1) {
		ERROR(writer->ctx, "%s\n", ERR_error_string(ERR_get_error(), NULL));
		r = -EIO;
		goto END;
	}

	DEBUG(writer->ctx, "Successfully generated signature of %zu bytes\n", *length);
	r = 0;

	// Dump signature
	hexdump(writer->ctx, signature, *length);

END:
	EVP_MD_CTX_free(mdctx);

	return r;
}

LOC_EXPORT int loc_writer_write(struct loc_writer* writer, FILE* f, enum loc_database_version version) {
	size_t bytes_written = 0;

	// Check version
	switch (version) {
		case LOC_DATABASE_VERSION_UNSET:
			version = LOC_DATABASE_VERSION_LATEST;
			break;

		case LOC_DATABASE_VERSION_1:
			break;

		default:
			ERROR(writer->ctx, "Invalid database version: %u\n", version);
			return -ENOTSUP;
	}

	DEBUG(writer->ctx, "Writing database in version %u\n", version);

	struct loc_database_magic magic = { 0 };
	make_magic(writer, &magic, version);

	// Make the header
	struct loc_database_header_v1 header = { 0 };
	header.vendor      = htobe32(writer->vendor);
	header.description = htobe32(writer->description);
	header.license     = htobe32(writer->license);

	time_t now = time(NULL);
	header.created_at = htobe64(now);

	// Clear the signatures
	memset(header.signature1, '\0', sizeof(header.signature1));
	header.signature1_length = 0;
	memset(header.signature2, '\0', sizeof(header.signature2));
	header.signature2_length = 0;

	// Clear the padding
	memset(header.padding, '\0', sizeof(header.padding));

	int r;
	off_t offset = 0;

	// Start writing at the beginning of the file
	r = fseek(f, 0, SEEK_SET);
	if (r)
		return -errno;

	// Write the magic
	offset += fwrite(&magic, 1, sizeof(magic), f);

	// Skip the space we need to write the header later
	r = fseek(f, sizeof(header), SEEK_CUR);
	if (r) {
		DEBUG(writer->ctx, "Could not seek to position after header\n");
		return -errno;
	}
	offset += sizeof(header);

	align_page_boundary(&offset, f);

	// Write all ASes
	r = loc_database_write_as_section(writer, &header, &offset, f);
	if (r)
		return r;

	// Write all networks
	r = loc_database_write_networks(writer, &header, &offset, f);
	if (r)
		return r;

	// Write countries
	r = loc_database_write_countries(writer, &header, &offset, f);
	if (r)
		return r;

	// Write pool
	r = loc_database_write_pool(writer, &header, &offset, f);
	if (r)
		return r;

	// Create the signatures
	if (writer->private_key1) {
		DEBUG(writer->ctx, "Creating signature with first private key\n");

		writer->signature1_length = sizeof(writer->signature1);

		r = loc_writer_create_signature(writer, &header, f,
			writer->private_key1, writer->signature1, &writer->signature1_length);
		if (r)
			return r;
	}

	if (writer->private_key2) {
		DEBUG(writer->ctx, "Creating signature with second private key\n");

		writer->signature2_length = sizeof(writer->signature2);

		r = loc_writer_create_signature(writer, &header, f,
			writer->private_key2, writer->signature2, &writer->signature2_length);
		if (r)
			return r;
	}

	// Copy the signatures into the header
	if (writer->signature1_length) {
		DEBUG(writer->ctx, "Copying first signature of %zu byte(s)\n",
			writer->signature1_length);

		memcpy(header.signature1, writer->signature1, writer->signature1_length);
		header.signature1_length = htobe16(writer->signature1_length);
	}

	if (writer->signature2_length) {
		DEBUG(writer->ctx, "Copying second signature of %zu byte(s)\n",
			writer->signature2_length);

		memcpy(header.signature2, writer->signature2, writer->signature2_length);
		header.signature2_length = htobe16(writer->signature2_length);
	}

	// Write the header
	r = fseek(f, sizeof(magic), SEEK_SET);
	if (r)
		return -errno;

	bytes_written = fwrite(&header, 1, sizeof(header), f);
	if (bytes_written < sizeof(header)) {
		ERROR(writer->ctx, "Could not write header: %s\n", strerror(errno));
		return -EIO;
	}

	// Seek back to the end
	r = fseek(f, 0, SEEK_END);
	if (r)
		return -errno;

	// Flush everything and fail if anything could not be written
	r = fflush(f);
	if (r || ferror(f)) {
		ERROR(writer->ctx, "Could not write the database: %s\n", strerror(errno));
		return -EIO;
	}

	return 0;
}
