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
#include <sys/queue.h>
#include <time.h>

#ifdef HAVE_ENDIAN_H
#  include <endian.h>
#endif

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>

#include <libloc/libloc.h>
#include <libloc/as.h>
#include <libloc/as-list.h>
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
	int refcount;

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

	struct loc_as_list* as_list;
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

		return -1;
	}

	return 0;
}

LOC_EXPORT int loc_writer_new(struct loc_ctx* ctx, struct loc_writer** writer,
		FILE* fkey1, FILE* fkey2) {
	struct loc_writer* w = calloc(1, sizeof(*w));
	if (!w)
		return 1;

	w->ctx = loc_ref(ctx);
	w->refcount = 1;

	int r = loc_stringpool_new(ctx, &w->pool);
	if (r) {
		loc_writer_unref(w);
		return r;
	}

	// Add an empty string to the stringpool
	r = loc_stringpool_add(w->pool, "");
	if (r) {
		loc_writer_unref(w);
		return r;
	}

	// Initialize the network tree
	r = loc_network_tree_new(ctx, &w->networks);
	if (r) {
		loc_writer_unref(w);
		return r;
	}

	// Initialize AS list
	r = loc_as_list_new(ctx, &w->as_list);
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
	writer->refcount++;

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
	if (writer->as_list)
		loc_as_list_unref(writer->as_list);

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
	if (--writer->refcount > 0)
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

LOC_EXPORT int loc_writer_add_as(struct loc_writer* writer, struct loc_as** as, uint32_t number) {
	// Create a new AS object
	int r = loc_as_new(writer->ctx, as, number);
	if (r)
		return r;

	// Append it to the list
	return loc_as_list_append(writer->as_list, *as);
}

LOC_EXPORT int loc_writer_add_network(struct loc_writer* writer, struct loc_network** network, const char* string) {
	int r;

	// Create a new network object
	r = loc_network_new_from_string(writer->ctx, network, string);
	if (r)
		return r;

	// Add it to the local tree
	return loc_network_tree_add_network(writer->networks, *network);
}

LOC_EXPORT int loc_writer_add_country(struct loc_writer* writer, struct loc_country** country, const char* country_code) {
	// Allocate a new country
	int r = loc_country_new(writer->ctx, country, country_code);
	if (r)
		return r;

	// Append it to the list
	return loc_country_list_append(writer->country_list, *country);
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

	// Sort the AS list first
	loc_as_list_sort(writer->as_list);

	const size_t as_count = loc_as_list_size(writer->as_list);

	struct loc_database_as_v1 block;
	size_t block_length = 0;

	for (unsigned int i = 0; i < as_count; i++) {
		struct loc_as* as = loc_as_list_get(writer->as_list, i);
		if (!as)
			return 1;

		// Convert AS into database format
		loc_as_to_database_v1(as, writer->pool, &block);

		// Write to disk
		*offset += fwrite(&block, 1, sizeof(block), f);
		block_length += sizeof(block);

		// Unref AS
		loc_as_unref(as);
	}

	DEBUG(writer->ctx, "AS section has a length of %zu bytes\n", block_length);
	header->as_length = htobe32(block_length);

	align_page_boundary(offset, f);

	return 0;
}

struct node {
	TAILQ_ENTRY(node) nodes;

	struct loc_network_tree_node* node;

	// Indices of the child nodes
	uint32_t index_zero;
	uint32_t index_one;
};

static struct node* make_node(struct loc_network_tree_node* node) {
	struct node* n = malloc(sizeof(*n));
	if (!n)
		return NULL;

	n->node  = loc_network_tree_node_ref(node);
	n->index_zero = n->index_one = 0;

	return n;
}

static void free_node(struct node* node) {
	loc_network_tree_node_unref(node->node);

	free(node);
}

struct network {
	TAILQ_ENTRY(network) networks;

	struct loc_network* network;
};

static struct network* make_network(struct loc_network* network) {
	struct network* n = malloc(sizeof(*n));
	if (!n)
		return NULL;

	n->network = loc_network_ref(network);

	return n;
}

static void free_network(struct network* network) {
	loc_network_unref(network->network);

	free(network);
}

static int loc_database_write_networks(struct loc_writer* writer,
		struct loc_database_header_v1* header, off_t* offset, FILE* f) {
	int r;

	// Write the network tree
	DEBUG(writer->ctx, "Network tree starts at %jd bytes\n", (intmax_t)*offset);
	header->network_tree_offset = htobe32(*offset);

	size_t network_tree_length = 0;
	size_t network_data_length = 0;

	struct node* node;
	struct node* child_node;

	uint32_t index = 0;
	uint32_t network_index = 0;

	struct loc_database_network_v1 db_network;
	struct loc_database_network_node_v1 db_node;

	// Initialize queue for nodes
	TAILQ_HEAD(node_t, node) nodes;
	TAILQ_INIT(&nodes);

	// Initialize queue for networks
	TAILQ_HEAD(network_t, network) networks;
	TAILQ_INIT(&networks);

	// Cleanup the tree before writing it
	r = loc_network_tree_cleanup(writer->networks);
	if (r)
		return r;

	// Add root
	struct loc_network_tree_node* root = loc_network_tree_get_root(writer->networks);
	node = make_node(root);
	if (!node)
		return 1;

	TAILQ_INSERT_TAIL(&nodes, node, nodes);

	while (!TAILQ_EMPTY(&nodes)) {
		// Pop first node in list
		node = TAILQ_FIRST(&nodes);
		TAILQ_REMOVE(&nodes, node, nodes);

		DEBUG(writer->ctx, "Processing node %p\n", node);

		// Get child nodes
		struct loc_network_tree_node* node_zero = loc_network_tree_node_get(node->node, 0);
		if (node_zero) {
			node->index_zero = ++index;

			child_node = make_node(node_zero);
			loc_network_tree_node_unref(node_zero);

			TAILQ_INSERT_TAIL(&nodes, child_node, nodes);
		}

		struct loc_network_tree_node* node_one = loc_network_tree_node_get(node->node, 1);
		if (node_one) {
			node->index_one = ++index;

			child_node = make_node(node_one);
			loc_network_tree_node_unref(node_one);

			TAILQ_INSERT_TAIL(&nodes, child_node, nodes);
		}

		// Prepare what we are writing to disk
		db_node.zero = htobe32(node->index_zero);
		db_node.one  = htobe32(node->index_one);

		if (loc_network_tree_node_is_leaf(node->node)) {
			struct loc_network* network = loc_network_tree_node_get_network(node->node);

			// Append network to be written out later
			struct network* nw = make_network(network);
			if (!nw) {
				free_node(node);
				return 1;
			}
			TAILQ_INSERT_TAIL(&networks, nw, networks);

			db_node.network = htobe32(network_index++);
			loc_network_unref(network);
		} else {
			db_node.network = htobe32(0xffffffff);
		}

		// Write the current node
		DEBUG(writer->ctx, "Writing node %p (0 = %d, 1 = %d)\n",
			node, node->index_zero, node->index_one);

		*offset += fwrite(&db_node, 1, sizeof(db_node), f);
		network_tree_length += sizeof(db_node);

		free_node(node);
	}

	loc_network_tree_node_unref(root);

	header->network_tree_length = htobe32(network_tree_length);

	align_page_boundary(offset, f);

	DEBUG(writer->ctx, "Networks data section starts at %jd bytes\n", (intmax_t)*offset);
	header->network_data_offset = htobe32(*offset);

	// We have now written the entire tree and have all networks
	// in a queue in order as they are indexed
	while (!TAILQ_EMPTY(&networks)) {
		struct network* nw = TAILQ_FIRST(&networks);
		TAILQ_REMOVE(&networks, nw, networks);

		// Prepare what we are writing to disk
		r = loc_network_to_database_v1(nw->network, &db_network);
		if (r)
			return r;

		*offset += fwrite(&db_network, 1, sizeof(db_network), f);
		network_data_length += sizeof(db_network);

		free_network(nw);
	}

	header->network_data_length = htobe32(network_data_length);

	align_page_boundary(offset, f);

	return 0;
}

static int loc_database_write_countries(struct loc_writer* writer,
		struct loc_database_header_v1* header, off_t* offset, FILE* f) {
	DEBUG(writer->ctx, "Countries section starts at %jd bytes\n", (intmax_t)*offset);
	header->countries_offset = htobe32(*offset);

	const size_t countries_count = loc_country_list_size(writer->country_list);

	struct loc_database_country_v1 block;
	size_t block_length = 0;

	for (unsigned int i = 0; i < countries_count; i++) {
		struct loc_country* country = loc_country_list_get(writer->country_list, i);

		// Convert country into database format
		loc_country_to_database_v1(country, writer->pool, &block);

		// Write to disk
		*offset += fwrite(&block, 1, sizeof(block), f);
		block_length += sizeof(block);
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
	rewind(f);

	// Create a new context for signing
	EVP_MD_CTX* mdctx = EVP_MD_CTX_new();

	// Initialise the context
	int r = EVP_DigestSignInit(mdctx, NULL, NULL, NULL, private_key);
	if (r != 1) {
		ERROR(writer->ctx, "%s\n", ERR_error_string(ERR_get_error(), NULL));
		goto END;
	}
	(void) mdctx;

	// Read magic
	struct loc_database_magic magic;
	bytes_read = fread(&magic, 1, sizeof(magic), f);
	if (bytes_read < sizeof(magic)) {
		ERROR(writer->ctx, "Could not read header: %s\n", strerror(errno));
		r = 1;
		goto END;
	}

	hexdump(writer->ctx, &magic, sizeof(magic));

	// Feed magic into the signature
	r = EVP_DigestSignUpdate(mdctx, &magic, sizeof(magic));
	if (r != 1) {
		ERROR(writer->ctx, "%s\n", ERR_error_string(ERR_get_error(), NULL));
		goto END;
	}

	hexdump(writer->ctx, header, sizeof(*header));

	// Feed the header into the signature
	r = EVP_DigestSignUpdate(mdctx, header, sizeof(*header));
	if (r != 1) {
		ERROR(writer->ctx, "%s\n", ERR_error_string(ERR_get_error(), NULL));
		goto END;
	}

	// Skip header
	fseek(f, sizeof(*header), SEEK_CUR);

	// Walk through the file in chunks of 64kB
	char buffer[64 * 1024];
	while (!feof(f)) {
		bytes_read = fread(buffer, 1, sizeof(buffer), f);

		if (ferror(f)) {
			ERROR(writer->ctx, "Error reading from file: %s\n", strerror(errno));
			r = 1;
			goto END;
		}

		hexdump(writer->ctx, buffer, bytes_read);

		r = EVP_DigestSignUpdate(mdctx, buffer, bytes_read);
		if (r != 1) {
			ERROR(writer->ctx, "%s\n", ERR_error_string(ERR_get_error(), NULL));
			r = -1;
			goto END;
		}
	}

	// Compute the signature
	r = EVP_DigestSignFinal(mdctx,
		(unsigned char*)signature, length);
	if (r != 1) {
		ERROR(writer->ctx, "%s\n", ERR_error_string(ERR_get_error(), NULL));
		r = -1;
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
			ERROR(writer->ctx, "Invalid database version: %d\n", version);
			return -1;
	}

	DEBUG(writer->ctx, "Writing database in version %d\n", version);

	struct loc_database_magic magic;
	make_magic(writer, &magic, version);

	// Make the header
	struct loc_database_header_v1 header;
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
		return r;

	// Write the magic
	offset += fwrite(&magic, 1, sizeof(magic), f);

	// Skip the space we need to write the header later
	r = fseek(f, sizeof(header), SEEK_CUR);
	if (r) {
		DEBUG(writer->ctx, "Could not seek to position after header\n");
		return r;
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
		return r;

	bytes_written = fwrite(&header, 1, sizeof(header), f);
	if (bytes_written < sizeof(header)) {
		ERROR(writer->ctx, "Could not write header: %s\n", strerror(errno));
		return r;
	}

	// Seek back to the end
	r = fseek(f, 0, SEEK_END);
	if (r)
		return r;

	// Flush everything
	fflush(f);

	return r;
}
