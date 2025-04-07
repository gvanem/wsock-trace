/*
	libloc - A library to determine the location of someone on the Internet

	Copyright (C) 2024 IPFire Development Team <info@ipfire.org>

	This library is free software; you can redistribute it and/or
	modify it under the terms of the GNU Lesser General Public
	License as published by the Free Software Foundation; either
	version 2.1 of the License, or (at your option) any later version.

	This library is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
	Lesser General Public License for more details.
*/

#include <stddef.h>
#include <stdlib.h>
#include <errno.h>

#include <libloc/libloc.h>
#include <libloc/address.h>
#include <libloc/network-tree.h>
#include <libloc/private.h>

struct loc_network_tree {
	struct loc_ctx* ctx;
	int refcount;

	struct loc_network_tree_node* root;
};

struct loc_network_tree_node {
	struct loc_ctx* ctx;
	int refcount;

	struct loc_network_tree_node* zero;
	struct loc_network_tree_node* one;

	struct loc_network* network;

	// Flags
	enum loc_network_tree_node_flags {
		NETWORK_TREE_NODE_DELETED = (1 << 0),
	} flags;
};

int loc_network_tree_new(struct loc_ctx* ctx, struct loc_network_tree** tree) {
	struct loc_network_tree* t = calloc(1, sizeof(*t));
	if (!t)
		return 1;

	t->ctx = loc_ref(ctx);
	t->refcount = 1;

	// Create the root node
	int r = loc_network_tree_node_new(ctx, &t->root);
	if (r) {
		loc_network_tree_unref(t);
		return r;
	}

	DEBUG(t->ctx, "Network tree allocated at %p\n", t);
	*tree = t;
	return 0;
}

static int loc_network_tree_node_has_flag(struct loc_network_tree_node* node, int flag) {
	return node->flags & flag;
}

struct loc_network_tree_node* loc_network_tree_get_root(struct loc_network_tree* tree) {
	return loc_network_tree_node_ref(tree->root);
}

static struct loc_network_tree_node* loc_network_tree_get_node(struct loc_network_tree_node* node, int path) {
	struct loc_network_tree_node** n = NULL;
	int r;

	switch (path) {
		case 0:
			n = &node->zero;
			break;

		case 1:
			n = &node->one;
			break;

		default:
			errno = EINVAL;
			return NULL;
	}

	// If the node existed, but has been deleted, we undelete it
	if (*n && loc_network_tree_node_has_flag(*n, NETWORK_TREE_NODE_DELETED)) {
		(*n)->flags &= ~NETWORK_TREE_NODE_DELETED;

	// If the desired node doesn't exist, yet, we will create it
	} else if (!*n) {
		r = loc_network_tree_node_new(node->ctx, n);
		if (r)
			return NULL;
	}

	return *n;
}

static struct loc_network_tree_node* loc_network_tree_get_path(struct loc_network_tree* tree, const struct in6_addr* address, unsigned int prefix) {
	struct loc_network_tree_node* node = tree->root;

	for (unsigned int i = 0; i < prefix; i++) {
		// Check if the ith bit is one or zero
		node = loc_network_tree_get_node(node, loc_address_get_bit(address, i));
	}

	return node;
}

static int __loc_network_tree_walk(struct loc_ctx* ctx, struct loc_network_tree_node* node,
		int(*filter_callback)(struct loc_network* network, void* data),
		int(*callback)(struct loc_network* network, void* data), void* data) {
	int r;

	// If the node has been deleted, don't process it
	if (loc_network_tree_node_has_flag(node, NETWORK_TREE_NODE_DELETED))
		return 0;

	// Finding a network ends the walk here
	if (node->network) {
		if (filter_callback) {
			int f = filter_callback(node->network, data);
			if (f < 0)
				return f;

			// Skip network if filter function returns value greater than zero
			if (f > 0)
				return 0;
		}

		r = callback(node->network, data);
		if (r)
			return r;
	}

	// Walk down on the left side of the tree first
	if (node->zero) {
		r = __loc_network_tree_walk(ctx, node->zero, filter_callback, callback, data);
		if (r)
			return r;
	}

	// Then walk on the other side
	if (node->one) {
		r = __loc_network_tree_walk(ctx, node->one, filter_callback, callback, data);
		if (r)
			return r;
	}

	return 0;
}

int loc_network_tree_walk(struct loc_network_tree* tree,
		int(*filter_callback)(struct loc_network* network, void* data),
		int(*callback)(struct loc_network* network, void* data), void* data) {
	return __loc_network_tree_walk(tree->ctx, tree->root, filter_callback, callback, data);
}

static void loc_network_tree_free(struct loc_network_tree* tree) {
	DEBUG(tree->ctx, "Releasing network tree at %p\n", tree);

	loc_network_tree_node_unref(tree->root);

	loc_unref(tree->ctx);
	free(tree);
}

struct loc_network_tree* loc_network_tree_unref(struct loc_network_tree* tree) {
	if (--tree->refcount > 0)
		return tree;

	loc_network_tree_free(tree);
	return NULL;
}

static int __loc_network_tree_dump(struct loc_network* network, void* data) {
	struct loc_ctx* ctx = data;

	DEBUG(ctx, "Dumping network at %p\n", network);

	const char* s = loc_network_str(network);
	if (!s)
		return 1;

	INFO(ctx, "%s\n", s);

	return 0;
}

int loc_network_tree_dump(struct loc_network_tree* tree) {
	DEBUG(tree->ctx, "Dumping network tree at %p\n", tree);

	return loc_network_tree_walk(tree, NULL, __loc_network_tree_dump, tree->ctx);
}

int loc_network_tree_add_network(struct loc_network_tree* tree, struct loc_network* network) {
	DEBUG(tree->ctx, "Adding network %p to tree %p\n", network, tree);

	const struct in6_addr* first_address = loc_network_get_first_address(network);
	const unsigned int prefix = loc_network_raw_prefix(network);

	struct loc_network_tree_node* node = loc_network_tree_get_path(tree, first_address, prefix);
	if (!node) {
		ERROR(tree->ctx, "Could not find a node\n");
		return -ENOMEM;
	}

	// Check if node has not been set before
	if (node->network) {
		DEBUG(tree->ctx, "There is already a network at this path: %s\n",
			loc_network_str(node->network));
		return -EBUSY;
	}

	// Point node to the network
	node->network = loc_network_ref(network);

	return 0;
}

static int loc_network_tree_delete_network(
		struct loc_network_tree* tree, struct loc_network* network) {
	struct loc_network_tree_node* node = NULL;

	DEBUG(tree->ctx, "Deleting network %s from tree...\n", loc_network_str(network));

	const struct in6_addr* first_address = loc_network_get_first_address(network);
		const unsigned int prefix = loc_network_raw_prefix(network);

	node = loc_network_tree_get_path(tree, first_address, prefix);
	if (!node) {
		ERROR(tree->ctx, "Network was not found in tree %s\n", loc_network_str(network));
		return 1;
	}

	// Drop the network
	if (node->network) {
		loc_network_unref(node->network);
		node->network = NULL;
	}

	// Mark the node as deleted if it was a leaf
	if (!node->zero && !node->one)
		node->flags |= NETWORK_TREE_NODE_DELETED;

	return 0;
}

static size_t __loc_network_tree_count_nodes(struct loc_network_tree_node* node) {
	size_t counter = 1;

	// Don't count deleted nodes
	if (loc_network_tree_node_has_flag(node, NETWORK_TREE_NODE_DELETED))
		return 0;

	if (node->zero)
		counter += __loc_network_tree_count_nodes(node->zero);

	if (node->one)
		counter += __loc_network_tree_count_nodes(node->one);

	return counter;
}

size_t loc_network_tree_count_nodes(struct loc_network_tree* tree) {
	return __loc_network_tree_count_nodes(tree->root);
}

int loc_network_tree_node_new(struct loc_ctx* ctx, struct loc_network_tree_node** node) {
	struct loc_network_tree_node* n = calloc(1, sizeof(*n));
	if (!n)
		return -ENOMEM;

	n->ctx = loc_ref(ctx);
	n->refcount = 1;

	n->zero = n->one = NULL;

	DEBUG(n->ctx, "Network node allocated at %p\n", n);
	*node = n;
	return 0;
}

struct loc_network_tree_node* loc_network_tree_node_ref(struct loc_network_tree_node* node) {
	if (node)
		node->refcount++;

	return node;
}

static void loc_network_tree_node_free(struct loc_network_tree_node* node) {
	DEBUG(node->ctx, "Releasing network node at %p\n", node);

	if (node->network)
		loc_network_unref(node->network);

	if (node->zero)
		loc_network_tree_node_unref(node->zero);

	if (node->one)
		loc_network_tree_node_unref(node->one);

	loc_unref(node->ctx);
	free(node);
}

struct loc_network_tree_node* loc_network_tree_node_unref(struct loc_network_tree_node* node) {
	if (--node->refcount > 0)
		return node;

	loc_network_tree_node_free(node);
	return NULL;
}

struct loc_network_tree_node* loc_network_tree_node_get(struct loc_network_tree_node* node, unsigned int index) {
	if (index == 0)
		node = node->zero;
	else
		node = node->one;

	if (!node)
		return NULL;

	return loc_network_tree_node_ref(node);
}

int loc_network_tree_node_is_leaf(struct loc_network_tree_node* node) {
	return (!!node->network);
}

struct loc_network* loc_network_tree_node_get_network(struct loc_network_tree_node* node) {
	return loc_network_ref(node->network);
}

/*
	Merge the tree!
*/

struct loc_network_tree_merge_ctx {
	struct loc_network_tree* tree;
	struct loc_network_list* networks;
	unsigned int merged;
};

static int loc_network_tree_merge_step(struct loc_network* network, void* data) {
	struct loc_network_tree_merge_ctx* ctx = (struct loc_network_tree_merge_ctx*)data;
	struct loc_network* n = NULL;
	struct loc_network* m = NULL;
	int r;

	// How many networks do we have?
	size_t i = loc_network_list_size(ctx->networks);

	// If the list is empty, just add the network
	if (i == 0)
		return loc_network_list_push(ctx->networks, network);

	while (i--) {
		// Fetch the last network of the list
		n = loc_network_list_get(ctx->networks, i);

		// Try to merge the two networks
		r = loc_network_merge(&m, n, network);
		if (r)
			goto ERROR;

		// Did we get a result?
		if (m) {
			DEBUG(ctx->tree->ctx, "Merged networks %s + %s -> %s\n",
				loc_network_str(n), loc_network_str(network), loc_network_str(m));

			// Add the new network
			r = loc_network_tree_add_network(ctx->tree, m);
			switch (r) {
				case 0:
					break;

				// There might already be a network
				case -EBUSY:
					r = 0;
					goto ERROR;

				default:
					goto ERROR;
			}

			// Remove the merge networks
			r = loc_network_tree_delete_network(ctx->tree, network);
			if (r)
				goto ERROR;

			r = loc_network_tree_delete_network(ctx->tree, n);
			if (r)
				goto ERROR;

			// Remove the previous network from the stack
			r = loc_network_list_remove(ctx->networks, n);
			if (r)
				goto ERROR;

			// Count merges
			ctx->merged++;

			// Try merging the new network with others
			r = loc_network_tree_merge_step(m, data);
			if (r)
				goto ERROR;

			// Add the new network to the stack
			r = loc_network_list_push(ctx->networks, m);
			if (r)
				goto ERROR;

			loc_network_unref(m);
			m = NULL;

			// Once we have found a merge, we are done
			break;

		// If we could not merge the two networks, we add the current one
		} else {
			r = loc_network_list_push(ctx->networks, network);
			if (r)
				goto ERROR;
		}

		loc_network_unref(n);
		n = NULL;
	}

	const unsigned int prefix = loc_network_prefix(network);

	// Remove any networks that we cannot merge
	loc_network_list_remove_with_prefix_smaller_than(ctx->networks, prefix);

ERROR:
	if (m)
		loc_network_unref(m);
	if (n)
		loc_network_unref(n);

	return r;
}

static int loc_network_tree_merge(struct loc_network_tree* tree) {
	struct loc_network_tree_merge_ctx ctx = {
		.tree     = tree,
		.networks = NULL,
		.merged   = 0,
	};
	unsigned int total_merged = 0;
	int r;

	// Create a new list
	r = loc_network_list_new(tree->ctx, &ctx.networks);
	if (r)
		goto ERROR;

	// This is a fix for a very interesting problem which only occurs on non-Debian
	// systems where the algorithm seems to miss some merges. If we run it multiple
	// times it will however find them...
	do {
		// Reset merges
		ctx.merged = 0;

		// Walk through the entire tree
		r = loc_network_tree_walk(tree, NULL, loc_network_tree_merge_step, &ctx);
		if (r)
			goto ERROR;

		// Count all merges
		total_merged += ctx.merged;
	} while (ctx.merged > 0);

	DEBUG(tree->ctx, "%u network(s) have been merged\n", total_merged);

ERROR:
	if (ctx.networks)
		loc_network_list_unref(ctx.networks);

	return r;
}

/*
	Deduplicate the tree
*/

struct loc_network_tree_dedup_ctx {
	struct loc_network_tree* tree;
	struct loc_network_list* stack;
	unsigned int* removed;
	int family;
};

static int loc_network_tree_dedup_step(struct loc_network* network, void* data) {
	struct loc_network_tree_dedup_ctx* ctx = (struct loc_network_tree_dedup_ctx*)data;
	struct loc_network* n = NULL;
	int r;

	// Walk through all networks on the stack...
	for (int i = loc_network_list_size(ctx->stack) - 1; i >= 0; i--) {
		n = loc_network_list_get(ctx->stack, i);

		// Is network a subnet?
		if (loc_network_is_subnet(n, network)) {
			// Do all properties match?
			if (loc_network_properties_cmp(n, network) == 0) {
				r = loc_network_tree_delete_network(ctx->tree, network);
				if (r)
					goto END;

				// Count
				(*ctx->removed)++;

				// Once we removed the subnet, we are done
				goto END;
			}

			// Once we found a subnet, we are done
			break;
		}

		// If the network wasn't a subnet, we can remove it,
		// because we won't ever see a subnet again.
		r = loc_network_list_remove(ctx->stack, n);
		if (r)
			goto END;

		loc_network_unref(n);
		n = NULL;
	}

	// If network did not get removed, we push it into the stack
	r = loc_network_list_push(ctx->stack, network);
	if (r)
		return r;

END:
	if (n)
		loc_network_unref(n);

	return r;
}

static int loc_network_tree_dedup_filter(struct loc_network* network, void* data) {
	const struct loc_network_tree_dedup_ctx* ctx = data;

	// Match address family
	return ctx->family == loc_network_address_family(network);
}

static int loc_network_tree_dedup_one(struct loc_network_tree* tree,
		const int family, unsigned int* removed) {
	struct loc_network_tree_dedup_ctx ctx = {
		.tree    = tree,
		.stack   = NULL,
		.removed = removed,
		.family  = family,
	};
	int r;

	r = loc_network_list_new(tree->ctx, &ctx.stack);
	if (r)
		return r;

	// Walk through the entire tree
	r = loc_network_tree_walk(tree,
		loc_network_tree_dedup_filter, loc_network_tree_dedup_step, &ctx);
	if (r)
		goto ERROR;

ERROR:
	if (ctx.stack)
		loc_network_list_unref(ctx.stack);

	return r;
}

static int loc_network_tree_dedup(struct loc_network_tree* tree) {
	unsigned int removed = 0;
	int r;

	r = loc_network_tree_dedup_one(tree, AF_INET6, &removed);
	if (r)
		return r;

	r = loc_network_tree_dedup_one(tree, AF_INET, &removed);
	if (r)
		return r;

	DEBUG(tree->ctx, "%u network(s) have been removed\n", removed);

	return 0;
}

static int loc_network_tree_delete_node(struct loc_network_tree* tree,
		struct loc_network_tree_node** node) {
	struct loc_network_tree_node* n = *node;
	int r0 = 1;
	int r1 = 1;

	// Return for nodes that have already been deleted
	if (loc_network_tree_node_has_flag(n, NETWORK_TREE_NODE_DELETED))
		goto DELETE;

	// Delete zero
	if (n->zero) {
		r0 = loc_network_tree_delete_node(tree, &n->zero);
		if (r0 < 0)
			return r0;
	}

	// Delete one
	if (n->one) {
		r1 = loc_network_tree_delete_node(tree, &n->one);
		if (r1 < 0)
			return r1;
	}

	// Don't delete this node if we are a leaf
	if (n->network)
		return 0;

	// Don't delete this node if has child nodes that we need
	if (!r0 || !r1)
		return 0;

	// Don't delete root
	if (tree->root == n)
		return 0;

DELETE:
	// It is now safe to delete the node
	loc_network_tree_node_unref(n);
	*node = NULL;

	return 1;
}

static int loc_network_tree_delete_nodes(struct loc_network_tree* tree) {
	int r;

	r = loc_network_tree_delete_node(tree, &tree->root);
	if (r < 0)
		return r;

	return 0;
}

int loc_network_tree_cleanup(struct loc_network_tree* tree) {
	int r;

	// Deduplicate the tree
	r = loc_network_tree_dedup(tree);
	if (r)
		return r;

	// Merge networks
	r = loc_network_tree_merge(tree);
	if (r) {
		ERROR(tree->ctx, "Could not merge networks: %s\n", LIBLOC_NETERR());
		return r;
	}

	// Delete any unneeded nodes
	r = loc_network_tree_delete_nodes(tree);
	if (r)
		return r;

	return 0;
}
