/*
	libloc - A library to determine the location of someone on the Internet

	Copyright (C) 2017-2024 IPFire Development Team <info@ipfire.org>

	This library is free software; you can redistribute it and/or
	modify it under the terms of the GNU Lesser General Public
	License as published by the Free Software Foundation; either
	version 2.1 of the License, or (at your option) any later version.

	This library is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
	Lesser General Public License for more details.
*/

#ifndef LIBLOC_NETWORK_TREE_H
#define LIBLOC_NETWORK_TREE_H

#ifdef LIBLOC_PRIVATE

#include <libloc/libloc.h>
#include <libloc/network.h>

struct loc_network_tree;

int loc_network_tree_new(struct loc_ctx* ctx, struct loc_network_tree** tree);

struct loc_network_tree* loc_network_tree_unref(struct loc_network_tree* tree);

struct loc_network_tree_node* loc_network_tree_get_root(struct loc_network_tree* tree);

int loc_network_tree_walk(struct loc_network_tree* tree,
		int(*filter_callback)(struct loc_network* network, void* data),
		int(*callback)(struct loc_network* network, void* data), void* data);

int loc_network_tree_dump(struct loc_network_tree* tree);

int loc_network_tree_add_network(struct loc_network_tree* tree, struct loc_network* network);

size_t loc_network_tree_count_nodes(struct loc_network_tree* tree);

int loc_network_tree_cleanup(struct loc_network_tree* tree);

/*
	Nodes
*/

struct loc_network_tree_node;

int loc_network_tree_node_new(struct loc_ctx* ctx, struct loc_network_tree_node** node);

struct loc_network_tree_node* loc_network_tree_node_ref(struct loc_network_tree_node* node);
struct loc_network_tree_node* loc_network_tree_node_unref(struct loc_network_tree_node* node);

struct loc_network_tree_node* loc_network_tree_node_get(
	struct loc_network_tree_node* node, unsigned int index);

int loc_network_tree_node_is_leaf(struct loc_network_tree_node* node);

struct loc_network* loc_network_tree_node_get_network(struct loc_network_tree_node* node);

#endif /* LIBLOC_PRIVATE */

#endif /* LIBLOC_NETWORK_TREE_H */
