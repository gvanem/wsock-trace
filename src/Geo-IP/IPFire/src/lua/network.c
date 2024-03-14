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

#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include <lua.h>
#include <lauxlib.h>

#include <libloc/network.h>

#include "location.h"
#include "network.h"

typedef struct network {
	struct loc_network* network;
} Network;

static Network* luaL_checknetwork(lua_State* L, int i) {
	void* userdata = luaL_checkudata(L, i, "location.Network");

	// Throw an error if the argument doesn't match
	luaL_argcheck(L, userdata, i, "Network expected");

	return (Network*)userdata;
}

int create_network(lua_State* L, struct loc_network* network) {
	// Allocate a new object
	Network* self = (Network*)lua_newuserdata(L, sizeof(*self));

	// Set metatable
	luaL_setmetatable(L, "location.Network");

	// Store network
	self->network = loc_network_ref(network);

	return 1;
}

static int Network_new(lua_State* L) {
	struct loc_network* network = NULL;
	const char* n = NULL;
	int r;

	// Fetch the network
	n = luaL_checkstring(L, 1);

	// Parse the string
	r = loc_network_new_from_string(ctx, &network, n);
	if (r)
		return luaL_error(L, "Could not create network %s: %s\n", n, strerror(errno));

	// Return the network
	r = create_network(L, network);
	loc_network_unref(network);

	return r;
}

static int Network_gc(lua_State* L) {
	Network* self = luaL_checknetwork(L, 1);

	// Free the network
	if (self->network) {
		loc_network_unref(self->network);
		self->network = NULL;
	}

	return 0;
}

static int Network_tostring(lua_State* L) {
	Network* self = luaL_checknetwork(L, 1);

	// Push string representation of the network
	lua_pushstring(L, loc_network_str(self->network));

	return 1;
}

// ASN

static int Network_get_asn(lua_State* L) {
	Network* self = luaL_checknetwork(L, 1);

	uint32_t asn = loc_network_get_asn(self->network);

	// Push ASN
	if (asn)
		lua_pushnumber(L, asn);
	else
		lua_pushnil(L);

	return 1;
}

// Family

static int Network_get_family(lua_State* L) {
	Network* self = luaL_checknetwork(L, 1);

	// Push family
	lua_pushnumber(L, loc_network_address_family(self->network));

	return 1;
}

// Country Code

static int Network_get_country_code(lua_State* L) {
	Network* self = luaL_checknetwork(L, 1);

	const char* country_code = loc_network_get_country_code(self->network);

	// Push country code
	if (country_code && *country_code)
		lua_pushstring(L, country_code);
	else
		lua_pushnil(L);

	return 1;
}

// Has Flag?

static int Network_has_flag(lua_State* L) {
	Network* self = luaL_checknetwork(L, 1);

	// Fetch flag
	int flag = luaL_checknumber(L, 2);

	// Push result
	lua_pushboolean(L, loc_network_has_flag(self->network, flag));

	return 1;
}

static const struct luaL_Reg Network_functions[] = {
	{ "new", Network_new },
	{ "get_asn", Network_get_asn },
	{ "get_country_code", Network_get_country_code },
	{ "get_family", Network_get_family },
	{ "has_flag", Network_has_flag },
	{ "__gc", Network_gc },
	{ "__tostring", Network_tostring },
	{ NULL, NULL },
};

int register_network(lua_State* L) {
	return register_class(L, "location.Network", Network_functions);
}
