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
#include <string.h>
#include <stdlib.h>

#include <lua.h>
#include <lauxlib.h>

#include <libloc/as.h>

#include "location.h"
#include "as.h"

typedef struct as {
	struct loc_as* as;
} AS;

static AS* luaL_checkas(lua_State* L, int i) {
	void* userdata = luaL_checkudata(L, i, "location.AS");

	// Throw an error if the argument doesn't match
	luaL_argcheck(L, userdata, i, "AS expected");

	return (AS*)userdata;
}

int create_as(lua_State* L, struct loc_as* as) {
	// Allocate a new object
	AS* self = (AS*)lua_newuserdata(L, sizeof(*self));

	// Set metatable
	luaL_setmetatable(L, "location.AS");

	// Store country
	self->as = loc_as_ref(as);

	return 1;
}

static int AS_new(lua_State* L) {
	struct loc_as* as = NULL;
	unsigned int n = 0;
	int r;

	// Fetch the number
	n = luaL_checknumber(L, 1);

	// Create the AS
	r = loc_as_new(ctx, &as, n);
	if (r)
		return luaL_error(L, "Could not create AS %u: %s\n", n, strerror(errno));

	// Return the AS
	r = create_as(L, as);
	loc_as_unref(as);

	return r;
}

static int AS_gc(lua_State* L) {
	AS* self = luaL_checkas(L, 1);

	// Free AS
	if (self->as) {
		loc_as_unref(self->as);
		self->as = NULL;
	}

	return 0;
}

static int AS_tostring(lua_State* L) {
	AS* self = luaL_checkas(L, 1);

	uint32_t number = loc_as_get_number(self->as);
	const char* name = loc_as_get_name(self->as);

	// Return string
	if (name)
		lua_pushfstring(L, "AS%d - %s", number, name);
	else
		lua_pushfstring(L, "AS%d", number);

	return 1;
}

// Name

static int AS_get_name(lua_State* L) {
	AS* self = luaL_checkas(L, 1);

	// Return the name
	lua_pushstring(L, loc_as_get_name(self->as));

	return 1;
}

// Number

static int AS_get_number(lua_State* L) {
	AS* self = luaL_checkas(L, 1);

	// Return the number
	lua_pushnumber(L, loc_as_get_number(self->as));

	return 1;
}

static const struct luaL_Reg AS_functions[] = {
	{ "new", AS_new },
	{ "get_name", AS_get_name },
	{ "get_number", AS_get_number },
	{ "__gc", AS_gc },
	{ "__tostring", AS_tostring },
	{ NULL, NULL },
};

int register_as(lua_State* L) {
	return register_class(L, "location.AS", AS_functions);
}
