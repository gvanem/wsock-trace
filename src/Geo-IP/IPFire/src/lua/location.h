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

#ifndef LUA_LOCATION_LOCATION_H
#define LUA_LOCATION_LOCATION_H

#include <lua.h>

#include <libloc/libloc.h>

#include "compat.h"

extern struct loc_ctx* ctx;

int luaopen_location(lua_State* L);

static inline int register_class(lua_State* L,
		const char* name, const struct luaL_Reg* functions) {
	// Create a new metatable
	luaL_newmetatable(L, name);

	// Set functions
	luaL_setfuncs(L, functions, 0);

	// Configure metatable
	lua_pushvalue(L, -1);
	lua_setfield(L, -2, "__index");

	return 1;
}

#endif /* LUA_LOCATION_LOCATION_H */
