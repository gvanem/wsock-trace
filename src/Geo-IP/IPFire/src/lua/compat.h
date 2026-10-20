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

#ifndef LUA_LOCATION_COMPAT_H
#define LUA_LOCATION_COMPAT_H

#include <lua.h>
#include <lauxlib.h>

#if LUA_VERSION_RELEASE_NUM < 502

static inline void luaL_setmetatable(lua_State* L, const char* name) {
	luaL_checkstack(L, 1, "not enough stack slots");
	luaL_getmetatable(L, name);
	lua_setmetatable(L, -2);
}

static inline void luaL_setfuncs(lua_State* L, const luaL_Reg* l, int nup) {
	int i;

	luaL_checkstack(L, nup+1, "too many upvalues");

	for (; l->name != NULL; l++) {
		lua_pushstring(L, l->name);

		for (i = 0; i < nup; i++)
			lua_pushvalue(L, -(nup + 1));

		lua_pushcclosure(L, l->func, nup);
		lua_settable(L, -(nup + 3));
  }

  lua_pop(L, nup);
}

static inline void luaL_newlib(lua_State* L, const luaL_Reg* l) {
  lua_newtable(L);
  luaL_setfuncs(L, l, 0);
}

#endif /* Lua < 5.2 */

#include <stdint.h>

/*
	Pushes a whole number as an integer where Lua has 64 bit integers (5.3 and later).
	Before, lua_Integer only has 32 bits on 32 bit systems, which AS numbers and times
	do not fit into, but a lua_Number can hold them exactly.
*/
static inline void location_pushinteger(lua_State* L, int64_t n) {
#if LUA_VERSION_NUM >= 503
	lua_pushinteger(L, (lua_Integer)n);
#else
	lua_pushnumber(L, (lua_Number)n);
#endif
}

#endif /* LUA_LOCATION_COMPAT_H */
