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
#include <lualib.h>

#include <libloc/libloc.h>
#include <libloc/network.h>
#include <libloc/version.h>
#include <libloc/private.h> /* For '__attribute__' */

#include "location.h"
#include "as.h"
#include "compat.h"
#include "country.h"
#include "database.h"
#include "network.h"

struct loc_ctx* ctx = NULL;

static int log_callback_ref = 0;

static void log_callback(struct loc_ctx* _ctx, void* data, int priority, const char* file,
	int line, const char* fn, const char* format, va_list args) __attribute__((format(printf, 7, 0)));

static void log_callback(struct loc_ctx* _ctx, void* data, int priority, const char* file,
		int line, const char* fn, const char* format, va_list args) {
	char* message = NULL;
	int r;

	lua_State* L = data;

	// Format the log message
	r = vasprintf(&message, format, args);
	if (r < 0)
		return;

	// Fetch the Lua callback function
	lua_rawgeti(L, LUA_REGISTRYINDEX, log_callback_ref);

	// Pass the priority as first argument
	lua_pushnumber(L, priority);

	// Pass the message as second argument
	lua_pushstring(L, message);

	// Call the function
	lua_call(L, 2, 0);

	free(message);
}

static int set_log_callback(lua_State* L) {
	// Check if we have received a function
	luaL_checktype(L, 1, LUA_TFUNCTION);

	// Store a reference to the callback function
	log_callback_ref = luaL_ref(L, LUA_REGISTRYINDEX);

	// Register our callback helper
	if (ctx)
		loc_set_log_callback(ctx, log_callback, L);

	return 0;
}

static int set_log_level(lua_State* L) {
	const int level = luaL_checknumber(L, 1);

	// Store the new log level
	if (ctx)
		loc_set_log_priority(ctx, level);

	return 0;
}

static int version(lua_State* L) {
	lua_pushstring(L, PACKAGE_VERSION);
	return 1;
}

static const struct luaL_Reg location_functions[] = {
	{ "set_log_callback", set_log_callback },
	{ "set_log_level", set_log_level },
	{ "version", version },
	{ NULL, NULL },
};

int luaopen_location(lua_State* L) {
	int r;

	// Initialize the context
	r = loc_new(&ctx);
	if (r)
		return luaL_error(L,
			"Could not initialize location context: %s\n", strerror(errno));

	// Register functions
	luaL_newlib(L, location_functions);

	// Register AS type
	register_as(L);

	lua_setfield(L, -2, "AS");

	// Register Country type
	register_country(L);

	lua_setfield(L, -2, "Country");

	// Register Database type
	register_database(L);

	lua_setfield(L, -2, "Database");

	// Register DatabaseEnumerator type
	register_database_enumerator(L);

	lua_setfield(L, -2, "DatabaseEnumerator");

	// Register Network type
	register_network(L);

	lua_setfield(L, -2, "Network");

	// Set DATABASE_PATH
	lua_pushstring(L, LIBLOC_DEFAULT_DATABASE_PATH);
	lua_setfield(L, -2, "DATABASE_PATH");

	// Add flags
	lua_pushnumber(L, LOC_NETWORK_FLAG_ANONYMOUS_PROXY);
	lua_setfield(L, -2, "NETWORK_FLAG_ANONYMOUS_PROXY");

	lua_pushnumber(L, LOC_NETWORK_FLAG_SATELLITE_PROVIDER);
	lua_setfield(L, -2, "NETWORK_FLAG_SATELLITE_PROVIDER");

	lua_pushnumber(L, LOC_NETWORK_FLAG_ANYCAST);
	lua_setfield(L, -2, "NETWORK_FLAG_ANYCAST");

	lua_pushnumber(L, LOC_NETWORK_FLAG_DROP);
	lua_setfield(L, -2, "NETWORK_FLAG_DROP");

	return 1;
}
