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

#include <libloc/country.h>

#include "location.h"
#include "country.h"

typedef struct country {
	struct loc_country* country;
} Country;

static Country* luaL_checkcountry(lua_State* L, int i) {
	void* userdata = luaL_checkudata(L, i, "location.Country");

	// Throw an error if the argument doesn't match
	luaL_argcheck(L, userdata, i, "Country expected");

	return (Country*)userdata;
}

int create_country(lua_State* L, struct loc_country* country) {
	// Allocate a new object
	Country* self = (Country*)lua_newuserdata(L, sizeof(*self));

	// Set metatable
	luaL_setmetatable(L, "location.Country");

	// Store country
	self->country = loc_country_ref(country);

	return 1;
}

static int Country_new(lua_State* L) {
	struct loc_country* country = NULL;
	const char* code = NULL;
	int r;

	// Fetch the code
	code = luaL_checkstring(L, 1);

	// Parse the string
	r = loc_country_new(ctx, &country, code);
	if (r)
		return luaL_error(L, "Could not create country %s: %s\n", code, strerror(errno));

	// Return the country
	r = create_country(L, country);
	loc_country_unref(country);

	return r;
}

static int Country_gc(lua_State* L) {
	Country* self = luaL_checkcountry(L, 1);

	// Free country
	if (self->country) {
		loc_country_unref(self->country);
		self->country = NULL;
	}

	return 0;
}

static int Country_eq(lua_State* L) {
	Country* self  = luaL_checkcountry(L, 1);
	Country* other = luaL_checkcountry(L, 2);

	// Push comparison result
	lua_pushboolean(L, loc_country_cmp(self->country, other->country) == 0);

	return 1;
}

// Name

static int Country_get_name(lua_State* L) {
	Country* self = luaL_checkcountry(L, 1);

	// Return the code
	lua_pushstring(L, loc_country_get_name(self->country));

	return 1;
}

// Code

static int Country_get_code(lua_State* L) {
	Country* self = luaL_checkcountry(L, 1);

	// Return the code
	lua_pushstring(L, loc_country_get_code(self->country));

	return 1;
}

// Continent Code

static int Country_get_continent_code(lua_State* L) {
	Country* self = luaL_checkcountry(L, 1);

	// Return the code
	lua_pushstring(L, loc_country_get_continent_code(self->country));

	return 1;
}

static const struct luaL_Reg Country_functions[] = {
	{ "new", Country_new },
	{ "get_code", Country_get_code },
	{ "get_continent_code", Country_get_continent_code },
	{ "get_name", Country_get_name },
	{ "__eq", Country_eq },
	{ "__gc", Country_gc },
	{ "__tostring", Country_get_code },
	{ NULL, NULL },
};

int register_country(lua_State* L) {
	return register_class(L, "location.Country", Country_functions);
}
