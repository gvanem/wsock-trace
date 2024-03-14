#pragma once

/*
 * LIBLOC hacks to support LuaJIT.
 *
 * Scraped from:
 *   https://github.com/launchdarkly/lua-server-sdk/blob/main/launchdarkly-server-sdk-redis.c#L63
 */
static __inline void luaL_setfuncs (lua_State *L, const luaL_Reg *l, int nup)
{
  luaL_checkstack (L, nup+1, "too many upvalues");

  for ( ; l->name; l++)   /* fill the table with given functions */
  {
    int i;

    lua_pushstring (L, l->name);
    for (i = 0; i < nup; i++)            /* copy upvalues to the top */
       lua_pushvalue (L, -(nup+1));
    lua_pushcclosure (L, l->func, nup);  /* closure with those upvalues */
    lua_settable (L, -(nup + 3));
  }
  lua_pop (L, nup);                      /* remove upvalues */
}

/*
 * Adapted from:
 *   https://github.com/LuaJIT/LuaJIT/blob/2b8de8cfc6ae483d6ec16b7609bab64e37d6fc02/src/lj_api.c#L1003
 */
#define luaL_setmetatable(L, tname) (lua_getfield (L, LUA_REGISTRYINDEX, tname), \
                                     lua_setmetatable (L, -2))

/*
 * Scraped from:
 *  https://github.com/LuaJIT/LuaJIT/blob/d06beb0480c5d1eb53b3343e78063950275aa281/src/lauxlib.h#L123-L125
 */
#define luaL_newlibtable(L, l)  lua_createtable(L, 0, sizeof(l) / sizeof((l)[0]) - 1)
#define luaL_newlib(L, l)      (luaL_newlibtable(L, l), luaL_setfuncs(L, l, 0))

