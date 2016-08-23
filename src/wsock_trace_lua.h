/*
 * A Lua interface for WSock-Trace.
 */
#ifndef _WSOCK_TRACE_LUA_H
#define _WSOCK_TRACE_LUA_H

#if defined(USE_LUA)
  #include <lua.h>
  #include <lualib.h>
  #include <lauxlib.h>

  __declspec(dllexport) int luaopen_wsock_trace (lua_State *L);
  __declspec(dllexport) int luaJIT_BC_wsock_trace (lua_State *L);

  void wstrace_init_lua (const char *script);
  void wstrace_exit_lua (const char *script);

  int l_WSAStartup (WORD ver, WSADATA *data);

  #if defined(_MSC_VER) && defined(__FUNCSIG__)
   /*
    * MSVC supports '__FUNCSIG__' and includes full list of arguments.
    * E.g. in 'void foo(int bar)', __FUNCSIG__' gives "void foo(int bar)".
    */
  #else
    #define __FUNCSIG__ NULL
  #endif

  extern const char *func_sig;

  #define LUA_HOOK(rc, func)  func_sig = ## __FUNCSIG__, rc = l_ ## func
#else
  #define LUA_HOOK(rc, func)  ((void)0)
#endif

#endif /* USE_LUA && !_WSOCK_TRACE_LUA_H */
