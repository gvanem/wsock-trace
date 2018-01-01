/*
 * A Lua interface for WSock-Trace.
 */
#ifndef _WSOCK_TRACE_LUA_H
#define _WSOCK_TRACE_LUA_H

#if defined(USE_LUA)
  #include <lua.h>
  #include <lualib.h>
  #include <lauxlib.h>

  extern const char *func_sig;

  extern void wstrace_init_lua (const char *script);
  extern void wstrace_exit_lua (const char *script);

  extern int l_WSAStartup (WORD ver, WSADATA *data);
  extern int l_WSACleanup (void);

  #if defined(_MSC_VER) && defined(__FUNCSIG__)
   /*
    * MSVC supports '__FUNCSIG__' and includes full list of arguments.
    * E.g. in 'void foo(int bar)', __FUNCSIG__' gives "void foo(int bar)".
    */
    #define LUA_HOOK(rc, func)  func_sig = __FUNCSIG__, rc = func
  #else
    #define LUA_HOOK(rc, func)  func_sig = __FUNCTION__, rc = func
  #endif

#else
  #define LUA_HOOK(rc, func)    ((void)0)
#endif

#endif /* USE_LUA && !_WSOCK_TRACE_LUA_H */
