/**\file    wsock_trace_lua.h
 * \ingroup Lua
 */
#ifndef _WSOCK_TRACE_LUA_H
#define _WSOCK_TRACE_LUA_H

#if defined(USE_LUA)
  #include <lua.h>
  #include <lualib.h>
  #include <lauxlib.h>

  extern const char *wslua_func_sig;

  extern BOOL wslua_DllMain (HINSTANCE instDLL, DWORD reason);
  extern void wslua_print_stack (void);

  extern int wslua_WSAStartup (WORD ver, WSADATA *data);
  extern int wslua_WSACleanup (void);

  #if defined(_MSC_VER) && defined(__FUNCSIG__)
   /*
    * MSVC supports '__FUNCSIG__' and includes full list of arguments.
    * E.g. in 'void foo(int bar)', __FUNCSIG__' gives "void foo(int bar)".
    */
    #define WSLUA_HOOK(rc, func)  wslua_func_sig = __FUNCSIG__, rc = func
  #else
    #define WSLUA_HOOK(rc, func)  wslua_func_sig = __FUNCTION__, rc = func
  #endif

#else
  #define WSLUA_HOOK(rc, func)    ((void)0)
#endif

#endif /* USE_LUA && !_WSOCK_TRACE_LUA_H */
