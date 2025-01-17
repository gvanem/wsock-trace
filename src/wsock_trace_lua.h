/**\file    wsock_trace_lua.h
 * \ingroup Lua
 */
#ifndef _WSOCK_TRACE_LUA_H
#define _WSOCK_TRACE_LUA_H

#if defined(USE_LUAJIT)
  #include <lua.h>
  #include <lualib.h>
  #include <lauxlib.h>

  extern const char *wslua_func_sig;

  extern BOOL wslua_DllMain (HINSTANCE instDLL, DWORD reason);
  extern int  wslua_WSAStartup (WORD ver, WSADATA *data);
  extern int  wslua_WSACleanup (void);

  #if defined(__FUNCSIG__)
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

#endif /* USE_LUAJIT && !_WSOCK_TRACE_LUA_H */
