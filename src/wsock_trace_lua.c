/**\file    wsock_trace_lua.c
 * \ingroup Lua
 *
 * \brief
 *  A LuaJIT interface for Wsock-Trace.
 *
 * A WSock LuaJIT script could be run like:
 * ```
 *   c:\wsock_trace> set LUA_CPATH=?_mw_x64.dll
 *   c:\wsock_trace> ..\LuaJIT\src\luajit.exe wsock_trace_init.lua
 * ```
 *
 * Or to enter interactive mode after loading:
 * ```
 *   c:\wsock_trace> set LUA_CPATH=?_mw_x64.dll
 *   c:\wsock_trace> ..\LuaJIT\src\luajit.exe -l wsock_trace -i
 * ```
 */
#include "common.h"

#if defined(USE_LUAJIT)  /* Rest of file */

#define LUA_USE_ASSERT

#include "init.h"
#include "wsock_trace_lua.h"
#include "miniz.h"

#include "luajit.h"
#include "lj_arch.h"
#include "lj_debug.h"

#if !defined(LJ_HASFFI) || (LJ_HASFFI == 0)
#error "LuaJIT needs to be built with 'LJ_HASFFI=1'."
#endif

#ifndef va_copy
#define va_copy(dst, src) ((dst) = (src))
#endif

#define LUA_TRACE(level, fmt, ...)              \
        do {                                    \
          if (g_cfg.LUA.trace_level >= level) { \
             ENTER_CRIT();                      \
             C_printf ("~8%s(%u): ~9" fmt "~0", \
                       __FILE__, __LINE__,      \
                       ## __VA_ARGS__);         \
             LEAVE_CRIT (0);                    \
             C_flush();                         \
          }                                     \
        } while (0)

#define LUA_WARNING(fmt, ...)             \
        do {                              \
          ENTER_CRIT();                   \
          C_printf ("~8LUA: ~9" fmt "~0", \
                    ## __VA_ARGS__);      \
          LEAVE_CRIT (0);                 \
        } while (0)

/* There is only one Lua-state variable.
 */
static lua_State *L = NULL;

/* The function-signature of currently hooking function.
 */
const char *wslua_func_sig = NULL;

/*
 * The open() function for LuaJIT must be marked as a DLL-export.
 */
__declspec(dllexport) int luaopen_wsock_trace (lua_State *l);

/*
 * Globals:
 */
static BOOL init_script_ok = FALSE;
static BOOL open_ok        = TRUE;

static void wslua_init (const char *script);
static void wslua_exit (const char *script);
static void wslua_set_path (const char *full_name);
static void wslua_print_stack (void);

BOOL wslua_DllMain (HINSTANCE instDLL, DWORD reason)
{
  const char *reason_str = NULL;
  const char *full_name;
  BOOL        rc = TRUE;

  if (!g_cfg.LUA.enable)
     return (TRUE);

  full_name = get_dll_full_name();
  if (!full_name)
     set_dll_full_name (instDLL);

  if (reason == DLL_PROCESS_ATTACH)
  {
    /* Set by the real 'DllMain()'.
     * Of 'main()' in 'ws_tool.exe'.
     */
    const char *dll = get_dll_short_name();
    const char *loaded = basename (full_name);

    reason_str = "DLL_PROCESS_ATTACH";

    *ljit_trace_level() = g_cfg.LUA.trace_level;

    LUA_TRACE (1, "ws_from_dll_main: %d, dll/exe: '%s', loaded: '%s'\n", ws_from_dll_main, dll, loaded);

    if (!g_cfg.LUA.color_head)
       get_color (NULL, &g_cfg.LUA.color_head);

    if (!g_cfg.LUA.color_body)
       get_color (NULL, &g_cfg.LUA.color_body);

    if (ws_from_dll_main && stricmp(loaded, dll))
    {
      LUA_WARNING ("Expected '%s', but loaded DLL/EXE was '%s:\n", dll, loaded);
      rc = FALSE;
    }
    else
    {
      if (ws_from_dll_main)
      {
        LUA_TRACE (1, "Importing from '%s'\n", full_name);
        wslua_set_path (full_name);
      }
      wslua_init (g_cfg.LUA.init_script);
    }
  }
  else if (reason == DLL_PROCESS_DETACH)
  {
    reason_str = "DLL_PROCESS_DETACH";
    wslua_exit (g_cfg.LUA.exit_script);
  }
  else if (reason == DLL_THREAD_ATTACH)
  {
    reason_str = "DLL_THREAD_ATTACH";
    /** \todo */
  }
  else if (reason == DLL_THREAD_DETACH)
  {
    reason_str = "DLL_THREAD_DETACH";
    /** \todo */
  }

  LUA_TRACE (1, "rc: %d, full_name: %s, reason_str: %s\n", rc, full_name, reason_str);
  return (rc);
}

static const char *get_func_sig (void)
{
  static char buf [100];

  if (!wslua_func_sig)
     return ("None");

  strcpy (buf, wslua_func_sig);

#if !(defined(_MSC_VER) && defined(__FUNCSIG__))
  strcat (buf, "()");
#endif
  return (buf);
}

/**
 * The Lua-hooks.
 * For the moment these does nothing.
 */
int wslua_WSAStartup (WORD ver, WSADATA *data)
{
  if (g_cfg.LUA.enable)
     LUA_TRACE (1, "wslua_func_sig: ~9'%s'\n", get_func_sig());
  ARGSUSED (ver);
  ARGSUSED (data);
  return (0);
}

int wslua_WSACleanup (void)
{
  if (g_cfg.LUA.enable)
     LUA_TRACE (1, "wslua_func_sig: ~9'%s'\n", get_func_sig());
  return (0);
}

/**
 * Execute a script using `lua_pcall()` and
 * report any errors in it.
 */
static BOOL execute_and_report (lua_State *l)
{
  const char *msg = "";
  int         rc = lua_pcall (l, 0, LUA_MULTRET, 0);

  if (rc == 0)
  {
    /* Success. The returned value at the top of the stack (index -1)
     * would be `lua_tonumber(l, -1)`. But we ignore that except for tracing.
     */
    LUA_TRACE (1, "Script OK, ret: %d:\n", (int)lua_tonumber(l, -1));
    return (TRUE);
  }

  if (!lua_isnil(l, -1))
  {
    msg = lua_tostring (l, -1);
    if (!msg)
       msg = "(error object is not a string)";
     lua_pop (l, 1);
  }

  LUA_WARNING ("Failed to load script (rc = %d):~0\n  %s\n", rc, msg);
  wslua_print_stack();
  return (FALSE);
}

/**
 * Run a .lua script.
 *
 * Inspired from the example in Swig:
 * <Swig-Root>/Examples/lua/embed/embed.c
 */
static BOOL wslua_run_script (lua_State *l, const char *script)
{
  LUA_TRACE (1, "Launching script: %s\n", script ? script : "<none>");

  if (!script)
     return (FALSE);

  if (luaL_loadfile(l, script) == 0)
     return execute_and_report (l);
  return (FALSE);
}

/**
 * Use 'miniz.c' and extract a script from a zip-file and run it.
 *
 * Or use one of these:
 *   https://github.com/luaforge/lar/blob/master/lar/lar.lua
 *   https://github.com/davidm/lua-compress-deflatelua
 */
static BOOL wslua_run_zipfile (lua_State *l, const char *zipfile, const char *script)
{
  char *buf = mz_zip_extract_archive_file_to_heap (zipfile, script, NULL,
                                                   MZ_ZIP_FLAG_IGNORE_PATH);

  if (buf && luaL_loadstring(l, buf) == 0)
  {
    free (buf);
    return execute_and_report (l);
  }
  if (buf)
     free (buf);
  return (FALSE);
}

static int wslua_get_trace_level (lua_State *l)
{
  lua_pushnumber (l, g_cfg.LUA.trace_level);
  return (1);
}

static int wslua_set_trace_level (lua_State *l)
{
  if (!lua_isnumber(L, 1))
  {
    lua_pushstring (L, "incorrect argument to 'g_cfg.LUA.trace_level'");
    lua_error (L);
  }
  else
    g_cfg.LUA.trace_level = (int) lua_tonumber (L, 1);
  ARGSUSED (l);
  return (1);
}

static int wslua_get_profiler (lua_State *l)
{
  lua_pushnumber (l, g_cfg.LUA.profile);
  return (1);
}

static int wslua_register_hook (lua_State *l)
{
  const lua_CFunction func1 = lua_tocfunction (L, LUA_ENVIRONINDEX);
  const lua_CFunction func2 = lua_tocfunction (L, 2);

  LUA_TRACE (1, "func1=0x%p, func2=0x%p\n", func1, func2);
  ARGSUSED (l);
  return (1);
}

static int wslua_C_puts (lua_State *l)
{
  C_puts (lua_tostring(l,1));
  return (1);
}

#if 0
/*
 * This function is broken.
 * Accepts only strings passed from Lua-land.
 */
static int wslua_C_printf (lua_State *l)
{
  va_list    args1, args2;
  const char *fmt = lua_tostring (l, 1);
  const char *arg = lua_tostring (l, 2);
  int         i, n = lua_gettop (l);    /* number of arguments */

  va_start (args1, fmt);
  va_copy (args2, args1);

  for (i = 2; i <= n; i++)
  {
    arg = lua_tostring (l, i);
    va_arg (args2, const char*) = arg;
  }

  va_start (args1, fmt);
  C_vprintf (fmt, args1);
  va_end (args2);
  return (n);
}
#endif

static int wslua_get_dll_short_name (lua_State *l)
{
  lua_pushstring (l, get_dll_short_name());
  return (1);
}

static int wslua_get_dll_full_name (lua_State *l)
{
  lua_pushstring (l, get_dll_full_name());
  return (1);
}

static int wslua_get_builder (lua_State *l)
{
  lua_pushstring (l, get_builder(FALSE));
  return (1);
}

static int wslua_get_copyright (lua_State *l)
{
  lua_pushstring (l, LUAJIT_COPYRIGHT);
  return (1);
}

static int wslua_get_version (lua_State *l)
{
  lua_pushstring (l, LUAJIT_VERSION);
  return (1);
}

static void wslua_print_stack (void)
{
  lua_Debug ar;
  int       level = 0;

  while (lua_getstack(L, level++, &ar))
  {
    lua_getinfo (L, "Snl", &ar);
    C_printf ("  %s:", ar.short_src);
    if (ar.currentline > 0)
       C_printf ("%d:", ar.currentline);
    if (*ar.namewhat != '\0')    /* is there a name? */
       C_printf (" in function " LUA_QS, ar.name);
    else
    {
      if (*ar.what == 'm')       /* main? */
           C_puts (" in main chunk");
      else if (*ar.what == 'C' || *ar.what == 't')
           C_puts (" ?");   /* C function or tail call */
      else C_printf (" in function <%s:%d>", ar.short_src, ar.linedefined);
    }
    C_putc ('\n');
  }
//C_printf ("LuaJIT stack depth: %d.\n", level-1);
}

static int wstrace_lua_panic (lua_State *l)
{
  const char *msg = lua_tostring (l, 1);

  LUA_WARNING ("Panic: %s\n", msg);
  wslua_print_stack();
  lua_close (L);
  L = NULL;
  return (0);
}

/*
 * The 'lua_sethook()' callback.
 */
static void wstrace_lua_hook (lua_State *l, lua_Debug *_ld)
{
  switch (_ld->event)
  {
    case LUA_HOOKCALL:
         C_printf ("~9LUA_HOOKCALL");
         break;
    case LUA_HOOKRET:
         C_printf ("~9LUA_HOOKRET");
         break;
    case LUA_HOOKLINE:
         C_printf ("~9LUA_HOOKLINE at %d", _ld->currentline);
         break;
  }

#if 1   /** \todo */
  if (_ld->event == LUA_HOOKCALL)
  {
    lua_Debug ld;

    memset (&ld, '\0', sizeof(ld));
    lua_getinfo (l, ">nl", &ld);
    C_printf (": ld.name: %s, ld.short_src: %s", ld.name, ld.short_src);
  }
#else
  ARGSUSED (l);
#endif
  C_puts ("~0\n");
}

/**
 * Called from 'DllMain()' / 'DLL_PROCESS_ATTATACH' to setup LuaJIT
 * and optionally run the given 'script'.
 *
 * \todo:
 *   Support a byte-code generated script to be generated by e.g:
 *   $(LUAJIT_ROOT)/src/luajit -b wsock_trace_init.lua wsock_trace_init.h
 *
 *   Then add:
 *     #include "wsock_trace_init.h"
 *
 *   here and execute 'luaL_loadstring (l, luaJIT_BC_wsock_trace_init)'
 *   here would do the same thing. But that would be another chicken
 *   and egg problem.
 *
 *   A better way is maybe to generate an .obj-file:
 *   $(LUAJIT_ROOT)/src/luajit -b wsock_trace_init.lua wsock_trace_init.obj
 *   and simply execute that.
 *
 *  \note:
 *    The 'luajit -b' command is really executed by
 *    '$(LUAJIT_ROOT)/src/jit/bcsave.lua'. It needs that 'LUA_PATH' contains
 *    the '$(LUAJIT_ROOT)/src' part.
 *    E.g. do a:
 *      set LUA_PATH=c:\net\wsock_trace\LuaJIT\src\?.lua;?.lua
 */
static void wslua_init (const char *script)
{
  if (L)
     return;

  L = luaL_newstate();
  if (!L)
  {
    LUA_WARNING ("luaL_newstate() failed.\n");
    return;
  }

  luaL_openlibs (L);    /* Load LuaJIT libraries */
  luaopen_jit (L);      /* Turn on he JIT engine */

  /* Set up the 'panic' handler, which let's us control LuaJIT execution.
   */
  lua_atpanic (L, wstrace_lua_panic);

  if (!ws_from_dll_main)
     luaopen_wsock_trace (L);

#if 1
  else
  {
    lua_pushcfunction (L, wslua_get_trace_level);
    lua_setglobal (L, "get_trace_level");

    lua_pushcfunction (L, wslua_set_trace_level);
    lua_setglobal (L, "set_trace_level");
  }
#endif

  if (g_cfg.LUA.trace_level >= 3)
     lua_sethook (L, wstrace_lua_hook, LUA_MASKCALL | LUA_HOOKRET | LUA_MASKLINE, 0);

  init_script_ok = wslua_run_script (L, script);
}

/**
 * Called on 'wslua_DllMain (...DLL_PROCESS_DETACH)' to tear down
 * LuaJIT and optionally run the 'script'.
 * Provided the 'script' in 'wslua_init()' ran okay.
 */
static void wslua_exit (const char *script)
{
  LUA_TRACE (1, "In %s(), L=0x%p\n", __FUNCTION__, L);
  if (!L)
     return;

  if (init_script_ok && open_ok)
     wslua_run_script (L, script);
  lua_sethook (L, NULL, 0, 0);
  lua_close (L);
  L = NULL;
}

#include "wsock_trace.rc"

/**
 * Setup the "LUA_CPATH" for LuaJIT to load the correct Wsock-trace .dll.
 */
static void wslua_set_path (const char *full_name)
{
  const char *env = getenv ("LUA_CPATH");
  char       *p;
  char        dll_path [_MAX_PATH] = { "?" };
  char        lua_cpath [_MAX_PATH] = { "-" };
  const char *dll_ofs;
  size_t      len, left = sizeof(lua_cpath);

  p = strrchr (full_name, '\\');
  _strlcpy (dll_path, full_name, p - full_name + 1);

  p = lua_cpath;

  /* Ensure a 'require("wsock_trace")' in Lua-land will match the correct .DLL.
   * E.g.
   *   for Cygwin / x64, our RC_DLL_NAME == "wsock_trace_cyg_x64", so the
   *   'lua_cpath' MUST end with "?_cyg_x64.dll".
   *
   *   But if "LUA_CPATH=?_cyg.dll" is already defined, set our 'lua_cpath' first.
   *   Otherwise 'LoadLibrary()' in LuaJIT errors with code 193; ERROR_BAD_EXE_FORMAT
   */
  dll_ofs = (const char*) RC_DLL_NAME + strlen ("wsock_trace");
  len = snprintf (p, left, "%s\\?%s.dll", dll_path, dll_ofs);

  p    += len;
  left -= len;

  if (env && left > strlen(env)+2)
  {
    *p++ = ';';
    _strlcpy (p, env, left-1);
  }

  _ws_setenv ("LUA_CPATH", lua_cpath, 1);
  LUA_TRACE (1, "LUA_CPATH: %s.\n", lua_cpath);
}

static const struct luaL_Reg wslua_table[] = {
  { "register_hook",       wslua_register_hook },
  { "C_puts",              wslua_C_puts },
//{ "C_printf",            wslua_C_printf },
  { "get_dll_full_name",   wslua_get_dll_full_name },
  { "get_dll_short_name",  wslua_get_dll_short_name },
  { "get_builder",         wslua_get_builder },
  { "get_version",         wslua_get_version },
  { "get_copyright",       wslua_get_copyright },
  { "set_trace_level",     wslua_set_trace_level },
  { "get_trace_level",     wslua_get_trace_level },
  { "get_profiler",        wslua_get_profiler },
  { NULL,                  NULL }
};

/**
 * The open() function exported and called from LuaJIT when "wsock_trace"
 * is used as a module. This is called explicitly when pushing "wsock_trace"
 * as a global module.
 */
int luaopen_wsock_trace (lua_State *l)
{
  char *dot, module [20];
  const char *comment = "";

  _strlcpy (module, get_dll_short_name(), sizeof(module));
  dot = strrchr (module, '.');
  dot[0] = '\0';

  if (!ws_from_dll_main)
  {
    _strlcpy (module, "wsock_trace", sizeof(module));
    comment = " (faking 'wsock_trace' module)";
  }

#if (LUA_VERSION_NUM >= 502)
  /*
   * From:
   *   https://stackoverflow.com/questions/19041215/lual-openlib-replacement-for-lua-5-2
   */
  lua_newtable (l);
  luaL_setfuncs (l, wslua_table, 0);
  lua_setglobal (l, module);
#else
  luaL_register (l, module, wslua_table);
#endif

  LUA_TRACE (1, "%s(), module: \"%s\"%s.\n", __FUNCTION__, module, comment);
  return (1);
}
#endif /* USE_LUAJIT */

