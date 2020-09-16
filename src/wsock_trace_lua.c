/**\file    wsock_trace_lua.c
 * \ingroup Lua
 *
 * \brief
 *  A LuaJIT interface for Wsock-Trace.
 */
#include "common.h"

#if defined(USE_LUA)  /* Rest of file */

#include "init.h"
#include "wsock_trace_lua.h"

#include "luajit.h"
#include "lj_arch.h"
#include "lj_debug.h"

#if !defined(LJ_HASFFI) || (LJ_HASFFI == 0)
#error "LuaJIT needs to be built with 'LJ_HASFFI=1'."
#endif

#ifndef va_copy
#define va_copy(dst, src) ((dst) = (src))
#endif

#define LUA_TRACE(level, fmt, ...)                  \
        do {                                        \
          if (g_cfg.lua.trace_level >= level)       \
             ENTER_CRIT();                          \
             trace_printf ("~8%s(%u): ~9" fmt "~0", \
                           __FILE__, __LINE__,      \
                           ## __VA_ARGS__);         \
             LEAVE_CRIT();                          \
        } while (0)

#define LUA_WARNING(fmt, ...)                 \
        do {                                  \
          ENTER_CRIT();                       \
          trace_printf ("~8LUA: ~9" fmt "~0", \
                        ## __VA_ARGS__);      \
          LEAVE_CRIT();                       \
        } while (0)

/* There is only one Lua-state variable.
 */
static lua_State *L = NULL;

/* The function-signature of currently hooking function.
 */
const char *wslua_func_sig = NULL;

static BOOL init_script_ok = FALSE;
static BOOL open_ok        = TRUE;

static void wslua_init (const char *script);
static void wslua_exit (const char *script);

#include "wsock_trace.rc"

static void wslua_set_path (const char *full_name)
{
  const char *env = getenv ("LUA_CPATH");
  char       *p;
  char        dll_path [_MAX_PATH] = { "?" };
  char        lua_cpath [_MAX_PATH] = { "-" };
  size_t      len, left = sizeof(lua_cpath);

  p = strrchr (full_name, '\\');
  _strlcpy (dll_path, full_name, p - full_name + 1);

  p = lua_cpath;
  if (env)
  {
    len = snprintf (p, left, "%s;", env);
    p    += len;
    left -= len;
  }

  /* Ensure a 'require("wsock_trace")' in Lua-land will match the correct .DLL.
   * E.g.
   *   for Cygwin / x64, our RC_DLL_NAME == "wsock_trace_cyg_x64", so the
   *   'lua_cpath' MUST end with "?_cyg_x64.dll".
   */
  snprintf (p, left, "%s\\?%s.dll", dll_path, RC_DLL_NAME + strlen("wsock_trace"));

  _setenv ("LUA_CPATH", lua_cpath, 1);
  LUA_TRACE (1, "LUA_CPATH: %s.\n", lua_cpath);
}

BOOL wslua_DllMain (HINSTANCE instDLL, DWORD reason)
{
  const char *dll        = get_dll_short_name();
  const char *reason_str = NULL;
  BOOL        rc = TRUE;

  if (!g_cfg.lua.enable)
     return (TRUE);

  if (reason == DLL_PROCESS_ATTACH)
  {
    const char *full_name = get_dll_full_name();   /* Set by the real 'DllMain()' */
    const char *loaded;

    reason_str = "DLL_PROCESS_ATTACH";

    *ljit_trace_level() = g_cfg.lua.trace_level;

    if (!g_cfg.lua.color_head)
       get_color (NULL, &g_cfg.lua.color_head);

    if (!g_cfg.lua.color_body)
       get_color (NULL, &g_cfg.lua.color_body);

    loaded = basename (full_name);
    if (stricmp(loaded, dll))
    {
      LUA_WARNING ("Expected %s, but loaded DLL was '%s:\n", dll, loaded);
      rc = FALSE;
    }
    else
    {
      wslua_set_path (full_name);
      wslua_init (g_cfg.lua.init_script);
    }
  }
  else if (reason == DLL_PROCESS_DETACH)
  {
    reason_str = "DLL_PROCESS_DETACH";
    wslua_exit (g_cfg.lua.exit_script);
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

  LUA_TRACE (1, "rc: %d, dll: %s, reason_str: %s\n", rc, dll, reason_str);
  ARGSUSED (instDLL);
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

/*
 * The Lua-hooks.
 * For the moment these does nothing.
 */
int wslua_WSAStartup (WORD ver, WSADATA *data)
{
  if (g_cfg.lua.enable)
     LUA_TRACE (1, "wslua_func_sig: ~9'%s'\n", get_func_sig());
  ARGSUSED (ver);
  ARGSUSED (data);
  return (0);
}

int wslua_WSACleanup (void)
{
  if (g_cfg.lua.enable)
     LUA_TRACE (1, "wslua_func_sig: ~9'%s'\n", get_func_sig());
  return (0);
}

static BOOL execute_and_report (lua_State *l)
{
  const char *msg = "";
  int         rc = lua_pcall (l, 0, LUA_MULTRET, 0);

  if (rc == 0)
     return (TRUE);

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

/*
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

#if defined(NOT_YET)
/*
 * Extract a script from a zip-file and run it.
 * Or use one of these:
 *   https://github.com/luaforge/lar/blob/master/lar/lar.lua
 *   https://github.com/davidm/lua-compress-deflatelua
 */
#include "miniz.c"

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
#endif /* NOT_YET */


static int wslua_get_trace_level (lua_State *l)
{
  lua_pushnumber (l, g_cfg.lua.trace_level);
  return (1);
}

static int wslua_set_trace_level (lua_State *l)
{
  if (!lua_isnumber(L, 1))
  {
    lua_pushstring (L, "incorrect argument to 'g_cfg.lua.trace_level'");
    lua_error (L);
  }
  else
    g_cfg.lua.trace_level = (int) lua_tonumber (L, 1);
  ARGSUSED (l);
  return (1);
}

static int wslua_get_profiler (lua_State *l)
{
  lua_pushnumber (l, g_cfg.lua.profile);
  return (1);
}

static int wslua_register_hook (lua_State *l)
{
  const lua_CFunction func1 = lua_tocfunction (L, LUA_ENVIRONINDEX);
  const lua_CFunction func2 = lua_tocfunction (L, 2);

  LUA_TRACE (1, "func1=%p, func2=%p\n", func1, func2);
  ARGSUSED (l);
  return (1);
}

static int wslua_trace_puts (lua_State *l)
{
  trace_puts (lua_tostring(l,1));
  return (1);
}

#if 0
/*
 * This function is broken.
 * Accepts only strings passed from Lua-land.
 */
static int wslua_trace_printf (lua_State *l)
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
  trace_vprintf (fmt, args1);
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
  lua_pushstring (l, get_builder());
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

void wslua_print_stack (void)
{
  lua_Debug ar;
  int       level = 0;

  while (lua_getstack(L, level++, &ar))
  {
    lua_getinfo (L, "Snl", &ar);
    trace_printf ("  %s:", ar.short_src);
    if (ar.currentline > 0)
       trace_printf ("%d:", ar.currentline);
    if (*ar.namewhat != '\0')    /* is there a name? */
       trace_printf (" in function " LUA_QS, ar.name);
    else
    {
      if (*ar.what == 'm')       /* main? */
           trace_puts (" in main chunk");
      else if (*ar.what == 'C' || *ar.what == 't')
           trace_puts (" ?");   /* C function or tail call */
      else trace_printf (" in function <%s:%d>", ar.short_src, ar.linedefined);
    }
    trace_putc ('\n');
  }
//trace_printf ("Lua stack depth: %d.\n", level-1);
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
         trace_printf ("~9LUA_HOOKCALL");
         break;
    case LUA_HOOKRET:
         trace_printf ("~9LUA_HOOKRET");
         break;
    case LUA_HOOKLINE:
         trace_printf ("~9LUA_HOOKLINE at %d", _ld->currentline);
         break;
  }

#if 0   /** \todo */
  if (_ld->event == LUA_HOOKCALL)
  {
    lua_Debug ld;

    memset (&ld, '\0', sizeof(ld));
    lua_getinfo (l, ">nl", &ld);
    trace_printf ("ld.name:        %s\n", ld.name);
    trace_printf ("ld.short_src:   %s\n", ld.short_src);
  }
#else
  ARGSUSED (l);
#endif
  trace_puts ("~0\n");
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
  luaL_openlibs (L);    /* Load Lua libraries */

  /* Set up the 'panic' handler, which let's us control Lua execution.
   */
  lua_atpanic (L, wstrace_lua_panic);

#if 1
  lua_pushcfunction (L, wslua_get_trace_level);
  lua_setglobal (L, "get_trace_level");

  lua_pushcfunction (L, wslua_set_trace_level);
  lua_setglobal (L, "set_trace_level");
#endif

  if (g_cfg.lua.trace_level >= 3)
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
  LUA_TRACE (1, "In %s(), L=%p\n", __FUNCTION__, L);
  if (!L)
     return;

  if (init_script_ok && open_ok)
     wslua_run_script (L, script);
  lua_sethook (L, NULL, 0, 0);
  lua_close (L);
  L = NULL;
}

static const struct luaL_Reg wslua_table[] = {
  { "register_hook",       wslua_register_hook },
  { "trace_puts",          wslua_trace_puts },
//{ "trace_printf",        wslua_trace_printf },
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

/*
 * The open() function for LuaJIT must be marked as a DLL-export.
 */
__declspec(dllexport) int luaopen_wsock_trace (lua_State *l);

int luaopen_wsock_trace (lua_State *l)
{
  char *dll = strdup (get_dll_short_name());
  char *dot = strrchr (dll, '.');

  *dot = '\0';

#if (LUA_VERSION_NUM >= 502)
  /*
   * From:
   *   https://stackoverflow.com/questions/19041215/lual-openlib-replacement-for-lua-5-2
   */
  lua_newtable (l);
  luaL_setfuncs (l, wslua_table, 0);
  lua_setglobal (l, dll);
#else
  luaL_register (l, dll, wslua_table);
#endif

  LUA_TRACE (1, "%s(), dll: \"%s.dll\".\n", __FUNCTION__, dll);
  free (dll);
  return (1);
}
#endif /* USE_LUA */

