/*
 * A Lua interface for WSock-Trace.
 */
#include "common.h"

#if defined(USE_LUA)  /* Rest of file */

#include "init.h"
#include "wsock_trace_lua.h"

#include "lj_arch.h"

#if !defined(LJ_HASFFI) || (LJ_HASFFI == 0)
#error "LuaJIT needs to be built with 'LJ_HASFFI=1'."
#endif

#ifndef va_copy
#define va_copy(dst,src) ((dst) = (src))
#endif

#define LUA_TRACE(level, fmt, ...)                  \
        do {                                        \
          if (g_cfg.lua.trace_level >= level)       \
             trace_printf ("~8%s(%u): ~9" fmt "~0", \
                           __FILE__, __LINE__,      \
                           ## __VA_ARGS__);         \
        } while (0)

#define LUA_WARNING(fmt, ...)               \
        trace_printf ("~8LUA: ~9" fmt "~0", \
                      ## __VA_ARGS__)

/* There is only one Lua-state variable.
 */
static lua_State *L = NULL;

/* The function-signature of currently hooking function.
 */
const char *wslua_func_sig = NULL;

static BOOL init_script_ok = FALSE;
static BOOL open_ok        = TRUE;

BOOL wslua_DllMain (HINSTANCE instDLL, DWORD reason)
{
  const char *dll  = get_dll_full_name();
  const char *base = basename (dll);
  char        cpath [_MAX_PATH] = { "?" };
  BOOL        rc = TRUE;

  if (reason == DLL_PROCESS_ATTACH)
  {
    if (!g_cfg.lua.color_head)
       get_color (NULL, &g_cfg.lua.color_head);

    if (!g_cfg.lua.color_body)
       get_color (NULL, &g_cfg.lua.color_body);

    if (stricmp(base,get_dll_short_name()))
       rc = FALSE;
    else
    {
      snprintf (cpath, sizeof(cpath), "%.*s\\?.dll", (int)(base-dll-1), dll);
      _setenv ("LUA_CPATH", cpath, 1);
    }
  }
  LUA_TRACE (1, "rc: %d, dll: %s\n"
                 "                       %s.\n", rc, dll, cpath);
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
  return (1);
}

static int wslua_register_hook (lua_State *l)
{
  const lua_CFunction func1 = lua_tocfunction (L, LUA_ENVIRONINDEX);
  const lua_CFunction func2 = lua_tocfunction (L, 2);

  LUA_TRACE (1, "func1=%p, func2=%p\n", func1, func2);
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
static void wstrace_lua_hook (lua_State *L, lua_Debug *_ld)
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

#if 0   /* to-do */
  if (_ld->event == LUA_HOOKCALL)
  {
    lua_Debug ld;

    memset (&ld, '\0', sizeof(ld));
    lua_getinfo (L, ">nl", &ld);
    trace_printf ("ld.name:        %s\n", ld.name);
    trace_printf ("ld.short_src:   %s\n", ld.short_src);
  }
#endif
  trace_puts ("~0\n");
}

/**
 * Called from 'DllMain()' / 'DLL_PROCESS_ATTATACH' to setup Lua
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
void wslua_init (const char *script)
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

/*
 * Called from 'DllMain()' / 'DLL_PROCESS_DETACH' to tear down
 * Lua and optionally run the 'script'.
 * Provided the 'script' in 'wslua_init()' ran okay.
 */
void wslua_exit (const char *script)
{
  if (!L)
     return;

  if (init_script_ok && open_ok)
     wslua_run_script (L, script);
  lua_sethook (L, NULL, 0, 0);
  lua_close (L);
  L = NULL;
}

static const struct luaL_reg wslua_table[] = {
  { "register_hook",       wslua_register_hook },
  { "trace_puts",          wslua_trace_puts },
//{ "trace_printf",        wslua_trace_printf },
  { "get_dll_full_name",   wslua_get_dll_full_name },
  { "get_dll_short_name",  wslua_get_dll_short_name },
  { "get_builder",         wslua_get_builder },
  { "set_trace_level",     wslua_set_trace_level },
  { "get_trace_level",     wslua_get_trace_level },
  { NULL,                  NULL }
};

static int common_open (lua_State *l, const char *func, BOOL is_ours)
{
  char       *dll = strdup (get_dll_short_name());
  char       *dot = strrchr (dll, '.');
  const char *my_name = func + sizeof("luaopen_") - 1;

  assert (!strncmp(func,"luaopen_",8));

  *dot = '\0';

  if (stricmp(dll, my_name))
  {
    LUA_WARNING ("require (\"%s\") does not match our .dll basename: \"%s\"~0\n", dll, my_name);
    open_ok = FALSE;
    is_ours = FALSE;
  }

  if (is_ours)
  {
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
  }

  LUA_TRACE (1, "%s(), is_ours: %d, dll: \"%s\".\n", func, is_ours, dll);
  free (dll);
  return (is_ours ? 1 : 0);
}

#define IS_MSVC   0
#define IS_MINGW  0
#define IS_CYGWIN 0

#if defined(_MSC_VER) || defined(__clang__)
  #undef  IS_MSVC
  #define IS_MSVC 1

#elif defined(__MINGW32__)
  #undef  IS_MINGW
  #define IS_MINGW 1

#elif defined(__CYGWIN__)
  #undef  IS_CYGWIN
  #define IS_CYGWIN 1
#endif

/*
 * The open() functions for Lua-5.x.
 * These functions are marked as a DLL-export.
 *
 * Note: It is possible that if a script says:
 *  local ws = require "wsock_trace"
 *
 * and if the running program is linked to e.g. "wsock_trace_mw.dll",
 * we will get re-entered here.
 */
#define OPEN_EXPORT(func, ours)                                  \
        __declspec(dllexport) int luaopen_##func (lua_State *L); \
        int luaopen_##func (lua_State *L)                        \
        {                                                        \
          return common_open (L, __FUNCTION__, ours);            \
        }

OPEN_EXPORT (wsock_trace,         IS_WIN64 == 0 && IS_MSVC)
OPEN_EXPORT (wsock_trace_x64,     IS_WIN64 == 1 && IS_MSVC)
OPEN_EXPORT (wsock_trace_mw,      IS_WIN64 == 0 && IS_MINGW)
OPEN_EXPORT (wsock_trace_mw_x64,  IS_WIN64 == 1 && IS_MINGW)
OPEN_EXPORT (wsock_trace_cyg,     IS_WIN64 == 0 && IS_CYGWIN)
OPEN_EXPORT (wsock_trace_cyg_x64, IS_WIN64 == 1 && IS_CYGWIN)

#endif /* USE_LUA */

