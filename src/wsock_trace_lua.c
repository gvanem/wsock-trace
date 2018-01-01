/*
 * A Lua interface for WSock-Trace.
 */
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

#if defined(USE_LUA)  /* Rest of file */

#include "common.h"
#include "init.h"
#include "wsock_trace_lua.h"

#include "lj_arch.h"

#if !defined(LJ_HASFFI) || (LJ_HASFFI == 0)
#error "LuaJIT needs to be built with 'LJ_HASFFI=1'."
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
const char *func_sig = NULL;

const char *get_func_sig (void)
{
  static char buf [100];

  if (!func_sig)
     return ("None");

  strcpy (buf, func_sig);

#if !(defined(_MSC_VER) && defined(__FUNCSIG__))
  strcat (buf, "()");
#endif
  return (buf);
}

/*
 * Inspired from the example in Swig:
 * <Swig-Root>/Examples/lua/embed/embed.c
 */
static void wstrace_lua_run_script (lua_State *l, const char *script)
{
  const char *msg;
  int   rc;

  LUA_TRACE (1, "Launching script: %s\n", script ? script : "<none>");

  if (!script)
     return;

  if (luaL_loadfile(l, script))
  {
    LUA_WARNING ("~1Failed to load script:~0\n  %s\n", script);
    return;
  }

  rc = lua_pcall (l, 0, LUA_MULTRET, 0);
  if (rc == 0)
     return;

  if (!lua_isnil(l, -1))
  {
    msg = lua_tostring (l, -1);
    if (!msg)
       msg = "(error object is not a string)";
    LUA_WARNING ("~1%s:\n  ~0%s\n", script, msg);
    lua_pop (l, 1);
  }
  else
    LUA_WARNING ("~1%s: rc: %d\n", script, rc);
}

static int l_register_hook (lua_State *l)
{
  const lua_CFunction func1 = lua_tocfunction (L,1);
  const lua_CFunction func2 = lua_tocfunction (L,2);

  LUA_TRACE (1, "func1=%p, func2=%p\n", func1, func2);
  return (1);
}

static int l_trace_puts (lua_State *l)
{
  trace_puts (lua_tostring(l,1));
  return (1);
}

static void wstrace_lua_print_stack (void)
{
  lua_Debug ar;
  int level = 0;

  while (lua_getstack(L, level++, &ar))
  {
    lua_getinfo (L, "Snl", &ar);
    printf ("\t%s:", ar.short_src);
    if (ar.currentline > 0)
       printf ("%d:", ar.currentline);
    if (*ar.namewhat != '\0')    /* is there a name? */
       printf (" in function " LUA_QS, ar.name);
    else
    {
      if (*ar.what == 'm')  /* main? */
           printf (" in main chunk");
      else if (*ar.what == 'C' || *ar.what == 't')
           printf (" ?");   /* C function or tail call */
      else printf (" in function <%s:%d>", ar.short_src, ar.linedefined);
    }
    printf ("\n");
  }
  printf ("Lua stack depth: %d\n", level-1);
}

static int wstrace_lua_panic (lua_State *l)
{
  const char *err_msg = lua_tostring (l, 1);

  LUA_WARNING ("~1Panic: %s\n", err_msg);
  wstrace_lua_print_stack();
  lua_close (L);
  L = NULL;
  return (0);
}

/*
 * Called from 'wsock_trace_init()' to setup Lua and
 * optionally run the 'script'.
 */
void wstrace_init_lua (const char *script)
{
  if (!g_cfg.lua.enable)
     return;

  assert (L == NULL);
  L = luaL_newstate();
  luaL_openlibs (L);    /* Load Lua libraries */

  /* Set up the 'panic' handler, which let's us control Lua execution.
   */
  lua_atpanic (L, wstrace_lua_panic);

//luaopen_wsock_trace (L);
  wstrace_lua_run_script (L, script);
}

/*
 * Called from 'wsock_trace_exit()' to tear down Lua and
 * optionally run the 'script'.
 */
void wstrace_exit_lua (const char *script)
{
  if (!g_cfg.lua.enable)
     return;

  assert (L != NULL);
  wstrace_lua_run_script (L, script);
  lua_close (L);
  L = NULL;
}

static const struct luaL_reg wstrace_lua_table[] = {
  { "register_hook", l_register_hook },
  { "trace_puts",    l_trace_puts    },
  { NULL,            NULL }
};

/*
 * The open() function for normal Lua-5.x.
 * This function is marked as a DLL-export.
 *
 * Note: It is possible that if a script says:
 *  local ws = require "wsock_trace"
 *
 * and the running program is linked to e.g. "wsock_trace_mw.dll", we
 * gets re-entered here.
 */
int luaopen_wsock_trace (lua_State *l)
{
  char *dll = strdup (wsock_trace_dll_name);
  char *dot = strrchr (dll, '.');

  *dot = '\0';
  LUA_TRACE (2, "In %s()\n", __FUNCTION__);

#if (LUA_VERSION_NUM >= 502)
  /*
   * From:
   *   https://stackoverflow.com/questions/19041215/lual-openlib-replacement-for-lua-5-2
   */
  lua_newtable (l);
  luaL_setfuncs (l, wstrace_lua_table, 0);
  lua_setglobal (l, dll);
#else
  luaL_register (l, dll, wstrace_lua_table);
#endif

//wstrace_lua_print_stack(); // test!
  free (dll);
  return (1);
}

/*
 * The open() function for Lua-JIT.
 * Also marked as a DLL-export.
 */
int luaJIT_BC_wsock_trace (lua_State *l)
{
  return luaopen_wsock_trace (l);
}

int l_WSAStartup (WORD ver, WSADATA *data)
{
  LUA_TRACE (1, "func_sig: ~9'%s'\n", get_func_sig());
  return (0);
}

int l_WSACleanup (void)
{
  LUA_TRACE (1, "func_sig: ~9'%s'\n", get_func_sig());
  return (0);
}
#endif /* USE_LUA */

