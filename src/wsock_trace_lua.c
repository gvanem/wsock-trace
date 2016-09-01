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

#define LUA_TRACE(level, fmt, ...)                  \
        do {                                        \
          if (g_cfg.trace_level >= level)           \
             trace_printf ("~2%s(%u): ~4" fmt "~0", \
                           __FILE__, __LINE__,      \
                           ## __VA_ARGS__);         \
        } while (0)

/* There is only one Lua-state variable.
 */
static lua_State *L = NULL;

/* The function-signature of currently hooking function.
 */
const char *func_sig = NULL;

/*
 * Inspired from the example in Swig:
 * <Swig-Root>/Examples/lua/embed/embed.c
 */
static void run_lua_script (lua_State *l, const char *script)
{
  if (!script)
     return;

  if (luaL_loadfile(l, script))
  {
    WARNING ("Failed to load script: %s\n", script);
    return;
  }
  if (lua_pcall(l, 0, LUA_MULTRET, 0))
     WARNING ("Failure in script:\n    %s\n", lua_tostring(l, -1));
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
    if (*ar.namewhat != '\0') {  /* is there a name? */
       printf (" in function " LUA_QS, ar.name);
    }
    else
    {
      if (*ar.what == 'm')  /* main? */
        printf (" in main chunk");
      else if (*ar.what == 'C' || *ar.what == 't')
        printf (" ?");  /* C function or tail call */
      else
        printf (" in function <%s:%d>",
                ar.short_src, ar.linedefined);
    }
    printf("\n");
  }
  printf( "Lua stack depth: %d\n", level-1);
}

static int wstrace_lua_panic (lua_State *l)
{
  const char *err_msg = lua_tostring (l, 1);

  WARNING ("Unprotected error from LUA runtime: %s\n", err_msg);
  wstrace_lua_print_stack();
  lua_close (L);
  L = NULL;
  return (0);
}

void wstrace_init_lua (const char *script)
{
  assert (L == NULL);
  L = luaL_newstate();
  luaL_openlibs (L);    /* Load Lua libraries */

  /* Set up the 'panic' handler, which let's us control.
  */
  lua_atpanic (L, wstrace_lua_panic);

  luaopen_wsock_trace (L);
  run_lua_script (L, script);
}

void wstrace_exit_lua (const char *script)
{
  assert (L != NULL);
  run_lua_script (L, script);
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
 * Note: Is is possible that if a script says:
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
  luaL_register (l, dll, wstrace_lua_table);

//wstrace_lua_print_stack(); // test!
  free (dll);
  return (1);
}

/*
 * The open() function for Lua-JIT.
 */
int luaJIT_BC_wsock_trace (lua_State *l)
{
  char *dll = strdup (wsock_trace_dll_name);
  char *dot = strrchr (dll, '.');

  *dot = '\0';
  LUA_TRACE (2, "In %s()\n", __FUNCTION__);
  luaL_register (l, dll, wstrace_lua_table);
  free (dll);
  return (1);
}

int l_WSAStartup (WORD ver, WSADATA *data)
{
  LUA_TRACE (1, "func_sig: ~5'%s'\n", func_sig);
  return (0);
}

#endif /* USE_LUA */

