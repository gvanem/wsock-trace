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

static int l_get_dll_name (lua_State *l)
{
  lua_pushstring (l,get_dll_name());
  return (1);
}

static void wstrace_lua_print_stack (void)
{
  lua_Debug ar;
  int level = 0;

  while (lua_getstack(L, level++, &ar))
  {
    lua_getinfo (L, "Snl", &ar);
    printf ("  %s:", ar.short_src);
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
    putchar ('\n');
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
 * The 'lua_sethook()' callback.
 */
static void wstrace_lua_hook (lua_State *L, lua_Debug *_ld)
{
  switch (_ld->event)
  {
    case LUA_HOOKCALL:
         printf ("LUA_HOOKCALL");
         break;
    case LUA_HOOKRET:
         printf ("LUA_HOOKRET");
         break;
    case LUA_HOOKLINE:
         printf ("LUA_HOOKLINE at %d", _ld->currentline);
         break;
  }
  putchar ('\n');

#if 0   /* to-do */
  if (_ld->event == LUA_HOOKCALL)
  {
    lua_Debug ld;

    memset (&ld, '\0', sizeof(ld));
    lua_getinfo (L, ">nl", &ld);
    printf ("ld.name:        %s\n", ld.name);
    printf ("ld.short_src:   %s\n", ld.short_src);
  }
#endif
}

/*
 * Called from 'wsock_trace_init()' to setup Lua and
 * optionally run the 'script'.
 */
void wstrace_init_lua (const char *script)
{
  assert (L == NULL);
  L = luaL_newstate();
  luaL_openlibs (L);    /* Load Lua libraries */

  /* Set up the 'panic' handler, which let's us control Lua execution.
   */
  lua_atpanic (L, wstrace_lua_panic);

  if (g_cfg.lua.trace_level >= 3)
     lua_sethook (L, wstrace_lua_hook, LUA_MASKCALL | LUA_HOOKRET | LUA_MASKLINE, 0);

  wstrace_lua_run_script (L, script);
}

/*
 * Called from 'wsock_trace_exit()' to tear down Lua and
 * optionally run the 'script'.
 */
void wstrace_exit_lua (const char *script)
{
  lua_sethook (L, NULL, 0, 0);
  assert (L != NULL);
  wstrace_lua_run_script (L, script);
  lua_close (L);
  L = NULL;
}

static const struct luaL_reg wstrace_lua_table[] = {
  { "register_hook", l_register_hook },
  { "trace_puts",    l_trace_puts    },
  { "get_dll_name",  l_get_dll_name },
  { NULL,            NULL }
};

static int common_open (lua_State *l, const char *my_name)
{
  char *dll = strdup (get_dll_name());
  char *dot = strrchr (dll, '.');

  *dot = '\0';

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

  LUA_TRACE (1, "%s(), dll: %s\n", my_name, dll);
  free (dll);
  return (1);
}

/*
 * The open() function names depends on wsock_trace RC_BASENAME and bitness.
 * Only MSVC supported at the moment.
 */
#if defined(_MSC_VER)
  #if defined(_M_X64) || defined(_M_AMD64)
    #define OPEN_FUNC1   luaopen_wsock_trace_x64
    #define OPEN_FUNC2 luaJIT_BC_wsock_trace_x64
  #else
    #define OPEN_FUNC1   luaopen_wsock_trace
    #define OPEN_FUNC2 luaJIT_BC_wsock_trace
  #endif

#elif defined(__MINGW32__)
  #if defined(__x86_64__) || defined(__ia64__)
    #define OPEN_FUNC1   luaopen_wsock_trace_mw_x64
    #define OPEN_FUNC2 luaJIT_BC_wsock_trace_mw_x64
  #else
    #define OPEN_FUNC1   luaopen_wsock_trace_mw
    #define OPEN_FUNC2 luaJIT_BC_wsock_trace_mw
  #endif

#elif defined(__CYGWIN__)
  #if defined(__x86_64__) || defined(__ia64__)
    #define OPEN_FUNC1   luaopen_wsock_trace_cyg_x64
    #define OPEN_FUNC2 luaJIT_BC_wsock_trace_cyg_x64
  #else
    #define OPEN_FUNC1   luaopen_wsock_trace_cyg
    #define OPEN_FUNC2 luaJIT_BC_wsock_trace_cyg
  #endif
#endif

__declspec(dllexport) int OPEN_FUNC1 (lua_State *L);
__declspec(dllexport) int OPEN_FUNC2 (lua_State *L);

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
int OPEN_FUNC1 (lua_State *l)
{
  return common_open (l, __FUNCTION__);
}

/*
 * The open() function for Lua-JIT.
 * Also marked as a DLL-export.
 */
int OPEN_FUNC2 (lua_State *l)
{
  return common_open (l, __FUNCTION__);
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

