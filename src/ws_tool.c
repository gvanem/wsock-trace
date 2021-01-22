/** \file   ws_tool.c
 *  \ingroup Main
 *
 *  \brief
 *    All previous test-programs are now corrected under this
 *    "umbrella program". Each `main()` function is now `xx_main()`
 *    called from this program depending on the first non-option
 *    given in `argv[]`.
 *    \eg{}
 *     \code
 *       ws_tool.exe -d geoip -4 8.8.8.8
 *     \code
 *    will set `g_cfg.trace_level = 1` and call `geoip_main()` with
 *    "-4" and "8.8.8.8" in it's `argv[]`.
 */
#define IN_WS_TOOL_C

/* Because of warning "Use getaddrinfo() or GetAddrInfoW() instead ..." in idna.c.
 */
#ifndef _WINSOCK_DEPRECATED_NO_WARNINGS
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#endif

#if defined(__WATCOMC__)
  /*
   * Required to define `IN6_IS_ADDR_LOOPBACK()` etc. in
   * OpenWatcom's <ws2ipdef.h>.
   */
  #undef  NTDDI_VERSION
  #define NTDDI_VERSION 0x05010000
#endif

#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <signal.h>
#include <tchar.h>

#include "common.h"
#include "init.h"
#include "geoip.h"
#include "getopt.h"
#include "wsock_trace_lua.h"

#define show_help   backtrace_show_help
#define main        backtrace_main
#define TEST_BACKTRACE
#include "backtrace.c"
#undef  TEST_BACKTRACE

#undef  show_help
#undef  main
#define show_help   csv_show_help
#define main        csv_main
#define TEST_CSV
#include "csv.c"
#undef  TEST_CSV

#undef  show_help
#undef  main
#define show_help   dnsbl_show_help
#define main        dnsbl_main
#define TEST_DNSBL
#include "dnsbl.c"
#undef  TEST_DNSBL

#undef  show_help
#undef  main
#define show_help   firewall_show_help
#define main        firewall_main
#define TEST_FIREWALL
#include "firewall.c"
#undef  TEST_FIREWALL

#undef  show_help
#undef  main
#define update_file geoip_local_update_file
#define show_help   geoip_show_help
#define main        geoip_main
#define TEST_GEOIP
#include "geoip.c"
#undef  TEST_GEOIP

#undef  show_help
#undef  main
#define show_help   iana_show_help
#define main        iana_main
#define TEST_IANA
#include "iana.c"
#undef  TEST_IANA

#undef  show_help
#undef  main
#define show_help   idna_show_help
#define main        idna_main
#define TEST_IDNA
#include "idna.c"

#undef  show_help
#undef  main
#define show_help   test_show_help
#define main        test_main
#include "test.c"

#undef main
#undef show_help

char *program_name;  /* For getopt.c */

/* Prevent MinGW + Cygwin from globbing the cmd-line.
 */
int _dowildcard = 0;

static int show_help (const char *extra)
{
  if (extra)
     puts (extra);
  printf ("Wsock-trace test tool.\n"
          "Usage: %s [-dhH] <command> [<args>]\n"
          "  Available commands:\n"
          "    backtrace   - Run a command in 'backtrace'\n"
          "    csv         - Run a command in 'csv'\n"
          "    dnsbl       - Run a command in 'dnsbl'\n"
          "    firewall    - Run a command in 'firewall'\n"
          "    geoip       - Run a command in 'geoip'\n"
          "    iana        - Run a command in 'iana'\n"
          "    idna        - Run a command in 'idna'\n"
          "    test        - Run a command in 'test'\n", program_name);
  return (1);
}

#define _STR2(x) #x
#define _STR(x)  _STR2(x)

#define SHOW_SUB_HELP(prog) do {          \
        puts ("\nHelp for '" #prog "':"); \
        program_name = _STR(prog);        \
        prog ##_show_help();              \
      } while (0)

static int show_help_all (void)
{
  show_help (NULL);
  SHOW_SUB_HELP (backtrace);
  SHOW_SUB_HELP (csv);
  SHOW_SUB_HELP (dnsbl);
  SHOW_SUB_HELP (firewall);
  SHOW_SUB_HELP (geoip);
  SHOW_SUB_HELP (iana);
  SHOW_SUB_HELP (idna);
  SHOW_SUB_HELP (test);
  return (1);
}

int run_mains (int argc, char **argv)
{
  char buf[100];
  int  rc;

  set_dll_full_name (GetModuleHandle(NULL));

#if defined(USE_LUA)
  wslua_DllMain (NULL, DLL_PROCESS_ATTACH);
#endif

  if (!stricmp(*argv, "backtrace"))
     rc = backtrace_main (argc, argv);

  else if (!stricmp(*argv, "csv"))
     rc = csv_main (argc, argv);

  else if (!stricmp(*argv, "dnsbl"))
     rc = dnsbl_main (argc, argv);

  else if (!stricmp(*argv, "firewall"))
     rc = firewall_main (argc, argv);

  else if (!stricmp(*argv, "geoip"))
     rc = geoip_main (argc, argv);

  else if (!stricmp(*argv, "iana"))
     rc = iana_main (argc, argv);

  else if (!stricmp(*argv, "idna"))
     rc = idna_main (argc, argv);

  else if (!stricmp(*argv, "test"))
     rc = test_main (argc, argv);

  else
  {
    snprintf (buf, sizeof(buf), "Unknown command '%s'", *argv);
    show_help (buf);
    rc = 1;
  }

#if defined(USE_LUA)
  wslua_DllMain (NULL, DLL_PROCESS_DETACH);
#endif

  return (rc);
}

int main (int argc, char **argv)
{
  int c, rc;

  program_name = argv[0];

  memset (&g_cfg, '\0', sizeof(g_cfg));
  crtdbg_init();
  wsock_trace_init();

  g_cfg.trace_use_ods = FALSE;
  g_cfg.DNSBL.test    = FALSE;
  g_cfg.trace_time_format = TS_RELATIVE;

  while ((c = getopt (argc, argv, "+dHh?")) != EOF)
    switch (c)
    {
      case 'd':
           g_cfg.trace_level++;
           break;
      case 'H':
           return show_help_all();
      case '?':
      case 'h':
           return show_help (NULL);
      default:
           return show_help ("Illegal option");
    }

  argc -= optind;
  argv += optind;

  /* Restart 'getopt()'
   */
  optind = 1;
#if defined(__CYGWIN__)
  optreset = 1;
#endif

  if (!*argv)
       rc = show_help ("Please give a command");
  else rc = run_mains (argc, argv);

  wsock_trace_exit();
  crtdbg_exit();
  return (rc);
}

#if defined(__GNUC__)
int volatile cleaned_up = 0;
int volatile startup_count = 0;

int WSAError_save_restore (int pop)
{
  ARGSUSED (pop);
  return (0);
}

void load_ws2_funcs (void)
{
}

const struct LoadTable *find_ws2_func_by_name (const char *func)
{
  ARGSUSED (func);
  return (NULL);
}

const char *sockaddr_str2 (const struct sockaddr *sa, const int *sa_len)
{
  ARGSUSED (sa);
  ARGSUSED (sa_len);
  return (NULL);
}
#endif
