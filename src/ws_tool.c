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

#include "common.h"
#include "init.h"
#include "geoip.h"
#include "getopt.h"

#define program_name csv_program_name
#define show_help    csv_show_help
#define main         csv_main
#define TEST_CSV
#include "csv.c"

#undef  TEST_CSV
#undef  program_name
#undef  show_help
#undef  main
#define program_name backtrace_program_name
#define show_help    backtrace_show_help
#define main         backtrace_main
#define TEST_BACKTRACE
#include "backtrace.c"

#undef  TEST_BACKTRACE
#undef  program_name
#undef  show_help
#undef  main
#define program_name geoip_program_name
#define show_help    geoip_show_help
#define main         geoip_main
#define TEST_GEOIP
#include "geoip.c"

#undef  TEST_GEOIP
#undef  program_name
#undef  show_help
#undef  main
#define program_name iana_program_name
#define show_help    iana_show_help
#define main iana_main
#define TEST_IANA
#include "iana.c"

#undef  TEST_IANA
#undef  program_name
#undef  show_help
#undef  main
#define program_name firewall_program_name
#define show_help    firewall_show_help
#define main         firewall_main
#define TEST_FIREWALL
#include "firewall.c"

#undef  TEST_FIREWALL
#undef  program_name
#undef  show_help
#undef  main
#define update_file  dnsbl_update_file
#define program_name dnsbl_program_name
#define show_help    dnsbl_show_help
#define main         dnsbl_main
#define TEST_DNSBL
#include "dnsbl.c"

#undef  TEST_DNSBL
#undef  ADD_VALUE
#undef  DEF_FUNC
#undef  program_name
#undef  show_help
#undef  main
#define program_name idna_program_name
#define show_help    idna_show_help
#define main         idna_main
#define TEST_IDNA
#include "idna.c"

#undef main
#undef program_name
#undef show_help

char *program_name;  /* For getopt.c */

static int show_help (const char *extra)
{
  if (extra)
     puts (extra);
  printf ("Wsock-trace test tool.\n"
          "Usage: %s [-d] <command> [<args>]\n"
          "  Available commands:\n"
          "    geoip        - Run a test command for 'geoip'\n"
          "    csv          - Run a test command for 'csv'\n"
          "    backtrace    - Run a test command for 'backtrace'\n"
          "    iana         - Run a test command for 'iana'\n"
          "    firewall\n", program_name);
  return (1);
}

int run_mains (int argc, char **argv)
{
  int rc;

#if defined(USE_LUA)
  wslua_DllMain (GetModuleHandle(NULL), DLL_PROCESS_ATTACH);
#endif

  if (!stricmp(*argv, "geoip"))
     rc = geoip_main (argc, argv);

  else if (!stricmp(*argv, "iana"))
     rc = iana_main (argc, argv);

  else if (!stricmp(*argv, "csv"))
     rc = csv_main (argc, argv);

  else if (!stricmp(*argv, "firewall"))
     rc = firewall_main (argc, argv);

  else if (!stricmp(*argv, "backtrace"))
     rc = backtrace_main (argc, argv);

  else if (!stricmp(*argv, "dnsbl"))
     rc = dnsbl_main (argc, argv);

  else if (!stricmp(*argv, "idna"))
     rc = idna_main (argc, argv);

  else
  {
    show_help ("Unknown command.");
    rc = 1;
  }

#if defined(USE_LUA)
  wslua_DllMain (GetModuleHandle(NULL), DLL_PROCESS_DETACH);
#endif

  return (rc);
}

int main (int argc, char **argv)
{
  int i, c, rc;

  program_name = argv[0];

  memset (&g_cfg, '\0', sizeof(g_cfg));
  crtdbg_init();
  wsock_trace_init();

  g_cfg.trace_use_ods = FALSE;
  g_cfg.DNSBL.test    = FALSE;
  g_cfg.trace_time_format = TS_RELATIVE;

  while ((c = getopt (argc, argv, "+dh?")) != EOF)
    switch (c)
    {
      case 'd':
           g_cfg.trace_level++;
           break;
      case '?':
      case 'h':
           return show_help (NULL);
      default:
           return show_help ("Illegal option");
    }

  argc -= optind;
  argv += optind;
  optind = 0;     /* restart 'getopt()' */

  for (i = 0; i < argc; i++)
     TRACE (2, "argv[%d]: '%s'\n", i, argv[i]);

  if (!*argv)
       rc = show_help ("Please give a command");
  else rc = run_mains (argc, argv);

  if (*argv && (stricmp(*argv, "geoip"))) // && stricmp(*argv, "firewall"))
  {
    wsock_trace_exit();
    crtdbg_exit();
  }
  return (rc);
}