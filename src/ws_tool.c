/** \file   ws_tool.c
 *  \ingroup Main
 *
 *  \brief
 *    All previous test-programs are now collected under this
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
#include "config.h"

#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <signal.h>

#include "common.h"
#include "init.h"
#include "geoip.h"
#include "getopt.h"
#include "wsock_trace_lua.h"

extern int asn_main           (int argc, char **argv);
extern int backtrace_main     (int argc, char **argv);
extern int csv_main           (int argc, char **argv);
extern int dnsbl_main         (int argc, char **argv);
extern int firewall_main      (int argc, char **argv);
extern int geoip_main         (int argc, char **argv);
extern int iana_main          (int argc, char **argv);
extern int idna_main          (int argc, char **argv);
extern int services_file_main (int argc, char **argv);
extern int test_main          (int argc, char **argv);

/* Prevent MinGW + Cygwin from globbing the cmd-line.
 */
int _dowildcard = 0;

static const struct {
       int (*main_func) (int, char**);
       char *main_name;
     } sub_commands[] = {
       { asn_main,           "asn"       },
       { backtrace_main,     "backtrace" },
       { csv_main,           "csv"       },
       { dnsbl_main,         "dnsbl"     },
       { firewall_main,      "firewall"  },
       { geoip_main,         "geoip"     },
       { iana_main,          "iana"      },
       { idna_main,          "idna"      },
       { services_file_main, "services"  },
       { test_main,          "test"      }
     };

static void show_help (const char *extra);

static int run_sub_command (int argc, char **argv)
{
  char buf[100];
  int  i, rc = 1;

  for (i = 0; i < DIM(sub_commands); i++)
  {
    if (stricmp(*argv, sub_commands[i].main_name))
       continue;

    optind = 1;         /* Restart 'getopt()' */
#if defined(__CYGWIN__)
    optreset = 1;
#endif

    rc = (*sub_commands[i].main_func) (argc, argv);
    break;
  }
  if (i == DIM(sub_commands))
  {
    snprintf (buf, sizeof(buf), "Unknown sub-command '%s'\n", *argv);
    show_help (buf);
  }
  return (rc);
}

static void show_help (const char *extra)
{
  int i;

  printf ("%sWsock-trace test tool.\n"
          "Usage: %s [-h] <command> [<args>]\n"
          "       -h:   shows this help\n"
          "Available sub-commands:\n", extra ? extra : "",
          g_data.program_name ? g_data.program_name : "ws_tool");

  for (i = 0; i < DIM(sub_commands); i++)
     printf ("  %s\n", sub_commands[i].main_name);
}

int main (int argc, char **argv)
{
  int c, do_help = 0, rc = 0;

  memset (&g_cfg, '\0', sizeof(g_cfg));

  set_program_name (argv[0]);

  while ((c = getopt (argc, argv, "+h?")) != EOF)
    switch (c)
    {
      case '?':
      case 'h':
           do_help++;
           break;
      default:
           show_help ("Illegal option\n");
           goto quit;
    }

  if (do_help >= 1)
  {
    show_help (NULL);
    goto quit;
  }

  /* Do the same as 'DllMain (inst, DLL_PROCESS_ATTACH, ...)' does
   */
  crtdbg_init();
  wsock_trace_init();

#if defined(USE_LUAJIT)
  wslua_DllMain (GetModuleHandle(NULL), DLL_PROCESS_ATTACH);
#endif

  argc -= optind;
  argv += optind;

  if (!*argv)
       show_help ("Please give a sub-command\n");
  else rc = run_sub_command (argc, argv);

quit:

  /* Does the same as 'DllMain (inst, DLL_PROCESS_DETACH, ...)'
   */
#if defined(USE_LUAJIT)
  wslua_DllMain (NULL, DLL_PROCESS_DETACH);
#endif

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
#endif
