/**\file    init.c
 * \ingroup Main
 *
 * \brief
 *  Most things here are called from `wsock_trace_init()`
 *  which is called from `DllMain()`:
 *
 * \li  Parsing of the `wsock_trace` config-file.
 * \li  exclude-list handling.
 */

#include <stdint.h>
#include <limits.h>
#include <time.h>
#include <fcntl.h>
#include <errno.h>
#include <math.h>
#include <locale.h>

#include "config.h"
#include "common.h"
#include "wsock_trace.h"
#include "bfd_gcc.h"
#include "dump.h"
#include "geoip.h"
#include "idna.h"
#include "smartlist.h"
#include "stkwalk.h"
#include "overlap.h"
#include "hosts.h"
#include "services.h"
#include "firewall.h"
#include "cpu.h"
#include "asn.h"
#include "iana.h"
#include "dnsbl.h"
#include "in_addr.h"
#include "init.h"

#define FREE(p)   (p ? (void) (free(p), p = NULL) : (void)0)

struct config_table g_cfg;

CONSOLE_SCREEN_BUFFER_INFO console_info;

static HANDLE console_hnd = INVALID_HANDLE_VALUE;

/* The "Thread Local Storage" index used per thread to internal data.
 */
DWORD ws_Tls_index = TLS_OUT_OF_INDEXES; /* == DWORD_MAX */

/* Signal we're called via DllMain()
 */
BOOL ws_from_dll_main;

/* Use CreateSemaphore() to check for multiple instances of ourself.
 */
HANDLE      ws_sema = INVALID_HANDLE_VALUE;
BOOL        ws_sema_inherited;
const char *ws_sema_name = "Global\\wsock_trace-semaphore";

/**
 * \typedef exclude
 *
 * Structure for `exclude_list*()` functions.
 * This is used to exclude both tracing of functions,
 * programs ("addId") and addresses in firewall.c.
 */
typedef struct exclude {
        char        *name;          /**< The `name` to exclude from trace */
        uint64       num_excludes;  /**< Number of times this `name` was excluded */
        exclude_type which;         /**< A single `exclude_type` of the above `name` */
      } exclude;

/* Dynamic array of above exclude structure.
 */
static smartlist_t *exclude_list = NULL;

/* Set and restore the "Invalid Parameter Handler".
 */
static void set_invalid_handler (void);
static void reset_invalid_handler (void);

/*
 * Wait on the global semaphore to get freed.
 */
void ws_sema_wait (void)
{
  while (ws_sema && ws_sema != INVALID_HANDLE_VALUE)
  {
    DWORD ret = WaitForSingleObject (ws_sema, 0);

    if (ret == WAIT_OBJECT_0)
       break;
    if (ret == WAIT_FAILED)
    {
      SetLastError (0);
      break;
    }
    g_cfg.counts.sema_waits++;
    Sleep (5);
  }
}

/*
 * Release the global semaphore.
 */
void ws_sema_release (void)
{
  if (ws_sema && ws_sema != INVALID_HANDLE_VALUE)
     ReleaseSemaphore (ws_sema, 1, NULL);
}

/**
 * Get the `start-ticks` value for showing time-stamps.
 *
 * \note
 *   The `g_cfg.clocks_per_usec` is not the true CPU-speed.
 *   On a multicore CPU, this is normally higher than the real
 *   CPU MHz frequeny.
 */
static void init_timestamp (void)
{
  LARGE_INTEGER rc;
  uint64        frequency;
  double        MHz;

  QueryPerformanceFrequency (&rc);
  frequency = rc.QuadPart;
  g_cfg.clocks_per_usec = frequency / 1000000ULL;
  MHz = (double)frequency / 1E3;
  if (MHz > 1000.0)
       TRACE (2, "QPC speed: %.3f GHz\n", MHz/1000.0);
  else TRACE (2, "QPC speed: %.0f MHz\n", MHz);

  QueryPerformanceCounter (&rc);
  g_cfg.start_ticks = rc.QuadPart;
}

static void set_time_format (TS_TYPE *ret, const char *val)
{
  *ret = TS_NONE;

  if (!stricmp(val, "absolute"))
     *ret = TS_ABSOLUTE;
  else if (!stricmp(val, "relative"))
     *ret = TS_RELATIVE;
  else if (!stricmp(val, "delta"))
     *ret = TS_DELTA;
  TRACE (4, "val: %s -> TS_TYPE: %d\n", val, *ret);
}

/**
 * Return the preferred time-stamp string.
 *
 * \todo the below `buf[]` should be a "Thread Local" variable.
 * \ref  https://docs.microsoft.com/en-us/windows/win32/dlls/using-thread-local-storage-in-a-dynamic-link-library
 */
const char *get_timestamp (void)
{
  static LARGE_INTEGER last = {{ S64_SUFFIX(0) }};
  static char          buf [40];
  SYSTEMTIME           now;
  LARGE_INTEGER        ticks;
  int64                clocks;

  switch (g_cfg.trace_time_format)
  {
//  case TS_ELAPSED:
    case TS_RELATIVE:
    case TS_DELTA:
         if (last.QuadPart == 0ULL)
            last.QuadPart = g_cfg.start_ticks;

         QueryPerformanceCounter (&ticks);
         if (g_cfg.trace_time_format == TS_RELATIVE)
              clocks = (int64) (ticks.QuadPart - g_cfg.start_ticks);
         else clocks = (int64) (ticks.QuadPart - last.QuadPart);

         last = ticks;

         if (g_cfg.trace_time_usec)
         {
           double      usec = (double)clocks / (double)g_cfg.clocks_per_usec;
           int         dec = (int) fmodl (usec, 1000000.0);
           const char *sec = qword_str ((unsigned __int64) (usec/1000000.0));
           char *p;

           strcpy (buf, sec);
           p = strchr (buf, '\0');
           if (p) /* could be NULL due to another thread calling this function */
           {
             *p++ = '.';
             _utoa10w (dec, 6, p);
           }
           strcat (buf, " sec: ");
         }
         else
         {
           double      msec = (double)clocks / ((double)g_cfg.clocks_per_usec * 1000.0);
           int         dec = (int) fmodl (msec, 1000.0);
           const char *sec = qword_str ((unsigned __int64) (msec/1000.0));
           char *p;

           strcpy (buf, sec);
           p = strchr (buf, '\0');
           if (p)  /* could be NULL due to another thread calling this function */
           {
             *p++ = '.';
             _utoa10w (dec, 3, p);
           }
           strcat (buf, " sec: ");
         }
         return (buf);

    case TS_ABSOLUTE:
         GetLocalTime (&now);
         if (g_cfg.trace_time_usec)
              sprintf (buf, "%02u:%02u:%02u.%06u: ", now.wHour, now.wMinute, now.wSecond, now.wMilliseconds * 1000);
         else sprintf (buf, "%02u:%02u:%02u.%03u: ", now.wHour, now.wMinute, now.wSecond, now.wMilliseconds);
         return (buf);

    case TS_NONE:
         return ("");
  }
  return ("");
}

/*
 * Return a time-stamp as a double.
 * Works independently of whether 'init_timestamp()' was called or not.
 */
double get_timestamp_now (void)
{
  static uint64 frequency = U64_SUFFIX(0);
  LARGE_INTEGER ticks;
  double        sec;

  if (frequency == U64_SUFFIX(0))
     QueryPerformanceFrequency ((LARGE_INTEGER*)&frequency);

  QueryPerformanceCounter (&ticks);
  sec = 1E6 * ((double)ticks.QuadPart / (double)frequency);
  return (sec);
}

/**
 * Format a date string from a `SYSTEMTIME*`.
 */
const char *get_date_str (const SYSTEMTIME *st)
{
  static char time [30];
  static char months [3*12] = { "JanFebMarAprMayJunJulAugSepOctNovDec" };
  snprintf (time, sizeof(time), "%02d %.3s %04d",
            st->wDay, months + 3*(st->wMonth-1), st->wYear);
  return (time);
}

/**
 * Format a date/time string for current local-time.
 */
const char *get_time_now (void)
{
  static char time[50];
  SYSTEMTIME  now;

  GetLocalTime (&now);
  snprintf (time, sizeof(time), "%s, %02u:%02u:%02u",
            get_date_str(&now), now.wHour, now.wMinute, now.wSecond);
  return (time);
}

static BOOL image_opt_header_is_msvc (HMODULE mod)
{
  const IMAGE_DOS_HEADER      *dos = (const IMAGE_DOS_HEADER*) mod;
  const IMAGE_NT_HEADERS      *nt  = (const IMAGE_NT_HEADERS*) ((const BYTE*)mod + dos->e_lfanew);
  const IMAGE_OPTIONAL_HEADER *opt = (const IMAGE_OPTIONAL_HEADER*) &nt->OptionalHeader;

  TRACE (2, "opt->MajorLinkerVersion: %u, opt->MinorLinkerVersion: %u\n",
         opt->MajorLinkerVersion, opt->MinorLinkerVersion);
  return (opt->MajorLinkerVersion >= 10 && opt->MinorLinkerVersion == 0);
}

static BOOL image_opt_header_is_mingw (HMODULE mod)
{
  const IMAGE_DOS_HEADER      *dos = (const IMAGE_DOS_HEADER*) mod;
  const IMAGE_NT_HEADERS      *nt  = (const IMAGE_NT_HEADERS*) ((const BYTE*)mod + dos->e_lfanew);
  const IMAGE_OPTIONAL_HEADER *opt = (const IMAGE_OPTIONAL_HEADER*) &nt->OptionalHeader;

  TRACE (2, "opt->MajorLinkerVersion: %u, opt->MinorLinkerVersion: %u\n",
         opt->MajorLinkerVersion, opt->MinorLinkerVersion);
  return (opt->MajorLinkerVersion >= 2 && opt->MajorLinkerVersion < 30);
}

static BOOL image_opt_header_is_cygwin (HMODULE mod)
{
  const IMAGE_DOS_HEADER      *dos = (const IMAGE_DOS_HEADER*) mod;
  const IMAGE_NT_HEADERS      *nt  = (const IMAGE_NT_HEADERS*) ((const BYTE*)mod + dos->e_lfanew);
  const IMAGE_OPTIONAL_HEADER *opt = (const IMAGE_OPTIONAL_HEADER*) &nt->OptionalHeader;
  const IMAGE_FILE_HEADER     *fh  = (const IMAGE_FILE_HEADER*) &nt->FileHeader;
  BOOL  wild_tstamp = FALSE;

  /*
   * File-headers in CygWin32's .EXEs often seems to contain junk:
   *
   *   TimeDateStamp:     20202020 -> Fri Jan 30 03:38:08 1987
   *
   * or some time in the future.
   */
  if (fh->TimeDateStamp == 0x20202020 || fh->TimeDateStamp > (DWORD)time(NULL))
     wild_tstamp = TRUE;

  TRACE (2, "opt->MajorLinkerVersion: %u, opt->MinorLinkerVersion: %u, wild_tstamp: %d\n",
         opt->MajorLinkerVersion, opt->MinorLinkerVersion, wild_tstamp);
  return ((opt->MajorLinkerVersion >= 2 && opt->MajorLinkerVersion < 30) || wild_tstamp);
}

/*
 * Check if we're linked to a program that is a GUI app.
 * If we are, we might need to disable sound etc.
 */
static BOOL image_opt_header_is_gui_app (HMODULE mod)
{
  const IMAGE_DOS_HEADER *dos = (const IMAGE_DOS_HEADER*) mod;
  const IMAGE_NT_HEADERS *nt = (const IMAGE_NT_HEADERS*) ((const BYTE*)mod + dos->e_lfanew);

  return (nt->OptionalHeader.Subsystem == IMAGE_SUBSYSTEM_WINDOWS_GUI);
}

/*
 * Return the next line from the config-file with key, value and
 * section. Increment line of config-file.
 */
static int config_get_line (FILE        *fil,
                            unsigned    *line,
                            const char **key_p,
                            const char **val_p,
                            const char **section_p)
{
  static char key[256], val[512], val2[512], section[40];
  static BOOL seen_a_section = FALSE;
  char  *p, *q;
  int    len;

  while (1)
  {
    char buf[500];

    if (!fgets(buf, sizeof(buf)-1, fil))   /* EOF */
       return (0);

    for (p = buf; *p && isspace((int)*p); )
        p++;

    if (*p == '#' || *p == ';')
    {
      (*line)++;
      continue;
    }

    if (!seen_a_section)
       *section = '\0';

    /*
     * Hit a '[section]' line. Let the caller switch to another config-table.
     */
    if (sscanf(p, "[%[^]\r\n]", section) == 1)
    {
      (*line)++;
      *section_p = section;
      seen_a_section = TRUE;
      continue;
    }

    if (sscanf(p, "%[^= ] = %[^\r\n]", key, val) != 2)
    {
      (*line)++;
      continue;
    }

    q = strrchr (val, '\"');
    p = strchr (val, ';');

    /* Remove trailing comments
     */
    if (p > q)
       *p = '\0';
    p = strchr (val, '#');
    if (p > q)
       *p = '\0';

    /* Remove trailing space.
     */
    for (len = (int)strlen(val)-1; len >= 0 && isspace((int)val[len]); )
        val[len--] = '\0';
    break;
  }

  (*line)++;
  *key_p = key;
  *val_p = getenv_expand (val, val2, sizeof(val2));
  return (1);
}

/**
 * Given a C-format, extract the 1st word from it and check
 * if the function / program should be excluded from tracing.
 *
 * We always assume that `fmt` starts with a valid name.
 * Using `strnicmp()` avoids copying `fmt` into a local
 * buffer first.
 */
BOOL exclude_list_get (const char *fmt, unsigned exclude_which)
{
  size_t len;
  int    i, max;

  /* If no tracing of any callers, that should exclude everything.
   */
  if (exclude_which == EXCL_FUNCTION && g_cfg.trace_caller <= 0)
     return (TRUE);

  max = exclude_list ? smartlist_len (exclude_list) : 0;
  for (i = 0; i < max; i++)
  {
    struct exclude *ex = smartlist_get (exclude_list, i);

    len = strlen (ex->name);
    if ((ex->which & exclude_which) && !strnicmp(fmt, ex->name, len))
    {
      ex->num_excludes++;
      return (TRUE);
    }
  }
  return (FALSE);
}

BOOL exclude_list_free (void)
{
  smartlist_wipe (exclude_list, free);
  exclude_list = NULL;
  return (TRUE);
}

/*
 * \todo: Make 'FD_ISSET' an alias for '__WSAFDIsSet'.
 *        Print a warning when trying to exclude an unknown Winsock function.
 */
static BOOL _exclude_list_add (const char *name, unsigned exclude_which)
{
  static const struct search_list exclude_flags[] = {
                    { EXCL_NONE,     "EXCL_NONE"     },
                    { EXCL_FUNCTION, "EXCL_FUNCTION" },
                    { EXCL_PROGRAM,  "EXCL_PROGRAM"  },
                    { EXCL_ADDRESS,  "EXCL_ADDRESS"  },
                  };
  struct exclude *ex = NULL;
  const char     *p = name;
  size_t          len = strlen (p);
  u_char          ia4[4], ia6[16];
  char            prog [_MAX_PATH];
  exclude_type    which = EXCL_NONE;

  if (exclude_which & EXCL_ADDRESS)
  {
    if (_wsock_trace_inet_pton(AF_INET, name, ia4, NULL) == 1 ||
        _wsock_trace_inet_pton(AF_INET6, name, ia6, NULL) == 1)
       which = EXCL_ADDRESS;
  }

  if (which == EXCL_NONE && (exclude_which & EXCL_PROGRAM))
  {
    if (strchr(p+1,'"') > strchr(p,'"'))
    {
      len -= 2;
      p++;
    }
    p = _strlcpy (prog, p, min(len+1, sizeof(prog)));
    if (basename(prog) > prog && !file_exists(prog))
         TRACE (1, "EXCL_PROGRAM '%s' does not exist.\n", prog);
    else which = EXCL_PROGRAM;
  }

  if (which == EXCL_NONE && (exclude_which & EXCL_FUNCTION))
  {
    if (isalpha((int)*p))
       which = EXCL_FUNCTION;
  }

  if (which != EXCL_NONE)
  {
    if (!exclude_list)
       exclude_list = smartlist_new();

    ex = malloc (sizeof(*ex)+len+1);
    ex->num_excludes = 0;
    ex->which        = which;
    ex->name         = _strlcpy ((char*)(ex+1), p, len+1);
    smartlist_add (exclude_list, ex);
  }

  TRACE (3, "_exclude_list_add() of '%s', which: %s.\n",
         ex ? ex->name : name, flags_decode(which, exclude_flags, DIM(exclude_flags)));
  return (which != EXCL_NONE);
}

/**
 * Handler for `"exclude = func1, func2"` or <br>
 *             `"exclude = prog1, prog2"` or <br>
 *             `"exclude = addr1, addr2"`.
 *
 * If `(which & EXCL_PROGRAM) == EXCL_PROGRAM`, allow a `name` with quotes (`""`).
 * But remove those before storing the `name`.
 */
BOOL exclude_list_add (const char *name, unsigned exclude_which)
{
  const char *tok_fmt = " ,";
  char       *p, *tok, *copy = strdup (name);

  p = copy;

  /* If adding a `"program with spaces.exe"`, we must use `strtok (p, ",")`.
   */
  if (exclude_which & EXCL_PROGRAM)
  {
    char *end;
    while (*p == '"')
       p++;
    end = strrchr (p, '"');
    if (p > copy && end > p)
       *end = '\0';
    tok_fmt = ",";
  }

  for (tok = strtok(p, tok_fmt); tok; tok = strtok(NULL, tok_fmt))
  {
    if (exclude_which & EXCL_PROGRAM)
       while (*tok == ' ')
          tok++;
    _exclude_list_add (tok, exclude_which);
  }
  free (copy);
  return (TRUE);
}

/*
 * Open the config-file given by 'base_name'.
 *
 * First try file pointed to by %WSOCK_TRACE%,
 * then in current_dir.
 * then in %APPDATA%.
 */

/*
 * Ignore stuff like:
 *   warning: '%.30s' directive output may be truncated writing 11 bytes into a region
 *            of size between 0 and 259 [-Wformat-truncation=]
 */
#if !defined(__clang__)
  GCC_PRAGMA (GCC diagnostic push)
  GCC_PRAGMA (GCC diagnostic ignored "-Wformat-truncation=")
#endif

static char fname [MAX_PATH];

static FILE *open_config_file (const char *base_name)
{
  char *appdata, *env = getenv_expand ("WSOCK_TRACE", fname, sizeof(fname));
  FILE *fil;

  TRACE (2, "%%WSOCK_TRACE%%=%s.\n", env);

  if (env == fname)
  {
    if (!file_exists(fname))
    {
      WARNING ("%%WSOCK_TRACE=\"%s\" does not exist.\nRunning with default values.\n", env);
      return (NULL);
    }
  }
  else
    snprintf (fname, sizeof(fname), "%s\\%.30s", curr_dir, base_name);

  fil = fopen (fname, "r");
  if (!fil)
  {
    appdata = getenv ("APPDATA");
    if (appdata)
    {
      snprintf (fname, sizeof(fname), "%s\\%s", appdata, base_name);
      fil = fopen (fname, "r");
    }
  }
  TRACE (2, "config-file: \"%s\". %sfound.\n", fname, fil ? "" : "not ");
  return (fil);
}

#if !defined(__clang__)
  GCC_PRAGMA (GCC diagnostic pop)
#endif

const char *config_file_name (void)
{
  return (fname);
}

/*
 * Handler for default section or '[core]' section.
 */
static void parse_core_settings (const char *key, const char *val, unsigned line)
{
  if (!stricmp(key, "trace_level"))
     g_cfg.trace_level = atoi (val);

  else if (!stricmp(key, "trace_overlap"))
     g_cfg.trace_overlap = atoi (val);

  else if (!stricmp(key, "trace_file"))
     g_cfg.trace_file = strdup (val);

  else if (!stricmp(key, "trace_binmode"))
     g_cfg.trace_binmode = atoi (val);

  else if (!stricmp(key, "trace_file_commit"))
     g_cfg.trace_file_commit = atoi (val);

  else if (!stricmp(key, "trace_caller"))
     g_cfg.trace_caller = atoi (val);

  else if (!stricmp(key, "trace_indent"))
  {
    g_cfg.trace_indent = atoi (val);
    g_cfg.trace_indent = max (0, g_cfg.trace_indent);
  }

  else if (!stricmp(key, "trace_report"))
     g_cfg.trace_report = atoi (val);

  else if (!stricmp(key, "trace_max_len") || !stricmp(key, "trace_max_length"))
     g_cfg.trace_max_len = atoi (val);

  else if (!stricmp(key, "trace_time"))
     set_time_format (&g_cfg.trace_time_format, val);

  else if (!stricmp(key, "trace_time_usec"))
     g_cfg.trace_time_usec = atoi (val);

  else if (!stricmp(key, "pcap_enable"))
     g_cfg.PCAP.enable = atoi (val);

  else if (!stricmp(key, "pcap_dump"))
    g_cfg.PCAP.dump_fname = strdup (val);

  else if (!stricmp(key, "show_caller"))
     g_cfg.show_caller = atoi (val);

  else if (!stricmp(key, "demangle") || !stricmp(key, "cpp_demangle"))
     g_cfg.cpp_demangle = atoi (val);

  else if (!stricmp(key, "callee_level"))
     g_cfg.callee_level = atoi (val);   /* Control how many stack-frames to show. Not used yet */

  else if (!stricmp(key, "exclude"))
     exclude_list_add (val, EXCL_FUNCTION);

  else if (!stricmp(key, "hook_extensions"))
     g_cfg.hook_extensions = atoi (val);

  else if (!stricmp(key, "short_errors"))
     g_cfg.short_errors = atoi (val);

  else if (!stricmp(key, "pdb_report"))
     g_cfg.pdb_report = atoi (val);

  else if (!stricmp(key, "use_sema"))
     g_cfg.use_sema = atoi (val);

  else if (!stricmp(key, "recv_delay"))
     g_cfg.recv_delay = (DWORD) _atoi64 (val);

  else if (!stricmp(key, "send_delay"))
     g_cfg.send_delay = (DWORD) _atoi64 (val);

  else if (!stricmp(key, "select_delay"))
     g_cfg.select_delay = (DWORD) _atoi64 (val);

  else if (!stricmp(key, "poll_delay"))
     g_cfg.poll_delay = (DWORD) _atoi64 (val);

  else if (!stricmp(key, "use_toolhlp32"))
     g_cfg.use_toolhlp32 = atoi (val);

  else if (!stricmp(key, "use_ole32"))
     g_cfg.use_ole32 = atoi (val);

  else if (!stricmp(key, "use_full_path"))
     g_cfg.use_full_path = atoi (val);

  else if (!stricmp(key, "use_short_path"))
     g_cfg.use_short_path = atoi (val);

  else if (!stricmp(key, "color_file"))
     get_color (val, &g_cfg.color_file);

  else if (!stricmp(key, "color_time"))
     get_color (val, &g_cfg.color_time);

  else if (!stricmp(key, "color_func"))
     get_color (val, &g_cfg.color_func);

  else if (!stricmp(key, "color_trace"))
     get_color (val, &g_cfg.color_trace);

  else if (!stricmp(key, "color_data"))
     get_color (val, &g_cfg.color_data);

  else if (!stricmp(key, "nice_numbers"))
     g_cfg.nice_numbers = atoi (val);

  else if (!stricmp(key, "compact"))
     g_cfg.compact = atoi (val);

  else if (!stricmp(key, "dump_select"))
     g_cfg.dump_select = atoi (val);

  else if (!stricmp(key, "dump_nameinfo"))
     g_cfg.dump_nameinfo = atoi (val);

  else if (!stricmp(key, "dump_protoent"))
     g_cfg.dump_protoent = atoi (val);

  else if (!stricmp(key, "dump_modules"))
     g_cfg.dump_modules = atoi (val);

  else if (!stricmp(key, "dump_hostent"))
     g_cfg.dump_hostent = atoi (val);

  else if (!stricmp(key, "dump_servent"))
     g_cfg.dump_servent = atoi (val);

  else if (!stricmp(key, "dump_data"))
     g_cfg.dump_data = atoi (val);

  else if (!stricmp(key, "dump_wsaprotocol_info"))
     g_cfg.dump_wsaprotocol_info = atoi (val);

  else if (!stricmp(key, "dump_wsanetwork_events"))
     g_cfg.dump_wsanetwork_events = atoi (val);

  else if (!stricmp(key, "dump_tcpinfo"))
     g_cfg.dump_tcpinfo = atoi (val);

  else if (!stricmp(key, "max_data"))
     g_cfg.max_data = atoi (val);

  else if (!stricmp(key, "max_fd_set") || !stricmp(key, "max_fd_sets"))
     g_cfg.max_fd_sets = atoi (val);

  else if (!stricmp(key, "max_displacement"))
     g_cfg.max_displacement = atoi (val);

  else if (!stricmp(key, "start_new_line"))
     g_cfg.start_new_line = atoi (val);

  else if (!stricmp(key, "extra_new_line"))
     g_cfg.extra_new_line = atoi (val);

  else if (!stricmp(key, "msvc_only"))
     g_cfg.msvc_only = atoi (val);

  else if (!stricmp(key, "mingw_only"))
     g_cfg.mingw_only = atoi (val);

  else if (!stricmp(key, "cygwin_only"))
     g_cfg.cygwin_only = atoi (val);

  else if (!stricmp(key, "no_buffering"))
     g_cfg.no_buffering = atoi (val);

  else if (!stricmp(key, "use_winhttp"))
     g_cfg.use_winhttp = atoi (val);

  else if (!stricmp(key, "hosts_file"))
  {
    if (g_cfg.num_hosts_files < DIM(g_cfg.hosts_file)-1)
       g_cfg.hosts_file [g_cfg.num_hosts_files++] = strdup (val);
  }
  else if (!stricmp(key, "services_file"))
  {
    if (g_cfg.num_services_files < DIM(g_cfg.services_file)-1)
       g_cfg.services_file [g_cfg.num_services_files++] = strdup (val);
  }

  else TRACE (1, "%s (%u):\n   Unknown keyword '%s' = '%s'\n",
              fname, line, key, val);
}

/*
 * Handler for '[lua]' section.
 */
static void parse_lua_settings (const char *key, const char *val, unsigned line)
{
  if (!stricmp(key, "enable"))
       g_cfg.LUA.enable = atoi (val);

  else if (!stricmp(key, "trace_level"))
       g_cfg.LUA.trace_level = atoi (val);

  else if (!stricmp(key, "profile"))
       g_cfg.LUA.profile = atoi (val);

  else if (!stricmp(key, "color_head"))
       get_color (val, &g_cfg.LUA.color_head);

  else if (!stricmp(key, "color_body"))
       get_color (val, &g_cfg.LUA.color_body);

  else if (!stricmp(key, "lua_init"))
       g_cfg.LUA.init_script = strdup (val);

  else if (!stricmp(key, "lua_exit"))
       g_cfg.LUA.exit_script = strdup (val);

  else TRACE (1, "%s (%u):\n   Unknown keyword '%s' = '%s'\n",
              fname, line, key, val);
}

/*
 * Handler for '[geoip]' section.
 */
static void parse_geoip_settings (const char *key, const char *val, unsigned line)
{
  if (!stricmp(key, "enable"))
       g_cfg.GEOIP.enable = (*val > '0') ? TRUE : FALSE;

  else if (!stricmp(key, "show_position"))
       g_cfg.GEOIP.show_position = atoi (val);

  else if (!stricmp(key, "show_map_url"))
       g_cfg.GEOIP.show_map_url = atoi (val);

  else if (!stricmp(key, "ip4_file"))
       g_cfg.GEOIP.ip4_file = strdup (val);

  else if (!stricmp(key, "ip6_file"))
       g_cfg.GEOIP.ip6_file = strdup (val);

  else if (!stricmp(key, "ip4_url"))
       g_cfg.GEOIP.ip4_url = strdup (val);

  else if (!stricmp(key, "ip6_url"))
       g_cfg.GEOIP.ip6_url = strdup (val);

  else if (!stricmp(key, "proxy"))
       g_cfg.GEOIP.proxy = strdup (val);

  else if (!stricmp(key, "max_days"))
       g_cfg.GEOIP.max_days = atoi (val);

  else if (!stricmp(key, "ip2location_bin_file"))
  {
    if (g_cfg.GEOIP.ip2location_bin_file)
    {
      WARNING ("'ip2location_bin_file' already set. Replacing with '%s'\n", val);
      free (g_cfg.GEOIP.ip2location_bin_file);
    }
    g_cfg.GEOIP.ip2location_bin_file = strdup (val);
  }

  else TRACE (1, "%s (%u):\n   Unknown keyword '%s' = '%s'\n",
              fname, line, key, val);
}

/*
 * Handler for '[idna]' section.
 */
static void parse_idna_settings (const char *key, const char *val, unsigned line)
{
  if (!stricmp(key, "enable"))
       g_cfg.IDNA.enable = atoi (val);

  else if (!stricmp(key, "use_winidn"))
       g_cfg.IDNA.use_winidn = atoi (val);

  else if (!stricmp(key, "fix_getaddrinfo"))
       g_cfg.IDNA.fix_getaddrinfo = atoi (val);

  else if (!stricmp(key, "codepage"))
       g_cfg.IDNA.codepage = atoi (val);

  else TRACE (1, "%s (%u):\n   Unknown keyword '%s' = '%s'\n",
              fname, line, key, val);
}

/*
 * Handler for '[DNSBL]' section.
 */
static void parse_DNSBL_settings (const char *key, const char *val, unsigned line)
{
  if (!stricmp(key, "enable"))
       g_cfg.DNSBL.enable = atoi (val);

  else if (!stricmp(key, "drop_file"))
       g_cfg.DNSBL.drop_file = strdup (val);

  else if (!stricmp(key, "dropv6_file"))
       g_cfg.DNSBL.dropv6_file = strdup (val);

  else if (!stricmp(key, "edrop_file"))
       g_cfg.DNSBL.edrop_file = strdup (val);

  else if (!stricmp(key, "drop_url"))
       g_cfg.DNSBL.drop_url = strdup (val);

  else if (!stricmp(key, "dropv6_url"))
       g_cfg.DNSBL.dropv6_url = strdup (val);

  else if (!stricmp(key, "edrop_url"))
       g_cfg.DNSBL.edrop_url = strdup (val);

  else if (!stricmp(key, "max_days"))
       g_cfg.DNSBL.max_days = atoi (val);

  else TRACE (1, "%s (%u):\n   Unknown keyword '%s' = '%s'\n",
              fname, line, key, val);
}

/*
 * parse a "Hertz, mill-sec" value for the '[firewall]' section.
 */
static void get_freq_msec (const char *val, struct FREQ_MILLISEC *out)
{
  struct FREQ_MILLISEC fr = { 0, 0 };
  int num = sscanf (val, "%u,%u", &fr.frequency, &fr.milli_sec);

  if (num == 2)
  {
    out->frequency = fr.frequency;
    out->milli_sec = fr.milli_sec;
  }
  else if (num == 1)
    out->frequency = fr.frequency;

  out->frequency = min (out->frequency, 10000);
  out->milli_sec = min (out->milli_sec, 1000);
  TRACE (4, "freq: %u Hz, %u msec.\n", out->frequency, out->milli_sec);
}

/*
 * Handler for '[firewall]' section.
 */
static void parse_firewall_settings (const char *key, const char *val, unsigned line)
{
  if (!stricmp(key, "enable"))
       g_cfg.FIREWALL.enable = atoi (val);

  else if (!stricmp(key, "show_ipv4"))
       g_cfg.FIREWALL.show_ipv4 = atoi (val);

  else if (!stricmp(key, "show_ipv6"))
       g_cfg.FIREWALL.show_ipv6 = atoi (val);

  else if (!stricmp(key, "show_all"))
       g_cfg.FIREWALL.show_all = atoi (val);

  else if (!stricmp(key, "api_level"))
       g_cfg.FIREWALL.api_level = atoi (val);

  else if (!stricmp(key, "console_title"))
       g_cfg.FIREWALL.console_title = atoi (val);

  else if (!stricmp(key, "exclude"))
       exclude_list_add (val, EXCL_PROGRAM | EXCL_ADDRESS);

  else if (!stricmp(key, "sound.enable"))
      g_cfg.FIREWALL.sound.enable = atoi (val);

  else if (!stricmp(key, "sound.beep.event_drop"))
      get_freq_msec (val, &g_cfg.FIREWALL.sound.beep.event_drop);

  else if (!stricmp(key, "sound.beep.event_allow"))
      get_freq_msec (val, &g_cfg.FIREWALL.sound.beep.event_allow);

  else if (!stricmp(key, "sound.beep.event_DNSBL"))
      get_freq_msec (val, &g_cfg.FIREWALL.sound.beep.event_DNSBL);

  else TRACE (1, "%s (%u):\n   Unknown keyword '%s' = '%s'\n",
              fname, line, key, val);
}

/*
 * Handler for '[IANA]' section.
 */
static void parse_iana_settings (const char *key, const char *val, unsigned line)
{
  if (!stricmp(key, "enable"))
       g_cfg.IANA.enable = atoi (val);

  else if (!stricmp(key, "ip4_file"))
       g_cfg.IANA.ip4_file = strdup (val);

  else if (!stricmp(key, "ip6_file"))
       g_cfg.IANA.ip6_file = strdup (val);

  else TRACE (1, "%s (%u):\n   Unknown keyword '%s' = '%s'\n",
              fname, line, key, val);
}

/*
 * Handler for '[ASN]' section.
 */
static void parse_asn_settings (const char *key, const char *val, unsigned line)
{
  if (!stricmp(key, "enable"))
       g_cfg.ASN.enable = atoi (val);

  else if (!stricmp(key, "asn_csv_file"))
       g_cfg.ASN.asn_csv_file = strdup (val);

  else if (!stricmp(key, "asn_bin_file"))
       g_cfg.ASN.asn_bin_file = strdup (val);

  else if (!stricmp(key, "asn_bin_url"))
       g_cfg.ASN.asn_bin_url = strdup (val);

  else if (!stricmp(key, "max_days"))
       g_cfg.ASN.max_days = atoi (val);

  else if (!stricmp(key, "xz_decompress"))
       g_cfg.ASN.xz_decompress = atoi (val);

  else TRACE (1, "%s (%u):\n   Unknown keyword '%s' = '%s'\n",
              fname, line, key, val);
}

enum cfg_sections {
     CFG_NONE = 0,
     CFG_CORE,
     CFG_LUA,
     CFG_GEOIP,
     CFG_ASN,
     CFG_IANA,
     CFG_IDNA,
     CFG_DNSBL,
     CFG_FIREWALL
   };

/*
 * Give a section-name, lookup the 'enum cfg_section' for the name.
 */
static enum cfg_sections lookup_section (const char *section)
{
  if (!section || !stricmp(section, "core"))
     return (CFG_CORE);
  if (section && !stricmp(section, "lua"))
     return (CFG_LUA);
  if (section && !stricmp(section, "geoip"))
     return (CFG_GEOIP);
  if (section && !stricmp(section, "asn"))
     return (CFG_ASN);
  if (section && !stricmp(section, "iana"))
     return (CFG_IANA);
  if (section && !stricmp(section, "idna"))
     return (CFG_IDNA);
  if (section && !stricmp(section, "dnsbl"))
     return (CFG_DNSBL);
  if (section && !stricmp(section, "firewall"))
     return (CFG_FIREWALL);
  return (CFG_NONE);
}

/*
 * Parse the config-file given in 'file'.
 */
static int parse_config_file (FILE *file)
{
  const char *key, *val, *section;
  char        last_section[40];
  unsigned    line  = 0;
  unsigned    lines = 0;
  BOOL        done = FALSE;

  str_replace ('\\', '/', fname);

  /* If for some reason the config-file is missing a "[section]", the
   * default section is "core". This can happen with an old 'wsock_trace'
   * file.
   */
  section = "core";

  while (config_get_line(file, &line, &key, &val, &section))
  {
    TRACE (4, "line %u: '%s' = '%s' (section: '%s')\n", line, key, val, section);
    lines++;

    if (!*val)      /* foo = <empty value> */
       continue;

    switch (lookup_section(section))
    {
      case CFG_CORE:
           parse_core_settings (key, val, line);
           strcpy (last_section, "core");
           if (!done)
           {
            /**
             * \todo
             * Let the below be printed at column 0.
             * I.e. add a newline. But we do not yet have the `console_info`.
             */
#if 0
             if (console_hnd != INVALID_HANDLE_VALUE && console_info.dwCursorPosition.X > 0
                C_putc ('\n');
#endif
             TRACE (1, "Parsing config-file \"%s\"\n"
                       "              for \"%s, %s\".\n",
                    fname, get_builder(TRUE), get_dll_build_date());
           }
           done = TRUE;
           break;
      case CFG_LUA:
           parse_lua_settings (key, val, line);
           strcpy (last_section, "lua");
           break;
      case CFG_GEOIP:
           parse_geoip_settings (key, val, line);
           strcpy (last_section, "geoip");
           break;
      case CFG_IDNA:
           parse_idna_settings (key, val, line);
           strcpy (last_section, "idna");
           break;
      case CFG_DNSBL:
           parse_DNSBL_settings (key, val, line);
           strcpy (last_section, "dnsbl");
           break;
      case CFG_FIREWALL:
           parse_firewall_settings (key, val, line);
           strcpy (last_section, "firewall");
           break;
      case CFG_ASN:
           parse_asn_settings (key, val, line);
           strcpy (last_section, "asn");
           break;
      case CFG_IANA:
           parse_iana_settings (key, val, line);
           strcpy (last_section, "iana");
           break;

      /* \todo: handle more 'key' / 'val' here by extending lookup_section().
       */
      case CFG_NONE:
      default:
           if (section[0] && stricmp(section,last_section))
           {
             TRACE (0, "%s (%u):\nKeyword '%s' = '%s' in unknown section '%s'.\n",
                    fname, line, key, val, section);
             _strlcpy (last_section, section, sizeof(last_section));
           }
           break;
    }
  }
  return (lines);
}

static void trace_report (void)
{
  const struct exclude *ex;
  const char  *indent;
  int          i, max;
  size_t       len, max_len = 0, max_digits = 0;

  g_cfg.trace_report = FALSE;

  C_puts ("\n  Exclusions:~5");

  max = exclude_list ? smartlist_len (exclude_list) : 0;
  for (i = 0; i < max; i++)
  {
    ex = smartlist_get (exclude_list, i);
    len = strlen (ex->name);
    if (max_len < len)
       max_len = len;
    len = strlen (qword_str(ex->num_excludes));
    if (max_digits < len)
       max_digits = len;
  }
  if (i == 0)
     C_puts (" None.\n");
  else
  {
    for (i = 0; i < max; i++)
    {
      indent = (i == 0) ? " " : "              ";
      ex = smartlist_get (exclude_list, i);
      len = strlen (ex->name);

      if (ex->which == EXCL_FUNCTION)
           C_printf ("%s%s():%*s ", indent, ex->name, (int)(max_len-len), "");
      else C_printf ("%s%s:%*s   ", indent, ex->name, (int)(max_len-len), "");
      C_printf ("%*s times.\n", (int)max_digits, qword_str(ex->num_excludes));
    }
  }

  if (g_cfg.reentries > 0)
     C_printf ("  get_caller() reentered %lu times.\n", DWORD_CAST(g_cfg.reentries));

//if (g_cfg.counts.dll_attach > 0 || g_cfg.counts.dll_detach > 0)
  {
    C_printf ("  DLL attach %" U64_FMT " times.\n", g_cfg.counts.dll_attach);
    C_printf ("  DLL detach %" U64_FMT " times.\n", g_cfg.counts.dll_detach);
  }
  C_puts ("~0");

#if 0
  {
    max = thread_list ? smartlist_len(thread_list) : 0;
    for (i = 0; i < max; i++)
    {
      const struct thread_info *thr = smartlist_get (thread_list, i);
      HANDLE hnd = OpenThread (THREAD_QUERY_INFORMATION, FALSE, thr->id);

      C_printf (" tid: %lu, alive: %d:\n", thr->id, thr->alive);
      print_thread_times (hnd);
    }
  }
#endif

 /* E.g.:
  *  Statistics:
  *    Recv bytes:   1,000,000,000  Recv errors:           0
  *    Recv bytes:   9,999,999,900 (MSG_PEEK)
  *    Send bytes:      20,000,000  Send errors:      20,000
  */

#if 0  /* test */
  g_cfg.counts.recv_bytes  = 1000000000;
  g_cfg.counts.recv_peeked = 9999999900;
  g_cfg.counts.send_bytes  = 20000000;
  g_cfg.counts.send_errors = 20000;
#endif

  C_printf ("\n"
            "  Statistics:\n"
            "    Recv bytes:   %15s",               qword_str(g_cfg.counts.recv_bytes));
  C_printf ("  Recv errors:  %15s\n",               qword_str(g_cfg.counts.recv_errors));
  C_printf ("    Recv bytes:   %15s  (MSG_PEEK)\n", qword_str(g_cfg.counts.recv_peeked));
  C_printf ("    Send bytes:   %15s",               qword_str(g_cfg.counts.send_bytes));
  C_printf ("  Send errors:  %15s\n",               qword_str(g_cfg.counts.send_errors));

  if (g_cfg.use_sema)
     C_printf ("    Semaphore wait: %13s\n",        qword_str(g_cfg.counts.sema_waits));

  if (g_cfg.GEOIP.enable)
  {
    DWORD num_ip4, num_ip6, num_ip2loc4, num_ip2loc6;

    geoip_num_unique_countries (&num_ip4, &num_ip6, &num_ip2loc4, &num_ip2loc6);
    C_printf ("  # of unique countries (IPv4): %3lu, by ip2loc: %3lu.\n",
              DWORD_CAST(num_ip4), DWORD_CAST(num_ip2loc4));

    C_printf ("  # of unique countries (IPv6): %3lu, by ip2loc: %3lu.\n",
              DWORD_CAST(num_ip6), DWORD_CAST(num_ip2loc6));
  }

  if (g_cfg.IANA.enable)
     iana_report();

  if (g_cfg.ASN.enable)
     ASN_report();

  if (g_cfg.FIREWALL.enable)
     fw_report();
}

/*
 * Called from DllMain(): dwReason == DLL_PROCESS_DETACH
 */
void wsock_trace_exit (void)
{
  int  i;
  BOOL rc;

  set_color (NULL);

  if (fatal_error)
     g_cfg.trace_report = FALSE;

#if 0
  if (!cleaned_up || startup_count > 0)
     g_cfg.trace_report = FALSE;
#endif

  if (g_cfg.trace_report)
     trace_report();

  exclude_list_free();
  StackWalkExit();
  overlap_exit();
  hosts_file_exit();
  services_file_exit();

#if 0
  if (g_cfg.trace_level >= 3)
  {
    print_perf_times();
    print_process_times();
  }
#endif

  if (g_cfg.FIREWALL.enable)
  {
    TRACE (2, "Calling fw_monitor_stop(), startup_count: %d, cleaned_up:%d.\n",
           startup_count, cleaned_up);

    fw_monitor_stop (TRUE);
    fw_exit();
  }

  rc = TlsFree (ws_Tls_index);
  TRACE (2, "TlsFree (%lu) -> %d.\n", ws_Tls_index, rc);

  common_exit();

  if (g_cfg.trace_stream && !g_cfg.trace_file_device)
     fclose (g_cfg.trace_stream);

  if (g_cfg.PCAP.dump_stream)
     fclose (g_cfg.PCAP.dump_stream);

  for (i = 0; i < DIM(g_cfg.hosts_file); i++)
      FREE (g_cfg.hosts_file[i]);

  for (i = 0; i < DIM(g_cfg.services_file); i++)
      FREE (g_cfg.services_file[i]);

  g_cfg.trace_file_okay = FALSE;
  g_cfg.trace_stream = g_cfg.PCAP.dump_stream = NULL;

  FREE (g_cfg.trace_file);
  FREE (g_cfg.PCAP.dump_fname);
  FREE (g_cfg.LUA.init_script);
  FREE (g_cfg.LUA.exit_script);
  FREE (g_cfg.GEOIP.ip4_file);
  FREE (g_cfg.GEOIP.ip6_file);
  FREE (g_cfg.GEOIP.ip4_url);
  FREE (g_cfg.GEOIP.ip6_url);
  FREE (g_cfg.GEOIP.proxy);
  FREE (g_cfg.GEOIP.ip2location_bin_file);
  FREE (g_cfg.DNSBL.drop_file);
  FREE (g_cfg.DNSBL.dropv6_file);
  FREE (g_cfg.DNSBL.edrop_file);
  FREE (g_cfg.DNSBL.drop_url);
  FREE (g_cfg.DNSBL.dropv6_url);
  FREE (g_cfg.DNSBL.edrop_url);

  DNSBL_exit();
  geoip_exit();
  iana_exit();
  ASN_exit();
  IDNA_exit();

  reset_invalid_handler();
  if (ws_sema && ws_sema != INVALID_HANDLE_VALUE)
     CloseHandle (ws_sema);
  ws_sema = NULL;
  DeleteCriticalSection (&crit_sect);
}

/**
 * Called from DllMain(): dwReason == DLL_PROCESS_ATTACH.
 *
 * \note There are significant limits on what you can safely do in a
 *       DLL entry point. More at: \n
 *       https://docs.microsoft.com/en-gb/windows/desktop/Dlls/dllmain
 *
 *       But the below code (except calling any "WinInet.dll" functions from
 *       inet_util.c) seems safe to call.
 */
void wsock_trace_init (void)
{
  FILE       *file;
  char       *end, *env = getenv ("WSOCK_TRACE_LEVEL");
  const char *now;
  BOOL        okay;
  HMODULE     mod;
  BOOL        is_msvc, is_mingw, is_cygwin;

  /**
   * \todo
   * Use `InitializeCriticalSectionEx (&crit_sect, CRITICAL_SECTION_NO_DEBUG_INFO)` instead?
   * Ref:
   *   https://www.codeproject.com/Articles/5278932/Synchronization-with-Visual-Cplusplus-and-the-Wind
   * and the comments there.
   */
  InitializeCriticalSection (&crit_sect);

  /* Set default values.
   */
  memset (&g_cfg, 0, sizeof(g_cfg));

  /* Set trace-level before config-file could reset it.
   */
  if (env && isdigit((int)*env))
  {
    g_cfg.trace_level = (*env - '0');
    g_cfg.show_caller = 1;
  }
  else
    g_cfg.trace_level = 1;

  g_cfg.trace_max_len = 9999;      /* Infinite */
  g_cfg.trace_stream  = stdout;
  g_cfg.trace_file_device = TRUE;

  tzset();
//setlocale (LC_ALL, "");
  common_init();

  mod = GetModuleHandle (NULL);
  GetCurrentDirectory (sizeof(curr_dir), curr_dir);
  GetModuleFileName (NULL, prog_dir, sizeof(prog_dir));
  end = strrchr (prog_dir, '\0');
  if (!strnicmp(end-4, ".exe", 4))
  {
    end = strrchr (prog_dir, '\\');
    _strlcpy (curr_prog, end+1, sizeof(curr_prog));
    end[1] = '\0';  /* Ensure 'prog_dir' has a trailing '\\' */
  }
  else
    _strlcpy (curr_prog, "??", sizeof(curr_prog));

  file = open_config_file ("wsock_trace");
  if (file)
  {
    parse_config_file (file);
    fclose (file);
  }

  is_msvc   = image_opt_header_is_msvc (mod);
  is_mingw  = image_opt_header_is_mingw (mod);
  is_cygwin = image_opt_header_is_cygwin (mod);

  if (g_cfg.use_sema)
  {
    /* Check if we've already got an instance of ourself.
     * If we are the top-level wsock_trace, we want the handle to be inherited
     * by child processes.
     */
    SECURITY_ATTRIBUTES sec;

    sec.nLength = sizeof (sec);
    sec.lpSecurityDescriptor = NULL;
    sec.bInheritHandle       = TRUE;
    ws_sema = CreateSemaphore (&sec, 1, 1, ws_sema_name);
    if (GetLastError() == ERROR_ALREADY_EXISTS)
         ws_sema_inherited = TRUE;
    else ws_sema_inherited = FALSE;
  }

  set_invalid_handler();

  if ((g_cfg.msvc_only   && !is_msvc)  ||
      (g_cfg.mingw_only  && !is_mingw) ||
      (g_cfg.cygwin_only && !is_cygwin) )
  {
 // g_cfg.stealth_mode = 1;
    g_cfg.trace_level = g_cfg.trace_report = g_cfg.dump_tcpinfo = 0;
    g_cfg.FIREWALL.sound.enable = g_cfg.extra_new_line = 0;
  }

  if (g_cfg.trace_file && !stricmp(g_cfg.trace_file, "stderr"))
  {
    g_cfg.trace_stream      = stderr;
    g_cfg.trace_file_device = TRUE;
  }
  else if (g_cfg.trace_file && !stricmp(g_cfg.trace_file, "$ODS"))
  {
    g_cfg.trace_stream      = NULL;
    g_cfg.trace_file_device = TRUE;
    g_cfg.trace_use_ods     = TRUE;
    g_cfg.trace_binmode     = 1;
  }
  else if (g_cfg.trace_file && g_cfg.trace_level > 0)
  {
    const char *mode = "at+";

#ifdef _MSC_VER
    if (g_cfg.trace_file_commit)
       mode = "atc+";
#endif

    g_cfg.trace_stream      = fopen_excl (g_cfg.trace_file, mode);
    g_cfg.trace_file_okay   = (g_cfg.trace_stream != NULL);
    g_cfg.trace_file_device = FALSE;

    if (!g_cfg.trace_stream || !file_exists(g_cfg.trace_file))
    {
      WARNING ("Failed to open or create trace_file '%s': %s\n"
               "Printing to stdout.\n", g_cfg.trace_file, strerror(errno));
      g_cfg.trace_stream = stdout;
      g_cfg.trace_file = NULL;
      g_cfg.trace_file_commit = FALSE;
    }
  }

  if (g_cfg.trace_stream)
  {
#if defined(__CYGWIN__) && (CYGWIN_VERSION_DLL_COMBINED >= 3001000)
    g_cfg.no_buffering = 1;
#endif

    if (g_cfg.no_buffering)
       setvbuf (g_cfg.trace_stream, NULL, _IONBF, 0);

    if (g_cfg.trace_binmode)
       _setmode (_fileno(g_cfg.trace_stream), O_BINARY);
  }

  if (g_cfg.PCAP.enable)
  {
    errno = 0;
    g_cfg.PCAP.dump_stream = fopen_excl (g_cfg.PCAP.dump_fname, "w+b");
    TRACE (1, "g_cfg.PCAP.dump_stream: 0x%p, errno: %d.\n", g_cfg.PCAP.dump_stream, errno);
    write_pcap_header();
  }

  if (g_cfg.IDNA.enable && !IDNA_init(g_cfg.IDNA.codepage, g_cfg.IDNA.use_winidn))
  {
    g_cfg.IDNA.enable = FALSE;
    IDNA_exit();
  }

  if (image_opt_header_is_gui_app(mod))
  {
    TRACE (2, "Disabling sound in a GUI-program.\n");
    g_cfg.FIREWALL.sound.enable = 0;
  }

  now = get_time_now();

  if (g_cfg.trace_level > 0 &&
      (g_cfg.trace_use_ods || (!g_cfg.trace_file_device && g_cfg.trace_file_okay)))
    C_printf ("\n------- Trace started at %s --------"
              "------ %s, %s. Build-date: %s.\n",
             now, get_builder(TRUE), get_dll_short_name(), get_dll_build_date());

  memset (&console_info, 0, sizeof(console_info));

  if (g_cfg.trace_stream == stderr)
       console_hnd = GetStdHandle (STD_ERROR_HANDLE);
  else console_hnd = GetStdHandle (STD_OUTPUT_HANDLE);

  okay = (console_hnd != INVALID_HANDLE_VALUE &&
          GetConsoleScreenBufferInfo(console_hnd, &console_info));

  if (!okay || GetFileType(console_hnd) != FILE_TYPE_CHAR)
  {
    g_cfg.stdout_redirected = TRUE;
  }
  else
  {
    DWORD mode;

    GetConsoleMode (console_hnd, &mode);
    TRACE (3, "GetConsoleMode(): 0x%08lX\n", DWORD_CAST(mode));
  }

  /* These env-var override the actual screen-height and width.
   * Even if console is redirected.
   */
  env = getenv ("LINES");
  if (env && atoi(env) > 0)
     g_cfg.screen_heigth = atoi (env);

  env = getenv ("COLUMNS");
  if (env && atoi(env) > 0)
     g_cfg.screen_width = atoi (env);

  /* If console not redirected and not set above.
   */
  if (g_cfg.screen_width == 0)
  {
    if (!g_cfg.stdout_redirected)
         g_cfg.screen_width = console_info.srWindow.Right - console_info.srWindow.Left + 1;
    else g_cfg.screen_width = g_cfg.trace_max_len;
  }
  if (g_cfg.screen_heigth == 0 && !g_cfg.stdout_redirected)
      g_cfg.screen_heigth = console_info.srWindow.Bottom - console_info.srWindow.Top + 1;

  TRACE (2, "g_cfg.screen_width: %d, g_cfg.screen_heigth: %d, g_cfg.stdout_redirected: %d\n",
         g_cfg.screen_width, g_cfg.screen_heigth, g_cfg.stdout_redirected);

  TRACE (2, "g_cfg.trace_file_okay: %d, g_cfg.trace_file_device: %d\n",
         g_cfg.trace_file_okay, g_cfg.trace_file_device);

  if (g_cfg.use_sema)
     TRACE (2, "ws_sema: 0x%" ADDR_FMT ", ws_sema_inherited: %d\n",
            ADDR_CAST(ws_sema), ws_sema_inherited);

  ws_Tls_index = TlsAlloc();
  if (ws_Tls_index == TLS_OUT_OF_INDEXES)
       TRACE (1, "TlsAlloc() -> TLS_OUT_OF_INDEXES! GetLastError(): %lu.\n", GetLastError());
  else TRACE (2, "TlsAlloc() -> %lu.\n", ws_Tls_index);

  if (!g_cfg.stdout_redirected)
  {
    if (!g_cfg.color_file)
       g_cfg.color_file = console_info.wAttributes;

    if (!g_cfg.color_func)
       g_cfg.color_func = console_info.wAttributes;

    if (!g_cfg.color_trace)
       g_cfg.color_trace = console_info.wAttributes;

    if (!g_cfg.color_time)
       g_cfg.color_time = console_info.wAttributes;

    if (!g_cfg.color_data)
       g_cfg.color_data = console_info.wAttributes;
  }

  if (g_cfg.trace_time_format != TS_NONE)
     init_timestamp();

  if (g_cfg.trace_level <= 0)
  {
    g_cfg.dump_data              = FALSE;
    g_cfg.dump_hostent           = FALSE;
    g_cfg.dump_servent           = FALSE;
    g_cfg.dump_protoent          = FALSE;
    g_cfg.dump_nameinfo          = FALSE;
    g_cfg.dump_wsaprotocol_info  = FALSE;
    g_cfg.dump_wsanetwork_events = FALSE;
    g_cfg.dump_data              = 0;
    g_cfg.dump_select            = 0;
    g_cfg.dump_tcpinfo           = 0;
    g_cfg.extra_new_line         = 0;
    g_cfg.FIREWALL.enable        = FALSE;
    g_cfg.FIREWALL.sound.enable  = FALSE;
  }

  TRACE (3, "curr_prog:           '%s'\n"
            "                curr_dir:            '%s'\n"
            "                prog_dir:            '%s'\n"
            "                get_dll_short_name(): %s\n"
            "                get_dll_build_date(): %s\n",
         curr_prog, curr_dir, prog_dir, get_dll_short_name(), get_dll_build_date());

  geoip_init (NULL, NULL);

  DNSBL_init();

  if (g_cfg.trace_level >= 3)
     check_all_search_lists();

  load_ws2_funcs();
  hosts_file_init();
  services_file_init();

#if defined(USE_BFD)
  BFD_init();
#endif

  StackWalkInit();
  overlap_init();
  iana_init();
  ASN_init();

#if defined(USE_LWIP)
  ws_lwip_init();
#endif
}

/**
 * Check if a Winsock function pointer was set.
 * If it was not set and is not an optional function,
 * cause a `FATAL()` exit.
 *
 * Used as e.g. `CHECK_PTR (p_WSAStartup)` which expands to
 * ```
 *   check_ptr ((const void**)&p_WSAStartup, "p_WSAStartup")
 * ```
 *
 * Hence `func_name` should be equal to `ptr_name + 2`.
 */
void check_ptr (const void **ptr, const char *ptr_name)
{
  const char *func_name = ptr_name + 2;

  if (*ptr == NULL)
  {
    const struct LoadTable *f = find_ws2_func_by_name (func_name);

    if (f && f->optional)
    {
      TRACE (1, "Optional function '%s()' not found. Continuing anyway.\n", func_name);
      return;
    }
    FATAL ("Function '%s()' not initialised.\n", func_name);
  }

  if (cleaned_up && strcmp(func_name, "WSAGetLastError"))
     TRACE (1, "Function '%s()' called after 'WSACleanup()' was done.\n", func_name);
}

static const struct search_list colors[] = {
                              { 0, "black"   },
                              { 1, "blue"    },
                              { 2, "green"   },
                              { 3, "cyan"    },
                              { 4, "red"     },
                              { 5, "magenta" },
                              { 6, "yellow"  },
                              { 7, "white"   }
                            };
/*
 * Parse a color specifier like:
 *   [bright | bold] fg [on bg]
 *
 * Returns foreground in lower 8 bits of '*col'.
 *     and background in upper 8 bits of '*col'.
 * Sets upper 8 bits in '*col' to -1 if "on bg" is missing.
 * I.e. using default background in set_color().
 */
void get_color (const char *val, WORD *col)
{
  BYTE        fg = 0;
  BYTE        bg = (BYTE)-1;
  unsigned    x;
  const char *orig = val;
  char        fg_str [20] = "";
  char        bg_str [20] = "";
  int         num1, num2;

  if (!val)
  {
    *col = 0xFF00 | (console_info.wAttributes & 7);
    return;
  }

  if (!strnicmp(val, "bright ", 7))
  {
    fg |= FOREGROUND_INTENSITY;
    val += 7;
  }
  else if (!strnicmp(val, "bold ", 5))
  {
    fg |= FOREGROUND_INTENSITY;
    val += 5;
  }

  num1 = sscanf (val, "%20s", fg_str);
  num2 = sscanf (val, "%20[^ ] on %20s", fg_str, bg_str);

  if (num1 != 1 && num2 != 2)
  {
    TRACE (0, "Unknown color '%s'\n", orig);
    return;
  }

  TRACE (5, "num1: %d, num2: %d, fg_str: '%s', bg_str: '%s'\n",
         num1, num2, fg_str, bg_str);

  x = list_lookup_value (fg_str, colors, DIM(colors));
  if (x == UINT_MAX)
  {
    TRACE (0, "Unknown color '%s'\n", orig);
    return;
  }

  fg |= x;

  if (bg_str[0])
  {
    x = list_lookup_value (bg_str, colors, DIM(colors));
    if (x == UINT_MAX)
    {
      TRACE (0, "Unknown color '%s'\n", orig);
      return;
    }

   /* Since BG with high intensity (BACKGROUND_INTENSITY) isn't supported.
    */
    bg = x;
  }

  *col = fg + (bg << 8);

  if (!g_cfg.trace_use_ods && g_cfg.trace_file_device)
     TRACE (5, "orig '%s' -> fg: %d, bg: %d, *col: 0x%04X\n", orig, (int)fg, (int)bg, *col);
}

/*
 * Set console foreground and optionally background color.
 * FG is in the low 4 bits.
 * BG is in the upper 4 bits of the BYTE.
 * If 'col == NULL', set default console colour.
 *
 * Returns the value of active colour prior to setting a new colour
 */
WORD set_color (const WORD *col)
{
  BYTE   fg, bg;
  WORD   attr, rc;
  static WORD last_attr = (WORD)-1;

  if (!col)
  {
    attr = console_info.wAttributes;
    fg   = loBYTE (attr);
    bg   = hiBYTE (attr);
  }
  else
  {
    attr = *col;
    fg   = loBYTE (attr);
    bg   = hiBYTE (attr);

    if (bg == (BYTE)-1)
    {
      attr = console_info.wAttributes & ~7;
      attr &= ~8;  /* Since 'wAttributes' could have been hi-intensity at startup. */
    }
    else
      attr = bg << 4;

    attr |= fg;
  }

  if (attr != last_attr)
  {
    FlushFileBuffers (console_hnd);
    SetConsoleTextAttribute (console_hnd, attr);
  }

  if (last_attr == (WORD)-1)
       rc = console_info.wAttributes;
  else rc = last_attr;
  last_attr = attr;
  return (rc);
}

int get_column (void)
{
  CONSOLE_SCREEN_BUFFER_INFO ci;

  if (console_hnd == INVALID_HANDLE_VALUE)
     return (-1);

  memset (&ci, 0, sizeof(ci));
  if (!GetConsoleScreenBufferInfo (console_hnd, &ci))
     return (-1);

  return (int) (ci.dwCursorPosition.X);
}

/*
 * Functions for writing dump-file in pcap-format.
 */
#define TCPDUMP_MAGIC       0xA1B2C3D4
#define PCAP_VERSION_MAJOR  2
#define PCAP_VERSION_MINOR  4
#define DLT_RAW             12    /* raw IP */
#define DLT_IPV4            228
#define DLT_IPV6            229

#if defined(_MSC_VER) || defined(__CYGWIN__)
  #pragma pack(push,1)
#else
  #pragma pack(1)
#endif

struct pcap_file_header {
       DWORD  magic;
       WORD   version_major;
       WORD   version_minor;
       DWORD  thiszone;        /* GMT to local correction */
       DWORD  sigfigs;         /* accuracy of timestamps */
       DWORD  snap_len;        /* max length saved portion of each pkt */
       DWORD  linktype;        /* data link type (DLT_*) */
     };

/* The 'struct timeval' layout in a 32-bit NPF.SYS driver
 * uses 'long'. In CygWin64, a 'struct timeval' has 'long' which
 * are 64-bits. Hence our 'struct timeval' must be unique.
 * So use this:
 */
struct pcap_timeval {
       DWORD  tv_sec;
       DWORD  tv_usec;
     };

/*
 * Each packet in the dump file is prepended with this generic header.
 * This gets around the problem of different headers for different
 * packet interfaces.
 */
struct pcap_pkt_header {
       struct pcap_timeval ts;      /* time stamp */
       DWORD               caplen;  /* length of portion present */
       DWORD               len;     /* length of this packet (off wire) */
     };

struct ip_header {
       BYTE    ip_hlen : 4;    /* header length */
       BYTE    ip_ver  : 4;    /* version */
       BYTE    ip_tos;         /* type of service */
       WORD    ip_len;         /* total length */
       WORD    ip_id;          /* identification */
       WORD    ip_off;         /* fragment offset field */
       BYTE    ip_ttl;         /* time to live */
       BYTE    ip_p;           /* protocol */
       WORD    ip_sum;         /* checksum */
       DWORD   ip_src;         /* source address */
       DWORD   ip_dst;         /* dest address */
     };

/*
 * TCP header.
 * Per RFC 793, September, 1981.
 */
struct tcp_header {
       WORD    th_sport;       /* source port */
       WORD    th_dport;       /* destination port */
       DWORD   th_seq;         /* sequence number */
       DWORD   th_ack;         /* acknowledgement number */
       BYTE    th_offx2;       /* data offset, rsvd */
       BYTE    th_flags;
       WORD    th_win;         /* window */
       WORD    th_sum;         /* checksum */
       WORD    th_urp;         /* urgent pointer */
     };

/*
 * UDP protocol header.
 * Per RFC 768, September, 1981.
 */
struct udp_header {
       WORD   uh_sport;        /* source port */
       WORD   uh_dport;        /* destination port */
       WORD   uh_ulen;         /* udp length */
       WORD   uh_sum;          /* udp checksum */
     };

#if defined(_MSC_VER) || defined(__CYGWIN__)
  #pragma pack(pop)
#else
  #pragma pack()
#endif

static int make_ip_chksum (const void *buf, size_t len)
{
  long  cksum   = 0;
  long  slen    = (long) len;   /* must be signed */
  const WORD *w = (const WORD*) buf;

  while (slen > 1)
  {
    cksum += *w++;
    slen  -= 2;
  }
  if (slen > 0)
     cksum += *(const BYTE*) w;

  while (cksum >> 16)
      cksum = (cksum & 0xFFFF) + (cksum >> 16);
  return (WORD) cksum;
}

static const void *make_ip_hdr (size_t data_len)
{
  static struct ip_header ip;
  static WORD   ip_id = 1;

  memset (&ip, 0, sizeof(ip));
  ip.ip_ver  = 4;
  ip.ip_hlen = sizeof(ip) / 4;
  ip.ip_len  = swap16 ((WORD)(sizeof(ip) + data_len));
  ip.ip_ttl  = 255;
  ip.ip_id   = swap16 (++ip_id);
  ip.ip_p    = IPPROTO_TCP;
  ip.ip_src  = 0x10203040;      /* Just for now 64.48.32.16 */
  ip.ip_dst  = 0x50607080;      /* Just for now 128.112.96.80 */
  ip.ip_sum  = ~make_ip_chksum (&ip, sizeof(ip));
  return (&ip);
}

const void *make_udp_hdr (size_t data_len)
{
  static struct udp_header uh;

  memset (&uh, 0xff, sizeof(uh));  /* \todo */
  ARGSUSED (data_len);
  return (&uh);
}

const void *make_tcp_hdr (size_t data_len)
{
  static struct tcp_header th;

  memset (&th, '\0', sizeof(th));  /* \todo */
  th.th_offx2 = 16 * (sizeof(th)/4);
  ARGSUSED (data_len);
  return (&th);
}

/*
 * Stolen and modified from APR (Apache Portable Runtime):
 * Number of micro-seconds between the beginning of the Windows epoch
 * (Jan. 1, 1601) and the Unix epoch (Jan. 1, 1970).
 *
 * This assumes all Win32 compilers have 64-bit support.
 */
#define DELTA_EPOCH_IN_USEC  U64_SUFFIX (11644473600000000)

uint64 FILETIME_to_unix_epoch (const FILETIME *ft)
{
  uint64 res = (uint64) ft->dwHighDateTime << 32;

  res |= ft->dwLowDateTime;
  res /= 10;                   /* from 100 nano-sec periods to usec */
  res -= DELTA_EPOCH_IN_USEC;  /* from Win epoch to Unix epoch */
  return (res);
}

time_t FILETIME_to_time_t (const FILETIME *ft)
{
  return (FILETIME_to_unix_epoch (ft) / U64_SUFFIX(1000000));
}

/**
 * Return FILETIME in seconds as a double.
 */
double FILETIME_to_sec (const FILETIME *filetime)
{
  const LARGE_INTEGER *ft = (const LARGE_INTEGER*) filetime;
  long double          rc = (long double) ft->QuadPart;

  return (double) (rc/1E7);    /* from 100 nano-sec periods to sec */
}

/**
 * Return number of micro-sec from a `FILETIME` as a 64-bit signed.
 */
int64 FILETIME_to_usec (const FILETIME *ft)
{
  int64 res = (int64) ft->dwHighDateTime << 32;

  res |= ft->dwLowDateTime;
  return (res / 10);   /* from 100 nano-sec periods to usec */
}

static void _gettimeofday (struct pcap_timeval *tv)
{
  FILETIME ft;
  uint64   tim;

  if (p_GetSystemTimePreciseAsFileTime)
       (*p_GetSystemTimePreciseAsFileTime) (&ft);
  else GetSystemTimeAsFileTime (&ft);

  tim = FILETIME_to_unix_epoch (&ft);
  tv->tv_sec  = (DWORD) (tim / 1000000L);
  tv->tv_usec = (DWORD) (tim % 1000000L);
}

size_t write_pcap_header (void)
{
  struct pcap_file_header pf_hdr;
  size_t rc;

  if (!g_cfg.PCAP.dump_stream)
     return (-1);

  memset (&pf_hdr, 0, sizeof(pf_hdr));

  pf_hdr.magic         = TCPDUMP_MAGIC;
  pf_hdr.version_major = PCAP_VERSION_MAJOR;
  pf_hdr.version_minor = PCAP_VERSION_MINOR;
  pf_hdr.thiszone      = 60 * _timezone;
  pf_hdr.sigfigs       = 0;
  pf_hdr.snap_len      = 64*1024;
  pf_hdr.linktype      = DLT_IPV4;

  rc = fwrite (&pf_hdr, 1, sizeof(pf_hdr), g_cfg.PCAP.dump_stream);
  return (rc == 0 ? -1 : rc);
}

size_t write_pcap_packet (SOCKET s, const void *pkt, size_t len, BOOL out)
{
  struct pcap_pkt_header pc_hdr;
  size_t rc, pcap_len;

  if (!g_cfg.PCAP.dump_stream)
     return (-1);

  pcap_len = len + sizeof(struct ip_header) + sizeof(struct tcp_header);
  _gettimeofday (&pc_hdr.ts);

  pc_hdr.len    = (DWORD) pcap_len;
  pc_hdr.caplen = (DWORD) pcap_len;

  fwrite (&pc_hdr, sizeof(pc_hdr), 1, g_cfg.PCAP.dump_stream);

#if 0
  switch (lookup_sk_proto(s))
  {
    case IPPROTO_TCP:
         fwrite (make_ip_hdr(len + sizeof(struct tcp_header)), sizeof(struct ip_header), 1, g_cfg.PCAP.dump_stream);
         fwrite (make_tcp_hdr(len), sizeof(struct tcp_header), 1, g_cfg.PCAP.dump_stream);
         break;
    case IPPROTO_UDP:
         fwrite (make_ip_hdr(len + sizeof(struct udp_header)), sizeof(struct ip_header), 1, g_cfg.PCAP.dump_stream);
         fwrite (make_udp_hdr(len), sizeof(struct udp_header), 1, g_cfg.PCAP.dump_stream);
         break;
    default:
         return (0);
  }

#else
  fwrite (make_ip_hdr(len + sizeof(struct tcp_header)), 1, sizeof(struct ip_header), g_cfg.PCAP.dump_stream);
  fwrite (make_tcp_hdr(len), 1, sizeof(struct tcp_header), g_cfg.PCAP.dump_stream);

  ARGSUSED (s);
  ARGSUSED (out);
#endif

  rc = fwrite (pkt, 1, len, g_cfg.PCAP.dump_stream);
  return (rc == 0 ? -1 : pcap_len);
}

/*
 * As above, but an array of packets.
 * \todo.
 */
size_t write_pcap_packetv (SOCKET s, const WSABUF *bufs, DWORD num_bufs, BOOL out)
{
  ARGSUSED (s);
  ARGSUSED (bufs);
  ARGSUSED (num_bufs);
  ARGSUSED (out);
  return (0);
}

#if defined(_MSC_VER) || (__MSVCRT_VERSION__ >= 0x800)
/*
 * Ripped from Gnulib:
 */
#include <excpt.h>

/* Gnulib can define its own status codes, as described in the page
   "Raising Software Exceptions" on microsoft.com
   <http://msdn.microsoft.com/en-us/library/het71c37.aspx>.
   Our status codes are composed of
     - 0xE0000000, mandatory for all user-defined status codes,
     - 0x474E550, a API identifier ("GNU"),
     - 0, 1, 2, ..., used to distinguish different status codes from the
       same API.
 */

#define STATUS_GNULIB_INVALID_PARAMETER (0xE0000000 + 0x474E550 + 0)

static void __cdecl invalid_parameter_handler (const wchar_t *expression,
                                               const wchar_t *function,
                                               const wchar_t *file,
                                               unsigned int   line,
                                               uintptr_t      dummy)
{
  TRACE (1, "%s (%" WCHAR_FMT ", %" WCHAR_FMT ", %" WCHAR_FMT ", %u, %p)\n",
         __FUNCTION__, expression, function, file, line, (void*)dummy);
  RaiseException (STATUS_GNULIB_INVALID_PARAMETER, 0, 0, NULL);
}
#endif

static int inv_handler_set = 0;

static void set_invalid_handler (void)
{
#if defined(_MSC_VER) || (__MSVCRT_VERSION__ >= 0x800)

  if (g_cfg.trace_level >= 1 && !inv_handler_set)
  {
    _set_invalid_parameter_handler (invalid_parameter_handler);
    inv_handler_set = 1;
  }
#endif
}

static void reset_invalid_handler (void)
{
#if defined(_MSC_VER) || (__MSVCRT_VERSION__ >= 0x800)
  if (inv_handler_set)
     _set_invalid_parameter_handler (NULL);
  inv_handler_set = 0;
#endif
}

#if defined(_MSC_VER) && defined(USE_VLD)
  /*
   * Using "Visual Leak Detector" in _RELEASE mode is possible via the
   * '-DVLD_FORCE_ENABLE' flag. But not advisable according to:
   *   https://github.com/KindDragon/vld/wiki
   *
   * VLD is useful for '_MSC_VER' only.
   */
  #include <vld.h>

  void crtdbg_init (void)
  {
    VLD_UINT opts;

    VLDSetReportOptions (VLD_OPT_REPORT_TO_STDOUT, NULL); /* Force all reports to "stdout" in "ASCII" */
    opts = VLDGetOptions();
    VLDSetOptions (opts, 100, 4);   /* Dump max 100 bytes data. And walk max 4 stack frames */
  }

  void crtdbg_exit (void)
  {
  }

#elif defined(_MSC_VER) && defined(_DEBUG)
  static _CrtMemState last_state;

  void crtdbg_init (void)
  {
    int flags = _CRTDBG_LEAK_CHECK_DF     |
                _CRTDBG_DELAY_FREE_MEM_DF |
             /* _CRTDBG_CHECK_CRT_DF      | */   /* Don't report allocs in CRT */
             /* _CRTDBG_CHECK_ALWAYS_DF   | */   /* This flag makes things extremely slow */
                _CRTDBG_ALLOC_MEM_DF;

    _CrtSetReportFile (_CRT_WARN, _CRTDBG_FILE_STDERR);
    _CrtSetReportMode (_CRT_WARN, _CRTDBG_MODE_FILE);
    _CrtSetDbgFlag (flags | _CrtSetDbgFlag(_CRTDBG_REPORT_FLAG));
    _CrtMemCheckpoint (&last_state);
  }

  void crtdbg_exit (void)
  {
    _CrtMemState new_state, diff_state;

    _CrtMemCheckpoint (&new_state);

    /* Do this only if there is a significant difference in the mem-state.
     */
    if (_CrtMemDifference(&diff_state, &last_state, &new_state))
    {
      _CrtMemDumpAllObjectsSince (&last_state);
      _CrtMemDumpStatistics (&last_state);
      _CrtCheckMemory();
      _CrtDumpMemoryLeaks();
    }
    smartlist_leak_check();
    reset_invalid_handler();
  }

#else
  void crtdbg_init (void)
  {
  }
  void crtdbg_exit (void)
  {
  }
#endif
