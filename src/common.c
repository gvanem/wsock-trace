/**\file    common.c
 * \ingroup Main
 *
 * \brief
 *   Common support functions for Wsock-Trace and Geoip.exe etc.
 *
 * basename() and dirname():
 *   Copyright (C) 1998 DJ Delorie, see COPYING.DJ for details
 *   Copyright (C) 1997 DJ Delorie, see COPYING.DJ for details
 */

#include <signal.h>
#include <limits.h>
#include <windows.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <errno.h>

#if defined(__CYGWIN__)
  #include <sys/ioctl.h>
  #include <termios.h>
#else
  #include <share.h>
#endif

#include "common.h"
#include "smartlist.h"
#include "init.h"
#include "dump.h"

#ifndef WSA_QOS_EUNKOWNPSOBJ
#define WSA_QOS_EUNKOWNPSOBJ  (WSABASEERR + 1024)
#endif

#define IS_SLASH(c)  ((c) == '\\' || (c) == '/')
#define TOUPPER(c)   toupper ((int)(c))
#define TOLOWER(c)   tolower ((int)(c))

int              fatal_error;
CRITICAL_SECTION crit_sect;

char curr_dir  [MAX_PATH] = { '\0' };
char curr_prog [MAX_PATH] = { '\0' };
char prog_dir  [MAX_PATH] = { '\0' };

HINSTANCE ws_trace_base;        /* Our base-address */
char     *program_name;         /* For getopt.c and 'xx_main()' functions */

char *set_program_name (char *argv0)
{
  static char ret [_MAX_PATH];

  snprintf (ret, sizeof(ret), "%s %s", __argv[0], argv0);
  program_name = ret;
  return (ret);
}

static void __stdcall dummy_WSASetLastError (int err)
{
  ARGSUSED (err);
}

static int __stdcall dummy_WSAGetLastError (void)
{
  return (0);
}

void (__stdcall *g_WSASetLastError) (int err) = dummy_WSASetLastError;
int  (__stdcall *g_WSAGetLastError) (void)    = dummy_WSAGetLastError;

/*
 * A cache of file-names with true casing as returned from
 * 'GetLongPathName()'. Use a 32-bit CRC value to lookup an
 * entry in fname_cache_get().
 */
struct file_name_entry {
       char  *orig_name;
       char  *real_name;
       DWORD  crc32;
     };

static smartlist_t *fname_list = NULL;
static const char  *fname_cache_get (const char *fname);
static const char  *fname_cache_add (const char *fname);
static void         fname_cache_free (void);
static void         fname_cache_dump (void);

static DWORD crc_bytes (const char *buf, size_t len);

#define TRACE_BUF_SIZE (2*1024)

/* \todo: these should be "Thread Local" variables.
 */
static char *trace_ptr, *trace_end;
static char  trace_buf [TRACE_BUF_SIZE];

static BOOL tilde_escape = TRUE;
static BOOL trace_get_color = FALSE;

void common_init (void)
{
  tilde_escape = TRUE;
  trace_ptr = trace_buf;
  trace_end = trace_ptr + TRACE_BUF_SIZE - 1;
}

void common_exit (void)
{
  if (g_cfg.trace_level >= 5)
     fname_cache_dump();

  fname_cache_free();
  trace_ptr = trace_end = NULL;
}

#define ADD_VALUE(code,str) { code, #code, str }

static const struct WSAE_search_list err_list[] = {
  ADD_VALUE (WSAEINTR,           "Call interrupted"),
  ADD_VALUE (WSAEBADF,           "Bad file"),
  ADD_VALUE (WSAEACCES,          "Bad access"),
  ADD_VALUE (WSAEFAULT,          "Bad argument"),
  ADD_VALUE (WSAEINVAL,          "Invalid arguments"),
  ADD_VALUE (WSAEMFILE,          "Out of file descriptors"),
  ADD_VALUE (WSAEWOULDBLOCK,     "Call would block"),
  ADD_VALUE (WSAEINPROGRESS,     "Blocking call in progress"),
  ADD_VALUE (WSAEALREADY,        "Blocking call in progress"),
  ADD_VALUE (WSAENOTSOCK,        "Descriptor is not a socket"),
  ADD_VALUE (WSAEDESTADDRREQ,    "Need destination address"),
  ADD_VALUE (WSAEMSGSIZE,        "Bad message size"),
  ADD_VALUE (WSAEPROTOTYPE,      "Bad protocol"),
  ADD_VALUE (WSAENOPROTOOPT,     "Protocol option is unsupported"),
  ADD_VALUE (WSAEPROTONOSUPPORT, "Protocol is unsupported"),
  ADD_VALUE (WSAESOCKTNOSUPPORT, "Socket is unsupported"),
  ADD_VALUE (WSAEOPNOTSUPP,      "Operation not supported"),
  ADD_VALUE (WSAEPFNOSUPPORT,    "Protocol family not supported"),
  ADD_VALUE (WSAEAFNOSUPPORT,    "Address family not supported"),
  ADD_VALUE (WSAEADDRINUSE,      "Address already in use"),
  ADD_VALUE (WSAEADDRNOTAVAIL,   "Address not available"),
  ADD_VALUE (WSAENETDOWN,        "Network down"),
  ADD_VALUE (WSAENETUNREACH,     "Network unreachable"),
  ADD_VALUE (WSAENETRESET,       "Network has been reset"),
  ADD_VALUE (WSAECONNABORTED,    "Connection was aborted"),
  ADD_VALUE (WSAECONNRESET,      "Connection was reset"),
  ADD_VALUE (WSAENOBUFS,         "No buffer space"),
  ADD_VALUE (WSAEISCONN,         "Socket is already connected"),
  ADD_VALUE (WSAENOTCONN,        "Socket is not connected"),
  ADD_VALUE (WSAESHUTDOWN,       "Socket has been shut down"),
  ADD_VALUE (WSAETOOMANYREFS,    "Too many references"),
  ADD_VALUE (WSAETIMEDOUT,       "Timed out"),
  ADD_VALUE (WSAECONNREFUSED,    "Connection refused"),
  ADD_VALUE (WSAELOOP,           "Loop??"),
  ADD_VALUE (WSAENAMETOOLONG,    "Name too long"),
  ADD_VALUE (WSAEHOSTDOWN,       "Host down"),
  ADD_VALUE (WSAEHOSTUNREACH,    "Host unreachable"),
  ADD_VALUE (WSAENOTEMPTY,       "Not empty"),
  ADD_VALUE (WSAEPROCLIM,        "Process limit reached"),
  ADD_VALUE (WSAEUSERS,          "Too many users"),
  ADD_VALUE (WSAEDQUOT,          "Bad quota"),
  ADD_VALUE (WSAESTALE,          "Something is stale"),
  ADD_VALUE (WSAEREMOTE,         "Remote error"),
  ADD_VALUE (WSAEDISCON,         "Disconnected"),
  ADD_VALUE (WSASYSNOTREADY,     "Winsock library is not ready"),
  ADD_VALUE (WSAVERNOTSUPPORTED, "Winsock version not supported"),
  ADD_VALUE (WSANOTINITIALISED,  "Winsock library not initialised"),
  ADD_VALUE (WSAHOST_NOT_FOUND,  "Host not found"),
  ADD_VALUE (WSATRY_AGAIN,       "Host not found, try again"),
  ADD_VALUE (WSANO_RECOVERY,     "Unrecoverable error in call to nameserver"),
  ADD_VALUE (WSANO_DATA,         "No data record of requested type"),

  /* WinSock2 specific error codes */
  ADD_VALUE (WSAENOMORE,                "No more results can be returned by WSALookupServiceNext"),
  ADD_VALUE (WSAECANCELLED,             "A call to WSALookupServiceEnd was made while this call was still processing. The call has been canceled"),
  ADD_VALUE (WSAEINVALIDPROCTABLE,      "The procedure call table is invalid"),
  ADD_VALUE (WSAEINVALIDPROVIDER,       "The requested service provider is invalid"),
  ADD_VALUE (WSAEPROVIDERFAILEDINIT,    "The requested service provider could not be loaded or initialized"),
  ADD_VALUE (WSASYSCALLFAILURE,         "A system call that should never fail has failed"),
  ADD_VALUE (WSASERVICE_NOT_FOUND,      "No such service is known"),
  ADD_VALUE (WSATYPE_NOT_FOUND,         "The specified class was not found"),
  ADD_VALUE (WSA_E_NO_MORE,             "No more results can be returned by WSALookupServiceNext"),
  ADD_VALUE (WSA_E_CANCELLED,           "A call to WSALookupServiceEnd was made while this call was still processing"),
  ADD_VALUE (WSAEREFUSED,               "A database query failed because it was actively refused"),

  /* WS QualityofService errors */
  ADD_VALUE (WSA_QOS_RECEIVERS,         "At least one reserve has arrived"),
  ADD_VALUE (WSA_QOS_SENDERS,           "At least one path has arrived"),
  ADD_VALUE (WSA_QOS_NO_SENDERS,        "There are no senders"),
  ADD_VALUE (WSA_QOS_NO_RECEIVERS,      "There are no receivers"),
  ADD_VALUE (WSA_QOS_REQUEST_CONFIRMED, "Reserve has been confirmed"),
  ADD_VALUE (WSA_QOS_ADMISSION_FAILURE, "Error due to lack of resources"),
  ADD_VALUE (WSA_QOS_POLICY_FAILURE,    "Rejected for administrative reasons - bad credentials"),
  ADD_VALUE (WSA_QOS_BAD_STYLE,         "Unknown or conflicting style"),
  ADD_VALUE (WSA_QOS_BAD_OBJECT,        "Problem with some part of the filterspec or providerspecific buffer in general"),
  ADD_VALUE (WSA_QOS_TRAFFIC_CTRL_ERROR,"Problem with some part of the flowspec"),
  ADD_VALUE (WSA_QOS_GENERIC_ERROR,     "General QOS error"),
  ADD_VALUE (WSA_QOS_ESERVICETYPE,      "An invalid or unrecognized service type was found in the flowspec"),
  ADD_VALUE (WSA_QOS_EFLOWSPEC,         "An invalid or inconsistent flowspec was found in the QOS structure"),
  ADD_VALUE (WSA_QOS_EPROVSPECBUF,      "Invalid QOS provider-specific buffer"),
  ADD_VALUE (WSA_QOS_EFILTERSTYLE,      "An invalid QOS filter style was used"),
  ADD_VALUE (WSA_QOS_EFILTERTYPE,       "An invalid QOS filter type was used"),
  ADD_VALUE (WSA_QOS_EFILTERCOUNT,      "An incorrect number of QOS FILTERSPECs were specified in the FLOWDESCRIPTOR"),
  ADD_VALUE (WSA_QOS_EOBJLENGTH,        "An object with an invalid ObjectLength field was specified in the QOS provider-specific buffer"),
  ADD_VALUE (WSA_QOS_EFLOWCOUNT,        "An incorrect number of flow descriptors was specified in the QOS structure"),
  ADD_VALUE (WSA_QOS_EUNKOWNPSOBJ,      "An unrecognized object was found in the QOS provider-specific buffer"),
  ADD_VALUE (WSA_QOS_EPOLICYOBJ,        "An invalid policy object was found in the QOS provider-specific buffer"),
  ADD_VALUE (WSA_QOS_EFLOWDESC,         "An invalid QOS flow descriptor was found in the flow descriptor list"),
  ADD_VALUE (WSA_QOS_EPSFLOWSPEC,       "An invalid or inconsistent flowspec was found in the QOS provider-specific buffer"),
  ADD_VALUE (WSA_QOS_EPSFILTERSPEC,     "An invalid FILTERSPEC was found in the QOS provider-specific buffer"),
  ADD_VALUE (WSA_QOS_ESDMODEOBJ,        "An invalid shape discard mode object was found in the QOS provider-specific buffer"),
  ADD_VALUE (WSA_QOS_ESHAPERATEOBJ,     "An invalid shaping rate object was found in the QOS provider-specific buffer"),
  ADD_VALUE (WSA_QOS_RESERVED_PETYPE,   "A reserved policy element was found in the QOS provider-specific buffer"),

  /* WSAx overlapped errors */
  ADD_VALUE (WSA_IO_PENDING,            "Overlapped I/O operation in progress"),              /* == ERROR_IO_PENDING == 997 */
  ADD_VALUE (WSA_IO_INCOMPLETE,         "Overlapped I/O operation not in signalled status"),  /* == ERROR_IO_INCOMPLETE == 996 */
  ADD_VALUE (WSA_INVALID_HANDLE,        "Invalid handle")                                     /* == ERROR_INVALID_HANDLE == 6 */
};

/**
 * Return a text for a Winsock2 error-code.
 *
 * \todo do a qsort() of 'err_list' (make a copy). And use bsearch() to lookup 'err'.
 */
char *ws_strerror (DWORD err, char *buf, size_t len)
{
  #define CHECK_AND_JUMP(err_val, idx)               \
          do {                                       \
            if (err == err_val) {                    \
               el = &err_list [DIM(err_list) - idx]; \
               goto fill;                            \
            }                                        \
          } while (0)

  const struct WSAE_search_list *el = err_list;
  size_t i = 0;

  if (err == 0)
     return ("No error");

  /* First check for 'WSAx overlapped errors' to get an English text for
   * the one in the above table.
   *
   * Some programs (notably Nmap and Nping) calls 'WSAGetLastError()'
   * when they ought to call 'GetLastError()'. Handle this so tracing
   * of e.g. 'WSAGetLastError()' returns the correct error-string.
   */
  CHECK_AND_JUMP (WSA_IO_PENDING, 3);
  CHECK_AND_JUMP (WSA_IO_INCOMPLETE, 2);
  CHECK_AND_JUMP (WSA_INVALID_HANDLE, 1);

  if (err > 0 && err < WSABASEERR)
     return win_strerror (err);

  for ( ; i < DIM(err_list); i++, el++)
      if (err == el->err)
      {
      fill:
        if (g_cfg.short_errors)
             snprintf (buf, len, "%s (%lu)", el->short_name, DWORD_CAST(err));
        else snprintf (buf, len, "%s: %s (%lu)", el->short_name, el->full_name, DWORD_CAST(err));
        return (buf);
      }
  snprintf (buf, len, "Unknown error: %lu", DWORD_CAST(err));
  return (buf);
}

/**
 * Removes the 1st end-of-line termination from a string.
 * Removes "\n" (Unix), "\r" (MacOS) or "\r\n" (DOS) terminations.
 */
char *str_rip (char *s)
{
  char *p;

  if ((p = strchr (s, '\n')) != NULL) *p = '\0';
  if ((p = strchr (s, '\r')) != NULL) *p = '\0';
  return (s);
}

/**
 * Removes the 1st end-of-line termination from a wide-string.
 * Removes "\n" (Unix), "\r" (MacOS) or "\r\n" (DOS) terminations.
 */
wchar_t *str_ripw (wchar_t *s)
{
  wchar_t *p;

  if ((p = wcschr (s, L'\n')) != NULL) *p = L'\0';
  if ((p = wcschr (s, L'\r')) != NULL) *p = L'\0';
  return (s);
}

/**
 * Trim leading blanks (space/tab) from a string.
 */
char *str_ltrim (char *s)
{
  assert (s != NULL);

  while (s[0] && s[1] && isspace ((int)s[0]))
       s++;
  return (s);
}

/**
 * Return err-number and string for 'err'. Only use this with
 * GetLastError(). Remove trailing `[\r\n]`.
 */
char *win_strerror (DWORD err)
{
  static  char buf[512+20];
  char    err_buf[512], *p;
  HRESULT hr = 0;

  if (HRESULT_SEVERITY(err))
     hr = err;

  if (err == ERROR_SUCCESS)
     strcpy (err_buf, "No error");
  else
  if (!FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM, NULL, err,
                      LANG_NEUTRAL, err_buf, sizeof(err_buf)-1, NULL))
     strcpy (err_buf, "Unknown error");

  if (hr)
       snprintf (buf, sizeof(buf), "0x%08lX: %s", (u_long)hr, err_buf);
  else snprintf (buf, sizeof(buf), "%lu: %s", (u_long)err, err_buf);

  str_rip (buf);
  p = strrchr (buf, '.');
  if (p && p[1] == '\0')
     *p = '\0';
  return (buf);
}

/**
 * Handles dynamic loading and unloading of DLLs and their functions.
 */
int load_dynamic_table (struct LoadTable *tab, int tab_size)
{
  int i, j;

  for (i = j = 0; i < tab_size; tab++, i++)
  {
    const char             *is_opt;
    const struct LoadTable *prev = i > 0 ? (tab - 1) : NULL;
    HINSTANCE               mod_handle;
    FARPROC                 func_addr;

    if (prev && !stricmp(tab->mod_name, prev->mod_name))
         mod_handle = prev->mod_handle;
    else mod_handle = LoadLibrary (tab->mod_name);

    if (mod_handle && mod_handle != INVALID_HANDLE_VALUE)
    {
      func_addr = GetProcAddress (mod_handle, tab->func_name);

      if (!tab->optional && !func_addr)
      {
        TRACE (2, "Function \"%s\" not found in %s.\n", tab->func_name, tab->mod_name);
        j++;
      }
      *tab->func_addr = func_addr;
    }
    is_opt = (tab->optional ? " (optional)" : "");
    tab->mod_handle = mod_handle;

    TRACE (4, "%2d: Module 0x%" ADDR_FMT "/%s, func \"%s\" -> 0x%" ADDR_FMT "%s.\n", i,
              ADDR_CAST(tab->mod_handle), tab->mod_name, tab->func_name,
              ADDR_CAST(*tab->func_addr), is_opt);
  }
  return (i - j);
}

int unload_dynamic_table (struct LoadTable *tab, int tab_size)
{
  int i, m_unload, f_unload;

  for (i = 0; i < tab_size; tab++, i++)
  {
    m_unload = f_unload = 0;

    if (tab->mod_handle && tab->mod_handle != INVALID_HANDLE_VALUE)
    {
      FreeLibrary (tab->mod_handle);
      m_unload = 1;
    }
    tab->mod_handle = INVALID_HANDLE_VALUE;

    if (*tab->func_addr)
       f_unload = 1;
    *tab->func_addr = NULL;

    TRACE (4, "%2d: function \"%s\" %s. Module \"%s\" %s.\n", i,
              tab->func_name, f_unload ? "freed"    : "not used",
              tab->mod_name,  m_unload ? "unloaded" : "not used");
  }
  return (i);
}

const struct LoadTable *find_dynamic_table (const struct LoadTable *tab, int tab_size, const char *func_name)
{
  int i;

  for (i = 0; i < tab_size; tab++, i++)
      if (!strcmp(tab->func_name, func_name))
         return (tab);
  return (NULL);
}

#if defined(__CYGWIN__)
  char *_itoa (int value, char *buf, int radix)
  {
    assert (radix == 8 || radix == 10);
    sprintf (buf, (radix == 8) ? "%o" : "%d", value);
    return (buf);
  }

  char *_ultoa (unsigned long value, char *buf, int radix)
  {
    assert (radix == 8 || radix == 10);
    sprintf (buf, (radix == 8) ? "%lo" : "%lu", value);
    return (buf);
  }

  /*
   * '_kbhit()' and '_getch()' for CygWin based on:
   *   https://stackoverflow.com/questions/29335758/using-kbhit-and-getch-on-linux
   */
  static int ch_waiting, bytes_waiting;
  static struct termios old_term;

  static void enable_raw_mode (void)
  {
    struct termios term;

    tcgetattr (STDIN_FILENO, &old_term);
    memcpy (&term, &old_term, sizeof(term));
    term.c_lflag &= ~(ICANON | ECHO);   /* Disable echo as well */
    tcsetattr (STDIN_FILENO, TCSANOW, &term);
  }

  static void disable_raw_mode (void)
  {
    tcsetattr (STDIN_FILENO, TCSANOW, &old_term);
  }

  int _kbhit (void)
  {
    BOOL rc;

    enable_raw_mode();
    ch_waiting = ioctl (STDIN_FILENO, FIONREAD, &bytes_waiting);
    rc = (bytes_waiting > 0);
    disable_raw_mode();
    tcflush (STDIN_FILENO, TCIFLUSH);
    TRACE (2, "ch_waiting: %d, bytes_waiting: %d\n", ch_waiting, bytes_waiting);
    return (rc);
  }

  int _getch (void)
  {
    if (bytes_waiting > 0)
    {
      bytes_waiting--;
      return (ch_waiting);
    }
    return (0);
  }
#endif

/*
 * 'unsigned int' to string with leading zeros specified in 'width'.
 * _utoa10w (1234,5,buf) -> "01234".
 *
 * Faster than using 'snprintf (buf, sizeof(buf), "%*u", 5, 1234)'.
 */
char *_utoa10w (int value, int width, char *buf)
{
  int i = 0;

  do           /* generate digits in reverse order */
  {
    buf[i++] = (value % 10) + '0';
  }
  while ((value /= 10) > 0);

  while (i < width)
     buf [i++] = '0';
  buf [i] = '\0';
  return _strreverse (buf);
}

/**
 * Search 'list' for 'value' and return it's name.
 */
const char *list_lookup_name (unsigned value, const struct search_list *list, int num)
{
  static char buf[10];

  while (num > 0 && list->name)
  {
    if (list->value == value)
       return (list->name);
    num--;
    list++;
  }
  return _itoa (value, buf, 10);
}

/**
 * Search 'list' for 'name' and return it's 'value'.
 */
unsigned list_lookup_value (const char *name, const struct search_list *list, int num)
{
  while (num > 0 && list->name)
  {
    if (!stricmp(name, list->name))
       return (list->value);
    num--;
    list++;
  }
  return (UINT_MAX);
}

const char *flags_decode (DWORD flags, const struct search_list *list, int num)
{
  static char buf[400];
  char  *ret  = buf;
  char  *end  = buf + sizeof(buf) - 1;
  size_t left = end - ret;
  int    i;

  *ret = '\0';
  for (i = 0; i < num; i++, list++)
      if (flags & list->value)
      {
        ret += snprintf (ret, left, "%s|", list->name);
        left = end - ret;
        flags &= ~list->value;
      }
  if (flags)           /* print unknown flag-bits */
     ret += snprintf (ret, left, "0x%08lX|", DWORD_CAST(flags));
  if (ret > buf)
     *(--ret) = '\0';   /* remove '|' */
  return (buf);
}

/**
 * Traverse `list` and check that all values are unique and no `value`
 * (except the last) is `UINT_MAX`.
 */
int list_lookup_check (const struct search_list *list, int num, int *err_idx1, int *err_idx2)
{
  const struct search_list *start = list;
  int   i, j;

  *err_idx1 = *err_idx2 = 0;

  for (i = 0; i < num; i++, list++)
  {
    if (!list->name)
    {
      *err_idx1 = i;
      return (-1);
    }
    if (!list->name[0])
    {
      *err_idx1 = i;
      return (-2);
    }
    if (i < num-1 && list->value == UINT_MAX)
    {
      *err_idx1 = i;
      return (-3);
    }

    for (j = i+1; j < num; j++)
        if (list->value == start[j].value)
        {
          *err_idx1 = i;
          *err_idx2 = j;
          return (-4);
        }
  }
  return (0);
}

/**
 * Convert 32-bit big-endian (network order) to host order format.
 */
DWORD swap32 (DWORD val)
{
  return ((val & 0x000000FFU) << 24) |
         ((val & 0x0000FF00U) <<  8) |
         ((val & 0x00FF0000U) >>  8) |
         ((val & 0xFF000000U) >> 24);
}

/**
 * Convert 16-bit big-endian (network order) to host order format.
 */
WORD swap16 (WORD val)
{
  return ((val & 0x00FF) << 8) | ((val & 0xFF00) >> 8);
}

/**
 * Return the filename without any path or drive specifiers.
 */
char *basename (const char *fname)
{
  const char *base = fname;

  if (fname && *fname)
  {
    if (fname[1] == ':')
    {
      fname += 2;
      base = fname;
    }

    while (*fname)
    {
      if (*fname == '\\' || *fname == '/')
         base = fname + 1;
      fname++;
    }
  }
  return (char*) base;
}

/**
 * Return the malloc'ed directory part of a filename.
 */
char *dirname (const char *fname)
{
  const char *p  = fname;
  const char *slash = NULL;
  char       *dirpart;
  size_t      dirlen;

  if (!fname)
     return (NULL);

  if (*fname && fname[1] == ':')
  {
    slash = fname + 1;
    p += 2;
  }

  /* Find the rightmost slash
   */
  while (*p)
  {
    if (IS_SLASH(*p))
       slash = p;
    p++;
  }

  if (slash == NULL)
  {
    fname = ".";
    dirlen = 1;
  }
  else
  {
    /* Remove any trailing slashes
     */
    while (slash > fname && IS_SLASH(slash[-1]))
        slash--;

    /* How long is the directory we will return?
     */
    dirlen = slash - fname + (slash == fname || slash[-1] == ':');
    if (*slash == ':' && dirlen == 1)
       dirlen += 2;
  }

  dirpart = malloc (dirlen + 1);
  if (dirpart)
  {
    _strlcpy (dirpart, fname, dirlen+1);
    if (slash && *slash == ':' && dirlen == 3)
       dirpart[2] = '.';      /* for "x:foo" return "x:." */
  }
  return (dirpart);
}

/**
 * Copy and replace (single or multiple) `\\` with single `/` if `use == /`. And vice-versa.
 * Assume `in_path` and `out_path` are not larger than `_MAX_PATH`.
 */
char *copy_path (char *out_path, const char *in_path, char use)
{
  _strlcpy (out_path, in_path, _MAX_PATH);
  if (use == '/')
     str_replace ('\\', '/', out_path);
  else if (use == '\\')
     str_replace ('/', '\\', out_path);
  return (out_path);
}

/**
 * Canonize file and paths names. E.g. convert this: \n
 *  `g:\mingw32\bin\../lib/gcc/x86_64-w64-mingw32/4.8.1/include`
 *
 * into something more readable: \n
 *   `g:\mingw32\lib\gcc\x86_64-w64-mingw32\4.8.1\include`
 *
 * I.e. turns `path` into a fully-qualified path.
 *
 * \note the `path` doesn't have to exist.
 *       Assumes `result` is at least `_MAX_PATH` characters long (if non-NULL).
 */
char *fix_path (const char *path)
{
  static char result [_MAX_PATH];

 /* GetFullPathName() doesn't seems to handle
  * '/' in 'path'. Convert to '\\'.
  *
  * Note: the 'result' file or path may not exists.
  *       Use 'file_exists()' to test.
  */
  copy_path (result, path, '\\');
  if (!GetFullPathName(result, sizeof(result), result, NULL))
     TRACE (2, "GetFullPathName(\"%s\") failed: %s\n",
            path, win_strerror(GetLastError()));

  return (result);
}

/**
 * Check for a path starting with `"\\device\\harddiskvolume[0-9]\\"` and map
 * to a drive letter the easy way.
 *
 * E.g. `"\\device\\harddiskvolume1\\x"` -> `"d:\\x"`
 *
 * Somewhat related:
 *   https://stackoverflow.com/questions/18509633/how-do-i-map-the-device-details-such-as-device-harddisk1-dr1-in-the-event-log-t
 */
static char *volume_to_path (char *path)
{
  #define VOLUME "\\Device\\HarddiskVolume"
  char *p;

  if (strnicmp(path, VOLUME, sizeof(VOLUME)-1))
     return (path);

  p = path + sizeof(VOLUME) - 1;

  if (!isdigit((int)*p) || p[1] != '\\')
     return (path);

  p--;
  p[0] = 'a' - '0' + p[1];
  p[1] = ':';
  return (p);
}

/*
 * Ignore stuff like:
 *   warning: '\System32\' directive output may be truncated writing 10 bytes into a
 *            region of size between 1 and 256 [-Wformat-truncation=]
 */
#ifndef __clang__
  GCC_PRAGMA (GCC diagnostic push)
  GCC_PRAGMA (GCC diagnostic ignored "-Wformat-truncation=")
#endif

static char *get_native_path (const char *path)
{
  static char win_root[_MAX_PATH] = { "" };
  static char sys_dir [_MAX_PATH] = { "" };
  static char ret [_MAX_PATH];

  if (!win_root[0])
  {
    const char *p = getenv ("WinDir");

    _strlcpy (win_root, p ? p : "?", sizeof(win_root));
    fix_drive (win_root);
    snprintf (sys_dir, sizeof(sys_dir), "%s\\System32\\", win_root);
  }
  if (!strnicmp(path, sys_dir, strlen(sys_dir)))
  {
    BOOL exist;

    snprintf (ret, sizeof(ret), "%s\\sysnative\\%s", win_root, path + strlen(sys_dir));
    exist = file_exists (ret);
    TRACE (2, "ret: '%s', exist: %d\n", ret, exist);
    if (exist)
       return (ret);
  }
  return (NULL);
}

#ifndef __clang__
  GCC_PRAGMA (GCC diagnostic pop)
#endif

/**
 * Returns the true casing for a file or path.
 *
 * \param[in]     apath      The ASCII-char path to work on.
 * \param[in]     wpath      The wide-char path to work on.
 * \param[in,out] exist      Optionally check if the file exists.
 * \param[in,out] is_native  If a file `"%WinDir\\System32\xx"` does not exists, check if the
 *                           `"%WinDir\\sysnative\xx"` file exists.
 *                           And return that file-name instead and set `is_native == TRUE`.
 *
 * \retval a ASCII-string with the true casing for the `wpath`.
 *
 * \note if the `wpath` does not exist, the casing remains unchanged.
 */
const char *get_path (const char    *apath,
                      const wchar_t *wpath,
                      BOOL          *exist,
                      BOOL          *is_native)
{
  static char ret [_MAX_PATH];
  static char path [_MAX_PATH];
  char   *p;
  int     save;

  if (exist)
     *exist = TRUE;       /* assume the 'wpath' exists */

  if (is_native)
     *is_native = FALSE;  /* assume it's not a native file */

  if (wpath)
       snprintf (path, sizeof(path), "%" WCHAR_FMT, wpath);
  else _strlcpy (path, apath, sizeof(path));

  if (!stricmp(path, "System"))    /* No more to do for this path */
     return (path);

  p = volume_to_path (path);
  if (strchr (p, '%'))
     p = getenv_expand (p, path, sizeof(path));

  save = g_cfg.use_full_path;
  g_cfg.use_full_path = 1;
  copy_path (ret, shorten_path(p), '\\');
  fix_drive (ret);
  g_cfg.use_full_path = save;

  if (exist)
  {
    *exist = file_exists (ret);
    if (!*exist && is_native && (p = get_native_path(ret)) != NULL)
    {
      *exist = *is_native = TRUE;
      return (p);
    }
  }
  return (ret);
}

static const char *get_guid_ole32_str (const GUID *guid, char *result, size_t result_size)
{
  wchar_t *str = alloca (2*result_size);
  DWORD    len;

  strcpy (result, "{??}");
  if (StringFromGUID2(guid, (LPOLESTR)str, (int)result_size-1))
  {
    len = WideCharToMultiByte (CP_ACP, 0, str, -1, result, (int)result_size, NULL, NULL);
    if (len == 0)
       strcpy (result, "{??}");
  }
  return (result);
}

static const char hex_chars[] = "0123456789ABCDEF";

static const char *get_guid_internal_str (const GUID *guid, char *result, size_t result_size)
{
  char  *out;
  const  BYTE *bytes;
  BYTE   v, hi_nibble, lo_nibble;
  GUID   guid_copy = *guid;
  int    i, j;
  static const char mask[] = "12345678-1234-1234-1234-123456789012";

  /* The GUID is the "data-structure from hell": the 1st 64-bit are on
   * big-endian format. But the rest are little endian. Go figure!
   */
  guid_copy.Data1 = swap32 (guid_copy.Data1);
  guid_copy.Data2 = swap16 (guid_copy.Data2);
  guid_copy.Data3 = swap16 (guid_copy.Data3);

  /* E.g. guid: {E70F1AA0-AB8B-11CF-8CA3-00805F48A192}
   */
  bytes  = (const BYTE*) &guid_copy;
  out    = result;
  *out++ = '{';

  for (i = j = 0; i < sizeof(guid_copy); i++)
  {
    v = *bytes++;
    lo_nibble = v % 16;
    hi_nibble = v >> 4;
    *out++ = hex_chars [(int)hi_nibble];
    *out++ = hex_chars [(int)lo_nibble];
    if (i == 3 || i == 5 || i == 7 || i == 9)
       *out++ = '-';
    assert (j < sizeof(mask)-1);
  }
  *out++ = '}';
  *out++ = '\0';
  ARGSUSED (result_size);
  return (result);
}

/*
 * Return a 'char' string for the given GUID.
 * Use OLE32.DLL or do it ourself.
 */
const char *get_guid_string (const GUID *guid)
{
  static char result [40];

  if (g_cfg.use_ole32)
     return get_guid_ole32_str (guid, result, sizeof(result));
  return get_guid_internal_str (guid, result, sizeof(result));
}

/*
 * As above, but with the '{', '}' and '-' stripped.
 */
const char *get_guid_path_string (const GUID *guid)
{
  static char result [40];
  const char *p = get_guid_string (guid);
  char       *out;

  for (out = result; *p; p++)
  {
    if (*p != '{' && *p != '}' && *p != '-')
      *out++ = *p;
  }
  *out = '\0';
  return (result);
}

static char hex_result [9];

static __inline void byte2hex (char *buf, BYTE val)
{
  buf[0] = hex_chars [val >> 4];
  buf[1] = hex_chars [val % 16];
}

const char *str_hex_byte (BYTE val)
{
  byte2hex (hex_result, val);
  hex_result[2] = '\0';
  return (hex_result);
}

const char *str_hex_word (WORD val)
{
  byte2hex (hex_result, val >> 8);
  byte2hex (hex_result+2, val & 255);
  hex_result[4] = '\0';
  return (hex_result);
}

const char *str_hex_dword (DWORD val)
{
  WORD hi_word = val >> 16;
  WORD lo_word = val & 0xFFFF;

  byte2hex (hex_result, hi_word >> 8);
  byte2hex (hex_result+2, hi_word & 255);
  byte2hex (hex_result+4, lo_word >> 8);
  byte2hex (hex_result+6, lo_word & 255);
  hex_result[8] = '\0';
  return (hex_result);
}

/**
 * Replace `ch1` with `ch2` in string `str`.
 */
char *str_replace (int ch1, int ch2, char *str)
{
  char *s = str;

  while (s && *s)
  {
    if (*s == ch1)
        *s = ch2;
    s++;
  }
  return (str);
}

/**
 * Return the left-trimmed place where paths `p1` and `p2` are similar.
 * Not case sensitive. Treats `/` and `\\` equally.
 */
const char *path_ltrim (const char *p1, const char *p2)
{
  for ( ; *p1 && *p2; p1++, p2++)
  {
    if (IS_SLASH(*p1) || IS_SLASH(*p2))
       continue;
    if (TOUPPER(*p1) != TOUPPER(*p2))
       break;
  }
  return (p1);
}

/**
 * For consistency, report drive-letter in lower case.
 */
char *fix_drive (char *path)
{
  size_t len = strlen (path);

  if (len >= 3 && path[1] == ':' && IS_SLASH(path[2]))
     path[0] = (char) TOLOWER (path[0]);
  return (path);
}

/**
 * This function is called from `StackWalkShow()` to return a
 * short version of `Line.FileName`. I.e. a file-name relative to
 * the path of the calling program.
 *
 * \note The `SymGetLineFromAddr64()` function always seems to
 *       return `Line.FileName` in lower-case.
 */
const char *shorten_path (const char *path)
{
  const char *real_name = fname_cache_get (path);

  if (!real_name)
  {
    real_name = fname_cache_add (path);
    if (!real_name)
       return (path);
  }
  if (g_cfg.use_short_path)
     return basename (path);

  if (!g_cfg.use_full_path)
  {
    size_t len = strlen (prog_dir);
    if (len >= 3 && !strnicmp(prog_dir, path, len))
       return (real_name + len);
  }
  return (real_name);
}

static const char *fname_cache_get (const char *fname)
{
  const struct file_name_entry *fe;
  DWORD crc32 = crc_bytes (fname, strlen(fname));
  int   i, max;

  if (!fname_list)
  {
    fname_list = smartlist_new();
    return (NULL);
  }
  max = smartlist_len (fname_list);
  for (i = 0; i < max; i++)
  {
    fe = smartlist_get (fname_list, i);
    if (crc32 == fe->crc32)
       return (fe->real_name ? fe->real_name : fe->orig_name);
  }
  return (NULL);
}

/**
 * Add a filename to the cache.
 */
static const char *fname_cache_add (const char *fname)
{
  struct file_name_entry *fn;
  size_t fn_len = strlen (fname);
  char   buf [MAX_PATH];

  fn = malloc (sizeof(*fn) + fn_len + 1);
  if (!fn)
     return (NULL);

  fn->crc32     = crc_bytes (fname, fn_len);
  fn->orig_name = str_replace ('\\', '/', strcpy((char*)(fn+1), fname));

  if (GetLongPathName(fname, buf, sizeof(buf)))
  {
    fn->real_name = str_replace ('\\', '/', strdup(buf));
    fix_drive (fn->real_name);
  }
  else
    fn->real_name = NULL;

  smartlist_add (fname_list, fn);
  return (fn->real_name ? fn->real_name : fn->orig_name);
}

static void fname_cache_dump (void)
{
  int i, max = fname_list ? smartlist_len (fname_list) : 0;

  for (i = 0; i < max; i++)
  {
    const struct file_name_entry *fn = smartlist_get (fname_list, i);

    trace_printf ("%2d: orig: '%s'\n"
                  "    real: '%s',   CRC32: 0x%08lX\n",
                  i, fn->orig_name, fn->real_name,
                  DWORD_CAST(fn->crc32));
  }
}

static void fname_cache_free_one (void *e)
{
  struct file_name_entry *fn = (struct file_name_entry*) e;

  free (fn->real_name);
  free (fn);
}

static void fname_cache_free (void)
{
  if (fname_list)
     smartlist_wipe (fname_list, fname_cache_free_one);
  fname_list = NULL;
}

/**
 * Only used by the `TRACE()` macro in `common.h`.
 */
void debug_printf (const char *file, unsigned line, const char *fmt, ...)
{
  int     save1, save2;
  va_list args;

  /* Since 'g_cfg.trace_raw = 0' below, ensure colorised messages from 'WSTRACE()'
   * cannot interrupt this piece of code (we'd then get colours here).
   * Thus make this a critical region.
   */
  ENTER_CRIT();

  save1 = g_cfg.trace_raw;
  save2 = g_cfg.trace_indent;
  g_cfg.trace_raw    = 1;
  g_cfg.trace_indent = 0;

  if (g_cfg.show_caller && file)
     trace_printf ("%s(%u): ", basename(file), line);

  va_start (args, fmt);
  trace_vprintf (fmt, args);
  va_end (args);

  g_cfg.trace_raw    = save1;
  g_cfg.trace_indent = save2;
  LEAVE_CRIT (0);
}

/**
 * Indent a printed line to `indent` spaces.
 */
int trace_indent (size_t indent)
{
  int rc = 0;

  while (indent--)
    rc += trace_putc_raw (' ');
  return (rc);
}

/**
 * Write out the trace-buffer.
 */
size_t trace_flush (void)
{
  size_t len = trace_ptr - trace_buf;
  size_t written = len;

  assert (len <= TRACE_BUF_SIZE);

  ws_sema_wait();

  if (g_cfg.trace_use_ods)
  {
    *trace_ptr = '\0';
    OutputDebugStringA (trace_buf);
  }
  else if (g_cfg.trace_stream)
  {
    /*
     * Use 'fwrite()' (a bit slower than '_write()') so the Lua-output
     * written using 'io.write()' is in sync with our trace-output.
     */
    written = (int) fwrite (trace_buf, 1, (size_t)len, g_cfg.trace_stream);
  }
  trace_ptr = trace_buf;   /* restart buffer */

  ws_sema_release();
  return (written);
}

int trace_printf (const char *fmt, ...)
{
  char    buf [2000];
  int     l1, l2;
  va_list args;

  va_start (args, fmt);

#if 0  /* todo ? */
  l2 = vsnprintf (trace_ptr, trace_end - trace_ptr - 1, fmt, args);
  l1 = trace_puts (trace_ptr);
  trace_ptr += l2;
#else
  l2 = vsnprintf (buf, sizeof(buf)-1, fmt, args);
  l1 = trace_puts (buf);
#endif

  if (l1 < l2)
    FATAL ("l1: %d, l2: %d. trace_buf: '%.*s',\nbuf: '%s'\n",
           l1, l2, (int)(trace_ptr - trace_buf), trace_buf, buf);

  va_end (args);
  return (l2);
}

int trace_vprintf (const char *fmt, va_list args)
{
  char buf [2000];
  int  l1, l2 = vsnprintf (buf, sizeof(buf)-1, fmt, args);

  l1 = trace_puts (buf);
  if (l1 < l2)
    FATAL ("l1: %d, l2: %d. trace_buf: '%.*s',\nbuf: '%s'\n",
           l1, l2, (int)(trace_ptr - trace_buf), trace_buf, buf);

  return (l2);
}

int trace_putc (int ch)
{
  int rc = 0;

  if (!trace_ptr || !trace_end)
     return (0);

  assert (trace_ptr >= trace_buf);
  assert (trace_ptr < trace_end-1);

  if (tilde_escape && trace_get_color && !g_cfg.trace_raw)
  {
    const WORD *color;
    int         col_idx;

    trace_get_color = FALSE;

    /* If we got "~~", print a single "~"
    */
    if (ch == '~')
       goto put_it;

    col_idx = ch - '0';
    switch (col_idx)
    {
      case 0:
           color = NULL;     /* restore to default colour */
           break;
      case 1:
           color = &g_cfg.color_trace;
           break;
      case 2:
           color = &g_cfg.color_file;
           break;
      case 3:
           color = &g_cfg.color_time;
           break;
      case 4:
           color = &g_cfg.color_data;
           break;
      case 5:
           color = &g_cfg.color_func;
           break;
      case 8:
           color = &g_cfg.LUA.color_head;
           break;
      case 9:
           color = &g_cfg.LUA.color_body;
           break;
      default:
#if defined(_DEBUG) || defined(__NO_INLINE__)
          /*
           * Some strangness with 'gcc -O0' or 'cl -MDd'
           */
           if (ch == ' ')
              return (1);
#endif
           trace_flush();
           FATAL ("Illegal color index %d ('%c'/0x%02X) in trace_buf: '%.*s'\n",
                  col_idx, ch, ch, (int)(trace_ptr - trace_buf), trace_buf);
           break;
    }

    if (!g_cfg.trace_use_ods)
    {
      trace_flush();
      set_color (color);
    }
    return (1);
  }

  if (tilde_escape && ch == '~' && !g_cfg.trace_raw)
  {
    trace_get_color = TRUE;
    return (1);
  }

  if (ch == '\n' && (g_cfg.trace_binmode || g_cfg.trace_use_ods))
  {
    if ((trace_ptr == trace_buf) ||
        (trace_ptr > trace_buf && trace_ptr[-1] != '\r'))
    {
      *trace_ptr++ = '\r';
      rc++;
    }
  }

put_it:
  *trace_ptr++ = ch;
  rc++;

  if (ch == '\n' || trace_ptr >= trace_end)
     trace_flush();
  return (rc);
}

int trace_putc_raw (int ch)
{
  int  rc;
  BOOL save = tilde_escape;

  tilde_escape = FALSE;
  rc = trace_putc (ch);
  tilde_escape = save;
  return (rc);
}

int trace_puts_raw (const char *str)
{
  int  rc;
  BOOL save = tilde_escape;

  tilde_escape = FALSE;
  rc = trace_puts (str);
  tilde_escape = save;
  return (rc);
}

int trace_puts (const char *str)
{
  int ch, rc = 0;

  for (rc = 0; (ch = *str) != '\0'; str++)
      rc += trace_putc (ch);
  return (rc);
}

/**
 * Save and restore the `g_cfg.trace_level` value: \n
 *   pop = 0: set it to 0. \n
 *   pop = 1: restore the global value.
 *
 * Used e.g. when firewall.c calls `getservbyport()` to prevent a `WSTRACE()` for it.
 */
int trace_level_save_restore (int pop)
{
  static int val = 0;

  if (pop == 0)
  {
    val = g_cfg.trace_level;
    g_cfg.trace_level = 0;
  }
  else
    g_cfg.trace_level = val;
  return (val);
}

/**
 * Open an existing file (or create) in share-mode but deny other
 * processes to write to the file.
 *
 * CygWin does not have `_sopen()`. Simply call `fopen()`.
 */
FILE *fopen_excl (const char *file, const char *mode)
{
#if defined(__CYGWIN__)
  return fopen (file, mode);
#else
  int fd, open_flags, share_flags;

  switch (*mode)
  {
    case 'r':
          open_flags  = _O_RDONLY;
          share_flags = S_IREAD;
          break;
    case 'w':
          open_flags  = _O_WRONLY;
          share_flags = S_IWRITE;
          break;
    case 'a':
          open_flags  = _O_CREAT | _O_WRONLY | _O_APPEND;
          share_flags = S_IWRITE;
          break;
    default:
          return (NULL);
  }

  if (mode[1] == '+')
     open_flags |= _O_CREAT | _O_TRUNC;

  if (mode[strlen(mode)-1] == 'b')
     open_flags |= O_BINARY;

#ifdef _O_SEQUENTIAL
  open_flags |= _O_SEQUENTIAL;
#endif

  fd = _sopen (file, open_flags, SH_DENYWR, share_flags);
  if (fd <= -1)
     return (NULL);
  return fdopen (fd, mode);
#endif  /* __CYGWIN__ */
}

/**
 * Return nicely formatted string `"xx,xxx,xxx"`
 * with thousand separators (left adjusted).
 *
 * Use 8 buffers in round-robin.
 */
int use_win_locale = 0;

const char *qword_str (unsigned __int64 val)
{
  static char buf[8][30];
  static int  idx = 0;
  char   tmp[30];
  char  *rc = buf [idx++];

#if defined(_MSC_VER)
  if (use_win_locale)
  {
    char buf2[30];

    if (_ui64toa_s (val, buf2, sizeof(buf2), 10) == 0 &&
        GetNumberFormat (LOCALE_USER_DEFAULT, 0, buf2, NULL, rc, sizeof(buf[0])))
    {
      idx &= 7;
      return str_ltrim (rc);
    }
  }
#endif

  if (val < U64_SUFFIX(1000))
  {
    sprintf (rc, "%lu", (u_long)val);
  }
  else if (val < U64_SUFFIX(1000000))       /* < 1E6 */
  {
    sprintf (rc, "%lu,%03lu", (u_long)(val/1000UL), (u_long)(val % 1000UL));
  }
  else if (val < U64_SUFFIX(1000000000))    /* < 1E9 */
  {
    sprintf (tmp, "%9" U64_FMT, val);
    sprintf (rc, "%.3s,%.3s,%.3s", tmp, tmp+3, tmp+6);
  }
  else if (val < U64_SUFFIX(1000000000000)) /* < 1E12 */
  {
    sprintf (tmp, "%12" U64_FMT, val);
    sprintf (rc, "%.3s,%.3s,%.3s,%.3s", tmp, tmp+3, tmp+6, tmp+9);
  }
  else                                      /* >= 1E12 */
  {
    sprintf (tmp, "%15" U64_FMT, val);
    sprintf (rc, "%.3s,%.3s,%.3s,%.3s,%.3s", tmp, tmp+3, tmp+6, tmp+9, tmp+12);
  }
  idx &= 7;
  return str_ltrim (rc);
}

const char *dword_str (DWORD val)
{
  return qword_str ((uint64)val);
}

/**
 * Similar to `strncpy()`, but always returns `dst` with 0-termination.
 */
char *_strlcpy (char *dst, const char *src, size_t len)
{
  assert (dst != NULL);
  assert (src != NULL);
  assert (len > 0);

  if (strlen(src) < len)
  {
    strcpy (dst, src);
    return (dst);
  }
  memcpy (dst, src, len);
  dst [len-1] = '\0';
  return (dst);
}

/**
 * Return a string with `ch` repeated `num` times. \n
 * Limited to 200 characters.
 */
char *_strrepeat (int ch, size_t num)
{
  static char buf [200];
  char  *p = buf;
  size_t i;

  *p = '\0';
  for (i = 0; i < num && i < sizeof(buf)-1; i++)
     *p++ = ch;
  *p = '\0';
  return (buf);
}

/**
 * A `strtok_r()` function taken from libcurl:
 *
 * Copyright (C) 1998 - 2007, Daniel Stenberg, <daniel@haxx.se>, et al.
  */
char *_strtok_r (char *ptr, const char *sep, char **end)
{
  if (!ptr)
  {
    /* we got NULL input so then we get our last position instead */
    ptr = *end;
  }

  /* pass all letters that are including in the separator string */
  while (*ptr && strchr(sep, *ptr))
    ++ptr;

  if (*ptr)
  {
    /* so this is where the next piece of string starts */
    char *start = ptr;

    /* set the end pointer to the first byte after the start */
    *end = start + 1;

    /* scan through the string to find where it ends, it ends on a
     * null byte or a character that exists in the separator string.
     */
    while (**end && !strchr(sep, **end))
      ++*end;

    if (**end)
    {
      /* the end is not a null byte */
      **end = '\0';  /* zero terminate it! */
      ++*end;        /* advance the last pointer to beyond the null byte */
    }
    return (start);  /* return the position where the string starts */
  }
  /* we ended up on a null byte, there are no more strings to find! */
  return (NULL);
}

/**
 * Reverse string `str` in place.
 */
char *_strreverse (char *str)
{
  int i, j;

  for (i = 0, j = (int)strlen(str)-1; i < j; i++, j--)
  {
    char c = str[i];
    str[i] = str[j];
    str[j] = c;
  }
  return (str);
}

/*
 * According to:
 *  http://msdn.microsoft.com/en-us/library/windows/desktop/ms683188(v=vs.85).aspx
 */
#define MAX_ENV_VAR 32767

/**
 * Returns the expanded version of an environment variable.
 * This function also works for env-vars inside a variable.
 * E.g. it will expand: \n
 *   variable = `"%TEMP%\foo"` into `"c:\temp\foo"`.
 *
 * The expanded result is copied into user supplied `buf`. \n
 * If expansion fails, it will return `variable` unchanged into `buf`.
 */
char *getenv_expand (const char *variable, char *buf, size_t size)
{
  char *rc, *env = NULL, *orig_var = (char*) variable;
  char  buf1 [MAX_ENV_VAR], buf2 [MAX_ENV_VAR];
  DWORD ret;

  /* Don't use getenv(); it doesn't find variable added after program was
   * started. Don't accept truncated results (i.e. rc >= sizeof(buf1)).
   */
  ret = GetEnvironmentVariable (variable, buf1, sizeof(buf1));
  if (ret > 0 && ret < sizeof(buf1))
  {
    env = buf1;
    variable = buf1;
  }
  if (strchr(variable, '%'))
  {
    /* buf2 == variable if not expanded.
     */
    ret = ExpandEnvironmentStrings (variable, buf2, sizeof(buf2));
    if (ret > 0 && ret < sizeof(buf2) &&
        !strchr(buf2, '%'))    /* no variables still un-expanded */
      env = buf2;
  }

  rc = env ? _strlcpy(buf, env, size) : orig_var;
  TRACE (3, "env: '%s', expanded: '%s'\n", orig_var, rc);
  return (rc);
}

int _ws_setenv (const char *env, const char *val, int overwrite)
{
#if defined(__CYGWIN__)
  int rc = setenv (env,  val, overwrite);

  TRACE (3, "getenv(env): '%s'.\n", getenv(env));
  return (rc);

#else
  size_t len, i = 0;
  char *e, value [_MAX_PATH] = { "?" };

  if (strchr(env, '='))
  {
    errno = EINVAL;
    return (-1);
  }

  for (e = _environ[i]; e; e = _environ[++i])
  {
    len = strchr (e, '=') - e;
    TRACE (3, "e: '%s'.\n", e);
    if (!strnicmp(env, e, len))
       break;
  }

  if (!e)
  {
    snprintf (value, sizeof(value), "%s=%s", env, val);
    e = strdup (value);
    if (!e)
    {
      errno = ENOMEM;
      return (-1);
    }
    _environ[i++] = e;
    _environ[i] = NULL;
  }
  else if (overwrite)
  {
    snprintf (value, sizeof(value), "%s=%s", env, val);
    e = strdup (value);
    if (!e)
    {
      errno = ENOMEM;
      return (-1);
    }

    /* Some crash-issue on MinGW-w64 (x64) with this 'free()'.
     */
#if !(defined(__MINGW64_VERSION_MAJOR) && IS_WIN64)
    free (_environ[i]);
#endif
    _environ[i] = e;
  }

  SetEnvironmentVariable (env, e);

  TRACE (3, "getenv(env): '%s'.\n", getenv(env));
  return (0);
#endif  /* __CYGWIN__ */
}

/*
 * These CRC functions are derived from code in chapter 19 of the book
 * "C Programmer's Guide to Serial Communications", by Joe Campbell.
 */
#define CRC_BITS    32
#define CRC_HIBIT   ((DWORD) (1L << (CRC_BITS-1)))
#define CRC_SHIFTS  (CRC_BITS-8)

/* Our PRZ's 24-bit CRC generator polynomial. Ref:
 *   http://en.wikipedia.org/wiki/Cyclic_redundancy_check
 *   Section "Commonly used and standardized CRCs"
 */
#define CRC_PRZ  0x864CFBL

/* Pre-generated table for speeding up CRC calculations.
 */
static DWORD crc_table [256 * sizeof(DWORD)] = { '\0' };

/*
 * mk_crctbl() derives a CRC lookup table from the CRC polynomial.
 * The table is used later by crc_bytes() below.
 * mk_crctbl() only needs to be called once at the dawn of time.
 *
 * The theory behind mk_crctbl() is that table[i] is initialized
 * with the CRC of i, and this is related to the CRC of `i >> 1',
 * so the CRC of `i >> 1' (pointed to by p) can be used to derive
 * the CRC of i (pointed to by q).
 */
static void mk_crctbl (DWORD poly, DWORD *tab)
{
  DWORD *p = tab;
  DWORD *q = tab;
  int    i;

  *q++ = 0;
  *q++ = poly;
  for (i = 1; i < 128; i++)
  {
    DWORD t = *(++p);

    if (t & CRC_HIBIT)
    {
      t <<= 1;
      *q++ = t ^ poly;
      *q++ = t;
    }
    else
    {
      t <<= 1;
      *q++ = t;
      *q++ = t ^ poly;
    }
  }
}

/*
 * Calculate 32-bit CRC on buffer 'buf' with length 'len'.
 */
static DWORD crc_bytes (const char *buf, size_t len)
{
  DWORD accum;

  if (!crc_table[0])
     mk_crctbl (CRC_PRZ, crc_table);

  for (accum = 0; len > 0; len--)
      accum = (accum << 8) ^ crc_table[(BYTE)(accum >> CRC_SHIFTS) ^ *buf++];
  return (accum);
}

/**
 * Simple check for file-existence.
 *
 * Using `access()` for CygWin in case the file is on a
 * Posix `"/usr/bin/foo"` form. But try `GetFileAttributes()`
 * also in case it's on Windows form (but that would match a directory
 * too).
 */
int file_exists (const char *fname)
{
  DWORD attr = GetFileAttributes (fname);

  return (attr != INVALID_FILE_ATTRIBUTES || access(fname,0) == 0);
}

/**
 * Include the resource-file. This is the only place (besides the makefiles)
 * where the basenames for `wsock_trace*.dll` is set. We use these here to
 * return those short-names and also the fully qualified names when known at
 * runtime.
 *
 * The .lua-scripts needs this information to know which .DLL (or .EXE) to
 * integrate with. If called from 'ws_tool.c', the `full_name` is `ws_tool.exe`.
 * Hopefully LUA will be able to import from that.
 *
 * Some of these functions are also called from `geoip.c`.
 */
#include "wsock_trace.rc"

static char full_name [_MAX_PATH];

const char *set_dll_full_name (HINSTANCE inst_dll)
{
  if (!full_name[0])  /* prevent re-entry from the same .dll */
     GetModuleFileName (inst_dll, full_name, sizeof(full_name));
  return (full_name);
}

/**
 * Returns the full name of our `.dll` (or `.exe`).
 */
const char *get_dll_full_name (void)
{
  if (full_name[0] == '\0')
     return (NULL);
  return (full_name);
}

/**
 * Returns the `.dll` basename.
 *
 * \retval
 *   "wsock_trace.dll"          for 32-bit Visual-C / clang-cl
 *   "wsock_trace_x64.dll"      for 64-bit Visual-C / clang-cl
 *   "wsock_trace_mw.dll"       for 32-bit MinGW
 *   "wsock_trace_mw_x64.dll"   for 64-bit MinGW
 *   "wsock_trace_cyg.dll"      for 32-bit CygWin
 *   "wsock_trace_cyg_x64.dll"  for 64-bit CygWin
 *
 * And an extra `"_d"` (before `".dll"`) for a CRT-DEBUG version.
 *
 * When the code in "wsock_trace*.dll" is loaded via a program,
 * return that program's shortname.
 */
const char *get_dll_short_name (void)
{
  return (RC_BASENAME RC_CPU_SUFFIX RC_DBG_SUFFIX ".dll");
}

const char *get_dll_build_date (void)
{
  return (__DATE__);
}

/**
 * Returns e.g. "Visual-C, 32-bit"
 */
const char *get_builder (BOOL show_dbg_rel)
{
#if defined(_M_X64) || defined(__x86_64__)
  /*
   * Do this since a '-DBITNESS=64' could be missing from makefiles
   */
  const char *platform = "x64";
#else
  const char *platform = RC_BITNESS; /* from 'wsock_trace.rc' included above */
#endif

#if defined(_DEBUG) || defined(__NO_INLINE__)
  const char *dbg_rel = "debug";
#else
  const char *dbg_rel = "release";
#endif

  static char buf[100];

  if (show_dbg_rel)
       snprintf (buf, sizeof(buf), "%s (%s, %s)", RC_BUILDER, platform, dbg_rel);
  else snprintf (buf, sizeof(buf), "%s (%s)", RC_BUILDER, platform);
  return (buf);
}

