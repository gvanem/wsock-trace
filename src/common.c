/* basename() and dirname():
 *   Copyright (C) 1998 DJ Delorie, see COPYING.DJ for details
 *   Copyright (C) 1997 DJ Delorie, see COPYING.DJ for details
 */

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <limits.h>
#include <ctype.h>
#include <windows.h>
#include <fcntl.h>
#include <sys/stat.h>

#if !defined(__CYGWIN__)
  #include <share.h>
#endif

#include "common.h"
#include "init.h"
#include "dump.h"

/* Missing in Open-Watcom's <winsock2.h>.
 */
#ifndef WSA_QOS_EUNKOWNPSOBJ
#define WSA_QOS_EUNKOWNPSOBJ  (WSABASEERR + 1024)
#endif

char curr_dir  [MAX_PATH] = { '\0' };
char curr_prog [MAX_PATH] = { '\0' };
char prog_dir  [MAX_PATH] = { '\0' };

HINSTANCE ws_trace_base;        /* Our base-address */

int trace_binmode = 0;

/*
 * A cache of file-names with true casing as returned from
 * 'GetLongPathName()'. Use a 32-bit CRC value to lookup an
 * entry in fname_cache_get().
 */
struct file_name_entry {
       char                   *orig_name;
       char                   *real_name;
       DWORD                   crc32;
       struct file_name_entry *next;
     };

static struct file_name_entry *fname_list0 = NULL;

static const char *fname_cache_get (const char *fname);
static const char *fname_cache_add (const char *fname);
static void        fname_cache_free (void);
static void        fname_cache_dump (void);

static void  crc_init  (void);
static void  crc_exit (void);
static DWORD crc_bytes (const char *buf, size_t len);

#define TRACE_BUF_SIZE (2*1024)

static char *trace_ptr, *trace_end;
static char *trace_buf = NULL;

static BOOL tilde_escape = TRUE;

void common_init (void)
{
  trace_buf = malloc (TRACE_BUF_SIZE);
  trace_ptr = trace_buf;
  trace_end = trace_ptr + TRACE_BUF_SIZE - 1;
  crc_init();
}

void common_exit (void)
{
  crc_exit();
  fname_cache_free();

  free (trace_buf);
  trace_buf = trace_ptr = trace_end = NULL;
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
};

/*
 * todo: do a qsort() of 'err_list' (make a copy). And use bsearch() to lookup 'err'.
 */
char *ws_strerror (DWORD err, char *buf, size_t len)
{
  const struct WSAE_search_list *el = err_list;
  size_t i;

  for (i = 0; i < DIM(err_list); i++, el++)
      if (err == el->err)
      {
        if (g_cfg.short_errors)
             snprintf (buf, len, "%s (%lu)", el->short_name, err);
        else snprintf (buf, len, "%s: %s (%lu)", el->short_name, el->full_name, err);
        return (buf);
      }
  snprintf (buf, len, "Unknown error: %lu", err);
  return (buf);
}

/*
 * Handling of dynamic loading and unloading of DLLs and their functions.
 */
int load_dynamic_table (struct LoadTable *tab, int tab_size)
{
  int i;

  for (i = 0; i < tab_size; tab++, i++)
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

      if (!tab->optional)
      {
        if (!func_addr)
           TRACE (2, "Function \"%s\" not found in %s.\n", tab->func_name, tab->mod_name);
      }
      *tab->func_addr = func_addr;
    }
    is_opt = (tab->optional ? " (optional)" : "");
    tab->mod_handle = mod_handle;

    TRACE (4, "%2d: Module 0x%" ADDR_FMT "/%s, func \"%s\" -> 0x%" ADDR_FMT "%s.\n", i,
              ADDR_CAST(tab->mod_handle), tab->mod_name, tab->func_name,
              ADDR_CAST(*tab->func_addr), is_opt);
  }
  return (i);
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

struct LoadTable *find_dynamic_table (struct LoadTable *tab, int tab_size, const char *func_name)
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
#endif

/*
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
  return _itoa (value,buf,10);
}

/*
 * Search 'list' for 'name' and return it's 'value'.
 */
unsigned list_lookup_value (const char *name, const struct search_list *list, int num)
{
  while (num > 0 && list->name)
  {
    if (!stricmp(name,list->name))
       return (list->value);
    num--;
    list++;
  }
  return (UINT_MAX);
}

const char *flags_decode (DWORD flags, const struct search_list *list, int num)
{
  static char buf[300];
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
     ret += snprintf (ret, left, "0x%08lX|", flags);
  if (ret > buf)
     *(--ret) = '\0';   /* remove '|' */
  return (buf);
}

/*
 * Traverse 'list' and check that all values are unique and no 'value'
 * (except the last) is UINT_MAX.
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
unsigned long swap32 (DWORD val)
{
  return ((val & 0x000000FFU) << 24) |
         ((val & 0x0000FF00U) <<  8) |
         ((val & 0x00FF0000U) >>  8) |
         ((val & 0xFF000000U) >> 24);
}

/**
 * Convert 16-bit big-endian (network order) to host order format.
 */
unsigned short swap16 (WORD val)
{
  return ((val & 0x00FF) << 8) | ((val & 0xFF00) >> 8);
}

/*
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

/*
 * Return the malloc'ed directory part of a filename.
 */
char *dirname (const char *fname)
{
  const char *p  = fname;
  const char *slash = NULL;

  if (fname)
  {
    size_t dirlen;
    char  *dirpart;

    if (*fname && fname[1] == ':')
    {
      slash = fname + 1;
      p += 2;
    }

    /* Find the rightmost slash.  */
    while (*p)
    {
      if (*p == '/' || *p == '\\')
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
      /* Remove any trailing slashes.  */
      while (slash > fname && (slash[-1] == '/' || slash[-1] == '\\'))
          slash--;

      /* How long is the directory we will return?  */
      dirlen = slash - fname + (slash == fname || slash[-1] == ':');
      if (*slash == ':' && dirlen == 1)
         dirlen += 2;
    }

    dirpart = malloc (dirlen + 1);
    if (dirpart)
    {
      strncpy (dirpart, fname, dirlen);
      if (slash && *slash == ':' && dirlen == 3)
         dirpart[2] = '.';      /* for "x:foo" return "x:." */
      dirpart[dirlen] = '\0';
    }
    return (dirpart);
  }
  return (NULL);
}

static const char *get_guid_ole32_str (const GUID *guid)
{
  static char result [40];
  wchar_t     str [40];
  DWORD       len;

  strcpy (result, "{??}");
  if (StringFromGUID2(guid, (LPOLESTR)&str, DIM(str)-1))
  {
    len = WideCharToMultiByte (CP_ACP, 0, str, -1, result, sizeof(result), NULL, NULL);
    if (len == 0)
       strcpy (result, "{??}");
  }
  return (result);
}

static const char hex_chars[] = "0123456789ABCDEF";

static const char *get_guid_internal_str (const GUID *guid)
{
  static char result [40];
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
  return (result);
}

/*
 * Return a 'char' string for the given GUID.
 * Use OLE32.DLL or do it ourself.
 */
const char *get_guid_string (const GUID *guid)
{
  if (g_cfg.use_ole32)
     return get_guid_ole32_str (guid);
  return get_guid_internal_str (guid);
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

/*
 * Replace 'ch1' with 'ch2' in string 'str'.
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

/*
 * Return the left-trimmed place where paths 'p1' and 'p2' are similar.
 * Not case sensitive. Treats '/' and '\\' equally.
 */
#define IS_SLASH(c)  ((c) == '\\' || (c) == '/')
#define TOUPPER(c)   toupper ((int)(c))

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

/*
 * This function is called from StackWalkShow() to return a
 * short version of 'Line.FileName'. I.e. a file-name relative to
 * the path of the calling program.
 *
 * Note: The SymGetLineFromAddr64() function always seems to
 *       return 'Line.FileName' in lower-case.
 */
const char *shorten_path (const char *path)
{
  const char *real_name = fname_cache_get (path);
  size_t      len       = strlen (prog_dir);

  if (!real_name)
  {
    real_name = fname_cache_add (path);
    if (!real_name)
       return (path);
  }

  if (!g_cfg.use_full_path && len >= 3 && !strnicmp(prog_dir,path,len))
     return (real_name + len);
  return (real_name);
}

static const char *fname_cache_get (const char *fname)
{
  const struct file_name_entry *fe;
  DWORD crc32 = crc_bytes (fname, strlen(fname));

  for (fe = fname_list0; fe; fe = fe->next)
  {
    if (crc32 == fe->crc32)
       return (fe->real_name ? fe->real_name : fe->orig_name);
  }
  return (NULL);
}

/*
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
       fn->real_name = str_replace ('\\', '/', strdup(buf));
  else fn->real_name = NULL;

  fn->next    = fname_list0;
  fname_list0 = fn;
  return (fn->real_name ? fn->real_name : fn->orig_name);
}

static void fname_cache_dump (void)
{
  const struct file_name_entry *fn;
  int   i;

  for (i = 0, fn = fname_list0; fn; fn = fn->next, i++)
  {
    trace_printf ("%2d: orig: '%s'\n"
                  "    real: '%s',   CRC32: 0x%08lX\n",
                  i, fn->orig_name, fn->real_name, fn->crc32);
  }
}

static void fname_cache_free (void)
{
  struct file_name_entry *fn, *next;

  if (g_cfg.trace_level >= 5)
     fname_cache_dump();

  for (fn = fname_list0; fn; fn = next)
  {
    if (fn->real_name)
       free (fn->real_name);
    next = fn->next;
    free (fn);
  }
}

/*
 * Only used by the TRACE() macro in common.h.
 */
void debug_printf (const char *file, unsigned line, const char *fmt, ...)
{
  int     save = g_cfg.test_trace;
  va_list args;

  g_cfg.test_trace = 1;
  trace_indent (g_cfg.trace_indent);

  if (g_cfg.show_caller && file)
     trace_printf ("%s(%u): ", basename(file), line);

  va_start (args, fmt);
  trace_vprintf (fmt, args);
  g_cfg.test_trace = save;
  va_end (args);
}

/*
 * Indent a printed line to 'indent' spaces.
 */
int trace_indent (int indent)
{
  int rc = 0;

  while (indent--)
    rc += trace_putc (' ');
  return (rc);
}

/*
 * Write out the trace-buffer.
 */
int trace_flush (void)
{
  int len = trace_ptr - trace_buf;

  if (g_cfg.trace_use_ods)
  {
    *trace_ptr = '\0';
    OutputDebugStringA (trace_buf);
  }
  else
  {
#if defined(USE_LUA)
    /*
     * Use 'fwrite()' (a bit slower?) so the Lua-output
     * written using 'io.write()' is in sync with our trace-output.
     */
    fwrite (trace_buf, (size_t)len, 1, g_cfg.trace_stream);
#else
    int hnd = _fileno (g_cfg.trace_stream);

    assert (hnd >= 1);
    _write (hnd, trace_buf, (unsigned int)len);
#endif
  }
  trace_ptr = trace_buf;   /* restart buffer */
  return (len);
}

int trace_printf (const char *fmt, ...)
{
  char    buf [500];
  int     l1, l2;
  va_list args;

  va_start (args, fmt);
  l2 = vsnprintf (buf, sizeof(buf), fmt, args);
  l1 = trace_puts (buf);

  if (l1 < l2)
    FATAL ("l1: %d, l2: %d. trace_buf: '%.*s',\nbuf: '%s'\n",
           l1, l2, (int)(trace_ptr - trace_buf), trace_buf, buf);

  va_end (args);
  return (l2);
}

int trace_vprintf (const char *fmt, va_list args)
{
  char buf [500];
  int  l1, l2 = vsnprintf (buf, sizeof(buf), fmt, args);

  l1 = trace_puts (buf);
  if (l1 < l2)
    FATAL ("l1: %d, l2: %d. trace_buf: '%.*s',\nbuf: '%s'\n",
           l1, l2, (int)(trace_ptr - trace_buf), trace_buf, buf);

  return (l2);
}

int trace_putc (int ch)
{
  static BOOL get_color = FALSE;
  int    rc = 0;

  assert (trace_ptr);
  assert (trace_end);
  assert (trace_ptr >= trace_buf);
  assert (trace_ptr < trace_end-1);

  if (tilde_escape && get_color && !g_cfg.test_trace)
  {
    const WORD *color;

    get_color = FALSE;
    if (ch == '~')
       goto put_it;

    switch (ch - '0')
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
#if defined(__MINGW32__) && 1
      case -16:
      case -38:
           ch = '!';
           goto put_it;
#endif
      default:
           FATAL ("Illegal color index %d ('%c'/0x%02X) in trace_buf: '%.*s'\n",
                  ch - '0', ch, ch, (int)(trace_ptr - trace_buf), trace_buf);
           break;
    }
    trace_flush();
    set_color (color);
    return (1);
  }

  if (tilde_escape && ch == '~' && !g_cfg.test_trace)
  {
    get_color = TRUE;
    return (1);
  }

  if (ch == '\n' && (trace_binmode || g_cfg.trace_use_ods))
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
  BOOL save = tilde_escape;
  int  rc;

  tilde_escape = FALSE;
  rc = trace_putc (ch);
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
 * Open an existing file (or create) in share-mode but deny other
 * processes to write to the file. On Watcom, fopen() already seems to
 * open with SH_DENYWR internally.
 */
FILE *fopen_excl (const char *file, const char *mode)
{
#if !defined(__WATCOMC__) && !defined(__CYGWIN__)
  int fd, flags = _O_CREAT | _O_WRONLY;

#ifdef _O_SEQUENTIAL
  flags |= _O_SEQUENTIAL;
#endif

  if (*mode == 'a')
       flags |= _O_APPEND;
  else flags |= _O_TRUNC;

  if (mode[strlen(mode)-1] == 'b')
     flags |= O_BINARY;

  fd = _sopen (file, flags, SH_DENYWR, S_IREAD | S_IWRITE);
  if (fd <= -1)
     return (NULL);
  return fdopen (fd, mode);

#else
  return fopen (file, mode);
#endif
}

/**
 * Return nicely formatted string "xx,xxx,xxx"
 * with thousand separators (left adjusted).
 */
const char *qword_str (unsigned __int64 val)
{
  static char buf [30];
  char   tmp [30], *p;
  int    i, j, len = snprintf (tmp, sizeof(tmp), "%" U64_FMT, val);

  p = buf + len;
  *p-- = '\0';

  for (i = len, j = -1; i >= 0; i--, j++)
  {
    if (j > 0 && (j % 3) == 0)
      *p-- = ',';
    *p-- = tmp[i];
  }
  return (p+1);
}

const char *dword_str (DWORD val)
{
  return qword_str ((uint64)val);
}

/*
 * Similar to strncpy(), but always returns 'dst' with 0-termination.
 */
char *_strlcpy (char *dst, const char *src, size_t len)
{
  assert (dst != NULL);
  assert (src != NULL);
  assert (len > 0);

  if (strlen(src) < len)
     return strcpy (dst, src);

  memcpy (dst, src, len);
  dst [len-1] = '\0';
  return (dst);
}

/*
 * According to:
 *  http://msdn.microsoft.com/en-us/library/windows/desktop/ms683188(v=vs.85).aspx
 */
#define MAX_ENV_VAR 32767

/*
 * Returns the expanded version of an environment variable.
 * This function also works for env-vars inside a variable.
 * E.g. it will expand:
 *   variable = "%TEMP%\foo" into "c:\temp\foo".
 *
 * The expanded result is copied into user supplied 'buf'.
 * If expansion fails, it will return 'variable' unchanged into 'buf'.
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
  if (strchr(variable,'%'))
  {
    /* buf2 == variable if not expanded.
     */
    ret = ExpandEnvironmentStrings (variable, buf2, sizeof(buf2));
    if (ret > 0 && ret < sizeof(buf2) &&
        !strchr(buf2,'%'))    /* no variables still un-expanded */
      env = buf2;
  }

  rc = env ? _strlcpy(buf,env,size) : orig_var;
  TRACE (3, "env: '%s', expanded: '%s'\n", orig_var, rc);
  return (rc);
}

/*
 *  These CRC functions are derived from code in chapter 19 of the book
 *  "C Programmer's Guide to Serial Communications", by Joe Campbell.
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
static DWORD *crc_table = NULL;

/*
 * mk_crctbl() derives a CRC lookup table from the CRC polynomial.
 * The table is used later by crc_bytes() below.
 * mk_crctbl() only needs to be called once at the dawn of time.
 * I.e. in crc_init().
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

  assert (crc_table);

  for (accum = 0; len > 0; len--)
      accum = (accum << 8) ^ crc_table[(BYTE)(accum >> CRC_SHIFTS) ^ *buf++];
  return (accum);
}

static void crc_init (void)
{
  crc_table = calloc (sizeof(DWORD), 256);
  if (!crc_table)
     FATAL ("Failed to generated CRC-table.\n");

  mk_crctbl (CRC_PRZ, crc_table);
}

static void crc_exit (void)
{
  if (crc_table)
     free (crc_table);
  crc_table = NULL;
}

