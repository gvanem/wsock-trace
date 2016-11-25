#ifndef _COMMON_H
#define _COMMON_H

/*
 * Because I had problems exporting "__WSAFDIsSet@8" to wsock_trace.dll,
 * I was forced to use a .def-file to export all functions.
 */
#if defined(USE_DEF_FILE)
  #define EXPORT
#else
  #define EXPORT  __declspec(dllexport)
#endif

#if defined(IN_WSOCK_TRACE_C) && (defined(UNICODE) || defined(_UNICODE))
  #error "Compiling this as UNICODE breaks in countless ways."
#endif

/*
 * OpenWatcom has no #ifdef around it's WINSOCK_API_LINKAGE.
 * Hence we cannot export stuff in it's <winsock2.h>. So just
 * don't include it.
 */
#if defined(IN_WSOCK_TRACE_C) && defined(__WATCOMC__)
  #define _WINSOCK2API_
  #define _WS2IPDEF_
  #define _WS2TCPIP_H_
  #define SOCKET  UINT_PTR
  #define WSAAPI  PASCAL

  #include <windows.h>
  #include <inaddr.h>
  #include <in6addr.h>

  #define WSAEVENT                HANDLE
  #define GROUP                   unsigned int
  #define WSAPROTOCOL_INFOA       struct { GUID ProviderId; } /* fake; not important in wsock_trace.c */
  #define WSAPROTOCOL_INFOW       struct { GUID ProviderId; } /* Ditto */
  #define WSAOVERLAPPED           void                        /* Ditto */
  #define WSANETWORKEVENTS        void                        /* Ditto */
  #define AF_INET                 2
  #define AF_INET6                23
  #define MSG_PEEK                0x00000002L
  #define INVALID_SOCKET          0xFFFFFFFF
  #define SOCKET_ERROR            (-1)

  #define WSA_WAIT_FAILED         WAIT_FAILED
  #define WSA_WAIT_IO_COMPLETION  WAIT_IO_COMPLETION
  #define WSA_WAIT_TIMEOUT        WAIT_TIMEOUT
  #define WSA_WAIT_EVENT_0        WAIT_OBJECT_0
  #define WSA_INFINITE            INFINITE

  typedef unsigned short          u_short;
  typedef unsigned long           u_long;
  typedef int                     socklen_t;

  #include <ws2def.h>  /* needs 'u_short' */

  typedef struct fd_set {
          unsigned fd_count;
          SOCKET   fd_array [64];
        } fd_set;

  typedef struct WSADATA {
          WORD            wVersion;
          WORD            wHighVersion;
          char            szDescription [256 + 1];
          char            szSystemStatus [128 + 1];
          unsigned short  iMaxSockets;
          unsigned short  iMaxUdpDg;
          char           *lpVendorInfo;
        } WSADATA, *LPWSADATA;

  typedef struct sockaddr_in6 {
          short           sin6_family;
          USHORT          sin6_port;
          ULONG           sin6_flowinfo;
          IN6_ADDR        sin6_addr;
          union {
            ULONG         sin6_scope_id;
            SCOPE_ID      sin6_scope_struct;
          };
       } SOCKADDR_IN6;

  struct timeval {
         long   tv_sec;
         long   tv_usec;
       };

  struct hostent {
         char   *h_name;
         char  **h_aliases;
         short   h_addrtype;
         short   h_length;
         char  **h_addr_list;
       };

  /* Quality of Service */
  #include <qos.h>

  typedef struct _QualityOfService {
          FLOWSPEC    SendingFlowspec;
          FLOWSPEC    ReceivingFlowspec;
          WSABUF      ProviderSpecific;
        } QOS;

  typedef void (__stdcall *LPWSAOVERLAPPED_COMPLETION_ROUTINE) (DWORD, DWORD, void*, DWORD);

#elif !defined(__WATCOMC__)
  #define WINSOCK_API_LINKAGE  EXPORT
#endif

#include <stdio.h>
#include <malloc.h>
#include <io.h>
#include <time.h>
#include <string.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <objbase.h>

#if defined(__MINGW32__)
  #include <specstrings.h>
#endif

#if defined(_MSC_VER) && defined(_DEBUG)  /* use CrtDebug in MSVC debug-mode */
  #define _CRTDBG_MAP_ALLOC
  #undef _malloca                         /* Avoid MSVC-9 <malloc.h>/<crtdbg.h> name-clash */
  #include <crtdbg.h>
#endif

extern int raw__WSAFDIsSet (SOCKET s, fd_set *fd);

#if defined(__GNUC__)
  #define ATTR_PRINTF(_1,_2)   __attribute__((format(printf,_1,_2)))
#else
  #define ATTR_PRINTF(_1,_2)   /* nothing */
#endif

#if defined(__GNUC__) && defined(__MINGW32__)
  #define WCHAR_FMT      "S"
  #define S64_FMT        "I64d"
  #define U64_FMT        "I64u"
  #define X64_FMT        "I64X"
  #define S64_SUFFIX(x)  (x##LL)
  #define U64_SUFFIX(x)  (x##ULL)

#elif defined(_MSC_VER) || defined(_MSC_EXTENSIONS) || defined(__WATCOMC__)
  #define WCHAR_FMT      "ws"
  #define S64_FMT        "I64d"
  #define U64_FMT        "I64u"
  #define X64_FMT        "I64X"
  #define S64_SUFFIX(x)  (x##i64)
  #define U64_SUFFIX(x)  (x##Ui64)

#else
  #if defined(__CYGWIN__)
    #define WCHAR_FMT    "S"
  #else
    #define WCHAR_FMT    "ws"
  #endif
  #define S64_FMT        "Ld"
  #define U64_FMT        "Lu"
  #define X64_FMT        "Lx"
  #define S64_SUFFIX(x)  (x##LL)
  #define U64_SUFFIX(x)  (x##ULL)
#endif


/*
 * Printing an hex linear address.
 * Printing a decimal value from the address-bus (e.g. a stack-limit)
 * E.g. printf (buf, "0x%"ADDR_FMT, ADDR_CAST(ptr));
 */
#if defined(WIN64) || defined(_WIN64)
  #if defined(_MSC_VER) ||   /* MSVC/WIN64 little untested */ \
      defined(__GNUC__)      /* MinGW64 normally */
    #define ADDR_FMT     "016I64X"
    #define ADDR_CAST(x) ((uint64)(x))
  #else
    #error Help me!
  #endif

  /*
   * A 'SOCKET' is defined as 'unsigned long long' on Win64.
   * But we hardly ever need to print all bits. Just cast to
   * silence MinGW-w64.
   */
  #define SOCKET_CAST(s)  ((unsigned int)(s))
#else    /* WIN32 */
  #define ADDR_FMT        "08lX"
  #define ADDR_CAST(x)    ((DWORD_PTR)(x))   /* "cl -Wp64" warns here. Ignore it. */
  #define SOCKET_CAST(s)  s
#endif

#if defined(__CYGWIN__)
  #include <sys/stat.h>

  static inline int FILE_EXISTS (const char *f)
  {
    struct stat st;
    return (stat(f,&st) == 0);
  }
#else
  static __inline int FILE_EXISTS (const char *f)
  {
    return (GetFileAttributes(f) != INVALID_FILE_ATTRIBUTES);
  }
#endif

#define loBYTE(w)       (BYTE)(w)
#define hiBYTE(w)       (BYTE)((WORD)(w) >> 8)
#define DIM(x)          (int) (sizeof(x) / sizeof((x)[0]))
#define SIZEOF(x)       (int) sizeof(x)
#define ARGSUSED(foo)   (void)foo

#if defined(_MSC_VER)
  #ifndef _CRTDBG_MAP_ALLOC
  #define strdup       _strdup
  #endif

  #define strnicmp    _strnicmp
  #define stricmp     _stricmp
  #define snprintf    _snprintf
  #define vsnprintf   _vsnprintf
  #define fdopen      _fdopen
  #define tzset()     _tzset()
  #define isatty(fd)  _isatty (fd)
  #define fileno(f)   _fileno (f)

#elif defined(__MINGW32__)
  /*
   * I want the MSVC version of vsnprintf() since there is some trouble
   * with MinGW's version in trace_printf(). No idea what.
   */
  #define vsnprintf _vsnprintf
#endif

#if !defined(_WIN32_WINNT) || (_WIN32_WINNT < 0x0600) || !defined(POLLRDNORM)
  /*
   * Ripped from MS's <winsock2.h>:
   */
  #define POLLERR     0x0001
  #define POLLHUP     0x0002
  #define POLLNVAL    0x0004

  #define POLLWRNORM  0x0010
  #define POLLOUT     POLLWRNORM
  #define POLLWRBAND  0x0020

  #define POLLRDNORM  0x0100
  #define POLLRDBAND  0x0200
  #define POLLIN      (POLLRDNORM | POLLRDBAND)
  #define POLLPRI     0x0400

  typedef struct pollfd {
          SOCKET  fd;
          SHORT   events;
          SHORT   revents;
        } WSAPOLLFD, *LPWSAPOLLFD;
#endif


/*
 * Generic debug and trace macro. Print to 'g_cfg.trace_stream' (default 'stdout')
 * if 'g_cfg.trace_level' is above or equal 'level'.
 *
 * Do not confuse this with the 'WSTRACE()' macro in wsock_trace.c.
 * The 'TRACE()'   macro shows what wsock_trace.dll is doing.
 * The 'WSTRACE()' macro shows what the *user* of wsock_trace.dll is doing.
 *
 */
#define TRACE(level, fmt, ...)                                     \
                           do {                                    \
                             if (g_cfg.trace_level >= level)       \
                               debug_printf (__FILE__, __LINE__,   \
                                             fmt, ## __VA_ARGS__); \
                           } while (0)

#define WARNING(fmt, ...)  do {                                     \
                             fprintf (stderr, fmt, ## __VA_ARGS__); \
                           } while (0)

#define FATAL(fmt, ...)    do {                                        \
                             fprintf (stderr, "\n%s(%u): " fmt,        \
                                      __FILE__, __LINE__,              \
                                      ## __VA_ARGS__);                 \
                             fatal_error = 1;                          \
                             if (IsDebuggerPresent())                  \
                                  abort();                             \
                             else ExitProcess (GetCurrentProcessId()); \
                           } while (0)

/*
 * Defined in newer <sal.h> for MSVC.
 */
#ifndef _Printf_format_string_
#define _Printf_format_string_
#endif

extern void debug_printf (const char *file, unsigned line,
                          _Printf_format_string_ const char *fmt, ...) ATTR_PRINTF (3,4);

extern int trace_binmode;

extern int trace_printf  (_Printf_format_string_ const char *fmt, ...) ATTR_PRINTF (1,2);
extern int trace_vprintf (const char *fmt, va_list args);
extern int trace_puts    (const char *str);
extern int trace_putc    (int ch);
extern int trace_putc_raw(int ch);
extern int trace_indent  (int indent);
extern int trace_flush   (void);

/* Init/exit functions for stuff in common.c.
 */
extern void common_init (void);
extern void common_exit (void);


/* Generic search-list type.
 */
struct search_list {
       unsigned    value;
       const char *name;
     };

/* Search-list type for WSA-Errors.
 */
struct WSAE_search_list {
       DWORD       err;
       const char *short_name;
       const char *full_name;
     };

/* Search-list type for GUIDs.
 */
struct GUID_search_list {
       GUID        guid;
       const char *name;
     };

/* Generic table for loading DLLs and functions from them.
 */
struct LoadTable {
       const BOOL  optional;
       HINSTANCE   mod_handle;
       const char *mod_name;
       const char *func_name;
       void      **func_addr;
     };

extern int load_dynamic_table   (struct LoadTable *tab, int tab_size);
extern int unload_dynamic_table (struct LoadTable *tab, int tab_size);

extern struct LoadTable *find_dynamic_table (struct LoadTable *tab, int tab_size,
                                             const char *func_name);
extern char        curr_dir  [MAX_PATH];
extern char        curr_prog [MAX_PATH];
extern char        prog_dir  [MAX_PATH];
extern HINSTANCE   ws_trace_base;        /* Our base-address */

extern char       *ws_strerror (DWORD err, char *buf, size_t len);
extern char       *win_strerror (DWORD err);
extern char       *basename (const char *fname);
extern char       *dirname (const char *fname);
extern char       *str_replace (int ch1, int ch2, char *str);
extern const char *shorten_path (const char *path);
extern const char *list_lookup_name (unsigned value, const struct search_list *list, int num);
extern unsigned    list_lookup_value (const char *name, const struct search_list *list, int num);
extern const char *flags_decode (DWORD flags, const struct search_list *list, int num);
extern int         list_lookup_check (const struct search_list *list, int num, int *idx1, int *idx2);

extern const char *str_hex_byte (BYTE val);
extern const char *str_hex_word (WORD val);
extern const char *str_hex_dword (DWORD val);

extern unsigned long  swap32 (DWORD val);
extern unsigned short swap16 (WORD val);

extern const char    *get_guid_string (const GUID *guid);
extern const char    *dword_str (DWORD val);
extern const char    *qword_str (unsigned __int64 val);

extern char * _strlcpy (char *dst, const char *src, size_t len);
extern char * _strtok_r (char *ptr, const char *sep, char **end);
extern char * getenv_expand (const char *variable, char *buf, size_t size);
extern FILE * fopen_excl (const char *file, const char *mode);

#if defined(__CYGWIN__)
  extern char *_itoa (int value, char *buf, int radix);

  #define stricmp(s1, s2)      strcasecmp (s1, s2)
  #define strnicmp(s1, s2, n)  strncasecmp (s1, s2, n)
#endif

#endif  /* _COMMON_H */
