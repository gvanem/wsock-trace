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

  #define WSAEVENT           HANDLE
  #define GROUP              unsigned int
  #define WSAPROTOCOL_INFOA  void    /* Not important in wsock_trace.c */
  #define WSAOVERLAPPED      void    /* Ditto */
  #define WSAPROTOCOL_INFOW  void    /* Ditto */
  #define WSANETWORKEVENTS   void    /* Ditto */
  #define AF_INET            2
  #define AF_INET6           23
  #define MSG_PEEK           0x00000002L
  #define INVALID_SOCKET     0xFFFFFFFF
  #define SOCKET_ERROR       (-1)

  typedef unsigned short     u_short;
  typedef unsigned long      u_long;
  typedef int                socklen_t;

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

  typedef struct WSABUF {
          ULONG   len;
          CHAR    *buf;
        } WSABUF, *LPWSABUF;

  typedef struct {
          union {
            struct {
              ULONG Zone  : 28;
              ULONG Level : 4;
            };
            ULONG   Value;
          };
        } SCOPE_ID;

  typedef struct sockaddr {
          u_short  sa_family;
          CHAR     sa_data[14];
        } SOCKADDR;

  typedef struct sockaddr_in {
          short           sin_family;
          USHORT          sin_port;
          IN_ADDR         sin_addr;
          CHAR            sin_zero[8];
        } SOCKADDR_IN;

  typedef struct sockaddr_in6 {
          short  sin6_family;
          USHORT          sin6_port;
          ULONG           sin6_flowinfo;
          IN6_ADDR        sin6_addr;
          union {
            ULONG       sin6_scope_id;
            SCOPE_ID    sin6_scope_struct;
          };
       } SOCKADDR_IN6;

  struct timeval {
         long   tv_sec;
         long   tv_usec;
       };

  typedef void (__stdcall *LPWSAOVERLAPPED_COMPLETION_ROUTINE) (DWORD, DWORD, void*, DWORD);

#elif !defined(__WATCOMC__)
  #define WINSOCK_API_LINKAGE  EXPORT
#endif

#include <stdio.h>
#include <malloc.h>
#include <io.h>
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
  #define U64_SUFFIX(x)  (x##ULL)

#elif defined(_MSC_VER) || defined(_MSC_EXTENSIONS) || defined(__WATCOMC__)
  #define WCHAR_FMT      "ws"
  #define S64_FMT        "I64d"
  #define U64_FMT        "I64u"
  #define X64_FMT        "I64X"
  #define U64_SUFFIX(x)  (x##Ui64)

#else
  #define WCHAR_FMT      "ws"
  #define S64_FMT        "Ld"
  #define U64_FMT        "Lu"
  #define X64_FMT        "Lx"
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
  #define FILE_EXISTS(f)  (chmod(f,0) == -1 ? 0 : 1)
#else
  #if 0
    #define FILE_EXISTS(f)  (_access(f,0) == 0)
  #else
    static __inline int FILE_EXISTS (const char *f)
    {
      return (GetFileAttributes(f) != INVALID_FILE_ATTRIBUTES);
    }
  #endif

#endif

#define loBYTE(w)       (BYTE)(w)
#define hiBYTE(w)       (BYTE)((WORD)(w) >> 8)
#define DIM(x)          (int) (sizeof(x) / sizeof((x)[0]))
#define SIZEOF(x)       (int) sizeof(x)
#define ARGSUSED(foo)   (void)foo

#if defined(_MSC_VER)
  #ifndef _CRTDBG_MAP_ALLOC
  #define strdup    _strdup
  #endif

  #define strnicmp  _strnicmp
  #define stricmp   _stricmp
  #define snprintf  _snprintf
  #define vsnprintf _vsnprintf
  #define fdopen    _fdopen

#elif defined(__MINGW32__)
  /*
   * I want the MSVC version of vsnprintf() since there is some trouble
   * with MingW's version in trace_printf(). No idea what.
   */
  #define vsnprintf _vsnprintf
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
#define TRACE(level, fmt, ...)  do {                                    \
                                  if (g_cfg.trace_level >= level)       \
                                    debug_printf (__FILE__, __LINE__,   \
                                                  fmt, ## __VA_ARGS__); \
                                } while (0)
#if defined(__WATCOMC__)
  #define WCTRACE(fmt, ...)     do {                                 \
                                  debug_printf (__FILE__, __LINE__,  \
                                                "Watcom: " fmt "\n", \
                                                ## __VA_ARGS__);     \
                                } while (0)
#else
  #define WCTRACE(fmt, ...)     /* nothing */
#endif

#define WARNING(fmt, ...)  do {                                       \
                             trace_printf (fmt "\7", ## __VA_ARGS__); \
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


extern void debug_printf (const char *file, unsigned line, const char *fmt, ...) ATTR_PRINTF (3,4);

extern int trace_binmode;

extern int trace_printf  (const char *fmt, ...) ATTR_PRINTF (1,2);
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
extern char * getenv_expand (const char *variable, char *buf, size_t size);
extern FILE * fopen_excl (const char *file, const char *mode);

#if defined(__CYGWIN__)
  extern char *_itoa (int value, char *buf, int radix);
#endif

#endif  /* _COMMON_H */
