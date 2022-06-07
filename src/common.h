/**\file    common.h
 * \ingroup Main
 */
#ifndef _COMMON_H
#define _COMMON_H

#include "wsock_defs.h"

/*
 * Because I had problems exporting "__WSAFDIsSet@8" to wsock_trace.dll,
 * I was forced to use a .def-file to export all functions.
 */
#if defined(USE_DEF_FILE)
  #define EXPORT
#else
  #define EXPORT  __declspec(dllexport)
#endif

#ifdef _MSC_VER
  #define NO_INLINE     __declspec(noinline)
  #define THREAD_LOCAL  __declspec(thread)
#else
  #define NO_INLINE     __attribute__((noinline))
  #define THREAD_LOCAL  __thread
#endif

#if defined(IN_WSOCK_TRACE_C) && (defined(UNICODE) || defined(_UNICODE))
  #error "Compiling this as UNICODE breaks in countless ways."
#endif

#undef  WINSOCK_API_LINKAGE
#define WINSOCK_API_LINKAGE  EXPORT

#include <winsock2.h>
#include <ws2tcpip.h>
#include <objbase.h>

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

#define FATAL(fmt, ...)    do {                                         \
                             fprintf (stderr, "\nFatal error: %s(%u): " \
                                      fmt, __FILE__, __LINE__,          \
                                      ## __VA_ARGS__);                  \
                             fatal_error = 1;                           \
                             if (IsDebuggerPresent())                   \
                                  abort();                              \
                             else ExitProcess (GetCurrentProcessId());  \
                           } while (0)

extern void debug_printf (const char *file, unsigned line,
                          _Printf_format_string_ const char *fmt, ...) ATTR_PRINTF (3,4);

extern int    C_printf   (_Printf_format_string_ const char *fmt, ...)          ATTR_PRINTF (1,2);
extern int    C_vprintf  (_Printf_format_string_ const char *fmt, va_list args) ATTR_PRINTF (1,0);
extern int    C_puts     (const char *str);
extern int    C_puts_raw (const char *str);
extern int    C_putc     (int ch);
extern int    C_putc_raw (int ch);
extern int    C_indent   (size_t indent);
extern size_t C_flush    (void);
extern int    C_level_save_restore (int pop);

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

extern const struct LoadTable *find_dynamic_table (const struct LoadTable *tab, int tab_size,
                                                   const char *func_name);
extern char        curr_dir  [MAX_PATH];
extern char        curr_prog [MAX_PATH];
extern char        prog_dir  [MAX_PATH];
extern HINSTANCE   ws_trace_base;        /* Our base-address */

/* For getopt.c
 */
extern char *program_name;
extern char *set_program_name (const char *argv0);

extern void (__stdcall *g_WSASetLastError) (int err);
extern int  (__stdcall *g_WSAGetLastError) (void);

extern char       *ws_strerror (DWORD err, char *buf, size_t len);
extern char       *win_strerror (DWORD err);
extern char       *basename (const char *fname);
extern char       *dirname (const char *fname);
extern char       *fix_path (const char *path);
extern char       *fix_drive (char *path);
extern char       *copy_path (char *out_path, const char *in_path, char use);
extern const char *get_path (const char    *apath,
                             const wchar_t *wpath,
                             BOOL          *exist,
                             BOOL          *is_native);

extern const char *shorten_path (const char *path);
extern const char *list_lookup_name (unsigned value, const struct search_list *list, int num);
extern unsigned    list_lookup_value (const char *name, const struct search_list *list, int num);
extern const char *flags_decode (DWORD flags, const struct search_list *list, int num);
extern int         list_lookup_check (const struct search_list *list, int num, int *idx1, int *idx2);
extern DWORD       swap32 (DWORD val);
extern WORD        swap16 (WORD val);

extern char       *str_replace (int ch1, int ch2, char *str);
extern const char *str_hex_byte (BYTE val);
extern const char *str_hex_word (WORD val);
extern const char *str_hex_dword (DWORD val);
extern char       *str_rip  (char *s);
extern wchar_t    *str_ripw (wchar_t *s);
extern char       *str_ltrim (char *s);

extern const char *get_guid_string (const GUID *guid);
extern const char *get_guid_path_string (const GUID *guid);
extern const char *dword_str (DWORD val);
extern const char *qword_str (unsigned __int64 val);

extern char       *_strlcpy (char *dst, const char *src, size_t len);
extern char       *_strndup (const char *str, size_t max);
extern size_t      _strnlen (const char *s, size_t maxlen);
extern char       *_strtok_r (char *ptr, const char *sep, char **end);
extern char       *_strrepeat (int ch, size_t num);
extern char       *_strreverse (char *str);
extern char       *_utoa10w (int value, int width, char *buf);
extern char       *getenv_expand (const char *variable, char *buf, size_t size);
extern int         ws_setenv (const char *env, const char *val, int overwrite);
extern FILE       *fopen_excl (const char *file, const char *mode);
extern int         file_exists (const char *fname);

extern const char *get_dll_full_name (void);
extern const char *set_dll_full_name (HINSTANCE inst_dll);
extern const char *get_dll_short_name (void);
extern const char *get_dll_build_date (void);
extern const char *get_builder (BOOL show_dbg_rel);

extern void sock_list_add (SOCKET sock, int family, int type, int protocol);
extern void sock_list_remove (SOCKET sock);
extern int  sock_list_type (SOCKET sock, int *family, int *protocol);

#if defined(__CYGWIN__)
  extern char *_itoa (int value, char *buf, int radix);
  extern char *_ultoa (unsigned long value, char *buf, int radix);
  extern int   _kbhit (void);
  extern int   _getch (void);
#else
  /*
   * fnmatch() for non-Cygwin:
   */
  #define FNM_NOMATCH   1
  #define FNM_NOESCAPE  0x01
  #define FNM_PATHNAME  0x02
  #define FNM_CASEFOLD  0x04

  extern int fnmatch (const char *pattern, const char *string, int flags);
#endif

/*
 * For decoding 'WSAIoctl (sock, SIO_TCP_INFO, ...)':
 *
 * The more advanced 'TCP_INFO_v1' structure seems only to be valid for WinHTTP:
 *   https://docs.microsoft.com/en-us/windows/win32/winhttp/option-flags
 */
typedef struct local_TCP_INFO_v0 {
        uint32_t   State;       /* TCPSTATE_CLOSED=0, ... TCPSTATE_TIME_WAIT=10 */
        uint32_t   Mss;
        uint64_t   ConnectionTimeMs;
        uint8_t    TimestampsEnabled;
        uint32_t   RttUs;
        uint32_t   MinRttUs;
        uint32_t   BytesInFlight;
        uint32_t   Cwnd;
        uint32_t   SndWnd;
        uint32_t   RcvWnd;
        uint32_t   RcvBuf;
        uint64_t   BytesOut;
        uint64_t   BytesIn;
        uint32_t   BytesReordered;
        uint32_t   BytesRetrans;
        uint32_t   FastRetrans;
        uint32_t   DupAcksIn;
        uint32_t   TimeoutEpisodes;
        uint8_t    SynRetrans;
      } local_TCP_INFO_v0;

/*
 * Type-defined in the SDK `<shared/mstcpip.h>` as `TCP_INFO_v1` when
 * `NTDDI_VERSION >= NTDDI_WIN10_RS5`. Hence keep a private typedef here.
 *
 * Besides it's only usable on Win-10, Build 20348 or later.
 * Ref: https://docs.microsoft.com/en-us/windows/win32/api/mstcpip/ns-mstcpip-tcp_info_v1#requirements
 */
typedef struct local_TCP_INFO_v1 {
        uint32_t   State;
        uint32_t   Mss;
        uint64_t   ConnectionTimeMs;
        uint8_t    TimestampsEnabled;
        uint32_t   RttUs;
        uint32_t   MinRttUs;
        uint32_t   BytesInFlight;
        uint32_t   Cwnd;
        uint32_t   SndWnd;
        uint32_t   RcvWnd;
        uint32_t   RcvBuf;
        uint64_t   BytesOut;
        uint64_t   BytesIn;
        uint32_t   BytesReordered;
        uint32_t   BytesRetrans;
        uint32_t   FastRetrans;
        uint32_t   DupAcksIn;
        uint32_t   TimeoutEpisodes;
        uint8_t    SynRetrans;
        uint32_t   SndLimTransRwin;
        uint32_t   SndLimTimeRwin;
        uint64_t   SndLimBytesRwin;
        uint32_t   SndLimTransCwnd;
        uint32_t   SndLimTimeCwnd;
        uint64_t   SndLimBytesCwnd;
        uint32_t   SndLimTransSnd;
        uint32_t   SndLimTimeSnd;
        uint64_t   SndLimBytesSnd;
      } local_TCP_INFO_v1;

#define TCP_INFO_v0  local_TCP_INFO_v0
#define TCP_INFO_v1  local_TCP_INFO_v1

/**
 * \struct local_ICMP_ERROR_INFO
 * This is in `<ws2ipdef.h>` on recent SDK's.
 */
typedef struct local_ICMP_ERROR_INFO {
        union {
          struct sockaddr_in  Ipv4;
          struct sockaddr_in6 Ipv6;
          uint16_t            si_family;
        } srcaddress;
        int      protocol;
        uint8_t  type;
        uint8_t  code;
      } local_ICMP_ERROR_INFO;

#define ICMP_ERROR_INFO local_ICMP_ERROR_INFO

/**
 * \struct local_sockaddr_un
 * This is in `<afunix.h>` on recent SDK's.
 */
struct local_sockaddr_un {
       short sun_family;       /* AF_UNIX */
       char  sun_path [108];   /* pathname */
     };

#define sockaddr_un local_sockaddr_un

#ifndef AF_UNIX
#define AF_UNIX 1
#endif

#ifndef SIO_TCP_INFO
#define SIO_TCP_INFO   0xD8000027   /* == _WSAIORW (IOC_VENDOR, 39) */
#endif

#ifndef TCP_ICMP_ERROR_INFO
#define TCP_ICMP_ERROR_INFO 19
#endif

#endif  /* _COMMON_H */
