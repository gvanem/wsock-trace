/*
 * A small and simple drop-in tracer for most normal Winsock calls.
 * Works best for MSVC since the stack-walking code requires the program's
 * PDB symbol-file to be present. And unfortunately MingW/CygWin doesn't
 * produce PDB-symbols.
 *
 * Usage (MSVC):
 *   link with wsock_trace.lib instead of the system's ws32_2.lib. Thus
 *   most normal Winsock calls are traced on entry and exit.
 *
 * Usage (MingW/CygWin):
 *   link with libwsock_trace.a instead of the system's libws32_2.a.
 *   I.e. copy it to a directory in $(LIBRARY_PATH) and use '-lwsock_trace'
 *   to link. The Makefile.MingW already does the copying to $(MINGW32)/lib.
 *
 * Ignore warnings like:
 *   foo.obj : warning LNK4049: locally defined symbol _closesocket@4
 *             imported in bar().
 */

#define IN_WSOCK_TRACE_C

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <assert.h>
#include <limits.h>
#include <ctype.h>
#include <math.h>

#include "common.h"
#include "bfd_gcc.h"
#include "in_addr.h"
#include "init.h"
#include "dump.h"
#include "wsock_trace.h"

#if !defined(NO_STACK_WALK)
  #include "stkwalk.h"
#endif

#if defined(__MINGW64__)
#endif

/* Keep track of number of calls to WSAStartup() and WSACleanup().
 */
int volatile cleaned_up = 0;
int volatile startup_count = 0;

static BOOL exclude_this = FALSE;

static const char *get_caller (ULONG_PTR ret_addr, ULONG_PTR ebp);
static const char *get_timestamp (void);

#ifdef USE_BFD
  static void test_get_caller (const void *from);
#endif

#if defined(WIN64) || defined(_WIN64)
  #define SOCK_RC_TYPE SOCKET
#else
  #define SOCK_RC_TYPE unsigned
#endif


/*
 * All 'p_function' pointers below are checked before use with this
 * macro. 'init_ptr()' makes sure 'wsock_trace_init()' is called once
 * and 'p_function' is not NULL.
*/
#if defined(USE_DETOURS)
  #define INIT_PTR(ptr) /* */
#else
  #define INIT_PTR(ptr) init_ptr ((const void**)&ptr, #ptr)
#endif

#if defined(__MINGW_GNUC_PREREQ)
  #if __MINGW_GNUC_PREREQ(4, 4) && 0
    #define NO_WARN_FORMAT()                 \
           _Pragma ("GCC diagnostic push"); \
           _Pragma ("GCC diagnostic ignored -Wformat")
    #define POP_WARN_FORMAT() \
            _Pragma ("GCC diagnostic pop")
  #endif
#endif

#ifndef NO_WARN_FORMAT
#define NO_WARN_FORMAT()   ((void)0)
#endif

#ifndef POP_WARN_FORMAT
#define POP_WARN_FORMAT()  ((void)0)
#endif


/*
 * A WSTRACE() macro for the WinSock calls we support.
 * This macro is used like 'WSTRACE ("WSAStartup (%u.%u) --> %s.\n", args).'
 *
 * If "g_cfg.trace_caller == 0" or "WSAStartup" is in the
 * "g_cfg.exclude_list[]", the '!exclude_list_get("WSAStartup...")'
 * returns FALSE.
 */
#define WSTRACE(fmt, ...)                                  \
  do {                                                     \
    exclude_this = TRUE;                                   \
    if (g_cfg.trace_level > 0 && !exclude_list_get(fmt)) { \
       exclude_this = FALSE;                               \
       wstrace_printf (TRUE, "~1* ~3%s~5%s: ~1",           \
                       get_timestamp(),                    \
                       get_caller (GET_RET_ADDR(),         \
                                   get_EBP()) );           \
       NO_WARN_FORMAT();                                   \
       wstrace_printf (FALSE, fmt "~0", ## __VA_ARGS__);   \
       POP_WARN_FORMAT();                                  \
    }                                                      \
  } while (0)


#if defined(__GNUC__)
  #define GET_RET_ADDR()  (ULONG_PTR)__builtin_return_address (0)
#else
  #define GET_RET_ADDR()  0
#endif

#if defined(_MSC_VER) && defined(_X86_)
  __declspec(naked) static ULONG_PTR get_EBP (void)
  {
    __asm mov eax, ebp
    __asm ret
  }

#elif defined(_MSC_VER) && defined(_M_X64)
  static __inline ULONG_PTR get_EBP (void)
  {
    return (0); /* to-do */
  }

#elif defined(__WATCOMC__)
  extern ULONG_PTR get_EBP (void);
  #pragma aux  get_EBP = \
          "mov eax, ebp" \
          modify [eax];

#elif defined(__GNUC__)
  extern __inline__ ULONG_PTR get_EBP (void)
  {
    ULONG_PTR ebp;
    __asm__ __volatile__ ("movl %%ebp,%k0" : "=r" (ebp) : );
    return (ebp);
  }
#else
  #error "Unsupported compiler."
#endif


static fd_set *last_rd_fd = NULL;
static fd_set *last_wr_fd = NULL;
static fd_set *last_ex_fd = NULL;

static void wstrace_printf (BOOL first_line, const char *fmt, ...) ATTR_PRINTF (2,3);

typedef SOCKET  (WINAPI *func_socket) (int family, int type, int protocol);
typedef SOCKET  (WINAPI *func_accept) (SOCKET s, struct sockaddr *addr, int *addr_len);
typedef int     (WINAPI *func_bind) (SOCKET s, const struct sockaddr *addr, int addr_len);
typedef int     (WINAPI *func_shutdown) (SOCKET s, int how);
typedef int     (WINAPI *func_closesocket) (SOCKET s);
typedef int     (WINAPI *func_connect) (SOCKET s, const struct sockaddr *addr, int addr_len);
typedef int     (WINAPI *func_ioctlsocket) (SOCKET s, long opt, u_long *arg);
typedef int     (WINAPI *func_select) (int nfds, fd_set *rd_fd, fd_set *wr_fd, fd_set *ex_fd, const struct timeval *timeout);
typedef int     (WINAPI *func_listen) (SOCKET s, int backlog);
typedef int     (WINAPI *func_recv) (SOCKET s, char *buf, int buf_len, int flags);
typedef int     (WINAPI *func_recvfrom) (SOCKET s, char *buf, int buf_len, int flags, struct sockaddr *from, int *from_len);
typedef int     (WINAPI *func_send) (SOCKET s, const char *buf, int buf_len, int flags);
typedef int     (WINAPI *func_sendto) (SOCKET s, const char *buf, int buf_len, int flags, const struct sockaddr *to, int to_len);
typedef int     (WINAPI *func_setsockopt) (SOCKET s, int level, int opt, const char *opt_val, int opt_len);
typedef int     (WINAPI *func_getsockopt) (SOCKET s, int level, int opt, char *opt_val, int *opt_len);
typedef int     (WINAPI *func_gethostname) (char *buf, int buf_len);
typedef int     (WINAPI *func_getpeername) (SOCKET s, struct sockaddr *name, int *namelen);
typedef int     (WINAPI *func_getsockname) (SOCKET s, struct sockaddr *name, int *namelen);
typedef u_short (WINAPI *func_htons) (u_short x);
typedef u_short (WINAPI *func_ntohs) (u_short x);
typedef u_long  (WINAPI *func_htonl) (u_long x);
typedef u_long  (WINAPI *func_ntohl) (u_long x);
typedef u_long  (WINAPI *func_inet_addr) (const char *addr);
typedef char *  (WINAPI *func_inet_ntoa) (struct in_addr addr);

typedef struct servent  *(WINAPI *func_getservbyport) (int port, const char *proto);
typedef struct servent  *(WINAPI *func_getservbyname) (const char *serv, const char *proto);
typedef struct hostent  *(WINAPI *func_gethostbyname) (const char *name);
typedef struct hostent  *(WINAPI *func_gethostbyaddr) (const char *addr, int len, int type);
typedef struct protoent *(WINAPI *func_getprotobynumber) (int num);
typedef struct protoent *(WINAPI *func_getprotobyname) (const char *name);

typedef int (WINAPI *func_getnameinfo) (const struct sockaddr *sa, socklen_t sa_len,
                                        char *buf, DWORD buf_size, char *serv_buf,
                                        DWORD serv_buf_size, int flags);

typedef int (WINAPI *func_getaddrinfo) (const char *host_name, const char *serv_name,
                                        const struct addrinfo *hints, struct addrinfo **res);

typedef void (WINAPI *func_freeaddrinfo) (struct addrinfo *ai);

typedef char *    (WINAPI *func_gai_strerrorA) (int err);
typedef wchar_t * (WINAPI *func_gai_strerrorW) (int err);

typedef int  (WINAPI *func_WSAStartup) (WORD version, LPWSADATA data);
typedef int  (WINAPI *func_WSACleanup) (void);
typedef int  (WINAPI *func_WSAGetLastError) (void);
typedef void (WINAPI *func_WSASetLastError) (int err);
typedef int  (WINAPI *func_WSAIoctl) (SOCKET s, DWORD code, VOID *vals, DWORD size_in,
                                      VOID *out_buf, DWORD out_size, DWORD *size_ret,
                                      WSAOVERLAPPED *ov, LPWSAOVERLAPPED_COMPLETION_ROUTINE func);

typedef WSAEVENT (WINAPI *func_WSACreateEvent) (void);
typedef BOOL     (WINAPI *func_WSACloseEvent) (WSAEVENT);
typedef BOOL     (WINAPI *func_WSASetEvent) (WSAEVENT);
typedef BOOL     (WINAPI *func_WSAResetEvent) (WSAEVENT);
typedef int      (WINAPI *func_WSAEventSelect) (SOCKET s, WSAEVENT hnd, long net_ev);
typedef int      (WINAPI *func_WSAAsyncSelect) (SOCKET s, HWND wnd, unsigned int msg, long net_ev);

typedef int      (WINAPI *func_WSARecv) (SOCKET s, WSABUF *bufs, DWORD num_bufs, DWORD *num_bytes,
                                         DWORD *flags, WSAOVERLAPPED *ov,
                                         LPWSAOVERLAPPED_COMPLETION_ROUTINE func);


typedef int      (WINAPI *func_WSARecvFrom) (SOCKET s, WSABUF *bufs, DWORD num_bufs, DWORD *num_bytes,
                                             DWORD *flags, struct sockaddr *from, INT *from_len,
                                             WSAOVERLAPPED *ov, LPWSAOVERLAPPED_COMPLETION_ROUTINE func);

typedef int      (WINAPI *func_WSARecvDisconnect) (SOCKET s, WSABUF *disconnect_data);
typedef int      (WINAPI *func_WSARecvEx) (SOCKET s, char *buf, int buf_len, int *flags);

typedef int      (WINAPI *func_WSASend) (SOCKET s, WSABUF *bufs, DWORD num_bufs, DWORD *num_bytes,
                                         DWORD flags, WSAOVERLAPPED *ov, LPWSAOVERLAPPED_COMPLETION_ROUTINE func);

typedef int      (WINAPI *func_WSASendTo) (SOCKET s, WSABUF *bufs, DWORD num_bufs, DWORD *num_bytes,
                                           DWORD flags, const struct sockaddr *to, int to_len,
                                           WSAOVERLAPPED *ow, LPWSAOVERLAPPED_COMPLETION_ROUTINE func);

typedef int (WINAPI *func___WSAFDIsSet) (SOCKET s, fd_set *);

typedef SOCKET (WINAPI *func_WSASocketA) (int af, int type, int protocol,
                                          WSAPROTOCOL_INFOA *protocol_info,
                                          GROUP grp, DWORD dwFlags);

typedef SOCKET (WINAPI *func_WSASocketW) (int af, int type, int protocol,
                                          WSAPROTOCOL_INFOW *protocol_info,
                                          GROUP grp, DWORD dwFlags);

typedef int (WINAPI *func_WSADuplicateSocketA) (SOCKET, DWORD process_id,
                                                WSAPROTOCOL_INFOA *protocol_info);

typedef int (WINAPI *func_WSADuplicateSocketW) (SOCKET, DWORD process_id,
                                                WSAPROTOCOL_INFOW *protocol_info);

typedef INT (WINAPI *func_WSAAddressToStringA) (SOCKADDR          *address,
                                                DWORD              address_len,
                                                WSAPROTOCOL_INFOA *protocol_info,
                                                char              *result_string,
                                                DWORD             *result_string_len);

typedef INT (WINAPI *func_WSAAddressToStringW) (SOCKADDR          *address,
                                                DWORD              address_len,
                                                WSAPROTOCOL_INFOW *protocol_info,
                                                wchar_t           *result_string,
                                                DWORD             *result_string_len);

typedef BOOL (WINAPI *func_WSAGetOverlappedResult) (SOCKET s, WSAOVERLAPPED *ov, DWORD *transfered,
                                                    BOOL wait, DWORD *flags);

typedef int (WINAPI *func_WSAEnumNetworkEvents) (SOCKET s, WSAEVENT ev, WSANETWORKEVENTS *events);

typedef DWORD (WINAPI *func_WSAWaitForMultipleEvents) (DWORD           num_ev,
                                                       const WSAEVENT *ev,
                                                       BOOL            waitAll,
                                                       DWORD           timeout,
                                                       BOOL            alertable);

typedef DWORD (WINAPI *func_WaitForMultipleObjectsEx) (DWORD         num_ev,
                                                       const HANDLE *hnd,
                                                       BOOL          waitAll,
                                                       DWORD         timeout,
                                                       BOOL          alertable);

typedef int (WINAPI *func_WSACancelBlockingCall) (void);

/*
 * Windows-Vista functions.
 */
typedef INT   (WINAPI *func_inet_pton) (int family, const char *string, void *res);
typedef PCSTR (WINAPI *func_inet_ntop) (int family, void *addr, char *string, size_t string_size);

/*
 * In ntdll.dll
 */
typedef USHORT (WINAPI *func_RtlCaptureStackBackTrace) (ULONG  frames_to_skip,
                                                        ULONG  frames_to_capture,
                                                        void **frames,
                                                        ULONG *trace_hash);

/*
 * All function pointers are file global.
 */
static func_WSAStartup               p_WSAStartup = NULL;
static func_WSACleanup               p_WSACleanup = NULL;
static func_WSAGetLastError          p_WSAGetLastError = NULL;
static func_WSASetLastError          p_WSASetLastError = NULL;
static func_WSASocketA               p_WSASocketA = NULL;
static func_WSASocketW               p_WSASocketW = NULL;
static func_WSADuplicateSocketA      p_WSADuplicateSocketA = NULL;
static func_WSADuplicateSocketW      p_WSADuplicateSocketW = NULL;
static func_WSAIoctl                 p_WSAIoctl = NULL;
static func_WSACreateEvent           p_WSACreateEvent = NULL;
static func_WSASetEvent              p_WSASetEvent = NULL;
static func_WSACloseEvent            p_WSACloseEvent = NULL;
static func_WSAResetEvent            p_WSAResetEvent = NULL;
static func_WSAEventSelect           p_WSAEventSelect = NULL;
static func_WSAAsyncSelect           p_WSAAsyncSelect = NULL;
static func_WSAAddressToStringA      p_WSAAddressToStringA = NULL;
static func_WSAAddressToStringW      p_WSAAddressToStringW = NULL;
static func___WSAFDIsSet             p___WSAFDIsSet = NULL;
static func_accept                   p_accept = NULL;
static func_bind                     p_bind = NULL;
static func_closesocket              p_closesocket = NULL;
static func_connect                  p_connect = NULL;
static func_ioctlsocket              p_ioctlsocket = NULL;
static func_select                   p_select = NULL;
static func_gethostname              p_gethostname = NULL;
static func_listen                   p_listen = NULL;
static func_recv                     p_recv = NULL;
static func_recvfrom                 p_recvfrom = NULL;
static func_send                     p_send = NULL;
static func_sendto                   p_sendto = NULL;
static func_setsockopt               p_setsockopt = NULL;
static func_getsockopt               p_getsockopt = NULL;
static func_shutdown                 p_shutdown = NULL;
static func_socket                   p_socket = NULL;
static func_getservbyport            p_getservbyport = NULL;
static func_getservbyname            p_getservbyname = NULL;
static func_gethostbyname            p_gethostbyname = NULL;
static func_gethostbyaddr            p_gethostbyaddr = NULL;
static func_htons                    p_htons = NULL;
static func_ntohs                    p_ntohs = NULL;
static func_htonl                    p_htonl = NULL;
static func_ntohl                    p_ntohl = NULL;
static func_inet_addr                p_inet_addr = NULL;
static func_inet_ntoa                p_inet_ntoa = NULL;
static func_getpeername              p_getpeername = NULL;
static func_getsockname              p_getsockname = NULL;
static func_getprotobynumber         p_getprotobynumber = NULL;
static func_getprotobyname           p_getprotobyname = NULL;
static func_getnameinfo              p_getnameinfo = NULL;
static func_getaddrinfo              p_getaddrinfo = NULL;
static func_freeaddrinfo             p_freeaddrinfo = NULL;
static func_gai_strerrorA            p_gai_strerrorA = NULL;
static func_gai_strerrorW            p_gai_strerrorW = NULL;

static func_inet_pton                p_inet_pton = NULL;
static func_inet_ntop                p_inet_ntop = NULL;
static func_WSARecv                  p_WSARecv = NULL;
static func_WSARecvEx                p_WSARecvEx = NULL;
static func_WSARecvFrom              p_WSARecvFrom = NULL;
static func_WSARecvDisconnect        p_WSARecvDisconnect = NULL;
static func_WSASend                  p_WSASend = NULL;
static func_WSASendTo                p_WSASendTo = NULL;
static func_WSAGetOverlappedResult   p_WSAGetOverlappedResult = NULL;
static func_WSAEnumNetworkEvents     p_WSAEnumNetworkEvents = NULL;
static func_WSAWaitForMultipleEvents p_WSAWaitForMultipleEvents = NULL;
static func_WSACancelBlockingCall    p_WSACancelBlockingCall = NULL;
// static func_WaitForMultipleObjectsEx p_WaitForMultipleObjectsEx = NULL;

static func_RtlCaptureStackBackTrace p_RtlCaptureStackBackTrace = NULL;

#define ADD_VALUE(opt,dll,func)   { opt, NULL, dll, #func, (void**)&p_##func }

static struct LoadTable dyn_funcs [] = {
              ADD_VALUE (0, "ws2_32.dll", WSAStartup),
              ADD_VALUE (0, "ws2_32.dll", WSACleanup),
              ADD_VALUE (0, "ws2_32.dll", WSAGetLastError),
              ADD_VALUE (0, "ws2_32.dll", WSASetLastError),
              ADD_VALUE (0, "ws2_32.dll", WSASocketA),
              ADD_VALUE (0, "ws2_32.dll", WSASocketW),
              ADD_VALUE (0, "ws2_32.dll", WSAIoctl),
              ADD_VALUE (0, "ws2_32.dll", WSACreateEvent),
              ADD_VALUE (0, "ws2_32.dll", WSACloseEvent),
              ADD_VALUE (0, "ws2_32.dll", WSAResetEvent),
              ADD_VALUE (0, "ws2_32.dll", WSAEventSelect),
              ADD_VALUE (0, "ws2_32.dll", WSAAsyncSelect),
              ADD_VALUE (0, "ws2_32.dll", WSAAddressToStringA),
              ADD_VALUE (0, "ws2_32.dll", WSAAddressToStringW),
              ADD_VALUE (0, "ws2_32.dll", WSADuplicateSocketA),
              ADD_VALUE (0, "ws2_32.dll", WSADuplicateSocketW),
              ADD_VALUE (0, "ws2_32.dll", __WSAFDIsSet),
              ADD_VALUE (0, "ws2_32.dll", WSARecv),
              ADD_VALUE (0, "ws2_32.dll", WSARecvDisconnect),
              ADD_VALUE (0, "ws2_32.dll", WSARecvFrom),
              ADD_VALUE (1, "Mswsock.dll",WSARecvEx),
              ADD_VALUE (0, "ws2_32.dll", WSASend),
              ADD_VALUE (0, "ws2_32.dll", WSASendTo),
              ADD_VALUE (0, "ws2_32.dll", WSAGetOverlappedResult),
              ADD_VALUE (0, "ws2_32.dll", WSAEnumNetworkEvents),
              ADD_VALUE (0, "ws2_32.dll", WSACancelBlockingCall),
              ADD_VALUE (1, "ws2_32.dll", WSAWaitForMultipleEvents),
              ADD_VALUE (0, "ws2_32.dll", accept),
              ADD_VALUE (0, "ws2_32.dll", bind),
              ADD_VALUE (0, "ws2_32.dll", closesocket),
              ADD_VALUE (0, "ws2_32.dll", connect),
              ADD_VALUE (0, "ws2_32.dll", ioctlsocket),
              ADD_VALUE (0, "ws2_32.dll", select),
              ADD_VALUE (0, "ws2_32.dll", listen),
              ADD_VALUE (0, "ws2_32.dll", recv),
              ADD_VALUE (0, "ws2_32.dll", recvfrom),
              ADD_VALUE (0, "ws2_32.dll", send),
              ADD_VALUE (0, "ws2_32.dll", sendto),
              ADD_VALUE (0, "ws2_32.dll", setsockopt),
              ADD_VALUE (0, "ws2_32.dll", getsockopt),
              ADD_VALUE (0, "ws2_32.dll", shutdown),
              ADD_VALUE (0, "ws2_32.dll", socket),
              ADD_VALUE (0, "ws2_32.dll", getservbyport),
              ADD_VALUE (0, "ws2_32.dll", getservbyname),
              ADD_VALUE (0, "ws2_32.dll", gethostbyname),
              ADD_VALUE (0, "ws2_32.dll", gethostbyaddr),
              ADD_VALUE (0, "ws2_32.dll", gethostname),
              ADD_VALUE (0, "ws2_32.dll", htons),
              ADD_VALUE (0, "ws2_32.dll", ntohs),
              ADD_VALUE (0, "ws2_32.dll", htonl),
              ADD_VALUE (0, "ws2_32.dll", ntohl),
              ADD_VALUE (0, "ws2_32.dll", inet_addr),
              ADD_VALUE (0, "ws2_32.dll", inet_ntoa),
              ADD_VALUE (0, "ws2_32.dll", getpeername),
              ADD_VALUE (0, "ws2_32.dll", getsockname),
              ADD_VALUE (0, "ws2_32.dll", getprotobynumber),
              ADD_VALUE (0, "ws2_32.dll", getprotobyname),
              ADD_VALUE (0, "ws2_32.dll", getnameinfo),
              ADD_VALUE (0, "ws2_32.dll", getaddrinfo),
              ADD_VALUE (0, "ws2_32.dll", freeaddrinfo),
              ADD_VALUE (1, "ws2_32.dll", inet_pton),
              ADD_VALUE (1, "ws2_32.dll", inet_ntop),
              ADD_VALUE (0, "ntdll.dll",  RtlCaptureStackBackTrace),
           // ADD_VALUE (1, "kernel32.dll", WaitForMultipleObjectsEx),
#if defined(__MINGW32__)
              ADD_VALUE (1, "ws2_32.dll", gai_strerrorA),
              ADD_VALUE (1, "ws2_32.dll", gai_strerrorW),
#endif
            };

void load_ws2_funcs (void)
{
  load_dynamic_table (dyn_funcs, DIM(dyn_funcs));

  if (p_RtlCaptureStackBackTrace == NULL)
      g_cfg.trace_caller = 0;

  if (p_inet_pton == NULL)
      p_inet_pton = inet_pton;

  if (p_inet_ntop == NULL)
      p_inet_ntop = inet_ntop;
}

struct LoadTable *find_ws2_func_by_name (const char *func)
{
  return find_dynamic_table (dyn_funcs, DIM(dyn_funcs), func);
}

static void wstrace_printf (BOOL first_line, const char *fmt, ...)
{
  DWORD   err = GetLastError();   /* save error status */
  va_list args;

  va_start (args, fmt);

  if (first_line)
  {
    /* If stdout or stderr is redirected, we cannot get the cursor coloumn.
     * So just wrap if told to do so. Also add an extra newline if writing
     * to a trace-file.
     */
    BOOL add_nl = (g_cfg.start_new_line && g_cfg.trace_file_device &&
                   (get_column() > 0 || g_cfg.stdout_redirected));

    if (add_nl || g_cfg.trace_file_okay)
       trace_putc ('\n');

    trace_indent (g_cfg.trace_indent);
  }
  else if (!first_line && !g_cfg.compact)
  {
    trace_putc ('\n');
    trace_indent (g_cfg.trace_indent+2);
  }

#if 0
  if (first_line && g_cfg.trace_time_format != TS_NONE)
  {
    trace_printf ("~3* %s: ~1", get_timestamp());
    fmt += 4;  /* step over the "~1* " we're called with */
  }
#endif

  trace_vprintf (fmt, args);

  SetLastError (err);  /* restore error status */
  va_end (args);
}

static const char *get_error (SOCK_RC_TYPE rc)
{
  if (rc != 0)
  {
    /* Longest result:
     *   "WSANO_RECOVERY: Unrecoverable error in call to nameserver (11003)" = 68 chars.
     */
    static char buf[100];
    int         err = (*p_WSAGetLastError)(); /* save WSAGetLastError() */
    const char *ret = ws_strerror (err, buf, sizeof(buf));

    (*p_WSASetLastError) (err);               /* restore WSAGetLastError() */
    return (ret);
  }
  return ("No error");
}

/*
 * WSAAddressToStringA() returns the address AND the port in the 'buf'.
 * Like: 127.0.0.1:1234
 */
const char *sockaddr_str (const struct sockaddr *sa, const int *sa_len)
{
  static char buf [MAX_IP6_SZ+MAX_PORT_SZ+1];
  DWORD  size = sizeof(buf);
  DWORD  len  = sa_len ? *(DWORD*)sa_len : (DWORD)sizeof(*sa);
  int    err  = (*p_WSAGetLastError)();  /* push WSAGetLastError() */

  if ((*p_WSAAddressToStringA)((SOCKADDR*)sa, len, NULL, buf, &size))
     strcpy (buf, "??");
  (*p_WSASetLastError) (err);
  return (buf);
}

/*
 * Don't call the above 'WSAAddressToStringA()' for AF_INET/AF_INET6 addresses.
 * We do it ourself using the below sockaddr_str_port().
 */
static const char *sockaddr_str2 (const struct sockaddr *sa, const int *sa_len)
{
  char *p, *q = (char*) sockaddr_str_port (sa, sa_len);

  if (!q)
     return sockaddr_str (sa, sa_len);
#if 0
  p = strrchr (q, ':');
  if (p)
    *p = '\0';
#else
  ARGSUSED (p);
#endif
  return (q);
}

const char *sockaddr_str_port (const struct sockaddr *sa, const int *sa_len)
{
  const struct sockaddr_in  *sa4 = (const struct sockaddr_in*) sa;
  const struct sockaddr_in6 *sa6 = (const struct sockaddr_in6*) sa;
  static char buf [MAX_IP6_SZ+MAX_PORT_SZ+1];
  char       *end;

  if (!sa4)
     return ("<NULL>");

  if (sa4->sin_family == AF_INET)
  {
    snprintf (buf, sizeof(buf), "%u.%u.%u.%u:%d",
              sa4->sin_addr.S_un.S_un_b.s_b1,
              sa4->sin_addr.S_un.S_un_b.s_b2,
              sa4->sin_addr.S_un.S_un_b.s_b3,
              sa4->sin_addr.S_un.S_un_b.s_b4,
              swap16(sa4->sin_port));
    return (buf);
  }

  if (sa4->sin_family == AF_INET6)
  {
    wsock_trace_inet_ntop6 ((const u_char*)&sa6->sin6_addr, buf, sizeof(buf));
    end = strchr (buf, '\0');
    *end++ = ':';
    _itoa (swap16(sa6->sin6_port), end, 10);
    return (buf);
  }
  return (NULL);
}

static const char *inet_ntop2 (const char *addr, int family)
{
  static char buf [MAX_IP6_SZ+1];
  int    err = (*p_WSAGetLastError)(); /* push WSAGetLastError() */
  PCSTR  rc  = (*p_inet_ntop) (family, (void*)addr, buf, sizeof(buf));

  if (!rc)
     strcpy (buf, "??");
  (*p_WSASetLastError) (err);    /* pop it. */
  return (buf);
}

static __inline const char *uint_ptr_hexval (UINT_PTR val, char *buf)
{
  int i, j;

  buf[0] = '0';
  buf[1] = 'x';
  for (i = 0, j = 1+2*sizeof(val); i < 4*sizeof(val); i += 2, j--)
  {
    static const char hex_chars[] = "0123456789ABCDEF";
    unsigned idx = val % 16;

    val >>= 4;
    buf[j] = hex_chars [idx];
//  printf ("val: 0x%08lX, idx: %u, buf[%d]: %c\n", val, idx, j, buf[j]);
  }
  return (buf);
}

static const char *ptr_or_error (const void *ptr)
{
  static char buf [30];

  if (!ptr)
     return get_error (-1);

  memset (&buf, '\0', sizeof(buf));
  return uint_ptr_hexval ((UINT_PTR)ptr, buf);
}

static const char *socket_or_error (SOCK_RC_TYPE rc)
{
  static char buf [10];

  if (rc == INVALID_SOCKET || rc == SOCKET_ERROR)
     return get_error (rc);
  return _itoa ((int)rc, buf, 10);
}

/*
 * The actual Winsock functions we trace.
 */

EXPORT int WINAPI WSAStartup (WORD ver, WSADATA *data)
{
  int rc;

  INIT_PTR (p_WSAStartup);
  rc = (*p_WSAStartup) (ver, data);

  if (startup_count < INT_MAX)
     startup_count++;

  ENTER_CRIT();
  WSTRACE ("WSAStartup (%u.%u) --> %s.\n",
           loBYTE(data->wVersion), hiBYTE(data->wVersion), get_error(rc));
  LEAVE_CRIT();
  return (rc);
}

EXPORT int WINAPI WSACleanup (void)
{
  int rc;

  INIT_PTR (p_WSACleanup);
  rc = (*p_WSACleanup)();

  ENTER_CRIT();
  WSTRACE ("WSACleanup() --> %s.\n", get_error(rc));

//unload_dynamic_table (dyn_funcs, DIM(dyn_funcs));

  if (startup_count > 0)
  {
    startup_count--;
    cleaned_up = (startup_count == 0);
  }
  LEAVE_CRIT();
  return (rc);
}

EXPORT int WINAPI WSAGetLastError (void)
{
  int rc;

  INIT_PTR (p_WSAGetLastError);
  rc = (*p_WSAGetLastError)();

  ENTER_CRIT();
  WSTRACE ("WSAGetLastError() --> %s.\n", get_error(rc));
  LEAVE_CRIT();
  return (rc);
}

EXPORT void WINAPI WSASetLastError (int err)
{
  INIT_PTR (p_WSASetLastError);
  (*p_WSASetLastError)(err);

  ENTER_CRIT();
  WSTRACE ("WSASetLastError (%d=%s).\n", err, get_error(err));
  LEAVE_CRIT();
}

EXPORT SOCKET WINAPI WSASocketA (int af, int type, int protocol,
                                 WSAPROTOCOL_INFOA *proto_info,
                                 GROUP group, DWORD flags)
{
  SOCKET rc;

  INIT_PTR (p_WSASocketA);
  rc = (*p_WSASocketA) (af, type, protocol, proto_info, group, flags);

  ENTER_CRIT();

  WSTRACE ("WSASocketA (%s, %s, %s, 0x%p, %d, %s) --> %s.\n",
           socket_family(af), socket_type(type), protocol_name(protocol),
           proto_info, group, wsasocket_flags_decode(flags),
           socket_or_error(rc));

  if (!exclude_this && g_cfg.dump_wsaprotocol_info)
     dump_wsaprotocol_info ('A', proto_info);

  LEAVE_CRIT();
  return (rc);
}

EXPORT SOCKET WINAPI WSASocketW (int af, int type, int protocol, WSAPROTOCOL_INFOW *proto_info,
                                 GROUP group, DWORD flags)
{
  SOCKET rc;

  INIT_PTR (p_WSASocketW);
  rc = (*p_WSASocketW) (af, type, protocol, proto_info, group, flags);

  ENTER_CRIT();

  WSTRACE ("WSASocketW (%s, %s, %s, 0x%p, %d, %s) --> %s.\n",
           socket_family(af), socket_type(type), protocol_name(protocol),
           proto_info, group, wsasocket_flags_decode(flags),
           socket_or_error(rc));

  if (!exclude_this && g_cfg.dump_wsaprotocol_info)
     dump_wsaprotocol_info ('W', proto_info);

  LEAVE_CRIT();
  return (rc);
}

EXPORT int WINAPI WSADuplicateSocketA (SOCKET s, DWORD process_id, WSAPROTOCOL_INFOA *proto_info)
{
  int rc;

  INIT_PTR (p_WSADuplicateSocketA);
  rc = (*p_WSADuplicateSocketA) (s, process_id, proto_info);

  ENTER_CRIT();

  WSTRACE ("WSADuplicateSocketA (%u, proc-ID %lu, ...) --> %s.\n",
           SOCKET_CAST(s), process_id, get_error(rc));

  if (!exclude_this && g_cfg.dump_wsaprotocol_info)
     dump_wsaprotocol_info ('A', proto_info);

  LEAVE_CRIT();
  return (rc);
}

EXPORT int WINAPI WSADuplicateSocketW (SOCKET s, DWORD process_id, WSAPROTOCOL_INFOW *proto_info)
{
  int rc;

  INIT_PTR (p_WSADuplicateSocketW);
  rc = (*p_WSADuplicateSocketW) (s, process_id, proto_info);

  ENTER_CRIT();

  WSTRACE ("WSADuplicateSocketW (%u, proc-ID %lu, ...) --> %s.\n",
            SOCKET_CAST(s), process_id, get_error(rc));

  if (!exclude_this && g_cfg.dump_wsaprotocol_info)
     dump_wsaprotocol_info ('W', proto_info);

  LEAVE_CRIT();
  return (rc);
}

EXPORT INT WINAPI WSAAddressToStringA (SOCKADDR          *address,
                                       DWORD              address_len,
                                       WSAPROTOCOL_INFOA *proto_info,
                                       char              *result_string,
                                       DWORD             *result_string_len)
{
  INT rc;

  INIT_PTR (p_WSAAddressToStringA);
  rc = (*p_WSAAddressToStringA) (address, address_len, proto_info,
                                 result_string, result_string_len);
  ENTER_CRIT();

  WSTRACE ("WSAAddressToStringA(). --> %s.\n", rc == 0 ? result_string : get_error(rc));

  if (!exclude_this && g_cfg.dump_wsaprotocol_info)
     dump_wsaprotocol_info ('A', proto_info);

  LEAVE_CRIT();
  return (rc);
}

EXPORT INT WINAPI WSAAddressToStringW (SOCKADDR          *address,
                                       DWORD              address_len,
                                       WSAPROTOCOL_INFOW *proto_info,
                                       wchar_t           *result_string,
                                       DWORD             *result_string_len)
{
  INT rc;

  INIT_PTR (p_WSAAddressToStringW);
  rc = (*p_WSAAddressToStringW) (address, address_len, proto_info,
                                 result_string, result_string_len);
  ENTER_CRIT();

  if (rc == 0)
       WSTRACE ("WSAAddressToStringW(). --> %" WCHAR_FMT ".\n", result_string);
  else WSTRACE ("WSAAddressToStringW(). --> %s.\n", get_error(rc));

  if (!exclude_this && g_cfg.dump_wsaprotocol_info)
     dump_wsaprotocol_info ('W', proto_info);

  LEAVE_CRIT();
  return (rc);
}

EXPORT int WINAPI WSAIoctl (SOCKET s, DWORD code, VOID *vals, DWORD size_in,
                            VOID *out_buf, DWORD out_size, DWORD *size_ret,
                            WSAOVERLAPPED *ov, LPWSAOVERLAPPED_COMPLETION_ROUTINE func)
{
  int rc;

  INIT_PTR (p_WSAIoctl);
  rc = (*p_WSAIoctl) (s, code, vals, size_in, out_buf, out_size, size_ret, ov, func);

  ENTER_CRIT();

  WSTRACE ("WSAIoctl (%u, %s, ...) --> %s.\n",
            SOCKET_CAST(s), get_sio_name(code), socket_or_error(rc));

  LEAVE_CRIT();
  return (rc);
}

EXPORT WSAEVENT WINAPI WSACreateEvent (void)
{
  WSAEVENT ev;

  INIT_PTR (p_WSACreateEvent);
  ev = (*p_WSACreateEvent)();

  ENTER_CRIT();

  WSTRACE ("WSACreateEvent() --> 0x%" ADDR_FMT ".\n", ADDR_CAST(ev));

  LEAVE_CRIT();
  return (ev);
}

EXPORT BOOL WINAPI WSASetEvent (WSAEVENT ev)
{
  BOOL rc;

  INIT_PTR (p_WSASetEvent);
  rc = (*p_WSASetEvent) (ev);

  ENTER_CRIT();

  WSTRACE ("WSASetEvent (0x%" ADDR_FMT ").\n", ADDR_CAST(ev));

  LEAVE_CRIT();
  return (rc);
}

EXPORT BOOL WINAPI WSACloseEvent (WSAEVENT ev)
{
  BOOL rc;

  INIT_PTR (p_WSACloseEvent);
  rc = (*p_WSACloseEvent) (ev);

  ENTER_CRIT();

  WSTRACE ("WSACloseEvent (0x%" ADDR_FMT ").\n", ADDR_CAST(ev));

  LEAVE_CRIT();
  return (rc);
}

EXPORT BOOL WINAPI WSAResetEvent (WSAEVENT ev)
{
  BOOL rc;

  INIT_PTR (p_WSAResetEvent);
  rc = (*p_WSAResetEvent) (ev);

  ENTER_CRIT();

  WSTRACE ("WSAResetEvent (0x%" ADDR_FMT ").\n", ADDR_CAST(ev));

  LEAVE_CRIT();
  return (rc);
}

EXPORT int WINAPI WSAEventSelect (SOCKET s, WSAEVENT ev, long net_ev)
{
  int rc;

  INIT_PTR (p_WSAEventSelect);

  ENTER_CRIT();

  WSTRACE ("WSAEventSelect (%u, 0x%" ADDR_FMT ", %s).\n",
            SOCKET_CAST(s), ADDR_CAST(ev), event_bits_decode(net_ev));

  LEAVE_CRIT();

  rc = (*p_WSAEventSelect) (s, ev, net_ev);

  return (rc);
}

EXPORT int WINAPI WSAAsyncSelect (SOCKET s, HWND wnd, unsigned int msg, long net_ev)
{
  int rc;

  INIT_PTR (p_WSAAsyncSelect);
  rc = (*p_WSAAsyncSelect) (s, wnd, msg, net_ev);

  ENTER_CRIT();

  WSTRACE ("WSAAsyncSelect (%u, 0x%" ADDR_FMT ", %u, %s).\n",
            SOCKET_CAST(s), ADDR_CAST(wnd), msg, event_bits_decode(net_ev));

  LEAVE_CRIT();
  return (rc);
}

#if !defined(_MSC_VER)
EXPORT
#endif

int WINAPI __WSAFDIsSet (SOCKET s, fd_set *fd)
{
  int     rc;
  unsigned _s = s;

  INIT_PTR (p___WSAFDIsSet);
  rc = (*p___WSAFDIsSet) (s, fd);

  ENTER_CRIT();

  if (fd == last_rd_fd)
       WSTRACE ("FD_ISSET (%u, \"rd fd_set\") --> %d.\n",  _s, rc);
  else if (fd == last_wr_fd)
       WSTRACE ("FD_ISSET (%u, \"wr fd_set\") --> %d.\n",  _s, rc);
  else if (fd == last_ex_fd)
       WSTRACE ("FD_ISSET (%u, \"ex fd_set\") --> %d.\n",  _s, rc);
  else WSTRACE ("FD_ISSET (%u, %p) --> %d.\n", _s, fd, rc);

  LEAVE_CRIT();
  return (rc);
}

/*
 * Since the MS SDK headers lacks an dllexport on this, this function is just
 * added to the imp-lib. Called from data.c.
 */
int raw__WSAFDIsSet (SOCKET s, fd_set *fd)
{
  return __WSAFDIsSet (s, fd);
}

EXPORT SOCKET WINAPI accept (SOCKET s, struct sockaddr *addr, int *addr_len)
{
  SOCKET rc;

  INIT_PTR (p_accept);
  rc = (*p_accept) (s, addr, addr_len);

  ENTER_CRIT();

  WSTRACE ("accept (%u, %s) --> %s.\n",
            SOCKET_CAST(s), sockaddr_str2(addr,addr_len), socket_or_error(rc));

  LEAVE_CRIT();
  return (rc);
}

EXPORT int WINAPI bind (SOCKET s, const struct sockaddr *addr, int addr_len)
{
  int rc;

  INIT_PTR (p_bind);
  rc = (*p_bind) (s, addr, addr_len);

  ENTER_CRIT();

  WSTRACE ("bind (%u, %s) --> %s.\n",  SOCKET_CAST(s), sockaddr_str2(addr,&addr_len), get_error(rc));

  LEAVE_CRIT();
  return (rc);
}

EXPORT int WINAPI closesocket (SOCKET s)
{
  int rc;

  INIT_PTR (p_closesocket);
  rc = (*p_closesocket) (s);

  ENTER_CRIT();

  WSTRACE ("closesocket (%u) --> %s.\n",  SOCKET_CAST(s), get_error(rc));

  LEAVE_CRIT();
  return (rc);
}

EXPORT int WINAPI connect (SOCKET s, const struct sockaddr *addr, int addr_len)
{
  /*
   * todo: we may need to record (in ioctlsocket() below) if socket is non-blocking.
   *       It seems the WSAGetLastError() is not reliably returned on a non-blocking socket.
   */
  const struct sockaddr_in *sa = (const struct sockaddr_in*)addr;
  const char               *sa_str;
  int   rc;

  INIT_PTR (p_connect);
  ENTER_CRIT();

  sa_str = sockaddr_str2 (addr, &addr_len);

  rc = (*p_connect) (s, addr, addr_len);

  WSTRACE ("connect (%u, %s, fam %s) --> %s.\n",
            SOCKET_CAST(s), sa_str, socket_family(sa->sin_family), get_error(rc));

  LEAVE_CRIT();
  return (rc);
}

EXPORT int WINAPI ioctlsocket (SOCKET s, long opt, u_long *argp)
{
  char arg[10] = "?";
  int  rc;

  INIT_PTR (p_ioctlsocket);
  rc = (*p_ioctlsocket) (s, opt, argp);

  ENTER_CRIT();

  if (argp)
     _itoa (*argp, arg, 10);

  WSTRACE ("ioctlsocket (%u, %s, %s) --> %s.\n",
            SOCKET_CAST(s), ioctlsocket_cmd_name(opt), arg, get_error(rc));

  LEAVE_CRIT();
  return (rc);
}

#if defined(__MINGW64_VERSION_MAJOR)
  #define SELECT_LAST_TYPE const PTIMEVAL
#else
  #define SELECT_LAST_TYPE const struct timeval *
#endif

#define FD_INPUT   "fd_input  ->"
#define FD_OUTPUT  "fd_output ->"

EXPORT int WINAPI select (int nfds, fd_set *rd_fd, fd_set *wr_fd, fd_set *ex_fd, SELECT_LAST_TYPE tv)
{
  char tv_buf [50];
  char buf_in [400];
  char buf_out[400];
  int  rc;

  INIT_PTR (p_select);
  ENTER_CRIT();

  exclude_this = exclude_list_get ("select");

  if (!exclude_this && g_cfg.trace_level > 0)
  {
    if (!tv)
         strcpy (tv_buf, "unspec");
    else snprintf (tv_buf, sizeof(tv_buf), "tv=%ld.%06lds", tv->tv_sec, tv->tv_usec);

    if (g_cfg.dump_select)
       dump_select (rd_fd, wr_fd, ex_fd, g_cfg.trace_indent + 2 + sizeof(FD_INPUT),
                    buf_in, sizeof(buf_in));
  }

  rc = (*p_select) (nfds, rd_fd, wr_fd, ex_fd, tv);

  /*  Remember last 'fd_set' for printing their types in FD_ISSET().
   */
  last_rd_fd = rd_fd;
  last_wr_fd = wr_fd;
  last_ex_fd = ex_fd;

  if (!exclude_this && g_cfg.trace_level > 0)
  {
    char buf [20];

    WSTRACE ("select (n=%d, %s, %s, %s, {%s}) --> (rc=%d) %s.\n",
             nfds,
             rd_fd ? "rd" : "NULL",
             wr_fd ? "wr" : "NULL",
             ex_fd ? "ex" : "NULL",
             tv_buf, rc, rc > 0 ? _itoa(rc,buf,10) : get_error(rc));

    if (g_cfg.dump_select)
    {
      dump_select (rd_fd, wr_fd, ex_fd, g_cfg.trace_indent + 2 + sizeof(FD_OUTPUT),
                   buf_out, sizeof(buf_out));

      trace_indent (g_cfg.trace_indent+2);
      trace_puts ("~4");
      trace_printf (FD_INPUT  " %s\n", buf_in);
      trace_indent (g_cfg.trace_indent+2);
      trace_printf (FD_OUTPUT " %s~0\n", buf_out);
    }
  }

#if 0
  if (!exclude_this && g_cfg.trace_level > 0)
     trace_puts ("~0");
#endif

  LEAVE_CRIT();
  return (rc);
}

EXPORT int WINAPI gethostname (char *buf, int buf_len)
{
  int rc;

  INIT_PTR (p_gethostname);
  rc = (*p_gethostname) (buf, buf_len);

  ENTER_CRIT();

  WSTRACE ("gethostname (->%.*s) --> %s.\n", buf_len, buf, get_error(rc));

  LEAVE_CRIT();
 return (rc);
}

EXPORT int WINAPI listen (SOCKET s, int backlog)
{
  int rc;

  INIT_PTR (p_listen);
  rc = (*p_listen) (s, backlog);

  ENTER_CRIT();

  WSTRACE ("listen (%u, %d) --> %s.\n",  SOCKET_CAST(s), backlog, get_error(rc));

  LEAVE_CRIT();
  return (rc);
}

EXPORT int WINAPI recv (SOCKET s, char *buf, int buf_len, int flags)
{
  int rc;

  INIT_PTR (p_recv);
  rc = (*p_recv) (s, buf, buf_len, flags);

  ENTER_CRIT();

  if (rc >= 0)
  {
    if (flags & MSG_PEEK)
         g_cfg.counts.recv_peeked += rc;
    else g_cfg.counts.recv_bytes  += rc;
  }
  else
    g_cfg.counts.recv_errors++;

  if (g_cfg.trace_level > 0)
  {
    char res[100];

    if (rc >= 0)
        sprintf (res, "%d bytes", rc);
    else strcpy (res, get_error(rc));

    WSTRACE ("recv (%u, 0x%p, %d, %s) --> %s.\n",
             SOCKET_CAST(s), buf, buf_len, socket_flags(flags), res);

    if (rc > 0 && !exclude_this && g_cfg.dump_data)
       dump_data (buf, rc);

    if (g_cfg.pcap.enable)
       write_pcap_packet (buf, buf_len, FALSE);
  }

  LEAVE_CRIT();
  return (rc);
}

EXPORT int WINAPI recvfrom (SOCKET s, char *buf, int buf_len, int flags, struct sockaddr *from, int *from_len)
{
  int rc;

  INIT_PTR (p_recvfrom);
  rc = (*p_recvfrom) (s, buf, buf_len, flags, from, from_len);

  ENTER_CRIT();

  if (rc >= 0)
  {
    if (flags & MSG_PEEK)
         g_cfg.counts.recv_peeked += rc;
    else g_cfg.counts.recv_bytes  += rc;
  }
  else
    g_cfg.counts.recv_errors++;

  if (g_cfg.trace_level > 0)
  {
    char res[100];

    if (rc >= 0)
       sprintf (res, "%d bytes", rc);
    else
    {
      strcpy (res, get_error(rc));
      if (rc == WSAEWOULDBLOCK)
         g_cfg.counts.recv_EWOULDBLOCK++;
    }

    WSTRACE ("recvfrom (%u, 0x%p, %d, %s, %s) --> %s.\n",
              SOCKET_CAST(s), buf, buf_len, socket_flags(flags),
              sockaddr_str2(from,from_len), res);

    if (rc > 0 && !exclude_this && g_cfg.dump_data)
       dump_data (buf, rc);

    if (g_cfg.pcap.enable)
       write_pcap_packet (buf, buf_len, FALSE);
  }

  LEAVE_CRIT();
  return (rc);
}

EXPORT int WINAPI send (SOCKET s, const char *buf, int buf_len, int flags)
{
  int rc;

  INIT_PTR (p_send);
  rc = (*p_send) (s, buf, buf_len, flags);

  ENTER_CRIT();

  if (rc >= 0)
       g_cfg.counts.send_bytes += rc;
  else g_cfg.counts.send_errors++;

  if (g_cfg.trace_level > 0)
  {
    char res[100];

    if (rc >= 0)
         sprintf (res, "%d bytes", rc);
    else strcpy (res, get_error(rc));

    WSTRACE ("send (%u, 0x%p, %d, %s) --> %s.\n",
             SOCKET_CAST(s), buf, buf_len, socket_flags(flags), res);

    if (!exclude_this && g_cfg.dump_data)
       dump_data (buf, buf_len);

    if (g_cfg.pcap.enable)
       write_pcap_packet (buf, buf_len, TRUE);
  }

  LEAVE_CRIT();
  return (rc);
}

EXPORT int WINAPI sendto (SOCKET s, const char *buf, int buf_len, int flags, const struct sockaddr *to, int to_len)
{
  int rc;

  INIT_PTR (p_sendto);
  rc = (*p_sendto) (s, buf, buf_len, flags, to, to_len);

  ENTER_CRIT();

  if (rc >= 0)
       g_cfg.counts.send_bytes += rc;
  else g_cfg.counts.send_errors++;

  if (g_cfg.trace_level > 0)
  {
    char res[100];

    if (rc >= 0)
         sprintf (res, "%d bytes", rc);
    else strcpy (res, get_error(rc));

    WSTRACE ("sendto (%u, 0x%p, %d, %s, %s) --> %s.\n",
              SOCKET_CAST(s), buf, buf_len, socket_flags(flags),
              sockaddr_str2(to,&to_len), res);

    if (!exclude_this && g_cfg.dump_data)
       dump_data (buf, buf_len);

    if (g_cfg.pcap.enable)
       write_pcap_packet (buf, buf_len, TRUE);
  }

  LEAVE_CRIT();
  return (rc);
}

EXPORT int WINAPI WSARecv (SOCKET s, WSABUF *bufs, DWORD num_bufs, DWORD *num_bytes,
                           DWORD *flags, WSAOVERLAPPED *ov,
                           LPWSAOVERLAPPED_COMPLETION_ROUTINE func)
{
  int rc;

  INIT_PTR (p_WSARecv);
  rc = (*p_WSARecv) (s, bufs, num_bufs, num_bytes, flags, ov, func);

  ENTER_CRIT();

  if (rc == 0)
       g_cfg.counts.recv_bytes += bufs->len * num_bufs;
  else g_cfg.counts.recv_errors++;

  if (g_cfg.trace_level > 0)
  {
    char res[100];
    const char *flg = flags ? socket_flags(*flags) : "NULL";

    if (rc != 0)
         strcpy (res, get_error(rc));
    else strcpy (res, "WSA_IO_PENDING");

    WSTRACE ("WSARecv (%u, 0x%p, %lu, %lu, <%s>, 0x%p, 0x%p) --> %s.\n",
              SOCKET_CAST(s), bufs, num_bufs, *num_bytes, flg, ov, func, res);
#if 0
    if (rc > 0 && !exclude_this && g_cfg.dump_data)
       dump_data (bufs->bufs, bufs->len);
#endif
  }

  LEAVE_CRIT();
  return (rc);
}

EXPORT int WINAPI WSARecvFrom (SOCKET s, WSABUF *bufs, DWORD num_bufs, DWORD *num_bytes,
                               DWORD *flags, struct sockaddr *from, INT *from_len,
                               WSAOVERLAPPED *ov, LPWSAOVERLAPPED_COMPLETION_ROUTINE func)
{
  int rc;

  INIT_PTR (p_WSARecvFrom);
  rc = (*p_WSARecvFrom) (s, bufs, num_bufs, num_bytes, flags, from, from_len, ov, func);

  ENTER_CRIT();

  if (rc >= 0)
       g_cfg.counts.recv_bytes += rc;
  else g_cfg.counts.recv_errors++;

  if (g_cfg.trace_level > 0)
  {
    char res[100];
    const char *flg = flags ? socket_flags(*flags) : "NULL";

    if (rc != 0)
         strcpy (res, get_error(rc));
    else strcpy (res, "WSA_IO_PENDING");

    WSTRACE ("WSARecvFrom (%u, 0x%p, %lu, %lu, <%s>, %s, 0x%p, 0x%p) --> %s.\n",
              SOCKET_CAST(s), bufs, num_bufs, *num_bytes, flg,
              sockaddr_str2(from,from_len), ov, func, res);
#if 0
    if (rc == 0 && !exclude_this && g_cfg.dump_data)
       dump_data (bufs->bufs, bufs->len);
#endif
  }

  LEAVE_CRIT();
  return (rc);
}

EXPORT int WINAPI WSARecvEx (SOCKET s, char *buf, int buf_len, int *flags)
{
  int rc;

  INIT_PTR (p_WSARecvEx);
  rc = (*p_WSARecvEx) (s, buf, buf_len, flags);

  ENTER_CRIT();

  if (rc >= 0)
       g_cfg.counts.recv_bytes += rc;
  else g_cfg.counts.recv_errors++;

  if (g_cfg.trace_level > 0)
  {
    char res[100];
    const char *flg = flags ? socket_flags(*flags) : "NULL";

    if (rc >= 0)
        sprintf (res, "%d bytes", rc);
    else strcpy (res, get_error(rc));

    WSTRACE ("WSARecvEx (%u, 0x%p, %d, <%s>) --> %s.\n",
             SOCKET_CAST(s), buf, buf_len, flg, res);
    if (rc > 0 && !exclude_this && g_cfg.dump_data)
       dump_data (buf, rc);
  }

  LEAVE_CRIT();
  return (rc);
}

EXPORT int WINAPI WSARecvDisconnect (SOCKET s, WSABUF *disconnect_data)
{
  int rc;

  INIT_PTR (p_WSARecvDisconnect);
  rc = (*p_WSARecvDisconnect) (s, disconnect_data);

  ENTER_CRIT();

  if (g_cfg.trace_level > 0)
  {
    WSTRACE ("WSARecvDisconnect (%u, 0x%p) --> %s.\n",
             SOCKET_CAST(s), disconnect_data, get_error(rc));
    if (rc == 0 && !exclude_this && g_cfg.dump_data)
       dump_data (disconnect_data->buf, disconnect_data->len);
  }

  LEAVE_CRIT();
  return (rc);
}

EXPORT int WINAPI WSASend (SOCKET s, WSABUF *bufs, DWORD num_bufs, DWORD *num_bytes,
                           DWORD flags, WSAOVERLAPPED *ov, LPWSAOVERLAPPED_COMPLETION_ROUTINE func)
{
  int rc;

  INIT_PTR (p_WSASend);
  rc = (*p_WSASend) (s, bufs, num_bufs, num_bytes, flags, ov, func);

  ENTER_CRIT();

  if (g_cfg.trace_level > 0)
  {
    char res[100];

    if (rc != 0)
         strcpy (res, get_error(rc));
    else strcpy (res, "WSA_IO_PENDING");

    WSTRACE ("WSASend (%u, 0x%p, %lu, %lu, <%s>, 0x%p, 0x%p) --> %s.\n",
              SOCKET_CAST(s), bufs, num_bufs, *num_bytes,
              socket_flags(flags), ov, func, res);
#if 0
    if (rc == 0 && !exclude_this && g_cfg.dump_data)
       dump_data (bufs->bufs, bufs->len);
#endif
  }

  LEAVE_CRIT();
  return (rc);
}

EXPORT int WINAPI WSASendTo (SOCKET s, WSABUF *bufs, DWORD num_bufs, DWORD *num_bytes,
                             DWORD flags, const struct sockaddr *to, int to_len,
                             WSAOVERLAPPED *ov, LPWSAOVERLAPPED_COMPLETION_ROUTINE func)
{
  int rc;

  INIT_PTR (p_WSASendTo);
  rc = (*p_WSASendTo) (s, bufs, num_bufs, num_bytes, flags, to, to_len, ov, func);

  ENTER_CRIT();

  if (g_cfg.trace_level > 0)
  {
    char res[100];

    if (rc != 0)
         strcpy (res, get_error(rc));
    else strcpy (res, "WSA_IO_PENDING");

    WSTRACE ("WSASendTo (%u, 0x%p, %lu, %lu, <%s>, %s, 0x%p, 0x%p) --> %s.\n",
              SOCKET_CAST(s), bufs, num_bufs, *num_bytes, socket_flags(flags),
              sockaddr_str2(to,&to_len), ov, func, res);
#if 0
    if (rc == 0 && !exclude_this && g_cfg.dump_data)
       dump_data (bufs->bufs, bufs->len);
#endif
  }

  LEAVE_CRIT();
  return (rc);
}

EXPORT BOOL WINAPI WSAGetOverlappedResult (SOCKET s, WSAOVERLAPPED *ov, DWORD *transfered,
                                           BOOL wait, DWORD *flags)
{
  BOOL rc;
  char  xfer[10]  = "<N/A>";
  const char *flg = "<N/A>";

  INIT_PTR (p_WSAGetOverlappedResult);
  rc = (*p_WSAGetOverlappedResult) (s, ov, transfered, wait, flags);

  ENTER_CRIT();

  if (transfered)
     _itoa (*transfered, xfer, 10);
  if (flags)
     flg = wsasocket_flags_decode (*flags);

  WSTRACE ("WSAGetOverlappedResult (%u, 0x%p, %s, %d, %s) --> %s.\n",
            SOCKET_CAST(s), ov, xfer, wait, flg, get_error(rc));

  LEAVE_CRIT();
  return (rc);
}

EXPORT int WINAPI WSAEnumNetworkEvents (SOCKET s, WSAEVENT ev, WSANETWORKEVENTS *events)
{
  int rc;

  INIT_PTR (p_WSAEnumNetworkEvents);
  rc = (*p_WSAEnumNetworkEvents) (s, ev, events);

  ENTER_CRIT();

  WSTRACE ("WSAEnumNetworkEvents (%u, 0x%" ADDR_FMT ", 0x%" ADDR_FMT ") --> %s.\n",
            SOCKET_CAST(s), ADDR_CAST(ev), ADDR_CAST(events), get_error(rc));

    if (rc == 0 && !exclude_this && g_cfg.dump_wsanetwork_events)
       dump_events (events);

  LEAVE_CRIT();
  return (rc);
}

EXPORT int WINAPI WSACancelBlockingCall (void)
{
  int rc;

  INIT_PTR (p_WSACancelBlockingCall);
  rc = (*p_WSACancelBlockingCall)();

  ENTER_CRIT();

  WSTRACE ("WSACancelBlockingCall() --> %s.\n", get_error(rc));

  LEAVE_CRIT();
  return (rc);
}

/* to-do:
 */
EXPORT DWORD WINAPI WSAWaitForMultipleEvents (DWORD           num_ev,
                                              const WSAEVENT *ev,
                                              BOOL            wait_all,
                                              DWORD           timeout,
                                              BOOL            alertable)
{
  int rc;

  if (p_WSAWaitForMultipleEvents == NULL)
     rc = WaitForMultipleObjectsEx (num_ev, (const HANDLE*)ev, wait_all, timeout, alertable);
  else
  {
    INIT_PTR (p_WSAWaitForMultipleEvents);
    rc = (*p_WSAWaitForMultipleEvents) (num_ev, ev, wait_all, timeout, alertable);
  }

  ENTER_CRIT();

  WSTRACE ("WSAWaitForMultipleEvents (%lu, %p, %d, %lu, %d) --> %s.\n",
           num_ev, ev, wait_all,timeout, alertable, get_error(rc));

  LEAVE_CRIT();
  return (rc);
}


EXPORT int WINAPI setsockopt (SOCKET s, int level, int opt, const char *opt_val, int opt_len)
{
  int rc;

  INIT_PTR (p_setsockopt);
  rc = (*p_setsockopt) (s, level, opt, opt_val, opt_len);

  ENTER_CRIT();

  WSTRACE ("setsockopt (%u, %s, %s, %s, %d) --> %s.\n",
           SOCKET_CAST(s), socklevel_name(level), sockopt_name(level,opt),
           sockopt_value(opt_val,opt_len), opt_len,
           get_error(rc));

  LEAVE_CRIT();
  return (rc);
}

EXPORT int WINAPI getsockopt (SOCKET s, int level, int opt, char *opt_val, int *opt_len)
{
  int rc;

  INIT_PTR (p_getsockopt);
  rc = (*p_getsockopt) (s, level, opt, opt_val, opt_len);

  ENTER_CRIT();

  WSTRACE ("getsockopt (%u, %s, %s, %s, %d) --> %s.\n",
           SOCKET_CAST(s), socklevel_name(level), sockopt_name(level,opt),
           sockopt_value(opt_val, opt_len ? *opt_len : 0),
           opt_len ? *opt_len : 0, get_error(rc));

  LEAVE_CRIT();
  return (rc);
}

EXPORT int WINAPI shutdown (SOCKET s, int how)
{
  int rc;

  INIT_PTR (p_shutdown);
  rc = (*p_shutdown) (s, how);

  ENTER_CRIT();

  WSTRACE ("shutdown (%u, %d) --> %s.\n",  SOCKET_CAST(s), how, get_error(rc));

  LEAVE_CRIT();
  return (rc);
}

EXPORT SOCKET WINAPI socket (int family, int type, int protocol)
{
  SOCKET rc;

  INIT_PTR (p_socket);
  rc = (*p_socket) (family, type, protocol);

  ENTER_CRIT();

  WSTRACE ("socket (%s, %s, %d) --> %s.\n",
           socket_family(family), socket_type(type), protocol,
           socket_or_error(rc));

  LEAVE_CRIT();
  return (rc);
}

EXPORT struct servent *WINAPI getservbyport (int port, const char *proto)
{
  struct servent *rc;

  INIT_PTR (p_getservbyport);
  rc = (*p_getservbyport) (port, proto);

  ENTER_CRIT();

  WSTRACE ("getservbyport (%d, \"%s\") --> %s.\n",
           swap16(port), proto, ptr_or_error(rc));

  if (rc && !exclude_this && g_cfg.dump_servent)
     dump_servent (rc);

  LEAVE_CRIT();
  return (rc);
}

EXPORT struct servent *WINAPI getservbyname (const char *serv, const char *proto)
{
  struct servent *rc;

  INIT_PTR (p_getservbyname);
  rc = (*p_getservbyname) (serv, proto);

  ENTER_CRIT();

  WSTRACE ("getservbyname (\"%s\", \"%s\") --> %s.\n",
           serv, proto, ptr_or_error(rc));

  if (rc && !exclude_this && g_cfg.dump_servent)
     dump_servent (rc);

  LEAVE_CRIT();
  return (rc);
}

EXPORT struct hostent *WINAPI gethostbyname (const char *name)
{
  struct hostent *rc;

  INIT_PTR (p_gethostbyname);
  rc = (*p_gethostbyname) (name);

  ENTER_CRIT();

  WSTRACE ("gethostbyname (\"%s\") --> %s.\n", name, ptr_or_error(rc));

  if (rc && !exclude_this && g_cfg.dump_hostent)
  {
    dump_hostent (rc);

    /* to-do: Turn IDNA names like "www.xn--seghr-kiac.no" into sensible local names.
     */
  }

  LEAVE_CRIT();
  return (rc);
}

EXPORT struct hostent *WINAPI gethostbyaddr (const char *addr, int len, int type)
{
  struct hostent *rc;

  INIT_PTR (p_gethostbyaddr);
  rc = (*p_gethostbyaddr) (addr, len, type);

  ENTER_CRIT();

#ifdef USE_BFD
  // test_get_caller (&gethostbyaddr);
#endif

  WSTRACE ("gethostbyaddr (%s, %d, %s) --> %s.\n",
           inet_ntop2(addr,type), len, socket_family(type), ptr_or_error(rc));

  if (rc && !exclude_this && g_cfg.dump_hostent)
     dump_hostent (rc);

  LEAVE_CRIT();
  return (rc);
}

EXPORT u_short WINAPI htons (u_short x)
{
  u_short rc;

  INIT_PTR (p_htons);
  rc = (*p_htons) (x);

  ENTER_CRIT();
  WSTRACE ("htons (%u) --> %u.\n", x, rc);
  LEAVE_CRIT();
  return (rc);
}

EXPORT u_short WINAPI ntohs (u_short x)
{
  u_short rc;

  INIT_PTR (p_ntohs);
  rc = (*p_ntohs) (x);

  ENTER_CRIT();
  WSTRACE ("ntohs (%u) --> %u.\n", x, rc);
  LEAVE_CRIT();
  return (rc);
}

EXPORT u_long WINAPI htonl (u_long x)
{
  u_long rc;

  INIT_PTR (p_htonl);
  rc = (*p_htonl) (x);

  ENTER_CRIT();
  WSTRACE ("htonl (%lu) --> %lu.\n", x, rc);
  LEAVE_CRIT();
  return (rc);
}

EXPORT u_long WINAPI ntohl (u_long x)
{
  u_long rc;

  INIT_PTR (p_ntohl);
  rc = (*p_ntohl) (x);

  ENTER_CRIT();
  WSTRACE ("ntohl (%lu) --> %lu.\n", x, rc);
  LEAVE_CRIT();
  return (rc);
}

EXPORT u_long WINAPI inet_addr (const char *addr)
{
  u_long rc;

  INIT_PTR (p_inet_addr);
  rc = (*p_inet_addr) (addr);

  ENTER_CRIT();
  WSTRACE ("inet_addr (\"%s\").\n", addr);
  LEAVE_CRIT();
  return (rc);
}

EXPORT char * WINAPI inet_ntoa (struct in_addr addr)
{
  char *rc;

  INIT_PTR (p_inet_ntoa);
  rc = (*p_inet_ntoa) (addr);

  ENTER_CRIT();
  WSTRACE ("inet_ntoa (%u.%u.%u.%u) --> %s.\n",
           addr.S_un.S_un_b.s_b1,
           addr.S_un.S_un_b.s_b2,
           addr.S_un.S_un_b.s_b3,
           addr.S_un.S_un_b.s_b4, rc);

  LEAVE_CRIT();
  return (rc);
}

EXPORT int WINAPI getpeername (SOCKET s, struct sockaddr *name, int *name_len)
{
  int rc;

  INIT_PTR (p_getpeername);
  rc = (*p_getpeername) (s, name, name_len);

  ENTER_CRIT();

  WSTRACE ("getpeername (%u, %s) --> %s.\n",
            SOCKET_CAST(s), sockaddr_str2(name,name_len), get_error(rc));

  LEAVE_CRIT();
  return (rc);
}

EXPORT int WINAPI getsockname (SOCKET s, struct sockaddr *name, int *name_len)
{
  int rc;

  INIT_PTR (p_getsockname);
  rc = (*p_getsockname) (s, name, name_len);

  ENTER_CRIT();

  WSTRACE ("getsockname (%u, %s) --> %s.\n",
            SOCKET_CAST(s), sockaddr_str2(name,name_len), get_error(rc));

  LEAVE_CRIT();
  return (rc);
}

EXPORT struct protoent * WINAPI getprotobynumber (int num)
{
  struct protoent *rc;

  INIT_PTR (p_getprotobynumber);
  rc = (*p_getprotobynumber) (num);

  ENTER_CRIT();

  WSTRACE ("getprotobynumber (%d) --> %s.\n", num, ptr_or_error(rc));

  if (rc && !exclude_this && g_cfg.dump_protoent)
     dump_protoent (rc);

  LEAVE_CRIT();
  return (rc);
}

EXPORT struct protoent * WINAPI getprotobyname (const char *name)
{
  struct protoent *rc;

  INIT_PTR (p_getprotobyname);
  rc = (*p_getprotobyname) (name);

  ENTER_CRIT();

  WSTRACE ("getprotobyname (\"%s\") --> %s.\n", name, ptr_or_error(rc));

  if (rc && !exclude_this && g_cfg.dump_protoent)
     dump_protoent (rc);

  LEAVE_CRIT();
  return (rc);
}

EXPORT int WINAPI getnameinfo (const struct sockaddr *sa, socklen_t sa_len,
                               char *host, DWORD host_size, char *serv_buf,
                               DWORD serv_buf_size, int flags)
{
  int rc;

  INIT_PTR (p_getnameinfo);
  rc = (*p_getnameinfo) (sa, sa_len, host, host_size, serv_buf, serv_buf_size, flags);

  ENTER_CRIT();

  WSTRACE ("getnameinfo (%s, ..., %s) --> %s.\n",
           sockaddr_str2(sa,&sa_len), getnameinfo_flags_decode(flags), get_error(rc));

  if (rc == 0 && !exclude_this && g_cfg.dump_nameinfo)
  {
    dump_nameinfo (host, serv_buf, flags);

    /* to-do: Turn IDNA names like "www.xn--seghr-kiac.no" into sensible local names.
     */
  }

  LEAVE_CRIT();
  return (rc);
}

EXPORT int WINAPI getaddrinfo (const char *host_name, const char *serv_name,
                               const struct addrinfo *hints, struct addrinfo **res)
{
  int rc;

  INIT_PTR (p_getaddrinfo);
  rc = (*p_getaddrinfo) (host_name, serv_name, hints, res);

  ENTER_CRIT();

  WSTRACE ("getaddrinfo (%s, %s, ...) --> %s.\n",
           host_name, serv_name, get_error(rc));

  if (rc == 0 && *res && !exclude_this && g_cfg.dump_data)
     dump_addrinfo (*res);

  LEAVE_CRIT();
  return (rc);
}

EXPORT void WINAPI freeaddrinfo (struct addrinfo *ai)
{
  INIT_PTR (p_freeaddrinfo);
  (*p_freeaddrinfo) (ai);

  ENTER_CRIT();
  WSTRACE ("freeaddrinfo (0x%" ADDR_FMT ").\n", ADDR_CAST(ai));
  LEAVE_CRIT();
}

#if defined(__MINGW32__)
char * gai_strerrorA (int err)
{
  char *rc;

  INIT_PTR (p_gai_strerrorA);
  rc = (*p_gai_strerrorA) (err);

  ENTER_CRIT();
  WSTRACE ("gai_strerrorA (%d) -> %s.\n", err, rc);
  LEAVE_CRIT();
  return (rc);
}

wchar_t * gai_strerrorW (int err)
{
  wchar_t *rc;

  INIT_PTR (p_gai_strerrorW);
  rc = (*p_gai_strerrorW) (err);

  ENTER_CRIT();
  WSTRACE ("gai_strerrorW (%d) -> %" WCHAR_FMT ".\n", err, rc);
  LEAVE_CRIT();
  return (rc);
}
#endif  /* __MINGW32__ */

#if (defined(__MINGW32__) && !defined(__MINGW64_VERSION_MAJOR)) || defined(__WATCOMC__) || defined(__CYGWIN__)
  #define ADDRINFOW  void *
  #define PADDRINFOW void *
#endif

#define UNIMPLEMENTED() FATAL ("Call to unimplemented function %s().\n", __FUNCTION__)

EXPORT VOID WINAPI FreeAddrInfoW (PADDRINFOW addr_info)
{
  UNIMPLEMENTED();
}

EXPORT INT WINAPI GetAddrInfoW (PCWSTR           node_name,
                                PCWSTR           service_name,
                                const ADDRINFOW *hints,
                                PADDRINFOW      *result)
{
  UNIMPLEMENTED();
  return (-1);
}


EXPORT INT WINAPI GetNameInfoW (const SOCKADDR *sockaddr,
                                socklen_t       sockaddr_len,
                                PWCHAR          node_buf,
                                DWORD           node_buf_size,
                                PWCHAR          service_buf,
                                DWORD           service_buf_size,
                                INT             flags)
{
  UNIMPLEMENTED();
  return (-1);
}

/****************** Internal utility functions **********************************/

static const char *get_timestamp (void)
{
  static LARGE_INTEGER last = { 0ULL };
  static char          buf [40];

  SYSTEMTIME           now;
  LARGE_INTEGER        ticks;
  int64                clocks;
  double               msec;

  switch (g_cfg.trace_time_format)
  {
    case TS_RELATIVE:
    case TS_DELTA:
         if (last.QuadPart == 0ULL)
            last.QuadPart = g_cfg.start_ticks;

         QueryPerformanceCounter (&ticks);
         if (g_cfg.trace_time_format == TS_RELATIVE)
              clocks = (int64) (ticks.QuadPart - g_cfg.start_ticks);
         else clocks = (int64) (ticks.QuadPart - last.QuadPart);

         last = ticks;
         msec = (double)clocks / ((double)g_cfg.clocks_per_usec * 1000.0);
#if 0
         sprintf (buf, "%.3f msec: ", msec);
#else
         {
           int         dec = (int) fmodl (msec, 1000.0);
           const char *s = qword_str ((unsigned __int64) (msec/1000.0));

           sprintf (buf, "%s.%03d msec: ", s, dec);
         }
#endif
         return (buf);

    case TS_ABSOLUTE:
         GetLocalTime (&now);
         sprintf (buf, "%02u:%02u:%02u: ", now.wHour, now.wMinute, now.wSecond);
         return (buf);

    case TS_NONE:
         return ("");
  }
  return (NULL);
}

#if defined(NO_STACK_WALK)
static const char *get_caller (ULONG_PTR ret_addr, ULONG_PTR ebp)
{
  ARGSUSED (ret_addr);
  ARGSUSED (ebp);
  return ("No stkwalk for X64 yet");
}

#else
static const char *get_caller (ULONG_PTR ret_addr, ULONG_PTR ebp)
{
  static int   reentry = 0;
  char *ret = NULL;

  if (reentry++)
  {
    ret = "get_caller() reentry. Breaking out.";
    g_cfg.reentries++;
  }
  else
  {
    CONTEXT ctx;
    int     err;
    HANDLE  thr = GetCurrentThread();

#if !defined(USE_BFD)       /* I.e. MSVC/Watcom, not gcc */
    void   *frames [10];
    USHORT  num_frames;

    err = (*p_WSAGetLastError)();
    memset (frames, '\0', sizeof(frames));
    num_frames = (*p_RtlCaptureStackBackTrace) (0, DIM(frames), frames, NULL);
    if (num_frames <= 2)
    {
      ret = "No stack";
      goto quit;
    }

    /* For MSVC/Watcom (USE_BFD undefined), the passed 'ret_addr' is
     * always 0. We have to get it from 'frames[2]'.
     */
    ret_addr = (ULONG_PTR) frames [2];
#endif

    /* We don't need a CONTEXT_FULL; only EIP+EBP. We want the caller's address of
     * a traced function (e.g. select()). Since we're called twice, that address
     * (for MSVC/PDB files) should be at frames[2]. For gcc, the RtlCaptureStackBackTrace()
     * doesn't work. I've had to use __builtin_return_addres(0) (='ret_addr').
     */
    ctx.Eip = ret_addr;
    ctx.Ebp = ebp;

    ret = StackWalkShow (thr, &ctx);

#if !defined(USE_BFD)
    if (g_cfg.callee_level > 1)
    {
      char *a, *b;

      ctx.Eip = (ULONG_PTR) frames [3];

      a = strdup (ret);
      b = strdup (StackWalkShow (thr, &ctx));
      ret = malloc (strlen(a)+strlen(b)+50);
      sprintf (ret, "%s\n                  %s", a, b);
    }
#endif

    (*p_WSASetLastError) (err);
  }

quit:
  reentry--;
  return (ret);
}
#endif  /* NO_STACK_WALK */

#if defined(USE_BFD)  /* MingW implied */

extern ULONG_PTR _image_base__;

#define FILL_STACK_ADDRESS(X) \
        stack_addr[X] = (ULONG_PTR) __builtin_return_address (X)

static void test_get_caller (const void *from)
{
  ULONG_PTR   stack_addr [3];
  void       *frames [5];
  const char *ret;
  int         i, num;
  char        buf[100];

  memset (frames, '\0', sizeof(frames));
  num = (*p_RtlCaptureStackBackTrace) (0, DIM(frames), frames, NULL);

  FILL_STACK_ADDRESS (0);
  FILL_STACK_ADDRESS (1);
  FILL_STACK_ADDRESS (2);

  TRACE (4, "_image_base__: 0x%" ADDR_FMT ", from: 0x%" ADDR_FMT ", delta: 0x%" ADDR_FMT ".\n",
            _image_base__, ADDR_CAST(from), ADDR_CAST(from - _image_base__));

  for (i = 0; i < num; i++)
      TRACE (1, " frames[%d]: 0x%" ADDR_FMT "\n", i, ADDR_CAST(frames[i]));

#if 1
  for (i = 0; i < DIM(stack_addr); i++)
      TRACE (1, " stack_addr[%d]: 0x%" ADDR_FMT "\n", i, ADDR_CAST(stack_addr[i]));
#endif

  BFD_get_function_name (stack_addr[0], buf, sizeof(buf));
  TRACE (1, "BFD_get_function_name(stack_addr[0]): %s\n", buf);

  BFD_get_function_name (stack_addr[1], buf, sizeof(buf));
  TRACE (1, "BFD_get_function_name(stack_addr[1]): %s\n", buf);

  BFD_get_function_name (stack_addr[2], buf, sizeof(buf));
  TRACE (1, "BFD_get_function_name(stack_addr[2]): %s\n", buf);

  BFD_get_function_name (10 + (ULONG_PTR)from, buf, sizeof(buf));
  TRACE (1, "BFD_get_function_name(from): %s, frames[0] - from: 0x%02lX\n",
            buf, (DWORD) (ADDR_CAST(frames[0]) - ADDR_CAST(from)));
  exit (0);
}
#endif  /* USE_BFD */

BOOL WINAPI DllMain (HINSTANCE hinstDLL, DWORD dwReason, LPVOID lpvReserved)
{
  const char *note = "";

  if (ws_trace_base && hinstDLL == ws_trace_base)
     note = " (" WSOCK_TRACE_DLL ")";

  if (dwReason == DLL_PROCESS_ATTACH)
  {
    crtdbg_init();
    wsock_trace_init();
  }
  else if (dwReason == DLL_PROCESS_DETACH)
  {
    wsock_trace_exit();
    crtdbg_exit();
  }
  else if (dwReason == DLL_THREAD_ATTACH)
  {
    g_cfg.counts.dll_attach++;
    TRACE (3, "  DLL_THREAD_ATTACH. hinstDLL: 0x%" ADDR_FMT "%s, thr-id: %lu.\n",
           ADDR_CAST(hinstDLL), note, GetCurrentThreadId());
  }
  else if (dwReason == DLL_THREAD_DETACH)
  {
    g_cfg.counts.dll_detach++;
    TRACE (3, "  DLL_THREAD_DETACH. hinstDLL: 0x%" ADDR_FMT "%s, thr-id: %lu.\n",
          ADDR_CAST(hinstDLL), note, GetCurrentThreadId());
  }

  ARGSUSED (lpvReserved);
  return (TRUE);
}


