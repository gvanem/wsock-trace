/**\file    wsock_trace.c
 * \ingroup Main
 *
 * \brief
 * A small and simple drop-in tracer for most normal Winsock calls.
 * Works best for MSVC since the stack-walking code requires the program's
 * PDB symbol-file to be present. And unfortunately MinGW/CygWin doesn't
 * produce PDB-symbols.
 */

/**
 * Usage (MSVC): <br>
 *   link with `wsock_trace.lib` instead of the system's `ws32_2.lib`.
 *
 * Usage (MinGW/CygWin): <br>
 *   link with libwsock_trace.a instead of the system's `libws2_32.a`. <br>
 *   I.e. copy it to a directory in `$(LIBRARY_PATH)` and use `-lwsock_trace`
 *   to link. The `Makefile.MinGW` already does the copying to `$(MINGW32)/lib`.
 *
 * Ignore warnings like: <br>
 * ```
 *   foo.obj : warning LNK4049: locally defined symbol _closesocket@4
 *             imported in bar().
 * ```
 */

#define IN_WSOCK_TRACE_C

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <assert.h>
#include <limits.h>
#include <ctype.h>

#if defined(__CYGWIN__)
  /*
   * A hack to hide the different prototypes of 'InetNtopW()' in
   * various version of CygWin's <ws2tcpip.h>.
   */
  #define InetNtopW orig_InetNtopW
#endif

#include "common.h"
#include "bfd_gcc.h"
#include "in_addr.h"
#include "init.h"
#include "idna.h"
#include "cpu.h"
#include "stkwalk.h"
#include "overlap.h"
#include "dump.h"
#include "firewall.h"
#include "wsock_trace_lua.h"
#include "wsock_trace.h"

#ifndef WSA_IO_PENDING
#define WSA_IO_PENDING  ERROR_IO_PENDING
#endif

/**
 * Keep track of number of calls to `WSAStartup()` and `WSACleanup()`.
 *
 * \todo: these (and the statics below) should be "Thread Local" variables.
 */
int volatile cleaned_up = 0;
int volatile startup_count = 0;

static BOOL    exclude_this = FALSE;
static fd_set *last_rd_fd = NULL;
static fd_set *last_wr_fd = NULL;
static fd_set *last_ex_fd = NULL;

static const char *get_caller (ULONG_PTR ret_addr, ULONG_PTR ebp);
static const char *get_error (SOCK_RC_TYPE rc, int local_err);
static void        wstrace_printf (BOOL first_line,
                                   _Printf_format_string_ const char *fmt, ...)
                                   ATTR_PRINTF (2, 3);

#if defined(USE_BFD) || defined(__clang__)
  static void test_get_caller (const void *from);
#endif

/**
 * \def CHECK_PTR()
 *   All `p_function` pointers below are checked before use with this
 *   macro. `check_ptr()` makes sure `wsock_trace_init()` is called once
 *   and `p_function` is not NULL.
*/
#if defined(USE_DETOURS)   /* \todo */
  #define CHECK_PTR(ptr)    /* */
#else
  #define CHECK_PTR(ptr) check_ptr ((const void**)&ptr, #ptr)
#endif

/**
 * \def WSTRACE()
 *   A macro for the WinSock calls we support. <br>
 *   This macro is used like `WSTRACE ("WSAStartup (%u.%u) --> %s", args).`
 *   \note
 *     Do NOT add a trailing `".~0\n"`; it's done in this macro.
 *
 *   If `"g_cfg.trace_caller == 0"` or `"WSAStartup"` is in the
 *   `exclude_list` smartlist, the `!exclude_list_get("WSAStartup...", EXCL_FUNCTION)`
 *   returns `FALSE`.
 */
#define WSTRACE(fmt, ...)                                        \
        do {                                                     \
          exclude_this = TRUE;                                   \
          if (g_cfg.trace_level > 0 &&                           \
              !exclude_list_get (fmt, EXCL_FUNCTION))            \
          {                                                      \
            exclude_this = FALSE;                                \
            wstrace_printf (TRUE, "~1* ~3%s~5%s: ~1",            \
                            get_timestamp(),                     \
                            get_caller (GET_RET_ADDR(),          \
                                        get_EBP()) );            \
            wstrace_printf (FALSE, fmt ".~0\n", ## __VA_ARGS__); \
          }                                                      \
        } while (0)


#if defined(__GNUC__) || defined(__clang__)
  #define GET_RET_ADDR()  (ULONG_PTR)__builtin_return_address (0)
#else
  #define GET_RET_ADDR()  0
#endif

#if (defined(_MSC_VER) && defined(_M_X64)) || \
    (defined(__GNUC__) && !defined(__i386__))
  #define get_EBP() 0

#elif defined(_MSC_VER) && defined(_X86_)
  __declspec(naked) static ULONG_PTR get_EBP (void)
  {
    __asm mov eax, ebp
    __asm ret
  }

#elif defined(__GNUC__)
  #if defined(__NO_INLINE__)
    static ULONG_PTR get_EBP (void)
  #else
    extern __inline__ ULONG_PTR get_EBP (void)
  #endif
  {
    ULONG_PTR ebp;
    __asm__ __volatile__ ("movl %%ebp,%k0" : "=r" (ebp) : );
    return (ebp);
  }

#elif defined(__WATCOMC__)  /* OpenWatcom is x86 only */
  extern ULONG_PTR get_EBP (void);
  #pragma aux  get_EBP = \
          "mov eax, ebp" \
          modify [eax];

#else
  #error "Unsupported compiler."
#endif

/**
 * Hooking and tracing of Winsock extension functions returned in
 * `WSAIoctl (s, SIO_GET_EXTENSION_FUNCTION_POINTER,...)`.
 */
#include "wsock_hooks.c"

/**
 * \def DEF_FUNC()
 * Handy macro to both define and declare the function-pointer.
 */
#define DEF_FUNC(ret, f, args)  typedef ret (WINAPI *func_##f) args; \
                                static func_##f  p_##f = NULL

DEF_FUNC (SOCKET,      socket,      (int family, int type, int protocol));
DEF_FUNC (SOCKET,      accept,      (SOCKET s, struct sockaddr *addr, int *addr_len));
DEF_FUNC (int,         bind,        (SOCKET s, const struct sockaddr *addr, int addr_len));
DEF_FUNC (int,         shutdown,    (SOCKET s, int how));
DEF_FUNC (int,         closesocket, (SOCKET s));
DEF_FUNC (int,         connect,     (SOCKET s, const struct sockaddr *addr, int addr_len));
DEF_FUNC (int,         ioctlsocket, (SOCKET s, __LONG32 opt, __ms_u_long *arg));
DEF_FUNC (int,         select,      (int nfds, fd_set *rd_fd, fd_set *wr_fd, fd_set *ex_fd, CONST_PTIMEVAL timeout));
DEF_FUNC (int,         listen,      (SOCKET s, int backlog));
DEF_FUNC (int,         recv,        (SOCKET s, char *buf, int buf_len, int flags));
DEF_FUNC (int,         recvfrom,    (SOCKET s, char *buf, int buf_len, int flags, struct sockaddr *from, int *from_len));
DEF_FUNC (int,         send,        (SOCKET s, const char *buf, int buf_len, int flags));
DEF_FUNC (int,         sendto,      (SOCKET s, const char *buf, int buf_len, int flags, const struct sockaddr *to, int to_len));
DEF_FUNC (int,         setsockopt,  (SOCKET s, int level, int opt, const char *opt_val, int opt_len));
DEF_FUNC (int,         getsockopt,  (SOCKET s, int level, int opt, char *opt_val, int *opt_len));
DEF_FUNC (int,         gethostname, (char *buf, int buf_len));
DEF_FUNC (int,         getpeername, (SOCKET s, struct sockaddr *name, int *namelen));
DEF_FUNC (int,         getsockname, (SOCKET s, struct sockaddr *name, int *namelen));
DEF_FUNC (u_short,     htons,       (u_short x));
DEF_FUNC (u_short,     ntohs,       (u_short x));
DEF_FUNC (__ms_u_long, htonl,       (__ms_u_long x));
DEF_FUNC (__ms_u_long, ntohl,       (__ms_u_long x));
DEF_FUNC (__ULONG32,   inet_addr,   (const char *addr));
DEF_FUNC (char *,      inet_ntoa,   (struct in_addr addr));

DEF_FUNC (struct servent *,  getservbyport,    (int port, const char *proto));
DEF_FUNC (struct servent *,  getservbyname,    (const char *serv, const char *proto));
DEF_FUNC (struct hostent *,  gethostbyname,    (const char *name));
DEF_FUNC (struct hostent *,  gethostbyaddr,    (const char *addr, int len, int type));
DEF_FUNC (struct protoent *, getprotobynumber, (int num));
DEF_FUNC (struct protoent *, getprotobyname,   (const char *name));

DEF_FUNC (int, getnameinfo, (const struct sockaddr *sa,
                             socklen_t              sa_len,
                             char                  *buf,
                             DWORD                  buf_size,
                             char                  *serv_buf,
                             DWORD                  serv_buf_size,
                             int                    flags));

DEF_FUNC (int, getaddrinfo, (const char            *host_name,
                             const char            *serv_name,
                             const struct addrinfo *hints,
                             struct addrinfo      **res));

DEF_FUNC (void, freeaddrinfo, (struct addrinfo *ai));

DEF_FUNC (int,  WSAStartup,      (WORD version, LPWSADATA data));
DEF_FUNC (int,  WSACleanup,      (void));
DEF_FUNC (int,  WSAGetLastError, (void));
DEF_FUNC (void, WSASetLastError, (int err));

DEF_FUNC (int,  WSAIoctl, (SOCKET                             s,
                           DWORD                              code,
                           void                              *vals,
                           DWORD                              size_in,
                           void                              *out_buf,
                           DWORD                              out_size,
                           DWORD                             *size_ret,
                           WSAOVERLAPPED                     *ov,
                           LPWSAOVERLAPPED_COMPLETION_ROUTINE func));

DEF_FUNC (WSAEVENT, WSACreateEvent, (void));
DEF_FUNC (BOOL,     WSACloseEvent,  (WSAEVENT));
DEF_FUNC (BOOL,     WSASetEvent,    (WSAEVENT));
DEF_FUNC (BOOL,     WSAResetEvent,  (WSAEVENT));

DEF_FUNC (int, WSAEventSelect, (SOCKET   s,
                                WSAEVENT hnd,
                                __LONG32 net_ev));

DEF_FUNC (int, WSAAsyncSelect, (SOCKET       s,
                                HWND         wnd,
                                unsigned int msg,
                                __LONG32     net_ev));

DEF_FUNC (SOCKET, WSAAccept, (SOCKET       s,
                              struct sockaddr *sa,
                              int             *sa_len,
                              LPCONDITIONPROC  condition,
                              DWORD_PTR        callback_data));

DEF_FUNC (int, WSARecv, (SOCKET                             s,
                         WSABUF                            *bufs,
                         DWORD                              num_bufs,
                         DWORD                             *num_bytes,
                         DWORD                             *flags,
                         WSAOVERLAPPED                     *ov,
                         LPWSAOVERLAPPED_COMPLETION_ROUTINE func));

DEF_FUNC (int, WSARecvFrom, (SOCKET                             s,
                             WSABUF                            *bufs,
                             DWORD                              num_bufs,
                             DWORD                             *num_bytes,
                             DWORD                             *flags,
                             struct sockaddr                   *from,
                             INT                               *from_len,
                             WSAOVERLAPPED                     *ov,
                             LPWSAOVERLAPPED_COMPLETION_ROUTINE func));

DEF_FUNC (int, WSARecvDisconnect, (SOCKET  s,
                                   WSABUF *disconnect_data));

DEF_FUNC (int, WSARecvEx, (SOCKET s,
                           char  *buf,
                           int    buf_len,
                           int   *flags));

DEF_FUNC (int, WSASend, (SOCKET                             s,
                         WSABUF                            *bufs,
                         DWORD                              num_bufs,
                         DWORD                             *num_bytes,
                         DWORD                              flags,
                         WSAOVERLAPPED                     *ov,
                         LPWSAOVERLAPPED_COMPLETION_ROUTINE func));

DEF_FUNC (int, WSASendTo, (SOCKET                             s,
                           WSABUF                            *bufs,
                           DWORD                              num_bufs,
                           DWORD                             *num_bytes,
                           DWORD                              flags,
                           const struct sockaddr             *to,
                           int                                to_len,
                           WSAOVERLAPPED                     *ow,
                           LPWSAOVERLAPPED_COMPLETION_ROUTINE func));

DEF_FUNC (int, WSASendMsg, (SOCKET                             s,
                            WSAMSG                            *msg,
                            DWORD                              flags,
                            DWORD                             *num_bytes_sent,
                            WSAOVERLAPPED                     *ov,
                            LPWSAOVERLAPPED_COMPLETION_ROUTINE func));

DEF_FUNC (int, WSAConnect, (SOCKET                 s,
                            const struct sockaddr *name,
                            int                    namelen,
                            WSABUF                *caller_data,
                            WSABUF                *callee_data,
                            QOS                   *SQOS,
                            QOS                   *GQOS));


DEF_FUNC (BOOL, WSAConnectByList, (SOCKET               s,
                                   SOCKET_ADDRESS_LIST *socket_addr_list,
                                   DWORD               *local_addr_len,
                                   SOCKADDR            *local_addr,
                                   DWORD               *remote_addr_len,
                                   SOCKADDR            *remote_addr,
                                   CONST_PTIMEVAL       timeout,
                                   WSAOVERLAPPED       *reserved));

DEF_FUNC (BOOL, WSAConnectByNameA, (SOCKET              s,
                                    CONST_LPSTR         node_name,
                                    CONST_LPSTR         service_name,
                                    DWORD              *local_addr_len,
                                    SOCKADDR           *local_addr,
                                    DWORD              *remote_addr_len,
                                    SOCKADDR           *remote_addr,
                                    CONST_PTIMEVAL      timeout,
                                    WSAOVERLAPPED      *reserved));

DEF_FUNC (BOOL, WSAConnectByNameW, (SOCKET              s,
                                    LPWSTR              node_name,
                                    LPWSTR              service_name,
                                    DWORD              *local_addr_len,
                                    SOCKADDR           *local_addr,
                                    DWORD              *remote_addr_len,
                                    SOCKADDR           *remote_addr,
                                    CONST_PTIMEVAL      timeout,
                                    WSAOVERLAPPED      *reserved));

DEF_FUNC (int, __WSAFDIsSet,  (SOCKET s,
                               fd_set *fds));

DEF_FUNC (SOCKET, WSASocketA, (int                af,
                               int                type,
                               int                protocol,
                               WSAPROTOCOL_INFOA *protocol_info,
                               GROUP              grp,
                               DWORD              flags));

DEF_FUNC (SOCKET, WSASocketW, (int                af,
                               int                type,
                               int                protocol,
                               WSAPROTOCOL_INFOW *protocol_info,
                               GROUP              grp,
                               DWORD              flags));

DEF_FUNC (int, WSADuplicateSocketA, (SOCKET             s,
                                     DWORD              process_id,
                                     WSAPROTOCOL_INFOA *protocol_info));

DEF_FUNC (int, WSADuplicateSocketW, (SOCKET             s,
                                     DWORD              process_id,
                                     WSAPROTOCOL_INFOW *protocol_info));

DEF_FUNC (INT, WSAAddressToStringA, (SOCKADDR          *address,
                                     DWORD              address_len,
                                     WSAPROTOCOL_INFOA *protocol_info,
                                     char              *result_string,
                                     DWORD             *result_string_len));

DEF_FUNC (INT, WSAAddressToStringW, (SOCKADDR          *address,
                                     DWORD              address_len,
                                     WSAPROTOCOL_INFOW *protocol_info,
                                     wchar_t           *result_string,
                                     DWORD             *result_string_len));

DEF_FUNC (INT, WSAStringToAddressA, (char              *address_str,
                                     INT                address_fam,
                                     WSAPROTOCOL_INFOA *protocol_info,
                                     SOCKADDR          *address,
                                     INT               *address_len));

DEF_FUNC (INT, WSAStringToAddressW, (wchar_t           *address_str,
                                     INT                address_fam,
                                     WSAPROTOCOL_INFOW *protocol_info,
                                     SOCKADDR          *address,
                                     INT               *address_len));

DEF_FUNC (int, WSAEnumNetworkEvents, (SOCKET            s,
                                      WSAEVENT          ev,
                                      WSANETWORKEVENTS *events));

DEF_FUNC (int, WSAEnumProtocolsA, (int               *protocols,
                                   WSAPROTOCOL_INFOA *proto_info,
                                   DWORD             *buf_len));

DEF_FUNC (int, WSAEnumProtocolsW, (int               *protocols,
                                   WSAPROTOCOL_INFOW *proto_info,
                                   DWORD             *buf_len));

DEF_FUNC (DWORD, WSAWaitForMultipleEvents, (DWORD           num_ev,
                                            const WSAEVENT *ev,
                                            BOOL            wait_all,
                                            DWORD           timeout,
                                            BOOL            alertable));

DEF_FUNC (DWORD, WaitForMultipleObjectsEx, (DWORD         num_ev,
                                            const HANDLE *hnd,
                                            BOOL          wait_all,
                                            DWORD         timeout,
                                            BOOL          alertable));

DEF_FUNC (int, WSACancelBlockingCall, (void));

DEF_FUNC (int, WSCGetProviderPath, (GUID    *provider_id,
                                    wchar_t *provider_dll_path,
                                    int     *provider_dll_path_len,
                                    int     *error));
/**
 * Windows-Vista functions.
 */
DEF_FUNC (int,   WSAPoll,   (WSAPOLLFD *fd_array, ULONG fds, int timeout));
DEF_FUNC (INT,   inet_pton, (int family, const char *string, void *res));
DEF_FUNC (PCSTR, inet_ntop, (int family, const void *addr, char *string, size_t string_size));
DEF_FUNC (INT,   InetPtonW, (int family, PCWSTR waddr, void *waddr_dest));
DEF_FUNC (PCWSTR,InetNtopW, (int family, const void *addr, PWSTR res_buf, size_t res_buf_size));

/**
 * In ntdll.dll
 */
DEF_FUNC (USHORT, RtlCaptureStackBackTrace, (ULONG  frames_to_skip,
                                             ULONG  frames_to_capture,
                                             void **frames,
                                             ULONG *trace_hash));

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
              ADD_VALUE (0, "ws2_32.dll", WSASetEvent),
              ADD_VALUE (0, "ws2_32.dll", WSAEventSelect),
              ADD_VALUE (0, "ws2_32.dll", WSAAsyncSelect),
              ADD_VALUE (0, "ws2_32.dll", WSAAccept),
              ADD_VALUE (0, "ws2_32.dll", WSAAddressToStringA),
              ADD_VALUE (0, "ws2_32.dll", WSAAddressToStringW),
              ADD_VALUE (0, "ws2_32.dll", WSAStringToAddressA),
              ADD_VALUE (0, "ws2_32.dll", WSAStringToAddressW),
              ADD_VALUE (0, "ws2_32.dll", WSADuplicateSocketA),
              ADD_VALUE (0, "ws2_32.dll", WSADuplicateSocketW),
              ADD_VALUE (0, "ws2_32.dll", __WSAFDIsSet),
              ADD_VALUE (0, "ws2_32.dll", WSARecv),
              ADD_VALUE (0, "ws2_32.dll", WSARecvDisconnect),
              ADD_VALUE (0, "ws2_32.dll", WSARecvFrom),
              ADD_VALUE (1, "Mswsock.dll",WSARecvEx),
              ADD_VALUE (0, "ws2_32.dll", WSASend),
              ADD_VALUE (0, "ws2_32.dll", WSASendTo),
              ADD_VALUE (0, "ws2_32.dll", WSAConnect),
              ADD_VALUE (1, "ws2_32.dll", WSAConnectByList),   /* Windows Vista+ */
              ADD_VALUE (1, "ws2_32.dll", WSAConnectByNameA),  /* Windows Vista+ */
              ADD_VALUE (1, "ws2_32.dll", WSAConnectByNameW),  /* Windows Vista+ */
              ADD_VALUE (1, "ws2_32.dll", WSAPoll),
              ADD_VALUE (0, "ws2_32.dll", WSAGetOverlappedResult),
              ADD_VALUE (0, "ws2_32.dll", WSAEnumNetworkEvents),
              ADD_VALUE (1, "ws2_32.dll", WSAEnumProtocolsA),
              ADD_VALUE (1, "ws2_32.dll", WSAEnumProtocolsW),
              ADD_VALUE (0, "ws2_32.dll", WSACancelBlockingCall),
              ADD_VALUE (1, "ws2_32.dll", WSAWaitForMultipleEvents),
              ADD_VALUE (1, "ws2_32.dll", WSCGetProviderPath),
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
              ADD_VALUE (1, "ws2_32.dll", InetPtonW),
              ADD_VALUE (1, "ws2_32.dll", InetNtopW),
              ADD_VALUE (0, "ntdll.dll",  RtlCaptureStackBackTrace),
           // ADD_VALUE (1, "kernel32.dll", WaitForMultipleObjectsEx),

             /**
              * Allthough `WSASendMsg()` seems to be an "extension-function"
              * accessible only (?) via the `WSAID_WSASENDMSG` GUID, it is present
              * in `libws2_32.a` in some MinGW distros. <br>
              * Add it as an option.
              */
              ADD_VALUE (1, "ws2_32.dll", WSASendMsg),
            };

void load_ws2_funcs (void)
{
  load_dynamic_table (dyn_funcs, DIM(dyn_funcs));

  g_WSASetLastError = p_WSASetLastError;
  g_WSAGetLastError = p_WSAGetLastError;

  if (p_RtlCaptureStackBackTrace == NULL)
      g_cfg.trace_caller = 0;

  if (p_inet_pton == NULL)
     TRACE (2, "Failed to import 'inet_pton()'\n.");

  if (p_inet_ntop == NULL)
     TRACE (2, "Failed to import 'inet_ntop()'\n.");

  ARGSUSED (p_WaitForMultipleObjectsEx); /* Silence the warning */
}

const struct LoadTable *find_ws2_func_by_name (const char *func)
{
  return find_dynamic_table (dyn_funcs, DIM(dyn_funcs), func);
}

static void wstrace_printf (BOOL first_line, const char *fmt, ...)
{
  DWORD   err = GetLastError();   /* save error status */
  va_list args;

  if (first_line)
  {
    /* If stdout or stderr is redirected, we cannot get the cursor column.
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
    trace_printf ("~3* %s~1", get_timestamp());
    fmt += 4;  /* step over the "~1* " we're called with */
  }
#endif

  va_start (args, fmt);
  trace_vprintf (fmt, args);
  va_end (args);

  SetLastError (err);  /* restore error status */
}

/**
 * Save and restore WSA error-state:
 * \param[in]  pop  if = 0: return value from `WSAGetLastError()`.
 *                  if = 1: calls `WSASetLastError (err)`.
 */
int WSAError_save_restore (int pop)
{
  static int err = 0;  /**\todo This should be a "Thread Local" variable */

  if (pop)
       (*p_WSASetLastError) (err);
  else err = (*p_WSAGetLastError)();
  return (err);
}

/**
 * Return an error-string for either a locally-generated error in `local_err`. <br>
 * Or an error from `WSAGetLastError()`.
 *
 * In both cases the error-text is retrieved* using `ws_strerror()`
 * (which also handles non-Winsock error-codes).
 */
static const char *get_error (SOCK_RC_TYPE rc, int local_err)
{
  /* Longest result:
   *   "WSAECANCELLED: A call to WSALookupServiceEnd was made while this call was still processing. The call has been canceled (10103)" = 127 chars.
   */
  static char buf[150];

  if (local_err != 0)
     return ws_strerror (local_err, buf, sizeof(buf));

  if (rc != 0)
  {
    const char *ret;
    int   err = WSAERROR_PUSH();   /* = 'WSAError_save_restore (0)' */

    ret = ws_strerror (err, buf, sizeof(buf));
    WSAERROR_POP();                /* = WSAError_save_restore (1) */
    return (ret);
  }
  return ("No error");
}

/**
 * `WSAAddressToStringA()` returns the address *and* the port.<br>
 * Like: `127.0.0.1:1234`
 *
 * \param[in] sa      the `struct sockaddr *` to return the address from.
 * \param[in] sa_len  the length of the `struct sockaddr` structure.
 */
const char *sockaddr_str (const struct sockaddr *sa, const int *sa_len)
{
  static char buf [MAX_IP6_SZ+MAX_PORT_SZ+1];
  DWORD  size = sizeof(buf);
  DWORD  len  = sa_len ? *(DWORD*)sa_len : (DWORD)sizeof(*sa);

  WSAERROR_PUSH();
  if ((*p_WSAAddressToStringA)((SOCKADDR*)sa, len, NULL, buf, &size))
     strcpy (buf, "??");
  WSAERROR_POP();
  return (buf);
}

/**
 * Instead of calling `WSAAddressToStringA()` for AF_INET/AF_INET6 addresses,
 * we do it ourself using `sockaddr_str_port()`.
 *
 * \param[in] sa      the `struct sockaddr *` to format and return from.
 * \param[in] sa_len  the length of the `struct sockaddr` structure.
 */
const char *sockaddr_str2 (const struct sockaddr *sa, const int *sa_len)
{
  const char *p = sockaddr_str_port (sa, sa_len);

  if (!p)
     return sockaddr_str (sa, sa_len);
  return (p);
}

/**
 * \struct fake_sockaddr_un
 * This is in `<afunix.h>` on recent SDK's.
 */
struct fake_sockaddr_un {
       short sun_family;       /* AF_UNIX */
       char  sun_path [108];   /* pathname */
     };
#define sockaddr_un fake_sockaddr_un

#ifndef AF_UNIX
#define AF_UNIX 1
#endif

/**
 * This returns the address *and* the port in the `buf`. <br>
 * Like:
 *  \li `"127.0.0.1:1234"`  for an `AF_INET` sockaddr. And
 *  \li `"[0F::80::]:1234"` for an `AF_INET6` sockaddr.
 */
const char *sockaddr_str_port (const struct sockaddr *sa, const int *sa_len)
{
  const struct sockaddr_in  *sa4 = (const struct sockaddr_in*) sa;
  const struct sockaddr_in6 *sa6 = (const struct sockaddr_in6*) sa;
  const struct sockaddr_un  *su  = (const struct sockaddr_un*) sa;
  static char buf [MAX_IP6_SZ+MAX_PORT_SZ+3];
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
    buf[0] = '[';
    _wsock_trace_inet_ntop (AF_INET6, &sa6->sin6_addr, buf+1, sizeof(buf)-1, NULL);
    end = strchr (buf, '\0');
    *end++ = ']';
    *end++ = ':';
    _itoa (swap16(sa6->sin6_port), end, 10);
    return (buf);
  }

  if (sa4->sin_family == AF_UNIX)
  {
    const wchar_t *path = (const wchar_t*) &su->sun_path;

    if (!su->sun_path[0])
         strcpy (buf, "abstract");
    else if (su->sun_path[0] && su->sun_path[1])
         _strlcpy (buf, su->sun_path, sizeof(buf));
    else if (WideCharToMultiByte(CP_ACP, 0, path, (int)wcslen(path), buf, (int)sizeof(buf), NULL, NULL) == 0)
         strcpy (buf, "??");
    return (buf);
  }

  ARGSUSED (sa_len);
  return (NULL);
}

static const char *inet_ntop2 (const char *addr, int family)
{
  static char buf [MAX_IP6_SZ+1];
  PCSTR  rc;

#if 0
  rc = (*p_inet_ntop) (family, addr, buf, sizeof(buf));
  if (!rc)
     return get_error (-1, 0);
#else
  rc = _wsock_trace_inet_ntop (family, addr, buf, sizeof(buf), NULL);
  if (!rc)
     strcpy (buf, "??");
#endif
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
    buf [j] = hex_chars [idx];
  }
  return (buf);
}

static const char *ptr_or_error (const void *ptr)
{
  static char buf [30];

  if (!ptr)
     return get_error (-1, 0);

  memset (&buf, '\0', sizeof(buf));
  return uint_ptr_hexval ((UINT_PTR)ptr, buf);
}

static const char *socket_or_error (SOCK_RC_TYPE rc)
{
  static char buf [10];

  if (rc == INVALID_SOCKET || rc == SOCKET_ERROR)
     return get_error (rc, 0);
  return _itoa ((int)rc, buf, 10);
}

/*
 * Show if a Winsock function is given a 'SOCKET == -1'.
 */
static const char *socket_number (SOCKET s)
{
  static char buf [20];

  if ((signed int)s == -1)
     return ("-1");

  _itoa ((int)s, buf, 10);
  return (buf);
}

/*
 * The actual Winsock functions we trace.
 */
EXPORT int WINAPI WSAStartup (WORD ver, WSADATA *data)
{
  int rc;

  cleaned_up = 0;

  CHECK_PTR (p_WSAStartup);
  rc = (*p_WSAStartup) (ver, data);

  if (startup_count < INT_MAX)
     startup_count++;

  if (startup_count == 1 && g_cfg.FIREWALL.enable)
  {
    fw_init();
    fw_monitor_start();
  }

  ENTER_CRIT();
  WSTRACE ("WSAStartup (%u.%u) --> %s",
           loBYTE(data->wVersion), hiBYTE(data->wVersion), get_error(rc, 0));

  WSLUA_HOOK (rc, wslua_WSAStartup(ver,data));
  LEAVE_CRIT();
  return (rc);
}

EXPORT int WINAPI WSACleanup (void)
{
  int rc;

  CHECK_PTR (p_WSACleanup);
  rc = (*p_WSACleanup)();

  ENTER_CRIT();
  WSTRACE ("WSACleanup() --> %s", get_error(rc, 0));

  if (startup_count > 0)
  {
    startup_count--;
    cleaned_up = (startup_count == 0);
  }

  WSLUA_HOOK (rc, wslua_WSACleanup());
  LEAVE_CRIT();
  return (rc);
}

EXPORT int WINAPI WSAGetLastError (void)
{
  int rc;

  CHECK_PTR (p_WSAGetLastError);
  rc = (*p_WSAGetLastError)();

  ENTER_CRIT();
  WSTRACE ("WSAGetLastError() --> %s", get_error(rc, 0));
  LEAVE_CRIT();
  return (rc);
}

EXPORT void WINAPI WSASetLastError (int err)
{
  CHECK_PTR (p_WSASetLastError);
  (*p_WSASetLastError) (err);

  ENTER_CRIT();
  WSTRACE ("WSASetLastError (%s%s)",
           err ? "" : "0: ", get_error(err, 0));
  LEAVE_CRIT();
}

EXPORT SOCKET WINAPI WSASocketA (int af, int type, int protocol,
                                 WSAPROTOCOL_INFOA *proto_info,
                                 GROUP group, DWORD flags)
{
  SOCKET rc;

  CHECK_PTR (p_WSASocketA);
  rc = (*p_WSASocketA) (af, type, protocol, proto_info, group, flags);

  ENTER_CRIT();

  WSTRACE ("WSASocketA (%s, %s, %s, 0x%p, %d, %s) --> %s",
           socket_family(af), socket_type(type), protocol_name(protocol),
           proto_info, group, wsasocket_flags_decode(flags),
           socket_or_error(rc));

  if (!exclude_this && g_cfg.dump_wsaprotocol_info)
     dump_wsaprotocol_info ('A', proto_info, p_WSCGetProviderPath);

  LEAVE_CRIT();
  return (rc);
}

EXPORT SOCKET WINAPI WSASocketW (int af, int type, int protocol,
                                 WSAPROTOCOL_INFOW *proto_info,
                                 GROUP group, DWORD flags)
{
  SOCKET rc;

  CHECK_PTR (p_WSASocketW);
  rc = (*p_WSASocketW) (af, type, protocol, proto_info, group, flags);

  ENTER_CRIT();

  WSTRACE ("WSASocketW (%s, %s, %s, 0x%p, %d, %s) --> %s",
           socket_family(af), socket_type(type), protocol_name(protocol),
           proto_info, group, wsasocket_flags_decode(flags),
           socket_or_error(rc));

  if (!exclude_this && g_cfg.dump_wsaprotocol_info)
     dump_wsaprotocol_info ('W', proto_info, p_WSCGetProviderPath);

  LEAVE_CRIT();
  return (rc);
}

EXPORT int WINAPI WSADuplicateSocketA (SOCKET s, DWORD process_id, WSAPROTOCOL_INFOA *proto_info)
{
  int rc;

  CHECK_PTR (p_WSADuplicateSocketA);
  rc = (*p_WSADuplicateSocketA) (s, process_id, proto_info);

  ENTER_CRIT();

  WSTRACE ("WSADuplicateSocketA (%s, proc-ID %lu, ...) --> %s",
           socket_number(s), DWORD_CAST(process_id), get_error(rc, 0));

  if (!exclude_this && g_cfg.dump_wsaprotocol_info)
     dump_wsaprotocol_info ('A', proto_info, p_WSCGetProviderPath);

  LEAVE_CRIT();
  return (rc);
}

EXPORT int WINAPI WSADuplicateSocketW (SOCKET s, DWORD process_id, WSAPROTOCOL_INFOW *proto_info)
{
  int rc;

  CHECK_PTR (p_WSADuplicateSocketW);
  rc = (*p_WSADuplicateSocketW) (s, process_id, proto_info);

  ENTER_CRIT();

  WSTRACE ("WSADuplicateSocketW (%s, proc-ID %lu, ...) --> %s",
            socket_number(s), DWORD_CAST(process_id), get_error(rc, 0));

  if (!exclude_this && g_cfg.dump_wsaprotocol_info)
     dump_wsaprotocol_info ('W', proto_info, p_WSCGetProviderPath);

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

  CHECK_PTR (p_WSAAddressToStringA);
  rc = (*p_WSAAddressToStringA) (address, address_len, proto_info,
                                 result_string, result_string_len);
  ENTER_CRIT();

  WSTRACE ("WSAAddressToStringA(). --> %s", rc == 0 ? result_string : get_error(rc, 0));

  if (!exclude_this && g_cfg.dump_wsaprotocol_info)
     dump_wsaprotocol_info ('A', proto_info, p_WSCGetProviderPath);

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

  CHECK_PTR (p_WSAAddressToStringW);
  rc = (*p_WSAAddressToStringW) (address, address_len, proto_info,
                                 result_string, result_string_len);
  ENTER_CRIT();

  if (rc == 0)
       WSTRACE ("WSAAddressToStringW(). --> %" WCHAR_FMT, result_string);
  else WSTRACE ("WSAAddressToStringW(). --> %s", get_error(rc, 0));

  if (!exclude_this && g_cfg.dump_wsaprotocol_info)
     dump_wsaprotocol_info ('W', proto_info, p_WSCGetProviderPath);

  LEAVE_CRIT();
  return (rc);
}

EXPORT INT WINAPI WSAStringToAddressA (char              *address_str,
                                       INT                address_fam,
                                       WSAPROTOCOL_INFOA *protocol_info,
                                       SOCKADDR          *address,
                                       INT               *address_len)
{
  INT rc;

  CHECK_PTR (p_WSAStringToAddressA);
  rc = (*p_WSAStringToAddressA) (address_str, address_fam, protocol_info, address, address_len);

  ENTER_CRIT();
  WSTRACE ("WSAStringToAddressA (\"%s\"). --> %s", address_str, get_error(rc, 0));
  LEAVE_CRIT();
  return (rc);
}

EXPORT INT WINAPI WSAStringToAddressW (wchar_t           *address_str,
                                       INT                address_fam,
                                       WSAPROTOCOL_INFOW *protocol_info,
                                       SOCKADDR          *address,
                                       INT               *address_len)
{
  INT rc;

  CHECK_PTR (p_WSAStringToAddressW);
  rc = (*p_WSAStringToAddressW) (address_str, address_fam, protocol_info, address, address_len);

  ENTER_CRIT();
  WSTRACE ("WSAStringToAddressW (L\"%" WCHAR_FMT "\"). --> %s", address_str, get_error(rc, 0));
  LEAVE_CRIT();
  return (rc);
}


EXPORT int WINAPI WSAIoctl (SOCKET s, DWORD code, void *vals, DWORD size_in,
                            void *out_buf, DWORD out_size, DWORD *size_ret,
                            WSAOVERLAPPED *ov, LPWSAOVERLAPPED_COMPLETION_ROUTINE func)
{
  const char *in_out = "";
  int   rc;

  CHECK_PTR (p_WSAIoctl);
  rc = (*p_WSAIoctl) (s, code, vals, size_in, out_buf, out_size, size_ret, ov, func);

  ENTER_CRIT();

  if (code & IOC_INOUT)
    in_out = " (RW)";
  else if (code & IOC_OUT)
    in_out = " (R)";
  else if (code & IOC_IN)
    in_out = " (W)";
  else if (code & IOC_VOID)
    in_out = " (N)";

  WSTRACE ("WSAIoctl (%s, %s%s, ...) --> %s",
           socket_number(s), get_sio_name(code), in_out, socket_or_error(rc));

  /* Dump known extension functions by GUID.
   */
  if (g_cfg.trace_level > 0 && code == SIO_GET_EXTENSION_FUNCTION_POINTER &&
      size_in == sizeof(GUID) && out_size == sizeof(void*))
  {
    dump_extension_funcs (vals, out_buf);

   /* hook the extension function only when someone wants to
    * use it. Thus allowing a trace of it.
    * Ref. wsock_hooks.c for details.
    */
    if (g_cfg.hook_extensions)
    {
#if defined(HAVE_WSA_EXTENSIONS_FUNCTIONS)
      hook_extension_func (vals, out_buf);
#else
      TRACE (1, "Tracing extension functions not possible with this compiler.\n");
#endif
    }
  }

  LEAVE_CRIT();
  return (rc);
}

EXPORT int WINAPI WSAConnect (SOCKET s, const struct sockaddr *name, int namelen,
                              WSABUF *caller_data, WSABUF *callee_data, QOS *SQOS, QOS *GQOS)
{
  int rc;

  CHECK_PTR (p_WSAConnect);
  rc = (*p_WSAConnect) (s, name, namelen, caller_data, callee_data, SQOS, GQOS);

  ENTER_CRIT();

  WSTRACE ("WSAConnect (%s, %s, 0x%p, 0x%p, ...) --> %s",
           socket_number(s), sockaddr_str2(name, &namelen),
           caller_data, callee_data, socket_or_error(rc));

#if 0
  if (!exclude_this && rc == NO_ERROR && g_cfg.dump_data)
   {
     dump_wsabuf (caller_data, 1);
     dump_wsabuf (callee_data, 1);
   }
#endif

#if 0
    /**\todo store the address in a connect cache-file with above 'geo-ip', IANA and ASN information.
     */
    if (g_cfg.cache_file)
       cache_store_connect (addr);
#endif

  LEAVE_CRIT();
  return (rc);
}

EXPORT BOOL WINAPI WSAConnectByNameA (SOCKET         s,
                                      CONST_LPSTR    node_name,
                                      CONST_LPSTR    service_name,
                                      DWORD         *local_addr_len,
                                      SOCKADDR      *local_addr,
                                      DWORD         *remote_addr_len,
                                      SOCKADDR      *remote_addr,
                                      CONST_PTIMEVAL tv,
                                      WSAOVERLAPPED *reserved)
{
  BOOL rc;
  char tv_buf[30];

  CHECK_PTR (p_WSAConnectByNameA);
  rc = (*p_WSAConnectByNameA) (s, node_name, service_name, local_addr_len, local_addr,
                               remote_addr_len, remote_addr, tv, reserved);

  ENTER_CRIT();

  exclude_this = (g_cfg.trace_level == 0 || exclude_list_get("WSAConnectByNameA", EXCL_FUNCTION));
  if (!exclude_this)
  {
    if (!tv)
         strcpy (tv_buf, "unspec");
    else snprintf (tv_buf, sizeof(tv_buf), "tv=%ld.%06lds",
                   LONG_CAST(tv->tv_sec), LONG_CAST(tv->tv_usec));

    WSTRACE ("WSAConnectByNameA (%s, %s, %s, %s, ...) --> %s",
             socket_number(s), node_name, service_name, tv_buf, get_error(rc, 0));

#if 0
    /**\todo store the address in a connect cache-file with above 'geo-ip', IANA and ASN information.
     */
    if (g_cfg.cache_file)
       cache_store_connect (addr);
#endif
  }
  LEAVE_CRIT();
  return (rc);
}

EXPORT BOOL WINAPI WSAConnectByNameW (SOCKET         s,
                                      LPWSTR        node_name,
                                      LPWSTR        service_name,
                                      DWORD         *local_addr_len,
                                      SOCKADDR      *local_addr,
                                      DWORD         *remote_addr_len,
                                      SOCKADDR      *remote_addr,
                                      CONST_PTIMEVAL tv,
                                      WSAOVERLAPPED *reserved)
{
  BOOL rc;
  char tv_buf[30];

  CHECK_PTR (p_WSAConnectByNameW);
  rc = (*p_WSAConnectByNameW) (s, node_name, service_name, local_addr_len, local_addr,
                               remote_addr_len, remote_addr, tv, reserved);

  ENTER_CRIT();

  exclude_this = (g_cfg.trace_level == 0 || exclude_list_get("WSAConnectByNameW", EXCL_FUNCTION));
  if (!exclude_this)
  {
    if (!tv)
         strcpy (tv_buf, "unspec");
    else snprintf (tv_buf, sizeof(tv_buf), "tv=%ld.%06lds",
                   LONG_CAST(tv->tv_sec), LONG_CAST(tv->tv_usec));

    WSTRACE ("WSAConnectByNameW (%s, %" WCHAR_FMT ", %" WCHAR_FMT ", %s, ...) --> %s",
             socket_number(s), node_name, service_name, tv_buf, get_error(rc, 0));

#if 0
    /**\todo store the address in a connect cache-file with above 'geo-ip', IANA and ASN information.
     */
    if (g_cfg.cache_file)
       cache_store_connect (addr);
#endif
  }
  LEAVE_CRIT();
  return (rc);
}

EXPORT BOOL WINAPI WSAConnectByList (SOCKET               s,
                                     SOCKET_ADDRESS_LIST *socket_addr_list,
                                     DWORD               *local_addr_len,
                                     SOCKADDR            *local_addr,
                                     DWORD               *remote_addr_len,
                                     SOCKADDR            *remote_addr,
                                     CONST_PTIMEVAL       tv,
                                     WSAOVERLAPPED       *reserved)
{
  BOOL rc;
  char tv_buf[30];

  CHECK_PTR (p_WSAConnectByList);
  rc = (*p_WSAConnectByList) (s, socket_addr_list, local_addr_len, local_addr,
                              remote_addr_len, remote_addr, tv, reserved);

  ENTER_CRIT();

  exclude_this = (g_cfg.trace_level == 0 || exclude_list_get("WSAConnectByList", EXCL_FUNCTION));
  if (!exclude_this)
  {
    if (!tv)
         strcpy (tv_buf, "unspec");
    else snprintf (tv_buf, sizeof(tv_buf), "tv=%ld.%06lds",
                   LONG_CAST(tv->tv_sec), LONG_CAST(tv->tv_usec));

    WSTRACE ("WSAConnectByList (%s, %s, ...) --> %s",
             socket_number(s), tv_buf, get_error(rc, 0));

#if 0
    /**\todo store the address in a connect cache-file with above 'geo-ip', IANA and ASN information.
     */
    if (g_cfg.cache_file)
       cache_store_connect (addr);
#endif
  }
  LEAVE_CRIT();
  return (rc);
}

EXPORT WSAEVENT WINAPI WSACreateEvent (void)
{
  WSAEVENT ev;

  CHECK_PTR (p_WSACreateEvent);
  ev = (*p_WSACreateEvent)();

  ENTER_CRIT();

  WSTRACE ("WSACreateEvent() --> 0x%" ADDR_FMT, ADDR_CAST(ev));

  LEAVE_CRIT();
  return (ev);
}

EXPORT BOOL WINAPI WSASetEvent (WSAEVENT ev)
{
  BOOL rc;

  CHECK_PTR (p_WSASetEvent);
  rc = (*p_WSASetEvent) (ev);

  ENTER_CRIT();

  WSTRACE ("WSASetEvent (0x%" ADDR_FMT ") --> %s", ADDR_CAST(ev), get_error(rc, 0));

  LEAVE_CRIT();
  return (rc);
}

EXPORT BOOL WINAPI WSACloseEvent (WSAEVENT ev)
{
  BOOL rc;

  CHECK_PTR (p_WSACloseEvent);
  rc = (*p_WSACloseEvent) (ev);

  ENTER_CRIT();

  WSTRACE ("WSACloseEvent (0x%" ADDR_FMT ") --> %s", ADDR_CAST(ev), get_error(rc, 0));

  LEAVE_CRIT();
  return (rc);
}

EXPORT BOOL WINAPI WSAResetEvent (WSAEVENT ev)
{
  BOOL rc;

  CHECK_PTR (p_WSAResetEvent);
  rc = (*p_WSAResetEvent) (ev);

  ENTER_CRIT();

  WSTRACE ("WSAResetEvent (0x%" ADDR_FMT ") --> %s", ADDR_CAST(ev), get_error(rc, 0));

  LEAVE_CRIT();
  return (rc);
}

EXPORT int WINAPI WSAEventSelect (SOCKET s, WSAEVENT ev, __LONG32 net_ev)
{
  int rc;

  CHECK_PTR (p_WSAEventSelect);
  rc = (*p_WSAEventSelect) (s, ev, net_ev);

  ENTER_CRIT();

  WSTRACE ("WSAEventSelect (%s, 0x%" ADDR_FMT ", %s) --> %s",
           socket_number(s), ADDR_CAST(ev), event_bits_decode(net_ev), get_error(rc, 0));

  LEAVE_CRIT();
  return (rc);
}

EXPORT int WINAPI WSAAsyncSelect (SOCKET s, HWND wnd, unsigned int msg, __LONG32 net_ev)
{
  int rc;

  CHECK_PTR (p_WSAAsyncSelect);
  rc = (*p_WSAAsyncSelect) (s, wnd, msg, net_ev);

  ENTER_CRIT();

  WSTRACE ("WSAAsyncSelect (%s, 0x%" ADDR_FMT ", %u, %s) --> %s",
           socket_number(s), ADDR_CAST(wnd), msg, event_bits_decode(net_ev), get_error(rc, 0));

  LEAVE_CRIT();
  return (rc);
}

/*
 * The `condition` handler is not traced (only the address is printed).
 * It has the following signature:
 *  int CALLBACK ConditionFunc (
 *   IN     LPWSABUF    lpCallerId,
 *   IN     LPWSABUF    lpCallerData,
 *   IN OUT LPQOS       lpSQOS,
 *   IN OUT LPQOS       lpGQOS,
 *   IN     LPWSABUF    lpCalleeId,
 *   IN     LPWSABUF    lpCalleeData,
 *   OUT    GROUP FAR * g,
 *   IN     DWORD_PTR   dwCallbackData);
 *
 * From:
 *   https://docs.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-wsaaccept
 */
EXPORT SOCKET WINAPI WSAAccept (SOCKET s, struct sockaddr *addr, int *addr_len,
                                LPCONDITIONPROC condition, DWORD_PTR callback_data)
{
  SOCKET rc;

  CHECK_PTR (p_WSAAccept);
  rc = (*p_WSAAccept) (s, addr, addr_len, condition, callback_data);

  ENTER_CRIT();

  WSTRACE ("WSAAccept (%s, %s, 0x%p, 0x%p) --> %s",
           socket_number(s), sockaddr_str2(addr, addr_len),
           condition, (const void*)callback_data, socket_or_error(rc));

  if (!exclude_this)
  {
    if (g_cfg.GEOIP.enable)
       dump_countries_sockaddr (addr);

    if (g_cfg.IANA.enable)
       dump_IANA_sockaddr (addr);

    if (g_cfg.ASN.enable)
       dump_ASN_sockaddr (addr);

    if (g_cfg.DNSBL.enable)
       dump_DNSBL_sockaddr (addr);
  }

  LEAVE_CRIT();
  return (rc);
}

#if !defined(_MSC_VER)
EXPORT
#endif
int WINAPI __WSAFDIsSet (SOCKET s, fd_set *fd)
{
  int     rc;
  unsigned _s = (unsigned) s;

  CHECK_PTR (p___WSAFDIsSet);
  rc = (*p___WSAFDIsSet) (s, fd);

  ENTER_CRIT();

  if (fd == last_rd_fd)
       WSTRACE ("FD_ISSET (%u, \"rd fd_set\") --> %d", _s, rc);
  else if (fd == last_wr_fd)
       WSTRACE ("FD_ISSET (%u, \"wr fd_set\") --> %d", _s, rc);
  else if (fd == last_ex_fd)
       WSTRACE ("FD_ISSET (%u, \"ex fd_set\") --> %d", _s, rc);
  else WSTRACE ("FD_ISSET (%u, 0x%p) --> %d", _s, fd, rc);

  LEAVE_CRIT();
  return (rc);
}

EXPORT SOCKET WINAPI accept (SOCKET s, struct sockaddr *addr, int *addr_len)
{
  SOCKET rc;

  CHECK_PTR (p_accept);
  rc = (*p_accept) (s, addr, addr_len);

  ENTER_CRIT();

  WSTRACE ("accept (%s, %s) --> %s",
           socket_number(s), sockaddr_str2(addr, addr_len), socket_or_error(rc));

  if (!exclude_this)
  {
    if (g_cfg.GEOIP.enable)
       dump_countries_sockaddr (addr);

    if (g_cfg.IANA.enable)
       dump_IANA_sockaddr (addr);

    if (g_cfg.ASN.enable)
       dump_ASN_sockaddr (addr);

    if (g_cfg.DNSBL.enable)
       dump_DNSBL_sockaddr (addr);
  }

  LEAVE_CRIT();
  return (rc);
}

EXPORT int WINAPI bind (SOCKET s, const struct sockaddr *addr, int addr_len)
{
  int rc;

  CHECK_PTR (p_bind);
  rc = (*p_bind) (s, addr, addr_len);

  ENTER_CRIT();

  if (addr->sa_family == AF_UNIX)
  {
    WSTRACE ("bind (%s, \"%s\") --> %s",
             socket_number(s), sockaddr_str_port (addr, &addr_len), get_error(rc, 0));
  }
  else
  {
    WSTRACE ("bind (%s, %s) --> %s",
             socket_number(s), sockaddr_str2 (addr, &addr_len), get_error(rc, 0));
  }

  if (!exclude_this)
  {
    if (g_cfg.GEOIP.enable)
       dump_countries_sockaddr (addr);

    if (g_cfg.IANA.enable)
       dump_IANA_sockaddr (addr);

    if (g_cfg.ASN.enable)
       dump_ASN_sockaddr (addr);

    if (g_cfg.DNSBL.enable)
       dump_DNSBL_sockaddr (addr);
  }

  LEAVE_CRIT();
  return (rc);
}

EXPORT int WINAPI closesocket (SOCKET s)
{
  int rc;

  CHECK_PTR (p_closesocket);
  rc = (*p_closesocket) (s);

  ENTER_CRIT();

  WSTRACE ("closesocket (%s) --> %s", socket_number(s), get_error(rc, 0));
  overlap_remove (s);

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
  int   rc;

  CHECK_PTR (p_connect);
  ENTER_CRIT();

  rc = (*p_connect) (s, addr, addr_len);

  WSTRACE ("connect (%s, %s, fam %s) --> %s",
           socket_number(s), sockaddr_str2(addr, &addr_len),
           socket_family(sa->sin_family), get_error(rc, 0));

  if (!exclude_this)
  {
    WSAERROR_PUSH();

    if (g_cfg.GEOIP.enable)
       dump_countries_sockaddr (addr);

    if (g_cfg.IANA.enable)
       dump_IANA_sockaddr (addr);

    if (g_cfg.ASN.enable)
       dump_ASN_sockaddr (addr);

    if (g_cfg.DNSBL.enable)
       dump_DNSBL_sockaddr (addr);

#if 0
    /**\todo store the address in a connect cache-file with above 'geo-ip', IANA and ASN information.
     */
    if (g_cfg.cache_file)
       cache_store_connect (addr);
#endif

    WSAERROR_POP();
  }
  LEAVE_CRIT();
  return (rc);
}

EXPORT int WINAPI ioctlsocket (SOCKET s, __LONG32 opt, __ms_u_long *argp)
{
  char arg[10] = "?";
  int  rc;

  CHECK_PTR (p_ioctlsocket);
  rc = (*p_ioctlsocket) (s, opt, argp);

  ENTER_CRIT();

  if (argp)
     _itoa (*argp, arg, 10);

  WSTRACE ("ioctlsocket (%s, %s, %s) --> %s",
           socket_number(s), ioctlsocket_cmd_name(opt), arg, get_error(rc, 0));

  LEAVE_CRIT();
  return (rc);
}

#define FD_INPUT   "fd_input  ->"
#define FD_OUTPUT  "fd_output ->"

EXPORT int WINAPI select (int nfds, fd_set *rd_fd, fd_set *wr_fd, fd_set *ex_fd, CONST_PTIMEVAL tv)
{
  fd_set *rd_copy = NULL;
  fd_set *wr_copy = NULL;
  fd_set *ex_copy = NULL;
  char    rc_buf [20];
  char    tv_buf [50];
  char    ts_buf [40] = "";  /* timestamp at start of select() */
  int     rc;
  size_t  sz;
  BOOL    _exclude_this;

  CHECK_PTR (p_select);
  ENTER_CRIT();

  /* Set the global and local 'exclude_this' values
   */
  exclude_this = (g_cfg.trace_level == 0 || exclude_list_get("select", EXCL_FUNCTION));
  _exclude_this = exclude_this;

  if (!_exclude_this)
  {
    strcpy (ts_buf, get_timestamp());

    if (!tv)
         strcpy (tv_buf, "unspec");
    else snprintf (tv_buf, sizeof(tv_buf), "tv=%ld.%06lds",
                   LONG_CAST(tv->tv_sec), LONG_CAST(tv->tv_usec));

    if (g_cfg.dump_select)
    {
      sz = size_fd_set (rd_fd);
      if (sz)
         rd_copy = copy_fd_set_to (rd_fd, alloca(sz));

      sz = size_fd_set (wr_fd);
      if (sz)
         wr_copy = copy_fd_set_to (wr_fd, alloca(sz));

      sz = size_fd_set (ex_fd);
      if (sz)
         ex_copy = copy_fd_set_to (ex_fd, alloca(sz));
    }
  }

  LEAVE_CRIT();

  /**
   * The `select()` can block for a long time. And other calls from other
   * threads can call us. Therefore we must not be in a critical section
   * while `select()` is blocking.
   *
   * \note
   * Several POSIX programs uses `select()` like this:
   * ```
   *   30.812 sec: src/Ntop.cpp(553) (Ntop::start+1018):
   *     select (n=1, rd, NULL, NULL, {tv=0.711000s}) --> (rc=-1) WSAEINVAL (10022).
   *     fd_input  --> rd: <no fds>
   *                   wr: <not set>
   *                   ex: <not set>
   * ```
   *
   * In this case a `tv->tv_usec = 711000` gets ignored (winsock returns immediately). <br>
   * Since it does not like that no sockets are set in `rd_fd`. <br>
   * Maybe we should just add a dummy socket to `rd_fd`?
   */
  rc = (*p_select) (nfds, rd_fd, wr_fd, ex_fd, tv);

  ENTER_CRIT();

  /* Remember last 'fd_set' for printing their types in FD_ISSET().
   */
  last_rd_fd = rd_fd;
  last_wr_fd = wr_fd;
  last_ex_fd = ex_fd;

  if (!_exclude_this)
  {
    /* We want the timestamp for when select() was called.
     * Not the timestamp for when select() returned. Hence do not
     * use the WSTRACE() macro here.
     */
    wstrace_printf (TRUE, "~1* ~3%s~5%s: ~1",
                    ts_buf, get_caller(GET_RET_ADDR(), get_EBP()));

    wstrace_printf (FALSE, "select (n=%d, %s, %s, %s, {%s}) --> (rc=%d) %s.~0\n",
                    nfds,
                    rd_fd ? "rd" : "NULL",
                    wr_fd ? "wr" : "NULL",
                    ex_fd ? "ex" : "NULL",
                    tv_buf, rc, rc > 0 ? _itoa(rc,rc_buf,10) : get_error(rc, 0));

    if (g_cfg.dump_select)
    {
      trace_indent (g_cfg.trace_indent+2);
      trace_puts ("~4" FD_INPUT);
      dump_select (rd_copy, wr_copy, ex_copy, g_cfg.trace_indent + 1 + sizeof(FD_OUTPUT));

      trace_indent (g_cfg.trace_indent+2);
      trace_puts (FD_OUTPUT);
      dump_select (rd_fd, wr_fd, ex_fd, g_cfg.trace_indent + 1 + sizeof(FD_OUTPUT));
      trace_puts ("~0");
    }
  }

  LEAVE_CRIT();

  if (g_cfg.select_delay)
     SleepEx (g_cfg.select_delay, FALSE);

  return (rc);
}

EXPORT int WINAPI gethostname (char *buf, int buf_len)
{
  int rc;

  CHECK_PTR (p_gethostname);
  rc = (*p_gethostname) (buf, buf_len);

  ENTER_CRIT();

  WSTRACE ("gethostname (0x%p, %d) --> \"%.*s\", %s", buf, buf_len, buf_len, buf, get_error(rc, 0));

  LEAVE_CRIT();
  return (rc);
}

EXPORT int WINAPI listen (SOCKET s, int backlog)
{
  int rc;

  CHECK_PTR (p_listen);
  rc = (*p_listen) (s, backlog);

  ENTER_CRIT();

  WSTRACE ("listen (%s, %d) --> %s", socket_number(s), backlog, get_error(rc, 0));

  LEAVE_CRIT();
  return (rc);
}

EXPORT int WINAPI recv (SOCKET s, char *buf, int buf_len, int flags)
{
  int rc;

  CHECK_PTR (p_recv);
  rc = (*p_recv) (s, buf, buf_len, flags);

  ENTER_CRIT();

  exclude_this = (g_cfg.trace_level == 0 || exclude_list_get("recv", EXCL_FUNCTION));

  if (rc >= 0)
  {
    if (flags & MSG_PEEK)
         g_cfg.counts.recv_peeked += rc;
    else g_cfg.counts.recv_bytes  += rc;
  }
  else
    g_cfg.counts.recv_errors++;

  if (!exclude_this)
  {
    char res[100];

    if (rc >= 0)
        sprintf (res, "%d bytes", rc);
    else strcpy (res, get_error(rc, 0));

    WSTRACE ("recv (%s, 0x%p, %d, %s) --> %s",
             socket_number(s), buf, buf_len, socket_flags(flags), res);

    if (rc > 0 && g_cfg.dump_data)
       dump_data (buf, rc);
  }

  if (g_cfg.PCAP.enable)
     write_pcap_packet (s, buf, buf_len, FALSE);

  LEAVE_CRIT();

  if (g_cfg.recv_delay)
     SleepEx (g_cfg.recv_delay, FALSE);

  return (rc);
}

EXPORT int WINAPI recvfrom (SOCKET s, char *buf, int buf_len, int flags, struct sockaddr *from, int *from_len)
{
  int rc;

  CHECK_PTR (p_recvfrom);
  rc = (*p_recvfrom) (s, buf, buf_len, flags, from, from_len);

  ENTER_CRIT();

  exclude_this = (g_cfg.trace_level == 0 || exclude_list_get("recvfrom", EXCL_FUNCTION));

  if (rc >= 0)
  {
    if (flags & MSG_PEEK)
         g_cfg.counts.recv_peeked += rc;
    else g_cfg.counts.recv_bytes  += rc;
  }
  else
    g_cfg.counts.recv_errors++;

  if (!exclude_this)
  {
    char res[100];

    if (rc >= 0)
       sprintf (res, "%d bytes", rc);
    else
    {
      strcpy (res, get_error(rc, 0));
      if ((*g_WSAGetLastError)() == WSAEWOULDBLOCK)
         g_cfg.counts.recv_EWOULDBLOCK++;
    }

    WSTRACE ("recvfrom (%s, 0x%p, %d, %s, %s) --> %s",
             socket_number(s), buf, buf_len, socket_flags(flags),
             sockaddr_str2(from, from_len), res);

    if (rc > 0 && g_cfg.dump_data)
       dump_data (buf, rc);

    if (g_cfg.GEOIP.enable)
       dump_countries_sockaddr (from);

    if (g_cfg.IANA.enable)
       dump_IANA_sockaddr (from);

    if (g_cfg.ASN.enable)
       dump_ASN_sockaddr (from);

    if (g_cfg.DNSBL.enable)
       dump_DNSBL_sockaddr (from);
  }

  if (g_cfg.PCAP.enable)
     write_pcap_packet (s, buf, buf_len, FALSE);

  LEAVE_CRIT();

  if (g_cfg.recv_delay)
     SleepEx (g_cfg.recv_delay, FALSE);

  return (rc);
}

EXPORT int WINAPI send (SOCKET s, const char *buf, int buf_len, int flags)
{
  int rc;

  CHECK_PTR (p_send);
  rc = (*p_send) (s, buf, buf_len, flags);

  ENTER_CRIT();

  exclude_this = (g_cfg.trace_level == 0 || exclude_list_get("send", EXCL_FUNCTION));

  if (rc >= 0)
       g_cfg.counts.send_bytes += rc;
  else g_cfg.counts.send_errors++;

  if (!exclude_this)
  {
    char res[100];

    if (rc >= 0)
         sprintf (res, "%d bytes", rc);
    else strcpy (res, get_error(rc, 0));

    WSTRACE ("send (%s, 0x%p, %d, %s) --> %s",
             socket_number(s), buf, buf_len, socket_flags(flags), res);

    if (g_cfg.dump_data)
       dump_data (buf, buf_len);
  }

  if (g_cfg.PCAP.enable)
     write_pcap_packet (s, buf, buf_len, TRUE);

  LEAVE_CRIT();

  if (g_cfg.send_delay)
     SleepEx (g_cfg.send_delay, FALSE);

  return (rc);
}

EXPORT int WINAPI sendto (SOCKET s, const char *buf, int buf_len, int flags, const struct sockaddr *to, int to_len)
{
  int rc;

  CHECK_PTR (p_sendto);
  rc = (*p_sendto) (s, buf, buf_len, flags, to, to_len);

  ENTER_CRIT();

  exclude_this = (g_cfg.trace_level == 0 || exclude_list_get("sendto", EXCL_FUNCTION));

  if (rc >= 0)
       g_cfg.counts.send_bytes += rc;
  else g_cfg.counts.send_errors++;

  if (!exclude_this)
  {
    char res[100];

    if (rc >= 0)
         sprintf (res, "%d bytes", rc);
    else strcpy (res, get_error(rc, 0));

    WSTRACE ("sendto (%s, 0x%p, %d, %s, %s) --> %s",
             socket_number(s), buf, buf_len, socket_flags(flags),
             sockaddr_str2(to, &to_len), res);

    if (g_cfg.dump_data)
       dump_data (buf, buf_len);

    if (g_cfg.GEOIP.enable)
       dump_countries_sockaddr (to);

    if (g_cfg.DNSBL.enable)
       dump_DNSBL_sockaddr (to);
  }

  if (g_cfg.PCAP.enable)
     write_pcap_packet (s, buf, buf_len, TRUE);

  LEAVE_CRIT();

  if (g_cfg.send_delay)
     SleepEx (g_cfg.send_delay, FALSE);

  return (rc);
}

/*
 * Count the number of bytes in an array of 'WSABUF' structures.
 * Only used for counting bytes in 'WSASend*' calls.
 */
static DWORD count_wsabuf (const WSABUF *bufs, DWORD num_bufs)
{
  DWORD bytes = 0;
  int   i;

  for (i = 0; i < (int)num_bufs && bufs; i++, bufs++)
      bytes += bufs->len;
  return (bytes);
}

EXPORT int WINAPI WSARecv (SOCKET s, WSABUF *bufs, DWORD num_bufs, DWORD *num_bytes,
                           DWORD *flags, WSAOVERLAPPED *ov,
                           LPWSAOVERLAPPED_COMPLETION_ROUTINE func)
{
  DWORD size;
  int   rc;

  CHECK_PTR (p_WSARecv);
  rc = (*p_WSARecv) (s, bufs, num_bufs, num_bytes, flags, ov, func);

  ENTER_CRIT();

  exclude_this = (g_cfg.trace_level == 0 || exclude_list_get("WSARecv", EXCL_FUNCTION));
  size = bufs->len * num_bufs;

  if (rc == NO_ERROR)
  {
    /* If the transfer is overlapped this counter should be
     * updated in 'WSAGetOverlappedResult()'.
     *
     * But this may not work so maybe we need to hook
     * 'PostQueuedCompletionStatus()' and update the recv/transmit counters there?
     */
    g_cfg.counts.recv_bytes += size;
  }

  if (!exclude_this)
  {
    char        res[100];
    char        nbytes[20];
    const char *flg = flags ? socket_flags(*flags) : "NULL";

    if (num_bytes)
         _itoa (*num_bytes, nbytes, 10);
    else strcpy (nbytes, "??");

    strcpy (res, get_error(rc, 0));

    WSTRACE ("WSARecv (%s, 0x%p, %lu, %s, <%s>, 0x%p, 0x%p) --> %s",
             socket_number(s), bufs, DWORD_CAST(num_bufs), nbytes, flg, ov, func, res);

    if (rc == NO_ERROR && g_cfg.dump_data)
    {
      WSABUF bufs2;

      bufs2.buf = bufs->buf;
      bufs2.len = num_bytes ? *num_bytes : size;
      dump_wsabuf (&bufs2, 1);
    }

    if (ov)
       overlap_store (s, ov, size, TRUE);
  }

  if (g_cfg.PCAP.enable)
     write_pcap_packetv (s, bufs, num_bufs, FALSE);

  LEAVE_CRIT();

  if (g_cfg.recv_delay)
     SleepEx (g_cfg.recv_delay, FALSE);

  return (rc);
}

EXPORT int WINAPI WSARecvFrom (SOCKET s, WSABUF *bufs, DWORD num_bufs, DWORD *num_bytes,
                               DWORD *flags, struct sockaddr *from, INT *from_len,
                               WSAOVERLAPPED *ov, LPWSAOVERLAPPED_COMPLETION_ROUTINE func)
{
  DWORD size;
  int   rc;

  CHECK_PTR (p_WSARecvFrom);
  rc = (*p_WSARecvFrom) (s, bufs, num_bufs, num_bytes, flags, from, from_len, ov, func);

  ENTER_CRIT();

  exclude_this = (g_cfg.trace_level == 0 || exclude_list_get("WSARecvFrom", EXCL_FUNCTION));
  size = bufs->len * num_bufs;

  if (rc == NO_ERROR)
  {
    /* If the transfer is overlapped this counter should be
     * updated in 'WSAGetOverlappedResult()'
     */
    g_cfg.counts.recv_bytes += size;
  }

  if (!exclude_this)
  {
    char        res[100];
    char        nbytes[20];
    const char *flg = flags ? socket_flags(*flags) : "NULL";

    if (num_bytes)
         _itoa (*num_bytes, nbytes, 10);
    else strcpy (nbytes, "??");

    strcpy (res, get_error(rc, 0));

    WSTRACE ("WSARecvFrom (%s, 0x%p, %lu, %s, <%s>, %s, 0x%p, 0x%p) --> %s",
             socket_number(s), bufs, DWORD_CAST(num_bufs), nbytes, flg,
             sockaddr_str2(from, from_len), ov, func, res);

    if (rc == NO_ERROR && g_cfg.dump_data)
    {
      WSABUF bufs2;

      bufs2.buf = bufs->buf;
      bufs2.len = num_bytes ? *num_bytes : size;
      dump_wsabuf (&bufs2, 1);
    }

    if ((*g_WSAGetLastError)() != WSA_IO_PENDING)
    {
      if (g_cfg.GEOIP.enable)
         dump_countries_sockaddr (from);

      if (g_cfg.DNSBL.enable)
         dump_DNSBL_sockaddr (from);
    }

    if (ov)
       overlap_store (s, ov, size, TRUE);
  }

  if (g_cfg.PCAP.enable)
     write_pcap_packetv (s, bufs, num_bufs, FALSE);

  LEAVE_CRIT();

  if (g_cfg.recv_delay)
     SleepEx (g_cfg.recv_delay, FALSE);

  return (rc);
}

EXPORT int WINAPI WSARecvEx (SOCKET s, char *buf, int buf_len, int *flags)
{
  int rc;

  CHECK_PTR (p_WSARecvEx);
  rc = (*p_WSARecvEx) (s, buf, buf_len, flags);

  ENTER_CRIT();

  exclude_this = (g_cfg.trace_level == 0 || exclude_list_get("WSARecvEx", EXCL_FUNCTION));

  if (rc >= 0)
       g_cfg.counts.recv_bytes += rc;
  else g_cfg.counts.recv_errors++;

  if (!exclude_this)
  {
    char res[100];
    const char *flg = flags ? socket_flags(*flags) : "NULL";

    if (rc == SOCKET_ERROR)
         strcpy (res, get_error(rc, 0));
    else sprintf (res, "%d bytes", rc);

    WSTRACE ("WSARecvEx (%s, 0x%p, %d, <%s>) --> %s",
             socket_number(s), buf, buf_len, flg, res);

    if (rc > 0 && g_cfg.dump_data)
       dump_data (buf, rc);
  }

  if (g_cfg.PCAP.enable)
     write_pcap_packet (s, buf, buf_len, FALSE);

  LEAVE_CRIT();

  if (g_cfg.recv_delay)
     SleepEx (g_cfg.recv_delay, FALSE);

  return (rc);
}

EXPORT int WINAPI WSARecvDisconnect (SOCKET s, WSABUF *disconnect_data)
{
  int rc;

  CHECK_PTR (p_WSARecvDisconnect);
  rc = (*p_WSARecvDisconnect) (s, disconnect_data);

  ENTER_CRIT();

  WSTRACE ("WSARecvDisconnect (%s, 0x%p) --> %s",
           socket_number(s), disconnect_data, get_error(rc, 0));

  if (!exclude_this && rc == NO_ERROR && g_cfg.dump_data)
     dump_data (disconnect_data->buf, disconnect_data->len);

  LEAVE_CRIT();

  if (g_cfg.recv_delay)
     SleepEx (g_cfg.recv_delay, FALSE);

  return (rc);
}

EXPORT int WINAPI WSASend (SOCKET s, WSABUF *bufs, DWORD num_bufs, DWORD *num_bytes,
                           DWORD flags, WSAOVERLAPPED *ov, LPWSAOVERLAPPED_COMPLETION_ROUTINE func)
{
  int rc;

  CHECK_PTR (p_WSASend);
  rc = (*p_WSASend) (s, bufs, num_bufs, num_bytes, flags, ov, func);

  ENTER_CRIT();

  if (rc == NO_ERROR)
  {
    /* If the transfer is overlapped this counter should be
     * updated in 'WSAGetOverlappedResult()'
     */
    g_cfg.counts.send_bytes += count_wsabuf (bufs, num_bufs);
  }

  exclude_this = (g_cfg.trace_level == 0 || exclude_list_get("WSASend", EXCL_FUNCTION));

  if (!exclude_this)
  {
    char res[100];
    char nbytes[20];

    if (num_bytes)
         _itoa (*num_bytes, nbytes, 10);
    else strcpy (nbytes, "??");

    strcpy (res, get_error(rc, 0));

    WSTRACE ("WSASend (%s, 0x%p, %lu, %s, <%s>, 0x%p, 0x%p) --> %s",
             socket_number(s), bufs, DWORD_CAST(num_bufs), nbytes,
             socket_flags(flags), ov, func, res);

    if (g_cfg.dump_data)
       dump_wsabuf (bufs, num_bufs);

    if (ov)
       overlap_store (s, ov, count_wsabuf(bufs, num_bufs), FALSE);
  }

  if (g_cfg.PCAP.enable)
     write_pcap_packetv (s, bufs, num_bufs, TRUE);

  LEAVE_CRIT();

  if (g_cfg.send_delay)
     SleepEx (g_cfg.send_delay, FALSE);

  return (rc);
}

EXPORT int WINAPI WSASendTo (SOCKET s, WSABUF *bufs, DWORD num_bufs, DWORD *num_bytes,
                             DWORD flags, const struct sockaddr *to, int to_len,
                             WSAOVERLAPPED *ov, LPWSAOVERLAPPED_COMPLETION_ROUTINE func)
{
  int rc;

  CHECK_PTR (p_WSASendTo);
  rc = (*p_WSASendTo) (s, bufs, num_bufs, num_bytes, flags, to, to_len, ov, func);

  ENTER_CRIT();

  if (rc == NO_ERROR)
  {
    /* If the transfer is overlapped this counter should be
     * updated in 'WSAGetOverlappedResult()'
     */
    g_cfg.counts.send_bytes += count_wsabuf (bufs, num_bufs);
  }

  exclude_this = (g_cfg.trace_level == 0 || exclude_list_get("WSASendTo", EXCL_FUNCTION));

  if (!exclude_this)
  {
    char res[100];
    char nbytes[20];

    if (num_bytes)
         _itoa (*num_bytes, nbytes, 10);
    else strcpy (nbytes, "??");

    strcpy (res, get_error(rc, 0));

    WSTRACE ("WSASendTo (%s, 0x%p, %lu, %s, <%s>, %s, 0x%p, 0x%p) --> %s",
             socket_number(s), bufs, DWORD_CAST(num_bufs), nbytes, socket_flags(flags),
             sockaddr_str2(to, &to_len), ov, func, res);

    if (g_cfg.dump_data)
       dump_wsabuf (bufs, num_bufs);

    if (g_cfg.GEOIP.enable)
       dump_countries_sockaddr (to);

    if (g_cfg.IANA.enable)
       dump_IANA_sockaddr (to);

    if (g_cfg.ASN.enable)
       dump_ASN_sockaddr (to);

    if (g_cfg.DNSBL.enable)
       dump_DNSBL_sockaddr (to);

    if (ov)
       overlap_store (s, ov, count_wsabuf(bufs, num_bufs), FALSE);
  }

  if (g_cfg.PCAP.enable)
     write_pcap_packetv (s, bufs, num_bufs, TRUE);

  LEAVE_CRIT();

  if (g_cfg.send_delay)
     SleepEx (g_cfg.send_delay, FALSE);

  return (rc);
}

EXPORT int WINAPI WSASendMsg (SOCKET s, WSAMSG *msg, DWORD flags, DWORD *num_bytes_sent,
                              WSAOVERLAPPED *ov, LPWSAOVERLAPPED_COMPLETION_ROUTINE func)
{
  int rc;

  CHECK_PTR (p_WSASendMsg);
  rc = (*p_WSASendMsg) (s, msg, flags, num_bytes_sent, ov, func);

  ENTER_CRIT();

  exclude_this = (g_cfg.trace_level == 0 || exclude_list_get("WSASendMsg", EXCL_FUNCTION));

  if (!exclude_this)
  {
    char res[100];

    strcpy (res, get_error(rc, 0));

    WSTRACE ("WSASendMsg (%s, 0x%p, ...) --> %s", socket_number(s), msg, res);
  }

  LEAVE_CRIT();
  return (rc);
}

EXPORT BOOL WINAPI WSAGetOverlappedResult (SOCKET s, WSAOVERLAPPED *ov, DWORD *transfered,
                                           BOOL wait, DWORD *flags)
{
  BOOL  rc;
  DWORD bytes = 0;
  char  xfer[10]  = "<N/A>";
  const char *flg = "<N/A>";

  CHECK_PTR (p_WSAGetOverlappedResult);
  rc = (*p_WSAGetOverlappedResult) (s, ov, &bytes, wait, flags);

  ENTER_CRIT();

  /* MSDN says "This parameter must not be a NULL pointer."
   * But test anyway.
   */
  if (transfered)
     _itoa (bytes, xfer, 10);

  if (flags)
     flg = wsasocket_flags_decode (*flags);

  WSTRACE ("WSAGetOverlappedResult (%s, 0x%p, %s, %d, %s) --> %s",
           socket_number(s), ov, xfer, wait, flg, get_error(rc, 0));

  if (transfered)
  {
    overlap_recall (s, ov, bytes);
    *transfered = bytes;
  }

  LEAVE_CRIT();
  return (rc);
}

#if defined(__WATCOMC__)
/*
 * Since OpenWatcom is so limited with regard to 'WSANETWORKEVENTS' etc.
 */
EXPORT int WINAPI WSAEnumNetworkEvents (SOCKET s, WSAEVENT ev, WSANETWORKEVENTS *events)
{
  int rc;

  CHECK_PTR (p_WSAEnumNetworkEvents);
  rc = (*p_WSAEnumNetworkEvents) (s, ev, events);

  ENTER_CRIT();

  WSTRACE ("WSAEnumNetworkEvents (%s, 0x%" ADDR_FMT ", 0x%" ADDR_FMT ") --> %s",
           socket_number(s), ADDR_CAST(ev), ADDR_CAST(events), get_error(rc, 0));

  LEAVE_CRIT();
  return (rc);
}

#else
EXPORT int WINAPI WSAEnumNetworkEvents (SOCKET s, WSAEVENT ev, WSANETWORKEVENTS *events)
{
  int rc, do_it = (g_cfg.trace_level > 0 && g_cfg.dump_wsanetwork_events);
  WSANETWORKEVENTS in_events;

  if (do_it && events)
       memcpy (&in_events, events, sizeof(in_events));
  else memset (&in_events, '\0', sizeof(in_events));

  CHECK_PTR (p_WSAEnumNetworkEvents);
  rc = (*p_WSAEnumNetworkEvents) (s, ev, events);

  ENTER_CRIT();

  WSTRACE ("WSAEnumNetworkEvents (%s, 0x%" ADDR_FMT ", 0x%" ADDR_FMT ") --> %s",
           socket_number(s), ADDR_CAST(ev), ADDR_CAST(events), get_error(rc, 0));

  if (rc == 0 && !exclude_this && do_it)
     dump_events (&in_events, events);

  LEAVE_CRIT();
  return (rc);
}
#endif  /* !__WATCOMC__ */

/*
 * This function is what the command "netsh WinSock Show Catalog" uses.
 */
EXPORT int WINAPI WSAEnumProtocolsA (int *protocols, WSAPROTOCOL_INFOA *proto_info, DWORD *buf_len)
{
  char buf[50], *p = buf;
  int  i, rc, do_it = (g_cfg.trace_level > 0 && g_cfg.dump_wsaprotocol_info);

  CHECK_PTR (p_WSAEnumProtocolsA);
  rc = (*p_WSAEnumProtocolsA) (protocols, proto_info, buf_len);

  ENTER_CRIT();

  if (do_it)
  {
    if (rc > 0)
         snprintf (buf, sizeof(buf), "num: %d, size: %lu", rc, DWORD_CAST(*buf_len));
    else p = (char*) get_error (rc, 0);
  }

  WSTRACE ("WSAEnumProtocolsA() --> %s", p);

  if (do_it && rc != SOCKET_ERROR && rc > 0 && !exclude_this)
  {
    for (i = 0; i < rc; i++)
    {
      trace_indent (g_cfg.trace_indent+2);
      trace_printf ("~1Provider Entry # %d:\n", i);
      dump_wsaprotocol_info ('A', proto_info + i, p_WSCGetProviderPath);
    }
  }

  LEAVE_CRIT();
  return (rc);
}

EXPORT int WINAPI WSAEnumProtocolsW (int *protocols, WSAPROTOCOL_INFOW *proto_info, DWORD *buf_len)
{
  char buf[50], *p = buf;
  int  i, rc, do_it = (g_cfg.trace_level > 0 && g_cfg.dump_wsaprotocol_info);

  CHECK_PTR (p_WSAEnumProtocolsW);
  rc = (*p_WSAEnumProtocolsW) (protocols, proto_info, buf_len);

  ENTER_CRIT();

  if (do_it)
  {
    if (rc > 0)
         snprintf (buf, sizeof(buf), "num: %d, size: %lu", rc, DWORD_CAST(*buf_len));
    else p = (char*) get_error (rc, 0);
  }

  WSTRACE ("WSAEnumProtocolsW() --> %s", p);

  if (do_it && rc != SOCKET_ERROR && rc > 0 && !exclude_this)
  {
    for (i = 0; i < rc; i++)
    {
      trace_indent (g_cfg.trace_indent+2);
      trace_printf ("~1Provider Entry # %d\n", i);
      dump_wsaprotocol_info ('W', proto_info + i, p_WSCGetProviderPath);
    }
  }

  LEAVE_CRIT();
  return (rc);
}

EXPORT int WINAPI WSACancelBlockingCall (void)
{
  int rc;

  CHECK_PTR (p_WSACancelBlockingCall);
  rc = (*p_WSACancelBlockingCall)();

  ENTER_CRIT();

  WSTRACE ("WSACancelBlockingCall() --> %s", get_error(rc, 0));

  LEAVE_CRIT();
  return (rc);
}

EXPORT int WINAPI WSAPoll (LPWSAPOLLFD fd_array, ULONG fds, int timeout_ms)
{
  int        rc;
  WSAPOLLFD *fd_in = NULL;
  char       ts_buf [40] = "";  /* timestamp at start of WSAPoll() */

  CHECK_PTR (p_WSAPoll);

  if (!p_WSAPoll)
     return (0);

  ENTER_CRIT();

  exclude_this = (g_cfg.trace_level == 0 || exclude_list_get("WSAPoll", EXCL_FUNCTION));

  if (!exclude_this)
     strcpy (ts_buf, get_timestamp());

  if (!exclude_this && fd_array)
  {
    size_t size = fds * sizeof(*fd_in);

    fd_in = alloca (size);
    memcpy (fd_in, fd_array, size);
  }

  rc = (*p_WSAPoll) (fd_array, fds, timeout_ms);

  if (!exclude_this)
  {
    char ms_buf[20];

    if (timeout_ms > 0)
         snprintf (ms_buf, sizeof(ms_buf), "%d ms", timeout_ms);
    else if (timeout_ms == 0)
         strcpy (ms_buf, "return imm.");
    else strcpy (ms_buf, "wait indef.");

    /* We want the timestamp for when WSAPoll() was called.
     * Not the timestamp for when WSAPoll() returned. Hence do not
     * use the WSTRACE() macro here.
     */
    wstrace_printf (TRUE, "~1* ~3%s~5%s: ~1",
                    ts_buf, get_caller(GET_RET_ADDR(), get_EBP()));

    wstrace_printf (FALSE, "WSAPoll (0x%" ADDR_FMT ", %lu, %s) --> %s",
                    ADDR_CAST(fd_array), DWORD_CAST(fds), ms_buf, socket_or_error(rc));

    trace_indent (g_cfg.trace_indent+2);
    trace_puts ("~4" FD_INPUT " ");
    if (fd_in)
         dump_wsapollfd (fd_in, fds, g_cfg.trace_indent + 2 + sizeof(FD_INPUT));
    else trace_puts ("None!\n");

    trace_indent (g_cfg.trace_indent+2);
    trace_puts (FD_OUTPUT " ");
    if (fd_array)
         dump_wsapollfd (fd_array, fds, g_cfg.trace_indent + 2 + sizeof(FD_OUTPUT));
    else trace_puts ("None!\n");
    trace_puts ("~0");
  }

  LEAVE_CRIT();

  if (g_cfg.poll_delay)
     SleepEx (g_cfg.poll_delay, FALSE);

  return (rc);
}

/* \todo:
 */
#if 0
EXPORT DWORD WaitForMultipleObjectsEx (DWORD         num_ev,
                                       const HANDLE *hnd,
                                       BOOL          wait_all,
                                       DWORD         timeout,
                                       BOOL          alertable)
{
}
#endif

EXPORT DWORD WINAPI WSAWaitForMultipleEvents (DWORD           num_ev,
                                              const WSAEVENT *ev,
                                              BOOL            wait_all,
                                              DWORD           timeout,
                                              BOOL            alertable)
{
  DWORD rc;

  if (p_WSAWaitForMultipleEvents == NULL)
  {
    /* This should maybe call '(*p_WaitForMultipleObjectsEx)()' when finished.
     */
    rc = WaitForMultipleObjectsEx (num_ev, (const HANDLE*)ev, wait_all, timeout, alertable);
  }
  else
  {
    CHECK_PTR (p_WSAWaitForMultipleEvents);
    rc = (*p_WSAWaitForMultipleEvents) (num_ev, ev, wait_all, timeout, alertable);
  }

  ENTER_CRIT();

  exclude_this = (g_cfg.trace_level == 0 || exclude_list_get("WSAWaitForMultipleEvents", EXCL_FUNCTION));

  if (!exclude_this)
  {
    char  buf[50];
    char  time[20]  = "WSA_INFINITE";
    const char *err = "Unknown";

    if (rc == WSA_WAIT_FAILED)
         err = get_error (rc, 0);
    else if (rc == WSA_WAIT_IO_COMPLETION)
         err = "WSA_WAIT_IO_COMPLETION";
    else if (rc == WSA_WAIT_TIMEOUT)
         err = "WSA_WAIT_TIMEOUT";
    else if (rc < (WSA_WAIT_EVENT_0 + num_ev))
    {
      if (wait_all)
           strcpy (buf, ", all completed");
      else snprintf (buf, sizeof(buf), "%lu completed", DWORD_CAST(rc-WSA_WAIT_EVENT_0));
      err = buf;
    }

    if (timeout != WSA_INFINITE)
       snprintf (time, sizeof(time), "%lu ms", DWORD_CAST(timeout));

    WSTRACE ("WSAWaitForMultipleEvents (%lu, 0x%p, %s, %s, %sALERTABLE) --> %s",
             DWORD_CAST(num_ev), ev, wait_all ? "TRUE" : "FALSE",
             time, alertable ? "" : "not ", err);

    /* Update all sockets with overlapped operations that matches this event.
     */
    if (rc < (WSA_WAIT_EVENT_0 + num_ev))
       overlap_recall_all (ev);
  }

  LEAVE_CRIT();
  return (rc);
}

EXPORT int WINAPI setsockopt (SOCKET s, int level, int opt, const char *opt_val, int opt_len)
{
  int rc;

  CHECK_PTR (p_setsockopt);
  rc = (*p_setsockopt) (s, level, opt, opt_val, opt_len);

  ENTER_CRIT();

  WSTRACE ("setsockopt (%s, %s, %s, %s, %d) --> %s",
           socket_number(s), socklevel_name(level), sockopt_name(level,opt),
           sockopt_value(opt_val, opt_len), opt_len, get_error(rc, 0));

  LEAVE_CRIT();
  return (rc);
}

EXPORT int WINAPI getsockopt (SOCKET s, int level, int opt, char *opt_val, int *opt_len)
{
  int rc;

  CHECK_PTR (p_getsockopt);
  rc = (*p_getsockopt) (s, level, opt, opt_val, opt_len);

  ENTER_CRIT();

  WSTRACE ("getsockopt (%s, %s, %s, %s, %d) --> %s",
           socket_number(s), socklevel_name(level), sockopt_name(level,opt),
           sockopt_value(opt_val, opt_len ? *opt_len : 0),
           opt_len ? *opt_len : 0, get_error(rc, 0));

#if 0  /* \todo */
  if (level == SOL_SOCKET && !exclude_this && g_cfg.dump_wsaprotocol_info)
  {
    if (opt == SO_PROTOCOL_INFOA)
       dump_wsaprotocol_info ('A', opt_val, p_WSCGetProviderPath);
    else if (opt == SO_PROTOCOL_INFOW)
       dump_wsaprotocol_info ('W', opt_val, p_WSCGetProviderPath);
  }
#endif

  LEAVE_CRIT();
  return (rc);
}

EXPORT int WINAPI shutdown (SOCKET s, int how)
{
  int rc;

  CHECK_PTR (p_shutdown);
  rc = (*p_shutdown) (s, how);

  ENTER_CRIT();

  WSTRACE ("shutdown (%s, %d) --> %s", socket_number(s), how, get_error(rc, 0));

  LEAVE_CRIT();
  return (rc);
}

EXPORT SOCKET WINAPI socket (int family, int type, int protocol)
{
  SOCKET rc;

  CHECK_PTR (p_socket);
  rc = (*p_socket) (family, type, protocol);

  ENTER_CRIT();

  WSTRACE ("socket (%s, %s, %s) --> %s",
           socket_family(family), socket_type(type), protocol_name(protocol),
           socket_or_error(rc));

  LEAVE_CRIT();
  return (rc);
}

EXPORT struct servent *WINAPI getservbyport (int port, const char *proto)
{
  struct servent *rc;

  CHECK_PTR (p_getservbyport);
  rc = (*p_getservbyport) (port, proto);

  ENTER_CRIT();

  WSTRACE ("getservbyport (%d, \"%s\") --> %s",
           swap16(port), proto, ptr_or_error(rc));

  if (rc && !exclude_this && g_cfg.dump_servent)
     dump_servent (rc);

  LEAVE_CRIT();
  return (rc);
}

EXPORT struct servent *WINAPI getservbyname (const char *serv, const char *proto)
{
  struct servent *rc;

  CHECK_PTR (p_getservbyname);
  rc = (*p_getservbyname) (serv, proto);

  ENTER_CRIT();

  WSTRACE ("getservbyname (\"%s\", \"%s\") --> %s",
           serv, proto, ptr_or_error(rc));

  if (rc && !exclude_this && g_cfg.dump_servent)
     dump_servent (rc);

  LEAVE_CRIT();
  return (rc);
}

EXPORT struct hostent *WINAPI gethostbyname (const char *name)
{
  struct hostent *rc;

  CHECK_PTR (p_gethostbyname);
  rc = (*p_gethostbyname) (name);

  ENTER_CRIT();

  WSTRACE ("gethostbyname (\"%s\") --> %s", name, ptr_or_error(rc));

  if (rc && !exclude_this && g_cfg.dump_hostent)
     dump_hostent (name, rc);

  if (rc && !exclude_this)
  {
    if (g_cfg.GEOIP.enable)
       dump_countries (rc->h_addrtype, (const char**)rc->h_addr_list);

    if (g_cfg.IANA.enable)
       dump_IANA_addresses (rc->h_addrtype, (const char**)rc->h_addr_list);

    if (g_cfg.ASN.enable)
       dump_ASN_addresses (rc->h_addrtype, (const char**)rc->h_addr_list);

    if (g_cfg.DNSBL.enable)
       dump_DNSBL (rc->h_addrtype, (const char**)rc->h_addr_list);
  }
  LEAVE_CRIT();
  return (rc);
}

EXPORT struct hostent *WINAPI gethostbyaddr (const char *addr, int len, int type)
{
  struct hostent *rc;

  CHECK_PTR (p_gethostbyaddr);
  rc = (*p_gethostbyaddr) (addr, len, type);

  ENTER_CRIT();

#if defined(USE_BFD)
  // test_get_caller (&gethostbyaddr);
#endif

  WSTRACE ("gethostbyaddr (%s, %d, %s) --> %s",
           inet_ntop2(addr, type), len, socket_family(type), ptr_or_error(rc));

#if defined(__clang__)
  // test_get_caller (&gethostbyaddr);
#endif

  if (!exclude_this)
  {
    const char *a[2];

    if (rc && g_cfg.dump_hostent)
       dump_hostent (rc->h_name, rc);

    a[0] = addr;
    a[1] = NULL;

    if (g_cfg.GEOIP.enable)
    {
      if (rc)
           dump_countries (rc->h_addrtype, (const char**)rc->h_addr_list);
      else dump_countries (type, a);
    }
    if (g_cfg.IANA.enable)
    {
      if (rc)
           dump_IANA_addresses (rc->h_addrtype, (const char**)rc->h_addr_list);
      else dump_IANA_addresses (type, a);
    }
    if (g_cfg.ASN.enable)
    {
      if (rc)
           dump_ASN_addresses (rc->h_addrtype, (const char**)rc->h_addr_list);
      else dump_ASN_addresses (type, a);
    }

    if (g_cfg.DNSBL.enable)
    {
      if (rc)
           dump_DNSBL (rc->h_addrtype, (const char**)rc->h_addr_list);
      else dump_DNSBL (type, a);
    }
  }

  LEAVE_CRIT();
  return (rc);
}

EXPORT u_short WINAPI htons (u_short x)
{
  u_short rc;

  CHECK_PTR (p_htons);
  rc = (*p_htons) (x);

  ENTER_CRIT();
  WSTRACE ("htons (%u) --> %u", x, rc);
  LEAVE_CRIT();
  return (rc);
}

EXPORT u_short WINAPI ntohs (u_short x)
{
  u_short rc;

  CHECK_PTR (p_ntohs);
  rc = (*p_ntohs) (x);

  ENTER_CRIT();
  WSTRACE ("ntohs (%u) --> %u", x, rc);
  LEAVE_CRIT();
  return (rc);
}

EXPORT __ms_u_long WINAPI htonl (__ms_u_long x)
{
  __ms_u_long rc;

  CHECK_PTR (p_htonl);
  rc = (*p_htonl) (x);

  ENTER_CRIT();
  WSTRACE ("htonl (%lu) --> %lu", DWORD_CAST(x), DWORD_CAST(rc));
  LEAVE_CRIT();
  return (rc);
}

EXPORT __ms_u_long WINAPI ntohl (__ms_u_long x)
{
  __ms_u_long rc;

  CHECK_PTR (p_ntohl);
  rc = (*p_ntohl) (x);

  ENTER_CRIT();
  WSTRACE ("ntohl (%lu) --> %lu", DWORD_CAST(x), DWORD_CAST(rc));
  LEAVE_CRIT();
  return (rc);
}

EXPORT __ULONG32 WINAPI inet_addr (const char *addr)
{
  __ULONG32 rc;

  CHECK_PTR (p_inet_addr);
  rc = (*p_inet_addr) (addr);

  ENTER_CRIT();
  WSTRACE ("inet_addr (\"%s\") --> %lu", addr, DWORD_CAST(rc));
  LEAVE_CRIT();
  return (rc);
}

EXPORT char * WINAPI inet_ntoa (struct in_addr addr)
{
  char *rc;

  CHECK_PTR (p_inet_ntoa);
  rc = (*p_inet_ntoa) (addr);

  ENTER_CRIT();
  WSTRACE ("inet_ntoa (%u.%u.%u.%u) --> %s",
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

  CHECK_PTR (p_getpeername);
  rc = (*p_getpeername) (s, name, name_len);

  ENTER_CRIT();

  WSTRACE ("getpeername (%s, %s) --> %s",
           socket_number(s), sockaddr_str2(name, name_len), get_error(rc, 0));

  if (!exclude_this)
  {
    if (g_cfg.GEOIP.enable)
       dump_countries_sockaddr (name);

    if (g_cfg.IANA.enable)
       dump_IANA_sockaddr (name);

    if (g_cfg.ASN.enable)
       dump_ASN_sockaddr (name);

    if (g_cfg.DNSBL.enable)
       dump_DNSBL_sockaddr (name);
  }

  LEAVE_CRIT();
  return (rc);
}

EXPORT int WINAPI getsockname (SOCKET s, struct sockaddr *name, int *name_len)
{
  int rc;

  CHECK_PTR (p_getsockname);
  rc = (*p_getsockname) (s, name, name_len);

  ENTER_CRIT();

  WSTRACE ("getsockname (%s, %s) --> %s",
           socket_number(s), sockaddr_str2(name, name_len), get_error(rc, 0));

  if (!exclude_this)
  {
    if (g_cfg.GEOIP.enable)
       dump_countries_sockaddr (name);

    if (g_cfg.IANA.enable)
       dump_IANA_sockaddr (name);

    if (g_cfg.ASN.enable)
       dump_ASN_sockaddr (name);

    if (g_cfg.DNSBL.enable)
       dump_DNSBL_sockaddr (name);
  }

  LEAVE_CRIT();
  return (rc);
}

EXPORT struct protoent * WINAPI getprotobynumber (int num)
{
  struct protoent *rc;

  CHECK_PTR (p_getprotobynumber);
  rc = (*p_getprotobynumber) (num);

  ENTER_CRIT();

  WSTRACE ("getprotobynumber (%d) --> %s", num, ptr_or_error(rc));

  if (rc && !exclude_this && g_cfg.dump_protoent)
     dump_protoent (rc);

  LEAVE_CRIT();
  return (rc);
}

EXPORT struct protoent * WINAPI getprotobyname (const char *name)
{
  struct protoent *rc;

  CHECK_PTR (p_getprotobyname);
  rc = (*p_getprotobyname) (name);

  ENTER_CRIT();

  WSTRACE ("getprotobyname (\"%s\") --> %s", name, ptr_or_error(rc));

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

  CHECK_PTR (p_getnameinfo);
  rc = (*p_getnameinfo) (sa, sa_len, host, host_size, serv_buf, serv_buf_size, flags);

  ENTER_CRIT();

  WSTRACE ("getnameinfo (%s, ..., %s) --> %s",
           sockaddr_str2(sa, &sa_len), getnameinfo_flags_decode(flags), get_error(rc, 0));

  if (!exclude_this)
  {
    if (rc == 0 && g_cfg.dump_nameinfo)
       dump_nameinfo (host, serv_buf, flags);

    if (g_cfg.GEOIP.enable)
       dump_countries_sockaddr (sa);

    if (g_cfg.IANA.enable)
       dump_IANA_sockaddr (sa);

    if (g_cfg.ASN.enable)
       dump_ASN_sockaddr (sa);

    if (g_cfg.DNSBL.enable)
       dump_DNSBL_sockaddr (sa);
  }

  LEAVE_CRIT();
  return (rc);
}

EXPORT int WINAPI getaddrinfo (const char *host_name, const char *serv_name,
                               const struct addrinfo *hints, struct addrinfo **res)
{
  int rc;

  CHECK_PTR (p_getaddrinfo);

  ENTER_CRIT();

  rc = (*p_getaddrinfo) (host_name, serv_name, hints, res);

  /**
   * If no address was found for the `host_name`, then convert it to ACE-form and call
   * `*p_getaddrinfo()` again with the converted host-name from `IDNA_convert_to_ACE()`.
   */
#if 1
  if (rc != 0 && g_cfg.IDNA.enable && g_cfg.IDNA.fix_getaddrinfo && !IDNA_is_ASCII(host_name))
  {
    char   buf [MAX_HOST_LEN] = "?";
    size_t size;

    _strlcpy (buf, host_name, sizeof(buf));
    size = strlen (buf);
    if (IDNA_convert_to_ACE(buf, &size))
    {
      host_name = buf;
      rc = (*p_getaddrinfo) (host_name, serv_name, hints, res);
    }
  }
#endif

  WSTRACE ("getaddrinfo (\"%s\", %s, <hints>, ...) --> %s\n"
           "%*shints: %s",
           host_name, serv_name, get_error(rc, 0),
           g_cfg.trace_indent+4, "",
           hints ? get_addrinfo_hint(hints,g_cfg.trace_indent+3+sizeof("hints: ")) : "<none>");

  if (rc == 0 && *res && !exclude_this)
  {
    if (g_cfg.dump_data)
       dump_addrinfo (host_name, *res);

    if (g_cfg.GEOIP.enable)
       dump_countries_addrinfo (*res);

    if (g_cfg.IANA.enable)
       dump_IANA_addrinfo (*res);

    if (g_cfg.ASN.enable)
       dump_ASN_addrinfo (*res);

    if (g_cfg.DNSBL.enable)
       dump_DNSBL_addrinfo (*res);
  }

  LEAVE_CRIT();
  return (rc);
}

EXPORT void WINAPI freeaddrinfo (struct addrinfo *ai)
{
  CHECK_PTR (p_freeaddrinfo);
  (*p_freeaddrinfo) (ai);

  ENTER_CRIT();
  WSTRACE ("freeaddrinfo (0x%" ADDR_FMT ")", ADDR_CAST(ai));
  LEAVE_CRIT();
}

#if (defined(__MINGW32__) && !defined(__MINGW64_VERSION_MAJOR)) || defined(__WATCOMC__)
  #define ADDRINFOW  void *
  #define PADDRINFOW void *
#endif

#define UNIMPLEMENTED() FATAL ("Call to unimplemented function %s().\n", __FUNCTION__)

EXPORT void WINAPI FreeAddrInfoW (PADDRINFOW addr_info)
{
  ARGSUSED (addr_info);
  UNIMPLEMENTED();
}

EXPORT INT WINAPI GetAddrInfoW (PCWSTR           node_name,
                                PCWSTR           service_name,
                                const ADDRINFOW *hints,
                                PADDRINFOW      *result)
{
  UNIMPLEMENTED();
  ARGSUSED (node_name);
  ARGSUSED (service_name);
  ARGSUSED (hints);
  ARGSUSED (result);
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
  ARGSUSED (sockaddr);
  ARGSUSED (sockaddr_len);
  ARGSUSED (node_buf);
  ARGSUSED (node_buf_size);
  ARGSUSED (service_buf);
  ARGSUSED (service_buf_size);
  ARGSUSED (flags);
  return (-1);
}

EXPORT INET_NTOP_RET WINAPI inet_ntop (INT af, INET_NTOP_ADDR src, PSTR dst, size_t size)
{
  INET_NTOP_RET ret;
  int err = 0;

  CHECK_PTR (p_inet_ntop);

  if (p_inet_ntop)
       ret = (*p_inet_ntop) (af, src, dst, size);
  else ret = _wsock_trace_inet_ntop (af, src, dst, size, &err);

  ENTER_CRIT();

  if (ret)
       WSTRACE ("inet_ntop (%s, 0x%p, 0x%p, %u) --> \"%s\"", socket_family(af), src, dst, (u_int)size, ret);
  else WSTRACE ("inet_ntop (%s, 0x%p, 0x%p, %u) --> %s", socket_family(af), src, dst, (u_int)size, get_error(-1, err));

  LEAVE_CRIT();
  return (ret);
}

EXPORT int WINAPI inet_pton (int af, const char *src, void *dst)
{
  int ret, err = 0;

  CHECK_PTR (p_inet_pton);

  if (p_inet_pton)
       ret = (*p_inet_pton) (af, src, dst);
  else ret = _wsock_trace_inet_pton (af, src, dst, &err);

  ENTER_CRIT();

  /*
   * From: https://docs.microsoft.com/en-us/windows/win32/api/ws2tcpip/nf-ws2tcpip-inet_pton
   *
   * The InetPton function returns a value of 0 if the pAddrBuf parameter points to a string
   * that is not a valid IPv4 dotted-decimal string or a valid IPv6 address string.
   * Otherwise, a value of -1 is returned, and a specific error code can be retrieved by
   * calling the WSAGetLastError for extended error information.
   *
   * Meaning we cannot call 'get_error(-1, err)' when 'ret == 0'.
   * Hence set our local-error to 'WSAEINVAL'.
   */
  if (ret == 0)
     err = WSAEINVAL;

  if (ret <= 0)
       WSTRACE ("inet_pton (%s, \"%s\", 0x%p) --> %s", socket_family(af), src, dst, get_error(-1, err));
  else WSTRACE ("inet_pton (%s, \"%s\", 0x%p) --> %d", socket_family(af), src, dst, ret);

  LEAVE_CRIT();
  return (ret);
}

/**
 * These may be needed by some Win-Vista+ applications
 */
EXPORT int WINAPI InetPtonW (int family, PCWSTR waddr, void *waddr_dest)
{
  int ret;

  CHECK_PTR (p_InetPtonW);
  ret = (*p_InetPtonW) (family, waddr, waddr_dest);

  ENTER_CRIT();

  WSTRACE ("InetPtonW (%d, \"%" WCHAR_FMT "\", 0x%p) --> %d", family, waddr, waddr_dest, ret);

  LEAVE_CRIT();
  return (ret);
}

/* Undo the Cygwin hack at the top.
 */
#if defined(__CYGWIN__)
#undef InetNtopW
#endif

/**
 * \note there is no `InetNtopA()` function since the Winsock headers has a:
 * ```
 *  #define InetNtopA  inet_ntop
 * ```
 */
EXPORT PCWSTR WINAPI InetNtopW (int af, const void *addr, PWSTR res_buf, size_t res_buf_size)
{
  PCWSTR ret;

  CHECK_PTR (p_InetNtopW);
  ret = (*p_InetNtopW) (af, addr, res_buf, res_buf_size);

  ENTER_CRIT();

  if (!ret)
       WSTRACE ("InetNtopW (%s, 0x%p, 0x%p, %u) --> %s",
                socket_family(af), addr, res_buf, (u_int)res_buf_size, get_error(-1, 0));
  else WSTRACE ("InetNtopW (%s, 0x%p, 0x%p, %u) --> \"%" WCHAR_FMT "\"",
                socket_family(af), addr, res_buf, (u_int)res_buf_size, res_buf);

  LEAVE_CRIT();
  return (ret);
}

/****************** Internal utility functions **********************************/

static const char *get_caller (ULONG_PTR ret_addr, ULONG_PTR ebp)
{
  static int reentry = 0;
  char  *ret = NULL;

  WSAERROR_PUSH();

  if (reentry++)
  {
    ret = "get_caller() reentry. Breaking out.";
    g_cfg.reentries++;
  }
  else if (g_cfg.callee_level == 0)
  {
    ret = "~1";
  }
  else
  {
    CONTEXT ctx;
    HANDLE  thr = GetCurrentThread();

#if !defined(USE_BFD)       /* All compilers if 'USE_BFD' is undefined for MinGW/CygWin */
    void   *frames [10];
    USHORT  num_frames;

    memset (frames, '\0', sizeof(frames));
    num_frames = (*p_RtlCaptureStackBackTrace) (0, DIM(frames), frames, NULL);
    if (num_frames <= 2)
    {
      ret = "No stack";

#if defined(__clang__)
     /*
      * The flag '-Oy-' turns off frame pointer omission.
      */
      TRACE (2, "RtlCaptureStackBackTrace(): %d; add '-Oy-' to your CFLAGS.\n", num_frames);

#elif defined(_MSC_VER)
     /*
      * The MSVC flag '-Ox' (maximum optimizations) breaks the assumption for
      * 'RtlCaptureStackBackTrace()'. Hence warn strongly against it.
      */
      TRACE (2, "RtlCaptureStackBackTrace(): %d; Do not use '-Ox' in your CFLAGS.\n", num_frames);
#endif
      goto quit;
    }

#if !defined(__GNUC__)
    /*
     * For MSVC/clang-cl/Watcom (USE_BFD undefined), the passed 'ret_addr' is
     * always 0. We have to get it from 'frames[2]'.
     */
    ret_addr = (ULONG_PTR) frames [2];
#endif
#endif  /* USE_BFD */

    /* We don't need a CONTEXT_FULL; only EIP+EBP (or RIP+RBP for x64). We want the caller's
     * address of a traced function (e.g. select()). Since we're called twice, that address
     * (for MSVC/PDB files) should be at frames[2]. For gcc, the RtlCaptureStackBackTrace()
     * doesn't work. I've had to use __builtin_return_addres(0) (='ret_addr').
     */
#ifdef _WIN64
    ctx.Rip = ret_addr;
    ctx.Rbp = ebp;       /* = 0 */
#else
    ctx.Eip = ret_addr;
    ctx.Ebp = ebp;
#endif

    ret = StackWalkShow (thr, &ctx);

#if !defined(USE_BFD)
    if (g_cfg.callee_level > 1 && num_frames > 2 && frames[3])
    {
      char *a, *b;

#ifdef _WIN64
      ctx.Rip = (ULONG_PTR) frames [3];
#else
      ctx.Eip = (ULONG_PTR) frames [3];
#endif

      a = strdup (ret);
      b = strdup (StackWalkShow (thr, &ctx));
      ret = malloc (strlen(a)+strlen(b)+50);
      sprintf (ret, "%s\n               %s", a, b);
    }
#endif
  }

#ifndef USE_BFD /* Avoid a '-Wunused-label' warning */
quit:
#endif

  reentry--;
  WSAERROR_POP();
  return (ret);
}

#if defined(USE_BFD)  /* MinGW / CygWin implied */

extern ULONG_PTR _image_base__;

#define FILL_STACK_ADDRESS(X) \
        stack_addr[X] = (ULONG_PTR) __builtin_return_address (X)

static void test_get_caller (const void *from)
{
  ULONG_PTR stack_addr [3];
  ULONG_PTR frame_diff;
  void     *frames [5];
  int       i, num;
  char      buf[100];

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
  frame_diff = ADDR_CAST(frames[0]) - ADDR_CAST(from);
  TRACE (1, "BFD_get_function_name(from): %s, frames[0] - from: 0x%02lX\n", buf, DWORD_CAST(frame_diff));
  exit (0);
}

#elif defined(__clang__)

#include <imagehlp.h>

static void test_get_caller (const void *from)
{
  CONTEXT     ctx;
  HANDLE      thr = GetCurrentThread();
  void       *frames [5];
  const char *ret;
  int         i, num;

  memset (frames, '\0', sizeof(frames));
  num = (*p_RtlCaptureStackBackTrace) (1, DIM(frames), frames, NULL);

  for (i = 0; i < num; i++)
  {
    ret = "<none>";
    if (i == 0)
    {
#ifdef _WIN64
      ctx.Rip = (ULONG_PTR) frames [i];
      ctx.Rbp = 0;
#else
      ctx.Eip = (DWORD) frames[i];
      ctx.Ebp = 0;
#endif
      ret = StackWalkShow (thr, &ctx);
    }
    TRACE (1, "frames[%d]: 0x%" ADDR_FMT ", ret: %s\n", i, ADDR_CAST(frames[i]), ret);
  }
  ARGSUSED (from);

#if 0
  void *stk_p = NULL;
  STACKFRAME64 *stk;

  memset (&ctx, '\0', sizeof(ctx));
  ctx.ContextFlags = CONTEXT_FULL;
  GetThreadContext (thr, &ctx);
  ctx.Eip = (DWORD) from;
  ctx.Ebp = 0;
  ret = StackWalkShow2 (thr, &ctx, &stk_p);
  TRACE (1, "from: 0x%" ADDR_FMT ", ret: %s\n", ADDR_CAST(from), ret);

  stk = (STACKFRAME64*) stk_p;
  ctx.Eip = stk->AddrPC.Offset;
  ctx.Ebp = 0;
  ret = StackWalkShow2 (thr, &ctx, &stk_p);
  TRACE (1, "from: 0x%" ADDR_FMT ", ret: %s\n", ADDR_CAST(from), ret);
#endif
}
#endif  /* USE_BFD */

/**
 * The `wsock_trace*.dll` main entry point.
 */
BOOL WINAPI DllMain (HINSTANCE instDLL, DWORD reason, LPVOID reserved)
{
  const char *reason_str = NULL;
  DWORD tid = 0;
  BOOL  rc = TRUE;

  g_cfg.from_dll_main = TRUE;  /* signal we're called via DllMain() */

  switch (reason)
  {
    case DLL_PROCESS_ATTACH:
         set_dll_full_name (instDLL);
         tid = GetCurrentThreadId();
         reason_str = "DLL_PROCESS_ATTACH";
         crtdbg_init();
         wsock_trace_init();
      // smartlist_add (thread_list, tid);

#if defined(USE_LUA)
         rc = wslua_DllMain (instDLL, reason);
#endif
         break;

    case DLL_PROCESS_DETACH:
         tid = GetCurrentThreadId();
      // smartlist_remove (thread_list, tid);

#if defined(USE_LUA)
         wslua_DllMain (instDLL, reason);
#endif
         wsock_trace_exit();
         crtdbg_exit();
         break;

    case DLL_THREAD_ATTACH:
         tid = GetCurrentThreadId();
         g_cfg.counts.dll_attach++;
         reason_str = "DLL_THREAD_ATTACH";

         /** \todo
          *  Add this `tid` as a new thread to a `smartlist_t` and call `print_thread_times()`
          *  for it when `DLL_PROCESS_DETACH` is received.
          */
#if defined(USE_LUA)
         rc = wslua_DllMain (instDLL, reason);
#endif
         break;

    case DLL_THREAD_DETACH:
         tid = GetCurrentThreadId();
         g_cfg.counts.dll_detach++;
         reason_str = "DLL_THREAD_DETACH";
         if (g_cfg.trace_level >= 3)
         {
           HANDLE hnd = OpenThread (THREAD_QUERY_INFORMATION, FALSE, tid);

           print_thread_times (hnd);
         }
         /** \todo
          *  Instead of calling `print_thread_times()` here, add this `tid` as
          *  dying thread and call `print_thread_times()` for all threads (alive or dead) when
          *  `DLL_PROCESS_DETACH` is received.
          */
#if defined(USE_LUA)
         rc = wslua_DllMain (instDLL, reason);
#endif
         break;
  }

#if !defined(__CYGWIN__)
  if (reason_str)
     TRACE (2, "rc: %d, %s. instDLL: 0x%" ADDR_FMT ", thr-id: %lu, ws_sema_inherited: %d.\n",
            rc, reason_str, ADDR_CAST(instDLL), DWORD_CAST(tid), ws_sema_inherited);
#else
  ARGSUSED (reason_str);
#endif

  ARGSUSED (reserved);
  return (rc);
}


