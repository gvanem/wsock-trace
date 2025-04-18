/**
 * \file wsock_hooks.c
 * \ingroup Main
 *
 * \brief Hooking and tracing of Winsock extension functions returned in
 *   `WSAIoctl (s, SIO_GET_EXTENSION_FUNCTION_POINTER,...)`. <br>
 *   This file **must** be included from wsock_trace.c since it needs several
 *   static data defintions.
 */
#if !defined(IN_WSOCK_TRACE_C)
#error "Include this file in wsock_trace.c only."
#endif

#include <MSWSock.h>

/* We need to have all these GUIDs defined to compile this.
 */
#if defined(WSAID_ACCEPTEX)             && \
    defined(WSAID_CONNECTEX)            && \
    defined(WSAID_DISCONNECTEX)         && \
    defined(WSAID_GETACCEPTEXSOCKADDRS) && \
    defined(WSAID_TRANSMITFILE)         && \
    defined(WSAID_TRANSMITPACKETS)      && \
    defined(WSAID_WSARECVMSG)           && \
    defined(WSAID_WSASENDMSG)           && \
    defined(WSAID_WSAPOLL)
  #define HAVE_WSA_EXTENSIONS_FUNCTIONS 1

#elif defined(__GNUC__)
  #pragma message ("HAVE_WSA_EXTENSIONS_FUNCTIONS not possible.")
#endif

#if defined(HAVE_WSA_EXTENSIONS_FUNCTIONS)   /* Rest of file */

typedef BOOL (PASCAL *extension_func) (void);

/* A copy of the awful 'LPWSAOVERLAPPED_COMPLETION_ROUTINE' typedef.
 */
typedef void (PASCAL *WSAOVERLAPPED_COMPLETION_ROUTINE) (
                      DWORD          dwError,
                      DWORD          cbTransferred,
                      WSAOVERLAPPED *Overlapped,
                      DWORD          dwFlags);

typedef enum ext_enum {
        ex_ACCEPTEX = 0,
        ex_CONNECTEX,
        ex_DISCONNECTEX,
        ex_GETACCEPTEXSOCKADDRS,
        ex_TRANSMITFILE,
        ex_TRANSMITPACKETS,
        ex_WSARECVMSG,
        ex_WSASENDMSG,
        ex_WSAPOLL,
        ex_NONE
      } extensions;

/* Search-list for GUIDs of extension functions.
 */
struct extension_hook_list {
       extensions  ext;
       GUID        guid;
       const char *guid_name;
     };

/**
 * \todo These should be in "Thread Local Storage"
 */
static LPFN_ACCEPTEX             orig_ACCEPTEX;
static LPFN_CONNECTEX            orig_CONNECTEX;
static LPFN_DISCONNECTEX         orig_DISCONNECTEX;
static LPFN_GETACCEPTEXSOCKADDRS orig_GETACCEPTEXSOCKADDRS;
static LPFN_TRANSMITFILE         orig_TRANSMITFILE;
static LPFN_TRANSMITPACKETS      orig_TRANSMITPACKETS;
static LPFN_WSARECVMSG           orig_WSARECVMSG;
static LPFN_WSASENDMSG           orig_WSASENDMSG;
static LPFN_WSAPOLL              orig_WSAPOLL;

static BOOL PASCAL hooked_ACCEPTEX (SOCKET      listen_sock,
                                    SOCKET      accept_sock,
                                    void*       out_buf,
                                    DWORD       recv_data_len,
                                    DWORD       local_addr_len,
                                    DWORD       remote_addr_len,
                                    DWORD      *bytes_received,
                                    OVERLAPPED *ov)
{
  BOOL rc = (*orig_ACCEPTEX) (listen_sock, accept_sock, out_buf, recv_data_len,
                              local_addr_len, remote_addr_len, bytes_received, ov);

  ENTER_CRIT();
  WSTRACE ("AcceptEx (%s, %s, ...) (ex-func) --> %s",
           socket_number(listen_sock), socket_number(accept_sock), get_error(rc, 0));
  LEAVE_CRIT (!exclude_this);
  return (rc);
}

static BOOL PASCAL hooked_CONNECTEX (SOCKET                 s,
                                     const struct sockaddr *name,
                                     int                    name_len,
                                     void                  *send_buf,
                                     DWORD                  send_data_len,
                                     DWORD                 *bytes_sent,
                                     OVERLAPPED            *ov)
{
  BOOL rc = (*orig_CONNECTEX) (s, name, name_len, send_buf, send_data_len, bytes_sent, ov);

  ENTER_CRIT();
  WSTRACE ("ConnectEx (%s, ...) (ex-func) --> %s", socket_number(s), get_error(rc, 0));

  if (g_cfg.dump_data && send_buf && (rc != SOCKET_ERROR || WSAERROR_PUSH() == ERROR_IO_PENDING))
     dump_data (send_buf, send_data_len);

  LEAVE_CRIT (!exclude_this);
  return (rc);
}

static BOOL PASCAL hooked_DISCONNECTEX (SOCKET      s,
                                        OVERLAPPED *ov,
                                        DWORD       flags,
                                        DWORD       reserved)
{
  BOOL rc = (*orig_DISCONNECTEX) (s, ov, flags, reserved);

  ENTER_CRIT();
  WSTRACE ("DisconnectEx (%s, ...) (ex-func) --> %s",
           socket_number(s), get_error(rc, 0));
  LEAVE_CRIT (!exclude_this);
  return (rc);
}

static void PASCAL hooked_GETACCEPTEXSOCKADDRS (void             *out_buf,
                                                DWORD             recv_data_len,
                                                DWORD             local_addr_len,
                                                DWORD             remote_addr_len,
                                                struct sockaddr **local_sa,
                                                INT              *local_sa_len,
                                                struct sockaddr **remote_sa,
                                                INT              *remote_sa_len)
{
  (*orig_GETACCEPTEXSOCKADDRS) (out_buf, recv_data_len, local_addr_len,
                                remote_addr_len, local_sa, local_sa_len,
                                remote_sa, remote_sa_len);
  ENTER_CRIT();
  WSTRACE ("GetAcceptExSockaddr (...) (ex-func)");
  LEAVE_CRIT (!exclude_this);
}

static BOOL PASCAL hooked_TRANSMITFILE (SOCKET                 s,
                                        HANDLE                 file,
                                        DWORD                  bytes_to_write,
                                        DWORD                  bytes_per_send,
                                        OVERLAPPED            *ov,
                                        TRANSMIT_FILE_BUFFERS *transmit_bufs,
                                        DWORD                  reserved)
{
  BOOL rc = (*orig_TRANSMITFILE) (s, file, bytes_to_write, bytes_per_send,
                                  ov, transmit_bufs, reserved);
  ENTER_CRIT();
  WSTRACE ("TransmitFile (%s, ...) (ex-func) --> %s", socket_number(s), get_error(rc, 0));
  LEAVE_CRIT (!exclude_this);
  return (rc);
}

static BOOL PASCAL hooked_TRANSMITPACKETS (SOCKET                    s,
                                           TRANSMIT_PACKETS_ELEMENT *packet_array,
                                           DWORD                     elements,
                                           DWORD                     transmit_size,
                                           OVERLAPPED               *ov,
                                           DWORD                     flags)
{
  BOOL rc = (*orig_TRANSMITPACKETS) (s, packet_array, elements, transmit_size, ov, flags);

  ENTER_CRIT();
  WSTRACE ("TransmitPackets (%s, ...) (ex-func) --> %s", socket_number(s), get_error(rc, 0));
  LEAVE_CRIT (!exclude_this);
  return (rc);
}

static INT PASCAL hooked_WSARECVMSG (SOCKET          s,
                                     WSAMSG         *msg,
                                     DWORD          *bytes_recv,
                                     WSAOVERLAPPED  *ov,
                                     WSAOVERLAPPED_COMPLETION_ROUTINE complete_func)
{
  char recv [20] = "?";
  INT  rc;

  WSAERROR_PUSH();

  rc = (*orig_WSARECVMSG) (s, msg, bytes_recv, ov, complete_func);

  ENTER_CRIT();

  if (bytes_recv)
  {
    WSAMSG copy;
    WSABUF wcopy;

    _itoa (*bytes_recv, recv, 10);

    memset (&copy, '\0', sizeof(copy));
    memset (&wcopy, '\0', sizeof(wcopy));
    wcopy.len          = *bytes_recv;
    wcopy.buf          = msg->lpBuffers ? msg->lpBuffers->buf : NULL;
    copy.lpBuffers     = &wcopy;
    copy.dwBufferCount = 1;
    copy.dwFlags       = msg->dwFlags;
    msg = &copy;

    if (rc == NO_ERROR || (*g_data.WSAGetLastError)() == WSA_IO_PENDING)
       g_data.counts.recv_bytes += *bytes_recv;
  }

  WSTRACE ("WSARecvMsg (%s, 0x%p, ...) (ex-func) --> %s, recv: %s",
           socket_number(s), msg, get_error(rc, 0), recv);

  if (rc != SOCKET_ERROR && !exclude_this)
  {
    C_printf ("~4%*src: %ld, msg->lpBuffers: 0x%p, msg->dwBufferCount: %lu~0\n",
              g_cfg.trace_indent+2, "", (long)rc, msg->lpBuffers, msg->dwBufferCount);

    dump_wsamsg (msg, rc);
  }

  LEAVE_CRIT (!exclude_this);
  WSAERROR_POP();
  return (rc);
}

static INT PASCAL hooked_WSASENDMSG (SOCKET        s,
                                     WSAMSG        *msg,
                                     DWORD          flags,
                                     DWORD         *bytes_sent,
                                     WSAOVERLAPPED *ov,
                                     WSAOVERLAPPED_COMPLETION_ROUTINE complete_func)
{
  char sent [20] = "?";
  INT  rc = (*orig_WSASENDMSG) (s, msg, flags, bytes_sent, ov, complete_func);

  ENTER_CRIT();

  if (bytes_sent)
    _itoa (*bytes_sent, sent, 10);

  WSTRACE ("WSASendMsg (%s, 0x%p, %s, ...) (ex-func) --> %s, sent: %s",
           socket_number(s), msg, socket_flags(flags), get_error(rc, 0), sent);

  if (rc != SOCKET_ERROR && !exclude_this)
     dump_wsamsg (msg, rc);

  LEAVE_CRIT (!exclude_this);
  return (rc);
}

/*
 * What does this do that 'WSAPoll()' doesn't do?
 */
static INT WSAAPI hooked_WSAPOLL (WSAPOLLFD *fdarray,
                                  ULONG      num_fds,
                                  INT        timeout)
{
  INT rc = (*orig_WSAPOLL) (fdarray, num_fds, timeout);

  ENTER_CRIT();
  WSTRACE ("WSAPoll (...) (ex-func) --> %s", get_error(rc, 0));
  LEAVE_CRIT (!exclude_this);
  return (rc);
}

#define ADD_HOOK(guid) { ex_##guid, WSAID_##guid, "WSAID_" #guid }

static struct extension_hook_list extension_hooks[] = {
                                  ADD_HOOK (ACCEPTEX),
                                  ADD_HOOK (CONNECTEX),
                                  ADD_HOOK (DISCONNECTEX),
                                  ADD_HOOK (GETACCEPTEXSOCKADDRS),
                                  ADD_HOOK (TRANSMITFILE),
                                  ADD_HOOK (TRANSMITPACKETS),
                                  ADD_HOOK (WSARECVMSG),
                                  ADD_HOOK (WSASENDMSG),
                                  ADD_HOOK (WSAPOLL)
                                };

static extensions find_extension_func (const GUID *in_guid)
{
  const GUID *guid = &extension_hooks[0].guid;
  int   i;

  for (i = 0; i < DIM(extension_hooks); guid = &extension_hooks[++i].guid)
      if (!memcmp(in_guid, guid, sizeof(*guid)))
         return (extensions) i;
  return (ex_NONE);
}

static void hook_extension_func (const GUID *in_guid, extension_func *in_out)
{
  extension_func *orig = in_out;
  extensions      ex = find_extension_func (in_guid);

  TRACE (3, "extension func at index %d matching GUID \"%s\"\n",
         ex, ex != ex_NONE ? extension_hooks[ex].guid_name : "<none>");

  #define CASE_HOOK(x)  case ex_##x:                                         \
                             orig_##x = (LPFN_##x) *orig;                    \
                             *in_out = (extension_func) hooked_##x;          \
                             TRACE (2, "ext-func 0x%p -> '%s()' at 0x%p.\n", \
                                    orig, "hooked_" #x, *in_out);            \
                             break
  switch (ex)
  {
    case ex_NONE:
         TRACE (2, "No hook set for extension func 0x%p!\n", orig);
         break;
    CASE_HOOK (ACCEPTEX);
    CASE_HOOK (CONNECTEX);
    CASE_HOOK (DISCONNECTEX);
    CASE_HOOK (GETACCEPTEXSOCKADDRS);
    CASE_HOOK (TRANSMITFILE);
    CASE_HOOK (TRANSMITPACKETS);
    CASE_HOOK (WSARECVMSG);
    CASE_HOOK (WSASENDMSG);
    CASE_HOOK (WSAPOLL);
  }
}

#undef ADD_HOOK
#undef CASE_HOOK

#endif /* HAVE_WSA_EXTENSIONS_FUNCTIONS */

