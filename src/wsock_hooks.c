/**
 * \file wsock_hooks.c
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

static LPFN_ACCEPTEX             orig_ACCEPTEX;
static LPFN_CONNECTEX            orig_CONNECTEX;
static LPFN_DISCONNECTEX         orig_DISCONNECTEX;
static LPFN_GETACCEPTEXSOCKADDRS orig_GETACCEPTEXSOCKADDRS;
static LPFN_TRANSMITFILE         orig_TRANSMITFILE;
static LPFN_TRANSMITPACKETS      orig_TRANSMITPACKETS;
static LPFN_WSARECVMSG           orig_WSARECVMSG;
static LPFN_WSASENDMSG           orig_WSASENDMSG;
static LPFN_WSAPOLL              orig_WSAPOLL;

static const char *get_error (SOCK_RC_TYPE rc);

static BOOL PASCAL hooked_ACCEPTEX (SOCKET      listen_sock,
                                    SOCKET      accept_sock,
                                    void*       out_buf,
                                    DWORD       recv_data_len,
                                    DWORD       local_addr_len,
                                    DWORD       remote_addr_len,
                                    DWORD      *bytes_received,
                                    OVERLAPPED *ov)
{
  BOOL rc;

  ENTER_CRIT();
  rc = (*orig_ACCEPTEX) (listen_sock, accept_sock, out_buf, recv_data_len,
                         local_addr_len, remote_addr_len, bytes_received, ov);

  WSTRACE ("AcceptEx (%u, %u, ...) --> %s",
           SOCKET_CAST(listen_sock), SOCKET_CAST(accept_sock), get_error(!rc));
  LEAVE_CRIT();
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
  BOOL rc;

  ENTER_CRIT();
  rc = (*orig_CONNECTEX) (s, name, name_len, send_buf, send_data_len,
                          bytes_sent, ov);

  WSTRACE ("ConnectEx (%u, ...) --> %s",
           SOCKET_CAST(s), get_error(!rc));

  if (g_cfg.dump_data && send_buf && (rc || WSAERROR_PUSH() == ERROR_IO_PENDING))
     dump_data (send_buf, send_data_len);

  LEAVE_CRIT();
  return (rc);
}

static BOOL PASCAL hooked_DISCONNECTEX (SOCKET      s,
                                        OVERLAPPED *ov,
                                        DWORD       flags,
                                        DWORD       reserved)
{
  BOOL rc;

  ENTER_CRIT();
  rc = (*orig_DISCONNECTEX) (s, ov, flags, reserved);

  WSTRACE ("DisconnectEx (%u, ...) --> %s",
           SOCKET_CAST(s), get_error(!rc));
  LEAVE_CRIT();
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
  ENTER_CRIT();

  (*orig_GETACCEPTEXSOCKADDRS) (out_buf, recv_data_len, local_addr_len,
                                remote_addr_len, local_sa, local_sa_len,
                                remote_sa, remote_sa_len);
  WSTRACE ("GetAcceptExSockaddr (...)");
  LEAVE_CRIT();
}

static BOOL PASCAL hooked_TRANSMITFILE (SOCKET                 s,
                                        HANDLE                 file,
                                        DWORD                  bytes_to_write,
                                        DWORD                  bytes_per_send,
                                        OVERLAPPED            *ov,
                                        TRANSMIT_FILE_BUFFERS *transmit_bufs,
                                        DWORD                  reserved)
{
  BOOL rc;

  ENTER_CRIT();

  rc = (*orig_TRANSMITFILE) (s, file, bytes_to_write, bytes_per_send,
                             ov, transmit_bufs, reserved);

  WSTRACE ("TransmitFile (%u, ...) --> %s",
           SOCKET_CAST(s), get_error(!rc));
  LEAVE_CRIT();
  return (rc);
}

static BOOL PASCAL hooked_TRANSMITPACKETS (SOCKET                    s,
                                           TRANSMIT_PACKETS_ELEMENT *packet_array,
                                           DWORD                     elements,
                                           DWORD                     transmit_size,
                                           OVERLAPPED               *ov,
                                           DWORD                     flags)
{
  BOOL rc;

  ENTER_CRIT();

  rc = (*orig_TRANSMITPACKETS) (s, packet_array, elements, transmit_size,
                                ov, flags);
  WSTRACE ("TransmitPackets (%u, ...) --> %s",
           SOCKET_CAST(s), get_error(!rc));
  LEAVE_CRIT();
  return (rc);
}

static INT PASCAL hooked_WSARECVMSG (SOCKET         s,
                                     WSAMSG        *msg,
                                     DWORD         *bytes_recv,
                                     WSAOVERLAPPED *ov,
                                     LPWSAOVERLAPPED_COMPLETION_ROUTINE complete_func)
{
  INT rc;

  ENTER_CRIT();

  rc = (*orig_WSARECVMSG) (s, msg, bytes_recv, ov, complete_func);

  WSTRACE ("WSARecvMsg (%u, ...) --> %s",
           SOCKET_CAST(s), get_error(!rc));
  LEAVE_CRIT();
  return (rc);
}

static INT PASCAL hooked_WSASENDMSG (SOCKET        s,
                                     WSAMSG        *msg,
                                     DWORD          flags,
                                     DWORD         *bytes_sent,
                                     WSAOVERLAPPED *ov,
                                     LPWSAOVERLAPPED_COMPLETION_ROUTINE complete_func)
{
  INT rc;

  ENTER_CRIT();

  rc = (*orig_WSASENDMSG) (s, msg, flags, bytes_sent, ov, complete_func);

  WSTRACE ("WSASendMsg (%u, ...) --> %s",
           SOCKET_CAST(s), get_error(!rc));
  LEAVE_CRIT();
  return (rc);
}

/*
 * What does this do that 'WSAPoll()' doesn't do?
 */
static INT WSAAPI hooked_WSAPOLL (WSAPOLLFD *fdarray,
                                  ULONG      num_fds,
                                  INT        timeout)
{
  INT rc;

  ENTER_CRIT();
  rc = (*orig_WSAPOLL) (fdarray, num_fds, timeout);

  WSTRACE ("WSAPoll (...) --> %s", get_error(!rc));
  LEAVE_CRIT();

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
      if (!memcmp(in_guid,guid,sizeof(*guid)))
         return (extensions) i;
  return (ex_NONE);
}

static void hook_extension_func (const GUID *in_guid, extension_func *in_out)
{
  extension_func *orig = in_out;
  extensions      ex = find_extension_func (in_guid);

  TRACE (3, "extension func at index %d matching GUID \"%s\"\n",
         ex, ex != ex_NONE ? extension_hooks[ex].guid_name : "<none>");

  #define CASE_HOOK(x)  case ex_##x:                                \
                             orig_##x = (LPFN_##x) *orig;           \
                             *in_out = (extension_func) hooked_##x; \
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
  TRACE (2, "orig extension func 0x%p hooked to 0x%p\n", orig, *in_out);
}

#undef ADD_HOOK
#undef CASE_HOOK

#endif /* HAVE_WSA_EXTENSIONS_FUNCTIONS */

