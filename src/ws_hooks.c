/*
typedef BOOL
(PASCAL FAR * LPFN_ACCEPTEX) (
    SOCKET       sListenSocket,
    SOCKET       sAcceptSocket,
    PVOID        lpOutputBuffer,
    DWORD        dwReceiveDataLength,
    DWORD        dwLocalAddressLength,
    DWORD        dwRemoteAddressLength,
    LPDWORD      lpdwBytesReceived,
    LPOVERLAPPED lpOverlapped
    );

typedef BOOL
(PASCAL FAR * LPFN_CONNECTEX) (
    SOCKET s,
    const struct sockaddr *name,
    int namelen,
    VOID *lpSendBuffer,
    DWORD dwSendDataLength,
    DWORD *lpdwBytesSent,
    OVERLAPPED *lpOverlapped);

typedef BOOL
(PASCAL FAR * LPFN_DISCONNECTEX) (
    SOCKET s,
    OVERLAPPED *lpOverlapped,
    DWORD  dwFlags,
    DWORD  dwReserved);

typedef VOID
(PASCAL FAR * LPFN_GETACCEPTEXSOCKADDRS)(
    VOID *lpOutputBuffer,
    DWORD dwReceiveDataLength,
    DWORD dwLocalAddressLength,
    DWORD dwRemoteAddressLength,
    struct sockaddr **LocalSockaddr,
    INT *LocalSockaddrLength,
    struct sockaddr **RemoteSockaddr,
    INT *RemoteSockaddrLength);
 */

#include <MSWSock.h>

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

/* Search-list for GUIDs and new/orig extension functions.
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

static const char *socket_or_error (SOCK_RC_TYPE rc);

static BOOL PASCAL hooked_ACCEPTEX (SOCKET      listen_sock,
                                    SOCKET      accept_sock,
                                    void*       out_buf,
                                    DWORD       recv_data_len,
                                    DWORD       local_addr_len,
                                    DWORD       remote_addr_len,
                                    DWORD      *bytes_received,
                                    OVERLAPPED *ov)
{
  BOOL rc = (*orig_ACCEPTEX) (listen_sock,
                              accept_sock,
                              out_buf,
                              recv_data_len,
                              local_addr_len,
                              remote_addr_len,
                              bytes_received,
                              ov);

  WSTRACE ("AcceptEx (...) --> %s", socket_or_error(rc));
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
  BOOL rc = (*orig_CONNECTEX) (s,
                               name,
                               name_len,
                               send_buf,
                               send_data_len,
                               bytes_sent,
                               ov);

  WSTRACE ("ConnectEx (...) --> %s", socket_or_error(rc));
  return (rc);
}

static BOOL PASCAL hooked_DISCONNECTEX (SOCKET      s,
                                        OVERLAPPED *ov,
                                        DWORD       flags,
                                        DWORD       reserved)
{
  BOOL rc = (*orig_DISCONNECTEX) (s,
                                  ov,
                                  flags,
                                  reserved);

  WSTRACE ("DisConnectEx (...) --> %s", socket_or_error(rc));
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
  TRACE (1, "calling GetAcceptExSockaddr (...)");
  (*orig_GETACCEPTEXSOCKADDRS) (out_buf,
                                          recv_data_len,
                                          local_addr_len,
                                          remote_addr_len,
                                          local_sa,
                                          local_sa_len,
                                          remote_sa,
                                          remote_sa_len);

  WSTRACE ("GetAcceptExSockaddr (...)");
}

#if 0
static void PASCAL hooked_TRANSMITFILE
static void PASCAL hooked_TRANSMITPACKETS
static void PASCAL hooked_WSARECVMSG
static void PASCAL hooked_WSASENDMSG
static void PASCAL hooked_WSAPOLL
#endif

#define ADD_HOOK(guid) { ex_##guid, WSAID_##guid, "WSAID_" #guid }

static struct extension_hook_list extension_hooks[] = {
                                  ADD_HOOK (ACCEPTEX),
                                  ADD_HOOK (CONNECTEX),
                                  ADD_HOOK (DISCONNECTEX),
                                  ADD_HOOK (GETACCEPTEXSOCKADDRS),
                              //  ADD_HOOK (TRANSMITFILE),
                              //  ADD_HOOK (TRANSMITPACKETS),
                              //  ADD_HOOK (WSARECVMSG),
                              //  ADD_HOOK (WSASENDMSG),
                              //  ADD_HOOK (WSAPOLL)
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
  BOOL            set = FALSE;

  TRACE (1, "extension func at index %d matching GUID \"%s\"\n",
         ex, ex != ex_NONE ? extension_hooks[ex].guid_name : "<none>");

  #define CASE_HOOK(x)  case ex_##x:                                \
                             orig_##x = (LPFN_##x) *orig;           \
                             *in_out = (extension_func) hooked_##x; \
                             set = TRUE;                            \
                             break;
  switch (ex)
  {
    case ex_NONE:
         break;
    CASE_HOOK (ACCEPTEX);
    CASE_HOOK (CONNECTEX);
    CASE_HOOK (DISCONNECTEX);
    CASE_HOOK (GETACCEPTEXSOCKADDRS);
//  CASE_HOOK (TRANSMITFILE);
//  CASE_HOOK (TRANSMITPACKETS);
//  CASE_HOOK (WSARECVMSG);
//  CASE_HOOK (WSASENDMSG);
//  CASE_HOOK (WSAPOLL);
  }

  if (!set)
       TRACE (1, "No hook set for extension func 0x%p!\n", orig);
  else TRACE (1, "orig extension func 0x%p hooked to 0x%p\n", orig, *in_out);
}

#undef ADD_HOOK
#undef CASE_HOOK

