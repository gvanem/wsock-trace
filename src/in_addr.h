#ifndef _IN_ADDR_H
#define _IN_ADDR_H

#define INT16SZ     2
#define INADDRSZ    4
#define IN6ADDRSZ   16

#if defined(IN_WSOCK_TRACE_C) && defined(__WATCOMC__)
  #define u_char unsigned char
#endif

/*
 * Max size of an IPv6-address string.
 */
#define MAX_IP6_SZ   sizeof("ffff:ffff:ffff:ffff:ffff:ffff:255.255.255.255")
#define MAX_PORT_SZ  sizeof("65000")

#if !defined(NTDDI_VERSION) || (NTDDI_VERSION < NTDDI_VISTA) || defined(__MINGW32__)
  EXPORT PCSTR WSAAPI inet_ntop (INT Family, PVOID pAddr, PSTR pStringBuf, size_t StringBufSize);
  EXPORT INT   WSAAPI inet_pton (INT Family, PCSTR pszAddrString, PVOID pAddrBuf);
#endif

extern char *wsock_trace_inet_ntop (int family, const void *addr, char *dst, size_t size);
extern int   wsock_trace_inet_pton (int family, const char *addr, void *dst);

extern const char *wsock_trace_inet_ntop4 (const u_char *src, char *dst, size_t size);
extern const char *wsock_trace_inet_ntop6 (const u_char *src, char *dst, size_t size);
extern int         wsock_trace_inet_pton4 (const char *src, u_char *dst);
extern int         wsock_trace_inet_pton6 (const char *src, u_char *dst);

#endif

