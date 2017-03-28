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

/*
 * In MS's <ws2tcpip.h> header, the 'addr' parameter in 'inet_ntop()'
 * sensible is defined as 'const void *'. But in MinGW it is 'void *'.
 */
#if defined(__MINGW32__)
  #define INET_NTOP_ADDR void *
#else
  #define INET_NTOP_ADDR const void *
#endif

#if !defined(NTDDI_VERSION) || (NTDDI_VERSION < NTDDI_VISTA) || defined(__MINGW32__)
  EXPORT PCSTR WSAAPI inet_ntop (INT family, INET_NTOP_ADDR addr, PSTR string_buf, size_t string_buf_size);
  EXPORT INT   WSAAPI inet_pton (INT family, PCSTR addr_string, PVOID addr_buf);
#endif

extern BOOL       is_ip4_addr (const char *str);

extern char       *wsock_trace_inet_ntop (int family, const void *addr, char *dst, size_t size);
extern int         wsock_trace_inet_pton (int family, const char *addr, void *dst);

extern const char *wsock_trace_inet_ntop4 (const u_char *src, char *dst, size_t size);
extern const char *wsock_trace_inet_ntop6 (const u_char *src, char *dst, size_t size);
extern int         wsock_trace_inet_pton4 (const char *src, u_char *dst);
extern int         wsock_trace_inet_pton6 (const char *src, u_char *dst);

#endif

