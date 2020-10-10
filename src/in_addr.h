/**\file    in_addr.h
 * \ingroup inet_util
 */
#ifndef _IN_ADDR_H
#define _IN_ADDR_H

#define INT16SZ     2
#define INADDRSZ    4
#define IN6ADDRSZ  16

#if defined(IN_WSOCK_TRACE_C) && defined(__WATCOMC__)
#define u_char unsigned char
#define u_int  unsigned int
#endif

/**
 * Max size of an IPv4-address:port string.
 */
#ifndef INET_ADDRSTRLEN
#define INET_ADDRSTRLEN  sizeof("255.255.255.255:65000")    /* =22 */
#endif

/**
 * Max size of an IPv6 `[address%scope]:port` string. Winsock2 claims this to be 65.
 * But AFAICS `"[ffff:ffff:ffff:ffff:ffff:ffff:255.255.255.255%65000]:65000\0"` is
 * *only* 61.
 */
#ifndef INET6_ADDRSTRLEN
#define INET6_ADDRSTRLEN  65
#endif

/**
 * Max size of an IPv4 / IPv6-address string.
 */
#define MAX_IP4_SZ   INET_ADDRSTRLEN
#define MAX_IP6_SZ   sizeof("ffff:ffff:ffff:ffff:ffff:ffff:255.255.255.255")  /* =46 */
#define MAX_PORT_SZ  sizeof("65000")

/**
 * Max suffix for an IPv6-address
 */
#ifndef MAX_IPV6_CIDR_MASK
#define MAX_IPV6_CIDR_MASK 128
#endif

#if !defined(s6_bytes)  /* mingw.org */
#define s6_bytes _s6_bytes
#endif

#if !defined(s6_words)  /* mingw.org */
#define s6_words _s6_words
#endif

/**
 * In MicroSoft's `<ws2tcpip.h>` header, the `addr` parameter to `inet_ntop()`
 * is defined as `const void *`. <br>
 * But in some older MinGW it is defined as `void *`.
 */
#if (defined(__MINGW64_VERSION_MAJOR) && (__MINGW64_VERSION_MAJOR <= 4))
  #define INET_NTOP_ADDR void *
  #define INET_NTOP_RET  PCSTR

#elif defined(__CYGWIN__) && (CYGWIN_VERSION_DLL_COMBINED < 3000000)
  #define INET_NTOP_ADDR void *
  #define INET_NTOP_RET  LPCSTR

#else
  #define INET_NTOP_ADDR const void *
  #define INET_NTOP_RET  const char *
#endif

#if !defined(NTDDI_VERSION) || (NTDDI_VERSION < NTDDI_VISTA) || defined(__MINGW32__) || defined(__CYGWIN__)
//  EXPORT INET_NTOP_RET WSAAPI inet_ntop (INT family, INET_NTOP_ADDR addr, PSTR string_buf, size_t string_buf_size);
//  EXPORT INT           WSAAPI inet_pton (INT family, PCSTR addr_string, void *addr_buf);
#endif

extern BOOL IPv6_leading_zeroes;

/**
 * `inet_ntop()` and `inet_pton()` for internal use or to be used before
 * `load_ws2_funcs()` has dynamically loaded all needed Winsock functions.
 */
extern char *_wsock_trace_inet_ntop (int family, const void *addr, char *dst, size_t size, int *err);
extern int   _wsock_trace_inet_pton (int family, const char *addr, void *dst, int *err);

#endif

