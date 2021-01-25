#ifndef WSOCK_TRACE_CONFIG
#define WSOCK_TRACE_CONFIG

/*
 * A small 'config.h' for building Wsock-trace.
 * Mostly to fix a OpenWatcom build.
 */

#if defined(__WATCOMC__)
  /*
   * Required to define `IN6_IS_ADDR_LOOPBACK()` etc. in
   * OpenWatcom's <ws2ipdef.h>.
   */
  #undef  NTDDI_VERSION
  #define NTDDI_VERSION 0x05010000

  /* No <winhttp.h> in OpenWatcom.
   */
  #undef HAVE_WINHTTP_H
#else
  #define HAVE_WINHTTP_H
#endif
#endif
