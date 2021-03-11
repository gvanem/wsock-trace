#ifndef WSOCK_TRACE_CONFIG
#define WSOCK_TRACE_CONFIG

/* Do not pull in <winsock.h> in <windows.h>
 */
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

/* Because of warning "Use getaddrinfo() or GetAddrInfoW() instead ..." in idna.c.
 */
#ifndef _WINSOCK_DEPRECATED_NO_WARNINGS
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#endif

/*
 * Tests for 'fmodl()' used in init.c:
 */
#if defined(__CYGWIN__)
  #if (CYGWIN_VERSION_DLL_COMBINED >= 2009000)
  #define HAVE_FMODL
  #endif
#else
  #define HAVE_FMODL
#endif

#endif
