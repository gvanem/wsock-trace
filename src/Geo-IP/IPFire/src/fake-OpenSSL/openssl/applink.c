/**
 * \file applink.c
 *
 * Fake OpenSSL for libloc.
 *
 * This file gets included in all `libloc` files, so
 * we can fake `WSAStartup()` (since it could interfere when used from Wsock-trace).
 *
 * For all `libloc` files, it's force-included using:
 *  ```
 *   --include $(LIBLOC_ROOT)/src/fake-OpenSSL/openssl/applink.c  -- for MinGW / Cygwin
 *   -FI$(LIBLOC_ROOT)/src/fake-OpenSSL/openssl/applink.c         -- for MSVC / clang-cl
 *  ```
 *
 * This is to bypass the dependency on the real `WSAGetLastError()`, `inet_pton()`
 * and `inet_ntop()` in Winsock2.
 */
#ifndef OpenSSL_fake_applink_c
#define OpenSSL_fake_applink_c

#ifndef _CRT_NONSTDC_NO_WARNINGS
#define _CRT_NONSTDC_NO_WARNINGS
#endif

#include "common.h"
#include "inet_addr.h"

#undef  LIBLOC_PRIVATE
#define LIBLOC_PRIVATE

#if defined(__CYGWIN__)
  #define _WIN32  1
#endif

/**
 * Avoid the dependency on this OpenSSL function called in libloc.c.
 * And avoid `WSAStartup()` etc. too.
 */
#define OpenSSL_add_all_algorithms()    ((void) 0)

#if defined(USE_WSOCK_TRACE)
  #define WSAStartup(ver, wsa)          ((void) 0)
  #define WSAGetLastError()             0
#endif

/**
 * Ignore some MinGW/Cygwin warnings in all `libloc` files.
 * Keep this here to keep clean Makefiles.
 */
#if defined(__MINGW32__) || (defined(__CYGWIN__) && defined(__x86_64__))
  #pragma GCC diagnostic ignored  "-Wformat"             /* does not understand '%zu'! */
  #pragma GCC diagnostic ignored  "-Wformat-extra-args"  /* ditto */
#endif

#if defined(__GNUC__)
  #pragma GCC diagnostic ignored  "-Wstrict-aliasing"
  #pragma GCC diagnostic ignored  "-Wmissing-braces"
  #pragma GCC diagnostic ignored  "-Wstrict-aliasing"
  #pragma GCC diagnostic ignored  "-Wunused-variable"

#elif defined(_MSC_VER) && !defined(__clang__)
  #pragma warning (disable:4101 4146 4244 4267)
#endif

#endif  /* OpenSSL_fake_applink_c */

