/**
 * \file applink.c
 *
 * Fake OpenSSL for libloc.
 *
 * This is to bypass the dependency on the real `WSAGetLastError()`, `inet_pton()`
 * and `inet_ntop()` in Winsock2.
 */
#pragma once

#ifndef _CRT_NONSTDC_NO_WARNINGS
#define _CRT_NONSTDC_NO_WARNINGS
#endif

#include "../../../../../common.h"
#include "../../../../../inet_addr.h"

#undef  LIBLOC_PRIVATE
#define LIBLOC_PRIVATE

/**
 * Avoid the dependency on this OpenSSL function called in libloc.c.
 * And avoid `WSAStartup()` etc. too.
 */
#define OpenSSL_add_all_algorithms()    ((void) 0)

#if defined(USE_WSOCK_TRACE)
  #define WSAStartup(ver, wsa)          ((void) 0)
  #define WSAGetLastError()             0
#endif

#if defined(_MSC_VER) && !defined(__clang__)
 // #pragma warning (disable: 4101 4146 4244 4267)
#endif
