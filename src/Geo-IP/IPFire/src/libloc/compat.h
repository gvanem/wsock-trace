/*
	libloc - A library to determine the location of someone on the Internet

	Copyright (C) 2019 IPFire Development Team <info@ipfire.org>

	This library is free software; you can redistribute it and/or
	modify it under the terms of the GNU Lesser General Public
	License as published by the Free Software Foundation; either
	version 2.1 of the License, or (at your option) any later version.

	This library is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
	Lesser General Public License for more details.
*/

#ifndef LIBLOC_COMPAT_H
#define LIBLOC_COMPAT_H

#ifdef __APPLE__
  /* Hacks to make this library compile on Mac OS X */

  #include <libkern/OSByteOrder.h>
  #define be16toh(x) OSSwapBigToHostInt16(x)
  #define htobe16(x) OSSwapHostToBigInt16(x)
  #define be32toh(x) OSSwapBigToHostInt32(x)
  #define htobe32(x) OSSwapHostToBigInt32(x)
  #define be64toh(x) OSSwapBigToHostInt64(x)
  #define htobe64(x) OSSwapHostToBigInt64(x)

  #ifndef s6_addr16
  #  define s6_addr16 __u6_addr.__u6_addr16
  #endif
  #ifndef s6_addr32
  #  define s6_addr32 __u6_addr.__u6_addr32
  #endif

#elif defined(_MSC_VER)
  #include <stdio.h>
  #include <stdint.h>
  #include <string.h>
  #include <time.h>
  #include <limits.h>
  #include <io.h>
  #include <intrin.h>

  #pragma intrinsic (_byteswap_ushort)  /* make these inlined */
  #pragma intrinsic (_byteswap_ulong)
  #pragma intrinsic (_byteswap_uint64)

  #define be16toh(x)  _byteswap_ushort (x)
  #define htobe16(x)  _byteswap_ushort (x)
  #define be32toh(x)  _byteswap_ulong (x)
  #define htobe32(x)  _byteswap_ulong (x)
  #define be64toh(x)  _byteswap_uint64 (x)
  #define htobe64(x)  _byteswap_uint64 (x)

  #ifndef CLOCK_MONOTONIC
  #define CLOCK_MONOTONIC 0
  #endif

  /* Missing in older Visual-C.
   * Not sure about the '_MSC_VER' value.
   * Also for 'clang-cl' when '-fms-compatibility-version=18' is used.
   */
  #if (_MSC_VER <= 1800)
    struct timespec {
        time_t tv_sec;   /* Seconds - >= 0 */
        long   tv_nsec;  /* Nanoseconds - [0, 999999999] */
    };
  #endif

  int asprintf  (char **buf, const char *fmt, ...);
  int vasprintf (char **buf, const char *fmt, va_list args);

  int  loc_clock_gettime (int clk_id, struct timespec *tp);
  void loc_memory (const char *what, const char *path1, const char *path2);

  #define clock_gettime(id, tp) loc_clock_gettime (id, tp)
  #define memory(what, p1, p2)  loc_memory (what, p1, p2)

  #if !defined(__clang__)    /* Move to 'libloc/msvc-hacks.h'? */
    #ifndef __attribute__
    #define __attribute__(x)
    #endif

    /*
     * Adapted from:
     *   https://github.com/llvm-mirror/libcxx/blob/9dcbb46826fd4d29b1485f25e8986d36019a6dca/include/support/win32/support.h
     *
     * Returns the number of leading 0-bits in `value`, starting at the most significant bit position.
     */
    static __inline uint32_t __builtin_clz(unsigned long value)
    {
      unsigned long ret = 0;
      if (_BitScanReverse(&ret, value) == 0)
         return (32);
      return (uint32_t) (31 - ret);
    }

    /*
     * Returns the number of trailing 0-bits in `value`, starting at the most significant bit position.
     */
    static __inline uint32_t __builtin_ctz(unsigned long value)
    {
      unsigned long ret = 0;
      if (_BitScanForward(&ret, value) == 0)
         return (32);
      return (uint32_t) ret;
    }
  #endif /* !__clang__ */

  #if defined(LIBLOC_LUAJIT_HACKS)
    #include <lua.h>
    #include <lauxlib.h>
    #include <libloc/luajit-hacks.h>
  #endif

  #if defined(LIBLOC_PRIVATE)
    extern char  *strcasestr (const char *haystack, const char *needle);
    extern char  *strptime (const char *buf, const char *format, struct tm *tm);
    extern char  *strsep  (char **stringp, const char *delim);
    extern time_t timegm (struct tm *tm);
    extern char  *get_neterr (void);

    #define LIBLOC_NETERR() get_neterr()

    #if !defined(Py_PYTHON_H) && !defined(ssize_t) && !defined(_SSIZE_T_DEFINED)
      #define ssize_t INT_PTR
      #define _SSIZE_T_DEFINED 1
    #endif
  #endif    /* LIBLOC_PRIVATE */

#endif      /* __APPLE__ */

#ifndef LIBLOC_NETERR
#define LIBLOC_NETERR() strerror (errno)
#endif

#ifndef s6_addr16
#define s6_addr16 __u6_addr.__u6_addr16
#endif

#ifndef s6_addr32
#define s6_addr32 __u6_addr.__u6_addr32
#endif

#ifndef reallocarray
#define reallocarray(ptr, nmemb, size) realloc (ptr, (nmemb) * (size))
#endif

#ifdef _WIN32
const char *handle_m_format (const char *fmt);
#endif

#endif  /* LIBLOC_COMPAT_H */
