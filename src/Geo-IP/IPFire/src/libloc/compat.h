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

#elif defined(_WIN32) || defined(__CYGWIN__)   /* '_WIN32' implies MinGW too */
  #include <stdio.h>
  #include <stdint.h>
  #include <string.h>
  #include <time.h>
  #include <limits.h>
  #include <io.h>
  #include <intrin.h>

  #if defined(__CYGWIN__)
    #include <endian.h>

  #elif defined(_MSC_VER)
    #pragma intrinsic (_byteswap_ushort)  /* make these inlined */
    #pragma intrinsic (_byteswap_ulong)
    #pragma intrinsic (_byteswap_uint64)

    /* Drop dependency on 'oldnames.lib'
     */
    #define lseek(fd, ofs, whence) _lseek (fd, ofs, whence)
  #endif

  #if !defined(__CYGWIN__)  /* '_MSC_VER' or '__MINGW32__' */
    #define be16toh(x)  _byteswap_ushort (x)
    #define htobe16(x)  _byteswap_ushort (x)
    #define be32toh(x)  _byteswap_ulong (x)
    #define htobe32(x)  _byteswap_ulong (x)
    #define be64toh(x)  _byteswap_uint64 (x)
    #define htobe64(x)  _byteswap_uint64 (x)

    #define reallocarray(ptr, nmemb, size)  realloc (ptr, (nmemb) * (size))

    int asprintf  (char **buf, const char *fmt, ...);
    int vasprintf (char **buf, const char *fmt, va_list args);
  #endif

  #if defined(LIBLOC_PRIVATE)
    /*
     * Cygwin exposes these prototypes only if `__XSI_VISIBLE` and
     * `__GNU_VISIBLE` is set.
     */
    extern char *strcasestr (const char *haystack, const char *needle);
    extern char *strptime (const char *buf, const char *format, struct tm *tm);

    /*
     * Cygwin always exposes these prototypes in it's <time.h>
     */
    #if !defined(__CYGWIN__)
      extern char  *strsep  (char **stringp, const char *delim);
      extern time_t timegm (struct tm *tm);
      extern char  *get_neterr (void);

      #define LIBLOC_NETERR() get_neterr()
    #else
      int asprintf  (char **buf, const char *fmt, ...);
      int vasprintf (char **buf, const char *fmt, va_list args);
    #endif

    #if !defined(Py_PYTHON_H) && !defined(ssize_t) && !defined(_SSIZE_T_DEFINED)
      #define ssize_t SSIZE_T     /* From <basetsd.h> */
      #define _SSIZE_T_DEFINED 1
    #endif

    #if !defined(__WORDSIZE)
      #ifdef _WIN64
      #define __WORDSIZE   64
      #else
      #define __WORDSIZE   32
      #endif
    #endif
  #endif    /* LIBLOC_PRIVATE */
#endif      /* _WIN32 || __CYGWIN__ */

#ifndef LIBLOC_NETERR
#define LIBLOC_NETERR() strerror(errno)
#endif

#ifndef s6_addr16
#define s6_addr16 __u6_addr.__u6_addr16
#endif

#ifndef s6_addr32
#define s6_addr32 __u6_addr.__u6_addr32
#endif

#ifndef reallocarray
#define reallocarray(ptr, nmemb, size) realloc(ptr, nmemb * size)
#endif

#endif  /* LIBLOC_COMPAT_H */
