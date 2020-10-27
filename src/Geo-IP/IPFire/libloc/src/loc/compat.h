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

#elif defined(_WIN32)
  #include <stdio.h>
  #include <stdint.h>
  #include <string.h>
  #include <time.h>
  #include <io.h>
  #include <intrin.h>

  #ifdef _MSC_VER
    #pragma intrinsic (_byteswap_ushort)  /* make these inlined */
    #pragma intrinsic (_byteswap_ulong)
    #pragma intrinsic (_byteswap_uint64)
  #endif

  #define be16toh(x)  _byteswap_ushort (x)
  #define htobe16(x)  _byteswap_ushort (x)
  #define be32toh(x)  _byteswap_ulong (x)
  #define htobe32(x)  _byteswap_ulong (x)
  #define be64toh(x)  _byteswap_uint64 (x)
  #define htobe64(x)  _byteswap_uint64 (x)

  #if defined(LIBLOC_PRIVATE)

    #if defined(_MSC_VER)
      /*
       * In debug-mode, 'strdup()' is already defined to 'strdup_dbg()'
       */
      #if !defined(_DEBUG)
      #define strdup(str)    _strdup (str)
      #endif

      #define dup(fd)          _dup (fd)
      #define fileno(stream)   _fileno (stream)
      #define fdopen(fd, mode) _fdopen (fd, mode)
    #endif

    extern char  *strsep     (char **stringp, const char *delim);
    extern char  *strcasestr (const char *haystack, const char *needle);
    extern char  *strptime   (const char *buf, const char *format, struct tm *tm);
    extern time_t timegm     (struct tm *tm);

    #if !defined(Py_PYTHON_H) && !defined(ssize_t) && !defined(_SSIZE_T_DEFINED)
      #define ssize_t SSIZE_T   /* From <basetsd.h> */
    #endif
  #endif
#endif

#endif
