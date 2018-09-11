/**\file    wsock_defs.h
 * \ingroup Main
 */
#ifndef _WSOCK_DEFS_H
#define _WSOCK_DEFS_H

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <ctype.h>
#include <string.h>
#include <malloc.h>
#include <io.h>
#include <assert.h>
#include <sys/utime.h>
#include <sys/stat.h>

#if defined(__CYGWIN__)
  /*
   * We use a local "getopt.h" which is slightly
   * incompatible with CygWin's standard getopt.h.
   * So do not include it via <unistd.h>.
   */
  #define __GETOPT_H__      /* CygWin header guard for <getopt.h> */
  #define __UNISTD_GETOPT__ /* No getopt() in CygWin's <unistd.h> */

  #include <cygwin/version.h>
  #include <sys/stat.h>
  #include <unistd.h>
  #include <limits.h>
  #include <wchar.h>

  #if defined(__x86_64__) && !defined(_WIN64)
  #define _WIN64 1
  #endif

  #if !defined(_MAX_PATH)
  #define _MAX_PATH   _POSIX_PATH_MAX   /* 256 */
  #endif

#else
  #include <conio.h>
#endif

#if defined(__MINGW32__)
  #include <specstrings.h>
#endif

#if defined(__WATCOMC__) || defined(__MINGW32__)
  #include <stdint.h>   /* 'uintptr_t' */
#endif

#if defined(_MSC_VER) && defined(_DEBUG)  /* use CrtDebug in MSVC debug-mode */
  #define _CRTDBG_MAP_ALLOC
  #undef _malloca                         /* Avoid MSVC-9 <malloc.h>/<crtdbg.h> name-clash */
  #include <crtdbg.h>
#endif

#define loBYTE(w)       (BYTE)(w)
#define hiBYTE(w)       (BYTE)((WORD)(w) >> 8)
#define DIM(x)          (int) (sizeof(x) / sizeof((x)[0]))
#define SIZEOF(x)       (int) sizeof(x)
#define TOUPPER(c)      toupper ((int)(c))
#define ARGSUSED(foo)   (void)foo

#ifndef MAX_HOST_LEN
#define MAX_HOST_LEN  256
#endif

#ifndef MAX_HOST_LABELS
#define MAX_HOST_LABELS  8
#endif

#ifndef DWORD_MAX
#define DWORD_MAX  0xFFFFFFFF
#endif

#ifndef QWORD_MAX
#define QWORD_MAX  U64_SUFFIX (0xFFFFFFFFFFFFFFFF)
#endif

#if defined(__GNUC__) && defined(__MINGW32__)
  #define WCHAR_FMT      "S"
  #define S64_FMT        "I64d"
  #define U64_FMT        "I64u"
  #define X64_FMT        "I64X"
  #define S64_SUFFIX(x)  (x##LL)
  #define U64_SUFFIX(x)  (x##ULL)

#elif defined(_MSC_VER) || defined(_MSC_EXTENSIONS) || defined(__WATCOMC__)
  #define WCHAR_FMT      "ws"
  #define S64_FMT        "I64d"
  #define U64_FMT        "I64u"
  #define X64_FMT        "I64X"
  #define S64_SUFFIX(x)  (x##i64)
  #define U64_SUFFIX(x)  (x##Ui64)

#else
  #if defined(__CYGWIN__)
    #define WCHAR_FMT    "S"
  #else
    #define WCHAR_FMT    "ws"
  #endif
  #define S64_FMT        "Ld"
  #define U64_FMT        "Lu"
  #define X64_FMT        "Lx"
  #define S64_SUFFIX(x)  (x##LL)
  #define U64_SUFFIX(x)  (x##ULL)
#endif

#if defined(__GNUC__)
  #define GCC_VERSION  (10000 * __GNUC__ + 100 * __GNUC_MINOR__ + __GNUC_PATCHLEVEL__)
#else
  #define GCC_VERSION  0
#endif

#if (GCC_VERSION >= 40600) || defined(__clang__)
  #define GCC_PRAGMA(x)  _Pragma (#x)
#else
  #define GCC_PRAGMA(x)
#endif

#if defined(IN_WSOCK_TRACE_C)
  #if defined(WIN64) || defined(_WIN64)
    #define SOCK_RC_TYPE SOCKET
  #else
    #define SOCK_RC_TYPE unsigned
  #endif

  /*
   * There is some difference between some Winsock prototypes in MS-SDK's
   * versus MinGW-w64/MinGW-TDM headers. This is to fit the 'const struct timeval*'
   * parameter in 'select()' etc.
   */
  #if (defined(__MINGW32__) && defined(__MINGW64_VERSION_MAJOR)) || \
      (defined(__CYGWIN__) && (CYGWIN_VERSION_DLL_COMBINED >= 2002001)) /* Not sure about this value */
    #define CONST_PTIMEVAL   const PTIMEVAL
  #else
    #define CONST_PTIMEVAL   const struct timeval *
  #endif

  /*
   * More hacks for string parameters to 'WSAConnectByNameA()'. According to
   * MSDN:
   *   https://msdn.microsoft.com/en-us/library/windows/desktop/ms741557(v=vs.85).aspx
   *
   * they want an 'LPSTR' for 'node_name' and 'service_name'. Hence so does MinGW.
   * But the <winsock2.h> in the WindowsKit wants an 'LPCSTR'.
   *
   * Funny enough, 'WSAConnectByNameW()' doesn't want a 'const wide-string'.
   */
  #if defined(_MSC_VER) // && defined(_CRT_BEGIN_C_HEADER)
    #define CONST_LPSTR  LPCSTR
  #else
    #define CONST_LPSTR  LPSTR    /* non-const 'char*' as per MSDN */
  #endif
#endif  /* IN_WSOCK_TRACE_C */


/*
 * To fix the warnings for the use of "%lu" with a DWORD-arg.
 * Or warnings with "%ld" and an 'int' argument.
 * Especially noisy for 'x64' builds since CygWin is a LP64-platform:
 *   https://en.wikipedia.org/wiki/64-bit_computing
 */
#if defined(__CYGWIN__)
  #define DWORD_CAST(x)   ((unsigned long)(x))
  #define LONG_CAST(x)    ((long int)(x))

#else
  #define DWORD_CAST(x)   x
  #define LONG_CAST(x)    x
#endif


/*
 * Printing an hex linear address.
 * Printing a decimal value from the address-bus (e.g. a stack-limit)
 * E.g. printf (buf, "0x%"ADDR_FMT, ADDR_CAST(ptr));
 *
 * todo: Maybe print a 64-bit address as 'cdb' does:
 *       "00000001`0040175a"
 */
#if defined(WIN64) || defined(_WIN64)
  #if defined(_MSC_VER) ||   /* MSVC/WIN64 little tested */ \
      defined(__MINGW32__)
    #define ADDR_FMT      "016I64X"
    #define ADDR_CAST(x)  ((unsigned __int64)(x))

  #elif defined(__CYGWIN__)
    #define ADDR_FMT      "016llX"
    #define ADDR_CAST(x)  ((unsigned __int64)(x))

  #else
    #error Help me!
  #endif

  #define IS_WIN64 1

  /*
   * A 'SOCKET' is defined as 'unsigned long long' on Win64.
   * But we hardly ever need to print all bits. Just cast to
   * silence MinGW-w64 / CygWin64.
   */
  #define SOCKET_CAST(s)  ((unsigned int)(s))

#else    /* WIN32 */
  #define ADDR_FMT        "08lX"
  #define ADDR_CAST(x)    ((DWORD_PTR)(x))   /* "cl -Wp64" warns here. Ignore it. */
  #define SOCKET_CAST(s)  s
  #define IS_WIN64        0
#endif

/*
 * And now the 'long' versus '32-bit long' insanity to suite
 * 64-bit CygWin.
 */
#define __ULONG32  unsigned __LONG32

#if !defined(__CYGWIN__)
  #if !defined(__MINGW32__)
  #define __LONG32  long  /* Several <winsock2.h> functions for CygWin uses this */
  #endif

  #define __ms_u_long  u_long

#elif defined(__i386__) // && (CYGWIN_VERSION_DLL_COMBINED <= 2882000)
   /*
    * Not sure about the above CYGWIN_VERSION_DLL_COMBINED value.
    * Never mind this shit. Add it for all 32-bit CygWin.
    */
  #define __ms_u_long u_long
#endif

#if defined(_MSC_VER)
  #ifndef _CRTDBG_MAP_ALLOC
  #define strdup       _strdup
  #endif

  #define strnicmp    _strnicmp
  #define stricmp     _stricmp
  #define strlwr      _strlwr
  #define snprintf    _snprintf
  #define vsnprintf   _vsnprintf
  #define fdopen      _fdopen
  #define tzset()     _tzset()
  #define isatty(fd)  _isatty (fd)
  #define fileno(f)   _fileno (f)
  #define access(f,m) _access (f,m)

#elif defined(__CYGWIN__)
  #ifndef _fileno
  #define _fileno(fil)            fileno (fil)
  #endif
  #define _atoi64(str)            strtoull (str, NULL, 10)
  #define stricmp(str1, str2)     strcasecmp (str1, str2)
  #define strnicmp(str1, str2, n) strncasecmp (str1, str2, n)
  #define _utime(path, buf)       utime (path, buf)
  #define _write(fd, buf, len)    write (fd, buf, len)

#elif defined(__MINGW32__)
  /*
   * I want the MSVC version of vsnprintf() since there is some trouble
   * with MinGW's version in trace_printf(). No idea what.
   */
  #define vsnprintf _vsnprintf
#endif


#if defined(_MSC_VER) && !defined(__POCC__)
  /*
   * All MS compilers insists that 'main()', signal-handlers, atexit functions and
   * var-arg functions must be defined as cdecl. This is only an issue if a program
   * is using 'fastcall' globally (cl option '-Gr').
   */
  #define MS_CDECL __cdecl
#else
  #define MS_CDECL
#endif

/*
 * Defined in newer <sal.h> for MSVC.
 */
#ifndef _Printf_format_string_
#define _Printf_format_string_
#endif

#if defined(__GNUC__)
  #define ATTR_PRINTF(_1,_2)   __attribute__((format(printf,_1,_2)))
#else
  #define ATTR_PRINTF(_1,_2)   /* nothing */
#endif

#endif /* _WSOCK_DEFS_H */
