/**\file    wsock_defs.h
 * \ingroup Main
 */
#ifndef _WSOCK_DEFS_H
#define _WSOCK_DEFS_H

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <time.h>
#include <ctype.h>
#include <string.h>
#include <malloc.h>
#include <io.h>
#include <assert.h>
#include <sys/utime.h>
#include <sys/stat.h>

#if defined(__CYGWIN__)
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

#if defined(_MSC_VER) && defined(_DEBUG)  /* use CrtDebug in MSVC debug-mode */
  #undef  _CRTDBG_MAP_ALLOC
  #define _CRTDBG_MAP_ALLOC
  #undef _malloca                         /* Avoid MSVC-9 <malloc.h>/<crtdbg.h> name-clash */
  #include <crtdbg.h>
#endif

/*
 * Checks for compilers and CPU artitecture.
 * Refs:
 *   https://sourceforge.net/p/predef/wiki/Compilers
 *   https://sourceforge.net/p/predef/wiki/Architectures
 */
#if defined(_MSC_VER)   /* This includes 'clang-cl' and Intel's 'icx' too */
  #if defined(_M_IX86)
    #define WS_TRACE_I386

  #elif defined(_M_AMD64)
    #define WS_TRACE_AMD64

  #elif defined(_M_IA64)
    #define WS_TRACE_IA64

  #elif defined(_M_ARM)
    #define WS_TRACE_ARM

  #elif defined(_M_ARM64) || defined(_M_HYBRID_X86_ARM64) || defined(_M_ARM64EC)
    #define WS_TRACE_ARM64

  #else
    #error "Unsupported CPU"
  #endif

#elif defined(__GNUC__)
  #if defined(__i386__)
    #define WS_TRACE_I386

  #elif defined(__amd64__)
    #define WS_TRACE_AMD64

  #elif defined(__ia64__)
    #define WS_TRACE_IA64

  #elif defined(__arm__)
    #define WS_TRACE_ARM

  #elif defined(__aarch64__)
    #define WS_TRACE_ARM64

  #else
    #error "Unsupported CPU"
  #endif
#endif

#if defined(WS_TRACE_I386)
  #define WS_TRACE_IMAGE_TYPE  IMAGE_FILE_MACHINE_I386

#elif defined(WS_TRACE_AMD64)
  #define WS_TRACE_IMAGE_TYPE  IMAGE_FILE_MACHINE_AMD64

#elif defined(WS_TRACE_IA64)
  #define WS_TRACE_IMAGE_TYPE  IMAGE_FILE_MACHINE_IA64

#elif defined(WS_TRACE_ARM)
  #define WS_TRACE_IMAGE_TYPE  IMAGE_FILE_MACHINE_ARM

#elif defined(WS_TRACE_ARM64)
  #define WS_TRACE_IMAGE_TYPE  IMAGE_FILE_MACHINE_ARM64

#else
  #error "Unknown 'WS_TRACE_IMAGE_TYPE'."
#endif

extern uintptr_t dummy_reg;

#if defined(WS_TRACE_AMD64)
  #define REG_EBP(ctx)  (ctx)->Rbp
  #define REG_ESP(ctx)  (ctx)->Rsp
  #define REG_EIP(ctx)  (ctx)->Rip
  #define REG_BSP(ctx)  dummy_reg

#elif defined(WS_TRACE_IA64)
  #define REG_EBP(ctx)  (ctx)->Rbp
  #define REG_ESP(ctx)  (ctx)->IntSp
  #define REG_EIP(ctx)  (ctx)->StIIP
  #define REG_BSP(ctx)  (ctx)->RsBSP

#elif defined(WS_TRACE_ARM) || defined(WS_TRACE_ARM64)
  #define REG_EBP(ctx)  dummy_reg
  #define REG_ESP(ctx)  (ctx)->Sp
  #define REG_EIP(ctx)  (ctx)->Pc
  #define REG_BSP(ctx)  dummy_reg

#else
  #define REG_EBP(ctx)  (ctx)->Ebp
  #define REG_ESP(ctx)  (ctx)->Esp
  #define REG_EIP(ctx)  (ctx)->Eip
  #define REG_BSP(ctx)  dummy_reg
#endif

#define loBYTE(w)       (BYTE)(w)
#define hiBYTE(w)       (BYTE)((WORD)(w) >> 8)
#define DIM(x)          (int) (sizeof(x) / sizeof((x)[0]))
#define SIZEOF(x)       (int) sizeof(x)
#define TOUPPER(c)      toupper ((int)(c))
#define ARGSUSED(foo)   (void)foo

/*
 * According to:
 *  http://msdn.microsoft.com/en-us/library/windows/desktop/ms683188(v=vs.85).aspx
 */
#ifndef MAX_ENV_VAR
#define MAX_ENV_VAR   32767
#endif

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

#if defined(__GNUC__) && !defined(__CYGWIN__) /* Implies MinGW */
  #define WCHAR_FMT      "S"
  #define S64_FMT        "I64d"
  #define U64_FMT        "I64u"
  #define X64_FMT        "I64X"
  #define S64_SUFFIX(x)  (x##LL)
  #define U64_SUFFIX(x)  (x##ULL)

#elif defined(_MSC_VER) || defined(_MSC_EXTENSIONS)
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
  #if defined(_MSC_VER)
    #define CONST_LPSTR  LPCSTR
  #else
    #define CONST_LPSTR  LPSTR    /* non-const 'char*' as per MSDN */
  #endif
#endif  /* IN_WSOCK_TRACE_C */


/**
 * \def DWORD_CAST
 *
 * To fix the warnings for the use of `%lu` with a DWORD-arg.\n
 * Or warnings with `%ld` and an `int` argument.
 *
 * Especially noisy for `x64` builds since CygWin is a LP64-platform: \n
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
    #error "Help me!"
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
  #define __LONG32  long   /* Several <winsock2.h> functions for CygWin uses this */
  #endif

  #define __ms_u_long  u_long

#elif defined(__i386__)
   /*
    * Add this for all 32-bit CygWin.
    */
  #define __ms_u_long  u_long
#endif

#if defined(_MSC_VER)
  #ifndef _CRTDBG_MAP_ALLOC
  #define strdup       _strdup
  #endif

  #define strnicmp    _strnicmp
  #define stricmp     _stricmp
  #define strlwr      _strlwr
  #define strupr      _strupr
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

  #ifndef _popen
  #define _popen(cmd, mode)       popen (cmd, mode)
  #endif

  #ifndef _pclose
  #define _pclose(fil)            pclose (fil)
  #endif

  #define _atoi64(str)            strtoull (str, NULL, 10)
  #define stricmp(str1, str2)     strcasecmp (str1, str2)
  #define strnicmp(str1, str2, n) strncasecmp (str1, str2, n)
  #define _utime(path, buf)       utime (path, buf)
  #define _write(fd, buf, len)    write (fd, buf, len)

#elif defined(__MINGW32__)
  /*
   * I want the MSVC version of vsnprintf() since there is some trouble
   * with MinGW's version in C_printf(). No idea what.
   */
  #define vsnprintf _vsnprintf
#endif

/*
 * Defined in newer <sal.h> for MSVC.
 */
#ifndef _Printf_format_string_
#define _Printf_format_string_
#endif

#if defined(__GNUC__) || defined(__clang__)
  #define ATTR_PRINTF(_1,_2)   __attribute__((format(printf,_1,_2)))
#else
  #define ATTR_PRINTF(_1,_2)   /* nothing */
#endif

/*
 * For decoding 'WSAIoctl (sock, SIO_TCP_INFO, ...)':
 *
 * The more advanced 'TCP_INFO_v1' structure seems only to be valid for WinHTTP:
 *   https://docs.microsoft.com/en-us/windows/win32/winhttp/option-flags
 */
typedef struct local_TCP_INFO_v0 {
        uint32_t   State;       /* TCPSTATE_CLOSED=0, ... TCPSTATE_TIME_WAIT=10 */
        uint32_t   Mss;
        uint64_t   ConnectionTimeMs;
        uint8_t    TimestampsEnabled;
        uint32_t   RttUs;
        uint32_t   MinRttUs;
        uint32_t   BytesInFlight;
        uint32_t   Cwnd;
        uint32_t   SndWnd;
        uint32_t   RcvWnd;
        uint32_t   RcvBuf;
        uint64_t   BytesOut;
        uint64_t   BytesIn;
        uint32_t   BytesReordered;
        uint32_t   BytesRetrans;
        uint32_t   FastRetrans;
        uint32_t   DupAcksIn;
        uint32_t   TimeoutEpisodes;
        uint8_t    SynRetrans;
      } local_TCP_INFO_v0;

/*
 * Type-defined in the SDK `<shared/mstcpip.h>` as `TCP_INFO_v1` when
 * `NTDDI_VERSION >= NTDDI_WIN10_RS5`. Hence keep a private typedef here.
 *
 * Besides it's only usable on Win-10, Build 20348 or later.
 * Ref: https://docs.microsoft.com/en-us/windows/win32/api/mstcpip/ns-mstcpip-tcp_info_v1#requirements
 */
typedef struct local_TCP_INFO_v1 {
        uint32_t   State;
        uint32_t   Mss;
        uint64_t   ConnectionTimeMs;
        uint8_t    TimestampsEnabled;
        uint32_t   RttUs;
        uint32_t   MinRttUs;
        uint32_t   BytesInFlight;
        uint32_t   Cwnd;
        uint32_t   SndWnd;
        uint32_t   RcvWnd;
        uint32_t   RcvBuf;
        uint64_t   BytesOut;
        uint64_t   BytesIn;
        uint32_t   BytesReordered;
        uint32_t   BytesRetrans;
        uint32_t   FastRetrans;
        uint32_t   DupAcksIn;
        uint32_t   TimeoutEpisodes;
        uint8_t    SynRetrans;
        uint32_t   SndLimTransRwin;
        uint32_t   SndLimTimeRwin;
        uint64_t   SndLimBytesRwin;
        uint32_t   SndLimTransCwnd;
        uint32_t   SndLimTimeCwnd;
        uint64_t   SndLimBytesCwnd;
        uint32_t   SndLimTransSnd;
        uint32_t   SndLimTimeSnd;
        uint64_t   SndLimBytesSnd;
      } local_TCP_INFO_v1;

#define TCP_INFO_v0  local_TCP_INFO_v0
#define TCP_INFO_v1  local_TCP_INFO_v1

#ifndef SIO_TCP_INFO
#define SIO_TCP_INFO   0xD8000027   /* == _WSAIORW (IOC_VENDOR, 39) */
#endif

#endif /* _WSOCK_DEFS_H */
