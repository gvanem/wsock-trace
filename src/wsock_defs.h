/**\file    wsock_defs.h
 * \ingroup Main
 */
#ifndef _WSOCK_DEFS_H
#define _WSOCK_DEFS_H

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <time.h>
#include <ctype.h>
#include <string.h>
#include <malloc.h>
#include <io.h>
#include <conio.h>
#include <assert.h>
#include <sys/utime.h>
#include <sys/stat.h>

#if defined(_DEBUG)           /* use CrtDebug in debug-mode */
  #undef  _CRTDBG_MAP_ALLOC
  #define _CRTDBG_MAP_ALLOC
  #undef _malloca             /* Avoid MSVC-9 <malloc.h>/<crtdbg.h> name-clash */
  #include <crtdbg.h>
#endif

/*
 * Checks for compilers and CPU artitecture.
 * Refs:
 *   https://sourceforge.net/p/predef/wiki/Compilers
 *   https://sourceforge.net/p/predef/wiki/Architectures
 */
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

/*
 * When the architecture has no such `x` register,
 * use `g_data.dummy_reg`.
 */
#if defined(WS_TRACE_AMD64)
  #define REG_EBP(ctx)  (ctx)->Rbp
  #define REG_ESP(ctx)  (ctx)->Rsp
  #define REG_EIP(ctx)  (ctx)->Rip
  #define REG_BSP(ctx)  g_data.dummy_reg

#elif defined(WS_TRACE_IA64)
  #define REG_EBP(ctx)  (ctx)->Rbp
  #define REG_ESP(ctx)  (ctx)->IntSp
  #define REG_EIP(ctx)  (ctx)->StIIP
  #define REG_BSP(ctx)  (ctx)->RsBSP

#elif defined(WS_TRACE_ARM) || defined(WS_TRACE_ARM64)
  #define REG_EBP(ctx)  g_data.dummy_reg
  #define REG_ESP(ctx)  (ctx)->Sp
  #define REG_EIP(ctx)  (ctx)->Pc
  #define REG_BSP(ctx)  g_data.dummy_reg

#else
  #define REG_EBP(ctx)  (ctx)->Ebp
  #define REG_ESP(ctx)  (ctx)->Esp
  #define REG_EIP(ctx)  (ctx)->Eip
  #define REG_BSP(ctx)  g_data.dummy_reg
#endif

#define loBYTE(w)       (BYTE)(w)
#define hiBYTE(w)       (BYTE)((WORD)(w) >> 8)
#define DIM(x)          (int) (sizeof(x) / sizeof((x)[0]))
#define SIZEOF(x)       (int) sizeof(x)
#define TOUPPER(c)      toupper ((int)(c))
#define ARGSUSED(foo)   (void)foo
#define S64_SUFFIX(x)   (x##i64)
#define U64_SUFFIX(x)   (x##Ui64)

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
#define QWORD_MAX  0xFFFFFFFFFFFFFFFFULL
#endif

#if defined(__clang__)
  #define _PRAGMA(x)            _Pragma (#x)
  #define ATTR_PRINTF(_1, _2)   __attribute__((format(printf, _1, _2)))
#else
  #define _PRAGMA(x)
  #define ATTR_PRINTF(_1, _2)
#endif

/*
 * Printing an hex linear address.
 * Printing a decimal value from the address-bus (e.g. a stack-limit)
 * E.g. printf (buf, "0x%"ADDR_FMT, ADDR_CAST(ptr));
 *
 * todo: Maybe print a 64-bit address as 'cdb' does:
 *       "00000001`0040175a"
 */
#if defined(_WIN64)
  #define ADDR_FMT      "016I64X"
  #define ADDR_CAST(x)  ((unsigned __int64)(x))
  #define IS_WIN64      1

  /*
   * A 'SOCKET' is defined as 'unsigned long long' on Win64.
   * But we hardly ever need to print all bits.
   */
  #define SOCKET_CAST(s)  ((unsigned int)(s))

#else    /* WIN32 */
  #define ADDR_FMT        "08lX"
  #define ADDR_CAST(x)    ((DWORD_PTR)(x))   /* "cl -Wp64" warns here. Ignore it. */
  #define SOCKET_CAST(s)  s
  #define IS_WIN64        0
#endif

#ifndef _DEBUG
#define strdup       _strdup
#endif

#define strnicmp     _strnicmp
#define stricmp      _stricmp
#define strlwr       _strlwr
#define strupr       _strupr
#define snprintf     _snprintf
#define vsnprintf    _vsnprintf
#define fdopen       _fdopen
#define tzset()      _tzset()
#define isatty(fd)   _isatty (fd)
#define fileno(f)    _fileno (f)
#define access(f, m) _access (f, m)

/*
 * Defined in newer <sal.h>
 */
#ifndef _Printf_format_string_
#define _Printf_format_string_
#endif

#endif /* _WSOCK_DEFS_H */
