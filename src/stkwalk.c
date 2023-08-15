/** \file   stkwalk.c
 *  \ingroup Misc
 *  \brief
 *    StackWalker (simple backtrace) for Win32 (MSVC, clang-cl and MinGW)
 */

/**
 * Author:
 *    Jochen Kalmbach, Germany
 *    (c) 2002-2004 (Freeware)
 *    http://www.codeproject.com/tools/leakfinder.asp
 *
 * License (The zlib/libpng License, http://www.opensource.org/licenses/zlib-license.php):
 *
 * Copyright (c) 2004 Jochen Kalmbach
 *
 * This software is provided 'as-is', without any express or implied warranty.
 * In no event will the authors be held liable for any damages arising from the
 * use of this software.
 *
 * Permission is granted to anyone to use this software for any purpose, including
 * commercial applications, and to alter it and redistribute it freely, subject to
 * the following restrictions:
 *
 * 1. The origin of this software must not be misrepresented; you must not claim
 *    that you wrote the original software. If you use this software in a product,
 *    an acknowledgment in the product documentation would be appreciated but is
 *    not required.
 *
 * 2. Altered source versions must be plainly marked as such, and must not be
 *    misrepresented as being the original software.
 *
 * 3. This notice may not be removed or altered from any source distribution.
 *
 */

/**
 * Aug 2011   Adapted for Wsock_trace - G. Vanem (gvanem@yahoo.no)
 *            No longer Unicode aware.
 *            Simplified and rewritten from C++ to pure C.
 *            Removed the Hungarian notation etc, etc.
 */

#if defined(UNICODE) || defined(_UNICODE)
  #define DBGHELP_TRANSLATE_TCHAR
#endif

#include <windows.h>
#include <psapi.h>
#include <tlhelp32.h>
#include <imagehlp.h>

#include <time.h>
#include <assert.h>
#include <errno.h>

#include "common.h"
#include "init.h"
#include "bfd_gcc.h"
#include "stkwalk.h"

#if defined(_MSC_VER) && (_MSC_VER >= 1900) && !defined(__clang__)
 /**
  * With the Universal CRT in Windows/MSVC and with 'cl' CFLAGS:
  *  '-MD' or '-MDd' -> __scrt_is_ucrt_dll_in_use() = 1.
  *  '-MT' or '-MTd' -> __scrt_is_ucrt_dll_in_use() = 0.
  *
  * The latter case causes very long C++ symbols to be found in 'enum_symbols_proc()'
  * for 'g_module'. Ref. the use of 'g_long_CPP_syms'.
  */
  extern int __cdecl __scrt_is_ucrt_dll_in_use (void);
  #define SCRT_IS_UCRT_DLL_IN_USE() __scrt_is_ucrt_dll_in_use()
#endif

/**
 * Check if the <imagehlp.h> / <dbghelp.h> API is good enough for
 * using 'SymEnumSymbolsEx()' etc.
 */
#if defined(API_VERSION_NUMBER) && (API_VERSION_NUMBER >= 11)
  #define USE_SymEnumSymbolsEx 1
#else
  #define USE_SymEnumSymbolsEx 0
#endif

/**
 * \def USE_SymFromAaddr
 *  Use `(*p_SymFromAddr)()` to decode a single stack-frame
 *
 * \def USE_CreateToolhelp32Snapshot
 *  When using the ToolHelp32 API, call `(*p_CreateToolhelp32Snapshot)()`
 *  to get a thread snapshot. But it's not used for anything yet.
 */
#define USE_SymFromAaddr             1
#define USE_CreateToolhelp32Snapshot 1

static HANDLE       g_proc;                /**< Value from `GetCurrentProcess()` */
static DWORD        g_proc_id;             /**< Value from `GetCurrentProcessId()` */
static char         g_module [_MAX_PATH];  /**< The .exe we're linked to */
static char         g_sym_dir[_MAX_PATH];  /**< The `%WinDir\\symbols` directory */
static smartlist_t *g_modules_list;        /**< List of all modules in our program */
static smartlist_t *g_symbols_list;        /**< List of all symbols when `g_cfg.pdb_report == TRUE` */
static int          g_quit_count = 0;      /**< Count of `q` or `ESC` keypresses in the `enum_symbols_proc()` callback */
static DWORD        g_num_compares;        /** Number of compares in `print_modules_and_pdb_info()`. Just for tracing */

static const char *get_error (void);

#if !defined(USE_PythonHook)
  #define USE_PythonHook     1
  #define USE_Py_inject_code 0
  #define USE_Py_mhook_code  1

#else
  #define USE_PythonHook     0
  #define USE_Py_inject_code 0
  #define USE_Py_mhook_code  0
#endif

#if USE_Py_mhook_code && (defined(_M_IX86) || defined(_M_X64))
  #include "mhook/mhook.h" /* MSVC/clang-cl only */
#else
  #undef  USE_Py_mhook_code
  #define USE_Py_mhook_code 0
#endif

#if USE_SymEnumSymbolsEx
  static bool  g_long_CPP_syms = false;
  static DWORD enum_module_symbols (smartlist_t *sl, const char *module, bool is_last, bool verbose);
#endif

#define MAX_NAMELEN  1024        /* max name length for found symbols */
#define TBUF_LEN     1024        /* for a temp buffers */

#ifndef IN_OPT
#define IN_OPT
#endif

#ifndef SYMENUM_OPTIONS_DEFAULT
#define SYMENUM_OPTIONS_DEFAULT 0x00000001
#endif

#ifndef SYMENUM_OPTIONS_INLINE
#define SYMENUM_OPTIONS_INLINE  0x00000002
#endif

/*
 * 'API_VERSION_NUMBER' defined in '<imagehlp.h>'
 *
 * Here I have included the API-Version 9 declarations, so it will also compile on systems,
 * where the new 'Platform SDK' is not installed.
 */
#if defined(API_VERSION_NUMBER) && (API_VERSION_NUMBER < 9)

#define DBHHEADER_DEBUGDIRS   0x1
#define DBHHEADER_CVMISC      0x2
#define DBHHEADER_PDBGUID     0x3

typedef struct _MODLOAD_DATA {
    DWORD   ssize;                  /* size of this struct */
    DWORD   ssig;                   /* signature identifying the passed data */
    PVOID   data;                   /* pointer to passed data */
    DWORD   size;                   /* size of passed data */
    DWORD   flags;                  /* options */
  } MODLOAD_DATA;

typedef BOOL (WINAPI *PREAD_PROCESS_MEMORY_ROUTINE64)(
    HANDLE      process,
    DWORD64     qwBaseAddress,
    PVOID       lpBuffer,
    DWORD       nSize,
    LPDWORD     lpNumberOfBytesRead);

typedef struct _IMAGEHLP_LINE64 {
    DWORD       SizeOfStruct;           /* set to sizeof(IMAGEHLP_LINE64) */
    PVOID       Key;                    /* internal */
    DWORD       LineNumber;             /* line number in file */
    PCHAR       FileName;               /* full filename */
    DWORD64     Address;                /* first instruction of line */
  } IMAGEHLP_LINE64;

typedef struct _IMAGEHLP_MODULE64 {
    DWORD       SizeOfStruct;           /* set to sizeof(IMAGEHLP_MODULE64) */
    DWORD64     BaseOfImage;            /* base load address of module */
    DWORD       ImageSize;              /* virtual size of the loaded module */
    DWORD       TimeDateStamp;          /* date/time stamp from pe header */
    DWORD       CheckSum;               /* checksum from the pe header */
    DWORD       NumSyms;                /* number of symbols in the symbol table */
    SYM_TYPE    SymType;                /* type of symbols loaded */
    CHAR        ModuleName[32];         /* module name */
    CHAR        ImageName[256];         /* image name */
    CHAR        LoadedImageName[256];   /* symbol file name */
  } IMAGEHLP_MODULE64;

typedef struct _IMAGEHLP_SYMBOL64 {
    DWORD       SizeOfStruct;           /* set to sizeof(IMAGEHLP_SYMBOL64) */
    DWORD64     Address;                /* virtual address including dll base address */
    DWORD       Size;                   /* estimated size of symbol, can be zero */
    DWORD       Flags;                  /* info about the symbols, see the SYMFLAG_x defines (DbgHelp.h) */
    DWORD       MaxNameLength;          /* maximum size of symbol name in 'Name' */
    CHAR        Name[1];                /* symbol name (null terminated string) */
  } IMAGEHLP_SYMBOL64;

typedef struct _ADDRESS64 {
    DWORD64      Offset;
    WORD         Segment;
    ADDRESS_MODE Mode;
  } ADDRESS64;

typedef struct _KDHELP64 {
    /* address of kernel thread object, as provided in the WAIT_STATE_CHANGE packet.
     */
    DWORD64  Thread;

    /* offset in thread object to pointer to the current callback frame in kernel stack.
     */
    DWORD    ThCallbackStack;

    /* offset in thread object to pointer to the current callback backing store frame in kernel stack.
     */
    DWORD    ThCallbackBStore;

    /* offsets to values in frame: */

    /* address of next callback frame
     */
    DWORD    NextCallback;

    /* address of saved frame pointer (if applicable)
     */
    DWORD    FramePointer;

    /* address of the kernel function that calls out to user mode
     */
    DWORD64  KiCallUserMode;

    /* address of the user mode dispatcher function
     */
    DWORD64  KeUserCallbackDispatcher;

    /* lowest kernel mode address
     */
    DWORD64  SystemRangeStart;
    DWORD64  Reserved[8];
  } KDHELP64;

typedef struct _STACKFRAME64 {
    ADDRESS64   AddrPC;             /* program counter */
    ADDRESS64   AddrReturn;         /* return address */
    ADDRESS64   AddrFrame;          /* frame pointer */
    ADDRESS64   AddrStack;          /* stack pointer */
    ADDRESS64   AddrBStore;         /* backing store pointer */
    PVOID       FuncTableEntry;     /* pointer to pdata/fpo or NULL */
    DWORD64     Params[4];          /* possible arguments to the function */
    BOOL        Far;                /* WOW far call */
    BOOL        Virtual;            /* is this a virtual frame? */
    DWORD64     Reserved[3];
    KDHELP64    KdHelp;
  } STACKFRAME64;

#if defined(__MINGW32__) || defined(__CYGWIN__)
  typedef struct _SYMBOL_INFO {
      ULONG   SizeOfStruct;
      ULONG   TypeIndex;
      ULONG64 Reserved[2];
      ULONG   Index;
      ULONG   Size;
      ULONG64 ModBase;
      ULONG   Flags;
      ULONG64 Value;
      ULONG64 Address;
      ULONG   Register;
      ULONG   Scope;
      ULONG   Tag;
      ULONG   NameLen;
      ULONG   MaxNameLen;
      TCHAR   Name[1];
    } SYMBOL_INFO;
#endif

typedef PVOID (WINAPI *PFUNCTION_TABLE_ACCESS_ROUTINE64) (
                       HANDLE process, DWORD64 AddrBase);

typedef DWORD64 (WINAPI *PGET_MODULE_BASE_ROUTINE64) (
                         HANDLE process, DWORD64 Address);

typedef DWORD64 (WINAPI *PTRANSLATE_ADDRESS_ROUTINE64) (
                         HANDLE process, HANDLE thread, ADDRESS64 *addr);

#endif  /* API_VERSION_NUMBER < 9 */

/**
 * \def DEF_WIN_FUNC
 *
 * Handy macro to both define and declare the function-pointer for
 * `dbghelp.dll`, `psapi.dll`, `tlhelp32.dll` and `kernel32.dll` functions.
 */
#define DEF_WIN_FUNC(ret, f, args)  typedef ret (WINAPI *func_##f) args; \
                                    static func_##f p_##f = NULL

/**
 * \def DEF_PY_FUNC
 *
 * Similarily for Python function which are always `__cdecl`.
 */
#define DEF_PY_FUNC(ret, f, args)  typedef ret (__cdecl *func_##f) args; \
                                   static func_##f p_##f = NULL

DEF_WIN_FUNC (BOOL,  SymCleanup, (IN HANDLE process));
DEF_WIN_FUNC (DWORD, SymGetOptions, (VOID));
DEF_WIN_FUNC (DWORD, SymSetOptions, (IN DWORD SymOptions));

DEF_WIN_FUNC (PVOID, SymFunctionTableAccess64, (IN HANDLE process,
                                                IN DWORD64 AddrBase));

DEF_WIN_FUNC (BOOL,  SymGetLineFromAddr64, (IN  HANDLE           process,
                                            IN  DWORD64          addr,
                                            OUT DWORD           *displacement,
                                            OUT IMAGEHLP_LINE64 *Line));

DEF_WIN_FUNC (DWORD64, SymGetModuleBase64, (IN HANDLE  process,
                                            IN DWORD64 addr));

DEF_WIN_FUNC (BOOL,    SymGetModuleInfo64, (IN  HANDLE             process,
                                            IN  DWORD64            addr,
                                            OUT IMAGEHLP_MODULE64 *ModuleInfo));

DEF_WIN_FUNC (BOOL,    SymGetSymFromAddr64, (IN  HANDLE             process,
                                             IN  DWORD64            addr,
                                             OUT DWORD64           *displacement,
                                             OUT IMAGEHLP_SYMBOL64 *Symbol));

DEF_WIN_FUNC (BOOL,    SymFromAddr,         (IN     HANDLE       process,
                                             IN     DWORD64      addr,
                                             OUT    DWORD64     *displacement,
                                             IN OUT SYMBOL_INFO *Symbol));

DEF_WIN_FUNC (BOOL,    SymInitialize,       (IN HANDLE process,
                                             IN PCSTR  UserSearchPath,
                                             IN BOOL   invadeProcess));

DEF_WIN_FUNC (DWORD,   SymLoadModule64,     (IN HANDLE  process,
                                             IN HANDLE  file,
                                             IN PCSTR   ImageName,
                                             IN PCSTR   ModuleName,
                                             IN DWORD64 BaseOfDll,
                                             IN DWORD   SizeOfDll));

DEF_WIN_FUNC (BOOL,    StackWalk64,         (IN     DWORD                            MachineType,
                                             IN     HANDLE                           process,
                                             IN     HANDLE                           thread,
                                             IN OUT STACKFRAME64                    *StackFrame,
                                             IN OUT VOID                            *ContextRecord,
                                             IN     PREAD_PROCESS_MEMORY_ROUTINE64   ReadMemoryRoutine,
                                             IN     PFUNCTION_TABLE_ACCESS_ROUTINE64 FunctionTableAccessRoutine,
                                             IN     PGET_MODULE_BASE_ROUTINE64       GetModuleBaseRoutine,
                                             IN     PTRANSLATE_ADDRESS_ROUTINE64     TranslateAddress));

DEF_WIN_FUNC (DWORD,   UnDecorateSymbolName, (IN  PCSTR DecoratedName,
                                              OUT PSTR  UnDecoratedName,
                                              IN  DWORD UndecoratedLength,
                                              IN  DWORD Flags));
#if USE_SymEnumSymbolsEx
  DEF_WIN_FUNC (BOOL, SymEnumSymbolsEx,      (IN     HANDLE                         hProcess,
                                              IN     ULONG64                        BaseOfDll,
                                              IN_OPT const char                    *Mask,
                                              IN     PSYM_ENUMERATESYMBOLS_CALLBACK EnumSymbolsCallback,
                                              IN_OPT VOID                           *UserContext,
                                              IN     DWORD                          Options));

  DEF_WIN_FUNC (BOOL, SymSrvGetFileIndexInfo, (IN  PCTSTR             File,
                                               OUT PSYMSRV_INDEX_INFO Info,
                                               IN  DWORD              Flags));
#endif

/*
 * For `tlhelp32.dll` functions:
 */
DEF_WIN_FUNC (HANDLE, CreateToolhelp32Snapshot, (DWORD dwFlags, DWORD PID));
DEF_WIN_FUNC (BOOL,   Module32First, (HANDLE snap, MODULEENTRY32 *me));
DEF_WIN_FUNC (BOOL,   Module32Next, (HANDLE snap, MODULEENTRY32 *me));
DEF_WIN_FUNC (BOOL,   Thread32First, (HANDLE snap, THREADENTRY32 *te));
DEF_WIN_FUNC (BOOL,   Thread32Next, (HANDLE snap, THREADENTRY32 *te));

#define ADD_VALUE(opt, dll, func)  { opt, NULL, dll, #func, (void**)&p_##func }

static struct LoadTable tlhelp32_funcs[] = {
              ADD_VALUE (0, "kernel32.dll", CreateToolhelp32Snapshot),
              ADD_VALUE (0, "kernel32.dll", Module32First),
              ADD_VALUE (0, "kernel32.dll", Module32Next),
              ADD_VALUE (0, "kernel32.dll", Thread32First),
              ADD_VALUE (0, "kernel32.dll", Thread32Next),
              ADD_VALUE (1, "tlhelp32.dll", CreateToolhelp32Snapshot), /* (1) */
              ADD_VALUE (1, "tlhelp32.dll", Module32First),            /* (1) */
              ADD_VALUE (1, "tlhelp32.dll", Module32Next)              /* (1) */
            };
            /* (1): tlhelp32.dll is present on Win9x/ME. On Win-NT+ these functions are in kernel32.dll.
             */

/*
 * For `psapi.dll` and `kernel32.dll` functions:
 */
DEF_WIN_FUNC (BOOL,  EnumProcessModules,   (HANDLE process, HMODULE *module, DWORD cb, DWORD *needed));
DEF_WIN_FUNC (DWORD, GetModuleFileNameExA, (HANDLE process, HMODULE module, LPSTR lpFilename, DWORD nSize));
DEF_WIN_FUNC (BOOL,  GetModuleInformation, (HANDLE process, HMODULE module, MODULEINFO *pmi, DWORD nSize));

static struct LoadTable psapi_funcs[] = {
              ADD_VALUE (1, "kernel32.dll", EnumProcessModules),   /* (1) */
              ADD_VALUE (1, "kernel32.dll", GetModuleFileNameExA), /* (1) */
              ADD_VALUE (1, "kernel32.dll", GetModuleInformation), /* (1) */
              ADD_VALUE (0, "psapi.dll",    EnumProcessModules),
              ADD_VALUE (0, "psapi.dll",    GetModuleFileNameExA),
              ADD_VALUE (0, "psapi.dll",    GetModuleInformation)
             };
            /* (1) = These are in Kernel32.dll in Win-7+ Win-Server 2008 R2.
             */

/*
 * For `dbghelp.dll` functions:
 */
static struct LoadTable dbghelp_funcs[] = {
                        ADD_VALUE (0, "dbghelp.dll", SymCleanup),
                        ADD_VALUE (0, "dbghelp.dll", SymFunctionTableAccess64),
                        ADD_VALUE (0, "dbghelp.dll", SymGetLineFromAddr64),
                        ADD_VALUE (0, "dbghelp.dll", SymGetModuleBase64),
                        ADD_VALUE (0, "dbghelp.dll", SymGetModuleInfo64),
                        ADD_VALUE (0, "dbghelp.dll", SymGetOptions),
                        ADD_VALUE (0, "dbghelp.dll", SymGetSymFromAddr64),
                        ADD_VALUE (0, "dbghelp.dll", SymFromAddr),
                        ADD_VALUE (0, "dbghelp.dll", SymInitialize),
                        ADD_VALUE (0, "dbghelp.dll", SymSetOptions),
                        ADD_VALUE (0, "dbghelp.dll", StackWalk64),
                        ADD_VALUE (0, "dbghelp.dll", SymLoadModule64),
#if USE_SymEnumSymbolsEx
                        ADD_VALUE (0, "dbghelp.dll", SymEnumSymbolsEx),
                        ADD_VALUE (1, "dbghelp.dll", SymSrvGetFileIndexInfo),
#endif
                        ADD_VALUE (0, "dbghelp.dll", UnDecorateSymbolName),
                      };

/*
 * For decoding 'struct _SYMBOL_INFO::Flags'.
 *
 * Ref: https://msdn.microsoft.com/en-us/library/windows/desktop/ms680686(v=vs.85).aspx
 */
#if defined(__MINGW32__) || defined(__CYGWIN__)
  #define SYMFLAG_VALUEPRESENT 0x00000001
  #define SYMFLAG_REGISTER     0x00000008
  #define SYMFLAG_REGREL       0x00000010
  #define SYMFLAG_FRAMEREL     0x00000020
  #define SYMFLAG_PARAMETER    0x00000040
  #define SYMFLAG_LOCAL        0x00000080
  #define SYMFLAG_CONSTANT     0x00000100
  #define SYMFLAG_EXPORT       0x00000200
  #define SYMFLAG_FUNCTION     0x00000800
  #define SYMFLAG_VIRTUAL      0x00001000
  #define SYMFLAG_THUNK        0x00002000
  #define SYMFLAG_TLSREL       0x00004000
  #define SYMFLAG_SLOT         0x00008000
  #define SYMFLAG_ILREL        0x00010000
  #define SYMFLAG_METADATA     0x00020000
  #define SYMFLAG_CLR_TOKEN    0x00040000
#endif

#ifndef SYMFLAG_NULL
#define SYMFLAG_NULL               0x00080000
#endif

#ifndef SYMFLAG_FUNC_NO_RETURN
#define SYMFLAG_FUNC_NO_RETURN     0x00100000
#endif

#ifndef SYMFLAG_SYNTHETIC_ZEROBASE
#define SYMFLAG_SYNTHETIC_ZEROBASE 0x00200000
#endif

#ifndef SYMFLAG_PUBLIC_CODE
#define SYMFLAG_PUBLIC_CODE        0x00400000
#endif

#if USE_SymEnumSymbolsEx
#define ADD_FLAG_VALUE(v)  { v, #v }

static const struct search_list symbol_info_flags[] = {
                                ADD_FLAG_VALUE (SYMFLAG_CLR_TOKEN),
                                ADD_FLAG_VALUE (SYMFLAG_CONSTANT),
                                ADD_FLAG_VALUE (SYMFLAG_EXPORT),
                                ADD_FLAG_VALUE (SYMFLAG_FORWARDER),
                                ADD_FLAG_VALUE (SYMFLAG_FRAMEREL),
                                ADD_FLAG_VALUE (SYMFLAG_FUNCTION),
                                ADD_FLAG_VALUE (SYMFLAG_ILREL),
                                ADD_FLAG_VALUE (SYMFLAG_LOCAL),
                                ADD_FLAG_VALUE (SYMFLAG_METADATA),
                                ADD_FLAG_VALUE (SYMFLAG_PARAMETER),
                                ADD_FLAG_VALUE (SYMFLAG_REGISTER),
                                ADD_FLAG_VALUE (SYMFLAG_REGREL),
                                ADD_FLAG_VALUE (SYMFLAG_SLOT),
                                ADD_FLAG_VALUE (SYMFLAG_THUNK),
                                ADD_FLAG_VALUE (SYMFLAG_TLSREL),
                                ADD_FLAG_VALUE (SYMFLAG_VALUEPRESENT),
                                ADD_FLAG_VALUE (SYMFLAG_VIRTUAL),
                                ADD_FLAG_VALUE (SYMFLAG_NULL),
                                ADD_FLAG_VALUE (SYMFLAG_FUNC_NO_RETURN),
                                ADD_FLAG_VALUE (SYMFLAG_SYNTHETIC_ZEROBASE),
                                ADD_FLAG_VALUE (SYMFLAG_PUBLIC_CODE)
                              };

static const char *sym_flags_decode (DWORD flags)
{
  if (flags == 0)
     return ("0");
  return flags_decode (flags, symbol_info_flags, DIM(symbol_info_flags));
}

#if !defined(_MSC_VER) || !defined(_NO_CVCONST_H)
  enum SymTagEnum {
       SymTagNull,
       SymTagExe,
       SymTagCompiland,
       SymTagCompilandDetails,
       SymTagCompilandEnv,
       SymTagFunction,
       SymTagBlock,
       SymTagData,
       SymTagAnnotation,
       SymTagLabel,
       SymTagPublicSymbol,
       SymTagUDT,
       SymTagEnum,
       SymTagFunctionType,
       SymTagPointerType,
       SymTagArrayType,
       SymTagBaseType,
       SymTagTypedef,
       SymTagBaseClass,
       SymTagFriend,
       SymTagFunctionArgType,
       SymTagFuncDebugStart,
       SymTagFuncDebugEnd,
       SymTagUsingNamespace,
       SymTagVTableShape,
       SymTagVTable,
       SymTagCustom,
       SymTagThunk,
       SymTagCustomType,
       SymTagManagedType,
       SymTagDimension,
       SymTagCallSite,
       SymTagInlineSite,
       SymTagBaseInterface,
       SymTagVectorType,
       SymTagMatrixType,
       SymTagHLSLType,
       SymTagMax
     };
#endif

#define ADD_TAG_VALUE(v)  { v, #v }

static const struct search_list symbol_tags[] = {
                                ADD_TAG_VALUE (SymTagNull),
                                ADD_TAG_VALUE (SymTagExe),
                                ADD_TAG_VALUE (SymTagCompiland),
                                ADD_TAG_VALUE (SymTagCompilandDetails),
                                ADD_TAG_VALUE (SymTagCompilandEnv),
                                ADD_TAG_VALUE (SymTagFunction),
                                ADD_TAG_VALUE (SymTagBlock),
                                ADD_TAG_VALUE (SymTagData),
                                ADD_TAG_VALUE (SymTagAnnotation),
                                ADD_TAG_VALUE (SymTagLabel),
                                ADD_TAG_VALUE (SymTagPublicSymbol),
                                ADD_TAG_VALUE (SymTagUDT),
                                ADD_TAG_VALUE (SymTagEnum),
                                ADD_TAG_VALUE (SymTagFunctionType),
                                ADD_TAG_VALUE (SymTagPointerType),
                                ADD_TAG_VALUE (SymTagArrayType),
                                ADD_TAG_VALUE (SymTagBaseType),
                                ADD_TAG_VALUE (SymTagTypedef),
                                ADD_TAG_VALUE (SymTagBaseClass),
                                ADD_TAG_VALUE (SymTagFriend),
                                ADD_TAG_VALUE (SymTagFunctionArgType),
                                ADD_TAG_VALUE (SymTagFuncDebugStart),
                                ADD_TAG_VALUE (SymTagFuncDebugEnd),
                                ADD_TAG_VALUE (SymTagUsingNamespace),
                                ADD_TAG_VALUE (SymTagVTableShape),
                                ADD_TAG_VALUE (SymTagVTable),
                                ADD_TAG_VALUE (SymTagCustom),
                                ADD_TAG_VALUE (SymTagThunk),
                                ADD_TAG_VALUE (SymTagCustomType),
                                ADD_TAG_VALUE (SymTagManagedType),
                                ADD_TAG_VALUE (SymTagDimension),
                                ADD_TAG_VALUE (SymTagCallSite),
                                ADD_TAG_VALUE (SymTagInlineSite),
                                ADD_TAG_VALUE (SymTagBaseInterface),
                                ADD_TAG_VALUE (SymTagVectorType),
                                ADD_TAG_VALUE (SymTagMatrixType),
                                ADD_TAG_VALUE (SymTagHLSLType)
                              };

static const char *sym_tag_decode (unsigned tag)
{
  return list_lookup_name (tag, symbol_tags, DIM(symbol_tags));
}
#endif /* USE_SymEnumSymbolsEx */


#if USE_PythonHook
/**
 * Special hacks for tracing Python scripts:
 * If a module-list is like (starting with module 0 == 'python.exe' or 'python3.exe' etc.):
 * ```
 *   c:\ProgramFiles\Python39\src\python.exe                0x1CED0000     104 kB
 *   c:\gv\VC_2019\bin\wsock_trace-x86.dll                  0x644D0000     624 kB
 *   c:\ProgramFiles\Python\src\python311.dll               0x64570000   5,816 kB
 * ```
 *
 * Python 3.x: find and hook the `PyModule_Create2()` function. Then when it's called with
 *   `PySocket_MODULE_NAME == "_socket"` in the `struct PyModuleDef` argument, enumerate
 *   the `<g_py_dir>/DLLs/_socket.pyd` module for PDB symbols.
 *
 * Python 2.x: find and hook the `PyModule_New()` function. The rest is similar.
 */
static char     *g_py_dir, *g_py_exe, *g_py_dll;
static int       g_py_major_ver;
static HINSTANCE g_py_hnd;

#if !defined(ssize_t) && !defined(_SSIZE_T_DEFINED)
#define ssize_t INT_PTR
#endif

#define Py_ssize_t    ssize_t
#define PyTypeObject  void

typedef struct PyObject {
        Py_ssize_t    ob_refcnt;
        PyTypeObject *ob_type;
      } PyObject;

typedef struct PyModuleDef_Base {
        PyObject      ob_base;
        PyObject   *(*m_init)(void);
        Py_ssize_t    m_index;
        PyObject     *m_copy;
      } PyModuleDef_Base;

typedef struct PyModuleDef {
        PyModuleDef_Base m_base;
        const char      *m_name;
        const char      *m_doc;
      } PyModuleDef;

#if USE_Py_inject_code
  DEF_PY_FUNC (PyObject*, PyModule_Create2, (PyModuleDef *m_def, int api_ver));
  DEF_PY_FUNC (PyObject*, PyModule_New,     (const char *module));
#endif

typedef int (*Py_AuditHookFunction) (const char *event, PyObject *args, void *userdata);

DEF_PY_FUNC (int,          PySys_AddAuditHook, (Py_AuditHookFunction hook, void *user_data));
DEF_PY_FUNC (int,          PyArg_ParseTuple,   (PyObject *o, const char *, ...));
DEF_PY_FUNC (const char *, PyUnicode_AsUTF8,   (PyObject *o));

/*
 * The table of "audit events":
 *   https://docs.python.org/3/library/audit_events.html
 */
static int our_AddAuditHook (const char *event, PyObject *args, void *userdata)
{
  /* args tuple == module, filename, sys.path, sys.meta_path, sys.path_hooks
   */
  if (!strcmp(event, "import"))
  {
    PyObject   *module, *filename, *dont_care;
    const char *_module = "?";
    const char *_filename = "?";

    if ((*p_PyArg_ParseTuple) (args, "OOOOO", &module, &filename, &dont_care, &dont_care, &dont_care))
    {
      _module   = (*p_PyUnicode_AsUTF8) (module);
      _filename = (*p_PyUnicode_AsUTF8) (filename);
    }
    TRACE (2, "audit event: %s, module: '%s', filename: '%s'\n", event, _module, _filename);

    /** \todo
     */
  }
  (void) userdata;
  return (0);
}

static bool load_AddAuditHook (void)
{
  #define LOAD_FUNC(f)                                          \
          do {                                                  \
            func = #f;                                          \
            p_##f = (func_##f) GetProcAddress (g_py_hnd, func); \
            if (!p_##f)                                         \
               goto quit;                                       \
          } while (0)

  const char *func;

  if (!g_py_hnd)
     g_py_hnd = LoadLibrary (g_py_dll);

  if (!g_py_hnd)
  {
    TRACE (1, "LoadLibrary (\"%s\") failed: %s.\n", g_py_dll, get_error());
    return (false);
  }

  /* Needs Python 3.8+. But try anyway
   */
  LOAD_FUNC (PySys_AddAuditHook);
  LOAD_FUNC (PyArg_ParseTuple);
  LOAD_FUNC (PyUnicode_AsUTF8);
  #undef LOAD_FUNC
  return (true);

quit:
  TRACE (1, "Did not find \"%s()\" in \"%s\".\n", func, g_py_dll);
  return (false);
}

/**
 * This requires that a `python*.dll` is in the same directory as `python*exe'.
 * I'm not sure that's the case for all situations (like with `%WinDir\\py.exe`).
 */
static bool is_python_dll (const char *fname)
{
  bool  equal_dir;
  char *dir;
  const char *base, *ext;

  dir = dirname (fname);
  equal_dir = (stricmp(g_py_dir, dir) == 0);

  base = fname + strlen (dir) + 1;
  ext = strrchr (base, '.');

  if (equal_dir && !stricmp(ext, ".dll") && !strnicmp(base, "python", 5))
     g_py_dll = strdup (fname);

  ext--;
  while (isdigit((int)*ext))
     ext--;
  g_py_major_ver = ext[1] - '0';

  free (dir);

  if (equal_dir && g_py_dll && (g_py_major_ver == 2 || g_py_major_ver == 3))
  {
    TRACE (1, "equal_dir: %d, g_py_dll: '%s', g_py_major_ver: %d\n", equal_dir, g_py_dll, g_py_major_ver);
    return (true);
  }
  return (false);
}

#if USE_Py_inject_code
static INT_PTR addr_to_patch, addr_to_unpatch;

static void unpatch_python_dll (void);

static PyObject *our_PyModule_Create2 (PyModuleDef *m_def, int api_ver)
{
  PyObject *ret;

  TRACE (1, "m_name: 0x%p, api_ver: %d.\n", m_def->m_name, api_ver);

  unpatch_python_dll();

  ret = (*p_PyModule_Create2) (m_def, api_ver);

  TRACE (1, "ret: 0x%p.\n", ret);
  return (ret);
}

static PyObject *our_PyModule_New (const char *m_name)
{
  PyObject *ret;

  TRACE (1, "m_name: '%s'.\n", m_name);

  unpatch_python_dll();

  ret = (*p_PyModule_New) (m_name);

  TRACE (1, "ret: 0x%p.\n", ret);
  return (ret);
}

/**
 * Rewritten from:
 *  https://wiki.skullsecurity.org/.dll_Injection_and_Patching
 *
 * Except it's triggering a 'APPLICATION_FAULT_SOFTWARE_NX_FAULT' when
 * the following 'str*[]' array is in the data-segment. Hence use
 * `VirtualAlloc()`.
 */

/* This creates the wrapper, leaving an "????" where the call distance will be inserted.
 */
static char str_wrapper[] = "\x89\x90\x58\xee\x4f\x00\x60\xe8????\xc3";

static char str_wrapper_C[] = "\x89\x90\x58\xee\x4f\x00\x60\xe8????\x83\xc4\x08\xc3";  /* add esp,8; ret */

/* This is the actual patch
 */
static char str_patch[] = "\xE8????\x90";

/* This is the original buffer, used when the .dll is removed (to restore the program's
 * original functionality)
 */
static char str_unpatch[] = "\x29\x90\x88\xEE\x4F\x00";

static char *vaddr_wrapper, *vaddr_patch;

static void dump_opcodes (SIZE_T written)
{
  char  instructions [100];
  char *p = instructions;
  int   i;

  for (i = 0; p < instructions + sizeof(instructions) - 2 && i < written; i++)
  {
    strcpy (p, str_hex_byte(vaddr_wrapper[i]));
    p += 2;
    *p++ = ' ';
  }
  *p = '\0';
  TRACE (1, "WriteProcessMemory() wrote %lu bytes at 0x%p:\n"
            "       %s\n", written, vaddr_wrapper, instructions);
}

static void inject_code (void)
{
  /* This is the address where the patch is going
   */
  SIZE_T written = 0;

  strcpy (vaddr_wrapper, str_wrapper);
  vaddr_patch = vaddr_wrapper + strlen(str_wrapper);
  strcpy (vaddr_patch, str_patch);

  /* This sets the "????" in the string to equal the distance between 'our_PyModule_X'
   * and from the byte immediately after the ????, which is 12 bytes from the beginning of
   * the string (that's where the relative distance begins)
   */
  *((INT_PTR*) (vaddr_wrapper + 8)) = addr_to_patch - (INT_PTR)(vaddr_wrapper + 12);

  /* This replaces the ???? with the distance from the patch to the wrapper. 5 is added because that's
   * the length of the call instruction (E8 xx xx xx xx xx) and the distance is relative to the byte
   * after the call.
   */
  *((INT_PTR*) (vaddr_patch + 1)) = ((INT_PTR)vaddr_wrapper) - (addr_to_patch + 5);

  /* Write our patch.
   */
  WriteProcessMemory (GetCurrentProcess(), (void*)addr_to_patch, vaddr_wrapper,
                      sizeof(str_wrapper) + sizeof(str_patch) - 2, &written);
  dump_opcodes (written);
}

/*
 * Undo the above patch.
 */
static void unpatch_python_dll (void)
{
  SIZE_T  written = 0;

  *((INT_PTR*) (vaddr_wrapper + 8)) = addr_to_unpatch - (INT_PTR)(vaddr_wrapper + 10);
  *((INT_PTR*) (vaddr_patch + 1)) = ((INT_PTR)vaddr_wrapper) - (addr_to_unpatch + 5);

  WriteProcessMemory (GetCurrentProcess(), (void*)addr_to_unpatch, vaddr_patch, sizeof(str_unpatch) - 1, &written);
  TRACE (1, "WriteProcessMemory() written: %lu.\n", written);
}

/*
 * Patch 'python3*.dll' to call `our_PyModule_Create2()`.
 * Or if it's Python 2.x, patch 'python2*.dll' to
 * call `our_PyModule_New()`.
 */
static void patch_python_dll (void)
{
  DWORD prot = PAGE_READWRITE;
  BOOL  vaddr_ok;

  g_py_hnd = LoadLibrary (g_py_dll);
  if (!g_py_hnd)
  {
    TRACE (1, "LoadLibrary (\"%s\") failed: %s.\n", g_py_dll, get_error());
    goto failed;
  }

  if (g_py_major_ver == 3)
  {
    p_PyModule_Create2 = (func_PyModule_Create2*) GetProcAddress (g_py_hnd, "PyModule_Create2");
    addr_to_patch   = (INT_PTR) p_PyModule_Create2;
    addr_to_unpatch = (INT_PTR) our_PyModule_Create2;
    if (!p_PyModule_Create2)
    {
      TRACE (1, "Did not find \"PyModule_Create2\" in \"%s\".\n", g_py_dll);
      goto failed;
    }
  }
  else
  {
    p_PyModule_New  = (func_PyModule_New*) GetProcAddress (g_py_hnd, "PyModule_New");
    addr_to_patch   = (INT_PTR) p_PyModule_New;
    addr_to_unpatch = (INT_PTR) our_PyModule_New;
    if (!p_PyModule_New)
    {
      TRACE (1, "Did not find \"PyModule_New\" in \"%s\".\n", g_py_dll);
      goto failed;
    }
  }

  TRACE (1, "g_py_dll: '%s', addr: 0x%p.\n", g_py_dll, (const void*)addr_to_patch);

  vaddr_wrapper = VirtualAlloc (NULL, 1024, MEM_COMMIT, prot);
  vaddr_ok = VirtualProtect (vaddr_wrapper, 1024, PAGE_EXECUTE_READWRITE, &prot);

  TRACE (1, "vaddr_wrapper: %p, vaddr_ok: %d.\n", vaddr_wrapper, vaddr_ok);
  if (!vaddr_ok)
     goto failed;

  inject_code();
  return;

failed:
  if (vaddr_wrapper)
     VirtualFree (vaddr_wrapper, 0, MEM_RELEASE);
  if (g_py_hnd)
     FreeLibrary (g_py_hnd);
  g_py_hnd = NULL;
  vaddr_wrapper = NULL;
}

#else /* USE_PythonHook */

/**
 * \todo Enumerate the extra .pyd files reported from Python.
 */
static void enumerate_py_DLLs (void)
{
}
#endif /* USE_Py_inject_code  */
#endif /* USE_PythonHook */

/*
 * Add some module information to 'g_modules_list'.
 */
static void modules_list_add (const char *module, ULONG_PTR base_addr, DWORD size)
{
  struct ModuleEntry *me = malloc (sizeof(*me) + strlen(module) + 1);

  me->module_name = strcpy ((char*)(me+1), module);
  me->base_addr   = base_addr;
  me->size        = size;
  memset (&me->stat, '\0', sizeof(me->stat));
  smartlist_add (g_modules_list, me);
}

/*
 * A `smartlist_wipe()` helper callback for `modules_list_free()`.
 */
static void module_free (void *m)
{
  struct ModuleEntry *me = (struct ModuleEntry*) m;

#ifdef USE_BFD
  BFD_unload_debug_symbols (me->module_name);
#endif
  free (me);
}

/*
 * Free and delete the contents of 'g_modules_list'.
 */
static void modules_list_free (void)
{
  smartlist_wipe (g_modules_list, module_free);
  g_modules_list = NULL;
}

/*
 * A `smartlist_wipe()` helper callback for `symbols_list_free()`.
 */
static void symbols_free (void *s)
{
  struct SymbolEntry *se = (struct SymbolEntry*) s;

  free (se->func_name);
  free (se->file_name);
  free (se);
}

/**
 * Free and delete the contents of 'g_symbols_list'.
 */
static void symbols_list_free (void)
{
  smartlist_wipe (g_symbols_list, symbols_free);
  g_symbols_list = NULL;
}

#if USE_SymEnumSymbolsEx
static DWORD enum_and_load_symbols (const char *module)
{
  const struct ModuleEntry *me;
  DWORD num;
  bool  is_last = false;
  int   mod_len, sym_len;

  mod_len = smartlist_len (g_modules_list);
  sym_len = smartlist_len (g_symbols_list);

  me      = smartlist_get (g_modules_list, mod_len-1);
  is_last = (stricmp(module, me->module_name) == 0);
  num     = enum_module_symbols (g_symbols_list, module, is_last, g_cfg.pdb_report);

  TRACE (2, "num: %5lu, sym_len: %5d, num+sym_len: %5lu.\n",
         DWORD_CAST(num), sym_len, DWORD_CAST(num+sym_len));

//assert (num + len == smartlist_len(g_symbols_list));

  return (num);     /* # of symbols added for this module */
}
#endif

/*
 * Never call this before StackWalkInit().
 */
DWORD StackWalkSymbols (smartlist_t **sl_p)
{
  const struct ModuleEntry *me;
  DWORD num = 0;
  int   mod_len, sym_len;

  assert (g_modules_list);
  mod_len = smartlist_len (g_modules_list);
  assert (mod_len > 0);
  assert (g_symbols_list);

#if USE_SymEnumSymbolsEx
  sym_len = smartlist_len (g_symbols_list);
  if (sym_len == 0)
  {
   /* Walking the symbols in 'enum_and_load_symbols()' takes time.
    * Hence do this only if 'sym_len == 0'.
    * And quit as soon as 'check_quit()' sets 'g_quit_count > 0'.
    */
    int i;

    g_quit_count = 0;
    for (i = 0; i < mod_len && g_quit_count == 0; i++)
    {
      me = smartlist_get (g_modules_list, i);
      enum_and_load_symbols (me->module_name);
    }
  }
  num = smartlist_len (g_symbols_list);
#endif

  if (sl_p)
     *sl_p = g_symbols_list;

  ARGSUSED (me);
  ARGSUSED (sym_len);
  return (num);     /*  Total # of symbols */
}

bool StackWalkOurModule (const char *module)
{
  static char  module_unix [_MAX_PATH] = { '\0' };
  static char *module_base = NULL;

  if (!module_unix[0])
  {
    copy_path (module_unix, g_module, '/');
    module_base = basename (g_module);
  }

  /* Check for a short-name match.
   */
  if (!strchr(module, '\\') && !strchr(module, '/'))
     return !stricmp (module, module_base);
  return (!stricmp(module, g_module) || !stricmp(module, module_unix));
}

DWORD StackWalkModules (smartlist_t **sl_p)
{
  if (sl_p)
     *sl_p = g_modules_list;
  if (!g_modules_list)
     return (0);
  return smartlist_len (g_modules_list);
}

bool StackWalkExit (void)
{
  symbols_list_free();
  modules_list_free();

#if USE_PythonHook
  free (g_py_dir);
  free (g_py_exe);
  free (g_py_dll);

#if USE_Py_inject_code
  if (vaddr_wrapper)
     VirtualFree (vaddr_wrapper, 0, MEM_RELEASE);
  vaddr_wrapper = NULL;
#endif

  if (g_py_hnd)
     FreeLibrary (g_py_hnd);

  g_py_dir = g_py_exe = g_py_dll = NULL;
  g_py_hnd = NULL;
  g_py_major_ver = 0;
#endif /* USE_PythonHook */

  return (true);
}

static const char *get_error (void)
{
  static char buf[15];
  DWORD err = GetLastError();

  if (err == ERROR_MOD_NOT_FOUND)
     return ("ERROR_MOD_NOT_FOUND");
  if (err == ERROR_INVALID_PARAMETER)
     return ("ERROR_INVALID_PARAMETER");
  if (err == ERROR_INVALID_ADDRESS)
     return ("ERROR_INVALID_ADDRESS");
  if ((err & 0xC0000000) == 0xC0000000)
  {
    buf[0] = '0';
    buf[1] = 'x';
    _itoa (err, buf+2, 16);
    return (buf);
  }
  return win_strerror (err);
}

static int GetModuleList_TLHELP32 (void)
{
  HANDLE        snap = INVALID_HANDLE_VALUE;
  MODULEENTRY32 me;
  bool          okay = (load_dynamic_table(tlhelp32_funcs, DIM(tlhelp32_funcs)) >= 3);
  int           i;

  if (!okay)
     goto cleanup;

  snap = (*p_CreateToolhelp32Snapshot) (TH32CS_SNAPMODULE, g_proc_id);
  if (snap == (HANDLE)-1)
     goto cleanup;

  me.dwSize = sizeof(me);
  for ((*p_Module32First)(snap, &me);; )
  {
    modules_list_add (me.szExePath, (ULONG_PTR)me.modBaseAddr, me.modBaseSize);
    if (!(*p_Module32Next)(snap,&me))
       break;
  }

#if USE_CreateToolhelp32Snapshot
  if (p_Thread32First && p_Thread32Next)
  {
    HANDLE thr_snap = (*p_CreateToolhelp32Snapshot) (TH32CS_SNAPTHREAD, g_proc_id);

    if (thr_snap != INVALID_HANDLE_VALUE)
    {
      THREADENTRY32 te;

      te.dwSize = sizeof(te);
      for (i = 0, (*p_Thread32First)(thr_snap, &te);; i++)
      {
        if (te.th32OwnerProcessID == g_proc_id)
           TRACE (1, "  %d: thread-info for this process: TID: %lu, PID: %lu\n",
                  i, DWORD_CAST(te.th32ThreadID), DWORD_CAST(te.th32OwnerProcessID));
        if (!(*p_Thread32Next)(thr_snap, &te))
           break;
      }
      CloseHandle (thr_snap);
    }
  }
#endif

cleanup:
  if (snap != INVALID_HANDLE_VALUE)
     CloseHandle (snap);

  unload_dynamic_table (tlhelp32_funcs, DIM(tlhelp32_funcs));

  return smartlist_len (g_modules_list);
}

static int GetModuleList_PSAPI (void)
{
  DWORD    i, needed, num_modules;
  HMODULE *mods;
  bool     okay = (load_dynamic_table(psapi_funcs, DIM(psapi_funcs)) >= 3);
  DWORD    rc;

  if (!okay || !p_EnumProcessModules)
     goto cleanup;

  needed = rc = 0;

  if (!(*p_EnumProcessModules)(g_proc, NULL, 0, &needed))
     rc = GetLastError();

  if (rc != 0 && rc != ERROR_BUFFER_OVERFLOW)
  {
    TRACE (1, "(1): EnumProcessModules() failed: %s.\n", get_error());
    goto cleanup;
  }

  mods = alloca (needed);
  if (!(*p_EnumProcessModules)(g_proc, mods, needed, &needed))
  {
    TRACE (1, "(2): EnumProcessModules() failed: %s.\n", get_error());
    goto cleanup;
  }

  num_modules = needed / sizeof(*mods);

  for (i = 0; i < num_modules; i++)
  {
    char       fname [_MAX_PATH];
    MODULEINFO mi;

    (*p_GetModuleInformation) (g_proc, mods[i], &mi, sizeof(mi));

    /*
     * May have to use QueryFullProcessImageName (Vista+) or GetProcessImageFileName (Win-XP)
     * Ref. comments at:
     *   http://msdn.microsoft.com/en-us/library/windows/desktop/ms683198(v=vs.85).aspx
     */
    fname[0] = '\0';
    (*p_GetModuleFileNameExA) (g_proc, mods[i], fname, sizeof(fname));
    modules_list_add (fname, (ULONG_PTR)mi.lpBaseOfDll, mi.SizeOfImage);
  }

cleanup:

  unload_dynamic_table (psapi_funcs, DIM(psapi_funcs));

  return smartlist_len (g_modules_list);
}

#if USE_SymEnumSymbolsEx
/*
 * smartlist_sort() helper; sort list of modules on base_addr.
 */
static int compare_on_baseaddr (const void **_a, const void **_b)
{
  const struct ModuleEntry *a = *_a;
  const struct ModuleEntry *b = *_b;

  g_num_compares++;

  if (a->base_addr < b->base_addr)
     return (-1);
  if (a->base_addr > b->base_addr)
     return (1);
  return (0);
}

/**
 * Return a shorten string with length `max_len` such that
 * it looks like `"abcde...12345"`.
 * I.e. equally many starting and ending characters.
 */
static char *shorten_path2 (const char *str, size_t max_len)
{
  static char buf [_MAX_PATH];
  const char *end  = strchr (str,'\0');
  int         shift = 0;
  size_t      len;

  assert (max_len > 5);

  if (strlen(str) <= max_len)
     return (char*) str;

  len = (max_len - 3) / 2;
  if ((max_len & 1) == 0)   /* an even number */
     shift++;

  snprintf (buf, sizeof(buf), "%.*s...%.*s",
            (int)len, str, (int)(len+shift), end-len-shift);
  return (buf);
}

/*
 * Show the retrieved information on all our modules;
 * PDB symbols etc.
 *
 * To get the needed .PDB files for a process, this command could be used:
 * ```
 * c:\> cdb -s -c g <the_program.exe>
 * ```
 * This will take some time for the SymbolServer program to download them.
 */
static void print_modules_and_pdb_info (bool do_sort)
{
  DWORD        total_text = 0;
  DWORD        total_data = 0;
  DWORD        total_cpp  = 0;
  DWORD        total_junk = 0;
  smartlist_t *orig_modules = NULL;
  smartlist_t *modules_copy = NULL;
  const char  *pdb_hdr  = "  PDB: text  data   C++  junk";
  size_t       mod_len  = 68;
  size_t       dash_len = mod_len + 22 + 8*IS_WIN64;
  int          i, max = smartlist_len (g_modules_list);

  if (g_cfg.pdb_report)
     dash_len += strlen (pdb_hdr);

  C_printf ("  %-*s %-*s Size%s\n  %s\n",
            (int)mod_len, "Module",
            16+8*IS_WIN64, "Baseaddr",
            g_cfg.pdb_report ? pdb_hdr : "",
            str_repeat('-', dash_len));

  /* Make a sorted copy before printing the module-list.
   * Sort on Baseaddr
   */
  if (do_sort)
  {
    modules_copy = smartlist_new();
    smartlist_append (modules_copy, g_modules_list);
    g_num_compares = 0;
    smartlist_sort (modules_copy, compare_on_baseaddr);
    TRACE (2, "g_num_compares: %lu.\n", DWORD_CAST(g_num_compares));
    g_num_compares = 0;
    orig_modules   = g_modules_list;
    g_modules_list = modules_copy;
  }

  for (i = 0; i < max; i++)
  {
    const struct ModuleEntry *me = smartlist_get (g_modules_list, i);

    C_printf ("  %-*s 0x%" ADDR_FMT " %7s kB",
              (int)mod_len, shorten_path2(me->module_name, mod_len),
              ADDR_CAST(me->base_addr),
              dword_str(me->size/1024));
    if (g_cfg.pdb_report)
    {
      C_printf ("      %5lu %5lu %5lu %5lu",
                DWORD_CAST(me->stat.num_syms),
                DWORD_CAST(me->stat.num_data_syms),
                DWORD_CAST(me->stat.num_cpp_syms),
                DWORD_CAST(me->stat.num_junk_syms));
      total_text += me->stat.num_syms;
      total_data += me->stat.num_data_syms;
      total_cpp  += me->stat.num_cpp_syms;
      total_junk += me->stat.num_junk_syms;
    }

    if (g_cfg.pdb_symsrv && p_SymSrvGetFileIndexInfo)
    {
      SYMSRV_INDEX_INFO si;

      C_puts ("  ");
      memset (&si, '\0', sizeof(si));
      si.sizeofstruct = sizeof(SYMSRV_INDEX_INFO);
      if (!(*p_SymSrvGetFileIndexInfo) (me->module_name, &si, 0))
         C_printf ("\n    SymSrvGetFileIndexInfo() failed: %s", get_error());
      else
      {
        char        pdb_fullname [2*_MAX_PATH] = { "" };
        const char *pdb_base = basename (si.pdbfile);

        /**
         * \todo
         * Call `SymFindFileInPath()` to locate the true .PDB-file for a `si.guid`.
         * For now, just guess it's under `c:\\Windows\\symbols\\<pdb-file>\\<si.guid>1\\<pdb-file>`.
         *
         * E.g. the symbol-file `wwin32u.pdb` with `si.guid == D3CAE32F6C9D443362C27D4D4FF51E151`
         * should be this file:
         * ```
         *   c:\Windows\symbols\wwin32u.pdb\D3CAE32F6C9D443362C27D4D4FF51E151\wwin32u.pdb
         * ```
         */
        snprintf (pdb_fullname, sizeof(pdb_fullname), "%s\\%s\\%s1\\%s",
                  g_sym_dir, pdb_base, get_guid_path_string(&si.guid), pdb_base);

        C_printf ("\n    %s%s", pdb_fullname, file_exists(pdb_fullname) ? "" : " not found");
      }
    }
    C_putc ('\n');
  }

  if (orig_modules)
  {
    smartlist_free (modules_copy);
    g_modules_list = orig_modules;
  }

  if (g_cfg.pdb_report)
     C_printf ("%*s  %s\n"
               "%*s  = %5lu %5lu %5lu %5lu\n",
               26 + (int)mod_len + 8*IS_WIN64, "",
               str_repeat('-',  25),
               26 + (int)mod_len + 8*IS_WIN64, "",
               DWORD_CAST(total_text),
               DWORD_CAST(total_data),
               DWORD_CAST(total_cpp),
               DWORD_CAST(total_junk));
}

/**
 * Just a simple 'q' / ESC-handler to force 'SymEnumSymbolsEx()' to quit
 * calling the callback 'enum_symbols_proc()'.
 *
 * I tried setting up a ^C|^Break handler using 'SetConsoleCtrlHandler()',
 * but that doesn't seems to work in a DLL (?)
 */
static bool check_quit (void)
{
  if (_kbhit())
  {
    int ch = _getch();

    if (ch == 'q' || ch == 27) /* 'q' or ESC */
       g_quit_count++;
    return (1);
  }
  return (0);
}
#endif /* USE_SymEnumSymbolsEx */

static void enum_and_load_modules (void)
{
  struct ModuleEntry *me;
  int    i, max, rc = 0;

  if (g_cfg.use_toolhlp32)
     rc = GetModuleList_TLHELP32();   /* Try `tlhelp32.dll` API */

  if (rc == 0)
     rc = GetModuleList_PSAPI();      /* if not okay, then try `psapi.dll` API */

  max = smartlist_len (g_modules_list);

  g_quit_count = 0;

  for (i = 0; i < max && g_quit_count == 0; i++)
  {
    me = smartlist_get (g_modules_list, i);
    (*p_SymLoadModule64) (g_proc, 0, me->module_name, me->module_name,
                          me->base_addr, me->size);

    if (!stricmp(g_module, me->module_name))
    {
   // add_to_shared_list (base);   /* \todo */
      g_data.ws_trace_base = (HINSTANCE) me->base_addr;
    }

#ifdef USE_BFD
    BFD_load_debug_symbols (me->module_name, me->base_addr, me->size);
#endif

#if USE_PythonHook
    if (g_py_exe && !g_py_dll && is_python_dll(me->module_name))
    {
  #if USE_Py_inject_code
      patch_python_dll();
  #else
      enumerate_py_DLLs();
  #endif
      if (load_AddAuditHook())
         (*p_PySys_AddAuditHook) (our_AddAuditHook, NULL);
     }
#endif

#if USE_SymEnumSymbolsEx
    if (g_cfg.pdb_report)
       enum_and_load_symbols (me->module_name);
#endif
  }

#ifdef USE_BFD
  BFD_dump();
#endif
}

static bool set_symbol_search_path (void)
{
  DWORD  symOptions;
  char   tmp [TBUF_LEN], path [TBUF_LEN];
  char  *p    = path;
  char  *end  = path + sizeof(path) - 1;
  char  *dir  = NULL;
  size_t left = end - p;

  if (GetModuleFileName(NULL, tmp, sizeof(tmp)) && (dir = dirname(tmp)) != NULL)
  {
#if USE_PythonHook
    /*
     * Match all 'python*.exe'.
     */
    const char *ext = strrchr (tmp, '.');
    const char *base = basename (tmp);
    BOOL        is_py = ext && (stricmp(ext, ".exe") == 0) &&
                        (strnicmp(base, "python", 6) == 0);
    if (is_py)
    {
      g_py_dir = strdup (dir);
      g_py_exe = strdup (tmp);
      TRACE (1, "Python detected: \"%s\", g_py_dir: '%s'.\n", g_py_exe, g_py_dir);
    }
#endif
    if (strcmp(dir, g_data.curr_dir))
    {
      p   += snprintf (p, left, "%s;", dir);
      left = end - p;
    }
    free (dir);
  }

  if (g_data.curr_dir[0])  /* set in wsock_trace_init() */
  {
    p += snprintf (p, left, "%s;", g_data.curr_dir);
    left = end - p;
  }

#if USE_PythonHook
  if (g_py_dir)
  {
    p += snprintf (p, left, "%s\\DLLs;", g_py_dir);
    left = end - p;
  }
#endif

  if (GetEnvironmentVariable("_NT_SYMBOL_PATH", tmp, sizeof(tmp)))
  {
    p   += snprintf (p, left, "%s;", tmp);
    left = end - p;
  }

  if (GetEnvironmentVariable("_NT_ALTERNATE_SYMBOL_PATH", tmp, sizeof(tmp)))
  {
    p   += snprintf (p, left, "%s;", tmp);
    left = end - p;
  }

  if (GetEnvironmentVariable("SYSTEMROOT", tmp, sizeof(tmp)))
  {
    p   += snprintf (p, left, "%s;", tmp);
    left = end - p;
  }

  end = strrchr (path, '\0');
  if (end[-1] == ';')
      end[-1] = '\0';   /* if we added anything, we have a trailing semicolon */

  TRACE (2, "symbolSearchPath = \"%s\".\n", path);

  /* init symbol handler stuff
   */
  if (!(*p_SymInitialize)(g_proc, path, FALSE))
  {
    TRACE (1, "SymInitialize(): %s.\n", get_error());
    return (false);
  }

  symOptions = (*p_SymGetOptions)();
  symOptions |= SYMOPT_LOAD_LINES;
  symOptions &= ~SYMOPT_UNDNAME;
  symOptions &= ~SYMOPT_DEFERRED_LOADS;
  (*p_SymSetOptions) (symOptions);

  return (true);
}

#if USE_SymEnumSymbolsEx
/*
 * Return index of entry in 'g_modules_list' whos 'me->module_name' == 'module'
 * or 'me->base_addr == base_addr'.
 * Return -1 if not found.
 */
static int find_module_index (const char *module, ULONG64 base_addr)
{
  int i, max = g_modules_list ? smartlist_len(g_modules_list) : 0;

  for (i = 0; i < max; i++)
  {
    const struct ModuleEntry *me = smartlist_get (g_modules_list, i);

    if (module && !stricmp(module, me->module_name))
       return (i);
    if (me->base_addr == (ULONG_PTR)base_addr)
       return (i);
  }
  return (-1);
}

static int (*_C_printf) (const char *, ...);

static int null_C_printf (const char *fmt, ...)
{
  ARGSUSED (fmt);
  return (0);
}

/**
 * This callback called from 'SymEnumSymbolsEx()' should be called only for
 * modules possibly containing PDB-symbols. I.e. in a MinGW compiled program
 * 'test.exe', this should never look for symbols in 'test.pdb'.
 */
static BOOL CALLBACK enum_symbols_proc (SYMBOL_INFO *sym, ULONG sym_size, void *arg)
{
  struct SymbolEntry *se;

  bool is_cv_cpp, is_gnu_cpp;

  bool ok_flags = (sym->Flags == 0 ||
                   sym->Flags == SYMFLAG_THUNK ||
                   sym->Flags == SYMFLAG_EXPORT ||
                   sym->Flags == SYMFLAG_FORWARDER ||
                   sym->Flags == SYMFLAG_PUBLIC_CODE ||
                   sym->Flags == SYMFLAG_FUNC_NO_RETURN);
  bool ok_tag = (sym->Tag == SymTagPublicSymbol ||
                 sym->Tag == SymTagInlineSite ||
                 sym->Tag == SymTagFunction);

  char   raw_name [MAX_NAMELEN];
  char   und_name [MAX_NAMELEN] = { '\0' };
  char  *name;
  size_t len;

  smartlist_t *sl = (smartlist_t*)arg;

  /* For 'p_SymGetLineFromAddr64()'
   */
  DWORD           ofs_from_line = 0;
  const char     *fname = NULL;
  const char     *name_fmt;
  IMAGEHLP_LINE64 Line;

  static bool is_ours  = false;
  static bool have_PDB = false;

  static ULONG64 last_base_addr;
  static char   *module;
  static struct ModuleEntry *me;

  if (check_quit() > 0)
     return (FALSE);

  is_cv_cpp = is_gnu_cpp = false;

  if (sym->ModBase != last_base_addr)
  {
    int idx = find_module_index (NULL, sym->ModBase);

    assert (idx >= 0);
    me = smartlist_get (g_modules_list, idx);
    module = me->module_name;
    is_ours = (stricmp(g_module, module) == 0);
    have_PDB = false;

#if defined(_MSC_VER)
    {
      const char *dot = strrchr (module, '.');
      char  pdb_file [_MAX_PATH];

      if (dot > module)
      {
        str_ncpy (pdb_file, module, dot-module+1);
        strcat (pdb_file, ".pdb");
        have_PDB = file_exists (pdb_file);
      }
    }
#endif
  }

  last_base_addr = sym->ModBase;

  if (sym->Tag == SymTagData)
  {
    assert (me);
    me->stat.num_data_syms++;
    return (TRUE);
  }

  if (!(ok_flags && ok_tag))
     return (TRUE);

  (*_C_printf) ("  %" ADDR_FMT " ", ADDR_CAST(sym->Address));

  len = min (sym->NameLen+1, MAX_NAMELEN);

  str_ncpy (raw_name, sym->Name, len);
  name_fmt = (g_long_CPP_syms && is_ours ? "%-140.140s " : "%-50.50s ");

  /* Ignore symbols like these:
   *   "<7F>ole32_NULL_THUNK_DATA"
   */
  if ((int)raw_name[0] == 0x7F)
     goto junk_sym;

  if (raw_name[0] == '?')
     is_cv_cpp = true;

#if !defined(_MSC_VER)
  /*
   * dbghelp.dll can decode C++ symbols in our module only if
   * we were compiled with MSVC or clang-cl.
   */
  if (have_PDB)
     is_cv_cpp = false;

   /* If a "module.pdb" is present, do not call 'p_SymGetLineFromAddr64()' below.
    * That will return fake info.
    */
  if (is_ours)
     have_PDB = false;
#endif

  if (raw_name[0] == '$')
     is_gnu_cpp = true;

  if (g_cfg.cpp_demangle)
  {
#ifdef USE_BFD
   /*
    * Gnu style C++ symbols must be passed to bfd_gcc.c.
    */
    if (is_gnu_cpp && BFD_demangle(module, raw_name, und_name, sizeof(und_name)))
    {
      me->stat.num_cpp_syms++;
      (*_C_printf) (name_fmt, und_name);
    }
    else
#endif
    if (is_cv_cpp && (*p_UnDecorateSymbolName)(raw_name, und_name, sizeof(und_name), UNDNAME_COMPLETE))
    {
      if (!strncmp(und_name, "`string", 7))
         goto junk_sym;
      me->stat.num_cpp_syms++;
      (*_C_printf) (name_fmt, und_name);
    }
  }

  /* Not a C++ symbol or C++ demangle failed; print the raw-name.
   */
  if (und_name[0] == '\0')
     (*_C_printf) (name_fmt, raw_name);

  (*_C_printf) ("tag: %s", sym_tag_decode(sym->Tag));

  if (sym->Flags)
     (*_C_printf) (", %s", sym_flags_decode(sym->Flags));

  if (is_cv_cpp || is_gnu_cpp)
     (*_C_printf) (", C++");

  /*
   * dbghelp.dll will only return line-information from our own module(s).
   * And if we were compiled with MSVC or clang-cl.
   */
  memset (&Line, '\0', sizeof(Line));
  Line.SizeOfStruct = sizeof(Line);

  if (have_PDB &&
      (*p_SymGetLineFromAddr64)(g_proc, sym->Address, &ofs_from_line, &Line))
  {
    fname = shorten_path (Line.FileName);
    Line.LineNumber--;
    (*_C_printf) ("\n    %s (%lu", fname, Line.LineNumber);
    if (ofs_from_line)
       (*_C_printf) ("+%lu", ofs_from_line);
    (*_C_printf) (")");
    me->stat.num_syms_lines++;
  }

  (*_C_printf) ("\n");

  name = und_name[0] ? und_name : raw_name;
  se = calloc (1, sizeof(*se));

  se->addr      = (ULONG_PTR) sym->Address;
  se->module    = module;
  se->func_name = strdup (name);
  if (have_PDB)
  {
    se->file_name     = strdup (fname);
    se->line_number   = Line.LineNumber;
    se->ofs_from_line = (unsigned) ofs_from_line;
  }
  smartlist_add (sl, se);

  if (is_ours || have_PDB)
       me->stat.num_our_syms++;
  else me->stat.num_other_syms++;

  ARGSUSED (sym_size);
  return (TRUE);

junk_sym:
  assert (me);
  me->stat.num_junk_syms++;
  (*_C_printf) ("<junk>\n");
  return (TRUE);
}

#if defined(__MINGW32__)
/*
 * It is a real PITA to get the public symbols out of a MinGW compiled PE-file.
 * Would have to use the archaic libbfd.a library (which is hard to use).
 * Use the easy way out and parse the <module>.map file.
 *
 * The parts we're interested in look like:
 *
 * LOAD F:/MingW32/TDM-gcc/bin/../lib/gcc/x86_64-w64-mingw32/5.1.0/32/crtend.o
 *  ...
 * .text          0x00000000702c14c0     0x236c MinGW_obj/common.o
 *                0x00000000702c14f7                common_init
 *                0x00000000702c1539                common_exit
 *
 *  Start parsing lines after a 'LOAD xx' is found.
 *  Match only lines on the form:
 *    ".text   0x00000000702c14c0    0x236c    MinGW_obj/common.o"
 *             <addr>                <size>    <.o-file>
 *
 *  or if the above is found:
 *     "  0x00000000702c1539   common_exit"
 *
 *  which is assumed to be an continuation of the first.
 *  I.e. .o-file is the same.
 */
static DWORD parse_map_file (const char *module, smartlist_t *sl)
{
  const char *dot = strrchr (module, '.');
  char  map_file [_MAX_PATH];
  DWORD line = 0, rc = 0;
  bool  found_load = false;  /* Found the " LOAD " line */
  bool  found_text = false;  /* Found a ".text <addr> <size> <.o-file>" line */
  FILE *fil;

  if (!dot)
     return (0);

  str_ncpy (map_file, module, dot-module+1);
  strcat (map_file, ".map");
  if (!file_exists(map_file))
  {
    TRACE (2, "No %s file.\n", map_file);
    return (0);
  }

  fil = fopen (map_file, "rt");
  if (!fil)
  {
    TRACE (1, "Failed to open %s; errno: %d\n", map_file, errno);
    return (0);
  }

  while (!feof(fil))
  {
    char   buf [500], *p;
    char   file [_MAX_PATH];
    char   func [101] = { '\0' };
    void  *addr = NULL;
    DWORD  size;
    bool   found_func = false;

    if (!fgets(buf, sizeof(buf)-1, fil) ||  /* EOF */
        !strncmp(buf, "*(SORT(", 7))        /* End of ".text" section */
       break;

    line++;

    if (!strncmp(buf, "LOAD ", 5))
    {
      found_load = true;
      continue;
    }

    if (!found_load)
       continue;

    p = 1 + str_rip (buf);

#define TEXT_SECTION   ".text          0x"
#define TEXT_CONTINUE  "               0x"

    if (!found_text && !strncmp(p, TEXT_SECTION, sizeof(TEXT_SECTION)))
    {
      p += sizeof(TEXT_SECTION);
      found_text = (sscanf(p, "%p 0x%lx %s", &addr, &size, file) == 3);
      TRACE (1, "line: %lu, addr: %p, file: %s.\n", line, addr, file);
      dot = strrchr (file, '.');
      if (!dot || dot[1] != 'o')
         file[0] = '\0';
      continue;
    }

    if (found_text && !strncmp(p, TEXT_CONTINUE, sizeof(TEXT_CONTINUE)))
    {
      p += sizeof(TEXT_CONTINUE);
      found_func = (sscanf(p, "%p %100s", &addr, func) == 2);
      TRACE (1, "line: %lu, addr: %p, func: %s.\n", line, addr, func);
    }

    TRACE (3, "line: %lu, addr: %p, found_load: %d, found_text: %d, found_func: %d, p: '%s'.\n",
           line, addr, found_load, found_text, found_func, p);

    if (addr && found_func)
    {
      struct SymbolEntry *se = calloc (1, sizeof(*se));

      se->addr      = (ULONG_PTR) addr;
      se->module    = (char*) module;
      se->func_name = strdup (func);
      se->file_name = strdup (fix_path(file));
      smartlist_add (sl, se);
      rc++;
    }
  }
  fclose (fil);
  return (rc);
}
#endif  /* __MINGW32__ */

/*
 * smartlist_sort() helper: return -1, 1, or 0 based on comparison of two
 * 'struct SymbolEntry'.
 * Sort on address.
 */
static int compare_on_addr (const void **_a, const void **_b)
{
  const struct SymbolEntry *a = *_a;
  const struct SymbolEntry *b = *_b;

  g_num_compares++;

  if (a->addr < b->addr)
     return (-1);
  if (a->addr > b->addr)
     return (1);
  return (0);
}

/**
 * Enumerate all PDB symbols for a module.
 *
 * The callback 'enum_symbols_proc()' adds the 'SymbolEntry' to the smartlist 'sl'.
 */
static DWORD enum_module_symbols (smartlist_t *sl, const char *module, bool is_last, bool verbose)
{
  struct ModuleEntry *me;
  char  *dot, pattern [_MAX_PATH+3];
  int    idx, save, num_mingw_syms = 0;

  TRACE (3, "\nEnumerating all PDB symbols for %s:\n", module);

  if (!p_SymEnumSymbolsEx)
  {
    TRACE (2, "SymEnumSymbolsEx() not found in dbghelp.dll\n");
    return (0);
  }
  if (!g_proc)
  {
    TRACE (2, "'g_proc' is zero?!.\n");
    return (0);
  }

  _C_printf = verbose ? C_printf : null_C_printf;

  save = g_data.trace_raw;
  g_data.trace_raw = true;

#if !defined(_MSC_VER)
  if (!stricmp(g_module, module))
  {
    TRACE (3, "Not searching for PDB-symbols in module %s.\n", module);
    goto check_mingw_map_file;
  }
#endif

  str_ncpy (pattern, basename(module), _MAX_PATH);
  dot = strrchr (pattern, '.');
  if (dot)
     *dot = '\0';
  strcat (pattern, "!*");

  if (!(*p_SymEnumSymbolsEx) (g_proc, 0, pattern, enum_symbols_proc, sl,
                              SYMENUM_OPTIONS_DEFAULT | SYMENUM_OPTIONS_INLINE))
     TRACE (2, "SymEnumSymbolsEx() failed for %s: %s\n", basename(module), get_error());

#if !defined(_MSC_VER)
check_mingw_map_file:

#if defined(__MINGW32__)
  num_mingw_syms = parse_map_file (module, sl);
#endif
#endif

  g_data.trace_raw = save;

  /* Only do the sorting when the last module is processed.
   * Wastefull otherwise, since no modules should have overlapping base-addresses.
   */
  if (is_last)
  {
    g_num_compares = 0;
    smartlist_sort (sl, compare_on_addr);
    TRACE (3, "g_num_compares: %lu.\n", DWORD_CAST(g_num_compares));
    g_num_compares = 0;
  }

  idx = find_module_index (module, 0);
  assert (idx >= 0);
  me = smartlist_get (g_modules_list, idx);

  me->stat.num_syms = me->stat.num_our_syms + me->stat.num_other_syms + num_mingw_syms;

  TRACE (3, " num_our_syms: %lu, num_other_syms: %lu, num_cpp_syms: %lu, num_junk_syms: %lu,\n"
         "                    num_data_syms: %lu, num_syms_lines: %lu, is_last: %d, g_quit_count: %d.\n",
         DWORD_CAST(me->stat.num_our_syms), DWORD_CAST(me->stat.num_other_syms),
         DWORD_CAST(me->stat.num_cpp_syms), DWORD_CAST(me->stat.num_junk_syms),
         DWORD_CAST(me->stat.num_data_syms), DWORD_CAST(me->stat.num_syms_lines),
         is_last, g_quit_count);

  return (me->stat.num_syms);
}
#endif /* USE_SymEnumSymbolsEx */

/*
 * The user of StackWalkShow() must call StackWalkInit() first.
 */
bool StackWalkInit (void)
{
  bool  ok = (load_dynamic_table(dbghelp_funcs, DIM(dbghelp_funcs)) == DIM(dbghelp_funcs));
  char *p;

  g_modules_list = smartlist_new();
  g_symbols_list = smartlist_new();

  g_proc    = GetCurrentProcess();
  g_proc_id = GetCurrentProcessId();

  GetModuleFileName (NULL, g_module, sizeof(g_module));
  if (GetSystemDirectory(g_sym_dir, DIM(g_sym_dir)) && (p = strrchr(g_sym_dir, '\\')) != NULL)
       str_ncpy (p+1, "symbols", p - g_sym_dir - 1);
  else str_ncpy (g_sym_dir, "c:\\Windows\\symbols", sizeof(g_sym_dir));

  TRACE (1, "g_module: %s, g_sym_dir: %s\n", g_module, g_sym_dir);

#if defined(_MSC_VER)
  #ifdef SCRT_IS_UCRT_DLL_IN_USE
    g_long_CPP_syms = (SCRT_IS_UCRT_DLL_IN_USE() == 0);
  #elif defined(_MT)
    g_long_CPP_syms = true;
  #endif

  TRACE (2, "g_long_CPP_syms: %d\n", g_long_CPP_syms);
#endif

  if (ok && set_symbol_search_path())
  {
    /* Enumerate modules and tell dbghelp.dll about them.
     */
    enum_and_load_modules();

#if 0  /* \todo */
    if (num_in_shared_list() > 1)
    {
      WARN ("PROBLEM: Multiple %s in the same process.\n", basename(g_module));
    }
#endif
  }
  if (!ok)
  {
    TRACE (1, "StackWalker failed to initialize.\n");
    return (false);
  }

#if USE_SymEnumSymbolsEx
  if (g_cfg.dump_modules)
     print_modules_and_pdb_info (TRUE);
#endif

  TRACE (2, "\n");
  return (ok);
}

/**
 * \todo Use "Thread Local Storage" for this
 */
static char ret_buf [MAX_NAMELEN+100];

#if defined(__GNUC__)
  GCC_PRAGMA (GCC diagnostic ignored  "-Wunused-variable")
  GCC_PRAGMA (GCC diagnostic ignored  "-Wunused-but-set-variable")
#endif

static DWORD decode_one_stack_frame (HANDLE thread, STACKFRAME64 *stk, CONTEXT *ctx)
{
  struct {
#if USE_SymFromAaddr
    SYMBOL_INFO  hdr;
#else
    IMAGEHLP_SYMBOL64  hdr;
#endif
    char name [MAX_NAMELEN];
  } sym;

  IMAGEHLP_LINE64 Line;

  /* The problem is that the symbol engine only finds those source
   * line addresses (after the first lookup) that fall exactly on
   * a zero displacement. I will walk backwards 100 bytes to
   * find the line and return the proper displacement.
   */
  char    undec_name [MAX_NAMELEN];             /* undecorated name */
  DWORD   displacement     = 0;
  DWORD   temp_dispacement = 0;
  DWORD   max_displacement = 100;
  DWORD   flags            = UNDNAME_NAME_ONLY;  /* show procedure info */
  DWORD64 addr;
  DWORD64 ofs_from_symbol = 0;                  /* How far from the symbol we were */
  DWORD   ofs_from_line   = 0;                  /* How far from the line we were */
  size_t  left            = sizeof(ret_buf);
  char   *str             = ret_buf;
  char   *p, *end         = str + left;

  /* Assume the module is MSVC/clang-cl compiled. Call 'p_SymFromAddr' and
   * 'p_SymGetLineFromAddr64()' if this is the case. If the '<module>.pdb'
   * is present while running a MinGW compiled program, this just returns
   * wrong information from dbghelp.dll.
   */
  bool have_PDB_info = true;

  if (g_cfg.max_displacement > 0)
     max_displacement = g_cfg.max_displacement;

  if (g_cfg.cpp_demangle)
     flags = UNDNAME_COMPLETE;

  undec_name[0] = '\0';

  /* Get next stack frame (StackWalk64(), SymFunctionTableAccess64(), SymGetModuleBase64()).
   * if this returns ERROR_INVALID_ADDRESS (487) or ERROR_NOACCESS (998), you can
   * assume that either you are done, or that the stack is so hosed that the next
   * deeper frame could not be found.
   * CONTEXT need not to be supplied if 'WS_TRACE_IMAGE_TYPE' is 'IMAGE_FILE_MACHINE_I386'!
   */
  if (!(*p_StackWalk64)(WS_TRACE_IMAGE_TYPE, g_proc, thread, stk, ctx, NULL,
                        p_SymFunctionTableAccess64, p_SymGetModuleBase64, NULL))
     return (1);

  addr = stk->AddrPC.Offset;

  if (addr == 0)    /* If we are here, we have no valid callstack entry! */
     return (2);

#if !defined(_MSC_VER)
  {
    DWORD64 base = (*p_SymGetModuleBase64) (g_proc, addr);
    char    path [MAX_PATH] = { '\0' };

    if (GetModuleFileName((HANDLE)(uintptr_t)base, path, sizeof(path)) &&
        !stricmp(g_module, path))
       have_PDB_info = false;
  }
  /* otherwise the module can be a MSVC/clang-cl compiled module in a MinGW program.
   */
#endif

  /* 'addr' is address of the returning location. Subtracting the address-width
   * (width of the address bus) will give a more precise location of the address
   * we were called *from*.
   */
  addr -= sizeof(void*);

#ifdef USE_BFD
  if (BFD_get_function_name(addr, str, left) != 0)
     return (3);

#else
  if (!have_PDB_info)
     return (4);

  memset (&sym, '\0', sizeof(sym));
  sym.hdr.SizeOfStruct  = sizeof(sym.hdr);

#if USE_SymFromAaddr
  sym.hdr.MaxNameLen = sizeof(sym.name);
  if (!(*p_SymFromAddr)(g_proc, addr, &ofs_from_symbol, &sym.hdr))
     return (4);

#else
  sym.hdr.MaxNameLength = sizeof(sym.name);
  if (!(*p_SymGetSymFromAddr64)(g_proc, addr, &ofs_from_symbol, &sym.hdr))
     return (4);
#endif

  (*p_UnDecorateSymbolName) (sym.hdr.Name, undec_name, sizeof(undec_name), flags);

  memset (&Line, '\0', sizeof(Line));
  Line.SizeOfStruct = sizeof(Line);

  while (temp_dispacement < max_displacement &&
         !(*p_SymGetLineFromAddr64)(g_proc, addr - temp_dispacement, &ofs_from_line, &Line))
       ++temp_dispacement;

  if (temp_dispacement >= max_displacement)
     return (5);

  /* It was found and the source line information is correct so
   * change the displacement if it was looked up multiple times.
   */
  if (temp_dispacement < max_displacement && temp_dispacement != 0)
     displacement = temp_dispacement;

  str += snprintf (str, left, "~2%s(%lu)~1 (",
                   shorten_path(Line.FileName),
                   DWORD_CAST(Line.LineNumber));
  left = end - str;

  /* If 'undec_name[]' contains a "~" (a C++ destructor),
   * replace that with "~~" since 'C_putc()' gets confused otherwise.
   */
  for (p = undec_name; *p && left > 2; p++)
  {
    *str++ = *p;
    left--;
    if (*p == '~')
    {
      *str++ = '~';
      left--;
    }
  }
  *str = '\0';

  if (displacement)
     snprintf (str, left, "+%lu)", DWORD_CAST(displacement));
  else if (ofs_from_symbol && undec_name[0])
  {
    /* The 'ofs_from_symbol' is the address past the call (the return address). E.g.:
     *   01BE    FF 15 00 00 00 00         call        dword ptr __imp__WSAStartup@8
     *
     * So to be correct we should decode the instruction and subtract it's size
     * (6 bytes in this case).
     */
    snprintf (str, left, "+%" U64_FMT ")", ofs_from_symbol);
  }
#endif          /* USE_BFD */
  return (0);   /* Okay */
}

char *StackWalkShow (HANDLE thread, CONTEXT *ctx)
{
  DWORD        err  = 0;
  size_t       left = sizeof(ret_buf);
  char        *str  = ret_buf;
  char        *end  = str + left;
  STACKFRAME64 stk;    /* in/out stackframe */

  memset (&stk, 0, sizeof(stk));

  /* init STACKFRAME.
   * Notes: AddrModeFlat is just an assumption.
   */
  stk.AddrPC.Offset    = REG_EIP (ctx);
  stk.AddrFrame.Offset = REG_EBP (ctx);
  stk.AddrStack.Offset = REG_ESP (ctx);

  stk.AddrPC.Mode    = AddrModeFlat;
  stk.AddrFrame.Mode = AddrModeFlat;
  stk.AddrStack.Mode = AddrModeFlat;

  err = decode_one_stack_frame (thread, &stk, ctx);
  if (err == 0)
     return (ret_buf);

  str += snprintf (ret_buf, sizeof(ret_buf), "0x%" ADDR_FMT, ADDR_CAST(stk.AddrPC.Offset));
  left = end - str;

#ifdef _MSC_VER
  /*
   * \todo: In this case figure out the module-name (from the base-addresses in
   *        g_modules_list) and print which module that is missing a .PDB file.
   */
  snprintf (str, left, " (no PDB, err: %lu)", err);
#endif

  return (ret_buf);
}
