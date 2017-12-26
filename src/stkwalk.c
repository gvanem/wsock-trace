/*!\file stkwalk.c
 * StackWalker (backtrace) for Win32 / MSVC+clang-cl+MinGW
 */

/*
 * File:
 *    stkwalk.c
 *
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

/*
 * Aug 2011   Adapted for Wsock_trace - G. Vanem (gvanem@yahoo.no)
 *            No longer Unicode aware.
 *            Simplified and rewritten from C++ to pure C.
 *            Removed the IMHO awful Hungarian notation.
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

#include "common.h"
#include "init.h"
#include "bfd_gcc.h"
#include "stkwalk.h"

#if defined(_MSC_VER) && (_MSC_VER >= 1900)
 /*
  * With the Universal CRT in Windows/MSVC and with 'cl' CFLAGS:
  *  '-MD' or '-MDd' -> __scrt_is_ucrt_dll_in_use() = 1.
  *  '-MT' or '-MTd' -> __scrt_is_ucrt_dll_in_use() = 0.
  *
  * The latter case causes very long C++ symbols to be found in 'enum_symbols_proc()'
  * for 'g_module'. Ref. the use of 'g_long_CPP_syms'.
  */
  extern int __cdecl __scrt_is_ucrt_dll_in_use (void);
#endif

/*
 * Check if the <imagehlp.h> / <dbghelp.h> API is good enough for
 * using 'SymEnumSymbolsEx()' etc.
 */
#if defined(API_VERSION_NUMBER) && (API_VERSION_NUMBER >= 11)
  #define USE_SymEnumSymbolsEx 1
#else
  #define USE_SymEnumSymbolsEx 0
#endif

static HANDLE       g_proc;
static DWORD        g_proc_id;
static char         g_module [_MAX_PATH];  /* The .exe we're linked to */
static smartlist_t *g_modules_list;        /* List of all modules in our program */
static smartlist_t *g_symbols_list;
static int          g_quit_count = 0;
static DWORD        g_num_compares;

#if USE_SymEnumSymbolsEx
  static BOOL  g_long_CPP_syms = FALSE;
  static DWORD enum_module_symbols (smartlist_t *sl, const char *module, BOOL is_last, BOOL verbose);
#endif

#define USE_SymFromAaddr 1

#define MAX_NAMELEN  1024        /* max name length for found symbols */
#define TTBUFLEN     8096        /* for a temp buffer (2^13) */

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
 * 'API_VERSION_NUMBER' defined in <imagehlp.h>
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


typedef BOOL (WINAPI *func_SymCleanup) (IN HANDLE process);

typedef DWORD (WINAPI *func_SymGetOptions) (VOID);

typedef DWORD (WINAPI *func_SymSetOptions) (IN DWORD SymOptions);

typedef PVOID (WINAPI *func_SymFunctionTableAccess64) (IN HANDLE  process,
                                                       IN DWORD64 AddrBase);

typedef BOOL (WINAPI *func_SymGetLineFromAddr64) (IN  HANDLE           process,
                                                  IN  DWORD64          addr,
                                                  OUT DWORD           *displacement,
                                                  OUT IMAGEHLP_LINE64 *Line);

typedef DWORD64 (WINAPI *func_SymGetModuleBase64) (IN HANDLE  process,
                                                   IN DWORD64 addr);

typedef BOOL (WINAPI *func_SymGetModuleInfo64) (IN  HANDLE             process,
                                                IN  DWORD64            addr,
                                                OUT IMAGEHLP_MODULE64 *ModuleInfo);

typedef BOOL (WINAPI *func_SymGetSymFromAddr64) (IN  HANDLE             process,
                                                 IN  DWORD64            addr,
                                                 OUT DWORD64           *displacement,
                                                 OUT IMAGEHLP_SYMBOL64 *Symbol);

typedef BOOL (WINAPI *func_SymFromAddr) (IN     HANDLE       process,
                                         IN     DWORD64      addr,
                                         OUT    DWORD64     *displacement,
                                         IN OUT SYMBOL_INFO *Symbol);

typedef BOOL (WINAPI *func_SymInitialize) (IN HANDLE process,
                                           IN PCSTR  UserSearchPath,
                                           IN BOOL   invadeProcess);

typedef DWORD (WINAPI *func_SymLoadModule64) (IN HANDLE  process,
                                              IN HANDLE  file,
                                              IN PCSTR   ImageName,
                                              IN PCSTR   ModuleName,
                                              IN DWORD64 BaseOfDll,
                                              IN DWORD   SizeOfDll);

typedef BOOL (WINAPI *func_StackWalk64) (IN     DWORD                            MachineType,
                                         IN     HANDLE                           process,
                                         IN     HANDLE                           thread,
                                         IN OUT STACKFRAME64                    *StackFrame,
                                         IN OUT VOID                            *ContextRecord,
                                         IN     PREAD_PROCESS_MEMORY_ROUTINE64   ReadMemoryRoutine,
                                         IN     PFUNCTION_TABLE_ACCESS_ROUTINE64 FunctionTableAccessRoutine,
                                         IN     PGET_MODULE_BASE_ROUTINE64       GetModuleBaseRoutine,
                                         IN     PTRANSLATE_ADDRESS_ROUTINE64     TranslateAddress);

typedef DWORD (WINAPI *func_UnDecorateSymbolName) (IN  PCSTR DecoratedName,
                                                   OUT PSTR  UnDecoratedName,
                                                   IN  DWORD UndecoratedLength,
                                                   IN  DWORD Flags);

#if USE_SymEnumSymbolsEx
  typedef BOOL (WINAPI *func_SymEnumSymbolsEx) (IN     HANDLE                         hProcess,
                                                IN     ULONG64                        BaseOfDll,
                                                IN_OPT const char                    *Mask,
                                                IN     PSYM_ENUMERATESYMBOLS_CALLBACK EnumSymbolsCallback,
                                                IN_OPT VOID                           *UserContext,
                                                IN     DWORD                          Options);

  typedef BOOL (WINAPI *func_SymSrvGetFileIndexInfo) (IN  PCTSTR             File,
                                                      OUT PSYMSRV_INDEX_INFO Info,
                                                      IN  DWORD              Flags);
#endif

static func_SymCleanup                p_SymCleanup = NULL;
static func_SymFunctionTableAccess64  p_SymFunctionTableAccess64 = NULL;
static func_SymGetLineFromAddr64      p_SymGetLineFromAddr64 = NULL;
static func_SymGetModuleBase64        p_SymGetModuleBase64 = NULL;
static func_SymGetModuleInfo64        p_SymGetModuleInfo64 = NULL;
static func_SymGetOptions             p_SymGetOptions = NULL;
static func_SymGetSymFromAddr64       p_SymGetSymFromAddr64 = NULL;
static func_SymFromAddr               p_SymFromAddr = NULL;
static func_SymInitialize             p_SymInitialize = NULL;
static func_SymLoadModule64           p_SymLoadModule64 = NULL;
static func_SymSetOptions             p_SymSetOptions = NULL;
static func_StackWalk64               p_StackWalk64 = NULL;
static func_UnDecorateSymbolName      p_UnDecorateSymbolName = NULL;

#if USE_SymEnumSymbolsEx
  static func_SymEnumSymbolsEx        p_SymEnumSymbolsEx = NULL;
  static func_SymSrvGetFileIndexInfo  p_SymSrvGetFileIndexInfo = NULL;
#endif

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

#define ADD_VALUE(v)  { v, #v }

#if USE_SymEnumSymbolsEx

static const struct search_list symbol_info_flags[] = {
                                ADD_VALUE (SYMFLAG_CLR_TOKEN),
                                ADD_VALUE (SYMFLAG_CONSTANT),
                                ADD_VALUE (SYMFLAG_EXPORT),
                                ADD_VALUE (SYMFLAG_FORWARDER),
                                ADD_VALUE (SYMFLAG_FRAMEREL),
                                ADD_VALUE (SYMFLAG_FUNCTION),
                                ADD_VALUE (SYMFLAG_ILREL),
                                ADD_VALUE (SYMFLAG_LOCAL),
                                ADD_VALUE (SYMFLAG_METADATA),
                                ADD_VALUE (SYMFLAG_PARAMETER),
                                ADD_VALUE (SYMFLAG_REGISTER),
                                ADD_VALUE (SYMFLAG_REGREL),
                                ADD_VALUE (SYMFLAG_SLOT),
                                ADD_VALUE (SYMFLAG_THUNK),
                                ADD_VALUE (SYMFLAG_TLSREL),
                                ADD_VALUE (SYMFLAG_VALUEPRESENT),
                                ADD_VALUE (SYMFLAG_VIRTUAL),
                                ADD_VALUE (SYMFLAG_NULL),
                                ADD_VALUE (SYMFLAG_FUNC_NO_RETURN),
                                ADD_VALUE (SYMFLAG_SYNTHETIC_ZEROBASE),
                                ADD_VALUE (SYMFLAG_PUBLIC_CODE)
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

static const struct search_list symbol_tags[] = {
                                ADD_VALUE (SymTagNull),
                                ADD_VALUE (SymTagExe),
                                ADD_VALUE (SymTagCompiland),
                                ADD_VALUE (SymTagCompilandDetails),
                                ADD_VALUE (SymTagCompilandEnv),
                                ADD_VALUE (SymTagFunction),
                                ADD_VALUE (SymTagBlock),
                                ADD_VALUE (SymTagData),
                                ADD_VALUE (SymTagAnnotation),
                                ADD_VALUE (SymTagLabel),
                                ADD_VALUE (SymTagPublicSymbol),
                                ADD_VALUE (SymTagUDT),
                                ADD_VALUE (SymTagEnum),
                                ADD_VALUE (SymTagFunctionType),
                                ADD_VALUE (SymTagPointerType),
                                ADD_VALUE (SymTagArrayType),
                                ADD_VALUE (SymTagBaseType),
                                ADD_VALUE (SymTagTypedef),
                                ADD_VALUE (SymTagBaseClass),
                                ADD_VALUE (SymTagFriend),
                                ADD_VALUE (SymTagFunctionArgType),
                                ADD_VALUE (SymTagFuncDebugStart),
                                ADD_VALUE (SymTagFuncDebugEnd),
                                ADD_VALUE (SymTagUsingNamespace),
                                ADD_VALUE (SymTagVTableShape),
                                ADD_VALUE (SymTagVTable),
                                ADD_VALUE (SymTagCustom),
                                ADD_VALUE (SymTagThunk),
                                ADD_VALUE (SymTagCustomType),
                                ADD_VALUE (SymTagManagedType),
                                ADD_VALUE (SymTagDimension),
                                ADD_VALUE (SymTagCallSite),
                                ADD_VALUE (SymTagInlineSite),
                                ADD_VALUE (SymTagBaseInterface),
                                ADD_VALUE (SymTagVectorType),
                                ADD_VALUE (SymTagMatrixType),
                                ADD_VALUE (SymTagHLSLType)
                              };

static const char *sym_tag_decode (unsigned tag)
{
  return list_lookup_name (tag, symbol_tags, DIM(symbol_tags));
}
#endif /* USE_SymEnumSymbolsEx */

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
 * Free and delete the contents of 'g_modules_list'.
 */
static void modules_list_free (void)
{
  struct ModuleEntry *me;
  int    i, max;

  if (!g_modules_list)
     return;

  max = smartlist_len (g_modules_list);
  for (i = 0; i < max; i++)
  {
    me = smartlist_get (g_modules_list, i);
#ifdef USE_BFD
    BFD_unload_debug_symbols (me->module_mame);
#endif
    free (me);
  }
  smartlist_free (g_modules_list);
  g_modules_list = NULL;
}

/*
 * Free and delete the contents of 'g_symbols_list'.
 */
static void symbols_list_free (void)
{
  struct SymbolEntry *se;
  int    i, max;

  if (!g_symbols_list)
     return;

  max = smartlist_len (g_symbols_list);
  for (i = 0; i < max; i++)
  {
    se = smartlist_get (g_symbols_list, i);
#if 1
    if (se->func_name)
       free (se->func_name);
    if (se->file_name)
       free (se->file_name);
#endif
    free (se);
  }
  smartlist_free (g_symbols_list);
  g_symbols_list = NULL;
}

#if USE_SymEnumSymbolsEx
static DWORD enum_and_load_symbols (const char *module)
{
  const struct ModuleEntry *me;
  DWORD num;
  BOOL  is_last = FALSE;
  int   mod_len, sym_len;

  mod_len = smartlist_len (g_modules_list);
  sym_len = smartlist_len (g_symbols_list);

  me      = smartlist_get (g_modules_list, mod_len-1);
  is_last = (stricmp(module,me->module_name) == 0);
  num     = enum_module_symbols (g_symbols_list, module, is_last, g_cfg.pdb_report == 0);

  TRACE (2, "num: %5lu, sym_len: %5d, num+sym_len: %5lu.\n",
         DWORD_CAST(num), sym_len, DWORD_CAST(num+sym_len));

 // assert (num + len == smartlist_len(g_symbols_list));

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

DWORD StackWalkModules (smartlist_t **sl_p)
{
  if (sl_p)
     *sl_p = g_modules_list;
  if (!g_modules_list)
     return (0);
  return smartlist_len (g_modules_list);
}

BOOL StackWalkExit (void)
{
  symbols_list_free();
  modules_list_free();
  return (TRUE);
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

/**************************************** ToolHelp32 *************************/

typedef HANDLE (WINAPI *func_CreateToolhelp32Snapshot) (DWORD dwFlags, DWORD PID);
typedef BOOL   (WINAPI *func_Module32First) (HANDLE snap, MODULEENTRY32 *me);
typedef BOOL   (WINAPI *func_Module32Next) (HANDLE snap, MODULEENTRY32 *me);
typedef BOOL   (WINAPI *func_Thread32First) (HANDLE snap, THREADENTRY32 *te);
typedef BOOL   (WINAPI *func_Thread32Next) (HANDLE snap, THREADENTRY32 *te);

static func_CreateToolhelp32Snapshot p_CreateToolhelp32Snapshot = NULL;
static func_Module32First            p_Module32First = NULL;
static func_Module32Next             p_Module32Next  = NULL;
static func_Thread32First            p_Thread32First = NULL;
static func_Thread32Next             p_Thread32Next  = NULL;

#undef  ADD_VALUE
#define ADD_VALUE(opt, dll, func)  { opt, NULL, dll, #func, (void**)&p_##func }
#define ADD_THREAD_SNAPSHOT        1

static struct LoadTable th32_funcs[] = {
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

static int GetModuleListTH32 (void)
{
  HANDLE        snap = INVALID_HANDLE_VALUE;
  MODULEENTRY32 me;
  BOOL          okay = (load_dynamic_table(th32_funcs, DIM(th32_funcs)) >= 3);
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

#if ADD_THREAD_SNAPSHOT
  if (p_Thread32First && p_Thread32Next)
  {
    HANDLE thr_snap = (*p_CreateToolhelp32Snapshot) (TH32CS_SNAPTHREAD, g_proc_id);

    if (thr_snap != INVALID_HANDLE_VALUE)
    {
      THREADENTRY32 te;

      te.dwSize = sizeof(te);
      for (i = 0, (*p_Thread32First)(thr_snap,&te);; i++)
      {
        if (te.th32OwnerProcessID == g_proc_id)
           TRACE (4, "  %d: thread-info for this process: TID: %lu, PID: %lu\n",
                  i, DWORD_CAST(te.th32ThreadID), DWORD_CAST(te.th32OwnerProcessID));
        if (!(*p_Thread32Next)(thr_snap,&te))
           break;
      }
      CloseHandle (thr_snap);
    }
  }
#endif

cleanup:
  if (snap != INVALID_HANDLE_VALUE)
     CloseHandle (snap);

  unload_dynamic_table (th32_funcs, DIM(th32_funcs));

  return smartlist_len (g_modules_list);
}

/**************************************** PSAPI ************************/

typedef BOOL  (WINAPI *func_EnumProcessModules) (HANDLE process, HMODULE *module, DWORD cb, DWORD *needed);
typedef DWORD (WINAPI *func_GetModuleFileNameExA) (HANDLE process, HMODULE module, LPSTR lpFilename, DWORD nSize);
typedef BOOL  (WINAPI *func_GetModuleInformation) (HANDLE process, HMODULE module, MODULEINFO *pmi, DWORD nSize);

static func_EnumProcessModules   p_EnumProcessModules;
static func_GetModuleFileNameExA p_GetModuleFileNameExA;
static func_GetModuleInformation p_GetModuleInformation;

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

static int GetModuleListPSAPI (void)
{
  DWORD    i, needed, num_modules;
  HMODULE *mods;
  BOOL     okay = (load_dynamic_table(psapi_funcs, DIM(psapi_funcs)) >= 3);
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

/*
 * Show the retrieved information on all our modules;
 * PDB symbols etc.
 */
static void print_modules_and_pdb_info (BOOL do_pdb, BOOL do_symsrv_info, BOOL do_sort)
{
  DWORD        total_text = 0;
  DWORD        total_data = 0;
  DWORD        total_cpp  = 0;
  DWORD        total_junk = 0;
  smartlist_t *orig_modules = NULL;
  smartlist_t *modules_copy;
  const char  *pdb_hdr  = "  PDB: text  data   C++  junk";
  size_t       dash_len = 72 + 8*IS_WIN64;
  int          i, max = smartlist_len (g_modules_list);

  if (do_pdb)
     dash_len += strlen (pdb_hdr);

  trace_printf ("  %-50s %-*s Size%s\n",
                "Module", 16+8*IS_WIN64, "Baseaddr", do_pdb ? pdb_hdr : "");
  trace_printf ("  %s\n", _strrepeat('-', dash_len));

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
    orig_modules = g_modules_list;
    g_modules_list = modules_copy;
  }

  for (i = 0; i < max; i++)
  {
    const struct ModuleEntry *me = smartlist_get (g_modules_list, i);
    const char  *mod_name = me->module_name;
    size_t       len = strlen (me->module_name);

    if (len > 50)
         trace_printf ("  ...%-47s", mod_name+len-47);
    else trace_printf ("  %-50s", mod_name);

    trace_printf (" 0x%" ADDR_FMT " %7s kB",
                  ADDR_CAST(me->base_addr), dword_str(me->size/1024));
    if (do_pdb)
    {
      trace_printf ("      %5lu %5lu %5lu %5lu",
                    DWORD_CAST(me->stat.num_syms),
                    DWORD_CAST(me->stat.num_data_syms),
                    DWORD_CAST(me->stat.num_cpp_syms),
                    DWORD_CAST(me->stat.num_junk_syms));
      total_text += me->stat.num_syms;
      total_data += me->stat.num_data_syms;
      total_cpp  += me->stat.num_cpp_syms;
      total_junk += me->stat.num_junk_syms;
    }

    if (do_symsrv_info && p_SymSrvGetFileIndexInfo)
    {
      SYMSRV_INDEX_INFO si;

      trace_puts ("  ");
      memset (&si, '\0', sizeof(si));
      si.sizeofstruct = sizeof(SYMSRV_INDEX_INFO);
      if (!(*p_SymSrvGetFileIndexInfo) (me->module_name, &si, 0))
           trace_printf ("SymSrvGetFileIndexInfo() failed: %s", get_error());
      else trace_printf ("%-25s: %s", basename(si.pdbfile), get_guid_path_string(&si.guid));
    }
    trace_putc ('\n');
  }

  if (orig_modules)
  {
    smartlist_free (modules_copy);
    g_modules_list = orig_modules;
  }

  if (do_pdb)
     trace_printf ("%*s  %s\n"
                   "%*s  = %5lu %5lu %5lu %5lu\n",
                   76+8*IS_WIN64, "",
                   _strrepeat('-',  25),
                   76+8*IS_WIN64, "",
                   DWORD_CAST(total_text),
                   DWORD_CAST(total_data),
                   DWORD_CAST(total_cpp),
                   DWORD_CAST(total_junk));
}

/*
 * Just a simple 'q' / ESC-handler to force 'SymEnumSymbolsEx()' to quit
 * calling the callback 'enum_symbols_proc()'.
 *
 * I tried setting up a ^C|^Break handler using 'SetConsoleCtrlHandler()',
 * but that doesn't seems to work in a DLL (?)
 */
static BOOL check_quit (void)
{
#if defined(__CYGWIN__)
  if (getc(STDIN_FILENO))
  {
    g_quit_count++;
    return (1);
  }
#else
  if (_kbhit())
  {
    int ch = _getch();

    if (ch == 'q' || ch == 27) /* 'q' or ESC */
       g_quit_count++;
    return (1);
  }
#endif
  return (0);
}
#endif /* USE_SymEnumSymbolsEx */

static void enum_and_load_modules (void)
{
  struct ModuleEntry *me;
  int    i, max, rc = 0;

  if (g_cfg.use_toolhlp32)
     rc = GetModuleListTH32();     /* Try ToolHelp32 API */

  if (rc == 0)
     rc = GetModuleListPSAPI();    /* if not okay, then try PSAPI */

  max = smartlist_len (g_modules_list);

  g_quit_count = 0;

  for (i = 0; i < max && g_quit_count == 0; i++)
  {
    me = smartlist_get (g_modules_list, i);
    (*p_SymLoadModule64) (g_proc, 0, me->module_name, me->module_name,
                          me->base_addr, me->size);

    if (!stricmp(g_module,me->module_name))
    {
   // add_to_shared_list (base);   /* \todo */
      ws_trace_base = (HINSTANCE) me->base_addr;
    }

#ifdef USE_BFD
    BFD_load_debug_symbols (me->module_name, me->base_addr, me->size);
#endif

#if USE_SymEnumSymbolsEx
    if (g_cfg.pdb_report || g_cfg.trace_level >= 4)
       enum_and_load_symbols (me->module_name);
#endif
  }

#ifdef USE_BFD
  BFD_dump();
#endif
}

static BOOL set_symbol_search_path (void)
{
  DWORD  symOptions;
  char   tmp [TTBUFLEN];
  char   path[TTBUFLEN];
  char  *p    = path;
  char  *end  = path + sizeof(path) - 1;
  char  *dir  = NULL;
  size_t left = end - path;

  if (curr_dir[0])  /* set in wsock_trace_init() */
  {
    p += snprintf (p, left, "%s;", curr_dir);
    left = end - p;
  }

  if (GetModuleFileName(NULL, tmp, sizeof(tmp)) && (dir = dirname(tmp)) != NULL)
  {
    if (strcmp(dir,curr_dir))
    {
      p   += snprintf (p, left, "%s;", dir);
      left = end - p;
    }
    free (dir);
  }

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
    return (FALSE);
  }

  symOptions = (*p_SymGetOptions)();
  symOptions |= SYMOPT_LOAD_LINES;
  symOptions &= ~SYMOPT_UNDNAME;
  symOptions &= ~SYMOPT_DEFERRED_LOADS;
  (*p_SymSetOptions) (symOptions);

  return (TRUE);
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

    if (module && !stricmp(module,me->module_name))
       return (i);
    if (me->base_addr == (ULONG_PTR)base_addr)
       return (i);
  }
  return (-1);
}

static int (*_trace_printf) (const char *, ...);

static int null_printf (const char *fmt, ...)
{
  ARGSUSED (fmt);
  return (0);
}

/*
 * This callback called from 'SymEnumSymbolsEx()' should be called only for
 * modules possibly containing PDB-symbols. I.e. in a MinGW compiled program
 * 'test.exe', this should never look for symbols in 'test.pdb'.
 */
static BOOL CALLBACK enum_symbols_proc (SYMBOL_INFO *sym, ULONG sym_size, void *arg)
{
  struct SymbolEntry *se;

  BOOL is_cv_cpp, is_gnu_cpp;

  BOOL ok_flags = (sym->Flags == 0 ||
                   sym->Flags == SYMFLAG_THUNK ||
                   sym->Flags == SYMFLAG_EXPORT ||
                   sym->Flags == SYMFLAG_FORWARDER ||
                   sym->Flags == SYMFLAG_PUBLIC_CODE ||
                   sym->Flags == SYMFLAG_FUNC_NO_RETURN);
  BOOL ok_tag = (sym->Tag == SymTagPublicSymbol ||
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

  static BOOL is_ours  = FALSE;
  static BOOL have_PDB = FALSE;

  static ULONG64 last_base_addr;
  static char   *module;
  static struct ModuleEntry *me;

  if (check_quit() > 0)
     return (FALSE);

  is_cv_cpp = is_gnu_cpp = FALSE;

  if (sym->ModBase != last_base_addr)
  {
    int idx = find_module_index (NULL, sym->ModBase);

    assert (idx >= 0);
    me = smartlist_get (g_modules_list, idx);
    module = me->module_name;
    is_ours = (stricmp(g_module,module) == 0);
    have_PDB = FALSE;

#if defined(_MSC_VER)
    {
      const char *dot = strrchr (module, '.');
      char  pdb_file [_MAX_PATH];

      if (dot > module)
      {
        _strlcpy (pdb_file, module, dot-module+1);
        strcat (pdb_file, ".pdb");
        have_PDB = FILE_EXISTS (pdb_file);
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

  (*_trace_printf) ("  %" ADDR_FMT " ", ADDR_CAST(sym->Address));

  len = min (sym->NameLen+1, MAX_NAMELEN);

  _strlcpy (raw_name, sym->Name, len);
  name_fmt = (g_long_CPP_syms && is_ours ? "%-140.140s " : "%-50.50s ");

  /* Ignore symbols like these:
   *   "<7F>ole32_NULL_THUNK_DATA"
   */
  if ((int)raw_name[0] == 0x7F)
     goto junk_sym;

  if (raw_name[0] == '?')
     is_cv_cpp = TRUE;

#if !defined(_MSC_VER) && !defined(__clang__)
  /*
   * dbghelp.dll can decode C++ symbols in our module only if
   * we were compiled with MSVC or clang-cl.
   */
  if (have_PDB)
     is_cv_cpp = FALSE;

   /* If a "module.pdb" is present, do not call 'p_SymGetLineFromAddr64()' below.
    * That will return fake info.
    */
  if (is_ours)
     have_PDB = FALSE;
#endif

  if (raw_name[0] == '$')
     is_gnu_cpp = TRUE;

  if (g_cfg.cpp_demangle)
  {
#ifdef USE_BFD
   /*
    * Gnu style C++ symbols must be passed to bfd_gcc.c.
    */
    if (is_gnu_cpp && BFD_demangle(module, raw_name, und_name, sizeof(und_name)))
    {
      me->stat.num_cpp_syms++;
      (*_trace_printf) (name_fmt, und_name);
    }
    else
#endif
    if (is_cv_cpp && (*p_UnDecorateSymbolName)(raw_name, und_name, sizeof(und_name), UNDNAME_COMPLETE))
    {
      if (!strncmp(und_name,"`string",7))
         goto junk_sym;
      me->stat.num_cpp_syms++;
      (*_trace_printf) (name_fmt, und_name);
    }
  }

  /* Not a C++ symbol or C++ demangle failed; print the raw-name.
   */
  if (und_name[0] == '\0')
     (*_trace_printf) (name_fmt, raw_name);

  (*_trace_printf) ("tag: %s", sym_tag_decode(sym->Tag));

  if (sym->Flags)
     (*_trace_printf) (", %s", sym_flags_decode(sym->Flags));

  if (is_cv_cpp || is_gnu_cpp)
     (*_trace_printf) (", C++");

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
    (*_trace_printf) ("\n    %s (%lu", fname, Line.LineNumber);
    if (ofs_from_line)
       (*_trace_printf) ("+%lu", ofs_from_line);
    (*_trace_printf) (")");
    me->stat.num_syms_lines++;
  }

  (*_trace_printf) ("\n");

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
  (*_trace_printf) ("<junk>\n");
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
  BOOL  found_load = FALSE;  /* Found the " LOAD " line */
  BOOL  found_text = FALSE;  /* Found a ".text <addr> <size> <.o-file>" line */
  FILE *fil;

  if (!dot)
     return (0);

  _strlcpy (map_file, module, dot-module+1);
  strcat (map_file, ".map");
  if (!FILE_EXISTS(map_file))
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
    BOOL   found_func = FALSE;

    if (!fgets(buf,sizeof(buf)-1,fil) ||  /* EOF */
        !strncmp(buf,"*(SORT(",7))        /* End of ".text" section */
       break;

    line++;

    if (!strncmp(buf,"LOAD ",5))
    {
      found_load = TRUE;
      continue;
    }

    if (!found_load)
       continue;

    p = 1 + strip_nl (buf);

#define TEXT_SECTION   ".text          0x"
#define TEXT_CONTINUE  "               0x"

    if (!found_text && !strncmp(p,TEXT_SECTION,sizeof(TEXT_SECTION)))
    {
      p += sizeof(TEXT_SECTION);
      found_text = (sscanf(p, "%p 0x%lx %s", &addr, &size, file) == 3);
      TRACE (1, "line: %lu, addr: %p, file: %s.\n", line, addr, file);
      dot = strrchr (file, '.');
      if (!dot || dot[1] != 'o')
         file[0] = '\0';
      continue;
    }

    if (found_text && !strncmp(p,TEXT_CONTINUE,sizeof(TEXT_CONTINUE)))
    {
      p += sizeof(TEXT_CONTINUE);
      found_func = (sscanf(p, "%p %100s", &addr, func) == 2);
      TRACE (1, "line: %lu, addr: %p, func: %s.\n", line, addr, func);
    }

    TRACE (1, "line: %lu, addr: %p, found_load: %d, found_text: %d, found_func: %d, p: '%s'.\n",
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

/*
 * Enumerate all PDB symbols for a module.
 * The callback 'enum_symbols_proc()' adds the 'SymbolEntry' to the smartlist 'sl'.
 */
static DWORD enum_module_symbols (smartlist_t *sl, const char *module, BOOL is_last, BOOL verbose)
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

  _trace_printf = verbose ? trace_printf : null_printf;

  save = g_cfg.test_trace;
  g_cfg.test_trace = 1;

#if !defined(_MSC_VER) && !defined(__clang__)
  if (!stricmp(g_module,module))
  {
    TRACE (3, "Not searching for PDB-symbols in module %s.\n", module);
    goto check_mingw_map_file;
  }
#endif

  _strlcpy (pattern, basename(module), _MAX_PATH);
  dot = strrchr (pattern, '.');
  if (dot)
     *dot = '\0';
  strcat (pattern, "!*");

  if (!(*p_SymEnumSymbolsEx) (g_proc, 0, pattern, enum_symbols_proc, sl,
                              SYMENUM_OPTIONS_DEFAULT | SYMENUM_OPTIONS_INLINE))
     TRACE (2, "SymEnumSymbolsEx() failed for %s: %s\n", basename(module), get_error());

#if !defined(_MSC_VER) && !defined(__clang__)
check_mingw_map_file:

#if defined(__MINGW32__)
  num_mingw_syms = parse_map_file (module, sl);
#endif
#endif

  g_cfg.test_trace = save;

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

#undef  ADD_VALUE
#define ADD_VALUE(opt, func)  { opt, NULL, "dbghelp.dll", #func, (void**)&p_##func }

/*
 * The user of StackWalkShow() must call StackWalkInit() first.
 */
BOOL StackWalkInit (void)
{
  static struct LoadTable dbghelp_funcs[] = {
                          ADD_VALUE (0, SymCleanup),
                          ADD_VALUE (0, SymFunctionTableAccess64),
                          ADD_VALUE (0, SymGetLineFromAddr64),
                          ADD_VALUE (0, SymGetModuleBase64),
                          ADD_VALUE (0, SymGetModuleInfo64),
                          ADD_VALUE (0, SymGetOptions),
                          ADD_VALUE (0, SymGetSymFromAddr64),
                          ADD_VALUE (0, SymFromAddr),
                          ADD_VALUE (0, SymInitialize),
                          ADD_VALUE (0, SymSetOptions),
                          ADD_VALUE (0, StackWalk64),
                          ADD_VALUE (0, SymLoadModule64),
#if USE_SymEnumSymbolsEx
                          ADD_VALUE (0, SymEnumSymbolsEx),
                          ADD_VALUE (1, SymSrvGetFileIndexInfo),
#endif
                          ADD_VALUE (0, UnDecorateSymbolName),
                        };
  BOOL ok = (load_dynamic_table(dbghelp_funcs, DIM(dbghelp_funcs)) == DIM(dbghelp_funcs));

  g_modules_list = smartlist_new();
  g_symbols_list = smartlist_new();

  g_proc    = GetCurrentProcess();
  g_proc_id = GetCurrentProcessId();

  GetModuleFileName (NULL, g_module, sizeof(g_module));
  TRACE (2, "g_module: %s\n", g_module);

#if defined(_MSC_VER)
  #if (_MSC_VER >= 1900)
    g_long_CPP_syms = (__scrt_is_ucrt_dll_in_use() == 0);
  #elif defined(_MT)
    g_long_CPP_syms = TRUE;
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
    return (FALSE);
  }

#if USE_SymEnumSymbolsEx
  if (g_cfg.pdb_report || g_cfg.dump_modules)
     print_modules_and_pdb_info (g_cfg.pdb_report, FALSE, TRUE);
#endif

  TRACE (2, "\n");
  return (ok);
}

/*****************************************************************************************/

static char ret_buf [MAX_NAMELEN+100];

static DWORD decode_one_stack_frame (HANDLE thread, DWORD image_type,
                                     STACKFRAME64 *stk, CONTEXT *ctx)
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
  DWORD   displacement    = 0;
  DWORD   temp_disp       = 0;
  DWORD   max_displ       = 100;
  DWORD   flags           = UNDNAME_NAME_ONLY;  /* show procedure info */
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
  BOOL have_PDB_info = TRUE;

  if (g_cfg.max_displacement > 0)
     max_displ = g_cfg.max_displacement;

  if (g_cfg.cpp_demangle)
     flags = UNDNAME_COMPLETE;

  undec_name[0] = '\0';

  /* Get next stack frame (StackWalk64(), SymFunctionTableAccess64(), SymGetModuleBase64()).
   * if this returns ERROR_INVALID_ADDRESS (487) or ERROR_NOACCESS (998), you can
   * assume that either you are done, or that the stack is so hosed that the next
   * deeper frame could not be found.
   * CONTEXT need not to be supplied if image_type is IMAGE_FILE_MACHINE_I386!
   */
  if (!(*p_StackWalk64)(image_type, g_proc, thread, stk, ctx, NULL,
                        p_SymFunctionTableAccess64, p_SymGetModuleBase64, NULL))
     return (1);

  addr = stk->AddrPC.Offset;

  if (addr == 0)    /* If we are here, we have no valid callstack entry! */
     return (2);

#if !defined(_MSC_VER) && !defined(__clang__)
  {
    DWORD64 base = (*p_SymGetModuleBase64) (g_proc, addr);
    char    path [MAX_PATH] = { '\0' };

    if (GetModuleFileName((HANDLE)(uintptr_t)base, path, sizeof(path)) &&
        !stricmp(g_module,path))
       have_PDB_info = FALSE;
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

  while (temp_disp < max_displ &&
         !(*p_SymGetLineFromAddr64)(g_proc, addr - temp_disp, &ofs_from_line, &Line))
       ++temp_disp;

  if (temp_disp >= max_displ)
     return (5);

  /* It was found and the source line information is correct so
   * change the displacement if it was looked up multiple times.
   */
  if (temp_disp < max_displ && temp_disp != 0)
     displacement = temp_disp;

  str += snprintf (str, left, "~2%s(%lu)~1 (",
                   shorten_path(Line.FileName),
                   DWORD_CAST(Line.LineNumber));
  left = end - str;

  /* If 'undec_name[]' contains a "~" (a C++ destructor),
   * replace that with "~~" since 'trace_putc()' gets confused otherwise.
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
  DWORD        image_type;
  DWORD        err  = 0;
  size_t       left = sizeof(ret_buf);
  char        *str  = ret_buf;
  char        *end  = str + left;
  STACKFRAME64 stk;    /* in/out stackframe */

  memset (&stk, 0, sizeof(stk));

  /* init STACKFRAME.
   * Notes: AddrModeFlat is just an assumption.
   */
#ifdef _WIN64
  image_type = IMAGE_FILE_MACHINE_AMD64;

  stk.AddrPC.Offset    = ctx->Rip;
  stk.AddrFrame.Offset = ctx->Rbp;
  stk.AddrStack.Offset = ctx->Rsp;
#else
  image_type = IMAGE_FILE_MACHINE_I386;

  stk.AddrPC.Offset    = ctx->Eip;
  stk.AddrFrame.Offset = ctx->Ebp;
  stk.AddrStack.Offset = ctx->Esp;
#endif

  stk.AddrPC.Mode    = AddrModeFlat;
  stk.AddrFrame.Mode = AddrModeFlat;
  stk.AddrStack.Mode = AddrModeFlat;

  err = decode_one_stack_frame (thread, image_type, &stk, ctx);
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
