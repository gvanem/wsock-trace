/*!\file stkwalk.c
 * StackWalker (backtrace) for Win32 / MSVC+MinGW
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

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <assert.h>

#include "common.h"
#include "init.h"
#include "bfd_gcc.h"
#include "stkwalk.h"

static HANDLE g_proc;
static DWORD  g_proc_id;

#define USE_SYMFROMADDR 1

#define MAX_NAMELEN  1024        /* max name length for found symbols */
#define TTBUFLEN     8096        /* for a temp buffer (2^13) */

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

typedef BOOL (__stdcall *PREAD_PROCESS_MEMORY_ROUTINE64)(
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

typedef PVOID (__stdcall   *PFUNCTION_TABLE_ACCESS_ROUTINE64) (
                            HANDLE process, DWORD64 AddrBase);

typedef DWORD64 (__stdcall *PGET_MODULE_BASE_ROUTINE64) (
                            HANDLE process, DWORD64 Address);

typedef DWORD64 (__stdcall *PTRANSLATE_ADDRESS_ROUTINE64) (
                            HANDLE process, HANDLE thread, ADDRESS64 *addr);

#endif  /* API_VERSION_NUMBER < 9 */


typedef BOOL (__stdcall *func_SymCleanup) (IN HANDLE process);

typedef DWORD (__stdcall *func_SymGetOptions) (VOID);

typedef DWORD (__stdcall *func_SymSetOptions) (IN DWORD SymOptions);

typedef PVOID (__stdcall *func_SymFunctionTableAccess64) (IN HANDLE  process,
                                                          IN DWORD64 AddrBase);

typedef BOOL (__stdcall *func_SymGetLineFromAddr64) (IN  HANDLE           process,
                                                     IN  DWORD64          addr,
                                                     OUT DWORD           *displacement,
                                                     OUT IMAGEHLP_LINE64 *Line);

typedef DWORD64 (__stdcall *func_SymGetModuleBase64) (IN HANDLE  process,
                                                      IN DWORD64 addr);

typedef BOOL (__stdcall *func_SymGetModuleInfo64) (IN  HANDLE             process,
                                                   IN  DWORD64            addr,
                                                   OUT IMAGEHLP_MODULE64 *ModuleInfo);

typedef BOOL (__stdcall *func_SymGetSymFromAddr64) (IN  HANDLE             process,
                                                    IN  DWORD64            addr,
                                                    OUT DWORD64           *displacement,
                                                    OUT IMAGEHLP_SYMBOL64 *Symbol);

typedef BOOL (__stdcall *func_SymFromAddr) (IN     HANDLE       process,
                                            IN     DWORD64      addr,
                                            OUT    DWORD64     *displacement,
                                            IN OUT SYMBOL_INFO *Symbol);

typedef BOOL (__stdcall *func_SymInitialize) (IN HANDLE process,
                                              IN PCSTR  UserSearchPath,
                                              IN BOOL   invadeProcess);

typedef DWORD (__stdcall *func_SymLoadModule64) (IN HANDLE  process,
                                                 IN HANDLE  file,
                                                 IN PCSTR   ImageName,
                                                 IN PCSTR   ModuleName,
                                                 IN DWORD64 BaseOfDll,
                                                 IN DWORD   SizeOfDll);

typedef BOOL (__stdcall *func_StackWalk64) (IN DWORD                         MachineType,
                                            IN HANDLE                        process,
                                            IN HANDLE                        thread,
                                            STACKFRAME64                    *StackFrame,
                                            VOID                            *ContextRecord,
                                            PREAD_PROCESS_MEMORY_ROUTINE64   ReadMemoryRoutine,
                                            PFUNCTION_TABLE_ACCESS_ROUTINE64 FunctionTableAccessRoutine,
                                            PGET_MODULE_BASE_ROUTINE64       GetModuleBaseRoutine,
                                            PTRANSLATE_ADDRESS_ROUTINE64     TranslateAddress);

typedef DWORD (__stdcall WINAPI *func_UnDecorateSymbolName) (PCSTR DecoratedName,
                                                             PSTR  UnDecoratedName,
                                                             DWORD UndecoratedLength,
                                                             DWORD Flags);

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

struct ModuleEntry {
       char               *moduleName;    /* fully qualified name of module */
       char               *parentName;    /* fully qualified name of parent module */
       ULONG_PTR           baseAddress;
       DWORD               size;
       struct ModuleEntry *next;          /* \todo: make it a linked list */
     } ModuleEntry;

static struct ModuleEntry *me_list = NULL;
static int                 me_list_top = 0;   /* # of modules in 'me_list' */
static size_t              me_list_size = 0;

#if USE_SYMFROMADDR
/*
 * For decoding 'struct _SYMBOL_INFO::Flags'.
 *
 * Ref: https://msdn.microsoft.com/en-us/library/windows/desktop/ms680686(v=vs.85).aspx
 */
#define ADD_VALUE(v)  { v, #v }

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

const struct search_list symbol_info_flags[] = {
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
                         ADD_VALUE (SYMFLAG_VIRTUAL)
                       };
#endif  /* USE_SYMFROMADDR != 0 */

BOOL StackWalkExit (void)
{
  struct ModuleEntry *me = me_list;
  int    i;

  for (i = 0; i < me_list_top; i++, me++)
  {
#ifdef USE_BFD
    BFD_unload_debug_symbols (me->moduleName);
#endif
    free (me->moduleName);
  }
  free (me_list);
  me_list = NULL;
  me_list_top = 0;
  me_list_size = 0;
  return (TRUE);
}

static void AllocateModuleList (int num_elements)
{
  me_list_size = num_elements * sizeof(*me_list);
  me_list = calloc (1, me_list_size);
  me_list_top = 0;
}

static void AddToModuleList (int index, const struct ModuleEntry *me)
{
  assert (index == me_list_top);
  assert (me_list_size >= (me_list_top * sizeof(*me)));
  me_list [me_list_top++] = *me;
}


static const char *get_error (void)
{
  static char buf[10];
  DWORD err = GetLastError();

  if (err == ERROR_MOD_NOT_FOUND)
     return ("ERROR_MOD_NOT_FOUND");
  if (err == ERROR_INVALID_PARAMETER)
     return ("ERROR_INVALID_PARAMETER");
  if (err == ERROR_INVALID_ADDRESS)
     return ("ERROR_INVALID_ADDRESS");
  return _itoa (err,buf,10);
}

/**************************************** ToolHelp32 *************************/

typedef HANDLE (__stdcall *func_CreateToolhelp32Snapshot) (DWORD dwFlags, DWORD PID);
typedef BOOL   (__stdcall *func_Module32First) (HANDLE snap, MODULEENTRY32 *me);
typedef BOOL   (__stdcall *func_Module32Next) (HANDLE snap, MODULEENTRY32 *me);
typedef BOOL   (__stdcall *func_Thread32First) (HANDLE snap, THREADENTRY32 *te);
typedef BOOL   (__stdcall *func_Thread32Next) (HANDLE snap, THREADENTRY32 *te);

static func_CreateToolhelp32Snapshot p_CreateToolhelp32Snapshot = NULL;
static func_Module32First            p_Module32First = NULL;
static func_Module32Next             p_Module32Next  = NULL;
static func_Thread32First            p_Thread32First = NULL;
static func_Thread32Next             p_Thread32Next  = NULL;

#undef  ADD_VALUE
#define ADD_VALUE(opt,dll,func)   { opt, NULL, dll, #func, (void**)&p_##func }
#define ADD_THREAD_SNAPSHOT       1

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

  AllocateModuleList (TTBUFLEN / sizeof(*me_list));

  me.dwSize = sizeof(me);

  for (i = 0, (*p_Module32First)(snap,&me);; i++)
  {
    struct ModuleEntry e;

    e.moduleName  = strdup (me.szExePath);
    e.baseAddress = (ULONG_PTR) me.modBaseAddr;
    e.size        = me.modBaseSize;
    AddToModuleList (i, &e);

    if (i == (me_list_size/sizeof(e))-1)
       break;
    if (!(*p_Module32Next)(snap,&me))
       break;
  }

#if ADD_THREAD_SNAPSHOT
  if (p_Thread32First && p_Thread32Next)
  {
    HANDLE thr_snap = INVALID_HANDLE_VALUE;

    thr_snap = (*p_CreateToolhelp32Snapshot) (TH32CS_SNAPTHREAD, g_proc_id);
    if (thr_snap != INVALID_HANDLE_VALUE)
    {
      THREADENTRY32 te;

      te.dwSize = sizeof(te);
      for (i = 0, (*p_Thread32First)(thr_snap,&te);; i++)
      {
         if (te.th32OwnerProcessID == g_proc_id)
            TRACE (4, "  %d: thread-info for this process: TID: %lu, PID: %lu\n",
                      i, te.th32ThreadID, te.th32OwnerProcessID);
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

  return (me_list_top);
}

/**************************************** PSAPI ************************/

typedef BOOL  (__stdcall *func_EnumProcessModules) (HANDLE process, HMODULE *module, DWORD cb, DWORD *needed);
typedef DWORD (__stdcall *func_GetModuleFileNameExA) (HANDLE process, HMODULE module, LPSTR lpFilename, DWORD nSize);
typedef BOOL  (__stdcall *func_GetModuleInformation) (HANDLE process, HMODULE module, MODULEINFO *pmi, DWORD nSize);

static func_EnumProcessModules   p_EnumProcessModules;
static func_GetModuleFileNameExA p_GetModuleFileNameExA;
static func_GetModuleInformation p_GetModuleInformation;

static struct LoadTable psapi_funcs[] = {
              ADD_VALUE (0, "psapi.dll",    EnumProcessModules),
              ADD_VALUE (0, "psapi.dll",    GetModuleFileNameExA),
              ADD_VALUE (0, "psapi.dll",    GetModuleInformation),
              ADD_VALUE (1, "kernel32.dll", EnumProcessModules),   /* (1) */
              ADD_VALUE (1, "kernel32.dll", GetModuleFileNameExA), /* (1) */
              ADD_VALUE (1, "kernel32.dll", GetModuleInformation)  /* (1) */
             };
            /* (1) = These are in Kernel32.dll in Win-7+ Win-Server 2008 R2.
             */

static int GetModuleListPSAPI (void)
{
  DWORD    i, needed, num_modules;
  HMODULE *hMods = alloca (TTBUFLEN);
  BOOL     okay = (load_dynamic_table(psapi_funcs, DIM(psapi_funcs)) >= 3);

  if (!okay)
     goto cleanup;

  if (!(*p_EnumProcessModules)(g_proc, hMods, TTBUFLEN, &needed))
  {
    TRACE (1, "EnumProcessModules() failed: %s.\n", get_error());
    goto cleanup;
  }

  num_modules = needed / sizeof(HMODULE);
  if (needed > TTBUFLEN)
  {
    TRACE (1, "More than %lu module handles. Huh?\n", num_modules);
    goto cleanup;
  }

  AllocateModuleList (num_modules);

  for (i = 0; i < num_modules; i++)
  {
    struct ModuleEntry me;
    char        tt [TTBUFLEN];
    MODULEINFO  mi;

    (*p_GetModuleInformation) (g_proc, hMods[i], &mi, sizeof(mi));
    me.baseAddress = (ULONG_PTR) mi.lpBaseOfDll;
    me.size = mi.SizeOfImage;

    /*
     * May have to use QueryFullProcessImageName (Vista+) or GetProcessImageFileName (Win-XP)
     * Ref. comments at:
     *   http://msdn.microsoft.com/en-us/library/windows/desktop/ms683198(v=vs.85).aspx
     */

    tt[0] = '\0';
    (*p_GetModuleFileNameExA) (g_proc, hMods[i], tt, sizeof(tt));
    me.moduleName = strdup (tt);

    AddToModuleList (i, &me);
    if (i == (me_list_size/sizeof(me))-1)
       break;
  }

cleanup:

  unload_dynamic_table (psapi_funcs, DIM(psapi_funcs));

  return (me_list_top);
}

static int EnumAndLoadModuleSymbols (void)
{
  const struct ModuleEntry *me;
  int   num, rc = 0;

  if (!g_cfg.use_toolhlp32)
  {
    rc = GetModuleListPSAPI();    /* First try PSAPI */
    TRACE (2, "GetModuleListPSAPI(): Enumerated %d modules:\n", rc);
  }

  if (rc == 0)
  {
    rc = GetModuleListTH32();     /* then try ToolHelp32 API */
    TRACE (2, "GetModuleListTH32(): Enumerated %d modules:\n", rc);
  }

  TRACE (2, "  %-60s Baseaddr       Size\n"
            "  -------------------------------------------------"
            "---------------------------------------------------\n",
            "Module");

  for (num = 0, me = me_list; num < me_list_top; me++, num++)
  {
    DWORD64 rc = (*p_SymLoadModule64) (g_proc, 0, me->moduleName, me->moduleName,
                                       me->baseAddress, me->size);

    if (!stricmp(wsock_trace_dll_name,basename(me->moduleName)))
    {
   // add_to_shared_list (base);   /* \todo */
      ws_trace_base = (HINSTANCE) me->baseAddress;
    }

    TRACE (2, "  %-60s 0x%" ADDR_FMT " %7s kB. %s\n",
           me->moduleName, ADDR_CAST(me->baseAddress), dword_str(me->size/1024),
           rc == 0 ? get_error() : "");

#ifdef USE_BFD
    BFD_load_debug_symbols (me->moduleName, me->baseAddress, me->size);
#endif
  }

#ifdef USE_BFD
  BFD_dump();
#endif
  return (num);
}


static BOOL SetSymbolSearchPath (void)
{
  DWORD  symOptions;
  char   tmp [TTBUFLEN];
  char   path [TTBUFLEN];
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

/*
 * The user of StackWalkShow() must call StackWalkInit() first.
 */
#undef  ADD_VALUE
#define ADD_VALUE(func)   { 0, NULL, "dbghelp.dll", #func, (void**)&p_##func }

BOOL StackWalkInit (void)
{
  static struct LoadTable dbghelp_funcs[] = {
                          ADD_VALUE (SymCleanup),
                          ADD_VALUE (SymFunctionTableAccess64),
                          ADD_VALUE (SymGetLineFromAddr64),
                          ADD_VALUE (SymGetModuleBase64),
                          ADD_VALUE (SymGetModuleInfo64),
                          ADD_VALUE (SymGetOptions),
                          ADD_VALUE (SymGetSymFromAddr64),
                          ADD_VALUE (SymFromAddr),
                          ADD_VALUE (SymInitialize),
                          ADD_VALUE (SymSetOptions),
                          ADD_VALUE (StackWalk64),
                          ADD_VALUE (SymLoadModule64),
                          ADD_VALUE (UnDecorateSymbolName)
                        };
  BOOL ok = (load_dynamic_table(dbghelp_funcs, DIM(dbghelp_funcs)) == DIM(dbghelp_funcs));

  g_proc    = GetCurrentProcess();
  g_proc_id = GetCurrentProcessId();

  if (ok && SetSymbolSearchPath())
  {
    /* Enumerate modules and tell dbghelp.dll about them.
     */
    EnumAndLoadModuleSymbols();

#if 0  /* \todo */
    if (num_in_shared_list() > 1)
    {
      WARN ("PROBLEM: Multiple %s in the same process.\n", wsock_trace_dll_name);
    }
#endif
  }
  if (!ok)
     TRACE (1, "StackWalker failed to initialize.\n");

  TRACE (2, "\n");
  return (ok);
}

/*****************************************************************************************/

static char ret_buf [MAX_NAMELEN+100];

static DWORD decode_one_stack_frame (HANDLE thread, DWORD image_type,
                                     STACKFRAME64 *stk, CONTEXT *ctx)
{
  struct {
#if USE_SYMFROMADDR
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
  DWORD   max_displ       = 100;                /* \todo: g_cfg.max_displacement */
  DWORD   flags           = UNDNAME_NAME_ONLY;  /* show procedure info */
  DWORD64 ofs_from_symbol = 0;                  /* How far from the symbol we were */
  DWORD   ofs_from_line   = 0;                  /* How far from the line we were */
  size_t  left            = sizeof(ret_buf);
  char   *str             = ret_buf;
  char   *p, *end         = str + left;

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

  if (stk->AddrPC.Offset == 0)  /* If we are here, we have no valid callstack entry! */
     return (2);

#ifdef USE_BFD
  if (BFD_get_function_name(stk->AddrPC.Offset, str, left) != 0)
     return (3);

#else

  memset (&sym, '\0', sizeof(sym));
  sym.hdr.SizeOfStruct  = sizeof(sym.hdr);

#if USE_SYMFROMADDR
  sym.hdr.MaxNameLen = sizeof(sym.name);
  if (!(*p_SymFromAddr)(g_proc, stk->AddrPC.Offset, &ofs_from_symbol, &sym.hdr))
     return (4);

#else
  sym.hdr.MaxNameLength = sizeof(sym.name);
  if (!(*p_SymGetSymFromAddr64)(g_proc, stk->AddrPC.Offset, &ofs_from_symbol, &sym.hdr))
     return (4);
#endif

  (*p_UnDecorateSymbolName) (sym.hdr.Name, undec_name, sizeof(undec_name), flags);

  memset (&Line, '\0', sizeof(Line));
  Line.SizeOfStruct = sizeof(Line);

  while (temp_disp < max_displ &&
         !(*p_SymGetLineFromAddr64)(g_proc, stk->AddrPC.Offset - temp_disp, &ofs_from_line, &Line))
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
                   Line.LineNumber);
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
     snprintf (str, left, "+%lu)", displacement);
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

  stk.AddrPC.Mode      = AddrModeFlat;
  stk.AddrFrame.Mode   = AddrModeFlat;
  stk.AddrStack.Mode   = AddrModeFlat;

  err = decode_one_stack_frame (thread, image_type, &stk, ctx);
  if (err == 0)
     return (ret_buf);

  str += snprintf (ret_buf, sizeof(ret_buf), "0x%" ADDR_FMT, ADDR_CAST(stk.AddrPC.Offset));
  left = end - str;

#ifdef _MSC_VER
  /*
   * \todo: In this case figure out the module-name (from the base-addresses in
   *        EnumAndLoadModuleSymbols()) and print which module (i.e. DLL) that is
   *        missing a .PDB file.
   */
  snprintf (str, left, " (no PDB, err: %lu)", err);
#endif

  return (ret_buf);
}
