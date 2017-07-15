/*
 * vm_dump.c
 *
 * Copyright (C) 2004-2007 Koichi Sasada
 *
 * Heavily modified version of the Ruby crash-handler at:
 *   https://opensource.apple.com/source/ruby/ruby-104/ruby/vm_dump.c
 */

#include <stdio.h>
#include <signal.h>
#include <process.h>
#include <windows.h>
#include <imagehlp.h>

#include "common.h"
#include "vm_dump.h"

int vm_bug_debug = 0;

#undef  TRACE
#define TRACE(level, fmt, ...)                           \
        do {                                             \
          if (vm_bug_debug >= level)                     \
             printf ("%s(%u): " fmt, __FILE__, __LINE__, \
                     ## __VA_ARGS__);                    \
        } while (0)

#ifndef SYMOPT_DEBUG
#define SYMOPT_DEBUG 0x80000000
#endif

#ifndef MAX_SYM_NAME
#define MAX_SYM_NAME 2000
#endif

#if defined(_MSC_VER) && !defined(__POCC__)
  /*
   * All MS compilers insists that signal-handlers, atexit functions and var-arg
   * functions must be defined as cdecl. This is only an issue if a program is using
   * 'fastcall' globally (cl option '-Gr').
   */
  #define MS_CDECL cdecl
#else
  #define MS_CDECL
#endif

#if defined(__GNUC__) && defined(__i386__)
  /*
   * Problems at 'gcc -O0'. Use this hack
   */
  static inline void *_NtCurrentTeb (void)
  {
    return (void*) __readfsdword (0x18);
  }
  #define NtCurrentTeb() _NtCurrentTeb()
#endif

typedef DWORD   (WINAPI *func_SymSetOptions) (IN DWORD options);

typedef BOOL    (WINAPI *func_SymInitialize) (IN HANDLE process,
                                              IN PCSTR  UserSearchPath,
                                              IN BOOL   invadeProcess);

typedef BOOL    (WINAPI *func_SymCleanup) (IN HANDLE process);

typedef DWORD64 (WINAPI *func_SymGetModuleBase64) (IN HANDLE  process,
                                                   IN DWORD64 addr);

typedef BOOL    (WINAPI *func_SymFromAddr) (IN     HANDLE       process,
                                            IN     DWORD64      addr,
                                            OUT    DWORD64     *displacement,
                                            IN OUT SYMBOL_INFO *Symbol);

typedef BOOL    (WINAPI *func_SymGetLineFromAddr64) (IN  HANDLE           process,
                                                     IN  DWORD64          addr,
                                                     OUT DWORD           *displacement,
                                                     OUT IMAGEHLP_LINE64 *Line);

typedef BOOL    (WINAPI *func_StackWalk64) (IN     DWORD                            MachineType,
                                            IN     HANDLE                           process,
                                            IN     HANDLE                           thread,
                                            IN OUT STACKFRAME64                    *StackFrame,
                                            IN OUT VOID                            *ContextRecord,
                                            IN     PREAD_PROCESS_MEMORY_ROUTINE64   ReadMemoryRoutine,
                                            IN     PFUNCTION_TABLE_ACCESS_ROUTINE64 FunctionTableAccessRoutine,
                                            IN     PGET_MODULE_BASE_ROUTINE64       GetModuleBaseRoutine,
                                            IN     PTRANSLATE_ADDRESS_ROUTINE64     TranslateAddress);

typedef struct thread_args {
        DWORD                     tid;
        HANDLE                    proc;
        void                     *list;
        int                       max_frames;      /* How many addresses to trace */
        int                       max_recursion;   /* How many recursive calls to trace */
        int                       skip_frames;     /* How many initial frames to NOT trace */
        func_SymFromAddr          p_SymFromAddr;
        func_SymGetModuleBase64   p_SymGetModuleBase64;
        func_SymGetLineFromAddr64 p_SymGetLineFromAddr64;
      } thread_args;

static char our_module [_MAX_PATH];

static void (MS_CDECL *orig_abort_handler)(int) = SIG_DFL;

static void print_one_address (thread_args *args, DWORD64 addr)
{
  SYMBOL_INFO    *info;
  char            buf [sizeof(*info) + MAX_SYM_NAME];
  DWORD64         base, displacement;
  IMAGEHLP_LINE64 line;
  DWORD           tmp;
  char            path [MAX_PATH] = { '\0' };

  /* Assume the module is MSVC/clang-cl compiled. Call 'p_SymFromAddr' and
   * 'p_SymGetLineFromAddr64()' if this is the case. If the '<module>.pdb'
   * is present while running a MinGW compiled program, this just returns
   * wrong information from dbghelp.dll.
   */
  BOOL have_PDB_info = TRUE;

  printf ( "0x%" ADDR_FMT ": ", ADDR_CAST(addr));

  memset (buf, 0, sizeof(buf));
  info = (SYMBOL_INFO*) buf;
  info->SizeOfStruct = sizeof(*info);
  info->MaxNameLen   = sizeof(buf) - sizeof(*info);

#if 0
  if (args->list)
  {
    size_t len1                = strlen (path) + 1;
    size_t len2                = strlen (line.FileName) + 1;
    size_t len3                = strlen (info->Name) + 1;
    struct backtrace_entry *be = calloc (1, sizeof(*be) + len1 + len2 + len3);
    char                   *dst = (char*) (be + 1);

    be->addr         = addr;
    be->line_number  = line.LineNumber;
    be->displacement = displacement;
    be->module_name  = strcpy (dst, path);           dst += len1;
    be->file_name    = strcpy (dst, line.FileName);  dst += len2;
    be->name         = strcpy (dst, info->Name);

    smartlist_add (args->list, be);
  }
#endif

  base = (*args->p_SymGetModuleBase64) (args->proc, addr);

  if (GetModuleFileName((HANDLE)(uintptr_t)base, path, sizeof(path)))
     printf ("%-15s", shorten_path(path));

#if !defined(_MSC_VER) && !defined(__clang__)
  if (path[0] && !stricmp(our_module,path))
     have_PDB_info = FALSE;
 /*
  * otherwise the module can be a MSVC/clang-cl compiled module in a MinGW program.
  */
#endif

  if (have_PDB_info && (*args->p_SymFromAddr)(args->proc, addr, &displacement, info))
     printf (" (%s+%lu)", info->Name, (DWORD)displacement);

  if (have_PDB_info)
  {
    memset (&line, 0, sizeof(line));
    line.SizeOfStruct = sizeof(line);
    if ((*args->p_SymGetLineFromAddr64)(args->proc, addr, &tmp, &line))
       printf ("  %s(%lu)", shorten_path(line.FileName), line.LineNumber);
  }
  else
  {
    printf (" <No PDB>");
#if !defined(_MSC_VER)
     /* look in map_file_list */
#endif
  }
  putchar ('\n');
}

extern void print_thread_times (HANDLE thread);

static DWORD WINAPI dump_thread (void *arg)
{
  thread_args  args = *(thread_args*) arg;
  HANDLE       proc, thr = NULL;
  CONTEXT      context;
  STACKFRAME64 frame;
  DWORD        mac;
  int          rec_count = 0;

  func_SymInitialize        p_SymInitialize;
  func_SymCleanup           p_SymCleanup;
  func_SymGetModuleBase64   p_SymGetModuleBase64;
  func_SymFromAddr          p_SymFromAddr;
  func_SymGetLineFromAddr64 p_SymGetLineFromAddr64;
  func_SymSetOptions        p_SymSetOptions;
  func_StackWalk64          p_StackWalk64;

#define ADD_VALUE(func)  { 0, NULL, "dbghelp.dll", #func, (void**)&p_##func }

  struct LoadTable funcs[] = {
         ADD_VALUE (SymInitialize),
         ADD_VALUE (SymCleanup),
         ADD_VALUE (SymGetModuleBase64),
         ADD_VALUE (SymFromAddr),
         ADD_VALUE (SymGetLineFromAddr64),
         ADD_VALUE (SymSetOptions),
         ADD_VALUE (StackWalk64)
       };
  BOOL okay = (load_dynamic_table(funcs, DIM(funcs)) == DIM(funcs));

  if (!okay)
  {
    TRACE (1, "Some missing functions.\n");
    goto quit;
  }

  (*p_SymSetOptions) (SYMOPT_UNDNAME | SYMOPT_DEFERRED_LOADS | SYMOPT_DEBUG | SYMOPT_LOAD_LINES);
  proc = GetCurrentProcess();
  (*p_SymInitialize) (proc, NULL, TRUE);

  thr = OpenThread (THREAD_SUSPEND_RESUME|THREAD_GET_CONTEXT, FALSE, args.tid);
  if (!thr)
  {
    TRACE (1, "Failed in OpenThread(): %s.\n", win_strerror(GetLastError()));
    goto sym_cleanup;
  }
  if (SuspendThread(thr) == (DWORD)-1)
  {
    TRACE (1, "Failed in SuspendThread(): %s.\n", win_strerror(GetLastError()));
    goto close_thread;
  }

  memset (&context, 0, sizeof(context));
  context.ContextFlags = CONTEXT_FULL;
  if (!GetThreadContext(thr, &context))
  {
    TRACE (1, "Failed in GetThreadContext(): %s.\n", win_strerror(GetLastError()));
    goto resume_thread;
  }

  memset (&frame, 0, sizeof(frame));

#if defined(_M_AMD64) || defined(__x86_64__)
  mac                    = IMAGE_FILE_MACHINE_AMD64;
  frame.AddrPC.Mode      = AddrModeFlat;
  frame.AddrPC.Offset    = context.Rip;
  frame.AddrFrame.Mode   = AddrModeFlat;
  frame.AddrFrame.Offset = context.Rbp;
  frame.AddrStack.Mode   = AddrModeFlat;
  frame.AddrStack.Offset = context.Rsp;
#elif defined(_M_IA64) || defined(__ia64__)
  mac                     = IMAGE_FILE_MACHINE_IA64;
  frame.AddrPC.Mode       = AddrModeFlat;
  frame.AddrPC.Offset     = context.StIIP;
  frame.AddrBStore.Mode   = AddrModeFlat;
  frame.AddrBStore.Offset = context.RsBSP;
  frame.AddrStack.Mode    = AddrModeFlat;
  frame.AddrStack.Offset  = context.IntSp;
#else   /* i386 */
  mac                    = IMAGE_FILE_MACHINE_I386;
  frame.AddrPC.Mode      = AddrModeFlat;
  frame.AddrPC.Offset    = context.Eip;
  frame.AddrFrame.Mode   = AddrModeFlat;
  frame.AddrFrame.Offset = context.Ebp;
  frame.AddrStack.Mode   = AddrModeFlat;
  frame.AddrStack.Offset = context.Esp;
#endif

  while ((*p_StackWalk64)(mac, proc, thr, &frame, &context, NULL, NULL, NULL, NULL))
  {
    DWORD64 addr      = frame.AddrPC.Offset;
    BOOL    recursion = (addr == frame.AddrReturn.Offset);
    char    rec_buf [40];

    if (recursion)
    {
      rec_count++;
      snprintf (rec_buf, sizeof(rec_buf), " (count %d)", rec_count);
    }

    if (vm_bug_debug >= 3)
    {
      const NT_TIB *tib = (const NT_TIB*) NtCurrentTeb();

      TRACE (3, "stack-base:  0x%p\n"
                "                stack-limit: 0x%p\n", tib->StackBase, tib->StackLimit);
    }

    if (recursion || addr == 0 || frame.AddrReturn.Offset == 0)
    {
      TRACE (2, "addr:                    0x%I64X %s%s\n"
                "                frame.AddrPC.Offset:     0x%I64X\n"
                "                frame.AddrReturn.Offset: 0x%I64X.\n",
             addr,
             recursion ? "recursion" : "",
             recursion ? rec_buf     : "",
             frame.AddrPC.Offset,
             frame.AddrReturn.Offset);
      if (!recursion || rec_count >= args.max_recursion)
         break;
    }

    if (args.skip_frames > 0)
    {
      args.skip_frames--;
      continue;
    }

    /* The return-address is usually 5 bytes after the calling line.
     * E.g. 'call foo' decodes to
     *   E8 xx xx xx xx             for 32-bit.
     *   E8 xx xx xx xx xx xx xx xx for 64-bit.
     *
     * So try to get the function-name, displacement and line of the calling
     * line. We're not so much interested in the 'return address'.
     */
    addr -= 1 + sizeof(void*);

    args.p_SymFromAddr          = p_SymFromAddr;
    args.p_SymGetModuleBase64   = p_SymGetModuleBase64;
    args.p_SymGetLineFromAddr64 = p_SymGetLineFromAddr64;
    args.proc                   = proc;
    print_one_address (&args, addr);
  }

resume_thread:
  ResumeThread (thr);

close_thread:
  CloseHandle (thr);

sym_cleanup:
  (*p_SymCleanup) (proc);

quit:
  unload_dynamic_table (funcs, DIM(funcs));
  return (0);
}

static void init (void)
{
  char *end;

  GetModuleFileName (NULL, our_module, sizeof(our_module));

  if (prog_dir[0])
     return;

  /* In case wsock_trace_init() wasn't called.
   * This is important only for the return value of 'shorten_path()'.
   */
  end = strrchr (our_module, '\0');
  if (!strnicmp(end-4,".exe",4))
  {
    end = strrchr (our_module, '\\');   /* Ensure 'prog_dir' has a trailing '\\' */
    strncpy (prog_dir, our_module, end-our_module+1);
  }
}

void vm_bug_list (int skip_frames, void *list)
{
  thread_args arg;
  HANDLE      th;
  DWORD       tid;

  init();

  arg.list          = list;    /* \todo: A user defined 'smartlist_t' array to fill */
  arg.tid           = GetCurrentThreadId();
  arg.skip_frames   = skip_frames;
  arg.max_recursion = INT_MAX;
  arg.max_frames    = INT_MAX;

  th = CreateThread (NULL, 0, dump_thread, &arg, 0, &tid);
  if (th != INVALID_HANDLE_VALUE)
  {
    WaitForSingleObject (th, INFINITE);
    if (vm_bug_debug >= 2)
       print_thread_times (th);
    CloseHandle (th);
  }
  else
    TRACE (1, "CreateThread() failed: %s.\n", win_strerror(GetLastError()));

#if 0
  if (!arg.list)
  {
    puts ("");
    fflush (stdout);
  }
#endif
}

void vm_bug_report (void)
{
  vm_bug_list (0, NULL);
}

static void MS_CDECL abort_handler (int sig)
{
  fflush (stderr);

#if 0
  vm_bug_list (4, NULL);   /* First traced function should become raise() in the CRT */
#else
  vm_bug_list (10, NULL);  /* First traced function should become the function with assert(FALSE) */
#endif

  fflush (stdout);

  if (orig_abort_handler != SIG_DFL)
    (*orig_abort_handler) (sig);

  exit (-1);
}

void vm_bug_abort_init (void)
{
  if (orig_abort_handler == SIG_DFL && !IsDebuggerPresent())
  {
    orig_abort_handler = signal (SIGABRT, abort_handler);
#if defined(_MSC_VER)
    _set_abort_behavior (0, _WRITE_ABORT_MSG);
#endif
  }
}
