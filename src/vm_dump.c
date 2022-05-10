/**
 * \file vm_dump.c
 * \ingroup Misc
 *
 * \brief
 * A backtrace-like module. Currently only used from backtrace.c.
 *
 * Copyright (C) 2004-2007 Koichi Sasada
 *
 * Heavily modified version of the Ruby crash-handler at:
 *   https://github.com/ruby/ruby/blob/master/vm_dump.c
 */

#include <stdio.h>
#include <signal.h>
#include <process.h>
#include <windows.h>
#include <imagehlp.h>

#include "common.h"
#include "init.h"
#include "cpu.h"
#include "vm_dump.h"

int   vm_bug_debug  = 0;
int   vm_bug_indent = 0;
FILE *vm_bug_stream;

#define VM_BUG_INDENT   vm_bug_indent, ""

#undef  TRACE
#define TRACE(level, fmt, ...)                                        \
        do {                                                          \
          if (vm_bug_debug >= level) {                                \
            fprintf (vm_bug_stream, "%*s%s(%u): ", vm_bug_indent, "", \
                     __FILE__, __LINE__);                             \
            fprintf (vm_bug_stream, fmt, ## __VA_ARGS__);             \
          }                                                           \
        } while (0)

#ifndef SYMOPT_DEBUG
#define SYMOPT_DEBUG 0x80000000
#endif

#ifndef MAX_SYM_NAME
#define MAX_SYM_NAME 2000
#endif

#if defined(__GNUC__) && defined(__i386__)
  /*
   * Problems with 'gcc -O0'. Use this hack:
   */
  static inline void *_NtCurrentTeb (void)
  {
    return (void*) __readfsdword (0x18);
  }
  #define NtCurrentTeb() _NtCurrentTeb()
#endif

/**
 * \def DEF_WIN_FUNC
 *
 * Handy macro to both define and declare the function-pointer for
 * `dbghelp.dll`, `psapi.dll`, `tlhelp32.dll` and `kernel32.dll` functions.
 */
#define DEF_WIN_FUNC(ret, f, args)  typedef ret (WINAPI *func_##f) args; \
                                    static func_##f p_##f = NULL


DEF_WIN_FUNC (DWORD,   SymSetOptions, (IN DWORD options));

DEF_WIN_FUNC (BOOL,    SymInitialize, (IN HANDLE process,
                                       IN PCSTR  UserSearchPath,
                                       IN BOOL   invadeProcess));

DEF_WIN_FUNC (BOOL,    SymCleanup, (IN HANDLE process));

DEF_WIN_FUNC (DWORD64, SymGetModuleBase64, (IN HANDLE  process,
                                            IN DWORD64 addr));

DEF_WIN_FUNC (BOOL,    SymFromAddr, (IN     HANDLE       process,
                                     IN     DWORD64      addr,
                                     OUT    DWORD64     *displacement,
                                     IN OUT SYMBOL_INFO *Symbol));

DEF_WIN_FUNC (BOOL,    SymGetLineFromAddr64, (IN  HANDLE           process,
                                              IN  DWORD64          addr,
                                              OUT DWORD           *displacement,
                                              OUT IMAGEHLP_LINE64 *Line));

DEF_WIN_FUNC (BOOL,    StackWalk64, (IN     DWORD                            MachineType,
                                     IN     HANDLE                           process,
                                     IN     HANDLE                           thread,
                                     IN OUT STACKFRAME64                    *StackFrame,
                                     IN OUT VOID                            *ContextRecord,
                                     IN     PREAD_PROCESS_MEMORY_ROUTINE64   ReadMemoryRoutine,
                                     IN     PFUNCTION_TABLE_ACCESS_ROUTINE64 FunctionTableAccessRoutine,
                                     IN     PGET_MODULE_BASE_ROUTINE64       GetModuleBaseRoutine,
                                     IN     PTRANSLATE_ADDRESS_ROUTINE64     TranslateAddress));

#define ADD_VALUE(func)  { 0, NULL, "dbghelp.dll", #func, (void**)&p_##func }

static struct LoadTable sym_funcs[] = {
              ADD_VALUE (SymInitialize),
              ADD_VALUE (SymCleanup),
              ADD_VALUE (SymGetModuleBase64),
              ADD_VALUE (SymFromAddr),
              ADD_VALUE (SymGetLineFromAddr64),
              ADD_VALUE (SymSetOptions),
              ADD_VALUE (StackWalk64)
            };

typedef struct thread_args {
        DWORD   tid;
        HANDLE  proc;
        void   *list;
        int     max_frames;      /* How many addresses to trace */
        int     max_recursion;   /* How many recursive calls to trace */
        int     skip_frames;     /* How many initial frames NOT to trace */
      } thread_args;

static char our_module [_MAX_PATH];

static void (*orig_abort_handler)(int) = SIG_DFL;

/* For some `REG_BSP()` etc. macros.
 */
static uintptr_t dummy_reg = 0;

static NO_INLINE void print_one_address (thread_args *args, DWORD64 addr)
{
  SYMBOL_INFO    *info;
  char            buf [sizeof(*info) + MAX_SYM_NAME];
  DWORD64         base, displacement;
  IMAGEHLP_LINE64 line;
  DWORD           tmp;
  char            path [MAX_PATH] = { '\0' };

  /* Assume the module is MSVC/clang-cl compiled. Call 'p_SymFromAddr()'
   * and 'p_SymGetLineFromAddr64()' if this is the case. If the '<module>.pdb'
   * is present while running a MinGW compiled program, this just returns
   * wrong information from dbghelp.dll.
   */
  BOOL have_PDB_info = TRUE;

  fprintf (vm_bug_stream, "%*s0x%" ADDR_FMT ": ", vm_bug_indent, "", ADDR_CAST(addr));

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

  base = (*p_SymGetModuleBase64) (args->proc, addr);

  if (GetModuleFileName((HANDLE)(uintptr_t)base, path, sizeof(path)))
     fprintf (vm_bug_stream, "%-15s", shorten_path(path));

#if !defined(_MSC_VER)
  if (path[0] && !stricmp(our_module, path))
     have_PDB_info = FALSE;

  /* Otherwise the module can be a MSVC/clang-cl compiled module in a MinGW program.
   */
#endif

  if (have_PDB_info && (*p_SymFromAddr)(args->proc, addr, &displacement, info))
     fprintf (vm_bug_stream, " (%s+%lu)", info->Name, DWORD_CAST((DWORD)displacement));

  if (have_PDB_info)
  {
    memset (&line, 0, sizeof(line));
    line.SizeOfStruct = sizeof(line);
    if ((*p_SymGetLineFromAddr64)(args->proc, addr, &tmp, &line))
       fprintf (vm_bug_stream, "  %s(%lu)", shorten_path(line.FileName), DWORD_CAST(line.LineNumber));
  }
  else
  {
    fprintf (vm_bug_stream, " <No PDB>");
#if !defined(_MSC_VER)
     /* look in map_file_list */
#endif
  }
  fputc ('\n', vm_bug_stream);
}

static DWORD WINAPI dump_thread (void *arg)
{
  thread_args  args = *(thread_args*) arg;
  HANDLE       proc, thr = NULL;
  CONTEXT      context;
  STACKFRAME64 frame;
  int          save = g_cfg.trace_level;
  int          rec_count = 0;
  BOOL         okay;

#ifdef USE_ASAN
  /*
   * Using ASAN could insert some trampoline function.
   * Let us see their values.
   */
  g_cfg.trace_level = 4;
#endif

  okay = (load_dynamic_table(sym_funcs, DIM(sym_funcs)) == DIM(sym_funcs));
  g_cfg.trace_level = save;

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
    TRACE (1, "OpenThread() failed: %s.\n", win_strerror(GetLastError()));
    goto sym_cleanup;
  }

  if (SuspendThread(thr) == (DWORD)-1)
  {
    TRACE (1, "SuspendThread() failed: %s.\n", win_strerror(GetLastError()));
    goto close_thread;
  }

  memset (&context, 0, sizeof(context));
  context.ContextFlags = CONTEXT_FULL;
  if (!GetThreadContext(thr, &context))
  {
    TRACE (1, "GetThreadContext() failed: %s.\n", win_strerror(GetLastError()));
    goto resume_thread;
  }

  memset (&frame, 0, sizeof(frame));
  frame.AddrPC.Mode       = AddrModeFlat;
  frame.AddrFrame.Mode    = AddrModeFlat;
  frame.AddrStack.Mode    = AddrModeFlat;
  frame.AddrBStore.Mode   = AddrModeFlat;
  frame.AddrPC.Offset     = REG_EIP (&context);
  frame.AddrFrame.Offset  = REG_EBP (&context);
  frame.AddrStack.Offset  = REG_ESP (&context);
  frame.AddrBStore.Offset = REG_BSP (&context);

  while ((*p_StackWalk64)(WS_TRACE_IMAGE_TYPE, proc, thr, &frame, &context, NULL, NULL, NULL, NULL))
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
      DWORD stk_len;

      /* 'length' = 'base - limit' since the stack grows towards a lower address.
       */
      stk_len = (DWORD) ((DWORD_PTR)tib->StackBase - (DWORD_PTR)tib->StackLimit);

      /* The base and limit (2MByte) of the thread-stack should be constant
       * throughout it's life-time. But print it anyway on each iteration.
       * How do we check if the base/limit was changed?
       * And what bad could happen then?
       */
      TRACE (3, "stack-base:  0x%p\n"
                "%*s                stack-limit: 0x%p (%s bytes)\n",
             tib->StackBase,
             vm_bug_indent, "", tib->StackLimit, dword_str(stk_len));
    }

    if (recursion || addr == 0 || frame.AddrReturn.Offset == 0)
    {
      TRACE (2, "addr:                    0x%" ADDR_FMT " %s%s\n"
                "%*s                frame.AddrPC.Offset:     0x%" ADDR_FMT "\n"
                "%*s                frame.AddrReturn.Offset: 0x%" ADDR_FMT ".\n",
             ADDR_CAST(addr),
             recursion ? "recursion" : "",
             recursion ? rec_buf     : "",
             vm_bug_indent, "", ADDR_CAST(frame.AddrPC.Offset),
             vm_bug_indent, "", ADDR_CAST(frame.AddrReturn.Offset));

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
    args.proc = proc;
    print_one_address (&args, addr);
  }

resume_thread:
  ResumeThread (thr);

close_thread:
  CloseHandle (thr);

sym_cleanup:
  (*p_SymCleanup) (proc);

quit:
  unload_dynamic_table (sym_funcs, DIM(sym_funcs));
  return (0);
}

static void init (void)
{
  char *end;

  if (!vm_bug_stream)
     vm_bug_stream = stdout;

  GetModuleFileName (NULL, our_module, sizeof(our_module));

  if (prog_dir[0])
     return;

  /* In case wsock_trace_init() wasn't called.
   * This is important only for the return value of 'shorten_path()'.
   */
  end = strrchr (our_module, '\0');
  if (!strnicmp(end-4, ".exe", 4))
  {
    end = strrchr (our_module, '\\');   /* Ensure 'prog_dir' has a trailing '\\' */
    strncpy (prog_dir, our_module, end-our_module+1);
  }
}

void vm_bug_list (int skip_frames, void *list)
{
  thread_args arg;
  HANDLE      th;
  DWORD       tid, flags;

  init();

  /**\todo: 'list' is a user defined 'smartlist_t' array to fill.
   */
  arg.list          = list;
  arg.tid           = GetCurrentThreadId();
  arg.skip_frames   = skip_frames;
  arg.max_recursion = INT_MAX;
  arg.max_frames    = INT_MAX;

  /* 16kByte seems to be the minimum stack-size on Windows-10.
   * Whatever the crappy pages at 'https://docs.microsoft.com' says.
   *
   * And  without the 'STACK_SIZE_PARAM_IS_A_RESERVATION' flag, the
   * given stack-size is the *commit* size of the stack. Not the reserve
   * size.
   *
   * Ref:
   *   https://bugzilla.mozilla.org/show_bug.cgi?id=958796
   */
  flags = STACK_SIZE_PARAM_IS_A_RESERVATION;
  th = CreateThread (NULL, 4*1024, dump_thread, &arg, flags, &tid);
  if (th != INVALID_HANDLE_VALUE)
  {
    WaitForSingleObject (th, INFINITE);
    if (vm_bug_debug >= 2)
    {
      FILE *save = g_cfg.trace_stream;

      g_cfg.trace_stream = vm_bug_stream;
      print_thread_times (th);
      g_cfg.trace_stream = save;
    }
    CloseHandle (th);
  }
  else
    TRACE (1, "CreateThread() failed: %s.\n", win_strerror(GetLastError()));

#if 0
  if (!arg.list)
  {
    fputs ("\n", vm_bug_stream);
    fflush (vm_bug_stream);
  }
#endif
}

void vm_bug_report (void)
{
  vm_bug_list (0, NULL);
}

static void abort_handler (int sig)
{
  /*
   * For MSVC / clang-cl, all frames should look like this for a
   * `ws_tool.exe backtrace -a` command:
   *   Frame Address     Module (Function + displacement) etc.
   *   --------------------------------------------------------------------------------------------------
   *   0     0x77E629D7: c:/Windows/System32/ntdll.dll (NtWaitForSingleObject+7)
   *   1     0x77AF1F44: c:/Windows/System32/KERNELBASE.dll (WaitForSingleObjectEx+148)
   *   2     0x77AF1E9D: c:/Windows/System32/KERNELBASE.dll (WaitForSingleObject+13)
   *   3     0x008E73B3: ws_tool.exe     (vm_bug_list+99)  vm_dump.c(386)
   *   4     0x008E7AEC: ws_tool.exe     (abort_handler+28)  vm_dump.c(415)
   *   5     0x7713D8CA: c:/Windows/System32/ucrtbase.dll (raise+442)
   *   6     0x7713EDBD: c:/Windows/System32/ucrtbase.dll (abort+45)
   *   7     0x77140989: c:/Windows/System32/ucrtbase.dll (common_assert_to_stderr_direct+152)
   *   8     0x771408AB: c:/Windows/System32/ucrtbase.dll (common_assert_to_stderr<wchar_t>+15)
   *   9     0x7713FE2D: c:/Windows/System32/ucrtbase.dll (common_assert<wchar_t>+65)
   * > 10    0x771409E1: c:/Windows/System32/ucrtbase.dll (_wassert+17)             !! we want to start decoding frames from this point
   *   11    0x00BA43AA: ws_tool.exe     (smartlist_get+90)  smartlist.c(207)
   *   12    0x00BB7F5C: ws_tool.exe     (backtrace_main+316)  backtrace.c(488)
   *   13    0x00BBB83E: ws_tool.exe     (run_sub_command+94)  ws_tool.c(77)
   *   14    0x00BBB968: ws_tool.exe     (main+232)  ws_tool.c(142)
   *   15    0x00BC62D3: ws_tool.exe     (__scrt_common_main_seh+245)  d:/a01/_work/38/s/src/vctools/crt/vcstartup/src/startup/exe_common.inl(288)
   *   16    0x76EEFA24: c:/Windows/System32/kernel32.dll (BaseThreadInitThunk+20)
   *   17    0x77E57A79: c:/Windows/System32/ntdll.dll (__RtlUserThreadStart+42)
   */
  vm_bug_list (10, NULL);  /* First traced function should become the function with assert(FALSE) */

  fflush (vm_bug_stream);

  if (orig_abort_handler != SIG_DFL)
    (*orig_abort_handler) (sig);

  wsock_trace_exit();
  crtdbg_exit();
  exit (-1);
}

void vm_bug_abort_init (void)
{
  vm_bug_stream = stdout;

  if (orig_abort_handler == SIG_DFL && !IsDebuggerPresent())
  {
    orig_abort_handler = signal (SIGABRT, abort_handler);
#if defined(_MSC_VER)
    _set_abort_behavior (0, _WRITE_ABORT_MSG);
#endif
  }
}
