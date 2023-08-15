/** \file    backtrace.c
 *  \ingroup Misc
 *
 *  \brief
 *    Another stack-walker implementation for Win32 (MSVC, clang-cl and MinGW).
 *    Will completely replace the functions in stkwalk.c when finished in
 *    the hope that this one works better for *all* Windows targets.
 *    Will also replace `get_caller()` in wsock_trace.c.
 */
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <signal.h>
#include <windows.h>

#include "common.h"
#include "init.h"
#include "getopt.h"
#include "stkwalk.h"
#include "vm_dump.h"

#define USE_STRDUP2 1

/*
 * From 'man backtrace':
 *
 * SYNOPSIS
 *  #include <execinfo.h>
 *
 *  int backtrace (void **buffer, int size);
 *
 *  char **backtrace_symbols (void *const *buffer, int size);
 */

/*
 * In ntdll.dll
 */
typedef USHORT (WINAPI *func_RtlCaptureStackBackTrace) (ULONG  frames_to_skip,
                                                        ULONG  frames_to_capture,
                                                        void **frames,
                                                        ULONG *trace_hash);

static func_RtlCaptureStackBackTrace p_RtlCaptureStackBackTrace = NULL;

static HANDLE g_ntdll = INVALID_HANDLE_VALUE;
static char   g_module [_MAX_PATH];
static bool   g_use_sym_list = false;

static smartlist_t *modules_list = NULL;  /* A 'smartlist' of modules in our process. */
static smartlist_t *symbols_list = NULL;  /* A 'smartlist' of symbols in all modules. */

static char *strdup2 (const char *s1, const char *s2);
static char *search_symbols_list (ULONG_PTR addr);

#if defined(_MSC_VER) && !defined(__clang__)
  #pragma optimize("y", off)   /* Disable "elimination of frame pointer generation"; 'cl -Oy-' */
#endif

/**
 * Look at 'class CStackDumper' in VC's `atlmfc\include\atlutil.h`
 *
 * Especially how a new thread is used to dump a stack of a thread: \n
 *   `HRESULT DumpStack() throw()`
 */
static char *get_caller (int frame_num, int *err)
{
  static CONTEXT ctx;
  static void   *frames [20];
  static USHORT  num_frames;

  HANDLE    thr;
  ULONG_PTR ret_addr;

  *err = 0;
  if (!p_RtlCaptureStackBackTrace)
  {
    *err = 1;
    return ("RtlCaptureStackBackTrace() not found");
  }

  if (frame_num == 0)
  {
    memset (frames, '\0', sizeof(frames));
    num_frames = (*p_RtlCaptureStackBackTrace) (0, DIM(frames), frames, NULL);
    if (num_frames <= 1)
    {
      *err = 2;
      return ("No stack");
    }
  }
  else if (frame_num >= num_frames)
  {
    *err = 3;
    return ("frame not found");
  }

  thr = GetCurrentThread();

  ret_addr = (ULONG_PTR) frames [frame_num];

  /* The return-address is usually 5 bytes after the calling line.
   * E.g. 'call foo' decodes to 'E8 xx xx xx xx' (32-bit).
   *
   * So try to get the function-name, displacement and line of the calling
   * line. We're not so much interested in the 'return address'.
   */
  if (ret_addr)
     ret_addr -= 1 + sizeof(void*);

  if (frame_num == 0)
  {
   /* We don't need a CONTEXT_FULL; only EIP (or RIP for x64).
    */
    memset (&ctx, '\0', sizeof(ctx));
  }

  REG_EIP (&ctx) = ret_addr;

  if (g_use_sym_list)
  {
#if USE_STRDUP2
    char *rc2 = StackWalkShow (thr, &ctx);
    char *rc1 = search_symbols_list (ret_addr);
    return strdup2 (rc1, rc2);
#else
    return search_symbols_list (ret_addr);
#endif
  }
  return StackWalkShow (thr, &ctx);
}

static bool long_CPP_syms (void)
{
#if defined(_MSC_VER) && defined(_MT)
  return (true);
#else
  return (false);
#endif
}

/**
 * Print symbols in our module; symbols with `se->module` matching `g_module`.\n
 * Or print all.
 */
static void print_symbols (const smartlist_t *sl, bool print_all)
{
  int i, max = smartlist_len (sl);
  const char *short_fmt = "%-50.50s ";
  const char *long_fmt  = "%-140.140s ";
  const char *name_fmt  = (long_CPP_syms() ? long_fmt : short_fmt);

  printf ("Symbols-list (%d):\n"
          "  idx:   Module               Addr%*s      Symbol                                              line ofs file\n",
          max, 1+8*IS_WIN64, "");

  for (i = 0; i < max; i++)
  {
    const struct SymbolEntry *se = smartlist_get (sl, i);
    bool is_ours = (stricmp(se->module, g_module) == 0);

    if (print_all || is_ours)
    {
      printf ("  %5d: %-20.20s 0x%" ADDR_FMT " ", i, basename(se->module), ADDR_CAST(se->addr));
      printf (is_ours && long_CPP_syms() ? long_fmt : short_fmt, se->func_name);
      printf ("%5u %3u %s\n", se->line_number, se->ofs_from_line, se->file_name);
    }
  }
  if (i == 0)
     puts ("No symbols.");
  ARGSUSED (name_fmt);
}

int backtrace_init (void)
{
  int rc = 0;

  if (g_ntdll == INVALID_HANDLE_VALUE)
     g_ntdll = LoadLibrary ("ntdll.dll");

  GetModuleFileName (NULL, g_module, sizeof(g_module));

  if (g_ntdll)
     p_RtlCaptureStackBackTrace = (func_RtlCaptureStackBackTrace)
                                    GetProcAddress (g_ntdll, "RtlCaptureStackBackTrace");
  if (g_use_sym_list)
  {
    StackWalkSymbols (&symbols_list);
    if (g_cfg.trace_level >= 2)
       print_symbols (symbols_list, g_cfg.trace_level >= 3);
  }
  return (rc);
}

int backtrace_exit (void)
{
  /* The 'smartlist_t*' and their contents are freed in stkwalk.c
   */
  symbols_list = modules_list = NULL;
  if (g_ntdll && g_ntdll != INVALID_HANDLE_VALUE)
     FreeLibrary (g_ntdll);
  g_ntdll = INVALID_HANDLE_VALUE;
  return (1);
}

static char *strdup2 (const char *s1, const char *s2)
{
  size_t len1  = strlen (s1);
  size_t len2  = strlen (s2);
  char  *s     = malloc (len1+3+len2+1);
  char  *start = s;

  strcpy (s, s1);
  s += strlen (s1);
  *s++ = ' ';
  *s++ = '-';
  *s++ = ' ';
  strcpy (s, s2);
  return (start);
}

/**
 * smartlist_bsearch() helper: return -1, 1, or 0 based on comparison of
 * a 'struct SymbolEntry'.
 */
static int compare_addr (const void *key, const void **member)
{
  const struct SymbolEntry *se = *member;
  ULONG_PTR    addr = *(ULONG_PTR*) key;

  if (addr < se->addr)
     return (-1);
  if (addr > se->addr)
     return (1);
  return (0);
}

/**
 * Search `symbols_list` for a symbol with a near match to `addr`.\n
 * Return it's `func_name` with displacement.
 */
static char *search_symbols_list (ULONG_PTR addr)
{
  static char buf [400];
  const struct SymbolEntry *se = NULL;
  char *ret = "";
  char  mod [40] = { '\0' };
  char  displacement [20];
  char  file_line [_MAX_PATH+10] = { '\0' };
  int   diff = 0;
  int   found = 0, idx;

  idx = smartlist_bsearch_idx (symbols_list, &addr, compare_addr, &found);

  /* An exact match
   */
  if (found)
  {
    se  = smartlist_get (symbols_list, idx);
    ret = se->func_name;
  }
  else if (idx > 0) /* nearest match is 'SymbolEntry' below 'idx' */
  {
    se   = smartlist_get (symbols_list, idx-1);
    ret  = se->func_name;
    diff = (int) (addr - se->addr);
  }

  if (diff)
  {
    displacement[0] = '+';
    _itoa (diff, displacement+1, 10);
  }
  else
    displacement[0] = '\0';

  if (se)
  {
    if (stricmp(se->module, g_module))
       snprintf (mod, sizeof(mod), "%s!", se->module);
    if (se->file_name)
    {
      snprintf (file_line, sizeof(file_line), "  %s (%u, %u)",
                se->file_name, se->line_number, se->ofs_from_line);
      if (diff != 0)
         strcat (file_line, ". not excact");
    }
  }

  snprintf (buf, sizeof(buf), "%" ADDR_FMT " %s%s%s%s",
            ADDR_CAST(addr), mod, ret, displacement, file_line);
  return (buf);
}

/*
 * Test-code for this module called from 'ws_tool.c'
 */
static int threaded        = 0;
static int test_vm_bug     = 0;
static int test_vm_abort   = 0;
static int test_VM_ASSERT  = 0;
static int test_inv_parameter_handler = 0;
static int recursion_depth = 0;

struct thread_arg {
       unsigned line;
       int      depth;
     };

/*
 * gcc / clang-cl may optimize some of the 'foo_x()' function into one!
 * Try to prevent that.
 * Or use '_Pragma (clang optimize off)' for clang.
 */
#if defined(__clang__)
  #define OPT_OFF()   __attribute__((optnone))
#elif defined(__GNUC__)
  #define OPT_OFF()   __attribute__((optimize("0")))
#else
  #define OPT_OFF()
#endif

#define FOO_FUNC(_this, _next)                                    \
        OPT_OFF()                                                 \
        DWORD WINAPI foo_##_this (void *a)                        \
        {                                                         \
          struct thread_arg args = *(struct thread_arg*) a;       \
                                                                  \
          C_printf ("%s() called from line %u.\n",                \
                        __FUNCTION__, args.line);                 \
          args.line = __LINE__; /* since this macro is 1 line! */ \
          foo_##_next (&args);                                    \
          return (0);                                             \
        }

DWORD WINAPI foo_last (void *arg)
{
  struct thread_arg ta = *(struct thread_arg*) arg;
  char  *rc;
  int    i, err;

  C_printf ("%s() called from line %u.\n", __FUNCTION__, ta.line);

  if (test_vm_bug)
  {
    vm_bug_list (0, NULL);
    return (0);
  }

  /* Ignore the return-value of the 1st stack-fram since it should simply be 'get_caller+X'.
   * The 'frame_num == 0' is just to initialise the 'frames[]' in 'RtlCaptureStackBackTrace()'.
   */
  rc = get_caller (0, &err);

#if USE_STRDUP2
  if (g_use_sym_list && err == 0)
     free (rc);
#endif

  C_puts ("Call-stack:\n");
  fflush (stdout);

  for (i = 1; i < 12; i++)
  {
    rc = get_caller (i, &err);
    C_printf ("  %s\n", rc);
#if USE_STRDUP2
    if (g_use_sym_list && err == 0)
       free (rc);
#endif
  }
  return (0);
}

FOO_FUNC (15, last)
FOO_FUNC (14, 15)
FOO_FUNC (13, 14)
FOO_FUNC (12, 13)
FOO_FUNC (11, 12)
FOO_FUNC (10, 11)
FOO_FUNC (9, 10)
FOO_FUNC (8, 9)
FOO_FUNC (7, 8)
FOO_FUNC (6, 7)
FOO_FUNC (5, 6)
FOO_FUNC (4, 5)
FOO_FUNC (3, 4)
FOO_FUNC (2, 3)
FOO_FUNC (1, 2)

DWORD WINAPI foo_first (void *arg)
{
  struct thread_arg ta = *(struct thread_arg*) arg;

  C_printf ("%s() called from line %u.\n", __FUNCTION__, ta.line);

  if (ta.depth < recursion_depth)
  {
    ta.depth++;
    ta.line = __LINE__ + 1;
    foo_first (&ta);
  }
  else
  {
    ta.line = __LINE__ + 1;
    foo_1 (&ta);
  }
  return (0);
}

static int show_help (void)
{
  printf ("Usage: %s [-aAbistv] [-r <depth>]\n"
          "       -a:   test vm_bug_abort_handler().\n"
          "       -A:   test VM_ASSERT().\n"
          "       -b:   test vm_bug_list().\n"
          "       -i:   test invalid-parameter trapping.\n"
          "       -s:   test symbol-list and not 'StackWalkShow()'.\n"
          "       -t:   run threaded test.\n"
          "       -v:   sets 'vm_bug_debug' value. Will also show all frames.\n"
          "       -r #: sets 'foo_first()' recursion-level.\n", g_data.program_name);
  return (0);
}

static void test_unwind_fooX (void)
{
  struct thread_arg ta;

  ta.depth = 0;

  if (threaded)
  {
    DWORD  t_id;
    HANDLE t_hnd;

    ta.line = __LINE__ + 1;
    t_hnd = CreateThread (NULL, 0, foo_first, &ta, 0, &t_id);
    if (t_hnd != INVALID_HANDLE_VALUE)
    {
      WaitForSingleObject (t_hnd, INFINITE);
      CloseHandle (t_hnd);
    }
  }
  else
  {
    ta.line  = __LINE__ + 1;
    foo_first (&ta);
  }
}

#if (defined(_MSC_VER) || (__MSVCRT_VERSION__ >= 0x800) || defined(__MINGW64_VERSION_MAJOR)) && !defined(__CYGWIN__)
#define HAVE_INVALID_HANDLER 1

static DWORD old_err_mode;

#if defined(_DEBUG) || defined(__MINGW64_VERSION_MAJOR)
/*
 * In case it's MinGW-w64, include this here.
 */
#include <crtdbg.h>

/*
 * Temporarily disable asserts just for the current thread.
 */
static int crt_dbg_report_handler (int report_type, char *message, int *ret_val)
{
  if (report_type != _CRT_ASSERT)
     return (FALSE);

  if (ret_val)
     *ret_val = 0;

  /* Returning TRUE prevents real _CrtDbgReport() handler to
   * show the Dialogbox with the error details.
   */
  return (TRUE);
}
#endif

static void __cdecl invalid_parameter_handler (const wchar_t *expression,
                                               const wchar_t *function,
                                               const wchar_t *file,
                                               unsigned int   line,
                                               uintptr_t      dummy)
{
#if defined(_DEBUG)
  const char *comment = "";
#else
  const char *comment = ", expecting no sensible parameters";
#endif

  fprintf (vm_bug_stream,
           "invalid_parameter_handler() invoked%s:\n"
           "  expression: %" WCHAR_FMT "\n"
           "  function:   %" WCHAR_FMT "\n"
           "  file:       %" WCHAR_FMT "\n"
           "  line:       %u)\n",
           comment, expression, function, file, line);

  _set_invalid_parameter_handler (NULL);
  SetErrorMode (old_err_mode);

  fprintf (vm_bug_stream, "Call-stack:\n");

  /* Raise the signal for SIGABRT to cause the call-stack to be printed.
   * This also exists the program.
   */
  raise (SIGABRT);
  (void) dummy;
}

static void setup_handlers (void)
{
  /* Setup the signal-handler for SIGABRT
   */
  vm_bug_abort_init();

  /*
   * Let all 'vm_dump.c' print-outs go to 'stderr' with an indent of 2.
   * Like this:
   *
   *   invalid_parameter_handler() invoked:
   *     expression: stream != nullptr
   *     function:   _fwrite_internal
   *     file:       minkernel\crts\ucrt\src\appcrt\stdio\fwrite.cpp
   *     line:       35)
   *   Call-stack:
   *     0x00DE8F89: ws_tool.exe     (backtrace_main+585)  backtrace.c(641)  << fwrite() to NULL
   *     0x00DEDD74: ws_tool.exe     (run_sub_command+132)  ws_tool.c(77)
   *     0x00DEDEF9: ws_tool.exe     (main+249)  ws_tool.c(142)
   *     0x00DFAF7E: ws_tool.exe     (invoke_main+46)  d:/a01/_work/38/s/src/vctools/crt/vcstartup/src/startup/exe_common.inl(78)
   *     0x00DFAE52: ws_tool.exe     (__scrt_common_main_seh+338)  d:/a01/_work/38/s/src/vctools/crt/vcstartup/src/startup/exe_common.inl(2
   *     88)
   *     0x00DFACF8: ws_tool.exe     (__scrt_common_main+8)  d:/a01/_work/38/s/src/vctools/crt/vcstartup/src/startup/exe_common.inl(330)
   *     0x00DFAFE3: ws_tool.exe     (mainCRTStartup+3)  d:/a01/_work/38/s/src/vctools/crt/vcstartup/src/startup/exe_main.cpp(16)
   *     0x76EEFA24: c:/Windows/System32/kernel32.dll (BaseThreadInitThunk+20)
   *     0x77E57A79: c:/Windows/System32/ntdll.dll (__RtlUserThreadStart+42)
   */
  vm_bug_stream = stderr;
  vm_bug_indent = 2;

#if !defined(__CYGWIN__)
  setvbuf (vm_bug_stream, NULL, _IONBF, 0);
#endif

  old_err_mode = SetErrorMode (SEM_FAILCRITICALERRORS);
  _set_invalid_parameter_handler (invalid_parameter_handler);

  /* Also need to setup our CRT-debug report handler.
   */
#if defined(_DEBUG) || defined(__MINGW64_VERSION_MAJOR)
  _CrtSetReportHook (crt_dbg_report_handler);
#endif
}
#endif

int backtrace_main (int argc, char **argv)
{
  int c;

  set_program_name (argv[0]);

  while ((c = getopt (argc, argv, "aAbitvsr:h?")) != EOF)
    switch (c)
    {
      case 'a':
           test_vm_abort = 1;
           break;
      case 'A':
           test_VM_ASSERT = 1;
           break;
      case 'b':
           test_vm_bug = 1;
           break;
      case 'i':
           test_inv_parameter_handler = 1;
           break;
      case 't':
           threaded = 1;
           break;
      case 'v':
           vm_bug_debug++;
           break;
      case 's':
           g_use_sym_list = true;
           break;
      case 'r':
           recursion_depth = atoi (optarg);
           break;
      case '?':
      case 'h':
           show_help();
           return (0);
    }

  argc -= optind;
  argv += optind;

#if !defined(__CYGWIN__)
  setvbuf (stdout, NULL, _IONBF, 0);
#endif

  if (test_vm_abort)
  {
    smartlist_t *sl;

    g_cfg.trace_stream = stdout;

    vm_bug_abort_init();
    sl = smartlist_new();
    smartlist_free (sl);

    /* Access a smartlist after it's freed should trigger a SIGABRT.
     * But not with ASAN since it's "heap-use-after-free" handler will
     * kick in before this code:
     *   assert (sl->num_used > idx);
     * in smartlist.c.
     * Hence just call 'abort()' with USE_ASAN.
     */
#ifdef USE_ASAN
    abort();
#else
    smartlist_get (sl, 0);
    return (1);
#endif
  }

  if (test_VM_ASSERT)
  {
    VM_ASSERT (c == 'A');
    return (1);
  }

  if (test_inv_parameter_handler)
  {
#if defined(HAVE_INVALID_HANDLER)
    setup_handlers();

    /**
     * Writing to NULL triggers the MSVC invalid parameter handler inside `ftell()`:
     * ```
     *  0x69B11FF2: c:/Windows/System32/ucrtbased.dll (ftell+546)
     *  0x69B12616: c:/Windows/System32/ucrtbased.dll (fwrite+38)
     *  0x00EE8E8E: ws_tool.exe     (backtrace_main+590)  backtrace.c(552)
     *  0x00EEDCF4: ws_tool.exe     (run_sub_command+132)  ws_tool.c(77)
     *  0x00EEDE79: ws_tool.exe     (main+249)  ws_tool.c(142)
     * ```
     *
     * But sensible parameters for the handler is only present in `_DEBUG`-mode
     * which also triggers a Dialogbox unless we call `SetErrorMode()` and
     * `_CrtSetReportHook()`
     *
     * In _DEBUG-mode, the below results in this:
     * ```
     *   invalid_parameter_handler() invoked:
     *     expression: stream != nullptr
     *     function:   _fwrite_internal
     *     file:       minkernel\crts\ucrt\src\appcrt\stdio\fwrite.cpp [1]
     *     line:       35)
     *   Call-stack:
     *     0x00007FFC7A10D13B: c:/Windows/System32/ntdll.dll (ZwWaitForSingleObject+11)
     *     0x00007FFC779A3065: c:/Windows/System32/KERNELBASE.dll (WaitForSingleObjectEx+133)
     *     0x00007FF797F60AA7: f:/gv/VC_project/ws_trace/src/ws_tool.exe (vm_bug_list+199)  f:/gv/VC_project/ws_trace/src/vm_dump.c(388)
     *     0x00007FF797F616A5: f:/gv/VC_project/ws_trace/src/ws_tool.exe (abort_handler+21)  f:/gv/VC_project/ws_trace/src/vm_dump.c(448)
     *     0x00007FFC367E90E4: c:/Windows/System32/ucrtbased.dll (raise+1124)
     *     0x00007FF797F78B70: f:/gv/VC_project/ws_trace/src/ws_tool.exe (invalid_parameter_handler+144)  f:/gv/VC_project/ws_trace/src/backtrace.c(507)
     *     0x00007FFC367E819D: c:/Windows/System32/ucrtbased.dll (_invalid_parameter+397)
     *     0x00007FFC367FD973: c:/Windows/System32/ucrtbased.dll (ftell+819)
     * ```
     *
     * \note [1]:
     *
     * The corresponding code in `fwrite.cpp (35)`: is <br>
     *  `_UCRT_VALIDATE_RETURN(ptd, stream != nullptr, EINVAL, 0);`
     *
     * (defined in `corecrt_internal_ptd_propagation.h`) which in my case expands to:
     * ```
     *  if (!(_Expr_val))
     *  {
     *    (ptd).get_errno().set ((22));
     *    _invalid_parameter_internal (L"stream != nullptr", L__FUNCTION__,
     *           L"f:/gv/WinKit/Source/10.0.22621.0/ucrt/stdio/fwrite.cpp", 35, 0, (ptd));
     *    return (0);
     *  }
     * ```
     *
     * These files should be part of your WinKit: <br>
     *   \li `$(WindowsSdkDir)/Source/$(WindowsSdkVer)/ucrt/stdio/fwrite.cpp`
     *   \li `$(WindowsSdkDir)/Source/$(WindowsSdkVer)/ucrt/inc/corecrt_internal_ptd_propagation.h`
     */
    fwrite ("hello world", 11, 1, NULL);

    fputs ("This compiler does not seems to trap 'invalid parameters'!\n", stderr);
#else
    fputs ("This compiler lacks support for the '-i' option\n", stderr);
#endif
    return (1);
  }

  g_cfg.trace_report = 0;

  backtrace_init();
  test_unwind_fooX();
  backtrace_exit();
  return (0);
}

