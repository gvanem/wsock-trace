//
// Copyright (c) 2007-2008, Marton Anka
//
// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the "Software"),
// to deal in the Software without restriction, including without limitation
// the rights to use, copy, modify, merge, publish, distribute, sublicense,
// and/or sell copies of the Software, and to permit persons to whom the
// Software is furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included
// in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
// OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
// THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
// FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
// IN THE SOFTWARE.

#include "disasm.h"
#include "mhook.h"
#include <winternl.h>

//
// Defined in newer <sal.h> for MSVC.
//
#ifndef _Printf_format_string_
#define _Printf_format_string_
#endif

#undef TRACE

#if defined(USE_TRACE)
  #define TRACE_COLOUR_TIME      (0x0008 | 5)  /* bright magenta */
  #define TRACE_COLOUR_FILELINE  (0x0008 | 2)  /* bright green */
  #define TRACE_COLOUR_ARGS      (0x0008 | 7)  /* bright white */

  #define TRACE(fmt, ...)                                                            \
          do {                                                                       \
            if (mhook_trace_level() > 0) {                                           \
               EnterCriticalSection (&trace_crit);                                   \
               mhook_printf (TRACE_COLOUR_TIME, "%.3lf ", mhook_diff_time());        \
               mhook_printf (TRACE_COLOUR_FILELINE, "%s(%u): ", __FILE__, __LINE__); \
               mhook_printf (TRACE_COLOUR_ARGS, fmt "\n", ## __VA_ARGS__);           \
               LeaveCriticalSection (&trace_crit);                                   \
            }                                                                        \
          } while (0)

  static CONSOLE_SCREEN_BUFFER_INFO console_info;
  static HANDLE                     stdout_hnd;
  static CRITICAL_SECTION           trace_crit;

  static void   mhook_printf (int color, _Printf_format_string_ const char *fmt, ...);
  static int    mhook_trace_level (void);
  static double mhook_diff_time (void);

#elif defined(USE_DBG_TRACE)
  #define TRACE(fmt, ...) mhook_printf (fmt, ## __VA_ARGS__)

  static void mhook_printf (_Printf_format_string_ const char *format, ...)
  {
    char buf[1000];
    va_list args;
    va_start (args, format);
    int len = _vsnprintf (buf, sizeof(buf)-3, format, args);

    if (len > 0)
    {
      buf[len++] = '\r';
      buf[len++] = '\n';
      buf[len] = '\0';
      OutputDebugStringA (buf);
    }
    va_end (args);
  }
#else
  #define TRACE(fmt, ...)   ((void)0)
#endif

#ifndef DIM
#define DIM(x)        (int) (sizeof(x) / sizeof((x)[0]))
#endif

#ifndef DISASM_FLAGS
#define DISASM_FLAGS  (DISASM_DECODE | DISASM_DISASSEMBLE | DISASM_ALIGNOUTPUT)
#endif

#define MHOOKS_MAX_CODE_BYTES   32
#define MHOOKS_MAX_RIPS          4

#if defined(_M_IX86)
  static ARCHITECTURE_TYPE  g_arch = ARCH_X86;
#elif defined(_M_IA64) || defined(_M_AMD64)
  static ARCHITECTURE_TYPE  g_arch = ARCH_X64;
#else
  #error "Unsupported CPU"
#endif

//
// The trampoline structure - stores every bit of info about a hook
//
typedef struct MHOOKS_TRAMPOLINE {
        BYTE  *system_function;                                     // the original system function
        DWORD  overwritten_code;                                    // number of bytes overwritten by the jump
        BYTE  *hook_function;                                       // the hook function that we provide
        BYTE   code_jump_to_hook_function [MHOOKS_MAX_CODE_BYTES];  // placeholder for code that jumps to the hook function
        BYTE   code_trampoline [MHOOKS_MAX_CODE_BYTES];             // placeholder for code that holds the first few
                                                                    // bytes from the system function and a jump to the remainder
                                                                    // in the original location
        BYTE   code_untouched [MHOOKS_MAX_CODE_BYTES];              // placeholder for unmodified original code
                                                                    // (we patch IP-relative addressing)
        struct MHOOKS_TRAMPOLINE *prev_trampoline;                  // When in the free list, these are pointers to the prev and next entry.
        struct MHOOKS_TRAMPOLINE *next_trampoline;                  // When not in the free list, these are pointers to the prev and next trampoline in use.
      } MHOOKS_TRAMPOLINE;

//
// The patch data structures - store info about rip-relative instructions
// during hook placement
//
typedef struct {
        DWORD   offset;
        int64_t displacement;
      } MHOOKS_RIPINFO;

typedef struct {
        int64_t         limit_up;
        int64_t         limit_down;
        DWORD           rip_count;
        MHOOKS_RIPINFO  rips [MHOOKS_MAX_RIPS];
      } MHOOKS_PATCHDATA;

//
// Hook context contains info about one hook
//
typedef struct {
        void              *system_function;
        void              *hook_function;
        DWORD              instruction_length;
        MHOOKS_TRAMPOLINE *trampoline;
        MHOOKS_PATCHDATA   patch_data;
        BOOL               need_patch_jump;
        BOOL               need_patch_call;
      } HOOK_CONTEXT;

//
// Module global vars
//
static BOOL               g_initialized = FALSE;
static CRITICAL_SECTION   g_crit;
static MHOOKS_TRAMPOLINE *g_hooks = NULL;
static MHOOKS_TRAMPOLINE *g_free_list = NULL;
static HANDLE            *g_thread_handles = NULL;
static DWORD              g_num_thread_handles = 0;

#define MHOOK_JMPSIZE          5
#define MHOOK_MIN_ALLOCSIZE 4096

//
// A private more detailed version of
// 'SYSTEM_PROCESS_INFORMATION'
//
#define SYSTEM_PROCESS_INFORMATION   SYSTEM_PROCESS_INFORMATION_priv

typedef struct SYSTEM_PROCESS_INFORMATION {
        ULONG          NextEntryOffset;
        ULONG          NumberOfThreads;
        LARGE_INTEGER  WorkingSetPrivateSize;         // since VISTA
        ULONG          HardFaultCount;                // since WIN7
        ULONG          NumberOfThreadsHighWatermark;  // since WIN7
        ULONGLONG      CycleTime;                     // since WIN7
        LARGE_INTEGER  CreateTime;
        LARGE_INTEGER  UserTime;
        LARGE_INTEGER  KernelTime;
        UNICODE_STRING ImageName;
        KPRIORITY      BasePriority;
        HANDLE         UniqueProcessId;
        HANDLE         InheritedFromUniqueProcessId;
        ULONG          HandleCount;
        ULONG          SessionId;
        ULONG_PTR      UniqueProcessKey;   // since VISTA (requires SystemExtendedProcessInformation)
        SIZE_T         PeakVirtualSize;
        SIZE_T         VirtualSize;
        ULONG          PageFaultCount;
        SIZE_T         PeakWorkingSetSize;
        SIZE_T         WorkingSetSize;
        SIZE_T         QuotaPeakPagedPoolUsage;
        SIZE_T         QuotaPagedPoolUsage;
        SIZE_T         QuotaPeakNonPagedPoolUsage;
        SIZE_T         QuotaNonPagedPoolUsage;
        SIZE_T         PagefileUsage;
        SIZE_T         PeakPagefileUsage;
        SIZE_T         PrivatePageCount;
        LARGE_INTEGER  ReadOperationCount;
        LARGE_INTEGER  WriteOperationCount;
        LARGE_INTEGER  OtherOperationCount;
        LARGE_INTEGER  ReadTransferCount;
        LARGE_INTEGER  WriteTransferCount;
        LARGE_INTEGER  OtherTransferCount;
        SYSTEM_THREAD_INFORMATION Threads [1];
      } SYSTEM_PROCESS_INFORMATION;

//
// ZwQuerySystemInformation definitions
//
typedef NTSTATUS (NTAPI *func_ZwQuerySystemInformation) (
                         __in      SYSTEM_INFORMATION_CLASS system_information_class,
                         __inout   void                    *system_information,
                         __in      ULONG                    system_information_length,
                         __out_opt ULONG                   *return_length);

#ifndef STATUS_INFO_LENGTH_MISMATCH
#define STATUS_INFO_LENGTH_MISMATCH      ((NTSTATUS)0xC0000004L)
#endif

static func_ZwQuerySystemInformation p_ZwQuerySystemInformation = NULL;

//
// Internal function:
//
// Remove the trampoline from the specified list, updating the head pointer
// if necessary.
//
static void ListRemove (MHOOKS_TRAMPOLINE **listHead, MHOOKS_TRAMPOLINE *node)
{
  if (node->prev_trampoline)
     node->prev_trampoline->next_trampoline = node->next_trampoline;

  if (node->next_trampoline)
     node->next_trampoline->prev_trampoline = node->prev_trampoline;

  if (*listHead == node)
  {
    *listHead = node->next_trampoline;
    if (*listHead)
       assert ((*listHead)->prev_trampoline == NULL);
  }
  node->prev_trampoline = node->next_trampoline = NULL;
}

//
// Internal function:
//
// Prepend the trampoline from the specified list and update the head pointer.
//
static void ListPrepend (MHOOKS_TRAMPOLINE **listHead, MHOOKS_TRAMPOLINE *node)
{
  node->prev_trampoline = NULL;
  node->next_trampoline = *listHead;

  if (*listHead)
     (*listHead)->prev_trampoline = node;
  *listHead = node;
}

//
// Internal function:
//
// For iterating over the list
//
static MHOOKS_TRAMPOLINE *ListNext (MHOOKS_TRAMPOLINE *node)
{
  if (node && node->next_trampoline)
     return (node->next_trampoline);
  return (NULL);
}

static void EnterCritSec (void)
{
  if (!g_initialized)
  {
    InitializeCriticalSection (&g_crit);
    g_initialized = TRUE;
  }
  EnterCriticalSection (&g_crit);
}

static void LeaveCritSec (void)
{
  LeaveCriticalSection (&g_crit);
}

//
// Internal function:
//
// Skip over jumps that lead to the real function.
// Gets around import jump tables, etc.
//
static BYTE *SkipJumps (BYTE *code)
{
  BYTE *orig_code = code;

#ifdef _M_IX86
  //mov edi,edi: hot patch point
  if (code[0] == 0x8b && code[1] == 0xff)
     code += 2;

  // push ebp; mov ebp, esp; pop ebp;
  // "collapsed" stackframe generated by MSVC
  if (code[0] == 0x55 && code[1] == 0x8b && code[2] == 0xec && code[3] == 0x5d)
     code += 4;
#endif

  if (code[0] == 0xff && code[1] == 0x25)
  {
#ifdef _M_IX86
    // on x86 we have an absolute pointer...
    BYTE *target = *(BYTE**) &code[2];

    // ... that shows us an absolute pointer.
    return SkipJumps (*(BYTE**)target);
#else
    // on x64 we have a 32-bit offset...
    INT32 offset = *(INT32*) &code[2];

    // ... that shows us an absolute pointer
    return SkipJumps (*(BYTE**)(code + 6 + offset));
  }
  if (code[0] == 0x48 && code[1] == 0xff && code[2] == 0x25)
  {
    // or we can have the same with a REX prefix
    INT32 offset = *(INT32*) &code[3];

    // ... that shows us an absolute pointer
    return SkipJumps (*(BYTE**)(code + 7 + offset));
#endif
  }

  if (code[0] == 0xe9)
  {
    // here the behavior is identical, we have...
    // ...a 32-bit offset to the destination.
    return SkipJumps (code + 5 + *(INT32*)&code[1]);
  }
  if (code[0] == 0xeb)
  {
    // and finally an 8-bit offset to the destination
    return SkipJumps (code + 2 + *(CHAR*)&code[1]);
  }
  return (orig_code);
}

//
// Internal function:
//
// Writes code at 'code' that jumps to 'jump_to'. Will attempt to do this
// in as few bytes as possible. Important on x64 where the long jump
// (0xFF 0x25 ....) can take up 14 bytes.
//
static BYTE *EmitJump (BYTE *code, BYTE *jump_to)
{
  BYTE  *jump_from = code + 5;
  SIZE_T diff = jump_from > jump_to ? jump_from - jump_to : jump_to - jump_from;

  TRACE ("EmitJump: Jumping from %p to %p, diff is %p", jump_from, jump_to, diff);

  if (diff <= 0x7FFF0000)
  {
    code[0] = 0xE9;
    code += 1;
    *(DWORD*) code = (DWORD) (DWORD_PTR) (jump_to - jump_from);
    code += sizeof (DWORD);
  }
  else
  {
    code[0] = 0xFF;
    code[1] = 0x25;
    code += 2;

#ifdef _M_IX86
    // on x86 we write an absolute address (just behind the instruction)
    *(DWORD*) code = (DWORD) (DWORD_PTR) (code + sizeof(DWORD));
#else
    // on x64 we write the relative address of the same location
    *(DWORD*) code = 0;
#endif
    code += sizeof (DWORD);
    *(DWORD_PTR*) code = (DWORD_PTR) jump_to;
    code += sizeof (DWORD_PTR);
  }
  return (code);
}

//
// Internal function:
//
// Round down to the next multiple of 'round_down'
//
static size_t RoundDown (size_t addr, size_t round_down)
{
  return (addr / round_down) * round_down;
}

//
// Internal function:
//
// Will attempt allocate a block of memory within the specified range, as
// near as possible to the specified function.
//
static MHOOKS_TRAMPOLINE *BlockAlloc (BYTE *system_function, BYTE *lower, BYTE *upper)
{
  SYSTEM_INFO sys_info =  { 0 };

  GetSystemInfo (&sys_info);

  // Always allocate in bulk, in case the system actually has a smaller allocation granularity than 'MHOOK_MIN_ALLOCSIZE'.
  ptrdiff_t          alloc_size = MAX (sys_info.dwAllocationGranularity, MHOOK_MIN_ALLOCSIZE);
  MHOOKS_TRAMPOLINE *ret_val = NULL;
  BYTE              *module_guess = (BYTE*) RoundDown ((size_t)system_function, alloc_size);
  BYTE              *alloc;
  int                loopCount = 0;

  for (alloc = module_guess; lower < alloc && alloc < upper; ++loopCount)
  {
    // determine current state
    MEMORY_BASIC_INFORMATION mbi;
    ptrdiff_t    bytes_to_ofs;

    TRACE ("BlockAlloc: Looking at address %p", alloc);

    if (!VirtualQuery(alloc, &mbi, sizeof(mbi)))
       break;

    // free & large enough?
    if (mbi.State == MEM_FREE && mbi.RegionSize >= (unsigned)alloc_size)
    {
      // and then try to allocate it
      ret_val = VirtualAlloc (alloc, alloc_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

      if (ret_val)
      {
        size_t trampolineCount = alloc_size / sizeof(MHOOKS_TRAMPOLINE);

        TRACE ("BlockAlloc: Allocated block at %p as %d trampolines", ret_val, trampolineCount);
        ret_val[0].prev_trampoline = NULL;
        ret_val[0].next_trampoline = &ret_val[1];

        // prepare them by having them point down the line at the next entry.
        for (size_t s = 1; s < trampolineCount; ++s)
        {
          ret_val[s].prev_trampoline = &ret_val[s - 1];
          ret_val[s].next_trampoline = &ret_val[s + 1];
        }

        // last entry points to the current head of the free list
        ret_val [trampolineCount-1].next_trampoline = g_free_list;

        if (g_free_list)
           g_free_list->prev_trampoline = &ret_val [trampolineCount-1];
        break;
      }
    }

    // This is a spiral, should be -1, 1, -2, 2, -3, 3, etc. (* alloc_size)
    bytes_to_ofs = (alloc_size * (loopCount + 1) * ((loopCount % 2 == 0) ? -1 : 1) );
    alloc += bytes_to_ofs;
  }
  return (ret_val);
}

//
// Internal function:
//
// Will try to allocate a big block of memory inside the required range.
//
static MHOOKS_TRAMPOLINE *FindTrampolineInRange (const BYTE *lower, const BYTE *upper)
{
  // This is a standard free list, except we're doubly linked to deal with some return shenanigans.
  MHOOKS_TRAMPOLINE *curr_entry = g_free_list;

  while (curr_entry)
  {
    if ((MHOOKS_TRAMPOLINE*)lower < curr_entry && curr_entry < (MHOOKS_TRAMPOLINE*)upper)
    {
      ListRemove (&g_free_list, curr_entry);
      return (curr_entry);
    }
    curr_entry = curr_entry->next_trampoline;
  }
  return (NULL);
}

//
// Internal function:
//
// Will try to allocate the trampoline structure within 2 gigabytes of
// the target function.
//
static MHOOKS_TRAMPOLINE *TrampolineAlloc (BYTE *system_function, int64_t limit_up, int64_t limit_down)
{
  MHOOKS_TRAMPOLINE *trampoline = NULL;

  // determine lower and upper bounds for the allocation locations.
  // in the basic scenario this is +/- 2GB but IP-relative instructions
  // found in the original code may require a smaller window.
  BYTE *lower = system_function + limit_up;

  if (lower < (BYTE*)(DWORD_PTR)0x0000000080000000)
       lower = (BYTE*) 1;
  else lower = (BYTE*) (lower - (BYTE*)0x7FFF0000);

  BYTE *upper = system_function + limit_down;

  if (upper < (BYTE*)(DWORD_PTR)0xFFFFFFFF80000000)
       upper = (BYTE*) (upper + (DWORD_PTR)0x7FF80000);
  else upper = (BYTE*) (DWORD_PTR)0xFFFFFFFFFFF80000;

  TRACE ("TrampolineAlloc: Allocating for %p between %p and %p", system_function, lower, upper);

  // try to find a trampoline in the specified range
  trampoline = FindTrampolineInRange (lower, upper);
  if (!trampoline)
  {
    // if it we can't find it, then we need to allocate a new block and
    // try again. Just fail if that doesn't work
    g_free_list = BlockAlloc (system_function, lower, upper);
    trampoline = FindTrampolineInRange (lower, upper);
  }

  // found and allocated a trampoline?
  if (trampoline)
     ListPrepend (&g_hooks, trampoline);
  return (trampoline);
}

//
// Internal function:
//
// Return the internal trampoline structure that belongs to a hooked function.
//
static MHOOKS_TRAMPOLINE *TrampolineGet (const BYTE *hooked_function)
{
  MHOOKS_TRAMPOLINE *current = g_hooks;

  while (current)
  {
    if ((BYTE*)&current->code_trampoline == hooked_function)
       return (current);
    current = current->next_trampoline;
  }
  return (NULL);
}

//
// Internal function:
//
// Free a trampoline structure.
//
static void TrampolineFree (MHOOKS_TRAMPOLINE *trampoline, BOOL never_used)
{
  ListRemove (&g_hooks, trampoline);

  // If a thread could feasibly have some of our trampoline code
  // on its stack and we yank the region from underneath it then it will
  // surely crash upon returning. So instead of freeing the
  // memory we just let it leak. Ugly, but safe.
  if (never_used)
     ListPrepend (&g_free_list, trampoline);
}

static BOOL VerifyThreadContext (const BYTE *ip, const HOOK_CONTEXT *hook_ctx)
{
  if (ip >= (const BYTE*)hook_ctx->system_function && ip < ((const BYTE*)hook_ctx->system_function + hook_ctx->instruction_length))
     return (FALSE);
  return (TRUE);
}

//
// Internal function:
//
// Suspend a given thread and try to make sure that its instruction
// pointer is not in the given range.
//
static HANDLE SuspendOneThread (DWORD thread_id, HOOK_CONTEXT *hook_ctx)
{
  HANDLE thread = OpenThread (THREAD_ALL_ACCESS, FALSE, thread_id);   // open the thread
  DWORD  suspend_count;

  if (GOOD_HANDLE(thread))
  {
    suspend_count = SuspendThread (thread);  // attempt suspension

    if (suspend_count != (DWORD)-1)
    {
      CONTEXT ctx;   // see where the IP is

      ctx.ContextFlags = CONTEXT_CONTROL;
      int nTries = 0;

      while (GetThreadContext (thread, &ctx))
      {
#ifdef _M_IX86
        BYTE *ip = (BYTE*) (DWORD_PTR) ctx.Eip;
#else
        BYTE *ip = (BYTE*) (DWORD_PTR) ctx.Rip;
#endif

        if (!VerifyThreadContext (ip, hook_ctx))
        {
          if (nTries < 3)
          {
            // oops - we should try to get the instruction pointer out of here.
            TRACE ("SuspendOneThread: suspended thread %d - IP is at %p - IS COLLIDING WITH CODE", thread_id, ip);
            ResumeThread (thread);
            Sleep (100);
            SuspendThread (thread);
            nTries++;
          }
          else
          {
            // we gave it all we could. (this will probably never
            // happen - unless the thread has already been suspended
            // to begin with)
            TRACE ("SuspendOneThread: suspended thread %d - IP is at %p - IS COLLIDING WITH CODE - CAN'T FIX", thread_id, ip);
            ResumeThread (thread);
            CloseHandle (thread);
            thread = NULL;
            break;
          }
        }
        else
        {
          // success, the IP is not conflicting
          TRACE ("SuspendOneThread: Successfully suspended thread %d - IP is at %p", thread_id, ip);
          break;
        }
      }
    }
    else
    {
      // couldn't suspend
      CloseHandle (thread);
      thread = NULL;
    }
  }
  return (thread);
}

//
// Internal function:
//
// Free memory allocated for processes snapshot
//
static void CloseProcessSnapshot (void *snapshot_context)
{
  free (snapshot_context);
}

//
// Internal function:
//
// Resumes all previously suspended threads in the current process.
//
static void ResumeOtherThreads (void)
{
  // make sure things go as fast as possible
  INT original_priority = GetThreadPriority (GetCurrentThread());

  SetThreadPriority (GetCurrentThread(), THREAD_PRIORITY_TIME_CRITICAL);

  // go through our list
  for (DWORD i = 0; i < g_num_thread_handles; i++)
  {
    // and resume & close thread handles
    ResumeThread (g_thread_handles[i]);
    CloseHandle (g_thread_handles[i]);
  }

  // clean up
  free (g_thread_handles);
  g_thread_handles = NULL;
  g_num_thread_handles = 0;
  SetThreadPriority (GetCurrentThread(), original_priority);
}

//
// Internal function:
//
// Get snapshot of the processes started in the system
//
static BOOL CreateProcessSnapshot (void **snapshot_context)
{
  ULONG    buf_size = 1024 * 1024;  // 1Mb - default process information buffer size (that's enough in most cases for high-loaded systems)
  void*    buffer = NULL;
  NTSTATUS status = 0;

  if (!p_ZwQuerySystemInformation)
  {
    p_ZwQuerySystemInformation = (func_ZwQuerySystemInformation) GetProcAddress (GetModuleHandleA("ntdll.dll"), "ZwQuerySystemInformation");
    if (!p_ZwQuerySystemInformation)
       return (FALSE);
  }

  do
  {
    buffer = malloc (buf_size);
    if (!buffer)
       return (FALSE);

    status = (*p_ZwQuerySystemInformation) (SystemProcessInformation, buffer, buf_size, NULL);
    if (status == STATUS_INFO_LENGTH_MISMATCH)
    {
      free (buffer);
      buf_size *= 2;
    }
    else if (status < 0)
    {
      free (buffer);
      return (FALSE);
    }
  }
  while (status == STATUS_INFO_LENGTH_MISMATCH);

  *snapshot_context = buffer;
  return (TRUE);
}

//
// Internal function:
//
// Find and return process information from snapshot
//
static SYSTEM_PROCESS_INFORMATION *FindProcess (const void *snapshot_context, SIZE_T process_id)
{
  SYSTEM_PROCESS_INFORMATION *process = (SYSTEM_PROCESS_INFORMATION*) snapshot_context;

  while (process)
  {
    if (process->UniqueProcessId == (HANDLE)process_id)
       return (process);

    if (process->NextEntryOffset == 0)
       break;

    process = (SYSTEM_PROCESS_INFORMATION*) (((BYTE*)process) + process->NextEntryOffset);
  }
  return (NULL);
}

//
// Internal function:
//
// Get current process snapshot and process info
//
static BOOL GetCurrentProcessSnapshot (void **snapshot, SYSTEM_PROCESS_INFORMATION **proc_info)
{
  *snapshot = NULL;

  // get a view of the threads in the system
  if (!CreateProcessSnapshot(snapshot))
  {
    TRACE ("Can't get process snapshot!");
    return (FALSE);
  }

  // this never returns NULL as the current process id is always present in the processes snapshot
  *proc_info = FindProcess (*snapshot, GetCurrentProcessId());
  assert (*proc_info);
  return (TRUE);
}

//
// Internal function:
//
// Suspend all threads in this process while trying to make sure that their
// instruction pointer is not in the given range.
//
static BOOL SuspendOtherThreads (HOOK_CONTEXT *hook_ctx, SYSTEM_PROCESS_INFORMATION *proc_info)
{
  BOOL  ret = FALSE;
  DWORD pid, tid;
  DWORD threads_in_process = 0;

  // make sure we're the most important thread in the process
  INT original_priority = GetThreadPriority (GetCurrentThread());

  SetThreadPriority (GetCurrentThread(), THREAD_PRIORITY_TIME_CRITICAL);

  pid = GetCurrentProcessId();
  tid = GetCurrentThreadId();

  // count threads in this process (except for ourselves)
  if (proc_info->NumberOfThreads > 0)
     threads_in_process = proc_info->NumberOfThreads - 1;

  TRACE ("[%d:%d] SuspendOtherThreads: counted %d other threads", pid, tid, threads_in_process);

  if (threads_in_process)
  {
    // alloc buffer for the handles we really suspended
    g_thread_handles = calloc (threads_in_process * sizeof(HANDLE), 1);
    if (g_thread_handles)
    {
      BOOL  failed = FALSE;
      DWORD current_thread = 0;
      DWORD thread_id;
      ULONG thread_idx;

      // go through every thread
      for (thread_idx = 0; thread_idx < proc_info->NumberOfThreads; thread_idx++)
      {
        thread_id = (DWORD) (DWORD_PTR) proc_info->Threads[thread_idx].ClientId.UniqueThread;

        if (thread_id != tid)   // not this thread
        {
          // attempt to suspend it
          g_thread_handles[current_thread] = SuspendOneThread (thread_id, hook_ctx);

          if (GOOD_HANDLE (g_thread_handles[current_thread]))
          {
            TRACE ("[%d:%d] SuspendOtherThreads: successfully suspended %d", pid, tid, thread_id);
            current_thread++;
          }
          else
          {
            TRACE ("[%d:%d] SuspendOtherThreads: error while suspending thread %d: %d",
                   pid, tid, thread_id, GetLastError());

            // TODO:
            // this might not be the wisest choice but we can choose to ignore failures on
            // thread suspension. It's pretty unlikely that we'll fail - and even if we
            // do, the chances of a thread's IP being in the wrong place is pretty small.
            // failed = TRUE;
          }
        }
      }
      g_num_thread_handles = current_thread;
      ret = !failed;
    }
  }

  // TODO: we might want to have another pass to make sure all threads
  // in the current process (including those that might have been
  // created since we took the original snapshot) have been
  // suspended.

  if (!ret && threads_in_process != 0)
  {
    TRACE ("[%d:%d] SuspendOtherThreads: Had a problem (or not running multithreaded), resuming all threads.", pid, tid);
    ResumeOtherThreads();
  }
  SetThreadPriority (GetCurrentThread(), original_priority);
  return (ret);
}

//
// if IP-relative addressing has been detected, fix up the code so the
// offset points to the original location
//
static void FixupIPRelativeAddressing (BYTE *new, BYTE *original, MHOOKS_PATCHDATA *data)
{
#if defined _M_X64
  int64_t diff = new - original;

  for (DWORD i = 0; i < data->rip_count; i++)
  {
    DWORD new_displacement = (DWORD) (data->rips[i].displacement - diff);

    TRACE ("fixing up RIP instruction operand for code at 0x%p: "
           "old displacement: 0x%8.8x, new displacement: 0x%8.8x",
           new + data->rips[i].offset,
           (DWORD) data->rips[i].displacement,
           new_displacement);
    *(DWORD*)(new + data->rips[i].offset) = new_displacement;
  }
#endif
}

//
// Examine the machine code at the target function's entry point, and
// skip bytes in a way that we'll always end on an instruction boundary.
// We also detect branches and subroutine calls (as well as returns)
// at which point disassembly must stop.
// Finally, detect and collect information on IP-relative instructions
// that we can patch.
//
static DWORD DisassembleAndSkip (void *function, DWORD min_len, MHOOKS_PATCHDATA *data)
{
  DISASSEMBLER dis;
  DWORD ret = 0;

  data->limit_down = 0;
  data->limit_up   = 0;
  data->rip_count  = 0;

  if (InitDisassembler(&dis, g_arch))
  {
    INSTRUCTION *instruction = NULL;
    uint8_t     *location = (uint8_t*) function;

    TRACE ("DisassembleAndSkip: Disassembling %p", location);

    while (ret < min_len && (instruction = GetInstruction (&dis, (ULONG_PTR)location, location, DISASM_FLAGS)) != NULL)
    {
      TRACE ("DisassembleAndSkip: %p (0x%2.2x) %s", location, instruction->Length, instruction->String);

      if (instruction->Type == ITYPE_RET)
         break;

      if (instruction->Type == ITYPE_BRANCHCC)
         break;

      if (instruction->Type == ITYPE_CALLCC)
         break;

#ifdef _M_X64
      BOOL bProcessRip = FALSE;

      // jmp to rip+imm32
      if (instruction->Type == ITYPE_BRANCH && instruction->OperandCount == 1 && instruction->X86.Relative &&
          instruction->X86.BaseRegister == AMD64_REG_RIP && (instruction->Operands[0].Flags & OP_IPREL))
      {
        // rip-addressing "jmp [rip+imm32]"
        TRACE ("DisassembleAndSkip: found OP_IPREL on operand %d with displacement 0x%x (in memory: 0x%x)",
               1, instruction->X86.Displacement, *(DWORD*) (location + 3));
        bProcessRip = TRUE;
      }
      // mov or lea to register from rip+imm32
      else if ((instruction->Type == ITYPE_MOV || instruction->Type == ITYPE_LEA) && instruction->X86.Relative &&
               instruction->X86.OperandSize == 8 && instruction->OperandCount == 2 && (instruction->Operands[1].Flags & OP_IPREL) &&
              instruction->Operands[1].Register == AMD64_REG_RIP)
      {
        // rip-addressing "mov reg, [rip+imm32]"
        TRACE ("DisassembleAndSkip: found OP_IPREL on operand %d with displacement 0x%x (in memory: 0x%x)",
               1, instruction->X86.Displacement, *(DWORD*)(location + 3));
        bProcessRip = TRUE;
      }
      // mov or lea to rip+imm32 from register
      else if ((instruction->Type == ITYPE_MOV || instruction->Type == ITYPE_LEA) &&
               instruction->X86.Relative && instruction->X86.OperandSize == 8 && instruction->OperandCount == 2 &&
               (instruction->Operands[0].Flags & OP_IPREL) && instruction->Operands[0].Register == AMD64_REG_RIP)
      {
        // rip-addressing "mov [rip+imm32], reg"
        TRACE ("DisassembleAndSkip: found OP_IPREL on operand %d with displacement 0x%x (in memory: 0x%x)",
               0, instruction->X86.Displacement, *(DWORD*)(location + 3));
        bProcessRip = TRUE;
      }
      else if (instruction->OperandCount >= 1 && (instruction->Operands[0].Flags & OP_IPREL))
      {
        // unsupported rip-addressing
        TRACE ("DisassembleAndSkip: found unsupported OP_IPREL on operand %d", 0);

        // dump instruction bytes to the debug output
        for (DWORD i = 0; i < instruction->Length; i++)
            TRACE ("DisassembleAndSkip: instr byte %2.2d: 0x%2.2x", i, location[i]);
        break;
      }
      else if (instruction->OperandCount >= 2 && (instruction->Operands[1].Flags & OP_IPREL))
      {
        // unsupported rip-addressing
        TRACE ("DisassembleAndSkip: found unsupported OP_IPREL on operand %d", 1);

        // dump instruction bytes to the debug output
        for (DWORD i = 0; i < instruction->Length; i++)
            TRACE ("DisassembleAndSkip: instr byte %2.2d: 0x%2.2x", i, location[i]);
        break;
      }
      else if (instruction->OperandCount >= 3 && (instruction->Operands[2].Flags & OP_IPREL))
      {
        // unsupported rip-addressing
        TRACE ("DisassembleAndSkip: found unsupported OP_IPREL on operand %d", 2);

        // dump instruction bytes to the debug output
        for (DWORD i = 0; i < instruction->Length; i++)
            TRACE ("DisassembleAndSkip: instr byte %2.2d: 0x%2.2x", i, location[i]);
        break;
      }

      // follow through with RIP-processing if needed
      if (bProcessRip)
      {
        // calculate displacement relative to function start
        int64_t adjusted_displacement = instruction->X86.Displacement + (location - (uint8_t*) function);

        // store displacement values furthest from zero (both positive and negative)
        if (adjusted_displacement < data->limit_down)
           data->limit_down = adjusted_displacement;

        if (adjusted_displacement > data->limit_up)
           data->limit_up = adjusted_displacement;

        // store patch info
        if (data->rip_count < DIM(data->rips))
        {
          data->rips [data->rip_count].offset = ret + 3;
          data->rips [data->rip_count].displacement = instruction->X86.Displacement;
          data->rip_count++;
        }
        else
        {
          // no room for patch info, stop disassembly
          break;
        }
      }
#endif

      ret       += instruction->Length;
      location  += instruction->Length;
    }
    CloseDisassembler (&dis);
  }
  return (ret);
}

static BOOL IsInstructionPresentInFirstFiveByte (void *function, INSTRUCTION_TYPE type)
{
  DWORD ret = 0;
  DISASSEMBLER dis;

  if (InitDisassembler(&dis, g_arch))
  {
    INSTRUCTION *instruction = NULL;
    uint8_t     *location = (uint8_t*) function;

    while (ret < MHOOK_JMPSIZE && (instruction = GetInstruction (&dis, (ULONG_PTR)location, location, DISASM_FLAGS)) != NULL)
    {
      if (instruction->Type == type)
         return (TRUE);

      ret      += instruction->Length;
      location += instruction->Length;
    }
    CloseDisassembler (&dis);
  }
  return (FALSE);
}

static BYTE *PatchRelative (BYTE *code_trampoline, void *system_function)
{
  DISASSEMBLER dis;
  DWORD        ret = 0;

  if (InitDisassembler(&dis, g_arch))
  {
    INSTRUCTION *instruction = NULL;
    uint8_t     *location = (uint8_t*) code_trampoline;

    while (ret < MHOOK_JMPSIZE && (instruction = GetInstruction (&dis, (ULONG_PTR)location, location, DISASM_FLAGS)) != NULL)
    {
      if (instruction->Type == ITYPE_BRANCHCC)
      {
        // we will patch only near jump je/jz for now
        if (instruction->OpcodeLength == 1 && (instruction->OpcodeBytes[0] == 0x74 || instruction->OpcodeBytes[0] == 0x75))
        {
          // save old offset from current position to jump destination
          uint8_t old_offset = location [instruction->OpcodeLength];

          // write je opcode with rel32 address in 'code_trampoline' block
          *location = 0x0f;
          location [instruction->OpcodeLength] = instruction->OpcodeBytes[0] + 0x10;

          // Calculating offset from 'code_trampoline' to jump label in original function
          // get address of original jump destination
          ULONG_PTR jumpDestinationAddress = (ULONG_PTR) system_function;

          // 'old_offset' is from the 'location + instruction->OpcodeLength' address, so add it
          jumpDestinationAddress += old_offset + instruction->OpcodeLength;

          // current address is from the location + 2 (JE REL32 opcode is 2-bytes length), so add it
          #define JERel32_OPCODE_LEN  2
          ULONG_PTR currentAddress = (ULONG_PTR) (location + JERel32_OPCODE_LEN);

          // take the offset that we should add to current address to reach original jump destination
          LONG new_offset = (LONG) (jumpDestinationAddress - currentAddress);
          assert (currentAddress + new_offset == jumpDestinationAddress);
          memcpy (location + JERel32_OPCODE_LEN, &new_offset, sizeof (new_offset));
          return (location + JERel32_OPCODE_LEN + sizeof (new_offset));
        }
      }

      if (instruction->Type == ITYPE_CALL)
      {
        // we will patch CALL relative32
        if (instruction->OpcodeLength == 1 && instruction->OpcodeBytes[0] == 0xE8)
        {
          // call rel32 address is relative to the next instruction start address.
          // '(ULONG_PTR)system_function' is the original function address
          // '(location - code_trampoline)' for current offset of call from start of the function,
          // 'instruction->Length' - full length of instruction and operand address
          ULONG_PTR old_start_addr = (location - code_trampoline) + (ULONG_PTR) system_function + instruction->Length;

          // offset from the next instruction address
          LONG old_offset = *(LONG*) instruction->Operands[0].BCD;

          // target function address
          ULONG_PTR destination = old_start_addr + old_offset;

          // now calculate new start address and new offset
          ULONG_PTR new_start_addr = (ULONG_PTR) instruction->Address + instruction->Length;
          LONG      new_offset     = (LONG) (destination - new_start_addr);

          // save new offset to the trampoline code
          *(LONG*) (location + instruction->OpcodeLength) = new_offset;
          return (location + instruction->OpcodeLength + sizeof (new_offset));
        }
      }
      ret      += instruction->Length;
      location += instruction->Length;
    }
    CloseDisassembler (&dis);
  }
  return (code_trampoline);
}

//
// The main work-horse
//
int Mhook_SetHook (void **system_function, void *hook_function)
{
  int  hooksSet = 0;
  HOOK_CONTEXT *hook_ctx = calloc (sizeof(*hook_ctx), 1);

  if (!hook_ctx)
  {
    // return error status
    TRACE ("Can't allocate buffer!");
    return (hooksSet);
  }

  EnterCritSec();

  hook_ctx->system_function = *system_function;
  hook_ctx->hook_function   = hook_function;

  TRACE ("Mhook_SetHook: Started on the job: %p / %p", hook_ctx->system_function, hook_ctx->hook_function);

  // find the real functions (jump over jump tables, if any)
  hook_ctx->system_function = SkipJumps ((BYTE*)hook_ctx->system_function);
  hook_ctx->hook_function   = SkipJumps ((BYTE*)hook_ctx->hook_function);

  TRACE ("Mhook_SetHook: Started on the job: %p / %p", hook_ctx->system_function, hook_ctx->hook_function);

  // figure out the length of the overwrite zone
  hook_ctx->instruction_length = DisassembleAndSkip (hook_ctx->system_function, MHOOK_JMPSIZE, &hook_ctx->patch_data);
  hook_ctx->need_patch_jump    = IsInstructionPresentInFirstFiveByte (hook_ctx->system_function, ITYPE_BRANCHCC);
  hook_ctx->need_patch_call    = IsInstructionPresentInFirstFiveByte (hook_ctx->system_function, ITYPE_CALL);

  if (hook_ctx->instruction_length >= MHOOK_JMPSIZE && !(hook_ctx->need_patch_jump && hook_ctx->need_patch_call))
  {
    TRACE ("Mhook_SetHook: disassembly signals %d bytes", hook_ctx->instruction_length);

    // allocate a trampoline structure (TODO: it is pretty wasteful to get
    // VirtualAlloc to grab chunks of memory smaller than 100 bytes)
    hook_ctx->trampoline = TrampolineAlloc ((BYTE*)hook_ctx->system_function,
                                            hook_ctx->patch_data.limit_up,
                                            hook_ctx->patch_data.limit_down);
  }
  else
  {
    // error - skip hook
    TRACE ("Error! disassembly signals %d bytes (unacceptable)", hook_ctx->instruction_length);
  }

  void  *proc_enumeration_ctx;
  SYSTEM_PROCESS_INFORMATION *proc_info = NULL;

  if (GetCurrentProcessSnapshot(&proc_enumeration_ctx, &proc_info))
  {
    // suspend threads
    SuspendOtherThreads (hook_ctx, proc_info);

    // returns pseudo-handle, no need to CloseHandle() for it
    HANDLE currentProcessHandle = GetCurrentProcess();

    if (hook_ctx->trampoline)
    {
      TRACE ("Mhook_SetHook: allocated structure at %p", hook_ctx->trampoline);
      DWORD dwOldProtectSystemFunction = 0;
      DWORD dwOldProtectTrampolineFunction = 0;

      // set the system function to PAGE_EXECUTE_READWRITE
      if (VirtualProtect (hook_ctx->system_function, hook_ctx->instruction_length, PAGE_EXECUTE_READWRITE, &dwOldProtectSystemFunction))
      {
        TRACE ("Mhook_SetHook: readwrite set on system function");

        // mark our trampoline buffer to PAGE_EXECUTE_READWRITE
        if (VirtualProtect (hook_ctx->trampoline, sizeof(MHOOKS_TRAMPOLINE), PAGE_EXECUTE_READWRITE, &dwOldProtectTrampolineFunction))
        {
          TRACE ("Mhook_SetHook: readwrite set on trampoline structure");

          // create our trampoline function
          BYTE *code = hook_ctx->trampoline->code_trampoline;

          // save original code..
          for (DWORD k = 0; k < hook_ctx->instruction_length; k++)
              hook_ctx->trampoline->code_untouched[k] = code[k] = ((BYTE*)hook_ctx->system_function) [k];

          if (hook_ctx->need_patch_jump || hook_ctx->need_patch_call)
               code = PatchRelative (code, hook_ctx->system_function);
          else code += hook_ctx->instruction_length;

          // plus a jump to the continuation in the original location
          code = EmitJump (code, (BYTE*)hook_ctx->system_function + hook_ctx->instruction_length);
          TRACE ("Mhook_SetHook: updated the trampoline");

          // fix up any IP-relative addressing in the code
          FixupIPRelativeAddressing (hook_ctx->trampoline->code_trampoline,
                                     (BYTE*)hook_ctx->system_function,
                                     &hook_ctx->patch_data);

          DWORD_PTR distance = (BYTE*) hook_ctx->hook_function < (BYTE*) hook_ctx->system_function ?
                               (BYTE*) hook_ctx->system_function - (BYTE*) hook_ctx->hook_function :
                               (BYTE*) hook_ctx->hook_function - (BYTE*) hook_ctx->system_function;

          if (distance > 0x7FFF0000)
          {
            // create a stub that jumps to the replacement function.
            // we need this because jumping from the API to the hook directly
            // will be a long jump, which is 14 bytes on x64, and we want to
            // avoid that - the API may or may not have room for such stuff.
            // (remember, we only have 5 bytes guaranteed in the API.)
            // on the other hand we do have room, and the trampoline will always be
            // within +/- 2GB of the API, so we do the long jump in there.
            // the API will jump to the "reverse trampoline" which
            // will jump to the user's hook code.
            code = hook_ctx->trampoline->code_jump_to_hook_function;
            code = EmitJump (code, (BYTE*)hook_ctx->hook_function);

            TRACE ("Mhook_SetHook: created reverse trampoline");
            FlushInstructionCache (GetCurrentProcess(), hook_ctx->trampoline->code_jump_to_hook_function,
                                   code - hook_ctx->trampoline->code_jump_to_hook_function);

            // update the API itself
            code = (BYTE*) hook_ctx->system_function;
            code = EmitJump (code, hook_ctx->trampoline->code_jump_to_hook_function);
          }
          else
          {
            // the jump will be at most 5 bytes so we can do it directly
            // update the API itself
            code = (BYTE*) hook_ctx->system_function;
            code = EmitJump (code, (BYTE*)hook_ctx->hook_function);
          }

          // update data members
          hook_ctx->trampoline->overwritten_code = hook_ctx->instruction_length;
          hook_ctx->trampoline->system_function   = (BYTE*) hook_ctx->system_function;
          hook_ctx->trampoline->hook_function     = (BYTE*) hook_ctx->hook_function;

          // update pointer here for ability to hook system functions follows
          if (hook_ctx->trampoline->system_function)
          {
            // this is what the application will use as the entry point
            // to the "original" unhooked function.
            *system_function = hook_ctx->trampoline->code_trampoline;
          }

          // flush instruction cache and restore original protection
          FlushInstructionCache (currentProcessHandle,
                                 hook_ctx->trampoline->code_trampoline,
                                 hook_ctx->instruction_length);
          VirtualProtect (hook_ctx->trampoline, sizeof(MHOOKS_TRAMPOLINE),
                          dwOldProtectTrampolineFunction, &dwOldProtectTrampolineFunction);
        }
        else
          TRACE ("Mhook_SetHook: failed VirtualProtect 2: %d", GetLastError());

        // flush instruction cache and restore original protection
        FlushInstructionCache (currentProcessHandle, hook_ctx->system_function, hook_ctx->instruction_length);
        VirtualProtect (hook_ctx->system_function, hook_ctx->instruction_length,
                        dwOldProtectSystemFunction, &dwOldProtectSystemFunction);
      }
      else
        TRACE ("Mhook_SetHook: failed VirtualProtect 1: %d", GetLastError());

      if (hook_ctx->trampoline->system_function)
      {
        hooksSet++;

        // setting the entry point is moved upper for ability to hook some internal system functions
        TRACE ("Mhook_SetHook: Hooked the function!");
      }
      else
      {
        // if we failed discard the trampoline (forcing VirtualFree)
        TrampolineFree (hook_ctx->trampoline, TRUE);
        hook_ctx->trampoline = NULL;
      }
    }

    // resume threads
    ResumeOtherThreads();
    CloseProcessSnapshot (proc_enumeration_ctx);
  }

  free (hook_ctx);
  LeaveCritSec();
  return (hooksSet);
}

BOOL Mhook_Unhook (void **hooked_function)
{
  BOOL result = FALSE;
  HOOK_CONTEXT *hook_ctx = malloc (sizeof(HOOK_CONTEXT));

  TRACE ("Mhook_Unhook: unhook function %p", *hooked_function);

  if (!hook_ctx)
  {
    // return error status
    TRACE ("Mhook_Unhook: can't allocate buffer!");
    return (result);
  }

  EnterCritSec();

  hook_ctx->system_function = *hooked_function;

  // get the trampoline structure that corresponds to our function
  hook_ctx->trampoline = TrampolineGet ((BYTE*)hook_ctx->system_function);
  if (hook_ctx->trampoline)
  {
    TRACE ("Mhook_Unhook: found struct at %p", hook_ctx->trampoline);
    hook_ctx->instruction_length = hook_ctx->trampoline->overwritten_code;
  }

  void *proc_enumeration_ctx;
  SYSTEM_PROCESS_INFORMATION *proc_info = NULL;

  if (GetCurrentProcessSnapshot(&proc_enumeration_ctx, &proc_info))
  {
    // make sure nobody's executing code where we're about to overwrite a few bytes
    SuspendOtherThreads (hook_ctx, proc_info);

    if (hook_ctx->trampoline)
    {
      DWORD dwOldProtectSystemFunction = 0;

      // make memory writable
      if (VirtualProtect (hook_ctx->trampoline->system_function, hook_ctx->trampoline->overwritten_code,
                          PAGE_EXECUTE_READWRITE, &dwOldProtectSystemFunction))
      {
        TRACE ("Mhook_Unhook: readwrite set on system function");

        BYTE *code = (BYTE*)hook_ctx->trampoline->system_function;

        for (DWORD i = 0; i < hook_ctx->trampoline->overwritten_code; i++)
           code[i] = hook_ctx->trampoline->code_untouched[i];

        // flush instruction cache and make memory unwritable
        FlushInstructionCache (GetCurrentProcess(), hook_ctx->trampoline->system_function, hook_ctx->trampoline->overwritten_code);
        VirtualProtect (hook_ctx->trampoline->system_function, hook_ctx->trampoline->overwritten_code,
                        dwOldProtectSystemFunction, &dwOldProtectSystemFunction);

        // return the original function pointer
        *hooked_function = hook_ctx->trampoline->system_function;
        result = TRUE;

        TRACE ("Mhook_Unhook: sysfunc: %p", *hooked_function);

        // free the trampoline while not really discarding it from memory
        TrampolineFree (hook_ctx->trampoline, FALSE);
        TRACE ("Mhook_Unhook: unhook successful");
      }
      else
        TRACE ("Mhook_Unhook: failed VirtualProtect 1: %d", GetLastError());
    }

    // make the other guys runnable
    ResumeOtherThreads();
    CloseProcessSnapshot (proc_enumeration_ctx);
  }

  free (hook_ctx);
  LeaveCritSec();
  return (result);
}

#if defined(USE_TRACE)  /* Rest of file */
static void mhook_trace_exit (void)
{
  TRACE ("In %s()", __FUNCTION__);
  DeleteCriticalSection (&trace_crit);
}

static void mhook_set_color (unsigned short col)
{
  fflush (stdout);

  if (col == 0)
       SetConsoleTextAttribute (stdout_hnd, console_info.wAttributes);
  else SetConsoleTextAttribute (stdout_hnd, (console_info.wAttributes & ~7) | col);
}

static int mhook_trace_level (void)
{
  char env[100] = "";
  static int ret = -1;

  if (ret >= 0)
     return (ret);

  if (GetEnvironmentVariableA("MHOOK_TRACE", env, sizeof(env)) > 0 && isdigit((int)env[0]))
       ret = (env[0] - '0');
  else ret = 0;

  if (ret > 0)
  {
    stdout_hnd = GetStdHandle (STD_OUTPUT_HANDLE);
    GetConsoleScreenBufferInfo (stdout_hnd, &console_info);
    InitializeCriticalSection (&trace_crit);
    atexit (mhook_trace_exit);
    TRACE ("Leaving %s()", __FUNCTION__);
  }
  return (ret);
}

static void mhook_printf (int color, const char *fmt, ...)
{
  va_list args;
  va_start (args, fmt);

  mhook_set_color (color);
  vfprintf (stdout, fmt, args);
  if (color == TRACE_COLOUR_ARGS)   /* last call in macro 'TRACE()' */
     mhook_set_color (0);
  va_end (args);
}

static double mhook_tv_diff (const struct timeval *newer, const struct timeval *older)
{
  long d_sec  = (long)newer->tv_sec - (long)older->tv_sec;
  long d_usec = newer->tv_usec - older->tv_usec;

  while (d_usec < 0)
  {
    d_usec += 1000000L;
    d_sec  -= 1;
  }
  return (double)d_sec + ((double)d_usec) / 1E6;
}

typedef union {
        uint64_t tm;
        FILETIME ft;
      } FT;

static void mhook_gettimeofday (struct timeval *tp)
{
  FT ft;

  memset (&ft, 0, sizeof(ft));
  GetSystemTimeAsFileTime (&ft.ft);
  ft.tm /= 10;
  tp->tv_usec = ft.tm % 1000000ULL;
  tp->tv_sec  = (long) (ft.tm - 11644473600000000ULL) / 1000000ULL;
}

static double mhook_diff_time (void)
{
  static struct timeval trace_start;
  struct timeval now;

  mhook_gettimeofday (&now);
  if (trace_start.tv_sec == 0)
     trace_start = now;
  return mhook_tv_diff (&now, &trace_start);
}
#endif /* USE_TRACE */

#ifdef MHOOK_TEST  /* Rest of file */

#include <ws2tcpip.h>
#include <tchar.h>

typedef ULONG (WINAPI *_NtOpenProcess) (OUT HANDLE     *ProcessHandle,
                                        IN  ACCESS_MASK AccessMask,
                                        IN  void       *ObjectAttributes,
                                        IN  CLIENT_ID  *ClientId);

typedef HGDIOBJ (WINAPI *_SelectObject) (HDC hdc, HGDIOBJ hgdiobj);

typedef int (WSAAPI *_getaddrinfo) (const char *nodename,
                                    const char *servname,
                                    const struct addrinfo *hints,
                                    struct addrinfo **res);

typedef void * (WINAPI *_HeapAlloc) (HANDLE, DWORD, SIZE_T);
typedef BOOL   (WINAPI *_HeapFree) (HANDLE, DWORD, LPVOID);

typedef ULONG (WINAPI *_NtClose) (IN HANDLE Handle);

typedef HMODULE (WINAPI *_LoadLibraryA) (IN const char    *dll_name);
typedef HMODULE (WINAPI *_LoadLibraryW) (IN const wchar_t *dll_name);

static _NtOpenProcess True_NtOpenProcess;
static _SelectObject  True_SelectObject;
static _getaddrinfo   True_getaddrinfo;
static _HeapAlloc     True_HeapAlloc;
static _HeapFree      True_HeapFree;
static _NtClose       True_NtClose;
static _LoadLibraryA  True_LoadLibraryA_1, True_LoadLibraryA_2;
static _LoadLibraryW  True_LoadLibraryW_1, True_LoadLibraryW_2;

static ULONG WINAPI Hook_NtOpenProcess (OUT HANDLE     *ProcessHandle,
                                        IN  ACCESS_MASK AccessMask,
                                        IN  VOID       *ObjectAttributes,
                                        IN  CLIENT_ID  *ClientId)
{
  printf ("***** Call to open process %lu\n", (DWORD)(LONG_PTR)ClientId->UniqueProcess);
  return (*True_NtOpenProcess) (ProcessHandle, AccessMask, ObjectAttributes, ClientId);
}

static HGDIOBJ WINAPI Hook_Selectobject (HDC hdc, HGDIOBJ hgdiobj)
{
  printf ("***** Call to SelectObject(0x%p, 0x%p)\n", hdc, hgdiobj);
  return (*True_SelectObject) (hdc, hgdiobj);
}

static int WSAAPI Hook_getaddrinfo (const char *nodename, const char *servname, const struct addrinfo *hints, struct addrinfo **res)
{
  printf ("***** Call to getaddrinfo(0x%p, 0x%p, 0x%p, 0x%p)\n", nodename, servname, hints, res);
  return (*True_getaddrinfo) (nodename, servname, hints, res);
}

static HMODULE WINAPI Hook_LoadLibraryA_1 (const char *dll_name)
{
  HMODULE ret = (*True_LoadLibraryA_1) (dll_name);
  printf ("***** (1): Call to LoadLibraryA (\"%s\") -> 0x%p\n", dll_name, ret);
  return (ret);
}

static HMODULE WINAPI Hook_LoadLibraryA_2 (const char *dll_name)
{
  HMODULE ret = (*True_LoadLibraryA_2) (dll_name);
  printf ("***** (2): Call to LoadLibraryA (\"%s\") -> 0x%p\n", dll_name, ret);
  return (ret);
}

static HMODULE WINAPI Hook_LoadLibraryW_1 (const wchar_t *dll_name)
{
  HMODULE ret = (*True_LoadLibraryW_1) (dll_name);
  printf ("***** (1): Call to LoadLibraryW (L\"%ws\") -> 0x%p\n", dll_name, ret);
  return (ret);
}

static HMODULE WINAPI Hook_LoadLibraryW_2 (const wchar_t *dll_name)
{
  HMODULE ret = (*True_LoadLibraryW_2) (dll_name);
  printf ("***** (2): Call to LoadLibraryW (L\"%ws\") -> 0x%p\n", dll_name, ret);
  return (ret);
}

static void *WINAPI Hook_HeapAlloc (HANDLE a_Handle, DWORD a_Bla, SIZE_T a_Bla2)
{
  void *ret = (*True_HeapAlloc) (a_Handle, a_Bla, a_Bla2);
  printf ("***** Call to HeapAlloc(0x%p, %lu, 0x%zu) -> 0x%p\n", a_Handle, a_Bla, a_Bla2, ret);
  return (ret);
}

static BOOL WINAPI Hook_HeapFree (HANDLE a_Handle, DWORD flags, VOID *lpMem)
{
  BOOL ret = (*True_HeapFree) (a_Handle, flags, lpMem);
  printf ("***** Call to HeapFree(0x%p, %lu, 0x%p) -> %d\n", a_Handle, flags, lpMem, ret);
  return (ret);
}

static ULONG WINAPI Hook_NtClose (HANDLE hHandle)
{
  printf ("***** Call to NtClose(0x%p)\n", hHandle);
  return (*True_NtClose) (hHandle);
}

int _tmain (int argc, TCHAR *argv[])
{
  HANDLE  proc;
  HMODULE gdi32      = GetModuleHandleA ("gdi32");
  HMODULE kernel32   = GetModuleHandleA ("kernel32");
  HMODULE lib_loader = GetModuleHandleA ("api-ms-win-core-libraryloader-l1-2-1");
  HMODULE ntdll      = GetModuleHandleA ("ntdll");
  HMODULE ws2_32     = GetModuleHandleA ("ws2_32");

  True_NtOpenProcess = (_NtOpenProcess) GetProcAddress (ntdll, "NtOpenProcess");
  True_NtClose       = (_NtClose)       GetProcAddress (ntdll, "NtClose");
  True_SelectObject  = (_SelectObject)  GetProcAddress (gdi32, "SelectObject");
  True_getaddrinfo   = (_getaddrinfo)   GetProcAddress (ws2_32, "getaddrinfo");
  True_HeapAlloc     = (_HeapAlloc)     GetProcAddress (kernel32, "HeapAlloc");
  True_HeapFree      = (_HeapFree)      GetProcAddress (kernel32, "HeapFree");

  // Set the hook
  if (Mhook_SetHook((void**)&True_NtOpenProcess, (void*)Hook_NtOpenProcess))
  {
    // Now call OpenProcess and observe NtOpenProcess being redirected
    // under the hood.
    proc = OpenProcess (PROCESS_ALL_ACCESS, FALSE, GetCurrentProcessId());
    if (proc)
    {
      printf ("Successfully opened self: %p\n", proc);
      CloseHandle (proc);
    }
    else
      printf ("Could not open self: %lu\n", GetLastError());

    Mhook_Unhook ((void**)&True_NtOpenProcess);
  }

  // Call OpenProces again - this time there won't be a redirection as
  // the hook has been removed.
  proc = OpenProcess (PROCESS_ALL_ACCESS, FALSE, GetCurrentProcessId());
  if (proc)
  {
    printf ("Successfully opened self: %p\n", proc);
    CloseHandle (proc);
  }
  else
    printf ("Could not open self: %lu\n", GetLastError());

  True_LoadLibraryA_1 = (_LoadLibraryA) GetProcAddress (kernel32, "LoadLibraryA");
  True_LoadLibraryW_1 = (_LoadLibraryW) GetProcAddress (kernel32, "LoadLibraryW");
  True_LoadLibraryA_2 = (_LoadLibraryA) GetProcAddress (lib_loader, "LoadLibraryA");
  True_LoadLibraryW_2 = (_LoadLibraryW) GetProcAddress (lib_loader, "LoadLibraryW");

  printf ("Hooking LoadLibraryA(): True_LoadLibraryA_1: 0x%p.\n", True_LoadLibraryA_1);
  printf ("Hooking LoadLibraryW(): True_LoadLibraryW_1: 0x%p.\n", True_LoadLibraryW_1);
  printf ("Hooking LoadLibraryA(): True_LoadLibraryA_2: 0x%p.\n", True_LoadLibraryA_2);
  printf ("Hooking LoadLibraryW(): True_LoadLibraryW_2: 0x%p.\n", True_LoadLibraryW_2);

  Mhook_SetHook ((void**)&True_LoadLibraryA_1, (void*)Hook_LoadLibraryA_1);
  Mhook_SetHook ((void**)&True_LoadLibraryW_1, (void*)Hook_LoadLibraryW_1);
  Mhook_SetHook ((void**)&True_LoadLibraryA_2, (void*)Hook_LoadLibraryA_2);
  Mhook_SetHook ((void**)&True_LoadLibraryW_2, (void*)Hook_LoadLibraryW_2);

  LoadLibraryA ("dnsapi");
  LoadLibraryW (L"dnsapi");

  // Test another hook, this time in SelectObject().
  //
  // (SelectObject is interesting in that on XP x64, the second instruction
  // in the trampoline uses IP-relative addressing and we need to do some
  // extra work under the hood to make things work properly. This really
  // is more of a test case rather than a demo.)
  //
  printf ("Testing SelectObject.\n");

  if (Mhook_SetHook((void**)&True_SelectObject, (void*)Hook_Selectobject))
  {
    HDC     hdc        = GetDC (NULL);
    HDC     hdc_mem    = CreateCompatibleDC (hdc);
    HBITMAP bitmap     = CreateCompatibleBitmap (hdc, 32, 32);
    HBITMAP bitmap_old = (HBITMAP) SelectObject (hdc_mem, bitmap);

    SelectObject (hdc_mem, bitmap_old);
    DeleteObject (bitmap);
    DeleteDC (hdc_mem);
    ReleaseDC (NULL, hdc);
    Mhook_Unhook ((void**)&True_SelectObject);
  }

  printf ("Testing getaddrinfo.\n");

  if (Mhook_SetHook((void**)&True_getaddrinfo, (void*)Hook_getaddrinfo))
  {
    WSADATA wd = { 0 };
    const char      *ip = "localhost";
    struct addrinfo  aiHints;
    struct addrinfo *res = NULL;
    int    n = 0;

    WSAStartup (MAKEWORD (2, 2), &wd);
    memset (&aiHints, 0, sizeof (aiHints));
    aiHints.ai_family = PF_UNSPEC;
    aiHints.ai_socktype = SOCK_STREAM;

    if (getaddrinfo (ip, NULL, &aiHints, &res) != 0)
       printf ("getaddrinfo failed\n");
    else
    {
      while (res)
      {
        res = res->ai_next;
        n++;
      }
      printf ("got %d addresses\n", n);
    }
    WSACleanup();
    Mhook_Unhook ((void**)&True_getaddrinfo);
  }

  printf ("Testing HeapAlloc() and HeapFree().\n");

  if (Mhook_SetHook((void**)&True_HeapAlloc, (void*)Hook_HeapAlloc) &&
      Mhook_SetHook((void**)&True_HeapFree, (void*)Hook_HeapFree))
  {
    free (malloc (10));
    Mhook_Unhook ((void**)&True_HeapAlloc);
    Mhook_Unhook ((void**)&True_HeapFree);
  }

  printf ("Testing NtClose.\n");

  if (Mhook_SetHook ((void**)&True_NtClose, (void*)Hook_NtClose))
  {
    CloseHandle (NULL);
    Mhook_Unhook ((void**)&True_NtClose);
  }

  Mhook_Unhook ((void**)&True_LoadLibraryA_1);
  Mhook_Unhook ((void**)&True_LoadLibraryA_2);
  Mhook_Unhook ((void**)&True_LoadLibraryW_1);
  Mhook_Unhook ((void**)&True_LoadLibraryW_2);
  return (0);
}
#endif /* MHOOK_TEST */
