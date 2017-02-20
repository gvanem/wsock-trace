/*
 * cpu.c - Part of Wsock-Trace.
 */

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <windows.h>

#include "common.h"
#include "init.h"

/*
 * Instead of including <NtDDK.h> here, we define undocumented stuff
 * needed for NtQueryInformationThread() here:
 */
typedef LONG NTSTATUS;

#define STATUS_SUCCESS 0

typedef enum _THREADINFOCLASS {
              ThreadBasicInformation,
              ThreadTimes,
              ThreadPriority,
              ThreadBasePriority,
              ThreadAffinityMask,
              ThreadImpersonationToken,
              ThreadDescriptorTableEntry,
              ThreadEnableAlignmentFaultFixup,
              ThreadEventPair_Reusable,
              ThreadQuerySetWin32StartAddress,
              ThreadZeroTlsCell,
              ThreadPerformanceCount,
              ThreadAmILastThread,
              ThreadIdealProcessor,
              ThreadPriorityBoost,
              ThreadSetTlsArrayAddress,
              ThreadIsIoPending,
              MaxThreadInfoClass
            } THREADINFOCLASS;

/* end <NTddk.h> stuff */

typedef BOOL  (WINAPI *func_QueryThreadCycleTime) (
        IN     HANDLE   thread_handle,
        OUT    ULONG64 *cycle_time);

typedef NTSTATUS (WINAPI *func_NtQueryInformationThread) (
        IN        HANDLE           thread_handle,
        IN        THREADINFOCLASS  thread_information_class,
        IN OUT    void            *thread_information,
        IN        ULONG            thread_information_length,
        OUT       ULONG           *return_length OPTIONAL);

typedef NTSTATUS (WINAPI *func_NtQuerySystemInformation) (
        IN  ULONG  system_information_class,
        OUT void  *system_information,
        IN  ULONG  system_information_length,
        OUT ULONG *return_length);

static func_QueryThreadCycleTime      p_QueryThreadCycleTime;
static func_NtQueryInformationThread  p_NtQueryInformationThread;
static func_NtQuerySystemInformation  p_NtQuerySystemInformation;

#define ADD_VALUE(opt,dll,func)   { opt, NULL, dll, #func, (void**)&p_##func }

static struct LoadTable dyn_funcs2 [] = {
                        ADD_VALUE (1, "kernel32.dll", QueryThreadCycleTime),
                        ADD_VALUE (1, "ntdll.dll",    NtQueryInformationThread),
                        ADD_VALUE (1, "ntdll.dll",    NtQuerySystemInformation)
                      };

static int num_cpus = -1;

static void init_cpu (void)
{
  SYSTEM_INFO sys_info;

  if (num_cpus >= 0)
     return;

  memset (&sys_info, 0, sizeof(sys_info));
  GetSystemInfo (&sys_info);
  num_cpus = sys_info.dwNumberOfProcessors;

  load_dynamic_table (dyn_funcs2, DIM(dyn_funcs2));
}

/**
 * Return FILETIME in seconds as a double.
 */
static double filetime_sec (const FILETIME *filetime)
{
  const LARGE_INTEGER *ft = (const LARGE_INTEGER*) filetime;
  long double          rc = (long double) ft->QuadPart;

  return (double) (rc/1E7);    /* from 100 nano-sec periods to sec */
}

/**
 * Print some times (and CPU cycle counts) for a thread.
 * I.e. the WinPcap receiver thread.
 */
void print_thread_times (HANDLE thread)
{
  FILETIME ctime, etime, ktime, utime;

  init_cpu();

  if (thread == NULL)
  {
    TRACE (2, "  GetThreadTimes(NULL) called!.\n");
    return;
  }

  if (!GetThreadTimes(thread, &ctime, &etime, &ktime, &utime))
  {
    DWORD err = GetLastError();
    TRACE (2, "  GetThreadTimes (%" ADDR_FMT ") %s.\n", ADDR_CAST(thread), win_strerror(err));
    return;
  }

  printf ("  kernel-time: %.6fs, user-time: %.6fs, life-span: %.6fs",
          filetime_sec(&ktime), filetime_sec(&utime),
          filetime_sec(&etime) - filetime_sec(&ctime));

  if (p_QueryThreadCycleTime)
  {
    ULONG64 cycle_time;

    if (!(*p_QueryThreadCycleTime) (thread, &cycle_time))
         printf (", cycle-time: <failed>");
    else printf (", cycle-time: %s clocks", qword_str(cycle_time));
  }

  if (p_NtQueryInformationThread)
  {
    LARGE_INTEGER perf_count;

    NTSTATUS rc = (*p_NtQueryInformationThread) (
                      thread, ThreadPerformanceCount, &perf_count,
                      sizeof(perf_count), NULL);
    if (rc != STATUS_SUCCESS)
         printf (", perf-count: <fail %ld>", (long)rc);
    else printf (", perf-count: %s", qword_str(perf_count.QuadPart));
  }
  putchar ('\n');
}

/**
 * Print some times for a process.
 */
void print_process_times (void)
{
  HANDLE proc = OpenProcess (PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
                             FALSE, GetCurrentProcessId());
  FILETIME cr_time, exit_time, krnl_time, usr_time;

  if (!proc)
     return;

  if (GetProcessTimes(proc, &cr_time, &exit_time, &krnl_time, &usr_time))
  {
    const struct tm *tm;
    char   time_str [50];
    uint64 ct      = FileTimeToUnixEpoch (&cr_time);
    time_t ct_time = ct / U64_SUFFIX(1000000);

    tzset();
    tm = localtime (&ct_time);
    if (tm)
         strftime (time_str, sizeof(time_str), "%Y%m%d/%H:%M:%S", tm);
    else strcpy (time_str, "??");

    /* 'exit_time' is not printed since the process has not exited yet.
     * Therefore it is zero.
     */
    printf ("\ncreation-time: %s.%06" U64_FMT ", kernel-time: %.6fs, user-time: %.6fs\n",
            time_str, ct % U64_SUFFIX(1000000), filetime_sec(&krnl_time), filetime_sec(&usr_time));
  }
  CloseHandle (proc);
}

/*
 * Taken from NetPerf's netcpu_ntperf.c:
 *   http://www.netperf.org/netperf
 *
 * System CPU time information class.
 * Used to get CPU time information.
 *
 * SDK/inc/ntexapi.h:
 *   Function x8:   SystemProcessorPerformanceInformation
 *   DataStructure: SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION
 */
#define SystemProcessorPerformanceInformation 0x08

typedef struct {
        LARGE_INTEGER  IdleTime;
        LARGE_INTEGER  KernelTime;
        LARGE_INTEGER  UserTime;
        LARGE_INTEGER  DpcTime;
        LARGE_INTEGER  InterruptTime;
        LONG           InterruptCount;
      } SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION;

#define MAX_CPUS 256

/**
 * Print some performance timers.
 *
 * \todo:
 *   Store the counters before and after to get the delta-times.
 */
void print_perf_times (void)
{
  SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION info [MAX_CPUS];
  DWORD     i, ret_len, ret_num_CPUs;
  NTSTATUS  rc;

  init_cpu();

  if (!p_NtQuerySystemInformation || num_cpus == 0)
  {
    TRACE (2, "  p_NtQuerySystemInformation = NULL!\n");
    return;
  }

  /* Get the current CPUTIME information.
   */
  rc = (*p_NtQuerySystemInformation) (SystemProcessorPerformanceInformation,
                                      &info, sizeof(info), &ret_len);
  if (rc != 0)
  {
    DWORD err = GetLastError();
    TRACE (2, "  NtQuerySystemInformation() %s.\n", win_strerror(err));
    return;
  }

  /* Validate that NtQuery returned a reasonable amount of data
   */
  if ((ret_len % sizeof(info[0])) != 0)
  {
    TRACE (1, "NtQuery didn't return expected amount of data\n"
              "Expected a multiple of %u, returned %lu.\n",
              SIZEOF(info[0]), (u_long)ret_len);
    return;
  }

  ret_num_CPUs = ret_len / sizeof(info[0]);
  if (ret_num_CPUs != num_cpus)
  {
    TRACE (1, "NtQuery didn't return expected amount of data\n"
              "Expected data for %i CPUs, returned %lu.\n",
              num_cpus, (u_long)ret_num_CPUs);
    return;
  }

  /* Print total all of the CPUs:
   *   KernelTime needs to be fixed-up; it includes both idle & true kernel time.
   */
  for (i = 0; i < ret_num_CPUs; i++)
  {
    ULONG64 x;

    printf ("CPU %lu:%s", (u_long)i, (i == 0) ? "\t\t\t  CPU clocks\n" : "\n");

    x = info[i].KernelTime.QuadPart - info[i].IdleTime.QuadPart;
    printf ("  KernelTime:     %18s\n", qword_str(x));

    x = info[i].IdleTime.QuadPart;
    printf ("  IdleTime:       %18s\n", qword_str(x));

    x = info[i].UserTime.QuadPart;
    printf ("  UserTime:       %18s\n", qword_str(x));

    x = info[i].DpcTime.QuadPart;
    printf ("  DpcTime:        %18s\n", qword_str(x));

    x = info[i].InterruptTime.QuadPart;
    printf ("  InterruptTime:  %18s\n", qword_str(x));
    printf ("  InterruptCount: %18s\n", dword_str(info[i].InterruptCount));
  }
}
