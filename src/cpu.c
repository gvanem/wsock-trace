/**\file    cpu.c
 * \ingroup Misc
 *
 * \brief
 *  `cpu_init()` is for obtaining the number of CPU cores and the
 *  average CPU frequency.
 *
 * cpu.c - Part of Wsock-Trace.
 */
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <windows.h>

#define IN_CPU_C

#include "common.h"
#include "init.h"
#include "cpu.h"

#define MAX_CPUS 256

#define ADD_VALUE(opt,dll,func)   { opt, NULL, dll, #func, (void**)&p_##func }

static struct LoadTable dyn_funcs [] = {
                        ADD_VALUE (1, "kernel32.dll", QueryThreadCycleTime),
                        ADD_VALUE (1, "kernel32.dll", GetSystemTimePreciseAsFileTime),
                        ADD_VALUE (1, "ntdll.dll",    NtQueryInformationThread),
                        ADD_VALUE (1, "ntdll.dll",    NtQuerySystemInformation),
                        ADD_VALUE (1, "powrprof.dll", CallNtPowerInformation)
                      };

typedef struct _PROCESSOR_POWER_INFORMATION {
        ULONG  Number;
        ULONG  MaxMhz;
        ULONG  CurrentMhz;
        ULONG  MhzLimit;
        ULONG  MaxIdleState;
        ULONG  CurrentIdleState;
      } PROCESSOR_POWER_INFORMATION;

/* From 'enum POWER_INFORMATION_LEVEL'. We only need this value.
 * Ref:
 *   https://docs.microsoft.com/en-us/windows/desktop/api/Powerbase/nf-powerbase-callntpowerinformation
 */
#define _ProcessorInformation 11

static unsigned num_cpus = 0;

void cpu_init (void)
{
  SYSTEM_INFO sys_info;

  if (num_cpus >= 1)
     return;

  memset (&sys_info, 0, sizeof(sys_info));
  GetNativeSystemInfo (&sys_info);

  if (sys_info.dwNumberOfProcessors == 0)
       num_cpus = 1;
  else num_cpus = sys_info.dwNumberOfProcessors;
  num_cpus = min (num_cpus, MAX_CPUS);

  load_dynamic_table (dyn_funcs, DIM(dyn_funcs));

  if (p_CallNtPowerInformation)
  {
    /* Rewritten from:
     *   https://github.com/giampaolo/psutil/blob/master/psutil/_psutil_windows.c
     */
    PROCESSOR_POWER_INFORMATION  ppi [MAX_CPUS];
    DWORD     rc = (*p_CallNtPowerInformation) (_ProcessorInformation,
                                                NULL, 0,   /* No input buffer */
                                                &ppi, sizeof(ppi));
    if (rc == STATUS_SUCCESS)
    {
      unsigned cpu;
      double   MHz = 0.0;

      for (cpu = 0; cpu < num_cpus; cpu++)
          MHz += (double) ppi[cpu].CurrentMhz;

      MHz /= num_cpus;
      if (MHz > 1000.0)
           TRACE (2, "CPU speed: %.3f GHz\n", MHz/1000.0);
      else TRACE (2, "CPU speed: %.0f MHz\n", MHz);
    }
    else
      TRACE (1, "CallNtPowerInformation() failed: %s.\n", win_strerror(rc));
  }
  else
    TRACE (1, "CallNtPowerInformation() not present in \"powrprof.dll\".\n");
}

/**
 * Print some times (and CPU cycle counts) for a thread.
 * I.e. the WinPcap receiver thread.
 */
void print_thread_times (HANDLE thread)
{
  FILETIME ctime, etime, ktime, utime;
  double   life_span;

  cpu_init();

  if (thread == NULL)
  {
    TRACE (2, "  GetThreadTimes(NULL) called!.\n");
    return;
  }

  memset (&etime, '\0', sizeof(etime));  /* exit-time */

  if (!GetThreadTimes(thread, &ctime, &etime, &ktime, &utime))
  {
    DWORD err = GetLastError();
    TRACE (2, "  GetThreadTimes (%" ADDR_FMT ") %s.\n", ADDR_CAST(thread), win_strerror(err));
    return;
  }

  /* The thread has not yet exited.
   */
  if (CompareFileTime(&etime,&ctime) < 0)
  {
    if (p_GetSystemTimePreciseAsFileTime)
         (*p_GetSystemTimePreciseAsFileTime) (&etime);
    else GetSystemTimeAsFileTime (&etime);
  }

  /* If this is negative, the thread lived in kernel all the time.
   */
  life_span = FILETIME_to_sec (&etime) - FILETIME_to_sec (&ctime);
  if (life_span < 0.0)
     life_span = -life_span;

  C_printf ("  kernel-time: %.6fs, user-time: %.6fs, life-span: %.6fs",
            FILETIME_to_sec(&ktime), FILETIME_to_sec(&utime), life_span);

  if (p_QueryThreadCycleTime)
  {
    ULONG64 cycle_time;

    if (!(*p_QueryThreadCycleTime) (thread, &cycle_time))
         C_printf (", cycle-time: <failed>");
    else C_printf (", cycle-time: %s clocks", qword_str(cycle_time));
  }

  if (p_NtQueryInformationThread)
  {
    LARGE_INTEGER perf_count;
    NTSTATUS rc = (*p_NtQueryInformationThread) (
                      thread, ThreadPerformanceCount, &perf_count,
                      sizeof(perf_count), NULL);

    if (rc != STATUS_SUCCESS)
         C_printf (", perf-count: <fail %ld>", (long)rc);
    else C_printf (", perf-count: %s", qword_str(perf_count.QuadPart));
  }
  C_putc ('\n');
}

/**
 * Print some times for a process.
 */
void print_process_times (void)
{
  FILETIME cr_time, exit_time, krnl_time, usr_time;
  HANDLE   proc = OpenProcess (PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
                               FALSE, GetCurrentProcessId());
  if (!proc)
     return;

  if (GetProcessTimes(proc, &cr_time, &exit_time, &krnl_time, &usr_time))
  {
    const struct tm *tm;
    char   time_str [50];
    time_t ct      = FILETIME_to_time_t (&cr_time);
    uint64 fract_t = FILETIME_to_unix_epoch (&cr_time) % U64_SUFFIX(1000000);

    tm = localtime (&ct);
    if (tm)
         strftime (time_str, sizeof(time_str), "%Y%m%d/%H:%M:%S", tm);
    else strcpy (time_str, "??");

    /* 'exit_time' is not printed since the process has not exited yet.
     * Therefore it is zero.
     */
    C_printf ("\ncreation-time: %s.%06" U64_FMT ", kernel-time: %.6fs, user-time: %.6fs\n",
              time_str, fract_t, FILETIME_to_sec(&krnl_time), FILETIME_to_sec(&usr_time));
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

  cpu_init();

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

    C_printf ("CPU %lu:%s", (u_long)i, (i == 0) ? "\t\t\t  CPU clocks\n" : "\n");

    x = info[i].KernelTime.QuadPart - info[i].IdleTime.QuadPart;
    C_printf ("  KernelTime:     %18s\n", qword_str(x));

    x = info[i].IdleTime.QuadPart;
    C_printf ("  IdleTime:       %18s\n", qword_str(x));

    x = info[i].UserTime.QuadPart;
    C_printf ("  UserTime:       %18s\n", qword_str(x));

    x = info[i].DpcTime.QuadPart;
    C_printf ("  DpcTime:        %18s\n", qword_str(x));

    x = info[i].InterruptTime.QuadPart;
    C_printf ("  InterruptTime:  %18s\n", qword_str(x));
    C_printf ("  InterruptCount: %18s\n", dword_str(info[i].InterruptCount));
  }
}
