#ifndef _CPU_H
#define _CPU_H

/* Handy macro to both define and declare the function-pointer.
 */
#if defined(IN_CPU_C)  /* If we're compiling cpu.c */
  #define CPU_FUNC(ret, f, args)  typedef ret (WINAPI *func_##f) args; \
                                  func_##f p_##f = NULL
#else
  #define CPU_FUNC(ret, f, args)  typedef ret (WINAPI *func_##f) args; \
                                  extern func_##f p_##f
#endif

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

/* end <NTddk.h> stuff
 */

CPU_FUNC (BOOL, QueryThreadCycleTime,
                (HANDLE   thread_handle,
                 ULONG64 *cycle_time));

CPU_FUNC (NTSTATUS, NtQueryInformationThread,
                   (HANDLE           thread_handle,
                    THREADINFOCLASS  thread_information_class,
                    void            *thread_information,
                    ULONG            thread_information_length,
                    ULONG           *return_length));

CPU_FUNC (NTSTATUS, NtQuerySystemInformation,
                    (ULONG  system_information_class,
                     void  *system_information,
                     ULONG  system_information_length,
                     ULONG *return_length));

CPU_FUNC (void, GetSystemTimePreciseAsFileTime,  /* A Win 8+ function */
                (FILETIME *sys_time));

extern void print_thread_times (HANDLE thread);
extern void print_process_times (void);
extern void print_perf_times (void);

#endif /* _CPU_H */
