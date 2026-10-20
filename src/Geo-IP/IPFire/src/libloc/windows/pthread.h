#pragma once

#if defined(__GNUC__)
  #include_next <pthreads.h>
#else
  /*
   * Minimal '<pthread.h> for libloc on Windows (MSVC / clang-cl).
   */
  #include <windows.h>
  #include <process.h>

  typedef HANDLE  pthread_t;
  typedef HANDLE  pthread_mutex_t;

  #define pthread_create(tp, x, p, d)     ((*tp = (HANDLE)_beginthreadex(NULL, 0, p, d, 0, NULL)) == NULL ? -1 : 0)
  #define pthread_cancel(th)              (!TerminateThread(th, 0))
  #define pthread_join(th, p)             (WaitForSingleObject(th, INFINITE))
  #define pthread_self()                  (GetCurrentThread())

  #define pthread_mutex_init(mp, a)       ((*mp = CreateMutex(NULL, FALSE, NULL)) == NULL ? -1 : 0)
  #define pthread_mutex_destroy(mp)       (CloseHandle(*mp) == 0 ? -1 : 0)
  #define pthread_mutex_lock(mp)          (WaitForSingleObject(*mp, INFINITE) == WAIT_OBJECT_0 ? 0 : -1)
  #define pthread_mutex_unlock(mp)        (ReleaseMutex(*mp) == 0 ? -1 : 0)
#endif /* __GNUC__ */
