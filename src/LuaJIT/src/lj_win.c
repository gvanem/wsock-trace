
#include "lj_win.h"

#if defined(_WIN32)
#include <windows.h>

static HANDLE stdout_hnd = INVALID_HANDLE_VALUE;
static CONSOLE_SCREEN_BUFFER_INFO console_info;
static int trace_level = -1;

void ljit_set_color (int color)
{
  if (stdout_hnd != INVALID_HANDLE_VALUE)
     SetConsoleTextAttribute (stdout_hnd, (console_info.wAttributes & ~7) |
                             (FOREGROUND_INTENSITY | FOREGROUND_GREEN));
}

void ljit_restore_color (void)
{
  if (stdout_hnd != INVALID_HANDLE_VALUE)
     SetConsoleTextAttribute (stdout_hnd, console_info.wAttributes);
}

int *ljit_trace_level (void)
{
  return (&trace_level);
}

int ljit_trace_init (void)
{
  const char *env;

  if (trace_level == -1)
  {
    trace_level = 0;
    env = getenv("LUA_TRACE");
    if (env)
    {
      trace_level = *env - '0';
      if (trace_level > 0 && trace_level <= 9)
      {
        stdout_hnd = GetStdHandle (STD_OUTPUT_HANDLE);
        GetConsoleScreenBufferInfo (stdout_hnd, &console_info);
      }
    }
  }
  return (trace_level);
}
#endif /* _WIN32 */

