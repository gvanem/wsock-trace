/**
 * \file geoip-stub.c
 * \ingroup Geoip
 *
 * \brief
 * Simple stub-code for 'geoip.dll'. \n
 * Adds minimal stub-functions needed by `../ip2loc.c` etc.
 */
#include <stdint.h>
#include <errno.h>

#include "common.h"
#include "init.h"
#include "inet_util.h"

struct config_table g_cfg;

void debug_printf (const char *file, unsigned line, const char *fmt, ...)
{
  ARGSUSED (file);
  ARGSUSED (line);
  ARGSUSED (fmt);
}

const char *INET_util_get_ip_num (const struct in_addr *ip4, const struct in6_addr *ip6)
{
  ARGSUSED (ip4);
  ARGSUSED (ip6);
  return (NULL);
}

FILE *fopen_excl (const char *file, const char *mode)
{
  return fopen (file, mode);
}

const char *dword_str (DWORD val)
{
  static char buf[8][30];
  static int  idx = 0;
  char  *rc = buf [idx++];

  snprintf (rc, sizeof(buf[0]), "%lu", val);
  idx &= 7;
  return (rc);
}

/**
 * Format a date string from a `SYSTEMTIME*`.
 */
const char *get_date_str (const SYSTEMTIME *st)
{
  static char time [30];
  static char months [3*12] = { "JanFebMarAprMayJunJulAugSepOctNovDec" };
  snprintf (time, sizeof(time), "%02d %.3s %04d",
            st->wDay, months + 3*(st->wMonth-1), st->wYear);
  return (time);
}

/**
 * Removes the 1st end-of-line termination from a string.
 * Removes "\n" (Unix), "\r" (MacOS) or "\r\n" (DOS) terminations.
 */
char *str_rip (char *s)
{
  char *p;

  if ((p = strchr (s, '\n')) != NULL) *p = '\0';
  if ((p = strchr (s, '\r')) != NULL) *p = '\0';
  return (s);
}

/**
 * Return err-number and string for 'err'. Only use this with
 * GetLastError(). Remove trailing `[\r\n]`.
 */
char *win_strerror (DWORD err)
{
  static  char buf[512+20];
  char    err_buf[512], *p;
  HRESULT hr = 0;

  if (HRESULT_SEVERITY(err))
     hr = err;

  if (err == ERROR_SUCCESS)
     strcpy (err_buf, "No error");
  else
  if (!FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM, NULL, err,
                      LANG_NEUTRAL, err_buf, sizeof(err_buf)-1, NULL))
     strcpy (err_buf, "Unknown error");

  if (hr)
       snprintf (buf, sizeof(buf), "0x%08lX: %s", (u_long)hr, err_buf);
  else snprintf (buf, sizeof(buf), "%lu: %s", (u_long)err, err_buf);

  str_rip (buf);
  p = strrchr (buf, '.');
  if (p && p[1] == '\0')
     *p = '\0';
  return (buf);
}

BOOL WINAPI DllMain (HINSTANCE instDLL, DWORD reason, LPVOID reserved)
{
  ARGSUSED (instDLL);
  ARGSUSED (reserved);
  return (TRUE);
}
