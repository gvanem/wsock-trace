/*
 * Various missing functions needed for libloc
 * on Windows. MSVC and clang-cl only.
 *
 * Only 'loc_clock_gettime()' and 'loc_memory()' gets
 * exported for use by 'bin/benchmark.exe'.
 *
 * The rest are for internal LIBLOC use.
 */
#include <string.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <errno.h>
#include <assert.h>
#include <intsafe.h>
#include <sys/mman.h>
#include <windows.h>
#include <psapi.h>     /* GetProcessMemoryInfo() */

#include <libloc/libloc.h>
#include <libloc/private.h>

#if 0
  #define DWORD_HI(x)  ((uint64_t)(x) >> 32)
  #define DWORD_LO(x)  ((x) & 0xffffffff)
#else
  #define DWORD_HI HIDWORD
  #define DWORD_LO LODWORD
#endif

static SYSTEM_INFO si;

/**
 * A small array of 'mmap()' return values we need to remember
 * until we call `munmap()` on the pointer.
 */
struct mmap_info {
       void  *map;   /* the value from 'MapViewOfFile()' */
       void  *rval;  /* the value we returned to caller of 'mmap()' */
     };
static struct mmap_info mmap_storage [10];

static void *mmap_remember (void *map, uint64_t offset);
static int   mmap_forget (void *map, struct mmap_info *info);

void *mmap (void *address, size_t length, int protection, int flags, int fd, off_t offset)
{
  void     *map = NULL;
  HANDLE    handle;
  HANDLE    fd_h = INVALID_HANDLE_VALUE;
  DWORD     access = 0;
  uint64_t  pstart, psize, poffset;

  (void) address;  /* unused args */
  (void) flags;

  if (fd > -1)
     fd_h = (HANDLE) _get_osfhandle (fd);

  if (si.dwAllocationGranularity == 0)
     GetNativeSystemInfo (&si);

  pstart  = (offset / si.dwAllocationGranularity) * si.dwAllocationGranularity;
  poffset = offset - pstart;
  psize   = poffset + length;

  /**
   * If `fd_h == INVALID_HANDLE_VALUE`, the `CreateFileMapping()` indicates that the
   * file mapping object will be backed by the system's paging file, rather than
   * an actual file on disk.
   */

  switch (protection)
  {
    case PROT_READ:
         handle = CreateFileMapping (fd_h, 0, PAGE_READONLY, 0, 0, NULL);
         access = FILE_MAP_READ;
         break;
    case PROT_WRITE:
         handle = CreateFileMapping (fd_h, 0, PAGE_READWRITE, 0, 0, NULL);
         access = FILE_MAP_WRITE;  /* Or FILE_MAP_COPY? */
         break;
    case PROT_READWRITE:
         handle = CreateFileMapping (fd_h, 0, PAGE_READWRITE, 0, 0, NULL);
         access = FILE_MAP_ALL_ACCESS;
         break;
    default:
         handle = INVALID_HANDLE_VALUE;
         break;
  }

  if (!handle || handle == INVALID_HANDLE_VALUE)
     map = MAP_FAILED;
  else
  {
    map = MapViewOfFile (handle, access, DWORD_HI(pstart), DWORD_LO(pstart), (SIZE_T)psize);
    CloseHandle (handle);
    if (!map)
       map = MAP_FAILED;
  }

  SetLastError (0);   /* clear any possible error from above */
  return mmap_remember (map, poffset);
}

int munmap (void *map, size_t length)
{
  struct mmap_info info;
  int    rc = 0;

  if (!mmap_forget(map, &info))
  {
    errno = EINVAL;
    rc = -1;
  }
  else if (!UnmapViewOfFile(info.map))
  {
    errno = EFAULT;
    SetLastError (0);
    rc = -1;
  }
  return (rc);
}

static void *mmap_remember (void *map, uint64_t offset)
{
  size_t i;

  if (map == MAP_FAILED)  /* never remember this */
  {
    errno = EFAULT;
    goto fail;
  }

  for (i = 0; i < _countof(mmap_storage); i++)
  {
    if (!mmap_storage[i].map)   /* use this vacant slot */
    {
      mmap_storage [i].map  = map;
      mmap_storage [i].rval = (char*)map + offset;
      return (mmap_storage[i].rval);
    }
  }
  errno = EAGAIN;

fail:
  return (MAP_FAILED); /* all buckets full */
}

static int mmap_forget (void *map, struct mmap_info *info)
{
  size_t i;

  for (i = 0; i < _countof(mmap_storage); i++)
  {
    if (map == mmap_storage[i].rval)
    {
      *info = mmap_storage [i];
      mmap_storage [i].map = NULL;   /* reuse this */
      SetLastError (0);
      return (1);
    }
  }
  return (0);  /* not found! */
}

/**
 * Get next token from string `*stringp`, where tokens are possibly empty
 * strings separated by characters from `delim`.
 *
 * Writes NULs into the string at `*stringp` to end tokens.
 *
 * `delim` need not remain constant from call to call.
 *
 * On return, `*stringp` points past the last `NUL` written (if there might
 * be further tokens), or is `NULL` (if there are definitely no more tokens).
 *
 * If `*stringp` is NULL, `strsep()` returns `NULL`.
 */
char *strsep (char **stringp, const char *delim)
{
  int         c, sc;
  char       *tok, *s = *stringp;
  const char *spanp;

  if (!s)
     return (NULL);

  for (tok = s;;)
  {
    c = *s++;
    spanp = delim;
    do
    {
      sc = *spanp++;
      if (sc == c)
      {
        if (c == '\0')
             s = NULL;
        else s[-1] = '\0';
        *stringp = s;
        return (tok);
      }
    }
    while (sc != 0);
  }
  return (NULL);
}

/**
 * Case-insensitive search for substring (`needle`) in
 * string `haystack`.
 */
char *strcasestr (const char *hay_stack, const char *needle)
{
  int i, lhay_stack, lneedle;

  lhay_stack = strlen (hay_stack);
  lneedle    = strlen (needle);
  for (i = 0; i < lhay_stack; i++)
  {
    if (!_strnicmp(hay_stack + i, needle, lneedle))
       return (char*) (hay_stack + i);
  }
  return (NULL);
}

/**
 * \def DELTA_EPOCH_SEC
 * Number of seconds from start of the Windows epoch
 * (Jan. 1, 1601) and to the Unix epoch (Jan. 1, 1970).
 */
#define DELTA_EPOCH_SEC  11644473600

/**
 * Return a Unix timestamp from a `struct tm`;
 * the inverse of function `gmtime()`.
 */
time_t timegm (struct tm *tm)
{
  time_t         ret;
  SYSTEMTIME     st;
  FILETIME       ft;
  ULARGE_INTEGER uli;

  memset (&st, '\0', sizeof(st));
  st.wYear   = (WORD) (tm->tm_year + 1900);
  st.wMonth  = (WORD) (tm->tm_mon + 1);
  st.wDay    = (WORD) tm->tm_mday;
  st.wHour   = (WORD) tm->tm_hour;
  st.wMinute = (WORD) tm->tm_min;
  st.wSecond = (WORD) tm->tm_sec;

  SystemTimeToFileTime (&st, &ft);
  uli.LowPart  = ft.dwLowDateTime;
  uli.HighPart = ft.dwHighDateTime;

  ret = (time_t) (uli.QuadPart / 10000000);
  ret -= DELTA_EPOCH_SEC;   /* from Win epoch to Unix epoch */
  ret += _timezone;         /* Is this correct? (since strptime() ignores time-zone) */
  return (ret);
}

/**
 * Return last error from Winsock as "WSAE: xxx"
 */
char *get_neterr (void)
{
  static char err_buf [30];
  strcpy (err_buf, "WSAE: ");
  return _itoa (WSAGetLastError(), err_buf + sizeof("WSAE: ")-1, 10);
}

int loc_clock_gettime (int clk_id, struct timespec *tp)
{
  uint64_t usec;
  FILETIME ft;

  assert (clk_id == CLOCK_MONOTONIC);

  /* Needs '_WIN32_WINNT >= _WIN32_WINNT_WIN8' (0x0602)
   */
  GetSystemTimePreciseAsFileTime (&ft);

  usec = ((uint64_t)ft.dwHighDateTime << 32) + ft.dwLowDateTime;
  usec /= 10;                        /* from 100 nano-sec periods to usec */
  usec -= DELTA_EPOCH_SEC * 100000;  /* from Win epoch to Unix epoch */

  tp->tv_sec  = (long) (usec / 1000000L);
  tp->tv_nsec = 1000 * (long) (usec % 1000000L);
  return (0);
}

void loc_memory (const char* what, const char* path1, const char* path2)
{
  PROCESS_MEMORY_COUNTERS_EX pmc;
  long rss;

  if (!GetProcessMemoryInfo(GetCurrentProcess(), (PROCESS_MEMORY_COUNTERS*)&pmc, sizeof(pmc)))
  {
    printf("Failed to retrieve memory info: %lu\n", GetLastError());
    return;
  }

  rss = pmc.PeakWorkingSetSize + pmc.PrivateUsage + pmc.WorkingSetSize; // is this correct?
  printf("%-44s %6.1f MiB of the database in memory\n", what, rss / 1024.0);

  (void) path1;
  (void) path2;
}

/*-
 * Copyright (c) 1997, 1998 The NetBSD Foundation, Inc.
 * All rights reserved.
 *
 * This code was contributed to The NetBSD Foundation by Klaus Klein.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *        This product includes software developed by the NetBSD
 *        Foundation, Inc. and its contributors.
 * 4. Neither the name of The NetBSD Foundation nor the names of its
 *    contributors may be used to endorse or promote products derived
 *    from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE NETBSD FOUNDATION, INC. AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE FOUNDATION OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * We do not implement alternate representations. However, we always
 * check whether a given modifier is allowed for a certain conversion.
 */
#define ALT_E          0x01
#define ALT_O          0x02
#define TM_YEAR_BASE   1900

#define LEGAL_ALT(x)   do {                     \
                         if (alt_format & ~(x)) \
                            return (0);         \
                       } while (0)

static int conv_num (const char **buf, int *dest, int llim, int ulim);

static const char *day[7] = { "Sunday", "Monday", "Tuesday", "Wednesday", "Thursday",
                               "Friday", "Saturday"
                            };
static const char *abday[7] = { "Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat" };
static const char *mon[12] = { "January", "February", "March", "April", "May", "June", "July",
                               "August", "September", "October", "November", "December"
                             };
static const char *abmon[12] = { "Jan", "Feb", "Mar", "Apr", "May", "Jun",
                                 "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"
                               };
static const char *am_pm[2] = { "AM", "PM" };

char *strptime (const char *buf, const char *fmt, struct tm *tm)
{
  char        c;
  const char *bp = buf;
  size_t      len = 0;
  int         alt_format, i, split_year = 0;

  while ((c = *fmt) != '\0')
  {
    /* Clear `alternate' modifier prior to new conversion. */
    alt_format = 0;

    /* Eat up white-space. */
    if (isspace(c))
    {
      while (isspace(*bp))
          bp++;
      fmt++;
      continue;
    }

    if ((c = *fmt++) != '%')
       goto literal;

again:
      switch (c = *fmt++)
      {
        case '%':   /* "%%" is converted to "%". */
literal:
             if (c != *bp++)
                return (0);
             break;

        /* "Alternative" modifiers. Just set the appropriate flag
         * and start over again.
         */
        case 'E':   /* "%E?" alternative conversion modifier. */
             LEGAL_ALT (0);
             alt_format |= ALT_E;
             goto again;

        case 'O':   /* "%O?" alternative conversion modifier. */
             LEGAL_ALT (0);
             alt_format |= ALT_O;
             goto again;

        /* "Complex" conversion rules, implemented through recursion.
         */
        case 'c':   /* Date and time, using the locale's format. */
             LEGAL_ALT (ALT_E);
             bp = strptime (bp, "%x %X", tm);
             if (!bp)
                return (0);
             break;

        case 'D':   /* The date as "%m/%d/%y". */
             LEGAL_ALT (0);
             bp = strptime (bp, "%m/%d/%y", tm);
             if (!bp)
                return (0);
             break;

        case 'R':   /* The time as "%H:%M". */
             LEGAL_ALT (0);
             bp = strptime (bp, "%H:%M", tm);
             if (!bp)
                return (0);
             break;

        case 'r':   /* The time in 12-hour clock representation. */
             LEGAL_ALT (0);
             bp = strptime (bp, "%I:%M:%S %p", tm);
             if (!bp)
                return (0);
             break;

        case 'T':   /* The time as "%H:%M:%S". */
             LEGAL_ALT (0);
             bp = strptime (bp, "%H:%M:%S", tm);
             if (!bp)
                return (0);
             break;

        case 'X':   /* The time, using the locale's format. */
             LEGAL_ALT (ALT_E);
             bp = strptime (bp, "%H:%M:%S", tm);
             if (!bp)
                return (0);
             break;

        case 'x':   /* The date, using the locale's format. */
             LEGAL_ALT (ALT_E);
             bp = strptime (bp, "%m/%d/%y", tm);
             if (!bp)
                return (0);
             break;

             /* "Elementary" conversion rules.
              */
        case 'A':   /* The day of week, using the locale's form. */
        case 'a':
             LEGAL_ALT (0);
             for (i = 0; i < 7; i++)
             {
               /* Full name. */
               len = strlen (day[i]);
               if (!_strnicmp(day[i], bp, len))
                  break;

               /* Abbreviated name. */
               len = strlen (abday[i]);
               if (!_strnicmp(abday[i], bp, len))
                  break;
             }
             /* Nothing matched. */
             if (i == 7)
                return (0);

             tm->tm_wday = i;
             bp += len;
             break;

        case 'B':   /* The month, using the locale's form. */
        case 'b':
        case 'h':
             LEGAL_ALT (0);
             for (i = 0; i < 12; i++)
             {
               /* Full name. */
               len = strlen (mon[i]);
               if (!_strnicmp(mon[i], bp, len))
                  break;

               /* Abbreviated name. */
               len = strlen (abmon[i]);
               if (!_strnicmp(abmon[i], bp, len))
                  break;
             }
             /* Nothing matched. */
             if (i == 12)
                return (0);
             tm->tm_mon = i;
             bp += len;
             break;

        case 'C':   /* The century number. */
             LEGAL_ALT (ALT_E);
             if (!conv_num(&bp, &i, 0, 99))
                return (0);

             if (split_year)
                tm->tm_year = (tm->tm_year % 100) + (i * 100);
             else
             {
               tm->tm_year = i * 100;
               split_year = 1;
             }
             break;

        case 'd':   /* The day of month. */
        case 'e':
             LEGAL_ALT (ALT_O);
             if (!conv_num(&bp, &tm->tm_mday, 1, 31))
                return (0);
             break;

        case 'k':   /* The hour (24-hour clock representation). */
             LEGAL_ALT (0);
             __attribute__((fallthrough));

        case 'H':
             LEGAL_ALT (ALT_O);
             if (!conv_num(&bp, &tm->tm_hour, 0, 23))
                return (0);
             break;

        case 'l':   /* The hour (12-hour clock representation). */
             LEGAL_ALT (0);
             __attribute__((fallthrough));

        case 'I':
             LEGAL_ALT (ALT_O);
             if (!conv_num(&bp, &tm->tm_hour, 1, 12))
                return (0);
             if (tm->tm_hour == 12)
                tm->tm_hour = 0;
             break;

        case 'j':   /* The day of year. */
             LEGAL_ALT (0);
             if (!conv_num(&bp, &i, 1, 366))
                return (0);
             tm->tm_yday = i - 1;
             break;

        case 'M':   /* The minute. */
             LEGAL_ALT (ALT_O);
             if (!conv_num(&bp, &tm->tm_min, 0, 59))
                return (0);
             break;

        case 'm':   /* The month. */
             LEGAL_ALT (ALT_O);
             if (!conv_num(&bp, &i, 1, 12))
                return (0);
             tm->tm_mon = i - 1;
             break;

        case 'p':   /* The locale's equivalent of AM/PM. */
             LEGAL_ALT (0);
             if (!_stricmp(am_pm[0], bp)) /* AM? */
             {
               if (tm->tm_hour > 11)
                  return (0);
               bp += strlen(am_pm[0]);
               break;
             }
             if (!_stricmp(am_pm[1], bp)) /* PM? */
             {
               if (tm->tm_hour > 11)
                   return (0);
               tm->tm_hour += 12;
               bp += strlen(am_pm[1]);
               break;
             }
             /* Nothing matched. */
             return (0);

        case 'S':   /* The seconds. */
             LEGAL_ALT (ALT_O);
             if (!conv_num(&bp, &tm->tm_sec, 0, 61))
                return (0);
             break;

        case 'U':   /* The week of year, beginning on sunday. */
        case 'W':   /* The week of year, beginning on monday. */
             LEGAL_ALT (ALT_O);

            /* XXX This is bogus, as we can not assume any valid
             * information present in the tm structure at this
             * point to calculate a real value, so just check the
             * range for now.
             */
             if (!conv_num(&bp, &i, 0, 53))
                return (0);
             break;

        case 'w':   /* The day of week, beginning on sunday. */
             LEGAL_ALT (ALT_O);
             if (!conv_num(&bp, &tm->tm_wday, 0, 6))
                return (0);
             break;

        case 'Y':   /* The year. */
             LEGAL_ALT (ALT_E);
             if (!conv_num(&bp, &i, 0, 9999))
                return (0);
             tm->tm_year = i - TM_YEAR_BASE;
             break;

        case 'y':   /* The year within 100 years of the epoch. */
             LEGAL_ALT (ALT_E | ALT_O);
             if (!conv_num(&bp, &i, 0, 99))
                return (0);

             if (split_year)
             {
               tm->tm_year = ((tm->tm_year / 100) * 100) + i;
               break;
             }
             split_year = 1;
             if (i <= 68)
                  tm->tm_year = i + 2000 - TM_YEAR_BASE;
             else tm->tm_year = i + 1900 - TM_YEAR_BASE;
             break;

        case 'n':   /* Any kind of white-space. */
        case 't':
             LEGAL_ALT (0);
             while (isspace(*bp))
                 bp++;
             break;

        default:    /* Unknown/unsupported conversion. */
             return (0);
    }
  }
  return ((char*)bp);
}

static int conv_num (const char **buf, int *dest, int llim, int ulim)
{
  int result = 0;
  int rulim = ulim;  /* The limit also determines the number of valid digits. */

  if (**buf < '0' || **buf > '9')
     return (0);

  do
  {
    result *= 10;
    result += *(*buf)++ - '0';
    rulim /= 10;
  }
  while ((result * 10 <= ulim) && rulim && **buf >= '0' && **buf <= '9');

  if (result < llim || result > ulim)
     return (0);

  *dest = result;
  return (1);
}

/*
 * Ripped from libpcap's 'missing/asprintf.c' and modified:
 *
 * vasprintf() and asprintf() for platforms with a C99-compliant
 * snprintf() - so that, if you format into a 1-byte buffer, it
 * will return how many characters it would have produced had
 * it been given an infinite-sized buffer.
 */
int vasprintf (char **strp, const char *format, va_list args)
{
  char   buf, *str;
  int    ret, len;
  size_t str_size;

  len = vsnprintf (&buf, sizeof(buf), format, args);
  if (len == -1)
  {
    *strp = NULL;
    return (-1);
  }

  str_size = len + 1;
  str = malloc (str_size);
  if (!str)
  {
    *strp = NULL;
    return (-1);
  }

  ret = vsnprintf (str, str_size, format, args);
  if (ret == -1)
  {
    free (str);
    *strp = NULL;
    return (-1);
  }

  *strp = str;
  return (ret);
}

int asprintf (char **strp, const char *format, ...)
{
  va_list args;
  int     ret;

  va_start (args, format);
  ret = vasprintf (strp, format, args);
  va_end (args);
  return (ret);
}

#if 0
/*
 * Handle '%m' format to show 'strerror(errno)' or 'WSAGetLastError()' values.
 * Called from 'loc_log() and 'log_stderr()' in 'libloc.c'.
 */
const char *handle_m_format (const char *fmt)
{
  static char buf [1000];
  const char *m_fmt = strstr("%m", fmt);
  char       *p = buf, *err;

  if (!m_fmt || strlen(fmt) > sizeof(buf) - 50)
     return (fmt);

  err = strerror(errno);
  if (!err || errno == 0)
     err = get_neterr();
  if (!err)
     err = "No error?!";

  memcpy(p, fmt, m_fmt - fmt);
  p += m_fmt - fmt;

  memcpy(p, err, strlen(err));
  p += strlen(err);

  memcpy(p, m_fmt + 2, strlen(m_fmt + 2));
  p += strlen(m_fmt + 2);
  *p = '\0';
  return (buf);
}
#endif