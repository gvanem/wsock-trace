/**\file    in_addr.c
 * \ingroup inet_util
 *
 * \brief
 *  Convert network addresses to printable format.
 */

/* Copyright (c) 1996 by Internet Software Consortium.
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND INTERNET SOFTWARE CONSORTIUM DISCLAIMS
 * ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL INTERNET SOFTWARE
 * CONSORTIUM BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL
 * DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR
 * PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS
 * ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS
 * SOFTWARE.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#if defined(__CYGWIN__)
  /*
   * A hack to hide the different prototypes of 'InetNtopW()' in
   * various version of CygWin's <ws2tcpip.h>.
   */
  #define InetNtopW orig_InetNtopW
#endif

#include "common.h"
#include "init.h"
#include "in_addr.h"

/**
 * \todo
 * The `IPv6_leading_zeroes` variable should be a
 * "Thread Local Storage" variable.
 *
 * Print an IPv6 address with leading zeros in each 16-bit chunk. Like:
 * ```
 *  2001:0800::
 * ```
 *
 * and not like (which is default):
 * ```
 *  2001:800::
 * ```
 */
int IPv6_leading_zeroes = FALSE;

static const char hex_chars[] = "0123456789abcdef";

/* These are now locals:
 */
static char *_ws_inet_ntop4 (const u_char *src, char *dst, size_t size, int *err);
static char *_ws_inet_ntop6 (const u_char *src, char *dst, size_t size, int *err);
static int   _ws_inet_pton4 (const char *src, u_char *dst, int *err);
static int   _ws_inet_pton6 (const char *src, u_char *dst, int *err);

/**
 * Check if `str` is simply an IPv4 address.
 */
static BOOL is_ip4_addr (const char *str)
{
  int ch;

  while ((ch = *str++) != 0)
  {
    if (isdigit(ch) || ch == '.')
       continue;
    return (FALSE);
  }
  return (TRUE);
}

/**
 * This function is for internal use or to be used before
 * `load_ws2_funcs()` has dynamically loaded all needed Winsock functions.
 */
char *ws_inet_ntop (int family, const void *addr, char *result, size_t result_size, int *err)
{
  int err2;

  if (!err)
     err = &err2;
  *err = 0;

  if (family == AF_INET)
     return _ws_inet_ntop4 (addr, result, result_size, err);
  if (family == AF_INET6)
     return _ws_inet_ntop6 (addr, result, result_size, err);

  *err = WSAEAFNOSUPPORT;
  return (NULL);
}

/**
 * A more compact version of the above.
 */
char *ws_inet_ntop2 (int family, const void *addr)
{
  static char buf [MAX_IP6_SZ+1];
  PCSTR  rc = ws_inet_ntop (family, addr, buf, sizeof(buf), NULL);

  if (!rc)
     strcpy (buf, "??");
  return (buf);
}

/**
 * This function is for internal use or to be used before
 * `load_ws2_funcs()` has dynamically loaded all needed Winsock functions.
 */
int ws_inet_pton (int family, const char *addr, void *result, int *err)
{
  int err2;

  if (!err)
     err = &err2;
  *err = 0;

  if (family == AF_INET)
     return _ws_inet_pton4 (addr, result, err);
  if (family == AF_INET6)
     return _ws_inet_pton6 (addr, result, err);

  *err = WSAEAFNOSUPPORT;
  return (0);
}

/**
 * A more compact version of the above.
 */
int ws_inet_pton2 (int family, const char *addr, void *result)
{
  return ws_inet_pton (family, addr, result, NULL);
}


/**
 * Format an IPv4 address, more or less like `inet_ntoa()`.
 *
 * \retval `dst` (as a const)
 * \note
 *  - uses no statics
 *  - takes an `u_char*` and not an `in_addr` as input.
 *
 * \author Paul Vixie, 1996.
 */
static char *_ws_inet_ntop4 (const u_char *src, char *dst, size_t size, int *err)
{
  char tmp [sizeof("255.255.255.255")];

  if ((size_t)sprintf(tmp, "%u.%u.%u.%u", src[0], src[1], src[2], src[3]) > size)
  {
    *err = WSAEINVAL;
    return (NULL);
  }
  return strcpy (dst, tmp);
}

/**
 * Convert IPv6 binary address into presentation (printable) format.
 *
 * \author
 *  Paul Vixie, 1996.
 */
static char *_ws_inet_ntop6 (const u_char *src, char *dst, size_t size, int *err)
{
  /*
   * Note that int32_t and int16_t need only be "at least" large enough
   * to contain a value of the specified size.  On some systems, like
   * Crays, there is no such thing as an integer variable with 16 bits.
   * Keep this in mind if you think this function should have been coded
   * to use pointer overlays.  All the world's not a VAX.
   */
  char  tmp [MAX_IP6_SZ+1];
  char *tp;
  struct {
    long base;
    long len;
  } best, cur;
  u_long words [IN6ADDRSZ / INT16SZ];
  int    i;

  /* Preprocess:
   *  Copy the input (bytewise) array into a wordwise array.
   *  Find the longest run of 0x00's in src[] for :: shorthanding.
   */
  memset (words, 0, sizeof(words));
  for (i = 0; i < IN6ADDRSZ; i++)
      words[i/2] |= (src[i] << ((1 - (i % 2)) << 3));

  best.base = -1;
  best.len  = 0;
  cur.base  = -1;
  cur.len   = 0;

  for (i = 0; i < (IN6ADDRSZ / INT16SZ); i++)
  {
    if (words[i] == 0)
    {
      if (cur.base == -1)
      {
        cur.base = i;
        cur.len = 1;
      }
      else
        cur.len++;
    }
    else if (cur.base != -1)
    {
      if (best.base == -1 || cur.len > best.len)
         best = cur;
      cur.base = -1;
    }
  }
  if ((cur.base != -1) && (best.base == -1 || cur.len > best.len))
     best = cur;

  if (best.base != -1 && best.len < 2)
     best.base = -1;

  /* Format the result.
   */
  tp = tmp;
  for (i = 0; i < (IN6ADDRSZ / INT16SZ); i++)
  {
    /* Are we inside the best run of 0x00's?
     */
    if (best.base != -1 && i >= best.base && i < (best.base + best.len))
    {
      if (i == best.base)
         *tp++ = ':';
      continue;
    }

    /* Are we following an initial run of 0x00s or any real hex?
     */
    if (i != 0)
       *tp++ = ':';

    /* Is this address an encapsulated IPv4?
     */
    if (i == 6 && best.base == 0 &&
        (best.len == 6 || (best.len == 5 && words[5] == 0xffff)))
    {
      if (!_ws_inet_ntop4(src+12, tp, sizeof(tmp) - (tp - tmp), err))
         goto inval;
      tp += strlen (tp);
      break;
    }
    if (IPv6_leading_zeroes)
         tp += sprintf (tp, "%04lx", words[i]);
    else tp += sprintf (tp, "%lx", words[i]);
  }

  /* Was it a trailing run of 0x00's?
   */
  if (best.base != -1 && (best.base + best.len) == (IN6ADDRSZ / INT16SZ))
     *tp++ = ':';
  *tp++ = '\0';

  /* Check for overflow, copy, and we're done.
   */
  if ((size_t)(tp - tmp) <= size)
     return strcpy (dst, tmp);

inval:
  *err = WSAEINVAL;
  return (NULL);
}

/**
 * Like `inet_aton()` but without all the hexadecimal and shorthand.
 *
 * \retval 1 if `src` is a valid dotted quad
 * \retval 0 if `src` is not a valid dotted quad.
 *
 * \note
 *   does not touch `dst` unless it's returning 1.
 *
 * \author
 *   Paul Vixie, 1996.
 */
static int _ws_inet_pton4 (const char *src, u_char *dst, int *err)
{
  static const char digits[] = "0123456789";
  int    saw_digit, octets, ch;
  u_char tmp[INADDRSZ];
  u_char *tp;

  saw_digit = 0;
  octets = 0;
  *(tp = tmp) = '\0';

  while ((ch = *src++) != '\0')
  {
    const char *pch = strchr (digits, ch);

    if (pch)
    {
      u_int New = (u_int) ((*tp * 10) + (pch - digits));

      if (New > 255)
         goto inval;
      *tp = New;
      if (!saw_digit)
      {
        if (++octets > 4)
           goto inval;
        saw_digit = 1;
      }
    }
    else if (ch == '.' && saw_digit)
    {
      if (octets == 4)
         goto inval;
      *++tp = '\0';
      saw_digit = 0;
    }
    else
      goto inval;
  }

  if (octets >= 4)
  {
    memcpy (dst, tmp, INADDRSZ);
    return (1);
  }
inval:
  *err = WSAEINVAL;
  return (0);
}

/**
 * Convert presentation level address to network order binary form.
 *
 * \retval 1 if `src` is a valid [RFC1884 2.2] address.
 * \retval 0 otherwise.
 * \note
 *   - does not touch `dst` unless it's returning 1.
 *   - `::` in a full address is silently ignored.
 *
 * \author Paul Vixie, 1996.
 * \n\b credit: inspired by Mark Andrews.
 */
static int _ws_inet_pton6 (const char *src, u_char *dst, int *err)
{
  u_char  tmp [IN6ADDRSZ];
  u_char *endp, *colonp, *tp = tmp;
  const   char *curtok;
  int     ch, saw_xdigit;
  u_int   val;

  if (is_ip4_addr(src)) /* A plain IPv4 address is illegal here */
     goto inval;

  memset (tmp, 0, sizeof(tmp));
  endp   = tmp + sizeof(tmp);
  colonp = NULL;

  /* Leading :: requires some special handling.
   */
  if (*src == ':' && *++src != ':')
     goto inval;

  curtok = src;
  saw_xdigit = 0;
  val = 0;

  while ((ch = *src++) != '\0')
  {
    const char *pch;

    ch = tolower (ch);
    pch = strchr (hex_chars, ch);
    if (pch)
    {
      val <<= 4;
      val |= (pch - hex_chars);
      if (val > 0xffff)
         goto inval;
      saw_xdigit = 1;
      continue;
    }
    if (ch == ':')
    {
      curtok = src;
      if (!saw_xdigit)
      {
        if (colonp)
           goto inval;
        colonp = tp;
        continue;
      }
      if (tp + INT16SZ > endp)
         goto toolong;

      *tp++ = (u_char) (val >> 8) & 0xff;
      *tp++ = (u_char) (val & 0xff);
      saw_xdigit = 0;
      val = 0;
      continue;
    }
    if (ch == '.' && ((tp + INADDRSZ) <= endp) &&
        _ws_inet_pton4(curtok, tp, err) > 0)
    {
      tp += INADDRSZ;
      saw_xdigit = 0;
      break;     /* '\0' was seen by _ws_inet_pton4(). */
    }
    goto inval;
  }

  if (saw_xdigit)
  {
    if (tp + INT16SZ > endp)
       goto toolong;
    *tp++ = (u_char) (val >> 8) & 0xff;
    *tp++ = (u_char) val & 0xff;
  }

  if (colonp)
  {
    /*
     * Since some memmove()'s erroneously fail to handle
     * overlapping regions, we'll do the shift by hand.
     */
    const int n = (int) (tp - colonp);
    int   i;

    for (i = 1; i <= n; i++)
    {
      endp[-i] = colonp[n-i];
      colonp[n-i] = '\0';
    }
    tp = endp;
  }

  if (tp != endp)
     goto toolong;

  memcpy (dst, tmp, IN6ADDRSZ);
  return (1);

inval:
  *err = WSAEINVAL;
  return (0);

toolong:
  *err = WSAENAMETOOLONG;
  return (0);
}

/**
 * \struct fake_sockaddr_un
 * This is in `<afunix.h>` on recent SDK's.
 */
struct fake_sockaddr_un {
       short sun_family;       /* AF_UNIX */
       char  sun_path [108];   /* pathname */
     };
#define sockaddr_un fake_sockaddr_un

/**
 * Instead of calling `WSAAddressToStringA()` for `AF_INET`, `AF_INET6`
 * and `AF_UNIX` addresses, we do it ourself.
 *
 * This function returns the address *and* the port if the
 * `sockaddr_in::sin_port` (or `sockaddr_in6::sin6_port`) is set.
 * Like:
 *  \li `127.0.0.1:1234` or
 *  \li `[aa:bb::ff]:1234`
 *
 * \param[in] sa   the `struct sockaddr *` to format a string from.
 */
char *ws_sockaddr_ntop (const struct sockaddr *sa)
{
  const struct sockaddr_in  *sa4 = (const struct sockaddr_in*) sa;
  const struct sockaddr_in6 *sa6 = (const struct sockaddr_in6*) sa;
  const struct sockaddr_un  *su  = (const struct sockaddr_un*) sa;
  static char buf [MAX_IP6_SZ+MAX_PORT_SZ+3];
  char       *end;

  if (!sa4)
     return ("<NULL>");

  if (sa4->sin_family == AF_INET)
  {
    _ws_inet_ntop4 ((u_char*)&sa4->sin_addr, buf, sizeof(buf), NULL);
    if (sa4->sin_port)
    {
     end = strchr (buf, '\0');
     *end++ = ':';
      _itoa (swap16(sa4->sin_port), end, 10);
    }
    return (buf);
  }

  if (sa4->sin_family == AF_INET6)
  {
    buf[0] = '[';
    _ws_inet_ntop6 ((u_char*)&sa6->sin6_addr, buf+1, sizeof(buf)-1, NULL);
    end = strchr (buf, '\0');
    *end++ = ']';
    if (sa6->sin6_port)
    {
      *end++ = ':';
      _itoa (swap16(sa6->sin6_port), end, 10);
    }
    return (buf);
  }

  if (sa4->sin_family == AF_UNIX)
  {
    const wchar_t *path = (const wchar_t*) &su->sun_path;

    if (!su->sun_path[0])
         strcpy (buf, "abstract");
    else if (su->sun_path[0] && su->sun_path[1])
         _strlcpy (buf, su->sun_path, sizeof(buf));
    else if (WideCharToMultiByte(CP_ACP, 0, path, (int)wcslen(path), buf, (int)sizeof(buf), NULL, NULL) == 0)
         strcpy (buf, "??");
    return (buf);
  }
  return ("??");
}
