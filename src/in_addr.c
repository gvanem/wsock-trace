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

#include "common.h"
#include "in_addr.h"

/* \todo: these publics should be "Thread Local" variables.
 */
BOOL call_WSASetLastError = TRUE;
BOOL leading_zeroes       = FALSE;

static const char hex_chars[] = "0123456789abcdef";

/**
 * Check if `str` is simply an IPv4 address.
 */
BOOL is_ip4_addr (const char *str)
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
 * Convert a network format address to presentation format.
 *
 * \retval pointer to presentation format address (`dst`),
 * \retval NULL on error (see `WSAGetLastError()`).
 *
 * \author Paul Vixie, 1996.
 */
/* EXPORT */ INET_NTOP_RET WINAPI inet_ntop (INT af, INET_NTOP_ADDR src, PSTR dst, size_t size)
{
  switch (af)
  {
    case AF_INET:
         return wsock_trace_inet_ntop4 ((const u_char*)src, dst, size);
    case AF_INET6:
         return wsock_trace_inet_ntop6 ((const u_char*)src, dst, size);
    default:
         if (call_WSASetLastError)
            WSASetLastError (WSAEAFNOSUPPORT);
         return (NULL);
  }
}

/**
 * Convert from presentation format (which usually means ASCII printable)
 * to network format (which is usually some kind of binary format).
 *
 * \retval 1  the address was valid for the specified address family.
 * \retval 0  the address wasn't valid (`dst` is untouched in this case).
 * \retval -1 some other error occurred (`dst` is untouched in this case, too).
 *
 * \author Paul Vixie, 1996.
 */
EXPORT int WINAPI inet_pton (int af, const char *src, void *dst)
{
  switch (af)
  {
    case AF_INET:
         return wsock_trace_inet_pton4 (src, (u_char*)dst);
    case AF_INET6:
         return wsock_trace_inet_pton6 (src, (u_char*)dst);
    default:
         if (call_WSASetLastError)
            WSASetLastError (WSAEAFNOSUPPORT);
         return (-1);
  }
}

/**
 * inet_ntop() + inet_pton() for internal use.
 */
char *wsock_trace_inet_ntop (int family, const void *addr, char *result, size_t result_size)
{
  return (char*) inet_ntop (family, (INET_NTOP_ADDR)addr, result, result_size);
}

int wsock_trace_inet_pton (int family, const char *addr, void *result)
{
  return inet_pton (family, addr, result);
}

/**
 * These may be needed by some Win-Vista+ applications
 */
EXPORT int WINAPI InetPtonW (int family, PCWSTR waddr, void *waddr_dest)
{
  char addr [INET6_ADDRSTRLEN];

  switch (family)
  {
    case AF_INET:
         snprintf (addr, sizeof(addr), "%S", waddr);
         return wsock_trace_inet_pton4 (addr, (u_char*)waddr_dest);
    case AF_INET6:
         snprintf (addr, sizeof(addr), "%S", waddr);
         return wsock_trace_inet_pton6 (addr, (u_char*)waddr_dest);
    default:
         WSASetLastError (WSAEAFNOSUPPORT);
         /* fall through */
  }
  return (-1);
}

EXPORT PCWSTR WINAPI InetNtopW (int family, const void *addr, PWSTR res_buf, size_t res_buf_size)
{
  char buf [INET6_ADDRSTRLEN];

  if (!inet_ntop(family, (INET_NTOP_ADDR)addr, buf, sizeof(buf)))
      return (NULL);

  if (!MultiByteToWideChar(CP_ACP, 0, buf, -1, res_buf, res_buf_size))
     return (NULL);
  return (res_buf);
}

char *_wsock_trace_inet_ntop (int family, const void *addr, char *result, size_t result_size)
{
  BOOL save = call_WSASetLastError;
  char *rc;

  call_WSASetLastError = FALSE;
  rc = (char*) inet_ntop (family, (INET_NTOP_ADDR)addr, result, result_size);
  call_WSASetLastError = save;
  return (rc);
}

int _wsock_trace_inet_pton (int family, const char *addr, void *result)
{
  BOOL save = call_WSASetLastError;
  int  rc;

  call_WSASetLastError = FALSE;
  rc = inet_pton (family, addr, result);
  call_WSASetLastError = save;
  return (rc);
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
const char *wsock_trace_inet_ntop4 (const u_char *src, char *dst, size_t size)
{
  char tmp [sizeof("255.255.255.255")];

  if ((size_t)sprintf(tmp,"%u.%u.%u.%u",src[0],src[1],src[2],src[3]) > size)
  {
    if (call_WSASetLastError)
       WSASetLastError (WSAEINVAL);
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
const char *wsock_trace_inet_ntop6 (const u_char *src, char *dst, size_t size)
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
      if (!wsock_trace_inet_ntop4(src+12, tp, sizeof(tmp) - (tp - tmp)))
         goto inval;
      tp += strlen (tp);
      break;
    }
    if (leading_zeroes)
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
  if (call_WSASetLastError)
     WSASetLastError (WSAEINVAL);
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
int wsock_trace_inet_pton4 (const char *src, u_char *dst)
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
  if (call_WSASetLastError)
     WSASetLastError (WSAEINVAL);
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
int wsock_trace_inet_pton6 (const char *src, u_char *dst)
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
        wsock_trace_inet_pton4(curtok,tp) > 0)
    {
      tp += INADDRSZ;
      saw_xdigit = 0;
      break;     /* '\0' was seen by inet_pton4(). */
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
  if (call_WSASetLastError)
     WSASetLastError (WSAEINVAL);
  return (0);

toolong:
  if (call_WSASetLastError)
     WSASetLastError (WSAENAMETOOLONG);
  return (0);
}
