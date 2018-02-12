/**\file inet_util.c
 *
 * \brief
 *   Various functions for downloading files via WinInet.dll and
 *   checking of address types.
 *
 * inet_util.c - Part of Wsock-Trace.
 */
#if defined(__WATCOMC__)
  /*
   * Required to define 'IN6_IS_ADDR_LOOPBACK()' etc. in
   * OpenWatcom's <ws2ipdef.h>.
   */
  #undef  NTDDI_VERSION
  #define NTDDI_VERSION 0x05010000
#endif

#include <windows.h>
#include <wininet.h>
#include <limits.h>

#include "common.h"
#include "init.h"
#include "in_addr.h"
#include "inet_util.h"

#ifndef IN4_CLASSD
#define IN4_CLASSD(i) (((LONG)(i) & 0x000000F0) == 0x000000E0)
#endif

/*
 * Fix for building with 'gcc -O0' and the GCC 'extern __inline__'
 * insanity.
 */
#if defined(__GNUC__) && defined(__NO_INLINE__)   /* -O0 */
  int IN6_IS_ADDR_LOOPBACK (const struct in6_addr *a)
  {
    return ((a->s6_words[0] == 0) && (a->s6_words[1] == 0) &&
            (a->s6_words[2] == 0) && (a->s6_words[3] == 0) &&
            (a->s6_words[4] == 0) && (a->s6_words[5] == 0) &&
            (a->s6_words[6] == 0) && (a->s6_words[7] == 0x0100));
  }

  int IN6_IS_ADDR_LINKLOCAL (const struct in6_addr *a)
  {
    return ((a->s6_bytes[0] == 0xFE) && ((a->s6_bytes[1] & 0xC0) == 0x80));
  }

  int IN6_IS_ADDR_SITELOCAL (const struct in6_addr *a)
  {
    return ((a->s6_bytes[0] == 0xFE) && ((a->s6_bytes[1] & 0xC0) == 0xC0));
  }

  int IN6_IS_ADDR_V4MAPPED (const struct in6_addr *a)
  {
    return ((a->s6_words[0] == 0) && (a->s6_words[1] == 0) &&
            (a->s6_words[2] == 0) && (a->s6_words[3] == 0) &&
            (a->s6_words[4] == 0) && (a->s6_words[5] == 0xFFFF));
  }

  int IN6_IS_ADDR_V4COMPAT (const struct in6_addr *a)
  {
    return ((a->s6_words[0] == 0) && (a->s6_words[1] == 0) &&
            (a->s6_words[2] == 0) && (a->s6_words[3] == 0) &&
            (a->s6_words[4] == 0) && (a->s6_words[5] == 0) &&
            !((a->s6_words[6] == 0) && (a->s6_addr[14] == 0) &&
             ((a->s6_addr[15] == 0) || (a->s6_addr[15] == 1))));
  }
#endif

/* Handy macro to both define and declare the function-pointer.
 */
#define INET_FUNC(ret, f, args)  typedef ret (WINAPI *func_##f) args; \
                                 static func_##f p_##f = NULL

/*
 * Download a single file using the WinInet API.
 * Load WinInet.dll dynamically.
 */
INET_FUNC (HINTERNET, InternetOpenA, (const char *user_agent,
                                      DWORD       access_type,
                                      const char *proxy_name,
                                      const char *proxy_bypass,
                                      DWORD       flags));

INET_FUNC (HINTERNET, InternetOpenUrlA, (HINTERNET   hnd,
                                         const char *url,
                                         const char *headers,
                                         DWORD       headers_len,
                                         DWORD       flags,
                                         DWORD_PTR   context));

INET_FUNC (BOOL, InternetGetLastResponseInfoA, (DWORD *err_code,
                                                char  *err_buff,
                                                DWORD *err_buff_len));

INET_FUNC (BOOL, InternetReadFile, (HINTERNET hnd,
                                    void     *buffer,
                                    DWORD     num_bytes_to_read,
                                    DWORD    *num_bytes_read));

INET_FUNC (BOOL, InternetCloseHandle, (HINTERNET handle));

#define ADD_VALUE(func)   { 0, NULL, "wininet.dll", #func, (void**)&p_##func }

static struct LoadTable funcs[] = {
                        ADD_VALUE (InternetOpenA),
                        ADD_VALUE (InternetOpenUrlA),
                        ADD_VALUE (InternetGetLastResponseInfoA),
                        ADD_VALUE (InternetReadFile),
                        ADD_VALUE (InternetCloseHandle)
                      };

/**
 * Return error-string for 'err' from wininet.dll.
 *
 * Try to get a more detailed error-code and text from
 * the server response using 'InternetGetLastResponseInfoA()'.
 */
static const char *wininet_strerror (DWORD err)
{
  HMODULE mod = GetModuleHandle ("wininet.dll");
  char    buf[512];

  if (mod && mod != INVALID_HANDLE_VALUE &&
      FormatMessageA (FORMAT_MESSAGE_FROM_HMODULE,
                      mod, err, MAKELANGID(LANG_NEUTRAL,SUBLANG_DEFAULT),
                      buf, sizeof(buf), NULL))
  {
    static char err_buf[512];
    char   wininet_err_buf[200];
    char  *p;
    DWORD  wininet_err = 0;
    DWORD  wininet_err_len = sizeof(wininet_err_buf)-1;

    str_rip (buf);
    p = strrchr (buf, '.');
    if (p && p[1] == '\0')
       *p = '\0';

    p = err_buf;
    p += snprintf (err_buf, sizeof(err_buf), "%lu: %s", (u_long)err, buf);

    if (p_InternetGetLastResponseInfoA &&
        (*p_InternetGetLastResponseInfoA)(&wininet_err,wininet_err_buf,&wininet_err_len) &&
        wininet_err > INTERNET_ERROR_BASE && wininet_err <= INTERNET_ERROR_LAST)
    {
      snprintf (p, (size_t)(p-err_buf), " (%lu/%s)", (u_long)wininet_err, wininet_err_buf);
      p = strrchr (p, '.');
      if (p && p[1] == '\0')
         *p = '\0';
    }
    return (err_buf);
  }
  return win_strerror (err);
}

/**
 * Download a file from url using dynamcally loaded functions
 * from wininet.dll.
 *
 * \param[in] file the file to write to.
 * \param[in] url  the URL to retrieve from.
 */
DWORD INET_util_download_file (const char *file, const char *url)
{
  DWORD       rc    = 0;
  DWORD       flags = INTERNET_FLAG_NO_UI;
  HINTERNET   h1    = NULL;
  HINTERNET   h2    = NULL;
  FILE       *fil   = NULL;
  DWORD       access_type  = INTERNET_OPEN_TYPE_DIRECT;
  const char *proxy_name   = NULL;
  const char *proxy_bypass = NULL;

  if (load_dynamic_table(funcs, DIM(funcs)) != DIM(funcs))
  {
    TRACE (0, "Failed to load needed WinInet.dll functions.\n");
    return (0);
  }

  if (g_cfg.geoip_proxy && g_cfg.geoip_proxy[0])
  {
    proxy_name   = g_cfg.geoip_proxy;
    proxy_bypass = "<local>";
    access_type  = INTERNET_OPEN_TYPE_PROXY;
  }

  TRACE (2, "Calling InternetOpenA(): proxy: %s, URL: %s.\n",
         proxy_name ? proxy_name : "<none>", url);

  h1 = (*p_InternetOpenA) ("Wsock-trace", access_type, proxy_name, proxy_bypass, 0);
  if (!h1)
  {
    TRACE (0, "InternetOpenA() failed: %s.\n", wininet_strerror(GetLastError()));
    goto quit;
  }

  h2 = (*p_InternetOpenUrlA) (h1, url, NULL, 0, flags, (DWORD_PTR)0);
  if (!h2)
  {
    TRACE (0, "InternetOpenA() failed: %s.\n", wininet_strerror(GetLastError()));
    goto quit;
  }

  fil = fopen (file, "w+b");

  while (1)
  {
    char  buf [4000];
    DWORD read = 0;

    if (!(*p_InternetReadFile)(h2, &buf, sizeof(buf), &read) || read == 0)
       break;
    fwrite (buf, 1, (size_t)read, fil);
    rc += read;
  }

  TRACE (2, "INET_util_download_file (%s) -> rc: %lu\n", file, DWORD_CAST(rc));

quit:
  if (fil)
     fclose (fil);

  if (h2)
    (*p_InternetCloseHandle) (h2);
  if (h1)
    (*p_InternetCloseHandle) (h1);

  unload_dynamic_table (funcs, DIM(funcs));
  return (rc);
}

int INET_util_touch_file (const char *file)
{
  struct stat st;
  int    rc;

  stat (file, &st);
  TRACE (2, "touch_file: %s", ctime(&st.st_mtime));
  rc = _utime (file, NULL);
  stat (file, &st);
  TRACE (2, "         -> %s", ctime(&st.st_mtime));
  return (rc);
}

/*
 * Taken from:
 *   ettercap -- IP address management
 *
 *  Copyright (C) ALoR & NaGA
 *
 * ... and rewritten.
 *
 * return true if an IPv4/IPv6 address is 0.0.0.0 or 0::
 */
int INET_util_addr_is_zero (const struct in_addr *ip4, const struct in6_addr *ip6)
{
  if (ip4)
  {
    if (!memcmp(ip4, "\x00\x00\x00\x00", sizeof(*ip4)))
       return (1);
  }
  else if (ip6)
  {
    if (!memcmp(ip6, "\x00\x00\x00\x00\x00\x00\x00\x00"   /* IN6_IS_ADDR_UNSPECIFIED() */
                     "\x00\x00\x00\x00\x00\x00\x00\x00", sizeof(*ip6)))
       return (1);
  }
  return (0);
}

/*
 * returns 1 if the ip is multicast
 * returns 0 if not
 */
int INET_util_addr_is_multicast (const struct in_addr *ip4, const struct in6_addr *ip6)
{
  if (ip4)
  {
    if (IN4_CLASSD(ip4->s_addr))  /* 224.0.0.0/4, Global multicast */
       return (1);
  }
  else if (ip6)
  {
    if (ip6->s6_bytes[0] == 0xFF) /* ff00::/8, Global multicast */
       return (1);
  }
  return (0);
}

int INET_util_addr_is_special (const struct in_addr *ip4, const struct in6_addr *ip6, const char **remark)
{
  if (ip4)
  {
    /* 240.0.0.0/4, https://whois.arin.net/rest/net/NET-240-0-0-0-0
     */
    if (ip4->S_un.S_un_b.s_b1 >= 240)
    {
      if (ip4->S_un.S_un_b.s_b1 == 255)
           *remark = "Broadcast";
      else *remark = "Future use";
      return (1);
    }

    /* 169.254.0.0/16, https://whois.arin.net/rest/net/NET-169-254-0-0-1
     */
    if (ip4->S_un.S_un_b.s_b1 == 169 && ip4->S_un.S_un_b.s_b2 == 254)
    {
      *remark = "Link Local";
      return (1);
    }

    /* 100.64.0.0/10, https://whois.arin.net/rest/net/NET-100-64-0-0-1
     */
    if (ip4->S_un.S_un_b.s_b1 == 100 &&
        (ip4->S_un.S_un_b.s_b2 >= 64 && ip4->S_un.S_un_b.s_b2 <= 127))
    {
      *remark = " Shared Address Space";
      return (1);
    }
  }
  else if (ip6)
  {
    if (IN6_IS_ADDR_LOOPBACK(ip6))
    {
      *remark = "Loopback";
      return (1);
    }
    if (IN6_IS_ADDR_LINKLOCAL(ip6))
    {
      *remark = "Link Local";
      return (1);
    }
    if (IN6_IS_ADDR_SITELOCAL(ip6))
    {
      *remark = "Site Local";
      return (1);
    }
    if (IN6_IS_ADDR_V4COMPAT(ip6))
    {
      *remark = "IPv4 compatible";
      return (1);
    }
    if (IN6_IS_ADDR_V4MAPPED(ip6))
    {
      *remark = "IPv4 mapped";
      return (1);
    }

    /* Teredo in RFC 4380 is 2001:0::/32
     * http://www.ipuptime.net/Teredo.aspx
     */
    if (ip6->s6_bytes[0] == 0x20 &&
        ip6->s6_bytes[1] == 0x01 &&
        ip6->s6_bytes[2] == 0x00)
    {
      *remark = "Teredo";
      return (1);
    }

    /* Old WinXP Teredo prefix, 3FFE:831F::/32
     * https://technet.microsoft.com/en-us/library/bb457011.aspx
     */
    if (ip6->s6_bytes[0] == 0x3F && ip6->s6_bytes[1] == 0xFE &&
        ip6->s6_bytes[2] == 0x83 && ip6->s6_bytes[3] == 0x1F)
    {
      *remark = "Teredo old";
      return (1);
    }
  }
  *remark = NULL;
  return (0);
}

/*
 * returns 1 if the ip is a Global Unicast
 * returns 0 if not
 */
int INET_util_addr_is_global (const struct in_addr *ip4, const struct in6_addr *ip6)
{
   if (ip4)
   {
     /* Global for IPv4 means not status "RESERVED" by IANA
      */
     if (ip4->S_un.S_un_b.s_b1 != 0x0  &&                       /* not 0/8        */
         ip4->S_un.S_un_b.s_b1 != 0x7F &&                       /* not 127/8      */
         ip4->S_un.S_un_b.s_b1 != 0x0A &&                       /* not 10/8       */
         (swap16(ip4->S_un.S_un_w.s_w1) & 0xFFF0) != 0xAC10 &&  /* not 172.16/12  */
         swap16(ip4->S_un.S_un_w.s_w1) != 0xC0A8 &&             /* not 192.168/16 */
         !INET_util_addr_is_multicast(ip4,NULL))                /* not 224/3      */
        return (1);
   }
   else if (ip6)
   {
     /*
      * As IANA does not apply masks > 8-bit for Global Unicast block,
      * only the first 8-bit are significant for this test.
      */
     if ((ip6->s6_bytes[0] & 0xE0) == 0x20)
     {
       /*
        * This may be extended in future as IANA assigns further ranges
        * to Global Unicast.
        */
       return (1);
     }
   }
   return (0);
}

/*
 * Return an IP-number as a string.
 */
const char *INET_util_get_ip_num (const struct in_addr *ip4, const struct in6_addr *ip6)
{
  static char buf [4*sizeof("65535")+1];
  const u_long *dword;

  if (ip4)
      return _ultoa (swap32(ip4->s_addr), buf, 10);
  if (ip6)
  {
    dword = (const u_long*) &ip6->s6_bytes[0];
    snprintf (buf, sizeof(buf), "%lu%lu%lu%lu",
              dword[0], dword[1], dword[2], dword[3]);
  }
  else
  {
    buf[0] = '?';
    buf[1] = '\0';
  }
  return (buf);
}

/*
 * Figure out the prefix length when given an IPv4 "low" and "high" address.
 */
int INET_util_network_len32 (DWORD hi, DWORD lo)
{
  DWORD m = (hi - lo);

  m = (m & 0x55555555) + ((m & 0xAAAAAAAA) >> 1);
  m = (m & 0x33333333) + ((m & 0xCCCCCCCC) >> 2);
  m = (m & 0x0F0F0F0F) + ((m & 0xF0F0F0F0) >> 4);
  m = (m & 0x00FF00FF) + ((m & 0xFF00FF00) >> 8);
  m = (m & 0x0000FFFF) + ((m & 0xFFFF0000) >> 16);
  return (m);
}

/*
 * Figure out the prefix length by checking the common '1's in each
 * of the 16 BYTEs in IPv6-addresses '*a' and '*b'.
 */
int INET_util_network_len128 (const struct in6_addr *a, const struct in6_addr *b)
{
  int  i, j, bits = 0;
  BYTE v;

  for (i = 15; i >= 0; i--)
  {
    v = (a->s6_bytes[i] ^ b->s6_bytes[i]);
    for (j = 0; j < 8; j++, bits++)
        if ((v & (1 << j)) == 0)
           goto quit;
  }
quit:
  return (128 - bits);
}

/*
 * The 'bits' is the suffix from a CIDR notation: "prefix/suffix".
 * Taken from libnet.
 */
void INET_util_get_mask4 (struct in_addr *out, int bits)
{
  *(DWORD*)out = bits ? swap32 (~0 << (32 - bits)) : 0;
}

/*
 * Taken from libdnet's 'addr_btom()' and modified:
 *   https://github.com/nmap/nmap/blob/master/libdnet-stripped/src/addr.c?L441#L441-L470
 */
void INET_util_get_mask6 (struct in6_addr *out, int bits)
{
  char *p = (char*) out;
  int   host, net = bits / 8;

  memset (p, 0, sizeof(*out));
  if (net > 0)
     memset (p, 0xFF, net);

  host = bits % 8;
  if (host > 0)
  {
    p[net] = 0xFF << (8 - host);
    memset (p+net+1, 0, IN6ADDRSZ-net-1);
  }
  else
    memset (p+net, 0, IN6ADDRSZ-net);
}

/*
 * Return a hex-string for an 'in6_addr *mask'.
 * Should return the same as 'wsock_trace_inet_ntop6()' without
 * the '::' shorthanding.
 */
const char *INET_util_in6_mask_str (const struct in6_addr *mask)
{
  static char buf [2*IN6ADDRSZ+1];
  char  *p = buf;
  int    i;

  for (i = 0; i < IN6ADDRSZ; i++)
  {
    const char *q = str_hex_byte (mask->s6_bytes[i]);

    *p++ = *q++;
    *p++ = *q;
  }
  *p = '\0';
  return strlwr (buf);
}

/**
 * Compare 2 IPv4-addresses; 'addr1' and 'addr2' considering 'prefix_len'.
 *
 * \retval 0  if 'addr1' is inside range of 'addr2' block determined by 'prefix_len'.
 *         1  if 'addr1' is above the range of 'addr2'.
 *        -1  if 'addr1' is below the range of 'addr2'.
 */
int INET_util_range4cmp (const struct in_addr *addr1, const struct in_addr *addr2, int prefix_len)
{
  DWORD mask, start_ip, end_ip;

  if (prefix_len == 0)
  {
    start_ip = 0;
    end_ip   = DWORD_MAX;
  }
  else
  {
    mask = swap32 (0xFFFFFFFF << (32 - prefix_len));
    start_ip = addr2->s_addr & mask;
    end_ip   = start_ip | ~mask;
  }

  if (swap32(addr1->s_addr) < swap32(start_ip))
     return (-1);
  if (swap32(addr1->s_addr) > swap32(end_ip))
     return (1);
  return (0);
}

/**
 * Compare 2 IPv6-addresses; 'addr1' and 'addr2' considering 'prefix_len'.
 *
 * \retval 0  if 'addr1' is inside range of 'addr2' block determined by 'prefix_len'.
 *         1  if 'addr1' is above the range of 'addr2'.
 *        -1  if 'addr1' is below the range of 'addr2'.
 */
int INET_util_range6cmp (const struct in6_addr *addr1, const struct in6_addr *addr2, int prefix_len)
{
  BYTE bytes    = prefix_len / 8;
  BYTE bits     = prefix_len % 8;
  BYTE bmask    = 0xFF << (8 - bits);
  int  diff, rc = memcmp (addr1, addr2, bytes);

  if (rc == 0)
  {
    diff = (int)(addr1->s6_bytes[bytes] | bmask) - (int)(addr2->s6_bytes[bytes] | bmask);
    if (bits == 0 || diff == 0)
       return (0);
    rc = diff;
  }
  return (rc);
}

static const char *head_fmt = "%3s %-*s %-*s %-*s %-*s %s\n";
static const char *line_fmt = "%3d %-*s %-*s %-*s %-*s %s\n";

#define IP4_NET "69.208.0.0"
#define IP6_NET "2001:0db8::"

static void test_mask (int family, int start_ip_width, int ip_width, int cidr_width)
{
  struct in_addr  network4;
  struct in6_addr network6;
  int             i, bits, max_bits = (family == AF_INET6 ? 128 : 32);
  uint64          total_ips;
  const char     *total_str;
  char            network_str [MAX_IP6_SZ+1];

  /* Print an IPv6-address chunk like this:
   * '2001:0800::' (not like '2001:800::' which is default).
   */
  leading_zeroes = TRUE;

  trace_printf (head_fmt, "bit",
                cidr_width,     "CIDR",
                start_ip_width, "start_ip",
                ip_width,       "end_ip",
                ip_width,       "mask",
                "total");

  wsock_trace_inet_pton4 (IP4_NET, (u_char*)&network4);
  wsock_trace_inet_pton6 (IP6_NET, (u_char*)&network6);
  _wsock_trace_inet_ntop (family, (family == AF_INET6) ?
                          (const u_char*)&network6 : (const u_char*)&network4,
                          network_str, sizeof(network_str));

  for (bits = 0; bits <= max_bits; bits++)
  {
    char   start_ip_str [MAX_IP6_SZ+1];
    char   end_ip_str   [MAX_IP6_SZ+1];
    char   mask_str     [MAX_IP6_SZ+1];
    char   cidr_str     [MAX_IP6_SZ+11];
    uint64 max64 = U64_SUFFIX(1) << (max_bits - bits);

    if (bits == max_bits)
         total_ips = 1;
    else if (max64 > U64_SUFFIX(0))
         total_ips = max64;
    else total_ips = QWORD_MAX;

    if (family == AF_INET6)
    {
      struct in6_addr mask, start_ip, end_ip;

      INET_util_get_mask6 (&mask, bits);

      if (bits == 0)
      {
        /* A 'mask' from 'INET_util_get_mask6 (&mask, 0)' cannot be used here.
         */
        memset (&start_ip, '\0', sizeof(start_ip));
        memset (&end_ip, 0xFF, sizeof(end_ip));
      }
      else for (i = 0; i < IN6ADDRSZ; i++)
      {
        start_ip.s6_bytes[i] = network6.s6_bytes[i] & mask.s6_bytes[i];
        end_ip.s6_bytes[i]   = start_ip.s6_bytes[i] | ~mask.s6_bytes[i];
      }

      _wsock_trace_inet_ntop (AF_INET6, (const u_char*)&start_ip, start_ip_str, sizeof(start_ip_str));
      _wsock_trace_inet_ntop (AF_INET6, (const u_char*)&end_ip, end_ip_str, sizeof(end_ip_str));
      _wsock_trace_inet_ntop (AF_INET6, (const u_char*)&mask, mask_str, sizeof(mask_str));
    }
    else
    {
      struct in_addr mask, start_ip, end_ip;

      INET_util_get_mask4 (&mask, bits);

      if (bits == 0)
      {
        /* A 'mask' from 'INET_util_get_mask4 (&mask, 0)' cannot be used here.
         */
        start_ip.s_addr = 0;
        end_ip.s_addr   = DWORD_MAX;
        total_ips       = DWORD_MAX;
      }
      else
      {
        start_ip.s_addr = network4.s_addr & mask.s_addr;
        end_ip.s_addr   = start_ip.s_addr | ~mask.s_addr;
        total_ips = swap32 (end_ip.s_addr) - swap32 (start_ip.s_addr) + 1;
      }

      _wsock_trace_inet_ntop (AF_INET, (const u_char*)&start_ip, start_ip_str, sizeof(start_ip_str));
      _wsock_trace_inet_ntop (AF_INET, (const u_char*)&end_ip, end_ip_str, sizeof(end_ip_str));
      _wsock_trace_inet_ntop (AF_INET, (const u_char*)&mask, mask_str, sizeof(mask_str));
    }

    if (total_ips >= QWORD_MAX)
         total_str = "Inf";
    else total_str = qword_str (total_ips);

    snprintf (cidr_str, sizeof(cidr_str), "%s/%u", network_str, bits);
    trace_printf (line_fmt, bits,
                  cidr_width, cidr_str,
                  start_ip_width, start_ip_str,
                  ip_width, end_ip_str,
                  ip_width, mask_str,
                  total_str);
  }
  leading_zeroes = FALSE;
}

/*
 * Check that 'INET_util_get_mask4()' is correct.
 *
 * Attempt to create a "Table of sample ranges" similar to this:
 *   https://www.mediawiki.org/wiki/Help:Range_blocks
 */
void INET_util_test_mask4 (void)
{
  trace_puts ("\nINET_util_test_mask4()\n");
  test_mask (AF_INET, strlen(IP4_NET), strlen("255.255.255.255"), strlen(IP4_NET "/32"));
}

/*
 * Check that 'INET_util_get_mask6()' is correct.
 *
 * Attempt to create a "Range Table" similar to this:
 *   https://www.mediawiki.org/wiki/Help:Range_blocks/IPv6
 */
void INET_util_test_mask6 (void)
{
  trace_puts ("\nINET_util_test_mask6()\n");
  test_mask (AF_INET6, strlen(IP6_NET), MAX_IP6_SZ-7, strlen(IP6_NET "/128"));
}

