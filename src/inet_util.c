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

#include "common.h"
#include "init.h"
#include "in_addr.h"
#include "inet_util.h"

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
                                    VOID     *buffer,
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
    if ((ip4->s_addr & 0xF0) == 0xE0)
       return (1);
  }
  else if (ip6)
  {
    if (ip6->s6_bytes[0] == 0xFF)
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
 * https://stackoverflow.com/questions/218604/whats-the-best-way-to-convert-from-network-bitcount-to-netmask
 *
 * Ret-val on network-order
 */
void INET_util_get_mask4a (struct in_addr *out, int bits)
{
  if (bits == 0)
  {
    out->s_addr = 0xFFFFFFFF;
    return;
  }
  bits = 32 - bits;
  out->s_addr = swap32 ((0xFFFFFFFF >> bits) << bits);
}

/*
 * Taken from libnet
 */
void INET_util_get_mask4b (struct in_addr *out, int bits)
{
  *(DWORD*)out = bits ? swap32 (~0 << (32 - bits)) : 0;
}

void INET_util_get_mask4 (struct in_addr *out, int bits)
{
  INET_util_get_mask4b (out, bits);
}

void INET_util_get_mask6a (struct in6_addr *out, int bits)
{
  DWORD s;
  int   i;

  if (bits == 0)
  {
    memset (out, 0xFF, sizeof(*out));
    return;
  }

  for (i = 0; i < IN6ADDRSZ && bits >= 0; i++)
  {
    s = 8 - (bits % 8);
    if (bits == 0)
         out->s6_bytes[i] = 0xFF;
    else out->s6_bytes[i] = (0xFF >> s) << s;
    bits -= 8;
  }
}

/*
 * Taken from libnet
 */
void INET_util_get_mask6b (struct in6_addr *out, int bits)
{
  char *p = (char*) out;
  int   host, net = bits / 8;

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
 * Taken from 2nd answer here:
 *   https://stackoverflow.com/questions/7683121/validating-ipv6-netmask-prefix
 */
void INET_util_get_mask6c (struct in6_addr *out, int bits)
{
  int i;

  for (i = 0; i < IN6ADDRSZ; i++)
  {
    BYTE mask = 0xFF;

    if (bits >= 8)
    {
      bits -= 8;
    }
    else if (bits == 0)
    {
      mask = 0;
    }
    else   /* 'bits' is between 1 and 7, inclusive */
    {
      mask <<= (8 - bits);
      bits = 0;
    }
    out->s6_addr[i] = mask;
  }
}

void INET_util_get_mask6 (struct in6_addr *out, int bits)
{
  INET_util_get_mask6b (out, bits);
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
  strlwr (buf);
  return (buf);
}

static const char *head_fmt = "%3s  %-*s %-*s %-*s %s\n";
static const char *line_fmt = "%3d: %-*s %-*s %-*s %s\n";

static void test_mask (int family, int ip_width, int cidr_width)
{
  struct in_addr  network4;
  struct in6_addr network6;
  int    i, bits, max_bits = (family == AF_INET6 ? 128 : 32);

  memset (&network4, 0, sizeof(network4));
  memset (&network6, 0, sizeof(network6));
  network4.s_addr      = 127;              /* 127.0.0.0 */
  network6.s6_words[0] = swap16 (0x2001);  /* "2001::" */

  printf (head_fmt, "Num", cidr_width, "CIDR", ip_width, "start_ip", ip_width, "end_ip", "mask");

  for (bits = 0; bits <= max_bits; bits++)
  {
    char start_ip_str [MAX_IP6_SZ+1];
    char end_ip_str   [MAX_IP6_SZ+1];
    char mask_str     [MAX_IP6_SZ+1];
    char network_str  [MAX_IP6_SZ+1];
    char cidr         [MAX_IP6_SZ+11];

    if (family == AF_INET6)
    {
      struct in6_addr mask, start_ip, end_ip;

      INET_util_get_mask6 (&mask, bits);
      for (i = 0; i < IN6ADDRSZ; i++)
      {
        start_ip.s6_bytes[i] = network6.s6_bytes[i] & mask.s6_bytes[i];
        end_ip.s6_bytes[i]   = start_ip.s6_bytes[i] | ~mask.s6_bytes[i];
      }
      _wsock_trace_inet_ntop (AF_INET6, (const u_char*)&start_ip, start_ip_str, sizeof(start_ip_str));
      _wsock_trace_inet_ntop (AF_INET6, (const u_char*)&end_ip, end_ip_str, sizeof(end_ip_str));
      _wsock_trace_inet_ntop (AF_INET6, (const u_char*)&mask, mask_str, sizeof(mask_str));
      _wsock_trace_inet_ntop (AF_INET6, (const u_char*)&network6, network_str, sizeof(network_str));
    }
    else
    {
      struct in_addr mask, start_ip, end_ip;

      INET_util_get_mask4 (&mask, bits);
      start_ip.s_addr = network4.s_addr & mask.s_addr;
      end_ip.s_addr   = start_ip.s_addr | ~mask.s_addr;

      _wsock_trace_inet_ntop (AF_INET, (const u_char*)&start_ip, start_ip_str, sizeof(start_ip_str));
      _wsock_trace_inet_ntop (AF_INET, (const u_char*)&end_ip, end_ip_str, sizeof(end_ip_str));
      _wsock_trace_inet_ntop (AF_INET, (const u_char*)&mask, mask_str, sizeof(mask_str));
      _wsock_trace_inet_ntop (AF_INET, (const u_char*)&network4, network_str, sizeof(network_str));
    }

    snprintf (cidr, sizeof(cidr), "%s/%u", network_str, bits);
    printf (line_fmt, bits, cidr_width, cidr, ip_width, start_ip_str, ip_width, end_ip_str, mask_str);
  }
}

/*
 * Check that 'INET_util_get_mask4()' is correct.
 */
void INET_util_test_mask4 (void)
{
  puts ("INET_util_test_mask4()");
  test_mask (AF_INET, MAX_IP4_SZ, sizeof("127.0.0.255/32"));
}

/*
 * Check that 'INET_util_get_mask6()' is correct.
 */
void INET_util_test_mask6 (void)
{
  puts ("INET_util_test_mask6()");
  test_mask (AF_INET6, MAX_IP6_SZ-5, sizeof("2000::/128"));
}
