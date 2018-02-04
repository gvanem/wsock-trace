/*
 * geoip.c - Part of Wsock-Trace.
 *
 * This file implements parsing of CSV value files of MaxMind IPv4 + IPv6
 * geoip-data files. It is inspired by Tor's geoip.c:
 *   https://gitweb.torproject.org/tor.git/tree/src/or/geoip.c
 */

#include <assert.h>
#include <limits.h>
#include <errno.h>
#include <windows.h>
#include <wininet.h>

#if defined(__WATCOMC__)
  #undef  NTDDI_VERSION
  #define NTDDI_VERSION 0x05010000
#endif

#include "common.h"
#include "smartlist.h"
#include "init.h"
#include "in_addr.h"
#include "geoip.h"

#if !defined(s6_bytes)  /* mingw.org */
  #define s6_bytes _s6_bytes
#endif

#if !defined(s6_words)  /* mingw.org */
  #define s6_words _s6_words
#endif

/* Number of calls for 'smartlist_bsearch()' to find an IPv4 or IPv6 entry.
 */
static DWORD num_4_compare, num_6_compare;

static int  geoip4_parse_entry (char *buf, unsigned *line, DWORD *num);
static int  geoip6_parse_entry (char *buf, unsigned *line, DWORD *num);
static int  geoip4_add_entry (DWORD low, DWORD high, const char *country);
static int  geoip6_add_entry (const struct in6_addr *low, const struct in6_addr *high, const char *country);
static void geoip_stats_init (void);
static void geoip_stats_exit (void);
static void geoip_stats_update (const char *country_A2, int flag);
static int  geoip_get_num_addr (DWORD *num4, DWORD *num6);

/*
 * Deallocate a smartlist and associated storage in the list's elements.
 */
static void smartlist_free_all (smartlist_t *sl)
{
  if (sl && !g_cfg.geoip_use_generated)
  {
    int i, max = smartlist_len (sl);

    for (i = 0; i < max; i++)
        free (smartlist_get(sl, i));
  }
  smartlist_free (sl);
}

/*
 * Used to make the smartlists for the fixed arrays 'ipv4_gen_array' and 'ipv6_gen_array'.
 * Since we know their sizes, just allocate the smartlist size once.
 * Called from 'gen-geoip4.c' and 'geoip-gen6.c'
 */
smartlist_t *geoip_smartlist_fixed (void *start, size_t el_size, unsigned num)
{
  smartlist_t *sl = smartlist_new();
  char        *ofs = (char*) start;
  size_t       i;

  smartlist_ensure_capacity (sl, num);
  for (i = 0; i < num; i++, ofs += el_size)
     smartlist_add (sl, ofs);
  return (sl);
}

/*
 * Geoip specific stuff.
 */
static smartlist_t *geoip_ipv4_entries = NULL;
static smartlist_t *geoip_ipv6_entries = NULL;

/*
 * Structure for counting countries found at run-time.
 */
struct geoip_stats {
       uint64  num4;        /* Total # of times seen in an IPv4-address */
       uint64  num6;        /* Total # of times seen in an IPv6-address */
       char    country[2];  /* 2 letter ISO-3166 2 letter Country-code */
       char    flag;        /* The country was seen in IPv4 or IPv6 address(es) */
    };

#define GEOIP_STAT_IPV4   0x01
#define GEOIP_STAT_IPV6   0x02
#define GEOIP_VIA_IP2LOC  0x04


static struct geoip_stats *geoip_stats_buf = NULL;

/*
 * Simplified version of the one in wsock_trace.c.
 */
static const char *get_ws_error (void)
{
  static char buf[150];
  return ws_strerror (WSAGetLastError(), buf, sizeof(buf));
}

/*
 * smartlist_sort() helper: return -1, 1, or 0 based on comparison of two
 * 'ipv4_node'
 */
static int geoip_ipv4_compare_entries (const void **_a, const void **_b)
{
  const struct ipv4_node *a = *_a;
  const struct ipv4_node *b = *_b;

  if (a->low < b->low)
     return (-1);
  if (a->low > b->low)
     return (1);
  return (0);
}

/*
 * smartlist_bsearch() helper: return -1, 1, or 0 based on comparison of an IP (a pointer
 * to a DWORD in host order) to a 'struct ipv4_node' element.
 */
static int geoip_ipv4_compare_key_to_entry (const void *key, const void **member)
{
  const struct ipv4_node *entry = *member;
  const DWORD             addr  = *(DWORD*) key;

  num_4_compare++;

  if (addr < entry->low)
     return (-1);
  if (addr > entry->high)
     return (1);
  return (0);
}

/*
 * smartlist_sort() helper: return -1, 1, or 0 based on comparison of two
 * 'struct ipv6_node' elements.
 */
static int geoip_ipv6_compare_entries (const void **_a, const void **_b)
{
  const struct ipv6_node *a = *_a;
  const struct ipv6_node *b = *_b;

  return memcmp (a->low.s6_addr, b->low.s6_addr, sizeof(struct in6_addr));
}

/*
 * smartlist_bsearch() helper: return -1, 1, or 0 based on comparison of an IPv6
 * (a pointer to a in6_addr) to a 'struct ipv6_node'.
 */
static int geoip_ipv6_compare_key_to_entry (const void *key, const void **member)
{
  const struct ipv6_node *entry = *member;
  const struct in6_addr  *addr  = (const struct in6_addr*) key;

  num_6_compare++;

  if (memcmp(addr->s6_addr, entry->low.s6_addr, sizeof(struct in6_addr)) < 0)
     return (-1);
  if (memcmp(addr->s6_addr, entry->high.s6_addr, sizeof(struct in6_addr)) > 0)
     return (1);
  return (0);
}

/*
 * Add these special addresses to the 'geoip_ipv4_entries' smartlist.
 */
void geoip_ipv4_add_specials (void)
{
  static const struct {
         const char *low;
         const char *high;
         const char *remark;
       } priv[] = {
         { "0.0.0.0",     "0.255.255.255",   "-L" },
         { "10.0.0.0",    "10.255.255.255",  "-P" }, /* https://en.wikipedia.org/wiki/Private_network */
         { "127.0.0.0",   "127.255.255.255", "-L" },
         { "172.16.0.0",  "172.31.255.255",  "-P" },
         { "192.168.0.0", "192.168.255.255", "-P" },
         { "224.0.0.0",   "239.255.255.253", "-M" }  /* https://en.wikipedia.org/wiki/Multicast_address */
       };
  int i;

  for (i = 0; i < DIM(priv); i++)
  {
    DWORD low, high;

    if (wsock_trace_inet_pton4(priv[i].low, (u_char*)&low) == 1 &&
        wsock_trace_inet_pton4(priv[i].high, (u_char*)&high) == 1)
      geoip4_add_entry (swap32(low), swap32(high), priv[i].remark);
    else
      TRACE (0, "Illegal low/high IPv4 address: %s/%s\n", priv[i].low, priv[i].high);
  }
}

/*
 * Add these special addresses to the 'geoip_ipv6_entries' smartlist.
 */
void geoip_ipv6_add_specials (void)
{
  static const struct {
         const char *low;
         const char *high;
         const char *remark;
       } priv[] = {
         { "::",      "::",  "-Z"       },                                   /* IN6_IS_ADDR_UNSPECIFIED() */
         { "::1",     "::1", "-L"      },                                    /* IN6_IS_ADDR_LOOPBACK() */
      #if 1
         { "2001:0::",    "2001:0000:ffff:ffff:ffff:ffff:ffff:ffff", "-T" }, /* RFC 4380 Teredo, 2001:0::/32 */
         { "3ffe:831f::", "3ffe:831f:ffff:ffff:ffff:ffff:ffff:ffff", "-t" }, /* WinXP Teroedo,   3FFE:831F::/32 */
      #endif
         { "f0::",    "f0::ffff", "-G" },                                    /* !IN6_IS_ADDR_GLOBAL() */
         { "fe80::",  "fe80:ffff:ffff:ffff:ffff:ffff:ffff:ffff", "-l" }      /* IN6_IS_ADDR_LINKLOCAL() */
       };
  int i;

  for (i = 0; i < DIM(priv); i++)
  {
    struct in6_addr low, high;

    if (wsock_trace_inet_pton6(priv[i].low, (u_char*)&low) != 1)
    {
      TRACE (0, "Illegal low IPv6 address: %s, %s\n", priv[i].low, get_ws_error());
      continue;
    }
    if (wsock_trace_inet_pton6(priv[i].high, (u_char*)&high) != 1)
    {
      TRACE (0, "Illegal high IPv6 address: %s, %s\n", priv[i].high, get_ws_error());
      continue;
    }
    geoip6_add_entry (&low, &high, priv[i].remark);
  }
}

/*
 * Load pre-generated data from GeoIP files.
 *   IPv4-address (AF_INET) only or
 *   IPv6-address (AF_INET6) only.
 *
 * Watcom-C is not able to compile the huge generated geoip-gen6.c.
 * Thus no 'geoip_smartlist_fixed_ipv4/6()' for Watcom :-(
 */
static DWORD geoip_load_data (int family)
{
  DWORD num = 0;

  if (family == AF_INET)
  {
    geoip_ipv4_entries = geoip_smartlist_fixed_ipv4();
    num = geoip_ipv4_entries ? smartlist_len (geoip_ipv4_entries) : 0;
    TRACE (2, "Using %lu fixed IPv4 records instead of parsing %s.\n",
           DWORD_CAST(num), g_cfg.geoip4_file);
  }
  else if (family == AF_INET6)
  {
    geoip_ipv6_entries = geoip_smartlist_fixed_ipv6();
    num = geoip_ipv6_entries ? smartlist_len (geoip_ipv6_entries) : 0;
    TRACE (2, "Using %lu fixed IPv6 records instead of parsing %s.\n",
           DWORD_CAST(num), g_cfg.geoip6_file);
  }
  else
  {
    TRACE (0, "Only address-families AF_INET and AF_INET6 supported.\n");
    return (0);
  }
  return (num);
}

/*
 * Open and parse a GeoIP file with either:
 *   IPv4-address (AF_INET) only or
 *   IPv6-address (AF_INET6) only.
 *
 * Both files are on CVS format.
 */
static DWORD geoip_parse_file (const char *file, int family)
{
  unsigned line = 0;
  DWORD    num4 = 0;
  DWORD    num6 = 0;
  FILE    *f;

  TRACE (4, "address-family: %d, file: %s.\n", family, file);

  if (!file || !file_exists(file))
  {
    TRACE (2, "Geoip-file \"%s\" does not exist.\n", file);
    return (0);
  }

  if (family == AF_INET)
  {
    assert (geoip_ipv4_entries == NULL);
    geoip_ipv4_entries = smartlist_new();
    geoip_ipv4_add_specials();
  }
  else if (family == AF_INET6)
  {
    assert (geoip_ipv6_entries == NULL);
    geoip_ipv6_entries = smartlist_new();
    geoip_ipv6_add_specials();
  }
  else
  {
    TRACE (0, "Only address-families AF_INET and AF_INET6 supported.\n");
    return (0);
  }

  f = fopen (file, "rt");
  if (!f)
  {
    TRACE (2, "Failed to open Geoip-file \"%s\". errno: %d\n", file, errno);
    return (0);
  }

  while (!feof(f))
  {
    char buf[512];
    int  rc;

    if (fgets(buf, (int)sizeof(buf), f) == NULL)
       break;
    if (family == AF_INET)
         rc = geoip4_parse_entry (buf, &line, &num4);
    else rc = geoip6_parse_entry (buf, &line, &num6);
    if (rc < 0)  /* malloc() failed, give up */
       break;
  }

  fclose (f);

  if (family == AF_INET)
  {
    smartlist_sort (geoip_ipv4_entries, geoip_ipv4_compare_entries);
    TRACE (2, "Parsed %lu IPv4 records from \"%s\".\n",
           DWORD_CAST(num4), file);
    return (num4);
  }
  else
  {
    smartlist_sort (geoip_ipv6_entries, geoip_ipv6_compare_entries);
    TRACE (2, "Parsed %lu IPv6 records from \"%s\".\n",
           DWORD_CAST(num6), file);
    return (num6);
  }
  return (0);
}

/*
 * The main init function for this module.
 * Normally called from wsock_trace_init().
 */
int geoip_init (DWORD *_num4, DWORD *_num6)
{
  DWORD num4 = 0, num6 = 0;
  BOOL open_geoip = FALSE;

#if defined(TEST_GEOIP)
  open_geoip = TRUE;
#endif

  if (g_cfg.geoip_enable && (g_cfg.trace_level > 0 || open_geoip))
  {
    if (!open_geoip && g_cfg.geoip_use_generated)
    {
      num4 = geoip_load_data (AF_INET);
      num6 = geoip_load_data (AF_INET6);
    }
    else
    {
      num4 = geoip_parse_file (g_cfg.geoip4_file, AF_INET);
      num6 = geoip_parse_file (g_cfg.geoip6_file, AF_INET6);
    }
  }
  if (num4 == 0 && num6 == 0)
     g_cfg.geoip_enable = FALSE;

  geoip_stats_init();
  ip2loc_init();

  return geoip_get_num_addr (_num4, _num6);
}

void geoip_exit (void)
{
  smartlist_free_all (geoip_ipv4_entries);
  smartlist_free_all (geoip_ipv6_entries);
  geoip_ipv4_entries = geoip_ipv6_entries = NULL;
  geoip_stats_exit();
  ip2loc_exit();
}

/*
 * Parse and add a IPv4 entry to the 'geoip_ipv4_entries' smart-list.
 */
static int geoip4_parse_entry (char *buf, unsigned *line, DWORD *num)
{
  char *p = buf;
  char  country[3];
  int   rc = 0;
#ifdef __CYGWIN__
  unsigned long low, high;
#else
  DWORD low, high;
#endif

  for ( ; *p && isspace((int)*p); )
      p++;

  if (*p == '#' || *p == ';')
  {
    (*line)++;
    return (1);
  }

  if (sscanf(buf,"%lu,%lu,%2s", &low, &high, country) == 3 ||
      sscanf(buf,"\"%lu\",\"%lu\",\"%2s\",", &low, &high, country) == 3)
  {
    rc = geoip4_add_entry (low, high, country);
    (*num)++;
  }
  (*line)++;

  if (rc == 0)
     TRACE (0, "Unable to parse line %u in GEOIP IPv4 file.\n", *line);
  return (rc);
}

/*
 * Parse and add a IPv6 entry to the 'geoip_ipv6_entries' smart-list.
 */
static int geoip6_parse_entry (char *buf, unsigned *line, DWORD *num)
{
  struct in6_addr low, high;
  char           *p = buf;
  char           *country, *low_str, *high_str, *strtok_state;
  int             rc = 0;

  for ( ; *p && isspace((int)*p); )
      p++;

  if (*p == '#' || *p == ';')
  {
    (*line)++;
    return (1);
  }

  low_str = _strtok_r (buf, ",", &strtok_state);
  if (!low_str)
     goto fail;

  high_str = _strtok_r (NULL, ",", &strtok_state);
  if (!high_str)
     goto fail;

  country = _strtok_r (NULL, "\n", &strtok_state);
  if (!country)
     goto fail;

  if (strlen(country) == 2 &&
      wsock_trace_inet_pton6(low_str, (u_char*)&low) == 1 &&
      wsock_trace_inet_pton6(high_str, (u_char*)&high) == 1)
  {
    rc = geoip6_add_entry (&low, &high, country);
    (*num)++;
  }

fail:
  (*line)++;

  if (rc == 0)
     TRACE (0, "Unable to parse line %u in GEOIP IPv6 file.\n", *line);
  return (rc);
}

/*
 * Taken from:
 *   ettercap -- IP address management
 *
 *  Copyright (C) ALoR & NaGA
 *
 * ... and rewritten.
 */

/*
 * return true if an IPv4/IPv6 address is 0.0.0.0 or 0::
 */
int geoip_addr_is_zero (const struct in_addr *ip4, const struct in6_addr *ip6)
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
int geoip_addr_is_multicast (const struct in_addr *ip4, const struct in6_addr *ip6)
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

int geoip_addr_is_special (const struct in_addr *ip4, const struct in6_addr *ip6, const char **remark)
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
int geoip_addr_is_global (const struct in_addr *ip4, const struct in6_addr *ip6)
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
         !geoip_addr_is_multicast(ip4,NULL))                    /* not 224/3      */
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

static int geoip4_add_entry (DWORD low, DWORD high, const char *country)
{
  struct ipv4_node *entry = malloc (sizeof(*entry));

  if (!entry)
     return (-1);

  entry->low  = low;
  entry->high = high;
  if (country)
       memcpy (&entry->country, country, sizeof(entry->country));
  else entry->country[0] = '\0';
  smartlist_add (geoip_ipv4_entries, entry);
  return (1);
}

static int geoip6_add_entry (const struct in6_addr *low, const struct in6_addr *high, const char *country)
{
  struct ipv6_node *entry = malloc (sizeof(*entry));

  if (!entry)
     return (-1);

  memcpy (&entry->low,  low,  sizeof(entry->low));
  memcpy (&entry->high, high, sizeof(entry->high));
  if (country)
       memcpy (&entry->country, country, sizeof(entry->country));
  else entry->country[0] = '\0';
  smartlist_add (geoip_ipv6_entries, entry);
  return (1);
}

/*
 * This is global here to get the location (city and region) later on.
 */
static struct ip2loc_entry g_ip2loc_entry;

#define IP2LOC_IS_GOOD()  (g_ip2loc_entry.country_short[0] >= 'A' && \
                           g_ip2loc_entry.country_short[0] <= 'Z')
#define IP2LOC_SET_BAD()  g_ip2loc_entry.country_short[0] = '\0'

/*
 * Given an IPv4 address on network order, return an ISO-3166 2 letter
 * Country-code representing the country to which that address
 * belongs, or NULL for "No geoip information available".
 *
 * To decode it, call 'geoip_get_long_name_by_A2()'.
 */
const char *geoip_get_country_by_ipv4 (const struct in_addr *addr)
{
  struct ipv4_node *entry = NULL;
  char     buf [25];
  unsigned num;

  IP2LOC_SET_BAD();
  num_4_compare = 0;

  wsock_trace_inet_ntop4 ((const u_char*)addr, buf, sizeof(buf));

#ifdef USE_IP2LOCATION
  num = ip2loc_num_ipv4_entries();
  TRACE (4, "Looking for %s in %u elements (USE_IP2LOCATION: 1).\n", buf, num);

  if (num > 0 && geoip_addr_is_global(addr,NULL) && ip2loc_get_entry(buf, &g_ip2loc_entry))
  {
    if (g_cfg.trace_report)
       geoip_stats_update (g_ip2loc_entry.country_short, GEOIP_STAT_IPV4 | GEOIP_VIA_IP2LOC);
    return (g_ip2loc_entry.country_short);
  }

  /* IP2LOCATION lookup failed. Fallback to a geoip lookup below.
   */
#else
  num = geoip_ipv4_entries ? smartlist_len (geoip_ipv4_entries) : 0;
  TRACE (4, "Looking for %s in %u elements (USE_IP2LOCATION: 0).\n", buf, num);
#endif

  if (geoip_ipv4_entries)
  {
    DWORD ip_num = swap32 (addr->s_addr);

    entry = smartlist_bsearch (geoip_ipv4_entries, &ip_num,
                               geoip_ipv4_compare_key_to_entry);

    if (g_cfg.trace_report && entry && entry->country[0])
       geoip_stats_update (entry->country, GEOIP_STAT_IPV4);
  }
  return (entry ? entry->country : NULL);
}

/*
 * Given an IPv6 address,  return an ISO-3166 2 letter Country-code
 * representing the country to which that address belongs, or NULL for
 * "No geoip information available".
 *
 * To decode it, call 'geoip_get_long_name_by_A2()'.
 */
const char *geoip_get_country_by_ipv6 (const struct in6_addr *addr)
{
  struct ipv6_node *entry = NULL;
  char     buf [MAX_IP6_SZ];
  unsigned num;

  IP2LOC_SET_BAD();
  num_6_compare = 0;

  wsock_trace_inet_ntop6 ((const u_char*)addr, buf, sizeof(buf));

#ifdef USE_IP2LOCATION
  num = ip2loc_num_ipv6_entries();
  TRACE (4, "Looking for %s in %u elements (USE_IP2LOCATION: 1).\n", buf, num);

  if (num > 0 && geoip_addr_is_global(NULL,addr) && ip2loc_get_entry(buf, &g_ip2loc_entry))
  {
    if (g_cfg.trace_report)
       geoip_stats_update (g_ip2loc_entry.country_short, GEOIP_STAT_IPV6 | GEOIP_VIA_IP2LOC);
    return (g_ip2loc_entry.country_short);
  }
#else
  num = geoip_ipv6_entries ? smartlist_len (geoip_ipv6_entries) : 0;
  TRACE (4, "Looking for %s in %u elements (USE_IP2LOCATION: 0).\n",  buf, num);
#endif

  if (geoip_ipv6_entries)
  {
    entry = smartlist_bsearch (geoip_ipv6_entries, addr,
                               geoip_ipv6_compare_key_to_entry);

    if (g_cfg.trace_report && entry && entry->country[0])
       geoip_stats_update (entry->country, GEOIP_STAT_IPV6);
  }
  return (entry ? entry->country : NULL);
}

/*
 * Given an IPv4 address, return the location (city+region).
 * Assumes geoip_get_country_by_ipv4() was just called for this address.
 * Currently only works when 'ip2location_bin_file' is present.
 */
const char *geoip_get_location_by_ipv4 (const struct in_addr *ip4)
{
  static char buf [100];

  if (IP2LOC_IS_GOOD())
  {
    snprintf (buf, sizeof(buf), "%s/%s", g_ip2loc_entry.city, g_ip2loc_entry.region);
    return (buf);
  }
  ARGSUSED (ip4);
  return (NULL);
}

/*
 * Given an IPv6 address, return the location.
 * Assumes geoip_get_country_by_ipv6() was just called for this address.
 * Currently only works when 'ip2location_bin_file' is present.
 */
const char *geoip_get_location_by_ipv6 (const struct in6_addr *ip6)
{
  static char buf [100];

  if (IP2LOC_IS_GOOD())
  {
    snprintf (buf, sizeof(buf), "%s/%s", g_ip2loc_entry.city, g_ip2loc_entry.region);
    return (buf);
  }
  ARGSUSED (ip6);
  return (NULL);
}

/*
 * \todo:
 *   Optionally use MaxMind's GeoLite2-City.mmdb file and print the location (city) too.
 *   This will have to be coded in 'geoip_get_location_by_ipv4()' and 'geoip_get_location_by_ipv6()'.
 *   Emulate what this command does:
 *     mmdblookup.exe -f GeoLite2-City.mmdb --ip x.x.x.x subdivisions 0 names en
 *   giving:
 *     "New York" <utf8_string>
 *
 *   Or this command:
 *     mmdblookup.exe -f GeoLite2-City.mmdb --ip x.x.x.x subdivisions location
 *   giving:
 *     {
 *       "accuracy_radius":
 *         1000 <uint16>
 *       "latitude":
 *         43.048100 <double>
 *       "longitude":
 *         -76.147400 <double>
 *       "metro_code":
 *         555 <uint16>
 *       "time_zone":
 *         "America/New_York" <utf8_string>
 *     }
 *
 * Ref: https://github.com/maxmind/libmaxminddb/blob/master/doc/libmaxminddb.md
 *
 * \todo: Put this inside a '#ifdef USE_MAXMINDDB' section later.
 */

static int geoip_get_num_addr (DWORD *num4, DWORD *num6)
{
  if (num4 && geoip_ipv4_entries)
     *num4 = smartlist_len (geoip_ipv4_entries);

  if (num6 && geoip_ipv6_entries)
     *num6 = smartlist_len (geoip_ipv6_entries);

  if (!geoip_ipv4_entries && !geoip_ipv6_entries)
     return (0);

  return (1);
}

struct country_list {
       int         country_number; /* ISO-3166-2 country number */
       char        short_name[3];  /* A2 short country code */
       const char *long_name;      /* normal country name */
     };

/*
 * Refs:
 *  ftp://ftp.ripe.net/iso3166-countrycodes.txt
 *  https://en.wikipedia.org/wiki/ISO_3166-2
 */
static const struct country_list c_list[] = {
       {   4, "af", "Afghanistan"                          },
       { 248, "ax", "Åland Island"                         },
       {   8, "al", "Albania"                              },
       {  12, "dz", "Algeria"                              },
       {  16, "as", "American Samoa"                       },
       {  20, "ad", "Andorra"                              },
       {  24, "ao", "Angola"                               },
       { 660, "ai", "Anguilla"                             },
       {  10, "aq", "Antarctica"                           },
       {  28, "ag", "Antigua & Barbuda"                    },
       {  32, "ar", "Argentina"                            },
       {  51, "am", "Armenia"                              },
       { 533, "aw", "Aruba"                                },
       {  36, "au", "Australia"                            },
       {  40, "at", "Austria"                              },
       {  31, "az", "Azerbaijan"                           },
       {  44, "bs", "Bahamas"                              },
       {  48, "bh", "Bahrain"                              },
       {  50, "bd", "Bangladesh"                           },
       {  52, "bb", "Barbados"                             },
       { 112, "by", "Belarus"                              },
       {  56, "be", "Belgium"                              },
       {  84, "bz", "Belize"                               },
       { 204, "bj", "Benin"                                },
       {  60, "bm", "Bermuda"                              },
       {  64, "bt", "Bhutan"                               },
       {  68, "bo", "Bolivia"                              },
       { 535, "bq", "Bonaire"                              },
       {  70, "ba", "Bosnia & Herzegowina"                 },
       {  72, "bw", "Botswana"                             },
       {  74, "bv", "Bouvet Island"                        },
       {  76, "br", "Brazil"                               },
       {  86, "io", "British Indian Ocean Territory"       },
       {  96, "bn", "Brunei Darussalam"                    },
       { 100, "bg", "Bulgaria"                             },
       { 854, "bf", "Burkina Faso"                         },
       { 108, "bi", "Burundi"                              },
       { 116, "kh", "Cambodia"                             },
       { 120, "cm", "Cameroon"                             },
       { 124, "ca", "Canada"                               },
       { 132, "cv", "Cape Verde"                           },
       { 136, "ky", "Cayman Islands"                       },
       { 140, "cf", "Central African Republic"             },
       { 148, "td", "Chad"                                 },
       { 152, "cl", "Chile"                                },
       { 156, "cn", "China"                                },
       { 162, "cx", "Christmas Island"                     },
       { 166, "cc", "Cocos Islands"                        },
       { 170, "co", "Colombia"                             },
       { 174, "km", "Comoros"                              },
       { 178, "cg", "Congo"                                },
       { 180, "cd", "Congo"                                },
       { 184, "ck", "Cook Islands"                         },
       { 188, "cr", "Costa Rica"                           },
       { 384, "ci", "Cote d'Ivoire"                        },
       { 191, "hr", "Croatia"                              },
       { 192, "cu", "Cuba"                                 },
       { 531, "cw", "Curaçao"                              },
       { 196, "cy", "Cyprus"                               },
       { 203, "cz", "Czech Republic"                       },
       { 208, "dk", "Denmark"                              },
       { 262, "dj", "Djibouti"                             },
       { 212, "dm", "Dominica"                             },
       { 214, "do", "Dominican Republic"                   },
       { 218, "ec", "Ecuador"                              },
       { 818, "eg", "Egypt"                                },
       { 222, "sv", "El Salvador"                          },
       { 226, "gq", "Equatorial Guinea"                    },
       { 232, "er", "Eritrea"                              },
       { 233, "ee", "Estonia"                              },
       { 231, "et", "Ethiopia"                             },
     { 65281, "eu", "European Union"                       }, /* 127.0.255.1 */
       { 238, "fk", "Falkland Islands"                     },
       { 234, "fo", "Faroe Islands"                        },
       { 242, "fj", "Fiji"                                 },
       { 246, "fi", "Finland"                              },
       { 250, "fr", "France"                               },
       { 249, "fx", "France, Metropolitan"                 },
       { 254, "gf", "French Guiana"                        },
       { 258, "pf", "French Polynesia"                     },
       { 260, "tf", "French Southern Territories"          },
       { 266, "ga", "Gabon"                                },
       { 270, "gm", "Gambia"                               },
       { 268, "ge", "Georgia"                              },
       { 276, "de", "Germany"                              },
       { 288, "gh", "Ghana"                                },
       { 292, "gi", "Gibraltar"                            },
       { 300, "gr", "Greece"                               },
       { 304, "gl", "Greenland"                            },
       { 308, "gd", "Grenada"                              },
       { 312, "gp", "Guadeloupe"                           },
       { 316, "gu", "Guam"                                 },
       { 320, "gt", "Guatemala"                            },
       { 831, "gg", "Guernsey"                             },
       { 324, "gn", "Guinea"                               },
       { 624, "gw", "Guinea-Bissau"                        },
       { 328, "gy", "Guyana"                               },
       { 332, "ht", "Haiti"                                },
       { 334, "hm", "Heard & Mc Donald Islands"            },
       { 336, "va", "Vatican City"                         },
       { 340, "hn", "Honduras"                             },
       { 344, "hk", "Hong kong"                            },
       { 348, "hu", "Hungary"                              },
       { 352, "is", "Iceland"                              },
       { 356, "in", "India"                                },
       { 360, "id", "Indonesia"                            },
       { 364, "ir", "Iran"                                 },
       { 368, "iq", "Iraq"                                 },
       { 372, "ie", "Ireland"                              },
       { 833, "im", "Isle of Man"                          },
       { 376, "il", "Israel"                               },
       { 380, "it", "Italy"                                },
       { 388, "jm", "Jamaica"                              },
       { 392, "jp", "Japan"                                },
       { 832, "je", "Jersey"                               },
       { 400, "jo", "Jordan"                               },
       { 398, "kz", "Kazakhstan"                           },
       { 404, "ke", "Kenya"                                },
       { 296, "ki", "Kiribati"                             },
       { 408, "kp", "Korea (north)"                        },
       { 410, "kr", "Korea (south)"                        },
       {   0, "xk", "Kosovo"                               },  /* https://en.wikipedia.org/wiki/ISO_3166-1_alpha-2 */
       { 414, "kw", "Kuwait"                               },
       { 417, "kg", "Kyrgyzstan"                           },
       { 418, "la", "Laos"                                 },
       { 428, "lv", "Latvia"                               },
       { 422, "lb", "Lebanon"                              },
       { 426, "ls", "Lesotho"                              },
       { 430, "lr", "Liberia"                              },
       { 434, "ly", "Libya"                                },
       { 438, "li", "Liechtenstein"                        },
       { 440, "lt", "Lithuania"                            },
       { 442, "lu", "Luxembourg"                           },
       { 446, "mo", "Macao"                                },
       { 807, "mk", "Macedonia"                            },
       { 450, "mg", "Madagascar"                           },
       { 454, "mw", "Malawi"                               },
       { 458, "my", "Malaysia"                             },
       { 462, "mv", "Maldives"                             },
       { 466, "ml", "Mali"                                 },
       { 470, "mt", "Malta"                                },
       { 584, "mh", "Marshall Islands"                     },
       { 474, "mq", "Martinique"                           },
       { 478, "mr", "Mauritania"                           },
       { 480, "mu", "Mauritius"                            },
       { 175, "yt", "Mayotte"                              },
       { 484, "mx", "Mexico"                               },
       { 583, "fm", "Micronesia"                           },
       { 498, "md", "Moldova"                              },
       { 492, "mc", "Monaco"                               },
       { 496, "mn", "Mongolia"                             },
       { 499, "me", "Montenegro"                           },
       { 500, "ms", "Montserrat"                           },
       { 504, "ma", "Morocco"                              },
       { 508, "mz", "Mozambique"                           },
       { 104, "mm", "Myanmar"                              },
       { 516, "na", "Namibia"                              },
       { 520, "nr", "Nauru"                                },
       { 524, "np", "Nepal"                                },
       { 528, "nl", "Netherlands"                          },
       { 530, "an", "Netherlands Antilles"                 },
       { 540, "nc", "New Caledonia"                        },
       { 554, "nz", "New Zealand"                          },
       { 558, "ni", "Nicaragua"                            },
       { 562, "ne", "Niger"                                },
       { 566, "ng", "Nigeria"                              },
       { 570, "nu", "Niue"                                 },
       { 574, "nf", "Norfolk Island"                       },
       { 580, "mp", "Northern Mariana Islands"             },
       { 578, "no", "Norway"                               },
       { 512, "om", "Oman"                                 },
       { 586, "pk", "Pakistan"                             },
       { 585, "pw", "Palau"                                },
       { 275, "ps", "Palestinian Territory"                },
       { 591, "pa", "Panama"                               },
       { 598, "pg", "Papua New Guinea"                     },
       { 600, "py", "Paraguay"                             },
       { 604, "pe", "Peru"                                 },
       { 608, "ph", "Philippines"                          },
       { 612, "pn", "Pitcairn"                             },
       { 616, "pl", "Poland"                               },
       { 620, "pt", "Portugal"                             },
       { 630, "pr", "Puerto Rico"                          },
       { 634, "qa", "Qatar"                                },
       { 638, "re", "Reunion"                              },
       { 642, "ro", "Romania"                              },
       { 643, "ru", "Russia"                               },
       { 646, "rw", "Rwanda"                               },
       { 0,   "bl", "Saint Barthélemy"                     }, /* https://en.wikipedia.org/wiki/ISO_3166-2:BL */
       { 659, "kn", "Saint Kitts & Nevis"                  },
       { 662, "lc", "Saint Lucia"                          },
       { 663, "mf", "Saint Martin"                         },
       { 670, "vc", "Saint Vincent"                        },
       { 882, "ws", "Samoa"                                },
       { 674, "sm", "San Marino"                           },
       { 678, "st", "Sao Tome & Principe"                  },
       { 682, "sa", "Saudi Arabia"                         },
       { 686, "sn", "Senegal"                              },
       { 688, "rs", "Serbia"                               },
       { 690, "sc", "Seychelles"                           },
       { 694, "sl", "Sierra Leone"                         },
       { 702, "sg", "Singapore"                            },
       { 534, "sx", "Sint Maarten"                         },
       { 703, "sk", "Slovakia"                             },
       { 705, "si", "Slovenia"                             },
       {  90, "sb", "Solomon Islands"                      },
       { 706, "so", "Somalia"                              },
       { 710, "za", "South Africa"                         },
       { 239, "gs", "South Georgia"                        },
       { 728, "ss", "South Sudan"                          },
       { 724, "es", "Spain"                                },
       { 144, "lk", "Sri Lanka"                            },
       { 654, "sh", "St. Helena"                           },
       { 666, "pm", "St. Pierre & Miquelon"                },
       { 736, "sd", "Sudan"                                },
       { 740, "sr", "Suriname"                             },
       { 744, "sj", "Svalbard & Jan Mayen Islands"         },
       { 748, "sz", "Swaziland"                            },
       { 752, "se", "Sweden"                               },
       { 756, "ch", "Switzerland"                          },
       { 760, "sy", "Syrian Arab Republic"                 },
       { 626, "tl", "Timor-Leste"                          },
       { 158, "tw", "Taiwan"                               },
       { 762, "tj", "Tajikistan"                           },
       { 834, "tz", "Tanzania"                             },
       { 764, "th", "Thailand"                             },
       { 768, "tg", "Togo"                                 },
       { 772, "tk", "Tokelau"                              },
       { 776, "to", "Tonga"                                },
       { 780, "tt", "Trinidad & Tobago"                    },
       { 788, "tn", "Tunisia"                              },
       { 792, "tr", "Turkey"                               },
       { 795, "tm", "Turkmenistan"                         },
       { 796, "tc", "Turks & Caicos Islands"               },
       { 798, "tv", "Tuvalu"                               },
       { 800, "ug", "Uganda"                               },
       { 804, "ua", "Ukraine"                              },
       { 784, "ae", "United Arab Emirates"                 },
       { 826, "gb", "United Kingdom"                       },
       { 840, "us", "United States"                        },
       { 581, "um", "United States Minor Outlying Islands" },
       { 858, "uy", "Uruguay"                              },
       { 860, "uz", "Uzbekistan"                           },
       { 548, "vu", "Vanuatu"                              },
       { 862, "ve", "Venezuela"                            },
       { 704, "vn", "Vietnam"                              },
       {  92, "vg", "Virgin Islands (British)"             },
       { 850, "vi", "Virgin Islands (US)"                  },
       { 876, "wf", "Wallis & Futuna Islands"              },
       { 732, "eh", "Western Sahara"                       },
       { 887, "ye", "Yemen"                                },
       { 894, "zm", "Zambia"                               },
       { 716, "zw", "Zimbabwe"                             }
     };

size_t geoip_num_countries (void)
{
  return DIM(c_list);
}

const char *geoip_get_short_name_by_idx (int idx)
{
  if (idx < 0 || idx > DIM(c_list))
     return (NULL);
  return (c_list[idx].short_name);
}

const char *geoip_get_long_name_by_A2 (const char *short_name)
{
  const struct country_list *list = c_list + 0;
  size_t i, num = DIM(c_list);

  if (!short_name)
     return ("?");

  /* \todo: rewrite this into using bsearch().
   */
  for (i = 0; i < num; i++, list++)
  {
    if (!strnicmp(list->short_name,short_name, sizeof(list->short_name)))
       return (list->long_name);
  }
  return (NULL);
}

const char *geoip_get_long_name_by_id (int number)
{
  const struct country_list *list = c_list + 0;
  size_t i, num = DIM(c_list);

  /* Since several countries above have no assigned number, we cannot return a
   * sensible name.
   */
  if (number == 0)
     return ("?");

  /* \todo: rewrite this into using bsearch().
   */
  for (i = 0; i < num; i++, list++)
  {
    if (list->country_number == number)
       return (list->long_name);
  }
  return (NULL);
}

/*
 * Allocate memory for the geoip statistics array.
 * Keep a zero-element at the end.
 */
static void geoip_stats_init (void)
{
  size_t i, num, size;

  assert (geoip_stats_buf == NULL);

  num  = geoip_num_countries();
  size = sizeof(*geoip_stats_buf) * (num + 1);

  geoip_stats_buf = calloc (1, size);
  if (!geoip_stats_buf)
     size = 0;

  for (i = 0; size && i < num; i++)
  {
    const char *c_A2 = geoip_get_short_name_by_idx ((int)i);

    geoip_stats_buf[i].country[0] = TOUPPER (c_A2[0]);
    geoip_stats_buf[i].country[1] = TOUPPER (c_A2[1]);
  }
  TRACE (2, "Allocated %u bytes for geoip_stats_buf needed for %u countries.\n",
         (unsigned)size, (unsigned)num);
}

static void geoip_stats_exit (void)
{
  if (geoip_stats_buf)
     free (geoip_stats_buf);
  geoip_stats_buf = NULL;
}

/*
 * Update the country statistics for an IPv4 or IPv6-address.
 * 'country_A2' should already be in upper case.
 */
static void geoip_stats_update (const char *country_A2, int flag)
{
  struct geoip_stats *stats;
  int    c1, c2 = (int)country_A2[0] + ((int)country_A2[1] << 8);
  size_t i;

  for (i = 0, stats = geoip_stats_buf;
       stats && i < geoip_num_countries();
       stats++, i++)
  {
    c1 = (int)stats->country[0] + ((int)stats->country[1] << 8);
    if (c1 == c2)
    {
      if (flag & GEOIP_STAT_IPV4)
           stats->num4++;
      else if (flag & GEOIP_STAT_IPV6)
           stats->num6++;
      stats->flag |= flag;
      break;
    }
  }
  if (!stats)
       TRACE (2, "Found unknown country \"%.2s\" not in 'c_list[]'!.\n", country_A2);
  else TRACE (3, "geoip_stats_update() for \"%.2s\" at index: %d.\n", country_A2, (int)i);
}

/*
 * This function assumes the above 'geoip_stats_update()' was called to update
 * 'stats->num[46]'. Hence if 'country_A2' is found and 'stats->num[46] > 1', the country
 * is no longer considered unique when 'flag == stats->flag'.
 */
int geoip_stats_is_unique (const char *country_A2, int flag)
{
  const struct geoip_stats *stats;
  int    c1, c2 = (int)country_A2[0] + ((int)country_A2[1] << 8);
  size_t i;

  for (i = 0, stats = geoip_stats_buf;
       stats && i <= geoip_num_countries();
       stats++, i++)
  {
    c1 = (int)stats->country[0] + ((int)stats->country[1] << 8);
    if (c1 == c2 && (stats->flag & flag))
       break;
  }

  if (stats)
  {
    if (flag & GEOIP_STAT_IPV4)
       return  (stats->num4 == 1);
    return (stats->num6 == 1);
  }
  return (0);
}

void geoip_num_unique_countries (DWORD *num_ip4, DWORD *num_ip6, DWORD *num_ip2loc4, DWORD *num_ip2loc6)
{
  const struct geoip_stats *stats;
  DWORD  n4 = 0, n6 = 0;
  DWORD  ip2loc_n4 = 0;
  DWORD  ip2loc_n6 = 0;
  size_t i;

  for (i = 0, stats = geoip_stats_buf;
       stats && i < geoip_num_countries();
       stats++, i++)
  {
    if (stats->num4 > 0)
    {
      n4++;
      if (stats->flag & GEOIP_VIA_IP2LOC)
         ip2loc_n4++;
    }
    if (stats->num6 > 0)
    {
      n6++;
      if (stats->flag & GEOIP_VIA_IP2LOC)
         ip2loc_n6++;
    }
  }
  if (num_ip4)
     *num_ip4 = n4;
  if (num_ip6)
     *num_ip6 = n6;
  if (num_ip2loc4)
     *num_ip2loc4 = ip2loc_n4;
  if (num_ip2loc6)
     *num_ip2loc6 = ip2loc_n6;

  TRACE (2, "%s() n4: %lu, n6: %lu, ip2loc_n4: %lu, ip2loc_n6: %lu.\n",
         __FUNCTION__,
         DWORD_CAST(n4),        DWORD_CAST(n6),
         DWORD_CAST(ip2loc_n4), DWORD_CAST(ip2loc_n6));
}

uint64 geoip_get_stats_by_idx (int idx)
{
  if (!geoip_stats_buf || idx < 0 || idx > (int)geoip_num_countries())
     return (0);
  return (geoip_stats_buf[idx].num4 + geoip_stats_buf[idx].num6);
}

/*
 * Download a single file using the WinInet API.
 * Load WinInet.dll dynamically.
 */
typedef HINTERNET (WINAPI *func_InternetOpenA) (const char *user_agent,
                                                DWORD       access_type,
                                                const char *proxy_name,
                                                const char *proxy_bypass,
                                                DWORD       flags);

typedef HINTERNET (WINAPI *func_InternetOpenUrlA) (HINTERNET   hnd,
                                                   const char *url,
                                                   const char *headers,
                                                   DWORD       headers_len,
                                                   DWORD       flags,
                                                   DWORD_PTR   context);

typedef BOOL (WINAPI *func_InternetGetLastResponseInfoA) (DWORD *err_code,
                                                          char  *err_buff,
                                                          DWORD *err_buff_len);

typedef BOOL (WINAPI *func_InternetReadFile) (HINTERNET hnd,
                                              VOID     *buffer,
                                              DWORD     num_bytes_to_read,
                                              DWORD    *num_bytes_read);

typedef BOOL (WINAPI *func_InternetCloseHandle) (HINTERNET handle);

static func_InternetOpenA                p_InternetOpenA;
static func_InternetOpenUrlA             p_InternetOpenUrlA;
static func_InternetGetLastResponseInfoA p_InternetGetLastResponseInfoA;
static func_InternetReadFile             p_InternetReadFile;
static func_InternetCloseHandle          p_InternetCloseHandle;

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
        (p_InternetGetLastResponseInfoA)(&wininet_err,wininet_err_buf,&wininet_err_len) &&
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
static DWORD download_file (const char *file, const char *url)
{
  DWORD rc = 0;
  DWORD flags = INTERNET_FLAG_IGNORE_REDIRECT_TO_HTTP |
                INTERNET_FLAG_IGNORE_REDIRECT_TO_HTTPS |
                INTERNET_FLAG_NO_UI;
  HINTERNET   h1 = NULL;
  HINTERNET   h2 = NULL;
  FILE       *fil = NULL;
  DWORD       access_type = INTERNET_OPEN_TYPE_DIRECT;
  const char *proxy_name = NULL;
  const char *proxy_bypass = NULL;

  if (load_dynamic_table(funcs, DIM(funcs)) != DIM(funcs))
  {
    TRACE (0, "Failed to load needed WinInet.dll functions.\n");
    return (0);
  }

  if (g_cfg.geoip_proxy && g_cfg.geoip_proxy[0])
  {
    proxy_name = g_cfg.geoip_proxy;
    proxy_bypass = "<local>";
    access_type = INTERNET_OPEN_TYPE_PROXY;
  }

  TRACE (2, "Calling InternetOpenA(): proxy: %s, URL: %s.\n", proxy_name, url);

  h1 = (*p_InternetOpenA) ("GeoIP-update", access_type, proxy_name, proxy_bypass, 0);
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

static int touch_file (const char *file)
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
 * Figure out if a download is needed.
 */
static DWORD update_file (const char *loc_file, const char *tmp_file, const char *url, BOOL force_update)
{
  struct stat st_tmp,  st_loc;
  BOOL       _st_tmp, _st_loc, equal = FALSE;
  time_t      now  = time (NULL);
  time_t      past = now - 24 * 3600 * g_cfg.geoip_max_days;
  DWORD       rc = 0;

  _st_tmp = (stat(tmp_file, &st_tmp) == 0);
  _st_loc = (stat(loc_file, &st_loc) == 0);

  TRACE (1, "updating \"%s\"\n", loc_file);

  if (!force_update && _st_loc && st_loc.st_mtime >= past)
  {
    TRACE (1, "update not needed for \"%s\". Try again in %ld days.\n",
           loc_file, g_cfg.geoip_max_days + (long int)(now-st_loc.st_mtime)/(24*3600));
    return (rc);
  }

  if (!_st_tmp || force_update)
  {
    rc = download_file (tmp_file, url);
    TRACE (1, "download_file (%s) -> rc: %lu\n", tmp_file, DWORD_CAST(rc));
    if (rc > 0)
       _st_tmp = (stat(tmp_file, &st_tmp) == 0);
  }

  if (_st_loc)
  {
    equal = (st_tmp.st_mtime >= st_loc.st_mtime) && (st_tmp.st_size == st_loc.st_size);
    TRACE (1, "local file exist, equal: %d\n", equal);
    touch_file (loc_file);
  }

  if ((_st_tmp && !_st_loc) || !equal)
  {
    TRACE (1, "%s -> %s\n", tmp_file, loc_file);
    CopyFile (tmp_file, loc_file, FALSE);
    stat (loc_file, &st_loc);
    rc = st_loc.st_size;
  }
  return (rc);
}

/*
 * Check and download files from:
 *   g_cfg.geoip4_url = https://gitweb.torproject.org/tor.git/plain/src/config/geoip   (if 'family == AF_INET')
 *   g_cfg.geoip6_url = https://gitweb.torproject.org/tor.git/plain/src/config/geoip6  (if 'family == AF_INET6')
 */
void geoip_update_file (int family, BOOL force_update)
{
  char        tmp_file [MAX_PATH];
  const char *env = getenv ("TEMP");

  if (family == AF_INET)
  {
    snprintf (tmp_file, sizeof(tmp_file), "%s\\%s", env, "geoip.tmp");
    update_file (g_cfg.geoip4_file, tmp_file, g_cfg.geoip4_url, force_update);
  }
  else if (family == AF_INET6)
  {
    snprintf (tmp_file, sizeof(tmp_file), "%s\\%s", env, "geoip6.tmp");
    update_file (g_cfg.geoip6_file, tmp_file, g_cfg.geoip6_url, force_update);
  }
  else
    TRACE (0, "Unknown address-family %d\n", family);
}

#if defined(TEST_GEOIP)

#include "getopt.h"
#include "dnsbl.h"

/*
 * Determine length of the network part in an IPv4 address.
 * Courtesey of 'Lev Walkin <vlm@lionet.info>'.
 */
static int network_len32 (DWORD hi, DWORD lo)
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
static int network_len128 (const struct in6_addr *a, const struct in6_addr *b)
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

static int check_ipv4_unallocated (FILE *out, int dump_cidr,
                                   const struct ipv4_node *entry, const struct ipv4_node *last,
                                   long *diff_p)
{
  struct in_addr addr;
  long   diff = (long)(entry->low - last->high);
  int    len;
  BOOL   special = FALSE;
  BOOL   mcast = FALSE;
  BOOL   global = FALSE;
  const char *remark = NULL;

  if (diff > 1)
  {
    addr.s_addr = swap32 (last->high+1);
    fprintf (out, "    **: ");
    if (dump_cidr)
    {
      char low[25] = "?";
      int  nw_len = network_len32 (last->high+1, entry->low-1);

      wsock_trace_inet_ntop4 ((const u_char*)&addr, low, sizeof(low));
      len = fprintf (out, "%s/%d", low, nw_len);
    }
    else
    {
      fprintf (out, "%10lu  %10lu %8ld",
               DWORD_CAST(last->high+1), DWORD_CAST(entry->low-1), LONG_CAST(diff));
      len = 22;
    }

    special = geoip_addr_is_special (&addr, NULL, &remark);
    mcast   = geoip_addr_is_multicast (&addr, NULL);
    global  = geoip_addr_is_global (&addr, NULL);

    fprintf (out, "%*sUnallocated block%s%s%s %s\n",
             24-len, "",
             special ? ", Special"   : "",
             mcast   ? ", Multicast" : "",
             !global ? ", !Global"   : "",
             remark  ? remark        : "");

    *diff_p = 0;
    if (special)
       return (0);
    *diff_p = diff;
    return (1);
  }
  return (0);
}

static void dump_ipv4_entries (FILE *out, int dump_cidr, int raw)
{
  int   i, len, max;
  DWORD missing_blocks = 0;
  DWORD missing_addr = 0;
  long  diff = 0;
  const struct ipv4_node *last = NULL;

  if (!raw)
  {
    fputs ("IPv4 entries:\n Index: ", out);
    if (dump_cidr)
         fputs ("CIDR                    Country\n", out);
    else fputs ("  IP-low      IP-high      Diff  Country\n", out);
  }

  max = geoip_ipv4_entries ? smartlist_len (geoip_ipv4_entries) : 0;
  for (i = 0; i < max; i++)
  {
    const struct ipv4_node *entry = smartlist_get (geoip_ipv4_entries, i);

    if (!raw && last)
    {
      missing_blocks += check_ipv4_unallocated (out, dump_cidr, entry, last, &diff);
      missing_addr   += (DWORD)diff;
    }
    last = entry;

    if (dump_cidr)
    {
      char  low[25] = "?";
      int   nw_len = network_len32 (entry->high, entry->low);
      DWORD addr   = swap32 (entry->low);

      wsock_trace_inet_ntop4 ((const u_char*)&addr, low, sizeof(low));
      len = fprintf (out, "%6d: %s/%d", i, low, nw_len);
    }
    else
    {
      if (raw)
           fprintf (out, "  { %10luU, %10luU, ", DWORD_CAST(entry->low), DWORD_CAST(entry->high));
      else fprintf (out, "%6d: %10lu  %10lu %8ld",
                    i, DWORD_CAST(entry->low), DWORD_CAST(entry->high),
                    (long)(entry->high - entry->low));
      len = 30;
    }
    if (raw)
         fprintf (out, " \"%2.2s\" },\n", entry->country);
    else fprintf (out, " %*s %2.2s - %s\n", 30-len, "", entry->country, geoip_get_long_name_by_A2(entry->country));
  }

  if (!raw)
  {
    fprintf (out, "%s missing blocks ", dword_str(missing_blocks));
    fprintf (out, "totalling %s missing IPv4 addresses.\n", dword_str(missing_addr));
  }
}

static void hex_dump (FILE *out, const void *data_p, size_t datalen)
{
  const BYTE *data = (const BYTE*) data_p;
  UINT  i;

  for (i = 0; i < datalen; i++)
  {
    fprintf (out, "0x%02X", (unsigned)data[i]);
    if (i < datalen-1)
       fputc (',', out);
  }
}

static int check_ipv6_unallocated (FILE *out, int dump_cidr, const struct ipv6_node *entry, const struct ipv6_node *last, uint64 *diff_p)
{
#if 0    /* \todo */
  uint64 diff = (long)(entry->low - last->high);
  int    len;

  if (diff > 1)
  {
    fprintf (out, "    **: ");
    if (dump_cidr)
    {
      char  low[25] = "?";
      int   nw_len = network_len32 (last->high+1, entry->low-1);
      DWORD addr   = swap32 (last->high+1);

      wsock_trace_inet_ntop4 ((const u_char*)&addr, low, sizeof(low));
      len = fprintf (out, "%s/%d", low, nw_len);
    }
    else
    {
      fprintf (out, "%10lu  %10lu %8ld",
               DWORD_CAST(last->high+1), DWORD_CAST(entry->low-1), LONG_CAST(diff));
      len = 22;
    }
    fprintf (out, "%*sUnallocated block\n", 24-len, "");
    *diff_p = diff;
    return (1);
  }
#endif
  *diff_p = 0;
  return (0);
}

static void dump_ipv6_entries (FILE *out, int dump_cidr, int raw)
{
  int    i, len, max;
  uint64 missing_blocks = 0;
  uint64 missing_addr = 0;
  uint64 diff;
  const struct ipv6_node *last = NULL;

  if (!raw)
  {
    fputs ("IPv6 entries:\nIndex: ", out);

    if (dump_cidr)
         fprintf (out, "%-*s Country\n", (int)(MAX_IP6_SZ-5), "CIDR");
    else fprintf (out, "%-*s %-*s Country\n", (int)(MAX_IP6_SZ-4), "IP-low", (int)(MAX_IP6_SZ-5), "IP-high");
  }

  max = geoip_ipv6_entries ? smartlist_len (geoip_ipv6_entries) : 0;
  for (i = 0; i < max; i++)
  {
    const struct ipv6_node *entry = smartlist_get (geoip_ipv6_entries, i);
    char  low  [MAX_IP6_SZ] = "?";
    char  high [MAX_IP6_SZ] = "?";
    int   nw_len;

    if (!raw && last)
    {
      missing_blocks += check_ipv6_unallocated (out, dump_cidr, entry, last, &diff);
      missing_addr   += diff;
    }
    last = entry;

    wsock_trace_inet_ntop6 ((const u_char*)&entry->low, low, sizeof(low));
    wsock_trace_inet_ntop6 ((const u_char*)&entry->high, high, sizeof(high));

    if (raw)
    {
      fputs (" { {", out);
      hex_dump (out, &entry->low, sizeof(entry->low));
      fputs ("},\n"
             "   {", out);
      hex_dump (out, &entry->high, sizeof(entry->high));
      fputs ("}, ", out);
    }
    else if (dump_cidr)
    {
#if 0
      char *end = low + strlen(low);

      if (!strncmp(end-2,"::",2))   /* Drop the last "::" */
         end[-2] = '\0';
#endif
      nw_len = network_len128 (&entry->high, &entry->low);
      len = fprintf (out, "%5d: %s/%d ", i, low, nw_len);
    }
    else
    {
      fprintf (out, "%5d: %-*s %-*s", i, (int)(MAX_IP6_SZ-4), low, (int)(MAX_IP6_SZ-4), high);
      len = 50;
    }

    if (raw)
         fprintf (out, "\"%s\" },\n", entry->country);
    else fprintf (out, "%*.2s - %s\n", 51-len, entry->country, geoip_get_long_name_by_A2(entry->country));
  }

  if (!raw)
  {
    fprintf (out, "%s missing blocks ", qword_str(missing_blocks));
    fprintf (out, "totalling %s missing IPv6 addresses.\n", qword_str(missing_addr));
  }
}

static void dump_num_ip_blocks_by_country (void)
{
  const struct country_list *list = c_list + 0;
  size_t                     i, num_c = DIM(c_list);
  size_t                    *counts4 = alloca (sizeof(*counts4) * num_c);
  size_t                    *counts6 = alloca (sizeof(*counts6) * num_c);

  memset (counts4, 0, sizeof(*counts4) * num_c);
  memset (counts6, 0, sizeof(*counts6) * num_c);

  puts ("IPv4/6 blocks by countries:\n"
        " Idx: Country                           IPv4   IPv6");

  if (geoip_ipv4_entries)
     for (i = 0; i < num_c; i++, list++)
     {
       int j, max = smartlist_len (geoip_ipv4_entries);

       for (j = 0; j < max; j++)
       {
         const struct ipv4_node *entry = smartlist_get (geoip_ipv4_entries, j);
         if (!strnicmp(entry->country, list->short_name, 2))
         {
           counts4[i]++;
        // tot_ip_counts[i] += entry->high - entry->low;
         }
       }
     }

  list = c_list + 0;

  if (geoip_ipv6_entries)
     for (i = 0; i < num_c; i++, list++)
     {
       int j, max = smartlist_len (geoip_ipv6_entries);

       for (j = 0; j < max; j++)
       {
         const struct ipv6_node *entry = smartlist_get (geoip_ipv6_entries, j);
         if (!strnicmp(entry->country, list->short_name, 2))
            counts6[i]++;
       }
     }

  list = c_list + 0;

  for (i = 0; i < num_c; i++, list++)
      printf (" %3d: %c%c, %-28.28s %5u  %5u\n",
              (int)i, TOUPPER(list->short_name[0]), TOUPPER(list->short_name[1]),
              list->long_name, (unsigned)counts4[i], (unsigned)counts6[i]);
  puts ("");
}

#ifdef USE_IP2LOCATION
/*
 * Get the region/city from the last successful call to either
 * 'geoip_get_country_by_ipv4()' or 'geoip_get_country_by_ipv6()'.
 *
 * Just mimick the code in 'geoip_get_location_by_ipvX()' here
 * as those functions doesn't use it's 'struct in_addr *' and
 * 'struct in6_addr *' arguments.
 */
static const char *get_location (void)
{
  static char buf[110];

  if (IP2LOC_IS_GOOD())
       snprintf (buf, sizeof(buf), "loc: %s/%s", g_ip2loc_entry.city, g_ip2loc_entry.region);
  else strcpy (buf, "loc: <unknown>");
  return (buf);
}
#endif

/*
 * Common code for testing an IPv4 or IPv6 address.
 */
static void test_addr_common (const struct in_addr  *a4,
                              const struct in6_addr *a6,
                              BOOL use_ip2loc)
{
  const char *location = NULL;
  const char *comment  = NULL;
  const char *remark   = NULL;
  const char *cc;
  int   save, flag, width = 0;
  char  buf1 [100];
  char  buf2 [100];

  /* Start the timing now. Print the delta-time at the end.
   */
  get_timestamp2();

  /* Needed for 'geoip_stats_update()' and the "unique" counter to work
   */
  save = g_cfg.trace_report;
  g_cfg.trace_report = 1;

  cc = (a4 ? geoip_get_country_by_ipv4(a4) :
             geoip_get_country_by_ipv6(a6));

  flag = (a4 ? GEOIP_STAT_IPV4 : GEOIP_STAT_IPV6);

  g_cfg.trace_report = save;

  if (cc && *cc != '-')
  {
#ifdef USE_IP2LOCATION
    if (use_ip2loc)
    {
      width = 40;
      location = get_location();
    }
#endif

    /* Longest name from 'geoip_get_long_name_by_A2()' is
     * "United States Minor Outlying Islands". 36 characters.
     * Truncate to 20 thus becoming "United States Minor".
     */
    snprintf (buf1, sizeof(buf1),
              "%-2s, %-20.20s %-*.*s",
              cc, geoip_get_long_name_by_A2(cc), width, width, location);
    snprintf (buf2, sizeof(buf2), "unique: %d", geoip_stats_is_unique(cc,flag));
  }
  else
  {
    if (geoip_addr_is_zero(a4,a6))
       comment = "NULL-addr";
    else if (geoip_addr_is_multicast(a4,a6))
       comment = "Multicast";
    else if (geoip_addr_is_special(a4,a6,&remark))
       comment = "Special";
    else if (!geoip_addr_is_global(a4,a6))
       comment = "Not global";
    else
       comment = "Unallocated?";

    if (remark)
         snprintf (buf1, sizeof(buf1), "%s (%s)", comment, remark);
    else snprintf (buf1, sizeof(buf1), "%s", comment);

    if (a4 && geoip_ipv4_entries)
         snprintf (buf2, sizeof(buf2), "%lu compares", DWORD_CAST(num_4_compare));
    else if (a6 && geoip_ipv6_entries)
         snprintf (buf2, sizeof(buf2), "%lu compares", DWORD_CAST(num_6_compare));
    else strcpy (buf2, "??");
  }

#ifdef USE_IP2LOCATION
  width = 60;
#else
  width = 29;
#endif

  if (!use_ip2loc)
     width = 29;

  printf ("%-*.*s %-25.25s %s\n", width, width, buf1, buf2, get_timestamp2());

  /* Check the global IPv4 / IPv6 address for membership in a SpamHaus DROP / EDROP list
   */
  if (geoip_addr_is_global(a4, NULL))
  {
    const char *sbl_ref  = NULL;
    BOOL        rc = DNSBL_check_ipv4 (a4, &sbl_ref);
    char        addr [20];

    if (!sbl_ref)
       sbl_ref = " <none>";
    if (rc)
    {
      wsock_trace_inet_ntop4 ((const u_char*)a4, addr, sizeof(addr));
      printf ("  %s listed as SpamHaus SBL%s\n", addr, sbl_ref);
    }
  }
  else if (geoip_addr_is_global(NULL, a6))
  {
    const char *sbl_ref  = NULL;
    BOOL        rc = DNSBL_check_ipv6 (a6, &sbl_ref);
    char        addr [MAX_IP6_SZ];

    if (!sbl_ref)
       sbl_ref = " <none>";
    if (rc)
    {
      wsock_trace_inet_ntop6 ((const u_char*)a6, addr, sizeof(addr));
      printf ("  %s listed as SpamHaus SBL%s\n", addr, sbl_ref);
    }
  }

#ifndef USE_IP2LOCATION
  ARGSUSED (use_ip2loc);
#endif
}

static void test_addr4 (const char *ip4_addr, BOOL use_ip2loc)
{
  struct in_addr addr;

  if (wsock_trace_inet_pton4((const char*)ip4_addr, (u_char*)&addr) == 1)
       test_addr_common (&addr, NULL, use_ip2loc);
  else printf ("'%s': Invalid address: %s.\n", ip4_addr, get_ws_error());
}

static void test_addr6 (const char *ip6_addr, BOOL use_ip2loc)
{
  struct in6_addr addr;

  if (wsock_trace_inet_pton6(ip6_addr,(u_char*)&addr) == 1)
       test_addr_common (NULL, &addr, use_ip2loc);
  else printf ("Invalid address: %s.\n", get_ws_error());
}

/*
 * Called on 'geoip.exe -g4 <file>' or
 *           'geoip.exe -g6 <file>' to generate a '<file>' with
 * fixed IPv4 or IPv6 arrays:
 *   static struct ipv4_node ipv4_gen_array [NNN] and
 *   static struct ipv6_node ipv6_gen_array [NNN].
 *
 * These files are then compiled into normal obj-files and the arrays are
 * accessed via these functions (also generated):
 *   smartlist_t *geoip_smartlist_fixed_ipv4 (void);
 *   smartlist_t *geoip_smartlist_fixed_ipv6 (void);
 */
static int geoip_generate_array (int family, const char *out_file)
{
  int    len, fam;
  time_t now = time (NULL);
  FILE  *out;

  if (family == AF_INET && geoip_ipv4_entries)
  {
    len = smartlist_len (geoip_ipv4_entries);
    fam = '4';
  }
  else if (family == AF_INET6 && geoip_ipv6_entries)
  {
    len = smartlist_len (geoip_ipv6_entries);
    fam = '6';
  }
  else
  {
    printf ("family must be AF_INET or AF_INET6.\n");
    return (1);
  }

  if (!strcmp(out_file,"-"))
       out = stdout;
  else out = fopen (out_file, "w+t");
  if (!out)
  {
    printf ("Failed to create file %s; %s\n", out_file, strerror(errno));
    return (1);
  }

  fprintf (out,
           "/*\n"
           " * This file was generated at %.24s.\n"
           " * by the Makefile command: \"geoip.exe -%cg %s\"\n"
           " * Built by %s. DO NOT EDIT!\n"
           " */\n"
           "#include \"geoip.h\"\n"
           "\n"
           "GCC_PRAGMA (GCC diagnostic ignored \"-Wmissing-braces\")\n"
           "\n", ctime(&now), fam, out_file, get_builder());

  fprintf (out, "static struct ipv%c_node ipv%c_gen_array [%d] = {\n", fam, fam, len);

  if (family == AF_INET)
       dump_ipv4_entries (out, 0, 1);
  else dump_ipv6_entries (out, 0, 1);

  fprintf (out,
           "};\n"
           "\n"
           "smartlist_t *geoip_smartlist_fixed_ipv%c (void)\n"
           "{\n"
           "  return geoip_smartlist_fixed (&ipv%c_gen_array, sizeof(ipv%c_gen_array[0]), %d);\n"
           "}\n\n", fam, fam, fam, len);
  fclose (out);
  return (0);
}

/*
 * A random integer in range [a..b].
 *   http://stackoverflow.com/questions/2509679/how-to-generate-a-random-number-from-within-a-range
 */
unsigned int static rand_range (unsigned int min, unsigned int max)
{
  double scaled = (double) rand()/RAND_MAX;
  return (unsigned int) ((max - min + 1) * scaled) + min;
}

/*
 * Generates a random IPv4/6 address.
 */
static void make_random_addr (struct in_addr *addr4, struct in6_addr *addr6)
{
  int i;

  if (addr4)
  {
    addr4->S_un.S_un_b.s_b1 = rand_range (1,255);
    addr4->S_un.S_un_b.s_b2 = rand_range (1,255);
    addr4->S_un.S_un_b.s_b3 = rand_range (1,255);
    addr4->S_un.S_un_b.s_b4 = rand_range (1,255);
  }
  if (addr6)
  {
    addr6->s6_words[0] = swap16 (0x2001); /* Since most IPv6 addr has this prefix */
    for (i = 1; i < 8; i++)
        addr6->s6_words[i] = rand_range (0,0xFFFF);
  }
}

static void show_help (const char *my_name)
{
#ifdef USE_IP2LOCATION
  #define I_OPT   "i"
  #define I_HELP  "       -i:      do no use the IP2Location database.\n"
#else
  #define I_OPT   ""
  #define I_HELP  ""
#endif

  printf ("Usage: %s [-cdfG%snruh] [-g file] <-4|-6> address(es)\n"
          "       -c:      dump addresses on CIDR form.\n"
          "       -d:      dump address entries for countries and count of blocks.\n"
          "       -f:      force an update with the '-u' option.\n"
          "       -G:      use generated built-in IPv4/IPv6 arrays.\n"
          "       -g file: generate IPv4/IPv6 tables to <file> (or '-' for stdout).\n"
          "%s"
          "       -n #:    number of loops for random test.\n"
          "       -r:      random test for '-n' rounds (default 10).\n"
          "       -u:      test updating of geoip files.\n"
          "       -4:      test IPv4 address(es).\n"
          "       -6:      test IPv6 address(es).\n"
          "       -h:      this help.\n",
          my_name, I_OPT, I_HELP);
  printf ("   address(es) can also come from a response-file: '@file-with-addr'.\n"
          "   Or from 'stdin': \"cat file-with-addr | geoip.exe -4\".\n"
          "   Built by %s\n", get_builder());
  wsock_trace_exit();
  exit (0);
}

typedef void (*test_func) (const char *addr, BOOL use_ip2loc);

static void test_addr_list (smartlist_t *list, BOOL use_ip2loc, test_func func)
{
  int   i, max = smartlist_len (list);
  DWORD num;

  for (i = 0; i < max; i++)
      (*func) (smartlist_get(list, i), use_ip2loc);
  if (max > 1)
  {
    geoip_num_unique_countries (&num, NULL, NULL, NULL);
    printf ("# of unique IPv%c countries: %lu\n",
            (func == test_addr4 ? '4' : '6'), DWORD_CAST(num));
  }
}

static void rand_test_addr4 (int loops, BOOL use_ip2loc)
{
  DWORD num_ip4;
  int   i;

  srand ((unsigned int)time(NULL));

  for (i = 0; i < loops; i++)
  {
    struct in_addr addr;
    char   buf [20];

    make_random_addr (&addr, NULL);
    wsock_trace_inet_ntop4 ((const u_char*)&addr, buf, sizeof(buf));
    printf ("%-15s: ", buf);
    test_addr4 (buf, use_ip2loc);
  }
  geoip_num_unique_countries (&num_ip4, NULL, NULL, NULL);
  printf ("# of unique IPv4 countries: %lu\n", DWORD_CAST(num_ip4));
}

static void rand_test_addr6 (int loops, BOOL use_ip2loc)
{
  DWORD num_ip6;
  int   i;

  srand ((unsigned int)time(NULL));

  for (i = 0; i < loops; i++)
  {
    struct in6_addr addr;
    char   buf [MAX_IP6_SZ];

    make_random_addr (NULL, &addr);
    wsock_trace_inet_ntop6 ((const u_char*)&addr, buf, sizeof(buf));
    printf ("%-40s: ", buf);
    test_addr6 (buf, use_ip2loc);
  }
  geoip_num_unique_countries (NULL, &num_ip6, NULL, NULL);
  printf ("# of unique IPv6 countries: %lu\n", DWORD_CAST(num_ip6));
}

/*
 * This accepts only address per line.
 */
static smartlist_t *read_file (FILE *f, smartlist_t *list)
{
  while (f && !feof(f))
  {
    char buf[512], *p;

    if (fgets(buf, (int)sizeof(buf), f) == NULL)
       break;

    /* Remove blanks, newlines or '#' comments.
     */
    str_rip (buf);
    p = strchr (buf, '#');
    if (p)
       *p = '\0';
    p = strchr (buf, ' ');
    if (p)
       *p = '\0';
    smartlist_add (list, strdup(buf));
  }
  if (f && f != stdin)
     fclose (f);
  return (list);
}

static smartlist_t *make_argv_list (int _argc, char **_argv)
{
  smartlist_t *list = smartlist_new();
  int          i;

  /*
   * Since Cygwin already converts a '@file' on the cmd-line into an
   * 'argv[]', this is of no use. And I found no way to disable this.
   */
#if !defined(__CYGWIN__)
  if (_argc > 0 && _argv[0][0] == '@')
     return read_file (fopen(_argv[0]+1,"rb"), list);
#endif

  if (isatty(fileno(stdin)) == 0)
     return read_file (stdin, list);

  for (i = 0; i < _argc; i++)
      smartlist_add (list, strdup(_argv[i]));
  return (list);
}

static void free_argv_list (smartlist_t *sl)
{
  int i, max = smartlist_len (sl);

  for (i = 0; i < max; i++)
      free (smartlist_get(sl, i));
  smartlist_free (sl);
}

static int check_requirements (BOOL check_geoip4, BOOL check_geoip6)
{
  if (check_geoip4 && (!g_cfg.geoip4_file || !file_exists(g_cfg.geoip4_file)))
  {
    printf ("'geoip4' file '%s' not found. This is needed for these tests.\n", g_cfg.geoip4_file);
    return (0);
  }
  if (check_geoip6 && (!g_cfg.geoip6_file || !file_exists(g_cfg.geoip6_file)))
  {
    printf ("'geoip6' file '%s' not found. This is needed for these tests.\n", g_cfg.geoip6_file);
    return (0);
  }
  if (!g_cfg.geoip_enable)
  {
    printf ("'[geoip]' section must have 'enable=1' in %s to use this option.\n", config_file_name());
    return (0);
  }
  return (1);
}

int main (int argc, char **argv)
{
  int c, do_cidr = 0,  do_4 = 0, do_6 = 0, do_force = 0;
  int do_update = 0, do_dump = 0, do_rand = 0, do_generate = 0;
  int use_ip2loc = 1;
  int loops = 10;
  int rc = 0;
  const char *my_name = argv[0];
  const char *g_file = NULL;

  wsock_trace_init();
  g_cfg.trace_use_ods = FALSE;

  while ((c = getopt (argc, argv, "h?cdfGg:" I_OPT "n:ru46")) != EOF)
    switch (c)
    {
      case '?':
      case 'h':
           show_help (my_name);
           break;
      case 'c':
           do_cidr = 1;
           break;
      case 'd':
           do_dump++;
           break;
      case 'f':
           do_force = 1;
           break;
      case 'g':
           do_generate++;
           g_file = optarg;
           break;
      case 'G':
           geoip_exit();
           g_cfg.geoip_use_generated = TRUE;
           geoip_load_data (AF_INET);
           geoip_load_data (AF_INET6);
           geoip_stats_init();
           break;
      case 'i':
           use_ip2loc = 0;
           break;
      case 'n':
           loops = atoi (optarg);
           break;
      case 'r':
           do_rand = 1;
           break;
      case 'u':
           do_update = 1;
           break;
      case '4':
           do_4 = 1;
           break;
      case '6':
           do_6 = 1;
           break;
    }

  if (!do_4 && !do_6)
     show_help (my_name);

  /* Possibly call 'ip2loc_init()' again.
   */
  use_ip2loc ? (void)ip2loc_init() : (void)ip2loc_exit();

  if (do_update)
  {
    if (do_4)
       geoip_update_file (AF_INET, do_force);
    if (do_6)
       geoip_update_file (AF_INET6, do_force);
  }
  else if (!g_cfg.geoip_use_generated)
  {
    if (!check_requirements(TRUE, TRUE))
       return (0);
  }

  if (do_generate)
  {
    if (!check_requirements(do_4, do_6))
       rc++;
    else if (do_4)
       rc += geoip_generate_array (AF_INET, g_file);
    if (do_6)
       rc += geoip_generate_array (AF_INET6, g_file);
    return (rc);
  }

  argc -= optind;
  argv += optind;

  if (do_dump)
  {
    if (do_4)
       dump_ipv4_entries (stdout, do_cidr, 0);
    if (do_6)
       dump_ipv6_entries (stdout, do_cidr, 0);
    if (do_dump >= 2 && (do_4 || do_6))
       dump_num_ip_blocks_by_country();
  }

  if (do_rand)
  {
    if (do_4)
       rand_test_addr4 (loops, use_ip2loc);
    if (do_6)
       rand_test_addr6 (loops, use_ip2loc);
  }
  else
  {
    smartlist_t *list = make_argv_list (argc, argv);

    if (do_4)
       test_addr_list (list, use_ip2loc, test_addr4);
    if (do_6)
       test_addr_list (list, use_ip2loc, test_addr6);
    free_argv_list (list);
  }

  wsock_trace_exit();
  return (rc);
}
#endif  /* TEST_GEOIP */

