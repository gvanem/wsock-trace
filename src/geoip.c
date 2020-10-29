/**\file    geoip.c
 * \ingroup Geoip
 *
 * \brief Implements parsing of CSV value files of MaxMind's IPv4 + IPv6
 *        geoip-data files.
 *        It is inspired by Tor's `geoip.c`: <br>
 *          https://gitweb.torproject.org/tor.git/tree/src/feature/stats/geoip.c
 *
 * geoip.c - Part of Wsock-Trace.
 *
 * \todo
 *   Use MaxMind's `GeoLite2-City.mmdb` [1] or `DBIP*.mmdb` [2] files and print the location (city + location) too.
 *   This will have to be coded in `geoip_get_location_by_ipv4()` and `geoip_get_location_by_ipv6()`.
 *   Emulate what this command does:
 *     \code
 *     mmdblookup.exe -f GeoLite2-City.mmdb --ip 102.12.212.12 country names en
 *     \endcode
 *   giving:
 *     \code
 *     "Egypt" <utf8_string>
 *     \endcode
 *
 *   Or this command:
 *     \code
 *     mmdblookup.exe -f GeoLite2-City.mmdb --ip 102.12.212.12 city names en
 *     \endcode
 *   giving:
 *     \code
 *    "Cairo" <utf8_string>
 *     \endcode
 *
 *   Or this command:
 *     \code
 *     mmdblookup.exe -f GeoLite2-City.mmdb --ip 102.12.212.12 location
 *     \endcode
 *   giving:
 *     \code
 *     {
 *       "latitude":
 *        30.063100 <double>
 *       "longitude":
 *        31.231200 <double>
 *     }
 *     \endcode
 *
 * Refs:
 *  [1] https://github.com/maxmind/libmaxminddb/blob/master/doc/libmaxminddb.md
 *  [2] https://db-ip.com/db
 *
 * \todo Put this inside a `#ifdef USE_MAXMINDDB` section later.
 *
 * Another option is to use `libloc`.
 * Refs: https://blog.ipfire.org/post/on-retiring-the-maxmind-geoip-database
 *       https://location.ipfire.org/how-to-use
 *       https://git.ipfire.org/pub/git/location/libloc.git
 */

#include <assert.h>
#include <limits.h>
#include <errno.h>
#include <math.h>
#include <windows.h>
#include <wininet.h>

#include "common.h"
#include "smartlist.h"
#include "init.h"
#include "in_addr.h"
#include "inet_util.h"
#include "iana.h"
#include "asn.h"
#include "csv.h"
#include "geoip.h"

/** Number of calls for `smartlist_bsearch()` to find an IPv4 entry. <br>
 *  Used in `test_addr4()` only.
 */
static DWORD num_4_compare;

/** Number of calls for `smartlist_bsearch()` to find an IPv6 entry.
 *  Used in `test_addr6()` only.
 */
static DWORD num_6_compare;

static int  geoip4_CSV_add (struct CSV_context *ctx, const char *value);
static int  geoip6_CSV_add (struct CSV_context *ctx, const char *value);
static int  geoip4_add_entry (DWORD low, DWORD high, const char *country);
static int  geoip6_add_entry (const struct in6_addr *low, const struct in6_addr *high, const char *country);
static void geoip_stats_init (void);
static void geoip_stats_exit (void);
static void geoip_make_c_lists (void);
static void geoip_free_c_lists (void);
static void geoip_stats_update (const char *country_A2, int flag);
static int  geoip_get_num_addr (DWORD *num4, DWORD *num6);

/**
 * Geoip specific smartlist; list of IPv4 blocks.
 */
static smartlist_t *geoip_ipv4_entries = NULL;

/**
 * Geoip specific smartlist; list of IPv6 blocks.
 */
static smartlist_t *geoip_ipv6_entries = NULL;

/**\struct geoip_stats
 *
 * Structure for counting countries found at run-time.
 */
struct geoip_stats {
       uint64  num4;        /**< Total # of times seen in an IPv4-address */
       uint64  num6;        /**< Total # of times seen in an IPv6-address */
       char    country[2];  /**< 2 letter ISO-3166 2 letter Country-code */
       char    flag;        /**< The country was seen in IPv4 or IPv6 address(es). <br>
                             *   If the address was found by `ip2loc_get_ipv4_entry()` or `ip2loc_get_ipv6_entry()`
                             *   the flag `GEOIP_VIA_IP2LOC` is also set.
                             */
    };

/**
 * \def GEOIP_STAT_IPV4
 *      The flag for `geoip_stats_update()` if it was an IPv4 address.
 *
 * \def GEOIP_STAT_IPV6
 *      The flag for `geoip_stats_update()` if it was an IPv6 address.
 *
 * \def GEOIP_VIA_IP2LOC
 *      The flag for `geoip_stats_update()` if the address was found by
 *      `ip2loc_get_ipv4_entry()` or `ip2loc_get_ipv6_entry()`.
 */
#define GEOIP_STAT_IPV4   0x01
#define GEOIP_STAT_IPV6   0x02
#define GEOIP_VIA_IP2LOC  0x04

/**
 * An array of statistics for each country.
 * Updated by `geoip_stats_update()` as countries are discovered from IPv4/IPv6 addresses.
 */
static struct geoip_stats *geoip_stats_buf = NULL;

/**
 * `smartlist_sort()` helper.
 *
 *  Returns -1, 1, or 0 based on comparison of two `ipv4_node`s.
 *
 * \param[in] _a  the address to the first node for comparision.
 * \param[in] _b  the address to the second node for comparision.
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

/**
 * `smartlist_bsearch()` helper.
 *
 * Returns -1, 1, or 0 based on comparison of an IP (a pointer
 * to a `DWORD` on host order) to a `struct ipv4_node` element.
 *
 * \param[in] key    the IPv4 address to search for.
 * \param[in] member a pointer to the entry in `geoip_ipv4_entries` to test for range membership.
 */
static int geoip_ipv4_compare_key_to_entry (const void *key, const void **member)
{
  const struct ipv4_node *entry = *member;
  const DWORD             addr  = *(const DWORD*) key;

  num_4_compare++;

  if (addr < entry->low)
     return (-1);
  if (addr > entry->high)
     return (1);
  return (0);
}

/**
 * `smartlist_sort()` helper.
 *
 * Returns -1, 1, or 0 based on comparison of two `struct ipv6_node` elements.
 *
 * \param[in] _a  the address to the first node for comparision.
 * \param[in] _b  the address to the second node for comparision.
 */
static int geoip_ipv6_compare_entries (const void **_a, const void **_b)
{
  const struct ipv6_node *a = *_a;
  const struct ipv6_node *b = *_b;

  return memcmp (a->low.s6_addr, b->low.s6_addr, sizeof(struct in6_addr));
}

/**
 * `smartlist_bsearch()` helper.
 *
 * Returns -1, 1, or 0 based on comparison of an IPv6
 * (a pointer to an `struct in6_addr`) to a `struct ipv6_node`.
 *
 * \param[in] key    the IPv6 address to search for.
 * \param[in] member a pointer to the entry in `geoip_ipv6_entries` to test for range membership.
 */
static int geoip_ipv6_compare_key_to_entry (const void *key, const void **member)
{
  const struct ipv6_node *entry = *member;
  const struct in6_addr  *addr  = key;

  num_6_compare++;

  if (memcmp(addr->s6_addr, entry->low.s6_addr, sizeof(struct in6_addr)) < 0)
     return (-1);
  if (memcmp(addr->s6_addr, entry->high.s6_addr, sizeof(struct in6_addr)) > 0)
     return (1);
  return (0);
}

/**
 * Add these special addresses to the `geoip_ipv4_entries` smartlist.
 * Ref:
 *  https://en.wikipedia.org/wiki/Private_network
 */
static void geoip_ipv4_add_specials (void)
{
  static const struct {
         const char *low;
         const char *high;
         const char *remark;
       } priv[] = {
         { "0.0.0.0",     "0.255.255.255",   "-L" }, /**< Local addresses */
         { "10.0.0.0",    "10.255.255.255",  "-P" }, /**< The 10.0.0/8 Private block */
         { "127.0.0.0",   "127.255.255.255", "-L" }, /**< Loopback addresses */
         { "172.16.0.0",  "172.31.255.255",  "-P" }, /**< The 172.16/12 Private block */
         { "192.168.0.0", "192.168.255.255", "-P" }, /**< The 192.168/16 Private block */
         { "224.0.0.0",   "239.255.255.253", "-M" }  /**< https://en.wikipedia.org/wiki/Multicast_address */
       };
  int i;

  for (i = 0; i < DIM(priv); i++)
  {
    DWORD low, high;

    if (_wsock_trace_inet_pton (AF_INET, priv[i].low, &low, NULL) == 1 &&
        _wsock_trace_inet_pton (AF_INET, priv[i].high, &high, NULL) == 1)
      geoip4_add_entry (swap32(low), swap32(high), priv[i].remark);
    else
      TRACE (0, "Illegal low/high IPv4 address: %s/%s\n", priv[i].low, priv[i].high);
  }
}

/**
 * Add these special addresses to the `geoip_ipv6_entries` smartlist.
 */
static void geoip_ipv6_add_specials (void)
{
  static const struct {
         const char *low;
         const char *high;
         const char *remark;
       } priv[] = {
         { "::",      "::",  "-Z" },                                         /**< IN6_IS_ADDR_UNSPECIFIED() */
         { "::1",     "::1", "-L" },                                         /**< IN6_IS_ADDR_LOOPBACK() */
      #if 1
         { "2001:0::",    "2001:0000:ffff:ffff:ffff:ffff:ffff:ffff", "-T" }, /**< RFC 4380 Teredo, 2001:0::/32 */
         { "3ffe:831f::", "3ffe:831f:ffff:ffff:ffff:ffff:ffff:ffff", "-t" }, /**< WinXP Teroedo,   3FFE:831F::/32 */
      #endif
         { "f0::",    "f0::ffff", "-G" },                                    /**< !IN6_IS_ADDR_GLOBAL() */
         { "fe80::",  "fe80:ffff:ffff:ffff:ffff:ffff:ffff:ffff", "-l" }      /**< IN6_IS_ADDR_LINKLOCAL() */
       };
  int i;

  for (i = 0; i < DIM(priv); i++)
  {
    struct in6_addr low, high;

    _wsock_trace_inet_pton (AF_INET6, priv[i].low, &low, NULL);
    _wsock_trace_inet_pton (AF_INET6, priv[i].high, &high, NULL);
    geoip6_add_entry (&low, &high, priv[i].remark);
  }
}

/**
 * Open and parse a GeoIP file.
 *
 * \param[in] file   the file on CVS format to read and parse.
 * \param[in] family the address family of the file; `AF_INET` or `AF_INET6`.
 */
static DWORD geoip_parse_file (const char *file, int family)
{
  struct CSV_context ctx;
  DWORD  num = 0;

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

  memset (&ctx, '\0', sizeof(ctx));
  ctx.file_name  = file;
  ctx.num_fields = 3;
  ctx.delimiter  = ',';
  ctx.callback   = (family == AF_INET ? geoip4_CSV_add : geoip6_CSV_add);

  CSV_open_and_parse_file (&ctx);
  num = ctx.rec_num;

  if (family == AF_INET)
  {
    smartlist_sort (geoip_ipv4_entries, geoip_ipv4_compare_entries);
    TRACE (2, "Parsed %s IPv4 records from \"%s\".\n",
           dword_str(num), file);
  }
  else
  {
    smartlist_sort (geoip_ipv6_entries, geoip_ipv6_compare_entries);
    TRACE (2, "Parsed %s IPv6 records from \"%s\".\n",
           dword_str(num), file);
  }
  return (num);
}

/**
 * The main init function for this module.
 * Normally called from `wsock_trace_init()`.
 *
 * \param[in,out]  _num4  Number of IPv4-addresses returned from
 *                        the `g_cfg.GEOIP.ip4_file` file.
 *
 * \param[in,out]  _num6  Number of IPv6-addresses returned from
 *                        the `g_cfg.GEOIP.ip6_file` file.
 */
int geoip_init (DWORD *_num4, DWORD *_num6)
{
  DWORD num4 = 0, num6 = 0;
  BOOL  open_geoip = FALSE;

#if defined(TEST_GEOIP)
  open_geoip = TRUE;
#endif

  if (g_cfg.GEOIP.enable || open_geoip)
  {
    num4 = geoip_parse_file (g_cfg.GEOIP.ip4_file, AF_INET);
    num6 = geoip_parse_file (g_cfg.GEOIP.ip6_file, AF_INET6);
  }
  if (num4 == 0 && num6 == 0)
     g_cfg.GEOIP.enable = FALSE;

  geoip_make_c_lists();
  geoip_stats_init();
  ip2loc_init();

  return geoip_get_num_addr (_num4, _num6);
}

/**
 * Free memory allocated here. <br>
 * Normally called from `wsock_trace_exit()`.
 */
void geoip_exit (void)
{
  if (geoip_ipv4_entries)
     smartlist_wipe (geoip_ipv4_entries, free);
  if (geoip_ipv6_entries)
     smartlist_wipe (geoip_ipv6_entries, free);

  geoip_ipv4_entries = geoip_ipv6_entries = NULL;
  geoip_stats_exit();
  geoip_free_c_lists();
  ip2loc_exit();
}

/**
 * The CSV callback to add an IPv4 entry to the `geoip_ipv4_entries` smart-list.
 *
 * \param[in]  ctx   the CSV context structure.
 * \param[in]  value the value for this CSV field in record `ctx->rec_num`.
 */
static int geoip4_CSV_add (struct CSV_context *ctx, const char *value)
{
  static char        country[3];
  static __ms_u_long low, high;
  int    rc = 1;

  switch (ctx->field_num)
  {
    case 0:
         low = (u_long) _atoi64 (value);
         break;
    case 1:
         high = (u_long) _atoi64 (value);
         break;
    case 2:
         memcpy (&country, value, sizeof(country));
         rc = geoip4_add_entry (low, high, country);
         low = high = country[0] = 0;
         break;
  }
  return (rc);
}

/**
 * The CSV callback to add an IPv6 entry to the `geoip_ipv6_entries` smart-list.
 *
 * \param[in]  ctx   the CSV context structure.
 * \param[in]  value the value for this CSV field in record `ctx->rec_num`.
 */
static int geoip6_CSV_add (struct CSV_context *ctx, const char *value)
{
  static char            country[3];
  static struct in6_addr low, high;
  int    rc = 1;

  switch (ctx->field_num)
  {
    case 0:
          _wsock_trace_inet_pton (AF_INET6, value, &low, NULL);
          break;
     case 1:
          _wsock_trace_inet_pton (AF_INET6, value, &high, NULL);
          break;
     case 2:
          memcpy (&country, value, sizeof(country));
          rc = geoip6_add_entry (&low, &high, country);
          memset (&low, '\0', sizeof(low));
          memset (&high, '\0', sizeof(high));
          country[0] = '\0';
          break;
  }
  return (rc);
}

/**
 * Add an IPv4 entry to the `geoip_ipv4_entries` smart-list.
 *
 * \param[in] low      The lowest address in the IPv4-block.
 * \param[in] high     The highest address in the IPv4-block.
 * \param[in] country  The short country associated with this IPv4-block. <br>
 *                     Or the `-X` remark if this IPv4-block is a special address.
 */
static int geoip4_add_entry (DWORD low, DWORD high, const char *country)
{
  struct ipv4_node *entry = malloc (sizeof(*entry));

  if (!entry)
     return (0);

  entry->low  = low;
  entry->high = high;
  memcpy (&entry->country, country, sizeof(entry->country));
  smartlist_add (geoip_ipv4_entries, entry);
  return (1);
}

/**
 * Add an IPv6 entry to the `geoip_ipv6_entries` smart-list.
 *
 * \param[in] low      The lowest address in the IPv6-block.
 * \param[in] high     The highest address in the IPv6-block.
 * \param[in] country  The short country associated with this IPv6-block. <br>
 *                     Or the `-X` remark if this IPv6-block is a special address.
 */
static int geoip6_add_entry (const struct in6_addr *low, const struct in6_addr *high, const char *country)
{
  struct ipv6_node *entry = malloc (sizeof(*entry));

  if (!entry)
     return (0);

  memcpy (&entry->low, low, sizeof(entry->low));
  memcpy (&entry->high, high, sizeof(entry->high));
  memcpy (&entry->country, country, sizeof(entry->country));
  smartlist_add (geoip_ipv6_entries, entry);
  return (1);
}

/**
 * This is global here to get the location (city, region and optionally latitude/longitude) later on.
 */
static struct ip2loc_entry g_ip2loc_entry;

#define IP2LOC_IS_GOOD()  (g_ip2loc_entry.country_short[0] >= 'A' && \
                           g_ip2loc_entry.country_short[0] <= 'Z')
#define IP2LOC_SET_BAD()  g_ip2loc_entry.country_short[0] = '\0'

/**
 * Given an IPv4 address on network order, return an ISO-3166 2 letter
 * country-code representing the country to which that address
 * belongs, or NULL for `No geoip information available`.
 *
 * To decode it, call `geoip_get_long_name_by_A2()`.
 *
 * \param[in] addr  The IPv4 address to get the country for.
 */
const char *geoip_get_country_by_ipv4 (const struct in_addr *addr)
{
  struct ipv4_node *entry = NULL;
  char     buf [25];
  unsigned num;

  IP2LOC_SET_BAD();
  num_4_compare = 0;

  _wsock_trace_inet_ntop (AF_INET, addr, buf, sizeof(buf), NULL);

  num = ip2loc_num_ipv4_entries();
  TRACE (4, "Looking for %s in %u elements.\n", buf, num);

  if (num > 0 && INET_util_addr_is_global(addr, NULL) && ip2loc_get_ipv4_entry(addr, &g_ip2loc_entry))
  {
    if (g_cfg.trace_report)
       geoip_stats_update (g_ip2loc_entry.country_short, GEOIP_STAT_IPV4 | GEOIP_VIA_IP2LOC);
    return (g_ip2loc_entry.country_short);
  }

  /* IP2LOCATION lookup failed. Fallback to a geoip lookup below.
   */
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

/**
 * Given an IPv6 address,  return an ISO-3166 2 letter country-code
 * representing the country to which that address belongs, or NULL for
 * `No geoip information available`.
 *
 * To decode it, call `geoip_get_long_name_by_A2()`.
 *
 * \param[in] addr  The IPv6 address to get the country for.
 */
const char *geoip_get_country_by_ipv6 (const struct in6_addr *addr)
{
  struct ipv6_node *entry = NULL;
  char     buf [MAX_IP6_SZ+1];
  unsigned num;

  IP2LOC_SET_BAD();
  num_6_compare = 0;

  _wsock_trace_inet_ntop (AF_INET6, addr, buf, sizeof(buf), NULL);

  num = ip2loc_num_ipv6_entries();
  TRACE (4, "Looking for %s in %u elements.\n", buf, num);

  if (num > 0 && INET_util_addr_is_global(NULL, addr) && ip2loc_get_ipv6_entry(addr, &g_ip2loc_entry))
  {
    if (g_cfg.trace_report)
       geoip_stats_update (g_ip2loc_entry.country_short, GEOIP_STAT_IPV6 | GEOIP_VIA_IP2LOC);
    return (g_ip2loc_entry.country_short);
  }

  if (geoip_ipv6_entries)
  {
    entry = smartlist_bsearch (geoip_ipv6_entries, addr,
                               geoip_ipv6_compare_key_to_entry);

    if (g_cfg.trace_report && entry && entry->country[0])
       geoip_stats_update (entry->country, GEOIP_STAT_IPV6);
  }
  return (entry ? entry->country : NULL);
}

/**
 * Given an IPv4 address, return the location (city+region).
 *
 * Assumes `geoip_get_country_by_ipv4()` was just called for this address.
 * Currently only works when `ip2location_bin_file` is present.
 *
 * \param[in] ip4  The IPv4 address to get the location for (not used though).
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

/**
 * Given an IPv6 address, return the location.
 *
 * Assumes `geoip_get_country_by_ipv6()` was just called for this address.
 * Currently only works when `ip2location_bin_file` is present.
 *
 * \param[in] ip6 The IPv6 address to get the location for.
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

/**
 * Given an IPv4 address, return the position (latitude+longitude).
 *
 * Assumes `geoip_get_country_by_ipv4()` was just called for this address.
 * Currently only works when `ip2location_bin_file` is present.
 *
 * \param[in] ip4   The IPv4 address to get the location for (not used though).
 * \retval    NULL  if last IP2Location lookup failed.
 *            !NULL if last IP2Location lookup succeeded.
 *            But both `ret->longitude` and `ret->latitude` could be 0.0 depending on the
 *            IP2location file used.
 */
const position *geoip_get_position_by_ipv4 (const struct in_addr *ip4)
{
  static struct position ret;

  if (IP2LOC_IS_GOOD())
  {
    ret.latitude  = g_ip2loc_entry.latitude;   /* Both of these could be 0.0 depending on the IP2location file used. */
    ret.longitude = g_ip2loc_entry.longitude;
    return (&ret);
  }
  ARGSUSED (ip4);
  return (NULL);
}

/**
 * Given an IPv6 address, return the position (latitude+longitude).
 *
 * Assumes `geoip_get_country_by_ipv6()` was just called for this address.
 * Currently only works when `ip2location_bin_file` is present.
 *
 * \param[in] ip6   The IPv4 address to get the location for (not used though).
 * \retval    NULL  if last IP2Location lookup failed.
 *            !NULL if last IP2Location lookup succeeded.
 *            But both `ret->longitude` and `ret->latitude` could be 0.0 depending on the
 *            IP2location file used.
 */
const position *geoip_get_position_by_ipv6 (const struct in6_addr *ip6)
{
  static struct position ret;

  if (IP2LOC_IS_GOOD())
  {
    ret.latitude  = g_ip2loc_entry.latitude;   /* Both of these could be 0.0 depending on the IP2location file used. */
    ret.longitude = g_ip2loc_entry.longitude;
    return (&ret);
  }
  ARGSUSED (ip6);
  return (NULL);
}

/**
 * Return the number of records of `AF_INET` and/or `AF_INET6` addresses.
 *
 * \param[in,out] num4  Number of IPv4-addresses in the `geoip_ipv4_entries` list.
 * \param[in,out] num6  Number of IPv6-addresses in the `geoip_ipv6_entries` list.
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

/**\enum Continent
 *
 * The continents of the World.
 */
enum Continent {
     C_NONE = 0, /* None */
     C_EU,       /* Europe */
     C_AS,       /* Asia */
     C_NA,       /* North America */
     C_SA,       /* South America */
     C_AF,       /* Africa */
     C_OC,       /* Ocean Pacific */
     C_AN        /* Antarctica */
  };

/**\struct country_list
 *
 * Structure for ISO-3166-2 country information.
 */
struct country_list {
       int            country_number; /**< ISO-3166-2 country number */
       char           short_name[3];  /**< A2 short country code */
       enum Continent continent;      /**< The continet of the country */
       const char    *long_name;      /**< normal (long) country name */
     };

/**
 * The ISO-3166-2 list of countries.
 *
 * Refs: <br>
 *  ftp://ftp.ripe.net/iso3166-countrycodes.txt <br>
 *  https://en.wikipedia.org/wiki/ISO_3166-2
 */
static const struct country_list c_list[] = {
       {   4, "af", C_AS, "Afghanistan"                          },
       { 248, "ax", C_EU, "Åland Island"                         },
       {   8, "al", C_EU, "Albania"                              },
       {  12, "dz", C_AF, "Algeria"                              },
       {  16, "as", C_OC, "American Samoa"                       },
       {  20, "ad", C_EU, "Andorra"                              },
       {  24, "ao", C_AF, "Angola"                               },
       { 660, "ai", C_NA, "Anguilla"                             },
       {  10, "aq", C_AN, "Antarctica"                           },
       {  28, "ag", C_NA, "Antigua & Barbuda"                    },
       {  32, "ar", C_SA, "Argentina"                            },
       {  51, "am", C_AS, "Armenia"                              },
       { 533, "aw", C_NA, "Aruba"                                },
       {  36, "au", C_OC, "Australia"                            },
       {  40, "at", C_EU, "Austria"                              },
       {  31, "az", C_EU, "Azerbaijan"                           },
       {  44, "bs", C_NA, "Bahamas"                              },
       {  48, "bh", C_AS, "Bahrain"                              },
       {  50, "bd", C_AS, "Bangladesh"                           },
       {  52, "bb", C_NA, "Barbados"                             },
       { 112, "by", C_EU, "Belarus"                              },
       {  56, "be", C_EU, "Belgium"                              },
       {  84, "bz", C_NA, "Belize"                               },
       { 204, "bj", C_AF, "Benin"                                },
       {  60, "bm", C_NA, "Bermuda"                              },
       {  64, "bt", C_AS, "Bhutan"                               },
       {  68, "bo", C_SA, "Bolivia"                              },
       { 535, "bq", C_SA, "Bonaire"                              },
       {  70, "ba", C_EU, "Bosnia & Herzegowina"                 },
       {  72, "bw", C_AF, "Botswana"                             },
       {  74, "bv", C_AN, "Bouvet Island"                        },
       {  76, "br", C_SA, "Brazil"                               },
       {  86, "io", C_AS, "British Indian Ocean Territory"       },
       {  96, "bn", C_AS, "Brunei Darussalam"                    },
       { 100, "bg", C_EU, "Bulgaria"                             },
       { 854, "bf", C_AF, "Burkina Faso"                         },
       { 108, "bi", C_AF, "Burundi"                              },
       { 116, "kh", C_AS, "Cambodia"                             },
       { 120, "cm", C_AF, "Cameroon"                             },
       { 124, "ca", C_NA, "Canada"                               },
       { 132, "cv", C_AF, "Cape Verde"                           },
       { 136, "ky", C_NA, "Cayman Islands"                       },
       { 140, "cf", C_AF, "Central African Republic"             },
       { 148, "td", C_AF, "Chad"                                 },
       { 152, "cl", C_SA, "Chile"                                },
       { 156, "cn", C_AS, "China"                                },
       { 162, "cx", C_AS, "Christmas Island"                     },
       { 166, "cc", C_AS, "Cocos Islands"                        },
       { 170, "co", C_SA, "Colombia"                             },
       { 174, "km", C_AF, "Comoros"                              },
       { 178, "cg", C_AF, "Congo"                                },
       { 180, "cd", C_AF, "Congo, Democratic Republic"           },
       { 184, "ck", C_OC, "Cook Islands"                         },
       { 188, "cr", C_NA, "Costa Rica"                           },
       { 384, "ci", C_AF, "Cote d'Ivoire"                        },
       { 191, "hr", C_EU, "Croatia"                              },
       { 192, "cu", C_NA, "Cuba"                                 },
       { 531, "cw", C_SA, "Curaçao"                              },
       { 196, "cy", C_AS, "Cyprus"                               },
       { 203, "cz", C_EU, "Czech Republic"                       },
       { 208, "dk", C_EU, "Denmark"                              },
       { 262, "dj", C_AF, "Djibouti"                             },
       { 212, "dm", C_NA, "Dominica"                             },
       { 214, "do", C_NA, "Dominican Republic"                   },
       { 218, "ec", C_SA, "Ecuador"                              },
       { 818, "eg", C_AF, "Egypt"                                },
       { 222, "sv", C_NA, "El Salvador"                          },
       { 226, "gq", C_AF, "Equatorial Guinea"                    },
       { 232, "er", C_AF, "Eritrea"                              },
       { 233, "ee", C_EU, "Estonia"                              },
       { 231, "et", C_AF, "Ethiopia"                             },
     { 65281, "eu", C_EU, "European Union"                       }, /* 127.0.255.1 */
       { 238, "fk", C_SA, "Falkland Islands"                     },
       { 234, "fo", C_EU, "Faroe Islands"                        },
       { 242, "fj", C_OC, "Fiji"                                 },
       { 246, "fi", C_EU, "Finland"                              },
       { 250, "fr", C_EU, "France"                               },
       { 249, "fx", C_EU, "France, Metropolitan"                 },
       { 254, "gf", C_SA, "French Guiana"                        },
       { 258, "pf", C_OC, "French Polynesia"                     },
       { 260, "tf", C_AN, "French Southern Territories"          },
       { 266, "ga", C_AF, "Gabon"                                },
       { 270, "gm", C_AF, "Gambia"                               },
       { 268, "ge", C_AS, "Georgia"                              },
       { 276, "de", C_EU, "Germany"                              },
       { 288, "gh", C_AF, "Ghana"                                },
       { 292, "gi", C_EU, "Gibraltar"                            },
       { 300, "gr", C_EU, "Greece"                               },
       { 304, "gl", C_NA, "Greenland"                            },
       { 308, "gd", C_NA, "Grenada"                              },
       { 312, "gp", C_NA, "Guadeloupe"                           },
       { 316, "gu", C_OC, "Guam"                                 },
       { 320, "gt", C_NA, "Guatemala"                            },
       { 831, "gg", C_EU, "Guernsey"                             },
       { 324, "gn", C_AF, "Guinea"                               },
       { 624, "gw", C_AF, "Guinea-Bissau"                        },
       { 328, "gy", C_SA, "Guyana"                               },
       { 332, "ht", C_NA, "Haiti"                                },
       { 334, "hm", C_AN, "Heard & Mc Donald Islands"            },
       { 336, "va", C_EU, "Vatican City"                         },
       { 340, "hn", C_NA, "Honduras"                             },
       { 344, "hk", C_AS, "Hong kong"                            },
       { 348, "hu", C_EU, "Hungary"                              },
       { 352, "is", C_EU, "Iceland"                              },
       { 356, "in", C_AS, "India"                                },
       { 360, "id", C_AS, "Indonesia"                            },
       { 364, "ir", C_AS, "Iran"                                 },
       { 368, "iq", C_AS, "Iraq"                                 },
       { 372, "ie", C_EU, "Ireland"                              },
       { 833, "im", C_EU, "Isle of Man"                          },
       { 376, "il", C_AS, "Israel"                               },
       { 380, "it", C_EU, "Italy"                                },
       { 388, "jm", C_NA, "Jamaica"                              },
       { 392, "jp", C_AS, "Japan"                                },
       { 832, "je", C_EU, "Jersey"                               },
       { 400, "jo", C_AS, "Jordan"                               },
       { 398, "kz", C_AS, "Kazakhstan"                           },
       { 404, "ke", C_AF, "Kenya"                                },
       { 296, "ki", C_OC, "Kiribati"                             },
       { 408, "kp", C_AS, "Korea (north)"                        },
       { 410, "kr", C_AS, "Korea (south)"                        },
       {   0, "xk", C_EU, "Kosovo"                               },  /* https://en.wikipedia.org/wiki/ISO_3166-1_alpha-2 */
       { 414, "kw", C_AS, "Kuwait"                               },
       { 417, "kg", C_AS, "Kyrgyzstan"                           },
       { 418, "la", C_AS, "Laos"                                 },
       { 428, "lv", C_EU, "Latvia"                               },
       { 422, "lb", C_AS, "Lebanon"                              },
       { 426, "ls", C_AF, "Lesotho"                              },
       { 430, "lr", C_AF, "Liberia"                              },
       { 434, "ly", C_AF, "Libya"                                },
       { 438, "li", C_EU, "Liechtenstein"                        },
       { 440, "lt", C_EU, "Lithuania"                            },
       { 442, "lu", C_EU, "Luxembourg"                           },
       { 446, "mo", C_AS, "Macao"                                },
       { 807, "mk", C_EU, "Macedonia"                            },
       { 450, "mg", C_AF, "Madagascar"                           },
       { 454, "mw", C_AF, "Malawi"                               },
       { 458, "my", C_AS, "Malaysia"                             },
       { 462, "mv", C_AS, "Maldives"                             },
       { 466, "ml", C_AF, "Mali"                                 },
       { 470, "mt", C_EU, "Malta"                                },
       { 584, "mh", C_OC, "Marshall Islands"                     },
       { 474, "mq", C_NA, "Martinique"                           },
       { 478, "mr", C_AF, "Mauritania"                           },
       { 480, "mu", C_AF, "Mauritius"                            },
       { 175, "yt", C_AF, "Mayotte"                              },
       { 484, "mx", C_NA, "Mexico"                               },
       { 583, "fm", C_OC, "Micronesia"                           },
       { 498, "md", C_EU, "Moldova"                              },
       { 492, "mc", C_EU, "Monaco"                               },
       { 496, "mn", C_AS, "Mongolia"                             },
       { 499, "me", C_EU, "Montenegro"                           },
       { 500, "ms", C_NA, "Montserrat"                           },
       { 504, "ma", C_AF, "Morocco"                              },
       { 508, "mz", C_AF, "Mozambique"                           },
       { 104, "mm", C_AS, "Myanmar"                              },
       { 516, "na", C_AF, "Namibia"                              },
       { 520, "nr", C_OC, "Nauru"                                },
       { 524, "np", C_AS, "Nepal"                                },
       { 528, "nl", C_EU, "Netherlands"                          },
       { 530, "an", C_NA, "Netherlands Antilles"                 },
       { 540, "nc", C_OC, "New Caledonia"                        },
       { 554, "nz", C_OC, "New Zealand"                          },
       { 558, "ni", C_NA, "Nicaragua"                            },
       { 562, "ne", C_AF, "Niger"                                },
       { 566, "ng", C_AF, "Nigeria"                              },
       { 570, "nu", C_OC, "Niue"                                 },
       { 574, "nf", C_OC, "Norfolk Island"                       },
       { 580, "mp", C_OC, "Northern Mariana Islands"             },
       { 578, "no", C_EU, "Norway"                               },
       { 512, "om", C_AS, "Oman"                                 },
       { 586, "pk", C_AS, "Pakistan"                             },
       { 585, "pw", C_OC, "Palau"                                },
       { 275, "ps", C_AS, "Palestinian Territory"                },
       { 591, "pa", C_NA, "Panama"                               },
       { 598, "pg", C_OC, "Papua New Guinea"                     },
       { 600, "py", C_SA, "Paraguay"                             },
       { 604, "pe", C_SA, "Peru"                                 },
       { 608, "ph", C_AS, "Philippines"                          },
       { 612, "pn", C_OC, "Pitcairn"                             },
       { 616, "pl", C_EU, "Poland"                               },
       { 620, "pt", C_EU, "Portugal"                             },
       { 630, "pr", C_NA, "Puerto Rico"                          },
       { 634, "qa", C_AS, "Qatar"                                },
       { 638, "re", C_AF, "Réunion"                              },
       { 642, "ro", C_EU, "Romania"                              },
       { 643, "ru", C_EU, "Russia"                               },
       { 646, "rw", C_AF, "Rwanda"                               },
       {   0, "bl", C_NA, "Saint Barthélemy"                     }, /* https://en.wikipedia.org/wiki/ISO_3166-2:BL */
       { 659, "kn", C_NA, "Saint Kitts & Nevis"                  },
       { 662, "lc", C_NA, "Saint Lucia"                          },
       { 663, "mf", C_NA, "Saint Martin"                         },
       { 670, "vc", C_NA, "Saint Vincent"                        },
       { 882, "ws", C_OC, "Samoa"                                },
       { 674, "sm", C_EU, "San Marino"                           },
       { 678, "st", C_AF, "Sao Tome & Principe"                  },
       { 682, "sa", C_AS, "Saudi Arabia"                         },
       { 686, "sn", C_AF, "Senegal"                              },
       { 688, "rs", C_EU, "Serbia"                               },
       { 690, "sc", C_AF, "Seychelles"                           },
       { 694, "sl", C_AF, "Sierra Leone"                         },
       { 702, "sg", C_AS, "Singapore"                            },
       { 534, "sx", C_NA, "Sint Maarten"                         },
       { 703, "sk", C_EU, "Slovakia"                             },
       { 705, "si", C_EU, "Slovenia"                             },
       {  90, "sb", C_OC, "Solomon Islands"                      },
       { 706, "so", C_AF, "Somalia"                              },
       { 710, "za", C_AF, "South Africa"                         },
       { 239, "gs", C_AN, "South Georgia"                        },
       { 728, "ss", C_AF, "South Sudan"                          },
       { 724, "es", C_EU, "Spain"                                },
       { 144, "lk", C_AS, "Sri Lanka"                            },
       { 654, "sh", C_AF, "St. Helena"                           },
       { 666, "pm", C_NA, "St. Pierre & Miquelon"                },
       { 736, "sd", C_AF, "Sudan"                                },
       { 740, "sr", C_SA, "Suriname"                             },
       { 744, "sj", C_EU, "Svalbard & Jan Mayen Islands"         },
       { 748, "sz", C_AF, "Swaziland"                            },
       { 752, "se", C_EU, "Sweden"                               },
       { 756, "ch", C_EU, "Switzerland"                          },
       { 760, "sy", C_AS, "Syrian Arab Republic"                 },
       { 626, "tl", C_AS, "Timor-Leste"                          },
       { 158, "tw", C_AS, "Taiwan"                               },
       { 762, "tj", C_AS, "Tajikistan"                           },
       { 834, "tz", C_AF, "Tanzania"                             },
       { 764, "th", C_AS, "Thailand"                             },
       { 768, "tg", C_AF, "Togo"                                 },
       { 772, "tk", C_OC, "Tokelau"                              },
       { 776, "to", C_OC, "Tonga"                                },
       { 780, "tt", C_NA, "Trinidad & Tobago"                    },
       { 788, "tn", C_AF, "Tunisia"                              },
       { 792, "tr", C_AS, "Turkey"                               },
       { 795, "tm", C_AS, "Turkmenistan"                         },
       { 796, "tc", C_NA, "Turks & Caicos Islands"               },
       { 798, "tv", C_OC, "Tuvalu"                               },
       { 800, "ug", C_AF, "Uganda"                               },
       { 804, "ua", C_EU, "Ukraine"                              },
       { 784, "ae", C_AS, "United Arab Emirates"                 },
       { 826, "gb", C_EU, "United Kingdom"                       },
       { 840, "us", C_NA, "United States"                        },
       { 581, "um", C_OC, "United States Minor Outlying Islands" },
       { 858, "uy", C_SA, "Uruguay"                              },
       { 860, "uz", C_AS, "Uzbekistan"                           },
       { 548, "vu", C_OC, "Vanuatu"                              },
       { 862, "ve", C_SA, "Venezuela"                            },
       { 704, "vn", C_AS, "Vietnam"                              },
       {  92, "vg", C_NA, "Virgin Islands (British)"             },
       { 850, "vi", C_NA, "Virgin Islands (US)"                  },
       { 876, "wf", C_OC, "Wallis & Futuna Islands"              },
       { 732, "eh", C_AF, "Western Sahara"                       },
       { 887, "ye", C_AS, "Yemen"                                },
       { 894, "zm", C_AF, "Zambia"                               },
       { 716, "zw", C_AF, "Zimbabwe"                             }
     };

static struct country_list *c_list_sorted_on_short_name = NULL;
static struct country_list *c_list_sorted_on_country_number = NULL;

typedef int (MS_CDECL *Qsort_func) (const void *a, const void *b);

/**
 * `qsort()` helpers for sorted copies of `c_list[]`.
 */
static int compare_on_short_name (const void *_a, const void *_b)
{
  const struct country_list *a = (const struct country_list*) _a;
  const struct country_list *b = (const struct country_list*) _b;

  return memcmp (&a->short_name, &b->short_name, sizeof(a->short_name));
}

static int compare_on_country_number  (const void *_a, const void *_b)
{
  const struct country_list *a = (const struct country_list*) _a;
  const struct country_list *b = (const struct country_list*) _b;

  return (a->country_number - b->country_number);
}

/**
 * `bsearch()` helpers for sorted copies of `c_list[]`.
 */
static int compare2_on_short_name (const void *a, const void *b)
{
  const char                *key    = (const char*) a;
  const struct country_list *member = (const struct country_list*) b;

  return memcmp (key, &member->short_name, sizeof(member->short_name));
}

static int compare2_on_country_number (const void *a, const void *b)
{
  int                       *key    = (int*) a;
  const struct country_list *member = (const struct country_list*) b;

  return (*key - member->country_number);
}

static void make_c_list (struct country_list **list_p,
                         Qsort_func compare,
                         const char *list_name)
{
  struct country_list *list;
  size_t i, size = sizeof (c_list);

  list = malloc (size);
  *list_p = list;
  if (!list)
     return;

  memcpy (list, &c_list, size);
  qsort (list, DIM(c_list), sizeof(c_list[0]), compare);
  if (g_cfg.trace_level >= 3)
  {
    trace_printf ("\n%s:\n    #    Num  XX  Continent   long-name\n"
                  "  ------------------------------------------------------------\n",
                  list_name);
    for (i = 0; i < DIM(c_list); i++, list++)
        trace_printf ("  %3u: %5d  %c%c  %-10s  %s\n",
                      (UINT)i, list->country_number,
                      toupper(list->short_name[0]), toupper(list->short_name[1]),
                      geoip_get_continent_name(list->continent), list->long_name);
  }
}

/**
 * Allocate 2 copies of the `c_list[]' array.
 * One sorted on `short_name` and the other sorted on `country_number`.
 */
static void geoip_make_c_lists (void)
{
  make_c_list (&c_list_sorted_on_short_name,     compare_on_short_name,     "c_list_sorted_on_short_name, XX");
  make_c_list (&c_list_sorted_on_country_number, compare_on_country_number, "c_list_sorted_on_country_number, Num");
}

static void geoip_free_c_lists (void)
{
  if (c_list_sorted_on_short_name)
     free (c_list_sorted_on_short_name);
  if (c_list_sorted_on_country_number)
     free (c_list_sorted_on_country_number);
  c_list_sorted_on_short_name = c_list_sorted_on_country_number = NULL;
}

/**
 * Return number of countries in the `c_list[]' array.
 */
size_t geoip_num_countries (void)
{
  return DIM(c_list);
}

/**
 * Return the short-country name for an index in range `[0... DIM(c_list)]`.
 *
 * \param[in] idx  the index to get the short-country name for.
 */
const char *geoip_get_short_name_by_idx (int idx)
{
  if (idx < 0 || idx > DIM(c_list))
     return (NULL);
  return (c_list[idx].short_name);
}

/**
 * Return the continent name for an `enum Continent` value.
 *
 * \param[in] continent  the enum-value to get the continent name for.
 */
const char *geoip_get_continent_name (int continent)
{
  static const struct search_list continents[] = {
                    { C_NONE, "??" },
                    { C_EU,   "Europe" },
                    { C_AS,   "Asia" },
                    { C_NA,   "N-America" },
                    { C_SA,   "S-America" },
                    { C_AF,   "Africa" },
                    { C_OC,   "Oceania" },
                    { C_AN,   "Antarctica" }
                  };
  return list_lookup_name (continent, continents, DIM(continents));
}

/**
 * Given an ISO-3166-2 short-country, return the long-country name for it.
 *
 * \param[in] short_name  the ISO-3166-2 short-country name.
 */
const char *geoip_get_long_name_by_A2 (const char *short_name)
{
  const struct country_list *list;
  size_t i, num = DIM(c_list);

  if (!short_name)
     return ("?");

  if (c_list_sorted_on_short_name)
  {
    list = bsearch (short_name, c_list_sorted_on_short_name, DIM(c_list),
                    sizeof(c_list[0]), compare2_on_short_name);
    if (list)
       return (list->long_name);
  }

  list = c_list + 0;
  for (i = 0; i < num; i++, list++)
  {
    if (!strnicmp(list->short_name, short_name, sizeof(list->short_name)))
       return (list->long_name);
  }
  return (NULL);
}

/**
 * Given an ISO-3166-2 country-number, return the long-country name for it.
 *
 * \param[in] number  the ISO-3166-2 country-number.
 *
 * \note This function is currently not used.
 */
const char *geoip_get_long_name_by_id (int number)
{
  const struct country_list *list;
  size_t i, num = DIM(c_list);

  /**
   * Since some countries above ("Kosovo / XK" and "Saint Barthélemy / BL") have no
   * assigned number, we cannot return a sensible name.
   */
  if (number == 0)
     return ("?");

  if (c_list_sorted_on_country_number)
  {
    list = bsearch (&number, c_list_sorted_on_country_number, DIM(c_list),
                    sizeof(c_list[0]), compare2_on_country_number);
    if (list)
       return (list->long_name);
  }

  list = c_list + 0;
  for (i = 0; i < num; i++, list++)
  {
    if (list->country_number == number)
       return (list->long_name);
  }
  return (NULL);
}

/**
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

/**
 * Free the memory for the geoip statistics array.
 */
static void geoip_stats_exit (void)
{
  if (geoip_stats_buf)
     free (geoip_stats_buf);
  geoip_stats_buf = NULL;
}

/**
 * Update the country statistics for an IPv4 or IPv6-address.
 * `country_A2` should already be in upper case.
 *
 * \param[in] country_A2  The 2-letter country to update the statistics for.
 * \param[in] flag        A flag describing what counter should be incremented.
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

/**
 * This function assumes the above `geoip_stats_update()` was called to update
 * `stats->num[46]`. Hence if `country_A2` is found and `stats->num[46] > 1`, the country
 * is no longer considered unique when `flag == stats->flag`.
 *
 * \param[in] country_A2  The 2-letter country to check uniqueness for.
 * \param[in] flag        A flag describing which address type to check for.
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

/**
 * Using `geoip_stats_buf`, count the number of unique countries found in addresses at run-time.
 * Normally called from `trace_report()` to print final accumulated statistics.
 *
 * \param[in] num_ip4      The total count of IPv4-addresses found for countries.
 * \param[in] num_ip6      The total count of IPv6-addresses found for countries.
 * \param[in] num_ip2loc4  The count of IPv4-addresses found for countries by functions in ip2loc.c.
 * \param[in] num_ip2loc6  The count of IPv6-addresses found for countries by functions in ip2loc.c.
 */
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

/**
 * Using `geoip_stats_buf`, count the number of IPv4 and IPv6 addresses found at run-time.
 *
 * \param[in] idx  the index into `c_list[]`.
 *
 * \note this function is currently not used.
 */
uint64 geoip_get_stats_by_idx (int idx)
{
  if (!geoip_stats_buf || idx < 0 || idx > (int)geoip_num_countries())
     return (0);
  return (geoip_stats_buf[idx].num4 + geoip_stats_buf[idx].num6);
}

/**
 * Using `geoip_stats_buf`, count the number of IPv4 and IPv6 addresses found at run-time.
 *
 * \param[in] number  the ISO-3166-2 country-number.
 *
 * \note this function is currently not used.
 */
uint64 geoip_get_stats_by_number (int number)
{
  const struct country_list *list = c_list + 0;
  size_t i, num = DIM(c_list);

  for (i = 0; number > 0 && i < num; i++, list++)
  {
    if (list->country_number == number)
       return geoip_get_stats_by_idx ((int)i);
  }
  return (0U);
}

/**
 * Figure out if a download is needed for a `loc_file`.
 * If it is, copy `tmp_file` over to `loc_file`.
 *
 * \param[in] loc_file      The local file to check for an update.
 * \param[in] tmp_file      The temporary file to compare against the `loc_file`.
 * \param[in] url           The URL to download from. Can be `http` or `https`.
 * \param[in] force_update  If TRUE, download the `tmp_file` regardless.
 */
static DWORD update_file (const char *loc_file, const char *tmp_file, const char *url, BOOL force_update)
{
  struct stat st_tmp,  st_loc;
  BOOL       _st_tmp, _st_loc, equal = FALSE;
  time_t      now  = time (NULL);
  time_t      past = now - 24 * 3600 * g_cfg.GEOIP.max_days;
  DWORD       rc = 0;

  _st_tmp = (stat(tmp_file, &st_tmp) == 0);
  _st_loc = (stat(loc_file, &st_loc) == 0);

  TRACE (1, "updating \"%s\"\n", loc_file);

  if (!force_update && _st_loc && st_loc.st_mtime >= past)
  {
    TRACE (1, "update not needed for \"%s\". Try again in %ld days.\n",
           loc_file, g_cfg.GEOIP.max_days + (long int)(now-st_loc.st_mtime)/(24*3600));
    return (rc);
  }

  if (!_st_tmp || force_update)
  {
    rc = INET_util_download_file (tmp_file, url);
    if (rc > 0)
       _st_tmp = (stat(tmp_file, &st_tmp) == 0);
  }

  if (_st_loc)
  {
    equal = (st_tmp.st_mtime >= st_loc.st_mtime) && (st_tmp.st_size == st_loc.st_size);
    TRACE (1, "local file exist, equal: %d\n", equal);
    INET_util_touch_file (loc_file);
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

/**
 * Check and download files from: <br>
 * ```
 *   g_cfg.GEOIP.ip4_url = https://gitweb.torproject.org/tor.git/plain/src/config/geoip   (if family == AF_INET)
 *   g_cfg.GEOIP.ip6_url = https://gitweb.torproject.org/tor.git/plain/src/config/geoip6  (if family == AF_INET6)
 * ```
 *
 * \param[in] family        If `AF_INET`, check if `g_cfg.GEOIP.ip4_file` needs to be updated.<br>
 *                          If `AF_INET6`, check if `g_cfg.GEOIP.ip6_file` needs to be updated.
 * \param[in] force_update  If TRUE, download the `%TEMP%/geoip.tmp` / `%TEMP%/geoip6.tmp` regardless.
 */
void geoip_update_file (int family, BOOL force_update)
{
  char        tmp_file [MAX_PATH];
  const char *env = getenv ("TEMP");

  if (family == AF_INET)
  {
    snprintf (tmp_file, sizeof(tmp_file), "%s\\%s", env, "geoip.tmp");
    update_file (g_cfg.GEOIP.ip4_file, tmp_file, g_cfg.GEOIP.ip4_url, force_update);
  }
  else if (family == AF_INET6)
  {
    snprintf (tmp_file, sizeof(tmp_file), "%s\\%s", env, "geoip6.tmp");
    update_file (g_cfg.GEOIP.ip6_file, tmp_file, g_cfg.GEOIP.ip6_url, force_update);
  }
  else
    TRACE (0, "Unknown address-family %d\n", family);
}

#if defined(TEST_GEOIP) && !defined(TEST_FIREWALL)   /* If not used with firewall_test.exe */

#include "getopt.h"
#include "dnsbl.h"

/* Prevent MinGW + Cygwin from globbing the cmd-line.
 */
#ifdef __CYGWIN__
  int _CRT_glob = 0;
#else
  int _dowildcard = -1;
#endif

/* For getopt.c.
 */
const char *program_name = "geoip.exe";

/**
 * Simplified version of the `get_error()` function in `wsock_trace.c`.
 */
static const char *get_ws_error (void)
{
  static char buf[150];
  return ws_strerror (WSAGetLastError(), buf, sizeof(buf));
}

/*
 * Determine length of the network part in an IPv4 address.
 * Courtesey of `Lev Walkin <vlm@lionet.info>`.
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

/**
 * Figure out the prefix length by checking the common `1`s in each
 * of the 16 BYTEs in IPv6-addresses `*a` and `*b`.
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

static int check_ipv4_unallocated (int dump_cidr,
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
    trace_printf ("    **: ");
    if (dump_cidr)
    {
      char low[25] = "?";
      int  nw_len = network_len32 (last->high+1, entry->low-1);

      _wsock_trace_inet_ntop (AF_INET, &addr, low, sizeof(low), NULL);
      len = trace_printf ("%s/%d", low, nw_len);
    }
    else
    {
      trace_printf ("%10lu  %10lu %8ld",
                    DWORD_CAST(last->high+1), DWORD_CAST(entry->low-1), LONG_CAST(diff));
      len = 22;
    }

    special = INET_util_addr_is_special (&addr, NULL, &remark);
    mcast   = INET_util_addr_is_multicast (&addr, NULL);
    global  = INET_util_addr_is_global (&addr, NULL);

    trace_printf ("%*sUnallocated block%s%s%s %s\n",
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

static void dump_ipv4_entries (int dump_cidr)
{
  int   i, len, max;
  DWORD missing_blocks = 0;
  DWORD missing_addr = 0;
  long  diff = 0;
  const struct ipv4_node *last = NULL;

  trace_puts ("IPv4 entries:\n Index: ");
  if (dump_cidr)
       trace_puts ("CIDR                    Country\n");
  else trace_puts ("  IP-low      IP-high      Diff  Country\n");

  max = geoip_ipv4_entries ? smartlist_len (geoip_ipv4_entries) : 0;
  for (i = 0; i < max; i++)
  {
    const struct ipv4_node *entry = smartlist_get (geoip_ipv4_entries, i);

    if (last)
    {
      missing_blocks += check_ipv4_unallocated (dump_cidr, entry, last, &diff);
      missing_addr   += (DWORD)diff;
    }
    last = entry;

    if (dump_cidr)
    {
      char  low[25] = "?";
      int   nw_len = network_len32 (entry->high, entry->low);
      DWORD addr   = swap32 (entry->low);

      _wsock_trace_inet_ntop (AF_INET, &addr, low, sizeof(low), NULL);
      len = trace_printf ("%6d: %s/%d", i, low, nw_len);
    }
    else
    {
      trace_printf ("%6d: %10lu  %10lu %8ld",
                    i, DWORD_CAST(entry->low), DWORD_CAST(entry->high),
                    (long)(entry->high - entry->low));
      len = 30;
    }
    trace_printf (" %*s %2.2s - %s\n", 30-len, "", entry->country, geoip_get_long_name_by_A2(entry->country));
  }

  trace_printf ("%s missing blocks ", dword_str(missing_blocks));
  trace_printf ("totalling %s missing IPv4 addresses.\n", dword_str(missing_addr));
}

static int check_ipv6_unallocated (int dump_cidr, const struct ipv6_node *entry, const struct ipv6_node *last, uint64 *diff_p)
{
#if 0    /* \todo */
  uint64 diff = (long)(entry->low - last->high);
  int    len;

  if (diff > 1)
  {
    trace_puts ("    **: ");
    if (dump_cidr)
    {
      char  low[25] = "?";
      int   nw_len = network_len32 (last->high+1, entry->low-1);
      DWORD addr   = swap32 (last->high+1);

      _wsock_trace_inet_ntop (AF_INET, &addr, low, sizeof(low), NULL);
      len = trace_printf ("%s/%d", low, nw_len);
    }
    else
    {
      trace_printf ("%10lu  %10lu %8ld", DWORD_CAST(last->high+1), DWORD_CAST(entry->low-1), LONG_CAST(diff));
      len = 22;
    }
    trace_printf ("%*sUnallocated block\n", 24-len, "");
    *diff_p = diff;
    return (1);
  }
#else
  ARGSUSED (dump_cidr);
  ARGSUSED (entry);
  ARGSUSED (last);
#endif
  *diff_p = 0;
  return (0);
}

static void dump_ipv6_entries (int dump_cidr)
{
  int    i, len, max;
  uint64 missing_blocks = 0;
  uint64 missing_addr = 0;
  uint64 diff;
  const struct ipv6_node *last = NULL;

  trace_puts ("IPv6 entries:\nIndex: ");

  if (dump_cidr)
       trace_printf ("%-*s Country\n", (int)(MAX_IP6_SZ-5), "CIDR");
  else trace_printf ("%-*s %-*s Country\n", (int)(MAX_IP6_SZ-4), "IP-low", (int)(MAX_IP6_SZ-5), "IP-high");

  max = geoip_ipv6_entries ? smartlist_len (geoip_ipv6_entries) : 0;
  for (i = 0; i < max; i++)
  {
    const struct ipv6_node *entry = smartlist_get (geoip_ipv6_entries, i);
    char  low  [MAX_IP6_SZ+1] = "?";
    char  high [MAX_IP6_SZ+1] = "?";
    int   nw_len;

    if (last)
    {
      missing_blocks += check_ipv6_unallocated (dump_cidr, entry, last, &diff);
      missing_addr   += diff;
    }
    last = entry;
    len = 0;

    _wsock_trace_inet_ntop (AF_INET6, &entry->low, low, sizeof(low), NULL);
    _wsock_trace_inet_ntop (AF_INET6, &entry->high, high, sizeof(high), NULL);

    if (dump_cidr)
    {
#if 0
      char *end = low + strlen(low);

      if (!strncmp(end-2, "::", 2))   /* Drop the last "::" */
         end[-2] = '\0';
#endif
      nw_len = network_len128 (&entry->high, &entry->low);
      len = trace_printf ("%5d: %s/%d ", i, low, nw_len);
    }
    else
    {
      trace_printf ("%5d: %-*s %-*s", i, (int)(MAX_IP6_SZ-4), low, (int)(MAX_IP6_SZ-4), high);
      len = 50;
    }
    trace_printf ("%*.2s - %s\n", 51-len, entry->country, geoip_get_long_name_by_A2(entry->country));
  }

  trace_printf ("%s missing blocks ", qword_str(missing_blocks));
  trace_printf ("totalling %s missing IPv6 addresses.\n", qword_str(missing_addr));
}

static void dump_num_ip_blocks_by_country (void)
{
  const struct country_list *list = c_list + 0;
  size_t                     i, num_c = DIM(c_list);
  size_t                    *counts4 = alloca (sizeof(*counts4) * num_c);
  size_t                    *counts6 = alloca (sizeof(*counts6) * num_c);

  memset (counts4, 0, sizeof(*counts4) * num_c);
  memset (counts6, 0, sizeof(*counts6) * num_c);

  trace_puts ("IPv4/6 blocks by countries:\n"
              " Idx: Country                           IPv4   IPv6\n");

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
      trace_printf (" %3d: %c%c, %-28.28s %5u  %5u\n",
                    (int)i, TOUPPER(list->short_name[0]), TOUPPER(list->short_name[1]),
                    list->long_name, (unsigned)counts4[i], (unsigned)counts6[i]);
  trace_putc ('\n');
}

/**
 * Get the region/city from the last successful call to either
 * `geoip_get_country_by_ipv4()` or `geoip_get_country_by_ipv6()`.
 *
 * Just mimick the code in `geoip_get_location_by_ipvX()` here
 * as those functions doesn't use it's `struct in_addr *` and
 * `struct in6_addr *` arguments.
 */
static const char *get_location (void)
{
  static char buf[110];

  if (IP2LOC_IS_GOOD())
       snprintf (buf, sizeof(buf), "loc: %s/%s", g_ip2loc_entry.city, g_ip2loc_entry.region);
  else strcpy (buf, "loc: <unknown>");
  return (buf);
}

/**
 * Common code for testing an IPv4 or IPv6 address.
 */
static void test_addr_common (const char            *addr_str,
                              const struct in_addr  *a4,
                              const struct in6_addr *a6,
                              BOOL use_ip2loc)
{
  const char *location = NULL;
  const char *comment  = NULL;
  const char *remark   = NULL;
  const char *cc;
  const BYTE *nibble;
  const position *pos;
  int   save, flag, ip_width;
  char  buf1 [200];
  char  buf2 [200];

  /** Start the timing now. Print the delta-time at the end.
   */
  get_timestamp2();

  /** Needed for `geoip_stats_update()` and the "unique" counter to work
   */
  save = g_cfg.trace_report;
  g_cfg.trace_report = 1;

  cc = (a4 ? geoip_get_country_by_ipv4(a4) :
             geoip_get_country_by_ipv6(a6));

  flag = (a4 ? GEOIP_STAT_IPV4 : GEOIP_STAT_IPV6);

  ip_width = a4 ? 14 : 40;

  g_cfg.trace_report = save;

  location = "";

  if (cc && *cc != '-')
  {
    if (use_ip2loc)
       location = get_location();

    /** Longest name from `geoip_get_long_name_by_A2()` is
     *  `United States Minor Outlying Islands`. 36 characters.
     *  Truncate to 20 thus becoming `United States Minor`.
     */
    snprintf (buf1, sizeof(buf1),
              "%-2s, %-20.20s %-40.40s",
              cc, geoip_get_long_name_by_A2(cc), location);
    snprintf (buf2, sizeof(buf2), "unique: %d", geoip_stats_is_unique(cc,flag));
  }
  else
  {
    if (INET_util_addr_is_zero(a4, a6))
       comment = "NULL-addr";
    else if (INET_util_addr_is_multicast(a4, a6))
       comment = "Multicast";
    else if (INET_util_addr_is_special(a4, a6, &remark))
       comment = "Special";
    else if (!INET_util_addr_is_global(a4, a6))
       comment = "Not global";
    else
       comment = "Unallocated?";

    if (remark)
    {
      if (!strcmp(remark, "6to4"))
      {
        nibble = (const BYTE*) &a6->s6_words[1];   /* = IN6_EXTRACT_V4ADDR_FROM_6TO4 (a6); */
        snprintf (buf1, sizeof(buf1), "%s (6to4: %u.%u.%u.%u)",
                  comment, nibble[0], nibble[1], nibble[2], nibble[3]);
      }
      else if (a6 && !stricmp(remark, "IPv4 compatible"))
      {
        trace_printf ("Recursing for a %s address.\n", remark);
        test_addr_common (addr_str, (const struct in_addr*)&a6->s6_words[6], NULL, use_ip2loc);
        return;
      }
      else
        snprintf (buf1, sizeof(buf1), "%s (%s)", comment, remark);
    }
    else
      snprintf (buf1, sizeof(buf1), "%s", comment);

    if (a4 && geoip_ipv4_entries)
         snprintf (buf2, sizeof(buf2), "%lu compares", DWORD_CAST(num_4_compare));
    else if (a6 && geoip_ipv6_entries)
         snprintf (buf2, sizeof(buf2), "%lu compares", DWORD_CAST(num_6_compare));
    else strcpy (buf2, "??");
  }

  trace_printf ("%-*.*s: %s %s\n", ip_width, ip_width, addr_str, buf1, buf2);

  pos = a4 ? geoip_get_position_by_ipv4 (a4) : geoip_get_position_by_ipv6 (a6);

  if (g_cfg.GEOIP.show_position)
  {
    if (pos)
         trace_printf ("  Pos:  %.3f%c, %.3f%c\n",
                       fabsf(pos->latitude), (pos->latitude  >= 0.0) ? 'N' : 'S',
                       fabsf(pos->longitude), (pos->longitude >= 0.0) ? 'E' : 'W');
    else trace_printf ("  Pos:  <none>\n");
  }

  if (g_cfg.GEOIP.show_map_url)
  {
    const char *zoom = "10z";

    if (pos)
         trace_printf ("  URL:  https://www.google.com/maps/@%.5f,%.5f,%s\n", pos->latitude, pos->longitude, zoom);
    else trace_printf ("  URL:  <none>\n");
  }

  if (g_cfg.IANA.enable || g_cfg.ASN.enable)
  {
    struct IANA_record rec;

    if (a4 && iana_find_by_ip4_address(a4, &rec))
    {
      iana_print_rec ("  IANA: ", &rec);
      ASN_print ("  ASN:  ", &rec, a4, NULL);
    }
    else if (a6 && iana_find_by_ip6_address(a6, &rec))
    {
      iana_find_by_ip6_address (a6, &rec);
      iana_print_rec ("  IANA: ", &rec);
      ASN_print ("  ASN:  ", &rec, NULL, a6);
    }
    ASN_libloc_print ("  ASN:  ", a4, a6);
  }

  /** Check the global IPv4 / IPv6 address for membership in a SpamHaus `DROP` / `EDROP` list
   */
  if (INET_util_addr_is_global(a4, NULL))
  {
    const char *sbl_ref = NULL;
    BOOL        rc = DNSBL_check_ipv4 (a4, &sbl_ref);
    char        addr [MAX_IP4_SZ+1];

    if (!sbl_ref)
       sbl_ref = " <none>";
    if (rc)
    {
      _wsock_trace_inet_ntop (AF_INET, a4, addr, sizeof(addr), NULL);
      trace_printf ("  Listed as SpamHaus SBL%s\n", sbl_ref);
    }
  }
  else if (INET_util_addr_is_global(NULL, a6))
  {
    const char *sbl_ref = NULL;
    BOOL        rc = DNSBL_check_ipv6 (a6, &sbl_ref);
    char        addr [MAX_IP6_SZ+1];

    if (!sbl_ref)
       sbl_ref = " <none>";
    if (rc)
    {
      _wsock_trace_inet_ntop (AF_INET6, a6, addr, sizeof(addr), NULL);
      trace_printf ("  Listed as SpamHaus SBL%s\n", sbl_ref);
    }
  }
  trace_printf ("  %s\n", str_ltrim((char*)get_timestamp2()));
}

static struct addrinfo *resolve_addr_or_name (const char *addr_or_host, int af)
{
  struct addrinfo hints, *res = NULL;

  memset (&hints, '\0', sizeof(hints));
  hints.ai_family   = af;
  hints.ai_socktype = SOCK_STREAM;
  if (getaddrinfo(addr_or_host, NULL, &hints, &res) == 0)
     return (res);
  return (NULL);
}

static void test_addr4 (const char *ip4_addr, BOOL use_ip2loc)
{
  struct addrinfo *ai = resolve_addr_or_name (ip4_addr, AF_INET);

  if (ai)
  {
    const struct sockaddr_in *sa = (struct sockaddr_in*) ai->ai_addr;

    test_addr_common (ip4_addr, &sa->sin_addr, NULL, use_ip2loc);
    freeaddrinfo (ai);
  }
  else
    trace_printf ("Invalid address: %s.\n", get_ws_error());
}

static void test_addr6 (const char *ip6_addr, BOOL use_ip2loc)
{
  struct addrinfo *ai = resolve_addr_or_name (ip6_addr, AF_INET6);

  if (ai)
  {
    const struct sockaddr_in6 *sa = (struct sockaddr_in6*) ai->ai_addr;

    test_addr_common (ip6_addr, NULL, &sa->sin6_addr, use_ip2loc);
    freeaddrinfo (ai);
  }
  else
    trace_printf ("Invalid address: %s.\n", get_ws_error());
}

/**
 * Return a random integer in range `[a..b]`. \n
 * Ref: http://stackoverflow.com/questions/2509679/how-to-generate-a-random-number-from-within-a-range
 */
unsigned int static rand_range (unsigned int min, unsigned int max)
{
  double scaled = (double) rand()/RAND_MAX;
  return (unsigned int) ((max - min + 1) * scaled) + min;
}

/**
 * Generates a random IPv4/6 address.
 */
static void make_random_addr (struct in_addr *addr4, struct in6_addr *addr6)
{
  int i;

  if (addr4)
  {
    addr4->S_un.S_un_b.s_b1 = rand_range (1, 255);
    addr4->S_un.S_un_b.s_b2 = rand_range (1, 255);
    addr4->S_un.S_un_b.s_b3 = rand_range (1, 255);
    addr4->S_un.S_un_b.s_b4 = rand_range (1, 255);
  }
  if (addr6)
  {
    addr6->s6_words[0] = swap16 (0x2001); /* Since most IPv6 addr has this prefix */
    for (i = 1; i < 8; i++)
        addr6->s6_words[i] = rand_range (0, 0xFFFF);
  }
}

static int show_help (const char *my_name, int err_code)
{
  printf ("Usage: %s [-cdfinruh] <-4|-6> address(es)\n"
          "       -c:      dump addresses on CIDR form.\n"
          "       -d:      dump address entries for countries and count of blocks.\n"
          "       -f:      force an update with the '-u' option.\n"
          "       -i:      do no use the IP2Location database.\n"
          "       -n #:    number of loops for random test.\n"
          "       -r:      random test for '-n' rounds (default 10).\n"
          "       -u:      test updating of geoip files.\n"
          "       -4:      test IPv4 address(es).\n"
          "       -6:      test IPv6 address(es).\n"
          "       -h:      this help.\n",
          my_name);
  printf ("   address(es) can also come from a response-file: '@file-with-addr'.\n"
          "   Or from 'stdin': \"geoip.exe -4 < file-with-addr\".\n"
          "   Built by %s\n", get_builder(FALSE));
  wsock_trace_exit();
  return (err_code);
}

typedef void (*test_func) (const char *addr, BOOL use_ip2loc);

static void test_addr_list (smartlist_t *list, BOOL use_ip2loc, test_func func)
{
  int   i, max = smartlist_len (list);
  DWORD num;

  for (i = 0; i < max; i++)
  {
    (*func) (smartlist_get(list, i), use_ip2loc);
    if (i < max-1)
       trace_putc ('\n'); /* Add an extra newline after each test (except the last) */
  }
  if (max > 1)
  {
    if (func == test_addr4)
         geoip_num_unique_countries (&num, NULL, NULL, NULL);
    else geoip_num_unique_countries (NULL, &num, NULL, NULL);
    trace_printf ("# of unique IPv%c countries: %lu\n",
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
    char   addr_buf [MAX_IP4_SZ+1];

    make_random_addr (&addr, NULL);
    _wsock_trace_inet_ntop (AF_INET, &addr, addr_buf, sizeof(addr_buf), NULL);
    test_addr4 (addr_buf, use_ip2loc);
    trace_putc ('\n');
  }
  geoip_num_unique_countries (&num_ip4, NULL, NULL, NULL);
  trace_printf ("# of unique IPv4 countries: %lu\n", DWORD_CAST(num_ip4));
}

static void rand_test_addr6 (int loops, BOOL use_ip2loc)
{
  DWORD num_ip6;
  int   i;

  srand ((unsigned int)time(NULL));

  for (i = 0; i < loops; i++)
  {
    struct in6_addr addr;
    char   addr_buf [MAX_IP6_SZ+1];

    make_random_addr (NULL, &addr);
    _wsock_trace_inet_ntop (AF_INET6, &addr, addr_buf, sizeof(addr_buf), NULL);
    test_addr6 (addr_buf, use_ip2loc);
    trace_putc ('\n');
  }
  geoip_num_unique_countries (NULL, &num_ip6, NULL, NULL);
  trace_printf ("# of unique IPv6 countries: %lu\n", DWORD_CAST(num_ip6));
}

/**
 * This accepts only one address per line.
 * Trailing `# comments` with or without a starting `<TAB>` are stripped off.
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
    p = strchr (buf, '\t');
    if (p)
       *p = '\0';
    smartlist_add (list, strdup(buf));
  }
  if (f && f != stdin)
     fclose (f);
  return (list);
}

/**
 * Make and return a `smartlist_t` list from an `argv[]` array.
 */
static smartlist_t *make_argv_list (int _argc, char **_argv)
{
  smartlist_t *list = smartlist_new();
  int          i;

  /**
   * Since Cygwin already converts a `@file` on the command-line into an
   * `argv[]`, this is of no use. And I found no way to disable this.
   * But try anyway.
   */
  if (_argc > 0 && _argv[0][0] == '@')
     return read_file (fopen(_argv[0]+1,"rb"), list);

  if (isatty(fileno(stdin)) == 0)
     return read_file (stdin, list);

  for (i = 0; i < _argc; i++)
      smartlist_add (list, strdup(_argv[i]));
  return (list);
}

static int check_requirements (void)
{
  if (!g_cfg.GEOIP.ip4_file || !file_exists(g_cfg.GEOIP.ip4_file))
  {
    trace_printf ("'geoip4' file '%s' not found. This is needed for these tests.\n", g_cfg.GEOIP.ip4_file);
    return (0);
  }
  if (!g_cfg.GEOIP.ip6_file || !file_exists(g_cfg.GEOIP.ip6_file))
  {
    trace_printf ("'geoip6' file '%s' not found. This is needed for these tests.\n", g_cfg.GEOIP.ip6_file);
    return (0);
  }
  if (!g_cfg.GEOIP.enable)
  {
    trace_printf ("'[geoip]' section must have 'enable=1' in %s to use this option.\n", config_file_name());
    return (0);
  }
  return (1);
}

int main (int argc, char **argv)
{
  int         c, do_cidr = 0,  do_4 = 0, do_6 = 0, do_force = 0;
  int         do_update = 0, do_dump = 0, do_rand = 0;
  int         use_ip2loc = 1;
  int         loops = 10;
  const char *my_name = argv[0];
  WSADATA     wsa;

  crtdbg_init();
  wsock_trace_init();

  /* Since these are inside a 'if !defined(TEST_GEOIP)' block in init.c
   */
  iana_init();
  ASN_init();

  g_cfg.trace_use_ods = g_cfg.DNSBL.test = FALSE;
  g_cfg.trace_time_format = TS_RELATIVE;

  while ((c = getopt (argc, argv, "h?cdfin:ru46")) != EOF)
    switch (c)
    {
      case '?':
      case 'h':
           return show_help (my_name, 0);
      case 'c':
           do_cidr = 1;
           break;
      case 'd':
           do_dump++;
           break;
      case 'f':
           do_force = 1;
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
      default:
           return show_help (my_name, 1);
    }

  if (!do_4 && !do_6)
     return show_help (my_name, 1);

  /** Possibly call `ip2loc_init()` again.
   */
  if (use_ip2loc)
  {
    ip2loc_exit();
    ip2loc_init();
  }

  if (do_update)
  {
    if (do_4)
       geoip_update_file (AF_INET, do_force);
    if (do_6)
       geoip_update_file (AF_INET6, do_force);
  }
  else
  {
    if (!check_requirements())
       return (1);
  }

  argc -= optind;
  argv += optind;

  if (do_dump)
  {
    if (do_4)
       dump_ipv4_entries (do_cidr);
    if (do_6)
       dump_ipv6_entries (do_cidr);
    if (do_dump >= 2 && (do_4 || do_6))
       dump_num_ip_blocks_by_country();
  }

  WSAStartup (MAKEWORD(1,1), &wsa);
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
     smartlist_wipe (list, free);
  }

  wsock_trace_exit();

  /* Since this is inside a 'if !defined(TEST_GEOIP)' block in init.c
   */
  exclude_list_free();
  crtdbg_exit();
  return (0);
}
#endif  /* TEST_GEOIP */

