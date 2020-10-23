/**\file    iana.c
 * \ingroup IANA
 *
 * \brief Implements parsing of CSV file of "IANA IPv4 Address Space Registry"
 *        from: https://www.iana.org/assignments/ipv4-address-space/ipv4-address-space.csv
 *
 *        Also Implements parsing of CSV file of "IPv6 Global Unicast Address Assignments".
 *        from: https://www.iana.org/assignments/ipv6-unicast-address-assignments/ipv6-unicast-address-assignments.csv
 *
 *  IANA = "Internet Assigned Numbers Authority"
 *
 * CSV parsing is loosely adapting the rules in: https://tools.ietf.org/html/rfc4180
 *
 * iana.c - Part of Wsock-Trace.
 */
#include <limits.h>

#if defined(__WATCOMC__)
  /*
   * Required to define `IN6_IS_ADDR_LOOPBACK()` etc. in
   * OpenWatcom's <ws2ipdef.h>.
   */
  #undef  NTDDI_VERSION
  #define NTDDI_VERSION 0x05010000
#endif

#include "common.h"
#include "csv.h"
#include "smartlist.h"
#include "inet_util.h"
#include "in_addr.h"
#include "init.h"
#include "iana.h"

#ifdef USE_LIBLOC
  #include <loc/libloc.h>
  #include <loc/database.h>
  #include <loc/network.h>
  #include <loc/resolv.h>
  #include <loc/windows/syslog.h>

  #define USE_LOC_NETWORK_STR 1

  static void ASN_bin_close (void);
#endif

#ifdef TEST_IANA
  static unsigned rec_max = UINT_MAX;
  static unsigned rec_illegal;
#endif

static smartlist_t *iana_entries_ip4;
static smartlist_t *iana_entries_ip6;

static DWORD g_num_ipv4, g_num_ipv6;

static void iana_sort_lists (void);
static void iana_load_and_parse (int family, const char *file);
static int  iana_add_entry (const struct IANA_record *rec);
static int  iana_CSV_add4 (struct CSV_context *ctx, const char *value);
static int  iana_CSV_add6 (struct CSV_context *ctx, const char *value);

/**
 * A smartlist of `struct ASN_record`. <br>
 *
 * \note
 * This does NOT contain any data from a 'libloc' datafile.
 * When using 'libloc', we use the 'loc_network_get_asn()` function directly.
 */
static smartlist_t *ASN_entries;

static int  ASN_load_bin_file (const char *file);
static void ASN_load_CSV_file (const char *file);
static int  ASN_CSV_add (struct CSV_context *ctx, const char *value);

/**
 * The main init function for this module.
 * Normally called from `wsock_trace_init()`.
 */
void iana_init (void)
{
  if (!g_cfg.IANA.enable)
     return;

  /* Load the IANA IPv4/6 assignment files.
   */
  iana_load_and_parse (AF_INET, g_cfg.IANA.ip4_file);
  iana_load_and_parse (AF_INET6, g_cfg.IANA.ip6_file);

  if (g_cfg.IANA.asn_bin_file)
     ASN_load_bin_file (g_cfg.IANA.asn_bin_file);

  if (g_cfg.IANA.asn_csv_file)
     ASN_load_CSV_file (g_cfg.IANA.asn_csv_file);

  iana_sort_lists();

  if ((!iana_entries_ip4 || smartlist_len(iana_entries_ip4) == 0) &&
      (!iana_entries_ip6 || smartlist_len(iana_entries_ip6) == 0))
     g_cfg.IANA.enable = FALSE;

  if (g_cfg.trace_level >= 2)
  {
    iana_dump();
    ASN_dump();
  }
}

static char print_buf [500];

/**
 * Printers common to both `iana_print_rec()` and `iana_dump()`.
 */
static const char *iana_get_rec4 (const IANA_record *rec, BOOL aligned)
{
  static const char *fmt[2] = { "%03lu/%d, %s, %s, %s, %s, %s",
                                "%03lu/%-2d   %-20.20s %-8.8s %-20.20s %-22.22s  %s"
                              };
  if (rec->family != AF_INET)
     return ("Illegal");

  snprintf (print_buf, sizeof(print_buf), fmt[aligned],
            rec->net_num.ip4.s_addr, rec->mask,
            rec->misc[0]   ? rec->misc   : "-",
            rec->date[0]   ? rec->date   : "-",
            rec->whois[0]  ? rec->whois  : "-",
            rec->url[0]    ? rec->url    : "-",
            rec->status[0] ? rec->status : "-");
  return (print_buf);
}

static const char *iana_get_rec6 (const IANA_record *rec, BOOL aligned)
{
  char ip6_buf1 [MAX_IP6_SZ+1];
  char ip6_buf2 [MAX_IP6_SZ+10];
  static const char *fmt[2] = { "%s, %s, %s, %s, %s, %s",
                                "%-16s %-16.16s %-12.12s %-20.20s %-20.20s  %s"
                              };

  if (rec->family != AF_INET6)
     return ("Illegal");

  _wsock_trace_inet_ntop (AF_INET6, &rec->net_num.ip6, ip6_buf1, sizeof(ip6_buf1), NULL);
  snprintf (ip6_buf2, sizeof(ip6_buf2), "%s/%-2d", ip6_buf1, rec->mask);

  snprintf (print_buf, sizeof(print_buf), fmt[aligned],
            ip6_buf2,
            rec->misc[0]   ? rec->misc   : "-",
            rec->date[0]   ? rec->date   : "-",
            rec->whois[0]  ? rec->whois  : "-",
            rec->url[0]    ? rec->url    : "-",
            rec->status[0] ? rec->status : "-");
  return (print_buf);
}

/**
 * With a positive result (`rec->family != -1`) from `iana_find_by_ip4_address()`,
 * print an IANA record in `dump.c` to show it like this:
 *
 * ```
 * * 0.329 sec: test.c(251) (test_gethostbyname+95):
 *   gethostbyname ("google-public-dns-a.google.com") --> 0x00C7CAC0.
 *   name: google-public-dns-a.google.com, addrtype: AF_INET, addr_list: 8.8.8.8
 *   aliases: <none>
 *   geo-IP: US - United States, Mountain View/California
 *   IANA:   Administered by ARIN, 1992-12, LEGACY
 * ```
 */
void iana_print_rec (const IANA_record *rec)
{
  switch (rec->family)
  {
    case AF_INET:
         trace_puts (iana_get_rec4(rec, FALSE));
         break;
    case AF_INET6:
         trace_puts (iana_get_rec6(rec, FALSE));
         break;
    case -1:
         trace_puts ("<no data>");
         break;
    default:
         trace_puts ("<wrong AF>");
         break;
  }
  trace_putc ('\n');
}

/**
 * Dump the IANA smartlists of IPv4/IPv6 records.
 */
void iana_dump (void)
{
  const IANA_record *rec;
  int   i, max4, max6;

  max4 = iana_entries_ip4 ? smartlist_len (iana_entries_ip4) : 0;
  for (i = 0; i < max4; i++)
  {
    if (i == 0)
       printf ("Dumping %d IANA IPv4 records:\n"
               "   #  Net/mask misc                 date     whois                url"
               "                     status\n", max4);

    rec = smartlist_get (iana_entries_ip4, i);
    printf (" %3d: %s\n", i, iana_get_rec4(rec, TRUE));
  }

  max6 = iana_entries_ip6 ? smartlist_len (iana_entries_ip6) : 0;
  for (i = 0; i < max6; i++)
  {
    if (i == 0)
       printf ("%sDumping %d IANA IPv6 records:\n"
               "   #  Net/mask         misc             date         whois"
               "                url                   status\n",
               max4 > 0 ? "\n" : "", max6);

    rec = smartlist_get (iana_entries_ip6, i);
    printf (" %3d: %s\n", i, iana_get_rec6(rec, TRUE));
  }
}

/**
 * Free memory allocated here. <br>
 * Normally called from `wsock_trace_exit()`.
 */
void iana_exit (void)
{
  if (iana_entries_ip4)
     smartlist_wipe (iana_entries_ip4, free);

  if (iana_entries_ip6)
     smartlist_wipe (iana_entries_ip6, free);

  if (ASN_entries)
     smartlist_wipe (ASN_entries, free);

#ifdef USE_LIBLOC
  ASN_bin_close();
#endif

  iana_entries_ip4 = iana_entries_ip6 = ASN_entries = NULL;
  free (g_cfg.IANA.ip4_file);
  free (g_cfg.IANA.ip6_file);
  free (g_cfg.IANA.asn_csv_file);
  free (g_cfg.IANA.asn_bin_file);
}

/**
 * \todo
 * Collect some statistics on net blocks discovered and print that information here.
 */
void iana_report (void)
{
  trace_printf ("\n  IANA statistics:\n"
                "    Got %lu IPv4 records, %lu IPv6 records.\n",
                DWORD_CAST(g_num_ipv4), DWORD_CAST(g_num_ipv6));
}

/**
 * Open and parse a
 *  "IANA IPv4 Address Space Registry" or a
 *  "IPv6 Global Unicast Address Assignments" file.
 *
 * \param[in] family  the address family; AF_INET or AF_INET6.
 * \param[in] file    the CSV file to read and parse.
 */
static void iana_load_and_parse (int family, const char *file)
{
  struct CSV_context ctx;

  assert (family == AF_INET || family == AF_INET6);

  if (family == AF_INET)
  {
    assert (iana_entries_ip4 == NULL);
    iana_entries_ip4 = smartlist_new();
    if (!iana_entries_ip4)
       return;
  }
  else
  {
    assert (iana_entries_ip6 == NULL);
    iana_entries_ip6 = smartlist_new();
    if (!iana_entries_ip6)
       return;
  }

  if (!file || !file_exists(file))
  {
    TRACE (1, "file \"%s\" does not exist.\n", file);
    return;
  }

  memset (&ctx, '\0', sizeof(ctx));
  ctx.file_name  = file;
  ctx.num_fields = 7;
  ctx.delimiter  = ',';
  ctx.callback   = family == AF_INET ? iana_CSV_add4 : iana_CSV_add6;

  #ifdef TEST_IANA
  ctx.rec_max = rec_max;
  #endif

  CSV_open_and_parse_file (&ctx);
}

/**
 * The CSV callback to add a record to the `iana_entries_ip4` smart-list.
 *
 * \param[in]  ctx   the CSV context structure.
 * \param[in]  value the value for this CSV field in record `ctx->rec_num`.
 *
 * Match the fields for a record like this (family == AF_INET):
 * ```
 *   014/8,Administered by APNIC,2010-04,whois.apnic.net,https://rdap.apnic.net/,ALLOCATED,NOTE
 *   ^   ^ ^                     ^       ^               ^                       ^         ^
 *   |   | |                     |       |__ rec.whois   |                       |         |___ ignored
 *   |   | |_ rec.misc           |__________ rec.date    |___ rec.url            |____ rec.status
 *   |   |___ rec.mask                                        can be quoted
 *   |_______ rec.net_num.ip4
 * ```
 *
 * Note: The `rec.url` can be quoted and contain 2 URLs.
 *       We split this and ignore this 2nd URL.
 */
static int iana_CSV_add4 (struct CSV_context *ctx, const char *value)
{
  static struct IANA_record rec = { -1 };
  char  *space;
  int    rc = 1;

  switch (ctx->field_num)
  {
    case 0:
         sscanf (value, "%lu/%d", (unsigned long*)&rec.net_num.ip4.s_addr, &rec.mask);
         break;
    case 1:
         _strlcpy (rec.misc, value, sizeof(rec.misc));
         break;
    case 2:
         _strlcpy (rec.date, value, sizeof(rec.date));
         break;
    case 3:
         _strlcpy (rec.whois, value, sizeof(rec.whois));
         break;
    case 4:
         _strlcpy (rec.url, value, sizeof(rec.url));
         space = strchr (rec.url, ' ');
         if (space)
            *space = '\0';
         break;
    case 5:
         _strlcpy (rec.status, value, sizeof(rec.status));
         break;
    case 6:   /* The value in this 'NOTE' field is ignored */
         rec.family = AF_INET;
         rc = iana_add_entry (&rec);
         memset (&rec, '\0', sizeof(rec));    /* Ready for a new record. */
         rec.family = rec.mask = -1;
         rec.net_num.ip4.s_addr = INADDR_NONE;
         break;
  }
  return (rc);
}

/**
 * The CSV callback to add a record to the `iana_entries_ip6` smart-list.
 *
 * \param[in]  ctx   the CSV context structure.
 * \param[in]  value the value for this CSV field in record `ctx->rec_num`.
 *
 * Match the fields for a record like this:
 * ```
 *   Prefix,Designation,Date,WHOIS,RDAP,Status,Note
 *
 *   2001:1a00::/23,RIPE NCC,2004-01-01,whois.ripe.net,https://rdap.db.ripe.net/,ALLOCATED,
 *   ^           ^  ^        ^          ^              ^                         ^         ^
 *   |           |  |        |          |__ rec.whois  |__ rec.url               |         |__ Note; thield field can be very long.
 *   |           |  |        |__ rec.date                                        |             And over multiple lines. But then it's quoted.
 *   |           |  |_ rec.misc                                                  |____ rec.status
 *   |           |_ __ rec.mask
 *   |________________ rec.net_num.ip6
 * ```
 *
 * Note: The `rec.url` can be quoted and contain 2 URLs.
 *       We split this and ignore this 2nd URL.
 */
static int iana_CSV_add6 (struct CSV_context *ctx, const char *value)
{
  static struct IANA_record rec = { -1 };
  static char   ip6_addr [MAX_IP6_SZ+1];
  char  *space;
  int    rc = 1;

  switch (ctx->field_num)
  {
    case 0:
         sscanf (value, "%50[^/]/%d", ip6_addr, &rec.mask);
         _wsock_trace_inet_pton (AF_INET6, ip6_addr, &rec.net_num.ip6, NULL);
         break;
    case 1:
         _strlcpy (rec.misc, value, sizeof(rec.misc));
         break;
    case 2:
         _strlcpy (rec.date, value, sizeof(rec.date));
         break;
    case 3:
         _strlcpy (rec.whois, value, sizeof(rec.whois));
         break;
    case 4:
         _strlcpy (rec.url, value, sizeof(rec.url));
         space = strchr (rec.url, ' ');
         if (space)
            *space = '\0';
         break;
    case 5:
         _strlcpy (rec.status, value, sizeof(rec.status));
         break;
    case 6:                                   /* The value in this 'NOTE' field is ignored */
         rec.family = AF_INET6;
         rc = iana_add_entry (&rec);
         memset (&rec, '\0', sizeof(rec));    /* Ready for a new record. */
         rec.family = rec.mask = -1;
         memset (&rec.net_num.ip6, '\0', sizeof(rec.net_num.ip6)); /* IN6_IS_ADDR_UNSPECIFIED() */
         break;
  }
  return (rc);
}

/**
 * Add an IANA record to the `iana_entries_ip4` ir `iana_entries_ip6` smart-list.
 */
static int iana_add_entry (const struct IANA_record *rec)
{
  struct IANA_record *copy = malloc (sizeof(*copy));

  if (!copy)
     return (0);

#ifdef TEST_IANA
   if (rec->family == AF_INET && rec->mask == -1)
      rec_illegal++;
   else if (rec->family == AF_INET6 && IN6_IS_ADDR_UNSPECIFIED(&rec->net_num.ip6))
      rec_illegal++;
#endif

  memcpy (copy, rec, sizeof(*copy));
  if (rec->family == AF_INET)
       smartlist_add (iana_entries_ip4, copy);
  else smartlist_add (iana_entries_ip6, copy);
  return (1);
}

/**
 * `smartlist_sort()` helper for `iana_entries_ip4`:
 *   return -1, 1, or 0 based on comparison of two `struct IANA_record`.
 *
 * Sort on network-number, mask and then finally status.
 */
static DWORD g_num_compares;

static int compare_on_netnum_ip4 (const void **_a, const void **_b)
{
  const struct IANA_record *a = *_a;
  const struct IANA_record *b = *_b;

  assert (a->family == AF_INET && b->family == AF_INET);

  g_num_compares++;

  if (a->net_num.ip4.s_addr < b->net_num.ip4.s_addr)
     return (-1);
  if (a->net_num.ip4.s_addr > b->net_num.ip4.s_addr)
     return (1);

  if (a->mask < b->mask)
     return (-1);
  if (a->mask > b->mask)
     return (-1);
  return stricmp (a->status, b->status);
}

/**
 * `smartlist_sort()` helper for `iana_entries_ip6`:
 *   return -1, 1, or 0 based on comparison of two `struct IANA_record`.
 *
 * Sort on network-number, mask and then finally status.
 */
static int compare_on_netnum_ip6 (const void **_a, const void **_b)
{
  const struct IANA_record *a = *_a;
  const struct IANA_record *b = *_b;
  int   rc;

  assert (a->family == AF_INET6 && b->family == AF_INET6);

  g_num_compares++;

  rc = memcmp (&a->net_num.ip6, &b->net_num.ip6, sizeof(a->net_num.ip6));
  if (rc < 0)
     return (-1);
  if (rc > 0)
     return (1);

  if (a->mask < b->mask)
     return (-1);
  if (a->mask > b->mask)
     return (-1);

  return stricmp (a->status, b->status);
}

/**
 * `smartlist_bsearch()` helper; compare on IPv4 range.
 */
static int compare_on_netnum_prefix_ip4 (const void *key, const void **member)
{
  const struct IANA_record *rec = *member;
  const struct in_addr     *ip4 = key;
  char  ip4_buf [MAX_IP4_SZ+1];
  int   rc;

  g_num_compares++;

  rc = INET_util_range4cmp (ip4, &rec->net_num.ip4, rec->mask);
  _wsock_trace_inet_ntop (AF_INET, ip4, ip4_buf, sizeof(ip4_buf), NULL);

  TRACE (2, "key: %s, net_num: %lu, mask: %d, rc: %d\n",
         ip4_buf, (unsigned long)rec->net_num.ip4.s_addr, rec->mask, rc);
  return (rc);
}

/**
 * `smartlist_bsearch()` helper; compare on IPv6 range.
 */
static int compare_on_netnum_prefix_ip6 (const void *key, const void **member)
{
  const struct IANA_record *rec = *member;
  const struct in6_addr    *ip6 = key;
  struct in6_addr mask;
  char  ip6_buf [MAX_IP6_SZ+1];
  char  net6_buf[MAX_IP6_SZ+1];
  int   rc;

  g_num_compares++;

  INET_util_get_mask6 (&mask, rec->mask);

  rc = INET_util_range6cmp (ip6, &rec->net_num.ip6, rec->mask);

  _wsock_trace_inet_ntop (AF_INET6, &rec->net_num.ip6, net6_buf, sizeof(net6_buf), NULL);
  _wsock_trace_inet_ntop (AF_INET6, ip6, ip6_buf, sizeof(ip6_buf), NULL);

  TRACE (2, "key: %s, net_num: %-12s prefix: %2d mask: %-12s rc: %d\n",
         ip6_buf, net6_buf, rec->mask, INET_util_in6_mask_str(&mask), rc);
  return (rc);
}

/**
 * Sort both `iana_entries_ip4` and  `iana_entries_ip6` smart-lists on
 * net-number, mask and finally on status.
 *
 * \note The `ASN_entries` is already sorted on IPv4 low/high range since
 *       the .CSV-file the records are read from, was assumed to be sorted.
 */
static void iana_sort_lists (void)
{
  if (iana_entries_ip4)
  {
    g_num_compares = 0;
    smartlist_sort (iana_entries_ip4, compare_on_netnum_ip4);
    TRACE (2, "g_num_compares: %lu.\n", DWORD_CAST(g_num_compares));
    g_num_compares = 0;
  }
  if (iana_entries_ip6)
  {
    g_num_compares = 0;
    smartlist_sort (iana_entries_ip6, compare_on_netnum_ip6);
    TRACE (2, "g_num_compares: %lu.\n", DWORD_CAST(g_num_compares));
    g_num_compares = 0;
  }
}

/**
 * Find an IANA record based on an IPv4 address.
 *
 * \param[in]     ip4      The address to search for.
 * \param[in,out] out_rec  The filled record if the address was found.
 */
int iana_find_by_ip4_address (const struct in_addr *ip4, struct IANA_record *out_rec)
{
  const struct IANA_record *rec;

  out_rec->family = -1;  /* Signal an invalid record */
  out_rec->rir_list = NULL;

  if (!iana_entries_ip4)
     return (0);

  g_num_compares = 0;
  rec = smartlist_bsearch (iana_entries_ip4, ip4, compare_on_netnum_prefix_ip4);

  TRACE (2, "g_num_compares: %lu.\n", DWORD_CAST(g_num_compares));
  g_num_compares = 0;

  if (rec)
  {
    *out_rec = *rec;
    g_num_ipv4++;
    return (1);
  }
  return (0);
}

/*
 * Ignore the gcc warning on 'loop' initialisation.
 */
#if defined(__GNUC__)
#pragma GCC diagnostic ignored  "-Wmissing-braces"
#endif

/**
 * Find an IANA record based on an IPv6 address.
 *
 * \param[in]     ip6      The address to search for.
 * \param[in,out] out_rec  The filled record if the address was found.
 */
int iana_find_by_ip6_address (const struct in6_addr *ip6, struct IANA_record *out_rec)
{
  const struct IANA_record *rec;

  out_rec->family = -1;  /* Signal an invalid record */
  out_rec->rir_list = NULL;

  if (!iana_entries_ip6)
     return (0);

  if (IN6_IS_ADDR_LOOPBACK(ip6))
  {
    const struct in6_addr loop = { 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1 }; /* IN6ADDR_LOOPBACK_INIT */

    TRACE (2, "Returning fixed 'in6addr_loopback'.\n");
    out_rec->family = AF_INET6;
    out_rec->mask   = 128;
    memcpy (&out_rec->net_num.ip6, &loop, sizeof(out_rec->net_num.ip6));
    strcpy (out_rec->misc, "IPv6 Loopback");
    strcpy (out_rec->date, "No idea");
    strcpy (out_rec->whois, "No WHOIS");
    strcpy (out_rec->url, "No RDAP");
    strcpy (out_rec->status, "Fixed status");
    g_num_ipv6++;
    return (1);
  }

  g_num_compares = 0;
  rec = smartlist_bsearch (iana_entries_ip6, ip6, compare_on_netnum_prefix_ip6);

  TRACE (2, "g_num_compares: %lu.\n", DWORD_CAST(g_num_compares));
  g_num_compares = 0;

  if (rec)
  {
    *out_rec = *rec;
    g_num_ipv6++;
    return (1);
  }
  return (0);
}

/**
 * Open and parse `GeoIPASNum.csv` file. <br>
 * This must be generated using "Blockfinder" and
 * `python2 blockfinder --export`.
 *
 * \param[in] file  the CSV file to read and parse.
 */
static void ASN_load_CSV_file (const char *file)
{
  struct CSV_context ctx;

  assert (ASN_entries == NULL);
  ASN_entries = smartlist_new();
  if (!ASN_entries)
      return;

  if (!file_exists(file))
  {
    TRACE (1, "ASN file \"%s\" does not exist.\n", file);
    return;
  }

  memset (&ctx, '\0', sizeof(ctx));
  ctx.file_name  = file;
  ctx.num_fields = 5;
  ctx.callback   = ASN_CSV_add;

  #ifdef TEST_IANA
  ctx.rec_max = rec_max;
  #endif

  CSV_open_and_parse_file (&ctx);
}

/**
 * Split a string like `{12849,21450}` and add each to
 * ASN_record::asn[]`.
 */
static void ASN_add_asn_numbers (struct ASN_record *rec, const char *value)
{
  if (*value == '{')
  {
    char val[50], *v, *end;
    int  i = 0;

    _strlcpy (val, value+1, sizeof(val));
    for (v = _strtok_r(val, ",", &end); v; v = _strtok_r(NULL, ",", &end))
       rec->asn[i++] = (DWORD) _atoi64 (v);
  }
  else
    rec->asn[0] = (DWORD) _atoi64 (value);
}

/**
 * Currently handles only IPv4 addresses.
 */
static int ASN_CSV_add (struct CSV_context *ctx, const char *value)
{
  static struct ASN_record rec = { 0 };
  struct ASN_record *copy;

  switch (ctx->field_num)
  {
    case 0:
    case 1:      /* Ignore the low/high `a.b.c.d` fields */
         break;
    case 2:
         rec.ipv4.low.s_addr = swap32 ((DWORD)_atoi64(value));
         break;
    case 3:
         rec.ipv4.high.s_addr = swap32 ((DWORD)_atoi64(value));
         break;
    case 4:
         ASN_add_asn_numbers (&rec, value);
         rec.family = AF_INET;
         copy = malloc (sizeof(*copy));
         if (copy)
         {
           memcpy (copy, &rec, sizeof(*copy));
           smartlist_add (ASN_entries, copy);
         }
         memset (&rec, '\0', sizeof(rec));    /* Ready for a new record. */
         break;
  }
  return (1);
}

/**
 * `smartlist_bsearch()` helper; compare on IPv4 range.
 */
static int compare_on_ip4 (const void *key, const void **member)
{
  const struct ASN_record *rec  = *member;
  struct in_addr ipv4;
  char   low_str  [MAX_IP4_SZ+1];
  char   high_str [MAX_IP4_SZ+1];
  char   ipv4_str [MAX_IP4_SZ+1];
  int    rc;

  g_num_compares++;
  ipv4.s_addr = *(const u_long*)key;

  if (swap32(ipv4.s_addr) < swap32(rec->ipv4.low.s_addr))
       rc = -1;
  else if (swap32(ipv4.s_addr) > swap32(rec->ipv4.high.s_addr))
       rc = 1;
  else rc = 0;

  _wsock_trace_inet_ntop (AF_INET, &ipv4, ipv4_str, sizeof(ipv4_str), NULL);
  _wsock_trace_inet_ntop (AF_INET, &rec->ipv4.low, low_str, sizeof(low_str), NULL);
  _wsock_trace_inet_ntop (AF_INET, &rec->ipv4.high, high_str, sizeof(high_str), NULL);

  TRACE (1, "\nkey: %s, low: %s, high: %s, rc: %d\n", ipv4_str, low_str, high_str, rc);
  return (rc);
}

#ifdef USE_LIBLOC
  static struct {
    int                  error;
    size_t               num_AS;
    FILE                *file;
    struct loc_ctx      *ctx;
    struct loc_database *db;
    const char           *vendor;
  } libloc_data;

  static void ASN_bin_close (void)
  {
    if (libloc_data.db)
       loc_database_unref (libloc_data.db);

    if (libloc_data.ctx)
       loc_unref (libloc_data.ctx);

    if (libloc_data.file)
       fclose (libloc_data.file);

    memset (&libloc_data, '\0', sizeof(libloc_data));
  }

  #define DO_NOTHING(f)  void *f(void) { return NULL; }
  DO_NOTHING (OPENSSL_init_crypto)
  DO_NOTHING (PEM_read_PUBKEY)
  DO_NOTHING (EVP_MD_CTX_new)
  DO_NOTHING (EVP_DigestVerifyInit)
  DO_NOTHING (EVP_DigestVerifyUpdate)
  DO_NOTHING (ERR_get_error)
  DO_NOTHING (ERR_error_string)
  DO_NOTHING (EVP_MD_CTX_free)
  DO_NOTHING (EVP_PKEY_free)
  DO_NOTHING (EVP_DigestVerifyFinal)

int check_libloc_database (void)
{
  time_t time;

  if (loc_discover_latest_version(libloc_data.ctx, LOC_DATABASE_VERSION_LATEST, &time) != 0)
  {
    TRACE (1, "Could not check IPFire's database version.\n");
    return (0);
  }
  return (1);
}

static int ASN_load_bin_file (const char *file)
{
  const char *descr, *licence, *vendor;
  size_t      len, num_AS;
  time_t      created;
  int         save;

  memset (&libloc_data, '\0', sizeof(libloc_data)); // should be un-needed

#if 0
  check_libloc_database();
#endif

  if (!file || !file_exists(file))
  {
    TRACE (0, "file \"%s\" does not exist.\n", file);
    return (0);
  }

  TRACE (1, "Trying to open IPFire's database: \"%s\" .\n", file);
  libloc_data.file = fopen (file, "rb");
  if (!libloc_data.file)
  {
    TRACE (1, "Could not open IPFire's binary database: %s\n", strerror(errno));
    return (0);
  }

  /* Do not trace 'WSAStartup()' inside libloc's 'loc_new()'.
   */
  save = g_cfg.trace_level;
  g_cfg.trace_level = 0;
  libloc_data.error = loc_new (&libloc_data.ctx);
  g_cfg.trace_level = save;

  if (libloc_data.error < 0)
  {
    TRACE (1, "Cannot create libloc context; %s.\n", strerror(-libloc_data.error));
    ASN_bin_close();
    return (0);
  }

  loc_set_log_priority (libloc_data.ctx, g_cfg.trace_level >= 2 ? LOG_INFO : 0);

  libloc_data.error = loc_database_new (libloc_data.ctx, &libloc_data.db, libloc_data.file);
  if (libloc_data.error)
  {
    TRACE (1, "Could not open database: %s\n", strerror(-libloc_data.error));
    ASN_bin_close();
    return (0);
  }

  descr   = loc_database_get_description (libloc_data.db);
  licence = loc_database_get_license (libloc_data.db);
  vendor  = loc_database_get_vendor (libloc_data.db);
  num_AS  = loc_database_count_as (libloc_data.db);
  created = loc_database_created_at (libloc_data.db);

  if (descr)
  {
    const char *nl = strchr (descr, '\n');
    len = strlen (descr);
    if (nl)
       len = nl - descr - 1;
  }
  else
  {
    descr = "??";
    len = 2;
  }

  TRACE (1, "\n  Description: %.*s\n"
            "  Licence:     %s\n"
            "  Vendor:      %s\n"
            "  Created:     %.24s\n"
            "  num_AS:      %lu\n\n",
         len, descr, licence, vendor, ctime(&created), num_AS);
  libloc_data.num_AS = num_AS;
  return (num_AS);
}

static const IN6_ADDR _in6addr_v4mappedprefix = {{
       0,0,0,0,0,0,0,0,0,0,0xFF,0xFF,0,0,0,0
     }};

/*
 * If `g_cfg.IANA.asn_bin_file` is set and valid, make
 * it print the information like IPFire's Python3-scipt does.
 * E.g.:
 *
 * c:\> py -3 location.py lookup 45.150.206.231
 *   Network:           45.150.206.0/23
 *   Autonomous System: AS35029 - WebLine LTD
 *   Anonymous Proxy:   yes
 *
 * for an IPv4 address we must map `ip4` to an IPv4-mapped first:
 * `45.150.206.231`  -> `::ffff:45.150.206.231`)

 * This function does nothing for top-level network like from IANA, RIPE etc.
 * 'libloc' only have information on RIRs.
 *
 * \todo: Use a cache of IPv4/6 addresses and ASN-info?
 */

/**
 * \def ASN_MAX_NAME
 * Maximum length of an ASN-name, which can be quite long.
 * E.g.:
 * AS49450 - Federal State Budget Institution NATIONAL MEDICAL RESEARCH CENTER FOR OBSTETRICS, GYNECOLOGY
 *           AND PERINATOLOGY named after academician V. I. Kulakov of the Ministry of Healthcare of
 *           the Russian Federation,   214 bytes
 */
#define ASN_MAX_NAME 250

struct _loc_network {      /* Scraped from network.c */
       struct loc_ctx *ctx;
       int             refcount;
       int             family;
       struct in6_addr first_address;
       struct in6_addr last_address;
       unsigned int    prefix;
       char            country_code[3];
       uint32_t        asn;
       int             flags;
     };

int ASN_libloc_print (const struct in_addr *ip4, const struct in6_addr *ip6) //, BOOL from_dump_c)
{
  struct loc_network *net;
  struct loc_as      *as = NULL;
  struct in6_addr     addr;
  char  *net_name;
  char   addr_str [MAX_IP6_SZ+1];
  char   AS_name [ASN_MAX_NAME] = "<unknown>";
  int    r, save;
  DWORD  AS_num;
  BOOL   is_anycast, is_anon_proxy, sat_provider;

  if (!libloc_data.db || libloc_data.num_AS == 0)
  {
    TRACE (2, "LIBLOC is not initialised.\n");
    return (0);
  }
  if (!INET_util_addr_is_global(ip4, ip6))
  {
    TRACE (2, "Address is not global.\n");
    return (0);
  }

  if (ip4) /* Convert to IPv6-mapped address */
  {
    memcpy (&addr, &_in6addr_v4mappedprefix, sizeof(_in6addr_v4mappedprefix));
    *(DWORD*) &addr.s6_words[6] = ip4->s_addr;
    _wsock_trace_inet_ntop (AF_INET6, &addr, addr_str, sizeof(addr_str), NULL);
  }
  else if (ip6)
  {
    memcpy (&addr, ip6, sizeof(addr));
    _wsock_trace_inet_ntop (AF_INET6, &addr, addr_str, sizeof(addr_str), NULL);
  }
  else
    return (0);

  TRACE (2, "Looking up: %s.\n", addr_str);

  /* Do not trace 'inet_pton()' inside libloc
   */
  save = g_cfg.trace_level;
  g_cfg.trace_level = 0;

  r = loc_database_lookup (libloc_data.db, &addr, &net);
  if (r || !net)
  {
    g_cfg.trace_level = save;
    TRACE (1, "Invalid address: %s, err: %d/%s.\n", addr_str, -r, strerror(-r));
    return (0);
  }

#if USE_LOC_NETWORK_STR
  net_name = loc_network_str (net);
#else
  {
    const struct _loc_network *_net = (const struct _loc_network*) net;
    char _prefix_str [10];
    char _net_name [MAX_IP6_SZ+1+3];
    int  _prefix = _net->prefix;

    if (ip4)
       _prefix -= 96;

    _wsock_trace_inet_ntop (AF_INET6, &_net->first_address, _net_name, sizeof(_net_name), NULL);
    strcat (_net_name, "/");
    strcat (_net_name, _itoa(_prefix, _prefix_str, 10));

    if (ip4)
         net_name = _net_name + strlen("::ffff:");
    else net_name = _net_name;
  }
#endif

  AS_num = loc_network_get_asn (net);

  g_cfg.trace_level = save;

  is_anycast    = (loc_network_has_flag (net, LOC_NETWORK_FLAG_ANYCAST) != 0);
  is_anon_proxy = (loc_network_has_flag (net, LOC_NETWORK_FLAG_ANONYMOUS_PROXY) != 0);
  sat_provider  = (loc_network_has_flag (net, LOC_NETWORK_FLAG_SATELLITE_PROVIDER) != 0);

  if (AS_num && loc_database_get_as(libloc_data.db, &as, AS_num) == 0)
  {
#if 0 // E.g. a Teredo address like 2001::1:203:405 returns AS_num = 6939
    const char *remark = NULL;

    if (INET_util_addr_is_special (ip4, ip6, &remark))
       // ...
#endif

    _strlcpy (AS_name, loc_as_get_name(as) ? loc_as_get_name(as) : "<Unknown>", sizeof(AS_name));
    loc_as_unref (as);
  }

  trace_printf ("    ASN:    %lu, name: %s, net: %s (%d,%d,%d)",
                AS_num, AS_name, net_name, is_anycast, is_anon_proxy, sat_provider);

#if USE_LOC_NETWORK_STR
  free (net_name);
#endif

  loc_network_unref (net);
  return (1);
}

#else
static int ASN_load_bin_file (const char *file)
{
  TRACE (0, "Cannot load a binary '%s' file without 'USE_LIBLOC' defined.\n", file);
  ARGSUSED (file);
  return (0);
}

int ASN_libloc_print (const struct in_addr *ip4, const struct in6_addr *ip6)
{
  ARGSUSED (ip4);
  ARGSUSED (ip6);
  return (0);
}
#endif

/**
 * Find and print the ASN information for an IPv4 address.
 * (from a CSV file only).
 *
 * \todo
 *  Handle an IPv6 address too. <br>
 *  Dump the delegated RIR information for this record.
 */
void ASN_print (const IANA_record *iana, const struct in_addr *ip4, const struct in6_addr *ip6)
{
  const struct ASN_record *rec;

  if (ip6 || !ASN_entries || !stricmp(iana->status, "RESERVED"))
     return;

  g_num_compares = 0;
  rec = smartlist_bsearch (ASN_entries, ip4, compare_on_ip4);
  TRACE (2, "g_num_compares: %lu.\n", DWORD_CAST(g_num_compares));
  g_num_compares = 0;

  if (rec)
  {
    int i;

    printf ("\n  ASN (CSV): ");
    for (i = 0; rec->asn[i]; i++)
        printf ("%lu%s", rec->asn[i], (rec->asn[i+1] && i < DIM(rec->asn)) ? ", " : " ");
    printf ("(status: %s)\n", iana->status);
  }
}

/*
 * Handles only IPv4 addresses now.
 */
void ASN_dump (void)
{
  int i, j, num;

  if (!ASN_entries)
     return;

  num = smartlist_len (ASN_entries);
  TRACE (2, "\nParsed %s records from \"%s\":\n",
         dword_str(num), g_cfg.IANA.asn_csv_file);

  for (i = 0; i < num; i++)
  {
    const struct ASN_record *rec = smartlist_get (ASN_entries, i);
    char   low_str [MAX_IP4_SZ];
    char   high_str[MAX_IP4_SZ];

    if (_wsock_trace_inet_ntop (AF_INET, &rec->ipv4.low, low_str, sizeof(low_str), NULL) &&
        _wsock_trace_inet_ntop (AF_INET, &rec->ipv4.high, high_str, sizeof(high_str), NULL))
    {
      printf ("  %3d:  %-15.15s - %-15.15s ASN: ", i, low_str, high_str);
      for (j = 0; rec->asn[j]; j++)
          printf ("%lu%s", rec->asn[j], (rec->asn[j+1] && j < DIM(rec->asn)) ? ", " : "\n");
    }
    else
      printf ("  %3d: <bogus>\n", i);
  }
}

#ifdef TEST_IANA

#include "getopt.h"

/* For getopt.c.
 */
const char *program_name = "iana.exe";

#undef  DO_NOTHING
#define DO_NOTHING(f)  void f(void) {}

DO_NOTHING (ip2loc_init)
DO_NOTHING (ip2loc_exit)
DO_NOTHING (ip2loc_get_ipv4_entry)
DO_NOTHING (ip2loc_get_ipv6_entry)
DO_NOTHING (ip2loc_num_ipv4_entries)
DO_NOTHING (ip2loc_num_ipv6_entries)

static void usage (void)
{
  puts ("Usage: iana.exe [-d] [-a ASN-csv-file] [-b ASN-bin-file] [-m max] <ipv4-address-space.csv>\n"
        "  or   iana.exe [-d] [-a ASN-csv-file] [-b ASN-bin-file] [-m max] -6 <ipv6-unicast-address-assignments.csv>\n"
        "  option '-b' assumes the ASN-file is a binary IPFire database.\n"
        "  option '-m' stops after 'max' records.\n"
        "  both '-a' and '-b' options can be used to show both ASN-types.\n"
        "  E.g.: for \"37.142.14.15\"\n"
        "    ASN: 12849, 21450 (status: ALLOCATED)\n"
        "    ASN: 12849, name: Hot-Net internet services Ltd. (0,0,0)\n"
        );
  exit (0);
}

typedef struct TEST_ADDR {
        int      family;
        IN_ADDR  ip4;
        IN6_ADDR ip6;
      } TEST_ADDR;

int main (int argc, char **argv)
{
  struct IANA_record rec;
  static const TEST_ADDR test_addr[] = {
             { AF_INET, { 224,   0,  0,  1 } },
             { AF_INET, { 181,  10, 20, 30 } },
             { AF_INET, {   8,   8,  8,  8 } },
             { AF_INET, {   8,   8,  4,  0 } },   /* 8.8.4.0, 8.8.7.255, ASN 15169 */

             /* According to IPFire's 'python3 location lookup ::ffff:37.142.14.15':
              * Network          : 37.142.0.0/20
              * Country          : Israel
              * Autonomous System: AS12849 - Hot-Net internet services Ltd.
              */
             { AF_INET, {  37, 142, 14, 15 } },

             /* A TEREDO address
              */
             { AF_INET6, { 0 }, { 0x20, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 2, 3, 4, 5 } },

             /* Old TEREDO
              */
             { AF_INET6, { 0 }, { 0x3F, 0xFE, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 2, 3, 4, 5 } },

             /* This address is part of the block:
              *   2c00:0000::/12,AFRINIC,2006-10-03,whois.afrinic.net,"https://rdap.afrinic.net/rdap/
              */
             { AF_INET6, { 0 }, { 0x2C, 0xF0, 0xA0, 0x08 } },
             { AF_INET6, { 0 }, { 0x2C, 0xF1, 0xA0, 0x08 } }  /* 1 address above */

           };
  int i, ch, do_ip6 = 0;

  if (argc < 2)
     usage();

  while ((ch = getopt(argc, argv, "6a:b:dm:h?")) != EOF)
     switch (ch)
     {
       case '6':
            do_ip6 = 1;
            break;
       case 'a':
            g_cfg.IANA.asn_csv_file = strdup (optarg);
            break;
       case 'b':
            g_cfg.IANA.asn_bin_file = strdup (optarg);
            break;
       case 'm':
            rec_max = atoi (optarg);
            break;
       case 'd':
            g_cfg.trace_level++;
            break;
       case '?':
       case 'h':
       default:
            usage();
            break;
  }
  argv += optind;
  if (!*argv)
     usage();

  g_cfg.trace_stream = stdout;
  g_cfg.show_caller  = 1;
  g_cfg.IANA.enable  = 1;

  if (do_ip6)
       g_cfg.IANA.ip6_file = strdup (argv[0]);
  else g_cfg.IANA.ip4_file = strdup (argv[0]);

  InitializeCriticalSection (&crit_sect);
  common_init();
  iana_init();

  if (rec_illegal > 0)
     printf ("File %s does not look like a valid IPv%c assignment file.\n",
             do_ip6 ? g_cfg.IANA.ip6_file : g_cfg.IANA.ip4_file,
             do_ip6 ? '6' : '4');

  for (i = 0; i < DIM(test_addr); i++)
  {
    char ip4_buf [MAX_IP4_SZ+1];
    char ip6_buf [MAX_IP6_SZ+1];

    if (test_addr[i].family == AF_INET)
    {
      _wsock_trace_inet_ntop (AF_INET, &test_addr[i].ip4, ip4_buf, sizeof(ip4_buf), NULL);
      printf ("\ntest_ip4_address (\"%s\"):\n", ip4_buf);
      if (iana_find_by_ip4_address(&test_addr[i].ip4, &rec))
      {
        trace_printf ("  %s\n", iana_get_rec4(&rec, FALSE));
        ASN_print (&rec, &test_addr[i].ip4, NULL);
      }
      if (ASN_libloc_print(&test_addr[i].ip4, NULL))
           trace_putc ('\n');
      else trace_puts ("    ASN: <no info>\n");
    }
    else
    {
      _wsock_trace_inet_ntop (AF_INET6, &test_addr[i].ip6, ip6_buf, sizeof(ip6_buf), NULL);
      printf ("\ntest_ip6_address (\"%s\"):\n", ip6_buf);
      if (iana_find_by_ip6_address(&test_addr[i].ip6, &rec))
      {
        trace_printf ("  %s\n", iana_get_rec6(&rec, FALSE));
        ASN_print (&rec, NULL, &test_addr[i].ip6);
      }
      if (ASN_libloc_print(NULL, &test_addr[i].ip6))
           trace_putc ('\n');
      else trace_puts ("    ASN: <no info>\n");
    }
  }

  iana_exit();
  return (0);
}
#endif  /* TEST_IANA */
