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

#ifdef TEST_IANA
  static unsigned  rec_max = UINT_MAX;
#endif

static smartlist_t *iana_entries_ip4;
static smartlist_t *iana_entries_ip6;

static void iana_sort_lists (void);
static void iana_load_and_parse (int family, const char *file);
static int  iana_add_entry (const struct IANA_record *rec);
static int  iana_CSV_add4 (struct CSV_context *ctx, const char *value);
static int  iana_CSV_add6 (struct CSV_context *ctx, const char *value);

/**
 * The main init function for this module.
 * Normally called from `wsock_trace_init()`.
 */
void iana_init (void)
{
  if (!g_cfg.IANA.enable)
     return;

  iana_load_and_parse (AF_INET, g_cfg.IANA.ip4_file);
  iana_load_and_parse (AF_INET6, g_cfg.IANA.ip6_file);
  iana_sort_lists();

  if ((!iana_entries_ip4 || smartlist_len(iana_entries_ip4) == 0) &&
      (!iana_entries_ip6 || smartlist_len(iana_entries_ip6) == 0))
     g_cfg.IANA.enable = FALSE;

  if (g_cfg.trace_level >= 2)
     iana_dump();
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

  _wsock_trace_inet_ntop (AF_INET6, (const u_char*)&rec->net_num.ip6, ip6_buf1, sizeof(ip6_buf1));
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

  iana_entries_ip4 = NULL;
  free (g_cfg.IANA.ip4_file);
  free (g_cfg.IANA.ip6_file);
}

/**
 * \todo
 * Collect some statistics on net blocks discovered and print that information here.
 */
void iana_report (void)
{
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
  static struct IANA_record rec;
  int    rc = 1;

  if (ctx->field_num == 0)
     sscanf (value, "%lu/%d", (unsigned long*)&rec.net_num.ip4.s_addr, &rec.mask);

  else if (ctx->field_num == 1)
     _strlcpy (rec.misc, value, sizeof(rec.misc));

  else if (ctx->field_num == 2)
    _strlcpy (rec.date, value, sizeof(rec.date));

  else if (ctx->field_num == 3)
     _strlcpy (rec.whois, value, sizeof(rec.whois));

  else if (ctx->field_num == 4)
  {
    char *space;

    _strlcpy (rec.url, value, sizeof(rec.url));
    space = strchr (rec.url, ' ');
    if (space)
       *space = '\0';
  }
  else if (ctx->field_num == 5)
     _strlcpy (rec.status, value, sizeof(rec.status));

  else if (ctx->field_num == 6)   /* The value in this 'NOTE' field is ignored */
  {
    rec.family = AF_INET;
    rc = iana_add_entry (&rec);
    memset (&rec, '\0', sizeof(rec));    /* Ready for a new record. */
    rec.family = rec.mask = -1;
    rec.net_num.ip4.s_addr = INADDR_NONE;
  }
  return (rc);
}

/**
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
  static struct IANA_record rec;
  static char   ip6_addr [MAX_IP6_SZ+1];
  int    rc = 1;

  if (ctx->field_num == 0)
  {
    sscanf (value, "%50[^/]/%d", ip6_addr, &rec.mask);
    wsock_trace_inet_pton6 (ip6_addr, (u_char*)&rec.net_num.ip6);
  }
  else if (ctx->field_num == 1)
     _strlcpy (rec.misc, value, sizeof(rec.misc));

  else if (ctx->field_num == 2)
    _strlcpy (rec.date, value, sizeof(rec.date));

  else if (ctx->field_num == 3)
     _strlcpy (rec.whois, value, sizeof(rec.whois));

  else if (ctx->field_num == 4)
  {
    char *space;

    _strlcpy (rec.url, value, sizeof(rec.url));
    space = strchr (rec.url, ' ');
    if (space)
       *space = '\0';
  }
  else if (ctx->field_num == 5)
     _strlcpy (rec.status, value, sizeof(rec.status));

  else if (ctx->field_num == 6)   /* The value in this 'NOTE' field is ignored */
  {
    rec.family = AF_INET6;
    rc = iana_add_entry (&rec);
    memset (&rec, '\0', sizeof(rec));    /* Ready for a new record. */
    rec.family = rec.mask = -1;
    memset (&rec.net_num.ip6, '\0', sizeof(rec.net_num.ip6)); /* IN6_IS_ADDR_UNSPECIFIED() */
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
  _wsock_trace_inet_ntop (AF_INET, (const u_char*)ip4, ip4_buf, sizeof(ip4_buf));

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

  _wsock_trace_inet_ntop (AF_INET6, (const u_char*)&rec->net_num.ip6, net6_buf, sizeof(net6_buf));
  _wsock_trace_inet_ntop (AF_INET6, (const u_char*)ip6, ip6_buf, sizeof(ip6_buf));

  TRACE (2, "key: %s, net_num: %-12s prefix: %2d mask: %-12s rc: %d\n",
         ip6_buf, net6_buf, rec->mask, INET_util_in6_mask_str(&mask), rc);
  return (rc);
}

/**
 * Sort both `iana_entries_ip4` and  `iana_entries_ip6` smart-lists on
 * net-number, mask and finally on status.
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

  if (!iana_entries_ip4)
     return (0);

  g_num_compares = 0;
  rec = smartlist_bsearch (iana_entries_ip4, ip4, compare_on_netnum_prefix_ip4);

  TRACE (2, "g_num_compares: %lu.\n", DWORD_CAST(g_num_compares));
  g_num_compares = 0;

  if (rec)
  {
    *out_rec = *rec;
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
    return (1);
  }

  g_num_compares = 0;
  rec = smartlist_bsearch (iana_entries_ip6, ip6, compare_on_netnum_prefix_ip6);

  TRACE (2, "g_num_compares: %lu.\n", DWORD_CAST(g_num_compares));
  g_num_compares = 0;

  if (rec)
  {
    *out_rec = *rec;
    return (1);
  }
  return (0);
}

#ifdef TEST_IANA

#define DO_NOTHING(f)  void f(void) {}

DO_NOTHING (ip2loc_init)
DO_NOTHING (ip2loc_exit)
DO_NOTHING (ip2loc_get_ipv4_entry)
DO_NOTHING (ip2loc_get_ipv6_entry)
DO_NOTHING (ip2loc_num_ipv4_entries)
DO_NOTHING (ip2loc_num_ipv6_entries)

static int usage (void)
{
  puts ("Usage: 'iana.exe [-d] <ipv4-address-space.csv>'\n"
        "or     'iana.exe [-d] -6 <ipv6-unicast-address-assignments.csv>'");
  return (1);
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
             { AF_INET, { 224,  0,  0,  1 } },
             { AF_INET, { 181, 10, 20, 30 } },
             { AF_INET, {   8,  8,  8,  8 } },

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
  int i, do_ip6 = 0;

  if (argc < 2)
     return usage();

  if (!strcmp(argv[1], "-d"))
  {
    argc--;
    argv++;
    g_cfg.trace_level = 3;
  }
  else if (!strcmp(argv[1], "-d6"))
  {
    argc--;
    argv++;
    g_cfg.trace_level = 3;
    do_ip6 = 1;
  }
  if (!strcmp(argv[1], "-6"))
  {
    argc--;
    argv++;
    do_ip6 = 1;
  }

  g_cfg.trace_stream = stdout;
  g_cfg.show_caller  = 1;
  g_cfg.IANA.enable  = 1;

  if (do_ip6)
       g_cfg.IANA.ip6_file = strdup (argv[1]);
  else g_cfg.IANA.ip4_file = strdup (argv[1]);

// rec_max = 4;

  InitializeCriticalSection (&crit_sect);
  common_init();
  iana_init();

  for (i = 0; i < DIM(test_addr); i++)
  {
    char ip4_buf [MAX_IP4_SZ+1];
    char ip6_buf [MAX_IP6_SZ+1];

    if (test_addr[i].family == AF_INET)
    {
      wsock_trace_inet_ntop4 ((const u_char*)&test_addr[i].ip4, ip4_buf, sizeof(ip4_buf));
      printf ("\niana_find_by_ip4_address (\"%s\"):\n", ip4_buf);
      iana_find_by_ip4_address (&test_addr[i].ip4, &rec);
      printf ("  %s\n", iana_get_rec4(&rec, FALSE));
    }
    else
    {
      wsock_trace_inet_ntop6 ((const u_char*)&test_addr[i].ip6, ip6_buf, sizeof(ip6_buf));
      printf ("\niana_find_by_ip6_address (\"%s\"):\n", ip6_buf);
      iana_find_by_ip6_address (&test_addr[i].ip6, &rec);
      printf ("  %s\n", iana_get_rec6(&rec, FALSE));
    }
  }

  iana_exit();
  return (0);
}
#endif  /* TEST_IANA */
