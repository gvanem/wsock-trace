/**\file    asn.c
 * \ingroup ASN
 *
 * \brief
 *
 * asn.c - Part of Wsock-Trace.
 */
#include "common.h"
#include "csv.h"
#include "smartlist.h"
#include "inet_util.h"
#include "in_addr.h"
#include "init.h"
#include "iana.h"
#include "asn.h"

#if !defined(__WATCOMC__)
#define USE_LIBLOC
#endif

#ifdef USE_LIBLOC
  #if defined(__CYGWIN__) && !defined(_WIN32)
  #define _WIN32
  #endif

  #include <loc/libloc.h>
  #include <loc/database.h>
  #include <loc/network.h>
  #include <loc/resolv.h>

  #if defined(__CYGWIN__)
    #include <syslog.h>     /* LOG_DEBUG */
  #else
    #include <loc/windows/syslog.h>
  #endif

  /*
   * Ignore some MinGW/gcc warnings below.
   */
  #if defined(__MINGW32__)
    #pragma GCC diagnostic ignored  "-Wformat"             /* does not understand '%zu'! */
    #pragma GCC diagnostic ignored  "-Wformat-extra-args"  /* ditto */
  #endif

  #if defined(__GNUC__)
    #pragma GCC diagnostic ignored  "-Wstrict-aliasing"
    #pragma GCC diagnostic ignored  "-Wmissing-braces"
  #endif

  struct libloc_data {
         struct loc_ctx      *ctx;
         struct loc_database *db;
         FILE                *file;
         size_t               num_AS;
       };
  struct libloc_data libloc;

  struct _loc_network {   /* Scraped from '$(LIBLOC_ROOT)/src/network.c' */
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

  static void ASN_bin_close (void);

  static int _IN6_IS_ADDR_TEREDO (const struct in6_addr *ip6)
  {
    if (!ip6)
       return (0);
    return (ip6->s6_bytes[0] == 0x20 && ip6->s6_bytes[1] == 0x01 && ip6->s6_bytes[2] == 0x00);
  }
#endif

/**
 * Module global variables.
 */
static u_long g_num_asn, g_num_as_names, g_num_compares;

/**
 * A smartlist of `struct ASN_record`.
 */
static smartlist_t *ASN_entries;

static size_t ASN_load_bin_file (const char *file);
static size_t ASN_load_CSV_file (const char *file);
static int    ASN_CSV_add (struct CSV_context *ctx, const char *value);

/**
 * The main init function for this module.
 * Normally called from `wsock_trace_init()`.
 */
void ASN_init (void)
{
  size_t num_AS = 0;

  if (!g_cfg.ASN.enable)
     return;

  if (g_cfg.ASN.asn_bin_file)
     num_AS = ASN_load_bin_file (g_cfg.ASN.asn_bin_file);

  if (g_cfg.ASN.asn_csv_file)
     num_AS += ASN_load_CSV_file (g_cfg.ASN.asn_csv_file);

  if (num_AS == 0)
     g_cfg.ASN.enable = 0;

  if (g_cfg.trace_level >= 2)
     ASN_dump();
}

/**
 * Open and parse `GeoIPASNum.csv` file. \n
 * This must be generated using "Blockfinder" and
 * `python2 blockfinder --export`.
 *
 * \param[in] file  the CSV file to read and parse.
 *
 * \note The `ASN_entries` is *not* sorted on IPv4 low/high range since
 *       the .CSV-file the records are read from, is assumed to be sorted.
 */
static size_t ASN_load_CSV_file (const char *file)
{
  struct CSV_context ctx;

  assert (ASN_entries == NULL);
  ASN_entries = smartlist_new();
  if (!ASN_entries)
      return (0);

  if (!file_exists(file))
  {
    TRACE (1, "ASN file \"%s\" does not exist.\n", file);
    return (0);
  }

  memset (&ctx, '\0', sizeof(ctx));
  ctx.file_name  = file;
  ctx.num_fields = 5;
  ctx.callback   = ASN_CSV_add;

  return CSV_open_and_parse_file (&ctx);
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
    {
      rec->asn[i++] = (DWORD) _atoi64 (v);
      if (i == DIM(rec->asn))    /* Room for "only" 8 ASN */
         break;
    }
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
           copy->prefix = INET_util_network_len32 (copy->ipv4.high.s_addr, copy->ipv4.low.s_addr);
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
static int ASN_compare_on_ip4 (const void *key, const void **member)
{
  const struct ASN_record *rec = *member;
  struct in_addr ipv4;

  g_num_compares++;
  ipv4.s_addr = *(const u_long*) key;

  return INET_util_range4cmp (&ipv4, &rec->ipv4.low, rec->prefix);
}

#ifdef USE_LIBLOC
/**
 * Close the use of `libloc`.
 */
static void ASN_bin_close (void)
{
  if (libloc.db)
     loc_database_unref (libloc.db);

  if (libloc.ctx)
     loc_unref (libloc.ctx);

  if (libloc.file)
     fclose (libloc.file);

  memset (&libloc, '\0', sizeof(libloc));
}

/**
 * Check for latest version of the `libloc` database.
 */
static int ASN_check_database (const char *local_db)
{
  const char *default_url = "https://location.ipfire.org/databases/1/location.db.xz";
  const char *url = g_cfg.ASN.asn_bin_url;
  struct stat st;
  time_t time_local_db = 0;
  time_t time_remote_db = 0;
  BOOL   older = FALSE;
  char   hours_behind [50] = "";

  if (loc_discover_latest_version(libloc.ctx, LOC_DATABASE_VERSION_LATEST, &time_remote_db) != 0)
  {
    TRACE (1, "Could not check IPFire's database time-stamp.\n");
    return (0);
  }

  time_remote_db -= _timezone;
  if (stat(local_db, &st) == 0)
  {
    time_local_db = st.st_mtime;
    older = (time_local_db < time_remote_db);
    if (older)
       snprintf (hours_behind, sizeof(hours_behind), " (%ld hours behind) ",
                 (long)((time_remote_db - time_local_db) / 3600));
  }

  if (!url)
     url = default_url;

  TRACE (1, "IPFire's latest database time-stamp: %.24s (UTC)\n"
            "            It should be at: %s\n"
            "            Your local database is %sup-to-date.%s\n",
            ctime(&time_remote_db), url, older ? "not " : "", hours_behind);
  return (1);
}

static size_t ASN_load_bin_file (const char *file)
{
  const char *descr, *licence, *vendor;
  size_t      len, num_AS;
  time_t      created;
  int         err, save;

  memset (&libloc, '\0', sizeof(libloc)); // should be un-needed

  if (!file || !file_exists(file))
  {
    TRACE (1, "file \"%s\" does not exist.\n", file);
    return (0);
  }

  TRACE (2, "Trying to open IPFire's database: \"%s\".\n", file);
  libloc.file = fopen_excl (file, "rb");
  if (!libloc.file)
  {
    TRACE (1, "Could not open IPFire's binary database: %s\n", strerror(errno));
    return (0);
  }

  /* Do not trace 'WSAStartup()' inside libloc's 'loc_new()'.
   */
  save = g_cfg.trace_level;
  g_cfg.trace_level = 0;
  err = loc_new (&libloc.ctx);
  g_cfg.trace_level = save;

  if (err < 0)
  {
    TRACE (1, "Cannot create libloc context; %s.\n", strerror(-err));
    ASN_bin_close();
    return (0);
  }

  loc_set_log_priority (libloc.ctx, g_cfg.trace_level >= 2 ? LOG_DEBUG : 0);

  if (g_cfg.trace_level == 0)
     _ws_setenv ("LOC_LOG", "", 1);  /* Clear the 'libloc' internal trace-level */

  if (g_cfg.trace_level >= 2 || getenv("APPVEYOR_BUILD_NUMBER"))
     ASN_check_database (file);

  err = loc_database_new (libloc.ctx, &libloc.db, libloc.file);
  if (err)
  {
    TRACE (1, "Could not open database: %s\n", strerror(-err));
    ASN_bin_close();
    return (0);
  }

  /* No need to keep the file open
   */
  fclose (libloc.file);
  libloc.file = NULL;

  descr   = loc_database_get_description (libloc.db);
  licence = loc_database_get_license (libloc.db);
  vendor  = loc_database_get_vendor (libloc.db);
  num_AS  = loc_database_count_as (libloc.db);
  created = loc_database_created_at (libloc.db);

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
  TRACE (2, "\n  Description: %.*s\n"
            "  Licence:     %s\n"
            "  Vendor:      %s\n"
            "  Created:     %.24s\n"
            "  num_AS:      %zu\n\n",
         (int)len, descr, licence, vendor, ctime(&created), num_AS);
  libloc.num_AS = num_AS;
  return (num_AS);
}

/**
 * \def ASN_MAX_NAME
 * Maximum length of an ASN-name, which can be quite long.
 * E.g.:
 * AS49450 - Federal State Budget Institution NATIONAL MEDICAL RESEARCH CENTER FOR OBSTETRICS, GYNECOLOGY
 *           AND PERINATOLOGY named after academician V. I. Kulakov of the Ministry of Healthcare of
 *           the Russian Federation,   214 bytes
 */
#define ASN_MAX_NAME 250

/**
 * Internal functoion called from `ASN_libloc_print()`.
 */
static int libloc_handle_net (struct loc_network    *net,
                              const struct in_addr  *ip4,
                              const struct in6_addr *ip6)
{
  struct loc_as       *as = NULL;
  struct _loc_network *_net = (struct _loc_network*) net;
  char                 _prefix_str [10];
  char                 _net_name [MAX_IP6_SZ+1+4];
  int                  _prefix = _net->prefix;
  const char          *net_name;
  const char          *remark;
  const char          *AS_name;
  char                 attributes [100] = "";
  int                  rc = 0;
  uint32_t             AS_num;
  BOOL                 is_anycast, is_anon_proxy, sat_provider; //, is_tor_exit /* some day */ ;

  if (ip4)
     _prefix -= 96;

  _wsock_trace_inet_ntop (AF_INET6, &_net->first_address, _net_name, sizeof(_net_name), NULL);
  strcat (_net_name, "/");
  strcat (_net_name, _itoa(_prefix, _prefix_str, 10));

  if (ip4)
       net_name = _net_name + strlen("::ffff:");
  else net_name = _net_name;

  AS_num = loc_network_get_asn (net);

  is_anycast    = (loc_network_has_flag (net, LOC_NETWORK_FLAG_ANYCAST) != 0);
  is_anon_proxy = (loc_network_has_flag (net, LOC_NETWORK_FLAG_ANONYMOUS_PROXY) != 0);
  sat_provider  = (loc_network_has_flag (net, LOC_NETWORK_FLAG_SATELLITE_PROVIDER) != 0);
//is_tor_exit   = (loc_network_has_flag (net, LOC_NETWORK_FLAG_TOR_EXIT) != 0);

  /* Since a Teredo address is valid here, maybe other blocks have an AS_num too?
   */
  INET_util_addr_is_special (ip4, ip6, &remark);

  if (AS_num > 0)
  {
    g_num_asn++;   /**< \todo This should be a count of unique ASN */
    rc = loc_database_get_as (libloc.db, &as, AS_num);
  }

  if (rc == 0 && as)
  {
    AS_name = as ? loc_as_get_name (as) : NULL;
    if (!AS_name)
         AS_name = "<Unknown>";
    else g_num_as_names++;   /**< \todo This should be a count of unique AS-names */
  }
  else
  {
    TRACE (2, "No data for AS%u, err: %d/%s.\n", AS_num, -rc, strerror(-rc));
    AS_name = "<unknown>";
  }

  if (remark)
  {
    strcat (attributes, ", ");
    strcat (attributes, remark);
  }

  if (is_anycast)
     strcat (attributes, ", Anycast");
  if (is_anon_proxy)
     strcat (attributes, ", Anonymous Proxy");
  if (sat_provider)
     strcat (attributes, ", Satellite Provider");

  trace_printf ("%u, name: %.*s, net: %s%s\n", AS_num, ASN_MAX_NAME-30, AS_name, net_name, attributes);

  if (as)
     loc_as_unref (as);
  rc = 1;

  return (rc);
}

static const IN6_ADDR _in6addr_v4mappedprefix = {{
       0,0,0,0,0,0,0,0,0,0,0xFF,0xFF,0,0,0,0
     }};

/**
 * Print ASN information for an IPv4 or IPv6 address.
 *
 * Simlator to wahat the IPFire script does:
 * c:\> py -3 location.py lookup ::ffff:45.150.206.231
 *   Network:           45.150.206.0/23
 *   Autonomous System: AS35029 - WebLine LTD
 *   Anonymous Proxy:   yes
 *
 * for an IPv4 address we must map `ip4` to an IPv4-mapped first:
 * `45.150.206.231`  -> `::ffff:45.150.206.231`)
 *
 * This function does nothing for top-level networks like from IANA, RIPE etc.
 * 'libloc' only have information on RIRs (Regional Internet Registries).
 *
 * \todo
 *  Create a cache for this since calling `loc_database_lookup()` can
 *  sometimes be slow.
 */
int ASN_libloc_print (const char *intro, const struct in_addr *ip4, const struct in6_addr *ip6)
{
  struct loc_network *net = NULL;
  struct in6_addr     addr;
  char                addr_str [MAX_IP6_SZ+1];
  int                 rc, save, err_save;

  if (!libloc.db)
  {
    TRACE (2, "LIBLOC is not initialised.\n");
    return (0);
  }
  if (libloc.num_AS == 0)
  {
    TRACE (2, "LIBLOC has no AS-info!\n");
    return (0);
  }
  if (!_IN6_IS_ADDR_TEREDO(ip6) &&  /* since a Terodo can have an AS-number assigned */
      !INET_util_addr_is_global(ip4, ip6))
  {
    trace_printf ("%s<not global>\n", intro);
    return (0);
  }

  if (ip4) /* Convert to IPv6-mapped address */
  {
    memcpy (&addr, &_in6addr_v4mappedprefix, sizeof(_in6addr_v4mappedprefix));
    *(u_long*) &addr.s6_words[6] = ip4->s_addr;
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

  /* Do not trace 'inet_pton()' inside libloc or \WSAGetLastError()' below.
   */
  save = g_cfg.trace_level;
  g_cfg.trace_level = 0;

  /* Save WSA error-status since loc_database_lookup() could set it.
   */
  err_save = WSAGetLastError();

  trace_puts (intro);

#if 0
   /**
    * \todo Search the cached ASN-list first (sorted on net?)
    */
   g_num_compares = 0;
   const struct ASN_record *asn = smartlist_bsearch (ASN_entries, &rec, ASN_compare_on_net);
   if (asn)
      rc = libloc_handle_net (NULL, asn, ip4, ip6);
   else
#endif

  rc = loc_database_lookup (libloc.db, &addr, &net);
  if (rc == 0 && net)
  {
    rc = libloc_handle_net (net, ip4, ip6);
    loc_network_unref (net);
  }
  else
  {
    trace_puts ("<no info>\n");
    TRACE (2, "No data for address: %s, err: %d/%s.\n", addr_str, -rc, strerror(-rc));
    rc = 0;
  }

#if 0
  /**
   * \todo
   * Add this to the ASN-list (sorted on net?)
   * Add negative lookups also; no `net` or `AS_num` found.
   */
  smartlist_insert (ASN_entries, at_sorted_pos, copy);
#endif

  /* Restore WSA-error and trace-level
   */
  WSASetLastError (err_save);
  g_cfg.trace_level = save;
  return (rc);
}

#else
static size_t ASN_load_bin_file (const char *file)
{
  TRACE (1, "Cannot load a binary '%s' file without 'USE_LIBLOC' defined.\n", file);
  ARGSUSED (file);
  return (0);
}

int ASN_libloc_print (const char *intro, const struct in_addr *ip4, const struct in6_addr *ip6)
{
  ARGSUSED (intro);
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
void ASN_print (const char *intro, const struct IANA_record *iana, const struct in_addr *ip4, const struct in6_addr *ip6)
{
  const struct ASN_record *rec;
  int   i;

  if (ip6 || !ASN_entries)
     return;

  trace_puts (intro);
  if (!stricmp(iana->status, "RESERVED"))
  {
    trace_puts ("<reserved>\n");
    return;
  }

  g_num_compares = 0;
  rec = smartlist_bsearch (ASN_entries, ip4, ASN_compare_on_ip4);
  TRACE (2, "g_num_compares: %lu.\n", g_num_compares);

  if (!rec)
     trace_puts ("<no data>\n");
  else
  {
    for (i = 0; rec->asn[i]; i++)
        trace_printf ("%lu%s", rec->asn[i], (rec->asn[i+1] && i < DIM(rec->asn)) ? ", " : " ");
    trace_printf ("(status: %s)\n", iana->status);
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
  TRACE (2,
        "\nParsed %s records from \"%s\":\n"
        "  Num.  Low              High             Pfx  ASN\n"
        "----------------------------------------------------\n",
         dword_str(num), g_cfg.ASN.asn_csv_file);

  for (i = 0; i < num; i++)
  {
    const struct ASN_record *rec = smartlist_get (ASN_entries, i);
    char  low_str [MAX_IP4_SZ];
    char  high_str[MAX_IP4_SZ];

    if (_wsock_trace_inet_ntop (AF_INET, &rec->ipv4.low, low_str, sizeof(low_str), NULL) &&
        _wsock_trace_inet_ntop (AF_INET, &rec->ipv4.high, high_str, sizeof(high_str), NULL))
    {
      trace_printf ("  %3d:  %-14.14s - %-14.14s    %2d  ", i, low_str, high_str, rec->prefix);
      for (j = 0; j < DIM(rec->asn) && rec->asn[j]; j++)
          trace_printf ("%lu%s", rec->asn[j], (rec->asn[j+1] && j < DIM(rec->asn)) ? ", " : "\n");
    }
    else
      trace_printf ("  %3d: <bogus>\n", i);
  }
}

/**
 * Free memory allocated here. <br>
 * Normally called from `wsock_trace_exit()`.
 */
void ASN_exit (void)
{
  if (ASN_entries)
     smartlist_wipe (ASN_entries, free);

#ifdef USE_LIBLOC
  ASN_bin_close();
#endif

  ASN_entries = NULL;
  free (g_cfg.ASN.asn_csv_file);
  free (g_cfg.ASN.asn_bin_file);
  free (g_cfg.ASN.asn_bin_url);
}

/**
 * \todo
 * Collect some statistics on AS-numbers etc. discovered and print that information here.
 */
void ASN_report (void)
{
  trace_printf ("\n  ASN statistics:\n"
                "    Got %lu ASN-numbers, %lu AS-names.\n", g_num_asn, g_num_as_names);
}

