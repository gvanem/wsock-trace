/**\file    asn.c
 * \ingroup ASN
 *
 * \brief
 *  Provides lookup of AS numbers (Autonomous System Number)
 *  and their name (if any). Currently it uses these methods to lookup:
 *  \li 'libloc' library from IPFire.
 *  \li 'IP2Location*ASN.csv' files from IP2Location.
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
#define USE_LIBLOC 1
#endif

#ifdef USE_LIBLOC
  #if defined(__CYGWIN__) && !defined(_WIN32)
  #define _WIN32   /* Needed in '$(LIBLOC_ROOT)/src/loc/libloc.h' only */
  #endif

  #include <loc/libloc.h>
  #include <loc/database.h>
  #include <loc/network.h>
  #include <loc/resolv.h>
  #include <loc/windows/syslog.h> /* LOG_DEBUG */

  #define LOCATION_DEFAULT_URL  "https://location.ipfire.org/databases/1/location.db.xz"
  #define SZ_OK                 0

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
  int         XZ_decompress (const char *from_file, const char *to_file);
  const char *XZ_strerror (int rc);


  static int _IN6_IS_ADDR_TEREDO (const struct in6_addr *ip6)
  {
    if (!ip6)
       return (0);
    return (ip6->s6_bytes[0] == 0x20 && ip6->s6_bytes[1] == 0x01 && ip6->s6_bytes[2] == 0x00);
  }
#endif  /* USE_LIBLOC */

/**
 * Module global variables.
 */
static u_long g_num_asn, g_num_as_names, g_num_compares;

/**
 * A smartlist of `struct ASN_record`.
 */
static smartlist_t *ASN_entries;

static BOOL   ASN_check_and_update (const char *db_file);
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
  {
    ASN_check_and_update (g_cfg.ASN.asn_bin_file);
    num_AS = ASN_load_bin_file (g_cfg.ASN.asn_bin_file);
  }

  if (g_cfg.ASN.asn_csv_file)
     num_AS += ASN_load_CSV_file (g_cfg.ASN.asn_csv_file);

  if (num_AS == 0)
     g_cfg.ASN.enable = 0;

  if (g_cfg.trace_level >= 2)
     ASN_dump();
}

/**
 * Open and parse `IP2LOCATION-*-ASN.csv` file. \n
 * This is on the format used by IP2Location. Like:
 *  "16778240","16778495","1.0.4.0/24","56203","Big Red Group"
 *   ^          ^          ^            ^       ^
 *   |          |          |            |       |___ AS-name
 *   |          |          |__ Net      |__ AS-number
 *   |          |__ end IP
 *   |_____________ start IP
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
 * Currently handles only IPv4 addresses.
 */
static int ASN_CSV_add (struct CSV_context *ctx, const char *value)
{
  static struct ASN_record rec = { 0 };
  struct ASN_record *copy;

  switch (ctx->field_num)
  {
    case 0:
         rec.ipv4.low.s_addr = swap32 ((DWORD)_atoi64(value));
         break;
    case 1:
         rec.ipv4.high.s_addr = swap32 ((DWORD)_atoi64(value));
         break;
    case 2:      /* Ignore the `a.b.c.d/prefix` field */
         break;
    case 3:
         rec.as_number = (DWORD) _atoi64 (value);
         break;
    case 4:
         copy = malloc (sizeof(*copy));
         if (copy)
         {
           memcpy (&copy->ipv4, &rec.ipv4, sizeof(copy->ipv4));
           copy->as_number = rec.as_number;
           copy->prefix = 32 - INET_util_network_len32 (copy->ipv4.high.s_addr, copy->ipv4.low.s_addr);
           copy->family = AF_INET;
           _strlcpy (copy->as_name, value, sizeof(copy->as_name));
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
 * Return the user-defined URL for the 'location.db.xz' file
 * or the default URL.
 */
static const char *ASN_get_url (void)
{
  const char *default_url = LOCATION_DEFAULT_URL;
  const char *url = g_cfg.ASN.asn_bin_url;

  if (!url)
     url = default_url;
  return (url);
}

/**
 * Check if a temporary `%TEMP%/location.db.xz` file exists.
 * Otherwise download and decompress it to `%TEMP%/location.db`.
 *
 * Then compare the file-time of `%TEMP%/location.db` with the final `.db`
 * file specified by caller. If the latter is too old; the time-difference is
 * `>= g_cfg.ASN.max_days`, copy over the temporary .db-file to the `.db`
 * specified  by `db_file`.
 */
static BOOL ASN_check_and_update (const char *db_file)
{
  struct stat st;
  char   db_xz_temp_file [MAX_PATH];
  char   db_temp_file [MAX_PATH];
  time_t now, expiry, when;
  time_t db_time, db_temp_time;
  DWORD  db_xz_temp_size = 0;
  BOOL   need_update = FALSE;
  char  *db_dir = NULL;

  if (g_cfg.from_dll_main)
  {
    TRACE (1, "Not safe to enter here from 'DllMain()'.\n");
    return (FALSE);
  }

  if (g_cfg.ASN.xz_decompress <= 0)
  {
    TRACE (1, "Nothing to do for '%s' file with XZ-decompression disabled.\n", db_file);
    return (FALSE);
  }

  db_dir = dirname (db_file);
  if (!db_dir || !file_exists(db_dir))
  {
    TRACE (1, "Directory '%s' does not exist.\n", db_dir);
    free (db_dir);
    return (FALSE);
  }

  free (db_dir);
  snprintf (db_temp_file, sizeof(db_temp_file)-3, "%s\\%s", getenv("TEMP"), "location.db");
  strcpy (db_xz_temp_file, db_temp_file);
  strcat (db_xz_temp_file, ".xz");

  memset (&st, '\0', sizeof(st));
  stat (db_temp_file, &st);
  if (st.st_size == 0)
     need_update = TRUE;

  now = time (NULL);
  expiry = now - g_cfg.ASN.max_days * 24 * 3600;
  expiry -= 10;   /* Give a 10 sec time slack */

  memset (&st, '\0', sizeof(st));
  stat (db_file, &st);
  db_time = st.st_mtime;

  /* 'db_file' exists and is not too old.
   */
  if (db_time && db_time > expiry)
  {
    when = now + g_cfg.ASN.max_days * 24 * 3600;
    TRACE (2, "Update of \"%s\" not needed until \"%.24s\"\n", db_file, ctime(&when));
    return (FALSE);
  }

  need_update = TRUE;

  memset (&st, '\0', sizeof(st));
  stat (db_xz_temp_file, &st);
  db_xz_temp_size = st.st_size;

  /* `%TEMP%/location.db.xz` not found or is 0 bytes.
   * Force a download.
   */
  if (db_xz_temp_size == 0)
  {
    db_xz_temp_size = INET_util_download_file (db_xz_temp_file, ASN_get_url());
    TRACE (1, "Downloaded '%s' -> '%s'. %s\n",
           ASN_get_url(), db_xz_temp_file, db_xz_temp_size > 0 ? "OK" : "Failed");

    if (db_xz_temp_size == 0)
       return (FALSE);
  }

  memset (&st, '\0', sizeof(st));
  stat (db_temp_file, &st);
  db_temp_time = st.st_mtime;
  if (db_temp_time && db_time && db_temp_time == db_time)
     need_update = FALSE;

  /* `%TEMP%/location.db` not found or is 0 bytes. Or 'db_file' is too old.
   * Force a XZ-decompress and copy.
   */
  if (need_update)
  {
    unsigned rc = XZ_decompress (db_xz_temp_file, db_temp_file);

    TRACE (1, "XZ_decompress(): rc: %d/%s\n", rc, XZ_strerror(rc));

    if (rc == SZ_OK)
    {
      INET_util_touch_file (db_xz_temp_file);
      INET_util_touch_file (db_temp_file);

      memset (&st, '\0', sizeof(st));
      stat (db_temp_file, &st);

      TRACE (1, "Compressed: %s bytes. Uncompressed %s bytes.\n",
             dword_str(db_xz_temp_size), dword_str(st.st_size));

      rc = (BOOL) CopyFile (db_temp_file, db_file, FALSE);
      TRACE (2, "CopyFile(): rc: %d, %s -> %s\n", rc, db_temp_file, db_file);
      INET_util_touch_file (db_file);
    }
    return (TRUE);
  }
  return (FALSE);
}

/**
 * Check for latest version of the `libloc` database
 * using a `TXT _v1._db.location.ipfire.org` DNS query.
 */
static int ASN_check_database (const char *local_db)
{
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

  if (stat(local_db, &st) == 0)
  {
    time_local_db = st.st_mtime - _timezone;
    older = (time_local_db < time_remote_db);
    if (older)
       snprintf (hours_behind, sizeof(hours_behind), " (%ld hours behind) ",
                 (long)((time_remote_db - time_local_db) / 3600));
  }

  TRACE (1, "IPFire's latest database time-stamp: %.24s (UTC)\n"
            "            It should be at: %s\n"
            "            Your local database is %sup-to-date.%s\n",
            ctime(&time_remote_db), ASN_get_url(), older ? "not " : "", hours_behind);

  time_local_db += _timezone;
  TRACE (1, "local time-stamp: %.24s (%s)\n", ctime(&time_local_db), _tzname[0]);
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

  /* Do not trace 'WSAStartup()' inside libloc's 'loc_new()' in case
   * "Geo-IP/IPFile/src/fake-OpenSSL/openssl/applink.c" was not included somehow.
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
    rc = 1;
  }
  else
  {
    TRACE (2, "No data for AS%u, err: %d/%s.\n", AS_num, -rc, strerror(-rc));
    AS_name = "<unknown>";
    rc = 0;
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
  if (ASN_entries)
  {
    const struct ASN_record *asn;

    g_num_compares = 0;
    asn = smartlist_bsearch (ASN_entries, &rec, ASN_compare_on_net);
    if (asn)
       rc = libloc_handle_net (NULL, asn, ip4, ip6);
  }
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

#else   /* !USE_LIBLOC */
static size_t ASN_load_bin_file (const char *file)
{
  TRACE (1, "Sorry, OpenWatcom is not supported; cannot load database '%s' file.\n", file);
  ARGSUSED (file);
  return (0);
}

static BOOL ASN_check_and_update (const char *file)
{
  TRACE (1, "Sorry, OpenWatcom is not supported; cannot update database '%s' file automatically.\n", file);
  ARGSUSED (file);
  return (FALSE);
}

int ASN_libloc_print (const char *intro, const struct in_addr *ip4, const struct in6_addr *ip6)
{
  ARGSUSED (intro);
  ARGSUSED (ip4);
  ARGSUSED (ip6);
  return (0);
}
#endif  /* USE_LIBLOC */

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
  else trace_printf ("%lu, %s (status: %s)\n",
                     rec->as_number, rec->as_name[0] ? rec->as_name : "<unknown>" ,
                     iana->status);
}

/*
 * Handles only IPv4 addresses now.
 */
void ASN_dump (void)
{
  int i, num;

  if (!ASN_entries)
     return;

  num = smartlist_len (ASN_entries);
  TRACE (2,
        "\nParsed %s records from \"%s\":\n"
        "  Num.  Low              High             Pfx     ASN  Name\n"
        "-------------------------------------------------------------------\n",
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
      trace_printf ("%6lu  %s\n", rec->as_number, rec->as_name);
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

/**
 * The code for `XZ_decompress()` is included below for easy building.
 */
#ifdef USE_LIBLOC
  #define INCLUDED_FROM_WSOCK_TRACE
  #if 0
    #define CONFIG_PROB32
    #define CONFIG_SIZE_OPT
    #define CONFIG_DEBUG
  #endif

  #define RINOK(x)  do {                                  \
                      unsigned  _res = x;                 \
                      if (_res != 0) {                    \
                         TRACE (1, "RINOK() -> %u/%s.\n", \
                                _res, XZ_strerror(_res)); \
                         return (_res);                   \
                      }                                   \
                    } while (0)

  #include "xz_decompress.c"
#endif
