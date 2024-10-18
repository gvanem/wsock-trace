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
#include <math.h>

#include "common.h"
#include "csv.h"
#include "getopt.h"
#include "smartlist.h"
#include "xz_decompress.h"
#include "inet_util.h"
#include "inet_addr.h"
#include "init.h"
#include "iana.h"
#include "asn.h"

#if defined(__CYGWIN__)
  #include <sys/cygwin.h>
  #include <fnmatch.h>

  #ifndef FNM_CASEFOLD
  #define FNM_CASEFOLD  0x10  /* Needs `__GNU_VISIBLE` to be set */
  #endif

  #ifndef _WIN32
  #define _WIN32   /* Needed in '$(LIBLOC_ROOT)/src/libloc/libloc.h' only */
  #endif
#endif

#include <libloc/libloc.h>
#include <libloc/database.h>
#include <libloc/network.h>
#include <libloc/resolv.h>
#include <libloc/windows/syslog.h>   /* LOG_DEBUG */

/*
 * Since 'Geo-IP/IPFire/src/libloc/version.h' is generated
 * and no longer under Git revision control, just take the
 * version numbers as in 'Geo-IP/IPFire/configure.ac':
 */
#ifndef LIBLOC_MAJOR_VER
#define LIBLOC_MAJOR_VER  0
#endif

#ifndef LIBLOC_MINOR_VER
#define LIBLOC_MINOR_VER  9
#endif

#ifndef LIBLOC_MICRO_VER
#define LIBLOC_MICRO_VER  17
#endif

#define LOCATION_DEFAULT_URL  "https://location.ipfire.org/databases/1/location.db.xz"
#define SZ_OK                 0

/*
 * Ignore some MinGW/gcc warnings below.
 */
#if defined(__MINGW32__)
  GCC_PRAGMA (GCC diagnostic ignored  "-Wformat")             /* does not understand '%zu'! */
  GCC_PRAGMA (GCC diagnostic ignored  "-Wformat-extra-args")  /* ditto */
#endif

#if defined(__GNUC__)
  GCC_PRAGMA (GCC diagnostic ignored  "-Wstrict-aliasing")
  GCC_PRAGMA (GCC diagnostic ignored  "-Wmissing-braces")
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
  {
    g_cfg.ASN.enable = false;
    ASN_bin_close();
  }
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
 *       the .CSV-records are assumed to be already sorted.
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
           str_ncpy (copy->as_name, value, sizeof(copy->as_name));
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
 * XZ-decompress and copy a file.
 *
 * \param[in]  db_xz_temp_file  The XZ-compressed file to decompress.
 * \param[in]  db_temp_file     The file to decompress to.
 * \param[in]  db_file          The final file to copy `db_temp_file` to if decompression succeeded.
 */
static void ASN_xz_decompress (const char *db_xz_temp_file, const char *db_temp_file, const char *db_file)
{
  struct stat st;
  DWORD  compr_size, uncompr_size;
  char   win_db_file [_MAX_PATH];   /* For Cygwin only */
  int    rc;

  rc = XZ_decompress (db_xz_temp_file, db_temp_file);
  TRACE (1, "XZ_decompress(): rc: %d/%s\n", rc, XZ_strerror(rc));
  if (rc != SZ_OK)
     return;

  INET_util_touch_file (db_xz_temp_file);
  INET_util_touch_file (db_temp_file);

  memset (&st, '\0', sizeof(st));
  stat (db_xz_temp_file, &st);
  compr_size = st.st_size;

  memset (&st, '\0', sizeof(st));
  stat (db_temp_file, &st);
  uncompr_size = st.st_size;

  TRACE (1, "Compressed: %s bytes. Uncompressed %s bytes.\n", dword_str(compr_size), dword_str(uncompr_size));

#ifdef __CYGWIN__
  /*
   * Since 'CopyFile()' does not understand a POSIX-path like
   * "/cygdrive/c/TEMP/wsock_trace\\location.db" or "/c/TEMP/wsock_trace\\location.db".
   * Just try to convert to Windows-form.
   */
  if (cygwin_conv_path (CCP_POSIX_TO_WIN_A, db_temp_file, win_db_file, sizeof(win_db_file)) == 0)
  {
    TRACE (1, "cygwin_conv_path(): %s -> %s.\n", db_temp_file, win_db_file);
    db_temp_file = win_db_file;
  }
#else
   ARGSUSED (win_db_file);
#endif

  /* The `CopyFile()` fails if `db_file` is open.
   */
  if (!CopyFile(db_temp_file, db_file, FALSE))
       TRACE (1, "CopyFile(): %s -> %s failed: %s\n", db_temp_file, db_file, win_strerror(GetLastError()));
  else TRACE (1, "CopyFile(): %s -> %s OK\n", db_temp_file, db_file);
}

/**
 * Check if a temporary `%TEMP%/wsock_trace/location.db.xz` file exists.
 * Otherwise download and decompress it to `%TEMP%/wsock_trace/location.db`.
 *
 * Then compare the file-time of `%TEMP%/wsock_trace/location.db` with the final `db_file`.
 * If the latter is too old; the time-difference is `>= g_cfg.ASN.max_days`,
 * copy `%TEMP%/wsock_trace/location.db` to `db_file`.
 */
void ASN_update_file (const char *db_file, bool force_update)
{
  struct stat st;
  char   db_xz_temp_file [_MAX_PATH];
  char   db_temp_file [_MAX_PATH];
  char  *db_dir;
  bool   db_dir_ok, need_update;
  DWORD  downloaded;

  db_dir = dirname (db_file);
  db_dir_ok = (db_dir && file_exists(db_dir));   /* Target .db directory okay? */
  free (db_dir);
  if (!db_dir_ok)
  {
    TRACE (1, "Directory '%s' does not exist.\n", db_dir);
    return;
  }

  snprintf (db_temp_file, sizeof(db_temp_file)-3, "%s\\location.db", g_data.ws_tmp_dir);
  strcpy (db_xz_temp_file, db_temp_file);  /* == `%TEMP%/wsock_trace/location.db` */
  strcat (db_xz_temp_file, ".xz");         /* == `%TEMP%/wsock_trace/location.db.xz` */

  if (g_cfg.ASN.xz_decompress <= 0)
  {
    TRACE (1, "Nothing to do for '%s' file with XZ-decompression disabled.\n", db_xz_temp_file);
    return;
  }

  memset (&st, '\0', sizeof(st));
  stat (db_temp_file, &st);

  need_update = false;

  /* If `%TEMP%/wsock_trace/location.db` does not exist, is 0 bytes or
   * 'force_update == true', update it.
   */
  if (st.st_size == 0 || force_update)
     need_update = true;
  else
  {
    time_t now = time (NULL);
    time_t expiry = now - g_cfg.ASN.max_days * 24 * 3600;
    time_t when   = now + g_cfg.ASN.max_days * 24 * 3600;

    expiry -= 10;   /* Give a 10 sec time slack */

    memset (&st, '\0', sizeof(st));
    stat (db_file, &st);

    /* 'db_file' exists, is not 0 bytes and is not too old.
     */
    if (st.st_size && st.st_mtime > expiry)
    {
      TRACE (0, "Update of \"%s\" not needed until \"%.24s\".\n"
                "            Use option '-f' to force an update.\n",
             db_file, ctime(&when));
      return;
    }

    memset (&st, '\0', sizeof(st));
    stat (db_xz_temp_file, &st);

    /* 'db_xz_temp_file' exists, is not 0 bytes and is not too old.
     */
    if (st.st_size && st.st_mtime > expiry)
    {
      TRACE (0, "Download of \"%s\" not needed until \"%.24s\"\n"
                "              Use option '-f' to force an update\n",
             db_xz_temp_file, ctime(&when));
      ASN_xz_decompress (db_xz_temp_file, db_temp_file, db_file);
      return;
    }
    need_update = true;
  }

  if (!need_update)
  {
    TRACE (2, "Returning since 'need_update == false'.\n");
    return;
  }

  /* `%TEMP%/wsock_trace/location.db.xz` need to be updated.
   * Force a download, XZ-decompress and copy to the final `db_file`.
   */
  downloaded = INET_util_download_file (db_xz_temp_file, ASN_get_url());

  TRACE (1, "Downloaded:\n"
         "            %s -> %s. %s\n"
         "            %s bytes.\n",
         ASN_get_url(), db_xz_temp_file, downloaded > 0 ? "OK" : "Failed", dword_str(downloaded));

  if (downloaded > 0)  /* If download succeeded */
     ASN_xz_decompress (db_xz_temp_file, db_temp_file, db_file);
}

/**
 * Check for latest version of the `libloc` database
 * using a `TXT _v1._db.location.ipfire.org` DNS query.
 */
static int ASN_check_database (const char *local_db, int trace_level)
{
  struct stat st;
  time_t time_local_db = 0;
  time_t time_remote_db = 0;
  bool   older = false;
  char   days_behind [50] = "";
  const char *zone = _tzname[0];

  if (loc_discover_latest_version(libloc.ctx, LOC_DATABASE_VERSION_LATEST, &time_remote_db) != 0)
  {
    TRACE (trace_level, "Could not check IPFire's database time-stamp.\n");
    return (0);
  }

  if (stat(local_db, &st) == 0)
  {
    time_t slack = g_cfg.ASN.max_days * 24 * 3600;

    time_local_db = st.st_mtime - _timezone;
    older = (time_local_db + slack < time_remote_db);
    if (older)
    {
      double day_diff = (double) (time_remote_db - time_local_db);

      day_diff /= 24.0 * 3600;
      snprintf (days_behind, sizeof(days_behind), " (%.1f days behind) ", day_diff);
    }
  }

  TRACE (trace_level,
         "IPFire's latest database time-stamp: %.24s (UTC)\n"
         "            It should be at: %s\n"
         "            Your local database is %sup-to-date.%s\n",
         ctime(&time_remote_db), ASN_get_url(), older ? "not " : "", days_behind);

  time_local_db += _timezone;

#if defined(__CYGWIN__) /* Cygwin doesn't always set '_tzname[0]' */
  TRACE (trace_level, "local time-stamp: %.24s\n", ctime(&time_local_db));
  ARGSUSED (zone);
#else
  TRACE (trace_level, "local time-stamp: %.24s (%s)\n", ctime(&time_local_db), zone);
#endif
  return (1);
}

/**
 * Print the libloc library version.
 */
static void ASN_print_libloc_version (void)
{
  printf ("libloc ver: %d.%d.%d\n", LIBLOC_MAJOR_VER, LIBLOC_MINOR_VER, LIBLOC_MICRO_VER);
}

/**
 * A custom libloc logger function used to log to `g_cfg.trace_stream`.
 */
static void ASN_libloc_logger (struct loc_ctx *ctx,
                               int             priority,
                               const char     *file,
                               int             line,
                               const char     *function,
                               const char     *format,
                               va_list         args)
{
  if (g_cfg.trace_stream)
  {
    WORD col = set_color (NULL);  /* Use default console colour */

    fprintf (g_cfg.trace_stream, "LIBLOC(%d): %s(%u): ", priority, basename(file), line);
    vfprintf (g_cfg.trace_stream, format, args);
    fflush (g_cfg.trace_stream);
    set_color (&col);            /* Restore active colour */
  }
  ARGSUSED (ctx);
  ARGSUSED (function);
}

/**
 * A custom libloc logger to log to system Debugger
 * via `OutputDebugStringA()`.
 */
static void ASN_libloc_logger_ods (struct loc_ctx *ctx,
                                   int             priority,
                                   const char     *file,
                                   int             line,
                                   const char     *function,
                                   const char     *format,
                                   va_list         args)
{
  char buf [1000];
  int  len;

  buf[0] = '\0';
  len = snprintf (buf, sizeof(buf), "LIBLOC(%d): %s(%u): ", priority, basename(file), line);
  if (len > -1 && len < sizeof(buf))
     vsnprintf (buf + len, sizeof(buf) - len, format, args);

  OutputDebugStringA (buf);

  ARGSUSED (ctx);
  ARGSUSED (priority);
  ARGSUSED (function);
}

/**
 * Load the binary ASN .db-file specified in the
 * `[asn::asn_bin_file]` config-section.
 */
static size_t ASN_load_bin_file (const char *file)
{
  const char *descr, *licence, *vendor;
  size_t      len, num_AS;
  time_t      created;
  int         err, save;

  memset (&libloc, '\0', sizeof(libloc)); /* should be un-needed */

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

  if (g_cfg.trace_level >= 2 && (g_cfg.trace_stream || g_cfg.trace_use_ods))
  {
    /* Let libloc log to trace-stream or system Debugger.
     */
    if (g_cfg.trace_use_ods)
         loc_set_log_fn (libloc.ctx, ASN_libloc_logger_ods);
    else loc_set_log_fn (libloc.ctx, ASN_libloc_logger);
    loc_set_log_priority (libloc.ctx, g_cfg.trace_level >= 3 ? LOG_DEBUG : LOG_INFO);
  }

  if (g_cfg.trace_level == 0)
     SetEnvironmentVariable ("LOC_LOG", NULL);  /* Clear the 'libloc' internal trace-level */

  if (g_cfg.trace_level >= 2)
  {
    ASN_print_libloc_version();
    ASN_check_database (file, 1);
  }

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
            "  num ASN:     %zu\n\n",
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
 * Internal function called from `ASN_libloc_print()`.
 */
static int libloc_handle_net (struct loc_network    *net,
                              const struct in_addr  *ip4,
                              const struct in6_addr *ip6,
                              str_put_func           func)
{
  struct loc_as       *as = NULL;
  struct _loc_network *_net = (struct _loc_network*) net;
  char                 _net_name [MAX_IP6_SZ+1+4];
  int                  _prefix = _net->prefix;
  const char          *net_name;
  const char          *remark;
  const char          *AS_name;
  char                 attributes [100] = "";
  char                 print_buf [1000];
  int                  rc = 0;
  uint32_t             AS_num;
  bool                 is_anycast, is_anon_proxy, is_sat_provider, is_hostile;

#if 0
  /** \todo: hopefully, some day this could be possible in 'libloc'
   */
  bool is_tor_exit;  /* Ref: https://en.wikipedia.org/wiki/Tor_(network)#Tor_exit_node_block */
  bool is_bogon;     /* Ref: https://en.wikipedia.org/wiki/Bogon_filtering */
#endif

  if (ip4)
     _prefix -= 96;

  snprintf (_net_name, sizeof(_net_name), "%s/%d", INET_addr_ntop2(AF_INET6, &_net->first_address), _prefix);

  if (ip4)
       net_name = _net_name + strlen("::ffff:");
  else net_name = _net_name;

  AS_num = loc_network_get_asn (net);

  is_anycast      = (loc_network_has_flag (net, LOC_NETWORK_FLAG_ANYCAST) != 0);
  is_anon_proxy   = (loc_network_has_flag (net, LOC_NETWORK_FLAG_ANONYMOUS_PROXY) != 0);
  is_sat_provider = (loc_network_has_flag (net, LOC_NETWORK_FLAG_SATELLITE_PROVIDER) != 0);
  is_hostile      = (loc_network_has_flag (net, LOC_NETWORK_FLAG_DROP) != 0);
#if 0
  is_tor_exit     = (loc_network_has_flag (net, LOC_NETWORK_FLAG_TOR_EXIT) != 0);
  is_bogon        = (loc_network_has_flag (net, LOC_NETWORK_FLAG_BOGON) != 0);
#endif

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
    rc = 1;
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
  if (is_sat_provider)
     strcat (attributes, ", Satellite Provider");
  if (is_hostile)
     strcat (attributes, ", Hostile");

  snprintf (print_buf, sizeof(print_buf), "%u, name: %.*s, net: %s%s",
            AS_num, ASN_MAX_NAME-30, AS_name, net_name, attributes);
  (*func) (print_buf);

  if (as)
     loc_as_unref (as);

  return (rc);
}

/**
 * Print ASN information for an IPv4 or IPv6 address.
 *
 * Simlator to wahat the IPFire script does:
 * ```
 * c:\> py -3 location.py lookup ::ffff:45.150.206.231
 *   Network:           45.150.206.0/23
 *   Autonomous System: AS35029 - WebLine LTD
 *   Anonymous Proxy:   yes
 * ```
 *
 * for an IPv4 address we must first map `ip4` to an IPv4-mapped address:
 * ```
 *   45.150.206.231 -> ::ffff:45.150.206.231
 * ```
 *
 * This function does nothing for top-level networks like from IANA, RIPE etc.
 * 'libloc' only have information on RIRs (Regional Internet Registries).
 *
 * \todo
 *  Create a cache for this since calling `loc_database_lookup()` can
 *  sometimes be slow.
 */
static int __ASN_libloc_print (const char            *intro,
                               const struct in_addr  *ip4,
                               const struct in6_addr *ip6,
                               str_put_func           func)
{
  struct loc_network *net = NULL;
  struct in6_addr     addr;
  const  char        *addr_str = "?";
  int                 rc, save, ip6_teredo;

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

  ip6_teredo = ip6 && _IN6_IS_ADDR_TEREDO (ip6);

  if (!ip6_teredo &&  /* since a Terodo can have an AS-number assigned */
      !INET_util_addr_is_global(ip4, ip6))
  {
    (*func) (intro);
    (*func) ("<not global>\n");
    return (0);
  }

  if (ip4)   /* Convert to IPv6-mapped address */
  {
    static const IN6_ADDR _in6addr_v4mappedprefix = {{
                 0,0,0,0,0,0,0,0,0,0,0xFF,0xFF,0,0,0,0
               }};

    memcpy (&addr, &_in6addr_v4mappedprefix, sizeof(_in6addr_v4mappedprefix));
    *(__ms_u_long*) &addr.s6_words[6] = ip4->s_addr;
  }
  else if (ip6)
  {
    memcpy (&addr, ip6, sizeof(addr));
  }
  else
    return (0);

  if (g_cfg.trace_level >= 2)
     addr_str = INET_addr_ntop2 (AF_INET6, &addr);

  TRACE (2, "Looking up: %s.\n", addr_str);

  /* Do not trace 'inet_pton()' inside libloc or `WSAGetLastError()' below.
   */
  save = g_cfg.trace_level;
  g_cfg.trace_level = 0;

  (*func) (intro);

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
       rc = libloc_handle_net (NULL, asn, ip4, ip6, func);
  }
  else
#endif

  rc = loc_database_lookup (libloc.db, &addr, &net);
  if (rc == 0 && net)
  {
    rc = libloc_handle_net (net, ip4, ip6, func);
    loc_network_unref (net);
  }
  else
  {
    (*func) ("<no info>");
    TRACE (2, "No data for address: %s, err: %d/%s.\n", addr_str, -rc, strerror(-rc));
    rc = 0;
  }

#if 0
  /**
   * \todo
   * Add this to the ASN-list (sorted on net?)
   * Add negative lookups also; no `net` or `AS_num` found.
   */
  if (rc)
  {
    smartlist_insert (ASN_entries, at_sorted_pos, asn);

  /**
   * \todo
   * Check if the resulting network is a "Bogon".
   * Ref: https://en.wikipedia.org/wiki/Bogon_filtering
   */
  }
#endif

  /* Restore trace-level
   */
  g_cfg.trace_level = save;
  return (rc);
}

int ASN_libloc_print (const char *intro, const struct in_addr *ip4, const struct in6_addr *ip6, str_put_func print_func)
{
  if (!print_func)
     print_func = C_puts;

  return __ASN_libloc_print (intro, ip4, ip6, print_func);
}

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

  C_puts (intro);
  if (!stricmp(iana->status, "RESERVED"))
  {
    C_puts ("<reserved>\n");
    return;
  }

  g_num_compares = 0;
  rec = smartlist_bsearch (ASN_entries, ip4, ASN_compare_on_ip4);
  TRACE (2, "g_num_compares: %lu.\n", g_num_compares);

  if (!rec)
       C_puts ("<no data>\n");
  else C_printf ("%lu, %s (status: %s)\n",
                 rec->as_number, rec->as_name[0] ? rec->as_name : "<unknown>" ,
                 iana->status);
}

static bool ASN_match_number (const struct ASN_record *rec, const char *spec)
{
  char AS_num_str [20];

  if (rec->as_number == 0 && !strcmp(spec, "0")) /* match all or the unknowns */
     return (true);

  _ultoa (rec->as_number, AS_num_str, 10);
  return (fnmatch(spec, AS_num_str, FNM_NOESCAPE) == 0);
}

static bool ASN_match_name (const struct ASN_record *rec, const char *spec)
{
  char *p, *end, AS_name_spec [200];

  if (!rec->as_name[0] && *spec == '*')  /* match all or the unknowns */
     return (true);

  str_ncpy (AS_name_spec, spec, sizeof(AS_name_spec)-1);

  /* To turn this 'spec':
   *   ws_tool.exe asn -D "Adobe Systems* Ireland"
   *
   * into this 'spec':
   *   ws_tool.exe asn -D "Adobe Systems* Ireland*"
   */
  p = strrchr (AS_name_spec, '*');
  end = strrchr (AS_name_spec, '\0');
  if (p && p < end - 1)
     strcpy (end, "*");

  return (fnmatch(AS_name_spec, rec->as_name, FNM_NOESCAPE | FNM_CASEFOLD) == 0);
}

static bool ASN_match (const struct ASN_record *rec, const char *spec)
{
  if (!spec)
     return (true);
  if (isdigit((int)*spec))
     return ASN_match_number (rec, spec);
  return ASN_match_name (rec, spec);
}

/*
 * Handles only IPv4 addresses now.
 */
static void ASN_dump (const char *spec)
{
  int   i, max = ASN_entries ? smartlist_len (ASN_entries) : 0;
  int   width = (max > 0) ? (int)log10 ((double)max) : 3;
  DWORD no_match = 0;

  C_printf ("Dumping AS numbers matching \"%s\".\n", spec ? spec : "all");

  if (!ASN_entries)
  {
    fputs ("[asn:asn_csv_file] seems to be missing?!\n", stderr);
    return;
  }

  C_printf ("\nParsed %s records from \"%s\":\n"
            "%*sNum.  Low              High             Pfx     ASN  Name\n"
            "--------------------------------------------------------------------------\n",
            dword_str(max), g_cfg.ASN.asn_csv_file ? g_cfg.ASN.asn_csv_file : "<none>",
            width-1, "");

  for (i = 0; i < max; i++)
  {
    const struct ASN_record *rec = smartlist_get (ASN_entries, i);
    char  low_str [MAX_IP4_SZ];
    char  high_str[MAX_IP4_SZ];

    if (!ASN_match(rec, spec))
    {
      no_match++;
      continue;
    }

    if (INET_addr_ntop(AF_INET, &rec->ipv4.low, low_str, sizeof(low_str), NULL) &&
        INET_addr_ntop(AF_INET, &rec->ipv4.high, high_str, sizeof(high_str), NULL))
    {
      C_printf ("  %*d:  %-14.14s - %-14.14s    %2d  ", width, i, low_str, high_str, rec->prefix);
      C_printf ("%6lu  %s\n", rec->as_number, rec->as_name);
    }
    else
      C_printf ("  %*d: <bogus>\n", width, i);
  }
  if (no_match > 0)
     C_printf ("  %lu matches for \"%s\" out of %d.\n", DWORD_CAST(max - no_match), spec, max);
}

/**
 * Free memory allocated here. <br>
 * Normally called from `wsock_trace_exit()`.
 */
void ASN_exit (void)
{
  smartlist_wipe (ASN_entries, free);

  ASN_bin_close();
  ASN_entries = NULL;

  free (g_cfg.ASN.asn_csv_file);
  free (g_cfg.ASN.asn_bin_file);
  free (g_cfg.ASN.asn_bin_url);
  g_cfg.ASN.asn_csv_file = g_cfg.ASN.asn_bin_file = g_cfg.ASN.asn_bin_url = NULL;
}

/**
 * \todo
 * Collect some statistics on AS-numbers etc. discovered and print that information here.
 */
void ASN_report (void)
{
  C_printf ("\n  ASN statistics:\n"
            "    Got %lu ASN-numbers, %lu AS-names.\n", g_num_asn, g_num_as_names);
}

/*
 * A small test for ASN.
 */
static int show_help (void)
{
  printf ("Usage: %s [-D <spec>] [-ftuv]\n"
          "       -D <spec>: dump the list of AS'es. Or only those matching <spec>.\n"
          "       -f:        force an update with the '-u' option.\n"
          "       -u:        update the IPFire database-file.\n"
          "       -v:        show version of IPFire database and libloc library version.\n"
          "  Option '-D' accepts a range or name wildcard.\n"
          "       E.g. 'ws_tool asn -D 10[2-4]*'\n"
          "       or   'ws_tool asn -D \"Nasdaq*\"'\n", g_data.program_name);
  return (0);
}

int asn_main (int argc, char **argv)
{
  int ch, do_dump = 0, do_force = 0, do_update = 0, do_version = 0;

  set_program_name (argv[0]);

  while ((ch = getopt(argc, argv, "Dfuvh?")) != EOF)
     switch (ch)
     {
       case 'D':
            do_dump = 1;
            break;
       case 'f':
            do_force = 1;
            break;
       case 'u':
            do_update = 1;
            break;
       case 'v':
            do_version = 1;
            break;
       case '?':
       case 'h':
       default:
            return show_help();
  }

  argc -= optind;
  argv += optind;

  if (do_dump)
  {
    g_cfg.ASN.enable = true;
    ASN_dump (*argv);
  }
  else if (do_update)
  {
    ASN_bin_close();
    g_cfg.ASN.enable = true;
    ASN_update_file (g_cfg.ASN.asn_bin_file, do_force);
  }
  else if (do_version)
  {
    ASN_print_libloc_version();
    ASN_check_database (g_cfg.ASN.asn_bin_file, 0);
  }
  else
    show_help();

  return (0);
}
