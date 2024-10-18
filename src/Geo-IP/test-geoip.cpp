
#include <stdlib.h>
#include <stdbool.h>

#include <GeoipMMDB/maxminddb.h>
#include <GeoipMMDB/maxminddb-compat-util.h>

// todo:
//
// #include <DB-IP/db-ip.h>
// #include <SpamHaus/DROP.h>

#include <IPFire/src/libloc/libloc.h>
#include <IPFire/src/libloc/database.h>
#include <IPFire/src/libloc/network.h>

extern "C" {
  #include "../inet_addr.h"
  #include "../inet_util.h"
  #include "../geoip.h"
  #include "../getopt.h"
  #include "../ip2loc.c"
}

#ifndef MAX_PROVIDERS
#define MAX_PROVIDERS 8
#endif

/*
 * From ../asn.c
 */
typedef struct libloc_data {
        struct loc_ctx      *ctx;
        struct loc_database *db;
        FILE                *file;
      } libloc_data;

typedef enum geoip_flags {
        GEOIP_IPV4_ADDR = 0x00001,
        GEOIP_IPV6_ADDR = 0x00002,
        GEOIP_BIN_FILE  = 0x00004,
        GEOIP_MMDB_FILE = 0x00008,
        GEOIP_ASN_FILE  = 0x00010,
        GEOIP_CSV_FILE  = 0x00020,
        GEOIP_TXT_FILE  = 0x00040,
        GEOIP_DROP      = 0x00080,
      } geoip_flags;

typedef struct geoip_handle_st {
        IP2Location  *ip2loc;
        libloc_data  *libloc;
        MMDB_s       *mmdb;

        // ... add more provider specifics
      } geoip_handle_st;

// Move to geoip.h
typedef struct geoip_data_rec {
        char       *country;
        char       *location;
        DWORD       as_number;
        char       *as_name;
        const char *providers [MAX_PROVIDERS];  // Which provider(s) gave this record?

        // ... add more elements
      } geoip_data_rec;

typedef bool (*lookup_func) (geoip_handle_st  *geoip, const struct sockaddr *sa_in, geoip_data_rec *rec_out);
typedef bool (*init_func)   (geoip_handle_st **geoip_p);
typedef bool (*update_func) (geoip_handle_st  *geoip);
typedef bool (*close_func)  (geoip_handle_st  *geoip);

typedef struct geoip_provider_st {
        unsigned         flags;
        char            *files [4];
        char            *urls  [4];
        char            *config;
        init_func        init;
        lookup_func      lookup;
        update_func      update;
        close_func       close;

        // these are to be private to this implementation
        geoip_handle_st *handle;
        char            *provider_name;
      } geoip_provider_st;

/* -- Dummy no-op providers: ------------------------------------------------------------------------------------------ */

static bool geoip_null_init (geoip_handle_st **geoip_p)
{
  TRACE (1, "In %s().\n", __FUNCTION__);
  *geoip_p = nullptr;
  return (false);
}

static bool geoip_null_close (geoip_handle_st *geoip)
{
  TRACE (1, "In %s().\n", __FUNCTION__);
  return (false);
}

static bool geoip_null_lookup (geoip_handle_st *geoip, const struct sockaddr *sa, geoip_data_rec *rec)
{
  TRACE (1, "In %s().\n", __FUNCTION__);
  return (false);
}

static bool geoip_null_update  (geoip_handle_st *geoip)
{
  TRACE (1, "In %s().\n", __FUNCTION__);
  return (false);
}

static geoip_provider_st g_providers [MAX_PROVIDERS + 1];

static geoip_provider_st null_handler = {
    .flags  = 0,
    .files  = { nullptr },
    .urls   = { nullptr },
    .config = nullptr,
    .init   = geoip_null_init,
    .lookup = geoip_null_lookup,
    .update = geoip_null_update,
    .close  = geoip_null_close
  };


/* -- Public GeoIP interface: ----------------------------------------------------------------------------------------- */

#define ADD_VALUE(v)  { v, #v }
static const struct search_list _geoip_flags[] = {
                    ADD_VALUE (GEOIP_IPV4_ADDR),
                    ADD_VALUE (GEOIP_IPV6_ADDR),
                    ADD_VALUE (GEOIP_BIN_FILE),
                    ADD_VALUE (GEOIP_MMDB_FILE),
                    ADD_VALUE (GEOIP_ASN_FILE),
                    ADD_VALUE (GEOIP_CSV_FILE),
                    ADD_VALUE (GEOIP_TXT_FILE),
                    ADD_VALUE (GEOIP_DROP)
                  };

static const struct search_list _mmdb_data_types[] = {
                    ADD_VALUE (MMDB_DATA_TYPE_EXTENDED),
                    ADD_VALUE (MMDB_DATA_TYPE_POINTER),
                    ADD_VALUE (MMDB_DATA_TYPE_UTF8_STRING),
                    ADD_VALUE (MMDB_DATA_TYPE_DOUBLE),
                    ADD_VALUE (MMDB_DATA_TYPE_BYTES),
                    ADD_VALUE (MMDB_DATA_TYPE_UINT16),
                    ADD_VALUE (MMDB_DATA_TYPE_UINT32),
                    ADD_VALUE (MMDB_DATA_TYPE_MAP),
                    ADD_VALUE (MMDB_DATA_TYPE_INT32),
                    ADD_VALUE (MMDB_DATA_TYPE_UINT64),
                    ADD_VALUE (MMDB_DATA_TYPE_UINT128),
                    ADD_VALUE (MMDB_DATA_TYPE_ARRAY),
                    ADD_VALUE (MMDB_DATA_TYPE_CONTAINER),
                    ADD_VALUE (MMDB_DATA_TYPE_END_MARKER),
                    ADD_VALUE (MMDB_DATA_TYPE_BOOLEAN),
                    ADD_VALUE (MMDB_DATA_TYPE_FLOAT)
                 };


const char *geoip_flags_decode (unsigned flags)
{
  if (flags == 0)
     return ("0");
  return flags_decode (flags, _geoip_flags, DIM(_geoip_flags));
}

const char *geoip_mmdb_data_type (unsigned type)
{
  return list_lookup_name (type, _mmdb_data_types, DIM(_mmdb_data_types));
}

const char *geoip_get_providers (const struct geoip_data_rec *rec)
{
  static char buf [100];
  char  *p     = buf;
  char  *p_max = p + sizeof(buf);
  int    i;

  for (i = 0; i < DIM(rec->providers) && rec->providers[i] && p < p_max-2; i++)
  {
    strcpy (p, rec->providers[i]);
    p += strlen (rec->providers[i]);
    *p++ = ',';
  }
  p[-1] = '\0';
  return (buf);
}

static char *expand_file (char *file)
{
#if 0
  return strdup (get_path (file, nullptr, nullptr, nullptr));
#else
  return strdup (file);
#endif
}

bool geoip_add_provider (const char *provider_name, const geoip_provider_st *provider)
{
  geoip_provider_st *p = g_providers + 0;
  int   i, i_max = DIM (g_providers) - 1;
  bool  rc = false;

  for (i = 0; i < i_max; i++, p++)
      if (!p->provider_name)
         break;

  if (i == i_max)
  {
    TRACE (1, "too many providers already (%d)\n", i);
    return (false);
  }

  *p = *provider;

  p->provider_name = strdup (provider_name);

  // expand any env-vars in these fields

  p->config = expand_file (p->config);
  for (i = 0; p->files[i]; i++)
       p->files[i] = expand_file (p->files[i]);

  TRACE (1, "free slot at 'g_providers[%d]'\n", i);

  if (p->init)
     rc = (*p->init) (&p->handle);

  TRACE (1, "p->handle: 0x%p\n", p->handle ? p->handle : 0);
  return (rc);
}

/*
 * Delete a single provider
 */
int geoip_del_provider (int i)
{
  geoip_provider_st *p;
  int   f, rc = 0;

  assert (i < DIM(g_providers));
  p = g_providers + i;

  TRACE (2, "  i: %d, p: 0x%p\n", i, p);
  if (p->close && p->handle)
  {
    (*p->close) (p->handle);
    free (p->handle);
    p->handle = nullptr;
    rc = 1;
  }
  for (f = 0; p->files[f]; f++)
  {
    free (p->files[f]);
    p->files [f] = nullptr;
  }
  free (p->provider_name);
  p->provider_name = nullptr;
  return (rc);
}

/*
 * Delete all in reverse order of `geoip_add_provider()`.
 */
bool geoip_del_providers (void)
{
  int i = DIM (g_providers) - 1;

  TRACE (1, "In %s().\n", __FUNCTION__);

  for (i = DIM (g_providers) - 1; i >= 0; i--)
      geoip_del_provider (i);
  return (true);
}

int geoip_dump_provider (int i)
{
  geoip_provider_st *p = g_providers + i;
  const char        *db_file;
  int                f;

  if (!p->provider_name)
     return (0);

  printf ("i: %d, provider_name: '%s':\n", i, p->provider_name);
  printf ("  p->flags:  0x%04X: '%s'\n", p->flags, geoip_flags_decode(p->flags));
  printf ("  p->init:   0x%p\n",   p->init);
  printf ("  p->lookup: 0x%p\n",   p->lookup);
  printf ("  p->update: 0x%p\n",   p->update);
  printf ("  p->close:  0x%p\n",   p->close);
  for (f = 0; (db_file = p->files[f]) != nullptr; f++)
      printf ("  p->files[%d]: '%s'. %s.\n",
              f, db_file, access(db_file, 0) == 0 ?
              "Does exist" : " Does not exist");
  puts ("");
  return (1);
}

int geoip_dump_providers (void)
{
  int rc = 0;
  int i, i_max = DIM (g_providers);

  for (i = 0; i < i_max; i++, rc++)
      rc += geoip_dump_provider (i);
  return (rc);
}

geoip_provider_st *geoip_get_provider_by_name (const char *provider_name)
{
  geoip_provider_st *p, *rc = nullptr;

  for (p = g_providers + 0; p; p++)
  {
    if (!strcmp(p->provider_name, provider_name))
    {
      rc = p;
      break;
    }
  }
  TRACE (1, "In %s(). provider_name: '%s', files[0]: '%s'\n",
         __FUNCTION__, provider_name, rc ? rc->files[0] : "?");
  return (rc);
}

geoip_provider_st *geoip_get_provider_by_idx (int i)
{
  geoip_provider_st *p, *rc = nullptr;
  int   j = 0;

  for (p = g_providers + 0; p; p++, j++)
  {
    if (i == j)
    {
      rc = p;
      break;
    }
  }
  TRACE (1, "In %s(). i: %d, provider_name: '%s'\n",
         __FUNCTION__, i, rc ? rc->provider_name : "??");
  return (rc);
}

static bool geoip_lookup4 (const struct sockaddr *sa, unsigned flags, geoip_data_rec *rec)
{
  geoip_provider_st    *p;
  const struct in_addr *ia4 = (const struct in_addr*) &sa->sa_data;
  const char           *ip4_addr = inet_ntoa (*ia4);
  const char           *bit_str;
  int                   rc = 0;

  TRACE (1, "In %s()\n", __FUNCTION__);

  if ((flags & GEOIP_IPV4_ADDR) && !INET_util_addr_is_global(ia4, nullptr))
  {
    TRACE (0, "IPv4 addr %s is not global.\n", ip4_addr);
    return (false);
  }

  for (p = g_providers + 0; p->provider_name && flags; p++)
  {
    bit_str = geoip_flags_decode (flags & p->flags);
    if (flags & p->flags)
    {
      TRACE (1, "flag '%s' handled by provider %s.\n", bit_str, p->provider_name);
      if ((*p->lookup) (p->handle, sa, rec))
         rec->providers [rc++] = p->provider_name;
    }
    else
      TRACE (1, "flag '%s' NOT handled by provider %s.\n", bit_str, p->provider_name);

    flags &= ~p->flags;
  }
  return (rc > 0);
}

static bool geoip_lookup6 (const struct sockaddr *sa, unsigned flags, geoip_data_rec *rec)
{
  geoip_provider_st *p;
  const struct in6_addr *ia6 = (const struct in6_addr*) &sa->sa_data;
  char  buf [INET6_ADDRSTRLEN];
  const char        *bit_str;
  const char        *addr;
  int                rc = 0;

  TRACE (1, "In %s()\n", __FUNCTION__);

  if ((flags & GEOIP_IPV6_ADDR) && !INET_util_addr_is_global(nullptr, ia6))
  {
    addr = inet_ntop (AF_INET6, (const void*)ia6, buf, sizeof(buf));
    TRACE (0, "IPv6 addr %s is not global.\n", addr);
    return (false);
  }

  for (p = g_providers + 0; p->provider_name && flags; p++)
  {
    bit_str = geoip_flags_decode (flags & p->flags);
    if (flags & p->flags)
    {
      TRACE (1, "flag '%s' handled by provider %s.\n", bit_str, p->provider_name);
      if ((*p->lookup) (p->handle, sa, rec))
         rec->providers [rc++] = p->provider_name;
    }
    else
      TRACE (1, "flag '%s' NOT handled by provider %s.\n", bit_str, p->provider_name);

    flags &= ~p->flags;
  }
  return (rc > 0);
}

bool geoip_lookup (const struct sockaddr *sa, unsigned flags, geoip_data_rec *rec)
{
  memset (rec, '\0', sizeof(*rec));

  if (sa->sa_family == AF_INET)
     return geoip_lookup4 (sa, flags, rec);

  if (sa->sa_family == AF_INET6)
     return geoip_lookup6 (sa, flags, rec);

  TRACE (1, "Unsupported family: %d.\n", sa->sa_family);
  return (false);
}

void geoip_free_rec (struct geoip_data_rec *rec)
{
  TRACE (1, "In %s()\n", __FUNCTION__);
  free (rec->country);
  free (rec->as_name);
}

/* -- MMDB interface: ----------------------------------------------------------------------------------------- */

static bool geoip_MMDB_init (geoip_handle_st **geoip_p)
{
  TRACE (1, "In %s()\n", __FUNCTION__);

  geoip_handle_st   *geoip = (geoip_handle_st *) calloc (sizeof(*geoip), 1);
  geoip->mmdb              = (MMDB_s *)          calloc (sizeof(*geoip->mmdb), 1);
  geoip_provider_st *provider = geoip_get_provider_by_name ("MMDB");
  int                rc = MMDB_open (provider->files[0], MMDB_MODE_MMAP, geoip->mmdb);

  *geoip_p = geoip;
  return (rc == MMDB_SUCCESS);
}

static bool geoip_MMDB_lookup (geoip_handle_st *geoip, const struct sockaddr *sa, geoip_data_rec *rec)
{
  MMDB_lookup_result_s result;
  MMDB_entry_data_s    data;
  const char          *addr;
  char                 buf [INET6_ADDRSTRLEN];
  char                *path [4];
  int                  rc = 0;

  TRACE (1, "In %s()\n", __FUNCTION__);

  memset (&result, 0, sizeof(result));
  addr = inet_ntop (sa->sa_family, (const void*)&sa->sa_data, buf, sizeof(buf));

  result = MMDB_lookup_sockaddr (geoip->mmdb, sa, &rc);
  TRACE (1, "MMDB_lookup_sockaddr (\"%s\") -> result.found_entry: %d, rc: %d\n", addr, result.found_entry, rc);

  if (rc != MMDB_SUCCESS || !result.found_entry)
     return (false);

  path[0] = "autonomous_system_number";
  path[1] = nullptr;
  if (MMDB_aget_value(&result.entry, &data, (const char *const *const) path) == MMDB_SUCCESS && data.has_data)
     rec->as_number = data.uint16;
  TRACE (1, "AS number: data.has_data: %d, data.type: %s.\n", data.has_data, geoip_mmdb_data_type(data.type));

  path[0] = "autonomous_system_organization";
  path[1] = nullptr;
  if (MMDB_aget_value(&result.entry, &data, (const char *const *const) path) == MMDB_SUCCESS && data.has_data && data.type == MMDB_DATA_TYPE_UTF8_STRING)
     rec->as_name = mmdb_strndup (data.utf8_string, data.data_size);
  TRACE (1, "AS org: data.has_data: %d, data.type: %s.\n", data.has_data, geoip_mmdb_data_type(data.type));

  path[0] = "country";
  path[1] = "names";
  path[2] = "en";
  path[3] = nullptr;
  if (MMDB_aget_value(&result.entry, &data, (const char *const *const)path) == MMDB_SUCCESS && data.has_data && data.type == MMDB_DATA_TYPE_UTF8_STRING)
     rec->country = mmdb_strndup (data.utf8_string, data.data_size);
  TRACE (1, "Country: data.has_data: %d, data.type: %s.\n", data.has_data, geoip_mmdb_data_type(data.type));
  return (rec->as_number || rec->as_name || rec->country);
}

static bool geoip_MMDB_close (geoip_handle_st *geoip)
{
  TRACE (1, "In %s()\n", __FUNCTION__);
  MMDB_close (geoip->mmdb);
  return (true);
}

/* -- IP2Location interface: ---------------------------------------------------------------------------- */

static bool geoip_ip2loc_init (geoip_handle_st **geoip_p)
{
  geoip_provider_st *provider = geoip_get_provider_by_name ("IP2LOC");
  int  rc = 0;

  TRACE (1, "In %s()\n", __FUNCTION__);

  g_cfg.GEOIP.ip2location_bin_file = strdup (provider->files[0]);

  if (ip2loc_init())
  {
    geoip_handle_st *ip2loc = (geoip_handle_st *) calloc (sizeof(*ip2loc), 1);
    ip2loc->ip2loc          = (IP2Location *)     calloc (sizeof(*ip2loc->ip2loc), 1);
    rc = 1;
    TRACE (1, "ip2loc_init() OK\n");
    *geoip_p = ip2loc;
  }
  else
    TRACE (1, "ip2loc_init() failed\n");

  // todo
  return (rc != 0);
}

static bool geoip_ip2loc_lookup (geoip_handle_st *geoip, const struct sockaddr *sa, geoip_data_rec *rec)
{
  struct ip2loc_entry entry;
  bool   rc = false;

  TRACE (1, "In %s()\n", __FUNCTION__);

  if (sa->sa_family == AF_INET)
  {
    rc = ip2loc_get_ipv4_entry ((const struct in_addr*)&sa->sa_data, &entry);
    TRACE (1, "IPv4: country_short: %s, country_long: %s, city: %s.\n", entry.country_short, entry.country_long, entry.city);
  }
  else if (sa->sa_family == AF_INET6)
  {
    rc = ip2loc_get_ipv6_entry ((const struct in6_addr*)&sa->sa_data, &entry);
    TRACE (1, "IPv6: country_short: %s, country_long: %s, city: %s.\n", entry.country_short, entry.country_long, entry.city);
  }

  if (rc)
  {
    char location [100];

    snprintf (location, sizeof(location), "%s/%s", entry.city, entry.region);
    rec->location = strdup (location);
    rec->country  = strdup (entry.country_short);
  }
  return (rc);
}

static bool geoip_ip2loc_update (geoip_handle_st *geoip)
{
  TRACE (1, "In %s()\n", __FUNCTION__);
  // todo
  return (true);
}

static bool geoip_ip2loc_close (geoip_handle_st *geoip)
{
  TRACE (1, "In %s()\n", __FUNCTION__);

  ip2loc_exit();
  free (g_cfg.GEOIP.ip2location_bin_file);
  memset (geoip->ip2loc, '\0', sizeof(*geoip->ip2loc));
  return (true);
}

/* -- LibLoc interface: ---------------------------------------------------------------------------------------- */

static bool geoip_libloc_init (geoip_handle_st **geoip_p)
{
  int rc = 0;

  TRACE (1, "In %s()\n", __FUNCTION__);

  geoip_handle_st   *libloc   = (geoip_handle_st *) calloc (sizeof(*libloc), 1);
  libloc->libloc              = (libloc_data *)     calloc (sizeof(*libloc->libloc), 1);
  geoip_provider_st *provider = geoip_get_provider_by_name ("LIBLOC");

  *geoip_p = libloc;

  // todo
  return (rc != 0);
}

static bool geoip_libloc_lookup (geoip_handle_st *geoip, const struct sockaddr *sa, geoip_data_rec *rec)
{
  int  rc = 0;
  TRACE (1, "In %s()\n", __FUNCTION__);

  // todo
  return (rc != 0);
}

static bool geoip_libloc_update (geoip_handle_st *geoip)
{
  TRACE (1, "In %s()\n", __FUNCTION__);

  // todo
  return (true);
}

static bool geoip_libloc_close (geoip_handle_st *geoip)
{
  libloc_data *libloc = geoip->libloc;

  TRACE (1, "In %s()\n", __FUNCTION__);

  if (libloc->db)
     loc_database_unref (libloc->db);

  if (libloc->ctx)
     loc_unref (libloc->ctx);

  if (libloc->file)
     fclose (libloc->file);

  memset (libloc, '\0', sizeof(*libloc));
  return (true);
}

/* -- ASN interface: ------------------------------------------------------------------------------------------- */

static bool geoip_ASN_init (geoip_handle_st **geoip_p)
{
  geoip_handle_st   *geoip    = (geoip_handle_st *) calloc (sizeof(*geoip), 1);
  geoip_provider_st *provider = geoip_get_provider_by_name ("ASN");
  int   rc = 0;

  TRACE (1, "In %s()\n", __FUNCTION__);
  // todo
  return (rc != 0);
}

static bool geoip_ASN_lookup (geoip_handle_st *geoip, const struct sockaddr *sa, geoip_data_rec *rec)
{
  int  rc = 0;

  TRACE (1, "In %s()\n", __FUNCTION__);
  // todo
  return (rc != 0);
}

static bool geoip_ASN_close (geoip_handle_st *geoip)
{
  TRACE (1, "In %s()\n", __FUNCTION__);
  // todo
  return (true);
}

/* -- SpamHaus DROP interface: -------------------------------------------------------------------------------- */

static bool geoip_DROP_init (geoip_handle_st **geoip_p)
{
  geoip_handle_st   *geoip    = (geoip_handle_st*) calloc (sizeof(*geoip), 1);
  geoip_provider_st *provider = geoip_get_provider_by_name ("DROP");
  int  rc = 0;

  TRACE (1, "In %s()\n", __FUNCTION__);
  // todo
  return (rc != 0);
}

static bool geoip_DROP_lookup (geoip_handle_st *geoip, const struct sockaddr *sa, geoip_data_rec *rec)
{
  int rc = 0;

  TRACE (1, "In %s()\n", __FUNCTION__);
  // todo
  return (rc != 0);
}

static bool geoip_DROP_update (geoip_handle_st *geoip)
{
  TRACE (1, "In %s()\n", __FUNCTION__);
  // todo
  return (true);
}

static bool geoip_DROP_close (geoip_handle_st *geoip)
{
  TRACE (1, "In %s()\n", __FUNCTION__);
  // todo
  return (true);
}

/* -- Usage example: ------------------------------------------------------------------------------------------- */

struct config_table g_cfg;
struct global_data  g_data;
char               *program_name;   /* for '../getopt.c' */

void debug_printf (const char *file, unsigned line, const char *fmt, ...)
{
  va_list args;

  printf ("%s(%u): ", file, line);
  va_start (args, fmt);
  vprintf (fmt, args);
  va_end (args);
}

static const struct geoip_provider_st mmdb_handler = {
  .flags  = GEOIP_IPV4_ADDR | GEOIP_IPV6_ADDR | GEOIP_MMDB_FILE,
  .files  = { "DB-IP/dbip-asn-lite-2020-10.mmdb" },
  .urls   = { "https://updates.maxmind.com/app/update_getfilename?product_id=GeoLite2-Country/update?db_md5=a456ade123456789" },
  .config = "%APPDATA%/GeoIP.conf",
  .init   = geoip_MMDB_init,
  .lookup = geoip_MMDB_lookup,
  .update = nullptr,
  .close  = geoip_MMDB_close
};

static const struct geoip_provider_st ip2loc_handler = {
  .flags  = GEOIP_IPV4_ADDR | GEOIP_IPV6_ADDR | GEOIP_BIN_FILE,
  .files  = { "c:/Users/gvane/AppData/Roaming/IP2LOCATION-LITE-DB9.IPV6.BIN" },
  .urls   = { "https://lite.ip2location.com/database-download" },
  .init   = geoip_ip2loc_init,
  .lookup = geoip_ip2loc_lookup,
  .update = geoip_ip2loc_update,
  .close  = geoip_ip2loc_close
};

static const struct geoip_provider_st libloc_handler = {
  .flags  = GEOIP_IPV4_ADDR | GEOIP_IPV6_ADDR | GEOIP_ASN_FILE,
  .files  = { "../../IPFire-database.db" },
  .urls   = { "https://location.ipfire.org/databases/1/location.db.xz" },
  .init   = geoip_libloc_init,
  .lookup = geoip_libloc_lookup,
  .update = geoip_libloc_update,
  .close  = geoip_libloc_close
};

static const struct geoip_provider_st asn_handler1 = {
  .flags  = GEOIP_ASN_FILE | GEOIP_MMDB_FILE,
  .files  = { "DB-IP/dbip-asn-lite-2020-10.mmdb" },
  .init   = geoip_ASN_init,
  .lookup = geoip_ASN_lookup,
  .update = nullptr,
  .close  = geoip_ASN_close
};

static const struct geoip_provider_st asn_handler2 = {
  .flags  = GEOIP_ASN_FILE | GEOIP_CSV_FILE,
  .files  = { "../../IP4-ASN.CSV" },
  .init   = geoip_ASN_init,
  .lookup = geoip_ASN_lookup,
  .update = nullptr,
  .close  = geoip_ASN_close
};

static const struct geoip_provider_st drop_handler = {
  .flags  = GEOIP_DROP | GEOIP_TXT_FILE,
  .files  = { "../../DROP.txt",
              "../../DROPv6.txt",
              "../../EDROP.txt" },
  .urls   = { "http://www.spamhaus.org/drop/drop.txt",
              "http://www.spamhaus.org/drop/edrop.txt",
              "http://www.spamhaus.org/drop/dropv6.txt" },
  .init   = geoip_DROP_init,
  .lookup = geoip_DROP_lookup,
  .update = geoip_DROP_update,
  .close  = geoip_DROP_close
};

int main (int argc, char **argv)
{
  struct geoip_data_rec rec;
  int    c;

  program_name = argv[0];
  memset (&g_cfg, '\0', sizeof(g_cfg));
  g_cfg.GEOIP.enable = true;

  while ((c = getopt(argc, argv, "d")) != EOF)
  {
    switch (c)
    {
      case 'd':
           g_cfg.trace_level++;
           break;
      default:
           puts ("Illegal option.");
           return (1);
    }
  }
  argv += optind;

  geoip_add_provider ("IP2LOC", &ip2loc_handler);
  geoip_add_provider ("MMDB", &mmdb_handler);
  geoip_add_provider ("LIBLOC", &libloc_handler);
  geoip_add_provider ("ASN", &asn_handler1);
  geoip_add_provider ("ASN", &asn_handler2);
  geoip_add_provider ("DROP",&drop_handler);
  geoip_add_provider ("NONE", &null_handler);

  if (g_cfg.trace_level >= 2)
     geoip_dump_providers();

  WSADATA     wsa;
  WSAStartup (MAKEWORD(1, 1), &wsa);

  struct sockaddr sa  = { .sa_family = AF_INET };
  struct in_addr  ia4 = { 8, 8, 8, 8 };

  if (argv[0] && inet_pton(AF_INET, argv[0], &ia4) != 1)
  {
    printf ("Illegal IPv4 address: %s\n", argv[1]);
    return (1);
  }
  *(u_long*) &sa.sa_data = ia4.s_addr;

  if (geoip_lookup(&sa, GEOIP_IPV4_ADDR | GEOIP_BIN_FILE | GEOIP_MMDB_FILE /* | GEOIP_ASN_FILE */, &rec))
  {
    printf ("Info from %s:\n", geoip_get_providers(&rec));
    printf ("  Country:           %s, location: %s\n", rec.country, rec.location);
    printf ("  Autonomous System: %lu, name: %s\n", rec.as_number, rec.as_name);
    geoip_free_rec (&rec);
  }
  else
  {
    char buf [INET6_ADDRSTRLEN];
    printf ("No information on address %s\n", inet_ntop (sa.sa_family, (const void*)&sa.sa_data, buf, sizeof(buf)));
  }

  geoip_del_providers();
  return (0);
}
