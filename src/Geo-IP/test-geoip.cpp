
#include <stdlib.h>
#include <stdbool.h>

#include <GeoipMMDB/maxminddb.h>
#include <GeoipMMDB/maxminddb-compat-util.h>

// todo:
//
// #include <DB-IP/db-ip.h>
// #include <IP2Location/ip2location.h>
// #include <SpamHaus/DROP.h>

#include <IPFire/src/libloc/libloc.h>
#include <IPFire/src/libloc/database.h>
#include <IPFire/src/libloc/network.h>

#include "../geoip.h"

#ifndef MAX_PROVIDERS
#define MAX_PROVIDERS 8
#endif

/*
 * From ../ip2loc.c
 */
typedef struct IP2Location {
        FILE       *file;         /**< The `fopen_excl()` file structure */
        uint8_t    *sh_mem_ptr;
        uint64      sh_mem_max;
        uint64      sh_mem_index_errors;
        HANDLE      sh_mem_fd;
        BOOL        sh_mem_already;
        struct stat stat_buf;
        uint8_t     db_type;
      } IP2Location;

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
        GEOIP_MMDB_FILE = 0x00004,
        GEOIP_ASN_FILE  = 0x00008,
        GEOIP_CSV_FILE  = 0x00010,
        GEOIP_TXT_FILE  = 0x00010,
        GEOIP_DROP      = 0x00020,
      } geoip_flags;

typedef struct geoip_handle_st {
               MMDB_s       *mmdb;
               IP2Location  *ip2loc;
               libloc_data  *libloc;
               // ... add more provider specifics
             } geoip_handle_st;

// Move to geoip.h
typedef struct geoip_data_rec {
        char   *country;
        char   *location;
        DWORD   as_number;
        char   *as_name;
        // ... add more elements
      } geoip_data_rec;

typedef bool (*init_func)   (geoip_handle_st **geoip_p);
typedef bool (*lookup_func) (geoip_handle_st  *geoip, const char *ip_address, geoip_data_rec *rec);
typedef bool (*update_func) (geoip_handle_st  *geoip);
typedef bool (*close_func)  (geoip_handle_st  *geoip);

typedef struct geoip_provider_st {
        unsigned         flags;
        const char      *files [4];
        const char      *url;
        const char      *config;
        init_func        init;
        lookup_func      lookup;
        update_func      update;
        close_func       close;

        // these are to be private to this implementation
        geoip_handle_st *handle;
        char            *provider_name;
      } geoip_provider_st;

/* -- Dummy no-op providers: ------------------------------------------------------------------------------------------ */

static bool geoip_dummy_init (geoip_handle_st **geoip_p)
{
  TRACE (1, "In %s().\n", __FUNCTION__);
  *geoip_p = NULL;
  return (false);
}

static bool geoip_dummy_close (geoip_handle_st *geoip)
{
  TRACE (1, "In %s().\n", __FUNCTION__);
  return (false);
}

static bool geoip_dummy_lookup (geoip_handle_st *geoip, const char *ip_address, geoip_data_rec *rec)
{
  TRACE (1, "In %s().\n", __FUNCTION__);
  return (false);
}

static bool geoip_dummy_update  (geoip_handle_st *geoip)
{
  TRACE (1, "In %s().\n", __FUNCTION__);
  return (false);
}

static geoip_provider_st g_providers [MAX_PROVIDERS + 1];

static geoip_provider_st dummy_provider = {
    .flags  = 0,
    .files  = { NULL },
    .url    = NULL,
    .config = NULL,
    .init   = geoip_dummy_init,
    .lookup = geoip_dummy_lookup,
    .update = geoip_dummy_update,
    .close  = geoip_dummy_close
  };


/* -- Public GeoIP interface: ----------------------------------------------------------------------------------------- */

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

  if (provider == NULL)
     provider = &dummy_provider;
  *p = *provider;

  p->provider_name = strdup (provider_name);

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
  geoip_provider_st *p = g_providers + i;
  int   rc = 0;

  TRACE (2, "  i: %d, p: 0x%p\n", i, p);
  if (p->close && p->handle)
  {
    (*p->close) (p->handle);
    free (p->handle);
    rc++;
  }
  free (p->provider_name);
  p->provider_name = NULL;
  p->handle = NULL;
  return (rc);
}

/*
 * Delete all in reverse order of geoip_add_provider
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

  if (!p->provider_name)
     return (0);

  printf ("i: %d, provider_name: '%s':\n", i, p->provider_name);
  printf ("  p->flags:  0x%04X\n", p->flags);
  printf ("  p->init:   0x%p\n",   p->init);
  printf ("  p->lookup: 0x%p\n",   p->lookup);
  printf ("  p->update: 0x%p\n",   p->update);
  printf ("  p->close:  0x%p\n",   p->close);
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
  geoip_provider_st *p, *rc = NULL;

  for (p = g_providers + 0; p; p++)
  {
    if (!strcmp(p->provider_name, provider_name))
    {
      rc = p;
      break;
    }
  }
  TRACE (1, "In %s(). provider_name: '%s', provider->files[0]: '%s'\n",
         __FUNCTION__, provider_name, rc ? rc->files[0] : "?");
  return (rc);
}

geoip_provider_st *geoip_get_provider_by_idx (int i)
{
  geoip_provider_st *p, *rc = NULL;
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

bool geoip_lookup (const struct in_addr *ia4, unsigned flags, geoip_data_rec *rec)
{
  geoip_provider_st *p;
  const char        *ip_address = inet_ntoa (*ia4);
  bool               rc = false;

  TRACE (1, "In %s()\n", __FUNCTION__);
  memset (rec, '\0', sizeof(*rec));
  for (p = g_providers + 0; p->provider_name; p++)
  {
    if ((flags & p->flags) != flags)
       TRACE (1, "flags 0x%04X NOT handled by provider %s.\n", flags, p->provider_name);
    else
    {
      TRACE (1, "flags 0x%04X handled by provider %s.\n", flags, p->provider_name);
      if ((*p->lookup) (p->handle, ip_address, rec))
      {
        rc = true;
        break;
      }
    }
  }
  return (rc);
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

static bool geoip_MMDB_lookup (geoip_handle_st *geoip, const char *ip_address, geoip_data_rec *rec)
{
  MMDB_lookup_result_s result;
  MMDB_entry_data_s  data;
  char              *path [4];
  int                rc = 0;
  int                gai_error;

  TRACE (1, "In %s()\n", __FUNCTION__);

  memset (&result, 0, sizeof(result));
  result = MMDB_lookup_string (geoip->mmdb, ip_address, &gai_error, &rc);
  TRACE (1, "MMDB_lookup_string (\"%s\") -> result.found_entry: %d, rc: %d\n", ip_address, result.found_entry, rc);

  if (rc != MMDB_SUCCESS || !result.found_entry)
     return (false);

  path[0] = "autonomous_system_number";
  path[1] = NULL;
  if (MMDB_aget_value(&result.entry, &data, (const char *const *const) path) == MMDB_SUCCESS && data.has_data)
     rec->as_number = data.uint16;
  TRACE (1, "data.has_data: %d, data.type: %d.\n", data.has_data, data.type);

  path[0] = "autonomous_system_organization";
  path[1] = NULL;
  if (MMDB_aget_value(&result.entry, &data, (const char *const *const) path) == MMDB_SUCCESS && data.has_data && data.type == MMDB_DATA_TYPE_UTF8_STRING)
     rec->as_name = mmdb_strndup (data.utf8_string, data.data_size);
  TRACE (1, "data.has_data: %d, data.type: %d.\n", data.has_data, data.type);

  path[0] = "country";
  path[1] = "names";
  path[2] = "en";
  path[3] = NULL;
  if (MMDB_aget_value(&result.entry, &data, (const char *const *const)path) == MMDB_SUCCESS && data.has_data && data.type == MMDB_DATA_TYPE_UTF8_STRING)
     rec->country = mmdb_strndup (data.utf8_string, data.data_size);
  TRACE (1, "data.has_data: %d, data.type: %d.\n", data.has_data, data.type);
  return (rec->as_number || rec->as_name || rec->country);
}

static bool geoip_MMDB_close (geoip_handle_st *geoip)
{
  TRACE (1, "In %s()\n", __FUNCTION__);
  MMDB_close (geoip->mmdb);
  return (true);
}

/* -- LibLoc interface: ---------------------------------------------------------------------------------------- */

static bool geoip_libloc_init (geoip_handle_st **geoip_p)
{
  TRACE (1, "In %s()\n", __FUNCTION__);

  geoip_handle_st   *geoip = (geoip_handle_st *) calloc (sizeof(*geoip), 1);
  geoip->libloc            = (libloc_data *)     calloc (sizeof(*geoip->libloc), 1);
  geoip_provider_st *provider = geoip_get_provider_by_name ("LIBLOC");
  int  rc = 0;

  // todo
  return (rc != 0);
}

static bool geoip_libloc_lookup (geoip_handle_st *geoip, const char *ip_address, geoip_data_rec *rec)
{
  int  rc = 0;
  TRACE (1, "In %s()\n", __FUNCTION__);

  // todo
  return (rc != 0);
}

static bool geoip_libloc_update (geoip_handle_st *geoip)
{
  // todo
  return (true);
}

static bool geoip_libloc_close (geoip_handle_st *geoip)
{
  TRACE (1, "In %s()\n", __FUNCTION__);

  if (geoip->libloc->db)
     loc_database_unref (geoip->libloc->db);

  if (geoip->libloc->ctx)
     loc_unref (geoip->libloc->ctx);

  if (geoip->libloc->file)
     fclose (geoip->libloc->file);

  memset (geoip->libloc, '\0', sizeof(*geoip->libloc));
  return (true);
}

/* -- ASN interface: ------------------------------------------------------------------------------------------- */

static bool geoip_ASN_init (geoip_handle_st **geoip_p)
{
  TRACE (1, "In %s()\n", __FUNCTION__);

  geoip_handle_st   *geoip    = (geoip_handle_st *) calloc (sizeof(*geoip), 1);
  geoip_provider_st *provider = geoip_get_provider_by_name ("ASN");
  int  rc = 0;
  // todo
  return (rc != 0);
}

static bool geoip_ASN_lookup (geoip_handle_st *geoip, const char *ip_address, geoip_data_rec *rec)
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
  TRACE (1, "In %s()\n", __FUNCTION__);

  geoip_handle_st   *geoip    = (geoip_handle_st*) calloc (sizeof(*geoip), 1);
  geoip_provider_st *provider = geoip_get_provider_by_name ("DROP");
  int  rc = 0;
  // todo
  return (rc != 0);
}

static bool geoip_DROP_lookup (geoip_handle_st *geoip, const char *ip_address, geoip_data_rec *rec)
{
  int  rc = 0;
  TRACE (1, "In %s()\n", __FUNCTION__);

  // todo
  return (rc != 0);
}

static bool geoip_DROP_close (geoip_handle_st *geoip)
{
  TRACE (1, "In %s()\n", __FUNCTION__);

  // todo
  return (true);
}

/* -- Usage example: ------------------------------------------------------------------------------------------- */

struct config_table g_cfg;

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
    .url    = "https://updates.maxmind.com/app/update_getfilename?product_id=GeoLite2-Country/update?db_md5=a456ade123456789",
    .config = "$(APPDATA)/GeoIP.conf",
    .init   = geoip_MMDB_init,
    .lookup = geoip_MMDB_lookup,
    .close  = geoip_MMDB_close
  };

static const struct geoip_provider_st libloc_handler = {
  .flags  = GEOIP_IPV4_ADDR | GEOIP_IPV6_ADDR | GEOIP_ASN_FILE,
  .files  = { "IPFire/location.db" },
  .url    = "https://location.ipfire.org/databases/1/location.db.xz",
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
  .close  = geoip_ASN_close
};

static const struct geoip_provider_st asn_handler2 = {
  .flags  = GEOIP_ASN_FILE | GEOIP_CSV_FILE,
  .files  = { "IP4-ASN.CSV" },
  .init   = geoip_ASN_init,
  .lookup = geoip_ASN_lookup,
  .close  = geoip_ASN_close
};

static const struct geoip_provider_st drop_handler = {
  .flags  = GEOIP_DROP | GEOIP_TXT_FILE,
  .files  = { "DROP.txt", "DROPv6.txt", "EDROP.txt" },
  .init   = geoip_DROP_init,
  .lookup = geoip_DROP_lookup,
  .close  = geoip_DROP_close
};

int main (int argc, char **argv)
{
  struct in_addr ia4 = { 8, 8, 8, 8 };
  struct geoip_data_rec rec;

  memset (&g_cfg, '\0', sizeof(g_cfg));
  g_cfg.trace_level = 1;

  geoip_add_provider ("NONE",  NULL);
  geoip_add_provider ("MMDB",  &mmdb_handler);
  geoip_add_provider ("LIBLOC",&libloc_handler);
  geoip_add_provider ("ASN",   &asn_handler1);
  geoip_add_provider ("ASN",   &asn_handler2);
  geoip_add_provider ("DROP",  &drop_handler);
  geoip_dump_providers();

  WSADATA     wsa;
  WSAStartup (MAKEWORD(1, 1), &wsa);

  if (geoip_lookup(&ia4, GEOIP_IPV4_ADDR | GEOIP_MMDB_FILE /* | GEOIP_ASN_FILE */, &rec))
  {
    printf ("%s, location: %s\n", rec.country, rec.location);
    printf ("AS%lu, name: %s\n", rec.as_number, rec.as_name);
    geoip_free_rec (&rec);
  }

  geoip_del_providers();
  return (0);
}
