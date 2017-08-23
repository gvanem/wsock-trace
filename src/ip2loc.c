/*
 * ip2loc.c - Part of Wsock-Trace.
 *
 * This file is an interface for the IP2Location library.
 *   Ref: https://github.com/chrislim2888/IP2Location-C-Library
 *
 * For 'inet_addr' warning.
 */
#ifndef _WINSOCK_DEPRECATED_NO_WARNINGS
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#endif

#include "common.h"
#include "init.h"
#include "geoip.h"

#if defined(USE_IP2LOCATION) && !defined(TEST_GEOIP)
#include <stdint.h>
#include <IP2Location.h>

static IP2Location *handle;

static IP2Location *open_file (char *file)
{
  IP2Location *loc = IP2Location_open (file);

  if (!loc)
  {
    TRACE (1, "ip2loc: Failed to open \"bin_file\" file %s.\n", file);
    return (NULL);
  }

  if (IP2Location_open_mem(loc, IP2LOCATION_SHARED_MEMORY) == -1)
  {
    TRACE (1, "ip2loc: Call to IP2Location_open_mem() failed.\n");
    IP2Location_close (loc);
    return (NULL);
  }

  TRACE (2, "ip2loc: Success. Database has %s entries. API-version: %s\n"
            "                 Date: %02d-%02d-%04d, IPv: %d, "
            "IP4count: %u, IP6count: %u\n",
         dword_str(loc->ipv4databasecount), IP2Location_api_version_string(),
         loc->databaseday, loc->databasemonth, 2000+loc->databaseyear,
         loc->ipversion, loc->ipv4databasecount, loc->ipv6databasecount);
  return (loc);
}

BOOL ip2loc_init (void)
{
  if (!g_cfg.geoip_enable || !g_cfg.ip2location_bin_file)
     return (FALSE);

  handle = open_file (g_cfg.ip2location_bin_file);
  return (handle != NULL);
}

void ip2loc_exit (void)
{
  if (handle)
     IP2Location_close (handle);

  IP2Location_delete_shm();
  handle = NULL;
}

DWORD ip2loc_num_entries (void)
{
  if (handle)
     return (handle->ipv4databasecount);
  return (0);
}

/*
 * Include the IP2Location sources here to avoid the need to build the library.
 * The Makefile.win on Github is broken anyway.
 *
 * PACKAGE_VERSION is missing in "libIP2Location/IP2Location.c".
 * Must be a string. Take it from API_VERSION.
 */
#undef PACKAGE_VERSION
#define _STR2(x)  #x
#define _STR(x)  _STR2(x)
#define PACKAGE_VERSION  _STR(API_VERSION)

#if defined(_MSC_VER)
  #pragma warning (disable: 4101 4244)

#elif defined(__WATCOMC__)
  #include "in_addr.h"
#endif

/*
 * This assumes the "IP2Location.h" is in the %INCLUDE% or %C_INCLUDE_PATH% path.
 * The .c-files should be in the same directory.
 */
#include "IP2Location.c"
#include "IP2Loc_DBInterface.c"

/* A hack to avoid IP2Location.c allocating memory for the record.
 * Also to avoid the need to free it since we never work with several entries
 * at the time.
 */
#undef  calloc
#define calloc(x) &fixed

static IP2LocationRecord fixed;

BOOL ip2loc_get_entry (DWORD ip_num, struct ip2loc_entry *ent)
{
  IP2LocationRecord *r;
  ipv_t parsed_ipv;

  parsed_ipv.ipv4 = ip_num;
  r = IP2Location_get_ipv4_record (handle, NULL, COUNTRYSHORT | COUNTRYLONG | REGION | CITY, parsed_ipv);

  memset (ent, '\0', sizeof(*ent));
  if (!r)
     return (FALSE);

  if (!strncmp(r->country_short,"INVALID",7))
     return (FALSE);

  ent->country_short = r->country_short;
  ent->country_long  = r->country_long;
  ent->city          = r->city;
  ent->region        = r->region;
  return (TRUE);
}

#else /* USE_IP2LOCATION && !TEST_GEOIP */

BOOL ip2loc_init (void)
{
  return (FALSE);
}

void ip2loc_exit (void)
{
}

DWORD ip2loc_num_entries (void)
{
  return (0);
}

BOOL ip2loc_get_entry (DWORD ip_num, struct ip2loc_entry *ent)
{
  ARGSUSED (ip_num);
  ARGSUSED (ent);
  return (FALSE);
}
#endif  /* USE_IP2LOCATION */
