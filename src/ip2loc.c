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

#include <sys/stat.h>

#include "common.h"
#include "init.h"
#include "geoip.h"

#if defined(USE_IP2LOCATION) && !defined(TEST_GEOIP)
#include <stdint.h>
#include <IP2Location.h>

static IP2Location *handle;
static DWORD        file_size;

static int IP2Location_initialize (IP2Location *loc);

/*
 * Do not call 'IP2Location_open()' because of it's 'printf()'.
 * Hence just do what 'IP2Location_open()' do here.
 */
static IP2Location *open_file (const char *file)
{
  struct stat  st;
  IP2Location *loc;
  FILE        *f;

  f = fopen (file, "rb");
  if (!f)
  {
    TRACE (1, "ip2loc: Failed to open \"bin_file\" file %s.\n", file);
    return (NULL);
  }
  loc = calloc (1, sizeof(*loc));
  loc->filehandle = f;

  IP2Location_initialize (loc);
  if (IP2Location_open_mem(loc, IP2LOCATION_SHARED_MEMORY) == -1)
  {
    TRACE (1, "ip2loc: Call to IP2Location_open_mem() failed.\n");
    IP2Location_close (loc);
    return (NULL);
  }

  stat (file, &st);
  file_size = st.st_size;

  TRACE (2, "ip2loc: Success. Database has %s entries. API-version: %s\n"
            "                Date: %02d-%02d-%04d, IPv: %d, "
            "IP4count: %u, IP6count: %u.\n",
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

DWORD ip2loc_num_ipv4_entries (void)
{
  if (handle)
     return (handle->ipv4databasecount);
  return (0);
}

DWORD ip2loc_num_ipv6_entries (void)
{
  if (handle)
     return (handle->ipv6databasecount);
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

#elif defined(__GNUC__)
  /*
  * For warning: 'IP2Location_ipv6_to_no' declared 'static'
  * but never defined [-Wunused-function]
  */
  GCC_PRAGMA (GCC diagnostic ignored "-Wunused-function");
#endif

/*
 * For 'inet_pton()' in below "IP2Location.c"
 */
#include "in_addr.h"

#undef  inet_pton
#define inet_pton(family, addr, dst)  wsock_trace_inet_pton (family, addr, dst)

/*
 * This assumes the IP2Location .c/.h files are in the %INCLUDE% or %C_INCLUDE_PATH% path.
 */
#include "IP2Location.c"
#include "IP2Loc_DBInterface.c"

BOOL ip2loc_get_entry (const char *addr, struct ip2loc_entry *ent)
{
  IP2LocationRecord *r = IP2Location_get_record (handle, (char*)addr,
                                                 COUNTRYSHORT | COUNTRYLONG | REGION | CITY);

  memset (ent, '\0', sizeof(*ent));
  if (!r)
     return (FALSE);

  if (!strncmp(r->country_short,"INVALID",7))
  {
    IP2Location_free_record (r);
    return (FALSE);
  }

  _strlcpy (ent->country_short, r->country_short, sizeof(ent->country_short));
  _strlcpy (ent->country_long, r->country_long, sizeof(ent->country_long));
  _strlcpy (ent->city, r->city, sizeof(ent->city));
  _strlcpy (ent->region, r->region, sizeof(ent->region));
  IP2Location_free_record (r);
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

DWORD ip2loc_num_ipv4_entries (void)
{
  return (0);
}

DWORD ip2loc_num_ipv6_entries (void)
{
  return (0);
}

BOOL ip2loc_get_entry (const char *addr, struct ip2loc_entry *ent)
{
  ARGSUSED (addr);
  ARGSUSED (ent);
  return (FALSE);
}
#endif  /* USE_IP2LOCATION && !TEST_GEOIP */
