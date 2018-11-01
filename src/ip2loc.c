/**\file    ip2loc.c
 * \ingroup Geoip
 *
 * \brief
 *   This file is an interface for the IP2Location library. \n
 *     Ref: https://github.com/chrislim2888/IP2Location-C-Library <br>
 *          http://lite.ip2location.com
 *
 * ip2loc.c - Part of Wsock-Trace.
 *
 * Together with the `geoip*.c` files, this module will return location
 * information (country, city and region) for an IPv4/IPv6-address.
 *
 * Unlike `geoip.c`, this module uses an external binary file specified
 * in the `[geoip]` section and keyword ` ip2location_bin_file` of `wsock_trace`.
 *
 * Compiling this file is optional; only done if the respective Makefile
 * has a `-DUSE_IP2LOCATION` in it.
 */

/**\def _WINSOCK_DEPRECATED_NO_WARNINGS
 * To supress the warning on `inet_addr()`.
 */
#ifndef _WINSOCK_DEPRECATED_NO_WARNINGS
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#endif

#include <sys/stat.h>
#include <stdint.h>

#include "common.h"
#include "init.h"
#include "in_addr.h"
#include "inet_util.h"
#include "geoip.h"

#if defined(USE_IP2LOCATION)
#if defined(__clang__)
  #pragma clang diagnostic ignored "-Wstrict-prototypes"

#elif defined(__CYGWIN__)
  GCC_PRAGMA (GCC diagnostic ignored "-Wpointer-to-int-cast")
#endif

#include <IP2Location.h>

/**
 * The handle for all IP2Location access.
 * Returned from open_file().
 */
static IP2Location *ip2loc_handle;

/**
 * The size of the `file` opened by open_file().
 * Currently not used for anything sensible.
 */
static DWORD ip2loc_file_size;

/**
 * Prototype to a static function inside IP2Location.c.
 * This gets included below.
 */
static int IP2Location_initialize (IP2Location *loc);

/**
 * Open and initialise access to the IP2Location library and binary data-file.
 *
 * Do not call `IP2Location_open()` because of it's use of `printf()`.
 * Hence just do what `IP2Location_open()` does here.
 *
 * \param[in] file  the IP2Location binary file.
 */
static IP2Location *open_file (const char *file)
{
  struct stat  st;
  IP2Location *loc;
  FILE        *f;
  UINT         IPvX;
  BOOL         is_IPv4_only, is_IPv6_only;

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
  ip2loc_file_size = st.st_size;

  /* The IP2Loc database scheme is really strange.
   * This used to be true previously.
   */
  IPvX = loc->ipversion;
  if (IPvX == IPV4)
     IPvX = 4;
  else if (IPvX == IPV6)
     IPvX = 6;

  /* The IPvX count could now mean the count of IPv6 addresses
   * in a database with both IPv4 and IPv6 addresses.
   */
  is_IPv4_only = is_IPv6_only = FALSE;
  if ((IPvX == loc->ipv6databasecount) && (loc->ipv4databasecount == 0))
     is_IPv6_only = TRUE;

  else if ((IPvX == loc->ipv4databasecount) && (loc->ipv6databasecount == 0))
     is_IPv4_only = TRUE;

  TRACE (2, "ip2loc: Success. Database has %s entries. API-version: %s, size: %s bytes\n"
            "                 Date: %02d-%02d-%04d, IPvX: %d, "
            "IPv4-count: %u, IPv6-count: %u (is_IPv4_only: %d, is_IPv6_only: %d).\n",
         dword_str(loc->ipv4databasecount), IP2Location_api_version_string(),
         dword_str(ip2loc_file_size), loc->databaseday, loc->databasemonth, 2000+loc->databaseyear,
         IPvX,
         loc->ipv4databasecount, loc->ipv6databasecount, is_IPv4_only, is_IPv6_only);
  return (loc);
}

/**
 * Our initialiser for IP2Location library and binary data-file. <br>
 * Called from geoip_init().
 */
BOOL ip2loc_init (void)
{
  if (!g_cfg.geoip_enable || !g_cfg.ip2location_bin_file)
     return (FALSE);

  if (!ip2loc_handle)
     ip2loc_handle = open_file (g_cfg.ip2location_bin_file);

  return (ip2loc_handle != NULL);
}

/**
 * Close the IP2Location library. <br>
 * Called from geoip_exit().
 */
void ip2loc_exit (void)
{
  if (ip2loc_handle)
     IP2Location_close (ip2loc_handle);

  IP2Location_delete_shm(); /* Currently does nothing for '_WIN32' */
  ip2loc_handle = NULL;
}

/**
 * Return the number of IPv4-addresses in the data-file.
 */
DWORD ip2loc_num_ipv4_entries (void)
{
  if (ip2loc_handle)
     return (ip2loc_handle->ipv4databasecount);
  return (0);
}

/**
 * Return the number of IPv6-addresses in the data-file.
 */
DWORD ip2loc_num_ipv6_entries (void)
{
  if (ip2loc_handle)
     return (ip2loc_handle->ipv6databasecount);
  return (0);
}

/*
 * Include the IP2Location sources here to avoid the need to build the library.
 * The `Makefile.win` on Github is broken anyway.
 *
 * And turn off some warnings:
 */
#if defined(__GNUC__) || defined(__clang__)
  #pragma GCC diagnostic ignored     "-Wunused-function"
  #pragma GCC diagnostic ignored     "-Wunused-variable"
  #pragma GCC diagnostic ignored     "-Wunused-parameter"
  #if defined(__clang__)
    #pragma clang diagnostic ignored "-Wcast-qual"
    #pragma clang diagnostic ignored "-Wconditional-uninitialized"
  #else
    #pragma GCC diagnostic ignored   "-Wunused-but-set-variable"
  #endif

#elif defined(_MSC_VER)
  #pragma warning (disable: 4101 4244)
#endif

/**\def inet_pton
 *
 * Redefine `inet_pton()`.
 *
 * Since `IP2Location_parse_addr()` does a lot of calls to
 * `IP2Location_ip_is_ipv4()` and `IP2Location_ip_is_ipv6()`, keep
 * the noise-level down by not calling `WSASetLastError()` in in_addr.c.
 */
#undef  inet_pton
#define inet_pton(family, addr, result)  _wsock_trace_inet_pton (family, addr, result)

/* \todo */
#if 0
  #define inet_addr(str)                 _wsock_trace_inet_addr (str)
#endif

/**\def _WIN32
 * Since the code in `IP2Location.c` tests on `_WIN32`.
 */
#if defined(__DOXYGEN__) || (defined(__CYGWIN__) && !defined(_WIN32))
#define _WIN32
#endif

/*
 * This assumes the IP2Location `.c/.h` files are in the `%INCLUDE%` or
 * `%C_INCLUDE_PATH%` path. Or the `$(IP2LOCATION_ROOT)` is set in
 * respective makefile.
 */
#include "IP2Location.c"
#include "IP2Loc_DBInterface.c"

/**\def IP2LOC_FLAGS
 * The flags used to look up a location record with a <i>short country</i>,
 * <i>long country</i> name, <i>region</i> and <i>city</i>.
 */
#define IP2LOC_FLAGS  (COUNTRYSHORT | COUNTRYLONG | REGION | CITY)

/**
 * \param[out]    out The `ip2loc_entry` to fill.
 * \param[in,out] r   The `IP2LocationRecord` record to get the result from.
 *                    This will be freed when no longer needed.
 */
static BOOL ip2loc_get_common (struct ip2loc_entry *out, IP2LocationRecord *r)
{
  if (r->country_short[0] == '-' ||                   /* is "-" for unallocated addr */
      !strncmp(r->country_short,"INVALID",7) ||       /* INVALID_IPV4_ADDRESS/INVALID IPV4 ADDRESS */
      !strncmp(r->country_short,"This parameter",14)) /* NOT_SUPPORTED */
  {
    IP2Location_free_record (r);
    return (FALSE);
  }

  _strlcpy (out->country_short, r->country_short, sizeof(out->country_short));
  _strlcpy (out->country_long, r->country_long, sizeof(out->country_long));
  _strlcpy (out->city, r->city, sizeof(out->city));
  _strlcpy (out->region, r->region, sizeof(out->region));
  IP2Location_free_record (r);
  return (TRUE);
}

/**
 * This can be passed both IPv4 and IPv6 addresses. <br>
 * But slower than the below.
 */
BOOL ip2loc_get_entry (const char *addr, struct ip2loc_entry *out)
{
  IP2LocationRecord *r = IP2Location_get_record (ip2loc_handle, (char*)addr, IP2LOC_FLAGS);

  memset (out, '\0', sizeof(*out));
  if (!r)
     return (FALSE);

  TRACE (3, "Record for %s; country_short: \"%.2s\"\n", addr, r->country_short);
  return ip2loc_get_common (out, r);
}

/**
 * This avoids the call to `inet_pton()` and `inet_addr()` since the passed
 * `*addr` should be a valid IPv4-address.
 */
BOOL ip2loc_get_ipv4_entry (const struct in_addr *addr, struct ip2loc_entry *out)
{
  IP2LocationRecord *r;
  ipv_t parsed_ipv;

  parsed_ipv.ipversion = 4;
  parsed_ipv.ipv4 = swap32 (addr->s_addr);
  r = IP2Location_get_ipv4_record (ip2loc_handle, NULL, IP2LOC_FLAGS, parsed_ipv);

  memset (out, '\0', sizeof(*out));
  if (!r)
     return (FALSE);

  TRACE (3, "Record for IPv4-number %s; country_short: \"%.2s\"\n",
         INET_util_get_ip_num(addr, NULL), r->country_short);
  return ip2loc_get_common (out, r);
}

/**
 * This avoids the call to `inet_pton()` since the passed
 * `*addr` should be a valid IPv6-address.
 */
BOOL ip2loc_get_ipv6_entry (const struct in6_addr *addr, struct ip2loc_entry *out)
{
  IP2LocationRecord *r;
  ipv_t parsed_ipv;

  if (IN6_IS_ADDR_V4MAPPED(addr))
  {
    parsed_ipv.ipversion = 4;
    parsed_ipv.ipv4 = *(const uint32_t*) addr;
  }
  else
  {
    parsed_ipv.ipversion = 6;
    memcpy (&parsed_ipv.ipv6, addr, sizeof(*addr));
  }
  r = IP2Location_get_ipv6_record (ip2loc_handle, NULL, IP2LOC_FLAGS, parsed_ipv);

  memset (out, '\0', sizeof(*out));
  if (!r)
     return (FALSE);

  TRACE (3, "Record for IPv6-number %s; country_short: \"%.2s\"\n",
         INET_util_get_ip_num(NULL, (const struct in6_addr*)&parsed_ipv.ipv6),
         r->country_short);
  return ip2loc_get_common (out, r);
}

/**
 * Return number of index-errors to the shared memory area.
 *
 * This seems to be an issue when >= 2 processes are accessing the
 * `g_cfg.ip2location_bin_file` at the same time. The latter process
 * (using wsock_trace.dll) will get junk returned for locations.
 * This is just an attempt to detect it.
 */
DWORD ip2loc_index_errors (void)
{
  return (DWORD)IP2Location_DB_index_errors();
}

#else /* USE_IP2LOCATION */

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

BOOL ip2loc_get_entry (const char *addr, struct ip2loc_entry *out)
{
  ARGSUSED (addr);
  ARGSUSED (out);
  return (FALSE);
}

BOOL ip2loc_get_ipv4_entry (const struct in_addr *addr, struct ip2loc_entry *out)
{
  ARGSUSED (addr);
  ARGSUSED (out);
  return (FALSE);
}

BOOL ip2loc_get_ipv6_entry (const struct in6_addr *addr, struct ip2loc_entry *out)
{
  ARGSUSED (addr);
  ARGSUSED (out);
  return (FALSE);
}

DWORD ip2loc_index_errors (void)
{
  return (0);
}
#endif  /* USE_IP2LOCATION */
