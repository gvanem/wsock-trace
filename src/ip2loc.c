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
 */

#include "common.h"
#include "init.h"
#include "in_addr.h"
#include "inet_util.h"
#include "geoip.h"

#include <stdint.h>

#if !defined(__CYGWIN__)
  #include <io.h>
  #include <fcntl.h>
  #include <share.h>
#endif

#if defined(__clang__)
  #pragma clang diagnostic ignored "-Wstrict-prototypes"

#elif defined(__CYGWIN__)
  GCC_PRAGMA (GCC diagnostic ignored "-Wpointer-to-int-cast")
#endif

/*
 * Previously ip2loc.c used the IP2Location-C-Library as a `git submodule`.
 * But now, I've simply pasted in the code from:
 *   IP2Location.c
 *   IP2Loc_DBInterface.c
 *   IP2Location.h
 *   IP2Loc_DBInterface.h
 *
 * below, patched and removed stuff not needed.
 *
 * IP2Location C library is distributed under MIT license
 * Copyright (c) 2013-2015 IP2Location.com. support at ip2location dot com
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the MIT license
 */

/* API version changes only if functions are added (release) or changed (minor/major)
 */
#define API_VERSION_MAJOR    8
#define API_VERSION_MINOR    0
#define API_VERSION_RELEASE  7
#define API_VERSION_NUMERIC  (((API_VERSION_MAJOR * 100) + API_VERSION_MINOR) * 100 + API_VERSION_RELEASE)

#define MAX_IPV4_RANGE       4294967295U
#define IPV4                 0
#define IPV6                 1

#define COUNTRYSHORT        0x00001
#define COUNTRYLONG         0x00002
#define REGION              0x00004
#define CITY                0x00008
#define ISP                 0x00010
#define LATITUDE            0x00020
#define LONGITUDE           0x00040
#define DOMAIN_             0x00080
#define ZIPCODE             0x00100
#define TIMEZONE            0x00200
#define NETSPEED            0x00400
#define IDDCODE             0x00800
#define AREACODE            0x01000
#define WEATHERSTATIONCODE  0x02000
#define WEATHERSTATIONNAME  0x04000
#define MCC                 0x08000
#define MNC                 0x10000
#define MOBILEBRAND         0x20000
#define ELEVATION           0x40000
#define USAGETYPE           0x80000

#define ALL                 (COUNTRYSHORT | COUNTRYLONG | REGION | CITY | ISP | LATITUDE | \
                             LONGITUDE | DOMAIN_ | ZIPCODE | TIMEZONE | NETSPEED | IDDCODE | \
                             AREACODE | WEATHERSTATIONCODE | WEATHERSTATIONNAME | MCC | MNC | \
                             MOBILEBRAND | ELEVATION | USAGETYPE)

#define INVALID_IPV4_ADDRESS  "INVALID IPV4 ADDRESS"
#define NOT_SUPPORTED         "This parameter is unavailable for selected data file. Please upgrade the data file."

#define IP2LOCATION_SHM       "IP2location_Shm"

/**\def IP2LOC_FLAGS
 * The flags used to look up a location record with a <i>short country</i>,
 * <i>long country</i> name, <i>region</i> and <i>city</i>.
 */
#define IP2LOC_FLAGS  (COUNTRYSHORT | COUNTRYLONG | REGION | CITY)

typedef struct {
        FILE    *filehandle;
        uint8_t  databasetype;
        uint8_t  databasecolumn;
        uint8_t  databaseday;
        uint8_t  databasemonth;
        uint8_t  databaseyear;
        uint32_t databasecount;
        uint32_t databaseaddr;
        uint32_t ipversion;
        uint32_t ipv4databasecount;
        uint32_t ipv4databaseaddr;
        uint32_t ipv6databasecount;
        uint32_t ipv6databaseaddr;
        uint32_t ipv4indexbaseaddr;
        uint32_t ipv6indexbaseaddr;
      } IP2Location;

typedef struct IP2LocationRecord {
        char  *country_short;
        char  *country_long;
        char  *region;
        char  *city;
        char  *isp;
        float  latitude;
        float  longitude;
        char  *domain;
        char  *zipcode;
        char  *timezone;
        char  *netspeed;
        char  *iddcode;
        char  *areacode;
        char  *weatherstationcode;
        char  *weatherstationname;
        char  *mcc;
        char  *mnc;
        char  *mobilebrand;
        float  elevation;
        char  *usagetype;
      } IP2LocationRecord;

typedef enum IP2Location_mem_type {
        IP2LOCATION_FILE_IO,
        IP2LOCATION_CACHE_MEMORY,
        IP2LOCATION_SHARED_MEMORY
      } IP2Location_mem_type;

typedef struct in6_addr_local {
        union {
          uint8_t addr8[16];
          uint8_t addr16[8];
        } u;
      } in6_addr_local;

typedef struct ipv_t {
        uint32_t              ipversion;
        uint32_t              ipv4;
        struct in6_addr_local ipv6;
      } ipv_t;

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

static IP2Location_mem_type  DB_access_type = IP2LOCATION_FILE_IO;
static void                 *cache_shm_ptr;
static uint64                cache_shm_max_index;
static uint64                cache_shm_index_errors;
static HANDLE                shm_fd;

static int32_t               IP2Location_DB_Load_to_mem (FILE *filehandle, void *cache_shm_ptr, int64_t size);
static int                   IP2Location_initialize (IP2Location *loc);
static struct in6_addr_local IP2Location_readIPv6Address (FILE *handle, uint32_t position);
static uint32_t              IP2Location_read32 (FILE *handle, uint32_t position);
static uint8_t               IP2Location_read8 (FILE *handle, uint32_t position);
static char                 *IP2Location_readStr (FILE *handle, uint32_t position);
static float                 IP2Location_readFloat (FILE *handle, uint32_t position);
static int32_t               IP2Location_DB_set_shared_memory (FILE *filehandle);
static int32_t               IP2Location_DB_close (FILE *filehandle);
static IP2Location          *IP2Location_open (const char *db);
static int                   IP2Location_open_mem (IP2Location *loc, IP2Location_mem_type);
static uint32_t              IP2Location_close (IP2Location *loc);
static IP2LocationRecord    *IP2Location_get_country_short (IP2Location *loc, const char *ip);
static IP2LocationRecord    *IP2Location_get_country_long (IP2Location *loc, const char *ip);
static IP2LocationRecord    *IP2Location_get_region (IP2Location *loc, const char *ip);
static IP2LocationRecord    *IP2Location_get_city (IP2Location *loc, const char *ip);
static IP2LocationRecord    *IP2Location_get_isp (IP2Location *loc, const char *ip);
static IP2LocationRecord    *IP2Location_get_latitude (IP2Location *loc, const char *ip);
static IP2LocationRecord    *IP2Location_get_longitude (IP2Location *loc, const char *ip);
static IP2LocationRecord    *IP2Location_get_domain (IP2Location *loc, const char *ip);
static IP2LocationRecord    *IP2Location_get_zipcode (IP2Location *loc, const char *ip);
static IP2LocationRecord    *IP2Location_get_timezone (IP2Location *loc, const char *ip);
static IP2LocationRecord    *IP2Location_get_netspeed (IP2Location *loc, const char *ip);
static IP2LocationRecord    *IP2Location_get_iddcode (IP2Location *loc, const char *ip);
static IP2LocationRecord    *IP2Location_get_areacode (IP2Location *loc, const char *ip);
static IP2LocationRecord    *IP2Location_get_weatherstationcode (IP2Location *loc, const char *ip);
static IP2LocationRecord    *IP2Location_get_weatherstationname (IP2Location *loc, const char *ip);
static IP2LocationRecord    *IP2Location_get_mcc (IP2Location *loc, const char *ip);
static IP2LocationRecord    *IP2Location_get_mnc (IP2Location *loc, const char *ip);
static IP2LocationRecord    *IP2Location_get_mobilebrand (IP2Location *loc, const char *ip);
static IP2LocationRecord    *IP2Location_get_elevation (IP2Location *loc, const char *ip);
static IP2LocationRecord    *IP2Location_get_usagetype (IP2Location *loc, const char *ip);
static IP2LocationRecord    *IP2Location_get_all (IP2Location *loc, const char *ip);
static unsigned long int     IP2Location_api_version_num (void);
static const char           *IP2Location_api_version_string (void);
static void                  IP2Location_free_record (IP2LocationRecord *record);

#ifdef NOT_NEEDED
  static int32_t             IP2Location_DB_set_memory_cache (FILE *filehandle);
#endif

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

  TRACE (2, "ip2loc: Success: %s\n"
            "        Database has %s entries. API-version: %s, size: %s bytes\n"
            "        Date: %02d-%02d-%04d, IPvX: %d, "
            "IPv4-count: %u, IPv6-count: %u (is_IPv4_only: %d, is_IPv6_only: %d).\n",
         file,
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

/*
 * Since we do not want a dependency on `wsock_trace.c` and it's `inet_addr()`,
 * just create a local version here.
 */
static u_long local_inet_addr (const char *ip_str)
{
  const char *s = ip_str;
  u_long      ip = 0;
  int         i;

  for (i = 24; i >= 0; i -= 8)
  {
    int cur = atoi (s);

    ip |= (u_long)(cur & 0xFF) << i;
    if (!i)
       return (ip);

    s = strchr (s, '.');
    if (!s)
       break;      /* return 0 on error */
    s++;
  }
  return (0);
}

static uint8_t COUNTRY_POSITION[25]             = { 0, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2 };
static uint8_t REGION_POSITION[25]              = { 0, 0, 0, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3 };
static uint8_t CITY_POSITION[25]                = { 0, 0, 0, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4 };
static uint8_t ISP_POSITION[25]                 = { 0, 0, 3, 0, 5, 0, 7, 5, 7, 0, 8, 0, 9, 0, 9, 0, 9, 0, 9, 7, 9, 0, 9, 7, 9 };
static uint8_t LATITUDE_POSITION[25]            = { 0, 0, 0, 0, 0, 5, 5, 0, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5 };
static uint8_t LONGITUDE_POSITION[25]           = { 0, 0, 0, 0, 0, 6, 6, 0, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6 };
static uint8_t DOMAIN_POSITION[25]              = { 0, 0, 0, 0, 0, 0, 0, 6, 8, 0, 9, 0, 10,0, 10, 0, 10, 0, 10, 8, 10, 0, 10, 8, 10 };
static uint8_t ZIPCODE_POSITION[25]             = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 7, 7, 7, 7, 0, 7, 7, 7, 0, 7, 0, 7, 7, 7, 0, 7 };
static uint8_t TIMEZONE_POSITION[25]            = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 8, 8, 7, 8, 8, 8, 7, 8, 0, 8, 8, 8, 0, 8 };
static uint8_t NETSPEED_POSITION[25]            = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 8, 11,0, 11,8, 11, 0, 11, 0, 11, 0, 11 };
static uint8_t IDDCODE_POSITION[25]             = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9, 12, 0, 12, 0, 12, 9, 12, 0, 12 };
static uint8_t AREACODE_POSITION[25]            = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 10 ,13 ,0, 13, 0, 13, 10, 13, 0, 13 };
static uint8_t WEATHERSTATIONCODE_POSITION[25]  = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9, 14, 0, 14, 0, 14, 0, 14 };
static uint8_t WEATHERSTATIONNAME_POSITION[25]  = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 10, 15, 0, 15, 0, 15, 0, 15 };
static uint8_t MCC_POSITION[25]                 = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9, 16, 0, 16, 9, 16 };
static uint8_t MNC_POSITION[25]                 = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 10,17, 0, 17, 10, 17 };
static uint8_t MOBILEBRAND_POSITION[25]         = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 11,18, 0, 18, 11, 18 };
static uint8_t ELEVATION_POSITION[25]           = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 11, 19, 0, 19 };
static uint8_t USAGETYPE_POSITION[25]           = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 12, 20 };

static IP2LocationRecord *IP2Location_new_record (void);
static uint32_t IP2Location_ip2no (const char* ip);
static struct in6_addr_local  IP2Location_ipv6_to_no (const char *ipaddr);
static int IP2Location_ip_is_ipv4 (const char *ipaddr);
static int IP2Location_ip_is_ipv6 (const char *ipaddr);
static IP2LocationRecord *IP2Location_get_record (IP2Location *loc, const char *ip, uint32_t mode);
static IP2LocationRecord *IP2Location_get_ipv6_record (IP2Location *loc, const char *ipstring, uint32_t mode, ipv_t parsed_ipv);
static int32_t openMemFlag = 0;

// Open the IP2Location database file
static IP2Location *IP2Location_open (const char *db)
{
    FILE *f;
    IP2Location *loc;

#if !defined(__CYGWIN__)
    int fd = _sopen (db, O_BINARY, SH_DENYWR, S_IREAD);

    if (fd < 0)
    {
        printf("IP2Location library error in opening database %s (errno=%d).\n", db, errno);
        return NULL;
    }
    f = fdopen (fd, "rb");
#else
    f = fopen (db, "rb");
#endif

    if (f == NULL)
    {
        printf("IP2Location library error in opening database %s.\n", db);
        return NULL;
    }

    loc = (IP2Location *) calloc(1, sizeof(IP2Location));
    loc->filehandle = f;

    IP2Location_initialize(loc);
    return loc;
}

// This function to set the DB access type.
static int32_t IP2Location_open_mem (IP2Location *loc, IP2Location_mem_type mtype)
{
    if( loc == NULL)
        return -1;

    // Once IP2Location_open_mem is called, it can not be called again till IP2Location_close is called
    if(openMemFlag != 0)
        return -1;
    openMemFlag = 1;

    if(mtype == IP2LOCATION_FILE_IO)
    {
        return 0; //Just return, by default its IP2LOCATION_FILE_IO
    }
#ifdef NOT_NEEDED
    else if(mtype == IP2LOCATION_CACHE_MEMORY)
    {
        return IP2Location_DB_set_memory_cache(loc->filehandle);
    }
#endif
    else if (mtype == IP2LOCATION_SHARED_MEMORY)
    {
        return IP2Location_DB_set_shared_memory(loc->filehandle);
    }
    else
        return -1;
}

// Close the IP2Location database file
static uint32_t IP2Location_close (IP2Location *loc)
{
    openMemFlag = 0;
    if (loc != NULL)
    {
        IP2Location_DB_close(loc->filehandle);
        free(loc);
    }

    return 0;
}

// Startup
static int IP2Location_initialize (IP2Location *loc)
{
    loc->databasetype   = IP2Location_read8(loc->filehandle, 1);
    loc->databasecolumn = IP2Location_read8(loc->filehandle, 2);
    loc->databaseyear   = IP2Location_read8(loc->filehandle, 3);
    loc->databasemonth  = IP2Location_read8(loc->filehandle, 4);
    loc->databaseday    = IP2Location_read8(loc->filehandle, 5);

    loc->databasecount  = IP2Location_read32(loc->filehandle, 6);
    loc->databaseaddr   = IP2Location_read32(loc->filehandle, 10);
    loc->ipversion      = IP2Location_read32(loc->filehandle, 14);

    loc->ipv4databasecount = IP2Location_read32(loc->filehandle, 6);
    loc->ipv4databaseaddr  = IP2Location_read32(loc->filehandle, 10);
    loc->ipv6databasecount = IP2Location_read32(loc->filehandle, 14);
    loc->ipv6databaseaddr  = IP2Location_read32(loc->filehandle, 18);

    loc->ipv4indexbaseaddr = IP2Location_read32(loc->filehandle, 22);
    loc->ipv6indexbaseaddr = IP2Location_read32(loc->filehandle, 26);

    return 0;
}

// Compare to ipv6 address
static int ipv6_compare (struct in6_addr_local *addr1, struct in6_addr_local *addr2)
{
    int i, ret = 0;
    for(i = 0 ; i < 16 ; i++ )
    {
        if(addr1->u.addr8[i] > addr2->u.addr8[i])
        {
            ret = 1;
            break;
        }
        else if(addr1->u.addr8[i] < addr2->u.addr8[i])
        {
            ret = -1;
            break;
        }
    }

    return ret;
}


// Parses IPv[46] addresses and returns both the version of address
// and binary address used for searching
// You can implement domain name lookup here as well
// ipversion will be -1 on error (or something other than 4 or 6)
static ipv_t IP2Location_parse_addr (const char *addr)
{
    ipv_t parsed;
    if (IP2Location_ip_is_ipv4(addr))
    {
        parsed.ipversion = 4;
        parsed.ipv4 = IP2Location_ip2no(addr);
    }
    else if (IP2Location_ip_is_ipv6(addr))
    {
        // Parse the v6 address
        inet_pton(AF_INET6, addr, &parsed.ipv6);
        if (parsed.ipv6.u.addr8[0] == 0 && parsed.ipv6.u.addr8[1] == 0 && parsed.ipv6.u.addr8[2] == 0 &&
                parsed.ipv6.u.addr8[3] == 0 && parsed.ipv6.u.addr8[4] == 0 && parsed.ipv6.u.addr8[5] == 0 &&
                parsed.ipv6.u.addr8[6] == 0 && parsed.ipv6.u.addr8[7] == 0 && parsed.ipv6.u.addr8[8] == 0 &&
                parsed.ipv6.u.addr8[9] == 0 && parsed.ipv6.u.addr8[10] == 255 && parsed.ipv6.u.addr8[11] == 255)
        {
            // IPv4 address in IPv6 format (::ffff:0.0.0.0 or ::ffff:00:00)
            parsed.ipversion = 4;
            parsed.ipv4 = (parsed.ipv6.u.addr8[12] << 24) + (parsed.ipv6.u.addr8[13] << 16) + (parsed.ipv6.u.addr8[14] << 8) + parsed.ipv6.u.addr8[15];
        }
        else
        {
            // pure IPv6 format
            parsed.ipversion = 6;
        }
    }
    else
    {
        parsed.ipversion = -1;
    }

    return parsed;
}

// Get country code
static IP2LocationRecord *IP2Location_get_country_short (IP2Location *loc, const char *ip)
{
    return IP2Location_get_record(loc, ip, COUNTRYSHORT);
}

// Get country name
static IP2LocationRecord *IP2Location_get_country_long (IP2Location *loc, const char *ip)
{
    return IP2Location_get_record(loc, ip, COUNTRYLONG);
}

// Get the name of state/region
static IP2LocationRecord *IP2Location_get_region (IP2Location *loc, const char *ip)
{
    return IP2Location_get_record(loc, ip, REGION);
}

// Get city name
static IP2LocationRecord *IP2Location_get_city (IP2Location *loc, const char *ip)
{
    return IP2Location_get_record(loc, ip, CITY);
}

// Get ISP name
static IP2LocationRecord *IP2Location_get_isp(IP2Location *loc, const char *ip)
{
    return IP2Location_get_record(loc, ip, ISP);
}

// Get latitude
static IP2LocationRecord *IP2Location_get_latitude (IP2Location *loc, const char *ip)
{
    return IP2Location_get_record(loc, ip, LATITUDE);
}

// Get longitude
static IP2LocationRecord *IP2Location_get_longitude (IP2Location *loc, const char *ip)
{
    return IP2Location_get_record(loc, ip, LONGITUDE);
}

// Get domain name
static IP2LocationRecord *IP2Location_get_domain(IP2Location *loc, const char *ip)
{
    return IP2Location_get_record(loc, ip, DOMAIN_);
}

// Get ZIP code
static IP2LocationRecord *IP2Location_get_zipcode (IP2Location *loc, const char *ip)
{
    return IP2Location_get_record(loc, ip, ZIPCODE);
}

// Get time zone
static IP2LocationRecord *IP2Location_get_timezone (IP2Location *loc, const char *ip)
{
    return IP2Location_get_record(loc, ip, TIMEZONE);
}

// Get net speed
static IP2LocationRecord *IP2Location_get_netspeed (IP2Location *loc, const char *ip)
{
    return IP2Location_get_record(loc, ip, NETSPEED);
}

// Get IDD code
static IP2LocationRecord *IP2Location_get_iddcode (IP2Location *loc, const char *ip)
{
    return IP2Location_get_record(loc, ip, IDDCODE);
}

// Get area code
static IP2LocationRecord *IP2Location_get_areacode (IP2Location *loc, const char *ip)
{
    return IP2Location_get_record(loc, ip, AREACODE);
}

// Get weather station code
static IP2LocationRecord *IP2Location_get_weatherstationcode (IP2Location *loc, const char *ip)
{
    return IP2Location_get_record(loc, ip, WEATHERSTATIONCODE);
}

// Get weather station name
static IP2LocationRecord *IP2Location_get_weatherstationname (IP2Location *loc, const char *ip)
{
    return IP2Location_get_record(loc, ip, WEATHERSTATIONNAME);
}

// Get mobile country code
static IP2LocationRecord *IP2Location_get_mcc (IP2Location *loc, const char *ip)
{
    return IP2Location_get_record(loc, ip, MCC);
}

// Get mobile national code
static IP2LocationRecord *IP2Location_get_mnc (IP2Location *loc, const char *ip)
{
    return IP2Location_get_record(loc, ip, MNC);
}

// Get mobile carrier brand
static IP2LocationRecord *IP2Location_get_mobilebrand (IP2Location *loc, const char *ip)
{
    return IP2Location_get_record(loc, ip, MOBILEBRAND);
}

// Get elevation
static IP2LocationRecord *IP2Location_get_elevation(IP2Location *loc, const char *ip)
{
    return IP2Location_get_record(loc, ip, ELEVATION);
}

// Get usage type
static IP2LocationRecord *IP2Location_get_usagetype (IP2Location *loc, const char *ip)
{
    return IP2Location_get_record(loc, ip, USAGETYPE);
}

// Get all records of an IP address
static IP2LocationRecord *IP2Location_get_all (IP2Location *loc, const char *ip)
{
    return IP2Location_get_record(loc, ip, ALL);
}

// Fill the record fields with error message
static IP2LocationRecord *IP2Location_bad_record (const char *message)
{
    IP2LocationRecord *record = IP2Location_new_record();
    record->country_short = strdup(message);
    record->country_long = strdup(message);
    record->region = strdup(message);
    record->city = strdup(message);
    record->isp = strdup(message);
    record->latitude = 0;
    record->longitude = 0;
    record->domain = strdup(message);
    record->zipcode = strdup(message);
    record->timezone = strdup(message);
    record->netspeed = strdup(message);
    record->iddcode = strdup(message);
    record->areacode = strdup(message);
    record->weatherstationcode = strdup(message);
    record->weatherstationname = strdup(message);
    record->mcc = strdup(message);
    record->mnc = strdup(message);
    record->mobilebrand = strdup(message);
    record->elevation = 0;
    record->usagetype = strdup(message);

    return record;
}

// Read the record data
static IP2LocationRecord *IP2Location_read_record (IP2Location *loc, uint32_t rowaddr, uint32_t mode)
{
    uint8_t dbtype = loc->databasetype;
    FILE *handle = loc->filehandle;
    IP2LocationRecord *record = IP2Location_new_record();

    if ((mode & COUNTRYSHORT) && (COUNTRY_POSITION[dbtype] != 0))
    {
        record->country_short = IP2Location_readStr(handle, IP2Location_read32(handle, rowaddr + 4 * (COUNTRY_POSITION[dbtype]-1)));
    }
    else
    {
        record->country_short = strdup(NOT_SUPPORTED);
    }

    if ((mode & COUNTRYLONG) && (COUNTRY_POSITION[dbtype] != 0))
    {
        record->country_long = IP2Location_readStr(handle, IP2Location_read32(handle, rowaddr + 4 * (COUNTRY_POSITION[dbtype]-1))+3);
    }
    else
    {
        record->country_long = strdup(NOT_SUPPORTED);
    }

    if ((mode & REGION) && (REGION_POSITION[dbtype] != 0))
    {
        record->region = IP2Location_readStr(handle, IP2Location_read32(handle, rowaddr + 4 * (REGION_POSITION[dbtype]-1)));
    }
    else
    {
        record->region = strdup(NOT_SUPPORTED);
    }

    if ((mode & CITY) && (CITY_POSITION[dbtype] != 0))
    {
        record->city = IP2Location_readStr(handle, IP2Location_read32(handle, rowaddr + 4 * (CITY_POSITION[dbtype]-1)));
    }
    else
    {
        record->city = strdup(NOT_SUPPORTED);
    }

    if ((mode & ISP) && (ISP_POSITION[dbtype] != 0))
    {
        record->isp = IP2Location_readStr(handle, IP2Location_read32(handle, rowaddr + 4 * (ISP_POSITION[dbtype]-1)));
    }
    else
    {
        record->isp = strdup(NOT_SUPPORTED);
    }

    if ((mode & LATITUDE) && (LATITUDE_POSITION[dbtype] != 0))
    {
        record->latitude = IP2Location_readFloat(handle, rowaddr + 4 * (LATITUDE_POSITION[dbtype]-1));
    }
    else
    {
        record->latitude = 0.0;
    }

    if ((mode & LONGITUDE) && (LONGITUDE_POSITION[dbtype] != 0))
    {
        record->longitude = IP2Location_readFloat(handle, rowaddr + 4 * (LONGITUDE_POSITION[dbtype]-1));
    }
    else
    {
        record->longitude = 0.0;
    }

    if ((mode & DOMAIN_) && (DOMAIN_POSITION[dbtype] != 0))
    {
        record->domain = IP2Location_readStr(handle, IP2Location_read32(handle, rowaddr + 4 * (DOMAIN_POSITION[dbtype]-1)));
    }
    else
    {
        record->domain = strdup(NOT_SUPPORTED);
    }

    if ((mode & ZIPCODE) && (ZIPCODE_POSITION[dbtype] != 0))
    {
        record->zipcode = IP2Location_readStr(handle, IP2Location_read32(handle, rowaddr + 4 * (ZIPCODE_POSITION[dbtype]-1)));
    }
    else
    {
        record->zipcode = strdup(NOT_SUPPORTED);
    }

    if ((mode & TIMEZONE) && (TIMEZONE_POSITION[dbtype] != 0))
    {
        record->timezone = IP2Location_readStr(handle, IP2Location_read32(handle, rowaddr + 4 * (TIMEZONE_POSITION[dbtype]-1)));
    }
    else
    {
        record->timezone = strdup(NOT_SUPPORTED);
    }

    if ((mode & NETSPEED) && (NETSPEED_POSITION[dbtype] != 0))
    {
        record->netspeed = IP2Location_readStr(handle, IP2Location_read32(handle, rowaddr + 4 * (NETSPEED_POSITION[dbtype]-1)));
    }
    else
    {
        record->netspeed = strdup(NOT_SUPPORTED);
    }

    if ((mode & IDDCODE) && (IDDCODE_POSITION[dbtype] != 0))
    {
        record->iddcode = IP2Location_readStr(handle, IP2Location_read32(handle, rowaddr + 4 * (IDDCODE_POSITION[dbtype]-1)));
    }
    else
    {
        record->iddcode = strdup(NOT_SUPPORTED);
    }

    if ((mode & AREACODE) && (AREACODE_POSITION[dbtype] != 0))
    {
        record->areacode = IP2Location_readStr(handle, IP2Location_read32(handle, rowaddr + 4 * (AREACODE_POSITION[dbtype]-1)));
    }
    else
    {
        record->areacode = strdup(NOT_SUPPORTED);
    }

    if ((mode & WEATHERSTATIONCODE) && (WEATHERSTATIONCODE_POSITION[dbtype] != 0))
    {
        record->weatherstationcode = IP2Location_readStr(handle, IP2Location_read32(handle, rowaddr + 4 * (WEATHERSTATIONCODE_POSITION[dbtype]-1)));
    }
    else
    {
        record->weatherstationcode = strdup(NOT_SUPPORTED);
    }

    if ((mode & WEATHERSTATIONNAME) && (WEATHERSTATIONNAME_POSITION[dbtype] != 0))
    {
        record->weatherstationname = IP2Location_readStr(handle, IP2Location_read32(handle, rowaddr + 4 * (WEATHERSTATIONNAME_POSITION[dbtype]-1)));
    }
    else
    {
        record->weatherstationname = strdup(NOT_SUPPORTED);
    }

    if ((mode & MCC) && (MCC_POSITION[dbtype] != 0))
    {
        record->mcc = IP2Location_readStr(handle, IP2Location_read32(handle, rowaddr + 4 * (MCC_POSITION[dbtype]-1)));
    }
    else
    {
        record->mcc = strdup(NOT_SUPPORTED);
    }

    if ((mode & MNC) && (MNC_POSITION[dbtype] != 0))
    {
        record->mnc = IP2Location_readStr(handle, IP2Location_read32(handle, rowaddr + 4 * (MNC_POSITION[dbtype]-1)));
    }
    else
    {
        record->mnc = strdup(NOT_SUPPORTED);
    }

    if ((mode & MOBILEBRAND) && (MOBILEBRAND_POSITION[dbtype] != 0))
    {
        record->mobilebrand = IP2Location_readStr(handle, IP2Location_read32(handle, rowaddr + 4 * (MOBILEBRAND_POSITION[dbtype]-1)));
    }
    else
    {
        record->mobilebrand = strdup(NOT_SUPPORTED);
    }

    if ((mode & ELEVATION) && (ELEVATION_POSITION[dbtype] != 0))
    {
        record->elevation = atof(IP2Location_readStr(handle, IP2Location_read32(handle, rowaddr + 4 * (ELEVATION_POSITION[dbtype]-1))));
    }
    else
    {
        record->elevation = 0.0;
    }

    if ((mode & USAGETYPE) && (USAGETYPE_POSITION[dbtype] != 0))
    {
        record->usagetype = IP2Location_readStr(handle, IP2Location_read32(handle, rowaddr + 4 * (USAGETYPE_POSITION[dbtype]-1)));
    }
    else
    {
        record->usagetype = strdup(NOT_SUPPORTED);
    }
    return record;
}

// Get record for a IPv6 from database
static IP2LocationRecord *IP2Location_get_ipv6_record (IP2Location *loc, const char *ipstring, uint32_t mode, ipv_t parsed_ipv)
{
    FILE *handle = loc->filehandle;
    uint32_t baseaddr = loc->ipv6databaseaddr;
    uint32_t dbcolumn = loc->databasecolumn;
    uint32_t ipv6indexbaseaddr = loc->ipv6indexbaseaddr;

    uint32_t low = 0;
    uint32_t high = loc->ipv6databasecount;
    uint32_t mid = 0;

    struct in6_addr_local ipfrom;
    struct in6_addr_local ipto;
    struct in6_addr_local ipno;

    ipno = parsed_ipv.ipv6;

    if (!high)
    {
        return NULL;
    }

    if (ipv6indexbaseaddr > 0)
    {
        // use the index table
        uint32_t ipnum1 = (ipno.u.addr8[0] * 256) + ipno.u.addr8[1];
        uint32_t indexpos = ipv6indexbaseaddr + (ipnum1 << 3);

        low = IP2Location_read32(handle, indexpos);
        high = IP2Location_read32(handle, indexpos + 4);

    }

    while (low <= high)
    {
        mid = (uint32_t)((low + high) >> 1);
        ipfrom = IP2Location_readIPv6Address(handle, baseaddr + mid * (dbcolumn * 4 + 12));
        ipto = IP2Location_readIPv6Address(handle, baseaddr + ( mid + 1 ) * (dbcolumn * 4 + 12));

        if( (ipv6_compare(&ipno, &ipfrom) >= 0) && (ipv6_compare(&ipno, &ipto) < 0))
        {
            return IP2Location_read_record(loc, baseaddr + mid * (dbcolumn * 4 + 12) + 12, mode);
        }
        else
        {
            if ( ipv6_compare(&ipno, &ipfrom) < 0)
            {
                high = mid - 1;
            }
            else
            {
                low = mid + 1;
            }
        }
    }
    return NULL;
}

// Get record for a IPv4 from database
static IP2LocationRecord *IP2Location_get_ipv4_record (IP2Location *loc, const char *ipstring, uint32_t mode, ipv_t parsed_ipv)
{
    FILE *handle = loc->filehandle;
    uint32_t baseaddr = loc->ipv4databaseaddr;
    uint32_t dbcolumn = loc->databasecolumn;
    uint32_t ipv4indexbaseaddr = loc->ipv4indexbaseaddr;

    uint32_t low = 0;
    uint32_t high = loc->ipv4databasecount;
    uint32_t mid = 0;

    uint32_t ipno;
    uint32_t ipfrom;
    uint32_t ipto;

    ipno = parsed_ipv.ipv4;
    if (ipno == (uint32_t) MAX_IPV4_RANGE)
    {
        ipno = ipno - 1;
    }

    if (ipv4indexbaseaddr > 0)
    {
        // use the index table
        uint32_t ipnum1n2 = (uint32_t) ipno >> 16;
        uint32_t indexpos = ipv4indexbaseaddr + (ipnum1n2 << 3);

        low = IP2Location_read32(handle, indexpos);
        high = IP2Location_read32(handle, indexpos + 4);
    }

    while (low <= high)
    {
        mid = (uint32_t)((low + high) >> 1);
        ipfrom = IP2Location_read32(handle, baseaddr + mid * dbcolumn * 4);
        ipto = IP2Location_read32(handle, baseaddr + (mid + 1) * dbcolumn * 4);

        if ((ipno >= ipfrom) && (ipno < ipto))
        {
            return IP2Location_read_record(loc, baseaddr + (mid * dbcolumn * 4), mode);
        }
        else
        {
            if ( ipno < ipfrom )
            {
                high = mid - 1;
            }
            else
            {
                low = mid + 1;
            }
        }
    }
    return NULL;
}

// Get the location data
static IP2LocationRecord *IP2Location_get_record (IP2Location *loc, const char *ipstring, uint32_t mode)
{
    ipv_t parsed_ipv = IP2Location_parse_addr(ipstring);
    if (parsed_ipv.ipversion == 4)
    {
      // process IPv4
      return IP2Location_get_ipv4_record(loc, ipstring, mode, parsed_ipv);
    }
    if (parsed_ipv.ipversion == 6)
    {
        // process IPv6
        return IP2Location_get_ipv6_record(loc, ipstring, mode, parsed_ipv);
    }
    else
    {
        return IP2Location_bad_record(INVALID_IPV4_ADDRESS);
    }
}

// Initialize the record object
static IP2LocationRecord *IP2Location_new_record (void)
{
    return calloc(1, sizeof(IP2LocationRecord));
}

// Free the record object
static void IP2Location_free_record (IP2LocationRecord *record)
{
    if (record == NULL)
       return;

    free (record->city);
    free (record->country_long);
    free (record->country_short);
    free (record->domain);
    free (record->isp);
    free (record->region);
    free (record->zipcode);
    free (record->timezone);
    free (record->netspeed);
    free (record->iddcode);
    free (record->areacode);
    free (record->weatherstationcode);
    free (record->weatherstationname);
    free (record->mcc);
    free (record->mnc);
    free (record->mobilebrand);
    free (record->usagetype);
    free (record);
}

// Convert the IP address (v4) into number
static uint32_t IP2Location_ip2no (const char *ipstring)
{
    uint32_t       ip = local_inet_addr (ipstring);
    const uint8_t *ptr = (const uint8_t*) &ip;
    uint32_t       a = 0;

    if (ipstring != NULL)
    {
        a =  (uint8_t)(ptr[3]);
        a += (uint8_t)(ptr[2]) * 256;
        a += (uint8_t)(ptr[1]) * 256 * 256;
        a += (uint8_t)(ptr[0]) * 256 * 256 * 256;
    }
    return a;
}

// Check if this was an IPv4 address
static int IP2Location_ip_is_ipv4 (const char *ipaddr)
{
    struct sockaddr_in sa;
    return inet_pton(AF_INET, ipaddr, &sa.sin_addr);
}

// Check if this was an IPv6 address
static int IP2Location_ip_is_ipv6 (const char* ipaddr)
{
    struct in6_addr_local ipv6;
    return  inet_pton(AF_INET6, ipaddr, &ipv6);
}

// Return API version numeric
static unsigned long int IP2Location_api_version_num (void)
{
    return (API_VERSION_NUMERIC);
}

// Return API version as string
static const char *IP2Location_api_version_string (void)
{
  #define _STR2(x) #x
  #define _STR(x)  _STR2(x)

  return (_STR(API_VERSION_MAJOR) "." _STR(API_VERSION_MINOR) "." _STR(API_VERSION_RELEASE));
}

#ifdef NOT_NEEDED

// Set the DB access method as memory cache and read the file into cache
static int32_t IP2Location_DB_set_memory_cache (FILE *filehandle)
{
    struct stat statbuf;
    DB_access_type = IP2LOCATION_CACHE_MEMORY;

    if(fstat(fileno(filehandle), &statbuf) == -1)
    {
        DB_access_type = IP2LOCATION_FILE_IO;
        return -1;
    }

    if ( (cache_shm_ptr = malloc(statbuf.st_size + 1)) == NULL )
    {
        DB_access_type = IP2LOCATION_FILE_IO;
        return -1;
    }
    if( IP2Location_DB_Load_to_mem(filehandle, cache_shm_ptr, statbuf.st_size) == -1 )
    {
        DB_access_type = IP2LOCATION_FILE_IO;
        free(cache_shm_ptr);
        return -1;
    }
    return 0;
}
#endif /* NOT_NEEDED */

// Set the DB access method as shared memory

static int32_t IP2Location_DB_set_shared_memory (FILE *filehandle)
{
    struct stat statbuf;
    int32_t DB_loaded = 1;

    DB_access_type = IP2LOCATION_SHARED_MEMORY;

    if(fstat(fileno(filehandle), &statbuf) == -1)
    {
        TRACE (1, "fstat() failed. Reverting to slower IP2LOCATION_FILE_IO mode.\n");
        DB_access_type = IP2LOCATION_FILE_IO;
        return -1;
    }

    shm_fd = CreateFileMapping(
                 INVALID_HANDLE_VALUE,
                 NULL,
                 PAGE_READWRITE,
                 0,
                 statbuf.st_size + 1,
                 TEXT(IP2LOCATION_SHM));
    if(shm_fd == NULL)
    {
        TRACE (1, "CreateFileMapping() failed. Reverting to slower IP2LOCATION_FILE_IO mode.\n");
        DB_access_type = IP2LOCATION_FILE_IO;
        return -1;
    }

    DB_loaded = (GetLastError() == ERROR_ALREADY_EXISTS);

    cache_shm_ptr = MapViewOfFile(
                        shm_fd,
                        FILE_MAP_WRITE,
                        0,
                        0,
                        0);

    if(cache_shm_ptr == NULL)
    {
        TRACE (1, "MapViewOfFile() failed. Reverting to slower IP2LOCATION_FILE_IO mode.\n");
        UnmapViewOfFile(cache_shm_ptr);
        DB_access_type = IP2LOCATION_FILE_IO;
        return -1;
    }

    if( DB_loaded == 0 )
    {
        if ( IP2Location_DB_Load_to_mem(filehandle, cache_shm_ptr, statbuf.st_size) == -1 )
        {
            TRACE (1, "IP2Location_DB_Load_to_mem() failed. Reverting to slower IP2LOCATION_FILE_IO mode.\n");
            UnmapViewOfFile(cache_shm_ptr);
            CloseHandle(shm_fd);
            DB_access_type = IP2LOCATION_FILE_IO;
            return -1;
        }
    }
    else
      TRACE (1, "CreateFileMapping() already exist. Sharing %p file-mapping with another process?\n", cache_shm_ptr);

    cache_shm_max_index = (uint64)cache_shm_ptr + statbuf.st_size;
    return 0;
}

// Load the DB file into shared/cache memory
static int32_t IP2Location_DB_Load_to_mem (FILE *filehandle, void *memory, int64_t size)
{
    fseek(filehandle, SEEK_SET, 0);
    if ( fread(memory, size, 1, filehandle) != 1 )
        return -1;
    return 0;
}

// Close the corresponding memory, based on the opened option.
static int32_t IP2Location_DB_close (FILE *filehandle)
{
    struct stat statbuf;

#ifdef NOT_NEEDED
    if ( DB_access_type == IP2LOCATION_CACHE_MEMORY )
    {
        if( cache_shm_ptr != NULL )
            free(cache_shm_ptr);
    }
    else
#endif
    if ( DB_access_type == IP2LOCATION_SHARED_MEMORY )
    {
        if( cache_shm_ptr != NULL )
        {
            UnmapViewOfFile(cache_shm_ptr);
            CloseHandle(shm_fd);
        }
    }

    if ( filehandle != NULL )
        fclose(filehandle);

    DB_access_type = IP2LOCATION_FILE_IO;
    return 0;
}

static struct in6_addr_local IP2Location_readIPv6Address (FILE *handle, uint32_t position)
{
    int i,j;
    struct in6_addr_local addr6;

    for( i = 0, j = 15; i < 16; i++, j-- )
    {
        addr6.u.addr8[i] = IP2Location_read8(handle, position + j);
    }
    return addr6;
}

static uint32_t IP2Location_read32 (FILE *handle, uint32_t position)
{
    uint8_t byte1 = 0;
    uint8_t byte2 = 0;
    uint8_t byte3 = 0;
    uint8_t byte4 = 0;
    uint8_t *cache_shm = cache_shm_ptr;
    size_t temp;

    // Read from file
    if (DB_access_type == IP2LOCATION_FILE_IO && handle != NULL)
    {
        fseek(handle, position-1, 0);
        temp = fread(&byte1, 1, 1, handle);
        temp = fread(&byte2, 1, 1, handle);
        temp = fread(&byte3, 1, 1, handle);
        temp = fread(&byte4, 1, 1, handle);
    }
    else
    {
        byte1 = cache_shm[ position - 1 ];
        byte2 = cache_shm[ position ];
        byte3 = cache_shm[ position + 1 ];
        byte4 = cache_shm[ position + 2 ];
    }
    return ((byte4 << 24) | (byte3 << 16) | (byte2 << 8) | (byte1));
}

static uint8_t IP2Location_read8 (FILE *handle, uint32_t position)
{
    uint8_t ret = 0;
    uint8_t *cache_shm = cache_shm_ptr;
    size_t temp;

    if (DB_access_type == IP2LOCATION_FILE_IO && handle != NULL)
    {
        fseek(handle, position-1, 0);
        temp = fread(&ret, 1, 1, handle);
    }
    else
    {
        if ((uint64)cache_shm + position - 1 <= cache_shm_max_index)
          ret = cache_shm[ position - 1 ];
        else
          cache_shm_index_errors++;
    }
    return ret;
}

static char *IP2Location_readStr (FILE *handle, uint32_t position)
{
    uint8_t size = 0;
    char *str = 0;
    uint8_t *cache_shm = cache_shm_ptr;
    size_t temp;

    if (DB_access_type == IP2LOCATION_FILE_IO && handle != NULL)
    {
        fseek(handle, position, 0);
        temp = fread(&size, 1, 1, handle);
        str = (char *)malloc(size+1);
        memset(str, 0, size+1);
        temp = fread(str, size, 1, handle);
    }
    else
    {
        size = cache_shm[ position ];
        str = (char *)malloc(size+1);
        memset(str, 0, size+1);
        memcpy((void*) str, (void*)&cache_shm[ position + 1 ], size);
    }
    return str;
}

static float IP2Location_readFloat (FILE *handle, uint32_t position)
{
    float ret = 0.0;
    uint8_t *cache_shm = cache_shm_ptr;
    size_t temp;

    if (DB_access_type == IP2LOCATION_FILE_IO && handle != NULL)
    {
        fseek(handle, position-1, 0);
        temp = fread(&ret, 4, 1, handle);
    }
    else
    {
        memcpy((void*) &ret, (void*)&cache_shm[ position - 1 ], 4);
    }
    return ret;
}

/* End of pasting in "IP2Location/libIP2Location" code */

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
 * This avoids the call to `inet_pton()` since the passed `*addr`
 * should be a valid IPv4-address.
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
  return cache_shm_index_errors;
}

