/**\file    geoip.h
 * \ingroup Geoip
 */
#ifndef _GEOIP_H
#define _GEOIP_H

#include "common.h"
#include "smartlist.h"
#include "init.h"

/**\struct ip4_node
 * The IPv4-address structure with a short-country.
 */
struct ipv4_node {
       DWORD low;         /**< The lowest address for this node */
       DWORD high;        /**< The highest address for this node */
       char  country[3];  /**< The short country name of this node */
     };

/**\struct ip4_node
 * The IPv6-address structure with a short-country.
 */
struct ipv6_node {
       struct in6_addr low;         /**< The lowest address for this node */
       struct in6_addr high;        /**< The highest address for this node */
       char            country[3];  /**< The short country name of this node */
     };

/**\struct ip2loc_entry
 * A structure as returned from functions in ip2loc.c.
 */
struct ip2loc_entry {
       char country_short [3];  /**< The short country name of this entry */
       char country_long [30];  /**< The full country name of this entry */
       char city   [40];        /**< The city name of this entry (if any) */
       char region [40];        /**< The region name of this entry (if any) */
     };

extern int         geoip_init (DWORD *_num4, DWORD *_num6);
extern void        geoip_exit (void);
extern const char *geoip_get_country_by_ipv4 (const struct in_addr *addr);
extern const char *geoip_get_country_by_ipv6 (const struct in6_addr *addr);
extern const char *geoip_get_long_name_by_id (int number);
extern const char *geoip_get_long_name_by_A2 (const char *short_name);
extern const char *geoip_get_location_by_ipv4 (const struct in_addr *ip4);
extern const char *geoip_get_location_by_ipv6 (const struct in6_addr *ip6);
extern uint64      geoip_get_stats_by_idx    (int idx);
extern uint64      geoip_get_stats_by_number (int number);

extern void geoip_num_unique_countries (DWORD *num_ip4,     DWORD *num_ip6,
                                        DWORD *num_ip2loc4, DWORD *num_ip2loc6);

/*
 * To build a version of geoip.exe that should support `g_cfg.geoip_use_generated`,
 * is bit of an "chicken and egg" problem. These 2 commands:
 * ```
 *   geoip.exe -4g geoip-gen4.c
 *   geoip.exe -6g geoip-gen6.c
 * ```
 *
 * will generate these files. Then `geoip.exe` (or `wsock_trace.dll`) must be rebuilt
 * and used with `g_cfg.geoip_use_generated = 1` to make use of this faster feature.
 *
 * This function is defined in `geoip.c`, but called from `geoip_smartlist_fixed_ipv4/6()`
 * in `gen-geoip4.c` and `geoip-gen6.c`.
 */
extern smartlist_t *geoip_smartlist_fixed (void *start, size_t el_size, unsigned num);

/** These generated functions are defined in `gen-geoip4.c` and `geoip-gen6.c`.
 */
extern smartlist_t *geoip_smartlist_fixed_ipv4 (void);
extern smartlist_t *geoip_smartlist_fixed_ipv6 (void);

/** Functions defined in `ip2loc.c`.
 */
extern BOOL  ip2loc_init (void);
extern void  ip2loc_exit (void);
extern BOOL  ip2loc_get_entry (const char *ip, struct ip2loc_entry *out);
extern BOOL  ip2loc_get_ipv4_entry (const struct in_addr *addr, struct ip2loc_entry *out);
extern BOOL  ip2loc_get_ipv6_entry (const struct in6_addr *addr, struct ip2loc_entry *out);
extern DWORD ip2loc_num_ipv4_entries (void);
extern DWORD ip2loc_num_ipv6_entries (void);
extern DWORD ip2loc_index_errors (void);

#endif

