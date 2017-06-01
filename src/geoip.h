#ifndef _GEOIP_H
#define _GEOIP_H

#include "common.h"
#include "smartlist.h"

struct ipv4_node {
       DWORD low;
       DWORD high;
       char  country[3];
     };

struct ipv6_node {
       struct in6_addr low;
       struct in6_addr high;
       char            country[3];
     };

extern int         geoip_init (DWORD *_num4, DWORD *_num6);
extern void        geoip_exit (void);
extern const char *geoip_get_country_by_ipv4 (const struct in_addr *addr);
extern const char *geoip_get_country_by_ipv6 (const struct in6_addr *addr);
extern const char *geoip_get_long_name_by_id (int number);
extern const char *geoip_get_long_name_by_A2 (const char *short_name);

extern int         geoip_addr_is_zero (const struct in_addr *ip4, const struct in6_addr *ip6);
extern int         geoip_addr_is_multicast (const struct in_addr *ip4, const struct in6_addr *ip6);
extern int         geoip_addr_is_special (const struct in_addr *ip4, const struct in6_addr *ip6, const char **remark);
extern int         geoip_addr_is_global (const struct in_addr *ip4, const struct in6_addr *ip6);

extern void        geoip_num_unique_countries (DWORD *num_ip4, DWORD *num_ip6);

/*
 * To build a version of geoip.exe that should support 'g_cfg.geoip_use_generated',
 * is bit of an "chicken and egg" problem. These 2 commands:
 *   geoip.exe -4g geoip-gen4.c
 *   geoip.exe -6g geoip-gen6.c
 *
 * will generate these files. Then geoip.exe (or wsock_trace.dll) must be rebuilt
 * and used with 'g_cfg.geoip_use_generated = 1' to make use of this faster feature.
 *
 * This function is defined in geoip.c, but called from 'geoip_smartlist_fixed_ipv4/6()'
 * in gen-geoip4.c and geoip-gen6.c.
 */
extern smartlist_t *geoip_smartlist_fixed (void *start, size_t el_size, unsigned num);

/* These generated functions are defined in gen-geoip4.c and geoip-gen6.c.
 */
extern smartlist_t *geoip_smartlist_fixed_ipv4 (void);
extern smartlist_t *geoip_smartlist_fixed_ipv6 (void);

#endif

