
#ifndef GEOIP_H
#define GEOIP_H

extern DWORD       geoip_parse_file (const char *file, int fam);
extern const char *geoip_get_country_by_ipv4 (const struct in_addr *addr);
extern const char *geoip_get_country_by_ipv6 (const struct in6_addr *addr);
extern const char *geoip_get_long_name_by_id (int number);
extern const char *geoip_get_long_name_by_A2 (const char *short_name);
extern void        geoip_exit (void);

extern int         geoip_addr_is_zero (const struct in_addr *ip4, const struct in6_addr *ip6);
extern int         geoip_addr_is_multicast (const struct in_addr *ip4, const struct in6_addr *ip6);
extern int         geoip_addr_is_special (const struct in_addr *ip4, const struct in6_addr *ip6);
extern int         geoip_addr_is_global (const struct in_addr *ip4, const struct in6_addr *ip6);

#endif

