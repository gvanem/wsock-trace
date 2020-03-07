/**\file    inet_util.h
 * \ingroup inet_util
 */
#ifndef _INET_UTIL_H
#define _INET_UTIL_H

extern int         INET_util_addr_is_zero (const struct in_addr *ip4, const struct in6_addr *ip6);
extern int         INET_util_addr_is_multicast (const struct in_addr *ip4, const struct in6_addr *ip6);
extern int         INET_util_addr_is_special (const struct in_addr *ip4, const struct in6_addr *ip6, const char **remark);
extern int         INET_util_addr_is_global (const struct in_addr *ip4, const struct in6_addr *ip6);

extern int         INET_util_network_len32 (DWORD hi, DWORD lo);
extern int         INET_util_network_len128 (const struct in6_addr *a, const struct in6_addr *b);
extern int         INET_util_range4cmp (const struct in_addr *addr1, const struct in_addr *addr2, int prefix_len);
extern int         INET_util_range6cmp (const struct in6_addr *addr1, const struct in6_addr *addr2, int prefix_len);

extern DWORD       INET_util_download_file (const char *file, const char *url);
extern int         INET_util_touch_file (const char *file);
extern void        INET_util_get_mask4 (struct in_addr *out, int bits);
extern void        INET_util_get_mask6 (struct in6_addr *out, int bits);
extern void        INET_util_test_mask4 (void);
extern void        INET_util_test_mask6 (void);

extern const char *INET_util_get_ip_num (const struct in_addr *ip4, const struct in6_addr *ip6);
extern const char *INET_util_in6_mask_str (const struct in6_addr *ip6);
extern BOOL        INET_util_get_CIDR_from_IPv4_string (const char *str, struct in_addr *res, int *cidr_len);
extern BOOL        INET_util_get_CIDR_from_IPv6_string (const char *str, struct in6_addr *res, int *cidr_len);

#endif /* INET_UTIL_H */
