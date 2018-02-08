#ifndef _INET_UTIL_H
#define _INET_UTIL_H

extern int         INET_util_addr_is_zero (const struct in_addr *ip4, const struct in6_addr *ip6);
extern int         INET_util_addr_is_multicast (const struct in_addr *ip4, const struct in6_addr *ip6);
extern int         INET_util_addr_is_special (const struct in_addr *ip4, const struct in6_addr *ip6, const char **remark);
extern int         INET_util_addr_is_global (const struct in_addr *ip4, const struct in6_addr *ip6);

extern int         INET_util_network_len32 (DWORD hi, DWORD lo);
extern int         INET_util_network_len128 (const struct in6_addr *a, const struct in6_addr *b);
extern const char *INET_util_get_ip_num (const struct in_addr *ip4, const struct in6_addr *ip6);

extern DWORD       INET_util_download_file (const char *file, const char *url);
extern int         INET_util_touch_file (const char *file);
extern const char *INET_util_in6_mask_str (const struct in6_addr *ip6);
extern void        INET_util_get_mask4 (struct in_addr *out, int bits);
extern void        INET_util_get_mask6 (struct in6_addr *out, int bits);
extern void        INET_util_test_mask4 (void);
extern void        INET_util_test_mask6 (void);

#endif /* INET_UTIL_H */