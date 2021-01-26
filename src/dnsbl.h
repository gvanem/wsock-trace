/**\file    dnsbl.h
 * \ingroup DNSBL
 */
#ifndef _DNSBL_H
#define _DNSBL_H

#include "wsock_defs.h"

extern void DNSBL_init (void);
extern void DNSBL_exit (void);
extern int  DNSBL_test (void);
extern BOOL DNSBL_check_ipv4 (const struct in_addr *ip4, const char **sbl_ref);
extern BOOL DNSBL_check_ipv6 (const struct in6_addr *ip6, const char **sbl_ref);
extern int  DNSBL_update_files (BOOL force_update);

#endif
