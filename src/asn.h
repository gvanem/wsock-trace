/**\file    asn.h
 * \ingroup ASN
 */
#ifndef _ASN_H
#define _ASN_H

struct IANA_record;  /* In 'iana.h' */

/**
 * For handling *Autonomous System Number* (ASN) and IPv4 net blocks.\n
 * IPv6 net-blocks is not supported yet.
 */
struct ASN_addr4 {
       struct in_addr low;      /**< The lowest address for this node */
       struct in_addr high;     /**< The highest address for this noder */
     };

struct ASN_addr6 {
       struct in6_addr low;     /**< The lowest address for this node */
       struct in6_addr high;    /**< The highest address for this node */
     };

struct ASN_record {
       int    family;           /**< The address-family of this node. Only `AF_INET` supported at the moment */
       int    prefix;           /**< The network prefix for this block */
       u_long as_number;        /**< The AS-number of this node */
       char   as_name[100];     /**< The AS-name of this node */
       union {
         struct ASN_addr4 ipv4; /**< The IPv4 address of this node */
         struct ASN_addr6 ipv6; /**< The IPv6 address of this node */
       };
     };

extern void ASN_init   (void);
extern void ASN_exit   (void);
extern void ASN_report (void);
extern void ASN_dump   (void);
extern void ASN_print  (const char *intro, const struct IANA_record *iana, const struct in_addr *ip4, const struct in6_addr *ip6);
extern int  ASN_libloc_print (const char *intro, const struct in_addr *ip4, const struct in6_addr *ip6);

#endif
