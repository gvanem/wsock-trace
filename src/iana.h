/**\file    iana.h
 * \ingroup IANA
 */
#ifndef _IANA_H
#define _IANA_H

#include "wsock_defs.h"

/** \typedef struct IANA_record
 */
typedef struct IANA_record {
        /**
         * The address family for this record:
         * `AF_INET` or `AF_INET6`. Or `-1` is the record is invalid.
         */
        int  family;

        /** The prefix-length for the below network block.
         */
        int  mask;

        /** The network number of this block.
         */
        union {
          struct in_addr  ip4;
          struct in6_addr ip6;
        } net_num;

        /** RIR (Regional Internet Registry) like IANA, APNIC, ARIN, AFRINIC and RIPE.
         *  and things like "Administered by ..."
         */
        char misc [100];

        /** The date this network block was added.
         */
        char date [30];

        /** The WHOIS address for this network block.
         */
        char whois [100];

        /** The RDAP address for this network block.
         */
        char url [100];

        /** The status for this network block.
         */
        char status[100];

        /**
         * \todo The smartlist for a `delegated` RIR array.
         */
        void *rir_list;
      } IANA_record;

extern void iana_init (void);
extern void iana_exit (void);
extern void iana_dump (void);
extern void iana_report (void);
extern int  iana_find_by_ip4_address (const struct in_addr *ip4, struct IANA_record *rec);
extern int  iana_find_by_ip6_address (const struct in6_addr *ip6, struct IANA_record *rec);
extern void iana_print_rec (const IANA_record *rec);

extern const char *iana_get_rec4 (const IANA_record *rec, BOOL aligned);
extern const char *iana_get_rec6 (const IANA_record *rec, BOOL aligned);

/**
 * For handling *Autonomous System Number* (ASN) and IPv4 net blocks.
 */
struct ASN_addr4 {
       struct in_addr low;    /**< The lowest address for this node */
       struct in_addr high;   /**< The highest address for this noder */
     };

struct ASN_addr6 {
       struct in6_addr low;   /**< The lowest address for this node */
       struct in6_addr high;  /**< The highest address for this node */
     };

struct ASN_record {
       int   family;             /**< The address-family of this node. Only `AF_INET` supported at the moment */
       DWORD asn[5];             /**< The ASN-number(s) of this node */
       union {
         struct ASN_addr4 ipv4;  /**< The IPv4 address of this node */
         struct ASN_addr6 ipv6;  /**< The IPv6 address of this node */
       };
     };

extern void ASN_dump (void);
extern void ASN_print (const char *intro, const IANA_record *iana, const struct in_addr *ip4, const struct in6_addr *ip6);
extern int  ASN_libloc_print (const char *intro, const struct in_addr *ip4, const struct in6_addr *ip6);

#endif
