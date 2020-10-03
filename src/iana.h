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
        char misc  [100];

        /** The date this network block was added.
         */
        char date  [30];

        /** The WHOIS address for this network block.
         */
        char whois [100];

        /** The RDAP address for this network block.
         */
        char url   [100];

        /** The status for this network block.
         */
        char status[100];
      } IANA_record;

void iana_init (void);
void iana_exit (void);
void iana_dump (void);
void iana_report (void);
int  iana_find_by_ip4_address (const struct in_addr *ip4, struct IANA_record *rec);
int  iana_find_by_ip6_address (const struct in6_addr *ip6, struct IANA_record *rec);
void iana_print_rec (const IANA_record *rec);

#endif
