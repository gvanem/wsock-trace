/**\file    _ipproto.h
 * \ingroup Main
 */
#ifndef _IPPROTO_H
#define _IPPROTO_H

/**
 * These are a rewrite of the enums in `<ws2def.h>` and `<wsrm.h>`. <br>
 * Since many of these are missing in e.g. MinGW, using
 * `#ifndef IPPROTO_x` around them are not safe.
 */
#define _IPPROTO_IP                    0
#define _IPPROTO_HOPOPTS               0
#define _IPPROTO_ICMP                  1
#define _IPPROTO_IGMP                  2
#define _IPPROTO_GGP                   3
#define _BTHPROTO_RFCOMM               3
#define _IPPROTO_IPV4                  4
#define _IPPROTO_ST                    5
#define _IPPROTO_TCP                   6
#define _IPPROTO_CBT                   7
#define _IPPROTO_EGP                   8
#define _IPPROTO_IGP                   9
#define _IPPROTO_PUP                   12
#define _IPPROTO_UDP                   17
#define _IPPROTO_IDP                   22
#define _IPPROTO_RDP                   27
#define _IPPROTO_IPV6                  41
#define _IPPROTO_ROUTING               43
#define _IPPROTO_FRAGMENT              44
#define _IPPROTO_ESP                   50
#define _IPPROTO_AH                    51
#define _IPPROTO_ICMPV6                58
#define _IPPROTO_NONE                  59
#define _IPPROTO_DSTOPTS               60
#define _IPPROTO_ND                    77
#define _IPPROTO_ICLFXBM               78
#define _IPPROTO_PIM                   103
#define _IPPROTO_PGM                   113
#define _IPPROTO_RM                    113
#define _IPPROTO_L2TP                  115
#define _IPPROTO_SCTP                  132
#define _IPPROTO_RAW                   255
#define _IPPROTO_MAX                   256
#define _IPPROTO_RESERVED_RAW          257
#define _IPPROTO_RESERVED_IPSEC        258
#define _IPPROTO_RESERVED_IPSECOFFLOAD 259
#define _IPPROTO_RESERVED_WNV          260
#define _IPPROTO_RESERVED_MAX          261

#endif
