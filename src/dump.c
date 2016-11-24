/*
 * Dump and trace-functions for wsock_trace.
 */
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <limits.h>
#include <assert.h>

#include "common.h"
#include "in_addr.h"
#include "init.h"
#include "geoip.h"
#include "wsock_trace.h"

#if defined(_MSC_VER) || defined(__MINGW64_VERSION_MAJOR)
  #include <mstcpip.h>
  #include <ws2bth.h>

#elif defined(__MINGW32__)
  typedef struct pollfd WSAPOLLFD;  /* Missing in MinGW */
#endif

#include <MSWSock.h>

#define ADD_VALUE(v)  { v, #v }

/*
 * Handle printing of option names
 */
#ifndef TCP_EXPEDITED_1122
#define TCP_EXPEDITED_1122  2
#endif

#ifndef TCP_KEEPALIVE
#define TCP_KEEPALIVE 3
#endif

#ifndef TCP_MAXSEG
#define TCP_MAXSEG 4
#endif

#ifndef TCP_MAXRT
#define TCP_MAXRT 5
#endif

#ifndef TCP_STDURG
#define TCP_STDURG 6
#endif

#ifndef TCP_NOURG
#define TCP_NOURG 7
#endif

#ifndef TCP_ATMARK
#define TCP_ATMARK 8
#endif

#ifndef TCP_NOSYNRETRIES
#define TCP_NOSYNRETRIES 9
#endif

#ifndef TCP_TIMESTAMPS
#define TCP_TIMESTAMPS 10
#endif

#ifndef TCP_OFFLOAD_PREFERENCE
#define TCP_OFFLOAD_PREFERENCE 11
#endif

#ifndef TCP_CONGESTION_ALGORITHM
#define TCP_CONGESTION_ALGORITHM 12
#endif

#ifndef TCP_DELAY_FIN_ACK
#define TCP_DELAY_FIN_ACK 13
#endif

/*
 * Missing 'SO_x' codes.
 */
#ifndef SO_BSP_STATE
#define SO_BSP_STATE              0x1009
#endif

#ifndef SO_CONDITIONAL_ACCEPT
#define SO_CONDITIONAL_ACCEPT     0x3002
#endif

#ifndef SO_PAUSE_ACCEPT
#define SO_PAUSE_ACCEPT           0x3003
#endif

#ifndef SO_RANDOMIZE_PORT
#define SO_RANDOMIZE_PORT         0x3005
#endif

#ifndef SO_PORT_SCALABILITY
#define SO_PORT_SCALABILITY       0x3006
#endif

#ifndef SO_REUSE_UNICASTPORT
#define SO_REUSE_UNICASTPORT      0x3007
#endif

#ifndef SO_REUSE_MULTICASTPORT
#define SO_REUSE_MULTICASTPORT    0x3008
#endif

#ifndef SO_UPDATE_CONNECT_CONTEXT
#define SO_UPDATE_CONNECT_CONTEXT 0x7010
#endif

#ifndef IP_HOPLIMIT
#define IP_HOPLIMIT 21
#endif

#ifndef IP_RECEIVE_BROADCAST
#define IP_RECEIVE_BROADCAST 22
#endif

#ifndef IP_RECVIF
#define IP_RECVIF 24
#endif

#ifndef IP_RECVDSTADDR
#define IP_RECVDSTADDR 25
#endif

#ifndef IP_IFLIST
#define IP_IFLIST 28
#endif

#ifndef IP_ADD_IFLIST
#define IP_ADD_IFLIST 29
#endif

#ifndef IP_DEL_IFLIST
#define IP_DEL_IFLIST 30
#endif

#ifndef IP_UNICAST_IF
#define IP_UNICAST_IF 31
#endif

#ifndef IP_RTHDR
#define IP_RTHDR 32
#endif

#ifndef IP_RECVRTHDR
#define IP_RECVRTHDR 38
#endif

#ifndef IP_TCLASS
#define IP_TCLASS 39
#endif

#ifndef IP_RECVTCLASS
#define IP_RECVTCLASS 40
#endif

#ifndef IP_ORIGINAL_ARRIVAL_IF
#define IP_ORIGINAL_ARRIVAL_IF 47
#endif

#ifndef IP_UNSPECIFIED_TYPE_OF_SERVICE
#define IP_UNSPECIFIED_TYPE_OF_SERVICE -1
#endif

#ifndef IPV6_HOPOPTS
#define IPV6_HOPOPTS 1
#endif

#ifndef IPV6_HDRINCL
#define IPV6_HDRINCL 2
#endif

#ifndef IPV6_DONTFRAG
#define IPV6_DONTFRAG 14
#endif

#ifndef IPV6_HOPLIMIT
#define IPV6_HOPLIMIT 21
#endif

#ifndef IPV6_PROTECTION_LEVEL
#define IPV6_PROTECTION_LEVEL 23
#endif

#ifndef IPV6_RECVIF
#define IPV6_RECVIF 24
#endif

#ifndef IPV6_RECVDSTADDR
#define IPV6_RECVDSTADDR 25
#endif

#ifndef IPV6_CHECKSUM
#define IPV6_CHECKSUM 26
#endif

#ifndef IPV6_V6ONLY
#define IPV6_V6ONLY 27
#endif

#ifndef IPV6_IFLIST
#define IPV6_IFLIST 28
#endif

#ifndef IPV6_ADD_IFLIST
#define IPV6_ADD_IFLIST 29
#endif

#ifndef IPV6_DEL_IFLIST
#define IPV6_DEL_IFLIST 30
#endif

#ifndef IPV6_UNICAST_IF
#define IPV6_UNICAST_IF 31
#endif

#ifndef IPV6_RTHDR
#define IPV6_RTHDR 32
#endif

#ifndef IPV6_RECVRTHDR
#define IPV6_RECVRTHDR 38
#endif

#ifndef IPV6_TCLASS
#define IPV6_TCLASS 39
#endif

#ifndef IPV6_RECVTCLASS
#define IPV6_RECVTCLASS 40
#endif

#ifndef IP_WFP_REDIRECT_CONTEXT
#define IP_WFP_REDIRECT_CONTEXT 48 // ??
#endif

#ifndef IP_WFP_REDIRECT_RECORDS
#define IP_WFP_REDIRECT_RECORDS 49 // ??
#endif

#ifndef IPPROTO_IPV6
#define IPPROTO_IPV6            41
#endif

#ifndef IPPROTO_ICMPV6
#define IPPROTO_ICMPV6          58
#endif

#ifndef IPPROTO_RM
#define IPPROTO_RM              113
#endif

#ifndef BTHPROTO_RFCOMM
#define BTHPROTO_RFCOMM  3
#endif

#ifndef AF_BTH
#define AF_BTH  32
#endif

#ifndef IOCGROUP
#define IOCGROUP(x) (((x) >> 8) & 0xFF)
#endif

#ifndef MSG_WAITALL
#define MSG_WAITALL 0x8
#endif

/*
 * struct addrinfo::flags.
 */
#ifndef AI_ALL
#define AI_ALL                    0x00000100
#endif

#ifndef AI_ADDRCONFIG
#define AI_ADDRCONFIG             0x00000400
#endif

#ifndef AI_V4MAPPED
#define AI_V4MAPPED               0x00000800
#endif

#ifndef AI_NON_AUTHORITATIVE
#define AI_NON_AUTHORITATIVE      0x00004000
#endif

#ifndef AI_RETURN_PREFERRED_NAMES
#define AI_RETURN_PREFERRED_NAMES 0x00010000
#endif

#ifndef AI_FQDN
#define AI_FQDN                   0x00020000
#endif

#ifndef AI_FILESERVER
#define AI_FILESERVER             0x00040000
#endif

#ifndef AI_SECURE
#define AI_SECURE                 0x00008000
#endif

/*
 * WSAPROTOCOL_INFO::ServiceFlags1
 */
#ifndef XP1_SAN_SUPPORT_SDP
#define XP1_SAN_SUPPORT_SDP         0x00080000
#endif

/*
 * WSAPROTOCOL_INFO::ProviderFlags
 */
#ifndef PFL_NETWORKDIRECT_PROVIDER
#define PFL_NETWORKDIRECT_PROVIDER  0x00000010
#endif

/*
 * WSASocket() flags
 */
#ifndef WSA_FLAG_ACCESS_SYSTEM_SECURITY
#define WSA_FLAG_ACCESS_SYSTEM_SECURITY 0x40
#endif

#ifndef WSA_FLAG_NO_HANDLE_INHERIT
#define WSA_FLAG_NO_HANDLE_INHERIT      0x80
#endif

/*
 * Missing 'SIO_x' codes.
 */
#ifndef SIO_SOCKET_CLOSE_NOTIFY
#define SIO_SOCKET_CLOSE_NOTIFY             _WSAIOW (IOC_VENDOR,13)
#endif

#ifndef SIO_GET_EXTENSION_FUNCTION_POINTER
#define SIO_GET_EXTENSION_FUNCTION_POINTER  _WSAIORW (IOC_WS2,6)
#endif

#ifndef SIO_GET_QOS
#define SIO_GET_QOS                         _WSAIORW (IOC_WS2,7)
#endif

#ifndef SIO_GET_INTERFACE_LIST
#define SIO_GET_INTERFACE_LIST              _IOR ('t', 127, ULONG)
#endif

#ifndef SIO_GET_INTERFACE_LIST_EX
#define SIO_GET_INTERFACE_LIST_EX           _IOR ('t', 126, ULONG)
#endif

#ifndef SIO_SET_MULTICAST_FILTER
#define SIO_SET_MULTICAST_FILTER            _IOW ('t', 125, ULONG)
#endif

#ifndef SIO_GET_MULTICAST_FILTER
#define SIO_GET_MULTICAST_FILTER            _IOW ('t', 124 | IOC_IN, ULONG)
#endif

#ifndef SIO_IDEAL_SEND_BACKLOG_QUERY
#define SIO_IDEAL_SEND_BACKLOG_QUERY        _IOR ('t', 123, ULONG)
#endif

#ifndef SIO_IDEAL_SEND_BACKLOG_CHANGE
#define SIO_IDEAL_SEND_BACKLOG_CHANGE       _IO ('t', 122)
#endif

/*
 * More missing 'SIO_x' codes.
 */
#if !defined(_MSC_VER)
  #if !defined(__MINGW64_VERSION_MAJOR)
    #define SIO_RCVALL                      _WSAIOW  (IOC_VENDOR,1)
    #define SIO_RCVALL_MCAST                _WSAIOW  (IOC_VENDOR,2)
    #define SIO_RCVALL_IGMPMCAST            _WSAIOW  (IOC_VENDOR,3)
    #define SIO_KEEPALIVE_VALS              _WSAIOW  (IOC_VENDOR,4)
    #define SIO_ABSORB_RTRALERT             _WSAIOW  (IOC_VENDOR,5)
    #define SIO_UCAST_IF                    _WSAIOW  (IOC_VENDOR,6)
    #define SIO_LIMIT_BROADCASTS            _WSAIOW  (IOC_VENDOR,7)
    #define SIO_INDEX_BIND                  _WSAIOW  (IOC_VENDOR,8)
    #define SIO_INDEX_MCASTIF               _WSAIOW  (IOC_VENDOR,9)
    #define SIO_INDEX_ADD_MCAST             _WSAIOW  (IOC_VENDOR,10)
    #define SIO_INDEX_DEL_MCAST             _WSAIOW  (IOC_VENDOR,11)
  #endif

  #undef  SIO_UDP_CONNRESET
  #define SIO_UDP_CONNRESET                 _WSAIOW  (IOC_VENDOR,12)
  #define SIO_RCVALL_MCAST_IF               _WSAIOW  (IOC_VENDOR,13)
  #define SIO_RCVALL_IF                     _WSAIOW  (IOC_VENDOR,14)
  #define SIO_UDP_NETRESET                  _WSAIOW  (IOC_VENDOR,15)

  #if (_WIN32_WINNT < 0x0600)
    #define SIO_BSP_HANDLE                  _WSAIOR  (IOC_WS2,27)
    #define SIO_BSP_HANDLE_SELECT           _WSAIOR  (IOC_WS2,28)
    #define SIO_BSP_HANDLE_POLL             _WSAIOR  (IOC_WS2,29)
    #define SIO_EXT_SELECT                  _WSAIORW (IOC_WS2,30)
    #define SIO_EXT_POLL                    _WSAIORW (IOC_WS2,31)
    #define SIO_EXT_SENDMSG                 _WSAIORW (IOC_WS2,32)
    #define SIO_BASE_HANDLE                 _WSAIOR  (IOC_WS2,34)
  #endif

  #define SIO_ACQUIRE_PORT_RESERVATION      _WSAIOW  (IOC_VENDOR, 100)
  #define SIO_RELEASE_PORT_RESERVATION      _WSAIOW  (IOC_VENDOR, 101)
  #define SIO_ASSOCIATE_PORT_RESERVATION    _WSAIOW  (IOC_VENDOR, 102)

  #define SIO_SET_SECURITY                  _WSAIOW  (IOC_VENDOR, 200)
  #define SIO_QUERY_SECURITY                _WSAIORW (IOC_VENDOR, 201)
  #define SIO_SET_PEER_TARGET_NAME          _WSAIOW  (IOC_VENDOR, 202)
  #define SIO_DELETE_PEER_TARGET_NAME       _WSAIOW  (IOC_VENDOR, 203)
  #define SIO_SOCKET_USAGE_NOTIFICATION     _WSAIOW  (IOC_VENDOR, 204)
  #define SIO_QUERY_WFP_ALE_ENDPOINT_HANDLE _WSAIOR  (IOC_VENDOR, 205)
  #define SIO_QUERY_RSS_SCALABILITY_INFO    _WSAIOR  (IOC_VENDOR, 210)
#endif



static const struct search_list sol_options[] = {
                    ADD_VALUE (SO_DEBUG),
                    ADD_VALUE (SO_ACCEPTCONN),
                    ADD_VALUE (SO_REUSEADDR),
                    ADD_VALUE (SO_KEEPALIVE),
                    ADD_VALUE (SO_DONTROUTE),
                    ADD_VALUE (SO_BROADCAST),
                    ADD_VALUE (SO_USELOOPBACK),
                    ADD_VALUE (SO_LINGER),
                    ADD_VALUE (SO_OOBINLINE),
                    ADD_VALUE (SO_SNDBUF),
                    ADD_VALUE (SO_RCVBUF),
                    ADD_VALUE (SO_SNDLOWAT),
                    ADD_VALUE (SO_RCVLOWAT),
                    ADD_VALUE (SO_SNDTIMEO),
                    ADD_VALUE (SO_RCVTIMEO),
                    ADD_VALUE (SO_ERROR),
                    ADD_VALUE (SO_TYPE),
                    ADD_VALUE (SO_GROUP_ID),
                    ADD_VALUE (SO_GROUP_PRIORITY),
                    ADD_VALUE (SO_MAX_MSG_SIZE),
                    ADD_VALUE (SO_PROTOCOL_INFO),
                    ADD_VALUE (SO_CONDITIONAL_ACCEPT),
                    ADD_VALUE (SO_UPDATE_CONNECT_CONTEXT),
                    ADD_VALUE (SO_BSP_STATE),
                    ADD_VALUE (SO_CONNDATA),
                    ADD_VALUE (SO_CONNDATALEN),
                    ADD_VALUE (SO_CONNECT_TIME),
                    ADD_VALUE (SO_CONNOPT),
                    ADD_VALUE (SO_CONNOPTLEN),
                    ADD_VALUE (SO_DISCDATA),
                    ADD_VALUE (SO_DISCDATALEN),
                    ADD_VALUE (SO_DISCOPT),
                    ADD_VALUE (SO_DISCOPTLEN),
                    ADD_VALUE (SO_DONTLINGER),
                    ADD_VALUE (SO_EXCLUSIVEADDRUSE),
                    ADD_VALUE (SO_MAXDG),
                    ADD_VALUE (SO_MAXPATHDG),
                    ADD_VALUE (SO_OPENTYPE),
                    ADD_VALUE (SO_PAUSE_ACCEPT),
                    ADD_VALUE (SO_PORT_SCALABILITY),
                    ADD_VALUE (SO_PROTOCOL_INFOA),
                    ADD_VALUE (SO_PROTOCOL_INFOW),
                    ADD_VALUE (SO_RANDOMIZE_PORT),
                    ADD_VALUE (SO_REUSE_UNICASTPORT),
                    ADD_VALUE (SO_REUSE_MULTICASTPORT),
                    ADD_VALUE (SO_UPDATE_ACCEPT_CONTEXT),
                    ADD_VALUE (PVD_CONFIG)
                  };

static const struct search_list tcp_options[] = {
                    ADD_VALUE (TCP_NODELAY),
                    ADD_VALUE (TCP_MAXSEG),
                    ADD_VALUE (TCP_EXPEDITED_1122),
                    ADD_VALUE (TCP_KEEPALIVE),
                    ADD_VALUE (TCP_MAXRT),
                    ADD_VALUE (TCP_STDURG),
                    ADD_VALUE (TCP_NOURG),
                    ADD_VALUE (TCP_ATMARK),
                    ADD_VALUE (TCP_NOSYNRETRIES),
                    ADD_VALUE (TCP_TIMESTAMPS),
                    ADD_VALUE (TCP_OFFLOAD_PREFERENCE),
                    ADD_VALUE (TCP_CONGESTION_ALGORITHM),
                    ADD_VALUE (TCP_DELAY_FIN_ACK),
                  };

static const struct search_list ip4_options[] = {
                    ADD_VALUE (IP_OPTIONS),
                    ADD_VALUE (IP_HDRINCL),
                    ADD_VALUE (IP_TOS),
                    ADD_VALUE (IP_TTL),
                    ADD_VALUE (IP_MULTICAST_IF),
                    ADD_VALUE (IP_MULTICAST_TTL),
                    ADD_VALUE (IP_MULTICAST_LOOP),
                    ADD_VALUE (IP_ADD_MEMBERSHIP),
                    ADD_VALUE (IP_DROP_MEMBERSHIP),
                    ADD_VALUE (IP_DONTFRAGMENT),
                    ADD_VALUE (IP_ADD_SOURCE_MEMBERSHIP),
                    ADD_VALUE (IP_DROP_SOURCE_MEMBERSHIP),
                    ADD_VALUE (IP_BLOCK_SOURCE),
                    ADD_VALUE (IP_UNBLOCK_SOURCE),
                    ADD_VALUE (IP_PKTINFO),
                    ADD_VALUE (IP_HOPLIMIT),
                    ADD_VALUE (IP_RECEIVE_BROADCAST),
                    ADD_VALUE (IP_RECVIF),
                    ADD_VALUE (IP_RECVDSTADDR),
                    ADD_VALUE (IP_IFLIST),
                    ADD_VALUE (IP_ADD_IFLIST),
                    ADD_VALUE (IP_DEL_IFLIST),
                    ADD_VALUE (IP_UNICAST_IF),
                    ADD_VALUE (IP_RTHDR),
                    ADD_VALUE (IP_RECVRTHDR),
                    ADD_VALUE (IP_TCLASS),
                    ADD_VALUE (IP_RECVTCLASS),
                    ADD_VALUE (IP_ORIGINAL_ARRIVAL_IF),
                    ADD_VALUE (IP_WFP_REDIRECT_CONTEXT),
                    ADD_VALUE (IP_WFP_REDIRECT_RECORDS),
                    ADD_VALUE (IP_UNSPECIFIED_TYPE_OF_SERVICE)  /* == -1 = UINT_MAX */
                  };

static const struct search_list ip6_options[] = {
                    ADD_VALUE (IPV6_HOPOPTS),
                    ADD_VALUE (IPV6_HDRINCL),
                    ADD_VALUE (IPV6_UNICAST_HOPS),
                    ADD_VALUE (IPV6_MULTICAST_IF),
                    ADD_VALUE (IPV6_MULTICAST_HOPS),
                    ADD_VALUE (IPV6_MULTICAST_LOOP),
                    ADD_VALUE (IPV6_ADD_MEMBERSHIP),
                    ADD_VALUE (IPV6_DROP_MEMBERSHIP),
                    ADD_VALUE (IPV6_DONTFRAG),
                    ADD_VALUE (IPV6_PKTINFO),
                    ADD_VALUE (IPV6_HOPLIMIT),
                    ADD_VALUE (IPV6_PROTECTION_LEVEL),
                    ADD_VALUE (IPV6_RECVIF),
                    ADD_VALUE (IPV6_RECVDSTADDR),
                    ADD_VALUE (IPV6_CHECKSUM),
                    ADD_VALUE (IPV6_V6ONLY),
                    ADD_VALUE (IPV6_IFLIST),
                    ADD_VALUE (IPV6_ADD_IFLIST),
                    ADD_VALUE (IPV6_DEL_IFLIST),
                    ADD_VALUE (IPV6_UNICAST_IF),
                    ADD_VALUE (IPV6_RTHDR),
                    ADD_VALUE (IPV6_RECVRTHDR),
                    ADD_VALUE (IPV6_TCLASS),
                    ADD_VALUE (IPV6_RECVTCLASS)
                  };

static const struct search_list families[] = {
                    ADD_VALUE (AF_UNSPEC),
                    ADD_VALUE (AF_UNIX),
                    ADD_VALUE (AF_INET),
                    ADD_VALUE (AF_IMPLINK),
                    ADD_VALUE (AF_PUP),
                    ADD_VALUE (AF_CHAOS),
                 /* ADD_VALUE (AF_NS),  Because AF_NS == AF_IPX */
                    ADD_VALUE (AF_IPX),
                 /* ADD_VALUE (AF_ISO), Because AF_ISO == AF_OSI */
                    ADD_VALUE (AF_OSI),
                    ADD_VALUE (AF_ECMA),
                    ADD_VALUE (AF_DATAKIT),
                    ADD_VALUE (AF_CCITT),
                    ADD_VALUE (AF_SNA),
                    ADD_VALUE (AF_DECnet),
                    ADD_VALUE (AF_DLI),
                    ADD_VALUE (AF_LAT),
                    ADD_VALUE (AF_HYLINK),
                    ADD_VALUE (AF_APPLETALK),
                    ADD_VALUE (AF_NETBIOS),
                    ADD_VALUE (AF_VOICEVIEW),
                    ADD_VALUE (AF_FIREFOX),
                    ADD_VALUE (AF_UNKNOWN1),
                    ADD_VALUE (AF_BAN),
                    ADD_VALUE (AF_ATM),
                    ADD_VALUE (AF_INET6),
                    ADD_VALUE (AF_IRDA),
                    ADD_VALUE (AF_BTH)
                  };

static const struct search_list levels[] = {
                    ADD_VALUE (SOL_SOCKET),
                    ADD_VALUE (IPPROTO_UDP),
                    ADD_VALUE (IPPROTO_TCP),
                    ADD_VALUE (IPPROTO_IP),
                    ADD_VALUE (IPPROTO_ICMP),
                    ADD_VALUE (IPPROTO_RM),
                  };

static const struct search_list types[] = {
                    ADD_VALUE (SOCK_STREAM),
                    ADD_VALUE (SOCK_DGRAM),
                    ADD_VALUE (SOCK_RAW),
                    ADD_VALUE (SOCK_RDM),
                    ADD_VALUE (SOCK_SEQPACKET)
                  };

static const struct search_list wsasocket_flags[] = {
                    ADD_VALUE (WSA_FLAG_OVERLAPPED),
                    ADD_VALUE (WSA_FLAG_MULTIPOINT_C_ROOT),
                    ADD_VALUE (WSA_FLAG_MULTIPOINT_C_LEAF),
                    ADD_VALUE (WSA_FLAG_MULTIPOINT_D_ROOT),
                    ADD_VALUE (WSA_FLAG_MULTIPOINT_D_LEAF),
                    ADD_VALUE (WSA_FLAG_ACCESS_SYSTEM_SECURITY),
                    ADD_VALUE (WSA_FLAG_NO_HANDLE_INHERIT)
                  };

static const struct search_list ai_flgs[] = {
                    ADD_VALUE (AI_PASSIVE),
                    ADD_VALUE (AI_CANONNAME),
                    ADD_VALUE (AI_NUMERICHOST),
                    ADD_VALUE (AI_ADDRCONFIG),
                    ADD_VALUE (AI_NON_AUTHORITATIVE),
                    ADD_VALUE (AI_SECURE),
                    ADD_VALUE (AI_RETURN_PREFERRED_NAMES),
                    ADD_VALUE (AI_FILESERVER),
                    ADD_VALUE (AI_ALL),
                    ADD_VALUE (AI_V4MAPPED),
                    ADD_VALUE (AI_FQDN)
                 };

static const struct search_list getnameinfo_flgs[] = {
                    ADD_VALUE (NI_NOFQDN),
                    ADD_VALUE (NI_NUMERICHOST),
                    ADD_VALUE (NI_NAMEREQD),
                    ADD_VALUE (NI_NUMERICSERV),
                    ADD_VALUE (NI_DGRAM)
                 };

static const struct search_list protocols[] = {
                    ADD_VALUE (IPPROTO_ICMP),
                    ADD_VALUE (IPPROTO_IGMP),
                    ADD_VALUE (BTHPROTO_RFCOMM),
                    ADD_VALUE (IPPROTO_TCP),
                    ADD_VALUE (IPPROTO_UDP),
                    ADD_VALUE (IPPROTO_ICMPV6),
                    ADD_VALUE (IPPROTO_RM),
                  };

static const struct search_list wsaprotocol_info_ServiceFlags1[] = {
                    ADD_VALUE (XP1_CONNECTIONLESS),
                    ADD_VALUE (XP1_GUARANTEED_DELIVERY),
                    ADD_VALUE (XP1_GUARANTEED_ORDER),
                    ADD_VALUE (XP1_MESSAGE_ORIENTED),
                    ADD_VALUE (XP1_PSEUDO_STREAM),
                    ADD_VALUE (XP1_GRACEFUL_CLOSE),
                    ADD_VALUE (XP1_EXPEDITED_DATA),
                    ADD_VALUE (XP1_CONNECT_DATA),
                    ADD_VALUE (XP1_DISCONNECT_DATA),
                    ADD_VALUE (XP1_SUPPORT_BROADCAST),
                    ADD_VALUE (XP1_SUPPORT_MULTIPOINT),
                    ADD_VALUE (XP1_MULTIPOINT_CONTROL_PLANE),
                    ADD_VALUE (XP1_MULTIPOINT_DATA_PLANE),
                    ADD_VALUE (XP1_QOS_SUPPORTED),
                    ADD_VALUE (XP1_INTERRUPT),
                    ADD_VALUE (XP1_UNI_SEND),
                    ADD_VALUE (XP1_UNI_RECV),
                    ADD_VALUE (XP1_IFS_HANDLES),
                    ADD_VALUE (XP1_PARTIAL_MESSAGE),
                    ADD_VALUE (XP1_SAN_SUPPORT_SDP)
                 };

static const struct search_list wsaprotocol_info_ProviderFlags[] = {
                    ADD_VALUE (PFL_MULTIPLE_PROTO_ENTRIES),
                    ADD_VALUE (PFL_RECOMMENDED_PROTO_ENTRY),
                    ADD_VALUE (PFL_HIDDEN),
                    ADD_VALUE (PFL_MATCHES_PROTOCOL_ZERO),
                    ADD_VALUE (PFL_NETWORKDIRECT_PROVIDER)
                  };

static const struct search_list wsa_events_flgs[] = {
                    ADD_VALUE (FD_READ),
                    ADD_VALUE (FD_WRITE),
                    ADD_VALUE (FD_OOB),
                    ADD_VALUE (FD_ACCEPT),
                    ADD_VALUE (FD_CONNECT),
                    ADD_VALUE (FD_CLOSE),
                    ADD_VALUE (FD_QOS),
                    ADD_VALUE (FD_GROUP_QOS),
                    ADD_VALUE (FD_ROUTING_INTERFACE_CHANGE),
                    ADD_VALUE (FD_ADDRESS_LIST_CHANGE)
                  };

static const struct search_list ioctl_commands[] = {
                    ADD_VALUE (FIONREAD),
                    ADD_VALUE (FIONBIO),
                    ADD_VALUE (FIOASYNC),
                    ADD_VALUE (SIOCSHIWAT),
                    ADD_VALUE (SIOCGHIWAT),
                    ADD_VALUE (SIOCSLOWAT),
                    ADD_VALUE (SIOCGLOWAT),
                    ADD_VALUE (SIOCATMARK)
                  };

static const struct search_list sio_codes[] = {
                    ADD_VALUE (SIO_RCVALL),
                    ADD_VALUE (SIO_RCVALL_MCAST),
                    ADD_VALUE (SIO_RCVALL_IGMPMCAST),
                    ADD_VALUE (SIO_KEEPALIVE_VALS),
                    ADD_VALUE (SIO_ABSORB_RTRALERT),
                    ADD_VALUE (SIO_UCAST_IF),
                    ADD_VALUE (SIO_LIMIT_BROADCASTS),
                    ADD_VALUE (SIO_INDEX_BIND),
                    ADD_VALUE (SIO_INDEX_MCASTIF),
                    ADD_VALUE (SIO_INDEX_ADD_MCAST),
                    ADD_VALUE (SIO_INDEX_DEL_MCAST),
                    ADD_VALUE (SIO_UDP_CONNRESET),
                    ADD_VALUE (SIO_RCVALL_MCAST_IF),
                    ADD_VALUE (SIO_RCVALL_IF),
                    ADD_VALUE (SIO_ACQUIRE_PORT_RESERVATION),
                    ADD_VALUE (SIO_RELEASE_PORT_RESERVATION),
                    ADD_VALUE (SIO_ASSOCIATE_PORT_RESERVATION),
                    ADD_VALUE (SIO_SET_SECURITY),
                    ADD_VALUE (SIO_QUERY_SECURITY),
                    ADD_VALUE (SIO_SET_PEER_TARGET_NAME),
                    ADD_VALUE (SIO_DELETE_PEER_TARGET_NAME),
                    ADD_VALUE (SIO_SOCKET_USAGE_NOTIFICATION),
                    ADD_VALUE (SIO_QUERY_WFP_ALE_ENDPOINT_HANDLE),
                    ADD_VALUE (SIO_QUERY_RSS_SCALABILITY_INFO),
                    ADD_VALUE (SIO_UDP_NETRESET),
                    ADD_VALUE (SIO_BSP_HANDLE),
                    ADD_VALUE (SIO_BSP_HANDLE_SELECT),
                    ADD_VALUE (SIO_BSP_HANDLE_POLL),
                    ADD_VALUE (SIO_BASE_HANDLE),
                    ADD_VALUE (SIO_EXT_SELECT),
                    ADD_VALUE (SIO_EXT_POLL),
                    ADD_VALUE (SIO_EXT_SENDMSG),
                    ADD_VALUE (SIO_SOCKET_CLOSE_NOTIFY),
                    ADD_VALUE (SIO_GET_EXTENSION_FUNCTION_POINTER),
                    ADD_VALUE (SIO_GET_QOS),
                    ADD_VALUE (SIO_GET_INTERFACE_LIST),
                    ADD_VALUE (SIO_GET_INTERFACE_LIST_EX),
                    ADD_VALUE (SIO_SET_MULTICAST_FILTER),
                    ADD_VALUE (SIO_GET_MULTICAST_FILTER),
                    ADD_VALUE (SIO_IDEAL_SEND_BACKLOG_QUERY),
                    ADD_VALUE (SIO_IDEAL_SEND_BACKLOG_CHANGE)
                  };

static const struct search_list wsapollfd_flgs[] = {
                    ADD_VALUE (POLLERR),
                    ADD_VALUE (POLLHUP),
                    ADD_VALUE (POLLNVAL),
                    ADD_VALUE (POLLOUT),
                    ADD_VALUE (POLLWRBAND),
                    ADD_VALUE (POLLRDNORM),
                    ADD_VALUE (POLLRDBAND),
                    ADD_VALUE (POLLIN),
                    ADD_VALUE (POLLPRI)
                  };

const char *socket_family (int family)
{
  return list_lookup_name (family, families, DIM(families));
}

const char *socket_type (int type)
{
  return list_lookup_name (type, types, DIM(types));
}

const char *socket_flags (int flags)
{
  static char buf[100];
  char  *end;

  buf[0] = '\0';
  if (flags == 0)
     return ("0");

  if (flags & MSG_PEEK)
     strcat (buf, "MSG_PEEK+");

  if (flags & MSG_OOB)
     strcat (buf, "MSG_OOB+");

  if (flags & MSG_DONTROUTE)
     strcat (buf, "MSG_DONTROUTE+");

  if (flags & MSG_WAITALL)
     strcat (buf, "MSG_WAITALL+");

  if (flags & MSG_PARTIAL)
     strcat (buf, "MSG_PARTIAL+");

  if (flags & MSG_INTERRUPT)
     strcat (buf, "MSG_INTERRUPT+");

  end = strrchr (buf, '+');
  if (end)
     *end = '\0';
  return (buf);
}

const char *wsasocket_flags_decode (int flags)
{
  if (flags == 0)
     return ("0");
  return flags_decode (flags, wsasocket_flags, DIM(wsasocket_flags));
}

const char *ai_flags_decode (int flags)
{
  if (flags == 0)
     return ("0");
  return flags_decode (flags, ai_flgs, DIM(ai_flgs));
}

const char *getnameinfo_flags_decode (int flags)
{
  if (flags == 0)
     return ("0");
  return flags_decode (flags, getnameinfo_flgs, DIM(getnameinfo_flgs));
}

const char *event_bits_decode (long flag)
{
  if (flag == 0)
     return ("0");
  return flags_decode (flag, wsa_events_flgs, DIM(wsa_events_flgs));
}

const char *get_sio_name (DWORD code)
{
  static char buf[20];
  const  struct search_list *sl = sio_codes;
  size_t i;

  for (i = 0; i < DIM(sio_codes); i++, sl++)
      if (code == sl->value)
         return (sl->name);
  snprintf (buf, sizeof(buf), "code 0x%08lX", code);
  return (buf);
}

const char *socklevel_name (int level)
{
  return list_lookup_name (level, levels, DIM(levels));
}

const char *protocol_name (int proto)
{
  return list_lookup_name (proto, protocols, DIM(protocols));
}

const char *sockopt_name (int level, int opt)
{
  static char buf[20];

  switch (level)
  {
    case SOL_SOCKET:
         return list_lookup_name (opt, sol_options, DIM(sol_options));

    case IPPROTO_UDP:
         return ("UDP option!?");

    case IPPROTO_TCP:
         return list_lookup_name (opt, tcp_options, DIM(tcp_options));

    case IPPROTO_IP:
    case IPPROTO_ICMP:
         return list_lookup_name (opt, ip4_options, DIM(ip4_options));

    case IPPROTO_IPV6:
         return list_lookup_name (opt, ip6_options, DIM(ip6_options));

    default:
         snprintf (buf, sizeof(buf), "level %d?", level);
         return (buf);
  }
}

const char *sockopt_value (const char *opt_val, int opt_len)
{
  static  char buf[50];
  DWORD   val;
  ULONG64 val64;

  if (!opt_val)
     return ("NULL");

  switch (opt_len)
  {
    case sizeof(BYTE):
         val = *(BYTE*) opt_val;
         return _itoa ((BYTE)val, buf, 10);

    case sizeof(WORD):
         val = *(WORD*) opt_val;
         snprintf (buf, sizeof(buf), "%u", (WORD)val);
         break;

    case sizeof(DWORD):
         val = *(DWORD*) opt_val;
         if (val == ULONG_MAX)
              strcpy (buf, "ULONG_MAX");
         else snprintf (buf, sizeof(buf), "%lu", val);
         break;

    case sizeof(ULONG64):
         val64 = *(ULONG64*) opt_val;
         snprintf (buf, sizeof(buf), "%" U64_FMT, val64);
         break;

    default:
         snprintf (buf, sizeof(buf), "%d bytes at 0x%p", opt_len, opt_val);
         break;
  }
  return (buf);
}

const char *ioctlsocket_cmd_name (long cmd)
{
  static char buf[50];
  int    group = IOCGROUP (cmd);

  if (group == 'f' || group == 's')
     return list_lookup_name (cmd, ioctl_commands, DIM(ioctl_commands));
  snprintf (buf, sizeof(buf), "cmd %ld?", cmd);
  return (buf);
}

/*
 * One dump-line is like:
 * "<prefix> 0000: 47 45 54 20 2F 20 48 54 54 50 2F 31 2E 31 0D 0A GET / HTTP/1.1..\n"
 *
 */
#define CHECK_MAX_DATA(ofs) \
        (g_cfg.max_data > 0 && (ofs) >= (unsigned)g_cfg.max_data-1)

static void dump_data_internal (const void *data_p, unsigned data_len, const char *prefix)
{
  const BYTE *data = (const BYTE*) data_p;
  UINT  i = 0, j, ofs;

  trace_puts ("~4");

  for (ofs = 0; ofs < data_len; ofs += 16)
  {
    trace_indent (g_cfg.trace_indent+2);

    if (prefix)
    {
      if (ofs == 0)
           trace_puts (prefix);
      else trace_indent (strlen(prefix));
    }

    trace_puts (str_hex_word(ofs));
    trace_puts (": ");

    for (i = j = 0; i < 16 && i+ofs < data_len; i++)
    {
      trace_puts (str_hex_byte(data[i+ofs]));
      trace_putc (' ');
      j = i;
      if (CHECK_MAX_DATA(ofs+i))
         break;
    }

    for ( ; j < 15; j++)     /* pad line to 16 positions */
       trace_puts ("   ");

    for (i = 0; i < 16 && i+ofs < data_len; i++)
    {
      int ch = data[i+ofs];

      if (ch < ' ' || ch == 0x7F)    /* non-printable */
           trace_putc ('.');
      else trace_putc_raw (ch);

      if (CHECK_MAX_DATA(ofs+i))
         break;
    }
    trace_putc ('\n');

    if (CHECK_MAX_DATA(ofs+i))
       break;
  }

  if (ofs + i < data_len - 1)
  {
    trace_indent (g_cfg.trace_indent+2);
    trace_printf ("<%d more bytes...>\n", data_len-1-ofs-i);
  }
  trace_puts ("~0");
}

void dump_data (const void *data_p, unsigned data_len)
{
  if (g_cfg.max_data > 0)
     dump_data_internal (data_p, data_len, NULL);
}

void dump_wsabuf (const WSABUF *bufs, DWORD num_bufs)
{
  int i;

  if (g_cfg.max_data <= 0)
     return;

  for (i = 0; i < (int)num_bufs && bufs; i++, bufs++)
  {
    char prefix[30];

    snprintf (prefix, sizeof(prefix), "iov %d: ", i);
    dump_data_internal (bufs->buf, bufs->len, prefix);
  }
}

static char *maybe_wrap_line (int indent, int trailing_len, const char *start, char *out)
{
  const char *newline    = strrchr (start, '\n');
  int         i, max_len = g_cfg.screen_width - indent - trailing_len;

  if (newline)
     start = newline;

#if 0
  TRACE (5, "newline: %p, start: %p, out: %p, len: %d, max_len: %d\n",
            newline, start, out, out-start, max_len);
#endif

  if (out - start >= max_len)
  {
    *out++ = '\n';
    for (i = 0; i < indent; i++)
       *out++ = ' ';
  }
  return (out);
}

/*
 * Function that prints the line argument while limiting it
 * to at most 'g_cfg.screen_width'. An appropriate number
 * of spaces are added on subsequent lines.
 *
 * Stolen from Wget (main.c) and rewritten.
 */
static void format_and_print_line (const char *line, int indent, int brk_ch)
{
  char *token, *line_dup = strdup (line);
  char  brk_chars[2] = "?";
  int   remaining_chars = g_cfg.screen_width - indent;

  brk_chars[0] = brk_ch;
  token = strtok (line_dup, brk_chars);
  while (token)
  {
    /* If a token is much larger than the maximum
     * line length, we print the token on the next line.
     */
    if (remaining_chars <= (int)strlen(token))
    {
      trace_printf ("\n%*c", indent, ' ');
      remaining_chars = g_cfg.screen_width - indent;
    }
    trace_puts (token);
    remaining_chars -= strlen (token);
    token = strtok (NULL, brk_chars);
    if (token)
       trace_putc (brk_ch);
  }
  trace_putc ('\n');
  free (line_dup);
}

void dump_addrinfo (const struct addrinfo *ai)
{
  for ( ; ai; ai = ai->ai_next)
  {
    const int *addr_len;

    trace_indent (g_cfg.trace_indent+2);
    trace_printf ("~4ai_flags: %s, ai_family: %s, ai_socktype: %s, ai_protocol: %s\n",
                  ai_flags_decode(ai->ai_flags),
                  socket_family(ai->ai_family),
                  socket_type(ai->ai_socktype),
                  protocol_name(ai->ai_protocol));

    trace_indent (g_cfg.trace_indent+4);
    addr_len = (const int*)&ai->ai_addrlen;
    trace_printf ("ai_canonname: %s, ai_addr: %s\n",
                  ai->ai_canonname, sockaddr_str2(ai->ai_addr,addr_len));
  }
  trace_puts ("~0");
}

fd_set *copy_fd_set (const fd_set *fd)
{
  fd_set *copy;
  size_t  size;
  u_int   i;

  if (!fd)
     return (NULL);

  /*
   * From <winsock.h>:
   *
   * typedef struct fd_set {
   *         u_int  fd_count;
   *         SOCKET fd_array[FD_SETSIZE];
   *      } fd_set;
   *
   * But we cannot assume a certain 'FD_SETSIZE'.
   * Just allocate according to 'fd_count'.
   */
  size = fd->fd_count * sizeof(SOCKET) + sizeof(u_int);
  copy = malloc (size);

  copy->fd_count = fd->fd_count;
  for (i = 0; i < fd->fd_count; i++)
      copy->fd_array[i] = fd->fd_array[i];
  return (copy);
}

static void dump_one_fd (const fd_set *fd, int indent)
{
  u_int i, max_len, len = indent;
  int   j;

  for (i = 0; i < fd->fd_count; i++)
  {
    char buf[10];

    _itoa (fd->fd_array[i], buf, 10);
    max_len = g_cfg.screen_width - strlen(buf) - 1;
    trace_puts (buf);

    if (i < fd->fd_count-1)
    {
      trace_putc (',');
      len += strlen(buf) + 1;
    }
    else
    {
      trace_putc ('\n');
      len = indent;
    }

    if (len >= max_len)
    {
      trace_putc ('\n');
      for (j = 0; j < indent; j++)
          trace_putc (' ');
      len = indent;
    }
  }
  if (i == 0)
     trace_puts ("<no fds>\n");
}

void dump_select (const fd_set *rd, const fd_set *wr, const fd_set *ex, int indent)
{
  int i;

  struct sel_info {
         const char   *which;
         const fd_set *fd;
       } info[3] = {
         { " rd: ", NULL },
         { " wr: ", NULL },
         { " ex: ", NULL }
       };

  info[0].fd = rd;
  info[1].fd = wr;
  info[1].fd = ex;

  for (i = 0; i < DIM(info); i++)
  {
    trace_puts (info[i].which);

    if (info[i].fd)
         dump_one_fd (info[i].fd, indent+5);
    else trace_puts ( "<not set>\n");

    if (i < DIM(info)-1)
       trace_indent (indent);
  }
}

static const char *wsapollfd_event_decode (SHORT ev, char *buf)
{
  if (ev == 0)
     return ("0x0000");

  if (ev == (POLLRDNORM | POLLRDBAND))
     return ("POLLIN");

  if (ev == (POLLOUT | POLLRDNORM | POLLRDBAND))
     return ("POLLOUT|POLLIN");

  strcpy (buf, flags_decode(ev, wsapollfd_flgs, DIM(wsapollfd_flgs)));
  return (buf);
}

void dump_wsapollfd (const WSAPOLLFD *fd_array, ULONG fds, int indent)
{
  const WSAPOLLFD *fd = fd_array;
  int   line = 0;
  char  ev_buf1[30];
  char  ev_buf2[30];
  ULONG i;

  for (i = 0; i < fds; i++, fd++)
  {
    if (fd->fd == INVALID_SOCKET)
       continue;

    trace_printf ("%*sfd: %4u, fd->events: %s, fd->revents: %s\n",
                  line > 0 ? indent : 0, "", fd->fd,
                  wsapollfd_event_decode(fd->events,ev_buf1),
                  wsapollfd_event_decode(fd->revents,ev_buf2));
    line++;
  }
}

void dump_one_proto_info (const char *prefix, const char *buf)
{
  static const char *padding = "                   ";  /* Length of "WSAPROTOCOL_INFOx: " */

  trace_indent (g_cfg.trace_indent+2);
  trace_printf ("%s%s\n", prefix ? prefix : padding, buf);
}

void dump_provider_path (const GUID *guid, const void *provider_path_func)
{
  /* Watcom lacks many things making this difficult.
   */
#if !defined(__WATCOMC__)
  int     error;
  wchar_t path[MAX_PATH] = L"??";
  int     path_len = DIM(path);

  /* As in wsock_trace.c:
   */
  typedef int (WINAPI *func_WSCGetProviderPath) (GUID    *provider_id,
                                                 wchar_t *provider_dll_path,
                                                 int     *provider_dll_path_len,
                                                 int     *error);

  func_WSCGetProviderPath p_WSCGetProviderPath = (func_WSCGetProviderPath) provider_path_func;

  if (p_WSCGetProviderPath &&
      (*p_WSCGetProviderPath)((GUID*)guid, path, &path_len, &error) == 0)
  {
    char buf [100+MAX_PATH];

    snprintf (buf, sizeof(buf), "~4Provider Path:      \"%" WCHAR_FMT "\"~0", path);
    dump_one_proto_info (NULL, buf);
  }
#endif
}

void dump_wsaprotocol_info (char ascii_or_wide, const void *proto_info, const void *provider_path_func)
{
  /* Watcom lacks many things making this difficult.
   */
#if !defined(__WATCOMC__)
  const char *flags_str;
  char        buf1 [100];
  char        buf2 [200];
  DWORD       flags;

  const WSAPROTOCOL_INFOA *pi_a = (const WSAPROTOCOL_INFOA*) proto_info;
  const WSAPROTOCOL_INFOW *pi_w = (const WSAPROTOCOL_INFOW*) proto_info;

  assert (offsetof(WSAPROTOCOL_INFOA,szProtocol) == offsetof(WSAPROTOCOL_INFOW,szProtocol));

  if (ascii_or_wide != 'A' && ascii_or_wide != 'W')
     return;

  strcpy (buf1, "~4WSAPROTOCOL_INFO");
  strcat (buf1, ascii_or_wide == 'A' ? "A: " : "W: ");

  if (!proto_info)
  {
    dump_one_proto_info (buf1, "NULL");
    trace_puts ("~0");
    return;
  }

  flags = pi_a->dwServiceFlags1;
  if (flags == 0)
       flags_str = "0";
  else flags_str = flags_decode (flags, wsaprotocol_info_ServiceFlags1,
                                 DIM(wsaprotocol_info_ServiceFlags1));

  snprintf (buf2, sizeof(buf2), "dwServiceFlags1:    %s", flags_str);

#if 1
  trace_indent (g_cfg.trace_indent+2);
  trace_puts (buf1);
  format_and_print_line (buf2, g_cfg.trace_indent + strlen(buf1) + sizeof("dwServiceFlags1:   "), '|');
#else
  dump_one_proto_info (buf1, buf2);
#endif

  dump_one_proto_info (NULL, "dwServiceFlags2:    Reserved");
  dump_one_proto_info (NULL, "dwServiceFlags3:    Reserved");
  dump_one_proto_info (NULL, "dwServiceFlags4:    Reserved");

  flags = pi_a->dwProviderFlags;
  if (flags == 0)
       flags_str = "0";
  else flags_str = flags_decode (flags, wsaprotocol_info_ProviderFlags,
                                 DIM(wsaprotocol_info_ProviderFlags));

  snprintf (buf2, sizeof(buf2), "dwProviderFlags:    %s", flags_str);
  dump_one_proto_info (NULL, buf2);

  snprintf (buf2, sizeof(buf2), "dwCatalogEntryId:   %lu", pi_a->dwCatalogEntryId);
  dump_one_proto_info (NULL, buf2);

  snprintf (buf2, sizeof(buf2), "ProtocolChain:      {len: %d... }", pi_a->ProtocolChain.ChainLen);
  dump_one_proto_info (NULL, buf2);

  snprintf (buf2, sizeof(buf2), "iVersion:           %d", pi_a->iVersion);
  dump_one_proto_info (NULL, buf2);

  snprintf (buf2, sizeof(buf2), "iAddressFamily:     %d = %s", pi_a->iAddressFamily, socket_family(pi_a->iAddressFamily));
  dump_one_proto_info (NULL, buf2);

  snprintf (buf2, sizeof(buf2), "iMaxSockAddr:       %d", pi_a->iMaxSockAddr);
  dump_one_proto_info (NULL, buf2);

  snprintf (buf2, sizeof(buf2), "iMinSockAddr:       %d", pi_a->iMinSockAddr);
  dump_one_proto_info (NULL, buf2);

  snprintf (buf2, sizeof(buf2), "iSocketType:        %d = %s", pi_a->iSocketType, socket_type(pi_a->iSocketType));
  dump_one_proto_info (NULL, buf2);

  snprintf (buf2, sizeof(buf2), "iProtocol:          %d = %s", pi_a->iProtocol, protocol_name(pi_a->iProtocol));
  dump_one_proto_info (NULL, buf2);

  snprintf (buf2, sizeof(buf2), "iProtocolMaxOffset: %d", pi_a->iProtocolMaxOffset);
  dump_one_proto_info (NULL, buf2);

  snprintf (buf2, sizeof(buf2), "iNetworkByteOrder:  %d = %s",
            pi_a->iNetworkByteOrder, pi_a->iNetworkByteOrder == 0 ? "BIGENDIAN" : "LITTLEENDIAN");
  dump_one_proto_info (NULL, buf2);

  snprintf (buf2, sizeof(buf2), "iSecurityScheme:    %d", pi_a->iSecurityScheme);
  dump_one_proto_info (NULL, buf2);

  snprintf (buf2, sizeof(buf2), "dwMessageSize:      0x%08lX", pi_a->dwMessageSize);
  dump_one_proto_info (NULL, buf2);

  snprintf (buf2, sizeof(buf2), "dwProviderReserved: Reserved");
  dump_one_proto_info (NULL, buf2);

  if (ascii_or_wide == 'A')
       snprintf (buf2, sizeof(buf2), "szProtocol:         \"%.*s\"", WSAPROTOCOL_LEN, pi_a->szProtocol);
  else snprintf (buf2, sizeof(buf2), "szProtocol:         \"%.*S\"", WSAPROTOCOL_LEN, pi_w->szProtocol);
  dump_one_proto_info (NULL, buf2);

  snprintf (buf2, sizeof(buf2), "ProviderId:         %s", get_guid_string(&pi_a->ProviderId));
  dump_one_proto_info (NULL, buf2);

  if (ascii_or_wide == 'A')
       dump_provider_path (&pi_a->ProviderId, provider_path_func);
  else dump_provider_path (&pi_w->ProviderId, provider_path_func);

  trace_puts ("~0");
#endif
}

#if defined(__GNUC__)
  /*
   * dump.c:1106:17: warning: trigraph ??> ignored, use -trigraphs to enable [-Wtrigraphs]
   *                  addr = "<??>";
   */
  #pragma GCC diagnostic ignored "-Wtrigraphs"
#endif

static const char *dump_addr_list (int type, const char **addresses)
{
  static char result[200];
  char  *out = result;
  int    i, len, left = (int)sizeof(result)-1;

  for (i = 0; addresses && addresses[i] && left > 0; i++)
  {
    char  buf [MAX_IP6_SZ];
    char *addr = wsock_trace_inet_ntop (type, addresses[i], buf, sizeof(buf));

    if (!addr)
       addr = "<??>";
    len = snprintf (out, left, "%s, ", addr);
    out  += len;
    left -= len;
    if (left < 15)
    {
      strcpy (out-2, "..  ");
      break;
    }
  }
  if (i == 0)
     return ("<none>");
  *(out-2) = '\0';
  return (result);
}

/*
 * Dump the list of aliases from dump_hostent(), dump_servent() or dump_protoent().
 */
static const char *dump_aliases (char **aliases)
{
  static char result[500];  /* Win-XP supports only 8 aliases in a 'hostent::h_aliases' */
  char  *out = result;
  int    i, len, indent = g_cfg.trace_indent + 3 + (int)strlen("aliases:");
  size_t left = sizeof(result)-1;

  for (i = 0; aliases && aliases[i]; i++)
  {
    out = maybe_wrap_line (indent, (int)strlen(aliases[i])+2, result, out);
    len = snprintf (out, left, "%s, ", aliases[i]);
    out  += len;
    left -= len;

    if (aliases[i+1] && left < strlen(aliases[i+1])+2)
    {
      strcpy (out-2, "...  ");
      out += 2;
      break;
    }
  }
  if (i == 0)
     return ("<none>");
  *(out-2) = '.';
  *(out-1) = '\0';
  return (result);
}

/*
 * \todo: Optionally use MaxMind's Geoip*.mmdb files and print the location (city) too.
 */
static void trace_printf_cc (const char            *country_code,
                             const char            *location,
                             const struct in_addr  *a4,
                             const struct in6_addr *a6,
                             const void            *next_addr)
{
  if (country_code)
       trace_printf ("%s - %s", country_code, geoip_get_long_name_by_A2(country_code));
  else if (geoip_addr_is_zero(a4,a6))
       trace_puts ("NULL-addr");
  else if (geoip_addr_is_multicast(a4,a6))
       trace_puts ("Multicast");
  else if (geoip_addr_is_special(a4,a6))
       trace_puts ("Special");
  else if (!geoip_addr_is_global(a4,a6))
       trace_puts ("Not global");
  else trace_puts ("None");

  if (next_addr)
       trace_puts (", ");
  else trace_putc ('.');

  ARGSUSED (location);
}

void dump_countries (int type, const char **addresses)
{
  int i;

  WSAError_save_restore (0);

  trace_indent (g_cfg.trace_indent+2);
  trace_printf ("~4geo-IP: ");

  for (i = 0; addresses && addresses[i]; i++)
  {
    const struct in_addr  *a4  = NULL;
    const struct in6_addr *a6  = NULL;
    const char            *cc  = NULL;
    const char            *loc = NULL;

    if (type == AF_INET)
    {
      a4 = (const struct in_addr*) addresses[i];
      cc = geoip_get_country_by_ipv4 (a4);
  //  loc = geoip_get_location_by_ipv4 (a4);
    }
    else if (type == AF_INET6)
    {
      a6 = (const struct in6_addr*) addresses[i];
      cc = geoip_get_country_by_ipv6 (a6);
  //  loc = geoip_get_location_by_ipv6 (a6);
    }
    else
    {
      trace_printf ("Unknown family: %d.", type);
      break;
    }
    trace_printf_cc (cc, loc, a4, a6, addresses[i+1]);
  }
  if (i == 0)
       trace_puts ("None!?\n~0");
  else trace_puts ("\n~0");

  WSAError_save_restore (1);
}

/*
 * Can only be 1 address in a 'sockaddr', but use the plural
 * 'countries' here anyway.
 */
void dump_countries_sockaddr (const struct sockaddr *sa)
{
  const char                *addr[2] = { NULL, NULL };
  const struct sockaddr_in  *sa4;
  const struct sockaddr_in6 *sa6;

  if (!sa)
     return;

  if (sa->sa_family == AF_INET)
  {
    sa4 = (const struct sockaddr_in*) sa;
    addr[0] = (const char*) &sa4->sin_addr;
    dump_countries (AF_INET, addr);
  }
  else if (sa->sa_family == AF_INET6)
  {
    sa6 = (const struct sockaddr_in6*) sa;
    addr[0] = (const char*) &sa6->sin6_addr;
    dump_countries (AF_INET6, addr);
  }
}

/*
 * There can be a mix of 'AF_INET/AF_INET6' types in a single 'addrinfo'
 * structure.
 */
void dump_countries_addrinfo (const struct addrinfo *ai)
{
  int num;

  WSAError_save_restore (0);

  trace_indent (g_cfg.trace_indent+2);
  trace_printf ("~4geo-IP: ");

  for (num = 0; ai; ai = ai->ai_next, num++)
  {
    const struct sockaddr_in  *sa4 = NULL;
    const struct sockaddr_in6 *sa6 = NULL;
    const char                *cc  = NULL;
    const char                *loc = NULL;

    if (ai->ai_family == AF_INET)
    {
      sa4 = (const struct sockaddr_in*) ai->ai_addr;
      cc  = geoip_get_country_by_ipv4 (&sa4->sin_addr);
    }
    else if (ai->ai_family == AF_INET6)
    {
      sa6 = (const struct sockaddr_in6*) ai->ai_addr;
      cc  = geoip_get_country_by_ipv6 (&sa6->sin6_addr);
    }
    else
    {
      trace_printf ("Unknown family: %d.", ai->ai_family);
      break;
    }
    trace_printf_cc (cc, loc,
                     sa4 ? &sa4->sin_addr : NULL,
                     sa6 ? &sa6->sin6_addr : NULL,
                     ai->ai_next);
  }
  if (num == 0)
       trace_puts ("None!?\n~0");
  else trace_puts ("\n~0");

  WSAError_save_restore (1);
}

void dump_nameinfo (const char *host, const char *serv, DWORD flags)
{
  trace_indent (g_cfg.trace_indent+2);
  trace_printf ("~4name: %s, serv: %s\n~0",
                host ? host : "NULL", serv ? serv : "NULL");
}

void dump_hostent (const struct hostent *host)
{
  trace_indent (g_cfg.trace_indent+2);
  trace_printf ("~4name: %s, addrtype: %s, addr_list: %s\n",
                host->h_name, socket_family(host->h_addrtype),
                dump_addr_list(host->h_addrtype, (const char**)host->h_addr_list));

  trace_indent (g_cfg.trace_indent+2);
  trace_printf ("aliases: %s\n~0", dump_aliases(host->h_aliases));
}

void dump_servent (const struct servent *serv)
{
  trace_indent (g_cfg.trace_indent+2);
  trace_printf ("~4name: %s, port: %d, proto: %s\n",
                serv->s_name, swap16(serv->s_port), serv->s_proto);

  trace_indent (g_cfg.trace_indent+2);
  trace_printf ("aliases: %s\n~0", dump_aliases(serv->s_aliases));
}

void dump_protoent (const struct protoent *proto)
{
  trace_indent (g_cfg.trace_indent+2);
  trace_printf ("~4name: %s, proto: %d\n", proto->p_name, proto->p_proto);

  trace_indent (g_cfg.trace_indent+2);
  trace_printf ("aliases: %s\n~0", dump_aliases(proto->p_aliases));
}

void dump_events (const WSANETWORKEVENTS *events)
{
  int i;

  trace_indent (g_cfg.trace_indent+2);
  trace_puts ("~4events: ");
  if (!events)
  {
    trace_puts ("NULL~0");
    return;
  }
  trace_printf ("lNetworkEvents: %s\n", event_bits_decode(events->lNetworkEvents));
  for (i = 0; i < DIM(events->iErrorCode); i++)
  {
    trace_indent (g_cfg.trace_indent+4);
    trace_printf ("iErrorCode[%d]: %08X\n", i, events->iErrorCode[i]);
  }
  trace_puts ("~0");
}

/*
 * Dump the GUIDs and the address of the assosiated extension-function.
 * Called from 'WSAIoctl()' when 'code == SIO_GET_EXTENSION_FUNCTION_POINTER'.
 *
 * \todo: During init, hook all these extension functions in-case a wsock_trace
 *        user wants to use them. Thus allowing a trace of these.
 *
 * Listed at:
 *   https://msdn.microsoft.com/en-us/library/windows/desktop/bb736550(v=vs.85).aspx
 *
 * Should be in <mswsock.h>, but it's not for __WATCOMC__.
 */
#ifndef WSAID_WSASENDMSG
#define WSAID_WSASENDMSG { 0xA441E712, 0x754F, 0x43CA, {0x84,0xA7,0x0D,0xEE,0x44,0xCF,0x60,0x6D }}
#endif

static const struct GUID_search_list extension_guids[] = {
                    ADD_VALUE (WSAID_ACCEPTEX),
                    ADD_VALUE (WSAID_CONNECTEX),
                    ADD_VALUE (WSAID_DISCONNECTEX),
                    ADD_VALUE (WSAID_GETACCEPTEXSOCKADDRS),
                    ADD_VALUE (WSAID_TRANSMITFILE),
                    ADD_VALUE (WSAID_TRANSMITPACKETS),
                    ADD_VALUE (WSAID_WSARECVMSG),
                    ADD_VALUE (WSAID_WSASENDMSG)
                  };

void dump_extension_funcs (const GUID *in_guid, const void *out_buf)
{
  const GUID *guid = &extension_guids[0].guid;
  const char *name = "Unknown extension";
  int   i;

  for (i = 0; i < DIM(extension_guids); guid = &extension_guids[++i].guid)
  {
    if (!memcmp(in_guid,guid,sizeof(*guid)))
    {
      name = extension_guids[i].name;
      break;
    }
  }
  trace_indent (g_cfg.trace_indent+2);
  trace_printf ("~4GUID %s -> %s (0x%p)~0\n", get_guid_string(in_guid), name, out_buf);
}

static const struct search_list test_list_1[] = {
                              { 0, "foo"    },
                              { 1, "bar"    },
                              { 2, "bar2"   },
                              { 3, "bar3"   },
                              { 0, "foobar" }
                            };
static const struct search_list test_list_2[] = {
                              { 0,          "foo" },
                              { 1,          "bar" },
                              { UINT_MAX,   "00"  },
                              { UINT_MAX,   "01"  }
                            };

static void report_check_err (const struct search_list *tab, const char *name, int rc, int idx1, int idx2)
{
  switch (rc)
  {
    case -1:
         trace_printf ("%s[%d]: name == NULL.\n", name, idx1);
         break;
    case -2:
         trace_printf ("%s[%d]: name[0] == 0.\n", name, idx1);
         break;
    case -3:
         trace_printf ("%s[%d]: value == UINT_MAX.\n", name, idx1);
         break;
     case -4:
         trace_printf ("%s[%d+%d]: Duplicated values: '%s'=%u and '%s'=%u.\n",
                         name, idx1, idx2, tab[idx1].name, tab[idx1].value,
                         tab[idx2].name, tab[idx2].value);
         break;
  }
}

void check_all_search_lists (void)
{
  const struct search_list *list;
  int   rc, idx1, idx2;

#define CHECK(tab) rc = list_lookup_check (list = tab, DIM(tab), &idx1, &idx2); \
                   report_check_err (list, #tab, rc, idx1, idx2)

  CHECK (sol_options);
  CHECK (tcp_options);
  CHECK (ip4_options);
  CHECK (ip6_options);
  CHECK (families);
  CHECK (levels);
  CHECK (types);
  CHECK (ai_flgs);
  CHECK (wsa_events_flgs);
  CHECK (ioctl_commands);
  CHECK (sio_codes);
  CHECK (test_list_1);
  CHECK (test_list_2);
}

