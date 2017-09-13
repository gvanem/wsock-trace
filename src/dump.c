/*
 * Dump and trace-functions for wsock_trace.
 */
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <limits.h>
#include <assert.h>
#include <ctype.h>

#include "common.h"
#include "in_addr.h"
#include "init.h"
#include "geoip.h"
#include "idna.h"
#include "hosts.h"
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
 * Missing 'SOL_x' levels.
 */
#ifndef SOL_RFCOMM
#define SOL_RFCOMM  0x0003
#endif

#ifndef SOL_IRLMP
#define SOL_IRLMP   0x00FF
#endif

#ifndef SOL_L2CAP
#define SOL_L2CAP   0x0100
#endif

#ifndef SOL_SDP
#define SOL_SDP     0x0101
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

#ifndef AF_CLUSTER
#define AF_CLUSTER       24
#endif

#ifndef AF_12844
#define AF_12844         25
#endif

#ifndef AF_NETDES
#define AF_NETDES        28
#endif

#ifndef AF_TCNPROCESS
#define AF_TCNPROCESS    29
#endif

#ifndef AF_TCNMESSAGE
#define AF_TCNMESSAGE    30
#endif

#ifndef AF_ICLFXBM
#define AF_ICLFXBM       31
#endif

#ifndef AF_BTH
#define AF_BTH           32
#endif

#ifndef AF_LINK
#define AF_LINK          33
#endif

#ifndef AF_HYPERV
#define AF_HYPERV        34
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

#ifndef AI_NUMERICSERV
#define AI_NUMERICSERV            0x00000008
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

#ifndef AI_SECURE
#define AI_SECURE                 0x00008000
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

#ifndef AI_DISABLE_IDN_ENCODING
#define AI_DISABLE_IDN_ENCODING   0x00080000
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
 * All 'SIO_x' codes presently in MS's Windows headers.
 */
#ifndef SIO_ASSOCIATE_HANDLE
#define SIO_ASSOCIATE_HANDLE                         _WSAIOW (IOC_WS2, 1)
#endif

#ifndef SIO_ENABLE_CIRCULAR_QUEUEING
#define SIO_ENABLE_CIRCULAR_QUEUEING                 _WSAIO (IOC_WS2, 2)
#endif

#ifndef SIO_FIND_ROUTE
#define SIO_FIND_ROUTE                               _WSAIOR (IOC_WS2, 3)
#endif

#ifndef SIO_FLUSH
#define SIO_FLUSH                                    _WSAIO (IOC_WS2, 4)
#endif

#ifndef SIO_GET_BROADCAST_ADDRESS
#define SIO_GET_BROADCAST_ADDRESS                    _WSAIOR (IOC_WS2, 5)
#endif

#ifndef SIO_GET_EXTENSION_FUNCTION_POINTER
#define SIO_GET_EXTENSION_FUNCTION_POINTER           _WSAIORW (IOC_WS2, 6)
#endif

#ifndef SIO_GET_QOS
#define SIO_GET_QOS                                  _WSAIORW (IOC_WS2, 7)
#endif

#ifndef SIO_GET_GROUP_QOS
#define SIO_GET_GROUP_QOS                            _WSAIORW (IOC_WS2, 8)
#endif

#ifndef SIO_MULTIPOINT_LOOPBACK
#define SIO_MULTIPOINT_LOOPBACK                      _WSAIOW (IOC_WS2, 9)
#endif

#ifndef SIO_SET_QOS
#define SIO_SET_QOS                                  _WSAIOW (IOC_WS2, 11)
#endif

#ifndef SIO_MULTICAST_SCOPE
#define SIO_MULTICAST_SCOPE                          _WSAIOW (IOC_WS2, 10)
#endif

#ifndef SIO_SET_GROUP_QOS
#define SIO_SET_GROUP_QOS                            _WSAIOW (IOC_WS2, 12)
#endif

#ifndef SIO_TRANSLATE_HANDLE
#define SIO_TRANSLATE_HANDLE                         _WSAIORW (IOC_WS2, 13)
#endif

#ifndef SIO_ROUTING_INTERFACE_CHANGE
#define SIO_ROUTING_INTERFACE_CHANGE                 _WSAIOW (IOC_WS2, 21)
#endif

#ifndef SIO_ROUTING_INTERFACE_QUERY
#define SIO_ROUTING_INTERFACE_QUERY                  _WSAIORW (IOC_WS2, 20)
#endif

#ifndef SIO_ADDRESS_LIST_QUERY
#define SIO_ADDRESS_LIST_QUERY                       _WSAIOR (IOC_WS2, 22)
#endif

#ifndef SIO_ADDRESS_LIST_CHANGE
#define SIO_ADDRESS_LIST_CHANGE                      _WSAIO (IOC_WS2, 23)
#endif

#ifndef SIO_QUERY_TARGET_PNP_HANDLE
#define SIO_QUERY_TARGET_PNP_HANDLE                  _WSAIOR (IOC_WS2, 24)
#endif

#ifndef SIO_ADDRESS_LIST_SORT
#define SIO_ADDRESS_LIST_SORT                        _WSAIORW (IOC_WS2, 25)
#endif

#ifndef SIO_NSP_NOTIFY_CHANGE
#define SIO_NSP_NOTIFY_CHANGE                        _WSAIOW (IOC_WS2, 25)
#endif

#ifndef SIO_RESERVED_1
#define SIO_RESERVED_1                               _WSAIOW (IOC_WS2, 26)
#endif

#ifndef SIO_BSP_HANDLE
#define SIO_BSP_HANDLE                               _WSAIOR (IOC_WS2, 27)
#endif

#ifndef SIO_BSP_HANDLE_SELECT
#define SIO_BSP_HANDLE_SELECT                        _WSAIOR (IOC_WS2, 28)
#endif

#ifndef SIO_BSP_HANDLE_POLL
#define SIO_BSP_HANDLE_POLL                          _WSAIOR (IOC_WS2, 29)
#endif

#ifndef SIO_EXT_SELECT
#define SIO_EXT_SELECT                               _WSAIORW (IOC_WS2, 30)
#endif

#ifndef SIO_EXT_POLL
#define SIO_EXT_POLL                                 _WSAIORW (IOC_WS2, 31)
#endif

#ifndef SIO_EXT_SENDMSG
#define SIO_EXT_SENDMSG                              _WSAIORW (IOC_WS2, 32)
#endif

#ifndef SIO_RESERVED_2
#define SIO_RESERVED_2                               _WSAIOW (IOC_WS2, 33)
#endif

#ifndef SIO_BASE_HANDLE
#define SIO_BASE_HANDLE                              _WSAIOR (IOC_WS2, 34)
#endif

#ifndef SIO_GET_MULTIPLE_EXTENSION_FUNCTION_POINTER
#define SIO_GET_MULTIPLE_EXTENSION_FUNCTION_POINTER  _WSAIORW (IOC_WS2, 36)
#endif

#ifndef SIO_QUERY_RSS_PROCESSOR_INFO
#define SIO_QUERY_RSS_PROCESSOR_INFO                 _WSAIOR (IOC_WS2, 37)
#endif

#ifndef SIO_IDEAL_SEND_BACKLOG_CHANGE
#define SIO_IDEAL_SEND_BACKLOG_CHANGE                _IO ('t', 122)
#endif

#ifndef SIO_IDEAL_SEND_BACKLOG_QUERY
#define SIO_IDEAL_SEND_BACKLOG_QUERY                 _IOR ('t', 123, ULONG)
#endif

#ifndef SIO_GET_MULTICAST_FILTER
#define SIO_GET_MULTICAST_FILTER                     _IOW ('t', 124 | IOC_IN, ULONG)
#endif

#ifndef SIO_SET_MULTICAST_FILTER
#define SIO_SET_MULTICAST_FILTER                     _IOW ('t', 125, ULONG)
#endif

#ifndef SIO_GET_INTERFACE_LIST_EX
#define SIO_GET_INTERFACE_LIST_EX                    _IOR ('t', 126, ULONG)
#endif

#ifndef SIO_LAZY_DISCOVERY
#define SIO_LAZY_DISCOVERY                           _IOR ('t', 127, u_long)
#endif

#ifndef SIO_GET_INTERFACE_LIST
#define SIO_GET_INTERFACE_LIST                       _IOR ('t', 127, ULONG)
#endif

#ifndef SIO_RCVALL
#define SIO_RCVALL                                   _WSAIOW (IOC_VENDOR, 1)
#endif

#ifndef SIO_CHK_QOS
#define SIO_CHK_QOS                                  _WSAIORW (IOC_VENDOR, 1)
#endif

#ifndef SIO_RCVALL_MCAST
#define SIO_RCVALL_MCAST                             _WSAIOW (IOC_VENDOR, 2)
#endif

#ifndef SIO_RCVALL_IGMPMCAST
#define SIO_RCVALL_IGMPMCAST                         _WSAIOW (IOC_VENDOR, 3)
#endif

#ifndef SIO_KEEPALIVE_VALS
#define SIO_KEEPALIVE_VALS                           _WSAIOW (IOC_VENDOR, 4)
#endif

#ifndef SIO_ABSORB_RTRALERT
#define SIO_ABSORB_RTRALERT                          _WSAIOW (IOC_VENDOR, 5)
#endif

#ifndef SIO_UCAST_IF
#define SIO_UCAST_IF                                 _WSAIOW (IOC_VENDOR, 6)
#endif

#ifndef SIO_LIMIT_BROADCASTS
#define SIO_LIMIT_BROADCASTS                         _WSAIOW (IOC_VENDOR, 7)
#endif

#ifndef SIO_BTH_PING
#define SIO_BTH_PING                                 _WSAIORW (IOC_VENDOR, 8)
#endif

#ifndef SIO_INDEX_BIND
#define SIO_INDEX_BIND                               _WSAIOW (IOC_VENDOR, 8)
#endif

#ifndef SIO_INDEX_MCASTIF
#define SIO_INDEX_MCASTIF                            _WSAIOW (IOC_VENDOR, 9)
#endif

#ifndef SIO_BTH_INFO
#define SIO_BTH_INFO                                 _WSAIORW (IOC_VENDOR, 9)
#endif

#ifndef SIO_INDEX_ADD_MCAST
#define SIO_INDEX_ADD_MCAST                          _WSAIOW (IOC_VENDOR, 10)
#endif

#ifndef SIO_INDEX_DEL_MCAST
#define SIO_INDEX_DEL_MCAST                          _WSAIOW (IOC_VENDOR, 11)
#endif

#ifndef SIO_UDP_CONNRESET
#define SIO_UDP_CONNRESET                            _WSAIOW (IOC_VENDOR, 12)
#endif

#ifndef SIO_RCVALL_MCAST_IF
#define SIO_RCVALL_MCAST_IF                          _WSAIOW (IOC_VENDOR, 13)
#endif

#ifndef SIO_SOCKET_CLOSE_NOTIFY
#define SIO_SOCKET_CLOSE_NOTIFY                      _WSAIOW (IOC_VENDOR, 13)
#endif

#ifndef SIO_RCVALL_IF
#define SIO_RCVALL_IF                                _WSAIOW (IOC_VENDOR, 14)
#endif

#ifndef SIO_UDP_NETRESET
#define SIO_UDP_NETRESET                             _WSAIOW (IOC_VENDOR, 15)
#endif

#ifndef SIO_LOOPBACK_FAST_PATH
#define SIO_LOOPBACK_FAST_PATH                       _WSAIOW (IOC_VENDOR, 16)
#endif

#ifndef SIO_TCP_INITIAL_RTO
#define SIO_TCP_INITIAL_RTO                          _WSAIOW (IOC_VENDOR, 17)
#endif

#ifndef SIO_APPLY_TRANSPORT_SETTING
#define SIO_APPLY_TRANSPORT_SETTING                  _WSAIOW (IOC_VENDOR, 19)
#endif

#ifndef SIO_QUERY_TRANSPORT_SETTING
#define SIO_QUERY_TRANSPORT_SETTING                  _WSAIOW (IOC_VENDOR, 20)
#endif

#ifndef SIO_TCP_SET_ICW
#define SIO_TCP_SET_ICW                              _WSAIOW (IOC_VENDOR, 22)
#endif

#ifndef SIO_TCP_SET_ACK_FREQUENCY
#define SIO_TCP_SET_ACK_FREQUENCY                    _WSAIOW (IOC_VENDOR, 23)
#endif

#ifndef SIO_ACQUIRE_PORT_RESERVATION
#define SIO_ACQUIRE_PORT_RESERVATION                 _WSAIOW (IOC_VENDOR, 100)
#endif

#ifndef SIO_RELEASE_PORT_RESERVATION
#define SIO_RELEASE_PORT_RESERVATION                 _WSAIOW (IOC_VENDOR, 101)
#endif

#ifndef SIO_RFCOMM_SEND_COMMAND
#define SIO_RFCOMM_SEND_COMMAND                      _WSAIORW (IOC_VENDOR, 101)
#endif

#ifndef SIO_ASSOCIATE_PORT_RESERVATION
#define SIO_ASSOCIATE_PORT_RESERVATION               _WSAIOW (IOC_VENDOR, 102)
#endif

#ifndef SIO_RFCOMM_WAIT_COMMAND
#define SIO_RFCOMM_WAIT_COMMAND                      _WSAIORW (IOC_VENDOR, 102)
#endif

#ifndef SIO_RFCOMM_SESSION_FLOW_OFF
#define SIO_RFCOMM_SESSION_FLOW_OFF                  _WSAIORW (IOC_VENDOR, 103)
#endif

#ifndef SIO_RFCOMM_TEST
#define SIO_RFCOMM_TEST                              _WSAIORW (IOC_VENDOR, 104)
#endif

#ifndef SIO_RFCOMM_USECFC
#define SIO_RFCOMM_USECFC                            _WSAIORW (IOC_VENDOR, 105)
#endif

#ifndef SIO_SET_SECURITY
#define SIO_SET_SECURITY                             _WSAIOW (IOC_VENDOR, 200)
#endif

#ifndef SIO_QUERY_SECURITY
#define SIO_QUERY_SECURITY                           _WSAIORW (IOC_VENDOR, 201)
#endif

#ifndef SIO_SET_PEER_TARGET_NAME
#define SIO_SET_PEER_TARGET_NAME                     _WSAIOW (IOC_VENDOR, 202)
#endif

#ifndef SIO_DELETE_PEER_TARGET_NAME
#define SIO_DELETE_PEER_TARGET_NAME                  _WSAIOW (IOC_VENDOR, 203)
#endif

#ifndef SIO_SOCKET_USAGE_NOTIFICATION
#define SIO_SOCKET_USAGE_NOTIFICATION                _WSAIOW (IOC_VENDOR, 204)
#endif

#ifndef SIO_QUERY_WFP_ALE_ENDPOINT_HANDLE
#define SIO_QUERY_WFP_ALE_ENDPOINT_HANDLE            _WSAIOR (IOC_VENDOR, 205)
#endif

#ifndef SIO_QUERY_RSS_SCALABILITY_INFO
#define SIO_QUERY_RSS_SCALABILITY_INFO               _WSAIOR (IOC_VENDOR, 210)
#endif

#ifndef SIO_QUERY_WFP_CONNECTION_REDIRECT_CONTEXT
#define SIO_QUERY_WFP_CONNECTION_REDIRECT_CONTEXT    _WSAIOW (IOC_VENDOR, 221)
#endif

#ifndef SIO_QUERY_WFP_CONNECTION_REDIRECT_RECORDS
#define SIO_QUERY_WFP_CONNECTION_REDIRECT_RECORDS    _WSAIOW (IOC_VENDOR, 220)
#endif

#ifndef SIO_SET_WFP_CONNECTION_REDIRECT_RECORDS
#define SIO_SET_WFP_CONNECTION_REDIRECT_RECORDS      _WSAIOW (IOC_VENDOR, 222)
#endif

#ifndef SIO_SET_COMPATIBILITY_MODE
#define SIO_SET_COMPATIBILITY_MODE                   _WSAIOW (IOC_VENDOR, 300)
#endif

#ifndef SIO_GET_NUMBER_OF_ATM_DEVICES
#define SIO_GET_NUMBER_OF_ATM_DEVICES                0x50160001
#endif

#ifndef SIO_GET_ATM_ADDRESS
#define SIO_GET_ATM_ADDRESS                          0xD0160002
#endif

#ifndef SIO_ASSOCIATE_PVC
#define SIO_ASSOCIATE_PVC                            0x90160003
#endif

#ifndef SIO_GET_ATM_CONNECTION_ID
#define SIO_GET_ATM_CONNECTION_ID                    0x50160004
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
                /*  ADD_VALUE (SO_PROTOCOL_INFOA), Same as above */
                    ADD_VALUE (SO_PROTOCOL_INFOW),
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
                    ADD_VALUE (AF_BTH),
                    ADD_VALUE (AF_CLUSTER),
                    ADD_VALUE (AF_12844),
                    ADD_VALUE (AF_NETDES),
                    ADD_VALUE (AF_TCNPROCESS),
                    ADD_VALUE (AF_TCNMESSAGE),
                    ADD_VALUE (AF_ICLFXBM),
                    ADD_VALUE (AF_LINK),
                    ADD_VALUE (AF_HYPERV)
                  };

static const struct search_list levels[] = {
                    ADD_VALUE (SOL_SOCKET),
                    ADD_VALUE (SOL_IRLMP),
                    ADD_VALUE (SOL_SDP),
                    ADD_VALUE (SOL_RFCOMM),
                    ADD_VALUE (SOL_L2CAP),
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
                    ADD_VALUE (AI_NUMERICSERV),
                    ADD_VALUE (AI_ADDRCONFIG),
                    ADD_VALUE (AI_NON_AUTHORITATIVE),
                    ADD_VALUE (AI_SECURE),
                    ADD_VALUE (AI_RETURN_PREFERRED_NAMES),
                    ADD_VALUE (AI_FILESERVER),
                    ADD_VALUE (AI_DISABLE_IDN_ENCODING),
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
                    ADD_VALUE (IPPROTO_RAW)
                  };

#if !defined(__WATCOMC__)
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
#endif

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
                    ADD_VALUE (SIO_ABSORB_RTRALERT),
                    ADD_VALUE (SIO_ACQUIRE_PORT_RESERVATION),
                    ADD_VALUE (SIO_ADDRESS_LIST_CHANGE),
                    ADD_VALUE (SIO_ADDRESS_LIST_QUERY),
                    ADD_VALUE (SIO_ADDRESS_LIST_SORT),
                    ADD_VALUE (SIO_APPLY_TRANSPORT_SETTING),
                    ADD_VALUE (SIO_ASSOCIATE_HANDLE),
                    ADD_VALUE (SIO_ASSOCIATE_PORT_RESERVATION),
                    ADD_VALUE (SIO_ASSOCIATE_PVC),
                    ADD_VALUE (SIO_BASE_HANDLE),
                    ADD_VALUE (SIO_BSP_HANDLE),
                    ADD_VALUE (SIO_BSP_HANDLE_POLL),
                    ADD_VALUE (SIO_BSP_HANDLE_SELECT),
                    ADD_VALUE (SIO_BTH_INFO),
                    ADD_VALUE (SIO_BTH_PING),
                    ADD_VALUE (SIO_CHK_QOS),
                    ADD_VALUE (SIO_DELETE_PEER_TARGET_NAME),
                    ADD_VALUE (SIO_ENABLE_CIRCULAR_QUEUEING),
                    ADD_VALUE (SIO_EXT_POLL),
                    ADD_VALUE (SIO_EXT_SELECT),
                    ADD_VALUE (SIO_EXT_SENDMSG),
                    ADD_VALUE (SIO_FIND_ROUTE),
                    ADD_VALUE (SIO_FLUSH),
                    ADD_VALUE (SIO_GET_ATM_ADDRESS),
                    ADD_VALUE (SIO_GET_ATM_CONNECTION_ID),
                    ADD_VALUE (SIO_GET_BROADCAST_ADDRESS),
                    ADD_VALUE (SIO_GET_EXTENSION_FUNCTION_POINTER),
                    ADD_VALUE (SIO_GET_GROUP_QOS),
                    ADD_VALUE (SIO_GET_INTERFACE_LIST),
                    ADD_VALUE (SIO_GET_INTERFACE_LIST_EX),
                    ADD_VALUE (SIO_GET_MULTICAST_FILTER),
                    ADD_VALUE (SIO_GET_MULTIPLE_EXTENSION_FUNCTION_POINTER),
                    ADD_VALUE (SIO_GET_NUMBER_OF_ATM_DEVICES),
                    ADD_VALUE (SIO_GET_QOS),
                    ADD_VALUE (SIO_IDEAL_SEND_BACKLOG_CHANGE),
                    ADD_VALUE (SIO_IDEAL_SEND_BACKLOG_QUERY),
                    ADD_VALUE (SIO_INDEX_ADD_MCAST),
                    ADD_VALUE (SIO_INDEX_BIND),
                    ADD_VALUE (SIO_INDEX_DEL_MCAST),
                    ADD_VALUE (SIO_INDEX_MCASTIF),
                    ADD_VALUE (SIO_KEEPALIVE_VALS),
                 /* ADD_VALUE (SIO_LAZY_DISCOVERY), Because it's the same value as 'SIO_GET_INTERFACE_LIST' */
                    ADD_VALUE (SIO_LIMIT_BROADCASTS),
                    ADD_VALUE (SIO_LOOPBACK_FAST_PATH),
                    ADD_VALUE (SIO_MULTICAST_SCOPE),
                    ADD_VALUE (SIO_MULTIPOINT_LOOPBACK),
                    ADD_VALUE (SIO_NSP_NOTIFY_CHANGE),
                    ADD_VALUE (SIO_QUERY_RSS_PROCESSOR_INFO),
                    ADD_VALUE (SIO_QUERY_RSS_SCALABILITY_INFO),
                    ADD_VALUE (SIO_QUERY_SECURITY),
                    ADD_VALUE (SIO_QUERY_TARGET_PNP_HANDLE),
                    ADD_VALUE (SIO_QUERY_TRANSPORT_SETTING),
                    ADD_VALUE (SIO_QUERY_WFP_ALE_ENDPOINT_HANDLE),
                    ADD_VALUE (SIO_QUERY_WFP_CONNECTION_REDIRECT_CONTEXT),
                    ADD_VALUE (SIO_QUERY_WFP_CONNECTION_REDIRECT_RECORDS),
                    ADD_VALUE (SIO_RCVALL),
                    ADD_VALUE (SIO_RCVALL_IF),
                    ADD_VALUE (SIO_RCVALL_IGMPMCAST),
                    ADD_VALUE (SIO_RCVALL_MCAST),
                 /* ADD_VALUE (SIO_RCVALL_MCAST_IF), Because it's the same value as 'SIO_SOCKET_CLOSE_NOTIFY' */
                    ADD_VALUE (SIO_RELEASE_PORT_RESERVATION),
                    ADD_VALUE (SIO_RESERVED_1),
                    ADD_VALUE (SIO_RESERVED_2),
                    ADD_VALUE (SIO_RFCOMM_SEND_COMMAND),
                    ADD_VALUE (SIO_RFCOMM_SESSION_FLOW_OFF),
                    ADD_VALUE (SIO_RFCOMM_TEST),
                    ADD_VALUE (SIO_RFCOMM_USECFC),
                    ADD_VALUE (SIO_RFCOMM_WAIT_COMMAND),
                    ADD_VALUE (SIO_ROUTING_INTERFACE_CHANGE),
                    ADD_VALUE (SIO_ROUTING_INTERFACE_QUERY),
                    ADD_VALUE (SIO_SET_COMPATIBILITY_MODE),
                    ADD_VALUE (SIO_SET_GROUP_QOS),
                    ADD_VALUE (SIO_SET_MULTICAST_FILTER),
                    ADD_VALUE (SIO_SET_PEER_TARGET_NAME),
                    ADD_VALUE (SIO_SET_QOS),
                    ADD_VALUE (SIO_SET_SECURITY),
                    ADD_VALUE (SIO_SET_WFP_CONNECTION_REDIRECT_RECORDS),
                    ADD_VALUE (SIO_SOCKET_CLOSE_NOTIFY),
                    ADD_VALUE (SIO_SOCKET_USAGE_NOTIFICATION),
                    ADD_VALUE (SIO_TCP_INITIAL_RTO),
                    ADD_VALUE (SIO_TCP_SET_ACK_FREQUENCY),
                    ADD_VALUE (SIO_TCP_SET_ICW),
                    ADD_VALUE (SIO_TRANSLATE_HANDLE),
                    ADD_VALUE (SIO_UCAST_IF),
                    ADD_VALUE (SIO_UDP_CONNRESET),
                    ADD_VALUE (SIO_UDP_NETRESET)
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

    case SOL_IRLMP:
         return ("IrDA option!?");

    case SOL_SDP:
         return ("SDP option!?");

    case SOL_RFCOMM:
         return ("RFCOMM option!?");

    case SOL_L2CAP:
         return ("L2CAP option!?");

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
 */
void print_long_flags (const char *start, size_t indent, int brk_ch)
{
  size_t      room, left = g_cfg.screen_width - indent;
  const char *c = start;

  while (*c)
  {
    /* Break a long line only at 'break char'.
     * Check if room for a flag-component ("foo|") before we must break the line.
     */
    if (*c == brk_ch)
    {
      room = (size_t) (start - strchr(c+1,brk_ch));
      if (c[1] && room < left)
      {
        trace_printf ("%c\n%*c", *c++, (int)indent, ' ');
        left  = g_cfg.screen_width - indent;
        start = c;
        continue;
      }
    }
    trace_putc (*c++);
    left--;
  }
  trace_putc ('\n');
}

const char *get_addrinfo_hint (const struct addrinfo *hint, size_t indent)
{
  static char buf[300];

  snprintf (buf, sizeof(buf),
            "ai_flags:    %s\n"
            "%*sai_family:   %s\n"
            "%*sai_socktype: %s\n"
            "%*sai_protocol: %s",
            ai_flags_decode(hint->ai_flags),
            (int)indent, "", socket_family(hint->ai_family),
            (int)indent, "", socket_type(hint->ai_socktype),
            (int)indent, "", protocol_name(hint->ai_protocol));
  return (buf);
}

void dump_addrinfo (const char *name, const struct addrinfo *ai)
{
  for ( ; ai; ai = ai->ai_next)
  {
    const int  *addr_len;
    const char *comment;

    trace_indent (g_cfg.trace_indent+2);
    trace_printf ("~4ai_flags: %s, ai_family: %s, ai_socktype: %s, ai_protocol: %s\n",
                  ai_flags_decode(ai->ai_flags),
                  socket_family(ai->ai_family),
                  socket_type(ai->ai_socktype),
                  protocol_name(ai->ai_protocol));

    if (hosts_file_check_addrinfo(name, ai) > 0)
         comment = " (in 'hosts' file)";
    else comment = "";

    trace_indent (g_cfg.trace_indent+4);
    addr_len = (const int*)&ai->ai_addrlen;

    trace_printf ("ai_canonname: %s, ai_addr: %s%s\n",
                  ai->ai_canonname, sockaddr_str2(ai->ai_addr,addr_len),
                  comment);
  }
  trace_puts ("~0");
}

/*
 * Return the number of bytes needed to hold a 'fd_set'
 */
size_t size_fd_set (const fd_set *fd)
{
  size_t size, count;

  if (!fd)
     return (0);

  /*
   * From <winsock.h>:
   *
   * typedef struct fd_set {
   *         u_int  fd_count;
   *         SOCKET fd_array[FD_SETSIZE];
   *       } fd_set;
   *
   * 'FD_SETSIZE' is defined to 64 in <winsock.h> by default.
   * But we cannot assume a certain 'FD_SETSIZE'.
   * Just allocate according to the maximum of 64 and 'fd_count'.
   */
  count = max (64, fd->fd_count);
  size = count * sizeof(SOCKET) + sizeof(u_int);
  return (size);
}

fd_set *copy_fd_set (const fd_set *fd)
{
  fd_set *copy;
  size_t  i, size;

  size = size_fd_set (fd);
  if (size == 0)
     return (NULL);

  copy = malloc (size);
  copy->fd_count = fd->fd_count;
  for (i = 0; i < (u_int)fd->fd_count; i++)
      copy->fd_array[i] = fd->fd_array[i];
  return (copy);
}

/*
 * As above, but 'dst' is allocated prior to this.
 * E.g. by 'alloca()'.
 */
void *copy_fd_set_to (const fd_set *fd, fd_set *dst)
{
  u_int i;

  dst->fd_count = fd->fd_count;
  for (i = 0; i < fd->fd_count; i++)
      dst->fd_array[i] = fd->fd_array[i];
  return (dst);
}

static void dump_one_fd (const fd_set *fd, int indent)
{
  u_int i, max_len, len = indent;
  int   j;

  for (i = 0; i < fd->fd_count; i++)
  {
    char buf[10];

    _itoa ((int)fd->fd_array[i], buf, 10);
    max_len = (u_int) (g_cfg.screen_width - strlen(buf) - 1);
    trace_puts (buf);

    if (i < fd->fd_count-1)
    {
      trace_putc (',');
      len += (u_int) strlen(buf) + 1;
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
  info[2].fd = ex;

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

  return strcpy (buf, flags_decode(ev, wsapollfd_flgs, DIM(wsapollfd_flgs)));
}

void dump_wsapollfd (const WSAPOLLFD *fd_array, ULONG fds, int indent)
{
  const WSAPOLLFD *fd = fd_array;
  int   line = 0;
  char  ev_buf1 [300];
  char  ev_buf2 [300];
  ULONG i;

  for (i = 0; i < fds; i++, fd++)
  {
    if (fd->fd == INVALID_SOCKET)
       continue;

    trace_printf ("%*sfd: %4u, fd->events: %s, fd->revents: %s\n",
                  line > 0 ? indent : 0, "", (unsigned)fd->fd,
                  wsapollfd_event_decode(fd->events,ev_buf1),
                  wsapollfd_event_decode(fd->revents,ev_buf2));
    line++;
  }
  if (line == 0)
     trace_puts ("<None>\n");
}

static const char *proto_padding = "                   ";  /* Length of "WSAPROTOCOL_INFOx: " */

void dump_one_proto_info (const char *prefix, const char *buf)
{
  trace_indent (g_cfg.trace_indent+2);
  trace_printf ("%s%s\n", prefix ? prefix : proto_padding, buf);
}

void dump_one_proto_infof (const char *fmt, ...)
{
  va_list args;

  va_start (args, fmt);
  trace_indent (g_cfg.trace_indent+2);
  trace_puts (proto_padding);
  trace_vprintf (fmt, args);
  va_end (args);
}

/*
 * Watcom lacks many things making this difficult.
 */
#if defined(__WATCOMC__)
void dump_wsaprotocol_info (char ascii_or_wide, const void *proto_info, const void *provider_path_func)
{
}
#else
static void dump_provider_path (const GUID *guid, const void *provider_path_func)
{
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

  (*p_WSCGetProviderPath) ((GUID*)guid, path, &path_len, &error);

  dump_one_proto_infof ("Provider Path:      \"%" WCHAR_FMT "\"\n", path);
}

void dump_wsaprotocol_info (char ascii_or_wide, const void *proto_info, const void *provider_path_func)
{
  const char *flags_str, *af_str;
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
    dump_one_proto_info (buf1, "NULL~0");
    return;
  }

  flags = pi_a->dwServiceFlags1;
  if (flags == 0)
       flags_str = "0";
  else flags_str = flags_decode (flags, wsaprotocol_info_ServiceFlags1,
                                 DIM(wsaprotocol_info_ServiceFlags1));

  snprintf (buf2, sizeof(buf2), "dwServiceFlags1:    %s", flags_str);

  trace_indent (g_cfg.trace_indent+2);
  trace_puts (buf1);
  print_long_flags (buf2, g_cfg.trace_indent + strlen(buf1) + sizeof("dwServiceFlags1:   "), '|');

  dump_one_proto_infof ("dwServiceFlags2:    0x%08lX (reserved)\n", pi_a->dwServiceFlags2);
  dump_one_proto_infof ("dwServiceFlags3:    0x%08lX (reserved)\n", pi_a->dwServiceFlags3);
  dump_one_proto_infof ("dwServiceFlags4:    0x%08lX (reserved)\n", pi_a->dwServiceFlags4);

  flags = pi_a->dwProviderFlags;
  if (flags == 0)
       flags_str = "0";
  else flags_str = flags_decode (flags, wsaprotocol_info_ProviderFlags,
                                 DIM(wsaprotocol_info_ProviderFlags));

  dump_one_proto_infof ("dwProviderFlags:    %s\n", flags_str);
  dump_one_proto_infof ("dwCatalogEntryId:   %lu\n", pi_a->dwCatalogEntryId);
  dump_one_proto_infof ("ProtocolChain:      len: %d, %s\n", pi_a->ProtocolChain.ChainLen,
                                                             (pi_a->ProtocolChain.ChainLen == 1) ?
                                                             "Base Service Provider" : "Layered Chain Entry");
  dump_one_proto_infof ("iVersion:           %d\n",      pi_a->iVersion);

  af_str = socket_family (pi_a->iAddressFamily);
  dump_one_proto_infof ("iAddressFamily:     %d = %s\n", pi_a->iAddressFamily, isdigit(*af_str) ? "Unknown" : af_str);
  dump_one_proto_infof ("iMaxSockAddr:       %d\n",      pi_a->iMaxSockAddr);
  dump_one_proto_infof ("iMinSockAddr:       %d\n",      pi_a->iMinSockAddr);
  dump_one_proto_infof ("iSocketType:        %d = %s\n", pi_a->iSocketType, socket_type(pi_a->iSocketType));
  dump_one_proto_infof ("iProtocol:          %d = %s\n", pi_a->iProtocol, protocol_name(pi_a->iProtocol));
  dump_one_proto_infof ("iProtocolMaxOffset: %d\n",      pi_a->iProtocolMaxOffset);
  dump_one_proto_infof ("iNetworkByteOrder:  %d = %s\n", pi_a->iNetworkByteOrder,
                                                         pi_a->iNetworkByteOrder == 0 ? "BIGENDIAN" : "LITTLEENDIAN");
  dump_one_proto_infof ("iSecurityScheme:    %d\n",      pi_a->iSecurityScheme);
  dump_one_proto_infof ("dwMessageSize:      %lu\n",     pi_a->dwMessageSize);
  dump_one_proto_infof ("dwProviderReserved: 0x%08lX (reserved)\n", pi_a->dwProviderReserved);

  if (ascii_or_wide == 'A')
       dump_one_proto_infof ("szProtocol:         \"%.*s\"\n", WSAPROTOCOL_LEN, pi_a->szProtocol);
  else dump_one_proto_infof ("szProtocol:         \"%.*S\"\n", WSAPROTOCOL_LEN, pi_w->szProtocol);

  dump_one_proto_infof ("ProviderId:         %s\n", get_guid_string(&pi_a->ProviderId));

  if (provider_path_func)
  {
    if (ascii_or_wide == 'A')
         dump_provider_path (&pi_a->ProviderId, provider_path_func);
    else dump_provider_path (&pi_w->ProviderId, provider_path_func);
  }
  trace_puts ("~0");
}
#endif  /* __WATCOMC__ */

/*
 * dump.c:1106:17: warning: trigraph ??> ignored, use -trigraphs to enable [-Wtrigraphs]
 *                  addr = "<??>";
 */
GCC_PRAGMA (GCC diagnostic ignored "-Wtrigraphs")

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

static const char *cc_last   = NULL;  /* CountryCode of previous address */
static const char *loc_last  = NULL;  /* Location of previous address */
static BOOL        cc_equal  = FALSE;
static BOOL        loc_equal = FALSE;

static int trace_printf_cc (const char            *country_code,
                            const char            *location,
                            const struct in_addr  *a4,
                            const struct in6_addr *a6)
{
  const char *remark = NULL;

  if (country_code && isalpha(*country_code))
  {
   /* Print Country-code (and location) only once for a host with multiple addresses.
    * Like with 'www.google.no':
    *   193.212.4.117, 193.212.4.120, 193.212.4.123, 193.212.4.119,
    *   193.212.4.122, 193.212.4.121, 193.212.4.116, 193.212.4.118
    *
    * PS. there should be no way to have 'location != NULL' and a
    *     'country_code == NULL'.
    */
    cc_equal = (cc_last && !strcmp(country_code,cc_last));
    if (!cc_equal)
       trace_printf ("%s - %s", country_code, geoip_get_long_name_by_A2(country_code));

    loc_equal = (location && loc_last && !strcmp(location,loc_last));
    if (location && !loc_equal)
       trace_printf (", %s", location);

    cc_last  = country_code;
    loc_last = location;
  }
  else if (geoip_addr_is_special(a4,a6,&remark))
  {
    trace_puts ("Special");
    if (remark)
       trace_printf (" (%s)", remark);
  }
  else if (country_code && *country_code == '-')
       trace_puts ("Private");
  else if (geoip_addr_is_zero(a4,a6))
       trace_puts ("NULL-addr");
  else if (geoip_addr_is_multicast(a4,a6))
       trace_puts ("Multicast");
  else if (!geoip_addr_is_global(a4,a6))
       trace_puts ("Not global");
  else trace_puts ("None");

  return (!cc_equal && !loc_equal);
}

static void check_and_dump_idna (const char *name)
{
  char   buf [MAX_HOST_LEN] = "?";
  size_t size;

  if (!g_cfg.idna_enable || !name || !strstr(name,"xn--"))
     return;

  trace_indent (g_cfg.trace_indent+2);
  trace_puts ("from ACE: ");

  _strlcpy (buf, name, sizeof(buf));
  size = strlen (buf);
  if (IDNA_convert_from_ACE(buf, &size))
       trace_printf ("%s\n", buf);
  else trace_printf ("failed for %s: %s\n", name, IDNA_strerror(_idna_errno));
}

void dump_countries (int type, const char **addresses)
{
  int i;

  WSAERROR_PUSH();

  trace_indent (g_cfg.trace_indent+2);
  trace_printf ("~4geo-IP: ");
  cc_last  = loc_last  = NULL;
  cc_equal = loc_equal = FALSE;

  for (i = 0; addresses && addresses[i]; i++)
  {
    const struct in_addr  *a4  = NULL;
    const struct in6_addr *a6  = NULL;
    const char            *cc  = NULL;
    const char            *loc = NULL;

    if (type == AF_INET)
    {
      a4  = (const struct in_addr*) addresses[i];
      cc  = geoip_get_country_by_ipv4 (a4);
      loc = geoip_get_location_by_ipv4 (a4);
    }
    else if (type == AF_INET6)
    {
      a6  = (const struct in6_addr*) addresses[i];
      cc  = geoip_get_country_by_ipv6 (a6);
      loc = geoip_get_location_by_ipv6 (a6);
    }
    else
    {
      trace_printf ("Unknown family: %d", type);
      break;
    }
    if (trace_printf_cc(cc, loc, a4, a6) && addresses[i+1])
       trace_puts (", ");
  }
  if (i == 0)
       trace_puts ("None!?~0\n");
  else trace_puts ("~0\n");

  WSAERROR_POP();
}

/*
 * Can only be 1 address in a 'sockaddr', but use the plural
 * 'countries' here anyway.
 */
void dump_countries_sockaddr (const struct sockaddr *sa)
{
  const char                *addr[2];
  const struct sockaddr_in  *sa4;
  const struct sockaddr_in6 *sa6;

  if (!sa)
     return;

  if (sa->sa_family == AF_INET)
  {
    sa4 = (const struct sockaddr_in*) sa;
    addr[0] = (const char*) &sa4->sin_addr;
    addr[1] = NULL;
    dump_countries (AF_INET, addr);
  }
  else if (sa->sa_family == AF_INET6)
  {
    sa6 = (const struct sockaddr_in6*) sa;
    addr[0] = (const char*) &sa6->sin6_addr;
    addr[1] = NULL;
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

  WSAERROR_PUSH();

  trace_indent (g_cfg.trace_indent+2);
  trace_printf ("~4geo-IP: ");
  cc_last  = loc_last  = NULL;
  cc_equal = loc_equal = FALSE;

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
      loc = geoip_get_location_by_ipv4 (&sa4->sin_addr);
    }
    else if (ai->ai_family == AF_INET6)
    {
      sa6 = (const struct sockaddr_in6*) ai->ai_addr;
      cc  = geoip_get_country_by_ipv6 (&sa6->sin6_addr);
      loc = geoip_get_location_by_ipv6 (&sa6->sin6_addr);
    }
    else
    {
      trace_printf ("Unknown family: %d", ai->ai_family);
      break;
    }
    if (trace_printf_cc(cc, loc,
                        sa4 ? &sa4->sin_addr  : NULL,
                        sa6 ? &sa6->sin6_addr : NULL) && ai->ai_next)
      trace_puts (", ");
  }
  if (num == 0)
       trace_puts ("None!?~0\n");
  else trace_puts ("~0\n");

  WSAERROR_POP();
}

void dump_nameinfo (const char *host, const char *serv, DWORD flags)
{
  trace_indent (g_cfg.trace_indent+2);
  trace_printf ("~4name: %s, serv: %s~0\n",
                host ? host : "NULL", serv ? serv : "NULL");
  check_and_dump_idna (host);
}

void dump_hostent (const char *name, const struct hostent *host)
{
  const char *comment;

  if (hosts_file_check_hostent(name, host) > 0)
       comment = " (in 'hosts' file)";
  else comment = "";

  trace_indent (g_cfg.trace_indent+2);
  trace_printf ("~4name: %s, addrtype: %s, addr_list: %s%s\n",
                host->h_name, socket_family(host->h_addrtype),
                dump_addr_list(host->h_addrtype, (const char**)host->h_addr_list),
                comment);

  check_and_dump_idna (host->h_name);

  trace_indent (g_cfg.trace_indent+2);
  trace_printf ("aliases: %s~0\n", dump_aliases(host->h_aliases));
}

void dump_servent (const struct servent *serv)
{
  trace_indent (g_cfg.trace_indent+2);
  trace_printf ("~4name: %s, port: %d, proto: %s\n",
                serv->s_name, swap16(serv->s_port), serv->s_proto);

  trace_indent (g_cfg.trace_indent+2);
  trace_printf ("aliases: %s~0\n", dump_aliases(serv->s_aliases));
}

void dump_protoent (const struct protoent *proto)
{
  trace_indent (g_cfg.trace_indent+2);
  trace_printf ("~4name: %s, proto: %d\n", proto->p_name, proto->p_proto);

  trace_indent (g_cfg.trace_indent+2);
  trace_printf ("aliases: %s~0\n", dump_aliases(proto->p_aliases));
}

static void _dump_events (BOOL out, const WSANETWORKEVENTS *events)
{
  int  i;
  long ev;

  trace_indent (g_cfg.trace_indent+2);
  trace_printf ("~4%s", out ? "out: " : "in:  ");
  if (!events)
  {
    trace_puts ("NULL~0");
    return;
  }

  ev = events->lNetworkEvents;
  trace_puts ("lNetworkEvents: ");

  /*
   * Print this like:
   *   in:  lNetworkEvents: FD_READ|FD_WRITE|FD_OOB|FD_ACCEPT|FD_CLOSE|FD_QOS|FD_GROUP_QOS|
   *                        FD_ADDRESS_LIST_CHANGE|0xDEADBC00
   */
  print_long_flags (event_bits_decode(ev), g_cfg.trace_indent +
                    sizeof("events in:            "), '|');

  for (i = 0; out && i < DIM(events->iErrorCode) && i < DIM(wsa_events_flgs); i++)
  {
    if (ev & (1 << i))
    {
      const char *ev_bit = list_lookup_name (ev & (1 << i), wsa_events_flgs, DIM(wsa_events_flgs));

      trace_indent (g_cfg.trace_indent+4);
      trace_printf ("iErrorCode [%s_BIT]: %08X\n", ev_bit, events->iErrorCode[i]);
    }
  }
  trace_puts ("~0");
}

void dump_events (const WSANETWORKEVENTS *in_events, const WSANETWORKEVENTS *out_events)
{
  _dump_events (FALSE, in_events);
  _dump_events (TRUE, out_events);
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
#ifndef WSAID_ACCEPTEX
#define WSAID_ACCEPTEX  { 0xB5367DF1, 0xCBAC, 0x11CF, { 0x95,0xCA,0x00,0x80,0x5F,0x48,0xA1,0x92 }}
#endif

#ifndef WSAID_CONNECTEX
#define WSAID_CONNECTEX  { 0x25A207B9, 0xDDF3, 0x4660, { 0x8E,0xE9,0x76,0xE5,0x8C,0x74,0x06,0x3E }}
#endif

#ifndef WSAID_DISCONNECTEX
#define WSAID_DISCONNECTEX  { 0x7FDA2E11, 0x8630, 0x436F, { 0xA0,0x31,0xF5,0x36,0xA6,0xEE,0xC1,0x57 }}
#endif

#ifndef WSAID_GETACCEPTEXSOCKADDRS
#define WSAID_GETACCEPTEXSOCKADDRS  { 0xB5367DF2, 0xCBAC, 0x11CF, { 0x95,0xCA,0x00,0x80,0x5F,0x48,0xA1,0x92 }}
#endif

#ifndef WSAID_TRANSMITFILE
#define WSAID_TRANSMITFILE  { 0xB5367DF0, 0xCBAC, 0x11CF, { 0x95,0xCA,0x00,0x80,0x5F,0x48,0xA1,0x92 }}
#endif

#ifndef WSAID_TRANSMITPACKETS
#define WSAID_TRANSMITPACKETS  { 0xD9689DA0,0x1F90,0x11D3, { 0x99,0x71,0x00,0xC0,0x4F,0x68,0xC8,0x76 }}
#endif

#ifndef WSAID_WSARECVMSG
#define WSAID_WSARECVMSG  { 0xF689D7C8, 0x6F1F, 0x436B, { 0x8A,0x53,0xE5,0x4F,0xE3,0x51,0xC3,0x22 }}
#endif

#ifndef WSAID_WSASENDMSG
#define WSAID_WSASENDMSG { 0xA441E712, 0x754F, 0x43CA, { 0x84,0xA7,0x0D,0xEE,0x44,0xCF,0x60,0x6D }}
#endif

#ifndef WSAID_WSAPOLL
#define WSAID_WSAPOLL { 0x18C76F85, 0xDC66, 0x4964, { 0x97,0x2E,0x23,0xC2,0x72,0x38,0x31,0x2B }}
#endif

static const struct GUID_search_list extension_guids[] = {
                    ADD_VALUE (WSAID_ACCEPTEX),
                    ADD_VALUE (WSAID_CONNECTEX),
                    ADD_VALUE (WSAID_DISCONNECTEX),
                    ADD_VALUE (WSAID_GETACCEPTEXSOCKADDRS),
                    ADD_VALUE (WSAID_TRANSMITFILE),
                    ADD_VALUE (WSAID_TRANSMITPACKETS),
                    ADD_VALUE (WSAID_WSARECVMSG),
                    ADD_VALUE (WSAID_WSASENDMSG),
                    ADD_VALUE (WSAID_WSAPOLL)
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

