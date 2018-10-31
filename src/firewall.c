/**\file    firewall.c
 * \ingroup inet_util
 *
 * \brief
 *  Function for listening for Windows "Internet Connection Firewall" (ICF) events.
 *
 *  The `fw_init()` and `fw_monotor_start()` needs Administrator privileges.
 *  Running `firewall_test.exe` as a normal non-elevated user will normally cause an
 *  "Access Denied".
 *
 * Thanks to dmex for his implementation of similar stuff in his ProcessHacker:
 * \see
 *   + https://github.com/processhacker/plugins-extra/blob/master/FirewallMonitorPlugin/fw.c
 *   + https://github.com/processhacker/plugins-extra/blob/master/FirewallMonitorPlugin/monitor.c
 *
 * Also many thanks to Henry++ for his SimpleWall:
 *  \see
 *    + https://github.com/henrypp/simplewall/blob/master/src/main.cpp
 *
 * A rather messy but rich example is at:
 *  \see
 *   + https://social.msdn.microsoft.com/Forums/sqlserver/en-US/74e3bf1d-3a0b-43ce-a528-2a88bc1fb882/log-packets?forum=wfp
 */

/*
 * For MSVC/clang We need at least a Win-Vista SDK here.
 * But for tdm-gcc (MingW) we need 0x601; Win-7.
 */
#if defined(__MINGW32__)
  #define MIN_WINNT 0x601
#else
  #define MIN_WINNT 0x600
#endif

#if !defined(_WIN32_WINNT) || (_WIN32_WINNT < MIN_WINNT)
  #undef  _WIN32_WINNT
  #define _WIN32_WINNT MIN_WINNT
#endif

// #define USE_FWUCLNT_STATIC_LIB

#include "common.h"
#include "init.h"
#include "in_addr.h"
#include "dump.h"
#include "geoip.h"
#include "wsock_trace.h"

typedef LONG NTSTATUS;

#include <fwpmu.h>

#if !defined(__MINGW32__)
  #include <fwpsu.h>
#endif

#include "firewall.h"

/* The code 'ip = _byteswap_ulong (*(DWORD*)&header->localAddrV4);' causes
 * a gcc warning. Ignore it.
 */
GCC_PRAGMA (GCC diagnostic ignored "-Wstrict-aliasing")
GCC_PRAGMA (GCC diagnostic ignored "-Wunused-but-set-variable")
GCC_PRAGMA (GCC diagnostic ignored "-Wenum-compare")

#define FW_API_LOW     0
#define FW_API_HIGH    4
#define FW_API_DEFAULT 3

typedef enum FW_STORE_TYPE {
             FW_STORE_TYPE_INVALID,
             FW_STORE_TYPE_GP_RSOP,
             FW_STORE_TYPE_LOCAL,
             FW_STORE_TYPE_NOT_USED_VALUE_3,
             FW_STORE_TYPE_NOT_USED_VALUE_4,
             FW_STORE_TYPE_DYNAMIC,
             FW_STORE_TYPE_GPO,
             FW_STORE_TYPE_DEFAULTS,
             FW_STORE_TYPE_MAX
           } FW_STORE_TYPE;

typedef enum FW_PROFILE_TYPE {
             FW_PROFILE_TYPE_INVALID  = 0,
             FW_PROFILE_TYPE_DOMAIN   = 0x001,
             FW_PROFILE_TYPE_STANDARD = 0x002,
             FW_PROFILE_TYPE_PRIVATE  = FW_PROFILE_TYPE_STANDARD,
             FW_PROFILE_TYPE_PUBLIC   = 0x004,
             FW_PROFILE_TYPE_ALL      = 0x7FFFFFFF,
             FW_PROFILE_TYPE_CURRENT  = 0x80000000,
             FW_PROFILE_TYPE_NONE     = FW_PROFILE_TYPE_CURRENT + 1
           } FW_PROFILE_TYPE;

typedef enum FW_RULE_STATUS {
             FW_RULE_STATUS_OK                                               = 0x00010000,
             FW_RULE_STATUS_PARTIALLY_IGNORED                                = 0x00020000,
             FW_RULE_STATUS_IGNORED                                          = 0x00040000,
             FW_RULE_STATUS_PARSING_ERROR_NAME                               = 0x00080001,
             FW_RULE_STATUS_PARSING_ERROR_DESC                               = 0x00080002,
             FW_RULE_STATUS_PARSING_ERROR_APP                                = 0x00080003,
             FW_RULE_STATUS_PARSING_ERROR_SVC                                = 0x00080004,
             FW_RULE_STATUS_PARSING_ERROR_RMA                                = 0x00080005,
             FW_RULE_STATUS_PARSING_ERROR_RUA                                = 0x00080006,
             FW_RULE_STATUS_PARSING_ERROR_EMBD                               = 0x00080007,
             FW_RULE_STATUS_PARSING_ERROR_RULE_ID                            = 0x00080008,
             FW_RULE_STATUS_PARSING_ERROR_PHASE1_AUTH                        = 0x00080009,
             FW_RULE_STATUS_PARSING_ERROR_PHASE2_CRYPTO                      = 0x0008000A,
             FW_RULE_STATUS_PARSING_ERROR_REMOTE_ENDPOINTS                   = 0x0008000F,
             FW_RULE_STATUS_PARSING_ERROR_REMOTE_ENDPOINT_FQDN               = 0x00080010,
             FW_RULE_STATUS_PARSING_ERROR_KEY_MODULE                         = 0x00080011,
             FW_RULE_STATUS_PARSING_ERROR_PHASE2_AUTH                        = 0x0008000B,
             FW_RULE_STATUS_PARSING_ERROR_RESOLVE_APP                        = 0x0008000C,
             FW_RULE_STATUS_PARSING_ERROR_MAINMODE_ID                        = 0x0008000D,
             FW_RULE_STATUS_PARSING_ERROR_PHASE1_CRYPTO                      = 0x0008000E,
             FW_RULE_STATUS_PARSING_ERROR                                    = 0x00080000,
             FW_RULE_STATUS_SEMANTIC_ERROR_RULE_ID                           = 0x00100010,
             FW_RULE_STATUS_SEMANTIC_ERROR_PORTS                             = 0x00100020,
             FW_RULE_STATUS_SEMANTIC_ERROR_PORT_KEYW                         = 0x00100021,
             FW_RULE_STATUS_SEMANTIC_ERROR_PORT_RANGE                        = 0x00100022,
             FW_RULE_STATUS_SEMANTIC_ERROR_ADDR_V4_SUBNETS                   = 0x00100040,
             FW_RULE_STATUS_SEMANTIC_ERROR_ADDR_V6_SUBNETS                   = 0x00100041,
             FW_RULE_STATUS_SEMANTIC_ERROR_ADDR_V4_RANGES                    = 0x00100042,
             FW_RULE_STATUS_SEMANTIC_ERROR_ADDR_V6_RANGES                    = 0x00100043,
             FW_RULE_STATUS_SEMANTIC_ERROR_ADDR_RANGE                        = 0x00100044,
             FW_RULE_STATUS_SEMANTIC_ERROR_ADDR_MASK                         = 0x00100045,
             FW_RULE_STATUS_SEMANTIC_ERROR_ADDR_PREFIX                       = 0x00100046,
             FW_RULE_STATUS_SEMANTIC_ERROR_ADDR_KEYW                         = 0x00100047,
             FW_RULE_STATUS_SEMANTIC_ERROR_LADDR_PROP                        = 0x00100048,
             FW_RULE_STATUS_SEMANTIC_ERROR_RADDR_PROP                        = 0x00100049,
             FW_RULE_STATUS_SEMANTIC_ERROR_ADDR_V6                           = 0x0010004A,
             FW_RULE_STATUS_SEMANTIC_ERROR_LADDR_INTF                        = 0x0010004B,
             FW_RULE_STATUS_SEMANTIC_ERROR_ADDR_V4                           = 0x0010004C,
             FW_RULE_STATUS_SEMANTIC_ERROR_TUNNEL_ENDPOINT_ADDR              = 0x0010004D,
             FW_RULE_STATUS_SEMANTIC_ERROR_DTE_VER                           = 0x0010004E,
             FW_RULE_STATUS_SEMANTIC_ERROR_DTE_MISMATCH_ADDR                 = 0x0010004F,
             FW_RULE_STATUS_SEMANTIC_ERROR_PROFILE                           = 0x00100050,
             FW_RULE_STATUS_SEMANTIC_ERROR_ICMP                              = 0x00100060,
             FW_RULE_STATUS_SEMANTIC_ERROR_ICMP_CODE                         = 0x00100061,
             FW_RULE_STATUS_SEMANTIC_ERROR_IF_ID                             = 0x00100070,
             FW_RULE_STATUS_SEMANTIC_ERROR_IF_TYPE                           = 0x00100071,
             FW_RULE_STATUS_SEMANTIC_ERROR_ACTION                            = 0x00100080,
             FW_RULE_STATUS_SEMANTIC_ERROR_ALLOW_BYPASS                      = 0x00100081,
             FW_RULE_STATUS_SEMANTIC_ERROR_DO_NOT_SECURE                     = 0x00100082,
             FW_RULE_STATUS_SEMANTIC_ERROR_ACTION_BLOCK_IS_ENCRYPTED_SECURE  = 0x00100083,
             FW_RULE_STATUS_SEMANTIC_ERROR_DIR                               = 0x00100090,
             FW_RULE_STATUS_SEMANTIC_ERROR_PROT                              = 0x001000A0,
             FW_RULE_STATUS_SEMANTIC_ERROR_PROT_PROP                         = 0x001000A1,
             FW_RULE_STATUS_SEMANTIC_ERROR_DEFER_EDGE_PROP                   = 0x001000A2,
             FW_RULE_STATUS_SEMANTIC_ERROR_ALLOW_BYPASS_OUTBOUND             = 0x001000A3,
             FW_RULE_STATUS_SEMANTIC_ERROR_DEFER_USER_INVALID_RULE           = 0x001000A4,
             FW_RULE_STATUS_SEMANTIC_ERROR_FLAGS                             = 0x001000B0,
             FW_RULE_STATUS_SEMANTIC_ERROR_FLAGS_AUTO_AUTH                   = 0x001000B1,
             FW_RULE_STATUS_SEMANTIC_ERROR_FLAGS_AUTO_BLOCK                  = 0x001000B2,
             FW_RULE_STATUS_SEMANTIC_ERROR_FLAGS_AUTO_DYN_RPC                = 0x001000B3,
             FW_RULE_STATUS_SEMANTIC_ERROR_FLAGS_AUTHENTICATE_ENCRYPT        = 0x001000B4,
             FW_RULE_STATUS_SEMANTIC_ERROR_FLAGS_AUTH_WITH_ENC_NEGOTIATE_VER = 0x001000B5,
             FW_RULE_STATUS_SEMANTIC_ERROR_FLAGS_AUTH_WITH_ENC_NEGOTIATE     = 0x001000B6,
             FW_RULE_STATUS_SEMANTIC_ERROR_FLAGS_ESP_NO_ENCAP_VER            = 0x001000B7,
             FW_RULE_STATUS_SEMANTIC_ERROR_FLAGS_ESP_NO_ENCAP                = 0x001000B8,
             FW_RULE_STATUS_SEMANTIC_ERROR_FLAGS_TUNNEL_AUTH_MODES_VER       = 0x001000B9,
             FW_RULE_STATUS_SEMANTIC_ERROR_FLAGS_TUNNEL_AUTH_MODES           = 0x001000BA,
             FW_RULE_STATUS_SEMANTIC_ERROR_FLAGS_IP_TLS_VER                  = 0x001000BB,
             FW_RULE_STATUS_SEMANTIC_ERROR_FLAGS_PORTRANGE_VER               = 0x001000BC,
             FW_RULE_STATUS_SEMANTIC_ERROR_FLAGS_ADDRS_TRAVERSE_DEFER_VER    = 0x001000BD,
             FW_RULE_STATUS_SEMANTIC_ERROR_FLAGS_AUTH_WITH_ENC_NEGOTIATE_OUTBOUND      = 0x001000BE,
             FW_RULE_STATUS_SEMANTIC_ERROR_FLAGS_AUTHENTICATE_WITH_OUTBOUND_BYPASS_VER = 0x001000BF,
             FW_RULE_STATUS_SEMANTIC_ERROR_REMOTE_AUTH_LIST                  = 0x001000C0,
             FW_RULE_STATUS_SEMANTIC_ERROR_REMOTE_USER_LIST                  = 0x001000C1,
             FW_RULE_STATUS_SEMANTIC_ERROR_PLATFORM                          = 0x001000E0,
             FW_RULE_STATUS_SEMANTIC_ERROR_PLATFORM_OP_VER                   = 0x001000E1,
             FW_RULE_STATUS_SEMANTIC_ERROR_PLATFORM_OP                       = 0x001000E2,
             FW_RULE_STATUS_SEMANTIC_ERROR_DTE_NOANY_ADDR                    = 0x001000F0,
             FW_RULE_STATUS_SEMANTIC_TUNNEL_EXEMPT_WITH_GATEWAY              = 0x001000F1,
             FW_RULE_STATUS_SEMANTIC_TUNNEL_EXEMPT_VER                       = 0x001000F2,
             FW_RULE_STATUS_SEMANTIC_ERROR_PHASE1_AUTH_SET_ID                = 0x00100500,
             FW_RULE_STATUS_SEMANTIC_ERROR_PHASE2_CRYPTO_SET_ID              = 0x00100510,
             FW_RULE_STATUS_SEMANTIC_ERROR_PHASE1_CRYPTO_SET_ID              = 0x00100511,
             FW_RULE_STATUS_SEMANTIC_ERROR_SET_ID                            = 0x00101000,
             FW_RULE_STATUS_SEMANTIC_ERROR_IPSEC_PHASE                       = 0x00101010,
             FW_RULE_STATUS_SEMANTIC_ERROR_EMPTY_SUITES                      = 0x00101020,
             FW_RULE_STATUS_SEMANTIC_ERROR_PHASE1_AUTH_METHOD                = 0x00101030,
             FW_RULE_STATUS_SEMANTIC_ERROR_PHASE2_AUTH_METHOD                = 0x00101031,
             FW_RULE_STATUS_SEMANTIC_ERROR_AUTH_METHOD_ANONYMOUS             = 0x00101032,
             FW_RULE_STATUS_SEMANTIC_ERROR_AUTH_METHOD_DUPLICATE             = 0x00101033,
             FW_RULE_STATUS_SEMANTIC_ERROR_AUTH_METHOD_VER                   = 0x00101034,
             FW_RULE_STATUS_SEMANTIC_ERROR_AUTH_SUITE_FLAGS                  = 0x00101040,
             FW_RULE_STATUS_SEMANTIC_ERROR_HEALTH_CERT                       = 0x00101041,
             FW_RULE_STATUS_SEMANTIC_ERROR_AUTH_SIGNCERT_VER                 = 0x00101042,
             FW_RULE_STATUS_SEMANTIC_ERROR_AUTH_INTERMEDIATE_CA_VER          = 0x00101043,
             FW_RULE_STATUS_SEMANTIC_ERROR_MACHINE_SHKEY                     = 0x00101050,
             FW_RULE_STATUS_SEMANTIC_ERROR_CA_NAME                           = 0x00101060,
             FW_RULE_STATUS_SEMANTIC_ERROR_MIXED_CERTS                       = 0x00101061,
             FW_RULE_STATUS_SEMANTIC_ERROR_NON_CONTIGUOUS_CERTS              = 0x00101062,
             FW_RULE_STATUS_SEMANTIC_ERROR_MIXED_CA_TYPE_IN_BLOCK            = 0x00101063,
             FW_RULE_STATUS_SEMANTIC_ERROR_MACHINE_USER_AUTH                 = 0x00101070,
             FW_RULE_STATUS_SEMANTIC_ERROR_PHASE1_CRYPTO_NON_DEFAULT_ID      = 0x00105000,
             FW_RULE_STATUS_SEMANTIC_ERROR_PHASE1_CRYPTO_FLAGS               = 0x00105001,
             FW_RULE_STATUS_SEMANTIC_ERROR_PHASE1_CRYPTO_TIMEOUT_MINUTES     = 0x00105002,
             FW_RULE_STATUS_SEMANTIC_ERROR_PHASE1_CRYPTO_TIMEOUT_SESSIONS    = 0x00105003,
             FW_RULE_STATUS_SEMANTIC_ERROR_PHASE1_CRYPTO_KEY_EXCHANGE        = 0x00105004,
             FW_RULE_STATUS_SEMANTIC_ERROR_PHASE1_CRYPTO_ENCRYPTION          = 0x00105005,
             FW_RULE_STATUS_SEMANTIC_ERROR_PHASE1_CRYPTO_HASH                = 0x00105006,
             FW_RULE_STATUS_SEMANTIC_ERROR_PHASE1_CRYPTO_ENCRYPTION_VER      = 0x00105007,
             FW_RULE_STATUS_SEMANTIC_ERROR_PHASE1_CRYPTO_HASH_VER            = 0x00105008,
             FW_RULE_STATUS_SEMANTIC_ERROR_PHASE2_CRYPTO_PFS                 = 0x00105020,
             FW_RULE_STATUS_SEMANTIC_ERROR_PHASE2_CRYPTO_PROTOCOL            = 0x00105021,
             FW_RULE_STATUS_SEMANTIC_ERROR_PHASE2_CRYPTO_ENCRYPTION          = 0x00105022,
             FW_RULE_STATUS_SEMANTIC_ERROR_PHASE2_CRYPTO_HASH                = 0x00105023,
             FW_RULE_STATUS_SEMANTIC_ERROR_PHASE2_CRYPTO_TIMEOUT_MINUTES     = 0x00105024,
             FW_RULE_STATUS_SEMANTIC_ERROR_PHASE2_CRYPTO_TIMEOUT_KBYTES      = 0x00105025,
             FW_RULE_STATUS_SEMANTIC_ERROR_PHASE2_CRYPTO_ENCRYPTION_VER      = 0x00105026,
             FW_RULE_STATUS_SEMANTIC_ERROR_PHASE2_CRYPTO_HASH_VER            = 0x00105027,
             FW_RULE_STATUS_SEMANTIC_ERROR_QUERY_OR_AND_CONDITIONS           = 0x00106000,
             FW_RULE_STATUS_SEMANTIC_ERROR_QUERY_AND_CONDITIONS              = 0x00106001,
             FW_RULE_STATUS_SEMANTIC_ERROR_QUERY_CONDITION_KEY               = 0x00106002,
             FW_RULE_STATUS_SEMANTIC_ERROR_QUERY_CONDITION_MATCH_TYPE        = 0x00106003,
             FW_RULE_STATUS_SEMANTIC_ERROR_QUERY_CONDITION_DATA_TYPE         = 0x00106004,
             FW_RULE_STATUS_SEMANTIC_ERROR_QUERY_CONDITION_KEY_AND_DATA_TYPE = 0x00106005,
             FW_RULE_STATUS_SEMANTIC_ERROR_QUERY_KEYS_PROTOCOL_PORT          = 0x00106006,
             FW_RULE_STATUS_SEMANTIC_ERROR_QUERY_KEY_PROFILE                 = 0x00106007,
             FW_RULE_STATUS_SEMANTIC_ERROR_QUERY_KEY_STATUS                  = 0x00106008,
             FW_RULE_STATUS_SEMANTIC_ERROR_QUERY_KEY_FILTERID                = 0x00106009,
             FW_RULE_STATUS_SEMANTIC_ERROR_QUERY_KEY_APP_PATH                = 0x00106010,
             FW_RULE_STATUS_SEMANTIC_ERROR_QUERY_KEY_PROTOCOL                = 0x00106011,
             FW_RULE_STATUS_SEMANTIC_ERROR_QUERY_KEY_LOCAL_PORT              = 0x00106012,
             FW_RULE_STATUS_SEMANTIC_ERROR_QUERY_KEY_REMOTE_PORT             = 0x00106013,
             FW_RULE_STATUS_SEMANTIC_ERROR_QUERY_KEY_SVC_NAME                = 0x00106015,
             FW_RULE_STATUS_SEMANTIC_ERROR_REQUIRE_IN_CLEAR_OUT_ON_TRANSPORT = 0x00107000,
             FW_RULE_STATUS_SEMANTIC_ERROR_TUNNEL_BYPASS_TUNNEL_IF_SECURE_ON_TRANSPORT = 0x00107001,
             FW_RULE_STATUS_SEMANTIC_ERROR_AUTH_NOENCAP_ON_TUNNEL            = 0x00107002,
             FW_RULE_STATUS_SEMANTIC_ERROR_AUTH_NOENCAP_ON_PSK               = 0x00107003,
             FW_RULE_STATUS_SEMANTIC_ERROR_CRYPTO_ENCR_HASH                  = 0x00105040,
             FW_RULE_STATUS_SEMANTIC_ERROR_CRYPTO_ENCR_HASH_COMPAT           = 0x00105041,
             FW_RULE_STATUS_SEMANTIC_ERROR_SCHEMA_VERSION                    = 0x00105050,
             FW_RULE_STATUS_SEMANTIC_ERROR                                   = 0x00100000,
             FW_RULE_STATUS_RUNTIME_ERROR_PHASE1_AUTH_NOT_FOUND              = 0x00200001,
             FW_RULE_STATUS_RUNTIME_ERROR_PHASE2_AUTH_NOT_FOUND              = 0x00200002,
             FW_RULE_STATUS_RUNTIME_ERROR_PHASE2_CRYPTO_NOT_FOUND            = 0x00200003,
             FW_RULE_STATUS_RUNTIME_ERROR_AUTH_MCHN_SHKEY_MISMATCH           = 0x00200004,
             FW_RULE_STATUS_RUNTIME_ERROR_PHASE1_CRYPTO_NOT_FOUND            = 0x00200005,
             FW_RULE_STATUS_RUNTIME_ERROR_AUTH_NOENCAP_ON_TUNNEL             = 0x00200006,
             FW_RULE_STATUS_RUNTIME_ERROR_AUTH_NOENCAP_ON_PSK                = 0x00200007,
             FW_RULE_STATUS_RUNTIME_ERROR                                    = 0x00200000,
             FW_RULE_STATUS_ERROR                                            = FW_RULE_STATUS_PARSING_ERROR |
                                                                               FW_RULE_STATUS_SEMANTIC_ERROR |
                                                                               FW_RULE_STATUS_RUNTIME_ERROR,
             FW_RULE_STATUS_ALL                                              = 0xFFFF0000
           } FW_RULE_STATUS;

typedef enum FW_RULE_STATUS_CLASS {
             FW_RULE_STATUS_CLASS_OK                = FW_RULE_STATUS_OK,
             FW_RULE_STATUS_CLASS_PARTIALLY_IGNORED = FW_RULE_STATUS_PARTIALLY_IGNORED,
             FW_RULE_STATUS_CLASS_IGNORED           = FW_RULE_STATUS_IGNORED,
             FW_RULE_STATUS_CLASS_PARSING_ERROR     = FW_RULE_STATUS_PARSING_ERROR,
             FW_RULE_STATUS_CLASS_SEMANTIC_ERROR    = FW_RULE_STATUS_SEMANTIC_ERROR,
             FW_RULE_STATUS_CLASS_RUNTIME_ERROR     = FW_RULE_STATUS_RUNTIME_ERROR,
             FW_RULE_STATUS_CLASS_ERROR             = FW_RULE_STATUS_ERROR,
             FW_RULE_STATUS_CLASS_ALL               = FW_RULE_STATUS_ALL
           } FW_RULE_STATUS_CLASS;

typedef enum FW_POLICY_ACCESS_RIGHT {
             FW_POLICY_ACCESS_RIGHT_INVALID,
             FW_POLICY_ACCESS_RIGHT_READ,
             FW_POLICY_ACCESS_RIGHT_READ_WRITE,
             FW_POLICY_ACCESS_RIGHT_MAX
           } FW_POLICY_ACCESS_RIGHT;

typedef enum FW_POLICY_STORE_FLAGS {
             FW_POLICY_STORE_FLAGS_NONE,
             FW_POLICY_STORE_FLAGS_DELETE_DYNAMIC_RULES_AFTER_CLOSE,
             FW_POLICY_STORE_FLAGS_MAX
           } FW_POLICY_STORE_FLAGS;

typedef enum FW_RULE_ORIGIN_TYPE {
             FW_RULE_ORIGIN_INVALID,
             FW_RULE_ORIGIN_LOCAL,
             FW_RULE_ORIGIN_GP,
             FW_RULE_ORIGIN_DYNAMIC,
             FW_RULE_ORIGIN_AUTOGEN,
             FW_RULE_ORIGIN_HARDCODED,
             FW_RULE_ORIGIN_MAX
           } FW_RULE_ORIGIN_TYPE;

/**
 * \enum FW_ENUM_RULES_FLAGS
 * \see http://msdn.microsoft.com/en-us/library/cc231521.aspx
 */
typedef enum FW_ENUM_RULES_FLAGS {
             /**
              * This value signifies that no specific flag is used.
              * It is defined for IDL definitions and code to add readability, instead of using the number 0.
              */
             FW_ENUM_RULES_FLAG_NONE = 0x0000,

             /** Resolves rule description strings to user-friendly, localizable strings if they are in the following
              *  format: @file.dll,-<resID>. resID refers to the resource ID in the indirect string.
              *  Please see [MSDN-SHLoadIndirectString] for further documentation on the string format.
              */
             FW_ENUM_RULES_FLAG_RESOLVE_NAME = 0x0001,

             /** Resolves rule description strings to user-friendly, localizable strings if they are in the following
              *  format: @file.dll,-<resID>. resID refers to the resource ID in the indirect string.
              * Please see [MSDN-SHLoadIndirectString] for further documentation on the string format.
              */
             FW_ENUM_RULES_FLAG_RESOLVE_DESCRIPTION = 0x0002,

             /** If this flag is set, the server MUST inspect the wszLocalApplication field of each FW_RULE structure
              *  and replace all environment variables in the string with their corresponding values.
              *  See [MSDN-ExpandEnvironmentStrings] for more details about environment-variable strings.
              */
             FW_ENUM_RULES_FLAG_RESOLVE_APPLICATION = 0x0004,

             /** Resolves keywords in addresses and ports to the actual addresses and
              *  ports (dynamic store only).
              */
             FW_ENUM_RULES_FLAG_RESOLVE_KEYWORD = 0x0008,

             /** Resolves the GPO name for the GP_RSOP rules.
              */
             FW_ENUM_RULES_FLAG_RESOLVE_GPO_NAME = 0x0010,

             /** If this flag is set, the server MUST only return objects where at least one
              *  FW_ENFORCEMENT_STATE entry in the object's metadata is equal to FW_ENFORCEMENT_STATE_FULL.
              *  This flag is available for the dynamic store only.
              */
             FW_ENUM_RULES_FLAG_EFFECTIVE = 0x0020,

             /** Includes the metadata object information, represented by the FW_OBJECT_METADATA structure,
              *  in the enumerated objects.
              */
             FW_ENUM_RULES_FLAG_INCLUDE_METADATA = 0x0040,

             /** This value and greater values are invalid and MUST NOT be used. It is defined for
              *  simplicity in writing IDL definitions and code.
              */
             FW_ENUM_RULES_FLAG_MAX = 0x0080
           } FW_ENUM_RULES_FLAGS;

typedef enum FW_RULE_ACTION {
             FW_RULE_ACTION_INVALID = 0,
             FW_RULE_ACTION_ALLOW_BYPASS,
             FW_RULE_ACTION_BLOCK,
             FW_RULE_ACTION_ALLOW,
             FW_RULE_ACTION_MAX
           } FW_RULE_ACTION;

typedef enum FW_DIRECTION {
             FW_DIR_INVALID = 0,
             FW_DIR_IN      = 1,
             FW_DIR_OUT     = 2,
             FW_DIR_BOTH    = 3 /* MAX */
           } FW_DIRECTION;

typedef enum FW_ENFORCEMENT_STATE {
             FW_ENFORCEMENT_STATE_INVALID,
             FW_ENFORCEMENT_STATE_FULL,
             FW_ENFORCEMENT_STATE_WF_OFF_IN_PROFILE,
             FW_ENFORCEMENT_STATE_CATEGORY_OFF,
             FW_ENFORCEMENT_STATE_DISABLED_OBJECT,
             FW_ENFORCEMENT_STATE_INACTIVE_PROFILE,
             FW_ENFORCEMENT_STATE_LOCAL_ADDRESS_RESOLUTION_EMPTY,
             FW_ENFORCEMENT_STATE_REMOTE_ADDRESS_RESOLUTION_EMPTY,
             FW_ENFORCEMENT_STATE_LOCAL_PORT_RESOLUTION_EMPTY,
             FW_ENFORCEMENT_STATE_REMOTE_PORT_RESOLUTION_EMPTY,
             FW_ENFORCEMENT_STATE_INTERFACE_RESOLUTION_EMPTY,
             FW_ENFORCEMENT_STATE_APPLICATION_RESOLUTION_EMPTY,
             FW_ENFORCEMENT_STATE_REMOTE_MACHINE_EMPTY,
             FW_ENFORCEMENT_STATE_REMOTE_USER_EMPTY,
             FW_ENFORCEMENT_STATE_LOCAL_GLOBAL_OPEN_PORTS_DISALLOWED,
             FW_ENFORCEMENT_STATE_LOCAL_AUTHORIZED_APPLICATIONS_DISALLOWED,
             FW_ENFORCEMENT_STATE_LOCAL_FIREWALL_RULES_DISALLOWED,
             FW_ENFORCEMENT_STATE_LOCAL_CONSEC_RULES_DISALLOWED,
             FW_ENFORCEMENT_STATE_MISMATCHED_PLATFORM,
             FW_ENFORCEMENT_STATE_OPTIMIZED_OUT,
             FW_ENFORCEMENT_STATE_MAX
           } FW_ENFORCEMENT_STATE;

typedef enum _FWPM_NET_EVENT_TYPE {
             _FWPM_NET_EVENT_TYPE_IKEEXT_MM_FAILURE  = 0,
             _FWPM_NET_EVENT_TYPE_IKEEXT_QM_FAILURE  = 1,
             _FWPM_NET_EVENT_TYPE_IKEEXT_EM_FAILURE  = 2,
             _FWPM_NET_EVENT_TYPE_CLASSIFY_DROP      = 3,
             _FWPM_NET_EVENT_TYPE_IPSEC_KERNEL_DROP  = 4,
             _FWPM_NET_EVENT_TYPE_IPSEC_DOSP_DROP    = 5,
             _FWPM_NET_EVENT_TYPE_CLASSIFY_ALLOW     = 6,
             _FWPM_NET_EVENT_TYPE_CAPABILITY_DROP    = 7,
             _FWPM_NET_EVENT_TYPE_CAPABILITY_ALLOW   = 8,
             _FWPM_NET_EVENT_TYPE_CLASSIFY_DROP_MAC  = 9,
             _FWPM_NET_EVENT_TYPE_LPM_PACKET_ARRIVAL = 10,
             _FWPM_NET_EVENT_TYPE_MAX                = 11
           } _FWPM_NET_EVENT_TYPE;

typedef struct FW_PORT_RANGE {
         USHORT  wBegin;
         USHORT  wEnd;
       } FW_PORT_RANGE;

typedef struct FW_PORT_RANGE_LIST {
        ULONG          dwNumEntries;
        FW_PORT_RANGE *pPorts;
      } FW_PORT_RANGE_LIST;

typedef struct FW_PORTS {
        USHORT             wPortKeywords;
        FW_PORT_RANGE_LIST Ports;
      } FW_PORTS;

typedef struct FW_ICMP_TYPE_CODE {
        UCHAR  bType;
        USHORT wCode;
      } FW_ICMP_TYPE_CODE;

typedef struct FW_ICMP_TYPE_CODE_LIST {
        ULONG              dwNumEntries;
        FW_ICMP_TYPE_CODE *pEntries;
      } FW_ICMP_TYPE_CODE_LIST;

typedef struct FW_IPV4_SUBNET {
        ULONG  dwAddress;
        ULONG  dwSubNetMask;
      } FW_IPV4_SUBNET;

typedef struct FW_IPV4_SUBNET_LIST {
        ULONG           dwNumEntries;
        FW_IPV4_SUBNET *pSubNets;
      } FW_IPV4_SUBNET_LIST;

typedef struct FW_IPV4_ADDRESS_RANGE {
        ULONG  dwBegin;
        ULONG  dwEnd;
    } FW_IPV4_ADDRESS_RANGE;

typedef struct FW_IPV4_RANGE_LIST {
        ULONG                  dwNumEntries;
        FW_IPV4_ADDRESS_RANGE *pRanges;
      } FW_IPV4_RANGE_LIST;

typedef struct FW_IPV6_SUBNET {
        UCHAR  Address [16];
        ULONG  dwNumPrefixBits;
      } FW_IPV6_SUBNET;

typedef struct FW_IPV6_SUBNET_LIST {
        ULONG           dwNumEntries;
        FW_IPV6_SUBNET *pSubNets;
      } FW_IPV6_SUBNET_LIST;

typedef struct FW_IPV6_ADDRESS_RANGE {
        UCHAR  Begin [16];
        UCHAR  End [16];
      } FW_IPV6_ADDRESS_RANGE;

typedef struct FW_IPV6_RANGE_LIST {
        ULONG                  dwNumEntries;
        FW_IPV6_ADDRESS_RANGE *pRanges;
      } FW_IPV6_RANGE_LIST;

typedef struct FW_ADDRESSES {
        ULONG               dwV4AddressKeywords;
        ULONG               dwV6AddressKeywords;
        FW_IPV4_SUBNET_LIST V4SubNets;
        FW_IPV4_RANGE_LIST  V4Ranges;
        FW_IPV6_SUBNET_LIST V6SubNets;
        FW_IPV6_RANGE_LIST  V6Ranges;
      } FW_ADDRESSES;

typedef struct FW_INTERFACE_LUIDS {
        ULONG  dwNumLUIDs;
        GUID  *pLUIDs;
      } FW_INTERFACE_LUIDS;

typedef struct FW_NETWORK_NAMES {
        ULONG     dwNumEntries;
        wchar_t **wszNames;
      } FW_NETWORK_NAMES;

typedef struct FW_OS_PLATFORM {
        UCHAR  bPlatform;
        UCHAR  bMajorVersion;
        UCHAR  bMinorVersion;
        UCHAR  Reserved;
      } FW_OS_PLATFORM;

typedef struct FW_OS_PLATFORM_LIST {
        ULONG           dwNumEntries;
        FW_OS_PLATFORM *pPlatforms;
      } FW_OS_PLATFORM_LIST;

typedef struct FW_RULE2_0 {
        struct FW_RULE2_0 *pNext;
        USHORT             wSchemaVersion;
        wchar_t           *wszRuleId;
        wchar_t           *wszName;
        wchar_t           *wszDescription;
        FW_PROFILE_TYPE    dwProfiles;
        FW_DIRECTION       Direction;
        USHORT             wIpProtocol;
        union {
          struct {
            FW_PORTS LocalPorts;
            FW_PORTS RemotePorts;
          };
          FW_ICMP_TYPE_CODE_LIST V4TypeCodeList;
          FW_ICMP_TYPE_CODE_LIST V6TypeCodeList;
        };
        FW_ADDRESSES         LocalAddresses;
        FW_ADDRESSES         RemoteAddresses;
        FW_INTERFACE_LUIDS   LocalInterfaceIds;
        ULONG                dwLocalInterfaceTypes;
        wchar_t             *wszLocalApplication;
        wchar_t             *wszLocalService;
        FW_RULE_ACTION       Action;
        FW_ENUM_RULES_FLAGS  wFlags;
        wchar_t             *wszRemoteMachineAuthorizationList;
        wchar_t             *wszRemoteUserAuthorizationList;
        wchar_t             *wszEmbeddedContext;
        FW_OS_PLATFORM_LIST  PlatformValidityList;
        FW_RULE_STATUS       Status;
        FW_RULE_ORIGIN_TYPE  Origin;
        wchar_t             *wszGPOName;
        ULONG                Reserved;
      } FW_RULE2_0;

typedef struct FW_OBJECT_METADATA {
         ULONGLONG             qwFilterContextID;
         ULONG                 dwNumEntries;
         FW_ENFORCEMENT_STATE *pEnforcementStates;
       } FW_OBJECT_METADATA;

typedef struct FW_RULE {
        struct FW_RULE *pNext;
        USHORT          wSchemaVersion;
        wchar_t        *wszRuleId;
        wchar_t        *wszName;
        wchar_t        *wszDescription;
        FW_PROFILE_TYPE dwProfiles;
        FW_DIRECTION    Direction;
        USHORT          wIpProtocol;
        union {
          struct {
            FW_PORTS LocalPorts;
            FW_PORTS RemotePorts;
          };
          FW_ICMP_TYPE_CODE_LIST V4TypeCodeList;
          FW_ICMP_TYPE_CODE_LIST V6TypeCodeList;
        };
        FW_ADDRESSES        LocalAddresses;
        FW_ADDRESSES        RemoteAddresses;
        FW_INTERFACE_LUIDS  LocalInterfaceIds;
        ULONG               dwLocalInterfaceTypes;
        wchar_t            *wszLocalApplication;
        wchar_t            *wszLocalService;
        FW_RULE_ACTION      Action;
        FW_ENUM_RULES_FLAGS wFlags;
        wchar_t            *wszRemoteMachineAuthorizationList;
        wchar_t            *wszRemoteUserAuthorizationList;
        wchar_t            *wszEmbeddedContext;
        FW_OS_PLATFORM_LIST PlatformValidityList;
        FW_RULE_STATUS      Status;
        FW_RULE_ORIGIN_TYPE Origin;
        wchar_t            *wszGPOName;
        ULONG               Reserved;
        FW_OBJECT_METADATA *pMetaData;
        wchar_t            *wszLocalUserAuthorizationList;
        wchar_t            *wszPackageId;
        wchar_t            *wszLocalUserOwner;
        unsigned long       dwTrustTupleKeywords;
        FW_NETWORK_NAMES    OnNetworkNames;
        wchar_t            *wszSecurityRealmId;
        unsigned short      wFlags2;
        FW_NETWORK_NAMES    RemoteOutServerNames;
        wchar_t            *Fqbn;     /* since RS1 or RS2? */
        ULONG               compartmentId;
      } FW_RULE;

typedef void (*FW_WALK_RULES) (const FW_RULE *rule);

/*
 * http://msdn.microsoft.com/en-us/library/cc231461.aspx
 */
#define FW_VISTA_SCHEMA_VERSION        0x0200
#define FW_SERVER2K8_BINARY_VERSION    0x0201
#define FW_SERVER2K8_SCHEMA_VERSION    0x0201
#define FW_SEVEN_BINARY_VERSION        0x020A
#define FW_SEVEN_SCHEMA_VERSION        0x020A
#define FW_WIN8_1_BINARY_VERSION       0x0214
#define FW_WIN10_BINARY_VERSION        0x0216
#define FW_THRESHOLD_BINARY_VERSION    0x0218
#define FW_THRESHOLD2_BINARY_VERSION   0x0219
#define FW_REDSTONE1_BINARY_VERSION    0x021A
#define FW_REDSTONE2_BINARY_VERSION    0x021B

#define FWP_DIRECTION_IN      0x00003900L
#define FWP_DIRECTION_OUT     0x00003901L
#define FWP_DIRECTION_FORWARD 0x00003902L

/*
 * Handy macro to both define and declare the function-pointer.
 */
#define DEF_FUNC(ret, f, args)       typedef ret (WINAPI *func_##f) args; \
                                     static func_##f  p_##f = NULL

#define DEF_FUNC2(ret, f1, args, f2) typedef ret (WINAPI *func_##f1) args; \
                                     static func_##f1  p_##f1 = f2

typedef struct _FWPM_NET_EVENT_CLASSIFY_DROP0 {
        UINT64  filterId;
        UINT16  layerId;
     } _FWPM_NET_EVENT_CLASSIFY_DROP0;

typedef struct _FWPM_NET_EVENT_CLASSIFY_DROP1 {
        UINT64        filterId;
        UINT16        layerId;
        UINT32        reauthReason;
        UINT32        originalProfile;
        UINT32        currentProfile;
        UINT32        msFwpDirection;
        BOOL          isLoopback;
      } _FWPM_NET_EVENT_CLASSIFY_DROP1;

typedef struct _FWPM_NET_EVENT_CLASSIFY_DROP2 {
        UINT64        filterId;
        UINT16        layerId;
        UINT32        reauthReason;
        UINT32        originalProfile;
        UINT32        currentProfile;
        UINT32        msFwpDirection;
        BOOL          isLoopback;
        FWP_BYTE_BLOB vSwitchId;
        UINT32        vSwitchSourcePort;
        UINT32        vSwitchDestinationPort;
      } _FWPM_NET_EVENT_CLASSIFY_DROP2;

typedef struct _FWPM_NET_EVENT_CLASSIFY_ALLOW0 {
        UINT64        filterId;
        UINT16        layerId;
        UINT32        reauthReason;
        UINT32        originalProfile;
        UINT32        currentProfile;
        UINT32        msFwpDirection;
        BOOL          isLoopback;
      } _FWPM_NET_EVENT_CLASSIFY_ALLOW0;

typedef struct _FWPM_NET_EVENT_HEADER0 {
        FILETIME           timeStamp;
        UINT32             flags;
        FWP_IP_VERSION     ipVersion;
        UINT8              ipProtocol;
        union {
          UINT32           localAddrV4;
          FWP_BYTE_ARRAY16 localAddrV6;
        };
        union {
          UINT32           remoteAddrV4;
          FWP_BYTE_ARRAY16 remoteAddrV6;
        };
        UINT16             localPort;
        UINT16             remotePort;
        UINT32             scopeId;
        FWP_BYTE_BLOB      appId;
        SID               *userId;
      } _FWPM_NET_EVENT_HEADER0;

typedef struct _FWPM_NET_EVENT_HEADER1 {
        FILETIME           timeStamp;
        UINT32             flags;
        FWP_IP_VERSION     ipVersion;
        UINT8              ipProtocol;
        union {
          UINT32           localAddrV4;
          FWP_BYTE_ARRAY16 localAddrV6;
        };
        union {
          UINT32           remoteAddrV4;
          FWP_BYTE_ARRAY16 remoteAddrV6;
        };
        UINT16             localPort;
        UINT16             remotePort;
        UINT32             scopeId;
        FWP_BYTE_BLOB      appId;
        SID               *userId;
        union {
          struct {
            FWP_AF reserved1;
            union {
              struct {
                FWP_BYTE_ARRAY6 reserved2;
                FWP_BYTE_ARRAY6 reserved3;
                UINT32          reserved4;
                UINT32          reserved5;
                UINT16          reserved6;
                UINT32          reserved7;
                UINT32          reserved8;
                UINT16          reserved9;
                UINT64          reserved10;
              };
            };
          };
        };
      } _FWPM_NET_EVENT_HEADER1;

typedef struct _FWPM_NET_EVENT_HEADER2 {
        FILETIME           timeStamp;
        UINT32             flags;
        FWP_IP_VERSION     ipVersion;
        UINT8              ipProtocol;
        union {
          UINT32           localAddrV4;
          FWP_BYTE_ARRAY16 localAddrV6;
        };
        union {
          UINT32           remoteAddrV4;
          FWP_BYTE_ARRAY16 remoteAddrV6;
        };
        UINT16             localPort;
        UINT16             remotePort;
        UINT32             scopeId;
        FWP_BYTE_BLOB      appId;
        SID               *userId;
        FWP_AF             addressFamily;
        SID               *packageSid;
      } _FWPM_NET_EVENT_HEADER2;

typedef struct _FWPM_NET_EVENT_HEADER3 {
        FILETIME            timeStamp;
        UINT32              flags;
        FWP_IP_VERSION      ipVersion;
        UINT8               ipProtocol;
        union {
          UINT32            localAddrV4;
          FWP_BYTE_ARRAY16  localAddrV6;
        };
        union {
          UINT32            remoteAddrV4;
          FWP_BYTE_ARRAY16  remoteAddrV6;
        };
        UINT16              localPort;
        UINT16              remotePort;
        UINT32              scopeId;
        FWP_BYTE_BLOB       appId;
        SID                *userId;
        FWP_AF              addressFamily;
        SID                *packageSid;
        wchar_t            *enterpriseId;
        UINT64              policyFlags;
        FWP_BYTE_BLOB       effectiveName;
      } _FWPM_NET_EVENT_HEADER3;

#if defined(__MINGW32__)
  typedef struct FWPM_LAYER_STATISTICS0 {
          GUID    layerId;
          UINT32  classifyPermitCount;
          UINT32  classifyBlockCount;
          UINT32  classifyVetoCount;
          UINT32  numCacheEntries;
        } FWPM_LAYER_STATISTICS0;

  typedef struct FWPM_STATISTICS0 {
          UINT32                  numLayerStatistics;
          FWPM_LAYER_STATISTICS0 *layerStatistics;
          UINT32                  inboundAllowedConnectionsV4;
          UINT32                  inboundBlockedConnectionsV4;
          UINT32                  outboundAllowedConnectionsV4;
          UINT32                  outboundBlockedConnectionsV4;
          UINT32                  inboundAllowedConnectionsV6;
          UINT32                  inboundBlockedConnectionsV6;
          UINT32                  outboundAllowedConnectionsV6;
          UINT32                  outboundBlockedConnectionsV6;
          UINT32                  inboundActiveConnectionsV4;
          UINT32                  outboundActiveConnectionsV4;
          UINT32                  inboundActiveConnectionsV6;
          UINT32                  outboundActiveConnectionsV6;
          UINT64                  reauthDirInbound;
          UINT64                  reauthDirOutbound;
          UINT64                  reauthFamilyV4;
          UINT64                  reauthFamilyV6;
          UINT64                  reauthProtoOther;
          UINT64                  reauthProtoIPv4;
          UINT64                  reauthProtoIPv6;
          UINT64                  reauthProtoICMP;
          UINT64                  reauthProtoICMP6;
          UINT64                  reauthProtoUDP;
          UINT64                  reauthProtoTCP;
          UINT64                  reauthReasonPolicyChange;
          UINT64                  reauthReasonNewArrivalInterface;
          UINT64                  reauthReasonNewNextHopInterface;
          UINT64                  reauthReasonProfileCrossing;
          UINT64                  reauthReasonClassifyCompletion;
          UINT64                  reauthReasonIPSecPropertiesChanged;
          UINT64                  reauthReasonMidStreamInspection;
          UINT64                  reauthReasonSocketPropertyChanged;
          UINT64                  reauthReasonNewInboundMCastBCastPacket;
          UINT64                  reauthReasonEDPPolicyChanged;
          UINT64                  reauthReasonPreclassifyLocalAddrLayerChange;
          UINT64                  reauthReasonPreclassifyRemoteAddrLayerChange;
          UINT64                  reauthReasonPreclassifyLocalPortLayerChange;
          UINT64                  reauthReasonPreclassifyRemotePortLayerChange;
          UINT64                  reauthReasonProxyHandleChanged;
        } FWPM_STATISTICS0;

  #if 0
    typedef struct FWPM_FILTER_CONDITION0 {
            GUID                  fieldKey;
            FWP_MATCH_TYPE        matchType;
            FWP_CONDITION_VALUE0  conditionValue;
          } FWPM_FILTER_CONDITION0;

    typedef struct FWPM_NET_EVENT_ENUM_TEMPLATE0 {
            FILETIME                 startTime;
            FILETIME                 endTime;
            UINT32                   numFilterConditions;
            FWPM_FILTER_CONDITION0  *filterCondition;
          } FWPM_NET_EVENT_ENUM_TEMPLATE0;

    typedef struct FWPM_NET_EVENT_SUBSCRIPTION0 {
            FWPM_NET_EVENT_ENUM_TEMPLATE0 *enumTemplate;
            UINT32                         flags;
            GUID                           sessionKey;
          } FWPM_NET_EVENT_SUBSCRIPTION0;
  #endif

//#define FWPM_NET_EVENT_CLASSIFY_DROP             FWPM_NET_EVENT_CLASSIFY_DROP2
//#define FWPM_NET_EVENT_CLASSIFY_ALLOW            FWPM_NET_EVENT_CLASSIFY_ALLOW0
  #define FWPM_NET_EVENT_SUBSCRIPTION              FWPM_NET_EVENT_SUBSCRIPTION0
  #define FWPM_NET_EVENT_ENUM_TEMPLATE             FWPM_NET_EVENT_ENUM_TEMPLATE0
  #define FWPM_NET_EVENT                           FWPM_NET_EVENT2
  #define FWPM_SESSION                             FWPM_SESSION0
  #define FWP_VALUE                                FWP_VALUE0
  #define FWPM_STATISTICS                          FWPM_STATISTICS0

  #define FWPM_NET_EVENT_KEYWORD_CAPABILITY_DROP   0x00000004
  #define FWPM_NET_EVENT_KEYWORD_CAPABILITY_ALLOW  0x00000008
  #define FWPM_NET_EVENT_KEYWORD_CLASSIFY_ALLOW    0x00000010

  #define FWPM_NET_EVENT_FLAG_IP_PROTOCOL_SET      0x00000001
  #define FWPM_NET_EVENT_FLAG_LOCAL_ADDR_SET       0x00000002
  #define FWPM_NET_EVENT_FLAG_REMOTE_ADDR_SET      0x00000004
  #define FWPM_NET_EVENT_FLAG_LOCAL_PORT_SET       0x00000008
  #define FWPM_NET_EVENT_FLAG_REMOTE_PORT_SET      0x00000010
  #define FWPM_NET_EVENT_FLAG_APP_ID_SET           0x00000020
  #define FWPM_NET_EVENT_FLAG_USER_ID_SET          0x00000040
  #define FWPM_NET_EVENT_FLAG_SCOPE_ID_SET         0x00000080
  #define FWPM_NET_EVENT_FLAG_IP_VERSION_SET       0x00000100
  #define FWPM_NET_EVENT_FLAG_REAUTH_REASON_SET    0x00000200
  #define FWPM_NET_EVENT_FLAG_PACKAGE_ID_SET       0x00000400
  #define FWPM_NET_EVENT_FLAG_ENTERPRISE_ID_SET    0x00000800
  #define FWPM_NET_EVENT_FLAG_POLICY_FLAGS_SET     0x00001000
  #define FWPM_NET_EVENT_FLAG_EFFECTIVE_NAME_SET   0x00002000

  #define FWPM_ENGINE_MONITOR_IPSEC_CONNECTIONS    3
#endif

/*
 * These are not in any MinGW SDK. So just define them here.
 */
typedef struct _FWPM_NET_EVENT0 {
        _FWPM_NET_EVENT_HEADER0 header;
        FWPM_NET_EVENT_TYPE     type;
        union {
            _FWPM_NET_EVENT_CLASSIFY_DROP0     *classifyDrop;
          /* FWPM_NET_EVENT_IKEEXT_MM_FAILURE0 *ikeMmFailure; Not needed */
          /* FWPM_NET_EVENT_IKEEXT_QM_FAILURE0 *ikeQmFailure; Not needed */
          /* FWPM_NET_EVENT_IKEEXT_EM_FAILURE0 *ikeEmFailure; Not needed */
          /* FWPM_NET_EVENT_IPSEC_KERNEL_DROP0 *ipsecDrop;    Not needed */
          /* FWPM_NET_EVENT_IPSEC_DOSP_DROP0   *idpDrop;      Not needed */
        };
      }  _FWPM_NET_EVENT0;

typedef struct _FWPM_NET_EVENT1 {
        _FWPM_NET_EVENT_HEADER1 header;
        FWPM_NET_EVENT_TYPE     type;
        union {
            _FWPM_NET_EVENT_CLASSIFY_DROP1     *classifyDrop;
          /* FWPM_NET_EVENT_IKEEXT_MM_FAILURE1 *ikeMmFailure;  Not needed */
          /* FWPM_NET_EVENT_IKEEXT_QM_FAILURE0 *ikeQmFailure;  Not needed */
          /* FWPM_NET_EVENT_IKEEXT_EM_FAILURE1 *ikeEmFailure;  Not needed */
          /* FWPM_NET_EVENT_IPSEC_KERNEL_DROP0 *ipsecDrop;     Not needed */
          /* FWPM_NET_EVENT_IPSEC_DOSP_DROP0   *idpDrop;       Not needed */
        };
      } _FWPM_NET_EVENT1;

typedef struct _FWPM_NET_EVENT2 {
        _FWPM_NET_EVENT_HEADER2 header;
        FWPM_NET_EVENT_TYPE     type;
        union {
             _FWPM_NET_EVENT_CLASSIFY_DROP2    *classifyDrop;
             _FWPM_NET_EVENT_CLASSIFY_ALLOW0   *classifyAllow;
          /* FWPM_NET_EVENT_IKEEXT_MM_FAILURE1 *ikeMmFailure;     Not needed */
          /* FWPM_NET_EVENT_IKEEXT_QM_FAILURE0 *ikeQmFailure;     Not needed */
          /* FWPM_NET_EVENT_IKEEXT_EM_FAILURE1 *ikeEmFailure;     Not needed */
          /* FWPM_NET_EVENT_IPSEC_KERNEL_DROP0 *ipsecDrop;        Not needed */
          /* FWPM_NET_EVENT_IPSEC_DOSP_DROP0   *idpDrop;          Not needed */
          /* FWPM_NET_EVENT_CAPABILITY_DROP0   *capabilityDrop;   Not needed */
          /* FWPM_NET_EVENT_CAPABILITY_ALLOW0  *capabilityAllow;  Not needed */
          /* FWPM_NET_EVENT_CLASSIFY_DROP_MAC0 *classifyDropMac;  Not needed */
        };
      } _FWPM_NET_EVENT2;

typedef struct _FWPM_NET_EVENT3 {
        _FWPM_NET_EVENT_HEADER3 header;
        FWPM_NET_EVENT_TYPE     type;
        union {
          _FWPM_NET_EVENT_CLASSIFY_DROP2     *classifyDrop;
          _FWPM_NET_EVENT_CLASSIFY_ALLOW0    *classifyAllow;
       /* FWPM_NET_EVENT_IKEEXT_MM_FAILURE1  *ikeMmFailure;    Not needed */
       /* FWPM_NET_EVENT_IKEEXT_QM_FAILURE0  *ikeQmFailure;    Not needed */
       /* FWPM_NET_EVENT_IKEEXT_EM_FAILURE1  *ikeEmFailure;    Not needed */
       /* FWPM_NET_EVENT_IPSEC_KERNEL_DROP0  *ipsecDrop;       Not needed */
       /* FWPM_NET_EVENT_IPSEC_DOSP_DROP0    *idpDrop;         Not needed */
       /* FWPM_NET_EVENT_CAPABILITY_DROP0    *capabilityDrop;  Not needed */
       /* FWPM_NET_EVENT_CAPABILITY_ALLOW0   *capabilityAllow; Not needed */
       /* FWPM_NET_EVENT_CLASSIFY_DROP_MAC0  *classifyDropMac; Not needed */
        };
      } _FWPM_NET_EVENT3;

typedef struct _FWPM_NET_EVENT4 {
        _FWPM_NET_EVENT_HEADER3 header;
        FWPM_NET_EVENT_TYPE     type;
        union {
          _FWPM_NET_EVENT_CLASSIFY_DROP2     *classifyDrop;
          _FWPM_NET_EVENT_CLASSIFY_ALLOW0    *classifyAllow;
       /* FWPM_NET_EVENT_IKEEXT_MM_FAILURE2  *ikeMmFailure;    Not needed */
       /* FWPM_NET_EVENT_IKEEXT_QM_FAILURE1  *ikeQmFailure;    Not needed */
       /* FWPM_NET_EVENT_IKEEXT_EM_FAILURE1  *ikeEmFailure;    Not needed */
       /* FWPM_NET_EVENT_IPSEC_KERNEL_DROP0  *ipsecDrop;       Not needed */
       /* FWPM_NET_EVENT_IPSEC_DOSP_DROP0    *idpDrop;         Not needed */
       /* FWPM_NET_EVENT_CAPABILITY_DROP0    *capabilityDrop;  Not needed */
       /* FWPM_NET_EVENT_CAPABILITY_ALLOW0   *capabilityAllow; Not needed */
       /* FWPM_NET_EVENT_CLASSIFY_DROP_MAC0  *classifyDropMac; Not needed */
        };
      } _FWPM_NET_EVENT4;

typedef struct _FWPM_NET_EVENT5 {
        _FWPM_NET_EVENT_HEADER3 header;
        FWPM_NET_EVENT_TYPE     type;
        union {
          _FWPM_NET_EVENT_CLASSIFY_DROP2      *classifyDrop;
          _FWPM_NET_EVENT_CLASSIFY_ALLOW0     *classifyAllow;
       /* FWPM_NET_EVENT_IKEEXT_MM_FAILURE2   *ikeMmFailure;     Not needed */
       /* FWPM_NET_EVENT_IKEEXT_QM_FAILURE1   *ikeQmFailure;     Not needed */
       /* FWPM_NET_EVENT_IKEEXT_EM_FAILURE1   *ikeEmFailure;     Not needed */
       /* FWPM_NET_EVENT_IPSEC_KERNEL_DROP0   *ipsecDrop;        Not needed */
       /* FWPM_NET_EVENT_IPSEC_DOSP_DROP0     *idpDrop;          Not needed */
       /* FWPM_NET_EVENT_CAPABILITY_DROP0     *capabilityDrop;   Not needed */
       /* FWPM_NET_EVENT_CAPABILITY_ALLOW0    *capabilityAllow;  Not needed */
       /* FWPM_NET_EVENT_CLASSIFY_DROP_MAC0   *classifyDropMac;  Not needed */
       /* FWPM_NET_EVENT_LPM_PACKET_ARRIVAL0  *lpmPacketArrival; Not needed */
        };
      } _FWPM_NET_EVENT5;

typedef void (CALLBACK *_FWPM_NET_EVENT_CALLBACK0) (void *context,
                                                    const _FWPM_NET_EVENT1 *event);

typedef void (CALLBACK *_FWPM_NET_EVENT_CALLBACK1) (void                   *context,
                                                    const _FWPM_NET_EVENT2 *event);

typedef void (CALLBACK *_FWPM_NET_EVENT_CALLBACK2) (void                   *context,
                                                    const _FWPM_NET_EVENT3 *event);

typedef void (CALLBACK *_FWPM_NET_EVENT_CALLBACK3) (void                   *context,
                                                    const _FWPM_NET_EVENT4 *event);

typedef void (CALLBACK *_FWPM_NET_EVENT_CALLBACK4) (void                   *context,
                                                    const _FWPM_NET_EVENT5 *event);

#if defined(USE_FWUCLNT_STATIC_LIB)
  DEF_FUNC2 (DWORD, FwpmEngineOpen0, (const wchar_t             *server_name,
                                      UINT32                     authn_service,
                                      SEC_WINNT_AUTH_IDENTITY_W *auth_identity,
                                      const FWPM_SESSION0       *session,
                                      HANDLE                    *engine_handle),
                    FwpmEngineOpen0);

  DEF_FUNC2 (DWORD, FwpmEngineSetOption0, (HANDLE            engine_handle,
                                          FWPM_ENGINE_OPTION option,
                                          const FWP_VALUE0  *new_value),
                    FwpmEngineSetOption0);

  DEF_FUNC2 (DWORD, FwpmNetEventSubscribe2, (HANDLE                              engine_handle,
                                             const FWPM_NET_EVENT_SUBSCRIPTION0 *subscription,
                                             _FWPM_NET_EVENT_CALLBACK2           callback,
                                             void                               *context,
                                             HANDLE                             *events_handle),
                    FwpmNetEventSubscribe2);

  DEF_FUNC2 (DWORD, FwpmNetEventSubscribe3, (HANDLE                              engine_handle,
                                             const FWPM_NET_EVENT_SUBSCRIPTION0 *subscription,
                                             _FWPM_NET_EVENT_CALLBACK3           callback,
                                             void                               *context,
                                             HANDLE                             *events_handle),
                    FwpmNetEventSubscribe3);

  DEF_FUNC2 (DWORD, FwpmNetEventSubscribe4, (HANDLE                              engine_handle,
                                             const FWPM_NET_EVENT_SUBSCRIPTION0 *subscription,
                                             _FWPM_NET_EVENT_CALLBACK4           callback,
                                             void                               *context,
                                             HANDLE                             *events_handle),
                    FwpmNetEventSubscribe4);

#else

  /*
   * "FwpUclnt.dll" typedefs and functions pointers:
   */
  DEF_FUNC (DWORD, FwpmNetEventSubscribe0, (HANDLE                              engine_handle,
                                            const FWPM_NET_EVENT_SUBSCRIPTION0 *subscription,
                                            _FWPM_NET_EVENT_CALLBACK0           callback,
                                            void                               *context,
                                            HANDLE                             *events_handle));

  DEF_FUNC (DWORD, FwpmNetEventSubscribe1, (HANDLE                              engine_handle,
                                            const FWPM_NET_EVENT_SUBSCRIPTION0 *subscription,
                                            _FWPM_NET_EVENT_CALLBACK1            callback,
                                            void                               *context,
                                            HANDLE                             *events_handle));

  DEF_FUNC (DWORD, FwpmNetEventSubscribe2, (HANDLE                              engine_handle,
                                            const FWPM_NET_EVENT_SUBSCRIPTION0 *subscription,
                                            _FWPM_NET_EVENT_CALLBACK2           callback,
                                            void                               *context,
                                            HANDLE                             *events_handle));

  DEF_FUNC (DWORD, FwpmNetEventSubscribe3, (HANDLE                              engine_handle,
                                            const FWPM_NET_EVENT_SUBSCRIPTION0 *subscription,
                                            _FWPM_NET_EVENT_CALLBACK3           callback,
                                            void                               *context,
                                            HANDLE                             *events_handle));

  DEF_FUNC (DWORD, FwpmNetEventSubscribe4, (HANDLE                              engine_handle,
                                            const FWPM_NET_EVENT_SUBSCRIPTION0 *subscription,
                                            _FWPM_NET_EVENT_CALLBACK4           callback,
                                            void                               *context,
                                            HANDLE                             *events_handle));

  DEF_FUNC (DWORD, FwpmNetEventUnsubscribe0, (HANDLE engine_handle,
                                              HANDLE events_handle));

  DEF_FUNC (DWORD, FwpmEngineOpen0, (const wchar_t             *server_name,
                                     UINT32                     authn_service,
                                     SEC_WINNT_AUTH_IDENTITY_W *auth_identity,
                                     const FWPM_SESSION0       *session,
                                     HANDLE                    *engine_handle));

  DEF_FUNC (DWORD, FwpmEngineSetOption0, (HANDLE             engine_handle,
                                          FWPM_ENGINE_OPTION option,
                                          const FWP_VALUE0  *new_value));

  DEF_FUNC (DWORD, FwpmLayerGetById0, (HANDLE        engine_handle,
                                       UINT16        id,
                                       FWPM_LAYER0 **layer));

  DEF_FUNC (DWORD, FwpmFilterGetById0, (HANDLE         engine_handle,
                                        UINT64         id,
                                        FWPM_FILTER0 **filter));

  DEF_FUNC (void, FwpmFreeMemory0, (void **p));

  DEF_FUNC (DWORD, FwpmEngineClose0, (HANDLE engine_handle));

  DEF_FUNC (DWORD, FwpmCalloutCreateEnumHandle0, (HANDLE                             engine_handle,
                                                  const FWPM_CALLOUT_ENUM_TEMPLATE0 *enum_template,
                                                  HANDLE                            *enum_handle));

  DEF_FUNC (DWORD, FwpmCalloutEnum0, (HANDLE           engine_handle,
                                      HANDLE           enum_handle,
                                      UINT32           num_entries_requested,
                                      FWPM_CALLOUT0 ***entries,
                                      UINT32          *num_entries_returned));

  DEF_FUNC (DWORD, FwpmCalloutDestroyEnumHandle0, (HANDLE engine_handle,
                                                   HANDLE enum_handle));

#endif /* USE_FWUCLNT_STATIC_LIB */

/*
 * "FirewallAPI.dll" typedefs and functions pointers:
 */
DEF_FUNC (ULONG, FWOpenPolicyStore, (USHORT                   binary_version,
                                     wchar_t                 *machine_or_GPO,
                                     FW_STORE_TYPE           store_type,
                                     FW_POLICY_ACCESS_RIGHT  access_right,
                                     FW_POLICY_STORE_FLAGS   flags,
                                     HANDLE                 *policy));

DEF_FUNC (ULONG, FWEnumFirewallRules, (HANDLE                 policy_store,
                                       FW_RULE_STATUS_CLASS   filtered_by_status,
                                       FW_PROFILE_TYPE        profile_filter,
                                       FW_ENUM_RULES_FLAGS    flags,
                                       ULONG                 *num_rules,
                                       FW_RULE              **rules));

DEF_FUNC (ULONG, FWStatusMessageFromStatusCode, (FW_RULE_STATUS status_code,
                                                 wchar_t       *msg,
                                                 ULONG         *msg_size));

DEF_FUNC (ULONG, FWFreeFirewallRules, (FW_RULE *pFwRules));
DEF_FUNC (ULONG, FWClosePolicyStore, (HANDLE *policy_store));

/**
 * Use this error-code if a needed function is not found.
 */
#define FUNC_ERROR ERROR_FUNCTION_FAILED

#define ADD_VALUE(dll, func)   { TRUE, NULL, dll, #func, (void**)&p_##func }

static struct LoadTable fw_funcs[] = {
              ADD_VALUE ("FirewallAPI.dll", FWOpenPolicyStore),
              ADD_VALUE ("FirewallAPI.dll", FWClosePolicyStore),
              ADD_VALUE ("FirewallAPI.dll", FWEnumFirewallRules),
              ADD_VALUE ("FirewallAPI.dll", FWFreeFirewallRules),
              ADD_VALUE ("FirewallAPI.dll", FWStatusMessageFromStatusCode),
#if !defined(USE_FWUCLNT_STATIC_LIB)
              ADD_VALUE ("FwpUclnt.dll",    FwpmNetEventSubscribe0),
              ADD_VALUE ("FwpUclnt.dll",    FwpmNetEventSubscribe1),
              ADD_VALUE ("FwpUclnt.dll",    FwpmNetEventSubscribe2),
              ADD_VALUE ("FwpUclnt.dll",    FwpmNetEventSubscribe3),    /* Win10 RS4+ */
              ADD_VALUE ("FwpUclnt.dll",    FwpmNetEventSubscribe4),    /* Win10 RS5+ */
              ADD_VALUE ("FwpUclnt.dll",    FwpmNetEventUnsubscribe0),
              ADD_VALUE ("FwpUclnt.dll",    FwpmFreeMemory0),
              ADD_VALUE ("FwpUclnt.dll",    FwpmEngineClose0),
              ADD_VALUE ("FwpUclnt.dll",    FwpmEngineOpen0),
              ADD_VALUE ("FwpUclnt.dll",    FwpmEngineSetOption0),
              ADD_VALUE ("FwpUclnt.dll",    FwpmLayerGetById0),
              ADD_VALUE ("FwpUclnt.dll",    FwpmFilterGetById0),
              ADD_VALUE ("FwpUclnt.dll",    FwpmCalloutCreateEnumHandle0),
              ADD_VALUE ("FwpUclnt.dll",    FwpmCalloutEnum0),
              ADD_VALUE ("FwpUclnt.dll",    FwpmCalloutDestroyEnumHandle0)
#endif
            };

DWORD fw_errno;
int   fw_lowest_api = -1;

static HANDLE fw_policy_handle = NULL;
static HANDLE fw_engine_handle = NULL;
static HANDLE fw_event_handle  = NULL;
static DWORD  fw_num_rules     = 0;
static DWORD  fw_num_events    = 0;
static DWORD  fw_num_ignored   = 0;
static BOOL   fw_show_ipv4     = TRUE;
static BOOL   fw_show_ipv6     = TRUE;

static BOOL fw_monitor_init (FWPM_NET_EVENT_SUBSCRIPTION *subscription);

#define FW_ASSERT(x)                                                \
        do {                                                        \
          if (!(x)) {                                               \
             fprintf (stderr, "\n%s(%u): Assertion failed: '%s'\n", \
                     __FILE__, __LINE__, #x);                       \
             _exit (-1);                                            \
          }                                                         \
        } while (0)

#define FW_EVENT_CALLBACK(event_ver, callback_ver, drop, allow)                          \
        static void CALLBACK                                                             \
        fw_event_callback##event_ver (void *context,                                     \
                 const _FWPM_NET_EVENT##callback_ver *event)                             \
        {                                                                                \
          if (!event) {                                                                  \
            trace_printf ("~4event == NULL!\n~0");                                       \
            fw_num_ignored++;                                                            \
          }                                                                              \
          else {                                                                         \
            fw_event_callback (event->type,                                              \
                               (const _FWPM_NET_EVENT_HEADER3*)&event->header,           \
                               event->type == _FWPM_NET_EVENT_TYPE_CLASSIFY_DROP ?       \
                                (const _FWPM_NET_EVENT_CLASSIFY_DROP2*) drop : NULL,     \
                               event->type == _FWPM_NET_EVENT_TYPE_CLASSIFY_ALLOW ?      \
                                 (const _FWPM_NET_EVENT_CLASSIFY_ALLOW0*) allow : NULL); \
          }                                                                              \
          ARGSUSED (context);                                                            \
        }

static void CALLBACK fw_event_callback (const UINT                             event_type,
                                        const _FWPM_NET_EVENT_HEADER3         *header,
                                        const _FWPM_NET_EVENT_CLASSIFY_DROP2  *drop_event,
                                        const _FWPM_NET_EVENT_CLASSIFY_ALLOW0 *allow_event);

FW_EVENT_CALLBACK (0, 1, event->classifyDrop, NULL)  /* -> 'static void CALLBACK fw_event_callback0 (void *context, const _FWPM_NET_EVENT1 *event) ...' */
FW_EVENT_CALLBACK (1, 2, event->classifyDrop, NULL)
FW_EVENT_CALLBACK (2, 3, event->classifyDrop, event->classifyAllow)
FW_EVENT_CALLBACK (3, 4, event->classifyDrop, event->classifyAllow)
FW_EVENT_CALLBACK (4, 5, event->classifyDrop, event->classifyAllow)


/**
 * Ensure the needed functions are loaded only once.
 *
 * We'll probably manage with only `FwpmNetEventSubscribe0()`.
 * Hence subtract 4 from the number of functions in `fw_funcs[]`.
 */
static BOOL fw_load_funcs (void)
{
  const struct LoadTable *tab = fw_funcs + 0;
  int   i, num, functions_needed = DIM(fw_funcs);

#if !defined(USE_FWUCLNT_STATIC_LIB)
  functions_needed -= 4;
#endif

  for (i = num = 0; i < DIM(fw_funcs); i++)
  {
    if (*tab->func_addr)
       num++;
    tab++;
  }

  /* Already loaded functions okay; get out.
   */
  if (num >= functions_needed)
     return (TRUE);

  /* Functions never loaded.
   */
  if (num == 0)
     num = load_dynamic_table (fw_funcs, DIM(fw_funcs));

  if (num < functions_needed)
  {
    fw_errno = FUNC_ERROR;
    return (FALSE);
  }
  return (TRUE);
}

/**
 * This should be the first functions called in this module.
 * But `fw_monitor_start()` does not depend on this function having
 * been called first.
 */
BOOL fw_init (void)
{
  USHORT api_version = FW_REDSTONE2_BINARY_VERSION;

  fw_num_rules = 0;

  if (!fw_load_funcs())
     return (FALSE);

  fw_errno = (*p_FWOpenPolicyStore) (api_version, NULL, FW_STORE_TYPE_DEFAULTS, FW_POLICY_ACCESS_RIGHT_READ,
                                     FW_POLICY_STORE_FLAGS_NONE, &fw_policy_handle);
  return (fw_errno == ERROR_SUCCESS);
}

/**
 * This should be the last functions called in this module.
 */
void fw_exit (void)
{
  if (p_FWClosePolicyStore && fw_policy_handle)
    (*p_FWClosePolicyStore) (fw_policy_handle);

  fw_policy_handle = NULL;

  fw_monitor_stop();

  unload_dynamic_table (fw_funcs, DIM(fw_funcs));
}

static void fw_enumerate_rules (FW_PROFILE_TYPE type,
                                FW_DIRECTION    direction,
                                FW_WALK_RULES   callback)
{
  FW_RULE *rule, *rules = NULL;
  ULONG    rule_count = 0;
  ULONG    result;
  ULONG    flags  = FW_ENUM_RULES_FLAG_RESOLVE_NAME |
                    FW_ENUM_RULES_FLAG_RESOLVE_DESCRIPTION |
                    FW_ENUM_RULES_FLAG_RESOLVE_APPLICATION |
                    FW_ENUM_RULES_FLAG_RESOLVE_KEYWORD;

  result = (*p_FWEnumFirewallRules) (fw_policy_handle, FW_RULE_STATUS_CLASS_ALL,
                                     type, (FW_ENUM_RULES_FLAGS)flags,
                                     &rule_count, &rules);
  if (result == ERROR_SUCCESS && rules && rule_count)
  {
    for (rule = rules; rule; rule = rule->pNext)
    {
      if (direction == FW_DIR_BOTH || rule->Direction == direction)
        (*callback) (rule);
    }
  }
  if (p_FWFreeFirewallRules && rules)
    (*p_FWFreeFirewallRules) (rules);
}

static void print_long_wline (const wchar_t *start, size_t indent)
{
  size_t         width = g_cfg.screen_width;
  size_t         left = width - indent;
  const wchar_t *c = start;

  while (*c)
  {
    /* Break a long line only at space or TAB.
     * Check if room for a word (L"foo ") before we must break the line.
     */
    if (iswspace(*c))
    {
      const wchar_t *next = wcschr (c+1, L' ');

      if (!next)
         next = wcschr (c+1, L'\0');
      if (left <= 2 || (left < (next - c)/sizeof(wchar_t)))
      {
        trace_printf ("\n%*c", (int)indent, ' ');
        left = width - indent;
        do {
          c++;
        } while (c[1] && iswspace(*c));  /* If next 'wchar_t' is a space, drop it */
        continue;
      }
    }
    trace_putc (*c++);  /* truncates to 'char' */
    left--;
  }
  trace_putc ('\n');
}

static void fw_dump_rules (const FW_RULE *rule)
{
  const char *dir = (rule->Direction == FW_DIR_INVALID) ? "INV" :
                    (rule->Direction == FW_DIR_IN)      ? "IN"  :
                    (rule->Direction == FW_DIR_OUT)     ? "OUT" :
                    (rule->Direction == FW_DIR_BOTH)    ? "BOTH": "?";

  int indent = trace_printf ("%3lu: %s: ", ++fw_num_rules, dir);

  print_long_wline (rule->wszDescription, indent);

  if (rule->wszLocalApplication)
     trace_printf ("     wszName:            %S\n", rule->wszName);

  if (rule->wszEmbeddedContext)
     trace_printf ("     wszEmbeddedContext: %S\n", rule->wszEmbeddedContext);

  trace_putc ('\n');
}

static BOOL fw_monitor_init (FWPM_NET_EVENT_SUBSCRIPTION *subscription)
{
  FWPM_SESSION session;
  FWP_VALUE    value;
  DWORD        rc;

  memset (&session, '\0', sizeof(session));
  session.flags                   = 0;  // FWPM_SESSION_FLAG_DYNAMIC;
  session.displayData.name        = L"FirewallMonitoringSession";
  session.displayData.description = L"Non-Dynamic session for wsock_trace";

  /* Assume `p_FwpmEngineOpen0` is NULL
   */
  rc = FUNC_ERROR;

  /* Create a non-dynamic BFE session.
   * Adapted from:
   *   https://docs.microsoft.com/en-us/windows/desktop/fwp/displaying-net-events
   */
  if (!p_FwpmEngineOpen0 ||
      (rc = (*p_FwpmEngineOpen0)(NULL, RPC_C_AUTHN_WINNT, NULL, &session,
                                 &fw_engine_handle)) != ERROR_SUCCESS)
  {
    fw_errno = rc;
    return (FALSE);
  }

  /* Assume `p_FwpmEngineSetOption0` is NULL
   */
  rc = FUNC_ERROR;

  /* Enable collection of NetEvents
   */
  memset (&value, '\0', sizeof(value));
  value.type   = FWP_EMPTY;
  value.type   = FWP_UINT32;
  value.uint32 = 1;

  if (!p_FwpmEngineSetOption0 ||
      (rc = (*p_FwpmEngineSetOption0)(fw_engine_handle,
                                      FWPM_ENGINE_COLLECT_NET_EVENTS,
                                      &value)) != ERROR_SUCCESS)
  {
    fw_errno = rc;
    return (FALSE);
  }

  value.type   = FWP_UINT32;
  value.uint32 = FWPM_NET_EVENT_KEYWORD_CAPABILITY_DROP  |
                 FWPM_NET_EVENT_KEYWORD_CAPABILITY_ALLOW |
                 FWPM_NET_EVENT_KEYWORD_CLASSIFY_ALLOW   |
                 FWPM_NET_EVENT_KEYWORD_INBOUND_MCAST    |
                 FWPM_NET_EVENT_KEYWORD_INBOUND_BCAST;

  rc = (*p_FwpmEngineSetOption0) (fw_engine_handle, FWPM_ENGINE_NET_EVENT_MATCH_ANY_KEYWORDS, &value);
  if (rc != ERROR_SUCCESS)
  {
    fw_errno = rc;
    return (FALSE);
  }

#if 1
  value.type   = FWP_UINT32;
  value.uint32 = 1;

  rc = (*p_FwpmEngineSetOption0) (fw_engine_handle, FWPM_ENGINE_MONITOR_IPSEC_CONNECTIONS, &value);
  if (rc != ERROR_SUCCESS)
  {
    fw_errno = rc;
    return (FALSE);
  }
#endif

  subscription->sessionKey = session.sessionKey;
  fw_errno = ERROR_SUCCESS;
  return (TRUE);
}


/*
 * Try all available `FwpmNetEventSubscribeX()` functions and return TRUE if one succeedes.
 * Start with the one above or equal the given API-level.
 */
static BOOL fw_monitor_subscribe (FWPM_NET_EVENT_SUBSCRIPTION *subscription)
{
  #define SET_API_CALLBACK(N)                                                      \
          do {                                                                     \
            if (lowest_api >= N && p_FwpmNetEventSubscribe##N &&                   \
                (*p_FwpmNetEventSubscribe##N) (fw_engine_handle, subscription,     \
                                               fw_event_callback##N, hnd,          \
                                               &fw_event_handle) == ERROR_SUCCESS) \
            {                                                                      \
              TRACE (1, "FwpmNetEventSubscribe%d() succeeded.\n", N);              \
              return (TRUE);                                                       \
            }                                                                      \
          } while (0)

  #define CHK_API_CALLBACK(N)               \
          do {                              \
            if (lowest_api > N) {           \
              fw_errno = ERROR_BAD_COMMAND; \
              goto quit;                    \
            }                               \
          } while (0)

#if 1
  HANDLE hnd = fw_engine_handle;  /* pass engine_handle so we don't have to open another */
#else
  HANDLE hnd = NULL;
#endif

  int lowest_api = fw_lowest_api;

  if (lowest_api < FW_API_LOW)
      lowest_api = FW_API_DEFAULT;

  CHK_API_CALLBACK (FW_API_HIGH);

  SET_API_CALLBACK (4);
  CHK_API_CALLBACK (4);

  SET_API_CALLBACK (3);
  CHK_API_CALLBACK (3);

  SET_API_CALLBACK (2);
  CHK_API_CALLBACK (2);

  SET_API_CALLBACK (1);
  CHK_API_CALLBACK (1);

  SET_API_CALLBACK (0);

quit:
  TRACE (0, "FwpmNetEventSubscribe%d() failed.\n", lowest_api);
  return (FALSE);
}

static BOOL fw_check_sizes (void)
{
  #define CHK_SIZE(a, cond, b)                                            \
          do {                                                            \
            if (! (sizeof(a) cond sizeof(b)) ) {                          \
              printf ("Mismatch of '%s' and '%s'. %d versus %d bytes.\n", \
                      #a, #b, (int)sizeof(a), (int)sizeof(b));            \
              return (FALSE);                                             \
            }                                                             \
          } while (0)

  #define OffsetOf(x, item) (unsigned) offsetof (x, item)

  #define CHK_OFS(a, b, item)                                                 \
          do {                                                                \
            if (offsetof(a, item) != offsetof(b, item)) {                     \
              printf ("Mismatch of '%s' and '%s'. ofs %d versus %d bytes.\n", \
                      #a, #b, OffsetOf(a,item), OffsetOf(b,item));            \
              return (FALSE);                                                 \
            }                                                                 \
          } while (0)

  fw_errno = FUNC_ERROR;  /* Assume failure */

#if (_WIN32_WINNT >= 0x0A02)
  CHK_SIZE (FWPM_NET_EVENT_HEADER1, ==, _FWPM_NET_EVENT_HEADER1);
  CHK_SIZE (FWPM_NET_EVENT_HEADER2, ==, _FWPM_NET_EVENT_HEADER2);
  CHK_SIZE (FWPM_NET_EVENT_HEADER3, ==, _FWPM_NET_EVENT_HEADER3);

  CHK_SIZE (FWPM_NET_EVENT_CLASSIFY_DROP2, ==, _FWPM_NET_EVENT_CLASSIFY_DROP2);
  CHK_SIZE (FWPM_NET_EVENT_CLASSIFY_ALLOW0, ==, _FWPM_NET_EVENT_CLASSIFY_ALLOW0);

  CHK_SIZE (FWPM_NET_EVENT0, ==, _FWPM_NET_EVENT0);
  CHK_SIZE (FWPM_NET_EVENT1, ==, _FWPM_NET_EVENT1);
  CHK_SIZE (FWPM_NET_EVENT2, ==, _FWPM_NET_EVENT2);
  CHK_SIZE (FWPM_NET_EVENT3, ==, _FWPM_NET_EVENT3);
  CHK_SIZE (FWPM_NET_EVENT4, ==, _FWPM_NET_EVENT4);
  CHK_SIZE (FWPM_NET_EVENT5, ==, _FWPM_NET_EVENT5);
#endif

  CHK_OFS (FWPM_NET_EVENT_HEADER0,        _FWPM_NET_EVENT_HEADER0, appId);
  CHK_OFS (FWPM_NET_EVENT_HEADER1,        _FWPM_NET_EVENT_HEADER1, appId);
  CHK_OFS (FWPM_NET_EVENT_CLASSIFY_DROP1, _FWPM_NET_EVENT_CLASSIFY_DROP1, msFwpDirection);

#if (_WIN32_WINNT >= 0x0602)
  CHK_OFS (FWPM_NET_EVENT_HEADER2,        _FWPM_NET_EVENT_HEADER2, appId);
  CHK_OFS (FWPM_NET_EVENT_CLASSIFY_DROP2, _FWPM_NET_EVENT_CLASSIFY_DROP2, msFwpDirection);
#endif

  CHK_SIZE (_FWPM_NET_EVENT_HEADER3, >, _FWPM_NET_EVENT_HEADER0);
  CHK_SIZE (_FWPM_NET_EVENT_HEADER3, <, _FWPM_NET_EVENT_HEADER1); /* Yeah, really */
  CHK_SIZE (_FWPM_NET_EVENT_HEADER3, >, _FWPM_NET_EVENT_HEADER2);

  fw_errno = 0;
  return (TRUE);
}

BOOL fw_monitor_start (void)
{
  /* static */ FWPM_NET_EVENT_SUBSCRIPTION  subscription   = { 0 };
  /* static */ FWPM_NET_EVENT_ENUM_TEMPLATE event_template = { 0 };

  if (!fw_check_sizes())
     return (FALSE);

  if (!fw_load_funcs())
     return (FALSE);

  if (!fw_monitor_init(&subscription))
     return (FALSE);

  /* Get events for all conditions
   */
  event_template.numFilterConditions = 0;

#if 0
  subscription.enumTemplate = &event_template;
#else
  subscription.enumTemplate = NULL; /* Don't really need a template */
#endif

  /* Subscribe to the events.
   * With API level = `fw_lowest_api` or `2` if not user-defined.
   */
  if (!fw_monitor_subscribe(&subscription))
  {
    fw_errno = FUNC_ERROR;
    return (FALSE);
  }
  fw_num_events = fw_num_ignored = 0;
  return (TRUE);
}

void fw_monitor_stop (void)
{
  if (fw_engine_handle && fw_event_handle && p_FwpmNetEventUnsubscribe0)
  {
    (*p_FwpmNetEventUnsubscribe0) (fw_engine_handle, fw_event_handle);
    fw_event_handle = NULL;
  }
  if (fw_engine_handle && p_FwpmEngineClose0)
  {
    (*p_FwpmEngineClose0) (fw_engine_handle);
    fw_engine_handle = NULL;
  }
}

static void fw_enumerate_callouts (void)
{
  TRACE (1, "%s()\n", __FUNCTION__);
}

static void fw_dump_events (void)
{
  TRACE (1, "%s()\n", __FUNCTION__);
}

static void print_layer_item (const _FWPM_NET_EVENT_CLASSIFY_DROP2  *drop_event,
                              const _FWPM_NET_EVENT_CLASSIFY_ALLOW0 *allow_event)
{
  FWPM_LAYER0 *layer_item;
  UINT16       id = 0;

  if (drop_event)
     id = drop_event->layerId;
  else if (allow_event)
     id = allow_event->layerId;

  if (id && (*p_FwpmLayerGetById0)(fw_engine_handle, id, &layer_item) == ERROR_SUCCESS)
  {
    trace_printf ("  layer-item:  %S\n", layer_item->displayData.name);
    (*p_FwpmFreeMemory0) ((void**)&layer_item);
  }
}

static void print_filter_rule (const _FWPM_NET_EVENT_CLASSIFY_DROP2  *drop_event,
                               const _FWPM_NET_EVENT_CLASSIFY_ALLOW0 *allow_event)
{
  FWPM_FILTER0 *filter_item;
  UINT64        id = 0;

  if (drop_event)
     id = drop_event->filterId;
  else if (allow_event)
     id = allow_event->filterId;

  if (id && (*p_FwpmFilterGetById0)(fw_engine_handle, id, &filter_item) == ERROR_SUCCESS)
  {
    trace_printf ("  filter-item: %S\n", filter_item->displayData.name);
    (*p_FwpmFreeMemory0) ((void**)&filter_item);
  }
}

#if 0
static void print_user_id (const xx *header)
{
  if (header->flags & FWPM_NET_EVENT_FLAG_USER_ID_SET)
     trace_printf ("%S, " header->userId);
}
#endif

static const char *get_time_string (const FILETIME *ts)
{
  static char  time_str [30];
  time_t       ct = FILETIME_to_time_t (ts);
  const struct tm *tm = localtime (&ct);

  if (tm)
       strftime (time_str, sizeof(time_str), "%H:%M:%S", tm);
  else strcpy (time_str, "??");
  return (time_str);
}

static void print_country_location (const struct in_addr *ia4, const struct in6_addr *ia6)
{
  const char *country, *location;

  country = ia4 ? geoip_get_country_by_ipv4(ia4) : geoip_get_country_by_ipv6(ia6);
  if (country && *country != '-')
  {
    location = ia4 ? geoip_get_location_by_ipv4(ia4) : geoip_get_location_by_ipv6(ia6);
    country  = geoip_get_long_name_by_A2 (country);
    trace_printf ("\n  loc:  %s, %s", country, location ? location : "");
  }
}

#define PORT_STR_SIZE 80

static char *get_port (const _FWPM_NET_EVENT_HEADER3 *header, u_short port, char *port_str)
{
  struct servent *se = NULL;

  if (header->ipProtocol == IPPROTO_TCP)
     se = getservbyport (_byteswap_ushort(port), "tcp");
  else if (header->ipProtocol == IPPROTO_UDP)
     se = getservbyport (_byteswap_ushort(port), "udp");

  if (se && se->s_name)
       snprintf (port_str, PORT_STR_SIZE, "%d (%s)", port, se->s_name);
  else _itoa (port, port_str, 10);
  return (port_str);
}

static void get_ports (const _FWPM_NET_EVENT_HEADER3 *header,
                       const char                   **local_port_p,
                       const char                   **remote_port_p)
{
  static char local_port [PORT_STR_SIZE];
  static char remote_port [PORT_STR_SIZE];

  if (header->flags & FWPM_NET_EVENT_FLAG_LOCAL_PORT_SET)
       *local_port_p = get_port (header, header->localPort, local_port);
  else *local_port_p = "-";

  if (header->flags & FWPM_NET_EVENT_FLAG_REMOTE_PORT_SET)
       *remote_port_p = get_port (header, header->remotePort, remote_port);
  else *remote_port_p = "-";
}

/*
 * If it's an IPv4 ALLOW/DROP event, print the local / remote addresses for it.
 */
static BOOL print_addresses_ipv4 (const _FWPM_NET_EVENT_HEADER3 *header, BOOL direction_in)
{
  struct in_addr ia4;
  const char    *local_port;
  const char    *remote_port;
  char           local_addr [INET_ADDRSTRLEN];
  char           remote_addr [INET_ADDRSTRLEN];
  DWORD          ip;

  if (header->ipVersion != FWP_IP_VERSION_V4)
     return (FALSE);

  if ((header->flags & FWPM_NET_EVENT_FLAG_IP_VERSION_SET) == 0 ||
      (header->flags & (FWPM_NET_EVENT_FLAG_LOCAL_ADDR_SET | FWPM_NET_EVENT_FLAG_REMOTE_ADDR_SET)) == 0)
     return (FALSE);

  if (header->flags & FWPM_NET_EVENT_FLAG_LOCAL_ADDR_SET)
  {
    ip = _byteswap_ulong (*(DWORD*)&header->localAddrV4);
    inet_ntop (AF_INET, (INET_NTOP_ADDR)&ip, local_addr, sizeof(local_addr));
  }
  else
    strcpy (local_addr, "-");

  if (header->flags & FWPM_NET_EVENT_FLAG_REMOTE_ADDR_SET)
  {
    ip = _byteswap_ulong (*(DWORD*)&header->remoteAddrV4);
    inet_ntop (AF_INET, (INET_NTOP_ADDR)&ip, remote_addr, sizeof(remote_addr));
  }
  else
    strcpy (remote_addr, "-");

  get_ports (header, &local_port, &remote_port);

  if (direction_in)
       trace_printf ("  addr: %s -> %s, ports: %s / %s",
                     remote_addr, local_addr, remote_port, local_port);

  else trace_printf ("  addr: %s -> %s, ports: %s / %s",
                     local_addr, remote_addr, local_port, remote_port);

  if (header->flags & FWPM_NET_EVENT_FLAG_REMOTE_ADDR_SET)
  {
    ia4.s_addr = _byteswap_ulong (*(DWORD*)&header->remoteAddrV4);
    print_country_location (&ia4, NULL);
  }

  return (TRUE);
}

/*
 * If it's an IPv6 ALLOW/DROP event, print the local / remote addresses for it.
 */
static BOOL print_addresses_ipv6 (const _FWPM_NET_EVENT_HEADER3 *header, BOOL direction_in)
{
  const char *local_port;
  const char *remote_port;
  char        local_addr [INET6_ADDRSTRLEN];
  char        remote_addr [INET6_ADDRSTRLEN];

  if (header->ipVersion != FWP_IP_VERSION_V6)
     return (FALSE);

  if ((header->flags & FWPM_NET_EVENT_FLAG_IP_VERSION_SET) == 0 ||
      (header->flags & (FWPM_NET_EVENT_FLAG_LOCAL_ADDR_SET | FWPM_NET_EVENT_FLAG_REMOTE_ADDR_SET)) == 0)
     return (FALSE);

  if (header->flags & FWPM_NET_EVENT_FLAG_LOCAL_ADDR_SET)
       inet_ntop (AF_INET6, (INET_NTOP_ADDR)&header->localAddrV6, local_addr, sizeof(local_addr));
  else strcpy (local_addr, "-");

  if (header->flags & FWPM_NET_EVENT_FLAG_REMOTE_ADDR_SET)
       inet_ntop (AF_INET6, (INET_NTOP_ADDR)&header->remoteAddrV6, remote_addr, sizeof(remote_addr));
  else strcpy (remote_addr, "-");

  get_ports (header, &local_port, &remote_port);

  if (direction_in)
       trace_printf ("  addr: %s -> %s, ports: %s / %s",
                     remote_addr, local_addr, remote_port, local_port);

  else trace_printf ("  addr: %s -> %s, ports: %s / %s",
                     local_addr, remote_addr, local_port, remote_port);

  if (header->flags & FWPM_NET_EVENT_FLAG_REMOTE_ADDR_SET)
     print_country_location (NULL, (const struct in6_addr*)&header->remoteAddrV6);

  return (TRUE);
}

/*
 * Copied from dump.c:
 */
#define _IPPROTO_HOPOPTS               0
#define _IPPROTO_ICMP                  1
#define _IPPROTO_IGMP                  2
#define _IPPROTO_GGP                   3
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

#define ADD_PROTO(p)   { _##p, #p }

static const struct search_list protocols[] = {
                    ADD_PROTO (IPPROTO_ICMP),
                    ADD_PROTO (IPPROTO_IGMP),
                    ADD_PROTO (IPPROTO_TCP),
                    ADD_PROTO (IPPROTO_UDP),
                    ADD_PROTO (IPPROTO_ICMPV6),
                    ADD_PROTO (IPPROTO_RM),
                    ADD_PROTO (IPPROTO_RAW),
                    ADD_PROTO (IPPROTO_HOPOPTS),
                    ADD_PROTO (IPPROTO_GGP),
                    ADD_PROTO (IPPROTO_IPV4),
                    ADD_PROTO (IPPROTO_IPV6),
                    ADD_PROTO (IPPROTO_ST),
                    ADD_PROTO (IPPROTO_CBT),
                    ADD_PROTO (IPPROTO_EGP),
                    ADD_PROTO (IPPROTO_IGP),
                    ADD_PROTO (IPPROTO_PUP),
                    ADD_PROTO (IPPROTO_IDP),
                    ADD_PROTO (IPPROTO_RDP),
                    ADD_PROTO (IPPROTO_ROUTING),
                    ADD_PROTO (IPPROTO_FRAGMENT),
                    ADD_PROTO (IPPROTO_ESP),
                    ADD_PROTO (IPPROTO_AH),
                    ADD_PROTO (IPPROTO_DSTOPTS),
                    ADD_PROTO (IPPROTO_ND),
                    ADD_PROTO (IPPROTO_ICLFXBM),
                    ADD_PROTO (IPPROTO_PIM),
                    ADD_PROTO (IPPROTO_PGM),
                    ADD_PROTO (IPPROTO_L2TP),
                    ADD_PROTO (IPPROTO_SCTP),
                    ADD_PROTO (IPPROTO_RESERVED_IPSEC),
                    ADD_PROTO (IPPROTO_RESERVED_IPSECOFFLOAD),
                    ADD_PROTO (IPPROTO_RESERVED_WNV),
                    ADD_PROTO (IPPROTO_RAW),
                    ADD_PROTO (IPPROTO_RESERVED_RAW),
                    ADD_PROTO (IPPROTO_NONE),
                    ADD_PROTO (IPPROTO_RESERVED_IPSEC),
                    ADD_PROTO (IPPROTO_RESERVED_IPSECOFFLOAD),
                    ADD_PROTO (IPPROTO_RESERVED_WNV),
                    ADD_PROTO (IPPROTO_RESERVED_MAX)
                  };

static const char *get_protocol (UINT8 proto)
{
  return list_lookup_name (proto, protocols, DIM(protocols));
}

static void CALLBACK
  fw_event_callback (const UINT                             event_type,
                     const _FWPM_NET_EVENT_HEADER3         *header,
                     const _FWPM_NET_EVENT_CLASSIFY_DROP2  *drop_event,
                     const _FWPM_NET_EVENT_CLASSIFY_ALLOW0 *allow_event)
{
  #undef  ADD_VALUE
  #define ADD_VALUE(v)  { _FWPM_NET_EVENT_TYPE_##v, "FWPM_NET_EVENT_TYPE" #v }

  static const struct search_list events[] = {
                      ADD_VALUE (IKEEXT_MM_FAILURE),
                      ADD_VALUE (IKEEXT_QM_FAILURE),
                      ADD_VALUE (IKEEXT_EM_FAILURE),
                      ADD_VALUE (CLASSIFY_DROP),
                      ADD_VALUE (IPSEC_KERNEL_DROP),
                      ADD_VALUE (IPSEC_DOSP_DROP),
                      ADD_VALUE (CLASSIFY_ALLOW),
                      ADD_VALUE (CAPABILITY_DROP),
                      ADD_VALUE (CAPABILITY_ALLOW),
                      ADD_VALUE (CLASSIFY_DROP_MAC),
                      ADD_VALUE (LPM_PACKET_ARRIVAL),
                      ADD_VALUE (MAX)
                    };

  #undef  ADD_VALUE
  #define ADD_VALUE(v)  { v, #v }

  static const struct search_list ev_flags[] = {
                      ADD_VALUE (FWPM_NET_EVENT_FLAG_IP_PROTOCOL_SET),
                      ADD_VALUE (FWPM_NET_EVENT_FLAG_LOCAL_ADDR_SET),
                      ADD_VALUE (FWPM_NET_EVENT_FLAG_REMOTE_ADDR_SET),
                      ADD_VALUE (FWPM_NET_EVENT_FLAG_LOCAL_PORT_SET),
                      ADD_VALUE (FWPM_NET_EVENT_FLAG_REMOTE_PORT_SET),
                      ADD_VALUE (FWPM_NET_EVENT_FLAG_APP_ID_SET),
                      ADD_VALUE (FWPM_NET_EVENT_FLAG_USER_ID_SET),
                      ADD_VALUE (FWPM_NET_EVENT_FLAG_SCOPE_ID_SET),
                      ADD_VALUE (FWPM_NET_EVENT_FLAG_IP_VERSION_SET),
                      ADD_VALUE (FWPM_NET_EVENT_FLAG_REAUTH_REASON_SET),
                      ADD_VALUE (FWPM_NET_EVENT_FLAG_PACKAGE_ID_SET),
                      ADD_VALUE (FWPM_NET_EVENT_FLAG_ENTERPRISE_ID_SET),
                      ADD_VALUE (FWPM_NET_EVENT_FLAG_POLICY_FLAGS_SET),
                      ADD_VALUE (FWPM_NET_EVENT_FLAG_EFFECTIVE_NAME_SET)
       };

  static const struct search_list directions[] = {
                    { FWP_DIRECTION_IN,       "IN"  },
                    { FWP_DIRECTION_INBOUND,  "IN"  },
                    { FWP_DIRECTION_OUT,      "OUT" },
                    { FWP_DIRECTION_OUTBOUND, "OUT" }
                  };

  BOOL direction_in  = FALSE;
  BOOL direction_out = FALSE;
  BOOL printed;

  fw_num_events++;

  if (header->flags & FWPM_NET_EVENT_FLAG_IP_VERSION_SET)
  {
    if ( (header->ipVersion == FWP_IP_VERSION_V4 && !fw_show_ipv4) ||
         (header->ipVersion == FWP_IP_VERSION_V6 && !fw_show_ipv6) )
    {
      fw_num_ignored++;
      TRACE (2, "Ignoring IPv%d event.\n", header->ipVersion == FWP_IP_VERSION_V4 ? 4 : 6);
      return;
    }
  }

  trace_printf ("\n~1%s: ~4%s~0",
                get_time_string(&header->timeStamp),
                list_lookup_name(event_type, events, DIM(events)));

  if (event_type == _FWPM_NET_EVENT_TYPE_CLASSIFY_DROP)
  {
    if (drop_event->msFwpDirection == FWP_DIRECTION_IN ||
        drop_event->msFwpDirection == FWP_DIRECTION_INBOUND)
       direction_in = TRUE;
    else
    if (drop_event->msFwpDirection == FWP_DIRECTION_OUT ||
        drop_event->msFwpDirection == FWP_DIRECTION_OUTBOUND)
       direction_out = TRUE;

    if (direction_in || direction_out)
       trace_printf (", %s", list_lookup_name(drop_event->msFwpDirection, directions, DIM(directions)));

    if (header->flags & FWPM_NET_EVENT_FLAG_IP_PROTOCOL_SET)
         trace_printf (", %s\n", get_protocol(header->ipProtocol));
    else trace_putc ('\n');

    print_layer_item (drop_event, NULL);
    print_filter_rule (drop_event, NULL);
  }
  else if (event_type == _FWPM_NET_EVENT_TYPE_CLASSIFY_ALLOW)
  {
    if (allow_event->msFwpDirection == FWP_DIRECTION_IN ||
        allow_event->msFwpDirection == FWP_DIRECTION_INBOUND)
       direction_in = TRUE;
    else
    if (allow_event->msFwpDirection == FWP_DIRECTION_OUT ||
        allow_event->msFwpDirection == FWP_DIRECTION_OUTBOUND)
       direction_out = TRUE;

    if (direction_in || direction_out)
       trace_printf (", %s", list_lookup_name(allow_event->msFwpDirection, directions, DIM(directions)));

    if (header->flags & FWPM_NET_EVENT_FLAG_IP_PROTOCOL_SET)
         trace_printf (", %s\n", get_protocol(header->ipProtocol));
    else trace_putc ('\n');

    print_layer_item (NULL, allow_event);
    print_filter_rule (NULL, allow_event);
  }
  else if (event_type == _FWPM_NET_EVENT_TYPE_CAPABILITY_ALLOW)
  {
    if (header->flags & FWPM_NET_EVENT_FLAG_IP_PROTOCOL_SET)
       trace_printf (", %s\n", get_protocol(header->ipProtocol));

    print_layer_item (NULL, allow_event);
    print_filter_rule (NULL, allow_event);
  }
  else if (event_type == _FWPM_NET_EVENT_TYPE_CAPABILITY_DROP)
  {
    if (header->flags & FWPM_NET_EVENT_FLAG_IP_PROTOCOL_SET)
       trace_printf (", %s\n", get_protocol(header->ipProtocol));

    print_layer_item (drop_event, NULL);
    print_filter_rule (drop_event, NULL);
  }

  /* Print the local / remote addresses and ports for IPv4 / IPv6.
   * An event can only match IPv4 or IPv6 (or something else).
   */
  printed = print_addresses_ipv4 (header, direction_in);

  if (!printed)
      printed = print_addresses_ipv6 (header, direction_in);

  if (!printed && g_cfg.trace_level >= 1 && header->flags)
     trace_printf (", header->flags: %s", flags_decode(header->flags, ev_flags, DIM(ev_flags)));

  if (event_type == _FWPM_NET_EVENT_TYPE_CLASSIFY_ALLOW   ||
      event_type == _FWPM_NET_EVENT_TYPE_CAPABILITY_ALLOW ||
      event_type == _FWPM_NET_EVENT_TYPE_CLASSIFY_DROP    ||
      event_type == _FWPM_NET_EVENT_TYPE_CAPABILITY_DROP)
  {
    if ((header->flags & FWPM_NET_EVENT_FLAG_APP_ID_SET) &&
        header->appId.data && header->appId.size > 0)
      trace_printf ("\n  app:  %.*S",
                    header->appId.size,
                    /* cast from 'UINT8' to 'wchar_t*' to shut up gcc */
                    (const wchar_t*)header->appId.data);
  }

  trace_putc ('\n');
}

void fw_print_statistics (FWPM_STATISTICS *stats)
{
  if (fw_num_events > 0UL || fw_num_ignored > 0UL)
     trace_printf ("Got %lu events, %lu ignored.\n", fw_num_events, fw_num_ignored);
  ARGSUSED (stats);
}

/*
 * Return text of FWP_E_* error codes in range 0x80320001 - 0x80320039 and
 * RPC_* error codes in range 0x80010001 - 0x80010122.
 *
 * win_strerror() works for these ranges too.
 */
const char *fw_strerror (DWORD err)
{
  return win_strerror (err);
}

#if defined(TEST_FIREWALL)

#include <signal.h>
#include <locale.h>
#include "getopt.h"

/* For getopt.c.
 */
const char *program_name = "firewall_test.exe";
static int  quit;

static char *set_net_program (int argc, char **argv)
{
  char   *prog = NULL;
  size_t len, i;

  for (i = len = 0; i < (size_t)argc; i++)
      len += strlen (argv[i]) + 2;

  if (len > 0)
  {
    prog = malloc (len+1);
    *prog = '\0';
    for (i = 0; i < (size_t)argc; i++)
    {
      strcat (prog, argv[i]);
      if (i < (size_t)(argc-1))
         strcat (prog, " ");
    }
  }
  return (prog);
}

static int show_help (const char *my_name)
{
  printf ("Simple Windows ICF Firewall monitor test program.\n"
          "  Usage: %s [options] [program]\n"
          "  options:\n"
          "    -a:  the minimum API \"level\" to try (=%d-%d, default: %d).\n"
          "    -c:  only dump the callout rules                            (not yet).\n"
          "    -d:  debug level.\n"
          "    -e:  only dump recent event                                 (not yet).\n"
          "    -l:  also write the filter activity to \"log-file\"           (not yet).\n"
          "    -p:  show only activity for programs matching \"app1,app2..\" (not yet).\n"
          "    -r:  only dump the firewall rules.\n"
          "    -4:  show IPv4 filter activity.\n"
          "    -6:  show IPv6 filter activity (use \"-46\" to show both).\n"
          "\n"
          "  program: the program (and arguments) to test Firewall activity with.\n"
          "    Examples:\n"
          "      pause\n"
          "      ping -n 10 www.google.com\n"
          "      wget -d -o- -O NUL www.vg.no\n",
          my_name, FW_API_LOW, FW_API_HIGH, FW_API_DEFAULT);
  return (0);
}

static void sig_handler (int sig)
{
  quit = 1;
  trace_puts ("~1Quitting.~0\n");
  (void) sig;
}

int main (int argc, char **argv)
{
  int     ch, rc = 0;
  int     dump_rules = 0;
  int     dump_callouts = 0;
  int     dump_events = 0;
  int     debug_level = 0;
  char   *program;
  char   *only_appid = NULL;   /* \todo Capture 'appId' matching program(s) only. Support a list of 'appId's */
  char   *ignore_appid = NULL; /* \todo Ignore 'appId' matching program(s). Support a list of 'appId's */
  WSADATA wsa;
  WORD    ver = MAKEWORD(1,1);

  wsock_trace_init();
  geoip_exit();

  g_cfg.trace_use_ods = g_cfg.DNSBL.test = FALSE;
  g_cfg.trace_level   = 0;
  g_cfg.trace_indent  = 0;

  fw_show_ipv4 = fw_show_ipv6 = FALSE;
  setlocale (LC_CTYPE, "");
  tzset();

  while ((ch = getopt(argc, argv, "a:h?cdep:r46")) != EOF)
    switch (ch)
    {
      case 'a':
           fw_lowest_api = atoi (optarg);
           break;
      case 'd':
           debug_level++;
           break;
      case 'c':
           dump_callouts = 1;
           break;
      case 'e':
           dump_events = 1;
           break;
      case 'i':
           ignore_appid = strdup (optarg);
           break;
      case 'p':
           only_appid = strdup (optarg);
           break;
      case 'r':
           dump_rules = 1;
           break;
      case '4':
           fw_show_ipv4 = TRUE;
           break;
      case '6':
           fw_show_ipv6 = TRUE;
           break;
      case '?':
      case 'h':
           return show_help (argv[0]);
    }

  g_cfg.geoip_use_generated = TRUE;
  g_cfg.trace_level = debug_level;

  if (fw_show_ipv4)
     geoip_load_data (AF_INET);

  if (fw_show_ipv6)
     geoip_load_data (AF_INET6);

  ip2loc_init();

  program = set_net_program (argc - optind, argv + optind);

  /* Because we use `getservbyport()` above, we need to call `WSAStartup()` too.
   */
  if (WSAStartup(ver, &wsa) != 0 || wsa.wVersion < ver)
  {
    printf ("Winsock init failed; code %s\n", win_strerror(GetLastError()));
    goto quit;
  }

  if (dump_rules || dump_callouts || dump_events)
  {
    if (!fw_init())
    {
      TRACE (0, "fw_init() failed: %s\n", win_strerror(fw_errno));
      goto quit;
    }
    if (dump_rules)
       fw_enumerate_rules (FW_PROFILE_TYPE_CURRENT, FW_DIR_BOTH, fw_dump_rules);

    if (dump_events)
       fw_dump_events();

    if (dump_callouts)
       fw_enumerate_callouts();
    goto quit;
  }

  if (!fw_monitor_start())
  {
    TRACE (0, "fw_monitor_start() failed: %s\n", win_strerror(fw_errno));
    goto quit;
  }

  signal (SIGINT, sig_handler);

  trace_printf ("Executing ~1%s~0 while listening for %sFilter events.\n",
                program ? program : "no program",
                fw_show_ipv4 &&  fw_show_ipv6 ? "IPv4/6 " :
                fw_show_ipv4 && !fw_show_ipv6 ? "IPv4 "  :
               !fw_show_ipv4 &&  fw_show_ipv6 ? "IPv6 "  : "non-IPv4/IPv6 ");

  if (program)
  {
    char  p_buf [1000];
    FILE *p = _popen (program, "rb");

    if (p)
    {
      while (fgets(p_buf,sizeof(p_buf)-1,p) && !quit)
      {
        trace_printf ("~1program: %s~0", p_buf);
        trace_flush();
      }
      _pclose (p);
      fw_print_statistics (NULL);
    }
    else
      TRACE (0, "_popen() failed, errno %d\n", errno);
  }

quit:
  free (program);
  free (only_appid);
  free (ignore_appid);
  fw_monitor_stop();
  fw_exit();

  wsock_trace_exit();
  return (rc);
}
#endif  /* TEST_FIREWALL */
