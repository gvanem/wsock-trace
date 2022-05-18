/**\file    init.h
 * \ingroup Main
 */
#ifndef _INIT_H
#define _INIT_H

typedef unsigned __int64 uint64;
typedef          __int64 int64;

struct statistics {
       uint64  send_bytes;
       uint64  send_errors;

       uint64  recv_bytes;
       uint64  recv_peeked;
       uint64  recv_errors;
       uint64  recv_EWOULDBLOCK;

       uint64  connects;
       uint64  connect_EWOULDBLOCK;
       uint64  dll_attach;
       uint64  dll_detach;
       uint64  sema_waits;
     };

typedef enum TS_TYPE {  /* Time-Stamp enum type */
        TS_NONE,
        TS_ABSOLUTE,
        TS_RELATIVE,
        TS_DELTA,
      } TS_TYPE;

struct PCAP_cfg {
       BOOL    enable;
       char   *dump_fname;
       FILE   *dump_stream;
     };

struct LUA_cfg {
       BOOL    enable;
       BOOL    profile;
       int     trace_level;
       WORD    color_head;
       WORD    color_body;

       /*
        * Path-names for the LuaJIT init/exit script-files.
        * These are effective only if built with 'USE_LUAJIT'.
        */
       char   *init_script;
       char   *exit_script;
     };

struct DNSBL_cfg {
       BOOL    enable;
       char   *drop_file;
       char   *edrop_file;
       char   *dropv6_file;
       char   *drop_url;
       char   *edrop_url;
       char   *dropv6_url;
       int     max_days;
     };

struct IANA_cfg {
       BOOL    enable;
       char   *ip4_file;
       char   *ip6_file;
     };

struct ASN_cfg {
       BOOL    enable;
       char   *asn_csv_file;
       char   *asn_bin_file;
       char   *asn_bin_url;
       int     max_days;
       int     xz_decompress;
    };

struct IDNA_cfg {
       BOOL    enable;
       BOOL    use_winidn;
       BOOL    fix_getaddrinfo;
       UINT    codepage;
     };

struct GEOIP_cfg {
       BOOL    enable;
       BOOL    show_position;
       BOOL    show_map_url;
       BOOL    openstreetmap;
       UINT    map_zoom;
       int     max_days;
       char   *ip4_file;
       char   *ip6_file;
       char   *ip4_url;
       char   *ip6_url;
       char   *ip2location_bin_file;
       char   *proxy;
     };

typedef struct FREQ_MILLISEC {
        unsigned  frequency;
        unsigned  milli_sec;
      } FREQ_MILLISEC;

struct FIREWALL_cfg {
       BOOL    enable;
       BOOL    show_ipv4;
       BOOL    show_ipv6;
       BOOL    show_all;
       BOOL    show_user;
       BOOL    console_title;
       int     api_level;

       struct {
         BOOL enable;
         struct {
           FREQ_MILLISEC  event_allow;
           FREQ_MILLISEC  event_drop;
           FREQ_MILLISEC  event_DNSBL;
         } beep;
       } sound;
     };

struct config_table {
       char   *trace_file;
       FILE   *trace_stream;
       char   *hosts_file [3+1];     /* Handle loading of 3 hosts files */
       int     num_hosts_files;
       char   *services_file [3+1];  /* Handle loading of 3 services files */
       int     num_services_files;
       BOOL    trace_binmode;
       BOOL    trace_caller;
       BOOL    trace_report;
       BOOL    trace_file_okay;
       BOOL    trace_file_device;
       BOOL    trace_file_commit;
       BOOL    trace_use_ods;
       BOOL    trace_raw;
       int     trace_level;
       int     trace_overlap;
       int     trace_indent;
       int     trace_max_len;
       int     line_buffered;
       BOOL    show_tid;
       BOOL    show_caller;
       int     callee_level;
       int     cpp_demangle;
       int     max_data;
       UINT    max_fd_sets;
       int     max_displacement;
       BOOL    use_sema;
       BOOL    start_new_line;
       BOOL    extra_new_line;
       BOOL    dump_data;
       BOOL    dump_select;
       BOOL    dump_nameinfo;
       BOOL    dump_addrinfo;
       BOOL    dump_hostent;
       BOOL    dump_servent;
       BOOL    dump_protoent;
       BOOL    dump_wsaprotocol_info;
       BOOL    dump_wsanetwork_events;
       BOOL    dump_namespace_providers;
       BOOL    dump_modules;
       BOOL    dump_tcpinfo;
       BOOL    compact;
       BOOL    short_errors;
       BOOL    use_full_path;
       BOOL    use_short_path;
       BOOL    use_toolhlp32;
       BOOL    use_ole32;
       BOOL    pdb_report;
       BOOL    pdb_symsrv;
       BOOL    hook_extensions;
       DWORD   recv_delay;
       DWORD   send_delay;
       DWORD   select_delay;
       DWORD   poll_delay;
       WORD    color_file;
       WORD    color_time;
       WORD    color_func;
       WORD    color_trace;
       WORD    color_data;

       BOOL    nice_numbers;
       BOOL    use_winhttp;
       BOOL    msvc_only;
       BOOL    mingw_only;
       BOOL    cygwin_only;
       BOOL    stealth_mode;
       BOOL    no_buffering;
       BOOL    stdout_redirected;
       WORD    screen_width;
       WORD    screen_heigth;
       DWORD   reentries;

       TS_TYPE trace_time_format;
       BOOL    trace_time_usec;
       uint64  start_ticks;
       uint64  clocks_per_usec;

       struct LUA_cfg      LUA;
       struct PCAP_cfg     PCAP;
       struct DNSBL_cfg    DNSBL;
       struct IANA_cfg     IANA;
       struct IDNA_cfg     IDNA;
       struct ASN_cfg      ASN;
       struct GEOIP_cfg    GEOIP;
       struct FIREWALL_cfg FIREWALL;
       struct statistics   counts;
     };

extern struct config_table g_cfg;
extern int                 fatal_error;

extern DWORD       ws_Tls_index;
extern BOOL        ws_from_dll_main;
extern HANDLE      ws_sema;
extern BOOL        ws_sema_inherited;
extern const char *ws_sema_name;

extern CONSOLE_SCREEN_BUFFER_INFO console_info;

extern void wsock_trace_init (void);
extern void wsock_trace_exit (void);
extern void crtdbg_init (void);
extern void crtdbg_exit (void);
extern void ws_sema_wait (void);
extern void ws_sema_release (void);

extern WORD set_color (const WORD *col);
extern void get_color (const char *str, WORD *col);
extern int  get_column (void);

extern void check_ptr (const void **ptr, const char *ptr_name);

typedef enum exclude_type {
        EXCL_NONE     = 0x00,
        EXCL_FUNCTION = 0x01,
        EXCL_PROGRAM  = 0x02,
        EXCL_ADDRESS  = 0x04,
      } exclude_type;

extern BOOL exclude_list_add (const char *name, unsigned exclude_which);
extern BOOL exclude_list_get (const char *fmt, unsigned exclude_which);
extern BOOL exclude_list_free (void);

extern const char *config_file_name (void);
extern const char *get_timestamp (void);
extern double      get_timestamp_now (void);
extern const char *get_date_str (const SYSTEMTIME *st);
extern const char *get_time_now (void);

extern double FILETIME_to_sec        (const FILETIME *ft);
extern int64  FILETIME_to_usec       (const FILETIME *ft);
extern uint64 FILETIME_to_unix_epoch (const FILETIME *ft);
extern time_t FILETIME_to_time_t     (const FILETIME *ft);

extern size_t write_pcap_header  (void);
extern size_t write_pcap_packet  (SOCKET s, const void *pkt, size_t len, BOOL out);
extern size_t write_pcap_packetv (SOCKET s, const WSABUF *bufs, DWORD num_bufs, BOOL out);

extern CRITICAL_SECTION crit_sect;

#define ENTER_CRIT()           EnterCriticalSection (&crit_sect)
#define LEAVE_CRIT(extra_nl)   do {                                    \
                                 if (extra_nl && g_cfg.extra_new_line) \
                                    C_putc ('\n');                     \
                                 LeaveCriticalSection (&crit_sect);    \
                               } while (0)
#endif


