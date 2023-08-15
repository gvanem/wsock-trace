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
       bool    enable;
       char   *dump_fname;
       FILE   *dump_stream;
     };

struct LUA_cfg {
       bool    enable;
       bool    profile;
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
       bool    enable;
       char   *drop_file;
       char   *edrop_file;
       char   *dropv6_file;
       char   *drop_url;
       char   *edrop_url;
       char   *dropv6_url;
       int     max_days;
     };

struct IANA_cfg {
       bool    enable;
       char   *ip4_file;
       char   *ip6_file;
     };

struct ASN_cfg {
       bool    enable;
       char   *asn_csv_file;
       char   *asn_bin_file;
       char   *asn_bin_url;
       int     max_days;
       int     xz_decompress;
    };

struct IDNA_cfg {
       bool    enable;
       bool    use_winidn;
       bool    fix_getaddrinfo;
       UINT    codepage;
     };

struct GEOIP_cfg {
       bool    enable;
       bool    show_position;
       bool    show_map_url;
       bool    openstreetmap;
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
       bool    enable;
       bool    show_ipv4;
       bool    show_ipv6;
       bool    show_all;
       bool    show_user;
       bool    console_title;
       int     api_level;

       struct {
         bool enable;
         struct {
           FREQ_MILLISEC  event_allow;
           FREQ_MILLISEC  event_drop;
           FREQ_MILLISEC  event_DNSBL;
         } beep;
       } sound;
     };

/**
 * Keep ALL user-configurable data to this structure:
 */
struct config_table {
       char   *trace_file;
       FILE   *trace_stream;
       char   *hosts_file [3+1];     /* Handle loading of 3 hosts files */
       int     num_hosts_files;
       char   *services_file [3+1];  /* Handle loading of 3 services files */
       int     num_services_files;
       bool    trace_binmode;
       bool    trace_caller;
       bool    trace_report;
       bool    trace_file_okay;
       bool    trace_file_device;
       bool    trace_file_commit;
       bool    trace_use_ods;
       int     trace_level;
       int     trace_overlap;
       int     trace_indent;
       int     trace_max_len;
       int     line_buffered;
       bool    show_tid;
       bool    show_caller;
       int     callee_level;
       int     cpp_demangle;
       int     max_data;
       UINT    max_fd_sets;
       int     max_displacement;
       bool    use_sema;
       bool    start_new_line;
       bool    extra_new_line;
       bool    dump_data;
       bool    dump_select;
       bool    dump_nameinfo;
       bool    dump_addrinfo;
       bool    dump_hostent;
       bool    dump_servent;
       bool    dump_protoent;
       bool    dump_wsaprotocol_info;
       bool    dump_wsanetwork_events;
       bool    dump_namespace_providers;
       bool    dump_modules;
       bool    dump_tcpinfo;
       bool    dump_icmp_info;
       bool    compact;
       bool    short_errors;
       bool    use_full_path;
       bool    use_short_path;
       bool    use_toolhlp32;
       bool    use_ole32;
       bool    pdb_report;
       bool    pdb_symsrv;
       bool    hook_extensions;
       DWORD   recv_delay;
       DWORD   send_delay;
       DWORD   select_delay;
       DWORD   poll_delay;
       WORD    color_file;
       WORD    color_time;
       WORD    color_func;
       WORD    color_trace;
       WORD    color_data;
       bool    nice_numbers;
       bool    msvc_only;
       bool    mingw_only;
       bool    cygwin_only;
       bool    no_buffering;
       bool    no_inv_handler;
       TS_TYPE trace_time_format;
       bool    trace_time_usec;

       struct LUA_cfg      LUA;
       struct PCAP_cfg     PCAP;
       struct DNSBL_cfg    DNSBL;
       struct IANA_cfg     IANA;
       struct IDNA_cfg     IDNA;
       struct ASN_cfg      ASN;
       struct GEOIP_cfg    GEOIP;
       struct FIREWALL_cfg FIREWALL;
     };

extern struct config_table g_cfg;

/**
 * Keep ALL other global data to this structure:
 */
struct global_data {
       bool                       fatal_error;
       bool                       trace_raw;
       bool                       ws_from_dll_main;          /**< We're called via DllMain() */
       DWORD                      ws_Tls_index;              /**< *Thread Local Storage* index */
       HANDLE                     ws_sema;                   /**< Handle of global semaphore */
       bool                       ws_sema_inherited;         /**< Semaphore was inherited from another running instance */
       const char                *ws_sema_name;              /**< Name of global semaphore; `"Global\\wsock_trace-semaphore"` */
       uint64                     start_ticks;               /**< Absolute start-time from `QueryPerformanceCounter()` */
       uint64                     clocks_per_usec;           /**< Clocks per usec from `QueryPerformanceFrequency()` */
       CRITICAL_SECTION           crit_sect;                 /**< Global critical section */
       HANDLE                     console_hnd;               /**< Console handle */
       CONSOLE_SCREEN_BUFFER_INFO console_info;              /**< Console information (unless redirected) */
       bool                       stealth_mode;              /**< Not used */
       bool                       stdout_redirected;         /**< Trace is redirected to a file */
       WORD                       screen_width;              /**< Max width of the screen to use */
       WORD                       screen_heigth;             /**< The height of the screen (not used) */
       DWORD                      reentries;                 /**< Reentries in get_caller()`; fatal */
       uintptr_t                  dummy_reg;                 /**< For some `REG_x()` macros */
       bool                       use_win_locale;            /**< Currently alway false */
       char                      *program_name;              /**< For getopt.c filled by `set_program_name()` */
       char                       curr_dir  [_MAX_PATH];     /**< Current working directory */
       char                       curr_prog [_MAX_PATH];     /**< Current running program */
       char                       prog_dir  [_MAX_PATH];     /**< And it's program directory */
       char                       full_name [_MAX_PATH];     /**< Full name of program that loaded `wsock_trace.dll` */
       char                       cfg_fname [_MAX_PATH];     /**< Full name of `wsock_trace` config-file */
       HINSTANCE                  ws_trace_base;             /**< Our base-address */
       void (__stdcall           *WSASetLastError) (int);    /**< Dummy WSA* functions */
       int  (__stdcall           *WSAGetLastError) (void);
       struct statistics          counts;                    /**< Statistics counters */
     };

extern struct global_data g_data;

extern void wsock_trace_init (void);
extern void wsock_trace_exit (void);
extern void crtdbg_init (void);
extern void crtdbg_exit (void);
extern void ws_sema_wait (void);
extern void ws_sema_release (void);

#if defined(USE_LWIP)
  extern void ws_lwip_init (void);
#endif

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

extern bool exclude_list_add (const char *name, unsigned exclude_which);
extern bool exclude_list_get (const char *fmt, unsigned exclude_which);
extern bool exclude_list_free (void);

extern const char *get_timestamp (void);
extern double      get_timestamp_now (void);
extern const char *get_date_str (const SYSTEMTIME *st);
extern const char *get_time_now (void);

extern double FILETIME_to_sec        (const FILETIME *ft);
extern int64  FILETIME_to_usec       (const FILETIME *ft);
extern uint64 FILETIME_to_unix_epoch (const FILETIME *ft);
extern time_t FILETIME_to_time_t     (const FILETIME *ft);

extern size_t write_pcap_header  (void);
extern size_t write_pcap_packet  (SOCKET s, const void *pkt, size_t len, bool out);
extern size_t write_pcap_packetv (SOCKET s, const WSABUF *bufs, DWORD num_bufs, bool out);

#define ENTER_CRIT()           EnterCriticalSection (&g_data.crit_sect)
#define LEAVE_CRIT(extra_nl)   do {                                        \
                                 if (extra_nl && g_cfg.extra_new_line)     \
                                    C_putc ('\n');                         \
                                 LeaveCriticalSection (&g_data.crit_sect); \
                               } while (0)
#endif


