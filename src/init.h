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

struct pcap_cfg {
       BOOL    enable;
       char   *dump_fname;
       FILE   *dump_stream;
     };

struct lua_cfg {
       BOOL    enable;
       int     trace_level;
       WORD    color_head;
       WORD    color_body;

       /*
        * Path-names for the Lua init/exit script-files.
        * These are effective only if built with 'USE_LUA'.
        */
       char   *init_script;
       char   *exit_script;
     };

struct config_table {
       char   *trace_file;
       FILE   *trace_stream;
       BOOL    trace_binmode;
       BOOL    trace_caller;
       BOOL    trace_report;
       BOOL    trace_file_okay;
       BOOL    trace_file_device;
       BOOL    trace_use_ods;
       int     trace_level;
       int     trace_overlap;
       int     trace_indent;
       int     trace_max_len;
       int     line_buffered;
       int     show_caller;
       int     callee_level;
       int     cpp_demangle;
       int     max_data;
       int     max_displacement;
       BOOL    use_sema;
       BOOL    test_trace;
       BOOL    start_new_line;
       BOOL    dump_data;
       BOOL    dump_select;
       BOOL    dump_nameinfo;
       BOOL    dump_hostent;
       BOOL    dump_servent;
       BOOL    dump_protoent;
       BOOL    dump_wsaprotocol_info;
       BOOL    dump_wsanetwork_events;
       BOOL    dump_modules;
       BOOL    compact;
       BOOL    short_errors;
       BOOL    use_full_path;
       BOOL    use_toolhlp32;
       BOOL    use_ole32;
       BOOL    pdb_report;
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

       BOOL    geoip_enable;
       BOOL    geoip_use_generated;
       int     geoip_max_days;
       char   *geoip4_file;
       char   *geoip6_file;
       char   *geoip4_url;
       char   *geoip6_url;
       char   *ip2location_bin_file;
       char   *hosts_file;
       char   *geoip_proxy;

       BOOL    idna_enable;
       BOOL    idna_winidn;
       UINT    idna_cp;

       BOOL    msvc_only;
       BOOL    mingw_only;
       BOOL    cygwin_only;
       BOOL    stealth_mode;
       BOOL    no_buffering;
       BOOL    stdout_redirected;
       WORD    screen_width;
       WORD    screen_heigth;

       struct lua_cfg     lua;
       struct pcap_cfg    pcap;
       struct statistics  counts;
       DWORD  reentries;

       TS_TYPE    trace_time_format;
       uint64     start_ticks;
       uint64     clocks_per_usec;
     };

extern struct config_table g_cfg;
extern int                 fatal_error;

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

extern void set_color (const WORD *col);
extern void get_color (const char *str, WORD *col);
extern int  get_column (void);

extern void init_ptr (const void **ptr, const char *ptr_name);

extern BOOL exclude_list_add (const char *name);
extern BOOL exclude_list_get (const char *fmt);
extern BOOL exclude_list_free (void);

extern const char *config_file_name (void);
extern const char *get_timestamp (void);
extern const char *get_timestamp2 (void);

extern uint64 FILETIME_to_unix_epoch (const FILETIME *ft);
extern time_t FILETIME_to_time_t     (const FILETIME *ft);

extern size_t write_pcap_header  (void);
extern size_t write_pcap_packet  (SOCKET s, const void *pkt, size_t len, BOOL out);
extern size_t write_pcap_packetv (SOCKET s, const WSABUF *bufs, DWORD num_bufs, BOOL out);

extern CRITICAL_SECTION crit_sect;

#define ENTER_CRIT()    EnterCriticalSection (&crit_sect)
#define LEAVE_CRIT()    LeaveCriticalSection (&crit_sect)

#endif


