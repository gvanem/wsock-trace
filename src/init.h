#ifndef _INIT_H
#define _INIT_H

#define MAX_EXCLUDES 100

typedef unsigned __int64 uint64;
typedef          __int64 int64;

struct exclude {
       char    *name;          /* name of function to exclude from the trace */
       unsigned num_excludes;  /* # of times this function was excluded */
     };

struct excludes {
       unsigned       list_max;
       struct exclude func [MAX_EXCLUDES];
     };

struct statistics {
       uint64  recv_bytes;
       uint64  recv_peeked;
       uint64  send_bytes;
       uint64  recv_errors;
       uint64  send_errors;
       uint64  dll_attach;
       uint64  dll_detach;
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
       int     trace_indent;
       int     trace_max_len;
       int     line_buffered;
       int     show_caller;
       int     callee_level;
       int     cpp_demangle;
       int     max_data;
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
       BOOL    compact;
       BOOL    short_errors;
       BOOL    use_full_path;
       BOOL    use_toolhlp32;
       BOOL    use_ole32;
       WORD    color_file;
       WORD    color_time;
       WORD    color_func;
       WORD    color_trace;
       WORD    color_data;

       BOOL    msvc_only;
       BOOL    mingw_only;
       BOOL    stealth_mode;
       BOOL    no_buffering;
       BOOL    stdout_redirected;
       WORD    screen_width;
       WORD    screen_heigth;

       struct pcap_cfg    pcap;
       struct excludes    excl;
       struct statistics  counts;
       DWORD  reentries;

       TS_TYPE    trace_time_format;
       SYSTEMTIME start_time;
       uint64     start_ticks;
       uint64     clocks_per_usec;
     };

extern struct config_table g_cfg;
extern int    fatal_error;

extern CONSOLE_SCREEN_BUFFER_INFO console_info;

extern void wsock_trace_init (void);
extern void wsock_trace_exit (void);
extern void crtdbg_init (void);
extern void crtdbg_exit (void);

extern void set_color (const WORD *col);
extern void get_color (const char *str, WORD *col);
extern int  get_column (void);

extern void init_ptr (const void **ptr, const char *ptr_name);

extern BOOL exclude_list_add (const char *name);
extern BOOL exclude_list_get (const char *fmt);
extern BOOL exclude_list_free (void);

extern size_t write_pcap_header (void);
extern size_t write_pcap_packet (const void *pkt, size_t len, BOOL out);

extern CRITICAL_SECTION crit_sect;

#define ENTER_CRIT()    EnterCriticalSection (&crit_sect)
#define LEAVE_CRIT()    LeaveCriticalSection (&crit_sect)

#endif


