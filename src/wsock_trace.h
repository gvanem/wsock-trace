#ifndef _WSOCK_TRACE_H
#define _WSOCK_TRACE_H

extern int volatile cleaned_up;
extern int volatile startup_count;

extern void              load_ws2_funcs (void);
extern struct LoadTable *find_ws2_func_by_name (const char *func);

extern const char *sockaddr_str (const struct sockaddr *sa, const int *sa_len);
extern const char *sockaddr_str_port (const struct sockaddr *sa, const int *sa_len);

#endif
