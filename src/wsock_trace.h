/**\file    wsock_trace.h
 * \ingroup Main
 */
#ifndef _WSOCK_TRACE_H
#define _WSOCK_TRACE_H

extern int volatile cleaned_up;
extern int volatile startup_count;

extern void                    load_ws2_funcs (void);
extern const struct LoadTable *find_ws2_func_by_name (const char *func);

#define WSAERROR_PUSH()  WSAError_save_restore (0)
#define WSAERROR_POP()   WSAError_save_restore (1)

extern int WSAError_save_restore (int pop);

extern const char *sockaddr_str      (const struct sockaddr *sa, const int *sa_len);
extern const char *sockaddr_str2     (const struct sockaddr *sa, const int *sa_len);
extern const char *sockaddr_str_port (const struct sockaddr *sa);

#endif
