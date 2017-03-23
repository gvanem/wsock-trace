#ifndef _DUMP_H
#define _DUMP_H

extern void    check_all_search_lists (void);
extern fd_set *copy_fd_set (const fd_set *fd);

extern void dump_addrinfo  (const struct addrinfo *ai);
extern void dump_data      (const void *data_p, unsigned data_len);
extern void dump_wsabuf    (const WSABUF *bufs, DWORD num_bufs);

extern void dump_hostent   (const struct hostent *h);
extern void dump_servent   (const struct servent *s);
extern void dump_protoent  (const struct protoent *p);
extern void dump_nameinfo  (const char *host, const char *serv, DWORD flags);
extern void dump_select    (const fd_set *rd, const fd_set *wr, const fd_set *ex, int indent);
extern void dump_wsapollfd (const WSAPOLLFD *fd_array, ULONG fds, int indent);

extern void dump_wsaprotocol_info (char ascii_or_wide, const void *proto_info, const void *provider_path_func);
extern void dump_events           (const WSANETWORKEVENTS *events);
extern void dump_extension_funcs  (const GUID *guid, const void *out_buf);

extern void dump_countries          (int type, const char **addresses);
extern void dump_countries_sockaddr (const struct sockaddr *sa);
extern void dump_countries_addrinfo (const struct addrinfo *ai);

extern const char *socket_family (int family);
extern const char *socket_type (int type);
extern const char *socket_flags (int flags);
extern const char *socklevel_name (int level);
extern const char *sockopt_name (int level, int opt);
extern const char *sockopt_value (const char *opt_val, int opt_len);
extern const char *protocol_name (int proto);
extern const char *ioctlsocket_cmd_name (long cmd);

extern const char *wsasocket_flags_decode (int flags);
extern const char *ai_flags_decode (int flags);
extern const char *getnameinfo_flags_decode (int flags);
extern const char *event_bits_decode (long flag);
extern const char *get_sio_name (DWORD code);
extern const char *get_addrinfo_hint (const struct addrinfo *hint, size_t indent);

#endif
