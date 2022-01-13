/**\file    services.h
 * \ingroup inet_util
 */
#ifndef _SERVICES_H
#define _SERVICES_H

extern void services_file_init  (void);
extern void services_file_exit  (void);
extern int  services_file_check_hostent   (const char *name, const struct servent *he);
extern int  services_file_check_addrinfo  (const char *name, const struct addrinfo *ai);
extern int  services_file_check_addrinfoW (const wchar_t *name, const struct addrinfoW *aiW);

extern const struct servent *ws_getservbyport (uint16_t    port,
                                               const char *proto,
                                               BOOL        fallback);

#endif
