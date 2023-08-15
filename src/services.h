/**\file    services.h
 * \ingroup inet_util
 */
#ifndef _SERVICES_H
#define _SERVICES_H

extern void services_file_init (void);
extern void services_file_exit (void);

extern const struct servent *ws_getservbyport (uint16_t    port,
                                               const char *proto,
                                               bool        fallback,
                                               bool        do_wstrace);

#endif
