/**\file    hosts.h
 * \ingroup inet_util
 */
#ifndef _HOSTS_H
#define _HOSTS_H

extern void hosts_file_init  (void);
extern void hosts_file_exit  (void);
extern int  hosts_file_check_hostent  (const char *name, const struct hostent *he);
extern int  hosts_file_check_addrinfo (const char *name, const struct addrinfo *ai);

#endif
