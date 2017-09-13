#ifndef _HOSTS_H
#define _HOSTS_H

extern void hosts_file_init  (void);
extern void hosts_file_exit  (void);
extern int  hosts_file_check (const char *name, const struct hostent *host);

#endif
