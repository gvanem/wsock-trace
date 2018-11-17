/**\file    firewall.h
 * \ingroup inet_util
 */
#ifndef _FIREWALL_H
#define _FIREWALL_H

extern BOOL        fw_init (void);
extern void        fw_exit (void);
extern BOOL        fw_monitor_start (void);
extern void        fw_monitor_stop (void);
extern const char *fw_strerror (DWORD err);

#endif /* _FIREWALL_H */


