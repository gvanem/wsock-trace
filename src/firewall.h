/**\file    firewall.h
 * \ingroup Misc
 */
#ifndef _FIREWALL_H
#define _FIREWALL_H

extern BOOL        fw_init (void);
extern void        fw_exit (void);
extern void        fw_report (void);
extern BOOL        fw_enumerate_callouts (void);
extern BOOL        fw_monitor_start (void);
extern void        fw_monitor_stop (BOOL force);
extern const char *fw_strerror (DWORD err);

#endif /* _FIREWALL_H */


