/**\file    firewall.h
 * \ingroup Misc
 */
#ifndef _FIREWALL_H
#define _FIREWALL_H

extern void        fw_report (void);
extern BOOL        fw_enumerate_callouts (void);
extern BOOL        fw_monitor_start (void);
extern void        fw_monitor_stop (BOOL force);
extern const char *fw_strerror (DWORD err);
extern void        fw_warning_sound (void);

#endif /* _FIREWALL_H */


