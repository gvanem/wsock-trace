/**\file    firewall.h
 * \ingroup Misc
 */
#ifndef _FIREWALL_H
#define _FIREWALL_H

extern void        fw_report (void);
extern bool        fw_enumerate_callouts (void);
extern bool        fw_monitor_start (void);
extern void        fw_monitor_stop (bool force);
extern const char *fw_strerror (DWORD err);
extern void        fw_warning_sound (void);

#endif /* _FIREWALL_H */


