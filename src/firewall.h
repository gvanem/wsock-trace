/**\file    firewall.h
 * \ingroup inet_util
 */
#ifndef _FIREWALL_H
#define _FIREWALL_H

#if defined(__WATCOMC__)
  /*
   * OpenWatcom 2.x is hardly able to compile and use anything in firewall.c.
   */
  #define fw_init()           FALSE
  #define fw_exit()           (void)0
  #define fw_monitor_start()  FALSE
  #define fw_monitor_stop()   (void)0
  #define fw_strerror(err)    NULL

#else
  extern BOOL        fw_init (void);
  extern void        fw_exit (void);
  extern BOOL        fw_monitor_start (void);
  extern void        fw_monitor_stop (void);
  extern const char *fw_strerror (DWORD err);
#endif

#endif /* _FIREWALL_H */


