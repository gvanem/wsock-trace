/**
 * \file wsock_trace_lwip.c
 *
 * \brief A preliminary lwIP interface for WSock-Trace.
 *        It does nothing at the moment. But the idea is to
 *        make it possible to switch network stacks at run-time.
 */
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

#if defined(USE_LWIP)  /* Rest of file */

#include "common.h"
#include "init.h"

/* Redeclared in '$(LWIP_ROOT)/contrib/ports/win32/cfg_file.h'
 */
#undef ENTER_CRIT
#undef LEAVE_CRIT

#include <lwip/init.h>
#include <lwip/netif.h>
#include <lwip/tcpip.h>
#include <contrib/ports/win32/pcapif.h>
#include <contrib/ports/win32/cfg_file.h>

static struct netif netif;

void ws_lwip_init (void)
{
  ip4_addr_t ipaddr, netmask, gw;

  lwip_cfg_init();
  lwip_init();

  ip4_addr_set_zero (&gw);
  ip4_addr_set_zero (&ipaddr);
  ip4_addr_set_zero (&netmask);

  #if NO_SYS
    netif_set_default (netif_add(&netif, &ipaddr, &netmask, &gw, NULL, pcapif_init, netif_input));
  #else
    netif_set_default (netif_add(&netif, &ipaddr, &netmask, &gw, NULL, pcapif_init, tcpip_input));
  #endif
}
#endif /* USE_LWIP */


