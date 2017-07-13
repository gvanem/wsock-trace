/*
 * lwIP interface for WSock-Trace.
 */
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

#if defined(USE_LWIP)  /* Rest of file */

#include "common.h"
#include "init.h"

// #include "wsock_trace_lwip.h"

#include <lwip/init.h>
#include <lwip/netif.h>
#include <ports/win32/pcapif.h>

static struct netif netif;

void ws_lwip_init (void)
{
  ip4_addr_t ipaddr, netmask, gw;

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

#endif

