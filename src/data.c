/*
 * The resulting 'wsock_trace.lib' is an import-lib for 'wsock_trace.dll'.
 * Since the SDK header <ws2ipdef.h> declares the below data with no export
 * declaration, this data.obj is simply added to the imp-lib.
 */

#include "common.h"
#include "in_addr.h"

const IN_ADDR in4addr_any                     = { 0,0,0,0 };
const IN_ADDR in4addr_loopback                = { 127,0,0,1 };
const IN_ADDR in4addr_broadcast               = { 255,255,255,255 };
const IN_ADDR in4addr_allnodesonlink          = { 224,0,0,1 };
const IN_ADDR in4addr_allroutersonlink        = { 224,0,0,2 };
const IN_ADDR in4addr_alligmpv3routersonlink  = { 224,0,0,22 };
const IN_ADDR in4addr_allteredohostsonlink    = { 224,0,0,253 };
const IN_ADDR in4addr_linklocalprefix         = { 169,254,0,0 };
const IN_ADDR in4addr_multicastprefix         = { 224,0,0,0 };

const IN6_ADDR in6addr_any = {{
      0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
    }};

const IN6_ADDR in6addr_loopback = {{
      0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1
    }};

const IN6_ADDR in6addr_allnodesonnode = {{
      0xFF,1,0,0,0,0,0,0,0,0,0,0,0,0,0,1
    }};

const IN6_ADDR in6addr_allnodesonlink = {{
      0xFF,2,0,0,0,0,0,0,0,0,0,0,0,0,0,1
    }};

const IN6_ADDR in6addr_allroutersonlink = {{
      0xFF,2,0,0,0,0,0,0,0,0,0,0,0,0,0,2
    }};

const IN6_ADDR in6addr_allmldv2routersonlink = {{
      0xFF,2,0,0,0,0,0,0,0,0,0,0,0,0,0,0x10
    }};

const IN6_ADDR in6addr_teredoinitiallinklocaladdress = {{
      0xFE,0x80,0,0,0,0,0,0,0,0,0xFF,0xFF,0xFF,0xFF,0xFF,0xFE
    }};

const IN6_ADDR in6addr_linklocalprefix = {{
      0xFE,0x80,0,0,0,0,0,0,0,0,0,0,0,0,0,0
    }};

const IN6_ADDR in6addr_multicastprefix = {{
      0xFF,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
    }};

const IN6_ADDR in6addr_solicitednodemulticastprefix = {{
      0xFF,2,0,0,0,0,0,0,0,0,0,1,0xFF,0,0,0
    }};

const IN6_ADDR in6addr_v4mappedprefix = {{
      0,0,0,0,0,0,0,0,0,0,0xFF,0xFF,0,0,0,0
    }};

const IN6_ADDR in6addr_6to4prefix = {{
      0x20,2,0,0,0,0,0,0,0,0,0,0,0,0,0,0
    }};

const IN6_ADDR in6addr_teredoprefix = {{
      0x20,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0
    }};

const IN6_ADDR in6addr_teredoprefix_old = {{
      0x3F,0xFE,0x83,0x1F,0,0,0,0,0,0,0,0,0,0,0,0
    }};

#if 0
int WINAPI __WSAFDIsSet (SOCKET s, fd_set *fd)
{
  return raw__WSAFDIsSet (s,fd);
}
#endif