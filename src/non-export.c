/**
 * \file    non-export.c
 * \ingroup Misc
 *
 * \brief
 * Since the SDK header `<ws2ipdef.h>` declares the below data with no export
 * declaration, this `non-export.obj` is simply added to the import-library.
 */

#include "common.h"
#include "inet_addr.h"

_PRAGMA (clang diagnostic ignored "-Wmissing-braces")

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

#if defined(__DOXYGEN__) && 0   /* Rest of file */

/**
 * Similar to the one in common.c.
 */
static char *str_rip2 (char *s)
{
  char *p;

  if ((p = strrchr(s, '\n')) != NULL) *p = '\0';
  if ((p = strrchr(s, '\r')) != NULL) *p = '\0';
  return (s);
}

static wchar_t *str_ripw2 (wchar_t *s)
{
  wchar_t *p;

  if ((p = wcsrchr(s, L'\n')) != NULL) *p = L'\0';
  if ((p = wcsrchr(s, L'\r')) != NULL) *p = L'\0';
  return (s);
}

/**
 * These are `static __inline` function in MinGW.org's `<ws2tcpip.h>`.
 * But in other MinGW distribution they are not.
 *
 * Under CygWin these functions seems to be in several places: \n
 * `libc.a`, `libcygwin.a` and `libg.a`.
 *
 * In any case, they are part of `libws2_32.a` even though `gai_strerror[A|W]`
 * is not part of the system `ws2_32.dll`. So for `libwsock_trace_mw.a` (and
 * `libwsock_trace_cyg.a`) to be a replacement for `libws2_32.a`, we must also
 * add these functions to it.
 *
 * But tracing these calls would be difficult since the needed functions
 * for that is in `wsock_trace.c`.
 */
#define FORMAT_FLAGS (FORMAT_MESSAGE_FROM_SYSTEM    | \
                      FORMAT_MESSAGE_IGNORE_INSERTS | \
                      FORMAT_MESSAGE_MAX_WIDTH_MASK)

#undef gai_strerrorA
#undef gai_strerrorW

char *gai_strerrorA (int err)
{
  static char err_buf [512];

  err_buf[0] = '\0';
  FormatMessageA (FORMAT_FLAGS, NULL, err, LANG_NEUTRAL,
                  err_buf, sizeof(err_buf)-1, NULL);
  return str_rip2 (err_buf);
}

wchar_t *gai_strerrorW (int err)
{
  static wchar_t err_buf [512];

  err_buf[0] = L'\0';
  FormatMessageW (FORMAT_FLAGS, NULL, err, LANG_NEUTRAL,
                  err_buf, DIM(err_buf)-1, NULL);
  return str_ripw2 (err_buf);
}

#endif  /* __DOXYGEN__ */

