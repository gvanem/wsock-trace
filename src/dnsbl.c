/**\file    dnsbl.c
 * \ingroup DNSBL
 *
 * \brief
 *   A simple DNSBL (Domain Name System Blacklists) implementation.
 *   Parses and uses the the Spamhaus DROP / EDROP files to check an
 *   IPv4-address for member of a "spam network".
 *   Uses in dump.c to print the SBL reference if found in the
 *   'DNSBL_list' smartlist.
 *
 * Refs:
 *   http://www.spamhaus.org/drop/
 *   https://www.spamhaus.org/drop/dropv6.txt
 *   https://www.spamhaus.org/drop/asndrop.txt
 *
 * This file is part of envtool.
 *
 * By Gisle Vanem <gvanem@yahoo.no> August 2018.
 */

#include "common.h"
#include "init.h"
#include "in_addr.h"
#include "smartlist.h"
#include "geoip.h"
#include "dnsbl.h"

typedef enum {
        DNSBL_DROP,
        DNSBL_EDROP,
        DNSBL_DROPv6,
        DNSBL_MAX
      } DNSBL_type;

struct DNSBL_info {
       struct in_addr network;
       DWORD          mask;
       unsigned       suffix;
       DNSBL_type     type;
       int            family;  /* AF_INET or AF_INET6 */
       char           SBL_ref[10];
     };

static smartlist_t *DNSBL_list = NULL;
static char        *DNSBL_expiry [DNSBL_MAX];

static void MS_CDECL DNSBL_parse_DROP   (smartlist_t *sl, const char *line);
static void MS_CDECL DNSBL_parse_DROPv6 (smartlist_t *sl, const char *line);
static void MS_CDECL DNSBL_parse_EDROP  (smartlist_t *sl, const char *line);
static DWORD         get_mask4 (unsigned suffix);

/*
 * smartlist_sort() helper; compare on network.
 */
static int DNSBL_compare_net (const void **_a, const void **_b)
{
  const struct DNSBL_info *a = *_a;
  const struct DNSBL_info *b = *_b;
  DWORD a_net = swap32 (a->network.s_addr);
  DWORD b_net = swap32 (b->network.s_addr);

  if (a_net < b_net)
     return (-1);
  if (a_net > b_net)
     return (1);
  return (0);
}

/*
 * smartlist_bsearch() helper; compare on IPv4 network range.
 */
static int DNSBL_compare_is_on_net4 (const void *key, const void **member)
{
  const struct DNSBL_info *dnsbl = *member;
  const struct in_addr    *ia    = key;
  char  ip_str      [25];
  char  start_ip_str[25];
  char  end_ip_str  [25];
  char  net_str     [25];
  DWORD mask     = dnsbl->mask;
  DWORD netw     = dnsbl->network.s_addr;
  DWORD ip       = ia->s_addr;
  DWORD start_ip = netw & mask;
  DWORD end_ip   = start_ip | ~mask;
  int   rc;

  if (swap32(ip) < swap32(start_ip))
       rc = -1;
  else if (swap32(ip) > swap32(end_ip))
       rc = 1;
  else rc = 0;

  wsock_trace_inet_ntop4 ((const u_char*)&dnsbl->network, net_str, sizeof(net_str));
  wsock_trace_inet_ntop4 ((const u_char*)&ip, ip_str, sizeof(ip_str));
  wsock_trace_inet_ntop4 ((const u_char*)&start_ip, start_ip_str, sizeof(start_ip_str));
  wsock_trace_inet_ntop4 ((const u_char*)&end_ip, end_ip_str, sizeof(end_ip_str));

  TRACE (2, "ip: %-15s net: %-15s (%-15s - %-15s) mask: 0x%08lX rc: %d\n",
         ip_str, net_str, start_ip_str, end_ip_str, mask, rc);

  return (rc);
}

/*
 * \todo
 * smartlist_bsearch() helper; compare on IPv6 network range.
 */
static int DNSBL_compare_is_on_net6 (const void *key, const void **member)
{
  ARGSUSED (key);
  ARGSUSED (member);
  return (0);
}

/*
 * Do a binary search in the 'DNSBL_list' to figure out if
 * 'ip4' is a member of a "spam group".
 */
BOOL DNSBL_check_ipv4 (const struct in_addr *ip4, const char **sbl_ref)
{
  const struct DNSBL_info *dnsbl;
  BOOL  save = call_WSASetLastError;

  if (sbl_ref)
     *sbl_ref = NULL;

  if (!DNSBL_list)
     return (FALSE);

  dnsbl = smartlist_bsearch (DNSBL_list, ip4, DNSBL_compare_is_on_net4);
  if (sbl_ref && dnsbl)
     *sbl_ref = dnsbl->SBL_ref;

  call_WSASetLastError = save;
  return (dnsbl ? TRUE : FALSE);
}

/*
 * Do a binary search in the 'DNSBL_list' to figure out if
 * 'ip6' is a member of a "spam group".
 */
BOOL DNSBL_check_ipv6 (const struct in6_addr *ip6, const char **sbl_ref)
{
  const struct DNSBL_info *dnsbl;
  BOOL  save = call_WSASetLastError;

  if (sbl_ref)
     *sbl_ref = NULL;

  if (!DNSBL_list)
     return (FALSE);

  dnsbl = smartlist_bsearch (DNSBL_list, ip6, DNSBL_compare_is_on_net6);
  if (sbl_ref && dnsbl)
     *sbl_ref = dnsbl->SBL_ref;

  call_WSASetLastError = save;
  return (dnsbl ? TRUE : FALSE);
}

static void DNSBL_dump (void)
{
  int  i, max = DNSBL_list ? smartlist_len(DNSBL_list) : 0;
  BOOL save = call_WSASetLastError;

  for (i = 0; i < max; i++)
  {
    const struct DNSBL_info *dnsbl = smartlist_get (DNSBL_list, i);
    char  addr[25];
    char  mask[25];
    char  cidr[60];

    wsock_trace_inet_ntop4 ((const u_char*)&dnsbl->network, addr, sizeof(addr));
    wsock_trace_inet_ntop4 ((const u_char*)&dnsbl->mask, mask, sizeof(mask));

    snprintf (cidr, sizeof(cidr), "%s/%u", addr, dnsbl->suffix);
    TRACE (2, "%3d: SBL%-6s  %-18s %-18s type: %d.\n",
            i, dnsbl->SBL_ref[0] ? dnsbl->SBL_ref : "<none>", cidr, mask, dnsbl->type);
  }
  call_WSASetLastError = save;
}

/*
 * Test some lines from drop.txt:
 *   108.166.224.0/19 ; SBL235333
 *   24.51.0.0/19     ; SBL293696
 *   193.25.48.0/20   ; SBL211796
 *   8.8.8.8/xx       ; should not be in DNSBL
 *
 * Test some lines from edrop.txt:
 *   120.46.0.0/15  ; SBL262362
 *   208.12.64.0/19 ; SBL201196
 *
 *  Further details for the SBL-reference is found from:
 *    https://www.spamhaus.org/sbl/query/SBL<xxx>
 */
static void DNSBL_test (void)
{
  struct in_addr     ip;
  int                i;
  const char        *sbl_ref  = NULL;
  const char        *country_code, *location;
  BOOL               rc, save = call_WSASetLastError;
  static const char *addr[] = {
                    "108.166.224.2", /* in drop.txt */
                    "24.51.0.2",
                    "8.8.8.8",
                    "193.25.48.3",
                    "120.46.4.1",    /* in edrop.txt */
                    "208.12.64.5"
                  };

  for (i = 0; i < DIM(addr); i++)
  {
    wsock_trace_inet_pton4 (addr[i], (u_char*)&ip);
    country_code = geoip_get_country_by_ipv4 (&ip);
    location     = geoip_get_location_by_ipv4 (&ip);
    rc = DNSBL_check_ipv4 (&ip, &sbl_ref);
    if (!sbl_ref)
       sbl_ref = " <none>";
    TRACE (2, "%-15s -> %d, SBL %-7s country: %s, location: %s\n",
           addr[i], rc, sbl_ref, country_code, location);
  }
  call_WSASetLastError = save;
}

static void DNSBL_parse_and_add (smartlist_t **prev, const char *file, smartlist_parse_func parser)
{
  if (g_cfg.DNSBL.enable && file)
  {
    smartlist_t *sl = smartlist_read_file (file, parser, TRUE);

    if (*prev)
    {
      smartlist_append (*prev, sl);
      smartlist_free (sl);
    }
    else
      *prev = sl;
  }
}

/*
 * called from init.c /  wsock_trace_init().
 */
void DNSBL_init (void)
{
  DNSBL_parse_and_add (&DNSBL_list, g_cfg.DNSBL.drop_file, DNSBL_parse_DROP);
  DNSBL_parse_and_add (&DNSBL_list, g_cfg.DNSBL.edrop_file, DNSBL_parse_EDROP);
  DNSBL_parse_and_add (&DNSBL_list, g_cfg.DNSBL.dropv6_file, DNSBL_parse_DROPv6);

  /* Each of the 'drop.txt' and 'edrop.txt' should be sorted.
   * But after merging them into one list, we must sort them ourself.
   */
  if (DNSBL_list)
     smartlist_sort (DNSBL_list, DNSBL_compare_net);

  if (g_cfg.trace_level >= 2)
  {
    DNSBL_dump();
    DNSBL_test();
  }
}

void DNSBL_exit (void)
{
  struct DNSBL_info *dnsbl;
  int    i, max = DNSBL_list ? smartlist_len(DNSBL_list) : 0;

  for (i = 0; i < max; i++)
  {
    dnsbl = smartlist_get (DNSBL_list, i);
    free (dnsbl);
  }
  smartlist_free (DNSBL_list);
  DNSBL_list = NULL;

  for (i = 0; i < DNSBL_MAX; i++)
  {
    if (DNSBL_expiry[i])
       free (DNSBL_expiry[i]);
  }
}

/*
 * \todo: check and download '*drop*.txt' files based on expiriry in the file header.
 *        Use WinInet.dll similar as in geoip.c
 */
int DNSBL_update_files (void)
{
#if 0
  time_t now = time (NULL);
  time_t expiry;
  int    i;

  for (i = 0; i < DNSBL_MAX; i++)
  {
    if (!DNSBL_expiry[i])
       continue;
    expiry = parse_date (DNSBL_expiry[i]);
    if (expiry <= now)
       update_file (i);
  }
#endif
  return (0);
}

static BOOL DNSBL_parse_expiry (const char *line, DNSBL_type type)
{
  const char *expires = "; Expires: ";

  if (*line == ';')
  {
    if (!strncmp(line,expires,strlen(expires)))
    {
      assert (type >= 0);
      assert (type < DNSBL_MAX);
      line += strlen (expires);
      DNSBL_expiry [type] = strdup (line);
      TRACE (2, "expiry: '%s', type: %d\n", DNSBL_expiry [type], type);
    }
    return (TRUE);
  }
  return (FALSE);
}

static void DNSBL_parse4 (smartlist_t *sl, const char *line, DNSBL_type type)
{
  struct DNSBL_info *dnsbl;
  int                b1 = 0, b2 = 0, b3 = 0, b4 = 0, suffix = 0;

  if (DNSBL_parse_expiry(line,type))
     return;

  if (sscanf(line, "%d.%d.%d.%d/%d ; SBL", &b1, &b2, &b3, &b4, &suffix) != 5)
     return;

  if (suffix < 8 || suffix > 32) /* Cannot happen */
     return;

  dnsbl = malloc (sizeof(*dnsbl));
  if (!dnsbl)
     return;

  /* Store as big-endian
   */
  dnsbl->network.s_addr = (b4 << 24) + (b3 << 16) + (b2 << 8) + b1;
  dnsbl->suffix         = suffix;
  dnsbl->mask           = get_mask4 (suffix);
  dnsbl->type           = type;
  dnsbl->family         = AF_INET;

  _strlcpy (dnsbl->SBL_ref, strchr(line, 'L') + 1, sizeof(dnsbl->SBL_ref));
  smartlist_add (sl, dnsbl);
}

/*
 * \todo Parse a "dropv6.txt" file.
 */
static void DNSBL_parse6 (smartlist_t *sl, const char *line, DNSBL_type type)
{
  if (DNSBL_parse_expiry(line,type))
     return;

  TRACE (3, "%s, type: %d\n", line, type);
}

static void MS_CDECL DNSBL_parse_DROP (smartlist_t *sl, const char *line)
{
  DNSBL_parse4 (sl, line, DNSBL_DROP);
}

static void MS_CDECL DNSBL_parse_EDROP (smartlist_t *sl, const char *line)
{
  DNSBL_parse4 (sl, line, DNSBL_EDROP);
}

static void MS_CDECL DNSBL_parse_DROPv6 (smartlist_t *sl, const char *line)
{
  DNSBL_parse6 (sl, line, DNSBL_DROPv6);
}

/*
 * https://stackoverflow.com/questions/218604/whats-the-best-way-to-convert-from-network-bitcount-to-netmask
 *
 * Ret-val on network-order
 */
static DWORD get_mask4 (unsigned suffix)
{
  if (suffix == 0)
     return (0xFFFFFFFF);
  suffix = 32 - suffix;
  return swap32 ((0xFFFFFFFF >> suffix) << suffix);
}

/*
 * \todo: create a small test for DNSBL.
 */
#if defined(TEST_DNSBL)

#include "getopt.h"

int main (int argc, char **argv)
{
  return (0);
}
#endif