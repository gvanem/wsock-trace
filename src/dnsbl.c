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
 *
 * By Gisle Vanem <gvanem@yahoo.no> August 2018.
 */

#include "common.h"
#include "init.h"
#include "in_addr.h"
#include "smartlist.h"
#include "geoip.h"
#include "inet_util.h"
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
static const char  *current_file;   /* The DROP-file we're currently parsing */

static void MS_CDECL DNSBL_parse_DROP   (smartlist_t *sl, const char *line);
static void MS_CDECL DNSBL_parse_DROPv6 (smartlist_t *sl, const char *line);
static void MS_CDECL DNSBL_parse_EDROP  (smartlist_t *sl, const char *line);
static DWORD         get_mask4 (unsigned suffix);

static const char *DNSBL_type_name (DNSBL_type type)
{
  return (type == DNSBL_DROP   ? "DROP"   :
          type == DNSBL_EDROP  ? "EDROP"  :
          type == DNSBL_DROPv6 ? "DROPv6" :
          "?");
}

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

  if (g_cfg.trace_level >= 3)
  {
    char ip_str      [25];
    char start_ip_str[25];
    char end_ip_str  [25];
    char net_str     [25];

    _wsock_trace_inet_ntop (AF_INET, (const u_char*)&dnsbl->network, net_str, sizeof(net_str));
    _wsock_trace_inet_ntop (AF_INET, (const u_char*)&ip, ip_str, sizeof(ip_str));
    _wsock_trace_inet_ntop (AF_INET, (const u_char*)&start_ip, start_ip_str, sizeof(start_ip_str));
    _wsock_trace_inet_ntop (AF_INET, (const u_char*)&end_ip, end_ip_str, sizeof(end_ip_str));

    TRACE (3, "ip: %-15s net: %-15s (%-12s - %-15s) mask: 0x%08lX rc: %d\n",
           ip_str, net_str, start_ip_str, end_ip_str, (u_long)mask, rc);
  }

  return (rc);
}

/*
 * \todo:
 * smartlist_bsearch() helper; compare on IPv6 network range.
 */
static int DNSBL_compare_is_on_net6 (const void *key, const void **member)
{
  ARGSUSED (key);
  ARGSUSED (member);
  return (1);
}

/*
 * Do a binary search in the 'DNSBL_list' to figure out if
 * 'ip4' or 'ip6' address is a member of a "spam group".
 */
static BOOL DNSBL_check_addr (const struct in_addr *ip4, const struct in6_addr *ip6, const char **sbl_ref)
{
  const struct DNSBL_info *dnsbl;

  if (!DNSBL_list)
     return (FALSE);

  if (sbl_ref)
     *sbl_ref = NULL;

  dnsbl = smartlist_bsearch (DNSBL_list, ip4 ? (const void*)ip4 : (const void*)ip6,
                             ip4 ? DNSBL_compare_is_on_net4 : DNSBL_compare_is_on_net6);
  if (sbl_ref && dnsbl)
     *sbl_ref = dnsbl->SBL_ref;

  return (dnsbl ? TRUE : FALSE);
}

BOOL DNSBL_check_ipv4 (const struct in_addr *ip4, const char **sbl_ref)
{
  return DNSBL_check_addr (ip4, NULL, sbl_ref);
}

BOOL DNSBL_check_ipv6 (const struct in6_addr *ip6, const char **sbl_ref)
{
  return DNSBL_check_addr (NULL, ip6, sbl_ref);
}

static void DNSBL_dump (void)
{
  int  i, max = DNSBL_list ? smartlist_len(DNSBL_list) : 0;

  for (i = 0; i < max; i++)
  {
    const struct DNSBL_info *dnsbl = smartlist_get (DNSBL_list, i);
    char  addr [MAX_IP6_SZ];
    char  mask [MAX_IP6_SZ];
    char  cidr [60];

    _wsock_trace_inet_ntop (dnsbl->family, (const u_char*)&dnsbl->network, addr, sizeof(addr));
    _wsock_trace_inet_ntop (dnsbl->family, (const u_char*)&dnsbl->mask, mask, sizeof(mask));

    snprintf (cidr, sizeof(cidr), "%s/%u", addr, dnsbl->suffix);
    trace_printf ("%3d: SBL%-6s  %-18s %-18s type: %d.\n",
                  i, dnsbl->SBL_ref[0] ? dnsbl->SBL_ref : "<none>", cidr, mask, dnsbl->type);
  }
}

/*
 * Test some lines from drop.txt:
 *   108.166.224.0/19 ; SBL235333
 *   24.51.0.0/19     ; SBL293696
 *   193.25.48.0/20   ; SBL211796
 *
 * Verify that Google's NS is not in any DNSBL
 *   8.8.8.8/xx
 *
 * Test some lines from edrop.txt:
 *   120.46.0.0/15  ; SBL262362
 *   208.12.64.0/19 ; SBL201196
 *
 * \todo: Test some lines from dropv6.txt:
 *   2a06:5280::/29 ; SBL334219
 *   2607:d100::/32 ; SBL347495
 *
 * Further details for the SBL-reference is found from:
 *   https://www.spamhaus.org/sbl/query/SBL<xxx>
 */
int DNSBL_test (void)
{
  struct in_addr     ip;
  int                i;
  const char        *sbl_ref  = NULL;
  const char        *country_code, *location;
  BOOL               rc;
  static const char *addr[] = {
                    "108.166.224.2", /* in drop.txt */
                    "24.51.0.2",
                    "8.8.8.8",
                    "193.25.48.3",
                    "120.46.4.1",    /* in edrop.txt */
                    "208.12.64.5"
                  };

  if (g_cfg.trace_level < 3)
     return (0);

  DNSBL_dump();

  trace_puts ("DNSBL_test():\n");
  for (i = rc = 0; i < DIM(addr); i++)
  {
    _wsock_trace_inet_pton (AF_INET, addr[i], (u_char*)&ip);
    country_code = geoip_get_country_by_ipv4 (&ip);
    location     = geoip_get_location_by_ipv4 (&ip);
    rc += DNSBL_check_ipv4 (&ip, &sbl_ref);
    if (!sbl_ref)
       sbl_ref = " <none>";
    trace_printf ("%-15s -> %d, SBL %-7s country: %s, location: %s\n",
                  addr[i], rc, sbl_ref, country_code, location);
  }
  return (rc);
}

static void DNSBL_parse_and_add (smartlist_t **prev, const char *file, smartlist_parse_func parser)
{
  if (g_cfg.DNSBL.enable && file)
  {
    smartlist_t *sl = smartlist_read_file (file, parser);

    current_file = file;
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
 * Called from init.c /  wsock_trace_init().
 *
 * This function is called before 'load_ws2_funcs()' that dynamically loads
 * all Winsock functions. That means we must NOT call any true Winsock functions.
 * But instead use private functions like '_wsock_trace_inet_pton()' that sets
 * 'call_WSASetLastError == FALSE'.
 *
 * Since the 'DNSBL_test()' test function will call 'inet_addr()' (at trace_level >= 3)
 * via 'IP2Location_get_record()', the 'DNSBL_test()' must be postponed to a later
 * stage in 'wsock_trace_init()'.
 */
void DNSBL_init (void)
{
  DNSBL_update_files();
  DNSBL_parse_and_add (&DNSBL_list, g_cfg.DNSBL.drop_file, DNSBL_parse_DROP);
  DNSBL_parse_and_add (&DNSBL_list, g_cfg.DNSBL.edrop_file, DNSBL_parse_EDROP);
  DNSBL_parse_and_add (&DNSBL_list, g_cfg.DNSBL.dropv6_file, DNSBL_parse_DROPv6);

  /* Each of the 'drop.txt', 'edrop.txt' and 'dropv6.txt' should be sorted.
   * But after merging them into one list, we must sort them ourself.
   */
  if (DNSBL_list)
     smartlist_sort (DNSBL_list, DNSBL_compare_net);
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
}

/**
 * Check if 'fname' needs an update.
 * If it does, download it using WinInet.dll and 'touch' it.
 */
static int update_file (const char *fname, const char *url, time_t now, time_t expiry)
{
  struct stat st;
  time_t when;

  if (!fname || !url || stat(fname, &st) != 0)
     return (0);

  if (st.st_mtime > expiry)
  {
    when = now + g_cfg.DNSBL.max_days * 24 * 3600;
    TRACE (1, "Update of \"%s\" not needed until %.24s\"\n",
           fname, ctime(&when));
    return (0);
  }

  TRACE (1, "Updating \"%s\" from \"%s\"\n", fname, url);
  if (INET_util_download_file(fname, url) > 0)
  {
    INET_util_touch_file (fname);
    return (1);
  }
  return (0);
}

/**
 * Check all '*drop*.txt' files based on file's timestamp. The expiriry in the
 * file header is a bit too hard to parse. Simply use 'g_cfg.DNSBL.max_days'
 * and download it if it's too old.
 */
int DNSBL_update_files (void)
{
  time_t now, expiry;
  int    num = 0;

  tzset();
  now = time (NULL);
  expiry = now - g_cfg.DNSBL.max_days * 24 * 3600;

  num += update_file (g_cfg.DNSBL.drop_file, g_cfg.DNSBL.drop_url, now, expiry);
  num += update_file (g_cfg.DNSBL.edrop_file, g_cfg.DNSBL.edrop_url, now, expiry);
  num += update_file (g_cfg.DNSBL.dropv6_file, g_cfg.DNSBL.dropv6_url, now, expiry);
  return (num);
}

static void DNSBL_parse4 (smartlist_t *sl, const char *line, DNSBL_type type)
{
  struct DNSBL_info *dnsbl;
  int                b1 = 0, b2 = 0, b3 = 0, b4 = 0, suffix = 0;

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

static void MS_CDECL DNSBL_parse_DROP (smartlist_t *sl, const char *line)
{
  DNSBL_parse4 (sl, line, DNSBL_DROP);
}

static void MS_CDECL DNSBL_parse_EDROP (smartlist_t *sl, const char *line)
{
  DNSBL_parse4 (sl, line, DNSBL_EDROP);
}

/*
 * \todo Parse a "dropv6.txt" file.
 */
static void DNSBL_parse_DROPv6 (smartlist_t *sl, const char *line)
{
  TRACE (3, "%s, type: %s\n", line, DNSBL_type_name(DNSBL_DROPv6));
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
