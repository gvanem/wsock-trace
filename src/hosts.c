/*
 * '/etc/hosts' parsing for wsock_trace.
 */
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

/* Avoid "warning C4996: 'GetVersion': was declared deprecated"
*/
#ifndef BUILD_WINDOWS
#define BUILD_WINDOWS
#endif

#include "common.h"
#include "init.h"
#include "smartlist.h"
#include "in_addr.h"
//#include "wsock_trace.h"
#include "hosts.h"

struct host_entry {
       char host_name [MAX_HOST_LEN];  /* name of 'etc/hosts' entry */
       int  addr_size;                 /* size of this adresses (4 or 16) */
       int  addr_type;                 /* type AF_INET or AF_INET6 */
       char addr [IN6ADDRSZ];          /* the actual address */
     };

static smartlist_t *hosts_list = (smartlist_t*) -1;

static const char *etc_path (const char *file);

/*
 * Add an entry to the 'hosts_list'.
 */
static void add_entry (const char *name, const char *ip, const void *addr, size_t size, int af_type)
{
  struct host_entry *he = calloc (1, sizeof(*he));
  char   buf [MAX_IP6_SZ];
  int    len;

  if (!he)
     return;

  assert (hosts_list != (smartlist_t*) -1);
  assert (hosts_list != NULL);
  assert (size <= sizeof(struct in6_addr));

  he->addr_type = af_type;
  he->addr_size = size;
  _strlcpy (he->host_name, name, sizeof(he->host_name));
  memcpy (&he->addr, addr, size);
  smartlist_add (hosts_list, he);
}

/*
 * Parse the file for lines matching "ip host".
 * Do not care about aliases.
 *
 * Note: the Windows 'hosts' file support both AF_INET and AF_INET6 addresses.
 *       That's the reason we set 'call_WSASetLastError = FALSE'. Since passing
 *       an IPv6-addresses to 'wsock_trace_inet_pton4()' will call 'WSASetLastError()'.
 *       And vice-versa.
 */
static void parse_hosts (FILE *fil)
{
  while (1)
  {
    struct in_addr  in4;
    struct in6_addr in6;

    char  buf[500];
    char *p, *ip, *name, *tok_buf;

    if (!fgets(buf,sizeof(buf)-1,fil))   /* EOF */
       break;

    strip_nl (buf);
    for (p = buf ; *p && isspace((int)*p); )
        p++;

    if (*p == '\0' || *p == '#' || *p == ';')
       continue;

    ip   = _strtok_r (p, " \t", &tok_buf);
    name = _strtok_r (NULL, " \t", &tok_buf);

    if (!name || !ip)
       continue;

    TRACE (2, "p: '%s', name: '%s', ip: '%s'\n", p, name, ip);

    if (wsock_trace_inet_pton4(ip, (u_char*)&in4) == 1)
         add_entry (name, ip, &in4, sizeof(in4), AF_INET);
    else if (wsock_trace_inet_pton6(ip, (u_char*)&in6) == 1)
         add_entry (name, ip, &in6, sizeof(in6), AF_INET6);
  }
}

/*
 * Print the 'hosts_list'.
 */
static void hosts_file_dump (void)
{
  int i, max = smartlist_len (hosts_list);

  for (i = 0; i < max; i++)
  {
    const struct host_entry *he = smartlist_get (hosts_list, i);

    TRACE (1, "%3d: host: '%s', ip: %s\n",
         len-1, he->host_name, wsock_trace_inet_ntop(af_type,he->addr,buf,sizeof(buf)));
  }
}

/*
 * Free the memory in 'hosts_list' and free the list itself.
 */
void hosts_file_exit (void)
{
  int i, max;

  if (!hosts_list || hosts_list == (smartlist_t*)-1)
     return;

  max = smartlist_len (hosts_list);
  for (i = 0; i < max; i++)
      free (smartlist_get(hosts_list, i));

  smartlist_free (hosts_list);
  hosts_list = NULL;
}

void hosts_file_init (void)
{
  FILE *fil;

  hosts_list = smartlist_new();
  if (!hosts_list)
     return;

  fil = fopen (etc_path("hosts"), "r");
  if (fil)
  {
    /* Cannot call 'WSASetLastError()' in in_addr.c before we're fully unitialised.
     */
    call_WSASetLastError = FALSE;
    parse_hosts (fil);
    call_WSASetLastError = TRUE;
    fclose (fil);

    if (g_cfg.trace_level >= 3)
       hosts_file_dump();
  }
}

/*
 * Check if one of the addresses for 'name' is from the hosts-file.
 */
int hosts_file_check (const char *name, const struct hostent *host)
{
  const char              **addresses = (const char**) host->h_addr_list;
  const struct host_entry  *he;
  const char               *found = NULL;
  int                       i, max, num = 0;

  /* This should never happen
   */
  if (!hosts_list || hosts_list == (smartlist_t*)-1)
     return (0);

  /* Get number of entries in the '/etc/hosts' file.
   */
  max = smartlist_len (hosts_list);
  if (max == 0)
     return (0); /* None! */

  for (i = 0; i < max; i++)
  {
    he = smartlist_get (hosts_list, i);
    if (!stricmp(he->host_name, name))
    {
      found = he->host_name;
      break;
    }
  }

  if (!found)
     return (0);

  for (i = 0; addresses && addresses[i]; i++)
  {
    if (he->addr_type != host->h_addrtype)
       continue;
    if (!memcmp(addresses[i], &he->addr, he->addr_size))
       num++;
  }
  return (num);
}

/*
 * Return TRUE if running under Win-95/98/ME.
 */
static BOOL is_win9x (void)
{
  DWORD os_ver = GetVersion();
  DWORD major_ver = LOBYTE (LOWORD(os_ver));

  return (os_ver >= 0x80000000 && major_ver >= 4);
}

/*
 * Return path to "%SystemRoot%/drivers/etc/<file>"  (Win-NT+)
 *          or to "%Windir%/etc/<file>"              (Win-9x/ME)
 */
static const char *etc_path (const char *file)
{
  BOOL win9x = is_win9x();
  const char *env = win9x ? getenv("WinDir") : getenv("SystemRoot");
  static char path [MAX_PATH];

  TRACE (3, "win9x: %d, env: %s\n", win9x, env);

  if (!env)
     return (file);

  if (win9x)
       snprintf (path, sizeof(path), "%s\\etc\\%s", env, file);
  else snprintf (path, sizeof(path), "%s\\system32\\drivers\\etc\\%s", env, file);

  TRACE (3, "path: %s\n", path);
  return (path);
}