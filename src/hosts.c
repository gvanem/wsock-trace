/**\file    hosts.c
 * \ingroup NET_UTIL
 *
 * \brief '/etc/hosts' parsing for wsock_trace.
 *
 * By Gisle Vanem <gvanem@yahoo.no> August 2017.
 */
#include "common.h"
#include "init.h"
#include "smartlist.h"
#include "in_addr.h"
#include "hosts.h"

struct host_entry {
       char   host_name [MAX_HOST_LEN];  /* name of 'etc/hosts' entry */
       size_t addr_size;                 /* size of this adresses (4 or 16) */
       int    addr_type;                 /* type AF_INET or AF_INET6 */
       char   addr [IN6ADDRSZ];          /* the actual address */
     };

static smartlist_t *hosts_list;

/**
 * Add an entry to the given 'smartlist_t' that becomes 'hosts_list'.
 */
static void add_entry (smartlist_t *sl, const char *name, const char *ip, const void *addr, size_t size, int af_type)
{
  struct host_entry *he;

  assert (size <= sizeof(struct in6_addr));

  he = calloc (1, sizeof(*he));
  if (he)
  {
    he->addr_type = af_type;
    he->addr_size = size;
    _strlcpy (he->host_name, name, sizeof(he->host_name));
    memcpy (&he->addr, addr, size);
    smartlist_add (sl, he);
  }
}

/**
 * smartlist_sort() helper; compare on names.
 */
static int hosts_compare_name (const void **_a, const void **_b)
{
  const struct host_entry *a = *_a;
  const struct host_entry *b = *_b;

  if (a->addr_type == b->addr_type)
     return strcmp (a->host_name, b->host_name);

  /* This will cause AF_INET6 addresses to come last.
   */
  return (a->addr_type - b->addr_type);
}

/**
 * smartlist_bsearch() helper; compare on names.
 */
static int hosts_bsearch_name (const void *key, const void **member)
{
  const struct host_entry *he = *member;
  const char              *name = key;
  int   rc = strcmp (name, he->host_name);

  TRACE (3, "key: %-30s he->host_name: %-30s he->addr_type: %d, rc: %d\n",
         name, he->host_name, he->addr_type, rc);
  return (rc);
}

/**
 * Parse the file for lines matching "ip host".
 * Do not care about aliases.
 *
 * \note the Windows 'hosts' file support both AF_INET and AF_INET6 addresses.
 *       That's the reason we call '_wsock_trace_pton(). Since passing
 *       an IPv6-addresses to 'wsock_trace_inet_pton4()' will call 'WSASetLastError()'.
 *       And vice-versa.
 */
static void parse_hosts (smartlist_t *sl, const char *line)
{
  struct in_addr  in4;
  struct in6_addr in6;
  char            buf[500];
  char           *tok_buf;
  char           *p    = _strlcpy (buf, line, sizeof(buf));
  char           *ip   = _strtok_r (p, " \t", &tok_buf);
  char           *name = _strtok_r (NULL, " \t", &tok_buf);

  if (!name || !ip)
     return;

  if (_wsock_trace_inet_pton(AF_INET, ip, (u_char*)&in4) == 1)
       add_entry (sl, name, ip, &in4, sizeof(in4), AF_INET);
  else if (_wsock_trace_inet_pton(AF_INET6, ip, (u_char*)&in6) == 1)
       add_entry (sl, name, ip, &in6, sizeof(in6), AF_INET6);
}

/**
 * Print the 'hosts_list' if 'g_cfg.trace_level >= 3'.
 */
static void hosts_file_dump (void)
{
  int i, max = smartlist_len (hosts_list);

  trace_printf ("\n%d entries in \"%s\" sorted on name:\n", max, g_cfg.hosts_file);

  for (i = 0; i < max; i++)
  {
    const struct host_entry *he = smartlist_get (hosts_list, i);
    char  buf [MAX_IP6_SZ];

    wsock_trace_inet_ntop (he->addr_type, he->addr, buf, sizeof(buf));
    trace_printf ("%3d: %-40s %-20s AF_INET%c\n",
                  i, he->host_name, buf,
                  (he->addr_type == AF_INET6) ? '6' : ' ');
  }
}

/**
 * Free the memory in 'hosts_list' and free the list itself.
 */
void hosts_file_exit (void)
{
  int i, max;

  if (!hosts_list)
     return;

  max = smartlist_len (hosts_list);
  for (i = 0; i < max; i++)
      free (smartlist_get(hosts_list, i));

  smartlist_free (hosts_list);
  hosts_list = NULL;
}

/**
 * Build the 'hosts_file' smartlist.
 *
 * \todo: support loading multiple '/etc/hosts' files.
 */
void hosts_file_init (void)
{
  hosts_list = g_cfg.hosts_file ?
                 smartlist_read_file (g_cfg.hosts_file, parse_hosts, FALSE) : NULL;
  if (hosts_list)
  {
    smartlist_sort (hosts_list, hosts_compare_name);

    if (g_cfg.trace_level >= 3)
       hosts_file_dump();
  }
}

/*
 * Check if one of the addresses for 'name' is from the hosts-file.
 */
int hosts_file_check_hostent (const char *name, const struct hostent *host)
{
  const char              **addresses;
  const struct host_entry  *he;
  int                       i, num = 0;

  addresses = (const char**) host->h_addr_list;

  if (!name || !hosts_list || !addresses)
     return (0);

  /* Do a binary search in the 'hosts_list'.
   */
  he = smartlist_bsearch (hosts_list, name, hosts_bsearch_name);

  for (i = num = 0; he && addresses[i]; i++)
  {
    if (he->addr_type == host->h_addrtype &&
        !memcmp(addresses[i], &he->addr, he->addr_size))
       num++;
  }
  return (num);
}

/*
 * As above, but for an 'struct addrinfo *'.
 */
int hosts_file_check_addrinfo (const char *name, const struct addrinfo *ai)
{
  struct hostent he;
  const struct sockaddr_in  *sa4;
  const struct sockaddr_in6 *sa6;
  char *addr_list [2];

  if (!ai || !ai->ai_addr || !name)
     return (0);

  addr_list[1]   = NULL;
  he.h_aliases   = NULL;
  he.h_addr_list = &addr_list[0];
  he.h_addrtype  = ai->ai_family;

  if (ai->ai_family == AF_INET)
  {
    sa4 = (const struct sockaddr_in*) ai->ai_addr;
    addr_list[0] = (char*) &sa4->sin_addr;
    return hosts_file_check_hostent (name, &he);
  }

  if (ai->ai_family == AF_INET6)
  {
    sa6 = (const struct sockaddr_in6*) ai->ai_addr;
    addr_list[0] = (char*) &sa6->sin6_addr;
    return hosts_file_check_hostent (name, &he);
  }
  return (0);
}
