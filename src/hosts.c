/**\file    hosts.c
 * \ingroup inet_util
 *
 * \brief
 *   `/etc/hosts` parsing for wsock_trace.
 *
 * By Gisle Vanem <gvanem@yahoo.no> August 2017.
 */
#include "common.h"
#include "init.h"
#include "smartlist.h"
#include "inet_addr.h"
#include "csv.h"
#include "hosts.h"

/**
 * \struct host_entry
 * The structure for host-entries we read from a file.
 */
struct host_entry {
       char        host_name [MAX_HOST_LEN];  /**< name of `/etc/hosts` entry */
       int         addr_type;                 /**< type `AF_INET` or `AF_INET6` */
       char        addr [IN6ADDRSZ];          /**< the address; 16 bytes to hold an IPv6 address */
       const char *file;                      /**< which `g_cfg.hosts_file[]` is this entry from? */
     };

static smartlist_t *hosts_list;
static int          current_hosts_file;
static unsigned     num_af_inet;
static unsigned     num_af_inet6;

/**
 * Add an entry to the given `smartlist_t` that becomes `hosts_list`.
 */
static void add_entry (const void *addr, const char *name, int af_type)
{
  struct host_entry *he;
  int    asize = 0;

  switch (af_type)
  {
    case AF_INET:
         asize = sizeof (struct in_addr);
         break;
    case AF_INET6:
         asize = sizeof (struct in6_addr);
         break;
    default:
         assert (0);
  }

  he = calloc (1, sizeof(*he));
  if (he && asize)
  {
    he->addr_type = af_type;
    _strlcpy (he->host_name, name, sizeof(he->host_name));
    memcpy (&he->addr, addr, asize);
    he->file = g_cfg.hosts_file [current_hosts_file];
    smartlist_add (hosts_list, he);
  }
}

/**
 * `smartlist_sort()` and `smartlist_make_uniq()` helper;
 * compare on address-types, then on names.
 */
static int hosts_compare_name (const void **_a, const void **_b)
{
  const struct host_entry *a = *_a;
  const struct host_entry *b = *_b;

  if (a->addr_type == b->addr_type)
     return stricmp (a->host_name, b->host_name);

  /* This will cause AF_INET6 addresses to come last.
   */
  return (a->addr_type - b->addr_type);
}

/**
 * `smartlist_bsearch()` helper; compare on names.
 */
static int hosts_bsearch_name (const void *key, const void **member)
{
  const struct host_entry *he = *member;
  const char              *name = key;
  int   rc = stricmp (name, he->host_name);

  TRACE (3, "key: %-30s he->host_name: %-30s he->addr_type: %d, rc: %d\n",
         name, he->host_name, he->addr_type, rc);
  return (rc);
}

/**
 * Handle field 0 which is the ip address (AF_INET or AF_INET6). Or: <br>
 * Handle field 1 which is the host name.
 *
 * Do not care about aliases.
 * Ignore IPv6 records with a scoped address. Like `FE80::94F3:7B8:2773:8B31%5`.
 *
 * \note
 * The Windows `hosts` file support both `AF_INET` and `AF_INET6` addresses. <br>
 * That's the reason we use the internal `INET_addr_pton2()`.
 */
static int hosts_CSV_add (struct CSV_context *ctx, const char *value)
{
  static struct in_addr  ip4;
  static struct in6_addr ip6;
  static int    family = -1;

  switch (ctx->field_num)
  {
    case 0:
         if (strchr(value, '%'))
         {
           TRACE (3, "Ignoring scoped addr: '%s'\n", value);
           family = -1;
         }
         else if (INET_addr_pton2(AF_INET, value, &ip4) == 1)
         {
           TRACE (3, "AF_INET: addr: '%s'\n", value);
           family = AF_INET;
         }
         else if (INET_addr_pton2(AF_INET6, value, &ip6) == 1)
         {
           TRACE (3, "AF_INET6: addr: '%s'\n", value);
           family = AF_INET6;
         }
         else
         {
           TRACE (3, "Bogus field 0 value: '%s'\n", value);
           family = -1;
         }
         break;
    case 1:
         if (family == AF_INET)
         {
           add_entry (&ip4, value, family);
           num_af_inet++;
         }
         else if (family == AF_INET6)
         {
           add_entry (&ip6, value, family);
           num_af_inet6++;
         }
         family = -1;
         memset (&ip4, '\0', sizeof(ip4));
         memset (&ip6, '\0', sizeof(ip6));
         break;
  }
  return (1);
}

/**
 * Print the details of the `hosts_list` and some additional statistics.
 */
static void hosts_file_dump (int max, int duplicates, const struct CSV_context *ctx)
{
  int i;

  C_printf ("\nA total of %d entries in these files:\n", max);
  for (i = 0; g_cfg.hosts_file[i]; i++)
      C_printf ("  %d: \"%s\"\n", i, g_cfg.hosts_file[i]);

  C_printf ("  duplicates: %d, num_af_inet: %u, num_af_inet6: %u.\n"
            "  ctx->rec_num: %u, ctx->line_num: %u, ctx->parse_errors: %u, ctx->comment_lines: %u.\n\n",
            duplicates, num_af_inet, num_af_inet6, ctx->rec_num, ctx->line_num,
            ctx->parse_errors, ctx->comment_lines);

  C_puts ("Entries sorted on name:\n");
  for (i = 0; i < max; i++)
  {
    const struct host_entry *he = smartlist_get (hosts_list, i);
    char  buf [MAX_IP6_SZ+1];
    int   file_idx;

    for (file_idx = 0; g_cfg.hosts_file [file_idx]; file_idx++)
    {
      if (he->file == g_cfg.hosts_file [file_idx])
         break;
    }
    INET_addr_ntop (he->addr_type, he->addr, buf, sizeof(buf), NULL);
    C_printf ("%3d: %-70s %-20s (hosts-file: %d)\n",
              i, he->host_name, buf, file_idx);
  }
}

/**
 * Free the memory in `hosts_list` and free the list itself.
 */
void hosts_file_exit (void)
{
  smartlist_wipe (hosts_list, free);
  hosts_list = NULL;
}

/**
 * Build the `hosts_file` smartlist.
 *
 * We support loading multiple `/etc/hosts` files;
 * Currently max 3.
 */
void hosts_file_init (void)
{
  struct CSV_context ctx;
  int    dups, max;

  assert (hosts_list == NULL);
  hosts_list = smartlist_new();
  if (!hosts_list)
     return;

  for (current_hosts_file = 0; g_cfg.hosts_file[current_hosts_file]; current_hosts_file++)
  {
    memset (&ctx, '\0', sizeof(ctx));
    ctx.file_name  = g_cfg.hosts_file [current_hosts_file];
    ctx.delimiter  = ' ';
    ctx.callback   = hosts_CSV_add;
    CSV_open_and_parse_file (&ctx);
  }

  smartlist_sort (hosts_list, hosts_compare_name);
  dups = smartlist_make_uniq (hosts_list, hosts_compare_name, free);

  /* The new length after the duplicates were removed.
   */
  max = smartlist_len (hosts_list);
  if (g_cfg.trace_level >= 3)
     hosts_file_dump (max, dups, &ctx);
}

/*
 * Check if one of the addresses for `name` is from a hosts-file.
 */
int hosts_file_check_hostent (const char *name, const struct hostent *host)
{
  const char              **addresses;
  const struct host_entry  *he;
  int                       i, asize;
  int                       num = 0;

  addresses = (const char**) host->h_addr_list;

  if (!name || !hosts_list || !addresses)
     return (0);

  /** Do a binary search in the `hosts_list`.
   */
  he = smartlist_bsearch (hosts_list, name, hosts_bsearch_name);

  for (i = num = 0; he && addresses[i]; i++)
  {
    switch (he->addr_type)
    {
      case AF_INET:
           asize = sizeof(struct in_addr);
           break;
      case AF_INET6:
           asize = sizeof(struct in6_addr);
           break;
      default:
           return (num);
    }
    if (he->addr_type == host->h_addrtype &&
        !memcmp(addresses[i], &he->addr, asize))
       num++;
  }
  return (num);
}

/**
 * As above, but for an `struct addrinfo *`.
 */
int hosts_file_check_addrinfo (const char *name, const struct addrinfo *ai)
{
  struct hostent             he;
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

/**
 * As above, but for an `struct addrinfoW *`.
 */
int hosts_file_check_addrinfoW (const wchar_t *name, const struct addrinfoW *aiW)
{
  struct addrinfo ai;
  char   a_name [100] = "??";

  if (WideCharToMultiByte(CP_ACP, 0, name, -1, a_name, (int)sizeof(a_name), NULL, NULL) == 0)
     return (0);

  ai.ai_family = aiW->ai_family;
  ai.ai_addr   = aiW->ai_addr;
  return hosts_file_check_addrinfo (a_name, &ai);
}
