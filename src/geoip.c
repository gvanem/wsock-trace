/*
 * geoip.c - Part of Wsock-Trace.
 *
 * This file implements parsing of CSV value files of MaxMind IPv4 + IPv6
 * geoip-data files. It is inspired by Tor's geoip.c:
 *   https://gitweb.torproject.org/tor.git/tree/src/or/geoip.c
 */

#include <assert.h>
#include <sys/stat.h>
#include <sys/utime.h>
#include <limits.h>
#include <errno.h>
#include <windows.h>
#include <wininet.h>

#include "common.h"
#include "init.h"
#include "in_addr.h"
#include "geoip.h"

#if defined(__CYGWIN__)
  #define _utime(path, buf) utime (path, buf)
#endif

static int geoip4_parse_entry (char *buf, unsigned *line, DWORD *num);
static int geoip6_parse_entry (char *buf, unsigned *line, DWORD *num);
static int geoip4_add_entry (DWORD low, DWORD high, const char *country);
static int geoip6_add_entry (const struct in6_addr *low, const struct in6_addr *high, const char *country);

struct ipv4_node {
       DWORD low;
       DWORD high;
       char  country[3];
     };

struct ipv6_node {
       struct in6_addr low;
       struct in6_addr high;
       char            country[3];
     };

static BOOL use_geoip_generated = FALSE;

/*
 * From Tor's src/common/container.h:
 *
 * A resizeable list of pointers, with associated helpful functionality.
 *
 * The members of this struct are exposed only so that macros and inlines can
 * use them; all access to smartlist internals should go through the functions
 * and macros defined here.
 */
typedef struct smartlist_t {
        /*
         * 'list' (of anything) has enough capacity to store exactly 'capacity'
         * elements before it needs to be resized. Only the first 'num_used'
         * (<= capacity) elements point to valid data.
         */
        void **list;
        int    num_used;
        int    capacity;
      } smartlist_t;

/*
 * All newly allocated smartlists have this capacity.
 * I.e. room for 16 elements in 'smartlist_t::list[]'.
 */
#define SMARTLIST_DEFAULT_CAPACITY  16

/*
 * A smartlist can hold 'INT_MAX' (2147483647) number of
 * elements in 'smartlist_t::list[]'.
 */
#define SMARTLIST_MAX_CAPACITY  INT_MAX

/*
 * Return the number of items in 'sl'.
 */
static int smartlist_len (const smartlist_t *sl)
{
  assert (sl);
  return (sl->num_used);
}

/*
 * Return the 'idx'th element of 'sl'.
 */
static void *smartlist_get (const smartlist_t *sl, int idx)
{
  assert (sl);
  assert (idx >= 0);
  assert (sl->num_used > idx);
  return (sl->list[idx]);
}

/*
 * Allocate and return an empty smartlist.
 */
static smartlist_t *smartlist_new (void)
{
  smartlist_t *sl = malloc (sizeof(*sl));

  if (sl)
  {
    sl->num_used = 0;
    sl->capacity = SMARTLIST_DEFAULT_CAPACITY;
    sl->list = calloc (sizeof(void*), sl->capacity);
  }
  return (sl);
}

/*
 * Deallocate a smartlist. Does not release storage associated with the
 * list's elements.
 */
static void smartlist_free (smartlist_t *sl)
{
  if (sl)
  {
    free (sl->list);
    free (sl);
  }
}

/*
 * Deallocate a smartlist and associated storage in the list's elements.
 */
static void smartlist_free_all (smartlist_t *sl)
{
  if (sl && !use_geoip_generated)
  {
    int i, max = smartlist_len (sl);

    for (i = 0; i < max; i++)
        free (smartlist_get(sl, i));
  }
  smartlist_free (sl);
}

/*
 * Make sure that 'sl' can hold at least 'num' entries.
 */
static void smartlist_ensure_capacity (smartlist_t *sl, size_t num)
{
  assert (num <= SMARTLIST_MAX_CAPACITY);

  if (num > (size_t)sl->capacity)
  {
    size_t higher = (size_t) sl->capacity;

    if (num > SMARTLIST_MAX_CAPACITY/2)
       higher = SMARTLIST_MAX_CAPACITY;
    else
    {
      while (num > higher)
        higher *= 2;
    }
    sl->list = realloc (sl->list, sizeof(void*) * higher);
    memset (sl->list + sl->capacity, 0, sizeof(void*) * (higher - sl->capacity));
    sl->capacity = (int) higher;
  }
}

/*
 * Append element to the end of the list.
 */
static void smartlist_add (smartlist_t *sl, void *element)
{
  smartlist_ensure_capacity (sl, 1 + (size_t)sl->num_used);
  sl->list [sl->num_used++] = element;
}

#if defined(USE_GEOIP_GENERATED)
/*
 * Used to make the smartlists for the fixed arrays 'ipv4_gen_array' and 'ipv6_gen_array'.
 * Since we know their sizes, just allocate the smartlist size once.
 */
static smartlist_t *smartlist_new_fixed (void *start, size_t el_size, unsigned num)
{
  smartlist_t *sl  = malloc (sizeof(*sl));
  char        *ofs = (char*) start;
  size_t       i;

  sl->capacity = num;
  sl->num_used = num;
  sl->list = malloc (sizeof(void*) * sl->capacity);

  for (i = 0; i < num; i++, ofs += el_size)
      sl->list [i] = ofs;
  return (sl);
}
#endif

/*
 * Sort the members of 'sl' into an order defined by
 * the ordering function 'compare', which returns less then 0 if a
 * precedes b, greater than 0 if b precedes a, and 0 if a 'equals' b.
 */
static void smartlist_sort (smartlist_t *sl, int (*compare)(const void **a, const void **b))
{
  if (sl->num_used > 0)
     qsort (sl->list, sl->num_used, sizeof(void*),
            (int (*)(const void *,const void*))compare);
}

/*
 * Assuming the members of 'sl' are in order, return the index of the
 * member that matches 'key'.  If no member matches, return the index of
 * the first member greater than 'key', or 'smartlist_len(sl)' if no member
 * is greater than 'key'.  Set 'found_out to true on a match, to false otherwise.
 * Ordering and matching are defined by a 'compare' function that returns 0 on
 * a match; less than 0 if key is less than member, and greater than 0 if key
 * is greater then member.
 */
int smartlist_bsearch_idx (const smartlist_t *sl, const void *key,
                           int (*compare)(const void *key, const void **member),
                           int *found_out)
{
  int hi, lo, cmp, mid, len, diff;

  assert (sl);
  assert (compare);
  assert (found_out);

  len = smartlist_len (sl);

  /* Check for the trivial case of a zero-length list
   */
  if (len == 0)
  {
    *found_out = 0;

    /* We already know smartlist_len(sl) is 0 in this case
     */
    return (0);
  }

  /* Okay, we have a real search to do
   */
  assert (len > 0);
  lo = 0;
  hi = len - 1;

  /*
   * These invariants are always true:
   *
   * For all i such that 0 <= i < lo, sl[i] < key
   * For all i such that hi < i <= len, sl[i] > key
   */

  while (lo <= hi)
  {
    diff = hi - lo;

    /*
     * We want mid = (lo + hi) / 2, but that could lead to overflow, so
     * instead diff = hi - lo (non-negative because of loop condition), and
     * then hi = lo + diff, mid = (lo + lo + diff) / 2 = lo + (diff / 2).
     */
    mid = lo + (diff / 2);
    cmp = (*compare) (key, (const void**) &(sl->list[mid]));
    if (cmp == 0)
    {
      /* sl[mid] == key; we found it
       */
      *found_out = 1;
      return (mid);
    }
    if (cmp > 0)
    {
      /*
       * key > sl[mid] and an index i such that sl[i] == key must
       * have i > mid if it exists.
       */

      /*
       * Since lo <= mid <= hi, hi can only decrease on each iteration (by
       * being set to mid - 1) and hi is initially len - 1, mid < len should
       * always hold, and this is not symmetric with the left end of list
       * mid > 0 test below.  A key greater than the right end of the list
       * should eventually lead to lo == hi == mid == len - 1, and then
       * we set lo to len below and fall out to the same exit we hit for
       * a key in the middle of the list but not matching.  Thus, we just
       * assert for consistency here rather than handle a mid == len case.
       */
      assert(mid < len);

      /* Move lo to the element immediately after sl[mid]
       */
      lo = mid + 1;
    }
    else
    {
      /* This should always be true in this case
       */
      assert (cmp < 0);

      /*
       * key < sl[mid] and an index i such that sl[i] == key must
       * have i < mid if it exists.
       */

      if (mid > 0)
      {
        /* Normal case, move hi to the element immediately before sl[mid] */
        hi = mid - 1;
      }
      else
      {
        /* These should always be true in this case
         */
        assert (mid == lo);
        assert (mid == 0);

        /*
         * We were at the beginning of the list and concluded that every
         * element e compares e > key.
         */
        *found_out = 0;
        return (0);
      }
    }
  }

  /*
   * lo > hi; we have no element matching key but we have elements falling
   * on both sides of it.  The lo index points to the first element > key.
   */
  assert (lo == hi + 1);  /* All other cases should have been handled */
  assert (lo >= 0);
  assert (lo <= len);
  assert (hi >= 0);
  assert (hi <= len);

  if (lo < len)
  {
    cmp = (*compare) (key, (const void**) &(sl->list[lo]));
    assert (cmp < 0);
  }
  else
  {
    cmp = (*compare) (key, (const void**) &(sl->list[len-1]));
    assert (cmp > 0);
  }

  *found_out = 0;
  return (lo);
}

/*
 * Assuming the members of 'sl' are in order, return a pointer to the
 * member that matches 'key'. Ordering and matching are defined by a
 * 'compare' function that returns 0 on a match; less than 0 if key is
 * less than member, and greater than 0 if key is greater then member.
 */
void *smartlist_bsearch (const smartlist_t *sl, const void *key,
                         int (*compare)(const void *key, const void **member))
{
  int found, idx = smartlist_bsearch_idx (sl, key, compare, &found);

  return (found ? smartlist_get(sl, idx) : NULL);
}

/*
 * Geoip specific stuff.
 */
static smartlist_t *geoip_ipv4_entries = NULL;
static smartlist_t *geoip_ipv6_entries = NULL;

/*
 * smartlist_sort() helper: return -1, 1, or 0 based on comparison of two
 * 'ipv4_node'
 */
static int geoip_ipv4_compare_entries (const void **_a, const void **_b)
{
  const struct ipv4_node *a = *_a;
  const struct ipv4_node *b = *_b;

  if (a->low < b->low)
     return (-1);
  if (a->low > b->low)
     return (1);
  return (0);
}

/*
 * smartlist_bsearch() helper: return -1, 1, or 0 based on comparison of an IP (a pointer
 * to a DWORD in host order) to a 'ipv4_node' element.
 */
static int geoip_ipv4_compare_key_to_entry (const void *key, const void **member)
{
  const struct ipv4_node *entry = *member;
  const DWORD             addr  = *(DWORD*) key;

  if (addr < entry->low)
     return (-1);
  if (addr > entry->high)
     return (1);
  return (0);
}

/*
 * smartlist_sort() helper: return -1, 1, or 0 based on comparison of two
 * 'struct ipv6_node' elements.
 */
static int geoip_ipv6_compare_entries (const void **_a, const void **_b)
{
  const struct ipv6_node *a = *_a;
  const struct ipv6_node *b = *_b;

  return memcmp (a->low.s6_addr, b->low.s6_addr, sizeof(struct in6_addr));
}

/*
 * smartlist_bsearch() helper: return -1, 1, or 0 based on comparison of an IPv6
 * (a pointer to a in6_addr) to a 'struct ipv6_node'.
 */
static int geoip_ipv6_compare_key_to_entry (const void *key, const void **member)
{
  const struct ipv6_node *entry = *member;
  const struct in6_addr  *addr  = (const struct in6_addr*) key;

  if (memcmp(addr->s6_addr, entry->low.s6_addr, sizeof(struct in6_addr)) < 0)
     return (-1);
  if (memcmp(addr->s6_addr, entry->high.s6_addr, sizeof(struct in6_addr)) > 0)
     return (1);
  return (0);
}

/*
 * Add these special addresses to the 'geoip_ipv4_entries' smartlist.
 */
void geoip_ipv4_add_specials (void)
{
  static const struct {
         const char *low;
         const char *high;
       } priv[] = {
         { "0.0.0.0",     "0.255.255.255"   },
         { "10.0.0.0",    "10.255.255.255"  },
         { "127.0.0.0",   "127.255.255.255" },
         { "172.16.0.0",  "172.31.255.255"  },
         { "192.168.0.0", "192.168.255.255" },
         { "224.0.0.0",   "239.255.255.253" }  /* https://en.wikipedia.org/wiki/Multicast_address */
       };
  int i;

  for (i = 0; i < DIM(priv); i++)
  {
    DWORD low, high;

    wsock_trace_inet_pton4 (priv[i].low, (u_char*)&low);
    wsock_trace_inet_pton4 (priv[i].high, (u_char*)&high);
    geoip4_add_entry (swap32(low), swap32(high), "--");
  }
}

/*
 * Add these special addresses to the 'geoip_ipv6_entries' smartlist.
 */
void geoip_ipv6_add_specials (void)
{
  static const struct {
         const char *low;
         const char *high;
       } priv[] = {
         { "::",     "::"       },                                /* IN6_IS_ADDR_UNSPECIFIED() */
         { "::1",    "::1"      },                                /* IN6_IS_ADDR_LOOPBACK() */
         { "f0::",   "f0::ffff" },                                /* !IN6_IS_ADDR_GLOBAL() */
         { "fe80::", "fe80:ffff:ffff:ffff:ffff:ffff:ffff:ffff" }  /* IN6_IS_ADDR_LINKLOCAL() */
       };
  int i;

  for (i = 0; i < DIM(priv); i++)
  {
    struct in6_addr low, high;

    if (wsock_trace_inet_pton6(priv[i].low, (u_char*)&low) != 1)
    {
      TRACE (0, "Illegal low IPv6 address: %s, %d\n", priv[i].low, WSAGetLastError());
      continue;
    }
    if (wsock_trace_inet_pton6(priv[i].high, (u_char*)&high) != 1)
    {
      TRACE (0, "Illegal high IPv6 address: %s, %d\n", priv[i].high, WSAGetLastError());
      continue;
    }
    geoip6_add_entry (&low, &high, "--");
  }
}

/*
 * Open and parse either a GeoIP file with either:
 *   IPv4-address (AF_INET) only or
 *   IPv6-address (AF_INET6) only.
 *
 * Both files are on CVS format.
 */
DWORD geoip_parse_file (const char *file, int family)
{
  unsigned line = 0;
  DWORD    num4 = 0;
  DWORD    num6 = 0;
  FILE    *f;

  TRACE (4, "address-family: %d, file: %s.\n", family, file);

  if (!file || !FILE_EXISTS(file))
  {
    TRACE (2, "Geoip-file \"%s\" does not exist.\n", file);
    return (0);
  }

  if (family == AF_INET)
  {
    assert (geoip_ipv4_entries == NULL);
    geoip_ipv4_entries = smartlist_new();
 // geoip_ipv4_add_specials();
  }
  else if (family == AF_INET6)
  {
    assert (geoip_ipv6_entries == NULL);
    geoip_ipv6_entries = smartlist_new();
 // geoip_ipv6_add_specials();
  }
  else
  {
    TRACE (0, "Only address-families AF_INET and AF_INET6 supported.\n");
    return (0);
  }

  f = fopen (file, "rt");
  if (!f)
  {
    TRACE (2, "Failed to open Geoip-file \"%s\". errno: %d\n", file, errno);
    return (0);
  }

  while (!feof(f))
  {
    char buf[512];
    int  rc;

    if (fgets(buf, (int)sizeof(buf), f) == NULL)
       break;
    if (family == AF_INET)
         rc = geoip4_parse_entry (buf, &line, &num4);
    else rc = geoip6_parse_entry (buf, &line, &num6);
    if (rc < 0)  /* malloc() failed, give up */
       break;
  }

  fclose (f);

  if (family == AF_INET)
  {
    smartlist_sort (geoip_ipv4_entries, geoip_ipv4_compare_entries);
    TRACE (2, "Parsed %lu IPv4 records from \"%s\".\n", num4, file);
    return (num4);
  }
  else
  {
    smartlist_sort (geoip_ipv6_entries, geoip_ipv6_compare_entries);
    TRACE (2, "Parsed %lu IPv6 records from \"%s\".\n", num6, file);
    return (num6);
  }
  return (0);
}

void geoip_exit (void)
{
  smartlist_free_all (geoip_ipv4_entries);
  smartlist_free_all (geoip_ipv6_entries);
  geoip_ipv4_entries = geoip_ipv6_entries = NULL;
}

/*
 * Parse and add a IPv4 entry to the 'geoip_ipv4_entries' smart-list.
 */
static int geoip4_parse_entry (char *buf, unsigned *line, DWORD *num)
{
  char *p = buf;
  char  country[3];
  DWORD low, high;
  int   rc = 0;

  for ( ; *p && isspace((int)*p); )
      p++;

  if (*p == '#' || *p == ';')
  {
    (*line)++;
    return (1);
  }

  if (sscanf(buf,"%lu,%lu,%2s", &low, &high, country) == 3 ||
      sscanf(buf,"\"%lu\",\"%lu\",\"%2s\",", &low, &high, country) == 3)
  {
    rc = geoip4_add_entry (low, high, country);
    (*num)++;
  }
  (*line)++;

  if (rc == 0)
     TRACE (0, "Unable to parse line %u in GEOIP IPv4 file.\n", *line);
  return (rc);
}

/*
 * Parse and add a IPv6 entry to the 'geoip_ipv6_entries' smart-list.
 */
static int geoip6_parse_entry (char *buf, unsigned *line, DWORD *num)
{
  struct in6_addr low, high;
  char           *p = buf;
  char           *country, *low_str, *high_str, *strtok_state;
  int             rc = 0;

  for ( ; *p && isspace((int)*p); )
      p++;

  if (*p == '#' || *p == ';')
  {
    (*line)++;
    return (1);
  }

  low_str = _strtok_r (buf, ",", &strtok_state);
  if (!low_str)
     goto fail;

  high_str = _strtok_r (NULL, ",", &strtok_state);
  if (!high_str)
     goto fail;

  country = _strtok_r (NULL, "\n", &strtok_state);
  if (!country)
     goto fail;

  if (strlen(country) == 2 &&
      wsock_trace_inet_pton6(low_str, (u_char*)&low) == 1 &&
      wsock_trace_inet_pton6(high_str, (u_char*)&high) == 1)
  {
    rc = geoip6_add_entry (&low, &high, country);
    (*num)++;
  }

fail:
  (*line)++;

  if (rc == 0)
     TRACE (0, "Unable to parse line %u in GEOIP IPv6 file.\n", *line);
  return (rc);
}

/*
 * Taken from:
 *   ettercap -- IP address management
 *
 *  Copyright (C) ALoR & NaGA
 *
 * ... and rewritten.
 */

/*
 * return true if an IPv4/IPv6 address is 0.0.0.0 or 0::
 */
int geoip_addr_is_zero (const struct in_addr *ip4, const struct in6_addr *ip6)
{
  if (ip4)
  {
    if (!memcmp(ip4, "\x00\x00\x00\x00", sizeof(*ip4)))
       return (1);
  }
  else if (ip6)
  {
    if (!memcmp(ip6, "\x00\x00\x00\x00\x00\x00\x00\x00"
                     "\x00\x00\x00\x00\x00\x00\x00\x00", sizeof(*ip6)))
       return (1);
  }
  return (0);
}

/*
 * returns 1 if the ip is multicast
 * returns 0 if not
 */
int geoip_addr_is_multicast (const struct in_addr *ip4, const struct in6_addr *ip6)
{
  if (ip4)
  {
    if ((ip4->s_addr & 0xF0) == 0xE0)
       return (1);
  }
  else if (ip6)
  {
    if (ip6->s6_bytes[0] == 0xFF)
       return (1);
  }
  return (0);
}

int geoip_addr_is_special (const struct in_addr *ip4, const struct in6_addr *ip6)
{
  if (ip4)
  {
    /* 240.0.0.0/4, https://whois.arin.net/rest/net/NET-240-0-0-0-0
     */
    if (ip4->S_un.S_un_b.s_b1 >= 240)
       return (1);

    /* 169.254.0.0/16, https://whois.arin.net/rest/net/NET-169-254-0-0-1
     */
    if (ip4->S_un.S_un_b.s_b1 == 169 && ip4->S_un.S_un_b.s_b2 == 254)
       return (1);

    /* 100.64.0.0/10, https://whois.arin.net/rest/net/NET-100-64-0-0-1
     */
    if (ip4->S_un.S_un_b.s_b1 == 100 &&
        (ip4->S_un.S_un_b.s_b2 >= 64 && ip4->S_un.S_un_b.s_b2 <= 127))
       return (1);
  }
  else if (ip6)
  {
    /* \todo */
  }
  return (0);
}

/*
 * returns 1 if the ip is a Global Unicast
 * returns 0 if not
 */
int geoip_addr_is_global (const struct in_addr *ip4, const struct in6_addr *ip6)
{
   if (ip4)
   {
     /* Global for IPv4 means not status "RESERVED" by IANA
      */
     if (ip4->S_un.S_un_b.s_b1 != 0x0  &&                       /* not 0/8        */
         ip4->S_un.S_un_b.s_b1 != 0x7F &&                       /* not 127/8      */
         ip4->S_un.S_un_b.s_b1 != 0x0A &&                       /* not 10/8       */
         (swap16(ip4->S_un.S_un_w.s_w1) & 0xFFF0) != 0xAC10 &&  /* not 172.16/12  */
         swap16(ip4->S_un.S_un_w.s_w1) != 0xC0A8 &&             /* not 192.168/16 */
         !geoip_addr_is_multicast(ip4,NULL))                    /* not 224/3      */
        return (1);
   }
   else if (ip6)
   {
     /*
      * As IANA does not appy masks > 8-bit for Global Unicast block,
      * only the first 8-bit are significant for this test.
      */
     if ((ip6->s6_bytes[0] & 0xE0) == 0x20)
     {
       /*
        * This may be extended in future as IANA assigns further ranges
        * to Global Unicast.
        */
       return (1);
     }
   }
   return (0);
}

static int geoip4_add_entry (DWORD low, DWORD high, const char *country)
{
  struct ipv4_node *entry = malloc (sizeof(*entry));

  if (!entry)
     return (-1);

  entry->low  = low;
  entry->high = high;
  memcpy (&entry->country, country, sizeof(entry->country));
  smartlist_add (geoip_ipv4_entries, entry);
  return (1);
}

static int geoip6_add_entry (const struct in6_addr *low, const struct in6_addr *high, const char *country)
{
  struct ipv6_node *entry = malloc (sizeof(*entry));

  if (!entry)
     return (-1);

  memcpy (&entry->low,  low,  sizeof(entry->low));
  memcpy (&entry->high, high, sizeof(entry->high));
  memcpy (&entry->country, country, sizeof(entry->country));
  smartlist_add (geoip_ipv6_entries, entry);
  return (1);
}

/*
 * To compile a version of geoip.c using '-DUSE_GEOIP_GENERATED', is
 * bit of an "chicken and egg" problem. These 2 commands:
 *   geoip.exe -g4 > geoip-gen4.c
 *   geoip.exe -g6 > geoip-gen6.c
 *
 * will generate these files. Then geoip.c must be compiled again with
 * '-DUSE_GEOIP_GENERATED' to make use of this faster feature.
 */
#if defined(USE_GEOIP_GENERATED)
  #include "geoip-gen4.c"
  #include "geoip-gen6.c"
#endif

/*
 * Given an IPv4 address on network order, return an ISO-3166 2 letter
 * Country-code representing the country to which that address
 * belongs, or NULL for "No geoip information available".
 *
 * To decode it, call 'geoip_get_long_name_by_A2()'.
 */
const char *geoip_get_country_by_ipv4 (const struct in_addr *addr)
{
  struct ipv4_node *entry = NULL;
  DWORD    ip_num = swap32 (addr->s_addr);
  char     buf [25];
  unsigned num = geoip_ipv4_entries ? smartlist_len (geoip_ipv4_entries) : 0;

  TRACE (5, "Looking for %s (%lu) in %u elements.\n",
         wsock_trace_inet_ntop4((const u_char*)addr,buf,sizeof(buf)),
         ip_num, num);

  if (geoip_ipv4_entries)
     entry = smartlist_bsearch (geoip_ipv4_entries, &ip_num,
                                geoip_ipv4_compare_key_to_entry);

  return (entry ? entry->country : NULL);
}

/*
 * Given an IPv6 address,  return an ISO-3166 2 letter Country-code
 * representing the country to which that address belongs, or NULL for
 * "No geoip information available".
 *
 * To decode it, call 'geoip_get_long_name_by_A2()'.
 */
const char *geoip_get_country_by_ipv6 (const struct in6_addr *addr)
{
  struct ipv6_node *entry = NULL;
  char     buf [MAX_IP6_SZ];
  unsigned num = geoip_ipv6_entries ? smartlist_len (geoip_ipv6_entries) : 0;

  TRACE (5, "Looking for %s in %u elements.\n",
         wsock_trace_inet_ntop6((const u_char*)addr,buf,sizeof(buf)), num);

   if (geoip_ipv6_entries)
      entry = smartlist_bsearch (geoip_ipv6_entries, addr,
                                 geoip_ipv6_compare_key_to_entry);

  return (entry ? entry->country : NULL);
}

int geoip_get_n_countries (DWORD *num4, DWORD *num6)
{
  if (num4 && geoip_ipv4_entries)
     *num4 = smartlist_len (geoip_ipv4_entries);

  if (num6 && geoip_ipv6_entries)
     *num6 = smartlist_len (geoip_ipv6_entries);

  if (!geoip_ipv4_entries && !geoip_ipv6_entries)
     return (0);

  return (1);
}

struct country_list {
       int         country_number; /* ISO-3166 country number */
       char        short_name[3];  /* A2 short country code */
       const char *long_name;      /* normal country name */
     };

/*
 * Ref: ftp://ftp.ripe.net/iso3166-countrycodes.txt
 */
static const struct country_list c_list[] = {
       {   4, "af", "Afghanistan"                          },
       { 248, "ax", "Åland Island"                         },
       {   8, "al", "Albania"                              },
       {  12, "dz", "Algeria"                              },
       {  16, "as", "American Samoa"                       },
       {  20, "ad", "Andorra"                              },
       {  24, "ao", "Angola"                               },
       { 660, "ai", "Anguilla"                             },
       {  10, "aq", "Antarctica"                           },
       {  28, "ag", "Antigua & Barbuda"                    },
       {  32, "ar", "Argentina"                            },
       {  51, "am", "Armenia"                              },
       { 533, "aw", "Aruba"                                },
       {  36, "au", "Australia"                            },
       {  40, "at", "Austria"                              },
       {  31, "az", "Azerbaijan"                           },
       {  44, "bs", "Bahamas"                              },
       {  48, "bh", "Bahrain"                              },
       {  50, "bd", "Bangladesh"                           },
       {  52, "bb", "Barbados"                             },
       { 112, "by", "Belarus"                              },
       {  56, "be", "Belgium"                              },
       {  84, "bz", "Belize"                               },
       { 204, "bj", "Benin"                                },
       {  60, "bm", "Bermuda"                              },
       {  64, "bt", "Bhutan"                               },
       {  68, "bo", "Bolivia"                              },
       { 535, "bq", "Bonaire"                              },
       {  70, "ba", "Bosnia & Herzegowina"                 },
       {  72, "bw", "Botswana"                             },
       {  74, "bv", "Bouvet Island"                        },
       {  76, "br", "Brazil"                               },
       {  86, "io", "British Indian Ocean Territory"       },
       {  96, "bn", "Brunei Darussalam"                    },
       { 100, "bg", "Bulgaria"                             },
       { 854, "bf", "Burkina Faso"                         },
       { 108, "bi", "Burundi"                              },
       { 116, "kh", "Cambodia"                             },
       { 120, "cm", "Cameroon"                             },
       { 124, "ca", "Canada"                               },
       { 132, "cv", "Cape Verde"                           },
       { 136, "ky", "Cayman Islands"                       },
       { 140, "cf", "Central African Republic"             },
       { 148, "td", "Chad"                                 },
       { 152, "cl", "Chile"                                },
       { 156, "cn", "China"                                },
       { 162, "cx", "Christmas Island"                     },
       { 166, "cc", "Cocos Islands"                        },
       { 170, "co", "Colombia"                             },
       { 174, "km", "Comoros"                              },
       { 178, "cg", "Congo"                                },
       { 180, "cd", "Congo"                                },
       { 184, "ck", "Cook Islands"                         },
       { 188, "cr", "Costa Rica"                           },
       { 384, "ci", "Cote d'Ivoire"                        },
       { 191, "hr", "Croatia"                              },
       { 192, "cu", "Cuba"                                 },
       { 531, "cw", "Curaçao"                              },
       { 196, "cy", "Cyprus"                               },
       { 203, "cz", "Czech Republic"                       },
       { 208, "dk", "Denmark"                              },
       { 262, "dj", "Djibouti"                             },
       { 212, "dm", "Dominica"                             },
       { 214, "do", "Dominican Republic"                   },
       { 218, "ec", "Ecuador"                              },
       { 818, "eg", "Egypt"                                },
       { 222, "sv", "El Salvador"                          },
       { 226, "gq", "Equatorial Guinea"                    },
       { 232, "er", "Eritrea"                              },
       { 233, "ee", "Estonia"                              },
       { 231, "et", "Ethiopia"                             },
     { 65281, "eu", "European Union"                       }, /* 127.0.255.1 */
       { 238, "fk", "Falkland Islands"                     },
       { 234, "fo", "Faroe Islands"                        },
       { 242, "fj", "Fiji"                                 },
       { 246, "fi", "Finland"                              },
       { 250, "fr", "France"                               },
       { 249, "fx", "France, Metropolitan"                 },
       { 254, "gf", "French Guiana"                        },
       { 258, "pf", "French Polynesia"                     },
       { 260, "tf", "French Southern Territories"          },
       { 266, "ga", "Gabon"                                },
       { 270, "gm", "Gambia"                               },
       { 268, "ge", "Georgia"                              },
       { 276, "de", "Germany"                              },
       { 288, "gh", "Ghana"                                },
       { 292, "gi", "Gibraltar"                            },
       { 300, "gr", "Greece"                               },
       { 304, "gl", "Greenland"                            },
       { 308, "gd", "Grenada"                              },
       { 312, "gp", "Guadeloupe"                           },
       { 316, "gu", "Guam"                                 },
       { 320, "gt", "Guatemala"                            },
       { 831, "gg", "Guernsey"                             },
       { 324, "gn", "Guinea"                               },
       { 624, "gw", "Guinea-Bissau"                        },
       { 328, "gy", "Guyana"                               },
       { 332, "ht", "Haiti"                                },
       { 334, "hm", "Heard & Mc Donald Islands"            },
       { 336, "va", "Vatican City"                         },
       { 340, "hn", "Honduras"                             },
       { 344, "hk", "Hong kong"                            },
       { 348, "hu", "Hungary"                              },
       { 352, "is", "Iceland"                              },
       { 356, "in", "India"                                },
       { 360, "id", "Indonesia"                            },
       { 364, "ir", "Iran"                                 },
       { 368, "iq", "Iraq"                                 },
       { 372, "ie", "Ireland"                              },
       { 833, "im", "Isle of Man"                          },
       { 376, "il", "Israel"                               },
       { 380, "it", "Italy"                                },
       { 388, "jm", "Jamaica"                              },
       { 392, "jp", "Japan"                                },
       { 832, "je", "Jersey"                               },
       { 400, "jo", "Jordan"                               },
       { 398, "kz", "Kazakhstan"                           },
       { 404, "ke", "Kenya"                                },
       { 296, "ki", "Kiribati"                             },
       { 408, "kp", "Korea (north)"                        },
       { 410, "kr", "Korea (south)"                        },
       {   0, "xk", "Kosovo"                               },  /* https://en.wikipedia.org/wiki/ISO_3166-1_alpha-2 */
       { 414, "kw", "Kuwait"                               },
       { 417, "kg", "Kyrgyzstan"                           },
       { 418, "la", "Laos"                                 },
       { 428, "lv", "Latvia"                               },
       { 422, "lb", "Lebanon"                              },
       { 426, "ls", "Lesotho"                              },
       { 430, "lr", "Liberia"                              },
       { 434, "ly", "Libya"                                },
       { 438, "li", "Liechtenstein"                        },
       { 440, "lt", "Lithuania"                            },
       { 442, "lu", "Luxembourg"                           },
       { 446, "mo", "Macao"                                },
       { 807, "mk", "Macedonia"                            },
       { 450, "mg", "Madagascar"                           },
       { 454, "mw", "Malawi"                               },
       { 458, "my", "Malaysia"                             },
       { 462, "mv", "Maldives"                             },
       { 466, "ml", "Mali"                                 },
       { 470, "mt", "Malta"                                },
       { 584, "mh", "Marshall Islands"                     },
       { 474, "mq", "Martinique"                           },
       { 478, "mr", "Mauritania"                           },
       { 480, "mu", "Mauritius"                            },
       { 175, "yt", "Mayotte"                              },
       { 484, "mx", "Mexico"                               },
       { 583, "fm", "Micronesia"                           },
       { 498, "md", "Moldova"                              },
       { 492, "mc", "Monaco"                               },
       { 496, "mn", "Mongolia"                             },
       { 499, "me", "Montenegro"                           },
       { 500, "ms", "Montserrat"                           },
       { 504, "ma", "Morocco"                              },
       { 508, "mz", "Mozambique"                           },
       { 104, "mm", "Myanmar"                              },
       { 516, "na", "Namibia"                              },
       { 520, "nr", "Nauru"                                },
       { 524, "np", "Nepal"                                },
       { 528, "nl", "Netherlands"                          },
       { 530, "an", "Netherlands Antilles"                 },
       { 540, "nc", "New Caledonia"                        },
       { 554, "nz", "New Zealand"                          },
       { 558, "ni", "Nicaragua"                            },
       { 562, "ne", "Niger"                                },
       { 566, "ng", "Nigeria"                              },
       { 570, "nu", "Niue"                                 },
       { 574, "nf", "Norfolk Island"                       },
       { 580, "mp", "Northern Mariana Islands"             },
       { 578, "no", "Norway"                               },
       { 512, "om", "Oman"                                 },
       { 586, "pk", "Pakistan"                             },
       { 585, "pw", "Palau"                                },
       { 275, "ps", "Palestinian Territory"                },
       { 591, "pa", "Panama"                               },
       { 598, "pg", "Papua New Guinea"                     },
       { 600, "py", "Paraguay"                             },
       { 604, "pe", "Peru"                                 },
       { 608, "ph", "Philippines"                          },
       { 612, "pn", "Pitcairn"                             },
       { 616, "pl", "Poland"                               },
       { 620, "pt", "Portugal"                             },
       { 630, "pr", "Puerto Rico"                          },
       { 634, "qa", "Qatar"                                },
       { 638, "re", "Reunion"                              },
       { 642, "ro", "Romania"                              },
       { 643, "ru", "Russia"                               },
       { 646, "rw", "Rwanda"                               },
       { 0,   "bl", "Saint Barthélemy"                     }, /* https://en.wikipedia.org/wiki/ISO_3166-2:BL */
       { 659, "kn", "Saint Kitts & Nevis"                  },
       { 662, "lc", "Saint Lucia"                          },
       { 663, "mf", "Saint Martin"                         },
       { 670, "vc", "Saint Vincent"                        },
       { 882, "ws", "Samoa"                                },
       { 674, "sm", "San Marino"                           },
       { 678, "st", "Sao Tome & Principe"                  },
       { 682, "sa", "Saudi Arabia"                         },
       { 686, "sn", "Senegal"                              },
       { 688, "rs", "Serbia"                               },
       { 690, "sc", "Seychelles"                           },
       { 694, "sl", "Sierra Leone"                         },
       { 702, "sg", "Singapore"                            },
       { 534, "sx", "Sint Maarten"                         },
       { 703, "sk", "Slovakia"                             },
       { 705, "si", "Slovenia"                             },
       {  90, "sb", "Solomon Islands"                      },
       { 706, "so", "Somalia"                              },
       { 710, "za", "South Africa"                         },
       { 239, "gs", "South Georgia"                        },
       { 728, "ss", "South Sudan"                          },
       { 724, "es", "Spain"                                },
       { 144, "lk", "Sri Lanka"                            },
       { 654, "sh", "St. Helena"                           },
       { 666, "pm", "St. Pierre & Miquelon"                },
       { 736, "sd", "Sudan"                                },
       { 740, "sr", "Suriname"                             },
       { 744, "sj", "Svalbard & Jan Mayen Islands"         },
       { 748, "sz", "Swaziland"                            },
       { 752, "se", "Sweden"                               },
       { 756, "ch", "Switzerland"                          },
       { 760, "sy", "Syrian Arab Republic"                 },
       { 626, "tl", "Timor-Leste"                          },
       { 158, "tw", "Taiwan"                               },
       { 762, "tj", "Tajikistan"                           },
       { 834, "tz", "Tanzania"                             },
       { 764, "th", "Thailand"                             },
       { 768, "tg", "Togo"                                 },
       { 772, "tk", "Tokelau"                              },
       { 776, "to", "Tonga"                                },
       { 780, "tt", "Trinidad & Tobago"                    },
       { 788, "tn", "Tunisia"                              },
       { 792, "tr", "Turkey"                               },
       { 795, "tm", "Turkmenistan"                         },
       { 796, "tc", "Turks & Caicos Islands"               },
       { 798, "tv", "Tuvalu"                               },
       { 800, "ug", "Uganda"                               },
       { 804, "ua", "Ukraine"                              },
       { 784, "ae", "United Arab Emirates"                 },
       { 826, "gb", "United Kingdom"                       },
       { 840, "us", "United States"                        },
       { 581, "um", "United States Minor Outlying Islands" },
       { 858, "uy", "Uruguay"                              },
       { 860, "uz", "Uzbekistan"                           },
       { 548, "vu", "Vanuatu"                              },
       { 862, "ve", "Venezuela"                            },
       { 704, "vn", "Vietnam"                              },
       {  92, "vg", "Virgin Islands (British)"             },
       { 850, "vi", "Virgin Islands (US)"                  },
       { 876, "wf", "Wallis & Futuna Islands"              },
       { 732, "eh", "Western Sahara"                       },
       { 887, "ye", "Yemen"                                },
       { 894, "zm", "Zambia"                               },
       { 716, "zw", "Zimbabwe"                             }
     };

const char *geoip_get_long_name_by_A2 (const char *short_name)
{
  const struct country_list *list = c_list + 0;
  size_t i, num = DIM(c_list);

  if (!short_name)
     return ("?");

  for (i = 0; i < num; i++, list++)
  {
    if (!strnicmp(list->short_name,short_name, sizeof(list->short_name)))
       return (list->long_name);
  }
  return (NULL);
}

const char *geoip_get_long_name_by_id (int number)
{
  const struct country_list *list = c_list + 0;
  size_t i, num = DIM(c_list);

  /* Since several countries above have no assigned number, we cannot return a
   * sensible name.
   */
  if (number == 0)
     return ("?");

  for (i = 0; i < num; i++, list++)
  {
    if (list->country_number == number)
       return (list->long_name);
  }
  return (NULL);
}

/*
 * Download a single file using the WinInet API.
 * Load WinInet.dll dynamically.
 */
typedef HINTERNET (WINAPI *func_InternetOpenA) (const char *user_agent,
                                                DWORD       dwAccessType,
                                                const char *lpszProxyName,
                                                const char *lpszProxyBypass,
                                                DWORD       dwFlags);

typedef HINTERNET (WINAPI *func_InternetOpenUrlA) (HINTERNET   hInternet,
                                                   const char *lpszUrl,
                                                   const char *lpszHeaders,
                                                   DWORD       dwHeadersLength,
                                                   DWORD       dwFlags,
                                                   DWORD_PTR   dwContext);

typedef BOOL (WINAPI *func_InternetReadFile) (HINTERNET hFile,
                                              VOID    *lpBuffer,
                                              DWORD     dwNumberOfBytesToRead,
                                              DWORD   *lpdwNumberOfBytesRead);

typedef BOOL (WINAPI *func_InternetCloseHandle) (HINTERNET handle);

static func_InternetOpenA        p_InternetOpenA;
static func_InternetOpenUrlA     p_InternetOpenUrlA;
static func_InternetReadFile     p_InternetReadFile;
static func_InternetCloseHandle  p_InternetCloseHandle;

#define ADD_VALUE(func)   { 0, NULL, "wininet.dll", #func, (void**)&p_##func }

static struct LoadTable funcs[] = {
                 ADD_VALUE (InternetOpenA),
                 ADD_VALUE (InternetOpenUrlA),
                 ADD_VALUE (InternetReadFile),
                 ADD_VALUE (InternetCloseHandle)
               };

static DWORD download_file (const char *file, const char *url)
{
  DWORD rc = 0;
  DWORD flags = INTERNET_FLAG_IGNORE_REDIRECT_TO_HTTP |
                INTERNET_FLAG_IGNORE_REDIRECT_TO_HTTPS |
                INTERNET_FLAG_NO_UI;
  HINTERNET h1, h2;
  FILE     *fil;

  if (load_dynamic_table(funcs, DIM(funcs)) != DIM(funcs))
  {
    TRACE (2, "Failed to load needed WinInet.dll functions.\n");
    return (0);
  }

  h1  = (*p_InternetOpenA) ("GeoIP-update", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
  h2  = (*p_InternetOpenUrlA) (h1, url, NULL, 0, flags, (DWORD_PTR)0);
  fil = fopen (file, "w+t");

  while (1)
  {
    char  buf [4000];
    DWORD read = 0;

    if (!(*p_InternetReadFile)(h2, &buf, sizeof(buf), &read) || read == 0)
       break;
    fwrite (buf, 1, (size_t)read, fil);
    rc += read;
  }
  fclose (fil);
  (*p_InternetCloseHandle) (h2);
  (*p_InternetCloseHandle) (h1);

  unload_dynamic_table (funcs, DIM(funcs));
  return (rc);
}

static int touch_file (const char *file)
{
  struct stat st;
  int    rc;

  stat (file, &st);
  TRACE (2, "touch_file: %s", ctime(&st.st_mtime));
  rc = _utime (file, NULL);
  stat (file, &st);
  TRACE (2, "         -> %s", ctime(&st.st_mtime));
  return (rc);
}

/*
 * Figure out if a download is needed.
 */
static DWORD update_file (const char *loc_file, const char *tmp_file, const char *url, BOOL force_update)
{
  struct stat st_tmp,  st_loc;
  BOOL       _st_tmp, _st_loc, equal = FALSE;
  time_t      now  = time (NULL);
  time_t      past = now - 24 * 3600 * g_cfg.geoip_max_days;
  DWORD       rc = 0;

  _st_tmp = (stat(tmp_file, &st_tmp) == 0);
  _st_loc = (stat(loc_file, &st_loc) == 0);

  TRACE (1, "updating \"%s\"\n", loc_file);

  if (!force_update && _st_loc && st_loc.st_mtime >= past)
  {
    TRACE (1, "update not needed for \"%s\". Try again in %ld days.\n",
           loc_file, g_cfg.geoip_max_days + (now-st_loc.st_mtime)/(24*3600));
    return (rc);
  }

  if (!_st_tmp)
  {
    rc = download_file (tmp_file, url);
    TRACE (1, "download_file (%s) -> rc: %lu\n", tmp_file, rc);
    if (rc > 0)
       _st_tmp = (stat(tmp_file, &st_tmp) == 0);
  }

  if (_st_loc)
  {
    equal = (st_tmp.st_mtime >= st_loc.st_mtime) && (st_tmp.st_size == st_loc.st_size);
    TRACE (1, "local file exist, equal: %d\n", equal);
    touch_file (loc_file);
  }

  if ((_st_tmp && !_st_loc) || !equal)
  {
    TRACE (1, "%s -> %s\n", tmp_file, loc_file);
    CopyFile (tmp_file, loc_file, FALSE);
    stat (loc_file, &st_loc);
    rc = st_loc.st_size;
  }
  return (rc);
}

/*
 * Check and download files from:
 *   g_cfg.geoip4_url = https://gitweb.torproject.org/tor.git/plain/src/config/geoip   (if 'family == AF_INET')
 *   g_cfg.geoip6_url = https://gitweb.torproject.org/tor.git/plain/src/config/geoip6  (if 'family == AF_INET6')
 */
void geoip_update_file (int family, BOOL force_update)
{
  char        tmp_file [MAX_PATH];
  const char *env = getenv ("TEMP");

  if (family == AF_INET)
  {
    snprintf (tmp_file, sizeof(tmp_file), "%s\\%s", env, "geoip.tmp");
    update_file (g_cfg.geoip4_file, tmp_file, g_cfg.geoip4_url, force_update);
  }
  else if (family == AF_INET6)
  {
    snprintf (tmp_file, sizeof(tmp_file), "%s\\%s", env, "geoip6.tmp");
    update_file (g_cfg.geoip6_file, tmp_file, g_cfg.geoip6_url, force_update);
  }
  else
    TRACE (0, "Unknown address-family %d\n", family);
}

#if defined(TEST_GEOIP)

#if !defined(USE_FWRITE)
#error "Define -DUSE_FWRITE while compiling geoip.c."
#endif

#include "getopt.h"

/*
 * Determine length of the network part in an IPv4 address.
 * Courtesey of 'Lev Walkin <vlm@lionet.info>'.
 */
static int network_len32 (DWORD hi, DWORD lo)
{
  DWORD m = (hi - lo);

  m = (m & 0x55555555) + ((m & 0xAAAAAAAA) >> 1);
  m = (m & 0x33333333) + ((m & 0xCCCCCCCC) >> 2);
  m = (m & 0x0F0F0F0F) + ((m & 0xF0F0F0F0) >> 4);
  m = (m & 0x00FF00FF) + ((m & 0xFF00FF00) >> 8);
  m = (m & 0x0000FFFF) + ((m & 0xFFFF0000) >> 16);
  return (m);
}

/*
 * Figure out the prefix length by checking the common '1's in each
 * of the 16 BYTEs in IPv6-addresses '*a' and '*b'.
 */
static int network_len128 (const struct in6_addr *a, const struct in6_addr *b)
{
  int  i, j, bits = 0;
  BYTE v;

  for (i = 15; i >= 0; i--)
  {
    v = (a->s6_bytes[i] ^ b->s6_bytes[i]);
    for (j = 0; j < 8; j++, bits++)
        if ((v & (1 << j)) == 0)
           goto quit;
  }
quit:
  return (128 - bits);
}

static int check_ipv4_unallocated (FILE *out, int dump_cidr, const struct ipv4_node *entry, const struct ipv4_node *last, long *diff_p)
{
  long diff = (long)(entry->low - last->high);
  int  len;

  if (diff > 1)
  {
    fprintf (out, "    **: ");
    if (dump_cidr)
    {
      char  low[25] = "?";
      int   nw_len = network_len32 (last->high+1, entry->low-1);
      DWORD addr   = swap32 (last->high+1);

      wsock_trace_inet_ntop4 ((const u_char*)&addr, low, sizeof(low));
      len = fprintf (out, "%s/%d", low, nw_len);
    }
    else
    {
      fprintf (out, "%10lu  %10lu %8ld", last->high+1, entry->low-1, diff);
      len = 22;
    }
    fprintf (out, "%*sUnallocated block\n", 24-len, "");
    *diff_p = diff;
    return (1);
  }
  return (0);
}

static void dump_ipv4_entries (FILE *out, int dump_cidr, int raw)
{
  int i, len, max = smartlist_len (geoip_ipv4_entries);
  DWORD missing_blocks = 0;
  DWORD missing_addr = 0;
  long  diff = 0;
  const struct ipv4_node *last = NULL;

  if (!raw)
  {
    fputs ("IPv4 entries:\n Index: ", out);
    if (dump_cidr)
         fputs ("CIDR                    Country\n", out);
    else fputs ("  IP-low      IP-high      Diff  Country\n", out);
  }

  for (i = 0; i < max; i++)
  {
    const struct ipv4_node *entry = smartlist_get (geoip_ipv4_entries, i);

    if (!raw && last)
    {
      missing_blocks += check_ipv4_unallocated (out, dump_cidr, entry, last, &diff);
      missing_addr   += (DWORD)diff;
    }
    last = entry;

    if (dump_cidr)
    {
      char  low[25] = "?";
      int   nw_len = network_len32 (entry->high, entry->low);
      DWORD addr   = swap32 (entry->low);

      wsock_trace_inet_ntop4 ((const u_char*)&addr, low, sizeof(low));
      len = fprintf (out, "%6d: %s/%d", i, low, nw_len);
    }
    else
    {
      if (raw)
           fprintf (out, "  { %10lu, %10lu, ", entry->low, entry->high);
      else fprintf (out, "%6d: %10lu  %10lu %8ld",
                    i, entry->low, entry->high, (long)(entry->high - entry->low));
      len = 30;
    }
    if (raw)
         fprintf (out, " \"%.2s\" },\n", entry->country);
    else fprintf (out, " %*s %.2s - %s\n", 30-len, "", entry->country, geoip_get_long_name_by_A2(entry->country));
  }

  if (!raw)
  {
    fprintf (out, "%s missing blocks ", dword_str(missing_blocks));
    fprintf (out, "totalling %s missing IPv4 addresses.\n", dword_str(missing_addr));
  }
}

static void hex_dump (FILE *out, const void *data_p, size_t datalen)
{
  const BYTE *data = (const BYTE*) data_p;
  UINT  i;

  for (i = 0; i < datalen; i++)
  {
    fprintf (out, "0x%02X", (unsigned)data[i]);
    if (i < datalen-1)
       fputc (',', out);
  }
}

static int check_ipv6_unallocated (FILE *out, int dump_cidr, const struct ipv6_node *entry, const struct ipv6_node *last, uint64 *diff_p)
{
#if 0
  uint64 diff = (long)(entry->low - last->high);
  int    len;

  if (diff > 1)
  {
    fprintf (out, "    **: ");
    if (dump_cidr)
    {
      char  low[25] = "?";
      int   nw_len = network_len32 (last->high+1, entry->low-1);
      DWORD addr   = swap32 (last->high+1);

      wsock_trace_inet_ntop4 ((const u_char*)&addr, low, sizeof(low));
      len = fprintf (out, "%s/%d", low, nw_len);
    }
    else
    {
      fprintf (out, "%10lu  %10lu %8ld", last->high+1, entry->low-1, diff);
      len = 22;
    }
    fprintf (out, "%*sUnallocated block\n", 24-len, "");
    *diff_p = diff;
    return (1);
  }
#endif
  *diff_p = 0;
  return (0);
}

static void dump_ipv6_entries (FILE *out, int dump_cidr, int raw)
{
  int i, len, max = smartlist_len (geoip_ipv6_entries);
  uint64 missing_blocks = 0;
  uint64 missing_addr = 0;
  uint64 diff;
  const struct ipv6_node *last = NULL;

  if (!raw)
  {
    fputs ("IPv6 entries:\nIndex: ", out);

    if (dump_cidr)
         fprintf (out, "%-*s Country\n", MAX_IP6_SZ-5, "CIDR");
    else fprintf (out, "%-*s %-*s Country\n", MAX_IP6_SZ-4, "IP-low", MAX_IP6_SZ-5, "IP-high");
  }

  for (i = 0; i < max; i++)
  {
    const struct ipv6_node *entry = smartlist_get (geoip_ipv6_entries, i);
    char low  [MAX_IP6_SZ] = "?";
    char high [MAX_IP6_SZ] = "?";
    int  nw_len;

    if (!raw && last)
    {
      missing_blocks += check_ipv6_unallocated (out, dump_cidr, entry, last, &diff);
      missing_addr   += diff;
    }
    last = entry;

    wsock_trace_inet_ntop6 ((const u_char*)&entry->low, low, sizeof(low));
    wsock_trace_inet_ntop6 ((const u_char*)&entry->high, high, sizeof(high));

    if (raw)
    {
      fputs (" { {", out);
      hex_dump (out, &entry->low, sizeof(entry->low));
      fputs ("},\n"
             "   {", out);
      hex_dump (out, &entry->high, sizeof(entry->high));
      fputs ("}, ", out);
    }
    else if (dump_cidr)
    {
#if 0
      char *end = low + strlen(low);

      if (!strncmp(end-2,"::",2))   /* Drop the last "::" */
         end[-2] = '\0';
#endif
      nw_len = network_len128 (&entry->high, &entry->low);
      len = fprintf (out, "%5d: %s/%d ", i, low, nw_len);
    }
    else
    {
      fprintf (out, "%5d: %-*s %-*s", i, MAX_IP6_SZ-4, low, MAX_IP6_SZ-4, high);
      len = 50;
    }

    if (raw)
         fprintf (out, "\"%s\" },\n", entry->country);
    else fprintf (out, "%*.2s - %s\n", 51-len, entry->country, geoip_get_long_name_by_A2(entry->country));
  }

  if (!raw)
  {
    fprintf (out, "%s missing blocks ", qword_str(missing_blocks));
    fprintf (out, "totalling %s missing IPv6 addresses.\n", qword_str(missing_addr));
  }
}

static void dump_num_ip_blocks_by_country (void)
{
  const struct country_list *list = c_list + 0;
  size_t                     i, num_c = DIM(c_list);
  size_t                    *counts4 = alloca (sizeof(*counts4) * num_c);
  size_t                    *counts6 = alloca (sizeof(*counts6) * num_c);

  memset (counts4, 0, sizeof(*counts4) * num_c);
  memset (counts6, 0, sizeof(*counts6) * num_c);

  puts ("IPv4/6 blocks by countries:\n"
        " Idx: Country                           IPv4   IPv6");

  if (geoip_ipv4_entries)
     for (i = 0; i < num_c; i++, list++)
     {
       int j, max = smartlist_len (geoip_ipv4_entries);

       for (j = 0; j < max; j++)
       {
         const struct ipv4_node *entry = smartlist_get (geoip_ipv4_entries, j);
         if (!strnicmp(entry->country, list->short_name, 2))
         {
           counts4[i]++;
        // tot_ip_counts[i] += entry->high - entry->low;
         }
       }
     }

  list = c_list + 0;

  if (geoip_ipv6_entries)
     for (i = 0; i < num_c; i++, list++)
     {
       int j, max = smartlist_len (geoip_ipv6_entries);

       for (j = 0; j < max; j++)
       {
         const struct ipv6_node *entry = smartlist_get (geoip_ipv6_entries, j);
         if (!strnicmp(entry->country, list->short_name, 2))
            counts6[i]++;
       }
     }

  list = c_list + 0;

  for (i = 0; i < num_c; i++, list++)
      printf (" %3d: %c%c, %-28.28s %5u  %5u\n",
              i, toupper(list->short_name[0]), toupper(list->short_name[1]),
              list->long_name, counts4[i], counts6[i]);
  puts ("");
}

static void test_addr4 (const char *ip4_addr)
{
  struct in_addr addr;

  printf ("%s(): ", __FUNCTION__);

  if (wsock_trace_inet_pton4((const char*)ip4_addr, (u_char*)&addr) == 1)
  {
    const char *comment = "";
    const char *cc = geoip_get_country_by_ipv4 (&addr);

    if (cc)
       printf ("cc: %s, %s.\n", cc, geoip_get_long_name_by_A2(cc));
    else
    {
      if (geoip_addr_is_zero(&addr,NULL))
         comment = "NULL-addr.";
      else if (geoip_addr_is_multicast(&addr,NULL))
         comment = "Multicast.";
      else if (geoip_addr_is_special(&addr,NULL))
         comment = "Special.";
      else if (!geoip_addr_is_global(&addr,NULL))
         comment = "Not global.";
      puts (comment);
    }
  }
  else
    puts ("Invalid address.");
}

static void test_addr6 (const char *ip6_addr)
{
  struct in6_addr addr;

  printf ("%s(): ", __FUNCTION__);

  if (wsock_trace_inet_pton6(ip6_addr,(u_char*)&addr) == 1)
  {
    const char *comment = "";
    const char *cc = geoip_get_country_by_ipv6 (&addr);

    if (cc)
       printf ("cc: %s, %s.\n", cc, geoip_get_long_name_by_A2(cc));
    else
    {
      if (geoip_addr_is_zero(NULL,&addr))
         comment = "NULL-addr.";
      else if (geoip_addr_is_multicast(NULL,&addr))
         comment = "Multicast.";
      else if (geoip_addr_is_special(NULL,&addr))
         comment = "Special.";
      else if (!geoip_addr_is_global(NULL,&addr))
         comment = "Not global.";
      puts (comment);
    }
  }
  else
    puts ("Invalid address.");
}

#if !defined(USE_GEOIP_GENERATED)
static void geoip_generate_array (int family, const char *out_file)
{
  int    len, fam;
  time_t now = time (NULL);
  FILE  *out = fopen (out_file, "w+t");

  if (!out)
  {
    printf ("Failed to create file %s; %s\n", out_file, strerror(errno));
    return;
  }

  if (family == AF_INET && geoip_ipv4_entries)
  {
    len = smartlist_len (geoip_ipv4_entries);
    fam = '4';
  }
  else if (family == AF_INET6 && geoip_ipv6_entries)
  {
    len = smartlist_len (geoip_ipv6_entries);
    fam = '6';
  }
  else
  {
    printf ("'family must be AF_INET or AF_INET6.\n");
    return;
  }

  fprintf (out,
           "/*\n"
           " * This file was generated at %.24s.\n"
           " * by the Makefile command: \"geoip.exe -%cg %s\"\n"
           " * DO NOT EDIT!\n"
           " */\n", ctime(&now), fam, out_file);

  fprintf (out, "static struct ipv%c_node ipv%c_gen_array [%d] = {\n", fam, fam, len);

  if (family == AF_INET)
       dump_ipv4_entries (out, 0, 1);
  else dump_ipv6_entries (out, 0, 1);

  fprintf (out,
           "};\n"
           "\n"
           "static smartlist_t *smartlist_new_fixed_ipv%c (void)\n"
           "{\n"
           "  return smartlist_new_fixed (&ipv%c_gen_array, sizeof(ipv%c_gen_array[0]), %d);\n"
           "}\n\n", fam, fam, fam, len);
  fclose (out);
}
#endif  /* USE_GEOIP_GENERATED */

/*
 * A random integer in range [a..b].
 *   http://stackoverflow.com/questions/2509679/how-to-generate-a-random-number-from-within-a-range
 */
unsigned int static randr (unsigned int min, unsigned int max)
{
  double scaled = (double) rand()/RAND_MAX;
  return (unsigned int) ((max - min +1)*scaled) + min;
}

/*
 * Generates a random IPv4/6 address.
 */
static void make_random_addr (struct in_addr *addr4, struct in6_addr *addr6)
{
  int i;

  if (addr4)
  {
    addr4->S_un.S_un_b.s_b1 = randr (1,255);
    addr4->S_un.S_un_b.s_b2 = randr (1,255);
    addr4->S_un.S_un_b.s_b3 = randr (1,255);
    addr4->S_un.S_un_b.s_b4 = randr (1,255);
  }
  if (addr6)
  {
    addr6->s6_words[0] = swap16 (0x2001); /* Since most IPv6 addr has this prefix */
    for (i = 1; i < 8; i++)
        addr6->s6_words[i] = randr (0,0xFFFF);
  }
}

static void show_help (const char *my_name)
{
  const char *G_option = "";
  const char *G_help   = "";
  const char *g_option = " [-g file]";
  const char *g_help   = "       -g file: generate IPv4/IPv6 tables to <file>.\n";

#if defined(USE_GEOIP_GENERATED)
  G_option = "G";
  G_help   = "       -G:      Use generated built-in IPv4/IPv6 arrays.\n";
  g_option = "";
  g_help   = "";
#endif

  printf ("Usage: %s [-cd%snruh]%s <-4|-6> address(es)\n"
          "       -c:      dump addresses on CIDR form.\n"
          "       -d:      dump address entries for countries and count of blocks.\n"
          "%s"
          "%s"
          "       -n #:    number of loops for random test.\n"
          "       -r:      random test for '-n' rounds (default 10).\n"
          "       -u:      test updating of geoip files.\n"
          "       -4:      test IPv4 address(es).\n"
          "       -6:      test IPv6 address(es).\n"
          "       -h:      this help.\n", my_name, G_option, g_option, G_help, g_help);
  printf ("   address(es) can also come from a response-file: '@file-with-addr'.\n"
          "   Or from 'stdin': \"cat file-with-addr | geoip.exe -4\"\n");
  exit (0);
}

static void rand_test_addr4 (int loops)
{
  int i;

  srand ((unsigned int)time(NULL));

  for (i = 0; i < loops; i++)
  {
    struct in_addr addr;
    char   buf [20];

    make_random_addr (&addr, NULL);
    wsock_trace_inet_ntop4 ((const u_char*)&addr, buf, sizeof(buf));
    printf ("%-15s: ", buf);
    test_addr4 (buf);
  }
}

static void rand_test_addr6 (int loops)
{
  int i;

  srand ((unsigned int)time(NULL));

  for (i = 0; i < loops; i++)
  {
    struct in6_addr addr;
    char   buf [MAX_IP6_SZ];

    make_random_addr (NULL, &addr);
    wsock_trace_inet_ntop6 ((const u_char*)&addr, buf, sizeof(buf));
    printf ("%-40s: ", buf);
    test_addr6 (buf);
  }
}

static smartlist_t *read_file (FILE *f, smartlist_t *list)
{
  while (f && !feof(f))
  {
    char *p, buf[512];

    if (fgets(buf, (int)sizeof(buf), f) == NULL)
       break;
    if ((p = strrchr(buf,'\n')) != NULL) *p = '\0';
    if ((p = strrchr(buf,'\r')) != NULL) *p = '\0';
    smartlist_add (list, strdup(buf));
  }
  if (f && f != stdin)
     fclose (f);
  return (list);
}

static smartlist_t *make_argv_list (int _argc, char **_argv)
{
  smartlist_t *list = smartlist_new();
  int          i;

  if (isatty(fileno(stdin)) == 0)
     return read_file (stdin, list);

  if (_argc > 0 && _argv[0][0] == '@')
  {
    const char *p = _argv[0] + 1;
    return read_file (fopen(p,"rt"), list);
  }
  for (i = 0; i < _argc; i++)
      smartlist_add (list, strdup(_argv[i]));
  return (list);
}

static void free_argv_list (smartlist_t *sl)
{
  int i, max = smartlist_len (sl);

  for (i = 0; i < max; i++)
      free (smartlist_get(sl, i));
  smartlist_free (sl);
}

int main (int argc, char **argv)
{
  int c, do_cidr = 0,  do_4 = 0, do_6 = 0;
  int do_update = 0, do_dump = 0, do_rand = 0;
  int loops = 10;
  const char *my_name = argv[0];

#if defined(USE_GEOIP_GENERATED)
  #define G_OPT "G"
  #define g_OPT ""
#else
  #define G_OPT ""
  #define g_OPT "g:"

  int         do_generate = 0;
  const char *g_file = NULL;
#endif

  wsock_trace_init();

  while ((c = getopt (argc, argv, "h?cd" g_OPT G_OPT "n:ru46")) != EOF)
    switch (c)
    {
      case '?':
      case 'h':
           show_help (my_name);
           break;
      case 'c':
           do_cidr = 1;
           break;
      case 'd':
           do_dump++;
           break;
#if !defined(USE_GEOIP_GENERATED)
      case 'g':
           do_generate++;
           g_file = optarg;
           break;
#else
      case 'G':
           use_geoip_generated = TRUE;
           geoip_exit();
           geoip_ipv4_entries = smartlist_new_fixed_ipv4();
           geoip_ipv6_entries = smartlist_new_fixed_ipv6();
           break;
#endif
      case 'n':
           loops = atoi (optarg);
           break;
      case 'r':
           do_rand = 1;
           break;
      case 'u':
           do_update = 1;
           break;
      case '4':
           do_4 = 1;
           break;
      case '6':
           do_6 = 1;
           break;
    }

  if (!do_4 && !do_6)
     show_help (my_name);

  if (do_update)
  {
    if (do_4)
       geoip_update_file (AF_INET, FALSE);
    if (do_6)
       geoip_update_file (AF_INET6, FALSE);
  }
  else if (!use_geoip_generated)
  {
    if (!g_cfg.geoip4_file || !FILE_EXISTS(g_cfg.geoip4_file))
    {
      printf ("'geoip4' file '%s' not found. This is needed for these tests.\n", g_cfg.geoip4_file);
      return (0);
    }
    if (!g_cfg.geoip6_file || !FILE_EXISTS(g_cfg.geoip6_file))
    {
      printf ("'geoip6' file '%s' not found. This is needed for these tests.\n", g_cfg.geoip6_file);
      return (0);
    }
    if (!g_cfg.geoip_enable)
    {
      printf ("'[geoip]' section must have 'enable=1' in %s is needed for these tests.\n", config_file_name());
      return (0);
    }
  }

#if !defined(USE_GEOIP_GENERATED)
  if (do_generate)
  {
    if (do_4)
       geoip_generate_array (AF_INET, g_file);
    if (do_6)
       geoip_generate_array (AF_INET6, g_file);
    return (0);
  }
#endif

  argc -= optind;
  argv += optind;

  if (do_dump)
  {
    if (do_4)
       dump_ipv4_entries (stdout, do_cidr, 0);
    if (do_6)
       dump_ipv6_entries (stdout, do_cidr, 0);
    if (do_dump >= 2 && (do_4 || do_6))
       dump_num_ip_blocks_by_country();
  }

  if (do_rand)
  {
    if (do_4)
       rand_test_addr4 (loops);
    if (do_6)
       rand_test_addr6 (loops);
  }
  else
  {
    smartlist_t *list = make_argv_list (argc, argv);
    int          i, max = smartlist_len (list);

    if (do_4)
       for (i = 0; i < max; i++)
           test_addr4 (smartlist_get(list, i));

    if (do_6)
       for (i = 0; i < max; i++)
           test_addr6 (smartlist_get(list, i));

    free_argv_list (list);
  }

  wsock_trace_exit();
  return (0);
}
#endif  /* TEST_GEOIP */

