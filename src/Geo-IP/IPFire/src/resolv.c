/*
	libloc - A library to determine the location of someone on the Internet

	Copyright (C) 2019 IPFire Development Team <info@ipfire.org>

	This library is free software; you can redistribute it and/or
	modify it under the terms of the GNU Lesser General Public
	License as published by the Free Software Foundation; either
	version 2.1 of the License, or (at your option) any later version.

	This library is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
	Lesser General Public License for more details.
*/

#ifdef _WIN32
#  include <winsock2.h>
#  include <windns.h>
#else
#  include <arpa/nameser.h>
#  include <arpa/nameser_compat.h>
#  include <resolv.h>
#endif
#include <string.h>
#include <time.h>

#include <libloc/format.h>
#include <libloc/private.h>
#include <libloc/resolv.h>

static int parse_timestamp(const unsigned char* txt, time_t* t) {
    struct tm ts;

    // Parse timestamp
    char* p = strptime((const char*)txt, "%a, %d %b %Y %H:%M:%S GMT", &ts);

    // If the whole string has been parsed, we convert the parse value to time_t
    if (p && !*p) {
        *t = timegm(&ts);

    // Otherwise we reset t
    } else {
        *t = 0;
        return -1;
    }

    return 0;
}

#if !defined(_WIN32)
LOC_EXPORT int loc_discover_latest_version(struct loc_ctx* ctx,
        unsigned int version, time_t* t) {
    // Initialise the resolver
    int r = res_init();
    if (r) {
        ERROR(ctx, "res_init() failed\n");
        return r;
    }

    // Make domain
    char domain[64];
    snprintf(domain, 63, LOC_DATABASE_DOMAIN, version);

    unsigned char answer[PACKETSZ];
    int len;

    DEBUG(ctx, "Querying %s\n", domain);

    // Send a query
    if ((len = res_query(domain, C_IN, T_TXT, answer, sizeof(answer))) < 0 || len > PACKETSZ) {
        ERROR(ctx, "Could not query %s: \n", domain);

        return -1;
    }

    unsigned char* end = answer + len;
    unsigned char* payload = answer + sizeof(HEADER);

    // Expand domain name
    char host[128];
    if ((len = dn_expand(answer, end, payload, host, sizeof(host))) < 0) {
        ERROR(ctx, "dn_expand() failed\n");
        return -1;
    }

    // Payload starts after hostname
    payload += len;

    if (payload > end - 4) {
        ERROR(ctx, "DNS reply too short\n");
        return -1;
    }

    int type;
    GETSHORT(type, payload);
    if (type != T_TXT) {
        ERROR(ctx, "DNS reply of unexpected type: %d\n", type);
        return -1;
    }

    // Skip class
    payload += INT16SZ;

    // Walk through CNAMEs
    unsigned int size = 0;
    int ttl __attribute__ ((unused));
    do {
        payload += size;

        if ((len = dn_expand(answer, end, payload, host, sizeof(host))) < 0) {
            ERROR(ctx, "dn_expand() failed\n");
            return -1;
        }

        payload += len;

        if (payload > end - 10) {
            ERROR(ctx, "DNS reply too short\n");
            return -1;
        }

        // Skip type, class, ttl
        GETSHORT(type, payload);
        payload += INT16SZ;
        GETLONG(ttl, payload);

        // Read size
        GETSHORT(size, payload);
        if (payload + size < answer || payload + size > end) {
            ERROR(ctx, "DNS RR overflow\n");
            return -1;
        }
    } while (type == T_CNAME);

    if (type != T_TXT) {
        ERROR(ctx, "Not a TXT record\n");
        return -1;
    }

    if (!size || (len = *payload) >= size || !len) {
        ERROR(ctx, "Broken TXT record (len = %d, size = %d)\n", len, size);
        return -1;
    }

    // Get start of the string
    unsigned char* txt = payload + 1;
    txt[len] = '\0';

    DEBUG(ctx, "Resolved to: %s\n", txt);

    // Parse timestamp
    r = parse_timestamp(txt, t);

    return r;
}

#else /* The much simpler _WIN32 version */

LOC_EXPORT int loc_discover_latest_version (struct loc_ctx* ctx,
                                            unsigned int version, time_t* t)
{
  DNS_RECORD *resource_rec, *data_rec = NULL;
  DNS_STATUS  rc;
  BOOL   found = FALSE;
  DWORD  opt = DNS_QUERY_NO_NETBT |     /* no NetBT names */
               DNS_QUERY_BYPASS_CACHE;  /* no cached info */
  char   domain [100];
  char   answer [512];

  /*
   * E.g. a:
   *   adig -t txt _v1._db.location.ipfire.org
   *
   * returns things like:
   *   Answers:
   *     _v1._db.location.ipfire.org.    300    TXT  Fri, 16 Oct 2020 07:54:08 GMT
   */
  snprintf (domain, sizeof(domain), LOC_DATABASE_DOMAIN, version);

  rc = DnsQuery_A (domain, DNS_TYPE_TEXT, opt, NULL, &data_rec, NULL);

  DEBUG(ctx, "Querying %s, DnsQuery_A: data_rec %p: %ld\n", domain, data_rec, rc);

  if (rc != ERROR_SUCCESS || !data_rec)
     return (-1);

  for (resource_rec = data_rec; resource_rec && !found; resource_rec = resource_rec->pNext)
  {
    const DNS_TXT_DATAA *txt;

    if (resource_rec->wType != DNS_TYPE_TEXT)
       continue;

    txt = &data_rec->Data.TXT;
    if (txt->dwStringCount >= 1)
    {
      strncpy (answer, txt->pStringArray[0], sizeof(answer)-1);
      found = TRUE;
    }
  }
  DnsFree (resource_rec, DnsFreeRecordList);

  if (!found)
  {
    DEBUG(ctx, "No TXT record found\n");
    return -1;
  }
  DEBUG(ctx, "Resolved to: %s\n", answer);
  return parse_timestamp ((const unsigned char*)&answer, t);
}
#endif
