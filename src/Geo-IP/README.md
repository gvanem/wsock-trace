## Geo-IP implementation

This is supposed to become a unified *library* for various
Geo-IP libraries:

 * **[MaxMind](https://dev.maxmind.com/geoip/legacy/downloadable/)**
   CSV databases as used by the **[Tor-project](https://gitweb.torproject.org/tor.git/plain/src/config/)**.

 * **[MaxMind Geoip2](https://www.maxmind.com/en/geoip2-databases)** MMDB databases. <br>
   The above CSV databases now seems unsupported by MaxMind. And they will be completely retired in
   **[2022](https://blog.maxmind.com/2020/06/01/retirement-of-geoip-legacy-downloadable-databases-in-may-2022/)**.

 * **[IP2Location](https://github.com/chrislim2888/IP2Location-C-Library)**.

 * **[IPFire's libloc](https://git.ipfire.org/?p=location/libloc.git;a=summary)**.

 * **[DB-IP](https://db-ip.com/db/)** and **[IP-to-ASN](https://db-ip.com/db/download/ip-to-asn-lite)**

It's task would be to show additional information for an IPv4/IPv6 address:
 * Country, Continent, Location (City, region).
 * IANA information.
 * Position (with a GoogleMap link).
 * *Autonomous System Number* information.
 * Various attributes like: *Satelitte provider*,
   [*Anonymous Proxy*](https://en.wikipedia.org/wiki/Anonymous_proxy),
   [*Anycast*](https://en.wikipedia.org/wiki/Anycast),
   [*Tor exit node*](https://en.wikipedia.org/wiki/Tor_(network)#Tor_exit_node_block),
   [*Bogons*](https://en.wikipedia.org/wiki/Bogon_filtering) etc.
 * And perhaps support for various block-lists. Like:
    * **[Spamhaus DROP](https://www.spamhaus.org/drop/)** (already supported, but move it here).
    * **[Spamhaus ASN-DROP](https://www.spamhaus.org/drop/)**.
    * **[Spamhaus BGPf / BCL](https://www.spamhaus.org/bgpf/)**.
    * ... more?

## Implementation Ideas

Ideas for the public interface to a unified "Geo-IP" library:

### INIT PHASE:

```c
  const struct geoip_provider_st mmdb_handler = {
    .flags  = GEOIP_IPV4_ADDR | GEOIP_IPV6_ADDR | GEOIP_MMDB_FILE,
    .files  = [ "DB-IP/dbip-country-lite-2020-03.mmdb", NULL ],  
    .url    = "https://updates.maxmind.com/app/update_getfilename?product_id=GeoLite2-Country/update?db_md5=a456ade...",
    .config = "$(APPDATA)/GeoIP.conf",                     // for using the 'geoipupdate' program
    .init   = geoip_MMDB_init,
    .close  = geoip_MMDB_close,
    .lookup = geoip_MMDB_lookup
  };

  const struct geoip_provider_st libloc_handler = {
    .flags  = GEOIP_IPV4_ADDR | GEOIP_IPV6_ADDR | GEOIP_ASN_FILE,
    .files  = [ "IPFire/location.db", NULL ],
    .url    = "https://location.ipfire.org/databases/1/location.db.xz",
    .init   = geoip_libloc_init,
    .close  = geoip_libloc_close,
    .lookup = geoip_libloc_lookup,
    .update = geoip_libloc_update  // update the local '.files[0]' from '.url'
  };

  const struct geoip_provider_st asn_handler1 = {
    .flags  = GEOIP_ASN_FILE | GEOIP_MMDB_FILE,
    .files  = [ "DB-IP/dbip-asn-lite-2020-10.mmdb", NULL ],
    .init   = geoip_ASN_init,
    .close  = geoip_ASN_close,
    .lookup = geoip_ASN_lookup
  };

  const struct geoip_provider_st asn_handler2 = {
    .flags  = GEOIP_ASN_FILE | GEOIP_CSV_FILE,
    .files  = [ "IP4-ASN.CSV", NULL ],
    .init   = geoip_ASN_init,
    .close  = geoip_ASN_close,
    .lookup = geoip_ASN_lookup
  };

  const struct geoip_provider_st drop_handler = {
    .flags  = GEOIP_DROP | GEOIP_TXT_FILES,
    .files  = [ "DROP.txt", "DROPv6.txt", "EDROP.txt", NULL ],
    .init   = geoip_DROP_init,
    .close  = geoip_DROP_close,
    .lookup = geoip_DROP_lookup
  };
```

(unset fields above is assumed to be `NULL`).
Add the above provider back-ends in an internal structure for later use:

```c
  geoip_add_provider (&mmdb_handler);
  geoip_add_provider (&libloc_handler);
  geoip_add_provider (&asn_handler1);
  geoip_add_provider (&asn_handler2);
  geoip_add_provider (&drop_handler);   // For SpamHaus 'DROP' lookups
  ...
```

### LOOKUP PHASE:

  This lookup depends on `.flags` in the **INIT PHASE** and `flags` given here. <br>
  Some precedence could be used or simply look for a flags-match in the order back-ends were added?


  ```c
  const struct in_addr ia4 = ...;
  const struct geoip_data_rec *rec = geoip_lookup (&ia4, GEOIP_IPV4_ADDR | GEOIP_ASN_FILE);

  if (rec)
  {
    printf ("%s, location: %s\"n, rec->country, rec->location);
    printf ("AS%lu, name: %s\"n, rec->as_number, rec->as_name);
    geoip_free_rec (rec);  // add to internal cache?
  }
  ```

### CLEANUP PHASE:

  Remove all added providers, close open files and free the memory used in **INIT PHASE**:

  ```c
  geoip_del_providers();
  ```
