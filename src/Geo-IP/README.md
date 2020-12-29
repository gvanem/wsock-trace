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
 * Various attributes like: *Satelitte provider*, *Anonymous Proxy*, *Anycast*, *Tor exit node* etc.
 * And perhaps support for various block-lists. Like:
    * **[Spamhaus DROP](https://www.spamhaus.org/drop/)** (already supported, but move it here).
    * **[Spamhaus ASN-DROP](https://www.spamhaus.org/drop/)**.
    * **[Spamhaus BGPf / BCL](https://www.spamhaus.org/bgpf/)**.
    * ... more?

## Implementation Ideas

Ideas for the public interface to a unified "Geo-IP" library:

* INIT PHASE:
```
  const struct geoip_provider_st mmdb_handler = {
    .flags  = GEOIP_IPV4_ADDR | GEOIP_IPV6_ADDR | GEOIP_MMDB_FILE,
    .file   = "DB-IP/dbip-country-lite-2020-03.mmdb",
    .init   = geoip_MMDB_init,
    .close  = geoip_MMDB_close,
    .lookup = geoip_MMDB_lookup
  };

  struct geoip_provider_st asn_handler1 = {
    .flags = GEOIP_ASN | GEOIP_MMDB_FILE,
    .file   = "DB-IP/dbip-asn-lite-2020-10.mmdb",
    .init   = geoip_ASN_init,
    .close  = geoip_ASN_close,
    .lookup = geoip_ASN_lookup
  };

  struct geoip_provider_st asn_handler2 = {
    .flags = GEOIP_ASN | GEOIP_CSV_FILE,
    .file   = "IP4-ASN.CSV",
    .init   = geoip_ASN_init,
    .close  = geoip_ASN_close,
    .lookup = geoip_ASN_lookup
  };

  struct geoip_provider_st drop_handler = {
    .flags = GEOIP_DROP | GEOIP_TXT_FILE,
    .file   = "DROP.txt",
    .init   = geoip_TXT_init,
    .close  = geoip_TXT_close,
    .lookup = geoip_TXT_lookup
  };

  // Adds the providers in an internal structure for low-level handling.
  // Action depends on '.flags'.

  geoip_add_provider (&mmdb_handler);
  geoip_add_provider (&asn_handler1);
  geoip_add_provider (&asn_handler2);
  ...
```

* LOOKUP PHASE:

```
  struct in_addr ia4 = ...;
  const struct geoip_data_rec *rec = geoip_lookup (&ia4, GEOIP_IPV4_ADDR | GEOIP_ASN);

  if (rec)
  {
    printf ("%s, location: %s\"n, rec->country, rec->location);
    printf ("AS%lu, name: %s\"n, rec->as_number, rec->as_name);
    geoip_free_rec (rec);
  }
```
