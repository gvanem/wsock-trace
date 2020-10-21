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

 * **[DB-IP](https://db-ip.com/db/)** and **[IP-to-ASN](https://db-ip.com/db/download/ip-to-asn-lite/)**


It's task would be to show additional information for an IPv4/IPv6 address:
 * Country, Continent, Location (City, region).
 * IANA information.
 * Position (with a GoogleMap link).
 * *Autonomous System Number* information.
 * Various attributes like: *Satelitte provider*, *Anonymous Proxy*, *Tor exit node* etc.
 * And perhaps support for various block-list. Like:
    * **[Spamhaus DROP](https://www.spamhaus.org/drop/)** (already supported, but move it here).
    * **[Spamhaus ASN-DROP](https://www.spamhaus.org/drop/)**.
    * **[Spamhaus BGPf / BCL](https://www.spamhaus.org/bgpf/)**.
    * ... more?


