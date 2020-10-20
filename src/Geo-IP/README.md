## Geo-IP implementation

This is supposed to become a unified *library* for various
Geo-IP libraries:

 * **[MaxMind](http://www.maxmind.com)** Lite databases
   as used by the **[Tor-project](https://gitweb.torproject.org/tor.git/plain/src/config/)**.

 * **[MaxMind Geoip2](http://www.maxmind.com)** MMDB databases.<br>
   (the above old CSV databases now seems unsupported by MaxMind).

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
    * **[Spamhaus DROP](http://www.spamhaus.org/drop/)** (already supported, but move it here).
    * **[Spamhaus ASN-DROP](https://www.spamhaus.org/drop/)**.
    * **[Spamhaus BGPf / BCL](https://www.spamhaus.org/bgpf/)**.
    * ... more?


