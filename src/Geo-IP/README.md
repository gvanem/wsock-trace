## Geo-IP implementation

This is supposed to become a unified *library* for various
Geo-IP libraries:

 * **[MaxMind](http://www.maxmind.com)** Lite databases
   as used by the **[Tor-project](https://gitweb.torproject.org/tor.git/plain/src/config/)**.

 * **[MaxMind](http://www.maxmind.com)** MMDB databases.<br>
   (the above old CSV databases are now unsupported by MaxMind).

 * **[IP2Location](https://github.com/chrislim2888/IP2Location-C-Library)**.

 * **[IPFire's libloc](https://git.ipfire.org/?p=location/libloc.git;a=summary)**.

 * **[DB-IP](https://db-ip.com)**.


It's task would be to show additional information for an IPv4/IPv6 address:
 * Country, Continent, Location (City, region).
 * IANA information.
 * Position (with a GoogleMap link).
 * *Autonomous System Number* information.
 * Various attributes like: *Satelitte provider*, *Anonymous Proxy*, *Tor exit node* etc.
 * And perhaps support for various block-list. Like:
    1) **[Spamhaus DROP](http://www.spamhaus.org/drop/)** (already supported, but move it here).
    2) **[Spamhaus ASN-DROP](https://www.spamhaus.org/drop/)**.
    3) **[Spamhaus BGPf / BCL](https://www.spamhaus.org/bgpf/)**.
    4) ... more?


