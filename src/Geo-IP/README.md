## Geo-IP implementation

This is supposed to become a unified *library* for various
Geo-IP libraries:

 * **[MaxMind](http://www.maxmind.com)** Lite databases
   as used by the **[Tor-project](https://gitweb.torproject.org/tor.git/plain/src/config/)**.

 * **[MaxMind](http://www.maxmind.com)** MMDB databases.<br>
   (the above old CSV databases are now unsupported by MaxMind).

 * **[IP2Location](https://github.com/chrislim2888/IP2Location-C-Library)**.

 * **[IPFire's libloc](https://git.ipfire.org/pub/git/location/libloc.git)**.

 * **[DB-IP](https://db-ip.com)**.


It's task would be to show additional information for an IPv4/IPv6 address:
 * Country, Continent, Location (City, region).
 * IANA information.
 * Position (with a GoogleMap link).
 * *Autonomous System Number* information.
 * Various attributes like: *Satelitte provider*, *Anonymous Proxy*, *Tor exit node* etc.

