## Wsock-trace v. 0.3.7:

[![Build Status](https://ci.appveyor.com/api/projects/status/github/gvanem/wsock-trace?branch=master&svg=true)](https://ci.appveyor.com/project/gvanem/wsock-trace)

A drop-in tracing library / DLL for most normal Winsock calls.
It sits between your program and the Winsock library (`ws2_32.dll`).
It works best for MSVC since the stack-walking code requires the program's
**PDB** symbol-file to be present. And unfortunately MinGW/CygWin doesn't produce
PDB-symbols (GNU-debugger instead relies on the archaic **BFD** library). So currently,
the MinGW and CygWin targets will only show raw addresses for the traced
functions.

A MSVC example output from `c:\> ahost msdn.com` showing all the addresses of `msdn.com` <br>
(`ahost` is part of the DNS library **[C-ares](https://c-ares.haxx.se/)**):

[![screenshot](screenshot_ahost-msdn-com.png?raw=true)](screenshot_ahost-msdn-com.png?raw=true)

### Features

* *Colourised trace* of the Winsock calls with function parameters and return
  values. The colours are configurable.

* *Runtime caller information*: Using Microsoft's *dbghelp* (or *psapi*) APIs
  together with the programs *PDB*-file, the filename, line-number of the calling
  function-name is shown. In the above example, [`WSAStartup()`](https://msdn.microsoft.com/en-us/library/windows/desktop/ms742213(v=vs.85).aspx)
  is called from `ahost.c`, line 68. Which should be 53 bytes into the `main()` function.
  This should be **[here](https://github.com/c-ares/c-ares/blob/main/src/tools/ahost.c#L68)**.

* *Precise Timestamps*: All trace-lines starts with a precise timestamp obtained
  from [`QueryPerformanceCounter()`](https://msdn.microsoft.com/en-us/library/windows/desktop/ms644904(v=vs.85).aspx).<br>
  The timestamp is controlled by `trace_time` in the
  [`wsock_trace`](https://github.com/gvanem/wsock-trace/blob/master/wsock_trace#L32)
  config-file.

* *Extension functions*: Winsock has several Microsoft-specific extension functions
  (like [`AcceptEx()`](https://msdn.microsoft.com/en-us/library/windows/desktop/ms737524.aspx)
  and [`ConnectEx()`](https://msdn.microsoft.com/en-us/library/windows/desktop/ms737606.aspx)).
  Wsock-trace is able to trace these too.

* *IP-Country* information thanks to the **[MaxMind](https://www.maxmind.com/en/geoip2-services-and-databases)**
  Lite databases. Thanks to the **[Tor-project](https://gitlab.torproject.org/tpo/core/tor/-/tree/main/src/config?ref_type=heads)**
  for a simplified CSV version of these MaxMind GeoIP-databases.
  (using the CSV files [`GeoIP.csv`](https://github.com/gvanem/wsock-trace/blob/master/wsock_trace#L213)
  and [`GeoIP6.csv`](https://github.com/gvanem/wsock-trace/blob/master/wsock_trace#L214)
  are always enabled).

* *IP-Location* information (City and Region) from  **[IP2Location](https://github.com/chrislim2888/IP2Location-C-Library)**.
  The above `Mountain View/California` is Google's well-known location. Many thanks to IP2Location
  [**[3]**](#footnotes) for their data-bases.

* *ASN* information (Autonomous System Number) from **[IPFire](https://location.ipfire.org)**. <br>
  The screen-shot above shows Google has ASN 15169 (for their DNS server-address `8.8.8.8`). <br>
  More details for that ASN is at **[DNSlytics](https://dnslytics.com/bgp/as15169)**
  and even more details at **[PeerDB](https://www.peeringdb.com/asn/15169)**.
  Many thanks to the IPFire developers [**[4]**](#footnotes) for their data-bases.

* *Domain Name System-based Blackhole List*
  (**[DNSBL](https://en.wikipedia.org/wiki/DNSBL)**) support: with the help of
  DROP-files from the **[Spamhaus](http://www.spamhaus.org/drop/)** project,
  it can detect IPv4 / IPv6-addresses uses by spammers and cyber-criminals.
  The more potent Spamhaus **[BGPf / BCL](https://www.spamhaus.org/bgpf/)** is on the *to-do* list.

* *Slowdown*; For testing *too fast programs*, all receive, transmit, `select()` and `WSAPoll()`
  calls can be delayed a number of milli-seconds. E.g. slowing down a `recv()` call is
  controlled by `recv_delay = 0` in [`wsock_trace`](https://github.com/gvanem/wsock-trace/blob/master/wsock_trace#L82)
  config-file.

* *Firewall* activity; report activity causing events from the *Window Filtering Platform* (the *Internet Connection Firewall*; ICF).
  See [below](https://github.com/gvanem/wsock-trace#firewall-monitor).

* **[LuaJIT](https://github.com/LuaJIT/LuaJIT.git)** script support is very
  preliminary at the moment. The idea is that `.lua` scripts could change the
  behaviour of Wsock-trace at runtime without rebuilding it. Only the absolute minimum
  of the needed files are in **[./LuaJIT](https://github.com/gvanem/wsock-trace/tree/master/LuaJIT)**.
  Goto **[here](https://github.com/LuaJIT/LuaJIT.git)** for the complete LuaJIT.


### Installation

The following assumes you will install this package in `c:\prog\wsock_trace`.
To clone this repository, do this in an **empty** `c:\prog\wsock_trace` directory:<br>
* `c:\prog\wsock_trace> git clone https://github.com/gvanem/wsock-trace.git .`

To be able to get more precise Geo-IP information for addresses (city and region), Wsock-trace
will use a IP2Location LITE [**database**](https://lite.ip2location.com). To make best use of it,
do this:
  * Sign-up for an [**account**](https://lite.ip2location.com/sign-up) and download a free
    IP2Location LITE [**database**](https://lite.ip2location.com/database/ip-country-region-city).
    Or in case you have an account, go [**here**](https://lite.ip2location.com/database-download).
  * Download and use a file named like `IP2LOCATION-LITE-DBx.IPV6.BIN`. <br>
    Such a file contains both IPv4 and IPv6 records. A `download-ip2loc.bat` like this could do
    it automatically:
    ```
    @echo off
    setlocal
    ::
    :: Fill in this from the login-page
    ::
    if %IP2LOCATION_TOKEN. == . set IP2LOCATION_TOKEN=xxxx
    curl --output IP2LOCATION-LITE-DB11.IPV6.BIN.zip ^
       "https://www.ip2location.com/download/?token=%IP2LOCATION_TOKEN%&file=DB11LITEBINIPV6"
    unzip IP2LOCATION-LITE-DB11.IPV6.BIN.zip
    ```
  * Copy `IP2LOCATION-LITE-DBx.IPV6.BIN` into your `%APPDATA%` directory and edit the keyword in
    the `[geoip]` section to read: <br>
    `ip2location_bin_file = %APPDATA%\IP2LOCATION-LITE-DBx.IPV6.BIN`

*Note*: [**IP2Location-C-Library**](https://github.com/chrislim2888/IP2Location-C-Library.git)
  is no longer used as a submodule (since I've made several local changes to it). It has been
  merged into `src/ip2loc.c` and simplified.

### Building

Enter the `src` sub-directory and do the respective *make* `all`command.<br>
If the `all` command succeeded, you can do the respective *make* `install` command:

| **Builder**  | `make all`command | `make install` result |
| :----------- | :---------------- | :--- |
| CygWin  | make -f Makefile.CygWin | `cp wsock_trace_cyg*.dll` to `/usr/bin` and<br> `cp libwsock_trace_cyg*.a` to `/usr/lib`  |
| MinGW32 | make -f Makefile.MinGW | `cp wsock_trace_mw.dll` to `$(MINGW32)/bin` and<br> `cp libwsock_trace_mw*.a` to  `$(MINGW32)/lib`|
| MSVC  | nmake -f makefile.vc6 | `copy wsock_trace*.dll` to `%VCINSTALLDIR%\bin` and<br> `copy wsock_trace.lib` to `%VCINSTALLDIR%\lib` |

*Notes:*
  * For a `WIN32` build, the above files will have an `-x86` suffix.
  * For a `WIN64` build, the above files will have an `-x64` suffix.
  * And for a `USE_CRT_DEBUG = 1` build, the above files will have an extra `_d` suffix.
  * So for a MinGW, `WIN64` debug-build, the files are named `wsock_trace_mw_d-x64.dll` and
    `libwsock_trace_mw_d-x64.a`.

### Usage

Link with one of these libraries (instead of the default `libws32_2.a` or `ws2_32.lib`):

| Builder  | Platform | Library |
| :------- | :------  | :------ |
| CygWin   | `x86`    | `libwsock_trace_cyg-x86.a` |
| CygWin   | `x64`    | `libwsock_trace_cyg-x64.a` |
| MinGW    | `x86`    | `libwsock_trace_mw-x86.a`  |
| MinGW    | `x64`    | `libwsock_trace_mw-x64.a`  |
| MSVC     | `x86`    | `wsock_trace-x86.lib`      |
| MSVC     | `x64`    | `wsock_trace-x64.lib`      |

Thus most normal Winsock calls are traced on entry and exit.

Example screen-shot above or details in **[Running samples](#running-samples)** below.

**MSVC**:  Remember to compile using [`-Zi`](https://docs.microsoft.com/en-gb/cpp/build/reference/z7-zi-zi-debug-information-format)
  to produce debug-symbols. For MSVC-2015 (or newer) it is recomended to use option
  [`-Zo`](https://docs.microsoft.com/en-gb/cpp/build/reference/zo-enhance-optimized-debugging)
  too (which will eases the debug of optimised code. And remember to use `-debug` when linking your program.
  See [`src/Makefile.vc6`](https://github.com/gvanem/wsock-trace/blob/master/src/Makefile.vc6) for an example.
  It is not adviced to use option [`-Oy`](https://docs.microsoft.com/en-gb/cpp/build/reference/oy-frame-pointer-omission)
  (*enable frame pointer omission*) since that will make it difficult for [`StackWalk64()`](https://docs.microsoft.com/en-us/windows/win32/api/dbghelp/nf-dbghelp-stackwalk64)
  to  figure out the filename and line of the calling function.


### Configuration

The trace-level and other settings are controlled by a config-file
`wsock_trace`. This file is searched along these places until found:
  *  The file pointed to by `%WSOCK_TRACE`.
  *  The current directory.
  *  Then finally the `%APPDATA%` directory.

`wsock_trace` is read in **[init.c](https://github.com/gvanem/wsock-trace/blob/master/src/init.c)**
at startup. Read it's contents; the comments therein should be self-explanatory.<br>
If `wsock_trace` is not found in one of the above directories, the default
`trace_level` is set to 1.

There is currently no `install.bat` file for Wsock-trace. So you should copy the following files (here at GitHub) <br>
to your `%APPDATA%` directory:
```
  wsock_trace
  GeoIP.csv
  GeoIP6.csv
  GeoIPASNum.csv
  IPv4-address-space.csv
  IPv6-unicast-address-assignments.csv
  DROP.txt
  EDROP.txt
  DROPv6.txt
  IPFire-database.db
```

These environment variables are on the form:
  * `<drive>:\Documents and Settings\<User Name>\ProgramData`.  (Win-XP)
  * `<drive>:\Users\<User Name>\AppData\Roaming`.               (Win-Vista+)

### Running samples

All the below samples uses these `%APPDATA%/wsock_trace` settings:
  * `compact = 1`
  * `trace_time = none` and
  * `use_short_path = 1`.

Example output from `src/ws_tool.exe test` (built with MSVC):
 ```c
   * ws_trace/test.c(45) (main+50):              WSAStartup (2.2) --> No error.
   * ws_trace/test.c(24) (do_wsock_tests+125):   gethostbyaddr (127.0.0.1, 4, AF_INET) --> 0x003C8780.
   * ws_trace/test.c(27) (do_wsock_tests+150):   gethostbyaddr (0.0.0.0, 4, AF_INET) --> 0x003C8780.
   * ws_trace/test.c(29) (do_wsock_tests+164):   gethostbyaddr (::1, 16, AF_INET6) --> 0x003C8780.
   * ws_trace/test.c(31) (do_wsock_tests+175):   gethostbyname (localhost) --> 0x003C8780.
   * ws_trace/test.c(31) (do_wsock_tests+187):   socket (AF_INET, SOCK_STREAM, 0) --> 1724.
   * ws_trace/test.c(33) (do_wsock_tests+196):   WSAGetLastError() --> No error.
   * ws_trace/test.c(36) (do_wsock_tests+343):   select (n=0-1724, rd, NULL, NULL, {tv=1.000001s}) --> No error.
   * ws_trace/test.c(37) (do_wsock_tests+358):   FD_ISSET (1724, fd) --> 0.
   * ws_trace/test.c(47) (main+61):              WSACleanup() --> No error.
     ^                ^   ^                      ^
     |                |   |                      |___ The traced Winsock function and the result.
     |                |   |
     |                |   |____ The calling function with displacement (i.e. offset from
     |                |                                          (nearest public symbol).
     |                |_____ Line number in src-file.
     |
     |____ Source-file relative of the application.

  ```

Here is a more realistic and useful example with `wsock_trace.lib` linked to
Nmap [**[1]**](#footnotes):

```c
  c:\> nmap -sT -P0 -p23,80 10.0.0.1
     * mswin32/winfix.cc(134) (win_pre_init+68):   WSAStartup (2.2) --> No error.

    Starting Nmap 6.02 ( http://nmap.org ) at 2012-07-24 12:48 CET
      * g:/vc_2010/sdk/include/wspiapi.h(1011) (WspiapiGetAddrInfo+79):   WSASetLastError (0).
      * g:/vc_2010/sdk/include/wspiapi.h(1011) (WspiapiGetAddrInfo+79):   WSASetLastError (0).
      * g:/vc_2010/sdk/include/wspiapi.h(1011) (WspiapiGetAddrInfo+79):   WSASetLastError (0).
      * g:/vc_2010/sdk/include/wspiapi.h(1011) (WspiapiGetAddrInfo+79):   WSASetLastError (0).
      * g:/vc_2010/sdk/include/wspiapi.h(1011) (WspiapiGetAddrInfo+79):   WSASetLastError (0).
      * g:/vc_2010/sdk/include/wspiapi.h(1011) (WspiapiGetAddrInfo+79):   WSASetLastError (0).
      * scan_engine.cc(3002) (sendConnectScanProbe+266):   socket (AF_INET, SOCK_STREAM, 6) --> 1780.
      * nbase/nbase_misc.c(261) (unblock_socket+65):   ioctlsocket (1780, FIONBIO, 1) --> No error.
      * scan_engine.cc(2964) (init_socket+82):   setsockopt (1780, SOL_SOCKET, SO_LINGER, 1, 4) --> No error.
      * libnetutil/netutil.cc(856) (set_ttl+34):   setsockopt (1780, IPPROTO_IP, IP_TTL, ULONG_MAX, 4) --> WSAEINVAL: Invalid arguments (10022).
      * scan_engine.cc(3021) (sendConnectScanProbe+599):   connect (1780, 10.0.0.1:23) --> WSAEWOULDBLOCK: Call would block (10035).
      * nbase/nbase_misc.c(133) (socket_errno+12):   WSAGetLastError() --> WSAEWOULDBLOCK: Call would block (10035).
      * scan_engine.cc(922) (ConnectScanInfo::watchSD+82):   FD_ISSET (1780, fd) --> 0.
      * scan_engine.cc(3002) (sendConnectScanProbe+266):   socket (AF_INET, SOCK_STREAM, 6) --> 1720.
      * nbase/nbase_misc.c(261) (unblock_socket+65):   ioctlsocket (1720, FIONBIO, 1) --> No error.
      * scan_engine.cc(2964) (init_socket+82):   setsockopt (1720, SOL_SOCKET, SO_LINGER, 1, 4) --> No error.
      * libnetutil/netutil.cc(856) (set_ttl+34):   setsockopt (1720, IPPROTO_IP, IP_TTL, ULONG_MAX, 4) --> WSAEINVAL: Invalid arguments (10022).
      * scan_engine.cc(3021) (sendConnectScanProbe+599):   connect (1720, 10.0.0.1:80) --> WSAEWOULDBLOCK: Call would block (10035).
      * nbase/nbase_misc.c(133) (socket_errno+12):   WSAGetLastError() --> WSAEWOULDBLOCK: Call would block (10035).
      * scan_engine.cc(922) (ConnectScanInfo::watchSD+82):   FD_ISSET (1720, fd) --> 0.
      * scan_engine.cc(3964) (do_one_select_round+473):   select (n=0-1780, rd, wr, ex, {tv=0.985000s}) --> 3.
      * nbase/nbase_misc.c(133) (socket_errno+12):   WSAGetLastError() --> WSAEWOULDBLOCK: Call would block (10035).
      * scan_engine.cc(4015) (do_one_select_round+1894):   FD_ISSET (1720, fd) --> 0.
      * scan_engine.cc(4015) (do_one_select_round+1917):   FD_ISSET (1720, fd) --> 1.
      * scan_engine.cc(4019) (do_one_select_round+2012):   getsockopt (1720, SOL_SOCKET, SO_ERROR, 0, 4) --> No error.
      * scan_engine.cc(938) (ConnectScanInfo::clearSD+82):   FD_ISSET (1720, fd) --> 1.
      * scan_engine.cc(789) (ConnectProbe::~ConnectProbe+37):   closesocket (1720) --> No error.
      * scan_engine.cc(4015) (do_one_select_round+1894):   FD_ISSET (1780, fd) --> 1.
      * scan_engine.cc(4019) (do_one_select_round+2012):   getsockopt (1780, SOL_SOCKET, SO_ERROR, 0, 4) --> No error.
      * scan_engine.cc(938) (ConnectScanInfo::clearSD+82):   FD_ISSET (1780, fd) --> 1.
      * scan_engine.cc(789) (ConnectProbe::~ConnectProbe+37):   closesocket (1780) --> No error.
    Nmap scan report for router (10.0.0.1)
    Host is up (0.0019s latency).
    PORT   STATE SERVICE
    23/tcp open  telnet
    80/tcp open  http

    Nmap done: 1 IP address (1 host up) scanned in 7.61 seconds
      * mswin32/winfix.cc(290) (win_cleanup+12):   WSACleanup() --> No error.
```

Notes:
* Nmap uses wrong arguments to [`setsockopt()`](https://msdn.microsoft.com/en-us/library/windows/desktop/ms740476(v=vs.85).aspx);
  a *TTL* of *ULONG_MAX*.
* Nmap also calls [`WSAStartup()`](https://msdn.microsoft.com/en-us/library/windows/desktop/ms742213(v=vs.85).aspx)
  before the startup message.
* Notice how Wsock-trace handles (demangles) C++ symbols just
  fine  thanks to `dbghelp.dll` and [`UnDecorateSymbolName()`](https://msdn.microsoft.com/en-us/library/windows/desktop/ms681400(v=vs.85).aspx).
  I.e. the destructor `ConnectProbe::~ConnectProbe` above is calling [`closesocket()`](https://msdn.microsoft.com/en-us/library/windows/desktop/ms737582(v=vs.85).aspx)
  at offset 37. (you can turn off C++ demangling by `cpp_demangle = 0` in the `wsock_trace` config-file).
* Even symbols from a Rust library can be demangled. E.g. from [**rustls-ffi**](https://github.com/rustls/rustls-ffi.git) as used in
  [**libcurl**](https://github.com/curl/curl):
  ```
  * 1.807833 sec: f:/MingW32/src/inet/Crypto/Rustls/src/io.rs(44) (rustls_ffi::io::impl$0::read+32)
    WSAGetLastError() --> WSAEWOULDBLOCK (10035).
  ```
  This Rust function `rustls_ffi::io::impl$0::read` should be [**here**](https://github.com/rustls/rustls-ffi/blob/main/src/io.rs#L41-L44).


Another example from [**C-ares**](https://github.com/c-ares/c-ares)'s
**[adig.c](https://github.com/c-ares/c-ares/blob/master/src/tools/adig.c)** with the same settings as above:
```c
    c:\> adig -t PTR 89.42.216.144
      * adig.c(216) (main+105):   WSAStartup (2.2) --> No error.
      * ares_process.c(1065) (open_udp_socket+248):   socket (AF_INET, SOCK_DGRAM, 0) --> 1604.
      * ares_process.c(857) (setsocknonblock+61):   ioctlsocket (1604, FIONBIO, 1) --> No error.
      * ares_process.c(1077) (open_udp_socket+345):   connect (1604, 8.8.8.8:53) --> No error.
      * ares_process.c(791) (ares__send_query+484):   send (1604, 0x00034BDA, 31, 0) --> 31 bytes tx.
      * adig.c(397) (main+1780):   select (n=0-1604, rd, wr, NULL, {tv=3.109000s}) --> 1.
      * ares_process.c(456) (read_udp_packets+146):   FD_ISSET (1604, fd) --> 1.
      * ares_process.c(485) (read_udp_packets+413):   recvfrom (1604, 0x0013F894, 513, 0, 8.8.8.8:53) --> 106 bytes rx.
    Domain name not found
    id: 58187
    flags: qr rd ra
    opcode: QUERY
    rcode: NXDOMAIN
    Questions:
            89.42.216.144  .                PTR
    Answers:
    NS records:
                           .        1413    SOA     a.root-servers.net.
                                                    nstld.verisign-grs.com.
                                                    ( 2012072400 1800 900 604800 86400 )
    Additional records:
      * ares__close_sockets.c(63) (ares__close_sockets+408):   closesocket (1604) --> No error.
      * adig.c(411) (main+1894):   WSACleanup() --> No error.
```

By default, the tracing of `htons()`,`htonl()`, `ntohs()` and `ntohl()` are
excluded from the trace.<br>
You can edit the `%APPDATA%/wsock_trace` config-file and exclude whatever calls you like.
And the 2 traces above is showing the effect of the config-value `compact = 1`.

A more eleborated example from 2 **[OpenVPN](https://openvpn.net/)** programs; a client and a
server running a simple test (in OpenVPN's root-dir). Started with the `vpn.bat` snippet:
```
cd sample
start /pos=200,50,1000,800   ..\openvpn.exe --config sample-config-files/loopback-server
start /pos=800,150,1000,1000 ..\openvpn.exe --config sample-config-files/loopback-client
```
[![screenshot](screenshot_openvpn-tmb.jpg?raw=true)](screenshot_openvpn.png?raw=true):

A **[Larger](https://www.watt-32.net/misc/screenshot_openvpn.png)** version.

### Firewall Monitor

The `ws_tool.exe firewall` program show a screen like:
[![screenshot](screenshot_firewall_test_DNSBL.png?raw=true)](screenshot_firewall_test_DNSBL.png?raw=true)

Together with `[DNSBL], enable = 1` it shows remote addresses in **[SpamHaus](https://www.spamhaus.org/sbl/)** DROP-lists.
In this case the **[address](https://blackhat.directory/ip/176.119.4.53)** `176.119.4.56`
in *Ukraine / Donetsk* is *very* active giving a Firewall event approximately every 5 minutes.

A good test of the `firewall.c` features is to open up your router (create a DMZ) and start a remote
**[port-scan](https://www.whatsmyip.org/port-scanner/server/)** while `ws_tool.exe firewall`
is running. You'll see a lot of **DROP**-events like:
```
6.700 sec: FWPM_NET_EVENT_TYPE_CLASSIFY_DROP, IN, IPPROTO_TCP
  layer:   (13) Inbound Transport v4 Discard-layer
  filter:  (277599) Filter to prevent port-scanning
  addr:    204.11.35.98 -> 10.0.0.10, ports: 21 (ftp) / 52115
  country: United States, Troy/Michigan
```

### Implementation notes

The names of the import libraries and the names of the 32-bit .DLLs are:
  * For MSVC:      `wsock_trace.lib` and `wsock_trace-x86.dll` .
  * For MinGW:     `libwsock_trace.a` and `wsock_trace_mw-x86.dll` .
  * For CygWin32:  `libwsock_trace.a` and `wsock_trace_cyg-x86.dll`.

And the 64-bit equivalents:
  * For MSVC:      `wsock_trace_x64.lib` and `wsock_trace-x64.dll` .
  * For MinGW:     `libwsock_trace_x64.a` and `wsock_trace_mw-x64.dll` .
  * For CygWin64:  `libwsock_trace_x64.a` and `wsock_trace_cyg-x64.dll`.

These DLLs off-course needs to be in current directory or on `%PATH`. The reason
I've chosen to make it a DLL and not a static-lib is that applications
using `wsock_trace*.lib` needs not to be re-linked when I do change the inner
workings of the Wsock-trace source code.
As long as the ABI is stable (e.g. not adding new functions to the
[`wsock_trace-x86.def`](https://github.com/gvanem/wsock-trace/blob/master/src/wsock_trace-x86.def)
file), the application using `wsock_trace*.dll` should work the same.

Note that some virus scanners may find the behaviour of programs linked to
`wsock_trace.lib` suspicious.

### Future plans:

   1. Get the decoding of calling function, file-name and lines in the MinGW/CygWin
      ports working.

   2. LuaJIT-script integration; use a `*.lua` file to exclude/include processes and/or
      functions to trace.

   3. Injecting `wsock_trace-*.dll` into a remote process. Ref:
      [**https://www.viksoe.dk/code/wepmetering.htm**](https://www.viksoe.dk/code/wepmetering.htm).

   4. Optionally load [**Wireshark's**](https://www.wireshark.org) `libwireshark.dll` to dissect
      transport and application protocols. <br>
      Do it for selected processes only.

   5. Deny certain applications to use `AF_INET6` protocols (return `-1` on
      `socket(AF_INET6,...)`).

   6. Make it possible to switch network stacks at run-time:
      select amongst Winsock2, **[lwIP](https://savannah.nongnu.org/projects/lwip/)**,
      **[SwsSock](http://www.softsystem.co.uk/products/swssock.htm)** and/or <br>
      **[Cyclone TCP](https://www.oryx-embedded.com/cyclone_tcp.html)**.

   7. Make a GUI trace viewer for it. Ref:
      [**https://www.viksoe.dk/code/windowless1.htm**](https://www.viksoe.dk/code/windowless1.htm)

   8. Add a Json type config feature to support the above features. E.g.:
      ```
      wireshark_dissect {
        wget.exe : 1    # Wireshark dissection in wget and curl only.
        curl.exe : 1
      }

      exclude_trace {
        select:    [curl.exe, wget.exe]  # Exclude trace of `select()` and `inet_ntoa()` in curl/wget.
        inet_ntoa: [curl.exe, wget.exe]
        htons:     [ * ]    # Exclude trace of `htons` globally.
      }

      deny_ipv6 {
        pycurl.pyd : 1     # Deny AF_INET6 sockets in scripts using the PyCurl module.
        python27.dll : 1   # And in other Python scripts too.

      }

      stack_mux {
        use_lwip: [wget2.exe, curl.exe]  # Force wget2.exe and curl.exe to use lwIP.dll
      }
      ```

-------------

G. Vanem ``<gvanem@yahoo.no>`` 2013 - 2023.

### Footnotes:

   * [1] Nmap; "*Network Mapper*" is a free and open source (license) utility for
         network  discovery and security auditing. <br>
         Ref. [**https://nmap.org/download.html**](https://nmap.org/download.html)

   * [2] A C library for asynchronous DNS requests (including name resolves) <br>
         Ref. [**https://c-ares.haxx.se/**](https://c-ares.haxx.se/)

   * [3] This product includes IP2Location LITE data available from
         [**https://lite.ip2location.com**](https://lite.ip2location.com).

   * [4] This product includes IPFire location and ASN data available from
         [**https://location.ipfire.org/databases/1/**](https://location.ipfire.org/databases/1/).

*PS*. This file is written with the aid of the **[Atom](https://atom.io/)**
      editor and it's **[Markdown-Preview](https://atom.io/packages/markdown-preview)**.
      A real time-saver.
