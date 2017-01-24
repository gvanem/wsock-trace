## Wsock-trace v0.3.5:

 A small and simple drop-in tracer for most normal Winsock calls.
 Works best for MSVC since the stack-walking code requires the program's
 **PDB** symbol-file to be present. And unfortunately MinGW/CygWin doesn't
 produce PDB-symbols (GNU-debugger instead relies on the archaic **BFD**
 library). Example output from `c:\> ahost msdn.com` (ahost is part of the DNS library
 [C-ares](http://c-ares.haxx.se/)):

[![screenshot](screenshot_ahost-msdn-com-win10.png?raw=true)](screenshot_ahost-msdn-com-win10.png?raw=true)

Geo-IP information has also been added. Thanks to the Tor-project for
a simplified version of the MaxMind GeoIP-databases. Also many thanks to
MaxMind for their GeoLite data-files. Available from <a href="http://www.maxmind.com">http://www.maxmind.com</a>.

### Installation (MSVC):

 Enter the `src` sub-directory and do a *nmake -f Makefile.vc6*.
 This produces a `wsock_trace.lib` that you'll need to use to
 link your project(s) with. This lib would then trace the normal
 Winsock calls. Example screen-shot above or details in
 **Running samples** below.

### Usage (MSVC):

 Link with `wsock_trace.lib` instead of the system's `ws32_2.lib`. Thus
 most normal Winsock calls are traced on entry and exit. Remember to
 compile using `-Zi` to produce debug-symbols. And remember to use `-debug`
 when linking your program. See `src/Makefile.vc6` for an example.

### Installation (MinGW/CygWin):

 to-do :soon: ?

### Usage (MinGW/CygWin):

 Link with `libwsock_trace.a` instead of the system's `libws32_2.a` (i.e. `-lws32_2`).
 So copy this library to a directory in `$(LIBRARY_PATH)` and use `-lwsock_trace`
 to link. The `Makefile.MinGW` already does the copying to `$(MINGW32)/lib`.

### Configuration

 The trace-level and other settings are controlled by a config-file
 `wsock_trace`. This file is searched along these places until found:
  *  The file pointed to by `%WSOCK_TRACE`.
  *  The current directory.
  *  The `%HOME` directory.
  *  Then finally the `%APPDATA` directory.

   `wsock_trace` is read in *init.c* at startup. Read it's contents; the comments
   therein should be self-explanatory. If `wsock_trace` is not found in one of
   the above directories, the default `trace_level` is set to 1.

   You should copy the following files (here at GitHub) to your `%HOME` or `%APPDATA`
   directory:
    ```
    wsock_trace
    geoip
    geoip6
    ```

    These environment variables are on the form:
  * `<drive>:\Documents and Settings\<User Name>\ProgramData`.  (Win-XP)
  * `<drive>:\Users\<User Name>\AppData\Roaming`.               (Win-Vista+)

    (Since it's a confusing subject what a program's configuration directory should be,
    it's best to define a `%HOME%` to point to the excact place for such config-files).

### Running samples

 Example output from src/test.exe (built with MSVC):
 ```

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

  Here is a more realistic and useful example with wsock_trace.lib linked to Nmap [1]:
  ```

    > nmap -sT -P0 -p23,80 10.0.0.1

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
* Nmap uses wrong arguments to `setsockopt()`; a *TTL* of *ULONG_MAX*.
* Nmap also calls `WSAStartup()` before the startup message.
* Last but not least, notice how `wsock_trace` handles (demangles) C++ symbols just
  fine  thanks to `dbghelp.dll` and `UnDecorateSymbolName()`. I.e. the destructor
  `ConnectProbe::~ConnectProbe` above is calling `closesocket()` at offset 37.
  (you can turn off C++ demangling by `cpp_demangle = 0` in the config-file).


And another example from C-ares' adig [2]:
```
    > adig -t PTR 89.42.216.144
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

 By default, the tracing of these calls:
 ```
  htons()
  htonl()
  ntohs()
  ntohl()
 ```
are excluded from the trace. You can edit the `%HOME/wsock_trace` file and exclude
whatever calls you like.


### Implementation notes

 The names of the import libraries and the names of the .DLLs are:
  * For MSVC:    `wsock_trace.lib` and `wsock_trace.dll` .
  * For MinGW:   `libwsock_trace.a` and `wsock_trace_mw.dll` .
  * For CygWin:  `libwsock_trace.a` and `wsock_trace_cyg.dll`.

 These DLLs off-course needs to be in current directory or on `%PATH`. The reason
 I've chosen to make it a DLL and not a static-lib is that applications
 using `wsock_trace.lib` needs not to be re-linked when I do change the inner
 workings of the `wsock_trace` source code (I've done that a lot lately).
 As long as the ABI is stable (e.g. not adding functions to the `wsock_trace.def`
 file), the application using `wsock_trace.dll` should work the same. Only the
 trace should change.

 Note that some virus scanners may find the behaviour of programs linked to
 `wsock_trace.lib` suspicious.

### Future plans:

   1. Get the MinGW/CygWin ports working.

   2. Lua-script integration; use a *.lua file to exclude/include processes and/or
      functions to trace.

   3. Injecting `wsock_trace.dll` into a remote process. Ref:
      http://www.viksoe.dk/code/wepmetering.htm

   4. Optionally load [Wireshark's](https://www.wireshark.org) `libwireshark.dll` to dissect
      transport and application protocols. Do it for selected processes only.

   5. Deny certain applications to use `AF_INET6` protocols (return `-1` on
      `socket(AF_INET6,...)`.

   6. Add a Json type config feature to support the above features. E.g.:
      ```
      wireshark_dissect {
        wget.exe : 1    # Wireshark dissection in wget and curl only.
        curl.exe : 1
      }

      exclude_trace {
        curl.exe, wget.exe: select   # Exclude trace of `select()` and `inet_ntoa()` in curl/wget.
        curl.exe, wget.exe: inet_ntoa
        *                 : htons    # Exclude trace of `htons` globally.
      }

      deny_ipv6 {
        pycurl.pyd : 1      # Deny AF_INET6 sockets in scripts using the PyCurl module.
        python27.dll : 1    # And in other Python scripts too.

      }
      ```

   7. Make a GUI trace viewer for it. Ref:
      http://www.viksoe.dk/code/windowless1.htm

   8. Make it possible to switch network stacks at run-time (select amongst Winsock2,
      [lwIP](http://savannah.nongnu.org/projects/lwip/),
      [SwsSock](http://www.softsystem.co.uk/products/swssock.htm) and/or
      [Cyclone TCP](http://www.oryx-embedded.com/cyclone_tcp.html) (ported to Win32)).

-------------

G. Vanem <gvanem@yahoo.no> 2013 - 2016.

Footnotes:

   [1] Nmap; "Network Mapper" is a free and open source (license) utility for network discovery and
       security auditing.
       Ref. http://nmap.org/download.html

   [2] A C library for asynchronous DNS requests (including name resolves)
       Ref. http://c-ares.haxx.se/
