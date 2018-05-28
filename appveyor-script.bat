@echo off

if %1. == init.  goto init
if %1. == clean. goto clean

echo Usage: %0 "init / clean"
exit /b 0

:init
::
:: The "CPU" and "BUILDER" agnostic init-stage.
::
echo Generating %CD%\wsock_trace.appveyor...
echo #                                                       > wsock_trace.appveyor
echo # This file was generated from %0.                     >> wsock_trace.appveyor
echo #                                                      >> wsock_trace.appveyor
echo [core]                                                 >> wsock_trace.appveyor
echo trace_level            = %%WSOCK_TRACE_LEVEL%%         >> wsock_trace.appveyor
echo trace_indent           = 2                             >> wsock_trace.appveyor
echo trace_caller           = 1                             >> wsock_trace.appveyor
echo trace_report           = %%WSOCK_TRACE_LEVEL%%         >> wsock_trace.appveyor
echo trace_time             = relative                      >> wsock_trace.appveyor
echo trace_max_len          = %%COLUMNS%%                   >> wsock_trace.appveyor
echo callee_level           = 1                             >> wsock_trace.appveyor
echo cpp_demangle           = 1                             >> wsock_trace.appveyor
echo short_errors           = 1                             >> wsock_trace.appveyor
echo use_full_path          = 1                             >> wsock_trace.appveyor
echo use_toolhlp32          = 1                             >> wsock_trace.appveyor
echo dump_modules           = 0                             >> wsock_trace.appveyor
echo dump_select            = 1                             >> wsock_trace.appveyor
echo dump_hostent           = 1                             >> wsock_trace.appveyor
echo dump_protoent          = 1                             >> wsock_trace.appveyor
echo dump_servent           = 1                             >> wsock_trace.appveyor
echo dump_nameinfo          = 1                             >> wsock_trace.appveyor
echo dump_wsaprotocol_info  = 1                             >> wsock_trace.appveyor
echo dump_wsanetwork_events = 1                             >> wsock_trace.appveyor
echo dump_data              = 1                             >> wsock_trace.appveyor
echo max_data               = 5000                          >> wsock_trace.appveyor
echo max_displacement       = 1000                          >> wsock_trace.appveyor
echo exclude                = htons,htonl,inet_addr         >> wsock_trace.appveyor

::
:: Windows-Defender thinks generating a 'hosts' file is suspicious.
:: Ref:
::   https://www.microsoft.com/en-us/wdsi/threats/malware-encyclopedia-description?name=Trojan%3aBAT%2fQhost!gen&threatid=2147649092
::
echo hosts_file             = %CD%\appveyor-hosts           >> wsock_trace.appveyor
echo [geoip]                                                >> wsock_trace.appveyor
echo enable                 = 1                             >> wsock_trace.appveyor
echo use_generated          = 0                             >> wsock_trace.appveyor
echo max_days               = 10                            >> wsock_trace.appveyor
echo geoip4_file            = %CD%\geoip                    >> wsock_trace.appveyor
echo geoip6_file            = %CD%\geoip6                   >> wsock_trace.appveyor
echo ip2location_bin_file   = %CD%\IP46-COUNTRY.BIN         >> wsock_trace.appveyor
echo [idna]                                                 >> wsock_trace.appveyor
echo enable                 = 1                             >> wsock_trace.appveyor
echo [lua]                                                  >> wsock_trace.appveyor
echo enable      = %%WSOCK_LUA_ENABLE%%                     >> wsock_trace.appveyor
echo trace_level = 1                                        >> wsock_trace.appveyor
echo lua_init    = %CD%\src\wsock_trace_init.lua            >> wsock_trace.appveyor
echo lua_exit    = %CD%\src\wsock_trace_exit.lua            >> wsock_trace.appveyor
echo [dnsbl]                                                >> wsock_trace.appveyor
echo enable      = 1                                        >> wsock_trace.appveyor
echo test        = %%WSOCK_DNSBL_TEST%%                     >> wsock_trace.appveyor
echo max_days    = 1                                        >> wsock_trace.appveyor
echo drop_file   = %CD%\drop.txt                            >> wsock_trace.appveyor
echo edrop_file  = %CD%\edrop.txt                           >> wsock_trace.appveyor
echo dropv6_file = %CD%\dropv6.txt                          >> wsock_trace.appveyor
echo drop_url    = http://www.spamhaus.org/drop/drop.txt    >> wsock_trace.appveyor
echo edrop_url   = http://www.spamhaus.org/drop/edrop.txt   >> wsock_trace.appveyor
echo dropv6_url  = https://www.spamhaus.org/drop/dropv6.txt >> wsock_trace.appveyor

echo Generating appveyor-hosts file...
type appveyor_host_content.txt > appveyor-hosts

::
:: These should survive until 'build_script' for 'msvc', 'mingw32', 'mingw64,
:: 'cygwin32', 'cygwin64' or 'watcom' get to run.
::
set WSOCK_TRACE=%CD%\wsock_trace.appveyor
set WSOCK_TRACE_LEVEL=2
set COLUMNS=120

::
:: Some issue with the Cygwin builds forces me to put the generated
:: 'wsock_trace.appveyor' in AppVeyor's %APPDATA directory.
::
copy wsock_trace.appveyor c:\Users\appveyor\AppData\Roaming\wsock_trace > NUL
exit /b 0

::
:: Cleanup after a local 'appveyor-script <builder>'.
:: This is not used by AppVeyor itself (not refered in appveyor.yml).
::
:clean
del /Q IP46-COUNTRY.BIN xz.exe wsock_trace.appveyor appveyor-hosts watcom20.zip 2> NUL
echo Cleaning done.
exit /b 0
