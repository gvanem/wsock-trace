@echo off
@echo arg1: "%1", arg2: "%2"

if %1. ==  build_msvc.  goto build_msvc
if %1. ==  build_mingw. goto build_mingw
if %1. NEQ init.  exit /b 0

::
:: The CPU agnostic init-stage.
::
echo Generating wsock_trace.appveyor...
echo #                                            > wsock_trace.appveyor
echo # This file was generated from %0.          >> wsock_trace.appveyor
echo #                                           >> wsock_trace.appveyor
echo [core]                                      >> wsock_trace.appveyor
echo trace_level            = 2                  >> wsock_trace.appveyor
echo trace_indent           = 2                  >> wsock_trace.appveyor
echo trace_caller           = 1                  >> wsock_trace.appveyor
echo trace_report           = 1                  >> wsock_trace.appveyor
echo trace_time             = relative           >> wsock_trace.appveyor
echo callee_level           = 1                  >> wsock_trace.appveyor
echo cpp_demangle           = 1                  >> wsock_trace.appveyor
echo short_errors           = 1                  >> wsock_trace.appveyor
echo use_full_path          = 1                  >> wsock_trace.appveyor
echo use_toolhlp32          = 1                  >> wsock_trace.appveyor
echo dump_select            = 1                  >> wsock_trace.appveyor
echo dump_hostent           = 1                  >> wsock_trace.appveyor
echo dump_protoent          = 1                  >> wsock_trace.appveyor
echo dump_servent           = 1                  >> wsock_trace.appveyor
echo dump_nameinfo          = 1                  >> wsock_trace.appveyor
echo dump_wsaprotocol_info  = 1                  >> wsock_trace.appveyor
echo dump_wsanetwork_events = 1                  >> wsock_trace.appveyor
echo dump_data              = 1                  >> wsock_trace.appveyor
echo max_data               = 5000               >> wsock_trace.appveyor
echo max_displacement       = 100                >> wsock_trace.appveyor
echo exclude                = htons,htonl        >> wsock_trace.appveyor
echo [geoip]                                     >> wsock_trace.appveyor
echo enable               = 1                    >> wsock_trace.appveyor
echo use_generated        = 0                    >> wsock_trace.appveyor
echo max_days             = 10                   >> wsock_trace.appveyor
echo geoip4_file          = %CD%\geoip           >> wsock_trace.appveyor
echo geoip6_file          = %CD%\geoip6          >> wsock_trace.appveyor
echo ip2location_bin_file= #%CD%\IP4-COUNTRY.BIN >> wsock_trace.appveyor
echo [idna]                                      >> wsock_trace.appveyor
echo enable   = 1                                >> wsock_trace.appveyor
echo winidn   = 0                                >> wsock_trace.appveyor
echo codepage = 0                                >> wsock_trace.appveyor

::
:: Get the IP2Location code.
::
md IP2Location
git clone https://github.com/chrislim2888/IP2Location-C-Library.git IP2Location
echo /* Dummy IP2Location config.h */ > IP2Location\config.h

::
:: Get the IP2Location .bin-file.
::
set WSOCK_TRACE=
set WSOCK_TRACE_LEVEL=
echo Downloading IP4-COUNTRY.BIN.gz
curl --remote-name --progress-bar http://www.watt-32.net/misc/IP4-COUNTRY.BIN.gz
goto end

::
:: Setup MSVC environment.
:: Param '%2' is either 'x86' or 'x64'
::
:build_msvc
call "c:\Program Files\Microsoft SDKs\Windows\v7.1\Bin\SetEnv.cmd" /%2
set WSOCK_TRACE=%CD%\wsock_trace.appveyor
set COLUMNS=120
set INCLUDE=%INCLUDE%;%CD%\IP2Location\libIP2Location
set PLATFORM=%CPU%

cd src
echo nmake -nologo -f Makefile.vc6 USER=AppVeyor PLATFORM=%2
nmake -nologo -f Makefile.vc6 USER=AppVeyor PLATFORM=%2
if errorlevel == 0 test.exe
goto end

::
:: Setup MinGW 32-bit environment (if '%2 == x86').
:: Setup MinGW 64-bit environment (if '%2 == x64').
::
:build_mingw
set WSOCK_TRACE=%CD%\wsock_trace.appveyor
set COLUMNS=120
set C_INCLUDE_PATH=%CD%\IP2Location\libIP2Location

echo on

if %2. == x86. (
  set MINGW_ROOT=c:\MinGW
) else (
  set MINGW_ROOT=c:\mingw-w64\x86_64-6.3.0-posix-seh-rt_v5-rev1
)

set PATH=%MINGW_ROOT%\bin;%PATH%

cd src
echo mingw32-make -f Makefile.MinGW USER=AppVeyor USE_IP2LOCATION=1 CPU=%2
mingw32-make -f Makefile.MinGW USER=AppVeyor USE_IP2LOCATION=1 CPU=%2
if errorlevel == 0 test.exe

:end
