@echo off
::
:: Simple test for geoip/IP2Loc.
:: Rewrite this into a Python script some day.
::
setlocal

if %1. == -h. (
  echo Usage: %0 [-h ^| -d ^| --ip2loc_4 ^| --ip2loc_6]
  echo ^    -h:         this help.
  echo ^    -d:         sets "WSOCK_TRACE_LEVEL=2".
  echo ^    --ip2loc_4: test using addresses in "..\IP2Location-C-Library\test\country_test_ipv4_data.txt".
  echo ^    --ip2loc_6: test using addresses in "..\IP2Location-C-Library\test\country_test_ipv6_data.txt".
  exit /b 0
)

if %1. == -d. (
  set WSOCK_TRACE_LEVEL=2
  shift
)

set TEST_INPUT=%TEMP%\geoip-addr.test
echo Generating %TEST_INPUT%...

if %1. == --ip2loc_4. (
  grep.exe -o "[0-9\.]*" ..\IP2Location-C-Library\test\country_test_ipv4_data.txt > %TEST_INPUT%
  %~dp0geoip.exe -4 %2 %3 %4 @%TEST_INPUT%
  exit /b 0
)

if %1. == --ip2loc_6. (
  grep.exe -o "[0-9a-f\:]*" ..\IP2Location-C-Library\test\country_test_ipv6_data.txt > %TEST_INPUT%
  %~dp0geoip.exe -6 %2 %3 %4 @%TEST_INPUT%
  exit /b 0
)

echo 19.5.10.1      # US  > %TEST_INPUT%
echo 25.5.10.2      # GB >> %TEST_INPUT%
echo 43.5.10.3      # JP >> %TEST_INPUT%
echo 47.5.10.4      # CA >> %TEST_INPUT%
echo 51.5.10.5      # DE >> %TEST_INPUT%
echo 53.5.10.6      # DE >> %TEST_INPUT%
echo 80.5.10.7      # GB >> %TEST_INPUT%
echo 81.5.10.8      # IL >> %TEST_INPUT%
echo 83.5.10.9      # PL >> %TEST_INPUT%
echo 85.5.10.0      # CH >> %TEST_INPUT%
echo 194.38.123.15       >> %TEST_INPUT%
echo 218.156.62.27       >> %TEST_INPUT%
echo 104.218.222.242     >> %TEST_INPUT%
echo 69.86.117.107       >> %TEST_INPUT%
echo 36.237.237.167      >> %TEST_INPUT%
echo 99.163.121.226      >> %TEST_INPUT%
echo 101.159.46.181      >> %TEST_INPUT%
echo 78.33.206.219       >> %TEST_INPUT%
echo 96.135.76.208       >> %TEST_INPUT%
echo 192.31.5.47         >> %TEST_INPUT%
echo 244.210.76.66       >> %TEST_INPUT%
echo 210.113.60.169      >> %TEST_INPUT%
echo 59.169.95.118       >> %TEST_INPUT%
echo 86.104.62.176       >> %TEST_INPUT%
echo 170.185.77.168      >> %TEST_INPUT%
echo 201.227.72.250      >> %TEST_INPUT%
echo 226.212.139.179     >> %TEST_INPUT%
echo 247.140.100.112     >> %TEST_INPUT%

::
:: Add some IPv4 addresses from SpamHaus' DROP.txt too:
::
echo 23.226.48.10  # part of 23.226.48.0/20  ; SBL322605 >> %TEST_INPUT%
echo 84.238.160.4  # part of 84.238.160.0/22 ; SBL339089 >> %TEST_INPUT%

@echo on
type %TEST_INPUT% | %~dp0geoip.exe -4 %1 %2 %3
