@echo off
::
:: Simple test for geoip/IP2Loc.
:: Rewrite this into a Python script some day.
::
:: setlocal
set WSOCK_TRACE_LEVEL=0
set TEST_INPUT_4=%TEMP%\geoip-addr_4.test
set TEST_INPUT_6=%TEMP%\geoip-addr_6.test

if %1. == -h. (
  echo Usage: %0 [-h ^| -d ^| --ip2loc_4 ^| --ip2loc_6]
  echo ^    -h:         this help.
  echo ^    -d:         sets "WSOCK_TRACE_LEVEL=2".
  echo ^    --ip2loc_4: test using addresses in "%TEST_INPUT_4%".
  echo ^    --ip2loc_6: test using addresses in "%TEST_INPUT_6%".
  exit /b 0
)

if %1. == -d. (
  set WSOCK_TRACE_LEVEL=2
  shift
)

::
:: Previously data from:
::  ..\IP2Location-C-Library\test\country_test_ipv4_data.txt
:: + some more
::
echo Generating %TEST_INPUT_4%...

echo 19.5.10.1         > %TEST_INPUT_4%
echo 25.5.10.2        >> %TEST_INPUT_4%
echo 43.5.10.3        >> %TEST_INPUT_4%
echo 47.5.10.4        >> %TEST_INPUT_4%
echo 51.5.10.5        >> %TEST_INPUT_4%
echo 53.5.10.6        >> %TEST_INPUT_4%
echo 80.5.10.7        >> %TEST_INPUT_4%
echo 81.5.10.8        >> %TEST_INPUT_4%
echo 83.5.10.9        >> %TEST_INPUT_4%
echo 85.5.10.0        >> %TEST_INPUT_4%
echo 194.38.123.15    >> %TEST_INPUT_4%
echo 218.156.62.27    >> %TEST_INPUT_4%
echo 104.218.222.242  >> %TEST_INPUT_4%
echo 69.86.117.107    >> %TEST_INPUT_4%
echo 36.237.237.167   >> %TEST_INPUT_4%
echo 99.163.121.226   >> %TEST_INPUT_4%
echo 101.159.46.181   >> %TEST_INPUT_4%
echo 78.33.206.219    >> %TEST_INPUT_4%
echo 96.135.76.208    >> %TEST_INPUT_4%
echo 192.31.5.47      >> %TEST_INPUT_4%
echo 244.210.76.66    >> %TEST_INPUT_4%
echo 210.113.60.169   >> %TEST_INPUT_4%
echo 59.169.95.118    >> %TEST_INPUT_4%
echo 86.104.62.176    >> %TEST_INPUT_4%
echo 170.185.77.168   >> %TEST_INPUT_4%
echo 201.227.72.250   >> %TEST_INPUT_4%
echo 226.212.139.179  >> %TEST_INPUT_4%
echo 247.140.100.112  >> %TEST_INPUT_4%
::
:: Add some IPv4 addresses from SpamHaus' DROP.txt too:
::
echo 23.226.48.10  # part of 23.226.48.0/20  ; SBL322605 >> %TEST_INPUT_4%
echo 84.238.160.4  # part of 84.238.160.0/22 ; SBL339089 >> %TEST_INPUT_4%

::
:: Previously data from:
::  ..\IP2Location-C-Library\test\country_test_ipv6_data.txt
:: + some more.
::
echo Generating %TEST_INPUT_6%...

echo 2001:0200:0102::      # JP  > %TEST_INPUT_6%
echo 2a01:04f8:0d16:25c2:: # DE >> %TEST_INPUT_6%
echo 2a01:04f8:0d16:26c2:: # DE >> %TEST_INPUT_6%
echo 2a01:ad20::           # ES >> %TEST_INPUT_6%
echo 2a01:af60::           # PL >> %TEST_INPUT_6%
echo 2a01:b200::           # SK >> %TEST_INPUT_6%
echo 2a01:b340::           # IE >> %TEST_INPUT_6%
echo 2a01:b4c0::           # CZ >> %TEST_INPUT_6%
echo 2a01:b600:8001::      # IT >> %TEST_INPUT_6%
echo 2a01:b6c0::           # SE >> %TEST_INPUT_6%

::
:: Add some special IPv6 addresses too:
::
echo fd00:a41::50          # non-global   >> %TEST_INPUT_6%
echo 2002::1               # 6to4 prefix  >> %TEST_INPUT_6%
echo 2001:0::50            # Teredo       >> %TEST_INPUT_6%
echo 3FFE:831F::50         # Teredo old   >> %TEST_INPUT_6%

::
:: Add some IPv6 addresses from SpamHaus' DROPv6.txt too:
::
echo 2a06:f680::3   # part of 2a06:f680::/29 ; SBL303641 >> %TEST_INPUT_6%
echo 2a07:9b80::33  # part of 2a07:9b80::/29 ; SBL342980 >> %TEST_INPUT_6%

@echo on

if %1. == --ip2loc_4. (
  shift
  %~dp0geoip.exe -4 %2 %3 %4 @%TEST_INPUT_4%
) else if %1. == --ip2loc_6. (
  shift
  %~dp0geoip.exe -6 %2 %3 %4 @%TEST_INPUT_6%
) else (
  %~dp0geoip.exe -4 %1 %2 %3 @%TEST_INPUT_4%
)

