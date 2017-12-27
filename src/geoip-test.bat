@echo off
::
:: Simple test for geoip/IP2Loc.
:: Rewrite this into a Python script some day.
::
setlocal

if %1. == -d. (
  set WSOCK_TRACE_LEVEL=2
  shift
)

set TEST_INPUT=%TEMP%\geoip-addr4.test
echo Generating %TEST_INPUT%...
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

@echo on
type %TEST_INPUT% | geoip.exe -4 %1 %2 %3
