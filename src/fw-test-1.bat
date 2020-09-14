@echo off
setlocal
::
:: CygWin's sleep
::
set PROG=sleep 20

echo Running 2 instances of firewall_test.exe for 20 sec and comparing the results.

start firewall_test.exe -l fw-test.1 %PROG% & ^
      firewall_test.exe -l fw-test.2 %PROG%

diff -u3 fw-test.1 fw-test.2
