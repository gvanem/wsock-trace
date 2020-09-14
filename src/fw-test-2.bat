@echo off
setlocal
::
:: Run net-SNMP's snmpwalk with 'Iface description OID'
::
set PROG="f:\MinGW32\src\inet\SNMP\net-snmp\snmpwalk.exe -v2c -c public -Ofn 10.0.0.21 .1.3.6.1.2.1.1.1 & sleep 10"
set WSOCK_TRACE_LEVEL=2

echo Running SNMPWALK.EXE in firewall_test.exe with a 10 sec sleep.

firewall_test.exe %* -l fw-test-2.txt %PROG%
