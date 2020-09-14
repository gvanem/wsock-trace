@echo off
setlocal
on break quit

set CARES_TRACE=0
set WSOCK_TRACE_LEVEL=2
set WSOCK_DNSBL_ENABLE=1
set WSOCK_DNSBL_TEST=1

%MINGW32%\src\inet\DNS\c-ares\adig.exe -s 193.213.112.4 -t PTR -x 103.21.59.169
