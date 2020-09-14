::
:: Generates a list of GUIDs for the Windows Filtering Platform.
:: I.e. parses this from the preprocessed outout of <fwpmu.h>:
::
:: DEFINE_GUID(
::   FWPM_LAYER_.* = {
::   0xc86fd1bf,
::   0x21cd,
::   0x497e,
::   0xa0, 0xbb, 0x17, 0x42, 0x5c, 0x88, 0x5c, 0x58
:: );
::
@echo off
setlocal
:: if %_cmdproc. neq 4NT. (set prompt=$P$G & echo on)

set CFLAGS=-nologo -E -D_WIN32_WINNT=0xA000
set GREP_OPT=--before-context=1 --after-context=5
set GUID_C=%TEMP%\gen-fwpm-guid.c
set GUID_TMP=%TEMP%\gen-fwpm-guid.tmp
set GUID_RES=%TEMP%\gen-fwpm-guid.result

echo #include "fwpmu.h"  > %GUID_C%
cl.exe %CFLAGS% %GUID_C% > %GUID_TMP%

grep.exe %GREP_OPT% "   FWPM_LAYER_.*," %GUID_TMP% | sed.exe -e "s@--@@" -e "s@DEFINE_GUID(@_DEFINE_GUID (@" > %GUID_RES%

echo Done. Look in %GUID_RES%