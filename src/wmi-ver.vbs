' Run as:
'   cscript -nologo wmi-ver.vbs

set WMI = GetObject ("WinMgmts:{impersonationLevel=impersonate}!/root/cimv2")
set obj = WMI.Get ("Win32_WMISetting=@")

WScript.Echo obj.BuildVersion

