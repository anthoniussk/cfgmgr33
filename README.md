# cfgmgr33
Proxy DLL for DaVinci Resolve 17 on Windows 7

This is proxy DLL created for using DaVinci Resolve on Windows 7. Windows 10 version of cfgmgr32.dll provide new function for notification from USB ports that is not available in Windows 7. DaVinci Resolve from version 17 uses this new function and cough at windows 7 users. This proxy DLL implements export of this function to run Resolve 7, but it only inmediatelly return back.

The disadvantage of this solution is that the application cannot work properly with USB devices inserted into the USB port during the operation of the application. If the device is inserted into the USB port before launching the application, this should not affect the function of the application.

This proxy DLL could also work with other applications that report a problem with cfgmgr32.dll - CM_Register_Notification error in the Windows 7. But the application needs to be patched.

Video tutorial for using DaVinchi Resolve 17 on Windows 7 (and how to patch application)
