//////////////////////////////////////////////////////////////////////////////
//
// This source code is part of SuRun
//
// Some sources in this project evolved from Microsoft sample code, some from 
// other free sources. The Application icons are from Foood's "iCandy" icon 
// set (http://www.iconaholic.com). the Shield Icons are taken from Windows XP 
// Service Pack 2 (xpsp2res.dll) 
// 
// Feel free to use the SuRun sources for your liking.
// 
//                                   (c) Kay Bruns (http://kay-bruns.de), 2007
//////////////////////////////////////////////////////////////////////////////

#pragma once
#include <shlobj.h>


extern "C" __declspec(dllexport) void RemoveShellExt();
extern "C" __declspec(dllexport) void InstallShellExt();

// {2C7B6088-5A77-4d48-BE43-30337DCA9A86}
DEFINE_GUID(CLSID_ShellExtension,0x2c7b6088,0x5a77,0x4d48,0xbe,0x43,0x30,0x33,0x7d,0xca,0x9a,0x86);
#define sGUID L"{2C7B6088-5A77-4d48-BE43-30337DCA9A86}"

#define ControlAsAdmin  L"ControlAsAdmin"  //"Control Panel As Admin" on Desktop Menu
#define CmdHereAsAdmin  L"CmdHereAsAdmin"  //"Cmd here As Admin" on Folder Menu
#define ExpHereAsAdmin  L"ExpHereAsAdmin"  //"Explorer here As Admin" on Folder Menu
#define RestartAsAdmin  L"RestartAsAdmin"  //"Restart As Admin" in System-Menu
#define StartAsAdmin    L"StartAsAdmin"    //"Start As Admin" in System-Menu
