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

#include "SuRunExt/SuRunExt.h"

//////////////////////////////////////////////////////////////////////////////
// 
//  HKLM\Security\SuRun keys
// 
//////////////////////////////////////////////////////////////////////////////

#define PASSWKEY      SVCKEY _T("\\Cache")
#define TIMESKEY      SVCKEY _T("\\Times")
#define WHTLSTKEY(u)  CBigResStr(_T("%s\\%s"),SVCKEY,u)
#define USERKEY(u)    CBigResStr(_T("%s\\%s\\Settings"),SVCKEY,u)

//////////////////////////////////////////////////////////////////////////////
// 
//  Macros for all Settings
// 
//////////////////////////////////////////////////////////////////////////////

//////////////////////////////////////////////////////////////////////////////
//Settings for all users; saved to "HKLM\SECURITY\SuRun":
//////////////////////////////////////////////////////////////////////////////
#define GetOption(s,d) GetRegInt(HKLM,SVCKEY,s,d)
#define SetOption(s,v) SetRegInt(HKLM,SVCKEY,s,v)

//blurred user desktop background on secure Desktop
#define GetBlurDesk       (GetOption(_T("BlurDesktop"),1)!=0)
#define SetBlurDesk(b)    SetOption(_T("BlurDesktop"),b)

//Minutes to wait until "Is that OK?" is asked again
#define GetPwTimeOut      min(60,max(0,(int)GetOption(_T("AskTimeOut"),0)))
#define SetPwTimeOut(t)   min(60,max(0,(int)SetOption(_T("AskTimeOut"),t)))

//Save or not Passwords in the registry
#define GetSavePW         (GetOption(_T("SavePasswords"),1)!=0)
#define SetSavePW(b)      SetOption(_T("SavePasswords"),b); \
                          if (!b) \
                          { \
                            DelRegKey(HKLM,PASSWKEY); \
                            DelRegKey(HKLM,TIMESKEY); \
                          }

//All Users may use SuRun
#define GetAllowAll       (GetOption(_T("AllowAllUsers"),0)!=0)
#define SetAllowAll(b)    SetOption(_T("AllowAllUsers"),b)

//////////////////////////////////////////////////////////////////////////////
//Settings for every user; saved to "HKLM\SECURITY\SuRun\<ComputerName>\<UserName>":
//////////////////////////////////////////////////////////////////////////////
#define GetUsrSetting(u,s,d)  GetRegInt(HKLM,USERKEY(u),s,d)
#define SetUsrSetting(u,s,v)  SetRegInt(HKLM,USERKEY(u),s,v)

//SuRunner is not allowed to run Setup
#define GetNoRunSetup(u)      (GetUsrSetting(u,_T("AdminOnlySetup"),0)!=0)
#define SetNoRunSetup(u,b)    SetUsrSetting(u,_T("AdminOnlySetup"),b)
//SuRunner may only run predefined Applications
#define GetRestrictApps(u)    (GetUsrSetting(u,_T("RestrictApps"),0)!=0)
#define SetRestrictApps(u,b)  SetUsrSetting(u,_T("RestrictApps"),b)

//////////////////////////////////////////////////////////////////////////////
//Shell Extension Settings; stored in: HKCR\\CLSID\\sGUID
//////////////////////////////////////////////////////////////////////////////
#define GetShExtSetting(s,d)  GetRegInt(HKCR,L"CLSID\\" sGUID,s,d)
#define SetShExtSetting(s,v)  SetRegInt(HKCR,L"CLSID\\" sGUID,s,v)

//the following settings are stored in: HKCR\\CLSID\\sGUID
#define ControlAsAdmin  L"ControlAsAdmin"  //"Control Panel As Admin" on Desktop Menu
#define CmdHereAsAdmin  L"CmdHereAsAdmin"  //"Cmd here As Admin" on Folder Menu
#define ExpHereAsAdmin  L"ExpHereAsAdmin"  //"Explorer here As Admin" on Folder Menu
#define RestartAsAdmin  L"RestartAsAdmin"  //"Restart As Admin" in System-Menu
#define StartAsAdmin    L"StartAsAdmin"    //"Start As Admin" in System-Menu

//"Control Panel As Admin" on Desktop Menu
#define GetCtrlAsAdmin        (GetShExtSetting(ControlAsAdmin,1)!=0)
#define SetCtrlAsAdmin(b)     SetShExtSetting(ControlAsAdmin,b)
//"Cmd here As Admin" on Folder Menu
#define GetCmdAsAdmin         (GetShExtSetting(CmdHereAsAdmin,1)!=0)
#define SetCmdAsAdmin(b)      SetShExtSetting(CmdHereAsAdmin,b)
//"Explorer here As Admin" on Folder Menu
#define GetExpAsAdmin         (GetShExtSetting(ExpHereAsAdmin,1)!=0)
#define SetExpAsAdmin(b)      SetShExtSetting(ExpHereAsAdmin,b)
//"Restart As Admin" in System-Menu
#define GetRestartAsAdmin     (GetShExtSetting(RestartAsAdmin,1)!=0)
#define SetRestartAsAdmin(b)  SetShExtSetting(RestartAsAdmin,b)
//"Start As Admin" in System-Menu
#define GetStartAsAdmin       (GetShExtSetting(StartAsAdmin,1)!=0)
#define SetStartAsAdmin(b)    SetShExtSetting(StartAsAdmin,b)

//////////////////////////////////////////////////////////////////////////////
//  Windows Policy Stuff
//////////////////////////////////////////////////////////////////////////////

#define IsOwnerAdminGrp     (GetRegInt(HKLM,\
                              _T("SYSTEM\\CurrentControlSet\\Control\\Lsa"),\
                              _T("nodefaultadminowner"),1)==0)

#define SetOwnerAdminGrp(b) SetRegInt(HKLM,\
                              _T("SYSTEM\\CurrentControlSet\\Control\\Lsa"),\
                              _T("nodefaultadminowner"),(b)==0)

#define IsWinUpd4All      GetRegInt(HKLM,\
                            _T("SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate"),\
                            _T("ElevateNonAdmins"),0)

#define SetWinUpd4All(b)  SetRegInt(HKLM,\
                            _T("SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate"),\
                            _T("ElevateNonAdmins"),b)

#define IsWinUpdBoot      GetRegInt(HKLM,\
                            _T("SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU"),\
                            _T("NoAutoRebootWithLoggedOnUsers"),0)

#define SetWinUpdBoot(b)  SetRegInt(HKLM,\
                            _T("SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU"),\
                            _T("NoAutoRebootWithLoggedOnUsers"),b)

#define CanSetEnergy  HasRegistryKeyAccess(_T("MACHINE\\Software\\Microsoft\\")\
                    _T("Windows\\CurrentVersion\\Controls Folder\\PowerCfg"),SURUNNERSGROUP)

#define SetEnergy(b)  SetRegistryTreeAccess(_T("MACHINE\\Software\\Microsoft\\")\
                    _T("Windows\\CurrentVersion\\Controls Folder\\PowerCfg"),SURUNNERSGROUP,b)

//////////////////////////////////////////////////////////////////////////////
// 
//  Password cache
// 
//////////////////////////////////////////////////////////////////////////////

void LoadPassword(LPTSTR UserName,LPTSTR Password,DWORD nBytes);
void DeletePassword(LPTSTR UserName);
void SavePassword(LPTSTR UserName,LPTSTR Password);

//////////////////////////////////////////////////////////////////////////////
// 
//  Password TimeOut
// 
//////////////////////////////////////////////////////////////////////////////

BOOL PasswordExpired(LPTSTR UserName);
void UpdLastRunTime(LPTSTR UserName);

//////////////////////////////////////////////////////////////////////////////
// 
// WhiteList handling
// 
//////////////////////////////////////////////////////////////////////////////

#define FLAG_DONTASK   1  //SuRun will not ask if App can be executed
#define FLAG_SHELLEXEC 2  //ShellExecute hook will execute App elevated
#define FLAG_NORESTRICT 4 //Restricted SuRunner may execute App elevated

BOOL IsInWhiteList(LPTSTR User,LPTSTR CmdLine,DWORD Flag);
BOOL SetWhiteListFlag(LPTSTR User,LPTSTR CmdLine,DWORD Flag,bool Enable);
BOOL ToggleWhiteListFlag(LPTSTR User,LPTSTR CmdLine,DWORD Flag);
BOOL RemoveFromWhiteList(LPTSTR User,LPTSTR CmdLine);

//////////////////////////////////////////////////////////////////////////////
// 
//  Setup
// 
//////////////////////////////////////////////////////////////////////////////

BOOL RunSetup();

