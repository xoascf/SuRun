//////////////////////////////////////////////////////////////////////////////
//
// This source code is part of SuRun
//
// Some sources in this project evolved from Microsoft sample code, some from 
// other free sources. The Shield Icons are taken from Windows XP Service Pack 
// 2 (xpsp2res.dll) 
// 
// Feel free to use the SuRun sources for your liking.
// 
//                                (c) Kay Bruns (http://kay-bruns.de), 2007,08
//////////////////////////////////////////////////////////////////////////////

#pragma once

#include "helpers.h"
#include "SuRunExt/SuRunExt.h"

//////////////////////////////////////////////////////////////////////////////
// 
//  HKLM\Security\SuRun keys
// 
//////////////////////////////////////////////////////////////////////////////

#define SVCKEY    _T("SECURITY\\SuRun")

#define PASSWKEY      SVCKEY _T("\\Cache")
#define TIMESKEY      SVCKEY _T("\\Times")
#define WHTLSTKEY(u)  CBigResStr(SVCKEY _T("\\%s"),u)
#define USERKEY(u)    CBigResStr(SVCKEY _T("\\%s\\Settings"),u)

#define RAPASSKEY(u)  CBigResStr(SVCKEY _T("\\RunAs\\%s\\Cache"),u)
#define USROPTKEY(u)  CBigResStr(_T("CLSID\\") sGUID _T("\\Options\\%s"),u)
//////////////////////////////////////////////////////////////////////////////
// 
//  Macros for all Settings
// 
//////////////////////////////////////////////////////////////////////////////

//////////////////////////////////////////////////////////////////////////////
//Settings for all users; saved to "HKLM\SECURITY\SuRun":
//////////////////////////////////////////////////////////////////////////////
#define GetOption(s,d)    GetRegInt(HKLM,SVCKEY,s,d)
#define SetOption(s,v,d)  if (GetOption(s,d)!=v)\
                            SetRegInt(HKLM,SVCKEY,s,v)

//blurred user desktop background on secure Desktop
#define GetBlurDesk       (GetOption(_T("BlurDesktop"),1)!=0)
#define SetBlurDesk(b)    SetOption(_T("BlurDesktop"),b,1)

//Minutes to wait until "Is that OK?" is asked again
#define GetPwTimeOut      min(60,max(0,(int)GetOption(_T("AskTimeOut"),0)))
#define SetPwTimeOut(t)   SetOption(_T("AskTimeOut"),(DWORD)min(60,max(0,(int)t)),0)

//Do not ask an Admin to become a SuRunner
#define GetNoConvAdmin    (GetOption(_T("NoAutoAdminToSuRunner"),0)!=0)
#define SetNoConvAdmin(b) SetOption(_T("NoAutoAdminToSuRunner"),b,0)

//Do not ask anyone to become a SuRunner
#define GetNoConvUser     (GetOption(_T("NoAutoUserToSuRunner"),0)!=0)
#define SetNoConvUser(b)  SetOption(_T("NoAutoUserToSuRunner"),b,0)

//New SuRunners are Restricted
#define GetRestrictNew    (GetOption(_T("RestrictNewRunner"),0)!=0)
#define SetRestrictNew(b) SetOption(_T("RestrictNewRunner"),b,0)

//New SuRunners may not Run Setup
#define GetNoSetupNew     (GetOption(_T("NewRunnerDenySetup"),0)!=0)
#define SetNoSetupNew(b)  SetOption(_T("NewRunnerDenySetup"),b,0)

//Save or not Passwords in the registry
#define GetSavePW         (GetOption(_T("SavePasswords"),1)!=0)
#define SetSavePW(b)      SetOption(_T("SavePasswords"),b,1); \
                          if (!b) \
                          { \
                            DelRegKey(HKLM,PASSWKEY); \
                            DelRegKey(HKLM,TIMESKEY); \
                          }

//////////////////////////////////////////////////////////////////////////////
//Settings for every user; saved to "HKLM\SECURITY\SuRun\<ComputerName>\<UserName>":
//////////////////////////////////////////////////////////////////////////////
#define GetUsrSetting(u,s,d)    GetRegInt(HKLM,USERKEY(u),s,d)
#define SetUsrSetting(u,s,v,d)  if(GetUsrSetting(u,s,d)!=v)\
                                  SetRegInt(HKLM,USERKEY(u),s,v)

#define DelUsrSettings(u)       DelRegKey(HKLM,WHTLSTKEY(u))

//SuRunner is not allowed to run Setup
#define GetNoRunSetup(u)      (GetUsrSetting(u,_T("AdminOnlySetup"),0)!=0)
#define SetNoRunSetup(u,b)    SetUsrSetting(u,_T("AdminOnlySetup"),b,0)
//SuRunner may only run predefined Applications
#define GetRestrictApps(u)    (GetUsrSetting(u,_T("RestrictApps"),0)!=0)
#define SetRestrictApps(u,b)  SetUsrSetting(u,_T("RestrictApps"),b,0)
//SuRunner may install Devices
//#define GetInstallDevs(u)      (GetUsrSetting(u,_T("AllowDevInst"),0)!=0)
//#define SetInstallDevs(u,b)    SetUsrSetting(u,_T("AllowDevInst"),b,0)

//////////////////////////////////////////////////////////////////////////////
//Shell Extension Settings; stored in: HKCR\\CLSID\\sGUID
//////////////////////////////////////////////////////////////////////////////
#define GetShExtSetting(s,d)    GetRegInt(HKCR,L"CLSID\\" sGUID,s,d)
#define SetShExtSetting(s,v,d)  if (GetShExtSetting(s,d)!=v)\
                                  SetRegInt(HKCR,L"CLSID\\" sGUID,s,v)

//the following settings are stored in: HKCR\\CLSID\\sGUID
#define ControlAsAdmin  L"ControlAsAdmin"  //"Control Panel As Admin" on Desktop Menu
#define CmdHereAsAdmin  L"CmdHereAsAdmin"  //"Cmd here As Admin" on Folder Menu
#define ExpHereAsAdmin  L"ExpHereAsAdmin"  //"Explorer here As Admin" on Folder Menu
#define RestartAsAdmin  L"RestartAsAdmin"  //"Restart As Admin" in System-Menu
#define StartAsAdmin    L"StartAsAdmin"    //"Start As Admin" in System-Menu

#define UseIShExHook    L"UseIShExHook"    //install IShellExecuteHook
#define UseIATHook      L"UseIATHook"      //install IAT Hook
#define UseAppInit      L"UseAppInit"      //use AppInit_DLLs
#define UseRemoteThread L"UseRemoteThread" //use CreateRemoteThread

#define ShowAutoRuns    L"ShowAutoRuns"    //use Show Message in Tray

//"Control Panel As Admin" on Desktop Menu
#define GetCtrlAsAdmin        (GetShExtSetting(ControlAsAdmin,1)!=0)
#define SetCtrlAsAdmin(b)     SetShExtSetting(ControlAsAdmin,b,1)
//"Cmd here As Admin" on Folder Menu
#define GetCmdAsAdmin         (GetShExtSetting(CmdHereAsAdmin,1)!=0)
#define SetCmdAsAdmin(b)      SetShExtSetting(CmdHereAsAdmin,b,1)
//"Explorer here As Admin" on Folder Menu
#define GetExpAsAdmin         (GetShExtSetting(ExpHereAsAdmin,1)!=0)
#define SetExpAsAdmin(b)      SetShExtSetting(ExpHereAsAdmin,b,1)
//"Restart As Admin" in System-Menu
#define GetRestartAsAdmin     (GetShExtSetting(RestartAsAdmin,1)!=0)
#define SetRestartAsAdmin(b)  SetShExtSetting(RestartAsAdmin,b,1)
//"Start As Admin" in System-Menu
#define GetStartAsAdmin       (GetShExtSetting(StartAsAdmin,1)!=0)
#define SetStartAsAdmin(b)    SetShExtSetting(StartAsAdmin,b,1)

//Hook stuff
#define GetUseIShExHook       (GetShExtSetting(UseIShExHook,1)!=0)
#define SetUseIShExHook(b)     SetShExtSetting(UseIShExHook,b,1)
#define GetUseIATHook         (GetShExtSetting(UseIATHook,0)!=0)
#define SetUseIATHook(b)       SetShExtSetting(UseIATHook,b,0)

//TrayMsg stuff
#define GetShowAutoRuns       (GetShExtSetting(ShowAutoRuns,1)!=0)
#define SetShowAutoRuns(b)    SetShExtSetting(ShowAutoRuns,b,1)

//Show App admin status in system tray
#define GetShowTrayAdmin      GetShExtSetting(_T("ShowTrayAdmin"),0)
#define SetShowTrayAdmin(b)   SetShExtSetting(_T("ShowTrayAdmin"),b,0)


//Show App admin status in system tray per user setting
#define GetUsrOption(u,s,d)   GetRegInt(HKCR,USROPTKEY(u),s,d)
#define SetUsrOption(u,s,v,d) if(GetUsrOption(u,s,d)!=v)\
                                SetRegInt(HKLM,USROPTKEY(u),s,v)

#define DelUsrOption(u,s)     RegDelVal(HKLM,USROPTKEY(u),s)

#define GetUserTSA(u)         GetUsrOption(u,_T("ShowTrayAdmin"),-1)
#define SetUserTSA(u,v)       SetUsrOption(u,_T("ShowTrayAdmin"),v,-1)
#define DelUserTSA(u)         DelUsrOption(u,_T("ShowTrayAdmin"))

#define ShowTray(u)           (GetShowTrayAdmin!=0)&&(GetUserTSA(u)!=0)
#define ShowBalloon(u)        ((GetShowTrayAdmin==2)&&(GetUserTSA(u)==-1))\
                              ||(GetUserTSA(u)==2)

//#define GetUseRmteThread      (GetShExtSetting(UseRemoteThread,0)!=0)
//#define SetUseRmteThread(b)    SetShExtSetting(UseRemoteThread,b,0)
  //...This is defined here but stored in HKLM\Security:
//#define GetUseAppInit         (GetOption(UseAppInit,0)!=0)
//#define SetUseAppInit(b)       SetOption(UseAppInit,b,0)

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

#define FLAG_DONTASK    0x01 //SuRun will not ask if App can be executed
#define FLAG_SHELLEXEC  0x02 //ShellExecute hook will execute App elevated
#define FLAG_NORESTRICT 0x04 //Restricted SuRunner may execute App elevated
#define FLAG_AUTOCANCEL 0x08 //SuRun will always answer "cancel"
#define FLAG_CANCEL_SX  0x10 //SuRun will answer "cancel" on ShellExec

BOOL IsInWhiteList(LPTSTR User,LPTSTR CmdLine,DWORD Flag);
DWORD GetWhiteListFlags(LPTSTR User,LPTSTR CmdLine,DWORD Default);
BOOL AddToWhiteList(LPTSTR User,LPTSTR CmdLine,DWORD Flags=0);
BOOL SetWhiteListFlag(LPTSTR User,LPTSTR CmdLine,DWORD Flag,bool Enable);
BOOL ToggleWhiteListFlag(LPTSTR User,LPTSTR CmdLine,DWORD Flag);
BOOL RemoveFromWhiteList(LPTSTR User,LPTSTR CmdLine);

//////////////////////////////////////////////////////////////////////////////
// 
//  Registry replace stuff
// 
//////////////////////////////////////////////////////////////////////////////
void ReplaceRunAsWithSuRun(HKEY hKey=HKCR);
void ReplaceSuRunWithRunAs(HKEY hKey=HKCR);

//////////////////////////////////////////////////////////////////////////////
// 
//  Setup
// 
//////////////////////////////////////////////////////////////////////////////

BOOL RunSetup();

