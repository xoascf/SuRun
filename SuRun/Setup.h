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

//Settings for all users; saved to "HKLM\SECURITY\SuRun":
extern bool g_BlurDesktop;      //blurred user desktop background on secure Desktop
extern BYTE g_NoAskTimeOut;     //Minutes to wait until "Is that OK?" is asked again
extern bool g_bSavePW;          //Save Passwords in Registry

//Settings for every user; saved to "HKLM\SECURITY\SuRun\<ComputerName>\<UserName>":
extern bool g_bAdminOnlySetup;  //Only real Admins may run Setup
extern bool g_bRestricApps;     //SuRunner may only run predefined Applications

//Shell Extension Settings; stored in: HKCR\\CLSID\\sGUID
extern bool g_bControlAsAdmin;  //"Control Panel As Admin" on Desktop Menu
extern bool g_bCmdHereAsAdmin;  //"Cmd here As Admin" on Folder Menu
extern bool g_bExpHereAsAdmin;  //"Explorer here As Admin" on Folder Menu
extern bool g_bRestartAsAdmin;  //"Restart As Admin" in System-Menu
extern bool g_bStartAsAdmin;    //"Start As Admin" in System-Menu

//////////////////////////////////////////////////////////////////////////////
// 
//  LoadSettings
// 
//////////////////////////////////////////////////////////////////////////////
void LoadSettings(LPTSTR UserName);

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

//FILETIME(100ns) to minutes multiplier
#define ft2min  (__int64)(10/*1µs*/*1000/*1ms*/*1000/*1s*/*60/*1min*/)

__int64 GetLastRunTime(LPTSTR UserName);
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
BOOL RemoveFromWhiteList(LPTSTR User,LPTSTR CmdLine,DWORD Flag);
void SaveToWhiteList(LPTSTR User,LPTSTR CmdLine,DWORD Flag);

//////////////////////////////////////////////////////////////////////////////
// 
//  Setup
// 
//////////////////////////////////////////////////////////////////////////////

BOOL RunSetup();

