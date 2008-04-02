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

//////////////////////////////////////////////////////////////////////////////
// Display various Dialogs to:
// *Logon a Windows User
// *Logon an Administrator
// *Logon the current user
// *Ask, if something should be started with administrative rights
//////////////////////////////////////////////////////////////////////////////
#pragma once

// Check is a password for a user is correct
BOOL PasswordOK(LPCTSTR User,LPCTSTR Password);

BOOL Logon(LPTSTR User,LPTSTR Password,int IDmsg,...);

BOOL RunAsLogon(LPTSTR User,LPTSTR Password,int IDmsg,...);

BOOL LogonAdmin(LPTSTR User,LPTSTR Password,int IDmsg,...);
BOOL LogonAdmin(int IDmsg,...);

DWORD LogonCurrentUser(LPTSTR User,LPTSTR Password,DWORD UsrFlags,int IDmsg,...);

DWORD AskCurrentUserOk(LPTSTR User,DWORD UsrFlags,int IDmsg,...);