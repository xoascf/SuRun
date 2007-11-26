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

BOOL LogonAdmin(LPTSTR User,LPTSTR Password,int IDmsg,...);
BOOL LogonAdmin(int IDmsg,...);

BOOL LogonCurrentUser(LPTSTR User,LPTSTR Password,BOOL bShellExecOk,int IDmsg,...);

BOOL AskCurrentUserOk(LPTSTR User,BOOL bShellExecOk,int IDmsg,...);