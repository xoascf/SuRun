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

//returns true if the hToken/the current Thread belongs to the Administrators
BOOL IsAdmin(HANDLE hToken=NULL);

//returns true if the user has a non piviliged split token
BOOL IsSplitAdmin();

// return true if you are running as local system
bool IsLocalSystem();

//Start a process with Admin cedentials and wait until it closed
BOOL RunAsAdmin(LPCTSTR lpCmdLine,int IDmsg);
