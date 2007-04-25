#pragma once

//returns true if the hToken/the current Thread belongs to the Administrators
BOOL IsAdmin(HANDLE hToken=NULL);

//returns true if the user has a non piviliged split token
BOOL IsSplitAdmin();

// return true if you are running as local system
bool IsLocalSystem();

//Start a process with Admin cedentials and wait until it closed
BOOL RunAsAdmin(LPCTSTR lpCmdLine,int IDmsg);
