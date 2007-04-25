#pragma once

BOOL Logon(LPTSTR User,LPTSTR Password,int IDmsg,...);
BOOL LogonAdmin(LPTSTR User,LPTSTR Password,int IDmsg,...);
BOOL LogonCurrentUser(LPTSTR User,LPTSTR Password,int IDmsg,...);

BOOL AskCurrentUserOk(LPTSTR User,int IDmsg,...);