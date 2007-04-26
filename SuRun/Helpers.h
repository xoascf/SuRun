#pragma once

#define countof(b) sizeof(b)/sizeof(b[0])
#define zero(x) memset(&x,0,sizeof(x))

//  Registry Helper
BOOL DelRegKey(HKEY hKey,LPTSTR pszSubKey);
BOOL RegDelVal(HKEY HK,LPCTSTR SubKey,LPCTSTR ValName);

BOOL SetRegInt(HKEY HK,LPCTSTR SubKey,LPCTSTR ValName,DWORD Value);
DWORD GetRegInt(HKEY HK,LPCTSTR SubKey,LPCTSTR ValName,DWORD Default);

BOOL SetRegStr(HKEY HK,LPCTSTR SubKey,LPCTSTR ValName,LPCTSTR Value);
BOOL GetRegStr(HKEY HK,LPCTSTR SubKey,LPCTSTR Val,LPTSTR Str,DWORD ccMax);

BOOL RegEnum(HKEY HK,LPCTSTR SubKey,int Index,LPTSTR Str,DWORD ccMax);

// Privilege stuff
BOOL EnablePrivilege(HANDLE hToken,LPCTSTR name);
BOOL EnablePrivilege(LPCTSTR name);

//  AllowAccess
void AllowAccess(HANDLE hObject);

//  NetworkPathToUNCPath
BOOL NetworkPathToUNCPath(LPTSTR path);

//UserName:
bool GetSIDUserName(PSID sid,LPTSTR Name);
bool GetTokenUserName(HANDLE hUser,LPTSTR Name);
bool GetProcessUserName(DWORD ProcessID,LPTSTR Name);

