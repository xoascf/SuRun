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
//                                (c) Kay Bruns (http://kay-bruns.de), 2007,08
//////////////////////////////////////////////////////////////////////////////

#pragma once

#define countof(b) sizeof(b)/sizeof(b[0])
#define zero(x) memset(&x,0,sizeof(x))

//  Registry Helper
#define HKCR HKEY_CLASSES_ROOT
#define HKCU HKEY_CURRENT_USER
#define HKLM HKEY_LOCAL_MACHINE

BOOL GetRegAny(HKEY HK,LPCTSTR SubKey,LPCTSTR ValName,DWORD Type,BYTE* RetVal,DWORD* nBytes);
BOOL SetRegAny(HKEY HK,LPCTSTR SubKey,LPCTSTR ValName,DWORD Type,BYTE* Data,DWORD nBytes);

BOOL DelRegKey(HKEY hKey,LPTSTR pszSubKey);
BOOL RegDelVal(HKEY HK,LPCTSTR SubKey,LPCTSTR ValName);

BOOL SetRegInt(HKEY HK,LPCTSTR SubKey,LPCTSTR ValName,DWORD Value);
DWORD GetRegInt(HKEY HK,LPCTSTR SubKey,LPCTSTR ValName,DWORD Default);

__int64 GetRegInt64(HKEY HK,LPCTSTR SubKey,LPCTSTR ValName,__int64 Default);
BOOL SetRegInt64(HKEY HK,LPCTSTR SubKey,LPCTSTR ValName,__int64 Value);

BOOL SetRegStr(HKEY HK,LPCTSTR SubKey,LPCTSTR ValName,LPCTSTR Value);
BOOL GetRegStr(HKEY HK,LPCTSTR SubKey,LPCTSTR Val,LPTSTR Str,DWORD ccMax);

BOOL RegEnum(HKEY HK,LPCTSTR SubKey,int Index,LPTSTR Str,DWORD ccMax);
BOOL RegEnumValName(HKEY HK,LPTSTR SubKey,int Index,LPTSTR Str,DWORD ccMax);

#define EmptyPWAllowed (GetRegInt(HKLM,\
                          _T("SYSTEM\\CurrentControlSet\\Control\\Lsa"),\
                          _T("limitblankpassworduse"),1)==0)

#define AllowEmptyPW(b) SetRegInt(HKLM,\
                          _T("SYSTEM\\CurrentControlSet\\Control\\Lsa"),\
                          _T("limitblankpassworduse"),(b)==0)

int inline SafeMsgBox(HWND w,LPTSTR m,LPTSTR c,DWORD f) 
{
  if(GetModuleHandle(TEXT("Shell32.dll"))==0)
    LoadLibrary(TEXT("Shell32.dll"));
  return MessageBox(w,m,c,f);
};

// String converter
LPWSTR AToW(LPCSTR aStr);

class CAToWStr
{
public:
  CAToWStr(LPCSTR s)
  {
    m_wStr=AToW(s);
  }
  ~CAToWStr()
  {
    free(m_wStr);
  }
  const LPCWSTR operator =(LPCSTR s)
  {
    free(m_wStr);
    m_wStr=AToW(s);
    return m_wStr;
  }
  const WCHAR operator [](int Index)
  {
    return (Index<(int)wcslen(m_wStr))?((Index>0)?m_wStr[Index]:'\0'):'\0';
  }
  operator LPWSTR() { return m_wStr; };
  operator LPCWSTR(){ return m_wStr; };
protected:
  LPWSTR m_wStr;
};


// Privilege stuff
BOOL EnablePrivilege(HANDLE hToken,LPCTSTR name);
BOOL EnablePrivilege(LPCTSTR name);

//  AllowAccess
void AllowAccess(HANDLE hObject);
void SetRegistryTreeAccess(LPTSTR KeyName,LPTSTR Account,bool bAllow);
BOOL HasRegistryKeyAccess(LPTSTR KeyName,LPTSTR Account);

// SetAdminDenyUserAccess
void SetAdminDenyUserAccess(HANDLE hObject,DWORD ProcessID=0);

// GetUserAccessSD
PSECURITY_DESCRIPTOR GetUserAccessSD();

//  NetworkPathToUNCPath
BOOL NetworkPathToUNCPath(LPTSTR path);

// ResolveCommandLine: Beautify path, try to resolve executables (msi,cpl...)
BOOL ResolveCommandLine(IN LPWSTR CmdLine,IN LPCWSTR CurDir,OUT LPTSTR cmd);

//Link Creation
BOOL CreateLink(LPCTSTR fname,LPCTSTR lnk_fname,int iIcon);

//DeleteDirectory ... all files and SubDirs
bool DeleteDirectory(LPCTSTR DIR);

//UserName:
bool GetSIDUserName(PSID sid,LPTSTR User,LPTSTR Domain=0);
PSID GetProcessUserSID(DWORD ProcessID);
bool GetTokenUserName(HANDLE hUser,LPTSTR User,LPTSTR Domain=0);
bool GetProcessUserName(DWORD ProcessID,LPTSTR User,LPTSTR Domain=0);

//Shell stuff
HANDLE GetShellProcessToken();

// GetVersionString
LPCTSTR GetVersionString();

// LoadUserBitmap
HBITMAP LoadUserBitmap(LPCTSTR UserName);

// CTimeOut
class CTimeOut
{
public:
  CTimeOut();
  CTimeOut(DWORD TimeOut);
  void Set(DWORD TimeOut);
  DWORD Rest();
  bool  TimedOut();
protected:
  DWORD m_EndTime;
};

