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
#define _WIN32_WINNT 0x0500
#define WINVER       0x0500
#include <windows.h>
#include <tchar.h>
#include <Aclapi.h>
#include <SHLWAPI.H>
#include <Shobjidl.h>
#include <ShlGuid.h>
#include <lm.h>
#include "DBGTRace.h"

#pragma comment(lib,"ShlWapi.lib")
#pragma comment(lib,"advapi32.lib")
#pragma comment(lib,"Mpr.lib")
#pragma comment(lib,"Shell32.lib")
#pragma comment(lib,"ole32.lib")

//////////////////////////////////////////////////////////////////////////////
//
//  Registry Helper
//
//////////////////////////////////////////////////////////////////////////////

BOOL GetRegAny(HKEY HK,LPCTSTR SubKey,LPCTSTR ValName,DWORD Type,BYTE* RetVal,DWORD nBytes)
{
  HKEY Key;
  if (RegOpenKeyEx(HK,SubKey,0,KEY_READ,&Key)==ERROR_SUCCESS)
  {
    DWORD dwType=Type;
    DWORD l=nBytes;
    BOOL bRet=(RegQueryValueEx(Key,ValName,NULL,&dwType,RetVal,&l)==ERROR_SUCCESS)
            &&(dwType==Type);
      RegCloseKey(Key);
    return bRet;
  }
  return FALSE;
}

BOOL SetRegAny(HKEY HK,LPCTSTR SubKey,LPCTSTR ValName,DWORD Type,BYTE* Data,DWORD nBytes)
{
  HKEY Key;
  BOOL bKey=FALSE;
  bKey=RegOpenKeyEx(HK,SubKey,0,KEY_WRITE,&Key)==ERROR_SUCCESS;
  if (!bKey)
    bKey=RegCreateKey(HK,SubKey,&Key)==ERROR_SUCCESS;
  if (bKey)
  {
    LONG l=RegSetValueEx(Key,ValName,0,Type,Data,nBytes);
    RegCloseKey(Key);
    return l==ERROR_SUCCESS;
  }
  return FALSE;
}

BOOL RegDelVal(HKEY HK,LPCTSTR SubKey,LPCTSTR ValName)
{
  HKEY Key;
  if (RegOpenKeyEx(HK,SubKey,0,KEY_WRITE,&Key)==ERROR_SUCCESS)
  {
    BOOL bRet=RegDeleteValue(Key,ValName)==ERROR_SUCCESS;
    RegCloseKey(Key);
    return bRet;
  }
  return FALSE;
}

DWORD GetRegInt(HKEY HK,LPCTSTR SubKey,LPCTSTR ValName,DWORD Default)
{
  DWORD RetVal=0;
  if (GetRegAny(HK,SubKey,ValName,REG_DWORD,(BYTE*)&RetVal,sizeof(RetVal)))
    return RetVal;
  return Default;
}

BOOL SetRegInt(HKEY HK,LPCTSTR SubKey,LPCTSTR ValName,DWORD Value)
{
  return SetRegAny(HK,SubKey,ValName,REG_DWORD,(BYTE*)&Value,sizeof(DWORD));
}

BOOL GetRegStr(HKEY HK,LPCTSTR SubKey,LPCTSTR Val,LPTSTR Str,DWORD ccMax)
{
  if (GetRegAny(HK,SubKey,Val,REG_SZ,(BYTE*)Str,ccMax))
    return true;
  return GetRegAny(HK,SubKey,Val,REG_EXPAND_SZ,(BYTE*)Str,ccMax);
}

BOOL SetRegStr(HKEY HK,LPCTSTR SubKey,LPCTSTR ValName,LPCTSTR Value)
{
  return SetRegAny(HK,SubKey,ValName,REG_SZ,(BYTE*)Value,_tcslen(Value)*sizeof(TCHAR));
}

BOOL RegEnum(HKEY HK,LPCTSTR SubKey,int Index,LPTSTR Str,DWORD ccMax)
{
  HKEY Key;
  if (RegOpenKeyEx(HK,SubKey,0,KEY_READ,&Key)==ERROR_SUCCESS)
  {
    BOOL bRet=(RegEnumKey(Key,Index,Str,ccMax)==ERROR_SUCCESS);
    RegCloseKey(Key);
    return bRet;
  }
  return false;
}

BOOL DelRegKey(HKEY hKey,LPTSTR pszSubKey)
{
  HKEY hEnumKey;
  if(RegOpenKeyEx(hKey,pszSubKey,0,KEY_ENUMERATE_SUB_KEYS,&hEnumKey)!=NOERROR)
    return FALSE;
  TCHAR szKey[MAX_PATH];
  DWORD dwSize = MAX_PATH;
  while (ERROR_SUCCESS==RegEnumKeyEx(hEnumKey,0,szKey,&dwSize,0,0,0,0))
  {
    DelRegKey(hEnumKey, szKey);
    dwSize=MAX_PATH;
  }
  RegCloseKey(hEnumKey);
  RegDeleteKey(hKey, pszSubKey);
  return TRUE;
}

//////////////////////////////////////////////////////////////////////////////
// 
// Privilege stuff
// 
//////////////////////////////////////////////////////////////////////////////

BOOL EnablePrivilege(HANDLE hToken,LPCTSTR name)
{
  TOKEN_PRIVILEGES priv = {1,{0,0,SE_PRIVILEGE_ENABLED}};
  LookupPrivilegeValue(0,name,&priv.Privileges[0].Luid);
  AdjustTokenPrivileges(hToken,FALSE,&priv,sizeof priv,0,0);
  return  GetLastError() == ERROR_SUCCESS;
}

BOOL EnablePrivilege(LPCTSTR name)
{
  HANDLE hToken=0;
  BOOL bRet=TRUE;
  if(!OpenThreadToken(GetCurrentThread(),TOKEN_ADJUST_PRIVILEGES,0,&hToken))
    bRet&=(GetLastError()==ERROR_NO_TOKEN);
  else
  {
    bRet&=EnablePrivilege(hToken,name);
    CloseHandle(hToken);
  }
  if(!OpenProcessToken(GetCurrentProcess(),TOKEN_ADJUST_PRIVILEGES,&hToken))
    return FALSE;
  bRet&=EnablePrivilege(hToken,name);
  CloseHandle(hToken);
  return bRet;
}

//////////////////////////////////////////////////////////////////////////////
// 
//  AllowAccess
// 
//////////////////////////////////////////////////////////////////////////////

void AllowAccess(HANDLE hObject)
{
  DWORD dwRes;
  PACL pOldDACL=NULL, pNewDACL=NULL;
  PSECURITY_DESCRIPTOR pSD = NULL;
  EXPLICIT_ACCESS ea;
  SID_IDENTIFIER_AUTHORITY SIDAuthWorld = SECURITY_WORLD_SID_AUTHORITY;
  PSID pEveryoneSID = NULL;
  if (NULL == hObject) 
    return;
  // Get a pointer to the existing DACL.
  dwRes = GetSecurityInfo(hObject,SE_KERNEL_OBJECT,DACL_SECURITY_INFORMATION,NULL,NULL,&pOldDACL,NULL,&pSD);
  if (ERROR_SUCCESS != dwRes) 
    goto Cleanup; 
  // Create a well-known SID for the Everyone group.
  if(! AllocateAndInitializeSid( &SIDAuthWorld,1,SECURITY_WORLD_RID,0,0,0,0,0,0,0,&pEveryoneSID) ) 
    return;
  // Initialize an EXPLICIT_ACCESS structure for an ACE.
  // The ACE will allow Everyone read access to the key.
  memset(&ea,0,sizeof(EXPLICIT_ACCESS));
  ea.grfAccessPermissions = STANDARD_RIGHTS_ALL|SPECIFIC_RIGHTS_ALL;
  ea.grfAccessMode = GRANT_ACCESS;
  ea.grfInheritance= NO_INHERITANCE;
  ea.Trustee.TrusteeForm = TRUSTEE_IS_SID;
  ea.Trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;
  ea.Trustee.ptstrName  = (LPTSTR) pEveryoneSID;
  // Create a new ACL that merges the new ACE
  // into the existing DACL.
  dwRes = SetEntriesInAcl(1,&ea,pOldDACL,&pNewDACL);
  if (ERROR_SUCCESS != dwRes)  
    goto Cleanup; 
  // Attach the new ACL as the object's DACL.
  dwRes = SetSecurityInfo(hObject,SE_KERNEL_OBJECT,DACL_SECURITY_INFORMATION,NULL,NULL,pNewDACL,NULL);
  if (ERROR_SUCCESS != dwRes)  
    goto Cleanup; 
Cleanup:
  if(pSD != NULL) 
    LocalFree((HLOCAL) pSD); 
  if(pNewDACL != NULL) 
    LocalFree((HLOCAL) pNewDACL); 
}

//////////////////////////////////////////////////////////////////////////////
//
//  NetworkPathToUNCPath
//
//  This will convert a path on a mapped network share to a UNC path
//  e.g. if you mapped \\Server\C$ to your drive Z:\ this function will
//  convert Z:\Sound\MOD4WIN\TheBest to \\Server\C$\Sound\MOD4WIN\TheBest
//  
//  This conversion is required since you loose network connections when
//  logging on as different user.
//  
//  NOTE1: The newly logged on user needs to have access permission to the
//         network share on the server
//  NOTE2: This function will fail if path is a "remembered" connection
//////////////////////////////////////////////////////////////////////////////

BOOL NetworkPathToUNCPath(LPTSTR path)
{
  if (!PathIsNetworkPath(path))
    return FALSE;
  DWORD cb=4096;
  TCHAR UNCPath[4096]={0};
  UNIVERSAL_NAME_INFO uni;
  uni.lpUniversalName=&UNCPath[0];
  UNIVERSAL_NAME_INFO* puni=(UNIVERSAL_NAME_INFO*)&UNCPath;
  DWORD dwErr=WNetGetUniversalName(path,UNIVERSAL_NAME_INFO_LEVEL,puni,&cb);
  if (dwErr!=NO_ERROR)
    return FALSE;
  _tcscpy(path,puni->lpUniversalName);
  return TRUE;
}

//////////////////////////////////////////////////////////////////////////////
// 
// CreateLink, creates a LNK file
// 
//////////////////////////////////////////////////////////////////////////////

BOOL CreateLink(LPCTSTR fname,LPCTSTR lnk_fname,int iIcon)
{
  //Save parameters
  TCHAR args[4096]={0};
  _tcscpy(args,PathGetArgs(fname));
  //Application
  TCHAR app[4096]={0};
  _tcscpy(app,fname);
  PathRemoveArgs(app);
  PathUnquoteSpaces(app);
  NetworkPathToUNCPath(app);
  //Get Path
  TCHAR path[4096];
  _tcscpy(path,app);
  PathRemoveFileSpec(path);
  if (!PathFileExists(app))
    return false;
  BOOL bRes=FALSE;
  IShellLink *psl = NULL;
  IPersistFile *pPf = NULL;
  if(FAILED(CoCreateInstance(CLSID_ShellLink,NULL,CLSCTX_INPROC_SERVER,IID_IShellLink,(LPVOID*)&psl)))
    goto cleanup;
  if(FAILED(psl->QueryInterface(IID_IPersistFile, (LPVOID*)&pPf)))
    goto cleanup;
  if(FAILED(psl->SetPath(app)))
    goto cleanup;
  if(FAILED(psl->SetWorkingDirectory(path)))
    goto cleanup;
  if(FAILED(psl->SetIconLocation(app,iIcon)))
    goto cleanup;
  if (args[0])
  {
    if(FAILED(psl->SetArguments(args)))
      goto cleanup;
  }
  if(FAILED(pPf->Save(lnk_fname, TRUE)))
    goto cleanup;
  bRes=TRUE;
cleanup:
  if(pPf)
    pPf->Release();
  if(psl)
    psl->Release();
  return bRes;
} 

//////////////////////////////////////////////////////////////////////////////
// 
// DeleteDirectory ... all files and SubDirs
// 
//////////////////////////////////////////////////////////////////////////////

bool DeleteDirectory(LPCTSTR DIR)
{
  bool bRet=true;
  WIN32_FIND_DATA fd={0};
  TCHAR s[MAX_PATH];
  _tcscpy(s,DIR);
  PathAppend(s,_T("*.*"));
  HANDLE hFind=FindFirstFile(s,&fd);
  if (hFind != INVALID_HANDLE_VALUE)
  {
    do
    {
      _tcscpy(s,DIR);
      PathAppend(s,fd.cFileName);
      if (PathIsDirectory(s))
      {
        if ( _tcscmp(fd.cFileName,_T("."))
          && _tcscmp(fd.cFileName,_T("..")))
        {
          SetFileAttributes(s,FILE_ATTRIBUTE_DIRECTORY);
          bRet=bRet && DeleteDirectory(s);
        }
      }else
      {
        SetFileAttributes(s,FILE_ATTRIBUTE_NORMAL);
        bRet=bRet && DeleteFile(s);
      }
    }while (FindNextFile(hFind,&fd));
  }
  FindClose(hFind);
  bRet=bRet && RemoveDirectory(DIR);
  return bRet;
}

//////////////////////////////////////////////////////////////////////////////
// 
//  GetTokenUserName
// 
//////////////////////////////////////////////////////////////////////////////

bool GetSIDUserName(PSID sid,LPTSTR User,LPTSTR Domain/*=0*/)
{
  SID_NAME_USE snu;
  TCHAR uName[UNLEN],dName[UNLEN];
  DWORD uLen=UNLEN, dLen=UNLEN;
  if(!LookupAccountSid(NULL,sid,uName,&uLen,dName,&dLen,&snu))
    return FALSE;
  if(Domain==0)
  {
    _tcscpy(User, dName);
    if(_tcslen(User))
      _tcscat(User, TEXT("\\"));
    _tcscat(User,uName);
  }else
  {
    _tcscpy(User, uName);
    _tcscpy(Domain, dName);
  }
  return TRUE;
}

bool GetTokenUserName(HANDLE hUser,LPTSTR User,LPTSTR Domain/*=0*/)
{
  DWORD dwLen=0;
  if ((!GetTokenInformation(hUser, TokenUser,NULL,0,&dwLen))
    &&(GetLastError()!=ERROR_INSUFFICIENT_BUFFER))
    return false;
  TOKEN_USER* ptu=(TOKEN_USER*)malloc(dwLen);
  if(!ptu)
    return false;
  if(GetTokenInformation(hUser,TokenUser,(PVOID)ptu,dwLen,&dwLen))
    GetSIDUserName(ptu->User.Sid,User,Domain);
  free(ptu);
  return true;
}

//////////////////////////////////////////////////////////////////////////////
// 
// GetProcessUserName
// 
//////////////////////////////////////////////////////////////////////////////

bool GetProcessUserName(DWORD ProcessID,LPTSTR User,LPTSTR Domain/*=0*/)
{
  EnablePrivilege(SE_DEBUG_NAME);
  HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS,TRUE,ProcessID);
  if (!hProc)
    return 0;
  HANDLE hToken;
  bool bRet=false;
  // Open impersonation token for Shell process
  if (OpenProcessToken(hProc,TOKEN_QUERY,&hToken))
  {
    bRet=GetTokenUserName(hToken,User,Domain);
    CloseHandle(hToken);
  }
  CloseHandle(hProc);
  return bRet;
}
