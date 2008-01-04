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
#define _WIN32_WINNT 0x0500
#define WINVER       0x0500
#include <windows.h>
#include <tchar.h>
#include <Aclapi.h>
#include <SHLWAPI.H>
#include <Shobjidl.h>
#include <ShlGuid.h>
#include <lm.h>
#include <MMSYSTEM.H>

#include "Helpers.h"
#include "DBGTRace.h"

#pragma comment(lib,"ShlWapi.lib")
#pragma comment(lib,"advapi32.lib")
#pragma comment(lib,"Mpr.lib")
#pragma comment(lib,"Shell32.lib")
#pragma comment(lib,"ole32.lib")
#pragma comment(lib,"Version.lib")
#pragma comment(lib,"WINMM.LIB")

//////////////////////////////////////////////////////////////////////////////
//
//  Registry Helper
//
//////////////////////////////////////////////////////////////////////////////

BOOL GetRegAny(HKEY HK,LPCTSTR SubKey,LPCTSTR ValName,DWORD Type,BYTE* RetVal,DWORD* nBytes)
{
  HKEY Key;
  if (RegOpenKeyEx(HK,SubKey,0,KEY_READ,&Key)==ERROR_SUCCESS)
  {
    DWORD dwType=Type;
    BOOL bRet=(RegQueryValueEx(Key,ValName,NULL,&dwType,RetVal,nBytes)==ERROR_SUCCESS)
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
  DWORD n=sizeof(RetVal);
  if (GetRegAny(HK,SubKey,ValName,REG_DWORD,(BYTE*)&RetVal,&n))
    return RetVal;
  return Default;
}

BOOL SetRegInt(HKEY HK,LPCTSTR SubKey,LPCTSTR ValName,DWORD Value)
{
  return SetRegAny(HK,SubKey,ValName,REG_DWORD,(BYTE*)&Value,sizeof(DWORD));
}

__int64 GetRegInt64(HKEY HK,LPCTSTR SubKey,LPCTSTR ValName,__int64 Default)
{
  __int64 RetVal=0;
  DWORD n=sizeof(RetVal);
  if (GetRegAny(HK,SubKey,ValName,REG_BINARY,(BYTE*)&RetVal,&n))
    return RetVal;
  return Default;
}

BOOL SetRegInt64(HKEY HK,LPCTSTR SubKey,LPCTSTR ValName,__int64 Value)
{
  return SetRegAny(HK,SubKey,ValName,REG_BINARY,(BYTE*)&Value,sizeof(__int64));
}

BOOL GetRegStr(HKEY HK,LPCTSTR SubKey,LPCTSTR Val,LPTSTR Str,DWORD ccMax)
{
  if (GetRegAny(HK,SubKey,Val,REG_SZ,(BYTE*)Str,&ccMax))
    return true;
  return GetRegAny(HK,SubKey,Val,REG_EXPAND_SZ,(BYTE*)Str,&ccMax);
}

BOOL SetRegStr(HKEY HK,LPCTSTR SubKey,LPCTSTR ValName,LPCTSTR Value)
{
  return SetRegAny(HK,SubKey,ValName,REG_SZ,(BYTE*)Value,(DWORD)_tcslen(Value)*sizeof(TCHAR));
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

BOOL RegEnumValName(HKEY HK,LPTSTR SubKey,int Index,LPTSTR Str,DWORD ccMax)
{
  HKEY Key;
  if (RegOpenKeyEx(HK,SubKey,0,KEY_READ,&Key)==ERROR_SUCCESS)
  {
    BOOL bRet=(RegEnumValue(Key,Index,Str,&ccMax,0,0,0,0)==ERROR_SUCCESS);
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
  if(pEveryoneSID)
    FreeSid(pEveryoneSID);
}

void SetRegistryTreeAccess(LPTSTR KeyName,LPTSTR Account,bool bAllow)
{
  DWORD dwRes;
  PACL pOldDACL = NULL, pNewDACL = NULL;
  PSECURITY_DESCRIPTOR pSD = NULL;
  EXPLICIT_ACCESS ea={0};
  if (NULL == KeyName) 
    return;
  // Get a pointer to the existing DACL.
  dwRes = GetNamedSecurityInfo(KeyName, SE_REGISTRY_KEY, DACL_SECURITY_INFORMATION,  
    NULL, NULL, &pOldDACL, NULL, &pSD);
  if (ERROR_SUCCESS != dwRes) 
  { 
    DBGTrace1( "GetNamedSecurityInfo failed %s\n", GetErrorNameStatic(dwRes));
    goto Cleanup; 
  }  
  // Initialize an EXPLICIT_ACCESS structure for an ACE.
  BuildExplicitAccessWithName(&ea,Account,KEY_ALL_ACCESS,
    bAllow?SET_ACCESS:REVOKE_ACCESS,SUB_CONTAINERS_AND_OBJECTS_INHERIT);
  // Create a new ACL that merges the new ACE into the existing DACL.
  dwRes = SetEntriesInAcl(1, &ea, pOldDACL, &pNewDACL);
  if (ERROR_SUCCESS != dwRes)  
  {
    DBGTrace1( "SetEntriesInAcl failed %s\n", GetErrorNameStatic(dwRes));
    goto Cleanup; 
  }  
  // Attach the new ACL as the object's DACL.
  dwRes = SetNamedSecurityInfo(KeyName, SE_REGISTRY_KEY, DACL_SECURITY_INFORMATION,  
    NULL, NULL, pNewDACL, NULL);
  if (ERROR_SUCCESS != dwRes)  
  {
    DBGTrace1( "SetNamedSecurityInfo failed %s\n", GetErrorNameStatic(dwRes));
    goto Cleanup; 
  }  
Cleanup:
  if(pSD != NULL) 
    LocalFree((HLOCAL) pSD); 
  if(pNewDACL != NULL) 
    LocalFree((HLOCAL) pNewDACL); 
}

BOOL HasRegistryKeyAccess(LPTSTR KeyName,LPTSTR Account)
{
  DWORD dwRes;
  PACL pDACL = NULL;
  PSECURITY_DESCRIPTOR pSD = NULL;
  TRUSTEE tr={0};
  ACCESS_MASK am=0;
  if (NULL == KeyName) 
    return 0;
  // Get a pointer to the existing DACL.
  dwRes = GetNamedSecurityInfo(KeyName, SE_REGISTRY_KEY, DACL_SECURITY_INFORMATION,  
    NULL, NULL, &pDACL, NULL, &pSD);
  if (ERROR_SUCCESS != dwRes) 
  { 
    DBGTrace1( "GetNamedSecurityInfo failed %s\n", GetErrorNameStatic(dwRes));
    goto Cleanup; 
  }  
  // Initialize an EXPLICIT_ACCESS structure for an ACE.
  BuildTrusteeWithName(&tr,Account);
  if (GetEffectiveRightsFromAcl(pDACL,&tr,&am)!=ERROR_SUCCESS)
    DBGTrace1( "GetEffectiveRightsFromAcl failed %s\n", GetErrorNameStatic(dwRes));
Cleanup:
  if(pSD != NULL) 
    LocalFree((HLOCAL) pSD); 
  if(pDACL != NULL) 
    LocalFree((HLOCAL) pDACL); 
  return (am&KEY_WRITE)==KEY_WRITE;
}

//////////////////////////////////////////////////////////////////////////////
//
// SetAdminDenyUserAccess
//
//////////////////////////////////////////////////////////////////////////////

void SetAdminDenyUserAccess(HANDLE hObject)
{
  DWORD dwRes;
  PACL pOldDACL=NULL, pNewDACL=NULL;
  PSECURITY_DESCRIPTOR pSD = NULL;
  EXPLICIT_ACCESS ea[2]={0};
  SID_IDENTIFIER_AUTHORITY AdminSidAuthority = SECURITY_NT_AUTHORITY;
  PSID AdminSID = NULL;
  PSID UserSID  = GetProcessUserSID(GetCurrentProcessId());
  if (NULL == hObject) 
    goto Cleanup; 
  // Get a pointer to the existing DACL.
  dwRes = GetSecurityInfo(hObject,SE_KERNEL_OBJECT,DACL_SECURITY_INFORMATION,NULL,NULL,&pOldDACL,NULL,&pSD);
  if (ERROR_SUCCESS != dwRes) 
    goto Cleanup; 

  // Initialize Admin SID
  if (!AllocateAndInitializeSid(&AdminSidAuthority,2,SECURITY_BUILTIN_DOMAIN_RID,
    DOMAIN_ALIAS_RID_ADMINS,0,0,0,0,0,0,&AdminSID))
    goto Cleanup; 
  // Initialize EXPLICIT_ACCESS structures
  // The ACE will allow Administrators full access to the object.
  ea[0].grfAccessPermissions = STANDARD_RIGHTS_ALL|SPECIFIC_RIGHTS_ALL;
  ea[0].grfAccessMode = GRANT_ACCESS;
  ea[0].Trustee.ptstrName  = (LPTSTR)AdminSID;
  // The ACE will deny the current User access to the object.
  ea[1].grfAccessMode = REVOKE_ACCESS;
  ea[1].Trustee.ptstrName  = (LPTSTR)UserSID;
  // Create a new ACL that merges the new ACE
  // into the existing DACL.
  dwRes = SetEntriesInAcl(2,&ea[0],pOldDACL,&pNewDACL);
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
  if (AdminSID)
    FreeSid(AdminSID);
  free(UserSID);
}

//////////////////////////////////////////////////////////////////////////////
// 
// GetUserAccessSD:
//   create a self relative "full access" Security Descriptor for the current user
// 
//////////////////////////////////////////////////////////////////////////////

PSECURITY_DESCRIPTOR GetUserAccessSD()
{
  PSID pUserSID = GetProcessUserSID(GetCurrentProcessId());
  PACL pACL = NULL;
  PSECURITY_DESCRIPTOR pSD = 0;
  PSECURITY_DESCRIPTOR pSDret =0;
  EXPLICIT_ACCESS ea={0};
  DWORD SDlen=0;
  ea.grfAccessPermissions = STANDARD_RIGHTS_ALL|SPECIFIC_RIGHTS_ALL|GENERIC_READ|GENERIC_WRITE;
  ea.grfAccessMode = SET_ACCESS;
  ea.grfInheritance= NO_INHERITANCE;
  ea.Trustee.TrusteeForm = TRUSTEE_IS_SID;
  ea.Trustee.TrusteeType = TRUSTEE_IS_GROUP;
  ea.Trustee.ptstrName  = (LPTSTR) pUserSID;
  if (ERROR_SUCCESS != SetEntriesInAcl(1,&ea,NULL,&pACL)) 
    goto Cleanup;
  pSD = (PSECURITY_DESCRIPTOR)LocalAlloc(LPTR,SECURITY_DESCRIPTOR_MIN_LENGTH); 
  if (pSD == NULL) 
    goto Cleanup; 
  if (!InitializeSecurityDescriptor(pSD,SECURITY_DESCRIPTOR_REVISION)) 
    goto Cleanup; 
  if (!SetSecurityDescriptorDacl(pSD,TRUE,pACL,FALSE))
    goto Cleanup; 
  MakeSelfRelativeSD(pSD,pSDret,&SDlen);
  pSDret=(PSECURITY_DESCRIPTOR)LocalAlloc(LPTR,SDlen);
  if(!MakeSelfRelativeSD(pSD,pSDret,&SDlen))
    goto Cleanup;
  LocalFree(pUserSID);
  LocalFree(pACL);
  LocalFree(pSD);
  return pSDret;
Cleanup:
  if (pUserSID) 
    LocalFree(pUserSID);
  if (pACL) 
    LocalFree(pACL);
  if (pSD) 
    LocalFree(pSD);
  if (pSDret) 
    LocalFree(pSDret);
  return 0;
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
  TCHAR uName[UNLEN+1],dName[UNLEN+1];
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
// GetProcessUserSID
// 
//////////////////////////////////////////////////////////////////////////////

PSID GetProcessUserSID(DWORD ProcessID)
{
  EnablePrivilege(SE_DEBUG_NAME);
  HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS,TRUE,ProcessID);
  if (!hProc)
    return 0;
  HANDLE hToken;
  PSID sid=0;
  // Open impersonation token for Shell process
  if (OpenProcessToken(hProc,TOKEN_QUERY,&hToken))
  {
    DWORD dwLen=0;
    if ((GetTokenInformation(hToken, TokenUser,NULL,0,&dwLen))
      ||(GetLastError()==ERROR_INSUFFICIENT_BUFFER))
    {
      TOKEN_USER* ptu=(TOKEN_USER*)malloc(dwLen);
      if(ptu)
      {
        if(GetTokenInformation(hToken,TokenUser,(PVOID)ptu,dwLen,&dwLen))
        {
          dwLen=GetLengthSid(ptu->User.Sid);
          sid=(PSID)malloc(dwLen);
          CopySid(dwLen,sid,ptu->User.Sid);
        }
        free(ptu);
      }
    }
    CloseHandle(hToken);
  }
  CloseHandle(hProc);
  return sid;
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

/////////////////////////////////////////////////////////////////////////////
// 
// GetVersionString
// 
/////////////////////////////////////////////////////////////////////////////

static TCHAR verstr[20]={0};
LPCTSTR GetVersionString()
{
  if (verstr[0]!=0)
    return verstr;
  TCHAR FName[MAX_PATH];
  GetModuleFileName(0,FName,MAX_PATH);
  int cbVerInfo=GetFileVersionInfoSize(FName,0);
  if (cbVerInfo)
  {
    void* VerInfo=malloc(cbVerInfo);
    GetFileVersionInfo(FName,0,cbVerInfo,VerInfo);
    VS_FIXEDFILEINFO* Ver;
    UINT cbVer=sizeof(Ver);
    VerQueryValue(VerInfo,_T("\\"),(void**)&Ver,&cbVer);
    if (cbVer)
    {
      _stprintf(verstr,_T("%d.%d.%d.%d"),
        Ver->dwProductVersionMS>>16 & 0x0000FFFF,
        Ver->dwProductVersionMS     & 0x0000FFFF,
        Ver->dwProductVersionLS>>16 & 0x0000FFFF,
        Ver->dwProductVersionLS     & 0x0000FFFF);
      free(VerInfo);
      return verstr;
    }
    free(VerInfo);
  }
  return _T("");
}

/////////////////////////////////////////////////////////////////////////////
//
// LoadUserBitmap
//
/////////////////////////////////////////////////////////////////////////////

HBITMAP LoadUserBitmap(LPCTSTR UserName)
{
  TCHAR PicDir[MAX_PATH];
  GetRegStr(HKEY_LOCAL_MACHINE,
    _T("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders"),
    _T("Common AppData"),PicDir,MAX_PATH);
  PathUnquoteSpaces(PicDir);
  PathAppend(PicDir,_T("Microsoft\\User Account Pictures"));
  TCHAR Pic[UNLEN+1];
  _tcscpy(Pic,UserName);
  PathStripPath(Pic);
  PathAppend(PicDir,Pic);
  PathAddExtension(PicDir,_T(".bmp"));
  //DBGTrace1("LoadUserBitmap: %s",Pic);
  return (HBITMAP)LoadImage(0,PicDir,IMAGE_BITMAP,0,0,LR_LOADFROMFILE);
}

/////////////////////////////////////////////////////////////////////////////
// 
// CTimeOut
// 
/////////////////////////////////////////////////////////////////////////////

CTimeOut::CTimeOut()
{
  Set(0);
}

CTimeOut::CTimeOut(DWORD TimeOut)
{
  Set(TimeOut);
}

void CTimeOut::Set(DWORD TimeOut)
{
  m_EndTime=timeGetTime()+TimeOut;
}

DWORD CTimeOut::Rest()
{
  int to=(int)m_EndTime-(int)timeGetTime();
  if (to<=0)
  {
    SetLastError(ERROR_TIMEOUT);
    return 0;
  }
  return (DWORD)to;
}

bool CTimeOut::TimedOut()
{
  return Rest()==0;
}
