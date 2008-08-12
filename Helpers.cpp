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
#include <WtsApi32.h>
#include <Tlhelp32.h>

#include "Helpers.h"
#include "lsa_laar.h"
#include "UserGroups.h"
#include "DBGTRace.h"

#pragma comment(lib,"ShlWapi.lib")
#pragma comment(lib,"advapi32.lib")
#pragma comment(lib,"Mpr.lib")
#pragma comment(lib,"Shell32.lib")
#pragma comment(lib,"ole32.lib")
#pragma comment(lib,"Version.lib")
#pragma comment(lib,"WINMM.LIB")
#pragma comment(lib,"Wtsapi32")

//////////////////////////////////////////////////////////////////////////////
//
//  Registry Helper
//
//////////////////////////////////////////////////////////////////////////////
BOOL GetRegAny(HKEY HK,LPCTSTR SubKey,LPCTSTR ValName,DWORD Type,BYTE* RetVal,DWORD* nBytes)
{
  HKEY Key;
  if (RegOpenKeyEx(HK,SubKey,0,KSAM(KEY_READ),&Key)==ERROR_SUCCESS)
  {
    DWORD dwType=Type;
    BOOL bRet=(RegQueryValueEx(Key,ValName,NULL,&dwType,RetVal,nBytes)==ERROR_SUCCESS)
            &&(dwType==Type);
    RegCloseKey(Key);
    return bRet;
  }
  return FALSE;
}

BOOL GetRegAnyPtr(HKEY HK,LPCTSTR SubKey,LPCTSTR ValName,DWORD* Type,BYTE* RetVal,DWORD* nBytes)
{
  HKEY Key;
  if (RegOpenKeyEx(HK,SubKey,0,KSAM(KEY_READ),&Key)==ERROR_SUCCESS)
  {
    BOOL bRet=RegQueryValueEx(Key,ValName,NULL,Type,RetVal,nBytes)==ERROR_SUCCESS;
    RegCloseKey(Key);
    return bRet;
  }
  return FALSE;
}

BOOL SetRegAny(HKEY HK,LPCTSTR SubKey,LPCTSTR ValName,DWORD Type,BYTE* Data,DWORD nBytes)
{
  HKEY Key;
  BOOL bKey=FALSE;
  bKey=RegOpenKeyEx(HK,SubKey,0,KSAM(KEY_WRITE),&Key)==ERROR_SUCCESS;
  if (!bKey)
    bKey=RegCreateKeyEx(HK,SubKey,0,0,0,KSAM(KEY_WRITE),0,&Key,0)==ERROR_SUCCESS;
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
  if (RegOpenKeyEx(HK,SubKey,0,KSAM(KEY_WRITE),&Key)==ERROR_SUCCESS)
  {
    BOOL bRet=RegDeleteValue(Key,ValName)==ERROR_SUCCESS;
    RegCloseKey(Key);
    return bRet;
  }
  return FALSE;
}

DWORD GetRegInt(HKEY HK,LPCTSTR SubKey,LPCTSTR ValName,DWORD Default)
{
  DWORD RetVal=Default;
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
  __int64 RetVal=Default;
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
  TCHAR s[4096];
  DWORD n=4096;
  if(GetRegAny(HK,SubKey,Val,REG_EXPAND_SZ,(BYTE*)&s,&n))
    return ExpandEnvironmentStrings(s,Str,min(4096,ccMax)),TRUE;
  return FALSE;
}

BOOL SetRegStr(HKEY HK,LPCTSTR SubKey,LPCTSTR ValName,LPCTSTR Value)
{
  return SetRegAny(HK,SubKey,ValName,REG_SZ,(BYTE*)Value,(DWORD)_tcslen(Value)*sizeof(TCHAR));
}

BOOL RegEnum(HKEY HK,LPCTSTR SubKey,int Index,LPTSTR Str,DWORD ccMax)
{
  HKEY Key;
  if (RegOpenKeyEx(HK,SubKey,0,KSAM(KEY_READ),&Key)==ERROR_SUCCESS)
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
  if (RegOpenKeyEx(HK,SubKey,0,KSAM(KEY_READ),&Key)==ERROR_SUCCESS)
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
  if(RegOpenKeyEx(hKey,pszSubKey,0,KSAM(KEY_ENUMERATE_SUB_KEYS),&hEnumKey)!=NOERROR)
    return FALSE;
  TCHAR szKey[4096];
  DWORD dwSize = 4096;
  while (ERROR_SUCCESS==RegEnumKeyEx(hEnumKey,0,szKey,&dwSize,0,0,0,0))
  {
    DelRegKey(hEnumKey, szKey);
    dwSize=4096;
  }
  RegCloseKey(hEnumKey);
  RegDeleteKey(hKey, pszSubKey);
  return TRUE;
}

BOOL DelRegKeyChildren(HKEY hKey,LPTSTR pszSubKey)
{
  HKEY hEnumKey;
  if(RegOpenKeyEx(hKey,pszSubKey,0,KSAM(KEY_ENUMERATE_SUB_KEYS),&hEnumKey)!=NOERROR)
    return FALSE;
  TCHAR szKey[4096];
  DWORD dwSize = 4096;
  while (ERROR_SUCCESS==RegEnumKeyEx(hEnumKey,0,szKey,&dwSize,0,0,0,0))
  {
    DelRegKey(hEnumKey, szKey);
    dwSize=4096;
  }
  RegCloseKey(hEnumKey);
  return TRUE;
}

void CopyRegKey(HKEY hSrc, HKEY hDst)
{
  LPTSTR s=(LPTSTR)malloc(512*sizeof(TCHAR));
  BYTE* b=(BYTE*)malloc(8192);
  DWORD i,nS,nB,t;
  for(i=0,nS=512,nB=8192;0==RegEnumValue(hSrc,i,s,&nS,0,&t,b,&nB);nS=512,nB=8192,i++)
    RegSetValueEx(hDst,s,0,t,b,nB);
  free(b);
  for(i=0,nS=512;0==RegEnumKey(hSrc,i,s,nS);i++)
  {
    HKEY newDst,newSrc;
    if(0==RegOpenKeyEx(hSrc,s,0,KSAM(KEY_ALL_ACCESS),&newSrc))
    {
      if(0==RegCreateKeyEx(hDst,s,0,0,0,KSAM(KEY_ALL_ACCESS),0,&newDst,0))
      {
        CopyRegKey(newSrc,newDst);
        RegCloseKey(newDst);
      }
      RegCloseKey(newSrc);
    }
  }
  free(s);
}

BOOL RenameRegKey(HKEY hKeyRoot,LPTSTR sSrc,LPTSTR sDst)
{
  HKEY hSrc,hDst;
  if(RegOpenKeyEx(hKeyRoot,sSrc,0,KSAM(KEY_ALL_ACCESS),&hSrc))
    return FALSE;
  if(RegCreateKeyEx(hKeyRoot,sDst,0,0,0,KSAM(KEY_ALL_ACCESS),0,&hDst,0))
    return RegCloseKey(hSrc),FALSE;
  CopyRegKey(hSrc,hDst);
  RegCloseKey(hDst);
  RegCloseKey(hSrc);
  DelRegKey(hKeyRoot,sSrc);
  return TRUE;
}

//////////////////////////////////////////////////////////////////////////////
// 
// Privilege stuff
// 
//////////////////////////////////////////////////////////////////////////////

BOOL DisablePrivilege(HANDLE hToken,LPCTSTR name)
{
  return  EnablePrivilege(hToken,name,0);
}

BOOL EnablePrivilege(HANDLE hToken,LPCTSTR name,DWORD how/*=SE_PRIVILEGE_ENABLED*/)
{
  TOKEN_PRIVILEGES priv = {1,{0,0,how}};
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
  {
    DBGTrace1( "GetEffectiveRightsFromAcl failed %s\n", GetErrorNameStatic(dwRes));
    am=0;
  }
Cleanup:
  if(pSD != NULL) 
    LocalFree((HLOCAL) pSD); 
  if(pDACL != NULL) 
    LocalFree((HLOCAL) pDACL); 
  return (am&KEY_WRITE)==KEY_WRITE;
}

BOOL HasRegistryKeyAccess(LPTSTR KeyName,DWORD Rid)
{
  DWORD cchG=GNLEN;
  WCHAR Group[GNLEN+1]={0};
  if (GetGroupName(Rid,Group,&cchG))
    return HasRegistryKeyAccess(KeyName,Group);
  return false;
}

void SetRegistryTreeAccess(LPTSTR KeyName,DWORD Rid,bool bAllow)
{
  DWORD cchG=GNLEN;
  WCHAR Group[GNLEN+1]={0};
  if (GetGroupName(Rid,Group,&cchG))
    SetRegistryTreeAccess(KeyName,Group,bAllow);
}

//////////////////////////////////////////////////////////////////////////////
//
// SetAdminDenyUserAccess
//
//////////////////////////////////////////////////////////////////////////////
PACL SetAdminDenyUserAccess(PACL pOldDACL,PSID UserSID,DWORD Permissions/*=SYNCHRONIZE*/)
{
  SID_IDENTIFIER_AUTHORITY AdminSidAuthority = SECURITY_NT_AUTHORITY;
  PSID AdminSID = NULL;
  // Initialize Admin SID
  if (!AllocateAndInitializeSid(&AdminSidAuthority,2,SECURITY_BUILTIN_DOMAIN_RID,
    DOMAIN_ALIAS_RID_ADMINS,0,0,0,0,0,0,&AdminSID))
    return 0; 
  // Initialize EXPLICIT_ACCESS structures
  EXPLICIT_ACCESS ea[2]={0};
  // The ACE will deny the current User access to the object.
  ea[0].grfAccessPermissions = Permissions;
  ea[0].grfAccessMode = SET_ACCESS;
  ea[0].Trustee.TrusteeForm = TRUSTEE_IS_SID;
  ea[0].Trustee.ptstrName  = (LPTSTR)UserSID;
  // The ACE will allow Administrators full access to the object.
  ea[1].grfAccessPermissions = STANDARD_RIGHTS_ALL|SPECIFIC_RIGHTS_ALL;
  ea[1].grfAccessMode = GRANT_ACCESS;
  ea[0].Trustee.TrusteeForm = TRUSTEE_IS_SID;
  ea[1].Trustee.ptstrName  = (LPTSTR)AdminSID;
  // Create a new ACL that merges the new ACE
  // into the existing DACL.
  PACL pNewDACL=NULL;
  SetEntriesInAcl(2,&ea[0],pOldDACL,&pNewDACL);
  if (AdminSID)
    FreeSid(AdminSID);
  return pNewDACL;
}

void SetAdminDenyUserAccess(HANDLE hObject,PSID UserSID,DWORD Permissions/*=SYNCHRONIZE*/)
{
  if (NULL == hObject) 
    return; 
  PACL pOldDACL=NULL;
  PSECURITY_DESCRIPTOR pSD = NULL;
  // Get a pointer to the existing DACL.
  if (0==GetSecurityInfo(hObject,SE_KERNEL_OBJECT,DACL_SECURITY_INFORMATION,NULL,NULL,&pOldDACL,NULL,&pSD)) 
  {
    PACL pNewDACL=SetAdminDenyUserAccess(pOldDACL,UserSID,Permissions/*=SYNCHRONIZE*/);
    // Attach the new ACL as the object's DACL.
    if (pNewDACL)
    {
      SetSecurityInfo(hObject,SE_KERNEL_OBJECT,DACL_SECURITY_INFORMATION,NULL,NULL,pNewDACL,NULL);
      LocalFree((HLOCAL)pNewDACL); 
    }
  }
  if(pSD != NULL) 
    LocalFree((HLOCAL) pSD); 
}

void SetAdminDenyUserAccess(HANDLE hObject,DWORD ProcessID/*=0*/,DWORD Permissions/*=SYNCHRONIZE*/)
{
  if (ProcessID==0)
    ProcessID=GetCurrentProcessId();
  PSID UserSID=GetProcessUserSID(ProcessID);
  if (!UserSID)
    return;
  SetAdminDenyUserAccess(hObject,UserSID,Permissions);
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
  free(pUserSID);
  LocalFree(pACL);
  LocalFree(pSD);
  return pSDret;
Cleanup:
  if (pUserSID) 
    free(pUserSID);
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
// QualifyPath
//
//////////////////////////////////////////////////////////////////////////////

//Combine path parts
void Combine(LPTSTR Dst,LPTSTR path,LPTSTR file,LPTSTR ext)
{
  _tcscpy(Dst,path);
  PathAppend(Dst,file);
  PathAddExtension(Dst,ext);
}

//Split path parts
void Split(LPTSTR app,LPTSTR path,LPTSTR file,LPTSTR ext)
{
  //Get Path
  _tcscpy(path,app);
  PathRemoveFileSpec(path);
  //Get File, Ext
  _tcscpy(file,app);
  PathStripPath(file);
  _tcscpy(ext,PathFindExtension(file));
  PathRemoveExtension(file);
}

BOOL QualifyPath(LPTSTR app,LPTSTR path,LPTSTR file,LPTSTR ext,LPCTSTR CurDir)
{
  static LPTSTR ExeExts[]={L".exe",L".lnk",L".cmd",L".bat",L".com",L".pif"};
  if (path[0]=='.')
  {
    //relative path: make it absolute
    _tcscpy(app,CurDir);
    PathAppend(app,path);
    PathCanonicalize(path,app);
    Combine(app,path,file,ext);
  }
  if ((path[0]=='\\'))
  {
    if(path[1]=='\\')
      //UNC path: must be fully qualified!
      return PathFileExists(app)
        && (!PathIsDirectory(app));
    //Root of current drive
    _tcscpy(path,CurDir);
    PathStripToRoot(path);
    Combine(app,path,file,ext);
  }
  if (path[0]==0)
  {
    _tcscpy(path,app);
    LPCTSTR d[2]={CurDir,0};
    // file.ext ->search in current dir and %path%
    if ((PathFindOnPath(path,d))&&(!PathIsDirectory(path)))
    {
      //Done!
      _tcscpy(app,path);
      PathRemoveFileSpec(path);
      return TRUE;
    }
    if (ext[0]==0) for (int i=0;i<countof(ExeExts);i++)
    //Not found! Try all Extensions for Executables
    // file ->search (exe,bat,cmd,com,pif,lnk) in current dir, search %path%
    {
      _stprintf(path,L"%s%s",file,ExeExts[i]);
      if ((PathFindOnPath(path,d))&&(!PathIsDirectory(path)))
      {
        //Done!
        _tcscpy(app,path);
        _tcscpy(ext,ExeExts[i]);
        PathRemoveFileSpec(path);
        return TRUE;
      }
    }
    return FALSE;
  }
  if (path[1]==':')
  {
    static TCHAR d[4096];
    zero(d);
    GetCurrentDirectory(countof(d),d);
    //if path=="d:" -> "cd d:"
    if (!SetCurrentDirectory(path))
      return false;
    //if path=="d:" -> "cd d:" -> "d:\documents"
    GetCurrentDirectory(4096,path);
    SetCurrentDirectory(d);
    Combine(app,path,file,ext);
  }
  // d:\path\file.ext ->PathFileExists
  if (PathFileExists(app) && (!PathIsDirectory(app)))
    return TRUE;
  if (ext[0]==0) for (int i=0;i<countof(ExeExts);i++)
  //Not found! Try all Extensions for Executables
  // file ->search (exe,bat,cmd,com,pif,lnk) in path
  {
    Combine(app,path,file,ExeExts[i]);
    if ((PathFileExists(app))&&(!PathIsDirectory(app)))
    {
      //Done!
      _tcscpy(ext,ExeExts[i]);
      return TRUE;
    }
  }
  return FALSE;
}

//////////////////////////////////////////////////////////////////////////////
//
// ResolveCommandLine: Based on SuDown (http://SuDown.sourceforge.net)
//
//////////////////////////////////////////////////////////////////////////////
BOOL ResolveCommandLine(IN LPWSTR CmdLine,IN LPCWSTR CurDir,OUT LPTSTR cmd)
{
  //Application
  static TCHAR app[4096];
  zero(app);
  static TCHAR args[4096]={0};
  zero(args);
  _tcscpy(args,CmdLine);
  PathRemoveBlanks(args);
  //Clean up double spaces or unneeded quotes
  LPTSTR p=&args[0];
  while (p && *p)
  {
    LPTSTR p1=PathGetArgs(p);
    if(p1 && *p1)
      *(p1-1)=0;
    PathRemoveBlanks(p);
    PathUnquoteSpaces(p);
    PathQuoteSpaces(p);
    _tcscat(app,p);
    if (p1 && *p1)
        _tcscat(app,_T(" "));
    p=p1;
  }
  //Save parameters
  _tcscpy(args,PathGetArgs(app));
  PathRemoveArgs(app);
  PathUnquoteSpaces(app);
  NetworkPathToUNCPath(app);
  BOOL fExist=PathFileExists(app);
  //Split path parts
  static TCHAR path[4096];
  static TCHAR file[4096+1];
  static TCHAR ext[4096+1];
  static TCHAR SysDir[4096+1];
  zero(path);
  zero(file);
  zero(ext);
  zero(SysDir);
  GetSystemDirectory(SysDir,4096);
  Split(app,path,file,ext);
  //Explorer(.exe)
  if ((!fExist)&&(!_wcsicmp(app,L"explorer"))||(!_wcsicmp(app,L"explorer.exe")))
  {
    if (args[0]==0) 
      wcscpy(args,L"/e, C:");
    GetSystemWindowsDirectory(app,4096);
    PathAppend(app, L"explorer.exe");
  }else 
  //Msconfig(.exe) is not in path but found by windows
  if ((!fExist)&&(!_wcsicmp(app,L"msconfig"))||(!_wcsicmp(app,L"msconfig.exe")))
  {
    GetSystemWindowsDirectory(app,4096);
    PathAppend(app, L"pchealth\\helpctr\\binaries\\msconfig.exe");
    if (!PathFileExists(app))
      wcscpy(app,L"msconfig");
    zero(args);
  }else
  //Control Panel special folder files:
  if (((!fExist)
    &&((!_wcsicmp(app,L"control.exe"))||(!_wcsicmp(app,L"control"))) 
    && (args[0]==0))
    ||(fExist && (!_wcsicmp(path,SysDir)) && (!_wcsicmp(file,L"control")) && (!_wcsicmp(ext,L".exe"))))
  {
    GetSystemWindowsDirectory(app,4096);
    PathAppend(app,L"explorer.exe");
    if (LOBYTE(LOWORD(GetVersion()))<6)
      //2k/XP: Control Panel is beneath "my computer"!
      wcscpy(args,L"/n, ::{20D04FE0-3AEA-1069-A2D8-08002B30309D}\\::{21EC2020-3AEA-1069-A2DD-08002B30309D}");
    else
      //Vista: Control Panel is beneath desktop!
      wcscpy(args,L"/n, ::{21EC2020-3AEA-1069-A2DD-08002B30309D}");
  }else if (((!_wcsicmp(app,L"ncpa.cpl")) && (args[0]==0))
    ||(fExist && (!_wcsicmp(path,SysDir)) && (!_wcsicmp(file,L"ncpa")) && (!_wcsicmp(ext,L".cpl"))))
  {
    GetSystemWindowsDirectory(app,4096);
    PathAppend(app,L"explorer.exe");
    if (LOBYTE(LOWORD(GetVersion()))<6)
      //2k/XP: Control Panel is beneath "my computer"!
      wcscpy(args,L"/n, ::{20D04FE0-3AEA-1069-A2D8-08002B30309D}\\::{21EC2020-3AEA-1069-A2DD-08002B30309D}\\::{7007ACC7-3202-11D1-AAD2-00805FC1270E}");
    else
      //Vista: Control Panel is beneath desktop!
      wcscpy(args,L"/n, ::{21EC2020-3AEA-1069-A2DD-08002B30309D}\\::{7007ACC7-3202-11D1-AAD2-00805FC1270E}");
  }else 
  //*.reg files
  if (!_wcsicmp(ext, L".reg")) 
  {
    PathQuoteSpaces(app);
    wcscpy(args,app);
    GetSystemWindowsDirectory(app,4096);
    PathAppend(app, L"regedit.exe");
  }else
  //Control Panel files  
  if (!_wcsicmp(ext, L".cpl")) 
  {
    PathQuoteSpaces(app);
    if (args[0] && app[0])
      wcscat(app,L",");
    wcscat(app,args);
    wcscpy(args,L"shell32.dll,Control_RunDLLAsUser ");
    wcscat(args,app);
    GetSystemDirectory(app,4096);
    PathAppend(app,L"rundll32.exe");
  }else 
  //Windows Installer files  
  if (!_wcsicmp(ext, L".msi")) 
  {
    PathQuoteSpaces(app);
    if (args[0] && app[0])
    {
      wcscat(app,L" ");
      wcscat(app,args);
      wcscpy(args,app);
    }else
    {
      wcscpy(args,L"/i ");
      wcscat(args,app);
    }
    GetSystemDirectory(app,4096);
    PathAppend(app,L"msiexec.exe");
  }else 
  //Windows Management Console Sanp-In
  if (!_wcsicmp(ext, L".msc")) 
  {
    if (path[0]==0)
    {
      GetSystemDirectory(path,4096);
      PathAppend(path,app);
      wcscpy(app,path);
      zero(path);
    }
    PathQuoteSpaces(app);
    if (args[0] && app[0])
      wcscat(app,L" ");
    wcscat(app,args);
    wcscpy(args,app);
    GetSystemDirectory(app,4096);
    PathAppend(app,L"mmc.exe");
  }else
  //Try to fully qualify the executable:
  if (!QualifyPath(app,path,file,ext,CurDir))
  {
    _tcscpy(app,CmdLine);
    PathRemoveArgs(app);
    PathUnquoteSpaces(app);
    NetworkPathToUNCPath(app);
    Split(app,path,file,ext);
  }
  wcscpy(cmd,app);
  fExist=PathFileExists(app);
  PathQuoteSpaces(cmd);
  if (args[0] && app[0])
    wcscat(cmd,L" ");
  wcscat(cmd,args);
  return fExist;
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
  TCHAR s[4096];
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
// GetTokenUserSID
// 
//////////////////////////////////////////////////////////////////////////////

PSID GetTokenUserSID(HANDLE hToken)
{
  PSID sid=0;
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
  return sid;
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
  // Open impersonation token for process
  if (OpenProcessToken(hProc,TOKEN_QUERY,&hToken))
  {
    sid=GetTokenUserSID(hToken);
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
  // Open impersonation token for process
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
// GetShellProcessToken
// 
/////////////////////////////////////////////////////////////////////////////

HANDLE GetShellProcessToken()
{
  DWORD ShellID=0;
  GetWindowThreadProcessId(GetShellWindow(),&ShellID);
  if (!ShellID)
    return 0;
  HANDLE hShell=OpenProcess(PROCESS_QUERY_INFORMATION,0,ShellID);
  if (!hShell)
    return 0;
  HANDLE hTok=0;
  OpenProcessToken(hShell,TOKEN_DUPLICATE,&hTok);
  CloseHandle(hShell);
  return hTok;
}

//////////////////////////////////////////////////////////////////////////////
//
//  GetProcessID
//
//  Get the Process ID for a file name. Filename is stripped to the bones e.g.
//  "Explorer.exe" instead of "C:\Windows\Explorer.exe"
//  If there are multiple "Explorer.exe"s running in your Logon session, the
//  function will return the ID of the first Process it finds.
//
//  The purpose of this function ist primarily to get the Process ID of the
//  Shell process.
//////////////////////////////////////////////////////////////////////////////

DWORD GetProcessID(LPCTSTR ProcName,DWORD SessID=-1)
{
  if (SessID!=(DWORD)-1)
  {
    //Terminal Services:
    DWORD nProcesses=0;
    WTS_PROCESS_INFO* pwtspi=0;
    WTSEnumerateProcesses(WTS_CURRENT_SERVER_HANDLE,0,1,&pwtspi,&nProcesses);
    for (DWORD Process=0;Process<nProcesses;Process++) 
    {
      if (pwtspi[Process].SessionId!=SessID)
        continue;
      TCHAR PName[MAX_PATH]={0};
      _tcscpy(PName,pwtspi[Process].pProcessName);
      PathStripPath(PName);
      if (_tcsicmp(ProcName,PName)==0)
        return WTSFreeMemory(pwtspi), pwtspi[Process].ProcessId;
    }
    WTSFreeMemory(pwtspi);
  }
  //ToolHelp
  HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0);
  if (hSnap==INVALID_HANDLE_VALUE)
    return 0; 
  DWORD dwRet=0;
  PROCESSENTRY32 pe={0};
  pe.dwSize = sizeof(PROCESSENTRY32);
  bool bFirst=true;
  while((bFirst?Process32First(hSnap,&pe):Process32Next(hSnap,&pe)))
  {
    bFirst=false;
    PathStripPath(pe.szExeFile);
    if(_tcsicmp(ProcName,pe.szExeFile)!=0) 
      continue;
    if ((SessID!=(DWORD)-1))
    {
      ULONG s=-2;
      if ((!ProcessIdToSessionId(pe.th32ProcessID,&s))||(s!=SessID))
        continue;
    }
    dwRet=pe.th32ProcessID;
    break;
  }
  CloseHandle(hSnap);
  return dwRet;
}

//////////////////////////////////////////////////////////////////////////////
// 
// GetTokenGroups
// 
//////////////////////////////////////////////////////////////////////////////

PTOKEN_GROUPS	GetTokenGroups(HANDLE hToken)
{
	DWORD	cbBuffer  = 0;
	PTOKEN_GROUPS	ptgGroups = NULL;
	GetTokenInformation(hToken, TokenGroups, NULL, cbBuffer, &cbBuffer);
	if (cbBuffer)
		ptgGroups=(PTOKEN_GROUPS)malloc(cbBuffer);
  if (ptgGroups)
    GetTokenInformation(hToken,TokenGroups,ptgGroups,cbBuffer,&cbBuffer);
  return ptgGroups;
}

//////////////////////////////////////////////////////////////////////////////
// 
// FindLogonSID
// 
//////////////////////////////////////////////////////////////////////////////

PSID FindLogonSID(PTOKEN_GROUPS	ptg)
{
  for(UINT i=0;i<ptg->GroupCount;i++)
    if(((ptg->Groups[i].Attributes & SE_GROUP_LOGON_ID)==SE_GROUP_LOGON_ID)
      &&(IsValidSid(ptg->Groups[i].Sid)))
        return ptg->Groups[i].Sid;
  return 0;
}

//////////////////////////////////////////////////////////////////////////////
// 
// GetLogonSid ...copies the SID from FindLogonSID to a new buffer
// 
//////////////////////////////////////////////////////////////////////////////

PSID GetLogonSid(HANDLE hToken)
{
	PTOKEN_GROUPS	ptgGroups = GetTokenGroups(hToken);
  if (!ptgGroups)
    return 0;
  PSID sid=FindLogonSID(ptgGroups);
  if (sid)
  {
    DWORD dwSidLength=GetLengthSid(sid);
    PSID pLogonSid=(PSID)malloc(dwSidLength);
    if (pLogonSid)
    {
      if (CopySid(dwSidLength,pLogonSid,sid))
      {
        free(ptgGroups);
        return pLogonSid;
      }
      free(pLogonSid);
    }
  }
  free(ptgGroups);
	return 0;
}

//////////////////////////////////////////////////////////////////////////////
// 
// UserIsInSuRunnersOrAdmins
// 
//////////////////////////////////////////////////////////////////////////////

DWORD UserIsInSuRunnersOrAdmins()
{
  HANDLE hToken=NULL;
  if (!OpenProcessToken(GetCurrentProcess(),TOKEN_QUERY,&hToken))
    return 0;
	PTOKEN_GROUPS	ptg = GetTokenGroups(hToken);
  CloseHandle(hToken);
  if (!ptg)
    return 0;
  SID_IDENTIFIER_AUTHORITY AdminSidAuthority = SECURITY_NT_AUTHORITY;
  PSID AdminSID = NULL;
  // Initialize Admin SID
  if (!AllocateAndInitializeSid(&AdminSidAuthority,2,SECURITY_BUILTIN_DOMAIN_RID,
    DOMAIN_ALIAS_RID_ADMINS,0,0,0,0,0,0,&AdminSID))
    return free(ptg),0; 
  PSID SuRunnersSID=GetAccountSID(SURUNNERSGROUP);
  DWORD dwRet=0;
  for(UINT i=0;i<ptg->GroupCount;i++)
    if((ptg->Groups[i].Attributes & SE_GROUP_ENABLED|SE_GROUP_ENABLED_BY_DEFAULT|SE_GROUP_MANDATORY)
      &&(IsValidSid(ptg->Groups[i].Sid)))
    {
      if(EqualSid(ptg->Groups[i].Sid,AdminSID))
        dwRet|=IS_IN_ADMINS;
      else if(EqualSid(ptg->Groups[i].Sid,SuRunnersSID))
        dwRet|=IS_IN_SURUNNERS;
    }

  FreeSid(AdminSID);
  free(SuRunnersSID);
  free(ptg);
	return dwRet;
}

//////////////////////////////////////////////////////////////////////////////
//
//  GetSessionUserToken
//
//  This function tries to use WTSQueryUserToken to get the token of the 
//  currently logged on user. If the WTSQueryUserToken method fails, we'll
//  try to steal the user token of the logon sessions shell process.
//////////////////////////////////////////////////////////////////////////////

HANDLE GetSessionUserToken(DWORD SessID)
{
  //WTSQueryUserToken is present in WinXP++, load it dynamically
  typedef BOOL (WINAPI* wtsqut)(ULONG,PHANDLE);
  static wtsqut wtsqueryusertoken=NULL;
  if (!wtsqueryusertoken)
  {
    HINSTANCE wtsapi32=LoadLibrary(_T("wtsapi32.dll"));
    if (wtsapi32)
      wtsqueryusertoken=(wtsqut)GetProcAddress(wtsapi32,"WTSQueryUserToken");
  }
  HANDLE hToken = NULL;
  //SE_TCB_NAME is only present in a local System User Token
  //WTSQueryUserToken requires SE_TCB_NAME!
  if ((!wtsqueryusertoken)
    ||(!EnablePrivilege(SE_TCB_NAME))
    ||(!wtsqueryusertoken(SessID,&hToken))
    ||(hToken==NULL))
  {
    //No WTSQueryUserToken: we're in Win2k
    //Get the Shells Name
    TCHAR Shell[MAX_PATH];
    if (!GetRegStr(HKEY_LOCAL_MACHINE,_T("SOFTWARE\\Microsoft\\Windows NT\\")
                   _T("CurrentVersion\\Winlogon"),_T("Shell"),Shell,MAX_PATH))
      return 0;
    PathRemoveArgs(Shell);
    PathStripPath(Shell);
    //Now get the Shells Process ID
    DWORD ShellID=GetProcessID(Shell,SessID);
    if (!ShellID)
      return 0;
    //We got the Shells Process ID, now get the user token
    EnablePrivilege(SE_DEBUG_NAME);
    HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS,TRUE,ShellID);
    if (!hProc)
      return 0;
    // Open impersonation token for Shell process
    OpenProcessToken(hProc,TOKEN_IMPERSONATE|TOKEN_QUERY|TOKEN_DUPLICATE
                          |TOKEN_ASSIGN_PRIMARY,&hToken);
    CloseHandle(hProc);
    if(!hToken)
      return 0;
  }
  HANDLE hTokenDup=NULL;
  DuplicateTokenEx(hToken,MAXIMUM_ALLOWED,NULL,SecurityIdentification,
                          TokenPrimary,&hTokenDup); 
  CloseHandle(hToken);
  return hTokenDup;
}

//////////////////////////////////////////////////////////////////////////////
//
//  GetSessionLogonSID
//
//////////////////////////////////////////////////////////////////////////////

PSID GetSessionLogonSID(DWORD SessionID)
{
  HANDLE hToken=GetSessionUserToken(SessionID);
  if (!hToken)
    return 0;
  PSID p=GetLogonSid(hToken);
  CloseHandle(hToken);
  return p;
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
  TCHAR FName[4096];
  GetModuleFileName(0,FName,4096);
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
  TCHAR PicDir[4096];
  GetRegStr(HKEY_LOCAL_MACHINE,
    _T("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders"),
    _T("Common AppData"),PicDir,4096);
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

/////////////////////////////////////////////////////////////////////////////
// 
// strwldcmp returns true if s matches pattern case insensitive
// pattern may contain '*' and '?' as wildcards
// '?' any "one" character in s match
// '*' any "zero or more" characters in s match
// e.G. strwldcmp("Test me","t*S*") strwldcmp("Test me","t?S*e") would match
//
/////////////////////////////////////////////////////////////////////////////

bool strwldcmp(LPCTSTR s, LPCTSTR pattern) 
{
  if ((!s) || (!pattern))
    return false;
  while (*pattern)
  {
    if (*s==0)
      return (*pattern=='*')&&(pattern[1]==0);
    //ignore case; skip, if pattern is '?'
    if ((toupper(*s)==toupper(*pattern))||(*pattern=='?'))
    {
      s++;
      pattern++;
    }else if (*pattern=='*') 
    {
      pattern++;
      //nothing after '*', ok for any string
      if (*pattern==0)
        return true;
      //pattern contains something after '*', string needs to have a match
      while(*s)
      {
        if (strwldcmp(s,pattern))
          return true;
        s++;
      }
      return false;
    }else
      return false;
  }
  return *s==0;
}
