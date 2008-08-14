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
#include <shlwapi.h>
#include <stdio.h>
#include <Aclapi.h>
#pragma comment(lib,"shlwapi.lib")

typedef UINT (WINAPI* GETSYSWOW64DIRA)(LPSTR, UINT);

void AllowAccess(LPTSTR FileName)
{
  DWORD dwRes;
  PACL pOldDACL = NULL, pNewDACL = NULL;
  PSECURITY_DESCRIPTOR pSD = NULL;
  EXPLICIT_ACCESS ea;
  SID_IDENTIFIER_AUTHORITY SIDAuthWorld = SECURITY_WORLD_SID_AUTHORITY;
  PSID pEveryoneSID = NULL;
  if (NULL == FileName) 
    return;
  // Get a pointer to the existing DACL.
  dwRes = GetNamedSecurityInfo(FileName, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION,  NULL, NULL, &pOldDACL, NULL, &pSD);
  if (ERROR_SUCCESS != dwRes) 
    goto Cleanup; 
  // Create a well-known SID for the Everyone group.
  if(! AllocateAndInitializeSid( &SIDAuthWorld, 1, SECURITY_WORLD_RID, 0, 0, 0, 0, 0, 0, 0, &pEveryoneSID) ) 
    return;
  // Initialize an EXPLICIT_ACCESS structure for an ACE.
  // The ACE will allow Users read access to the key.
  memset(&ea,0,sizeof(EXPLICIT_ACCESS));
  ea.grfAccessPermissions = FILE_ALL_ACCESS;
  ea.grfAccessMode = SET_ACCESS;
  ea.grfInheritance= SUB_CONTAINERS_AND_OBJECTS_INHERIT;
  ea.Trustee.TrusteeForm = TRUSTEE_IS_SID;
  ea.Trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;
  ea.Trustee.ptstrName  = (LPTSTR) pEveryoneSID;
  // Create a new ACL that merges the new ACE
  // into the existing DACL.
  dwRes = SetEntriesInAcl(1, &ea, pOldDACL, &pNewDACL);
  if (ERROR_SUCCESS != dwRes)  
    goto Cleanup; 
  // Attach the new ACL as the object's DACL.
  dwRes = SetNamedSecurityInfo(FileName, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION,  NULL, NULL, pNewDACL, NULL);
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

BOOL IsWow64()
{
  GETSYSWOW64DIRA gSysW64Dir;
  HMODULE hKrnl = GetModuleHandle("kernel32.dll");
  if (hKrnl == NULL)
    return FALSE;
  char Dir[MAX_PATH];
  gSysW64Dir=(GETSYSWOW64DIRA)GetProcAddress(hKrnl,"GetSystemWow64DirectoryA");
  if (gSysW64Dir==NULL)
    return FALSE;
  return (gSysW64Dir(Dir,MAX_PATH)!=0)
       ||(GetLastError()!=ERROR_CALL_NOT_IMPLEMENTED);
}

bool ResToTmp(LPCTSTR Section,LPCTSTR ResName)
{
  HMODULE hMod=GetModuleHandle(0);
  HRSRC hResFnd =FindResource(hMod,ResName,Section);
  if (hResFnd==0) 
    return false;
  HGLOBAL hResLd =LoadResource(hMod,hResFnd);
  if (hResLd==0) 
    return false;
  LPVOID pRes=LockResource(hResLd);
  if (pRes ==NULL) 
    return FreeResource(hResLd),false;
  DWORD Siz=SizeofResource(hMod,hResFnd);
  CHAR tmp[4096];
  GetTempPath(MAX_PATH,tmp);
  PathRemoveBackslash(tmp);
  PathAppend(tmp,"SuRunIst");
  CreateDirectory(tmp,0);
  AllowAccess(tmp);
  PathAppend(tmp,ResName);
  FILE* f=fopen(tmp,"wb");
  if (!f)
    return UnlockResource(hResLd),FreeResource(hResLd),false;
  bool res=fwrite(pRes,Siz,1,f)==1;
  fclose(f);
  AllowAccess(tmp);
  UnlockResource(hResLd);
  FreeResource(hResLd);
  return res;
};

void RunTmp(LPSTR cmd)
{
  CHAR tmp[4096];
  GetTempPath(MAX_PATH,tmp);
  SetCurrentDirectory(tmp);
  PathRemoveBackslash(tmp);
  PathAppend(tmp,cmd);
  PROCESS_INFORMATION pi={0};
  STARTUPINFO si={0};
  si.cb	= sizeof(si);
  if (CreateProcess(NULL,tmp,0,0,FALSE,NORMAL_PRIORITY_CLASS,0,0,&si,&pi))
  {
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
  }
}

void DelTmpFile(LPCSTR File)
{
  CHAR tmp[4096];
  GetTempPath(MAX_PATH,tmp);
  PathRemoveBackslash(tmp);
  PathAppend(tmp,File);
  MoveFileEx(tmp,NULL,MOVEFILE_DELAY_UNTIL_REBOOT); 
}

int APIENTRY WinMain(HINSTANCE,HINSTANCE,LPSTR,int)
{
  if(IsWow64()) //Win64
  {
    if ( ResToTmp("EXE64_FILE","SuRun.exe")
      && ResToTmp("EXE64_FILE","SuRunExt.dll")
      && ResToTmp("EXE64_FILE","SuRun32.bin")
      && ResToTmp("EXE64_FILE","SuRunExt32.dll"))
    {
      RunTmp("SuRunIst\\SuRun.exe /USERINST");
      DelTmpFile("SuRunIst\\SuRun32.bin");
      DelTmpFile("SuRunIst\\SuRunExt32.dll");
      DelTmpFile("SuRunIst\\SuRun.exe");
      DelTmpFile("SuRunIst\\SuRunExt.dll");
      DelTmpFile("SuRunIst");
    }
  }else //Win32
  {
    if ( ResToTmp("EXE_FILE","SuRun.exe")
      && ResToTmp("EXE_FILE","SuRunExt.dll"))
    {
      RunTmp("SuRun.exe /USERINST");
      DelTmpFile("SuRunIst\\SuRun.exe");
      DelTmpFile("SuRunIst\\SuRunExt.dll");
      DelTmpFile("SuRunIst");
    }
  }
	return 0;
}
