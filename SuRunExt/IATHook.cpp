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
#include <Psapi.h>
#include <ShlWapi.h>

#include <list>
#include <algorithm>
#include <iterator>

#include "../helpers.h"
#include "../DBGTrace.h"
#include "SysMenuHook.h"

#pragma comment(lib,"Advapi32.lib")
#pragma comment(lib,"ShlWapi.lib")
#pragma comment(lib,"PSAPI.lib")

//Forward decl:
BOOL WINAPI CreateProcA(LPCSTR,LPSTR,LPSECURITY_ATTRIBUTES,LPSECURITY_ATTRIBUTES,
                        BOOL,DWORD,LPVOID,LPCSTR,LPSTARTUPINFOA,LPPROCESS_INFORMATION);
BOOL WINAPI CreateProcW(LPCWSTR,LPWSTR,LPSECURITY_ATTRIBUTES,LPSECURITY_ATTRIBUTES,
                        BOOL,DWORD,LPVOID,LPCWSTR,LPSTARTUPINFOW,LPPROCESS_INFORMATION);

//BOOL WINAPI CreateProcWithLogonW(LPCWSTR,LPCWSTR,LPCWSTR,DWORD,LPCWSTR,LPWSTR,DWORD,
//                                 LPVOID,LPCWSTR,LPSTARTUPINFOW,LPPROCESS_INFORMATION);

FARPROC WINAPI GetProcAddr(HMODULE,LPCSTR);

HMODULE WINAPI LoadLibA(LPCSTR);
HMODULE WINAPI LoadLibW(LPCWSTR);
HMODULE WINAPI LoadLibExA(LPCSTR,HANDLE,DWORD);
HMODULE WINAPI LoadLibExW(LPCWSTR,HANDLE,DWORD);

typedef struct 
{
  HMODULE hMod;
  DWORD orgFunc;
  PROC newFunc;
}HOOKDATA;

typedef std::list<HOOKDATA> HookList;
typedef std::list<HMODULE> ModList;

int g_nHooked=0;
ModList g_ModList;
HookList g_HookList;

//Hook Descriptor
typedef struct 
{
  LPCSTR DllName;
  LPCSTR FuncName;
  PROC newFunc;
}HOOKDESCRIPTOR; 

const HOOKDESCRIPTOR hdt[]=
{
  //Standard Hooks: These must be implemented!
  {"kernel32.dll","LoadLibraryA",(PROC)LoadLibA},
  {"kernel32.dll","LoadLibraryW",(PROC)LoadLibW},
  {"kernel32.dll","LoadLibraryExA",(PROC)LoadLibExA},
  {"kernel32.dll","LoadLibraryExW",(PROC)LoadLibExW},
  {"kernel32.dll","GetProcAddress",(PROC)GetProcAddr},
  //User Hooks:
  {"kernel32.dll","CreateProcessA",(PROC)CreateProcA},
  {"kernel32.dll","CreateProcessW",(PROC)CreateProcW}
};

//relative pointers in PE images
#define RelPtr(_T,pe,rpt) (_T)( (DWORD_PTR)(pe)+(DWORD_PTR)(rpt))

//returns true if DllName is one to be hooked up
BOOL DoHookDll(char* DllName)
{
  for(int i=0;i<countof(hdt);i++)
    if (stricmp(hdt[i].DllName,DllName)==0)
      return true;
  return false;
}

//returns newFunc if DllName->ImpName is one to be hooked up
PROC DoHookFn(char* DllName,char* ImpName)
{
  if(IsBadReadPtr(DllName,1)||IsBadReadPtr(ImpName,1))
    return 0;
  if(*DllName && *ImpName)
    for(int i=0;i<countof(hdt);i++)
      if (stricmp(hdt[i].DllName,DllName)==0)
        if (stricmp(hdt[i].FuncName,ImpName)==0)
          return hdt[i].newFunc;
  return false;
}

DWORD HookIAT(HMODULE hMod,BOOL bUnHook)
{
  DWORD nHooked=0;
  if(hMod==l_hInst)
    return nHooked;
  // check "MZ" and DOS Header size
  if(IsBadReadPtr(hMod,sizeof(IMAGE_DOS_HEADER))
    || (((PIMAGE_DOS_HEADER)hMod)->e_magic!=IMAGE_DOS_SIGNATURE))
    return nHooked;
  // check "PE" and DOS Header size
  PIMAGE_NT_HEADERS pNTH = RelPtr(PIMAGE_NT_HEADERS,hMod,((PIMAGE_DOS_HEADER)hMod)->e_lfanew);
  if(IsBadReadPtr(pNTH, sizeof(IMAGE_NT_HEADERS)) ||(pNTH->Signature != IMAGE_NT_SIGNATURE))
    return nHooked;
  //the right header?
#ifdef _WIN64
  if(pNTH->FileHeader.Machine!=IMAGE_FILE_MACHINE_AMD64)
    return nHooked;
#else _WIN64
  if(pNTH->FileHeader.Machine!=IMAGE_FILE_MACHINE_I386)
    return nHooked;
#endif _WIN64
  if(pNTH->FileHeader.SizeOfOptionalHeader!=sizeof(IMAGE_OPTIONAL_HEADER))
    return nHooked;
  //patch IAT
  PIMAGE_IMPORT_DESCRIPTOR pID = RelPtr(PIMAGE_IMPORT_DESCRIPTOR,hMod,
    pNTH->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
  if((HMODULE)pID == hMod) 
    return nHooked;
  for(;pID->Name;pID++) 
  {
    char* DllName=RelPtr(char*,hMod,pID->Name);
    if(DoHookDll(DllName))
    {
      PIMAGE_THUNK_DATA pOrgThunk=RelPtr(PIMAGE_THUNK_DATA,hMod,pID->OriginalFirstThunk);
      PIMAGE_THUNK_DATA pThunk=RelPtr(PIMAGE_THUNK_DATA,hMod,pID->FirstThunk);
      for(;pOrgThunk->u1.Function;pOrgThunk++,pThunk++)
        if ((pOrgThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG )!=IMAGE_ORDINAL_FLAG)
        {
          PIMAGE_IMPORT_BY_NAME pBN=RelPtr(PIMAGE_IMPORT_BY_NAME,hMod,pOrgThunk->u1.AddressOfData);
          PROC newFunc = DoHookFn(DllName,(char*)pBN->Name);
          if (newFunc 
            && ((!bUnHook) && (pThunk->u1.Function!=(DWORD_PTR)newFunc)
            ||( bUnHook  && (pThunk->u1.Function==(DWORD_PTR)newFunc)))
            )
          {
            MEMORY_BASIC_INFORMATION mbi;
            if (VirtualQuery(&pThunk->u1.Function, &mbi, sizeof(MEMORY_BASIC_INFORMATION))!=0)
            {
              DWORD oldProt;
              if(VirtualProtect(mbi.BaseAddress, mbi.RegionSize, PAGE_READWRITE, &oldProt))
              {
                if (bUnHook)
                {
                  //search g_HookList for the function and revert the IAT change
                  for(HookList::iterator it=g_HookList.begin();it!=g_HookList.end();++it)
                    if ((it->hMod==hMod)&&(it->newFunc==newFunc))
                    {
                      pThunk->u1.Function = it->orgFunc;
                      g_HookList.erase(it);
                      g_nHooked--;
                      nHooked++;
                      break;
                    }
                }else
                {
                  //add Data to g_HookList for UnHook
                  HOOKDATA hd={hMod,pThunk->u1.Function,newFunc};
                  g_HookList.push_back(hd);
                  pThunk->u1.Function = (DWORD_PTR) newFunc;
                  g_nHooked++;
                  nHooked++;
                }
              }
              VirtualProtect(mbi.BaseAddress, mbi.RegionSize, oldProt, &oldProt);
            }
          }
        }
    }//if(DoHookDll(DllName))
  }//for(;pID->Name;pID++) 
  return nHooked;
}

DWORD HookModules()
{
  HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS,TRUE,GetCurrentProcessId());
  if (!hProc)
  {
    DBGTrace("HookModules(): OpenProcess failed");
    return 0;
  }
  DWORD Siz=0;
  DWORD nHooked=0;
  EnumProcessModules(hProc,0,0,&Siz);
  HMODULE* hMod=Siz?(HMODULE*)malloc(Siz):0;
  if(hMod)
  {
    DWORD n=Siz/sizeof(HMODULE);
    EnumProcessModules(hProc,hMod,Siz,&Siz);
    std::sort(hMod,hMod+n);
    ModList newMods;
    //get new hModules
    std::set_difference(hMod,hMod+n,g_ModList.begin(),g_ModList.end(),std::back_inserter(newMods));
    //Hook new hModules
    for(ModList::iterator it=newMods.begin();it!=newMods.end();++it)
      nHooked+=HookIAT(*it,false);
    //merge new hModules to list
    g_ModList.merge(newMods);
    free(hMod);
  }
  CloseHandle(hProc);
  return nHooked;
}

DWORD UnHookModules()
{
  //UnHook all hModules
  DWORD nHooked=0;
  for(ModList::iterator it=g_ModList.begin();it!=g_ModList.end();++it)
    nHooked+=HookIAT(*it,TRUE);
  g_ModList.clear();
  return nHooked;
}

BOOL InjectIATHook(HANDLE hProc)
{
  HANDLE hThread=0;
  __try
  {
    PROC pLoadLib=GetProcAddress(GetModuleHandleA("Kernel32"),"LoadLibraryA");
    if(!pLoadLib)
      return false;
	  char DllName[MAX_PATH];
	  if(!GetModuleFileNameA(l_hInst,DllName,MAX_PATH))
		  return false;
	  void* RmteName=VirtualAllocEx(hProc,NULL,sizeof(DllName),MEM_COMMIT,PAGE_READWRITE);
	  if(RmteName==NULL)
		  return false;
	  WriteProcessMemory(hProc,RmteName,(void*)DllName,sizeof(DllName),NULL);
    __try
    {
      hThread=CreateRemoteThread(hProc,NULL,0,(LPTHREAD_START_ROUTINE)pLoadLib,RmteName,0,NULL);
    }__except(1)
    {
    }
	  if(hThread!=NULL )
    {
      WaitForSingleObject(hThread,INFINITE);
      CloseHandle(hThread);
    }
	  VirtualFreeEx(hProc,RmteName,sizeof(DllName),MEM_RELEASE);
  }__except(1)
  {
  }
  return hThread!=0;
}

BOOL WINAPI CreateProcA(LPCSTR lpApplicationName,LPSTR lpCommandLine,
    LPSECURITY_ATTRIBUTES lpProcessAttributes,LPSECURITY_ATTRIBUTES lpThreadAttributes,
    BOOL bInheritHandles,DWORD dwCreationFlags,LPVOID lpEnvironment,
    LPCSTR lpCurrentDirectory,LPSTARTUPINFOA lpStartupInfo,
    LPPROCESS_INFORMATION lpProcessInformation)
{
  char cmd[4096];
  GetSystemWindowsDirectoryA(cmd,4096);
  PathAppendA(cmd,"SuRun.exe");
  PathQuoteSpacesA(cmd);
  strcat(cmd," /TESTAUTOADMIN ");
  char* parms=(lpCommandLine && strlen(lpCommandLine))?lpCommandLine:0;
  if(lpApplicationName)
  {
    char tmp[4096];
    if (parms)
    {
      //lpApplicationName and the first token of lpCommandLine may be the same
      //we need to check this:
      strcpy(tmp,lpCommandLine);
      PathRemoveArgsA(tmp);
      PathUnquoteSpacesA(tmp);
      if (stricmp(tmp,lpApplicationName)==0)
        parms=PathGetArgsA(lpCommandLine);
    }
    strcpy(tmp,lpApplicationName);
    PathQuoteSpacesA(tmp);
    strcat(cmd,tmp);
    if (parms)
      strcat(cmd," ");
  }
  if (parms)
    strcat(cmd,parms);
  DWORD ExitCode=ERROR_ACCESS_DENIED;
  STARTUPINFOA si;
  PROCESS_INFORMATION pi;
  ZeroMemory(&si, sizeof(si));
  si.cb = sizeof(si);
  // Start the child process.
  if (CreateProcessA(NULL,cmd,NULL,NULL,FALSE,0,NULL,NULL,&si,&pi))
  {
    CloseHandle(pi.hThread );
    if(WaitForSingleObject(pi.hProcess,60000)==WAIT_OBJECT_0)
      GetExitCodeProcess(pi.hProcess,(DWORD*)&ExitCode);
    CloseHandle(pi.hProcess);
  }
  BOOL b=FALSE;
  if (ExitCode!=0)
  {
    DWORD cf=CREATE_SUSPENDED|dwCreationFlags;
    b=CreateProcessA(lpApplicationName,lpCommandLine,lpProcessAttributes,
        lpThreadAttributes,bInheritHandles,cf,lpEnvironment,
        lpCurrentDirectory,lpStartupInfo,lpProcessInformation);
    if (b)
    {
      //Process is suspended...
      InjectIATHook(lpProcessInformation->hProcess);
      //Resume main thread:
      if ((CREATE_SUSPENDED & dwCreationFlags)==0)
        ResumeThread(lpProcessInformation->hThread);
    }
  }
  return b;
}

BOOL WINAPI CreateProcW(LPCWSTR lpApplicationName,LPWSTR lpCommandLine,
    LPSECURITY_ATTRIBUTES lpProcessAttributes,LPSECURITY_ATTRIBUTES lpThreadAttributes,
    BOOL bInheritHandles,DWORD dwCreationFlags,LPVOID lpEnvironment,
    LPCWSTR lpCurrentDirectory,LPSTARTUPINFOW lpStartupInfo,
    LPPROCESS_INFORMATION lpProcessInformation)
{
  WCHAR cmd[4096];
  GetSystemWindowsDirectoryW(cmd,4096);
  PathAppendW(cmd,L"SuRun.exe");
  PathQuoteSpacesW(cmd);
  wcscat(cmd,L" /TESTAUTOADMIN ");
  WCHAR* parms=(lpCommandLine && wcslen(lpCommandLine))?lpCommandLine:0;
  if(lpApplicationName)
  {
    WCHAR tmp[4096];
    if (parms)
    {
      //lpApplicationName and the first token of lpCommandLine may be the same
      //we need to check this:
      wcscpy(tmp,lpCommandLine);
      PathRemoveArgsW(tmp);
      PathUnquoteSpacesW(tmp);
      if (wcsicmp(tmp,lpApplicationName)==0)
        parms=PathGetArgsW(lpCommandLine);
    }
    wcscpy(tmp,lpApplicationName);
    PathQuoteSpacesW(tmp);
    wcscat(cmd,tmp);
    if (parms)
      wcscat(cmd,L" ");
  }
  if (parms)
    wcscat(cmd,parms);
  DWORD ExitCode=ERROR_ACCESS_DENIED;
  STARTUPINFOW si;
  PROCESS_INFORMATION pi;
  ZeroMemory(&si, sizeof(si));
  si.cb = sizeof(si);
  // Start the child process.
  if (CreateProcessW(NULL,cmd,NULL,NULL,FALSE,0,NULL,NULL,&si,&pi))
  {
    CloseHandle(pi.hThread );
    if(WaitForSingleObject(pi.hProcess,60000)==WAIT_OBJECT_0)
      GetExitCodeProcess(pi.hProcess,(DWORD*)&ExitCode);
    CloseHandle(pi.hProcess);
  }
  BOOL b=FALSE;
  if (ExitCode!=0)
  {
    DWORD cf=CREATE_SUSPENDED|dwCreationFlags;
    b=CreateProcessW(lpApplicationName,lpCommandLine,lpProcessAttributes,
        lpThreadAttributes,bInheritHandles,cf,lpEnvironment,
        lpCurrentDirectory,lpStartupInfo,lpProcessInformation);
    if (b)
    {
      //Process is suspended...
      InjectIATHook(lpProcessInformation->hProcess);
      //Resume main thread:
      if ((CREATE_SUSPENDED & dwCreationFlags)==0)
        ResumeThread(lpProcessInformation->hThread);
    }
  }
  return b;
}

CRITICAL_SECTION g_HookCs;

FARPROC WINAPI GetProcAddr(HMODULE hModule,LPCSTR lpProcName)
{
  char f[MAX_PATH]={0};
  GetModuleFileNameA(hModule,f,MAX_PATH);
  PathStripPathA(f);
  PROC p=DoHookFn(f,(char*)lpProcName);
  if(!p)
    p=GetProcAddress(hModule,lpProcName);;
  return p;
}

HMODULE WINAPI LoadLibA(LPCSTR lpLibFileName)
{
  EnterCriticalSection(&g_HookCs);
  HMODULE hMOD=LoadLibraryA(lpLibFileName);
  if(hMOD)
    HookModules();
  LeaveCriticalSection(&g_HookCs);
  return hMOD;
}

HMODULE WINAPI LoadLibW(LPCWSTR lpLibFileName)
{
  EnterCriticalSection(&g_HookCs);
  HMODULE hMOD=LoadLibraryW(lpLibFileName);
  if(hMOD)
    HookModules();
  LeaveCriticalSection(&g_HookCs);
  return hMOD;
}

HMODULE WINAPI LoadLibExA(LPCSTR lpLibFileName,HANDLE hFile,DWORD dwFlags)
{
  EnterCriticalSection(&g_HookCs);
  HMODULE hMOD=LoadLibraryExA(lpLibFileName,hFile,dwFlags);
  if(hMOD)
    HookModules();
  LeaveCriticalSection(&g_HookCs);
  return hMOD;
}

HMODULE WINAPI LoadLibExW(LPCWSTR lpLibFileName,HANDLE hFile,DWORD dwFlags)
{
  EnterCriticalSection(&g_HookCs);
  HMODULE hMOD=LoadLibraryExW(lpLibFileName,hFile,dwFlags);
  if(hMOD)
    HookModules();
  LeaveCriticalSection(&g_HookCs);
  return hMOD;
}

void LoadHooks()
{
  InitializeCriticalSection(&g_HookCs);
  EnterCriticalSection(&g_HookCs);
  HookModules();
  LeaveCriticalSection(&g_HookCs);
}

void UnloadHooks()
{
  EnterCriticalSection(&g_HookCs);
  UnHookModules();
  LeaveCriticalSection(&g_HookCs);
  DeleteCriticalSection(&g_HookCs);
}

