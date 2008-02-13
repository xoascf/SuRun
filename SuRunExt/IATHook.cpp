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

#include <list>
#include <algorithm>
#include <iterator>

#include "../helpers.h"
#include "../DBGTrace.h"
#include "SysMenuHook.h"

#pragma comment(lib,"Advapi32.lib")
#pragma comment(lib,"PSAPI.lib")

//Forward decl:
BOOL WINAPI CreateProcA(LPCSTR,LPSTR,LPSECURITY_ATTRIBUTES,LPSECURITY_ATTRIBUTES,
                        BOOL,DWORD,LPVOID,LPCSTR,LPSTARTUPINFOA,LPPROCESS_INFORMATION);
BOOL WINAPI CreateProcW(LPCWSTR,LPWSTR,LPSECURITY_ATTRIBUTES,LPSECURITY_ATTRIBUTES,
                        BOOL,DWORD,LPVOID,LPCWSTR,LPSTARTUPINFOW,LPPROCESS_INFORMATION);

BOOL WINAPI CreateProcWithLogonW(LPCWSTR,LPCWSTR,LPCWSTR,DWORD,LPCWSTR,LPWSTR,DWORD,
                                 LPVOID,LPCWSTR,LPSTARTUPINFOW,LPPROCESS_INFORMATION);

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
  {"kernel32.dll","CreateProcessW",(PROC)CreateProcW},
  {"advapi32.dll","CreateProcessWithLogonW",(PROC)CreateProcWithLogonW},
};

//relative pointers in PE images
#define RelPtr(_T,pe,rpt) (_T)( (DWORD)(pe)+(DWORD)(rpt))

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
  if (ImpName && *ImpName)
    for(int i=0;i<countof(hdt);i++)
      if (stricmp(hdt[i].DllName,DllName)==0)
        if (stricmp(hdt[i].FuncName,ImpName)==0)
          return hdt[i].newFunc;
  return false;
}

DWORD HookIAT(HMODULE hMod,BOOL bUnHook)
{
  if(hMod==l_hInst)
    return 0;
  // check "MZ" and DOS Header size
  if(IsBadReadPtr(hMod, sizeof(IMAGE_DOS_HEADER))
    || (((PIMAGE_DOS_HEADER)hMod)->e_magic != IMAGE_DOS_SIGNATURE))
    return 0;
  // check "PE" and DOS Header size
  PIMAGE_NT_HEADERS pNTH = RelPtr(PIMAGE_NT_HEADERS,hMod,((PIMAGE_DOS_HEADER)hMod)->e_lfanew);
  if(IsBadReadPtr(pNTH, sizeof(IMAGE_NT_HEADERS)) ||(pNTH->Signature != IMAGE_NT_SIGNATURE))
    return 0;
  //patch IAT
  PIMAGE_IMPORT_DESCRIPTOR pID = RelPtr(PIMAGE_IMPORT_DESCRIPTOR,hMod,
    pNTH->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
  if((void*)pID == (void*)pNTH) 
    return 0;
  for(;pID->Name;pID++) 
  {
    char* DllName=RelPtr(char*,hMod,pID->Name);
    if(DoHookDll(DllName))
    {
      PIMAGE_THUNK_DATA pThunk=RelPtr(PIMAGE_THUNK_DATA,hMod,pID->FirstThunk);
      for(;pThunk->u1.Function;pThunk++)
        if ((pThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG )!=IMAGE_ORDINAL_FLAG)
        {
          PIMAGE_IMPORT_BY_NAME pBN=RelPtr(PIMAGE_IMPORT_BY_NAME,hMod,pThunk->u1.AddressOfData);
          PROC newFunc = DoHookFn(RelPtr(char*,hMod,pID->Name),(char*)pBN->Name);
          if (newFunc 
            && ((!bUnHook) && (pThunk->u1.Function!=(DWORD)newFunc)
            ||( bUnHook  && (pThunk->u1.Function==(DWORD)newFunc)))
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
                      break;
                    }
                }else
                {
                  //add Data to g_HookList for UnHook
                  HOOKDATA hd={hMod,pThunk->u1.Function,newFunc};
                  g_HookList.push_back(hd);
                  pThunk->u1.Function = (DWORD) newFunc;
                }
              }
              VirtualProtect(mbi.BaseAddress, mbi.RegionSize, oldProt, &oldProt);
            }
          }
        }
    }
  }
  return 0;
}

DWORD HookModules()
{
  HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS,TRUE,GetCurrentProcessId());
  if (!hProc)
    return 0;
  DWORD Siz=0;
  EnumProcessModules(hProc,0,0,&Siz);
  HMODULE* hMod=(HMODULE*)malloc(Siz);
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
      HookIAT(*it,false);
    //merge new hModules to list
    g_ModList.merge(newMods);
    free(hMod);
  }
  CloseHandle(hProc);
  return 0;
}

DWORD UnHookModules()
{
  //UnHook all hModules
  for(ModList::iterator it=g_ModList.begin();it!=g_ModList.end();++it)
    HookIAT(*it,TRUE);
  g_ModList.clear();
  return 0;
}

BOOL WINAPI CreateProcA(LPCSTR lpApplicationName,LPSTR lpCommandLine,
    LPSECURITY_ATTRIBUTES lpProcessAttributes,LPSECURITY_ATTRIBUTES lpThreadAttributes,
    BOOL bInheritHandles,DWORD dwCreationFlags,LPVOID lpEnvironment,
    LPCSTR lpCurrentDirectory,LPSTARTUPINFOA lpStartupInfo,
    LPPROCESS_INFORMATION lpProcessInformation)
{
  DBGTrace2("CreateProcessA-Hook(%s,%s);",
    lpApplicationName?CAToWStr(lpApplicationName):L"",
    lpCommandLine?CAToWStr(lpCommandLine):L"");
  return CreateProcessA(lpApplicationName,lpCommandLine,lpProcessAttributes,
    lpThreadAttributes,bInheritHandles,dwCreationFlags,lpEnvironment,
    lpCurrentDirectory,lpStartupInfo,lpProcessInformation);
}

BOOL WINAPI CreateProcW(LPCWSTR lpApplicationName,LPWSTR lpCommandLine,
    LPSECURITY_ATTRIBUTES lpProcessAttributes,LPSECURITY_ATTRIBUTES lpThreadAttributes,
    BOOL bInheritHandles,DWORD dwCreationFlags,LPVOID lpEnvironment,
    LPCWSTR lpCurrentDirectory,LPSTARTUPINFOW lpStartupInfo,
    LPPROCESS_INFORMATION lpProcessInformation)
{
  DBGTrace2("CreateProcessW-Hook(%s,%s);",
    lpApplicationName?lpApplicationName:L"",lpCommandLine?lpCommandLine:L"");
  return CreateProcessW(lpApplicationName,lpCommandLine,lpProcessAttributes,
    lpThreadAttributes,bInheritHandles,dwCreationFlags,lpEnvironment,
    lpCurrentDirectory,lpStartupInfo,lpProcessInformation);
}

BOOL WINAPI CreateProcWithLogonW(LPCWSTR lpUsername,LPCWSTR lpDomain,LPCWSTR lpPassword,
    DWORD dwLogonFlags,LPCWSTR lpApplicationName,LPWSTR lpCommandLine,DWORD dwCreationFlags,
    LPVOID lpEnvironment,LPCWSTR lpCurrentDirectory,LPSTARTUPINFOW lpStartupInfo,
    LPPROCESS_INFORMATION lpProcessInformation)
{
  DWORD cf=CREATE_SUSPENDED|dwCreationFlags;
  BOOL b=CreateProcessWithLogonW(lpUsername,lpDomain,lpPassword,dwLogonFlags,
    lpApplicationName,lpCommandLine,cf,lpEnvironment,lpCurrentDirectory,
    lpStartupInfo,lpProcessInformation);
  if (b)
  {
    //Process is suspended...

    //Resume main thread:
    if ((CREATE_SUSPENDED & dwCreationFlags)==0)
      ResumeThread(lpProcessInformation->hThread);
  }
  return b;
}


CRITICAL_SECTION g_HookCs;

FARPROC WINAPI GetProcAddr(HMODULE hModule,LPCSTR lpProcName)
{
  char f[MAX_PATH]={0};
  GetModuleFileNameA(hModule,f,MAX_PATH);
  PROC p=DoHookFn(f,(char*)lpProcName);
  if(!p)
    p=GetProcAddress(hModule,lpProcName);;
  DBGTrace4("GetProcAddress(%x(%s),%s)==%x",hModule,CAToWStr(f),CAToWStr(lpProcName),p);
  return p;
}

HMODULE WINAPI LoadLibA(LPCSTR lpLibFileName)
{
  EnterCriticalSection(&g_HookCs);
  HMODULE hMOD=LoadLibraryA(lpLibFileName);
  if(hMOD)
    HookModules();
  LeaveCriticalSection(&g_HookCs);
  DBGTrace2("LoadLibA(%s)==%x",CAToWStr(lpLibFileName),hMOD);
  return hMOD;
}

HMODULE WINAPI LoadLibW(LPCWSTR lpLibFileName)
{
  EnterCriticalSection(&g_HookCs);
  HMODULE hMOD=LoadLibraryW(lpLibFileName);
  if(hMOD)
    HookModules();
  LeaveCriticalSection(&g_HookCs);
  DBGTrace2("LoadLibW(%s)==%x",lpLibFileName,hMOD);
  return hMOD;
}

HMODULE WINAPI LoadLibExA(LPCSTR lpLibFileName,HANDLE hFile,DWORD dwFlags)
{
  EnterCriticalSection(&g_HookCs);
  HMODULE hMOD=LoadLibraryExA(lpLibFileName,hFile,dwFlags);
  if(hMOD)
    HookModules();
  LeaveCriticalSection(&g_HookCs);
  DBGTrace2("LoadLibExA(%s)==%x",CAToWStr(lpLibFileName),hMOD);
  return hMOD;
}

HMODULE WINAPI LoadLibExW(LPCWSTR lpLibFileName,HANDLE hFile,DWORD dwFlags)
{
  EnterCriticalSection(&g_HookCs);
  HMODULE hMOD=LoadLibraryExW(lpLibFileName,hFile,dwFlags);
  if(hMOD)
    HookModules();
  LeaveCriticalSection(&g_HookCs);
  DBGTrace2("LoadLibExW(%s)==%x",lpLibFileName,hMOD);
  return hMOD;
}

void LoadHooks()
{
  InitializeCriticalSection(&g_HookCs);
  HookModules();
}

void UnloadHooks()
{
  EnterCriticalSection(&g_HookCs);
  UnHookModules();
  LeaveCriticalSection(&g_HookCs);
  DeleteCriticalSection(&g_HookCs);
}

