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
#include <LMCons.h>

#include <list>
#include <algorithm>
#include <iterator>

#include "../helpers.h"
#include "../IsAdmin.h"
#include "../UserGroups.h"
#include "../Service.h"
#include "../DBGTrace.h"
#include "SysMenuHook.h"

#pragma comment(lib,"Advapi32.lib")
#pragma comment(lib,"ShlWapi.lib")
#pragma comment(lib,"PSAPI.lib")

//Function Prototypes:
typedef HMODULE (WINAPI* lpLoadLibraryA)(LPCSTR);
typedef HMODULE (WINAPI* lpLoadLibraryW)(LPCWSTR);
typedef HMODULE (WINAPI* lpLoadLibraryExA)(LPCSTR,HANDLE,DWORD);
typedef HMODULE (WINAPI* lpLoadLibraryExW)(LPCWSTR,HANDLE,DWORD);
typedef FARPROC (WINAPI* lpGetProcAddress)(HMODULE,LPCSTR);
typedef BOOL (WINAPI* lpFreeLibrary)(HMODULE);
typedef VOID (WINAPI* lpFreeLibraryAndExitThread)(HMODULE,DWORD);
typedef BOOL (WINAPI* lpCreateProcessA)(LPCSTR,LPSTR,LPSECURITY_ATTRIBUTES,
                                        LPSECURITY_ATTRIBUTES,BOOL,DWORD,
                                        LPVOID,LPCSTR,LPSTARTUPINFOA,
                                        LPPROCESS_INFORMATION);
typedef BOOL (WINAPI* lpCreateProcessW)(LPCWSTR,LPWSTR,LPSECURITY_ATTRIBUTES,
                                         LPSECURITY_ATTRIBUTES,BOOL,DWORD,
                                         LPVOID,LPCWSTR,LPSTARTUPINFOW,
                                         LPPROCESS_INFORMATION);

//Forward decl:
BOOL WINAPI CreateProcA(LPCSTR,LPSTR,LPSECURITY_ATTRIBUTES,LPSECURITY_ATTRIBUTES,
                        BOOL,DWORD,LPVOID,LPCSTR,LPSTARTUPINFOA,LPPROCESS_INFORMATION);
BOOL WINAPI CreateProcW(LPCWSTR,LPWSTR,LPSECURITY_ATTRIBUTES,LPSECURITY_ATTRIBUTES,
                        BOOL,DWORD,LPVOID,LPCWSTR,LPSTARTUPINFOW,LPPROCESS_INFORMATION);

//BOOL WINAPI CreateProcWithLogonW(LPCWSTR,LPCWSTR,LPCWSTR,DWORD,LPCWSTR,LPWSTR,DWORD,
//                                 LPVOID,LPCWSTR,LPSTARTUPINFOW,LPPROCESS_INFORMATION);

HMODULE WINAPI LoadLibA(LPCSTR);
HMODULE WINAPI LoadLibW(LPCWSTR);
HMODULE WINAPI LoadLibExA(LPCSTR,HANDLE,DWORD);
HMODULE WINAPI LoadLibExW(LPCWSTR,HANDLE,DWORD);

FARPROC WINAPI GetProcAddr(HMODULE,LPCSTR);

BOOL WINAPI FreeLib(HMODULE);
VOID WINAPI FreeLibAndExitThread(HMODULE,DWORD);

typedef std::list<HMODULE> ModList;

int g_nHooked=0;
ModList g_ModList;

//Hook Descriptor
class CHookDescriptor
{
public:
  LPCSTR DllName;
  LPCSTR FuncName;
  PROC newFunc;
  PROC orgFunc;
  CHookDescriptor(LPCSTR Dll,LPCSTR Func,PROC nFunc)
  {
    DllName=Dll;
    FuncName=Func;
    newFunc=nFunc;
    orgFunc=GetProcAddress(GetModuleHandleA(DllName),FuncName);
  }
  PROC orgfn()
  {
    if (IsBadCodePtr(orgFunc))
      orgFunc=GetProcAddress(GetModuleHandleA(DllName),FuncName);
    return orgFunc;
  }
}; 

const CHookDescriptor hdt[]=
{
  //Standard Hooks: These must be implemented!
  CHookDescriptor("kernel32.dll","LoadLibraryA",(PROC)LoadLibA),
  CHookDescriptor("kernel32.dll","LoadLibraryW",(PROC)LoadLibW),
  CHookDescriptor("kernel32.dll","LoadLibraryExA",(PROC)LoadLibExA),
  CHookDescriptor("kernel32.dll","LoadLibraryExW",(PROC)LoadLibExW),
  CHookDescriptor("kernel32.dll","GetProcAddress",(PROC)GetProcAddr),
  CHookDescriptor("kernel32.dll","FreeLibrary",(PROC)FreeLib),
  CHookDescriptor("kernel32.dll","FreeLibraryAndExitThread",(PROC)FreeLibAndExitThread),
  //User Hooks:
  CHookDescriptor("kernel32.dll","CreateProcessA",(PROC)CreateProcA),
  CHookDescriptor("kernel32.dll","CreateProcessW",(PROC)CreateProcW),
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
PROC DoHookFn(char* DllName,char* ImpName,PROC* orgFN)
{
  if(IsBadReadPtr(DllName,1)||IsBadReadPtr(ImpName,1))
    return 0;
  if(*DllName && *ImpName)
    for(int i=0;i<countof(hdt);i++)
      if (stricmp(hdt[i].DllName,DllName)==0)
        if (stricmp(hdt[i].FuncName,ImpName)==0)
        {
          if(orgFN)
            *orgFN=hdt[i].orgFunc;
          return hdt[i].newFunc;
        }
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
  DWORD_PTR va=pNTH->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
  if(va==0) 
    return nHooked;
  PIMAGE_IMPORT_DESCRIPTOR pID = RelPtr(PIMAGE_IMPORT_DESCRIPTOR,hMod,va);
#ifdef _DEBUG
  char fmod[MAX_PATH]={0};
  {
    GetModuleFileNameA(0,fmod,MAX_PATH);
    PathStripPathA(fmod);
    strcat(fmod,": ");
    char* p=&fmod[strlen(fmod)];
    GetModuleFileNameA(hMod,p,MAX_PATH);
    PathStripPathA(p);
  }
  TRACExA("SuRunExt32.dll: HookIAT(%s[%x],%d)\n",fmod,hMod,bUnHook);
#endif _DEBUG
  for(;pID->Name;pID++) 
  {
    char* DllName=RelPtr(char*,hMod,pID->Name);
    if(DoHookDll(DllName))
    {
      PIMAGE_THUNK_DATA pOrgThunk=RelPtr(PIMAGE_THUNK_DATA,hMod,pID->OriginalFirstThunk);
      PIMAGE_THUNK_DATA pThunk=RelPtr(PIMAGE_THUNK_DATA,hMod,pID->FirstThunk);
      for(;(pOrgThunk->u1.Function)&&(pOrgThunk->u1.Function);pOrgThunk++,pThunk++)
        if ((pOrgThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG )!=IMAGE_ORDINAL_FLAG)
        {
          PIMAGE_IMPORT_BY_NAME pBN=RelPtr(PIMAGE_IMPORT_BY_NAME,hMod,pOrgThunk->u1.AddressOfData);
          PROC oldFunc=0;
          PROC newFunc = DoHookFn(DllName,(char*)pBN->Name,&oldFunc);
          if (newFunc 
            && ((!bUnHook) && (pThunk->u1.Function==(DWORD_PTR)oldFunc)
            ||( bUnHook  && (pThunk->u1.Function==(DWORD_PTR)newFunc)))
            )
          {
#ifdef _DEBUG
            TRACExA("SuRunExt32.dll: HookFunc(%s):%s,%s (%x->%x)\n",
              fmod,DllName,pBN->Name,oldFunc,newFunc);
#endif _DEBUG
            MEMORY_BASIC_INFORMATION mbi;
            if (VirtualQuery(&pThunk->u1.Function, &mbi, sizeof(MEMORY_BASIC_INFORMATION))!=0)
            {
              DWORD oldProt;
              if(VirtualProtect(mbi.BaseAddress, mbi.RegionSize, PAGE_READWRITE, &oldProt))
              {
                if (bUnHook)
                {
                  pThunk->u1.Function = (DWORD_PTR) oldFunc;
                  g_nHooked--;
                }else
                {
                  pThunk->u1.Function = (DWORD_PTR) newFunc;
                  g_nHooked++;
                }
                nHooked++;
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

//BOOL InjectIATHook(HANDLE hProc)
//{
//  HANDLE hThread=0;
//  //This does not work on Vista!
//  __try
//  {
//    //ToDo: GetProcAddress(GetModuleHandleA("Kernel32"),"LoadLibraryA"); does not work!
//    PROC pLoadLib=GetProcAddress(GetModuleHandleA("Kernel32"),"LoadLibraryA");
//    if(!pLoadLib)
//      return false;
//	  char DllName[MAX_PATH];
//	  if(!GetModuleFileNameA(l_hInst,DllName,MAX_PATH))
//		  return false;
//	  void* RmteName=VirtualAllocEx(hProc,NULL,sizeof(DllName),MEM_COMMIT,PAGE_READWRITE);
//	  if(RmteName==NULL)
//		  return false;
//	  WriteProcessMemory(hProc,RmteName,(void*)DllName,sizeof(DllName),NULL);
//    __try
//    {
//      hThread=CreateRemoteThread(hProc,NULL,0,(LPTHREAD_START_ROUTINE)pLoadLib,RmteName,0,NULL);
//    }__except(1)
//    {
//    }
//	  if(hThread!=NULL )
//    {
//      WaitForSingleObject(hThread,INFINITE);
//      CloseHandle(hThread);
//    }
//	  VirtualFreeEx(hProc,RmteName,sizeof(DllName),MEM_RELEASE);
//  }__except(1)
//  {
//  }
//  return hThread!=0;
//}

BOOL AutoSuRun(LPCWSTR lpApp,LPWSTR lpCmd,LPCWSTR lpCurDir,LPPROCESS_INFORMATION lppi)
{
  DWORD ExitCode=ERROR_ACCESS_DENIED;
  if(IsAdmin())
    return FALSE;
  {
    TCHAR User[UNLEN+GNLEN+2]={0};
    GetProcessUserName(GetCurrentProcessId(),User);
    if (!IsInSuRunners(User))
      return FALSE;
  }
  WCHAR cmd[4096];
  GetSystemWindowsDirectoryW(cmd,4096);
  PathAppendW(cmd,L"SuRun.exe");
  PathQuoteSpacesW(cmd);
  PPROCESS_INFORMATION ppi=(PPROCESS_INFORMATION)calloc(sizeof(PPROCESS_INFORMATION),1);
  wsprintf(&cmd[wcslen(cmd)],L" /QUIET /TESTAA %d %x ",GetCurrentProcessId(),ppi);
  WCHAR* parms=(lpCmd && wcslen(lpCmd))?lpCmd:0;
  if(lpApp)
  {
    WCHAR tmp[4096];
    if (parms)
      //lpApplicationName and the first token of lpCommandLine are the same
      //we need to check this:
      parms=PathGetArgsW(lpCmd);
    wcscpy(tmp,lpApp);
    PathQuoteSpacesW(tmp);
    wcscat(cmd,tmp);
    if (parms)
      wcscat(cmd,L" ");
  }
  if (parms)
    wcscat(cmd,parms);
  STARTUPINFOW si;
  PROCESS_INFORMATION pi;
  ZeroMemory(&si, sizeof(si));
  si.cb = sizeof(si);
  DBGTrace1("IATHook AutoSuRun(%s) test",cmd);
  // Start the child process.
  if (orgCreateProcessW(NULL,cmd,NULL,NULL,FALSE,0,NULL,lpCurDir,&si,&pi))
  {
    CloseHandle(pi.hThread);
    WaitForSingleObject(pi.hProcess,INFINITE);
    GetExitCodeProcess(pi.hProcess,(DWORD*)&ExitCode);
    CloseHandle(pi.hProcess);
    if (ExitCode==RETVAL_OK)
    {
      //return a valid PROCESS_INFORMATION!
      ppi->hProcess=OpenProcess(SYNCHRONIZE,false,ppi->dwProcessId);
      ppi->hThread=OpenThread(SYNCHRONIZE,false,ppi->dwThreadId);
      if(lppi)
        memmove(lppi,ppi,sizeof(PROCESS_INFORMATION));
      DBGTrace5("IATHook AutoSuRun(%s) success! PID=%d (h=%x); TID=%d (h=%x)",
        cmd,ppi->dwProcessId,ppi->hProcess,ppi->dwThreadId,ppi->hThread);
    }
    free(ppi);
  }
  SetLastError((ExitCode==RETVAL_OK)?NOERROR:ERROR_ACCESS_DENIED);
  return (ExitCode==RETVAL_OK)||(ExitCode==RETVAL_ACCESSDENIED);
}

BOOL WINAPI CreateProcA(LPCSTR lpApplicationName,LPSTR lpCommandLine,
    LPSECURITY_ATTRIBUTES lpProcessAttributes,LPSECURITY_ATTRIBUTES lpThreadAttributes,
    BOOL bInheritHandles,DWORD dwCreationFlags,LPVOID lpEnvironment,
    LPCSTR lpCurrentDirectory,LPSTARTUPINFOA lpStartupInfo,
    LPPROCESS_INFORMATION lpProcessInformation)
{
  BOOL b=FALSE;
  if (!AutoSuRun(CAToWStr(lpApplicationName),CAToWStr(lpCommandLine),
    CAToWStr(lpCurrentDirectory),lpProcessInformation))
  {
    DWORD cf=CREATE_SUSPENDED|dwCreationFlags;
    b=orgCreateProcessA(lpApplicationName,lpCommandLine,lpProcessAttributes,
        lpThreadAttributes,bInheritHandles,cf,lpEnvironment,
        lpCurrentDirectory,lpStartupInfo,lpProcessInformation);
    if (b)
    {
      //Process is suspended...
      //InjectIATHook(lpProcessInformation->hProcess);
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
  BOOL b=FALSE;
  if (!AutoSuRun(lpApplicationName,lpCommandLine,lpCurrentDirectory,lpProcessInformation))
  {
    DWORD cf=CREATE_SUSPENDED|dwCreationFlags;
    b=orgCreateProcessW(lpApplicationName,lpCommandLine,lpProcessAttributes,
        lpThreadAttributes,bInheritHandles,cf,lpEnvironment,
        lpCurrentDirectory,lpStartupInfo,lpProcessInformation);
    if (b)
    {
      //Process is suspended...
      //InjectIATHook(lpProcessInformation->hProcess);
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
  PROC p=DoHookFn(f,(char*)lpProcName,0);
  if(!p)
    p=orgGetProcAddress(hModule,lpProcName);;
  return p;
}

HMODULE WINAPI LoadLibA(LPCSTR lpLibFileName)
{
  EnterCriticalSection(&g_HookCs);
  HMODULE hMOD=orgLoadLibraryA(lpLibFileName);
  if(hMOD)
    HookModules();
  LeaveCriticalSection(&g_HookCs);
  return hMOD;
}

HMODULE WINAPI LoadLibW(LPCWSTR lpLibFileName)
{
  EnterCriticalSection(&g_HookCs);
  HMODULE hMOD=orgLoadLibraryW(lpLibFileName);
  if(hMOD)
    HookModules();
  LeaveCriticalSection(&g_HookCs);
  return hMOD;
}

HMODULE WINAPI LoadLibExA(LPCSTR lpLibFileName,HANDLE hFile,DWORD dwFlags)
{
  EnterCriticalSection(&g_HookCs);
  HMODULE hMOD=orgLoadLibraryExA(lpLibFileName,hFile,dwFlags);
  if(hMOD)
    HookModules();
  LeaveCriticalSection(&g_HookCs);
  return hMOD;
}

HMODULE WINAPI LoadLibExW(LPCWSTR lpLibFileName,HANDLE hFile,DWORD dwFlags)
{
  EnterCriticalSection(&g_HookCs);
  HMODULE hMOD=orgLoadLibraryExW(lpLibFileName,hFile,dwFlags);
  if(hMOD)
    HookModules();
  LeaveCriticalSection(&g_HookCs);
  return hMOD;
}

BOOL WINAPI FreeLib(HMODULE hLibModule)
{
  if (hLibModule==l_hInst)
    return true;
  return orgFreeLibrary(hLibModule);
}

VOID WINAPI FreeLibAndExitThread(HMODULE hLibModule,DWORD dwExitCode)
{
  if (hLibModule!=l_hInst)
    orgFreeLibraryAndExitThread(hLibModule,dwExitCode);
  else
    ExitThread(dwExitCode);
}

DWORD WINAPI InitHookProc(void* p)
{
  //The DLL must not be unloaded while the process is running!
  //Increment lock count!
  char f[MAX_PATH];
  GetModuleFileNameA(l_hInst,f,MAX_PATH);
  orgLoadLibraryA(f);
  EnterCriticalSection(&g_HookCs);
  HookModules();
  LeaveCriticalSection(&g_HookCs);
  return 0;
}

void LoadHooks()
{
  InitializeCriticalSection(&g_HookCs);
  CreateThread(0,0,InitHookProc,0,0,0);
}

void UnloadHooks()
{
#ifdef _DEBUG
  char fmod[MAX_PATH]={0};
  {
    GetModuleFileNameA(0,fmod,MAX_PATH);
    PathStripPathA(fmod);
    strcat(fmod,": ");
    char* p=&fmod[strlen(fmod)];
    GetModuleFileNameA(l_hInst,p,MAX_PATH);
    PathStripPathA(p);
  }
  TRACExA("SuRunExt32.dll: %s WARNING: Unloading IAT Hooks!\n",fmod);
#endif _DEBUG
  EnterCriticalSection(&g_HookCs);
  UnHookModules();
  LeaveCriticalSection(&g_HookCs);
  DeleteCriticalSection(&g_HookCs);
}

