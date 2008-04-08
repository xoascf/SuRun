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
#include <Psapi.h>
#include <ShlWapi.h>
#include <LMCons.h>

#include <list>
#include <algorithm>
#include <iterator>

#include "../Setup.h"
#include "../helpers.h"
#include "../IsAdmin.h"
#include "../UserGroups.h"
#include "../Service.h"
#include "../DBGTrace.h"

#pragma comment(lib,"Advapi32.lib")
#pragma comment(lib,"ShlWapi.lib")
#pragma comment(lib,"PSAPI.lib")

extern HINSTANCE l_hInst;

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

HMODULE WINAPI LoadLibA(LPCSTR);
HMODULE WINAPI LoadLibW(LPCWSTR);
HMODULE WINAPI LoadLibExA(LPCSTR,HANDLE,DWORD);
HMODULE WINAPI LoadLibExW(LPCWSTR,HANDLE,DWORD);

FARPROC WINAPI GetProcAddr(HMODULE,LPCSTR);

BOOL WINAPI FreeLib(HMODULE);
VOID WINAPI FreeLibAndExitThread(HMODULE,DWORD);

typedef std::list<HMODULE> ModList;

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
}; 

//Standard Hooks: These must be implemented!
static CHookDescriptor hkLdLibA  ("kernel32.dll","LoadLibraryA",(PROC)LoadLibA);
static CHookDescriptor hkLdLibW  ("kernel32.dll","LoadLibraryW",(PROC)LoadLibW);
static CHookDescriptor hkLdLibXA ("kernel32.dll","LoadLibraryExA",(PROC)LoadLibExA);
static CHookDescriptor hkLdLibXW ("kernel32.dll","LoadLibraryExW",(PROC)LoadLibExW);
static CHookDescriptor hkGetPAdr ("kernel32.dll","GetProcAddress",(PROC)GetProcAddr);
static CHookDescriptor hkFreeLib ("kernel32.dll","FreeLibrary",(PROC)FreeLib);
static CHookDescriptor hkFrLibXT ("kernel32.dll","FreeLibraryAndExitThread",(PROC)FreeLibAndExitThread);
//User Hooks:
static CHookDescriptor hkCrProcA ("kernel32.dll","CreateProcessA",(PROC)CreateProcA);
static CHookDescriptor hkCrProcW ("kernel32.dll","CreateProcessW",(PROC)CreateProcW);

static CHookDescriptor* hdt[]=
{
  &hkLdLibA,
  &hkLdLibW, 
  &hkLdLibXA, 
  &hkLdLibXW, 
  &hkGetPAdr, 
  &hkFreeLib, 
  &hkFrLibXT, 
  &hkCrProcA, 
  &hkCrProcW
};

//relative pointers in PE images
#define RelPtr(_T,pe,rpt) (_T)( (DWORD_PTR)(pe)+(DWORD_PTR)(rpt))

//returns true if DllName is one to be hooked up
BOOL DoHookDll(char* DllName)
{
  for(int i=0;i<countof(hdt);i++)
    if (stricmp(hdt[i]->DllName,DllName)==0)
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
      if (stricmp(hdt[i]->DllName,DllName)==0)
        if (stricmp(hdt[i]->FuncName,ImpName)==0)
          return hdt[i]->newFunc;
  return false;
}

DWORD HookIAT(HMODULE hMod)
{
  DWORD nHooked=0;
  if(hMod==l_hInst)
    return nHooked;
  {
    char f0[MAX_PATH]={0};
    char f1[MAX_PATH]={0};
    GetModuleFileNameA(hMod,f0,MAX_PATH);
    GetModuleFileNameA(l_hInst,f0,MAX_PATH);
    if (stricmp(f0,f1)==0)
      return nHooked;
  }
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
//  char fmod[MAX_PATH]={0};
//  {
//    GetModuleFileNameA(0,fmod,MAX_PATH);
//    PathStripPathA(fmod);
//    strcat(fmod,": ");
//    char* p=&fmod[strlen(fmod)];
//    GetModuleFileNameA(hMod,p,MAX_PATH);
//    PathStripPathA(p);
//  }
//  TRACExA("SuRunExt32.dll: HookIAT(%s[%x])\n",fmod,hMod);
#endif _DEBUG
  for(;pID->Name;pID++) 
  {
    char* DllName=RelPtr(char*,hMod,pID->Name);
    if(DoHookDll(DllName))
    {
      PIMAGE_THUNK_DATA pOrgThunk=RelPtr(PIMAGE_THUNK_DATA,hMod,pID->OriginalFirstThunk);
      PIMAGE_THUNK_DATA pThunk=RelPtr(PIMAGE_THUNK_DATA,hMod,pID->FirstThunk);
      for(;(pOrgThunk->u1.Function)&&(pOrgThunk->u1.Function);pOrgThunk++,pThunk++)
        if ((pOrgThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG )==0)
        {
          PIMAGE_IMPORT_BY_NAME pBN=RelPtr(PIMAGE_IMPORT_BY_NAME,hMod,pOrgThunk->u1.AddressOfData);
          PROC newFunc = DoHookFn(DllName,(char*)pBN->Name);
          if (newFunc && (pThunk->u1.Function!=(DWORD_PTR)newFunc))
          {
#ifdef _DEBUG
//            TRACExA("SuRunExt32.dll: HookFunc(%s):%s,%s (->%x)\n",
//              fmod,DllName,pBN->Name,newFunc);
#endif _DEBUG
            __try
            {
              MEMORY_BASIC_INFORMATION mbi;
              if (VirtualQuery(&pThunk->u1.Function, &mbi, sizeof(MEMORY_BASIC_INFORMATION))!=0)
              {
                DWORD oldProt=PAGE_READWRITE;
                if(VirtualProtect(mbi.BaseAddress, mbi.RegionSize,PAGE_EXECUTE_WRITECOPY,&oldProt))
                {
                  pThunk->u1.Function = (DWORD_PTR)newFunc;
                  VirtualProtect(mbi.BaseAddress, mbi.RegionSize, oldProt, &oldProt);
                  nHooked++;
                }
              }
            }
            __except(1)
            {
            }
          }
        }
    }//if(DoHookDll(DllName))
  }//for(;pID->Name;pID++) 
  return nHooked;
}

DWORD HookModules()
{
  if (!GetUseIATHook)
    return 0;
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
      nHooked+=HookIAT(*it);
    //merge new hModules to list
    g_ModList.merge(newMods);
    free(hMod);
  }
  CloseHandle(hProc);
  return nHooked;
}

CRITICAL_SECTION g_HookCs;

//For IAT-Hook IShellExecHook failed to start g_LastFailedCmd
extern LPTSTR g_LastFailedCmd; //defined in SuSunExt.cpp

DWORD TestAutoSuRunW(LPCWSTR lpApp,LPWSTR lpCmd,LPCWSTR lpCurDir,
                     DWORD dwCreationFlags,LPPROCESS_INFORMATION lppi)
{
  if (!GetUseIATHook)
    return RETVAL_SX_NOTINLIST;
  DWORD ExitCode=ERROR_ACCESS_DENIED;
  if(IsAdmin())
    return RETVAL_SX_NOTINLIST;
  {
    TCHAR User[UNLEN+GNLEN+2]={0};
    GetProcessUserName(GetCurrentProcessId(),User);
    if (!IsInSuRunners(User))
      return RETVAL_SX_NOTINLIST;
  }
  EnterCriticalSection(&g_HookCs);
  static TCHAR CurDir[4096];
  zero(CurDir);
  if (lpCurDir && *lpCurDir)
    _tcscpy(CurDir,lpCurDir);
  else
    GetCurrentDirectory(countof(CurDir),CurDir);
  WCHAR* parms=(lpCmd && wcslen(lpCmd))?lpCmd:0;
  static WCHAR cmd[4096];
  zero(cmd);
  if(lpApp)
  {
    wcscat(cmd,lpApp);
    PathQuoteSpacesW(cmd);
    if (parms)
      //lpApplicationName and the first token of lpCommandLine are the same
      //we need to check this:
      parms=PathGetArgsW(lpCmd);
    if (parms)
      wcscat(cmd,L" ");
  }
  if (parms)
    wcscat(cmd,parms);
  PROCESS_INFORMATION rpi={0};
  //ToDo: Directly write to service pipe!
  {
    static WCHAR tmp[4096];
    zero(tmp);
    ResolveCommandLine(cmd,CurDir,tmp);
    //Exit if ShellExecHook failed on "tmp"
    if(g_LastFailedCmd)
    {
      BOOL bExitNow=_tcsicmp(tmp,g_LastFailedCmd)==0;
      free(g_LastFailedCmd);
      g_LastFailedCmd=0;
      if(bExitNow)
        return LeaveCriticalSection(&g_HookCs),RETVAL_SX_NOTINLIST;  
    }
    GetSystemWindowsDirectoryW(cmd,countof(cmd));
    PathAppendW(cmd,L"SuRun.exe");
    PathQuoteSpacesW(cmd);
    if (_wcsnicmp(cmd,tmp,wcslen(cmd))==0)
      //Never start SuRun administrative
      return LeaveCriticalSection(&g_HookCs),RETVAL_SX_NOTINLIST;
    wsprintf(&cmd[wcslen(cmd)],L" /QUIET /TESTAA %d %x %s",
      GetCurrentProcessId(),&rpi,tmp);
  }
  //CTimeLog l(L"IATHook TestAutoSuRun(%s)",lpCmd);
  static STARTUPINFOW si;
  zero(si);
  static PROCESS_INFORMATION pi;
  zero(pi);
  si.cb = sizeof(si);
  // Start the child process.
  //DBGTrace1("IATHook AutoSuRun(%s) test",cmd);
  if (((lpCreateProcessW)hkCrProcW.orgFunc)
    (NULL,cmd,NULL,NULL,FALSE,0,NULL,CurDir,&si,&pi))
  {
    CloseHandle(pi.hThread);
    WaitForSingleObject(pi.hProcess,INFINITE);
    GetExitCodeProcess(pi.hProcess,(DWORD*)&ExitCode);
    CloseHandle(pi.hProcess);
    if (ExitCode==RETVAL_OK)
    {
      //return a valid PROCESS_INFORMATION!
      rpi.hProcess=OpenProcess(SYNCHRONIZE,false,rpi.dwProcessId);
      rpi.hThread=OpenThread(SYNCHRONIZE,false,rpi.dwThreadId);
      if(lppi)
        memmove(lppi,&rpi,sizeof(PROCESS_INFORMATION));
      DBGTrace5("IATHook AutoSuRun(%s) success! PID=%d (h=%x); TID=%d (h=%x)",
        cmd,rpi.dwProcessId,rpi.hProcess,
        rpi.dwThreadId,rpi.hThread);
    }
  }
  LeaveCriticalSection(&g_HookCs);
  return ExitCode;
}

DWORD TestAutoSuRunA(LPCSTR lpApp,LPSTR lpCmd,LPCSTR lpCurDir,
                     DWORD dwCreationFlags,LPPROCESS_INFORMATION lppi)
{
  EnterCriticalSection(&g_HookCs);
  static WCHAR wApp[4096];
  zero(wApp);
  MultiByteToWideChar(CP_ACP,0,lpApp,-1,wApp,(int)4096);
  static WCHAR wCmd[4096];
  zero(wCmd);
  MultiByteToWideChar(CP_ACP,0,lpCmd,-1,wCmd,(int)4096);
  static WCHAR wCurDir[4096];
  zero(wCurDir);
  MultiByteToWideChar(CP_ACP,0,lpCurDir,-1,wCurDir,(int)4096);
  DWORD dwRet=TestAutoSuRunW(wApp,wCmd,wCurDir,dwCreationFlags,lppi);
  LeaveCriticalSection(&g_HookCs);
  return dwRet;
}

BOOL WINAPI CreateProcA(LPCSTR lpApplicationName,LPSTR lpCommandLine,
    LPSECURITY_ATTRIBUTES lpProcessAttributes,LPSECURITY_ATTRIBUTES lpThreadAttributes,
    BOOL bInheritHandles,DWORD dwCreationFlags,LPVOID lpEnvironment,
    LPCSTR lpCurrentDirectory,LPSTARTUPINFOA lpStartupInfo,
    LPPROCESS_INFORMATION lpProcessInformation)
{
  DWORD tas=TestAutoSuRunA(lpApplicationName,lpCommandLine,lpCurrentDirectory,
                           dwCreationFlags,lpProcessInformation);
  if(tas==RETVAL_OK)
    return SetLastError(NOERROR),TRUE;
  if(tas==RETVAL_CANCELLED)
    return SetLastError(ERROR_ACCESS_DENIED),FALSE;
  return ((lpCreateProcessA)hkCrProcA.orgFunc)(lpApplicationName,lpCommandLine,
      lpProcessAttributes,lpThreadAttributes,bInheritHandles,dwCreationFlags,
      lpEnvironment,lpCurrentDirectory,lpStartupInfo,lpProcessInformation);
}

BOOL WINAPI CreateProcW(LPCWSTR lpApplicationName,LPWSTR lpCommandLine,
    LPSECURITY_ATTRIBUTES lpProcessAttributes,LPSECURITY_ATTRIBUTES lpThreadAttributes,
    BOOL bInheritHandles,DWORD dwCreationFlags,LPVOID lpEnvironment,
    LPCWSTR lpCurrentDirectory,LPSTARTUPINFOW lpStartupInfo,
    LPPROCESS_INFORMATION lpProcessInformation)
{
  DWORD tas=TestAutoSuRunW(lpApplicationName,lpCommandLine,lpCurrentDirectory,
                           dwCreationFlags,lpProcessInformation);
  if(tas==RETVAL_OK)
    return SetLastError(NOERROR),TRUE;
  if(tas==RETVAL_CANCELLED)
    return SetLastError(ERROR_ACCESS_DENIED),FALSE;
  return ((lpCreateProcessW)hkCrProcW.orgFunc)(lpApplicationName,lpCommandLine,
      lpProcessAttributes,lpThreadAttributes,bInheritHandles,dwCreationFlags,
      lpEnvironment,lpCurrentDirectory,lpStartupInfo,lpProcessInformation);
}

FARPROC WINAPI GetProcAddr(HMODULE hModule,LPCSTR lpProcName)
{
  char f[MAX_PATH]={0};
  GetModuleFileNameA(hModule,f,MAX_PATH);
  PathStripPathA(f);
  PROC p=DoHookFn(f,(char*)lpProcName);
  SetLastError(NOERROR);
  if(!p)
    p=((lpGetProcAddress)hkGetPAdr.orgFunc)(hModule,lpProcName);;
  return p;
}

HMODULE WINAPI LoadLibA(LPCSTR lpLibFileName)
{
  EnterCriticalSection(&g_HookCs);
  HMODULE hMOD=((lpLoadLibraryA)hkLdLibA.orgFunc)(lpLibFileName);
  DWORD dwe=GetLastError();
  if(hMOD)
    HookModules();
  LeaveCriticalSection(&g_HookCs);
  SetLastError(dwe);
  return hMOD;
}

HMODULE WINAPI LoadLibW(LPCWSTR lpLibFileName)
{
  EnterCriticalSection(&g_HookCs);
  HMODULE hMOD=((lpLoadLibraryW)hkLdLibW.orgFunc)(lpLibFileName);
  DWORD dwe=GetLastError();
  if(hMOD)
    HookModules();
  LeaveCriticalSection(&g_HookCs);
  SetLastError(dwe);
  return hMOD;
}

HMODULE WINAPI LoadLibExA(LPCSTR lpLibFileName,HANDLE hFile,DWORD dwFlags)
{
  EnterCriticalSection(&g_HookCs);
  HMODULE hMOD=((lpLoadLibraryExA)hkLdLibXA.orgFunc)(lpLibFileName,hFile,dwFlags);
  DWORD dwe=GetLastError();
  if(hMOD)
    HookModules();
  LeaveCriticalSection(&g_HookCs);
  SetLastError(dwe);
  return hMOD;
}

HMODULE WINAPI LoadLibExW(LPCWSTR lpLibFileName,HANDLE hFile,DWORD dwFlags)
{
  EnterCriticalSection(&g_HookCs);
  DWORD dwe=GetLastError();
  HMODULE hMOD=((lpLoadLibraryExW)hkLdLibXW.orgFunc)(lpLibFileName,hFile,dwFlags);
  if(hMOD)
    HookModules();
  LeaveCriticalSection(&g_HookCs);
  SetLastError(dwe);
  return hMOD;
}

BOOL WINAPI FreeLib(HMODULE hLibModule)
{
  //The DLL must not be unloaded while the process is running!
  if (hLibModule==l_hInst)
  {
#ifdef _DEBUG
//    char fmod[MAX_PATH]={0};
//    {
//      GetModuleFileNameA(0,fmod,MAX_PATH);
//      PathStripPathA(fmod);
//      strcat(fmod,": ");
//      char* p=&fmod[strlen(fmod)];
//      GetModuleFileNameA(hLibModule,p,MAX_PATH);
//      PathStripPathA(p);
//    }
//    TRACExA("SuRunExt32.dll: BLOCKING FreeLibrary (%s[%x])---------------------------------\n",fmod,hLibModule);
#endif _DEBUG
    SetLastError(NOERROR);
    return true;
  }
  SetLastError(NOERROR);
  EnterCriticalSection(&g_HookCs);
  BOOL bRet=((lpFreeLibrary)hkFreeLib.orgFunc)(hLibModule);
  LeaveCriticalSection(&g_HookCs);
  return bRet;
}

VOID WINAPI FreeLibAndExitThread(HMODULE hLibModule,DWORD dwExitCode)
{
  //The DLL must not be unloaded while the process is running!
  if (hLibModule!=l_hInst)
  {
    EnterCriticalSection(&g_HookCs);
    LeaveCriticalSection(&g_HookCs);
    ((lpFreeLibraryAndExitThread)hkFrLibXT.orgFunc)(hLibModule,dwExitCode);
    return;
  }
#ifdef _DEBUG
//  char fmod[MAX_PATH]={0};
//  {
//    GetModuleFileNameA(0,fmod,MAX_PATH);
//    PathStripPathA(fmod);
//    strcat(fmod,": ");
//    char* p=&fmod[strlen(fmod)];
//    GetModuleFileNameA(hLibModule,p,MAX_PATH);
//    PathStripPathA(p);
//  }
//  TRACExA("SuRunExt32.dll: BLOCKING FreeLibAndExitThread (%s[%x])---------------------------------\n",fmod,hLibModule);
#endif _DEBUG
  SetLastError(NOERROR);
  ExitThread(dwExitCode);
}

BOOL g_IATInit=FALSE;
DWORD WINAPI InitHookProc(void* p)
{
  if (g_IATInit)
    return 0;
  InitializeCriticalSection(&g_HookCs);
  g_IATInit=TRUE;
  if (!GetUseIATHook)
    return 0;
  EnterCriticalSection(&g_HookCs);
  HookModules();
  LeaveCriticalSection(&g_HookCs);
  return 0;
}

void LoadHooks()
{
  //CreateThread(0,0,InitHookProc,0,0,0);
  InitHookProc(0);
}

void UnloadHooks()
{
  if (!g_IATInit)
    return;
  //Do not unload the hooks, but wait for the Critical Section
  EnterCriticalSection(&g_HookCs);
  LeaveCriticalSection(&g_HookCs);
  DeleteCriticalSection(&g_HookCs);
}

