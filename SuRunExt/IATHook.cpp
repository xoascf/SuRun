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
#include <Tlhelp32.h>

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

extern DWORD     l_Groups;
#define     l_IsAdmin     ((l_Groups&IS_IN_ADMINS)!=0)
#define     l_IsSuRunner  ((l_Groups&IS_IN_SURUNNERS)!=0)

BOOL g_IATInit=FALSE;

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

typedef BOOL (WINAPI* lpCreateProcessAsUserA)(HANDLE,LPCSTR,LPSTR,
                                              LPSECURITY_ATTRIBUTES,
                                              LPSECURITY_ATTRIBUTES,BOOL,DWORD,
                                              LPVOID,LPCSTR,LPSTARTUPINFOA,
                                              LPPROCESS_INFORMATION);
typedef BOOL (WINAPI* lpCreateProcessAsUserW)(HANDLE,LPCWSTR,LPWSTR,
                                              LPSECURITY_ATTRIBUTES,
                                              LPSECURITY_ATTRIBUTES,BOOL,DWORD,
                                              LPVOID,LPCWSTR,LPSTARTUPINFOW,
                                              LPPROCESS_INFORMATION);

typedef BOOL (WINAPI* lpSwitchDesk)(HDESK);

//Forward decl:
BOOL WINAPI CreateProcA(LPCSTR,LPSTR,LPSECURITY_ATTRIBUTES,LPSECURITY_ATTRIBUTES,
                        BOOL,DWORD,LPVOID,LPCSTR,LPSTARTUPINFOA,LPPROCESS_INFORMATION);
BOOL WINAPI CreateProcW(LPCWSTR,LPWSTR,LPSECURITY_ATTRIBUTES,LPSECURITY_ATTRIBUTES,
                        BOOL,DWORD,LPVOID,LPCWSTR,LPSTARTUPINFOW,LPPROCESS_INFORMATION);

BOOL WINAPI CreatePAUA(HANDLE,LPCSTR,LPSTR,LPSECURITY_ATTRIBUTES,LPSECURITY_ATTRIBUTES,
                        BOOL,DWORD,LPVOID,LPCSTR,LPSTARTUPINFOA,LPPROCESS_INFORMATION);
BOOL WINAPI CreatePAUW(HANDLE,LPCWSTR,LPWSTR,LPSECURITY_ATTRIBUTES,LPSECURITY_ATTRIBUTES,
                        BOOL,DWORD,LPVOID,LPCWSTR,LPSTARTUPINFOW,LPPROCESS_INFORMATION);

HMODULE WINAPI LoadLibA(LPCSTR);
HMODULE WINAPI LoadLibW(LPCWSTR);
HMODULE WINAPI LoadLibExA(LPCSTR,HANDLE,DWORD);
HMODULE WINAPI LoadLibExW(LPCWSTR,HANDLE,DWORD);

FARPROC WINAPI GetProcAddr(HMODULE,LPCSTR);

BOOL WINAPI FreeLib(HMODULE);
VOID WINAPI FreeLibAndExitThread(HMODULE,DWORD);

BOOL WINAPI SwitchDesk(HDESK);

static lpGetProcAddress orgGPA=NULL;

typedef std::list<HMODULE> ModList;

ModList g_ModList;

//Hook Descriptor class
class CHookDescriptor
{
public:
  LPCSTR DllName;
  LPCSTR Win7DllName;
  LPCSTR FuncName;
  PROC newFunc;
  PROC orgFunc;
  CHookDescriptor(LPCSTR Dll,LPCSTR Win7Dll,LPCSTR Func,PROC nFunc)
  {
    DllName=Dll;
    Win7DllName=Win7Dll;
    FuncName=Func;
    newFunc=nFunc;
    orgFunc=0;
  }
  PROC OrgFunc()
  {
    if (orgFunc)
      return orgFunc;
    if (!orgGPA)
      orgGPA=GetProcAddr;
    if (Win7DllName)
      orgFunc=orgGPA(GetModuleHandleA(Win7DllName),FuncName);
    if (!orgFunc)
      orgFunc=orgGPA(GetModuleHandleA(DllName),FuncName);
    return orgFunc;
  }
}; 

//Standard Hooks: These must be implemented!
static CHookDescriptor hkLdLibA  ("kernel32.dll",NULL,"LoadLibraryA",(PROC)LoadLibA);
static CHookDescriptor hkLdLibW  ("kernel32.dll",NULL,"LoadLibraryW",(PROC)LoadLibW);
static CHookDescriptor hkLdLibXA ("kernel32.dll","api-ms-win-core-libraryloader-l1-1-0.dll","LoadLibraryExA",(PROC)LoadLibExA);
static CHookDescriptor hkLdLibXW ("kernel32.dll","api-ms-win-core-libraryloader-l1-1-0.dll","LoadLibraryExW",(PROC)LoadLibExW);
static CHookDescriptor hkGetPAdr ("kernel32.dll","api-ms-win-core-libraryloader-l1-1-0.dll","GetProcAddress",(PROC)GetProcAddr);
static CHookDescriptor hkFreeLib ("kernel32.dll","api-ms-win-core-libraryloader-l1-1-0.dll","FreeLibrary",(PROC)FreeLib);
static CHookDescriptor hkFrLibXT ("kernel32.dll","api-ms-win-core-libraryloader-l1-1-0.dll","FreeLibraryAndExitThread",(PROC)FreeLibAndExitThread);
//User Hooks:
static CHookDescriptor hkCrProcA ("kernel32.dll","api-ms-win-core-processthreads-l1-1-0.dll","CreateProcessA",(PROC)CreateProcA);
static CHookDescriptor hkCrProcW ("kernel32.dll","api-ms-win-core-processthreads-l1-1-0.dll","CreateProcessW",(PROC)CreateProcW);

static CHookDescriptor hkCrPAUA  ("advapi32.dll",NULL,"CreateProcessAsUserA",(PROC)CreatePAUA);
static CHookDescriptor hkCrPAUW  ("advapi32.dll","api-ms-win-core-processthreads-l1-1-0.dll","CreateProcessAsUserW",(PROC)CreatePAUW);

static CHookDescriptor hkSwDesk  ("user32.dll",NULL,"SwitchDesktop",(PROC)SwitchDesk);

//Functions that, if present in the IAT, cause the module to be hooked
static CHookDescriptor* need_hdt[]=
{
  &hkCrProcA, 
  &hkCrProcW,
  &hkCrPAUA, 
  &hkCrPAUW,
  &hkSwDesk,
};

//Functions that will be hooked
static CHookDescriptor* hdt[]=
{
  &hkLdLibA,
  &hkLdLibW, 
  &hkLdLibXA, 
  &hkLdLibXW, 
  &hkGetPAdr, //This hook caused Outlook 2007 with WindowsDesktopSearch to crash
  &hkFreeLib, 
  &hkFrLibXT, 
  &hkCrProcA, 
  &hkCrProcW,
  &hkCrPAUA, 
  &hkCrPAUW,
  &hkSwDesk,
};

//relative pointers in PE images
#define RelPtr(_T,pe,rpt) (_T)( (DWORD_PTR)(pe)+(DWORD_PTR)(rpt))

//returns true if DllName is one to be hooked up
BOOL DoHookDll(char* DllName)
{
  if(IsBadReadPtr(DllName,1))
    return FALSE;
  for(int i=0;i<countof(hdt);i++)
    if ((stricmp(hdt[i]->DllName,DllName)==0)
      ||(hdt[i]->Win7DllName && (stricmp(hdt[i]->Win7DllName,DllName)==0)))
      return true;
  return false;
}

//returns newFunc if DllName->ImpName is one to be hooked up
PROC DoHookFn(char* DllName,char* ImpName,PROC* orgFunc)
{
  if(IsBadReadPtr(DllName,1)||IsBadReadPtr(ImpName,1))
    return 0;
  if(*DllName && *ImpName)
    for(int i=0;i<countof(hdt);i++)
      if ((stricmp(hdt[i]->DllName,DllName)==0)
        ||(hdt[i]->Win7DllName && (stricmp(hdt[i]->Win7DllName,DllName)==0)))
        if (stricmp(hdt[i]->FuncName,ImpName)==0)
        {
          if(orgFunc)
            *orgFunc=hdt[i]->OrgFunc();
          return hdt[i]->newFunc;
        }
  return false;
}

PROC DoHookFn(char* DllName,PROC orgFunc)
{
  if(IsBadReadPtr(DllName,1)||IsBadReadPtr(orgFunc,1))
    return 0;
  if(*DllName)
    for(int i=0;i<countof(hdt);i++)
      if ((stricmp(hdt[i]->DllName,DllName)==0)
        ||(hdt[i]->Win7DllName && (stricmp(hdt[i]->Win7DllName,DllName)==0)))
        if (hdt[i]->OrgFunc()==orgFunc)
          return hdt[i]->newFunc;
  return false;
}

PROC GetOrgFn(char* DllName,char* ImpName)
{
  if(IsBadReadPtr(DllName,1)||IsBadReadPtr(ImpName,1))
    return 0;
  if(*DllName && *ImpName)
    for(int i=0;i<countof(hdt);i++)
      if ((stricmp(hdt[i]->DllName,DllName)==0)
        ||(hdt[i]->Win7DllName && (stricmp(hdt[i]->Win7DllName,DllName)==0)))
        if (stricmp(hdt[i]->FuncName,ImpName)==0)
          return hdt[i]->OrgFunc();
  return false;
}

//Detect if a module is using CreateProcess, if yes, it needs to be hooked
bool NeedHookFn(char* DllName,char* ImpName,void* orgFunc)
{
  if(IsBadReadPtr(DllName,1)||IsBadReadPtr(ImpName,1)||IsBadReadPtr(ImpName,1))
    return 0;
  if(*DllName && *ImpName)
    for(int i=0;i<countof(need_hdt);i++)
      if ((stricmp(need_hdt[i]->DllName,DllName)==0)
        ||(need_hdt[i]->Win7DllName && (stricmp(need_hdt[i]->Win7DllName,DllName)==0)))
        if (stricmp(need_hdt[i]->FuncName,ImpName)==0)
          return need_hdt[i]->OrgFunc()==orgFunc;
  return false;
}

DWORD HookIAT(HMODULE hMod,PIMAGE_IMPORT_DESCRIPTOR pID,bool bUnHook)
{
  DWORD nHooked=0;
#ifdef DoDBGTrace
//  char fmod[MAX_PATH]={0};
//  {
//    GetModuleFileNameA(0,fmod,MAX_PATH);
//    PathStripPathA(fmod);
//    strcat(fmod,": ");
//    char* p=&fmod[strlen(fmod)];
//    GetModuleFileNameA(hMod,p,MAX_PATH);
//    PathStripPathA(p);
//  }
//  TRACExA("SuRunExt32.dll: %sHookIAT(%s[%x])\n",(bUnHook?"Un":""),fmod,hMod);
#endif DoDBGTrace
  for(;pID->Name;pID++) 
  {
    char* DllName=RelPtr(char*,hMod,pID->Name);
    if(DoHookDll(DllName))
    {
      PIMAGE_THUNK_DATA pOrgThunk=RelPtr(PIMAGE_THUNK_DATA,hMod,pID->OriginalFirstThunk);
      PIMAGE_THUNK_DATA pThunk=RelPtr(PIMAGE_THUNK_DATA,hMod,pID->FirstThunk);
      for(;(pThunk->u1.Function)&&(pOrgThunk->u1.Function);pOrgThunk++,pThunk++)
        if ((pOrgThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG )==0)
        {
          PIMAGE_IMPORT_BY_NAME pBN=RelPtr(PIMAGE_IMPORT_BY_NAME,hMod,pOrgThunk->u1.AddressOfData);
          PROC orgFunc = 0;
          PROC newFunc = DoHookFn(DllName,(char*)pBN->Name,&orgFunc);
          //PROC newFunc = DoHookFn(DllName,(PROC)pThunk->u1.Function);
          if (newFunc && orgFunc 
            && (((!bUnHook) && (pThunk->u1.Function!=(DWORD_PTR)newFunc))
               ||(bUnHook && (pThunk->u1.Function==(DWORD_PTR)newFunc))))
          {
            __try
            {
              //MEMORY_BASIC_INFORMATION mbi;
              DWORD oldProt=PAGE_READWRITE;
              if(VirtualProtect(&pThunk->u1.Function,sizeof(pThunk->u1.Function),PAGE_EXECUTE_WRITECOPY,&oldProt))
              {
#ifdef DoDBGTrace
//                TRACExA("SuRunExt32.dll: %sHookFunc(%s):%s,%s (%x->%x) newProt:%x; oldProt:%x\n",
//                  (bUnHook?"Un":""),fmod,DllName,pBN->Name,pThunk->u1.Function,newFunc,PAGE_EXECUTE_WRITECOPY,oldProt);
#endif DoDBGTrace
                InterlockedExchangePointer((VOID**)&pThunk->u1.Function,(bUnHook?orgFunc:newFunc));
                VirtualProtect(&pThunk->u1.Function,sizeof(pThunk->u1.Function), oldProt, &oldProt);
                nHooked++;
              }
            }
            __except(1)
            {
              DBGTrace("FATAL: Exception in HookIAT");
            }
          }
        }
    }//if(DoHookDll(DllName))
  }//for(;pID->Name;pID++) 
  return nHooked;
}

DWORD Hook(HMODULE hMod,bool bUnHook)
{
  //Detect if a module is using CreateProcess, if yes, it needs to be hooked
  if(hMod==l_hInst)
    return 0;
  {
    char f0[MAX_PATH]={0};
    char f1[MAX_PATH]={0};
    GetModuleFileNameA(hMod,f0,MAX_PATH);
    GetModuleFileNameA(l_hInst,f0,MAX_PATH);
    if (stricmp(f0,f1)==0)
      return 0;
  }
  // check "MZ" and DOS Header size
  if(IsBadReadPtr(hMod,sizeof(IMAGE_DOS_HEADER))
    || (((PIMAGE_DOS_HEADER)hMod)->e_magic!=IMAGE_DOS_SIGNATURE))
    return 0;
  // check "PE" and DOS Header size
  PIMAGE_NT_HEADERS pNTH = RelPtr(PIMAGE_NT_HEADERS,hMod,((PIMAGE_DOS_HEADER)hMod)->e_lfanew);
  if(IsBadReadPtr(pNTH, sizeof(IMAGE_NT_HEADERS)) ||(pNTH->Signature != IMAGE_NT_SIGNATURE))
    return 0;
  //the right header?
#ifdef _WIN64
  if(pNTH->FileHeader.Machine!=IMAGE_FILE_MACHINE_AMD64)
    return 0;
#else _WIN64
  if(pNTH->FileHeader.Machine!=IMAGE_FILE_MACHINE_I386)
    return 0;
#endif _WIN64
  if(pNTH->FileHeader.SizeOfOptionalHeader!=sizeof(IMAGE_OPTIONAL_HEADER))
    return 0;
  //parse IAT
  DWORD_PTR va=pNTH->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
  if(va==0) 
    return false;
  PIMAGE_IMPORT_DESCRIPTOR pID = RelPtr(PIMAGE_IMPORT_DESCRIPTOR,hMod,va);
  for(;pID->Name;pID++) 
  {
    char* DllName=RelPtr(char*,hMod,pID->Name);
    if(DoHookDll(DllName))
    {
      PIMAGE_THUNK_DATA pOrgThunk=RelPtr(PIMAGE_THUNK_DATA,hMod,pID->OriginalFirstThunk);
      PIMAGE_THUNK_DATA pThunk=RelPtr(PIMAGE_THUNK_DATA,hMod,pID->FirstThunk);
      for(;(pThunk->u1.Function)&&(pOrgThunk->u1.Function);pOrgThunk++,pThunk++)
        if ((pOrgThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG )==0)
        {
          PIMAGE_IMPORT_BY_NAME pBN=RelPtr(PIMAGE_IMPORT_BY_NAME,hMod,pOrgThunk->u1.AddressOfData);
          if(NeedHookFn(DllName,(char*)pBN->Name,(void*)pThunk->u1.Function))
          {
            //Hook IAT
            DWORD dwRet=HookIAT(hMod,pID,bUnHook);
            return dwRet;
          }
        }
    }//if(DoHookDll(DllName))
  }//for(;pID->Name;pID++) 
  return false;
}

DWORD UnhookModules()
{
  DWORD nHooked=0;
  //Unhook hModules
  for(ModList::iterator it=g_ModList.begin();it!=g_ModList.end();++it)
    nHooked+=Hook(*it,TRUE);
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
      nHooked+=Hook(*it,FALSE);
    //merge new hModules to list
    g_ModList.merge(newMods);
    free(hMod);
  }
  CloseHandle(hProc);
  return nHooked;
}

CRITICAL_SECTION g_HookCs;

DWORD TestAutoSuRunW(LPCWSTR lpApp,LPWSTR lpCmd,LPCWSTR lpCurDir,
                     DWORD dwCreationFlags,LPPROCESS_INFORMATION lppi,
                     HANDLE hUser=0)
{
  if (!g_IATInit)
    return DBGTrace("NoIATHookInit->NoAutoSuRun"),RETVAL_SX_NOTINLIST;
  if (!GetUseIATHook)
    return DBGTrace("NoIATHook->NoAutoSuRun"),RETVAL_SX_NOTINLIST;
  DWORD ExitCode=ERROR_ACCESS_DENIED;
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
    GetSystemWindowsDirectoryW(cmd,countof(cmd));
    PathAppendW(cmd,L"SuRun.exe");
    PathQuoteSpacesW(cmd);
    if (_wcsnicmp(cmd,tmp,wcslen(cmd))==0)
      //Never start SuRun administrative
      return DBGTrace("NoSuRunAutoSuRun"),LeaveCriticalSection(&g_HookCs),RETVAL_SX_NOTINLIST;
    //Exit if ShellExecHook failed on "tmp"
    static WCHAR tmp2[4096];
    GetRegStr(HKCU,SURUNKEY,L"LastFailedCmd",tmp2,4096);
    RegDelVal(HKCU,SURUNKEY,L"LastFailedCmd");
    if(_tcsicmp(tmp,tmp2)==0)
      return DBGTrace("NoLastFailedCmdAutoSuRun"),LeaveCriticalSection(&g_HookCs),RETVAL_SX_NOTINLIST;  
    wsprintf(&cmd[wcslen(cmd)],L" /QUIET /TESTAA %d %x %s",
      GetCurrentProcessId(),&rpi,tmp);
  }
//  CTimeLog l(L"IATHook TestAutoSuRun(%s)",lpCmd);
  static STARTUPINFOW si;
  zero(si);
  static PROCESS_INFORMATION pi;
  zero(pi);
  si.cb = sizeof(si);
  BOOL bStarted=FALSE;
  if (hUser==0)
  {
    // Start the child process.
    bStarted=((lpCreateProcessW)hkCrProcW.OrgFunc())(NULL,cmd,NULL,NULL,FALSE,0,NULL,CurDir,&si,&pi);
  }else
  {
    // Start the child process as user
    bStarted=((lpCreateProcessAsUserW)hkCrPAUW.OrgFunc())(hUser,NULL,cmd,NULL,NULL,FALSE,0,NULL,CurDir,&si,&pi);
  }
  if (bStarted)
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
//      DBGTrace5("IATHook AutoSuRun(%s) success! PID=%d (h=%x); TID=%d (h=%x)",
//        cmd,rpi.dwProcessId,rpi.hProcess,
//        rpi.dwThreadId,rpi.hThread);
    }
  }
  LeaveCriticalSection(&g_HookCs);
  return ExitCode;
}

DWORD TestAutoSuRunA(LPCSTR lpApp,LPSTR lpCmd,LPCSTR lpCurDir,
                     DWORD dwCreationFlags,LPPROCESS_INFORMATION lppi,
                     HANDLE hUser=0)
{
  if (!g_IATInit)
    return RETVAL_SX_NOTINLIST;
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
  DWORD dwRet=TestAutoSuRunW(wApp,wCmd,wCurDir,dwCreationFlags,lppi,hUser);
  LeaveCriticalSection(&g_HookCs);
  return dwRet;
}

BOOL WINAPI CreateProcA(LPCSTR lpApplicationName,LPSTR lpCommandLine,
    LPSECURITY_ATTRIBUTES lpProcessAttributes,LPSECURITY_ATTRIBUTES lpThreadAttributes,
    BOOL bInheritHandles,DWORD dwCreationFlags,LPVOID lpEnvironment,
    LPCSTR lpCurrentDirectory,LPSTARTUPINFOA lpStartupInfo,
    LPPROCESS_INFORMATION lpProcessInformation)
{
#ifdef DoDBGTrace
//    TRACExA("SuRunExt32.dll: call to CreateProcA(%s,%s)",lpApplicationName,lpCommandLine);
#endif DoDBGTrace
  DWORD tas=RETVAL_SX_NOTINLIST;
  if ((!l_IsAdmin) && l_IsSuRunner)
    tas=TestAutoSuRunA(lpApplicationName,lpCommandLine,lpCurrentDirectory,
                       dwCreationFlags,lpProcessInformation);
  if(tas==RETVAL_OK)
    return SetLastError(NOERROR),TRUE;
  if(tas==RETVAL_CANCELLED)
    return SetLastError(ERROR_ACCESS_DENIED),FALSE;
  return ((lpCreateProcessA)hkCrProcA.OrgFunc())(lpApplicationName,lpCommandLine,
      lpProcessAttributes,lpThreadAttributes,bInheritHandles,dwCreationFlags,
      lpEnvironment,lpCurrentDirectory,lpStartupInfo,lpProcessInformation);
}

BOOL WINAPI CreateProcW(LPCWSTR lpApplicationName,LPWSTR lpCommandLine,
    LPSECURITY_ATTRIBUTES lpProcessAttributes,LPSECURITY_ATTRIBUTES lpThreadAttributes,
    BOOL bInheritHandles,DWORD dwCreationFlags,LPVOID lpEnvironment,
    LPCWSTR lpCurrentDirectory,LPSTARTUPINFOW lpStartupInfo,
    LPPROCESS_INFORMATION lpProcessInformation)
{
#ifdef DoDBGTrace
//    TRACEx(L"SuRunExt32.dll: call to CreateProcW(%s,%s)",lpApplicationName,lpCommandLine);
#endif DoDBGTrace
  DWORD tas=RETVAL_SX_NOTINLIST;
  if ((!l_IsAdmin) && l_IsSuRunner)
    tas=TestAutoSuRunW(lpApplicationName,lpCommandLine,lpCurrentDirectory,
                       dwCreationFlags,lpProcessInformation);
  if(tas==RETVAL_OK)
    return SetLastError(NOERROR),TRUE;
  if(tas==RETVAL_CANCELLED)
    return SetLastError(ERROR_ACCESS_DENIED),FALSE;
  return ((lpCreateProcessW)hkCrProcW.OrgFunc())(lpApplicationName,lpCommandLine,
      lpProcessAttributes,lpThreadAttributes,bInheritHandles,dwCreationFlags,
      lpEnvironment,lpCurrentDirectory,lpStartupInfo,lpProcessInformation);
}

static BOOL IsShellAndSuRunner(HANDLE hToken)
{
  BOOL bRet=FALSE;
  if (l_IsAdmin && (!GetUseSVCHook))
    return bRet;
  DWORD Groups=UserIsInSuRunnersOrAdmins(hToken);
  if ((Groups&(IS_IN_ADMINS|IS_IN_SURUNNERS))==IS_IN_SURUNNERS)
  {
    DWORD SessionId=0;
    DWORD siz=0;
    if (GetTokenInformation(hToken,TokenSessionId,&SessionId,sizeof(DWORD),&siz))
    {
      HANDLE hShell=GetSessionUserToken(SessionId);
      if (hShell)
      {
        PSID ShellSID=GetTokenUserSID(hShell);
        if (ShellSID)
        {
          PSID UserSID=GetTokenUserSID(hToken);
          if (UserSID)
          {
            bRet=EqualSid(UserSID,ShellSID);
            DBGTrace1("IsShellAndSuRunner=%d",bRet);
            free(UserSID);
          }
          free(ShellSID);
        }
        CloseHandle(hShell);
      }
    }
  }
  return bRet;
}

BOOL WINAPI CreatePAUA(HANDLE hToken,LPCSTR lpApplicationName,LPSTR lpCommandLine,
    LPSECURITY_ATTRIBUTES lpProcessAttributes,LPSECURITY_ATTRIBUTES lpThreadAttributes,
    BOOL bInheritHandles,DWORD dwCreationFlags,LPVOID lpEnvironment,
    LPCSTR lpCurrentDirectory,LPSTARTUPINFOA lpStartupInfo,
    LPPROCESS_INFORMATION lpProcessInformation)
{
  //ToDo: *original function will call CreateProcess. SuRun must not ask twice!
#ifdef DoDBGTrace
//  TRACExA("SuRunExt32.dll: call to CreatePAUA(%s,%s)",lpApplicationName,lpCommandLine);
#endif DoDBGTrace
  if(IsShellAndSuRunner(hToken))
  {
    DWORD tas=TestAutoSuRunA(lpApplicationName,lpCommandLine,lpCurrentDirectory,
      dwCreationFlags,lpProcessInformation,hToken);
    if(tas==RETVAL_OK)
      return SetLastError(NOERROR),TRUE;
    if(tas==RETVAL_CANCELLED)
      return SetLastError(ERROR_ACCESS_DENIED),FALSE;
  }
  return ((lpCreateProcessAsUserA)hkCrPAUA.OrgFunc())(hToken,lpApplicationName,
      lpCommandLine,lpProcessAttributes,lpThreadAttributes,bInheritHandles,
      dwCreationFlags,lpEnvironment,lpCurrentDirectory,lpStartupInfo,lpProcessInformation);
}


BOOL WINAPI CreatePAUW(HANDLE hToken,LPCWSTR lpApplicationName,LPWSTR lpCommandLine,
    LPSECURITY_ATTRIBUTES lpProcessAttributes,LPSECURITY_ATTRIBUTES lpThreadAttributes,
    BOOL bInheritHandles,DWORD dwCreationFlags,LPVOID lpEnvironment,
    LPCWSTR lpCurrentDirectory,LPSTARTUPINFOW lpStartupInfo,
    LPPROCESS_INFORMATION lpProcessInformation)
{
#ifdef DoDBGTrace
//  TRACEx(L"SuRunExt32.dll: call to CreatePAUW(%s,%s)",lpApplicationName,lpCommandLine);
#endif DoDBGTrace
  //ToDo: *original function may call CreateProcess. SuRun must not ask twice!
  if(IsShellAndSuRunner(hToken))
  {
    DWORD tas=TestAutoSuRunW(lpApplicationName,lpCommandLine,lpCurrentDirectory,
      dwCreationFlags,lpProcessInformation,hToken);
    if(tas==RETVAL_OK)
      return SetLastError(NOERROR),TRUE;
    if(tas==RETVAL_CANCELLED)
      return SetLastError(ERROR_ACCESS_DENIED),FALSE;
  }
  return ((lpCreateProcessAsUserW)hkCrPAUW.OrgFunc())(hToken,lpApplicationName,
      lpCommandLine,lpProcessAttributes,lpThreadAttributes,bInheritHandles,
      dwCreationFlags,lpEnvironment,lpCurrentDirectory,lpStartupInfo,lpProcessInformation);
}

FARPROC WINAPI GetProcAddr(HMODULE hModule,LPCSTR lpProcName)
{
#ifdef DoDBGTrace
//    TRACEx(L"SuRunExt32.dll: call to GetProcAddr(%s)",lpProcName);
#endif DoDBGTrace
  PROC p=0;
  if (HIWORD(lpProcName))
  {
    char f[MAX_PATH]={0};
    if(GetModuleFileNameA(hModule,f,MAX_PATH))
    {
      PathStripPathA(f);
      p=DoHookFn(f,(char*)lpProcName,NULL);
      SetLastError(NOERROR);
    }
  }
  if(!p)
    p=((lpGetProcAddress)hkGetPAdr.OrgFunc())(hModule,lpProcName);
  return p;
}

HMODULE WINAPI LoadLibA(LPCSTR lpLibFileName)
{
#ifdef DoDBGTrace
//    TRACExA("SuRunExt32.dll: call to LoadLibA(%s)",lpLibFileName);
#endif DoDBGTrace
  if (g_IATInit)
  {
    EnterCriticalSection(&g_HookCs);
    HMODULE hMOD=((lpLoadLibraryA)hkLdLibA.OrgFunc())(lpLibFileName);
    DWORD dwe=GetLastError();
    if(hMOD)
      HookModules();
    LeaveCriticalSection(&g_HookCs);
    SetLastError(dwe);
    return hMOD;
  }
  if (hkLdLibA.OrgFunc())
    return ((lpLoadLibraryA)hkLdLibA.OrgFunc())(lpLibFileName);
  return LoadLibraryA(lpLibFileName);
}

HMODULE WINAPI LoadLibW(LPCWSTR lpLibFileName)
{
#ifdef DoDBGTrace
//    TRACEx(L"SuRunExt32.dll: call to LoadLibW(%s)",lpLibFileName);
#endif DoDBGTrace
  if (g_IATInit)
  {
    EnterCriticalSection(&g_HookCs);
    HMODULE hMOD=((lpLoadLibraryW)hkLdLibW.OrgFunc())(lpLibFileName);
    DWORD dwe=GetLastError();
    if(hMOD)
      HookModules();
    LeaveCriticalSection(&g_HookCs);
    SetLastError(dwe);
    return hMOD;
  }
  if (hkLdLibW.OrgFunc())
    return ((lpLoadLibraryW)hkLdLibW.OrgFunc())(lpLibFileName);
  return LoadLibraryW(lpLibFileName);
}

HMODULE WINAPI LoadLibExA(LPCSTR lpLibFileName,HANDLE hFile,DWORD dwFlags)
{
#ifdef DoDBGTrace
//    TRACExA("SuRunExt32.dll: call to LoadLibExA(%s)",lpLibFileName);
#endif DoDBGTrace
  if (g_IATInit)
  {
    EnterCriticalSection(&g_HookCs);
    HMODULE hMOD=((lpLoadLibraryExA)hkLdLibXA.OrgFunc())(lpLibFileName,hFile,dwFlags);
    DWORD dwe=GetLastError();
    if(hMOD)
      HookModules();
    LeaveCriticalSection(&g_HookCs);
    SetLastError(dwe);
    return hMOD;
  }
  if (hkLdLibXA.OrgFunc())
    return ((lpLoadLibraryExA)hkLdLibXA.OrgFunc())(lpLibFileName,hFile,dwFlags);
  return LoadLibraryExA(lpLibFileName,hFile,dwFlags);
}

HMODULE WINAPI LoadLibExW(LPCWSTR lpLibFileName,HANDLE hFile,DWORD dwFlags)
{
#ifdef DoDBGTrace
//    TRACEx(L"SuRunExt32.dll: call to LoadLibExW(%s)",lpLibFileName);
#endif DoDBGTrace
  if (g_IATInit)
  {
    EnterCriticalSection(&g_HookCs);
    DWORD dwe=GetLastError();
    HMODULE hMOD=((lpLoadLibraryExW)hkLdLibXW.OrgFunc())(lpLibFileName,hFile,dwFlags);
    if(hMOD)
      HookModules();
    LeaveCriticalSection(&g_HookCs);
    SetLastError(dwe);
    return hMOD;
  }
  if (hkLdLibXW.OrgFunc())
    return ((lpLoadLibraryExW)hkLdLibXW.OrgFunc())(lpLibFileName,hFile,dwFlags);
  return LoadLibraryExW(lpLibFileName,hFile,dwFlags);
}

BOOL WINAPI FreeLib(HMODULE hLibModule)
{
#ifdef DoDBGTrace
//    TRACExA("SuRunExt32.dll: call to FreeLib()");
#endif DoDBGTrace
  //The DLL must not be unloaded while the process is running!
  if (hLibModule==l_hInst)
  {
    if (g_IATInit)
    {
      SetLastError(NOERROR);
      return true;
    }
  }
  SetLastError(NOERROR);
  BOOL bRet=((lpFreeLibrary)hkFreeLib.OrgFunc())(hLibModule);
  return bRet;
}

VOID WINAPI FreeLibAndExitThread(HMODULE hLibModule,DWORD dwExitCode)
{
  //The DLL must not be unloaded while the process is running!
  if ((!g_IATInit) || (hLibModule!=l_hInst))
  {
    if (((lpFreeLibraryAndExitThread)hkFrLibXT.OrgFunc()))
      ((lpFreeLibraryAndExitThread)hkFrLibXT.OrgFunc())(hLibModule,dwExitCode);
    else
      FreeLibraryAndExitThread(hLibModule,dwExitCode);
    return;
  }
  SetLastError(NOERROR);
  ExitThread(dwExitCode);
}

BOOL WINAPI SwitchDesk(HDESK Desk)
{
#ifdef DoDBGTrace
//  DBGTrace("SuRunExt32.dll: call to SwitchDesk()");
#endif DoDBGTrace
  if ((!l_IsAdmin)&&(!IsLocalSystem()))
  {
    HDESK d=OpenInputDesktop(0,0,DESKTOP_SWITCHDESKTOP);
    if (!d)
      return FALSE;
    TCHAR dn[4096]={0};
    DWORD dnl=4096;
    if (!GetUserObjectInformation(d,UOI_NAME,dn,dnl,&dnl))
      return CloseDesktop(d),FALSE;
    CloseDesktop(d);
    if ((_tcsicmp(dn,_T("Winlogon"))==0) || (_tcsnicmp(dn,_T("SRD_"),4)==0))
    {
      SetLastError(ERROR_ACCESS_DENIED);
      return CloseDesktop(d),FALSE;
    }
  }
  BOOL bRet=FALSE;
  if (hkSwDesk.OrgFunc())
    bRet=((lpSwitchDesk)hkSwDesk.OrgFunc())(Desk);
  bRet=SwitchDesktop(Desk);
  return bRet;
}

DWORD WINAPI InitHookProc(void* p)
{
  if (g_IATInit)
    return 0;
//  Sleep(10);
  orgGPA=GetProcAddress;
  InitializeCriticalSectionAndSpinCount(&g_HookCs,0x80000000);
  g_IATInit=TRUE;
  if (!GetUseIATHook)
    return 0;
  EnterCriticalSection(&g_HookCs);
  for(int i=0;i<countof(hdt);i++)
    PROC p=hdt[i]->OrgFunc();
  HookModules();
  LeaveCriticalSection(&g_HookCs);
  return 0;
}

void LoadHooks()
{
//  CloseHandle(CreateThread(0,0,InitHookProc,0,0,0));
  InitHookProc(0);
}

void UnloadHooks()
{
  if (!g_IATInit)
    return;
  //Do not unload the hooks, but wait for the Critical Section
  EnterCriticalSection(&g_HookCs);
  //UnhookModules();
  g_IATInit=FALSE;
  LeaveCriticalSection(&g_HookCs);
  DeleteCriticalSection(&g_HookCs);
}

