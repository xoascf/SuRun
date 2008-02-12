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

#include <windows.h>
#include <stdio.h>
#include <tchar.h>
#include <shlwapi.h>
#include "SysMenuHook.h"
#include "../DBGTrace.H"
#include "../ResStr.h"
#include "../IsAdmin.h"
#include "../Helpers.h"
#include "../Setup.h"
#include "SuRunExt.h"
#include "Resource.h"
#include "IATHook.h"
#include <Psapi.h>

#pragma comment(lib,"PSAPI.lib")
#pragma comment(lib,"shlwapi")

//////////////////////////////////////////////////////////////////////////////
//
// global data within shared data segment to allow sharing across instances
//
//////////////////////////////////////////////////////////////////////////////
#pragma data_seg(".SHDATA")

HHOOK       g_hookShell = NULL;
HHOOK       g_hookMenu  = NULL;
HINSTANCE   g_hHookInst = NULL;

TCHAR sMenuRestart[MAX_PATH]={0};
TCHAR sMenuStart[MAX_PATH]={0};
TCHAR sFileNotFound[MAX_PATH]={0};
TCHAR sSuRun[MAX_PATH]={0};
TCHAR sSuRunCmd[MAX_PATH]={0};
TCHAR sSuRunExp[MAX_PATH]={0};
TCHAR sErr[MAX_PATH]={0};
TCHAR sTip[MAX_PATH]={0};

#pragma data_seg()
#pragma comment(linker, "/section:.SHDATA,RWS")

UINT        WM_SYSMH0   = 0;
UINT        WM_SYSMH1   = 0;
HINSTANCE   l_hInst     = NULL;

// extern "C" prevents name mangling so that procedures can be referenced from outside the DLL
extern "C" static LRESULT CALLBACK ShellProc(int nCode, WPARAM wParam, LPARAM lParam)
{
  if(nCode>=0)
  {
    #define wps ((CWPSTRUCT*)lParam)
    switch(wps->message)
    {
    case WM_MENUSELECT:
      if((wps->lParam==NULL)&&(HIWORD(wps->wParam)==0xFFFF))
      {
        RemoveMenu(GetSystemMenu(wps->hwnd,FALSE),WM_SYSMH0,MF_BYCOMMAND);
        RemoveMenu(GetSystemMenu(wps->hwnd,FALSE),WM_SYSMH1,MF_BYCOMMAND);
      }
      break;
    case WM_CONTEXTMENU:
      //Load the System menu for the Window, if we don't, we'll get a default 
      //system menu on the first click.
      GetSystemMenu((HWND)wps->wParam,FALSE);
      break;
    case WM_INITMENUPOPUP:
      if ((HIWORD(wps->lParam)==TRUE) 
        && IsMenu((HMENU)wps->wParam) 
        && (!IsAdmin()))
      {
        if( GetRestartAsAdmin
        && (GetMenuState((HMENU)wps->wParam,WM_SYSMH0,MF_BYCOMMAND)==(UINT)-1))
          AppendMenu((HMENU)wps->wParam,MF_STRING,WM_SYSMH0,sMenuRestart);
        if( GetStartAsAdmin
        && (GetMenuState((HMENU)wps->wParam,WM_SYSMH1,MF_BYCOMMAND)==(UINT)-1))
          AppendMenu((HMENU)wps->wParam,MF_STRING,WM_SYSMH1,sMenuStart);
      }
      break;
    }
    #undef wps
  }
  return CallNextHookEx(g_hookShell, nCode, wParam, lParam);
}

extern "C" static LRESULT CALLBACK MenuProc(int nCode, WPARAM wParam, LPARAM lParam)
{
  #define msg ((MSG*)lParam)
  if ((nCode>=0)&&(msg->message==WM_SYSCOMMAND)&&(wParam==PM_REMOVE)
    &&((msg->wParam==WM_SYSMH0)||(msg->wParam==WM_SYSMH1)))
  {
    STARTUPINFO si={0};
    PROCESS_INFORMATION pi;
    si.cb = sizeof(si);
    TCHAR cmd[4096];
    GetSystemWindowsDirectory(cmd, MAX_PATH);
    PathAppend(cmd, _T("SuRun.exe"));
    PathQuoteSpaces(cmd);
    _tcscat(cmd,_T(" "));
    TCHAR PID[10];
    if (msg->wParam==WM_SYSMH0)
    {
      _tcscat(cmd,_T("/KILL "));
      _tcscat(cmd,_itot(GetCurrentProcessId(),PID,10));
      _tcscat(cmd,_T(" "));
    }
    _tcscat(cmd,GetCommandLine());
    if (CreateProcess(NULL,cmd,NULL,NULL,FALSE,0,NULL,NULL,&si,&pi))
    {
      CloseHandle(pi.hProcess);
      CloseHandle(pi.hThread);
      if (msg->wParam==WM_SYSMH0)
        ::ExitProcess(0);
    }else
      MessageBox(msg->hwnd,sFileNotFound,0,MB_ICONSTOP);
    //We processed the Message: Stop calling other hooks!
    return 0;
  }
  #undef msg
  return CallNextHookEx(g_hookMenu, nCode, wParam, lParam);
}

__declspec(dllexport) BOOL InstallSysMenuHook()
{
  DBGTrace2("InstallSysMenuHook init (%x,%x)",g_hookShell,g_hookMenu);
  if((g_hookShell!=NULL)||(g_hookMenu!=NULL))
    UninstallSysMenuHook();
  if((g_hookShell!=NULL)||(g_hookMenu!=NULL))
  {
    DBGTrace2("InstallSysMenuHook failed: Still Hooked (%x,%x)",g_hookShell,g_hookMenu);
    return FALSE;
  }
  g_hookShell=SetWindowsHookEx(WH_CALLWNDPROC,(HOOKPROC)ShellProc,l_hInst,0);
  if (g_hookShell==NULL)
    DBGTrace1("SetWindowsHookEx(Shell) failed: %s",GetLastErrorNameStatic());
  g_hookMenu =SetWindowsHookEx(WH_GETMESSAGE ,(HOOKPROC)MenuProc ,l_hInst,0);
  if (g_hookMenu==NULL)
    DBGTrace1("SetWindowsHookEx(Menu) failed: %s",GetLastErrorNameStatic());
  DBGTrace2("InstallSysMenuHook exit (%x,%x)",g_hookShell,g_hookMenu);
  g_hHookInst=l_hInst;
  return (g_hookShell!= NULL) && (g_hookMenu != NULL);
}

__declspec(dllexport) BOOL UninstallSysMenuHook()
{
  BOOL bRet=TRUE;
  if (g_hookShell)
    bRet&=(UnhookWindowsHookEx(g_hookShell)!=0);
  g_hookShell=NULL;
  if(g_hookMenu)
    bRet&=(UnhookWindowsHookEx(g_hookMenu)!=0);
  g_hookMenu=NULL;
  g_hHookInst=NULL;
  return bRet;
}

__declspec(dllexport) BOOL SysMenuHookInstalled()
{
  return (g_hookShell!=0)||(g_hookMenu!=0);
}

LPWSTR AToW(LPCSTR aStr)
{
  if(!aStr)
    return 0;
  DWORD nChars=strlen(aStr);
  if (!nChars)
    return 0;
  LPWSTR lpw=(LPWSTR)calloc(sizeof(WCHAR)*nChars,1);
  if(!lpw)
    return 0;
  WideCharToMultiByte(CP_ACP,0,lpw,-1,(char*)aStr,nChars,NULL,NULL);
  return lpw;
}

void CheckIAT(HMODULE hMod);

BOOL WINAPI CreateProcA(LPCSTR lpApplicationName,LPSTR lpCommandLine,
    LPSECURITY_ATTRIBUTES lpProcessAttributes,LPSECURITY_ATTRIBUTES lpThreadAttributes,
    BOOL bInheritHandles,DWORD dwCreationFlags,LPVOID lpEnvironment,
    LPCSTR lpCurrentDirectory,LPSTARTUPINFOA lpStartupInfo,
    LPPROCESS_INFORMATION lpProcessInformation)
{
  DBGTrace("CreateProcessA-Hook()");
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

HMODULE WINAPI LoadLibA(LPCSTR lpLibFileName)
{
  DBGTrace("LoadLibA");
  HMODULE hMOD=LoadLibraryA(lpLibFileName);
  CheckIAT(hMOD);
  return hMOD;
}

HMODULE WINAPI LoadLibW(LPCWSTR lpLibFileName)
{
  DBGTrace1("LoadLibW %s",lpLibFileName);
  HMODULE hMOD=LoadLibraryW(lpLibFileName);
  CheckIAT(hMOD);
  return hMOD;
}

HMODULE WINAPI LoadLibExA(LPCSTR lpLibFileName,HANDLE hFile,DWORD dwFlags)
{
  DBGTrace("LoadLibExA");
  HMODULE hMOD=LoadLibraryExA(lpLibFileName,hFile,dwFlags);
  CheckIAT(hMOD);
  return hMOD;
}

HMODULE WINAPI LoadLibExW(LPCWSTR lpLibFileName,HANDLE hFile,DWORD dwFlags)
{
  DBGTrace1("LoadLibExW %s",lpLibFileName);
  HMODULE hMOD=LoadLibraryExW(lpLibFileName,hFile,dwFlags);
  CheckIAT(hMOD);
  return hMOD;
}

void CheckIAT(HMODULE hMod)
{
  if(hMod == l_hInst)
    return;
  DBGTrace1("Hooking Module %x",hMod);
  HookIAT(hMod,"kernel32.dll",(PROC)LoadLibraryA,(PROC)LoadLibA);
  HookIAT(hMod,"kernel32.dll",(PROC)LoadLibraryW,(PROC)LoadLibW);
  HookIAT(hMod,"kernel32.dll",(PROC)LoadLibraryExA,(PROC)LoadLibExA);
  HookIAT(hMod,"kernel32.dll",(PROC)LoadLibraryExW,(PROC)LoadLibExW);
  HookIAT(hMod,"kernel32.dll",(PROC)CreateProcessA,(PROC)CreateProcA);
  HookIAT(hMod,"kernel32.dll",(PROC)CreateProcessW,(PROC)CreateProcW);
}

void CheckIAT()
{
  HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS,TRUE,GetCurrentProcessId());
  if (!hProc)
    return;
  DWORD Siz=0;
  EnumProcessModules(hProc,0,0,&Siz);
  HMODULE* hModues=(HMODULE*)malloc(Siz);
  if(hModues)
  {
    EnumProcessModules(hProc,hModues,Siz,&Siz);
    for (HMODULE* hMod=hModues;(DWORD)hMod<(DWORD)hModues+Siz;hMod++) 
      if(*hMod != l_hInst)
        CheckIAT(*hMod);
    free(hModues);
  }
  CloseHandle(hProc);
}

BOOL APIENTRY DllMain( HINSTANCE hInstDLL,DWORD dwReason,LPVOID lpReserved)
{
  if (dwReason==DLL_PROCESS_DETACH)
  {
    if(l_hInst==g_hHookInst)
      UninstallSysMenuHook();
  }
  if(dwReason!=DLL_PROCESS_ATTACH)
    return TRUE;
  if (l_hInst!=hInstDLL)
  {
#ifdef _DEBUG
    TCHAR f[MAX_PATH];
    GetModuleFileName(0,f,MAX_PATH);
    DWORD PID=GetCurrentProcessId();
    DBGTrace5("DLL_PROCESS_ATTACH(hInst=%x) %d:%s, g_hHookInst=%x, Admin=%d",
      hInstDLL,PID,f,g_hHookInst,IsAdmin());
    //      CheckIAT();
#endif _DEBUG
#ifdef _DEBUG_ENU
    SetThreadLocale(MAKELCID(MAKELANGID(LANG_ENGLISH,SUBLANG_ENGLISH_US),SORT_DEFAULT));
#endif _DEBUG_ENU
    l_hInst=hInstDLL;
    WM_SYSMH0=RegisterWindowMessage(_T("SYSMH1_2C7B6088-5A77-4d48-BE43-30337DCA9A86"));
    WM_SYSMH1=RegisterWindowMessage(_T("SYSMH2_2C7B6088-5A77-4d48-BE43-30337DCA9A86"));
    DisableThreadLibraryCalls(hInstDLL);
    if(sMenuRestart[0]==0)
    {
      _tcscpy(sMenuRestart,CResStr(l_hInst,IDS_MENURESTART));
      _tcscpy(sMenuStart,CResStr(l_hInst,IDS_MENUSTART));
      _tcscpy(sFileNotFound,CResStr(l_hInst,IDS_FILENOTFOUND));
      _tcscpy(sSuRun,CResStr(l_hInst,IDS_SURUN));
      _tcscpy(sSuRunCmd,CResStr(l_hInst,IDS_SURUNCMD));
      _tcscpy(sSuRunExp,CResStr(l_hInst,IDS_SURUNEXP));
      _tcscpy(sErr,CResStr(l_hInst,IDS_ERR));
      _tcscpy(sTip,CResStr(l_hInst,IDS_TOOLTIP));
    }
  }
  return TRUE;
}
