#include <windows.h>
#include <stdio.h>
#include <tchar.h>
#include <shlwapi.h>
#include "SysMenuHook.h"
#include "../ResStr.h"
#include "../IsAdmin.h"
#include "Resource.h"

#pragma comment(lib,"shlwapi")

// global data within shared data segment to allow sharing across instances
#pragma data_seg(".SHARDATA")

HHOOK       g_hookShell = NULL;
HHOOK       g_hookMenu  = NULL;
HINSTANCE   g_hInst     = NULL;
UINT        WM_SYSMH0    = 0;
UINT        WM_SYSMH1    = 0;

TCHAR sMenuRestart[MAX_PATH];
TCHAR sMenuStart[MAX_PATH];
TCHAR sFileNotFound[MAX_PATH];

#pragma data_seg()
#pragma comment(linker, "/section:.SHARDATA,rws")

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
        && (GetMenuState((HMENU)wps->wParam,WM_SYSMH0,MF_BYCOMMAND)==(UINT)-1)
        && (!IsAdmin()))
      {
        AppendMenu((HMENU)wps->wParam,MF_STRING,WM_SYSMH0,sMenuRestart);
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
  if ((nCode>=0)&&(msg->message==WM_SYSCOMMAND)
    &&((msg->wParam==WM_SYSMH0)||(msg->wParam==WM_SYSMH1)))
  {
    STARTUPINFO si={0};
    PROCESS_INFORMATION pi;
    si.cb = sizeof(si);
    TCHAR cmd[4096];
    TCHAR PID[10];
    GetWindowsDirectory(cmd, MAX_PATH);
    PathAppend(cmd, _T("surun.exe "));
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
    }else
      MessageBox(msg->hwnd,sFileNotFound,0,MB_ICONSTOP);
  }
  #undef msg
  return CallNextHookEx(g_hookMenu, nCode, wParam, lParam);
}

__declspec(dllexport) BOOL InstallSysMenuHook()
{
  if((g_hookShell!=NULL)&&(g_hookMenu!=NULL))
    return TRUE;
  if((g_hookShell!=NULL)||(g_hookMenu!=NULL))
    return FALSE;
  g_hookShell=SetWindowsHookEx(WH_CALLWNDPROC,(HOOKPROC)ShellProc,g_hInst,0);
  g_hookMenu =SetWindowsHookEx(WH_GETMESSAGE ,(HOOKPROC)MenuProc ,g_hInst,0);
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
  return bRet;
}

BOOL APIENTRY DllMain( HINSTANCE hInstDLL,DWORD dwReason,LPVOID lpReserved)
{
  switch(dwReason)
  {
  case DLL_PROCESS_ATTACH:
#ifdef _DEBUG_ENU
    SetThreadLocale(MAKELCID(MAKELANGID(LANG_ENGLISH,SUBLANG_ENGLISH_US),SORT_DEFAULT));
#endif _DEBUG_ENU
    g_hInst=hInstDLL;
    WM_SYSMH0=RegisterWindowMessage(_T("SYSMH1_2C7B6088-5A77-4d48-BE43-30337DCA9A86"));
    WM_SYSMH1=RegisterWindowMessage(_T("SYSMH2_2C7B6088-5A77-4d48-BE43-30337DCA9A86"));
    DisableThreadLibraryCalls(hInstDLL);
    _tcscpy(sMenuRestart,CResStr(g_hInst,IDS_MENURESTART));
    _tcscpy(sMenuStart,CResStr(g_hInst,IDS_MENUSTART));
    _tcscpy(sFileNotFound,CResStr(g_hInst,IDS_FILENOTFOUND));
  }
  return TRUE;
}
