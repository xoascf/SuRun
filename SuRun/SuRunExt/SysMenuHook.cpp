#include <windows.h>
#include <stdio.h>
#include <tchar.h>
#include <shlwapi.h>
#include "SysMenuHook.h"
#include "../IsAdmin.h"

#pragma comment(lib,"shlwapi")

// global data within shared data segment to allow sharing across instances
#pragma data_seg(".SHARDATA")

HHOOK       g_hookShell = NULL;
HHOOK       g_hookMenu  = NULL;
HINSTANCE   g_hInst     = NULL;
UINT        WM_SYSMH0    = 0;
UINT        WM_SYSMH1    = 0;

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
        AppendMenu((HMENU)wps->wParam,MF_STRING,WM_SYSMH0,_T("Restart with SuRun"));
        AppendMenu((HMENU)wps->wParam,MF_STRING,WM_SYSMH1,_T("Start with SuRun"));
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
    GetWindowsDirectory(cmd, MAX_PATH);
    PathAppend(cmd, _T("surun.exe "));
    _tcscat(cmd, GetCommandLine());
    if (CreateProcess(NULL,cmd,NULL,NULL,FALSE,0,NULL,NULL,&si,&pi))
    {
      if (msg->wParam==WM_SYSMH0)
        ::ExitProcess(0);
      CloseHandle(pi.hProcess);
      CloseHandle(pi.hThread);
    }else
      MessageBox(msg->hwnd,_T("File not found: surun.exe"),0,MB_ICONSTOP);
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
    g_hInst=hInstDLL;
    WM_SYSMH0=RegisterWindowMessage(_T("SYSMH229FE1EC5_F424_488b_A672_A21C189F4EDC"));
    WM_SYSMH1=RegisterWindowMessage(_T("SYSMH329FE1EC5_F424_488b_A672_A21C189F4EDC"));
    DisableThreadLibraryCalls(hInstDLL);
  }
  return TRUE;
}
