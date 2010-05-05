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
#include <stdio.h>
#include <tchar.h>
#include <Psapi.h>
#include <shlwapi.h>

#include "SysMenuHook.h"
#include "../DBGTrace.H"
#include "../ResStr.h"
#include "../IsAdmin.h"
#include "../Helpers.h"
#include "../Setup.h"
#include "SuRunExt.h"
#include "Resource.h"

#pragma comment(lib,"PSAPI")
#pragma comment(lib,"shlwapi")

//////////////////////////////////////////////////////////////////////////////
//
// global data within shared data segment to allow sharing across instances
//
//////////////////////////////////////////////////////////////////////////////
#pragma data_seg(".SHDATA")

HHOOK       g_hookShell = NULL;
HHOOK       g_hookMenu  = NULL;

#pragma data_seg()
#pragma comment(linker, "/section:.SHDATA,RWS")

extern HINSTANCE l_hInst; //the local Dll instance
extern TCHAR     l_User[514];  //the Process user Name
extern DWORD     l_Groups;
extern HANDLE    l_InitThread;
#define     l_IsAdmin     ((l_Groups&IS_IN_ADMINS)!=0)
#define     l_IsSuRunner  ((l_Groups&IS_IN_SURUNNERS)!=0)


UINT        WM_SYSMH0   = -2;
UINT        WM_SYSMH1   = -2;


BOOL g_IsShell=-1;
BOOL IsShell()
{
  if (g_IsShell!=-1)
    return g_IsShell;
  DWORD ShellID=0;
  GetWindowThreadProcessId(GetShellWindow(),&ShellID);
  g_IsShell=GetCurrentProcessId()==ShellID;
  return g_IsShell;
}

BOOL g_IsWin7Explorer=-1;

BOOL IsWin7Explorer()
{
  if (g_IsWin7Explorer!=-1)
    return g_IsWin7Explorer;
  g_IsWin7Explorer=FALSE;
  if (!IsWin7)
    return FALSE;
  TCHAR app[MAX_PATH]={0};
  GetSystemWindowsDirectory(app,MAX_PATH);
  PathAppend(app,_T("explorer.exe"));

  TCHAR cmd[MAX_PATH]={0};
  GetProcessFileName(cmd,MAX_PATH);
  g_IsWin7Explorer=_tcsicmp(cmd,app)==0;
  return g_IsWin7Explorer;
}

UINT GetMenuItemType(HMENU m,int pos)
{
  MENUITEMINFO mii={0};
  mii.cbSize=sizeof(mii);
  mii.fMask=MIIM_FTYPE;
  GetMenuItemInfo(m,pos,TRUE,&mii);
  return mii.fType;
}

int FindSCClose(HMENU m)
{
  //return position of SC_CLOSE in menu.
  //Insert Separator before SC_CLOSE if no separator precedes it
  int i;
  for (i=0;i<GetMenuItemCount(m)&&(GetMenuItemID(m,i)!=SC_CLOSE);i++);
  if(i && ((GetMenuItemType(m,i-1)&MFT_SEPARATOR)==0))
    InsertMenu(m,i++,MF_SEPARATOR|MF_BYPOSITION,WM_SYSMH0,0);
  return i;
}

LRESULT CALLBACK ShellProc(int nCode, WPARAM wParam, LPARAM lParam)
{
  if(nCode>=0)
  {
    if (l_InitThread)
        WaitForSingleObject(l_InitThread,5000);
    if (WM_SYSMH0==-2)
      WM_SYSMH0=RegisterWindowMessage(_T("SYSMH1_2C7B6088-5A77-4d48-BE43-30337DCA9A86"));
    if (WM_SYSMH1==-2)
      WM_SYSMH1=RegisterWindowMessage(_T("SYSMH2_2C7B6088-5A77-4d48-BE43-30337DCA9A86"));
    #define wps ((CWPSTRUCT*)lParam)
    #define hmenu (HMENU)wps->wParam
    switch(wps->message)
    {
    case WM_MENUSELECT:
      if((wps->lParam==NULL)&&(HIWORD(wps->wParam)==0xFFFF))
      {
        HMENU m=GetSystemMenu(wps->hwnd,FALSE);
        //Two menu items and two separators can be in Sysmenu, remove them:
        RemoveMenu(m,WM_SYSMH0,MF_BYCOMMAND);
        RemoveMenu(m,WM_SYSMH0,MF_BYCOMMAND);
        RemoveMenu(m,WM_SYSMH1,MF_BYCOMMAND);
        RemoveMenu(m,WM_SYSMH1,MF_BYCOMMAND);
      }
      break;
    //Load the System menu for the Window, if we don't, we'll get a default 
    //system menu on the first click.
    case WM_CREATE:
    case WM_INITDIALOG:
      GetSystemMenu((HWND)wps->hwnd,FALSE);
      break;
    case WM_INITMENUPOPUP:
      if ((HIWORD(wps->lParam)==TRUE) 
        && IsMenu(hmenu) 
        && (GetSystemMenu((HWND)wps->hwnd,FALSE)==hmenu)
        && (!IsWin7Explorer())
        && (!l_IsAdmin)
        && (!GetHideFromUser(l_User)))
      {
        int i=0;
        if( GetRestartAsAdmin 
        && (!IsShell())
        && (GetMenuState(hmenu,WM_SYSMH0,MF_BYCOMMAND)==(UINT)-1))
        {
          i=FindSCClose(hmenu);
          InsertMenu(hmenu,i++,MF_BYPOSITION,WM_SYSMH0,CResStr(l_hInst,IDS_MENURESTART));
        }
        if( GetStartAsAdmin
        && (GetMenuState(hmenu,WM_SYSMH1,MF_BYCOMMAND)==(UINT)-1))
        {
          if (i==0)
            i=FindSCClose(hmenu);
          InsertMenu(hmenu,i++,MF_BYPOSITION,WM_SYSMH1,CResStr(l_hInst,IDS_MENUSTART));
        }
        if (i)
          InsertMenu(hmenu,i,MF_SEPARATOR|MF_BYPOSITION,WM_SYSMH1,0);
      }
      break;
    }
    #undef hmenu
    #undef wps
  }
  return CallNextHookEx(g_hookShell, nCode, wParam, lParam);
}

LRESULT CALLBACK MenuProc(int nCode, WPARAM wParam, LPARAM lParam)
{
  #define msg ((MSG*)lParam)
  if ((nCode>=0)&&(msg->message==WM_SYSCOMMAND)&&(wParam==PM_REMOVE)
    &&((msg->wParam==WM_SYSMH0)||(msg->wParam==WM_SYSMH1)))
  {
    STARTUPINFO si={0};
    PROCESS_INFORMATION pi;
    si.cb = sizeof(si);
    TCHAR cmd[4096];
    GetSystemWindowsDirectory(cmd, 4096);
    PathAppend(cmd, _T("SuRun.exe"));
    PathQuoteSpaces(cmd);
    _tcscat(cmd,_T(" "));
    if (msg->wParam==WM_SYSMH0)
    {
      TCHAR PID[10];
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
      SafeMsgBox(msg->hwnd,CResStr(l_hInst,IDS_FILENOTFOUND),0,MB_ICONSTOP);
    //We processed the Message: Stop calling other hooks!
    return 0;
  }
  #undef msg
  return CallNextHookEx(g_hookMenu, nCode, wParam, lParam);
}

__declspec(dllexport) BOOL InstallSysMenuHook()
{
  DBGTrace2("InstallSysMenuHook init (%x,%x)",g_hookShell,g_hookMenu);
  if (l_InitThread)
      WaitForSingleObject(l_InitThread,5000);
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
  return (g_hookShell!= NULL) && (g_hookMenu != NULL);
}

__declspec(dllexport) BOOL UninstallSysMenuHook()
{
  DBGTrace2("UninstallSysMenuHook init (%x,%x)",g_hookShell,g_hookMenu);
  if (l_InitThread)
      WaitForSingleObject(l_InitThread,5000);
  BOOL bRet=TRUE;
  if (g_hookShell)
    bRet&=(UnhookWindowsHookEx(g_hookShell)!=0);
  g_hookShell=NULL;
  if(g_hookMenu)
    bRet&=(UnhookWindowsHookEx(g_hookMenu)!=0);
  g_hookMenu=NULL;
  DBGTrace2("UninstallSysMenuHook exit (%x,%x)",g_hookShell,g_hookMenu);
  return bRet;
}
