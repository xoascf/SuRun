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
#ifdef _DEBUG
//#define _DEBUGSETUP
#endif _DEBUG

#define _WIN32_WINNT 0x0500
#define WINVER       0x0500
#include <windows.h>
#include <stdio.h>
#include <tchar.h>
#include <lm.h>
#include <dbghelp.h>
#include <shlwapi.h>
#include <Tlhelp32.h>
#include "WinStaDesk.h"
#include "IsAdmin.h"
#include "Helpers.h"
#include "ResStr.h"
#include "Service.h"
#include "Setup.h"
#include "TrayMsgWnd.h"
#include "DBGTrace.h"
#include "UserGroups.h"
#include "Resource.h"

#pragma comment(lib,"netapi32.lib")
#pragma comment(lib,"shlwapi")

#ifdef _WIN64
#pragma comment(lib,"bin/Crypt32x64.lib")
#else _WIN64
#pragma comment(lib,"bin/Crypt32x86.lib")
#endif _WIN64

extern RUNDATA g_RunData;

//////////////////////////////////////////////////////////////////////////////
//
// WinMain
//
//////////////////////////////////////////////////////////////////////////////

static void HideAppStartCursor()
{
  HWND w=CreateWindow(_TEXT("Static"),0,0,0,0,0,0,0,0,0,0);
  if(w)
  {
    PostMessage(w,WM_QUIT,0,0);
    MSG msg;
    GetMessage(&msg,w,WM_QUIT,WM_QUIT);
    DestroyWindow(w);
  }
}

//extern LPTSTR GetSvcName();
int WINAPI WinMain(HINSTANCE hInst,HINSTANCE hPrevInst,LPSTR lpCmdLine,int nCmdShow)
{
  UNREFERENCED_PARAMETER(hInst);
  UNREFERENCED_PARAMETER(hPrevInst);
  UNREFERENCED_PARAMETER(lpCmdLine);
  UNREFERENCED_PARAMETER(nCmdShow);
  {
    //Enable DEP
    HMODULE hMod=GetModuleHandle(_T("Kernel32.dll"));
    if (hMod) 
    {
      typedef BOOL (WINAPI *PSETDEP)(DWORD);
      #define PROCESS_DEP_ENABLE 0x00000001
      PSETDEP SetProcessDEPPolicy=(PSETDEP)GetProcAddress(hMod,"SetProcessDEPPolicy");
      if (SetProcessDEPPolicy) 
        SetProcessDEPPolicy(PROCESS_DEP_ENABLE);
    }
  }
//  LPTSTR sn=GetSvcName();
  DBGTrace1("SuRun started with (%s)",GetCommandLine());
  switch (GetRegInt(HKLM,SURUNKEY,L"Language",0))
  {
  case 1:
    SetThreadLocale(MAKELCID(MAKELANGID(LANG_GERMAN,SUBLANG_GERMAN),SORT_DEFAULT));
    break;
  case 2:
    SetThreadLocale(MAKELCID(MAKELANGID(LANG_ENGLISH,SUBLANG_ENGLISH_US),SORT_DEFAULT));
    break;
  case 3:
    SetThreadLocale(MAKELCID(MAKELANGID(LANG_DUTCH,SUBLANG_DUTCH),SORT_DEFAULT));
    break;
  case 4:
    SetThreadLocale(MAKELCID(MAKELANGID(LANG_SPANISH,SUBLANG_SPANISH),SORT_DEFAULT));
    break;
  case 5:
    SetThreadLocale(MAKELCID(MAKELANGID(LANG_POLISH,SUBLANG_DEFAULT),SORT_DEFAULT));
    break;
  case 6:
    SetThreadLocale(MAKELCID(MAKELANGID(LANG_FRENCH,SUBLANG_FRENCH),SORT_DEFAULT));
    break;
  case 7:
    SetThreadLocale(MAKELCID(MAKELANGID(LANG_PORTUGUESE,SUBLANG_PORTUGUESE),SORT_DEFAULT));
    break;
  }
  HideAppStartCursor();
  if(HandleServiceStuff())
    return 0;
  
  if (g_RunData.CliThreadId==GetCurrentThreadId())
  {
    //Started from service:
    //Show ToolTip "<Program> is running elevated"...
    TrayMsgWnd(CResStr(IDS_APPNAME),g_RunData.cmdLine,g_RunData.IconId,g_RunData.TimeOut);
    return RETVAL_OK;
  }
  //ProcessId
  g_RunData.CliProcessId=GetCurrentProcessId();
  //ThreadId
  g_RunData.CliThreadId=GetCurrentThreadId();
  //Session
  ProcessIdToSessionId(g_RunData.CliProcessId,&g_RunData.SessionID);
  //WindowStation
  GetWinStaName(g_RunData.WinSta,countof(g_RunData.WinSta));
  //Desktop
  GetDesktopName(g_RunData.Desk,countof(g_RunData.Desk));
  //UserName
  GetProcessUserName(g_RunData.CliProcessId,g_RunData.UserName);
  //Groups
  g_RunData.Groups=UserIsInSuRunnersOrAdmins();
  //Current Directory
  GetCurrentDirectory(countof(g_RunData.CurDir),g_RunData.CurDir);
  NetworkPathToUNCPath(g_RunData.CurDir);
  bool bRunSetup=FALSE;
  bool bRetPID=FALSE;
  bool bWaitPID=FALSE;
  if (HideSuRun(g_RunData.UserName,g_RunData.Groups))
    g_RunData.beQuiet=TRUE;
  //cmdLine
  {
    LPTSTR args=_tcsdup(PathGetArgs(GetCommandLine()));
    LPTSTR Args=args;
    while (Args[0]==L' ')
      Args++;
    //Parse direct commands:
    while (Args[0]=='/')
    {
      LPTSTR c=Args;
      Args=PathGetArgs(Args);
      for(LPTSTR C=Args-1;*C==' ';C--)
        *C=0;
      if (!_wcsicmp(c,L"/QUIET"))
      {
        g_RunData.beQuiet=TRUE;
      }else if (!_wcsicmp(c,L"/RETPID"))
      {
        bRetPID=TRUE;
      }else if (!_wcsicmp(c,L"/WAIT"))
      {
        bWaitPID=TRUE;
      }else if (!_wcsicmp(c,L"/RUNAS"))
      {
        g_RunData.bRunAs|=1;
      }else if (!_wcsicmp(c,L"/LOW"))
      {
        g_RunData.bRunAs|=2;
      }else if ((!_wcsicmp(c,L"/USER"))&& (g_RunData.bRunAs&1))
      {
        c=Args;
        Args=PathGetArgs(Args);
        if (*(Args-1)==' ')
          *(Args-1)=0;
        wcsncpy(g_RunData.UserName,c,UNLEN+UNLEN);
        g_RunData.bRunAs|=4;
      }else if (!_wcsicmp(c,L"/SETUP"))
      {
        bRunSetup=TRUE;
        wcscpy(g_RunData.cmdLine,L"/SETUP");
        break;
      }else if (!_wcsicmp(c,L"/TESTAA"))
      {
        g_RunData.bShlExHook=TRUE;
        //ShellExec-Hook: We must return the PID and TID to fake CreateProcess:
        g_RunData.RetPID=wcstol(Args,0,10);
        Args=PathGetArgs(Args);
        g_RunData.RetPtr=wcstoul(Args,0,16);
        Args=PathGetArgs(Args);
        //If we run on a desktop we cannot switch from, bail out!
        HDESK d=OpenInputDesktop(0,0,0);
        if (!d)
          g_RunData.bShExNoSafeDesk=TRUE;
        else
        {
          TCHAR dn[4096]={0};
          DWORD dnl=4096;
          if (!GetUserObjectInformation(d,UOI_NAME,dn,dnl,&dnl))
            g_RunData.bShExNoSafeDesk=TRUE;
          else
            if ((_tcsicmp(dn,_T("Winlogon"))==0)
              ||(_tcsicmp(dn,_T("Disconnect"))==0)
              ||(_tcsicmp(dn,_T("Screen-saver"))==0))
              g_RunData.bShExNoSafeDesk=TRUE;
            CloseDesktop(d);
        }
      }else if (!_wcsicmp(c,L"/KILL"))
      {
        g_RunData.KillPID=wcstol(Args,0,10);
        Args=PathGetArgs(Args);
      }else if (!_wcsicmp(c,L"/RESTORE"))
      {
        if (!(g_RunData.Groups&IS_IN_ADMINS))
        {
          SafeMsgBox(0,CBigResStr(IDS_NOIMPORT),CResStr(IDS_APPNAME),MB_ICONSTOP);
          return g_RunData.bShlExHook?RETVAL_SX_NOTINLIST:RETVAL_ACCESSDENIED;
        }
        g_RunData.KillPID=(DWORD)-1;
        if (Args && (*(Args-1)==0))
          *(Args-1)=' ';
        Args=c;
        break;
      }else if (!_wcsicmp(c,L"/BACKUP"))
      {
        if (!(g_RunData.Groups&IS_IN_ADMINS))
        {
          SafeMsgBox(0,CBigResStr(IDS_NOEXPORT),CResStr(IDS_APPNAME),MB_ICONSTOP);
          return g_RunData.bShlExHook?RETVAL_SX_NOTINLIST:RETVAL_ACCESSDENIED;
        }
        g_RunData.KillPID=(DWORD)-1;
        if (Args && (*(Args-1)==0))
          *(Args-1)=' ';
        Args=c;
        break;
      }else if (!_wcsicmp(c,L"/SWITCHTO"))
      {
        g_RunData.KillPID=(DWORD)-1;
        if (Args && (*(Args-1)==0))
          *(Args-1)=' ';
        Args=c;
        break;
      }else
      {
        //invalid direct argument
        return g_RunData.bShlExHook?RETVAL_SX_NOTINLIST:RETVAL_ACCESSDENIED;
      }
    }
    bool bShellIsadmin=FALSE;
    HANDLE hTok=GetShellProcessToken();
    if(hTok)
    {
      bShellIsadmin=IsAdmin(hTok)!=0;
      CloseHandle(hTok);
    }
    //Convert Command Line
    if (!bRunSetup)
    {
      //If shell is Admin but User is SuRunner, the Shell must be restarted
      if (g_CliIsInSuRunners && bShellIsadmin)
      {
        //Complain if shell user is an admin!
        SafeMsgBox(0,CResStr(IDS_ADMINSHELL),CResStr(IDS_APPNAME),MB_ICONEXCLAMATION|MB_SETFOREGROUND);
        return RETVAL_ACCESSDENIED;
      }  
      ResolveCommandLine(Args,g_RunData.CurDir,g_RunData.cmdLine);
      //DBGTrace3("ResolveCommandLine(%s,%s)= %s",Args,g_RunData.CurDir,g_RunData.cmdLine);
    }
    free(args);
  }
  //Usage
  if (!g_RunData.cmdLine[0])
  {
    if (!g_RunData.beQuiet)
      SafeMsgBox(0,CBigResStr(IDS_USAGE),CResStr(IDS_APPNAME),MB_ICONSTOP);
    return RETVAL_ACCESSDENIED;
  }
  //Lets go:
  g_RetVal=RETVAL_WAIT;
  HANDLE hPipe=INVALID_HANDLE_VALUE;
  //retry if the pipe is busy: (max 240s)
  CTimeOut to(240000);
  while (!to.TimedOut())
  {
    hPipe=CreateFile(ServicePipeName,GENERIC_WRITE,0,0,OPEN_EXISTING,0,0);
    DWORD err=GetLastError();
    if(hPipe!=INVALID_HANDLE_VALUE)
      break;
    if ((err==ERROR_FILE_NOT_FOUND)||(err==ERROR_ACCESS_DENIED))
      return RETVAL_ACCESSDENIED;
    DBGTrace2("CreateFile(%s) failed: %s",ServicePipeName,GetErrorNameStatic(err));
    Sleep(250);
  }
  //No Pipe handle: fail!
  if (hPipe==INVALID_HANDLE_VALUE)
    return g_RunData.bShlExHook?RETVAL_SX_NOTINLIST:RETVAL_ACCESSDENIED;
  DWORD nWritten=0;
  WriteFile(hPipe,&g_RunData,sizeof(RUNDATA),&nWritten,0);
  CloseHandle(hPipe);
  //Wait for max 60s for the Password...
  to.Set(60000);
  while ((g_RetVal==RETVAL_WAIT)&&(!to.TimedOut()))
      Sleep(20);
  if (bRunSetup)
    return g_RetVal;
  switch(g_RetVal)
  {
  case RETVAL_WAIT:
    DBGTrace("ERROR: SuRun got no response from Service!");
    return ERROR_ACCESS_DENIED;
  case RETVAL_SX_NOTINLIST: //ShellExec->NOT in List
    return RETVAL_SX_NOTINLIST;
  case RETVAL_RESTRICT: //Restricted User, may not run App!
    if (!g_RunData.beQuiet)
      SafeMsgBox(0,
        CBigResStr(IDS_RUNRESTRICTED,g_RunData.UserName,g_RunData.cmdLine),
        CResStr(IDS_APPNAME),MB_ICONSTOP);
    return RETVAL_RESTRICT;
  case RETVAL_ACCESSDENIED:
    if (!g_RunData.beQuiet)
    {
      SafeMsgBox(0,CResStr(IDS_RUNFAILED,g_RunData.cmdLine),
        CResStr(IDS_APPNAME),MB_ICONSTOP);
    }
    return RETVAL_ACCESSDENIED;
  case RETVAL_CANCELLED:
    return RETVAL_CANCELLED;
  case RETVAL_OK:
    {
      if (bWaitPID)
      {
        HANDLE hProcess=OpenProcess(SYNCHRONIZE,0,g_RunData.NewPID);
        if(hProcess)
        {
          WaitForSingleObject(hProcess,INFINITE);
          CloseHandle(hProcess);
        }else
          DBGTrace2("OpenProcess(%d) failed: %s",g_RunData.NewPID,GetLastErrorNameStatic());
      }
      return bRetPID?g_RunData.NewPID:RETVAL_OK;
    }
  }
  return RETVAL_ACCESSDENIED;
}
