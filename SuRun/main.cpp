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
#define _DEBUGSETUP
#endif _DEBUG

#define _WIN32_WINNT 0x0500
#define WINVER       0x0500
#include <windows.h>
#include <shlwapi.h>
#include <stdio.h>
#include <tchar.h>
#include <lm.h>
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

#pragma comment(lib,"shlwapi.lib")
#pragma comment(lib,"netapi32.lib")

extern RUNDATA g_RunData;

//////////////////////////////////////////////////////////////////////////////
//
// WinMain
//
//////////////////////////////////////////////////////////////////////////////

#ifdef _DEBUG
//#include "LSALogon.h"
//extern BOOL TestSetup();
//extern BOOL TestLogonDlg();
#endif _DEBUG

int WINAPI WinMain(HINSTANCE hInst,HINSTANCE hPrevInst,LPSTR lpCmdLine,int nCmdShow)
{
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
  }
#ifdef _DEBUG
//  HKEY hkcu=0;
//  RegOpenKey(HKCU,0,&hkcu);
//  GetAdminToken(0);
//  TestSetup();
//  TestLogonDlg();
//  UserIsInSuRunnersOrAdmins();
//  ExitProcess(0);
#endif _DEBUG
  if(HandleServiceStuff())
    return 0;
  if (g_RunData.CliThreadId==GetCurrentThreadId())
  {
    //Started from services:
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
  //cmdLine
  {
    LPTSTR args=_tcsdup(PathGetArgs(GetCommandLine()));
    LPTSTR Args=args;
    //Parse direct commands:
    if (HideSuRun(g_RunData.UserName,g_RunData.Groups))
      g_RunData.beQuiet=TRUE;
    while (Args[0]=='/')
    {
      LPTSTR c=Args;
      Args=PathGetArgs(Args);
      if (*(Args-1)==' ')
        *(Args-1)=0;
      if (!_wcsicmp(c,L"/QUIET"))
      {
        g_RunData.beQuiet=TRUE;
      }else if (!_wcsicmp(c,L"/RUNAS"))
      {
        g_RunData.bRunAs=TRUE;
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
        HDESK d=OpenInputDesktop(0,0,DESKTOP_SWITCHDESKTOP);
        if (!d)
          return RETVAL_SX_NOTINLIST;
        TCHAR dn[4096]={0};
        DWORD dnl=4096;
        if (!GetUserObjectInformation(d,UOI_NAME,dn,dnl,&dnl))
          return RETVAL_SX_NOTINLIST;
        CloseDesktop(d);
        if ((_tcsicmp(dn,_T("Winlogon"))==0)
          ||(_tcsicmp(dn,_T("Disconnect"))==0)
          ||(_tcsicmp(dn,_T("Screen-saver"))==0))
          return RETVAL_SX_NOTINLIST;
      }else if (!_wcsicmp(c,L"/KILL"))
      {
        g_RunData.KillPID=wcstol(Args,0,10);
        Args=PathGetArgs(Args);
      }else
      {
        //Usage
        //SafeMsgBox(0,CBigResStr(IDS_USAGE),CResStr(IDS_APPNAME),MB_ICONSTOP);
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
  for(int i=0;i<720;i++)
  {
    hPipe=CreateFile(ServicePipeName,GENERIC_WRITE,0,0,OPEN_EXISTING,0,0);
    if(hPipe!=INVALID_HANDLE_VALUE)
      break;
    if ((GetLastError()==ERROR_FILE_NOT_FOUND)||(GetLastError()==ERROR_ACCESS_DENIED))
      return RETVAL_ACCESSDENIED;
    Sleep(250);
  }
  //No Pipe handle: fail!
  if (hPipe==INVALID_HANDLE_VALUE)
    return g_RunData.bShlExHook?RETVAL_SX_NOTINLIST:RETVAL_ACCESSDENIED;
  DWORD nWritten=0;
  WriteFile(hPipe,&g_RunData,sizeof(RUNDATA),&nWritten,0);
  CloseHandle(hPipe);
  //Wait for max 60s for the Password...
  for(int n=0;(g_RetVal==RETVAL_WAIT)&&(n<1000);n++)
    Sleep(60);
  if (bRunSetup)
    return RETVAL_OK;
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
    return RETVAL_OK;
  }
  return RETVAL_ACCESSDENIED;
}
