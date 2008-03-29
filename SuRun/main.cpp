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
#include <shlwapi.h>
#include <stdio.h>
#include <tchar.h>
#include <lm.h>
#include "WinStaDesk.h"
#include "IsAdmin.h"
#include "Helpers.h"
#include "ResStr.h"
#include "Service.h"
#include "TrayMsgWnd.h"
#include "DBGTrace.h"
#include "UserGroups.h"
#include "Resource.h"

#pragma comment(lib,"shlwapi.lib")
#pragma comment(lib,"netapi32.lib")
#ifndef _WIN64
#pragma comment(linker,"/DELAYLOAD:advapi32.dll")
#ifdef _SR32
#pragma comment(linker,"/DELAYLOAD:surunext32.dll")
#else _SR32
#pragma comment(linker,"/DELAYLOAD:surunext.dll")
#endif _SR32
#pragma comment(linker,"/DELAYLOAD:mpr.dll")
#pragma comment(linker,"/DELAYLOAD:version.dll")
#pragma comment(linker,"/DELAYLOAD:comctl32.dll")
#pragma comment(linker,"/DELAYLOAD:userenv.dll")
#pragma comment(linker,"/DELAYLOAD:comdlg32.dll")
#pragma comment(linker,"/DELAYLOAD:gdi32.dll")
#pragma comment(linker,"/DELAYLOAD:user32.dll")
#pragma comment(linker,"/DELAYLOAD:shell32.dll")
#pragma comment(linker,"/DELAYLOAD:shlwapi.dll")
#pragma comment(linker,"/DELAYLOAD:ole32.dll")
#pragma comment(linker,"/DELAYLOAD:netapi32.dll")
#pragma comment(linker,"/DELAYLOAD:psapi.dll")
#pragma comment(lib,"Delayimp")
#endif _WIN64

//////////////////////////////////////////////////////////////////////////////
// 
//  KillProcessNice
// 
//////////////////////////////////////////////////////////////////////////////
// callback function for window enumeration
static BOOL CALLBACK CloseAppEnum(HWND hwnd,LPARAM lParam )
{
  DWORD dwID ;
  GetWindowThreadProcessId(hwnd, &dwID) ;
  if(dwID==(DWORD)lParam)
    PostMessage(hwnd,WM_CLOSE,0,0) ;
  return TRUE ;
}

void KillProcessNice(DWORD PID)
{
  if (!PID)
    return;
  HANDLE hProcess=OpenProcess(SYNCHRONIZE,TRUE,PID);
  if(!hProcess)
    return;
  //Post WM_CLOSE to all Windows of PID
  EnumWindows(CloseAppEnum,(LPARAM)PID);
  //Give the Process time to close
  WaitForSingleObject(hProcess,2500);
  CloseHandle(hProcess);
  //The service will call TerminateProcess()...
}

//////////////////////////////////////////////////////////////////////////////
// 
//  Run()...the Trampoline
// 
//////////////////////////////////////////////////////////////////////////////
int Run()
{
  PROCESS_INFORMATION pi={0};
  STARTUPINFO si={0};
  si.cb = sizeof(STARTUPINFO);
  TCHAR un[2*UNLEN+2]={0};
  TCHAR dn[2*UNLEN+2]={0};
  _tcscpy(un,g_RunData.UserName);
  PathStripPath(un);
  _tcscpy(dn,g_RunData.UserName);
  PathRemoveFileSpec(dn);
  //To start control Panel and other Explorer children we need to tell 
  //Explorer to start a new Process:
  SetRegInt(HKEY_CURRENT_USER,
    L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced",
    L"SeparateProcess",1);
  //Create the process suspended to revoke access for the current user 
  //before it starts runnung
  if(!CreateProcessWithLogonW(un,dn,g_RunPwd,LOGON_WITH_PROFILE,NULL,
    g_RunData.cmdLine,CREATE_UNICODE_ENVIRONMENT|CREATE_SUSPENDED,NULL,
    g_RunData.CurDir,&si,&pi))
  {
    //Clear sensitive Data
    zero(g_RunPwd);
    return RETVAL_ACCESSDENIED;
  }else
  {
    //Clear sensitive Data
    zero(g_RunPwd);
    //Allow access to the Process and Thread to the Administrators and deny 
    //access for the current user
    SetAdminDenyUserAccess(pi.hThread);
    SetAdminDenyUserAccess(pi.hProcess);
    //Start the main thread
    ResumeThread(pi.hThread);
    //Ok, we're done with the handles:
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    //ShellExec-Hook: We must return the PID and TID to fake CreateProcess:
    if((g_RunData.RetPID)&&(g_RunData.RetPtr))
    {
      pi.hThread=0;
      pi.hProcess=0;
      HANDLE hProcess=OpenProcess(PROCESS_VM_OPERATION|PROCESS_VM_WRITE,FALSE,g_RunData.RetPID);
      if (hProcess)
      {
        SIZE_T n;
        if (!WriteProcessMemory(hProcess,(LPVOID)g_RunData.RetPtr,&pi,sizeof(PROCESS_INFORMATION),&n))
          DBGTrace2("AutoSuRun(%s) WriteProcessMemory failed: %s",
            g_RunData.cmdLine,GetLastErrorNameStatic());
        CloseHandle(hProcess);
      }else
        DBGTrace2("AutoSuRun(%s) OpenProcess failed: %s",
          g_RunData.cmdLine,GetLastErrorNameStatic());
    }
    zero(g_RunData);
    return RETVAL_OK;
  }
}

//////////////////////////////////////////////////////////////////////////////
//
// WinMain
//
//////////////////////////////////////////////////////////////////////////////
int WINAPI WinMain(HINSTANCE hInst,HINSTANCE hPrevInst,LPSTR lpCmdLine,int nCmdShow)
{
  if(HandleServiceStuff())
    return 0;
  //After the User presses OK, the service starts a clean SuRun exe with the 
  //Clients user token, it fills g_RunData and g_RunPwd
  //We must Do this for two reasons:
  //1. CreateProcessWithLogonW does not work directly from the service
  //2. IAT-Hookers may have infect the Client-SuRun.exe and intercept
  //   CreateProcessWithLogonW. If SuRun.exe is directly started from the 
  //   service, no common injection methods will work.
  if (g_RunData.CliProcessId==GetCurrentProcessId())
    //Started from services:
    return Run();
  if (g_RunData.CliThreadId==GetCurrentThreadId())
  {
    //Started from services:
    //Show ToolTip "<Program> is running elevated"...
    TrayMsgWnd(CResStr(IDS_APPNAME),CBigResStr(IDS_STARTED,g_RunData.cmdLine));
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
  //Current Directory
  GetCurrentDirectory(countof(g_RunData.CurDir),g_RunData.CurDir);
  NetworkPathToUNCPath(g_RunData.CurDir);
  //cmdLine
  LPTSTR Args=PathGetArgs(GetCommandLine());
  //Parse direct commands:
  bool bRunSetup=FALSE;
  while (Args[0]=='/')
  {
    LPTSTR c=Args;
    Args=PathGetArgs(Args);
    if (*(Args-1)==' ')
      *(Args-1)=0;
    if (!_wcsicmp(c,L"/QUIET"))
    {
      g_RunData.beQuiet=TRUE;
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
    }else if (!_wcsicmp(c,L"/KILL"))
    {
      g_RunData.KillPID=wcstol(Args,0,10);
      Args=PathGetArgs(Args);
      KillProcessNice(g_RunData.KillPID);
    }
  }
  //Convert Command Line
  if (!bRunSetup)
  {
    //If shell is Admin but User is SuRunner, the Shell must be restarted
    if (IsInSuRunners(g_RunData.UserName))
    {
      //Complain if shell user is an admin!
      HANDLE hTok=GetShellProcessToken();
      if(hTok)
      {
        BOOL bAdmin=IsAdmin(hTok);
        CloseHandle(hTok);
        if (bAdmin)
        {
          SafeMsgBox(0,CResStr(IDS_ADMINSHELL),CResStr(IDS_APPNAME),MB_ICONEXCLAMATION|MB_SETFOREGROUND);
          return RETVAL_ACCESSDENIED;
        }
        
      }
    }  
    ResolveCommandLine(Args,g_RunData.CurDir,g_RunData.cmdLine);
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
  //For Vista! The Thread Desktop is not set per default...
  HDESK hDesk=OpenInputDesktop(0,FALSE,DESKTOP_SWITCHDESKTOP);
  DWORD nWritten=0;
  WriteFile(hPipe,&g_RunData,sizeof(RUNDATA),&nWritten,0);
  CloseHandle(hPipe);
  //Wait for max 60s for the Password...
  for(int n=0;(g_RetVal==RETVAL_WAIT)&&(n<1000);n++)
    Sleep(60);
  //For Vista! The Thread Desktop is not set per default...
  SwitchDesktop(hDesk);
  CloseDesktop(hDesk);
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
