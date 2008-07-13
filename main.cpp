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

//#define GetSeparateProcess(k) GetRegInt(k,\
//                    _T("Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced"),\
//                    _T("SeparateProcess"),0)
//#define SetSeparateProcess(k,b) SetRegInt(k,\
//                    _T("Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced"),\
//                    _T("SeparateProcess"),b)
//
//#define DESKTOPPROXYCLASS   TEXT("Proxy Desktop")
//
//BOOL CALLBACK KillProxyDesktopEnum1(HWND hwnd, LPARAM lParam)
//{
//  TCHAR cn[MAX_PATH];
//  GetClassName(hwnd, cn, countof(cn));
//  if (_tcsicmp(cn, DESKTOPPROXYCLASS)==0)
//  {
//    if(lParam)
//    {
//      DWORD pid=0;
//      GetWindowThreadProcessId(hwnd,&pid);
//      if (pid==*((DWORD*)lParam))
//      {
//        SendMessage(hwnd,WM_CLOSE,0,0);
//        *((DWORD*)lParam)=0;
//        return FALSE;
//      }
//    }else
//      SendMessage(hwnd,WM_CLOSE,0,0);
//  }
//  return TRUE;
//}
//
//#include <USERENV.H>
//#include "LSALogon.h"
//void test()
//{
//  _tcscpy(g_RunData.cmdLine,L"C:\\WINDOWS\\explorer.exe ::{20D04FE0-3AEA-1069-A2D8-08002B30309D}\\::{21EC2020-3AEA-1069-A2DD-08002B30309D}");
//  _tcscpy(g_RunData.CurDir,L"C:\\WINDOWS");
//  DWORD SessionID=0;
//  HANDLE hAdmin=GetAdminToken(SessionID);
//  SetTokenInformation(hAdmin,TokenSessionId,&SessionID,sizeof(DWORD));
//  PROFILEINFO ProfInf = {sizeof(ProfInf),0,L"BRUNS\\Kay"};
//  if(!LoadUserProfile(hAdmin,&ProfInf))
//    return;
//  void* Env=0;
//  if (CreateEnvironmentBlock(&Env,hAdmin,FALSE))
//  {
//    PROCESS_INFORMATION pi={0};
//    STARTUPINFO si={0};
//    si.cb	= sizeof(si);
//    //Special handling for Explorer:
//    BOOL orgSP=FALSE;
//    BOOL bIsExplorer=FALSE;
//    {
//      TCHAR app[MAX_PATH]={0};
//      GetSystemWindowsDirectory(app,4096);
//      PathAppend(app,L"explorer.exe");
//      TCHAR cmd[MAX_PATH]={0};
//      _tcscpy(cmd,g_RunData.cmdLine);
//      PathRemoveArgs(cmd);
//      PathUnquoteSpaces(cmd);
//      bIsExplorer=_tcscmp(cmd,app)==0;
//    }
//    if(bIsExplorer)
//    {
//      //To start control Panel and other Explorer children we need to tell 
//      //Explorer to open folders in a new proecess
//      orgSP=GetSeparateProcess((HKEY)ProfInf.hProfile);
//      SetSeparateProcess((HKEY)ProfInf.hProfile,1);
//      //Messages work on the same WinSta/Desk only
//      SetProcWinStaDesk(g_RunData.WinSta,g_RunData.Desk);
//      //call DestroyWindow() for each "Desktop Proxy" Windows Class in an 
//      //Explorer.exe, this will cause a new Explorer.exe to stay running
//      EnumWindows(KillProxyDesktopEnum1,0);
//    }
//    //CreateProcessAsUser will only work from an NT System Account since the
//    //Privilege SE_ASSIGNPRIMARYTOKEN_NAME is not present elsewhere
//    EnablePrivilege(SE_ASSIGNPRIMARYTOKEN_NAME);
//    EnablePrivilege(SE_INCREASE_QUOTA_NAME);
//    if (CreateProcessAsUser(hAdmin,NULL,g_RunData.cmdLine,NULL,NULL,FALSE,
//      CREATE_UNICODE_ENVIRONMENT,Env,g_RunData.CurDir,&si,&pi))
//    {
//      DBGTrace1("CreateProcessAsUser(%s) OK",g_RunData.cmdLine);
//      if(bIsExplorer)
//      {
//        //Messages work on the same WinSta/Desk only
//        SetProcWinStaDesk(g_RunData.WinSta,g_RunData.Desk);
//        //call DestroyWindow() for each "Desktop Proxy" Windows Class in an 
//        //Explorer.exe, this will cause a new Explorer.exe to stay running
//        CTimeOut to(10000);
//        DWORD pid=pi.dwProcessId;
//        while ((!to.TimedOut()) 
//          && pid && EnumWindows(KillProxyDesktopEnum1,(LPARAM)&pid)
//          && (WaitForSingleObject(pi.hProcess,100)==WAIT_TIMEOUT));
//      }
//      CloseHandle(pi.hThread);
//      CloseHandle(pi.hProcess);
//    }else
//      DBGTrace1("CreateProcessAsUser failed: %s",GetLastErrorNameStatic());
//    if(bIsExplorer &&(!orgSP))
//      SetSeparateProcess((HKEY)ProfInf.hProfile,orgSP);
//    DestroyEnvironmentBlock(Env);
//  }else
//    DBGTrace1("CreateEnvironmentBlock failed: %s",GetLastErrorNameStatic());
//  UnloadUserProfile(hAdmin,ProfInf.hProfile);
//  CloseHandle(hAdmin);
//}

//////////////////////////////////////////////////////////////////////////////
//
// WinMain
//
//////////////////////////////////////////////////////////////////////////////
//extern BOOL TestSetup();

int WINAPI WinMain(HINSTANCE hInst,HINSTANCE hPrevInst,LPSTR lpCmdLine,int nCmdShow)
{
//  TestSetup();
//  test();
//  ExitProcess(0);
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
  //Current Directory
  GetCurrentDirectory(countof(g_RunData.CurDir),g_RunData.CurDir);
  NetworkPathToUNCPath(g_RunData.CurDir);
  bool bRunSetup=FALSE;
  //cmdLine
  {
    LPTSTR args=_tcsdup(PathGetArgs(GetCommandLine()));
    LPTSTR Args=args;
    //Parse direct commands:
    if (HideSuRun(g_RunData.UserName))
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
      }if (!_wcsicmp(c,L"/RUNAS"))
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
      }else if (!_wcsicmp(c,L"/KILL"))
      {
        g_RunData.KillPID=wcstol(Args,0,10);
        Args=PathGetArgs(Args);
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
      if (IsInSuRunners(g_RunData.UserName) && bShellIsadmin)
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
