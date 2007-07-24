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
//                                   (c) Kay Bruns (http://kay-bruns.de), 2007
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
#include "DBGTrace.h"
#include "Resource.h"

#pragma comment(lib,"shlwapi.lib")
#pragma comment(lib,"netapi32.lib")

//////////////////////////////////////////////////////////////////////////////
//
// ArgumentsToCommand: Based on SuDown (http://SuDown.sourceforge.net)
//
//////////////////////////////////////////////////////////////////////////////
VOID ArgsToCommand(LPWSTR Args, LPTSTR cmd)
{
  //Save parameters
  TCHAR args[4096]={0};
  _tcscpy(args,PathGetArgs(Args));
  //Application
  TCHAR app[4096]={0};
  _tcscpy(app,Args);
  PathRemoveArgs(app);
  PathUnquoteSpaces(app);
  NetworkPathToUNCPath(app);
  //Get Path
  TCHAR path[4096];
  _tcscpy(path,app);
  PathRemoveFileSpec(path);
  //Get File
  TCHAR file[MAX_PATH];
  _tcscpy(file,app);
  PathStripPath(file);
  //Get Ext
  TCHAR ext[MAX_PATH];
  _tcscpy(ext,PathFindExtension(file));
  PathRemoveExtension(file);
   if ((path[0]=='\0')&&(!_wcsicmp(file,L"explorer")) )
  {
    wcscpy(app,L"/n,/root,");
    if (args[0]==0) 
      wcscat(app, L"C:");
    else 
      wcscat(app,args);
    wcscpy(args,app);
    GetSystemWindowsDirectory(app,4096);
    PathAppend(app, L"explorer.exe");
  }else if ((path[0]==0)&&(!_wcsicmp(file,L"msconfig")))
  {
    GetSystemWindowsDirectory(app,4096);
    PathAppend(app, L"pchealth\\helpctr\\binaries\\msconfig.exe");
    if (!PathFileExists(app))
      wcscpy(app,L"msconfig");
    zero(args);
  }else if (((!_wcsicmp(app,L"control.exe"))||(!_wcsicmp(app,L"control"))) 
            && (args[0]==0))
  {
    GetSystemWindowsDirectory(app,4096);
    PathAppend(app,L"explorer.exe");
    wcscpy(args,L"::{20D04FE0-3AEA-1069-A2D8-08002B30309D}\\::{21EC2020-3AEA-1069-A2DD-08002B30309D}");
  }else if ((!_wcsicmp(app,L"ncpa.cpl")) 
            && (args[0]==0))
  {
    GetSystemWindowsDirectory(app,4096);
    PathAppend(app,L"explorer.exe");
    wcscpy(args,L"::{20D04FE0-3AEA-1069-A2D8-08002B30309D}\\::{21EC2020-3AEA-1069-A2DD-08002B30309D}\\::{7007ACC7-3202-11D1-AAD2-00805FC1270E}");
  }else if (!_wcsicmp(ext, L".cpl")) 
  {
    PathQuoteSpaces(app);
    if (args[0] && app[0])
      wcscat(app,L",");
    wcscat(app,args);
    wcscpy(args,L"shell32.dll,Control_RunDLLAsUser ");
    wcscat(args,app);
    GetSystemDirectory(app,4096);
    PathAppend(app,L"rundll32.exe");
  }else if (!_wcsicmp(ext, L".msi")) 
  {
    PathQuoteSpaces(app);
    if (args[0] && app[0])
      wcscat(app,L" ");
    wcscat(app,args);
    wcscpy(args,app);
    GetSystemDirectory(app,4096);
    PathAppend(app,L"msiexec.exe");
  }else if (!_wcsicmp(ext, L".msc")) 
  {
    if (path[0]==0)
    {
      GetSystemDirectory(path,4096);
      PathAppend(path,app);
      wcscpy(app,path);
      zero(path);
    }
    PathQuoteSpaces(app);
    if (args[0] && app[0])
      wcscat(app,L" ");
    wcscat(app,args);
    wcscpy(args,app);
    GetSystemDirectory(app,4096);
    PathAppend(app,L"mmc.exe");
  }
  wcscpy(cmd,app);
  PathQuoteSpaces(cmd);
  if (args[0] && app[0])
    wcscat(cmd,L" ");
  wcscat(cmd,args);
}

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
// WinMain
//
//////////////////////////////////////////////////////////////////////////////
int WINAPI WinMain(HINSTANCE hInst,HINSTANCE hPrevInst,LPSTR lpCmdLine,int nCmdShow)
{
  LoadLibrary(_T("Shell32.dll"));//To make MessageBox work with Themes
  zero(g_RunData);
  //ProcessId
  g_RunData.CliProcessId=GetCurrentProcessId();
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
  BOOL bRunSetup=FALSE;
  LPTSTR Args=PathGetArgs(GetCommandLine());
  //Parse direct commands:
  while (Args[0]=='/')
  {
    LPTSTR c=Args;
    Args=PathGetArgs(Args);
    if (*(Args-1)==' ')
      *(Args-1)=0;
    if (!_wcsicmp(c,L"/SETUP"))
    {
      bRunSetup=TRUE;
      wcscpy(g_RunData.cmdLine,L"/SETUP");
      break;
    }else
    if (!_wcsicmp(c,L"/KILL"))
    {
      g_RunData.KillPID=wcstol(Args,0,10);
      Args=PathGetArgs(Args);
      KillProcessNice(g_RunData.KillPID);
    }
  }
  //Convert Command Line
  if (!bRunSetup)
    ArgsToCommand(Args,g_RunData.cmdLine);
  //Usage
  if (!g_RunData.cmdLine[0])
  {
    MessageBox(0,CBigResStr(IDS_USAGE),CResStr(IDS_APPNAME),MB_ICONSTOP);
    return -1;
  }
  //Lets go:
  HANDLE hPipe=INVALID_HANDLE_VALUE;
  //retry if the pipe is busy: (max 240s)
  for(int i=0;i<720;i++)
  {
    hPipe=CreateFile(ServicePipeName,GENERIC_WRITE,0,0,OPEN_EXISTING,0,0);
    if(hPipe!=INVALID_HANDLE_VALUE)
      break;
    Sleep(250);
  }
  if (hPipe!=INVALID_HANDLE_VALUE)
  {
    zero(g_RunPwd);
    g_RunPwd[0]=0xFF;
    DWORD nWritten=0;
    WriteFile(hPipe,&g_RunData,sizeof(RUNDATA),&nWritten,0);
    CloseHandle(hPipe);
    int n=0;
    //Wait for max 60s for the Password...
    while ((g_RunPwd[0]==0xFF)&&(n<1000))
      Sleep(60);
    if ((g_RunPwd[0]==0xFF)
      ||(g_RunPwd[0]==1)
      || bRunSetup)
      return 0;
    PROCESS_INFORMATION pi={0};
    STARTUPINFO si={0};
    si.cb = sizeof(STARTUPINFO);
    TCHAR un[2*UNLEN]={0};
    TCHAR dn[2*UNLEN]={0};
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
      MessageBox(0,
        CResStr(IDS_RUNFAILED,g_RunData.cmdLine,GetLastErrorNameStatic()),
        CResStr(IDS_APPNAME),MB_ICONSTOP);
    }else
    {
      //Allow access to the Process and Thread to the Administrators and deny 
      //access for the current user
      SetAdminDenyUserAccess(pi.hThread);
      SetAdminDenyUserAccess(pi.hProcess);
      //Start the main thread
      ResumeThread(pi.hThread);
      //Ok, we're done with the handles:
      CloseHandle(pi.hThread);
      CloseHandle(pi.hProcess);
    }
    //Clear sensitive Data
    zero(g_RunPwd);
    zero(g_RunData);
    //Complain if the shell is runnig with administrative privileges:
    DWORD ShellID=0;
    GetWindowThreadProcessId(GetDesktopWindow(),&ShellID);
    if (ShellID)
    {
      HANDLE hShell=OpenProcess(PROCESS_QUERY_INFORMATION,0,ShellID);
      if (IsAdmin(hShell))
        MessageBox(0,CBigResStr(IDS_ADMINSHELL),CResStr(IDS_APPNAME),MB_ICONEXCLAMATION|MB_SERVICE_NOTIFICATION);
    }
  }
  return 0;
}
