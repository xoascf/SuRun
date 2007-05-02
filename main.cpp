#define _WIN32_WINNT 0x0500
#define WINVER       0x0500
#include <windows.h>
#include <shlwapi.h>
#include <stdio.h>
#include <tchar.h>
#include <lm.h>
#include "WinStaDesk.h"
#include "Helpers.h"
#include "ResStr.h"
#include "Service.h"
#include "DBGTrace.h"
#include "Resource.h"

#pragma comment(lib,"shlwapi.lib")

//////////////////////////////////////////////////////////////////////////////
//the App Icon is by Foood, "iCandy Junior", http://www.iconaholic.com
//the Shield Icons are taken from Windows XP Service Pack 2 (xpsp2res.dll)
//////////////////////////////////////////////////////////////////////////////

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
    wcscat(app, L" /n,/root,");
    if (args[0]==0) 
      wcscat(app, L"C:");
    else 
    {
      wcscat(app,args);
      zero(args);
    }
  }else if ((path[0]=='\0')&&(!_wcsicmp(file, L"msconfig")))
  {
    GetWindowsDirectory(app,4096);
    PathAppend(app, L"pchealth\\helpctr\\binaries\\msconfig.exe");
    if (!PathFileExists(app))
      wcscpy(app,L"msconfig");
    zero(args);
  }else if ((path[0]=='\0')&&(!_wcsicmp(file, L"control"))) 
  {
    GetSystemDirectory(app,4096);
    PathAppend(app,L"control.exe");
    zero(args);
  }else if (!_wcsicmp(ext, L".cpl")) 
  {
    PathQuoteSpaces(app);
    if (args[0] && app[0])
      wcscat(app,L" ");
    wcscat(app,args);
    wcscpy(args,app);
    GetSystemDirectory(app,4096);
    PathAppend(app,L"control.exe");
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
    if (path[0]=='\0')
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
  WaitForSingleObject(hProcess, 2500);
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
  PathStripPath(g_RunData.UserName);//strip computer name!
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
      *(Args-1)='\0';
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
    LoadLibrary(_T("Shell32.dll"));//To make MessageBox work with Themes
    MessageBox(0,CBigResStr(IDS_USAGE),0,MB_ICONSTOP);
    return -1;
  }
  //Lets go:
  HANDLE hPipe=CreateFile(ServicePipeName,GENERIC_WRITE,0,0,OPEN_EXISTING,0,0);
  if (hPipe!=INVALID_HANDLE_VALUE)
  {
    //Go!
    zero(g_RunPwd);
    g_RunPwd[0]=0xFF;
    DWORD nWritten=0;
    WriteFile(hPipe,&g_RunData,sizeof(RUNDATA),&nWritten,0);
    CloseHandle(hPipe);
    int n=0;
    while ((g_RunPwd[0]==0xFF)&&(n<1000))
      Sleep(55);
    if ((g_RunPwd[0]==0xFF)
      ||(g_RunPwd[0]==1)
      || bRunSetup)
      return 0;
    PROCESS_INFORMATION pi={0};
    STARTUPINFO si={0};
    si.cb = sizeof(STARTUPINFO);
    if(!CreateProcessWithLogonW(g_RunData.UserName,NULL,g_RunPwd,
      LOGON_WITH_PROFILE,NULL,g_RunData.cmdLine,CREATE_UNICODE_ENVIRONMENT,
      NULL,g_RunData.CurDir,&si,&pi))
    {
      MessageBox(0,
        CResStr(IDS_RUNFAILED,g_RunData.cmdLine,GetLastErrorNameStatic()),
        CResStr(IDS_APPNAME),MB_ICONSTOP);
    }
  }
  return 0;
}
