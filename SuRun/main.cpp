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
// QualifyPath
//
//////////////////////////////////////////////////////////////////////////////

//Combine path parts
void Combine(LPTSTR Dst,LPTSTR path,LPTSTR file,LPTSTR ext)
{
  _tcscpy(Dst,path);
  PathAppend(Dst,file);
  PathAddExtension(Dst,ext);
}

//Split path parts
void Split(LPTSTR app,LPTSTR path,LPTSTR file,LPTSTR ext)
{
  //Get Path
  _tcscpy(path,app);
  PathRemoveFileSpec(path);
  //Get File, Ext
  _tcscpy(file,app);
  PathStripPath(file);
  _tcscpy(ext,PathFindExtension(file));
  PathRemoveExtension(file);
}

BOOL QualifyPath(LPTSTR app,LPTSTR path,LPTSTR file,LPTSTR ext)
{
  static LPTSTR ExeExts[]={L".exe",L".lnk",L".cmd",L".bat",L".com",L".pif"};
  if (path[0]=='.')
  {
    //relative path: make it absolute
    _tcscpy(app,g_RunData.CurDir);
    PathAppend(app,path);
    PathCanonicalize(path,app);
    Combine(app,path,file,ext);
  }
  if ((path[0]=='\\'))
  {
    if(path[1]=='\\')
      //UNC path: must be fully qualified!
      return PathFileExists(app)
        && (!PathIsDirectory(app));
    //Root of current drive
    _tcscpy(path,g_RunData.CurDir);
    PathStripToRoot(path);
    Combine(app,path,file,ext);
  }
  if (path[0]==0)
  {
    _tcscpy(path,app);
    LPCTSTR d[2]={(LPCTSTR)&g_RunData.CurDir,0};
    // file.ext ->search in current dir and %path%
    if ((PathFindOnPath(path,d))&&(!PathIsDirectory(path)))
    {
      //Done!
      _tcscpy(app,path);
      PathRemoveFileSpec(path);
      return TRUE;
    }
    if (ext[0]==0) for (int i=0;i<countof(ExeExts);i++)
    //Not found! Try all Extensions for Executables
    // file ->search (exe,bat,cmd,com,pif,lnk) in current dir, search %path%
    {
      _stprintf(path,L"%s%s",file,ExeExts[i]);
      if ((PathFindOnPath(path,d))&&(!PathIsDirectory(path)))
      {
        //Done!
        _tcscpy(app,path);
        _tcscpy(ext,ExeExts[i]);
        PathRemoveFileSpec(path);
        return TRUE;
      }
    }
    return FALSE;
  }
  if (path[1]==':')
  {
    //if path=="d:" -> "cd d:"
    if (!SetCurrentDirectory(path))
      return false;
    //if path=="d:" -> "cd d:" -> "d:\documents"
    GetCurrentDirectory(4096,path);
    Combine(app,path,file,ext);
  }
  // d:\path\file.ext ->PathFileExists
  if (PathFileExists(app) && (!PathIsDirectory(app)))
    return TRUE;
  if (ext[0]==0) for (int i=0;i<countof(ExeExts);i++)
  //Not found! Try all Extensions for Executables
  // file ->search (exe,bat,cmd,com,pif,lnk) in path
  {
    Combine(app,path,file,ExeExts[i]);
    if ((PathFileExists(app))&&(!PathIsDirectory(app)))
    {
      //Done!
      _tcscpy(ext,ExeExts[i]);
      return TRUE;
    }
  }
  return FALSE;
}

//////////////////////////////////////////////////////////////////////////////
//
// ArgumentsToCommand: Based on SuDown (http://SuDown.sourceforge.net)
//
//////////////////////////////////////////////////////////////////////////////
BOOL ArgsToCommand(IN LPWSTR Args,OUT LPTSTR cmd)
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
  BOOL fExist=PathFileExists(app);
  //Split path parts
  TCHAR path[4096];
  TCHAR file[MAX_PATH+1];
  TCHAR ext[MAX_PATH+1];
  TCHAR SysDir[MAX_PATH+1];
  GetSystemDirectory(SysDir,MAX_PATH);
  Split(app,path,file,ext);
  //Explorer(.exe)
  if ((!fExist)&&(!_wcsicmp(app,L"explorer"))||(!_wcsicmp(app,L"explorer.exe")))
  {
    if (args[0]==0) 
      wcscpy(args,L"/e,C:");
    GetSystemWindowsDirectory(app,4096);
    PathAppend(app, L"explorer.exe");
  }else 
  //Msconfig(.exe) is not in path but found by windows
  if ((!fExist)&&(!_wcsicmp(app,L"msconfig"))||(!_wcsicmp(app,L"msconfig.exe")))
  {
    GetSystemWindowsDirectory(app,4096);
    PathAppend(app, L"pchealth\\helpctr\\binaries\\msconfig.exe");
    if (!PathFileExists(app))
      wcscpy(app,L"msconfig");
    zero(args);
  }else
  //Control Panel special folder files:
  if (((!fExist)
    &&((!_wcsicmp(app,L"control.exe"))||(!_wcsicmp(app,L"control"))) 
    && (args[0]==0))
    ||(fExist && (!_wcsicmp(path,SysDir)) && (!_wcsicmp(file,L"control")) && (!_wcsicmp(ext,L".exe"))))
  {
    GetSystemWindowsDirectory(app,4096);
    PathAppend(app,L"explorer.exe");
    if (LOBYTE(LOWORD(GetVersion()))<6)
      //2k/XP: Control Panel is beneath "my computer"!
      wcscpy(args,L"::{20D04FE0-3AEA-1069-A2D8-08002B30309D}\\::{21EC2020-3AEA-1069-A2DD-08002B30309D}");
    else
      //Vista: Control Panel is beneath desktop!
      wcscpy(args,L"::{21EC2020-3AEA-1069-A2DD-08002B30309D}");
  }else if (((!_wcsicmp(app,L"ncpa.cpl")) && (args[0]==0))
    ||(fExist && (!_wcsicmp(path,SysDir)) && (!_wcsicmp(file,L"ncpa")) && (!_wcsicmp(ext,L".cpl"))))
  {
    GetSystemWindowsDirectory(app,4096);
    PathAppend(app,L"explorer.exe");
    if (LOBYTE(LOWORD(GetVersion()))<6)
      //2k/XP: Control Panel is beneath "my computer"!
      wcscpy(args,L"::{20D04FE0-3AEA-1069-A2D8-08002B30309D}\\::{21EC2020-3AEA-1069-A2DD-08002B30309D}\\::{7007ACC7-3202-11D1-AAD2-00805FC1270E}");
    else
      //Vista: Control Panel is beneath desktop!
      wcscpy(args,L"::{21EC2020-3AEA-1069-A2DD-08002B30309D}\\::{7007ACC7-3202-11D1-AAD2-00805FC1270E}");
  }else 
  //*.reg files
  if (!_wcsicmp(ext, L".reg")) 
  {
    PathQuoteSpaces(app);
    wcscpy(args,app);
    GetSystemWindowsDirectory(app,4096);
    PathAppend(app, L"regedit.exe");
  }else
  //Control Panel files  
  if (!_wcsicmp(ext, L".cpl")) 
  {
    PathQuoteSpaces(app);
    if (args[0] && app[0])
      wcscat(app,L",");
    wcscat(app,args);
    wcscpy(args,L"shell32.dll,Control_RunDLLAsUser ");
    wcscat(args,app);
    GetSystemDirectory(app,4096);
    PathAppend(app,L"rundll32.exe");
  }else 
  //Windows Installer files  
  if (!_wcsicmp(ext, L".msi")) 
  {
    PathQuoteSpaces(app);
    if (args[0] && app[0])
    {
      wcscat(app,L" ");
      wcscat(app,args);
      wcscpy(args,app);
    }else
    {
      wcscpy(args,L"/i ");
      wcscat(args,app);
    }
    GetSystemDirectory(app,4096);
    PathAppend(app,L"msiexec.exe");
  }else 
  //Windows Management Console Sanp-In
  if (!_wcsicmp(ext, L".msc")) 
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
  }else
  //Try to fully qualify the executable:
  if (!QualifyPath(app,path,file,ext))
  {
    _tcscpy(app,Args);
    PathRemoveArgs(app);
    PathUnquoteSpaces(app);
    NetworkPathToUNCPath(app);
    Split(app,path,file,ext);
  }
  wcscpy(cmd,app);
  fExist=PathFileExists(app);
  PathQuoteSpaces(cmd);
  if (args[0] && app[0])
    wcscat(cmd,L" ");
  wcscat(cmd,args);
  return fExist;
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
  bool bRunSetup=FALSE;
  bool beQuiet=FALSE;
  bool bReturnPID=FALSE;
  LPTSTR Args=PathGetArgs(GetCommandLine());
  //Parse direct commands:
  while (Args[0]=='/')
  {
    LPTSTR c=Args;
    Args=PathGetArgs(Args);
    if (*(Args-1)==' ')
      *(Args-1)=0;
    if (!_wcsicmp(c,L"/QUIET"))
    {
      beQuiet=TRUE;
    }else
    if (!_wcsicmp(c,L"/SETUP"))
    {
      bRunSetup=TRUE;
      wcscpy(g_RunData.cmdLine,L"/SETUP");
      break;
    }else
    if (!_wcsicmp(c,L"/RETURNPID"))
    {
      bReturnPID=TRUE;
      break;
    }else
    if (!_wcsicmp(c,L"/TESTAUTOADMIN"))
    {
      g_RunData.bShlExHook=TRUE;
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
    if (!beQuiet)
      MessageBox(0,CBigResStr(IDS_USAGE),CResStr(IDS_APPNAME),MB_ICONSTOP);
    return bReturnPID?0:ERROR_INVALID_PARAMETER;
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
  //No Pipe handle: fail!
  if (hPipe==INVALID_HANDLE_VALUE)
    return bReturnPID?0:-2;
  zero(g_RunPwd);
  g_RunPwd[0]=0xFF;
  DWORD nWritten=0;
  WriteFile(hPipe,&g_RunData,sizeof(RUNDATA),&nWritten,0);
  CloseHandle(hPipe);
  int n=0;
  //Wait for max 60s for the Password...
  while ((g_RunPwd[0]==0xFF)&&(n<1000))
    Sleep(60);
  if (g_RunPwd[0]==0xFF)
    return bReturnPID?0:ERROR_ACCESS_DENIED;
  if (bRunSetup)
    return 0;
  if (g_RunPwd[0]==2) //ShellExec->NOT in List
    return -2;
  if (g_RunPwd[0]==3) //Restricted User, may not run App!
  {
    if (!beQuiet)
      MessageBox(0,
        CBigResStr(IDS_RUNRESTRICTED,g_RunData.UserName,g_RunData.cmdLine),
        CResStr(IDS_APPNAME),MB_ICONSTOP);
    return bReturnPID?0:-3;
  }
  if (g_RunPwd[0]==1)
    return bReturnPID?0:ERROR_ACCESS_DENIED;
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
    DWORD dwErr=GetLastError();
    if (!beQuiet)
      MessageBox(0,
        CResStr(IDS_RUNFAILED,g_RunData.cmdLine,GetErrorNameStatic(dwErr)),
        CResStr(IDS_APPNAME),MB_ICONSTOP);
    return bReturnPID?0:dwErr;
  }else
  {
    //Clear sensitive Data
    zero(g_RunPwd);
    zero(g_RunData);
    //Allow access to the Process and Thread to the Administrators and deny 
    //access for the current user
    SetAdminDenyUserAccess(pi.hThread);
    SetAdminDenyUserAccess(pi.hProcess);
    //Complain if the shell is runnig with administrative privileges:
    HANDLE hTok=GetShellProcessToken();
    if(hTok)
    {
      if(IsAdmin(hTok))
      {
        TCHAR s[MAX_PATH]={0};
        GetRegStr(HKEY_LOCAL_MACHINE,
          L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
          L"Shell",s,MAX_PATH);
        if (!beQuiet)
          MessageBox(0,CBigResStr(IDS_ADMINSHELL,s),CResStr(IDS_APPNAME),
          MB_ICONEXCLAMATION|MB_SETFOREGROUND);
      }
      CloseHandle(hTok);
    }
    //Start the main thread
    ResumeThread(pi.hThread);
    //Ok, we're done with the handles:
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
  }
  return bReturnPID?pi.dwProcessId:0;
}
