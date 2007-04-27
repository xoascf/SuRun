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
static BOOL CALLBACK TerminateAppEnum( HWND hwnd, LPARAM lParam )
{
  DWORD dwID ;
  GetWindowThreadProcessId(hwnd, &dwID) ;
  if(dwID == (DWORD)lParam)
    PostMessage(hwnd, WM_CLOSE, 0, 0) ;
  return TRUE ;
}

void KillProcessNice(DWORD PID)
{
  if (!PID)
    return;
  HANDLE hProcess=OpenProcess(SYNCHRONIZE|PROCESS_TERMINATE,TRUE,PID);
  if(!hProcess)
    return;
  // TerminateAppEnum() posts WM_CLOSE to all windows whose PID
  // matches your process's.
  ::EnumWindows(TerminateAppEnum,(LPARAM)PID);
  // Wait on the handle. If it signals, great. 
  WaitForSingleObject(hProcess, 5000);
  CloseHandle(hProcess);
}

//////////////////////////////////////////////////////////////////////////////
//
// WinMain
//
//////////////////////////////////////////////////////////////////////////////
int WINAPI WinMain(HINSTANCE hInst,HINSTANCE hPrevInst,LPSTR lpCmdLine,int nCmdShow)
{
  TCHAR cmd[4096]={0};
  BOOL bRunSetup=FALSE;
  DWORD KillPID=0;
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
      wcscpy(cmd,L"/SETUP");
      break;
    }else
    if (!_wcsicmp(c,L"/KILL"))
    {
      KillPID=wcstol(Args,0,10);
      Args=PathGetArgs(Args);
      KillProcessNice(KillPID);
    }
  }
  //Convert Command Line
  if (!bRunSetup)
    ArgsToCommand(Args,cmd);
  //Usage
  if (!cmd[0])
  {
    LoadLibrary(_T("Shell32.dll"));//To make MessageBox work with Themes
    MessageBox(0,CBigResStr(IDS_USAGE),0,MB_ICONSTOP);
    return -1;
  }
  //Lets go:
  HANDLE hPipe=CreateFile(ServicePipeName,GENERIC_WRITE,0,0,OPEN_EXISTING,0,0);
  if (hPipe!=INVALID_HANDLE_VALUE)
  {
    //Session
    DWORD SessionId=0;
    ProcessIdToSessionId(GetCurrentProcessId(),&SessionId);
    //User:
    HANDLE hCallingUser=0;
    EnablePrivilege(SE_DEBUG_NAME);
    HANDLE hProc=OpenProcess(PROCESS_ALL_ACCESS,TRUE,GetCurrentProcessId());
    if (hProc)
    {
      HANDLE hToken=0;
      OpenProcessToken(hProc,TOKEN_IMPERSONATE|TOKEN_QUERY|TOKEN_DUPLICATE
        |TOKEN_ASSIGN_PRIMARY,&hToken);
      CloseHandle(hProc);
      if(hToken)
      {
        DuplicateTokenEx(hToken,MAXIMUM_ALLOWED,NULL,SecurityIdentification,
          TokenPrimary,&hCallingUser); 
        CloseHandle(hToken);
      }
    }
    //WindowStation
    TCHAR WinSta[MAX_PATH];
    GetWinStaName(WinSta,MAX_PATH);
    //Desktop
    TCHAR Desk[MAX_PATH];
    GetDesktopName(Desk,MAX_PATH);
    //UserName
    TCHAR UserName[DNLEN+UNLEN+2];
    DWORD len=DNLEN+UNLEN+1;
    GetProcessUserName(GetCurrentProcessId(),UserName);
    //Current Directory
    TCHAR Dir[MAX_PATH]={0};
    GetCurrentDirectory(MAX_PATH,Dir);
    NetworkPathToUNCPath(Dir);
    //Go!
    DWORD nWritten=0;
    WriteFile(hPipe,&SessionId,sizeof(SessionId),&nWritten,0);
    WriteFile(hPipe,&hCallingUser,sizeof(hCallingUser),&nWritten,0);
    WriteFile(hPipe,WinSta,_tcslen(WinSta)*sizeof(TCHAR),&nWritten,0);
    WriteFile(hPipe,Desk,_tcslen(Desk)*sizeof(TCHAR),&nWritten,0);
    WriteFile(hPipe,UserName,_tcslen(UserName)*sizeof(TCHAR),&nWritten,0);
    WriteFile(hPipe,cmd,_tcslen(cmd)*sizeof(TCHAR),&nWritten,0);
    WriteFile(hPipe,Dir,_tcslen(Dir)*sizeof(TCHAR),&nWritten,0);
    WriteFile(hPipe,&KillPID,sizeof(KillPID),&nWritten,0);
    CloseHandle(hPipe);
  }
  return 0;
}
