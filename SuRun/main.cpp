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
//the Sheild Icons are taken from Windows XP Service Pack 2 (xpsp2res.dll)
//////////////////////////////////////////////////////////////////////////////

int WINAPI WinMain(HINSTANCE hInst,HINSTANCE hPrevInst,LPSTR lpCmdLine,int nCmdShow)
{
  TCHAR cmd[4096]={0};
  _tcsncpy(cmd,PathGetArgs(GetCommandLine()),4095);
  NetworkPathToUNCPath(cmd);
  if (!cmd[0])
  {
    LoadLibrary(_T("Shell32.dll"));//To make MessageBox work with Themes
    MessageBox(0,CBigResStr(IDS_USAGE),0,MB_ICONSTOP);
    return -1;
  }
  HANDLE hPipe=CreateFile(ServicePipeName,GENERIC_WRITE,0,0,OPEN_EXISTING,0,0);
  if (hPipe!=INVALID_HANDLE_VALUE)
  {
    //Session
    DWORD SessionId=0;
    ProcessIdToSessionId(GetCurrentProcessId(),&SessionId);
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
    WriteFile(hPipe,WinSta,_tcslen(WinSta)*sizeof(TCHAR),&nWritten,0);
    WriteFile(hPipe,Desk,_tcslen(Desk)*sizeof(TCHAR),&nWritten,0);
    WriteFile(hPipe,UserName,_tcslen(UserName)*sizeof(TCHAR),&nWritten,0);
    WriteFile(hPipe,cmd,_tcslen(cmd)*sizeof(TCHAR),&nWritten,0);
    WriteFile(hPipe,Dir,_tcslen(Dir)*sizeof(TCHAR),&nWritten,0);
    CloseHandle(hPipe);
  }
  return 0;
}
