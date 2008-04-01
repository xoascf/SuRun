#define _WIN32_IE    0x0600
#define _WIN32_WINNT 0x0500
#define WINVER       0x0500
#include <windows.h>
#include <LMAccess.h>
#include <SHLWAPI.H>
#include <TCHAR.h>
#include <stdio.h>
#include "helpers.h"
#include "IsAdmin.h"
#include "service.h"
#include "setup.h"
#include "resstr.h"
#include "resource.h"

#pragma comment(lib,"ShlWapi.lib")
#pragma comment(lib,"advapi32.lib")
#pragma comment(lib,"Wtsapi32.lib")

#define CLASSNAME     _T("SuRunTrayShowAdminClass")
#define MENU_SURUNSETUP WM_USER+903

bool g_BallonTips=1;
BOOL g_ForegroundWndIsAdmin=-1;
HWND g_FgWnd=0;
HINSTANCE g_hInstance=0;
TCHAR g_User[MAX_PATH*2+2]={0};
NOTIFYICONDATA g_NotyData={0};

static BOOL ForegroundWndIsAdmin(LPTSTR User,HWND& wnd,LPTSTR WndTitle)
{
  DWORD ProcId=0;
  wnd=GetForegroundWindow();
  if (!wnd)
    return -1;
  GetWindowThreadProcessId(wnd,&ProcId);
  GetProcessUserName(ProcId,User);
  //...ToDo: IPC->Service!
  if (!GetWindowText(wnd,WndTitle,MAX_PATH))
    _stprintf(WndTitle,_T("Process %d"),ProcId);
  HANDLE h=OpenProcess(PROCESS_QUERY_INFORMATION,FALSE,ProcId);
  if (!h)
    return TRUE;
  HANDLE hTok=0;
  if (!OpenProcessToken(h,TOKEN_DUPLICATE,&hTok))
    return CloseHandle(h),TRUE;
  CloseHandle(h);
  BOOL bAdmin=IsAdmin(hTok);
  CloseHandle(hTok);
  return bAdmin;
}

static void DisplayIcon()
{
  HICON OldIcon=g_NotyData.hIcon;
  TCHAR User[MAX_PATH*2+2]={0};
  TCHAR WndTxt[MAX_PATH+1]={0};
  HWND FgWnd=0;
  BOOL bIsFGAdm=ForegroundWndIsAdmin(User,FgWnd,WndTxt);
  if (_tcslen(WndTxt)>64)
  {
    WndTxt[61]='.';
    WndTxt[62]='.';
    WndTxt[63]='.';
    WndTxt[64]=0;
  }
  if (_tcslen(User)>32)
  {
    WndTxt[29]='.';
    WndTxt[30]='.';
    WndTxt[31]='.';
    WndTxt[32]=0;
  }
  if ((g_ForegroundWndIsAdmin==bIsFGAdm)
    && (_tcscmp(g_User,User)==0)
    &&(g_FgWnd==FgWnd))
    return;
  g_FgWnd=FgWnd;
  g_ForegroundWndIsAdmin=bIsFGAdm;
  _tcscpy(g_User,User);
  memset(&g_NotyData.szInfo,0,sizeof(g_NotyData.szInfo));
  _stprintf(g_NotyData.szTip,_T("SuRun %s"),GetVersionString());
  if (bIsFGAdm==-1)
  {
    g_NotyData.hIcon=(HICON)LoadImage(g_hInstance,MAKEINTRESOURCE(IDI_NOWINDOW),
                                        IMAGE_ICON,16,16,LR_DEFAULTCOLOR);
  }else if (bIsFGAdm)
  {
    g_NotyData.hIcon=(HICON)LoadImage(g_hInstance,MAKEINTRESOURCE(IDI_ADMIN),
                                        IMAGE_ICON,16,16,LR_DEFAULTCOLOR);
    if (g_BallonTips && (_tcscmp(User,g_RunData.UserName) || (!g_CliIsAdmin)))
      _stprintf(g_NotyData.szInfo,_T("\"%s\"\n\"%s\" - Administrator"),WndTxt,User);
    _stprintf(g_NotyData.szTip,_T("\"%s\"\n\"%s\" - Administrator"),WndTxt,User);
  }else
  {
    g_NotyData.hIcon=(HICON)LoadImage(g_hInstance,MAKEINTRESOURCE(IDI_NOADMIN),
                                        IMAGE_ICON,16,16,LR_DEFAULTCOLOR);
    if (g_BallonTips && (_tcscmp(User,g_RunData.UserName) || g_CliIsAdmin))
      _stprintf(g_NotyData.szInfo,_T("\"%s\"\n\"%s\" - Standard user"),WndTxt,User);
    _stprintf(g_NotyData.szTip,_T("\"%s\"\n\"%s\" - Standard user"),WndTxt,User);
  }
  Shell_NotifyIcon(NIM_MODIFY,&g_NotyData);
  DestroyIcon(OldIcon);
};

void MenuAdd(HMENU hMenu,LPTSTR Text,int CMD,int Flags)
{
  MENUITEMINFO mii;
  ZeroMemory(&mii, sizeof(mii));
  mii.cbSize = sizeof(mii);
  mii.fMask = MIIM_ID | MIIM_TYPE | MIIM_STATE | MIIM_CHECKMARKS;
  mii.wID = CMD;
  mii.fType = MFT_STRING;
  mii.dwTypeData = Text;
  mii.fState = Flags;
  InsertMenuItem(hMenu,GetMenuItemCount(hMenu),TRUE,&mii);
}

void DisplayMenu(HWND hWnd)
{
  bool bBTip=g_BallonTips;
  g_BallonTips=0;
  if (bBTip)
  {
    //Close Balloon
    memset(&g_NotyData.szInfo,0,sizeof(g_NotyData.szInfo));
    _stprintf(g_NotyData.szTip,_T("SuRun %s"),GetVersionString());
    Shell_NotifyIcon(NIM_MODIFY,&g_NotyData);
  }
  POINT pt;
  GetCursorPos(&pt);
  HMENU hMenu=CreatePopupMenu();
  MenuAdd(hMenu,CResStr(_T("SuRun %s"),GetVersionString()),(UINT)-1,MFS_DEFAULT);
  AppendMenu(hMenu,MF_SEPARATOR,(UINT)-1,0);
  MenuAdd(hMenu,CResStr(IDS_CPLNAME),MENU_SURUNSETUP,0);
  switch (TrackPopupMenu(hMenu,TPM_RIGHTALIGN|TPM_RETURNCMD|TPM_NONOTIFY|TPM_VERNEGANIMATION,
    pt.x+1,pt.y+1,0,hWnd,NULL))
  {
  case MENU_SURUNSETUP:
    ShellExecute(0,_T("open"),_T("SuRun.exe"),_T("/SETUP"),0,SW_SHOWNORMAL);
    break;
  }
  DestroyMenu(hMenu);
  g_BallonTips=bBTip;
};

LRESULT CALLBACK WndMainProc(HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam)
{
  switch (message)
  {
  case WM_USER+1758:
    {
      switch (lParam)
      {
      case WM_LBUTTONDOWN:
      case WM_RBUTTONDOWN:
      case WM_CONTEXTMENU:
        DisplayMenu(hwnd);
        return 0;
      };
    };
    break;
  }
  return DefWindowProc(hwnd , message, wParam, lParam);
}

void InitTrayShowAdmin()
{
  g_hInstance=GetModuleHandle(0);
  WNDCLASS WCLASS={0};
  WCLASS.hCursor      =LoadCursor(0,IDC_ARROW);
  WCLASS.lpszClassName=CLASSNAME;
  WCLASS.hInstance    =g_hInstance;
  WCLASS.style        =CS_BYTEALIGNCLIENT | CS_BYTEALIGNWINDOW;
  WCLASS.lpfnWndProc  =&WndMainProc;
  RegisterClass(&WCLASS);
  g_NotyData.cbSize= sizeof(NOTIFYICONDATA);
  g_NotyData.hWnd  = CreateWindowEx(0,CLASSNAME,_T("SuRunTrayShowAdmin"),
                                    WS_POPUP,0,0,0,0,0,0,g_hInstance,NULL);
  g_NotyData.hIcon = (HICON)LoadImage(g_hInstance,MAKEINTRESOURCE(IDI_NOWINDOW),
                                        IMAGE_ICON,16,16,LR_DEFAULTCOLOR);
  
  _stprintf(g_NotyData.szTip,_T("SuRun %s"),GetVersionString());
  _stprintf(g_NotyData.szInfoTitle,_T("SuRun %s"),GetVersionString());
  g_NotyData.dwInfoFlags=NIIF_INFO|NIIF_NOSOUND;
  g_NotyData.uID   = 1;
  g_NotyData.uFlags= NIF_ICON|NIF_TIP|NIF_INFO|NIF_MESSAGE;
  g_NotyData.uCallbackMessage = WM_USER+1758;
  Shell_NotifyIcon(NIM_ADD,&g_NotyData);
  

  g_NotyData.uVersion=NOTIFYICON_VERSION;
  Shell_NotifyIcon(NIM_SETVERSION,&g_NotyData);
  g_NotyData.uTimeout=10000;
}

BOOL ProcessTrayShowAdmin()
{
  g_BallonTips=GetShowTrayAdmin==2;
  DisplayIcon();
  MSG msg={0};
  if(PeekMessage(&msg,NULL,0,0,PM_REMOVE))
  {
    TranslateMessage(&msg);
    DispatchMessage(&msg);
    return TRUE;
  }
  return FALSE;
}

void CloseTrayShowAdmin()
{
  Shell_NotifyIcon(NIM_DELETE,&g_NotyData);
  DestroyWindow(g_NotyData.hWnd);
}
