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
#include "DBGTrace.h"

#pragma comment(lib,"ShlWapi.lib")
#pragma comment(lib,"advapi32.lib")
#pragma comment(lib,"Wtsapi32.lib")

#define CLASSNAME     _T("SuRunTrayShowAdminClass")
#define MENU_SURUNSETUP WM_USER+903

extern RUNDATA g_RunData;

bool g_BallonTips=1;
BOOL g_ForegroundWndIsAdmin=-1;
HWND g_FgWnd=0;
HINSTANCE g_hInstance=0;
TCHAR g_User[MAX_PATH*2+2]={0};
NOTIFYICONDATA g_NotyData={0};

struct
{
  DWORD CurProcId;
  TCHAR CurUserName[UNLEN+GNLEN+2];
  BOOL CurUserIsadmin;
}g_TSAData={0};

DWORD g_TSAPID=0;
BOOL g_TSAThreadRunning=FALSE;

//TSAThreadProc is called from Service!
DWORD WINAPI TSAThreadProc(void* p)
{
  HANDLE hProc=OpenProcess(PROCESS_ALL_ACCESS,0,(DWORD)(DWORD_PTR)p);
  if (!hProc)
    return 0;
  struct
  {
    DWORD CurProcId;
    TCHAR CurUserName[UNLEN+GNLEN+2];
    BOOL CurUserIsadmin;
  }TSAData={0};
  DWORD PID=0;
  BOOL TSAThreadRunning=TRUE;
  WriteProcessMemory(hProc,&g_TSAThreadRunning,&TSAThreadRunning,sizeof(g_TSAThreadRunning),0);
  EnablePrivilege(SE_DEBUG_NAME);
  for(;;)
  {
    SIZE_T s;
    if ((WaitForSingleObject(hProc,333)==WAIT_OBJECT_0)
     ||(!ReadProcessMemory(hProc,&g_TSAPID,&TSAData.CurProcId,sizeof(DWORD),&s))
     ||(sizeof(DWORD)!=s))
      return CloseHandle(hProc),0;
    if (TSAData.CurProcId!=PID)
    {
      HANDLE h = OpenProcess(PROCESS_ALL_ACCESS,TRUE,TSAData.CurProcId);
      if(h)
      {
        HANDLE hTok=0;
        if (OpenProcessToken(h,TOKEN_QUERY|TOKEN_DUPLICATE,&hTok))
        {
          GetTokenUserName(hTok,TSAData.CurUserName);
          TSAData.CurUserIsadmin=IsAdmin(hTok);
          CloseHandle(hTok);
          if(WriteProcessMemory(hProc,&g_TSAData,&TSAData,sizeof(g_TSAData),&s)
            && (s==sizeof(g_TSAData)))
            PID=TSAData.CurProcId;
          else
            DBGTrace1("WriteProcessMemory failed: %s",GetLastErrorNameStatic());
        }else
          DBGTrace1("OpenProcessToken failed: %s",GetLastErrorNameStatic());
        CloseHandle(h);
      }//else
        //DBGTrace2("OpenProcess(%d) failed: %s",TSAData.CurProcId,GetLastErrorNameStatic());
    }
  }
}

BOOL StartTSAThread()
{
  if (g_TSAThreadRunning)
    return TRUE;
  g_TSAPID=0;
  zero(g_TSAData);
  g_RunData.KillPID=0xFFFFFFFF;
  _tcscpy(g_RunData.cmdLine,_T("/TSATHREAD"));
  g_RetVal=RETVAL_WAIT;
  HANDLE hPipe=CreateFile(ServicePipeName,GENERIC_WRITE,0,0,OPEN_EXISTING,0,0);
  if(hPipe==INVALID_HANDLE_VALUE)
    return FALSE;
  DWORD n=0;
  WriteFile(hPipe,&g_RunData,sizeof(RUNDATA),&n,0);
  CloseHandle(hPipe);
  Sleep(10);
  for(n=0;(!g_TSAThreadRunning)&&(n<100);n++)
    Sleep(100);
  return g_TSAThreadRunning;
}

static BOOL ForegroundWndIsAdmin(LPTSTR User,HWND& wnd,LPTSTR WndTitle)
{
  if (!StartTSAThread())
    return -1;
  wnd=GetForegroundWindow();
  if (!wnd)
    return -1;
  HWND w=GetParent(wnd);
  while (w)
  {
    wnd=w;
    w=GetParent(wnd);
  }
  GetWindowThreadProcessId(wnd,&g_TSAPID);
  _tcscpy(User,g_TSAData.CurUserName);
  if (!g_TSAData.CurProcId)
    return -1;
  if (!InternalGetWindowText(wnd,WndTitle,MAX_PATH))
    _stprintf(WndTitle,L"Process %d",g_TSAData.CurProcId);
  return g_TSAData.CurUserIsadmin;
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
    /*&&(g_FgWnd==FgWnd)*/)
    return;
  g_FgWnd=FgWnd;
  g_ForegroundWndIsAdmin=bIsFGAdm;
  _tcscpy(g_User,User);
  memset(&g_NotyData.szInfo,0,sizeof(g_NotyData.szInfo));
  _stprintf(g_NotyData.szTip,_T("SuRun %s"),GetVersionString());
  BOOL bDiffUser=_tcscmp(User,g_RunData.UserName);
  if (bIsFGAdm==-1)
  {
    g_NotyData.hIcon=(HICON)LoadImage(g_hInstance,MAKEINTRESOURCE(IDI_NOWINDOW),
                                        IMAGE_ICON,16,16,LR_DEFAULTCOLOR);
  }else if (bIsFGAdm)
  {
    g_NotyData.hIcon=(HICON)LoadImage(g_hInstance,
      MAKEINTRESOURCE(bDiffUser?IDI_ADMIN:(g_CliIsAdmin?IDI_SHADMIN:IDI_SRADMIN)),
                            IMAGE_ICON,16,16,LR_DEFAULTCOLOR);
    if (g_BallonTips && bDiffUser)
      _stprintf(g_NotyData.szInfo,_T("\"%s\"\n\"%s\" - Administrator"),WndTxt,User);
    _stprintf(g_NotyData.szTip,_T("\"%s\"\n\"%s\" - Administrator"),WndTxt,User);
  }else
  {
    g_NotyData.hIcon=(HICON)LoadImage(g_hInstance,MAKEINTRESOURCE(IDI_NOADMIN),
                                        IMAGE_ICON,16,16,LR_DEFAULTCOLOR);
    if (g_BallonTips && bDiffUser)
      _stprintf(g_NotyData.szInfo,_T("\"%s\"\n\"%s\" - Standard user"),WndTxt,User);
    _stprintf(g_NotyData.szTip,_T("\"%s\"\n\"%s\" - Standard user"),WndTxt,User);
  }
  if (!Shell_NotifyIcon(NIM_MODIFY,&g_NotyData))
  {
    Shell_NotifyIcon(NIM_ADD,&g_NotyData);
    g_NotyData.uVersion=NOTIFYICON_VERSION;
    Shell_NotifyIcon(NIM_SETVERSION,&g_NotyData);
  }
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
  AllowSetForegroundWindow(GetCurrentProcessId());
  SetForegroundWindow(hWnd);
  switch (TrackPopupMenu(hMenu,TPM_RIGHTALIGN|TPM_RETURNCMD|TPM_NONOTIFY|TPM_VERNEGANIMATION,
    pt.x-1,pt.y-1,0,hWnd,NULL))
  {
  case MENU_SURUNSETUP:
    ShellExecute(0,_T("open"),_T("SuRun.exe"),_T("/SETUP"),0,SW_SHOWNORMAL);
    break;
  }
  DestroyMenu(hMenu);
  g_BallonTips=bBTip;
};

//int g_HotKeyID=0;

LRESULT CALLBACK WndMainProc(HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam)
{
  switch (message)
  {
  case WM_USER+1758:
    {
      switch (lParam)
      {
      case NIN_BALLOONSHOW:
        break;
      case NIN_BALLOONHIDE:
        //other App active
      case NIN_BALLOONTIMEOUT:
        //Click on [X] or TimeOut
      case NIN_BALLOONUSERCLICK:
        //Click in Balloon
        break;
      case WM_LBUTTONDOWN:
      case WM_RBUTTONDOWN:
      case WM_CONTEXTMENU:
        DisplayMenu(hwnd);
        return 0;
      case WM_LBUTTONDBLCLK:
        ShellExecute(0,_T("open"),_T("SuRun.exe"),_T("/SETUP"),0,SW_SHOWNORMAL);
        return 0;
      }
    }
    break;
  case WM_QUERYENDSESSION:
    {
      //ToDo: Warn, if SuRun processes are still running.
    }
    break;
  }
  return DefWindowProc(hwnd , message, wParam, lParam);
}

void InitTrayShowAdmin()
{
  g_hInstance=GetModuleHandle(0);
  g_CliIsAdmin=FALSE;
  HANDLE hTok=GetShellProcessToken();
  if(hTok)
  {
    g_CliIsAdmin=IsAdmin(hTok)!=0;
    CloseHandle(hTok);
  }
  WNDCLASS WCLASS={0};
  WCLASS.hCursor      =LoadCursor(0,IDC_ARROW);
  WCLASS.lpszClassName=CLASSNAME;
  WCLASS.hInstance    =g_hInstance;
  WCLASS.style        =CS_BYTEALIGNCLIENT | CS_BYTEALIGNWINDOW;
  WCLASS.lpfnWndProc  =&WndMainProc;
  RegisterClass(&WCLASS);
  g_NotyData.cbSize= sizeof(NOTIFYICONDATA);
  g_NotyData.hWnd  = CreateWindowEx(WS_EX_TOOLWINDOW|WS_EX_NOACTIVATE,
                                    CLASSNAME,_T("SuRunTrayShowAdmin"),
                                    WS_POPUP,0,0,0,0,0,0,g_hInstance,NULL);
  g_NotyData.hIcon = (HICON)LoadImage(g_hInstance,MAKEINTRESOURCE(IDI_NOWINDOW),
                                        IMAGE_ICON,16,16,LR_DEFAULTCOLOR);
  
  _stprintf(g_NotyData.szTip,_T("SuRun %s"),GetVersionString());
  _stprintf(g_NotyData.szInfoTitle,_T("SuRun %s"),GetVersionString());
  g_NotyData.dwInfoFlags=NIIF_INFO|NIIF_NOSOUND;
  g_NotyData.uID   = 1;
  g_NotyData.uFlags= NIF_ICON|NIF_TIP|NIF_INFO|NIF_MESSAGE;
  g_NotyData.uCallbackMessage = WM_USER+1758;
  g_NotyData.uTimeout=10000;
}

BOOL ProcessTrayShowAdmin(BOOL bBalloon)
{
  g_BallonTips=bBalloon!=0;
  DisplayIcon();
  MSG msg;
  int count=0;
  while (PeekMessage(&msg,0,0,0,PM_REMOVE) && (count++<10))
  {
    TranslateMessage(&msg);
    DispatchMessage(&msg);
  }
  return count>0;
}

void CloseTrayShowAdmin()
{
  Shell_NotifyIcon(NIM_DELETE,&g_NotyData);
  DestroyWindow(g_NotyData.hWnd);
}
