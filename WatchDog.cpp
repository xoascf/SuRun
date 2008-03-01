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
#include "DBGTrace.h"
#include "Service.h"
#include "Setup.h"
#include "WinstaDesk.h"

#include "Resource.h"

#define Classname _T("SRWDMSGWND")
/////////////////////////////////////////////////////////////////////////////
//
// CWDMsgWnd window
//
/////////////////////////////////////////////////////////////////////////////

class CWDMsgWnd
{
public:
	CWDMsgWnd(LPCTSTR Text,int IconId);
	~CWDMsgWnd();
  bool MsgLoop();
protected:
  bool m_Clicked;
  HWND m_hWnd;
  HFONT m_hFont;
  HBRUSH m_bkBrush;
  RECT m_wr;
  HICON m_Icon;
private:
  static LRESULT CALLBACK WindowProc(HWND hWnd,UINT msg,WPARAM wParam,LPARAM lParam);
  LRESULT CALLBACK WinProc(UINT msg,WPARAM wParam,LPARAM lParam);
};

/////////////////////////////////////////////////////////////////////////////
//
// CWDMsgWnd
//
/////////////////////////////////////////////////////////////////////////////
#ifdef DoDBGTrace
extern RUNDATA g_RunData;
#endif DoDBGTrace

CWDMsgWnd::CWDMsgWnd(LPCTSTR Text,int IconId)
{
#ifdef DoDBGTrace
//  GetWinStaName(g_RunData.WinSta,countof(g_RunData.WinSta));
//  GetDesktopName(g_RunData.Desk,countof(g_RunData.Desk));
//  DBGTrace2("CWDMsgWnd() on %s\\%s",g_RunData.WinSta,g_RunData.Desk);
#endif DoDBGTrace
  m_Clicked=FALSE;
  LoadLibrary(_T("Shell32.dll"));//Load Shell Window Classes
  m_Icon=(HICON)LoadImage(GetModuleHandle(0),MAKEINTRESOURCE(IconId),IMAGE_ICON,16,16,0);
  m_hFont=CreateFont(-14,0,0,0,FW_MEDIUM,0,0,0,0,0,0,0,0,_T("MS Shell Dlg"));
  {
    //Desktop Rect
    RECT rd={0};
    SystemParametersInfo(SPI_GETWORKAREA,0,&rd,0);
    //Client Rect
    HDC MemDC=CreateCompatibleDC(0);
    SelectObject(MemDC,m_hFont);
    m_wr.left=0;
    m_wr.top=0;
    m_wr.right=200;
    m_wr.bottom=800;
    DrawText(MemDC,Text,-1,&m_wr,DT_CALCRECT|DT_NOCLIP|DT_NOPREFIX|DT_EXPANDTABS);
    //Limit the width the screen width
    int maxDX=GetSystemMetrics(SM_CXFULLSCREEN)-40;
    if (m_wr.right-m_wr.left>maxDX)
    {
      TEXTMETRIC tm;
      GetTextMetrics(MemDC,&tm);
      m_wr.bottom+=tm.tmHeight*((m_wr.right-m_wr.left)/maxDX);
      m_wr.right=maxDX;
    }
    //Icon height
    m_wr.bottom=max(m_wr.top+16,m_wr.bottom);
    //Window Rect
    m_wr.right+=2*GetSystemMetrics(SM_CXDLGFRAME)+10+16+5;
    m_wr.bottom+=2*GetSystemMetrics(SM_CYDLGFRAME)+GetSystemMetrics(SM_CYSMCAPTION)+10;
    OffsetRect(&m_wr,rd.right-m_wr.right+m_wr.left,rd.bottom-m_wr.bottom+m_wr.top);
  }
  m_bkBrush=CreateSolidBrush(GetSysColor(COLOR_WINDOW));
  WNDCLASS wc={0};
  wc.lpfnWndProc=CWDMsgWnd::WindowProc;
  wc.lpszClassName=Classname;
  wc.hbrBackground=m_bkBrush;
  wc.hCursor=LoadCursor(0,IDC_HAND);
  RegisterClass(&wc);
  m_hWnd=CreateWindowEx(WS_EX_TOOLWINDOW|WS_EX_NOACTIVATE|WS_EX_TOPMOST,
    Classname,_T("SuRun"),WS_VISIBLE|WS_DLGFRAME,
    m_wr.left,m_wr.top,m_wr.right-m_wr.left,m_wr.bottom-m_wr.top,
    0,0,0,(LPVOID)this);
  if (!m_hWnd)
    DBGTrace("No Window!")
  else
    DBGTrace4("Window at %d,%d,%d,%d",m_wr.left,m_wr.top,m_wr.right-m_wr.left,m_wr.bottom-m_wr.top);
  SetWindowLongPtr(m_hWnd,GWLP_USERDATA,(LONG_PTR)this);
  RECT cr;
  GetClientRect(m_hWnd,&cr);
  InflateRect(&cr,-5,-5);
  //Icon:
  cr.right=cr.left+16;
  cr.bottom=cr.top+16;
  HWND s=CreateWindowEx(0,_T("Static"),Text,WS_CHILD|WS_VISIBLE|SS_ICON|SS_CENTERIMAGE,
    cr.left,cr.top,cr.right-cr.left,cr.bottom-cr.top,m_hWnd,0,0,0);
  SendMessage(s,STM_SETIMAGE,IMAGE_ICON,(LPARAM)m_Icon);
  s=0;
  //Static:
  GetClientRect(m_hWnd,&cr);
  InflateRect(&cr,-5,-5);
  cr.left+=16+5;
  s=CreateWindowEx(0,_T("Static"),Text,WS_CHILD|WS_VISIBLE|SS_NOPREFIX,
    cr.left,cr.top,cr.right-cr.left,cr.bottom-cr.top,m_hWnd,0,0,0);
  SendMessage(s,WM_SETFONT,(WPARAM)m_hFont,1);
  InvalidateRect(m_hWnd,0,1);
  UpdateWindow(m_hWnd);
  MsgLoop();
  SetWindowPos(m_hWnd,0,m_wr.left,m_wr.top,0,0,SWP_NOSIZE|SWP_NOZORDER|SWP_NOACTIVATE);
}

CWDMsgWnd::~CWDMsgWnd()
{
  if (IsWindow(m_hWnd))
    DestroyWindow(m_hWnd);
  DeleteObject(m_hFont);
  DestroyIcon(m_Icon);
  DeleteObject(m_bkBrush);
}

bool CWDMsgWnd::MsgLoop()
{
  if (m_Clicked)
    return FALSE;
  if (!IsWindow(m_hWnd))
  {
    DBGTrace("No Window!");
    return FALSE;
  }
  MSG msg;
  while (PeekMessage(&msg,0,0,0,PM_REMOVE))
  {
    TranslateMessage(&msg);
    DispatchMessage(&msg);
  }
  return TRUE;
}

LRESULT CALLBACK CWDMsgWnd::WindowProc(HWND hWnd,UINT msg,WPARAM wParam,LPARAM lParam)
{
  CWDMsgWnd* sw=(CWDMsgWnd*)GetWindowLongPtr(hWnd,GWLP_USERDATA);
  if (sw)
    return sw->WinProc(msg,wParam,lParam);
  return DefWindowProc(hWnd,msg,wParam,lParam);
}

LRESULT CALLBACK CWDMsgWnd::WinProc(UINT msg,WPARAM wParam,LPARAM lParam)
{
  switch (msg)
  {
  case WM_CLOSE:
    DestroyWindow(m_hWnd);
    return 0;
  case WM_CTLCOLORSTATIC:
    SetBkMode((HDC)wParam,TRANSPARENT);
  case WM_CTLCOLORDLG:
    return (DWORD_PTR)m_bkBrush;
  case WM_MOVING:
	  *((RECT*)lParam)=m_wr;
    return TRUE;
  case WM_QUERYENDSESSION://Block LogOff!
    return (lParam&ENDSESSION_LOGOFF)?FALSE:TRUE;
  case WM_LBUTTONDOWN:
    m_Clicked=TRUE;
    //fall through
  }
  return DefWindowProc(m_hWnd,msg,wParam,lParam);
}

/////////////////////////////////////////////////////////////////////////////
//
//
//
/////////////////////////////////////////////////////////////////////////////
extern HANDLE g_WatchDogEvent;

static void SwitchToDesk(LPCTSTR Desk)
{
  HDESK d=OpenDesktop(Desk,0,FALSE,DESKTOP_SWITCHDESKTOP);
  SwitchDesktop(d);
  CloseDesktop(d);
}

static bool ProcessRunning(DWORD PID)
{
  HANDLE hProc=OpenProcess(SYNCHRONIZE,0,PID);
  if (!hProc)
  {
    DBGTrace2("OpenProcess(%d) failed: %s",PID,GetLastErrorNameStatic());
    return false;
  }
  DWORD WaitRes=WaitForSingleObject(hProc,0);
  CloseHandle(hProc);
#ifdef DoDBGTrace
  if(WaitRes!=WAIT_TIMEOUT)
    DBGTrace1("ProcessRunning failed: Wait result==%08X",WaitRes);
#endif DoDBGTrace
  return WaitRes==WAIT_TIMEOUT;
}

static void EnsureProcRunning(DWORD PID,LPCTSTR UserDesk)
{
  if (!ProcessRunning(PID))
  {
    DBGTrace1("SuRun GUI Process %d is not running: WatchDog exit!",PID);
    SwitchToDesk(UserDesk);
    ExitProcess(0);
  }
}

void DoWatchDog(LPCTSTR SafeDesk,LPCTSTR UserDesk,DWORD ParentPID)
{
  SetProcWinStaDesk(0,SafeDesk);
  g_WatchDogEvent=OpenEvent(EVENT_ALL_ACCESS,0,WATCHDOG_EVENT_NAME);
  if (!g_WatchDogEvent)
  {
    DBGTrace1("FATAL: Failed to open WatchDog Event: %s",GetLastErrorNameStatic());
    return;
  }
  for(;;)
  {
    //Switch to SuRun's desktop
    SwitchToDesk(SafeDesk);
    //Exit if SuRun was killed
    EnsureProcRunning(ParentPID,UserDesk);
    ResetEvent(g_WatchDogEvent);
    BOOL bShowUserDesk=FALSE;
    if (WaitForSingleObject(g_WatchDogEvent,2000)==WAIT_TIMEOUT) 
    {
      CWDMsgWnd* w=new CWDMsgWnd(CBigResStr(IDS_SURUNSTUCK),IDI_SHIELD2);
      while (WaitForSingleObject(g_WatchDogEvent,0)==WAIT_TIMEOUT)
      {
        //Exit if SuRun was killed
        EnsureProcRunning(ParentPID,UserDesk);
        if (!w->MsgLoop())
        {
          bShowUserDesk=TRUE;
          break;
        }
      }
      delete w;
    }
    if(bShowUserDesk)
    {
      //Set Access to the user Desktop
      HANDLE hTok=0;
      OpenProcessToken(GetCurrentProcess(),TOKEN_ALL_ACCESS,&hTok);
      SetAccessToWinDesk(hTok,0,UserDesk,true);
      SetProcWinStaDesk(0,UserDesk);
      //Switch to the user desktop
      SwitchToDesk(UserDesk);
      //Show Window
      CWDMsgWnd* w=new CWDMsgWnd(CBigResStr(IDS_SWITCHBACK),IDI_SHIELD);
      //Turn off Hooks when displaying the user desktop!
      DWORD bIATHk=GetUseIATHook;
      DWORD bIShHk=GetUseIShExHook;
      SetUseIATHook(0);
      SetUseIShExHook(0);
      while (w->MsgLoop())
      {
        //Exit if SuRun was killed
        EnsureProcRunning(ParentPID,UserDesk);
        Sleep(10);
      }
      delete w;
      w=0;
      //Turn on Hooks if they where on!
      SetUseIShExHook(bIShHk);
      SetUseIATHook(bIATHk);
      //Switch back to SuRun's desktop
      SwitchToDesk(SafeDesk);
      //Revoke access from user desktop
      SetProcWinStaDesk(0,SafeDesk);
      SetAccessToWinDesk(hTok,0,UserDesk,false);
      CloseHandle(hTok);
      hTok=0;
    }
  }
  //DoWatchDog never returns! 
  //SuRun uses TerminateProcess() in DeleteSafeDesktop
}