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
#include <tchar.h>
#include "TrayMsgWnd.h"
#include "Helpers.h"
#include "Setup.h"
#include "Resource.h"

#define Classname _T("SRTRMSGWND")
/////////////////////////////////////////////////////////////////////////////
//
// CTrayMsgWnd window
//
/////////////////////////////////////////////////////////////////////////////

class CTrayMsgWnd
{
public:
	CTrayMsgWnd(LPCTSTR DlgTitle,LPCTSTR Text,int IconId,DWORD TimeOut);
	~CTrayMsgWnd();
  bool MsgLoop();
  HWND m_hWnd;
protected:
  UINT WM_SRTRMSGWNDCLOSED;
  UINT WM_SRTRMSGWNDGETPOS;
  HFONT m_hFont;
  HBRUSH m_bkBrush;
  RECT m_wr;
  RECT m_dr;
  int m_DoSlide;
  HICON m_Icon;
private:
  static LRESULT CALLBACK WindowProc(HWND hWnd,UINT msg,WPARAM wParam,LPARAM lParam);
  LRESULT CALLBACK WinProc(UINT msg,WPARAM wParam,LPARAM lParam);
private:
  void MoveAboveOthers()
  {
    //CTimeLog l(L"MoveAboveOthers");
    SendMessageCallback(HWND_BROADCAST,WM_SRTRMSGWNDGETPOS,0,0,MaxYProc,(ULONG_PTR)this);
    int y=m_wr.bottom;
    CTimeOut t(100);
    //Wait 100ms until y does not change
    while (!t.TimedOut())
    {
      MSG msg;
      while (PeekMessage(&msg,0,0,0,PM_REMOVE))
      {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
      }
      if(y!=m_wr.bottom)
      {
        y=m_wr.bottom;
        t.Set(100);
      }
    }
  }
  static VOID CALLBACK MaxYProc(HWND hwnd,UINT uMsg,ULONG_PTR dwData,LRESULT lResult)
  {
    if(LOWORD(lResult)==10131)
      ((CTrayMsgWnd*)dwData)->MaxYProc(HIWORD(lResult));
  }
  VOID CALLBACK MaxYProc(int y)
  {
    if (m_wr.bottom>y)
      OffsetRect(&m_wr,0,y-m_wr.bottom);
  }
};

/////////////////////////////////////////////////////////////////////////////
//
// CTrayMsgWnd
//
/////////////////////////////////////////////////////////////////////////////

CTrayMsgWnd::CTrayMsgWnd(LPCTSTR DlgTitle,LPCTSTR Text,int IconId,DWORD TimeOut)
{
  LoadLibrary(_T("Shell32.dll"));//Load Shell Window Classes
  m_Icon=(HICON)LoadImage(GetModuleHandle(0),MAKEINTRESOURCE(IconId),IMAGE_ICON,16,16,0);

  WM_SRTRMSGWNDCLOSED=RegisterWindowMessage(_T("WM_SRTRMSGWNDCLOSED"));
  WM_SRTRMSGWNDGETPOS=RegisterWindowMessage(_T("WM_SRTRMSGWNDGETPOS"));
  m_DoSlide=0;
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
  SystemParametersInfo(SPI_GETWORKAREA,0,&m_dr,0);
  //Get Position:
  MoveAboveOthers();
  m_bkBrush=CreateSolidBrush(GetSysColor(COLOR_WINDOW));
  WNDCLASS wc={0};
  wc.lpfnWndProc=CTrayMsgWnd::WindowProc;
  wc.lpszClassName=Classname;
  wc.hbrBackground=m_bkBrush;
  RegisterClass(&wc);
  m_hWnd=CreateWindowEx(WS_EX_TOOLWINDOW|WS_EX_NOACTIVATE|WS_EX_TOPMOST,
    Classname,DlgTitle,WS_VISIBLE|WS_CAPTION|WS_SYSMENU|WS_BORDER,
    m_wr.left,m_wr.top,m_wr.right-m_wr.left,m_wr.bottom-m_wr.top,
    0,0,0,(LPVOID)this);
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
  if (TimeOut)
    SetTimer(m_hWnd,2,TimeOut,0);
  InvalidateRect(m_hWnd,0,1);
  UpdateWindow(m_hWnd);
  MsgLoop();
  SetWindowPos(m_hWnd,0,m_wr.left,m_wr.top,0,0,SWP_NOSIZE|SWP_NOZORDER|SWP_NOACTIVATE);
}

CTrayMsgWnd::~CTrayMsgWnd()
{
  if (IsWindow(m_hWnd))
    DestroyWindow(m_hWnd);
  DeleteObject(m_hFont);
  DestroyIcon(m_Icon);
  DeleteObject(m_bkBrush);
}

bool CTrayMsgWnd::MsgLoop()
{
  if (!IsWindow(m_hWnd))
    return FALSE;
  MSG msg;
  while (PeekMessage(&msg,0,0,0,PM_REMOVE))
  {
    TranslateMessage(&msg);
    DispatchMessage(&msg);
  }
  return TRUE;
}

LRESULT CALLBACK CTrayMsgWnd::WindowProc(HWND hWnd,UINT msg,WPARAM wParam,LPARAM lParam)
{
  CTrayMsgWnd* sw=(CTrayMsgWnd*)GetWindowLongPtr(hWnd,GWLP_USERDATA);
  if (sw)
    return sw->WinProc(msg,wParam,lParam);
  return DefWindowProc(hWnd,msg,wParam,lParam);
}

LRESULT CALLBACK CTrayMsgWnd::WinProc(UINT msg,WPARAM wParam,LPARAM lParam)
{
  switch (msg)
  {
  case WM_CLOSE:
    {
      KillTimer(m_hWnd,1);
      KillTimer(m_hWnd,2);
      SendNotifyMessage(HWND_BROADCAST,WM_SRTRMSGWNDCLOSED,
        MAKELONG(m_wr.left,m_wr.top),MAKELONG(m_wr.right,m_wr.bottom));
      DestroyWindow(m_hWnd);
    }
    return 0;
  case WM_CTLCOLORSTATIC:
    SetBkMode((HDC)wParam,TRANSPARENT);
  case WM_CTLCOLORDLG:
    return (DWORD_PTR)m_bkBrush;
  case WM_MOVING:
	  *((RECT*)lParam)=m_wr;
    return TRUE;
  case WM_DISPLAYCHANGE:
    {
      RECT dr;
      SystemParametersInfo(SPI_GETWORKAREA,0,&dr,0);
      if (memcmp(&m_dr,&dr,sizeof(RECT))!=0)
      {
        OffsetRect(&m_wr,dr.right-m_dr.right,dr.bottom-m_dr.bottom);
        SetWindowPos(m_hWnd,0,m_wr.left,m_wr.top,0,0,SWP_NOSIZE|SWP_NOZORDER|SWP_NOACTIVATE);
        m_dr=dr;
      }
    }
    return 0;
  case WM_TIMER:
    if (wParam==2)
    {
      KillTimer(m_hWnd,2);
      PostMessage(m_hWnd,WM_CLOSE,0,0);
    }else
    if (wParam==1)
    {
      if (m_DoSlide)
      {
        OffsetRect(&m_wr,0,min(5,m_DoSlide));
        SetWindowPos(m_hWnd,0,m_wr.left,m_wr.top,0,0,SWP_NOSIZE|SWP_NOZORDER|SWP_NOACTIVATE);
        m_DoSlide-=5;
      }
      if (m_DoSlide<=0)
      {
        m_DoSlide=0;
        KillTimer(m_hWnd,1);
      }
    }
    return 0;
  default:
    if (msg==WM_SRTRMSGWNDGETPOS)
      return MAKELONG(10131,m_wr.top);
    if (msg==WM_SRTRMSGWNDCLOSED)
    {
      int t=HIWORD(wParam);
      int b=HIWORD(lParam);
      if (m_wr.bottom<=t)
      {
        m_DoSlide+=b-t; 
        SetTimer(m_hWnd,1,10,0);
      }
      return 1;
    }
  }
  return DefWindowProc(m_hWnd,msg,wParam,lParam);
}

/////////////////////////////////////////////////////////////////////////////
//
//Public Message Functions:
//
/////////////////////////////////////////////////////////////////////////////
void TrayMsgWnd(LPCTSTR DlgTitle,LPCTSTR Message,int IconId,DWORD TimeOut)
{
  if (!GetShowAutoRuns)
    return;
  CTrayMsgWnd* w=new CTrayMsgWnd(DlgTitle,Message,IconId,TimeOut);
  int prio=GetThreadPriority(GetCurrentThread());
  SetThreadPriority(GetCurrentThread(),THREAD_PRIORITY_IDLE);
  while (w->MsgLoop())
    Sleep(10);
  SetThreadPriority(GetCurrentThread(),prio);
  delete w;
}
