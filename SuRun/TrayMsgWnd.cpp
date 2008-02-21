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
#include <tchar.h>
#include "TrayMsgWnd.h"

/////////////////////////////////////////////////////////////////////////////
// CTrayMsgWnd window

class CTrayMsgWnd
{
public:
	CTrayMsgWnd(LPCTSTR DlgTitle,LPCTSTR Text);
	~CTrayMsgWnd();
  void Slide(int Height);
  bool MsgLoop();
  HWND m_hWnd;
protected:
  HFONT m_hFont;
  HBRUSH m_bkBrush;
  RECT m_wr;
  int m_DoSlide;
private:
  static LRESULT CALLBACK WindowProc(HWND hWnd,UINT msg,WPARAM wParam,LPARAM lParam);
  LRESULT CALLBACK WinProc(UINT msg,WPARAM wParam,LPARAM lParam);
};

/////////////////////////////////////////////////////////////////////////////
//Public Message Functions:
/////////////////////////////////////////////////////////////////////////////
#ifndef WS_EX_NOACTIVATE
#define WS_EX_NOACTIVATE        0x08000000L
#endif

void TrayMsgWnd(LPCTSTR DlgTitle,LPCTSTR Message)
{
  int prio=GetThreadPriority(GetCurrentThread());
  SetThreadPriority(GetCurrentThread(),THREAD_PRIORITY_IDLE);
  CTrayMsgWnd* w=new CTrayMsgWnd(DlgTitle,Message);
  while (w->MsgLoop())
    Sleep(10);
  delete w;
  SetThreadPriority(GetCurrentThread(),prio);
}

/////////////////////////////////////////////////////////////////////////////
// CTrayMsgWnd

#define Classname _T("SRTRMSGWND")
CTrayMsgWnd::CTrayMsgWnd(LPCTSTR DlgTitle,LPCTSTR Text)
{
  LoadLibrary(_T("Shell32.dll"));//Load Shell Window Classes
  m_DoSlide=0;
  m_hFont=CreateFont(-10,0,0,0,FW_MEDIUM,0,0,0,0,0,0,0,0,_T("MS Shell Dlg"));
  {
    HDC MemDC=CreateCompatibleDC(0);
    SelectObject(MemDC,m_hFont);
    m_wr.left=0;
    m_wr.top=0;
    m_wr.right=200;
    m_wr.bottom=400;
    DrawText(MemDC,Text,-1,&m_wr,DT_CALCRECT|DT_NOCLIP|DT_NOPREFIX|DT_EXPANDTABS);
    m_wr.right+=2*GetSystemMetrics(SM_CXDLGFRAME)+10;
    m_wr.bottom+=2*GetSystemMetrics(SM_CYDLGFRAME)+GetSystemMetrics(SM_CYSMCAPTION)+10;
    //Window Rect
    RECT rd={0};
    SystemParametersInfo(SPI_GETWORKAREA,0,&rd,0);
    OffsetRect(&m_wr,rd.right-m_wr.right+m_wr.left,rd.bottom-m_wr.bottom+m_wr.top);
    HWND w=WindowFromPoint(*((POINT*)&m_wr.left));
    while (w)
    {
      TCHAR cn[32];
      if (GetClassName(w,cn,31) && _tcsicmp(cn,Classname)==0)
        w=WindowFromPoint(*((POINT*)&m_wr.left));
      else
        w=0;
    }
  }
  m_bkBrush=CreateSolidBrush(GetSysColor(COLOR_WINDOW));
  WNDCLASS wc={0};
  wc.lpfnWndProc=CTrayMsgWnd::WindowProc;
  wc.lpszClassName=Classname;
  wc.hbrBackground=m_bkBrush;
  RegisterClass(&wc);
  m_hWnd=CreateWindowEx(WS_EX_TOOLWINDOW|WS_EX_NOACTIVATE|WS_EX_TOPMOST,
    Classname,DlgTitle,WS_VISIBLE|WS_CAPTION|WS_SYSMENU|WS_BORDER,
    m_wr.left,m_wr.top,m_wr.right-m_wr.left,m_wr.bottom-m_wr.top,
    0,0,0,0);
  SetWindowLongPtr(m_hWnd,GWLP_USERDATA,(LONG_PTR)this);
  //Static
  RECT cr;
  GetClientRect(m_hWnd,&cr);
  InflateRect(&cr,-5,-5);
  HWND s=CreateWindowEx(0,_T("Static"),Text,WS_CHILD|WS_VISIBLE|SS_NOPREFIX,
    cr.left,cr.top,cr.right-cr.left,cr.bottom-cr.top,m_hWnd,0,0,0);
  if (!s)
    DWORD dwe=GetLastError();
  SendMessage(s,WM_SETFONT,(WPARAM)m_hFont,1);
  SetTimer(m_hWnd,2,20000,0);
  InvalidateRect(m_hWnd,0,1);
  UpdateWindow(m_hWnd);
  MsgLoop();
}

CTrayMsgWnd::~CTrayMsgWnd()
{
  DeleteObject(m_hFont);
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
      DestroyWindow(m_hWnd);
//      POSITION p=g_MsgWindows.Find(this);
//      while(p)
//      {
//        CTrayMsgWnd* w=g_MsgWindows.GetNext(p);
//        if (w)
//          w->Slide(m_wr.Height());
//      }
//      p=g_MsgWindows.Find(this);
//      g_MsgWindows.RemoveAt(p);
    }
    return 0;
  case WM_CTLCOLORSTATIC:
    SetBkMode((HDC)wParam,TRANSPARENT);
  case WM_CTLCOLORDLG:
    return (DWORD)m_bkBrush;
  case WM_MOVING:
	  *((RECT*)lParam)=m_wr;
    return TRUE;
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
        SetWindowPos(m_hWnd,0,m_wr.left,m_wr.top,
          m_wr.right-m_wr.left,m_wr.bottom-m_wr.top,
          SWP_NOZORDER|SWP_NOACTIVATE);
        m_DoSlide-=5;
      }
      if (m_DoSlide<=0)
      {
        m_DoSlide=0;
        KillTimer(m_hWnd,1);
      }
    }
    return 0;
  }
  return DefWindowProc(m_hWnd,msg,wParam,lParam);
}

void CTrayMsgWnd::Slide(int Height)
{
  m_DoSlide+=Height; 
  SetTimer(m_hWnd,1,10,0);
};

