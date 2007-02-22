// TrayMsgWnd.cpp : implementation file
//

#include "stdafx.h"
#include "q8tool.h"
#include "Q8ToolNet.h"
#include "GfX.h"
#include "TrayMsgWnd.h"
#include "Monitor.h"
#include "ThreadStuff.h"

#ifdef _DEBUG
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#define new DEBUG_NEW
#endif

/////////////////////////////////////////////////////////////////////////////
// CTrayMsgWnd window

class CTrayMsgWnd : public CWnd
{
// Construction
public:
	CTrayMsgWnd(LPCTSTR Text);

// Attributes
public:

// Operations
public:

// Overrides
	// ClassWizard generated virtual function overrides
	//{{AFX_VIRTUAL(CTrayMsgWnd)
	public:
	protected:
	virtual BOOL PreCreateWindow(CREATESTRUCT& cs);
	//}}AFX_VIRTUAL

// Implementation
public:
	virtual ~CTrayMsgWnd();
  void Slide(int Height){m_DoSlide+=Height; SetTimer(1,10,0);};

	// Generated message map functions
protected:
  CStatic m_MsgText;
  CString m_Text;
  CFont m_Font;
  CBrush m_bkBrush;
  CRect m_wr;
  int m_DoSlide;
	//{{AFX_MSG(CTrayMsgWnd)
	afx_msg int OnCreate(LPCREATESTRUCT lpCreateStruct);
	afx_msg HBRUSH OnCtlColor(CDC* pDC, CWnd* pWnd, UINT nCtlColor);
	afx_msg void OnMoving(UINT fwSide, LPRECT pRect);
	afx_msg void OnTimer(UINT nIDEvent);
	afx_msg void OnClose();
	afx_msg void OnNcDestroy();
	//}}AFX_MSG
	DECLARE_MESSAGE_MAP()
  CMainWndIconSet m_Icons;
};

/////////////////////////////////////////////////////////////////////////////
// The List:
/////////////////////////////////////////////////////////////////////////////
CList <CTrayMsgWnd*,CTrayMsgWnd*> g_MsgWindows;

/////////////////////////////////////////////////////////////////////////////
//Public Message Functions:
/////////////////////////////////////////////////////////////////////////////
#ifndef WS_EX_NOACTIVATE
#define WS_EX_NOACTIVATE        0x08000000L
#endif

UINT TrayMsgWndProc(void* p)
{
  LPTSTR Title=(LPTSTR)p;
  LPTSTR Message=&Title[_tcslen(Title)+1];
  TrayMsgWnd(Title,Message);
  free(p);
  return 0;
}

void TrayMsgWnd(void* Buf)
{
  void* p=malloc(_msize(Buf));
  memmove(p,Buf,_msize(Buf));
  StartThread(TrayMsgWndProc,p);
}

void TrayMsgWnd(LPCTSTR DlgTitle,LPCTSTR Message)
{
  SetThreadPriority(GetCurrentThread(),THREAD_PRIORITY_IDLE);
  //CQ8ToolClient ruft das hier auf:
  RECT rc={0};
  CTrayMsgWnd* w=new CTrayMsgWnd(Message);
  CString S=Q8ToolServiceName;
  if (DlgTitle && *DlgTitle)
    S.Format("%s - %s",DlgTitle,Q8ToolServiceName);
  w->CreateEx(WS_EX_TOOLWINDOW|WS_EX_NOACTIVATE|WS_EX_TOPMOST,"Q8TMSGWND",S,
              WS_VISIBLE|WS_CAPTION|WS_SYSMENU|WS_BORDER,rc,0,0);
  while (::IsWindow(w->m_hWnd))
  {
    MSG msg;
    while(PeekMessage(&msg,0,0,0,PM_REMOVE))
      DispatchMessage(&msg);
    Sleep(10);
  }
}

void TrayMsg(LPTSTR DlgTitle,int nID,...)
{
  CString s=LoadCString(nID);
  if (!s.IsEmpty())
  {
    va_list argList;
    va_start(argList, nID);
    CString s1;
    s1.FormatV(s,argList);
    va_end(argList);
    //CNetSwitch verteilt an alle Clients!
    SendTrayMsg(DlgTitle,(LPTSTR)(LPCTSTR)s1);
  }
}

void TrayMsg(LPTSTR DlgTitle,CString s,...)
{
  va_list argList;
  va_start(argList, s);
  CString s1;
  s1.FormatV(s,argList);
  va_end(argList);
  //CNetSwitch verteilt an alle Clients!
  SendTrayMsg(DlgTitle,(LPTSTR)(LPCTSTR)s1);
}

void TrayMsgClear()
{
  while(g_MsgWindows.GetCount())
  {
     CTrayMsgWnd* w=g_MsgWindows.GetTail();
     if (w)
     {
       g_MsgWindows.RemoveTail();
       w->DestroyWindow();
       delete w;
     }
  }
}


/////////////////////////////////////////////////////////////////////////////
// CTrayMsgWnd

CTrayMsgWnd::CTrayMsgWnd(LPCTSTR Text)
{
  m_DoSlide=0;
  m_Text=Text;
  CreatePointFont(m_Font,8,"MS Sans Serif");
  {
    CDC MemDC;
    MemDC.CreateCompatibleDC(0);
    MemDC.SelectObject(m_Font);
    m_wr.left=0;
    m_wr.top=0;
    m_wr.right=180;
    m_wr.bottom=400;
    MemDC.DrawText(m_Text,m_wr,DT_CALCRECT|DT_NOPREFIX|DT_WORDBREAK);
    m_wr.right=180+2*GetSystemMetrics(SM_CXDLGFRAME)+10;
    m_wr.bottom+=2*GetSystemMetrics(SM_CYDLGFRAME)+GetSystemMetrics(SM_CYSMCAPTION)+10;
  }

  m_bkBrush.CreateSolidBrush(GetSysColor(COLOR_WINDOW));
}

CTrayMsgWnd::~CTrayMsgWnd()
{
}


BEGIN_MESSAGE_MAP(CTrayMsgWnd, CWnd)
	//{{AFX_MSG_MAP(CTrayMsgWnd)
	ON_WM_CREATE()
	ON_WM_CTLCOLOR()
	ON_WM_MOVING()
	ON_WM_DESTROY()
	ON_WM_TIMER()
	ON_WM_CLOSE()
	ON_WM_NCDESTROY()
	//}}AFX_MSG_MAP
END_MESSAGE_MAP()


/////////////////////////////////////////////////////////////////////////////
// CTrayMsgWnd message handlers

BOOL CTrayMsgWnd::PreCreateWindow(CREATESTRUCT& cs) 
{
  if (!CWnd::PreCreateWindow(cs))
    return FALSE;
  cs.style     |= WS_CLIPCHILDREN|WS_CAPTION;
  cs.dwExStyle |= WS_EX_TOOLWINDOW|WS_EX_TOPMOST;
  cs.lpszClass  = AfxRegisterWndClass(CS_HREDRAW|CS_VREDRAW, ::LoadCursor(NULL, IDC_ARROW), (HBRUSH)m_bkBrush.m_hObject, NULL);
  return TRUE;
}

int CTrayMsgWnd::OnCreate(LPCREATESTRUCT lpCreateStruct) 
{
	if (CWnd::OnCreate(lpCreateStruct) == -1)
		return -1;
  //Window Rect
  RECT rd={0};
  GetCurrentWorkArea(m_hWnd,&rd);
  POSITION p=g_MsgWindows.GetHeadPosition();
  while(p)
  {
     CTrayMsgWnd* w=g_MsgWindows.GetNext(p);
     if (w && (w->m_wr.top<rd.bottom))
       rd.bottom=w->m_wr.top;
  }
  m_wr.OffsetRect(rd.right-m_wr.Width(),rd.bottom-m_wr.Height());
  ClipOrCenterRectToMonitor(m_wr,0);
  ::SetWindowPos(m_hWnd,0,m_wr.left,m_wr.top,m_wr.Width(),m_wr.Height(),SWP_NOZORDER|SWP_NOACTIVATE);
  m_Icons.Init(*this,IDR_MAINFRAME,IDR_MAINFRAME1);
  //Static
  CRect cr;
  GetClientRect(cr);
  cr.DeflateRect(5,5);
  m_MsgText.Create(m_Text,WS_CHILD|WS_VISIBLE,cr,this);
  m_MsgText.SetFont(&m_Font);
  g_MsgWindows.AddTail(this);
  Invalidate();
  SetTimer(2,20000,0);
	return 0;
}

HBRUSH CTrayMsgWnd::OnCtlColor(CDC* pDC, CWnd* pWnd, UINT nCtlColor) 
{
	return (HBRUSH)m_bkBrush.m_hObject;
}

void CTrayMsgWnd::OnMoving(UINT fwSide, LPRECT pRect) 
{
	CWnd::OnMoving(fwSide, pRect);
	*pRect=m_wr;
}

void CTrayMsgWnd::OnTimer(UINT nIDEvent) 
{
  if (nIDEvent==2)
  {
    if (g_MsgWindows.GetCount()>1)
    {
      KillTimer(2);
      PostMessage(WM_CLOSE);
    }
  }else
  if (nIDEvent==1)
  {
    if (m_DoSlide)
    {
      m_wr.OffsetRect(0,min(5,m_DoSlide));
      ::SetWindowPos(m_hWnd,0,m_wr.left,m_wr.top,m_wr.Width(),m_wr.Height(),SWP_NOZORDER|SWP_NOACTIVATE);
      m_DoSlide-=5;
    }
    if (m_DoSlide<=0)
    {
      m_DoSlide=0;
      KillTimer(1);
    }
  }else
	  CWnd::OnTimer(nIDEvent);
}

void CTrayMsgWnd::OnClose() 
{
  KillTimer(1);
  KillTimer(2);
  POSITION p=g_MsgWindows.Find(this);
  while(p)
  {
     CTrayMsgWnd* w=g_MsgWindows.GetNext(p);
     if (w)
       w->Slide(m_wr.Height());
  }
  p=g_MsgWindows.Find(this);
  g_MsgWindows.RemoveAt(p);
	CWnd::OnClose();
}

void CTrayMsgWnd::OnNcDestroy() 
{
	CWnd::OnNcDestroy();
  delete this;
}
