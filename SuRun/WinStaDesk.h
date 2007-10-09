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
//                                   (c) Kay Bruns (http://kay-bruns.de), 2007
//////////////////////////////////////////////////////////////////////////////

//////////////////////////////////////////////////////////////////////////////
// Home of the CRunOnNewDeskTop class
//
// this class creates a new desktop in a given window station, captures the 
// screen of the current desktop, switches to the new desktop and sets the 
// captured screen as blurred backgroud.
//
// in the class destructor it swiches back to the users desktop
//////////////////////////////////////////////////////////////////////////////

#pragma once
#include "ScreenSnap.h"

// WindowStation Desktop Names:

BOOL GetWinStaName(LPTSTR WinSta,DWORD ccWinSta);
BOOL GetDesktopName(LPTSTR DeskName,DWORD ccDeskName);

//This class creates a new desktop with a darkened blurred image of the 
//current dektop as background.
class CRunOnNewDeskTop
{
public:
  CRunOnNewDeskTop(LPCTSTR WinStaName,LPCTSTR DeskName,BOOL bCreateBkWnd);
  ~CRunOnNewDeskTop();
  bool IsValid();
private:
  void CleanUp();
  bool    m_bOk;
  HWINSTA m_hwinstaSave;
  HWINSTA m_hwinstaUser;
  HDESK   m_hdeskSave;
  HDESK   m_hdeskUser;
  HDESK   m_hDeskSwitch;
  CBlurredScreen m_Screen;
};

//////////////////////////////////////////////////////////////////////////////
//
// CStayOnDeskTop
//
// There's no way to keep a thread in a different process from calling 
// SwitchDesktop(). 
// Even worse: Microsoft suggests using SwitchDeskTop(OpenDesktop("Default"))
// to detect if a screen saver or logon screen is active. 
// Apparently ShedHlp.exe from Acronis TrueImage 11 uses this trick. So I'm
// forced to use CStayOnDeskTop to switch back to SuRuns desktop.
//////////////////////////////////////////////////////////////////////////////

class CStayOnDeskTop
{
public:
  CStayOnDeskTop(LPCTSTR DeskName)
  {
    m_DeskName=_tcsdup(DeskName);
    m_Thread=CreateThread(0,0,ThreadProc,this,0,0);
  }
  ~CStayOnDeskTop()
  {
    LPTSTR s=m_DeskName;
    m_DeskName=0;
    free(s);
    WaitForSingleObject(m_Thread,INFINITE);
  }
  static DWORD WINAPI ThreadProc(void* p)
  {
    CStayOnDeskTop* t=(CStayOnDeskTop*)p;
    SetThreadPriority(t->m_Thread,THREAD_PRIORITY_IDLE);
    LPTSTR DeskName=_tcsdup(t->m_DeskName);
    while (t->m_DeskName)
    {
      HDESK d=OpenDesktop(t->m_DeskName,0,FALSE,DESKTOP_SWITCHDESKTOP);
      if (d!=0)
      {
        HDESK i=OpenInputDesktop(0,FALSE,DESKTOP_SWITCHDESKTOP);
        if (i!=0)
        {
          TCHAR n[MAX_PATH]={0};
          DWORD l=MAX_PATH;
          if (GetUserObjectInformation(i,UOI_NAME,n,l,&l))
            if (_tcscmp(n,DeskName))
              SwitchDesktop(d);
          CloseDesktop(i);
        }
        CloseDesktop(d);
      }
      Sleep(40);
    }
    free(DeskName);
    t->m_Thread=0;
    return 0;
  }
private:
  LPTSTR m_DeskName;
  HANDLE m_Thread;
};
