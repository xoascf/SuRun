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

void GrantAccessToWinstationAndDesktop(HANDLE htok,LPCTSTR WinSta,LPCTSTR Desk);