#define _WIN32_WINNT 0x0500
#define WINVER       0x0500
#include <windows.h>
#include <tchar.h>
#include <aclapi.h>
#include <userenv.h>
#include "WinStaDesk.h"
#include "Helpers.h"
#include "DBGTrace.h"

#pragma comment(lib,"Userenv.lib")

#ifdef _DEBUG
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#define new DEBUG_NEW
#endif

//////////////////////////////////////////////////////////////////////////////
// 
// WindowStation Desktop Names:
// 
//////////////////////////////////////////////////////////////////////////////
BOOL GetWinStaName(LPTSTR WinSta,DWORD ccWinSta)
{
  return GetUserObjectInformation(GetProcessWindowStation(),UOI_NAME,
    WinSta,ccWinSta,&ccWinSta);
}

BOOL GetDesktopName(LPTSTR DeskName,DWORD ccDeskName)
{
  return GetUserObjectInformation(GetThreadDesktop(GetCurrentThreadId()),
    UOI_NAME,DeskName,ccDeskName,&ccDeskName);
}

//////////////////////////////////////////////////////////////////////////////
// 
// CRunOnNewDeskTop:
//   create and Switch to Desktop, switch back when Object is deleted
// 
//////////////////////////////////////////////////////////////////////////////

CRunOnNewDeskTop::CRunOnNewDeskTop(LPCTSTR WinStaName,LPCTSTR DeskName,BOOL bCreateBkWnd)
{
  m_hDeskSwitch=NULL;
  m_hwinstaUser=NULL;
  m_bOk=TRUE;
  m_bOk=FALSE;
  //Get current WindowStation and Desktop
  m_hwinstaSave=GetProcessWindowStation();
  m_hdeskSave=GetThreadDesktop(GetCurrentThreadId());
  m_hdeskUser=m_hdeskSave;
  TCHAR wsn[MAX_PATH]={0};
  TCHAR dtn[MAX_PATH]={0};
  DWORD LenW=MAX_PATH;
  DWORD LenD=MAX_PATH;
  GetUserObjectInformation(m_hwinstaSave,UOI_NAME,wsn,LenW,&LenW);
  GetUserObjectInformation(m_hdeskSave,UOI_NAME,dtn,LenD,&LenD);
  //Set new WindowStation (WinStaName)  
  if ((wsn[0]=='\0') || _tcsicmp(wsn,WinStaName))
  {
    m_hwinstaUser = OpenWindowStation(WinStaName,FALSE,MAXIMUM_ALLOWED);
    if (m_hwinstaUser == NULL)
    {
      DBGTrace1("CRunOnNewDeskTop::OpenWindowStation failed: %s",GetLastErrorNameStatic());
      SECURITY_ATTRIBUTES saWinSta= { sizeof(saWinSta), NULL, TRUE };
      m_hwinstaUser = CreateWindowStation(WinStaName,0,WINSTA_ACCESSCLIPBOARD
        |WINSTA_ACCESSGLOBALATOMS|WINSTA_CREATEDESKTOP|WINSTA_ENUMDESKTOPS 
        |WINSTA_ENUMERATE|WINSTA_EXITWINDOWS|WINSTA_READATTRIBUTES 
        |WINSTA_READSCREEN|WINSTA_WRITEATTRIBUTES,&saWinSta);
      if (m_hwinstaUser == NULL)
      {
        DBGTrace1("CRunOnNewDeskTop::CreateWindowStation failed: %s",GetLastErrorNameStatic());
        return;
      }
    }
    if (!SetProcessWindowStation(m_hwinstaUser))
      DBGTrace1("CRunOnNewDeskTop::SetProcessWindowStation failed: %s",GetLastErrorNameStatic());
  }
  //Get interactive Desktop
  m_hDeskSwitch=OpenInputDesktop(0,FALSE,DESKTOP_SWITCHDESKTOP);
  if (!m_hDeskSwitch)
  {
    DBGTrace1("CRunOnNewDeskTop::OpenInputDesktop failed: %s",GetLastErrorNameStatic());
    return;
  }
  //Set Interactive Desktop as current Desktop to get the Desktop Bitmap
  if (!SetThreadDesktop(m_hDeskSwitch))
    DBGTrace1("CRunOnNewDeskTop::SetThreadDesktop(m_hDeskSwitch) failed!: %s",GetLastErrorNameStatic());
  //Create Background Bitmap
  if (bCreateBkWnd)
    m_Screen.Init();
  //Create a new Desktop and set as the Threads Desktop
  LenD=MAX_PATH;
  GetUserObjectInformation(m_hdeskSave,UOI_NAME,dtn,LenD,&LenD);
  if ((dtn[0]==TCHAR('\0')) || _tcsicmp(dtn,DeskName))
  {
    SECURITY_ATTRIBUTES saDesktop = { sizeof(saDesktop), NULL, TRUE };
    m_hdeskUser = CreateDesktop(DeskName,0,0,0,DESKTOP_CREATEMENU|DESKTOP_CREATEWINDOW
      |DESKTOP_ENUMERATE|DESKTOP_HOOKCONTROL|DESKTOP_READOBJECTS
      |DESKTOP_SWITCHDESKTOP|DESKTOP_WRITEOBJECTS,&saDesktop);
    if (m_hdeskUser == NULL)
    {
      CleanUp();
      DBGTrace1("CRunOnNewDeskTop::CreateDesktop failed: %s",GetLastErrorNameStatic());
      return;
    }
    if (!SetThreadDesktop(m_hdeskUser))
    {
      CleanUp();
      DBGTrace("CRunOnNewDeskTop::SetThreadDesktop failed!");
      return;
    }
  }
  //Switch to the new Desktop
  if (!SwitchDesktop(m_hdeskUser))
  {
    DBGTrace1("CRunOnNewDeskTop::SwitchDesktop failed: %s",GetLastErrorNameStatic());
    CleanUp();
    return;
  }
  m_bOk=TRUE;
  //Show Desktop Background
  if (bCreateBkWnd)
    m_Screen.Show();
}

void CRunOnNewDeskTop::CleanUp()
{
  //Delete Backgroung Window
  if(m_bOk)
    m_Screen.Done();
  //Switch back to the interactive Desktop
  if(m_hDeskSwitch)
  {
    if (!SwitchDesktop(m_hDeskSwitch))
      DBGTrace1("CRunOnNewDeskTop: SwitchDesktop failed: %s",GetLastErrorNameStatic());
    if (!CloseDesktop(m_hDeskSwitch))
      DBGTrace1("CRunOnNewDeskTop: CloseDesktop failed: %s",GetLastErrorNameStatic());
    m_hDeskSwitch=NULL;
  }
  //Set the previous Window Station
  if (m_hwinstaUser)
  {
    if (!SetProcessWindowStation(m_hwinstaSave))
      DBGTrace1("CRunOnNewDeskTop: SetProcessWindowStation failed: %s",GetLastErrorNameStatic());
    if (!CloseWindowStation(m_hwinstaUser))
      DBGTrace1("CRunOnNewDeskTop: CloseWindowStation failed: %s",GetLastErrorNameStatic());
    m_hwinstaUser=0;
  }
  //Set the previous Desktop
  if(m_hdeskUser!=m_hdeskSave)
  {
    if (!SetThreadDesktop(m_hdeskSave))
      DBGTrace1("CRunOnNewDeskTop: SetThreadDesktop failed: %s",GetLastErrorNameStatic());
    if (!CloseDesktop(m_hdeskUser))
      DBGTrace1("CRunOnNewDeskTop: CloseDesktop failed: %s",GetLastErrorNameStatic());
    m_hdeskUser=m_hdeskSave=0;
  }
  m_bOk=FALSE;
}

CRunOnNewDeskTop::~CRunOnNewDeskTop()
{
  CleanUp();
}

bool CRunOnNewDeskTop::IsValid()
{
  return m_bOk;
};
