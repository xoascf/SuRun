#define _WIN32_WINNT 0x0500
#define WINVER       0x0500
#include <windows.h>
#include <tchar.h>
#include <aclapi.h>
#include <userenv.h>
#include "WinStaDesk.h"
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

CRunOnNewDeskTop::CRunOnNewDeskTop(LPCTSTR DeskName,BOOL bCreateBkWnd)
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
  //Set new WindowStation (WinSta0)  
  if ((wsn[0]=='\0') || _tcsicmp(wsn,_T("WinSta0")))
  {
    m_hwinstaUser = OpenWindowStation(_T("WinSta0"), FALSE, MAXIMUM_ALLOWED);
    if (m_hwinstaUser == NULL)
    {
      DBGTrace1("CRunOnNewDeskTop::OpenWindowStation failed: %s",GetLastErrorNameStatic());
      SECURITY_ATTRIBUTES saWinSta= { sizeof(saWinSta), NULL, TRUE };
      m_hwinstaUser = CreateWindowStation(_T("WinSta0"),0,WINSTA_ACCESSCLIPBOARD
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

//////////////////////////////////////////////////////////////////////////////
//
// The following has evolved taken from Keith Browns cmdasuser
//
// http://www.develop.com/kbrown
//
//////////////////////////////////////////////////////////////////////////////

// for some reason, winuser.h doesn't define these useful aliases
#ifndef WINSTA_ALL_ACCESS
#define WINSTA_ALL_ACCESS 0x0000037F
#endif

#ifndef DESKTOP_ALL_ACCESS
#define DESKTOP_ALL_ACCESS 0x00001FF
#endif

void* GetTokenLogonSID(HANDLE htok)
{
	BYTE tgs[4096];
	DWORD cbtgs = sizeof tgs;
	if (!GetTokenInformation(htok,TokenGroups,tgs,cbtgs,&cbtgs))
  {
    DBGTrace1("GetTokenInformation failed: %s",GetLastErrorNameStatic());
    return 0;
  }
	const TOKEN_GROUPS* ptgs = (TOKEN_GROUPS*)(tgs);
	const SID_AND_ATTRIBUTES* it = ptgs->Groups;
	const SID_AND_ATTRIBUTES* end = it + ptgs->GroupCount;
	while (end!=it)
	{
		if ((it->Attributes & SE_GROUP_LOGON_ID)==SE_GROUP_LOGON_ID)
			break;
		++it;
	}
	if (end==it)
  {
    DBGTrace("UNEXPECTED: No Logon SID in TokenGroups");
    return 0;
  }
	return it->Sid;
}

void GrantAccessToWinstationAndDesktop(HANDLE htok,LPCTSTR WinSta,LPCTSTR Desk)
{
	void* psidLogonSession = GetTokenLogonSID(htok);
	HWINSTA hws = OpenWindowStation(WinSta,0,MAXIMUM_ALLOWED);
	if (!hws)
  {
    DBGTrace2("OpenWindowStation(%s) failed: %s",WinSta,GetLastErrorNameStatic());
  }else
	{
    PSECURITY_DESCRIPTOR pSD = NULL;
		PACL pOldDACL=NULL, pNewDACL=NULL;
		// get the existing DACL, with enough extra space for adding a couple more aces
    GetSecurityInfo(hws,SE_WINDOW_OBJECT,DACL_SECURITY_INFORMATION,0,0,&pOldDACL,0,&pSD);
    // Initialize an EXPLICIT_ACCESS structure for an ACE.
    EXPLICIT_ACCESS ea[2]={0};
    // grant the logon session all access to winsta0
    ea[1].grfAccessPermissions = WINSTA_ALL_ACCESS|STANDARD_RIGHTS_REQUIRED|SYNCHRONIZE;
    ea[1].grfAccessMode = SET_ACCESS;
    ea[1].grfInheritance= NO_INHERITANCE;
    ea[1].Trustee.TrusteeForm = TRUSTEE_IS_SID;
    ea[1].Trustee.TrusteeType = TRUSTEE_IS_USER;
    ea[1].Trustee.ptstrName  = (LPTSTR)psidLogonSession;
    // grant the logon session all access to any new desktops created in winsta0
		// by adding an inherit-only ace
    ea[0].grfAccessPermissions = DESKTOP_ALL_ACCESS|STANDARD_RIGHTS_REQUIRED|SYNCHRONIZE;
    ea[0].grfAccessMode = SET_ACCESS;
    ea[0].grfInheritance= SUB_CONTAINERS_AND_OBJECTS_INHERIT|INHERIT_ONLY;
    ea[0].Trustee.TrusteeForm = TRUSTEE_IS_SID;
    ea[0].Trustee.TrusteeType = TRUSTEE_IS_USER;
    ea[0].Trustee.ptstrName  = (LPTSTR)psidLogonSession;
    // Create a new ACL that merges the new ACE into the existing DACL.
    DWORD err=SetEntriesInAcl(2,ea,pOldDACL,&pNewDACL);
    if (err!=ERROR_SUCCESS)
    {
      DBGTrace1("SetEntriesInAcl failed:%s",GetErrorNameStatic(err));
    }else
    {
      // apply changes
      err=SetSecurityInfo(hws,SE_WINDOW_OBJECT,DACL_SECURITY_INFORMATION,0,0,pNewDACL,0);
      if ( err )
        DBGTrace1("SetSecurityInfo failed %s",GetErrorNameStatic(err));
    }
    LocalFree((HLOCAL)pNewDACL); 
		LocalFree((HLOCAL)pSD); 
    //We need to set hws to our WindowsStation to make Desk accessible to us 
    HWINSTA hwss=GetProcessWindowStation();
    SetProcessWindowStation(hws);
	  HDESK hd = OpenDesktop(Desk,0,0,MAXIMUM_ALLOWED);
	  if (!hd)
    {
      DBGTrace2("OpenDesktop(%s) failed: %s",Desk,GetLastErrorNameStatic());
    }else
	  {
      PSECURITY_DESCRIPTOR pSD = NULL;
		  PACL pOldDACL=NULL, pNewDACL=NULL;
		  // get the existing DACL, with enough extra space for adding a couple more aces
      GetSecurityInfo(hd,SE_WINDOW_OBJECT,DACL_SECURITY_INFORMATION,NULL,NULL,&pOldDACL,NULL,&pSD);
      // Initialize an EXPLICIT_ACCESS structure for an ACE.
      EXPLICIT_ACCESS ea={0};
      // grant the logon session all access to the default desktop
      ea.grfAccessPermissions = DESKTOP_ALL_ACCESS|STANDARD_RIGHTS_REQUIRED|SYNCHRONIZE;
      ea.grfAccessMode = SET_ACCESS;
      ea.grfInheritance= NO_INHERITANCE;
      ea.Trustee.TrusteeForm = TRUSTEE_IS_SID;
      ea.Trustee.TrusteeType = TRUSTEE_IS_USER;
      ea.Trustee.ptstrName  = (LPTSTR)psidLogonSession;
      // Create a new ACL that merges the new ACE into the existing DACL.
      DWORD err=SetEntriesInAcl(1,&ea,pOldDACL,&pNewDACL);
      if (err!=ERROR_SUCCESS)
      {
        DBGTrace1("SetEntriesInAcl failed:%s",GetErrorNameStatic(err));
      }else
      {
        // apply changes
        err=SetSecurityInfo(hd,SE_WINDOW_OBJECT,DACL_SECURITY_INFORMATION,0,0,pNewDACL,0);
        if ( err )
          DBGTrace1("SetSecurityInfo failed %s",GetErrorNameStatic(err));
      }
      LocalFree((HLOCAL)pNewDACL); 
		  LocalFree((HLOCAL)pSD); 
      if (!CloseDesktop(hd))
        DBGTrace1("CloseDesktop failed: %s",GetLastErrorNameStatic());
	  }
    if (!SetProcessWindowStation(hwss))
      DBGTrace1("SetProcessWindowStation failed: %s",GetLastErrorNameStatic());
    if (!CloseWindowStation(hws))
      DBGTrace1("CloseWindowStation failed: %s",GetLastErrorNameStatic());
	}
}
