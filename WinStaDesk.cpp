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
#include <aclapi.h>
#include <userenv.h>
#include "WinStaDesk.h"
#include "ScreenSnap.h"
#include "Helpers.h"
#include "ResStr.h"
#include "DBGTrace.h"

#pragma comment(lib,"Userenv.lib")

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

void SetProcWinStaDesk(LPCTSTR WinSta,LPCTSTR Desk)
{
	HWINSTA hws = OpenWindowStation(WinSta,0,MAXIMUM_ALLOWED);
	if (!hws)
  {
    DBGTrace2("OpenWindowStation(%s) failed: %s",WinSta,GetLastErrorNameStatic());
  }else
  {
    SetProcessWindowStation(hws);
    if (!CloseWindowStation(hws))
      DBGTrace1("CloseWindowStation failed: %s",GetLastErrorNameStatic());
    HDESK hd = OpenDesktop(Desk,0,0,MAXIMUM_ALLOWED);
    if (!hd)
    {
      DBGTrace2("OpenDesktop(%s) failed: %s",Desk,GetLastErrorNameStatic());
    }else
    {
      if (!SetThreadDesktop(hd))
        DBGTrace1("SetThreadDesktop failed: %s",GetLastErrorNameStatic());
      if (!CloseDesktop(hd))
        DBGTrace1("CloseDesktop failed: %s",GetLastErrorNameStatic());
    }
  }
}

void SetAccessToWinDesk(HANDLE htok,LPCTSTR WinSta,LPCTSTR Desk,BOOL bGrant)
{
	BYTE tgs[4096];
	DWORD cbtgs = sizeof tgs;
	if (!GetTokenInformation(htok,TokenGroups,tgs,cbtgs,&cbtgs))
  {
    DBGTrace1("GetTokenInformation failed: %s",GetLastErrorNameStatic());
    return;
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
    return;
  }
	void* psidLogonSession = it->Sid;
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
    ea[1].grfAccessPermissions = WINSTA_ALL_ACCESS;
    ea[1].grfAccessMode = bGrant?SET_ACCESS:REVOKE_ACCESS;
    ea[1].grfInheritance= NO_INHERITANCE;
    ea[1].Trustee.TrusteeForm = TRUSTEE_IS_SID;
    ea[1].Trustee.TrusteeType = TRUSTEE_IS_USER;
    ea[1].Trustee.ptstrName  = (LPTSTR)psidLogonSession;
    // grant the logon session all access to any new desktops created in winsta0
		// by adding an inherit-only ace
    ea[0].grfAccessPermissions = DESKTOP_ALL_ACCESS;
    ea[0].grfAccessMode = bGrant?SET_ACCESS:REVOKE_ACCESS;
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
      ea.grfAccessPermissions = DESKTOP_ALL_ACCESS;
      ea.grfAccessMode = bGrant?SET_ACCESS:REVOKE_ACCESS;
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
      CloseDesktop(hd);
	  }
    SetProcessWindowStation(hwss);
    CloseWindowStation(hws);
	}
}

void GrantUserAccessToDesktop(HDESK hDesk)
{
  PSID UserSID=0;
  DWORD SidLen=0;
  GetUserObjectInformation(hDesk,UOI_USER_SID,UserSID,SidLen,&SidLen);
  UserSID=LocalAlloc(LPTR,SidLen);
  if (!GetUserObjectInformation(hDesk,UOI_USER_SID,UserSID,SidLen,&SidLen))
    DBGTrace1("GetUserObjectInformation failed:%s",GetLastErrorNameStatic());

  PSECURITY_DESCRIPTOR pSD = NULL;
	PACL pOldDACL=NULL, pNewDACL=NULL;
	// get the existing DACL, with enough extra space for adding a couple more aces
  GetSecurityInfo(hDesk,SE_WINDOW_OBJECT,DACL_SECURITY_INFORMATION,NULL,NULL,&pOldDACL,NULL,&pSD);
  // Initialize an EXPLICIT_ACCESS structure for an ACE.
  EXPLICIT_ACCESS ea={0};
  // grant the logon session all access to the default desktop
  ea.grfAccessPermissions = DESKTOP_ALL_ACCESS;
  ea.grfAccessMode = SET_ACCESS;
  ea.grfInheritance= NO_INHERITANCE;
  ea.Trustee.TrusteeForm = TRUSTEE_IS_SID;
  ea.Trustee.TrusteeType = TRUSTEE_IS_USER;
  ea.Trustee.ptstrName  = (LPTSTR)UserSID;
  // Create a new ACL that merges the new ACE into the existing DACL.
  DWORD err=SetEntriesInAcl(1,&ea,pOldDACL,&pNewDACL);
  if (err!=ERROR_SUCCESS)
  {
    DBGTrace1("SetEntriesInAcl failed:%s",GetErrorNameStatic(err));
  }else
  {
    // apply changes
    err=SetSecurityInfo(hDesk,SE_WINDOW_OBJECT,DACL_SECURITY_INFORMATION,0,0,pNewDACL,0);
    if ( err )
      DBGTrace1("SetSecurityInfo failed %s",GetErrorNameStatic(err));
  }
  LocalFree(UserSID);
  LocalFree((HLOCAL)pNewDACL); 
	LocalFree((HLOCAL)pSD); 
}

void DenyUserAccessToDesktop(HDESK hDesk)
{
  PSID UserSID=0;
  DWORD SidLen=0;
  GetUserObjectInformation(hDesk,UOI_USER_SID,UserSID,SidLen,&SidLen);
  UserSID=LocalAlloc(LPTR,SidLen);
  if (!GetUserObjectInformation(hDesk,UOI_USER_SID,UserSID,SidLen,&SidLen))
    DBGTrace1("GetUserObjectInformation failed:%s",GetLastErrorNameStatic());

  PSECURITY_DESCRIPTOR pSD = NULL;
	PACL pOldDACL=NULL, pNewDACL=NULL;
	// get the existing DACL, with enough extra space for adding a couple more aces
  GetSecurityInfo(hDesk,SE_WINDOW_OBJECT,DACL_SECURITY_INFORMATION,NULL,NULL,&pOldDACL,NULL,&pSD);
  // Initialize an EXPLICIT_ACCESS structure for an ACE.
  EXPLICIT_ACCESS ea={0};
  // grant the logon session all access to the default desktop
  ea.grfAccessPermissions = DESKTOP_ALL_ACCESS;
  ea.grfAccessMode = REVOKE_ACCESS;
  ea.grfInheritance= NO_INHERITANCE;
  ea.Trustee.TrusteeForm = TRUSTEE_IS_SID;
  ea.Trustee.TrusteeType = TRUSTEE_IS_USER;
  ea.Trustee.ptstrName  = (LPTSTR)UserSID;
  // Create a new ACL that merges the new ACE into the existing DACL.
  DWORD err=SetEntriesInAcl(1,&ea,pOldDACL,&pNewDACL);
  if (err!=ERROR_SUCCESS)
  {
    DBGTrace1("SetEntriesInAcl failed:%s",GetErrorNameStatic(err));
  }else
  {
    // apply changes
    err=SetSecurityInfo(hDesk,SE_WINDOW_OBJECT,DACL_SECURITY_INFORMATION,0,0,pNewDACL,0);
    if ( err )
      DBGTrace1("SetSecurityInfo failed %s",GetErrorNameStatic(err));
  }
  LocalFree(UserSID);
  LocalFree((HLOCAL)pNewDACL); 
	LocalFree((HLOCAL)pSD); 
}

//This class creates a new desktop with a darkened blurred image of the 
//current dektop as background.
class CRunOnNewDeskTop
{
public:
  CRunOnNewDeskTop(LPCTSTR WinStaName,LPCTSTR DeskName,BOOL bCreateBkWnd);
  ~CRunOnNewDeskTop();
  bool IsValid();
  void CleanUp();
  void FadeOut();
private:
  bool    m_bOk;
  HWINSTA m_hwinstaSave;
  HWINSTA m_hwinstaUser;
  HDESK   m_hdeskSave;
  HDESK   m_hdeskUser;
  HDESK   m_hDeskSwitch;
public:
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
    if(m_Thread)
      WaitForSingleObject(m_Thread,INFINITE);
    while (m_Thread)
      Sleep(55);
  }
  static DWORD WINAPI ThreadProc(void* p)
  {
    CStayOnDeskTop* t=(CStayOnDeskTop*)p;
    SetThreadPriority(t->m_Thread,THREAD_PRIORITY_IDLE);
    LPTSTR DeskName=_tcsdup(t->m_DeskName);
    while (t->m_DeskName)
    {
      HDESK d=OpenDesktop(DeskName,0,FALSE,DESKTOP_SWITCHDESKTOP);
      if (d!=0)
      {
        HDESK i=OpenInputDesktop(0,FALSE,DESKTOP_SWITCHDESKTOP);
        if (i!=0)
        {
          TCHAR n[MAX_PATH]={0};
          DWORD l=MAX_PATH;
          if (GetUserObjectInformation(i,UOI_NAME,n,l,&l))
            if (_tcsicmp(n,DeskName))
              SwitchDesktop(d);
          CloseDesktop(i);
        }
        CloseDesktop(d);
      }
      Sleep(10);
    }
    free(DeskName);
    t->m_Thread=0;
    return 0;
  }
private:
  LPTSTR m_DeskName;
  HANDLE m_Thread;
};

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
  m_hDeskSwitch=OpenInputDesktop(0,FALSE,DESKTOP_SWITCHDESKTOP/*DESKTOP_ALL_ACCESS|WRITE_DAC|READ_CONTROL*/);
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
    //saDesktop.lpSecurityDescriptor allows access to m_hdeskUser only for the current user
    SECURITY_ATTRIBUTES saDesktop = { sizeof(saDesktop), GetUserAccessSD(), TRUE };
    m_hdeskUser = CreateDesktop(DeskName,0,0,0,DESKTOP_CREATEMENU|DESKTOP_CREATEWINDOW
      |DESKTOP_ENUMERATE|DESKTOP_HOOKCONTROL|DESKTOP_READOBJECTS
      |DESKTOP_SWITCHDESKTOP|DESKTOP_WRITEOBJECTS,&saDesktop);
    if (m_hdeskUser == NULL)
    {
      DBGTrace1("CRunOnNewDeskTop::CreateDesktop failed: %s",GetLastErrorNameStatic());
      LocalFree(saDesktop.lpSecurityDescriptor);
      CleanUp();
      return;
    }
    LocalFree(saDesktop.lpSecurityDescriptor);
  }
  if (!SetThreadDesktop(m_hdeskUser))
  {
    DBGTrace("CRunOnNewDeskTop::SetThreadDesktop failed!");
    CleanUp();
    return;
  }
  //DenyUserAccessToDesktop(m_hDeskSwitch);
  //Show Desktop Background
  if (bCreateBkWnd)
    m_Screen.Show();
  //Switch to the new Desktop
  if (!SwitchDesktop(m_hdeskUser))
  {
    DBGTrace1("CRunOnNewDeskTop::SwitchDesktop failed: %s",GetLastErrorNameStatic());
    CleanUp();
    return;
  }
  m_bOk=TRUE;
}

void CRunOnNewDeskTop::FadeOut()
{
  m_Screen.FadeOut();
}

void CRunOnNewDeskTop::CleanUp()
{
  //Switch back to the interactive Desktop
  if(m_hDeskSwitch)
  {
    //GrantUserAccessToDesktop(m_hDeskSwitch);
    if (!SwitchDesktop(m_hDeskSwitch))
      DBGTrace1("CRunOnNewDeskTop: SwitchDesktop failed: %s",GetLastErrorNameStatic());
    if (!CloseDesktop(m_hDeskSwitch))
      DBGTrace1("CRunOnNewDeskTop: CloseDesktop failed: %s",GetLastErrorNameStatic());
    m_hDeskSwitch=NULL;
  }
  //Delete Background Window
  if(m_bOk)
    m_Screen.Done();
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


CRunOnNewDeskTop* g_RunOnNewDesk=NULL;
CStayOnDeskTop* g_StayOnDesk=NULL;

bool CreateSafeDesktop(LPTSTR WinSta,BOOL BlurDesk)
{
  DeleteSafeDesktop(false);
  //Every "secure" Desktop has its own name:
  CResStr DeskName(L"SRD_%04x",GetTickCount());
  CRunOnNewDeskTop* rond=new CRunOnNewDeskTop(WinSta,DeskName,BlurDesk);
  if (!rond)
    return false;
  if (!rond->IsValid())
  {
    delete rond;
    return false;
  }
  g_RunOnNewDesk=rond;
  g_StayOnDesk=new CStayOnDeskTop(DeskName);
  return true;
}

void DeleteSafeDesktop(bool bFade)
{
  if (g_RunOnNewDesk)
    g_RunOnNewDesk->FadeOut();
  if (g_StayOnDesk)
    delete g_StayOnDesk;
  g_StayOnDesk=NULL;
  if (g_RunOnNewDesk)
    delete g_RunOnNewDesk;
  g_RunOnNewDesk=NULL;
}

//int TestBS()
//{
//  CreateSafeDesktop(_T("WinSta0"),true);
//  DWORD t=GetTickCount();
//  while (GetTickCount()-t<3000)
//    g_RunOnNewDesk->m_Screen.MsgLoop();
//  DeleteSafeDesktop();
//  ExitProcess(0);
//  return 1;
//}
//
//int tbs=TestBS();
