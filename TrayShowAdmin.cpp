#define _WIN32_IE    0x0600
#define _WIN32_WINNT 0x0500
#define WINVER       0x0500
#include <windows.h>
#include <LMAccess.h>
#include <SHLWAPI.H>
#include <TCHAR.h>
#include <stdio.h>
#include <Wtsapi32.h>
#include "resource.h"

#pragma comment(lib,"ShlWapi.lib")
#pragma comment(lib,"advapi32.lib")
#pragma comment(lib,"Wtsapi32.lib")

#define WM_TASKBAR WM_USER+1758
#define CLASSNAME     "TrayShowAdminClass"

int g_BallonTips=1;
BOOL g_ForegroundWndIsAdmin=-1;
HWND g_FgWnd=0;
HINSTANCE g_hInstance=0;
TCHAR g_User[MAX_PATH*2+2]={0};
NOTIFYICONDATA g_NotyData={0};

//////////////////////////////////////////////////////////////////////////////
// 
// IsAdmin  
// 
// check the token of the calling thread/process to see 
// if the caller belongs to the Administrators group.
//////////////////////////////////////////////////////////////////////////////

BOOL IsAdmin(HANDLE hToken/*=NULL*/) 
{
  BOOL   bReturn   = FALSE;
  PACL   pACL      = NULL;
  PSID   psidAdmin = NULL;
  PSECURITY_DESCRIPTOR psdAdmin = NULL;
  HANDLE hTok=NULL;
  if (hToken==NULL)
  {
    if((OpenThreadToken(GetCurrentThread(),TOKEN_DUPLICATE,FALSE,&hTok)==FALSE)
     &&(OpenProcessToken(GetCurrentProcess(),TOKEN_DUPLICATE,&hTok)==FALSE))
      return FALSE;
    hToken=hTok;
  }
  if (!DuplicateToken(hToken,SecurityImpersonation,&hToken))
    return FALSE;
  if (hTok)
    CloseHandle(hTok);
  __try 
  {
    // Initialize Admin SID and SD
    SID_IDENTIFIER_AUTHORITY SystemSidAuthority = SECURITY_NT_AUTHORITY;
    if (!AllocateAndInitializeSid(&SystemSidAuthority,2,SECURITY_BUILTIN_DOMAIN_RID,
      DOMAIN_ALIAS_RID_ADMINS,0,0,0,0,0,0,&psidAdmin))
      __leave;
    psdAdmin = LocalAlloc(LPTR,SECURITY_DESCRIPTOR_MIN_LENGTH);
    if (psdAdmin == NULL)
      __leave;
    if (!InitializeSecurityDescriptor(psdAdmin,SECURITY_DESCRIPTOR_REVISION))
      __leave;
    // Compute size needed for the ACL.
    DWORD dwACLSize=sizeof(ACL)+sizeof(ACCESS_ALLOWED_ACE)+GetLengthSid(psidAdmin)-sizeof(DWORD);
    // Allocate memory for ACL.
    pACL = (PACL)LocalAlloc(LPTR,dwACLSize);
    if (pACL == NULL)
      __leave;
    // Initialize the new ACL.
    if (!InitializeAcl(pACL,dwACLSize,ACL_REVISION2))
      __leave;
    // Add the access-allowed ACE to the DACL.
    if (!AddAccessAllowedAce(pACL,ACL_REVISION2,ACCESS_READ | ACCESS_WRITE,psidAdmin))
      __leave;
    // Set our DACL to the SD.
    if (!SetSecurityDescriptorDacl(psdAdmin,TRUE,pACL,FALSE))
      __leave;
    // AccessCheck is sensitive about what is in the SD; set the group and owner.
    SetSecurityDescriptorGroup(psdAdmin,psidAdmin,FALSE);
    SetSecurityDescriptorOwner(psdAdmin,psidAdmin,FALSE);
    if (!IsValidSecurityDescriptor(psdAdmin))
      __leave;
    // Initialize GenericMapping structure even though we won't be using generic rights.
    GENERIC_MAPPING GenericMapping;
    GenericMapping.GenericRead    = ACCESS_READ;
    GenericMapping.GenericWrite   = ACCESS_WRITE;
    GenericMapping.GenericExecute = 0;
    GenericMapping.GenericAll     = ACCESS_READ | ACCESS_WRITE;
    PRIVILEGE_SET ps;
    DWORD  dwStructureSize = sizeof(PRIVILEGE_SET);
    DWORD dwStatus;
    if (!AccessCheck(psdAdmin,hToken,ACCESS_READ,&GenericMapping,&ps, 
      &dwStructureSize,&dwStatus,&bReturn)) 
      __leave;
  } __finally 
  {
    // Cleanup 
    if (pACL) 
      LocalFree(pACL);
    if (psdAdmin) 
      LocalFree(psdAdmin);  
    if (psidAdmin) 
      FreeSid(psidAdmin);
    CloseHandle(hToken);
  }
  return bReturn;
}

bool GetSIDUserName(PSID sid,LPTSTR User)
{
  SID_NAME_USE snu;
  TCHAR uName[UNLEN+1],dName[UNLEN+1];
  DWORD uLen=UNLEN, dLen=UNLEN;
  if(!LookupAccountSid(NULL,sid,uName,&uLen,dName,&dLen,&snu))
    return FALSE;
  _tcscpy(User, dName);
  if(_tcslen(User))
    _tcscat(User, TEXT("\\"));
  _tcscat(User,uName);
  return TRUE;
}

bool GetTokenUserName(HANDLE hUser,LPTSTR User)
{
  DWORD dwLen=0;
  if ((!GetTokenInformation(hUser, TokenUser,NULL,0,&dwLen))
    &&(GetLastError()!=ERROR_INSUFFICIENT_BUFFER))
    return false;
  TOKEN_USER* ptu=(TOKEN_USER*)malloc(dwLen);
  if(!ptu)
    return false;
  if(GetTokenInformation(hUser,TokenUser,(PVOID)ptu,dwLen,&dwLen))
     GetSIDUserName(ptu->User.Sid,User);
  free(ptu);
  return true;
}

bool GetProcessUserName(DWORD ProcessID,LPTSTR User)
{
  HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION,0,ProcessID);
  if (!hProc)
    return 0;
  HANDLE hToken;
  bool bRet=false;
  // Open impersonation token for process
  if (OpenProcessToken(hProc,TOKEN_QUERY,&hToken))
  {
    bRet=GetTokenUserName(hToken,User);
    CloseHandle(hToken);
  }
  CloseHandle(hProc);
  return bRet;
}

BOOL ForegroundWndIsAdmin(LPTSTR User,HWND& wnd,LPTSTR WndTitle)
{
  DWORD ProcId=0;
  wnd=GetForegroundWindow();
  if (!wnd)
    return -1;
  DWORD ThrdId=GetWindowThreadProcessId(wnd,&ProcId);
  if (!GetProcessUserName(ProcId,User))
  {
    //OpenProcess failed! Try TS:
    WTS_PROCESS_INFO* ppi=0;
    DWORD n=0;
    WTSEnumerateProcesses(WTS_CURRENT_SERVER_HANDLE,0,1,&ppi,&n);
    if (ppi)
    {
      for (DWORD i=0;i<n;i++) if(ppi[i].ProcessId==ProcId)
      {
        GetSIDUserName(ppi[i].pUserSid,User);
        break;
      }
      WTSFreeMemory(ppi);
    }
  }
  if (!GetWindowText(wnd,WndTitle,MAX_PATH))
    sprintf(WndTitle,"Process %d",ProcId);
  HANDLE h=OpenProcess(PROCESS_QUERY_INFORMATION,FALSE,ProcId);
  if (!h)
    return TRUE;
  HANDLE hTok=0;
  if (!OpenProcessToken(h,TOKEN_DUPLICATE,&hTok))
    return CloseHandle(h),TRUE;
  CloseHandle(h);
  BOOL bAdmin=IsAdmin(hTok);
  CloseHandle(hTok);
  return bAdmin;
}

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
#define MENU_EXIT WM_USER+900
#define MENU_BALLON WM_USER+901
  int bBTip=g_BallonTips;
  g_BallonTips=0;
  if (bBTip)
  {
    //Close Balloon
    memset(&g_NotyData.szInfo,0,sizeof(g_NotyData.szInfo));
    lstrcpy(g_NotyData.szTip,"TrayShowAdmin");
    Shell_NotifyIcon(NIM_MODIFY,&g_NotyData);
  }
  POINT pt;
  GetCursorPos(&pt);
  HMENU hMenu=CreatePopupMenu();
  MenuAdd(hMenu,"TrayShowAdmin",(UINT)-1,MFS_ENABLED|MFS_UNCHECKED|MFS_DEFAULT);
  AppendMenu(hMenu,MF_SEPARATOR,(UINT)-1,0);
  MenuAdd(hMenu,"Balloon Tips for elevated programs",MENU_BALLON,MFS_ENABLED|((bBTip==1)?MFS_CHECKED:MFS_UNCHECKED));
  MenuAdd(hMenu,"Balloon Tips for all programs",MENU_BALLON+1,MFS_ENABLED|((bBTip==2)?MFS_CHECKED:MFS_UNCHECKED));
  AppendMenu(hMenu,MF_SEPARATOR,(UINT)-1,0);
  MenuAdd(hMenu,"E&xit",MENU_EXIT,MFS_ENABLED|MFS_UNCHECKED);
  switch (TrackPopupMenu(hMenu,TPM_RIGHTALIGN|TPM_RETURNCMD|TPM_NONOTIFY|TPM_VERNEGANIMATION,
    pt.x+1,pt.y+1,0,hWnd,NULL))
  {
  case MENU_EXIT:
    PostQuitMessage(0);
    break;
  case MENU_BALLON:
    if(bBTip==1)
      bBTip=FALSE;
    else
      bBTip=1;
    break;
  case MENU_BALLON+1:
    if(bBTip==2)
      bBTip=FALSE;
    else
      bBTip=2;
    break;
  }
  DestroyMenu(hMenu);
  g_BallonTips=bBTip;
};

static void DisplayIcon()
{
  HICON OldIcon=g_NotyData.hIcon;
  TCHAR User[MAX_PATH*2+2]={0};
  TCHAR WndTxt[MAX_PATH+1]={0};
  HWND FgWnd=0;
  BOOL bIsFGAdm=ForegroundWndIsAdmin(User,FgWnd,WndTxt);
  if (strlen(WndTxt)>64)
  {
    WndTxt[61]='.';
    WndTxt[62]='.';
    WndTxt[63]='.';
    WndTxt[64]=0;
  }
  if (strlen(User)>32)
  {
    WndTxt[29]='.';
    WndTxt[30]='.';
    WndTxt[31]='.';
    WndTxt[32]=0;
  }
  if ((g_ForegroundWndIsAdmin==bIsFGAdm)
    && (strcmp(g_User,User)==0)
    &&(g_FgWnd==FgWnd))
    return;
  g_FgWnd=FgWnd;
  g_ForegroundWndIsAdmin=bIsFGAdm;
  strcpy(g_User,User);
  memset(&g_NotyData.szInfo,0,sizeof(g_NotyData.szInfo));
  lstrcpy(g_NotyData.szTip,"TrayShowAdmin");
  if (bIsFGAdm==-1)
  {
    g_NotyData.hIcon=(HICON)LoadImage(g_hInstance,MAKEINTRESOURCE(IDI_NOWINDOW),
                                        IMAGE_ICON,16,16,LR_DEFAULTCOLOR);
  }else if (bIsFGAdm)
  {
    g_NotyData.hIcon=(HICON)LoadImage(g_hInstance,MAKEINTRESOURCE(IDI_ADMIN),
                                        IMAGE_ICON,16,16,LR_DEFAULTCOLOR);
    if (g_BallonTips)
      sprintf(g_NotyData.szInfo,"\"%s\"\n\n\"%s\" - Administrator",WndTxt,User);
    sprintf(g_NotyData.szTip,"TrayShowAdmin\n\"%s\"\n\"%s\" - Administrator",WndTxt,User);
  }else
  {
    g_NotyData.hIcon=(HICON)LoadImage(g_hInstance,MAKEINTRESOURCE(IDI_NOADMIN),
                                        IMAGE_ICON,16,16,LR_DEFAULTCOLOR);
    if (g_BallonTips==2)
      sprintf(g_NotyData.szInfo,"\"%s\"\n\n\"%s\" - Standard user",WndTxt,User);
    sprintf(g_NotyData.szTip,"TrayShowAdmin\n\"%s\"\n\"%s\" - Standard user",WndTxt,User);
  }
  Shell_NotifyIcon(NIM_MODIFY,&g_NotyData);
  DestroyIcon(OldIcon);
};

LRESULT CALLBACK WndMainProc(HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam)
{
  switch (message)
  {
  case WM_TASKBAR:
    {
      switch (lParam)
      {
      case WM_LBUTTONDOWN:
      case WM_RBUTTONDOWN:
      case WM_CONTEXTMENU:
        DisplayMenu(hwnd);
        return 0;
      };
    };
    break;
  case WM_TIMER:
    if (wParam==1)
      DisplayIcon();
    break;
  }
  return DefWindowProc (hwnd , message, wParam, lParam);
}

int APIENTRY WinMain(HINSTANCE hInstance,
                     HINSTANCE hPrevInstance,
                     LPSTR     lpCmdLine,
                     int       nCmdShow)
{
  CreateMutex(NULL,true,"TrayShowAdmin_Is_Running");
  if (GetLastError()==ERROR_ALREADY_EXISTS)
    return -1;
  g_hInstance=hInstance;  
  WNDCLASS WCLASS={0};
  WCLASS.hCursor      =LoadCursor(0,IDC_ARROW);
  WCLASS.lpszClassName=CLASSNAME;
  WCLASS.hInstance    =g_hInstance;
  WCLASS.style        =CS_BYTEALIGNCLIENT | CS_BYTEALIGNWINDOW;
  WCLASS.lpfnWndProc  =&WndMainProc;
  RegisterClass(&WCLASS);
  g_NotyData.cbSize= sizeof(NOTIFYICONDATA);
  g_NotyData.hWnd  = CreateWindowEx(0,CLASSNAME,"TrayShowAdmin",WS_POPUP,0,0,0,0,0,0,hInstance,NULL);
  g_NotyData.hIcon = (HICON)LoadImage(g_hInstance,MAKEINTRESOURCE(IDI_NOWINDOW),
                                        IMAGE_ICON,16,16,LR_DEFAULTCOLOR);
  
  lstrcpy(g_NotyData.szTip,"TrayShowAdmin");
  lstrcpy(g_NotyData.szInfoTitle,"TrayShowAdmin");
  g_NotyData.dwInfoFlags=NIIF_INFO|NIIF_NOSOUND;
  g_NotyData.uID   = 1;
  g_NotyData.uFlags= NIF_ICON|NIF_TIP|NIF_INFO|NIF_MESSAGE;
  g_NotyData.uCallbackMessage = WM_TASKBAR;
  Shell_NotifyIcon(NIM_ADD,&g_NotyData);
  

  g_NotyData.uVersion=NOTIFYICON_VERSION;
  Shell_NotifyIcon(NIM_SETVERSION,&g_NotyData);
  g_NotyData.uTimeout=10000;
  
  MSG msg={0};
  SetTimer(g_NotyData.hWnd,1,250,0);
  while(GetMessage(&msg,NULL,0,0))
  {
    TranslateMessage(&msg);
    DispatchMessage(&msg);
  }
  KillTimer(g_NotyData.hWnd,1);
  Shell_NotifyIcon(NIM_DELETE,&g_NotyData);
  DestroyWindow(g_NotyData.hWnd);
  return (int) msg.wParam;
}
