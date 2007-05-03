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
#define _WIN32_WINNT 0x0500
#define WINVER       0x0500
#include <windows.h>
#include <stdio.h>
#include <tchar.h>
#include <shlwapi.h>
#include <lm.h>
#include <commctrl.h>
#include "Isadmin.h"
#include "ResStr.h"
#include "DBGTrace.h"
#include "UserGroups.h"
#include "sspi_auth.h"
#include "Helpers.h"
#include "Resource.h"

#pragma comment(lib,"shlwapi.lib")
#pragma comment(lib,"Netapi32.lib")
#pragma comment(lib,"Gdi32.lib")
#pragma comment(lib,"comctl32.lib")

/////////////////////////////////////////////////////////////////////////////
//
// LoadUserBitmap
//
/////////////////////////////////////////////////////////////////////////////

HBITMAP LoadUserBitmap(LPCTSTR UserName)
{
  TCHAR BMP[MAX_PATH];
  GetRegStr(HKEY_LOCAL_MACHINE,
    _T("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders"),
    _T("Common AppData"),BMP,MAX_PATH);
  PathUnquoteSpaces(BMP);
  PathAppend(BMP,_T("Microsoft\\User Account Pictures"));
  TCHAR usr[UNLEN];
  _tcscpy(usr,UserName);
  PathStripPath(usr);
  PathAppend(BMP,usr);
  PathAddExtension(BMP,_T(".bmp"));
  //DBGTrace1("LoadUserBitmap: %s",Pic);
  return (HBITMAP)LoadImage(0,BMP,IMAGE_BITMAP,0,0,LR_LOADFROMFILE);
}

/////////////////////////////////////////////////////////////////////////////
//
// User list
//
/////////////////////////////////////////////////////////////////////////////

typedef struct  
{
  WCHAR UserName[UNLEN+UNLEN];
  HBITMAP UserBitmap;
}USERDATA;

class USERLIST
{
public:
  int nUsers;
  USERDATA User[1024];
  USERLIST(BOOL bAdminsOnly)
  {
    nUsers=0;
    if (bAdminsOnly)
      AddGroupUsers(DOMAIN_ALIAS_RID_ADMINS);
    else for (int g=0;g<countof(UserGroups);g++)
      AddGroupUsers(UserGroups[g]);
  }
  ~USERLIST()
  {
    for (int i=0;i<nUsers;i++)
      DeleteObject(User[i].UserBitmap);
  }
  void Add(LPWSTR UserName)
  {
    if(nUsers>511)
      return;
    for(int j=0;j<nUsers;j++)
    {
      int cr=_tcsicmp(User[j].UserName,UserName);
      if (cr==0)
        return;
      if (cr>0)
      {
        if (j<nUsers)
          memmove(&User[j+1],&User[j],(nUsers-j)*sizeof(User[0]));
        break;
      }
    }
    wcscpy(User[j].UserName,UserName);
    User[j].UserBitmap=LoadUserBitmap(UserName);
    nUsers++;
    return;
  }
private:
  void AddGroupUsers(DWORD WellKnownGroup)
  {
    DWORD i=0;
    DWORD GNLen=GNLEN;
    WCHAR GroupName[GNLEN+1];
    DWORD res=ERROR_MORE_DATA;
    if (GetGroupName(WellKnownGroup,GroupName,&GNLen)) for(;res==ERROR_MORE_DATA;)
    { 
      LPBYTE pBuff=0;
      DWORD dwRec=0;
      DWORD dwTot=0;
      res = NetLocalGroupGetMembers(NULL,GroupName,1,&pBuff,MAX_PREFERRED_LENGTH,&dwRec,&dwTot,&i);
      if((res!=ERROR_SUCCESS) && (res!=ERROR_MORE_DATA))
      {
        DBGTrace1("NetLocalGroupGetMembers failed: %s",GetErrorNameStatic(res));
        break;
      }
      for(LOCALGROUP_MEMBERS_INFO_1* p=(LOCALGROUP_MEMBERS_INFO_1*)pBuff;dwRec>0;dwRec--,p++)
      {
        if (p->lgrmi1_sidusage==SidTypeUser)
        {
          USER_INFO_2* b=0;
          NetUserGetInfo(0,p->lgrmi1_name,2,(LPBYTE*)&b);
          if (b)
          {
            if ((b->usri2_flags & UF_ACCOUNTDISABLE)==0)
              Add(p->lgrmi1_name);
            NetApiBufferFree(b);
          }else
            DBGTrace1("NetLocalGroupGetMembers failed: %s",GetErrorNameStatic(res));
        }
      }
      NetApiBufferFree(pBuff);
    }
  }
};

//////////////////////////////////////////////////////////////////////////////
//
//  Logon Helper
//
//////////////////////////////////////////////////////////////////////////////

HANDLE GetUserToken(LPCTSTR User,LPCTSTR Password)
{
  HANDLE hToken=NULL;
  EnablePrivilege(SE_CHANGE_NOTIFY_NAME);
  EnablePrivilege(SE_TCB_NAME);//Win2k
  if (!LogonUser(User,0,Password,LOGON32_LOGON_NETWORK,0,&hToken))
    if (GetLastError()==ERROR_PRIVILEGE_NOT_HELD)
      hToken=SSPLogonUser(0,User,Password);
  DBGTrace3("GetUserToken(%s,%s):%s",User,Password,hToken?_T("SUCCEEDED."):_T("FAILED!"));
  return hToken;
}

BOOL PasswordOK(LPCTSTR User,LPCTSTR Password)
{
  HANDLE hToken=GetUserToken(User,Password);
  BOOL bRet=hToken!=0;
  CloseHandle(hToken);
  return bRet;
}

/////////////////////////////////////////////////////////////////////////////
//
// Logon Dialog
//
/////////////////////////////////////////////////////////////////////////////

typedef struct _LOGONDLGPARAMS
{
  LPCTSTR Msg;
  LPTSTR User;
  LPTSTR Password;
  BOOL UserReadonly;
  BOOL ForceAdminLogon;
  USERLIST Users;
  _LOGONDLGPARAMS(LPCTSTR M,LPTSTR Usr,LPTSTR Pwd,BOOL RO,BOOL Adm):Users(Adm)
  {
    Msg=M;
    User=Usr;
    Password=Pwd;
    UserReadonly=RO;
    ForceAdminLogon=Adm;
  }
}LOGONDLGPARAMS;

void SetUserBitmap(HWND hwnd)
{
  LOGONDLGPARAMS* p=(LOGONDLGPARAMS*)GetWindowLong(hwnd,GWL_USERDATA);
  if (p==0)
    return;
  HWND UserList=GetDlgItem(hwnd,IDC_USER);
  HWND Edit=(HWND)SendMessage(UserList,CBEM_GETEDITCONTROL,0,0);
  TCHAR User[UNLEN+GNLEN+2]={0};
  GetWindowText(Edit,User,UNLEN+GNLEN+1);
  HBITMAP bm=0;
  for (int i=0;i<p->Users.nUsers;i++) 
    if (_tcsicmp(p->Users.User[i].UserName,User)==0)
    {
      bm=p->Users.User[i].UserBitmap;
      break;
    }
  HWND BmpIcon=GetDlgItem(hwnd,IDC_USERBITMAP);
  DWORD dwStyle=GetWindowLong(BmpIcon,GWL_STYLE)&(~SS_TYPEMASK);
  if(bm)
  {
    SetWindowLong(BmpIcon,GWL_STYLE,dwStyle|SS_BITMAP|SS_REALSIZEIMAGE|SS_CENTERIMAGE);
    SendMessage(BmpIcon,STM_SETIMAGE,IMAGE_BITMAP,(LPARAM)bm);
  }else
  {
    SetWindowLong(BmpIcon,GWL_STYLE,dwStyle|SS_ICON|SS_REALSIZEIMAGE|SS_CENTERIMAGE);
    SendMessage(BmpIcon,STM_SETIMAGE,IMAGE_ICON,
      SendMessage(hwnd,WM_GETICON,ICON_BIG,0));
  }
}

HBRUSH g_HintBrush=0;
INT_PTR CALLBACK DialogProc(HWND hwnd,UINT msg,WPARAM wParam,LPARAM lParam)
{
  switch(msg)
  {
  case WM_INITDIALOG:
    {
      LOGONDLGPARAMS* p=(LOGONDLGPARAMS*)lParam;
      SetWindowLong(hwnd,GWL_USERDATA,lParam);
      if (IsWindowEnabled(GetDlgItem(hwnd,IDC_PASSWORD)))
        g_HintBrush=CreateSolidBrush(RGB(192,128,0));
      else
        g_HintBrush=CreateSolidBrush(RGB(128,192,0));
      SendMessage(hwnd,WM_SETICON,ICON_BIG,
        (LPARAM)LoadImage(GetModuleHandle(0),MAKEINTRESOURCE(IDI_MAINICON),
        IMAGE_ICON,0,0,0));
      SendMessage(hwnd,WM_SETICON,ICON_SMALL,
        (LPARAM)LoadImage(GetModuleHandle(0),MAKEINTRESOURCE(IDI_MAINICON),
        IMAGE_ICON,16,16,0));
      SendDlgItemMessage(hwnd,IDC_DLGQUESTION,WM_SETFONT,
        (WPARAM)CreateFont(-12,0,0,0,FW_MEDIUM,0,0,0,0,0,0,0,0,_T("Arial")),1);
      if (GetDlgItem(hwnd,IDC_HINT))
        SendDlgItemMessage(hwnd,IDC_HINT,WM_SETFONT,
          (WPARAM)CreateFont(-12,0,0,0,FW_NORMAL,0,0,0,0,0,0,0,0,_T("Arial")),1);
      SetDlgItemText(hwnd,IDC_DLGQUESTION,p->Msg);
      SetDlgItemText(hwnd,IDC_PASSWORD,p->Password);
      SendDlgItemMessage(hwnd,IDC_PASSWORD,EM_SETPASSWORDCHAR,'*',0);
      HWND UserList=GetDlgItem(hwnd,IDC_USER);
      SendMessage(UserList,CB_SETEXTENDEDUI,1,0);
      BOOL bFoundUser=FALSE;
      for (int i=0;i<p->Users.nUsers;i++)
      {
        COMBOBOXEXITEM cei={0};
        cei.mask=CBEIF_TEXT|CBEIF_LPARAM;
        cei.iItem=i;
        cei.lParam=(LPARAM)p->Users.User[i].UserBitmap;
        cei.pszText=p->Users.User[i].UserName;
        if (_tcsicmp(p->Users.User[i].UserName,p->User)==0)
          bFoundUser=TRUE;
        SendMessage(UserList,CBEM_INSERTITEM,0,(LPARAM)&cei);
      }
      HWND Edit=(HWND)SendMessage(UserList,CBEM_GETEDITCONTROL,0,0);
      if (bFoundUser || p->UserReadonly)
        SetWindowText(Edit,p->User);
      else
        SetWindowText(Edit,p->Users.User[0].UserName);
      SetUserBitmap(hwnd);
      if (IsWindowEnabled(GetDlgItem(hwnd,IDC_PASSWORD)))
        SetFocus(GetDlgItem(hwnd,IDC_PASSWORD));
      else
        SetFocus(GetDlgItem(hwnd,IDCANCEL));
      if (p->UserReadonly)
        EnableWindow(UserList,false);
      return FALSE;
    }//WM_INITDIALOG
  case WM_DESTROY:
    {
      HGDIOBJ fs=GetStockObject(DEFAULT_GUI_FONT);
      HGDIOBJ f=(HGDIOBJ)SendDlgItemMessage(hwnd,IDC_DLGQUESTION,WM_GETFONT,0,0);
      SendDlgItemMessage(hwnd,IDC_DLGQUESTION,WM_SETFONT,(WPARAM)fs,0);
      DeleteObject(f);
      if (GetDlgItem(hwnd,IDC_HINT))
      {
        f=(HGDIOBJ)SendDlgItemMessage(hwnd,IDC_HINT,WM_GETFONT,0,0);
        SendDlgItemMessage(hwnd,IDC_HINT,WM_SETFONT,(WPARAM)fs,0);
        DeleteObject(f);
      }
      return TRUE;
    }
  case WM_NCDESTROY:
    {
      DeleteObject(g_HintBrush);
      g_HintBrush=0;
      DestroyIcon((HICON)SendMessage(hwnd,WM_GETICON,ICON_BIG,0));
      DestroyIcon((HICON)SendMessage(hwnd,WM_GETICON,ICON_SMALL,0));
      return TRUE;
    }//WM_NCDESTROY
  case WM_CTLCOLORSTATIC:
    {
      int CtlId=GetDlgCtrlID((HWND)lParam);
      if ((CtlId==IDC_DLGQUESTION)||(CtlId==IDC_SECICON))
      {
        SetBkMode((HDC)wParam,TRANSPARENT);
        return (BOOL)GetStockObject(WHITE_BRUSH);
      }
      if ((CtlId==IDC_HINT)||(CtlId==IDC_SECICON1))
      {
        SetBkMode((HDC)wParam,TRANSPARENT);
        return (BOOL)g_HintBrush;
      }
      if (CtlId==IDC_HINTBK)
        return (BOOL)g_HintBrush;
      break;
    }
  case WM_COMMAND:
    {
      switch (wParam)
      {
      case MAKELPARAM(IDC_USER,CBN_EDITCHANGE):
        SetUserBitmap(hwnd);
        return TRUE;
      case MAKELPARAM(IDCANCEL,BN_CLICKED):
        EndDialog(hwnd,0);
        return TRUE;
      case MAKELPARAM(IDOK,BN_CLICKED):
        {
          if (IsWindowEnabled(GetDlgItem(hwnd,IDC_PASSWORD)))
          {
            LOGONDLGPARAMS* p=(LOGONDLGPARAMS*)GetWindowLong(hwnd,GWL_USERDATA);
            GetWindowText((HWND)SendMessage(GetDlgItem(hwnd,IDC_USER),CBEM_GETEDITCONTROL,0,0),p->User,UNLEN+GNLEN+1);
            GetWindowText((HWND)GetDlgItem(hwnd,IDC_PASSWORD),p->Password,PWLEN);
            HANDLE hUser=GetUserToken(p->User,p->Password);
            if (hUser)
            {
              if ((p->ForceAdminLogon)&&(!IsAdmin(hUser)))
              {
                CloseHandle(hUser);
                MessageBox(hwnd,CResStr(IDS_NOADMIN,p->User),CResStr(IDS_APPNAME),MB_ICONINFORMATION);
              }else
              {
                CloseHandle(hUser);
                EndDialog(hwnd,1);
              }
            }else
              MessageBox(hwnd,CResStr(IDS_LOGONFAILED),CResStr(IDS_APPNAME),MB_ICONINFORMATION);
          }else
            EndDialog(hwnd,1);
          return TRUE;
        }//MAKELPARAM(IDOK,BN_CLICKED)
      }//switch (wParam)
      break;
    }//WM_COMMAND
  }//switch(msg)
  return FALSE;
}

/////////////////////////////////////////////////////////////////////////////
//
// Logon Functions
//
/////////////////////////////////////////////////////////////////////////////

BOOL Logon(LPTSTR User,LPTSTR Password,int IDmsg,...)
{
  va_list va;
  va_start(va,IDmsg);
  CBigResStr S(IDmsg,va);
  LOGONDLGPARAMS p(S,User,Password,false,false);
  return DialogBoxParam(GetModuleHandle(0),MAKEINTRESOURCE(IDD_LOGONDLG),0,
    DialogProc,(LPARAM)&p);
}

BOOL LogonAdmin(LPTSTR User,LPTSTR Password,int IDmsg,...)
{
  va_list va;
  va_start(va,IDmsg);
  CBigResStr S(IDmsg,va);
  LOGONDLGPARAMS p(S,User,Password,false,true);
  return DialogBoxParam(GetModuleHandle(0),MAKEINTRESOURCE(IDD_LOGONDLG),0,
    DialogProc,(LPARAM)&p);
}

BOOL LogonCurrentUser(LPTSTR User,LPTSTR Password,int IDmsg,...)
{
  va_list va;
  va_start(va,IDmsg);
  CBigResStr S(IDmsg,va);
  LOGONDLGPARAMS p(S,User,Password,true,false);
  return DialogBoxParam(GetModuleHandle(0),MAKEINTRESOURCE(IDD_CURUSRLOGON),0,
    DialogProc,(LPARAM)&p);
}

BOOL AskCurrentUserOk(LPTSTR User,int IDmsg,...)
{
  va_list va;
  va_start(va,IDmsg);
  CBigResStr S(IDmsg,va);
  LOGONDLGPARAMS p(S,User,_T("******"),true,false);
  return DialogBoxParam(GetModuleHandle(0),MAKEINTRESOURCE(IDD_CURUSRACK),0,
    DialogProc,(LPARAM)&p);
}
