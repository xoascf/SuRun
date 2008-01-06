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
#include "Setup.h"
#include "Resource.h"

#pragma comment(lib,"shlwapi.lib")
#pragma comment(lib,"Netapi32.lib")
#pragma comment(lib,"Gdi32.lib")
#pragma comment(lib,"comctl32.lib")

#ifdef _DEBUG
//#define _DEBUGLOGON
#endif _DEBUG

//////////////////////////////////////////////////////////////////////////////
//
//  Logon Helper
//
//////////////////////////////////////////////////////////////////////////////

HANDLE GetUserToken(LPCTSTR User,LPCTSTR Password)
{
  TCHAR un[2*UNLEN+2]={0};
  TCHAR dn[2*UNLEN+2]={0};
  _tcscpy(un,User);
  PathStripPath(un);
  _tcscpy(dn,User);
  PathRemoveFileSpec(dn);
  HANDLE hToken=NULL;
  EnablePrivilege(SE_CHANGE_NOTIFY_NAME);
  EnablePrivilege(SE_TCB_NAME);//Win2k
  //Enable use of empty passwords for network logon
  BOOL bEmptyPWAllowed=FALSE;
  if ((Password==NULL) || (*Password==NULL))
  {
    bEmptyPWAllowed=EmptyPWAllowed;
    AllowEmptyPW(TRUE);
  }
  if (!LogonUser(un,dn,Password,LOGON32_LOGON_NETWORK,0,&hToken))
    if (GetLastError()==ERROR_PRIVILEGE_NOT_HELD)
      hToken=SSPLogonUser(dn,un,Password);
  DBGTrace4("GetUserToken(%s,%s,%s):%s",un,dn,Password,hToken?_T("SUCCEEDED."):_T("FAILED!"));
  //Reset status of "use of empty passwords for network logon"
  if ((Password==NULL) || (*Password==NULL))
    AllowEmptyPW(bEmptyPWAllowed);
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
  int TimeOut;
  DWORD UsrFlags;
  _LOGONDLGPARAMS(LPCTSTR M,LPTSTR Usr,LPTSTR Pwd,BOOL RO,BOOL Adm,DWORD UFlags)
  {
    Msg=M;
    User=Usr;
    Password=Pwd;
    UserReadonly=RO;
    ForceAdminLogon=Adm;
    UsrFlags=UFlags;
    TimeOut=40;//s
  }
}LOGONDLGPARAMS;

//User Bitmaps:
static void SetUserBitmap(HWND hwnd)
{
  LOGONDLGPARAMS* p=(LOGONDLGPARAMS*)GetWindowLongPtr(hwnd,GWLP_USERDATA);
  if (p==0)
    return;
  TCHAR User[UNLEN+GNLEN+2]={0};
  GetDlgItemText(hwnd,IDC_USER,User,UNLEN+GNLEN+1);
  int n=(int)SendDlgItemMessage(hwnd,IDC_USER,CB_GETCURSEL,0,0);
  if (n!=CB_ERR)
    SendDlgItemMessage(hwnd,IDC_USER,CB_GETLBTEXT,n,(LPARAM)&User);
  HBITMAP bm=p->Users.GetUserBitmap(User);
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

//Dialog Resizing:
SIZE RectSize(RECT r)
{
  SIZE s={r.right-r.left,r.bottom-r.top};
  return s;
}

SIZE CliSize(HWND w)
{
  RECT r={0};
  GetClientRect(w,&r);
  return RectSize(r);
}

//These controls are not changed on X-Resize
int NX_Ctrls[]={IDC_SECICON,IDC_SECICON1,IDC_USERBITMAP,IDC_USRST,IDC_PWDST};
//These controls are stretched on X-Resize
int SX_Ctrls[]={IDC_WHTBK,IDC_HINTBK,IDC_FRAME1,IDC_FRAME2,IDC_DLGQUESTION,
                IDC_USER,IDC_PASSWORD,IDC_HINT,IDC_HINT2,IDC_ALWAYSOK};
//These controls are moved on X-Resize
int MX_Ctrls[]={IDCANCEL,IDOK};
//These controls are not changed on Y-Resize
int NY_Ctrls[]={IDC_SECICON};
//These controls are stretched on Y-Resize
int SY_Ctrls[]={IDC_WHTBK,IDC_DLGQUESTION};
//These controls are moved on Y-Resize
int MY_Ctrls[]={IDC_SECICON1,IDC_USERBITMAP,IDC_HINTBK,IDC_FRAME1,IDC_FRAME2,
                IDC_USER,IDC_PASSWORD,IDC_HINT,IDC_HINT2,IDCANCEL,IDOK,
                IDC_USRST,IDC_PWDST,IDC_ALWAYSOK};

void MoveDlgCtrl(HWND hDlg,int nId,int x,int y,int dx,int dy)
{
  HWND w=GetDlgItem(hDlg,nId);
  if(w)
  {
    RECT r;
    GetWindowRect(w,&r);
    ScreenToClient(hDlg,(LPPOINT)&r.left);
    ScreenToClient(hDlg,(LPPOINT)&r.right);
    MoveWindow(w,r.left+x,r.top+y,r.right-r.left+dx,r.bottom-r.top+dy,TRUE);
  }
}
    
void MoveWnd(HWND hwnd,int x,int y,int dx,int dy)
{
  RECT r;
  GetWindowRect(hwnd,&r);
  MoveWindow(hwnd,r.left+x,r.top+y,r.right-r.left+dx,r.bottom-r.top+dy,TRUE);
}
    
SIZE GetDrawSize(HWND w)
{
  TCHAR s[4096];
  GetWindowText(w,s,4096);
  HDC dc=GetDC(0);
  HDC MemDC=CreateCompatibleDC(dc);
  ReleaseDC(0,dc);
  SelectObject(MemDC,(HGDIOBJ)SendMessage(w,WM_GETFONT,0,0));
  RECT r={0};
  DrawText(MemDC,s,-1,&r,DT_CALCRECT|DT_NOCLIP|DT_NOPREFIX|DT_EXPANDTABS);
  //the size needed is sometimes too small
  //Tests have shown that 8 pixels added to cx would be enough
  //I'll add 10 pixels to cx and pixels 4 to cx until I know a better way:
  SIZE S={r.right-r.left+10,r.bottom-r.top+4};
  //Limit the width to 90% of the screen width
  int maxDX=GetSystemMetrics(SM_CXFULLSCREEN)*9/10;
  if (S.cx>maxDX)
  {
    TEXTMETRIC tm;
    GetTextMetrics(MemDC,&tm);
    S.cy+=tm.tmHeight*(S.cx/maxDX);
    S.cx=maxDX;
    //Limit the height to 60% of the screen height
    int maxDY=GetSystemMetrics(SM_CXFULLSCREEN)*6/10;
    if (S.cy>maxDY)
    {
      S.cy=maxDY;
      SetWindowLong(w,GWL_STYLE,GetWindowLong(w,GWL_STYLE)|WS_VSCROLL|WS_HSCROLL);
    }
  }
  DeleteDC(MemDC);
  return S;
}

void SetWindowSizes(HWND hDlg)
{
  RECT dlgr={0};
  GetWindowRect(hDlg,&dlgr);
  HWND ew=GetDlgItem(hDlg,IDC_DLGQUESTION);
  SIZE ds=GetDrawSize(ew);
  SIZE es=CliSize(ew);
  //Resize X
  int dx=ds.cx-es.cx;
  if (dx>0) 
  {
    MoveWnd(hDlg,-dx/2,0,dx,0);
    for (int i=0;i<countof(SX_Ctrls);i++)
      MoveDlgCtrl(hDlg,SX_Ctrls[i],0,0,dx,0);
    for (i=0;i<countof(MX_Ctrls);i++)
      MoveDlgCtrl(hDlg,MX_Ctrls[i],dx,0,0,0);
  }
  //Resize Y
  int dy=ds.cy-es.cy;
  if (dy>0)
  {
    MoveWnd(hDlg,0,-dy/2,0,dy);
    for (int i=0;i<countof(SY_Ctrls);i++)
      MoveDlgCtrl(hDlg,SY_Ctrls[i],0,0,0,dy);
    for (i=0;i<countof(MY_Ctrls);i++)
      MoveDlgCtrl(hDlg,MY_Ctrls[i],0,dy,0,0);
  }
}

//DialogProc
HBRUSH g_HintBrush=0;
INT_PTR CALLBACK DialogProc(HWND hwnd,UINT msg,WPARAM wParam,LPARAM lParam)
{
  switch(msg)
  {
  case WM_INITDIALOG:
    {
      LOGONDLGPARAMS* p=(LOGONDLGPARAMS*)lParam;
      SetWindowLongPtr(hwnd,GWLP_USERDATA,lParam);
      if (IsWindowEnabled(GetDlgItem(hwnd,IDC_PASSWORD)))
        g_HintBrush=CreateSolidBrush(RGB(192,128,0));
      else
        g_HintBrush=CreateSolidBrush(RGB(128,192,0));
      SendMessage(hwnd,WM_SETICON,ICON_BIG,
        (LPARAM)LoadImage(GetModuleHandle(0),MAKEINTRESOURCE(IDI_MAINICON),
        IMAGE_ICON,32,32,0));
      SendMessage(hwnd,WM_SETICON,ICON_SMALL,
        (LPARAM)LoadImage(GetModuleHandle(0),MAKEINTRESOURCE(IDI_MAINICON),
        IMAGE_ICON,16,16,0));
      SendDlgItemMessage(hwnd,IDC_DLGQUESTION,WM_SETFONT,
        (WPARAM)CreateFont(-14,0,0,0,FW_MEDIUM,0,0,0,0,0,0,0,0,_T("MS Shell Dlg")),1);
      if (GetDlgItem(hwnd,IDC_HINT))
        SendDlgItemMessage(hwnd,IDC_HINT,WM_SETFONT,
          (WPARAM)CreateFont(-14,0,0,0,FW_NORMAL,0,0,0,0,0,0,0,0,_T("MS Shell Dlg")),1);
      SetDlgItemText(hwnd,IDC_DLGQUESTION,p->Msg);
      SetDlgItemText(hwnd,IDC_PASSWORD,p->Password);
      SendDlgItemMessage(hwnd,IDC_PASSWORD,EM_SETPASSWORDCHAR,'*',0);
      BOOL bFoundUser=FALSE;
      for (int i=0;i<p->Users.GetCount();i++)
      {
        SendDlgItemMessage(hwnd,IDC_USER,CB_INSERTSTRING,i,
          (LPARAM)p->Users.GetUserName(i));
        if (_tcsicmp(p->Users.GetUserName(i),p->User)==0)
        {
          SendDlgItemMessage(hwnd,IDC_USER,CB_SETCURSEL,i,0);
          bFoundUser=TRUE;
        }
      }
      if (p->UserReadonly)
      {
        EnableWindow(GetDlgItem(hwnd,IDC_USER),false);
        if (GetNoRunSetup(p->User))
        {
          EnableWindow(GetDlgItem(hwnd,IDC_SHELLEXECOK),false);
          EnableWindow(GetDlgItem(hwnd,IDC_ALWAYSOK),false);
        }
      }
      if (IsWindowEnabled(GetDlgItem(hwnd,IDC_USER)))
        SetFocus(GetDlgItem(hwnd,IDC_USER));
      else if (IsWindowEnabled(GetDlgItem(hwnd,IDC_PASSWORD)))
      {
        SendDlgItemMessage(hwnd,IDC_PASSWORD,EM_SETSEL,0,-1);
        SetFocus(GetDlgItem(hwnd,IDC_PASSWORD));
      }else
        SetFocus(GetDlgItem(hwnd,IDCANCEL));
      if ((!p->ForceAdminLogon)|| bFoundUser)
        SetDlgItemText(hwnd,IDC_USER,p->User);
      else
      {
        SetDlgItemText(hwnd,IDC_USER,p->Users.GetUserName(0));
        SendDlgItemMessage(hwnd,IDC_USER,CB_SETCURSEL,0,0);
      }
      CheckDlgButton(hwnd,IDC_SHELLEXECOK,(p->UsrFlags&FLAG_SHELLEXEC)?1:0);
      CheckDlgButton(hwnd,IDC_ALWAYSOK,(p->UsrFlags&(FLAG_DONTASK|FLAG_AUTOCANCEL))?1:0);
      SetUserBitmap(hwnd);
      SetWindowSizes(hwnd);
      SetTimer(hwnd,2,1000,0);
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
        return (BOOL)PtrToUlong(GetStockObject(WHITE_BRUSH));
      }
      if ((CtlId==IDC_HINT)||(CtlId==IDC_SECICON1))
      {
        SetBkMode((HDC)wParam,TRANSPARENT);
        return (BOOL)PtrToUlong(g_HintBrush);
      }
      if (CtlId==IDC_HINTBK)
        return (BOOL)PtrToUlong(g_HintBrush);
      break;
    }
  case WM_TIMER:
    {
      if (wParam==1)
        SetUserBitmap(hwnd);
      if (wParam==2)
      {
        LOGONDLGPARAMS* p=(LOGONDLGPARAMS*)GetWindowLongPtr(hwnd,GWLP_USERDATA);
        p->TimeOut--;
        if (p->TimeOut<0)
          EndDialog(hwnd,0);
        else if (p->TimeOut<10)
          SetDlgItemText(hwnd,IDCANCEL,CResStr(IDS_CANCEL,p->TimeOut));
      }
      return TRUE;
    }
  case WM_COMMAND:
    {
      switch (wParam)
      {
      case MAKEWPARAM(IDC_USER,CBN_DROPDOWN):
        SetTimer(hwnd,1,250,0);
        return TRUE;
      case MAKEWPARAM(IDC_USER,CBN_CLOSEUP):
        KillTimer(hwnd,1);
        return TRUE;
      case MAKEWPARAM(IDC_USER,CBN_SELCHANGE):
      case MAKEWPARAM(IDC_USER,CBN_EDITCHANGE):
        SetUserBitmap(hwnd);
        return TRUE;
      case MAKEWPARAM(IDCANCEL,BN_CLICKED):
        EndDialog(hwnd,0);
        return TRUE;
      case MAKEWPARAM(IDOK,BN_CLICKED):
        {
          INT_PTR ExitCode=1+(IsDlgButtonChecked(hwnd,IDC_ALWAYSOK)<<1)
                            +(IsDlgButtonChecked(hwnd,IDC_SHELLEXECOK)<<2);
          if (IsWindowEnabled(GetDlgItem(hwnd,IDC_PASSWORD)))
          {
            LOGONDLGPARAMS* p=(LOGONDLGPARAMS*)GetWindowLongPtr(hwnd,GWLP_USERDATA);
            GetDlgItemText(hwnd,IDC_USER,p->User,UNLEN+GNLEN+1);
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
                EndDialog(hwnd,ExitCode);
              }
            }else
            {
              MessageBox(hwnd,CBigResStr(IDS_LOGONFAILED),CResStr(IDS_APPNAME),MB_ICONINFORMATION);
              SendDlgItemMessage(hwnd,IDC_PASSWORD,EM_SETSEL,0,-1);
              SetFocus(GetDlgItem(hwnd,IDC_PASSWORD));
            }
          }else
            EndDialog(hwnd,ExitCode);
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
  LOGONDLGPARAMS p(S,User,Password,false,false,false);
  p.Users.SetUsualUsers(FALSE);
  return (BOOL)DialogBoxParam(GetModuleHandle(0),MAKEINTRESOURCE(IDD_LOGONDLG),
                  0,DialogProc,(LPARAM)&p);
}

BOOL LogonAdmin(LPTSTR User,LPTSTR Password,int IDmsg,...)
{
  va_list va;
  va_start(va,IDmsg);
  CBigResStr S(IDmsg,va);
  LOGONDLGPARAMS p(S,User,Password,false,true,false);
  p.Users.SetGroupUsers(DOMAIN_ALIAS_RID_ADMINS,TRUE);
  return (BOOL)DialogBoxParam(GetModuleHandle(0),MAKEINTRESOURCE(IDD_LOGONDLG),
                  0,DialogProc,(LPARAM)&p);
}

BOOL LogonAdmin(int IDmsg,...)
{
  va_list va;
  va_start(va,IDmsg);
  CBigResStr S(IDmsg,va);
  TCHAR U[UNLEN+GNLEN+2]={0};
  TCHAR P[PWLEN]={0};
  LOGONDLGPARAMS p(S,U,P,false,true,false);
  p.Users.SetGroupUsers(DOMAIN_ALIAS_RID_ADMINS,TRUE);
  BOOL bRet=(BOOL)DialogBoxParam(GetModuleHandle(0),
                    MAKEINTRESOURCE(IDD_LOGONDLG),0,DialogProc,(LPARAM)&p);
  zero(U);
  zero(P);
  return bRet;
}

DWORD LogonCurrentUser(LPTSTR User,LPTSTR Password,DWORD UsrFlags,int IDmsg,...)
{
  va_list va;
  va_start(va,IDmsg);
  CBigResStr S(IDmsg,va);
  LOGONDLGPARAMS p(S,User,Password,true,false,UsrFlags);
  return (DWORD )DialogBoxParam(GetModuleHandle(0),MAKEINTRESOURCE(IDD_CURUSRLOGON),
                  0,DialogProc,(LPARAM)&p);
}

DWORD AskCurrentUserOk(LPTSTR User,DWORD UsrFlags,int IDmsg,...)
{
  va_list va;
  va_start(va,IDmsg);
  CBigResStr S(IDmsg,va);
  LOGONDLGPARAMS p(S,User,_T("******"),true,false,UsrFlags);
  return (DWORD)DialogBoxParam(GetModuleHandle(0),MAKEINTRESOURCE(IDD_CURUSRACK),
                  0,DialogProc,(LPARAM)&p);
}

#ifdef _DEBUGLOGON
BOOL TestLogonDlg()
{
  INITCOMMONCONTROLSEX icce={sizeof(icce),ICC_USEREX_CLASSES|ICC_WIN95_CLASSES};
  InitCommonControlsEx(&icce);
  TCHAR User[MAX_PATH]=L"Bruns\\KAY";
  TCHAR Password[MAX_PATH]={0};

  SetThreadLocale(MAKELCID(MAKELANGID(LANG_GERMAN,SUBLANG_GERMAN),SORT_DEFAULT));

  BOOL l=Logon(User,Password,IDS_ASKINSTALL);
  if (l==-1)
    DBGTrace2("DialogBoxParam returned %d: %s",l,GetLastErrorNameStatic());
  l=LogonAdmin(IDS_NOADMIN2,L"BRUNS\\NixDu");
  if (l==-1)
    DBGTrace2("DialogBoxParam returned %d: %s",l,GetLastErrorNameStatic());
  l=LogonAdmin(User,Password,IDS_NOSURUNNER);
  if (l==-1)
    DBGTrace2("DialogBoxParam returned %d: %s",l,GetLastErrorNameStatic());
  l=LogonCurrentUser(User,Password,0,IDS_ASKOK,L"cmd");
  if (l==-1)
    DBGTrace2("DialogBoxParam returned %d: %s",l,GetLastErrorNameStatic());
  l=AskCurrentUserOk(User,0,IDS_ASKOK,L"cmd");
  if (l==-1)
    DBGTrace2("DialogBoxParam returned %d: %s",l,GetLastErrorNameStatic());

  SetThreadLocale(MAKELCID(MAKELANGID(LANG_ENGLISH,SUBLANG_ENGLISH_US),SORT_DEFAULT));

  l=Logon(User,Password,IDS_ASKINSTALL);
  if (l==-1)
    DBGTrace2("DialogBoxParam returned %d: %s",l,GetLastErrorNameStatic());
  l=LogonAdmin(IDS_NOADMIN2,L"BRUNS\\NixDu");
  if (l==-1)
    DBGTrace2("DialogBoxParam returned %d: %s",l,GetLastErrorNameStatic());
  l=LogonAdmin(User,Password,IDS_NOSURUNNER);
  if (l==-1)
    DBGTrace2("DialogBoxParam returned %d: %s",l,GetLastErrorNameStatic());
  l=LogonCurrentUser(User,Password,0,IDS_ASKOK,L"cmd");
  if (l==-1)
    DBGTrace2("DialogBoxParam returned %d: %s",l,GetLastErrorNameStatic());
  l=AskCurrentUserOk(User,0,IDS_ASKOK,L"cmd");
  if (l==-1)
    DBGTrace2("DialogBoxParam returned %d: %s",l,GetLastErrorNameStatic());

  SetThreadLocale(MAKELCID(MAKELANGID(LANG_POLISH,0),SORT_DEFAULT));
  
  l=Logon(User,Password,IDS_ASKINSTALL);
  if (l==-1)
    DBGTrace2("DialogBoxParam returned %d: %s",l,GetLastErrorNameStatic());
  l=LogonAdmin(IDS_NOADMIN2,L"BRUNS\\NixDu");
  if (l==-1)
    DBGTrace2("DialogBoxParam returned %d: %s",l,GetLastErrorNameStatic());
  l=LogonAdmin(User,Password,IDS_NOSURUNNER);
  if (l==-1)
    DBGTrace2("DialogBoxParam returned %d: %s",l,GetLastErrorNameStatic());
  l=LogonCurrentUser(User,Password,0,IDS_ASKOK,L"cmd");
  if (l==-1)
    DBGTrace2("DialogBoxParam returned %d: %s",l,GetLastErrorNameStatic());
  l=AskCurrentUserOk(User,0,IDS_ASKOK,L"cmd");
  if (l==-1)
    DBGTrace2("DialogBoxParam returned %d: %s",l,GetLastErrorNameStatic());

  ::ExitProcess(0);
  return TRUE;
}

BOOL x=TestLogonDlg();
#endif _DEBUGLOGON
