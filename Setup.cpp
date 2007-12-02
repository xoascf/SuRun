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

#ifdef _DEBUG
#define _DEBUGSETUP
#endif _DEBUG

#define _WIN32_WINNT 0x0500
#define WINVER       0x0500
#include <windows.h>
#include <windowsx.h>
#include <stdio.h>
#include <tchar.h>
#include <lm.h>
#include <commctrl.h>
#include "Setup.h"
#include "Helpers.h"
#include "BlowFish.h"
#include "ResStr.h"
#include "UserGroups.h"
#include "lsa_laar.h"
#include "DBGTrace.h"
#include "Resource.h"
#include "Service.h"

#pragma comment(lib,"comctl32.lib")

//////////////////////////////////////////////////////////////////////////////
// 
//  Password cache
// 
//////////////////////////////////////////////////////////////////////////////

static BYTE KEYPASS[16]={0x5B,0xC3,0x25,0xE9,0x8F,0x2A,0x41,0x10,0xA3,0xF4,0x26,0xD1,0x62,0xB4,0x0A,0xE2};

void LoadPassword(LPTSTR UserName,LPTSTR Password,DWORD nBytes)
{
  if (!GetSavePW)
    return;
  CBlowFish bf;
  bf.Initialize(KEYPASS,sizeof(KEYPASS));
  if(GetRegAny(HKLM,PASSWKEY,UserName,REG_BINARY,(BYTE*)Password,&nBytes))
    bf.Decode((BYTE*)Password,(BYTE*)Password,nBytes);
}

void DeletePassword(LPTSTR UserName)
{
  RegDelVal(HKLM,PASSWKEY,UserName);
  RegDelVal(HKLM,TIMESKEY,UserName);
}

void SavePassword(LPTSTR UserName,LPTSTR Password)
{
  if (!GetSavePW)
    return;
  CBlowFish bf;
  TCHAR pw[PWLEN];
  bf.Initialize(KEYPASS,sizeof(KEYPASS));
  SetRegAny(HKLM,PASSWKEY,UserName,REG_BINARY,(BYTE*)pw,
    bf.Encode((BYTE*)Password,(BYTE*)pw,(int)_tcslen(Password)*sizeof(TCHAR)));
}

//////////////////////////////////////////////////////////////////////////////
// 
//  Password TimeOut
// 
//////////////////////////////////////////////////////////////////////////////

//FILETIME(100ns) to minutes multiplier
#define ft2min  (__int64)(10/*1µs*/*1000/*1ms*/*1000/*1s*/*60/*1min*/)

BOOL PasswordExpired(LPTSTR UserName)
{
  __int64 ft;
  GetSystemTimeAsFileTime((LPFILETIME)&ft);
  __int64 pwto=ft2min*GetPwTimeOut;
  if ((pwto==0) || ((ft-GetRegInt64(HKLM,TIMESKEY,UserName,0))<pwto))
    return FALSE;
  DBGTrace1("Password for %s Expired!",UserName);
  DeletePassword(UserName);
  return TRUE;
}

void UpdLastRunTime(LPTSTR UserName)
{
  __int64 ft;
  GetSystemTimeAsFileTime((LPFILETIME)&ft);
  SetRegInt64(HKLM,TIMESKEY,UserName,ft);
}

//////////////////////////////////////////////////////////////////////////////
// 
// WhiteList handling
// 
//////////////////////////////////////////////////////////////////////////////

BOOL IsInWhiteList(LPTSTR User,LPTSTR CmdLine,DWORD Flag)
{
  return (GetRegInt(HKLM,WHTLSTKEY(User),CmdLine,0)&Flag)==Flag;
}

BOOL RemoveFromWhiteList(LPTSTR User,LPTSTR CmdLine,DWORD Flag)
{
  DWORD dwwl=GetRegInt(HKLM,WHTLSTKEY(User),CmdLine,0)&(~Flag);
  if(dwwl)
    return SetRegInt(HKLM,WHTLSTKEY(User),CmdLine,dwwl);
  return RegDelVal(HKLM,WHTLSTKEY(User),CmdLine);
}

void SaveToWhiteList(LPTSTR User,LPTSTR CmdLine,DWORD Flag)
{
  SetRegInt(HKLM,WHTLSTKEY(User),CmdLine,
    GetRegInt(HKLM,WHTLSTKEY(User),CmdLine,0)|Flag);
}

//////////////////////////////////////////////////////////////////////////////
// 
//  Service setup
// 
//////////////////////////////////////////////////////////////////////////////

void LBSetScrollbar(HWND hwnd)
{
  HDC hdc=GetDC(hwnd);
  TCHAR s[4096];
  int nItems=(int)SendMessage(hwnd,LB_GETCOUNT,0,0);
  int wMax=0;
  for (int i=0;i<nItems;i++)
  {
    SIZE sz={0};
    GetTextExtentPoint32(hdc,s,(int)SendMessage(hwnd,LB_GETTEXT,i,(LPARAM)&s),&sz);
    wMax=max(sz.cx,wMax);
  }
  SendMessage(hwnd,LB_SETHORIZONTALEXTENT,wMax,0);
  ReleaseDC(hwnd,hdc);
}

void UpdateAskUser(HWND hwnd)
{
  if(!IsDlgButtonChecked(hwnd,IDC_SAVEPW))
  {
    CheckDlgButton(hwnd,IDC_RADIO1,1);
    CheckDlgButton(hwnd,IDC_RADIO2,0);
    EnableWindow(GetDlgItem(hwnd,IDC_RADIO1),false);
    EnableWindow(GetDlgItem(hwnd,IDC_RADIO2),false);
    EnableWindow(GetDlgItem(hwnd,IDC_ASKTIMEOUT),false);
  }else
  {
    CheckDlgButton(hwnd,IDC_RADIO1,0);
    CheckDlgButton(hwnd,IDC_RADIO2,1);
    EnableWindow(GetDlgItem(hwnd,IDC_RADIO1),false);
    EnableWindow(GetDlgItem(hwnd,IDC_RADIO2),false);
    EnableWindow(GetDlgItem(hwnd,IDC_ASKTIMEOUT),true);
  }
}

INT_PTR CALLBACK SetupDlgProc(HWND hwnd,UINT msg,WPARAM wParam,LPARAM lParam)
{
//  DBGTrace4("SetupDlgProc(%x,%x,%x,%x)",hwnd,msg,wParam,lParam);
  switch(msg)
  {
  case WM_INITDIALOG:
    {
      SendMessage(hwnd,WM_SETICON,ICON_BIG,
        (LPARAM)LoadImage(GetModuleHandle(0),MAKEINTRESOURCE(IDI_SETUP),
        IMAGE_ICON,32,32,0));
      SendMessage(hwnd,WM_SETICON,ICON_SMALL,
        (LPARAM)LoadImage(GetModuleHandle(0),MAKEINTRESOURCE(IDI_SETUP),
        IMAGE_ICON,16,16,0));
      {
        TCHAR WndText[MAX_PATH]={0},newText[MAX_PATH]={0};
        GetWindowText(hwnd,WndText,MAX_PATH);
        _stprintf(newText,WndText,GetVersionString());
        SetWindowText(hwnd,newText);
      }
      CheckDlgButton(hwnd,IDC_RADIO1,GetSavePW==0);
      CheckDlgButton(hwnd,IDC_RADIO2,GetSavePW!=0);
      SendDlgItemMessage(hwnd,IDC_ASKTIMEOUT,EM_LIMITTEXT,2,0);
      SetDlgItemInt(hwnd,IDC_ASKTIMEOUT,GetPwTimeOut,0);
      CheckDlgButton(hwnd,IDC_BLURDESKTOP,GetBlurDesk);
      CheckDlgButton(hwnd,IDC_SAVEPW,GetSavePW);
      CheckDlgButton(hwnd,IDC_ALLOWTIME,CanSetTime(SURUNNERSGROUP));
      CheckDlgButton(hwnd,IDC_OWNERGROUP,IsOwnerAdminGrp);
      CheckDlgButton(hwnd,IDC_WINUPD4ALL,IsWinUpd4All);
      CheckDlgButton(hwnd,IDC_WINUPDBOOT,IsWinUpdBoot);
      CheckDlgButton(hwnd,IDC_SETENERGY,CanSetEnergy);
      CBigResStr wlkey(_T("%s\\%s"),SVCKEY,g_RunData.UserName);
      TCHAR cmd[4096];
      for (int i=0;RegEnumValName(HKLM,wlkey,i,cmd,4096);i++)
        SendDlgItemMessage(hwnd,IDC_WHITELIST,LB_ADDSTRING,0,(LPARAM)&cmd);
      EnableWindow(GetDlgItem(hwnd,IDC_DELETE),
        SendDlgItemMessage(hwnd,IDC_WHITELIST,LB_GETCURSEL,0,0)!=-1);
      LBSetScrollbar(GetDlgItem(hwnd,IDC_WHITELIST));
      UpdateAskUser(hwnd);
      return TRUE;
    }//WM_INITDIALOG
  case WM_NCDESTROY:
    {
      DestroyIcon((HICON)SendMessage(hwnd,WM_GETICON,ICON_BIG,0));
      DestroyIcon((HICON)SendMessage(hwnd,WM_GETICON,ICON_SMALL,0));
      return TRUE;
    }//WM_NCDESTROY
  case WM_CTLCOLORSTATIC:
    {
      int CtlId=GetDlgCtrlID((HWND)lParam);
      if ((CtlId!=IDC_WHTBK))
      {
        SetBkMode((HDC)wParam,TRANSPARENT);
        return (BOOL)PtrToUlong(GetStockObject(WHITE_BRUSH));
      }
      break;
    }
  case WM_COMMAND:
    {
      switch (wParam)
      {
      case MAKELPARAM(IDC_SAVEPW,BN_CLICKED):
        UpdateAskUser(hwnd);
        return TRUE;
      case MAKELPARAM(IDCANCEL,BN_CLICKED):
        EndDialog(hwnd,0);
        return TRUE;
      case MAKELPARAM(IDOK,BN_CLICKED):
        {
          SetPwTimeOut(GetDlgItemInt(hwnd,IDC_ASKTIMEOUT,0,1));
          SetBlurDesk(IsDlgButtonChecked(hwnd,IDC_BLURDESKTOP));
          SetSavePW(IsDlgButtonChecked(hwnd,IDC_SAVEPW));
          if ((CanSetTime(SURUNNERSGROUP)!=0)!=((int)IsDlgButtonChecked(hwnd,IDC_ALLOWTIME)))
            AllowSetTime(SURUNNERSGROUP,IsDlgButtonChecked(hwnd,IDC_ALLOWTIME));
          SetOwnerAdminGrp(IsDlgButtonChecked(hwnd,IDC_OWNERGROUP));
          SetWinUpd4All(IsDlgButtonChecked(hwnd,IDC_WINUPD4ALL));
          SetWinUpdBoot(IsDlgButtonChecked(hwnd,IDC_WINUPDBOOT));
          if (CanSetEnergy!=(int)IsDlgButtonChecked(hwnd,IDC_SETENERGY))
            SetEnergy(IsDlgButtonChecked(hwnd,IDC_SETENERGY)==1);
          EndDialog(hwnd,1);
          return TRUE;
        }
      case MAKELPARAM(IDC_DELETE,BN_CLICKED):
        {
          int CurSel=(int)SendDlgItemMessage(hwnd,IDC_WHITELIST,LB_GETCURSEL,0,0);
          if (CurSel>=0)
          {
            TCHAR cmd[4096];
            SendDlgItemMessage(hwnd,IDC_WHITELIST,LB_GETTEXT,CurSel,(LPARAM)&cmd);
            RemoveFromWhiteList(g_RunData.UserName,cmd,FLAG_DONTASK);
            SendDlgItemMessage(hwnd,IDC_WHITELIST,LB_DELETESTRING,CurSel,0);
          }
          EnableWindow(GetDlgItem(hwnd,IDC_DELETE),
            SendDlgItemMessage(hwnd,IDC_WHITELIST,LB_GETCURSEL,0,0)!=-1);
          LBSetScrollbar(GetDlgItem(hwnd,IDC_WHITELIST));
          return TRUE;
        }
      case MAKELPARAM(IDC_WHITELIST,LBN_SELCHANGE):
        {
          EnableWindow(GetDlgItem(hwnd,IDC_DELETE),
            SendDlgItemMessage(hwnd,IDC_WHITELIST,LB_GETCURSEL,0,0)!=-1);
          return TRUE;
        }
      }//switch (wParam)
      break;
    }//WM_COMMAND
  }
  return FALSE;
}

BOOL RunSetup()
{
  return DialogBox(GetModuleHandle(0),MAKEINTRESOURCE(IDD_SETUP),0,SetupDlgProc)>=0;  
}

#ifdef _DEBUGSETUP

#define nTabs 2
typedef struct _SETUPDATA 
{
  USERLIST Users;
  int CurUser;
  HICON UserIcon;
  HWND hTabCtrl[nTabs];
  int DlgExitCode;
  HIMAGELIST ImgList;
  int ImgIconIdx[6];
  _SETUPDATA():Users(GetAllowAll?_T("*"):SURUNNERSGROUP)
  {
    DlgExitCode=IDCANCEL;
    zero(hTabCtrl);
    CurUser=-1;
    UserIcon=(HICON)LoadImage(GetModuleHandle(0),MAKEINTRESOURCE(IDI_MAINICON),
        IMAGE_ICON,48,48,0);
    ImgList=ImageList_Create(16,16,ILC_MASK,6,1);
    for (int i=0;i<6;i++)
    {
      HICON icon=(HICON)LoadImage(GetModuleHandle(0),
        MAKEINTRESOURCE(IDI_LISTICON+i),IMAGE_ICON,16,16,0);
      ImgIconIdx[i]=ImageList_AddIcon(ImgList,icon);
      DestroyIcon(icon);
    }
  }
  ~_SETUPDATA()
  {
    DestroyIcon(UserIcon);
    ImageList_Destroy(ImgList);
  }
}SETUPDATA;

//There can be only one Setup per Application. It's data is stored in g_SD
static SETUPDATA *g_SD=NULL;

//User Bitmaps:
static void UpdateUser(HWND hwnd)
{
  int n=(int)SendDlgItemMessage(hwnd,IDC_USER,CB_GETCURSEL,0,0);
  HBITMAP bm=0;
  HWND hWL=GetDlgItem(hwnd,IDC_WHITELIST);
  if (g_SD->CurUser==n)
    return;
  //Save Settings:
  if (g_SD->CurUser>=0)
  {
    SetNoRunSetup(g_SD->Users.GetUserName(g_SD->CurUser),
      IsDlgButtonChecked(hwnd,IDC_RUNSETUP)==0);
    SetRestrictApps(g_SD->Users.GetUserName(g_SD->CurUser),
      IsDlgButtonChecked(hwnd,IDC_RESTRICTED)!=0);
  }
  g_SD->CurUser=n;
  if (n!=CB_ERR)
  {
    bm=g_SD->Users.GetUserBitmap(n);
    EnableWindow(GetDlgItem(hwnd,IDC_RESTRICTED),true);
    CheckDlgButton(hwnd,IDC_RUNSETUP,!GetNoRunSetup(g_SD->Users.GetUserName(n)));
    EnableWindow(GetDlgItem(hwnd,IDC_RUNSETUP),true);
    CheckDlgButton(hwnd,IDC_RESTRICTED,GetRestrictApps(g_SD->Users.GetUserName(n)));
    EnableWindow(hWL,true);
    ListBox_ResetContent(hWL);
    CBigResStr wlkey(_T("%s\\%s"),SVCKEY,g_SD->Users.GetUserName(n));
    TCHAR cmd[4096];
    for (int i=0;RegEnumValName(HKLM,wlkey,i,cmd,4096);i++)
    {
      ListView_InsertItem()

      int Flags=GetRegInt(HKLM,wlkey,cmd,0);
      SendMessage(hWL,LB_ADDSTRING,0,(LPARAM)&cmd);
    }
    EnableWindow(GetDlgItem(hwnd,IDC_DELETE),SendMessage(hWL,LB_GETCURSEL,0,0)!=-1);
  }else
  {
    EnableWindow(GetDlgItem(hwnd,IDC_RESTRICTED),false);
    EnableWindow(GetDlgItem(hwnd,IDC_RUNSETUP),false);
    ListBox_ResetContent(hWL);
    EnableWindow(hWL,false);
  }
  LBSetScrollbar(hWL);
  HWND BmpIcon=GetDlgItem(hwnd,IDC_USERBITMAP);
  DWORD dwStyle=GetWindowLong(BmpIcon,GWL_STYLE)&(~SS_TYPEMASK);
  if(bm)
  {
    SetWindowLong(BmpIcon,GWL_STYLE,dwStyle|SS_BITMAP|SS_REALSIZEIMAGE|SS_CENTERIMAGE);
    SendMessage(BmpIcon,STM_SETIMAGE,IMAGE_BITMAP,(LPARAM)bm);
  }else
  {
    SetWindowLong(BmpIcon,GWL_STYLE,dwStyle|SS_ICON|SS_REALSIZEIMAGE|SS_CENTERIMAGE);
    SendMessage(BmpIcon,STM_SETIMAGE,IMAGE_ICON,(LPARAM)g_SD->UserIcon);
  }
}

INT_PTR CALLBACK SetupDlg1Proc(HWND hwnd,UINT msg,WPARAM wParam,LPARAM lParam)
{
  switch(msg)
  {
  case WM_INITDIALOG:
    {
      SendDlgItemMessage(hwnd,IDC_ASKTIMEOUT,EM_LIMITTEXT,2,0);
      SetDlgItemInt(hwnd,IDC_ASKTIMEOUT,GetPwTimeOut,0);
      CheckDlgButton(hwnd,IDC_BLURDESKTOP,GetBlurDesk);
      CheckDlgButton(hwnd,IDC_SAVEPW,GetSavePW);
      EnableWindow(GetDlgItem(hwnd,IDC_ASKTIMEOUT),GetSavePW);
      CheckDlgButton(hwnd,IDC_ALLOWALL,GetAllowAll);

      CheckDlgButton(hwnd,IDC_CTRLASADMIN,GetCtrlAsAdmin);
      CheckDlgButton(hwnd,IDC_CMDASADMIN,GetCmdAsAdmin);
      CheckDlgButton(hwnd,IDC_EXPASADMIN,GetExpAsAdmin);
      
      CheckDlgButton(hwnd,IDC_RESTARTADMIN,GetRestartAsAdmin);
      CheckDlgButton(hwnd,IDC_STARTADMIN,GetStartAsAdmin);
      
      CheckDlgButton(hwnd,IDC_ALLOWTIME,CanSetTime(SURUNNERSGROUP));
      CheckDlgButton(hwnd,IDC_OWNERGROUP,IsOwnerAdminGrp);
      CheckDlgButton(hwnd,IDC_WINUPD4ALL,IsWinUpd4All);
      CheckDlgButton(hwnd,IDC_WINUPDBOOT,IsWinUpdBoot);
      CheckDlgButton(hwnd,IDC_SETENERGY,CanSetEnergy);
      return TRUE;
    }//WM_INITDIALOG
  case WM_CTLCOLORDLG:
  case WM_CTLCOLORSTATIC:
    return (BOOL)PtrToUlong(GetStockObject(WHITE_BRUSH));
  case WM_COMMAND:
    {
      switch (wParam)
      {
      case MAKELPARAM(IDC_SAVEPW,BN_CLICKED):
        EnableWindow(GetDlgItem(hwnd,IDC_ASKTIMEOUT),IsDlgButtonChecked(hwnd,IDC_SAVEPW));
        return TRUE;
      }//switch (wParam)
      break;
    }//WM_COMMAND
  case WM_DESTROY:
    if (g_SD->DlgExitCode==IDOK) //User pressed OK, save settings
    {
      SetBlurDesk(IsDlgButtonChecked(hwnd,IDC_BLURDESKTOP));
      SetSavePW(IsDlgButtonChecked(hwnd,IDC_SAVEPW));
      SetPwTimeOut(GetDlgItemInt(hwnd,IDC_ASKTIMEOUT,0,1));
      SetAllowAll(IsDlgButtonChecked(hwnd,IDC_ALLOWALL));
      
      SetCtrlAsAdmin(IsDlgButtonChecked(hwnd,IDC_CTRLASADMIN));
      SetCmdAsAdmin(IsDlgButtonChecked(hwnd,IDC_CMDASADMIN));
      SetExpAsAdmin(IsDlgButtonChecked(hwnd,IDC_EXPASADMIN));
      
      SetRestartAsAdmin(IsDlgButtonChecked(hwnd,IDC_RESTARTADMIN));
      SetStartAsAdmin(IsDlgButtonChecked(hwnd,IDC_STARTADMIN));

      if ((CanSetTime(SURUNNERSGROUP)!=0)!=((int)IsDlgButtonChecked(hwnd,IDC_ALLOWTIME)))
        AllowSetTime(SURUNNERSGROUP,IsDlgButtonChecked(hwnd,IDC_ALLOWTIME));
      if (CanSetEnergy!=(int)IsDlgButtonChecked(hwnd,IDC_SETENERGY))
        SetEnergy(IsDlgButtonChecked(hwnd,IDC_SETENERGY)!=0);
      SetWinUpd4All(IsDlgButtonChecked(hwnd,IDC_WINUPD4ALL));
      SetWinUpdBoot(IsDlgButtonChecked(hwnd,IDC_WINUPDBOOT));
      SetOwnerAdminGrp(IsDlgButtonChecked(hwnd,IDC_OWNERGROUP));
      return TRUE;
    }//WM_DESTROY
  }
  return FALSE;
}

INT_PTR CALLBACK SetupDlg2Proc(HWND hwnd,UINT msg,WPARAM wParam,LPARAM lParam)
{
  switch(msg)
  {
  case WM_INITDIALOG:
    {
      //Program list icons:
      HWND hWL=GetDlgItem(hwnd,IDC_WHITELIST);
      SendMessage(hWL,LVM_SETEXTENDEDLISTVIEWSTYLE,0,LVS_EX_FULLROWSELECT|LVS_EX_SUBITEMIMAGES);
      ListView_SetImageList 
      //UserList
      BOOL bFoundUser=FALSE;
      for (int i=0;i<g_SD->Users.GetCount();i++)
      {
        SendDlgItemMessage(hwnd,IDC_USER,CB_INSERTSTRING,i,
          (LPARAM)g_SD->Users.GetUserName(i));
        if (_tcsicmp(g_SD->Users.GetUserName(i),g_RunData.UserName)==0)
        {
          SendDlgItemMessage(hwnd,IDC_USER,CB_SETCURSEL,i,0);
          bFoundUser=TRUE;
          g_SD->CurUser=i;
        }
      }
      if (!bFoundUser)
      {
        SetDlgItemText(hwnd,IDC_USER,g_SD->Users.GetUserName(0));
        SendDlgItemMessage(hwnd,IDC_USER,CB_SETCURSEL,0,0);
      }
      UpdateUser(hwnd);
      return TRUE;
    }//WM_INITDIALOG
  case WM_CTLCOLORDLG:
  case WM_CTLCOLORSTATIC:
    return (BOOL)PtrToUlong(GetStockObject(WHITE_BRUSH));
  case WM_TIMER:
    {
      if (wParam==1)
        UpdateUser(hwnd);
      return TRUE;
    }//WM_TIMER
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
        UpdateUser(hwnd);
        return TRUE;
      case MAKELPARAM(IDC_DELETE,BN_CLICKED):
        {
          int CurSel=(int)SendDlgItemMessage(hwnd,IDC_WHITELIST,LB_GETCURSEL,0,0);
          if (CurSel>=0)
          {
            TCHAR cmd[4096];
            SendDlgItemMessage(hwnd,IDC_WHITELIST,LB_GETTEXT,CurSel,(LPARAM)&cmd);
            RemoveFromWhiteList(g_RunData.UserName,cmd,FLAG_DONTASK);
            SendDlgItemMessage(hwnd,IDC_WHITELIST,LB_DELETESTRING,CurSel,0);
          }
          EnableWindow(GetDlgItem(hwnd,IDC_DELETE),
            SendDlgItemMessage(hwnd,IDC_WHITELIST,LB_GETCURSEL,0,0)!=-1);
          LBSetScrollbar(GetDlgItem(hwnd,IDC_WHITELIST));
          return TRUE;
        }
      case MAKELPARAM(IDC_WHITELIST,LBN_SELCHANGE):
        {
          EnableWindow(GetDlgItem(hwnd,IDC_DELETE),
            SendDlgItemMessage(hwnd,IDC_WHITELIST,LB_GETCURSEL,0,0)!=-1);
          return TRUE;
        }
      }//switch (wParam)
      break;
    }//WM_COMMAND
  case WM_DESTROY:
    if (/*(g_SD->DlgExitCode==IDOK) && */(g_SD->CurUser>=0))
    {
      SetNoRunSetup(g_SD->Users.GetUserName(g_SD->CurUser),
        IsDlgButtonChecked(hwnd,IDC_RUNSETUP)==0);
      SetRestrictApps(g_SD->Users.GetUserName(g_SD->CurUser),
        IsDlgButtonChecked(hwnd,IDC_RESTRICTED)!=0);
      return TRUE;
    }//WM_DESTROY
  }
  return FALSE;
}

INT_PTR CALLBACK MainSetupDlgProc(HWND hwnd,UINT msg,WPARAM wParam,LPARAM lParam)
{
  switch(msg)
  {
  case WM_INITDIALOG:
    {
      SendMessage(hwnd,WM_SETICON,ICON_BIG,
        (LPARAM)LoadImage(GetModuleHandle(0),MAKEINTRESOURCE(IDI_SETUP),
        IMAGE_ICON,32,32,0));
      SendMessage(hwnd,WM_SETICON,ICON_SMALL,
        (LPARAM)LoadImage(GetModuleHandle(0),MAKEINTRESOURCE(IDI_SETUP),
        IMAGE_ICON,16,16,0));
      {
        TCHAR WndText[MAX_PATH]={0},newText[MAX_PATH]={0};
        GetWindowText(hwnd,WndText,MAX_PATH);
        _stprintf(newText,WndText,GetVersionString());
        SetWindowText(hwnd,newText);
      }
      //Tab Control
      HWND hTab=GetDlgItem(hwnd,IDC_SETUP_TAB);
      int TabNames[nTabs]= {IDS_SETUP1, IDS_SETUP2};
      int TabIDs[nTabs]= { IDD_SETUP1,IDD_SETUP2};
      DLGPROC TabProcs[nTabs]= { SetupDlg1Proc,SetupDlg2Proc};
      for (int i=0;i<nTabs;i++)
      {
        TCITEM tie={TCIF_TEXT,0,0,CResStr(TabNames[i]),0,0,0};
		    TabCtrl_InsertItem(hTab,i,&tie);
		    g_SD->hTabCtrl[i]=CreateDialog(GetModuleHandle(0),
                          MAKEINTRESOURCE(TabIDs[i]),hwnd,TabProcs[i]);
        RECT r;
        GetWindowRect(hTab,&r);
        TabCtrl_AdjustRect(hTab,FALSE,&r);
        ScreenToClient(hwnd,(POINT*)&r.left);
        ScreenToClient(hwnd,(POINT*)&r.right);
	      SetWindowPos(g_SD->hTabCtrl[i],hTab,r.left,r.top,r.right-r.left,r.bottom-r.top,0);
      }
      ShowWindow(g_SD->hTabCtrl[0],TRUE);
      //...
      SetFocus(hTab);
      return FALSE;
    }//WM_INITDIALOG
  case WM_NCDESTROY:
    {
      for (int i=0;i<nTabs;i++)
        DestroyWindow(g_SD->hTabCtrl[i]);
      DestroyIcon((HICON)SendMessage(hwnd,WM_GETICON,ICON_BIG,0));
      DestroyIcon((HICON)SendMessage(hwnd,WM_GETICON,ICON_SMALL,0));
      return TRUE;
    }//WM_NCDESTROY
  case WM_NOTIFY:
    {
      if (wParam==IDC_SETUP_TAB)
      {
        int nSel=TabCtrl_GetCurSel(GetDlgItem(hwnd,IDC_SETUP_TAB));
        switch (((LPNMHDR)lParam)->code)
        {
          case TCN_SELCHANGING:
            ShowWindow(g_SD->hTabCtrl[nSel],FALSE);
            return TRUE;
		      case TCN_SELCHANGE:
            ShowWindow(g_SD->hTabCtrl[nSel],TRUE);
            return TRUE;
        }
      }
      break;
    }//WM_NOTIFY
  case WM_COMMAND:
    {
      switch (wParam)
      {
      case MAKELPARAM(IDCANCEL,BN_CLICKED):
        EndDialog(hwnd,0);
        return TRUE;
      case MAKELPARAM(IDOK,BN_CLICKED):
        {
          g_SD->DlgExitCode=IDOK;
          SetNoRunSetup(g_SD->Users.GetUserName(g_SD->CurUser),
            IsDlgButtonChecked(hwnd,IDC_RUNSETUP)==0);
          SetRestrictApps(g_SD->Users.GetUserName(g_SD->CurUser),
            IsDlgButtonChecked(hwnd,IDC_RESTRICTED)!=0);
          EndDialog(hwnd,1);
          return TRUE;
        }
      }//switch (wParam)
      break;
    }//WM_COMMAND
  }
  return FALSE;
}

BOOL RunMainSetup()
{
  SETUPDATA sd;
  g_SD=&sd;
  BOOL bRet=DialogBoxParam(GetModuleHandle(0),MAKEINTRESOURCE(IDD_SETUP_MAIN),
                           0,MainSetupDlgProc,(LPARAM)&sd)>=0;  
  g_SD=0;
  return bRet;
}

BOOL TestSetup()
{
  INITCOMMONCONTROLSEX icce={sizeof(icce),ICC_USEREX_CLASSES|ICC_WIN95_CLASSES};
  InitCommonControlsEx(&icce);

  RunMainSetup();
  
//  SetThreadLocale(MAKELCID(MAKELANGID(LANG_GERMAN,SUBLANG_GERMAN),SORT_DEFAULT));
//  if (!RunSetup())
//    DBGTrace1("DialogBox failed: %s",GetLastErrorNameStatic());
//
//  SetThreadLocale(MAKELCID(MAKELANGID(LANG_ENGLISH,SUBLANG_ENGLISH_US),SORT_DEFAULT));
//  if (!RunSetup())
//    DBGTrace1("DialogBox failed: %s",GetLastErrorNameStatic());
//  
//  SetThreadLocale(MAKELCID(MAKELANGID(LANG_POLISH,0),SORT_DEFAULT));
//  if (!RunSetup())
//    DBGTrace1("DialogBox failed: %s",GetLastErrorNameStatic());
  
  ::ExitProcess(0);
  return TRUE;
}

BOOL x=TestSetup();
#endif _DEBUGSETUP

