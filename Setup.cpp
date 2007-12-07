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
  if (GetRegAny(HKLM,PASSWKEY,UserName,REG_BINARY,(BYTE*)Password,&nBytes))
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

BOOL SetWhiteListFlag(LPTSTR User,LPTSTR CmdLine,DWORD Flag,bool Enable)
{
  DWORD d0=GetRegInt(HKLM,WHTLSTKEY(User),CmdLine,0);
  DWORD d1=(d0 &(~Flag))|(Enable?Flag:0);
  //only save reg key, when flag is different!
  return (d1==d0)||SetRegInt(HKLM,WHTLSTKEY(User),CmdLine,d1);
}

BOOL ToggleWhiteListFlag(LPTSTR User,LPTSTR CmdLine,DWORD Flag)
{
  DWORD d=GetRegInt(HKLM,WHTLSTKEY(User),CmdLine,0);
  if(d&Flag)
    d&=~Flag;
  else
    d|=Flag;
  return SetRegInt(HKLM,WHTLSTKEY(User),CmdLine,d);
}

BOOL RemoveFromWhiteList(LPTSTR User,LPTSTR CmdLine)
{
  return RegDelVal(HKLM,WHTLSTKEY(User),CmdLine);
}

//////////////////////////////////////////////////////////////////////////////
// 
//  Setup Dialog Data
// 
//////////////////////////////////////////////////////////////////////////////
#define nTabs 2
typedef struct _SETUPDATA 
{
  USERLIST Users;
  int CurUser;
  HICON UserIcon;
  HWND hTabCtrl[nTabs];
  HWND HelpWnd;
  int DlgExitCode;
  HIMAGELIST ImgList;
  int ImgIconIdx[6];
  _SETUPDATA()
  {
    Users.SetGroupUsers(SURUNNERSGROUP);
    DlgExitCode=IDCANCEL;
    HelpWnd=0;
    zero(hTabCtrl);
    CurUser=-1;
    UserIcon=(HICON)LoadImage(GetModuleHandle(0),MAKEINTRESOURCE(IDI_MAINICON),
        IMAGE_ICON,48,48,0);
    ImgList=ImageList_Create(16,16,ILC_COLOR32,6,1);
    for (int i=0;i<6;i++)
    {
      HICON icon=(HICON)LoadImage(GetModuleHandle(0),
        MAKEINTRESOURCE(IDI_LISTICON+i),IMAGE_ICON,0,0,0);
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

//////////////////////////////////////////////////////////////////////////////
// 
//  Help Dialog: White background, Cancel Button.
// 
//////////////////////////////////////////////////////////////////////////////

INT_PTR CALLBACK HelpDlgProc(HWND hwnd,UINT msg,WPARAM wParam,LPARAM lParam)
{
  switch(msg)
  {
  case WM_CTLCOLORSTATIC:
    SetBkMode((HDC)wParam,TRANSPARENT);
  case WM_CTLCOLORDLG:
    return (BOOL)PtrToUlong(GetStockObject(WHITE_BRUSH));
  case WM_COMMAND:
    if (wParam==MAKELPARAM(IDCANCEL,BN_CLICKED))
    {
      g_SD->HelpWnd=0;
      EnableWindow(GetDlgItem(g_SD->hTabCtrl[1],IDC_ICONHELP),1);
      EndDialog(hwnd,0);
      return TRUE;
    }
  }
  return FALSE;
}

//////////////////////////////////////////////////////////////////////////////
// 
//  Service setup
// 
//////////////////////////////////////////////////////////////////////////////

//////////////////////////////////////////////////////////////////////////////
// 
// Save Flags for the selected User
// 
//////////////////////////////////////////////////////////////////////////////
static void SaveUserFlags()
{
  if (g_SD->CurUser>=0)
  {
    SetNoRunSetup(g_SD->Users.GetUserName(g_SD->CurUser),
      IsDlgButtonChecked(g_SD->hTabCtrl[1],IDC_RUNSETUP)==0);
    SetRestrictApps(g_SD->Users.GetUserName(g_SD->CurUser),
      IsDlgButtonChecked(g_SD->hTabCtrl[1],IDC_RESTRICTED)!=0);
  }
}

//////////////////////////////////////////////////////////////////////////////
// 
// Program List handling
// 
//////////////////////////////////////////////////////////////////////////////
static int CALLBACK ListSortProc(LPARAM lParam1, LPARAM lParam2, LPARAM lParamSort)
{
  TCHAR s1[4096];
  TCHAR s2[4096];
  ListView_GetItemText((HWND)lParamSort,lParam1,3,s1,4095);
  ListView_GetItemText((HWND)lParamSort,lParam2,3,s2,4095);
  return _tcscmp(s1,s2);
}

static void UpdateWhiteListFlags(HWND hWL)
{
  CBigResStr wlkey(_T("%s\\%s"),SVCKEY,g_SD->Users.GetUserName(g_SD->CurUser));
  TCHAR cmd[4096];
  for (int i=0;i<ListView_GetItemCount(hWL);i++)
  {
    ListView_GetItemText(hWL,i,3,cmd,4095);
    int Flags=GetRegInt(HKLM,wlkey,cmd,0);
    LVITEM item={LVIF_IMAGE,i,0,0,0,0,0,g_SD->ImgIconIdx[2+(Flags&FLAG_DONTASK?1:0)],0,0};
    ListView_SetItem(hWL,&item);
    item.iSubItem=1;
    item.iImage=g_SD->ImgIconIdx[(Flags&FLAG_SHELLEXEC?0:1)];
    ListView_SetItem(hWL,&item);
    item.iSubItem=2;
    item.iImage=g_SD->ImgIconIdx[4+(Flags&FLAG_NORESTRICT?0:1)];
    ListView_SetItem(hWL,&item);
  }
  ListView_SetColumnWidth(hWL,3,LVSCW_AUTOSIZE_USEHEADER);
}

//////////////////////////////////////////////////////////////////////////////
// 
// Populate the Program list for the selected User, show the User Icon
// 
//////////////////////////////////////////////////////////////////////////////
static void UpdateUser(HWND hwnd)
{
  int n=(int)SendDlgItemMessage(hwnd,IDC_USER,CB_GETCURSEL,0,0);
  HBITMAP bm=0;
  HWND hWL=GetDlgItem(hwnd,IDC_WHITELIST);
  if (g_SD->CurUser==n)
    return;
  //Save Settings:
  SaveUserFlags();
  g_SD->CurUser=n;
  ListView_DeleteAllItems(hWL);
  if (n!=CB_ERR)
  {
    bm=g_SD->Users.GetUserBitmap(n);
    EnableWindow(GetDlgItem(hwnd,IDC_RESTRICTED),true);
    CheckDlgButton(hwnd,IDC_RUNSETUP,!GetNoRunSetup(g_SD->Users.GetUserName(n)));
    EnableWindow(GetDlgItem(hwnd,IDC_RUNSETUP),true);
    CheckDlgButton(hwnd,IDC_RESTRICTED,GetRestrictApps(g_SD->Users.GetUserName(n)));
    EnableWindow(hWL,true);
    CBigResStr wlkey(_T("%s\\%s"),SVCKEY,g_SD->Users.GetUserName(n));
    TCHAR cmd[4096];
    for (int i=0;RegEnumValName(HKLM,wlkey,i,cmd,4096);i++)
    {
      int Flags=GetRegInt(HKLM,wlkey,cmd,0);
      LVITEM item={LVIF_IMAGE,i,0,0,0,0,0,g_SD->ImgIconIdx[0],0,0};
      ListView_SetItemText(hWL,ListView_InsertItem(hWL,&item),3,cmd);
    }
    ListView_SortItemsEx(hWL,ListSortProc,hWL);
    UpdateWhiteListFlags(hWL);
    EnableWindow(GetDlgItem(hwnd,IDC_DELETE),ListView_GetSelectionMark(hWL)!=-1);
  }else
  {
    EnableWindow(GetDlgItem(hwnd,IDC_RESTRICTED),false);
    EnableWindow(GetDlgItem(hwnd,IDC_RUNSETUP),false);
    EnableWindow(hWL,false);
    EnableWindow(GetDlgItem(hwnd,IDC_DELETE),false);
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
    SendMessage(BmpIcon,STM_SETIMAGE,IMAGE_ICON,(LPARAM)g_SD->UserIcon);
  }
}

//////////////////////////////////////////////////////////////////////////////
// 
// Populate User Combobox and the Program list for the selected User
// 
//////////////////////////////////////////////////////////////////////////////
static void UpdateUserList(HWND hwnd)
{
  SendDlgItemMessage(hwnd,IDC_USER,CB_RESETCONTENT,0,0);
  SendDlgItemMessage(hwnd,IDC_USER,CB_SETCURSEL,-1,0);
  g_SD->CurUser=0;
  for (int i=0;i<g_SD->Users.GetCount();i++)
  {
    LPTSTR u=g_SD->Users.GetUserName(i);
    SendDlgItemMessage(hwnd,IDC_USER,CB_INSERTSTRING,i,(LPARAM)u);
    if (_tcsicmp(u,g_RunData.UserName)==0)
      g_SD->CurUser=i;
  }
  SendDlgItemMessage(hwnd,IDC_USER,CB_SETCURSEL,g_SD->CurUser,0);
  g_SD->CurUser=-1;
  UpdateUser(hwnd);
}

//////////////////////////////////////////////////////////////////////////////
// 
// Dialog Proc for first Tab-Control
// 
//////////////////////////////////////////////////////////////////////////////
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

//////////////////////////////////////////////////////////////////////////////
// 
// Dialog Proc for second Tab-Control
// 
//////////////////////////////////////////////////////////////////////////////
INT_PTR CALLBACK SetupDlg2Proc(HWND hwnd,UINT msg,WPARAM wParam,LPARAM lParam)
{
  switch(msg)
  {
  case WM_INITDIALOG:
    {
      //Program list icons:
      HWND hWL=GetDlgItem(hwnd,IDC_WHITELIST);
      SendMessage(hWL,LVM_SETEXTENDEDLISTVIEWSTYLE,0,
        LVS_EX_INFOTIP|LVS_EX_FULLROWSELECT|LVS_EX_SUBITEMIMAGES);
      ListView_SetImageList(hWL,g_SD->ImgList,LVSIL_SMALL);
      for (int i=0;i<4;i++)
      {
        LVCOLUMN col={LVCF_WIDTH,0,(i==0)?26:22,0,0,0,0,0};
        ListView_InsertColumn(hWL,i,&col);
      }
      //UserList
      UpdateUserList(hwnd);
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
      //User Combobox
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
      //Help Button
      case MAKELPARAM(IDC_ICONHELP,BN_CLICKED):
        if (g_SD->HelpWnd==0)
          g_SD->HelpWnd=CreateDialog(GetModuleHandle(0),MAKEINTRESOURCE(IDD_ICONHELP),hwnd,HelpDlgProc);
        if (g_SD->HelpWnd)
        {
          ShowWindow(g_SD->HelpWnd,SW_SHOW);
          EnableWindow(GetDlgItem(hwnd,IDC_ICONHELP),0);
        }
        return TRUE;
      //Delete Button
      case MAKELPARAM(IDC_DELETE,BN_CLICKED):
        {
          HWND hWL=GetDlgItem(hwnd,IDC_WHITELIST);
          int CurSel=(int)ListView_GetSelectionMark(hWL);
          if (CurSel>=0)
          {
            TCHAR cmd[4096];
            ListView_GetItemText(hWL,CurSel,3,cmd,4095);
            if(RemoveFromWhiteList(g_SD->Users.GetUserName(g_SD->CurUser),cmd))
            {
              ListView_DeleteItem(hWL,CurSel);
              CurSel=ListView_GetSelectionMark(hWL);
              if (CurSel>=0)
                ListView_SetItemState(hWL,CurSel,LVIS_SELECTED,0x0F);
            }else
              MessageBeep(MB_ICONERROR);
          }
          EnableWindow(GetDlgItem(hwnd,IDC_DELETE),
            ListView_GetSelectionMark(hWL)!=-1);
          return TRUE;
        }
      }//switch (wParam)
      break;
    }//WM_COMMAND
  case WM_NOTIFY:
    {
      switch (wParam)
      {
      //Program List Notofications
      case IDC_WHITELIST:
        if (lParam) switch(((LPNMHDR)lParam)->code)
        {
        //Selection changed
        case LVN_ITEMCHANGED:
          EnableWindow(GetDlgItem(hwnd,IDC_DELETE),
            ListView_GetSelectionMark(GetDlgItem(hwnd,IDC_WHITELIST))!=-1);
          return TRUE;
        //Mouse Click: Toggle Flags
        case NM_CLICK:
        case NM_DBLCLK:
          {
            LPNMITEMACTIVATE p=(LPNMITEMACTIVATE)lParam;
            int Flag=0;
            switch(p->iSubItem)
            {
            case 0:Flag=FLAG_DONTASK;     break;
            case 1:Flag=FLAG_SHELLEXEC;   break;
            case 2:Flag=FLAG_NORESTRICT;  break;
            }
            if (Flag)
            {
              TCHAR cmd[4096];
              HWND hWL=GetDlgItem(hwnd,IDC_WHITELIST);
              ListView_GetItemText(hWL,p->iItem,3,cmd,4095);
              if(ToggleWhiteListFlag(g_SD->Users.GetUserName(g_SD->CurUser),cmd,Flag))
                UpdateWhiteListFlags(hWL);
              else
                MessageBeep(MB_ICONERROR);
            }
          }
          return TRUE;
        }//switch (switch(((LPNMHDR)lParam)->code)
      }//switch (wParam)
      break;
    }//WM_NOTIFY
  case WM_DESTROY:
    if (g_SD->HelpWnd)
      DestroyWindow(g_SD->HelpWnd);
    g_SD->HelpWnd=0;
    //if (g_SD->DlgExitCode==IDOK)
    {
      SaveUserFlags();
      return TRUE;
    }//WM_DESTROY
  }
  return FALSE;
}

//////////////////////////////////////////////////////////////////////////////
// 
// Main Setup Dialog Proc
// 
//////////////////////////////////////////////////////////////////////////////
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

BOOL RunSetup()
{
  SETUPDATA sd;
  g_SD=&sd;
  BOOL bRet=DialogBoxParam(GetModuleHandle(0),MAKEINTRESOURCE(IDD_SETUP_MAIN),
                           0,MainSetupDlgProc,(LPARAM)&sd)>=0;  
  g_SD=0;
  return bRet;
}

#ifdef _DEBUGSETUP
BOOL TestSetup()
{
  INITCOMMONCONTROLSEX icce={sizeof(icce),ICC_USEREX_CLASSES|ICC_WIN95_CLASSES};
  InitCommonControlsEx(&icce);

  SetThreadLocale(MAKELCID(MAKELANGID(LANG_GERMAN,SUBLANG_GERMAN),SORT_DEFAULT));
  if (!RunSetup())
    DBGTrace1("DialogBox failed: %s",GetLastErrorNameStatic());

  SetThreadLocale(MAKELCID(MAKELANGID(LANG_ENGLISH,SUBLANG_ENGLISH_US),SORT_DEFAULT));
  if (!RunSetup())
    DBGTrace1("DialogBox failed: %s",GetLastErrorNameStatic());
  
  SetThreadLocale(MAKELCID(MAKELANGID(LANG_POLISH,0),SORT_DEFAULT));
  if (!RunSetup())
    DBGTrace1("DialogBox failed: %s",GetLastErrorNameStatic());
  
  ::ExitProcess(0);
  return TRUE;
}

BOOL x=TestSetup();
#endif _DEBUGSETUP

