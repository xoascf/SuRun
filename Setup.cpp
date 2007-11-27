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
  __int64 AskTime=GetRegInt64(HKLM,TIMESKEY,UserName,0);
  if ((AskTime==0) 
    || ((ft-GetPwTimeOut)<(ft2min*(__int64)AskTime)))
    return FALSE;
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
  if(IsDlgButtonChecked(hwnd,IDC_SAVEPW)!=BST_CHECKED)
  {
    CheckDlgButton(hwnd,IDC_RADIO1,(BST_CHECKED));
    CheckDlgButton(hwnd,IDC_RADIO2,(BST_UNCHECKED));
    EnableWindow(GetDlgItem(hwnd,IDC_RADIO1),false);
    EnableWindow(GetDlgItem(hwnd,IDC_RADIO2),false);
    EnableWindow(GetDlgItem(hwnd,IDC_ASKTIMEOUT),false);
  }else
  {
    CheckDlgButton(hwnd,IDC_RADIO1,(BST_UNCHECKED));
    CheckDlgButton(hwnd,IDC_RADIO2,(BST_CHECKED));
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
      CheckDlgButton(hwnd,IDC_RADIO1,((GetSavePW==0)?BST_CHECKED:BST_UNCHECKED));
      CheckDlgButton(hwnd,IDC_RADIO2,((GetSavePW!=0)?BST_CHECKED:BST_UNCHECKED));
      SendDlgItemMessage(hwnd,IDC_ASKTIMEOUT,EM_LIMITTEXT,2,0);
      SetDlgItemInt(hwnd,IDC_ASKTIMEOUT,GetPwTimeOut,0);
      CheckDlgButton(hwnd,IDC_BLURDESKTOP,(GetBlurDesk?BST_CHECKED:BST_UNCHECKED));
      CheckDlgButton(hwnd,IDC_SAVEPW,(GetSavePW?BST_CHECKED:BST_UNCHECKED));
      CheckDlgButton(hwnd,IDC_ALLOWTIME,CanSetTime(SURUNNERSGROUP)?BST_CHECKED:BST_UNCHECKED);
      CheckDlgButton(hwnd,IDC_OWNERGROUP,IsOwnerAdminGrp?BST_CHECKED:BST_UNCHECKED);
      CheckDlgButton(hwnd,IDC_WINUPD4ALL,IsWinUpd4All?BST_CHECKED:BST_UNCHECKED);
      CheckDlgButton(hwnd,IDC_WINUPDBOOT,IsWinUpdBoot?BST_CHECKED:BST_UNCHECKED);
      CheckDlgButton(hwnd,IDC_SETENERGY,CanSetEnergy?BST_CHECKED:BST_UNCHECKED);
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
          SetBlurDesk(IsDlgButtonChecked(hwnd,IDC_BLURDESKTOP)==BST_CHECKED);
          SetSavePW(IsDlgButtonChecked(hwnd,IDC_SAVEPW)==BST_CHECKED);
          if ((CanSetTime(SURUNNERSGROUP)!=0)!=(IsDlgButtonChecked(hwnd,IDC_ALLOWTIME)==BST_CHECKED))
            AllowSetTime(SURUNNERSGROUP,IsDlgButtonChecked(hwnd,IDC_ALLOWTIME)==BST_CHECKED);
          SetOwnerAdminGrp((IsDlgButtonChecked(hwnd,IDC_OWNERGROUP)==BST_CHECKED)?1:0);
          SetWinUpd4All((IsDlgButtonChecked(hwnd,IDC_WINUPD4ALL)==BST_CHECKED)?1:0);
          SetWinUpdBoot((IsDlgButtonChecked(hwnd,IDC_WINUPDBOOT)==BST_CHECKED)?1:0);
          if (CanSetEnergy!=(IsDlgButtonChecked(hwnd,IDC_SETENERGY)==BST_CHECKED))
            SetEnergy(IsDlgButtonChecked(hwnd,IDC_SETENERGY)==BST_CHECKED);
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

typedef struct _SETUPDATA 
{
  USERLIST Users;
  HICON UserIcon;
  _SETUPDATA ():Users(SURUNNERSGROUP)
  {
    UserIcon=(HICON)LoadImage(GetModuleHandle(0),MAKEINTRESOURCE(IDI_MAINICON),
        IMAGE_ICON,48,48,0);
  }
}SETUPDATA;

//There can be only one Setup per Application. It's data is stored in g_SD
static SETUPDATA *g_SD=NULL;

INT_PTR CALLBACK SetupDlg1Proc(HWND hwnd,UINT msg,WPARAM wParam,LPARAM lParam)
{
//  DBGTrace4("SetupDlgProc(%x,%x,%x,%x)",hwnd,msg,wParam,lParam);
  switch(msg)
  {
  case WM_INITDIALOG:
    {
      SendDlgItemMessage(hwnd,IDC_ASKTIMEOUT,EM_LIMITTEXT,2,0);
      SetDlgItemInt(hwnd,IDC_ASKTIMEOUT,GetPwTimeOut,0);
      CheckDlgButton(hwnd,IDC_BLURDESKTOP,(GetBlurDesk?BST_CHECKED:BST_UNCHECKED));
      CheckDlgButton(hwnd,IDC_SAVEPW,(GetSavePW?BST_CHECKED:BST_UNCHECKED));
      EnableWindow(GetDlgItem(hwnd,IDC_ASKTIMEOUT),GetSavePW);
      CheckDlgButton(hwnd,IDC_ALLOWTIME,CanSetTime(SURUNNERSGROUP)?BST_CHECKED:BST_UNCHECKED);
      CheckDlgButton(hwnd,IDC_OWNERGROUP,IsOwnerAdminGrp?BST_CHECKED:BST_UNCHECKED);
      CheckDlgButton(hwnd,IDC_WINUPD4ALL,IsWinUpd4All?BST_CHECKED:BST_UNCHECKED);
      CheckDlgButton(hwnd,IDC_WINUPDBOOT,IsWinUpdBoot?BST_CHECKED:BST_UNCHECKED);
      CheckDlgButton(hwnd,IDC_SETENERGY,CanSetEnergy?BST_CHECKED:BST_UNCHECKED);
      return TRUE;
    }//WM_INITDIALOG
  case WM_COMMAND:
    {
      switch (wParam)
      {
      case MAKELPARAM(IDC_SAVEPW,BN_CLICKED):
        EnableWindow(GetDlgItem(hwnd,IDC_ASKTIMEOUT),IsDlgButtonChecked(hwnd,IDC_SAVEPW)==BST_CHECKED);
        return TRUE;
      }//switch (wParam)
      break;
    }//WM_COMMAND
  }
  return FALSE;
}

//User Bitmaps:
static void SetUserBitmap(HWND hwnd)
{
  int n=(int)SendDlgItemMessage(hwnd,IDC_USER,CB_GETCURSEL,0,0);
  HBITMAP bm=0;
  if (n!=CB_ERR)
    bm=g_SD->Users.GetUserBitmap(n);
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
      //UserList
      BOOL bFoundUser=FALSE;
      for (int i=0;i<g_SD->Users.nUsers;i++)
      {
        SendDlgItemMessage(hwnd,IDC_USER,CB_INSERTSTRING,i,
          (LPARAM)&g_SD->Users.User[i].UserName);
        if (_tcsicmp(g_SD->Users.User[i].UserName,g_RunData.UserName)==0)
        {
          SendDlgItemMessage(hwnd,IDC_USER,CB_SETCURSEL,i,0);
          bFoundUser=TRUE;
        }
      }
      if (!bFoundUser)
      {
        SetDlgItemText(hwnd,IDC_USER,g_SD->Users.User[0].UserName);
        SendDlgItemMessage(hwnd,IDC_USER,CB_SETCURSEL,0,0);
      }
      SetUserBitmap(hwnd);
      //...
      return TRUE;
    }//WM_INITDIALOG
  case WM_NCDESTROY:
    {
      DestroyIcon((HICON)SendMessage(hwnd,WM_GETICON,ICON_BIG,0));
      DestroyIcon((HICON)SendMessage(hwnd,WM_GETICON,ICON_SMALL,0));
      return TRUE;
    }//WM_NCDESTROY
  case WM_TIMER:
    {
      if (wParam==1)
        SetUserBitmap(hwnd);
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
        SetUserBitmap(hwnd);
        return TRUE;
      case MAKELPARAM(IDCANCEL,BN_CLICKED):
        EndDialog(hwnd,0);
        return TRUE;
      case MAKELPARAM(IDOK,BN_CLICKED):
        {
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
  return DialogBox(GetModuleHandle(0),MAKEINTRESOURCE(IDD_SETUP),0,SetupDlgProc)>=0;  
}

#ifdef _DEBUGSETUP
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
  
  SetThreadLocale(MAKELCID(MAKELANGID(LANG_GERMAN,SUBLANG_GERMAN),SORT_DEFAULT));
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

