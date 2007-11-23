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
//  Globals
// 
//////////////////////////////////////////////////////////////////////////////

bool g_BlurDesktop=TRUE; //blurred user desktop background on secure Desktop
BYTE g_NoAskTimeOut=0;   //Minutes to wait until "Is that OK?" is asked again
bool g_bSavePW=TRUE;     //Save Passwords in Registry

#define Radio1chk (g_bSavePW==0)
#define Radio2chk (g_bSavePW!=0)

#define PWKEY     SVCKEY _T("\\Cache")
#define TMKEY     SVCKEY _T("\\Times")
#define WLKEY(u)  CBigResStr(_T("%s\\%s"),SVCKEY,u)

BYTE KEYPASS[16]={0x5B,0xC3,0x25,0xE9,0x8F,0x2A,0x41,0x10,0xA3,0xF4,0x26,0xD1,0x62,0xB4,0x0A,0xE2};

//////////////////////////////////////////////////////////////////////////////
// 
//  LoadSettings
// 
//////////////////////////////////////////////////////////////////////////////
void LoadSettings()
{
  g_BlurDesktop=GetRegInt(HKLM,SVCKEY,_T("BlurDesktop"),1)!=0;
  g_NoAskTimeOut=(BYTE)min(60,max(0,(int)GetRegInt(HKLM,SVCKEY,_T("AskTimeOut"),0)));
  g_bSavePW=GetRegInt(HKLM,SVCKEY,_T("SavePasswords"),1)!=0;
}

//////////////////////////////////////////////////////////////////////////////
// 
//  SaveSettings
// 
//////////////////////////////////////////////////////////////////////////////
void SaveSettings()
{
  SetRegInt(HKLM,SVCKEY,_T("BlurDesktop"),g_BlurDesktop);
  SetRegInt(HKLM,SVCKEY,_T("AskTimeOut"),g_NoAskTimeOut);
  SetRegInt(HKLM,SVCKEY,_T("SavePasswords"),g_bSavePW);
  if (!g_bSavePW)
  {
    DelRegKey(HKLM,PWKEY);
    DelRegKey(HKLM,TMKEY);
  }
}

//////////////////////////////////////////////////////////////////////////////
// 
//  Password cache
// 
//////////////////////////////////////////////////////////////////////////////
void LoadPassword(LPTSTR UserName,LPTSTR Password,DWORD nBytes)
{
  if (!g_bSavePW)
    return;
  CBlowFish bf;
  bf.Initialize(KEYPASS,sizeof(KEYPASS));
  if(GetRegAny(HKLM,PWKEY,UserName,REG_BINARY,(BYTE*)Password,&nBytes))
    bf.Decode((BYTE*)Password,(BYTE*)Password,nBytes);
}

void DeletePassword(LPTSTR UserName)
{
  RegDelVal(HKLM,PWKEY,UserName);
  RegDelVal(HKLM,TMKEY,UserName);
}

void SavePassword(LPTSTR UserName,LPTSTR Password)
{
  if (!g_bSavePW)
    return;
  CBlowFish bf;
  TCHAR pw[PWLEN];
  bf.Initialize(KEYPASS,sizeof(KEYPASS));
  SetRegAny(HKLM,PWKEY,UserName,REG_BINARY,(BYTE*)pw,
    bf.Encode((BYTE*)Password,(BYTE*)pw,(int)_tcslen(Password)*sizeof(TCHAR)));
}

//////////////////////////////////////////////////////////////////////////////
// 
//  Password TimeOut
// 
//////////////////////////////////////////////////////////////////////////////

__int64 GetLastRunTime(LPTSTR UserName)
{
  return GetRegInt64(HKLM,TMKEY,UserName,0);
}

void UpdLastRunTime(LPTSTR UserName)
{
  __int64 ft;
  GetSystemTimeAsFileTime((LPFILETIME)&ft);
  SetRegInt64(HKLM,TMKEY,UserName,ft);
}

//////////////////////////////////////////////////////////////////////////////
// 
// WhiteList handling
// 
//////////////////////////////////////////////////////////////////////////////
#define FLAG_DONTASK   1
#define FLAG_SHELLEXEC 2

BOOL IsInWhiteList(LPTSTR User,LPTSTR CmdLine,DWORD Flag)
{
  return (GetRegInt(HKLM,WLKEY(User),CmdLine,0)&Flag)==Flag;
}

BOOL RemoveFromWhiteList(LPTSTR User,LPTSTR CmdLine,DWORD Flag)
{
  DWORD dwwl=GetRegInt(HKLM,WLKEY(User),CmdLine,0)&(~Flag);
  if(dwwl)
    return SetRegInt(HKLM,WLKEY(User),CmdLine,dwwl);
  return RegDelVal(HKLM,WLKEY(User),CmdLine);
}

void SaveToWhiteList(LPTSTR User,LPTSTR CmdLine,DWORD Flag)
{
  SetRegInt(HKLM,WLKEY(User),CmdLine,GetRegInt(HKLM,WLKEY(User),CmdLine,0)|Flag);
}

//////////////////////////////////////////////////////////////////////////////
// 
//  Service setup
// 
//////////////////////////////////////////////////////////////////////////////
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

#define IsOwnerAdminGrp     (GetRegInt(HKLM,\
                              _T("SYSTEM\\CurrentControlSet\\Control\\Lsa"),\
                              _T("nodefaultadminowner"),1)==0)

#define SetOwnerAdminGrp(b) SetRegInt(HKLM,\
                              _T("SYSTEM\\CurrentControlSet\\Control\\Lsa"),\
                              _T("nodefaultadminowner"),(b)==0)

#define IsWinUpd4All      GetRegInt(HKLM,\
                            _T("SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate"),\
                            _T("ElevateNonAdmins"),0)

#define SetWinUpd4All(b)  SetRegInt(HKLM,\
                            _T("SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate"),\
                            _T("ElevateNonAdmins"),b)

#define IsWinUpdBoot      GetRegInt(HKLM,\
                            _T("SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU"),\
                            _T("NoAutoRebootWithLoggedOnUsers"),0)

#define SetWinUpdBoot(b)  SetRegInt(HKLM,\
                            _T("SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU"),\
                            _T("NoAutoRebootWithLoggedOnUsers"),b)

#define CanSetEnergy  HasRegistryKeyAccess(_T("MACHINE\\Software\\Microsoft\\")\
                    _T("Windows\\CurrentVersion\\Controls Folder\\PowerCfg"),SURUNNERSGROUP)

#define SetEnergy(b)  SetRegistryTreeAccess(_T("MACHINE\\Software\\Microsoft\\")\
                    _T("Windows\\CurrentVersion\\Controls Folder\\PowerCfg"),SURUNNERSGROUP,b)

INT_PTR CALLBACK SetupDlgProc(HWND hwnd,UINT msg,WPARAM wParam,LPARAM lParam)
{
//  DBGTrace4("SetupDlgProc(%x,%x,%x,%x)",hwnd,msg,wParam,lParam);
  switch(msg)
  {
  case WM_INITDIALOG:
    {
      SendMessage(hwnd,WM_SETICON,ICON_BIG,
        (LPARAM)LoadImage(GetModuleHandle(0),MAKEINTRESOURCE(IDI_SETUP),
        IMAGE_ICON,0,0,0));
      SendMessage(hwnd,WM_SETICON,ICON_SMALL,
        (LPARAM)LoadImage(GetModuleHandle(0),MAKEINTRESOURCE(IDI_SETUP),
        IMAGE_ICON,16,16,0));
      LoadSettings();
      {
        TCHAR WndText[MAX_PATH]={0},newText[MAX_PATH]={0};
        GetWindowText(hwnd,WndText,MAX_PATH);
        _stprintf(newText,WndText,GetVersionString());
        SetWindowText(hwnd,newText);
      }
      CheckDlgButton(hwnd,IDC_RADIO1,(Radio1chk?BST_CHECKED:BST_UNCHECKED));
      CheckDlgButton(hwnd,IDC_RADIO2,(Radio2chk?BST_CHECKED:BST_UNCHECKED));
      SendDlgItemMessage(hwnd,IDC_ASKTIMEOUT,EM_LIMITTEXT,2,0);
      SetDlgItemInt(hwnd,IDC_ASKTIMEOUT,g_NoAskTimeOut,0);
      CheckDlgButton(hwnd,IDC_BLURDESKTOP,(g_BlurDesktop?BST_CHECKED:BST_UNCHECKED));
      CheckDlgButton(hwnd,IDC_SAVEPW,(g_bSavePW?BST_CHECKED:BST_UNCHECKED));
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
          g_NoAskTimeOut=max(0,min(60,GetDlgItemInt(hwnd,IDC_ASKTIMEOUT,0,1)));
          g_BlurDesktop=IsDlgButtonChecked(hwnd,IDC_BLURDESKTOP)==BST_CHECKED;
          g_bSavePW=IsDlgButtonChecked(hwnd,IDC_SAVEPW)==BST_CHECKED;
          SaveSettings();
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

BOOL RunSetup()
{
  return DialogBox(GetModuleHandle(0),MAKEINTRESOURCE(IDD_SETUP),0,SetupDlgProc)>=0;  
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

