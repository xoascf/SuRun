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
#include <shlwapi.h>
#include "Setup.h"
#include "Helpers.h"
#include "BlowFish.h"
#include "ResStr.h"
#include "UserGroups.h"
#include "lsa_laar.h"
#include "DBGTrace.h"
#include "WinStaDesk.h"
#include "Resource.h"
#include "Anchor.h"

#pragma comment(lib,"comctl32.lib")
#pragma comment(lib,"Comdlg32.lib")
#pragma comment(lib,"shlwapi.lib")

//////////////////////////////////////////////////////////////////////////////
// 
//  Password cache
// 
//////////////////////////////////////////////////////////////////////////////

void DeletePassword(LPTSTR UserName)
{
  RegDelVal(HKLM,PASSWKEY,UserName);//for Historical reasons!
  RegDelVal(HKLM,TIMESKEY,UserName);
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

//Common for GetWhiteListFlags and GetBlackListFlags
DWORD GetRegListFlags(HKEY HKR,LPCTSTR SubKey,LPCTSTR CmdLine,DWORD Default)
{
  HKEY Key;
  if(RegOpenKeyEx(HKR,SubKey,0,KSAM(KEY_READ),&Key)!=ERROR_SUCCESS)
    return Default;
  DWORD sizd=sizeof(DWORD);
  DWORD d=Default;
  DWORD t=REG_DWORD;
  if ((RegQueryValueEx(Key,CmdLine,0,&t,(BYTE*)&d,&sizd)==ERROR_SUCCESS)
    &&(t==REG_DWORD))
    return RegCloseKey(Key),d;
  TCHAR cmd[4096];
  DWORD ccMax=countof(cmd);
  sizd=sizeof(DWORD);
  for (int i=0;(RegEnumValue(Key,i,cmd,&ccMax,0,&t,(BYTE*)&d,&sizd)==ERROR_SUCCESS);i++)
  {
    if((t==REG_DWORD) && strwldcmp(CmdLine,cmd))
      return RegCloseKey(Key),d;
    ccMax=countof(cmd);
    sizd=sizeof(DWORD);
  }
  RegCloseKey(Key);
  return Default;
}

DWORD GetWhiteListFlags(LPCTSTR User,LPCTSTR CmdLine,DWORD Default)
{
  return GetRegListFlags(HKLM,WHTLSTKEY(User),CmdLine,Default);
}

BOOL IsInWhiteList(LPCTSTR User,LPCTSTR CmdLine,DWORD Flag)
{
  return (GetWhiteListFlags(User,CmdLine,0)&Flag)==Flag;
}

BOOL AddToWhiteList(LPCTSTR User,LPCTSTR CmdLine,DWORD Flags/*=0*/)
{
  CBigResStr key(_T("%s\\%s"),SVCKEY,User);
  DWORD d=GetRegInt(HKLM,key,CmdLine,-1);
  return (d==Flags)||SetRegInt(HKLM,key,CmdLine,Flags);
}

BOOL SetWhiteListFlag(LPCTSTR User,LPCTSTR CmdLine,DWORD Flag,bool Enable)
{
  DWORD d0=GetWhiteListFlags(User,CmdLine,0);
  DWORD d1=(d0 &(~Flag))|(Enable?Flag:0);
  //only save reg key, when flag is different!
  return (d1==d0)||SetRegInt(HKLM,WHTLSTKEY(User),CmdLine,d1);
}

BOOL ToggleWhiteListFlag(LPCTSTR User,LPCTSTR CmdLine,DWORD Flag)
{
  DWORD d=GetWhiteListFlags(User,CmdLine,0);
  if(d&Flag)
  {
    d&=~Flag;
    if (Flag==FLAG_DONTASK)
      d|=FLAG_AUTOCANCEL;
    if (Flag==FLAG_SHELLEXEC)
      d|=FLAG_CANCEL_SX;
  }
  else
  {
    if ((Flag==FLAG_DONTASK)&&(d&FLAG_AUTOCANCEL))
      d&=~FLAG_AUTOCANCEL;
    else if ((Flag==FLAG_SHELLEXEC)&&(d&FLAG_CANCEL_SX))
      d&=~FLAG_CANCEL_SX;
    else
      d|=Flag;
  }
  return SetRegInt(HKLM,WHTLSTKEY(User),CmdLine,d);
}

BOOL RemoveFromWhiteList(LPCTSTR User,LPCTSTR CmdLine)
{
  return RegDelVal(HKLM,WHTLSTKEY(User),CmdLine);
}

//////////////////////////////////////////////////////////////////////////////
// 
//  BlackList for IATHook
// 
//////////////////////////////////////////////////////////////////////////////
DWORD GetBlackListFlags(LPCTSTR CmdLine,DWORD Default)
{
  return GetRegListFlags(HKLM,HKLSTKEY,CmdLine,Default);
}

BOOL IsInBlackList(LPCTSTR CmdLine)
{
  return GetBlackListFlags(CmdLine,-1)!=-1;
}

BOOL AddToBlackList(LPCTSTR CmdLine)
{
  return SetRegInt(HKLM,HKLSTKEY,CmdLine,1);
}

BOOL RemoveFromBlackList(LPCTSTR CmdLine)
{
  return RegDelVal(HKLM,HKLSTKEY,CmdLine);
}

//////////////////////////////////////////////////////////////////////////////
// 
//  Registry replace stuff
// 
//////////////////////////////////////////////////////////////////////////////
void ReplaceRunAsWithSuRun(HKEY hKey/*=HKCR*/)
{
  TCHAR s[512];
  DWORD i,nS;
  for(i=0,nS=512;0==RegEnumKey(hKey,i,s,nS);nS=512,i++)
  {
    if (_tcsicmp(s,L"CLSID")==0)
    {
      HKEY h;
      if(ERROR_SUCCESS==RegOpenKeyEx(hKey,s,0,KSAM(KEY_ALL_ACCESS),&h))
        ReplaceRunAsWithSuRun(h);
    }
    else
    {
      TCHAR v[4096];
      DWORD n=4096;
      DWORD t=0;
      BOOL bOk=GetRegAny(hKey,CResStr(L"%s\\%s",s,L"shell\\runas\\command"),L"",&t,(BYTE*)&v,&n);
      if (bOk 
        && ((t==REG_SZ)||(t==REG_EXPAND_SZ))
        && RenameRegKey(hKey,CResStr(L"%s\\%s",s,L"shell\\runas"),CResStr(L"%s\\%s",s,L"shell\\RunAsSuRun")))
      {
        //Preserve original command:
        SetRegAny(hKey,CResStr(L"%s\\%s",s,L"shell\\RunAsSuRun"),L"SuRunWasHere",t,(BYTE*)&v,n);
        //Set command
        TCHAR cmd[4096];
        GetSystemWindowsDirectory(cmd,4096);
        PathAppend(cmd,L"SuRun.exe");
        PathQuoteSpaces(cmd);
        _tcscat(cmd,L" /RUNAS ");
        _tcscat(cmd,v);
        SetRegAny(hKey,CResStr(L"%s\\%s",s,L"shell\\RunAsSuRun\\command"),L"",t,
          (BYTE*)&cmd,(DWORD)_tcslen(cmd)*sizeof(TCHAR));
        //Preserve original command name:
        n=4096;
        zero(v);
        GetRegAny(hKey,CResStr(L"%s\\%s",s,L"shell\\runas"),L"",&t,(BYTE*)&v,&n);
        SetRegAny(hKey,CResStr(L"%s\\%s",s,L"shell\\RunAsSuRun"),L"orgname",t,(BYTE*)&v,n);
        //Set SuRun command name
        SetRegStr(hKey,CResStr(L"%s\\%s",s,L"shell\\RunAsSuRun"),L"",CResStr(IDS_RUNAS));
      }
    }
  }
}

void ReplaceSuRunWithRunAs(HKEY hKey/*=HKCR*/)
{
  TCHAR s[512];
  DWORD i,nS;
  for(i=0,nS=512;0==RegEnumKey(hKey,i,s,nS);nS=512,i++)
  {
    if (_tcsicmp(s,L"CLSID")==0)
    {
      HKEY h;
      if(ERROR_SUCCESS==RegOpenKeyEx(hKey,s,0,KSAM(KEY_ALL_ACCESS),&h))
        ReplaceSuRunWithRunAs(h);
    }
    else
    {
      TCHAR v[4096];
      DWORD n=4096;
      DWORD t=0;
      BOOL bOk=GetRegAny(hKey,CResStr(L"%s\\%s",s,L"shell\\RunAsSuRun"),
                         L"SuRunWasHere",&t,(BYTE*)&v,&n);
      if ( bOk
        && ((t==REG_SZ)||(t==REG_EXPAND_SZ))
        && RegDelVal(hKey,CResStr(L"%s\\%s",s,L"shell\\RunAsSuRun"),L"SuRunWasHere")
        && RenameRegKey(hKey,CResStr(L"%s\\%s",s,L"shell\\RunAsSuRun"),CResStr(L"%s\\%s",s,L"shell\\runas")))
      {
        //Restore original command
        SetRegAny(hKey,CResStr(L"%s\\%s",s,L"shell\\runas\\command"),L"",t,
          (BYTE*)&v,(DWORD)_tcslen(v)*sizeof(TCHAR));
        //Restore  original command name:
        n=4096;
        zero(v);
        if(GetRegAny(hKey,CResStr(L"%s\\%s",s,L"shell\\runas"),L"orgname",&t,(BYTE*)&v,&n))
        {
          if (v[0])
            SetRegAny(hKey,CResStr(L"%s\\%s",s,L"shell\\runas"),L"",t,(BYTE*)&v,n);
          else
            RegDelVal(hKey,CResStr(L"%s\\%s",s,L"shell\\runas"),0);
          RegDelVal(hKey,CResStr(L"%s\\%s",s,L"shell\\runas"),L"orgname");
        }
      }
    }
  }
}

//////////////////////////////////////////////////////////////////////////////
// 
//  IsWin2k
// 
//////////////////////////////////////////////////////////////////////////////

bool IsWin2k()
{
  OSVERSIONINFO oie;
  oie.dwOSVersionInfoSize=sizeof(oie);
  GetVersionEx(&oie);
  return (oie.dwMajorVersion==5)&&(oie.dwMinorVersion==0);
}

//////////////////////////////////////////////////////////////////////////////
// 
//  Setup Dialog Data
// 
//////////////////////////////////////////////////////////////////////////////
#define nTabs 4
typedef struct _SETUPDATA 
{
  USERLIST Users;
  LPCTSTR OrgUser;
  int CurUser;
  HICON UserIcon;
  HWND hTabCtrl[nTabs];
  HWND HelpWnd;
  int DlgExitCode;
  HIMAGELIST ImgList;
  int ImgIconIdx[8];
  TCHAR NewUser[2*UNLEN+2];
  CDlgAnchor MainSetupAnchor;
  CDlgAnchor Setup2Anchor;
  int MinW;
  int MinH;
  int CurTab;
  _SETUPDATA(LPCTSTR User)
  {
    MinW=600;
    MinH=400;
    OrgUser=User;
    CurTab=0;
    Users.SetSurunnersUsers(FALSE);
    CurUser=-1;
    int i;
    for (i=0;i<Users.GetCount();i++)
      if (_tcsicmp(Users.GetUserName(i),OrgUser)==0)
      {
        CurUser=i;
        break;
      }
    DlgExitCode=IDCANCEL;
    HelpWnd=0;
    zero(hTabCtrl);
    zero(NewUser);
    UserIcon=(HICON)LoadImage(GetModuleHandle(0),MAKEINTRESOURCE(IDI_MAINICON),
        IMAGE_ICON,48,48,0);
    ImgList=ImageList_Create(16,16,ILC_COLOR8,7,1);
    for (i=0;i<8;i++)
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
//  Select a User Dialog
// 
//////////////////////////////////////////////////////////////////////////////
static int CALLBACK UsrListSortProc(LPARAM lParam1, LPARAM lParam2, LPARAM lParamSort)
{
  TCHAR s1[MAX_PATH];
  TCHAR s2[MAX_PATH];
  ListView_GetItemText((HWND)lParamSort,lParam1,0,s1,MAX_PATH);
  ListView_GetItemText((HWND)lParamSort,lParam2,0,s2,MAX_PATH);
  return _tcsicmp(s1,s2);
}

static void SetSelectedNameText(HWND hwnd)
{
  HWND hUL=GetDlgItem(hwnd,IDC_USERLIST);
  int n=ListView_GetSelectionMark(hUL);
  if(n>=0)
  {
    TCHAR u[MAX_PATH]={0};
    ListView_GetItemText(hUL,n,0,u,MAX_PATH);
    if (u[0])
      SetDlgItemText(hwnd,IDC_USERNAME,u);
  }
}

static void AddUsers(HWND hwnd,BOOL bDomainUsers)
{
  HWND hUL=GetDlgItem(hwnd,IDC_USERLIST);
  USERLIST ul;
  ul.SetGroupUsers(L"*",bDomainUsers);
  ListView_DeleteAllItems(hUL);
  for (int i=0;i<ul.GetCount();i++) 
  {
    LVITEM item={LVIF_TEXT,i,0,0,0,ul.GetUserName(i),0,0,0,0};
    if (!IsInSuRunners(item.pszText))
      ListView_InsertItem(hUL,&item);
  }
  ListView_SortItemsEx(hUL,UsrListSortProc,hUL);
  ListView_SetColumnWidth(hUL,0,LVSCW_AUTOSIZE_USEHEADER);
  ListView_SetItemState(hUL,0,LVIS_FOCUSED|LVIS_SELECTED,LVIS_FOCUSED|LVIS_SELECTED);
  SetSelectedNameText(hwnd);
  SetFocus(GetDlgItem(hwnd,IDC_USERNAME));
  SendMessage(GetDlgItem(hwnd,IDC_USERNAME),EM_SETSEL,0,-1);
}

INT_PTR CALLBACK SelUserDlgProc(HWND hwnd,UINT msg,WPARAM wParam,LPARAM lParam)
{
  switch(msg)
  {
  case WM_INITDIALOG:
    {
      HWND hUL=GetDlgItem(hwnd,IDC_USERLIST);
      SendMessage(hUL,LVM_SETEXTENDEDLISTVIEWSTYLE,0,LVS_EX_INFOTIP);
      LVCOLUMN col={LVCF_WIDTH,0,22,0,0,0,0,0};
      ListView_InsertColumn(hUL,0,&col);
      AddUsers(hwnd,FALSE);
    }
    return FALSE;
  case WM_CTLCOLORSTATIC:
    SetBkMode((HDC)wParam,TRANSPARENT);
  case WM_CTLCOLORDLG:
    return (BOOL)PtrToUlong(GetStockObject(WHITE_BRUSH));
  case WM_NOTIFY:
    {
      switch (wParam)
      {
      //Program List Notifications
      case IDC_USERLIST:
        if (lParam) switch(((LPNMHDR)lParam)->code)
        {
        //Mouse Click
        case NM_CLICK:
        case NM_DBLCLK:
        //Selection changed
        case LVN_ITEMCHANGED:
          SetSelectedNameText(hwnd);
          return TRUE;
        }//switch (switch(((LPNMHDR)lParam)->code)
      }//switch (wParam)
      break;
    }//WM_NOTIFY
  case WM_COMMAND:
    {
      switch (wParam)
      {
      case MAKELPARAM(IDC_ALLUSERS,BN_CLICKED):
        AddUsers(hwnd,IsDlgButtonChecked(hwnd,IDC_ALLUSERS));
        return TRUE;
      case MAKELPARAM(IDCANCEL,BN_CLICKED):
        EndDialog(hwnd,0);
        return TRUE;
      case MAKELPARAM(IDOK,BN_CLICKED):
        GetDlgItemText(hwnd,IDC_USERNAME,g_SD->NewUser,countof(g_SD->NewUser));
        EndDialog(hwnd,1);
        return TRUE;
      }//switch (wParam)
      break;
    }//WM_COMMAND
  }
  return FALSE;
}

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
// Add/Edit file to users file list:
// 
//////////////////////////////////////////////////////////////////////////////
struct
{
  DWORD* Flags;
  LPTSTR FileName;
  int OfnTitle;
}g_AppOpt;

static BOOL ChooseFile(HWND hwnd,LPTSTR FileName)
{
  #define ExpAdvReg L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced"
  int HideExt=GetRegInt(HKCU,ExpAdvReg,L"HideFileExt",-1);
  SetRegInt(HKCU,ExpAdvReg,L"HideFileExt",0);
  OPENFILENAME  ofn={0};
  ofn.lStructSize       = sizeof(OPENFILENAME);
  ofn.hwndOwner         = hwnd;
  ofn.lpstrFilter       = TEXT("*.*\0*.*\0\0"); 
  ofn.nFilterIndex      = 1;
  ofn.lpstrFile         = FileName;
  ofn.nMaxFile          = 4096;
  ofn.lpstrTitle        = CResStr(g_AppOpt.OfnTitle);
  ofn.Flags             = OFN_ENABLESIZING|OFN_NOVALIDATE|OFN_FORCESHOWHIDDEN;
  ofn.FlagsEx           = OFN_EX_NOPLACESBAR;
  BOOL bRet=GetOpenFileName(&ofn);
  if (HideExt!=-1)
    SetRegInt(HKCU,ExpAdvReg,L"HideFileExt",HideExt);
  if (PathFileExists(FileName))
    PathQuoteSpaces(FileName);
  return bRet;
  #undef ExpAdvReg
}

INT_PTR CALLBACK AppOptDlgProc(HWND hwnd,UINT msg,WPARAM wParam,LPARAM lParam)
{
  switch(msg)
  {
  case WM_INITDIALOG:
    SetDlgItemText(hwnd,IDC_FILENAME,g_AppOpt.FileName);
    if (g_AppOpt.OfnTitle==IDS_ADDFILETOLIST)
    {
      CheckDlgButton(hwnd,IDC_NOASK1,(*g_AppOpt.Flags&(FLAG_DONTASK|FLAG_AUTOCANCEL))==0);
      CheckDlgButton(hwnd,IDC_NOASK2,(*g_AppOpt.Flags&FLAG_DONTASK)!=0);
      CheckDlgButton(hwnd,IDC_NOASK3,(*g_AppOpt.Flags&FLAG_AUTOCANCEL)!=0);
      
      CheckDlgButton(hwnd,IDC_AUTO1,(*g_AppOpt.Flags&(FLAG_SHELLEXEC|FLAG_CANCEL_SX))==0);
      CheckDlgButton(hwnd,IDC_AUTO2,(*g_AppOpt.Flags&FLAG_SHELLEXEC)!=0);
      CheckDlgButton(hwnd,IDC_AUTO3,(*g_AppOpt.Flags&FLAG_CANCEL_SX)!=0);
      
      if((!IsDlgButtonChecked(g_SD->hTabCtrl[2],IDC_SHEXHOOK))
        &&(!IsDlgButtonChecked(g_SD->hTabCtrl[2],IDC_IATHOOK)))
      {
        EnableWindow(GetDlgItem(hwnd,IDC_AUTO1),0);
        EnableWindow(GetDlgItem(hwnd,IDC_AUTO2),0);
        EnableWindow(GetDlgItem(hwnd,IDC_AUTO3),0);
      }
    }
    return TRUE;
  case WM_CTLCOLORSTATIC:
    SetBkMode((HDC)wParam,TRANSPARENT);
  case WM_CTLCOLORDLG:
    return (BOOL)PtrToUlong(GetStockObject(WHITE_BRUSH));
  case WM_COMMAND:
    switch (wParam)
    {
    case MAKELPARAM(IDC_SELFILE,BN_CLICKED):
      GetDlgItemText(hwnd,IDC_FILENAME,g_AppOpt.FileName,4096);
      ChooseFile(hwnd,g_AppOpt.FileName);
      SetDlgItemText(hwnd,IDC_FILENAME,g_AppOpt.FileName);
      break;
    case MAKELPARAM(IDCANCEL,BN_CLICKED):
      EndDialog(hwnd,IDCANCEL);
      return TRUE;
    case MAKELPARAM(IDOK,BN_CLICKED):
      GetDlgItemText(hwnd,IDC_FILENAME,g_AppOpt.FileName,4096);
      if (g_AppOpt.OfnTitle==IDS_ADDFILETOLIST)
      {
        //Test drive:
        STARTUPINFO si={0};
        si.cb	= sizeof(si);
        PROCESS_INFORMATION pi={0};
        if (CreateProcess(NULL,g_AppOpt.FileName,NULL,NULL,FALSE,
          CREATE_SUSPENDED|CREATE_UNICODE_ENVIRONMENT,0,NULL,&si,&pi))
        {
          TerminateProcess(pi.hProcess,0);
          CloseHandle(pi.hThread);
          CloseHandle(pi.hProcess);
        }else
          if (SafeMsgBox(hwnd,CBigResStr(IDS_APPOK),CResStr(IDS_APPNAME),
            MB_YESNO|MB_ICONQUESTION|MB_DEFBUTTON2)==IDNO)
            return TRUE;
        *g_AppOpt.Flags=0;
        if (IsDlgButtonChecked(hwnd,IDC_NOASK2))
          *g_AppOpt.Flags|=FLAG_DONTASK;
        if (IsDlgButtonChecked(hwnd,IDC_NOASK3))
          *g_AppOpt.Flags|=FLAG_AUTOCANCEL;
        if (IsDlgButtonChecked(hwnd,IDC_AUTO2))
          *g_AppOpt.Flags|=FLAG_SHELLEXEC;
        if (IsDlgButtonChecked(hwnd,IDC_AUTO3))
          *g_AppOpt.Flags|=FLAG_CANCEL_SX;
      }
      EndDialog(hwnd,IDOK);
      return TRUE;
    }
  }
  return FALSE;
}

static BOOL GetFileName(HWND hwnd,DWORD& Flags,LPTSTR FileName,
                        int DlgID=IDD_APPOPTIONS,int OfnTitle=IDS_ADDFILETOLIST)
{
  if ((DlgID==IDD_APPOPTIONS)&&(FileName[0]==0))
  {
    if(!ChooseFile(hwnd,FileName))
      return FALSE;
  }
  g_AppOpt.FileName=FileName;
  g_AppOpt.Flags=&Flags;
  g_AppOpt.OfnTitle=OfnTitle;
  return DialogBox(GetModuleHandle(0),MAKEINTRESOURCE(DlgID),hwnd,AppOptDlgProc)==IDOK;
}

//////////////////////////////////////////////////////////////////////////////
// 
// Add/Edit file to IAT-Hook Blacklist:
// 
//////////////////////////////////////////////////////////////////////////////
static void FillBlackList(HWND hwnd)
{
  HWND hBL=GetDlgItem(hwnd,IDC_BLACKLIST);
  ListView_DeleteAllItems(hBL);
  HKEY Key;
  if(RegOpenKeyEx(HKLM,HKLSTKEY,0,KSAM(KEY_READ),&Key)==ERROR_SUCCESS)
  {
    TCHAR cmd[4096];
    DWORD ccMax=countof(cmd);
    for (int i=0;(RegEnumValue(Key,i,cmd,&ccMax,0,0,0,0)==ERROR_SUCCESS);i++)
    {
      ccMax=countof(cmd);
      LVITEM item={LVIF_TEXT,i,0,0,0,cmd,0,0,0,0};
      ListView_InsertItem(hBL,&item);
    }
    RegCloseKey(Key);
  }
  ListView_SortItemsEx(hBL,UsrListSortProc,hBL);
  ListView_SetColumnWidth(hBL,0,LVSCW_AUTOSIZE_USEHEADER);
  ListView_SetItemState(hBL,0,LVIS_FOCUSED|LVIS_SELECTED,LVIS_FOCUSED|LVIS_SELECTED);
  EnableWindow(GetDlgItem(hwnd,IDC_DELETE),ListView_GetSelectionMark(hBL)!=-1);
  EnableWindow(GetDlgItem(hwnd,IDC_EDITAPP),ListView_GetSelectionMark(hBL)!=-1);
}

INT_PTR CALLBACK BlkLstDlgProc(HWND hwnd,UINT msg,WPARAM wParam,LPARAM lParam)
{
  switch(msg)
  {
  case WM_INITDIALOG:
    {
      HWND hBL=GetDlgItem(hwnd,IDC_BLACKLIST);
      SendMessage(hBL,LVM_SETEXTENDEDLISTVIEWSTYLE,0,LVS_EX_INFOTIP);
      LVCOLUMN col={LVCF_WIDTH,0,22,0,0,0,0,0};
      ListView_InsertColumn(hBL,0,&col);
      FillBlackList(hwnd);
    }
    return TRUE;
  case WM_CTLCOLORSTATIC:
    SetBkMode((HDC)wParam,TRANSPARENT);
  case WM_CTLCOLORDLG:
    return (BOOL)PtrToUlong(GetStockObject(WHITE_BRUSH));
  case WM_COMMAND:
    switch (wParam)
    {
    case MAKELPARAM(IDC_ADDAPP,BN_CLICKED):
      {
        TCHAR cmd[4096]={0};
        DWORD f=0;
        if (GetFileName(hwnd,f,cmd,IDD_ADDTOBLKLST,IDS_ADDTOBLKLIST) && cmd[0])
        {
          AddToBlackList(cmd);
          FillBlackList(hwnd);
        }
      }
      return TRUE;
    //Edit App Button
    case MAKELPARAM(IDC_EDITAPP,BN_CLICKED):
      {
EditApp:
        HWND hBL=GetDlgItem(hwnd,IDC_BLACKLIST);
        int CurSel=(int)ListView_GetSelectionMark(hBL);
        if (CurSel>=0)
        {
          TCHAR cmd[4096];
          TCHAR CMD[4096];
          ListView_GetItemText(hBL,CurSel,0,cmd,4096);
          _tcscpy(CMD,cmd);
          DWORD f=0;
          if ( GetFileName(hwnd,f,CMD,IDD_ADDTOBLKLST,IDS_ADDTOBLKLIST)
            && (CMD[0]) &&(_tcsicmp(CMD,cmd)!=0))
          {
            if((GetRegInt(HKLM,HKLSTKEY,CMD,-1)==-1) //No duplicates!
              && RemoveFromBlackList(cmd))
            {
              AddToBlackList(CMD);
              FillBlackList(hwnd);
            }else
              MessageBeep(MB_ICONERROR);
          }
        }
      }
      return TRUE;
    //Delete App Button
    case MAKELPARAM(IDC_DELETE,BN_CLICKED):
      {
        HWND hBL=GetDlgItem(hwnd,IDC_BLACKLIST);
        int CurSel=(int)ListView_GetSelectionMark(hBL);
        if (CurSel>=0)
        {
          TCHAR cmd[4096];
          ListView_GetItemText(hBL,CurSel,0,cmd,4096);
          if(RemoveFromBlackList(cmd))
          {
            ListView_DeleteItem(hBL,CurSel);
            CurSel=ListView_GetSelectionMark(hBL);
            if (CurSel>=0)
              ListView_SetItemState(hBL,CurSel,LVIS_SELECTED,0x0F);
          }else
            MessageBeep(MB_ICONERROR);
        }
        EnableWindow(GetDlgItem(hwnd,IDC_DELETE),ListView_GetSelectionMark(hBL)!=-1);
        EnableWindow(GetDlgItem(hwnd,IDC_EDITAPP),ListView_GetSelectionMark(hBL)!=-1);
      }
      return TRUE;
    case MAKELPARAM(IDCANCEL,BN_CLICKED):
    case MAKELPARAM(IDOK,BN_CLICKED):
      EndDialog(hwnd,IDCANCEL);
      return TRUE;
    }//WM_COMMAND
  case WM_NOTIFY:
    {
      switch (wParam)
      {
      //Program List Notifications
      case IDC_BLACKLIST:
        if (lParam) switch(((LPNMHDR)lParam)->code)
        {
        case LVN_KEYDOWN:
          if (((LPNMLVKEYDOWN)lParam)->wVKey==VK_F2)
            goto EditApp;
          break;
        //Mouse Click: Toggle Flags
        case NM_DBLCLK:
        case LVN_BEGINLABELEDIT:
          goto EditApp;
        //Selection changed
        case LVN_ITEMCHANGED:
          EnableWindow(GetDlgItem(hwnd,IDC_DELETE),
            ListView_GetSelectionMark(GetDlgItem(hwnd,IDC_BLACKLIST))!=-1);
          return TRUE;
        }//switch (switch(((LPNMHDR)lParam)->code)
      }//switch (wParam)
      break;
    }//WM_NOTIFY
  }
  return FALSE;
}

//////////////////////////////////////////////////////////////////////////////
// 
// Save Flags for the selected User
// 
//////////////////////////////////////////////////////////////////////////////
static void SaveUserFlags()
{
  if (g_SD->CurUser>=0)
  {
    LPTSTR u=g_SD->Users.GetUserName(g_SD->CurUser);
    SetNoRunSetup(u,IsDlgButtonChecked(g_SD->hTabCtrl[1],IDC_RUNSETUP)==0);
    SetRestrictApps(u,IsDlgButtonChecked(g_SD->hTabCtrl[1],IDC_RESTRICTED)!=0);
    SetHideFromUser(u,IsDlgButtonChecked(g_SD->hTabCtrl[1],IDC_HIDESURUN)!=0);
    SetReqPw4Setup(u,IsDlgButtonChecked(g_SD->hTabCtrl[1],IDC_REQPW4SETUP)!=0);
    if(!IsDlgButtonChecked(g_SD->hTabCtrl[1],IDC_TRAYSHOWADMIN))
    {
      SetUserTSA(u,0);
    }
    else
    {
      SetUserTSA(u,1+(DWORD)IsDlgButtonChecked(g_SD->hTabCtrl[1],IDC_TRAYBALLOON));
    }
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
  ListView_GetItemText((HWND)lParamSort,lParam1,2,s1,4096);
  ListView_GetItemText((HWND)lParamSort,lParam2,2,s2,4096);
  return _tcsicmp(s1,s2);
}

static void UpdateWhiteListFlags(HWND hWL)
{
  CBigResStr wlkey(_T("%s\\%s"),SVCKEY,g_SD->Users.GetUserName(g_SD->CurUser));
  TCHAR cmd[4096];
  for (int i=0;i<ListView_GetItemCount(hWL);i++)
  {
    ListView_GetItemText(hWL,i,2,cmd,4096);
    int Flags=GetRegInt(HKLM,wlkey,cmd,0);
    LVITEM item={LVIF_IMAGE,i,0,0,0,0,0,
      g_SD->ImgIconIdx[2+(Flags&FLAG_DONTASK?1:0)+(Flags&FLAG_AUTOCANCEL?4:0)],
      0,0};
    ListView_SetItem(hWL,&item);
    item.iSubItem=1;
    item.iImage=g_SD->ImgIconIdx[(Flags&FLAG_SHELLEXEC?0:1)+(Flags&FLAG_CANCEL_SX?6:0)];
    ListView_SetItem(hWL,&item);
  }
  ListView_SetColumnWidth(hWL,1,
     (IsDlgButtonChecked(g_SD->hTabCtrl[2],IDC_SHEXHOOK)
   ||IsDlgButtonChecked(g_SD->hTabCtrl[2],IDC_IATHOOK))?22:0);
  ListView_SetColumnWidth(hWL,2,LVSCW_AUTOSIZE_USEHEADER);
  InvalidateRect(hWL,0,TRUE);
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
  if ((n>=0) && (g_SD->CurUser==n))
    return;
  //Save Settings:
  SaveUserFlags();
  g_SD->CurUser=n;
  ListView_DeleteAllItems(hWL);
  if (n!=CB_ERR)
  {
    LPTSTR u=g_SD->Users.GetUserName(g_SD->CurUser);
    bm=g_SD->Users.GetUserBitmap(n);
    EnableWindow(GetDlgItem(hwnd,IDC_USER),1);
    EnableWindow(GetDlgItem(hwnd,IDC_DELUSER),1);
    EnableWindow(GetDlgItem(hwnd,IDC_RESTRICTED),1);
    CheckDlgButton(hwnd,IDC_RUNSETUP,!GetNoRunSetup(u));
    EnableWindow(GetDlgItem(hwnd,IDC_RUNSETUP),1);
    EnableWindow(GetDlgItem(hwnd,IDC_HIDESURUN),1);
    CheckDlgButton(hwnd,IDC_RESTRICTED,GetRestrictApps(u));
    CheckDlgButton(hwnd,IDC_HIDESURUN,GetHideFromUser(u));
    if(GetNoRunSetup(u))
    {
      EnableWindow(GetDlgItem(hwnd,IDC_REQPW4SETUP),0);
      CheckDlgButton(hwnd,IDC_REQPW4SETUP,0);
    }else
    {
      CheckDlgButton(hwnd,IDC_REQPW4SETUP,GetReqPw4Setup(u));
    }
    //TSA:
    //Win2k:no balloon tips
    EnableWindow(GetDlgItem(hwnd,IDC_TRAYSHOWADMIN),1);
    EnableWindow(GetDlgItem(hwnd,IDC_TRAYBALLOON),0);
    CheckDlgButton(hwnd,IDC_TRAYBALLOON,BST_UNCHECKED);
    CheckDlgButton(hwnd,IDC_TRAYSHOWADMIN,BST_UNCHECKED);
    switch(GetUserTSA(u))
    {
    case 2:
      CheckDlgButton(hwnd,IDC_TRAYBALLOON,BST_CHECKED);
    case 1:
      if (!IsWin2k())
        EnableWindow(GetDlgItem(hwnd,IDC_TRAYBALLOON),1);
      CheckDlgButton(hwnd,IDC_TRAYSHOWADMIN,BST_CHECKED);
      break;
    }
    if(GetHideFromUser(u))
    {
      EnableWindow(GetDlgItem(hwnd,IDC_TRAYSHOWADMIN),0);
      EnableWindow(GetDlgItem(hwnd,IDC_TRAYBALLOON),0);
      EnableWindow(GetDlgItem(hwnd,IDC_REQPW4SETUP),0);
      EnableWindow(GetDlgItem(hwnd,IDC_RESTRICTED),0);
      EnableWindow(GetDlgItem(hwnd,IDC_RUNSETUP),0);
      CheckDlgButton(hwnd,IDC_TRAYBALLOON,BST_UNCHECKED);
      CheckDlgButton(hwnd,IDC_TRAYSHOWADMIN,BST_UNCHECKED);
      CheckDlgButton(hwnd,IDC_RUNSETUP,BST_UNCHECKED);
      CheckDlgButton(hwnd,IDC_REQPW4SETUP,BST_UNCHECKED);
      CheckDlgButton(hwnd,IDC_RESTRICTED,BST_CHECKED);
      CheckDlgButton(hwnd,IDC_RUNSETUP,BST_UNCHECKED);
    }
    EnableWindow(hWL,true);
    HKEY Key;
    if(RegOpenKeyEx(HKLM,WHTLSTKEY(u),0,KSAM(KEY_READ),&Key)==ERROR_SUCCESS)
    {
      TCHAR cmd[4096];
      DWORD ccMax=countof(cmd);
      for (int i=0;(RegEnumValue(Key,i,cmd,&ccMax,0,0,0,0)==ERROR_SUCCESS);i++)
      {
        ccMax=countof(cmd);
        LVITEM item={LVIF_IMAGE,i,0,0,0,0,0,g_SD->ImgIconIdx[0],0,0};
        ListView_SetItemText(hWL,ListView_InsertItem(hWL,&item),2,cmd);
      }
      RegCloseKey(Key);
    }

    ListView_SortItemsEx(hWL,ListSortProc,hWL);
    UpdateWhiteListFlags(hWL);

    EnableWindow(GetDlgItem(hwnd,IDC_ADDAPP),1);
    EnableWindow(GetDlgItem(hwnd,IDC_DELETE),ListView_GetSelectionMark(hWL)!=-1);
    EnableWindow(GetDlgItem(hwnd,IDC_EDITAPP),ListView_GetSelectionMark(hWL)!=-1);
  }else
  {
    EnableWindow(GetDlgItem(hwnd,IDC_USER),0);
    EnableWindow(GetDlgItem(hwnd,IDC_DELUSER),false);
    EnableWindow(GetDlgItem(hwnd,IDC_RESTRICTED),false);
    EnableWindow(GetDlgItem(hwnd,IDC_RUNSETUP),false);
    EnableWindow(GetDlgItem(hwnd,IDC_HIDESURUN),false);
    EnableWindow(GetDlgItem(hwnd,IDC_REQPW4SETUP),false);
    EnableWindow(GetDlgItem(hwnd,IDC_TRAYSHOWADMIN),false);
    EnableWindow(GetDlgItem(hwnd,IDC_TRAYBALLOON),false);
    EnableWindow(hWL,false);
    EnableWindow(GetDlgItem(hwnd,IDC_ADDAPP),false);
    EnableWindow(GetDlgItem(hwnd,IDC_DELETE),false);
    EnableWindow(GetDlgItem(hwnd,IDC_EDITAPP),false);
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
  InvalidateRect(hWL,0,TRUE);
}

//////////////////////////////////////////////////////////////////////////////
// 
// Populate User Combobox and the Program list for the selected User
// 
//////////////////////////////////////////////////////////////////////////////
static void UpdateUserList(HWND hwnd,LPCTSTR UserName)
{
  SendDlgItemMessage(hwnd,IDC_USER,CB_RESETCONTENT,0,0);
  SendDlgItemMessage(hwnd,IDC_USER,CB_SETCURSEL,-1,0);
  g_SD->CurUser=0;
  for (int i=0;i<g_SD->Users.GetCount();i++)
  {
    LPTSTR u=g_SD->Users.GetUserName(i);
    SendDlgItemMessage(hwnd,IDC_USER,CB_INSERTSTRING,i,(LPARAM)u);
    if (_tcsicmp(u,UserName)==0)
      g_SD->CurUser=i;
  }
  SendDlgItemMessage(hwnd,IDC_USER,CB_SETCURSEL,g_SD->CurUser,0);
  g_SD->CurUser=-1;
  UpdateUser(hwnd);
}

//////////////////////////////////////////////////////////////////////////////
// 
// SetRecommendedSettings()
// 
//////////////////////////////////////////////////////////////////////////////
void SetUseSuRuners(HWND hwnd,BOOL bUse)
{
  TCHAR u[MAX_PATH];
  _tcscpy(u,(g_SD->CurUser>=0)?g_SD->Users.GetUserName(g_SD->CurUser):g_SD->OrgUser);
  SetUseSuRunGrp((DWORD)bUse);
  g_SD->Users.SetSurunnersUsers(false);
  UpdateUserList(hwnd,u);
}

void SetRecommendedSettings(bool bExpertOnly=FALSE)
{
  HWND h=g_SD->hTabCtrl[0];
  if (!bExpertOnly)
  {
    CheckDlgButton(h,IDC_BLURDESKTOP,1);
    CheckDlgButton(h,IDC_FADEDESKTOP,1);
    CheckDlgButton(h,IDC_ASKPW,0);
    SetDlgItemInt(h,IDC_ASKTIMEOUT,0,0);
    ComboBox_SetCurSel(GetDlgItem(h,IDC_WARNADMIN),APW_NR_SR_ADMIN);
    CheckDlgButton(h,IDC_CTRLASADMIN,1);
    CheckDlgButton(h,IDC_CMDASADMIN,0);
    CheckDlgButton(h,IDC_EXPASADMIN,1);
    CheckDlgButton(h,IDC_RESTARTADMIN,1);
    CheckDlgButton(h,IDC_STARTADMIN,0);
    EnableWindow(GetDlgItem(h,IDC_FADEDESKTOP),!IsWin2k());
    EnableWindow(GetDlgItem(h,IDC_ASKTIMEOUT),0);
    
    h=g_SD->hTabCtrl[1]; 
    EnableWindow(GetDlgItem(h,IDC_RUNSETUP),1);
    EnableWindow(GetDlgItem(h,IDC_REQPW4SETUP),1);
    EnableWindow(GetDlgItem(h,IDC_RESTRICTED),1);
    EnableWindow(GetDlgItem(h,IDC_HIDESURUN),1);
    EnableWindow(GetDlgItem(h,IDC_TRAYSHOWADMIN),1);
    EnableWindow(GetDlgItem(h,IDC_TRAYBALLOON),!IsWin2k());
    CheckDlgButton(h,IDC_RUNSETUP,1);
    CheckDlgButton(h,IDC_REQPW4SETUP,0);
    CheckDlgButton(h,IDC_RESTRICTED,0);
    CheckDlgButton(h,IDC_HIDESURUN,0);
    CheckDlgButton(h,IDC_TRAYSHOWADMIN,1);
    CheckDlgButton(h,IDC_TRAYBALLOON,1);
    
    int User=g_SD->CurUser;
    for (g_SD->CurUser=0;g_SD->CurUser<g_SD->Users.GetCount();g_SD->CurUser++)
      SaveUserFlags();
    g_SD->CurUser=User;
    
  }
  h=g_SD->hTabCtrl[2];
  CheckDlgButton(h,IDC_SHEXHOOK,1);
  CheckDlgButton(h,IDC_IATHOOK,1);
  CheckDlgButton(h,IDC_REQADMIN,1);
  CheckDlgButton(h,IDC_SHOWTRAY,1);
  CheckDlgButton(h,IDC_NOUSESURUNNERS,0);
  SetUseSuRuners(h,TRUE);
  EnableWindow(GetDlgItem(h,IDC_REQADMIN),1);
  EnableWindow(GetDlgItem(h,IDC_BLACKLIST),1);
  EnableWindow(GetDlgItem(h,IDC_SHOWTRAY),1);
  UpdateWhiteListFlags(GetDlgItem(g_SD->hTabCtrl[1],IDC_WHITELIST));
  h=g_SD->hTabCtrl[3];
  CheckDlgButton(h,IDC_DORUNAS,0);
  CheckDlgButton(h,IDC_ALLOWTIME,0);
  CheckDlgButton(h,IDC_SETENERGY,1);
  CheckDlgButton(h,IDC_WINUPD4ALL,1);
  CheckDlgButton(h,IDC_WINUPDBOOT,1);
  CheckDlgButton(h,IDC_OWNERGROUP,1);
  ComboBox_SetCurSel(GetDlgItem(h,IDC_TRAYSHOWADMIN),TSA_ADMIN);
  CheckDlgButton(h,IDC_TRAYBALLOON,1);
  EnableWindow(GetDlgItem(h,IDC_TRAYBALLOON),!IsWin2k());
  CheckDlgButton(h,IDC_NOCONVADMIN,0);
  CheckDlgButton(h,IDC_NOCONVUSER,0);
  CheckDlgButton(h,IDC_HIDESURUN,0);
}

void ShowExpertSettings(HWND hwnd,bool bShow)
{
  HWND hTab=GetDlgItem(hwnd,IDC_SETUP_TAB);
  int nSel=TabCtrl_GetCurSel(hTab);
  TabCtrl_DeleteItem(hTab,3);
  TabCtrl_DeleteItem(hTab,2);
  if (!bShow)
  {
    ShowWindow(GetDlgItem(g_SD->hTabCtrl[1],IDC_NOUSESURUNNERS),SW_HIDE);
    if (nSel>1)
    {
      ShowWindow(g_SD->hTabCtrl[nSel],FALSE);
      ShowWindow(g_SD->hTabCtrl[1],TRUE);
      TabCtrl_SetCurSel(hTab,1);
      g_SD->CurTab=1;
    }
    SetRecommendedSettings(true);
  }else
  {
    ShowWindow(GetDlgItem(g_SD->hTabCtrl[1],IDC_NOUSESURUNNERS),SW_SHOW);
    TCITEM tie3={TCIF_TEXT,0,0,CResStr(IDS_SETUP3),0,0,0};
    TabCtrl_InsertItem(hTab,2,&tie3);
    TCITEM tie4={TCIF_TEXT,0,0,CResStr(IDS_SETUP4),0,0,0};
    TabCtrl_InsertItem(hTab,3,&tie4);
  }
  RedrawWindow(hwnd,0,0,RDW_INVALIDATE|RDW_ALLCHILDREN);
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
      CheckDlgButton(hwnd,IDC_FADEDESKTOP,GetFadeDesk);
      EnableWindow(GetDlgItem(hwnd,IDC_FADEDESKTOP),(!IsWin2k())&&GetBlurDesk);
      
      BOOL bAsk=(!GetSavePW)||(GetPwTimeOut!=0);
      CheckDlgButton(hwnd,IDC_ASKPW,bAsk);
      EnableWindow(GetDlgItem(hwnd,IDC_ASKTIMEOUT),bAsk);
      
      HWND cb=GetDlgItem(hwnd,IDC_WARNADMIN);
      for (int i=0;i<5;i++)
        ComboBox_InsertString(cb,i,CResStr(IDS_WARNADMIN+i));
      ComboBox_SetCurSel(cb,GetAdminNoPassWarn);

      CheckDlgButton(hwnd,IDC_CTRLASADMIN,GetCtrlAsAdmin);
      CheckDlgButton(hwnd,IDC_CMDASADMIN,GetCmdAsAdmin);
      CheckDlgButton(hwnd,IDC_EXPASADMIN,GetExpAsAdmin);
      
      CheckDlgButton(hwnd,IDC_RESTARTADMIN,GetRestartAsAdmin);
      CheckDlgButton(hwnd,IDC_STARTADMIN,GetStartAsAdmin);

      CheckDlgButton(hwnd,IDC_NOEXPERT,!GetHideExpertSettings);
      return TRUE;
    }//WM_INITDIALOG
  case WM_CTLCOLORSTATIC:
    SetBkMode((HDC)wParam,TRANSPARENT);
  case WM_CTLCOLORDLG:
    return (BOOL)PtrToUlong(GetStockObject(WHITE_BRUSH));
  case WM_COMMAND:
    {
      switch (wParam)
      {
      case MAKELPARAM(IDC_BLURDESKTOP,BN_CLICKED):
        EnableWindow(GetDlgItem(hwnd,IDC_FADEDESKTOP),(!IsWin2k())&& IsDlgButtonChecked(hwnd,IDC_BLURDESKTOP));
        return TRUE;
      case MAKELPARAM(IDC_ASKPW,BN_CLICKED):
        EnableWindow(GetDlgItem(hwnd,IDC_ASKTIMEOUT),IsDlgButtonChecked(hwnd,IDC_ASKPW));
        return TRUE;
      case MAKELPARAM(IDC_NOEXPERT,BN_CLICKED):
        if (!IsDlgButtonChecked(hwnd,IDC_NOEXPERT))
        {
          if (SafeMsgBox(hwnd,CBigResStr(IDS_EXPERTSETUP),CResStr(IDS_APPNAME),
            MB_YESNO|MB_ICONQUESTION|MB_DEFBUTTON2)==IDYES)
            ShowExpertSettings(GetParent(hwnd),false);
          else
            CheckDlgButton(hwnd,IDC_NOEXPERT,1);
        }else
          ShowExpertSettings(GetParent(hwnd),TRUE);
        break;
      case MAKELPARAM(IDC_SIMPLESETUP,BN_CLICKED):
        if (SafeMsgBox(hwnd,CBigResStr(IDS_SIMPLESETUP),CResStr(IDS_APPNAME),
          MB_YESNO|MB_ICONQUESTION|MB_DEFBUTTON2)==IDYES)
        {
          SetRecommendedSettings();
        }
        break;
      case MAKELPARAM(ID_APPLY,BN_CLICKED):
        goto ApplyChanges;
      }//switch (wParam)
      break;
    }//WM_COMMAND
  case WM_DESTROY:
    if (g_SD->DlgExitCode==IDOK) //User pressed OK, save settings
    {
ApplyChanges:
      SetBlurDesk(IsDlgButtonChecked(hwnd,IDC_BLURDESKTOP));
      SetFadeDesk(IsDlgButtonChecked(hwnd,IDC_FADEDESKTOP));
      if(IsDlgButtonChecked(hwnd,IDC_ASKPW))
      {
        SetPwTimeOut(GetDlgItemInt(hwnd,IDC_ASKTIMEOUT,0,0));
      }else
        SetPwTimeOut(0);
      DWORD bSave=(!IsDlgButtonChecked(hwnd,IDC_ASKPW))|| (GetPwTimeOut!=0);
      SetSavePW(bSave);
      SetAdminNoPassWarn(ComboBox_GetCurSel(GetDlgItem(hwnd,IDC_WARNADMIN)));
      
      SetCtrlAsAdmin(IsDlgButtonChecked(hwnd,IDC_CTRLASADMIN));
      SetCmdAsAdmin(IsDlgButtonChecked(hwnd,IDC_CMDASADMIN));
      SetExpAsAdmin(IsDlgButtonChecked(hwnd,IDC_EXPASADMIN));
      
      SetRestartAsAdmin(IsDlgButtonChecked(hwnd,IDC_RESTARTADMIN));
      SetStartAsAdmin(IsDlgButtonChecked(hwnd,IDC_STARTADMIN));

      SetHideExpertSettings(IsDlgButtonChecked(hwnd,IDC_NOEXPERT)==0);
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
      SetWindowLong(hWL,GWL_STYLE,GetWindowLong(hWL,GWL_STYLE)|LVS_SHAREIMAGELISTS);
      SendMessage(hWL,LVM_SETEXTENDEDLISTVIEWSTYLE,0,
        LVS_EX_FULLROWSELECT|LVS_EX_SUBITEMIMAGES);
      ListView_SetImageList(hWL,g_SD->ImgList,LVSIL_SMALL);
      for (int i=0;i<3;i++)
      {
        LVCOLUMN col={LVCF_WIDTH,0,(i==0)?26:22,0,0,0,0,0};
        ListView_InsertColumn(hWL,i,&col);
      }
      CheckDlgButton(hwnd,IDC_NOUSESURUNNERS,GetUseSuRunGrp==0);
      if (!GetUseSuRunGrp)
      {
        EnableWindow(GetDlgItem(hwnd,IDC_ADDUSER),false);
        EnableWindow(GetDlgItem(hwnd,IDC_DELUSER),false);
      }
      //UserList
      UpdateUserList(hwnd,
        (g_SD->CurUser>=0)?g_SD->Users.GetUserName(g_SD->CurUser):g_SD->OrgUser);
      g_SD->Setup2Anchor.Init(hwnd);
      g_SD->Setup2Anchor.Add(IDC_USER,ANCHOR_TOPLEFT|ANCHOR_RIGHT);
      g_SD->Setup2Anchor.Add(IDC_ADDUSER,ANCHOR_TOPRIGHT);
      g_SD->Setup2Anchor.Add(IDC_DELUSER,ANCHOR_TOPRIGHT);
      g_SD->Setup2Anchor.Add(IDS_GRPDESC,ANCHOR_ALL);
      g_SD->Setup2Anchor.Add(IDC_WHITELIST,ANCHOR_ALL);
      g_SD->Setup2Anchor.Add(IDC_NOUSESURUNNERS,ANCHOR_BOTTOMLEFT);
      g_SD->Setup2Anchor.Add(IDC_ADDAPP,ANCHOR_BOTTOMRIGHT);
      g_SD->Setup2Anchor.Add(IDC_EDITAPP,ANCHOR_BOTTOMRIGHT);
      g_SD->Setup2Anchor.Add(IDC_DELETE,ANCHOR_BOTTOMRIGHT);
      g_SD->Setup2Anchor.Add(IDC_ICONHELP,ANCHOR_BOTTOMRIGHT);
      return TRUE;
    }//WM_INITDIALOG
  case WM_SIZE:
    {
      g_SD->Setup2Anchor.OnSize(false);
      return TRUE;
    }
  case WM_CTLCOLORSTATIC:
    SetBkMode((HDC)wParam,TRANSPARENT);
  case WM_CTLCOLORDLG:
    return (BOOL)PtrToUlong(GetStockObject(WHITE_BRUSH));
  case WM_PAINT:
    // The List Control is (to for some to me unknow reason) NOT displayed if
    // a user app switches to the user desktop and WatchDog switches back.
    RedrawWindow(GetDlgItem(hwnd,IDC_WHITELIST),0,0,RDW_ERASE|RDW_INVALIDATE|RDW_FRAME);
    break;
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
      case MAKELPARAM(IDC_NOUSESURUNNERS,BN_CLICKED):
        SetUseSuRuners(hwnd,IsDlgButtonChecked(hwnd,IDC_NOUSESURUNNERS)==0);
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
      //Edit Button
      case MAKELPARAM(IDC_EDITAPP,BN_CLICKED):
        {
EditApp:
          HWND hWL=GetDlgItem(hwnd,IDC_WHITELIST);
          int CurSel=(int)ListView_GetSelectionMark(hWL);
          if (CurSel>=0)
          {
            TCHAR cmd[4096];
            TCHAR CMD[4096];
            ListView_GetItemText(hWL,CurSel,2,cmd,4096);
            _tcscpy(CMD,cmd);
            LPTSTR u=g_SD->Users.GetUserName(g_SD->CurUser);
            DWORD f=GetWhiteListFlags(u,cmd,0);
            if (GetFileName(hwnd,f,CMD))
            {
              if (RemoveFromWhiteList(u,cmd))
              {
                if (AddToWhiteList(u,CMD,f))
                {
                  ListView_DeleteItem(hWL,CurSel);
                  LVITEM item={LVIF_IMAGE,0,0,0,0,0,0,g_SD->ImgIconIdx[0],0,0};
                  ListView_SetItemText(hWL,ListView_InsertItem(hWL,&item),2,CMD);
                  ListView_SortItemsEx(hWL,ListSortProc,hWL);
                  UpdateWhiteListFlags(hWL);
                }else
                  MessageBeep(MB_ICONERROR);
              }else
                MessageBeep(MB_ICONERROR);
            }
            RedrawWindow(hwnd,0,0,RDW_INVALIDATE|RDW_ALLCHILDREN);
          }
        }
        return TRUE;
      //Add User Button
      case MAKELPARAM(IDC_ADDUSER,BN_CLICKED):
        {
          zero(g_SD->NewUser);
          DialogBox(GetModuleHandle(0),MAKEINTRESOURCE(IDD_SELUSER),hwnd,SelUserDlgProc);
          if (g_SD->NewUser[0] && BeOrBecomeSuRunner(g_SD->NewUser,FALSE,hwnd))
          {
            g_SD->Users.SetSurunnersUsers(TRUE);
            UpdateUserList(hwnd,g_SD->NewUser);
            zero(g_SD->NewUser);
          }
        }
        return TRUE;
      //Delete User Button
      case MAKELPARAM(IDC_DELUSER,BN_CLICKED):
        if(GetUseSuRunGrp)
        {
          LPTSTR u=g_SD->Users.GetUserName(g_SD->CurUser);
          switch (SafeMsgBox(hwnd,CBigResStr(IDS_DELUSER,u),
            CResStr(IDS_APPNAME),MB_ICONASTERISK|MB_YESNOCANCEL|MB_DEFBUTTON3))
          {
          case IDYES:
            AlterGroupMember(DOMAIN_ALIAS_RID_ADMINS,u,1);
            //Fall through
          case IDNO:
            AlterGroupMember(SURUNNERSGROUP,u,0);
            DelUsrSettings(u);
            g_SD->Users.SetSurunnersUsers(TRUE);
            UpdateUserList(hwnd,g_SD->OrgUser);
            break;
          }
        }
        return TRUE;
      //Add App Button
      case MAKELPARAM(IDC_ADDAPP,BN_CLICKED):
        {
          TCHAR cmd[4096]={0};
          DWORD f=0;
          if (GetFileName(hwnd,f,cmd))
          {
            if(AddToWhiteList(g_SD->Users.GetUserName(g_SD->CurUser),cmd,f))
            {
              HWND hWL=GetDlgItem(hwnd,IDC_WHITELIST);
              LVITEM item={LVIF_IMAGE,0,0,0,0,0,0,g_SD->ImgIconIdx[0],0,0};
              ListView_SetItemText(hWL,ListView_InsertItem(hWL,&item),2,cmd);
              ListView_SortItemsEx(hWL,ListSortProc,hWL);
              UpdateWhiteListFlags(hWL);
            }else
              MessageBeep(MB_ICONERROR);
          }
        }
        return TRUE;
      case MAKELPARAM(IDC_RESTRICTED,BN_CLICKED):
        UpdateWhiteListFlags(GetDlgItem(hwnd,IDC_WHITELIST));
        return TRUE;
      //Delete App Button
      case MAKELPARAM(IDC_DELETE,BN_CLICKED):
        {
          HWND hWL=GetDlgItem(hwnd,IDC_WHITELIST);
          int CurSel=(int)ListView_GetSelectionMark(hWL);
          if (CurSel>=0)
          {
            TCHAR cmd[4096];
            ListView_GetItemText(hWL,CurSel,2,cmd,4096);
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
          EnableWindow(GetDlgItem(hwnd,IDC_EDITAPP),
            ListView_GetSelectionMark(hWL)!=-1);
        }
        return TRUE;
      case MAKELPARAM(ID_APPLY,BN_CLICKED):
        goto ApplyChanges;
      case MAKELPARAM(IDC_RUNSETUP,BN_CLICKED):
        EnableWindow(GetDlgItem(hwnd,IDC_REQPW4SETUP),IsDlgButtonChecked(hwnd,IDC_RUNSETUP));
        return TRUE;
      case MAKELPARAM(IDC_HIDESURUN,BN_CLICKED):
        if(IsDlgButtonChecked(hwnd,IDC_HIDESURUN))
        {
          if (_tcscmp(g_SD->OrgUser,g_SD->Users.GetUserName(g_SD->CurUser))==0)
          {
            if (SafeMsgBox(hwnd,CBigResStr(IDS_HIDESELF),CResStr(IDS_APPNAME),
              MB_YESNO|MB_ICONQUESTION|MB_DEFBUTTON2)==IDNO)
            {
              CheckDlgButton(hwnd,IDC_HIDESURUN,0);
              return TRUE;
            }
          }
          EnableWindow(GetDlgItem(hwnd,IDC_TRAYSHOWADMIN),0);
          EnableWindow(GetDlgItem(hwnd,IDC_TRAYBALLOON),0);
          EnableWindow(GetDlgItem(hwnd,IDC_REQPW4SETUP),0);
          EnableWindow(GetDlgItem(hwnd,IDC_RESTRICTED),0);
          EnableWindow(GetDlgItem(hwnd,IDC_RUNSETUP),0);
          CheckDlgButton(hwnd,IDC_TRAYBALLOON,BST_UNCHECKED);
          CheckDlgButton(hwnd,IDC_TRAYSHOWADMIN,BST_UNCHECKED);
          CheckDlgButton(hwnd,IDC_RUNSETUP,BST_UNCHECKED);
          CheckDlgButton(hwnd,IDC_REQPW4SETUP,BST_UNCHECKED);
          CheckDlgButton(hwnd,IDC_RESTRICTED,BST_CHECKED);
          CheckDlgButton(hwnd,IDC_RUNSETUP,BST_UNCHECKED);
        }else
        {
          EnableWindow(GetDlgItem(hwnd,IDC_TRAYSHOWADMIN),1);
          BOOL bBal=(!IsWin2k())&&(IsDlgButtonChecked(hwnd,IDC_TRAYSHOWADMIN));
          EnableWindow(GetDlgItem(hwnd,IDC_TRAYBALLOON),bBal);
          EnableWindow(GetDlgItem(hwnd,IDC_RUNSETUP),1);
          EnableWindow(GetDlgItem(hwnd,IDC_RESTRICTED),1);
        }
        UpdateWhiteListFlags(GetDlgItem(hwnd,IDC_WHITELIST));
        return TRUE;
      case MAKELPARAM(IDC_TRAYSHOWADMIN,BN_CLICKED):
        if (!IsWin2k())
          EnableWindow(GetDlgItem(hwnd,IDC_TRAYBALLOON),
            IsDlgButtonChecked(hwnd,IDC_TRAYSHOWADMIN)==BST_CHECKED);
        return TRUE;
      }//switch (wParam)
      break;
    }//WM_COMMAND
  case WM_NOTIFY:
    {
      switch (wParam)
      {
      //Program List Notifications
      case IDC_WHITELIST:
        if (lParam) switch(((LPNMHDR)lParam)->code)
        {
        //Selection changed
        case LVN_ITEMCHANGED:
          EnableWindow(GetDlgItem(hwnd,IDC_DELETE),
            ListView_GetSelectionMark(GetDlgItem(hwnd,IDC_WHITELIST))!=-1);
          EnableWindow(GetDlgItem(hwnd,IDC_EDITAPP),
            ListView_GetSelectionMark(GetDlgItem(hwnd,IDC_WHITELIST))!=-1);
          return TRUE;
        //Mouse Click: Toggle Flags
        case NM_DBLCLK:
          if(((LPNMITEMACTIVATE)lParam)->iSubItem>1)
            goto EditApp;
        case NM_CLICK:
          {
            LPNMITEMACTIVATE p=(LPNMITEMACTIVATE)lParam;
            int Flag=0;
            switch(p->iSubItem)
            {
            case 0:Flag=FLAG_DONTASK;     break;
            case 1:Flag=FLAG_SHELLEXEC;   break;
            }
            if (Flag)
            {
              TCHAR cmd[4096];
              HWND hWL=GetDlgItem(hwnd,IDC_WHITELIST);
              ListView_GetItemText(hWL,p->iItem,2,cmd,4096);
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
    if (g_SD->DlgExitCode!=-1)
    {
ApplyChanges:
      SaveUserFlags();
      return TRUE;
    }//WM_DESTROY
  }
  return FALSE;
}


//////////////////////////////////////////////////////////////////////////////
// 
// Dialog Proc for third Tab-Control
// 
//////////////////////////////////////////////////////////////////////////////
INT_PTR CALLBACK SetupDlg3Proc(HWND hwnd,UINT msg,WPARAM wParam,LPARAM lParam)
{
  switch(msg)
  {
  case WM_INITDIALOG:
    {
      CheckDlgButton(hwnd,IDC_SHEXHOOK,GetUseIShExHook);
      CheckDlgButton(hwnd,IDC_IATHOOK,GetUseIATHook);
      CheckDlgButton(hwnd,IDC_SHOWTRAY,GetShowAutoRuns);
      CheckDlgButton(hwnd,IDC_REQADMIN,GetTestReqAdmin);
      BOOL bHook=GetUseIShExHook || GetUseIATHook;
      EnableWindow(GetDlgItem(hwnd,IDC_REQADMIN),bHook);
      EnableWindow(GetDlgItem(hwnd,IDC_BLACKLIST),bHook);
      EnableWindow(GetDlgItem(hwnd,IDC_SHOWTRAY),bHook);
      return TRUE;
    }//WM_INITDIALOG
  case WM_CTLCOLORSTATIC:
    SetBkMode((HDC)wParam,TRANSPARENT);
  case WM_CTLCOLORDLG:
    return (BOOL)PtrToUlong(GetStockObject(WHITE_BRUSH));
  case WM_DESTROY:
    if (g_SD->DlgExitCode==IDOK) //User pressed OK, save settings
    {
ApplyChanges:
      SetUseIShExHook(IsDlgButtonChecked(hwnd,IDC_SHEXHOOK));
      SetUseIATHook(IsDlgButtonChecked(hwnd,IDC_IATHOOK));
      SetShowAutoRuns(IsDlgButtonChecked(hwnd,IDC_SHOWTRAY));
      return TRUE;
    }//WM_DESTROY
  case WM_COMMAND:
    {
      switch (wParam)
      {
      case MAKELPARAM(IDC_IATHOOK,BN_CLICKED):
      case MAKELPARAM(IDC_SHEXHOOK,BN_CLICKED):
        {
          UpdateWhiteListFlags(GetDlgItem(g_SD->hTabCtrl[1],IDC_WHITELIST));
          BOOL bHook=IsDlgButtonChecked(hwnd,IDC_SHEXHOOK)
                   ||IsDlgButtonChecked(hwnd,IDC_IATHOOK);
          EnableWindow(GetDlgItem(hwnd,IDC_REQADMIN),bHook);
          EnableWindow(GetDlgItem(hwnd,IDC_BLACKLIST),bHook);
          EnableWindow(GetDlgItem(hwnd,IDC_SHOWTRAY),bHook);
        }
        return TRUE;
      case MAKELPARAM(IDC_BLACKLIST,BN_CLICKED):
        DialogBox(GetModuleHandle(0),MAKEINTRESOURCE(IDD_BLKLST),hwnd,BlkLstDlgProc);
        return TRUE;
      case MAKELPARAM(ID_APPLY,BN_CLICKED):
        goto ApplyChanges;
      }
    }
  }
  return FALSE;
}

//////////////////////////////////////////////////////////////////////////////
// 
// Dialog Proc for fourth Tab-Control
// 
//////////////////////////////////////////////////////////////////////////////
INT_PTR CALLBACK SetupDlg4Proc(HWND hwnd,UINT msg,WPARAM wParam,LPARAM lParam)
{
  switch(msg)
  {
  case WM_INITDIALOG:
    {
      HKEY kra=0;
      if (0==RegOpenKeyEx(HKCR,L"exefile\\shell\\runas\\command",0,KSAM(KEY_READ),&kra))
        RegCloseKey(kra);
      if ((!kra)
        &&(0==RegOpenKeyEx(HKCR,L"cplfile\\shell\\runas\\command",0,KSAM(KEY_READ),&kra)))
        RegCloseKey(kra);
      CheckDlgButton(hwnd,IDC_DORUNAS,(kra?BST_UNCHECKED:BST_CHECKED));
      if(GetUseSuRunGrp)
      {
        CheckDlgButton(hwnd,IDC_ALLOWTIME,GetSetTime(SURUNNERSGROUP));
        CheckDlgButton(hwnd,IDC_SETENERGY,GetSetEnergy);
      }
      else
      {
        EnableWindow(GetDlgItem(hwnd,IDC_ALLOWTIME),false);
        EnableWindow(GetDlgItem(hwnd,IDC_SETENERGY),false);
      }
      CheckDlgButton(hwnd,IDC_OWNERGROUP,GetOwnerAdminGrp);
      CheckDlgButton(hwnd,IDC_WINUPD4ALL,GetWinUpd4All);
      CheckDlgButton(hwnd,IDC_WINUPDBOOT,GetWinUpdBoot);

      HWND cb=GetDlgItem(hwnd,IDC_TRAYSHOWADMIN);
      DWORD tsa=GetShowTrayAdmin;
      ComboBox_InsertString(cb,0,CResStr(IDS_WARNADMIN5));//No users
      ComboBox_InsertString(cb,1,CResStr(IDS_WARNADMIN)); //"All users"
      ComboBox_InsertString(cb,2,CResStr(IDS_WARNADMIN4));//"Administrators"
      ComboBox_SetCurSel(cb,tsa & (~TSA_TIPS));
      CheckDlgButton(hwnd,IDC_TRAYBALLOON,(tsa&TSA_TIPS)!=0);
      if (IsWin2k())
        //Win2k:no balloon tips
        EnableWindow(GetDlgItem(hwnd,IDC_TRAYBALLOON),0);
      else
        EnableWindow(GetDlgItem(hwnd,IDC_TRAYBALLOON),(tsa&(~TSA_TIPS))!=0);
      CheckDlgButton(hwnd,IDC_NOCONVADMIN,GetNoConvAdmin);
      CheckDlgButton(hwnd,IDC_NOCONVUSER,GetNoConvUser);
      CheckDlgButton(hwnd,IDC_HIDESURUN,GetDefHideSuRun);
      return TRUE;
    }//WM_INITDIALOG
  case WM_CTLCOLORSTATIC:
    SetBkMode((HDC)wParam,TRANSPARENT);
  case WM_CTLCOLORDLG:
    return (BOOL)PtrToUlong(GetStockObject(WHITE_BRUSH));
  case WM_DESTROY:
    if (g_SD->DlgExitCode==IDOK) //User pressed OK, save settings
    {
ApplyChanges:
      switch (IsDlgButtonChecked(hwnd,IDC_DORUNAS))
      {
      case BST_CHECKED:
        ReplaceRunAsWithSuRun();
        break;
      case BST_UNCHECKED:
        ReplaceSuRunWithRunAs();
        break;
      }
      if(GetUseSuRunGrp)
      {
        if ((GetSetTime(SURUNNERSGROUP)!=0)!=((int)IsDlgButtonChecked(hwnd,IDC_ALLOWTIME)))
          SetSetTime(SURUNNERSGROUP,IsDlgButtonChecked(hwnd,IDC_ALLOWTIME));
        if (GetSetEnergy!=(int)IsDlgButtonChecked(hwnd,IDC_SETENERGY))
          SetSetEnergy(IsDlgButtonChecked(hwnd,IDC_SETENERGY)!=0);
      }
      SetWinUpd4All(IsDlgButtonChecked(hwnd,IDC_WINUPD4ALL));
      SetWinUpdBoot(IsDlgButtonChecked(hwnd,IDC_WINUPDBOOT));
      SetOwnerAdminGrp(IsDlgButtonChecked(hwnd,IDC_OWNERGROUP));

      SetNoConvAdmin(IsDlgButtonChecked(hwnd,IDC_NOCONVADMIN));
      SetNoConvUser(IsDlgButtonChecked(hwnd,IDC_NOCONVUSER));
      SetDefHideSuRun(IsDlgButtonChecked(hwnd,IDC_HIDESURUN));
      DWORD tsa=ComboBox_GetCurSel(GetDlgItem(hwnd,IDC_TRAYSHOWADMIN));
      if (IsDlgButtonChecked(hwnd,IDC_TRAYBALLOON))
        tsa|=TSA_TIPS;
      SetShowTrayAdmin(tsa);
      return TRUE;
    }//WM_DESTROY
  case WM_COMMAND:
    {
      switch (wParam)
      {
      case MAKELPARAM(IDC_TRAYSHOWADMIN,CBN_SELCHANGE):
        if (!IsWin2k())
          EnableWindow(GetDlgItem(hwnd,IDC_TRAYBALLOON),
            ComboBox_GetCurSel(GetDlgItem(hwnd,IDC_TRAYSHOWADMIN))>0);
        return TRUE;
      case MAKELPARAM(ID_APPLY,BN_CLICKED):
        goto ApplyChanges;
      }
    }
  }
  return FALSE;
}

//////////////////////////////////////////////////////////////////////////////
// 
//  Import/Export
// 
//////////////////////////////////////////////////////////////////////////////
BOOL WritePrivateProfileInt(LPCTSTR App, LPCTSTR Key, DWORD Val, LPCTSTR ini)
{
  TCHAR s[16]={0};
  return WritePrivateProfileString(App,Key,_itot(Val,s,10),ini);
}

#define EXPORTINT(App,f,ini)    WritePrivateProfileInt(_T(App),_T(#f),Get##f,ini)
#define IMPORTINT(App,f,ini)    Set##f(GetPrivateProfileInt(_T(App),_T(#f),Get##f,ini))

#define EXPORTINTu(App,f,u,ini) WritePrivateProfileInt(_T(App),_T(#f),Get##f(u),ini)
#define IMPORTINTu(App,f,u,ini) Set##f(u,GetPrivateProfileInt(_T(App),_T(#f),Get##f(u),ini))

#define EXPORTSTR(App,n,s,ini) \
  {\
      TCHAR ts[16];\
      WritePrivateProfileString(_T(App),_itot(n,ts,10),s,ini);\
  }

#define IMPORTSTR(App,n,s,ini)\
  {\
      TCHAR ts[16];\
      GetPrivateProfileString(_T(App),_itot(n,ts,10),_T(""),s,countof(s),ini);\
  }

#define EXPORTVAL(App,n,v,ini) \
  {\
      TCHAR ts[16];\
      WritePrivateProfileInt(_T(App),_itot(n,ts,10),v,ini);\
  }

#define IMPORTVAL(App,n,d,ini)\
  {\
      TCHAR ts[16];\
      d=GetPrivateProfileInt(_T(App),_itot(n,ts,10),d,ini);\
  }

void ExportSettings(LPCTSTR ini,bool bSuRunSettings,bool bBlackList,LPCTSTR User)
{
  DeleteFile(ini);
  if (bSuRunSettings)
  {
    WritePrivateProfileString(_T("SuRun"),_T("Version"),
      CResStr(_T("\"SuRun %s\""),GetVersionString()),ini);
    EXPORTINT("SuRun",UseSuRunGrp,ini);

    EXPORTINT("SuRun",BlurDesk,ini);
    EXPORTINT("SuRun",FadeDesk,ini);
    EXPORTINT("SuRun",SavePW,ini);
    
    EXPORTINT("SuRun",PwTimeOut,ini);
    EXPORTINT("SuRun",AdminNoPassWarn,ini);
    
    EXPORTINT("SuRun",CtrlAsAdmin,ini);
    EXPORTINT("SuRun",CmdAsAdmin,ini);
    EXPORTINT("SuRun",ExpAsAdmin,ini);
    EXPORTINT("SuRun",RestartAsAdmin,ini);
    EXPORTINT("SuRun",StartAsAdmin,ini);
    
    EXPORTINT("SuRun",HideExpertSettings,ini);
    
    EXPORTINT("SuRun",UseIShExHook,ini);
    EXPORTINT("SuRun",UseIATHook,ini);
    EXPORTINT("SuRun",TestReqAdmin,ini);
    EXPORTINT("SuRun",ShowAutoRuns,ini);
    
    WritePrivateProfileInt(_T("SuRun"),_T("ReplaceRunAs"),
      IsDlgButtonChecked(g_SD->hTabCtrl[3],IDC_DORUNAS),ini);
    if(GetUseSuRunGrp)
    {
      EXPORTINTu("SuRun",SetTime,SURUNNERSGROUP,ini);
      EXPORTINT("SuRun",SetEnergy,ini);
    }
    EXPORTINT("SuRun",WinUpd4All,ini);
    EXPORTINT("SuRun",WinUpdBoot,ini);
    EXPORTINT("SuRun",OwnerAdminGrp,ini);
    
    EXPORTINT("SuRun",ShowTrayAdmin,ini);
    
    EXPORTINT("SuRun",NoConvAdmin,ini);
    EXPORTINT("SuRun",NoConvUser,ini);
    EXPORTINT("SuRun",DefHideSuRun,ini);
  }
  if (bBlackList)
  {
    HKEY Key;
    if(RegOpenKeyEx(HKLM,HKLSTKEY,0,KSAM(KEY_READ),&Key)==ERROR_SUCCESS)
    {
      TCHAR cmd[4096];
      _tcscpy(cmd,_T("\"")); //Quote strings!
      DWORD ccMax=countof(cmd)-2;
      for (int i=0;(RegEnumValue(Key,i,&cmd[1],&ccMax,0,0,0,0)==ERROR_SUCCESS);i++)
      {
        ccMax=countof(cmd)-2;
        _tcscat(cmd,_T("\"")); //Quote strings!
        EXPORTSTR("BlackList",i,cmd,ini);
        _tcscpy(cmd,_T("\"")); //Quote strings!
      }
      RegCloseKey(Key);
    }
  }
  if(User)
  {
    EXPORTINTu("User",NoRunSetup,User,ini);
    EXPORTINTu("User",RestrictApps,User,ini);
    EXPORTINTu("User",UserTSA,User,ini);
    EXPORTINTu("User",HideFromUser,User,ini);
    EXPORTINTu("User",ReqPw4Setup,User,ini);
    HKEY Key;
    if(RegOpenKeyEx(HKLM,WHTLSTKEY(User),0,KSAM(KEY_READ),&Key)==ERROR_SUCCESS)
    {
      TCHAR cmd[4096];
      _tcscpy(cmd,_T("\"")); //Quote strings!
      DWORD ccMax=countof(cmd)-2;
      DWORD Flags=0;
      DWORD siz=sizeof(Flags);
      for (int i=0;(RegEnumValue(Key,i,&cmd[1],&ccMax,0,0,(BYTE*)&Flags,&siz)==ERROR_SUCCESS);i++)
      {
        ccMax=countof(cmd);
        siz=sizeof(Flags);
        _tcscat(cmd,_T("\"")); //Quote strings!
        EXPORTSTR("WhiteList",i,cmd,ini);
        EXPORTVAL("WhiteListFlags",i,Flags,ini);
        _tcscpy(cmd,_T("\"")); //Quote strings!

      }
      RegCloseKey(Key);
    }
  }
}

void ImportSettings(LPCTSTR ini,bool bSuRunSettings,bool bBlackList,LPCTSTR User)
{
  if (bSuRunSettings)
  {
    IMPORTINT("SuRun",UseSuRunGrp,ini);

    IMPORTINT("SuRun",BlurDesk,ini);
    IMPORTINT("SuRun",FadeDesk,ini);
    IMPORTINT("SuRun",SavePW,ini);
    
    IMPORTINT("SuRun",PwTimeOut,ini);
    IMPORTINT("SuRun",AdminNoPassWarn,ini);

    IMPORTINT("SuRun",CtrlAsAdmin,ini);
    IMPORTINT("SuRun",CmdAsAdmin,ini);
    IMPORTINT("SuRun",ExpAsAdmin,ini);
    IMPORTINT("SuRun",RestartAsAdmin,ini);
    IMPORTINT("SuRun",StartAsAdmin,ini);
    
    IMPORTINT("SuRun",HideExpertSettings,ini);

    IMPORTINT("SuRun",UseIShExHook,ini);
    IMPORTINT("SuRun",UseIATHook,ini);
    IMPORTINT("SuRun",TestReqAdmin,ini);
    IMPORTINT("SuRun",ShowAutoRuns,ini);

    switch(GetPrivateProfileInt(_T("SuRun"),_T("ReplaceRunAs"),-1,ini))
    {
    case 0:
      ReplaceSuRunWithRunAs(); 
      break;
    case 1:
      ReplaceRunAsWithSuRun(); 
      break;
    }
    IMPORTINT("SuRun",OwnerAdminGrp,ini);
    IMPORTINT("SuRun",WinUpd4All,ini);
    IMPORTINT("SuRun",WinUpdBoot,ini);
    if(GetUseSuRunGrp)
    {
      IMPORTINT("SuRun",SetEnergy,ini);
      IMPORTINTu("SuRun",SetTime,SURUNNERSGROUP,ini);
    }

    IMPORTINT("SuRun",ShowTrayAdmin,ini);
    
    IMPORTINT("SuRun",NoConvAdmin,ini);
    IMPORTINT("SuRun",NoConvUser,ini);
    IMPORTINT("SuRun",DefHideSuRun,ini);
  }
  if (bBlackList)
  {
    DelRegKey(HKLM,HKLSTKEY);
    for (int i=0;;i++)
    {
      TCHAR cmd[4096];
      IMPORTSTR("BlackList",i,cmd,ini);
      if (cmd[0])
        AddToBlackList(cmd);
      else
        break;
    }
  }
  if(User)
  {
    DelUsrSettings(User);
    IMPORTINTu("User",NoRunSetup,User,ini);
    IMPORTINTu("User",RestrictApps,User,ini);
    IMPORTINTu("User",UserTSA,User,ini);
    IMPORTINTu("User",HideFromUser,User,ini);
    IMPORTINTu("User",ReqPw4Setup,User,ini);
    for (int i=0;;i++)
    {
      TCHAR cmd[4096];
      cmd[0]=0;
      IMPORTSTR("WhiteList",i,cmd,ini);
      if (cmd[0])
      {
        DWORD d=0;
        IMPORTVAL("WhiteListFlags",i,d,ini)
          AddToWhiteList(User,cmd,d);
      }else
        break;
    }
  }
}

static BOOL GetINIFile(HWND hwnd,LPTSTR FileName)
{
  #define ExpAdvReg L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced"
  int HideExt=GetRegInt(HKCU,ExpAdvReg,L"HideFileExt",-1);
  SetRegInt(HKCU,ExpAdvReg,L"HideFileExt",0);
  OPENFILENAME  ofn={0};
  ofn.lStructSize       = sizeof(OPENFILENAME);
  ofn.hwndOwner         = hwnd;
  ofn.lpstrFilter       = TEXT("*.*\0*.*\0\0"); 
  ofn.nFilterIndex      = 1;
  ofn.lpstrFile         = FileName;
  ofn.nMaxFile          = 4096;
  ofn.lpstrTitle        = 0;
  ofn.Flags             = OFN_ENABLESIZING|OFN_FORCESHOWHIDDEN;
  ofn.FlagsEx           = OFN_EX_NOPLACESBAR;
  BOOL bRet=GetSaveFileName(&ofn);
  if (HideExt!=-1)
    SetRegInt(HKCU,ExpAdvReg,L"HideFileExt",HideExt);
  return bRet;
  #undef ExpAdvReg
}

INT_PTR CALLBACK ExportDlgProc(HWND hwnd,UINT msg,WPARAM wParam,LPARAM lParam)
{
  switch(msg)
  {
  case WM_INITDIALOG:
    {
      CheckDlgButton(hwnd,IDC_EXPSURUNSETTINGS,(g_SD->CurTab==0)||(g_SD->CurTab==3));
      CheckDlgButton(hwnd,IDC_EXPBLACKLIST,g_SD->CurTab==2);
      CheckDlgButton(hwnd,IDC_EXPUSRSETTINGS,g_SD->CurTab==1);
      if(!IsDlgButtonChecked(g_SD->hTabCtrl[0],IDC_NOEXPERT))
        EnableWindow(GetDlgItem(hwnd,IDC_EXPBLACKLIST),0);
      TCHAR s[MAX_PATH];
      GetDlgItemText(hwnd,IDC_EXPUSRSETTINGS,s,MAX_PATH);
      LPTSTR u=g_SD->Users.GetUserName(g_SD->CurUser);
      SetDlgItemText(hwnd,IDC_EXPUSRSETTINGS,CBigResStr(s,u));
          

      PostMessage(hwnd,WM_COMMAND,IDC_SELFILE,(LPARAM)GetDlgItem(hwnd,IDC_SELFILE));
    }
    return TRUE;
  case WM_CTLCOLORSTATIC:
    SetBkMode((HDC)wParam,TRANSPARENT);
  case WM_CTLCOLORDLG:
    return (BOOL)PtrToUlong(GetStockObject(WHITE_BRUSH));
  case WM_COMMAND:
    switch (wParam)
    {
    case MAKELPARAM(IDC_SELFILE,BN_CLICKED):
      {
        TCHAR f[4096]={0};
        GetDlgItemText(hwnd,IDC_FILENAME,f,4096);
        if(GetINIFile(hwnd,f))
          SetDlgItemText(hwnd,IDC_FILENAME,f);
        else 
          if (f[0]==0)
            EndDialog(hwnd,IDCANCEL);
      }
      break;
    case MAKELPARAM(IDCANCEL,BN_CLICKED):
      EndDialog(hwnd,IDCANCEL);
      return TRUE;
    case MAKELPARAM(IDOK,BN_CLICKED):
      {
        for (int i=0;i<nTabs;i++)
          SendMessage(g_SD->hTabCtrl[i],
            WM_COMMAND,MAKELPARAM(ID_APPLY,BN_CLICKED),
            (LPARAM)GetDlgItem(g_SD->hTabCtrl[i],ID_APPLY));
        TCHAR f[4096]={0};
        GetDlgItemText(hwnd,IDC_FILENAME,f,4096);
        LPTSTR u=g_SD->Users.GetUserName(g_SD->CurUser);
        ExportSettings(f,
          IsDlgButtonChecked(hwnd,IDC_EXPSURUNSETTINGS)!=0,
          IsDlgButtonChecked(hwnd,IDC_EXPBLACKLIST)!=0,
          IsDlgButtonChecked(hwnd,IDC_EXPUSRSETTINGS)?u:0);
        EndDialog(hwnd,IDOK);
      }
      return TRUE;
    }
  }
  return FALSE;
}

static BOOL ExportSettings(HWND hwnd)
{
  return DialogBox(GetModuleHandle(0),MAKEINTRESOURCE(IDD_EXPORTSETTINGS),
    hwnd,ExportDlgProc)==IDOK;
}

static BOOL OpenINIFile(HWND hwnd,LPTSTR FileName)
{
  #define ExpAdvReg L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced"
  int HideExt=GetRegInt(HKCU,ExpAdvReg,L"HideFileExt",-1);
  SetRegInt(HKCU,ExpAdvReg,L"HideFileExt",0);
  OPENFILENAME  ofn={0};
  ofn.lStructSize       = sizeof(OPENFILENAME);
  ofn.hwndOwner         = hwnd;
  ofn.lpstrFilter       = TEXT("*.*\0*.*\0\0"); 
  ofn.nFilterIndex      = 1;
  ofn.lpstrFile         = FileName;
  ofn.nMaxFile          = 4096;
  ofn.lpstrTitle        = 0;
  ofn.Flags             = OFN_ENABLESIZING|OFN_FORCESHOWHIDDEN;
  ofn.FlagsEx           = OFN_EX_NOPLACESBAR;
  BOOL bRet=GetOpenFileName(&ofn);
  if (HideExt!=-1)
    SetRegInt(HKCU,ExpAdvReg,L"HideFileExt",HideExt);
  return bRet;
  #undef ExpAdvReg
}

INT_PTR CALLBACK ImportDlgProc(HWND hwnd,UINT msg,WPARAM wParam,LPARAM lParam)
{
  switch(msg)
  {
  case WM_INITDIALOG:
    {
      CheckDlgButton(hwnd,IDC_IMPSURUNSETTINGS,1);
      CheckDlgButton(hwnd,IDC_IMPBLACKLIST,1);
      CheckDlgButton(hwnd,IDC_IMPUSRSETTINGS,1);
      TCHAR s[MAX_PATH];
      GetDlgItemText(hwnd,IDC_IMPUSRSETTINGS,s,MAX_PATH);
      LPTSTR u=g_SD->Users.GetUserName(g_SD->CurUser);
      SetDlgItemText(hwnd,IDC_IMPUSRSETTINGS,CBigResStr(s,u));
      PostMessage(hwnd,WM_COMMAND,IDC_SELFILE,(LPARAM)GetDlgItem(hwnd,IDC_SELFILE));
    }
    return TRUE;
  case WM_CTLCOLORSTATIC:
    SetBkMode((HDC)wParam,TRANSPARENT);
  case WM_CTLCOLORDLG:
    return (BOOL)PtrToUlong(GetStockObject(WHITE_BRUSH));
  case WM_COMMAND:
    switch (wParam)
    {
    case MAKELPARAM(IDC_SELFILE,BN_CLICKED):
      {
        TCHAR f[4096]={0};
        GetDlgItemText(hwnd,IDC_FILENAME,f,4096);
        if(OpenINIFile(hwnd,f))
        {
          SetDlgItemText(hwnd,IDC_FILENAME,f);
          TCHAR cmd[MAX_PATH];
          bool bSRSet=GetPrivateProfileInt(L"SuRun",L"BlurDesk",-1,f)!=-1;
          bool bBlLst=GetPrivateProfileString(L"BlackList",L"0",L"",cmd,MAX_PATH,f)!=0;
          bool bUsrSet=(GetPrivateProfileInt(L"User",L"NoRunSetup",-1,f)!=-1)
                    && (g_SD->CurUser>=0)
                    && (g_SD->Users.GetCount());
          CheckDlgButton(hwnd,IDC_IMPSURUNSETTINGS,bSRSet);
          CheckDlgButton(hwnd,IDC_IMPBLACKLIST,bBlLst);
          CheckDlgButton(hwnd,IDC_IMPUSRSETTINGS,bUsrSet);
          EnableWindow(GetDlgItem(hwnd,IDC_IMPSURUNSETTINGS),bSRSet);
          EnableWindow(GetDlgItem(hwnd,IDC_IMPBLACKLIST),bBlLst);
          EnableWindow(GetDlgItem(hwnd,IDC_IMPUSRSETTINGS),bUsrSet);
        }else 
          if (f[0]==0)
            EndDialog(hwnd,IDCANCEL);
      }
      break;
    case MAKELPARAM(IDCANCEL,BN_CLICKED):
      EndDialog(hwnd,IDCANCEL);
      return TRUE;
    case MAKELPARAM(IDOK,BN_CLICKED):
      {
        TCHAR f[4096]={0};
        TCHAR cmd[MAX_PATH];
        GetDlgItemText(hwnd,IDC_FILENAME,f,4096);
        if (PathFileExists(f))
        {
          LPTSTR u=g_SD->Users.GetUserName(g_SD->CurUser);
          bool bSRSet=GetPrivateProfileInt(L"SuRun",L"BlurDesk",-1,f)!=-1;
          bool bBlLst=GetPrivateProfileString(L"BlackList",L"0",L"",cmd,MAX_PATH,f)!=0;
          bool bUsrSet=GetPrivateProfileInt(L"User",L"NoRunSetup",-1,f)!=-1;
          if(bSRSet || bBlLst || bUsrSet)
          {
            ImportSettings(f,
              bSRSet && (IsDlgButtonChecked(hwnd,IDC_IMPSURUNSETTINGS)!=0),
              bBlLst && (IsDlgButtonChecked(hwnd,IDC_IMPBLACKLIST)!=0),
              (bUsrSet && IsDlgButtonChecked(hwnd,IDC_IMPUSRSETTINGS))?u:0);
            EndDialog(hwnd,IDOK);
          }
        }
      }
      return TRUE;
    }
  }
  return FALSE;
}

static BOOL ImportSettings(HWND hwnd)
{
  return DialogBox(GetModuleHandle(0),MAKEINTRESOURCE(IDD_IMPORTSETTINGS),
    hwnd,ImportDlgProc)==IDOK;
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
        (LPARAM)LoadImage(GetModuleHandle(0),MAKEINTRESOURCE(IDI_MAINICON),
        IMAGE_ICON,32,32,0));
      SendMessage(hwnd,WM_SETICON,ICON_SMALL,
        (LPARAM)LoadImage(GetModuleHandle(0),MAKEINTRESOURCE(IDI_MAINICON),
        IMAGE_ICON,16,16,0));
      {
        TCHAR WndText[MAX_PATH]={0},newText[MAX_PATH]={0};
        GetWindowText(hwnd,WndText,MAX_PATH);
        _stprintf(newText,WndText,GetVersionString());
        SetWindowText(hwnd,newText);
      }
      //Tab Control
      HWND hTab=GetDlgItem(hwnd,IDC_SETUP_TAB);
      int TabNames[nTabs]= {IDS_SETUP1,IDS_SETUP2,IDS_SETUP3,IDS_SETUP4};
      int TabIDs[nTabs]= { IDD_SETUP1,IDD_SETUP2,IDD_SETUP3,IDD_SETUP4};
      DLGPROC TabProcs[nTabs]= { SetupDlg1Proc,SetupDlg2Proc,SetupDlg3Proc,SetupDlg4Proc};
      int i;
      for (i=0;i<nTabs;i++)
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
      TabCtrl_SetCurSel(hTab,g_SD->CurTab);
      ShowWindow(g_SD->hTabCtrl[g_SD->CurTab],TRUE);
      //...
      UpdateWhiteListFlags(GetDlgItem(g_SD->hTabCtrl[1],IDC_WHITELIST));
      //...
      if (GetHideExpertSettings)
        ShowExpertSettings(hwnd,false);
      SetFocus(hTab);
      g_SD->MainSetupAnchor.Init(hwnd);
      g_SD->MainSetupAnchor.Add(IDC_SETUP_TAB,ANCHOR_ALL);
      for (i=0;i<nTabs;i++)
        g_SD->MainSetupAnchor.Add(g_SD->hTabCtrl[i],ANCHOR_ALL);
      g_SD->MainSetupAnchor.Add(IDC_IMPORT,ANCHOR_BOTTOMLEFT);
      g_SD->MainSetupAnchor.Add(IDC_EXPORT,ANCHOR_BOTTOMLEFT);
      g_SD->MainSetupAnchor.Add(ID_APPLY,ANCHOR_BOTTOMRIGHT);
      g_SD->MainSetupAnchor.Add(IDOK,ANCHOR_BOTTOMRIGHT);
      g_SD->MainSetupAnchor.Add(IDCANCEL,ANCHOR_BOTTOMRIGHT);
      RECT r;
      GetWindowRect(hwnd,&r);
      g_SD->MinW=r.right-r.left;
      g_SD->MinH=r.bottom-r.top;
      int w=GetRegInt(HKLM,SURUNKEY,L"SetupW",g_SD->MinW);
      int h=GetRegInt(HKLM,SURUNKEY,L"SetupH",g_SD->MinH);
      int x=r.left-(w-g_SD->MinW)/2;
      int y=r.top-(h-g_SD->MinH)/2;
      MoveWindow(hwnd,x,y,w,h,false);
      PostMessage(hwnd,WM_SIZE,0,0);
      return FALSE;
    }//WM_INITDIALOG
  case WM_SIZE:
    {
      g_SD->MainSetupAnchor.OnSize(false);
      RedrawWindow(hwnd,0,0,RDW_INVALIDATE|RDW_ALLCHILDREN);
      return TRUE;
    }
  case WM_GETMINMAXINFO:
    {
      MINMAXINFO* lpMMI=(MINMAXINFO*)lParam;
      lpMMI->ptMinTrackSize.x=g_SD->MinW;
      lpMMI->ptMinTrackSize.y=g_SD->MinH;
      return TRUE;
    }
  case WM_NCDESTROY:
    {
      RECT r;
      GetWindowRect(hwnd,&r);
      SetRegInt(HKLM,SURUNKEY,L"SetupW",r.right-r.left);
      SetRegInt(HKLM,SURUNKEY,L"SetupH",r.bottom-r.top);
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
            g_SD->CurTab=nSel;
            return TRUE;
        }
      }
      break;
    }//WM_NOTIFY
  case WM_COMMAND:
    {
      switch (wParam)
      {
      case MAKELPARAM(ID_APPLY,BN_CLICKED):
        SendMessage(
          g_SD->hTabCtrl[TabCtrl_GetCurSel(GetDlgItem(hwnd,IDC_SETUP_TAB))],
          WM_COMMAND,wParam,lParam);
        return TRUE;
      case MAKELPARAM(IDC_IMPORT,BN_CLICKED):
        if (ImportSettings(hwnd)==IDOK)
        {
          g_SD->DlgExitCode=-1;
          EndDialog(hwnd,-1);
        }
        return TRUE;
      case MAKELPARAM(IDC_EXPORT,BN_CLICKED):
        ExportSettings(hwnd);
        return TRUE;
      case MAKELPARAM(IDCANCEL,BN_CLICKED):
        g_SD->DlgExitCode=IDCANCEL;
        EndDialog(hwnd,0);
        return TRUE;
      case MAKELPARAM(IDOK,BN_CLICKED):
        g_SD->DlgExitCode=IDOK;
        EndDialog(hwnd,1);
        return TRUE;
      }//switch (wParam)
      break;
    }//WM_COMMAND
  }
  return FALSE;
}

BOOL RunSetup(LPCTSTR User)
{
  INT_PTR bRet=-1;
  SETUPDATA sd(User);
  g_SD=&sd;
  while (bRet==-1)
  {
    bRet=DialogBox(GetModuleHandle(0),MAKEINTRESOURCE(IDD_SETUP_MAIN),
      0,MainSetupDlgProc);  
  }
  g_SD=0;
  return bRet==IDOK;
}

#ifdef _DEBUGSETUP

#include "WinStaDesk.h"
BOOL TestSetup()
{
  LoadLibrary(TEXT("Shell32.dll"));
  INITCOMMONCONTROLSEX icce={sizeof(icce),0xFFFF};
  TCHAR un[2*MAX_PATH+1];
  GetProcessUserName(GetCurrentProcessId(),un);
  InitCommonControlsEx(&icce);

  SetThreadLocale(MAKELCID(MAKELANGID(LANG_GERMAN,SUBLANG_GERMAN),SORT_DEFAULT));
  if (!RunSetup(un))
    DBGTrace1("DialogBox failed: %s",GetLastErrorNameStatic());
  
  SetThreadLocale(MAKELCID(MAKELANGID(LANG_ENGLISH,SUBLANG_ENGLISH_US),SORT_DEFAULT));
  if (!RunSetup(un))
    DBGTrace1("DialogBox failed: %s",GetLastErrorNameStatic());
  
  SetThreadLocale(MAKELCID(MAKELANGID(LANG_POLISH,0),SORT_DEFAULT));
  if (!RunSetup(un))
    DBGTrace1("DialogBox failed: %s",GetLastErrorNameStatic());
  ::ExitProcess(0);
  return TRUE;
}

#endif _DEBUGSETUP

