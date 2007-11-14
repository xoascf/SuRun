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

// This is the main file for the SuRun service. This file handles:
// -SuRun Installation
// -SuRun Uninstallation
// -SuRun Setup
// -the Windows Service
// -putting the user to the SuRunners group
// -Terminating a Process for "Restart as admin..."
// -requesting permission/password in the logon session of the user
// -putting the users password to the user process via WriteProcessMemory

#ifdef _DEBUG
//#define _DEBUGSETUP
#endif _DEBUG

#define _WIN32_WINNT 0x0500
#define WINVER       0x0500
#include <windows.h>
#include <shlwapi.h>
#include <stdio.h>
#include <tchar.h>
#include <Rpcdce.h>
#include <lm.h>
#include <ntsecapi.h>
#include <USERENV.H>
#include <Psapi.h>
#include "Service.h"
#include "IsAdmin.h"
#include "CmdLine.h"
#include "WinStaDesk.h"
#include "ResStr.h"
#include "LogonDlg.h"
#include "UserGroups.h"
#include "Helpers.h"
#include "BlowFish.h"
#include "lsa_laar.h"
#include "DBGTrace.h"
#include "Resource.h"
#include "SuRunExt/SuRunExt.h"
#include "SuRunExt/SysMenuHook.h"

#pragma comment(lib,"shlwapi.lib")
#pragma comment(lib,"Rpcrt4.lib")
#pragma comment(lib,"Userenv.lib")
#pragma comment(lib,"AdvApi32.lib")
#pragma comment(lib,"PSAPI.lib")

#ifndef _DEBUG
  #ifdef _WIN64
    #pragma comment(lib,"SuRunExt/ReleaseUx64/SuRunExt.lib")
  #else  _WIN64
    #ifdef _SR32
      #pragma comment(lib,"SuRunExt/ReleaseUsr32/SuRunExt32.lib")
    #else _SR32
      #pragma comment(lib,"SuRunExt/ReleaseU/SuRunExt.lib")
    #endif _SR32
  #endif _WIN64
#else _DEBUG
  #ifdef _WIN64
    #pragma comment(lib,"SuRunExt/DebugUx64/SuRunExt.lib")
  #else  _WIN64
    #pragma comment(lib,"SuRunExt/DebugU/SuRunExt.lib")
  #endif _WIN64
#endif _DEBUG

//////////////////////////////////////////////////////////////////////////////
// 
//  Settings
// 
//////////////////////////////////////////////////////////////////////////////

static bool g_BlurDesktop=TRUE; //blurred user desktop background on secure Desktop
static bool g_AskAlways=TRUE;   //Ask "Is that ok?" every time
static BYTE g_NoAskTimeOut=0;   //Minutes to wait until "Is that OK?" is asked again
static bool g_bSavePW=TRUE;

typedef struct //User Token cache
{
  TCHAR UserName[UNLEN+GNLEN];
  TCHAR Password[PWLEN];
  __int64 LastAskTime;
}USERDATA;

static USERDATA g_Users[32]={0};    //Tokens for the last 32 Users are cached

//////////////////////////////////////////////////////////////////////////////
// 
//  Globals
// 
//////////////////////////////////////////////////////////////////////////////

#define Radio1chk (g_AskAlways!=0)
#define Radio2chk ((g_AskAlways==0)&&(g_NoAskTimeOut!=0))

#define HKLM      HKEY_LOCAL_MACHINE
#define SVCKEY    _T("SECURITY\\SuRun")
#define PWKEY     _T("SECURITY\\SuRun\\Cache")
#define WLKEY(u)  CBigResStr(_T("%s\\%s"),SVCKEY,u)

BYTE KEYPASS[16]={0x5B,0xC3,0x25,0xE9,0x8F,0x2A,0x41,0x10,0xA3,0xF4,0x26,0xD1,0x62,0xB4,0x0A,0xE2};

static SERVICE_STATUS_HANDLE g_hSS=0;
static SERVICE_STATUS g_ss= {0};
static HANDLE g_hPipe=INVALID_HANDLE_VALUE;

CResStr SvcName(IDS_SERVICE_NAME);

RUNDATA g_RunData={0};
TCHAR g_RunPwd[PWLEN];

//FILETIME(100ns) to minutes multiplier
#define ft2min  (__int64)(10/*1�s*/*1000/*1ms*/*1000/*1s*/*60/*1min*/)

//////////////////////////////////////////////////////////////////////////////
// 
//  LoadSettings
// 
//////////////////////////////////////////////////////////////////////////////
void LoadSettings()
{
  g_BlurDesktop=GetRegInt(HKLM,SVCKEY,_T("BlurDesktop"),1)!=0;
  g_AskAlways=GetRegInt(HKLM,SVCKEY,_T("AskAlways"),1)!=0;
  g_NoAskTimeOut=(BYTE)min(60,max(0,(int)GetRegInt(HKLM,SVCKEY,_T("AskTimeOut"),0)));
  g_bSavePW=GetRegInt(HKLM,SVCKEY,_T("SavePasswords"),1)!=0;
}

void LoadPasswords()
{
  zero (g_Users);
  if (!g_bSavePW)
    return;
  HKEY Key;
  if (RegOpenKeyEx(HKLM,PWKEY,0,KEY_QUERY_VALUE,&Key)!=ERROR_SUCCESS)
    return;
  CBlowFish bf;
  bf.Initialize(KEYPASS,sizeof(KEYPASS));
  DWORD n=0;
  for (int i=0;i<countof(g_Users);i++)
  {
    zero(g_Users[n]);
    DWORD cbPwd=sizeof(g_Users[n].Password);
    DWORD cbName=sizeof(g_Users[n].UserName);
    DWORD Type=0;
    if (ERROR_SUCCESS!=RegEnumValue(Key,i,g_Users[n].UserName,&cbName,0,&Type,
                                    (BYTE*)g_Users[n].Password,&cbPwd))
        break;
    if (Type!=REG_BINARY)
      continue;
    bf.Decode((BYTE*)g_Users[n].Password,(BYTE*)g_Users[n].Password,cbPwd);
    n++;
  }
}

//////////////////////////////////////////////////////////////////////////////
// 
//  SaveSettings
// 
//////////////////////////////////////////////////////////////////////////////
void SaveSettings()
{
  SetRegInt(HKLM,SVCKEY,_T("BlurDesktop"),g_BlurDesktop);
  SetRegInt(HKLM,SVCKEY,_T("AskAlways"),g_AskAlways);
  SetRegInt(HKLM,SVCKEY,_T("AskTimeOut"),g_NoAskTimeOut);
  SetRegInt(HKLM,SVCKEY,_T("SavePasswords"),g_bSavePW);
  if (!g_bSavePW)
    DelRegKey(HKLM,PWKEY);
}

void SavePassword(int n)
{
  if (!g_bSavePW)
    return;
  CBlowFish bf;
  TCHAR Password[PWLEN]={0};
  bf.Initialize(KEYPASS,sizeof(KEYPASS));
  SetRegAny(HKLM,PWKEY,g_Users[n].UserName,REG_BINARY,(BYTE*)Password,
    bf.Encode((BYTE*)g_Users[n].Password,(BYTE*)Password,
              (int)_tcslen(g_Users[n].Password)*sizeof(TCHAR)));
}

void SavePasswords()
{
  DelRegKey(HKLM,PWKEY);
  for (int i=0;i<countof(g_Users);i++) 
    SavePassword(i);
}

//////////////////////////////////////////////////////////////////////////////
// 
// WhiteList handling
// 
//////////////////////////////////////////////////////////////////////////////

BOOL IsInWhiteList(LPTSTR User,LPTSTR CmdLine)
{
  return GetRegInt(HKLM,WLKEY(User),CmdLine,0)==1;
}

BOOL RemoveFromWhiteList(LPTSTR User,LPTSTR CmdLine)
{
  return RegDelVal(HKLM,WLKEY(User),CmdLine);
}

void SaveToWhiteList(LPTSTR User,LPTSTR CmdLine)
{
  SetRegInt(HKLM,WLKEY(User),CmdLine,1);
}

//////////////////////////////////////////////////////////////////////////////
// 
// CheckCliProcess:
// 
// checks if rd.CliProcessId is this exe and if rd is g_RunData of the calling
// process equals rd, copies the clients g_RunData to our g_RunData
//////////////////////////////////////////////////////////////////////////////
DWORD CheckCliProcess(RUNDATA& rd)
{
  if (rd.CliProcessId==GetCurrentProcessId())
    return 0;
  HANDLE hProcess=OpenProcess(PROCESS_ALL_ACCESS,FALSE,rd.CliProcessId);
  if (!hProcess)
  {
    DBGTrace1("OpenProcess failed: %s",GetLastErrorNameStatic());
    return 0;
  }
  SIZE_T s;
  DWORD d;
  //Check if the calling process is this Executable:
  HMODULE hMod;
  TCHAR f1[MAX_PATH];
  TCHAR f2[MAX_PATH];
  if (!GetModuleFileName(0,f1,MAX_PATH))
  {
    DBGTrace1("GetModuleFileName failed: %s",GetLastErrorNameStatic());
    return CloseHandle(hProcess),0;
  }
  if(!EnumProcessModules(hProcess,&hMod,sizeof(hMod),&d))
  {
    DBGTrace1("EnumProcessModules failed: %s",GetLastErrorNameStatic());
    return CloseHandle(hProcess),0;
  }
  if(GetModuleFileNameEx(hProcess,hMod,f2,MAX_PATH)==0)
  {
    DBGTrace1("GetModuleFileNameEx failed: %s",GetLastErrorNameStatic());
    return CloseHandle(hProcess),0;
  }
  if(_tcsicmp(f1,f2)!=0)
  {
    DBGTrace2("Invalid Process! %s != %s !",f1,f2);
    return CloseHandle(hProcess),0;
  }
  //Since it's the same process, g_RunData has the same address!
  if (!ReadProcessMemory(hProcess,&g_RunData,&g_RunData,sizeof(RUNDATA),&s))
  {
    DBGTrace1("ReadProcessMemory failed: %s",GetLastErrorNameStatic());
    return CloseHandle(hProcess),0;
  }
  if (sizeof(RUNDATA)!=s)
  {
    DBGTrace2("ReadProcessMemory invalid size %d != %d ",sizeof(RUNDATA),s);
    return CloseHandle(hProcess),0;
  }
  if (memcmp(&rd,&g_RunData,sizeof(RUNDATA))!=0)
  {
    DBGTrace("RunData is different!");
    return CloseHandle(hProcess),1;
  }
  return CloseHandle(hProcess),2;
}

void WaitForProcess(DWORD ProcID)
{
  HANDLE hProc=OpenProcess(SYNCHRONIZE,0,ProcID);
  //First:
  // WaitforSingleObject() for a just started Process will return 
  // immediately with WAIT_OBJECT_0, so SuRun keeps trying until 
  // OpenProcess returns 0
  //
  //Second:
  // This is a bit tricky and because of the RootKit Detector of "ANTIVIR" 
  // avipbb.sys. With avipbb.sys loaded and AntiVir active, OpenProcess
  // will succeed even after the process has terminated
  // So SuRun uses an additional two stage detection,
  // * a total timeout of 50seconds
  // * at maximum 25 runs (WaitForSingleObject, Sleep)
  CTimeOut t(50000);
  int i=0;
  while (hProc)
  {
    if (t.TimedOut() 
      || (WaitForSingleObject(hProc,t.Rest())!=WAIT_OBJECT_0)
      || (i>25) )
      break;
    i++;
    Sleep(100);
    CloseHandle(hProc);
    hProc=OpenProcess(SYNCHRONIZE,0,ProcID);
  }
  DBGTrace1("WaitForProcess(%d) exit",ProcID);
}

//////////////////////////////////////////////////////////////////////////////
// 
//  The Service:
// 
//////////////////////////////////////////////////////////////////////////////

VOID WINAPI SvcCtrlHndlr(DWORD dwControl)
{
  //service control handler
  if(dwControl==SERVICE_CONTROL_STOP)
  {
    g_ss.dwCurrentState   = SERVICE_STOP_PENDING; 
    g_ss.dwCheckPoint     = 0; 
    g_ss.dwWaitHint       = 0; 
    g_ss.dwWin32ExitCode  = 0; 
    SetServiceStatus(g_hSS,&g_ss);
    //Close Named Pipe
    HANDLE hPipe=g_hPipe;
    g_hPipe=INVALID_HANDLE_VALUE;
    //Connect to Pipe
    HANDLE sw=CreateFile(ServicePipeName,GENERIC_WRITE,0,0,OPEN_EXISTING,0,0);
    if (sw==INVALID_HANDLE_VALUE)
    {
      DisconnectNamedPipe(hPipe);
      sw=CreateFile(ServicePipeName,GENERIC_WRITE,0,0,OPEN_EXISTING,0,0);
    }
    //As g_hPipe is now INVALID_HANDLE_VALUE, the Service will exit
    CloseHandle(hPipe);
    return;
  } 
  if (g_hSS!=(SERVICE_STATUS_HANDLE)0) 
    SetServiceStatus(g_hSS,&g_ss);
}

VOID WINAPI ServiceMain(DWORD argc,LPTSTR *argv)
{
#ifdef _DEBUG_ENU
  SetThreadLocale(MAKELCID(MAKELANGID(LANG_ENGLISH,SUBLANG_ENGLISH_US),SORT_DEFAULT));
#endif _DEBUG_ENU
  zero(g_RunPwd);
  //service main
  argc;//unused
  argv;//unused
  DBGTrace( "SuRun Service starting");
  g_ss.dwServiceType      = SERVICE_WIN32_OWN_PROCESS; 
  g_ss.dwControlsAccepted = SERVICE_ACCEPT_STOP; 
  g_ss.dwCurrentState     = SERVICE_START_PENDING; 
  g_hSS                   = RegisterServiceCtrlHandler(SvcName,SvcCtrlHndlr); 
  if (g_hSS==(SERVICE_STATUS_HANDLE)0) 
    return; 
  //Create Pipe:
  g_hPipe=CreateNamedPipe(ServicePipeName,
    PIPE_ACCESS_INBOUND|WRITE_DAC|FILE_FLAG_FIRST_PIPE_INSTANCE,
    PIPE_TYPE_MESSAGE|PIPE_READMODE_MESSAGE|PIPE_WAIT,
    1,0,0,NMPWAIT_USE_DEFAULT_WAIT,NULL);
  if (g_hPipe!=INVALID_HANDLE_VALUE)
  {
    AllowAccess(g_hPipe);
    //Set Service Status to "running"
    g_ss.dwCurrentState     = SERVICE_RUNNING; 
    g_ss.dwCheckPoint       = 0;
    g_ss.dwWaitHint         = 0;
    SetServiceStatus(g_hSS,&g_ss);
    DBGTrace( "SuRun Service running");
    //Setup
    LoadSettings();
    while (g_hPipe!=INVALID_HANDLE_VALUE)
    {
      //Wait for a connection
      ConnectNamedPipe(g_hPipe,0);
      //Exit if g_hPipe==INVALID_HANDLE_VALUE
      if (g_hPipe==INVALID_HANDLE_VALUE)
        break;
      DWORD nRead=0;
      RUNDATA rd={0};
      //Read Client Process ID and command line
      ReadFile(g_hPipe,&rd,sizeof(rd),&nRead,0); 
      //Disconnect client
      DisconnectNamedPipe(g_hPipe);
      if(CheckCliProcess(rd)==2)
      {
        //Process Check succeded, now start this exe in the calling processes
        //Terminal server session to get SwitchDesktop working:
        HANDLE hProc=0;
        if(OpenProcessToken(GetCurrentProcess(),TOKEN_ALL_ACCESS,&hProc))
        {
          HANDLE hRun=0;
          if (DuplicateTokenEx(hProc,MAXIMUM_ALLOWED,NULL,
            SecurityIdentification,TokenPrimary,&hRun))
          {
            DWORD SessionID=0;
            ProcessIdToSessionId(g_RunData.CliProcessId,&SessionID);
            if(SetTokenInformation(hRun,TokenSessionId,&SessionID,sizeof(DWORD)))
            {
              PROCESS_INFORMATION pi={0};
              STARTUPINFO si={0};
              si.cb=sizeof(si);
              TCHAR cmd[4096]={0};
              GetSystemWindowsDirectory(cmd,4096);
              PathAppend(cmd,L"SuRun.exe");
              PathQuoteSpaces(cmd);
              _tcscat(cmd,L" /AskPID ");
              TCHAR PID[10];
              _tcscat(cmd,_itot(g_RunData.CliProcessId,PID,10));
              EnablePrivilege(SE_ASSIGNPRIMARYTOKEN_NAME);
              EnablePrivilege(SE_INCREASE_QUOTA_NAME);
              if (CreateProcessAsUser(hRun,NULL,cmd,NULL,NULL,FALSE,
                          CREATE_UNICODE_ENVIRONMENT|HIGH_PRIORITY_CLASS,
                          0,NULL,&si,&pi))
              {
                CloseHandle(pi.hProcess);
                CloseHandle(pi.hThread);
                WaitForProcess(pi.dwProcessId);
              }else
                DBGTrace2("CreateProcessAsUser(%s) failed %s",cmd,GetLastErrorNameStatic());
            }else
              DBGTrace2("SetTokenInformation(TokenSessionId(%d)) failed %s",SessionID,GetLastErrorNameStatic());
            CloseHandle(hRun);
          }else
            DBGTrace1("DuplicateTokenEx() failed %s",GetLastErrorNameStatic());
          CloseHandle(hProc);
        }
      }
      zero(rd);
    }
  }else
    DBGTrace1( "CreateNamedPipe failed %s",GetLastErrorNameStatic());
  //Stop Service
  g_ss.dwCurrentState     = SERVICE_STOPPED; 
  g_ss.dwCheckPoint       = 0;
  g_ss.dwWaitHint         = 0;
  g_ss.dwWin32ExitCode    = 0; 
  DBGTrace( "SuRun Service stopped");
  SetServiceStatus(g_hSS,&g_ss);
}

//////////////////////////////////////////////////////////////////////////////
// 
//  KillProcess
// 
//////////////////////////////////////////////////////////////////////////////
void KillProcess(DWORD PID)
{
  if (!PID)
    return;
  HANDLE hProcess=OpenProcess(SYNCHRONIZE|PROCESS_TERMINATE,TRUE,PID);
  if(!hProcess)
    return;
  TerminateProcess(hProcess,0);
  CloseHandle(hProcess);
}

//////////////////////////////////////////////////////////////////////////////
// 
//  GivePassword
// 
//////////////////////////////////////////////////////////////////////////////
BOOL GivePassword() 
{
  HANDLE hProcess=OpenProcess(PROCESS_ALL_ACCESS,FALSE,g_RunData.CliProcessId);
  if (!hProcess)
  {
    DBGTrace1("OpenProcess failed: %s",GetLastErrorNameStatic());
    return FALSE;
  }
  SIZE_T n;
  //Since it's the same process, g_RunPwd has the same address!
  if (!WriteProcessMemory(hProcess,&g_RunPwd,&g_RunPwd,PWLEN,&n))
  {
    DBGTrace1("WriteProcessMemory failed: %s",GetLastErrorNameStatic());
    return CloseHandle(hProcess),FALSE;
  }
  if (PWLEN!=n)
  {
    DBGTrace2("WriteProcessMemory invalid size %d != %d ",PWLEN,n);
    return CloseHandle(hProcess),FALSE;
  }
  WaitForSingleObject(hProcess,15000);
  return CloseHandle(hProcess),TRUE;
}

//////////////////////////////////////////////////////////////////////////////
// 
//  CheckGroupMembership: check, if User is member of SuRunners, 
//      if not, try to join him
//////////////////////////////////////////////////////////////////////////////
BOOL CheckGroupMembership(LPCTSTR UserName)
{
  if (IsBuiltInAdmin(UserName))
  {
    MessageBox(0,CBigResStr(IDS_BUILTINADMIN),CResStr(IDS_APPNAME),MB_ICONSTOP);
    return FALSE;
  }
  //Is User member of SuRunners?
  if (IsInSuRunners(UserName))
  {
    if (IsInGroup(DOMAIN_ALIAS_RID_ADMINS,UserName))
    {
      DWORD dwRet=AlterGroupMember(DOMAIN_ALIAS_RID_USERS,UserName,1);
      if (dwRet && (dwRet!=ERROR_MEMBER_IN_ALIAS))
      {
        MessageBox(0,CBigResStr(IDS_NOADD2USERS,GetErrorNameStatic(dwRet)),CResStr(IDS_APPNAME),MB_ICONSTOP);
        return FALSE;
      }
      dwRet=AlterGroupMember(DOMAIN_ALIAS_RID_ADMINS,UserName,0);
      if (dwRet && (dwRet!=ERROR_MEMBER_NOT_IN_ALIAS))
      {
        MessageBox(0,CBigResStr(IDS_NOREMADMINS,GetErrorNameStatic(dwRet)),CResStr(IDS_APPNAME),MB_ICONSTOP);
        return FALSE;
      }
    }
    return TRUE;
  }
  //Domain user?
  LPWSTR lpdn=0;
  NETSETUP_JOIN_STATUS js;
  if(NetGetJoinInformation(0,&lpdn,&js))
  {
    if (IsInGroup(DOMAIN_ALIAS_RID_ADMINS,UserName))
      MessageBox(0,CBigResStr(IDS_DOMAINGROUPS2,lpdn),CResStr(IDS_APPNAME),MB_ICONINFORMATION);
    else
      MessageBox(0,CBigResStr(IDS_DOMAINGROUPS,lpdn),CResStr(IDS_APPNAME),MB_ICONINFORMATION);
    NetApiBufferFree(lpdn);
    return FALSE;
  }
  //Local User:
  if (IsInGroup(DOMAIN_ALIAS_RID_ADMINS,UserName))
  {
    if(MessageBox(0,CBigResStr(IDS_ASKSURUNNER),CResStr(IDS_APPNAME),
      MB_YESNO|MB_DEFBUTTON2|MB_ICONQUESTION)==IDNO)
      return FALSE;
    DWORD dwRet=AlterGroupMember(DOMAIN_ALIAS_RID_USERS,UserName,1);
    if (dwRet && (dwRet!=ERROR_MEMBER_IN_ALIAS))
    {
      MessageBox(0,CBigResStr(IDS_NOADD2USERS,GetErrorNameStatic(dwRet)),CResStr(IDS_APPNAME),MB_ICONSTOP);
      return FALSE;
    }
    dwRet=AlterGroupMember(DOMAIN_ALIAS_RID_ADMINS,UserName,0);
    if (dwRet && (dwRet!=ERROR_MEMBER_NOT_IN_ALIAS))
    {
      MessageBox(0,CBigResStr(IDS_NOREMADMINS,GetErrorNameStatic(dwRet)),CResStr(IDS_APPNAME),MB_ICONSTOP);
      return FALSE;
    }
    dwRet=(AlterGroupMember(SURUNNERSGROUP,UserName,1)!=0);
    if (dwRet && (dwRet!=ERROR_MEMBER_IN_ALIAS))
    {
      MessageBox(0,CBigResStr(IDS_SURUNNER_ERR,GetErrorNameStatic(dwRet)),CResStr(IDS_APPNAME),MB_ICONSTOP);
      return FALSE;
    }
    MessageBox(0,CBigResStr(IDS_LOGOFFON),CResStr(IDS_APPNAME),MB_ICONINFORMATION);
    return TRUE;
  }
  {
    TCHAR U[UNLEN+GNLEN]={0};
    TCHAR P[PWLEN]={0};
    if (!LogonAdmin(U,P,IDS_NOSURUNNER))
      return FALSE;
    zero(U);
    zero(P);
  }
  DWORD dwRet=(AlterGroupMember(SURUNNERSGROUP,UserName,1)!=0);
  if (dwRet && (dwRet!=ERROR_MEMBER_IN_ALIAS))
  {
    MessageBox(0,CBigResStr(IDS_SURUNNER_ERR,GetErrorNameStatic(dwRet)),CResStr(IDS_APPNAME),MB_ICONSTOP);
    return FALSE;
  }
  MessageBox(0,CBigResStr(IDS_SURUNNER_OK),CResStr(IDS_APPNAME),MB_ICONINFORMATION);
  return TRUE;
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
    EnableWindow(GetDlgItem(hwnd,IDC_RADIO1),true);
    EnableWindow(GetDlgItem(hwnd,IDC_RADIO2),true);
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
  DBGTrace4("SetupDlgProc(%x,%x,%x,%x)",hwnd,msg,wParam,lParam);
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
          g_AskAlways=IsDlgButtonChecked(hwnd,IDC_RADIO1)==BST_CHECKED;
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
            RemoveFromWhiteList(g_RunData.UserName,cmd);
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

BOOL Setup(LPCTSTR WinStaName)
{
#ifndef _DEBUGSETUP
  //Every "secure" Desktop has its own UUID as name:
  UUID uid;
  UuidCreate(&uid);
  LPTSTR DeskName=0;
  UuidToString(&uid,&DeskName);
  //Create the new desktop
  CRunOnNewDeskTop crond(WinStaName,DeskName,g_BlurDesktop);
  CStayOnDeskTop csod(DeskName);
  RpcStringFree(&DeskName);
#endif _DEBUGSETUP
  //only Admins and SuRunners may setup SuRun
  if ((IsInGroup(DOMAIN_ALIAS_RID_ADMINS,g_RunData.UserName))
    ||(IsInSuRunners(g_RunData.UserName))
    ||(CheckGroupMembership(g_RunData.UserName)))
    return DialogBox(GetModuleHandle(0),MAKEINTRESOURCE(IDD_SETUP),0,SetupDlgProc)>=0;  
  return false;
}

#ifdef _DEBUGSETUP
BOOL TestSetup()
{
  INITCOMMONCONTROLSEX icce={sizeof(icce),ICC_USEREX_CLASSES|ICC_WIN95_CLASSES};
  InitCommonControlsEx(&icce);
  if (!Setup(L"WinSta0"))
    DBGTrace1("DialogBox failed: %s",GetLastErrorNameStatic());
  SetThreadLocale(MAKELCID(MAKELANGID(LANG_ENGLISH,SUBLANG_ENGLISH_US),SORT_DEFAULT));
  if (!Setup(L"WinSta0"))
    DBGTrace1("DialogBox failed: %s",GetLastErrorNameStatic());
  ::ExitProcess(0);
  return TRUE;
}

BOOL x=TestSetup();
#endif _DEBUGSETUP

int CacheUserPassword(LPTSTR Password)
{
  __int64 minTime=0;
  int nUser=-1;
  int oldestUser=0;
  //find free or oldest USER
  for (int i=0;i<countof(g_Users);i++) 
  {
    if ((g_Users[i].UserName[0]=='\0')
      ||(_tcsicmp(g_Users[i].UserName,g_RunData.UserName)==0))
    {
      nUser=i;
      break;
    }
    if (g_Users[i].LastAskTime<minTime)
    {
      minTime=g_Users[i].LastAskTime;
      oldestUser=i;
    }
  }
  if (nUser==-1)
    nUser=oldestUser;
  //Set user name cache
  _tcscpy(g_Users[nUser].UserName,g_RunData.UserName);
  _tcscpy(g_Users[nUser].Password,Password);
  SavePasswords();
  return nUser;
}

//////////////////////////////////////////////////////////////////////////////
// 
//  PrepareSuRun: Show Password/Permission Dialog on secure Desktop,
// 
//////////////////////////////////////////////////////////////////////////////
int PrepareSuRun()
{
  BOOL bDoAsk=g_AskAlways;
  //Do we have a token for this user?
  int nUser=-1;
  for (int i=0;i<countof(g_Users);i++) 
    if (_tcsicmp(g_Users[i].UserName,g_RunData.UserName)==0)
    {
      nUser=i;
      if ((!bDoAsk) && g_NoAskTimeOut)
      {
        __int64 ft;
        GetSystemTimeAsFileTime((LPFILETIME)&ft);
        if ((ft-g_Users[nUser].LastAskTime)>=(ft2min*(__int64)g_NoAskTimeOut))
          bDoAsk=TRUE;
      }
      break;
    }
  if (nUser==-1)
  {
    //Test if password is empty:
    if ((PasswordOK(g_RunData.UserName,_T("")))
      &&(IsInSuRunners(g_RunData.UserName)))
    {
      //Password is empty, cache it ;)
      nUser=CacheUserPassword(_T(""));
    }else
      bDoAsk=TRUE;
  }
  else 
    if ((!PasswordOK(g_Users[nUser].UserName,g_Users[nUser].Password))
      ||(!IsInSuRunners(g_RunData.UserName)))
  {
    nUser=-1;
    bDoAsk=TRUE;
  }else
    if (IsInWhiteList(g_Users[nUser].UserName,g_RunData.cmdLine))
      return nUser;
  //No Ask, just start cmdLine:
  if (!bDoAsk)
    return nUser;
  //Every "secure" Desktop has its own UUID as name:
  UUID uid;
  UuidCreate(&uid);
  LPTSTR DeskName=0;
  UuidToString(&uid,&DeskName);
  //Create the new desktop
  CRunOnNewDeskTop crond(g_RunData.WinSta,DeskName,g_BlurDesktop);
  CStayOnDeskTop csod(DeskName);
  RpcStringFree(&DeskName);
  if (crond.IsValid())
  {
    //secure desktop created...
    if (!CheckGroupMembership(g_RunData.UserName))
      return -1;
    //Test if password is empty:
    if (PasswordOK(g_RunData.UserName,_T("")))
    {
      //Password is empty, cache it ;)
      nUser=CacheUserPassword(_T(""));
    }
    if(nUser!=-1)
    {
      BOOL bLogon=AskCurrentUserOk(g_RunData.UserName,IDS_ASKOK,g_RunData.cmdLine);
      if(!bLogon)
        return -1;
      if (bLogon==2)
        SaveToWhiteList(g_RunData.UserName,g_RunData.cmdLine);
      return nUser;
    }
    TCHAR Password[MAX_PATH]={0};
    BOOL bLogon=LogonCurrentUser(g_RunData.UserName,Password,IDS_ASKOK,g_RunData.cmdLine);
    if(bLogon)
    {
      nUser=CacheUserPassword(Password);
      zero(Password);
      if (bLogon==2)
        SaveToWhiteList(g_RunData.UserName,g_RunData.cmdLine);
      return nUser;
    }
  }else //FATAL: secure desktop could not be created!
    MessageBox(0,CBigResStr(IDS_NODESK),CResStr(IDS_APPNAME),MB_ICONSTOP|MB_SERVICE_NOTIFICATION);
  return -1;
}

//////////////////////////////////////////////////////////////////////////////
// 
//  CheckServiceStatus
// 
//////////////////////////////////////////////////////////////////////////////

DWORD CheckServiceStatus(LPCTSTR ServiceName)
{
  SC_HANDLE hdlSCM=OpenSCManager(0,0,SC_MANAGER_CONNECT|SC_MANAGER_ENUMERATE_SERVICE);
  if (hdlSCM==0) 
    return FALSE;
  SC_HANDLE hdlServ = OpenService(hdlSCM,ServiceName,SERVICE_QUERY_STATUS);
  if (!hdlServ) 
    return CloseServiceHandle(hdlSCM),FALSE;
  SERVICE_STATUS ss={0};
  if (!QueryServiceStatus(hdlServ,&ss))
  {
    CloseServiceHandle(hdlServ);
    return CloseServiceHandle(hdlSCM),FALSE;
  }
  CloseServiceHandle(hdlServ);
  CloseServiceHandle(hdlSCM);
  return ss.dwCurrentState;
}

DWORD CheckServiceStatus()
{
  return CheckServiceStatus(SvcName);
}

//////////////////////////////////////////////////////////////////////////////
// 
//  SuRun
// 
//////////////////////////////////////////////////////////////////////////////
void SuRun(DWORD ProcessID)
{
  //This is called from a separate process created by the service
  if (!IsLocalSystem())
    return;
  zero(g_RunData);
  zero(g_RunPwd);
  g_RunPwd[0]=1;
  LoadSettings();
  LoadPasswords();
  RUNDATA RD={0};
  RD.CliProcessId=ProcessID;
  if(CheckCliProcess(RD)!=1)
    return;
  //Setup?
  if (_tcsicmp(g_RunData.cmdLine,_T("/SETUP"))==0)
  {
    GivePassword();
    Setup(g_RunData.WinSta);
    return;
  }
  KillProcess(g_RunData.KillPID);
  //Start execution
  int nUser=PrepareSuRun();
  if (nUser!=-1)
  {
    //Secondary Logon service is required by CreateProcessWithLogonW
    if(CheckServiceStatus(_T("seclogon"))!=SERVICE_RUNNING)
    {
      //Start/Resume secondary logon
      SC_HANDLE hdlSCM=OpenSCManager(0,0,SC_MANAGER_CONNECT);
      if (hdlSCM!=0) 
      {
        SC_HANDLE hdlServ = OpenService(hdlSCM,_T("seclogon"),SERVICE_START|SERVICE_PAUSE_CONTINUE);
        if(hdlServ)
        {
          if (!StartService(hdlServ,0,0))
          {
            SERVICE_STATUS ss;
            ControlService(hdlServ,SERVICE_CONTROL_CONTINUE,&ss);
          }
          CloseServiceHandle(hdlServ);
        }
        CloseServiceHandle(hdlSCM);
      }
      if(CheckServiceStatus(_T("seclogon"))!=SERVICE_RUNNING)
      {
        GivePassword();
        MessageBox(0,CBigResStr(IDS_NOSECLOGON),CResStr(IDS_APPNAME),MB_ICONSTOP|MB_SERVICE_NOTIFICATION);
        return;
      }
    }
    //copy the password to the client
    _tcscpy(g_RunPwd,g_Users[nUser].Password);
    //Enable use of empty passwords for network logon
    BOOL bEmptyPWAllowed=FALSE;
    if (g_RunPwd[0]==0)
    {
      bEmptyPWAllowed=EmptyPWAllowed;
      AllowEmptyPW(TRUE);
    }
    //Add user to admins group
    AlterGroupMember(DOMAIN_ALIAS_RID_ADMINS,g_Users[nUser].UserName,1);
    //Give Password to the calling process
    GivePassword();
    //Reset status of "use of empty passwords for network logon"
    if (g_RunPwd[0]==0)
      AllowEmptyPW(bEmptyPWAllowed);
    //Remove user from Administrators group
    AlterGroupMember(DOMAIN_ALIAS_RID_ADMINS,g_Users[nUser].UserName,0);
    //Mark last start time
    GetSystemTimeAsFileTime((LPFILETIME)&g_Users[nUser].LastAskTime);
    return;
  }
  GivePassword();
}

//////////////////////////////////////////////////////////////////////////////
// 
//  InstallRegistry
// 
//////////////////////////////////////////////////////////////////////////////
#define UNINSTL L"Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\SuRun"

#define SHLRUN  L"\\Shell\\SuRun"
#define EXERUN  L"exefile" SHLRUN
#define CMDRUN  L"cmdfile" SHLRUN
#define CPLRUN  L"cplfile" SHLRUN
#define MSCRUN  L"mscfile" SHLRUN
#define BATRUN  L"batfile" SHLRUN
#define MSIPTCH L"Msi.Patch" SHLRUN
#define MSIPKG  L"Msi.Package" SHLRUN

void InstallRegistry()
{
  TCHAR SuRunExe[4096];
  GetSystemWindowsDirectory(SuRunExe,4096);
  PathAppend(SuRunExe,L"SuRun.exe");
  PathQuoteSpaces(SuRunExe);
  CResStr MenuStr(IDS_MENUSTR);
  CBigResStr DefCmd(L"%s \"%%1\" %%*",SuRunExe);
  //UnInstall
  SetRegStr(HKLM,UNINSTL,L"DisplayName",L"Super User run (SuRun)");
  SetRegStr(HKLM,UNINSTL,L"UninstallString",CBigResStr(L"%s /UNINSTALL",SuRunExe,SuRunExe));
  //AutoRun, System Menu Hook
  SetRegStr(HKLM,L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
    CResStr(IDS_SYSMENUEXT),CBigResStr(L"%s /SYSMENUHOOK",SuRunExe));
  //exefile
  SetRegStr(HKCR,EXERUN,L"",MenuStr);
  SetRegStr(HKCR,EXERUN L"\\command",L"",DefCmd);
  //cmdfile
  SetRegStr(HKCR,CMDRUN,L"",MenuStr);
  SetRegStr(HKCR,CMDRUN L"\\command",L"",DefCmd);
  //cplfile
  SetRegStr(HKCR,CPLRUN,L"",MenuStr);
  SetRegStr(HKCR,CPLRUN L"\\command",L"",DefCmd);
  //MSCFile
  SetRegStr(HKCR,MSCRUN,L"",MenuStr);
  SetRegStr(HKCR,MSCRUN L"\\command",L"",DefCmd);
  //batfile
  SetRegStr(HKCR,BATRUN,L"",MenuStr);
  SetRegStr(HKCR,BATRUN L"\\command",L"",DefCmd);
  TCHAR MSIExe[4096];
  GetSystemDirectory(MSIExe,4096);
  PathAppend(MSIExe,L"msiexec.exe");
  PathQuoteSpaces(MSIExe);
  //MSI Install
  SetRegStr(HKCR,MSIPKG L" open",L"",CResStr(IDS_SURUNINST));
  SetRegStr(HKCR,MSIPKG L" open\\command",L"",CBigResStr(L"%s %s /i \"%%1\" %%*",SuRunExe,MSIExe));
  //MSI Repair
  SetRegStr(HKCR,MSIPKG L" repair",L"",CResStr(IDS_SURUNREPAIR));
  SetRegStr(HKCR,MSIPKG L" repair\\command",L"",CBigResStr(L"%s %s /f \"%%1\" %%*",SuRunExe,MSIExe));
  //MSI Uninstall
  SetRegStr(HKCR,MSIPKG L" Uninstall",L"",CResStr(IDS_SURUNUNINST));
  SetRegStr(HKCR,MSIPKG L" Uninstall\\command",L"",CBigResStr(L"%s %s /x \"%%1\" %%*",SuRunExe,MSIExe));
  //MSP Apply
  SetRegStr(HKCR,MSIPTCH L" open",L"",MenuStr);
  SetRegStr(HKCR,MSIPTCH L" open\\command",L"",CBigResStr(L"%s %s /p \"%%1\" %%*",SuRunExe,MSIExe));
}

//////////////////////////////////////////////////////////////////////////////
// 
//  RemoveRegistry
// 
//////////////////////////////////////////////////////////////////////////////
void RemoveRegistry()
{
  //exefile
  DelRegKey(HKCR,EXERUN);
  //cmdfile
  DelRegKey(HKCR,CMDRUN);
  //cplfile
  DelRegKey(HKCR,CPLRUN);
  //MSCFile
  DelRegKey(HKCR,MSCRUN);
  //batfile
  DelRegKey(HKCR,BATRUN);
  //MSI Install
  DelRegKey(HKCR,MSIPKG L" open");
  //MSI Repair
  DelRegKey(HKCR,MSIPKG L" repair");
  //MSI Uninstall
  DelRegKey(HKCR,MSIPKG L" Uninstall");
  //AutoRun, System Menu Hook
  RegDelVal(HKLM,L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",CResStr(IDS_SYSMENUEXT));
  //UnInstall
  DelRegKey(HKLM,UNINSTL);
}

//////////////////////////////////////////////////////////////////////////////
// 
//  Service control helpers
// 
//////////////////////////////////////////////////////////////////////////////

#define WaitFor(a) \
    for (int i=0;i<30;i++)\
    {\
      Sleep(750);\
      if (a)\
        return TRUE; \
    } \
    return a;


BOOL RunThisAsAdmin(LPCTSTR cmd,DWORD WaitStat,int nResId)
{
  TCHAR ModName[MAX_PATH];
  TCHAR cmdLine[4096];
  GetModuleFileName(NULL,ModName,MAX_PATH);
  NetworkPathToUNCPath(ModName);
  PathQuoteSpaces(ModName);
  if (CheckServiceStatus()==SERVICE_RUNNING)
  {
    TCHAR SvcFile[4096];
    GetSystemWindowsDirectory(SvcFile,4096);
    PathAppend(SvcFile,_T("SuRun.exe"));
    PathQuoteSpaces(SvcFile);
    _stprintf(cmdLine,_T("%s %s %s"),SvcFile,ModName,cmd);
    STARTUPINFO si={0};
    PROCESS_INFORMATION pi;
    si.cb = sizeof(si);
    if (CreateProcess(NULL,cmdLine,NULL,NULL,FALSE,0,NULL,NULL,&si,&pi))
    {
      CloseHandle(pi.hProcess);
      CloseHandle(pi.hThread);
      WaitFor(CheckServiceStatus()==WaitStat);
    }
  }
  _stprintf(cmdLine,_T("%s %s"),ModName,cmd);
  if (!RunAsAdmin(cmdLine,nResId))
    return FALSE;
  WaitFor(CheckServiceStatus()==WaitStat);
}

void DelFile(LPCTSTR File)
{
  if (PathFileExists(File) && (!DeleteFile(File)))
  {
    CBigResStr tmp(_T("%s.tmp"),File);
    while (_trename(File,tmp))
      _tcscat(tmp,L".tmp");
    MoveFileEx(tmp,NULL,MOVEFILE_DELAY_UNTIL_REBOOT); 
  }
}

void CopyToWinDir(LPCTSTR File)
{
  TCHAR DstFile[4096];
  TCHAR SrcFile[4096];
  GetModuleFileName(NULL,SrcFile,MAX_PATH);
  NetworkPathToUNCPath(SrcFile);
  PathRemoveFileSpec(SrcFile);
  PathAppend(SrcFile,File);
  GetSystemWindowsDirectory(DstFile,4096);
  PathAppend(DstFile,File);
  DelFile(DstFile);
  CopyFile(SrcFile,DstFile,FALSE);
}

BOOL DeleteService(BOOL bJustStop=FALSE)
{
  if (!IsAdmin())
    return RunThisAsAdmin(_T("/UNINSTALL"),0,IDS_UNINSTALLADMIN);
  CBlurredScreen cbs;
  if(!bJustStop)
  {
    cbs.Init();
    cbs.Show();
  }
  if ((!bJustStop)
    &&(MessageBox(0,CBigResStr(IDS_ASKUNINST),CResStr(IDS_APPNAME),
                  MB_ICONQUESTION|MB_YESNO|MB_DEFBUTTON2|MB_SETFOREGROUND)==IDNO))
    return false;
  if(!bJustStop)
    cbs.MsgLoop();
  BOOL bRet=FALSE;
  SC_HANDLE hdlSCM = OpenSCManager(0,0,SC_MANAGER_CONNECT);
  if (hdlSCM) 
  {
    SC_HANDLE hdlServ=OpenService(hdlSCM,SvcName,SERVICE_STOP|DELETE);
    if (hdlServ)
    {
      SERVICE_STATUS ss;
      ControlService(hdlServ,SERVICE_CONTROL_STOP,&ss);
      DeleteService(hdlServ);
      CloseServiceHandle(hdlServ);
      bRet=TRUE;
    }
  }
  for (int n=0;CheckServiceStatus() && (n<100);n++)
    Sleep(100);
  //Shell Extension
  RemoveShellExt();
  //Registry
  RemoveRegistry();
  //Delete Files and directories
  TCHAR File[4096];
  GetSystemWindowsDirectory(File,4096);
  PathAppend(File,_T("SuRun.exe"));
  DelFile(File);
  GetSystemWindowsDirectory(File,4096);
  PathAppend(File,_T("SuRunExt.dll"));
  DelFile(File);
#ifdef _WIN64
  GetSystemWindowsDirectory(File,4096);
  PathAppend(File,_T("SuRun32.bin"));
  DelFile(File);
  GetSystemWindowsDirectory(File,4096);
  PathAppend(File,_T("SuRunExt32.dll"));
  DelFile(File);
#endif _WIN64
  TCHAR file[4096];
  GetRegStr(HKLM,L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders",
    L"Common Programs",file,4096);
  ExpandEnvironmentStrings(file,File,4096);
  PathAppend(File,CResStr(IDS_STARTMENUDIR));
  DeleteDirectory(File);
  if (bJustStop)
    return TRUE;
  DelRegKey(HKLM,SVCKEY);
  //Ok!
  MessageBox(0,CBigResStr(IDS_UNINSTREBOOT),CResStr(IDS_APPNAME),
    MB_ICONINFORMATION|MB_SETFOREGROUND);
  return bRet;
}

BOOL InstallService()
{
  if (!IsAdmin())
    return RunThisAsAdmin(_T("/INSTALL"),SERVICE_RUNNING,IDS_INSTALLADMIN);
  if (CheckServiceStatus())
  {
    if (!DeleteService(true))
      return FALSE;
    //Wait until "SuRun /SYSMENUHOOK" has exited:
    Sleep(2000);
  }
  SC_HANDLE hdlSCM=OpenSCManager(0,0,SC_MANAGER_CREATE_SERVICE);
  if (hdlSCM==0) 
    return FALSE;
  CopyToWinDir(_T("SuRun.exe"));
  CopyToWinDir(_T("SuRunExt.dll"));
#ifdef _WIN64
  CopyToWinDir(_T("SuRun32.bin"));
  CopyToWinDir(_T("SuRunExt32.dll"));
#endif _WIN64
  TCHAR SvcFile[4096];
  GetSystemWindowsDirectory(SvcFile,4096);
  PathAppend(SvcFile,_T("SuRun.exe"));
  PathQuoteSpaces(SvcFile);
  _tcscat(SvcFile,_T(" /ServiceRun"));
  SC_HANDLE hdlServ = CreateService(hdlSCM,SvcName,SvcName,STANDARD_RIGHTS_REQUIRED,
                          SERVICE_WIN32_OWN_PROCESS,SERVICE_AUTO_START,
                          SERVICE_ERROR_NORMAL,SvcFile,0,0,0,0,0);
  if (!hdlServ) 
    return CloseServiceHandle(hdlSCM),FALSE;
  CloseServiceHandle(hdlServ);
  hdlServ = OpenService(hdlSCM,SvcName,SERVICE_START);
  BOOL bRet=StartService(hdlServ,0,0);
  if (!bRet)
  {
    CloseServiceHandle(hdlServ);
    hdlServ=OpenService(hdlSCM,SvcName,SERVICE_STOP|DELETE);
    if (hdlServ)
      DeleteService(hdlServ);
  }
  CloseServiceHandle(hdlServ);
  CloseServiceHandle(hdlSCM);
  if (bRet)
  {
    //Registry
    InstallRegistry();
    //Shell Extension
    InstallShellExt();
    //"SuDuers" Group
    CreateSuRunnersGroup();
    //Install Start menu Links
    CoInitialize(0);
    TCHAR lnk[4096]={0};
    TCHAR file[4096]={0};
    GetRegStr(HKLM,L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders",
      L"Common Programs",file,4096);
    ExpandEnvironmentStrings(file,lnk,4096);
    PathAppend(lnk,CResStr(IDS_STARTMENUDIR));
    CreateDirectory(lnk,0); 
    PathAppend(lnk,CResStr(IDS_STARTMNUCFG));
    GetSystemWindowsDirectory(file,4096);
    PathAppend(file,L"SuRun.exe /SETUP");
    CreateLink(file,lnk,2);
    PathRemoveFileSpec(lnk);
    PathAppend(lnk,CResStr(IDS_STARTMUNINST));
    GetSystemWindowsDirectory(file,4096);
    PathAppend(file,L"SuRun.exe");
    PathQuoteSpaces(file);
    _tcscat(file,L" /UNINSTALL");
    CreateLink(file,lnk,1);
    CoUninitialize();
    WaitFor(CheckServiceStatus()==SERVICE_RUNNING);
  }
  return bRet;
}

BOOL UserInstall(int IDSMsg)
{
  if (!IsAdmin())
    return RunThisAsAdmin(_T("/USERINST"),SERVICE_RUNNING,IDS_INSTALLADMIN);
  CBlurredScreen cbs;
  cbs.Init();
  cbs.Show();
  if (MessageBox(0,CBigResStr(IDSMsg),CResStr(IDS_APPNAME),
    MB_ICONQUESTION|MB_YESNO|MB_DEFBUTTON2|MB_SETFOREGROUND)!=IDYES)
    return FALSE;
  cbs.MsgLoop();
  if (!InstallService())
    return FALSE;
  TCHAR SuRunExe[4096];
  GetSystemWindowsDirectory(SuRunExe,4096);
  PathAppend(SuRunExe,L"SuRun.exe");
  //This mostly does not work...
  //ShellExecute(0,L"open",SuRunExe,L"/SYSMENUHOOK",0,SW_HIDE);
  if (MessageBox(0,CBigResStr(IDS_INSTALLOK),CResStr(IDS_APPNAME),
    MB_ICONQUESTION|MB_YESNO|MB_SETFOREGROUND)==IDYES)
    ShellExecute(0,L"open",SuRunExe,L"/SETUP",0,SW_SHOWNORMAL);
  return TRUE;
}

//////////////////////////////////////////////////////////////////////////////
// 
// HandleServiceStuff: called on App Entry before WinMain()
// 
//////////////////////////////////////////////////////////////////////////////
bool HandleServiceStuff()
{
  INITCOMMONCONTROLSEX icce={sizeof(icce),ICC_USEREX_CLASSES|ICC_WIN95_CLASSES};
  InitCommonControlsEx(&icce);
#ifdef _DEBUG_ENU
  SetThreadLocale(MAKELCID(MAKELANGID(LANG_ENGLISH,SUBLANG_ENGLISH_US),SORT_DEFAULT));
#endif _DEBUG_ENU
  CCmdLine cmd;
  if ((cmd.argc()==3)&&(_tcsicmp(cmd.argv(1),_T("/AskPID"))==0))
  {
    SuRun(wcstol(cmd.argv(2),0,10));
    //clean sensitive Data
    zero(g_Users);
    zero(g_RunPwd);
    ExitProcess(0);
  }else
  if (cmd.argc()==2)
  {
    //Service
    if (_tcsicmp(cmd.argv(1),_T("/SERVICERUN"))==0)
    {
      if (!IsLocalSystem())
        return false;
      SERVICE_TABLE_ENTRY DispatchTable[]={{SvcName,ServiceMain},{0,0}};
      //StartServiceCtrlDispatcher is a blocking call
      StartServiceCtrlDispatcher(DispatchTable);
      ExitProcess(0);
      return true;
    }
    //System Menu Hook: This is AutoRun for every user
    if (_tcsicmp(cmd.argv(1),_T("/SYSMENUHOOK"))==0)
    {
      for(int i=0;(i<30)&&(CheckServiceStatus()!=SERVICE_RUNNING);i++)
        Sleep(1000);
      InstallSysMenuHook();
#ifdef _WIN64
      {
        TCHAR SuRun32Exe[4096];
        GetSystemWindowsDirectory(SuRun32Exe,4096);
        PathAppend(SuRun32Exe,L"SuRun32.bin /SYSMENUHOOK");
        STARTUPINFO si={0};
        PROCESS_INFORMATION pi;
        si.cb = sizeof(si);
        if (CreateProcess(NULL,SuRun32Exe,NULL,NULL,FALSE,0,NULL,NULL,&si,&pi))
        {
          CloseHandle(pi.hProcess);
          CloseHandle(pi.hThread);
        }
      }
#endif _WIN64
      while (CheckServiceStatus()==SERVICE_RUNNING)
      	Sleep(1000);
      UninstallSysMenuHook();
      ExitProcess(0);
      return true;
    }
    //Install
    if (_tcsicmp(cmd.argv(1),_T("/INSTALL"))==0)
    {
      InstallService();
      ExitProcess(0);
      return true;
    }
    //UnInstall
    if (_tcsicmp(cmd.argv(1),_T("/UNINSTALL"))==0)
    {
      DeleteService();
      ExitProcess(0);
      return true;
    }
    //UserInst:
    if (_tcsicmp(cmd.argv(1),_T("/USERINST"))==0)
    {
      UserInstall(IDS_ASKUSRINSTALL);
      ExitProcess(0);
      return true;
    }
  }
  //Are we run from the Windows directory?, if Not, ask for Install/update
  {
    TCHAR fn[4096];
    TCHAR wd[4096];
    GetModuleFileName(NULL,fn,MAX_PATH);
    NetworkPathToUNCPath(fn);
    PathRemoveFileSpec(fn);
    PathRemoveBackslash(fn);
    GetSystemWindowsDirectory(wd,4096);
    PathRemoveBackslash(wd);
    if(_tcsicmp(fn,wd))
    {
      DBGTrace2("Running from \"%s\" and NOT from WinDir(\"%s\")",fn,wd);
      UserInstall(IDS_ASKUSRINSTALL);
      ExitProcess(0);
      return true;
    }
  }
  //The Service must be running!
  DWORD ServiceStatus=CheckServiceStatus();
  while(ServiceStatus!=SERVICE_RUNNING)
  {
    if (!UserInstall(IDS_ASKINSTALL))
      ExitProcess(0);
    if (cmd.argc()==1)
      ExitProcess(0);
    ServiceStatus=CheckServiceStatus();
  }
  return false;
}

//////////////////////////////////////////////////////////////////////////////
// 
// The Trick: 
//  The statement below will call HandleServiceStuff() before WinMain.
//  if our process runs as service, WinMain will never get called
//  since HandleServiceStuff will call ExitProcess()
//////////////////////////////////////////////////////////////////////////////

//To make DialogBoxParam and MessageBox work with Themes:
HANDLE g_hShell32=LoadLibrary(_T("Shell32.dll"));
static bool g_IsServiceStuff=HandleServiceStuff();
