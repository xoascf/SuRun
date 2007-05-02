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
#pragma comment(lib,"SuRunExt/ReleaseU/SuRunExt.lib")
#else _DEBUG
#pragma comment(lib,"SuRunExt/DebugU/SuRunExt.lib")
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

static USERDATA g_Users[16]={0};    //Tokens for the last 16 Users are cached

//////////////////////////////////////////////////////////////////////////////
// 
//  Globals
// 
//////////////////////////////////////////////////////////////////////////////

#define Radio1chk (g_AskAlways!=0)
#define Radio2chk ((g_AskAlways==0)&&(g_NoAskTimeOut!=0))

#define HKLM    HKEY_LOCAL_MACHINE
#define SVCKEY  _T("SECURITY\\SuRun")
#define PWKEY   _T("SECURITY\\SuRun\\Cache")

BYTE KEYPASS[16]={0x5B,0xC3,0x25,0xE9,0x8F,0x2A,0x41,0x10,0xA3,0xF4,0x26,0xD1,0x62,0xB4,0x0A,0xE2};

static SERVICE_STATUS_HANDLE g_hSS=0;
static SERVICE_STATUS g_ss= {0};
static HANDLE g_hPipe=INVALID_HANDLE_VALUE;

CResStr SvcName(IDS_SERVICE_NAME);

RUNDATA g_RunData={0};
TCHAR g_RunPwd[PWLEN];

//FILETIME(100ns) to minutes multiplier
#define ft2min  (__int64)(10/*1µs*/*1000/*1ms*/*1000/*1s*/*60/*1min*/)

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
  if ((!g_bSavePW)||(g_Users[n].Password[0]==0))
    return;
  CBlowFish bf;
  TCHAR Password[PWLEN]={0};
  bf.Initialize(KEYPASS,sizeof(KEYPASS));
  SetRegAny(HKLM,PWKEY,g_Users[n].UserName,REG_BINARY,(BYTE*)Password,
    bf.Encode((BYTE*)g_Users[n].Password,(BYTE*)Password,
              _tcslen(g_Users[n].Password)*sizeof(TCHAR)));
}

void SavePasswords()
{
  DelRegKey(HKLM,PWKEY);
  for (int i=0;i<countof(g_Users);i++) 
    SavePassword(i);
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
  DWORD n;
  //Check if the calling process is this Executable:
  HMODULE hMod;
  TCHAR f1[MAX_PATH];
  TCHAR f2[MAX_PATH];
  if (!GetModuleFileName(0,f1,MAX_PATH))
  {
    DBGTrace1("GetModuleFileName failed: %s",GetLastErrorNameStatic());
    return CloseHandle(hProcess),0;
  }
  if(!EnumProcessModules(hProcess,&hMod,sizeof(hMod),&n))
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
  if (!ReadProcessMemory(hProcess,&g_RunData,&g_RunData,sizeof(RUNDATA),&n))
  {
    DBGTrace1("ReadProcessMemory failed: %s",GetLastErrorNameStatic());
    return CloseHandle(hProcess),0;
  }
  if (sizeof(RUNDATA)!=n)
  {
    DBGTrace2("ReadProcessMemory invalid size %d != %d ",sizeof(RUNDATA),n);
    return CloseHandle(hProcess),0;
  }
  if (memcmp(&rd,&g_RunData,sizeof(RUNDATA))!=0)
  {
    DBGTrace("RunData is different!");
    return CloseHandle(hProcess),1;
  }
  return CloseHandle(hProcess),2;
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
              GetWindowsDirectory(cmd,4096);
              PathAppend(cmd,L"SuRun.exe /AskPID ");
              TCHAR PID[10];
              _tcscat(cmd,_itot(g_RunData.CliProcessId,PID,10));
              EnablePrivilege(SE_ASSIGNPRIMARYTOKEN_NAME);
              EnablePrivilege(SE_INCREASE_QUOTA_NAME);
              if (CreateProcessAsUser(hRun,NULL,cmd,NULL,NULL,FALSE,
                          CREATE_UNICODE_ENVIRONMENT,0,NULL,&si,&pi))
              {
                CloseHandle(pi.hProcess);
                CloseHandle(pi.hThread);
              }
            }
            CloseHandle(hRun);
          }
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
  DWORD n;
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
    return TRUE;
  if (IsInGroup(DOMAIN_ALIAS_RID_ADMINS,UserName))
  {
    if(MessageBox(0,CBigResStr(IDS_ASKSURUNNER),CResStr(IDS_APPNAME),
      MB_YESNO|MB_DEFBUTTON2|MB_ICONQUESTION)==IDNO)
      return FALSE;
    if ((AlterGroupMember(DOMAIN_ALIAS_RID_ADMINS,UserName,0)!=0)
      ||(AlterGroupMember(SURUNNERSGROUP,UserName,1)!=0))
    {
      MessageBox(0,CBigResStr(IDS_SURUNNER_ERR),CResStr(IDS_APPNAME),MB_ICONSTOP);
      return FALSE;
    }
    MessageBox(0,CBigResStr(IDS_LOGOFFON),CResStr(IDS_APPNAME),MB_ICONINFORMATION);
    return TRUE;
  }
  TCHAR U[UNLEN+GNLEN]={0};
  TCHAR P[PWLEN]={0};
  if (!LogonAdmin(U,P,IDS_NOSURUNNER))
    return FALSE;
  if (AlterGroupMember(SURUNNERSGROUP,UserName,1)!=0)
  {
    MessageBox(0,CBigResStr(IDS_SURUNNER_ERR),CResStr(IDS_APPNAME),MB_ICONSTOP);
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

INT_PTR CALLBACK SetupDlgProc(HWND hwnd,UINT msg,WPARAM wParam,LPARAM lParam)
{
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
      CheckDlgButton(hwnd,IDC_RADIO1,(Radio1chk?BST_CHECKED:BST_UNCHECKED));
      CheckDlgButton(hwnd,IDC_RADIO2,(Radio2chk?BST_CHECKED:BST_UNCHECKED));
      SendDlgItemMessage(hwnd,IDC_ASKTIMEOUT,EM_LIMITTEXT,2,0);
      SetDlgItemInt(hwnd,IDC_ASKTIMEOUT,g_NoAskTimeOut,0);
      CheckDlgButton(hwnd,IDC_BLURDESKTOP,(g_BlurDesktop?BST_CHECKED:BST_UNCHECKED));
      CheckDlgButton(hwnd,IDC_SAVEPW,(g_bSavePW?BST_CHECKED:BST_UNCHECKED));
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
        return (BOOL)GetStockObject(WHITE_BRUSH);
      }
      break;
    }
  case WM_COMMAND:
    {
      switch (wParam)
      {
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
          EndDialog(hwnd,1);
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
  //Every "secure" Desktop has its own UUID as name:
  UUID uid;
  UuidCreate(&uid);
  LPTSTR DeskName=0;
  UuidToString(&uid,&DeskName);
  //Create the new desktop
  CRunOnNewDeskTop crond(WinStaName,DeskName,g_BlurDesktop);
  RpcStringFree(&DeskName);
  return DialogBox(GetModuleHandle(0),MAKEINTRESOURCE(IDD_SETUP),0,SetupDlgProc)>=0;
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
    bDoAsk=TRUE;
  else 
    if ((!PasswordOK(g_Users[nUser].UserName,g_Users[nUser].Password))
      ||(!IsInSuRunners(g_RunData.UserName)))
  {
    nUser=-1;
    bDoAsk=TRUE;
  }
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
  RpcStringFree(&DeskName);
  if (crond.IsValid())
  {
    //secure desktop created...
    if(nUser!=-1)
    {
      if(!AskCurrentUserOk(g_RunData.UserName,IDS_ASKOK,g_RunData.cmdLine))
        return -1;
      return nUser;
    }
    if (!CheckGroupMembership(g_RunData.UserName))
      return -1;
    TCHAR Password[MAX_PATH]={0};
    BOOL bLogon=LogonCurrentUser(g_RunData.UserName,Password,IDS_ASKOK,g_RunData.cmdLine);
    if(bLogon)
    {
      DBGTrace2("DialogBoxParam returned %d: %s",bLogon,GetLastErrorNameStatic());
      __int64 minTime=0;
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
  }else //FATAL: secure desktop could not be created!
    MessageBox(0,CBigResStr(IDS_NODESK),CResStr(IDS_APPNAME),MB_SERVICE_NOTIFICATION);
  return -1;
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
    _tcscpy(g_RunPwd,g_Users[nUser].Password);
    //Add user to admins group
    AlterGroupMember(DOMAIN_ALIAS_RID_ADMINS,g_Users[nUser].UserName,1);
    //Give Password to the calling process
    GivePassword();
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
#define HKCR HKEY_CLASSES_ROOT
#define HKLM HKEY_LOCAL_MACHINE

#define UNINSTL L"Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\SuRun"

#define SHLRUN  L"\\Shell\\SuRun"
#define EXERUN  L"exefile" SHLRUN
#define CMDRUN  L"cmdfile" SHLRUN
#define CPLRUN  L"cplfile" SHLRUN
#define MSCRUN  L"mscfile" SHLRUN
#define BATRUN  L"batfile" SHLRUN
#define MSIPKG  L"Msi.Package" SHLRUN

void InstallRegistry()
{
  TCHAR SuRunExe[4096];
  GetWindowsDirectory(SuRunExe,4096);
  PathAppend(SuRunExe,L"SuRun.exe");
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
  //MSI Install
  SetRegStr(HKCR,MSIPKG L" open",L"",CResStr(IDS_SURUNINST));
  SetRegStr(HKCR,MSIPKG L" open\\command",L"",CBigResStr(L"%s /i \"%%1\" %%*",SuRunExe));
  //MSI Repair
  SetRegStr(HKCR,MSIPKG L" repair",L"",CResStr(IDS_SURUNREPAIR));
  SetRegStr(HKCR,MSIPKG L" repair\\command",L"",CBigResStr(L"%s /f \"%%1\" %%*",SuRunExe));
  //MSI Uninstall
  SetRegStr(HKCR,MSIPKG L" Uninstall",L"",CResStr(IDS_SURUNUNINST));
  SetRegStr(HKCR,MSIPKG L" Uninstall\\command",L"",CBigResStr(L"%s /x \"%%1\" %%*",SuRunExe));
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


DWORD CheckServiceStatus()
{
  SC_HANDLE hdlSCM=OpenSCManager(0,0,SC_MANAGER_CONNECT|SC_MANAGER_ENUMERATE_SERVICE);
  if (hdlSCM==0) 
    return FALSE;
  SC_HANDLE hdlServ = OpenService(hdlSCM,SvcName,SERVICE_QUERY_STATUS);
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
    GetWindowsDirectory(SvcFile,4096);
    PathAppend(SvcFile,_T("SuRun.exe"));
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
  GetWindowsDirectory(DstFile,4096);
  PathAppend(DstFile,File);
  DelFile(DstFile);
  CopyFile(SrcFile,DstFile,FALSE);
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
  TCHAR SvcFile[4096];
  GetWindowsDirectory(SvcFile,4096);
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
    //InstallShellExt();
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
    GetWindowsDirectory(file,4096);
    PathAppend(file,L"SuRun.exe /SETUP");
    CreateLink(file,lnk,3);
    PathRemoveFileSpec(lnk);
    PathAppend(lnk,CResStr(IDS_STARTMUNINST));
    GetWindowsDirectory(file,4096);
    PathAppend(file,L"SuRun.exe /UNINSTALL");
    CreateLink(file,lnk,1);
    CoUninitialize();
    WaitFor(CheckServiceStatus()==SERVICE_RUNNING);
  }
  return bRet;
}

BOOL DeleteService(BOOL bJustStop/*=FALSE*/)
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
  //RemoveShellExt();
  //Registry
  RemoveRegistry();
  //Delete Files and directories
  TCHAR File[4096];
  GetWindowsDirectory(File,4096);
  PathAppend(File,_T("SuRun.exe"));
  DelFile(File);
  GetWindowsDirectory(File,4096);
  PathAppend(File,_T("SuRunExt.dll"));
  DelFile(File);
  TCHAR file[4096];
  GetRegStr(HKLM,L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders",
    L"Common Programs",file,4096);
  ExpandEnvironmentStrings(file,File,4096);
  PathAppend(File,CResStr(IDS_STARTMENUDIR));
  DeleteDirectory(File);
  if (bJustStop)
    return TRUE;
  //Ok!
  MessageBox(0,CBigResStr(IDS_UNINSTREBOOT),CResStr(IDS_APPNAME),
    MB_ICONINFORMATION|MB_SETFOREGROUND);
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
  GetWindowsDirectory(SuRunExe,4096);
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
  DWORD ServiceStatus=0;
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
  //The Service must be running!
  ServiceStatus=CheckServiceStatus();
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

