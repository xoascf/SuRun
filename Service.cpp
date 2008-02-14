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

// This is the main file for the SuRun service. This file handles:
// -SuRun Installation
// -SuRun Uninstallation
// -the Windows Service
// -putting the user to the SuRunners group
// -Terminating a Process for "Restart as admin..."
// -requesting permission/password in the logon session of the user
// -putting the users password to the user process via WriteProcessMemory

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
#include "Setup.h"
#include "Service.h"
#include "IsAdmin.h"
#include "CmdLine.h"
#include "WinStaDesk.h"
#include "ResStr.h"
#include "LogonDlg.h"
#include "UserGroups.h"
#include "ReqAdmin.h"
#include "Helpers.h"
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
//  Globals
// 
//////////////////////////////////////////////////////////////////////////////

static SERVICE_STATUS_HANDLE g_hSS=0;
static SERVICE_STATUS g_ss= {0};
static HANDLE g_hPipe=INVALID_HANDLE_VALUE;

CResStr SvcName(IDS_SERVICE_NAME);

RUNDATA g_RunData={0};
TCHAR g_RunPwd[PWLEN]={0};
int g_RetVal=0;
bool g_CliIsAdmin=FALSE;

//////////////////////////////////////////////////////////////////////////////
// 
// CheckCliProcess:
// 
// checks if rd.CliProcessId is this exe and if rd is g_RunData of the calling
// process equals rd, copies the clients g_RunData to our g_RunData
//////////////////////////////////////////////////////////////////////////////
DWORD CheckCliProcess(RUNDATA& rd)
{
  g_CliIsAdmin=FALSE;
  if (rd.CliProcessId==GetCurrentProcessId())
    return 0;
  HANDLE hProcess=OpenProcess(PROCESS_ALL_ACCESS,FALSE,rd.CliProcessId);
  if (!hProcess)
  {
    DBGTrace1("OpenProcess failed: %s",GetLastErrorNameStatic());
    return 0;
  }
  HANDLE hTok=NULL;
  HANDLE hThread=OpenThread(THREAD_ALL_ACCESS,FALSE,rd.CliThreadId);
  if (hThread)
  {
    OpenThreadToken(hThread,TOKEN_DUPLICATE,FALSE,&hTok);
    CloseHandle(hThread);
  }
  if ((!hTok) &&(!OpenProcessToken(hProcess,TOKEN_DUPLICATE,&hTok)))
  {
    DBGTrace1("OpenProcessToken failed: %s",GetLastErrorNameStatic());
    return 0;
  }
  g_CliIsAdmin=IsAdmin(hTok)!=0;
  CloseHandle(hTok);
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

//////////////////////////////////////////////////////////////////////////////
// 
//  ResumeClient
// 
//////////////////////////////////////////////////////////////////////////////
BOOL ResumeClient(int RetVal) 
{
  HANDLE hProcess=OpenProcess(PROCESS_ALL_ACCESS,FALSE,g_RunData.CliProcessId);
  if (!hProcess)
  {
    DBGTrace1("OpenProcess failed: %s",GetLastErrorNameStatic());
    return FALSE;
  }
  SIZE_T n;
  //Since it's the same process, g_RetVal has the same address!
  if (!WriteProcessMemory(hProcess,&g_RetVal,&RetVal,sizeof(int),&n))
  {
    DBGTrace1("WriteProcessMemory failed: %s",GetLastErrorNameStatic());
    return CloseHandle(hProcess),FALSE;
  }
  if (sizeof(int)!=n)
  {
    DBGTrace2("WriteProcessMemory invalid size %d != %d ",PWLEN,n);
    return CloseHandle(hProcess),FALSE;
  }
  WaitForSingleObject(hProcess,15000);
  return CloseHandle(hProcess),TRUE;
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
        DWORD wlf=GetWhiteListFlags(g_RunData.UserName,g_RunData.cmdLine,0);
        //check if the requested App is Flagged with AutoCancel
        if (wlf&FLAG_AUTOCANCEL)
        {
          //Access denied!
          ResumeClient((g_RunData.bShlExHook)?RETVAL_SX_NOTINLIST:RETVAL_ACCESSDENIED);
          DBGTrace2("ShellExecute AutoCancel WhiteList MATCH: %s: %s",g_RunData.UserName,g_RunData.cmdLine)
          continue;
        }
        //check if the requested App is in the ShellExecHook-Runlist
        if (g_RunData.bShlExHook)
        {
          if ((!(wlf&FLAG_SHELLEXEC))
            //check for requireAdministrator Manifest and
            //file names *setup*;*install*;*update*;*.msi;*.msc
            && (!RequiresAdmin(g_RunData.cmdLine)))
          {
            ResumeClient(RETVAL_SX_NOTINLIST);
            DBGTrace2("ShellExecute WhiteList MisMatch: %s: %s",g_RunData.UserName,g_RunData.cmdLine)
            continue;
          }
          DBGTrace2("ShellExecute WhiteList Match: %s: %s",g_RunData.UserName,g_RunData.cmdLine)
        }
        if  (GetRestrictApps(g_RunData.UserName) 
         && (_tcsicmp(g_RunData.cmdLine,_T("/SETUP"))!=0))
        {
          if (!(wlf&FLAG_NORESTRICT))
          {
            ResumeClient(g_RunData.bShlExHook?RETVAL_SX_NOTINLIST:RETVAL_RESTRICT);
            DBGTrace2("Restriction WhiteList MisMatch: %s: %s",g_RunData.UserName,g_RunData.cmdLine)
            continue;
          }
          DBGTrace2("Restriction WhiteList Match: %s: %s",g_RunData.UserName,g_RunData.cmdLine)
        }
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
                CloseHandle(pi.hThread);
                WaitForSingleObject(pi.hProcess,60000);
                CloseHandle(pi.hProcess);
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
//  PrepareSuRun: Show Password/Permission Dialog on secure Desktop,
// 
//////////////////////////////////////////////////////////////////////////////
BOOL PrepareSuRun()
{
  zero(g_RunPwd);
  //Do we have a Password for this user?
  if (GetSavePW &&(!PasswordExpired(g_RunData.UserName)))
      LoadPassword(g_RunData.UserName,g_RunPwd,sizeof(g_RunPwd));
  BOOL PwOk=PasswordOK(g_RunData.UserName,g_RunPwd);
#ifdef _DEBUG
  if (!PwOk)
    DBGTrace2("Password (%s) for %s is NOT ok!",g_RunPwd,g_RunData.UserName);
#endif _DEBUG
  if ((!PwOk)||(!IsInSuRunners(g_RunData.UserName)))
  //Password is NOT ok:
  {
    zero(g_RunPwd);
    DeletePassword(g_RunData.UserName);
    PwOk=FALSE;
  }else
  //Password is ok:
  //If SuRunner is already Admin, let him run the new process!
  if (g_CliIsAdmin || IsInWhiteList(g_RunData.UserName,g_RunData.cmdLine,FLAG_DONTASK))
    return UpdLastRunTime(g_RunData.UserName),TRUE;
  //Every "secure" Desktop has its own UUID as name:
  UUID uid;
  UuidCreate(&uid);
  LPTSTR DeskName=0;
  UuidToString(&uid,&DeskName);
  //Create the new desktop
  CRunOnNewDeskTop crond(g_RunData.WinSta,DeskName,GetBlurDesk);
  {
    CStayOnDeskTop csod(DeskName);
    RpcStringFree(&DeskName);
    if (crond.IsValid())
    {
      //secure desktop created...
      if (!BeOrBecomeSuRunner(g_RunData.UserName,TRUE))
        return FALSE;
      DWORD f=GetRegInt(HKLM,WHTLSTKEY(g_RunData.UserName),g_RunData.cmdLine,0);
      DWORD l=0;
      if (!PwOk)
      {
        l=LogonCurrentUser(g_RunData.UserName,g_RunPwd,f,g_RunData.bShlExHook?IDS_ASKAUTO:IDS_ASKOK,g_RunData.cmdLine);
        if (GetSavePW && (l&1))
          SavePassword(g_RunData.UserName,g_RunPwd);
      }else
        l=AskCurrentUserOk(g_RunData.UserName,f,g_RunData.bShlExHook?IDS_ASKAUTO:IDS_ASKOK,g_RunData.cmdLine);
      if((l&1)==0)
      {
        SetWhiteListFlag(g_RunData.UserName,g_RunData.cmdLine,FLAG_AUTOCANCEL,(l&2)!=0);
        if((l&2)!=0)
          SetWhiteListFlag(g_RunData.UserName,g_RunData.cmdLine,FLAG_DONTASK,0);
        return FALSE;
      }
      SetWhiteListFlag(g_RunData.UserName,g_RunData.cmdLine,FLAG_DONTASK,(l&2)!=0);
      if((l&2)!=0)
        SetWhiteListFlag(g_RunData.UserName,g_RunData.cmdLine,FLAG_AUTOCANCEL,0);
      SetWhiteListFlag(g_RunData.UserName,g_RunData.cmdLine,FLAG_SHELLEXEC,(l&4)!=0);
      return UpdLastRunTime(g_RunData.UserName),TRUE;
    }else //FATAL: secure desktop could not be created!
      MessageBox(0,CBigResStr(IDS_NODESK),CResStr(IDS_APPNAME),MB_ICONSTOP|MB_SERVICE_NOTIFICATION);
  }
  return FALSE;
}

//////////////////////////////////////////////////////////////////////////////
// 
//  CheckServiceStatus
// 
//////////////////////////////////////////////////////////////////////////////

DWORD CheckServiceStatus(LPCTSTR ServiceName=SvcName)
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

//////////////////////////////////////////////////////////////////////////////
// 
//  Setup
// 
//////////////////////////////////////////////////////////////////////////////

BOOL Setup(LPCTSTR WinStaName)
{
  //Every "secure" Desktop has its own UUID as name:
  UUID uid;
  UuidCreate(&uid);
  LPTSTR DeskName=0;
  UuidToString(&uid,&DeskName);
  //Create the new desktop
  CRunOnNewDeskTop crond(WinStaName,DeskName,GetBlurDesk);
  {
    CStayOnDeskTop csod(DeskName);
    RpcStringFree(&DeskName);
    if (!crond.IsValid())    
    {
      MessageBox(0,CBigResStr(IDS_NODESK),CResStr(IDS_APPNAME),MB_ICONSTOP|MB_SERVICE_NOTIFICATION);
      return FALSE;
    }
    //only Admins and SuRunners may setup SuRun
    if (g_CliIsAdmin)
      return RunSetup();
    if (GetNoRunSetup(g_RunData.UserName))
    {
      if(!LogonAdmin(IDS_NOADMIN2,g_RunData.UserName))
        return FALSE;
      else
        return RunSetup();
    }
    if (BeOrBecomeSuRunner(g_RunData.UserName,TRUE))
      return RunSetup();
  }
  return false;
}

//////////////////////////////////////////////////////////////////////////////
// 
//  StartAdminProcessTrampoline
// 
//////////////////////////////////////////////////////////////////////////////
DWORD StartAdminProcessTrampoline() 
{
  TCHAR cmd[4096]={0};
  GetSystemWindowsDirectory(cmd,4096);
  PathAppend(cmd,L"SuRun.exe");
  PathQuoteSpaces(cmd);
  DWORD RetVal=-1;
  HANDLE hUser=NULL;
  {
    HANDLE hToken=NULL;
    EnablePrivilege(SE_DEBUG_NAME);
    HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS,TRUE,g_RunData.CliProcessId);
    if (!hProc)
      return -1;
    // Open impersonation token for Shell process
    OpenProcessToken(hProc,TOKEN_IMPERSONATE|TOKEN_QUERY|TOKEN_DUPLICATE
      |TOKEN_ASSIGN_PRIMARY,&hToken);
    CloseHandle(hProc);
    if(!hToken)
      return -1;
    DuplicateTokenEx(hToken,MAXIMUM_ALLOWED,NULL,SecurityIdentification,
      TokenPrimary,&hUser); 
    CloseHandle(hToken);
    if(!hUser)
      return -1;
  }
  PROCESS_INFORMATION pi={0};
  TCHAR UserName[MAX_PATH]={0};
  PROFILEINFO ProfInf = {sizeof(ProfInf),0,UserName};
  if(GetTokenUserName(hUser,UserName) && LoadUserProfile(hUser,&ProfInf))
  {
    void* Env=0;
    if (CreateEnvironmentBlock(&Env,hUser,FALSE))
    {
      STARTUPINFO si={0};
      si.cb	= sizeof(si);
      //Do not inherit Desktop from calling process, use Tokens Desktop
      si.lpDesktop = _T("");
      //CreateProcessAsUser will only work from an NT System Account since the
      //Privilege SE_ASSIGNPRIMARYTOKEN_NAME is not present elsewhere
      EnablePrivilege(SE_ASSIGNPRIMARYTOKEN_NAME);
      EnablePrivilege(SE_INCREASE_QUOTA_NAME);
      if (CreateProcessAsUser(hUser,NULL,cmd,NULL,NULL,FALSE,
        CREATE_SUSPENDED|CREATE_UNICODE_ENVIRONMENT|DETACHED_PROCESS,Env,NULL,&si,&pi))
      {
        //Put g_RunData an g_RunPassword in!:
        SIZE_T n;
        //Since it's the same process, g_RunData and g_RunPwd have the same address!
        RUNDATA rd=g_RunData;
        rd.CliProcessId=pi.dwProcessId;
        rd.CliThreadId=pi.dwThreadId;
        rd.KillPID=0;
        if (!WriteProcessMemory(pi.hProcess,&g_RunData,&g_RunData,sizeof(RUNDATA),&n))
          TerminateProcess(pi.hProcess,0);
        else if (!WriteProcessMemory(pi.hProcess,&g_RunPwd,&g_RunPwd,PWLEN,&n))
          TerminateProcess(pi.hProcess,0);
        //Enable use of empty passwords for network logon
        BOOL bEmptyPWAllowed=FALSE;
        if (g_RunPwd[0]==0)
        {
          bEmptyPWAllowed=EmptyPWAllowed;
          AllowEmptyPW(TRUE);
        }
        //Add user to admins group
        AlterGroupMember(DOMAIN_ALIAS_RID_ADMINS,g_RunData.UserName,1);
        ResumeThread(pi.hThread);
        CloseHandle(pi.hThread);
        WaitForSingleObject(pi.hProcess,INFINITE);
        //Remove user from Administrators group
        AlterGroupMember(DOMAIN_ALIAS_RID_ADMINS,g_RunData.UserName,0);
        //Reset status of "use of empty passwords for network logon"
        if (g_RunPwd[0]==0)
          AllowEmptyPW(bEmptyPWAllowed);
        //Clear Password
        zero(g_RunPwd);
        GetExitCodeProcess(pi.hProcess,&RetVal);
        CloseHandle(pi.hProcess);
      }else
        RetVal=GetLastError();
      DestroyEnvironmentBlock(Env);
    }
    UnloadUserProfile(hUser,ProfInf.hProfile);
  }
  CloseHandle(hUser);
  return RetVal;
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
  RUNDATA RD={0};
  RD.CliProcessId=ProcessID;
  if(CheckCliProcess(RD)!=1)
    return;
  //Setup?
  if (_tcsicmp(g_RunData.cmdLine,_T("/SETUP"))==0)
  {
    ResumeClient(RETVAL_OK);
    Setup(g_RunData.WinSta);
    return;
  }
  KillProcess(g_RunData.KillPID);
  //Start execution
  if (!PrepareSuRun())
  {
    if ( g_RunData.bShlExHook
      &&(!IsInWhiteList(g_RunData.UserName,g_RunData.cmdLine,FLAG_SHELLEXEC)))
      ResumeClient(RETVAL_SX_NOTINLIST);//let ShellExecute start the process!
    else
      ResumeClient(RETVAL_ACCESSDENIED);
    return;
  }
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
      ResumeClient(RETVAL_ACCESSDENIED);
      MessageBox(0,CBigResStr(IDS_NOSECLOGON),CResStr(IDS_APPNAME),MB_ICONSTOP|MB_SERVICE_NOTIFICATION);
      return;
    }
  }
  //copy the password to the client
  StartAdminProcessTrampoline();
  //Clear Password
  zero(g_RunPwd);
  ResumeClient(RETVAL_OK);
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
#define REGRUN  L"regfile" SHLRUN

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
  //regfile
  SetRegStr(HKCR,REGRUN,L"",MenuStr);
  SetRegStr(HKCR,REGRUN L"\\command",L"",DefCmd);
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
  //regfile
  DelRegKey(HKCR,REGRUN);
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
  {\
    for (int i=0;i<30;i++)\
    {\
      Sleep(750);\
      if (a)\
        return TRUE; \
    } \
    return a;\
  }


BOOL RunThisAsAdmin(LPCTSTR cmd,DWORD WaitStat,int nResId)
{
  TCHAR ModName[MAX_PATH];
  TCHAR cmdLine[4096];
  GetModuleFileName(NULL,ModName,MAX_PATH);
  NetworkPathToUNCPath(ModName);
  PathQuoteSpaces(ModName);
  TCHAR User[UNLEN+GNLEN+2]={0};
  GetProcessUserName(GetCurrentProcessId(),User);
  if (IsInSuRunners(User) && (CheckServiceStatus()==SERVICE_RUNNING))
  {
    TCHAR SvcFile[4096];
    GetSystemWindowsDirectory(SvcFile,4096);
    PathAppend(SvcFile,_T("SuRun.exe"));
    PathQuoteSpaces(SvcFile);
    _stprintf(cmdLine,_T("%s /QUIET %s %s"),SvcFile,ModName,cmd);
    STARTUPINFO si={0};
    PROCESS_INFORMATION pi;
    si.cb = sizeof(si);
    if (CreateProcess(NULL,cmdLine,NULL,NULL,FALSE,0,NULL,NULL,&si,&pi))
    {
      CloseHandle(pi.hThread);
      DWORD ExitCode=-1;
      if (WaitForSingleObject(pi.hProcess,60000)==WAIT_OBJECT_0)
        GetExitCodeProcess(pi.hProcess,&ExitCode);
      CloseHandle(pi.hProcess);
      if (ExitCode==ERROR_ACCESS_DENIED)
        return FALSE;
      if (ExitCode==0)
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
    if(MessageBox(0,CBigResStr(IDS_ASKUNINST),CResStr(IDS_APPNAME),
                  MB_ICONQUESTION|MB_YESNO|MB_DEFBUTTON2|MB_SETFOREGROUND)==IDNO)
    return false;
    cbs.MsgLoop();
  }
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
  //Start Menu
  TCHAR file[4096];
  GetRegStr(HKLM,L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders",
    L"Common Programs",file,4096);
  ExpandEnvironmentStrings(file,File,4096);
  PathAppend(File,CResStr(IDS_STARTMENUDIR));
  DeleteDirectory(File);
  //Registry
  RemoveRegistry();
  if (bJustStop)
    return TRUE;
  //HKLM\Security\SuRun
  DelRegKey(HKLM,SVCKEY);
  //ToDo: SuRunners->Administratoren
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
  CCmdLine cmd(0);
  if ((cmd.argc()==3)&&(_tcsicmp(cmd.argv(1),_T("/AskPID"))==0))
  {
    SuRun(wcstol(cmd.argv(2),0,10));
    ExitProcess(0);
    return true;
  }
  if (cmd.argc()==2)
  {
    //Service
    if (_tcsicmp(cmd.argv(1),_T("/SERVICERUN"))==0)
    {
      if (!IsLocalSystem())
        return false;
      //Shell Extension
      InstallShellExt();
      SERVICE_TABLE_ENTRY DispatchTable[]={{SvcName,ServiceMain},{0,0}};
      //StartServiceCtrlDispatcher is a blocking call
      StartServiceCtrlDispatcher(DispatchTable);
      //Shell Extension
      RemoveShellExt();
      ExitProcess(0);
      return true;
    }
    //System Menu Hook: This is AutoRun for every user
    if (_tcsicmp(cmd.argv(1),_T("/SYSMENUHOOK"))==0)
    {
      //In the first three Minutes after Sytstem start:
      //Wait for the service to start
      DWORD ss=CheckServiceStatus();
      if ((ss==SERVICE_STOPPED)||(ss==SERVICE_START_PENDING))
        while ((GetTickCount()<3*60*1000)&&(CheckServiceStatus()!=SERVICE_RUNNING))
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
  //In the first three Minutes after Sytstem start:
  //Wait for the service to start
  DWORD ss=CheckServiceStatus();
  if ((ss==SERVICE_STOPPED)||(ss==SERVICE_START_PENDING))
    while ((GetTickCount()<3*60*1000)&&(CheckServiceStatus()!=SERVICE_RUNNING))
        Sleep(1000);
  //The Service must be running!
  ss=CheckServiceStatus();
  if (ss==SERVICE_STOPPED)
  {
    ExitProcess(-2);//Let ShellExec Hook return
    return false;
  }
  while(ss!=SERVICE_RUNNING)
  {
    if (!UserInstall(IDS_ASKINSTALL))
      ExitProcess(0);
    if (cmd.argc()==1)
      ExitProcess(0);
    ss=CheckServiceStatus();
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
//#ifndef _DEBUG
HANDLE g_hShell32=LoadLibrary(_T("Shell32.dll"));
static bool g_IsServiceStuff=HandleServiceStuff();
//#endif _DEBUG
