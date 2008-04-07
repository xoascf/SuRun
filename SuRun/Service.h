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

// All service related stuff is handled in Service.cpp
// The service bootstraps itself before WinMain gats called

#pragma once

//This is the pipe named used to get the SuRun command to the service
#define ServicePipeName _T("\\\\.\\Pipe\\SuperUserRun")

// This structure is passed from SuRun.exe to the service
// RUNDATA is bigger than required, but I'll leave it this way
#pragma pack(push)
#pragma pack(1)
typedef struct
{
  DWORD CliProcessId;
  DWORD CliThreadId;
  DWORD SessionID;
  TCHAR WinSta[MAX_PATH];
  TCHAR Desk[MAX_PATH];
  TCHAR UserName[UNLEN+UNLEN+2];
  union
  {
    struct //Normal
    {
      TCHAR cmdLine[4096];
      TCHAR CurDir[4096];
    };
    struct //TrayShowAdmin
    {
      DWORD CurProcId;
      TCHAR CurUserName[UNLEN+GNLEN+2];
      BOOL CurUserIsadmin;
    };
  };
  union
  {
    DWORD KillPID; //SuRun->Service: Process Id to be killed
    int IconId;    //Service->Tray Warning: ICON Resource Id
  };
  DWORD RetPID;
  DWORD_PTR RetPtr;
  bool  bNoSafeDesk; //only valid with /SETUP
  bool  bShlExHook;
  bool  beQuiet;
  bool  bRunAs;
  bool  bTrayShowAdmin;
}RUNDATA;

extern bool g_CliIsAdmin;

//This is used to verify that SuRun.exe started by the user is the same as 
//the Service process
extern RUNDATA g_RunData;

//The service copies the users password via WriteProcessMemory to g_RunPwd of 
//SuRun.exe that was started by the user
extern TCHAR g_RunPwd[PWLEN];

#define RETVAL_WAIT        -1
#define RETVAL_OK           0
#define RETVAL_ACCESSDENIED 1
#define RETVAL_SX_NOTINLIST 2
#define RETVAL_RESTRICT     3
#define RETVAL_CANCELLED    4
extern int g_RetVal;

bool HandleServiceStuff();

#pragma pack(pop)