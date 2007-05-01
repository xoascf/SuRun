#pragma once

#define ServicePipeName _T("\\\\.\\Pipe\\SuperUserRun")

typedef struct
{
  DWORD CliProcessId;
  DWORD SessionID;
  TCHAR WinSta[MAX_PATH];
  TCHAR Desk[MAX_PATH];
  TCHAR UserName[CNLEN+DNLEN];
  TCHAR cmdLine[4096];
  TCHAR CurDir[MAX_PATH];
  DWORD KillPID;
}RUNDATA;

extern RUNDATA g_RunData;
extern TCHAR g_RunPwd[PWLEN];

BOOL InstallService();
BOOL DeleteService(BOOL bJustStop=FALSE);
