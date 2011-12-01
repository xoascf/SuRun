// SuRunC.cpp : Defines the entry point for the console application.
//

#define _WIN32_WINNT 0x0500
#define WINVER       0x0500
#include <windows.h>
#include <stdio.h>
#include <tchar.h>
#include <ShlWapi.h>

#pragma comment(lib,"ShlWapi")


void GetErrorName(int ErrorCode,LPTSTR s)
{
  HMODULE hModule = NULL;
  LPTSTR MessageBuffer=0;
  DWORD dwFormatFlags = FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_IGNORE_INSERTS | FORMAT_MESSAGE_FROM_SYSTEM ;
  FormatMessage(dwFormatFlags,hModule,ErrorCode,MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),(LPTSTR) &MessageBuffer,0,NULL);
  if(hModule != NULL)
    FreeLibrary(hModule);
  _stprintf(s,_T("%d(0x%08X): %s"),ErrorCode,ErrorCode,MessageBuffer);
  LocalFree(MessageBuffer);
}

static TCHAR err[4096];
LPCTSTR GetErrorNameStatic(int ErrorCode)
{
  GetErrorName(ErrorCode,err);
  return err;
}

LPCTSTR GetLastErrorNameStatic()
{
  return GetErrorNameStatic(GetLastError());
}

void TRACEx(LPCTSTR s,...)
{
  TCHAR S[4096]={0};
  int len=0;
  va_list va;
  va_start(va,s);
  if (_vsntprintf(&S[len],4095-len,s,va)>=4096)
    DebugBreak();
  va_end(va);
  OutputDebugString(S);
  _tprintf(S);
  flushall();
}

DWORD WINAPI InProc(HANDLE hTx)
{
  TCHAR Buf[0x100];
  DWORD n;
  for(;;)
  {
    if ((!ReadFile(GetStdHandle(STD_INPUT_HANDLE),Buf,sizeof(Buf),&n,NULL)) || (!n))
      return 0;
    if (!WriteFile(hTx,Buf,n,&n,NULL))
      return 1;
  }
  return -1;
}

DWORD WINAPI OutProc(HANDLE hRx)
{
  TCHAR Buf[0x100];
  DWORD n;
  for(;;)
  {
    if ((!ReadFile(hRx,Buf,sizeof(Buf),&n,NULL)) || (!n))
      return 1;
    if(!WriteFile(GetStdHandle(STD_OUTPUT_HANDLE),Buf,n,&n,NULL))
      return 0;
  }
  return -1;
}

DWORD WINAPI ErrProc(HANDLE hRx)
{
  TCHAR Buf[0x100];
  DWORD n;
  for(;;)
  {
    if ((!ReadFile(hRx,Buf,sizeof(Buf),&n,NULL)) || (!n))
      return 1;
    if(!WriteFile(GetStdHandle(STD_ERROR_HANDLE),Buf,n,&n,NULL))
      return 0;
  }
  return -1;
}

static DWORD g_PipeInst=0;
BOOL CreateTxPipe(HANDLE* hRead,HANDLE* hWrite)
{
  SECURITY_ATTRIBUTES sar={sizeof(SECURITY_ATTRIBUTES),NULL,TRUE/*inherit*/};
  SECURITY_ATTRIBUTES saw={sizeof(SECURITY_ATTRIBUTES),NULL,FALSE/*inherit*/};
  TCHAR PipeName[MAX_PATH];
  _stprintf(PipeName,L"\\\\.\\pipe\\SuRunC%04X%04X",GetCurrentProcessId(),g_PipeInst++);
  *hWrite=CreateNamedPipe(PipeName,
      PIPE_ACCESS_OUTBOUND|FILE_FLAG_FIRST_PIPE_INSTANCE|FILE_FLAG_WRITE_THROUGH,
      PIPE_TYPE_MESSAGE|PIPE_READMODE_MESSAGE|PIPE_WAIT,1,0,0,0,&saw);
  if(*hWrite==INVALID_HANDLE_VALUE)
    return false;
  *hRead=CreateFile(PipeName,GENERIC_READ|SYNCHRONIZE,FILE_SHARE_READ|FILE_SHARE_WRITE,
      &sar,OPEN_EXISTING,FILE_FLAG_WRITE_THROUGH,0);
  if(*hRead==INVALID_HANDLE_VALUE)
    return CloseHandle(*hWrite),*hWrite=INVALID_HANDLE_VALUE,false;
  return true;
}

BOOL CreateRxPipe(HANDLE* hRead,HANDLE* hWrite)
{
  SECURITY_ATTRIBUTES sar={sizeof(SECURITY_ATTRIBUTES),NULL,FALSE/*inherit*/};
  SECURITY_ATTRIBUTES saw={sizeof(SECURITY_ATTRIBUTES),NULL,TRUE/*inherit*/};
  TCHAR PipeName[MAX_PATH];
  _stprintf(PipeName,L"\\\\.\\pipe\\SuRunC%04X%04X",GetCurrentProcessId(),g_PipeInst++);
  *hRead=CreateNamedPipe(PipeName,
      PIPE_ACCESS_INBOUND|FILE_FLAG_FIRST_PIPE_INSTANCE|FILE_FLAG_WRITE_THROUGH,
      PIPE_TYPE_MESSAGE|PIPE_READMODE_MESSAGE|PIPE_WAIT,1,0,0,0,&sar);
  if(*hRead==INVALID_HANDLE_VALUE)
    return false;
  *hWrite=CreateFile(PipeName,GENERIC_WRITE|SYNCHRONIZE,FILE_SHARE_READ|FILE_SHARE_WRITE,
      &saw,OPEN_EXISTING,FILE_FLAG_WRITE_THROUGH,0);
  if(*hWrite==INVALID_HANDLE_VALUE)
    return CloseHandle(*hRead),*hRead=INVALID_HANDLE_VALUE,false;
  return true;
}

wmain( int argc, wchar_t *argv[ ], wchar_t *envp[ ] )
{
  HANDLE hInRx,hInTx,hInThread;
  CreateTxPipe(&hInRx,&hInTx);
  hInThread=CreateThread(NULL,0,InProc,(LPVOID)hInTx,0,0);
  HANDLE hOutRx,hOutTx,hOutThread;
  CreateRxPipe(&hOutRx,&hOutTx);
  hOutThread=CreateThread(NULL,0,OutProc,(LPVOID)hOutRx,0,0);
  HANDLE hErrRx,hErrTx,hErrThread;
  CreateRxPipe(&hErrRx,&hErrTx);
  hErrThread=CreateThread(NULL,0,ErrProc,(LPVOID)hErrRx,0,0);
  
  PROCESS_INFORMATION pi={0};
  STARTUPINFO si={0};
  si.cb	= sizeof(si);
  si.dwFlags=STARTF_USESTDHANDLES|STARTF_FORCEOFFFEEDBACK;
  si.hStdInput=hInRx;
  si.hStdOutput=hOutTx;
  si.hStdError=hErrTx;
  
  TCHAR cmd[4096]={0};
  GetSystemWindowsDirectory(cmd,4096);
  PathAppend(cmd,L"SuRun.exe");
  PathQuoteSpaces(cmd);
  _tcscat(cmd,L" /RetPID ");
  _tcscat(cmd,PathGetArgs(GetCommandLine()));
  
  DWORD dwExCode=-1;
  if (CreateProcess(NULL,cmd,NULL,NULL,TRUE,DETACHED_PROCESS,NULL,NULL,&si,&pi))
  {
    CloseHandle(pi.hThread);
    WaitForSingleObject(pi.hProcess,INFINITE);
    GetExitCodeProcess(pi.hProcess,&dwExCode);
    CloseHandle(pi.hProcess);
    pi.hProcess=OpenProcess(SYNCHRONIZE,0,dwExCode);
    if(pi.hProcess)
    {
      WaitForSingleObject(pi.hProcess,INFINITE);
      GetExitCodeProcess(pi.hProcess,&dwExCode);
      CloseHandle(pi.hProcess);
    }else
      TRACEx(L"OpenProcess(%d) failed: %s",dwExCode,GetLastErrorNameStatic());
  }else
    TRACEx(L"CreateProcess(%s) failed: %s",cmd,GetLastErrorNameStatic());
  TerminateThread(hInThread,2);
  TerminateThread(hOutThread,2);
  TerminateThread(hErrThread,2);
  CloseHandle(hInThread);
  CloseHandle(hOutThread);
  CloseHandle(hErrThread);
  CloseHandle(hInRx);
  CloseHandle(hInTx);
  CloseHandle(hOutRx);
  CloseHandle(hOutTx);
  CloseHandle(hErrRx);
  CloseHandle(hErrTx);
  return dwExCode;
}
