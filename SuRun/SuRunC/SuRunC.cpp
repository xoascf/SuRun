// SuRunC.cpp : Defines the entry point for the console application.
//

#define _WIN32_WINNT 0x0500
#define WINVER       0x0500
#include <windows.h>
#include <stdio.h>
#include <tchar.h>

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
  if (_vstprintf(&S[len],s,va)>=4096)
    DebugBreak();
  va_end(va);
  OutputDebugString(S);
  _tprintf(S);
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

wmain( int argc, wchar_t *argv[ ], wchar_t *envp[ ] )
{
  if (argc==1)
  {
    SECURITY_ATTRIBUTES sa={sizeof(SECURITY_ATTRIBUTES),NULL,TRUE/*inherit*/};
    HANDLE hInRx,hInThread;
    {
      HANDLE hInTx,hTmp;
      CreatePipe(&hInRx,&hTmp,&sa,0);
      DuplicateHandle(GetCurrentProcess(),hTmp,GetCurrentProcess(),&hInTx,0,
                      FALSE/*don't inherit*/,DUPLICATE_SAME_ACCESS);
      CloseHandle(hTmp);
      DWORD tid;
      hInThread=CreateThread(NULL,0,InProc,(LPVOID)hInTx,0,&tid);
    }
    HANDLE hOutTx,hOutThread;
    {
      HANDLE hOutRx,hTmp;
      CreatePipe(&hTmp,&hOutTx,&sa,0);
      DuplicateHandle(GetCurrentProcess(),hTmp,GetCurrentProcess(),&hOutRx,0,
                      FALSE/*don't inherit*/,DUPLICATE_SAME_ACCESS);
      CloseHandle(hTmp);
      DWORD tid;
      hOutThread=CreateThread(NULL,0,OutProc,(LPVOID)hOutRx,0,&tid);
    }
    HANDLE hErrTx,hErrThread;
    {
      HANDLE hErrRx,hTmp;
      CreatePipe(&hTmp,&hErrTx,&sa,0);
      DuplicateHandle(GetCurrentProcess(),hTmp,GetCurrentProcess(),&hErrRx,0,
                      FALSE/*don't inherit*/,DUPLICATE_SAME_ACCESS);
      CloseHandle(hTmp);
      DWORD tid;
      hErrThread=CreateThread(NULL,0,ErrProc,(LPVOID)hErrRx,0,&tid);
    }

    PROCESS_INFORMATION pi={0};
    STARTUPINFO si={0};
    si.cb	= sizeof(si);
    si.dwFlags=STARTF_USESTDHANDLES/*|STARTF_USESHOWWINDOW*/|STARTF_FORCEOFFFEEDBACK;
    //si.wShowWindow = SW_HIDE | SW_FORCEMINIMIZE;
    si.hStdInput=hInRx;
    si.hStdOutput=hOutTx;
    si.hStdError=hErrTx;
    TCHAR cmd[4096];
    _stprintf(cmd,L"SuRunC.exe %d",GetCurrentProcessId());
    TRACEx(L"SuRunC: Starting: %s\n",cmd);
    if (!CreateProcess(NULL,cmd,NULL,NULL,TRUE,DETACHED_PROCESS,NULL,NULL,&si,&pi))
      return FALSE;
    CloseHandle(pi.hThread);
    WaitForSingleObject(pi.hProcess,INFINITE);
    DWORD dwExCode;
    GetExitCodeProcess(pi.hProcess,&dwExCode);
    CloseHandle(pi.hProcess);
    CloseHandle(hInRx);
    CloseHandle(hOutTx);
    CloseHandle(hErrTx);
    TerminateThread(hInThread,2);
    TerminateThread(hOutThread,2);
    TerminateThread(hErrThread,2);
    CloseHandle(hInThread);
    CloseHandle(hOutThread);
    CloseHandle(hErrThread);
    TRACEx(L"SuRunC: Process 1 exited with %d\n",dwExCode);
    return 0;
  }
  if (argc==2)
  {
    DWORD ProcID=_tcstol(argv[1],0,10);
    TRACEx(L"SuRunC second stage: %d\n",ProcID);
    Sleep(2500);
    TRACEx(L"press a key\n");
    TRACEx(L"key was %d\n",_gettchar());
    return 1;
  }
	return 0;
}
