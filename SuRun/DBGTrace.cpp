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
#define _WIN32_WINNT 0x0500
#define WINVER       0x0500
#include <windows.h>
#include <TCHAR.h>
#include "DBGTrace.h"

#include <stdio.h>
#include <stdarg.h>

#include <lmerr.h>
#pragma warning(disable : 4996)

void GetErrorName(int ErrorCode,LPTSTR s)
{
  HMODULE hModule = NULL;
  LPTSTR MessageBuffer=0;
  DWORD dwFormatFlags = FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_IGNORE_INSERTS | FORMAT_MESSAGE_FROM_SYSTEM ;
  if(ErrorCode >= NERR_BASE && ErrorCode <= MAX_NERR) 
  {
    hModule = LoadLibraryEx(_T("netmsg.dll"),NULL,LOAD_LIBRARY_AS_DATAFILE);
    if(hModule != NULL)
      dwFormatFlags |= FORMAT_MESSAGE_FROM_HMODULE;
  }
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

static void WriteLogA(LPSTR S)
{
  char tmp[MAX_PATH];
  GetTempPathA(MAX_PATH,tmp);
  strcat(tmp,"SuRunLog.log");
  FILE* f=fopen(tmp,"a+t");
  if(f)
  {
    SYSTEMTIME st;
    GetLocalTime(&st);
    fprintf(f,"%02d:%02d:%02d.%03d [%d]: %s",st.wHour,st.wMinute,st.wSecond,
      st.wMilliseconds,GetCurrentProcessId(),S);
    fclose(f);
  }
}

static void WriteLog(LPTSTR S)
{
#ifdef UNICODE
  WCHAR tmp[MAX_PATH];
  GetTempPathW(MAX_PATH,tmp);
  wcscat(tmp,L"SuRunLog.log");
  FILE* f=_wfopen(tmp,L"a+t");
  if(f)
  {
    SYSTEMTIME st;
    GetLocalTime(&st);
    fwprintf(f,L"%02d:%02d:%02d.%03d [%d]: %s",st.wHour,st.wMinute,st.wSecond,
      st.wMilliseconds,GetCurrentProcessId(),S);
    fclose(f);
  }
#else UNICODE
  WriteLogA(S);
#endif UNICODE
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
  LPTSTR c0=_tcschr(S,':');
  LPTSTR c1=_tcschr(S,'\\');
  LPTSTR c2=_tcschr(S,'.');
  LPTSTR c3=_tcschr(S,'(');
  LPTSTR c4=_tcschr(S,')');
  if((c0<c1)&&(c1<c2)&&(c2<c3)&&(c3<c4))
  {
    *c2=0;
    c0=_tcsrchr(c0,'\\')+1;
    *c2='.';
    memmove(S,c0,(_tcslen(c0)+1)*sizeof(TCHAR));
  }
  OutputDebugString(S);
//  WriteLog(S);
}

void TRACExA(LPCSTR s,...)
{
  char S[4096]={0};
  int len=0;
  va_list va;
  va_start(va,s);
  if (vsprintf(&S[len],s,va)>=1024)
    DebugBreak();
  va_end(va);
  LPSTR c0=strchr(S,':');
  LPSTR c1=strchr(S,'\\');
  LPSTR c2=strchr(S,'.');
  LPSTR c3=strchr(S,'(');
  LPSTR c4=strchr(S,')');
  if((c0<c1)&&(c1<c2)&&(c2<c3)&&(c3<c4))
  {
    *c2=0;
    c0=strrchr(c0,'\\')+1;
    *c2='.';
    memmove(S,c0,strlen(c0)+1);
  }
  OutputDebugStringA(S);
//  WriteLogA(S);
}

