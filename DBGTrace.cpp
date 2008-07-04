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

void TRACEx(LPCTSTR s,...)
{
  TCHAR S[4096]={0};
  int len=0;
  va_list va;
  va_start(va,s);
  if (_vstprintf(&S[len],s,va)>=4096)
    DebugBreak();
  va_end(va);
//  FILE* f=fopen("G:\\TEMP\\SuRunLog.log","a+t");
//  if(f)
//  {
//    int len=_tcslen(S);
//#ifdef UNICODE
//    char m[4096]={0};
//    WideCharToMultiByte(CP_UTF8,0,S,len,m,len,0,0);
//    fwrite(&m,1,len,f);
//#else UNICODE
//    fwrite(&S,1,len,f);
//#endif UNICODE
//    fclose(f);
//  }
  OutputDebugString(S);
}

void TRACExA(LPCSTR s,...)
{
  char S[1024]={0};
  int len=0;
  va_list va;
  va_start(va,s);
  if (vsprintf(&S[len],s,va)>=1024)
    DebugBreak();
  va_end(va);
//  FILE* f=fopen("G:\\TEMP\\SuRunLog.log","a+t");
//  if(f)
//  {
//    fwrite(&S,sizeof(char),strlen(S),f);
//    fclose(f);
//  }
  OutputDebugStringA(S);
}

