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

//#pragma pack(push,1)
//typedef struct
//{
//  DWORD PID;
//  char s[4096-sizeof(DWORD)];
//}DBGSTRBUF;
//#pragma pack(pop)
////DbgOutA was created after reading:
////http://unixwiz.net/techtips/outputdebugstring.html
//void DbgOutA(LPCSTR s)
//{
//  static HANDLE DBWMtx=NULL;
//  if (!DBWMtx)
//    DBWMtx=OpenMutexA(SYNCHRONIZE,false,"DBWinMutex");
//  if (!DBWMtx)
//  {
//    //Just in case Microsoft changes OutputDebugString in future:
//    OutputDebugStringA("FATAL: DBWinMutex not available\n");
//    return;
//  }
//  WaitForSingleObject(DBWMtx,INFINITE);
//  HANDLE DBWBuf=OpenFileMappingA(FILE_MAP_READ|FILE_MAP_WRITE,FALSE,"DBWIN_BUFFER");
//  if (!DBWBuf) 
//  {
//    ReleaseMutex(DBWMtx);
//    //Just in case Microsoft changes OutputDebugString in future:
//    OutputDebugStringA("FATAL: DBWIN_BUFFER not available\n");
//    return;
//  }
//  DBGSTRBUF* Buf=(DBGSTRBUF*)MapViewOfFile(DBWBuf,FILE_MAP_WRITE,0,0,0);
//  HANDLE evRdy=OpenEventA(EVENT_MODIFY_STATE,FALSE,"DBWIN_DATA_READY");
//  HANDLE evAck=OpenEventA(SYNCHRONIZE,FALSE,"DBWIN_BUFFER_READY");
//  __try 
//  {
//    if (evRdy && WaitForSingleObject(evAck,5000) == WAIT_OBJECT_0) 
//    {
//      Buf->PID=GetCurrentProcessId();
//      memset(&Buf->s,0,sizeof(Buf->s));
//      memmove(&Buf->s,s,min(strlen(s),sizeof(Buf->s)-1));
//      SetEvent(evRdy);
//    }else
//    {
//      //Just in case Microsoft changes OutputDebugString in future:
//      OutputDebugStringA("FATAL: DBWIN_xxx events not available\n");
//    }
//  }
//  __except(1) 
//  {
//    //Just in case Microsoft changes OutputDebugString in future:
//    OutputDebugStringA("FATAL: Exception in DbgOutA\n");
//  }
//  if (evAck) 
//    CloseHandle(evAck);
//  if (evRdy) 
//    CloseHandle(evRdy);
//  if (Buf) 
//    UnmapViewOfFile(Buf);
//  CloseHandle(DBWBuf);
//  ReleaseMutex(DBWMtx);
//}

void TRACEx(LPCTSTR s,...)
{
  __try
  {
    TCHAR S[4096]={0};
    va_list va;
    va_start(va,s);
    _vstprintf(S,s,va);
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
//    char Sa[4096]={0};
//	  WideCharToMultiByte(CP_ACP,0,S,_tcslen(S),Sa,4096,NULL,NULL);
//	  DbgOutA(Sa);
    //  WriteLog(S);
  }__except(1)
  {
    OutputDebugStringA("FATAL: Exception in TRACEx");
  }
}

void TRACExA(LPCSTR s,...)
{
  __try
  {
    char S[4096]={0};
    va_list va;
    va_start(va,s);
    vsprintf(S,s,va);
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
//    DbgOutA(S);
    OutputDebugStringA(S);
    //  WriteLogA(S);
  }__except(1)
  {
    OutputDebugStringA("FATAL: Exception in TRACExA");
  }
}

