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

#pragma once
#include <stdio.h>
#include <TCHAR.h>
#include <mmsystem.h>
#pragma comment(lib,"winmm")


//#define DoDBGTrace

#ifdef _DEBUG 
#define DoDBGTrace
#endif

void TRACEx(LPCTSTR s,...);

#ifdef DoDBGTrace

#define DBGTrace(msg)                             {TRACEx(_T("%s(%i): ")_T(msg)_T("\n"),_T(__FILE__),__LINE__);}
#define DBGTrace1(msg,d1)                         {TRACEx(_T("%s(%i): ")_T(msg)_T("\n"),_T(__FILE__),__LINE__,d1);}
#define DBGTrace2(msg,d1,d2)                      {TRACEx(_T("%s(%i): ")_T(msg)_T("\n"),_T(__FILE__),__LINE__,d1,d2);}
#define DBGTrace3(msg,d1,d2,d3)                   {TRACEx(_T("%s(%i): ")_T(msg)_T("\n"),_T(__FILE__),__LINE__,d1,d2,d3);}
#define DBGTrace4(msg,d1,d2,d3,d4)                {TRACEx(_T("%s(%i): ")_T(msg)_T("\n"),_T(__FILE__),__LINE__,d1,d2,d3,d4);}
#define DBGTrace5(msg,d1,d2,d3,d4,d5)             {TRACEx(_T("%s(%i): ")_T(msg)_T("\n"),_T(__FILE__),__LINE__,d1,d2,d3,d4,d5);}
#define DBGTrace6(msg,d1,d2,d3,d4,d5,d6)          {TRACEx(_T("%s(%i): ")_T(msg)_T("\n"),_T(__FILE__),__LINE__,d1,d2,d3,d4,d5,d6);}
#define DBGTrace7(msg,d1,d2,d3,d4,d5,d6,d7)       {TRACEx(_T("%s(%i): ")_T(msg)_T("\n"),_T(__FILE__),__LINE__,d1,d2,d3,d4,d5,d6,d7);}
#define DBGTrace8(msg,d1,d2,d3,d4,d5,d6,d7,d8)    {TRACEx(_T("%s(%i): ")_T(msg)_T("\n"),_T(__FILE__),__LINE__,d1,d2,d3,d4,d5,d6,d7,d8);}
#define DBGTrace9(msg,d1,d2,d3,d4,d5,d6,d7,d8,d9) {TRACEx(_T("%s(%i): ")_T(msg)_T("\n"),_T(__FILE__),__LINE__,d1,d2,d3,d4,d5,d6,d7,d8,d9);}

#else DoDBGTrace

#define DBGTrace(msg)                             {(void)0;}
#define DBGTrace1(msg,d1)                         {(void)0;}
#define DBGTrace2(msg,d1,d2)                      {(void)0;}
#define DBGTrace3(msg,d1,d2,d3)                   {(void)0;}
#define DBGTrace4(msg,d1,d2,d3,d4)                {(void)0;}
#define DBGTrace5(msg,d1,d2,d3,d4,d5)             {(void)0;}
#define DBGTrace6(msg,d1,d2,d3,d4,d5,d6)          {(void)0;}
#define DBGTrace7(msg,d1,d2,d3,d4,d5,d6,d7)       {(void)0;}
#define DBGTrace8(msg,d1,d2,d3,d4,d5,d6,d7,d8)    {(void)0;}
#define DBGTrace9(msg,d1,d2,d3,d4,d5,d6,d7,d8,d9) {(void)0;}

#endif DoDBGTrace 

void GetErrorName(int ErrorCode,LPTSTR s);
LPCTSTR GetErrorNameStatic(int ErrorCode);
LPCTSTR GetLastErrorNameStatic();

class CTimeLog
{
public:
  CTimeLog(LPCTSTR logTitle,...)
  {
    logTitle;
#ifdef DoDBGTrace
    va_list args;
    va_start(args, logTitle);
    _vstprintf(m_logTitle,logTitle,args);
    va_end(args);
    TRACEx(_T("%s init.\n"),(LPCTSTR)m_logTitle);
    m_StartTime=timeGetTime();
#endif DoDBGTrace
  }
  virtual ~CTimeLog()
  {
#ifdef DoDBGTrace
    DoLog(_T("exit"));
#endif DoDBGTrace
  };
  void DoLog(LPCTSTR s)
  {
#ifdef DoDBGTrace
    TRACEx(_T("%s %s: %d ms\n"),(LPCTSTR)m_logTitle,s,timeGetTime()-m_StartTime);
#endif DoDBGTrace
  };
#ifdef DoDBGTrace
  DWORD m_StartTime;
  TCHAR m_logTitle[4096];
#endif DoDBGTrace
};

