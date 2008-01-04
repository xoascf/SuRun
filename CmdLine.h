//////////////////////////////////////////////////////////////////////////////
//
//  CCmdLine is a little handy class for handling command line parameters
//    it uses PathGetArgs, PathRemoveBlanks and PathUnquoteSpaces to split the 
//    command line parameters.
//
//  Why: 
//    MS CRT has no UNICODE command line handling
//
//  Example:
//    CCmdLine c;
//    for (int i=0;i<c.argc();i++)
//      printf(c.argv(i));
//                                (c) Kay Bruns (http://kay-bruns.de), 2007,08
//////////////////////////////////////////////////////////////////////////////
#pragma once

#define _WIN32_WINNT 0x0500
#define WINVER       0x0500
#include <windows.h>
#include <stdio.h>
#include <TCHAR.h>
#include <SHLWAPI.H>
#pragma comment(lib,"ShlWapi.lib")

class CCmdLine
{
public:
  CCmdLine()
  {
    m_CmdLine=_tcsdup(GetCommandLine());
    m_Argc=0;
    //Count command line args and remove spaces
    for (LPTSTR p=m_CmdLine;p && *p;m_Argc++)
    {
      p=PathGetArgs(p);
      PathRemoveBlanks(p);
    }
    //allocate argv pointers
    m_Args=(LPTSTR*)malloc(sizeof(LPTSTR)*m_Argc);
    //set argv pointers
    p=m_CmdLine;
    for (int arg=0;arg<m_Argc;arg++)
    {
      //separate argv strings with '\0':
      if (arg)
        *(p-1)=0;
      m_Args[arg]=p;
      p=PathGetArgs(p);
    }
    //Remove quotes
    for (arg=0;arg<m_Argc;arg++)
      PathUnquoteSpaces(m_Args[arg]);
  }
  ~CCmdLine()
  {
    free(m_CmdLine);
    free(m_Args);
  }
  LPCTSTR argv(int index)
  {
    return ((index<0)||(index>=m_Argc))?NULL:m_Args[index];
  }
  int argc()
  {
    return m_Argc;
  }
private:
  LPTSTR m_CmdLine;
  LPTSTR* m_Args;
  int m_Argc;
};

