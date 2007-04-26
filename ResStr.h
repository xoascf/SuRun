#pragma once

//Quick and dirty resource string class
template<const int _S> class CResourceString
{
public:
  CResourceString()
  {
    memset(&m_str,0,sizeof(m_str));
  }
  CResourceString(int nID,...)
  {
    TCHAR S[_S];
    LoadString(GetModuleHandle(0),nID,S,_S-1);
    va_list va;
    va_start(va,nID);
    _vstprintf(m_str,S,va);
    va_end(va);
  }
  CResourceString(LPCTSTR s,...)
  {
    va_list va;
    va_start(va,s);
    _vstprintf(m_str,s,va);
    va_end(va);
  }
  CResourceString(int nID,va_list va)
  {
    TCHAR S[_S];
    LoadString(GetModuleHandle(0),nID,S,_S-1);
    _vstprintf(m_str,S,va);
  }
  const LPCTSTR operator =(int nID)
  {
    LoadString(GetModuleHandle(0),nID,m_str,_S-1);
    return m_str;
  }
  const LPCTSTR operator =(LPCTSTR s)
  {
    _tcsncpy(m_str,s,_S);
    return m_str;
  }
  const TCHAR operator [](int Index)
  {
    return (Index<_S)?((Index>0)?m_str[Index]:'\0'):'\0';
  }
  operator LPTSTR() { return m_str; };
  operator LPCTSTR(){ return m_str; };
protected:
  TCHAR m_str[_S];
};

typedef CResourceString<256> CResStr;
typedef CResourceString<4096> CBigResStr;