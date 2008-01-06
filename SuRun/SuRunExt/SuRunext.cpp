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
//                                (c) Kay Bruns (http://kay-bruns.de), 2007,08
//////////////////////////////////////////////////////////////////////////////

//////////////////////////////////////////////////////////////////////////////
//
// based on: SuDowns sudoext.cpp http://sudown.sourceforge.net
//
//////////////////////////////////////////////////////////////////////////////
#define _WIN32_WINNT 0x0500
#define WINVER       0x0500
#include <windows.h>
#include <tchar.h>
#include <shlobj.h>
#include <initguid.h>
#include <shlwapi.h>

#pragma comment(lib,"User32.lib")
#pragma comment(lib,"ole32.lib")
#pragma comment(lib,"Shell32.lib")
#pragma comment(lib,"ShFolder.Lib")
#pragma comment(lib,"Shlwapi.lib")

#include "SuRunExt.h"
#include "../ResStr.h"
#include "../Helpers.h"
#include "../Setup.h"
#include "../IsAdmin.h"
#include "Resource.h"

#include "../DBGTrace.h"

//////////////////////////////////////////////////////////////////////////////
//
// global data within shared data segment to allow sharing across instances
//
//////////////////////////////////////////////////////////////////////////////
#pragma data_seg(".SHARDATA")

UINT g_cRefThisDll = 0;    // Reference count of this DLL.

#pragma data_seg()
#pragma comment(linker, "/section:.SHARDATA,rws")

//////////////////////////////////////////////////////////////////////////////
//
// Strings: these are defined in SysMenuHook.cpp and placed in ".SHARDATA"
//
//////////////////////////////////////////////////////////////////////////////
extern TCHAR sFileNotFound[MAX_PATH];
extern TCHAR sSuRun[MAX_PATH];
extern TCHAR sSuRunCmd[MAX_PATH];
extern TCHAR sSuRunExp[MAX_PATH];
extern TCHAR sErr[MAX_PATH];
extern TCHAR sTip[MAX_PATH];

//////////////////////////////////////////////////////////////////////////////
//
// this class factory object creates context menu handlers for windows 32 shell
//
//////////////////////////////////////////////////////////////////////////////
class CShellExtClassFactory : public IClassFactory
{
protected:
  ULONG	m_cRef;
public:
  CShellExtClassFactory();
  ~CShellExtClassFactory();
  //IUnknown members
  STDMETHODIMP			QueryInterface(REFIID, LPVOID FAR *);
  STDMETHODIMP_(ULONG)	AddRef();
  STDMETHODIMP_(ULONG)	Release();
  //IClassFactory members
  STDMETHODIMP		CreateInstance(LPUNKNOWN, REFIID, LPVOID FAR *);
  STDMETHODIMP		LockServer(BOOL);
};
typedef CShellExtClassFactory *LPCSHELLEXTCLASSFACTORY;

//////////////////////////////////////////////////////////////////////////////
//
// this is the actual OLE Shell context menu handler
//
//////////////////////////////////////////////////////////////////////////////
class CShellExt : public IContextMenu, IShellExtInit, IShellExecuteHook
{
protected:
  ULONG m_cRef;
  bool m_pDeskClicked;
  TCHAR m_ClickFolderName[MAX_PATH];
public:
  CShellExt();
  ~CShellExt();
  //IUnknown members
  STDMETHODIMP QueryInterface(REFIID, LPVOID FAR *);
  STDMETHODIMP_(ULONG) AddRef();
  STDMETHODIMP_(ULONG) Release();
  //IContextMenu members
  STDMETHODIMP QueryContextMenu(HMENU, UINT, UINT, UINT, UINT);
  STDMETHODIMP InvokeCommand(LPCMINVOKECOMMANDINFO);
  STDMETHODIMP GetCommandString(UINT_PTR, UINT, UINT FAR *, LPSTR, UINT);
  //IShellExtInit methods
  STDMETHODIMP Initialize(LPCITEMIDLIST, LPDATAOBJECT, HKEY);
  //IShellExecuteHook methods
  STDMETHODIMP Execute(LPSHELLEXECUTEINFO pei);
};

typedef CShellExt *LPCSHELLEXT;

//////////////////////////////////////////////////////////////////////////////
//
// DLL Handling Stuff
//
//////////////////////////////////////////////////////////////////////////////

static void inc_cRefThisDLL()
{
	InterlockedIncrement((LPLONG)&g_cRefThisDll);
}

static void dec_cRefThisDLL()
{
	InterlockedDecrement((LPLONG)&g_cRefThisDll);
}

STDAPI DllCanUnloadNow(void)
{
	return (g_cRefThisDll == 0 ? S_OK : S_FALSE);
}

STDAPI DllGetClassObject(REFCLSID rclsid, REFIID riid, LPVOID *ppvOut)
{
	*ppvOut = NULL;
  if (IsEqualIID(rclsid, CLSID_ShellExtension)) 
  {
    CShellExtClassFactory *pcf = new CShellExtClassFactory;
    return pcf->QueryInterface(riid, ppvOut);
  }
  return CLASS_E_CLASSNOTAVAILABLE;
}

//////////////////////////////////////////////////////////////////////////////
//
// Install/Uninstall
//
//////////////////////////////////////////////////////////////////////////////

__declspec(dllexport) void InstallShellExt()
{
  //Disable "Open with..." when right clicking on SuRun.exe
  SetRegStr(HKCR,L"Applications\\SuRun.exe",L"NoOpenWith",L"");
  //Disable putting SuRun in the frequently used apps in the start menu
  SetRegStr(HKCR,L"Applications\\SuRun.exe",L"NoStartPage",L"");
  //COM-Object
  SetRegStr(HKCR,L"CLSID\\" sGUID,L"",L"SuRun Shell Extension");
  SetRegStr(HKCR,L"CLSID\\" sGUID L"\\InProcServer32",L"",L"SuRunExt.dll");
  SetRegStr(HKCR,L"CLSID\\" sGUID L"\\InProcServer32",L"ThreadingModel",L"Apartment");
  //Desktop-Background-Hook
  SetRegStr(HKCR,L"Directory\\Background\\shellex\\ContextMenuHandlers\\SuRun",L"",sGUID);
  SetRegStr(HKCR,L"Folder\\shellex\\ContextMenuHandlers\\SuRun",L"",sGUID);
  //SetRegStr(HKCR,L"*\\shellex\\ContextMenuHandlers\\SuRun",L"",sGUID);
  //ShellExecuteHook
  SetRegStr(HKLM,L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ShellExecuteHooks",
            sGUID,L"");
  //self Approval
  SetRegStr(HKLM,L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Shell Extensions\\Approved",
            sGUID,L"SuRun Shell Extension");

}

__declspec(dllexport) void RemoveShellExt()
{
  DelRegKey(HKCR,L"Applications\\SuRun.exe");
  //COM-Object
  DelRegKey(HKCR,L"CLSID\\" sGUID);
  //Desktop-Background-Hook
  DelRegKey(HKCR,L"Directory\\Background\\shellex\\ContextMenuHandlers\\SuRun");
  DelRegKey(HKCR,L"Folder\\shellex\\ContextMenuHandlers\\SuRun");
  //DelRegKey(HKEY_CLASSES_ROOT,L"*\\shellex\\ContextMenuHandlers\\SuRun");
  //ShellExecuteHook
  RegDelVal(HKLM,L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ShellExecuteHooks",sGUID);
  //self Approval
  RegDelVal(HKLM,L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Shell Extensions\\Approved",sGUID);
}

//////////////////////////////////////////////////////////////////////////////
//
// CShellExtClassFactory
//
//////////////////////////////////////////////////////////////////////////////

CShellExtClassFactory::CShellExtClassFactory()
{
	m_cRef = 0L;
  inc_cRefThisDLL();
}

CShellExtClassFactory::~CShellExtClassFactory()
{
	dec_cRefThisDLL();
}

//////////////////////////////////////////////////////////////////////////////
// IUnknown
//////////////////////////////////////////////////////////////////////////////
STDMETHODIMP CShellExtClassFactory::QueryInterface(REFIID riid, LPVOID FAR *ppv)
{
  *ppv = NULL;
  if (IsEqualIID(riid, IID_IUnknown) || IsEqualIID(riid, IID_IClassFactory)) 
  {
    *ppv = (LPCLASSFACTORY)this;
    AddRef();
    return NOERROR;
  }
  return E_NOINTERFACE;
}

STDMETHODIMP_(ULONG) CShellExtClassFactory::AddRef()
{
	return InterlockedIncrement((LPLONG)&m_cRef);
}

STDMETHODIMP_(ULONG) CShellExtClassFactory::Release()
{
	if (InterlockedDecrement((LPLONG)&m_cRef))
    return m_cRef;
  delete this;
  return 0L;
}

//////////////////////////////////////////////////////////////////////////////
// IClassFactory
//////////////////////////////////////////////////////////////////////////////
STDMETHODIMP CShellExtClassFactory::CreateInstance(LPUNKNOWN pUnkOuter, REFIID riid, LPVOID *ppvObj)
{
	*ppvObj = NULL;
  if (pUnkOuter)
    return CLASS_E_NOAGGREGATION;
  LPCSHELLEXT pShellExt = new CShellExt();  //Create the CShellExt object
  if (NULL == pShellExt)
    return E_OUTOFMEMORY;
  return pShellExt->QueryInterface(riid, ppvObj);
}

STDMETHODIMP CShellExtClassFactory::LockServer(BOOL fLock)
{
	return NOERROR;
}

//////////////////////////////////////////////////////////////////////////////
//
// CShellExt
//
//////////////////////////////////////////////////////////////////////////////

CShellExt::CShellExt()
{
	m_cRef = 0L;
  m_pDeskClicked=false;
  inc_cRefThisDLL();
}

CShellExt::~CShellExt()
{
  dec_cRefThisDLL();
}

//////////////////////////////////////////////////////////////////////////////
// IUnknown
//////////////////////////////////////////////////////////////////////////////
STDMETHODIMP CShellExt::QueryInterface(REFIID riid, LPVOID FAR *ppv)
{
  *ppv = NULL;
  if (IsEqualIID(riid, IID_IShellExtInit) || IsEqualIID(riid, IID_IUnknown)) 
    *ppv = (LPSHELLEXTINIT)this;
  else if (IsEqualIID(riid, IID_IContextMenu))
    *ppv = (LPCONTEXTMENU)this;
  if (IsEqualIID(riid, IID_IShellExecuteHook))
    *ppv = (IShellExecuteHook*)this;
  if (*ppv) 
  {
    AddRef();
    return NOERROR;
  }
  return E_NOINTERFACE;
}

STDMETHODIMP_(ULONG) CShellExt::AddRef()
{
	return InterlockedIncrement((LPLONG)&m_cRef);
}

STDMETHODIMP_(ULONG) CShellExt::Release()
{
	if (InterlockedDecrement((LPLONG)&m_cRef))
    return m_cRef;
  delete this;
  return 0L;
}

//////////////////////////////////////////////////////////////////////////////
// IShellExtInit
//////////////////////////////////////////////////////////////////////////////
STDMETHODIMP CShellExt::Initialize(LPCITEMIDLIST pIDFolder, LPDATAOBJECT pDataObj, HKEY hRegKey)
{
  zero(m_ClickFolderName);
  m_pDeskClicked=FALSE;
  if (IsAdmin())
    return NOERROR;
  if (pDataObj==0)
  {
    SHGetPathFromIDList(pIDFolder,m_ClickFolderName);
    TCHAR s[MAX_PATH]={0};
    SHGetFolderPath(0,CSIDL_DESKTOP,0,SHGFP_TYPE_CURRENT,s);
    m_pDeskClicked=_tcsicmp(s,m_ClickFolderName)==0;
  }else
  {
    FORMATETC fe = {CF_HDROP, NULL, DVASPECT_CONTENT, -1, TYMED_HGLOBAL};
    STGMEDIUM m;
    if ((SUCCEEDED(pDataObj->GetData(&fe,&m)))
      &&(DragQueryFile((HDROP)m.hGlobal,(UINT)-1,NULL,0)==1)) 
    {
      TCHAR path[MAX_PATH];
      DragQueryFile((HDROP)m.hGlobal, 0, path, countof(path));
      if (PathIsDirectory(path))
        _tcscpy(m_ClickFolderName,path);
      ReleaseStgMedium(&m);
    }
  } 
  return NOERROR;
}

//////////////////////////////////////////////////////////////////////////////
// IContextMenu
//////////////////////////////////////////////////////////////////////////////
STDMETHODIMP CShellExt::QueryContextMenu(HMENU hMenu, UINT indexMenu, UINT idCmdFirst, UINT idCmdLast, UINT uFlags)
{
  UINT id=idCmdFirst;
  if((CMF_DEFAULTONLY & uFlags)==0) 
  {
    if(m_pDeskClicked)
    {
      if (GetCtrlAsAdmin)
      {
        //right click target is folder background
        InsertMenu(hMenu, indexMenu++, MF_SEPARATOR|MF_BYPOSITION, NULL, NULL);
        InsertMenu(hMenu, indexMenu++, MF_STRING|MF_BYPOSITION, id++, sSuRun);
        InsertMenu(hMenu, indexMenu++, MF_SEPARATOR|MF_BYPOSITION, NULL, NULL);
      }
    }else
    if(m_ClickFolderName[0])
    {
      BOOL bCmd=GetCmdAsAdmin;
      BOOL bExp=GetExpAsAdmin;
      if (bExp || bCmd)
        InsertMenu(hMenu, indexMenu++, MF_SEPARATOR|MF_BYPOSITION, NULL, NULL);
      //right click target is folder background
      if (bCmd)
        InsertMenu(hMenu, indexMenu++, MF_STRING|MF_BYPOSITION, id, sSuRunCmd);
      id++;
      if (bExp)
        InsertMenu(hMenu, indexMenu++, MF_STRING|MF_BYPOSITION, id, sSuRunExp);
      id++;
      if (bExp || bCmd)
        InsertMenu(hMenu, indexMenu++, MF_SEPARATOR|MF_BYPOSITION, NULL, NULL);
    }
  }
  return MAKE_HRESULT(SEVERITY_SUCCESS, 0, (USHORT)(id-idCmdFirst));
}

STDMETHODIMP CShellExt::GetCommandString(UINT_PTR idCmd,UINT uFlags,UINT FAR *reserved,LPSTR pszName,UINT cchMax)
{
  if (m_pDeskClicked && (uFlags == GCS_HELPTEXT) && (cchMax > wcslen(sTip)))
    wcscpy((LPWSTR)pszName,sTip);
  return NOERROR;
}

STDMETHODIMP CShellExt::InvokeCommand(LPCMINVOKECOMMANDINFO lpcmi)
{
  HRESULT hr = E_INVALIDARG;
	if (!HIWORD(lpcmi->lpVerb))
  {
    STARTUPINFO si;
    PROCESS_INFORMATION pi;
    TCHAR cmd[MAX_PATH];
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    GetSystemWindowsDirectory(cmd,MAX_PATH);
    PathAppend(cmd, _T("SuRun.exe"));
    PathQuoteSpaces(cmd);
    if (m_pDeskClicked)
      _tcscat(cmd,L" control");
    else
    {
      if (LOWORD(lpcmi->lpVerb)==0)
        _tcscat(cmd,L" cmd /D /T:4E /K cd /D ");
      else
        _tcscat(cmd,L" explorer /e,");
      PathQuoteSpaces(m_ClickFolderName);
      _tcscat(cmd,m_ClickFolderName);
    }
    // Start the child process.
    if (CreateProcess(NULL,cmd,NULL,NULL,FALSE,0,NULL,NULL,&si,&pi))
    {
      CloseHandle( pi.hProcess );
      CloseHandle( pi.hThread );
      hr = NOERROR;
    }else
      MessageBoxW(lpcmi->hwnd,sFileNotFound,sErr,MB_ICONSTOP);
  }
  return hr;
}

//////////////////////////////////////////////////////////////////////////////
// IShellExecuteHook
//////////////////////////////////////////////////////////////////////////////
STDMETHODIMP CShellExt::Execute(LPSHELLEXECUTEINFO pei)
{
  DBGTrace15(
        "SuRun ShellExtHook: siz=%d, msk=%x wnd=%x, verb=%s, file=%s, parms=%s, dir=%s, nShow=%x, inst=%x, idlist=%x, class=%s, hkc=%x, hotkey=%x, hicon=%x, hProc=%x",
        pei->cbSize,
        pei->fMask,
        pei->hwnd,
        pei->lpVerb,
        pei->lpFile,
        pei->lpParameters,
        pei->lpDirectory,
        pei->nShow,
        pei->hInstApp,
        pei->lpIDList,
        pei->lpClass,
        pei->hkeyClass,
        pei->dwHotKey,
        pei->hIcon,
        pei->hProcess);
  //Struct Size Check
  if (!pei)
  {
    DBGTrace("SuRun ShellExtHook Error: LPSHELLEXECUTEINFO==NULL");
    return S_FALSE;
  }
  if(pei->cbSize<sizeof(SHELLEXECUTEINFO))
  {
    DBGTrace2("SuRun ShellExtHook Error: invalid Size (expected=%d;real=%d)",sizeof(SHELLEXECUTEINFO),pei->cbSize);
    return S_FALSE;
  }
  if (!pei->lpFile)
  {
    DBGTrace("SuRun ShellExtHook Error: invalid LPSHELLEXECUTEINFO->lpFile==NULL!");
    return S_FALSE;
  }
  //Check Directory
  if (pei->lpDirectory && (*pei->lpDirectory) && (!SetCurrentDirectory(pei->lpDirectory)))
  {
    DBGTrace2("SuRun ShellExtHook Error: SetCurrentDirectory(%s) failed: %s",
      pei->lpDirectory,GetLastErrorNameStatic());
    return S_FALSE;
  }
  //check if this Programm has an Auto-SuRun-Entry in the List
  TCHAR cmd[MAX_PATH];
  TCHAR tmp[MAX_PATH];
  _tcscpy(tmp,pei->lpFile);
  //Verb must be "open" or empty
  if (pei->lpVerb && (_tcslen(pei->lpVerb)!=0)
    &&(_tcsicmp(pei->lpVerb,L"open")!=0)
    &&(_tcsicmp(pei->lpVerb,L"cplopen")!=0))
  {
    if (_tcsicmp(pei->lpVerb,L"AutoRun")==0)
    {
      _tcscat(tmp,L"AutoRun.inf");
      GetPrivateProfileString(L"AutoRun",L"open",L"",cmd,MAX_PATH,tmp);
      if (!cmd[0])
        return S_FALSE;
      _tccpy(tmp,cmd);
    }else
    {
      DBGTrace("SuRun ShellExtHook Error: invalid verb!");
      return S_FALSE;
    }
  }
  GetSystemWindowsDirectory(cmd,MAX_PATH);
  PathAppend(cmd, _T("SuRun.exe"));
  PathQuoteSpaces(cmd);
  _tcscat(cmd,L" /TESTAUTOADMIN ");
  
  PathQuoteSpaces(tmp);
  _tcscat(cmd,tmp);
  if (pei->lpParameters && _tcslen(pei->lpParameters))
  {
    _tcscat(cmd,L" ");
    _tcscat(cmd,pei->lpParameters);
  }
  STARTUPINFO si;
  PROCESS_INFORMATION pi;
  ZeroMemory(&si, sizeof(si));
  si.cb = sizeof(si);
  // Start the child process.
  if (CreateProcess(NULL,cmd,NULL,NULL,FALSE,0,NULL,NULL,&si,&pi))
  {
    CloseHandle(pi.hThread );
    DWORD ExitCode=ERROR_ACCESS_DENIED;
    if((WaitForSingleObject(pi.hProcess,60000)==WAIT_OBJECT_0)
      && GetExitCodeProcess(pi.hProcess,(DWORD*)&ExitCode))
    {
      //ExitCode==-2 means that the program is not in the WhiteList
      if (ExitCode==0)
      {
        pei->hInstApp=(HINSTANCE)33;
        //ToDo: Show ToolTip "<Program> is running elevated"...
      }
      else 
      {
        DBGTrace2("SuRun ShellExtHook: failed to execute %s; %s",cmd,GetErrorNameStatic(ExitCode));
        if(ExitCode==ERROR_ACCESS_DENIED)
          pei->hInstApp=(HINSTANCE)SE_ERR_ACCESSDENIED;
      }
    }else
      DBGTrace1("SuRun ShellExtHook: WHOOPS! %s",cmd);
    CloseHandle(pi.hProcess);
    return ((ExitCode==NOERROR)||(ExitCode==ERROR_ACCESS_DENIED))?S_OK:S_FALSE;
  }else
    DBGTrace2("SuRun ShellExtHook: CreateProcess(%s) failed: %s",cmd,GetLastErrorNameStatic());
  return S_FALSE;
}
