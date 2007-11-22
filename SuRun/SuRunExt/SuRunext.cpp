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
#pragma comment(lib,"Shlwapi.lib")

#include "SuRunExt.h"
#include "../ResStr.h"
#include "../Helpers.h"
#include "Resource.h"

#include "../DBGTrace.h"

extern TCHAR sFileNotFound[MAX_PATH];
extern TCHAR sSuRun[MAX_PATH];
extern TCHAR sErr[MAX_PATH];
extern TCHAR sTip[MAX_PATH];


// global data within shared data segment to allow sharing across instances
#pragma data_seg(".SHARDATA")

UINT g_cRefThisDll = 0;    // Reference count of this DLL.

#pragma data_seg()
#pragma comment(linker, "/section:.SHARDATA,rws")


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

#define HKCR HKEY_CLASSES_ROOT
#define HKLM HKEY_LOCAL_MACHINE
__declspec(dllexport) void InstallShellExt()
{
  //COM-Object
  SetRegStr(HKCR,L"CLSID\\" sGUID,L"",L"SuRun Shell Extension");
  SetRegStr(HKCR,L"CLSID\\" sGUID L"\\InProcServer32",L"",L"SuRunExt.dll");
  SetRegStr(HKCR,L"CLSID\\" sGUID L"\\InProcServer32",L"ThreadingModel",L"Apartment");
  //Desktop-Background-Hook
  SetRegStr(HKCR,L"Directory\\Background\\shellex\\ContextMenuHandlers\\SuRun",L"",sGUID);
  SetRegStr(HKCR,L"*\\shellex\\ContextMenuHandlers\\SuRun",L"",sGUID);
  //ShellExecuteHook
  SetRegStr(HKLM,L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ShellExecuteHooks",
            sGUID,L"");
  //self Approval
  SetRegStr(HKLM,L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Shell Extensions\\Approved",
            sGUID,L"SuRun Shell Extension");

}

__declspec(dllexport) void RemoveShellExt()
{
  //COM-Object
  DelRegKey(HKEY_CLASSES_ROOT,L"CLSID\\" sGUID);
  //Desktop-Background-Hook
  DelRegKey(HKEY_CLASSES_ROOT,L"Directory\\Background\\shellex\\ContextMenuHandlers\\SuRun");
  DelRegKey(HKEY_CLASSES_ROOT,L"*\\shellex\\ContextMenuHandlers\\SuRun");
  //ShellExecuteHook
  RegDelVal(HKEY_CLASSES_ROOT,
    L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ShellExecuteHooks",sGUID);
  //self Approval
  RegDelVal(HKEY_LOCAL_MACHINE,
    L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Shell Extensions\\Approved",sGUID);
}

CShellExtClassFactory::CShellExtClassFactory()
{
	m_cRef = 0L;
  inc_cRefThisDLL();
}

CShellExtClassFactory::~CShellExtClassFactory()
{
	dec_cRefThisDLL();
}

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

STDMETHODIMP CShellExt::Initialize(LPCITEMIDLIST pIDFolder, LPDATAOBJECT pDataObj, HKEY hRegKey)
{
#ifdef _DEBUG
  TCHAR Path[MAX_PATH]={0};
  if (pIDFolder)
    SHGetPathFromIDList(pIDFolder,Path);
  TCHAR FileClass[MAX_PATH]={0};
  if(hRegKey)
    GetRegStr(hRegKey,0,L"",FileClass,MAX_PATH);
  TCHAR File[MAX_PATH]={0};
  if(pDataObj)
  {
    FORMATETC fe = {CF_HDROP, NULL, DVASPECT_CONTENT, -1, TYMED_HGLOBAL};
    STGMEDIUM stm;
    if (SUCCEEDED(pDataObj->GetData(&fe,&stm)))
    {
      if(DragQueryFile((HDROP)stm.hGlobal,(UINT)-1,NULL,0)==1)
        DragQueryFile((HDROP)stm.hGlobal,0,File,MAX_PATH-1);
      ReleaseStgMedium(&stm);
    }
  }
  DBGTrace3("CShellExt::Initialize(%s,%s,%s)",Path,File,FileClass);
#endif _DEBUG
  m_pDeskClicked=pDataObj==0;
  return NOERROR;
}

STDMETHODIMP CShellExt::QueryContextMenu(HMENU hMenu, UINT indexMenu, UINT idCmdFirst, UINT idCmdLast, UINT uFlags)
{
  if((!(CMF_DEFAULTONLY & uFlags))&& m_pDeskClicked) 
  {
    if(GetRegInt(HKCR,L"CLSID\\" sGUID,ControlAsAdmin,1)!=0)
    {
      //right click target is folder background
      InsertMenu(hMenu, indexMenu++, MF_SEPARATOR|MF_BYPOSITION, NULL, NULL);
      InsertMenu(hMenu, indexMenu++, MF_STRING|MF_BYPOSITION, idCmdFirst, sSuRun);
      InsertMenu(hMenu, indexMenu++, MF_SEPARATOR|MF_BYPOSITION, NULL, NULL);
      return MAKE_HRESULT(SEVERITY_SUCCESS, 0, (USHORT)(1));
    }
  }
  return MAKE_HRESULT(SEVERITY_SUCCESS, 0, USHORT(0));
}

STDMETHODIMP CShellExt::GetCommandString(UINT_PTR idCmd,UINT uFlags,UINT FAR *reserved,LPSTR pszName,UINT cchMax)
{
  if ((uFlags == GCS_HELPTEXT) && (cchMax > wcslen(sTip)))
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
    _tcscat(cmd,L" control");
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

STDMETHODIMP CShellExt::Execute(LPSHELLEXECUTEINFO pei)
{
  //Struct Size Check
  if (pei->cbSize<sizeof(SHELLEXECUTEINFO))
    return S_FALSE;
  //Verb must be "open" or empty
  if (pei->lpVerb && (_tcslen(pei->lpVerb)!=0)&&(_tcsicmp(pei->lpVerb,L"open")!=0))
    return S_FALSE;
  //Check Directory
  if (!SetCurrentDirectory(pei->lpDirectory))
    return S_FALSE;
  //check if this Programm has an Auto-SuRun-Entry in the List
  TCHAR cmd[MAX_PATH];
  TCHAR tmp[MAX_PATH];
  GetSystemWindowsDirectory(cmd,MAX_PATH);
  PathAppend(cmd, _T("SuRun.exe"));
  PathQuoteSpaces(cmd);
  _tcscat(cmd,L" /TESTAUTOADMIN ");
  _tcscpy(tmp,pei->lpFile);
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
      if (ExitCode==0)
        pei->hInstApp=(HINSTANCE)33;
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
