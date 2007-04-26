//////////////////////////////////////////////////////////////////////////////
//
// based on: SuDowns sudoext.cpp http://sudown.sourceforge.net
//           Tianmiao Hu's excellent GVimExt gvim extension v1.0.0.1
//             ftp://ftp.vim.org/pub/vim/pc/vim70src.zip.
//////////////////////////////////////////////////////////////////////////////
#define _WIN32_WINNT 0x0500
#define WINVER       0x0500
#include <windows.h>
#include <tchar.h>
#include <stdio.h>
#include <shlobj.h>
#include <initguid.h>
#include <shlguid.h>
#include <shlwapi.h>

#pragma comment(lib,"User32.lib")
#pragma comment(lib,"ole32.lib")
#pragma comment(lib,"Shell32.lib")
#pragma comment(lib,"Shlwapi.lib")

#include "SuRunExt.h"
#include "../ResStr.h"
#include "../Helpers.h"
#include "Resource.h"

// global data within shared data segment to allow sharing across instances
#pragma data_seg(".SHARDATA")

UINT g_cRefThisDll = 0;    // Reference count of this DLL.

#pragma data_seg()
#pragma comment(linker, "/section:.SHARDATA,rws")


extern "C" int APIENTRY DllMain(HINSTANCE hInstance, DWORD dwReason, LPVOID lpReserved)
{
  return 1;
}

static void inc_cRefThisDLL()
{
	InterlockedIncrement((LPLONG)&g_cRefThisDll);
}

static void dec_cRefThisDLL()
{
	InterlockedDecrement((LPLONG)&g_cRefThisDll);
}

STDAPI DllCanUnloadNow()
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

STDAPI DllRegisterServer()
{
  SetRegStr()
[HKEY_CLASSES_ROOT\CLSID\{2C7B6088-5A77-4d48-BE43-30337DCA9A86}]
   @="SuRun Shell Extension"
[HKEY_CLASSES_ROOT\CLSID\{2C7B6088-5A77-4d48-BE43-30337DCA9A86}\InProcServer32]
   @="SuRunExt.dll"
   "ThreadingModel"="Apartment"

[HKEY_CLASSES_ROOT\Directory\Background\shellex\ContextMenuHandlers\SuRun]
   @="{2C7B6088-5A77-4d48-BE43-30337DCA9A86}"

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Approved]
   "{2C7B6088-5A77-4d48-BE43-30337DCA9A86}"="SuRun Shell Extension"
  
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
  inc_cRefThisDLL();
}

CShellExt::~CShellExt()
{
  dec_cRefThisDLL();
}

STDMETHODIMP CShellExt::QueryInterface(REFIID riid, LPVOID FAR *ppv)
{
	*ppv = NULL;
  if (IsEqualIID(riid, IID_IContextMenu))
    *ppv = (LPCONTEXTMENU)this;
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

STDMETHODIMP CShellExt::QueryContextMenu(HMENU hMenu, UINT indexMenu, UINT idCmdFirst, UINT idCmdLast, UINT uFlags)
{
  if((CMF_DEFAULTONLY & uFlags)==0)
  {
    //right click target is folder background
    InsertMenu(hMenu, indexMenu++, MF_SEPARATOR|MF_BYPOSITION, NULL, NULL);
    InsertMenu(hMenu, indexMenu++, MF_STRING|MF_BYPOSITION, idCmdFirst, CResStr(IDS_SURUN));
    InsertMenu(hMenu, indexMenu++, MF_SEPARATOR|MF_BYPOSITION, NULL, NULL);
    return MAKE_HRESULT(SEVERITY_SUCCESS, 0, (USHORT)(idCmdFirst+1));
  }
  return MAKE_HRESULT(SEVERITY_SUCCESS, 0, USHORT(0));
}

STDMETHODIMP CShellExt::InvokeCommand(LPCMINVOKECOMMANDINFO lpcmi)
{
  HRESULT hr = E_INVALIDARG;
	if (!HIWORD(lpcmi->lpVerb))
  {
    STARTUPINFO si;
    PROCESS_INFORMATION pi;
    TCHAR sudocmd[MAX_PATH];
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    GetWindowsDirectory(sudocmd,MAX_PATH);
    PathAppend(sudocmd, _T("SuRun.exe"));
    // Start the child process.
    if (CreateProcess(NULL,sudocmd,NULL,NULL,FALSE,0,NULL,NULL,&si,&pi))
    {
      CloseHandle( pi.hProcess );
      CloseHandle( pi.hThread );
      hr = NOERROR;
    }else
      MessageBoxW(lpcmi->hwnd,CResStr(IDS_FILENOTFOUND),CResStr(IDS_ERR),MB_ICONSTOP);
  }
  return hr;
}

STDMETHODIMP CShellExt::GetCommandString(UINT_PTR idCmd,UINT uFlags,UINT FAR *reserved,LPSTR pszName,UINT cchMax)
{
  if (uFlags == GCS_HELPTEXT && cchMax > 35)
    wcscpy((LPWSTR)pszName,CResStr(IDS_TOOLTIP));
  return NOERROR;
}
