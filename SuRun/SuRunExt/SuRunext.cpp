/*
sudoext.cpp	http://sudown.mine.nu
by Gábor Iglói (sudown at gmail dot com)
General Public License (c) 2006

  SudoExt is a context menu handler shell extension for Sudown
  based on Tianmiao Hu's excellent GVimExt gvim extension v1.0.0.1
  at ftp://ftp.vim.org/pub/vim/pc/vim70src.zip.
*/

#include "sudoext.h"

UINT g_cRefThisDll = 0;    // Reference count of this DLL.

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
  m_pDataObj = NULL;
  ZeroMemory(&m_runcmd,sizeof(m_runcmd));
  inc_cRefThisDLL();
}

CShellExt::~CShellExt()
{
	if (m_pDataObj)
    m_pDataObj->Release();
  dec_cRefThisDLL();
}

STDMETHODIMP CShellExt::QueryInterface(REFIID riid, LPVOID FAR *ppv)
{
	*ppv = NULL;
  if (IsEqualIID(riid, IID_IShellExtInit) || IsEqualIID(riid, IID_IUnknown)) 
    *ppv = (LPSHELLEXTINIT)this;
  else if (IsEqualIID(riid, IID_IContextMenu))
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

STDMETHODIMP CShellExt::Initialize(LPCITEMIDLIST pIDFolder, LPDATAOBJECT pDataObj, HKEY hRegKey)
{
	if (m_pDataObj)
    m_pDataObj->Release();
  m_pDataObj=NULL;
  if (pDataObj) 
  {
    m_pDataObj = pDataObj;
    pDataObj->AddRef();
  }
  return NOERROR;
}

STDMETHODIMP CShellExt::QueryContextMenu(HMENU hMenu, UINT indexMenu, UINT idCmdFirst, UINT idCmdLast, UINT uFlags)
{
	UINT idCmd = idCmdFirst;
  TCHAR menucmd[_MAX_MENU];
  
  if(!(CMF_DEFAULTONLY & uFlags)) 
  {
    InsertMenu(hMenu, indexMenu++, MF_SEPARATOR|MF_BYPOSITION, NULL, NULL);
    if (m_pDataObj) 
    {	//right click target is a file
      FORMATETC fe = {CF_HDROP, NULL, DVASPECT_CONTENT, -1, TYMED_HGLOBAL};
      STGMEDIUM medium;
      if((SUCCEEDED(m_pDataObj->GetData(&fe, &medium)))&&(DragQueryFile((HDROP)medium.hGlobal, (UINT)-1, NULL, 0)==1)) 
      {
        TCHAR selectedfile[_MAX_PATH];
        TCHAR drive[_MAX_DRIVE];
        TCHAR dir[_MAX_DIR];
        TCHAR filename[_MAX_FNAME];
        TCHAR extension[_MAX_EXT];
        DragQueryFile((HDROP)medium.hGlobal, 0, selectedfile, sizeof(selectedfile)/sizeof(TCHAR));
        _wsplitpath_s(selectedfile, drive, _MAX_DRIVE, dir, _MAX_DIR, filename, _MAX_FNAME, extension, _MAX_EXT);
        wcscpy_s(m_runcmd, _MAX_PATH, L"\"");
        wcscat_s(m_runcmd, _MAX_PATH, selectedfile);
        wcscat_s(m_runcmd, _MAX_PATH, L"\"");
        wcscpy_s(menucmd, _MAX_MENU, SUDOMENU);
        if (!_wcsicmp(extension,L".exe")||!_wcsicmp(extension,L".msc")||!_wcsicmp(extension,L".cpl")) 
        {
          wcscat_s(menucmd, _MAX_MENU, filename);
          wcscat_s(menucmd, _MAX_MENU, extension);
          InsertMenu(hMenu, indexMenu++, MF_STRING|MF_BYPOSITION, idCmd++, menucmd);
        }else if (!_wcsicmp(extension,L".msi")) 
        {
          wcscat_s(m_runcmd, _MAX_PATH, L" /i");
          wcscat_s(menucmd, _MAX_MENU, INSTALLMSI);
          wcscat_s(menucmd, _MAX_MENU, filename);
          wcscat_s(menucmd, _MAX_MENU, extension);
          InsertMenu(hMenu, indexMenu++, MF_STRING|MF_BYPOSITION, idCmd++, menucmd);
          wcscpy_s(menucmd, _MAX_MENU, SUDOMENU);
          wcscat_s(menucmd, _MAX_MENU, REMOVEMSI);
          wcscat_s(menucmd, _MAX_MENU, filename);
          wcscat_s(menucmd, _MAX_MENU, extension);
          InsertMenu(hMenu, indexMenu++, MF_STRING|MF_BYPOSITION, idCmd++, menucmd);
        }
        ReleaseStgMedium(&medium);
      }
    }
    else 
    {	//right click target is folder background
      wcscpy_s(m_runcmd, _MAX_PATH, L"control");
      InsertMenu(hMenu, indexMenu++, MF_STRING|MF_BYPOSITION, idCmd++, SUDOCPL);
    }
    InsertMenu(hMenu, indexMenu++, MF_SEPARATOR|MF_BYPOSITION, NULL, NULL);
    return MAKE_HRESULT(SEVERITY_SUCCESS, 0, (USHORT)(idCmd-idCmdFirst));
  }
  return MAKE_HRESULT(SEVERITY_SUCCESS, 0, USHORT(0));
}

STDMETHODIMP CShellExt::InvokeCommand(LPCMINVOKECOMMANDINFO lpcmi)
{
  HRESULT hr = E_INVALIDARG;
	if (!HIWORD(lpcmi->lpVerb))
  {
    UINT idCmd = LOWORD(lpcmi->lpVerb);
    if (idCmd==1) 
    {
      m_runcmd[wcslen(m_runcmd)-2]=0;
      wcscat_s(m_runcmd, _MAX_PATH, L"/x");
    }
    STARTUPINFO si;
    PROCESS_INFORMATION pi;
    TCHAR sudocmd[_MAX_CMD];
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    GetWindowsDirectory(sudocmd, _MAX_PATH);
    wcscat_s(sudocmd, _MAX_CMD, SEPARATOR);
    wcscat_s(sudocmd, _MAX_CMD, SUDOEXE);
    wcscat_s(sudocmd, _MAX_CMD, m_runcmd);
    // Start the child process.
    if (CreateProcess(NULL,sudocmd,NULL,NULL,FALSE,0,NULL,NULL,&si,&pi))
    {
      CloseHandle( pi.hProcess );
      CloseHandle( pi.hThread );
      hr = NOERROR;
    }else
      MessageBoxW(lpcmi->hwnd, L"File not found: sudo.exe", L"sudoext.dll error", MB_OK);
  }
  return hr;
}

STDMETHODIMP CShellExt::GetCommandString(UINT_PTR idCmd, UINT uFlags, UINT FAR *reserved, LPSTR pszName, UINT cchMax)
{
  if (uFlags == GCS_HELPTEXT && cchMax > 35)
    wcscpy_s((LPWSTR)pszName, 35, L"Launch the selected file with Sudo");
  return NOERROR;
}
