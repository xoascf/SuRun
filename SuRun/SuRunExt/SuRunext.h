//sudoext.h

#include <shlobj.h>
#include <initguid.h>
#include <shlguid.h>

#pragma comment(lib,"User32.lib")
#pragma comment(lib,"ole32.lib")
#pragma comment(lib,"Shell32.lib")

#define SUDOEXE	L"sudo.exe "
#define SEPARATOR L"\\"
#define SUDOMENU L"* sudo "
#define SUDOCPL L"* sudo Control Panel"
#define INSTALLMSI L"install "
#define REMOVEMSI L"uninstall "

#define _MAX_MENU	_MAX_PATH+16
#define _MAX_CMD	_MAX_PATH*2

// Initialize GUIDs (should be done only and at-least once per DLL/EXE)
// NOTE!!!  If you use this shell extension as a starting point,
// you MUST change the GUID below.
// Simply run GUIDGEN.EXE to generate a new GUID.

// SudoExt class GUID:
// {7DB2D002-7357-11DB-9693-00E08161165F}
// {0x7db2d002, 0x7357, 0x11db, {0x96, 0x93, 0x00, 0xe0, 0x81, 0x61, 0x16, 0x5f}}

#pragma data_seg(".text")
#define INITGUID

#ifndef wcscpy_s
#define wcscpy_s(s1,l,s2) wcscpy(s1,s2)
#define wcscat_s(s1,l,s2) wcscat(s1,s2)
#define _wsplitpath_s(p,d,ds,D,Ds,f,fs,e,es)     _wsplitpath(p,d,D,f,e)
#endif wcscpy_s

DEFINE_GUID(CLSID_ShellExtension, 0x7db2d002, 0x7357, 0x11db, 0x96, 0x93, 0x00, 0xe0, 0x81, 0x61, 0x16, 0x5f);

// this class factory object creates context menu handlers for windows 32 shell
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

// this is the actual OLE Shell context menu handler
class CShellExt : public IContextMenu, IShellExtInit
{
protected:
  ULONG	 m_cRef;
  LPDATAOBJECT m_pDataObj;
  TCHAR m_runcmd[_MAX_PATH];
public:
  CShellExt();
  ~CShellExt();
  
  //IUnknown members
  STDMETHODIMP QueryInterface(REFIID, LPVOID FAR *);
  STDMETHODIMP_(ULONG) AddRef();
  STDMETHODIMP_(ULONG) Release();
  
  //IShell members
  STDMETHODIMP QueryContextMenu(HMENU, UINT, UINT, UINT, UINT);
  
  STDMETHODIMP InvokeCommand(LPCMINVOKECOMMANDINFO);
  
  STDMETHODIMP GetCommandString(UINT_PTR, UINT, UINT FAR *, LPSTR, UINT);
  
  //IShellExtInit methods
  STDMETHODIMP Initialize(LPCITEMIDLIST, LPDATAOBJECT, HKEY);
};

typedef CShellExt *LPCSHELLEXT;
#pragma data_seg()
