#pragma once

#include <shlobj.h>
#include <initguid.h>
#include <shlguid.h>

#pragma comment(lib,"User32.lib")
#pragma comment(lib,"ole32.lib")
#pragma comment(lib,"Shell32.lib")

#define SURUNEXE	  L"SuRun.exe "
#define SEPARATOR   L"\\"
#define SUDOMENU    L"* SuRun "
#define SUDOCPL     L"* SuRun Control Panel"
#define INSTALLMSI  L"install "
#define REMOVEMSI   L"uninstall "

#pragma data_seg(".text")
#define INITGUID

// {2C7B6088-5A77-4d48-BE43-30337DCA9A86}
DEFINE_GUID(CLSID_ShellExtension,0x2c7b6088,0x5a77,0x4d48,0xbe,0x43,0x30,0x33,0x7d,0xca,0x9a,0x86);

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
  BOOL m_bDeskTop;
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
