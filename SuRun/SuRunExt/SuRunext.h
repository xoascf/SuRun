#pragma once
#include <shlobj.h>


extern "C" __declspec(dllexport) void RemoveShellExt();
extern "C" __declspec(dllexport) void InstallShellExt();

// {2C7B6088-5A77-4d48-BE43-30337DCA9A86}
DEFINE_GUID(CLSID_ShellExtension,0x2c7b6088,0x5a77,0x4d48,0xbe,0x43,0x30,0x33,0x7d,0xca,0x9a,0x86);
#define sGUID L"{2C7B6088-5A77-4d48-BE43-30337DCA9A86}"

#define ControlAsAdmin  L"ControlAsAdmin"  //"Control Panel As Admin" on Desktop Menu
#define CmdHereAsAdmin  L"CmdHereAsAdmin"  //"Cmd here As Admin" on Folder Menu
#define RestartAsAdmin  L"RestartAsAdmin"  //"Restart As Admin" in System-Menu
#define StartAsAdmin    L"StartAsAdmin"    //"Start As Admin" in System-Menu


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
class CShellExt : public IContextMenu, IShellExtInit, IShellExecuteHook
{
protected:
  ULONG	 m_cRef;
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
