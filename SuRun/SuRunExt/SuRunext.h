#pragma once
#include <shlobj.h>


extern "C" __declspec(dllexport) void RemoveShellExt();
extern "C" __declspec(dllexport) void InstallShellExt();

#pragma data_seg(".SHARDATA")

// {2C7B6088-5A77-4d48-BE43-30337DCA9A86}
DEFINE_GUID(CLSID_ShellExtension,0x2c7b6088,0x5a77,0x4d48,0xbe,0x43,0x30,0x33,0x7d,0xca,0x9a,0x86);
#define sGUID L"{2C7B6088-5A77-4d48-BE43-30337DCA9A86}"

// {9F555256-BE01-41d2-B8AD-D268A5D89240}
DEFINE_GUID(IID_IShellExecHook, 0x9f555256,0xbe01,0x41d2,0xb8,0xad,0xd2,0x68,0xa5,0xd8,0x92,0x40);
#define sGUIDhk L"{9F555256-BE01-41d2-B8AD-D268A5D89240}"

#pragma data_seg()

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
  bool m_pDeskClicked;
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
};

class CShellExecHook : public IShellExecuteHook
{
protected:
  ULONG	 m_cRef;
public:
  CShellExecHook();
  ~CShellExecHook();
  //IUnknown members
  STDMETHODIMP QueryInterface(REFIID, LPVOID FAR *);
  STDMETHODIMP_(ULONG) AddRef();
  STDMETHODIMP_(ULONG) Release();
  //IShellExecuteHook methods
  STDMETHODIMP Execute(LPSHELLEXECUTEINFO pei);
};
typedef CShellExt *LPCSHELLEXT;
