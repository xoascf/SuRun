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
#include <lmcons.h>

#pragma comment(lib,"User32.lib")
#pragma comment(lib,"ole32.lib")
#pragma comment(lib,"Shell32.lib")
#pragma comment(lib,"ShFolder.Lib")
#pragma comment(lib,"Shlwapi.lib")

#include "SuRunExt.h"
#include "../ResStr.h"
#include "../Helpers.h"
#include "../Setup.h"
#include "../UserGroups.h"
#include "../IsAdmin.h"
#include "Resource.h"

#include "../DBGTrace.h"

//////////////////////////////////////////////////////////////////////////////
//
// global data within shared data segment to allow sharing across instances
//
//////////////////////////////////////////////////////////////////////////////
#pragma data_seg(".SHDATA")

UINT g_cRefThisDll = 0;    // Reference count of this DLL.

DWORD g_LoadAppInitDLLs = 0;

#ifdef _Win64
DWORD g_LoadAppInit32DLLs = 0;
#endif _Win64

//////////////////////////////////////////////////////////////////////////////
//
// Strings: these are defined in SysMenuHook.cpp and placed in ".SHDATA"
//
//////////////////////////////////////////////////////////////////////////////
extern TCHAR sFileNotFound[MAX_PATH];
extern TCHAR sSuRun[MAX_PATH];
extern TCHAR sSuRunCmd[MAX_PATH];
extern TCHAR sSuRunExp[MAX_PATH];
extern TCHAR sErr[MAX_PATH];
extern TCHAR sTip[MAX_PATH];

#pragma data_seg()
#pragma comment(linker, "/section:.SHDATA,RWS")

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
class CShellExt : public IContextMenu, IShellExtInit
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

//static void AddAppInit(LPCTSTR Key,LPCTSTR Dll)
//{
//  /* ToDo: Do not use AppInit_Dlls! */
//  TCHAR s[4096]={0};
//  GetRegStr(HKLM,Key,_T("AppInit_DLLs"),s,4096);
//  if (_tcsstr(s,Dll)==0)
//  {
//    if (s[0])
//      _tcscat(s,_T(","));
//    _tcscat(s,Dll);
//    SetRegStr(HKLM,Key,_T("AppInit_DLLs"),s);
//  }/**/
//}
//static void RemoveAppInit(LPCTSTR Key,LPCTSTR Dll)
//{
//  /* ToDo: Do not use AppInit_Dlls! */
//  //remove from AppInit_Dlls
//  TCHAR s[4096]={0};
//  GetRegStr(HKLM,Key,_T("AppInit_DLLs"),s,4096);
//  LPTSTR p=_tcsstr(s,Dll);
//  if (p!=0)
//  {
//    LPTSTR p1=p+_tcslen(Dll);
//    if((*p1==' ')||(*p1==','))
//      p1++;
//    if (p!=s)
//      p--;
//    *p=0;
//    if (*(p1))
//      _tcscat(p,p1);
//    SetRegStr(HKLM,Key,_T("AppInit_DLLs"),s);
//  }
//  /**/
//}

__declspec(dllexport) void InstallShellExt()
{
  //COM-Object
  SetRegStr(HKCR,L"CLSID\\" sGUID,L"",L"SuRun Shell Extension");
  SetRegStr(HKCR,L"CLSID\\" sGUID L"\\InProcServer32",L"",L"SuRunExt.dll");
  SetRegStr(HKCR,L"CLSID\\" sGUID L"\\InProcServer32",L"ThreadingModel",L"Apartment");
  //Desktop-Background-Hook
  SetRegStr(HKCR,L"Directory\\Background\\shellex\\ContextMenuHandlers\\SuRun",L"",sGUID);
  SetRegStr(HKCR,L"Folder\\shellex\\ContextMenuHandlers\\SuRun",L"",sGUID);
  //SetRegStr(HKCR,L"*\\shellex\\ContextMenuHandlers\\SuRun",L"",sGUID);
  //self Approval
  SetRegStr(HKLM,L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Shell Extensions\\Approved",
            sGUID,L"SuRun Shell Extension");
  //Disable "Open with..." when right clicking on SuRun.exe
  SetRegStr(HKCR,L"Applications\\SuRun.exe",L"NoOpenWith",L"");
  //Disable putting SuRun in the frequently used apps in the start menu
  SetRegStr(HKCR,L"Applications\\SuRun.exe",L"NoStartPage",L"");
  //add to AppInit_Dlls
//  g_LoadAppInitDLLs=GetRegInt(HKLM,AppInit,_T("LoadAppInit_DLLs"),0);
//  SetRegInt(HKLM,AppInit,_T("LoadAppInit_DLLs"),1);
//  AddAppInit(AppInit,_T("SuRunExt.dll"));
//#ifdef _WIN64
//  g_LoadAppInit32DLLs=GetRegInt(HKLM,AppInit32,_T("LoadAppInit_DLLs"),0);
//  SetRegInt(HKLM,AppInit32,_T("LoadAppInit_DLLs"),1);
//  AddAppInit(AppInit32,_T("SuRunExt32.dll"));
//#endif _WIN64
}

__declspec(dllexport) void RemoveShellExt()
{
  //Clean up:
  //AppInit_Dlls
//  SetRegInt(HKLM,AppInit,_T("LoadAppInit_DLLs"),g_LoadAppInitDLLs);
//  RemoveAppInit(AppInit,_T("SuRunExt.dll"));
//#ifdef _WIN64
//  RemoveAppInit(AppInit32,_T("SuRunExt32.dll"));
//  SetRegInt(HKLM,AppInit32,_T("LoadAppInit_DLLs"),g_LoadAppInit32DLLs);
//#endif _WIN64
  //"Open with..." when right clicking on SuRun.exe
  DelRegKey(HKCR,L"Applications\\SuRun.exe");
  //COM-Object
  DelRegKey(HKCR,L"CLSID\\" sGUID);
  //Desktop-Background-Hook
  DelRegKey(HKCR,L"Directory\\Background\\shellex\\ContextMenuHandlers\\SuRun");
  DelRegKey(HKCR,L"Folder\\shellex\\ContextMenuHandlers\\SuRun");
  //DelRegKey(HKEY_CLASSES_ROOT,L"*\\shellex\\ContextMenuHandlers\\SuRun");
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
UINT g_CF_FileNameW=RegisterClipboardFormat(CFSTR_FILENAMEW);
UINT g_CF_ShellIdList=RegisterClipboardFormat(CFSTR_SHELLIDLIST);

#define HIDA_GetPIDLFolder(pida) (LPCITEMIDLIST)(((LPBYTE)pida)+(pida)->aoffset[0])
#define HIDA_GetPIDLItem(pida, i) (LPCITEMIDLIST)(((LPBYTE)pida)+(pida)->aoffset[i+1])

static void PrintDataObj(LPDATAOBJECT pDataObj)
{
  IEnumFORMATETC *pefEtc = 0;
  if(SUCCEEDED(pDataObj->EnumFormatEtc(DATADIR_GET, &pefEtc)) && SUCCEEDED(pefEtc->Reset()))
  while(TRUE)
  {
    FORMATETC fEtc;
    ULONG ulFetched = 0L;
    if(FAILED(pefEtc->Next(1,&fEtc,&ulFetched)) || (ulFetched <= 0))
      break;
    STGMEDIUM stgM;
    if(SUCCEEDED(pDataObj->GetData(&fEtc, &stgM)))
    {
      switch (stgM.tymed)
      {
      case TYMED_HGLOBAL:
        if (fEtc.cfFormat==CF_HDROP)
        {
          UINT n = DragQueryFile((HDROP)stgM.hGlobal,0xFFFFFFFF,NULL,0);
          if(n>=1) for(UINT x = 0; x < n; x++)
          {
            TCHAR f[MAX_PATH]={0};
            DragQueryFile((HDROP)stgM.hGlobal,x,f,MAX_PATH-1);
            DBGTrace1("--------- TYMED_HGLOBAL, CF_HDROP, File=%s",f);
          }
        }else if (fEtc.cfFormat==g_CF_FileNameW)
        {
          DBGTrace1("--------- TYMED_HGLOBAL, CFSTR_FILENAMEW:%s",(LPCSTR)stgM.hGlobal); 
        }else if (fEtc.cfFormat==g_CF_ShellIdList)
        {
          TCHAR s[MAX_PATH]={0};
          DBGTrace1("--------- TYMED_HGLOBAL, CFSTR_SHELLIDLIST, %d Items",((LPIDA)stgM.hGlobal)->cidl); 
          LPCITEMIDLIST pIDFolder = HIDA_GetPIDLFolder((LPIDA)stgM.hGlobal);
          if (pIDFolder)
          {
            SHGetPathFromIDList(pIDFolder,s);
            DBGTrace1("------------------ Folder=%s",s);
          }
          for (UINT n=0;n<((LPIDA)stgM.hGlobal)->cidl;n++)
          {
            LPCITEMIDLIST pidlItem0=HIDA_GetPIDLItem((LPIDA)stgM.hGlobal,0);
            SHGetPathFromIDList(pidlItem0,s);
            DBGTrace2("------------------ Item[%d]=%s",n,s);
          }
        }else
        {
          TCHAR cfn[MAX_PATH]={0};
          GetClipboardFormatName(fEtc.cfFormat,cfn,MAX_PATH);
          DBGTrace2("--------- TYMED_HGLOBAL, CF_: %d (%s)",fEtc.cfFormat,cfn);
        }
        break;
      case TYMED_FILE:
        DBGTrace("--------- TYMED_FILE");
        break;
      case TYMED_ISTREAM:
        DBGTrace("--------- TYMED_ISTREAM");
        break;
      case TYMED_ISTORAGE:
        DBGTrace("--------- TYMED_ISTORAGE");
        break;
      case TYMED_GDI:
        DBGTrace("--------- TYMED_GDI");
        break;
      case TYMED_MFPICT:
        DBGTrace("--------- TYMED_MFPICT");
        break;
      case TYMED_ENHMF:
        DBGTrace("--------- TYMED_ENHMF");
        break;
      case TYMED_NULL:
        DBGTrace("--------- TYMED_NULL");
        break;
      default:
        DBGTrace1("--------- unknown tymed: %d",stgM.tymed);
      }
    }
  }
  if(pefEtc)
    pefEtc->Release();
}

STDMETHODIMP CShellExt::Initialize(LPCITEMIDLIST pIDFolder, LPDATAOBJECT pDataObj, HKEY hRegKey)
{
#ifdef _DEBUG
//  TCHAR Path[MAX_PATH]={0};
//  if (pIDFolder)
//    SHGetPathFromIDList(pIDFolder,Path);
//  TCHAR FileClass[MAX_PATH]={0};
//  if(hRegKey)
//    GetRegStr(hRegKey,0,L"",FileClass,MAX_PATH);
//  TCHAR File[MAX_PATH]={0};
//  if(pDataObj)
//  {
//    FORMATETC fe = {CF_HDROP, NULL, DVASPECT_CONTENT, -1, TYMED_HGLOBAL};
//    STGMEDIUM stm;
//    if (SUCCEEDED(pDataObj->GetData(&fe,&stm)))
//    {
//      if(DragQueryFile((HDROP)stm.hGlobal,(UINT)-1,NULL,0)==1)
//        DragQueryFile((HDROP)stm.hGlobal,0,File,MAX_PATH-1);
//      ReleaseStgMedium(&stm);
//    }
//  }
//  DBGTrace3("CShellExt::Initialize(%s,%s,%s)",Path,File,FileClass);
//  if(pDataObj)
//    PrintDataObj(pDataObj);
#endif _DEBUG
  zero(m_ClickFolderName);
  m_pDeskClicked=FALSE;
  {
    //Non SuRunners don't need the Shell Extension!
    TCHAR User[UNLEN+GNLEN+2]={0};
    GetProcessUserName(GetCurrentProcessId(),User);
    if (!IsInSuRunners(User))
      return NOERROR;
  }
  //Non Admins don't need the Shell Extension!
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
