//////////////////////////////////////////////////////////////////////////////
//
// This source code is part of SuRun
//
// Some sources in this project evolved from Microsoft sample code, some from 
// other free sources. The Shield Icons are taken from Windows XP Service Pack 
// 2 (xpsp2res.dll) 
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
#include <Winwlx.h>
#include <psapi.h>
#include <tlhelp32.h>
#include <USERENV.H>
#include <wtsapi32.h>

#pragma comment(lib,"User32.lib")
#pragma comment(lib,"ole32.lib")
#pragma comment(lib,"Shell32.lib")
#pragma comment(lib,"ShFolder.Lib")
#pragma comment(lib,"Shlwapi.lib")
#pragma comment(lib,"PSAPI.lib")
#pragma comment(lib,"Userenv.lib")
#pragma comment(lib,"WTSApi32.lib")

#include "../Setup.h"
#include "../Service.h"
#include "SuRunExt.h"
#include "IATHook.h"
#include "../ResStr.h"
#include "../Helpers.h"
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

#pragma data_seg()
#pragma comment(linker, "/section:.SHDATA,RWS")

HINSTANCE   l_hInst     = NULL;
TCHAR       l_User[514] = {0};
BOOL        l_bSetHook  = TRUE;
DWORD       l_Groups    = 0;

#define     l_IsAdmin     ((l_Groups&IS_IN_ADMINS)!=0)
#define     l_IsSuRunner  ((l_Groups&IS_IN_SURUNNERS)!=0)

UINT        WM_SYSMH0   = -2;
UINT        WM_SYSMH1   = -2;

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
  TCHAR m_ClickFolderName[4096];
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
  else if (GetUseIShExHook && IsEqualIID(riid, IID_IShellExecuteHook))
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
#define HIDA_GetPIDLFolder(pida) (LPCITEMIDLIST)(((LPBYTE)pida)+(pida)->aoffset[0])
#define HIDA_GetPIDLItem(pida, i) (LPCITEMIDLIST)(((LPBYTE)pida)+(pida)->aoffset[i+1])

static UINT g_CF_FileNameW=0;
static UINT g_CF_ShellIdList=0;

static void PrintDataObj(LPDATAOBJECT pDataObj)
{
  if (g_CF_FileNameW==0)
    g_CF_FileNameW=RegisterClipboardFormat(CFSTR_FILENAMEW);
  if(g_CF_ShellIdList==0)
    g_CF_ShellIdList=RegisterClipboardFormat(CFSTR_SHELLIDLIST);
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
            TCHAR f[4096]={0};
            DragQueryFile((HDROP)stgM.hGlobal,x,f,4096-1);
            DBGTrace1("--------- TYMED_HGLOBAL, CF_HDROP, File=%s",f);
          }
        }else if (fEtc.cfFormat==g_CF_FileNameW)
        {
          DBGTrace1("--------- TYMED_HGLOBAL, CFSTR_FILENAMEW:%s",(LPCSTR)stgM.hGlobal); 
        }else if (fEtc.cfFormat==g_CF_ShellIdList)
        {
          TCHAR s[4096]={0};
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
          TCHAR cfn[4096]={0};
          GetClipboardFormatName(fEtc.cfFormat,cfn,4096);
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
#ifdef DoDBGTrace
//  TCHAR Path[4096]={0};
//  if (pIDFolder)
//    SHGetPathFromIDList(pIDFolder,Path);
//  TCHAR FileClass[4096]={0};
//  if(hRegKey)
//    GetRegStr(hRegKey,0,L"",FileClass,4096);
//  TCHAR File[4096]={0};
//  if(pDataObj)
//  {
//    FORMATETC fe = {CF_HDROP, NULL, DVASPECT_CONTENT, -1, TYMED_HGLOBAL};
//    STGMEDIUM stm;
//    if (SUCCEEDED(pDataObj->GetData(&fe,&stm)))
//    {
//      if(DragQueryFile((HDROP)stm.hGlobal,(UINT)-1,NULL,0)==1)
//        DragQueryFile((HDROP)stm.hGlobal,0,File,4096-1);
//      ReleaseStgMedium(&stm);
//    }
//  }
//  DBGTrace3("CShellExt::Initialize(%s,%s,%s)",Path,File,FileClass);
//  if(pDataObj)
//    PrintDataObj(pDataObj);
#endif DoDBGTrace
  zero(m_ClickFolderName);
  m_pDeskClicked=FALSE;
  //Non SuRunners don't need the Shell Extension!
  if ((!l_IsSuRunner)||GetHideFromUser(l_User))
    return NOERROR;
  //Non Admins don't need the Shell Extension!
  if (!l_bSetHook)
    return NOERROR;
  if (pDataObj==0)
  {
    SHGetPathFromIDList(pIDFolder,m_ClickFolderName);
    PathRemoveBackslash(m_ClickFolderName);
    TCHAR s[4096]={0};
    SHGetFolderPath(0,CSIDL_DESKTOPDIRECTORY,0,SHGFP_TYPE_CURRENT,s);
    PathRemoveBackslash(s);
    m_pDeskClicked=_tcsicmp(s,m_ClickFolderName)==0;
    if(!m_pDeskClicked)
    {
      SHGetFolderPath(0,CSIDL_COMMON_DESKTOPDIRECTORY,0,SHGFP_TYPE_CURRENT,s);
      PathRemoveBackslash(s);
      m_pDeskClicked=_tcsicmp(s,m_ClickFolderName)==0;
    }
  }else
  {
    FORMATETC fe = {CF_HDROP, NULL, DVASPECT_CONTENT, -1, TYMED_HGLOBAL};
    if(g_CF_ShellIdList==0)
      g_CF_ShellIdList=RegisterClipboardFormat(CFSTR_SHELLIDLIST);
    FORMATETC fe1 = {g_CF_ShellIdList, NULL, DVASPECT_CONTENT, -1, TYMED_HGLOBAL};
    STGMEDIUM m;
    if ((SUCCEEDED(pDataObj->GetData(&fe,&m)))
      &&(DragQueryFile((HDROP)m.hGlobal,(UINT)-1,NULL,0)==1)) 
    {
      TCHAR path[4096];
      DragQueryFile((HDROP)m.hGlobal, 0, path, countof(path));
      if (PathIsDirectory(path))
        _tcscpy(m_ClickFolderName,path);
      ReleaseStgMedium(&m);
    }else if (SUCCEEDED(pDataObj->GetData(&fe1,&m)))
    {
      TCHAR s[4096]={0};
      if (((LPIDA)m.hGlobal)->cidl==1)
      {
        LPCITEMIDLIST pidlItem0=(LPCITEMIDLIST)(((LPBYTE)m.hGlobal)+((LPIDA)m.hGlobal)->aoffset[1]);
        if(SHGetPathFromIDList(pidlItem0,s))
          _tcscpy(m_ClickFolderName,s);
      }
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
      if ((!IsWin7)&&(GetCtrlAsAdmin))
      {
        //right click target is folder background
        InsertMenu(hMenu, indexMenu++, MF_SEPARATOR|MF_BYPOSITION, NULL, NULL);
        InsertMenu(hMenu, indexMenu++, MF_STRING|MF_BYPOSITION, id++, CResStr(l_hInst,IDS_SURUN));
        InsertMenu(hMenu, indexMenu++, MF_SEPARATOR|MF_BYPOSITION, NULL, NULL);
      }
    }else
    if(m_ClickFolderName[0])
    {
      BOOL bCmd=GetCmdAsAdmin;
      BOOL bExp=(!IsWin7)&& GetExpAsAdmin;
      if (bExp || bCmd)
        InsertMenu(hMenu, indexMenu++, MF_SEPARATOR|MF_BYPOSITION, NULL, NULL);
      //right click target is folder background
      if (bCmd)
        InsertMenu(hMenu, indexMenu++, MF_STRING|MF_BYPOSITION, id, CResStr(l_hInst,IDS_SURUNCMD));
      id++;
      if (bExp)
        InsertMenu(hMenu, indexMenu++, MF_STRING|MF_BYPOSITION, id, CResStr(l_hInst,IDS_SURUNEXP));
      id++;
      if (bExp || bCmd)
        InsertMenu(hMenu, indexMenu++, MF_SEPARATOR|MF_BYPOSITION, NULL, NULL);
    }
  }
  return MAKE_HRESULT(SEVERITY_SUCCESS, 0, (USHORT)(id-idCmdFirst));
}

STDMETHODIMP CShellExt::GetCommandString(UINT_PTR idCmd,UINT uFlags,UINT FAR *reserved,LPSTR pszName,UINT cchMax)
{
  CResStr s(l_hInst,IDS_TOOLTIP);
  if (m_pDeskClicked && (uFlags == GCS_HELPTEXT) && (cchMax > wcslen(s)))
    wcscpy((LPWSTR)pszName,s);
  return NOERROR;
}

STDMETHODIMP CShellExt::InvokeCommand(LPCMINVOKECOMMANDINFO lpcmi)
{
  HRESULT hr = E_INVALIDARG;
	if (!HIWORD(lpcmi->lpVerb))
  {
    STARTUPINFO si;
    PROCESS_INFORMATION pi;
    TCHAR cmd[4096];
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    GetSystemWindowsDirectory(cmd,4096);
    PathAppend(cmd, _T("SuRun.exe"));
    PathQuoteSpaces(cmd);
    if (m_pDeskClicked)
      _tcscat(cmd,L" control");
    else
    {
      if (LOWORD(lpcmi->lpVerb)==0)
        _tcscat(cmd,L" cmd /D /T:4E /K cd /D ");
      else
        _tcscat(cmd,L" explorer /e, ");
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
      MessageBoxW(lpcmi->hwnd,CResStr(l_hInst,IDS_FILENOTFOUND),CResStr(l_hInst,IDS_ERR),MB_ICONSTOP|MB_SYSTEMMODAL);
  }
  return hr;
}

static CRITICAL_SECTION l_SxHkCs={0};
//////////////////////////////////////////////////////////////////////////////
// IShellExecuteHook
//////////////////////////////////////////////////////////////////////////////
STDMETHODIMP CShellExt::Execute(LPSHELLEXECUTEINFO pei)
{
#ifdef DoDBGTrace
//  DBGTrace15("SuRun ShellExtHook: siz=%d, msk=%X wnd=%X, verb=%s, file=%s, parms=%s, "
//    L"dir=%s, nShow=%X, inst=%X, idlist=%X, class=%s, hkc=%X, hotkey=%X, hicon=%X, hProc=%X",
//    pei->cbSize,pei->fMask,pei->hwnd,pei->lpVerb,pei->lpFile,pei->lpParameters,
//    pei->lpDirectory,pei->nShow,pei->hInstApp,pei->lpIDList,
//    pei->lpClass,
//    pei->hkeyClass,pei->dwHotKey,pei->hIcon,pei->hProcess);
#endif DoDBGTrace
  //Admins don't need the ShellExec Hook!
  if (l_IsAdmin)
    return S_FALSE;
  //Non SuRunners don't need the ShellExec Hook!
  if ((!l_IsSuRunner))
    return S_FALSE;
  if (!pei)
  {
    DBGTrace("SuRun ShellExtHook Error: LPSHELLEXECUTEINFO==NULL");
    return S_FALSE;
  }
  if(pei->cbSize<sizeof(SHELLEXECUTEINFO))
  {
    DBGTrace2("SuRun ShellExtHook Error: invalid Size (expected=%d;real=%d)",
      sizeof(SHELLEXECUTEINFO),pei->cbSize);
    return S_FALSE;
  }
  if (!pei->lpFile)
  {
    DBGTrace("SuRun ShellExtHook Error: invalid LPSHELLEXECUTEINFO->lpFile==NULL!");
#ifdef DoDBGTrace
    DBGTrace15("  siz=%d, msk=%X wnd=%X, verb=%s, file=%s, parms=%s, "
      L"dir=%s, nShow=%X, inst=%X, idlist=%X, class=%s, hkc=%X, hotkey=%X, hicon=%X, hProc=%X",
      pei->cbSize,pei->fMask,pei->hwnd,pei->lpVerb,pei->lpFile,pei->lpParameters,
      pei->lpDirectory,pei->nShow,pei->hInstApp,pei->lpIDList,
      pei->lpClass,
      pei->hkeyClass,pei->dwHotKey,pei->hIcon,pei->hProcess);
#endif DoDBGTrace
    return S_FALSE;
  }
  EnterCriticalSection(&l_SxHkCs);
  static TCHAR tmp[4096];
  zero(tmp);
  static TCHAR cmd[4096];
  zero(cmd);
  //check if this Programm has an Auto-SuRun-Entry in the List
  _tcscpy(tmp,pei->lpFile);
  PathQuoteSpaces(tmp);
  //Verb must be "open" or empty
  BOOL bNoAutoRun=TRUE;
  BOOL bRunAs=FALSE;
  if (pei->lpVerb && (_tcslen(pei->lpVerb)!=0)
    &&(_tcsicmp(pei->lpVerb,L"open")!=0)
    &&(_tcsicmp(pei->lpVerb,L"cplopen")!=0))
  {
    if (GetHandleRunAs && (_tcsicmp(pei->lpVerb,L"runas")==0))
    {
      bRunAs=TRUE;
    }else
    if (_tcsicmp(pei->lpVerb,L"AutoRun")==0)
    {
      //AutoRun: get open command
      PathAppend(tmp,L"AutoRun.inf");
      if (GetPrivateProfileInt(L"AutoRun",L"UseAutoPlay",0,tmp)!=0)
        return LeaveCriticalSection(&l_SxHkCs),S_FALSE;
      GetPrivateProfileString(L"AutoRun",L"open",L"",cmd,countof(cmd)-1,tmp);
      if (!cmd[0])
        return LeaveCriticalSection(&l_SxHkCs),S_FALSE;
      _tcscpy(tmp,cmd);
      bNoAutoRun=FALSE;
    }else
    {
      DBGTrace1("SuRun ShellExtHook Error: invalid verb (%s)!",pei->lpVerb);
#ifdef DoDBGTrace
      DBGTrace15("  siz=%d, msk=%X wnd=%X, verb=%s, file=%s, parms=%s, "
        L"dir=%s, nShow=%X, inst=%X, idlist=%X, class=%s, hkc=%X, hotkey=%X, hicon=%X, hProc=%X",
        pei->cbSize,pei->fMask,pei->hwnd,pei->lpVerb,pei->lpFile,pei->lpParameters,
        pei->lpDirectory,pei->nShow,pei->hInstApp,pei->lpIDList,
        pei->lpClass,
        pei->hkeyClass,pei->dwHotKey,pei->hIcon,pei->hProcess);
#endif DoDBGTrace
      return LeaveCriticalSection(&l_SxHkCs),S_FALSE;
    }
  }
  if ( bNoAutoRun && pei->lpParameters && _tcslen(pei->lpParameters))
  {
    _tcscat(tmp,L" ");
    _tcscat(tmp,pei->lpParameters);
  }
  static TCHAR CurDir[4096];
  zero(CurDir);
  if (pei->lpDirectory && (*pei->lpDirectory) )
    _tcscpy(CurDir,pei->lpDirectory);
  else
    GetCurrentDirectory(countof(CurDir),CurDir);
  
  ResolveCommandLine(tmp,CurDir,tmp);
  SetCurrentDirectory(cmd);

  RegDelVal(HKCU,SURUNKEY,L"LastFailedCmd");

  GetSystemWindowsDirectory(cmd,countof(cmd));
#ifndef _SR32
  PathAppend(cmd, _T("SuRun.exe"));
#else _SR32
  PathAppend(cmd, _T("SuRun32.bin"));
#endif _SR32
  PathQuoteSpaces(cmd);
  if (_wcsnicmp(cmd,tmp,wcslen(cmd))==0)
    //Never start SuRun administrative
    return LeaveCriticalSection(&l_SxHkCs),S_FALSE;
  //CTimeLog l(L"ShellExecHook TestAutoSuRun(%s)",tmp);
  //ToDo: Directly write to service pipe!
  static PROCESS_INFORMATION rpi;
  zero(rpi);
  if (bRunAs)
    _stprintf(&cmd[wcslen(cmd)],L" /RUNAS %s",tmp);
  else
    _stprintf(&cmd[wcslen(cmd)],L" /QUIET /TESTAA %d %x %s",GetCurrentProcessId(),&rpi,tmp);
  STARTUPINFO si;
  PROCESS_INFORMATION pi;
  ZeroMemory(&si, sizeof(si));
  si.cb = sizeof(si);
  // Start the child process.
  if (CreateProcess(NULL,cmd,NULL,NULL,FALSE,0,NULL,CurDir,&si,&pi))
  {
    CloseHandle(pi.hThread);
    DWORD ExitCode=ERROR_ACCESS_DENIED;
    if((WaitForSingleObject(pi.hProcess,INFINITE)==WAIT_OBJECT_0)
      && GetExitCodeProcess(pi.hProcess,(DWORD*)&ExitCode))
    {
      //ExitCode==-2 means that the program is not in the WhiteList
      if (ExitCode==RETVAL_OK)
      {
        pei->hInstApp=(HINSTANCE)33;
        //return valid PROCESS_INFORMATION!
        if(pei->fMask&SEE_MASK_NOCLOSEPROCESS)
          pei->hProcess=OpenProcess(SYNCHRONIZE,false,rpi.dwProcessId);
      }else 
      {
        pei->hInstApp=bRunAs?(HINSTANCE)34:(HINSTANCE)SE_ERR_ACCESSDENIED;
        //Tell IAT-Hook to not check "tmp" again!
        if (!bRunAs)
          SetRegStr(HKCU,SURUNKEY,L"LastFailedCmd",tmp);
      }
    }else
      DBGTrace1("SuRun ShellExtHook: WHOOPS! %s",cmd);
    CloseHandle(pi.hProcess);
    LeaveCriticalSection(&l_SxHkCs);
    return ((ExitCode==RETVAL_OK)||(ExitCode==RETVAL_CANCELLED))?S_OK:S_FALSE;
  }else
    DBGTrace2("SuRun ShellExtHook: CreateProcess(%s) failed: %s",cmd,GetLastErrorNameStatic());
  return LeaveCriticalSection(&l_SxHkCs),S_FALSE;
}

//////////////////////////////////////////////////////////////////////////////
//
// Control Panel Applet
//
//////////////////////////////////////////////////////////////////////////////
#include <Cpl.h>

LONG CALLBACK CPlApplet(HWND hwnd,UINT uMsg,LPARAM lParam1,LPARAM lParam2)
{ 
  BOOL noCPL=HideSuRun(l_User,l_Groups);
  switch (uMsg) 
  { 
  case CPL_INIT:
    if (noCPL)
      return FALSE;
    return TRUE; 
  case CPL_GETCOUNT:
    if (noCPL)
      return 0;
    return 1; 
  case CPL_INQUIRE:
    {
      if (noCPL)
        return 1;
      LPCPLINFO cpli=(LPCPLINFO)lParam2; 
      cpli->lData = 0; 
      cpli->idIcon = IDI_MAINICON;
      cpli->idName = IDS_CPLNAME;
      cpli->idInfo = 0;
      return 0;
    }
  case CPL_DBLCLK:    // application icon double-clicked 
    {
      if (noCPL)
        return 1;
      TCHAR fSuRunExe[4096];
      GetSystemWindowsDirectory(fSuRunExe,4096);
      PathAppend(fSuRunExe,L"SuRun.exe");
      PathQuoteSpaces(fSuRunExe);
      ShellExecute(hwnd,L"open",fSuRunExe,L"/Setup",0,SW_SHOW);
      return 0;
    }
  } 
  return 0; 
} 

//////////////////////////////////////////////////////////////////////////////
// 
//  KillIfSuRunProcess
// 
//////////////////////////////////////////////////////////////////////////////
int KillIfSuRunProcess(PSID LogonSID,LUID SrcId,DWORD PID)
{
  HANDLE hp=OpenProcess(PROCESS_ALL_ACCESS,0,PID);
  if (!hp)
    return -1;
  HANDLE ht=0;
  int RetVal=0;
  if(OpenProcessToken(hp,TOKEN_ALL_ACCESS,&ht))
  {
    if (!IsLocalSystem(ht))
    {
      TOKEN_SOURCE tsrc;
      DWORD n=0;
      if (GetTokenInformation(ht,TokenSource,&tsrc,sizeof(tsrc),&n))
      {
        PSID tSID=GetLogonSid(ht);
        if (tSID && IsValidSid(tSID) && EqualSid(LogonSID,tSID))
        {
          if ((memcmp(&SrcId,&tsrc.SourceIdentifier,sizeof(LUID))==0)
            &&(strcmp(tsrc.SourceName,"SuRun")==0))
          {
            TerminateProcess(hp,0);
            //DBGTrace1("SuRunLogoffUser: PID:%d KILLED",PID);
            RetVal=1;
          }//else
            //DBGTrace1("SuRunLogoffUser: PID:%d was NOT killed",PID);
        }//else
          //DBGTrace1("Sid(%d) mismatch",PID);
        free(tSID);
      }else
        DBGTrace2("GetTokenInformation(%d) failed: %s",PID,GetLastErrorNameStatic());
    }
    CloseHandle(ht);
  }else
    DBGTrace2("OpenProcessToken(%d) failed: %s",PID,GetLastErrorNameStatic());
  CloseHandle(hp);
  return RetVal;
}

__declspec(dllexport) void TerminateAllSuRunnedProcesses(HANDLE hToken)
{
  //Terminate all Processes that have the same logon SID and 
  //"SuRun" as the Token source name
  PSID LogonSID=GetLogonSid(hToken);
  TOKEN_SOURCE Logonsrc;
  DWORD n=0;
  GetTokenInformation(hToken,TokenSource,&Logonsrc,sizeof(Logonsrc),&n);
  //EnumProcesses does not work here! need to call WTSEnumerateProcesses
  n=0;
  WTS_PROCESS_INFO* ppi=0;
  if(WTSEnumerateProcesses(WTS_CURRENT_SERVER_HANDLE,0,1,&ppi,&n) && n)
  {
    for (DWORD i=0;i<n;i++)
      KillIfSuRunProcess(LogonSID,Logonsrc.SourceIdentifier,ppi[i].ProcessId);
    WTSFreeMemory(ppi);
  }else
  {
    //Win2k: if WTSEnumerateProcesses does not work, try ToolHelp32
    HANDLE h=CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0);
    if(h!=INVALID_HANDLE_VALUE)
    {
      PROCESSENTRY32 pe32={0};
      pe32.dwSize=sizeof(pe32);
      if (Process32First(h, &pe32)) 
      { 
        do
        {
          KillIfSuRunProcess(LogonSID,Logonsrc.SourceIdentifier,pe32.th32ProcessID);
        }while (Process32Next(h, &pe32)); 
      } 
      CloseHandle(h);
    }
  }
  free(LogonSID);
}

//Winlogon Logoff event
VOID APIENTRY SuRunLogoffUser(PWLX_NOTIFICATION_INFO Info)
{
  TerminateAllSuRunnedProcesses(Info->hToken);
}

//////////////////////////////////////////////////////////////////////////////
//
// Install/Uninstall
//
//////////////////////////////////////////////////////////////////////////////
__declspec(dllexport) void InstallShellExt()
{
  if(GetUseIShExHook)
  {
    //Vista: Enable IShellExecHook
    SetOption(L"DelIShellExecHookEnable",
      (DWORD)(GetRegInt(HKLM,L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer",
      L"EnableShellExecuteHooks",-1)==-1),
      0);
    SetRegInt(HKLM,L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer",L"EnableShellExecuteHooks",1);
  }
  //COM-Object
  SetRegStr(HKCR,L"CLSID\\" sGUID,L"",L"SuRun Shell Extension");
  SetRegStr(HKCR,L"CLSID\\" sGUID L"\\InProcServer32",L"",L"SuRunExt.dll");
  SetRegStr(HKCR,L"CLSID\\" sGUID L"\\InProcServer32",L"ThreadingModel",L"Apartment");
  if(GetUseIShExHook)
    //ShellExecuteHook
    SetRegStr(HKLM,L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ShellExecuteHooks",
              sGUID,L"");
  //Desktop-Background-Hook
  SetRegStr(HKCR,L"Directory\\Background\\shellex\\ContextMenuHandlers\\SuRun",L"",sGUID);
  SetRegStr(HKCR,L"Folder\\shellex\\ContextMenuHandlers\\SuRun",L"",sGUID);
#ifdef DoDBGTrace
//  SetRegStr(HKCR,L"*\\shellex\\ContextMenuHandlers\\SuRun",L"",sGUID);
//  SetRegStr(HKCR,L"lnkfile\\shellex\\ContextMenuHandlers\\SuRun",L"",sGUID);
#endif DoDBGTrace
  //self Approval
  SetRegStr(HKLM,L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Shell Extensions\\Approved",
            sGUID,L"SuRun Shell Extension");
  //Disable "Open with..." when right clicking on SuRun.exe
  SetRegStr(HKCR,L"Applications\\SuRun.exe",L"NoOpenWith",L"");
  //Disable putting SuRun in the frequently used apps in the start menu
  SetRegStr(HKCR,L"Applications\\SuRun.exe",L"NoStartPage",L"");
}


__declspec(dllexport) void RemoveShellExt()
{
  //Clean up:
  //Vista: Disable ShellExecHook?
  if (GetOption(L"DelIShellExecHookEnable",0)!=0)
    RegDelVal(HKLM,L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer",
              L"EnableShellExecuteHooks");
  //"Open with..." when right clicking on SuRun.exe
  DelRegKey(HKCR,L"Applications\\SuRun.exe");
  //COM-Object
  DelRegKey(HKCR,L"CLSID\\" sGUID L"\\InProcServer32");

  //Desktop-Background-Hook
  DelRegKey(HKCR,L"Directory\\Background\\shellex\\ContextMenuHandlers\\SuRun");
  DelRegKey(HKCR,L"Folder\\shellex\\ContextMenuHandlers\\SuRun");
#ifdef DoDBGTrace
  DelRegKey(HKEY_CLASSES_ROOT,L"*\\shellex\\ContextMenuHandlers\\SuRun");
  DelRegKey(HKCR,L"lnkfile\\shellex\\ContextMenuHandlers\\SuRun");
#endif DoDBGTrace
  //ShellExecuteHook
  RegDelVal(HKLM,L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ShellExecuteHooks",sGUID);
  //self Approval
  RegDelVal(HKLM,L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Shell Extensions\\Approved",sGUID);
}

static HANDLE l_InitThread=0;
DWORD WINAPI InitProc(void* p)
{
  __try
  {
    //  CTimeLog l(L"InitProc");
    //Try to make shure that the NT Dll Loader is done:
    HINSTANCE h=0;
    for(;;)
    {
      h=GetModuleHandleA("psapi.dll");
      if (h)
        break;
      Sleep(1);
    }
    GetProcAddress(h,"EnumProcessModules");
    h=0;
    for(;;)
    {
      h=GetModuleHandleA("advapi32.dll");
      if (h)
        break;
      Sleep(1);
    }
    GetProcAddress(h,"CreateProcessAsUserW");
    //Resources
    l_Groups=UserIsInSuRunnersOrAdmins();
    GetProcessUserName(GetCurrentProcessId(),l_User);
    l_bSetHook=1;
    //IAT Hook:
    if (l_bSetHook)
    {
      TCHAR fMod[MAX_PATH];
      TCHAR fNoHook[4096];
      GetProcessFileName(fMod,MAX_PATH);
      //Do not set hooks into SuRun!
      GetSystemWindowsDirectory(fNoHook,4096);
#ifndef _SR32
      SR_PathAppendW(fNoHook, _T("SuRun.exe"));
#else _SR32
      SR_PathAppendW(fNoHook, _T("SuRun32.bin"));
#endif _SR32
      SR_PathQuoteSpacesW(fNoHook);
      l_bSetHook=l_bSetHook && (_tcsicmp(fMod,fNoHook)!=0);
      if(l_bSetHook)
      {
        if (l_IsAdmin)
        {
          //Admin process: Only set a hook into services.exe!
          GetSystemWindowsDirectory(fNoHook,4096);
          SR_PathAppendW(fNoHook,L"SYSTEM32\\services.exe");
          SR_PathQuoteSpacesW(fNoHook);
          l_bSetHook=l_bSetHook && (_tcsicmp(fMod,fNoHook)==0);
        }
        //Do not set hooks into blacklisted files!
        l_bSetHook=l_bSetHook && (!IsInBlackList(fMod));
        //      DBGTrace3("SuRunExt: %s Hook=%d [%s]",fMod,l_bSetHook,GetCommandLine());
        if(l_bSetHook && GetUseIATHook)
          LoadHooks();
      }
    }
  }__except(GetExceptionCode()==EXCEPTION_ACCESS_VIOLATION)
  {
    extern BOOL g_IATInit;
    g_IATInit=FALSE;
    l_InitThread=CreateThread(0,0,InitProc,(void*)1,0,0);
  }  
  return 0;
}

//////////////////////////////////////////////////////////////////////////////
//
// DllMain
//
//////////////////////////////////////////////////////////////////////////////
BOOL APIENTRY DllMain( HINSTANCE hInstDLL,DWORD dwReason,LPVOID lpReserved)
{
  //Process Detach:
  if(dwReason==DLL_PROCESS_DETACH)
  {
    if(l_InitThread)
    {
      if(WaitForSingleObject(l_InitThread,1000)==WAIT_TIMEOUT)
      {
        DBGTrace("WARNING: SuRunExt Terminating InitThread");
        TerminateThread(l_InitThread,0);
      }
      l_InitThread=0;
    }
    //"The Old New Thing:" Don't try to be smart on DLL_PROCESS_DETACH
    // Leave the critical section l_SxHkCs untouched to avoid possible dead locks
    //IAT-Hook
    UnloadHooks();
    return TRUE;
  }
  if(dwReason!=DLL_PROCESS_ATTACH)
    return TRUE;
  //Process Attach:
  if (l_hInst==hInstDLL)
    return TRUE;
  l_hInst=hInstDLL;
  InitializeCriticalSectionAndSpinCount(&l_SxHkCs,0x80000000);
  l_InitThread=CreateThread(0,0,InitProc,(void*)1,0,0);
  return TRUE;
}
