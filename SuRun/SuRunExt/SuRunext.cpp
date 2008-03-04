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

#pragma comment(lib,"User32.lib")
#pragma comment(lib,"ole32.lib")
#pragma comment(lib,"Shell32.lib")
#pragma comment(lib,"ShFolder.Lib")
#pragma comment(lib,"Shlwapi.lib")

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

DWORD g_LoadAppInitDLLs = 0;

#ifdef _Win64
DWORD g_LoadAppInit32DLLs = 0;
#endif _Win64

#pragma data_seg()
#pragma comment(linker, "/section:.SHDATA,RWS")

HINSTANCE   l_hInst     = NULL;

UINT        WM_SYSMH0   = 0;
UINT        WM_SYSMH1   = 0;

//For IAT-Hook IShellExecHook failed to start g_LastFailedCmd
LPTSTR g_LastFailedCmd=0;

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
#ifdef _DEBUG
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
    TCHAR s[4096]={0};
    SHGetFolderPath(0,CSIDL_DESKTOP,0,SHGFP_TYPE_CURRENT,s);
    m_pDeskClicked=_tcsicmp(s,m_ClickFolderName)==0;
  }else
  {
    FORMATETC fe = {CF_HDROP, NULL, DVASPECT_CONTENT, -1, TYMED_HGLOBAL};
    STGMEDIUM m;
    if ((SUCCEEDED(pDataObj->GetData(&fe,&m)))
      &&(DragQueryFile((HDROP)m.hGlobal,(UINT)-1,NULL,0)==1)) 
    {
      TCHAR path[4096];
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
        InsertMenu(hMenu, indexMenu++, MF_STRING|MF_BYPOSITION, id++, CResStr(l_hInst,IDS_SURUN));
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
      MessageBoxW(lpcmi->hwnd,CResStr(l_hInst,IDS_FILENOTFOUND),CResStr(l_hInst,IDS_ERR),MB_ICONSTOP);
  }
  return hr;
}

//////////////////////////////////////////////////////////////////////////////
// IShellExecuteHook
//////////////////////////////////////////////////////////////////////////////
STDMETHODIMP CShellExt::Execute(LPSHELLEXECUTEINFO pei)
{
//  DBGTrace15("SuRun ShellExtHook: siz=%d, msk=%X wnd=%X, verb=%s, file=%s, parms=%s, "
//    L"dir=%s, nShow=%X, inst=%X, idlist=%X, class=%s, hkc=%X, hotkey=%X, hicon=%X, hProc=%X",
//    pei->cbSize,pei->fMask,pei->hwnd,pei->lpVerb,pei->lpFile,pei->lpParameters,
//    pei->lpDirectory,pei->nShow,pei->hInstApp,pei->lpIDList,pei->lpClass,
//    pei->hkeyClass,pei->dwHotKey,pei->hIcon,pei->hProcess);
  //Admins don't need the ShellExec Hook!
  if (IsAdmin())
    return S_FALSE;
  {
    //Non SuRunners don't need the ShellExec Hook!
    TCHAR User[UNLEN+GNLEN+2]={0};
    GetProcessUserName(GetCurrentProcessId(),User);
    if (!IsInSuRunners(User))
      return S_FALSE;
  }
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
    return S_FALSE;
  }
  TCHAR tmp[4096];
  TCHAR cmd[4096];
  //check if this Programm has an Auto-SuRun-Entry in the List
  _tcscpy(tmp,pei->lpFile);
  PathQuoteSpaces(tmp);
  //Verb must be "open" or empty
  BOOL bNoAutoRun=TRUE;
  if (pei->lpVerb && (_tcslen(pei->lpVerb)!=0)
    &&(_tcsicmp(pei->lpVerb,L"open")!=0)
    &&(_tcsicmp(pei->lpVerb,L"cplopen")!=0))
  {
    if (_tcsicmp(pei->lpVerb,L"AutoRun")==0)
    {
      //AutoRun: get open command
      PathAppend(tmp,L"AutoRun.inf");
      if (GetPrivateProfileInt(L"AutoRun",L"UseAutoPlay",0,tmp)!=0)
        return S_FALSE;
      GetPrivateProfileString(L"AutoRun",L"open",L"",cmd,countof(cmd)-1,tmp);
      if (!cmd[0])
        return S_FALSE;
      _tcscpy(tmp,cmd);
      bNoAutoRun=FALSE;
    }else
    {
      DBGTrace("SuRun ShellExtHook Error: invalid verb!");
      return S_FALSE;
    }
  }
  if ( bNoAutoRun && pei->lpParameters && _tcslen(pei->lpParameters))
  {
    _tcscat(tmp,L" ");
    _tcscat(tmp,pei->lpParameters);
  }
  TCHAR CurDir[4096];
  PROCESS_INFORMATION rpi;
  GetCurrentDirectory(countof(CurDir),CurDir);
  ResolveCommandLine(tmp,CurDir,tmp);
  free(g_LastFailedCmd);
  g_LastFailedCmd=0;

  GetSystemWindowsDirectory(cmd,countof(cmd));
  PathAppend(cmd, _T("SuRun.exe"));
  PathQuoteSpaces(cmd);
  if (_wcsnicmp(cmd,tmp,wcslen(cmd))==0)
    //Never start SuRun administrative
    return S_FALSE;
  //Check Directory
  if (pei->lpDirectory && (*pei->lpDirectory) && (!SetCurrentDirectory(pei->lpDirectory)))
  {
    DBGTrace2("SuRun ShellExtHook Error: SetCurrentDirectory(%s) failed: %s",
      pei->lpDirectory,GetLastErrorNameStatic());
    return S_FALSE;
  }
  //CTimeLog l(L"ShellExecHook TestAutoSuRun(%s)",tmp);
  //ToDo: Directly write to service pipe!
//  _stprintf(&cmd[wcslen(cmd)],L" /QUIET /TESTAA 0 0 %s",tmp);
  
  _stprintf(&cmd[wcslen(cmd)],L" /QUIET /TESTAA %d %x %s",
    GetCurrentProcessId(),&rpi,tmp);
  DBGTrace1("ShellExecuteHook AutoSuRun(%s) test",cmd);
  STARTUPINFO si;
  PROCESS_INFORMATION pi;
  ZeroMemory(&si, sizeof(si));
  si.cb = sizeof(si);
  // Start the child process.
  if (CreateProcess(NULL,cmd,NULL,NULL,FALSE,0,NULL,NULL,&si,&pi))
  {
    SetCurrentDirectory(CurDir);
    CloseHandle(pi.hThread);
    DWORD ExitCode=ERROR_ACCESS_DENIED;
    if((WaitForSingleObject(pi.hProcess,60000)==WAIT_OBJECT_0)
      && GetExitCodeProcess(pi.hProcess,(DWORD*)&ExitCode))
    {
      //ExitCode==-2 means that the program is not in the WhiteList
      if (ExitCode==RETVAL_OK)
      {
        pei->hInstApp=(HINSTANCE)33;
        DBGTrace1("ShellExecuteHook AutoSuRun(%s) success!",cmd);
        //return valid PROCESS_INFORMATION!
        if(pei->fMask&SEE_MASK_NOCLOSEPROCESS)
          pei->hProcess=OpenProcess(SYNCHRONIZE,false,rpi.dwProcessId);
        rpi.hThread=OpenThread(THREAD_SUSPEND_RESUME|SYNCHRONIZE,false,rpi.dwThreadId);
#ifdef _DEBUG
        if(!rpi.hThread)
          DBGTrace1("ERROR: OpenThread failed! %s",GetLastErrorNameStatic());
#endif _DEBUG
        if (ResumeThread(rpi.hThread)==-1)
          DBGTrace1("ERROR: ResumeThread failed! %s",GetLastErrorNameStatic());
        CloseHandle(rpi.hThread);
      }else 
      {
        pei->hInstApp=(HINSTANCE)SE_ERR_ACCESSDENIED;
        //Tell IAT-Hook to not check "tmp" again!
        g_LastFailedCmd=_tcsdup(tmp);
      }
    }else
      DBGTrace1("SuRun ShellExtHook: WHOOPS! %s",cmd);
    CloseHandle(pi.hProcess);
    return ((ExitCode==RETVAL_OK)||(ExitCode==RETVAL_CANCELLED))?S_OK:S_FALSE;
  }else
    DBGTrace2("SuRun ShellExtHook: CreateProcess(%s) failed: %s",cmd,GetLastErrorNameStatic());
  SetCurrentDirectory(CurDir);
  return S_FALSE;
}

//////////////////////////////////////////////////////////////////////////////
//
// Control Panel Applet
//
//////////////////////////////////////////////////////////////////////////////
#include <Cpl.h>

LONG CALLBACK CPlApplet(HWND hwnd,UINT uMsg,LPARAM lParam1,LPARAM lParam2)
{ 
  switch (uMsg) 
  { 
  case CPL_INIT:
    return TRUE; 
  case CPL_GETCOUNT:
    return 1; 
  case CPL_INQUIRE:
    {
      LPCPLINFO cpli=(LPCPLINFO)lParam2; 
      cpli->lData = 0; 
      cpli->idIcon = IDI_MAINICON;
      cpli->idName = IDS_CPLNAME;
      cpli->idInfo = 0;
      return 0;
    }
  case CPL_DBLCLK:    // application icon double-clicked 
    {
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
  //SetRegStr(HKCR,L"*\\shellex\\ContextMenuHandlers\\SuRun",L"",sGUID);
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
  //DelRegKey(HKEY_CLASSES_ROOT,L"*\\shellex\\ContextMenuHandlers\\SuRun");
  //ShellExecuteHook
  RegDelVal(HKLM,L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ShellExecuteHooks",sGUID);
  //self Approval
  RegDelVal(HKLM,L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Shell Extensions\\Approved",sGUID);
}

//////////////////////////////////////////////////////////////////////////////
//
// NewDevProc:
// 
// Win2k: rundll32.exe newdev.dll,DevInstall USB\Vid_0451&Pid_3410\TUSB3410________
//  ::ExitProcess(0), SuRun /newdev newdev.dll,DevInstall USB\Vid_0451&Pid_3410\TUSB3410________
//        
// WinXP  rundll32.exe newdev.dll,ClientSideInstall \\.\pipe\PNP_Device_Install_Pipe_0.{8182B56F-B591-4785-8A9A-72477416A865}
//        CreateProcWithLogonW(rundll32.exe newdev.dll,DevInstall USB\Vid_0451&Pid_3410\TUSB3410________)
//        
//       Pipe:\\.\pipe\PNP_Device_Install_Pipe_0.{8182B56F-B591-4785-8A9A-72477416A865}
//        ->DWORD len;
//        ->wchar EventName[Len] 
// 
// Vista: rundll32.exe C:\Windows\system32\newdev.dll,pDiDeviceInstallAction \\.\pipe\PNP_Device_Install_Pipe_1.{a3312ee6-66f2-4163-94fb-403a447ab42b} "USB\VID_0451&PID_3410\TUSB3410________"
//  ::ExitProcess(0), SuRun C:\Windows\system32\newdev.dll,pDiDeviceInstallAction \\.\pipe\PNP_Device_Install_Pipe_1.{a3312ee6-66f2-4163-94fb-403a447ab42b} "USB\VID_0451&PID_3410\TUSB3410________"
//////////////////////////////////////////////////////////////////////////////
//DWORD WINAPI NewDevProc(void* p)
//{
//  TCHAR cmd[MAX_PATH];
//  GetSystemWindowsDirectory(cmd,MAX_PATH);
//  PathAppend(cmd, _T("SuRun.exe"));
//  PathQuoteSpaces(cmd);
//  STARTUPINFO si;
//  PROCESS_INFORMATION pi;
//  ZeroMemory(&si, sizeof(si));
//  si.cb = sizeof(si);
//  if(_tcsnicmp(L"newdev.dll,ClientSideInstall",PathGetArgs(GetCommandLine()),28)==0)
//  {
//    //WinXP! Close the CredUI Dialog, wait for CreateProcessWithLogonW and 
//    //start newdev.dll,DevInstall
//  }else
//  //if(_tcsnicmp(L"newdev.dll,DevInstall",PathGetArgs(GetCommandLine()),21)==0)
//  {
//    //Win2k! Kill the Process and run a new one:
//    _stprintf(&cmd[wcslen(cmd)],L" /NEWDEV %s",PathGetArgs(GetCommandLine()));
//    // Start the child process.
//    if (CreateProcess(NULL,cmd,NULL,NULL,FALSE,0,NULL,NULL,&si,&pi))
//    {
//      CloseHandle(pi.hThread );
//      CloseHandle(pi.hProcess);
//    }
//    ExitProcess(0);
//    return 0;
//  }
//  return 0;
//}

//////////////////////////////////////////////////////////////////////////////
//
// DllMain
//
//////////////////////////////////////////////////////////////////////////////
BOOL APIENTRY DllMain( HINSTANCE hInstDLL,DWORD dwReason,LPVOID lpReserved)
{
  TCHAR fMod[MAX_PATH];
  GetModuleFileName(0,fMod,MAX_PATH);
  BOOL bAdmin=IsAdmin();
  DWORD PID=GetCurrentProcessId();
  //Process Detach:
  if(dwReason==DLL_PROCESS_DETACH)
  {
#ifdef _DEBUG
    DBGTrace5("DLL_PROCESS_DETACH(hInst=%x) %d:%s[%s], Admin=%d",
      hInstDLL,PID,fMod,GetCommandLine(),bAdmin);
#endif _DEBUG
    //IAT-Hook
    UnloadHooks();
    return TRUE;
  }
  if(dwReason!=DLL_PROCESS_ATTACH)
    return TRUE;
  //Process Attach:
  DisableThreadLibraryCalls(hInstDLL);
  if (l_hInst==hInstDLL)
    return TRUE;
  l_hInst=hInstDLL;
  //Resources
#ifdef _DEBUG_ENU
  SetThreadLocale(MAKELCID(MAKELANGID(LANG_ENGLISH,SUBLANG_ENGLISH_US),SORT_DEFAULT));
#endif _DEBUG_ENU
  WM_SYSMH0=RegisterWindowMessage(_T("SYSMH1_2C7B6088-5A77-4d48-BE43-30337DCA9A86"));
  WM_SYSMH1=RegisterWindowMessage(_T("SYSMH2_2C7B6088-5A77-4d48-BE43-30337DCA9A86"));
  //IAT Hook:
  if ((!bAdmin) && GetUseIATHook)
  {
    //Do not set hooks into SuRun or Admin Processes!
    TCHAR fSuRunExe[4096];
    GetSystemWindowsDirectory(fSuRunExe,4096);
    PathAppend(fSuRunExe,L"SuRun.exe");
    PathQuoteSpaces(fSuRunExe);
    BOOL bSetHook=(!bAdmin)&&(_tcsicmp(fMod,fSuRunExe)!=0);
    DBGTrace6("DLL_PROCESS_ATTACH(hInst=%x) %d:%s[%s], Admin=%d, SetHook=%d",
      hInstDLL,PID,fMod,GetCommandLine(),bAdmin,bSetHook);
    if(bSetHook)
      LoadHooks();
  }
#ifdef _DEBUG
  else
    DBGTrace5("DLL_PROCESS_ATTACH(hInst=%x) %d:%s[%s], Admin=%d",
      hInstDLL,PID,fMod,GetCommandLine(),bAdmin);
#endif _DEBUG
  //DevInst
//  if(!bAdmin)
//  {
//    TCHAR f[4096];
//    GetSystemDirectory(f,4096);
//    PathAppend(f,L"rundll32.exe");
//    PathQuoteSpaces(f);
//    LPTSTR args=PathGetArgs(GetCommandLine());
//    if((_tcsicmp(f,fMod)==0) &&(_tcsnicmp(L"newdev.dll,",args,11)==0))
//    {
//      TCHAR UserName[UNLEN+UNLEN+2]={0};
//      GetProcessUserName(PID,UserName);
//      if(GetInstallDevs(UserName))
//        CreateThread(0,0,NewDevProc,0,0,0);
//    }
//  }
  return TRUE;
}
