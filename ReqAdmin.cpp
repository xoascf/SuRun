#define _WIN32_WINNT 0x0500
#define WINVER       0x0500
#include <windows.h>
#include <tchar.h>
#include <shlwapi.h>
#include "DBGTrace.h"
#pragma comment(lib,"shlwapi.lib")


//Define this in any implementation, before "pugxml.h", to be notified of API campatibility.
#define PUGAPI_VARIANT 0x58475550	//The Pug XML library variant we are using in this implementation.
#define PUGAPI_VERSION_MAJOR 1		//The Pug XML library major version we are using in this implementation.
#define PUGAPI_VERSION_MINOR 2		//The Pug XML library minor version we are using in this implementation.
//Include the Pug XML library.
#include "pugxml.h"


using namespace std;
using namespace pug;

BOOL RequiresAdmin(xml_node& document)
{
  BOOL bReqAdmin=FALSE;
  xml_node xn = document.first_element_by_name(_T("*trustInfo"));
  if (!xn.empty())
  {
    TCHAR name[MAX_PATH];
    _tcscpy(name,xn.name());
    LPTSTR p=_tcschr(name,':');
    if (p)
      p++;
    else
      p=name;
    _tcscpy(p,_T("security"));
    xn = xn.first_element_by_name(name);
    if (!xn.empty())
    {
      _tcscpy(p,_T("requestedPrivileges"));
      xn = xn.first_element_by_name(name);
      if (!xn.empty())
      {
        _tcscpy(p,_T("requestedExecutionLevel"));
        xml_node x1 = xn.first_element_by_attribute(name,_T("level"),_T("requireAdministrator"));
        if (!x1.empty())
          bReqAdmin=TRUE;
        else
        {
          x1 = xn.first_element_by_attribute(name,_T("level"),_T("highestAvailable"));
          if (!x1.empty())
            bReqAdmin=TRUE;
        }
      }
    }
  }
  return bReqAdmin;
}

BOOL CALLBACK EnumResProc(HMODULE hExe,LPCTSTR rType,LPTSTR rName,LONG_PTR lParam)
{
  BOOL bContinue=TRUE;
  *((BOOL*)lParam)=FALSE;
  HRSRC hr=FindResource(hExe,rName,RT_MANIFEST);
  DWORD siz=SizeofResource(hExe,hr);
  HGLOBAL hg=LoadResource(hExe,hr);
  LPTSTR Manifest=(LPTSTR)calloc(siz+2,1);
  memmove(Manifest,LockResource(hg),siz);
  UnlockResource(hg);
  FreeResource(hg);
  if(Manifest)
  {
    xml_parser xml; //Construct.
    if (xml.parse(Manifest))
      bContinue=!RequiresAdmin(xml.document());
  }
  free(Manifest);
  if (!bContinue)
    *((BOOL*)lParam)=TRUE;
  return bContinue;
}

BOOL RequiresAdmin(LPCTSTR FileName)
{
  BOOL bReqAdmin=FALSE;
  HINSTANCE hExe=LoadLibrary(FileName);
  if (hExe)
  {
    bReqAdmin=-1;
    EnumResourceNames(hExe,RT_MANIFEST,EnumResProc,(LONG_PTR)&bReqAdmin);
    FreeLibrary(hExe);
    if (bReqAdmin==-1)
      bReqAdmin=FALSE;
    else if(!bReqAdmin)
    {
      TCHAR s[MAX_PATH];
      _stprintf(s,_T("%s.%s"),FileName,_T("manifest"));
      xml_parser xml;
      if (xml.parse_file(s))
        bReqAdmin=RequiresAdmin(xml.document());
    }
    //Try FileName Pattern matching
    if(!bReqAdmin)
    {
      //Split path parts
      TCHAR file[MAX_PATH];
      TCHAR ext[MAX_PATH];
      //Get File, Ext
      _tcscpy(file,FileName);
      PathRemoveArgs(file);
      _tcsupr(file);
      _tcscpy(ext,PathFindExtension(file));
      PathRemoveExtension(file);
      PathStripPath(file);
      bReqAdmin=(_tcsicmp(ext,_T(".MSI"))==0)
              ||(_tcsicmp(ext,_T(".MSC"))==0);
      if(!bReqAdmin)
      {
        if ((_tcsicmp(ext,_T(".EXE"))==0)
          ||(_tcsicmp(ext,_T(".CMD"))==0)
          ||(_tcsicmp(ext,_T(".LNK"))==0)
          ||(_tcsicmp(ext,_T(".COM"))==0)
          ||(_tcsicmp(ext,_T(".PIF"))==0)
          ||(_tcsicmp(ext,_T(".BAT"))==0))
          bReqAdmin=(_tcsstr(file,_T("INSTALL"))!=0)
                  ||(_tcsstr(file,_T("SETUP"))!=0)
                  ||(_tcsstr(file,_T("UPDATE"))!=0);
      }
    }
  }
  DBGTrace2("RequiresAdmin(%s)==%d",FileName,bReqAdmin);
  return bReqAdmin;
}
