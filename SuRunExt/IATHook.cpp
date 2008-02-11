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

#include <windows.h>
#include "SysMenuHook.h"

DWORD WINAPI HookIAT(HMODULE hMod,LPCTSTR ModName,PROC origFunc, PROC newFunc)
{
  PIMAGE_DOS_HEADER pDosH;
  PIMAGE_NT_HEADERS pNTH;
  PIMAGE_IMPORT_DESCRIPTOR pImportDesc;
  PIMAGE_EXPORT_DIRECTORY pExportDir;
  PIMAGE_THUNK_DATA pThunk;
  PIMAGE_IMPORT_BY_NAME pImportName;
  
  if(!newFunc || !hMod || hMod == g_hInst)
    return 0;
  
  // Verify that the newFunc is valid
  if (IsBadCodePtr(newFunc))
    return 0;
  
  // Get DOS Header
  pDosH = (PIMAGE_DOS_HEADER) hMod;
  
  // Verify that the PE is valid by checking e_magic's value and DOS Header size
  if(IsBadReadPtr(pDosH, sizeof(IMAGE_DOS_HEADER)))
    return 0;
  
  if(pDosH->e_magic != IMAGE_DOS_SIGNATURE)
    return 0;
  
  // Find the NT Header by using the offset of e_lfanew value from hMod
  pNTH = (PIMAGE_NT_HEADERS) ((DWORD) pDosH + (DWORD) pDosH->e_lfanew);
  
  // Verify that the NT Header is correct
  if(IsBadReadPtr(pNTH, sizeof(IMAGE_NT_HEADERS)))
    return 0;
  
  if(pNTH->Signature != IMAGE_NT_SIGNATURE)
    return 0;
  
  // iat patching
  pImportDesc = (PIMAGE_IMPORT_DESCRIPTOR) ((DWORD) pDosH +
    (DWORD) (pNTH->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress));
  
  if(pImportDesc == (PIMAGE_IMPORT_DESCRIPTOR) pNTH)
    return 0;
  
  while(pImportDesc->Name)
  {
    // pImportDesc->Name gives the name of the module, so we can find "user32.dll"
    char *name = (char *) ((DWORD) pDosH + (DWORD) (pImportDesc->Name));
    // stricmp returns 0 if strings are equal, case insensitive
    if(_stricmp(name, ModName) == 0)
    {
      pThunk = (PIMAGE_THUNK_DATA)((DWORD) pDosH + (DWORD) pImportDesc->FirstThunk);
      while(pThunk->u1.Function)
      {
        // get the pointer of the imported function and see if it matches up with the original
        if((DWORD) pThunk->u1.Function == (DWORD) origFunc)
        {
          MEMORY_BASIC_INFORMATION mbi;
          DWORD oldProt;
          VirtualQuery(&pThunk->u1.Function, &mbi, sizeof(MEMORY_BASIC_INFORMATION));
          VirtualProtect(mbi.BaseAddress, mbi.RegionSize, PAGE_READWRITE, &oldProt);
          pThunk->u1.Function = (DWORD) newFunc;
          VirtualProtect(mbi.BaseAddress, mbi.RegionSize, oldProt, &oldProt);
          break;
        }
        else
        {
          ++pThunk;
        }      
      }
    }
    
    ++pImportDesc;
  }
  
  return 0;      
}