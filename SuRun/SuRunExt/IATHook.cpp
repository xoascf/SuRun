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
#include <Psapi.h>
#include "SysMenuHook.h"

#pragma comment(lib,"PSAPI.lib")

DWORD WINAPI HookIAT(HMODULE hMod,LPCSTR DllName,PROC origFunc, PROC newFunc)
{
  if((hMod==l_hInst)||(!newFunc)||(IsBadCodePtr(newFunc)))
    return 0;
  // Get DOS Header
  PIMAGE_DOS_HEADER pDosH = (PIMAGE_DOS_HEADER) hMod;
  // Verify that the PE is valid by checking e_magic's value and DOS Header size
  if(IsBadReadPtr(pDosH, sizeof(IMAGE_DOS_HEADER))
    || (pDosH->e_magic != IMAGE_DOS_SIGNATURE))
    return 0;
  // Find the NT Header by using the offset of e_lfanew value from hMod
  PIMAGE_NT_HEADERS pNTH = (PIMAGE_NT_HEADERS) ((DWORD) pDosH + (DWORD) pDosH->e_lfanew);
  // Verify that the NT Header is correct
  if(IsBadReadPtr(pNTH, sizeof(IMAGE_NT_HEADERS))
    ||(pNTH->Signature != IMAGE_NT_SIGNATURE))
    return 0;
  // iat patching
  PIMAGE_IMPORT_DESCRIPTOR pImportDesc = (PIMAGE_IMPORT_DESCRIPTOR) ((DWORD) pDosH +
    (DWORD) (pNTH->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress));
  if(pImportDesc == (PIMAGE_IMPORT_DESCRIPTOR) pNTH)
    return 0;
  while(pImportDesc->Name)
  {
    // pImportDesc->Name gives the name of the module, so we can find "user32.dll"
    char *name = (char *) ((DWORD) pDosH + (DWORD) (pImportDesc->Name));
    // stricmp returns 0 if strings are equal, case insensitive
    if(_stricmp(name, DllName) == 0)
    {
      PIMAGE_THUNK_DATA pThunk = (PIMAGE_THUNK_DATA)((DWORD) pDosH + (DWORD) pImportDesc->FirstThunk);
      while(pThunk->u1.Function)
      {
        // get the pointer of the imported function and see if it matches up with the original
        if((DWORD) pThunk->u1.Function == (DWORD) origFunc)
        {
          MEMORY_BASIC_INFORMATION mbi;
          if (VirtualQuery(&pThunk->u1.Function, &mbi, sizeof(MEMORY_BASIC_INFORMATION))!=0)
          {
            DWORD oldProt;
            if(VirtualProtect(mbi.BaseAddress, mbi.RegionSize, PAGE_READWRITE, &oldProt))
              pThunk->u1.Function = (DWORD) newFunc;
            VirtualProtect(mbi.BaseAddress, mbi.RegionSize, oldProt, &oldProt);
          }
        }
        ++pThunk;
      }
    }
    ++pImportDesc;
  }
  return 0;
}

DWORD WINAPI HookIAT(LPCSTR DllName,PROC origFunc, PROC newFunc)
{
  // Verify that the newFunc is valid
  if((!newFunc)||(IsBadCodePtr(newFunc)))
    return 0;
  HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS,TRUE,GetCurrentProcessId());
  if (!hProc)
    return 0;
  DWORD Siz=0;
  EnumProcessModules(hProc,0,0,&Siz);
  HMODULE* hModues=(HMODULE*)malloc(Siz);
  if(hModues)
  {
    EnumProcessModules(hProc,hModues,Siz,&Siz);
    for (HMODULE* hMod=hModues;(DWORD)hMod<(DWORD)hModues+Siz;hMod++) 
      HookIAT(*hMod,DllName,origFunc,newFunc);
    free(hModues);
  }
  CloseHandle(hProc);
  return 0;
}