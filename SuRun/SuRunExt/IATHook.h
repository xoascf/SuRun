#pragma once

DWORD WINAPI HookIAT(HMODULE hMod,LPCTSTR ModName,PROC origFunc, PROC newFunc);
