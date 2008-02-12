#pragma once

DWORD WINAPI HookIAT(HMODULE hMod,LPCSTR DllName,PROC origFunc, PROC newFunc);
DWORD WINAPI HookIAT(LPCSTR DllName,PROC origFunc, PROC newFunc);
