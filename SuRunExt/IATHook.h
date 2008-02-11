#pragma once

DWORD WINAPI HookIAT(LPCSTR DllName,PROC origFunc, PROC newFunc);
