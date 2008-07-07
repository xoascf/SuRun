#pragma once

DWORD WINAPI TSAThreadProc(void* p);

void InitTrayShowAdmin();
BOOL ProcessTrayShowAdmin();
void CloseTrayShowAdmin();
BOOL StartTSAThread();