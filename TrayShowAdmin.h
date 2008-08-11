#pragma once

DWORD WINAPI TSAThreadProc(void* p);

void InitTrayShowAdmin();
BOOL ProcessTrayShowAdmin(BOOL bBalloon);
void CloseTrayShowAdmin();
BOOL StartTSAThread();