#pragma once

#define ServicePipeName _T("\\\\.\\Pipe\\SuperUserRun")

BOOL InstallService();
BOOL DeleteService();
