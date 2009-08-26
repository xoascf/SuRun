#pragma once

HANDLE LSALogon(DWORD SessionID,LPWSTR UserName,LPWSTR Domain,
                LPWSTR Password,bool bNoAdmin);

BOOL CreateTempAdmin();
BOOL DeleteTempAdmin();
HANDLE GetTempAdminToken();

HANDLE GetAdminToken(DWORD SessionID);
