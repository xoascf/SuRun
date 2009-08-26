#pragma once

HANDLE LSALogon(HANDLE SrcToken,LPWSTR UserName,LPWSTR Domain,
                LPWSTR Password,bool bNoAdmin);

HANDLE LSALogon(DWORD SessionID,LPWSTR UserName,LPWSTR Domain,
                LPWSTR Password,bool bNoAdmin);

BOOL CreateTempAdmin();
BOOL DeleteTempAdmin();
HANDLE GetTempAdminToken();

HANDLE GetAdminToken(DWORD SessionID);
