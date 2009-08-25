#pragma once

HANDLE LSALogon(HANDLE SrcToken,LPWSTR UserName,LPWSTR Domain,
                LPWSTR Password,bool bNoAdmin);

HANDLE LSALogon(DWORD SessionID,LPWSTR UserName,LPWSTR Domain,
                LPWSTR Password,bool bNoAdmin);

HANDLE GetTempAdminToken();

HANDLE GetAdminToken(DWORD SessionID);
