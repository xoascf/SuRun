#pragma once

HANDLE LSALogon(DWORD SessionID,LPWSTR UserName,LPWSTR Domain,
                LPWSTR Password,bool bNoAdmin);

HANDLE LogonAsAdmin(LPTSTR UserName,LPTSTR p);

void RestoreUserPasswords();
void DeleteTempAdminTokens();
HANDLE GetTempAdminToken(LPTSTR UserName);

HANDLE GetAdminToken(DWORD SessionID);
