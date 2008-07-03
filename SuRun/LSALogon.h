#pragma once

HANDLE LSALogon(DWORD SessionID,LPWSTR UserName,LPWSTR Domain,
                LPWSTR Password,bool bNoAdmin);