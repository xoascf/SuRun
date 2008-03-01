//////////////////////////////////////////////////////////////////////////////
//
// This source code is part of SuRun
//
// Some sources in this project evolved from Microsoft sample code, some from 
// other free sources. The Shield Icons are taken from Windows XP Service Pack 
// 2 (xpsp2res.dll) 
// 
// Feel free to use the SuRun sources for your liking.
// 
//                                (c) Kay Bruns (http://kay-bruns.de), 2007,08
//////////////////////////////////////////////////////////////////////////////

/////////////////////////////////////////////////////////////////////////////
//
// Most of this is heavily based on SuDown (http://sudown.sourceforge.net)
//
/////////////////////////////////////////////////////////////////////////////

#pragma once

// SuRun users group name
#define SURUNNERSGROUP  _T("SuRunners")

// Well known user groups for filling the list in LogonDlg
const DWORD UserGroups[]=
{
  DOMAIN_ALIAS_RID_ADMINS,
  DOMAIN_ALIAS_RID_POWER_USERS,
  DOMAIN_ALIAS_RID_USERS,
  DOMAIN_ALIAS_RID_GUESTS
};

// this Creates the local user group "SuRunners"
void CreateSuRunnersGroup();

// this Deletes the local user group "SuRunners"
void DeleteSuRunnersGroup();

// Get the name of a well known group
BOOL GetGroupName(DWORD Rid,LPWSTR Name,PDWORD cchName);

// put/remove User "DomainAndName" in/from Group
DWORD AlterGroupMember(LPCWSTR Group,LPCWSTR DomainAndName, BOOL bAdd);
// put/remove User "DomainAndName" in/from Group GetGroupName("Rid")
DWORD AlterGroupMember(DWORD Rid,LPCWSTR DomainAndName, BOOL bAdd);

// is User "DomainAndName" member of Group?
BOOL IsInGroup(LPCWSTR Group,LPCWSTR DomainAndName);
// is User "DomainAndName" member of Group GetGroupName("Rid")?
BOOL IsInGroup(DWORD Rid,LPCWSTR DomainAndName);

// is User "DomainAndName" member of SuRunners?
BOOL IsInSuRunners(LPCWSTR DomainAndName);

//  BeOrBecomeSuRunner: check, if User is SuRunner if not, try to join him
BOOL BeOrBecomeSuRunner(LPCTSTR UserName,BOOL bHimSelf,HWND hwnd);

// User list
//
/////////////////////////////////////////////////////////////////////////////

typedef struct  
{
  WCHAR UserName[UNLEN+UNLEN+2];
  HBITMAP UserBitmap;
}USERDATA;

class USERLIST
{
public:
  USERLIST();
  ~USERLIST();
public:
  void SetUsualUsers(BOOL bScanDomain);
  void SetGroupUsers(LPWSTR GroupName,BOOL bScanDomain);
  void SetGroupUsers(DWORD WellKnownGroup,BOOL bScanDomain);
  LPTSTR  GetUserName(int nUser);
  HBITMAP GetUserBitmap(int nUser);
  HBITMAP GetUserBitmap(LPTSTR UserName);
  int     GetCount(){return nUsers;};
private:
  int nUsers;
  USERDATA* User;
  void Add(LPWSTR UserName);
  void AddGroupUsers(LPWSTR GroupName,BOOL bScanDomain);
  void AddGroupUsers(DWORD WellKnownGroup,BOOL bScanDomain);
  void AddAllUsers(BOOL bScanDomain);
};

