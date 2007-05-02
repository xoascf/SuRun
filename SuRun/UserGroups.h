/////////////////////////////////////////////////////////////////////////////
//
// Most of this is heavily based on SuDown (http://sudown.sourceforge.net)
//
/////////////////////////////////////////////////////////////////////////////
#pragma once

#define SURUNNERSGROUP  _T("SuRunners")

const DWORD UserGroups[]=
{
  DOMAIN_ALIAS_RID_ADMINS,
  DOMAIN_ALIAS_RID_POWER_USERS,
  DOMAIN_ALIAS_RID_USERS,
  DOMAIN_ALIAS_RID_GUESTS
};

void CreateSuRunnersGroup();

BOOL GetGroupName(DWORD Rid,LPWSTR Name,PDWORD cchName);

DWORD AlterGroupMember(LPCWSTR Group,LPCWSTR DomainAndName, BOOL bAdd);
DWORD AlterGroupMember(DWORD Rid,LPCWSTR DomainAndName, BOOL bAdd);

BOOL IsInGroup(LPCWSTR Group,LPCWSTR DomainAndName);
BOOL IsInGroup(DWORD Rid,LPCWSTR DomainAndName);
BOOL IsInSuRunners(LPCWSTR DomainAndName);

BOOL IsBuiltInAdmin(LPCWSTR DomainAndName);