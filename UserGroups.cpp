/////////////////////////////////////////////////////////////////////////////
//
// Most of this is heavily based on SuDown (http://sudown.sourceforge.net)
//
/////////////////////////////////////////////////////////////////////////////

#define _WIN32_WINNT 0x0500
#define WINVER       0x0500
#include <windows.h>
#include <TCHAR.h>
#include <lm.h>
#include "UserGroups.h"

#pragma comment(lib,"Netapi32.lib")

/////////////////////////////////////////////////////////////////////////////
//
// GetGroupName
//
/////////////////////////////////////////////////////////////////////////////
BOOL GetGroupName(DWORD Rid,LPWSTR Name,PDWORD cchName)
{
  SID_IDENTIFIER_AUTHORITY sia = SECURITY_NT_AUTHORITY;
  PSID pSid;
  BOOL bSuccess = FALSE;
  if(AllocateAndInitializeSid(&sia,2,SECURITY_BUILTIN_DOMAIN_RID,Rid,0,0,0,0,0,0,&pSid)) 
  {
    WCHAR DomainName[DNLEN];
    DWORD DnLen = DNLEN;
    SID_NAME_USE snu;
    bSuccess = LookupAccountSidW(0,pSid,Name,cchName,DomainName,&DnLen,&snu);
    FreeSid(pSid);
  }
  return bSuccess;
}

/////////////////////////////////////////////////////////////////////////////
//
// AlterGroupMembership
//
//  Adds or removes "DOMAIN\User" from the "Group" localgroup
/////////////////////////////////////////////////////////////////////////////
DWORD AlterGroupMember(LPCWSTR Group,LPCWSTR DomainAndName, BOOL bAdd)
{
  LOCALGROUP_MEMBERS_INFO_3 lgrmi3={0};
  lgrmi3.lgrmi3_domainandname=(LPWSTR)DomainAndName;
  if (bAdd) 
    return NetLocalGroupAddMembers(NULL,Group,3,(LPBYTE)&lgrmi3,1);
  return NetLocalGroupDelMembers(NULL,Group,3,(LPBYTE)&lgrmi3,1);
}

DWORD AlterGroupMember(DWORD Rid,LPCWSTR DomainAndName, BOOL bAdd)
{
  DWORD cchG=GNLEN;
  WCHAR Group[GNLEN+1]={0};
  if (!GetGroupName(Rid,Group,&cchG))
    return NERR_GroupNotFound;
  return AlterGroupMember(Group,DomainAndName,bAdd);
}

/////////////////////////////////////////////////////////////////////////////
//
// IsInGroup
//
//  Checks if "DOMAIN\User" is a member of the group
/////////////////////////////////////////////////////////////////////////////
BOOL IsInGroup(LPCWSTR Group,LPCWSTR DomainAndName)
{
	if (AlterGroupMember(Group,DomainAndName,TRUE)==ERROR_MEMBER_IN_ALIAS)
		return TRUE;
	AlterGroupMember(Group,DomainAndName,FALSE);
	return FALSE;
}

BOOL IsInGroup(DWORD Rid,LPCWSTR DomainAndName)
{
  DWORD cchG=GNLEN;
  WCHAR Group[GNLEN+1]={0};
  if (!GetGroupName(Rid,Group,&cchG))
    return FALSE;
  return IsInGroup(Group,DomainAndName);
}

/////////////////////////////////////////////////////////////////////////////
//
// IsInSudoers
//
//  Checks if "DOMAIN\User" is a member of the sudoers localgroup
/////////////////////////////////////////////////////////////////////////////
BOOL IsInSudoers(LPCWSTR DomainAndName)
{
  return IsInGroup(SUDOERSGROUP,DomainAndName);
}

/////////////////////////////////////////////////////////////////////////////
//
// IsBuiltInAdmin
//
//  Checks if "DOMAIN\User" is a built in administrator
/////////////////////////////////////////////////////////////////////////////
BOOL IsBuiltInAdmin(LPCWSTR DomainAndName)
{
  if (!IsInGroup(DOMAIN_ALIAS_RID_ADMINS,DomainAndName))
    return false;
	if (AlterGroupMember(DOMAIN_ALIAS_RID_ADMINS,DomainAndName,0)!=NERR_Success)
		return TRUE;
	AlterGroupMember(DOMAIN_ALIAS_RID_ADMINS,DomainAndName,1);
	return FALSE;
}

