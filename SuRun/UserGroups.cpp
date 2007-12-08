//////////////////////////////////////////////////////////////////////////////
//
// This source code is part of SuRun
//
// Some sources in this project evolved from Microsoft sample code, some from 
// other free sources. The Application icons are from Foood's "iCandy" icon 
// set (http://www.iconaholic.com). the Shield Icons are taken from Windows XP 
// Service Pack 2 (xpsp2res.dll) 
// 
// Feel free to use the SuRun sources for your liking.
// 
//                                   (c) Kay Bruns (http://kay-bruns.de), 2007
//////////////////////////////////////////////////////////////////////////////

/////////////////////////////////////////////////////////////////////////////
//
// Most of this is heavily based on SuDown (http://sudown.sourceforge.net)
//
/////////////////////////////////////////////////////////////////////////////

#define _WIN32_WINNT 0x0500
#define WINVER       0x0500
#include <windows.h>
#include <TCHAR.h>
#include <shlwapi.h>
#include <lm.h>
#include "Helpers.h"
#include "ResStr.h"
#include "UserGroups.h"
#include "Resource.h"
#include "LogonDlg.h"
#include "DBGTrace.h"

#pragma comment(lib,"shlwapi.lib")
#pragma comment(lib,"Netapi32.lib")

/////////////////////////////////////////////////////////////////////////////
//
// CreateSuRunnersGroup
//
/////////////////////////////////////////////////////////////////////////////
void CreateSuRunnersGroup()
{
  LOCALGROUP_INFO_1	lgri1={SURUNNERSGROUP,CResStr(IDS_GRPDESC)};
  DWORD error;
  NetLocalGroupAdd(NULL,1,(LPBYTE)&lgri1,&error);
}

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
    WCHAR DomainName[UNLEN+1];
    DWORD DnLen = UNLEN;
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
//  Adds or removes "DOMAIN\User" from the local group "Group"
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
/**/
BOOL IsInGroup(LPCWSTR Group,LPCWSTR DomainAndName)
{	
  //try to find user in local group
  NET_API_STATUS status;
	do
	{
    LPLOCALGROUP_MEMBERS_INFO_2 Members = NULL;
    DWORD num = 0;
    DWORD total = 0;
    DWORD_PTR resume = 0;
    DWORD i;
		status = NetLocalGroupGetMembers(NULL,Group,2,(LPBYTE*)&Members,MAX_PREFERRED_LENGTH,&num,&total,&resume);
		if (((status==NERR_Success)||(status==ERROR_MORE_DATA)))
		{
			if (Members)
				for(i = 0; (i<total); i++)
        {
          switch (Members[i].lgrmi2_sidusage)
          {
          case SidTypeUser:
            if(wcscmp(Members[i].lgrmi2_domainandname, DomainAndName)==0)
            {
              NetApiBufferFree(Members);
              DBGTrace2("SuRun: User %s is in Group %s",DomainAndName,Group);
              return TRUE;
            }
            break;
          case SidTypeComputer:
          case SidTypeDomain:
          case SidTypeGroup:
          case SidTypeWellKnownGroup:
            //Groups can be member of groups
            if (IsInGroup(Members[i].lgrmi2_domainandname,DomainAndName))
              return TRUE;
            break;
          }
        }
		}
    NetApiBufferFree(Members);
    Members=0;
	}while (status==ERROR_MORE_DATA);
  //try to find user in network group
  {
    TCHAR dn[2*UNLEN+2]={0};
    _tcscpy(dn,Group);
    PathRemoveFileSpec(dn);
    LPTSTR dc=0;
    if (NetGetAnyDCName(0,dn,(BYTE**)&dc)==NERR_Success) 
    {
      TCHAR gn[2*UNLEN+2]={0};
      _tcscpy(gn,Group);
      PathStripPath(gn);
      DWORD_PTR i=0;
      for(DWORD res=ERROR_MORE_DATA;res==ERROR_MORE_DATA;)
      { 
        LPBYTE pBuff=0;
        DWORD dwRec=0;
        DWORD dwTot=0;
        res = NetGroupGetUsers(dc,gn,0,&pBuff,MAX_PREFERRED_LENGTH,&dwRec,&dwTot,&i);
        if((res!=ERROR_SUCCESS) && (res!=ERROR_MORE_DATA))
        {
          DBGTrace3("NetGroupGetUsers(%s,%s) failed: %s",dc,gn,GetErrorNameStatic(res));
          break;
        }
        for(GROUP_USERS_INFO_0* p=(GROUP_USERS_INFO_0*)pBuff;dwRec>0;dwRec--,p++)
        {
          USER_INFO_2* b=0;
          NetUserGetInfo(dc,p->grui0_name,2,(LPBYTE*)&b);
          if (b)
          {
            if ((b->usri2_flags & UF_ACCOUNTDISABLE)==0)
            {
              CResStr s(L"%s\\%s",dn,p->grui0_name);
              if(wcscmp(s, DomainAndName)==0)
              {
                NetApiBufferFree(b);
                NetApiBufferFree(pBuff);
                NetApiBufferFree(dc);
                DBGTrace2("SuRun: User %s is in Group %s",DomainAndName,Group);
                return TRUE;
              }
            }
            NetApiBufferFree(b);
          }else
            DBGTrace1("NetUserGetInfo failed: %s",GetErrorNameStatic(res));
        }
        NetApiBufferFree(pBuff);
      }
      NetApiBufferFree(dc);
    }
  }
  DBGTrace2("SuRun: User %s is NOT in Group %s",DomainAndName,Group);
	return FALSE;
}
/**/

/**
BOOL IsInGroup(LPCWSTR Group,LPCWSTR DomainAndName)
{
	if (AlterGroupMember(Group,DomainAndName,TRUE)==ERROR_MEMBER_IN_ALIAS)
		return TRUE;
	AlterGroupMember(Group,DomainAndName,FALSE);
	return FALSE;
}
/**/

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
// IsInSuRunners
//
//  Checks if "DOMAIN\User" is a member of the SuRunners localgroup
/////////////////////////////////////////////////////////////////////////////
BOOL IsInSuRunners(LPCWSTR DomainAndName)
{
  return IsInGroup(SURUNNERSGROUP,DomainAndName);
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

//////////////////////////////////////////////////////////////////////////////
// 
//  BeOrBecomeSuRunner: check, if User is member of SuRunners, 
//      if not, try to join him
//////////////////////////////////////////////////////////////////////////////
BOOL BeOrBecomeSuRunner(LPCTSTR UserName,BOOL bVerifyAdmin/*=TRUE*/)
{
  CResStr sCaption(IDS_APPNAME);
  _tcscat(sCaption,L" (");
  _tcscat(sCaption,UserName);
  _tcscat(sCaption,L")");
  if (IsBuiltInAdmin(UserName))
  {
    MessageBox(0,CBigResStr(IDS_BUILTINADMIN),sCaption,MB_ICONSTOP);
    return FALSE;
  }
  //Is User member of SuRunners?
  if (IsInSuRunners(UserName))
  {
    if (IsInGroup(DOMAIN_ALIAS_RID_ADMINS,UserName))
    {
      DWORD dwRet=AlterGroupMember(DOMAIN_ALIAS_RID_USERS,UserName,1);
      if (dwRet && (dwRet!=ERROR_MEMBER_IN_ALIAS))
      {
        MessageBox(0,CBigResStr(IDS_NOADD2USERS,GetErrorNameStatic(dwRet)),sCaption,MB_ICONSTOP);
        return FALSE;
      }
      dwRet=AlterGroupMember(DOMAIN_ALIAS_RID_ADMINS,UserName,0);
      if (dwRet && (dwRet!=ERROR_MEMBER_NOT_IN_ALIAS))
      {
        MessageBox(0,CBigResStr(IDS_NOREMADMINS,GetErrorNameStatic(dwRet)),sCaption,MB_ICONSTOP);
        return FALSE;
      }
    }
    return TRUE;
  }
  if (IsInGroup(DOMAIN_ALIAS_RID_ADMINS,UserName))
  {
    if(MessageBox(0,CBigResStr(IDS_ASKSURUNNER),sCaption,
      MB_YESNO|MB_DEFBUTTON2|MB_ICONQUESTION)==IDNO)
      return FALSE;
    DWORD dwRet=AlterGroupMember(DOMAIN_ALIAS_RID_USERS,UserName,1);
    if (dwRet && (dwRet!=ERROR_MEMBER_IN_ALIAS))
    {
      MessageBox(0,CBigResStr(IDS_NOADD2USERS,GetErrorNameStatic(dwRet)),sCaption,MB_ICONSTOP);
      return FALSE;
    }
    dwRet=AlterGroupMember(DOMAIN_ALIAS_RID_ADMINS,UserName,0);
    if (dwRet && (dwRet!=ERROR_MEMBER_NOT_IN_ALIAS))
    {
      MessageBox(0,CBigResStr(IDS_NOREMADMINS,GetErrorNameStatic(dwRet)),sCaption,MB_ICONSTOP);
      return FALSE;
    }
    dwRet=(AlterGroupMember(SURUNNERSGROUP,UserName,1)!=0);
    if (dwRet && (dwRet!=ERROR_MEMBER_IN_ALIAS))
    {
      MessageBox(0,CBigResStr(IDS_SURUNNER_ERR,GetErrorNameStatic(dwRet)),sCaption,MB_ICONSTOP);
      return FALSE;
    }
    MessageBox(0,CBigResStr(IDS_LOGOFFON),sCaption,MB_ICONINFORMATION);
    return TRUE;
  }
  if (bVerifyAdmin && (!LogonAdmin(IDS_NOSURUNNER)))
    return FALSE;
  DWORD dwRet=(AlterGroupMember(SURUNNERSGROUP,UserName,1)!=0);
  if (dwRet && (dwRet!=ERROR_MEMBER_IN_ALIAS))
  {
    MessageBox(0,CBigResStr(IDS_SURUNNER_ERR,GetErrorNameStatic(dwRet)),sCaption,MB_ICONSTOP);
    return FALSE;
  }
  MessageBox(0,CBigResStr(IDS_SURUNNER_OK),sCaption,MB_ICONINFORMATION);
  return TRUE;
}

/////////////////////////////////////////////////////////////////////////////
//
// User list
//
/////////////////////////////////////////////////////////////////////////////

USERLIST::USERLIST()
{
  nUsers=0;
  User=0;
}

USERLIST::~USERLIST()
{
  for (int i=0;i<nUsers;i++)
    DeleteObject(User[i].UserBitmap);
  free(User);
}

LPTSTR USERLIST::GetUserName(int nUser)
{
  if ((nUser<0)||(nUser>=nUsers))
    return 0;
  return User[nUser].UserName;
}

HBITMAP USERLIST::GetUserBitmap(int nUser)
{
  if ((nUser<0)||(nUser>=nUsers))
    return 0;
  return User[nUser].UserBitmap;
}

HBITMAP USERLIST::GetUserBitmap(LPTSTR UserName)
{
  TCHAR un[2*UNLEN+2];
  _tcscpy(un,UserName);
  PathStripPath(un);
  for (int i=0;i<nUsers;i++) 
  {
    TCHAR UN[2*UNLEN+2]={0};
    _tcscpy(UN,User[i].UserName);
    PathStripPath(UN);
    if (_tcsicmp(un,UN)==0)
      return User[i].UserBitmap;
  }
  return 0;
}

void USERLIST::SetUsualUsers()
{
  for (int i=0;i<nUsers;i++)
    DeleteObject(User[i].UserBitmap);
  free(User);
  User=0;
  nUsers=0;
  for (int g=0;g<countof(UserGroups);g++)
    AddGroupUsers(UserGroups[g]);
}

void USERLIST::SetGroupUsers(LPWSTR GroupName)
{
  for (int i=0;i<nUsers;i++)
    DeleteObject(User[i].UserBitmap);
  free(User);
  User=0;
  nUsers=0;
  if (_tcscmp(GroupName,_T("*"))==0)
    AddAllUsers();
  else
    AddGroupUsers(GroupName);
}

void USERLIST::SetGroupUsers(DWORD WellKnownGroup)
{
  DWORD GNLen=GNLEN;
  WCHAR GroupName[GNLEN+1];
  if (GetGroupName(WellKnownGroup,GroupName,&GNLen))
    SetGroupUsers(GroupName);
}

void USERLIST::Add(LPWSTR UserName)
{
  for(int j=0;j<nUsers;j++)
  {
    int cr=_tcsicmp(User[j].UserName,UserName);
    if (cr==0)
      return;
    if (cr>0)
    {
      if (j<nUsers)
      {
        User=(USERDATA*)realloc(User,(nUsers+1)*sizeof(USERDATA));
        memmove(&User[j+1],&User[j],(nUsers-j)*sizeof(User[0]));
      }
      break;
    }
  }
  if (j>=nUsers)
    User=(USERDATA*)realloc(User,(nUsers+1)*sizeof(USERDATA));
  DBGTrace1("-->AddUser: %s",UserName);
  wcscpy(User[j].UserName,UserName);
  User[j].UserBitmap=LoadUserBitmap(UserName);
  nUsers++;
  return;
}

void USERLIST::AddGroupUsers(LPWSTR GroupName)
{
  DBGTrace1("AddGroupUsers for Group %s",GroupName);
  //First try to add network group members
  {
    TCHAR dn[2*UNLEN+2]={0};
    _tcscpy(dn,GroupName);
    PathRemoveFileSpec(dn);
    LPTSTR dc=0;
    if (NetGetAnyDCName(0,dn,(BYTE**)&dc)==NERR_Success) 
    {
      TCHAR gn[2*UNLEN+2]={0};
      _tcscpy(gn,GroupName);
      PathStripPath(gn);
      DWORD_PTR i=0;
      DWORD res=ERROR_MORE_DATA;
      for(;res==ERROR_MORE_DATA;)
      { 
        LPBYTE pBuff=0;
        DWORD dwRec=0;
        DWORD dwTot=0;
        res = NetGroupGetUsers(dc,gn,0,&pBuff,MAX_PREFERRED_LENGTH,&dwRec,&dwTot,&i);
        if((res!=ERROR_SUCCESS) && (res!=ERROR_MORE_DATA))
        {
          DBGTrace3("NetGroupGetUsers(%s,%s) failed: %s",dc,gn,GetErrorNameStatic(res));
          break;
        }
        for(GROUP_USERS_INFO_0* p=(GROUP_USERS_INFO_0*)pBuff;dwRec>0;dwRec--,p++)
        {
          USER_INFO_2* b=0;
          NetUserGetInfo(dc,p->grui0_name,2,(LPBYTE*)&b);
          if (b)
          {
            if ((b->usri2_flags & UF_ACCOUNTDISABLE)==0)
              Add(CResStr(L"%s\\%s",dn,p->grui0_name));
            NetApiBufferFree(b);
          }else
            DBGTrace3("NetUserGetInfo(%s,%s) failed: %s",dc,p->grui0_name,GetErrorNameStatic(res));
        }
        NetApiBufferFree(pBuff);
      }
      NetApiBufferFree(dc);
    }
  }

  //second try to add local group members
  DWORD_PTR i=0;
  DWORD res=ERROR_MORE_DATA;
  for(;res==ERROR_MORE_DATA;)
  { 
    LPBYTE pBuff=0;
    DWORD dwRec=0;
    DWORD dwTot=0;
    res = NetLocalGroupGetMembers(0,GroupName,2,&pBuff,MAX_PREFERRED_LENGTH,&dwRec,&dwTot,&i);
    if((res!=ERROR_SUCCESS) && (res!=ERROR_MORE_DATA))
    {
      DBGTrace1("NetLocalGroupGetMembers failed: %s",GetErrorNameStatic(res));
      break;
    }
    for(LOCALGROUP_MEMBERS_INFO_2* p=(LOCALGROUP_MEMBERS_INFO_2*)pBuff;dwRec>0;dwRec--,p++)
    {
      switch (p->lgrmi2_sidusage)
      {
      case SidTypeUser:
        {
          TCHAR un[2*UNLEN+2]={0};
          TCHAR dn[2*UNLEN+2]={0};
          _tcscpy(un,p->lgrmi2_domainandname);
          PathStripPath(un);
          _tcscpy(dn,p->lgrmi2_domainandname);
          PathRemoveFileSpec(dn);
          USER_INFO_2* b=0;
          LPTSTR dc=0;
          //
          if(NetGetAnyDCName(0,dn,(BYTE**)&dc)==NERR_Success)
            NetUserGetInfo(dc,un,2,(LPBYTE*)&b);
          else
            NetUserGetInfo(dn,un,2,(LPBYTE*)&b);
          if (b)
          {
            if ((b->usri2_flags & UF_ACCOUNTDISABLE)==0)
              Add(p->lgrmi2_domainandname);
            NetApiBufferFree(b);
          }
          if(dc)
            NetApiBufferFree(dc);
        }
        break;
      case SidTypeComputer:
      case SidTypeDomain:
      case SidTypeGroup:
      case SidTypeWellKnownGroup:
        //Groups can be members of Groups...
        AddGroupUsers(p->lgrmi2_domainandname);
        break;
      }
    }
    NetApiBufferFree(pBuff);
  }
}

void USERLIST::AddGroupUsers(DWORD WellKnownGroup)
{
  DWORD GNLen=GNLEN;
  WCHAR GroupName[GNLEN+1];
  if (GetGroupName(WellKnownGroup,GroupName,&GNLen))
    AddGroupUsers(GroupName);
}

void USERLIST::AddAllUsers()
{
  DWORD_PTR i=0;
  DWORD res=ERROR_MORE_DATA;
  for(;res==ERROR_MORE_DATA;)
  { 
    LPBYTE pBuff=0;
    DWORD dwRec=0;
    DWORD dwTot=0;
    res = NetLocalGroupEnum(NULL,0,&pBuff,MAX_PREFERRED_LENGTH,&dwRec,&dwTot,&i);
    if((res!=ERROR_SUCCESS) && (res!=ERROR_MORE_DATA))
    {
      DBGTrace1("NetLocalGroupEnum failed: %s",GetErrorNameStatic(res));
      return;
    }
    for(LOCALGROUP_INFO_0* p=(LOCALGROUP_INFO_0*)pBuff;dwRec>0;dwRec--,p++)
      AddGroupUsers(p->lgrpi0_name);
    NetApiBufferFree(pBuff);
  }
}