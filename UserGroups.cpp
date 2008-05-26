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

#define _WIN32_WINNT 0x0500
#define WINVER       0x0500
#include <windows.h>
#include <TCHAR.h>
#include <shlwapi.h>
#include <lm.h>
#include "Helpers.h"
#include "ResStr.h"
#include "UserGroups.h"
#include "Setup.h"
#include "Resource.h"
#include "LogonDlg.h"
#include "DBGTrace.h"

#ifdef DoDBGTrace
#include <Sddl.h>
#pragma comment(lib,"Advapi32.lib")
#endif DoDBGTrace

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
// DeleteSuRunnersGroup
//
/////////////////////////////////////////////////////////////////////////////
void DeleteSuRunnersGroup()
{
  NetLocalGroupDel(NULL,SURUNNERSGROUP);
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
// rename User
//
/////////////////////////////////////////////////////////////////////////////
DWORD ChangeUserName(LPWSTR oldName,LPWSTR newName)
{
  TCHAR dn[2*UNLEN+2]={0};
  _tcscpy(dn,_T("\\\\"));
  _tcscat(dn,oldName);
  PathRemoveFileSpec(dn);
  TCHAR on[2*UNLEN+2]={0};
  _tcscpy(on,oldName);
  PathStripPath(on);
  TCHAR nn[2*UNLEN+2]={0};
  _tcscpy(nn,newName);
  PathStripPath(nn);
  USER_INFO_0 ui={0};
  ui.usri0_name=nn;
  DWORD dwErr=0;
  return NetUserSetInfo(dn,on,0,(LPBYTE)&ui,&dwErr);
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
BOOL IsInGroupDirect(LPCWSTR Group,LPCWSTR DomainAndName)
{	
	DWORD result = 0;
	NET_API_STATUS status;
	LPLOCALGROUP_MEMBERS_INFO_3 Members = NULL;
	DWORD num = 0;
	DWORD total = 0;
	DWORD_PTR resume = 0;
	DWORD i;
	do
	{
		status = NetLocalGroupGetMembers(NULL,Group,3,(LPBYTE*)&Members,MAX_PREFERRED_LENGTH,&num,&total,&resume);
		if (((status==NERR_Success)||(status==ERROR_MORE_DATA))&&(result==0))
		{
			if (Members)
				for(i = 0; (i<total); i++)
					if (wcscmp(Members[i].lgrmi3_domainandname, DomainAndName)==0)
          {
            NetApiBufferFree(Members);
            return TRUE;
          }
		}
	}while (status==ERROR_MORE_DATA);
	NetApiBufferFree(Members);
	return FALSE;
}

BOOL IsInGroup(LPCWSTR Group,LPCWSTR DomainAndName)
{	
  //try to find user in local group
  NET_API_STATUS status;
	{
    LPLOCALGROUP_USERS_INFO_0 Users = 0;
    DWORD num = 0;
    DWORD total = 0;
    DWORD_PTR resume = 0;
    status = NetUserGetLocalGroups(NULL,DomainAndName,0,LG_INCLUDE_INDIRECT,
      (LPBYTE*)&Users,MAX_PREFERRED_LENGTH,&num,&total);
		if ((((status==NERR_Success)||(status==ERROR_MORE_DATA)))&& Users)
    {
      for(DWORD i = 0; (i<total); i++) 
        if(wcsicmp(Users[i].lgrui0_name, Group)==0)
        {
          NetApiBufferFree(Users);
          return TRUE;
        }
      NetApiBufferFree(Users);
      Users=0;
    }else
    {
//      DBGTrace3("IsInGroup(%s,%s): NetUserGetLocalGroups failed: %s",
//        Group,DomainAndName,GetErrorNameStatic(status));
      return IsInGroupDirect(Group,DomainAndName);
    }
	}
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
// IsInSuRunners
//
//  Checks if "DOMAIN\User" is a member of the SuRunners localgroup
/////////////////////////////////////////////////////////////////////////////
BOOL IsInSuRunners(LPCWSTR DomainAndName)
{
  if (IsInGroup(SURUNNERSGROUP,DomainAndName))
    return TRUE;
  DelUsrSettings(DomainAndName);
  return FALSE;
}

//////////////////////////////////////////////////////////////////////////////
// 
//  BeOrBecomeSuRunner: check, if User is member of SuRunners, 
//      if not, try to join him
//////////////////////////////////////////////////////////////////////////////
BOOL BeOrBecomeSuRunner(LPCTSTR UserName,BOOL bHimSelf,HWND hwnd)
{
  //Is User member of SuRunners?
  if (IsInSuRunners(UserName))
    return TRUE;
  CResStr sCaption(IDS_APPNAME);
  if(bHimSelf)
  {
    _tcscat(sCaption,L" (");
    _tcscat(sCaption,UserName);
    _tcscat(sCaption,L")");
  }
  //Is User member of Administrators?
  if (IsInGroup(DOMAIN_ALIAS_RID_ADMINS,UserName))
  {
    //Whoops...need to become a User!
    if(SafeMsgBox(hwnd,
      CBigResStr((bHimSelf?IDS_ASKSURUNNER:IDS_ASKSURUNNER1),UserName,UserName),
      sCaption,MB_YESNO|MB_DEFBUTTON2|MB_ICONQUESTION)==IDNO)
      return FALSE;
    DWORD dwRet=AlterGroupMember(DOMAIN_ALIAS_RID_ADMINS,UserName,0);
    if (dwRet)
    {
      //Built in (or Domain-)Admin... Bail out!
      SafeMsgBox(hwnd,
        bHimSelf?CBigResStr(IDS_BUILTINADMIN,GetErrorNameStatic(dwRet)):\
                 CBigResStr(IDS_BUILTINADMIN1,UserName,GetErrorNameStatic(dwRet)),
        sCaption,MB_ICONSTOP);
      return FALSE;
    }
    dwRet=AlterGroupMember(DOMAIN_ALIAS_RID_USERS,UserName,1);
    if (dwRet && (dwRet!=ERROR_MEMBER_IN_ALIAS))
    {
      AlterGroupMember(DOMAIN_ALIAS_RID_ADMINS,UserName,1);
      SafeMsgBox(hwnd,
        bHimSelf?CBigResStr(IDS_NOADD2USERS,GetErrorNameStatic(dwRet)):\
                 CBigResStr(IDS_NOADD2USERS1,UserName,GetErrorNameStatic(dwRet)),
        sCaption,MB_ICONSTOP);
      return FALSE;
    }
    dwRet=(AlterGroupMember(SURUNNERSGROUP,UserName,1)!=0);
    if (dwRet && (dwRet!=ERROR_MEMBER_IN_ALIAS))
    {
      SafeMsgBox(hwnd,
        bHimSelf?CBigResStr(IDS_SURUNNER_ERR,GetErrorNameStatic(dwRet)):\
                 CBigResStr(IDS_SURUNNER_ERR1,UserName,GetErrorNameStatic(dwRet)),
        sCaption,MB_ICONSTOP);
      return FALSE;
    }
    SetRestrictApps(UserName,(DWORD)GetRestrictNew);
    SetNoRunSetup(UserName,(DWORD)GetNoSetupNew);
    if (bHimSelf)
      SafeMsgBox(hwnd,CBigResStr(IDS_LOGOFFON),sCaption,MB_ICONINFORMATION);
    return TRUE;
  }
  if (bHimSelf && (!LogonAdmin(IDS_NOSURUNNER)))
    return FALSE;
  DWORD dwRet=(AlterGroupMember(SURUNNERSGROUP,UserName,1)!=0);
  if (dwRet && (dwRet!=ERROR_MEMBER_IN_ALIAS))
  {
    SafeMsgBox(hwnd,
      bHimSelf?CBigResStr(IDS_SURUNNER_ERR,GetErrorNameStatic(dwRet)):\
               CBigResStr(IDS_SURUNNER_ERR1,UserName,GetErrorNameStatic(dwRet)),
      sCaption,MB_ICONSTOP);
    return FALSE;
  }
  SetRestrictApps(UserName,(DWORD)GetRestrictNew);
  SetNoRunSetup(UserName,(DWORD)GetNoSetupNew);
  if (bHimSelf)
    SafeMsgBox(hwnd,CBigResStr(IDS_SURUNNER_OK),sCaption,MB_ICONINFORMATION);
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
    if(User[i].UserBitmap)
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

void USERLIST::SetUsualUsers(BOOL bScanDomain)
{
  for (int i=0;i<nUsers;i++)
    if(User[i].UserBitmap)
      DeleteObject(User[i].UserBitmap);
  free(User);
  User=0;
  nUsers=0;
  for (int g=0;g<countof(UserGroups);g++)
    AddGroupUsers(UserGroups[g],bScanDomain);
}

void USERLIST::SetGroupUsers(LPWSTR GroupName,BOOL bScanDomain)
{
  for (int i=0;i<nUsers;i++)
    if(User[i].UserBitmap)
      DeleteObject(User[i].UserBitmap);
  free(User);
  User=0;
  nUsers=0;
  if (_tcscmp(GroupName,_T("*"))==0)
    AddAllUsers(bScanDomain);
  else
    AddGroupUsers(GroupName,bScanDomain);
}

void USERLIST::SetGroupUsers(DWORD WellKnownGroup,BOOL bScanDomain)
{
  DWORD GNLen=GNLEN;
  WCHAR GroupName[GNLEN+1];
  if (GetGroupName(WellKnownGroup,GroupName,&GNLen))
    SetGroupUsers(GroupName,bScanDomain);
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
//  DBGTrace1("-->AddUser: %s",UserName);
  wcscpy(User[j].UserName,UserName);
  User[j].UserBitmap=LoadUserBitmap(UserName);
  nUsers++;
  return;
}

void USERLIST::AddGroupUsers(LPWSTR GroupName,BOOL bScanDomain)
{
//  DBGTrace1("AddGroupUsers for Group %s",GroupName);
  TCHAR cn[2*UNLEN+2]={0};
  DWORD cnl=UNLEN;
  GetComputerName(cn,&cnl);
  //First try to add network group members
  if(bScanDomain)
  {
    TCHAR dn[2*UNLEN+2]={0};
    _tcscpy(dn,GroupName);
    PathRemoveFileSpec(dn);
    LPTSTR dc=0;
    if (dn[0]/*only domain groups!*/ && (_tcsicmp(dn,cn)!=0)
      && (NetGetAnyDCName(0,dn,(BYTE**)&dc)==NERR_Success)) 
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
#ifdef DoDBGTrace
//      LPTSTR sSID=0;
//      ConvertSidToStringSid(p->lgrmi2_sid,&sSID);
//      DBGTrace4("Group %s Name: %s; Type: %d; SID: %s",
//        GroupName,p->lgrmi2_domainandname,p->lgrmi2_sidusage,sSID);
//      LocalFree(sSID);
#endif DoDBGTrace
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
          if (dn[0]/*only domain groups!*/ && (_tcsicmp(dn,cn)!=0))
            NetGetAnyDCName(0,dn,(BYTE**)&dc);
          NET_API_STATUS st=NetUserGetInfo(dc,un,2,(LPBYTE*)&b);
          if (b)
          {
            if ((b->usri2_flags & UF_ACCOUNTDISABLE)==0)
              Add(p->lgrmi2_domainandname);
            NetApiBufferFree(b);
          }else
            //User not found: Domain Controller not present! Add user to list
            Add(p->lgrmi2_domainandname);
          if(dc)
            NetApiBufferFree(dc);
        }
        break;
      case SidTypeComputer:
      case SidTypeDomain:
      case SidTypeGroup:
      case SidTypeWellKnownGroup:
        //Groups can be members of Groups...
        AddGroupUsers(p->lgrmi2_domainandname,bScanDomain);
        break;
      }
    }
    NetApiBufferFree(pBuff);
  }
}

void USERLIST::AddGroupUsers(DWORD WellKnownGroup,BOOL bScanDomain)
{
  DWORD GNLen=GNLEN;
  WCHAR GroupName[GNLEN+1];
  if (GetGroupName(WellKnownGroup,GroupName,&GNLen))
    AddGroupUsers(GroupName,bScanDomain);
}

void USERLIST::AddAllUsers(BOOL bScanDomain)
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
      AddGroupUsers(p->lgrpi0_name,bScanDomain);
    NetApiBufferFree(pBuff);
  }
  if (bScanDomain)
  {
    i=0;
    res=ERROR_MORE_DATA;
    for(;res==ERROR_MORE_DATA;)
    { 
      LPBYTE pBuff=0;
      DWORD dwRec=0;
      DWORD dwTot=0;
      res = NetGroupEnum(NULL,0,&pBuff,MAX_PREFERRED_LENGTH,&dwRec,&dwTot,&i);
      if((res!=ERROR_SUCCESS) && (res!=ERROR_MORE_DATA))
      {
        DBGTrace1("NetLocalGroupEnum failed: %s",GetErrorNameStatic(res));
        return;
      }
      for(GROUP_INFO_0* p=(GROUP_INFO_0*)pBuff;dwRec>0;dwRec--,p++)
        AddGroupUsers(p->grpi0_name,bScanDomain);
      NetApiBufferFree(pBuff);
    }
  }
}
