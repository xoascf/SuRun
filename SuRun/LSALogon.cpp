#define _WIN32_WINNT 0x0500
#define WINVER       0x0500
#include <windows.h>
#include <ntsecapi.h>
#include "Helpers.h"

#pragma comment(lib,"Advapi32.lib")
#pragma comment(lib,"Kernel32.lib")
#pragma comment(lib,"Secur32.lib ")

#define AUTH_PACKAGE "MICROSOFT_AUTHENTICATION_PACKAGE_V1_0"

#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS                  ((NTSTATUS)0x00000000L)
#define STATUS_UNSUCCESSFUL             ((NTSTATUS)0xC0000001L)
#endif

#define LSASTR(s,S) LSA_STRING s; InitString(&s,S);

void InitString(PLSA_STRING LsaString,LPSTR String)
{
  size_t StringLength;
  if (String == NULL)
  {
    LsaString->Buffer = NULL;
    LsaString->Length = 0;
    LsaString->MaximumLength = 0;
    return;
  }
  StringLength = strlen(String);
  LsaString->Buffer = String;
  LsaString->Length = (USHORT)StringLength*sizeof(CHAR);
  LsaString->MaximumLength =(USHORT)(StringLength+1)*sizeof(CHAR);
}

int _stringLenInBytes(const LPWSTR s) 
{
  if (!s) 
    return 0;
  return (lstrlen(s)+1) * sizeof *s;
}

void _initUnicodeString(UNICODE_STRING* target, LPWSTR source, USHORT cbMax) 
{
  target->Length        = max(sizeof *source,cbMax) - sizeof *source;
  target->MaximumLength = cbMax;
  target->Buffer        = source;
}

MSV1_0_INTERACTIVE_LOGON* GetLogonRequest(LPWSTR domain,LPWSTR user,LPWSTR pass,DWORD* pcbRequest) 
{
  const DWORD cbHeader = sizeof(MSV1_0_INTERACTIVE_LOGON);
  const DWORD cbDom    = _stringLenInBytes(domain);
  const DWORD cbUser   = _stringLenInBytes(user);
  const DWORD cbPass   = _stringLenInBytes(pass);
  *pcbRequest=cbHeader+cbDom+cbUser+cbPass;
  MSV1_0_INTERACTIVE_LOGON* pRequest =
    (MSV1_0_INTERACTIVE_LOGON*)LocalAlloc(LMEM_FIXED, *pcbRequest);
  if (!pRequest) 
    return 0;
  pRequest->MessageType = MsV1_0InteractiveLogon;
  char* p = (char*)(pRequest + 1); // point right past MSV1_0_INTERACTIVE_LOGON
  LPWSTR pDom  = (LPWSTR)(p);
  LPWSTR pUser = (LPWSTR)(p + cbDom);
  LPWSTR pPass = (LPWSTR)(p + cbDom + cbUser);
  CopyMemory(pDom,  domain, cbDom);
  CopyMemory(pUser, user,   cbUser);
  CopyMemory(pPass, pass,   cbPass);
  _initUnicodeString(&pRequest->LogonDomainName, pDom,  (USHORT)cbDom);
  _initUnicodeString(&pRequest->UserName,        pUser, (USHORT)cbUser);
  _initUnicodeString(&pRequest->Password,        pPass, (USHORT)cbPass);
  return pRequest;
}

HANDLE LSALogon(DWORD SessionID,LPWSTR UserName,LPWSTR Domain,
                LPWSTR Password,bool bNoAdmin)
{
  EnablePrivilege(SE_TCB_NAME);
  HANDLE hLSA;
  LSA_OPERATIONAL_MODE SecurityMode;
  LSASTR(ProcName,"Winlogon");
  if (LsaRegisterLogonProcess(&ProcName,&hLSA,&SecurityMode))
    return 0;
  TOKEN_SOURCE tsrc;
  QUOTA_LIMITS Quotas;
  PMSV1_0_INTERACTIVE_PROFILE* pProf=0;
  ULONG AuthInfoSize=0;
  PMSV1_0_INTERACTIVE_LOGON AuthInfo=0;
  ULONG ProfLen;
  PTOKEN_GROUPS ptg=NULL;
  PSID LogonSID=NULL;
  PSID AdminSID=NULL;
  PSID LocalSid=NULL;
  USHORT cbUserName;
  USHORT cbDomain;
  USHORT cbPassword;
  HANDLE hUser=0;
  NTSTATUS Status;
  // 
  // Initialize source context structure
  // 
  __try
  {
    HANDLE hShell=GetSessionUserToken(SessionID);
    if (hShell)
    {
      DWORD n=0;
      //Copy TokenSource from the Shell Process of SessionID:
      GetTokenInformation(hShell,TokenSource,&tsrc,sizeof(tsrc),&n);
      //Copy Logon SID from the Shell Process of SessionID:
      LogonSID=GetLogonSid(hShell);
      CloseHandle(hShell);
      hShell=0;
    }else
      __leave;
    // Initialize Admin SID
    SID_IDENTIFIER_AUTHORITY SystemSidAuthority = SECURITY_NT_AUTHORITY;
    if (!AllocateAndInitializeSid(&SystemSidAuthority,2,SECURITY_BUILTIN_DOMAIN_RID,
      DOMAIN_ALIAS_RID_ADMINS,0,0,0,0,0,0,&AdminSID))
      __leave;
    SID_IDENTIFIER_AUTHORITY IdentifierAuthority=SECURITY_LOCAL_SID_AUTHORITY;
    if (!AllocateAndInitializeSid(&IdentifierAuthority,1,SECURITY_LOCAL_RID,
      0,0,0,0,0,0,0,&LocalSid))
      __leave;
    //Initialize TOKEN_GROUPS
    ptg=(PTOKEN_GROUPS)malloc(sizeof(DWORD)+3*sizeof(SID_AND_ATTRIBUTES));
    if (ptg==NULL)
      __leave;
    ptg->GroupCount=bNoAdmin?2:3;
    ptg->Groups[0].Sid=LogonSID;
    ptg->Groups[0].Attributes=SE_GROUP_MANDATORY|SE_GROUP_ENABLED
      |SE_GROUP_ENABLED_BY_DEFAULT|SE_GROUP_LOGON_ID;
    ptg->Groups[1].Sid=LocalSid;
    ptg->Groups[1].Attributes=
      SE_GROUP_MANDATORY|SE_GROUP_ENABLED|SE_GROUP_ENABLED_BY_DEFAULT;
    ptg->Groups[2].Sid=AdminSID;
    ptg->Groups[2].Attributes=
      SE_GROUP_MANDATORY|SE_GROUP_ENABLED|SE_GROUP_ENABLED_BY_DEFAULT;
    //AuthInfo
    AuthInfo=GetLogonRequest(Domain,UserName,Password,&AuthInfoSize);
    if (!AuthInfo)
      __leave;
    //PackageName
    LSASTR(PackageName,AUTH_PACKAGE);
    DWORD AuthPackageId=0;
    if ((LsaLookupAuthenticationPackage(hLSA,&PackageName,&AuthPackageId))!=STATUS_SUCCESS)
      __leave;
    LUID LogonLuid={0};
    NTSTATUS SubStatus=0;
    Status=LsaLogonUser(hLSA,&ProcName,Interactive,AuthPackageId,AuthInfo,
      AuthInfoSize,ptg,&tsrc,(PVOID*)&pProf,
      &ProfLen,&LogonLuid,&hUser,&Quotas,&SubStatus);
    if (Status!=ERROR_SUCCESS)
      __leave;
  } // try
  __finally
  {
    cbUserName = cbDomain = cbPassword = 0; // sensitive information
    if (ptg)
      free(ptg);
    if (AuthInfo)
    {
      ZeroMemory(AuthInfo,AuthInfoSize); // sensitive buffer
      LocalFree(AuthInfo);
    }
    if (pProf)
      LsaFreeReturnBuffer(pProf);
    if (AdminSID)
      FreeSid(AdminSID);
    if (LocalSid)
      FreeSid(LocalSid);
    if (LogonSID)
      free(LogonSID);
  } // finally
  LsaDeregisterLogonProcess(hLSA);
  return hUser;
}
