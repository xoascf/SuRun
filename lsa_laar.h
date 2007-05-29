#pragma once

typedef enum {
    DelPrivilege = 0,
    AddPrivilege,
    HasPrivilege
}PrivOp;

BOOL AccountPrivilege(LPTSTR Account,LPTSTR Privilege,PrivOp op);

#define AddAcctPrivilege(a,p) AccountPrivilege(a,p,AddPrivilege)
#define DelAcctPrivilege(a,p) AccountPrivilege(a,p,DelPrivilege)
#define HasAcctPrivilege(a,p) AccountPrivilege(a,p,HasPrivilege)