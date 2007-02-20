#if !defined(AFX_TRAYMSGWND_H__0894CDC8_FC2A_4A01_B8A7_F5F3FEB75D8C__INCLUDED_)
#define AFX_TRAYMSGWND_H__0894CDC8_FC2A_4A01_B8A7_F5F3FEB75D8C__INCLUDED_

#pragma once
// TrayMsgWnd.h : header file
//
void TrayMsg(LPTSTR DlgTitle,int nID,...);
void TrayMsg(LPTSTR DlgTitle,CString s,...);

void TrayMsgWnd(LPCTSTR DlgTitle,LPCTSTR Message);
void TrayMsgWnd(void* Buf);

void TrayMsgClear();

//{{AFX_INSERT_LOCATION}}
// Microsoft Visual C++ will insert additional declarations immediately before the previous line.

#endif // !defined(AFX_TRAYMSGWND_H__0894CDC8_FC2A_4A01_B8A7_F5F3FEB75D8C__INCLUDED_)
