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

//////////////////////////////////////////////////////////////////////////////
// Home of CBlurredScreen
//
// This class captures the Windows Desktop (containing all windows) 
// into a bitmap, blurres and darkens that bitmap and displays a fullscreen 
// window with that bitmap as client area
//
//////////////////////////////////////////////////////////////////////////////

#pragma once
#include <WINDOWS.h>
#include <TCHAR.h>
#include "DBGTrace.H"

//Simplified 3x3 Gausian blur
inline void Blur(COLORREF* pDst,COLORREF* pSrc,DWORD w,DWORD h)
{
//  CTimeLog l(_T("Blur %dx%d"),w,h);
  DWORD x,y,c1,c2;
  for (y=1;y<h-1;y++)
    for (x=1;x<w-1;x++)
    {
      c1 =(pSrc[x-1+(y-1)*w]&0x00FF00FF);
      c2 =(pSrc[x-1+(y-1)*w]&0x0000FF00);
      c1+=(pSrc[x+(y-1)*w]&0x00FF00FF)<<1;
      c2+=(pSrc[x+(y-1)*w]&0x0000FF00)<<1;
      c1+=(pSrc[x+1+(y-1)*w]&0x00FF00FF);
      c2+=(pSrc[x+1+(y-1)*w]&0x0000FF00);
      c1+=(pSrc[x-1+y*w]&0x00FF00FF)<<1;
      c2+=(pSrc[x-1+y*w]&0x0000FF00)<<1;
      c1+=(pSrc[x+y*w]&0x00FF00FF)<<2;
      c2+=(pSrc[x+y*w]&0x0000FF00)<<2;
      c1+=(pSrc[x+1+y*w]&0x00FF00FF)<<1;
      c2+=(pSrc[x+1+y*w]&0x0000FF00)<<1;
      c1+=(pSrc[x-1+(y+1)*w]&0x00FF00FF);
      c2+=(pSrc[x-1+(y+1)*w]&0x0000FF00);
      c1+=(pSrc[x+(y+1)*w]&0x00FF00FF)<<1;
      c2+=(pSrc[x+(y+1)*w]&0x0000FF00)<<1;
      c1+=(pSrc[x+1+(y+1)*w]&0x00FF00FF);
      c2+=(pSrc[x+1+(y+1)*w]&0x0000FF00);
      pDst[x+y*w]=((c1>>5)&0x00FF00FF)+((c2>>5)&0x0000FF00);
    }
}

//Globals: (for better speed!)
static BITMAPINFO g_bmi32={{sizeof(BITMAPINFOHEADER),0,0,1,32,0,0,0,0},0};

inline HBITMAP Blur(HBITMAP hbm,DWORD w,DWORD h)
{
  HBITMAP hbbm=0;
  g_bmi32.bmiHeader.biHeight=h;
  g_bmi32.bmiHeader.biWidth=w;
  g_bmi32.bmiHeader.biSizeImage=((((w+3)/4)*4)*((h+3)/4)*4)*4;
  COLORREF* pSrc=(COLORREF*)malloc(g_bmi32.bmiHeader.biSizeImage); 
  if (pSrc==NULL)
    return 0;
  HDC DC=GetDC(0);
  if(!GetDIBits(DC,hbm,0,h,pSrc,&g_bmi32,DIB_RGB_COLORS))
  {
    ReleaseDC(0,DC);
    free(pSrc);
    return hbbm;
  }
  COLORREF* pDst=(COLORREF*)calloc(g_bmi32.bmiHeader.biSizeImage,1);
  if (pDst!=NULL)
  {
    Blur(pDst,pSrc,w,h);
    hbbm=CreateCompatibleBitmap(DC,w,h);
    SetDIBits(DC,hbbm,0,w,pDst,&g_bmi32,DIB_RGB_COLORS);
    free(pDst);
  }
  ReleaseDC(0,DC);
  free(pSrc);
  return hbbm;
}

class CBlurredScreen
{
public:
  CBlurredScreen()
  {
    m_hWnd=0;
    m_hWndTrans=0;
    m_dx=0;
    m_dy=0;
    m_bm=0;
    m_blurbm=0;
    m_Thread=NULL;
    timeBeginPeriod(1);
  }
  ~CBlurredScreen()
  {
    Done();
    timeEndPeriod(1);
  }
  HWND hWnd(){return m_hWndTrans;};
  void Init()
  {
    m_dx=GetSystemMetrics(SM_CXVIRTUALSCREEN);
    m_dy=GetSystemMetrics(SM_CYVIRTUALSCREEN);
    HDC dc=GetDC(0);
    HDC MemDC=CreateCompatibleDC(dc);
    m_bm=CreateCompatibleBitmap(dc,m_dx,m_dy);
    (HBITMAP)SelectObject(MemDC,m_bm);
    BitBlt(MemDC,0,0,m_dx,m_dy,dc,0,0,SRCCOPY|CAPTUREBLT);
    DeleteDC(MemDC);
    ReleaseDC(0,dc);
  }
  void Done()
  {
    if(m_Thread)
    {
      if(WaitForSingleObject(m_Thread,2000)!=WAIT_OBJECT_0)
        TerminateThread(m_Thread,0);
      CloseHandle(m_Thread);
    }
    m_Thread=NULL;
    if(m_hWnd)
    {
      SetWindowLongPtr(m_hWnd,GWLP_USERDATA,0);
      DestroyWindow(m_hWnd);
    }
    m_hWnd=0;
    if(m_hWndTrans)
    {
      SetWindowLongPtr(m_hWndTrans,GWLP_USERDATA,0);
      DestroyWindow(m_hWndTrans);
    }
    m_hWndTrans=0;
    if (m_bm)
      DeleteObject(m_bm);
    m_bm=0;
    if (m_blurbm)
      DeleteObject(m_blurbm);
    m_blurbm=0;
    UnregisterClass(_T("ScreenWndClass"),GetModuleHandle(0));
  }
  void Show(bool bFadeIn)
  {
    WNDCLASS wc={0};
    OSVERSIONINFO oie;
    oie.dwOSVersionInfoSize=sizeof(oie);
    GetVersionEx(&oie);
    bool bWin2k=(oie.dwMajorVersion==5)&&(oie.dwMinorVersion==0);
    wc.lpfnWndProc=CBlurredScreen::WindowProc;
    wc.lpszClassName=_T("ScreenWndClass");
    wc.hInstance=GetModuleHandle(0);
    RegisterClass(&wc);
    m_hWnd=CreateWindowEx(WS_EX_NOACTIVATE,wc.lpszClassName,
      _T("ScreenWnd"),WS_VISIBLE|WS_POPUP|WS_DISABLED|WS_VISIBLE,0,0,
      m_dx,m_dy,0,0,wc.hInstance,0);
    SetWindowLongPtr(m_hWnd,GWLP_USERDATA,(LONG_PTR)this);
    RedrawWindow(m_hWnd,0,0,RDW_INTERNALPAINT|RDW_UPDATENOW);
    if((!bWin2k)&& bFadeIn)
    {
      MsgLoop();
      m_hWndTrans=CreateWindowEx(WS_EX_NOACTIVATE|WS_EX_LAYERED,
        wc.lpszClassName,_T("ScreenWnd"),WS_POPUP|WS_DISABLED|WS_VISIBLE,0,0,
        m_dx,m_dy,m_hWnd,0,wc.hInstance,0);
      SetWindowLongPtr(m_hWndTrans,GWLP_USERDATA,(LONG_PTR)this);
    }else
    {
      m_hWndTrans=m_hWnd;
      m_hWnd=0;
      if (m_bm)
      {
        m_blurbm=Blur(m_bm,m_dx,m_dy);
        DeleteObject(m_bm);
        InvalidateRect(m_hWndTrans,0,true);
      }
      m_bm=0;
    }
    MsgLoop();
  }
  static void MsgLoop()
  {
    MSG msg;
    int count=0;
    while (PeekMessage(&msg,0,0,0,PM_REMOVE) && (count++<100))
    {
      TranslateMessage(&msg);
      DispatchMessage(&msg);
    }
  }
  void FadeIn()
  {
    if (m_hWndTrans && m_hWnd && m_bm && (m_Thread==NULL))
      m_Thread=CreateThread(0,0,BlurProc,this,0,0);
  }
  void FadeOut()
  {
    if (m_Thread && m_hWndTrans && m_hWnd)
    {
      if(WaitForSingleObject(m_Thread,2000)!=WAIT_OBJECT_0)
        TerminateThread(m_Thread,0);
      DWORD StartTime=timeGetTime();
      BYTE a=255;
      while (a)
      {
        a=255-(BYTE)min(255,(timeGetTime()-StartTime)/2);
        SetLayeredWindowAttributes(m_hWndTrans,0,a,LWA_ALPHA);
        MsgLoop();
      }
    }
  }
private:
  static DWORD WINAPI BlurProc(void* p)
  {
    SetThreadPriority(GetCurrentThread(),THREAD_PRIORITY_IDLE);
    Sleep(200);
    CBlurredScreen* bs=(CBlurredScreen*)p;  
    bs->m_blurbm=Blur(bs->m_bm,bs->m_dx,bs->m_dy);
    SetLayeredWindowAttributes(bs->m_hWndTrans,0,0,LWA_ALPHA);
    RedrawWindow(bs->m_hWndTrans,0,0,RDW_INTERNALPAINT|RDW_UPDATENOW);
    DWORD StartTime=timeGetTime();
    for(;;)
    {
      BYTE a=(BYTE)min(255,(timeGetTime()-StartTime)/2);
      SetLayeredWindowAttributes(bs->m_hWndTrans,0,a,LWA_ALPHA);
      MsgLoop();
      if (a==255)
        return 0;
    }
    return 0;
  }
  static LRESULT CALLBACK WindowProc(HWND hWnd,UINT msg,WPARAM wParam,LPARAM lParam)
  {
    CBlurredScreen* bs=(CBlurredScreen*)GetWindowLongPtr(hWnd,GWLP_USERDATA);
    if (bs)
      return bs->WndProc(hWnd,msg,wParam,lParam);
    return DefWindowProc(hWnd,msg,wParam,lParam);
  }
  LRESULT CALLBACK WndProc(HWND hwnd,UINT msg,WPARAM wParam,LPARAM lParam)
  {
    switch (msg)
    {
    case WM_PAINT:
      {
        PAINTSTRUCT ps;
        HDC hdc= BeginPaint(hwnd, &ps);
        HBITMAP bm=(hwnd==m_hWnd)?m_bm:m_blurbm;
        if(bm)
        {
          HDC MemDC=CreateCompatibleDC(hdc);
          SelectObject(MemDC,bm);
          BitBlt(hdc,0,0,m_dx,m_dy,MemDC,0,0,SRCCOPY);
          DeleteDC(MemDC);
        }
        EndPaint(hwnd, &ps);
        return 0;
      }
    case WM_SETCURSOR:
      SetCursor(LoadCursor(0,IDC_WAIT));
      return TRUE;
    case WM_MOUSEACTIVATE:
      if (LOWORD(lParam)==HTCAPTION)
        return MA_NOACTIVATEANDEAT;
	    return MA_NOACTIVATE;
    }
    return DefWindowProc(hwnd,msg,wParam,lParam);
  }
  HWND m_hWnd;
  HWND m_hWndTrans;
  int m_dx;
  int m_dy;
  HBITMAP m_bm;
  HBITMAP m_blurbm;
  HANDLE m_Thread;
};
