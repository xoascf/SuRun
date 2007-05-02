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

//Globals: (for better speed!)
static BITMAPINFO g_bmi32={{sizeof(BITMAPINFOHEADER),0,0,1,32,0,0,0,0},0};
//The (roughly Gausian) matrix is not multiplied, it is shifted to gain speed
static int g_m8rx[3][3]={{5,4,5},{4,3,4},{5,4,5}};
//The Mask is applied after each shift to multiply all three colors of a pixel 
//at once
static int g_msk [3][3]={{0x00070707,0x000F0F0F,0x00070707},
                         {0x000F0F0F,0x001F1F1F,0x000F0F0F},
                         {0x00070707,0x000F0F0F,0x00070707}};
//Simplified 3x3 Gausian blur
inline void Blur(HBITMAP hbm,int w,int h)
{
  g_bmi32.bmiHeader.biHeight=h;
  g_bmi32.bmiHeader.biWidth=w;
  g_bmi32.bmiHeader.biSizeImage=(w*h)<<2;
  COLORREF* pSrc=(COLORREF*)malloc(g_bmi32.bmiHeader.biSizeImage); 
  if (pSrc==NULL)
    return;
  HDC DC=GetDC(0);
  if(!GetDIBits(DC,hbm,0,h,pSrc,&g_bmi32,DIB_RGB_COLORS))
  {
    ReleaseDC(0,DC);
    free(pSrc);
    return;
  }
  COLORREF* pDst=(COLORREF*)calloc(w*h,4);
  if (pDst!=NULL)
  {
    for (int y=0;y<h;y++)
      for (int x=0;x<w;x++)
        for (int cx=max(0,1-x);cx<min(3,w-x);cx++)
          for (int cy=max(0,1-y);cy<min(3,h-y);cy++)
            pDst[x+y*w]+=(pSrc[(x+cx-1)+(y+cy-1)*w]>>g_m8rx[cx][cy])& g_msk[cx][cy];
    SetDIBits(DC,hbm,0,w,pDst,&g_bmi32,DIB_RGB_COLORS);
    free(pDst);
  }
  ReleaseDC(0,DC);
  free(pSrc);
}

class CBlurredScreen
{
public:
  CBlurredScreen()
  {
    m_hWnd=0;
    m_dx=0;
    m_dy=0;
    m_bm=0;
  }
  ~CBlurredScreen()
  {
    Done();
  }
  void Init()
  {
    m_dx=GetSystemMetrics(SM_CXVIRTUALSCREEN);
    m_dy=GetSystemMetrics(SM_CYVIRTUALSCREEN);
    HDC dc=GetDC(0);
    HDC MemDC=CreateCompatibleDC(dc);
    m_bm=CreateCompatibleBitmap(dc,m_dx,m_dy);
    (HBITMAP)SelectObject(MemDC,m_bm);
    BitBlt(MemDC,0,0,m_dx,m_dy,dc,0,0,SRCCOPY);
    DeleteDC(MemDC);
    Blur(m_bm,m_dx,m_dy);
    ReleaseDC(0,dc);
  }
  void Done()
  {
    if(m_hWnd)
      DestroyWindow(m_hWnd);
    m_hWnd=0;
    if (m_bm)
      DeleteObject(m_bm);
    m_bm=0;
    UnregisterClass(_T("ScreenWndClass"),GetModuleHandle(0));
  }
  void Show()
  {
    WNDCLASS wc={0};
    wc.lpfnWndProc=CBlurredScreen::WindowProc;
    wc.lpszClassName=_T("ScreenWndClass");
    wc.hInstance=GetModuleHandle(0);
    RegisterClass(&wc);
    m_hWnd=CreateWindowEx(WS_EX_TOOLWINDOW,wc.lpszClassName,_T("ScreenWnd"),
      WS_VISIBLE|WS_POPUP,0,0,m_dx,m_dy,0,0,wc.hInstance,0);
    SetWindowLong(m_hWnd,GWL_USERDATA,(LONG)this);
    InvalidateRect(m_hWnd,0,1);
    UpdateWindow(m_hWnd);
    MsgLoop();
  }
  void MsgLoop()
  {
    MSG msg;
    int count=0;
    while (PeekMessage(&msg,0,0,0,PM_REMOVE) && (count++<100))
    {
      TranslateMessage(&msg);
      DispatchMessage(&msg);
    }
  }
  HWND hWnd() { return m_hWnd;  };
private:
  static LRESULT CALLBACK WindowProc(HWND hWnd,UINT msg,WPARAM wParam,LPARAM lParam)
  {
    CBlurredScreen* sw=(CBlurredScreen*)GetWindowLong(hWnd,GWL_USERDATA);
    if (sw)
      return ((CBlurredScreen*)GetWindowLong(hWnd,GWL_USERDATA))->WindowProc(msg,wParam,lParam);
    return DefWindowProc(hWnd,msg,wParam,lParam);
  }
  LRESULT CALLBACK WindowProc(UINT msg,WPARAM wParam,LPARAM lParam)
  {
    switch (msg)
    {
    case WM_PAINT:
      {
        PAINTSTRUCT ps;
        HDC hdc= BeginPaint(m_hWnd, &ps);
        HDC MemDC=CreateCompatibleDC(hdc);
        SelectObject(MemDC,m_bm);
        BitBlt(hdc,0,0,m_dx,m_dy,MemDC,0,0,SRCCOPY);
        DeleteDC(MemDC);
        EndPaint(m_hWnd, &ps);
        return 0;
      }
    case WM_SETCURSOR:
      SetCursor(LoadCursor(0,IDC_WAIT));
      return TRUE;
    }
    return DefWindowProc(m_hWnd,msg,wParam,lParam);
  }
  HWND m_hWnd;
  int m_dx;
  int m_dy;
  HBITMAP m_bm;
};
