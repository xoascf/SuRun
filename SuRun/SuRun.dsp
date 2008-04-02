# Microsoft Developer Studio Project File - Name="SuRun" - Package Owner=<4>
# Microsoft Developer Studio Generated Build File, Format Version 6.00
# ** DO NOT EDIT **

# TARGTYPE "Win32 (x86) Application" 0x0101

CFG=SuRun - Win32 Unicode Release
!MESSAGE This is not a valid makefile. To build this project using NMAKE,
!MESSAGE use the Export Makefile command and run
!MESSAGE 
!MESSAGE NMAKE /f "SuRun.mak".
!MESSAGE 
!MESSAGE You can specify a configuration when running NMAKE
!MESSAGE by defining the macro CFG on the command line. For example:
!MESSAGE 
!MESSAGE NMAKE /f "SuRun.mak" CFG="SuRun - Win32 Unicode Release"
!MESSAGE 
!MESSAGE Possible choices for configuration are:
!MESSAGE 
!MESSAGE "SuRun - Win32 Unicode Debug" (based on "Win32 (x86) Application")
!MESSAGE "SuRun - Win32 Unicode Release" (based on "Win32 (x86) Application")
!MESSAGE "SuRun - Win32 x64 Unicode Release" (based on "Win32 (x86) Application")
!MESSAGE "SuRun - Win32 SuRun32 Unicode Release" (based on "Win32 (x86) Application")
!MESSAGE 

# Begin Project
# PROP AllowPerConfigDependencies 0
# PROP Scc_ProjName ""$/SuRun", TSQCAAAA"
# PROP Scc_LocalPath "."
CPP=cl.exe
MTL=midl.exe
RSC=rc.exe

!IF  "$(CFG)" == "SuRun - Win32 Unicode Debug"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 1
# PROP BASE Output_Dir "DebugU"
# PROP BASE Intermediate_Dir "DebugU"
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 1
# PROP Output_Dir "DebugU"
# PROP Intermediate_Dir "DebugU"
# PROP Ignore_Export_Lib 0
# PROP Target_Dir ""
# ADD BASE CPP /nologo /W3 /Gm /GX /ZI /Od /D "WIN32" /D "_DEBUG" /D "_WINDOWS" /D "_UNICODE" /D "UNICODE" /YX /FD /GZ /c
# ADD CPP /nologo /MT /W3 /Gm /GX /ZI /Od /D "WIN32" /D "_DEBUG" /D "_WINDOWS" /D "_UNICODE" /D "UNICODE" /YX /FD /GZ /c
# ADD BASE MTL /nologo /D "_DEBUG" /mktyplib203 /win32
# ADD MTL /nologo /D "_DEBUG" /mktyplib203 /win32
# ADD BASE RSC /l 0x407 /d "_DEBUG"
# ADD RSC /l 0x407 /d "_DEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LINK32=link.exe
# ADD BASE LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib /nologo /subsystem:windows /debug /machine:I386 /pdbtype:sept
# ADD LINK32 gdi32.lib user32.lib advapi32.lib kernel32.lib shell32.lib /nologo /subsystem:windows /debug /machine:I386 /pdbtype:sept
# SUBTRACT LINK32 /pdb:none
# Begin Special Build Tool
OutDir=.\DebugU
SOURCE="$(InputPath)"
PreLink_Desc=Check
PreLink_Cmds=if exist $(OutDir)\SuRun.exe del /f $(OutDir)\SuRun.exe 1>NUL 2>NUL
# End Special Build Tool

!ELSEIF  "$(CFG)" == "SuRun - Win32 Unicode Release"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 0
# PROP BASE Output_Dir "ReleaseU"
# PROP BASE Intermediate_Dir "ReleaseU"
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 0
# PROP Output_Dir "ReleaseU"
# PROP Intermediate_Dir "ReleaseU"
# PROP Ignore_Export_Lib 0
# PROP Target_Dir ""
# ADD BASE CPP /nologo /W3 /GX /O2 /D "WIN32" /D "NDEBUG" /D "_WINDOWS" /D "_UNICODE" /D "UNICODE" /YX /FD /c
# ADD CPP /nologo /MT /W3 /GX /O2 /D "WIN32" /D "NDEBUG" /D "_WINDOWS" /D "_UNICODE" /D "UNICODE" /YX /FD /c
# SUBTRACT CPP /Fr
# ADD BASE MTL /nologo /D "NDEBUG" /mktyplib203 /win32
# ADD MTL /nologo /D "NDEBUG" /mktyplib203 /win32
# ADD BASE RSC /l 0x407 /d "NDEBUG"
# ADD RSC /l 0x407 /d "NDEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LINK32=link.exe
# ADD BASE LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib /nologo /subsystem:windows /machine:I386 /IGNORE:4089
# ADD LINK32 gdi32.lib user32.lib advapi32.lib kernel32.lib shell32.lib /nologo /subsystem:windows /machine:I386 /IGNORE:4089
# SUBTRACT LINK32 /pdb:none /map /debug /nodefaultlib
# Begin Special Build Tool
OutDir=.\ReleaseU
SOURCE="$(InputPath)"
PreLink_Cmds=if exist $(OutDir)\SuRun.exe del /f $(OutDir)\SuRun.exe 1>NUL 2>NUL	if exist $(OutDir)\SuRun.exe $(OutDir)\SuRun.exe /DeleteService 1>NUL 2>NUL
# End Special Build Tool

!ELSEIF  "$(CFG)" == "SuRun - Win32 x64 Unicode Release"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 0
# PROP BASE Output_Dir "SuRun___Win32_x64_Unicode_Release"
# PROP BASE Intermediate_Dir "SuRun___Win32_x64_Unicode_Release"
# PROP BASE Ignore_Export_Lib 0
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 0
# PROP Output_Dir "ReleaseUx64"
# PROP Intermediate_Dir "ReleaseUx64"
# PROP Ignore_Export_Lib 0
# PROP Target_Dir ""
# ADD BASE CPP /nologo /W3 /GX /O2 /D "WIN32" /D "NDEBUG" /D "_WINDOWS" /D "_UNICODE" /D "UNICODE" /YX /FD /c
# ADD CPP /nologo /MT /W3 /O2 /D "WIN32" /D "NDEBUG" /D "_WINDOWS" /D "_UNICODE" /D "UNICODE" /FD /EHsc /Wp64 /c
# ADD BASE MTL /nologo /D "NDEBUG" /mktyplib203 /win32
# ADD MTL /nologo /D "NDEBUG" /mktyplib203 /win32
# ADD BASE RSC /l 0x407 /d "NDEBUG"
# ADD RSC /l 0x407 /d "NDEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LINK32=link.exe
# ADD BASE LINK32 gdi32.lib user32.lib advapi32.lib kernel32.lib shell32.lib /nologo /subsystem:windows /machine:I386 /IGNORE:4089
# SUBTRACT BASE LINK32 /pdb:none /nodefaultlib
# ADD LINK32 gdi32.lib user32.lib advapi32.lib kernel32.lib shell32.lib bufferoverflowu.lib /nologo /subsystem:windows /machine:IX86 /IGNORE:4089 /machine:AMD64
# SUBTRACT LINK32 /pdb:none
# Begin Special Build Tool
OutDir=.\ReleaseUx64
SOURCE="$(InputPath)"
PreLink_Cmds=if exist $(OutDir)\SuRun.exe del /f $(OutDir)\SuRun.exe 1>NUL 2>NUL	if exist $(OutDir)\SuRun.exe $(OutDir)\SuRun.exe /DeleteService 1>NUL 2>NUL
# End Special Build Tool

!ELSEIF  "$(CFG)" == "SuRun - Win32 SuRun32 Unicode Release"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 0
# PROP BASE Output_Dir "SuRun___Win32_SuRun32_Unicode_Release"
# PROP BASE Intermediate_Dir "SuRun___Win32_SuRun32_Unicode_Release"
# PROP BASE Ignore_Export_Lib 0
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 0
# PROP Output_Dir "ReleaseUsr32"
# PROP Intermediate_Dir "ReleaseUsr32"
# PROP Ignore_Export_Lib 0
# PROP Target_Dir ""
# ADD BASE CPP /nologo /W3 /GX /O2 /D "WIN32" /D "NDEBUG" /D "_WINDOWS" /D "_UNICODE" /D "UNICODE" /YX /FD /c
# ADD CPP /nologo /MT /W3 /GX /O2 /D "WIN32" /D "NDEBUG" /D "_WINDOWS" /D "_UNICODE" /D "UNICODE" /D "_SR32" /YX /FD /c
# ADD BASE MTL /nologo /D "NDEBUG" /mktyplib203 /win32
# ADD MTL /nologo /D "NDEBUG" /mktyplib203 /win32
# ADD BASE RSC /l 0x407 /d "NDEBUG"
# ADD RSC /l 0x407 /fo"ReleaseUsr32/SuRun32.res" /d "NDEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo /o"ReleaseUsr32/SuRun32.bsc"
LINK32=link.exe
# ADD BASE LINK32 gdi32.lib user32.lib advapi32.lib kernel32.lib shell32.lib /nologo /subsystem:windows /machine:I386 /IGNORE:4089
# SUBTRACT BASE LINK32 /pdb:none /nodefaultlib
# ADD LINK32 gdi32.lib user32.lib advapi32.lib kernel32.lib shell32.lib /nologo /subsystem:windows /machine:I386 /out:"ReleaseUx64/SuRun32.bin" /IGNORE:4089
# SUBTRACT LINK32 /pdb:none /nodefaultlib

!ENDIF 

# Begin Target

# Name "SuRun - Win32 Unicode Debug"
# Name "SuRun - Win32 Unicode Release"
# Name "SuRun - Win32 x64 Unicode Release"
# Name "SuRun - Win32 SuRun32 Unicode Release"
# Begin Group "Source Files"

# PROP Default_Filter "cpp;c;cxx;rc;def;r;odl;idl;hpj;bat"
# Begin Source File

SOURCE=.\blowfish.cpp
# End Source File
# Begin Source File

SOURCE=.\DBGTrace.cpp
# End Source File
# Begin Source File

SOURCE=.\Helpers.cpp
# End Source File
# Begin Source File

SOURCE=.\IsAdmin.cpp
# End Source File
# Begin Source File

SOURCE=.\LogonDlg.cpp
# End Source File
# Begin Source File

SOURCE=.\lsa_laar.cpp
# End Source File
# Begin Source File

SOURCE=.\main.cpp
# End Source File
# Begin Source File

SOURCE=.\ReqAdmin.cpp
# End Source File
# Begin Source File

SOURCE=.\Service.cpp
# End Source File
# Begin Source File

SOURCE=.\Setup.cpp
# End Source File
# Begin Source File

SOURCE=.\sspi_auth.cpp
# End Source File
# Begin Source File

SOURCE=.\SuRun.rc
# End Source File
# Begin Source File

SOURCE=.\TrayMsgWnd.cpp
# End Source File
# Begin Source File

SOURCE=.\TrayShowAdmin.cpp
# End Source File
# Begin Source File

SOURCE=.\UserGroups.cpp
# End Source File
# Begin Source File

SOURCE=.\WinStaDesk.cpp
# End Source File
# End Group
# Begin Group "Header Files"

# PROP Default_Filter "h;hpp;hxx;hm;inl"
# Begin Source File

SOURCE=.\BLOWFISH.h
# End Source File
# Begin Source File

SOURCE=.\CmdLine.h
# End Source File
# Begin Source File

SOURCE=.\DBGTrace.H
# End Source File
# Begin Source File

SOURCE=.\Helpers.h
# End Source File
# Begin Source File

SOURCE=.\IsAdmin.h
# End Source File
# Begin Source File

SOURCE=.\LogonDlg.h
# End Source File
# Begin Source File

SOURCE=.\lsa_laar.h
# End Source File
# Begin Source File

SOURCE=.\pugxml.h
# End Source File
# Begin Source File

SOURCE=.\ReqAdmin.h
# End Source File
# Begin Source File

SOURCE=.\resource.h
# End Source File
# Begin Source File

SOURCE=.\ResStr.h
# End Source File
# Begin Source File

SOURCE=.\ScreenSnap.h
# End Source File
# Begin Source File

SOURCE=.\Service.h
# End Source File
# Begin Source File

SOURCE=.\Setup.h
# End Source File
# Begin Source File

SOURCE=.\sspi_auth.h
# End Source File
# Begin Source File

SOURCE=.\TrayMsgWnd.h
# End Source File
# Begin Source File

SOURCE=.\TrayShowAdmin.h
# End Source File
# Begin Source File

SOURCE=.\UserGroups.h
# End Source File
# Begin Source File

SOURCE=.\WinStaDesk.h
# End Source File
# End Group
# Begin Group "Resource Files"

# PROP Default_Filter "ico;cur;bmp;dlg;rc2;rct;bin;rgs;gif;jpg;jpeg;jpe"
# Begin Source File

SOURCE=.\res\Admin.ico
# End Source File
# Begin Source File

SOURCE=.\res\ADMIN1.ico
# End Source File
# Begin Source File

SOURCE=.\res\app.manifest
# End Source File
# Begin Source File

SOURCE=.\res\AutoCancel.ico
# End Source File
# Begin Source File

SOURCE=.\res\ico10605.ico
# End Source File
# Begin Source File

SOURCE=.\res\ico10606.ico
# End Source File
# Begin Source File

SOURCE=.\res\ico10607.ico
# End Source File
# Begin Source File

SOURCE=.\res\NoAdmin.ico
# End Source File
# Begin Source File

SOURCE=.\res\NoQuestion.ico
# End Source File
# Begin Source File

SOURCE=.\res\NoRestrict.ico
# End Source File
# Begin Source File

SOURCE=.\res\NoWindow.ico
# End Source File
# Begin Source File

SOURCE=.\res\NoWindows.ico
# End Source File
# Begin Source File

SOURCE=.\res\Question.ico
# End Source File
# Begin Source File

SOURCE=.\res\Restrict.ico
# End Source File
# Begin Source File

SOURCE=.\res\SuRun.ico
# End Source File
# Begin Source File

SOURCE=.\res\Windows.ico
# End Source File
# End Group
# Begin Source File

SOURCE=.\ChangeLog.txt
# End Source File
# Begin Source File

SOURCE=.\gpedit.txt
# End Source File
# Begin Source File

SOURCE=.\ReadMe.txt
# End Source File
# End Target
# End Project
