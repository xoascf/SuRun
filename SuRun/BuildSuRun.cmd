@echo off
if NOT "%MSDevDir%"=="" goto VC6compile
if NOT "%VS80COMNTOOLS%"=="" goto VC8compile
if NOT "%VS90COMNTOOLS%"=="" goto VC9compile
if NOT "%VS100COMNTOOLS%"=="" goto VC10compile

rem compile using VC6
:VC6compile
if "%MSSDK%"=="" SET MSSDK=E:\MSTOOLS
SET VC6Dir=%MSDevDir%\..\..
if "%VC6Dir%"=="\..\.." SET VC6Dir=E:\VStudio

SETLOCAL
call %VC6Dir%\VC98\Bin\VCVARS32.BAT
call %MSSDK%\SetEnv.Cmd /X64 /RETAIL
echo building SuRunX64
%VC6Dir%\Common\MSDev98\Bin\MSDEV.EXE /useenv SuRun.dsw /MAKE "SuRun - Win32 x64 Unicode Release" /REBUILD /OUT %TMP%\SuRun64.log
ENDLOCAL
type %TMP%\SuRun64.log
del %TMP%\SuRun64.log 1>NUL 2>NUL

SETLOCAL
set MSVCDir=%VC6Dir%\VC98
set DevEnvDir=%VC6Dir%\Common\IDE
call %VC6Dir%\VC98\Bin\VCVARS32.BAT
call %MSSDK%\SetEnv.Cmd /2000 /RETAIL
set MSVCVer=6.0
echo building SuRun32
%VC6Dir%\Common\MSDev98\Bin\MSDEV.EXE /useenv SuRun.dsw /MAKE "SuRun - Win32 Unicode Release" "SuRun - Win32 SuRun32 Unicode Release" "InstallSuRun - Win32 Release" /REBUILD /OUT %TMP%\SuRun32.log
ENDLOCAL
type %TMP%\SuRun32.log
del %TMP%\SuRun32.log 1>NUL 2>NUL
goto Done

rem compile using VC8 (2005), VC9 (2008) or VC10 (2010)
:VC8compile
:VC9compile
:VC10compile
SETLOCAL
if NOT "%VS100COMNTOOLS%"=="" call "%VS100COMNTOOLS%vsvars32.bat"
if NOT "%VS90COMNTOOLS%"=="" call "%VS90COMNTOOLS%vsvars32.bat"
if NOT "%VS80COMNTOOLS%"=="" call "%VS80COMNTOOLS%vsvars32.bat"
msbuild SuRun.sln /t:Rebuild /p:Configuration="x64 Unicode Release" /p:Platform=x64
msbuild SuRun.sln /t:Rebuild /p:Configuration="SuRun32 Unicode Release" /p:Platform=Win32
msbuild SuRun.sln /t:Rebuild /p:Configuration="Unicode Release" /p:Platform=Win32
ENDLOCAL

:Done
pause
