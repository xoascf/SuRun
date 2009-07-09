@echo off
set VC6Dir=E:\VStudio
Set MSSDK=E:\MSTOOLS

SETLOCAL
call %VC6Dir%\VC98\Bin\VCVARS32.BAT
call %MSSDK%\SetEnv.Cmd /X64 /RETAIL
echo building SuRunX64
%VC6Dir%\Common\MSDev98\Bin\MSDEV.EXE /useenv SuRun.dsw /MAKE "SuRun - Win32 x64 Unicode Release" /REBUILD /OUT %TMP%\SuRun64.log
ENDLOCAL
type %TMP%\SuRun64.log
del %TMP%\SuRun64.log 1>NUL 2>NUL

SETLOCAL
call %VC6Dir%\VC98\Bin\VCVARS32.BAT
call %MSSDK%\SetEnv.Cmd /2000 /RETAIL
echo building SuRun32
%VC6Dir%\Common\MSDev98\Bin\MSDEV.EXE /useenv SuRun.dsw /MAKE "SuRun - Win32 Unicode Release" "SuRun - Win32 SuRun32 Unicode Release" "InstallSuRun - Win32 Release" /REBUILD /OUT %TMP%\SuRun32.log
ENDLOCAL
type %TMP%\SuRun32.log
del %TMP%\SuRun32.log 1>NUL 2>NUL
pause