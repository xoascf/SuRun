To be tested:
---------------------
* When finally uninstalling SuRun, ask to make "SuRunners" to Administrators
* Option that new SuRunners cannot modify SuRun settings

tested:
---------------------
* Setup Dialog for UseIShExHook, UseIATHook, NoAutoAdminToSuRunner, NoAutoSuRunner
* "Run as Admin" for Right click on Control Panel
* When User clicks "Cancel" don't tell that Process creation failed!
* if IShellExecHook and IATHook are used together, don't check or ask twice!
* Option that SuRun does not ask to make Users to SuRunners

ToDo:
---------------------
* On Login after Logout Explorer sometimes crashes with IATHook enabled
* Show Tray Tooltip after elevated AutoRunning a process

To be done in future:
---------------------
* Installation Container
* Make "SuRun"-Shell entries in Registry as Install-Option
* make context menu entries dynamically with ShellExt 
  (E.g.: msi with popup-menu)

Deferred Whishlist:
---------------------
* use MD5-Hash for "Always Yes" programs: 
    High Impact on Performance
* Console SuRun support: 
    Very difficult! Pipes need to be redirected.
* Connect Network drives for admin process: 
    High Impact on Performance and Resources NetUseEnum/NetUseAdd
* Intercept "rundll32.exe newdev.dll,": 
    needs CredUI hack for Windows XP/2k3; ok with 2k and Vista
==============================================================================
SuRun...  Super User Run
                                                      by Kay Bruns (c) 2007,08
==============================================================================

------------------------------------------------------------------------------
SuRun?
------------------------------------------------------------------------------

SuRun eases working with Windows 2000 or Windows XP with limited user rights.

The idea is simple and was taken from SuDown (http://SuDown.sourceforge.net).
The user usually works with the pc as standard user. 
If a program needs administrative rights, the user starts "SuRun <app>". 
SuRun then asks the user in a secure desktop if <app> should really be 
run with administrative rights. If the user acknowledges, SuRun will start 
<app> AS THE CURRENT USER but WITH ADMINISTRATIVE RIGHTS.
SuRun uses the trick from SuDown: 
 * Put the user in the local Administrators user group
 * Start <app>
 * Remove the user from the local Administrators user group

SuRun also installs a hook that appends "Run as admin..." and "Restart as 
admin..." to the system menu of every application that does not run as 
administrator. That makes it possible to accomplish tasks that you otherwise 
could not, e.g. setting the Windows clock by double clicking it in the task 
bar notification area would normally display a "Access denied" Message and 
exit. With SuRun you are able to click "Restart as admin..." and to set the 
clock.

SuRun integrates with the windows shell and adds "Start as admin..." to the 
Shell context menu of bat, cmd, cpl, exe, lnk and msi files.

------------------------------------------------------------------------------
Why not use the built in "Run As..." Windows command?
------------------------------------------------------------------------------

*Windows loads the registry and environment for the user that you run as.
 If a software is about to be installed, the installation program will see
 the admins HKEY_CURENT_USER and may create registry entries there.
 Also the software sees "C:\Documents and Settings\Administrator" as the users
 profile path.

 SuRun uses the current user account, so all registry entries and file system 
 paths are the same as the user would expect.

*Windows asks for the user name and password directly on the users desktop
 Any spy (or even the friendly Autohotkey) could get an administrator password.

------------------------------------------------------------------------------
Why not use SuDown?
------------------------------------------------------------------------------

*SuDown can very easily be used to spy your account password.
 SuDowns password dialog runs in the users desktop and the password can be 
 caught by any application that uses Windows hooks, even by autohotkey.
*SuDown puts every SuDoer, after he logged on, into the Administrators group.
 Spying the password and using it in a call to CreateProcessWithLogonW
 would make the spy running as administrator.
*SuDown starts any process as administrator without asking for permission for 
 a couple of minutes after the user entered the correct password.
*SuDown does not work in a plain Windows 2000 because the windows function 
 "LogOnuser" in Windows 2000 requires a privilege that only system processes 
 have.

------------------------------------------------------------------------------
Why use SuRun?
------------------------------------------------------------------------------

*SuRun uses a secure desktop for sensitive user interaction:
 SuRun uses a service to create a secure desktop in the window station of the 
 users logon session. On that desktop it will ask the user for permission or 
 the password. The desktop is not accessible by user applications. Keyboard 
 and mouse hooks will also not work on that desktop.
*SuRun does not leave the user in the administrators group.
 After creating the administrative process, SuRun removes the user from the 
 administrators group immediately. So spying even out the password would not 
 increase the chance that the system could be infected by malware.

------------------------------------------------------------------------------
How to build the sources?
------------------------------------------------------------------------------

To compile SuRun you probably need Visual C++ 6.0 and Microsoft's Platform SDK.

* To build the 32Bit version of SuRun you can use the last official Platform 
  SDK for VC6, version 02/2003.
  Use SuRun.dsw to build "Win32 Unicode Release". 
  SuRun.exe and SuRunExt.dll will be compiled to the directory ReleaseU.

* Compiling the 64 Bit version is a bit more tricky.
  In Win64, Windows has two subsystems in parallel, Win64 and Win32. To get the 
  System Menu hook for 32Bit and 64Bit Applications, you must install one Hook 
  for each subsystem. So SuRun64 consists of four files. "SuRun.exe", the Win64
  executable; "SuRunExt.dll" for the Win64 Hooks; "SuRun32.bin", the 32Bit
  executable and "SuRunExt32.dll" for the 32Bit system menu hook.
  -First you need to install Microsoft's Platform SDK 04/2005 ("Windows Server 
   2003 SP1")
  -Then "Open Build Environment Window"->"Windows XP 64-bit Build Environment"
   ->"Set Windows XP x64 Build Environment (Retail)"
  -In the command prompt type "MSDEV.EXE /useenv"
  I use the following batch file for that:
    --------------------------------------------------------------------------
    set VC6Dir=E:\VStudio
    Set MSSDK=E:\MSTOOLS
    call %VC6Dir%\VC98\Bin\VCVARS32.BAT
    call %MSSDK%\SetEnv.Cmd /X64
    start %VC6Dir%\Common\MSDev98\Bin\MSDEV.EXE /useenv
    --------------------------------------------------------------------------
  In MSDEV with the AMD64 build environment compile the "Win32 x64 Unicode 
  Release" to get SuRun.exe and SuRunExt.dll.
  Then start MSDEV just as usual with the 32Bit build environment and make 
  "Win32 SuRun32 Unicode Release" to get SuRun32.bin and SuRunExt32.dll.

------------------------------------------------------------------------------
Changes:
------------------------------------------------------------------------------
SuRun 1.0.2.105 - 2008-02-15: (Internal Beta)
----------------------------
*FIX: The IAT-Hook could cause circular calls that lead to Stack overflow

SuRun 1.0.2.104 - 2008-02-15: (Internal Beta)
----------------------------
* FIX: Vista does not set a Threads Desktop until it creates a Window.
  This caused a Deadlock because the SuRun client did show a Message Box on 
  the secure Desktop that it does not have access to.
* ShellExecuteHook was replaced by Import Address Table (IAT) Hooking
  WARNING: This is pretty experimental:
  SuRunExt.dll get loaded into all Processes that have a Window or are linked 
  to user32.dll. SuRun intercepts all calls to LoadLobrary, CreateProcess 
  and GetProcAddress. This ables SuRun to run predefined apps with elevated 
  rights and to check for manifests/setup programs more efficiently than with 
  a IShellExecute hook.
* FIX: SuRun could be hooked by IAT-Hookers. CreateProcessWithLogonW could 
  be intercepted by an IAT-Hooker and the Credentials could be used to run an 
  administrative process. Now a clean SuRun is started by the Service with 
  "AppInit_Dlls" disabled to do a clean CreateProcessWithLogonW.
* ShellExtension will be installed/removed with Service Start/Stop

SuRun 1.0.2.103 - 2008-01-21: (Internal Beta)
----------------------------
* ShellExecute Hook and Shell Context menu are now disabled for non "SuRunners"
* The Acronis TrueImage (SwitchDesktop) fix was disabled in SuRun 1.0.2.102

SuRun 1.0.2.102 - 2008-01-20: (Internal Beta)
----------------------------
* ShellExecute Hook and Shell Context menu are now disabled for Administrators
* SuRun now runs in Windows Vista :)) with UAC disabled
* SuRun now Enables/Disables IShellExecHook in Windows Vista
* "SuRun *.reg" now starts "%Windir%\Regedit.exe *.reg" as Admin
* Added "Start as Admin" for *.reg files

SuRun 1.0.2.101 - 2008-01-07: (Internal Beta)
----------------------------
* Fixed "AutoRun" ShellExecuteHook. In an AutoRun.inf in K:\ win an [AutoRun] 
  entry of 'open=setup.exe /autorun' caused the wrong command line 
  'SuRun.exe "setup.exe /autorun" /K:\'
* The english String for <IDS_DELUSER> was missing.

SuRun 1.0.2.100 - 2008-01-07: (Internal Beta)
----------------------------
* Fixed "SuRun %SystemRoot%\System32\control.exe" and
  "SuRun %SystemRoot%\System32\ncpa.cpl"
* Added ShellExecuteHook support for verbs "AutoRun" and "cplopen".
  So SuRun can now automatically start "*.cpl" files and AutoRun.INF entries 
  on removable media with elevated rights
* Choosing "Don't ask this question again for this program" and pressing 
  cancel causes SuRun to auto-cancel all future requests to run this program
  with elevated rights.

SuRun 1.0.2.99 - 2008-01-06: (Internal Beta)
---------------------------
* Removed parsing for Vista Manifests with <*requestedExecutionLevel 
   level="highestAvailable">.

SuRun 1.0.2.98 - 2008-01-05: (Internal Beta)
---------------------------
* SuRun is now hidden from the frequently used program list of the Start menu
* SuRuns file name pattern matching for files with SPACEs did not work.

SuRun 1.0.2.97 - 2008-01-04: (Internal Beta)
---------------------------
* fixed command line processing for "SuRun *.msi"
* changed "'cmd <folder>' as administrator" and "'Explorer <folder>' as 
  administrator" to "'SuRun cmd' here" and "'SuRun Explorer' here"
* Administrators will not see any of SuRuns System menu or shell menu entries
* Added parsing for Vista Manifests and Executable file name pattern matching.
  -All files with extension msi and msc and all files with extension exe, cmd, 
   lnk, com, pif, bat and a file name that contains install, setup or update 
   are suspected that they must be run with elevated rights.
  -All files with a Vista RT_MANIFEST resource containing <*trustInfo>->
   <*security>-><*requestedPrivileges>-><*requestedExecutionLevel 
   level="requireAdministrator|highestAvailable"> are suspected that they must 
   be run with elevated rights.

SuRun 1.0.2.96 - 2007-12-23: (Internal Beta)
---------------------------
* Setup User Interface improvements
* Speedups for Domain computers
* Simplification in the group membership check for SuRunners
* The "Is Client an Admin?" check is now done with the user token of the client 
  process and not with the group membership of the client user name
***Hopefully all speedups and simplifications did not cause security wholes***

SuRun 1.0.2.95 - 2007-12-09: (Internal Beta)
---------------------------
* Acronis TrueImage (SwitchDesktop) caused the users files list control not to 
  be drawn.

SuRun 1.0.2.94 - 2007-12-09: (Internal Beta)
---------------------------
* Context menu for Folders in Explorer (cmd/Explorer <here> as admin)
* When clicking the "Add..." user program button, *.lnk files are resolved to 
  their targets
* File Open/Save Dialogs now show all extensions in SuRun Setup.


SuRun 1.0.2.93 - 2007-12-07: (Internal Beta)
---------------------------
* New Commands. If the User right-clicks on a folder background, two new Items,
  "'cmd <folder>' as administrator" and "'Explorer <folder>' as administrator"
  are shown.
* New command line Option: /QUIET
* New: SuRun runs in a domain. It enumerates domain accounts for administrative 
  authorization and uses the local group "SuRunners" for local authorization.
* SuRun waits for max 3 minutes after the Windows start for the Service.
* SuRun tries to locate the Application to be started. So "surun cmd" will
  make ask SuRun whether "C:\Windows\System32\cmd.exe" is allowed to run.
* Users can make Windows Explorer run specific Applications always with 
  elevated rights. (No "SuRun" command required.)
* SuRun can be restricted on a per User basis:
  - Users can be denied to use "SuRun setup".
  - Users can be restricted to specific applications that are allowed to run 
    with elevated rights
  This enables to use SuRun in Parent/Children scenarios or in Companies where 
  real Administrators want to work with lowered rights.
* SuRuns Shell integration can be customized.

SuRun 1.0.2.9 - 2007-11-17:
---------------------------
* SuRun now set's an ExitCode
* FIX: In Windows XP a domain name can have more than DNLEN(=15) characters.
    This caused GetProcessUsername() to fail and NetLocalGroupAddMembers() 
    to return "1: Invalid Function".
* Fixed a Bug in the LogonDialog that could cause an exception.

SuRun 1.0.2.8 - 2007-10-11:
---------------------------
* Added code to avoid Deadlock with AntiVir's RootKit detector "avipbb.sys" 
  that breaks OpenProcess()
* Added code to recover SuRuns Desktop when user processes call SwitchDesktop()
  "shedhlp.exe", part of Acronis True Image Home 11 calls SwitchDesktop() 
  periodically and so switches from SuRuns Desktop back to the users Desktop.

SuRun 1.0.2.7 - 2007-09-21:
---------------------------
* Fixed a Bug in the Sysmenuhook that caused "start as administrator" to
  fire multiple times.

SuRun 1.0.2.6 - 2007-09-20:
---------------------------
* SuRun - x64 Version added, the version number is the same because SuRun 
  has no new functions or bugfixes

SuRun 1.0.2.6 - 2007-09-14:
---------------------------
* With the Option "Store &Passwords (protected, encrypted)" disabled SuRun 
  did not start any Process...Thanks to A.H.Klein for reporting.

SuRun 1.0.2.5 - 2007-09-05:
---------------------------
* Empty user passwords did not work in an out of the box Windows. Users 
  were forced to use the policy editor to set "Accounts: Limit local 
  account use of blank passwords to console logon only" to "Disabled".
  Now SuRun temporarily sets this policy automatically to "Disabled" and 
  after starting the administrative process SuRun restores the policy.

SuRun 1.0.2.4 - 2007-08-31:
---------------------------
* SuRun has been translated to polish by sarmat, Thanks! :-)
* Microsoft Installer Patch Files (*.msp) can be started with elevated rights

SuRun 1.0.2.3 - 2007-08-18:
---------------------------
* SuRun now works with users that have an empty password

SuRun 1.0.2.2 - 2007-07-30:
---------------------------
* Added SuRun Version display to setup dialog caption

SuRun 1.0.2.1 - 2007-07-24:
---------------------------
* The way that SuRun checks a users group membership was changed
* "surun ncpa.cpl" did not work
* SuRun now reports detailed, why a user could not be added or removed to/from 
  a user group
* SuRun now assures that a "SuRunner" is NOT member of "Administrators"
* SuRun now checks that a user is member of "Administrators" or "SuRunners" 
  before launching setup
* SuRun now starts/resumes the "Secondary Logon" service automatically
* SuRun now complains if the windows shell is running as Administrator

SuRun 1.0.2.0 - 2007-05-29:
---------------------------
* SuRun Setup now contains new options:
   -Allow 'SuRunners' to set (and show) the system time
   -Allow 'SuRunners' to change 'Power Options' and select power schemes
   -Show Windows update notifications to all users
   -No auto-restart for scheduled Automatic Windows Update installations
   -Set 'Administrators' instead of 'Object creator' as default owner for 
    ojects created by administrators
  The last option is pretty important!

SuRun 1.0.1.2 - 2007-05-16:
---------------------------
* Sven (http://speedproject.de) found a bug in the context menu extension for 
  the Desktop. The Entries for the sub menu "new" were not displayed when 
  SuRun was active.
* All calls GetWindowsDirectory were replaced with GetSystemWindowsDirectory 
  to make SuRun work with Windows 2003 Terminal Server Edition
* Control Panel and Control Panel Applets were not shown in Win2k, Win2k3.
  SuRun now sets the DWORD value "SeparateProcess" in the registry path
  "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" to 1 to
  let Explorer start a separate Process for the control panel. The main control 
  panel is now started with Explorer using the "Workspace\Control Panel" GUIDs.
  Control Panel Applets are now started with RunDLL32 instead of control.exe.

SuRun 1.0.1.1 - 2007-05-13:
---------------------------
* Sven (http://speedproject.de) fixed some typos and beautified the logon 
  dialogs, Thanks!

SuRun 1.0.1.0 - 2007-05-11:
---------------------------
* Added Whitelist for programs that are always run without asking
* When finally uninstalling SuRun the registry is cleaned
* Logon dialogs are resized only if the command line is too long
* Dialogs have a 40s Timeout to automatic "cancel"
* SuRun retries to open the service pipe for 3 minutes. This is useful, when a 
  user starts multiple apps in short intervals. (e.g. from the StartUp menu)

SuRun 1.0.0.1 - 2007-05-09:
---------------------------
* Fixed possible CreateRemoteThread() attack. Access for current user to 
  processes started by SuRun is now denied.

SuRun 1.0.0.0 - 2007-05-08:
---------------------------
* first public release

==============================================================================
                                 by Kay Bruns (c) 2007,08, http://kay-bruns.de
==============================================================================
