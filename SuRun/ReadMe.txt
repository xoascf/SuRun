==============================================================================
SuRun...  Super User Run
                                                        by Kay Bruns (c) 2007
==============================================================================

------------------------------------------------------------------------------
SuRun?
------------------------------------------------------------------------------

SuRun eases working with Windows 2000 or Windows XP with limited user rights.

The idea is simple and was taken from SuDown (http://SuDown.sourceforge.net).
The user usually works with the pc as standard user. 
If a program needs administrative rights, the user starts "SuRun <app>". 
SuRun then asks the user in a secure desktop if <app> should really be 
run with administrative rights. If the user acknowleges, SuRun will start 
<app> AS THE CURRENT USER but WITH ADMINISTRATIVE RIGHTS.
SuRun uses the trick from SuDown: 
 * Put the user in the local Administrators user group
 * Start <app>
 * remove the user from the local Administrators user group

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
 After creating the administrative process, surun removes the user from the 
 administrators group immediately. So spying even out the password would not 
 increase the chance that the system could be infected by malware.

------------------------------------------------------------------------------
ToDo:
------------------------------------------------------------------------------
- Store User SIDs instead of Domain\UserName 
  ...SIDs are variable length structures, so SuRun stores the names instead
- Whitelist
  List of Programs that are allowed to always be SuRun without questioning

------------------------------------------------------------------------------
Changes:
------------------------------------------------------------------------------
SuRun 1.0.1.0 - 2007-05-11:
---------------------------
* Added Support for programs that are always run without asking for permission
* When finally uninstalling SuRun the registry is cleaned
* Logon dialogs are resized only if the command line is too long
* Dialogs have a 40s Timeout to "cancel" now
* SuRun retries to open the pipe for 60 seconds on failure. This is useful, 
  when a user starts multiple applications in short time. (E.G. with Windows' 
  AutoStart menu)

SuRun 1.0.0.1 - 2007-05-09:
---------------------------
* Fixed possible CreateRemoteThread() attack. Access for current user to 
  processes started by SuRun is now denied.

SuRun 1.0.0.0 - 2007-05-08:
---------------------------
* first public release

==============================================================================
                                    by Kay Bruns (c) 2007, http://kay-bruns.de
==============================================================================
