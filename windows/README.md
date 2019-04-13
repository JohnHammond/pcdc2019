Windows Toolkit
=======================

Do not forget to download and install EMET!

And check the PowerShell history file:

```
%userprofile%\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
```


User Enumeration
---------------

```
C:\> whoami

C:\> net users

C:\> net localgroup administrators

C:\> net group administrators

C:\> wmic rdtoggle list

C:\> wmic useraccount list

C:\> wmic group list

C:\> wmic netlogin get name,lastlogon,badpasswordcount

C:\> wmic netclient list brief

C:\> doskey /history > history.txt
```


Network Information
-------------

```
C:\> netstat -e

C:\> netstat -naob

C:\> netstat -nr

C:\> netstat -vb

C:\> netstat -S

C:\> route print

C:\> arp -a

C:\> ipconfig /displaydns

C:\> netsh winhttp show proxy

C:\> ipconfig /allcompartments /all

C:\> netsh wlan show interfaces

C:\> netsh wlan show all

C:\> reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Connections\WinHttpSettings"

C:\> type %SYSTEMROOT%\system32\drivers\etc\hosts

C:\> wmic nicconfig get descriptions,IPaddress,MACaddress

C:\> wmic netuse get name,username,connectiontype,localname
```


Service Information
---------

```
C:\> at

C:\> tasklist

C:\> tasklist /svc

C:\> tasklist /svc /fi "imagename eq svchost.exe"

C:\> schtasks

C:\> net start

C:\> sc query

C:\> wmic service list brief | findstr "Running"

C:\> wmic service list config

C:\> wmic process list brief

C:\> wmic process list status

C:\> wmic process list memory

C:\> wmic job list breif 

PS C:\> Get-Service | Where-Object { $_.Status -eq "running" }
```

Autorun and Autoload Information
---------

__Startup information:__

```
C:\> wmic startup list full

C:\> wmic ntdomain list brief
```

__View directory contents of startup folder:__

```
C:\> dir "%SystemDrive%\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"

C:\> dir "%SystemDrive%\Documents and Settings\All Users\Start Menu\Programs\Startup"

C:\> dir "%userprofile%\Start Menu\Programs\Startup"

C:\> dir "%ProgramFiles%\Startup"

C:\> dir "C:\Users\%username%\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup"

C:\> dir "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"

C:\> dir "%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup"

C:\> dir "%ALLUSERSPROFILE%\Microsoft\Windows\Start Menu\Programs\Startup"

C:\> dir "%ALLUSERSPROFILE%\Start Menu\Programs\Startup"

C:\> type C:\Windows\winstart.bat

C:\> type %windir%\wininit.ini

C:\> type %windir%\win.ini
```

__View autoruns, hide Microsoft files:__


Reference:  [https://technet.microsoft.com/en-us/sysinternals/bb963902.aspx](https://technet.microsoft.com/en-us/sysinternals/bb963902.aspx)

```
C:\> autorunsc -accepteula -m

C:\> type C:\Autoexec.bat
```

__Show all autorun files, export to CSV and check with VirusTotal:__

```
C:\> autorunsc.exe -accepteula -a -c -i -e -f -l -m -v
```

__`HKEY_CLASSES_ROOT`__:

```
C:\> reg query HKCR\Comfile\Shell\Open\Command

C:\> reg query HKCR\Batfile\Shell\Open\Command

C:\> reg query HKCR\htafile\Shell\Open\Command

C:\> reg query HKCR\Exefile\Shell\Open\Command

C:\> reg query HKCR\Exefiles\Shell\Open\Command

C:\> reg query HKCR\piffile\shell\Open\Command
```

__`HKEY_CURRENT_USERS`:__

```
C:\> reg query "HKCU\Control Panel\Desktop"

C:\> reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run"

C:\> reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Run"

C:\> reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce"

C:\> reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnceEx"

C:\> reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\RunServices"

C:\> reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce"

C:\> reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Windows\Run"

C:\> reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Windows\Load"

C:\> reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Windows\Scripts"

C:\> reg query "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Windows" /f run

C:\> reg query "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Windows" /f load

C:\> reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run"

C:\> reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\RecentDocs"

C:\> reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\ComDlg32\LastVisitedMRU"

C:\> reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\ComDlg32\OpenSaveMRU"

C:\> reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\ComDlg32\LastVisitedPidlMRU"

C:\> reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\ComDlg32\OpenSavePidlMRU" /s

C:\> reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\RunMRU"

C:\> reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Shell Folders"

C:\> reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\User Shell Folders"

C:\> reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Applets\RegEdit" /v LastKey

C:\> reg query "HKCU\Software\Microsoft\Internet Explorer\TypedURLs"

C:\> reg query "HKCU\Software\Policies\Microsoft\Windows\Control Panel\Desktop"
```

__`HKEY_LOCAL_MACHINE`:__

```
C:\> reg query "HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components" /s

C:\> reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\explorer\User Shell Folders"

C:\> reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\explorer\Shell Folders"

C:\> reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ShellExecuteHooks" 

C:\> reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects" /s 

C:\> reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run"

C:\> reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"

C:\> reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"

C:\> reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceEx"

C:\> reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices"

C:\> reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServicesOnce"

C:\> reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Winlogon\Userinit"

C:\> reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\shellServiceObjectDelayLoad"

C:\> reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks" /s

C:\> reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows"

C:\> reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows" /f AppInit_DLLs

C:\> reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows" /f Shell

C:\> reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows" /f Userinit

C:\> reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows\System\Scripts"

C:\> reg query "HKLM\SOFTWARE\Classes\batfile\shell\open\command"

C:\> reg query "HKLM\SOFTWARE\Classes\comfile\shell\open\command"

C:\> reg query "HKLM\SOFTWARE\Classes\exefile\shell\open\command"

C:\> reg query "HKLM\SOFTWARE\Classes\htafile\shell\open\Command"

C:\> reg query "HKLM\SOFTWARE\Classes\piffile\shell\open\command"

C:\> reg query "HKLM\SOFTWARE\Woww6432Node\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects" /s

C:\> reg query "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager"

C:\> reg query "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs"

C:\> reg query "HKLM\SYSTEM\ControlSet001\Control\Session Manager\KnownDLLs"
```

__List of all processes and then all loaded modules:__


```
PS C:\> Get-Process | Select modules|ForEach-Object{$_.modules}
```



---------

* [`Sysinternals.zip`](Sysinternals.zip)

    Added by John Hammond. `Autoruns` - Check what is set to run on startup, `Process Explorer` - Check the processes in a process tree (and SIGNATURE), `PsLoggedOn` - Check who is logged on,  `TCPView` -  Check active connections and listeners, `Strings` - Check the strings of a binary (like we do in Linux), `PsExec` - a poor man's remote control

* [`enable_powershell_transcription_logging.bat`](enable_powershell_transcription_logging.bat)

    Added by John Hammond. Batch script that turns on PowerShell transcription logging in `C:\PS_transcription\`.

* [`enable_powershell_constrained_language.ps1`](enable_powershell_constrained_language.ps1)

    Added by John Hammond. PowerShell script to set an environment variable and turn on PowerShell Constrained Language Mode. This does not to be a full script (it is only one line) but I wanted it visible so we are sure to use it! 

* [`disable_powershell_v2.ps1`](disable_powershell_v2.ps1)

    Added by John Hammond. PowerShell switch to disable PowerShell V2 (can be used to avoid ExecutionPolicy or Constrained Language Mode). This does not to be a full script (it is only one line) but I wanted it visible so we are sure to use it! 

* [`forensics.bat`](forensics.bat)

    Added by G1d30N. Batch script that runs system information enumeration and store it in `C:\Users\`.

* [`WindowsEnum.ps1`](WindowsEnum.ps1)

    Added by John Hammond. Credited repo is here: [https://github.com/absolomb/WindowsEnum](https://github.com/absolomb/WindowsEnum). Running the extended check may take a long time: `powershell -nologo -executionpolicy bypass -file WindowsEnum.ps1 extended`

* [`DeepBlue.ps1`](DeepBlue.ps1)

    Added by John Hammond. Credited repo is here: [https://github.com/sans-blue-team/DeepBlueCLI](https://github.com/sans-blue-team/DeepBlueCLI). Awesome utility for quickly scanning logs and finding trouble. Usage like: `.\DeepBlue.ps1 -log security` or `.\DeepBlue.ps1 -log system`

* [`PoSH_R2.ps1`](PoSH_R2.ps1)

    Added by John Hammond. Credited repo is here: [https://github.com/WiredPulse/PoSh-R2](https://github.com/WiredPulse/PoSh-R2).  This tool is awesome, given a list of Windows IP addresses, it will use WMI to query Autorun entries , Disk info , Environment variables , Event logs (50 lastest) , Installed Software , Logon sessions , List of drivers , List of mapped network drives , List of running processes , Logged in user , Local groups , Local user accounts , Network configuration , Network connections , Patches , Scheduled tasks with AT command , Shares , Services , System Information. For easy viewing of results, you can run `(import-csv .<some_file.csv> | out-gridview`.

* [`windows_xp_stig.bat`](windows_xp_stig.bat)

    Added by John Hammond. A force-compliance script for Windows XP Security Technical Implementation Guide. Just makes a ton of registry tweaks to harden the box.

* [`windows_7_stig.bat`](windows_7_stig.bat)

    Added by John Hammond. A force-compliance script for Windows 7 Security Technical Implementation Guide. Just makes a ton of registry tweaks to harden the box.

* [`windows_2008_stig.bat`](windows_7_stig.bat)

    Added by John Hammond. A force-compliance script for Windows Server 2008 R2 DC Security Technical Implementation Guide. Just makes a ton of registry tweaks to harden the box.

* [`WN10_Stigs.ps1`](WN10_Stigs.ps1)

    Added by John Hammond. A force-compliance script for Windows 10 Security Technical Implementation Guide. Just makes a ton of registry tweaks to harden the box.

* [`WS16_Stigs.ps1`](WS16_Stigs.ps1)

    Added by John Hammond. A force-compliance script for Windows Server 2016 Security Technical Implementation Guide. Just makes a ton of registry tweaks to harden the box.