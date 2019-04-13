@echo off

:: John Hammond: these come from the BTFM
:: https://github.com/JohnHammond/blueteamfieldmanual

echo "Disabling IPv6..."
reg add "HKLM\System\CurrentControlSet\services\TCPIP6\Parameters" /v DisabledComponents /t REG_DWORD /d 255 /f

echo "Disabling Sticky Keys..."
reg add "HKCU\Control Panel\Accessibility\StickyKeys" /v Flags /t REG_SZ /d 506 /f

echo "Disabling Toggle Keys..."
reg add "HKCU\Control Panel\Accessibility\ToggleKeys" /v Flags /t REG_SZ /d 58 /f

echo "Disabling Filter Keys..."
reg add "HKCU\Control Panel\Accessibility\Keyboard Response" /v Flags /t REG_SZ /d 122 /f

echo "Disabling On-Screen Keyboard..."
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI" /v ShowTabletKeyboard /t REG_DWORD /d 0 /f

echo "Disabling Administrative Shares... (workstations)"
reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v AutoShareWks /t REG_DWORD /d 0 /f

echo "Disabling Administrative Shares... (servers)"
reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v AutoShareServer /t REG_DWORD /d 0 /f

echo "Disabling hash creation for PtH attacks.. (requires password reset and reboot to purge old hashes)"
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v NoLMHash /t REG_DWORD /d 1 /f

echo "Disabling IE Password cache..."
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v DisablePasswordCaching /t REG_DWORD /d 1 /f

echo "Disabling admin credentials cache on host when using RDP..."
reg add "HKLM\System\CurrentControlSet\Control\Lsa" /v DisableRestrictedAdmin /t REG_DWORD /d 0 /f

echo add "Disabling the RunOnce list..."
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v DisableLocalMachineRunOnce /t REG_DWORD /d 1 /f