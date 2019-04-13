@echo off

echo "V-1075"
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\" /v "ShutdownWithoutLogon" /t REG_DWORD /d 1 /f


echo "V-1083"
reg delete "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Subsystems" /v "Posix" /f


echo "V-1084"
reg add "HKLM\System\CurrentControlSet\Control\Session Manager\Memory Management\" /v "ClearPageFileAtShutdown" /t REG_DWORD /d 0 /f


echo "V-1085"
reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\" /v "Allocatefloppies" /t REG_SZ /d 0 /f

echo "V-1090"
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\" /v "CachedLogonsCount" /t REG_SZ /d 2 /f

echo "V-1091"
reg add "HKLM\System\CurrentControlSet\Control\Lsa" /v "CrashOnAuditFail" /t REG_DWORD /d 0 /f


echo "V-1093"
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa\" /v "RestrictAnonymous" /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa\" /v "RestrictAnonymousSAM" /t REG_DWORD /d 1 /f


echo "V-1122"
reg add "HKCU\SOFTWARE\Policies\Microsoft\Windows\Control Panel\Desktop\" /v "ScreenSaveActive" /t REG_SZ /d 1 /f
reg add "HKCU\SOFTWARE\Policies\Microsoft\Windows\Control Panel\Desktop\" /v "ScreenSaverIsSecure" /t REG_SZ /d 1 /f
reg add "HKCU\SOFTWARE\Policies\Microsoft\Windows\Control Panel\Desktop\" /v "ScreenSaveTimeout" /t REG_SZ /d 900 /f

echo "V-1136"
reg add "HKLM\System\CurrentControlSet\Services\LanManServer\Parameters\" /v "EnableForcedLogoff" /t REG_DWORD /d 1 /f


echo "V-1139"
reg add "HKLM\System\CurrentControlSet\Services\RasMan\Parameters\" /v "DisableSavePassword" /t REG_DWORD /d 1 /f


echo "V-1141"
reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters\" /v "EnablePlainTextPassword" /t REG_DWORD /d 0 /f

echo "V-1145"
reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\" /v "AutoAdminLogon" /t REG_SZ /d 0 /f

echo "V-1151"
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers\" /v "AddPrinterDrivers" /t REG_DWORD /d 1 /f

echo "V-1153"
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa\" /v "LmCompatibilityLevel" /t REG_DWORD /d 5 /f

echo "V-1154"
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\" /v "DisableCAD" /t REG_DWORD /d 0 /f

echo "V-1157"
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\" /v "SCRemoveOption" /t REG_SZ /d 1 /f

echo "V-1158"
reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Setup\RecoveryConsole\" /v "SetCommand" /t REG_DWORD /d 0 /f

echo "V-1159"
reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Setup\RecoveryConsole\" /v "SecurityLevel" /t REG_DWORD /d 0 /f


echo "V-1160"
reg add "HKLM\Software\Microsoft\Driver Signing\" /v "Policy" /t REG_BINARY /d 2 /f


echo "V-1162"
reg add "HKLM\System\CurrentControlSet\Services\LanManServer\Parameters\" /v "EnableSecuritySignature" /t REG_DWORD /d 1 /f


echo "V-1163"
reg add "HKLM\System\CurrentControlSet\Services\Netlogon\Parameters\" /v "SealSecureChannel" /t REG_DWORD /d 1 /f

echo "V-1164"
reg add "HKLM\System\CurrentControlSet\Services\Netlogon\Parameters\" /v "SignSecureChannel" /t REG_DWORD /d 1 /f

echo "V-1165"
reg add "HKLM\System\CurrentControlSet\Services\Netlogon\Parameters\" /v "DisablePasswordChange" /t REG_DWORD /d 0 /f

echo "V-1166"
reg add "HKLM\System\CurrentControlSet\Services\LanmanWorkstation\Parameters\" /v "EnableSecuritySignature" /t REG_DWORD /d 1 /f

echo "V-1171"
reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "AllocateDASD" /t REG_SZ /d 0 /f

echo "V-1172"
reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\" /v "PasswordExpiryWarning" /t REG_DWORD /d 14 /f

echo "V-1173"
reg add "HKLM\System\CurrentControlSet\Control\Session Manager\" /v "ProtectionMode" /t REG_DWORD /d 1 /f

echo "V-1174"
reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters\" /v "autodisconnect" /t REG_DWORD /d 0x0000000f /f

echo "V-2374"
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\policies\Explorer\" /v "NoDriveTypeAutorun" /t REG_DWORD /d 0x000000ff /f

echo "V-3338"
reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters\" /v "NullSessionPipes" /t REG_MULTI_SZ /d "" /f

echo "V-3339"
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurePipeServers\Winreg\AllowedExactPaths\" /v "Machine" /t REG_MULTI_SZ /d "System\CurrentControlSet\Control\ProductOptions  System\CurrentControlSet\Control\Server Applications  Software\Microsoft\Windows NT\CurrentVersion" /f

echo "V-3340"
reg add "HKLM\System\CurrentControlSet\Services\LanManServer\Parameters\" /v "NullSessionShares" /t REG_MULTI_SZ /d "" /f

echo "V-3341"
reg add "HKLM\Software\Policies\Microsoft\Windows NT\Terminal Services\" /v "Shadow" /t REG_DWORD /d 0 /f

echo "V-3343"
reg add "HKLM\Software\Policies\Microsoft\Windows NT\Terminal Services\" /v "fAllowToGetHelp" /t REG_DWORD /d 0 /f

echo "V-3344"
reg add "HKLM\System\CurrentControlSet\Control\Lsa" /v "LimitBlankPasswordUse" /t REG_DWORD /d 1 /f

echo "V-3348"
reg add "HKLM\Software\Policies\Microsoft\Messenger\Client\" /v "PreventRun" /t REG_DWORD /d 1 /f

echo "V-3349"
reg add "HKLM\Software\Policies\Microsoft\Messenger\Client\" /v "PreventAutoRun" /t REG_DWORD /d 1 /f

echo "V-3373"
reg add "HKLM\System\CurrentControlSet\Services\Netlogon\Parameters\" /v "MaximumPasswordAge" /t REG_DWORD /d 30 /f

echo "V-3374"
reg add "HKLM\System\CurrentControlSet\Services\Netlogon\Parameters\" /v "RequireStrongKey" /t REG_DWORD /d 1 /f

echo "V-3375"
reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\" /v "ForceUnlockLogon" /t REG_DWORD /d 0 /f

echo "V-3376"
reg add "HKLM\System\CurrentControlSet\Control\Lsa\" /v "DisableDomainCreds" /t REG_DWORD /d 1 /f

echo "V-3377"
reg add "HKLM\System\CurrentControlSet\Control\Lsa\" /v "EveryoneIncludesAnonymous" /t REG_DWORD /d 0 /f

echo "V-3378"
reg add "HKLM\System\CurrentControlSet\Control\Lsa\" /v "ForceGuest" /t REG_DWORD /d 0 /f

echo "V-3379"
reg add "HKLM\System\CurrentControlSet\Control\Lsa\" /v "NoLMHash" /t REG_DWORD /d 1 /f

echo "V-3381"
reg add "HKLM\System\CurrentControlSet\Services\LDAP\" /v "LDAPClientIntegrity" /t REG_DWORD /d 1 /f

echo "V-3382"
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0\" /v "NTLMMinClientSec" /t REG_DWORD /d 0x20080000 /f

echo "V-3383"
reg add "HKLM\System\CurrentControlSet\Control\Lsa\FIPSAlgorithmPolicy\" /v "Enabled" /t REG_DWORD /d 1 /f

echo "V-3384"
reg add "HKLM\System\CurrentControlSet\Control\Lsa\" /v "NoDefaultAdminOwner" /t REG_DWORD /d 1 /f

echo "V-3385"
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Kernel\" /v "ObCaseInsensitive" /t REG_DWORD /d 1 /f

echo "V-3426"
reg add "HKLM\Software\Policies\Microsoft\Conferencing\" /v "NoRDS" /t REG_DWORD /d 1 /f

echo "V-3453"
reg add "HKLM\Software\Policies\Microsoft\Windows NT\Terminal Services\" /v "fPromptForPassword" /t REG_DWORD /d 1 /f

echo "V-3454"
reg add "HKLM\Software\Policies\Microsoft\Windows NT\Terminal Services\" /v "MinEncryptionLevel" /t REG_DWORD /d 3 /f

echo "V-3455"
reg add "HKLM\Software\Policies\Microsoft\Windows NT\Terminal Services\" /v "PerSessionTempDir" /t REG_DWORD /d 1 /f

echo "V-3456"
reg add "HKLM\Software\Policies\Microsoft\Windows NT\Terminal Services\" /v "DeleteTempDirsOnExit" /t REG_DWORD /d 1 /f

echo "V-3457"
reg add "HKLM\Software\Policies\Microsoft\Windows NT\Terminal Services\" /v "MaxDisconnectionTime" /t REG_DWORD /d 0x0000ea60 /f

echo "V-3458"
reg add "HKLM\Software\Policies\Microsoft\Windows NT\Terminal Services\" /v "MaxIdleTime" /t REG_DWORD /d 0x000dbba0 /f

echo "V-3459"
reg add "HKLM\Software\Policies\Microsoft\Windows NT\Terminal Services\" /v "fReconnectSame" /t REG_DWORD /d 1 /f

echo "V-3460"
reg add "HKLM\Software\Policies\Microsoft\Windows NT\Terminal Services\" /v "fResetBroken" /t REG_DWORD /d 1 /f

echo "V-3469"
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\system\" /v "DisableBkGndGroupPolicy" /t REG_DWORD /d 0 /f

echo "V-3470"
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\" /v "fAllowUnsolicited" /t REG_DWORD /d 0 /f

echo "V-3471"
reg add "HKLM\Software\Policies\Microsoft\PCHealth\ErrorReporting\" /v "DoReport" /t REG_DWORD /d 0 /f


echo "V-3472"
reg add "HKLM\Software\Policies\Microsoft\W32time\Parameters\" /v "Type" /t REG_SZ /d "NoSync" /f

echo "V-3478"
reg add "HKLM\Software\Policies\Microsoft\Windows NT\Printers\" /v "KMPrintersAreBlocked" /t REG_DWORD /d 1 /f


echo "V-3479"
reg add "HKLM\System\CurrentControlSet\Control\Session Manager\" /v "SafeDllSearchMode" /t REG_DWORD /d 1 /f

echo "V-3480"
reg add "HKLM\Software\Policies\Microsoft\WindowsMediaPlayer\" /v "DisableAutoupdate" /t REG_DWORD /d 1 /f

echo "V-3480"
reg add "HKCU\Software\Policies\Microsoft\WindowsMediaPlayer\" /v "PreventCodecDownload" /t REG_DWORD /d 1 /f


echo "V-3666"
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0\" /v "NTLMMinServerSec" /t REG_DWORD /d 0x20080000 /f

echo "V-4108"
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Eventlog\Security\" /v "WarningLevel" /t REG_DWORD /d 0x0000005a /f

echo "V-4108"
reg add "HKLM\System\CurrentControlSet\Services\Tcpip\Parameters\" /v "EnableDeadGWDetect" /t REG_DWORD /d 0 /f


echo "V-4110"
reg add "HKLM\System\CurrentControlSet\Services\Tcpip\Parameters\" /v "DisableIPSourceRouting" /t REG_DWORD /d 2 /f

echo "V-4111"
reg add "HKLM\System\CurrentControlSet\Services\Tcpip\Parameters\" /v "EnableICMPRedirect" /t REG_DWORD /d 0 /f

echo "V-4112"
reg add "HKLM\System\CurrentControlSet\Services\Tcpip\Parameters\" /v "PerformRouterDiscovery" /t REG_DWORD /d 0 /f


echo "V-4113"
reg add "HKLM\System\CurrentControlSet\Services\Tcpip\Parameters\" /v "KeepAliveTime" /t REG_DWORD /d 300000 /f

echo "V-4116"
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Netbt\Parameters\" /v "NoNameReleaseOnDemand" /t REG_DWORD /d 1 /f

echo "V-4117"
reg add "HKLM\System\CurrentControlSet\Services\Tcpip\Parameters\" /v "SynAttackProtect" /t REG_DWORD /d 1 /f

echo "V-4137"
reg add "HKLM\System\CurrentControlSet\Services\Tcpip\Parameters\" /v "TcpMaxConnectResponseRetransmissions" /t REG_DWORD /d 1 /f


echo "V-4438"
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\" /v "TcpMaxDataRetransmissions" /t REG_DWORD /d 3 /f

echo "V-4442"
reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\" /v "ScreenSaverGracePeriod" /t REG_SZ /d 5 /f


echo "V-4447"
reg add "HKLM\Software\Policies\Microsoft\Windows NT\Terminal Services\" /v "fEncryptRPCTraffic" /t REG_DWORD /d 1 /f


echo "V-4448"
reg add "HKLM\Software\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}" /v "NoGPOListChanges" /t REG_DWORD /d 0 /f

echo "V-6831"
reg add "HKLM\System\CurrentControlSet\Services\Netlogon\Parameters\" /v "RequireSignOrSeal" /t REG_DWORD /d 1 /f

echo "V-6832"
reg add "HKLM\System\CurrentControlSet\Services\LanmanWorkstation\Parameters\" /v "RequireSecuritySignature" /t REG_DWORD /d 1 /f

echo "V-6833"
reg add "HKLM\System\CurrentControlSet\Services\LanManServer\Parameters\" /v "RequireSecuritySignature" /t REG_DWORD /d 1 /f

echo "V-6834"
reg add "HKLM\System\CurrentControlSet\Services\LanManServer\Parameters\" /v "RestrictNullSessAccess" /t REG_DWORD /d 1 /f

echo "V-11806"
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\" /v "DontDisplayLastUserName" /t REG_DWORD /d 1 /f

echo "V-14228"
reg add "HKLM\System\CurrentControlSet\Control\Lsa" /v "AuditBaseObjects" /t REG_DWORD /d 0 /f

echo "V-14229"
reg add "HKLM\System\CurrentControlSet\Control\Lsa" /v "FullPrivilegeAuditing" /t REG_Binary /d 0 /f

echo "V-14247"
reg add "HKLM\Software\Policies\Microsoft\Windows NT\Terminal Services\" /v "DisablePasswordSaving" /t REG_DWORD /d 1 /f

echo "V-14248"
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\" /v "fDenyTSConnections" /t REG_DWORD /d 1 /f

echo "V-14249"
reg add "HKLM\Software\Policies\Microsoft\Windows NT\Terminal Services\" /v "fDisableCdm" /t REG_DWORD /d 1 /f

echo "V-14253"
reg add "HKLM\Software\Policies\Microsoft\Windows NT\Rpc\" /v "RestrictRemoteClients" /t REG_DWORD /d 1 /f

echo "V-14254"
reg add "HKLM\Software\Policies\Microsoft\Windows NT\Rpc\" /v "EnableAuthEpResolution" /t REG_DWORD /d 1 /f


echo "V-14255"
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoPublishingWizard" /t REG_DWORD /d 1 /f


echo "V-14256"
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoWebServices" /t REG_DWORD /d 1 /f

echo "V-14257"
reg add "HKLM\Software\Policies\Microsoft\Messenger\Client" /v "CEIP" /t REG_DWORD /d 2 /f

echo "V-14258"
reg add "HKLM\Software\Policies\Microsoft\SearchCompanion" /v "DisableContentFileUpdates" /t REG_DWORD /d 1 /f


echo "V-14259"
reg add "HKLM\Software\Policies\Microsoft\Windows NT\Printers" /v "DisableHTTPPrinting" /t REG_DWORD /d 1 /f

echo "V-14260"
reg add "HKLM\Software\Policies\Microsoft\Windows NT\Printers" /v "DisableWebPnPDownload" /t REG_DWORD /d 1 /f

echo "V-14261"
reg add "HKLM\Software\Policies\Microsoft\Windows\DriverSearching" /v "DontSearchWindowsUpdate" /t REG_DWORD /d 1 /f

echo "V-14267"
reg add "HKCU\Software\Policies\Microsoft\Windows\System\Power\" /v "PromptPasswordOnResume" /t REG_DWORD /d 1 /f

echo "V-14268"
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments\" /v "SaveZoneInformation" /t REG_DWORD /d 2 /f

echo "V-14269"
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments\" /v "HideZoneInfoOnProperties" /t REG_DWORD /d 1 /f

echo "V-14270"
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments\" /v "ScanWithAntiVirus" /t REG_DWORD /d 3 /f

echo "V-15666"
reg add "HKLM\Software\Policies\Microsoft\Peernet\" /v "Disabled" /t REG_DWORD /d 1 /f

echo "V-15667"
reg add "HKLM\Software\Policies\Microsoft\Windows\Network Connections\" /v "NC_AllowNetBridge_NLA" /t REG_DWORD /d 0 /f

echo "V-15669"
reg add "HKLM\Software\Policies\Microsoft\Windows\Network Connections\" /v "NC_ShowSharedAccessUI" /t REG_DWORD /d 0 /f


echo "V-15670"
reg add "HKLM\Software\Policies\Microsoft\PCHealth\ErrorReporting\" /v "ShowUI" /t REG_DWORD /d 0 /f

echo "V-15671"
reg add "HKLM\Software\Policies\Microsoft\SystemCertificates\AuthRoot\" /v "DisableRootAutoUpdate" /t REG_DWORD /d 1 /f


echo "V-15672"
reg add "HKLM\Software\Policies\Microsoft\EventViewer\" /v "MicrosoftEventVwrDisableLinks" /t REG_DWORD /d 0 /f

echo "V-15673"
reg add "HKLM\Software\Policies\Microsoft\Windows\Internet Connection Wizard\" /v "ExitOnMSICW" /t REG_DWORD /d 1 /f


echo "V-15674"
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\" /v "NoInternetOpenWith" /t REG_DWORD /d 1 /f

echo "V-15675"
reg add "HKLM\Software\Policies\Microsoft\Windows\Registration Wizard Control\" /v "NoRegistration" /t REG_DWORD /d 1 /f


echo "V-15676"
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\" /v "NoOnlinePrintsWizard" /t REG_DWORD /d 1 /f

echo "V-15677"
reg add "HKLM\Software\Policies\Microsoft\WindowsMovieMaker\" /v "CodecDownload" /t REG_DWORD /d 1 /f

echo "V-15678"
reg add "HKLM\Software\Policies\Microsoft\WindowsMovieMaker\" /v "Webhelp" /t REG_DWORD /d 1 /f

echo "V-15679"
reg add "HKLM\Software\Policies\Microsoft\WindowsMovieMaker\" /v "WebPublish" /t REG_DWORD /d 1 /f


echo "V-15680"
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\" /v "LogonType" /t REG_DWORD /d 0 /f

echo "V-15682"
reg add "HKLM\SOFTWARE\Policies\Microsoft\Internet Explorer\Feeds\" /v "DisableEnclosureDownload" /t REG_DWORD /d 1 /f

echo "V-15683"
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\" /v "PreXPSP2ShellProtocolBehavior" /t REG_DWORD /d 0 /f

echo "V-15684"
reg add "HKLM\Software\Policies\Microsoft\Windows\Installer\" /v "SafeForScripting" /t REG_DWORD /d 0 /f

echo "V-15685"
reg add "HKLM\Software\Policies\Microsoft\Windows\Installer\" /v "EnableUserControl" /t REG_DWORD /d 0 /f

echo "V-15686"
reg add "HKLM\Software\Policies\Microsoft\Windows\Installer\" /v "DisableLUAPatching" /t REG_DWORD /d 1 /f

echo "V-15687"
reg add "HKLM\Software\Policies\Microsoft\WindowsMediaPlayer\" /v "GroupPrivacyAcceptance" /t REG_DWORD /d 1 /f


echo "V-17373"
reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\" /v "AllocateCDRoms" /t REG_SZ /d 0 /f

echo "V-17900"
reg add "HKLMSOFTWARE\Microsoft\Windows NT\CurrentVersion\IniFileMapping\Autorun.inf" /v "(Default)" /t REG_SZ /d "@SYS:DoesNotExist" /f



echo "V-26359"
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\" /v "LegalNoticeCaption" /t REG_SZ /d "Notice and Consent Banner" /f

echo "V-34974"
reg add "HKLM\Software\Policies\Microsoft\Windows\Installer\" /v "AlwaysInstallElevated" /t REG_DWORD /d 0 /f


echo "STIGs complete!"
