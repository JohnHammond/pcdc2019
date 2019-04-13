@echo off

echo "V-1075"
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\" /v "ShutdownWithoutLogon" /t REG_DWORD /d 1 /f


echo "V-1084"
reg add "HKLM\System\CurrentControlSet\Control\Session Manager\Memory Management\" /v "ClearPageFileAtShutdown" /t REG_DWORD /d 0 /f


echo "V-1085"
reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\" /v "Allocatefloppies" /t REG_SZ /d 0 /f

echo "V-1090"
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\" /v "CachedLogonsCount" /t REG_SZ /d 2 /f

echo "V-1093"
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa\" /v "RestrictAnonymous" /t REG_DWORD /d 1 /f


echo "V-1122"
reg add "HKCU\SOFTWARE\Policies\Microsoft\Windows\Control Panel\Desktop\" /v "ScreenSaveActive" /t REG_SZ /d 1 /f
reg add "HKCU\SOFTWARE\Policies\Microsoft\Windows\Control Panel\Desktop\" /v "ScreenSaverIsSecure" /t REG_SZ /d 1 /f
reg add "HKCU\SOFTWARE\Policies\Microsoft\Windows\Control Panel\Desktop\" /v "ScreenSaveTimeout" /t REG_SZ /d 900 /f

echo "V-1136"
reg add "HKLM\System\CurrentControlSet\Services\LanManServer\Parameters\" /v "EnableForcedLogoff" /t REG_DWORD /d 1 /f

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

echo "V-3343"
reg add "HKLM\Software\Policies\Microsoft\Windows NT\Terminal Services\" /v "fAllowToGetHelp" /t REG_DWORD /d 0 /f

echo "V-3344"
reg add "HKLM\System\CurrentControlSet\Control\Lsa" /v "LimitBlankPasswordUse" /t REG_DWORD /d 1 /f

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

echo "V-3385"
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Kernel\" /v "ObCaseInsensitive" /t REG_DWORD /d 1 /f

echo "V-3453"
reg add "HKLM\Software\Policies\Microsoft\Windows NT\Terminal Services\" /v "fPromptForPassword" /t REG_DWORD /d 1 /f

echo "V-3454"
reg add "HKLM\Software\Policies\Microsoft\Windows NT\Terminal Services\" /v "MinEncryptionLevel" /t REG_DWORD /d 3 /f

echo "V-3455"
reg add "HKLM\Software\Policies\Microsoft\Windows NT\Terminal Services\" /v "PerSessionTempDir" /t REG_DWORD /d 1 /f

echo "V-3456"
reg add "HKLM\Software\Policies\Microsoft\Windows NT\Terminal Services\" /v "DeleteTempDirsOnExit" /t REG_DWORD /d 1 /f

echo "V-3469"
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\system\" /v "DisableBkGndGroupPolicy" /t REG_DWORD /d 0 /f

echo "V-3470"
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\" /v "fAllowUnsolicited" /t REG_DWORD /d 0 /f

echo "V-3472"
reg add "HKLM\Software\Policies\Microsoft\W32time\Parameters\" /v "Type" /t REG_SZ /d "NoSync" /f

echo "V-3479"
reg add "HKLM\System\CurrentControlSet\Control\Session Manager\" /v "SafeDllSearchMode" /t REG_DWORD /d 1 /f

echo "V-3480"
reg add "HKLM\Software\Policies\Microsoft\WindowsMediaPlayer\" /v "DisableAutoupdate" /t REG_DWORD /d 1 /f

echo "V-3666"
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0\" /v "NTLMMinServerSec" /t REG_DWORD /d 0x20080000 /f

echo "V-4108"
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Eventlog\Security\" /v "WarningLevel" /t REG_DWORD /d 0x0000005a /f

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

echo "V-4438"
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\" /v "TcpMaxDataRetransmissions" /t REG_DWORD /d 3 /f

echo "V-4442"
reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\" /v "ScreenSaverGracePeriod" /t REG_SZ /d 5 /f

echo "V-4443"
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurePipeServers\Winreg\AllowedPaths\" /v "Machine" /t REG_MULTI_SZ /d "" /f

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

echo "V-14230"
reg add "HKLM\System\CurrentControlSet\Control\Lsa" /v "SCENoApplyLegacyAuditPolicy" /t REG_DWORD /d 1 /f

echo "V-14230"
reg add "HKLM\System\CurrentControlSet\Control\Lsa" /v "SCENoApplyLegacyAuditPolicy" /t REG_DWORD /d 1 /f

echo "V-14231"
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Lanmanserver\Parameters\" /v "Hidden" /t REG_DWORD /d 1 /f

echo "V-14232"
reg add "HKLM\System\CurrentControlSet\Services\IPSEC\" /v "NoDefaultExempt" /t REG_DWORD /d 1 /f

echo "V-14234"
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\" /v "FilterAdministratorToken" /t REG_DWORD /d 1 /f

echo "V-14235"
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\" /v "ConsentPromptBehaviorAdmin" /t REG_DWORD /d 2 /f

echo "V-14236"
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\" /v "ConsentPromptBehaviorUser" /t REG_DWORD /d 0 /f

echo "V-14237"
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\" /v "EnableInstallerDetection" /t REG_DWORD /d 1 /f

echo "V-14239"
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\" /v "EnableSecureUIAPaths" /t REG_DWORD /d 1 /f

echo "V-14240"
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\" /v "EnableLUA" /t REG_DWORD /d 1 /f

echo "V-14241"
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\" /v "PromptOnSecureDesktop" /t REG_DWORD /d 1 /f

echo "V-14242"
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\" /v "EnableVirtualization" /t REG_DWORD /d 1 /f

echo "V-14243"
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\CredUI" /v "EnumerateAdministrators" /t REG_DWORD /d 0 /f

echo "V-14247"
reg add "HKLM\Software\Policies\Microsoft\Windows NT\Terminal Services\" /v "DisablePasswordSaving" /t REG_DWORD /d 1 /f

echo "V-14248"
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\" /v "fDenyTSConnections" /t REG_DWORD /d 1 /f

echo "V-14249"
reg add "HKLM\Software\Policies\Microsoft\Windows NT\Terminal Services\" /v "fDisableCdm" /t REG_DWORD /d 1 /f

echo "V-14253"
reg add "HKLM\Software\Policies\Microsoft\Windows NT\Rpc\" /v "RestrictRemoteClients" /t REG_DWORD /d 1 /f

echo "V-14256"
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoWebServices" /t REG_DWORD /d 1 /f

echo "V-14259"
reg add "HKLM\Software\Policies\Microsoft\Windows NT\Printers" /v "DisableHTTPPrinting" /t REG_DWORD /d 1 /f

echo "V-14260"
reg add "HKLM\Software\Policies\Microsoft\Windows NT\Printers" /v "DisableWebPnPDownload" /t REG_DWORD /d 1 /f

echo "V-14261"
reg add "HKLM\Software\Policies\Microsoft\Windows\DriverSearching" /v "DontSearchWindowsUpdate" /t REG_DWORD /d 1 /f

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

echo "V-15672"
reg add "HKLM\Software\Policies\Microsoft\EventViewer\" /v "MicrosoftEventVwrDisableLinks" /t REG_DWORD /d 0 /f

echo "V-15674"
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\" /v "NoInternetOpenWith" /t REG_DWORD /d 1 /f

echo "V-15676"
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\" /v "NoOnlinePrintsWizard" /t REG_DWORD /d 1 /f

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

echo "V-15696"
reg add "HKLM\Software\Policies\Microsoft\Windows\LLTD\" /v "AllowLLTDIOOndomain" /t REG_DWORD /d 0 /f
reg add "HKLM\Software\Policies\Microsoft\Windows\LLTD\" /v "AllowLLTDIOOnPublicNet" /t REG_DWORD /d 0 /f
reg add "HKLM\Software\Policies\Microsoft\Windows\LLTD\" /v "EnableLLTDIO" /t REG_DWORD /d 0 /f
reg add "HKLM\Software\Policies\Microsoft\Windows\LLTD\" /v "ProhibitLLTDIOOnPrivateNet" /t REG_DWORD /d 0 /f

echo "V-15697"
reg add "HKLM\Software\Policies\Microsoft\Windows\LLTD\" /v "AllowRspndrOndomain" /t REG_DWORD /d 0 /f
reg add "HKLM\Software\Policies\Microsoft\Windows\LLTD\" /v "AllowRspndrOnPublicNet" /t REG_DWORD /d 0 /f
reg add "HKLM\Software\Policies\Microsoft\Windows\LLTD\" /v "EnableRspndr" /t REG_DWORD /d 0 /f
reg add "HKLM\Software\Policies\Microsoft\Windows\LLTD\" /v "ProhibitRspndrOnPrivateNet" /t REG_DWORD /d 0 /f

echo "V-15698"
reg add "HKLM\Software\Policies\Microsoft\Windows\WCN\Registrars\" /v "DisableFlashConfigRegistrar" /t REG_DWORD /d 0 /f
reg add "HKLM\Software\Policies\Microsoft\Windows\WCN\Registrars\" /v "DisableInBand802DOT11Registrar" /t REG_DWORD /d 0 /f
reg add "HKLM\Software\Policies\Microsoft\Windows\WCN\Registrars\" /v "DisableUPnPRegistrar" /t REG_DWORD /d 0 /f
reg add "HKLM\Software\Policies\Microsoft\Windows\WCN\Registrars\" /v "DisableWPDRegistrar" /t REG_DWORD /d 0 /f
reg add "HKLM\Software\Policies\Microsoft\Windows\WCN\Registrars\" /v "EnableRegistrars" /t REG_DWORD /d 0 /f


echo "V-15699"
reg add "HKLM\Software\Policies\Microsoft\Windows\WCN\UI\" /v "DisableWcnUi" /t REG_DWORD /d 1 /f

echo "V-15700"
reg add "HKLM\Software\Policies\Microsoft\Windows\DeviceInstall\Settings\" /v "AllowRemoteRPC" /t REG_DWORD /d 0 /f

echo "V-15701"
reg add "HKLM\Software\Policies\Microsoft\Windows\DeviceInstall\Settings\" /v "DisableSystemRestore" /t REG_DWORD /d 0 /f

echo "V-15702"
reg add "HKLM\Software\Policies\Microsoft\Windows\DeviceInstall\Settings\" /v "DisableSendGenericDriverNotFoundToWER" /t REG_DWORD /d 1 /f

echo "V-15703"
reg add "HKLM\Software\Policies\Microsoft\Windows\DriverSearching\" /v "DontPromptForWindowsUpdate" /t REG_DWORD /d 1 /f

echo "V-15704"
reg add "HKLM\Software\Policies\Microsoft\Windows\HandwritingErrorReports\" /v "PreventHandwritingErrorReports" /t REG_DWORD /d 1 /f

echo "V-15705"
reg add "HKLM\Software\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51\" /v "DCSettingIndex" /t REG_DWORD /d 1 /f

echo "V-15706"
reg add "HKLM\Software\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51\" /v "ACSettingIndex" /t REG_DWORD /d 1 /f

echo "V-15707"
reg add "HKLM\Software\Policies\Microsoft\Windows NT\Terminal Services\" /v "LoggingEnabled" /t REG_DWORD /d 1 /f

echo "V-15709"
reg add "HKLM\Software\Policies\Microsoft\Windows\GameUX\" /v "DownloadGameInfo" /t REG_DWORD /d 0 /f

echo "V-15711"
reg add "HKLM\Software\Policies\Microsoft\Windows\Windows Search\" /v "AllowIndexingEncryptedStoresOrItems" /t REG_DWORD /d 0 /f

echo "V-15712"
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search\" /v "PreventIndexingUncachedExchangeFolders" /t REG_DWORD /d 1 /f

echo "V-15713"
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Spynet\" /v "SpyNetReporting" /t REG_DWORD /d 0 /f

echo "V-15718"
reg add "HKLM\Software\Policies\Microsoft\Windows\Explorer\" /v "NoHeapTerminationOnCorruption" /t REG_DWORD /d 0 /f

echo "V-15722"
reg add "HKLM\Software\Policies\Microsoft\WMDRM\" /v "DisableOnline" /t REG_DWORD /d 1 /f

echo "V-15724"
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Windows\Sidebar\" /v "TurnOffSidebar" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Windows\Sidebar\" /v "TurnOffUnsignedGadgets" /t REG_DWORD /d 1 /f

echo "V-15725"
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Windows\Sidebar\" /v "TurnOffSidebar" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Windows\Sidebar\" /v "OverrideMoreGadgetsLink" /t REG_SZ /d "about:blank" /f

echo "V-15726"
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Windows\Sidebar\" /v "TurnOffSidebar" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Windows\Sidebar\" /v "TurnOffUserInstalledGadgets" /t REG_DWORD /d 1 /f

echo "V-15727"
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\" /v "NoInPlaceSharing" /t REG_DWORD /d 1 /f

echo "V-16008"
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\" /v "ValidateAdminCodeSignatures" /t REG_DWORD /d 0 /f

echo "V-16020"
reg add "HKLM\Software\Policies\Microsoft\SQMClient\Windows" /v "CEIPEnable" /t REG_DWORD /d 0 /f

echo "V-16021"
reg add "HKLM\Software\Policies\Microsoft\Assistance\Client\1.0" /v "NoImplicitFeedback" /t REG_DWORD /d 1 /f


echo "V-16048"
reg add "HKLM\Software\Policies\Microsoft\Assistance\Client\1.0" /v "NoExplicitFeedback" /t REG_DWORD /d 1 /f

echo "V-17373"
reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\" /v "AllocateCDRoms" /t REG_SZ /d 0 /f

echo "V-21950"
reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters\" /v "SmbServerNameHardeningLevel" /t REG_DWORD /d 1 /f

echo "V-21951"
reg add "HKLM\SYSTEM\CurrentControlSet\Control\LSA\" /v "UseMachineId" /t REG_DWORD /d 1 /f

echo "V-21952"
reg add "HKLM\SYSTEM\CurrentControlSet\Control\LSA\MSV1_0\" /v "allownullsessionfallback" /t REG_DWORD /d 0 /f

echo "V-21953"
reg add "HKLM\SYSTEM\CurrentControlSet\Control\LSA\pku2u\" /v "AllowOnlineID" /t REG_DWORD /d 0 /f

echo "V-21955"
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\" /v "DisableIpSourceRouting" /t REG_DWORD /d 2 /f

echo "V-21956"
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\" /v "TcpMaxDataRetransmissions" /t REG_DWORD /d 3 /f

echo "V-21960"
reg add "HKLM\Software\Policies\Microsoft\Windows\Network Connections\" /v "NC_StdDomainUserSetLocation" /t REG_DWORD /d 1 /f

echo "V-21961"
reg add "HKLM\Software\Policies\Microsoft\Windows\TCPIP\v6Transition\" /v "Force_Tunneling" /t REG_SZ /d "Enabled" /f

echo "V-21963"
reg add "HKLM\Software\Policies\Microsoft\Windows NT\Printers\" /v "DoNotInstallCompatibleDriverFromWindowsUpdate" /t REG_DWORD /d 1 /f

echo "V-21964"
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Device Metadata\" /v "PreventDeviceMetadataFromNetwork" /t REG_DWORD /d 1 /f

echo "V-21965"
reg add "HKLM\Software\Policies\Microsoft\Windows\DriverSearching\" /v "SearchOrderConfig" /t REG_DWORD /d 0 /f

echo "V-21966"
reg add "HKLM\Software\Policies\Microsoft\Windows\TabletPC\" /v "PreventHandwritingDataSharing" /t REG_DWORD /d 1 /f

echo "V-21967"
reg add "HKLM\Software\Policies\Microsoft\Windows\ScriptedDiagnosticsProvider\Policy\" /v "DisableQueryRemoteServer" /t REG_DWORD /d 0 /f

echo "V-21969"
reg add "HKLM\Software\Policies\Microsoft\Windows\ScriptedDiagnosticsProvider\Policy\" /v "EnableQueryRemoteServer" /t REG_DWORD /d 0 /f


echo "V-21970"
reg add "HKLM\Software\Policies\Microsoft\Windows\WDI\{9c5a40da-b965-4fc3-8781-88dd50a6299d}\" /v "ScenarioExecutionEnabled" /t REG_DWORD /d 0 /f

echo "V-21971"
reg add "HKLM\Software\Policies\Microsoft\Windows\AppCompat\" /v "DisableInventory" /t REG_DWORD /d 1 /f

echo "V-21973"
reg add "HKLM\Software\Policies\Microsoft\Windows\Explorer\" /v "NoAutoplayfornonVolume" /t REG_DWORD /d 1 /f


echo "V-21974"
reg add "HKLM\Software\Policies\Microsoft\Windows\GameUX\" /v "GameUpdateOptions" /t REG_DWORD /d 0 /f

echo "V-21975"
reg add "HKLM\Software\Policies\Microsoft\Windows\Homegroup\" /v "DisableHomeGroup" /t REG_DWORD /d 1 /f


echo "V-21978"
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\WAU\" /v "Disabled" /t REG_DWORD /d 1 /f

echo "V-21980"
reg add "HKLM\Software\Policies\Microsoft\Windows\Explorer\" /v "NoDataExecutionPrevention" /t REG_DWORD /d 0 /f

echo "V-22692"
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\" /v "NoAutorun" /t REG_DWORD /d 1 /f

echo "V-26283"
reg add "HKLM\System\CurrentControlSet\Control\Lsa\" /v "RestrictAnonymousSAM" /t REG_DWORD /d 1 /f

echo "V-26359"
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\" /v "LegalNoticeCaption" /t REG_SZ /d "Notice and Consent Banner" /f

echo "V-26575"
reg add "HKLM\Software\Policies\Microsoft\Windows\TCPIP\v6Transition\" /v "6to4_State" /t REG_SZ /d "Disabled" /f

echo "V-26576"
reg add "HKLM\Software\Policies\Microsoft\Windows\TCPIP\v6Transition\IPHTTPS\IPHTTPSInterface\" /v "IPHTTPS_ClientState" /t REG_DWORD /d 3 /f

echo "V-26577"
reg add "HKLM\Software\Policies\Microsoft\Windows\TCPIP\v6Transition\" /v "ISATAP_State" /t REG_SZ /d "Disabled" /f

echo "V-26578"
reg add "HKLM\Software\Policies\Microsoft\Windows\TCPIP\v6Transition\" /v "Teredo_State" /t REG_SZ /d "Disabled" /f

echo "V-26579"
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application\" /v "MaxSize" /t REG_DWORD /d 0x00008000 /f

echo "V-26580"
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security\" /v "MaxSize" /t REG_DWORD /d 0x00030000 /f

echo "V-26581"
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\Setup\" /v "MaxSize" /t REG_DWORD /d 0x00008000 /f

echo "V-26582"
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\System\" /v "MaxSize" /t REG_DWORD /d 0x00008000 /f

echo "V-34974"
reg add "HKLM\Software\Policies\Microsoft\Windows\Installer\" /v "AlwaysInstallElevated" /t REG_DWORD /d 0 /f

echo "V-34979"
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\" /v "LocalAccountTokenFilterPolicy" /t REG_DWORD /d 0x00000000 /f

echo "V-34979"
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\" /v "LocalAccountTokenFilterPolicy" /t REG_DWORD /d 0x00000000 /f

echo "V-36701"
reg add "HKLM\SOFTWARE\Policies\Microsoft\EMET\SysSettings\" /v "ASLR" /t REG_DWORD /d 3 /f

echo "V-36702"
reg add "HKLM\SOFTWARE\Policies\Microsoft\EMET\Defaults\" /v "*\Internet Explorer\iexplore.exe" /t REG_SZ /d "+EAF+ eaf_modules:mshtml.dll;flash*.ocx;jscript*.dll;vbscript.dll;vgx.dll +ASR asr_modules:npjpi*.dll;jp2iexp.dll;vgx.dll;msxml4*.dll;wshom.ocx;scrrun.dll;vbscript.dll asr_zones:1;2" /f

echo "V-36703"
reg add "HKLM\SOFTWARE\Policies\Microsoft\EMET\Defaults\" /v "*\Adobe\*\Reader\AcroRd32.exe" /t REG_SZ /d "+EAF+ eaf_modules:AcroRd32.dll;Acrofx32.dll;AcroForm.api" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\EMET\Defaults\" /v "*\Adobe\Acrobat*\Acrobat\Acrobat.exe" /t REG_SZ /d "EAF+ eaf_modules:AcroRd32.dll;Acrofx32.dll;AcroForm.api" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\EMET\Defaults\" /v "*\Java\jre*\bin\java.exe" /t REG_SZ /d "-HeapSpray" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\EMET\Defaults\" /v "*\Java\jre*\bin\javaw.exe" /t REG_SZ /d "-HeapSpray" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\EMET\Defaults\" /v "*\Java\jre*\bin\javaws.exe" /t REG_SZ /d "-HeapSpray" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\EMET\Defaults\" /v "*\OFFICE1*\EXCEL.EXE" /t REG_SZ /d "+ASR asr_modules:flash*.ocx" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\EMET\Defaults\" /v "*\OFFICE1*\INFOPATH.EXE" /t REG_SZ /d "" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\EMET\Defaults\" /v "*\OFFICE1*\LYNC.EXE" /t REG_SZ /d "" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\EMET\Defaults\" /v "*\OFFICE1*\MSACCESS.EXE" /t REG_SZ /d "" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\EMET\Defaults\" /v "*\OFFICE1*\MSPUB.EXE" /t REG_SZ /d "" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\EMET\Defaults\" /v "*\OFFICE1*\OIS.EXE" /t REG_SZ /d "" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\EMET\Defaults\" /v "*\OFFICE1*\OUTLOOK.EXE" /t REG_SZ /d "" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\EMET\Defaults\" /v "*\OFFICE1*\POWERPNT.EXE" /t REG_SZ /d "+ASR asr_modules:flash*.ocx" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\EMET\Defaults\" /v "*\OFFICE1*\PPTVIEW.EXE" /t REG_SZ /d "" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\EMET\Defaults\" /v "*\OFFICE1*\VISIO.EXE" /t REG_SZ /d "" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\EMET\Defaults\" /v "*\OFFICE1*\VPREVIEW.EXE" /t REG_SZ /d "" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\EMET\Defaults\" /v "*\OFFICE1*\WINWORD.EXEE" /t REG_SZ /d "+ASR asr_modules:flash*.ocx" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\EMET\Defaults\" /v "*\Windows NT\Accessories\wordpad.exe" /t REG_SZ /d "" /f


echo "V-36704"
reg add "HKLM\SOFTWARE\Policies\Microsoft\EMET\Defaults\" /v "*\7-Zip\7z.exe" /t REG_SZ /d "-EAF" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\EMET\Defaults\" /v "*\7-Zip\7zG.exe" /t REG_SZ /d "-EAF" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\EMET\Defaults\" /v "*\7-Zip\7zFM.exe" /t REG_SZ /d "-EAF" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\EMET\Defaults\" /v "*\Adobe\Adobe Photoshop CS*\Photoshop.exe" /t REG_SZ /d "" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\EMET\Defaults\" /v "*\Foxit Reader\Foxit Reader.exe" /t REG_SZ /d "" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\EMET\Defaults\" /v "*\Google\Chrome\Application\chrome.exe" /t REG_SZ /d "+EAF+ eaf_modules:chrome_child.dll" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\EMET\Defaults\" /v "*\Google\Google Talk\googletalk.exe" /t REG_SZ /d "-DEP" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\EMET\Defaults\" /v "*\iTunes\iTunes.exe" /t REG_SZ /d "" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\EMET\Defaults\" /v "*\Microsoft Lync\communicator.exe" /t REG_SZ /d "" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\EMET\Defaults\" /v "*\mIRC\mirc.exe" /t REG_SZ /d "" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\EMET\Defaults\" /v "*\Mozilla Firefox\firefox.exe" /t REG_SZ /d "+EAF+ eaf_modules:mozjs.dll;xul.dll" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\EMET\Defaults\" /v "*\Mozilla Firefox\plugin-container.exe" /t REG_SZ /d "" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\EMET\Defaults\" /v "*\Mozilla Thunderbird\plugin-container.exe" /t REG_SZ /d "" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\EMET\Defaults\" /v "*\Mozilla Thunderbird\thunderbird.exe" /t REG_SZ /d "" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\EMET\Defaults\" /v "*\Opera\*\opera.exe" /t REG_SZ /d "" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\EMET\Defaults\" /v "*\Opera\opera.exe" /t REG_SZ /d "" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\EMET\Defaults\" /v "*\Pidgin\pidgin.exe" /t REG_SZ /d "" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\EMET\Defaults\" /v "*\QuickTime\QuickTimePlayer.exe" /t REG_SZ /d "" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\EMET\Defaults\" /v "*\Real\RealPlayer\realconverter.exe" /t REG_SZ /d "" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\EMET\Defaults\" /v "*\Real\RealPlayer\realplay.exe" /t REG_SZ /d "" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\EMET\Defaults\" /v "*\Safari\Safari.exe" /t REG_SZ /d "" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\EMET\Defaults\" /v "*\SkyDrive\SkyDrive.exe" /t REG_SZ /d "" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\EMET\Defaults\" /v "*\Skype\Phone\Skype.exe " /t REG_SZ /d "-EAF" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\EMET\Defaults\" /v "*\VideoLAN\VLC\vlc.exe" /t REG_SZ /d "" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\EMET\Defaults\" /v "*\Winamp\winamp.exe" /t REG_SZ /d "" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\EMET\Defaults\" /v "*\Windows Live\Mail\wlmail.exe" /t REG_SZ /d "" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\EMET\Defaults\" /v "*\Windows Live\Photo Gallery\WLXPhotoGallery.exe" /t REG_SZ /d "" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\EMET\Defaults\" /v "*\Windows Live\Writer\WindowsLiveWriter.exe" /t REG_SZ /d "" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\EMET\Defaults\" /v "*\Windows Media Player\wmplayer.exe" /t REG_SZ /d "-EAF -MandatoryASLR" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\EMET\Defaults\" /v "*\WinRAR\rar.exe" /t REG_SZ /d "" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\EMET\Defaults\" /v "*\WinRAR\unrar.exe" /t REG_SZ /d "" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\EMET\Defaults\" /v "*\WinRAR\winrar.exe" /t REG_SZ /d "" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\EMET\Defaults\" /v "*\WinZip\winzip32.exe" /t REG_SZ /d "" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\EMET\Defaults\" /v "*\WinZip\winzip64.exe" /t REG_SZ /d "" /f



echo "V-36705"
reg add "HKLM\SOFTWARE\Policies\Microsoft\EMET\SysSettings\" /v "DEP" /t REG_DWORD /d 2 /f

echo "V-36706"
reg add "HKLM\SOFTWARE\Policies\Microsoft\EMET\SysSettings\" /v "SEHOP" /t REG_DWORD /d 2 /f

echo "V-367421"
reg add "HKLM\SOFTWARE\Policies\Microsoft\TabletTip\1.7\" /v "PasswordSecurityState" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\TabletTip\1.7\" /v "PasswordSecurity" /t REG_DWORD /d 5 /f


echo "V-68847"
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel\" /v "DisableExceptionChainValidation" /t REG_DWORD /d 0 /f

echo "V-72753"
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\Wdigest\" /v "UseLogonCredential" /t REG_DWORD /d 0x00000000 /f


echo "V-73519"
reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters\" /v "SMB1" /t REG_DWORD /d 0x00000000 /f

echo "V-73523"
reg add "HKLM\SYSTEM\CurrentControlSet\Services\mrxsmb10\" /v "Start" /t REG_DWORD /d 0x00000004 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\" /v "DependOnService" /t REG_MULTI_SZ /d "Bowser" /f


echo "STIGs complete!"
