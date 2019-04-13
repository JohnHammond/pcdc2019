﻿@echo off

echo WN10-00-000010
REG ADD HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer\ /v EnableUserControl /t REG_DWORD /d 0 /f

echo WN10-CC-000315
REG ADD HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer\ /v AlwaysInstallElevated /t REG_DWORD /d 0 /f

echo WN10-CC-000320
REG ADD HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer\ /v SafeForScripting /t REG_DWORD /d 0 /f

echo WN10-CC-000325
REG ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ /v DisableAutomaticRestartSignOn /t REG_DWORD /d 1 /f

echo WN10-CC-000330
REG ADD HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client\ /v AllowBasic /t REG_DWORD /d 0 /f

echo WN10-CC-000335
REG ADD HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client\ /v AllowUnencryptedTraffic /t REG_DWORD /d 0 /f

echo WN10-CC-000340
REG ADD HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client\ /v AllowDigest /t REG_DWORD /d 0 /f

echo WN10-CC-000345
REG ADD HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service\ /v AllowBasic /t REG_DWORD /d 0 /f

echo WN10-CC-000350
REG ADD HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service\ /v AllowUnencryptedTraffic /t REG_DWORD /d 0 /f

echo WN10-CC-000355
REG ADD HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service\ /v DisableRunAs /t REG_DWORD /d 1 /f

echo WN10-AU-000500
REG ADD HKLM\Software\Policies\Microsoft\Windows\EventLog\Application\ /v MaxSize /t REG_DWORD /d 32768 /f

echo WN10-AU-000505
REG ADD HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security\ /v MaxSize /t REG_DWORD /d 1024000 /f

echo WN10-AU-000510
REG ADD HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\System\ /v MaxSize /t REG_DWORD /d 32768 /f

echo WN10-CC-000005
REG ADD HKLM\SOFTWARE\Policies\Microsoft\Windows\Personalization\ /v NoLockScreenCamera /t REG_DWORD /d 1 /f

echo WN10-CC-000010
REG ADD HKLM\SOFTWARE\Policies\Microsoft\Windows\Personalization\ /v NoLockScreenSlideshow /t REG_DWORD /d 1 /f

echo WN10-CC-000020
REG ADD HKLM\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\ /v DisableIpSourceRouting /t REG_DWORD /d 2 /f

echo WN10-CC-000025
REG ADD HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\ /v DisableIPSourceRouting /t REG_DWORD /d 2 /f

echo WN10-CC-000030
REG ADD HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\ /v EnableICMPRedirect /t REG_DWORD /d 0 /f

echo WN10-CC-000035
REG ADD HKLM\SYSTEM\CurrentControlSet\Services\Netbt\Parameters\ /v NoNameReleaseOnDemand /t REG_DWORD /d 1 /f

echo WN10-CC-000040
REG ADD HKLM\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation\ /v AllowInsecureGuestAuth /t REG_DWORD /d 0 /f

echo WN10-CC-000050
REG ADD HKLM\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths\ /v \\*\NETLOGON /t REG_SZ /d 1 /f

echo WN10-CC-000050
REG ADD HKLM\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths\ /v \\*\SYSVOL /t REG_SZ /d 1 /f

echo WN10-CC-000055
REG ADD HKLM\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy\ /v fMinimizeCorrections /t REG_DWORD /d 1 /f

echo WN10-CC-000060
REG ADD HKLM\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy\ /v fBlockNonDomain /t REG_DWORD /d 1 /f

echo WN10-CC-000065
REG ADD HKLM\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config\ /v AutoConnectAllowedOEM /t REG_DWORD /d 0 /f

echo WN10-CC-000037
REG ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 0 /f

echo WN10-CC-000085
REG ADD HKLM\SYSTEM\CurrentControlSet\Policies\EarlyLaunch\ /v DriverLoadPolicy /t REG_DWORD /d 3 /f

echo WN10-CC-000090
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}" /v NoGPOListChanges /t REG_DWORD /d 0 /f

echo WN10-CC-000100
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers\" /v DisableWebPnPDownload /t REG_DWORD /d 1 /f

echo WN10-CC-000015
REG ADD HKLM\SYSTEM\CurrentControlSet\Control\Lsa\ /v LimitBlankPasswordUse /t REG_DWORD /d 1 /f

echo WN10-CC-000105
REG ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\ /v NoWebServices /t REG_DWORD /d 1 /f

echo WN10-CC-000110
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers" /v DisableHTTPPrinting /t REG_DWORD /d 1 /f

echo WN10-CC-000115
REG ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters\ /v DevicePKInitEnabled /t REG_DWORD /d 1 /f

echo WN10-CC-000120
REG ADD HKLM\SOFTWARE\Policies\Microsoft\Windows\System\ /v DontDisplayNetworkSelectionUI /t REG_DWORD /d 1 /f

echo WN10-CC-000130
REG ADD HKLM\SOFTWARE\Policies\Microsoft\Windows\System\ /v EnumerateLocalUsers /t REG_DWORD /d 1 /f

echo WN10-SO-000030
REG ADD HKLM\SYSTEM\CurrentControlSet\Control\Lsa\ /v SCENoApplyLegacyAuditPolicy /t REG_DWORD /d 1 /f

echo WN10-SO-000035
REG ADD HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\ /v RequireSignOrSeal /t REG_DWORD /d 1 /f

echo WN10-SO-000040
REG ADD HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\ /v SealSecureChannel /t REG_DWORD /d 1 /f

echo WN10-CC-000145
REG ADD HKLM\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51\ /v DCSettingIndex /t REG_DWORD /d 1 /f

echo WN10-SO-000045
REG ADD HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\ /v SignSecureChannel /t REG_DWORD /d 1 /f

echo WN10-CC-000150
REG ADD HKLM\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51\ /v ACSettingIndex /t REG_DWORD /d 1 /f

echo WN10-CC-000155
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\" /v fAllowToGetHelp /t REG_DWORD /d 0 /f

echo wN10-SO-000050
REG ADD HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\ /v DisablePasswordChange /t REG_DWORD /d 0 /f

echo WN10-CC-000165
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Rpc\" /v RestrictRemoteClients /t REG_DWORD /d 1 /f

echo WN10-CC-000170
REG ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ /v MSAOptional /t REG_DWORD /d 1 /f

echo WN10-SO-000055
REG ADD HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\ /v MaximumPasswordAge /t REG_DWORD /d 30 /f

echo WN10-CC-000175
REG ADD HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCombat\ /v DisableInventory /t REG_DWORD /d 1 /f

echo WN10-SO-000060
REG ADD HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\ /v RequireStrongKey /t REG_DWORD /d 1 /f

echo WN10-CC-000180
REG ADD HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer\ /v NoAutoplayfornonVolume /t REG_DWORD /d 1 /f

echo WN10-SO-000070
REG ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ /v InactivityTimeoutSecs /t REG_DWORD /d 900 /f

echo WN10-CC-000185
REG ADD HKLM\Microsoft\Windows\CurrentVersion\Policies\Explorer\ /v NoAutorun /t REG_DWORD /d 1 /f

echo WN10-CC-000190
REG ADD HKLM\Microsoft\Windows\CurrentVersion\policies\Explorer\ /v NoDriveTypeAutoRun /t REG_DWORD /d 255 /f

echo WN10-SO-000075
REG ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ /v LegalNoticeText /t REG_SZ /d "You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only." /f

echo WN10-CC-000195
REG ADD HKLM\SOFTWARE\Policies\Microsoft\Biometrics\FacialFeatures\ /v EnhancedAntiSpoofing /t REG_DWORD /d 1 /f

echo WN10-CC-000200
REG ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\CredUI\ /v EnumerateAdministrators /t REG_DWORD /d 0 /f

echo WN10-SO-000080
REG ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ /v LegalNoticeCaption /t REG_SZ /d "DoD Notice and Consent Banner" /f

echo WN10-CC-000205
REG ADD HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection\ /v AllowTelemetry /t REG_DWORD /d 0 /f

echo WN10-CC-000210
REG ADD HKLM\SOFTWARE\Policies\Microsoft\Windows\System\ /v EnableSmartScreen /t REG_DWORD /d 1 /f

echo WN10-SO-000084
REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\" /v CachedLogonsCount /t REG_SZ /d 9 /f

echo WN10-CC-000215
REG ADD HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer\ /v NoDataExecutionPrevention /t ReG_DWORD /d 0 /f

echo WN10-CC-000220
REG ADD HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer\ /v NoHeapTerminationOnCorruption /t REG_DWORD /d 0 /f

echo WN10-CC-000225
REG ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\ /v PreXPSP2ShellProtocolBehavior /t REG_DWORD /d 0 /f

echo WN10-SO-000095
REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\" /v SCRemoveOption /t REG_SZ /d 1 /f

echo WN10-CC-000230
REG ADD HKLM\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter\ /v PreventOverride /t REG_DWORD /d 1 /f

echo WN10-CC-000235
REG ADD HKLM\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter\ /v PreventOverrideAppRepUnknown /t REG_DWORD /d 1 /f

echo WN10-SO-000100
REG ADD HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters\ /v RequireSecuritySignature /t REG_DWORD /d 1 /f

echo WN10-CC-000240
REG ADD HKLM\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Main\ /v AllowInPrivate /t REG_DWORD /d 0 /f

echo WN10-SO-000105
REG ADD HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters\ /v EnableSecuritySignature /t REG_DWORD /d 1 /f

echo WN10-CC-000245
REG ADD HKLM\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Main\ /v "FormSuggest Passwords" /t REG_SZ /d 'no' /f

echo WN10-SO-000110
REG ADD HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters\ /v EnablePlainTextPassword /t REG_DWORD /d 0 /f

echo WN10-CC-000250
REG ADD HKLM\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter\ /v EnabledV9 /t REG_DWORD /d 1 /f

echo WN10-SO-000115
REG ADD HKLM\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters\ /v autodisconnect /t REG_DWORD /d 14 /f

echo WN10-CC-000255
REG ADD HKLM\SOFTWARE\Policies\Microsoft\PassportForWork\ /v RequireSecurityDevice /t REG_DWORD /d 1 /f

echo WN10-SO-000120
REG ADD HKLM\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters\ /v RequireSecuritySignature /t REG_DWORD /d 1 /f

echo WN10-CC-000260
REG ADD HKLM\SOFTWARE\Policies\Microsoft\PassportForWork\PINComplexity\ /v MinimumPINLength /t REG_DWORD /d 6 /f

echo WN10-SO-000125
REG ADD HKLM\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters\ /v EnableSecuritySignature /t REG_DWORD /d 1 /f

echo WN10-CC-000265
REG ADD HKLM\SOFTWARE\Policies\Microsoft\Windows\OneDrive\ /v DisableFileSyncNGSC /t REG_DWORD /d 1 /f

echo WN10-CC-000270
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\" /v DisablePasswordSaving /t REG_DWORD /d 1 /f

echo WN10-CC-000275
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\" /v fDisableCdm /t REG_DWORD /d 1 /f

echo WN10-CC-000280
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\" /v fPromptForPassword /t REG_DWORD /d 1 /f

echo WN10-CC-000285
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\" /v fEncryptRPCTraffic /t REG_DWORD /d 1 /f

echo WN10-CC-000290
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\" /v MinEncryptionLevel /t REG_DWORD /d 3 /f

echo WN10-CC-000295
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Internet Explorer\Feeds\" /v DisableEnclosureDownload /t REG_DWORD /d 1 /f

echo WN10-SO-000145
REG ADD HKLM\SYSTEM\CurrentControlSet\Control\Lsa\ /v RestrictAnonymousSAM /t REG_DWORD /d 1 /f

echo WN10-CC-000300
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Internet Explorer\Feeds\" /v AllowBasicAuthInClear /t REG_DWORD /d 0 /f

echo WN10-SO-000150
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search\" /v AllowIndexingEncryptedStoresOrItems /t REG_DWORD /d 0 /f

echo WN10-SO-000155
REG ADD HKLM\SYSTEM\CurrentControlSet\Control\Lsa\ /v DisableDomainCreds /t REG_DWORD /d 1 /f

echo WN10-SO-000160
REG ADD HKLM\SYSTEM\CurrentControlSet\Control\Lsa\ /v EveryoneIncludesAnonymous /t REG_DWORD /d 0 /f

echo WN10-SO-000165
REG ADD HKLM\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters\ /v RestrictNullSessAccess /t REG_DWORD /d 1 /f

echo WN10-SO-000175
REG ADD HKLM\SYSTEM\CurrentControlSet\Control\LSA\ /v UseMachineId /t REG_DWORD /d 1 /f

echo WN10-SO-000180
REG ADD HKLM\SYSTEM\CurrentControlSet\Control\LSA\MSV1_0\ /v allownullsessionfallback /t REG_DWORD /d 0 /f

echo WN10-SO-000185
REG ADD HKLM\SYSTEM\CurrentControlSet\Control\LSA\pku2u\ /v AllowOnlineID /t REG_DWORD /d 0 /f

echo WN10-SO-000190
REG ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters\ /v SupportedEncryptionTypes /t REG_DWORD /d 2147483640 /f

echo WN10-SO-000195
REG ADD HKLM\SYSTEM\CurrentControlSet\Control\Lsa\ /v NoLMHash /t REG_DWORD /d 1 /f

echo WN10-SO-000205
REG ADD HKLM\SYSTEM\CurrentControlSet\Control\Lsa\ /v LmCompatibilityLevel /t REG_DWORD /d 5 /f

echo WN10-SO-000210
REG ADD HKLM\SYSTEM\CurrentControlSet\Services\LDAP\ /v LDAPClientIntegrity /t REG_DWORD /d 1 /f

echo WN10-SO-000215
REG ADD HKLM\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0\ /v NTLMMinClientSec /t REG_DWORD /d 537395200 /f

echo WN10-SO-000220
REG ADD HKLM\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0\ /v NTLMMinServerSec /t REG_DWORD /d 537395200 /f

echo WN10-SO-000230
REG ADD HKLM\SYSTEM\CurrentControlSet\Control\Lsa\FIPSAlgorithmPolicy\ /v Enabled /t REG_DWORD /d 1 /f

echo WN10-SO-000240
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\" /v ProtectionMode /t REG_DWORD /d 1 /f

echo WN10-SO-000245
REG ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ /v FilterAdministratorToken /t REG_DWORD /d 1 /f

echo WN10-SO-000250
REG ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ /v ConsentPromptBehaviorAdmin /t REG_DWORD /d 2 /f

echo WN10-SO-000255
REG ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ /v ConsentPromptBehaviorUser /t REG_DWORD /d 0 /f

echo WN10-SO-000260
REG ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ /v EnableInstallerDetection /t REG_DWORD /d 1 /f

echo WN10-SO-000265
REG ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ /v EnableSecureUIAPaths /t REG_DWORD /d 1 /f

echo WN10-SO-000270
REG ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ /v EnableLUA /t REG_DWORD /d 1 /f

echo WN10-SO-000275
REG ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ /v EnableVirtualization /t REG_DWORD /d 1 /f

echo WN10-UC-000015
REG ADD HKCU\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications\ /v NoToastApplicationNotificationOnLockScreen /t REG_DWORD /d 1 /f

echo WN10-US-000020
REG ADD HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments\ /v SaveZoneInformation /t REG_DWORD /d 2 /f

echo WN10-CC-000206
REG ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config\ /v DODownloadMode /t REG_DWORD /d 99 /f

echo WN10-CC-000066
REG ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit\ /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f

echo WN10-CC-000326
REG ADD HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging\ /v EnableScriptBlockLogging /t REG_DWORD /d 1 /f

echo WN10-00-000150
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel\" /v DisableExceptionChainValidation /t REG_DWORD /d 0 /f

echo WN10-CC-000038
REG ADD HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\Wdigest\ /v UseLogonCredential /t REG_DWORD /d 0 /f

echo WN10-CC-000044
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\Network Connections\" /v NC_ShowSharedAccessUI /t REG_DWORD /d 0 /f

echo WN10-SO-000167
REG ADD HKLM\SYSTEM\CurrentControlSet\Control\Lsa\ /v RestrictRemoteSAM /t REG_SZ /d 'A;;RC;;;BA' /f

echo WN10-CC-000197
REG ADD HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent\ /v DisableWindowsConsumerFeatures /t REG_DWORD /d 1 /f

echo WN10-CC-000039
REG ADD HKLM\SOFTWARE\Classes\batfile\shell\runasuser\ /v SuppressionPolicy /t REG_DWORD /d 4096 /f

echo WN10-CC-000039
REG ADD HKLM\SOFTWARE\Classes\cmdfile\shell\runasuser\ /v SuppressionPolicy /t REG_DWORD /d 4096 /f

echo WN10-CC-000039
REG ADD HKLM\SOFTWARE\Classes\exefile\shell\runasuser\ /v SuppressionPolicy /t REG_DWORD /d 4096 /f

echo WN10-CC-000039
REG ADD HKLM\SOFTWARE\Classes\mscfile\shell\runasuser\ /v SuppressionPolicy /t REG_DWORD /d 4096 /f

echo WN10-CC-000052
REG ADD HKLM\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002\ /v EccCurves /t REG_MULTI_SZ /d 'NistP384 NistP256' /f

echo WN10-CC-000228
REG ADD HKLM\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Privacy\ /v ClearBrowsingHistoryOnExit /t REG_DWORD /d 0 /f

echo WN10-CC-000252
REG ADD HKLM\SOFTWARE\Policies\Microsoft\Windows\GameDVR\ /v AllowGameDVR /t REG_DWORD /d 0 /f

echo WN10-CC-000068
REG ADD HKLM\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation\ /v AllowProtectedCreds /t REG_DWORD /d 1 /f

echo WN10-00-000165
REG ADD HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters\ /v SMB1 /t REG_DWORD /d 0 /f

echo WN10-00-000170
REG ADD HKLM\SYSTEM\CurrentControlSet\Services\mrxsmb10\ /v Start /t REG_DWORD /d 4 /f

echo WN10-EP-000010
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\App and Browser protection\" /v DisallowExploitProtectionOverride /t REG_DWORD /d 1 /f

echo "STIGs complete!"
