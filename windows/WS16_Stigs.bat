@echo off

﻿echo SRG-OS-000134-GPOS-00068
REG ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\CredUI\ /v EnumerateAdministrators /t REG_DWORD /d 0 /f

echo SRG-OS-000095-GPOS-00049
REG ADD HKLM\SOFTWARE\Policies\Microsoft\Windows\Personalization\ /v NoLockScreenSlideshow /t REG_DWORD /d 1 /f

echo SRG-OS-000134-GPOS-00068
REG ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 0 /f

echo SRG-OS-000095-GPOS-00049
REG ADD HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\Wdigest\ /v UseLogonCredential /t REG_DWORD /d 0 /f

echo SRG-OS-000480-GPOS-00227
REG ADD HKLM\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\ /v DisableIPSourceRouting /t REG_DWORD /d 2 /f

echo SRG-OS-000480-GPOS-00227
REG ADD HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\ /v DisableIPSourceRouting /t REG_DWORD /d 2 /f

echo SRG-OS-000480-GPOS-00227
REG ADD HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\ /v EnableICMPRedirect /t REG_DWORD /d 0 /f

echo SRG-OS-000420-GPOS-00186
REG ADD HKLM\SYSTEM\CurrentControlSet\Services\Netbt\Parameters\ /v NoNameReleaseOnDemand /t REG_DWORD /d 1 /f

echo SRG-OS-000480-GPOS-00227
REG ADD HKLM\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation\ /v AllowInsecureGuestAuth /t REG_DWORD /d 0 /f

echo SRG-OS-000480-GPOS-00227
REG ADD HKLM\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths\ /v "\\*\NETLOGON" /t REG_SZ /d 'RequireMutualAuthentication=1' /f

echo SRG-OS-000480-GPOS-00227
REG ADD HKLM\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths\ /v "\\*\NETLOGON" /t REG_SZ /d 'RequireIntegrity=1' /f

echo SRG-OS-000480-GPOS-00227
REG ADD HKLM\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths\ /v "\\*\SYSVOL" /t REG_SZ /d 'RequireMutualAuthentication=1' /f

echo SRG-OS-000480-GPOS-00227
REG ADD HKLM\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths\ /v "\\*\SYSVOL" /t REG_SZ /d 'RequireIntegrity=1' /f

echo SRG-OS-000042-GPOS-00020
REG ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit\ /v "ProcessCreationIncludeCmdLine_Enabled" /t REG_DWORD /d 1 /f

echo SRG-OS-000480-GPOS-00227
REG ADD HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard\ /v LsaCfgFlags /t REG_DWORD /d 2 /f

echo SRG-OS-000480-GPOS-00227
REG ADD HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard\ /v HypervisorEnforcedCodeIntegrity /d 2 /f

echo SRG-OS-000480-GPOS-00227
REG ADD HKLM\SYSTEM\CurrentControlSet\Policies\EarlyLaunch\ /v DriverLoadPolicy /t REG_DWORD /d 3 /f

echo SRG-OS-000480-GPOS-00227
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}\" /v NoGPOListChanges /t REG_DWORD /d 0 /f

echo SRG-OS-000095-GPOS-00049
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers\" /v DisableWebPnPDownload /t REG_DWORD /d 1 /f

echo SRG-OS-000095-GPOS-00049
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers\" /v DisableHTTPPrinting /t REG_DWORD /d 1 /f

echo SRG-OS-000095-GPOS-00049
REG ADD HKLM\SOFTWARE\Policies\Microsoft\Windows\System\ /v DontDisplayNetworkSelectionUI /t REG_DWORD /d 1 /f

echo SRG-OS-000095-GPOS-00049
REG ADD HKLM\SOFTWARE\Policies\Microsoft\Windows\System\ /v EnumerateLocalUsers /t REG_DWORD /d 0 /f

echo SRG-OS-000480-GPOS-00227
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51\" /v DCSettingIndex /t REG_DWORD /d 1 /f

echo SRG-OS-000480-GPOS-00227
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51\" /v ACSettingIndex /t REG_DWORD /d 1 /f

echo SRG-OS-000379-GPOS-00164
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Rpc\" /v RestrictRemoteClients /t REG_DWORD /d 1 /f

echo SRG-OS-000095-GPOS-00049
REG ADD HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat\ /v DisableInventory /t REG_DWORD /d 1 /f

echo SRG-OS-000368-GPOS-00154
REG ADD HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer\ /v NoAutoplayfornonVolume /t REG_DWORD /d 1 /f

echo SRG-OS-000368-GPOS-00154
REG ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\ /v NoAutorun /t REG_DWORD /d 1 /f

echo SRG-OS-000368-GPOS-00154
REG ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\policies\Explorer\ /v NoDriveTypeAutoRun /t REG_DWORD /d 255 /f

echo SRG-OS-000480-GPOS-00227
REG ADD HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection\ /v AllowTelemetry /t REG_DWORD /d 1 /f

echo SRG-OS-000341-GPOS-00132
REG ADD HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application\ /v MaxSize /t REG_DWORD /d 32768 /f

echo SRG-OS-000341-GPOS-00132
REG ADD HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security\ /v MaxSize /t REG_DWORD /d 196608 /f

echo SRG-OS-000341-GPOS-00132
REG ADD HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\System\ /v MaxSize /t REG_DWORD /d 32768 /f

echo SRG-OS-000095-GPOS-00049
REG ADD HKLM\SOFTWARE\Policies\Microsoft\Windows\System\ /v EnableSmartScreen /t REG_DWORD /d 1 /f

echo SRG-OS-000433-GPOS-00192
REG ADD HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer\ /v NoDataExecutionPrevention /t REG_DWORD /d 0 /f

echo SRG-OS-000480-GPOS-00227
REG ADD HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer\ /v NoHeapTerminationOnCorruption /t REG_DWORD /d 0 /f

echo SRG-OS-000480-GPOS-00227
REG ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\ /v PreXPSP2ShellProtocolBehavior /t REG_DWORD /d 0 /f

echo SRG-OS-000373-GPOS-00157
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\" /v DisablePasswordSaving /t REG_DWORD /d 1 /f

echo SRG-OS-000138-GPOS-00069
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\" /v fDisableCdm /t REG_DWORD /d 1 /f

echo SRG-OS-000373-GPOS-00157
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\" /v fPromptForPassword /t REG_DWORD /d 1 /f

echo SRG-OS-000250-GPOS-00093
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\" /v fEncryptRPCTraffic /t REG_DWORD /d 1 /f

echo SRG-OS-000250-GPOS-00093
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\" /v MinEncryptionLevel /t REG_DWORD /d 3 /f

echo SRG-OS-000480-GPOS-00227
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Internet Explorer\Feeds\" /v DisableEnclosureDownload /t REG_DWORD /d 1 /f

echo SRG-OS-000095-GPOS-00049
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Internet Explorer\Feeds\" /v AllowBasicAuthInClear /t REG_DWORD /d 0 /f

echo SRG-OS-000095-GPOS-00049
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search\" /v AllowIndexingEncryptedStoresOrItems /t REG_DWORD /d 0 /f

echo SRG-OS-000362-GPOS-00149
REG ADD HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer\ /v EnableUserControl /t REG_DWORD /d 0 /f

echo SRG-OS-000362-GPOS-00149
REG ADD HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer\ /v AlwaysInstallElevated /t REG_DWORD /d 0 /f

echo SRG-OS-000480-GPOS-00227
REG ADD HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer\ /v SafeForScripting /t REG_DWORD /d 0 /f

echo SRG-OS-000480-GPOS-00229
REG ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ /v DisableAutomaticRestartSignOn /t REG_DWORD /d 1 /f

echo SRG-OS-000042-GPOS-00020
REG ADD "HKLM\SOFTWARE\ Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging\" /v EnableScriptBlockLogging /t REG_DWORD /d 1 /f

echo SRG-OS-000125-GPOS-00065
REG ADD HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client\ /v AllowBasic /t REG_DWORD /d 0 /f

echo SRG-OS-000393-GPOS-00173
REG ADD HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client\ /v AllowUnencryptedTraffic /t REG_DWORD /d 0 /f

echo SRG-OS-000125-GPOS-00065
REG ADD HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client\ /v AllowDigest /t REG_DWORD /d 0 /f

echo SRG-OS-000125-GPOS-00065
REG ADD HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service\ /v AllowBasic /t REG_DWORD /d 0 /f

echo SRG-OS-000393-GPOS-00173
REG ADD HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service\ /v AllowUnencryptedTraffic /t REG_DWORD /d 0 /f

echo SRG-OS-000373-GPOS-00157
REG ADD HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service\ /v DisableRunAs /t REG_DWORD /d 1 /f

echo SRG-OS-000480-GPOS-00227
REG ADD HKLM\SYSTEM\CurrentControlSet\Control\Lsa\ /v LimitBlankPasswordUse /t REG_DWORD /d 1 /f

echo SRG-OS-000062-GPOS-00031
REG ADD HKLM\SYSTEM\CurrentControlSet\Control\Lsa\ /v SCENoApplyLegacyAuditPolicy /t REG_DWORD /d 1 /f

echo SRG-OS-000423-GPOS-00187
REG ADD HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Parameters\ /v LDAPServerIntegrity /t REG_DWORD /d 2 /f

echo SRG-OS-000480-GPOS-00227
REG ADD HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\ /v RefusePasswordChange /t REG_DWORD /d 0 /f

echo SRG-OS-000423-GPOS-00187
REG ADD HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\ /v RequireSignOrSeal /t REG_DWORD /d 1 /f

echo SRG-OS-000423-GPOS-00187
REG ADD HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\ /v SealSecureChannel /t REG_DWORD /d 1 /f

echo SRG-OS-000423-GPOS-00187
REG ADD HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\ /v SignSecureChannel /t REG_DWORD /d 1 /f

echo SRG-OS-000379-GPOS-00164
REG ADD HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\ /v DisablePasswordChange /t REG_DWORD /d 0 /f

echo SRG-OS-000480-GPOS-00227
REG ADD HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\ /v MaximumPasswordAge /t REG_DWORD /d 30 /f

echo SRG-OS-000423-GPOS-00187
REG ADD HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\ /v RequireStrongKey /t REG_DWORD /d 1 /f

echo SRG-OS-000029-GPOS-00010
REG ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ /v InactivityTimeoutSecs /t REG_DWOWRD /d 900 /f

echo SRG-OS-000023-GPOS-00006
REG ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ /v LegalNoticeText /t REG_SZ /d 'You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only.' /f

echo SRG-OS-000023-GPOS-00006
REG ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ /v LegalNoticeCaption /t REG_SZ /d 'DoD Notice and Consent Banner' /f

echo SRG-OS-000480-GPOS-00227
REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\" /v CachedLogonsCount /t REG_SZ /d '4' /f

echo SRG-OS-000423-GPOS-00187
REG ADD HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters\ /v RequireSecuritySignature /t REG_DWORD /d 1 /f

echo SRG-OS-000423-GPOS-00187
REG ADD HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters\ /v EnableSecuritySignature /t REG_DWORD /d 1 /f

echo SRG-OS-000074-GPOS-00042
REG ADD HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters\ /v EnablePlainTextPassword /t REG_DWORD /d 0 /f

echo SRG-OS-000163-GPOS-00072
REG ADD HKLM\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters\ /v autodisconnect /t REG_DWORD /d 15 /f

echo SRG-OS-000423-GPOS-00187
REG ADD HKLM\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters\ /v RequireSecuritySignature /t REG_DWORD /d 1 /f

echo SRG-OS-000423-GPOS-00187
REG ADD HKLM\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters\ /v EnableSecuritySignature /t REG_DWORD /d 1 /f

echo SRG-OS-000480-GPOS-00227
REG ADD HKLM\SYSTEM\CurrentControlSet\Control\Lsa\ /v RestrictAnonymousSAM /t REG_DWORD /d 1 /f

echo SRG-OS-000138-GPOS-00069
REG ADD HKLM\SYSTEM\CurrentControlSet\Control\Lsa\ /v RestrictAnonymous /t REG_DWORD /d 1 /f

echo SRG-OS-000373-GPOS-00157
REG ADD HKLM\SYSTEM\CurrentControlSet\Control\Lsa\ /v DisableDomainCreds /t REG_DWORD /d 1 /f

echo SRG-OS-000480-GPOS-00227
REG ADD HKLM\SYSTEM\CurrentControlSet\Control\Lsa\ /v EveryoneIncludesAnonymous /t REG_DWORD /d 0 /f

echo SRG-OS-000138-GPOS-00069
REG ADD HKLM\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters\ /v RestrictNullSessAccess /t REG_DWORD /d 1 /f

echo SRG-OS-000324-GPOS-00125
REG ADD HKLM\SYSTEM\CurrentControlSet\Control\Lsa\ /v RestrictRemoteSAM /t REG_SZ /d 'A;;RC;;;BA' /f

echo SRG-OS-000480-GPOS-00227
REG ADD HKLM\SYSTEM\CurrentControlSet\Control\LSA\ /v UseMachineId /t REG_DWORD /d 1 /f

echo SRG-OS-000480-GPOS-00227
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\LSA\MSV1_0\" /v allownullsessionfallback /t REG_DWORD /d 0 /f

echo SRG-OS-000480-GPOS-00227
REG ADD HKLM\SYSTEM\CurrentControlSet\Control\LSA\pku2u\ /v AllowOnlineID /t REG_DWORD /d 0 /f

echo SRG-OS-000120-GPOS-00061
REG ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters\ /v SupportedEncryptionTypes /t REG_DWORD /d 2147483640 /f

echo SRG-OS-000073-GPOS-00041
REG ADD HKLM\SYSTEM\CurrentControlSet\Control\Lsa\ /v NoLMHash /t REG_DWORD /d 1 /f

echo SRG-OS-000480-GPOS-00227
REG ADD HKLM\SYSTEM\CurrentControlSet\Control\Lsa\ /v LmCompatibilityLevel /t REG_DWORD /d 5 /f

echo SRG-OS-000480-GPOS-00227
REG ADD HKLM\SYSTEM\CurrentControlSet\Services\LDAP\ /v LDAPClientIntegrity /t REG_DWORD /d 1 /f

echo SRG-OS-000480-GPOS-00227
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0\" /v NTLMMinClientSec /t REG_DWORD /d 537395200 /f

echo SRG-OS-000480-GPOS-00227
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0\" /v NTLMMinServerSec /t REG_DWORD /d 537395200 /f

echo SRG-OS-000067-GPOS-00035
REG ADD HKLM\SOFTWARE\Policies\Microsoft\Cryptography\ /v ForceKeyProtection /t REG_DWORD /d 2 /f

echo SRG-OS-000033-GPOS-00014
REG ADD HKLM\SYSTEM\CurrentControlSet\Control\Lsa\FIPSAlgorithmPolicy\ /v Enabled /t REG_DWORD /d 1 /f

echo SRG-OS-000480-GPOS-00227
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Kernel\" /v ObCaseInsensitive /t REG_DWORD /d 1 /f

echo SRG-OS-000480-GPOS-00227
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\" /v ProtectionMode /t REG_DWORD /d 1 /f

echo SRG-OS-000373-GPOS-00157
REG ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ /v FilterAdministratorToken /t REG_DWORD /d 1 /f

echo SRG-OS-000134-GPOS-00068
REG ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ /v EnableUIADesktopToggle /t REG_DWORD /d 0 /f

echo SRG-OS-000134-GPOS-00068
REG ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ /v ConsentPromptBehaviorAdmin /t REG_DWORD /d 2 /f

echo SRG-OS-000373-GPOS-00157
REG ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ /v ConsentPromptBehaviorUser /t REG_DWORD /d 0 /f

echo SRG-OS-000134-GPOS-00068
REG ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ /v EnableInstallerDetection /t REG_DWORD /d 1 /f

echo SRG-OS-000134-GPOS-00068
REG ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ /v EnableSecureUIAPaths /t REG_DWORD /d 1 /f

echo SRG-OS-000373-GPOS-00157
REG ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ /v EnableLUA /t REG_DWORD /d 1 /f

echo SRG-OS-000134-GPOS-00068
REG ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ /v EnableVirtualization /t REG_DWORD /d 1 /f

echo SRG-OS-000031-GPOS-00012
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\Control Panel\Desktop\" /v ScreenSaveActive /t REG_SZ /d '1' /f

echo SRG-OS-000028-GPOS-00009
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\Control Panel\Desktop\" /v ScreenSaverIsSecure /t REG_SZ /d '1' /f

echo SRG-OS-000480-GPOS-00227
REG ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments\ /v SaveZoneInformation /t REG_DWORD /d 2 /f

echo SRG-OS-000480-GPOS-00227
REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\" /v scremoveoption /t REG_SZ /d 1 /f

echo SRG-OS-000095-GPOS-00049
REG ADD HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters\ /v SMB1 /t REG_DWORD /d 0 /f

echo SRG-OS-000095-GPOS-00049
REG ADD HKLM\SYSTEM\CurrentControlSet\Services\mrxsmb10\ /v Start /t REG_DWORD /d 4 /f

echo "STIGs complete!"
