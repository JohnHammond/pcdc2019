@echo off

echo "Turning on PowerShell Transcription logging in directory C:\PS_transcription\ ..."
reg add HKLM\Software\Policies\Microsoft\Windows\Powershell\Transcription /v EnableTranscripting /t REG_DWORD /d 1 /f
reg add HKLM\Software\Policies\Microsoft\Windows\Powershell\Transcription /v OutputDirectory /t REG_SZ /d "C:/PS_transcription/" /f
reg add HKLM\Software\Policies\Microsoft\Windows\Powershell\Transcription /v EnableInvocationHeader /t REG_DWORD /d 1 /f
echo "Done!"