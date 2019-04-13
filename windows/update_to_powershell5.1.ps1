
# Download the .NET Framework 4.5.2 
(New-Object System.Net.WebClient).DownloadFile("https://download.microsoft.com/download/E/2/1/E21644B5-2DF2-47C2-91BD-63C560427900/NDP452-KB2901907-x86-x64-AllOS-ENU.exe", "dotnet4.5.2.exe")

./dotnet4.5.2.exe /norestart /passive 

# Download Windows Management Framework 5.1 as a ZIP file
(New-Object System.Net.WebClient).DownloadFile("https://download.microsoft.com/download/6/F/5/6F5FF66C-6775-42B0-86C4-47D41F2DA187/Win7AndW2K8R2-KB3191566-x64.zip", "wmf5.1.zip")


# Shamelessly stolen...

[Reflection.Assembly]::LoadWithPartialName("System.IO.Compression.Filesystem")
[Io.Compression.ZipFile]::ExtractToDirectory("wmf5.1.zip", ".")


