# Desinstalador do Netskope Log Analyzer
$AppName   = 'Netskope Log Analyzer'
$AppId     = 'NetskopeLogAnalyzer'
$Dest      = Join-Path $env:LOCALAPPDATA $AppId
$StartMenu = Join-Path ([Environment]::GetFolderPath('Programs')) "$AppName.lnk"
$Desktop   = Join-Path ([Environment]::GetFolderPath('Desktop')) "$AppName.lnk"
$UninstKey = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\$AppId"

foreach ($p in @($StartMenu, $Desktop)) { if (Test-Path $p) { Remove-Item $p -Force } }
if (Test-Path $UninstKey) { Remove-Item $UninstKey -Recurse -Force }
if (Test-Path $Dest) {
  # o próprio script está dentro da pasta: remove a pasta depois que ele terminar
  Start-Process -WindowStyle Hidden -FilePath cmd.exe -ArgumentList "/c timeout /t 2 >nul & rmdir /s /q `"$Dest`""
}
Write-Host "$AppName removido." -ForegroundColor Green
