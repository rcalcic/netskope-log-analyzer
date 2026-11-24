# Instalador do Netskope Log Analyzer (por usuário, não exige administrador)
$ErrorActionPreference = 'Stop'
$AppName    = 'Netskope Log Analyzer'
$AppId      = 'NetskopeLogAnalyzer'
$Version    = '__VERSION__'
$Src        = Join-Path $PSScriptRoot 'app'
$Dest       = Join-Path $env:LOCALAPPDATA $AppId
$StartMenu  = Join-Path ([Environment]::GetFolderPath('Programs')) "$AppName.lnk"
$Desktop    = Join-Path ([Environment]::GetFolderPath('Desktop')) "$AppName.lnk"
$UninstKey  = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\$AppId"

Write-Host ""
Write-Host "  $AppName $Version" -ForegroundColor Cyan
Write-Host "  Instalando em: $Dest"
Write-Host ""

if (-not (Test-Path (Join-Path $Src 'index.html'))) { throw "Pasta 'app' não encontrada ao lado do instalador. Extraia o .zip inteiro antes de instalar." }

# 1. Copiar arquivos
New-Item -ItemType Directory -Force -Path $Dest | Out-Null
Copy-Item -Path (Join-Path $Src '*') -Destination $Dest -Recurse -Force
Copy-Item -Path (Join-Path $PSScriptRoot 'desinstalar.ps1') -Destination $Dest -Force
Get-ChildItem -Path $Dest -Recurse | Unblock-File -ErrorAction SilentlyContinue

# 2. Escolher o navegador para abrir em modo aplicativo (janela própria, sem barra de endereço)
$Html = Join-Path $Dest 'index.html'
$Url  = ([System.Uri]$Html).AbsoluteUri
$Candidates = @(
  "${env:ProgramFiles(x86)}\Microsoft\Edge\Application\msedge.exe",
  "$env:ProgramFiles\Microsoft\Edge\Application\msedge.exe",
  "$env:ProgramFiles\Google\Chrome\Application\chrome.exe",
  "${env:ProgramFiles(x86)}\Google\Chrome\Application\chrome.exe",
  "$env:LOCALAPPDATA\Google\Chrome\Application\chrome.exe"
)
$Browser = $Candidates | Where-Object { $_ -and (Test-Path $_) } | Select-Object -First 1

# 3. Criar atalhos
$Shell = New-Object -ComObject WScript.Shell
foreach ($lnkPath in @($StartMenu, $Desktop)) {
  $lnk = $Shell.CreateShortcut($lnkPath)
  if ($Browser) {
    $lnk.TargetPath = $Browser
    $lnk.Arguments  = "--app=`"$Url`" --window-size=1360,900"
  } else {
    $lnk.TargetPath = $Html
  }
  $lnk.WorkingDirectory = $Dest
  $lnk.IconLocation     = (Join-Path $Dest 'app.ico') + ',0'
  $lnk.Description      = 'Analisa pacotes de logs do Netskope Client e mostra falhas e como resolvê-las'
  $lnk.Save()
}

# 4. Registrar em "Aplicativos instalados" para desinstalação pelo Windows
New-Item -Path $UninstKey -Force | Out-Null
$Uninst = "powershell.exe -NoProfile -ExecutionPolicy Bypass -File `"$Dest\desinstalar.ps1`""
Set-ItemProperty -Path $UninstKey -Name DisplayName     -Value $AppName
Set-ItemProperty -Path $UninstKey -Name DisplayVersion  -Value $Version
Set-ItemProperty -Path $UninstKey -Name Publisher       -Value 'Suporte de TI'
Set-ItemProperty -Path $UninstKey -Name DisplayIcon     -Value (Join-Path $Dest 'app.ico')
Set-ItemProperty -Path $UninstKey -Name InstallLocation -Value $Dest
Set-ItemProperty -Path $UninstKey -Name UninstallString -Value $Uninst
Set-ItemProperty -Path $UninstKey -Name NoModify        -Value 1 -Type DWord
Set-ItemProperty -Path $UninstKey -Name NoRepair        -Value 1 -Type DWord
Set-ItemProperty -Path $UninstKey -Name EstimatedSize   -Value ([int]((Get-ChildItem $Dest -Recurse | Measure-Object Length -Sum).Sum / 1KB)) -Type DWord

Write-Host "  Instalado com sucesso." -ForegroundColor Green
if (-not $Browser) { Write-Host "  Edge/Chrome não encontrados: o app abrirá no navegador padrão." -ForegroundColor Yellow }
Write-Host "  Atalhos criados no Menu Iniciar e na Área de Trabalho."
Write-Host ""

if ($Browser) { Start-Process -FilePath $Browser -ArgumentList "--app=`"$Url`"","--window-size=1360,900" } else { Start-Process $Html }
