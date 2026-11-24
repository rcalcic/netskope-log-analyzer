<#
  Gera os pacotes do Netskope Log Analyzer em .\dist
    - NetskopeLogAnalyzer-<versao>-Setup.exe     instalador (requer Inno Setup 6)
    - NetskopeLogAnalyzer-<versao>-portatil.zip  executavel unico, sem instalar
    - SHA256SUMS.txt                             hashes para liberacao pelo TI

  Requisitos: .NET 8 SDK; Inno Setup 6 (opcional para o Setup.exe)
  Uso:  powershell -ExecutionPolicy Bypass -File .\build.ps1 [-RequireSetup] [-SkipTests]
#>
param([switch]$RequireSetup, [switch]$SkipTests)
$ErrorActionPreference = 'Stop'
$root    = $PSScriptRoot
$Version = (Get-Content (Join-Path $root 'VERSION') -Raw).Trim()
$dist    = Join-Path $root 'dist'
$publish = Join-Path $root 'publish'

Write-Host "Netskope Log Analyzer $Version" -ForegroundColor Cyan
foreach ($d in @($dist, $publish)) { if (Test-Path $d) { Remove-Item $d -Recurse -Force } }
New-Item -ItemType Directory -Path $dist | Out-Null

if (-not $SkipTests) {
  dotnet test (Join-Path $root 'tests\NetskopeLogAnalyzer.Tests\NetskopeLogAnalyzer.Tests.csproj') -c Release
  if ($LASTEXITCODE -ne 0) { throw 'Testes falharam' }
}

# Executavel unico, autocontido (nao exige .NET instalado)
dotnet publish (Join-Path $root 'src\NetskopeLogAnalyzer\NetskopeLogAnalyzer.csproj') -c Release -r win-x64 --self-contained true `
  -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true -p:EnableCompressionInSingleFile=true `
  -p:DebugType=none -p:Version=$Version -o $publish
if ($LASTEXITCODE -ne 0) { throw 'dotnet publish falhou' }
$exe = Join-Path $publish 'NetskopeLogAnalyzer.exe'

# Portatil
Compress-Archive -Path $exe -DestinationPath (Join-Path $dist "NetskopeLogAnalyzer-$Version-portatil.zip")

# Setup.exe (Inno Setup 6)
$iscc = @(
  "${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe",
  "$env:ProgramFiles\Inno Setup 6\ISCC.exe",
  "$env:LOCALAPPDATA\Programs\Inno Setup 6\ISCC.exe"
) | Where-Object { $_ -and (Test-Path $_) } | Select-Object -First 1
if ($iscc) {
  & $iscc "/DAppVersion=$Version" "/DSourceDir=$publish" "/DOutDir=$dist" (Join-Path $root 'installer\NetskopeLogAnalyzer.iss')
  if ($LASTEXITCODE -ne 0) { throw "ISCC falhou ($LASTEXITCODE)" }
} elseif ($RequireSetup) {
  throw 'Inno Setup 6 nao encontrado (ISCC.exe).'
} else {
  Write-Warning 'Inno Setup 6 nao encontrado: Setup.exe nao foi gerado. Instale em https://jrsoftware.org/isinfo.php'
}

# Hashes para liberacao (AppLocker/WDAC/Defender)
$lines = @()
$lines += "{0}  {1}" -f (Get-FileHash $exe -Algorithm SHA256).Hash, 'NetskopeLogAnalyzer.exe'
foreach ($f in Get-ChildItem $dist -File) { $lines += "{0}  {1}" -f (Get-FileHash $f.FullName -Algorithm SHA256).Hash, $f.Name }
Set-Content -Path (Join-Path $dist 'SHA256SUMS.txt') -Value $lines -Encoding ascii

Get-ChildItem $dist | Format-Table Name, Length -AutoSize
Get-Content (Join-Path $dist 'SHA256SUMS.txt')
