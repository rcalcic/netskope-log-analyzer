<#
  Gera os pacotes do Netskope Log Analyzer em .\dist
    - NetskopeLogAnalyzer-<versao>-Setup.exe     (instalador; requer Inno Setup 6)
    - NetskopeLogAnalyzer-<versao>-Windows.zip   (instalador por script, sem .exe)
    - NetskopeLogAnalyzer-<versao>-portatil.html (abre direto no navegador)

  Uso:  powershell -ExecutionPolicy Bypass -File .\build.ps1 [-RequireSetup]
#>
param([switch]$RequireSetup)
$ErrorActionPreference = 'Stop'
$root    = $PSScriptRoot
$Version = (Get-Content (Join-Path $root 'VERSION') -Raw).Trim()
$dist    = Join-Path $root 'dist'
$stage   = Join-Path $root 'build'
$utf8    = New-Object System.Text.UTF8Encoding($false)
$utf8bom = New-Object System.Text.UTF8Encoding($true)

Write-Host "Netskope Log Analyzer $Version" -ForegroundColor Cyan
foreach ($d in @($dist, $stage)) { if (Test-Path $d) { Remove-Item $d -Recurse -Force }; New-Item -ItemType Directory -Path $d | Out-Null }

# 1. App: injeta favicon e versao
$app = Join-Path $stage 'app'
New-Item -ItemType Directory -Path $app | Out-Null
$fav  = [Convert]::ToBase64String([IO.File]::ReadAllBytes((Join-Path $root 'assets\icon-64.png')))
$html = [IO.File]::ReadAllText((Join-Path $root 'src\index.html'), $utf8)
$html = $html.Replace('<title>Netskope Log Analyzer</title>', "<title>Netskope Log Analyzer</title>`n<link rel=`"icon`" type=`"image/png`" href=`"data:image/png;base64,$fav`">")
$html = $html.Replace('__VERSION__', $Version)
[IO.File]::WriteAllText((Join-Path $app 'index.html'), $html, $utf8)
Copy-Item (Join-Path $root 'assets\icon.ico') (Join-Path $app 'app.ico')

# 2. Versao portatil
Copy-Item (Join-Path $app 'index.html') (Join-Path $dist "NetskopeLogAnalyzer-$Version-portatil.html")

# 3. Zip com instalador por script (PowerShell 5.1 exige UTF-8 com BOM)
$zdir = Join-Path $stage "NetskopeLogAnalyzer-$Version"
New-Item -ItemType Directory -Path $zdir | Out-Null
Copy-Item $app (Join-Path $zdir 'app') -Recurse
foreach ($f in 'instalar.ps1', 'desinstalar.ps1', 'LEIA-ME.txt') {
  $t = [IO.File]::ReadAllText((Join-Path $root "packaging\windows\$f"), $utf8).Replace('__VERSION__', $Version).Replace("`r`n", "`n").Replace("`n", "`r`n")
  [IO.File]::WriteAllText((Join-Path $zdir $f), $t, $utf8bom)
}
Copy-Item (Join-Path $root 'packaging\windows\*.cmd') $zdir
Compress-Archive -Path $zdir -DestinationPath (Join-Path $dist "NetskopeLogAnalyzer-$Version-Windows.zip")

# 4. Setup.exe (Inno Setup 6)
$iscc = @(
  "${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe",
  "$env:ProgramFiles\Inno Setup 6\ISCC.exe",
  "$env:LOCALAPPDATA\Programs\Inno Setup 6\ISCC.exe"
) | Where-Object { $_ -and (Test-Path $_) } | Select-Object -First 1
if (-not $iscc) { $c = Get-Command iscc.exe -ErrorAction SilentlyContinue; if ($c) { $iscc = $c.Source } }
if ($iscc) {
  & $iscc "/DAppVersion=$Version" "/DSourceDir=$app" "/DOutDir=$dist" (Join-Path $root 'installer\NetskopeLogAnalyzer.iss')
  if ($LASTEXITCODE -ne 0) { throw "ISCC falhou ($LASTEXITCODE)" }
} elseif ($RequireSetup) {
  throw 'Inno Setup 6 nao encontrado (ISCC.exe).'
} else {
  Write-Warning 'Inno Setup 6 nao encontrado: Setup.exe nao foi gerado. Instale em https://jrsoftware.org/isinfo.php'
}

Remove-Item $stage -Recurse -Force
Get-ChildItem $dist | Format-Table Name, Length -AutoSize
