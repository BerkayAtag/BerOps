<#
.SYNOPSIS
  Automation BER Windows MSI paketlerini (ajan ve sunucu) WiX Toolset v5 ile üretir.

.EXAMPLE
  ./installers/windows/build.ps1 -Version 1.0.0 -AgentExe dist/ber-agent.exe `
      -ServerExe dist/ber-server.exe -ConsoleDir console/dist -OutDir dist
#>
param(
  [Parameter(Mandatory)] [string] $Version,
  [Parameter(Mandatory)] [string] $AgentExe,
  [Parameter(Mandatory)] [string] $ServerExe,
  [Parameter(Mandatory)] [string] $ConsoleDir,
  [Parameter(Mandatory)] [string] $OutDir
)
$ErrorActionPreference = 'Stop'
$here = $PSScriptRoot
$wixVersion = '5.0.2'

if (-not (Get-Command wix -ErrorAction SilentlyContinue)) {
  dotnet tool install --global wix --version $wixVersion
  $env:PATH += ";$env:USERPROFILE\.dotnet\tools"
}
foreach ($ext in 'WixToolset.Util.wixext', 'WixToolset.UI.wixext', 'WixToolset.Firewall.wixext') {
  wix extension add -g "$ext/$wixVersion"
}

# MSI sürümü yalnızca rakam ve nokta içerebilir (1.2.3-rc.1 → 1.2.3).
$msiVersion = ($Version -replace '^v', '') -replace '[-+].*$', ''
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$OutDir = (Resolve-Path $OutDir).Path

# Sihirbazdaki lisans metni için LICENSE dosyasından basit bir RTF üretilir.
$license = Get-Content (Join-Path $here '..\..\LICENSE') -Raw
$escaped = $license.Replace('\', '\\').Replace('{', '\{').Replace('}', '\}') -replace "`r?`n", "\par`r`n"
$rtf = Join-Path $OutDir 'License.rtf'
Set-Content -Path $rtf -Encoding ascii -Value "{\rtf1\ansi\deff0{\fonttbl{\f0 Consolas;}}\f0\fs16 $escaped}"

wix build -arch x64 -culture tr-TR `
  -ext WixToolset.Util.wixext `
  -d Version=$msiVersion -d AgentExe=$((Resolve-Path $AgentExe).Path) `
  -o (Join-Path $OutDir "AutomationBER-Agent-$Version-x64.msi") `
  (Join-Path $here 'agent\BerAgent.wxs')
if ($LASTEXITCODE -ne 0) { throw "ajan MSI derlenemedi" }

wix build -arch x64 -culture tr-TR `
  -ext WixToolset.Util.wixext -ext WixToolset.UI.wixext -ext WixToolset.Firewall.wixext `
  -d Version=$msiVersion -d ServerExe=$((Resolve-Path $ServerExe).Path) `
  -d ConsoleDir=$((Resolve-Path $ConsoleDir).Path) -d LicenseRtf=$rtf `
  -o (Join-Path $OutDir "AutomationBER-Server-$Version-x64.msi") `
  (Join-Path $here 'server\BerServer.wxs')
if ($LASTEXITCODE -ne 0) { throw "sunucu MSI derlenemedi" }

Remove-Item $rtf
Get-ChildItem $OutDir -Filter *.msi | Format-Table Name, Length
