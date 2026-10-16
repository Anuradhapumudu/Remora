<#
.SYNOPSIS
  Package Remora for Windows x86_64: portable .zip and .msi (WiX v5).

.DESCRIPTION
  Expects `cargo build --release` output in target\release. Signing of the .exe
  files happens BEFORE this script and signing of the .msi AFTER it (both in
  .github/workflows/release.yml), so the MSI contains signed executables.

.EXAMPLE
  scripts\windows\package.ps1 -Version 0.1.0 -Out dist
#>
param(
  [Parameter(Mandatory = $true)][string]$Version,
  [string]$Out = "dist"
)
$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$Root = Resolve-Path (Join-Path $PSScriptRoot "..\..")
Set-Location $Root
$BinDir = Join-Path $Root "target\release"
foreach ($b in "remora-host.exe", "remora-viewer.exe") {
  if (-not (Test-Path (Join-Path $BinDir $b))) { throw "missing $BinDir\$b - run cargo build --release first" }
}
New-Item -ItemType Directory -Force -Path $Out | Out-Null

# MSI ProductVersion must be numeric X.Y.Z; any "-nightly..." suffix is dropped
# (AllowSameVersionUpgrades in remora.wxs lets nightlies replace each other).
$MsiVersion = ($Version -split "-")[0]
if ($MsiVersion -notmatch '^\d+\.\d+\.\d+$') { throw "bad version: $Version" }

# 1. Portable zip
$Stage = Join-Path ([System.IO.Path]::GetTempPath()) "remora-$Version-windows-x86_64"
if (Test-Path $Stage) { Remove-Item -Recurse -Force $Stage }
New-Item -ItemType Directory -Path $Stage | Out-Null
Copy-Item (Join-Path $BinDir "remora-host.exe"), (Join-Path $BinDir "remora-viewer.exe") $Stage
Copy-Item (Join-Path $Root "LICENSE-GPL") (Join-Path $Stage "LICENSE.txt")
$Zip = Join-Path $Out "remora-$Version-windows-x86_64.zip"
if (Test-Path $Zip) { Remove-Item $Zip }
Compress-Archive -Path $Stage -DestinationPath $Zip

# 2. MSI
$Msi = Join-Path $Out "Remora-$Version-windows-x86_64.msi"
wix build (Join-Path $Root "packaging\windows\remora.wxs") -arch x64 `
  -d "Version=$MsiVersion" -d "BinDir=$BinDir" -d "LicenseFile=$(Join-Path $Root 'LICENSE-GPL')" `
  -o $Msi
if ($LASTEXITCODE -ne 0) { throw "wix build failed" }

Get-ChildItem $Out
