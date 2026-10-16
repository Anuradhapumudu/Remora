<#
.SYNOPSIS
  CI only: sign files with a standard code-signing certificate (.pfx) via signtool.

.DESCRIPTION
  Environment:
    WINDOWS_CERTIFICATE_PFX_BASE64  base64 of the .pfx (certificate + private key)
    WINDOWS_CERTIFICATE_PASSWORD    its password
  Uses SHA-256 digests and an RFC 3161 timestamp, so signatures stay valid after
  the certificate expires.

.EXAMPLE
  scripts/windows/sign-pfx.ps1 target/release/remora-host.exe, target/release/remora-viewer.exe
#>
param([Parameter(Mandatory = $true)][string[]]$Files)
$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

if (-not $env:WINDOWS_CERTIFICATE_PFX_BASE64) { throw "WINDOWS_CERTIFICATE_PFX_BASE64 is not set" }

# signtool ships with the Windows SDK, which GitHub's Windows images include; pick the newest x64 one.
$signtool = Get-ChildItem "${env:ProgramFiles(x86)}\Windows Kits\10\bin\*\x64\signtool.exe" |
  Sort-Object FullName -Descending | Select-Object -First 1
if (-not $signtool) { throw "signtool.exe not found" }

$pfx = Join-Path $env:RUNNER_TEMP "remora-signing.pfx"
try {
  [IO.File]::WriteAllBytes($pfx, [Convert]::FromBase64String($env:WINDOWS_CERTIFICATE_PFX_BASE64))
  foreach ($f in $Files) {
    & $signtool.FullName sign /f $pfx /p $env:WINDOWS_CERTIFICATE_PASSWORD `
      /fd SHA256 /tr http://timestamp.digicert.com /td SHA256 /d "Remora" $f
    if ($LASTEXITCODE -ne 0) { throw "signtool failed for $f" }
    & $signtool.FullName verify /pa $f
    if ($LASTEXITCODE -ne 0) { throw "signature verification failed for $f" }
  }
} finally {
  Remove-Item -Force -ErrorAction SilentlyContinue $pfx
}
