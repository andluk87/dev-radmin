# Runs synthetic DLL/Go checks without changing Radmin VPN, its service or registry.
[CmdletBinding()]
param(
    [string]$DllPath,
    [string]$OutputDirectory = (Join-Path $PWD ('radmin-native-check-' + (Get-Date -Format 'yyyyMMdd-HHmmss-fff')))
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if (-not $DllPath) {
    foreach ($root in @(${env:ProgramFiles(x86)}, $env:ProgramFiles)) {
        if ($root) {
            $candidate = Join-Path $root 'Radmin VPN\shelper.dll'
            if (Test-Path -LiteralPath $candidate -PathType Leaf) {
                $DllPath = $candidate
                break
            }
        }
    }
}
if (-not $DllPath -or -not (Test-Path -LiteralPath $DllPath -PathType Leaf)) {
    throw 'Original shelper.dll was not found. Pass -DllPath with its installed path.'
}
$DllPath = (Resolve-Path -LiteralPath $DllPath).Path
$expectedHelper = 'd89daf6bcd5cafa3c7f6173f835ccf045baf8e7134f868819db6fd7615959ac4'
if ((Get-FileHash -LiteralPath $DllPath -Algorithm SHA256).Hash.ToLowerInvariant() -ne $expectedHelper) {
    throw 'Helper version does not match the researched Radmin VPN 2.1.4951.1 DLL.'
}
New-Item -ItemType Directory -Path $OutputDirectory -ErrorAction Stop | Out-Null
$OutputDirectory = (Resolve-Path -LiteralPath $OutputDirectory).Path
$binary = Join-Path $OutputDirectory 'native-check-windows-386.exe'
$checksum = Join-Path $OutputDirectory 'native-check-windows-386.exe.sha256'
$report = Join-Path $OutputDirectory 'native-check.json'
$base = 'https://raw.githubusercontent.com/andluk87/dev-radmin/main/bin'
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
Invoke-WebRequest -UseBasicParsing -Uri ($base + '/native-check-windows-386.exe.sha256') -OutFile $checksum
Invoke-WebRequest -UseBasicParsing -Uri ($base + '/native-check-windows-386.exe') -OutFile $binary
$line = (Get-Content -LiteralPath $checksum -Raw).Trim()
if ($line -notmatch '^([0-9a-fA-F]{64})\s+bin/native-check-windows-386\.exe$') {
    throw 'Invalid binary checksum file.'
}
$expectedBinary = $Matches[1].ToLowerInvariant()
if ((Get-FileHash -LiteralPath $binary -Algorithm SHA256).Hash.ToLowerInvariant() -ne $expectedBinary) {
    throw 'Downloaded binary checksum mismatch. The check was not started.'
}
Write-Host 'Running synthetic RSA/CChannel/SRP and rekey checks using the original DLL.'
Write-Host 'No VPN connection, packet capture, service restart or registry change is performed.'
$ErrorActionPreference = 'Continue'
try {
    & $binary -dll $DllPath -output $report
    $nativeExitCode = $LASTEXITCODE
} finally {
    $ErrorActionPreference = 'Stop'
    Write-Host ('Report: ' + $report)
}
if (-not (Test-Path -LiteralPath $report -PathType Leaf)) {
    throw 'The executable did not create a report. Check whether Windows blocked its launch.'
}
if ($nativeExitCode -ne 0) {
    throw 'Native check failed. Send native-check.json if it was created.'
}
Write-Host 'Finished. Send native-check.json for review.'
