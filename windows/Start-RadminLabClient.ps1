# Stages an own-key service copy. /run is allowed only on a dedicated test machine.
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$PatchedServicePath,
    [Parameter(Mandatory=$true)][string]$PatchReportPath,
    [string]$InstallationDirectory,
    [string]$OutputDirectory = (Join-Path $PWD ('radmin-lab-client-' + (Get-Date -Format 'yyyyMMdd-HHmmss-fff'))),
    [switch]$RunOnDedicatedTestMachine,
    [string]$ExpectedServerAddress
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if ($env:OS -ne 'Windows_NT') { throw 'Run this script on Windows.' }
if ($RunOnDedicatedTestMachine -and [string]::IsNullOrWhiteSpace($ExpectedServerAddress)) {
    throw '-ExpectedServerAddress is required with -RunOnDedicatedTestMachine.'
}
$hashes = [ordered]@{
    'RvControlSvc.exe' = '546efad9ab3ff85c2a50d61524d754bec94a3f3e30d6ae8addef481a1e8daa1e'
    'RvROLClient.dll' = '6ba7dfecd38183d4bff0fc53f1c8c05d25e636077fe753b1220912aa58938177'
    'shelper.dll' = 'd89daf6bcd5cafa3c7f6173f835ccf045baf8e7134f868819db6fd7615959ac4'
    'RvUESClient.dll' = '016b4c45384453bda250f2f665d89fac40ed5f3db57af40b5650dbc3fe9f8a80'
    'vcruntime140.dll' = '526d8774c67248aa62a5911acd7db667cc4bed5be2cd5dc139c6c4d5dfb9d57e'
    'libcurl.dll' = '3ddc77540f94e13c64d93a225298b33e963814abffa07314a8a2bf132e03306b'
    'libssl-3.dll' = '3f16e37080e03d05f2acf3c97e0c9258685ada14d2a65507632ed72fe3c247f9'
    'libcrypto-3.dll' = '65f8975a8356bc1bbd6935745bf7deaefe8fdec62014fe4787d1b7b741cadd66'
}
function Get-Sha256([string]$Path) {
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}
if (-not $InstallationDirectory) {
    foreach ($root in @(${env:ProgramFiles(x86)}, $env:ProgramFiles)) {
        if ($root) {
            $candidate = Join-Path $root 'Radmin VPN'
            if (Test-Path -LiteralPath (Join-Path $candidate 'RvControlSvc.exe') -PathType Leaf) {
                $InstallationDirectory = $candidate
                break
            }
        }
    }
}
if (-not $InstallationDirectory) { throw 'Pass -InstallationDirectory for the original Radmin VPN 2.1.4951.1 files.' }
$InstallationDirectory = (Resolve-Path -LiteralPath $InstallationDirectory).Path
$PatchedServicePath = (Resolve-Path -LiteralPath $PatchedServicePath).Path
$PatchReportPath = (Resolve-Path -LiteralPath $PatchReportPath).Path
$patch = Get-Content -LiteralPath $PatchReportPath -Raw | ConvertFrom-Json
if ($patch.original_sha256 -ne $hashes['RvControlSvc.exe'] -or $patch.modified -ne $true -or
    $patch.verification_code_modified -ne $false -or $patch.vendor_authenticode_valid_after_change -ne $false) {
    throw 'Expected an own-key offline-copy report from research/client_key.py.'
}
foreach ($entry in $hashes.GetEnumerator()) {
    $path = Join-Path $InstallationDirectory $entry.Key
    if (-not (Test-Path -LiteralPath $path -PathType Leaf) -or (Get-Sha256 $path) -ne $entry.Value) {
        throw ('Original file version/hash mismatch: ' + $entry.Key)
    }
}
if ((Get-Sha256 $PatchedServicePath) -ne $patch.output_sha256) { throw 'Patched EXE does not match its report.' }
# Independent byte guard for the pinned EXE. Do not trust report-supplied offsets.
$original = [IO.File]::ReadAllBytes((Join-Path $InstallationDirectory 'RvControlSvc.exe'))
$modified = [IO.File]::ReadAllBytes($PatchedServicePath)
if ($original.Length -ne $modified.Length) { throw 'Patched EXE size changed.' }
$differences = 0
for ($i = 0; $i -lt $original.Length; $i++) {
    if ($original[$i] -eq $modified[$i]) { continue }
    if (($i -ge 1174856 -and $i -lt 1175068) -or ($i -ge 376 -and $i -lt 380)) {
        $differences++
    } else { throw 'Patched EXE contains changes outside the public-key block and PE checksum.' }
}
if ($differences -eq 0) { throw 'EXE is unchanged; a replacement public key was expected.' }
$outputFull = [IO.Path]::GetFullPath($OutputDirectory).TrimEnd('\')
$installFull = [IO.Path]::GetFullPath($InstallationDirectory).TrimEnd('\')
if ($outputFull.Equals($installFull, [StringComparison]::OrdinalIgnoreCase) -or
    $outputFull.StartsWith($installFull + '\', [StringComparison]::OrdinalIgnoreCase)) {
    throw 'OutputDirectory must be outside the original installation.'
}
# Check runtime conditions before creating any staging files.
$isElevated = $false
$powerOn = $null
if ($RunOnDedicatedTestMachine) {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    try {
        $principal = New-Object Security.Principal.WindowsPrincipal($identity)
        $isElevated = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    } finally { $identity.Dispose() }
    if (-not $isElevated) {
        throw 'Open PowerShell as Administrator. The native /run client opens its HKLM settings with write access.'
    }
    $running = @(Get-CimInstance Win32_Service | Where-Object {
        ($_.Name -eq 'RvControlSvc' -or $_.PathName -match 'RvControlSvc\.exe') -and $_.State -ne 'Stopped'
    })
    if ($running.Count -gt 0) { throw 'Original Radmin service must already be stopped on the dedicated test machine. This script does not stop it.' }
    if (@(Get-Process -Name RvControlSvc,RvRvpnGui -ErrorAction SilentlyContinue).Count -gt 0) {
        throw 'A Radmin service or GUI process is already running. Concurrent /run is not isolated.'
    }
    $base = $null; $key = $null
    try {
        $base = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine,[Microsoft.Win32.RegistryView]::Registry32)
        $key = $base.OpenSubKey('SOFTWARE\Famatech\RadminVPN\1.0',$false)
        if (-not $key -or $key.GetValueKind('ServerAddress') -ne [Microsoft.Win32.RegistryValueKind]::String) {
            throw 'Dedicated test machine must already have a Registry32 String ServerAddress.'
        }
        $address = [string]$key.GetValue('ServerAddress',$null,[Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
        if (-not $address.Equals($ExpectedServerAddress,[StringComparison]::OrdinalIgnoreCase)) {
            throw 'ServerAddress does not match ExpectedServerAddress. This script never changes the registry.'
        }
        if ($key.GetValueNames() -contains 'PowerOn') {
            if ($key.GetValueKind('PowerOn') -eq [Microsoft.Win32.RegistryValueKind]::DWord) {
                $powerOn = $key.GetValue('PowerOn')
            }
        }
    } finally { if ($key) {$key.Dispose()}; if ($base) {$base.Dispose()} }
}
New-Item -ItemType Directory -Path $outputFull -ErrorAction Stop | Out-Null
foreach ($entry in $hashes.GetEnumerator()) {
    $source = Join-Path $InstallationDirectory $entry.Key
    $expected = $entry.Value
    if ($entry.Key -eq 'RvControlSvc.exe') { $source = $PatchedServicePath; $expected = $patch.output_sha256 }
    $target = Join-Path $outputFull $entry.Key
    Copy-Item -LiteralPath $source -Destination $target -ErrorAction Stop
    if ((Get-Sha256 $target) -ne $expected) { throw ('Staged file checksum mismatch: ' + $entry.Key) }
}
Copy-Item -LiteralPath $PatchReportPath -Destination (Join-Path $outputFull 'client-key-report.json')
$report = [ordered]@{
    SchemaVersion = 1
    PatchedServiceSHA256 = $patch.output_sha256
    PublicKeySPKISHA256 = $patch.replacement_public_key_spki_sha256
    VendorSignatureValid = $false
    Installed = $false
    Executed = $false
    IsolatedProfile = $false
    VPNReady = $false
    IsElevated = $isElevated
    PowerOn = $powerOn
}
Write-Host ('Staged own-key client: ' + $outputFull)
Write-Host 'The modified EXE has an invalid vendor signature. Windows trust policies remain enabled.'
if ($RunOnDedicatedTestMachine) {
    Write-Host '/run shares the original registry, pipe and adapter. Use only a dedicated test VM.'
    $process = Start-Process -FilePath (Join-Path $outputFull 'RvControlSvc.exe') -ArgumentList '/run' -WorkingDirectory $outputFull -PassThru
    $report.Executed = $true
    $report.ProcessId = $process.Id
    Write-Host ('Started /run process: ' + $process.Id)
    Start-Sleep -Seconds 2
    $process.Refresh()
    $report.RunningAfterTwoSeconds = -not $process.HasExited
    if ($process.HasExited) {
        $report.ExitCode = $process.ExitCode
        Write-Warning ('Client exited during startup. Exit code: ' + $process.ExitCode)
    } else {
        Write-Host ('Client is still running after two seconds. PID: ' + $process.Id)
    }
    if ($null -ne $powerOn) { Write-Host ('PowerOn (Registry32): ' + $powerOn) }
} else {
    Write-Host 'Staging complete. No EXE was started and no service or registry setting was changed.'
}
$report | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath (Join-Path $outputFull 'lab-client-launch.json') -Encoding UTF8
