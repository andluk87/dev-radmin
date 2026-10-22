# Changes only ServerAddress on a dedicated test Windows; saves/restores that value.
[CmdletBinding(DefaultParameterSetName='Set')]
param(
    [Parameter(Mandatory=$true,ParameterSetName='Set')][string]$ServerAddress,
    [Parameter(Mandatory=$true,ParameterSetName='Restore')][switch]$Restore,
    [Parameter(Mandatory=$true)][string]$BackupPath,
    [Parameter(Mandatory=$true)][switch]$DedicatedTestMachine
)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
if ($env:OS -ne 'Windows_NT') {throw 'Run on Windows.'}
if (-not $DedicatedTestMachine) {throw 'Use only a dedicated test Windows with the original service stopped.'}
if (@(Get-CimInstance Win32_Service | Where-Object {$_.Name -eq 'RvControlSvc' -and $_.State -ne 'Stopped'}).Count -gt 0) {
    throw 'Stop the original Radmin service on the test machine first.'
}
if (@(Get-Process -Name RvControlSvc,RvRvpnGui -ErrorAction SilentlyContinue).Count -gt 0) {
    throw 'Close Radmin service/GUI processes on the test machine first.'
}
$base=$null; $key=$null
try {
    $base=[Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine,[Microsoft.Win32.RegistryView]::Registry32)
    $key=$base.OpenSubKey('SOFTWARE\Famatech\RadminVPN\1.0',$true)
    if (-not $key) {throw 'Original Radmin VPN registry key is missing; install the original client first.'}
    if ($Restore) {
        $saved=Get-Content -LiteralPath $BackupPath -Raw | ConvertFrom-Json
        if ($saved.SchemaVersion -ne 1 -or $saved.RegistryView -ne 'Registry32' -or $saved.ValueName -ne 'ServerAddress') {throw 'Invalid address-only backup.'}
        if ($saved.Existed -eq $true) {
            if ($saved.Kind -ne 'String' -or $saved.Value -isnot [string]) {throw 'Unsupported backup value.'}
            $key.SetValue('ServerAddress',[string]$saved.Value,[Microsoft.Win32.RegistryValueKind]::String)
        } elseif ($saved.Existed -eq $false) {
            $key.DeleteValue('ServerAddress',$false)
        } else {throw 'Invalid backup presence flag.'}
        Write-Host 'Restored ServerAddress. Registration and other settings were not changed.'
    } else {
        if ($ServerAddress.Length -gt 253 -or $ServerAddress -notmatch '^[A-Za-z0-9][A-Za-z0-9.-]*$') {throw 'Pass an IPv4 address or host name without a port or URL scheme.'}
        $existed=@($key.GetValueNames()) -contains 'ServerAddress'
        $value=$null
        if ($existed) {
            if ($key.GetValueKind('ServerAddress') -ne [Microsoft.Win32.RegistryValueKind]::String) {throw 'Existing ServerAddress is not String.'}
            $value=[string]$key.GetValue('ServerAddress',$null,[Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
        }
        $saved=[ordered]@{SchemaVersion=1;RegistryView='Registry32';ValueName='ServerAddress';Existed=$existed;Kind='String';Value=$value}
        $data=(New-Object Text.UTF8Encoding($false)).GetBytes(($saved | ConvertTo-Json -Depth 3))
        $stream=[IO.File]::Open([IO.Path]::GetFullPath($BackupPath),[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
        try {$stream.Write($data,0,$data.Length)} finally {$stream.Dispose()}
        $key.SetValue('ServerAddress',$ServerAddress,[Microsoft.Win32.RegistryValueKind]::String)
        Write-Host 'Set ServerAddress; previous value saved. Registration was not changed.'
    }
} finally {if ($key) {$key.Dispose()}; if ($base) {$base.Dispose()}}
