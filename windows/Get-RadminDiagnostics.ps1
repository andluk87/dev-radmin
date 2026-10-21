# Run in Windows PowerShell 5.1 or PowerShell 7. This script does not change Radmin settings.
[CmdletBinding()]
param(
    [ValidateRange(1,120)][int]$Seconds = 30,
    [string]$OutputDirectory = (Join-Path $PWD ('radmin-diagnostics-' + (Get-Date -Format 'yyyyMMdd-HHmmss')))
)
$ErrorActionPreference = 'Stop'
if ($env:OS -ne 'Windows_NT') { throw 'Run this script on the Windows test computer.' }
New-Item -ItemType Directory -Path $OutputDirectory -ErrorAction Stop | Out-Null
$issues = [System.Collections.Generic.List[string]]::new()
$services = @(Get-CimInstance Win32_Service | Where-Object {
    $_.Name -eq 'RvControlSvc' -or $_.PathName -match 'RvControlSvc\.exe'
})
$registry = @()
# Explicit allowlist: never enumerate or export the full registry key.
# Registration, ServerPassword and network membership data are deliberately excluded.
$names = @('ServerAddress','FailServers','ProxyServers','PowerOn','IPv4','IPv6')
foreach ($view in @([Microsoft.Win32.RegistryView]::Registry32,[Microsoft.Win32.RegistryView]::Registry64)) {
    $base = $null; $key = $null
    try {
        $base = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine,$view)
        $key = $base.OpenSubKey('SOFTWARE\Famatech\RadminVPN\1.0',$false)
        if ($null -ne $key) {
            foreach ($name in $names) {
                $value = $key.GetValue($name,$null,[Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
                if ($null -eq $value) { continue }
                $kind = $key.GetValueKind($name).ToString()
                # Only known string/DWORD formats are included; never dump binary values.
                if ($kind -notin @('String','ExpandString','MultiString','DWord')) {
                    $registry += [pscustomobject]@{View=$view.ToString();Name=$name;Kind=$kind;Value='[not collected]'}
                } else {
                    $registry += [pscustomobject]@{View=$view.ToString();Name=$name;Kind=$kind;Value=$value}
                }
            }
        }
    } catch { $issues.Add(('Registry {0}: {1}' -f $view,$_.Exception.GetType().Name)) }
    finally { if($key){$key.Dispose()};if($base){$base.Dispose()} }
}
$directories = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
foreach ($service in $services) {
    $match = [regex]::Match($service.PathName,'^\s*(?:"([^"]+\.exe)"|(.+?\.exe))(?:\s|$)','IgnoreCase')
    if ($match.Success) {
        $exe = $match.Groups[1].Value
        if (-not $exe) { $exe = $match.Groups[2].Value }
        [void]$directories.Add((Split-Path -Parent $exe))
    }
}
foreach ($root in @($env:ProgramFiles,${env:ProgramFiles(x86)})) {
    if ($root) { $candidate=Join-Path $root 'Radmin VPN';if(Test-Path -LiteralPath $candidate){[void]$directories.Add($candidate)} }
}
$files = @()
foreach ($directory in $directories) {
    foreach ($name in @('RvControlSvc.exe','RvROLClient.dll','shelper.dll','RvUESClient.dll','RvRvpnGui.exe')) {
        $path=Join-Path $directory $name
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {continue}
        try {
            $file=Get-Item -LiteralPath $path
            $signature=Get-AuthenticodeSignature -LiteralPath $path
            $files += [pscustomobject]@{Name=$name;Version=$file.VersionInfo.FileVersion;
                SHA256=(Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash;
                SignatureStatus=$signature.Status.ToString()}
        } catch { $issues.Add(('File {0}: {1}' -f $name,$_.Exception.GetType().Name)) }
    }
}
$tcp = @{}; $udp = @{}
for ($i=0;$i -lt $Seconds;$i++) {
    $ids=@(Get-Process -Name RvControlSvc -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Id)
    if ($ids.Count -gt 0) {
        try {
            Get-NetTCPConnection -ErrorAction Stop | Where-Object {$_.OwningProcess -in $ids} | ForEach-Object {
                $id='{0}|{1}|{2}|{3}|{4}|{5}' -f $_.OwningProcess,$_.LocalAddress,$_.LocalPort,$_.RemoteAddress,$_.RemotePort,$_.State
                $tcp[$id]=[pscustomobject]@{ProcessId=$_.OwningProcess;LocalAddress=$_.LocalAddress;LocalPort=$_.LocalPort;
                    RemoteAddress=$_.RemoteAddress;RemotePort=$_.RemotePort;State=$_.State.ToString()}
            }
            Get-NetUDPEndpoint -ErrorAction Stop | Where-Object {$_.OwningProcess -in $ids} | ForEach-Object {
                $id='{0}|{1}|{2}' -f $_.OwningProcess,$_.LocalAddress,$_.LocalPort
                $udp[$id]=[pscustomobject]@{ProcessId=$_.OwningProcess;LocalAddress=$_.LocalAddress;LocalPort=$_.LocalPort}
            }
        } catch { $issues.Add(('Connections: {0}' -f $_.Exception.GetType().Name));break }
    }
    Start-Sleep -Seconds 1
}
$report = [ordered]@{
    SchemaVersion=1;CapturedAtUtc=[DateTime]::UtcNow.ToString('o');ObservationSeconds=$Seconds
    OSVersion=[Environment]::OSVersion.Version.ToString();PowerShellVersion=$PSVersionTable.PSVersion.ToString()
    Services=@($services | Select-Object Name,State,StartMode,ProcessId)
    Files=$files;Registry=$registry;TCP=@($tcp.Values);UDP=@($udp.Values);Issues=@($issues.ToArray())
}
$output=Join-Path $OutputDirectory 'diagnostics.json'
$report | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $output -Encoding UTF8
Write-Host ('Saved: ' + $output)
Write-Host 'Contains versions, selected settings and connection addresses. No passwords or packet contents collected.'
