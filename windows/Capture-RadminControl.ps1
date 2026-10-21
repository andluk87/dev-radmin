# Windows 10/11, elevated Windows PowerShell 5.1 or PowerShell 7.
# Records only packets to/from the configured control server IP. Does not modify registry settings.
[CmdletBinding()]
param(
    [ValidateRange(5,60)][int]$Seconds = 20,
    [string]$ServerAddress,
    [switch]$RestartService,
    [switch]$SkipConversion,
    [string]$OutputDirectory = (Join-Path $PWD ('radmin-capture-' + (Get-Date -Format 'yyyyMMdd-HHmmss-fff')))
)
$ErrorActionPreference = 'Stop'
if ($env:OS -ne 'Windows_NT') { throw 'Run on Windows.' }
$principal = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Open PowerShell as Administrator, then run this script again.'
}
$service = Get-Service -Name RvControlSvc -ErrorAction Stop
if ($service.Status -ne 'Running') { throw 'RvControlSvc must already be running.' }
if (-not $ServerAddress) {
    $base = $null; $key = $null
    try {
        $base = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine,[Microsoft.Win32.RegistryView]::Registry32)
        $key = $base.OpenSubKey('SOFTWARE\Famatech\RadminVPN\1.0',$false)
        if ($null -ne $key) { $ServerAddress = [string]$key.GetValue('ServerAddress',$null,[Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames) }
    } finally { if($key){$key.Dispose()};if($base){$base.Dispose()} }
}
$parsedAddress = $null
if (-not [Net.IPAddress]::TryParse($ServerAddress,[ref]$parsedAddress) -or $parsedAddress.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetwork) {
    throw 'Expected an IPv4 control-server address. Supply -ServerAddress if the registry value is unavailable.'
}
$ServerAddress = $parsedAddress.ToString()
$netsh = Join-Path $env:SystemRoot 'System32\netsh.exe'
$help = & $netsh trace show capturefilterhelp 2>&1
$filterHelp = $help -join "`n"
if ($LASTEXITCODE -ne 0 -or $filterHelp -notmatch 'IPv4\.Address' -or $filterHelp -notmatch 'Ethernet\.Type' -or $filterHelp -notmatch 'Protocol=') {
    throw 'This Windows build does not expose the required IPv4/Ethernet/protocol capture filters.'
}
New-Item -ItemType Directory -Path $OutputDirectory -ErrorAction Stop | Out-Null
$OutputDirectory = (Resolve-Path -LiteralPath $OutputDirectory).Path
$etl = Join-Path $OutputDirectory 'radmin-control.etl'
$pcap = Join-Path $OutputDirectory 'radmin-control.pcapng'
$log = Join-Path $OutputDirectory 'capture-log.txt'
$help | Out-File -LiteralPath (Join-Path $OutputDirectory 'capture-filter-help.txt') -Encoding UTF8
$started = $false; $stopped = $false; $restarted = $false; $failure = $null; $stopExitCode = $null
$startTime = [DateTime]::UtcNow
Write-Host ('Recording packets to/from control server ' + $ServerAddress + ' for ' + $Seconds + ' seconds.')
if ($RestartService) { Write-Host 'RvControlSvc will restart once. Existing Radmin VPN connections will briefly disconnect.' }
try {
    $arguments = @('trace','start','capture=yes','report=no','persistent=no','correlation=no',
        'maxsize=16','filemode=single','overwrite=no',('tracefile=' + $etl),
        'Ethernet.Type=IPv4','Protocol=TCP',('IPv4.Address=' + $ServerAddress))
    & $netsh @arguments 2>&1 | Out-File -LiteralPath $log -Encoding UTF8
    if ($LASTEXITCODE -ne 0) { throw 'netsh trace start failed. An existing trace was not stopped. See capture-log.txt.' }
    if (-not (Test-Path -LiteralPath $etl -PathType Leaf)) {
        throw 'The requested ETL file was not created; trace ownership is unconfirmed. No trace was stopped. See capture-log.txt.'
    }
    $started = $true
    if ($RestartService) {
        Restart-Service -Name RvControlSvc -ErrorAction Stop
        $restarted = $true
        (Get-Service -Name RvControlSvc).WaitForStatus([System.ServiceProcess.ServiceControllerStatus]::Running,[TimeSpan]::FromSeconds(15))
    } else {
        Write-Host 'No automatic restart requested; an already established connection may not include its initial handshake.'
    }
    Start-Sleep -Seconds $Seconds
} catch { $failure = $_.Exception.Message }
finally {
    if ($started) {
        & $netsh trace stop 2>&1 | Out-File -LiteralPath $log -Append -Encoding UTF8
        $stopExitCode = $LASTEXITCODE
        $stopped = ($stopExitCode -eq 0)
        if (-not $stopped) {
            & $netsh trace show status 2>&1 | Out-File -LiteralPath $log -Append -Encoding UTF8
            Write-Warning 'Stop returned a nonzero status; tracing may already have ended at its size limit. The ETL is retained and conversion will be attempted. See capture-log.txt for trace status.'
        }
    }
    $metadata = [ordered]@{
        SchemaVersion=2;StartedAtUtc=$startTime.ToString('o');FinishedAtUtc=[DateTime]::UtcNow.ToString('o')
        Filter=@('Ethernet.Type=IPv4','Protocol=TCP',('IPv4.Address=' + $ServerAddress));ExpectedControlTCPPort=17301
        RequestedSeconds=$Seconds;TraceStarted=$started;TraceStopped=$stopped
        StopExitCode=$stopExitCode
        RestartRequested=[bool]$RestartService;RestartCompleted=$restarted
        Failure=$failure;ETLExists=(Test-Path -LiteralPath $etl -PathType Leaf)
    }
    $metadata | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath (Join-Path $OutputDirectory 'capture-metadata.json') -Encoding UTF8
}
if ($failure) { throw $failure }
if (-not (Test-Path -LiteralPath $etl -PathType Leaf)) { throw 'An ETL capture file is unavailable. See capture-log.txt.' }
if (-not $SkipConversion) {
    # Official Microsoft release, pinned by the SHA-256 of the HTTPS-downloaded release artifact.
    $converterUrl = 'https://github.com/microsoft/etl2pcapng/releases/download/v1.11.0/etl2pcapng.exe'
    $expectedSHA256 = 'c2d03aac43ea0f5626fc8d909e6688393feaf71bd6facd39aaf8a637382d9043'
    $converter = Join-Path $OutputDirectory 'etl2pcapng.exe'
    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
        Invoke-WebRequest -Uri $converterUrl -OutFile $converter -UseBasicParsing -ErrorAction Stop
        if ((Get-FileHash -LiteralPath $converter -Algorithm SHA256).Hash.ToLowerInvariant() -ne $expectedSHA256) {
            throw 'Converter SHA-256 mismatch. The downloaded file will not be executed.'
        }
        & $converter $etl $pcap 2>&1 | Out-File -LiteralPath $log -Append -Encoding UTF8
        if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $pcap -PathType Leaf)) { throw 'ETL conversion did not complete.' }
        Write-Host ('Saved capture: ' + $pcap)
    } catch {
        Write-Warning ('Conversion unavailable: ' + $_.Exception.Message + ' The ETL capture is retained.')
    }
}
Write-Host ('Capture directory: ' + $OutputDirectory)
Write-Host 'Share radmin-control.pcapng (or the ETL if conversion failed) and capture-metadata.json for analysis.'
Write-Host 'Packet contents may contain client identifiers. Keep captures out of Git.'
